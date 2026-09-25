'use strict';

const { createHash, randomBytes } = require('node:crypto');

// Simplified, opinionated facade over the L2TP relay machinery: the panel
// page only exposes install/uninstall per relay, a revealed per-relay PSK
// and a global account list. All addressing is generated automatically.

const DEFAULT_DNS = Object.freeze(['1.1.1.1', '8.8.8.8']);
const DEFAULT_TPROXY_PORT = 12345;
const DEFAULT_FWMARK = 100;
const DEFAULT_ROUTE_TABLE = 100;
const SUBNET_THIRD_OCTET_MIN = 16;
const SUBNET_THIRD_OCTET_MAX = 239;
const AUTO_GROUP_NAME = 'auto-l2tp';
const AUTO_GROUP_PATH_KEY = 'main';
const MAX_GROUP_WALK_HOPS = 8;

class L2tpSimpleError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'L2tpSimpleError';
        this.code = code;
    }
}

function simpleError(code, message) {
    return new L2tpSimpleError(code, message);
}

function entityId(entity) {
    if (!entity) return '';
    if (typeof entity === 'string') return entity;
    if (typeof entity === 'object') {
        // bson ObjectId exposes a self-referencing `_id` getter — stringify
        // it before the generic `_id`/`id` branches to avoid recursion.
        if (typeof entity.toHexString === 'function') return entity.toHexString();
        if (entity._id !== undefined && entity._id !== entity) return entityId(entity._id);
        if (entity.id !== undefined && entity.id !== entity) return entityId(entity.id);
    }
    return String(entity);
}

function nodeRole(node) {
    const role = node?.cascadeRole;
    return typeof role === 'string' ? role : '';
}

function ipv4ToInt(ip) {
    if (typeof ip !== 'string') return null;
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    let value = 0;
    for (const part of parts) {
        if (!/^\d{1,3}$/.test(part)) return null;
        const octet = Number(part);
        if (octet > 255 || String(octet) !== part && part !== '0' && part.startsWith('0')) {
            return null;
        }
        value = value * 256 + octet;
    }
    return value >>> 0;
}

function intToIpv4(value) {
    return [
        (value >>> 24) & 255,
        (value >>> 16) & 255,
        (value >>> 8) & 255,
        value & 255,
    ].join('.');
}

function usedThirdOctets(states) {
    const used = new Set();
    for (const state of states) {
        const cidr = typeof state?.clientCidr === 'string' ? state.clientCidr : '';
        const match = cidr.match(/^10\.255\.(\d{1,3})\.0\/24$/);
        if (match) used.add(Number(match[1]));
    }
    return used;
}

function pickThirdOctet(nodeId, states) {
    const used = usedThirdOctets(states);
    const hash = createHash('sha256').update(String(nodeId)).digest();
    const span = SUBNET_THIRD_OCTET_MAX - SUBNET_THIRD_OCTET_MIN + 1;
    const start = SUBNET_THIRD_OCTET_MIN + (hash[0] % span);
    for (let offset = 0; offset < span; offset += 1) {
        const candidate = SUBNET_THIRD_OCTET_MIN + ((start - SUBNET_THIRD_OCTET_MIN + offset) % span);
        if (!used.has(candidate)) return candidate;
    }
    throw simpleError(
        'ADDRESS_SPACE_EXHAUSTED',
        'No free automatic L2TP subnet remains',
    );
}

function autoDesiredInput(nodeId, states, routeGroupId, preferredThird = null) {
    const third = preferredThird !== null && !usedThirdOctets(states).has(preferredThird)
        ? preferredThird
        : pickThirdOctet(nodeId, states);
    return {
        clientCidr: `10.255.${third}.0/24`,
        localAddress: `10.255.${third}.1`,
        poolStart: `10.255.${third}.10`,
        poolEnd: `10.255.${third}.250`,
        dnsServers: [...DEFAULT_DNS],
        tproxyPort: DEFAULT_TPROXY_PORT,
        fwmark: DEFAULT_FWMARK,
        routeTable: DEFAULT_ROUTE_TABLE,
        routeGroupId,
        generatePsk: true,
    };
}

function allocateIpv4(state, takenIps) {
    const start = ipv4ToInt(state?.poolStart);
    const end = ipv4ToInt(state?.poolEnd);
    const local = ipv4ToInt(state?.localAddress);
    if (start === null || end === null || start > end) {
        throw simpleError(
            'INVALID_CLIENT_POOL',
            'The relay L2TP pool is not configured',
        );
    }
    for (let candidate = start; candidate <= end; candidate += 1) {
        if (candidate === local) continue;
        const ip = intToIpv4(candidate);
        if (!takenIps.has(ip)) return ip;
    }
    throw simpleError(
        'POOL_EXHAUSTED',
        'No free L2TP address remains in the relay pool',
    );
}

function safeAccountUsers(users) {
    return users.map(user => ({
        id: entityId(user._id ?? user.id),
        relayNode: entityId(user.relayNode),
        login: user.login,
        ip: user.ip,
        enabled: user.enabled !== false,
        syncStatus: typeof user.syncStatus === 'string' ? user.syncStatus : '',
        desiredRevision: user.desiredRevision,
        passwordEncrypted: typeof user.passwordEncrypted === 'string' ? user.passwordEncrypted : '',
    }));
}

function generateAccountPassword() {
    // base64url keeps chap-secrets quoting safe (no whitespace/quotes).
    return randomBytes(12).toString('base64url');
}

function buildTeardownScript(state) {
    const routeTable = Number.isSafeInteger(state?.routeTable) ? state.routeTable : 0;
    const xrayStrip = Buffer.from(`
import json
path = '/usr/local/etc/xray/config.json'
try:
    with open(path) as handle:
        config = json.load(handle)
except Exception:
    raise SystemExit(0)
tags = {
    inbound.get('tag')
    for inbound in config.get('inbounds', [])
    if str(inbound.get('tag', '')).startswith('relay-l2tp-')
}
if not tags:
    raise SystemExit(0)
config['inbounds'] = [
    inbound for inbound in config.get('inbounds', [])
    if inbound.get('tag') not in tags
]
routing = config.get('routing') or {}
routing['rules'] = [
    rule for rule in routing.get('rules', [])
    if not (set(rule.get('inboundTag', [])) & tags)
]
with open(path, 'w') as handle:
    json.dump(config, handle, indent=2)
print('xray-l2tp-removed')
`).toString('base64');
    return [
        'set -u',
        'ipsec stop >/dev/null 2>&1 || true',
        'rm -f /var/run/charon.pid /var/run/starter.charon.pid >/dev/null 2>&1 || true',
        'systemctl stop xl2tpd.service strongswan-starter.service >/dev/null 2>&1 || true',
        'systemctl disable xl2tpd.service strongswan-starter.service >/dev/null 2>&1 || true',
        'nft delete table inet celerity_l2tp >/dev/null 2>&1 || true',
        'ip -4 rule del priority 10077 >/dev/null 2>&1 || true',
        `ip -4 route flush table ${routeTable} >/dev/null 2>&1 || true`,
        'rm -f /etc/ipsec.d/celerity-l2tp.conf /etc/ipsec.secrets'
            + ' /etc/xl2tpd/xl2tpd.conf /etc/ppp/options.xl2tpd /etc/ppp/chap-secrets'
            + ' /etc/nftables.d/celerity-l2tp.nft',
        `printf '%s' '${xrayStrip}' | base64 -d | python3 || true`,
        'systemctl is-active --quiet xray.service'
            + ' && systemctl restart xray.service >/dev/null 2>&1 || true',
        'echo TEARDOWN_OK',
    ].join('\n');
}

class L2tpSimpleService {
    constructor({
        HyNode,
        RelayL2tpState,
        L2tpUser,
        CascadeRouteGroup,
        CascadeLink,
        l2tpService,
        stateManagementService,
        userManagementService,
        stateRepository,
        nodeSSHFactory,
        secretBox = null,
        secretKey = null,
    } = {}) {
        if (!HyNode || typeof HyNode.find !== 'function' || typeof HyNode.findById !== 'function') {
            throw new TypeError('L2TP simple service requires the HyNode model');
        }
        if (!RelayL2tpState || typeof RelayL2tpState.find !== 'function') {
            throw new TypeError('L2TP simple service requires the RelayL2tpState model');
        }
        if (!L2tpUser || typeof L2tpUser.find !== 'function') {
            throw new TypeError('L2TP simple service requires the L2tpUser model');
        }
        if (!CascadeRouteGroup || typeof CascadeRouteGroup.find !== 'function') {
            throw new TypeError('L2TP simple service requires the CascadeRouteGroup model');
        }
        for (const [name, service, methods] of [
            ['l2tpService', l2tpService, ['install', 'getOperation']],
            ['stateManagementService', stateManagementService, ['configureRelay', 'revealPsk']],
            ['userManagementService', userManagementService, ['createUser', 'deleteUser', 'importUser']],
        ]) {
            for (const method of methods) {
                if (typeof service?.[method] !== 'function') {
                    throw new TypeError(`L2TP simple service requires ${name}.${method}`);
                }
            }
        }
        if (typeof stateRepository?.getTopologyRevision !== 'function') {
            throw new TypeError('L2TP simple service requires stateRepository.getTopologyRevision');
        }
        if (typeof nodeSSHFactory !== 'function') {
            throw new TypeError('L2TP simple service requires nodeSSHFactory');
        }
        this.HyNode = HyNode;
        this.RelayL2tpState = RelayL2tpState;
        this.L2tpUser = L2tpUser;
        this.CascadeRouteGroup = CascadeRouteGroup;
        this.CascadeLink = CascadeLink;
        this.l2tpService = l2tpService;
        this.stateManagementService = stateManagementService;
        this.userManagementService = userManagementService;
        this.stateRepository = stateRepository;
        this.nodeSSHFactory = nodeSSHFactory;
        this.secretBox = secretBox;
        this.secretKey = secretKey;
    }

    revealAccountPassword(passwordEncrypted) {
        if (!passwordEncrypted || !this.secretBox || !this.secretKey) return null;
        try {
            return this.secretBox.decrypt(passwordEncrypted, this.secretKey);
        } catch {
            return null;
        }
    }

    async listStates() {
        return this.RelayL2tpState.find({}).lean();
    }

    async listRelayNodes() {
        const nodes = await this.HyNode.find({ cascadeRole: 'relay' }).lean();
        const relays = (nodes || []).filter(node => nodeRole(node) === 'relay');
        // Nodes re-roled away from relay (e.g. after a topology rebuild) keep
        // their installed L2TP state and must stay listed so the operator can
        // still uninstall them.
        const states = (await this.listStates())
            .filter(state => state.status === 'installed' || state.desiredState === 'installed');
        const known = new Set(relays.map(node => entityId(node._id)));
        const orphanedIds = (states || [])
            .map(state => entityId(state.node))
            .filter(nodeId => nodeId && !known.has(nodeId));
        if (orphanedIds.length > 0) {
            const orphans = await this.HyNode.find({ _id: { $in: orphanedIds } }).lean();
            for (const node of orphans || []) {
                relays.push(node);
                known.add(entityId(node._id));
            }
        }
        return relays;
    }

    async listAccounts() {
        const users = await this.L2tpUser.find({})
            .select('relayNode login ip enabled syncStatus desiredRevision +passwordEncrypted')
            .lean();
        return safeAccountUsers(users || []);
    }

    async overview() {
        const [nodes, states, accounts] = await Promise.all([
            this.listRelayNodes(),
            this.listStates(),
            this.listAccounts(),
        ]);
        const stateByNode = new Map(states.map(state => [entityId(state.node), state]));
        const relays = [];
        for (const node of nodes) {
            const nodeId = entityId(node._id);
            const state = stateByNode.get(nodeId);
            let psk = null;
            // pskEncrypted is schema-hidden (select: false), so its presence
            // cannot be checked here — attempt to reveal for every configured
            // relay and treat decryption/absence failures as "no PSK yet".
            if (state?.desiredState === 'installed') {
                try {
                    psk = (await this.stateManagementService.revealPsk(nodeId)).psk;
                } catch {
                    psk = null;
                }
            }
            relays.push({
                id: nodeId,
                name: typeof node.name === 'string' && node.name.length > 0 ? node.name : nodeId,
                ip: typeof node.ip === 'string' ? node.ip : '',
                online: node.status === 'online',
                installed: state?.status === 'installed',
                configured: state?.desiredState === 'installed',
                status: state?.status ?? 'not_installed',
                psk,
            });
        }
        const nodeNames = new Map(relays.map(relay => [relay.id, relay.name]));
        const passwords = new Map();
        const grouped = new Map();
        for (const account of accounts) {
            if (!passwords.has(account.login)) {
                passwords.set(
                    account.login,
                    this.revealAccountPassword(account.passwordEncrypted),
                );
            }
            const entry = grouped.get(account.login) ?? {
                login: account.login,
                password: passwords.get(account.login),
                relays: [],
                pending: false,
            };
            entry.relays.push({
                nodeId: account.relayNode,
                name: nodeNames.get(account.relayNode) ?? account.relayNode,
                ip: account.ip,
                syncStatus: account.syncStatus,
            });
            if (account.syncStatus !== 'synced') entry.pending = true;
            grouped.set(account.login, entry);
        }
        return {
            relays,
            accounts: [...grouped.values()].sort((a, b) => a.login.localeCompare(b.login)),
        };
    }

    // Walks linear cascade links away from the relay until a bridge node is
    // reached; branches or loops reject automatic group creation.
    async buildAutoGroupPaths(nodeId) {
        if (!this.CascadeLink || typeof this.CascadeLink.find !== 'function') {
            throw simpleError(
                'ROUTE_GROUP_REQUIRED',
                'No L2TP route group exists and cascade links are unavailable',
            );
        }
        const links = await this.CascadeLink.find({}).lean();
        const byPortal = new Map();
        for (const link of links || []) {
            const portal = entityId(link.portalNode);
            if (!byPortal.has(portal)) byPortal.set(portal, []);
            byPortal.get(portal).push(link);
        }
        const ordered = [];
        let current = String(nodeId);
        const visited = new Set([current]);
        for (let hop = 0; hop < MAX_GROUP_WALK_HOPS; hop += 1) {
            const candidates = byPortal.get(current) ?? [];
            if (candidates.length === 0) break;
            let link = candidates[0];
            if (candidates.length > 1) {
                // Geo-routing links are side branches off the main chain: the
                // automatic L2TP path always follows the default (non-geo) hop.
                const mainHops = candidates.filter(candidate => candidate?.geoRouting?.enabled !== true);
                if (mainHops.length === 1) {
                    link = mainHops[0];
                } else {
                    throw simpleError(
                        'ROUTE_GROUP_AMBIGUOUS',
                        'Automatic L2TP route group creation needs a linear cascade chain',
                    );
                }
            }
            ordered.push(link._id);
            current = entityId(link.bridgeNode);
            if (visited.has(current)) {
                throw simpleError(
                    'ROUTE_GROUP_AMBIGUOUS',
                    'Automatic L2TP route group creation detected a cascade loop',
                );
            }
            visited.add(current);
            const nextNode = await this.HyNode.findById(current).lean();
            if (nodeRole(nextNode) === 'bridge') break;
        }
        if (ordered.length === 0) {
            throw simpleError(
                'ROUTE_GROUP_REQUIRED',
                'No L2TP route group exists and no cascade link leaves this relay',
            );
        }
        return [{
            pathKey: AUTO_GROUP_PATH_KEY,
            linkIds: ordered,
            priority: 1,
            enabled: true,
        }];
    }

    async ensureRouteGroup(nodeId) {
        const groups = await this.CascadeRouteGroup.find({}).sort({ name: 1, _id: 1 }).lean();
        if (Array.isArray(groups) && groups.length > 0) {
            return entityId(groups[0]._id);
        }
        const paths = await this.buildAutoGroupPaths(nodeId);
        const created = await this.CascadeRouteGroup.create({
            name: AUTO_GROUP_NAME,
            mode: 'reverse',
            strategy: 'priority-failover',
            paths,
        });
        await this.stateRepository.advanceTopologyRevision?.();
        return entityId(created?._id);
    }

    async installRelay(nodeId) {
        const selectedNodeId = entityId(nodeId);
        const node = await this.HyNode.findById(selectedNodeId).lean();
        if (!node) {
            throw simpleError('NODE_NOT_FOUND', 'L2TP node was not found');
        }
        if (nodeRole(node) !== 'relay') {
            throw simpleError('NODE_NOT_RELAY', 'L2TP can only be managed on relay nodes');
        }

        const states = await this.listStates();
        let state = states.find(entry => entityId(entry.node) === selectedNodeId);
        let routeGroupId = state?.routeGroup ? entityId(state.routeGroup) : null;
        if (routeGroupId) {
            // The pinned group may have been deleted together with cascade
            // links — fall back to (re)creating a group instead of failing
            // with ROUTE_GROUP_NOT_FOUND deep inside the install pipeline.
            const existing = await this.CascadeRouteGroup.findById(routeGroupId).lean();
            if (!existing) routeGroupId = null;
        }
        if (!routeGroupId) {
            routeGroupId = await this.ensureRouteGroup(selectedNodeId);
        }
        if (routeGroupId) {
            await this.ensureRelayGroupPath(selectedNodeId, routeGroupId);
        }

        if (!state || state.desiredState !== 'installed') {
            // Fresh relay or one whose state was reset by uninstall. Reuse the
            // network layout already assigned to this relay (the state record
            // survives uninstall) so existing accounts keep their pinned IPs.
            // For a truly fresh state, prefer the subnet of accounts that
            // already exist for this relay before picking a new octet.
            const input = state?.clientCidr
                ? {
                    clientCidr: state.clientCidr,
                    localAddress: state.localAddress,
                    poolStart: state.poolStart,
                    poolEnd: state.poolEnd,
                    dnsServers: state.dnsServers,
                    tproxyPort: state.tproxyPort,
                    fwmark: state.fwmark,
                    routeTable: state.routeTable,
                    routeGroupId,
                    generatePsk: true,
                }
                : autoDesiredInput(
                    selectedNodeId,
                    states,
                    routeGroupId,
                    await this.preferredThirdOctet(selectedNodeId),
                );
            await this.stateManagementService.configureRelay(
                selectedNodeId,
                input,
            );
        } else if (!state.routeGroup) {
            await this.stateManagementService.configureRelay(selectedNodeId, {
                clientCidr: state.clientCidr,
                localAddress: state.localAddress,
                poolStart: state.poolStart,
                poolEnd: state.poolEnd,
                dnsServers: state.dnsServers,
                tproxyPort: state.tproxyPort,
                fwmark: state.fwmark,
                routeTable: state.routeTable,
                routeGroupId,
                generatePsk: true,
            });
        }

        state = (await this.listStates())
            .find(entry => entityId(entry.node) === selectedNodeId);
        if (!state) {
            throw simpleError('L2TP_NOT_CONFIGURED', 'The relay L2TP state was not stored');
        }
        await this.inheritAccounts(selectedNodeId, state);

        const topologyRevision = await this.stateRepository.getTopologyRevision();
        return this.l2tpService.install(selectedNodeId, {
            routeGroupId,
            expectedTopologyRevision: topologyRevision,
        });
    }

    // Every relay gets its own path inside the shared group: the compiler
    // derives each relay's egress plan from the path whose first link starts
    // at that relay. A group auto-created for one relay therefore does not
    // serve another relay mid-chain until its suffix path is appended.
    // Caveat: the compiler also derives *suffix* candidates, so one long path
    // covers every downstream relay — overlapping paths at equal priority
    // block selection with DUPLICATE_PRIORITY. Keep exactly one (longest)
    // path covering each relay.
    async ensureRelayGroupPath(nodeId, routeGroupId) {
        const group = await this.CascadeRouteGroup.findById(routeGroupId).lean();
        if (!group) return;
        let wanted;
        try {
            [wanted] = await this.buildAutoGroupPaths(nodeId);
        } catch (error) {
            // No cascade chain currently leaves this relay — keep the group
            // untouched instead of failing the install.
            if (error instanceof L2tpSimpleError && error.code === 'ROUTE_GROUP_REQUIRED') {
                return;
            }
            throw error;
        }
        const wantedIds = (wanted?.linkIds || []).map(String);
        if (wantedIds.length === 0
            || typeof this.CascadeRouteGroup.findByIdAndUpdate !== 'function') {
            return;
        }
        const existing = Array.isArray(group.paths) ? group.paths : [];
        const linkIdsOf = path => (path?.linkIds || []).map(String);

        const covering = existing.filter(path => linkIdsOf(path).includes(wantedIds[0]));
        if (covering.length === 1 && existing.length === 1) return; // clean coverage
        if (covering.length > 0) {
            // The relay is covered, possibly by several overlapping paths —
            // keep only the longest (most upstream) covering path.
            const best = covering.reduce((a, b) => (
                linkIdsOf(b).length > linkIdsOf(a).length ? b : a
            ));
            const finalPaths = existing.filter(path => !covering.includes(path) || path === best);
            if (finalPaths.length !== existing.length) {
                await this.CascadeRouteGroup.findByIdAndUpdate(routeGroupId, {
                    $set: { paths: finalPaths },
                });
                await this.stateRepository.advanceTopologyRevision?.();
            }
            return;
        }

        // No coverage: append this relay's path and drop any existing path
        // that starts strictly inside it — those are now suffix-covered.
        const kept = existing.filter(path => !wantedIds.slice(1).includes(linkIdsOf(path)[0]));
        const usedKeys = new Set(kept.map(path => path?.pathKey));
        const pathKey = usedKeys.has(wanted.pathKey)
            ? `${wanted.pathKey}-${String(nodeId).slice(-6)}`
            : wanted.pathKey;
        await this.CascadeRouteGroup.findByIdAndUpdate(routeGroupId, {
            $set: { paths: [...kept, { ...wanted, pathKey }] },
        });
        await this.stateRepository.advanceTopologyRevision?.();
    }

    // Rebuilds the relay route group paths when a topology change (e.g. a
    // deleted cascade link stripped them) left the group empty and a chain
    // is available again.
    async refreshEmptyRouteGroup(nodeId, routeGroupId) {
        const groups = await this.CascadeRouteGroup.find({}).lean();
        const group = (groups || []).find(entry => entityId(entry) === routeGroupId);
        if (!group || (group.paths || []).length > 0) return;
        let paths;
        try {
            paths = await this.buildAutoGroupPaths(nodeId);
        } catch (error) {
            // No cascade chain currently leaves this relay — keep the group
            // empty instead of failing the install.
            if (error instanceof L2tpSimpleError && error.code === 'ROUTE_GROUP_REQUIRED') {
                return;
            }
            throw error;
        }
        if (!paths.length || typeof this.CascadeRouteGroup.findByIdAndUpdate !== 'function') {
            return;
        }
        await this.CascadeRouteGroup.findByIdAndUpdate(routeGroupId, { $set: { paths } });
        await this.stateRepository.advanceTopologyRevision?.();
    }

    // Returns the 10.255.N.x octet shared by every account already pinned to
    // this relay, or null when there are none / they disagree.
    async preferredThirdOctet(nodeId) {
        const accounts = await this.listAccounts();
        const octets = new Set();
        for (const account of accounts) {
            if (account.relayNode !== String(nodeId)) continue;
            const match = /^10\.255\.(\d{1,3})\.\d{1,3}$/.exec(account.ip || '');
            if (match) octets.add(Number(match[1]));
        }
        return octets.size === 1 ? [...octets][0] : null;
    }

    // Copies accounts known on other relays onto this relay before install,
    // reusing the encrypted password (same panel secret key) and allocating
    // a fresh address from this relay's pool. The queued install operation
    // then carries the full user snapshot to the node.
    async inheritAccounts(nodeId, state) {
        const accounts = await this.listAccounts();
        const mine = accounts.filter(account => account.relayNode === String(nodeId));
        const myLogins = new Set(mine.map(account => account.login));
        const takenIps = new Set(mine.map(account => account.ip));
        const byLogin = new Map();
        for (const account of accounts) {
            if (!byLogin.has(account.login)) byLogin.set(account.login, account);
        }
        const fullState = await this.RelayL2tpState.findOne({ node: nodeId }).lean();
        for (const [login, source] of byLogin) {
            if (myLogins.has(login)) continue;
            const sourceDoc = await this.L2tpUser.findOne({
                relayNode: source.relayNode,
                login,
            }).select('passwordEncrypted enabled').lean();
            if (!sourceDoc?.passwordEncrypted) continue;
            const ip = allocateIpv4(state, takenIps);
            takenIps.add(ip);
            await this.userManagementService.importUser(nodeId, {
                login,
                ip,
                enabled: sourceDoc.enabled !== false,
                passwordEncrypted: sourceDoc.passwordEncrypted,
                desiredRevision: fullState?.secretRevision ?? 1,
            });
        }
    }

    async uninstallRelay(nodeId) {
        const selectedNodeId = entityId(nodeId);
        const node = await this.HyNode.findById(selectedNodeId).lean();
        if (!node) {
            throw simpleError('NODE_NOT_FOUND', 'L2TP node was not found');
        }
        const state = await this.RelayL2tpState.findOne({ node: selectedNodeId }).lean();
        // A re-roled node (relay → bridge) keeps its installed L2TP state;
        // teardown must stay possible exactly so decommissioning can proceed.
        if (nodeRole(node) !== 'relay' && state?.status !== 'installed') {
            throw simpleError('NODE_NOT_RELAY', 'L2TP can only be managed on relay nodes');
        }
        if (!state || state.status !== 'installed') {
            throw simpleError('L2TP_NOT_CONFIGURED', 'L2TP is not installed on this relay');
        }

        const ssh = this.nodeSSHFactory(node);
        try {
            const result = await ssh.exec(buildTeardownScript(state));
            const stdout = typeof result === 'string' ? result : result?.stdout ?? '';
            const code = typeof result === 'object' && result !== null ? result.code : 0;
            if ((code ?? 0) !== 0 || !stdout.includes('TEARDOWN_OK')) {
                throw simpleError(
                    'UNINSTALL_FAILED',
                    'The relay L2TP teardown did not complete',
                );
            }
        } catch (error) {
            if (error instanceof L2tpSimpleError) throw error;
            throw simpleError(
                'UNINSTALL_FAILED',
                'The relay L2TP teardown could not reach the node',
            );
        } finally {
            ssh.disconnect?.();
        }

        await this.RelayL2tpState.findOneAndUpdate(
            { node: selectedNodeId },
            { $set: { desiredState: 'not_installed', status: 'not_installed' } },
        );
        return { ok: true };
    }

    async createAccount(input) {
        const login = typeof input?.login === 'string' ? input.login.trim() : '';
        const password = typeof input?.password === 'string' && input.password.length > 0
            ? input.password
            : generateAccountPassword();
        if (!login) {
            throw simpleError('INVALID_INPUT', 'An account login is required');
        }

        const states = (await this.listStates())
            .filter(state => state.status === 'installed');
        if (states.length === 0) {
            throw simpleError(
                'NO_INSTALLED_RELAYS',
                'Install L2TP on at least one relay first',
            );
        }
        const existing = await this.listAccounts();
        const results = [];
        for (const state of states) {
            const nodeId = entityId(state.node);
            const relayUsers = existing.filter(account => account.relayNode === nodeId);
            if (relayUsers.some(account => account.login === login)) {
                results.push({ nodeId, skipped: true });
                continue;
            }
            const takenIps = new Set(relayUsers.map(account => account.ip));
            const ip = allocateIpv4(state, takenIps);
            try {
                await this.userManagementService.createUser(nodeId, {
                    login,
                    ip,
                    password,
                    enabled: true,
                });
                results.push({ nodeId, created: true, ip });
            } catch (error) {
                if (error?.code === 'L2TP_USER_CONFLICT') {
                    results.push({ nodeId, skipped: true });
                    continue;
                }
                throw error;
            }
            existing.push({
                id: '',
                relayNode: nodeId,
                login,
                ip,
                enabled: true,
                syncStatus: 'pending',
            });
        }
        return { login, password, results };
    }

    async deleteAccount(login) {
        const selectedLogin = typeof login === 'string' ? login.trim() : '';
        if (!selectedLogin) {
            throw simpleError('INVALID_INPUT', 'An account login is required');
        }
        const users = await this.L2tpUser.find({ login: selectedLogin }).lean();
        if (!users || users.length === 0) {
            throw simpleError('L2TP_USER_NOT_FOUND', 'The L2TP account was not found');
        }
        const states = (await this.listStates())
            .filter(state => state.status === 'installed');
        const installedNodes = new Set(states.map(state => entityId(state.node)));
        const results = [];
        for (const user of users) {
            const nodeId = entityId(user.relayNode);
            if (installedNodes.has(nodeId)) {
                try {
                    const deleted = await this.userManagementService.deleteUser(
                        nodeId,
                        entityId(user._id),
                    );
                    results.push({ nodeId, deleted: true, syncOperationId: deleted.syncOperationId });
                } catch (error) {
                    // The pinned node may have been re-roled (relay → bridge)
                    // or removed while the account record remained. An orphan
                    // must still be deletable; purge the record instead of
                    // blocking on the stale role check.
                    if (error?.code === 'NODE_NOT_RELAY' || error?.code === 'NODE_NOT_FOUND') {
                        await this.L2tpUser.deleteOne({ _id: user._id });
                        results.push({ nodeId, deleted: true, orphaned: true });
                        continue;
                    }
                    throw error;
                }
            } else {
                await this.L2tpUser.deleteOne({ _id: user._id });
                results.push({ nodeId, deleted: true });
            }
        }
        return { login: selectedLogin, results };
    }
}

module.exports = {
    L2tpSimpleError,
    L2tpSimpleService,
    buildTeardownScript,
    autoDesiredInput,
    allocateIpv4,
};
