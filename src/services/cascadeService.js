/**
 * Cascade service — manages Xray reverse-proxy tunnels between nodes.
 *
 * Handles deployment, health checking, and topology retrieval for
 * CascadeLink connections (Portal <-> Bridge pairs).
 */

const net = require('net');
const { randomBytes, createHash } = require('node:crypto');
const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const Settings = require('../models/settingsModel');
const configGenerator = require('./configGenerator');
const { applyClassicL2tpPathIngress, finishClassicConfigRouting } = require('./classicL2tpConfigComposition');
const { mergePreservedL2tpSections } = require('../modules/relay-l2tp/domain/l2tpXrayConfigMerge');
const { APPLIED_LINK_STATUSES, usesTestTopologyConfig, topologyManagesNodeConfig } = require('./topologyConfigOwnership');
const NodeSSH = require('./nodeSSH');
const { withClassicNodeConfigWrite, assertClassicNodeConfigWriteHeld,
    assertHeldL2tpNodeConfigWrite } = require('./classicNodeConfigWrite');
const cache = require('./cacheService');
const logger = require('../utils/logger');
const webhook = require('./webhookService');
const { trackLegacyCascadeUndeploy } = require('../modules/relay-l2tp/services/legacyCascadeUndeploy');

const TOPOLOGY_CACHE_KEY = 'c3:cascade:topology';
const TOPOLOGY_CACHE_TTL = 15;

/**
 * Safe Redis helpers — cache module exposes .redis but may not be connected.
 */
async function cacheGet(key) {
    try { return cache.redis?.get ? await cache.redis.get(key) : null; } catch { return null; }
}
async function cacheSet(key, value, ttl) {
    try { if (cache.redis?.set) await cache.redis.set(key, value, 'EX', ttl); } catch {}
}
async function cacheDel(key) {
    try { if (cache.redis?.del) await cache.redis.del(key); } catch {}
}

function undeployUncertain(message) {
    return Object.assign(new Error(message), { code: 'LEGACY_CASCADE_UNDEPLOY_UNCERTAIN' });
}

// NodeSSH resolves on stream close, including nonzero or absent exit status.
// Require both a zero exit and an invocation-specific foreground completion
// receipt. A timeout/disconnect (or a later successful command) cannot join an
// earlier writer. systemctl commands here intentionally do not use --no-block.
function completionCheckedSSH(node) {
    const ssh = new NodeSSH(node);
    const exec = ssh.exec.bind(ssh);
    const upload = ssh.uploadContent.bind(ssh);
    ssh.uploadContent = async (...args) => {
        await assertClassicNodeConfigWriteHeld(node._id);
        const result = await upload(...args);
        if (result !== undefined) throw undeployUncertain('Upload completion refused');
        await assertClassicNodeConfigWriteHeld(node._id);
        return result;
    };
    ssh.exec = async (command, options) => {
        await assertClassicNodeConfigWriteHeld(node._id);
        const receipt = `C3_LEGACY_DONE_${randomBytes(24).toString('hex')}`;
        const result = await exec(`(
${command}
) && printf '\n${receipt}\n'`, options);
        const suffix = `\n${receipt}\n`;
        if (result?.code !== 0 || typeof result.stdout !== 'string'
            || typeof result.stderr !== 'string' || !result.stdout.endsWith(suffix)) {
            throw undeployUncertain(`Remote completion not proved for ${node.name}`);
        }
        await assertClassicNodeConfigWriteHeld(node._id);
        return { ...result, stdout: result.stdout.slice(0, -suffix.length) };
    };
    return ssh;
}

const SCOPED_MAIN = '/usr/local/etc/xray/config.json';
const SCOPED_BRIDGE = '/usr/local/etc/xray-bridge/config.json';
const SCOPED_PRESERVED_STATUSES = Object.freeze([...APPLIED_LINK_STATUSES, 'offline']);
const scopedFailure = code => Object.assign(new Error(code), { code });
const scopedHash = text => createHash('sha256').update(text).digest('hex');
const scopedId = value => String(value?._id || value);
const shellQuote = text => `'${text.replace(/'/g, `'\\''`)}'`;
// Compare JSON values without changing array/routing order or disclosing bytes.
function scopedCanonical(value) {
    if (Array.isArray(value)) return `[${value.map(scopedCanonical).join(',')}]`;
    if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key =>
        `${JSON.stringify(key)}:${scopedCanonical(value[key])}`).join(',')}}`;
    return JSON.stringify(value);
}
function scopedConfig(text) {
    try {
        const value = JSON.parse(text);
        if (!value || typeof value !== 'object' || !Array.isArray(value.outbounds)
            || !Array.isArray(value.routing?.rules) || (value.inbounds && !Array.isArray(value.inbounds))) throw new Error();
        return value;
    } catch { throw scopedFailure('CLASSIC_SCOPED_CONFIG_INVALID'); }
}
function scopedContains(rows, expected) {
    return rows?.some(row => scopedCanonical(row) === scopedCanonical(expected));
}
function scopedScopePin(scope) {
    const linkPin = link => {
        const pin = { ...link, _id: scopedId(link),
            portalNode: { _id: scopedId(link.portalNode), ip: link.portalNode?.ip },
            bridgeNode: { _id: scopedId(link.bridgeNode), ip: link.bridgeNode?.ip } };
        for (const key of ['lastHealthCheck', 'latencyMs', 'lastError', 'updatedAt', 'createdAt']) delete pin[key];
        // readScope validates status membership on every observation. Health is
        // independently mutable for the target too, not configuration identity.
        delete pin.status;
        return pin;
    };
    return scopedCanonical({ target: linkPin(scope.target),
        confirmed: scope.confirmed.map(link => linkPin(link)).sort((a, b) => a._id.localeCompare(b._id)) });
}
function scopedSourceHost(value) {
    if (typeof value !== 'string') return false;
    if (net.isIP(value)) return true;
    // Existing panel nodes support DNS SSH endpoints. Preserve the stored
    // source name in SSH/JSON; only the bridge enters the shell socket filter.
    const labels = value.split('.');
    return value.length <= 253 && labels.length > 1
        && /[A-Za-z]/.test(labels.at(-1))
        && labels.every(label => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label));
}
function scopedNodePin(node) {
    return scopedCanonical({ _id: scopedId(node), ip: node?.ip, active: node?.active,
        type: node?.type, cascadeRole: node?.cascadeRole, ssh: node?.ssh,
        clientTags: [node?.xray?.inboundTag, ...(node?.xray?.extraInbounds || []).map(row => row.inboundTag)] });
}

class CascadeService {
    /**
     * Completion-checked classic no-upstream Relay -> terminal Bridge only.
     * Caller MUST hold the nonexpiring topology reservation at this exact
     * revision and retain it on every throw. baselineLinkIds is the complete
     * active APPLIED/offline connected-component preservation baseline.
     * This entry never acquires topology adoption or native operation identity.
     */
    async deployScopedClassicLink({ linkId, expectedTopologyRevision, baselineLinkIds } = {}) {
        return this.#scopedClassicLink({ linkId, expectedTopologyRevision, baselineLinkIds });
    }

    /**
     * Checked inverse for an exactly present scoped reverse link. The caller
     * holds the topology reservation through this receipt and subsequent draft
     * deletion, retaining it on every throw. No DB row/status is changed here.
     * An absent/partial target is NOT an idempotent removal proof.
     */
    async removeScopedClassicLink({ linkId, expectedTopologyRevision, baselineLinkIds } = {}) {
        return this.#scopedClassicLink({ linkId, expectedTopologyRevision, baselineLinkIds, remove: true });
    }

    async #scopedClassicLink({ linkId, expectedTopologyRevision, baselineLinkIds, remove = false }) {
        const id = value => typeof value === 'string' && /^[a-f0-9]{24}$/.test(value);
        if (!id(linkId) || !Number.isSafeInteger(expectedTopologyRevision) || expectedTopologyRevision < 0
            || !Array.isArray(baselineLinkIds) || !baselineLinkIds.every(id)
            || new Set(baselineLinkIds).size !== baselineLinkIds.length || baselineLinkIds.includes(linkId)) {
            throw Object.assign(new Error('CLASSIC_SCOPED_INPUT_INVALID'), { code: 'CLASSIC_SCOPED_INPUT_INVALID' });
        }
        // Capture policy before the first await. This path never calls deployLink,
        // full-config generators, path-ingress composition, an installer or agent.
        const env = Object.freeze({ ...process.env });
        const baseline = Object.freeze([...baselineLinkIds].sort());
        try {
            const initial = await CascadeLink.findById(linkId).setOptions({ maxTimeMS: 5000 }).lean();
            if (!initial || initial.active !== true || (initial.mode || 'reverse') !== 'reverse') {
                throw scopedFailure('CLASSIC_SCOPED_REVERSE_LINK_REQUIRED');
            }
            const ids = [scopedId(initial.portalNode), scopedId(initial.bridgeNode)].sort();
            if (!ids.every(id) || ids[0] === ids[1]) throw scopedFailure('CLASSIC_SCOPED_ENDPOINT_INVALID');
            let result;
            await withClassicNodeConfigWrite({ nodeId: ids[0], kind: 'scoped-reverse', env, leaseMs: 120000 }, async () => {
                await withClassicNodeConfigWrite({ nodeId: ids[1], kind: 'scoped-reverse', env, leaseMs: 120000 }, async () => {
                    result = await this.#deployScopedClassicHeld({ linkId, expectedTopologyRevision, baseline, ids, remove });
                    return true;
                });
                return true;
            });
            return result;
        } catch (error) {
            // Never forward transport, generated config, credential or journal text.
            const code = typeof error?.code === 'string'
                && /^(CLASSIC_SCOPED_[A-Z_]+|CLASSIC_CONFIG_WRITE_[A-Z_]+|NODE_OPERATION_LOCK_CONFLICT)$/.test(error.code)
                ? error.code : 'CLASSIC_SCOPED_COMPLETION_UNCERTAIN';
            throw scopedFailure(code);
        }
    }

    async #deployScopedClassicHeld({ linkId, expectedTopologyRevision, baseline, ids, remove }) {
        const started = performance.now();
        const checkHeld = async () => {
            if (performance.now() - started >= 100000) throw scopedFailure('CLASSIC_SCOPED_DEADLINE');
            // Unlike assertClassic..., this refuses an authorization-disabled no-op.
            for (const nodeId of ids) await assertHeldL2tpNodeConfigWrite(nodeId);
        };
        const bounded = async (work, ms = 15000) => {
            let timer;
            try {
                return await Promise.race([work(), new Promise((_, reject) => {
                    timer = setTimeout(() => reject(scopedFailure('CLASSIC_SCOPED_COMPLETION_UNCERTAIN')), ms);
                })]);
            } finally { clearTimeout(timer); }
        };
        const State = require('../modules/relay-l2tp/models/cascadeTopologyStateModel');
        const revision = async () => {
            await checkHeld();
            const state = await State.findById('singleton').setOptions({ maxTimeMS: 5000,
                readPreference: 'primary', readConcern: { level: 'majority' } }).lean();
            if (state?.revision !== expectedTopologyRevision) throw scopedFailure('CLASSIC_SCOPED_REVISION_CONFLICT');
        };
        const readScope = async () => {
            await revision();
            const rows = await CascadeLink.find({ active: true, $or: [
                { _id: linkId }, { status: { $in: [...APPLIED_LINK_STATUSES, 'offline'] } },
            ] }).populate('portalNode bridgeNode').setOptions({ maxTimeMS: 5000 }).lean();
            const target = rows.find(row => scopedId(row) === linkId);
            // Match the public connected-component baseline, never all global links.
            const visited = new Set(ids), selected = new Set();
            let grew = true;
            while (grew) {
                grew = false;
                for (const row of rows) {
                    if (scopedId(row) === linkId || row.active !== true || !SCOPED_PRESERVED_STATUSES.includes(row.status)) continue;
                    const endpoints = [scopedId(row.portalNode), scopedId(row.bridgeNode)];
                    if (!endpoints.some(id => visited.has(id))) continue;
                    selected.add(scopedId(row));
                    for (const id of endpoints) if (!visited.has(id)) { visited.add(id); grew = true; }
                }
            }
            const confirmed = rows.filter(row => selected.has(scopedId(row)));
            if (!target || target.active !== true || (target.mode || 'reverse') !== 'reverse'
                || !['pending', 'error', ...SCOPED_PRESERVED_STATUSES].includes(target.status)
                || !Number.isSafeInteger(target.tunnelPort) || target.tunnelPort < 1 || target.tunnelPort > 65535
                || typeof target.tunnelUuid !== 'string' || !target.tunnelUuid) throw scopedFailure('CLASSIC_SCOPED_TARGET_INVALID');
            if (confirmed.some(row => row.active !== true || typeof row.status !== 'string'
                || !SCOPED_PRESERVED_STATUSES.includes(row.status))) throw scopedFailure('CLASSIC_SCOPED_BASELINE_CONFLICT');
            const actual = confirmed.map(scopedId).sort();
            if (scopedCanonical(actual) !== scopedCanonical(baseline)) throw scopedFailure('CLASSIC_SCOPED_BASELINE_CONFLICT');
            const endpoints = [scopedId(target.portalNode), scopedId(target.bridgeNode)].sort();
            if (scopedCanonical(endpoints) !== scopedCanonical(ids)) throw scopedFailure('CLASSIC_SCOPED_ENDPOINT_DRIFT');
            // Only current no-upstream Relay -> terminal Bridge is supported.
            // Do not silently omit or regenerate a reverse transit profile.
            const sourceId = scopedId(target.portalNode), bridgeId = scopedId(target.bridgeNode);
            const touches = row => [sourceId, bridgeId].some(node =>
                scopedId(row.portalNode) === node || scopedId(row.bridgeNode) === node);
            if (confirmed.some(row => touches(row) && row.mode === 'forward')) throw scopedFailure('CLASSIC_SCOPED_FORWARD_DEPENDENCY_UNSUPPORTED');
            if (confirmed.some(row => scopedId(row.bridgeNode) === sourceId)) throw scopedFailure('CLASSIC_SCOPED_REVERSE_UPSTREAM_UNSUPPORTED');
            if (confirmed.some(row => scopedId(row.portalNode) === sourceId)) throw scopedFailure('CLASSIC_SCOPED_SHARED_SOURCE_UNSUPPORTED');
            if (confirmed.some(row => scopedId(row.portalNode) === bridgeId)) throw scopedFailure('CLASSIC_SCOPED_TRANSIT_BRIDGE_UNSUPPORTED');
            const l2tp = require('../modules/relay-l2tp/models/relayL2tpStateModel');
            if (await l2tp.exists({ $or: [{ desiredState: 'installed' }, { status: { $ne: 'not_installed' } }] })
                .setOptions({ maxTimeMS: 5000 })) throw scopedFailure('CLASSIC_SCOPED_L2TP_UNSUPPORTED');
            return { target, confirmed };
        };
        const scope = await readScope();
        const scopePin = scopedScopePin(scope);
        const source = await HyNode.findById(scopedId(scope.target.portalNode)).setOptions({ maxTimeMS: 5000 }).lean();
        const bridge = await HyNode.findById(scopedId(scope.target.bridgeNode)).setOptions({ maxTimeMS: 5000 }).lean();
        if (source?.type !== 'xray' || source?.cascadeRole !== 'relay' || source.active !== true
            || !bridge || bridge.active !== true || !scopedSourceHost(source.ip) || !net.isIP(bridge.ip || '')
            || [source, bridge].some(node => !node.ssh?.password && !node.ssh?.privateKey)) {
            throw scopedFailure('CLASSIC_SCOPED_ENDPOINT_UNSUPPORTED');
        }
        const nodePins = [source, bridge].map(scopedNodePin);
        const checkNodePins = async () => {
            await checkHeld();
            for (const [index, node] of [source, bridge].entries()) {
                const fresh = await HyNode.findById(scopedId(node)).setOptions({ maxTimeMS: 5000 }).lean();
                if (scopedNodePin(fresh) !== nodePins[index]) throw scopedFailure('CLASSIC_SCOPED_ENDPOINT_DRIFT');
            }
        };
        const transports = new Map();
        const exec = async (node, command, stdin) => {
            await checkHeld();
            const marker = `C3_SCOPED_DONE_${randomBytes(24).toString('hex')}`;
            // A local timeout is NOT cancellation/quiescence. Its throw retains
            // both uncertain generations; no retry, rollback or later release.
            const remote = `timeout --signal=TERM --kill-after=2s 10s sh -c ${shellQuote(`set -eu\n${command}`)} && printf '\\n${marker}\\n'`;
            const result = await bounded(() => transports.get(scopedId(node)).exec(remote,
                { timeout: 13000, ...(stdin !== undefined && { stdin }) }));
            const suffix = `\n${marker}\n`;
            if (result?.code !== 0 || typeof result.stdout !== 'string' || typeof result.stderr !== 'string'
                || !result.stdout.endsWith(suffix) || result.stdout.length > 1100000) throw scopedFailure('CLASSIC_SCOPED_COMPLETION_UNCERTAIN');
            await checkHeld();
            return result.stdout.slice(0, -suffix.length);
        };
        const readConfig = (node, file) => exec(node, `# C3_READ_CONFIG\nif test -e ${file}; then\n test -f ${file} && test ! -L ${file} && test "$(stat -c %s ${file})" -le 1048576 && cat ${file}\nelse\n printf C3_CONFIG_ABSENT\nfi`);
        const readProfile = async (node, file) => {
            const bytes = await readConfig(node, file);
            const service = file === SCOPED_MAIN ? 'xray' : 'xray-bridge';
            const observed = bytes === 'C3_CONFIG_ABSENT' ? null
                : await exec(node, `systemctl show ${service} --property=ActiveState --property=MainPID --property=FragmentPath --property=DropInPaths --property=NeedDaemonReload --property=ExecStart && systemctl cat ${service}`);
            // ExecStart's runtime PID/timestamps change on restart. Pin its
            // loaded argv independently of unit-file text, retaining the stable
            // unit/drop-in bytes and all other observed service properties.
            const loaded = observed?.match(/^ExecStart=\{ path=([^;]+) ; argv\[\]=([^;]+) ;[^\n]*$/m);
            const stable = observed?.replace(/^MainPID=\d+\n/m, '');
            const unit = loaded ? stable.replace(loaded[0], `LoadedExecStart=${loaded[1].trim()}|${loaded[2].trim()}`) : stable;
            // Preserve runtime identity on untouched profiles, but permit expected
            // PID/timestamp changes only on explicitly restarted plan entries.
            return { bytes, unit, runtime: [observed?.match(/^MainPID=\d+$/m)?.[0] || null, loaded?.[0] || null],
                loaded: loaded ? [loaded[1].trim(), loaded[2].trim()] : null };
        };
        try {
            // Select checked SSH for both nodes before any configuration dispatch.
            for (const node of [source, bridge]) {
                await checkHeld();
                const ssh = new NodeSSH(node); transports.set(scopedId(node), ssh);
                await bounded(() => ssh.connect(), 10000);
                await checkHeld();
            }
            const mainBefore = await readProfile(source, SCOPED_MAIN);
            const bridgeBefore = await readProfile(bridge, SCOPED_BRIDGE);
            const preserved = [
                { node: source, file: SCOPED_BRIDGE, profile: await readProfile(source, SCOPED_BRIDGE) },
                { node: bridge, file: SCOPED_MAIN, profile: await readProfile(bridge, SCOPED_MAIN) },
            ];
            for (const [profile, file] of [[mainBefore, SCOPED_MAIN], [bridgeBefore, SCOPED_BRIDGE]]) {
                if (!profile.unit?.includes('ActiveState=active\n') || !profile.unit.includes('NeedDaemonReload=no\n')
                    || scopedCanonical(profile.loaded) !== scopedCanonical(['/usr/local/bin/xray', `/usr/local/bin/xray run -config ${file}`])) {
                    throw scopedFailure('CLASSIC_SCOPED_SERVICE_LAYOUT_UNSUPPORTED');
                }
            }
            const main = scopedConfig(mainBefore.bytes), combined = scopedConfig(bridgeBefore.bytes);
            const target = { ...scope.target, portalNode: source, bridgeNode: bridge };
            const targetSuffix = linkId.slice(-8), forwardTag = `fwd-${targetSuffix}`, hopTag = `fwd-hop-${targetSuffix}`;
            const targetMainItem = preserved.find(item => scopedId(item.node) === scopedId(bridge));
            const targetMain = targetMainItem.profile.bytes === 'C3_CONFIG_ABSENT' ? null : scopedConfig(targetMainItem.profile.bytes);
            const configuredTags = [source.xray?.inboundTag || 'vless-in',
                ...(source.xray?.extraInbounds || []).map(row => row.inboundTag).filter(Boolean)];
            let clientTags = [...configuredTags];
            const oldOutbound = main.outbounds.filter(row => row.tag === forwardTag);
            const oldHop = targetMain?.inbounds?.filter(row => row.tag === hopTag) || [];
            if (remove && (oldOutbound.length || oldHop.length)) throw scopedFailure('CLASSIC_SCOPED_OLD_FORWARD_MISMATCH');
            // Derive migration ingress ONLY from exact old target routes, including
            // preserved path SOCKS ingress. Never route arbitrary service inbounds.
            if (oldOutbound.length || oldHop.length) {
                const priorSecurity = oldOutbound[0]?.streamSettings?.security;
                if (!['none', 'reality', 'tls'].includes(priorSecurity)
                    || oldHop[0]?.streamSettings?.security !== priorSecurity) {
                    throw scopedFailure('CLASSIC_SCOPED_OLD_FORWARD_MISMATCH');
                }
                // The saved reverse settings describe the desired next config,
                // not the old transport. Infer only its finite security enum;
                // still compare both full fragments against persisted keys,
                // UUID/port/endpoints and every other canonical transport field.
                const priorTarget = { ...target, tunnelSecurity: priorSecurity };
                const expected = { inbounds: [], outbounds: [], routing: { rules: [] } };
                configGenerator.applyForwardChain(expected, [priorTarget], configuredTags);
                const routes = main.routing.rules.filter(row => row.outboundTag === forwardTag);
                const tags = routes.flatMap(row => row.inboundTag || []);
                if (oldOutbound.length !== 1 || oldHop.length !== 1
                    || !scopedContains(expected.outbounds, oldOutbound[0]) || !routes.length
                    || routes.some(row => !Array.isArray(row.inboundTag) || !row.inboundTag.length
                        || scopedCanonical(row) !== scopedCanonical({ type: 'field', inboundTag: row.inboundTag, outboundTag: forwardTag }))
                    || new Set(tags).size !== tags.length || configuredTags.some(tag => !tags.includes(tag))) {
                    throw scopedFailure('CLASSIC_SCOPED_OLD_FORWARD_MISMATCH');
                }
                clientTags = tags;
                main.outbounds = main.outbounds.filter(row => row.tag !== forwardTag);
                main.routing.rules = main.routing.rules.filter(row => row.outboundTag !== forwardTag);
                const hop = { inbounds: [], routing: { rules: [] } };
                configGenerator.applyForwardHopInbound(hop, [priorTarget]);
                const hopRules = targetMain.routing.rules.filter(row => row.inboundTag?.includes(hopTag));
                if (!scopedContains(hop.inbounds, oldHop[0]) || scopedCanonical(hopRules) !== scopedCanonical(hop.routing.rules)) {
                    throw scopedFailure('CLASSIC_SCOPED_OLD_FORWARD_MISMATCH');
                }
                targetMain.inbounds = targetMain.inbounds.filter(row => row.tag !== hopTag);
                targetMain.routing.rules = targetMain.routing.rules.filter(row => !row.inboundTag?.includes(hopTag));
                // No hidden references to the retired transport may survive.
                if ([main, targetMain].some(config => JSON.stringify(config).includes(forwardTag)
                    || JSON.stringify(config).includes(hopTag))) throw scopedFailure('CLASSIC_SCOPED_OLD_FORWARD_MISMATCH');
            } else {
                const existingClient = main.routing.rules.filter(row => row.outboundTag === `portal-${targetSuffix}` && !row.domain);
                if (existingClient.length) {
                    clientTags = existingClient.flatMap(row => row.inboundTag || []);
                    if (new Set(clientTags).size !== clientTags.length || configuredTags.some(tag => !clientTags.includes(tag))) {
                        throw scopedFailure('CLASSIC_SCOPED_MAIN_INGRESS_MISMATCH');
                    }
                }
            }
            if (clientTags.some(tag => typeof tag !== 'string' || main.inbounds?.filter(row => row.tag === tag).length !== 1)) {
                throw scopedFailure('CLASSIC_SCOPED_MAIN_INGRESS_MISMATCH');
            }
            const portalDelta = { inbounds: [], outbounds: [], routing: { rules: [] } };
            configGenerator.applyReversePortal(portalDelta, [target], clientTags);
            const bridgeDelta = JSON.parse(configGenerator.generateCombinedBridgeConfig([target]));
            let priorPortalDelta = portalDelta, priorBridgeDelta = bridgeDelta;
            const oldListeners = main.inbounds.filter(row => row.tag === `bridge-conn-${targetSuffix}`);
            if (!remove && target.tunnelSecurity === 'reality' && oldListeners.length) {
                const stream = oldListeners[0].streamSettings, reality = stream?.realitySettings;
                const dest = typeof reality?.dest === 'string'
                    ? reality.dest.match(/^(?:\[([0-9a-fA-F:]+)\]|([^:\[\]]+)):([1-9]\d{0,4})$/) : null;
                if (oldListeners.length !== 1 || stream?.security !== 'reality' || !dest
                    || Number(dest[3]) > 65535 || (dest[1] ? net.isIP(dest[1]) !== 6 : !scopedSourceHost(dest[2]))
                    || !Array.isArray(reality.serverNames) || !reality.serverNames.length
                    || reality.serverNames.some(name => !scopedSourceHost(name) || net.isIP(name))
                    || new Set(reality.serverNames).size !== reality.serverNames.length) {
                    throw scopedFailure('CLASSIC_SCOPED_LISTENER_OR_TAG_CONFLICT');
                }
                // Only decoy fields may come from the old listener, and only for
                // ownership validation. Regenerate BOTH complete prior fragments
                // from persisted credentials/transport: the bridge's old client
                // SNI must match the listener's first serverName exactly. Never
                // use these prior deltas when composing the desired configs.
                const priorTarget = { ...target, realityDest: reality.dest, realitySni: reality.serverNames };
                priorPortalDelta = { inbounds: [], outbounds: [], routing: { rules: [] } };
                configGenerator.applyReversePortal(priorPortalDelta, [priorTarget], clientTags);
                priorBridgeDelta = JSON.parse(configGenerator.generateCombinedBridgeConfig([priorTarget]));
            }
            // On replay remove only a COMPLETE exact generated target fragment.
            // A partial/duplicate/foreign collision must never be treated as ours.
            const stripOwnedReverse = (config, delta) => {
                const sections = [ ['inbounds', config, delta], ['outbounds', config, delta],
                    ['portals', config.reverse || {}, delta.reverse || {}],
                    ['bridges', config.reverse || {}, delta.reverse || {}], ['rules', config.routing, delta.routing] ];
                const owned = row => JSON.stringify(row).includes(targetSuffix);
                const present = sections.some(([key, from]) => (from[key] || []).some(owned));
                if (!present) return false;
                for (const [key, from, expected] of sections) {
                    const actual = (from[key] || []).filter(owned), wanted = (expected[key] || []).filter(owned);
                    if (actual.length !== wanted.length || wanted.some(row => actual.filter(item => scopedCanonical(item) === scopedCanonical(row)).length !== 1)) {
                        throw scopedFailure('CLASSIC_SCOPED_LISTENER_OR_TAG_CONFLICT');
                    }
                }
                for (const [key, from] of sections) if (from[key]) from[key] = from[key].filter(row => !owned(row));
                return true;
            };
            const portalApplied = stripOwnedReverse(main, priorPortalDelta);
            const bridgeApplied = stripOwnedReverse(combined, priorBridgeDelta);
            if (portalApplied !== bridgeApplied || (oldOutbound.length && portalApplied)) throw scopedFailure('CLASSIC_SCOPED_LISTENER_OR_TAG_CONFLICT');
            // The caller already proved durable per-link authorization under
            // its topology fence. A never-applied pending draft may be discarded
            // only after the same whole-profile baseline/absence/readback proof;
            // status alone is never physical absence. Applied/error rows need
            // an independent recovery receipt if their fragments disappeared.
            if (remove && !portalApplied && target.status !== 'pending') throw scopedFailure('CLASSIC_SCOPED_REMOVAL_PROOF_MISSING');
            const bridgeBaseline = scope.confirmed.filter(row => scopedId(row.bridgeNode) === scopedId(bridge));
            const representedDomains = bridgeBaseline.map(row =>
                `${scopedId(row).slice(-8)}.${row.tunnelDomain || 'reverse.tunnel.internal'}`).sort();
            if (scopedCanonical((combined.reverse?.bridges || []).map(row => row.domain).sort()) !== scopedCanonical(representedDomains)
                || combined.reverse?.portals?.length) throw scopedFailure('CLASSIC_SCOPED_UNREPRESENTED_BRIDGE_CONFIG');
            const forwardFragment = config => [...(config.inbounds || []), ...config.outbounds]
                .some(row => /^(fwd-|cascade-in-|conn-down-|bridge-conn-)/.test(row.tag || ''));
            if (main.reverse?.portals?.length || main.reverse?.bridges?.length || forwardFragment(main)) {
                throw scopedFailure('CLASSIC_SCOPED_UNREPRESENTED_MAIN_CONFIG');
            }
            if (forwardFragment(combined)) throw scopedFailure('CLASSIC_SCOPED_UNREPRESENTED_BRIDGE_CONFIG');
            // Confirm every established shared-bridge tunnel before adding a new
            // one. Preserve actual existing rows/extra sections, including old
            // single-tunnel tag conventions, instead of rebuilding from DB alone.
            for (const link of bridgeBaseline) {
                const candidates = [configGenerator.generateCombinedBridgeConfig([link])];
                if (bridgeBaseline.length === 1) candidates.push(configGenerator.generateBridgeConfig(link, link.portalNode));
                if (!candidates.some(text => {
                    const expected = JSON.parse(text);
                    // Attribute the existing link's tunnel and bridge routes,
                    // not newer generator-wide defaults (e.g. IPv6 blackhole).
                    // Existing global rules remain byte-for-byte preserved.
                    const bridgeTags = expected.reverse.bridges.map(row => row.tag);
                    const tunnelTags = expected.outbounds.filter(row => !['freedom', 'blackhole'].includes(row.protocol))
                        .map(row => row.tag);
                    const linkRules = expected.routing.rules.filter(row => tunnelTags.includes(row.outboundTag)
                        || row.inboundTag?.some(tag => bridgeTags.includes(tag)));
                    return expected.reverse.bridges.every(row => scopedContains(combined.reverse?.bridges, row))
                        && expected.outbounds.every(row => scopedContains(combined.outbounds, row))
                        && linkRules.every(row => scopedContains(combined.routing.rules, row));
                })) throw scopedFailure('CLASSIC_SCOPED_SHARED_BRIDGE_BASELINE_MISMATCH');
            }
            const hasCollision = config => [...(config.inbounds || []), ...config.outbounds,
                ...(config.reverse?.bridges || []), ...(config.reverse?.portals || [])].some(row =>
                row.tag?.includes(targetSuffix) || row.port === target.tunnelPort);
            if (hasCollision(main) || hasCollision(combined)) throw scopedFailure('CLASSIC_SCOPED_LISTENER_OR_TAG_CONFLICT');
            for (const item of preserved) {
                if (item.profile.bytes === 'C3_CONFIG_ABSENT') continue;
                let config;
                try { config = JSON.parse(item.profile.bytes); }
                catch { throw scopedFailure('CLASSIC_SCOPED_PRESERVED_PROFILE_INVALID'); }
                // Orphan source transit is preserved, not adopted. It must not
                // already occupy the new main-owned listener on the same host.
                if (scopedId(item.node) === scopedId(source)
                    && config.inbounds?.some(row => Number(row.port) === target.tunnelPort)) {
                    throw scopedFailure('CLASSIC_SCOPED_LISTENER_OR_TAG_CONFLICT');
                }
            }
            if (main.routing.rules.some(row => (!row.inboundTag || row.inboundTag.some(tag => clientTags.includes(tag)))
                && !['domain', 'ip', 'port', 'network', 'protocol', 'source', 'sourcePort', 'user'].some(key => row[key]))) {
                throw scopedFailure('CLASSIC_SCOPED_MAIN_ROUTING_SHADOW_UNSUPPORTED');
            }
            if (remove) {
                // Drop empty reverse sections; preserve all nonempty/unknown
                // sections, global defaults, user inbounds and sibling routes.
                // The last bridge stays active but idle on its validated config;
                // never stop a potentially shared service or touch target MAIN.
                for (const config of portalApplied ? [main, combined] : []) {
                    for (const key of ['portals', 'bridges']) {
                        if (config.reverse?.[key]?.length === 0) delete config.reverse[key];
                    }
                    if (config.reverse && !Object.keys(config.reverse).length) delete config.reverse;
                }
                if ([main, combined, ...preserved.filter(item => item.profile.bytes !== 'C3_CONFIG_ABSENT')
                    .map(item => JSON.parse(item.profile.bytes))].some(config => JSON.stringify(config).includes(targetSuffix))) {
                    throw scopedFailure('CLASSIC_SCOPED_REMOVAL_TARGET_REMAINS');
                }
            } else {
                main.reverse = main.reverse || {};
                main.reverse.portals = [...(main.reverse.portals || []), ...portalDelta.reverse.portals];
                main.inbounds.push(...portalDelta.inbounds);
                const insertRules = (config, rules) => {
                    const index = config.routing.rules.findIndex(row => !row.inboundTag && row.ip?.includes('geoip:private'));
                    config.routing.rules.splice(index < 0 ? config.routing.rules.length : index, 0, ...rules);
                };
                insertRules(main, portalDelta.routing.rules);
                if (portalDelta.routing.domainStrategy) main.routing.domainStrategy = portalDelta.routing.domainStrategy;
                combined.reverse = combined.reverse || {};
                combined.reverse.bridges = [...(combined.reverse.bridges || []), ...bridgeDelta.reverse.bridges];
                for (const outbound of bridgeDelta.outbounds) {
                    const old = combined.outbounds.find(row => row.tag === outbound.tag);
                    if (old && scopedCanonical(old) !== scopedCanonical(outbound)) throw scopedFailure('CLASSIC_SCOPED_BRIDGE_OUTBOUND_CONFLICT');
                    if (!old) combined.outbounds.push(outbound);
                }
                insertRules(combined, bridgeDelta.routing.rules.filter(row => row.domain || row.inboundTag));
            }
            const plans = [
                { node: source, file: SCOPED_MAIN, service: 'xray', before: mainBefore, config: main },
                { node: bridge, file: SCOPED_BRIDGE, service: 'xray-bridge', before: bridgeBefore, config: combined },
            ];
            if (targetMain && !remove) {
                if (hasCollision(targetMain)) throw scopedFailure('CLASSIC_SCOPED_LISTENER_OR_TAG_CONFLICT');
                if (!targetMainItem.profile.unit?.includes('ActiveState=active\n')
                    || !targetMainItem.profile.unit.includes('NeedDaemonReload=no\n')
                    || scopedCanonical(targetMainItem.profile.loaded) !== scopedCanonical(['/usr/local/bin/xray', `/usr/local/bin/xray run -config ${SCOPED_MAIN}`])) {
                    throw scopedFailure('CLASSIC_SCOPED_SERVICE_LAYOUT_UNSUPPORTED');
                }
                plans.push({ node: bridge, file: SCOPED_MAIN, service: 'xray', before: targetMainItem.profile, config: targetMain });
                preserved.splice(preserved.indexOf(targetMainItem), 1);
            }
            for (const plan of plans) {
                plan.bytes = scopedCanonical(plan.config) === scopedCanonical(scopedConfig(plan.before.bytes))
                    ? plan.before.bytes : JSON.stringify(plan.config, null, 2);
            }
            const changedPlans = plans.filter(plan => plan.bytes !== plan.before.bytes);
            if (scopedScopePin(await readScope()) !== scopePin) throw scopedFailure('CLASSIC_SCOPED_SCOPE_DRIFT');
            await checkNodePins();
            // Check every baseline again before the first mutation, including the
            // orphan source transit profile. Neither of its bytes/unit is adopted.
            for (const item of [...plans.map(plan => ({ ...plan, profile: plan.before })), ...preserved]) {
                if (scopedCanonical(await readProfile(item.node, item.file)) !== scopedCanonical(item.profile)) throw scopedFailure('CLASSIC_SCOPED_PHYSICAL_BASELINE_DRIFT');
            }
            // Stage and validate ALL changed payloads before restarting any service.
            for (const plan of changedPlans) {
                plan.stage = `${plan.file}.${randomBytes(12).toString('hex')}.stage`;
                await exec(plan.node, `umask 077\ncat > ${plan.stage}`, plan.bytes);
                await exec(plan.node, `/usr/local/bin/xray run -test -format json -config ${plan.stage}`);
                if (await readConfig(plan.node, plan.stage) !== plan.bytes) throw scopedFailure('CLASSIC_SCOPED_STAGE_READBACK_MISMATCH');
            }
            if (remove) {
                // Staging/validation can await remote work: do not overwrite a
                // concurrent edit observed after the initial physical snapshot.
                if (scopedScopePin(await readScope()) !== scopePin) throw scopedFailure('CLASSIC_SCOPED_SCOPE_DRIFT');
                await checkNodePins();
                for (const item of [...plans.map(plan => ({ ...plan, profile: plan.before })), ...preserved]) {
                    if (scopedCanonical(await readProfile(item.node, item.file)) !== scopedCanonical(item.profile)) {
                        throw scopedFailure('CLASSIC_SCOPED_PHYSICAL_BASELINE_DRIFT');
                    }
                }
            }
            const port = target.tunnelPort;
            if (changedPlans.length && !remove) await exec(source, `if command -v ufw >/dev/null 2>&1; then\n ufw allow ${port}/tcp\nelif command -v firewall-cmd >/dev/null 2>&1; then\n firewall-cmd --permanent --add-port=${port}/tcp && firewall-cmd --reload && firewall-cmd --query-port=${port}/tcp\nfi`);
            for (const plan of changedPlans) {
                if (remove) {
                    if (scopedCanonical(await readProfile(plan.node, plan.file)) !== scopedCanonical(plan.before)) {
                        throw scopedFailure('CLASSIC_SCOPED_PHYSICAL_BASELINE_DRIFT');
                    }
                    if (await readConfig(plan.node, plan.stage) !== plan.bytes) throw scopedFailure('CLASSIC_SCOPED_STAGE_READBACK_MISMATCH');
                    if (scopedScopePin(await readScope()) !== scopePin) throw scopedFailure('CLASSIC_SCOPED_SCOPE_DRIFT');
                    await checkNodePins();
                }
                await exec(plan.node, `chown --reference=${plan.file} ${plan.stage} && chmod --reference=${plan.file} ${plan.stage} && mv -- ${plan.stage} ${plan.file} && systemctl restart ${plan.service} && systemctl is-active --quiet ${plan.service}`);
                const after = await readProfile(plan.node, plan.file);
                if (after.bytes !== plan.bytes || after.unit !== plan.before.unit
                    || (plan.bytes === plan.before.bytes && scopedCanonical(after.runtime) !== scopedCanonical(plan.before.runtime))) throw scopedFailure('CLASSIC_SCOPED_CONFIG_READBACK_MISMATCH');
            }
            for (const item of preserved) {
                if (scopedCanonical(await readProfile(item.node, item.file)) !== scopedCanonical(item.profile)) throw scopedFailure('CLASSIC_SCOPED_PRESERVED_PROFILE_DRIFT');
            }
            let established = false;
            for (let attempt = 0; !remove && attempt < 8; attempt++) {
                const sockets = await exec(source, `ss -tnH state established '( sport = :${port} and dst ${bridge.ip} )'`);
                const targetPeer = sockets.trim().split('\n').some(line => {
                    const fields = line.trim().split(/\s+/);
                    if (fields.length !== 4 || !/^\d+$/.test(fields[0]) || !/^\d+$/.test(fields[1])) return false;
                    const peer = fields[3].slice(0, fields[3].lastIndexOf(':')).replace(/^\[|\]$/g, '');
                    return fields[2].endsWith(`:${port}`) && (peer === bridge.ip || peer === `::ffff:${bridge.ip}`);
                });
                if (targetPeer) { established = true; break; }
                await new Promise(resolve => setTimeout(resolve, 500));
            }
            if (!remove && !established) throw scopedFailure('CLASSIC_SCOPED_TUNNEL_UNCONFIRMED');
            // One final whole-scope barrier, not merely the last restarted node.
            for (const plan of plans) {
                const after = await readProfile(plan.node, plan.file);
                if (after.bytes !== plan.bytes || after.unit !== plan.before.unit
                    || (plan.bytes === plan.before.bytes && scopedCanonical(after.runtime) !== scopedCanonical(plan.before.runtime))) throw scopedFailure('CLASSIC_SCOPED_CONFIG_READBACK_MISMATCH');
            }
            for (const item of preserved) {
                if (scopedCanonical(await readProfile(item.node, item.file)) !== scopedCanonical(item.profile)) throw scopedFailure('CLASSIC_SCOPED_PRESERVED_PROFILE_DRIFT');
            }
            if (scopedScopePin(await readScope()) !== scopePin) throw scopedFailure('CLASSIC_SCOPED_SCOPE_DRIFT');
            await checkNodePins();
            if (remove) {
                await revision();
                return { success: true, remoteQuiescent: true, receipt: {
                    kind: 'classic-scoped-reverse-removal', linkId, topologyRevision: expectedTopologyRevision,
                    nodeIds: ids, preservedLinkIds: baseline, targetAbsent: true,
                    profiles: plans.map(plan => ({ nodeId: scopedId(plan.node), path: plan.file,
                        beforeSha256: scopedHash(plan.before.bytes), sha256: scopedHash(plan.bytes),
                        changed: plan.bytes !== plan.before.bytes })),
                    preservedProfiles: preserved.map(item => ({ nodeId: scopedId(item.node), path: item.file,
                        beforeSha256: item.profile.bytes === 'C3_CONFIG_ABSENT' ? null : scopedHash(item.profile.bytes),
                        sha256: item.profile.bytes === 'C3_CONFIG_ABSENT' ? null : scopedHash(item.profile.bytes), changed: false })),
                } };
            }
            const updated = await CascadeLink.updateOne({ _id: linkId, active: true }, {
                $set: { status: 'deployed', lastError: '', lastHealthCheck: new Date() },
            }, { maxTimeMS: 5000 });
            if (updated?.acknowledged !== true || updated.matchedCount !== 1) throw scopedFailure('CLASSIC_SCOPED_STATUS_UNCONFIRMED');
            const saved = await CascadeLink.findById(linkId).setOptions({ maxTimeMS: 5000 }).lean();
            if (!['deployed', 'online', 'offline'].includes(saved?.status) || saved.active !== true || scopedId(saved.portalNode) !== scopedId(source)
                || scopedId(saved.bridgeNode) !== scopedId(bridge)) throw scopedFailure('CLASSIC_SCOPED_STATUS_UNCONFIRMED');
            await revision();
            return { success: true, remoteQuiescent: true, receipt: {
                kind: 'classic-scoped-reverse', linkId, topologyRevision: expectedTopologyRevision,
                nodeIds: ids, preservedLinkIds: baseline, tunnelEstablished: true,
                profiles: plans.map(plan => ({ nodeId: scopedId(plan.node), path: plan.file,
                    beforeSha256: scopedHash(plan.before.bytes), sha256: scopedHash(plan.bytes) })),
                preservedProfiles: preserved.map(item => ({ nodeId: scopedId(item.node), path: item.file,
                    sha256: item.profile.bytes === 'C3_CONFIG_ABSENT' ? null : scopedHash(item.profile.bytes) })),
            } };
        } finally {
            for (const ssh of transports.values()) ssh.disconnect();
        }
    }

    /**
     * Deploy a single cascade link: upload configs to both Portal and Bridge,
     * restart services, and verify tunnel establishment.
     * @param {Object} link - CascadeLink document (populated with portalNode, bridgeNode)
     * @returns {Promise<{success: boolean, error?: string}>}
     */
    async deployLink(link) {
        const linkId = link._id;
        logger.info(`[Cascade] Deploying ${link.mode || 'reverse'} link ${link.name} (${linkId})`);

        await CascadeLink.updateOne({ _id: linkId }, { $set: { status: 'pending', lastError: '' } });

        const portalNode = link.portalNode._id ? link.portalNode : await HyNode.findById(link.portalNode);
        const bridgeNode = link.bridgeNode._id ? link.bridgeNode : await HyNode.findById(link.bridgeNode);

        if (!portalNode || !bridgeNode) {
            const err = 'Portal or Bridge node not found';
            await CascadeLink.updateOne({ _id: linkId }, { $set: { status: 'error', lastError: err } });
            return { success: false, error: err };
        }

        try {
            if (link.mode === 'forward') {
                await this._deployForwardLink(link, portalNode, bridgeNode);
            } else {
                await this._deployReverseLink(link, portalNode, bridgeNode);
            }

            const tunnelPort = link.tunnelPort || 10086;
            await new Promise(r => setTimeout(r, 3000));

            // For forward: check bridge; for reverse: check portal
            const checkNode = link.mode === 'forward' ? bridgeNode : portalNode;
            const [healthy, latencyMs] = await Promise.all([
                link.mode === 'forward'
                    ? this._measureTcpLatency(bridgeNode.ip, tunnelPort).then(ms => ms !== null)
                    : this._checkTunnel(portalNode, tunnelPort),
                this._measureTcpLatency(checkNode.ip, tunnelPort),
            ]);

            const newStatus = healthy ? 'online' : 'deployed';
            await CascadeLink.updateOne({ _id: linkId }, {
                $set: {
                    status:          newStatus,
                    lastError:       '',
                    lastHealthCheck: new Date(),
                    latencyMs:       latencyMs,
                },
            });

            await this._invalidateTopologyCache();

            logger.info(`[Cascade] Link ${link.name} deployed, status=${newStatus}`);
            return { success: true };
        } catch (error) {
            logger.error(`[Cascade] Deploy failed for ${link.name}: ${error.message}`);
            await CascadeLink.updateOne({ _id: linkId }, {
                $set: { status: 'error', lastError: error.message },
            });
            return { success: false, error: error.message };
        }
    }

    /**
     * Deploy a reverse-proxy link.
     * Portal config is rebuilt for the changed portal, while Bridge config is
     * rebuilt from all active reverse links that share this bridge node.
     */
    async _deployReverseLink(link, portalNode, bridgeNode) {
        await this._deployPortalConfig(portalNode);
        await this._deployBridgeConfig(link, bridgeNode, portalNode);
        await this._openFirewallPort(portalNode, link.tunnelPort || 10086);
    }

    /**
     * Deploy a forward-chain link.
     * Order: bridge first (cascade inbound), then portal (outbound to bridge).
     */
    async _deployForwardLink(link, portalNode, bridgeNode) {
        await this._deployForwardHopConfig(bridgeNode, [link]);
        await this._openFirewallPort(bridgeNode, link.tunnelPort || 10086);
        await this._deployPortalConfig(portalNode);
    }

    /**
     * Undeploy a cascade link: regenerate configs without this link's settings.
     * For reverse mode: regenerate Portal, stop xray-bridge on Bridge.
     * For forward mode: regenerate Portal (remove outbound), regenerate Bridge
     * (remove cascade inbound) if it's an existing Xray node, or stop xray-bridge.
     */
    async undeployLink(link) {
        return trackLegacyCascadeUndeploy(() => this._undeployLinkWithCompletion(link));
    }

    async _undeployLinkWithCompletion(link) {
        const portalNode = await HyNode.findById(link.portalNode);
        const bridgeNode = await HyNode.findById(link.bridgeNode);

        if (!portalNode || !bridgeNode || (!bridgeNode.ssh?.password && !bridgeNode.ssh?.privateKey)) {
            throw undeployUncertain('Legacy undeploy requires both nodes and bridge SSH credentials');
        }
        const opts = { excludeLinkIds: [link._id], requireCompletion: true };

        // Mark pending for health/status consumers; exclusion below is explicit.
        await CascadeLink.updateOne({ _id: link._id }, {
            $set: { status: 'pending', lastError: '' },
        });

        // Explicitly exclude the removed link in every regenerated config.
        if (portalNode) {
            await this._deployPortalConfig(portalNode, opts);
        }

        if (bridgeNode && (bridgeNode.ssh?.password || bridgeNode.ssh?.privateKey)) {
            if (link.mode === 'forward' && bridgeNode.type === 'xray' && bridgeNode.active) {
                await this._deployPortalConfig(bridgeNode, opts);
            } else {
                const remainingLinks = await CascadeLink.find({
                    bridgeNode: bridgeNode._id,
                    active: true,
                    mode: { $ne: 'forward' },
                    _id: { $ne: link._id },
                }).populate('portalNode');

                if (remainingLinks.length > 0) {
                    await this._deployBridgeConfig(remainingLinks[0], bridgeNode, remainingLinks[0].portalNode, opts);
                } else {
                    const ssh = completionCheckedSSH(bridgeNode);
                    try {
                        await ssh.connect();
                        await ssh.exec('systemctl stop xray-bridge && systemctl disable xray-bridge');
                        logger.info(`[Cascade] Bridge service stopped on ${bridgeNode.name}`);
                    } finally {
                        ssh.disconnect();
                    }
                }
            }
        }

        await this._invalidateTopologyCache();
        return { success: true, remoteQuiescent: true };
    }

    /**
     * Redeploy all cascade links associated with a given node.
     * Called when a node's configuration changes.
     */
    async redeployAllLinksForNode(nodeId) {
        const links = await CascadeLink.find({
            $or: [{ portalNode: nodeId }, { bridgeNode: nodeId }],
            active: true,
            status: { $in: ['deployed', 'online', 'offline'] },
        }).populate('portalNode bridgeNode');

        for (const link of links) {
            await this.deployLink(link).catch(err => {
                logger.error(`[Cascade] Redeploy link ${link.name}: ${err.message}`);
            });
        }
    }

    /**
     * Deploy an entire cascade chain in the correct order.
     * Finds all connected links starting from any node in the chain,
     * builds topological order (Portal → Relay → Bridge), and deploys
     * configs + restarts services with proper delays.
     *
     * @param {string} startNodeId - Any node ID in the chain
     * @returns {Promise<{success: boolean, deployed: number, errors: string[]}>}
     */
    async deployChain(startNodeId) {
        logger.info(`[Cascade] Starting chain deployment from node ${startNodeId}`);

        // 1. Find all links connected to this chain
        const { orderedNodes, orderedLinks } = await this._buildChainOrder(startNodeId);

        if (orderedLinks.length === 0) {
            return { success: true, deployed: 0, errors: [], message: 'No active links found' };
        }

        logger.info(`[Cascade] Chain has ${orderedNodes.length} nodes, ${orderedLinks.length} links`);

        const errors = [];
        let deployed = 0;

        // All links in a chain must use the same mode
        const modes = new Set(orderedLinks.map(l => l.mode || 'reverse'));
        if (modes.size > 1) {
            return { success: false, deployed: 0, errors: ['Mixed reverse/forward links in one chain are not supported'] };
        }
        const chainMode = modes.values().next().value;
        const deployOrder = chainMode === 'forward' ? [...orderedNodes].reverse() : orderedNodes;
        logger.info(`[Cascade] Chain mode: ${chainMode}, deploy order: ${deployOrder.map(n => n.name).join(' → ')}`);

        // 2. Deploy configs in order
        for (let i = 0; i < deployOrder.length; i++) {
            const node = deployOrder[i];
            const nodeLinks = orderedLinks.filter(
                l => String(l.portalNode._id || l.portalNode) === String(node._id) ||
                     String(l.bridgeNode._id || l.bridgeNode) === String(node._id)
            );

            try {
                await this._deployNodeInChain(node, nodeLinks, orderedLinks);
                deployed++;
                logger.info(`[Cascade] Deployed node ${i + 1}/${deployOrder.length}: ${node.name}`);

                if (i < deployOrder.length - 1) {
                    await new Promise(r => setTimeout(r, 2000));
                }
            } catch (err) {
                errors.push(`${node.name}: ${err.message}`);
                logger.error(`[Cascade] Failed to deploy ${node.name}: ${err.message}`);
            }
        }

        // 3. Update link statuses after deployment
        await new Promise(r => setTimeout(r, 3000));
        for (const link of orderedLinks) {
            await this.healthCheckLink(link).catch(() => {});
        }

        await this._invalidateTopologyCache();

        const success = errors.length === 0;
        logger.info(`[Cascade] Chain deployment complete: ${deployed} nodes, ${errors.length} errors`);

        return { success, deployed, errors };
    }

    /**
     * Build topological order of nodes in the chain.
     * Returns nodes ordered from head (pure Portal) to tail (pure Bridge).
     */
    async _buildChainOrder(startNodeId) {
        // Get all active links
        const allLinks = await CascadeLink.find({ active: true })
            .populate('portalNode bridgeNode')
            .lean();

        if (allLinks.length === 0) {
            return { orderedNodes: [], orderedLinks: [] };
        }

        // Build adjacency: nodeId -> { asPortal: [links], asBridge: [links] }
        const nodeMap = new Map();
        const linkSet = new Set();

        const addNode = (node) => {
            const id = String(node._id || node);
            if (!nodeMap.has(id)) {
                nodeMap.set(id, { node, asPortal: [], asBridge: [] });
            }
            return nodeMap.get(id);
        };

        for (const link of allLinks) {
            const portalId = String(link.portalNode._id || link.portalNode);
            const bridgeId = String(link.bridgeNode._id || link.bridgeNode);

            addNode(link.portalNode).asPortal.push(link);
            addNode(link.bridgeNode).asBridge.push(link);
        }

        // BFS to find all connected nodes starting from startNodeId
        const visited = new Set();
        const queue = [String(startNodeId)];
        const connectedLinks = [];

        while (queue.length > 0) {
            const nodeId = queue.shift();
            if (visited.has(nodeId)) continue;
            visited.add(nodeId);

            const entry = nodeMap.get(nodeId);
            if (!entry) continue;

            for (const link of [...entry.asPortal, ...entry.asBridge]) {
                const linkId = String(link._id);
                if (!linkSet.has(linkId)) {
                    linkSet.add(linkId);
                    connectedLinks.push(link);
                }

                const portalId = String(link.portalNode._id || link.portalNode);
                const bridgeId = String(link.bridgeNode._id || link.bridgeNode);

                if (!visited.has(portalId)) queue.push(portalId);
                if (!visited.has(bridgeId)) queue.push(bridgeId);
            }
        }

        // Find head nodes (portals that are not bridges in this chain)
        const bridgeIds = new Set(connectedLinks.map(l => String(l.bridgeNode._id || l.bridgeNode)));
        const portalIds = new Set(connectedLinks.map(l => String(l.portalNode._id || l.portalNode)));

        const headIds = [...portalIds].filter(id => !bridgeIds.has(id));

        // Topological sort from heads
        const orderedNodes = [];
        const orderedNodeIds = new Set();
        const toVisit = headIds.map(id => nodeMap.get(id)?.node).filter(Boolean);

        while (toVisit.length > 0) {
            const node = toVisit.shift();
            const nodeId = String(node._id);

            if (orderedNodeIds.has(nodeId)) continue;
            orderedNodeIds.add(nodeId);
            orderedNodes.push(node);

            // Add downstream nodes (where this node is portal)
            const entry = nodeMap.get(nodeId);
            if (entry) {
                for (const link of entry.asPortal) {
                    const bridgeNode = link.bridgeNode;
                    const bridgeId = String(bridgeNode._id || bridgeNode);
                    if (!orderedNodeIds.has(bridgeId)) {
                        toVisit.push(bridgeNode);
                    }
                }
            }
        }

        return { orderedNodes, orderedLinks: connectedLinks };
    }

    /**
     * Deploy a single node within a chain context.
     * Determines if node is Portal, Relay, or Bridge and applies appropriate config.
     * Handles both reverse and forward mode chains.
     */
    async _deployNodeInChain(node, nodeLinks, allChainLinks) {
        const nodeId = String(node._id);

        const asPortalLinks = allChainLinks.filter(l => String(l.portalNode._id || l.portalNode) === nodeId);
        const asBridgeLinks = allChainLinks.filter(l => String(l.bridgeNode._id || l.bridgeNode) === nodeId);

        const isPortal = asPortalLinks.length > 0;
        const isBridge = asBridgeLinks.length > 0;

        // Determine chain mode from any of the links
        const chainMode = (asPortalLinks[0]?.mode || asBridgeLinks[0]?.mode) || 'reverse';

        if (chainMode === 'forward') {
            if (isPortal) {
                await this._deployPortalConfig(node);
            }
            if (isBridge) {
                // Deploy all forward-hop inbounds at once to avoid overwriting
                await this._deployForwardHopConfig(node, asBridgeLinks);
                for (const link of asBridgeLinks) {
                    await this._openFirewallPort(node, link.tunnelPort || 10086);
                }
            }
        } else {
            // Reverse chain: original logic
            if (isPortal && !isBridge) {
                await this._deployPortalConfig(node);
                for (const link of asPortalLinks) {
                    await this._openFirewallPort(node, link.tunnelPort || 10086);
                }
            } else if (isBridge && isPortal) {
                const upstreamLink = asBridgeLinks[0];
                const upstreamPortal = await HyNode.findById(upstreamLink.portalNode);
                await this._deployRelayNode(node, upstreamLink, upstreamPortal, asPortalLinks);
                for (const link of asPortalLinks) {
                    await this._openFirewallPort(node, link.tunnelPort || 10086);
                }
            } else if (isBridge && !isPortal) {
                const upstreamLink = asBridgeLinks[0];
                const upstreamPortal = await HyNode.findById(upstreamLink.portalNode);
                await this._deployPureBridge(node, upstreamLink, upstreamPortal, asBridgeLinks);
            }
        }
    }

    /**
     * Deploy Relay node config (middle of chain).
     */
    async _deployRelayNode(node, upstreamLink, upstreamPortal, downstreamLinks) {
        return withClassicNodeConfigWrite({ nodeId: node._id, kind: '_deployRelayNode' }, () =>
            this.#deployRelayNodeUnfenced(node, upstreamLink, upstreamPortal, downstreamLinks));
    }

    async #deployRelayNodeUnfenced(node, upstreamLink, upstreamPortal, downstreamLinks) {
        if (!node.ssh?.password && !node.ssh?.privateKey) {
            throw new Error(`Relay node ${node.name} has no SSH credentials`);
        }

        const relay = JSON.parse(configGenerator.generateRelayConfig(upstreamLink, upstreamPortal, downstreamLinks));
        await this._applyClassicL2tpPathIngress(relay, node, { mode: 'reverse' });
        const relayConfig = JSON.stringify(relay, null, 2);
        const serviceUnit = configGenerator.generateBridgeSystemdService();

        const ssh = completionCheckedSSH(node);
        try {
            await ssh.connect();

            // Ensure Xray is installed
            const xrayCheck = await ssh.exec('command -v xray');
            if (!xrayCheck.stdout || !xrayCheck.stdout.trim()) {
                logger.info(`[Cascade] Installing Xray on relay ${node.name}`);
                await ssh.exec(
                    'curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-install.sh ' +
                    '&& chmod +x /tmp/xray-install.sh && bash /tmp/xray-install.sh install 2>&1 && rm -f /tmp/xray-install.sh'
                );
            }

            await ssh.exec('mkdir -p /usr/local/etc/xray-bridge');
            await ssh.uploadContent(relayConfig, '/usr/local/etc/xray-bridge/config.json');
            await ssh.uploadContent(serviceUnit, '/etc/systemd/system/xray-bridge.service');
            await ssh.exec('systemctl daemon-reload && systemctl enable xray-bridge && systemctl restart xray-bridge');

            logger.info(`[Cascade] Relay config deployed to ${node.name}`);
            return true;
        } finally {
            ssh.disconnect();
        }
    }

    /**
     * Deploy pure Bridge node config (tail of chain).
     */
    async _deployPureBridge(node, upstreamLink, upstreamPortal, upstreamLinks = null) {
        return withClassicNodeConfigWrite({ nodeId: node._id, kind: '_deployPureBridge' }, () =>
            this.#deployPureBridgeUnfenced(node, upstreamLink, upstreamPortal, upstreamLinks));
    }

    async #deployPureBridgeUnfenced(node, upstreamLink, upstreamPortal, upstreamLinks = null) {
        if (!node.ssh?.password && !node.ssh?.privateKey) {
            throw new Error(`Bridge node ${node.name} has no SSH credentials`);
        }

        let bridgeLinks = upstreamLinks;
        if (!Array.isArray(bridgeLinks) || bridgeLinks.length === 0) {
            bridgeLinks = [{ ...upstreamLink, portalNode: upstreamPortal }];
        }
        const bridgeConfig = configGenerator.generateCombinedBridgeConfig(bridgeLinks);
        const serviceUnit = configGenerator.generateBridgeSystemdService();

        const ssh = completionCheckedSSH(node);
        try {
            await ssh.connect();

            // Ensure Xray is installed
            const xrayCheck = await ssh.exec('command -v xray');
            if (!xrayCheck.stdout || !xrayCheck.stdout.trim()) {
                logger.info(`[Cascade] Installing Xray on bridge ${node.name}`);
                await ssh.exec(
                    'curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-install.sh ' +
                    '&& chmod +x /tmp/xray-install.sh && bash /tmp/xray-install.sh install 2>&1 && rm -f /tmp/xray-install.sh'
                );
            }

            await ssh.exec('mkdir -p /usr/local/etc/xray-bridge');
            await ssh.uploadContent(bridgeConfig, '/usr/local/etc/xray-bridge/config.json');
            await ssh.uploadContent(serviceUnit, '/etc/systemd/system/xray-bridge.service');
            await ssh.exec('systemctl daemon-reload && systemctl enable xray-bridge && systemctl restart xray-bridge');

            logger.info(`[Cascade] Bridge config deployed to ${node.name}`);
            return true;
        } finally {
            ssh.disconnect();
        }
    }

    /**
     * Deploy forward-chain hop config to a node (bridge/relay in forward mode).
     * If the node is an existing standalone Xray server, applies forward-hop inbound
     * to its config. Otherwise deploys a standalone forward-hop config.
     * @param {Object} node - HyNode document
     * @param {Array} hopLinks - Array of CascadeLink documents for this node
     */
    async _deployForwardHopConfig(node, hopLinks) {
        return withClassicNodeConfigWrite({ nodeId: node._id, kind: '_deployForwardHopConfig' }, () =>
            this.#deployForwardHopConfigUnfenced(node, hopLinks));
    }

    async #deployForwardHopConfigUnfenced(node, hopLinks) {
        if (!node.ssh?.password && !node.ssh?.privateKey) {
            throw new Error(`Forward hop node ${node.name} has no SSH credentials`);
        }

        // Existing Xray server: cascade inbounds are added via _deployPortalConfig
        if (node.type === 'xray' && node.active && node.status !== 'error') {
            return this._deployPortalConfig(node);
        }

        // Standalone: generate combined config with all hop inbounds
        const hopConfig = configGenerator.generateForwardHopConfig(hopLinks);
        const serviceUnit = configGenerator.generateBridgeSystemdService();

        const ssh = completionCheckedSSH(node);
        try {
            await ssh.connect();

            const xrayCheck = await ssh.exec('command -v xray');
            if (!xrayCheck.stdout || !xrayCheck.stdout.trim()) {
                logger.info(`[Cascade] Installing Xray on forward-hop ${node.name}`);
                await ssh.exec(
                    'curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-install.sh ' +
                    '&& chmod +x /tmp/xray-install.sh && bash /tmp/xray-install.sh install 2>&1 && rm -f /tmp/xray-install.sh'
                );
            }

            await ssh.exec('mkdir -p /usr/local/etc/xray-bridge');
            await ssh.uploadContent(hopConfig, '/usr/local/etc/xray-bridge/config.json');
            await ssh.uploadContent(serviceUnit, '/etc/systemd/system/xray-bridge.service');
            await ssh.exec('systemctl daemon-reload && systemctl enable xray-bridge && systemctl restart xray-bridge');

            const statusResult = await ssh.exec('sleep 1 && systemctl is-active xray-bridge');
            const isActive = (statusResult.stdout || '').trim() === 'active';
            if (!isActive) {
                const logs = await ssh.exec('journalctl -u xray-bridge --no-pager -n 20');
                throw new Error(`Forward-hop service not active. Logs: ${(logs.stdout || logs.stderr || '').slice(0, 500)}`);
            }

            logger.info(`[Cascade] Forward-hop config deployed to ${node.name}`);
            return true;
        } finally {
            ssh.disconnect();
        }
    }

    /**
     * Health-check a single cascade link.
     * Reverse: verify ESTABLISHED connections on Portal's tunnel port.
     * Forward: verify TCP connectivity to Bridge's tunnel port.
     */
    async healthCheckLink(link) {
        const isForward = link.mode === 'forward';
        const checkNodeId = isForward ? link.bridgeNode : link.portalNode;
        const checkNode = await HyNode.findById(checkNodeId);
        if (!checkNode) return false;

        const tunnelPort = link.tunnelPort || 10086;

        try {
            const [healthy, latencyMs] = await Promise.all([
                isForward
                    ? this._measureTcpLatency(checkNode.ip, tunnelPort).then(ms => ms !== null)
                    : this._checkTunnel(checkNode, tunnelPort),
                this._measureTcpLatency(checkNode.ip, tunnelPort),
            ]);

            const prevStatus = link.status;
            const newStatus  = healthy ? 'online' : 'offline';

            await CascadeLink.updateOne({ _id: link._id }, {
                $set: {
                    status:          newStatus,
                    lastHealthCheck: new Date(),
                    lastError:       healthy ? '' : (isForward ? 'Bridge unreachable on tunnel port' : 'No ESTABLISHED tunnel connections'),
                    latencyMs:       latencyMs,
                },
            });

            if (prevStatus !== newStatus) {
                const event = healthy ? 'cascade.online' : 'cascade.offline';
                webhook.emit(event, { linkId: link._id, name: link.name });
                logger.info(`[Cascade] Link ${link.name}: ${prevStatus} -> ${newStatus}, latency=${latencyMs}ms`);
            }

            return healthy;
        } catch (error) {
            await CascadeLink.updateOne({ _id: link._id }, {
                $set: { status: 'error', lastError: error.message, lastHealthCheck: new Date() },
            });
            return false;
        }
    }

    /**
     * Health-check all active, deployed cascade links.
     * Called periodically by cron.
     */
    async healthCheckAll() {
        const links = await CascadeLink.find({
            active: true,
            status: { $in: ['deployed', 'online', 'offline'] },
        });

        if (links.length === 0) return;

        const CONCURRENCY = 5;
        for (let i = 0; i < links.length; i += CONCURRENCY) {
            const batch = links.slice(i, i + CONCURRENCY);
            await Promise.allSettled(batch.map(l => this.healthCheckLink(l)));
        }

        await this._invalidateTopologyCache();
    }

    /**
     * Build the full network topology graph for the visual map.
     * Returns nodes and edges formatted for cytoscape.js consumption.
     * Cached in Redis for performance.
     *
     * @returns {Promise<{nodes: Array, edges: Array}>}
     */
    async getTopology() {
        const cached = await cacheGet(TOPOLOGY_CACHE_KEY);
        if (cached) {
            try { return JSON.parse(cached); } catch (_) {}
        }

        const [allNodes, allLinks] = await Promise.all([
            // Virtual nodes have no IP/country and don't participate in the cascade.
            HyNode.find({ active: true, type: { $ne: 'virtual' } })
                .select('name ip domain flag type status onlineUsers cascadeRole mapPosition country port ssh')
                .lean(),
            CascadeLink.find({ active: true })
                .populate('portalNode', 'name ip')
                .populate('bridgeNode', 'name ip')
                .lean(),
        ]);

        const nodes = allNodes.map(n => ({
            data: {
                id: String(n._id),
                label: n.name,
                ip: n.ip,
                domain: n.domain || '',
                flag: n.flag || '',
                type: n.type,
                status: n.status,
                onlineUsers: n.onlineUsers || 0,
                cascadeRole: n.cascadeRole || 'standalone',
                country: n.country || '',
                port: n.port,
                sshConfigured: !!(n.ssh?.password || n.ssh?.privateKey),
            },
            position: (n.mapPosition?.x != null && n.mapPosition?.y != null)
                ? { x: n.mapPosition.x, y: n.mapPosition.y }
                : undefined,
        }));

        const edges = allLinks.map(l => ({
            data: {
                id: `link-${l._id}`,
                linkId: String(l._id),
                source: String(l.portalNode?._id || l.portalNode),
                target: String(l.bridgeNode?._id || l.bridgeNode),
                label: l.name,
                status: l.status,
                tunnelPort: l.tunnelPort,
                latencyMs: l.latencyMs,
                tunnelProtocol: l.tunnelProtocol,
                tunnelTransport: l.tunnelTransport,
                mode: l.mode || 'reverse',
                muxEnabled: l.muxEnabled || false,
                tunnelSecurity: l.tunnelSecurity || 'none',
            },
        }));

        // Add virtual "Internet" node and edges from exit/standalone nodes
        const exitNodes = allNodes.filter(n =>
            n.cascadeRole === 'bridge' || n.cascadeRole === 'standalone' || !n.cascadeRole
        );

        if (exitNodes.length > 0) {
            const settings = await Settings.findById('settings').select('networkMap.internetPosition').lean();
            const saved = settings?.networkMap?.internetPosition;
            const positionedExits = exitNodes.map(n => n.mapPosition)
                .filter(p => Number.isFinite(p?.x) && Number.isFinite(p?.y));
            // On a fresh page, saved physical positions must not leave the
            // virtual icon at Cytoscape's origin when it has not been dragged yet.
            const defaultPosition = positionedExits.length > 0 ? {
                x: Math.max(...positionedExits.map(p => p.x)) + 160,
                y: Math.round(positionedExits.reduce((sum, p) => sum + p.y, 0) / positionedExits.length),
            } : undefined;
            const internetPosition = Number.isFinite(saved?.x) && Number.isFinite(saved?.y)
                ? { x: saved.x, y: saved.y } : defaultPosition;
            nodes.push({
                data: {
                    id: 'internet',
                    label: 'Internet',
                    ip: '',
                    domain: '',
                    flag: '🌐',
                    type: 'internet',
                    status: 'online',
                    onlineUsers: 0,
                    cascadeRole: 'internet',
                    country: '',
                    port: null,
                },
                position: internetPosition,
            });

            for (const exitNode of exitNodes) {
                edges.push({
                    data: {
                        id: `internet-${exitNode._id}`,
                        linkId: null,
                        source: String(exitNode._id),
                        target: 'internet',
                        label: '',
                        status: exitNode.status === 'online' ? 'online' : 'offline',
                        tunnelPort: null,
                        latencyMs: null,
                        tunnelProtocol: null,
                        tunnelTransport: null,
                        isInternetEdge: true,
                    },
                });
            }
        }

        const topology = { nodes, edges };
        await cacheSet(TOPOLOGY_CACHE_KEY, JSON.stringify(topology), TOPOLOGY_CACHE_TTL);
        return topology;
    }

    /**
     * Save node positions from the visual map editor.
     * @param {Array<{id: string, x: number, y: number}>} positions
     */
    async savePositions(positions) {
        if (!Array.isArray(positions) || positions.length === 0) return;

        const internet = positions.find(p => p.id === 'internet'
            && Number.isFinite(p.x) && Number.isFinite(p.y));
        const bulkOps = positions
            .filter(p => p.id && p.id !== 'internet' && typeof p.x === 'number' && typeof p.y === 'number')
            .map(p => ({
                updateOne: {
                    filter: { _id: p.id },
                    update: { $set: { 'mapPosition.x': p.x, 'mapPosition.y': p.y } },
                },
            }));

        if (bulkOps.length > 0) await HyNode.bulkWrite(bulkOps, { ordered: false });
        if (internet) {
            await Settings.findByIdAndUpdate('settings', {
                $set: { 'networkMap.internetPosition': { x: internet.x, y: internet.y } },
            }, { upsert: true });
        }
        if (bulkOps.length > 0 || internet) await this._invalidateTopologyCache();
    }

    /**
     * Resolve the full downstream forward-chain path starting from a node.
     *
     * Supports both styles currently present in the UI/data model:
     * 1. Pairwise graph links: A->B, B->C, C->D
     * 2. Head-defined ordered hops: A->B, A->C, A->D with priority ordering
     *
     * Returned links are ordered from the nearest downstream hop to the final
     * exit node and are ready to be passed to applyForwardChain().
     *
     * @param {string|ObjectId} startNodeId
     * @param {Set<string>} [excludeSet]
     * @param {Array<string>} [allowedStatuses] - Limit links when called by topology-enabled classic Sync
     * @returns {Promise<Array>}
     */
    async _getForwardChainLinks(startNodeId, excludeSet = new Set(), allowedStatuses) {
        const allForwardLinks = (await CascadeLink.find({
            mode: 'forward',
            active: true,
            ...(allowedStatuses && { status: { $in: allowedStatuses } }),
        }).populate('bridgeNode')).filter(l => !excludeSet.has(String(l._id)));

        if (allForwardLinks.length === 0) return [];

        const outgoingMap = new Map();
        for (const link of allForwardLinks) {
            const portalId = String(link.portalNode._id || link.portalNode);
            if (!outgoingMap.has(portalId)) outgoingMap.set(portalId, []);
            outgoingMap.get(portalId).push(link);
        }

        const ordered = [];
        const visitedLinks = new Set();
        const visitedNodes = new Set();
        let currentNodeId = String(startNodeId);

        while (true) {
            const outgoing = (outgoingMap.get(currentNodeId) || [])
                .filter(l => !visitedLinks.has(String(l._id)))
                .sort((a, b) => (a.priority || 100) - (b.priority || 100));

            if (outgoing.length === 0) break;

            for (const link of outgoing) {
                ordered.push(link);
                visitedLinks.add(String(link._id));
            }

            visitedNodes.add(currentNodeId);
            const tailLink = outgoing[outgoing.length - 1];
            const nextNodeId = String(tailLink.bridgeNode?._id || tailLink.bridgeNode);

            if (!nextNodeId || visitedNodes.has(nextNodeId)) {
                if (visitedNodes.has(nextNodeId)) {
                    logger.warn(`[Cascade] Forward chain cycle detected from node ${currentNodeId}, stopping path resolution`);
                }
                break;
            }

            currentNodeId = nextNodeId;
        }

        return ordered;
    }

    // ==================== INTERNAL HELPERS ====================

    /** Add accepted classic group/path listeners to their existing profile. */
    async _applyClassicL2tpPathIngress(config, node, { mode, excludeLinkIds = [] } = {}) {
        if (node.cascadeRole !== 'relay') return config;
        const excludeSet = new Set(excludeLinkIds.map(String));
        const outgoing = (await CascadeLink.find({ portalNode: node._id, active: true }))
            .filter(link => !excludeSet.has(String(link._id)) && (link.mode || 'reverse') === mode);
        if (outgoing.length === 0) return config;
        const CascadeRouteGroup = require('../modules/relay-l2tp/models/cascadeRouteGroupModel');
        const groups = (await CascadeRouteGroup.find({
            'paths.linkIds': { $in: outgoing.map(link => link._id) },
        }).lean()).map(group => ({
            ...group,
            paths: group.paths.filter(path => !path.linkIds.some(linkId => excludeSet.has(String(linkId)))),
        }));
        if (groups.length === 0) return config;
        const ids = [...new Set(groups.flatMap(group => group.paths.flatMap(path => path.linkIds.map(String))))];
        const links = await CascadeLink.find({ _id: { $in: ids } }).populate('bridgeNode');
        return applyClassicL2tpPathIngress(config, { nodeId: node._id, groups, links, mode });
    }

    /**
     * Regenerate the classic full main config, retaining installed L2TP sections.
     * excludeLinkIds is used by undeploy; no removed cascade is preserved.
     */
    async _deployPortalConfig(portalNode, opts = {}) {
        return withClassicNodeConfigWrite({ nodeId: portalNode._id, kind: '_deployPortalConfig' }, () =>
            this.#deployPortalConfigUnfenced(portalNode, opts));
    }

    async #deployPortalConfigUnfenced(portalNode, opts = {}) {
        // Topology-managed nodes get their full Xray config from the topology
        // deployment; the classic cascade writer would clobber it and uses
        // the persisted link.tunnelUuid, which mismatches the deterministic
        // tunnel credentials the topology composer derives for the other end.
        const allowedStatuses = usesTestTopologyConfig(portalNode) ? APPLIED_LINK_STATUSES : undefined;
        const statusFilter = allowedStatuses ? { status: { $in: allowedStatuses } } : {};
        const topologyManaged = await topologyManagesNodeConfig(portalNode);
        if (topologyManaged) {
            if (opts.requireCompletion) throw undeployUncertain('Topology-managed config cannot be removed by the classic writer');
            logger.info(`[Cascade] Node ${portalNode.name}: classic config deploy skipped (topology-managed node)`);
            return;
        }

        if (opts.requireCompletion && !portalNode.ssh?.password && !portalNode.ssh?.privateKey) {
            throw undeployUncertain('Legacy undeploy requires SSH credentials');
        }
        // Select checked SSH before dispatch: agent restart is not joinable.
        // This is not a fallback after an agent mutation or refusal.
        const hasAgent = !opts.requireCompletion && !!portalNode.xray?.agentToken;
        const createSSH = completionCheckedSSH;
        const syncService = require('./syncService');
        const users = await syncService._getUsersForNode(portalNode);

        const configStr = configGenerator.generateXrayConfigWithApi(portalNode, users);
        const config = JSON.parse(configStr);

        const excludeSet = new Set((opts.excludeLinkIds || []).map(String));

        const allPortalLinks = (await CascadeLink.find({
            portalNode: portalNode._id,
            active: true,
            ...statusFilter,
        }).populate('bridgeNode')).filter(l => !excludeSet.has(String(l._id)));

        const allBridgeLinks = (await CascadeLink.find({
            bridgeNode: portalNode._id,
            active: true,
            ...statusFilter,
        })).filter(l => !excludeSet.has(String(l._id)));
        // Reverse transit portals/listeners live in xray-bridge, not main.
        // Use the actual link modes, not a role label: a forward upstream
        // alone must not suppress an ordinary main-owned reverse portal.
        const hasReverseUpstream = allBridgeLinks.some(link => link.mode !== 'forward');
        const reverseLinks = hasReverseUpstream ? [] : allPortalLinks.filter(l => l.mode !== 'forward');
        const forwardLinks = await this._getForwardChainLinks(portalNode._id, excludeSet, allowedStatuses);

        // Cascade routing applies to ALL client-facing inbounds (main + extras).
        const inboundTags = [
            portalNode.xray?.inboundTag || 'vless-in',
            ...(portalNode.xray?.extraInbounds || [])
                .map(i => i.inboundTag)
                .filter(Boolean),
        ];

        if (reverseLinks.length > 0) {
            configGenerator.applyReversePortal(config, reverseLinks, inboundTags);
        }
        if (forwardLinks.length > 0) {
            configGenerator.applyForwardChain(config, forwardLinks, inboundTags);
        }

        const forwardHopLinks = allBridgeLinks.filter(link => link.mode === 'forward');
        // This path is classic-owned; topology-owned nodes returned before
        // generation. Keep legacy forward listeners in the main config.
        if (forwardHopLinks.length > 0) {
            configGenerator.applyForwardHopInbound(config, forwardHopLinks);
        }

        await this._applyClassicL2tpPathIngress(config, portalNode, { mode: 'forward', ...opts });

        // geoip:private block must be the very last routing rule
        configGenerator.ensurePrivateIpBlock(config);

        let finalConfig = JSON.stringify(config, null, 2);

        if (portalNode.ssh?.password || portalNode.ssh?.privateKey) {
            const ssh = createSSH(portalNode);
            try {
                await ssh.connect();
                // Xray nodes use different config path than Hysteria
                const configPath = portalNode.type === 'xray'
                    ? '/usr/local/etc/xray/config.json'
                    : (portalNode.paths?.config || '/etc/hysteria/config.yaml');
                if (portalNode.type === 'xray' && portalNode.cascadeRole === 'relay') {
                    const RelayL2tpState = require('../modules/relay-l2tp/models/relayL2tpStateModel');
                    if (await RelayL2tpState.exists({ node: portalNode._id, desiredState: 'installed' })) {
                        const live = await ssh.exec('cat /usr/local/etc/xray/config.json');
                        if (live?.code !== 0) throw new Error('Cannot preserve installed L2TP Xray sections');
                        const current = JSON.parse(live.stdout);
                        if (!Array.isArray(current?.inbounds) || !Array.isArray(current?.outbounds)
                            || !Array.isArray(current?.routing?.rules)
                            || !current.inbounds.some(row => row.tag?.startsWith('relay-l2tp-'))) {
                            throw new Error('Installed L2TP Xray sections are unavailable');
                        }
                        const merged = mergePreservedL2tpSections(config, current);
                        finishClassicConfigRouting(merged);
                        finalConfig = JSON.stringify(merged, null, 2);
                    }
                }
                await ssh.uploadContent(finalConfig, configPath);
                logger.info(`[Cascade] Portal config uploaded to ${portalNode.name} at ${configPath}`);
            } finally {
                ssh.disconnect();
            }
        }

        if (!portalNode.ssh?.password && !portalNode.ssh?.privateKey) return false;
        if (hasAgent) {
            try {
                const restarted = await syncService._agentRequest(portalNode, 'POST', '/restart');
                if (!Number.isInteger(restarted?.status) || restarted.status < 200 || restarted.status >= 300
                    || restarted.data?.ok === false || restarted.data?.success === false) {
                    throw undeployUncertain('Agent restart completion is unconfirmed');
                }
                logger.info(`[Cascade] Portal ${portalNode.name} restarted via agent`);
            } catch (err) {
                logger.warn(`[Cascade] Portal agent restart: ${err.message}`);
                // A deliberate agent HTTP refusal must not be overridden by SSH.
                // The earlier config upload is separate; deployment still fails here.
                throw err;
            }
        } else if (portalNode.ssh?.password || portalNode.ssh?.privateKey) {
            const ssh = createSSH(portalNode);
            try {
                await ssh.connect();
                await ssh.exec('systemctl restart xray');
            } finally { ssh.disconnect(); }
        }
        return true;
    }

    /**
     * Generate and upload the Bridge/Relay config, create systemd service, and start it.
     * Detects if bridgeNode is also a portal (relay) and generates appropriate config.
     */
    async _deployBridgeConfig(link, bridgeNode, portalNode, opts = {}) {
        return withClassicNodeConfigWrite({ nodeId: bridgeNode._id, kind: '_deployBridgeConfig' }, () =>
            this.#deployBridgeConfigUnfenced(link, bridgeNode, portalNode, opts));
    }

    async #deployBridgeConfigUnfenced(link, bridgeNode, portalNode, opts = {}) {
        if (!bridgeNode.ssh?.password && !bridgeNode.ssh?.privateKey) {
            throw new Error(`Bridge node ${bridgeNode.name} has no SSH credentials`);
        }

        // Check if this bridgeNode is also a portal for other links (i.e., it's a relay)
        const excludeSet = new Set((opts.excludeLinkIds || []).map(String));
        const downstreamLinks = (await CascadeLink.find({
            portalNode: bridgeNode._id,
            active: true,
        })).filter(row => !excludeSet.has(String(row._id)));
        const isRelay = downstreamLinks.length > 0;

        let bridgeConfig;
        if (isRelay) {
            logger.info(`[Cascade] Node ${bridgeNode.name} is a RELAY (${downstreamLinks.length} downstream link(s))`);
            bridgeConfig = configGenerator.generateRelayConfig(link, portalNode, downstreamLinks, [], opts.additionalUpstreams);
            const relay = JSON.parse(bridgeConfig);
            await this._applyClassicL2tpPathIngress(relay, bridgeNode, { mode: 'reverse', ...opts });
            bridgeConfig = JSON.stringify(relay, null, 2);
        } else {
            const bridgeLinks = (await CascadeLink.find({
                bridgeNode: bridgeNode._id,
                active: true,
                mode: { $ne: 'forward' },
            }).populate('portalNode')).filter(row => !excludeSet.has(String(row._id)));
            logger.info(`[Cascade] Node ${bridgeNode.name} is a BRIDGE (${bridgeLinks.length} reverse link(s))`);
            bridgeConfig = configGenerator.generateCombinedBridgeConfig(bridgeLinks);
        }

        const serviceUnit = configGenerator.generateBridgeSystemdService();

        const ssh = completionCheckedSSH(bridgeNode);
        try {
            await ssh.connect();

            // Ensure Xray is installed
            const xrayCheck = await ssh.exec('command -v xray');
            if (!xrayCheck.stdout || !xrayCheck.stdout.trim()) {
                if (opts.requireCompletion) throw undeployUncertain('Legacy undeploy cannot join an Xray installer');
                logger.info(`[Cascade] Installing Xray on bridge ${bridgeNode.name}`);
                await ssh.exec(
                    'curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-install.sh ' +
                    '&& chmod +x /tmp/xray-install.sh && bash /tmp/xray-install.sh install 2>&1 && rm -f /tmp/xray-install.sh'
                );
            }

            await ssh.exec('mkdir -p /usr/local/etc/xray-bridge');
            await ssh.uploadContent(bridgeConfig, '/usr/local/etc/xray-bridge/config.json');
            await ssh.uploadContent(serviceUnit, '/etc/systemd/system/xray-bridge.service');

            await ssh.exec('systemctl daemon-reload && systemctl enable xray-bridge && systemctl restart xray-bridge');

            // Verify the service started
            const statusResult = await ssh.exec('sleep 1 && systemctl is-active xray-bridge');
            const isActive = (statusResult.stdout || '').trim() === 'active';

            if (!isActive) {
                const logs = await ssh.exec('journalctl -u xray-bridge --no-pager -n 20');
                throw new Error(`Bridge service not active. Logs: ${(logs.stdout || logs.stderr || '').slice(0, 500)}`);
            }

            logger.info(`[Cascade] ${isRelay ? 'Relay' : 'Bridge'} config deployed to ${bridgeNode.name}`);
            return true;
        } finally {
            ssh.disconnect();
        }
    }

    /**
     * Open the tunnel port in the firewall on the Portal node.
     */
    async _openFirewallPort(node, port) {
        if (!node.ssh?.password && !node.ssh?.privateKey) return;

        const ssh = new NodeSSH(node);
        try {
            await ssh.connect();
            await ssh.exec(`
                if command -v ufw &>/dev/null; then
                    ufw allow ${port}/tcp 2>/dev/null
                elif command -v firewall-cmd &>/dev/null; then
                    firewall-cmd --permanent --add-port=${port}/tcp 2>/dev/null
                    firewall-cmd --reload 2>/dev/null
                fi
            `);
        } catch (err) {
            logger.warn(`[Cascade] Firewall open port ${port}: ${err.message}`);
        } finally {
            ssh.disconnect();
        }
    }

    /**
     * Check if there are ESTABLISHED connections on a given port (tunnel alive).
     */
    async _checkTunnel(node, port) {
        if (!node.ssh?.password && !node.ssh?.privateKey) return false;

        const ssh = new NodeSSH(node);
        try {
            await ssh.connect();
            // ss -tnH: -t=tcp, -n=numeric, -H=no header; count lines = count of ESTABLISHED connections
            const result = await ssh.exec(`ss -tnH state established '( sport = :${port} )' | wc -l`);
            const count = parseInt((result.stdout || '0').trim(), 10);
            return count > 0;
        } catch {
            return false;
        } finally {
            ssh.disconnect();
        }
    }

    async _invalidateTopologyCache() {
        await cacheDel(TOPOLOGY_CACHE_KEY);
    }

    /**
     * Measure TCP handshake latency to host:port.
     * Returns latency in ms, or null on timeout/error.
     * @param {string} host
     * @param {number} port
     * @param {number} [timeoutMs=3000]
     * @returns {Promise<number|null>}
     */
    async _measureTcpLatency(host, port, timeoutMs = 3000) {
        return new Promise((resolve) => {
            const start  = Date.now();
            const socket = new net.Socket();
            socket.setTimeout(timeoutMs);

            socket.connect(port, host, function () {
                const latency = Date.now() - start;
                socket.destroy();
                resolve(latency);
            });

            socket.on('error', function () {
                socket.destroy();
                resolve(null);
            });

            socket.on('timeout', function () {
                socket.destroy();
                resolve(null);
            });
        });
    }
}

module.exports = new CascadeService();
