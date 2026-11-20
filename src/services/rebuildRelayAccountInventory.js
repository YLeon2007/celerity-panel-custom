'use strict';

const { isIPv4 } = require('node:net');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');
const { decrypt } = require('../modules/relay-l2tp/services/secretBoxService');
const { ipv4, occupiedRange, validLogin } = require('./rebuildRelayBackendDesired');
const { captureRelayBinding } = require('./rebuildRelayAuthorization');

const fail = code => Object.assign(new Error(`REBUILD_L2TP_${code}`), { code: `REBUILD_L2TP_${code}` });
const inventoryInvalid = () => fail('ACCOUNT_INVENTORY_INVALID');
const exactToken = (value, re) => typeof value === 'string' && re.exec(value)?.[0] === value;
const objectId = value => exactToken(String(value), /^[a-f0-9]{24}$/);
const empty = value => value == null || value === '';
const bootstrap = 'relay-bootstrap';
const transitional = new Set(['queued', 'preflight', 'installing', 'removing']);

function sourcePool(row) {
    const [first, last] = occupiedRange(row.clientCidr);
    const { localAddress, poolStart, poolEnd } = row;
    if (![localAddress, poolStart, poolEnd].every(ip => isIPv4(ip) && ipv4(ip) > first && ipv4(ip) < last)) {
        throw inventoryInvalid();
    }
    const lo = ipv4(poolStart), hi = ipv4(poolEnd), local = ipv4(localAddress);
    if (lo > hi || (local >= lo && local <= hi)) throw inventoryInvalid();
    return { first, last, lo, hi };
}

function installedSource(row) {
    if (row.status !== 'installed' || row.desiredState !== 'installed') throw fail('ACCOUNT_SOURCE_BUSY');
    if (!objectId(row._id) || row.routingMode !== FOLLOW_RELAY_MODE || row.routingVersion !== FOLLOW_RELAY_VERSION
        || row.routeGroup != null || row.operationId != null || !empty(row.activePathKey)
        || row.appliedTopologyRevision != null || ![null, undefined, 0].includes(row.pppDriftQueueFence)
        || ![null, undefined, 0].includes(row.replacementFence)
        || !exactToken(row.rebuildMachineId, /^[a-f0-9]{32}$/)
        || !exactToken(row.rebuildInstallToken, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/)
        || !exactToken(row.backupId, /^[a-f0-9]{32}$/) || row.secretRevision !== 1
        || typeof row.pskEncrypted !== 'string' || !row.pskEncrypted
        || !(row.installedAt instanceof Date) || !Number.isFinite(row.installedAt.getTime())) throw inventoryInvalid();
    return sourcePool(row);
}

async function enrollSource(env, id, state, readNode) {
    const getNode = async () => {
        const node = await readNode(id);
        if (String(node?._id) !== id || node.type !== 'xray' || node.active !== true || node.cascadeRole !== 'relay'
            || node.useCustomConfig) throw inventoryInvalid();
        return node;
    };
    const node = await getNode();
    const notEnrolled = () => fail('ACCOUNT_SOURCE_NOT_ENROLLED');
    let fence;
    try { fence = captureRelayBinding(env, id, node); }
    catch { throw notEnrolled(); }
    // The singleton can authorize a standalone first install, not a cohort.
    if (!fence.listMode || fence.binding.machineId !== state.rebuildMachineId) throw notEnrolled();
    return { node, binding: fence.binding, async verifyBinding() {
        const current = await getNode();
        try { fence.check(current); } catch { throw notEnrolled(); }
    } };
}

// Login is the logical key. Source IP and the per-row sync revision are local
// to each relay. Agreement is on the actual envelope and enablement, not on
// decrypted passwords (independent historical bootstraps must not be merged).
async function resolveAccountSources({ nodeId, rows, env, key, readNode }) {
    const sources = new Map();
    const stateIds = new Set(), machineIds = new Set();
    const occupied = [], allocations = [];
    for (const state of rows.states) {
        const id = String(state.node);
        if (!objectId(id) || id === nodeId || stateIds.has(id)) throw inventoryInvalid();
        stateIds.add(id);
        if (state.status !== 'not_installed' || state.desiredState !== 'absent') {
            occupied.push(state);
            if (state.localAddress != null && state.localAddress !== '') allocations.push(state.localAddress);
        }
        if (state.routingMode !== FOLLOW_RELAY_MODE && empty(state.rebuildInstallToken) && empty(state.rebuildMachineId)) {
            // Not a source or an authorization to mint over an existing install.
            if (state.status === 'installed') throw inventoryInvalid();
            if (state.desiredState === 'installed' || state.operationId != null || transitional.has(state.status)) {
                throw fail('ACCOUNT_SOURCE_BUSY');
            }
            continue;
        }
        const pool = installedSource(state);
        if (machineIds.has(state.rebuildMachineId) || [...sources.values()].some(source =>
            pool.first <= source.pool.last && pool.last >= source.pool.first)) throw inventoryInvalid();
        machineIds.add(state.rebuildMachineId);
        sources.set(id, { state, pool, accounts: new Map() });
    }
    const assigned = new Set();
    for (const row of rows.users) {
        const source = sources.get(String(row.relayNode));
        if (!source || !objectId(row._id) || !validLogin(row.login) || !isIPv4(row.ip)
            || typeof row.enabled !== 'boolean' || typeof row.passwordEncrypted !== 'string' || !row.passwordEncrypted
            || source.accounts.has(row.login) || assigned.has(row.ip)
            || ipv4(row.ip) < source.pool.lo || ipv4(row.ip) > source.pool.hi) throw inventoryInvalid();
        if (row.syncStatus !== 'synced' || row.syncOperationId != null || !Number.isSafeInteger(row.desiredRevision)
            || row.desiredRevision < 1 || row.desiredRevision !== row.appliedRevision) throw fail('ACCOUNT_SOURCE_BUSY');
        source.accounts.set(row.login, { login: row.login, enabled: row.enabled, passwordEncrypted: row.passwordEncrypted, ip: row.ip });
        assigned.add(row.ip);
        allocations.push(row.ip);
    }
    let canonical;
    for (const [id, source] of sources) {
        const initial = source.accounts.get(bootstrap);
        if (!initial?.enabled || initial.ip !== source.state.poolStart) throw inventoryInvalid();
        if (canonical && (canonical.size !== source.accounts.size || [...canonical].some(([login, account]) => {
            const replica = source.accounts.get(login);
            return !replica || replica.enabled !== account.enabled || replica.passwordEncrypted !== account.passwordEncrypted;
        }))) throw fail('ACCOUNT_SOURCE_CONFLICT');
        canonical ??= source.accounts;
    }
    const prechecks = [];
    for (const [id, { state, accounts }] of sources) {
        const enrollment = await enrollSource(env, id, state, readNode);
        const { backupId, clientCidr, tproxyPort, fwmark, routeTable } = state;
        const installation = { nodeId: id, backupId, network: { clientCidr, tproxyPort, fwmark, routeTable } };
        let currentUsers;
        try {
            currentUsers = [...accounts.keys()].sort().map(login => {
                const { ip, enabled, passwordEncrypted } = accounts.get(login);
                return { login, ipAddress: ip, enabled, password: decrypt(passwordEncrypted, key) };
            });
        } catch { throw inventoryInvalid(); }
        prechecks.push({ ...enrollment, installation, currentUsers });
    }
    // Allocate bootstrap first: account lifecycle requires it at poolStart on
    // each relay, regardless of where its login sorts among inherited accounts.
    const inherited = canonical && [bootstrap, ...[...canonical.keys()].filter(login => login !== bootstrap).sort()]
        .map(login => {
            const { enabled, passwordEncrypted } = canonical.get(login);
            return { login, enabled, passwordEncrypted };
        });
    return { occupied, allocations, inherited, prechecks };
}

module.exports = { resolveAccountSources };
