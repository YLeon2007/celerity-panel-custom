'use strict';

const { isIPv4 } = require('node:net');
const { Types: { ObjectId } } = require('mongoose');
const { ROUTE_GROUP_MODE, FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');
const { decrypt } = require('../modules/relay-l2tp/services/secretBoxService');
const { ipv4, occupiedRange, validLogin } = require('./rebuildRelayBackendDesired');
const { captureRelayEffect, identityChanged, isIdentityChanged } = require('./rebuildRelayEffectAuthority');
const { logicalAccount, sameAccounts } = require('./rebuildRelayDirectory');

const fail = code => Object.assign(new Error(`REBUILD_L2TP_${code}`), { code: `REBUILD_L2TP_${code}` });
const inventoryInvalid = () => fail('ACCOUNT_INVENTORY_INVALID');
const exactToken = (value, re) => typeof value === 'string' && re.exec(value)?.[0] === value;
const hexId = value => {
    const hex = value instanceof ObjectId ? value.toHexString() : value;
    return exactToken(hex, /^[a-f0-9]{24}$/) ? hex : undefined;
};
const empty = value => value == null || value === '';
const zero = value => value == null || value === 0;
const bootstrap = 'relay-bootstrap';
const stateStatuses = new Set(['not_installed', 'queued', 'preflight', 'installing', 'installed', 'degraded',
    'drifted', 'removing', 'error', 'role_lost']);
const terminalOperations = ['succeeded', 'failed', 'cancelled', 'rolled_back'];
const activeOperations = new Set(['queued', 'running', 'rolling_back']);
const classicLimit = 1024;
const operationLimit = 4096;

const classicRouting = state => (state.routingMode === undefined || state.routingMode === ROUTE_GROUP_MODE)
    && state.routingVersion === undefined;
const unowned = state => empty(state.rebuildInstallToken) && empty(state.rebuildMachineId);
const validClassicRefs = state => (state._id === undefined || !!hexId(state._id))
    && (state.operationId == null || !!hexId(state.operationId))
    && (state.routeGroup == null || !!hexId(state.routeGroup))
    && (state.activePathKey == null || typeof state.activePathKey === 'string');

// Shape only: classic uninstall can retain the pool, PSK, path, group and
// operation pointer. This predicate says nothing about outstanding work and
// must not be used as target freshness or proof of physical absence.
function isDormantClassicState(state) {
    return !!state && !!hexId(state.node) && classicRouting(state) && unowned(state) && validClassicRefs(state)
        && zero(state.pppDriftQueueFence) && zero(state.replacementFence)
        && state.status === 'not_installed' && ['not_installed', 'absent'].includes(state.desiredState);
}

function classicScope(states) {
    if (!Array.isArray(states)) throw inventoryInvalid();
    const nodes = new Map(), pointers = new Map(), seen = new Set();
    for (const state of states) {
        const node = hexId(state?.node);
        if (!node || seen.has(node) || !stateStatuses.has(state.status)
            || !['installed', 'absent', 'not_installed'].includes(state.desiredState)) throw inventoryInvalid();
        seen.add(node);
        if (state.routingMode === FOLLOW_RELAY_MODE) continue;
        if (!classicRouting(state) || !validClassicRefs(state)) throw inventoryInvalid();
        if (!isDormantClassicState(state)) continue;
        nodes.set(node, state);
        const pointer = hexId(state.operationId);
        if (pointer) {
            if (pointers.has(pointer)) throw inventoryInvalid();
            pointers.set(pointer, state);
        }
        if (nodes.size > classicLimit) throw inventoryInvalid();
    }
    return { nodes, pointers };
}

function validateClassicOperations({ nodes, pointers }, rows) {
    if (!Array.isArray(rows) || rows.length > operationLimit) throw inventoryInvalid();
    const seen = new Set();
    let active = false;
    for (const row of rows) {
        const id = hexId(row?._id), node = hexId(row?.node);
        const state = nodes.get(node), pointedBy = pointers.get(id);
        const terminal = terminalOperations.includes(row?.status);
        if (!id || seen.has(id) || !state || typeof row.node !== typeof state.node
            || (pointedBy && (pointedBy !== state || typeof row._id !== typeof pointedBy.operationId))
            || (terminal ? !pointedBy : !activeOperations.has(row.status))) throw inventoryInvalid();
        seen.add(id);
        if (!terminal) active = true;
    }
    return active;
}

// Native read: Mongoose would cast string query operands to ObjectId. Query
// both spellings to detect a persisted type mismatch, never to authorize one.
const typedRefs = ids => [...ids].flatMap(hex => [new ObjectId(hex), hex]);

// Pass the same states to this reader and inspectAccountSources, with the
// returned array as rows.classicOperations. [] is a completed observation
// (or no dormant candidates), never a substitute for omitted/failed I/O.
// A supplied session must be the caller's active snapshot transaction.
async function readClassicOperations(db, states, session) {
    const scope = classicScope(states);
    if (!scope.nodes.size) return [];
    if (session != null && session.inTransaction?.() !== true) throw inventoryInvalid();
    // Classic Install enqueues by node before the worker updates the state
    // pointer. Read every nonterminal job on the node as well as the pointed
    // row (even terminal or on a wrong node). Compare the entire status value
    // so a malformed array containing a terminal token cannot hide a job.
    const byNode = { node: { $in: typedRefs(scope.nodes.keys()) },
        $expr: { $not: [{ $in: ['$status', terminalOperations] }] } };
    const filter = scope.pointers.size ? { $or: [{ _id: { $in: typedRefs(scope.pointers.keys()) } }, byNode] } : byNode;
    const rows = await db.collection('l2tpoperations').find(filter, {
        projection: { _id: 1, node: 1, status: 1 }, collation: { locale: 'simple' },
        limit: operationLimit + 1, maxTimeMS: 5000, timeoutMS: 5000,
        ...(session ? { session } : { readPreference: 'primary', readConcern: { level: 'majority' } }),
    }).toArray();
    validateClassicOperations(scope, rows);
    return rows.map(({ _id, node, status }) => ({ _id, node, status }))
        .sort((a, b) => hexId(a._id).localeCompare(hexId(b._id)));
}

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
    if (!hexId(row._id) || row.routingMode !== FOLLOW_RELAY_MODE || row.routingVersion !== FOLLOW_RELAY_VERSION
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

async function enrollSource(env, relayGrantStore, snapshot, id, state, readNode) {
    const getNode = async () => {
        const node = await readNode(id);
        if (String(node?._id) !== id || node.type !== 'xray' || node.active !== true || node.cascadeRole !== 'relay'
            || node.useCustomConfig) throw inventoryInvalid();
        return node;
    };
    const node = await getNode();
    const notEnrolled = () => fail('ACCOUNT_SOURCE_NOT_ENROLLED');
    let fence;
    try { fence = captureRelayEffect(env, relayGrantStore, snapshot, id, node); }
    catch (error) {
        if (isIdentityChanged(error)) throw error;
        throw notEnrolled();
    }
    if (relayGrantStore && fence.binding.machineId !== state.rebuildMachineId) throw identityChanged();
    // The singleton can authorize a standalone first install, not a cohort.
    if (!fence.listMode || fence.binding.machineId !== state.rebuildMachineId) throw notEnrolled();
    return { node, fence, async verifyBinding() {
        const current = await getNode();
        try { await fence.check(current); } catch (error) {
            if (relayGrantStore) throw error;
            throw notEnrolled();
        }
    } };
}

function validateAccount(row, pool, logins, addresses) {
    if (!hexId(row._id) || !validLogin(row.login) || !isIPv4(row.ip) || typeof row.enabled !== 'boolean'
        || typeof row.passwordEncrypted !== 'string' || !row.passwordEncrypted || logins.has(row.login)
        || addresses.has(row.ip) || ipv4(row.ip) < pool.lo || ipv4(row.ip) > pool.hi) throw inventoryInvalid();
    if (row.syncStatus !== 'synced' || row.syncOperationId != null || !Number.isSafeInteger(row.desiredRevision)
        || row.desiredRevision < 1 || row.desiredRevision !== row.appliedRevision) throw fail('ACCOUNT_SOURCE_BUSY');
}

// Remove needs the selected installation's physical preimage, not the
// logical account set inherited by another relay. Keep disabled rows in the
// projection: DIRECT validates their login/IP ownership, but renders no row.
function projectRelayChap(state, rows, key) {
    const pool = installedSource(state);
    if (!Array.isArray(rows) || !rows.length || rows.length > 2048 || typeof key !== 'string' || key.length < 32) {
        throw inventoryInvalid();
    }
    const logins = new Set(), addresses = new Set();
    const currentUsers = rows.map(row => {
        if (String(row.relayNode) !== String(state.node)) throw inventoryInvalid();
        validateAccount(row, pool, logins, addresses);
        logins.add(row.login);
        addresses.add(row.ip);
        let password;
        try { password = decrypt(row.passwordEncrypted, key); } catch { throw inventoryInvalid(); }
        if (!(/^[ -~]{1,255}(?![\s\S])/.test(password) || /^[A-Za-z0-9_-]{256}(?![\s\S])/.test(password))
            || password.startsWith('@')) throw inventoryInvalid();
        return Object.freeze({ login: row.login, password, ipAddress: row.ip, enabled: row.enabled });
    });
    return Object.freeze(currentUsers.sort((a, b) => (a.login > b.login) - (a.login < b.login)));
}

// Login is the logical key. Source IP and the per-row sync revision are local
// to each relay. Agreement is on the actual envelope and enablement, not on
// decrypted passwords (independent historical bootstraps must not be merged).
// Callers with a dormant candidate must supply rows.classicOperations from
// readClassicOperations against this same set of states. No I/O occurs here.
function inspectAccountSources({ nodeId, rows, listMode }) {
    const scope = classicScope(rows?.states);
    if (scope.nodes.size || Object.hasOwn(rows, 'classicOperations')) {
        if (!Object.hasOwn(rows, 'classicOperations')) throw inventoryInvalid();
        if (validateClassicOperations(scope, rows.classicOperations)) throw fail('ACCOUNT_SOURCE_BUSY');
    }
    if (!Array.isArray(rows.users)) throw inventoryInvalid();
    const sources = new Map();
    const machineIds = new Set();
    const occupied = [], allocations = [];
    for (const state of rows.states) {
        const id = hexId(state.node);
        if (id === nodeId) throw inventoryInvalid();
        if (scope.nodes.has(id)) continue; // Eligible shape and verified idle.
        if (classicRouting(state) && unowned(state)) {
            if (state.status === 'installed') throw inventoryInvalid();
            throw fail('ACCOUNT_SOURCE_BUSY');
        }
        const pool = installedSource(state);
        occupied.push(state);
        allocations.push(state.localAddress);
        if (machineIds.has(state.rebuildMachineId) || [...sources.values()].some(source =>
            pool.first <= source.pool.last && pool.last >= source.pool.first)) throw inventoryInvalid();
        machineIds.add(state.rebuildMachineId);
        sources.set(id, { state, pool, accounts: new Map() });
    }
    const assigned = new Set();
    for (const row of rows.users) {
        const source = sources.get(String(row.relayNode));
        // Historical singleton did not take ownership of another node's
        // account rows. Keep that behavior when no installed source exists.
        if (!source && !listMode && sources.size === 0 && String(row.relayNode) !== nodeId) continue;
        if (!source) throw inventoryInvalid();
        validateAccount(row, source.pool, source.accounts, assigned);
        source.accounts.set(row.login, { ...logicalAccount(row), ip: row.ip });
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
    const legacy = canonical && [...canonical.values()].map(({ ip: _, ...account }) => account);
    return { sources, occupied, allocations, legacy, machineIds };
}

async function resolveAccountSources({ nodeId, rows, env, relayGrantStore, snapshot, key, readNode, listMode, machineId }) {
    const { sources, occupied, allocations, legacy, machineIds } = inspectAccountSources({ nodeId, rows, listMode });
    if (machineIds.has(machineId)) throw inventoryInvalid();
    const catalog = rows.directory?.accounts;
    if (catalog && legacy && !sameAccounts(catalog, legacy)) throw fail('ACCOUNT_SOURCE_CONFLICT');
    if (catalog && !listMode && (catalog.length !== 1 || sources.size)) throw inventoryInvalid();
    const prechecks = [];
    for (const [id, { state, accounts }] of catalog ? [] : sources) {
        const enrollment = await enrollSource(env, relayGrantStore, snapshot, id, state, readNode);
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
    const shared = catalog ?? legacy;
    const inherited = shared && [...shared].sort((a, b) => a.login === bootstrap ? -1 : b.login === bootstrap ? 1
        : (a.login > b.login) - (a.login < b.login));
    return { occupied, allocations, inherited, prechecks };
}

module.exports = { resolveAccountSources, inspectAccountSources, projectRelayChap, isDormantClassicState, readClassicOperations };
