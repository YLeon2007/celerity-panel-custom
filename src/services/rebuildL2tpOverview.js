'use strict';

const { isIP, isIPv4 } = require('node:net');
const { isDeepStrictEqual: equal } = require('node:util');
const { resolveRelayBinding: defaultResolveBinding } = require('./rebuildRelayAuthorization');
const { assertNoPendingRelayAccounts } = require('./rebuildRelayAccountsStore');
const { readDirectory, sameAccounts } = require('./rebuildRelayDirectory');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');
const { decrypt } = require('../modules/relay-l2tp/services/secretBoxService');

const relayList = 'C3_REBUILD_L2TP_RELAYS_JSON';
const idPattern = /^[a-f0-9]{24}(?![\s\S])/;
const loginPattern = /^[A-Za-z0-9._@-]{1,64}(?![\s\S])/;
const receiptPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}(?![\s\S])/;
const hex32 = /^[a-f0-9]{32}(?![\s\S])/;
const matches = (pattern, value) => typeof value === 'string' && pattern.test(value);
const nonempty = value => typeof value === 'string' && value.length > 0;
const empty = value => value == null || value === '';
const stamp = value => value instanceof Date ? value.getTime() : NaN;
const compare = (a, b) => (a > b) - (a < b);
const read = (query, fields) => query.select(fields).read('primary').readConcern('majority').maxTimeMS(5000).lean();

const nodeFields = '_id name ip cascadeRole ssh.port ssh.username type active useCustomConfig';
// Name hidden paths explicitly in these inclusive projections: +path alone
// overrides select:false but is not an allowlist.
const stateFields = '_id node status desiredState routingMode routingVersion routeGroup operationId activePathKey'
    + ' appliedTopologyRevision pppDriftQueueFence replacementFence secretRevision backupId rebuildInstallToken rebuildMachineId'
    + ' poolStart poolEnd installedAt lastVerifiedAt lastSyncAt';
const userFields = '_id relayNode login ip enabled syncStatus syncOperationId desiredRevision appliedRevision'
    + ' createdAt updatedAt lastSyncedAt createdBy updatedBy';
const absentState = { status: 'not_installed', desiredState: 'absent' };
// Match the first Install store's pristine metadata, without retrieving a
// retained envelope or hint in the ordinary overview.
const pristineFilter = {
    ...absentState,
    routingMode: { $in: [null, 'route-group'] },
    ...Object.fromEntries(['secretRevision', 'pppDriftQueueFence', 'replacementFence'].map(key => [key, { $in: [null, 0] }])),
    ...Object.fromEntries(['pskEncrypted', 'pskHint', 'backupId', 'managedVersion', 'configFingerprint', 'rebuildInstallToken',
        'rebuildMachineId', 'activePathKey'].map(key => [key, { $in: [null, ''] }])),
    ...Object.fromEntries(['routeGroup', 'routingVersion', 'operationId', 'installedAt', 'lastVerifiedAt', 'lastSyncAt',
        'appliedTopologyRevision'].map(key => [key, null])),
};

// These are persisted DB receipts, not live attestation or mutation admission.
function ownedState(row, binding) {
    return !!(row && binding && matches(idPattern, String(row._id)) && String(row.node) === binding.nodeId
        && row.status === 'installed' && row.desiredState === 'installed'
        && row.routingMode === FOLLOW_RELAY_MODE && row.routingVersion === FOLLOW_RELAY_VERSION
        && row.routeGroup == null && row.operationId == null && empty(row.activePathKey)
        && row.appliedTopologyRevision == null && (row.pppDriftQueueFence ?? 0) === 0 && (row.replacementFence ?? 0) === 0
        && row.secretRevision === 1 && matches(hex32, row.backupId) && matches(receiptPattern, row.rebuildInstallToken)
        && matches(hex32, row.rebuildMachineId) && row.rebuildMachineId === binding.machineId
        && Number.isFinite(stamp(row.installedAt)));
}

function synced(row) {
    return matches(idPattern, String(row._id)) && isIPv4(row.ip) && typeof row.enabled === 'boolean'
        && row.syncStatus === 'synced' && row.syncOperationId == null && Number.isSafeInteger(row.desiredRevision)
        && row.desiredRevision > 0 && row.desiredRevision === row.appliedRevision;
}

// The singleton installer only publishes bootstrap. Its account and state
// share the same finish receipt, even if a later Apply changed updatedAt on state.
function legacyAccount(row, state) {
    const installed = stamp(state.installedAt);
    return row.login === 'relay-bootstrap' && row.enabled === true && row.desiredRevision === 1
        && row.ip === state.poolStart && empty(row.createdBy) && empty(row.updatedBy)
        && stamp(row.createdAt) <= installed && stamp(row.updatedAt) === installed && stamp(row.lastSyncedAt) === installed
        && stamp(state.lastVerifiedAt) === installed && stamp(state.lastSyncAt) === installed;
}

const bootstrap = 'relay-bootstrap';
const ipv4 = value => isIPv4(value) ? value.split('.').reduce((n, part) => n * 256 + Number(part), 0) : NaN;

function inventoryMatches(rows, cohort, list) {
    if (!cohort?.size) return false;
    if (!list) {
        if (rows.length !== 1 || !synced(rows[0])) return false;
        const state = cohort.get(String(rows[0].relayNode));
        return !!state && legacyAccount(rows[0], state);
    }
    const members = new Map([...cohort].map(([id, state]) => [id, { start: ipv4(state.poolStart), end: ipv4(state.poolEnd),
        logins: new Map(), ips: new Set() }]));
    for (const row of rows) {
        const member = members.get(String(row.relayNode));
        if (!member || !synced(row) || !matches(loginPattern, row.login)) return false;
        const { start, end, logins, ips } = member;
        const ip = ipv4(row.ip);
        if (!(ip >= start && ip <= end) || logins.size >= 2048 || logins.has(row.login) || ips.has(ip)
            || (row.login === bootstrap && (!row.enabled || ip !== start))) return false;
        logins.set(row.login, row.enabled);
        ips.add(ip);
    }
    let first;
    for (const { logins } of members.values()) {
        if (logins.get(bootstrap) !== true) return false;
        if (first && !equal(logins, first)) return false;
        first ??= logins;
    }
    return true;
}

function replicasAgree(rows, cohort, listMode, ciphertext = false) {
    if (!cohort || rows.length !== cohort.size) return false;
    const seen = new Set();
    return rows.every(row => {
        const id = String(row.relayNode), state = cohort.get(id);
        if (!state || seen.has(id)) return false;
        seen.add(id);
        return synced(row) && row.enabled === rows[0].enabled && (listMode || legacyAccount(row, state))
            && (!ciphertext || (nonempty(row.passwordEncrypted) && row.passwordEncrypted === rows[0].passwordEncrypted));
    });
}

function createRebuildL2tpOverview({ Node = require('../models/hyNodeModel'),
    State = require('../modules/relay-l2tp/models/relayL2tpStateModel'),
    L2tpUser = require('../modules/relay-l2tp/models/l2tpUserModel'), env = process.env,
    resolveRelayBinding = defaultResolveBinding } = {}) {
    const listMode = () => Object.hasOwn(env, relayList);
    const statuses = State.schema.path('status').enumValues;
    const findNodes = (filter = {}) => read(Node.find({ ...filter, cascadeRole: 'relay' }).sort('_id'), nodeFields);
    const hasKey = () => typeof env.ENCRYPTION_KEY === 'string' && env.ENCRYPTION_KEY.length >= 32;
    const eligible = (row, list) => row?.cascadeRole === 'relay' && row.active === true && row.type === 'xray'
        && !row.useCustomConfig && (list || !!isIP(row.ip));
    function bindingFor(row) {
        if (!row || row.cascadeRole !== 'relay') return null;
        const { _id, name, ip, cascadeRole, ssh } = row;
        try {
            return resolveRelayBinding(env, String(_id), { _id, name, ip, cascadeRole, ssh: { port: ssh?.port, username: ssh?.username } });
        } catch { return null; }
    }
    async function hasPendingAccounts() {
        if (Node.db !== State.db || Node.db !== L2tpUser.db) throw new Error('Rebuild L2TP persistence unavailable');
        try { await assertNoPendingRelayAccounts(L2tpUser.db); return false; }
        catch (error) {
            if (error.code === 'REBUILD_L2TP_ACCOUNTS_BLOCKED') return true;
            throw error;
        }
    }
    function ownedCohort(states, owned, list) {
        // This is the same global non-absent scope used by the account
        // writer, not just the subset of enrolled nodes visible on the page.
        if (states.length === 0 || states.length !== owned.size || (!list && states.length !== 1)) return null;
        return owned;
    }
    async function stableReveal(load, envelopeFor) {
        const key = env.ENCRYPTION_KEY;
        if (!hasKey() || await hasPendingAccounts()) return null;
        const before = await load();
        if (!before || !nonempty(envelopeFor(before)) || await hasPendingAccounts()) return null;
        // Read-only recheck: a Remove reservation can leave the account rows
        // untouched, and an account publication can clear its intent. Recheck
        // both witnesses without taking a writer lock or requiring a replica set.
        const after = await load();
        if (!equal(before, after) || await hasPendingAccounts() || env.ENCRYPTION_KEY !== key) return null;
        const value = envelopeFor(after);
        if (!nonempty(value)) return null;
        try { return decrypt(value, key) || null; } catch { return null; }
    }

    async function overview() {
        const [nodes, states, rows] = await Promise.all([
            findNodes(), read(State.find({}), stateFields), read(L2tpUser.find({}), userFields),
        ]);
        const byNode = new Map(), duplicates = new Set();
        for (const row of states) {
            const id = String(row.node);
            if (byNode.has(id)) duplicates.add(id);
            byNode.set(id, row);
        }
        const maybePristine = states.filter(row => row.status === 'not_installed' && row.desiredState === 'absent');
        const pristineIds = new Set(maybePristine.length ? (await read(State.find({ ...pristineFilter,
            _id: { $in: maybePristine.map(row => row._id) } }), '_id')).map(row => String(row._id)) : []);
        const accountsPending = await hasPendingAccounts();
        const clear = !accountsPending, list = listMode(), owned = new Map();
        const withUsers = new Set(rows.map(row => String(row.relayNode)));
        const relays = nodes.sort((a, b) => compare(String(a._id), String(b._id))).map(row => {
            const id = String(row._id), state = byNode.get(id), binding = bindingFor(row);
            const qualified = eligible(row, list) && !duplicates.has(id);
            if (qualified && ownedState(state, binding)) owned.set(id, state);
            return { id, name: typeof row.name === 'string' ? row.name : '', ip: typeof row.ip === 'string' ? row.ip : '',
                status: !state ? 'not_installed' : statuses.includes(state.status) ? state.status : 'error', bound: !!binding,
                canInstall: clear && qualified && !!binding && !withUsers.has(id) && (!state || pristineIds.has(String(state._id))),
                canRemove: clear && owned.has(id), canRevealPsk: clear && owned.has(id) && hasKey() };
        });
        const cohort = list ? ownedCohort(states.filter(row => row.status !== 'not_installed' || row.desiredState !== 'absent'), owned, list)
            : owned.size === 1 ? owned : null;
        const accountRows = list ? rows : rows.filter(row => owned.has(String(row.relayNode)));
        // An unfinished operation can leave this inventory unsettled. Do not
        // require a consistent directory to report the persisted fence.
        const directory = clear ? await readDirectory(L2tpUser.db, undefined, true) : null;
        const inventoryOk = clear && inventoryMatches(rows.filter(row => owned.has(String(row.relayNode))), cohort, list)
            && (!directory || [...cohort.keys()].every(id => sameAccounts(directory.accounts,
                rows.filter(row => String(row.relayNode) === id), false)));
        const grouped = new Map();
        for (const row of accountRows) {
            if (!matches(loginPattern, row.login)) continue;
            if (!grouped.has(row.login)) grouped.set(row.login, []);
            grouped.get(row.login).push(row);
        }
        const accounts = [];
        for (const [login, copies] of grouped) {
            const visible = copies.filter(row => {
                const state = owned.get(String(row.relayNode));
                return state && (list || legacyAccount(row, state));
            });
            if (!visible.length) continue;
            const consistent = inventoryOk && replicasAgree(copies, cohort, list);
            accounts.push({ login, enabled: visible.every(row => row.enabled === true),
                // GET can establish membership, sync and enabled agreement,
                // but intentionally cannot compare the encrypted envelopes.
                consistent, canRevealPassword: consistent && hasKey(),
                addresses: visible.filter(row => isIPv4(row.ip)).map(row => ({ id: String(row.relayNode), ip: row.ip }))
                    .sort((a, b) => compare(a.id, b.id)) });
        }
        if (directory && !rows.length && states.every(row => row.status === absentState.status && row.desiredState === absentState.desiredState)
            && (list || (directory.accounts.length === 1 && matches(idPattern, env.C3_REBUILD_L2TP_RELAY_ID)))) {
            for (const { login, enabled } of directory.accounts) {
                accounts.push({ login, enabled, consistent: clear, canRevealPassword: clear && hasKey(), addresses: [] });
            }
        }
        accounts.sort((a, b) => compare(a.login, b.login));
        return { relays, accounts, accountsPending, canReconcileAccounts: accountsPending && list,
            canManageAccounts: list && hasKey() && inventoryOk && accounts.every(row => row.consistent) };
    }

    function passwordCohort(states, nodes, list) {
        const byNode = new Map(nodes.map(node => [String(node._id), node]));
        const owned = new Map();
        for (const state of states) {
            const id = String(state.node), node = byNode.get(id);
            if (eligible(node, list) && ownedState(state, bindingFor(node))) owned.set(id, state);
        }
        return ownedCohort(states, owned, list);
    }

    async function revealPassword(login) {
        if (!matches(loginPattern, login)) return null;
        return stableReveal(async () => {
            const list = listMode();
            const singleton = env.C3_REBUILD_L2TP_RELAY_ID;
            if (!list && (!matches(idPattern, singleton) || login !== bootstrap)) return null;
            const filter = list ? { $nor: [absentState] } : { node: singleton };
            const states = await read(State.find(filter).sort('_id'), stateFields);
            if (states.some(row => !matches(idPattern, String(row.node)))) return null;
            const directory = await readDirectory(L2tpUser.db);
            if (states.length === 0 || (!list && states.length === 1 && states[0].status === absentState.status
                && states[0].desiredState === absentState.desiredState)) {
                if (!directory || (!list && directory.accounts.length !== 1)) return null;
                if ((!list && await read(State.findOne({ $nor: [absentState] }), '_id'))
                    || await read(L2tpUser.findOne({}), '_id')) return null;
                return { list, dormant: true, directory, states };
            }
            const nodes = await findNodes({ _id: { $in: states.map(row => row.node) } });
            const cohort = passwordCohort(states, nodes, list);
            if (!cohort) return null;
            const scope = list ? {} : { relayNode: singleton };
            const inventoryScope = list ? { $or: [{ relayNode: { $in: states.map(row => row.node) } }, { login }] } : scope;
            const inventory = await read(L2tpUser.find(inventoryScope).sort('_id'), userFields);
            if (!inventoryMatches(inventory, cohort, list)) return null;
            if (directory && ![...cohort.keys()].every(id => sameAccounts(directory.accounts,
                inventory.filter(row => String(row.relayNode) === id), false))) return null;
            // An unexpected same-login replica invalidates the account; don't
            // filter down to a good-looking subset of the installed cohort.
            const copies = await read(L2tpUser.find({ ...scope, login }).sort('_id'), `${userFields} passwordEncrypted`);
            if (!equal(inventory.filter(row => row.login === login), copies.map(({ passwordEncrypted: _, ...row }) => row))) return null;
            return { list, nodes, states, inventory, copies, directory };
        }, ({ list, dormant, states, nodes, copies, directory }) => {
            if (list !== listMode()) return null;
            const account = directory?.accounts.find(row => row.login === login);
            if (dormant) return account?.passwordEncrypted;
            if (!replicasAgree(copies, passwordCohort(states, nodes, list), list, true)) return null;
            if (directory && (!account || account.enabled !== copies[0].enabled || account.passwordEncrypted !== copies[0].passwordEncrypted)) return null;
            return copies[0].passwordEncrypted;
        });
    }

    async function revealPsk(id) {
        if (!matches(idPattern, id)) return null;
        return stableReveal(async () => {
            const list = listMode();
            const [node] = await findNodes({ _id: id });
            if (!eligible(node, list) || !bindingFor(node)) return null;
            const state = await read(State.findOne({ node: id }), `${stateFields} pskEncrypted`);
            return { list, node, state };
        }, ({ list, node, state }) => list === listMode() && ownedState(state, bindingFor(node)) ? state.pskEncrypted : null);
    }
    return Object.freeze({ overview, revealPassword, revealPsk, hasPendingAccounts });
}

module.exports = { createRebuildL2tpOverview };
