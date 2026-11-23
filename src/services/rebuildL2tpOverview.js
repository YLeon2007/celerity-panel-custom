'use strict';

const { isIP, isIPv4 } = require('node:net');
const { isDeepStrictEqual: equal } = require('node:util');
const { Types: { ObjectId } } = require('mongoose');
const { resolveRelayBinding: defaultResolveBinding, normalizeRelayBinding, parseRelayBindingList, sameRelayBinding,
    relayInstallEnabled, relayBindingFields, relayListKey: relayList } = require('./rebuildRelayAuthorization');
const { createRelayGrantStore } = require('./rebuildRelayGrantStore');
const { assertNoPendingRelayAccounts } = require('./rebuildRelayAccountsStore');
const { readDirectory, sameAccounts, collectionName: accountsCollection } = require('./rebuildRelayDirectory');
const { inspectAccountSources, isDormantClassicState, readClassicOperations } = require('./rebuildRelayAccountInventory');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');
const { decrypt } = require('../modules/relay-l2tp/services/secretBoxService');
const { publicProgress } = require('./rebuildInstallProgress');

const legacyId = 'C3_REBUILD_L2TP_RELAY_ID';
const legacyMachine = 'C3_REBUILD_L2TP_RELAY_MACHINE_ID';
const legacyPin = 'C3_REBUILD_L2TP_SSH_SHA256';
const identityChanged = 'REBUILD_L2TP_IDENTITY_CHANGED';
const disabled = 'REBUILD_L2TP_INSTALL_DISABLED';
const conflict = 'REBUILD_L2TP_GRANT_CONFLICT';
const grantUnavailable = 'REBUILD_L2TP_GRANT_PERSISTENCE_UNAVAILABLE';
const grantProblems = new Set([conflict, grantUnavailable, 'REBUILD_L2TP_GRANT_ENV_INVALID',
    'REBUILD_L2TP_GRANT_REGISTRY_INVALID', 'REBUILD_L2TP_GRANT_INVALID', 'REBUILD_L2TP_GRANT_CHANGED',
    'REBUILD_L2TP_GRANT_UNAVAILABLE']);
const grantError = code => Object.assign(new Error(code), { code });
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
const nativeRead = { readPreference: 'primary', readConcern: { level: 'majority' }, maxTimeMS: 5000, timeoutMS: 5000 };

const nodeFields = '_id name ip cascadeRole ssh.port ssh.username type active useCustomConfig';
// Name hidden paths explicitly in these inclusive projections: +path alone
// overrides select:false but is not an allowlist.
const stateFields = '_id node status desiredState routingMode routingVersion routeGroup operationId activePathKey'
    + ' appliedTopologyRevision pppDriftQueueFence replacementFence secretRevision backupId rebuildInstallToken rebuildMachineId'
    + ' poolStart poolEnd installedAt lastVerifiedAt lastSyncAt';
const userFields = '_id relayNode login ip enabled syncStatus syncOperationId desiredRevision appliedRevision'
    + ' createdAt updatedAt lastSyncedAt createdBy updatedBy';
const absentState = { status: 'not_installed', desiredState: 'absent' };
const isAbsent = row => row.status === absentState.status && row.desiredState === absentState.desiredState;
const fences = ['pppDriftQueueFence', 'replacementFence'];
const emptyInstallFields = ['pskEncrypted', 'pskHint', 'backupId', 'managedVersion', 'configFingerprint', 'rebuildInstallToken',
    'rebuildMachineId', 'activePathKey'];
const nullableInstallFields = ['routeGroup', 'routingVersion', 'operationId', 'installedAt', 'lastVerifiedAt',
    'lastSyncAt', 'appliedTopologyRevision'];
// Match the first Install store's pristine metadata, without retrieving a
// retained envelope or hint in the ordinary overview.
const pristineFilter = {
    ...absentState,
    routingMode: { $in: [null, 'route-group'] },
    ...Object.fromEntries(['secretRevision', ...fences].map(key => [key, { $in: [null, 0] }])),
    ...Object.fromEntries(emptyInstallFields.map(key => [key, { $in: [null, ''] }])),
    ...Object.fromEntries(nullableInstallFields.map(key => [key, null])),
};
// Admission's absence predicate is distinct from first Install: a settled
// Remove may leave monotonically increasing fences, but not a footprint.
const admissionPristineFilter = {
    ...absentState,
    routingMode: pristineFilter.routingMode,
    secretRevision: pristineFilter.secretRevision,
    ...Object.fromEntries([...emptyInstallFields, ...nullableInstallFields, 'lastErrorCode', 'lastError', 'tproxyPort',
        'fwmark', 'routeTable', 'poolStart', 'poolEnd'].map(key => [key, { $in: [null, ''] }])),
};

function admissionEndpoint(row) {
    const nodeId = String(row._id);
    try {
        return normalizeRelayBinding({ nodeId, host: row.ip, port: row.ssh?.port, username: row.ssh?.username,
            machineId: '0'.repeat(32), sshHostKeySha256: '0'.repeat(64) });
    } catch { return null; }
}
const endpointKey = ({ host, port }) => `${host}/${port}`;

function authorityWitness({ env, grants }) {
    return {
        enabled: relayInstallEnabled(env),
        // Distinguish absent from explicitly malformed ENV, including the
        // singleton's no-list contract. Do not compare unrelated secrets.
        config: [relayList, legacyId, legacyMachine, legacyPin].map(key => [Object.hasOwn(env, key), env[key]]),
        grants: grants.map(row => [row.nodeId, row.generation]).sort(([a], [b]) => compare(a, b)),
    };
}

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
    resolveRelayBinding = defaultResolveBinding, relayGrantStore = createRelayGrantStore({ db: Node.db, env }) } = {}) {
    const db = Node.db;
    const statuses = State.schema.path('status').enumValues;
    const findNodes = (filter = {}) => read(Node.find({ ...filter, cascadeRole: 'relay' }).sort('_id'), nodeFields);
    const hasKey = () => typeof env.ENCRYPTION_KEY === 'string' && env.ENCRYPTION_KEY.length >= 32;
    const eligible = (row, list) => row?.cascadeRole === 'relay' && row.active === true && row.type === 'xray'
        && !row.useCustomConfig && (list || !!isIP(row.ip));
    async function readAuthority(options) {
        try {
            const snapshot = await relayGrantStore.snapshot(options);
            if (snapshot?.env && Array.isArray(snapshot.grants) && typeof snapshot.sourceFor === 'function') return snapshot;
        } catch (error) { throw grantError(grantProblems.has(error?.code) ? error.code : grantUnavailable); }
        throw grantError(grantUnavailable);
    }
    function bindingFor(row, config) {
        if (!row || row.cascadeRole !== 'relay') return null;
        const { _id, name, ip, cascadeRole, ssh } = row;
        try {
            return resolveRelayBinding(config, String(_id), { _id, name, ip, cascadeRole, ssh: { port: ssh?.port, username: ssh?.username } });
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
    async function accountScope(states, hasUsers) {
        const classicStates = states.filter(isDormantClassicState);
        const classicIds = new Set(classicStates.map(row => String(row.node)));
        // Check the original scope, not just the filtered one: a duplicate
        // absent/active row or a local replica cannot be hidden by the skip.
        if (states.filter(row => classicIds.has(String(row.node))).length !== classicIds.size) return null;
        let classicOperations = [];
        if (classicStates.length) {
            try {
                classicOperations = await readClassicOperations(db, classicStates);
                // Use the same operation evidence rules as Install/Remove,
                // without reading any envelopes or treating classic as a source.
                inspectAccountSources({ rows: { states: classicStates, users: [], classicOperations }, listMode: true });
            } catch { return null; }
            if (await hasUsers(classicStates.map(row => row.node))) return null;
        }
        return { states: states.filter(row => !classicIds.has(String(row.node))), classicStates, classicOperations };
    }
    async function stableReveal(load, envelopeFor, confirm = () => true) {
        const key = env.ENCRYPTION_KEY;
        if (!hasKey() || await hasPendingAccounts()) return null;
        const authority = await readAuthority();
        const witness = authorityWitness(authority);
        const before = await load(authority);
        if (!before || !nonempty(envelopeFor(before, authority)) || await hasPendingAccounts()) return null;
        // Read-only recheck: a Remove reservation can leave the account rows
        // untouched, and an account publication can clear its intent. Recheck
        // both witnesses without taking a writer lock or requiring a replica set.
        const after = await load(authority);
        if (!equal(before, after) || !await confirm(after) || await hasPendingAccounts()) return null;
        // The grant can change during the last inventory/envelope read without
        // changing either. Compare the effective union AND DB generations.
        const current = await readAuthority();
        if (!equal(witness, authorityWitness(current)) || await hasPendingAccounts() || env.ENCRYPTION_KEY !== key) return null;
        const value = envelopeFor(after, current);
        if (!nonempty(value)) return null;
        try { return decrypt(value, key) || null; } catch { return null; }
    }

    async function readBusyAdmissions(ids) {
        if (!ids.length) return new Set();
        const nodes = ids.map(id => new ObjectId(id));
        // Same footprint as Admission, only the affected IDs, no lock tokens
        // or operation data. POST repeats these checks under its writer lock.
        const scopes = await Promise.all([
            db.collection('l2tpoperations').distinct('node', { node: { $in: nodes },
                status: { $nin: ['succeeded', 'rolled_back', 'cancelled'] } }, nativeRead),
            db.collection('remoteadmissions').distinct('nodeId', { nodeId: { $in: ids }, phase: { $ne: 'completed' } }, nativeRead),
            db.collection('nodeoperationlocks').distinct('node', { node: { $in: nodes } }, nativeRead),
        ]);
        return new Set(scopes.flat().map(String));
    }

    async function recoveryAttestation(cohort, bindings, grants) {
        const keys = [...relayBindingFields, 'grantGeneration', 'backupId'];
        const intent = await db.collection(accountsCollection).findOne({ _id: 'pending' }, {
            ...nativeRead, projection: { intentId: 1, action: 1, login: 1, ...Object.fromEntries(keys.map(key => [`relays.${key}`, 1])) },
        });
        const { relays } = intent ?? {};
        if (!matches(receiptPattern, intent?.intentId) || !['create', 'disable', 'delete'].includes(intent.action)
            || !matches(loginPattern, intent.login) || intent.login === bootstrap
            || !Array.isArray(relays) || !relays.length || relays.some(row => !matches(idPattern, row?.nodeId))) return false;
        const ids = cohort && [...cohort.keys()].sort();
        if (!ids || !equal(relays.map(row => row.nodeId), ids)) throw grantError(identityChanged);
        for (const row of relays) {
            if (!sameRelayBinding(bindings.get(row.nodeId), row)
                || grants.get(row.nodeId)?.generation !== row.grantGeneration
                || cohort.get(row.nodeId).backupId !== row.backupId) throw grantError(identityChanged);
        }
        return true;
    }

    async function admissionOverview(nodes, states, authority) {
        const { env: config } = authority;
        const list = Object.hasOwn(config, relayList);
        const registered = list ? parseRelayBindingList(config[relayList]).map(row => normalizeRelayBinding(row)) : [];
        if (!list && config[legacyId]) {
            // The store's first mutation also requires a complete legacy
            // endpoint before it can add any DB grant to the union.
            const legacy = nodes.find(row => String(row._id) === config[legacyId])
                ?? await db.collection('hynodes').findOne({ _id: new ObjectId(config[legacyId]) }, {
                    ...nativeRead, projection: { ip: 1, 'ssh.port': 1, 'ssh.username': 1 },
                });
            if (legacy?.ssh?.username !== 'root') return null;
            try {
                registered.push(normalizeRelayBinding({ nodeId: config[legacyId], host: legacy.ip, port: legacy.ssh.port,
                    username: legacy.ssh.username, machineId: config[legacyMachine], sshHostKeySha256: config[legacyPin] }));
            } catch { return null; }
        }
        const claimed = new Map(registered.map(binding => [endpointKey(binding), binding.nodeId]));
        const endpoints = new Map();
        for (const row of nodes) {
            const id = String(row._id);
            if (!authority.isRetired?.(id) && authority.sourceFor(id) !== 'env' && eligible(row, true)) {
                const endpoint = admissionEndpoint(row);
                if (endpoint) endpoints.set(id, endpointKey(endpoint));
            }
        }
        const absentIds = states.filter(row => endpoints.has(String(row.node)) && isAbsent(row)
            && fences.every(key => row[key] == null || (Number.isSafeInteger(row[key]) && row[key] >= 0))).map(row => row._id);
        const [busy, pristine] = await Promise.all([
            readBusyAdmissions([...endpoints.keys()]),
            absentIds.length ? db.collection('relayl2tpstates').find({ ...admissionPristineFilter, _id: { $in: absentIds } },
                { ...nativeRead, projection: { _id: 1 } }).toArray() : [],
        ]);
        return { endpoints, claimed, busy, pristine: new Set(pristine.map(row => String(row._id))) };
    }

    async function overview() {
        let grantProblem = null;
        const cards = Promise.resolve(findNodes());
        const [nodes, states, rows, authority] = await Promise.all([
            cards, read(State.find({}), `${stateFields} installProgress`), read(L2tpUser.find({}), userFields),
            cards.then(nodes => readAuthority({ nodeIds: nodes.filter(row => eligible(row, true)).map(row => String(row._id)) }))
                .catch(error => { grantProblem = error.code; return null; }),
        ]);
        const byNode = new Map(), duplicates = new Set(), byMachine = new Map();
        for (const row of states) {
            const id = String(row.node);
            if (byNode.has(id)) duplicates.add(id);
            byNode.set(id, row);
            if (matches(hex32, row.rebuildMachineId)) {
                if (!byMachine.has(row.rebuildMachineId)) byMachine.set(row.rebuildMachineId, new Set());
                byMachine.get(row.rebuildMachineId).add(id);
            }
        }
        const accountsPending = await hasPendingAccounts().catch(error => {
            if (!grantProblem) throw error;
            return false; // No affirmative pending observation; union still blocks everything.
        });
        const clear = !!authority && !accountsPending;
        const config = authority?.env;
        const list = !!config && Object.hasOwn(config, relayList), enabled = !!config && relayInstallEnabled(config);
        const maybePristine = clear ? states.filter(isAbsent) : [];
        const pristineIds = new Set(maybePristine.length ? (await read(State.find({ ...pristineFilter,
            _id: { $in: maybePristine.map(row => row._id) } }), '_id')).map(row => String(row._id)) : []);
        // Failed footprint reads are not proof of absence and do not alter
        // the already verified grant registry or installed-state receipts.
        const admission = clear && enabled ? await admissionOverview(nodes, states, authority)
            .catch(() => null) : null;
        const owned = new Map(), bindings = new Map(), displayOwned = new Map();
        const grants = new Map(authority?.grants.map(grant => [grant.nodeId, grant]));
        const withUsers = new Set(rows.map(row => String(row.relayNode)));
        const relays = nodes.sort((a, b) => compare(String(a._id), String(b._id))).map(row => {
            const id = String(row._id), state = byNode.get(id), grantSource = authority?.sourceFor(id) ?? null;
            const binding = grantSource && bindingFor(row, config);
            const qualified = matches(idPattern, id) && eligible(row, list) && !duplicates.has(id);
            const grant = grants.get(id), endpoint = admission?.endpoints.get(id), claimant = admission?.claimed.get(endpoint);
            const endpointConflict = !!claimant && claimant !== id;
            const machineChanged = !!binding && !empty(state?.rebuildMachineId) && binding.machineId !== state.rebuildMachineId;
            const problem = !authority ? grantProblem : !enabled ? disabled
                : grantSource && (!binding || machineChanged) ? identityChanged : endpointConflict ? conflict : null;
            if (qualified && ownedState(state, binding)) {
                owned.set(id, state);
                bindings.set(id, binding);
                displayOwned.set(id, state);
            } else if (!authority && !duplicates.has(id) && ownedState(state, { nodeId: id, machineId: state?.rebuildMachineId })) {
                // Show persisted DIRECT inventory as read-only, never as proof
                // of a binding and never by falling back to raw ENV.
                displayOwned.set(id, state);
            }
            const isForeign = machineId => [...(byMachine.get(machineId) ?? [])].some(nodeId => nodeId !== id);
            const foreignMachine = !!grant && isForeign(grant.machineId);
            const admissionReady = !!endpoint && !admission.busy.has(id);
            const admit = admissionReady && !endpointConflict && !duplicates.has(id) && !foreignMachine;
            const admissionAbsent = admit && !withUsers.has(id) && (!state || admission.pristine.has(String(state._id)));
            const refreshOwned = admit && !!binding && state?.status === 'installed' && state.desiredState === 'installed'
                && state.rebuildMachineId === grant?.machineId;
            // Offer verification of a persisted rebuild Install reservation,
            // not authorization to clear it. Unlike Install this must remain
            // visible with the reservation/lock in place; POST rechecks both.
            const canRecoverInstall = clear && qualified && list && grantSource === 'db' && !!binding && !problem
                && hasKey() && !isForeign(binding.machineId)
                && state?.status === 'installing' && state.desiredState === 'installed'
                && state.routingMode === FOLLOW_RELAY_MODE && state.routingVersion === FOLLOW_RELAY_VERSION
                && state.rebuildMachineId === binding.machineId && matches(hex32, state.backupId)
                && matches(receiptPattern, state.rebuildInstallToken);
            const installProgress = qualified && !duplicates.has(id) && state?.status === 'installing'
                && state.desiredState === 'installed' && publicProgress(state);
            return { ...(installProgress && { installProgress }), id, name: typeof row.name === 'string' ? row.name : '', ip: typeof row.ip === 'string' ? row.ip : '',
                status: !state ? 'not_installed' : statuses.includes(state.status) ? state.status : 'error', bound: !!binding,
                grantSource, grantProblem: problem,
                canGrant: grantSource === null && admissionAbsent,
                canReconfirm: grantSource === 'db' && (admissionAbsent || refreshOwned),
                canRevoke: grantSource === 'db' && !problem && !!binding && admissionAbsent,
                canInstall: clear && qualified && !!binding && !problem && (grantSource === 'env' || admissionReady)
                    && !isForeign(binding.machineId) && hasKey()
                    && !withUsers.has(id) && (!state || pristineIds.has(String(state._id))),
                ...(canRecoverInstall && { canRecoverInstall: true }),
                canRemove: clear && owned.has(id), canRevealPsk: clear && owned.has(id) && hasKey() };
        });
        const scope = await accountScope(states, refs => refs.some(node => withUsers.has(String(node))));
        // Grant has its own per-node checks. Install also consumes the shared account inventory.
        if (!scope) for (const relay of relays) relay.canInstall = false;
        if (relays.some(relay => relay.canInstall)) {
            // A shared lock says nothing about the outcome of Install on this relay.
            let lock;
            try {
                lock = await db.collection('c3_rebuild_locks').findOne({ _id: 'apply' },
                    { ...nativeRead, projection: { _id: 1, allowStaleUnlock: 1 } });
            } catch { /* Only a confirmed absence permits the button. */ }
            if (lock !== null) {
                const reason = lock === undefined ? 'unreadable' : lock.allowStaleUnlock === true ? 'pending'
                    : lock.allowStaleUnlock === false ? 'protected' : 'unspecified';
                for (const relay of relays) if (relay.canInstall) {
                    relay.canInstall = false;
                    relay.installBlockedReason = reason;
                }
            }
        }
        const cohort = list ? scope && ownedCohort(scope.states, owned, list)
            : owned.size === 1 ? owned : null;
        const accountRows = list ? rows : rows.filter(row => displayOwned.has(String(row.relayNode)));
        // An unfinished operation can leave this inventory unsettled. Do not
        // require a consistent directory to report the persisted fence.
        const directory = !accountsPending ? await readDirectory(L2tpUser.db, undefined, true).catch(error => {
            if (!grantProblem) throw error;
            return null;
        }) : null;
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
                const state = displayOwned.get(String(row.relayNode));
                return state && (list || !authority || legacyAccount(row, state));
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
        if (directory && !rows.length && scope?.states.length === 0
            && (list || !authority || (directory.accounts.length === 1 && matches(idPattern, config[legacyId])))) {
            for (const { login, enabled } of directory.accounts) {
                accounts.push({ login, enabled, consistent: clear, canRevealPassword: clear && hasKey(), addresses: [] });
            }
        }
        accounts.sort((a, b) => compare(a.login, b.login));
        const canReconcileAccounts = accountsPending && list && enabled && hasKey()
            && await recoveryAttestation(cohort, bindings, grants).catch(error => {
                grantProblem = error.code === identityChanged ? identityChanged : grantUnavailable;
                return false;
            });
        return { relays, accounts, accountsPending, grantProblem, canReconcileAccounts,
            canManageAccounts: list && hasKey() && inventoryOk && accounts.every(row => row.consistent) };
    }

    function passwordCohort(states, nodes, authority, list) {
        const byNode = new Map(nodes.map(node => [String(node._id), node]));
        const owned = new Map();
        for (const state of states) {
            const id = String(state.node), node = byNode.get(id);
            if (authority.sourceFor(id) && eligible(node, list) && ownedState(state, bindingFor(node, authority.env))) owned.set(id, state);
        }
        return ownedCohort(states, owned, list);
    }

    async function revealPassword(login) {
        if (!matches(loginPattern, login)) return null;
        return stableReveal(async authority => {
            const config = authority.env;
            const list = Object.hasOwn(config, relayList);
            const singleton = config[legacyId];
            if (!list && (!matches(idPattern, singleton) || login !== bootstrap)) return null;
            const candidates = await read(State.find(list ? {} : { node: singleton }).sort('_id'), stateFields);
            const legacyDormant = !list && (candidates.length === 0 || (candidates.length === 1
                && (isAbsent(candidates[0]) || isDormantClassicState(candidates[0]))));
            const scope = list || legacyDormant ? await accountScope(list ? candidates : await read(State.find({}).sort('_id'), stateFields),
                refs => read(L2tpUser.findOne({ relayNode: { $in: refs } }), '_id')) : { states: candidates };
            if (!scope) return null;
            const { states } = scope;
            if (states.some(row => !matches(idPattern, String(row.node)))) return null;
            const directory = await readDirectory(L2tpUser.db);
            if (states.length === 0) {
                if (!directory || (!list && directory.accounts.length !== 1)) return null;
                if (await read(L2tpUser.findOne({}), '_id')) return null;
                return { list, dormant: true, directory, scope };
            }
            if (legacyDormant) return null;
            const nodes = await findNodes({ _id: { $in: states.map(row => row.node) } });
            const cohort = passwordCohort(states, nodes, authority, list);
            if (!cohort) return null;
            const userScope = list ? {} : { relayNode: singleton };
            const inventoryScope = list ? { $or: [{ relayNode: { $in: states.map(row => row.node) } }, { login }] } : userScope;
            const inventory = await read(L2tpUser.find(inventoryScope).sort('_id'), userFields);
            if (!inventoryMatches(inventory, cohort, list)) return null;
            if (directory && ![...cohort.keys()].every(id => sameAccounts(directory.accounts,
                inventory.filter(row => String(row.relayNode) === id), false))) return null;
            // An unexpected same-login replica invalidates the account; don't
            // filter down to a good-looking subset of the installed cohort.
            const copies = await read(L2tpUser.find({ ...userScope, login }).sort('_id'), `${userFields} passwordEncrypted`);
            if (!equal(inventory.filter(row => row.login === login), copies.map(({ passwordEncrypted: _, ...row }) => row))) return null;
            return { list, nodes, scope, inventory, copies, directory };
        }, ({ list, dormant, scope: { states }, nodes, copies, directory }, authority) => {
            const account = directory?.accounts.find(row => row.login === login);
            if (dormant) return account?.passwordEncrypted;
            if (!replicasAgree(copies, passwordCohort(states, nodes, authority, list), list, true)) return null;
            if (directory && (!account || account.enabled !== copies[0].enabled || account.passwordEncrypted !== copies[0].passwordEncrypted)) return null;
            return copies[0].passwordEncrypted;
        }, async ({ scope: { classicStates, classicOperations } }) => {
            if (!classicStates?.length) return true;
            // A new classic job can start without changing the retained state
            // or the requested envelope. Check again after the last envelope.
            try { return equal(classicOperations, await readClassicOperations(db, classicStates)); }
            catch { return false; }
        });
    }

    async function revealPsk(id) {
        if (!matches(idPattern, id)) return null;
        return stableReveal(async authority => {
            const config = authority.env;
            const list = Object.hasOwn(config, relayList);
            const [node] = await findNodes({ _id: id });
            if (!authority.sourceFor(id) || !eligible(node, list) || !bindingFor(node, config)) return null;
            const state = await read(State.findOne({ node: id }), `${stateFields} pskEncrypted`);
            return { node, state };
        }, ({ node, state }, authority) => authority.sourceFor(id) && ownedState(state, bindingFor(node, authority.env))
            ? state.pskEncrypted : null);
    }
    return Object.freeze({ overview, revealPassword, revealPsk, hasPendingAccounts });
}

module.exports = { createRebuildL2tpOverview };
