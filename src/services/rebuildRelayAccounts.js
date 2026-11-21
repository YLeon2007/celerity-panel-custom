'use strict';

const { randomUUID } = require('node:crypto');
const { isIPv4 } = require('node:net');
const { isDeepStrictEqual: equal } = require('node:util');
const { withNodes } = require('./rebuildLocks');
const { validateRebuildMode } = require('./rebuildMode');
const { encrypt, decrypt } = require('../modules/relay-l2tp/services/secretBoxService');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');
const { accountError: fail, RelayAccountsError, createRebuildRelayAccountsStore } = require('./rebuildRelayAccountsStore');
const { logicalAccount, sameAccounts } = require('./rebuildRelayDirectory');

const idPattern = /^[a-f0-9]{24}(?![\s\S])/;
const machinePattern = /^[a-f0-9]{32}(?![\s\S])/;
const pinPattern = /^[a-f0-9]{64}(?![\s\S])/;
const installToken = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}(?![\s\S])/;
const loginPattern = /^[A-Za-z0-9._@-]{1,64}(?![\s\S])/;
const passwordPattern = /^[A-Za-z0-9_-]{1,256}(?![\s\S])/;
const escrowPattern = /^v1:[0-9a-f]{24}:[0-9a-f]{32}:(?:[0-9a-f]{2}){1,256}(?![\s\S])/;
const bootstrap = 'relay-bootstrap';
const operatorList = 'C3_REBUILD_L2TP_RELAYS_JSON';
const statuses = Object.freeze({ create: 'created', disable: 'disabled', delete: 'deleted' });
const matches = (re, value) => typeof value === 'string' && re.test(value);
const int = (v, lo, hi) => Number.isSafeInteger(v) && v >= lo && v <= hi;
const ipv4 = ip => isIPv4(ip) ? ip.split('.').reduce((n, s) => n * 256 + Number(s), 0) : NaN;
const address = n => [24, 16, 8, 0].map(shift => (n >>> shift) & 255).join('.');
const by = key => (a, b) => String(a[key]).localeCompare(String(b[key]));
const safe = e => e instanceof RelayAccountsError ? e
    : ['REBUILD_BUSY', 'REBUILD_LOCK_LOST'].includes(e?.code) ? Object.assign(new Error(e.code), { code: e.code })
        : fail('FAILED');

function installedIds(states) {
    if (states.length === 0) throw fail('NO_INSTALLED');
    const ids = states.map(row => {
        const id = String(row.node);
        if (!matches(idPattern, id) || !row._id || row.status !== 'installed' || row.desiredState !== 'installed'
            || row.routingMode !== FOLLOW_RELAY_MODE || row.routingVersion !== FOLLOW_RELAY_VERSION
            || row.routeGroup != null || row.operationId != null || (row.activePathKey ?? '') !== ''
            || row.appliedTopologyRevision != null || (row.pppDriftQueueFence ?? 0) !== 0 || (row.replacementFence ?? 0) !== 0
            || row.secretRevision !== 1 || !matches(machinePattern, row.rebuildMachineId)
            || !matches(machinePattern, row.backupId) || !matches(installToken, row.rebuildInstallToken)) throw fail('NOT_OWNED');
        return id;
    });
    if (new Set(ids).size !== ids.length) throw fail('NOT_OWNED');
    return ids.sort();
}

function networkFor({ clientCidr, tproxyPort, fwmark, routeTable, poolStart, poolEnd, localAddress }) {
    const cidr = typeof clientCidr === 'string' && /^([^/]+)\/(1[6-9]|2\d|30)(?![\s\S])/.exec(clientCidr);
    const first = cidr ? ipv4(cidr[1]) : NaN, size = cidr ? 2 ** (32 - Number(cidr[2])) : 0;
    const last = first + size - 1;
    const start = ipv4(poolStart), end = ipv4(poolEnd), local = ipv4(localAddress);
    if (first % size !== 0 || ![[0x0a000000, 0x0affffff], [0xac100000, 0xac1fffff], [0xc0a80000, 0xc0a8ffff]]
        .some(([lo, hi]) => first >= lo && last <= hi) || !(start > first && end < last && start <= end)
        || !(local > first && local < last && (local < start || local > end))
        || !int(tproxyPort, 1024, 65535) || [1701, 4500].includes(tproxyPort) || !int(fwmark, 1, 0x7fffffff)
        || !int(routeTable, 1, 0x7fffffff) || [253, 254, 255].includes(routeTable)) throw fail('NOT_OWNED');
    return { network: Object.freeze({ clientCidr, tproxyPort, fwmark, routeTable }), start, end, first, last };
}

async function bindingFor(resolve, env, state, node) {
    const nodeId = String(state.node);
    if (!node || node.type !== 'xray' || node.active !== true || node.cascadeRole !== 'relay' || node.useCustomConfig
        || String(node._id) !== nodeId) {
        throw fail('BINDING_MISMATCH', { nodeId });
    }
    let binding;
    try { binding = await resolve(env, nodeId, node); } catch { throw fail('BINDING_MISMATCH', { nodeId }); }
    const { nodeId: resolvedId, host, port, username, machineId, sshHostKeySha256 } = binding ?? {};
    if (resolvedId !== nodeId || typeof host !== 'string' || !host || !int(port, 1, 65535) || typeof username !== 'string' || !username
        || machineId !== state.rebuildMachineId || !matches(pinPattern, sshHostKeySha256)) throw fail('BINDING_MISMATCH', { nodeId });
    return Object.freeze({ nodeId, host, port, username, machineId, sshHostKeySha256 });
}

function makePlans({ states, users, nodes, bindings }, action, login, password, key, escrow) {
    const cohort = new Map(states.map(s => [String(s.node), []]));
    for (const user of users) {
        const group = cohort.get(String(user.relayNode));
        if (!group) throw fail('ACCOUNT_CONFLICT');
        group.push(user);
    }
    const plans = [];
    const passwordEncrypted = action === 'create' ? (escrow ?? encrypt(password, key)) : undefined;
    let shared, logical;
    for (const [i, state] of states.entries()) {
        const binding = bindings[i];
        const { nodeId } = binding;
        const { network, start, end, first, last } = networkFor(state);
        if (plans.some(p => first <= p.last && last >= p.first)) throw fail('NOT_OWNED');
        const accounts = cohort.get(nodeId), byLogin = new Map(), ips = new Set();
        if (accounts.length > 2048) throw fail('ACCOUNT_CONFLICT');
        const currentUsers = Object.freeze(accounts.map(row => {
            const ip = ipv4(row.ip);
            if (!row._id || !matches(loginPattern, row.login) || byLogin.has(row.login) || ips.has(ip)
                || !(ip >= start && ip <= end) || typeof row.enabled !== 'boolean' || row.syncStatus !== 'synced'
                || !int(row.desiredRevision, 1, Number.MAX_SAFE_INTEGER) || row.desiredRevision !== row.appliedRevision
                || row.syncOperationId != null) throw fail('ACCOUNT_CONFLICT');
            byLogin.set(row.login, row); ips.add(ip);
            let plain;
            try { plain = decrypt(row.passwordEncrypted, key); } catch { throw fail('ACCOUNT_CONFLICT'); }
            if (!matches(passwordPattern, plain)) throw fail('ACCOUNT_CONFLICT');
            return Object.freeze({ login: row.login, password: plain, ipAddress: row.ip, enabled: row.enabled });
        }));
        const initial = byLogin.get(bootstrap);
        if (!initial?.enabled || initial.ip !== state.poolStart) throw fail('ACCOUNT_CONFLICT');
        if (logical && (logical.size !== byLogin.size || [...logical].some(([name, row]) => {
            const other = byLogin.get(name);
            return !other || other.passwordEncrypted !== row.passwordEncrypted || other.enabled !== row.enabled;
        }))) throw fail('ACCOUNT_CONFLICT');
        logical ??= byLogin;
        const before = byLogin.get(login);
        let candidate, after;
        if (action === 'create') {
            if (before) throw fail('ACCOUNT_CONFLICT');
            let next = start;
            while (ips.has(next)) next += 1;
            if (next > end || accounts.length >= 2048) throw fail('POOL_EXHAUSTED', { nodeId });
            const ip = address(next);
            candidate = Object.freeze({ login, password, ipAddress: ip, enabled: true });
            after = { relayNode: nodeId, login, ip, enabled: true, passwordEncrypted, desiredRevision: 1,
                appliedRevision: 1, syncStatus: 'synced' };
        } else {
            if (!before || (shared && (before.passwordEncrypted !== shared.passwordEncrypted || before.enabled !== shared.enabled))) {
                throw fail('ACCOUNT_CONFLICT');
            }
            shared ??= before;
            if (action === 'disable' && before.enabled) {
                const revision = before.desiredRevision + 1;
                if (!Number.isSafeInteger(revision)) throw fail('ACCOUNT_CONFLICT');
                candidate = Object.freeze({ ...currentUsers.find(u => u.login === login), enabled: false });
                after = { enabled: false, desiredRevision: revision, appliedRevision: revision };
            }
        }
        const desiredUsers = action === 'disable' && !after ? currentUsers : Object.freeze([
            ...currentUsers.filter(u => u.login !== login), ...(candidate ? [candidate] : []),
        ].sort(by('login')));
        plans.push({ node: nodes[i], binding, first, last, currentUsers, desiredUsers, before, after,
            installation: Object.freeze({ nodeId, backupId: state.backupId, network }) });
    }
    return plans;
}

const recordRelays = plans => plans.map(({ installation, binding, before, after }) => ({ ...installation, ...binding,
    ip: before?.ip ?? after?.ip, revision: before?.desiredRevision ?? 0 }));
const fields = (row, names) => row !== null && typeof row === 'object' && Object.getPrototypeOf(row) === Object.prototype
    && Reflect.ownKeys(row).length === names.length && names.every(name => Object.hasOwn(row, name));

function openIntent(intent, key) {
    const create = intent?.action === 'create';
    if (!fields(intent, ['_id', 'intentId', 'action', 'login', 'createdAt', 'relays', ...(create ? ['passwordEncrypted'] : [])])
        || intent._id !== 'pending' || !matches(installToken, intent.intentId)
        || typeof intent.action !== 'string' || !Object.hasOwn(statuses, intent.action)
        || !matches(loginPattern, intent.login) || intent.login === bootstrap
        || !(intent.createdAt instanceof Date) || !Number.isFinite(intent.createdAt.getTime())
        || !Array.isArray(intent.relays) || intent.relays.length === 0
        || (create && !matches(escrowPattern, intent.passwordEncrypted))) throw fail('BLOCKED', { retryAllowed: false });
    if (create) {
        let password;
        try { password = decrypt(intent.passwordEncrypted, key); } catch { /* Not usable escrow. */ }
        if (!matches(passwordPattern, password)) throw fail('BLOCKED', { retryAllowed: false });
        return password;
    }
}

function publication(store, plans, baseline, { intentId, intent, action, login, recheck, verifyAuthority }) {
    const { directory } = baseline;
    const firstRelay = baseline.users.filter(row => String(row.relayNode) === plans[0].binding.nodeId);
    const directoryBase = directory?.accounts ?? firstRelay.map(logicalAccount);
    const now = new Date();
    const changes = plans.map(({ before, after }) => ({ before, after: after && {
        ...after, lastSyncedAt: now, updatedAt: now, ...(action === 'create' && { createdAt: now }),
    } }));
    return store.publish({ intentId, intent, action, changes, recheck, verifyAuthority, directory, directoryBase, login });
}

function validateDirectory({ directory, users }, firstId) {
    if (directory && !sameAccounts(directory.accounts, users.filter(row => String(row.relayNode) === firstId))) {
        throw fail('ACCOUNT_CONFLICT');
    }
}

async function withRemotes(work) {
    const opened = new Set();
    const track = (remote, ...methods) => {
        if (opened.has(remote) || typeof remote?.close !== 'function') throw fail('UNAVAILABLE');
        opened.add(remote);
        if (methods.some(method => typeof remote[method] !== 'function') || typeof remote.syncChap !== 'function') throw fail('UNAVAILABLE');
        return remote;
    };
    const closeAll = async () => {
        const remotes = Array.from(opened);
        opened.clear();
        const results = await Promise.allSettled(remotes.map(async remote => remote.close()));
        if (results.some(r => r.status === 'rejected')) throw fail('CLEANUP_FAILED');
    };
    try { return await work(track, closeAll); }
    finally {
        // Required close is done before settlement and while all locks are
        // held. A secondary close failure cannot change the primary outcome.
        try { await closeAll(); } catch { /* Preserve the primary outcome. */ }
    }
}

// Parent supplies the one ordinary resolver and DIRECT factory. The factory
// must bind the supplied endpoint, pin and machine identity. checkChap and
// inspectChap are read-only. fenceChap retires older commands without changing
// CHAP or PPP. Each write must verify authority at dispatch and attest the
// installation and preimage under the host lock before returning its receipt.
const chapReceipt = result => fields(result, ['changed']) && typeof result.changed === 'boolean';
const revokeReceipt = result => fields(result, ['changed', 'complete', 'sessionsTerminated']) && typeof result.changed === 'boolean'
    && typeof result.complete === 'boolean' && int(result.sessionsTerminated, 0, Number.MAX_SAFE_INTEGER);
const inspectionReceipt = (result, revokedLogin, sameProjection) => fields(result, ['projection', 'activeTargetSessions'])
    && (sameProjection ? result.projection === 'both' : ['original', 'desired'].includes(result.projection))
    && int(result.activeTargetSessions, 0, revokedLogin ? Number.MAX_SAFE_INTEGER : 0);
function createRebuildRelayAccounts({ Node, State, L2tpUser, locks, env = process.env, resolveRelayBinding,
    createRelayDirect, store = createRebuildRelayAccountsStore({ Node, State, L2tpUser }) }) {
    const allow = () => {
        let enabled;
        try { enabled = validateRebuildMode(env); } catch { /* Strict/classic conflict. */ }
        if (enabled !== true) throw fail('DISABLED');
    };

    function inventoryFor(ids, login, authority) {
        const readDatabase = async session => {
            const states = (await store.states(session)).sort(by('node'));
            if (!equal(installedIds(states), ids)) throw fail('CHANGED');
            const { nodes, users, directory } = await store.inventory(ids, login, session);
            nodes.sort(by('_id')); users.sort(by('_id'));
            if (!equal(nodes.map(n => String(n._id)), ids)) throw fail('BINDING_MISMATCH');
            return { states, nodes, users, directory };
        };
        const load = async () => {
            await authority();
            const db = await readDatabase();
            const bindings = [];
            for (const [i, state] of db.states.entries()) {
                const binding = await bindingFor(resolveRelayBinding, env, state, db.nodes[i]);
                if (bindings.some(b => b.machineId === binding.machineId || b.sshHostKeySha256 === binding.sshHostKeySha256
                    || (b.host === binding.host && b.port === binding.port))) throw fail('BINDING_MISMATCH', { nodeId: binding.nodeId });
                bindings.push(binding);
            }
            await authority();
            return { ...db, bindings };
        };
        return { load, async check(baseline, session) {
            // All remote calls and binding resolver work are outside the
            // transaction. Its snapshot must still match the frozen DB scope.
            await authority();
            const { bindings, ...db } = baseline;
            if (!(session ? equal(await readDatabase(session), db) : equal(await load(), baseline))) throw fail('CHANGED');
        } };
    }

    async function recover(intent, key, listMode, authority, requested) {
        const password = openIntent(intent, key);
        const { intentId, action, login } = intent;
        const revokedLogin = action === 'create' ? undefined : login;
        const matching = requested.action === action && requested.login === login
            && (action !== 'create' || requested.password === password);
        let phase = 'BLOCKED', uncertainNodeId;
        let sessionsTerminated = 0;
        const confirmedNodeIds = new Set();
        const verifyAuthority = async () => {
            await authority();
            await store.verifyIntent(intentId, intent);
            await authority();
        };
        try {
            // The released format was only produced by the list-mode writer.
            if (!listMode) throw fail('OPERATOR_LIST_REQUIRED');
            await verifyAuthority();
            const ids = installedIds(await store.states());
            if (!equal(intent.relays.map(row => row?.nodeId), ids)) throw fail('CHANGED');
            return await withNodes(ids, () => withRemotes(async (track, closeAll) => {
                const inventory = inventoryFor(ids, login, authority);
                const baseline = await inventory.load();
                const plans = makePlans(baseline, action, login, password, key, intent.passwordEncrypted);
                if (!equal(recordRelays(plans), intent.relays)) throw fail('CHANGED');
                validateDirectory(baseline, ids[0]);
                const recheck = async session => {
                    await inventory.check(baseline, session);
                    await verifyAuthority();
                };
                // For a disabled target, the two CHAP projections are identical
                // even when the requested DB delta is a deletion.
                const sameProjection = revokedLogin !== undefined && plans[0].before.enabled === false;
                const inspect = async ({ installation, currentUsers, desiredUsers }, remote) => {
                    await recheck();
                    const receipt = await remote.inspectChap(installation, currentUsers, desiredUsers, recheck, revokedLogin);
                    await recheck();
                    if (!inspectionReceipt(receipt, revokedLogin, sameProjection)) throw fail('CHANGED');
                    return receipt;
                };
                const calls = [];
                for (const plan of plans) {
                    await recheck();
                    const { node, binding } = plan;
                    const remote = track(await createRelayDirect({ node, env, binding }), 'inspectChap', 'fenceChap');
                    await inspect(plan, remote);
                    calls.push({ plan, remote });
                }

                // The first pass admits the whole cohort but is not settlement
                // evidence: a previously dispatched command could still land.
                // Retire those commands on every host before observing again.
                for (const { plan, remote } of calls) {
                    const { installation, currentUsers, desiredUsers } = plan;
                    await recheck();
                    const receipt = await remote.fenceChap(installation, currentUsers, desiredUsers, recheck, revokedLogin);
                    await recheck();
                    if (!fields(receipt, ['fenced']) || receipt.fenced !== true) throw fail('CHANGED');
                }
                const classified = [];
                for (const call of calls) classified.push({ ...call, ...await inspect(call.plan, call.remote) });

                const cancel = classified.every(call => call.projection === 'original');
                if (!cancel) {
                    let incompleteNodeId;
                    for (const { plan, remote, projection, activeTargetSessions } of classified) {
                        const changed = projection === 'original';
                        if (!changed && activeTargetSessions === 0) continue;
                        await recheck();
                        const { installation, currentUsers, desiredUsers } = plan;
                        // In the desired projection the target's row is already
                        // blocked. Carry its original IP even on a delete, so
                        // surviving sessions can still be attributed exactly.
                        const observed = changed ? currentUsers : Object.freeze(currentUsers.map(user => user.login === revokedLogin
                            ? Object.freeze({ ...user, enabled: false }) : user));
                        phase = 'OUTCOME_UNKNOWN';
                        uncertainNodeId = installation.nodeId;
                        const synced = await remote.syncChap(installation, observed, desiredUsers, recheck, revokedLogin);
                        if (!(revokedLogin ? revokeReceipt(synced) : chapReceipt(synced)) || synced.changed !== changed) throw fail(phase);
                        if (revokedLogin) {
                            const total = sessionsTerminated + synced.sessionsTerminated;
                            if (!Number.isSafeInteger(total)) throw fail(phase);
                            sessionsTerminated = total;
                            if (!synced.complete) incompleteNodeId ??= uncertainNodeId;
                        }
                        if (!revokedLogin || synced.complete) confirmedNodeIds.add(uncertainNodeId);
                        uncertainNodeId = undefined;
                    }
                    if (incompleteNodeId) {
                        uncertainNodeId = incompleteNodeId;
                        throw fail(phase);
                    }
                    for (const { plan, remote } of calls) {
                        uncertainNodeId = plan.installation.nodeId;
                        confirmedNodeIds.delete(uncertainNodeId);
                        const proof = await inspect(plan, remote);
                        if (proof.projection === 'original' || proof.activeTargetSessions !== 0) throw fail('CHANGED');
                        confirmedNodeIds.add(uncertainNodeId);
                        uncertainNodeId = undefined;
                    }
                }

                phase = 'FINISH_UNKNOWN';
                await closeAll();
                await recheck();
                if (cancel) await store.cancel({ intent, recheck, verifyAuthority });
                else await publication(store, plans, baseline, { intentId, intent, action, login, recheck, verifyAuthority });
                return { matching, result: { executionMode: 'rebuild', status: cancel ? 'canceled' : statuses[action], login,
                    relayCount: ids.length, recovered: true, ...(revokedLogin && { sessionsTerminated }) } };
            }));
        } catch {
            throw fail(phase, { intentId, retryAllowed: false, confirmedNodeIds: [...confirmedNodeIds].sort(),
                // Do not attribute closures from a different pending action to the requested mutation.
                ...(revokedLogin && (!requested.action || matching) && { confirmedSessionsTerminated: sessionsTerminated,
                    ...(matching && { sessionsTerminatedScope: 'request' }) }),
                ...(uncertainNodeId && { uncertainNodeId }) });
        }
    }

    async function run(action, input) {
        allow();
        const listMode = Object.hasOwn(env, operatorList);
        const list = env[operatorList], installEnabled = env.C3_REBUILD_L2TP_INSTALL_ENABLED;
        const { login, password } = input ?? {};
        if (action && (!matches(loginPattern, login) || login === bootstrap || (action === 'create' && !matches(passwordPattern, password)))) {
            throw fail('INVALID_REQUEST');
        }
        if (typeof resolveRelayBinding !== 'function' || typeof createRelayDirect !== 'function') throw fail('UNAVAILABLE');
        const key = env.ENCRYPTION_KEY;
        if (typeof key !== 'string' || key.length < 32) throw fail('CREDENTIAL_KEY_INVALID');
        const result = { executionMode: 'rebuild', status: statuses[action], login };
        let primary, completed = false;
        try {
            return await locks.run(async verifyLock => {
                try {
                    const authority = async () => {
                        allow();
                        if (await verifyLock() === false) throw Object.assign(new Error('REBUILD_LOCK_LOST'), { code: 'REBUILD_LOCK_LOST' });
                        allow();
                        if (env.ENCRYPTION_KEY !== key || Object.hasOwn(env, operatorList) !== listMode
                            || env[operatorList] !== list || env.C3_REBUILD_L2TP_INSTALL_ENABLED !== installEnabled) throw fail('CHANGED');
                    };
                    await authority();
                    const pending = await store.pending();
                    await authority();
                    if (pending !== null) {
                        const recovered = await recover(pending, key, listMode, authority, { action, login, password });
                        completed = true;
                        if (!action || recovered.matching) return recovered.result;
                    }
                    if (!action) return { executionMode: 'rebuild', status: 'idle' };
                    // An unrelated request takes a fresh baseline after settlement;
                    // it never inherits the recovered operation's host/DB proof.
                    await store.assertNoPending();
                    const ids = installedIds(await store.states());
                    return await withNodes(ids, () => withRemotes(async (track, closeAll) => {
                        const inventory = inventoryFor(ids, login, authority);
                        const baseline = await inventory.load();
                        const plans = makePlans(baseline, action, login, password, key);
                        const revokedLogin = action === 'create' ? undefined : login;
                        validateDirectory(baseline, ids[0]);

                        // Legacy Remove only owns the exact bootstrap row. Do
                        // not introduce account changes under that contract.
                        if (!listMode) throw fail('OPERATOR_LIST_REQUIRED');
                        let intentId, intent, phase, uncertainNodeId;
                        let sessionsTerminated = 0;
                        const confirmedNodeIds = [];
                        const verifyAuthority = async () => {
                            await authority();
                            if (intentId) await store.verifyIntent(intentId, intent);
                            await authority();
                        };
                        const recheck = async session => {
                            await inventory.check(baseline, session);
                            await verifyAuthority();
                        };
                        const outcome = suffix => fail(suffix, { intentId, retryAllowed: false, confirmedNodeIds: [...confirmedNodeIds],
                            ...(revokedLogin && { confirmedSessionsTerminated: sessionsTerminated }),
                            ...(uncertainNodeId && { uncertainNodeId }) });
                        try {
                            const calls = [];
                            for (const { node, binding, installation, currentUsers, desiredUsers } of plans) {
                                await recheck();
                                const remote = track(await createRelayDirect({ node, env, binding }), 'checkChap');
                                calls.push([remote, installation, currentUsers, desiredUsers]);
                            }
                            for (const call of calls) {
                                const [remote, installation, currentUsers, desiredUsers] = call;
                                await recheck();
                                let checked;
                                try { checked = await remote.checkChap(installation, currentUsers, desiredUsers, () => recheck(), revokedLogin); }
                                catch { throw fail('PREFLIGHT_REFUSED', { nodeId: installation.nodeId }); }
                                if (!chapReceipt(checked)) throw fail('PREFLIGHT_REFUSED', { nodeId: installation.nodeId });
                                call.push(checked.changed);
                            }
                            await store.assertNoPending();
                            await recheck();

                            const id = randomUUID();
                            phase = 'INTENT_UNKNOWN';
                            intentId = id;
                            // Only the create delta needs escrow. The password is
                            // never stored in plaintext, logged, or echoed in errors.
                            const submitted = { intentId: id, action, login, createdAt: new Date(),
                                ...(action === 'create' && { passwordEncrypted: plans[0].after.passwordEncrypted }),
                                relays: recordRelays(plans) };
                            await store.begin(submitted);
                            phase = 'OUTCOME_UNKNOWN';
                            await authority();
                            // Validate contents regardless of field order, then
                            // retain the unmodified BSON read image for CAS.
                            intent = await store.pending();
                            if (!equal(intent, { _id: 'pending', ...submitted })) throw fail('CHANGED');
                            let incompleteNodeId;
                            for (const [remote, installation, currentUsers, desiredUsers, changed] of calls) {
                                await recheck();
                                uncertainNodeId = installation.nodeId;
                                const synced = await remote.syncChap(installation, currentUsers, desiredUsers, () => recheck(), revokedLogin);
                                if (!(revokedLogin ? revokeReceipt(synced) : chapReceipt(synced)) || synced.changed !== changed) throw fail(phase);
                                if (revokedLogin) {
                                    const total = sessionsTerminated + synced.sessionsTerminated;
                                    if (!Number.isSafeInteger(total)) throw fail(phase);
                                    sessionsTerminated = total;
                                    if (!synced.complete) {
                                        // The command reached a checked terminal frame, but this relay is not settled.
                                        // Keep its intent and still revoke on the other independently pinned relays.
                                        incompleteNodeId ??= uncertainNodeId;
                                        uncertainNodeId = undefined;
                                        continue;
                                    }
                                }
                                confirmedNodeIds.push(uncertainNodeId);
                                uncertainNodeId = undefined;
                            }
                            if (incompleteNodeId) {
                                uncertainNodeId = incompleteNodeId;
                                throw fail(phase);
                            }
                            phase = 'FINISH_UNKNOWN';
                            await closeAll();
                            await recheck();
                            await publication(store, plans, baseline, { intentId, intent, action, login, recheck, verifyAuthority });
                            completed = true;
                            return { ...result, relayCount: ids.length, ...(revokedLogin && { sessionsTerminated }) };
                        } catch (error) {
                            if (phase) throw outcome(phase);
                            throw error;
                        }
                    }));
                } catch (error) {
                    primary = safe(error);
                    throw primary;
                }
            });
        } catch (error) {
            throw primary ?? (completed ? fail('CLEANUP_FAILED', { retryAllowed: false }) : safe(error));
        }
    }
    return Object.freeze({ create: input => run('create', input), disable: input => run('disable', input),
        delete: input => run('delete', input), reconcile: () => run() });
}

module.exports = { createRebuildRelayAccounts };
