'use strict';

const { randomUUID } = require('node:crypto');
const { isIPv4 } = require('node:net');
const { isDeepStrictEqual: equal } = require('node:util');
const { withNodes } = require('./rebuildLocks');
const { validateRebuildMode } = require('./rebuildMode');
const { encrypt, decrypt } = require('../modules/relay-l2tp/services/secretBoxService');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');
const { accountError: fail, RelayAccountsError, createRebuildRelayAccountsStore } = require('./rebuildRelayAccountsStore');

const idPattern = /^[a-f0-9]{24}(?![\s\S])/;
const machinePattern = /^[a-f0-9]{32}(?![\s\S])/;
const pinPattern = /^[a-f0-9]{64}(?![\s\S])/;
const installToken = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}(?![\s\S])/;
const loginPattern = /^[A-Za-z0-9._@-]{1,64}(?![\s\S])/;
const passwordPattern = /^[A-Za-z0-9_-]{1,256}(?![\s\S])/;
const bootstrap = 'relay-bootstrap';
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

function makePlans({ states, users, nodes, bindings }, action, login, password, key) {
    const cohort = new Map(states.map(s => [String(s.node), []]));
    for (const user of users) {
        const group = cohort.get(String(user.relayNode));
        if (!group) throw fail('ACCOUNT_CONFLICT');
        group.push(user);
    }
    const plans = [];
    const passwordEncrypted = action === 'create' ? encrypt(password, key) : undefined;
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

// Parent supplies the one ordinary resolver and DIRECT factory. The factory
// must bind the supplied endpoint, pin and machine identity. checkChap is
// read-only. syncChap must call verifyLock at dispatch, attest the installation
// and preimage under its host lock, and return a checked change receipt.
const chapReceipt = result => result !== null && typeof result === 'object'
    && Object.keys(result).length === 1 && typeof result.changed === 'boolean';
function createRebuildRelayAccounts({ Node, State, L2tpUser, locks, env = process.env, resolveRelayBinding,
    createRelayDirect, store = createRebuildRelayAccountsStore({ Node, State, L2tpUser }) }) {
    const allow = () => {
        let enabled;
        try { enabled = validateRebuildMode(env); } catch { /* Strict/classic conflict. */ }
        if (enabled !== true) throw fail('DISABLED');
    };
    async function run(action, input) {
        allow();
        const { login, password } = input ?? {};
        if (!matches(loginPattern, login) || login === bootstrap || (action === 'create' && !matches(passwordPattern, password))) {
            throw fail('INVALID_REQUEST');
        }
        if (typeof resolveRelayBinding !== 'function' || typeof createRelayDirect !== 'function') throw fail('UNAVAILABLE');
        const key = env.ENCRYPTION_KEY;
        if (typeof key !== 'string' || key.length < 32) throw fail('CREDENTIAL_KEY_INVALID');
        const result = { executionMode: 'rebuild', status: { create: 'created', disable: 'disabled', delete: 'deleted' }[action], login };
        let primary, completed = false;
        try {
            return await locks.run(async verifyLock => {
                try {
                    const authority = async () => {
                        allow();
                        if (await verifyLock() === false) throw Object.assign(new Error('REBUILD_LOCK_LOST'), { code: 'REBUILD_LOCK_LOST' });
                        allow();
                        if (env.ENCRYPTION_KEY !== key) throw fail('CHANGED');
                    };
                    await authority();
                    await store.assertNoPending();
                    const ids = installedIds(await store.states());
                    return await withNodes(ids, async () => {
                        const load = async session => {
                            await authority();
                            const states = (await store.states(session)).sort(by('node'));
                            if (!equal(states.map(s => String(s.node)), ids)) throw fail('CHANGED');
                            const { nodes, users } = await store.inventory(ids, login, session);
                            nodes.sort(by('_id')); users.sort(by('_id'));
                            if (!equal(nodes.map(n => String(n._id)), ids)) throw fail('BINDING_MISMATCH');
                            const bindings = [];
                            for (const [i, state] of states.entries()) {
                                const binding = await bindingFor(resolveRelayBinding, env, state, nodes[i]);
                                if (bindings.some(b => b.machineId === binding.machineId || b.sshHostKeySha256 === binding.sshHostKeySha256
                                    || (b.host === binding.host && b.port === binding.port))) throw fail('BINDING_MISMATCH', { nodeId: binding.nodeId });
                                bindings.push(binding);
                            }
                            await authority();
                            return { states, nodes, bindings, users };
                        };
                        const baseline = await load();
                        const plans = makePlans(baseline, action, login, password, key);
                        let intentId, phase, uncertainNodeId;
                        const confirmedNodeIds = [];
                        const verifyAuthority = async () => {
                            await authority();
                            if (intentId) await store.verifyIntent(intentId);
                            await authority();
                        };
                        const recheck = async session => {
                            if (!equal(await load(session), baseline)) throw fail('CHANGED');
                            await verifyAuthority();
                        };
                        const remotes = [];
                        const closeAll = async () => {
                            const results = await Promise.allSettled(remotes.splice(0).map(async remote => remote.close()));
                            if (results.some(r => r.status === 'rejected')) throw fail('CLEANUP_FAILED');
                        };
                        const outcome = suffix => fail(suffix, { intentId, retryAllowed: false, confirmedNodeIds: [...confirmedNodeIds],
                            ...(uncertainNodeId && { uncertainNodeId }) });
                        try {
                            const calls = [];
                            for (const { node, binding, installation, currentUsers, desiredUsers } of plans) {
                                await recheck();
                                const remote = await createRelayDirect({ node, env, binding });
                                if (remotes.includes(remote)) throw fail('UNAVAILABLE');
                                if (typeof remote?.close === 'function') remotes.push(remote);
                                if (typeof remote?.close !== 'function' || typeof remote.checkChap !== 'function' || typeof remote.syncChap !== 'function') {
                                    throw fail('UNAVAILABLE');
                                }
                                calls.push([remote, installation, currentUsers, desiredUsers]);
                            }
                            for (const call of calls) {
                                const [remote, installation, currentUsers, desiredUsers] = call;
                                await recheck();
                                let checked;
                                try { checked = await remote.checkChap(installation, currentUsers, desiredUsers, () => recheck()); }
                                catch { throw fail('PREFLIGHT_REFUSED', { nodeId: installation.nodeId }); }
                                if (!chapReceipt(checked)) throw fail('PREFLIGHT_REFUSED', { nodeId: installation.nodeId });
                                call.push(checked.changed);
                            }
                            await store.assertNoPending();
                            await recheck();
                            if (action === 'disable' && !plans[0].after) {
                                if (calls.some(call => call[4] !== false)) throw fail('PREFLIGHT_REFUSED');
                                await closeAll();
                                return { ...result, relayCount: ids.length };
                            }
                            const id = randomUUID();
                            phase = 'INTENT_UNKNOWN';
                            intentId = id;
                            // Only the create delta needs escrow. The password is
                            // never stored in plaintext, logged, or echoed in errors.
                            await store.begin({ intentId: id, action, login, createdAt: new Date(),
                                ...(action === 'create' && { passwordEncrypted: plans[0].after.passwordEncrypted }),
                                relays: plans.map(({ installation, binding, before, after }) => ({ ...installation, ...binding,
                                    ip: before?.ip ?? after?.ip, revision: before?.desiredRevision ?? 0 })) });
                            phase = 'OUTCOME_UNKNOWN';
                            for (const [remote, installation, currentUsers, desiredUsers, changed] of calls) {
                                await recheck();
                                uncertainNodeId = installation.nodeId;
                                const synced = await remote.syncChap(installation, currentUsers, desiredUsers, () => recheck());
                                if (!chapReceipt(synced) || synced.changed !== changed) throw fail(phase);
                                confirmedNodeIds.push(uncertainNodeId);
                                uncertainNodeId = undefined;
                            }
                            phase = 'FINISH_UNKNOWN';
                            await closeAll();
                            await recheck();
                            const now = new Date();
                            const changes = plans.map(({ before, after }) => ({ before, after: after && {
                                ...after, lastSyncedAt: now, updatedAt: now, ...(action === 'create' && { createdAt: now }),
                            } }));
                            await store.publish({ action, changes, recheck, verifyAuthority });
                            // A failed release can only happen after both host and
                            // DB acknowledgements; if it landed, exposing DB is safe.
                            completed = true;
                            phase = 'RELEASE_UNKNOWN';
                            await verifyAuthority();
                            await store.release(id);
                            return { ...result, relayCount: ids.length };
                        } catch (error) {
                            if (phase) throw outcome(phase);
                            throw error;
                        } finally {
                            // Required close is done before publish; secondary
                            // close failures cannot change an unknown outcome.
                            try { await closeAll(); } catch { /* Preserve the primary outcome. */ }
                        }
                    });
                } catch (error) {
                    primary = safe(error);
                    throw primary;
                }
            });
        } catch (error) {
            throw primary ?? (completed ? fail('CLEANUP_FAILED', { retryAllowed: false }) : safe(error));
        }
    }
    return Object.freeze({ create: input => run('create', input), disable: input => run('disable', input), delete: input => run('delete', input) });
}

module.exports = { createRebuildRelayAccounts };
