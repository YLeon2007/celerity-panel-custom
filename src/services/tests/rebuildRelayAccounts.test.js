'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isDeepStrictEqual: equal } = require('node:util');
const { createRebuildRelayAccounts } = require('../rebuildRelayAccounts');
const { resolveRelayBinding } = require('../rebuildRelayAuthorization');
const { accountError } = require('../rebuildRelayAccountsStore');
const { encrypt, decrypt } = require('../../modules/relay-l2tp/services/secretBoxService');

const A = 'a'.repeat(24), B = 'b'.repeat(24);
const key = 'unit-fixture-key-'.repeat(3);
const credentials = { login: 'shared', password: 'fixture-only' };
const sharedCipher = encrypt(credentials.password, key);
const bootstrap = 'relay-bootstrap';
const bootstrapCipher = encrypt('fixture-bootstrap', key);
const neighbor = 'other-account';
const neighborCipher = encrypt('fixture-neighbor', key);
const ip = (i, end) => `10.255.${16 + i}.${end}`;
const code = suffix => ({ code: `REBUILD_L2TP_ACCOUNTS_${suffix}` });
const order = rows => [...rows].sort((a, b) => a.login.localeCompare(b.login));
const sameStoredRow = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const reads = [`inspect:${A}`, `inspect:${B}`];
const fencePass = [...reads, `fence:${A}`, `fence:${B}`, ...reads];

function fixture({ shared = false, single = false, legacy = false, disabled = false, other = false, fault = () => {} } = {}) {
    const ids = single ? [A] : [A, B];
    const rows = ids.map((id, i) => ({
        node: { _id: id, ip: `192.0.2.${i + 1}`, ssh: { port: 22, username: 'root' },
            active: true, type: 'xray', cascadeRole: 'relay' },
        state: { _id: id, node: id, rebuildMachineId: String(i + 1).repeat(32), backupId: String(i + 2).repeat(32),
            rebuildInstallToken: `aaaaaaaa-aaaa-4aaa-aaaa-00000000000${i}`, status: 'installed', desiredState: 'installed',
            routingMode: 'follow-relay', routingVersion: 1, secretRevision: 1,
            clientCidr: `${ip(i, 0)}/24`, localAddress: ip(i, 1), poolStart: ip(i, 10), poolEnd: ip(i, 20),
            tproxyPort: 12345, fwmark: 100, routeTable: 100 },
    }));
    const user = (id, i, login, end, passwordEncrypted) => ({ _id: `${id}:${login}`, relayNode: id, login, ip: ip(i, end),
        enabled: true, passwordEncrypted, desiredRevision: 1, appliedRevision: 1, syncStatus: 'synced' });
    const users = rows.flatMap(({ node: { _id: id } }, i) => [
        user(id, i, bootstrap, 10, bootstrapCipher),
        ...(shared ? [{ ...user(id, i, credentials.login, 11, sharedCipher), enabled: !disabled }] : []),
        ...(other ? [user(id, i, neighbor, 12, neighborCipher)] : []),
    ]);
    const hosts = Object.fromEntries(ids.map(id => [id, users.filter(u => u.relayNode === id).map(u => ({
        login: u.login, password: decrypt(u.passwordEncrypted, key), ipAddress: u.ip, enabled: u.enabled,
    }))]));
    const operatorList = rows.map(({ node, state }, i) => ({ nodeId: node._id, host: node.ip, ...node.ssh,
        machineId: state.rebuildMachineId, sshHostKeySha256: String(i + 1).repeat(64) }));
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', ENCRYPTION_KEY: key,
        C3_REBUILD_L2TP_RELAY_ID: A, C3_REBUILD_L2TP_RELAY_MACHINE_ID: operatorList[0].machineId,
        C3_REBUILD_L2TP_SSH_SHA256: operatorList[0].sshHostKeySha256,
        ...(!legacy && { C3_REBUILD_L2TP_RELAYS_JSON: JSON.stringify(operatorList) }) };
    const events = [];
    let pending, held = false, inTransaction = false, directory;
    const sessions = Object.fromEntries(ids.map((id, i) => [id, [bootstrap, ...(other ? [neighbor] : []),
        ...(shared ? Array(i + 1).fill(credentials.login) : [])]]));
    const f = { rows, users, hosts, sessions, events, env, get pending() { return pending; },
        set pending(value) { pending = value; }, get directory() { return directory; }, set directory(value) { directory = value; } };
    const step = (name, id) => {
        assert.equal(held, true);
        if (id) assert.equal(inTransaction, false, 'no resolver or DIRECT I/O in the transaction');
        events.push(id ? `${name}:${id}` : name);
        return fault(name, id, f);
    };
    const compareInTransaction = async check => {
        inTransaction = true;
        try { await check({}); } finally { inTransaction = false; }
    };
    const store = {
        async assertNoPending() { step('gate'); if (pending) throw accountError('BLOCKED'); },
        async pending() { await step('pending'); return pending === undefined ? null : structuredClone(pending); },
        async states() { step('inventory'); return structuredClone(rows.map(r => r.state).reverse()); },
        async inventory(ids, login) {
            step('read');
            return structuredClone({ nodes: rows.map(r => r.node),
                users: users.filter(u => ids.includes(u.relayNode) || u.login === login), directory });
        },
        async begin(intent) { step('intent'); assert.equal(pending, undefined);
            pending = { _id: 'pending', ...structuredClone(intent) }; await step('intent-ack'); },
        async verifyIntent(intentId, expected) {
            step('own');
            if (intentId !== pending?.intentId || (expected && !sameStoredRow(expected, pending))) throw accountError('CHANGED');
        },
        async cancel({ intent, recheck, verifyAuthority }) {
            step('cancel'); await compareInTransaction(recheck); await verifyAuthority();
            if (!sameStoredRow(intent, pending)) throw accountError('CHANGED');
            pending = undefined;
            step('cancel-ack');
        },
        async publish({ intentId, intent, action, changes, recheck, verifyAuthority }) {
            step('publish'); await compareInTransaction(recheck);
            assert.equal(intentId, pending.intentId);
            await verifyAuthority();
            step('settle');
            if (intent && !sameStoredRow(intent, pending)) throw accountError('CHANGED');
            for (const { before, after } of changes) {
                if (action === 'create') users.push({ _id: `${after.relayNode}:${after.login}`, ...after });
                else if (action === 'delete') users.splice(users.findIndex(u => u._id === before._id), 1);
                else Object.assign(users.find(u => u._id === before._id), after);
            }
            if (directory) {
                directory.accounts = users.filter(u => u.relayNode === A).map(u => ({ id: u._id, login: u.login,
                    enabled: u.enabled, passwordEncrypted: u.passwordEncrypted }));
            }
            pending = undefined;
            step('publish-ack');
        },
    };
    const deps = { env, store,
        locks: { async run(fn) {
            assert.equal(held, false); held = true;
            try { return await fn(async () => step('lock')); }
            finally { held = false; fault('unlock', undefined, f); }
        } },
        resolveRelayBinding(_, id, node) {
            const altered = step('binding', id);
            return altered ?? resolveRelayBinding(env, id, node);
        },
        createRelayDirect({ node, binding }) {
            const id = node._id;
            step('connect', id); assert.equal(binding.nodeId, id);
            const changed = (current, desired) => !equal(order(current.filter(u => u.enabled)), order(desired.filter(u => u.enabled)));
            const check = (install, current) => {
                assert.equal(install.nodeId, id);
                assert.deepEqual(Object.keys(install.network).sort(), ['clientCidr', 'fwmark', 'routeTable', 'tproxyPort']);
                assert.equal(changed(current, hosts[id]), false, 'must pass observed CHAP preimage');
            };
            return {
                async checkChap(install, current, desired, verifyLock, revokedLogin) {
                    await verifyLock(); check(install, current);
                    assert.ok(Array.isArray(desired));
                    if (revokedLogin !== undefined) assert.ok(current.some(u => u.login === revokedLogin));
                    return step('check', id) ?? { changed: changed(current, desired) };
                },
                async inspectChap(install, current, desired, verifyLock, revokedLogin) {
                    await verifyLock();
                    assert.equal(install.nodeId, id);
                    const override = step('inspect', id);
                    const original = !changed(current, hosts[id]), target = !changed(desired, hosts[id]);
                    if (!original && !target) throw Error('unclassified CHAP');
                    if (sessions[id].some(login => !current.some(u => u.login === login)
                        && !desired.some(u => u.login === login))) throw Error('unclassified session');
                    return override ?? { projection: original && target ? 'both' : original ? 'original' : 'desired',
                        activeTargetSessions: sessions[id].filter(login => login === revokedLogin).length };
                },
                async syncChap(install, current, desired, verifyLock, revokedLogin) {
                    await step('before-sync-guard', id);
                    await verifyLock(); check(install, current);
                    assert.ok(pending);
                    if (revokedLogin) assert.ok(current.find(u => u.login === revokedLogin)?.ipAddress, 'target IP must be known');
                    const result = step('sync', id);
                    if (result === undefined) hosts[id] = structuredClone(desired);
                    if (result !== undefined) return result;
                    if (pending.action === 'create') return { changed: changed(current, desired) };
                    assert.ok(!hosts[id].some(u => u.login === revokedLogin && u.enabled), 'block CHAP before terminating');
                    const sessionsTerminated = sessions[id].filter(login => login === revokedLogin).length;
                    sessions[id] = sessions[id].filter(login => login !== revokedLogin);
                    return { changed: changed(current, desired), sessionsTerminated, complete: true };
                },
                async fenceChap(install, current, desired, verifyLock, revokedLogin) {
                    await verifyLock();
                    assert.equal(install.nodeId, id);
                    assert.ok(Array.isArray(current) && Array.isArray(desired));
                    assert.equal(revokedLogin, pending.action === 'create' ? undefined : pending.login);
                    return (await step('fence', id)) ?? { fenced: true };
                },
                async close() { step('close', id); },
            };
        },
    };
    f.service = createRebuildRelayAccounts(deps);
    f.restart = () => createRebuildRelayAccounts(deps);
    f.deps = deps;
    return f;
}

const effects = f => f.events.filter(x => /^(check:|intent$|sync:|publish$|settle$)/.test(x));
const noWrites = f => assert.deepEqual(effects(f).filter(x => !x.startsWith('check:')), []);

for (const action of ['create', 'disable', 'delete']) {
    test(`legacy singleton refuses mutating ${action} before DIRECT or persistence`, async () => {
        const f = fixture({ single: true, legacy: true, shared: action !== 'create' });
        await assert.rejects(f.service[action](credentials), code('OPERATOR_LIST_REQUIRED'));
        noWrites(f);
        assert.ok(!f.events.includes(`connect:${A}`));
    });
}

test('legacy singleton already-disabled account cannot claim revocation without a supported writer', async () => {
    const f = fixture({ single: true, legacy: true, shared: true, disabled: true });
    await assert.rejects(f.service.disable({ login: credentials.login }), code('OPERATOR_LIST_REQUIRED'));
    noWrites(f);
});

test('losing operator list mode with an identical legacy binding revokes writes', async () => {
    const f = fixture({ single: true, fault(step, _, fixture) {
        if (step === 'check') delete fixture.env.C3_REBUILD_L2TP_RELAYS_JSON;
    } });
    await assert.rejects(f.service.create(credentials), code('CHANGED'));
    assert.deepEqual(effects(f), [`check:${A}`]);
});

for (const [action, status] of [['create', 'created'], ['disable', 'disabled'], ['delete', 'deleted']]) {
    test(`${action}: checks both relays before intent, confirms both before publishing rows`, async () => {
        const f = fixture({ shared: action !== 'create' });
        const before = structuredClone(f.users.filter(u => u.login === bootstrap));
        assert.deepEqual(await f.service[action](action === 'create' ? credentials : { login: credentials.login }),
            { executionMode: 'rebuild', status, login: credentials.login, relayCount: 2,
                ...(action !== 'create' && { sessionsTerminated: 3 }) });
        assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent', `sync:${A}`, `sync:${B}`, 'publish', 'settle']);
        assert.equal(f.pending, undefined);
        assert.deepEqual(f.users.filter(u => u.login === bootstrap), before);
        assert.deepEqual(f.sessions, { [A]: [bootstrap], [B]: [bootstrap] });
        const rows = f.users.filter(u => u.login === credentials.login);
        if (action === 'delete') {
            assert.deepEqual(rows, []);
            assert.ok([A, B].every(id => f.hosts[id].length === 1));
            return;
        }
        assert.deepEqual(rows.map(u => u.ip), [ip(0, 11), ip(1, 11)]);
        assert.equal(rows[0].passwordEncrypted, rows[1].passwordEncrypted);
        assert.equal(decrypt(rows[0].passwordEncrypted, key), credentials.password);
        assert.deepEqual(rows.map(u => [u.enabled, u.desiredRevision, u.appliedRevision, u.syncStatus]),
            Array.from({ length: 2 }, () => action === 'create' ? [true, 1, 1, 'synced'] : [false, 2, 2, 'synced']));
        for (const [i, id] of [A, B].entries()) {
            assert.deepEqual(f.hosts[id].find(u => u.login === credentials.login), {
                ...credentials, ipAddress: ip(i, 11), enabled: action === 'create',
            });
        }
    });
}

test('already-disabled is checked and drained, without inventing a new account revision', async () => {
    const f = fixture({ shared: true, disabled: true });
    assert.equal((await f.service.disable(credentials)).sessionsTerminated, 3);
    assert.deepEqual(f.users.filter(u => u.login === credentials.login).map(u => [u.enabled, u.desiredRevision]), [[false, 1], [false, 1]]);
});

test('disable and subsequent delete preserve a second ordinary account on both relays', async () => {
    const f = fixture({ shared: true, other: true });
    const neighbors = () => f.users.filter(u => u.login === neighbor || u.login === bootstrap);
    const protectedRows = structuredClone(neighbors());
    const protectedChap = Object.fromEntries([A, B].map(id => [id,
        structuredClone(order(f.hosts[id].filter(u => u.login !== credentials.login)))]));
    assert.equal((await f.service.disable(credentials)).sessionsTerminated, 3);
    assert.deepEqual(f.sessions, { [A]: [bootstrap, neighbor], [B]: [bootstrap, neighbor] });
    // A delete with unchanged CHAP bytes still has to prove zero sessions.
    assert.equal((await f.service.delete(credentials)).sessionsTerminated, 0);
    assert.deepEqual(f.sessions, { [A]: [bootstrap, neighbor], [B]: [bootstrap, neighbor] });
    assert.deepEqual(neighbors(), protectedRows);
    assert.deepEqual(f.hosts, protectedChap);
});

test('partial B settlement reports only confirmed closures, never publishes or retries', async () => {
    const f = fixture({ shared: true, fault(step, id) {
        if (step === 'sync' && id === B) return { changed: true, sessionsTerminated: 1, complete: false };
    } });
    await assert.rejects(f.service.delete(credentials), { ...code('OUTCOME_UNKNOWN'), retryAllowed: false,
        confirmedNodeIds: [A], uncertainNodeId: B, confirmedSessionsTerminated: 2 });
    assert.ok(f.pending && f.users.filter(u => u.login === credentials.login).length === 2);
    assert.ok(!f.events.includes('publish'));
});

test('a terminal partial A does not prevent revoking on pinned B', async () => {
    const f = fixture({ shared: true, fault(step, id) {
        if (step === 'sync' && id === A) return { changed: true, sessionsTerminated: 0, complete: false };
    } });
    await assert.rejects(f.service.disable(credentials), { ...code('OUTCOME_UNKNOWN'), retryAllowed: false,
        confirmedNodeIds: [B], uncertainNodeId: A, confirmedSessionsTerminated: 2 });
    assert.deepEqual(f.sessions[B], [bootstrap]);
    assert.ok(f.pending && !f.events.includes('publish'));
});

test('preflight refusal on B leaves both hosts and persistence unchanged', async () => {
    const f = fixture({ fault: (step, id) => step === 'check' && id === B ? false : undefined });
    const before = structuredClone(f.hosts);
    await assert.rejects(f.service.create(credentials), { ...code('PREFLIGHT_REFUSED'), nodeId: B });
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`]);
    assert.deepEqual(f.hosts, before);
    assert.equal(f.pending, undefined);
    assert.ok([A, B].every(id => f.events.includes(`close:${id}`)));
});

test('timeout on B after A: no DB publication or rollback until a fresh observation can settle it', async () => {
    const f = fixture({ fault(step, id) {
        if (step === 'sync' && id === B) throw new Error('simulated lost acknowledgement');
        if (step === 'close' && id === A) throw new Error('simulated disposal error');
    } });
    await assert.rejects(f.service.create(credentials), e => {
        assert.equal(e.code, code('OUTCOME_UNKNOWN').code);
        assert.equal(e.intentId, f.pending.intentId);
        assert.deepEqual(e.confirmedNodeIds, [A]);
        assert.equal(e.uncertainNodeId, B);
        return e.retryAllowed === false;
    });
    assert.equal(f.hosts[A].length, 2);
    assert.equal(f.hosts[B].length, 1);
    assert.deepEqual(f.users.map(u => u.login), [bootstrap, bootstrap]);
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent', `sync:${A}`, `sync:${B}`]);
    assert.ok(f.events.includes(`close:${B}`));
    const end = f.events.length;
    await assert.rejects(f.restart().delete({ login: 'other' }), { ...code('OUTCOME_UNKNOWN'), uncertainNodeId: B });
    assert.deepEqual(recoveryEffects({ events: f.events.slice(end) }), [...fencePass, `sync:${B}`]);
    assert.ok(f.pending);
});

test('missing installed relays refuses without write or DIRECT', async () => {
    const f = fixture();
    f.rows.length = 0;
    await assert.rejects(f.service.create(credentials), code('NO_INSTALLED'));
    assert.deepEqual(effects(f), []);
});

test('binding on B mismatches installed receipt, no DIRECT or persistence write', async () => {
    const f = fixture({ fault(step, id) {
        if (step === 'binding' && id === B) return { nodeId: B, host: '192.0.2.2', port: 22, username: 'root',
            machineId: 'c'.repeat(32), sshHostKeySha256: '2'.repeat(64) };
    } });
    await assert.rejects(f.service.create(credentials), code('BINDING_MISMATCH'));
    assert.deepEqual(effects(f), []);
    assert.ok(!f.events.some(x => x.startsWith('connect:')));
});

test('DB drift during preflight on B refuses before intent and dispatch', async () => {
    const f = fixture({ fault(step, id, fixture) {
        if (step === 'check' && id === B) fixture.users.find(u => u.relayNode === A).comment = 'db drift';
    } });
    await assert.rejects(f.service.create(credentials), code('CHANGED'));
    noWrites(f);
});

test('binding drift after A is confirmed prevents B dispatch without trying to undo A', async () => {
    const f = fixture({ fault(step, id, fixture) {
        if (step === 'binding' && id === B && fixture.hosts[A].length === 2) {
            const { node, state } = fixture.rows[1];
            return { nodeId: B, host: node.ip, port: 22, username: 'root', machineId: state.rebuildMachineId,
                sshHostKeySha256: '3'.repeat(64) };
        }
    } });
    await assert.rejects(f.service.create(credentials), e => {
        assert.deepEqual(e.confirmedNodeIds, [A]);
        assert.equal(e.uncertainNodeId, undefined);
        return e.code === code('OUTCOME_UNKNOWN').code && e.retryAllowed === false;
    });
    assert.ok(f.pending);
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent', `sync:${A}`]);
});

for (const mismatch of ['missing', 'duplicate', 'ciphertext', 'enabled']) {
    test(`${mismatch} member of a shared account refuses before DIRECT and DB writes`, async () => {
        const f = fixture({ shared: true });
        const ix = f.users.findIndex(u => u.relayNode === B && u.login === credentials.login);
        if (mismatch === 'missing') f.users.splice(ix, 1);
        if (mismatch === 'duplicate') f.users.push({ ...f.users[ix], _id: 'duplicate' });
        if (mismatch === 'ciphertext') f.users[ix].passwordEncrypted = encrypt(credentials.password, key);
        if (mismatch === 'enabled') f.users[ix].enabled = false;
        await assert.rejects(f.service.disable({ login: credentials.login }), code('ACCOUNT_CONFLICT'));
        assert.deepEqual(effects(f), []);
        assert.ok(!f.events.some(x => x.startsWith('connect:')));
    });
}

test('intent acknowledgement loss never dispatches, a later all-original observation can cancel it', async () => {
    const f = fixture({ fault(step) { if (step === 'intent-ack') throw Error('ack lost'); } });
    await assert.rejects(f.service.create(credentials), { ...code('INTENT_UNKNOWN'), retryAllowed: false });
    assert.ok(f.pending);
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent']);
    assert.equal((await f.restart().create(credentials)).status, 'canceled');
    assert.equal(f.pending, undefined);
    assert.deepEqual(recoveryEffects(f), [`check:${A}`, `check:${B}`, 'intent', ...fencePass, 'cancel']);
});

test('visible intent is not permission to dispatch before its commit acknowledgement', async () => {
    let entered, acknowledge;
    const committing = new Promise(resolve => { entered = resolve; });
    const ack = new Promise(resolve => { acknowledge = resolve; });
    const f = fixture({ fault(step) { if (step === 'intent-ack') { entered(); return ack; } } });
    const result = f.service.create(credentials);
    await committing;
    assert.ok(f.pending);
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent']);
    acknowledge();
    assert.equal((await result).status, 'created');
    assert.deepEqual(effects(f).filter(e => e.startsWith('sync:')), [`sync:${A}`, `sync:${B}`]);
});

for (const [name, change] of [
    ['missing row', f => { f.pending = undefined; }],
    ['different owner', f => { f.pending.intentId = 'aaaaaaaa-bbbb-4ccc-8ddd-fffffffffffe'; }],
    ['same-owner added field', f => { f.pending.extra = true; }],
    ['nested change under the same owner', f => { f.pending.relays[1].network.routeTable++; }],
    ['read failure', () => { throw Error('fixture pending readback unavailable'); }],
]) {
    test(`fresh intent readback refuses ${name} before sync or publication`, async () => {
        const f = fixture({ fault(step, _, state) { if (step === 'pending' && state.pending) change(state); } });
        const original = structuredClone(f.hosts);
        await assert.rejects(f.service.create(credentials), { ...code('PRE_EFFECT_BLOCKED'), retryAllowed: false, confirmedNodeIds: [] });
        assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent']);
        assert.deepEqual(f.hosts, original);
    });
}

test('fresh intent accepts reordered content but uses the stored order for authority and settlement', async () => {
    const reverseFields = row => Object.fromEntries(Object.entries(row).reverse());
    const f = fixture({ fault(step, _, state) {
        if (step === 'intent-ack') state.pending = reverseFields({ ...state.pending, relays: state.pending.relays.map(relay =>
            reverseFields({ ...relay, network: reverseFields(relay.network) })) });
    } });
    assert.equal((await f.service.create(credentials)).status, 'created');
    assert.deepEqual(f.events.filter(step => ['pending', 'intent', `sync:${A}`].includes(step)),
        ['pending', 'intent', 'pending', `sync:${A}`]);
});

test('fresh authority rejects same-owner drift at B transport guard after A', async () => {
    const f = fixture({ fault(step, id, state) {
        if (step === 'before-sync-guard' && id === B) state.pending.createdAt = new Date(0);
    } });
    await assert.rejects(f.service.create(credentials), { ...code('OUTCOME_UNKNOWN'), retryAllowed: false,
        confirmedNodeIds: [A], uncertainNodeId: B });
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent', `sync:${A}`]);
    assert.equal(f.pending.createdAt.getTime(), 0);
});

test('fresh publication cannot settle same-owner drift after the last authority check', async () => {
    const f = fixture({ fault(step, _, state) { if (step === 'settle') state.pending.extra = true; } });
    const original = structuredClone(f.users);
    await assert.rejects(f.service.create(credentials), { ...code('FINISH_UNKNOWN'), retryAllowed: false, confirmedNodeIds: [A, B] });
    assert.equal(f.pending.extra, true);
    assert.deepEqual(f.users, original);
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent', `sync:${A}`, `sync:${B}`, 'publish', 'settle']);
});

test('publication CAS loss retains the intent and never publishes or rolls back hosts', async () => {
    const f = fixture({ fault(step) { if (step === 'settle') throw Error('settlement conflict'); } });
    await assert.rejects(f.service.create(credentials), { ...code('FINISH_UNKNOWN'), retryAllowed: false, confirmedNodeIds: [A, B] });
    assert.ok(f.pending);
    assert.deepEqual(f.users.map(u => u.login), [bootstrap, bootstrap]);
    f.events.length = 0;
    await assert.rejects(f.restart().create(credentials), code('FINISH_UNKNOWN'));
    assert.deepEqual(recoveryEffects(f), [...fencePass, ...reads, 'publish']);
    assert.ok(f.pending);
});

test('lost publication acknowledgement remains unknown after atomic settlement and never replays', async () => {
    const f = fixture({ fault(step) { if (step === 'publish-ack' || step === 'unlock') throw Error('ack lost'); } });
    await assert.rejects(f.service.create(credentials), { ...code('FINISH_UNKNOWN'), retryAllowed: false, confirmedNodeIds: [A, B] });
    assert.equal(f.pending, undefined);
    assert.deepEqual(f.users.filter(u => u.login === credentials.login).map(u => u.ip), [ip(0, 11), ip(1, 11)]);
    await assert.rejects(f.restart().create(credentials), code('ACCOUNT_CONFLICT'));
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent', `sync:${A}`, `sync:${B}`, 'publish', 'settle']);
});

test('ordinary guard rejects strict flags before resolving any binding', async () => {
    const f = fixture();
    f.env.L2TP_EXECUTION_ENABLED = 'true';
    await assert.rejects(f.service.create(credentials), code('DISABLED'));
    assert.deepEqual(f.events, []);
});

// The released intent had no progress journal, desired inventory, or count.
function releasedIntent(f, action) {
    return { _id: 'pending', intentId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', action, login: credentials.login,
        createdAt: new Date(0), ...(action === 'create' && { passwordEncrypted: sharedCipher }),
        relays: f.rows.map(({ node, state }, i) => ({
            ...resolveRelayBinding(f.env, node._id, node), backupId: state.backupId,
            network: { clientCidr: state.clientCidr, tproxyPort: state.tproxyPort, fwmark: state.fwmark, routeTable: state.routeTable },
            ip: ip(i, 11), revision: action === 'create' ? 0 : 1,
        })) };
}

const recoveryEffects = f => f.events.filter(x => /^(inspect:|fence:|check:|sync:|cancel$|intent$|publish$)/.test(x));

function withDbGrants(f) {
    const list = JSON.parse(f.env.C3_REBUILD_L2TP_RELAYS_JSON);
    const grants = list.map((binding, i) => ({ ...binding, generation: `generation-${i}` }));
    f.deps.relayGrantStore = { async snapshot() {
        return { env: { ...f.env, C3_REBUILD_L2TP_RELAYS_JSON: JSON.stringify(grants.map(({ generation, ...row }) => row)) },
            grants: structuredClone(grants), sourceFor: () => 'db' };
    } };
    f.deps.resolveRelayBinding = resolveRelayBinding;
    return grants;
}

test('admitted ordinary account mutations cannot settle a pending write, even with the original credentials', async () => {
    let loseAcknowledgement = true;
    const f = fixture({ fault(step, id) {
        if (loseAcknowledgement && step === 'sync' && id === B) throw Error('lost acknowledgement');
    } });
    withDbGrants(f);
    await assert.rejects(f.restart().create(credentials), { ...code('OUTCOME_UNKNOWN'), retryAllowed: false });
    loseAcknowledgement = false;
    const pending = structuredClone(f.pending), users = structuredClone(f.users), hosts = structuredClone(f.hosts);
    f.events.length = 0;
    for (const [action, input] of [['create', credentials], ['create', { ...credentials, login: neighbor }],
        ['disable', { login: credentials.login }], ['delete', { login: neighbor }]]) {
        await assert.rejects(f.restart()[action](input), { ...code('BLOCKED'), retryAllowed: false });
    }
    assert.ok(f.events.every(event => ['lock', 'pending'].includes(event)), 'nothing beyond the locked pending read');
    assert.deepEqual([f.pending, f.users, f.hosts], [pending, users, hosts]);
    f.events.length = 0;
    assert.equal((await f.restart().reconcile()).status, 'created');
    assert.deepEqual(recoveryEffects(f), [...fencePass, `sync:${B}`, ...reads, 'publish']);
    assert.equal(f.pending, undefined);
    assert.equal((await f.restart().create({ ...credentials, login: neighbor })).status, 'created');
});

test('admitted account revocation stops dispatch on a checked but incomplete relay', async () => {
    const f = fixture({ shared: true, fault(step, id) {
        if (step === 'sync' && id === A) return { changed: true, complete: false, sessionsTerminated: 1 };
    } });
    withDbGrants(f);
    await assert.rejects(f.restart().disable(credentials), { ...code('OUTCOME_UNKNOWN'), retryAllowed: false,
        confirmedNodeIds: [], confirmedSessionsTerminated: 1, uncertainNodeId: A });
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent', `sync:${A}`]);
    assert.ok(f.pending);
});

test('identity loss after A blocks B, retains the exact intent and reports uncertainty; manual recovery only converges B', async () => {
    let grants, originalIntent;
    const f = fixture({ fault(step, id, state) {
        if (step === 'sync' && id === A && !originalIntent) {
            originalIntent = JSON.stringify(state.pending);
            grants[1].sshHostKeySha256 = 'f'.repeat(64);
        }
    } });
    grants = withDbGrants(f);
    const originalPin = grants[1].sshHostKeySha256;
    await assert.rejects(f.restart().create(credentials), { ...code('OUTCOME_UNKNOWN'), retryAllowed: false,
        confirmedNodeIds: [A] });
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent', `sync:${A}`]);
    assert.equal(JSON.stringify(f.pending), originalIntent);
    f.events.length = 0;
    await assert.rejects(f.restart().reconcile(), { ...code('MANUAL_BLOCK'), retryAllowed: false });
    assert.ok(!f.events.some(event => event.startsWith('connect:')));
    assert.deepEqual(recoveryEffects(f), []);
    assert.equal(JSON.stringify(f.pending), originalIntent);

    grants[1].sshHostKeySha256 = originalPin;
    grants[1].generation = 'unrelated-successor';
    await assert.rejects(f.restart().reconcile(), { ...code('MANUAL_BLOCK'), retryAllowed: false });
    assert.deepEqual(recoveryEffects(f), []);
    assert.equal(JSON.stringify(f.pending), originalIntent);

    grants[1].generation = 'generation-1';
    const { state: stateB } = f.rows.find(({ node }) => node._id === B);
    const originalBackup = stateB.backupId;
    stateB.backupId = 'e'.repeat(32);
    await assert.rejects(f.restart().reconcile(), { ...code('MANUAL_BLOCK'), retryAllowed: false });
    assert.deepEqual(recoveryEffects(f), []);
    assert.equal(JSON.stringify(f.pending), originalIntent);
    stateB.backupId = originalBackup;
    const end = f.events.length;
    assert.deepEqual(await f.restart().reconcile(), { executionMode: 'rebuild', status: 'created', login: credentials.login,
        relayCount: 2, recovered: true });
    assert.deepEqual(recoveryEffects({ events: f.events.slice(end) }), [...fencePass, `sync:${B}`, ...reads, 'publish']);
    assert.equal(f.pending, undefined);
});

test('known pre-effect identity refusal stays distinct from a late cohort failure', async () => {
    for (const afterIntent of [false, true]) {
        let grants;
        const f = fixture({ fault(step, id) {
            if (afterIntent ? step === 'intent-ack' : step === 'check' && id === B) grants[1].sshHostKeySha256 = 'f'.repeat(64);
        } });
        grants = withDbGrants(f);
        await assert.rejects(f.restart().create(credentials), afterIntent ? { ...code('PRE_EFFECT_BLOCKED'), retryAllowed: false }
            : { code: 'REBUILD_L2TP_IDENTITY_CHANGED' });
        assert.equal(Boolean(f.pending), afterIntent);
        assert.ok(!effects(f).some(e => e.startsWith('sync:') || e === 'publish'));
    }
});

test('mounted reconcile reports only a bounded DIRECT inspection refusal while its intent remains pending', async t => {
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_RELAYS_JSON: '[]', PANEL_DOMAIN: 'panel.fixture.invalid',
        ACME_EMAIL: 'test@fixture.invalid', ENCRYPTION_KEY: key, SESSION_SECRET: 'test-session-only' };
    for (const [name, value] of Object.entries(env)) {
        const previous = process.env[name];
        process.env[name] = value;
        t.after(() => { if (previous === undefined) delete process.env[name]; else process.env[name] = previous; });
    }
    const express = require('express');
    const { request } = require('./helpers/rebuildPanelRequest');
    const { createPanelRouter, l2tpRateLimiter } = require('../../routes/panel');
    const Settings = require('../../models/settingsModel');
    const { issuePanelCsrfToken } = require('../../routes/panel/csrf');
    const { createRelayDirect } = require('../rebuildRelayDirect');
    const attested = require('./helpers/rebuildRelayDirectWire');
    const service = require('../rebuildService');
    const { i18nMiddleware } = require('../../middleware/i18n');
    const peer = '192.0.2.10';
    const config = require('../../../config');
    t.mock.method(Settings, 'findById', () => ({ select: () => ({ lean: async () => ({ deployment: { completed: true } }) }) }));
    t.after(() => require('../sshPoolService').closeAll());
    const whitelist = config.PANEL_IP_WHITELIST;
    config.PANEL_IP_WHITELIST = peer;
    t.after(() => { config.PANEL_IP_WHITELIST = whitelist; });

    const frame = 'DIRECT_INSPECT_PIDFD_GETFD_EPERM\n';
    const exact = { code: 70, stdout: '', stderr: frame };
    let f, loseReadback;
    const writer = t.mock.method(service, 'createRebuildService', () => ({ reconcileRelayAccounts: f.service.reconcile }));
    const app = express();
    app.set('view engine', 'ejs');
    app.set('views', require('node:path').join(__dirname, '../../../views'));
    app.use(i18nMiddleware);
    app.use('/panel', createPanelRouter({ rebuildL2tpOverview: {
        async overview() {
            return { relays: [], accounts: [], accountsPending: Boolean(f.pending), canReconcileAccounts: true, canManageAccounts: true };
        },
        async hasPendingAccounts() {
            if (loseReadback && f.events.includes(`close:${A}`)) throw new Error('FIXTURE_PRIVATE_DETAIL');
            return Boolean(f.pending);
        },
    } }));
    const session = { authenticated: true }, sessionID = 'inspect-fixture';
    const url = '/panel/rebuild/relays/l2tp/accounts/reconcile';
    const post = () => request(app, url, { session, sessionID, ip: peer,
        headers: { 'content-type': 'application/json', 'content-length': '2', 'x-csrf-token': issuePanelCsrfToken({ session }) } });
    const overview = (query = '') => request(app, `/panel/l2tp${query}`, { method: 'GET', session, sessionID, ip: peer,
        headers: { 'accept-language': 'en' } });
    const receipt = status => ({ executionMode: 'rebuild', status });
    const blocked = reason => ({ ...receipt('inspection-unproved'), reason, retryAllowed: false });
    const pending = receipt('pending');
    for (const [mode, wire, expected] of [
        ['denied', exact, blocked('pidfd-getfd-eperm')],
        ['legacy', { ...exact, stderr: 'DIRECT_CHAP_REFUSED\n' }, blocked('host-inspection-unproved')],
        ['tainted', { ...exact, stderr: `${frame}FIXTURE_PRIVATE_DETAIL\n` }, pending],
        ['busy host', { code: 75, stdout: '', stderr: '' }, pending],
        ['busy Apply', undefined, pending],
        ['lost Apply ownership', exact, pending],
        ['stale readback', exact, { error: { code: 'REBUILD_L2TP_RECONCILE_UNAVAILABLE' } }],
        ['proved', undefined, receipt('settled')],
    ]) {
        l2tpRateLimiter.resetKey(peer);
        let lockLost = false;
        f = fixture({ shared: true, other: true, fault(step) { if (step === 'lock' && lockLost) return false; } });
        f.pending = releasedIntent(f, 'delete');
        loseReadback = mode === 'stale readback';
        const before = structuredClone([f.pending, f.users, f.hosts, f.sessions]);
        const createMockRelay = f.deps.createRelayDirect;
        const calls = [];
        let connects = 0;
        class SSH {
            async connect() { connects++; }
            disconnect() { calls.push('close'); }
            async exec(_command, { stdin }, verifyBeforeStdin) {
                await verifyBeforeStdin();
                calls.push(JSON.parse(stdin).action);
                lockLost = mode === 'lost Apply ownership';
                return wire;
            }
        }
        if (wire) f.deps.createRelayDirect = options => options.node._id === B
            ? createRelayDirect({ ...options, SSH: attested(SSH, f.rows[1].state.rebuildMachineId) }) : createMockRelay(options);
        if (mode === 'busy Apply') f.deps.locks.run = async () => { throw Object.assign(new Error(), { code: 'REBUILD_BUSY' }); };
        f.service = f.restart();
        const previousWriters = writer.mock.callCount();
        if (mode === 'denied') {
            const page = await overview();
            assert.equal(page.status, 200);
            assert.match(page.body, /data-reconcile disabled/);
            assert.doesNotMatch(page.body, /data-create|data-secret-url|data-account-action/);
            assert.equal(writer.mock.callCount(), previousWriters);
            assert.equal(connects, 0);
            assert.deepEqual(recoveryEffects(f), []);
        }
        const response = await post();
        assert.equal(response.status, loseReadback ? 503 : 200, mode);
        assert.equal(response.headers['cache-control'], 'no-store', mode);
        assert.deepEqual(JSON.parse(response.body), expected, mode);
        assert.equal(writer.mock.callCount(), previousWriters + 1, mode);
        assert.equal(connects, wire ? 1 : 0, mode);
        if (mode === 'denied') {
            for (const query of ['?view=only', '']) {
                const refresh = await overview(query);
                assert.equal(refresh.status, 200);
                assert.match(refresh.body, /An unfinished operation is pending\. Controls are locked\./);
                assert.doesNotMatch(refresh.body, /data-create|data-secret-url|data-account-action/);
                if (query) assert.doesNotMatch(refresh.body, /data-reconcile/);
                else assert.match(refresh.body, /data-reconcile disabled/);
            }
            assert.equal(writer.mock.callCount(), previousWriters + 1);
            assert.equal(connects, 1);
        }
        assert.deepEqual(calls, wire ? ['inspect-chap', 'close'] : [], mode);
        if (mode === 'proved') {
            assert.equal(f.pending, undefined);
            assert.deepEqual(recoveryEffects(f), [...fencePass, 'cancel']);
        } else {
            assert.deepEqual([f.pending, f.users, f.hosts, f.sessions], before, mode);
            assert.deepEqual(recoveryEffects(f), wire ? [`inspect:${A}`] : [], mode);
        }
    }
});

test('no pending intent is a no-op, not an inventory or host sweep', async () => {
    const f = fixture();
    f.rows.length = 0;
    assert.deepEqual(await f.service.reconcile(), { executionMode: 'rebuild', status: 'idle' });
    assert.deepEqual(recoveryEffects(f), []);
});

test('all-original legacy revocation cancels just the intent, without signaling or touching the directory', async () => {
    const f = fixture({ shared: true, other: true });
    f.pending = releasedIntent(f, 'disable');
    f.directory = { generation: 'original', accounts: f.users.filter(u => u.relayNode === A) };
    const original = structuredClone([f.users, f.directory, f.hosts, f.sessions]);
    const result = await f.service.disable(credentials);
    assert.deepEqual(result, { executionMode: 'rebuild', status: 'canceled', login: credentials.login,
        relayCount: 2, sessionsTerminated: 0, recovered: true });
    assert.deepEqual([f.users, f.directory, f.hosts, f.sessions], original);
    assert.equal(f.pending, undefined);
    assert.deepEqual(recoveryEffects(f), [...fencePass, 'cancel']);
});

test('late B writer between first inspection and fence makes recovery converge instead of cancel', async () => {
    const f = fixture({ shared: true, other: true, fault(step, id, state) {
        if (step === 'fence' && id === B) {
            // The old writer won the host lock before B rotated its fence;
            // its CHAP change and PPP closures are not this caller's receipts.
            blockedHost(state, B);
            state.sessions[B] = [bootstrap, neighbor];
        }
    } });
    f.pending = releasedIntent(f, 'delete');
    assert.deepEqual(await f.service.reconcile(), { executionMode: 'rebuild', status: 'deleted', login: credentials.login,
        relayCount: 2, sessionsTerminated: 1, recovered: true });
    assert.deepEqual(recoveryEffects(f), [...fencePass, `sync:${A}`, ...reads, 'publish']);
    assert.equal(f.pending, undefined);
    assert.deepEqual(f.sessions, { [A]: [bootstrap, neighbor], [B]: [bootstrap, neighbor] });
});

for (const [name, response] of [
    ['lost acknowledgement', () => { throw Error('fence reply lost'); }],
    ['non-boolean acknowledgement', () => ({ fenced: 1 })],
    ['augmented acknowledgement', () => ({ fenced: true, changed: false })],
]) {
    test(`B fence ${name} permits neither cancellation nor convergence`, async () => {
        for (const mixed of [false, true]) {
            const f = fixture({ shared: true, fault(step, id) { if (step === 'fence' && id === B) return response(); } });
            f.pending = releasedIntent(f, 'delete');
            if (mixed) blockedHost(f, A);
            const before = structuredClone([f.pending, f.users, f.hosts, f.sessions]);
            await assert.rejects(f.service.reconcile(), { ...code('BLOCKED'), retryAllowed: false, confirmedNodeIds: [],
                confirmedSessionsTerminated: 0 });
            assert.deepEqual(recoveryEffects(f), [...reads, `fence:${A}`, `fence:${B}`]);
            assert.deepEqual([f.pending, f.users, f.hosts, f.sessions], before);
            assert.ok([A, B].every(id => f.events.includes(`close:${id}`)));
        }
    });
}

test('unknown second classification retains the intent even when A needs convergence', async () => {
    const f = fixture({ shared: true, fault(step, id, state) {
        if (step === 'fence' && id === B) state.sessions[B] = ['unclassified'];
    } });
    f.pending = releasedIntent(f, 'delete');
    blockedHost(f, A);
    const before = structuredClone(f.pending);
    await assert.rejects(f.service.reconcile(), { ...code('BLOCKED'), retryAllowed: false, confirmedSessionsTerminated: 0 });
    assert.deepEqual(f.pending, before);
    assert.deepEqual(recoveryEffects(f), fencePass);
});

test('mixed create after a crashed writer uses the exact escrow and mutates only the original relay', async () => {
    let crash = true;
    const f = fixture({ fault(step, id) {
        if (step === 'sync' && id === B && crash) throw Error('lost reply');
    } });
    await assert.rejects(f.service.create(credentials), code('OUTCOME_UNKNOWN'));
    const escrow = f.pending.passwordEncrypted;
    crash = false;
    f.events.length = 0;
    assert.deepEqual(await f.restart().create(credentials), { executionMode: 'rebuild', status: 'created',
        login: credentials.login, relayCount: 2, recovered: true });
    assert.deepEqual(recoveryEffects(f), [...fencePass, `sync:${B}`, ...reads, 'publish']);
    assert.ok(f.users.filter(u => u.login === credentials.login).every(u => u.passwordEncrypted === escrow));
    assert.equal(f.pending, undefined);
});

test('desired delete drains surviving target PPP with the original IP, not known neighboring sessions', async () => {
    const f = fixture({ shared: true, other: true });
    f.pending = releasedIntent(f, 'delete');
    for (const id of [A, B]) f.hosts[id] = f.hosts[id].filter(u => u.login !== credentials.login);
    f.sessions[A] = [bootstrap, neighbor]; // historical closure was never acknowledged to this caller
    assert.deepEqual(await f.service.reconcile(), { executionMode: 'rebuild', status: 'deleted',
        login: credentials.login, relayCount: 2, sessionsTerminated: 2, recovered: true });
    assert.deepEqual(recoveryEffects(f), [...fencePass, `sync:${B}`, ...reads, 'publish']);
    assert.deepEqual(f.sessions, { [A]: [bootstrap, neighbor], [B]: [bootstrap, neighbor] });
    assert.equal(f.users.some(u => u.login === credentials.login), false);
});

for (const action of ['disable', 'delete']) {
    test(`both projections: ${action} of disabled account still settles live PPP`, async () => {
        const f = fixture({ shared: true, disabled: true });
        f.pending = releasedIntent(f, action);
        assert.equal((await f.restart()[action](credentials)).sessionsTerminated, 3);
        assert.deepEqual(recoveryEffects(f), [...fencePass, `sync:${A}`, `sync:${B}`, ...reads, 'publish']);
        assert.deepEqual(f.sessions, { [A]: [bootstrap], [B]: [bootstrap] });
        assert.deepEqual(f.users.filter(u => u.login === credentials.login).map(u => u.desiredRevision), action === 'disable' ? [1, 1] : []);
    });
}

const blockedHost = (f, id) => {
    f.hosts[id] = f.hosts[id].filter(u => u.login !== credentials.login);
};

test('foreign session alone on B blocks a mixed cohort before writing A', async () => {
    const f = fixture({ shared: true });
    f.pending = releasedIntent(f, 'delete');
    blockedHost(f, B);
    f.sessions[B] = ['unclassified'];
    await assert.rejects(f.service.reconcile(), { ...code('BLOCKED'), retryAllowed: false });
    assert.ok(f.pending);
    assert.deepEqual(recoveryEffects(f), [`inspect:${A}`, `inspect:${B}`]);
});

test('fully desired revocation with only other managed sessions acknowledges zero closures', async () => {
    const f = fixture({ shared: true, other: true });
    f.pending = releasedIntent(f, 'delete');
    for (const id of [A, B]) {
        blockedHost(f, id);
        f.sessions[id] = [neighbor];
    }
    assert.equal((await f.service.reconcile()).sessionsTerminated, 0);
    assert.deepEqual(recoveryEffects(f), [...fencePass, ...reads, 'publish']);
    assert.deepEqual(f.sessions, { [A]: [neighbor], [B]: [neighbor] });
});

test('mixed revocation checks the observed host preimage again at write time', async () => {
    const f = fixture({ shared: true, fault(step, id, state) {
        if (step === 'inspect' && id === B && state.events.includes(`fence:${B}`)) state.hosts[A] = [];
    } });
    f.pending = releasedIntent(f, 'delete');
    blockedHost(f, B);
    await assert.rejects(f.service.reconcile(), { ...code('OUTCOME_UNKNOWN'), uncertainNodeId: A, confirmedSessionsTerminated: 0 });
    assert.deepEqual(recoveryEffects(f), fencePass);
    assert.ok(f.pending);
});

test('checked partial remains pending, and a different classified relay can still settle', async () => {
    const f = fixture({ shared: true, fault(step, id) {
        if (step === 'sync' && id === A) return { changed: false, complete: false, sessionsTerminated: 0 };
    } });
    f.pending = releasedIntent(f, 'delete');
    blockedHost(f, A);
    await assert.rejects(f.service.reconcile(), { ...code('OUTCOME_UNKNOWN'), uncertainNodeId: A,
        retryAllowed: false, confirmedSessionsTerminated: 2, confirmedNodeIds: [B] });
    assert.deepEqual(recoveryEffects(f), [...fencePass, `sync:${A}`, `sync:${B}`]);
    assert.ok(f.pending);
    assert.deepEqual(f.sessions[B], [bootstrap]);
});

test('partial recovery closure counts are only attributed to a matching mutation', async () => {
    for (const [action, login, matching] of [['delete', neighbor, false], ['disable', credentials.login, false],
        ['delete', credentials.login, true]]) {
        const f = fixture({ shared: true, other: true, fault(step, id) {
            if (step === 'sync' && id === A) return { changed: false, complete: false, sessionsTerminated: 0 };
        } });
        f.pending = releasedIntent(f, 'delete');
        blockedHost(f, A);
        await assert.rejects(f.service[action]({ login }), error => {
            assert.equal(error.code, code('OUTCOME_UNKNOWN').code);
            assert.equal(error.retryAllowed, false);
            if (matching) {
                assert.equal(error.confirmedSessionsTerminated, 2);
                assert.equal(error.sessionsTerminatedScope, 'request');
            } else {
                assert.equal(Object.hasOwn(error, 'confirmedSessionsTerminated'), false);
                assert.equal(Object.hasOwn(error, 'sessionsTerminatedScope'), false);
            }
            return true;
        });
        assert.deepEqual(recoveryEffects(f), [...fencePass, `sync:${A}`, `sync:${B}`]);
        assert.ok(f.pending);
        assert.deepEqual(f.sessions[B], [bootstrap, neighbor]);
    }
});

test('final readback showing a surviving target prevents publication even after checked sync', async () => {
    const f = fixture({ shared: true, fault(step, id, state) {
        if (step === 'inspect' && id === B && state.events.includes(`sync:${B}`)) state.sessions[B].push(credentials.login);
    } });
    f.pending = releasedIntent(f, 'delete');
    blockedHost(f, A);
    await assert.rejects(f.service.reconcile(), { ...code('OUTCOME_UNKNOWN'), uncertainNodeId: B,
        retryAllowed: false, confirmedSessionsTerminated: 3, confirmedNodeIds: [A] });
    assert.ok(f.pending);
    assert.deepEqual(recoveryEffects(f), [...fencePass, `sync:${A}`, `sync:${B}`, ...reads]);
});

for (const [name, change] of [
    ['different owner', f => { f.pending.intentId = 'aaaaaaaa-bbbb-4ccc-8ddd-fffffffffffe'; }],
    ['changed record under the same owner', f => { f.pending.createdAt = new Date(1); }],
    ['directory drift', f => { f.directory.generation = 'changed'; }],
    ['account metadata drift', f => { f.users[0].comment = 'changed'; }],
]) {
    test(`${name} at the transactional snapshot prevents recovery publication`, async () => {
        const f = fixture({ shared: true, fault(step, _, state) { if (step === 'publish') change(state); } });
        f.pending = releasedIntent(f, 'delete');
        f.directory = { generation: 'original', accounts: f.users.filter(u => u.relayNode === A) };
        for (const id of [A, B]) { blockedHost(f, id); f.sessions[id] = []; }
        await assert.rejects(f.service.reconcile(), { ...code('FINISH_UNKNOWN'), retryAllowed: false });
        assert.ok(f.pending && f.users.filter(u => u.login === credentials.login).length === 2);
        assert.ok(!f.events.includes('settle'));
    });
}

for (const [name, change] of [
    ['extra top-level field', f => { f.pending.extra = true; }],
    ['extra network field', f => { f.pending.relays[0].network.extra = true; }],
    ['unknown operation', f => { f.pending.action = 'constructor'; }],
    ['missing cohort member', f => { f.pending.relays.pop(); }],
    ['duplicate cohort member', f => { f.pending.relays[1] = f.pending.relays[0]; }],
    ['wrong SSH pin', f => { f.pending.relays[0].sshHostKeySha256 = '5'.repeat(64); }],
    ['wrong IP', f => { f.pending.relays[0].ip = ip(0, 12); }],
    ['wrong revision', f => { f.pending.relays[0].revision = 1; }],
    ['malformed escrow', f => { f.pending.passwordEncrypted = 'not-an-envelope'; }],
    ['escrow cannot authenticate', f => { f.pending.passwordEncrypted = encrypt(credentials.password, 'wrong-fixture-key'); }],
]) {
    test(`${name} in an intent refuses before opening DIRECT`, async () => {
        const f = fixture();
        f.pending = releasedIntent(f, 'create');
        change(f);
        const before = structuredClone(f.pending);
        await assert.rejects(f.service.reconcile(), { ...code('BLOCKED'), retryAllowed: false });
        assert.equal(equal(f.pending, before), true);
        assert.deepEqual(recoveryEffects(f), []);
        assert.ok(!f.events.some(e => e.startsWith('connect:')));
    });
}

for (const capability of ['inspectChap', 'fenceChap']) {
    test(`missing ${capability} cannot fall back to ordinary check or clear pending`, async () => {
        const f = fixture({ shared: true });
        f.pending = releasedIntent(f, 'delete');
        const factory = f.deps.createRelayDirect;
        f.deps.createRelayDirect = params => {
            const remote = factory(params);
            delete remote[capability];
            return remote;
        };
        await assert.rejects(f.restart().delete(credentials), code('BLOCKED'));
        assert.deepEqual(recoveryEffects(f), []);
        assert.ok(f.pending);
    });
}

test('unexpected create session count or impossible both projection blocks recovery', async () => {
    for (const receipt of [{ projection: 'original', activeTargetSessions: 1 }, { projection: 'both', activeTargetSessions: 0 }]) {
        const f = fixture({ fault(step, id) { if (step === 'inspect' && id === B) return receipt; } });
        f.pending = releasedIntent(f, 'create');
        await assert.rejects(f.service.reconcile(), code('BLOCKED'));
        assert.ok(f.pending);
        assert.deepEqual(recoveryEffects(f), [`inspect:${A}`, `inspect:${B}`]);
    }
});

test('unrelated mutation must check hosts anew after settling the prior intent', async () => {
    const f = fixture({ shared: true, other: true, fault(step, id) { if (step === 'check' && id === B) return false; } });
    f.pending = releasedIntent(f, 'delete');
    for (const id of [A, B]) { blockedHost(f, id); f.sessions[id] = [bootstrap, neighbor]; }
    await assert.rejects(f.service.disable({ login: neighbor }), code('PREFLIGHT_REFUSED'));
    assert.equal(f.pending, undefined);
    assert.deepEqual(recoveryEffects(f), [...fencePass, ...reads, 'publish', `check:${A}`, `check:${B}`]);
    assert.ok(f.users.filter(u => u.login === neighbor).every(u => u.enabled));
});

test('create with the same login but a different password does not claim the recovered outcome', async () => {
    const f = fixture();
    f.pending = releasedIntent(f, 'create');
    for (const [i, id] of [A, B].entries()) f.hosts[id].push({ ...credentials, ipAddress: ip(i, 11), enabled: true });
    await assert.rejects(f.service.create({ ...credentials, password: 'different-fixture-only' }), code('ACCOUNT_CONFLICT'));
    assert.equal(f.pending, undefined);
    assert.ok(f.users.filter(u => u.login === credentials.login).every(u => u.passwordEncrypted === sharedCipher));
    assert.deepEqual(recoveryEffects(f), [...fencePass, ...reads, 'publish']);
});

test('Apply ownership loss during the cohort inspection prevents any convergence', async () => {
    let lost = false;
    const f = fixture({ shared: true, fault(step, id) {
        if (step === 'inspect' && id === B) lost = true;
        if (step === 'lock' && lost) return false;
    } });
    f.pending = releasedIntent(f, 'delete');
    blockedHost(f, B);
    await assert.rejects(f.service.reconcile(), { ...code('BLOCKED'), retryAllowed: false });
    assert.ok(f.pending);
    assert.deepEqual(recoveryEffects(f), [`inspect:${A}`, `inspect:${B}`]);
    assert.ok([A, B].every(id => f.events.includes(`close:${id}`)));
});

test('lost cancellation acknowledgement blocks the unrelated request even if cancellation landed', async () => {
    const f = fixture({ shared: true, other: true, fault(step) { if (step === 'cancel-ack') throw Error('unknown cancel'); } });
    f.pending = releasedIntent(f, 'delete');
    await assert.rejects(f.service.disable({ login: neighbor }), { ...code('FINISH_UNKNOWN'), retryAllowed: false });
    assert.deepEqual(recoveryEffects(f), [...fencePass, 'cancel']);
    assert.ok([A, B].every(id => f.events.indexOf(`close:${id}`) < f.events.indexOf('cancel')));
    assert.equal(f.pending, undefined);
});
