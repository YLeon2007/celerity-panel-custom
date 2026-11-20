'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
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
const ip = (i, end) => `10.255.${16 + i}.${end}`;
const code = suffix => ({ code: `REBUILD_L2TP_ACCOUNTS_${suffix}` });

function fixture({ shared = false, single = false, legacy = false, disabled = false, fault = () => {} } = {}) {
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
    let pending, held = false;
    const f = { rows, users, hosts, events, env, get pending() { return pending; } };
    const step = (name, id) => { assert.equal(held, true); events.push(id ? `${name}:${id}` : name); return fault(name, id, f); };
    const store = {
        async assertNoPending() { step('gate'); if (pending) throw accountError('BLOCKED'); },
        async states() { step('inventory'); return structuredClone(rows.map(r => r.state).reverse()); },
        async inventory(ids, login) {
            step('read');
            return structuredClone({ nodes: rows.map(r => r.node),
                users: users.filter(u => ids.includes(u.relayNode) || u.login === login) });
        },
        async begin(intent) { step('intent'); assert.equal(pending, undefined); pending = structuredClone(intent); await step('intent-ack'); },
        async verifyIntent(intentId) { step('own'); assert.equal(intentId, pending.intentId); },
        async publish({ intentId, action, changes, recheck, verifyAuthority }) {
            step('publish'); await recheck();
            assert.equal(intentId, pending.intentId);
            await verifyAuthority();
            step('settle');
            for (const { before, after } of changes) {
                if (action === 'create') users.push({ _id: `${after.relayNode}:${after.login}`, ...after });
                else if (action === 'delete') users.splice(users.findIndex(u => u._id === before._id), 1);
                else Object.assign(users.find(u => u._id === before._id), after);
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
            const check = (install, current) => {
                assert.equal(install.nodeId, id);
                assert.deepEqual(Object.keys(install.network).sort(), ['clientCidr', 'fwmark', 'routeTable', 'tproxyPort']);
                assert.deepEqual(current, hosts[id]);
            };
            return {
                async checkChap(install, current, desired, verifyLock) {
                    await verifyLock(); check(install, current);
                    assert.ok(Array.isArray(desired));
                    return step('check', id) ?? { changed: !disabled };
                },
                async syncChap(install, current, desired, verifyLock) {
                    await verifyLock(); check(install, current);
                    assert.ok(pending);
                    const result = step('sync', id);
                    if (result === undefined) hosts[id] = structuredClone(desired);
                    return result ?? { changed: true };
                },
                async close() { step('close', id); },
            };
        },
    };
    f.service = createRebuildRelayAccounts(deps);
    f.restart = () => createRebuildRelayAccounts(deps);
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

test('legacy singleton already-disabled account still allows a verified read-only no-op', async () => {
    const f = fixture({ single: true, legacy: true, shared: true, disabled: true });
    assert.deepEqual(await f.service.disable({ login: credentials.login }),
        { executionMode: 'rebuild', status: 'disabled', login: credentials.login, relayCount: 1 });
    assert.deepEqual(effects(f), [`check:${A}`]);
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
            { executionMode: 'rebuild', status, login: credentials.login, relayCount: 2 });
        assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent', `sync:${A}`, `sync:${B}`, 'publish', 'settle']);
        assert.equal(f.pending, undefined);
        assert.deepEqual(f.users.filter(u => u.login === bootstrap), before);
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

test('preflight refusal on B leaves both hosts and persistence unchanged', async () => {
    const f = fixture({ fault: (step, id) => step === 'check' && id === B ? false : undefined });
    const before = structuredClone(f.hosts);
    await assert.rejects(f.service.create(credentials), { ...code('PREFLIGHT_REFUSED'), nodeId: B });
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`]);
    assert.deepEqual(f.hosts, before);
    assert.equal(f.pending, undefined);
    assert.ok([A, B].every(id => f.events.includes(`close:${id}`)));
});

test('timeout on B after A: leaves durable intent, no DB publication or rollback, refuses fresh caller', async () => {
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
    await assert.rejects(f.restart().delete({ login: 'other' }), code('BLOCKED'));
    assert.deepEqual(f.events.slice(end), ['lock', 'gate']);
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent', `sync:${A}`, `sync:${B}`]);
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

test('intent acknowledgement loss never dispatches, a committed intent still blocks', async () => {
    const f = fixture({ fault(step) { if (step === 'intent-ack') throw Error('ack lost'); } });
    await assert.rejects(f.service.create(credentials), { ...code('INTENT_UNKNOWN'), retryAllowed: false });
    assert.ok(f.pending);
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent']);
    await assert.rejects(f.restart().create(credentials), code('BLOCKED'));
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

test('publication CAS loss retains the intent and never publishes or rolls back hosts', async () => {
    const f = fixture({ fault(step) { if (step === 'settle') throw Error('settlement conflict'); } });
    await assert.rejects(f.service.create(credentials), { ...code('FINISH_UNKNOWN'), retryAllowed: false, confirmedNodeIds: [A, B] });
    assert.ok(f.pending);
    assert.deepEqual(f.users.map(u => u.login), [bootstrap, bootstrap]);
    await assert.rejects(f.restart().create(credentials), code('BLOCKED'));
    assert.deepEqual(effects(f), [`check:${A}`, `check:${B}`, 'intent', `sync:${A}`, `sync:${B}`, 'publish', 'settle']);
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
