'use strict';

// Opt in with a disposable loopback-only replica set in a private netns.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { networkInterfaces } = require('node:os');
const mongoose = require('mongoose');
const { createRelayGrantStore } = require('../rebuildRelayGrantStore');
const { resolveRelayBinding } = require('../rebuildRelayAuthorization');

const port = process.env.C3_GRANT_FIXTURE_PORT;
const local = { skip: !port && 'Requires a private loopback MongoDB replica-set fixture' };
const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true' };
const binding = n => ({ nodeId: n.repeat(24), host: `relay-${n}.invalid`, port: 22, username: 'root',
    machineId: n.repeat(32), sshHostKeySha256: n.repeat(64) });
const grantsName = 'c3_rebuild_l2tp_relay_grants', auditName = 'c3_rebuild_l2tp_relay_grant_audit';

async function fixture(t, config = env) {
    assert.match(port, /^\d{4,5}$/);
    assert.ok(Number(port) >= 1024 && Number(port) <= 65535);
    assert.deepEqual(Object.keys(networkInterfaces()), ['lo']);
    const db = mongoose.createConnection(`mongodb://127.0.0.1:${port}/?directConnection=true`, {
        dbName: `c3_grant_fixture_${randomUUID().replaceAll('-', '')}`, serverSelectionTimeoutMS: 2000,
    });
    t.after(async () => { try { if (db.readyState === 1) await db.dropDatabase(); } finally { await db.close(); } });
    await db.asPromise();
    const hello = await db.db.admin().command({ hello: 1 });
    assert.ok(hello.setName);
    assert.equal(hello.isWritablePrimary, true);
    assert.deepEqual(hello.hosts, [`127.0.0.1:${port}`]);
    const store = createRelayGrantStore({ db, env: config });
    const mutate = (binding, action = 'grant', expectedGeneration = null) =>
        store.mutate({ action, binding, expectedGeneration, actor: 'fixture-admin' });
    return { db, store, mutate, grants: db.collection(grantsName), audit: db.collection(auditName) };
}

for (const [field, duplicate] of Object.entries({
    nodeId: a => ({ nodeId: a.nodeId }), machineId: a => ({ machineId: a.machineId }),
    sshHostKeySha256: a => ({ sshHostKeySha256: a.sshHostKeySha256 }), endpoint: () => ({ host: '::ffff:c000:219' }),
})) {
    test(`real MongoDB rejects a concurrent ${field} collision and records only the winner`, local, async t => {
        const f = await fixture(t);
        const a = { ...binding('a'), host: '192.0.2.25' };
        const b = { ...binding('b'), ...duplicate(a) };
        const results = await Promise.allSettled([f.mutate(a), f.mutate(b)]);
        assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
        const [{ reason }] = results.filter(result => result.status === 'rejected');
        assert.equal(reason.code, 'REBUILD_L2TP_GRANT_CONFLICT');
        assert.equal(reason.field, field);
        const indexes = await f.grants.indexes();
        assert.deepEqual(indexes.filter(i => i.unique).map(i => Object.entries(i.key)).sort(), [
            [['nodeId', 1]], [['machineId', 1]], [['sshHostKeySha256', 1]], [['host', 1], ['port', 1]],
        ].sort());
        assert.equal(await f.grants.countDocuments(), 1);
        assert.equal(await f.audit.countDocuments({ action: 'grant', outcome: 'success' }), 1);
    });
}

test('real MongoDB joins legacy ObjectId inventory and aborts grant changes with failed audit', local, async t => {
    const a = binding('a'), b = binding('b');
    const config = { ...env, C3_REBUILD_L2TP_RELAY_ID: a.nodeId, C3_REBUILD_L2TP_RELAY_MACHINE_ID: a.machineId,
        C3_REBUILD_L2TP_SSH_SHA256: a.sshHostKeySha256 };
    const f = await fixture(t, config);
    await f.db.collection('hynodes').insertOne({ _id: new mongoose.Types.ObjectId(a.nodeId), ip: a.host,
        ssh: { username: a.username, port: a.port, password: 'unused-fixture-value' } });
    const first = await f.mutate(b);
    const restored = createRelayGrantStore({ db: f.db, env: config });
    const joined = await restored.snapshot();
    assert.equal(joined.sourceFor(a.nodeId), 'env');
    assert.equal(joined.sourceFor(b.nodeId), 'db');
    assert.deepEqual(resolveRelayBinding(joined.env, a.nodeId), a);
    const stub = t.mock.method(f.audit, 'insertOne', async (_, { session }) => {
        assert.ok(session.inTransaction());
        assert.equal(await f.grants.countDocuments({ nodeId: b.nodeId }, { session }), 0);
        throw new Error('modeled audit write failure after real transactional delete');
    });
    await assert.rejects(f.mutate(b, 'revoke', first.generation), { code: 'REBUILD_L2TP_GRANT_PERSISTENCE_UNAVAILABLE' });
    assert.equal(stub.mock.callCount(), 1);
    stub.mock.restore();
    assert.equal((await restored.snapshot()).grants[0].generation, first.generation);
    assert.equal(await f.audit.countDocuments(), 1);
    await f.mutate(b, 'revoke', first.generation);
    assert.deepEqual((await restored.snapshot()).grants, []);
    assert.equal(await f.audit.countDocuments(), 2);
});
