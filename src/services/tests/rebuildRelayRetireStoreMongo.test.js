'use strict';

// Opt in only against a fresh replica set in a private loopback-only netns.
const test = require('node:test');
const assert = require('node:assert/strict');
const { networkInterfaces } = require('node:os');
const { randomUUID } = require('node:crypto');
const mongoose = require('mongoose');
const { ObjectId } = mongoose.Types;
const { BSON } = mongoose.mongo;
const { createRetireStore } = require('../rebuildRelayRetireStore');
const { createRelayGrantStore, GRANTS, RETIRED } = require('../rebuildRelayGrantStore');
const { resolveRelayBinding, relayListKey } = require('../rebuildRelayAuthorization');
const { transactOnce } = require('../rebuildRelayInstallTransaction');
const { makeLocks, withNode } = require('../rebuildLocks');
const { collectionName: DIRECTORY } = require('../rebuildRelayDirectory');
const Node = require('../../models/hyNodeModel');
const HyUser = require('../../models/hyUserModel');
const Link = require('../../models/cascadeLinkModel');
const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
const L2tpUser = require('../../modules/relay-l2tp/models/l2tpUserModel');
const { inactiveClassicRelay, operations } = require('./helpers/rebuildRelayClassicLifecycleFixture');
const port = process.env.C3_RETIRE_FIXTURE_PORT;
const db = mongoose.connection;
const id = n => new ObjectId(String(n).repeat(24));
const binding = n => ({ nodeId: String(id(n)), host: `192.0.2.${n}`, port: 22, username: 'root',
    machineId: String(n).repeat(32), sshHostKeySha256: String(n).repeat(64) });
const a = id(1), b = id(2), x = id(3);
const ref = { $or: [{ portalNode: a }, { bridgeNode: a }] };

async function fixture(t, authority = 'db') {
    assert.match(port, /^\d{4,5}$/);
    assert.deepEqual(Object.keys(networkInterfaces()), ['lo']);
    await mongoose.connect(`mongodb://127.0.0.1:${port}/?directConnection=true`, {
        dbName: `retire_fixture_${randomUUID().replaceAll('-', '')}`, serverSelectionTimeoutMS: 2000,
        monitorCommands: true, autoIndex: false, autoCreate: false,
    });
    t.after(async () => { try { await db.dropDatabase(); } finally { await mongoose.disconnect(); } });
    const hello = await db.db.admin().command({ hello: 1 });
    assert.equal(hello.isWritablePrimary, true);
    assert.deepEqual(hello.hosts, [`127.0.0.1:${port}`]);
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true' };
    if (authority === 'legacy') Object.assign(env, { C3_REBUILD_L2TP_RELAY_ID: String(a),
        C3_REBUILD_L2TP_RELAY_MACHINE_ID: binding(1).machineId, C3_REBUILD_L2TP_SSH_SHA256: binding(1).sshHostKeySha256 });
    if (authority === 'list') env[relayListKey] = JSON.stringify([binding(1)]);
    const grantStore = createRelayGrantStore({ db, env });
    const grant = value => grantStore.mutate({ action: 'grant', binding: value, actor: 'fixture-operator' });
    const directory = db.collection(DIRECTORY), grants = db.collection(GRANTS), retired = db.collection(RETIRED);
    await db.createCollection(Node.collection.name, { collation: { locale: 'en', strength: 2 } });
    await Node.collection.insertMany([1, 2, 3].map(n => ({ _id: id(n), ip: binding(n).host, type: 'xray',
        active: true, cascadeRole: 'relay', groups: [b, x], ssh: { port: new BSON.Int32(22), username: 'root' },
        xray: { agentToken: 'fixture-agent', extraInbounds: [{ port: 443, inboundTag: 'fixture-extra' }] },
        hiddenFixture: { marker: 1 } })));
    await grant(binding(2));
    if (authority === 'db') await grant(binding(1));
    await Link.collection.insertMany([
        { _id: id(4), portalNode: a, bridgeNode: b, active: false, rebuildDelete: true },
        { _id: id(5), portalNode: b, bridgeNode: a, active: true },
        { _id: id(6), portalNode: x, bridgeNode: b, active: true },
    ]);
    await State.collection.insertMany([1, 2].map(n => ({ _id: id(n), node: id(n), status: 'installed', desiredState: 'installed',
        routingMode: 'follow-relay', routingVersion: 1, rebuildMachineId: binding(n).machineId, rebuildInstallToken: randomUUID(),
        backupId: binding(n).machineId, secretRevision: 1, pskEncrypted: 'fixture-envelope', installedAt: new Date(1),
        clientCidr: `10.200.${n}.0/24`, localAddress: `10.200.${n}.1`, poolStart: `10.200.${n}.10`, poolEnd: `10.200.${n}.20` })));
    await L2tpUser.collection.insertMany([1, 2].flatMap(n => ['relay-bootstrap', 'disabled'].map((login, i) => ({
        _id: new ObjectId(String(n).repeat(23) + i), relayNode: id(n), login, enabled: i === 0,
        passwordEncrypted: `fixture-envelope-${i}`, ip: `10.200.${n}.${10+i}`, syncStatus: 'synced', desiredRevision: 1, appliedRevision: 1,
    }))));
    await HyUser.collection.insertMany([{ _id: a, nodes: [b, a, String(a), a] }, { _id: b, nodes: [b, x] }]);
    const store = createRetireStore({ Link, Node, State, L2tpUser, env });
    const lock = makeLocks(db.collection('c3_rebuild_locks'));
    const underLock = fn => lock.run(verify => withNode(String(a), () => fn(verify)));
    const snapshotAll = async session => {
        const out = [];
        for (const coll of [Link.collection, Node.collection, State.collection, L2tpUser.collection, HyUser.collection, grants, directory, retired]) {
            out.push(await coll.find({}, { session, sort: { _id: 1 } }).toArray());
        }
        return out;
    };
    const removeLinks = async session => {
        const result = await Link.collection.deleteMany(ref, { session });
        assert.equal(result.deletedCount, 2);
    };
    return { env, store, grantStore, grant, directory, grants, retired, snapshotAll, underLock, removeLinks };
}

const run = (name, fn, authority) => test(name, { skip: !port }, async t => fn(await fixture(t, authority), t));

run('node capture and delete ignore health and non-authority siblings', async f => {
    const telemetry = { updatedAt: new Date(2), lastSync: new Date(3), agentLastSeen: new Date(4),
        status: 'offline', agentStatus: 'offline', xrayVersion: 'fixture-version', agentVersion: 'fixture-version',
        onlineUsers: 5, maxOnlineUsers: 5, healthFailures: 2, lastError: 'fixture-health', 'traffic.tx': 5,
        'xray.accessLogs.lastBatchAt': new Date(5), 'xray.accessLogs.spoolBytes': 5,
        'xray.accessLogs.status': 'degraded', 'xray.accessLogs.lastError': 'fixture-log',
        'hiddenFixture.marker': 2, 'ssh.unrelated': 2, 'xray.unrelated': 2, 'xray.extraInbounds.0.unrelated': 2 };
    await Node.collection.updateOne({ _id: a }, { $set: { 'ssh.password': '$fixture-literal', 'xray.manualKey': { $ne: 'fixture' } } });
    await f.underLock(async verify => {
        const snap = await f.store.capture(a);
        await Node.collection.updateOne({ _id: a }, { $set: telemetry });
        assert.equal(f.store.sameSnapshot(snap, await f.store.capture(a)), true);
        await transactOnce(State, L2tpUser, async session => {
            await f.removeLinks(session);
            await f.store.finish(snap, session, verify);
        });
    });
    assert.equal(await Node.collection.findOne({ _id: a }), null);
});

run('node snapshot binds authority leaves, not merely the SSH and agent endpoints', async f => {
    const fields = {
        name: 'renamed', role: 'bridge', active: false, ip: '192.0.2.90', domain: 'fixture.invalid', sni: 'fixture.invalid', port: 444,
        useCustomConfig: true, groups: [x, b], aclRules: ['reject(fixture.invalid)'],
        'ssh.port': 23, 'ssh.username': 'fixture', 'ssh.password': 'fixture-pw', 'ssh.privateKey': 'fixture-key',
        'xray.agentToken': 'fixture-other', 'xray.agentPort': 62081, 'xray.agentTls': false, 'xray.apiPort': 61001,
        'xray.accessLogs.enabled': true, 'xray.accessLogs.ingestTokenEncrypted': 'fixture-envelope',
        'xray.accessLogs.appliedFingerprint': 'fixture-config', 'xray.accessLogs.ingestTokenHash': 'fixture-hash', 'xray.inboundTag': 'fixture-in',
        'xray.transport': 'grpc', 'xray.security': 'tls', 'xray.flow': 'fixture-flow', 'xray.alpn': ['h2'],
        'xray.tlsSource': 'manual', 'xray.manualCert': 'fixture-cert', 'xray.manualKey': 'fixture-pem',
        'xray.realityPrivateKey': 'fixture-private', 'xray.realityPublicKey': 'fixture-public',
        'xray.realityShortIds': ['01'], 'xray.wsPath': '/fixture', 'xray.xhttpMode': 'auto',
        'xray.extraInbounds.0.port': 445, 'xray.extraInbounds.0.inboundTag': 'fixture-edit',
        'xray.extraInbounds.0.realityPublicKey': 'fixture-extra-public',
    };
    await f.underLock(async () => {
        await Node.collection.updateOne({ _id: a }, { $set: { 'xray.accessLogs.status': 'active' } });
        const original = await Node.collection.findOne({ _id: a }, { promoteValues: false });
        const snap = await f.store.capture(a);
        for (const [path, value] of Object.entries(fields)) {
            await Node.collection.updateOne({ _id: a }, { $set: { [path]: value } });
            assert.equal(f.store.sameSnapshot(snap, await f.store.capture(a)), false, path);
            await Node.collection.replaceOne({ _id: a }, original);
        }
        await Node.collection.updateOne({ _id: a }, { $set: { 'ssh.password': null } });
        assert.equal(f.store.sameSnapshot(snap, await f.store.capture(a)), false, 'missing is not null');
    });
});

run('the actual node delete predicate refuses late BSON and collation drift, aborting all writes', async (f, t) => {
    const cases = {
        arrayInsteadOfScalar: { 'ssh.username': ['root'] },
        wrongElementOrder: { groups: [x, b] },
        missingToNull: { 'ssh.password': null },
        equalNumericValue: { 'ssh.port': new BSON.Double(22) },
        equalNestedNumericValue: { 'xray.extraInbounds.0.port': new BSON.Double(443) },
        sameCaseFold: { 'xray.agentToken': 'FIXTURE-AGENT' },
        operatorLookingValue: { 'ssh.username': { $ne: 'fixture' } },
    };
    const original = await f.snapshotAll();
    const deleteOne = Node.collection.deleteOne.bind(Node.collection);
    for (const [kind, fields] of Object.entries(cases)) {
        let entered = false, missed = false;
        const mock = t.mock.method(Node.collection, 'deleteOne', async (filter, { session, ...opts }) => {
            entered = true;
            // Mutate only this fixture's own staged node after the final projected
            // read, so the real Mongo predicate (not an earlier compare) must miss.
            await Node.collection.updateOne({ _id: a }, { $unset: Object.fromEntries(Object.keys(fields).map(key => [key, ''])) }, { session });
            await Node.collection.updateOne({ _id: a }, { $set: fields }, { session });
            const deleted = await deleteOne(filter, { session, ...opts });
            missed = deleted.acknowledged === true && deleted.deletedCount === 0;
            return deleted;
        });
        try {
            await f.underLock(async verify => {
                const snap = await f.store.capture(a);
                await assert.rejects(transactOnce(State, L2tpUser, async session => {
                    await f.removeLinks(session);
                    await f.store.finish(snap, session, verify);
                }), { code: 'REBUILD_NODE_RETIRE_CHANGED' });
            });
            assert.ok(entered && missed, kind);
            assert.deepEqual(await f.snapshotAll(), original, kind);
        } finally { mock.mock.restore(); }
    }
});

run('real Mongo atomically retires graph and relay rows and backfills the agreeing directory', async f => {
    const outside = await f.snapshotAll();
    await f.underLock(async verify => {
        const snap = await f.store.capture(a);
        assert.ok(Object.isFrozen(snap));
        assert.equal(JSON.stringify(snap), '{}');
        assert.ok(f.store.sameSnapshot(snap, await f.store.capture(a)));
        await assert.rejects(f.store.finish(snap, undefined, verify), { code: 'REBUILD_NODE_RETIRE_UNAVAILABLE' });
        await transactOnce(State, L2tpUser, async session => {
            await f.removeLinks(session);
            await f.store.finish(snap, session, verify);
            assert.deepEqual(await f.snapshotAll(), outside, 'independent read sees the entire preimage before commit');
        });
        assert.equal(f.store.sameSnapshot(snap, await f.store.capture(b)), false);
    });
    const after = await f.snapshotAll();
    assert.deepEqual(after, [outside[0].slice(2), outside[1].slice(1), outside[2].slice(1), outside[3].slice(2),
        [{ _id: a, nodes: [b] }, outside[4][1]], outside[5].filter(row => row.nodeId === String(b)), after[6], [{ _id: String(a) }]]);
    const [directory] = after[6];
    assert.deepEqual(directory.accounts, outside[3].slice(0, 2).reverse().map(row => ({ id: String(row._id), login: row.login,
        enabled: row.enabled, passwordEncrypted: row.passwordEncrypted })));
    assert.equal((await f.grantStore.snapshot()).sourceFor(String(b)), 'db');
    await assert.rejects(f.grant(binding(1)), { code: 'REBUILD_L2TP_GRANT_CHANGED' });
    const replacement = { ...binding(3), host: binding(1).host, port: binding(1).port };
    await f.grant(replacement);
    assert.deepEqual(resolveRelayBinding((await f.grantStore.snapshot()).env, replacement.nodeId), replacement);
});

run('late verifier failure rolls back real Mongo link, directory, state, accounts, grant and node mutations', async f => {
    const original = await f.snapshotAll();
    const commands = [];
    db.getClient().on('commandStarted', ({ commandName, command }) => {
        if (['delete', 'insert', 'update'].includes(commandName) && command.autocommit === false) commands.push(command);
    });
    await f.underLock(async verify => {
        const snap = await f.store.capture(a);
        let calls = 0;
        await assert.rejects(transactOnce(State, L2tpUser, async session => {
            await f.removeLinks(session);
            await f.store.finish(snap, session, async () => {
                await verify();
                if (++calls !== 3) return;
                const staged = await f.snapshotAll(session);
                assert.deepEqual(staged.slice(0, 4), [original[0].slice(2), original[1].slice(1), original[2].slice(1), original[3].slice(2)]);
                assert.deepEqual(staged[4][0].nodes, [b]);
                assert.equal(staged[5].some(row => row.nodeId === String(a)), false);
                assert.equal(staged[6][0].accounts.length, 2);
                assert.deepEqual(staged[7], [{ _id: String(a) }]);
                return false;
            });
        }), { code: 'REBUILD_LOCK_LOST' });
        assert.equal(calls, 3);
    });
    assert.deepEqual(await f.snapshotAll(), original);
    assert.equal(new Set(commands.map(c => c.insert ?? c.update ?? c.delete)).size, 8);
    for (const command of commands) {
        assert.deepEqual(command.txnNumber, commands[0].txnNumber);
        assert.deepEqual(command.lsid, commands[0].lsid);
    }
});

for (const authority of ['legacy', 'list']) {
    run(`retired ${authority} ENV binding does not invalidate the other grant or reserve the old endpoint`, async f => {
        const catalog = await f.directory.insertOne({ _id: 'directory', version: 1, generation: randomUUID(), accounts:
            (await L2tpUser.collection.find({ relayNode: a }).toArray()).map(row => ({ id: String(row._id), login: row.login,
                enabled: row.enabled, passwordEncrypted: row.passwordEncrypted })) });
        const original = await f.directory.findOne({ _id: catalog.insertedId });
        await f.underLock(async verify => {
            const snap = await f.store.capture(a);
            await transactOnce(State, L2tpUser, async session => {
                await f.removeLinks(session);
                await f.store.finish(snap, session, verify);
            });
        });
        assert.deepEqual(await f.directory.findOne({ _id: catalog.insertedId }), original);
        const replacement = { ...binding(3), host: binding(1).host };
        if (authority === 'list') f.env[relayListKey] = JSON.stringify([binding(1), replacement]);
        else await f.grant(replacement);
        const restarted = await createRelayGrantStore({ db, env: { ...f.env } }).snapshot();
        assert.equal(restarted.sourceFor(String(a)), null);
        assert.equal(restarted.sourceFor(String(b)), 'db');
        assert.deepEqual(resolveRelayBinding(restarted.env, String(x)), replacement);
    }, authority);
}

run('finish rejects untouched tombstones, foreign capabilities and exact BSON drift without publishing', async f => {
    await f.underLock(async verify => {
        const snap = await f.store.capture(a);
        await assert.rejects(transactOnce(State, L2tpUser, session => f.store.finish(snap, session, verify)), { code: 'REBUILD_NODE_HAS_LINKS' });
        const next = await f.store.capture(a);
        await State.collection.updateOne({ node: a }, { $set: { unseenField: 'changed' } });
        assert.equal(f.store.sameSnapshot(next, await f.store.capture(a)), false);
        const expected = await f.snapshotAll();
        await assert.rejects(transactOnce(State, L2tpUser, async session => {
            await f.removeLinks(session);
            await assert.rejects(f.store.finish(Object.freeze({}), session, verify), { code: 'REBUILD_NODE_RETIRE_UNAVAILABLE' });
            await f.store.finish(next, session, verify);
        }), { code: 'REBUILD_NODE_RETIRE_CHANGED' });
        assert.deepEqual(await f.snapshotAll(), expected);
    });
});

run('capture refuses conflicting legacy ciphertext without changing graph or directory', async f => {
    await L2tpUser.collection.updateOne({ relayNode: b, login: 'disabled' }, { $set: { passwordEncrypted: 'foreign-envelope' } });
    const expected = await f.snapshotAll();
    await f.underLock(() => assert.rejects(f.store.capture(a), { code: 'REBUILD_L2TP_ACCOUNT_SOURCE_CONFLICT' }));
    assert.deepEqual(await f.snapshotAll(), expected);
});

for (const running of [false, true]) run(running
    ? '#13 raw Retire aborts if the classic reference is running at transactional recheck'
    : '#13 raw Retire backfills the directory in one transaction without mutating the inactive classic neighbor', async f => {
    const { state, operation } = inactiveClassicRelay(x, '10.200.1');
    const operationStore = db.collection(operations);
    await Node.collection.updateOne({ _id: x }, { $set: { active: false } });
    await State.collection.insertOne(state);
    await operationStore.insertOne(operation);
    assert.equal(await f.directory.findOne({ _id: 'directory' }), null);
    const neighborBytes = async () => Promise.all([
        Node.collection.findOne({ _id: x }, { raw: true }),
        State.collection.findOne({ _id: state._id }, { raw: true }),
        operationStore.findOne({ _id: operation._id }, { raw: true }),
    ]);
    const inTxn = [], ends = [];
    db.getClient().on('commandStarted', ({ commandName, command }) => {
        if (command.autocommit !== false) return;
        if (['commitTransaction', 'abortTransaction'].includes(commandName)) ends.push(commandName);
        inTxn.push({ commandName, command });
    });
    await f.underLock(async verify => {
        const snapshot = await f.store.capture(a);
        if (running) await operationStore.updateOne({ _id: operation._id }, {
            $set: { status: 'running' }, $unset: { finishedAt: '' },
        });
        const before = await f.snapshotAll(), classicBefore = await neighborBytes();
        const retire = () => transactOnce(State, L2tpUser, async session => {
            await f.removeLinks(session);
            await f.store.finish(snapshot, session, verify);
            assert.deepEqual(await f.snapshotAll(), before, 'independent read still sees the preimage before commit');
        });
        if (running) {
            await assert.rejects(retire, { code: 'REBUILD_L2TP_ACCOUNT_SOURCE_BUSY' });
            assert.deepEqual(await f.snapshotAll(), before);
            assert.deepEqual(ends, ['abortTransaction']);
        } else {
            await retire();
            assert.deepEqual(ends, ['commitTransaction']);
            assert.equal(await Node.collection.findOne({ _id: a }), null);
            assert.equal(await State.collection.findOne({ node: a }), null);
            assert.equal(await L2tpUser.collection.countDocuments({ relayNode: a }), 0);
            assert.equal(await f.grants.findOne({ nodeId: String(a) }), null);
            assert.deepEqual(await f.retired.findOne({ _id: String(a) }), { _id: String(a) });
            assert.deepEqual((await f.directory.findOne({ _id: 'directory' })).accounts,
                before[3].filter(row => row.relayNode.equals(a)).toSorted((l, r) => l.login.localeCompare(r.login)).map(row => ({
                    id: String(row._id), login: row.login, enabled: row.enabled, passwordEncrypted: row.passwordEncrypted,
                })));
        }
        assert.deepEqual(await neighborBytes(), classicBefore);
    });
    assert.ok(inTxn.some(({ command }) => command.find === operations || command.aggregate === operations),
        'classic operation is read in the same transaction, not only at capture');
    assert.ok(inTxn.every(({ command }) => ![command.insert, command.update, command.delete, command.findAndModify].includes(operations)));
    for (const { command } of inTxn) {
        assert.deepEqual(command.lsid, inTxn[0].command.lsid);
        assert.deepEqual(command.txnNumber, inTxn[0].command.txnNumber);
    }
});

run('retiring the last DB grant cannot downgrade a different installed legacy ENV singleton', async f => {
    const expected = await f.snapshotAll();
    await f.underLock(() => assert.rejects(f.store.capture(b), { code: 'REBUILD_L2TP_GRANT_LEGACY_SINGLETON_IN_USE' }));
    assert.deepEqual(await f.snapshotAll(), expected);
}, 'legacy');
