'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const mongoose = require('mongoose');
const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');
const { L2tpService } = require('../services/l2tpService');
const { L2tpOperationWorker } = require('../workers/l2tpOperationWorker');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');

const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to an isolated local MongoDB binary' };
const databaseName = `inverse_admission_${randomUUID().replaceAll('-', '')}`;
const nodeId = '507f1f77bcf86cd799439011';
const operationId = '507f1f77bcf86cd799439012';
const now = new Date('2026-10-19T09:00:00Z');
let connection, child, directory, models;

async function until(work) {
    let lastError;
    for (let attempt = 0; attempt < 100; attempt++) {
        try { return await work(); } catch (error) { lastError = error; }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw lastError;
}

test.before(async () => {
    if (!process.env.C3_MONGOD) return;
    assert.match(databaseName, /^inverse_admission_[a-f0-9]{32}$/);
    assert.ok(process.env.TMPDIR, 'Use the configured local scratch directory');
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-inverse-admission-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => {
            const selected = server.address().port;
            server.close(() => resolve(selected));
        });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port),
        '--bind_ip', '127.0.0.1', '--replSet', 'inverseAdmissionScratch',
        '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const uri = `mongodb://127.0.0.1:${port}/${databaseName}?directConnection=true`;
    const client = new mongoose.mongo.MongoClient(uri, { serverSelectionTimeoutMS: 100 });
    try {
        await until(() => client.connect());
        await client.db('admin').command({ replSetInitiate: { _id: 'inverseAdmissionScratch',
            members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
        assert.equal((await client.db('admin').admin().listDatabases()).databases
            .some(database => database.name === databaseName), false);
    } finally {
        await client.close();
    }
    connection = await mongoose.createConnection(uri).asPromise();
    const sources = {
        CascadeTopologyState: require('../models/cascadeTopologyStateModel'),
        RemoteAdmission: require('../models/remoteAdmissionModel'),
        L2tpOperation: require('../models/l2tpOperationModel'),
        NodeOperationLock: require('../models/nodeOperationLockModel'),
    };
    models = Object.fromEntries(Object.entries(sources).map(([name, model]) =>
        [name, connection.model(name, model.schema)]));
    await Promise.all(Object.values(models).map(model => model.init()));
});

test.after(async () => {
    try {
        if (connection) {
            try {
                assert.match(connection.name, /^inverse_admission_[a-f0-9]{32}$/);
                assert.equal(connection.name, databaseName);
                await connection.dropDatabase();
                assert.equal((await connection.db.admin().listDatabases()).databases
                    .some(database => database.name === databaseName), false, 'scratch database was removed');
            } finally {
                await connection.close();
            }
        }
    } finally {
        if (child && child.exitCode === null) {
            const exited = new Promise(resolve => child.once('exit', resolve));
            child.kill('SIGTERM');
            await exited;
        }
        if (directory) await fs.rm(directory, { recursive: true, force: true });
    }
});

async function reset(overrides = {}) {
    for (const model of Object.values(models)) await model.deleteMany({});
    // Raw persistence is intentional: no defaults/backfill may repair legacy counters.
    await models.CascadeTopologyState.collection.insertOne({ _id: 'singleton', revision: 7,
        topologyAdmissionCount: 0, remoteAdmissionCount: 0, ...overrides });
    await models.L2tpOperation.create({ _id: operationId, node: nodeId, kind: 'sync_users',
        executionContext: TEST, status: 'queued', attempts: 0, idempotencyKey: 'sync-users-test',
        plan: { ok: true, operationId, relayId: nodeId, desired: { credentialRevision: 1 },
            steps: [{ type: 'backup' }, { type: 'sync_users',
                artifacts: [{ type: 'desired', path: 'desired.json' }] }, { type: 'verify_users' }] },
    });
    // Existing unrelated durable ownership history must survive every rejection unchanged.
    await models.RemoteAdmission.create({ _id: 'foreign-admission', nodeId: 'other-node',
        kind: 'sync_users', phase: 'completed', operationId: 'foreign-operation',
        ownerGeneration: 4, leaseOwner: 'foreign-owner' });
}

async function snapshot() {
    return {
        gate: await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' }),
        operations: await models.L2tpOperation.collection.find().sort({ _id: 1 }).toArray(),
        admissions: await models.RemoteAdmission.collection.find().sort({ _id: 1 }).toArray(),
        locks: await models.NodeOperationLock.collection.find().sort({ _id: 1 }).toArray(),
    };
}

function candidate(kind, beforeCas = async () => {}) {
    const calls = { gate: 0, operationClaim: 0, admissionCreate: 0, remote: 0 };
    // Wrap only the real model boundaries; every query/write still executes on Mongo.
    let gateSession;
    const CascadeTopologyState = Object.create(models.CascadeTopologyState);
    CascadeTopologyState.updateOne = async (filter, update, options) => {
        calls.gate++;
        gateSession = options.session;
        assert.equal(options.session.inTransaction(), true);
        assert.equal(options.upsert, undefined, 'admission must never initialize the singleton');
        await beforeCas(options.session);
        return models.CascadeTopologyState.updateOne(filter, update, options);
    };
    const L2tpOperation = Object.create(models.L2tpOperation);
    L2tpOperation.updateOne = (...args) => {
        calls.operationClaim++;
        assert.strictEqual(args[2].session, gateSession, 'operation claim shares singleton transaction');
        return models.L2tpOperation.updateOne(...args);
    };
    const RemoteAdmission = Object.create(models.RemoteAdmission);
    RemoteAdmission.create = (...args) => {
        calls.admissionCreate++;
        assert.strictEqual(args[1].session, gateSession, 'admission insert shares singleton transaction');
        return models.RemoteAdmission.create(...args);
    };
    const repository = new RemoteAdmissionRepository({ ...models,
        CascadeTopologyState, L2tpOperation, RemoteAdmission });
    return { calls, repository, async run() {
        const result = kind === 'sync_users'
            ? await repository.claimQueuedSyncUsers({ owner: 'worker', leaseMs: 30000, now, executionContext: TEST })
            : await repository[kind === 'install' ? 'acquireInstall' : 'acquire']({ nodeId });
        // Local dispatch sentinel, never a transport or a remote write.
        if (result) calls.remote++;
        return result;
    } };
}

async function rejectsWithoutEffects(kind, before, probe = candidate(kind)) {
    if (kind === 'sync_users') assert.equal(await probe.run(), null);
    else await assert.rejects(probe.run(), { code: 'REMOTE_ADMISSION_BLOCKED' });
    assert.equal(probe.calls.operationClaim, 0, 'no operation/lease/generation CAS');
    assert.equal(probe.calls.admissionCreate, 0, 'no admission creation');
    assert.equal(probe.calls.remote, 0, 'no dispatch');
    assert.deepEqual(await snapshot(), before, 'counts, leases and existing admissions stay unchanged');
}

for (const kind of ['sync_users', 'standalone_preflight', 'install']) {
    for (const value of [1, 2, -1, 0.5, null, '0', 'missing']) {
        test(`${kind} rejects persisted topology counter ${JSON.stringify(value)} without claiming`, local, async () => {
            await reset({ topologyAdmissionCount: value });
            if (value === 'missing') await models.CascadeTopologyState.collection.updateOne(
                { _id: 'singleton' }, { $unset: { topologyAdmissionCount: '' } });
            await rejectsWithoutEffects(kind, await snapshot());
        });
    }
}

test('sync_users racing topology CAS loses its snapshot transaction before claim or dispatch', local, async () => {
    await reset();
    let won = false;
    let winner;
    const probe = candidate('sync_users', async losingSession => {
        if (won) return;
        won = true;
        await connection.transaction(async session => {
            assert.notStrictEqual(session, losingSession);
            const changed = await models.CascadeTopologyState.collection.updateOne({ _id: 'singleton',
                topologyAdmissionCount: 0, remoteAdmissionCount: 0,
                remoteDrain: { $exists: false }, replacementReservation: { $exists: false },
            }, { $inc: { topologyAdmissionCount: 1 } }, { session });
            assert.equal(changed.matchedCount, 1);
        });
        winner = await snapshot();
    });
    // One-shot sync claims surface write conflicts rather than retrying counted work.
    await assert.rejects(probe.run(), error => error.code === 112 && typeof error.admissionId === 'string');
    assert.equal(won, true);
    assert.equal(probe.calls.gate, 1);
    assert.equal(probe.calls.operationClaim, 0);
    assert.equal(probe.calls.admissionCreate, 0);
    assert.equal(probe.calls.remote, 0);
    assert.deepEqual(await snapshot(), winner);
    await rejectsWithoutEffects('sync_users', winner);
});

test('initialized TEST sync_users creates one counted admission and one exact operation claim', local, async () => {
    await reset();
    const probe = candidate('sync_users');
    const result = await probe.run();
    assert.equal(result.status, 'running');
    assert.equal(result.attempts, 1);
    assert.equal(result.ownerGeneration, 1);
    assert.equal(result.leaseOwner, 'worker');
    assert.deepEqual(result.leaseUntil, new Date(now.getTime() + 30000));
    const after = await snapshot();
    assert.equal(after.gate.topologyAdmissionCount, 0);
    assert.equal(after.gate.remoteAdmissionCount, 1);
    assert.equal(after.operations[0].admissionId, result.admissionId);
    assert.equal(after.operations[0].ownerGeneration, 1);
    assert.equal(after.admissions.filter(row => row._id === result.admissionId).length, 1);
    assert.deepEqual(probe.calls, { gate: 1, operationClaim: 1, admissionCreate: 1, remote: 1 });
});

for (const kind of ['standalone_preflight', 'install']) {
    test(`${kind} racing topology CAS retries and refuses before admission or dispatch`, local, async () => {
        await reset();
        let won = false;
        let winner;
        const probe = candidate(kind, async losingSession => {
            if (won) return;
            won = true;
            await connection.transaction(async session => {
                assert.notStrictEqual(session, losingSession);
                const changed = await models.CascadeTopologyState.collection.updateOne({ _id: 'singleton',
                    topologyAdmissionCount: 0, remoteAdmissionCount: 0,
                    remoteDrain: { $exists: false }, replacementReservation: { $exists: false },
                }, { $inc: { topologyAdmissionCount: 1 } }, { session });
                assert.equal(changed.matchedCount, 1);
            });
            winner = await snapshot();
        });
        await assert.rejects(probe.run(), { code: 'REMOTE_ADMISSION_BLOCKED' });
        assert.equal(won, true);
        assert.equal(probe.calls.gate, 2, 'real write conflict retries with a fresh snapshot');
        assert.equal(probe.calls.operationClaim, 0);
        assert.equal(probe.calls.admissionCreate, 0);
        assert.equal(probe.calls.remote, 0);
        assert.deepEqual(await snapshot(), winner);
    });

    test(`initialized TEST ${kind} acquires and releases exactly once without changing queued work`, local, async () => {
        await reset();
        const before = await snapshot();
        const probe = candidate(kind);
        const id = await probe.run();
        const after = await snapshot();
        assert.equal(after.gate.remoteAdmissionCount, 1);
        assert.equal(after.gate.topologyAdmissionCount, 0);
        assert.deepEqual(after.operations, before.operations);
        const record = after.admissions.find(row => row._id === id);
        assert.equal(record.kind, kind);
        assert.equal(record.phase, 'running');
        assert.equal(record.ownerGeneration, 1);
        assert.deepEqual(probe.calls, { gate: 1, operationClaim: 0, admissionCreate: 1, remote: 1 });
        await probe.repository.release(id);
        assert.equal((await snapshot()).gate.remoteAdmissionCount, 0);
        assert.equal((await models.RemoteAdmission.collection.findOne({ _id: id })).phase, 'completed');
        await assert.rejects(probe.repository.release(id), { code: 'REMOTE_ADMISSION_NOT_ACTIVE' });
        assert.equal((await snapshot()).gate.remoteAdmissionCount, 0);
    });
}

for (const kind of ['sync_users', 'standalone_preflight', 'install']) {
    for (const condition of ['missing singleton', 'missing remote counter', 'drain', 'replacement']) {
        test(`${kind} retains existing ${condition} exclusion without repair`, local, async () => {
            await reset();
            if (condition === 'missing singleton') await models.CascadeTopologyState.deleteMany({});
            else await models.CascadeTopologyState.collection.updateOne({ _id: 'singleton' },
                condition === 'missing remote counter' ? { $unset: { remoteAdmissionCount: '' } }
                    : { $set: { [condition === 'drain' ? 'remoteDrain' : 'replacementReservation']:
                        { ownerToken: 'foreign-owner', epoch: 8 } } });
            await rejectsWithoutEffects(kind, await snapshot());
        });
    }
}

for (const topologyAdmissionCount of [1, 'missing']) {
    test(`actual preflight service refuses topology ${topologyAdmissionCount} before node lock or runner`, local, async () => {
        await reset({ topologyAdmissionCount });
        if (topologyAdmissionCount === 'missing') await models.CascadeTopologyState.collection.updateOne(
            { _id: 'singleton' }, { $unset: { topologyAdmissionCount: '' } });
        const before = await snapshot();
        const probe = candidate('standalone_preflight');
        let lockCalls = 0, remoteCalls = 0;
        const service = new L2tpService({ executionContext: TEST,
            remoteAdmissionRepository: probe.repository,
            nodeRepository: { async findById() { return { id: nodeId, role: 'relay' }; } },
            stateRepository: {
                async findByNodeId() { return { desiredState: 'installed' }; },
                async findRouteGroupById() { return { id: 'group' }; },
                async getTopologyRevision() { return 7; },
                async getRelayGroupPlan() { return { relayId: nodeId }; },
            },
            lockService: { async acquire() { lockCalls++; throw new Error('unexpected node lock'); },
                async releaseVerified() { throw new Error('unexpected release'); } },
            async preflightRunner() { remoteCalls++; throw new Error('unexpected transport'); },
        });
        await assert.rejects(service.preflight(nodeId, { routeGroupId: 'group', expectedTopologyRevision: 7 }),
            { code: 'REMOTE_ADMISSION_BLOCKED' });
        assert.equal(lockCalls, 0);
        assert.equal(remoteCalls, 0);
        assert.equal(probe.calls.admissionCreate, 0);
        assert.deepEqual(await snapshot(), before);
    });

    test(`actual sync worker refuses topology ${topologyAdmissionCount} before lock, secrets or executor`, local, async () => {
        await reset({ topologyAdmissionCount });
        if (topologyAdmissionCount === 'missing') await models.CascadeTopologyState.collection.updateOne(
            { _id: 'singleton' }, { $unset: { topologyAdmissionCount: '' } });
        const before = await snapshot();
        const probe = candidate('sync_users');
        let lockCalls = 0, remoteCalls = 0, secretCalls = 0;
        const worker = new L2tpOperationWorker({ executionContext: TEST,
            enableUnsafeExecutionForTests: true, remoteAdmissionRepository: probe.repository,
            lockService: { async acquire() { lockCalls++; throw new Error('unexpected node lock'); } },
            executor: {
                async executeStep() { remoteCalls++; throw new Error('unexpected executor'); },
                async rollback() { remoteCalls++; throw new Error('unexpected rollback'); },
            },
            async secretResolver() { secretCalls++; throw new Error('unexpected secrets'); },
            async userSnapshotResolver() { secretCalls++; throw new Error('unexpected user snapshot'); },
            workerId: 'worker', leaseMs: 30000, clock: { now: () => now },
        });
        worker.nextClaimKind = 'sync_users';
        assert.deepEqual(await worker.runClaimedOperation(() => assert.fail('unexpected operation claim')),
            { claimed: false });
        assert.deepEqual([lockCalls, remoteCalls, secretCalls], [0, 0, 0]);
        assert.equal(probe.calls.operationClaim, 0);
        assert.equal(probe.calls.admissionCreate, 0);
        assert.deepEqual(await snapshot(), before);
    });
}
