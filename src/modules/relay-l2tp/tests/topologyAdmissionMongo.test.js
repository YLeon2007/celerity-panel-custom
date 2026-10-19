'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const mongoose = require('mongoose');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');

const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to an isolated local MongoDB binary' };
const databaseName = `topology_admission_${randomUUID().replaceAll('-', '')}`;
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
    assert.match(databaseName, /^topology_admission_[a-f0-9]{32}$/);
    assert.ok(process.env.TMPDIR, 'Use the configured local scratch directory');
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-topology-admission-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => {
            const selected = server.address().port;
            server.close(() => resolve(selected));
        });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port),
        '--bind_ip', '127.0.0.1', '--replSet', 'topologyAdmissionScratch',
        '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const uri = `mongodb://127.0.0.1:${port}/${databaseName}?directConnection=true`;
    const client = new mongoose.mongo.MongoClient(uri, { serverSelectionTimeoutMS: 100 });
    try {
        await until(() => client.connect());
        await client.db('admin').command({ replSetInitiate: { _id: 'topologyAdmissionScratch',
            members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
        assert.equal((await client.db('admin').admin().listDatabases()).databases
            .some(database => database.name === databaseName), false);
    } finally {
        await client.close();
    }
    connection = await mongoose.createConnection(uri).asPromise();
    const sources = {
        HyNode: require('../../../models/hyNodeModel'),
        CascadeLink: require('../../../models/cascadeLinkModel'),
        CascadeRouteGroup: require('../models/cascadeRouteGroupModel'),
        RelayL2tpState: require('../models/relayL2tpStateModel'),
        CascadeTopologyState: require('../models/cascadeTopologyStateModel'),
        TopologyOperation: require('../models/topologyOperationModel'),
    };
    models = Object.fromEntries(Object.entries(sources).map(([name, model]) =>
        [name, connection.model(name, model.schema)]));
    await Promise.all(Object.values(models).map(model => model.init()));
});

test.after(async () => {
    try {
        if (connection) {
            try {
                assert.match(connection.name, /^topology_admission_[a-f0-9]{32}$/);
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
    // Raw insert preserves legacy missing fields: schema defaults cannot repair this fixture.
    await models.CascadeTopologyState.collection.insertOne({ _id: 'singleton', revision: 7,
        deployedRevision: 5, topologyAdmissionCount: 0, remoteAdmissionCount: 0, ...overrides });
}

function admission({ expectedRevision = 7, beforeCas = async () => {} } = {}) {
    const repository = new TopologyDeploymentRepository({ ...models,
        snapshotReader: new TopologyDraftRepository(models) });
    const calls = { prepare: 0, createOperation: 0, remote: 0 };
    const operationId = new mongoose.Types.ObjectId();
    return { calls, operationId, async run() {
        const result = await repository.admitTopology({ expectedRevision,
            async prepare(snapshot, session) {
                calls.prepare++;
                await models.HyNode.collection.insertOne({ _id: new mongoose.Types.ObjectId(),
                    name: 'transaction-only-preparation' }, { session });
                await beforeCas(snapshot, session);
                return { prepared: true };
            },
            async admit(pinned, session) {
                calls.createOperation++;
                await models.TopologyOperation.create([{ _id: operationId,
                    idempotencyKey: `local-admission:${operationId}`, topologyRevision: pinned.revision,
                    priorDeployedRevision: pinned.deployedRevision, status: 'queued',
                    heldTopologyAdmission: true, nodes: [],
                    executionContext: { target: 'test', hostIdentity: 'test.infograd.online' },
                }], { session });
            },
        });
        // Local executor sentinel: rejected transactions must never reach dispatch.
        calls.remote++;
        return result;
    } };
}

async function rejectsWithoutEffects(candidate, before, code = 'TOPOLOGY_ADMISSION_UNAVAILABLE') {
    await assert.rejects(candidate.run(), { code });
    assert.equal(candidate.calls.createOperation, 0, 'no operation creation callback');
    assert.equal(candidate.calls.remote, 0, 'no external executor invocation');
    assert.equal(await models.TopologyOperation.countDocuments(), 0);
    assert.equal(await models.HyNode.countDocuments(), 0, 'preparation writes roll back');
    assert.deepEqual(await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' }),
        typeof before === 'function' ? before() : before);
}

test('foreign remote drain rejects actual transactional admission without effects', local, async () => {
    await reset({ remoteDrain: { ownerToken: 'foreign-drain', epoch: 4 } });
    const before = await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' });
    await rejectsWithoutEffects(admission(), before);
});

test('active remote admissions reject actual transactional admission without effects', local, async () => {
    await reset({ remoteAdmissionCount: 2 });
    const before = await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' });
    await rejectsWithoutEffects(admission(), before);
});

test('legacy missing remote counter stays missing and rejects admission', local, async () => {
    await reset();
    await models.CascadeTopologyState.collection.updateOne({ _id: 'singleton' }, { $unset: { remoteAdmissionCount: '' } });
    const before = await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' });
    assert.equal(Object.hasOwn(before, 'remoteAdmissionCount'), false);
    await rejectsWithoutEffects(admission(), before);
});

test('missing singleton at revision zero is never upserted by admission', local, async () => {
    await reset();
    await models.CascadeTopologyState.deleteMany({});
    const candidate = admission({ expectedRevision: 0 });
    await rejectsWithoutEffects(candidate, null);
    assert.equal(candidate.calls.prepare, 1, 'missing singleton reaches the real no-upsert CAS');
    assert.equal(await models.CascadeTopologyState.countDocuments(), 0);
});

test('legacy missing topology counter stays missing and rejects admission', local, async () => {
    await reset();
    await models.CascadeTopologyState.collection.updateOne({ _id: 'singleton' }, { $unset: { topologyAdmissionCount: '' } });
    const before = await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' });
    assert.equal(Object.hasOwn(before, 'topologyAdmissionCount'), false);
    await rejectsWithoutEffects(admission(), before);
});

test('nonzero or invalid counters and present malformed fences fail closed', local, async t => {
    for (const [label, overrides] of [
        ['negative remote count', { remoteAdmissionCount: -1 }],
        ['fractional remote count', { remoteAdmissionCount: 0.5 }],
        ['null remote count', { remoteAdmissionCount: null }],
        ['string remote count', { remoteAdmissionCount: '0' }],
        ['active topology count', { topologyAdmissionCount: 1 }],
        ['null drain', { remoteDrain: null }],
        ['empty drain', { remoteDrain: {} }],
        ['null replacement reservation', { replacementReservation: null }],
    ]) await t.test(label, async () => {
        await reset(overrides);
        const before = await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' });
        await rejectsWithoutEffects(admission(), before);
    });
});

test('held replacement reservation rejects admission before preparation', local, async () => {
    await reset({ replacementReservation: { ownerToken: 'foreign-replacement', epoch: 8 } });
    const before = await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' });
    const candidate = admission();
    await rejectsWithoutEffects(candidate, before, 'TOPOLOGY_REPLACEMENT_RESERVED');
    assert.equal(candidate.calls.prepare, 0);
});

for (const [label, update] of [
    ['remote drain', { $set: { remoteDrain: { ownerToken: 'race-winner', epoch: 9 } } }],
    ['remote admission count', { $inc: { remoteAdmissionCount: 2 } }],
    ['replacement reservation', { $set: { replacementReservation: { ownerToken: 'race-winner', epoch: 9 } } }],
]) test(`${label} committed after snapshot defeats the actual admission CAS`, { ...local, timeout: 20000 }, async () => {
    await reset();
    let winningState;
    let won = false;
    const candidate = admission({ async beforeCas(snapshot, losingSession) {
        assert.equal(snapshot.revision, 7);
        assert.equal(losingSession.inTransaction(), true);
        if (won) return;
        won = true;
        await connection.transaction(async winningSession => {
            assert.notStrictEqual(winningSession, losingSession);
            const result = await models.CascadeTopologyState.collection.updateOne({ _id: 'singleton',
                revision: 7, topologyAdmissionCount: 0, remoteAdmissionCount: 0,
                remoteDrain: { $exists: false }, replacementReservation: { $exists: false },
            }, update, { session: winningSession });
            assert.equal(result.matchedCount, 1);
        });
        winningState = await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' });
    } });
    await rejectsWithoutEffects(candidate, () => winningState,
        label === 'replacement reservation' ? 'TOPOLOGY_REPLACEMENT_RESERVED' : 'TOPOLOGY_ADMISSION_UNAVAILABLE');
    assert.equal(won, true);
    if (label !== 'replacement reservation') {
        assert.equal(candidate.calls.prepare, 2, 'write conflict retries the snapshot, then the new gate rejects');
    }
});

test('initialized quiescent TEST singleton commits one counted frozen operation', local, async () => {
    await reset();
    const candidate = admission();
    assert.deepEqual(await candidate.run(), { revision: 7, deployedRevision: 5, prepared: true });
    assert.deepEqual(candidate.calls, { prepare: 1, createOperation: 1, remote: 1 });
    const state = await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' });
    assert.equal(state.topologyAdmissionCount, 1);
    assert.equal(state.remoteAdmissionCount, 0);
    assert.equal(state.revision, 7);
    const operation = await models.TopologyOperation.findById(candidate.operationId).lean();
    assert.equal(operation.status, 'queued');
    assert.equal(operation.heldTopologyAdmission, true);
    assert.deepEqual(operation.executionContext, { target: 'test', hostIdentity: 'test.infograd.online' });
    assert.equal(await models.HyNode.countDocuments(), 1, 'successful preparation commits in the same transaction');
    const successor = admission();
    await assert.rejects(successor.run(), { code: 'TOPOLOGY_ADMISSION_UNAVAILABLE' });
    assert.deepEqual(successor.calls, { prepare: 1, createOperation: 0, remote: 0 });
    assert.equal(await models.TopologyOperation.countDocuments(), 1, 'existing operation is preserved');
    assert.equal(await models.HyNode.countDocuments(), 1, 'rejected successor preparation rolls back');
    assert.deepEqual(await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' }), state);
});
