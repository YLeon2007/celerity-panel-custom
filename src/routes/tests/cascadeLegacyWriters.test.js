'use strict';

// Isolated local Mongo only; never connect to the configured panel database.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');
const express = require('express');
const { registerModels } = require('../../modules/relay-l2tp');
const CascadeLink = require('../../models/cascadeLinkModel');
const HyNode = require('../../models/hyNodeModel');
const cascadeService = require('../../services/cascadeService');
const cache = require('../../services/cacheService');
const { manageCascade, getTopology } = require('../../mcp/tools/cascade');
const ids = ['507f1f77bcf86cd799439031', '507f1f77bcf86cd799439032'];
const linkId = '507f1f77bcf86cd799439021';
const operationId = '507f1f77bcf86cd799439041';
const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to a local isolated MongoDB binary' };
let models, directory, child, remoteCalls, cacheCalls;
const originalUndeploy = cascadeService.undeployLink;
const originalInvalidate = cache.invalidateAllSubscriptions;
async function until(work) {
    let error;
    for (let i = 0; i < 150; i++) {
        try { return await work(); } catch (e) { error = e; }
        await new Promise(resolve => setTimeout(resolve, 40));
    }
    throw error;
}
test.before(async () => {
    if (!process.env.C3_MONGOD) return;
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-legacy-writers-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(() => resolve(port)); });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', 'legacyScratch', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const uri = `mongodb://127.0.0.1:${port}/legacy_writers_scratch?directConnection=true`;
    const client = new mongoose.mongo.MongoClient(uri, { serverSelectionTimeoutMS: 100 });
    await until(() => client.connect());
    await client.db('admin').command({ replSetInitiate: { _id: 'legacyScratch', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
    await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    await client.close();
    await mongoose.connect(uri);
    models = { ...registerModels(), HyNode, CascadeLink };
    await Promise.all(Object.values(models).map(model => model.init()));
    cache.invalidateAllSubscriptions = async () => { cacheCalls++; };
});
test.after(async () => {
    require('../../services/sshPoolService').closeAll();
    cascadeService.undeployLink = originalUndeploy;
    cache.invalidateAllSubscriptions = originalInvalidate;
    await mongoose.disconnect();
    if (child && child.exitCode === null) {
        const exited = new Promise(resolve => child.once('exit', resolve));
        child.kill('SIGTERM'); await exited;
    }
    if (directory) await fs.rm(directory, { recursive: true, force: true });
});
async function reset({ count = 0, operation = false } = {}) {
    for (const model of Object.values(models)) await model.deleteMany({});
    await models.CascadeTopologyState.create({ _id: 'singleton', revision: 7, deployedRevision: 5,
        topologyAdmissionCount: count, remoteAdmissionCount: 0 });
    await HyNode.collection.insertMany(ids.map((_id, i) => ({ _id: new mongoose.Types.ObjectId(_id),
        name: `node-${i}`, type: 'xray', active: true, cascadeRole: i ? 'bridge' : 'portal', ip: `192.0.2.${i + 1}` })));
    await CascadeLink.create({ _id: linkId, name: 'original', portalNode: ids[0], bridgeNode: ids[1],
        tunnelUuid: 'local-only', tunnelPort: 10086, mode: 'forward', active: true, status: 'online' });
    if (operation) {
        await models.TopologyOperation.collection.insertOne({ _id: new mongoose.Types.ObjectId(operationId),
            status: 'committing', topologyRevision: 7, priorDeployedRevision: 5, heldTopologyAdmission: true,
            admissionFingerprint: 'a'.repeat(64), kind: 'link.apply', linkId, linkIds: [linkId] });
        if (count > 0) {
            await models.TopologyCreateIntent.collection.insertOne({ requestKey: 'bound', payloadHash: 'b'.repeat(64),
                status: 'admitted', ordinal: 1, operationId: new mongoose.Types.ObjectId(operationId),
                topologyRevision: 7, priorDeployedRevision: 5, admissionFingerprint: 'a'.repeat(64) });
            await models.TopologyIntentQueueState.create({ _id: 'create-v1', outstanding: 1, ordinal: 1 });
        }
    }
    remoteCalls = 0; cacheCalls = 0;
    cascadeService.undeployLink = async () => { remoteCalls++; };
}
async function httpUndeploy(body = {}) {
    // Fresh limiter per local request; the deployed middleware is unchanged.
    delete require.cache[require.resolve('../cascade')];
    const router = require('../cascade');
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    app.use(router);
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}/links/${linkId}/undeploy`, {
            method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
        });
        return { status: response.status, body: await response.json() };
    } finally { await new Promise(resolve => server.close(resolve)); }
}

test('MCP topology exposes the exact revision needed for a draft CAS', local, async () => {
    await reset();
    const topology = await getTopology();
    assert.equal(topology.topologyRevision, 7);
    assert.equal(topology.deployedRevision, 5);
});

test('MCP update rejects a frozen active operation without changing draft metadata', local, async () => {
    await reset({ count: 1, operation: true });
    await assert.rejects(manageCascade({ action: 'update', id: linkId, expectedTopologyRevision: 7,
        data: { name: 'bypassed' } }, () => {}), { code: 'TOPOLOGY_DEPLOY_BUSY' });
    assert.equal((await CascadeLink.findById(linkId).lean()).name, 'original');
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 1);
    assert.equal(cacheCalls, 0);
    assert.equal(remoteCalls, 0);
});

test('legacy HTTP undeploy rejects active queue-bound work before any external teardown or deletion', local, async () => {
    await reset({ count: 1, operation: true });
    const operation = await models.TopologyOperation.findById(operationId).lean();
    const before = await models.CascadeTopologyState.findById('singleton').lean();
    const intent = await models.TopologyCreateIntent.findOne({ requestKey: 'bound' }).lean();
    const queue = await models.TopologyIntentQueueState.findById('create-v1').lean();
    const response = await httpUndeploy();
    assert.equal(response.status, 409);
    assert.equal(response.body.error.code, 'LEGACY_CASCADE_UNDEPLOY_BUSY');
    assert.equal(remoteCalls, 0);
    assert.equal(cacheCalls, 0);
    assert.deepEqual(await models.CascadeTopologyState.findById('singleton').lean(), before);
    assert.deepEqual(await models.TopologyOperation.findById(operationId).lean(), operation);
    assert.deepEqual(await models.TopologyCreateIntent.findOne({ requestKey: 'bound' }).lean(), intent);
    assert.deepEqual(await models.TopologyIntentQueueState.findById('create-v1').lean(), queue);
});

for (const action of ['create', 'delete']) {
    test(`MCP ${action} rejects a counted active operation`, local, async () => {
        await reset({ count: 1, operation: true });
        await assert.rejects(manageCascade({ action, id: linkId, expectedTopologyRevision: 7,
            data: { name: 'blocked', portalNodeId: ids[0], bridgeNodeId: ids[1], tunnelPort: 10087 } }, () => {}),
        { code: 'TOPOLOGY_DEPLOY_BUSY' });
        assert.equal(await CascadeLink.countDocuments(), 1);
        assert.equal((await CascadeLink.findById(linkId).lean()).name, 'original');
        assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 7);
        assert.equal(cacheCalls, 0);
    });
}

test('MCP quiescent create/update/delete uses exact revisions without node effects', local, async () => {
    await reset();
    const created = await manageCascade({ action: 'create', expectedTopologyRevision: 7,
        data: { name: 'draft', portalNodeId: ids[0], bridgeNodeId: ids[1], tunnelPort: 10087, mode: 'forward' } }, () => {});
    assert.equal(created.topologyRevision, 8);
    const id = String(created.link._id);
    const updated = await manageCascade({ action: 'update', id, expectedTopologyRevision: 8, data: { priority: 11 } }, () => {});
    assert.equal(updated.topologyRevision, 9);
    assert.equal(updated.link.priority, 11);
    await assert.rejects(manageCascade({ action: 'update', id, expectedTopologyRevision: 8,
        data: { name: 'stale' } }, () => {}), { code: 'STALE_TOPOLOGY_REVISION' });
    const removed = await manageCascade({ action: 'delete', id, expectedTopologyRevision: 9 }, () => {});
    assert.equal(removed.topologyRevision, 10);
    assert.equal(await CascadeLink.findById(id), null);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).deployedRevision, 5);
    assert.equal(cacheCalls, 3);
    assert.equal(remoteCalls, 0);
});

test('MCP draft writes require an explicit revision rather than inferring the current one', local, async () => {
    await reset();
    for (const action of ['create', 'update', 'delete']) {
        await assert.rejects(manageCascade({ action, id: linkId, data: { name: 'unguarded' } }, () => {}),
            { code: 'INVALID_TOPOLOGY_REVISION' });
    }
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 7);
    assert.equal((await CascadeLink.findById(linkId).lean()).name, 'original');
    assert.equal(cacheCalls, 0);
});

test('legacy MCP undeploy shares the HTTP active-operation fence', local, async () => {
    await reset({ count: 1, operation: true });
    const progress = [];
    await assert.rejects(manageCascade({ action: 'undeploy', id: linkId }, (...args) => progress.push(args)),
        { code: 'LEGACY_CASCADE_UNDEPLOY_BUSY' });
    assert.equal(remoteCalls, 0);
    assert.equal(progress.length, 0);
    assert.equal(await models.TopologyOperation.countDocuments(), 1);
});

test('quiescent HTTP undeploy owns the fence across teardown and preserves operation history', local, async () => {
    await reset({ operation: true });
    await models.TopologyOperation.updateOne({ _id: operationId }, { $set: { status: 'succeeded', heldTopologyAdmission: false } });
    const operation = await models.TopologyOperation.findById(operationId).lean();
    cascadeService.undeployLink = async link => {
        remoteCalls++;
        assert.equal(String(link._id), linkId);
        const owned = await models.CascadeTopologyState.findById('singleton').lean();
        assert.equal(owned.revision, 8);
        assert.equal(owned.deployedRevision, 0);
        assert.match(owned.replacementReservation.ownerToken, /^legacy-undeploy:/);
        assert.equal(owned.replacementReservation.epoch, owned.replacementEpoch);
        await assert.rejects(manageCascade({ action: 'update', id: linkId, expectedTopologyRevision: 8,
            data: { name: 'raced' } }, () => {}), { code: 'TOPOLOGY_REPLACEMENT_RESERVED' });
        const { TopologyDeploymentRepository } = require('../../modules/relay-l2tp/repositories/topologyDeploymentRepository');
        const repo = new TopologyDeploymentRepository({ ...models,
            snapshotReader: { ...models, readDraft: async session => models.CascadeTopologyState.findById('singleton').session(session).lean() } });
        await assert.rejects(repo.admitTopology({ expectedRevision: 8, prepare: async () => ({}),
            admit: async () => assert.fail('cannot admit while teardown owns the topology') }), { code: 'TOPOLOGY_REPLACEMENT_RESERVED' });
        const denied = await httpUndeploy();
        assert.equal(denied.status, 409);
    };
    const response = await httpUndeploy();
    assert.equal(response.status, 200);
    assert.equal(remoteCalls, 1);
    assert.equal(cacheCalls, 1);
    const state = await models.CascadeTopologyState.findById('singleton').lean();
    assert.equal(state.revision, 8);
    assert.equal(state.deployedRevision, 0);
    assert.equal(state.topologyAdmissionCount, 0);
    assert.equal(state.replacementReservation, undefined);
    assert.equal(state.replacementEpoch, 1);
    assert.deepEqual(await models.TopologyOperation.findById(operationId).lean(), operation);
});

for (const [name, setup] of [
    ['uncounted active operation', async () => models.TopologyOperation.collection.insertOne({ status: 'queued', topologyRevision: 6 })],
    ['terminal operation retaining admission', async () => models.TopologyOperation.collection.insertOne({ status: 'failed', topologyRevision: 7, heldTopologyAdmission: true })],
    ['waiting intent', async () => models.TopologyCreateIntent.collection.insertOne({ requestKey: 'waiting', status: 'waiting', ordinal: 1 })],
    ['outstanding queue count without an intent', async () => models.TopologyIntentQueueState.create({ _id: 'create-v1', outstanding: 1, ordinal: 1 })],
    ['missing admission counter', async () => models.CascadeTopologyState.collection.updateOne({ _id: 'singleton' }, { $unset: { topologyAdmissionCount: '' } })],
    ['missing remote counter', async () => models.CascadeTopologyState.collection.updateOne({ _id: 'singleton' }, { $unset: { remoteAdmissionCount: '' } })],
    ['active remote admission', async () => models.CascadeTopologyState.updateOne({ _id: 'singleton' }, { $set: { remoteAdmissionCount: 1 } })],
    ['foreign reservation', async () => models.CascadeTopologyState.updateOne({ _id: 'singleton' }, { $set: { replacementReservation: { ownerToken: 'foreign', epoch: 3 } } })],
    ['remote drain', async () => models.CascadeTopologyState.updateOne({ _id: 'singleton' }, { $set: { remoteDrain: { ownerToken: 'drainer', epoch: 1 } } })],
    ['orphan node lock', async () => models.NodeOperationLock.collection.insertOne({ node: new mongoose.Types.ObjectId(ids[0]), ownerToken: 'foreign' })],
]) {
    test(`legacy undeploy rejects ${name} without mutation or remote calls`, local, async () => {
        await reset(); await setup();
        const before = await models.CascadeTopologyState.findById('singleton').lean();
        const response = await httpUndeploy();
        assert.equal(response.status, 409);
        assert.equal(remoteCalls, 0);
        assert.equal(cacheCalls, 0);
        assert.deepEqual(await models.CascadeTopologyState.findById('singleton').lean(), before);
    });
}

// The competing admission writes the real singleton outside the pending
// transaction, forcing Mongo write-conflict rollback/retry, not a mock CAS.
async function raceAdmission(work) {
    const State = models.CascadeTopologyState;
    const original = State.findOneAndUpdate;
    let raced = false;
    State.findOneAndUpdate = function (...args) {
        const query = original.apply(this, args);
        const lean = query.lean.bind(query);
        query.lean = async (...leanArgs) => {
            if (!raced && args[2]?.session) {
                raced = true;
                await State.collection.updateOne({ _id: 'singleton', topologyAdmissionCount: 0 }, { $inc: { topologyAdmissionCount: 1 } });
            }
            return lean(...leanArgs);
        };
        return query;
    };
    try { await work(); assert.equal(raced, true); } finally { State.findOneAndUpdate = original; }
}

test('HTTP undeploy loses a post-read admission race before external teardown', local, async () => {
    await reset();
    await raceAdmission(async () => {
        const response = await httpUndeploy();
        assert.equal(response.status, 409);
    });
    const state = await models.CascadeTopologyState.findById('singleton').lean();
    assert.equal(state.revision, 7);
    assert.equal(state.deployedRevision, 5);
    assert.equal(state.topologyAdmissionCount, 1);
    assert.equal(state.replacementReservation, undefined);
    assert.equal(remoteCalls, 0);
});

test('quiescent MCP undeploy preserves its progress/response contract and invalidates subscriptions', local, async () => {
    await reset();
    const progress = [];
    cascadeService.undeployLink = async current => {
        remoteCalls++;
        assert.equal(String(current.portalNode._id), ids[0]);
        assert.ok((await models.CascadeTopologyState.findById('singleton').lean()).replacementReservation);
    };
    const result = await manageCascade({ action: 'undeploy', id: linkId }, (...args) => progress.push(args));
    assert.equal(result.success, true);
    assert.equal(progress.length, 1);
    assert.equal(remoteCalls, 1);
    assert.equal(cacheCalls, 1);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).replacementReservation, undefined);
});

test('MCP draft update rolls back if a counted admission wins after its snapshot', local, async () => {
    await reset();
    await raceAdmission(async () => {
        await assert.rejects(manageCascade({ action: 'update', id: linkId, expectedTopologyRevision: 7,
            data: { name: 'must roll back' } }, () => {}), { code: 'TOPOLOGY_DEPLOY_BUSY' });
    });
    assert.equal((await CascadeLink.findById(linkId).lean()).name, 'original');
    const state = await models.CascadeTopologyState.findById('singleton').lean();
    assert.equal(state.revision, 7);
    assert.equal(state.topologyAdmissionCount, 1);
    assert.equal(cacheCalls, 0);
    assert.equal(remoteCalls, 0);
});

test('HTTP undeploy rereads metadata after a draft edit wins the existence-read race', local, async () => {
    await reset();
    const original = CascadeLink.findById;
    let raced = false;
    CascadeLink.findById = function (...args) {
        const query = original.apply(this, args);
        const exec = query.exec.bind(query);
        query.exec = async (...execArgs) => {
            const result = await exec(...execArgs);
            if (!raced) {
                raced = true;
                await manageCascade({ action: 'update', id: linkId, expectedTopologyRevision: 7,
                    data: { mode: 'reverse', name: 'new-metadata' } }, () => {});
            }
            return result;
        };
        return query;
    };
    cascadeService.undeployLink = async current => {
        remoteCalls++;
        assert.equal(current.mode, 'reverse');
        assert.equal(current.name, 'new-metadata');
        assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 9);
    };
    try {
        assert.equal((await httpUndeploy()).status, 200);
        assert.equal(remoteCalls, 1);
        assert.equal(raced, true);
    } finally { CascadeLink.findById = original; }
});

test('new intent accepted during teardown waits behind the owned reservation', local, async () => {
    await reset();
    const { createTopologyIntentService } = require('../../modules/relay-l2tp/services/topologyIntentService');
    const service = createTopologyIntentService(models);
    let job;
    cascadeService.undeployLink = async () => {
        remoteCalls++;
        job = await service.accept({ expectedTopologyRevision: 8, requestKey: 'behind-undeploy', link: {
            _id: new mongoose.Types.ObjectId(), name: 'deferred', mode: 'forward', portalNode: ids[0], bridgeNode: ids[1],
            tunnelPort: 10087, tunnelUuid: 'local-only-deferred',
        } });
        await service.runOnce();
        assert.equal(await models.TopologyOperation.countDocuments(), 0);
        assert.equal(await CascadeLink.countDocuments(), 1);
        assert.equal((await service.get(job.jobId)).status, 'waiting');
    };
    assert.equal((await httpUndeploy()).status, 200);
    assert.equal((await service.get(job.jobId)).status, 'waiting');
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
    assert.equal(remoteCalls, 1);
});

test('unknown reservation commit never authorizes teardown or a blind reservation release', local, async () => {
    await reset();
    const connection = models.CascadeTopologyState.db;
    const original = connection.transaction;
    connection.transaction = async function (...args) {
        await original.apply(this, args);
        throw Object.assign(new Error('local simulated unknown reservation commit'), {
            hasErrorLabel: label => label === 'UnknownTransactionCommitResult',
        });
    };
    try {
        assert.equal((await httpUndeploy()).status, 500);
        assert.equal(remoteCalls, 0);
        const state = await models.CascadeTopologyState.findById('singleton').lean();
        assert.match(state.replacementReservation.ownerToken, /^legacy-undeploy:/);
        assert.equal(state.revision, 8);
        assert.equal(state.topologyAdmissionCount, 0);
    } finally { connection.transaction = original; }
});

test('teardown failure retains non-expiring ownership with no operation purge', local, async () => {
    await reset();
    cascadeService.undeployLink = async () => { remoteCalls++; throw new Error('local simulated uncertain teardown'); };
    const response = await httpUndeploy();
    assert.equal(response.status, 500);
    const state = await models.CascadeTopologyState.findById('singleton').lean();
    assert.equal(state.revision, 8);
    assert.equal(state.deployedRevision, 0);
    assert.match(state.replacementReservation.ownerToken, /^legacy-undeploy:/);
    assert.equal((await httpUndeploy()).status, 409);
    assert.equal(remoteCalls, 1);
    assert.equal(cacheCalls, 0);
});

test('undeploy never releases a foreign reservation after losing ownership', local, async () => {
    await reset();
    cascadeService.undeployLink = async () => {
        remoteCalls++;
        await models.CascadeTopologyState.updateOne({ _id: 'singleton' }, {
            $set: { replacementReservation: { ownerToken: 'foreign-owner', epoch: 2 }, replacementEpoch: 2 },
        });
    };
    const response = await httpUndeploy();
    assert.equal(response.status, 500);
    assert.equal(response.body.error.code, 'LEGACY_CASCADE_UNDEPLOY_FENCE_LOST');
    const state = await models.CascadeTopologyState.findById('singleton').lean();
    assert.equal(state.replacementReservation.ownerToken, 'foreign-owner');
    assert.equal(state.replacementReservation.epoch, 2);
    assert.equal(remoteCalls, 1);
});
