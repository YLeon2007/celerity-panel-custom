'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');
const moduleEntry = require('..');
const { TopologyOperationFinalizationRepository } = require('../repositories/topologyOperationFinalizationRepository');
const ids = Array.from({ length: 5 }, (_, i) => `507f1f77bcf86cd79943903${i + 1}`);
let models, processHandle, directory;
async function until(work) {
    let error;
    for (let i = 0; i < 100; i++) {
        try { return await work(); } catch (e) { error = e; }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw error;
}
test.before(async () => {
    if (!process.env.C3_MONGOD) return;
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR || os.tmpdir(), 'c3-intent-db-'));
    const port = await new Promise(resolve => { const server = net.createServer(); server.listen(0, '127.0.0.1', () => { const p = server.address().port; server.close(() => resolve(p)); }); });
    processHandle = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1', '--replSet', 'intentScratch', '--setParameter', 'enableTestCommands=1', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const uri = `mongodb://127.0.0.1:${port}/intent_scratch?directConnection=true`;
    const client = new mongoose.mongo.MongoClient(uri, { serverSelectionTimeoutMS: 100 });
    await until(() => client.connect());
    await client.db('admin').command({ replSetInitiate: { _id: 'intentScratch', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
    await until(async () => { assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true); });
    await client.close();
    await mongoose.connect(uri, { monitorCommands: true });
    models = { ...moduleEntry.registerModels(), HyNode: require('../../../models/hyNodeModel'), CascadeLink: require('../../../models/cascadeLinkModel') };
    await Promise.all(Object.values(models).map(model => model.init()));
});
test.after(async () => {
    // Assembled-host/HTTP imports initialize this singleton even with local executors.
    // Close its idle-cleanup timer without importing it into otherwise isolated tests.
    require.cache[require.resolve('../../../services/sshPoolService')]?.exports.closeAll();
    await mongoose.disconnect();
    if (processHandle && processHandle.exitCode === null) {
        const exited = new Promise(resolve => processHandle.once('exit', resolve));
        processHandle.kill('SIGTERM'); await exited;
    }
    if (directory) await fs.rm(directory, { recursive: true, force: true });
});
async function reset() {
    for (const model of Object.values(models)) await model.deleteMany({});
    await models.CascadeTopologyState.create({ _id: 'singleton', revision: 7, deployedRevision: 5, topologyAdmissionCount: 0, remoteAdmissionCount: 0 });
    await models.HyNode.collection.insertMany(ids.map((_id, index) => ({ _id: new mongoose.Types.ObjectId(_id), type: 'xray', active: true, cascadeRole: ['portal', 'portal', 'relay', 'bridge', 'bridge'][index], ip: `192.0.2.${index + 1}`, domain: `node-${index}.test`, port: 443, xray: { security: 'none', transport: 'tcp', inboundTag: 'vless-in', apiPort: 10085 } })));
}
function link(index) {
    const pairs = [[0, 2], [1, 2], [2, 3], [2, 4]];
    const [source, target] = pairs[index];
    return { _id: new mongoose.Types.ObjectId(), name: `rapid-${index + 1}`, mode: index % 2 ? 'reverse' : 'forward',
        portalNode: ids[source], bridgeNode: ids[target], tunnelUuid: `local-test-${index}`, tunnelPort: 10086 + index,
        autoDeploy: true, ...(index === 3 ? { geoRouting: { enabled: true, geoip: ['ru'] } } : {}) };
}
const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to an isolated local MongoDB binary' };
test('four acceptances are durable before any draft mutation; duplicate and overflow are transactional', local, async () => {
    await reset();
    assert.equal(typeof moduleEntry.createTopologyIntentService, 'function', 'the runtime must expose persisted-intent admission');
    const service = moduleEntry.createTopologyIntentService({ ...models, capacity: 4 });
    const payloads = Array.from({ length: 4 }, (_, i) => link(i));
    const accepted = [];
    for (let i = 0; i < 4; i++) accepted.push(await service.accept({ expectedTopologyRevision: 7, requestKey: `rapid-${i}`, link: payloads[i] }));
    assert.equal(await models.CascadeLink.countDocuments(), 0);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 7);
    assert.equal(await models.TopologyCreateIntent.countDocuments({ status: 'waiting' }), 4);
    const restarted = moduleEntry.createTopologyIntentService({ ...models, capacity: 4 });
    assert.deepEqual(await restarted.get(accepted[0].jobId), accepted[0]);
    assert.deepEqual(await restarted.accept({ expectedTopologyRevision: 7, requestKey: 'rapid-0', link: payloads[0] }), accepted[0]);
    await assert.rejects(restarted.accept({ expectedTopologyRevision: 7, requestKey: 'overflow', link: link(0) }), { code: 'TOPOLOGY_INTENT_BACKLOG_FULL' });
    await assert.rejects(restarted.accept({ expectedTopologyRevision: 7, requestKey: 'rapid-0', link: { ...payloads[0], name: 'different' } }), { code: 'TOPOLOGY_INTENT_KEY_CONFLICT' });
    assert.equal(await models.TopologyCreateIntent.countDocuments(), 4);
    assert.deepEqual((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 4);
    assert.equal(JSON.stringify(accepted).includes('tunnelUuid'), false);
});
test('unknown acceptance commit is acknowledged only after a bounded majority readback', local, async () => {
    await reset();
    const commands = [];
    const observe = event => {
        if (event.commandName === 'find' && event.command.filter?.requestKey === 'accept-unknown') commands.push(event.command);
    };
    mongoose.connection.getClient().on('commandStarted', observe);
    let transactions = 0;
    const service = moduleEntry.createTopologyIntentService({ ...models, transactionRunner: async work => {
        transactions++;
        await mongoose.connection.transaction(work, {
            readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary',
        });
        throw Object.assign(new Error('synthetic unknown acceptance commit'), {
            hasErrorLabel: label => label === 'UnknownTransactionCommitResult',
        });
    } });
    try {
        const payload = link(0);
        const job = await service.accept({ expectedTopologyRevision: 7, requestKey: 'accept-unknown', link: payload });
        const recoveryReads = commands.filter(command => command.autocommit !== false);
        assert.equal(recoveryReads.length, 1, 'one exact readback, not another acceptance transaction');
        assert.equal(recoveryReads[0].readConcern?.level, 'majority', 'local visibility does not confirm a durable acceptance');
        assert.ok(recoveryReads[0].maxTimeMS > 0 && recoveryReads[0].maxTimeMS <= 5000, 'confirmation must be bounded');
        assert.equal(transactions, 1);
        assert.equal(job.status, 'waiting');
        assert.equal(JSON.stringify(job).includes(payload.tunnelUuid), false);
        assert.deepEqual(await moduleEntry.createTopologyIntentService(models).get(job.jobId), job);
        assert.equal(await models.TopologyCreateIntent.countDocuments(), 1);
        assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
        assert.equal(await models.CascadeLink.countDocuments(), 0);
        assert.equal(await models.TopologyOperation.countDocuments(), 0);
        assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 7);
    } finally {
        mongoose.connection.getClient().off('commandStarted', observe);
    }
});
test('unknown acceptance with no committed row fails closed without another transaction', local, async () => {
    await reset();
    const unknown = Object.assign(new Error('synthetic unknown aborted acceptance'), {
        hasErrorLabel: label => label === 'UnknownTransactionCommitResult',
    });
    let transactions = 0;
    const service = moduleEntry.createTopologyIntentService({ ...models, transactionRunner: async work => {
        transactions++;
        await assert.rejects(mongoose.connection.transaction(async session => {
            await work(session);
            throw unknown;
        }), error => error === unknown);
        throw unknown;
    } });
    await assert.rejects(service.accept({ expectedTopologyRevision: 7, requestKey: 'accept-absent', link: link(0) }), error => error === unknown);
    assert.equal(transactions, 1);
    assert.equal(await models.TopologyCreateIntent.countDocuments(), 0);
    assert.equal(await models.TopologyIntentQueueState.countDocuments(), 0);
    assert.equal(await models.CascadeLink.countDocuments(), 0);
    assert.equal(await models.TopologyOperation.countDocuments(), 0);
    const state = await models.CascadeTopologyState.findById('singleton').lean();
    assert.equal(state.revision, 7);
    assert.equal(state.stateTransitionRevision, 0);
});
test('unknown acceptance readback failure never acknowledges or retries the durable job', local, async () => {
    await reset();
    let transactions = 0;
    const client = mongoose.connection.getClient();
    const service = moduleEntry.createTopologyIntentService({ ...models, transactionRunner: async work => {
        transactions++;
        await mongoose.connection.transaction(work, { writeConcern: { w: 'majority' } });
        // Fail only the subsequent read, after the real transaction has committed.
        await client.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 },
            data: { failCommands: ['find'], errorCode: 50 } });
        throw Object.assign(new Error('synthetic unknown acceptance commit'), {
            hasErrorLabel: label => label === 'UnknownTransactionCommitResult',
        });
    } });
    try {
        await assert.rejects(service.accept({ expectedTopologyRevision: 7, requestKey: 'accept-unreadable', link: link(0) }), { code: 50 });
    } finally {
        await client.db('admin').command({ configureFailPoint: 'failCommand', mode: 'off' });
    }
    assert.equal(transactions, 1);
    assert.equal(await models.TopologyCreateIntent.countDocuments({ status: 'waiting' }), 1);
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
    assert.equal(await models.CascadeLink.countDocuments(), 0);
    assert.equal(await models.TopologyOperation.countDocuments(), 0);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 7);
});
test('ambiguous and duplicate acceptance readbacks enforce the exact payload identity', local, async t => {
    for (const code of ['unknown', 'duplicate']) await t.test(code, async () => {
        await reset();
        const payload = link(0);
        const accepted = moduleEntry.createTopologyIntentService(models);
        const job = await accepted.accept({ expectedTopologyRevision: 7, requestKey: 'accept-exact', link: payload });
        const commands = [];
        const observe = event => {
            if (event.commandName === 'find' && event.command.filter?.requestKey === 'accept-exact') commands.push(event.command);
        };
        const client = mongoose.connection.getClient();
        client.on('commandStarted', observe);
        const service = moduleEntry.createTopologyIntentService({ ...models, transactionRunner: async () => {
            throw code === 'duplicate' ? Object.assign(new Error('synthetic duplicate key race'), { code: 11000 })
                : Object.assign(new Error('synthetic unknown commit'), { hasErrorLabel: label => label === 'UnknownTransactionCommitResult' });
        } });
        try {
            assert.deepEqual(await service.accept({ expectedTopologyRevision: 7, requestKey: 'accept-exact', link: payload }), job);
            await assert.rejects(service.accept({ expectedTopologyRevision: 7, requestKey: 'accept-exact', link: { ...payload, name: 'different' } }),
                { code: 'TOPOLOGY_INTENT_KEY_CONFLICT' });
            assert.equal(commands.length, 2);
            assert.ok(commands.every(command => command.readConcern?.level === 'majority' && command.maxTimeMS > 0 && command.maxTimeMS <= 5000));
            assert.equal(await models.TopologyCreateIntent.countDocuments(), 1);
            assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
            assert.equal(await models.CascadeLink.countDocuments(), 0);
            assert.equal(await models.TopologyOperation.countDocuments(), 0);
        } finally {
            client.off('commandStarted', observe);
        }
    });
});
async function finish(operation) {
    const now = new Date(); const leaseUntil = new Date(now.getTime() + 60000);
    await models.TopologyOperation.updateOne({ _id: operation._id }, { $set: { status: 'committing', leaseOwner: 'local-finalizer', leaseUntil } });
    const finalizer = new TopologyOperationFinalizationRepository(models);
    assert.ok(await finalizer.finalizeSucceeded({ operationId: String(operation._id), owner: 'local-finalizer', leaseUntil, now,
        topologyRevision: operation.topologyRevision, priorDeployedRevision: operation.priorDeployedRevision,
        kind: operation.kind, linkId: operation.linkId, linkIds: operation.linkIds, staged: operation.staged,
    }), 'the unchanged exact finalizer must accept the frozen operation');
}
test('legacy autoDeploy pending drafts are neither inferred as intents nor included in a scoped baseline', local, async () => {
    await reset();
    const legacy = link(1);
    await models.CascadeLink.create({ ...legacy, active: true, status: 'pending' });
    const service = moduleEntry.createTopologyIntentService(models);
    await service.runOnce();
    assert.equal(await models.TopologyOperation.countDocuments(), 0);
    assert.equal(await models.TopologyCreateIntent.countDocuments(), 0);
    const job = await service.accept({ expectedTopologyRevision: 7, requestKey: 'exclude-legacy', link: link(0) });
    await service.runOnce();
    const admitted = await service.get(job.jobId);
    assert.equal(admitted.status, 'admitted', JSON.stringify(admitted));
    const operation = await models.TopologyOperation.findById(admitted.operationId).lean();
    assert.deepEqual(operation.linkIds.map(String), [admitted.createdLinkId]);
    assert.equal((await models.CascadeLink.findById(legacy._id).lean()).status, 'pending');
    await finish(operation);
});
test('mixed-mode links cannot share the same actual listener node and port', local, async t => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    for (const mode of ['forward', 'reverse']) await t.test(mode, async () => {
        await reset();
        const desired = { ...link(mode === 'forward' ? 0 : 2), mode };
        const existing = { ...link(mode === 'forward' ? 2 : 0),
            mode: mode === 'forward' ? 'reverse' : 'forward', tunnelPort: desired.tunnelPort };
        await models.CascadeLink.create(existing);
        const service = moduleEntry.createTopologyIntentService(models);
        const job = await service.accept({ expectedTopologyRevision: 7, requestKey: `same-listener-${mode}`, link: desired });
        const consumer = new TopologyIntentConsumer(models);
        const claim = await consumer.claim();
        await assert.rejects(consumer.consume(claim), { code: 'TOPOLOGY_INTENT_PORT_CONFLICT' });
        assert.equal((await service.get(job.jobId)).status, 'claimed');
        assert.equal(await models.CascadeLink.countDocuments(), 1);
        assert.equal(await models.CascadeLink.exists({ _id: desired._id }), null);
        assert.equal(await models.TopologyOperation.countDocuments(), 0);
        assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 7);
        assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 0);
        assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
    });
});
test('same-mode listener collisions including legacy default reverse mode remain blocked', local, async t => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    for (const mode of ['forward', 'reverse', 'legacy-reverse']) await t.test(mode, async () => {
        await reset();
        const desired = { ...link(mode === 'forward' ? 0 : 1), mode: mode === 'forward' ? 'forward' : 'reverse' };
        const existing = await models.CascadeLink.create({ ...desired, _id: new mongoose.Types.ObjectId() });
        if (mode === 'legacy-reverse') await models.CascadeLink.collection.updateOne({ _id: existing._id }, { $unset: { mode: '' } });
        const service = moduleEntry.createTopologyIntentService(models);
        await service.accept({ expectedTopologyRevision: 7, requestKey: `same-mode-${mode}`, link: desired });
        const consumer = new TopologyIntentConsumer(models);
        await assert.rejects(consumer.consume(await consumer.claim()), { code: 'TOPOLOGY_INTENT_PORT_CONFLICT' });
        assert.equal(await models.CascadeLink.countDocuments(), 1);
        assert.equal(await models.TopologyOperation.countDocuments(), 0);
        assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 7);
        assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
    });
});
test('mixed-mode links may reuse a port on different actual listener nodes', local, async t => {
    for (const mode of ['forward', 'reverse']) await t.test(mode, async () => {
        await reset();
        const desired = { ...link(mode === 'forward' ? 0 : 1), mode };
        const existing = { ...link(mode === 'forward' ? 1 : 2),
            ...(mode === 'reverse' ? { portalNode: desired.portalNode } : {}),
            mode: mode === 'forward' ? 'reverse' : 'forward', tunnelPort: desired.tunnelPort };
        await models.CascadeLink.create(existing);
        const service = moduleEntry.createTopologyIntentService(models);
        const job = await service.accept({ expectedTopologyRevision: 7, requestKey: `different-listener-${mode}`, link: desired });
        await service.runOnce();
        const admitted = await service.get(job.jobId);
        assert.equal(admitted.status, 'admitted', 'the shared endpoint is not the existing link listener');
        assert.equal(await models.CascadeLink.countDocuments(), 2);
        assert.equal(await models.TopologyOperation.countDocuments(), 1);
        assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 8);
        assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
        await finish(await models.TopologyOperation.findById(admitted.operationId).lean());
        await service.runOnce();
        assert.equal((await service.get(job.jobId)).status, 'succeeded');
        assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 0);
    });
});
test('an unrelated draft writer cannot advance the exact active revision', local, async () => {
    await reset();
    const service = moduleEntry.createTopologyIntentService(models);
    await service.accept({ expectedTopologyRevision: 7, requestKey: 'active-fence', link: link(0) });
    await service.runOnce();
    const { createTopologyDraftWriteService } = require('../services/topologyDraftWriteService');
    const writes = createTopologyDraftWriteService(models);
    await assert.rejects(writes.createLink({ expectedTopologyRevision: 8, link: link(1) }), { code: 'TOPOLOGY_DEPLOY_BUSY' });
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 8);
    assert.equal(await models.CascadeLink.countDocuments(), 1);
    const { L2tpSimpleService } = require('../services/l2tpSimpleService');
    const simple = Object.assign(Object.create(L2tpSimpleService.prototype), models);
    await assert.rejects(simple.withPathWriter(async ({ commit }) => commit()), { code: 'TOPOLOGY_DEPLOY_BUSY' });
    const { L2tpStateRepository } = require('../repositories/l2tpStateRepository');
    const stateRepository = new L2tpStateRepository(models);
    await assert.rejects(stateRepository.advanceTopologyRevision(), { code: 'TOPOLOGY_DEPLOY_BUSY' });
    await finish(await models.TopologyOperation.findOne().lean());
});
test('suspended deployment and consumer restart preserve the active revision then drain exactly four scoped operations', local, async () => {
    await reset();
    const service = moduleEntry.createTopologyIntentService(models);
    assert.equal(typeof service.runOnce, 'function', 'a supervised consumer must consume persisted create intents');
    const jobs = [];
    for (let i = 0; i < 4; i++) jobs.push(await service.accept({ expectedTopologyRevision: 7, requestKey: `suspend-${i}`, link: link(i) }));
    await service.runOnce();
    assert.equal(await models.CascadeLink.countDocuments(), 1);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 8);
    const first = await models.TopologyOperation.findOne().lean();
    assert.equal(first.topologyRevision, 8);
    assert.equal(first.kind, 'link.apply');
    assert.equal(first.heldTopologyAdmission, true);
    // A new object has no process-local memory of the accepted requests.
    const restarted = moduleEntry.createTopologyIntentService(models);
    for (let i = 0; i < 3; i++) await restarted.runOnce();
    assert.equal(await models.CascadeLink.countDocuments(), 1);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 8);
    for (let i = 0; i < 4; i++) {
        const job = await restarted.get(jobs[i].jobId);
        assert.equal(job.status, 'admitted', JSON.stringify(job));
        const operation = await models.TopologyOperation.findById(job.operationId).lean();
        assert.equal(operation.topologyRevision, 8 + i);
        assert.equal(operation.linkIds.length, i + 1);
        await finish(operation);
        await restarted.runOnce();
    }
    assert.equal(await models.TopologyCreateIntent.countDocuments({ status: 'succeeded' }), 4);
    assert.equal(await models.CascadeLink.countDocuments(), 4);
    assert.equal(await models.TopologyOperation.countDocuments(), 4);
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 0);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 0);
});
test('assembled TEST panel host exposes the durable service and supervises startup consumption', local, async () => {
    await reset();
    const { createL2tpPanelHost } = require('../../createL2tpPanelHost');
    const { createTopologyOperationRuntime } = require('../runtime/createTopologyOperationRuntime');
    const { L2tpSimpleService } = require('../services/l2tpSimpleService');
    const simple = Object.assign(Object.create(L2tpSimpleService.prototype), models);
    let tick; const executions = [];
    const executor = Object.fromEntries(['prepare', 'commit', 'verify', 'cleanupPrepared', 'rollback'].map(method => [method, async () => { throw Error('unexpected external execution'); }]));
    const host = createL2tpPanelHost({
        env: { L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: 'test.infograd.online' },
        HyNode: models.HyNode, CascadeLink: models.CascadeLink,
        moduleEntry: { ...moduleEntry, createTopologyDeploymentService: dependencies => createTopologyOperationRuntime({ ...dependencies,
            createTopologyOperationExecutor: () => executor,
            OperationWorker: class { async run(id) { executions.push(id); } },
        }) },
        createExecutionRuntime: () => ({ runtime: { simpleService: simple }, start() { return {}; }, async stop() { return {}; } }),
        workerLifecycle: { timer: { setInterval(fn) { tick = fn; return 1; }, clearInterval() {} } },
    });
    assert.equal(typeof host.topologyIntentService?.accept, 'function', 'the actual host must wire the intent service');
    const job = await host.topologyIntentService.accept({ expectedTopologyRevision: 7, requestKey: 'assembled-start', link: link(0) });
    assert.equal(await models.CascadeLink.countDocuments(), 0);
    host.start(); await host.stop();
    assert.equal((await host.topologyIntentService.get(job.jobId)).status, 'admitted');
    assert.equal(executions.length, 1);
    await tick(); assert.equal(executions.length, 1);
});
test('four actual HTTP POSTs while deployment is suspended survive assembled-host restart and never use general Sync', local, async () => {
    await reset();
    // Explicit non-PPP transit identity. A missing row is not permission to
    // bypass PPP readiness once the chain has a bridge.
    await models.RelayL2tpState.collection.insertOne({ node: new mongoose.Types.ObjectId(ids[2]),
        status: 'not_installed', desiredState: 'absent', secretRevision: 0 });
    const express = require('express');
    const { createCascadeLinksRouter } = require('../../../routes/cascadeLinks');
    const { l2tpActiveHostProvider } = require('../../l2tpActiveHostProvider');
    const { createL2tpPanelHost } = require('../../createL2tpPanelHost');
    const { createTopologyOperationRuntime } = require('../runtime/createTopologyOperationRuntime');
    const { createTopologyOperationRecoveryLifecycle } = require('../runtime/createTopologyOperationRecoveryLifecycle');
    const { L2tpSimpleService } = require('../services/l2tpSimpleService');
    const noop = async () => undefined;
    const simple = Object.assign(Object.create(L2tpSimpleService.prototype), models);
    let release; const suspended = new Promise(resolve => { release = resolve; });
    const ticks = [], lifecycles = [], executions = [];
    const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
    const executor = {
        async prepare(input) {
            if (!executions.includes(input.operationId)) executions.push(input.operationId);
            await suspended;
            return { backupId: `local-${input.node.node}`, prepared: {} };
        },
        async commit() { return { ok: true }; }, async verify() { return { ok: true }; },
        async cleanupPrepared() { return { ok: true }; }, async rollback() { return { ok: true }; },
    };
    const makeHost = pause => createL2tpPanelHost({
        env: { L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: 'test.infograd.online' },
        HyNode: models.HyNode, CascadeLink: models.CascadeLink,
        moduleEntry: { ...moduleEntry, createTopologyDeploymentService: dependencies => createTopologyOperationRuntime({ ...dependencies,
            createTopologyOperationExecutor: () => executor,
            // Real durable worker, lock repository, PPP gate and finalizer. Only
            // external transport and dynamic-user RPC are local deterministic seams.
            OperationWorker: class extends TopologyOperationWorker {
                constructor(input) { super({ ...input, userResync: { async resyncPlan() { return { ok: true }; } } }); }
            },
        }) },
        createExecutionRuntime: () => ({ runtime: { simpleService: simple,
            service: Object.fromEntries(['getStatus', 'preflight', 'install', 'getOperation'].map(name => [name, noop])),
            stateManagementService: { configureRelay: noop },
            userManagementService: Object.fromEntries(['createUser', 'listUsers', 'updateUser', 'disableUser'].map(name => [name, noop])),
        }, start() { return {}; }, async stop() { return {}; } }),
        createTopologyRecoveryLifecycle: options => { const lifecycle = createTopologyOperationRecoveryLifecycle(options); lifecycles.push(lifecycle); return lifecycle; },
        workerLifecycle: { timer: { setInterval(fn) { ticks.push(fn); return ticks.length; }, clearInterval() {} } },
    });
    const firstHost = makeHost(true); l2tpActiveHostProvider.installActiveHost(firstHost);
    const app = express(); app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    app.use(createCascadeLinksRouter({ Link: models.CascadeLink, Node: models.HyNode, TopologyState: models.CascadeTopologyState }));
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    const url = `http://127.0.0.1:${server.address().port}`;
    const jobs = []; let secondHost;
    try {
        for (let i = 0; i < 4; i++) {
            const desired = link(i);
            const revision = (await models.CascadeTopologyState.findById('singleton').lean()).revision;
            const body = { name: desired.name, portalNodeId: desired.portalNode, bridgeNodeId: desired.bridgeNode,
                tunnelPort: desired.tunnelPort, mode: desired.mode, geoRouting: desired.geoRouting,
                expectedTopologyRevision: revision, autoDeploy: true };
            const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': `http-${i}` }, body: JSON.stringify(body) });
            const accepted = await response.json();
            assert.equal(response.status, 202, JSON.stringify(accepted));
            assert.equal(accepted.createdLinkId, undefined); assert.equal(accepted.autoDeployOperation, undefined);
            jobs.push(accepted.autoDeployJob);
            if (i === 0) { firstHost.start(); await until(async () => { assert.equal(executions.length, 1); }); }
        }
        assert.equal(await models.CascadeLink.countDocuments(), 1);
        assert.equal(await models.TopologyCreateIntent.countDocuments(), 4);
        assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 8);
        const queued = await (await fetch(`${url}/auto-deploy-jobs/${jobs[3].jobId}`)).json();
        assert.equal(queued.autoDeployJob.status, 'waiting'); assert.equal(queued.autoDeployJob.createdLinkId, undefined);
        let drained = false; const stopping = firstHost.stop().then(() => { drained = true; });
        await new Promise(resolve => setImmediate(resolve)); assert.equal(drained, false);
        release(); await stopping; l2tpActiveHostProvider.clearActiveHost(firstHost);
        secondHost = makeHost(false); l2tpActiveHostProvider.installActiveHost(secondHost); secondHost.start();
        await until(async () => { assert.equal(lifecycles[1].start().inFlight, false); });
        for (let i = 0; i < 4; i++) await ticks[1]();
        assert.equal(await models.TopologyCreateIntent.countDocuments({ status: 'succeeded' }), 4,
            JSON.stringify({ jobs: await models.TopologyCreateIntent.find({}).lean(), ops: await models.TopologyOperation.find({}).select('status heldTopologyAdmission topologyRevision nodes.state').lean() }));
        const operations = await models.TopologyOperation.find({}).sort({ topologyRevision: 1 }).lean();
        assert.deepEqual(operations.map(row => row.topologyRevision), [8, 9, 10, 11]);
        assert(operations.every(row => row.kind === 'link.apply'), 'every operation is scoped, never general Sync');
        for (const operation of operations) for (const node of operation.nodes.filter(row => row.role === 'portal')) {
            const config = JSON.parse(Buffer.from(node.candidate.bytes).toString('utf8'));
            assert(!config.routing.rules.some(rule => ['direct', 'freedom'].includes(rule.outboundTag)), 'portal traffic must never select direct egress');
        }
    } finally {
        release(); await firstHost.stop();
        if (secondHost) { await secondHost.stop(); l2tpActiveHostProvider.clearActiveHost(secondHost); }
        l2tpActiveHostProvider.clearActiveHost(firstHost);
        await new Promise(resolve => server.close(resolve));
    }
});
test('concurrent overflow admits exactly the bounded capacity and reports safe refusal for every loser', local, async () => {
    await reset();
    const service = moduleEntry.createTopologyIntentService({ ...models, capacity: 4 });
    const results = await Promise.allSettled(Array.from({ length: 12 }, (_, i) => service.accept({ expectedTopologyRevision: 7, requestKey: `race-${i}`, link: link(i % 4) })));
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 4);
    for (const result of results.filter(result => result.status === 'rejected')) assert.equal(result.reason.code, 'TOPOLOGY_INTENT_BACKLOG_FULL');
    assert.equal(await models.TopologyCreateIntent.countDocuments(), 4);
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 4);
});
test('expired claim recovery fences an old generation before any draft mutation', local, async () => {
    await reset();
    let instant = new Date(); const clock = { now: () => instant };
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const service = moduleEntry.createTopologyIntentService(models);
    const job = await service.accept({ expectedTopologyRevision: 7, requestKey: 'claim-crash', link: link(0) });
    const old = new TopologyIntentConsumer({ ...models, clock, owner: 'old', leaseMs: 100 });
    const claim = await old.claim();
    instant = new Date(instant.getTime() + 101);
    const restarted = new TopologyIntentConsumer({ ...models, clock, owner: 'new', leaseMs: 1000 });
    const successor = await restarted.claim();
    assert.equal(successor.generation, claim.generation + 1);
    await assert.rejects(old.consume(claim), { code: 'TOPOLOGY_INTENT_FENCE_LOST' });
    assert.equal(await models.CascadeLink.countDocuments(), 0);
    await restarted.consume(successor);
    assert.equal((await service.get(job.jobId)).status, 'admitted');
    assert.equal(await models.TopologyOperation.countDocuments(), 1);
});
test('known preparation abort rolls back link maintenance and admission and exhausts bounded attempts', local, async () => {
    await reset();
    let instant = new Date(); const clock = { now: () => instant }; let calls = 0;
    const service = moduleEntry.createTopologyIntentService({ ...models, clock, maxAttempts: 3, backoffMs: 1,
        async maintainPaths({ CascadeRouteGroup, transactionRunner }) {
            return transactionRunner(async session => {
                calls++;
                await CascadeRouteGroup.create([{ name: 'rolled-back', mode: 'reverse', strategy: 'priority-failover', paths: [] }], { session });
                throw Error('synthetic local failure; must not escape into public error text');
            });
        },
    });
    const job = await service.accept({ expectedTopologyRevision: 7, requestKey: 'prepare-fail', link: link(0) });
    for (let i = 0; i < 6; i++) { await service.runOnce(); instant = new Date(instant.getTime() + 100); }
    assert.equal(calls, 3);
    assert.equal((await service.get(job.jobId)).status, 'failed');
    assert.equal((await service.get(job.jobId)).attempts, 3);
    assert.equal((await service.get(job.jobId)).errorCode, 'TOPOLOGY_INTENT_ATTEMPTS_EXHAUSTED');
    assert.equal(await models.CascadeLink.countDocuments(), 0);
    assert.equal(await models.CascadeRouteGroup.countDocuments(), 0);
    assert.equal(await models.TopologyOperation.countDocuments(), 0);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 7);
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 0);
});
test('unknown commit after atomic binding is recovered by exact persisted identity without a second operation', local, async () => {
    await reset();
    const accepted = moduleEntry.createTopologyIntentService(models);
    const job = await accepted.accept({ expectedTopologyRevision: 7, requestKey: 'unknown-commit', link: link(0) });
    const service = moduleEntry.createTopologyIntentService({ ...models, transactionRunner: async work => {
        const result = await mongoose.connection.transaction(work);
        if (result?.operationId) throw Object.assign(new Error('synthetic unknown commit result'), { hasErrorLabel: label => label === 'UnknownTransactionCommitResult' });
        return result;
    } });
    await service.runOnce();
    const bound = await accepted.get(job.jobId);
    assert.equal(bound.status, 'admitted');
    const operation = await models.TopologyOperation.findById(bound.operationId).lean();
    const intent = await models.TopologyCreateIntent.findById(job.jobId).lean();
    assert.equal(intent.admissionFingerprint, operation.admissionFingerprint);
    assert.equal(intent.topologyRevision, operation.topologyRevision);
    const restarted = moduleEntry.createTopologyIntentService(models);
    await restarted.runOnce();
    assert.equal(await models.TopologyOperation.countDocuments(), 1);
    assert.equal(await models.CascadeLink.countDocuments(), 1);
});
test('uncertain predecessor is visible and never requeued, released or bypassed by successors', local, async () => {
    await reset();
    const service = moduleEntry.createTopologyIntentService(models);
    const first = await service.accept({ expectedTopologyRevision: 7, requestKey: 'uncertain-1', link: link(0) });
    const second = await service.accept({ expectedTopologyRevision: 7, requestKey: 'uncertain-2', link: link(1) });
    await service.runOnce();
    const firstJob = await service.get(first.jobId);
    await models.TopologyOperation.updateOne({ _id: firstJob.operationId }, { $set: { status: 'failed', leaseUntil: new Date(0) } });
    const restarted = moduleEntry.createTopologyIntentService(models);
    for (let i = 0; i < 4; i++) await restarted.runOnce();
    assert.equal((await restarted.get(first.jobId)).status, 'blocked');
    assert.equal((await restarted.get(first.jobId)).attempts, 1);
    assert.equal((await restarted.get(second.jobId)).status, 'waiting');
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 1);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 8);
    assert.equal(await models.TopologyOperation.countDocuments(), 1);
});
