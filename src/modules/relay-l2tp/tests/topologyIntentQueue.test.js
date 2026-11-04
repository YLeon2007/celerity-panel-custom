'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID, createHash } = require('node:crypto');
const mongoose = require('mongoose');
const moduleEntry = require('..');
const ids = Array.from({ length: 5 }, (_, i) => `507f1f77bcf86cd79943903${i + 1}`);
const databaseName = `c3_anyorder_${randomUUID().replaceAll('-', '')}`;
let models, processHandle, directory, port;
const commands = [];
const TEST_CONTEXT = Object.freeze({ target: 'test', hostIdentity: 'test.infograd.online' });
function createIntentService(dependencies = models) {
    const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
    const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
    const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
    const { TopologyOperationCoordinator } = require('../services/topologyOperationCoordinator');
    const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
    const input = { executionContext: TEST_CONTEXT, ...dependencies };
    const draft = new TopologyDraftRepository(input);
    const deployment = new TopologyDeploymentRepository({ ...input, snapshotReader: draft });
    const coordinator = new TopologyOperationCoordinator({ executionContext: input.executionContext,
        topologyRepository: deployment,
        operationRepository: new TopologyOperationRepository({ model: models.TopologyOperation,
            topologyStateModel: models.CascadeTopologyState, selectedTopologyRepository: deployment }),
        planMaterializer: input.planMaterializer || new TopologyOperationPlanMaterializer(input) });
    return moduleEntry.createTopologyIntentService({ ...input,
        prepareLink: input.prepareLink ?? require('../../../routes/cascadeLinks').prepareIntentLink,
        intentDraftWriter: draft.createIntentDraftWriter({ selectedTopologyRepository: deployment }),
        intentOperationAdmission: { db: models.CascadeTopologyState.db, queue: request => coordinator.queueIntent(request) },
        resolveIntentResources: request => coordinator.resolveIntentResourcesForQueue(request) });
}
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
    assert.ok(process.env.TMPDIR, 'explicit local scratch root required');
    assert.ok((await fs.realpath(process.env.TMPDIR)).startsWith('/home/leon/.hermes/cache/scratch/'));
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-intent-db-'));
    port = await new Promise(resolve => { const server = net.createServer(); server.listen(0, '127.0.0.1', () => { const p = server.address().port; server.close(() => resolve(p)); }); });
    processHandle = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1', '--replSet', 'intentScratch', '--wiredTigerCacheSizeGB', '0.25', '--oplogSize', '32', '--setParameter', 'enableTestCommands=1', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const uri = `mongodb://127.0.0.1:${port}/${databaseName}`;
    const client = new mongoose.mongo.MongoClient(`${uri}?directConnection=true`, { serverSelectionTimeoutMS: 100 });
    await until(() => client.connect());
    await client.db('admin').command({ replSetInitiate: { _id: 'intentScratch', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
    await until(async () => { assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true); });
    await client.close();
    await mongoose.connect(`${uri}?replicaSet=intentScratch`, { monitorCommands: true, serverSelectionTimeoutMS: 5000, maxPoolSize: 5 });
    mongoose.connection.getClient().on('commandStarted', event => {
        if (['find', 'insert', 'update', 'delete', 'commitTransaction', 'abortTransaction'].includes(event.commandName)) {
            // Exact command semantics without private credentials/config payloads.
            commands.push({ name: event.commandName, databaseName: event.databaseName,
                collection: event.command[event.commandName], autocommit: event.command.autocommit,
                readConcern: event.command.readConcern, readPreference: event.command.$readPreference,
                maxTimeMS: event.command.maxTimeMS, projection: event.command.projection,
                requestKey: event.command.filter?.requestKey,
                id: event.command.filter?._id?.toHexString?.() });
        }
    });
    models = { ...moduleEntry.registerModels(), HyNode: require('../../../models/hyNodeModel'), CascadeLink: require('../../../models/cascadeLinkModel') };
    await Promise.all(Object.values(models).map(model => model.init()));
});
test.after(async () => {
    // Assembled-host/HTTP imports initialize this singleton even with local executors.
    // Close its idle-cleanup timer without importing it into otherwise isolated tests.
    require.cache[require.resolve('../../../services/sshPoolService')]?.exports.closeAll();
    let databaseAbsent = false;
    if (mongoose.connection.readyState === 1) {
        assert.equal(mongoose.connection.name, databaseName);
        await mongoose.connection.dropDatabase();
        databaseAbsent = !(await mongoose.connection.getClient().db('admin').admin().listDatabases()).databases.some(row => row.name === databaseName);
        assert.equal(databaseAbsent, true);
    }
    await mongoose.disconnect();
    if (processHandle && processHandle.exitCode === null) {
        const exited = new Promise(resolve => processHandle.once('exit', resolve));
        processHandle.kill('SIGTERM');
        await Promise.race([exited, new Promise((_, reject) => { const timer = setTimeout(() => reject(Error('owned mongod shutdown deadline')), 15000); timer.unref(); })]);
    }
    if (directory && process.env.C3_ANYORDER_MONGO_EVIDENCE) {
        await fs.mkdir(process.env.C3_ANYORDER_MONGO_EVIDENCE, { recursive: true });
        await fs.copyFile(path.join(directory, 'mongo.log'), path.join(process.env.C3_ANYORDER_MONGO_EVIDENCE, 'legacy-queue-mongod.log'));
    }
    if (directory) {
        await fs.rm(directory, { recursive: true, force: true });
        assert.equal(require('node:fs').existsSync(directory), false);
    }
    const portClosed = port === undefined || await new Promise(resolve => { const socket = net.connect({ host: '127.0.0.1', port });
        socket.once('connect', () => { socket.destroy(); resolve(false); }); socket.once('error', () => resolve(true)); });
    assert.equal(portClosed, true);
    if (process.env.C3_ANYORDER_MONGO_EVIDENCE) {
        await fs.writeFile(path.join(process.env.C3_ANYORDER_MONGO_EVIDENCE, 'commands.json'), JSON.stringify(commands, null, 2));
        await fs.writeFile(path.join(process.env.C3_ANYORDER_MONGO_EVIDENCE, 'legacy-queue-cleanup.json'),
            JSON.stringify({ databaseName, databaseAbsent, pid: processHandle?.pid, processExited: processHandle?.exitCode !== null,
                directory, directoryAbsent: !require('node:fs').existsSync(directory), port, portClosed }, null, 2));
    }
});
async function reset(context = TEST_CONTEXT) {
    assert.match(databaseName, /^c3_anyorder_[a-f0-9]{32}$/);
    assert.equal(mongoose.connection.name, databaseName);
    assert.equal(mongoose.connection.host, '127.0.0.1'); assert.equal(mongoose.connection.port, port);
    // Registered immutable binding/enrollment models must retain their public
    // mutation guards. Reset only the isolated fixture via its raw collections.
    for (const model of Object.values(models)) await model.collection.deleteMany({});
    await models.CascadeTopologyState.create({ _id: 'singleton', revision: 7, deployedRevision: 5, topologyAdmissionCount: 0, remoteAdmissionCount: 0 });
    await models.HyNode.collection.insertMany(ids.map((_id, index) => ({ _id: new mongoose.Types.ObjectId(_id), type: 'xray', active: true, cascadeRole: ['portal', 'portal', 'relay', 'bridge', 'bridge'][index], ip: `192.0.2.${index + 1}`, domain: `node-${index}.test`, port: 443, xray: { security: 'none', transport: 'tcp', inboundTag: 'vless-in', apiPort: 10085 } })));
    await adoptedEmptyBaseline(context);
    // Explicit absent/non-PPP transit. Missing state is not completed-chain readiness.
    await models.RelayL2tpState.collection.insertOne({ node: new mongoose.Types.ObjectId(ids[2]),
        status: 'not_installed', desiredState: 'absent', secretRevision: 0 });
}
function link(index) {
    const pairs = [[0, 2], [1, 2], [2, 3], [2, 4]];
    const [source, target] = pairs[index];
    return { _id: new mongoose.Types.ObjectId(), name: `rapid-${index + 1}`, mode: index % 2 ? 'reverse' : 'forward',
        portalNode: ids[source], bridgeNode: ids[target], tunnelUuid: `local-test-${index}`, tunnelPort: 10086 + index,
        autoDeploy: true, ...(index === 3 ? { geoRouting: { enabled: true, geoip: ['ru'] } } : {}) };
}
async function adoptedEmptyBaseline(context) {
    // Exercise the PUBLIC owner CAS and majority readback, not a seeded adopted
    // row. Physical identity, old-PID exclusion and empty original profiles are
    // explicitly SIMULATED local evidence, never operational adoption authority.
    const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
    const sha = value => createHash('sha256').update(value).digest('hex');
    const nodes = await models.HyNode.find({}).sort({ _id: 1 }).lean();
    for (const [i, node] of nodes.entries()) {
        const profile = node.cascadeRole === 'portal' ? 'xray-main' : 'xray-bridge';
        const nodeIdentity = { machineId: String(i + 1).repeat(32), sshHostKeySha256: String(i + 1).repeat(64) };
        const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: models.TopologyConfigOwner,
            async withVerifiedMaintenance({ binding, proofRef }, work) {
                assert.equal(proofRef, 'SIMULATED-empty-original');
                assert.equal(binding.node, String(node._id)); assert.equal(binding.profile, profile);
                assert.deepEqual(binding.nodeIdentity, nodeIdentity); assert.deepEqual(binding.executionContext, context);
                await work({ status: 'verified', authority: 'external-maintenance-v1', binding,
                    proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
                    oldBackend: { instanceId: 'SIMULATED-old-backend', pid: 42, processStartTime: 'SIMULATED-start',
                        processTree: 'stopped', dispatch: 'disabled' },
                    readback: { source: 'node-readback', configSha256: sha('{}'), unitSha256: sha('SIMULATED-unit'),
                        serviceActive: 'inactive', serviceEnabled: 'disabled' } });
            } });
        const classic = await transfer.initializeClassic({ node: String(node._id), profile, nodeIdentity });
        const adopted = await transfer.adopt({ node: String(node._id), profile, generation: classic.generation,
            proofRef: 'SIMULATED-empty-original' });
        const persisted = await models.TopologyConfigOwner.findById(adopted._id).read('primary').readConcern('majority').lean();
        assert.equal(persisted.owner, 'topology'); assert.equal(persisted.generation, adopted.generation);
        assert.equal(persisted.adoptionReceipt.fromGeneration, classic.generation);
    }
}
const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to an isolated local MongoDB binary' };
test('v1 acceptances remain durable before draft mutation; duplicate and overflow are transactional', local, async () => {
    await reset();
    assert.equal(typeof moduleEntry.createTopologyIntentService, 'function', 'the runtime must expose persisted-intent admission');
    const service = createIntentService({ ...models, capacity: 4 });
    const payloads = Array.from({ length: 4 }, (_, i) => link(i));
    const accepted = [];
    for (let i = 0; i < 4; i++) accepted.push(await service.accept({ expectedTopologyRevision: 7, requestKey: `rapid-${i}`, link: payloads[i] }));
    assert.equal(await models.CascadeLink.countDocuments(), 0);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 7);
    assert.equal(await models.TopologyCreateIntent.countDocuments({ status: 'waiting' }), 4);
    const restarted = createIntentService({ ...models, capacity: 4 });
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
    const service = createIntentService({ ...models, transactionRunner: async work => {
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
        assert.deepEqual(await createIntentService(models).get(job.jobId), job);
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
    const service = createIntentService({ ...models, transactionRunner: async work => {
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
    const service = createIntentService({ ...models, transactionRunner: async work => {
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
        const accepted = createIntentService(models);
        const job = await accepted.accept({ expectedTopologyRevision: 7, requestKey: 'accept-exact', link: payload });
        const commands = [];
        const observe = event => {
            if (event.commandName === 'find' && event.command.filter?.requestKey === 'accept-exact') commands.push(event.command);
        };
        const client = mongoose.connection.getClient();
        client.on('commandStarted', observe);
        const service = createIntentService({ ...models, transactionRunner: async () => {
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
test('PROD HTTP acceptance pins the immutable server identity through consumer admission', local, async () => {
    const prod = { target: 'production', hostIdentity: 'lm1.infograd.online' };
    await reset(prod);
    const express = require('express');
    const { createCascadeLinksRouter } = require('../../../routes/cascadeLinks');
    const context = { target: 'production', hostIdentity: 'lm1.infograd.online' };
    const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
    const materializer = new TopologyOperationPlanMaterializer(models);
    const materialized = [];
    const dependencies = { ...models, executionContext: context, planMaterializer: {
        async materialize(input) { materialized.push({ target: input.target, hostIdentity: input.hostIdentity }); return materializer.materialize(input); },
    } };
    const service = createIntentService(dependencies);
    context.target = 'test'; context.hostIdentity = 'test.infograd.online';
    dependencies.executionContext = context;
    const app = express(); app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    app.use(createCascadeLinksRouter({ Link: models.CascadeLink, Node: models.HyNode,
        TopologyState: models.CascadeTopologyState, topologyIntentService: service }));
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}`, {
            method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'prod-http' },
            body: JSON.stringify({ name: 'production-local-only', portalNodeId: ids[0], bridgeNodeId: ids[2],
                mode: 'forward', autoDeploy: true, expectedTopologyRevision: 7,
                executionContext: { target: 'test', hostIdentity: 'test.infograd.online' },
                target: 'test', hostIdentity: 'test.infograd.online' }),
        });
        const body = await response.json();
        assert.equal(response.status, 202, JSON.stringify(body));
        assert.equal(await models.CascadeLink.countDocuments(), 1, 'new HTTP v2 persists desired state at acceptance');
        assert.equal(body.desiredSaved, true); assert.equal(body.job.version, 2);
        assert.deepEqual(body.autoDeployJob, body.job, 'legacy response alias carries the current v2 envelope');
        const jobId = body.job.jobId;
        const persisted = await models.TopologyCreateIntent.findById(jobId).lean();
        assert.deepEqual(persisted.executionContext, prod);
        await models.TopologyCreateIntent.updateOne({ _id: jobId }, { $set: {
            'executionContext.target': 'test', 'executionContext.hostIdentity': 'test.infograd.online',
        } });
        assert.deepEqual((await models.TopologyCreateIntent.findById(jobId).lean()).executionContext, prod);
        await service.runOnce();
        const admitted = await service.get(jobId);
        assert.equal(admitted.status, 'admitted', JSON.stringify(admitted));
        const operation = await models.TopologyOperation.findById(admitted.operationId).lean();
        assert.deepEqual(materialized, [prod], 'real materialization must use PROD, not coordinator default TEST');
        assert.deepEqual(operation.executionContext, prod);
        await models.TopologyOperation.updateOne({ _id: operation._id }, { $set: {
            executionContext: TEST_CONTEXT, idempotencyKey: 'unbound-overwrite',
        } });
        const unchanged = await models.TopologyOperation.findById(operation._id).lean();
        assert.deepEqual(unchanged.executionContext, prod);
        assert.equal(unchanged.idempotencyKey, operation.idempotencyKey);
        assert.match(operation.idempotencyKey, /production.*lm1\.infograd\.online/);
        // Admission is not operational PROD authority. Never relabel it TEST or
        // manually fabricate success just to exercise queue settlement.
        assert.equal(operation.status, 'queued'); assert.equal(operation.heldTopologyAdmission, true);
        await service.runOnce();
        assert.equal((await service.get(jobId)).status, 'admitted');
        assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
    } finally { await new Promise(resolve => server.close(resolve)); }
});
test('cloned, missing and cross-paired queue identities never acquire or release ownership', local, async t => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const prod = { target: 'production', hostIdentity: 'lm1.infograd.online' };
    const contexts = [undefined, { target: 'test', hostIdentity: 'test.infograd.online' },
        { target: 'production', hostIdentity: 'test.infograd.online' },
        { target: 'production' }];
    for (const context of contexts) await t.test(JSON.stringify(context) || 'missing', async () => {
        await reset();
        const service = createIntentService({ ...models, executionContext: prod });
        const job = await service.accept({ expectedTopologyRevision: 7, requestKey: 'clone-negative', link: link(0) });
        await models.TopologyCreateIntent.collection.updateOne({ _id: new mongoose.Types.ObjectId(job.jobId) },
            context ? { $set: { executionContext: context } } : { $unset: { executionContext: '' } });
        const before = await models.TopologyCreateIntent.findById(job.jobId).lean();
        const state = await models.CascadeTopologyState.findById('singleton').lean();
        const consumer = new TopologyIntentConsumer({ ...models, executionContext: prod,
            planMaterializer: { materialize() { assert.fail('identity must reject before materialization'); } } });
        await assert.rejects(consumer.runOnce(), { code: 'TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH' });
        assert.deepEqual(await models.TopologyCreateIntent.findById(job.jobId).lean(), before);
        assert.deepEqual(await models.CascadeTopologyState.findById('singleton').lean(), state);
        assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
        assert.equal(await models.CascadeLink.countDocuments(), 0);
        assert.equal(await models.TopologyOperation.countDocuments(), 0);
        await models.TopologyCreateIntent.collection.updateOne({ _id: before._id }, { $set: {
            status: 'claimed', attempts: 3, generation: 9, leaseOwner: 'retained-foreign-owner', leaseUntil: new Date(0),
        } });
        const expired = await models.TopologyCreateIntent.findById(job.jobId).lean();
        await assert.rejects(consumer.runOnce(), { code: 'TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH' });
        assert.deepEqual(await models.TopologyCreateIntent.findById(job.jobId).lean(), expired);
        assert.deepEqual(await models.CascadeTopologyState.findById('singleton').lean(), state);
        assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
    });
});
test('unbound admitted queue heads do not become fresh claims or release capacity', local, async () => {
    await reset();
    const service = createIntentService(models);
    const job = await service.accept({ expectedTopologyRevision: 7, requestKey: 'unbound-negative', link: link(0) });
    await models.TopologyCreateIntent.collection.updateOne({ _id: new mongoose.Types.ObjectId(job.jobId) }, {
        $set: { status: 'admitted', generation: 5, leaseOwner: 'retained-owner', leaseUntil: new Date(0) },
    });
    const before = await models.TopologyCreateIntent.findById(job.jobId).lean();
    await assert.rejects(service.runOnce(), { code: 'TOPOLOGY_INTENT_BINDING_INVALID' });
    assert.deepEqual(await models.TopologyCreateIntent.findById(job.jobId).lean(), before);
    assert.equal(await models.CascadeLink.countDocuments(), 0);
    assert.equal(await models.TopologyOperation.countDocuments(), 0);
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
});
test('intent replay cannot acknowledge a different or unbound execution identity', local, async t => {
    const prod = { target: 'production', hostIdentity: 'lm1.infograd.online' };
    const testContext = { target: 'test', hostIdentity: 'test.infograd.online' };
    for (const recovery of ['normal', 'unknown', 'duplicate']) await t.test(recovery, async () => {
        await reset();
        const payload = link(0);
        const original = createIntentService({ ...models, executionContext: testContext });
        const job = await original.accept({ expectedTopologyRevision: 7, requestKey: 'identity-replay', link: payload });
        const transactionRunner = recovery === 'normal' ? undefined : async () => {
            throw recovery === 'duplicate' ? Object.assign(new Error('duplicate'), { code: 11000 })
                : { hasErrorLabel: label => label === 'UnknownTransactionCommitResult' };
        };
        const service = createIntentService({ ...models, executionContext: prod, transactionRunner });
        await assert.rejects(service.accept({ expectedTopologyRevision: 7, requestKey: 'identity-replay', link: payload }),
            { code: 'TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH' });
        await models.TopologyCreateIntent.collection.updateOne({ _id: new mongoose.Types.ObjectId(job.jobId) }, { $unset: { executionContext: '' } });
        await assert.rejects(original.accept({ expectedTopologyRevision: 7, requestKey: 'identity-replay', link: payload }),
            { code: 'TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH' });
        assert.equal(await models.TopologyCreateIntent.countDocuments(), 1);
        assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
        assert.equal(await models.CascadeLink.countDocuments(), 0);
    });
});
test('settlement rejects cloned and unbound operations without releasing queue ownership', local, async t => {
    const cases = [
        { name: 'missing context', unset: { executionContext: '' }, code: 'TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH' },
        { name: 'cross context', set: { executionContext: { target: 'production', hostIdentity: 'lm1.infograd.online' } }, code: 'TOPOLOGY_INTENT_EXECUTION_CONTEXT_MISMATCH' },
        { name: 'missing key', unset: { idempotencyKey: '' }, code: 'TOPOLOGY_INTENT_BINDING_INVALID' },
        { name: 'foreign key', set: { idempotencyKey: 'topology:production:revision-8:host-lm1.infograd.online:00000000-0000-0000-0000-000000000000' }, code: 'TOPOLOGY_INTENT_BINDING_INVALID' },
        { name: 'other run on same host', set: { idempotencyKey: 'topology:test:revision-8:host-test.infograd.online:00000000-0000-0000-0000-000000000000' }, code: 'TOPOLOGY_INTENT_BINDING_INVALID' },
    ];
    for (const phase of ['queued', 'terminal']) for (const item of cases) await t.test(`${phase}: ${item.name}`, async () => {
        await reset();
        const service = createIntentService(models);
        const job = await service.accept({ expectedTopologyRevision: 7, requestKey: 'settle-identity', link: link(2) });
        await service.runOnce();
        const intent = await models.TopologyCreateIntent.findById(job.jobId).lean();
        assert.equal(intent.status, 'admitted', 'identity corruption must reach a genuine queue binding');
        const operation = await models.TopologyOperation.findById(intent.operationId).lean();
        assert.equal(operation.status, 'queued'); assert.equal(operation.heldTopologyAdmission, true);
        await service.runOnce();
        assert.equal((await service.get(job.jobId)).status, 'admitted', 'a valid nonterminal operation retains capacity');
        if (phase === 'terminal') await finish(operation);
        await models.TopologyOperation.collection.updateOne({ _id: intent.operationId }, {
            ...(item.set ? { $set: item.set } : {}), ...(item.unset ? { $unset: item.unset } : {}),
        });
        const before = await models.TopologyCreateIntent.findById(job.jobId).lean();
        const state = await models.CascadeTopologyState.findById('singleton').lean();
        await assert.rejects(service.runOnce(), { code: item.code });
        assert.deepEqual(await models.TopologyCreateIntent.findById(job.jobId).lean(), before);
        assert.deepEqual(await models.CascadeTopologyState.findById('singleton').lean(), state);
        assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
    });
});
async function finish(operation) {
    assert.ok(operation, 'the intended boundary requires a real admitted operation');
    const { createTopologyOperationRuntime } = require('../runtime/createTopologyOperationRuntime');
    const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
    const calls = [];
    const state = await models.RelayL2tpState.findOne({ node: ids[2] }).select('node status desiredState secretRevision routeGroup activePathKey appliedTopologyRevision').lean();
    assert.equal(state.status, 'not_installed'); assert.equal(state.secretRevision, 0);
    assert.deepEqual(await models.L2tpUser.find({ relayNode: ids[2] }).select('_id').lean(), []);
    assert.equal(await models.L2tpOperation.findOne({ node: ids[2], status: { $in: ['queued', 'running', 'rolling_back'] } }).select('_id').lean(), null);
    const executor = { async prepare(input) { calls.push(['prepare', input.node.node]); return { backupId: `SIMULATED-${input.node.node}`, prepared: {} }; },
        async commit(input) { calls.push(['commit', input.node.node]); return { ok: true }; },
        async verify(input) { calls.push(['verify', input.node.node]); return { ok: true }; },
        async cleanupPrepared() { return { ok: true }; }, async rollback() { assert.fail('unexpected rollback'); } };
    const runtime = createTopologyOperationRuntime({ ...models,
        env: { L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', PANEL_DOMAIN: TEST_CONTEXT.hostIdentity },
        createTopologyOperationExecutor: () => executor,
        OperationWorker: class extends TopologyOperationWorker {
            constructor(input) { super({ ...input, userResync: { async resyncPlan() { return { ok: true }; } },
                pppReadinessGate: { async verifyPlan(plan) {
                    const result = await input.pppReadinessGate.verifyPlan(plan);
                    calls.push(['ppp', result, { staged: plan.staged, kind: plan.kind, routeState: plan.routeState,
                        nodes: plan.nodes.map(({ node, nodeRef, role }) => ({ node, nodeRef, role })) }]);
                    return result;
                } } }); }
        } });
    assert.ok(runtime.operationWorker, 'real local worker/finalizer must assemble');
    const result = await runtime.operationWorker.run(String(operation._id));
    assert.equal(result.status, 'succeeded', JSON.stringify({ result, calls }));
    const persisted = await models.TopologyOperation.findById(operation._id).lean();
    assert.equal(persisted.status, 'succeeded'); assert.equal(persisted.heldTopologyAdmission, false);
    assert.equal(await models.NodeOperationLock.countDocuments({ operationId: String(operation._id) }), 0);
    assert.equal(calls.filter(([method]) => method === 'verify').length, operation.nodes.length);
}
async function continueStoredV1(index) {
    await reset();
    // Historical storage shape, inserted independently of today's accept API.
    // Exercise both forms: prefix staging must not require an installed owner.
    const desired = link(index);
    const payload = JSON.parse(JSON.stringify(new models.CascadeLink({ ...desired,
        active: true, status: 'pending', autoDeploy: true }).toObject()));
    const canonical = value => Array.isArray(value) ? value.map(canonical)
        : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
    const { _id, ...content } = payload;
    const payloadHash = createHash('sha256').update(JSON.stringify(canonical(content))).digest('hex');
    const stored = { _id: new mongoose.Types.ObjectId(), version: 1, executionContext: TEST_CONTEXT,
        requestKey: 'existing-v1-record', payload, payloadHash, ordinal: 1, acceptanceRevision: 7,
        status: 'waiting', attempts: 0, generation: 0, createdAt: new Date(0), updatedAt: new Date(0) };
    await models.TopologyCreateIntent.collection.insertOne(stored);
    await models.TopologyIntentQueueState.create({ _id: 'create-v1', ordinal: 1, outstanding: 1 });
    const persisted = await models.TopologyCreateIntent.findById(stored._id).select('+payload').lean();
    assert.equal((await models.TopologyCreateIntent.findById(stored._id).lean()).payload, undefined, 'real select:false remains intact');
    assert.equal(persisted.kind, undefined); assert.equal(persisted.linkId, undefined);
    assert.equal(persisted.desiredVersion, undefined); assert.equal(persisted.resourceNodeIds, undefined);
    assert.deepEqual(persisted.payload, payload); assert.equal(await models.CascadeLink.countDocuments(), 0);
    const restarted = createIntentService({ ...models, prepareLink() { assert.fail('stored v1 must not regenerate credentials'); } });
    const start = commands.length;
    await restarted.runOnce();
    const bound = await restarted.get(String(stored._id));
    assert.equal(bound.status, 'admitted', JSON.stringify(bound));
    assert.equal(bound.createdLinkId, String(desired._id));
    assert.equal(await models.CascadeLink.countDocuments(), 1); assert.equal(await models.TopologyOperation.countDocuments(), 1);
    const operation = await models.TopologyOperation.findById(bound.operationId).lean();
    assert.equal(operation.kind, 'link.apply'); assert.equal(operation.topologyRevision, 8);
    assert.equal((await models.CascadeLink.findById(desired._id).lean()).tunnelUuid, desired.tunnelUuid);
    assert.ok(commands.slice(start).some(command => command.name === 'find' && command.collection === models.TopologyCreateIntent.collection.name
        && command.id === String(stored._id) && command.projection?.payload !== 0), 'real consumer must load the exact private stored payload');
    await finish(operation);
    await createIntentService(models).runOnce();
    assert.equal((await restarted.get(String(stored._id))).status, 'succeeded');
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 0);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 0);
    assert.equal(await models.TopologyOperation.countDocuments(), 1);
    const terminal = await models.TopologyCreateIntent.findById(stored._id).select('+payload').lean();
    assert.equal(terminal.version, 1); assert.deepEqual(terminal.payload, payload); assert.equal(terminal.payloadHash, payloadHash);
}
test('existing stored v1 backlog continues without a new acceptance or a v2 desired envelope', local, async t => {
    for (const index of [2, 0]) await t.test(index === 2 ? 'source-less suffix' : 'bridge-less prefix', () => continueStoredV1(index));
});

test('legacy autoDeploy pending drafts are neither inferred as intents nor included in a scoped baseline', local, async () => {
    await reset();
    const legacy = link(1);
    await models.CascadeLink.create({ ...legacy, active: true, status: 'pending' });
    const service = createIntentService(models);
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
test('consumer rejects active or missing remote counters and rolls back draft assembly', local, async t => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    for (const remoteCount of [2, undefined]) await t.test(`remote counter ${remoteCount}`, async () => {
        await reset();
        await models.CascadeTopologyState.collection.updateOne({ _id: 'singleton' },
            remoteCount === undefined ? { $unset: { remoteAdmissionCount: '' } }
                : { $set: { remoteAdmissionCount: remoteCount } });
        const service = createIntentService(models);
        const desired = link(0);
        const job = await service.accept({ expectedTopologyRevision: 7,
            requestKey: `remote-counter-${remoteCount}`, link: desired });
        const consumer = new TopologyIntentConsumer({ ...models, executionContext: TEST_CONTEXT });
        const claimed = await consumer.claim();
        const before = await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' });
        await assert.rejects(consumer.consume(claimed), { code: 'TOPOLOGY_DEPLOY_BUSY' });
        assert.equal(await models.CascadeLink.countDocuments(), 0, 'draft creation rolled back');
        assert.equal(await models.CascadeRouteGroup.countDocuments(), 0, 'path maintenance rolled back');
        assert.equal(await models.TopologyOperation.countDocuments(), 0);
        assert.deepEqual(await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' }), before);
        const intent = await models.TopologyCreateIntent.findById(job.jobId).lean();
        assert.equal(intent.status, 'claimed');
        assert.equal(intent.operationId, undefined);
        assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
    });
});

test('mixed-mode links cannot share the same actual listener node and port', local, async t => {
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    for (const mode of ['forward', 'reverse']) await t.test(mode, async () => {
        await reset();
        const desired = { ...link(mode === 'forward' ? 0 : 2), mode };
        const existing = { ...link(mode === 'forward' ? 2 : 0),
            mode: mode === 'forward' ? 'reverse' : 'forward', tunnelPort: desired.tunnelPort };
        await models.CascadeLink.create(existing);
        const service = createIntentService(models);
        const job = await service.accept({ expectedTopologyRevision: 7, requestKey: `same-listener-${mode}`, link: desired });
        const consumer = new TopologyIntentConsumer({ ...models, executionContext: TEST_CONTEXT });
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
        const service = createIntentService(models);
        await service.accept({ expectedTopologyRevision: 7, requestKey: `same-mode-${mode}`, link: desired });
        const consumer = new TopologyIntentConsumer({ ...models, executionContext: TEST_CONTEXT });
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
        const service = createIntentService(models);
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
    const service = createIntentService(models);
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
    const service = createIntentService(models);
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
    const restarted = createIntentService(models);
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
            assert.equal(accepted.desiredSaved, true); assert.equal(accepted.job.version, 2);
            assert.equal(accepted.createdLinkId, accepted.job.linkId); assert.equal(accepted.autoDeployOperation, undefined);
            assert.deepEqual(accepted.autoDeployJob, accepted.job);
            jobs.push(accepted.job);
            if (i === 0) { firstHost.start(); await until(async () => { assert.equal(executions.length, 1); }); }
        }
        assert.equal(await models.CascadeLink.countDocuments(), 4, 'HTTP v2 saves all desired drafts immediately');
        assert.equal(await models.TopologyCreateIntent.countDocuments(), 4);
        assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 11);
        const queued = await (await fetch(`${url}/auto-deploy-jobs/${jobs[3].jobId}`)).json();
        assert.equal(queued.job.status, 'waiting'); assert.equal(queued.job.createdLinkId, jobs[3].linkId);
        let drained = false; const stopping = firstHost.stop().then(() => { drained = true; });
        await new Promise(resolve => setImmediate(resolve)); assert.equal(drained, false);
        release(); await stopping; l2tpActiveHostProvider.clearActiveHost(firstHost);
        secondHost = makeHost(false); l2tpActiveHostProvider.installActiveHost(secondHost); secondHost.start();
        await until(async () => { assert.equal(lifecycles[1].start().inFlight, false); });
        for (let i = 0; i < 4; i++) await ticks[1]();
        assert.equal(await models.TopologyCreateIntent.countDocuments({ status: 'succeeded' }), 4,
            JSON.stringify({ jobs: await models.TopologyCreateIntent.find({}).lean(), ops: await models.TopologyOperation.find({}).select('status heldTopologyAdmission topologyRevision nodes.state').lean() }));
        const operations = await models.TopologyOperation.find({}).sort({ topologyRevision: 1 }).lean();
        // All desired creates committed while the first worker was suspended;
        // selected v2 admission pins the then-current revision without writing it.
        assert.deepEqual(operations.map(row => row.topologyRevision), [8, 11, 11, 11]);
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
    const service = createIntentService({ ...models, capacity: 4 });
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
    const service = createIntentService(models);
    const job = await service.accept({ expectedTopologyRevision: 7, requestKey: 'claim-crash', link: link(0) });
    const old = new TopologyIntentConsumer({ ...models, executionContext: TEST_CONTEXT, clock, owner: 'old', leaseMs: 100 });
    const claim = await old.claim();
    instant = new Date(instant.getTime() + 101);
    const restarted = new TopologyIntentConsumer({ ...models, executionContext: TEST_CONTEXT, clock, owner: 'new', leaseMs: 1000 });
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
    const service = createIntentService({ ...models, clock, maxAttempts: 3, backoffMs: 1,
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
    const accepted = createIntentService(models);
    const job = await accepted.accept({ expectedTopologyRevision: 7, requestKey: 'unknown-commit', link: link(0) });
    const service = createIntentService({ ...models, transactionRunner: async work => {
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
    const restarted = createIntentService(models);
    await restarted.runOnce();
    assert.equal(await models.TopologyOperation.countDocuments(), 1);
    assert.equal(await models.CascadeLink.countDocuments(), 1);
});
test('uncertain predecessor is visible and never requeued, released or bypassed by successors', local, async () => {
    await reset();
    const service = createIntentService(models);
    const first = await service.accept({ expectedTopologyRevision: 7, requestKey: 'uncertain-1', link: link(0) });
    const second = await service.accept({ expectedTopologyRevision: 7, requestKey: 'uncertain-2', link: link(1) });
    await service.runOnce();
    const firstJob = await service.get(first.jobId);
    await models.TopologyOperation.updateOne({ _id: firstJob.operationId }, { $set: { status: 'failed', leaseUntil: new Date(0) } });
    const restarted = createIntentService(models);
    for (let i = 0; i < 4; i++) await restarted.runOnce();
    assert.equal((await restarted.get(first.jobId)).status, 'blocked');
    assert.equal((await restarted.get(first.jobId)).attempts, 1);
    assert.equal((await restarted.get(second.jobId)).status, 'waiting');
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 1);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).revision, 8);
    assert.equal(await models.TopologyOperation.countDocuments(), 1);
});
