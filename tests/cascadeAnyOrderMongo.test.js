'use strict';
// REAL local Mongo replica-set persistence, schemas, indexes, repositories,
// coordinator, consumer and worker/finalizer. Only node execution is simulated.
// No Docker, application .env, remote DB, SSH, Xray or PPP is involved.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID, createHash } = require('node:crypto');
const mongoose = require('mongoose');
Object.assign(process.env, { PANEL_DOMAIN: 'test.infograd.online', ACME_EMAIL: 'scratch@invalid.test',
    ENCRYPTION_KEY: 'anyorder-local-test-key-not-a-production-secret', SESSION_SECRET: 'anyorder-local-session' });
const root = path.resolve(__dirname, '..');
assert.equal(require('node:fs').existsSync(path.join(root, '.env')), false, 'never load application .env');
const moduleEntry = require('../src/modules/relay-l2tp');
const { TopologyDraftRepository } = require('../src/modules/relay-l2tp/repositories/topologyDraftRepository');
const { TopologyDeploymentRepository } = require('../src/modules/relay-l2tp/repositories/topologyDeploymentRepository');
const { TopologyOperationRepository } = require('../src/modules/relay-l2tp/repositories/topologyOperationRepository');
const { TopologyOperationCoordinator } = require('../src/modules/relay-l2tp/services/topologyOperationCoordinator');
const { TopologyOperationPlanMaterializer } = require('../src/modules/relay-l2tp/services/topologyOperationPlanMaterializer');
const { TopologyOperationFinalizationRepository } = require('../src/modules/relay-l2tp/repositories/topologyOperationFinalizationRepository');
const { TopologyOperationFinalizer } = require('../src/modules/relay-l2tp/services/topologyOperationFinalizer');
const { TopologyOperationWorker } = require('../src/modules/relay-l2tp/workers/topologyOperationWorker');
const { NodeOperationLockRepository } = require('../src/modules/relay-l2tp/services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../src/modules/relay-l2tp/services/nodeOperationLockService');
const { TopologyIntentService, linkDesiredVersion } = require('../src/modules/relay-l2tp/services/topologyIntentService');
const { TopologyIntentConsumer } = require('../src/modules/relay-l2tp/services/topologyIntentConsumer');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../src/modules/relay-l2tp/domain/topologyExecutionContext');
const id = n => n.toString(16).padStart(24, '0');
const sha = s => createHash('sha256').update(s).digest('hex');
const privateFields = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +deleteJobId +installedPath';
let models, child, directory, connection, database, port, evidence;
const commands = [], lifecycle = {};
async function until(work, milliseconds = 15000) {
    const deadline = Date.now() + milliseconds; let error;
    while (Date.now() < deadline) { try { return await work(); } catch (e) { error = e; }
        if (child?.exitCode !== null) throw Error(`owned mongod exited ${child?.exitCode}: ${error?.message}`);
        await new Promise(resolve => setTimeout(resolve, 50)); }
    throw error || Error('fixture deadline exceeded');
}
function guarded() {
    assert.match(database, /^c3_anyorder_[a-f0-9]{32}$/);
    assert.equal(connection.name, database);
    assert.equal(connection.host, '127.0.0.1'); assert.equal(connection.port, port);
}
test.before(async () => {
    assert.ok(process.env.C3_MONGOD, 'C3_MONGOD must name an existing pinned local executable; no skipped proof');
    assert.ok(process.env.TMPDIR, 'explicit scratch root required');
    const scratch = await fs.realpath(process.env.TMPDIR);
    assert.ok(scratch.startsWith('/home/leon/.hermes/cache/scratch/'), 'fixture must stay under Hermes scratch');
    directory = await fs.mkdtemp(path.join(scratch, 'c3-anyorder-'));
    evidence = process.env.C3_ANYORDER_MONGO_EVIDENCE;
    if (evidence) await fs.mkdir(evidence, { recursive: true });
    port = await new Promise(resolve => { const server = net.createServer(); server.listen(0, '127.0.0.1', () => {
        const p = server.address().port; server.close(() => resolve(p)); }); });
    database = `c3_anyorder_${randomUUID().replaceAll('-', '')}`;
    const replicaSet = `c3_anyorder_${process.pid}`;
    const logpath = path.join(evidence || directory, `mongod-${process.pid}.log`);
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', replicaSet, '--wiredTigerCacheSizeGB', '0.25', '--oplogSize', '32',
        '--setParameter', 'enableTestCommands=1', '--logpath', logpath], { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = ''; child.stderr.on('data', data => { stderr += data; });
    Object.assign(lifecycle, { pid: child.pid, port, directory, database, replicaSet, logpath, binary: process.env.C3_MONGOD });
    const direct = new mongoose.mongo.MongoClient(`mongodb://127.0.0.1:${port}/admin?directConnection=true`, {
        serverSelectionTimeoutMS: 200, connectTimeoutMS: 500 });
    try {
        await until(() => direct.connect());
        await direct.db('admin').command({ replSetInitiate: { _id: replicaSet, members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await until(async () => assert.equal((await direct.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    } catch (error) { error.message += `; owned mongod stderr: ${stderr}`; throw error; }
    finally { await direct.close(); }
    // Normal replica-set discovery is essential: direct clients may rewrite primary to primaryPreferred.
    const uri = `mongodb://127.0.0.1:${port}/${database}?replicaSet=${replicaSet}&appName=c3-anyorder-acceptance`;
    await mongoose.connect(uri, { monitorCommands: true, serverSelectionTimeoutMS: 5000, maxPoolSize: 5 });
    connection = mongoose.connection; guarded();
    connection.getClient().on('commandStarted', event => {
        if (['find', 'insert', 'update', 'delete', 'commitTransaction', 'abortTransaction'].includes(event.commandName)) {
            // Retain command semantics, never credential/config payload bytes.
            commands.push({ name: event.commandName, databaseName: event.databaseName,
                collection: event.command[event.commandName], autocommit: event.command.autocommit,
                readConcern: event.command.readConcern, readPreference: event.command.$readPreference,
                maxTimeMS: event.command.maxTimeMS, requestKey: event.command.filter?.requestKey,
                projection: event.command.projection });
        }
    });
    models = { ...moduleEntry.registerModels(), HyNode: require('../src/models/hyNodeModel'),
        CascadeLink: require('../src/models/cascadeLinkModel') };
    for (const model of Object.values(models)) { assert.ok(model.db === connection); await model.init(); }
});
test.after(async () => {
    const cleanupErrors = [];
    if (connection?.readyState === 1) {
        try { guarded(); await connection.dropDatabase();
            lifecycle.databaseAbsent = !(await connection.getClient().db('admin').admin().listDatabases()).databases.some(row => row.name === database);
            assert.equal(lifecycle.databaseAbsent, true); } catch (error) { cleanupErrors.push(error.message); }
    }
    require.cache[require.resolve('../src/services/sshPoolService')]?.exports.closeAll();
    await mongoose.disconnect();
    if (child && child.exitCode === null) {
        const exit = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM');
        await Promise.race([exit, new Promise((_, reject) => { const timer = setTimeout(() => reject(Error('owned mongod did not terminate')), 15000); timer.unref(); })]);
    }
    lifecycle.processExited = child?.exitCode !== null;
    if (directory && lifecycle.processExited) { await fs.rm(directory, { recursive: true, force: true });
        lifecycle.directoryAbsent = !require('node:fs').existsSync(directory); }
    lifecycle.portClosed = await new Promise(resolve => { const socket = net.connect({ host: '127.0.0.1', port });
        socket.once('connect', () => { socket.destroy(); resolve(false); }); socket.once('error', () => resolve(true)); });
    if (evidence) {
        await fs.writeFile(path.join(evidence, 'commands.json'), JSON.stringify(commands, null, 2));
        await fs.writeFile(path.join(evidence, 'fixture-lifecycle.json'), JSON.stringify({ ...lifecycle, cleanupErrors }, null, 2));
    }
    assert.deepEqual(cleanupErrors, []); assert.equal(lifecycle.processExited, true);
    assert.equal(lifecycle.directoryAbsent, true); assert.equal(lifecycle.portClosed, true);
});
async function reset() {
    guarded();
    for (const model of Object.values(models)) await model.collection.deleteMany({});
    await models.CascadeTopologyState.create({ _id: 'singleton', revision: 7, deployedRevision: 3,
        remoteAdmissionCount: 0, topologyAdmissionCount: 0 });
    const nodes = ['relay', 'bridge', 'portal', 'bridge'].map((cascadeRole, i) => ({ _id: new mongoose.Types.ObjectId(id(i + 1)),
        cascadeRole, type: 'xray', active: true, ip: `192.0.2.${i + 1}`, port: 443,
        xray: { security: 'none', transport: 'tcp' } }));
    // Explicit local inventory/ownership fixture, NOT physical adoption evidence.
    await models.HyNode.collection.insertMany(nodes);
    await models.TopologyConfigOwner.create(nodes.map((node, i) => ({ node: node._id,
        profile: node.cascadeRole === 'portal' ? 'xray-main' : 'xray-bridge', executionContext: context,
        owner: 'topology', generation: '11111111-1111-4111-8111-111111111111',
        nodeIdentity: { machineId: String(i + 1).repeat(32), sshHostKeySha256: String(i + 1).repeat(64) },
        originalSnapshot: { configSha256: sha('{}'), unitSha256: sha('unit'), serviceActive: 'inactive', serviceEnabled: 'disabled' },
        adoptionReceipt: { fromGeneration: '00000000-0000-4000-8000-000000000000', toGeneration: '11111111-1111-4111-8111-111111111111',
            proofId: '22222222-2222-4222-8222-222222222222', maintenanceId: '33333333-3333-4333-8333-333333333333',
            oldBackendInstanceId: 'local-simulated-owner', oldPid: 1, oldProcessStartTime: 'fixture-only', verifiedAt: new Date() } })));
}
function link(n = 10, source = 1, target = 2) { return { _id: id(n), name: `scratch-${n}`, portalNode: id(source), bridgeNode: id(target),
    mode: 'reverse', active: true, status: 'pending', tunnelPort: 23400 + n, tunnelUuid: randomUUID(),
    tunnelSecurity: 'none', tunnelTransport: 'tcp' }; }
function stack(overrides = {}) {
    const draft = new TopologyDraftRepository(models);
    const deployment = new TopologyDeploymentRepository({ ...models, snapshotReader: draft });
    const operations = new TopologyOperationRepository({ model: models.TopologyOperation,
        topologyStateModel: models.CascadeTopologyState, selectedTopologyRepository: deployment });
    const coordinator = new TopologyOperationCoordinator({ executionContext: context, topologyRepository: deployment,
        operationRepository: operations, planMaterializer: new TopologyOperationPlanMaterializer(models) });
    const calls = [];
    const executor = { async prepare(input) { calls.push(['prepare', input.node]); return { backupId: 'simulated-backup', prepared: {} }; },
        async commit(input) { calls.push(['commit', input.node]); return { ok: true }; },
        async verify(input) { calls.push(['verify', input.node]); return { ok: true }; },
        cleanupPrepared: async () => ({ ok: true }), rollback: async () => ({ ok: true }) };
    const finalization = new TopologyOperationFinalizationRepository({ ...models, selectedTopologyRepository: deployment });
    const clock = { now: () => new Date() };
    const worker = new TopologyOperationWorker({ executionContext: context, operationRepository: operations, executor, clock,
        finalizer: new TopologyOperationFinalizer({ repository: finalization, clock }),
        lockService: new NodeOperationLockService({ repository: new NodeOperationLockRepository({ model: models.NodeOperationLock }), clock }),
        workerId: `local-anyorder-${process.pid}`, leaseMs: 30000, allowUnprovenTestExecution: true,
        selectedTopologyRepository: deployment });
    const dependencies = { ...models, executionContext: context,
        intentDraftWriter: draft.createIntentDraftWriter({ selectedTopologyRepository: deployment }),
        intentOperationAdmission: { db: connection, queue: input => coordinator.queueIntent(input) },
        resolveIntentResources: input => coordinator.resolveIntentResourcesForQueue(input),
        deleteIntentWriter: models.CascadeLink.createDeleteIntentWriter({ CascadeLink: models.CascadeLink }),
        ...overrides };
    return { draft, deployment, operations, coordinator, calls, executor, worker, finalization,
        service: new TopologyIntentService(dependencies), consumer: new TopologyIntentConsumer(dependencies) };
}
async function revision() { return (await models.CascadeTopologyState.findById('singleton').lean()).revision; }
async function apply(f, linkId) { return f.coordinator.queue({ expectedTopologyRevision: await revision(),
    scope: { kind: 'link.apply', linkId, linkIds: [linkId] } }); }
async function operation(id) { return models.TopologyOperation.findById(id).select(privateFields).lean(); }
const acceptance = (key, desired = link()) => ({ version: 2, kind: 'link.create', expectedTopologyRevision: 7, requestKey: key, link: desired });

test('v2 create atomically persists actual draft, intent and counter; restart replay precedes credential generation', async () => {
    await reset(); const f = stack(); const input = acceptance('atomic-create');
    const accepted = await f.service.accept(input);
    assert.equal(accepted.status, 'waiting'); assert.equal(await models.CascadeLink.countDocuments(), 1);
    assert.equal(await models.TopologyCreateIntent.countDocuments(), 1); assert.equal(await models.TopologyOperation.countDocuments(), 0);
    const saved = await models.CascadeLink.findById(accepted.linkId).lean();
    assert.equal(linkDesiredVersion(saved), accepted.desiredVersion); assert.equal(await revision(), 8);
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
    assert.deepEqual(await stack({ prepareLink() { assert.fail('replay must not generate credentials'); } }).service.accept({ ...input, expectedTopologyRevision: 0 }), accepted);
    assert.deepEqual(await models.CascadeLink.findById(accepted.linkId).lean(), saved);
    await assert.rejects(f.service.accept({ ...input, link: { ...input.link, name: 'changed' } }), { code: 'TOPOLOGY_INTENT_KEY_CONFLICT' });
    assert.deepEqual(f.calls, []);
});
test('injected precommit resource failure rolls back real link, intent, queue and topology revision together', async () => {
    await reset(); const before = await models.CascadeTopologyState.findById('singleton').lean();
    const f = stack({ resolveIntentResources() { throw Object.assign(Error('injected after actual draft insert'), { code: 'INJECTED_PRECOMMIT' }); } });
    await assert.rejects(f.service.accept(acceptance('abort-create')), { code: 'INJECTED_PRECOMMIT' });
    assert.equal(await models.CascadeLink.countDocuments(), 0); assert.equal(await models.TopologyCreateIntent.countDocuments(), 0);
    assert.equal(await models.TopologyIntentQueueState.countDocuments(), 0);
    assert.deepEqual(await models.CascadeTopologyState.findById('singleton').lean(), before);
});
test('actual unique request-key and node-lock indexes reject collisions without losing the original rows', async () => {
    await reset(); const f = stack(); const job = await f.service.accept(acceptance('unique-key'));
    const existing = await models.TopologyCreateIntent.findById(job.jobId).select('+payload').lean();
    const indexes = await models.TopologyCreateIntent.collection.indexes();
    assert.ok(indexes.some(index => index.unique && index.key.requestKey === 1));
    await assert.rejects(models.TopologyCreateIntent.create({ ...existing, _id: new mongoose.Types.ObjectId(), ordinal: 2 }), { code: 11000 });
    const lock = { node: id(1), owner: 'winner', operationId: 'fixture-winner', generation: randomUUID(),
        leaseUntil: new Date(Date.now() + 60000), remoteUncertain: true };
    await models.NodeOperationLock.create(lock);
    await assert.rejects(models.NodeOperationLock.create({ ...lock, owner: 'loser', generation: randomUUID() }), { code: 11000 });
    assert.equal((await models.NodeOperationLock.findOne({ node: id(1) }).lean()).generation, lock.generation);
    assert.equal(await models.TopologyCreateIntent.countDocuments(), 1);
});
test('injected postcommit response loss confirms exactly one real acceptance with bounded primary-majority readback', async () => {
    await reset(); let transactions = 0; const start = commands.length;
    const f = stack({ transactionRunner: async work => {
        transactions++; await connection.transaction(work, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
        throw Object.assign(Error('INJECTED response loss AFTER actual successful commit, not a wire failure'), {
            hasErrorLabel: label => label === 'UnknownTransactionCommitResult' });
    } });
    const accepted = await f.service.accept(acceptance('response-loss'));
    const readbacks = commands.slice(start).filter(command => command.name === 'find' && command.requestKey === 'response-loss' && command.autocommit !== false);
    assert.equal(transactions, 1); assert.equal(readbacks.length, 1);
    assert.equal(readbacks[0].readConcern.level, 'majority');
    assert.ok(!readbacks[0].readPreference || readbacks[0].readPreference.mode === 'primary');
    assert.ok(readbacks[0].maxTimeMS > 0 && readbacks[0].maxTimeMS <= 5000);
    assert.equal(await models.CascadeLink.countDocuments(), 1); assert.equal(await models.TopologyCreateIntent.countDocuments(), 1);
    assert.equal((await stack().service.get(accepted.jobId)).status, 'waiting');
});
test('selected actual repository/worker settles source-less apply after unrelated revision drift', async t => {
    await reset(); await models.CascadeLink.create(link()); const f = stack();
    const queued = await apply(f, id(10));
    await models.CascadeTopologyState.updateOne({ _id: 'singleton' }, { $inc: { revision: 1 } });
    const result = await f.worker.run(queued.operationId); t.diagnostic(JSON.stringify(result));
    assert.equal(result.status, 'succeeded');
    const persisted = await operation(queued.operationId);
    assert.equal(persisted.admissionScope, 'selected'); assert.equal(persisted.heldTopologyAdmission, false);
    assert.equal((await models.CascadeLink.findById(id(10)).lean()).status, 'staged');
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).deployedRevision, 3);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 0);
    assert.equal(await models.NodeOperationLock.countDocuments(), 0);
    assert.equal((await models.TopologyConfigOwner.findOne({ node: id(1) }).lean()).lastSettledOperation, queued.operationId);
});
test('REQUIRED real v2 consumer binds an operation using the unmodified select:false operation schema', async t => {
    await reset(); const f = stack(); const accepted = await f.service.accept(acceptance('consumer-binding'));
    const claimed = await f.consumer.claim(); assert.equal(String(claimed._id), accepted.jobId);
    try { const queued = await f.consumer.consumeVersioned(claimed);
        assert.equal((await f.service.get(accepted.jobId)).status, 'admitted');
        assert.equal((await operation(queued.operationId)).heldTopologyAdmission, true);
    } catch (error) {
        t.diagnostic(JSON.stringify({ code: error.code, message: error.message, stack: error.stack,
            operationsAfterAbort: await models.TopologyOperation.countDocuments(),
            admissionCount: (await models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount }));
        throw error;
    }
});
test('selected actual admission rejects overlap but permits disjoint work while uncertainty retains exact generations', async t => {
    await reset(); await models.CascadeLink.create([link(), link(11, 3, 4)]); const f = stack();
    const first = await apply(f, id(10));
    await assert.rejects(apply(stack(), id(10)), { code: 'TOPOLOGY_DEPLOY_BUSY' });
    f.executor.prepare = async () => { throw Error('INJECTED uncertain node executor, not a live writer'); };
    const failed = await f.worker.run(first.operationId); t.diagnostic(JSON.stringify(failed));
    assert.equal(failed.status, 'failed'); const retained = await models.NodeOperationLock.find({}).lean();
    assert.equal(retained.length, 2); assert.equal((await operation(first.operationId)).heldTopologyAdmission, true);
    const independent = stack(); const second = await apply(independent, id(11));
    assert.equal((await independent.worker.run(second.operationId)).status, 'succeeded');
    const after = await models.NodeOperationLock.find({}).lean();
    assert.deepEqual(after.map(row => row.generation).sort(), retained.map(row => row.generation).sort());
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 1);
});
test('selected actual delete retains job-bound tombstone through readback, removes it atomically and recreates same-port', async t => {
    await reset(); await models.CascadeLink.create(link()); const f = stack();
    const first = await apply(f, id(10)); assert.equal((await f.worker.run(first.operationId)).status, 'succeeded');
    const original = await models.CascadeLink.findById(id(10)).lean();
    const job = await f.service.accept({ version: 2, kind: 'link.delete', expectedTopologyRevision: await revision(),
        requestKey: 'delete-tombstone', linkId: id(10), desiredVersion: linkDesiredVersion(original) });
    const tombstone = await models.CascadeLink.findById(id(10)).lean();
    assert.equal(String(tombstone.lifecycle.deleteJobId), job.jobId);
    let queued;
    // Independent exact joined repository acceptance, not a substitute consumer or facade.
    // The separate REQUIRED consumer test above stays RED if its real projection is broken.
    await connection.transaction(async session => {
        queued = await f.coordinator.queueIntent({ session, executionContext: context, intentId: job.jobId,
            mutation: { kind: 'link.delete', linkId: id(10), desiredVersion: job.desiredVersion },
            expectedTopologyRevision: await revision(), resourceNodeIds: [id(1), id(2)] });
    });
    f.executor.verify = async () => { assert.equal(String((await models.CascadeLink.findById(id(10)).lean()).lifecycle.deleteJobId), job.jobId); return { ok: true }; };
    const result = await f.worker.run(queued.operationId); t.diagnostic(JSON.stringify(result));
    assert.equal(result.status, 'succeeded'); assert.equal(await models.CascadeLink.findById(id(10)).lean(), null);
    assert.equal(await models.NodeOperationLock.countDocuments(), 0);
    const replacement = { ...original, _id: id(12), status: 'pending' }; delete replacement.lifecycle;
    await models.CascadeLink.create(replacement); await models.CascadeTopologyState.updateOne({ _id: 'singleton' }, { $inc: { revision: 1 } });
    f.executor.verify = async () => ({ ok: true });
    const recreated = await apply(stack(), id(12)); assert.equal((await stack().worker.run(recreated.operationId)).status, 'succeeded');
    assert.equal((await models.CascadeLink.findById(id(12)).lean()).tunnelPort, original.tunnelPort);
});

test('concurrent v2 capacity admits exactly the bound and rolls all overflow counter changes back', async () => {
    await reset(); await models.CascadeLink.create(link()); const f = stack({ capacity: 2 });
    const desiredVersion = linkDesiredVersion(await models.CascadeLink.findById(id(10)).lean());
    const results = await Promise.allSettled(Array.from({ length: 6 }, (_, i) => f.service.accept({ version: 2,
        kind: 'link.apply', requestKey: `capacity-${i}`, expectedTopologyRevision: 7, linkId: id(10), desiredVersion })));
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 2);
    const refused = results.filter(result => result.status === 'rejected');
    assert.equal(refused.length, 4); assert.ok(refused.every(result => result.reason.code === 'TOPOLOGY_INTENT_BACKLOG_FULL'));
    const queue = await models.TopologyIntentQueueState.findById('create-v1').lean();
    assert.equal(queue.outstanding, 2); assert.equal(queue.ordinal, 2);
    assert.equal(await models.TopologyCreateIntent.countDocuments(), 2); assert.equal(await models.CascadeLink.countDocuments(), 1);
    assert.equal(await revision(), 7);
});
test('real FIFO claims bypass a leased overlapping predecessor only for disjoint resources without spending attempts', async () => {
    await reset(); await models.CascadeLink.create([link(), link(11, 3, 4)]); const f = stack();
    const jobs = [];
    for (const [i, linkId] of [id(10), id(10), id(11)].entries()) jobs.push(await f.service.accept({
        version: 2, kind: 'link.apply', requestKey: `fifo-${i}`, expectedTopologyRevision: 7, linkId,
        desiredVersion: linkDesiredVersion(await models.CascadeLink.findById(linkId).lean()) }));
    const first = await f.consumer.claim(); assert.equal(String(first._id), jobs[0].jobId);
    const independent = await stack().consumer.claim(); assert.equal(String(independent._id), jobs[2].jobId);
    const waiting = await models.TopologyCreateIntent.findById(jobs[1].jobId).lean();
    assert.equal(waiting.status, 'waiting'); assert.equal(waiting.waitingReason, 'TOPOLOGY_INTENT_RESOURCE_BUSY');
    assert.equal(waiting.attempts, 0); assert.equal(await models.TopologyOperation.countDocuments(), 0);
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 3);
});
test('expired real claim generation cannot assemble or decrement the replacement generation', async () => {
    await reset(); const f = stack(); const job = await f.service.accept(acceptance('expired-claim'));
    const stale = await f.consumer.claim();
    await models.TopologyCreateIntent.updateOne({ _id: stale._id }, { $set: { leaseUntil: new Date(0) } });
    const next = await stack().consumer.claim(); assert.equal(next.generation, stale.generation + 1);
    const before = await models.TopologyCreateIntent.findById(job.jobId).lean();
    await assert.rejects(f.consumer.consumeVersioned(stale), { code: 'TOPOLOGY_INTENT_FENCE_LOST' });
    assert.deepEqual(await models.TopologyCreateIntent.findById(job.jobId).lean(), before);
    assert.equal(await models.TopologyOperation.countDocuments(), 0);
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
});
test('real failCommand readback error after injected response loss never acknowledges the committed v2 job', async () => {
    await reset(); let transactions = 0;
    const f = stack({ transactionRunner: async work => {
        transactions++; await connection.transaction(work, { writeConcern: { w: 'majority' } });
        await connection.getClient().db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 },
            data: { failCommands: ['find'], errorCode: 50 } });
        throw Object.assign(Error('INJECTED postcommit response loss'), {
            hasErrorLabel: label => label === 'UnknownTransactionCommitResult' });
    } });
    try { await assert.rejects(f.service.accept(acceptance('unreadable-commit')), { code: 50 }); }
    finally { await connection.getClient().db('admin').command({ configureFailPoint: 'failCommand', mode: 'off' }); }
    assert.equal(transactions, 1); assert.equal(await models.CascadeLink.countDocuments(), 1);
    assert.equal(await models.TopologyCreateIntent.countDocuments({ status: 'waiting' }), 1);
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 1);
});
test('REQUIRED real consumer settles an actual selected success (explicit binding fixture isolates settlement projection)', async t => {
    await reset(); await models.CascadeLink.create(link()); const f = stack();
    const desiredVersion = linkDesiredVersion(await models.CascadeLink.findById(id(10)).lean());
    const job = await f.service.accept({ version: 2, kind: 'link.apply', requestKey: 'settlement-projection',
        expectedTopologyRevision: 7, linkId: id(10), desiredVersion });
    // The production consumeVersioned path is tested separately above, without alteration.
    // Seed only its persisted binding after REAL repository admission to reach settle independently.
    let queued;
    await connection.transaction(async session => {
        queued = await f.coordinator.queueIntent({ session, executionContext: context, intentId: job.jobId,
            mutation: { kind: 'link.apply', linkId: id(10), desiredVersion }, expectedTopologyRevision: 7,
            resourceNodeIds: [id(1), id(2)] });
        const op = await models.TopologyOperation.findById(queued.operationId).select(privateFields).session(session).lean();
        await models.TopologyCreateIntent.updateOne({ _id: job.jobId, status: 'waiting' }, { $set: {
            status: 'admitted', operationId: op._id, topologyRevision: op.topologyRevision,
            priorDeployedRevision: op.priorDeployedRevision, operationIdempotencyKey: op.idempotencyKey,
            admissionFingerprint: op.admissionFingerprint } }, { session });
    });
    assert.equal((await f.worker.run(queued.operationId)).status, 'succeeded');
    try { assert.equal(await stack().consumer.settle(await models.TopologyCreateIntent.findById(job.jobId).lean()), true); }
    catch (error) { t.diagnostic(JSON.stringify({ code: error.code,
        persistedOperation: (await operation(queued.operationId)).status,
        outstanding: (await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding })); throw error; }
    assert.equal((await f.service.get(job.jobId)).status, 'succeeded');
    assert.equal((await models.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 0);
});

const permutations = values => values.length ? values.flatMap((value, index) =>
    permutations(values.filter((_, i) => i !== index)).map(rest => [value, ...rest])) : [[]];
const repositoryMatrix = [
    { graph: 'G1', edges: [[10, 3, 2, 'reverse']] },
    { graph: 'G2', edges: [[10, 3, 1, 'forward'], [11, 1, 2, 'reverse']] },
    { graph: 'G3', edges: [[10, 3, 1, 'reverse'], [11, 1, 2, 'forward'], [12, 1, 4, 'reverse']] },
].flatMap(({ graph, edges }) => permutations(edges).map(order => ({ graph, order })));
for (const { graph, order } of repositoryMatrix) test(`${graph} actual Mongo selected repository create=${order.map(edge => edge[0]).join(',')} delete/recreate`, async t => {
    await reset(); const f = stack(); const history = [];
    const writes = new (require('../src/modules/relay-l2tp/services/topologyDraftWriteService').TopologyDraftWriteService)({ repository: f.draft });
    for (const [n, source, target, mode] of order) {
        const desired = { ...link(n, source, target), mode,
            ...(n === 12 ? { geoRouting: { enabled: true, geoip: ['ru'], domains: ['category-ru'] } } : {}) };
        await writes.createLink({ expectedTopologyRevision: await revision(), link: desired });
        const queued = await apply(f, id(n)); const result = await f.worker.run(queued.operationId);
        assert.equal(result.status, 'succeeded', JSON.stringify({ graph, n, result }));
        const op = await operation(queued.operationId);
        history.push({ phase: 'apply', linkId: id(n), operationId: queued.operationId, routeState: op.routeState, linkIds: op.linkIds });
        assert.equal(op.effectiveTopology.links.length, history.length);
        assert.equal(await models.NodeOperationLock.countDocuments(), 0);
    }
    assert.equal((await operation(history.at(-1).operationId)).routeState, 'complete');
    const [n] = order[0]; const original = await models.CascadeLink.findById(id(n)).lean();
    const job = await f.service.accept({ version: 2, kind: 'link.delete', expectedTopologyRevision: await revision(),
        requestKey: 'matrix-delete', linkId: id(n), desiredVersion: linkDesiredVersion(original) });
    let removed;
    await connection.transaction(async session => {
        const resources = await f.coordinator.resolveIntentResourcesForQueue({ kind: 'link.delete', link: original,
            desiredVersion: job.desiredVersion, session });
        removed = await f.coordinator.queueIntent({ session, executionContext: context, intentId: job.jobId,
            mutation: { kind: 'link.delete', linkId: id(n), desiredVersion: job.desiredVersion },
            expectedTopologyRevision: await revision(), resourceNodeIds: resources });
    });
    assert.equal((await f.worker.run(removed.operationId)).status, 'succeeded');
    assert.equal(await models.CascadeLink.findById(id(n)).lean(), null);
    history.push({ phase: 'delete', linkId: id(n), operationId: removed.operationId });
    // New ID, same desired endpoints/port; actual writer + baseline retain the other applied edges.
    const recreatedId = id(30); const replacement = { ...original, _id: recreatedId, status: 'pending' }; delete replacement.lifecycle;
    await writes.createLink({ expectedTopologyRevision: await revision(), link: replacement });
    const recreated = await apply(stack(), recreatedId); assert.equal((await stack().worker.run(recreated.operationId)).status, 'succeeded');
    const final = await operation(recreated.operationId);
    assert.equal(final.routeState, 'complete'); assert.equal(final.effectiveTopology.links.length, order.length);
    assert.equal(final.effectiveTopology.links.some(edge => edge.id === id(n)), false);
    assert.equal(final.effectiveTopology.links.find(edge => edge.id === recreatedId).tunnelPort, original.tunnelPort);
    assert.equal(await models.NodeOperationLock.countDocuments(), 0);
    assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 0);
    history.push({ phase: 'recreate', linkId: recreatedId, operationId: recreated.operationId });
    t.diagnostic(JSON.stringify({ graph, order: order.map(edge => edge[0]), history }));
});
