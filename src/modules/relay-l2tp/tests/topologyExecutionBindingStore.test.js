'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const modulePath = path.join(__dirname, '../repositories/topologyExecutionBindingStore.js');
const contract = fs.existsSync(modulePath) ? require(modulePath) : {};
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');

test('dormant binding store requires exact trusted PROD context and scoped external authority', () => {
    assert.equal(typeof contract.TopologyExecutionBindingStore, 'function', 'durable binding store is missing');
    for (const executionContext of [undefined, { ...PROD, forged: true },
        { target: 'production', hostIdentity: 'test.infograd.online' },
        { target: 'test', hostIdentity: 'test.infograd.online' }]) {
        assert.throws(() => new contract.TopologyExecutionBindingStore({ executionContext }), /server-owned production context/);
    }
    assert.throws(() => new contract.TopologyExecutionBindingStore({ executionContext: PROD }), /external authority/);
});

const fsp = require('node:fs/promises');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID, createHash } = require('node:crypto');
const mongoose = require('mongoose');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');
const { freeze, bindingRecord } = require('./helpers/topologyV2Fixture');
let connection, child, directory, models;
const dbName = `binding_scratch_${randomUUID().replaceAll('-', '')}`;
const NODE = '507f1f77bcf86cd799439011';
const IDENTITY = freeze({ machineId: '1'.repeat(32), sshHostKeySha256: '2'.repeat(64) });
const OWNER_GENERATION = randomUUID();
const PREDECESSOR = randomUUID();
const BOOT = randomUUID();
const content = '{"inbounds":[],"outbounds":[{"tag":"direct"}],"routing":{"rules":[]}}\n';
const hash = createHash('sha256').update(content).digest('hex');
const frozenNode = freeze({ node: NODE, nodeRef: 'portal', role: 'portal', targetProfile: 'xray-main',
    configPath: '/usr/local/etc/xray/config.json', serviceUnit: 'xray.service',
    serviceUnitPath: '/etc/systemd/system/xray.service', checks: [], candidateHash: hash,
    candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1',
        bytes: [...Buffer.from(content)], sha256: hash } });
async function until(work) {
    let error;
    for (let i = 0; i < 120; i++) {
        try { return await work(); } catch (e) { error = e; }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw error;
}
test.before(async () => {
    assert.ok(process.env.C3_MONGOD, 'C3_MONGOD must name an isolated local Mongo binary; no skipped proof');
    assert.ok(process.env.TMPDIR, 'scratch files require TMPDIR');
    directory = await fsp.mkdtemp(path.join(process.env.TMPDIR, 'c3-binding-db-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => { const p = server.address().port; server.close(() => resolve(p)); });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', 'bindingScratch', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const uri = `mongodb://127.0.0.1:${port}/${dbName}?directConnection=true`;
    const client = new mongoose.mongo.MongoClient(uri, { serverSelectionTimeoutMS: 100 });
    try {
        await until(() => client.connect());
        await client.db('admin').command({ replSetInitiate: { _id: 'bindingScratch', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
        assert.equal((await client.db('admin').admin().listDatabases()).databases.some(db => db.name === dbName), false);
    } finally { await client.close(); }
    connection = await mongoose.createConnection(uri.replace('?directConnection=true', '?replicaSet=bindingScratch'),
        { serverSelectionTimeoutMS: 1000, monitorCommands: true }).asPromise();
});
test.after(async () => {
    try {
        if (connection) {
            assert.match(dbName, /^binding_scratch_[a-f0-9]{32}$/);
            await connection.dropDatabase();
            assert.equal((await connection.getClient().db('admin').admin().listDatabases()).databases.some(db => db.name === dbName), false);
            await connection.close();
        }
    } finally {
        if (child && child.exitCode === null) {
            const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM'); await exited;
        }
        if (directory) await fsp.rm(directory, { recursive: true, force: true });
    }
});
function evidence(challenge, changes = {}) {
    return { authority: 'external-execution-maintenance-v1', status: 'verified', challenge: structuredClone(challenge),
        proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
        bootstrapWriters: 'excluded', physicalIdentity: { ...IDENTITY }, owner: 'topology',
        predecessor: { generation: PREDECESSOR, bootId: BOOT, status: 'pre-enrolled' },
        oldBackend: { instanceId: 'simulated-old-prod', pid: 42, processStartTime: 'simulated-start',
            processTree: 'stopped', dispatch: 'disabled' }, ...changes };
}
const goodAuthority = async (challenge, work) => work(evidence(challenge));
const missingInstanceAuthority = async (challenge, work) => {
    const proof = evidence(challenge);
    delete proof.oldBackend.instanceId;
    return work(proof);
};
function newStore(authority = goodAuthority) {
    return new contract.TopologyExecutionBindingStore({ executionContext: PROD, withVerifiedAuthority: authority, ...models });
}
async function assembled(store, { onResolved, onBootstrap } = {}) {
    const { TopologyOperationExecutor } = require('../services/topologyOperationExecutor');
    const { TopologyNodeExecutionResolver } = require('../services/topologyNodeExecutionResolver');
    const { runnerRequest, v2Receipt } = require('./helpers/topologyV2Fixture');
    const events = [];
    const Node = connection.models.BindingLocalNode || connection.model('BindingLocalNode', new mongoose.Schema({
        ip: String, name: String, type: String, active: Boolean, cascadeRole: String,
        ssh: { port: Number, username: String, privateKey: String },
    }));
    await Node.deleteMany({});
    await Node.create({ _id: NODE, ip: '192.0.2.17', name: 'local-only', type: 'xray', active: true,
        cascadeRole: 'portal', ssh: { port: 22, username: 'synthetic', privateKey: 'synthetic-local-fixture-not-a-key' } });
    class LocalSSH {
        constructor() { events.push('ssh-adapter'); }
        async writeFile() { events.push('local-upload'); }
        async exec(command) {
            const request = runnerRequest(command);
            events.push(request);
            return { code: 0, stdout: `${JSON.stringify(v2Receipt(request))}\n`, stderr: '' };
        }
    }
    class LocalBootstrapper { async ensureRunner() { events.push('local-bootstrap'); await onBootstrap?.(); } }
    const resolver = new TopologyNodeExecutionResolver({ ...PROD, NodeSSH: LocalSSH,
        HyNode: { findById(id) { events.push('node-read'); return Node.findById(id); } } });
    const executor = new TopologyOperationExecutor({ ...PROD, nodeExecutionResolver: {
        async resolve(request) { const ssh = await resolver.resolve(request); await onResolved?.(); return ssh; },
    },
        RunnerBootstrapper: LocalBootstrapper, ...(store ? { executionBindingReader: store } : {}) });
    return { executor, events, Node };
}
async function setup(authority = goodAuthority) {
    if (!models) {
        const bind = (name, location) => connection.model(name, require(location).schema);
        models = {
            Operation: bind('TopologyOperation', '../models/topologyOperationModel'),
            Lock: bind('NodeOperationLock', '../models/nodeOperationLockModel'),
            Owner: bind('TopologyConfigOwner', '../../../models/topologyConfigOwnerModel'),
            Enrollment: bind('TopologyExecutionEnrollment', '../models/topologyExecutionEnrollmentModel'),
            Binding: bind('TopologyExecutionBinding', '../models/topologyExecutionBindingModel'),
        };
        await Promise.all(Object.values(models).map(model => model.init()));
    }
    // Administrative fixture cleanup uses raw collections; public immutable models refuse mutation.
    await Promise.all(Object.values(models).map(model => model.collection.deleteMany({})));
    const operationId = new mongoose.Types.ObjectId().toString();
    const context = { operationId, topologyRevision: 17, priorDeployedRevision: 16, node: frozenNode,
        executionFence: freeze({ owner: 'worker-17', attempt: 1, generation: randomUUID() }) };
    const repository = new TopologyOperationRepository({ model: models.Operation });
    await connection.transaction(async session => repository.createFrozen({ operationId, executionContext: PROD,
        idempotencyKey: `topology:production:revision-17:host-${PROD.hostIdentity}:${randomUUID()}`,
        topologyRevision: 17, priorDeployedRevision: 16, nodes: [frozenNode], heldTopologyAdmission: true,
        admissionFingerprint: 'f'.repeat(64), session }));
    await repository.claim({ operationId, executionContext: PROD, owner: 'worker-17', now: new Date(), leaseMs: 120000 });
    await new NodeOperationLockRepository({ model: models.Lock }).acquireLease({ node: NODE, operationId,
        owner: 'worker-17', generation: context.executionFence.generation, leaseUntil: new Date(Date.now() + 120000) });
    await models.Owner.create({ executionContext: PROD, node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY,
        owner: 'topology', generation: OWNER_GENERATION,
        originalSnapshot: { configSha256: '3'.repeat(64), unitSha256: '4'.repeat(64), serviceActive: 'active', serviceEnabled: 'enabled' },
        adoptionReceipt: { proofId: randomUUID(), maintenanceId: randomUUID(), fromGeneration: randomUUID(),
            toGeneration: OWNER_GENERATION, oldBackendInstanceId: 'simulated-old-prod', oldPid: 42,
            oldProcessStartTime: 'simulated-start', verifiedAt: new Date() } });
    const { attemptId: _a, predecessorGeneration: _p, commandIds: _c, ...expected } = bindingRecord(context, PROD.hostIdentity);
    const store = new contract.TopologyExecutionBindingStore({ executionContext: PROD, withVerifiedAuthority: authority, ...models });
    return { store, context, expected: freeze(expected), enrollment: freeze({ nodeId: NODE, targetProfile: 'xray-main',
        nodeIdentity: IDENTITY, ownerGeneration: OWNER_GENERATION, predecessorGeneration: PREDECESSOR, bootId: BOOT }) };
}

test('actual Mongo stores pre-enrollment and insert-only execution binding; fresh reader verifies exact accepted operation and acquired lock', async () => {
    assert.equal(typeof contract.TopologyExecutionBindingStore.prototype.preEnroll, 'function', 'pre-enrollment is missing');
    const { store, expected, enrollment } = await setup();
    const enrolled = await store.preEnroll(enrollment);
    const row = await store.createBinding(expected);
    assert.equal(enrolled.predecessorGeneration, PREDECESSOR);
    assert.deepEqual(Object.fromEntries(Object.keys(expected).map(key => [key, row[key]])), expected);
    assert.equal(row.predecessorGeneration, PREDECESSOR);
    assert.match(row.attemptId, /^[a-f0-9-]{36}$/);
    assert.equal(new Set(Object.values(row.commandIds)).size, 4);
    assert.equal(Object.isFrozen(row), true);
    assert.equal(Object.isFrozen(row.commandIds), true);
    assert.equal(await models.Binding.countDocuments(), 1);
    const restarted = new contract.TopologyExecutionBindingStore({ executionContext: PROD, withVerifiedAuthority: goodAuthority, ...models });
    assert.deepEqual(await restarted.readVerified(expected), row);
    await assert.rejects(store.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_CONFLICT' });
    assert.equal(await models.Binding.countDocuments(), 1);
});

test('assembled executor refuses a cloned binding with extra persisted authority fields before resolver or SSH', async () => {
    const { store, expected, enrollment, context } = await setup();
    await store.preEnroll(enrollment);
    await store.createBinding(expected);
    await models.Binding.collection.updateOne({}, { $set: { clone: true } });
    const { executor, events } = await assembled(store);
    await assert.rejects(executor.prepare(context), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.deepEqual(events, []);
    assert.equal((await models.Lock.findOne().lean()).generation, expected.generation);
    assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
});

test('enrollment rejects old-backend proof missing its instance identity without inserting a row', async () => {
    const { store, enrollment } = await setup(missingInstanceAuthority);
    await assert.rejects(store.preEnroll(enrollment), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.equal(await models.Enrollment.countDocuments(), 0);
});

test('missing enrollment, caller-supplied IDs/proofs and non-enrolled predecessor never create or infer authority', async t => {
    const { store, expected, enrollment } = await setup();
    await assert.rejects(store.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    for (const predecessorGeneration of [undefined, 'none', '', expected.generation]) {
        await t.test(`predecessor ${String(predecessorGeneration)}`, async () => {
            if (predecessorGeneration === expected.generation) {
                // Even an explicit current generation cannot be the enrolled predecessor.
                const authority = async (challenge, work) => work(evidence(challenge,
                    { predecessor: { generation: predecessorGeneration, bootId: BOOT, status: 'pre-enrolled' } }));
                const custom = newStore(authority);
                await custom.preEnroll(freeze({ ...enrollment, predecessorGeneration }));
                await assert.rejects(custom.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
                await models.Enrollment.collection.deleteMany({});
            } else await assert.rejects(store.preEnroll({ ...enrollment, predecessorGeneration }), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        });
    }
    await store.preEnroll(enrollment);
    for (const extra of [{ attemptId: randomUUID() }, { commandIds: {} }, { predecessorGeneration: PREDECESSOR },
        { proof: evidence({}) }, { target: 'production' }]) {
        await assert.rejects(store.createBinding(freeze({ ...expected, ...extra })), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    }
    assert.equal(await models.Binding.countDocuments(), 0);
});

test('all authority stages fail closed on absent old-writer, physical, owner, bootstrap or predecessor proof', async t => {
    const mutations = {
        noCallback: null,
        noProof: () => undefined,
        unheld: proof => ({ ...proof, maintenance: 'released' }),
        oldDispatch: proof => ({ ...proof, oldBackend: { ...proof.oldBackend, dispatch: 'enabled' } }),
        oldWriter: proof => ({ ...proof, oldBackend: { ...proof.oldBackend, processTree: 'unknown' } }),
        oldIdentity: proof => ({ ...proof, oldBackend: { ...proof.oldBackend, instanceId: undefined } }),
        bootstrap: proof => ({ ...proof, bootstrapWriters: 'unknown' }),
        owner: proof => ({ ...proof, owner: 'classic' }),
        physicalClone: proof => ({ ...proof, physicalIdentity: { ...IDENTITY, machineId: 'f'.repeat(32) } }),
        foreignPredecessor: proof => ({ ...proof, predecessor: { ...proof.predecessor, generation: randomUUID() } }),
        foreignBoot: proof => ({ ...proof, predecessor: { ...proof.predecessor, bootId: randomUUID() } }),
        forgedChallenge: proof => ({ ...proof, challenge: { ...proof.challenge, nonce: randomUUID() } }),
    };
    for (const [label, mutate] of Object.entries(mutations)) await t.test(label, async () => {
        const { store, expected, enrollment } = await setup();
        const authority = mutate ? async (challenge, work) => work(mutate(evidence(challenge))) : async () => true;
        const denied = newStore(authority);
        await assert.rejects(denied.preEnroll(enrollment), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        assert.equal(await models.Enrollment.countDocuments(), 0);
        await store.preEnroll(enrollment);
        await assert.rejects(denied.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        assert.equal(await models.Binding.countDocuments(), 0);
        await store.createBinding(expected);
        await assert.rejects(denied.readVerified(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        assert.equal(await models.Binding.countDocuments(), 1);
    });
});

test('actual transactional CAS denies wrong context, claim attempt/owner, revision, node/profile, candidate, missing or foreign acquired generation', async t => {
    const mutations = {
        foreignContext: async () => models.Operation.collection.updateOne({}, { $set: { executionContext: { target: 'test', hostIdentity: 'test.infograd.online' } } }),
        clonedContext: async () => models.Operation.collection.updateOne({}, { $set: { 'executionContext.clone': true } }),
        missingContext: async () => models.Operation.collection.updateOne({}, { $unset: { executionContext: 1 } }),
        malformedAcceptedKey: async () => models.Operation.collection.updateOne({}, { $set: { idempotencyKey: 'forged' } }),
        revision: async () => models.Operation.collection.updateOne({}, { $set: { topologyRevision: 18 } }),
        priorRevision: async () => models.Operation.collection.updateOne({}, { $set: { priorDeployedRevision: 15 } }),
        owner: async () => models.Operation.collection.updateOne({}, { $set: { leaseOwner: 'foreign-worker' } }),
        attempt: async () => models.Operation.collection.updateOne({}, { $set: { attempts: 2 } }),
        expiredClaim: async () => models.Operation.collection.updateOne({}, { $set: { leaseUntil: new Date(0) } }),
        unheldAdmission: async () => models.Operation.collection.updateOne({}, { $set: { heldTopologyAdmission: false } }),
        terminal: async () => models.Operation.collection.updateOne({}, { $set: { status: 'succeeded' } }),
        foreignProfile: async () => models.Operation.collection.updateOne({}, { $set: { 'nodes.0.targetProfile': 'xray-bridge' } }),
        foreignCandidate: async () => models.Operation.collection.updateOne({}, { $set: { 'nodes.0.candidateHash': '0'.repeat(64) } }),
        changedBytes: async () => models.Operation.collection.updateOne({}, { $set: { 'nodes.0.candidate.bytes': [123, 125] } }),
        duplicatedNode: async () => {
            const row = await models.Operation.findOne().lean();
            return models.Operation.collection.updateOne({}, { $push: { nodes: row.nodes[0] } });
        },
        absentLock: async () => models.Lock.collection.deleteMany({}),
        foreignGeneration: async () => models.Lock.collection.updateOne({}, { $set: { generation: randomUUID() } }),
        foreignLockOwner: async () => models.Lock.collection.updateOne({}, { $set: { owner: 'foreign-worker' } }),
        foreignLockOperation: async () => models.Lock.collection.updateOne({}, { $set: { operationId: new mongoose.Types.ObjectId().toString() } }),
        expiredLock: async () => models.Lock.collection.updateOne({}, { $set: { leaseUntil: new Date(0) } }),
        absentUncertainty: async () => models.Lock.collection.updateOne({}, { $unset: { remoteUncertain: 1 } }),
        physicalClone: async () => models.Owner.collection.updateOne({}, { $set: { 'nodeIdentity.machineId': 'f'.repeat(32) } }),
        foreignOwnershipGeneration: async () => models.Owner.collection.updateOne({}, { $set: { generation: randomUUID() } }),
        classicOwner: async () => models.Owner.collection.updateOne({}, { $set: { owner: 'classic' } }),
        absentAdoption: async () => models.Owner.collection.updateOne({}, { $unset: { adoptionReceipt: 1 } }),
    };
    for (const [label, mutate] of Object.entries(mutations)) await t.test(label, async () => {
        const { store, expected, enrollment, context } = await setup();
        await store.preEnroll(enrollment);
        await mutate();
        const snapshot = await models.Operation.findOne().lean();
        await assert.rejects(store.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        assert.equal(await models.Binding.countDocuments(), 0);
        assert.deepEqual(await models.Operation.findOne().lean(), snapshot, 'failed transaction must not publish a CAS nonce');
        const { executor, events } = await assembled(store);
        await assert.rejects(executor.prepare(context), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        assert.deepEqual(events, []);
    });
});

test('real resolver/executor/transport seam consumes only majority-confirmed durable IDs and retains ownership; default executor still refuses', async () => {
    const { store, expected, enrollment, context } = await setup();
    await store.preEnroll(enrollment);
    const row = await store.createBinding(expected);
    const { executor, events } = await assembled(store);
    const prepared = await executor.prepare(context);
    const lifecycle = { ...context, ...prepared };
    delete lifecycle.ok;
    await executor.commit(lifecycle);
    await executor.verify(lifecycle);
    await executor.rollback(lifecycle);
    const dispatched = events.filter(event => typeof event === 'object');
    assert.deepEqual(dispatched.map(event => event.command), ['prepare', 'commit', 'verify', 'rollback']);
    assert.equal(events.filter(event => event === 'node-read').length, 1);
    for (const request of dispatched) {
        assert.equal(request.commandId, row.commandIds[request.command]);
        assert.equal(request.attemptId, row.attemptId);
        assert.equal(request.generation, expected.generation);
        assert.equal(request.predecessorGeneration, PREDECESSOR);
        assert.equal(request.executionContext, PROD.hostIdentity);
    }
    assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
    assert.equal((await models.Lock.findOne().lean()).generation, expected.generation);
    const normal = await assembled();
    await assert.rejects(normal.executor.prepare(context), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.deepEqual(normal.events, []);
});

test('persisted binding cannot be read under a replacement claim, acquired generation or ownership identity', async t => {
    for (const [label, update] of [
        ['attempt', async () => models.Operation.collection.updateOne({}, { $set: { attempts: 2 } })],
        ['claim owner', async () => models.Operation.collection.updateOne({}, { $set: { leaseOwner: 'next-worker' } })],
        ['node generation', async () => models.Lock.collection.updateOne({}, { $set: { generation: randomUUID() } })],
        ['physical identity', async () => models.Owner.collection.updateOne({}, { $set: { 'nodeIdentity.sshHostKeySha256': 'f'.repeat(64) } })],
        ['foreign context', async () => models.Binding.collection.updateOne({}, { $set: { executionContext: 'test.infograd.online' } })],
        ['missing proof', async () => models.Binding.collection.updateOne({}, { $unset: { proofId: 1 } })],
        ['changed command', async () => models.Binding.collection.updateOne({}, { $set: { 'commandIds.prepare': randomUUID() } })],
        ['cloned enrollment', async () => models.Enrollment.collection.updateOne({}, { $set: { clone: true } })],
    ]) await t.test(label, async () => {
        const { store, expected, enrollment, context } = await setup();
        await store.preEnroll(enrollment); await store.createBinding(expected); await update();
        const { executor, events } = await assembled(store);
        await assert.rejects(executor.prepare(context), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        assert.deepEqual(events, []);
        assert.equal(await models.Binding.countDocuments(), 1);
        assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
    });
});

test('required actual unique indexes reject missing physical isolation and block alias enrollment', async () => {
    const { store, enrollment } = await setup();
    const key = { 'nodeIdentity.machineId': 1, targetProfile: 1 };
    const index = (await models.Enrollment.collection.indexes()).find(value => JSON.stringify(value.key) === JSON.stringify(key));
    await models.Enrollment.collection.dropIndex(index.name);
    try {
        await assert.rejects(store.preEnroll(enrollment), { code: 'TOPOLOGY_EXECUTION_BINDING_INDEX_REQUIRED' });
        assert.equal(await models.Enrollment.countDocuments(), 0);
    } finally { await models.Enrollment.createIndexes(); }
    await store.preEnroll(enrollment);
    const owner = await models.Owner.findOne().lean();
    const alias = new mongoose.Types.ObjectId().toString();
    delete owner._id;
    await models.Owner.create({ ...owner, node: alias });
    await assert.rejects(store.preEnroll(freeze({ ...enrollment, nodeId: alias })), { code: 'TOPOLOGY_EXECUTION_BINDING_CONFLICT' });
    assert.equal(await models.Enrollment.countDocuments(), 1);
    assert.equal((await models.Owner.findOne({ node: alias }).lean()).executionBindingCheck, owner.executionBindingCheck,
        'losing alias transaction must roll back its owner CAS');
});

test('concurrent insert-only binding writers have one durable winner without replacing IDs', async () => {
    const { store, expected, enrollment } = await setup();
    await store.preEnroll(enrollment);
    const outcomes = await Promise.allSettled([store.createBinding(expected), newStore().createBinding(expected)]);
    assert.equal(outcomes.filter(value => value.status === 'fulfilled').length, 1);
    assert.equal(outcomes.filter(value => value.status === 'rejected').length, 1);
    assert.equal(await models.Binding.countDocuments(), 1);
    const winner = outcomes.find(value => value.status === 'fulfilled').value;
    assert.deepEqual(await newStore().readVerified(expected), winner);
});

test('lock/claim winners between transactional snapshot and CAS abort the entire binding insert', async t => {
    for (const name of ['Lock', 'Operation']) await t.test(name, async () => {
        const { store, expected, enrollment } = await setup();
        await store.preEnroll(enrollment);
        const snapshot = await models.Operation.findOne().lean();
        const Model = models[name];
        const original = Model.updateOne;
        const winningGeneration = randomUUID();
        let injected = false;
        Model.updateOne = async function (...args) {
            if (!injected) {
                injected = true;
                await Model.collection.updateOne({}, { $set: name === 'Lock'
                    ? { generation: winningGeneration, owner: 'winner' } : { attempts: 2, leaseOwner: 'winner' } });
            }
            return original.apply(this, args);
        };
        try { await assert.rejects(store.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' }); }
        finally { Model.updateOne = original; }
        assert.equal(injected, true);
        assert.equal(await models.Binding.countDocuments(), 0);
        if (name === 'Lock') {
            assert.equal((await models.Lock.findOne().lean()).generation, winningGeneration);
            assert.deepEqual(await models.Operation.findOne().lean(), snapshot);
        } else assert.equal((await models.Operation.findOne().lean()).leaseOwner, 'winner');
    });
});

function unknownCommit() {
    const error = new mongoose.mongo.MongoServerError({ message: 'injected unknown commit outcome' });
    error.addErrorLabel('UnknownTransactionCommitResult');
    return error;
}
async function injectCommit(work, afterCommit) {
    const start = connection.startSession;
    let calls = 0;
    connection.startSession = async function (...args) {
        const session = await start.apply(this, args);
        const commit = session.commitTransaction.bind(session);
        session.commitTransaction = async options => {
            calls++;
            assert.equal(options.timeoutMS, 5000);
            if (afterCommit) await commit(options);
            else await session.abortTransaction({ timeoutMS: 5000 });
            throw unknownCommit();
        };
        return session;
    };
    try { return await work(() => calls); }
    finally { connection.startSession = start; }
}

test('injected unknown commit is acknowledged only by exact bounded primary-majority readback; no transaction/ID regeneration', async () => {
    const { store, expected, enrollment } = await setup();
    await store.preEnroll(enrollment);
    const commands = [];
    const observe = event => { commands.push({ name: event.commandName, command: event.command }); };
    connection.getClient().on('commandStarted', observe);
    let row;
    try {
        await injectCommit(async count => { row = await store.createBinding(expected); assert.equal(count(), 1); }, true);
    } finally { connection.getClient().off('commandStarted', observe); }
    const committed = commands.find(event => event.name === 'commitTransaction').command;
    assert.equal(committed.writeConcern.w, 'majority');
    assert.ok(committed.maxTimeMS > 0 && committed.maxTimeMS <= 5000);
    const confirmation = commands.find(event => event.name === 'find'
        && event.command.find === models.Binding.collection.name && event.command.autocommit === undefined);
    assert.ok(confirmation, 'confirmation must be outside the transaction');
    assert.equal(confirmation.command.readConcern.level, 'majority');
    assert.equal(confirmation.command.filter._id, (await models.Binding.findOne().lean())._id);
    assert.ok(confirmation.command.maxTimeMS > 0 && confirmation.command.maxTimeMS <= 5000);
    assert.ok(commands.filter(event => event.name === 'find' && event.command.autocommit === undefined)
        .every(event => !event.command.$readPreference || event.command.$readPreference.mode === 'primary'));
    assert.deepEqual(await newStore().readVerified(expected), row);
    assert.equal(await models.Binding.countDocuments(), 1);
});

test('unknown non-commit absence and failed majority confirmation never acknowledge or remove retained ownership', async t => {
    await t.test('absence after injected abort', async () => {
        const { store, expected, enrollment } = await setup(); await store.preEnroll(enrollment);
        const before = await models.Operation.findOne().lean();
        await injectCommit(async count => {
            await assert.rejects(store.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
            assert.equal(count(), 1);
        }, false);
        assert.equal(await models.Binding.countDocuments(), 0);
        assert.deepEqual(await models.Operation.findOne().lean(), before);
    });
    await t.test('readback unavailable after actual commit', async () => {
        const { store, expected, enrollment, context } = await setup(); await store.preEnroll(enrollment);
        const find = models.Binding.findOne;
        let readbacks = 0;
        models.Binding.findOne = function (...args) {
            const query = find.apply(this, args);
            query.lean = async function () {
                readbacks++;
                assert.equal(this.getOptions().readConcern.level, 'majority');
                assert.equal(this.getOptions().readPreference.mode, 'primary');
                assert.ok(this.getOptions().maxTimeMS > 0 && this.getOptions().maxTimeMS <= 5000);
                throw new Error('injected primary majority read failure');
            };
            return query;
        };
        try {
            await injectCommit(async count => {
                await assert.rejects(store.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNCONFIRMED' });
                assert.equal(count(), 1); assert.equal(readbacks, 1);
            }, true);
            const { executor, events } = await assembled(store);
            await assert.rejects(executor.prepare(context), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
            assert.deepEqual(events, []);
        } finally { models.Binding.findOne = find; }
        assert.equal(await models.Binding.countDocuments(), 1);
        assert.equal((await models.Lock.findOne().lean()).generation, expected.generation);
        assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
    });
});

test('authority callback cannot outlive held scope or run later, and incomplete scope leaves no durable enrollment', async () => {
    const { enrollment } = await setup();
    let late, challenge;
    const lateStore = newStore(async (value, callback) => { challenge = value; late = callback; });
    await assert.rejects(lateStore.preEnroll(enrollment), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.throws(() => late(evidence(challenge)), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    const original = models.Owner.updateOne;
    let unblock;
    const blocked = new Promise(resolve => { unblock = resolve; });
    models.Owner.updateOne = async function (...args) { await blocked; return original.apply(this, args); };
    const premature = newStore(async (value, callback) => {
        callback(evidence(value));
        setImmediate(unblock);
        // Broken authority returns without awaiting the transaction/readback.
    });
    try { await assert.rejects(premature.preEnroll(enrollment), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' }); }
    finally { unblock(); models.Owner.updateOne = original; }
    assert.equal(await models.Enrollment.countDocuments(), 0);
});

test('actual binding reader rechecks ownership lost during real resolution or local bootstrap before dispatch', async t => {
    for (const hook of ['onResolved', 'onBootstrap']) await t.test(hook, async () => {
        const { store, expected, enrollment, context } = await setup();
        await store.preEnroll(enrollment); await store.createBinding(expected);
        const winner = randomUUID();
        const { executor, events } = await assembled(store, {
            [hook]: async () => models.Lock.collection.updateOne({}, { $set: { generation: winner, owner: 'winner' } }),
        });
        await assert.rejects(executor.prepare(context), { code: 'TOPOLOGY_OPERATION_EXECUTION_FAILED', remoteOutcomeUncertain: true });
        assert.equal(events.filter(event => typeof event === 'object').length, 0);
        if (hook === 'onResolved') assert.equal(events.includes('local-bootstrap'), false);
        assert.equal((await models.Lock.findOne().lean()).generation, winner);
        assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
    });
});

test('confirmation cannot silently accept changed immutable authority metadata hidden from the public executor record', async () => {
    const { store, expected, enrollment } = await setup(); await store.preEnroll(enrollment);
    const find = models.Binding.findOne;
    models.Binding.findOne = function (...args) {
        const query = find.apply(this, args);
        const lean = query.lean;
        query.lean = async function () {
            const row = await lean.call(this);
            return row ? { ...row, maintenanceId: randomUUID() } : row;
        };
        return query;
    };
    try { await assert.rejects(store.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNCONFIRMED' }); }
    finally { models.Binding.findOne = find; }
    assert.equal(await models.Binding.countDocuments(), 1, 'actual commit remains retained, never deleted after refused confirmation');
});

test('actual unique indexes exclude cross-record attempt and cross-command token reuse', async t => {
    const { store, expected, enrollment } = await setup();
    await store.preEnroll(enrollment); await store.createBinding(expected);
    const original = await models.Binding.findOne().lean();
    for (const key of ['attemptId', 'commandTokens']) await t.test(key, async () => {
        const commandIds = Object.fromEntries(['prepare', 'commit', 'verify', 'rollback'].map(command => [command, randomUUID()]));
        const clone = { ...original, _id: randomUUID(), operationId: new mongoose.Types.ObjectId().toString(),
            enrollmentId: randomUUID(), attemptId: key === 'attemptId' ? original.attemptId : randomUUID(),
            commandIds, commandTokens: key === 'commandTokens'
                ? [original.commandIds.verify, ...Object.values(commandIds).slice(1)] : Object.values(commandIds) };
        await assert.rejects(models.Binding.create(clone), error => error.code === 11000);
        assert.equal(await models.Binding.countDocuments(), 1);
    });
});

test('durable reader refuses a direct connection that can rewrite primary reads to primaryPreferred', async () => {
    await setup();
    const direct = await mongoose.createConnection(`mongodb://127.0.0.1:${connection.port}/${dbName}?directConnection=true`,
        { serverSelectionTimeoutMS: 1000 }).asPromise();
    try {
        const directModels = Object.fromEntries(Object.entries(models).map(([key, Model]) => [key, direct.model(Model.modelName, Model.schema)]));
        assert.throws(() => new contract.TopologyExecutionBindingStore({ executionContext: PROD,
            withVerifiedAuthority: goodAuthority, ...directModels }), /discovered replica set/);
    } finally { await direct.close(); }
});

test('immutable binding/enrollment models deny document deletion as well as updates, replacements, bulk writes and query deletion', async () => {
    const { store, expected, enrollment } = await setup();
    await store.preEnroll(enrollment);
    await store.createBinding(expected);
    for (const Model of [models.Binding, models.Enrollment]) {
        const document = await Model.findOne();
        await assert.rejects(document.deleteOne(), { code: 'TOPOLOGY_EXECUTION_BINDING_IMMUTABLE' });
        await assert.rejects(Model.updateOne({}, { $set: { predecessorGeneration: randomUUID() } }), { code: 'TOPOLOGY_EXECUTION_BINDING_IMMUTABLE' });
        await assert.rejects(Model.replaceOne({}, document.toObject()), { code: 'TOPOLOGY_EXECUTION_BINDING_IMMUTABLE' });
        await assert.rejects(Model.deleteMany({}), { code: 'TOPOLOGY_EXECUTION_BINDING_IMMUTABLE' });
        await assert.rejects(Model.bulkWrite([{ deleteOne: { filter: {} } }]), { code: 'TOPOLOGY_EXECUTION_BINDING_IMMUTABLE' });
        document.predecessorGeneration = randomUUID();
        await assert.rejects(document.save(), /immutable/i);
        assert.equal(await Model.countDocuments(), 1);
    }
});
