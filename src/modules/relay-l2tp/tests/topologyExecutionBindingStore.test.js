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
const MAINTENANCE = randomUUID();
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
        '--setParameter', 'enableTestCommands=1', '--replSet', 'bindingScratch', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
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
        proofId: randomUUID(), maintenanceId: MAINTENANCE, maintenance: 'held', allWriters: 'drained',
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
async function assembled(store, { onResolved, onBootstrap, localRunner, onCommand, acceptedBinding } = {}) {
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
        constructor(node, trustedConnection) {
            const { SIMULATED_TRUSTED_CONNECTION } = require('./helpers/topologyV2Fixture');
            assert.deepEqual(trustedConnection, SIMULATED_TRUSTED_CONNECTION);
            assert.deepEqual({ ip: node.ip, port: node.ssh.port, username: node.ssh.username },
                SIMULATED_TRUSTED_CONNECTION.expectedEndpoint);
            events.push('ssh-adapter');
        }
        async writeFile() { events.push('local-upload'); }
        async exec(command, options) {
            const request = runnerRequest(command);
            events.push(request);
            await onCommand?.(request);
            if (localRunner) return localRunner.execute(command, options);
            return { code: 0, stdout: `${JSON.stringify(v2Receipt(request, { bootId: BOOT }))}\n`, stderr: '' };
        }
    }
    class LocalBootstrapper { async ensureRunner() { events.push('local-bootstrap'); await onBootstrap?.(); } }
    const resolver = new TopologyNodeExecutionResolver({ ...PROD, NodeSSH: LocalSSH,
        HyNode: { findById(id) { events.push('node-read'); return Node.findById(id); } } });
    // Explicit LOCAL simulated authority, not a store capability and never
    // composed in the production host. Endpoint/key enrollment comes from this
    // independently fixed test fixture, not the mutable HyNode DB or request.
    let reader = store;
    if (store && acceptedBinding) {
        const accepted = acceptedBinding;
        let scoped;
        reader = {
            readVerified: expected => store.readVerified(expected),
            async readVerifiedConnection(expected, durable) {
                const { simulatedConnectionAuthority } = require('./helpers/topologyV2Fixture');
                const current = scoped ? (await scoped.assertCurrent(), scoped.durable) : await store.readVerified(expected);
                assert.deepEqual(current, accepted, 'simulated authority rejects changed accepted binding');
                assert.deepEqual(durable, accepted);
                assert.equal(current.maintenanceId, MAINTENANCE);
                return simulatedConnectionAuthority(accepted);
            },
            get withVerifiedBinding() {
                if (typeof store.withVerifiedBinding !== 'function') return undefined;
                return (expected, work) => store.withVerifiedBinding(expected, async (durable, assertCurrent) => {
                    scoped = { durable, assertCurrent };
                    try { return await work(durable, assertCurrent); } finally { scoped = undefined; }
                });
            },
        };
    }
    const executor = new TopologyOperationExecutor({ ...PROD, nodeExecutionResolver: {
        async resolve(request, trustedConnection) {
            const { SIMULATED_TRUSTED_CONNECTION } = require('./helpers/topologyV2Fixture');
            assert.deepEqual(trustedConnection, SIMULATED_TRUSTED_CONNECTION);
            assert.deepEqual(Object.keys(request).sort(), ['nodeId', 'role']);
            const ssh = await resolver.resolve(request, trustedConnection); await onResolved?.(); return ssh;
        },
    },
        RunnerBootstrapper: LocalBootstrapper, ...(reader ? { executionBindingReader: reader } : {}) });
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
    const { attemptId: _a, predecessorGeneration: _p, commandIds: _c, bootId: _b, maintenanceId: _m, ...expected } = bindingRecord(context, PROD.hostIdentity);
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
    assert.equal(new Set(Object.values(row.commandIds)).size, 5);
    assert.match(row.commandIds.close, /^[a-f0-9-]{36}$/);
    assert.equal(row.bootId, BOOT);
    assert.match(row.maintenanceId, /^[a-f0-9-]{36}$/);
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
    const { executor, events } = await assembled(store, { acceptedBinding: row });
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

test('real store alone has no trusted endpoint authority and remains unable to dispatch', async () => {
    const { store, expected, enrollment, context } = await setup();
    await store.preEnroll(enrollment); await store.createBinding(expected);
    assert.equal(store.readVerifiedConnection, undefined, 'production endpoint authority is deliberately not installed');
    const { executor, events } = await assembled(store);
    await assert.rejects(executor.prepare(context), {
        code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN', remoteOutcomeUncertain: false,
    });
    assert.deepEqual(events, []);
});

test('real resolver refuses mutable DB endpoint changes instead of adopting them as pin authority', async t => {
    for (const [field, value] of [['ip', '192.0.2.99'], ['ssh.port', 2222], ['ssh.username', 'foreign-user']]) {
        await t.test(field, async () => {
            const { store, expected, enrollment, context } = await setup();
            await store.preEnroll(enrollment); const row = await store.createBinding(expected);
            const { executor, events, Node } = await assembled(store, { acceptedBinding: row });
            await Node.updateOne({ _id: NODE }, { $set: { [field]: value } });
            await assert.rejects(executor.prepare(context));
            assert.deepEqual(events, ['node-read']);
            assert.equal((await models.Lock.findOne().lean()).generation, expected.generation);
            assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
        });
    }
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
        await store.preEnroll(enrollment); const row = await store.createBinding(expected);
        const winner = randomUUID();
        const { executor, events } = await assembled(store, { acceptedBinding: row,
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
        const commandIds = Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close'].map(command => [command, randomUUID()]));
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

// Regression lineage: c3-binding-independent-probes.cjs, real failCommand insert stall.
test('both enrollment and binding inserts honor the five-second driver I/O budget', async t => {
    for (const name of ['Enrollment', 'Binding']) await t.test(name, async () => {
        const { store, expected, enrollment } = await setup();
        if (name === 'Binding') await store.preEnroll(enrollment);
        const collection = models[name].collection;
        const originals = Object.fromEntries(['insertOne', 'insertMany'].map(key => [key, collection[key]]));
        const observed = [];
        for (const key of Object.keys(originals)) collection[key] = function (rows, options, ...rest) {
            observed.push({ timeoutMS: options.timeoutMS, session: Boolean(options.session) });
            return originals[key].call(this, rows, options, ...rest);
        };
        await connection.db.admin().command({ configureFailPoint: 'failCommand', mode: { times: 1 },
            data: { failCommands: ['insert'], blockConnection: true, blockTimeMS: 6500 } });
        let outcome, elapsed;
        try {
            const start = Date.now();
            outcome = await Promise.allSettled([name === 'Binding' ? store.createBinding(expected) : store.preEnroll(enrollment)]);
            elapsed = Date.now() - start;
        } finally {
            Object.assign(collection, originals);
            await connection.db.admin().command({ configureFailPoint: 'failCommand', mode: 'off' });
        }
        assert.equal(outcome[0].status, 'rejected', `stalled ${name} insert was accepted after ${elapsed}ms`);
        assert.equal(outcome[0].reason.code, 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN');
        assert.ok(elapsed >= 4500 && elapsed < 6000, `bounded refusal took ${elapsed}ms`);
        assert.deepEqual(observed, [{ timeoutMS: 5000, session: true }]);
        assert.equal(await models[name].countDocuments(), 0);
        assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
        assert.equal((await models.Lock.findOne().lean()).generation, expected.generation);
    });
});

// Keep the real Mongo reads; delay only delivery of the final owner confirmation.
// This reuses the independent reproducer's precise executor dispatch boundary.
test('expired lease after final confirmation or awaited cleanup never returns binding authority or dispatches', async t => {
    for (const boundary of ['read', 'executor', 'session-cleanup', 'authority-return']) await t.test(boundary, async () => {
        let untilDate, delayed = false;
        const authority = async (challenge, work) => {
            const result = await work(evidence(challenge));
            if (delayed && boundary === 'authority-return') await new Promise(resolve => setTimeout(resolve, 1500));
            return result;
        };
        const { store, expected, enrollment, context } = await setup(authority);
        await store.preEnroll(enrollment); await store.createBinding(expected);
        const execution = boundary === 'executor'
            ? await assembled(store, { acceptedBinding: await store.readVerified(expected) }) : null;
        untilDate = new Date(Date.now() + 1200);
        await models.Operation.updateOne({}, { $set: { leaseUntil: untilDate } });
        await models.Lock.updateOne({}, { $set: { leaseUntil: untilDate } });
        const find = models.Owner.findOne;
        const startSession = connection.startSession;
        let confirmations = 0;
        models.Owner.findOne = function (...args) {
            const query = find.apply(this, args);
            const lean = query.lean;
            query.lean = async function (...leanArgs) {
                const row = await lean.apply(this, leanArgs);
                if (this.getOptions().readConcern?.level !== 'majority') return row;
                confirmations++;
                if (confirmations === (boundary === 'executor' ? 3 : 1)) {
                    delayed = true;
                    if (['read', 'executor'].includes(boundary)) await new Promise(resolve => setTimeout(resolve, 1500));
                }
                return row;
            };
            return query;
        };
        if (boundary === 'session-cleanup') connection.startSession = async function (...args) {
            const session = await startSession.apply(this, args);
            const end = session.endSession.bind(session);
            session.endSession = async (...endArgs) => {
                await end(...endArgs);
                if (delayed) await new Promise(resolve => setTimeout(resolve, 1500));
            };
            return session;
        };
        try {
            await assert.rejects(execution ? execution.executor.prepare(context) : store.readVerified(expected),
                execution ? { code: 'TOPOLOGY_OPERATION_EXECUTION_FAILED', remoteOutcomeUncertain: true }
                    : { code: 'TOPOLOGY_EXECUTION_BINDING_UNCONFIRMED' });
        } finally { models.Owner.findOne = find; connection.startSession = startSession; }
        assert.equal(delayed, true);
        assert.ok(Date.now() > untilDate.getTime(), 'lease must actually expire at this boundary');
        if (execution) assert.equal(execution.events.filter(event => typeof event === 'object').length, 0);
        assert.equal((await models.Lock.findOne().lean()).generation, expected.generation);
        assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
    });
});

// Public Mongoose aggregation-pipeline updates bypass ordinary field casting,
// even with runValidators:true. Scalar query equality alone matches array elements.
test('malformed BSON authority arrays never authorize enrollment, binding creation or executor dispatch', async t => {
    const cases = {
        Operation: { leaseOwner: 'worker-17', attempts: 1, heldTopologyAdmission: true, topologyRevision: 17,
            priorDeployedRevision: 16, status: 'preparing', idempotencyKey: null, leaseUntil: null },
        Lock: { owner: 'worker-17', operationId: null, generation: null, remoteUncertain: true, leaseUntil: null, node: null },
        Owner: { owner: 'topology', generation: OWNER_GENERATION, profile: 'xray-main', node: null,
            executionContext: { ...PROD }, nodeIdentity: { ...IDENTITY }, 'adoptionReceipt.toGeneration': OWNER_GENERATION },
    };
    for (const [name, fields] of Object.entries(cases)) for (const key of Object.keys(fields)) {
        await t.test(`${name}.${key}`, async () => {
            const { store, expected, enrollment, context } = await setup();
            await store.preEnroll(enrollment); await store.createBinding(expected);
            const before = await models[name].findOne().lean();
            const value = key.split('.').reduce((row, part) => row[part], before);
            const array = [value, key === 'remoteUncertain' ? false : value];
            await models[name].updateOne({}, [{ $set: { [key]: { $literal: array } } }], { runValidators: true });
            const malformed = await models[name].collection.findOne({});
            assert.deepEqual(key.split('.').reduce((row, part) => row[part], malformed), array);
            const { executor, events } = await assembled(store);
            await assert.rejects(executor.prepare(context), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
            assert.deepEqual(events, []);
            await models.Binding.collection.deleteMany({});
            const operation = await models.Operation.collection.findOne({});
            await assert.rejects(store.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
            assert.equal(await models.Binding.countDocuments(), 0);
            assert.deepEqual(await models.Operation.collection.findOne({}), operation, 'failed transaction must roll back all CAS nonces');
            if (name === 'Owner') {
                await models.Enrollment.collection.deleteMany({});
                await assert.rejects(store.preEnroll(enrollment), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
                assert.equal(await models.Enrollment.countDocuments(), 0);
            }
            assert.equal(await models.Lock.countDocuments(), 1);
        });
    }
});

test('only a complete non-null restoration snapshot and coherent adoption receipt authorize the store', async t => {
    const changes = {
        nullSnapshot: { originalSnapshot: null },
        emptySnapshot: { originalSnapshot: {} },
        missingConfig: { originalSnapshot: { unitSha256: '4'.repeat(64), serviceActive: 'active', serviceEnabled: 'enabled' } },
        badConfig: { 'originalSnapshot.configSha256': 'not-a-digest' },
        arrayConfig: { 'originalSnapshot.configSha256': ['3'.repeat(64)] },
        badUnit: { 'originalSnapshot.unitSha256': 'not-a-digest' },
        badActive: { 'originalSnapshot.serviceActive': 'unknown' },
        badEnabled: { 'originalSnapshot.serviceEnabled': 'unknown' },
        nullReceipt: { adoptionReceipt: null },
        emptyReceipt: { adoptionReceipt: { toGeneration: OWNER_GENERATION } },
        badProof: { 'adoptionReceipt.proofId': 'not-a-uuid' },
        arrayProof: { 'adoptionReceipt.proofId': [randomUUID()] },
        badMaintenance: { 'adoptionReceipt.maintenanceId': 'not-a-uuid' },
        badFrom: { 'adoptionReceipt.fromGeneration': 'not-a-uuid' },
        sameGeneration: { 'adoptionReceipt.fromGeneration': OWNER_GENERATION },
        blankInstance: { 'adoptionReceipt.oldBackendInstanceId': '' },
        nonpositivePid: { 'adoptionReceipt.oldPid': 0 },
        fractionalPid: { 'adoptionReceipt.oldPid': 1.5 },
        stringPid: { 'adoptionReceipt.oldPid': '42' },
        blankProcessStart: { 'adoptionReceipt.oldProcessStartTime': '' },
        invalidVerificationDate: { 'adoptionReceipt.verifiedAt': 'yesterday' },
        futureVerificationDate: { 'adoptionReceipt.verifiedAt': new Date(Date.now() + 86400000) },
    };
    for (const [label, update] of Object.entries(changes)) await t.test(label, async () => {
        const { store, expected, enrollment, context } = await setup();
        await store.preEnroll(enrollment); await store.createBinding(expected);
        if (label === 'nullSnapshot') {
            // Original review reproducer: ordinary validated model update + document
            // validation accepted null. Keep that real persisted boundary explicit.
            await models.Owner.updateOne({}, { $set: update }, { runValidators: true });
            await (await models.Owner.findOne()).validate();
        } else await models.Owner.updateOne({}, [{ $set: Object.fromEntries(
            Object.entries(update).map(([key, value]) => [key, { $literal: value }])) }], { runValidators: true });
        const { executor, events } = await assembled(store);
        await assert.rejects(executor.prepare(context), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        assert.deepEqual(events, []);
        await models.Binding.collection.deleteMany({});
        await assert.rejects(store.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        assert.equal(await models.Binding.countDocuments(), 0);
        await models.Enrollment.collection.deleteMany({});
        await assert.rejects(store.preEnroll(enrollment), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        assert.equal(await models.Enrollment.countDocuments(), 0);
        assert.equal((await models.Lock.findOne().lean()).generation, expected.generation);
        assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
    });
});

test('majority confirmation refuses authority fields changed after commit, including an array CAS nonce', async t => {
    for (const [name, key] of [['Operation', 'leaseOwner'], ['Lock', 'generation'], ['Owner', 'owner'],
        ['Operation', 'executionBindingCheck'], ['Lock', 'executionBindingCheck'], ['Owner', 'executionBindingCheck'],
        ['Owner', 'originalSnapshot']]) await t.test(`${name}.${key}`, async () => {
        const { store, expected, enrollment } = await setup();
        await store.preEnroll(enrollment);
        const find = models[name].findOne;
        let injected = false;
        models[name].findOne = function (...args) {
            const query = find.apply(this, args);
            const lean = query.lean;
            query.lean = async function (...leanArgs) {
                if (!injected && this.getOptions().readConcern?.level === 'majority') {
                    injected = true;
                    const row = await models[name].collection.findOne({});
                    await models[name].updateOne({}, [{ $set: { [key]: { $literal: key === 'originalSnapshot' ? null : [row[key]] } } }],
                        { runValidators: true });
                }
                return lean.apply(this, leanArgs);
            };
            return query;
        };
        try { await assert.rejects(store.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNCONFIRMED' }); }
        finally { models[name].findOne = find; }
        assert.equal(injected, true);
        assert.equal(await models.Binding.countDocuments(), 1, 'refused readback must retain the real commit');
        assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
        assert.equal(await models.Lock.countDocuments(), 1);
    });
});

test('operation node authority fields are exact scalar values in both transaction and majority readback', async t => {
    for (const phase of ['transaction', 'confirmation']) for (const key of ['node', 'targetProfile', 'candidateHash']) {
        await t.test(`${phase}.${key}`, async () => {
            const { store, expected, enrollment, context } = await setup();
            await store.preEnroll(enrollment); await store.createBinding(expected);
            const operation = await models.Operation.findOne().lean();
            // Pipeline dot paths are object paths, not positional array updates.
            const mutate = () => models.Operation.updateOne({}, [{ $set: { nodes: { $literal:
                operation.nodes.map(node => ({ ...node, [key]: [node[key]] })) } } }], { runValidators: true });
            const find = models.Operation.findOne;
            let injected = false;
            if (phase === 'transaction') await mutate();
            else models.Operation.findOne = function (...args) {
                const query = find.apply(this, args);
                const lean = query.lean;
                query.lean = async function (...leanArgs) {
                    if (!injected && this.getOptions().readConcern?.level === 'majority') {
                        injected = true; await mutate();
                    }
                    return lean.apply(this, leanArgs);
                };
                return query;
            };
            const { executor, events } = await assembled(store);
            try { await assert.rejects(executor.prepare(context), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' }); }
            finally { models.Operation.findOne = find; }
            if (phase === 'confirmation') assert.equal(injected, true);
            assert.deepEqual(events, []);
        });
    }
});

test('real commit writeConcern uncertainty remains conservative with one bounded primary-majority binding confirmation', async () => {
    const { store, expected, enrollment } = await setup();
    await store.preEnroll(enrollment);
    const commands = [];
    const observe = event => commands.push({ name: event.commandName, command: event.command });
    const start = connection.startSession;
    let labels = [];
    connection.startSession = async function (...args) {
        const session = await start.apply(this, args);
        const commit = session.commitTransaction.bind(session);
        session.commitTransaction = async (...commitArgs) => {
            try { return await commit(...commitArgs); }
            catch (error) { labels = error.errorLabels; throw error; }
        };
        return session;
    };
    connection.getClient().on('commandStarted', observe);
    await connection.db.admin().command({ configureFailPoint: 'failCommand', mode: { times: 1 },
        data: { failCommands: ['commitTransaction'], writeConcernError: {
            code: 64, codeName: 'WriteConcernFailed', errmsg: 'local binding regression commit uncertainty',
        } } });
    let outcome;
    try { outcome = (await Promise.allSettled([store.createBinding(expected)]))[0]; }
    finally {
        connection.startSession = start;
        connection.getClient().off('commandStarted', observe);
        await connection.db.admin().command({ configureFailPoint: 'failCommand', mode: 'off' });
    }
    assert.ok(labels.includes('UnknownTransactionCommitResult'), 'server must actually produce unknown commit');
    const readbacks = commands.filter(({ name, command }) => name === 'find'
        && command.find === models.Binding.collection.name && !Object.hasOwn(command, 'autocommit'));
    assert.equal(readbacks.length, 1);
    const confirmation = readbacks[0].command;
    assert.equal(confirmation.readConcern.level, 'majority');
    assert.ok(!confirmation.$readPreference || confirmation.$readPreference.mode === 'primary');
    assert.ok(confirmation.maxTimeMS > 0 && confirmation.maxTimeMS <= 5000);
    assert.equal(commands.filter(({ name }) => name === 'insert').length, 1, 'unknown commit cannot regenerate IDs or retry the transaction');
    const durable = await until(async () => {
        const row = await models.Binding.findOne().read('primary').readConcern('majority').lean();
        assert.ok(row); return row;
    });
    assert.equal(confirmation.filter._id, durable._id);
    if (outcome.status === 'fulfilled') assert.equal(outcome.value.attemptId, durable.attemptId);
    else assert.ok(['TOPOLOGY_EXECUTION_BINDING_UNPROVEN', 'TOPOLOGY_EXECUTION_BINDING_UNCONFIRMED'].includes(outcome.reason.code));
    assert.equal(await models.Binding.countDocuments(), 1);
    assert.equal((await models.Lock.findOne().lean()).generation, expected.generation);
    assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
});

async function terminalFixture(t, { authority = goodAuthority, onCommand } = {}) {
    const { fakeRunner } = require('./helpers/topologyTerminalFakeRunner');
    const state = await setup(authority);
    const { store, expected, enrollment, context } = state;
    await store.preEnroll(enrollment);
    const row = await store.createBinding(expected);
    const localRunner = fakeRunner(t, BOOT);
    const prefix = `runner --command close --operation-id predecessor --node-id ${NODE} --candidate-hash ${expected.candidateHash} --backup-id previous --target-profile xray-main --execution-context ${PROD.hostIdentity} --attempt-id previous --generation ${PREDECESSOR} --predecessor-generation none --command-id previous-close`;
    assert.equal(localRunner.execute(prefix).code, 0);
    const assembledState = await assembled(store, { localRunner, onCommand, acceptedBinding: row });
    const { executor } = assembledState;
    const prepared = await executor.prepare(context);
    const lifecycle = { ...context, backupId: prepared.backupId, prepared: prepared.prepared };
    await executor.commit(lifecycle);
    return { ...state, ...assembledState, row, localRunner, prefix, lifecycle };
}

test('executor produces terminal proof data after verify or rollback with fresh exact real-runner status and retained Mongo ownership', async t => {
    for (const outcome of ['verify', 'rollback']) await t.test(outcome, async t => {
        const { executor, lifecycle, row, localRunner, prefix, expected, events } = await terminalFixture(t);
        await executor[outcome](lifecycle);
        assert.equal(typeof executor.close, 'function');
        const proof = await executor.close(lifecycle);
        assert.equal(proof.terminal, true);
        assert.equal(proof.command, 'status');
        assert.equal(proof.completedCommand, 'close');
        assert.equal(proof.commandId, row.commandIds.close);
        assert.equal(proof.bootId, BOOT);
        assert.equal(proof.terminalOutcome, outcome === 'verify' ? 'verified' : 'rolledback');
        assert.equal(proof.ownershipRetained, true);
        assert.equal(Object.isFrozen(proof), true);
        assert.deepEqual(events.filter(e => typeof e === 'object').map(e => e.command),
            ['prepare', 'commit', outcome, 'close', 'status']);
        const effects = fs.readFileSync(path.join(localRunner.root, 'systemctl.log'), 'utf8');
        for (const command of ['prepare', 'commit']) {
            const delayed = prefix.replace('--command close', `--command ${command}`)
                .replace('--operation-id predecessor', `--operation-id ${expected.operationId}`)
                .replace('--backup-id previous', `--backup-id ${expected.backupId}`)
                .replace('--attempt-id previous', `--attempt-id ${row.attemptId}`)
                .replace(`--generation ${PREDECESSOR}`, `--generation ${expected.generation}`)
                .replace('--predecessor-generation none', `--predecessor-generation ${PREDECESSOR}`)
                .replace('--command-id previous-close', `--command-id late-${command}`);
            assert.match(localRunner.execute(delayed, { stdin: content }).stderr, /GENERATION_CLOSED/);
        }
        assert.equal(fs.readFileSync(path.join(localRunner.root, 'systemctl.log'), 'utf8'), effects);
        assert.equal((await models.Lock.findOne().lean()).generation, expected.generation);
        assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
    });
});

test('terminal status unknown, corrupt, missing, rebooted or in-flight never returns proof or releases ownership', async t => {
    const { spawnSync } = require('node:child_process');
    for (const fault of ['unknown', 'corrupt', 'missing', 'in-flight', 'reboot', 'changed-status']) {
        await t.test(fault, async t => {
            const { executor, lifecycle, expected, localRunner } = await terminalFixture(t);
            await executor.verify(lifecycle);
            const execute = localRunner.execute;
            let statuses = 0;
            localRunner.execute = (command, options) => {
                if (!command.includes('--command status ')) return execute(command, options);
                statuses++;
                const journal = path.join(localRunner.root, 'var/lib/celerity/topology/fences/xray-main/journal.json');
                if (fault === 'unknown') command = command.replace(/--command-id \S+/, '--command-id unknown-close');
                if (fault === 'corrupt') fs.writeFileSync(journal, '{');
                if (fault === 'missing') fs.unlinkSync(journal);
                if (fault === 'reboot') localRunner.put('proc/sys/kernel/random/boot_id', `${randomUUID()}\n`);
                if (fault === 'in-flight') {
                    const result = spawnSync('flock', ['-x', path.join(path.dirname(journal), 'lock'), 'bash',
                        path.join(__dirname, '../node-artifacts/topology/runner.sh'), ...command.split(' ').slice(1)],
                    { env: { ...process.env, CELERITY_TOPOLOGY_ROOT: localRunner.root }, encoding: 'utf8' });
                    assert.match(result.stderr, /COMMAND_IN_FLIGHT/);
                    return { code: result.status, stdout: result.stdout, stderr: result.stderr };
                }
                const result = execute(command, options);
                if (fault === 'changed-status') {
                    const receipt = JSON.parse(result.stdout);
                    receipt.bootId = randomUUID();
                    return { ...result, stdout: `${JSON.stringify(receipt)}\n` };
                }
                return result;
            };
            await assert.rejects(executor.close(lifecycle), {
                code: 'TOPOLOGY_OPERATION_EXECUTION_FAILED', remoteOutcomeUncertain: true,
            });
            assert.equal(statuses, 1);
            await assert.rejects(executor.commit(lifecycle));
            await assert.rejects(executor.close(lifecycle));
            assert.equal(statuses, 1, 'uncertain close is sticky, never redispatched');
            assert.equal((await models.Lock.findOne().lean()).generation, expected.generation);
            assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
            assert.equal((await models.Owner.findOne().lean()).owner, 'topology');
        });
    }
});

test('terminal executor refuses missing scoped authority, switched maintenance and unsafe bootstrap/classic authority before close', async t => {
    for (const fault of ['bootstrap', 'classic', 'maintenance', 'absent-scope']) await t.test(fault, async t => {
        let unsafe = false;
        const authority = async (challenge, work) => work(evidence(challenge, unsafe ? {
            ...(fault === 'bootstrap' ? { bootstrapWriters: 'unknown' } : {}),
            ...(fault === 'classic' ? { allWriters: 'unknown' } : {}),
            ...(fault === 'maintenance' ? { maintenanceId: randomUUID() } : {}),
        } : {}));
        const { executor, lifecycle, expected, store, events } = await terminalFixture(t, { authority });
        await executor.verify(lifecycle);
        unsafe = true;
        if (fault === 'absent-scope') store.withVerifiedBinding = undefined;
        await assert.rejects(executor.close(lifecycle));
        assert.deepEqual(events.filter(e => typeof e === 'object').map(e => e.command), ['prepare', 'commit', 'verify']);
        assert.equal((await models.Lock.findOne().lean()).generation, expected.generation);
        assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
        assert.equal((await models.Owner.findOne().lean()).owner, 'topology');
    });
});

test('terminal dispatch stays inside held authority and ownership loss before or after status prevents proof', async t => {
    for (const lostAt of ['none', 'close', 'status']) await t.test(lostAt, async t => {
        let held = false;
        const authority = async (challenge, work) => {
            held = true;
            try { return await work(evidence(challenge)); } finally { held = false; }
        };
        const winner = randomUUID();
        const { executor, lifecycle, expected, events } = await terminalFixture(t, {
            authority,
            onCommand: async request => {
                if (!['close', 'status'].includes(request.command)) return;
                assert.equal(held, true, 'terminal commands escaped external exclusion');
                if (request.command === lostAt) await models.Lock.collection.updateOne({}, {
                    $set: { generation: winner, owner: 'winner' },
                });
            },
        });
        await executor.verify(lifecycle);
        if (lostAt === 'none') assert.equal((await executor.close(lifecycle)).terminal, true);
        else await assert.rejects(executor.close(lifecycle), {
            code: 'TOPOLOGY_OPERATION_EXECUTION_FAILED', remoteOutcomeUncertain: true,
        });
        assert.equal(held, false);
        const statuses = events.filter(e => e?.command === 'status').length;
        assert.equal(statuses, lostAt === 'close' ? 0 : 1);
        assert.equal((await models.Lock.findOne().lean()).generation, lostAt === 'none' ? expected.generation : winner);
        assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
    });
});

test('binding creation cannot switch maintenance authority after predecessor enrollment', async () => {
    const { store, expected, enrollment } = await setup();
    await store.preEnroll(enrollment);
    const switched = newStore(async (challenge, work) => work(evidence(challenge, { maintenanceId: randomUUID() })));
    await assert.rejects(switched.createBinding(expected), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.equal(await models.Binding.countDocuments(), 0);
    assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
});

test('terminal scope holds original maintenance authority and rechecks persisted ownership after callback', async () => {
    const { store, expected, enrollment } = await setup();
    await store.preEnroll(enrollment);
    const original = await store.createBinding(expected);
    assert.equal(typeof store.withVerifiedBinding, 'function');
    let held = false;
    const scoped = newStore(async (challenge, work) => {
        assert.equal(challenge.action, 'terminal', 'read-only authority must not silently grant terminal dispatch');
        held = true;
        try { return await work(evidence(challenge)); } finally { held = false; }
    });
    assert.equal(await scoped.withVerifiedBinding(expected, async row => {
        assert.equal(held, true);
        assert.deepEqual(row, original);
        return 'proof-data-only';
    }), 'proof-data-only');
    assert.equal(held, false);
    let invoked = false;
    const switched = newStore(async (challenge, work) => work(evidence(challenge, { maintenanceId: randomUUID() })));
    await assert.rejects(switched.withVerifiedBinding(expected, async () => { invoked = true; }),
        { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.equal(invoked, false);
    const winner = randomUUID();
    await assert.rejects(scoped.withVerifiedBinding(expected, async () => {
        await models.Lock.collection.updateOne({}, { $set: { generation: winner, owner: 'winner' } });
        return 'must-not-escape';
    }), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.equal((await models.Lock.findOne().lean()).generation, winner);
    assert.equal((await models.Operation.findOne().lean()).heldTopologyAdmission, true);
});
