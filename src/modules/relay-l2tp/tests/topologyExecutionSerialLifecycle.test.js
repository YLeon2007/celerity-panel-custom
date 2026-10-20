'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const contract = require('../repositories/topologyExecutionBindingStore');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');

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
const ENDPOINT = freeze({ ip: '192.0.2.17', port: 22, username: 'synthetic' });
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
        // Fixed server fixture, NOT copied from the caller challenge or mutable DB.
        connectionAttestation: { authority: 'server-physical-ssh-endpoint-v1', endpoint: { ...ENDPOINT },
            physicalIdentity: { ...IDENTITY }, maintenanceId: MAINTENANCE, aliases: 'excluded',
            hostKeyDigest: 'raw-ssh-public-key-sha256', endpointReassignment: 'excluded' },
        predecessor: { generation: PREDECESSOR, bootId: BOOT, status: 'pre-enrolled' },
        oldBackend: { instanceId: 'simulated-old-prod', pid: 42, processStartTime: 'simulated-start',
            processTree: 'stopped', dispatch: 'disabled' }, ...changes };
}
const goodAuthority = async (challenge, work) => work(evidence(challenge));
function newStore(authority = goodAuthority) {
    return new contract.TopologyExecutionBindingStore({ executionContext: PROD, withVerifiedAuthority: authority, ...models });
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
            HyNode: connection.model('BindingLocalNode', require('../../../models/hyNodeModel').schema),
        };
        await Promise.all(Object.values(models).map(model => model.init()));
    }
    // Administrative fixture cleanup uses raw collections; public immutable models refuse mutation.
    await Promise.all(Object.values(models).map(model => model.collection.deleteMany({})));
    await models.HyNode.create({ _id: NODE, ip: ENDPOINT.ip, name: 'local-only', type: 'xray', active: true,
        cascadeRole: 'portal', ssh: { port: ENDPOINT.port, username: ENDPOINT.username,
            privateKey: 'synthetic-local-fixture-not-a-key' } });
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
        endpoint: ENDPOINT, nodeIdentity: IDENTITY, ownerGeneration: OWNER_GENERATION, predecessorGeneration: PREDECESSOR, bootId: BOOT }) };
}


// All authority in this file is injected LOCAL simulation, not operational proof.
function emptyHead() {
    return { generation: 'none', bootId: BOOT, status: 'empty', protocolVersion: 2,
        journal: 'absent', legacyState: 'absent', writers: 'excluded' };
}
function initialAuthority(challenge, work) {
    return work(evidence(challenge, { predecessor: challenge.action === 'enroll'
        ? emptyHead() : { generation: 'none', bootId: BOOT, status: 'pre-enrolled' } }));
}
test('empty-runner provisioning is durably attested and executable by the real V2 runner', async t => {
    const { expected, enrollment } = await setup(initialAuthority);
    const store = newStore(initialAuthority);
    await store.preEnroll(freeze({ ...enrollment, predecessorGeneration: 'none' }));
    const persisted = await models.Enrollment.findOne().lean();
    assert.deepEqual(persisted.provisioningReceipt, emptyHead());
    const binding = await store.createBinding(expected);
    assert.equal(binding.predecessorGeneration, 'none');
    const runner = require('./helpers/topologyTerminalFakeRunner').fakeRunner(t, BOOT);
    const prepared = run(runner, binding, 'prepare');
    assert.equal(prepared.phase, 'prepared');
    const closed = run(runner, binding, 'close');
    assert.equal(closed.terminal, true);
    assert.deepEqual(run(runner, binding, 'status'), { ...closed, command: 'status' });
    assert.deepEqual(await newStore(initialAuthority).readVerified(expected), binding);
});
test('two sequential operations persist an exact terminal predecessor and use real runner generations', async t => {
    const f = await serialFixture(t);
    assert.equal(typeof f.store.createSuccessor, 'function', 'serial successor store API is missing');
    const second = await f.store.createSuccessor(f.next, f.firstId);
    assert.equal(second.predecessorGeneration, f.first.generation);
    assert.notEqual(second.attemptId, f.first.attemptId);
    assert.equal(new Set([...Object.values(second.commandIds), ...Object.values(f.first.commandIds)]).size, 10);
    assert.equal(await models.Enrollment.countDocuments(), 1);
    assert.equal(await models.Binding.countDocuments(), 2);
    const persisted = await models.Binding.findOne({ generation: second.generation }).lean();
    assert.equal(persisted.predecessorBindingId, f.firstId);
    assert.deepEqual(persisted.predecessorReceipt, f.status);
    for (const command of ['prepare', 'commit', 'verify', 'close']) run(f.runner, second, command);
    assert.equal(run(f.runner, second, 'status').generation, second.generation);
    assert.deepEqual(await newStore(f.authority).readVerified(f.next), second);
    await assert.rejects(f.store.readVerified(f.expected));
    await assert.rejects(f.store.createSuccessor(f.next, f.firstId));
    await assert.rejects(f.store.createBinding(f.next));
});
async function nextOperation(revision = 18) {
    const operationId = new mongoose.Types.ObjectId().toString();
    const owner = `worker-${revision}`;
    const generation = randomUUID();
    const repository = new TopologyOperationRepository({ model: models.Operation });
    await connection.transaction(async session => repository.createFrozen({ operationId, executionContext: PROD,
        idempotencyKey: `topology:production:revision-${revision}:host-${PROD.hostIdentity}:${randomUUID()}`,
        topologyRevision: revision, priorDeployedRevision: revision - 1, nodes: [frozenNode], heldTopologyAdmission: true,
        admissionFingerprint: 'f'.repeat(64), session }));
    await repository.claim({ operationId, executionContext: PROD, owner, now: new Date(), leaseMs: 120000 });
    await new NodeOperationLockRepository({ model: models.Lock }).acquireLease({ node: NODE, operationId,
        owner, generation, leaseUntil: new Date(Date.now() + 120000) });
    const context = { operationId, node: frozenNode, topologyRevision: revision, priorDeployedRevision: revision - 1,
        executionFence: { owner, attempt: 1, generation } };
    const { attemptId: _a, predecessorGeneration: _p, commandIds: _c, bootId: _b, maintenanceId: _m, ...expected } = bindingRecord(context, PROD.hostIdentity);
    return freeze(expected);
}
async function serialFixture(t) {
    const { expected, enrollment } = await setup(initialAuthority);
    let terminal, runner, first;
    const authority = (challenge, work) => challenge.predecessor
        ? work(evidence(challenge, { predecessor: { ...structuredClone(terminal),
            // Independent LOCAL journal observation while this simulated authority
            // holds its callback; never copied from the challenge or mutable node.
            headGeneration: JSON.parse(fs.readFileSync(path.join(runner.root,
                'var/lib/celerity/topology/fences/xray-main/journal.json'), 'utf8')).head,
            receipt: run(runner, first, 'status') } }))
        : initialAuthority(challenge, work);
    const store = newStore(authority);
    await store.preEnroll(freeze({ ...enrollment, predecessorGeneration: 'none' }));
    first = await store.createBinding(expected);
    const firstId = (await models.Binding.findOne().lean())._id;
    runner = require('./helpers/topologyTerminalFakeRunner').fakeRunner(t, BOOT);
    for (const command of ['prepare', 'commit', 'verify', 'close']) run(runner, first, command);
    const status = run(runner, first, 'status');
    terminal = { bindingId: firstId, generation: first.generation, headGeneration: first.generation,
        bootId: BOOT, status: 'terminal', receipt: status };
    // Simulated worker settlement/lock transfer is explicitly outside this store.
    await models.Operation.collection.updateOne({ _id: new mongoose.Types.ObjectId(expected.operationId) },
        { $set: { status: 'succeeded', heldTopologyAdmission: false } });
    await models.Lock.collection.deleteMany({});
    const next = await nextOperation();
    return { store, authority, terminal, first, firstId, status, runner, next, expected };
}
test('caller none, booleans and current scans cannot provision an empty runner', async t => {
    const { enrollment } = await setup();
    for (const predecessor of [true, { generation: 'none', bootId: BOOT, status: 'pre-enrolled' },
        { ...emptyHead(), journal: 'currently-empty' }, { ...emptyHead(), legacyState: 'unknown' },
        { ...emptyHead(), bootId: randomUUID() }]) await t.test(JSON.stringify(predecessor), async () => {
        const store = newStore((challenge, work) => work(evidence(challenge, { predecessor })));
        await assert.rejects(store.preEnroll(freeze({ ...enrollment, predecessorGeneration: 'none' })));
        assert.equal(await models.Enrollment.countDocuments(), 0);
        assert.equal((await models.Lock.findOne().lean()).remoteUncertain, true);
    });
});

test('terminal status alone is historical data, not attestation of the current runner head', async t => {
    const f = await serialFixture(t);
    const store = newStore((challenge, work) => {
        const predecessor = structuredClone(f.terminal);
        delete predecessor.headGeneration;
        return work(evidence(challenge, { predecessor }));
    });
    await assert.rejects(store.createSuccessor(f.next, f.firstId));
    assert.equal(await models.Binding.countDocuments(), 1);
});

test('successor requires exact fresh terminal status, never a label or unknown outcome', async t => {
    const f = await serialFixture(t);
    const original = structuredClone(f.terminal);
    const snapshot = await retained(f.next);
    const mutations = {
        boolean: () => true,
        scan: value => ({ generation: value.generation, bootId: BOOT, status: 'pre-enrolled' }),
        staleHead: value => ({ ...value, headGeneration: randomUUID() }),
        unknown: value => ({ ...value, receipt: { ...value.receipt, completion: 'unknown' } }),
        closeNotStatus: value => ({ ...value, receipt: { ...value.receipt, command: 'close' } }),
        otherCommand: value => ({ ...value, receipt: { ...value.receipt, commandId: f.first.commandIds.verify } }),
        otherAttempt: value => ({ ...value, receipt: { ...value.receipt, attemptId: randomUUID() } }),
        otherGeneration: value => ({ ...value, receipt: { ...value.receipt, generation: randomUUID() } }),
        otherBoot: value => ({ ...value, receipt: { ...value.receipt, bootId: randomUUID() } }),
        otherNode: value => ({ ...value, receipt: { ...value.receipt, nodeId: new mongoose.Types.ObjectId().toString() } }),
        pendingJob: value => ({ ...value, receipt: { ...value.receipt, systemdJob: 'pending' } }),
        notClosed: value => ({ ...value, receipt: { ...value.receipt, phase: 'verified', terminal: false } }),
        absent: value => ({ ...value, receipt: null }),
    };
    for (const [name, mutate] of Object.entries(mutations)) await t.test(name, async () => {
        const store = newStore((challenge, work) => work(evidence(challenge, { predecessor: mutate(structuredClone(original)) })));
        await assert.rejects(store.createSuccessor(f.next, f.firstId));
        assert.equal(await models.Binding.countDocuments(), 1);
        assert.deepEqual(await retained(f.next), snapshot);
    });
});

async function retained(expected) {
    return { lock: await models.Lock.findOne().lean(), owner: await models.Owner.findOne().lean(),
        operation: await models.Operation.findById(expected.operationId).lean() };
}

test('concurrent successor is single-winner; old generation and replay never fork', async t => {
    const f = await serialFixture(t);
    const results = await Promise.allSettled(Array.from({ length: 4 }, () => newStore(f.authority).createSuccessor(f.next, f.firstId)));
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    assert.equal(await models.Binding.countDocuments(), 2);
    const second = results.find(result => result.status === 'fulfilled').value;
    assert.deepEqual(await f.store.readVerified(f.next), second);
    for (const changed of [{ generation: f.first.generation }, { generation: randomUUID() }, { attempt: 2 },
        { owner: 'other-worker' }, { candidateHash: 'sha256:' + '0'.repeat(64) }]) {
        await assert.rejects(f.store.createSuccessor(freeze({ ...f.next, ...changed }), f.firstId));
    }
    await assert.rejects(f.store.createSuccessor(f.next, randomUUID()));
    await assert.rejects(f.store.createSuccessor(f.next, 'none'));
    assert.equal(await models.Binding.countDocuments(), 2);
    const state = await retained(f.next);
    assert.equal(state.lock.generation, f.next.generation);
    assert.equal(state.lock.remoteUncertain, true);
    assert.equal(state.operation.heldTopologyAdmission, true);
    assert.equal(state.owner.generation, OWNER_GENERATION);
});

test('retained terminal admission and stale config-owner generation block succession without release', async t => {
    const f = await serialFixture(t);
    await models.Operation.collection.updateOne({ _id: new mongoose.Types.ObjectId(f.first.operationId) },
        { $set: { heldTopologyAdmission: true } });
    const snapshot = await retained(f.next);
    await assert.rejects(f.store.createSuccessor(f.next, f.firstId));
    assert.deepEqual(await retained(f.next), snapshot);
    await models.Operation.collection.updateOne({ _id: new mongoose.Types.ObjectId(f.first.operationId) },
        { $set: { heldTopologyAdmission: false } });
    await models.Owner.collection.updateOne({}, { $set: { generation: randomUUID() } });
    const changed = await retained(f.next);
    await assert.rejects(f.store.createSuccessor(f.next, f.firstId));
    assert.deepEqual(await retained(f.next), changed);
    assert.equal(await models.Binding.countDocuments(), 1);
});

test('serial enrollment retains global machine, key and endpoint alias reservations', async t => {
    const f = await serialFixture(t);
    await f.store.createSuccessor(f.next, f.firstId);
    const original = await models.Enrollment.findOne().lean();
    for (const same of ['machineId', 'sshHostKeySha256', 'listener']) await t.test(same, async () => {
        const nodeId = new mongoose.Types.ObjectId().toString();
        const identity = { machineId: same === 'machineId' ? IDENTITY.machineId : '5'.repeat(32),
            sshHostKeySha256: same === 'sshHostKeySha256' ? IDENTITY.sshHostKeySha256 : '6'.repeat(64) };
        const endpoint = { ...ENDPOINT, ip: same === 'listener' ? ENDPOINT.ip : '192.0.2.18', username: 'alias' };
        // The immutable enrollment indexes apply independently of mutable HyNode
        // eligibility (which itself also excludes duplicate IP/type selections).
        // Raw local fixture insert reaches the actual unique indexes independently
        // of owner adoption. The store's alias policy must not relax for successors.
        await assert.rejects(models.Enrollment.insertMany([{ ...original, _id: randomUUID(), nodeId,
            targetProfile: 'xray-bridge', nodeIdentity: identity, endpoint }]), error => error.code === 11000);
        assert.equal(await models.Enrollment.countDocuments(), 1);
    });
});

test('first provisioning unknown commit is recovered only by exact durable enrollment readback', async t => {
    for (const committed of [false, true]) await t.test(String(committed), async () => {
        const { expected, enrollment } = await setup(initialAuthority);
        const store = newStore(initialAuthority);
        const proposal = freeze({ ...enrollment, predecessorGeneration: 'none' });
        let accepted;
        await injectCommit(async count => {
            if (committed) accepted = await store.preEnroll(proposal);
            else await assert.rejects(store.preEnroll(proposal));
            assert.equal(count(), 1);
        }, committed);
        assert.equal(await models.Enrollment.countDocuments(), committed ? 1 : 0);
        if (committed) {
            const row = await models.Enrollment.findOne().lean();
            assert.equal(row._id, accepted.enrollmentId);
            assert.deepEqual(row.provisioningReceipt, emptyHead());
            await assert.rejects(store.preEnroll(proposal));
            assert.equal((await store.createBinding(expected)).predecessorGeneration, 'none');
        }
        const state = await retained(expected);
        assert.equal(state.operation.heldTopologyAdmission, true);
        assert.equal(state.lock.generation, expected.generation);
        assert.equal(state.lock.remoteUncertain, true);
    });
});

test('terminal receipt contract refuses BSON-array command identifiers without coercion', async t => {
    const f = await serialFixture(t);
    const { validTerminalReceipt } = require('../models/topologyExecutionBindingContract');
    const commandId = [f.first.commandIds.close];
    assert.equal(validTerminalReceipt({ ...f.status, commandId },
        { ...f.first, commandIds: { ...f.first.commandIds, close: commandId } }), false);
});

test('unknown successor commit confirms once by primary-majority readback and never regenerates', async t => {
    const f = await serialFixture(t);
    const commands = [];
    const listener = event => commands.push(event);
    connection.getClient().on('commandStarted', listener);
    let accepted;
    try {
        await injectCommit(async count => {
            accepted = await f.store.createSuccessor(f.next, f.firstId);
            assert.equal(count(), 1);
        }, true);
    } finally { connection.getClient().off('commandStarted', listener); }
    assert.equal(await models.Binding.countDocuments(), 2);
    const commit = commands.find(event => event.commandName === 'commitTransaction').command;
    assert.equal(commit.writeConcern.w, 'majority');
    const reads = commands.filter(event => event.commandName === 'find' && event.command.autocommit === undefined);
    assert.ok(reads.length > 0);
    assert.ok(reads.every(event => event.command.readConcern.level === 'majority'
        && event.command.maxTimeMS > 0 && event.command.maxTimeMS <= 5000
        && (!event.command.$readPreference || event.command.$readPreference.mode === 'primary')));
    assert.deepEqual(await newStore(f.authority).readVerified(f.next), accepted);
    await assert.rejects(f.store.createSuccessor(f.next, f.firstId));
    assert.equal((await models.Lock.findOne().lean()).generation, f.next.generation);
});

test('unknown abort and committed-but-unconfirmed successor retain exact ownership', async t => {
    for (const committed of [false, true]) await t.test(String(committed), async t => {
        const f = await serialFixture(t);
        const before = await retained(f.next);
        const find = models.Binding.findOne;
        if (committed) models.Binding.findOne = function (...args) {
            const query = find.apply(this, args);
            const lean = query.lean;
            query.lean = function (...leanArgs) {
                if (this.getOptions().readConcern?.level === 'majority' && args[0]._id !== f.firstId) {
                    throw new Error('injected successor confirmation loss');
                }
                return lean.apply(this, leanArgs);
            };
            return query;
        };
        try {
            await injectCommit(async count => {
                await assert.rejects(f.store.createSuccessor(f.next, f.firstId));
                assert.equal(count(), 1);
            }, committed);
        } finally { models.Binding.findOne = find; }
        assert.equal(await models.Binding.countDocuments(), committed ? 2 : 1);
        const after = await retained(f.next);
        for (const field of ['generation', 'owner', 'operationId', 'remoteUncertain', 'leaseUntil']) {
            assert.deepEqual(after.lock[field], before.lock[field]);
        }
        assert.equal(after.operation.heldTopologyAdmission, true);
        assert.equal(after.owner.generation, before.owner.generation);
        if (committed) assert.equal((await newStore(f.authority).readVerified(f.next)).generation, f.next.generation);
    });
});
async function injectCommit(work, afterCommit) {
    const start = connection.startSession;
    let calls = 0;
    connection.startSession = async function (...args) {
        const session = await start.apply(this, args);
        const commit = session.commitTransaction.bind(session);
        session.commitTransaction = async options => {
            calls++;
            if (afterCommit) await commit(options);
            else await session.abortTransaction({ timeoutMS: 5000 });
            const error = new mongoose.mongo.MongoServerError({ message: 'injected unknown commit outcome' });
            error.addErrorLabel('UnknownTransactionCommitResult');
            throw error;
        };
        return session;
    };
    try { return await work(() => calls); }
    finally { connection.startSession = start; }
}

function run(runner, binding, command) {
    const names = { operationId: 'operation-id', nodeId: 'node-id', candidateHash: 'candidate-hash',
        backupId: 'backup-id', targetProfile: 'target-profile', executionContext: 'execution-context',
        attemptId: 'attempt-id', generation: 'generation', predecessorGeneration: 'predecessor-generation' };
    const parts = ['runner', '--command', command];
    for (const [key, flag] of Object.entries(names)) parts.push('--' + flag, binding[key]);
    parts.push('--command-id', binding.commandIds[command === 'status' ? 'close' : command]);
    if (command === 'verify') parts.push('--checks', Buffer.from('[]').toString('base64url'));
    const result = runner.execute(parts.join(' '), { stdin: content });
    assert.equal(result.code, 0, result.stderr);
    return JSON.parse(result.stdout);
}
