'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const modulePath = path.join(__dirname, '../topologyConfigTransfer.js');
const contract = fs.existsSync(modulePath) ? require(modulePath) : {};
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD,
    TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../../modules/relay-l2tp/domain/topologyExecutionContext');

test('transfer accepts explicit canonical TEST identity without adopting a mutable caller context', () => {
    const supplied = { ...TEST };
    const authority = async () => { throw new Error('constructor must not consult external authority'); };
    const service = new contract.TopologyConfigTransfer({ executionContext: supplied,
        TopologyConfigOwner: {}, withVerifiedMaintenance: authority });
    supplied.target = PROD.target;
    supplied.hostIdentity = PROD.hostIdentity;
    assert.equal(service.executionContext, TEST);
    assert.equal(Object.isFrozen(service.executionContext), true);
    assert.throws(() => { service.executionContext = PROD; }, TypeError);
});

test('transfer contract requires an explicit paired server identity and external maintenance authority', () => {
    assert.equal(typeof contract.TopologyConfigTransfer, 'function', 'durable paired transfer contract is missing');
    let externalCalls = 0;
    const authority = async () => { externalCalls++; };
    for (const context of [undefined, {}, { target: 'production', hostIdentity: TEST.hostIdentity },
        { target: 'test', hostIdentity: PROD.hostIdentity }, { ...PROD, clone: true }, { ...TEST, clone: true },
        { target: 'test', hostIdentity: 'foreign.infograd.online' }]) {
        assert.throws(() => new contract.TopologyConfigTransfer({ executionContext: context,
            TopologyConfigOwner: {}, withVerifiedMaintenance: authority }), /server-owned TEST or production context/);
    }
    for (const executionContext of [TEST, PROD]) {
        assert.throws(() => new contract.TopologyConfigTransfer({ executionContext }), /maintenance authority/);
    }
    assert.equal(externalCalls, 0);
});

const fsp = require('node:fs/promises');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID, createHash } = require('node:crypto');
const mongoose = require('mongoose');
const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to an isolated local MongoDB binary' };
let connection, child, directory, Model;
const NODE = '507f1f77bcf86cd799439011';
const IDENTITY = Object.freeze({ machineId: '1'.repeat(32), sshHostKeySha256: '2'.repeat(64) });
const SNAPSHOT = Object.freeze({ configSha256: '3'.repeat(64), unitSha256: '4'.repeat(64), serviceActive: 'active', serviceEnabled: 'enabled' });
async function until(work) {
    let error;
    for (let i = 0; i < 120; i++) {
        try { return await work(); } catch (e) { error = e; }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw error;
}
test.before(async () => {
    if (!process.env.C3_MONGOD) return;
    assert.ok(process.env.TMPDIR, 'isolated Mongo files require TMPDIR');
    directory = await fsp.mkdtemp(path.join(process.env.TMPDIR, 'c3-owner-db-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => { const p = server.address().port; server.close(() => resolve(p)); });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', 'ownerScratch', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const uri = `mongodb://127.0.0.1:${port}/owner_scratch?directConnection=true`;
    const client = new mongoose.mongo.MongoClient(uri, { serverSelectionTimeoutMS: 100 });
    try {
        await until(() => client.connect());
        await client.db('admin').command({ replSetInitiate: { _id: 'ownerScratch', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    } finally { await client.close(); }
    connection = await mongoose.createConnection(uri.replace('?directConnection=true', '?replicaSet=ownerScratch'),
        { serverSelectionTimeoutMS: 1000, monitorCommands: true }).asPromise();
});
test.after(async () => {
    if (connection) {
        await connection.dropDatabase();
        assert.equal((await connection.getClient().db('admin').admin().listDatabases()).databases.some(db => db.name === 'owner_scratch'), false);
        await connection.close();
    }
    if (child && child.exitCode === null) {
        const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM'); await exited;
    }
    if (directory) await fsp.rm(directory, { recursive: true, force: true });
});
// Run the same persistence and authority regressions for both explicit identities.
for (const CONTEXT of [TEST, PROD]) {
const FOREIGN = CONTEXT === TEST ? PROD : TEST;
const test = (name, ...args) => require('node:test')(`${CONTEXT.target}: ${name}`, ...args);
async function setup(authority = async () => { throw new Error('No external proof'); }) {
    const modelPath = path.join(__dirname, '../../models/topologyConfigOwnerModel.js');
    assert.equal(fs.existsSync(modelPath), true, 'durable owner model is missing');
    Model ||= connection.model('TopologyConfigOwner', require(modelPath).schema);
    await Model.init();
    await Model.deleteMany({});
    return new contract.TopologyConfigTransfer({ executionContext: CONTEXT, TopologyConfigOwner: Model, withVerifiedMaintenance: authority });
}

test('missing legacy ownership stays classic but cannot adopt; explicit records are exact node/profile and classic initially', local, async () => {
    const service = await setup();
    assert.equal(typeof service.initializeClassic, 'function', 'explicit classic initialization is missing');
    const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    assert.equal(row.owner, 'classic');
    assert.deepEqual(row.executionContext, CONTEXT);
    assert.equal(row.node.toString(), NODE);
    assert.equal(row.profile, 'xray-main');
    assert.match(row.generation, /^[a-f0-9-]{36}$/);
    assert.equal(await Model.countDocuments(), 1);
    await assert.rejects(service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY }), /duplicate key/);
    await assert.rejects(service.initializeClassic({ node: NODE, profile: 'unknown', nodeIdentity: IDENTITY }), /profile/);
    const bridge = await service.initializeClassic({ node: NODE, profile: 'xray-bridge', nodeIdentity: IDENTITY });
    assert.equal(bridge.owner, 'classic');
    assert.notEqual(bridge.generation, row.generation);
});

function evidence(binding, changes = {}) {
    return { status: 'verified', authority: 'external-maintenance-v1', proofId: randomUUID(),
        binding: structuredClone(binding), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
        oldBackend: { instanceId: 'old-prod-backend', pid: 42, processStartTime: 'server-observed-start-id',
            processTree: 'stopped', dispatch: 'disabled' },
        readback: { source: 'node-readback', ...SNAPSHOT }, ...changes };
}
const goodAuthority = async ({ binding }, work) => work(evidence(binding));

test('public maintenance chain provisions real-store enrollment and hands back only after local byte/state restoration', local, async () => {
    // Only the physical controller and systemd are simulated. The actual owner
    // service, public schemas, enrollment store and replica-set CAS are exercised.
    const root = await fsp.mkdtemp(path.join(directory, 'simulated-node-'));
    const configFile = path.join(root, 'config.json');
    const unitFile = path.join(root, 'xray.service');
    const stateFile = path.join(root, 'service-state.json');
    const originalConfig = Buffer.from('{"outbounds":[{"tag":"original-direct"}]}\n');
    const originalUnit = Buffer.from('[Service]\nExecStart=/usr/local/bin/xray run -config original.json\n');
    const originalState = Buffer.from('{"serviceActive":"active","serviceEnabled":"enabled"}\n');
    const restore = () => Promise.all([[configFile, originalConfig], [unitFile, originalUnit], [stateFile, originalState]]
        .map(([file, bytes]) => fsp.writeFile(file, bytes)));
    const readback = async () => ({ source: 'node-readback',
        configSha256: createHash('sha256').update(await fsp.readFile(configFile)).digest('hex'),
        unitSha256: createHash('sha256').update(await fsp.readFile(unitFile)).digest('hex'),
        ...JSON.parse(await fsp.readFile(stateFile, 'utf8')) });
    await restore();
    let held = false;
    const service = await setup(async ({ binding }, work) => {
        assert.deepEqual(binding.executionContext, CONTEXT);
        assert.deepEqual(binding.nodeIdentity, IDENTITY);
        held = true;
        // Failure intentionally leaves the simulated hold retained.
        const result = await work(evidence(binding, { readback: await readback() }));
        held = false;
        return result;
    });
    const classic = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    assert.equal(classic.owner, 'classic');
    assert.equal(classic.originalSnapshot, undefined);
    assert.equal(classic.adoptionReceipt, undefined);
    const observed = [];
    const observe = event => {
        if (['update', 'commitTransaction'].includes(event.commandName)
            || (event.commandName === 'find' && event.command.filter.owner === 'topology')) {
            observed.push(event.commandName);
            assert.equal(held, true, `${event.commandName} escaped maintenance`);
        }
    };
    connection.getClient().on('commandStarted', observe);
    let adopted;
    try { adopted = await service.adopt({ node: NODE, profile: 'xray-main', generation: classic.generation, proofRef: 'local-backup' }); }
    finally { connection.getClient().off('commandStarted', observe); }
    assert.ok(observed.includes('commitTransaction'));
    assert.deepEqual(adopted.executionContext, CONTEXT);
    assert.equal(adopted.adoptionReceipt.fromGeneration, classic.generation);
    assert.equal(adopted.adoptionReceipt.toGeneration, adopted.generation);
    const { source, ...originalSnapshot } = await readback();
    assert.deepEqual(adopted.originalSnapshot, originalSnapshot);

    const bind = (name, location) => connection.models[name] || connection.model(name, require(location).schema);
    const models = {
        Owner: Model,
        Operation: bind('TopologyOperation', '../../modules/relay-l2tp/models/topologyOperationModel'),
        Lock: bind('NodeOperationLock', '../../modules/relay-l2tp/models/nodeOperationLockModel'),
        Enrollment: bind('TopologyExecutionEnrollment', '../../modules/relay-l2tp/models/topologyExecutionEnrollmentModel'),
        Binding: bind('TopologyExecutionBinding', '../../modules/relay-l2tp/models/topologyExecutionBindingModel'),
        HyNode: bind('TransferLocalNode', '../../models/hyNodeModel'),
    };
    await Promise.all(Object.values(models).map(model => model.init()));
    // Exact isolated scratch collections only; immutable public rows stay immutable.
    await Promise.all([models.Enrollment, models.Binding, models.HyNode].map(model => model.collection.deleteMany({})));
    const endpoint = Object.freeze({ ip: '192.0.2.17', port: 2222, username: 'c3-test-runner' });
    await models.HyNode.create({ _id: NODE, name: 'local-maintenance-only', ip: endpoint.ip,
        type: 'xray', active: true, cascadeRole: 'portal', ssh: { port: endpoint.port, username: endpoint.username } });
    const bootId = randomUUID(), maintenanceId = randomUUID();
    const { TopologyExecutionBindingStore } = require('../../modules/relay-l2tp/repositories/topologyExecutionBindingStore');
    const store = new TopologyExecutionBindingStore({ executionContext: CONTEXT, ...models,
        withVerifiedAuthority: async (challenge, work) => {
            assert.deepEqual(challenge.executionContext, CONTEXT);
            return work({ authority: 'external-execution-maintenance-v1', status: 'verified', challenge: structuredClone(challenge),
                proofId: randomUUID(), maintenanceId, maintenance: 'held', allWriters: 'drained', bootstrapWriters: 'excluded',
                physicalIdentity: { ...IDENTITY }, owner: 'topology',
                connectionAttestation: { authority: 'server-physical-ssh-endpoint-v1', endpoint: { ...endpoint },
                    physicalIdentity: { ...IDENTITY }, maintenanceId, aliases: 'excluded',
                    hostKeyDigest: 'raw-ssh-public-key-sha256', endpointReassignment: 'excluded' },
                predecessor: { generation: 'none', bootId, status: 'empty', protocolVersion: 2,
                    journal: 'absent', legacyState: 'absent', writers: 'excluded' },
                oldBackend: { instanceId: 'simulated-old-backend', pid: 42, processStartTime: 'simulated-start',
                    processTree: 'stopped', dispatch: 'disabled' } });
        } });
    const enrollment = await store.preEnroll({ nodeId: NODE, targetProfile: 'xray-main', endpoint,
        nodeIdentity: IDENTITY, ownerGeneration: adopted.generation, predecessorGeneration: 'none', bootId });
    assert.equal(enrollment.ownerGeneration, adopted.generation);
    const persisted = await models.Enrollment.findById(enrollment.enrollmentId).read('primary').readConcern('majority').lean();
    assert.equal(persisted.executionContext, CONTEXT.hostIdentity);
    assert.deepEqual(persisted.endpoint, endpoint);
    assert.equal(persisted.provisioningReceipt.writers, 'excluded');

    await fsp.writeFile(configFile, '{"outbounds":[]}\n');
    await fsp.writeFile(unitFile, '[Service]\nExecStart=/different\n');
    await fsp.writeFile(stateFile, '{"serviceActive":"inactive","serviceEnabled":"disabled"}\n');
    const input = { node: NODE, profile: 'xray-main', generation: adopted.generation, proofRef: 'local-restore' };
    await assert.rejects(service.handback(input), { code: 'CONFIG_RESTORATION_MISMATCH' });
    assert.equal(held, true);
    assert.equal((await Model.findOne({ node: NODE }).lean()).generation, adopted.generation);
    await restore();
    const restored = await service.handback(input);
    assert.equal(restored.owner, 'classic');
    assert.deepEqual(restored.originalSnapshot, originalSnapshot);
    assert.deepEqual(restored.adoptionReceipt, adopted.adoptionReceipt);
    assert.equal(restored.handbackReceipt.fromGeneration, adopted.generation);
    assert.equal(restored.handbackReceipt.toGeneration, restored.generation);
    assert.deepEqual(await fsp.readFile(configFile), originalConfig);
    assert.deepEqual(await fsp.readFile(unitFile), originalUnit);
    assert.deepEqual(await fsp.readFile(stateFile), originalState);
    assert.equal(held, false);
    assert.equal(await models.Operation.countDocuments(), 0, 'maintenance provisioning must not claim or create operations');
    assert.equal(await models.Lock.countDocuments(), 0);
    await fsp.rm(root, { recursive: true, force: true });
});

test('opposite canonical service cannot adopt or initialize over the exact occupied global node/profile slot', local, async () => {
    let externalCalls = 0;
    const service = await setup(goodAuthority);
    const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    const foreign = new contract.TopologyConfigTransfer({ executionContext: FOREIGN, TopologyConfigOwner: Model,
        withVerifiedMaintenance: async () => { externalCalls++; throw new Error('foreign authority must not run'); } });
    await assert.rejects(foreign.adopt({ node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'foreign' }),
        { code: 'CONFIG_OWNERSHIP_CONFLICT' });
    await assert.rejects(foreign.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY }), /duplicate key/);
    const unchanged = await Model.findOne({ node: NODE }).lean();
    assert.deepEqual(unchanged, row);
    const adopted = await service.adopt({ node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'local' });
    await assert.rejects(foreign.handback({ node: NODE, profile: 'xray-main', generation: adopted.generation, proofRef: 'foreign' }),
        { code: 'CONFIG_OWNERSHIP_CONFLICT' });
    assert.deepEqual(await Model.findOne({ node: NODE }).lean(), adopted);
    assert.equal(externalCalls, 0);
});

test('classic initialization is majority written and confirmed by an exact bounded majority readback', local, async () => {
    const service = await setup();
    const commands = [];
    const observe = event => { if (['insert', 'find'].includes(event.commandName)) commands.push(event.command); };
    connection.getClient().on('commandStarted', observe);
    try {
        const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
        assert.equal(commands.find(command => command.insert)?.writeConcern?.w, 'majority');
        const confirmation = commands.find(command => command.find && command.filter.generation === row.generation);
        assert.ok(confirmation, 'initialization must read back the exact new generation');
        assert.equal(confirmation.readConcern.level, 'majority');
        assert.ok(confirmation.maxTimeMS > 0 && confirmation.maxTimeMS <= 5000);
    } finally { connection.getClient().off('commandStarted', observe); }
});

test('adoption requires external maintenance proof and durably CASes exact classic generation without changing other profiles', local, async () => {
    let maintenanceHeld = false;
    const service = await setup(async ({ binding, proofRef }, work) => {
        assert.equal(proofRef, 'opaque-external-reference');
        maintenanceHeld = true;
        try { return await work(evidence(binding)); } finally { maintenanceHeld = false; }
    });
    assert.equal(typeof service.adopt, 'function', 'transactional adoption is missing');
    const main = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    const bridge = await service.initializeClassic({ node: NODE, profile: 'xray-bridge', nodeIdentity: IDENTITY });
    const originalUpdate = Model.findOneAndUpdate.bind(Model);
    const update = Model.findOneAndUpdate;
    Model.findOneAndUpdate = (...args) => { assert.equal(maintenanceHeld, true); return originalUpdate(...args); };
    try {
        const adopted = await service.adopt({ node: NODE, profile: 'xray-main', generation: main.generation, proofRef: 'opaque-external-reference' });
        assert.equal(adopted.owner, 'topology');
        assert.notEqual(adopted.generation, main.generation);
        assert.deepEqual(adopted.originalSnapshot, SNAPSHOT);
        assert.equal(adopted.adoptionReceipt.fromGeneration, main.generation);
        assert.equal(adopted.adoptionReceipt.toGeneration, adopted.generation);
        assert.equal(adopted.adoptionReceipt.oldPid, 42);
        const restarted = new contract.TopologyConfigTransfer({ executionContext: CONTEXT, TopologyConfigOwner: Model, withVerifiedMaintenance: goodAuthority });
        await assert.rejects(restarted.adopt({ node: NODE, profile: 'xray-main', generation: main.generation, proofRef: 'replay' }), { code: 'CONFIG_OWNERSHIP_CONFLICT' });
        assert.equal((await Model.findOne({ node: NODE, profile: 'xray-bridge' }).lean()).generation, bridge.generation);
    } finally { Model.findOneAndUpdate = update; }
});

test('handback requires exact readback of original config, unit, active and enabled service state', local, async () => {
    const service = await setup(goodAuthority);
    assert.equal(typeof service.handback, 'function', 'verified restoration handback is missing');
    const classic = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    const adopted = await service.adopt({ node: NODE, profile: 'xray-main', generation: classic.generation, proofRef: 'external-ref' });
    for (const [field, wrong] of [['configSha256', '5'.repeat(64)], ['unitSha256', '6'.repeat(64)],
        ['serviceActive', 'inactive'], ['serviceEnabled', 'disabled']]) {
        const wrongRestoration = new contract.TopologyConfigTransfer({ executionContext: CONTEXT, TopologyConfigOwner: Model,
            withVerifiedMaintenance: async ({ binding }, work) => work(evidence(binding,
                { readback: { source: 'node-readback', ...SNAPSHOT, [field]: wrong } })) });
        await assert.rejects(wrongRestoration.handback({ node: NODE, profile: 'xray-main', generation: adopted.generation, proofRef: 'external-ref' }),
            { code: 'CONFIG_RESTORATION_MISMATCH' });
        assert.equal((await Model.findOne({ node: NODE }).lean()).owner, 'topology');
    }
    const restored = await service.handback({ node: NODE, profile: 'xray-main', generation: adopted.generation, proofRef: 'external-ref' });
    assert.equal(restored.owner, 'classic');
    assert.notEqual(restored.generation, adopted.generation);
    assert.deepEqual(restored.originalSnapshot, SNAPSHOT);
    assert.equal(restored.handbackReceipt.fromGeneration, adopted.generation);
    assert.equal(restored.handbackReceipt.toGeneration, restored.generation);
    assert.deepEqual(restored.adoptionReceipt, adopted.adoptionReceipt);
    await assert.rejects(service.handback({ node: NODE, profile: 'xray-main', generation: adopted.generation, proofRef: 'external-ref' }),
        { code: 'CONFIG_OWNERSHIP_CONFLICT' });
});

test('missing proof reference and unbound legacy owner records cannot be promoted even by a flag-positive caller', local, async () => {
    const service = await setup(goodAuthority);
    const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    await assert.rejects(service.adopt({ node: NODE, profile: 'xray-main', generation: row.generation,
        maintenanceVerified: true, oldPidStopped: true }), { code: 'CONFIG_TRANSFER_PROOF_INVALID' });
    await Model.collection.updateOne({ node: new mongoose.Types.ObjectId(NODE) }, { $unset: { nodeIdentity: 1 } });
    await assert.rejects(service.adopt({ node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'external-ref' }),
        { code: 'CONFIG_OWNERSHIP_CONFLICT' });
    assert.equal((await Model.findOne({ node: NODE }).lean()).owner, 'classic');
});

for (const [name, corrupt] of [
    ['missing proof', () => undefined],
    ['unknown proof status', proof => ({ ...proof, status: 'unknown' })],
    ['cross node', proof => { proof.binding.node = '507f1f77bcf86cd799439012'; return proof; }],
    ['cross profile', proof => { proof.binding.profile = 'xray-bridge'; return proof; }],
    ['foreign canonical context', proof => { proof.binding.executionContext = { ...FOREIGN }; return proof; }],
    ['cross-paired host', proof => { proof.binding.executionContext.hostIdentity = FOREIGN.hostIdentity; return proof; }],
    ['cloned physical node', proof => { proof.binding.nodeIdentity.machineId = '9'.repeat(32); return proof; }],
    ['cross SSH identity', proof => { proof.binding.nodeIdentity.sshHostKeySha256 = '8'.repeat(64); return proof; }],
    ['stale generation', proof => { proof.binding.generation = randomUUID(); return proof; }],
    ['wrong next generation', proof => { proof.binding.nextGeneration = randomUUID(); return proof; }],
    ['foreign action', proof => { proof.binding.action = 'handback'; return proof; }],
    ['wrong config path', proof => { proof.binding.paths.configPath = '/some/clone/config.json'; return proof; }],
    ['local marker not authority', proof => ({ ...proof, authority: 'operation-history' })],
    ['maintenance not held', proof => ({ ...proof, maintenance: 'expired' })],
    ['undrained writers', proof => ({ ...proof, allWriters: 'unknown' })],
    ['unknown old PID exit', proof => { proof.oldBackend.processTree = 'unknown'; return proof; }],
    ['old dispatcher can resume', proof => { proof.oldBackend.dispatch = 'enabled'; return proof; }],
    ['missing old PID identity', proof => { delete proof.oldBackend.processStartTime; return proof; }],
    ['flag not node readback', proof => { proof.readback.source = 'restored-flag'; return proof; }],
    ['missing snapshot', proof => { delete proof.readback; return proof; }],
    ['missing config readback', proof => { delete proof.readback.configSha256; return proof; }],
    ['missing unit readback', proof => { delete proof.readback.unitSha256; return proof; }],
    ['missing active state', proof => { delete proof.readback.serviceActive; return proof; }],
    ['missing enabled state', proof => { delete proof.readback.serviceEnabled; return proof; }],
    ['unknown service state', proof => { proof.readback.serviceActive = 'unknown'; return proof; }],
]) {
    test(`adoption rejects ${name} without changing ownership`, local, async () => {
        const service = await setup(async ({ binding }, work) => work(corrupt(evidence(binding))));
        const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
        await assert.rejects(service.adopt({ node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'external-ref' }),
            { code: 'CONFIG_TRANSFER_PROOF_INVALID' });
        const unchanged = await Model.findOne({ node: NODE }).lean();
        assert.equal(unchanged.owner, 'classic');
        assert.equal(unchanged.generation, row.generation);
        assert.equal(unchanged.adoptionReceipt, undefined);
    });
}

test('missing, cloned and cross-paired durable records fail before consulting external authority', local, async () => {
    let proofs = 0;
    const service = await setup(async () => { proofs++; throw new Error('must not verify'); });
    const generation = randomUUID();
    for (const extra of [null, {}, { executionContext: { ...FOREIGN } },
        { executionContext: { ...CONTEXT, hostIdentity: FOREIGN.hostIdentity } },
        { executionContext: { ...CONTEXT, clone: 'cloned-db' } }]) {
        await Model.deleteMany({});
        if (extra) await Model.collection.insertOne({ node: new mongoose.Types.ObjectId(NODE), profile: 'xray-main',
            owner: 'classic', generation, nodeIdentity: IDENTITY, ...extra });
        await assert.rejects(service.adopt({ node: NODE, profile: 'xray-main', generation, proofRef: 'external-ref' }),
            { code: 'CONFIG_OWNERSHIP_CONFLICT' });
    }
    assert.equal(proofs, 0);
});

test('missing durable unique node/profile index blocks transfer before external verification', local, async () => {
    let proofs = 0;
    const service = await setup(async ({ binding }, work) => { proofs++; return work(evidence(binding)); });
    const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    await Model.collection.dropIndex('node_1_profile_1');
    try {
        await assert.rejects(service.adopt({ node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'external-ref' }),
            { code: 'CONFIG_OWNERSHIP_INDEX_REQUIRED' });
        assert.equal(proofs, 0);
        assert.equal((await Model.findOne({ node: NODE }).lean()).owner, 'classic');
    } finally { await Model.createIndexes(); }
});

test('concurrent adoption from one generation has one durable winner on real Mongo', local, async () => {
    let entered = 0, release;
    const ready = new Promise(resolve => { release = resolve; });
    const service = await setup(async ({ binding }, work) => {
        if (++entered === 2) release();
        await ready;
        return work(evidence(binding));
    });
    const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    const input = { node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'external-ref' };
    const outcomes = await Promise.allSettled([service.adopt(input), service.adopt(input)]);
    assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 1);
    assert.equal(outcomes.find(result => result.status === 'rejected').reason.code, 'CONFIG_OWNERSHIP_CONFLICT');
    const stored = await Model.findOne({ node: NODE }).lean();
    assert.equal(stored.owner, 'topology');
    assert.equal(stored.generation, outcomes.find(result => result.status === 'fulfilled').value.generation);
    assert.equal(stored.adoptionReceipt.fromGeneration, row.generation);
});

test('aborted transaction rolls back owner and proof receipt together', local, async () => {
    const service = await setup(goodAuthority);
    const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    const transaction = connection.transaction;
    connection.transaction = work => transaction.call(connection, async session => {
        await work(session); throw new Error('injected abort after CAS');
    });
    try {
        await assert.rejects(service.adopt({ node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'external-ref' }), /injected abort/);
    } finally { connection.transaction = transaction; }
    const stored = await Model.findOne({ node: NODE }).lean();
    assert.equal(stored.owner, 'classic');
    assert.equal(stored.generation, row.generation);
    assert.equal(stored.adoptionReceipt, undefined);
});

test('injected unknown post-commit does not hand back or blindly retry a committed generation', local, async () => {
    let held = false;
    const service = await setup(async ({ binding }, work) => {
        held = true;
        const result = await work(evidence(binding));
        held = false;
        return result;
    });
    const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    const transaction = connection.transaction;
    let transactions = 0;
    connection.transaction = async (work, options) => {
        transactions++;
        await transaction.call(connection, work, options);
        throw Object.assign(new Error('injected unknown commit'), { hasErrorLabel: label => label === 'UnknownTransactionCommitResult' });
    };
    try {
        await assert.rejects(service.adopt({ node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'external-ref' }), /unknown commit/);
    } finally { connection.transaction = transaction; }
    const stored = await Model.findOne({ node: NODE }).readConcern('majority').lean();
    assert.equal(transactions, 1);
    assert.equal(held, true, 'unknown commit must leave external maintenance retained');
    assert.equal(stored.owner, 'topology');
    assert.notEqual(stored.generation, row.generation);
    assert.equal(stored.adoptionReceipt.toGeneration, stored.generation);
    await assert.rejects(service.adopt({ node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'external-ref' }),
        { code: 'CONFIG_OWNERSHIP_CONFLICT' });
});

test('a verifier returning a bare success marker cannot synthesize a transfer', local, async () => {
    const service = await setup(async () => true);
    const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    await assert.rejects(service.adopt({ node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'external-ref' }),
        { code: 'CONFIG_TRANSFER_PROOF_INVALID' });
    assert.equal((await Model.findOne({ node: NODE }).lean()).owner, 'classic');
});

test('authority cannot invoke a retained proof callback after its maintenance scope has returned', local, async () => {
    let callback, binding;
    const service = await setup(async (request, work) => { callback = work; binding = request.binding; });
    const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    await assert.rejects(service.adopt({ node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'external-ref' }),
        { code: 'CONFIG_TRANSFER_PROOF_INVALID' });
    await assert.rejects(callback(evidence(binding)), { code: 'CONFIG_TRANSFER_PROOF_INVALID' });
    assert.equal((await Model.findOne({ node: NODE }).lean()).owner, 'classic');
});

test('authority must await the transaction scope rather than returning while a callback is pending', local, async () => {
    let pending;
    const service = await setup(async ({ binding }, work) => {
        pending = work(evidence(binding));
        pending.catch(() => {});
        return true;
    });
    const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    await assert.rejects(service.adopt({ node: NODE, profile: 'xray-main', generation: row.generation, proofRef: 'external-ref' }),
        { code: 'CONFIG_TRANSFER_PROOF_INVALID' });
    await assert.rejects(pending, { code: 'CONFIG_TRANSFER_PROOF_INVALID' });
    assert.equal((await Model.findOne({ node: NODE }).lean()).owner, 'classic');
});
}
