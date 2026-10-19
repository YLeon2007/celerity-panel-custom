'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const modulePath = path.join(__dirname, '../topologyConfigTransfer.js');
const contract = fs.existsSync(modulePath) ? require(modulePath) : {};
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../../modules/relay-l2tp/domain/topologyExecutionContext');

test('transfer contract requires an explicit server-owned PROD context and external maintenance authority', () => {
    assert.equal(typeof contract.TopologyConfigTransfer, 'function', 'durable paired transfer contract is missing');
    for (const context of [undefined, { target: 'production', hostIdentity: 'test.infograd.online' },
        { target: 'test', hostIdentity: 'test.infograd.online' }, { ...PROD, clone: true }]) {
        assert.throws(() => new contract.TopologyConfigTransfer({ executionContext: context }), /production context/);
    }
    assert.throws(() => new contract.TopologyConfigTransfer({ executionContext: PROD }), /maintenance authority/);
});

const fsp = require('node:fs/promises');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
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
    connection = await mongoose.createConnection(uri, { serverSelectionTimeoutMS: 1000, monitorCommands: true }).asPromise();
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
async function setup(authority = async () => { throw new Error('No external proof'); }) {
    const modelPath = path.join(__dirname, '../../models/topologyConfigOwnerModel.js');
    assert.equal(fs.existsSync(modelPath), true, 'durable owner model is missing');
    Model ||= connection.model('TopologyConfigOwner', require(modelPath).schema);
    await Model.init();
    await Model.deleteMany({});
    return new contract.TopologyConfigTransfer({ executionContext: PROD, TopologyConfigOwner: Model, withVerifiedMaintenance: authority });
}

test('missing legacy ownership stays classic but cannot adopt; explicit records are exact node/profile and classic initially', local, async () => {
    const service = await setup();
    assert.equal(typeof service.initializeClassic, 'function', 'explicit classic initialization is missing');
    const row = await service.initializeClassic({ node: NODE, profile: 'xray-main', nodeIdentity: IDENTITY });
    assert.equal(row.owner, 'classic');
    assert.deepEqual(row.executionContext, PROD);
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
        const restarted = new contract.TopologyConfigTransfer({ executionContext: PROD, TopologyConfigOwner: Model, withVerifiedMaintenance: goodAuthority });
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
        const wrongRestoration = new contract.TopologyConfigTransfer({ executionContext: PROD, TopologyConfigOwner: Model,
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
    ['cloned TEST context', proof => { proof.binding.executionContext = { target: 'test', hostIdentity: 'test.infograd.online' }; return proof; }],
    ['cross-paired PROD host', proof => { proof.binding.executionContext.hostIdentity = 'test.infograd.online'; return proof; }],
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
    ['missing unit readback', proof => { delete proof.readback.unitSha256; return proof; }],
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
    for (const extra of [null, {}, { executionContext: { target: 'test', hostIdentity: 'test.infograd.online' } },
        { executionContext: { target: 'production', hostIdentity: 'test.infograd.online' } },
        { executionContext: { ...PROD, clone: 'test-db' } }]) {
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
    const service = await setup(goodAuthority);
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
