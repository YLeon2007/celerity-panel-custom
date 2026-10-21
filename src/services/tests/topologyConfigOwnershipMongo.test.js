'use strict';
// Real isolated replica-set owner reads + public transfer. Physical maintenance
// evidence is SIMULATED; no SSH, agent, filesystem/service or live DB operations.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const mongoose = require('mongoose');
const { topologyManagesNodeConfig } = require('../topologyConfigOwnership');
const { TopologyConfigTransfer } = require('../topologyConfigTransfer');
const { TOPOLOGY_EXECUTION_CONTEXTS } = require('../../modules/relay-l2tp/domain/topologyExecutionContext');
const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD for isolated Mongo acceptance' };
const NODE = new mongoose.Types.ObjectId('507f1f77bcf86cd799439011');
const OTHER = new mongoose.Types.ObjectId('507f1f77bcf86cd799439012');
const identity = { machineId: '1'.repeat(32), sshHostKeySha256: '2'.repeat(64) };
const snapshot = { source: 'node-readback', configSha256: '3'.repeat(64), unitSha256: '4'.repeat(64),
    serviceActive: 'active', serviceEnabled: 'enabled' };
let directory, child, Owner, Operation;
async function until(work) {
    let last;
    for (let i = 0; i < 160; i++) {
        try { return await work(); } catch (error) { last = error; }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw last;
}
test.before(async () => {
    if (!process.env.C3_MONGOD) return;
    assert.ok(process.env.TMPDIR, 'Scratch TMPDIR required');
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'owner-veto-mongo-'));
    const port = await new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(() => resolve(port)); });
    });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', 'vetoScratch', '--setParameter', 'enableTestCommands=1', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const direct = `mongodb://127.0.0.1:${port}/owner_veto_scratch?directConnection=true`;
    const admin = new mongoose.mongo.MongoClient(direct, { serverSelectionTimeoutMS: 100 });
    try {
        await until(() => admin.connect());
        await admin.db('admin').command({ replSetInitiate: { _id: 'vetoScratch', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await until(async () => assert.equal((await admin.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    } finally { await admin.close(); }
    await mongoose.connect(direct.replace('?directConnection=true', '?replicaSet=vetoScratch'), {
        autoCreate: false, autoIndex: false, monitorCommands: true, serverSelectionTimeoutMS: 1000,
    });
    Operation = require('../../modules/relay-l2tp/models/topologyOperationModel');
    await Operation.createCollection();
});
test.after(async () => {
    if (mongoose.connection.readyState) {
        assert.equal(mongoose.connection.db.databaseName, 'owner_veto_scratch');
        await mongoose.connection.dropDatabase();
        await mongoose.disconnect();
    }
    if (child && child.exitCode === null) {
        const exit = new Promise(resolve => child.once('exit', resolve));
        child.kill('SIGTERM'); await exit;
    }
    if (directory) await fs.rm(directory, { recursive: true, force: true });
});
const envFor = context => ({ PANEL_DOMAIN: context.hostIdentity });
const input = () => ({ _id: NODE, cascadeRole: 'edited-unrelated-role' });
async function readonly(context, expected, error) {
    const commands = [];
    const listener = event => commands.push(event);
    const client = mongoose.connection.getClient();
    client.on('commandStarted', listener);
    try {
        if (error) await assert.rejects(topologyManagesNodeConfig(input(), envFor(context)), error);
        else assert.equal(await topologyManagesNodeConfig(input(), envFor(context)), expected);
    } finally { client.off('commandStarted', listener); }
    assert.ok(commands.length > 0);
    assert.deepEqual(commands.filter(event => !['find', 'getMore', 'killCursors'].includes(event.commandName)).map(event => event.commandName), []);
    const ownerFind = commands.find(event => event.commandName === 'find' && event.command.find === 'topologyconfigowners');
    assert.ok(ownerFind, 'actual native owner query missing');
    assert.equal(ownerFind.command.readConcern.level, 'majority');
    assert.ok(ownerFind.command.maxTimeMS > 0 && ownerFind.command.maxTimeMS <= 5000);
    assert.equal(ownerFind.command.limit, 3);
}
async function owners() {
    if (!Owner) {
        Owner = require('../../models/topologyConfigOwnerModel');
        await Owner.createCollection();
        await Owner.createIndexes();
    }
    await Owner.collection.deleteMany({});
    return Owner;
}
function transfer(context) {
    return new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: Owner,
        withVerifiedMaintenance: async ({ binding }, work) => work({
            status: 'verified', authority: 'external-maintenance-v1', proofId: randomUUID(), maintenanceId: randomUUID(),
            binding: structuredClone(binding), maintenance: 'held', allWriters: 'drained',
            oldBackend: { instanceId: 'SIMULATED-old-backend', pid: 42, processStartTime: 'simulated-start',
                processTree: 'stopped', dispatch: 'disabled' }, readback: { ...snapshot },
        }),
    });
}
test('absent owner namespace is read-only classic, never imports/provisions owner model', local, async () => {
    assert.equal(mongoose.models.TopologyConfigOwner, undefined);
    for (const context of TOPOLOGY_EXECUTION_CONTEXTS) await readonly(context, false);
    assert.equal(mongoose.models.TopologyConfigOwner, undefined);
    assert.equal((await mongoose.connection.db.listCollections({ name: 'topologyconfigowners' }).toArray()).length, 0);
});
for (const context of TOPOLOGY_EXECUTION_CONTEXTS) {
    test(`${context.target}: actual public initialize/adopt/handback remains paired and read-only at veto`, local, async () => {
        await owners();
        const service = transfer(context);
        const classic = await service.initializeClassic({ node: String(NODE), profile: 'xray-main', nodeIdentity: identity });
        await readonly(context, false);
        const adopted = await service.adopt({ node: String(NODE), profile: 'xray-main', generation: classic.generation, proofRef: 'SIMULATED-snapshot' });
        await readonly(context, true);
        // A different classic node is never adopted by this veto.
        assert.equal(await topologyManagesNodeConfig({ _id: OTHER }, envFor(context)), false);
        const returned = await service.handback({ node: String(NODE), profile: 'xray-main', generation: adopted.generation, proofRef: 'SIMULATED-restoration' });
        assert.equal(returned.handbackReceipt.fromGeneration, adopted.generation);
        await readonly(context, false);
        // Changing only the classic label cannot bypass receipt-generation checks.
        await Owner.collection.updateOne({ node: NODE }, { $set: { generation: randomUUID() } });
        await readonly(context, undefined, { code: 'CONFIG_OWNERSHIP_UNCERTAIN' });
    });
    test(`${context.target}: foreign, malformed BSON, duplicate profiles and overflow veto rather than rewriting`, local, async () => {
        await owners();
        const classic = await transfer(context).initializeClassic({ node: String(NODE), profile: 'xray-main', nodeIdentity: identity });
        const raw = await Owner.collection.findOne({ node: NODE });
        const foreign = TOPOLOGY_EXECUTION_CONTEXTS.find(candidate => candidate !== context);
        for (const change of [{ executionContext: foreign }, { node: [NODE] }, { generation: [classic.generation] },
            { owner: 'unknown' }, { profile: 'unknown' }]) {
            await Owner.collection.deleteMany({});
            await Owner.collection.insertOne({ ...raw, ...change });
            await readonly(context, undefined, { code: 'CONFIG_OWNERSHIP_UNCERTAIN' });
        }
        await Owner.collection.deleteMany({});
        await Owner.collection.dropIndex('node_1_profile_1');
        try {
            await Owner.collection.insertMany([0, 1, 2].map(() => ({ ...raw, _id: new mongoose.Types.ObjectId() })));
            await readonly(context, undefined, { code: 'CONFIG_OWNERSHIP_UNCERTAIN' });
        } finally {
            await Owner.collection.deleteMany({});
            await Owner.createIndexes();
        }
    });
}
test('real native owner read error refuses; no ownership or operation writes', local, async t => {
    await owners();
    // Scope this fault to the actual native owner read. Other tests above use
    // real Operation reads too; do not let its earlier query consume the fault.
    t.mock.method(Operation, 'exists', async () => null);
    const client = mongoose.connection.getClient();
    await client.db('admin').command({ configureFailPoint: 'failCommand', mode: { times: 1 }, data: { failCommands: ['find'], errorCode: 2 } });
    try { await readonly(TOPOLOGY_EXECUTION_CONTEXTS[0], undefined, /failCommand/); }
    finally { await client.db('admin').command({ configureFailPoint: 'failCommand', mode: 'off' }); }
    assert.equal(await Owner.countDocuments(), 0);
    assert.equal(await Operation.countDocuments(), 0);
});
