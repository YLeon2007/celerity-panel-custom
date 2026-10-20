'use strict';
// All physical/kernel/systemd and durable-backup authority below is SIMULATED.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { createTestPhysicalController } = require('../src/modules/relay-l2tp/runtime/testPhysicalController');
const { TopologyExecutionAuthorityLifecycle } = require('../src/modules/relay-l2tp/runtime/topologyExecutionAuthorityLifecycle');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../src/modules/relay-l2tp/domain/topologyExecutionContext');
const NODES = {
    '6ab18adc63913ebd4a917471': ['132.243.230.19', 'xray-main'],
    '6ab93ad2646b4b7d2f43c907': ['94.103.2.186', 'xray-main'],
    '6ab18d9c63913ebd4a917670': ['50.114.160.63', 'xray-bridge'],
    '6ab4b53bc4c0304573e06c72': ['104.143.201.72', 'xray-bridge'],
    '6ab189dc63913ebd4a917399': ['212.119.42.100', 'xray-main'],
};
const configBytes = Buffer.from('simulated original config'), unitBytes = Buffer.from('simulated original unit');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function fixture(withDurableNodeOriginals, mutate = () => {}) {
    const config = { version: 1, executionContext: TEST, nodes: Object.entries(NODES).map(([nodeId, [ip, targetProfile]], i) => ({
        nodeId, targetProfile, endpoint: { ip, port: 2222, username: 'c3-test-runner' },
        physical: { machineId: nodeId === '6ab189dc63913ebd4a917399' ? '7fa266f995fe4aa69e96cf7d01359e34' : String(i + 1).repeat(32),
            sshHostKeySha256: String(i + 1).repeat(64), bootId: randomUUID() },
        maintenanceId: randomUUID(), planHash: 'a'.repeat(64), guard: { pid: 100 + i, start: '123', socket: '/var/lib/c3-test-node-isolation/recovery.sock' },
        operatorKeyPath: '/etc/celerity/test-operator.key',
        originalSnapshot: { proofRef: 'accepted-' + i, configSha256: sha(configBytes), unitSha256: sha(unitBytes), serviceActive: 'active', serviceEnabled: 'enabled' },
    })), host: { owner: randomUUID(), guard: { pid: 200, start: '321', socket: '/var/lib/c3-test-node-isolation/host.sock',
        owner: '', planHash: 'a'.repeat(64), session: { pid: 201, start: '320' } }, backend: { instanceId: 'a'.repeat(64), pid: 333, processStartTime: '42' } } };
    config.host.guard.owner = config.host.owner;
    const controller = createTestPhysicalController({ config, withDurableNodeOriginals, openChannel: async pin => ({
        alive: true, close() {}, async request() {
            const { proofRef, ...accepted } = pin.originalSnapshot;
            const value = { nodeId: pin.nodeId, targetProfile: pin.targetProfile, endpoint: pin.endpoint, physical: pin.physical,
                maintenanceId: pin.maintenanceId, planHash: pin.planHash, guard: pin.guard,
                host: pin.nodeId === '6ab189dc63913ebd4a917399' ? config.host : null,
                configTransfer: { configBase64: configBytes.toString('base64'), unitBase64: unitBytes.toString('base64'), readback: { source: 'node-readback', ...accepted } },
                runnerState: { head: null, journal: 'absent', legacyState: 'absent', terminal: null } };
            mutate(value); return value;
        },
    }) });
    return { controller, lifecycle: new TopologyExecutionAuthorityLifecycle({ executionContext: TEST, controller }), config };
}
test('controller capture gate needs an awaited five-node trusted callback, never a receipt or boolean', async () => {
    for (const seam of [undefined, async () => true, async () => ({ captured: true }), async (_, callback) => callback(undefined),
        async (_, callback) => { callback(async () => {}); return true; }]) {
        const f = fixture(seam); let entered = 0;
        assert.equal(typeof f.lifecycle.withCapturedTestOwnerEnrollment, 'function', 'held capture lifecycle missing');
        await assert.rejects(f.lifecycle.run(() => f.lifecycle.withCapturedTestOwnerEnrollment(() => { entered++; })));
        assert.equal(entered, 0); f.controller.close();
    }
});
test('real controller/lifecycle checks all five captures before callback and revokes escaped checks', async () => {
    const events = []; let escaped;
    const f = fixture(async (challenge, callback) => {
        assert.equal(challenge.nodes.length, 5); assert.ok(Object.isFrozen(challenge.nodes));
        assert.deepEqual(challenge.executionContext, TEST);
        assert.equal(JSON.stringify(challenge).includes('operatorKeyPath'), false);
        events.push('capture-all-five');
        return callback(async () => { events.push('check-durable'); });
    });
    const result = await f.lifecycle.run(() => f.lifecycle.withCapturedTestOwnerEnrollment(async (plan, check) => {
        assert.equal(plan.nodes.length, 5); assert.ok(Object.isFrozen(plan.nodes));
        escaped = check; await check(); events.push('candidate-write'); return 17;
    }));
    assert.equal(result, 17); assert.equal(events[0], 'capture-all-five');
    assert.ok(events.indexOf('check-durable') < events.indexOf('candidate-write'));
    await assert.rejects(escaped()); f.controller.close();
});
test('durable checker await cannot hide last-node original drift before first candidate write', async () => {
    let drift = false, writes = 0;
    const f = fixture(async (_, callback) => callback(async () => { drift = true; }), value => {
        if (drift && value.nodeId === '6ab189dc63913ebd4a917399') value.configTransfer.configBase64 = Buffer.from('changed').toString('base64');
    });
    await assert.rejects(f.controller.withHeldAuthority(TEST, capability => capability.withCapturedTestOwnerEnrollment(() => { writes++; })));
    assert.equal(writes, 0); f.controller.close();
});
test('one controller cannot recapture an owner enrollment after a completed scope', async () => {
    let captures = 0;
    const f = fixture(async (_, callback) => { captures++; return callback(async () => {}); });
    await f.lifecycle.run(() => f.lifecycle.withCapturedTestOwnerEnrollment(async () => 17));
    await assert.rejects(f.lifecycle.run(() => f.lifecycle.withCapturedTestOwnerEnrollment(async () => 19)));
    assert.equal(captures, 1); f.controller.close();
});
test('last-node current-byte drift blocks every candidate write even after capture callback', async () => {
    const f = fixture(async (_, callback) => callback(async () => {}), value => {
        if (value.nodeId === '6ab189dc63913ebd4a917399') value.configTransfer.configBase64 = Buffer.from('changed').toString('base64');
    });
    let writes = 0;
    await assert.rejects(f.lifecycle.run(() => f.lifecycle.withCapturedTestOwnerEnrollment(() => { writes++; })));
    assert.equal(writes, 0); f.controller.close();
});
test('ordinary root uses actual public schemas/default worker/store for five-node initializeClassic → adopt → preEnroll',
    { skip: !process.env.C3_MONGOD }, async t => {
    const fs = require('node:fs/promises'), path = require('node:path'), net = require('node:net');
    const { spawn } = require('node:child_process');
    const mongoose = require('mongoose');
    assert.ok(process.env.TMPDIR);
    const directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-owner-entry-'));
    const port = await new Promise(resolve => {
        const server = net.createServer(); server.listen(0, '127.0.0.1', () => {
            const value = server.address().port; server.close(() => resolve(value));
        });
    });
    const mongo = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1',
        '--replSet', 'ownerEntryScratch', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    let connection;
    t.after(async () => {
        try {
            if (connection) {
                const name = connection.name;
                assert.match(name, /^owner_entry_scratch_[a-f0-9]{32}$/);
                await connection.dropDatabase();
                assert.equal((await connection.getClient().db('admin').admin().listDatabases()).databases.some(db => db.name === name), false);
                await connection.close();
            }
        } finally {
            if (mongo.exitCode === null) { const exited = new Promise(resolve => mongo.once('exit', resolve)); mongo.kill('SIGTERM'); await exited; }
            await fs.rm(directory, { recursive: true, force: true });
        }
    });
    const until = async work => {
        let last;
        for (let n = 0; n < 150; n++) {
            try { return await work(); } catch (error) { last = error; }
            await new Promise(resolve => setTimeout(resolve, 50));
        }
        throw last;
    };
    const uri = `mongodb://127.0.0.1:${port}/owner_entry_scratch_${randomUUID().replaceAll('-', '')}`;
    const client = new mongoose.mongo.MongoClient(`${uri}?directConnection=true`, { serverSelectionTimeoutMS: 100 });
    try {
        await until(() => client.connect());
        await client.db('admin').command({ replSetInitiate: { _id: 'ownerEntryScratch', members: [{ _id: 0, host: `127.0.0.1:${port}` }] } });
        await until(async () => assert.equal((await client.db('admin').command({ hello: 1 })).isWritablePrimary, true));
    } finally { await client.close(); }
    connection = await mongoose.createConnection(`${uri}?replicaSet=ownerEntryScratch`, { monitorCommands: true }).asPromise();
    const models = {};
    for (const [name, location] of Object.entries({
        HyNode: '../src/models/hyNodeModel', CascadeLink: '../src/models/cascadeLinkModel',
        TopologyConfigOwner: '../src/models/topologyConfigOwnerModel',
        TopologyOperation: '../src/modules/relay-l2tp/models/topologyOperationModel', NodeOperationLock: '../src/modules/relay-l2tp/models/nodeOperationLockModel',
        TopologyExecutionBinding: '../src/modules/relay-l2tp/models/topologyExecutionBindingModel', TopologyExecutionEnrollment: '../src/modules/relay-l2tp/models/topologyExecutionEnrollmentModel',
        CascadeTopologyState: '../src/modules/relay-l2tp/models/cascadeTopologyStateModel', CascadeRouteGroup: '../src/modules/relay-l2tp/models/cascadeRouteGroupModel',
        RelayL2tpState: '../src/modules/relay-l2tp/models/relayL2tpStateModel', L2tpUser: '../src/modules/relay-l2tp/models/l2tpUserModel', L2tpOperation: '../src/modules/relay-l2tp/models/l2tpOperationModel',
    })) models[name] = connection.model(name, require(location).schema);
    await Promise.all(Object.values(models).map(model => model.init()));
    const mutations = [], observe = event => {
        if (['insert', 'update', 'delete', 'create', 'createIndexes', 'commitTransaction'].includes(event.commandName)) mutations.push(event.commandName);
    };
    let captured = false, selectedController, capturedChallenge, service;
    const positive = fixture(async (challenge, callback) => {
        capturedChallenge = challenge;
        assert.equal(mutations.length, 0, 'capture must precede first candidate DB mutation');
        throw new Error('SIMULATED_DURABLE_CAPTURE_LAST_NODE_REFUSAL');
    });
    for (const pin of positive.config.nodes) await models.HyNode.create({ _id: pin.nodeId, name: 'local-only', ip: pin.endpoint.ip,
        type: 'xray', active: true, cascadeRole: pin.targetProfile === 'xray-main' ? 'portal' : 'bridge',
        ssh: { port: pin.endpoint.port, username: pin.endpoint.username, privateKey: randomUUID() } });
    const env = { PANEL_DOMAIN: TEST.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
    const moduleEntry = require('../src/modules/relay-l2tp');
    const { createL2tpRootLifecycle, createL2tpRootHostDependencies, createL2tpRuntimeLifecycleHook } = require('../src/modules/l2tpRuntimeLifecycleHook');
    const { createL2tpStartupLifecycle } = require('../src/modules/createL2tpStartupLifecycle');
    const { createL2tpPanelHost } = require('../src/modules/createL2tpPanelHost');
    const { TopologyOperationExecutor } = require('../src/modules/relay-l2tp/services/topologyOperationExecutor');
    const { TopologyOperationWorker } = require('../src/modules/relay-l2tp/workers/topologyOperationWorker');
    const noop = () => {};
    const makeRoot = () => createL2tpRootLifecycle({ env,
        createMigrationBootstrap() { assert.fail('no enrollment migration'); }, ensureModelIndexes() { assert.fail('no enrollment index install'); },
        createHostDependencies: ({ env }) => createL2tpRootHostDependencies({ env, HyNode: models.HyNode,
            NodeSSH: class { constructor() { assert.fail('owner entry opens no executor SSH'); } },
            createTopologyExecutionAuthority: () => selectedController,
            candidateUserResolver: async () => [], syncService: null, requireAuth: noop, requireOnboarding: noop, csrf: noop,
            rateLimiter: noop, renderPage: noop, secretBox: { encrypt() {}, decrypt() {} }, secretKey: 'local-fixture-only',
            timer: { setInterval() { assert.fail('no maintenance schedule'); }, clearInterval() {} }, logger: { error() {} } }),
        createRuntimeLifecycleHook: options => createL2tpRuntimeLifecycleHook({ ...options,
            createStartupLifecycle: options => createL2tpStartupLifecycle({ ...options,
                createPanelHost: dependencies => createL2tpPanelHost({ ...dependencies, CascadeLink: models.CascadeLink,
                    moduleEntry: { ...moduleEntry, registerModels: () => models, createTopologyIntentService: undefined,
                        createTopologyDeploymentService(options) { service = moduleEntry.createTopologyDeploymentService(options); return service; } },
                    topologyRuntime: {}, Repository: class {}, createRepositoryAdapters: () => ({}), createPanelOverviewLoader: () => async () => ({}),
                    createExecutionRuntime: () => ({ runtime: { service: { getStatus: noop, preflight: noop, install: noop, getOperation: noop },
                        stateManagementService: { configureRelay: noop }, userManagementService: { createUser: noop, listUsers: noop, updateUser: noop, disableUser: noop } },
                        start() { assert.fail('no maintenance worker start'); }, async stop() {} }),
                }) }) }),
    });
    // Rejected actual controller capture leaves all candidate namespaces empty.
    selectedController = positive.controller;
    connection.getClient().on('commandStarted', observe);
    const refused = makeRoot();
    await assert.rejects(refused.enrollTestOwnersAfterDatabase());
    await refused.stop();
    assert.deepEqual(mutations, []);
    assert.equal(await models.TopologyConfigOwner.countDocuments(), 0);
    assert.equal(await models.TopologyExecutionEnrollment.countDocuments(), 0);
    // New independently accepted fixture controller, not restart/adoption of a
    // real uncertain operation. Physical/backup authority remains SIMULATED.
    const accepted = fixture(async (challenge, callback) => {
        capturedChallenge = challenge; assert.equal(mutations.length, 0); captured = true;
        return callback(async () => assert.equal(captured, true));
    });
    // Match the already inventoried fixture machine/key pins, not mutable rows.
    // fixture() fixes those constants independently; boot IDs need not be in HyNode.
    selectedController = accepted.controller;
    const root = makeRoot(); t.after(() => root.stop());
    const result = await root.enrollTestOwnersAfterDatabase();
    assert.equal(result.status, 'enrolled'); assert.equal(result.nodes.length, 5);
    assert.ok(service.operationWorker instanceof TopologyOperationWorker);
    assert.ok(service.operationWorker.executor instanceof TopologyOperationExecutor);
    const owners = await models.TopologyConfigOwner.find().sort({ node: 1 }).lean();
    const enrollments = await models.TopologyExecutionEnrollment.find().sort({ nodeId: 1 }).lean();
    assert.equal(owners.length, 5); assert.equal(enrollments.length, 5);
    for (const row of enrollments) {
        const owner = owners.find(owner => owner.node.toString() === row.nodeId);
        const pin = capturedChallenge.nodes.find(pin => pin.nodeId === row.nodeId);
        assert.deepEqual(owner.executionContext, TEST); assert.equal(owner.owner, 'topology');
        assert.equal(row.ownerGeneration, owner.generation); assert.equal(row.predecessorGeneration, 'none');
        assert.deepEqual(row.nodeIdentity, pin.nodeIdentity); assert.deepEqual(row.endpoint, pin.endpoint); assert.equal(row.bootId, pin.bootId);
        assert.equal(row.maintenanceId, pin.maintenanceId); assert.equal(owner.adoptionReceipt.maintenanceId, pin.maintenanceId);
        const { proofRef, ...snapshot } = pin.originalSnapshot; assert.deepEqual(owner.originalSnapshot, snapshot);
    }
    assert.equal(await models.TopologyOperation.countDocuments(), 0);
    assert.equal(await models.NodeOperationLock.countDocuments(), 0);
    assert.equal(await models.TopologyExecutionBinding.countDocuments(), 0);
    connection.getClient().off('commandStarted', observe);
    await assert.rejects(root.enrollTestOwnersAfterDatabase(), /TEST_OWNER_STARTUP_MODE_CONFLICT/);
    await root.stop();
});
