'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');
const { createL2tpRootLifecycle, productionSchemaConnectionOptions } = require('../src/modules/l2tpRuntimeLifecycleHook');
let directory, child, models;
const local = { skip: !process.env.C3_MONGOD && 'Set C3_MONGOD to an isolated local MongoDB binary' };
async function until(work) {
    let last;
    for (let i = 0; i < 100; i++) {
        try { return await work(); } catch (error) { last = error; }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw last;
}
test.before(async () => {
    if (!process.env.C3_MONGOD) return;
    assert.ok(process.env.TMPDIR, 'scratch TMPDIR is required');
    directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'c3-startup-indexes-'));
    const port = await new Promise(resolve => { const server = net.createServer(); server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(() => resolve(port)); }); });
    child = spawn(process.env.C3_MONGOD, ['--dbpath', directory, '--port', String(port), '--bind_ip', '127.0.0.1', '--logpath', path.join(directory, 'mongo.log')], { stdio: 'ignore' });
    const uri = `mongodb://127.0.0.1:${port}/startup_indexes_scratch`;
    models = require('../src/modules/relay-l2tp').registerModels();
    await until(() => mongoose.connect(uri, { serverSelectionTimeoutMS: 100,
        ...productionSchemaConnectionOptions({ PANEL_DOMAIN: 'lm1.infograd.online' }) }));
});
test.after(async () => {
    require.cache[require.resolve('../src/services/sshPoolService')]?.exports.closeAll();
    await mongoose.disconnect();
    if (child && child.exitCode === null) { const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM'); await exited; }
    if (directory) await fs.rm(directory, { recursive: true, force: true });
});
test('dormant PROD startup leaves the real Mongo catalog unchanged with TEST flags inherited', local, async () => {
    const before = await mongoose.connection.db.listCollections().toArray();
    const env = { PANEL_DOMAIN: 'lm1.infograd.online',
        L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
        TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
    let selected;
    const root = createL2tpRootLifecycle({ env,
        createRuntimeLifecycleHook({ env: safe }) {
            selected = safe;
            return { async stop() {} };
        },
    });
    await root.startAfterDatabase();
    assert.equal(selected.L2TP_EXECUTION_ENABLED, 'false');
    assert.deepEqual(await mongoose.connection.db.listCollections().toArray(), before);
    await root.stop();
});

test('real panel host injects registered V2 models through the actual runtime and settlement repository', local, async () => {
    const { createL2tpPanelHost } = require('../src/modules/createL2tpPanelHost');
    const HyNode = require('../src/models/hyNodeModel');
    const CascadeLink = require('../src/models/cascadeLinkModel');
    const { TopologyOperationFinalizationRepository } = require('../src/modules/relay-l2tp/repositories/topologyOperationFinalizationRepository');
    const { TopologyOperationExecutor } = require('../src/modules/relay-l2tp/services/topologyOperationExecutor');
    const before = await mongoose.connection.db.listCollections().toArray();
    for (const target of ['test', 'production']) {
        let worker;
        const host = createL2tpPanelHost({
            env: { PANEL_DOMAIN: target === 'test' ? 'test.infograd.online' : 'lm1.infograd.online',
                L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
                [target === 'test' ? 'TOPOLOGY_TEST_EXECUTION_ENABLED' : 'TOPOLOGY_PRODUCTION_EXECUTION_ENABLED']: 'true' },
            NodeSSH: class { constructor() { assert.fail('must not connect'); } },
            // Only the unrelated L2TP schedule is replaced; module registration,
            // topology runtime, worker, executor, finalizer and repository are real.
            createExecutionRuntime: () => ({ runtime: {}, async stop() {} }),
            createTopologyRecoveryLifecycle(options) {
                worker = options.worker;
                return { async stop() {} };
            },
        });
        try {
            const repository = worker.finalizer.repository;
            assert.ok(repository instanceof TopologyOperationFinalizationRepository);
            assert.ok(worker.executor instanceof TopologyOperationExecutor);
            for (const key of ['TopologyOperation', 'CascadeTopologyState', 'NodeOperationLock',
                'TopologyExecutionBinding', 'TopologyExecutionEnrollment', 'TopologyConfigOwner']) {
                assert.ok(models[key], `${key} must be registered`);
                assert.ok(repository[key] === models[key], `${key} must reach the real repository`);
                assert.strictEqual(repository[key].db, HyNode.db);
            }
            assert.strictEqual(repository.CascadeLink, CascadeLink);
            const { createHash } = require('node:crypto');
            const { freeze, executionFence } = require('../src/modules/relay-l2tp/tests/helpers/topologyV2Fixture');
            const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n';
            const sha256 = createHash('sha256').update(content).digest('hex');
            // Merely installing models must not fabricate held execution authority
            // or a durable binding reader for the default executor on either host.
            await assert.rejects(worker.executor.prepare({
                operationId: 'unbound-operation', topologyRevision: 7, priorDeployedRevision: 5,
                executionFence,
                node: freeze({ node: new mongoose.Types.ObjectId().toString(), nodeRef: 'portal', role: 'portal',
                    targetProfile: 'xray-main', serviceUnit: 'xray.service',
                    serviceUnitPath: '/etc/systemd/system/xray.service', configPath: '/usr/local/etc/xray/config.json',
                    checks: [], candidateHash: sha256,
                    candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1',
                        bytes: [...Buffer.from(content)], sha256 } }),
            }), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
            const operationId = new mongoose.Types.ObjectId().toString();
            // An absent durable terminal marker is a real majority read, not a
            // mocked finalizer result. It must not be refused as missing models.
            assert.equal(await worker.finalizer.probeV2Settlement({ operationId }), null);
            const result = await worker.run(operationId);
            assert.deepEqual(result, target === 'test'
                ? { claimed: false, operationId }
                : { claimed: false, operationId, stopped: true,
                    errorCode: 'TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN' });
        } finally { await host.stop(); }
    }
    assert.deepEqual(await mongoose.connection.db.listCollections().toArray(), before,
        'model composition and empty-history probing must not create collections');
});

test('real startup upgrades applied 001 and verifies indexes without initializing raw legacy counters', local, async () => {
    await models.RelayL2tpMigrationState.createCollection();
    await models.RelayL2tpMigrationState.collection.insertOne({ _id: 'relay-l2tp', version: 1, appliedMigrationIds: ['001-ensure-module-indexes'] });
    await models.CascadeTopologyState.createCollection();
    const legacy = { _id: 'singleton', revision: 7, deployedRevision: 5 };
    await models.CascadeTopologyState.collection.insertOne(legacy);
    let runtimeStarts = 0;
    const root = createL2tpRootLifecycle({ env: { L2TP_MIGRATIONS_ENABLED: 'true' },
        createRuntimeLifecycleHook() { runtimeStarts++; return { async stop() {} }; },
    });
    await root.startAfterDatabase();
    assert.equal(runtimeStarts, 1);
    const state = await models.RelayL2tpMigrationState.collection.findOne({ _id: 'relay-l2tp' });
    assert.deepEqual(state.appliedMigrationIds, ['001-ensure-module-indexes', '002-ensure-queue-admission-indexes']);
    assert.equal(state.version, 2);
    const indexes = await models.TopologyCreateIntent.collection.indexes();
    assert.equal(indexes.find(i => i.name === 'requestKey_1').unique, true);
    assert.equal(indexes.find(i => i.name === 'ordinal_1').unique, true);
    assert.equal(indexes.find(i => i.name === 'operationId_1').unique, true);
    assert.equal(indexes.find(i => i.name === 'operationId_1').sparse, true);
    assert.deepEqual(await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' }), legacy);
    assert.equal(await models.TopologyIntentQueueState.countDocuments(), 0, 'index readiness must not seed queue/counter state');
    await root.stop();
});
test('every boot repairs a missing queue index even with migrations disabled and 002 already recorded', local, async () => {
    await models.TopologyCreateIntent.collection.dropIndex('ordinal_1');
    const root = createL2tpRootLifecycle({ env: {} });
    await root.startAfterDatabase();
    assert.equal((await models.TopologyCreateIntent.collection.indexes()).find(i => i.name === 'ordinal_1').unique, true);
    assert.equal((await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' })).topologyAdmissionCount, undefined);
    await root.stop();
});
test('duplicate legacy queue values fail startup closed before runtime publication', local, async () => {
    await models.TopologyCreateIntent.collection.dropIndex('ordinal_1');
    await models.TopologyCreateIntent.collection.insertMany([{ requestKey: 'one', ordinal: 1 }, { requestKey: 'two', ordinal: 1 }]);
    let runtimeStarts = 0;
    const root = createL2tpRootLifecycle({ env: {}, createRuntimeLifecycleHook() { runtimeStarts++; return { async stop() {} }; } });
    await assert.rejects(root.startAfterDatabase(), error => error.code === 11000);
    assert.equal(runtimeStarts, 0);
    assert.equal(await models.TopologyCreateIntent.countDocuments(), 2, 'startup must not remove ambiguous queue rows');
    assert.equal((await models.CascadeTopologyState.collection.findOne({ _id: 'singleton' })).topologyAdmissionCount, undefined);
    await root.stop();
});
