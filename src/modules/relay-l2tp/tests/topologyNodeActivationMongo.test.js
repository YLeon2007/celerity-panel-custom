'use strict';
// Real Mongo + public HTTP + actual intent/coordinator/materializer/worker/
// finalizer. External maintenance and node execution explicitly modeled.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { randomUUID } = require('node:crypto');
const { sha, id } = require('./cascadeAnyOrderSelectedApply.test');
const { fixture } = require('./helpers/installedEditMongoFixture');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { TopologyOperationCoordinator } = require('../services/topologyOperationCoordinator');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { TopologyOperationFinalizationRepository } = require('../repositories/topologyOperationFinalizationRepository');
const { TopologyOperationFinalizer } = require('../services/topologyOperationFinalizer');
const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../services/nodeOperationLockService');
const { TopologyIntentService } = require('../services/topologyIntentService');
const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
const { createCascadeTopologyDeployRouter } = require('../../../routes/cascadeTopologyDeploy');
const mongo = fixture();
const privateFields = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +installedPath';
test('node activation assembled public HTTP intent real Mongo persistence and ordinary worker publication', async t => {
    const logger = require('../../../utils/logger'), priorError = logger.error, priorDebug = logger.debug;
    logger.error = message => console.error(message);
    logger.debug = () => {};
    t.after(() => { logger.error = priorError; logger.debug = priorDebug; });
    const telemetry = require('../../../services/uaStatsService'), priorTrack = telemetry.track;
    telemetry.track = () => {};
    t.after(() => { telemetry.track = priorTrack; });
    await mongo.start();
    let server, installedHost, cache;
    const redisIO = new Map(), cacheReads = [];
    const provider = require('../../../modules/l2tpActiveHostProvider').l2tpActiveHostProvider;
    try {
        const m = mongo.models;
        await m.CascadeTopologyState.create({ _id: 'singleton', revision: 7, deployedRevision: 3, remoteAdmissionCount: 0, topologyAdmissionCount: 0 });
        await m.HyNode.create(['portal', 'bridge'].map((cascadeRole, i) => ({ _id: id(i + 1), name: `activation-${i}`,
            cascadeRole, type: 'xray', active: true, status: 'online', ip: `192.0.2.${i + 1}`, port: 443,
            xray: { security: 'none', transport: 'tcp', flow: '' } })));
        const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: m.TopologyConfigOwner,
            withVerifiedMaintenance: async ({ binding }, work) => work({ status: 'verified', authority: 'external-maintenance-v1', binding,
                proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
                oldBackend: { instanceId: 'MODELED', pid: 42, processStartTime: 'MODELED', processTree: 'stopped', dispatch: 'disabled' },
                readback: { source: 'node-readback', configSha256: sha('{}'), unitSha256: sha('MODELED-unit'), serviceActive: 'active', serviceEnabled: 'enabled' } }) });
        for (const n of [1, 2]) {
            const a = await transfer.initializeClassic({ node: id(n), profile: n === 1 ? 'xray-main' : 'xray-bridge',
                nodeIdentity: { machineId: String(n).repeat(32), sshHostKeySha256: String(n).repeat(64) } });
            await transfer.adopt({ node: id(n), profile: a.profile, generation: a.generation, proofRef: 'MODELED' });
        }
        await m.CascadeLink.create({ _id: id(10), name: 'activation-anchor', portalNode: id(1), bridgeNode: id(2),
            tunnelPort: 24101, mode: 'reverse', active: true, tunnelSecurity: 'none', tunnelTransport: 'tcp',
            tunnelUuid: '11111111-1111-4111-8111-111111111111' });
        const draft = new TopologyDraftRepository(m), deployment = new TopologyDeploymentRepository({ ...m, snapshotReader: draft });
        const operations = new TopologyOperationRepository({ model: m.TopologyOperation, topologyStateModel: m.CascadeTopologyState, selectedTopologyRepository: deployment });
        const coordinator = new TopologyOperationCoordinator({ executionContext: context, topologyRepository: deployment,
            operationRepository: operations, planMaterializer: new TopologyOperationPlanMaterializer(m) });
        const clock = { now: () => new Date() }, files = new Map(), calls = [];
        const executor = { prepare: async c => { calls.push(c.node.node); return { backupId: 'MODELED', prepared: {} }; },
            commit: async c => { files.set(c.node.node, Buffer.from(c.node.candidate.bytes)); return { ok: true }; },
            verify: async () => ({ ok: true }), cleanupPrepared: async () => ({ ok: true }), rollback: async () => ({ ok: true }) };
        const worker = new TopologyOperationWorker({ executionContext: context, operationRepository: operations, executor,
            finalizer: new TopologyOperationFinalizer({ repository: new TopologyOperationFinalizationRepository({ ...m, selectedTopologyRepository: deployment }), clock }),
            lockService: new NodeOperationLockService({ repository: new NodeOperationLockRepository({ model: m.NodeOperationLock }), clock }),
            clock, workerId: 'activation-mongo', leaseMs: 30000, allowUnprovenTestExecution: true, selectedTopologyRepository: deployment });
        const initial = await coordinator.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: id(10), linkIds: [id(10)] } });
        assert.equal((await worker.run(initial.operationId)).status, 'succeeded');
        // Real cacheService serialization/key path; only Redis wire IO is modeled
        // here. The physical TEST check uses the existing isolated Redis DB6.
        cache = require('../../../services/cacheService');
        cache.redis = { get: async key => { cacheReads.push(key); return redisIO.get(key) || null; },
            setex: async (key, ttl, value) => { redisIO.set(key, value); }, del: async key => redisIO.delete(key) };
        cache.connected = true;
        await cache.setSettings({ loadBalancing: {}, subscription: {}, routing: { enabled: false } });
        const nop = () => {};
        installedHost = { runtime: { service: { getStatus: nop, preflight: nop, install: nop, getOperation: nop },
            stateManagementService: { configureRelay: nop }, userManagementService: { createUser: nop, listUsers: nop, updateUser: nop, disableUser: nop } },
            loadPanelOverview: nop,
            readAppliedNodePublication: input => deployment.readAppliedNodePublication({ ...input, executionContext: context }) };
        provider.installActiveHost(installedHost);
        require('../../../models/serverGroupModel');
        const User = require('../../../models/hyUserModel');
        await User.create({ userId: 'publication-mongo', password: 'local-fixture', enabled: true,
            subscriptionToken: 'publication-mongo', xrayUuid: '11111111-1111-4111-8111-111111111111', nodes: [id(1)] });
        await m.HyNode.updateOne({ _id: id(1) }, { $set: { 'xray.security': 'reality', 'xray.flow': 'xtls-rprx-vision',
            'xray.realityPrivateKey': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE', 'xray.realityPublicKey': 'public-key',
            'xray.wsPath': '/saved-only', port: 49999 } });
        await m.CascadeLink.updateOne({ _id: id(10) }, { $set: { tunnelPort: 29999 } });
        const dependencies = { ...m, executionContext: context,
            resolveIntentResources: input => coordinator.resolveIntentResourcesForQueue(input),
            intentOperationAdmission: { db: mongo.connection, queue: input => coordinator.queueIntent(input) } };
        const service = new TopologyIntentService(dependencies), consumer = new TopologyIntentConsumer(dependencies);
        const app = express(); app.use(express.json());
        app.use('/api', require('../../../routes/subscription'));
        const pass = (req, res, next) => next();
        app.use(createCascadeTopologyDeployRouter({ models: m, topologyDeploymentService: coordinator, topologyIntentService: service,
            deploymentEnv: {}, requireAuth: pass, requireScope: () => pass, csrf: pass, deployRateLimiter: pass, operationStatusRateLimiter: pass }));
        server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
        const publication = async security => {
            const reply = await fetch(`http://127.0.0.1:${server.address().port}/api/files/publication-mongo?format=xray-json`,
                { headers: { 'user-agent': 'Happ/1.0 (Android)' } });
            assert.equal(reply.status, 200);
            const proxy = (await reply.json())[0].outbounds.find(o => o.protocol === 'vless');
            assert.equal(proxy.settings.vnext[0].port, 443);
            assert.equal(proxy.streamSettings.network, 'tcp');
            assert.equal(proxy.streamSettings.security || 'none', security);
            assert.equal(proxy.settings.vnext[0].users[0].id, '11111111-1111-4111-8111-111111111111');
            if (security === 'reality') assert.equal(proxy.streamSettings.realitySettings.publicKey, 'public-key');
            return cacheReads.filter(k => k.startsWith('sub:')).at(-1);
        };
        const initialKey = await publication('none');
        const input = { expectedTopologyRevision: 7, linkId: id(10), nodeActivation: { nodeId: id(1), targetProfile: 'xray-main' } };
        const send = async body => { const r = await fetch(`http://127.0.0.1:${server.address().port}/deploy`, {
            method: 'POST', headers: { 'content-type': 'application/json', 'Idempotency-Key': 'explicit-activation-mongo' }, body: JSON.stringify(body) }); return { status: r.status, body: await r.json() }; };
        calls.length = 0;
        const accepted = await send(input); assert.equal(accepted.status, 202, JSON.stringify(accepted));
        assert.equal(calls.length, 0, 'acceptance never dispatches');
        assert.equal((await send(input)).body.job.jobId, accepted.body.job.jobId);
        const altered = await send({ ...input, nodeActivation: { nodeId: id(2), targetProfile: 'xray-main' } });
        assert.equal(altered.status, 400);
        await consumer.runOnce();
        const job = await service.get(accepted.body.job.jobId); assert.ok(job.operationId, JSON.stringify(job));
        const op = await m.TopologyOperation.findById(job.operationId).select(privateFields).lean();
        assert.deepEqual(op.nodeActivation, input.nodeActivation);
        assert.equal(op.effectiveTopology.links[0].tunnelPort, 24101);
        assert.equal(op.effectiveTopology.nodes.find(n => n.id === id(1)).port, 443);
        const result = await worker.run(job.operationId);
        if (result.status !== 'succeeded') {
            console.log(JSON.stringify({ result, operation: await m.TopologyOperation.findById(job.operationId).select(privateFields).lean(),
                owners: await m.TopologyConfigOwner.find({}).lean(), state: await m.CascadeTopologyState.findById('singleton').lean() }));
        }
        assert.equal(result.status, 'succeeded', JSON.stringify(result));
        await consumer.runOnce(); assert.equal((await service.get(job.jobId)).status, 'succeeded');
        assert.equal(await m.NodeOperationLock.countDocuments(), 0);
        assert.equal((await m.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 0);
        assert.equal((await m.TopologyIntentQueueState.findById('create-v1').lean()).outstanding, 0);
        assert.equal((await m.CascadeLink.findById(id(10)).lean()).tunnelPort, 29999);
        const applied = await m.TopologyOperation.findById(job.operationId).select(privateFields).lean();
        assert.equal(require('../repositories/topologyOperationRepository').selectedAdmissionFingerprint(applied), applied.admissionFingerprint);
        const activatedKey = await publication('reality');
        assert.notEqual(activatedKey, initialKey, 'settlement versions the same token/cache format');
        assert.equal(await publication('reality'), activatedKey, 'warm cache remains valid');
        await m.HyNode.updateOne({ _id: id(1) }, { $set: { 'xray.transport': 'ws', 'xray.security': 'none' } });
        const proofReader = require('../services/topologySelectedProofState').readSettledSelectedOperation;
        assert.equal(await proofReader(deployment, applied), null, 'desiredVersion client-proof guard unchanged');
        assert.equal(await publication('reality'), activatedKey, 'saved-only draft leaves applied publication/version intact');
        await m.HyNode.updateOne({ _id: id(1) }, { $set: { 'xray.flow': '' },
            $unset: { 'xray.realityPrivateKey': '', 'xray.realityPublicKey': '' } });
        const restore = await coordinator.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: id(10),
            linkIds: [id(10)], nodeActivation: input.nodeActivation } });
        assert.equal((await worker.run(restore.operationId)).status, 'succeeded');
        const restoredKey = await publication('none');
        assert.notEqual(restoredKey, activatedKey);
        assert.equal(await publication('none'), restoredKey);
        const desired = await m.HyNode.findById(id(1)).lean();
        assert.equal(desired.port, 49999); assert.equal(desired.xray.transport, 'ws');
        assert.equal((await m.CascadeLink.findById(id(10)).lean()).tunnelPort, 29999);
        assert.equal(await m.NodeOperationLock.countDocuments(), 0);
        const commandOffset = mongo.commands.length;
        const verified = await deployment.readAppliedNodePublication({ nodeIds: [id(1)], executionContext: context });
        assert.ok(verified.nodes[0].candidateHash);
        assert.equal(mongo.commands.slice(commandOffset).some(c => ['insert','update','delete','findAndModify'].includes(c.name)), false,
            'publication is strictly read-only');
        // Stored legacy heartbeat remains offline. Only actual health-provider
        // semantics may supply a request-local dedicated availability result.
        await m.HyNode.updateOne({ _id: id(1) }, { $set: { status: 'offline' } });
        let liveHash = verified.nodes[0].candidateHash, reachable = true;
        installedHost.readNodePublicationHealth = require('../services/topologyDedicatedTestHealth').createDedicatedTestNodeHealth({
            authority: { readCurrentHealth: async () => [{ nodeId: id(1), healthy: true,
                endpoint: { ip: '192.0.2.1' }, configSha256: liveHash }] }, connect: async () => reachable });
        assert.equal(await publication('none'), restoredKey);
        const unavailable = async () => {
            const reply = await fetch(`http://127.0.0.1:${server.address().port}/api/files/publication-mongo?format=xray-json`);
            assert.equal(reply.status, 503); assert.equal(await reply.text(), '# No servers available');
        };
        reachable = false; await unavailable();
        reachable = true; liveHash = 'b'.repeat(64); await unavailable();
        assert.equal((await m.HyNode.findById(id(1)).lean()).status, 'offline');
        const Group = require('../../../models/serverGroupModel');
        await Group.create({ _id: id(100), name: 'publication-classic-group' });
        await m.HyNode.create([{ _id: id(101), name: 'unowned-classic', type: 'xray', active: true, status: 'online',
            ip: '192.0.2.101', port: 12345, groups: [id(100)], xray: { transport: 'ws', security: 'none', wsPath: '/classic' } },
        { _id: id(102), name: 'unassigned-classic', type: 'xray', active: true, status: 'online',
            ip: '192.0.2.102', port: 12346, xray: { transport: 'tcp', security: 'none' } }]);
        await User.create({ userId: 'classic-group', password: 'local-fixture', enabled: true, groups: [id(100)],
            subscriptionToken: 'classic-group', xrayUuid: '11111111-1111-4111-8111-111111111111' });
        const classicURL = `http://127.0.0.1:${server.address().port}/api/files/classic-group?format=xray-json`;
        const classicReply = await fetch(classicURL); assert.equal(classicReply.status, 200);
        const classicProfiles = await classicReply.json(); assert.equal(classicProfiles.length, 1);
        const classicProxy = classicProfiles[0].outbounds.find(o => o.protocol === 'vless');
        assert.equal(classicProxy.settings.vnext[0].port, 12345); assert.equal(classicProxy.streamSettings.network, 'ws');
        await m.HyNode.updateOne({ _id: id(101) }, { $set: { status: 'offline' } });
        await cache.invalidateNodes();
        assert.equal((await fetch(classicURL)).status, 503, 'classic availability/group predicates survive warm rendered cache');
        console.log('MONGO_PUBLICATION_RECEIPT ' + JSON.stringify({ realMongo: true, publicHTTP: true,
            actualCacheService: true, redisWireModeled: true, versionedTransitions: 2, coldWarmAndSavedOnly: true,
            readOnlyReader: true, unavailableAndWrongPhysicalCandidate503DespiteWarmCache: true, storedStatusUnchanged: true,
            classicUnownedGroupAndAvailabilityPreserved: true }));
    } finally {
        if (server) await new Promise(resolve => server.close(resolve));
        if (installedHost) provider.clearActiveHost(installedHost);
        if (cache) { cache.connected = false; cache.redis = null; }
        await mongo.stop();
    }
});
