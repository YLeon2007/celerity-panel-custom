'use strict';
// Real isolated Mongo transactions + actual Mongoose models/queries and public
// PUT. Config ownership is produced by initializeClassic/adopt; baseline and
// later publication use the actual coordinator/worker/finalizer, never terminal
// row seeds. External maintenance, executor and installed MAIN/PPP readbacks
// are explicitly MODELED. This is DB proof, not native/physical acceptance.
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const express = require('express');
const { randomUUID } = require('node:crypto');
const { fixture, sha } = require('./helpers/installedEditMongoFixture');
const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
const { TopologyDraftWriteService } = require('../services/topologyDraftWriteService');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { TopologyOperationCoordinator } = require('../services/topologyOperationCoordinator');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { TopologyOperationFinalizationRepository } = require('../repositories/topologyOperationFinalizationRepository');
const { TopologyOperationFinalizer } = require('../services/topologyOperationFinalizer');
const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../services/nodeOperationLockService');
const { TopologyIntentService, linkDesiredVersion } = require('../services/topologyIntentService');
const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
const { L2tpSimpleService } = require('../services/l2tpSimpleService');
const { createCascadeLinksRouter, prepareIntentLink } = require('../../../routes/cascadeLinks');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const id = n => n.toString(16).padStart(24, '0');
const privateOperation = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +installedPath';
const mongo = fixture(); let models;
test.before(async () => { await mongo.start(); models = mongo.models; });
test.after(() => mongo.stop());
async function revision() { return (await models.CascadeTopologyState.findById('singleton').lean()).revision; }
async function operation(value) { return models.TopologyOperation.findById(value).select(privateOperation).lean(); }
function stack(overrides = {}) {
    const trace = [], draft = new TopologyDraftRepository(models);
    const deployment = new TopologyDeploymentRepository({ ...models, snapshotReader: draft });
    const operations = new TopologyOperationRepository({ model: models.TopologyOperation,
        topologyStateModel: models.CascadeTopologyState, selectedTopologyRepository: deployment });
    const coordinator = new TopologyOperationCoordinator({ executionContext: context, topologyRepository: deployment,
        operationRepository: operations, planMaterializer: new TopologyOperationPlanMaterializer(models) });
    const finalization = new TopologyOperationFinalizationRepository({ ...models, selectedTopologyRepository: deployment });
    const finalizeSucceeded = finalization.finalizeSucceeded.bind(finalization);
    finalization.finalizeSucceeded = async input => {
        try { return await finalizeSucceeded(input); }
        catch (error) {
            trace.push(['finalization-error', { name: error.name, code: error.code, message: error.message,
                errors: Object.entries(error.errors || {}).map(([path, entry]) => ({ path, message: entry.message })) }]);
            throw error;
        }
    };
    const clock = { now: () => new Date() }, files = new Map();
    // These are fixed simulated external readbacks, NOT persisted terminal rows.
    // The actual service still validates frozen plan, current owner/group and
    // both credential/topology epochs against real Mongo on either side.
    const forbidden = () => assert.fail('DB proof must never provision PPP, credentials or a real transport');
    const installedService = new L2tpSimpleService({ ...models, allowRemoteExecution: true,
        l2tpService: { install: forbidden, getOperation: forbidden },
        stateManagementService: { configureRelay: forbidden, revealPsk: forbidden },
        userManagementService: { createUser: forbidden, deleteUser: forbidden, importUser: forbidden },
        stateRepository: { getTopologyRevision: forbidden }, nodeSSHFactory: forbidden,
        topologyIngressGate: { async verifyPlan() { return { ok: true }; } },
        topologyPppReadinessGate: { async verifyPlan(plan) { return { ok: true, verifiedRelayCount: 1,
            relayRevisions: [{ relayNode: plan.ownerNodeId, credentialRevision: plan.ownerCredentialRevision }] }; } },
    });
    const executor = {
        async prepare(input) { trace.push(['prepare', input.node.node]); return { backupId: 'modeled-external-backup', prepared: {} }; },
        async commit(input) { files.set(input.node.node, Buffer.from(input.node.candidate.bytes).toString('utf8')); return { ok: true }; },
        async verify(input) { assert.equal(sha(files.get(input.node.node)), input.node.candidateHash); return { ok: true }; },
        cleanupPrepared: async () => ({ ok: true }), rollback: async () => ({ ok: true }),
    };
    const worker = new TopologyOperationWorker({ executionContext: context, operationRepository: operations, executor, clock,
        finalizer: new TopologyOperationFinalizer({ repository: finalization, clock }),
        lockService: new NodeOperationLockService({ repository: new NodeOperationLockRepository({ model: models.NodeOperationLock }), clock }),
        workerId: `installed-edit-${process.pid}`, leaseMs: 30000, allowUnprovenTestExecution: true,
        selectedTopologyRepository: deployment,
        installedIngressPreparer: async ({ operationPlan }) => {
            const locks = await models.NodeOperationLock.find({ operationId: operationPlan.operationId }).lean();
            assert.equal(locks.length, operationPlan.resourceNodeIds.length);
            return installedService.prepareConfiguredRelayIngress({ operationPlan });
        },
    });
    const joined = draft.createIntentDraftWriter({ selectedTopologyRepository: deployment });
    const dependencies = { ...models, executionContext: context, prepareLink: prepareIntentLink,
        deleteIntentWriter: models.CascadeLink.createDeleteIntentWriter({ CascadeLink: models.CascadeLink }),
        intentDraftWriter: { db: joined.db, createLink: joined.createLink,
            async updateLink(input) {
                assert.equal(input.session.inTransaction(), true);
                assert.ok(input.session.client === mongo.connection.getClient());
                trace.push(['joined', input]);
                return joined.updateLink(input);
            } },
        intentOperationAdmission: { db: mongo.connection, queue: input => coordinator.queueIntent(input) },
        async resolveIntentResources(input) { trace.push(['resources', input.session]);
            return coordinator.resolveIntentResourcesForQueue(input); },
        ...overrides };
    return { trace, files, draft, deployment, operations, coordinator, executor, worker, dependencies,
        writes: new TopologyDraftWriteService({ repository: draft }),
        service: new TopologyIntentService(dependencies), consumer: new TopologyIntentConsumer(dependencies) };
}
async function apply(f, linkId = id(10)) {
    const queued = await f.coordinator.queue({ expectedTopologyRevision: await revision(),
        scope: { kind: 'link.apply', linkId, linkIds: [linkId] } });
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.status, 'succeeded', JSON.stringify(result));
    return operation(queued.operationId);
}
async function baseline({ peer = false } = {}) {
    await mongo.reset();
    await models.CascadeTopologyState.create({ _id: 'singleton', revision: 7, deployedRevision: 3,
        remoteAdmissionCount: 0, topologyAdmissionCount: 0 });
    await models.HyNode.create((peer ? ['relay', 'bridge', 'relay', 'bridge'] : ['relay', 'bridge']).map((cascadeRole, index) => ({ _id: id(index + 1), name: `scratch-${cascadeRole}-${index}`,
        cascadeRole, type: 'xray', active: true, ip: `192.0.2.${index + 1}`, port: 443, xray: { security: 'none', transport: 'tcp' } })));
    const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: models.TopologyConfigOwner,
        withVerifiedMaintenance: async ({ binding }, work) => work({ status: 'verified', authority: 'external-maintenance-v1', binding,
            proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
            oldBackend: { instanceId: 'MODELED-only', pid: 42, processStartTime: 'MODELED-only', processTree: 'stopped', dispatch: 'disabled' },
            readback: { source: 'node-readback', configSha256: sha('{}'), unitSha256: sha('modeled-unit'), serviceActive: 'active', serviceEnabled: 'enabled' } }) });
    for (const number of (peer ? [1, 2, 3, 4] : [1, 2])) {
        const original = await transfer.initializeClassic({ node: id(number), profile: 'xray-bridge',
            nodeIdentity: { machineId: String(number).repeat(32), sshHostKeySha256: String(number).repeat(64) } });
        await transfer.adopt({ node: id(number), profile: original.profile, generation: original.generation, proofRef: 'MODELED-external-maintenance' });
    }
    assert.equal(await models.TopologyOperation.countDocuments(), 0);
    const f = stack();
    await f.writes.createLink({ expectedTopologyRevision: await revision(), link: { _id: id(10), name: 'installed owned link',
        portalNode: id(1), bridgeNode: id(2), tunnelUuid: '77777777-7777-4777-8777-777777777777',
        tunnelPort: 23410, tunnelSecurity: 'none', tunnelTransport: 'tcp', active: true } });
    await f.writes.createRouteGroup({ expectedTopologyRevision: await revision(), routeGroup: { _id: id(60), name: 'installed owned group',
        mode: 'reverse', strategy: 'priority-failover', paths: [] } });
    if (peer) {
        await f.writes.createLink({ expectedTopologyRevision: await revision(), link: { _id: id(13), name: 'preserved geo peer link',
            portalNode: id(1), bridgeNode: id(4), tunnelUuid: '88888888-8888-4888-8888-888888888888',
            tunnelPort: 23413, tunnelSecurity: 'none', tunnelTransport: 'tcp', active: true } });
        await models.RelayL2tpState.create({ node: id(1), routeGroup: id(60), activePathKey: 'peer',
            status: 'installed', desiredState: 'installed', secretRevision: 41, appliedTopologyRevision: 0,
            pskEncrypted: 'dummy-encrypted-psk-preserved', clientCidr: '10.255.30.0/24', localAddress: '10.255.30.1',
            poolStart: '10.255.30.10', poolEnd: '10.255.30.250', tproxyPort: 12345, fwmark: 100, routeTable: 100 });
        await models.L2tpUser.create({ relayNode: id(1), login: 'kept-peer', passwordEncrypted: 'dummy-peer-password', ip: '10.255.30.11' });
        await apply(f, id(13));
        const group = await models.CascadeRouteGroup.findById(id(60)).lean();
        assert.deepEqual(group.paths.find(path => path.pathKey === 'peer').linkIds.map(String), [id(13)]);
        // Explicit modeled pre-existing MAIN selection, not a terminal seed.
        // Publish peer bytes first; metadata alone cannot authorize an ingress.
        await models.RelayL2tpState.updateOne({ node: id(1) }, { $set: { activePathKey: 'mine' } }, { runValidators: true });
        await f.writes.updateLink({ expectedTopologyRevision: await revision(), linkId: id(13), changes: { geoRouting: policy().geoRouting } });
        await apply(f, id(13));
    }
    // Schema-valid pre-existing installed PPP inventory, explicitly MODELED.
    // No sync/topology operation or successful terminal status is seeded here.
    if (!peer) await models.RelayL2tpState.create({ node: id(1), routeGroup: id(60), activePathKey: 'mine',
        status: 'installed', desiredState: 'installed', secretRevision: 41, appliedTopologyRevision: 0,
        pskEncrypted: 'dummy-encrypted-psk-preserved', clientCidr: '10.255.30.0/24', localAddress: '10.255.30.1',
        poolStart: '10.255.30.10', poolEnd: '10.255.30.250', tproxyPort: 12345, fwmark: 100, routeTable: 100 });
    // Pre-existing user inventory only: pending is not a fabricated sync proof.
    await models.L2tpUser.create({ relayNode: id(1), login: 'kept-main', passwordEncrypted: 'dummy-main-password', ip: '10.255.30.10' });
    const published = await apply(f);
    assert.equal(published.status, 'succeeded');
    const group = await models.CascadeRouteGroup.findById(id(60)).lean();
    assert.deepEqual(group.paths.find(path => path.pathKey === 'mine').linkIds.map(String), [id(10)]);
    assert.equal(await models.NodeOperationLock.countDocuments(), 0);
    assert.equal(await models.L2tpOperation.countDocuments(), 0, 'no fake sync success');
    return f;
}
async function http(f, work) {
    const app = express(); app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    app.use('/links', createCascadeLinksRouter({ Link: models.CascadeLink, Node: models.HyNode,
        TopologyState: models.CascadeTopologyState, ClientProofOperation: models.TopologyOperation,
        topologyIntentService: f.service, topologyDraftWriteService: f.writes, deploymentEnv: {},
        // Draft-only route maintenance is outside this transaction proof.
        // No-op matches the prior Mongo HTTP fixture; no background claim.
        maintainAutoL2tpPathsFn: async () => {},
        invalidateSubscriptions: async () => {}, invalidateTopology: async () => {} }));
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try {
        await work(async (body, key, { method = 'PUT', linkId = id(10) } = {}) => {
            const response = await fetch(`http://127.0.0.1:${server.address().port}/links${method === 'POST' ? '' : `/${linkId}`}`, {
                method, headers: { 'content-type': 'application/json', ...(key ? { 'idempotency-key': key } : {}) }, body: JSON.stringify(body) });
            return { status: response.status, body: await response.json() };
        });
    } finally { await new Promise(resolve => server.close(resolve)); }
}
const policy = overrides => ({ autoDeploy: true, priority: '9', geoRouting: { enabled: true, domains: ['category-ru'], geoip: ['ru'] }, ...overrides });
async function inventory() {
    return { links: await models.CascadeLink.find({}).sort({ _id: 1 }).lean(),
        state: await models.CascadeTopologyState.findById('singleton').lean(),
        intents: await models.TopologyCreateIntent.find({}).select('+payload').sort({ _id: 1 }).lean(),
        counters: await models.TopologyIntentQueueState.find({}).sort({ _id: 1 }).lean(),
        owners: await models.TopologyConfigOwner.find({}).sort({ _id: 1 }).lean(),
        operations: await models.TopologyOperation.find({}).select(privateOperation).sort({ _id: 1 }).lean(),
        relay: await models.RelayL2tpState.find({}).select('+pskEncrypted').lean(),
        users: await models.L2tpUser.find({}).select('+passwordEncrypted').sort({ _id: 1 }).lean(),
        groups: await models.CascadeRouteGroup.find({}).sort({ _id: 1 }).lean() };
}
const publication = value => Object.fromEntries(['owners', 'operations', 'relay', 'groups', 'users'].map(key => [key, value[key]]));
function assertBlockedCandidate(op) {
    const node = op.nodes.find(row => String(row.node) === op.installedPath.ownerNodeId);
    const bytes = Buffer.from(node.candidate.bytes), config = JSON.parse(bytes);
    assert.equal(sha(bytes), node.candidateHash);
    const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
    assert.equal(config.inbounds.filter(row => row.tag === 'cascade-mine' && row.protocol === 'socks'
        && row.listen === '127.0.0.1' && row.port === cascadePathIngressPort(id(60), 'mine')).length, 1);
    const rules = config.routing.rules.filter(row => row.inboundTag?.includes('cascade-mine'));
    assert.deepEqual(rules, [{ type: 'field', inboundTag: ['cascade-mine'], outboundTag: 'block' }]);
    assert.equal(config.routing.rules.indexOf(rules[0]), 0, 'no-exit block must preempt global/reverse selectors');
    assert.equal(config.outbounds.find(row => row.tag === 'block').protocol, 'blackhole');
}
function transactionEvidence(commands, terminal) {
    const ended = commands.filter(row => row.name === terminal); assert.equal(ended.length, 1);
    const key = row => `${row.lsid}:${row.txnNumber}`;
    const same = commands.filter(row => row.autocommit === false && key(row) === key(ended[0]));
    assert.ok(same.some(row => row.collection === models.CascadeLink.collection.name && row.name === 'update'));
    assert.ok(same.some(row => row.collection === models.CascadeTopologyState.collection.name && row.name === 'find'));
    assert.ok(same.some(row => row.collection === models.RelayL2tpState.collection.name && row.name === 'find'
        && row.projection.secretRevision === 1 && row.projection.activePathKey === 1));
    const first = same.find(row => row.startTransaction);
    assert.equal(first.readConcern.level, 'snapshot');
    if (terminal === 'commitTransaction') assert.equal(ended[0].writeConcern.w, 'majority');
    return same;
}

test('installed policy public PUT commits normalized delta and intent in the same actual Mongo transaction', async () => {
    const f = await baseline(), before = await inventory(), start = mongo.commands.length;
    const expected = await revision(); let accepted;
    await http(f, async put => {
        const response = await put(policy({ expectedTopologyRevision: expected }), 'installed-policy');
        assert.equal(response.status, 202, JSON.stringify(response)); accepted = response.body.job;
        assert.equal(response.body.desiredSaved, true); assert.equal(accepted.kind, 'link.apply');
        assert.equal(accepted.status, 'waiting');
    });
    const actual = await inventory(), saved = actual.links[0];
    assert.equal(saved._id instanceof mongoose.Types.ObjectId, true); assert.equal(saved.portalNode instanceof mongoose.Types.ObjectId, true);
    assert.equal(saved.priority, 9); assert.equal(saved.autoDeploy, true); assert.deepEqual(saved.geoRouting, policy().geoRouting);
    assert.equal(saved.tunnelUuid, before.links[0].tunnelUuid);
    assert.equal(actual.state.revision, expected + 1); assert.equal(actual.state.deployedRevision, before.state.deployedRevision);
    assert.equal(actual.intents.length, 1); assert.equal(actual.intents[0].desiredVersion, linkDesiredVersion(saved));
    assert.equal(accepted.desiredVersion, linkDesiredVersion(saved)); assert.equal(actual.counters[0].outstanding, 1);
    assert.equal(actual.counters[0].ordinal, 1); assert.deepEqual(publication(actual), publication(before));
    const joined = f.trace.findLast(row => row[0] === 'joined')[1];
    assert.ok(joined.session === f.trace.findLast(row => row[0] === 'resources')[1]);
    assert.deepEqual(Object.keys(joined.changes).sort(), ['autoDeploy', 'geoRouting', 'priority']);
    assert.equal(joined.changes.tunnelUuid, undefined, 'sparse projection must not invent a credential migration');
    const tx = transactionEvidence(mongo.commands.slice(start), 'commitTransaction');
    assert.ok(tx.some(row => row.name === 'insert' && row.collection === models.TopologyCreateIntent.collection.name));
    const snapshot = await f.draft.readDraft();
    assert.equal(String(snapshot.installedRouteOwners[0].nodeId), id(1));
    assert.equal(snapshot.installedRouteOwners[0].ownerCredentialRevision, 41);
    assert.equal(snapshot.installedRouteOwners[0].ownerTopologyRevision, before.relay[0].appliedTopologyRevision);
    assert.equal((await models.RelayL2tpState.findOne({ node: id(1) }).lean()).pskEncrypted, undefined);
    assert.equal((await models.TopologyOperation.findById(before.operations[0]._id).lean()).effectiveTopology, undefined);
    assert.doesNotMatch(JSON.stringify(accepted), /dummy-encrypted-psk|selectedOwnerPins|effectiveTopology/);
    const selected = await f.deployment.readSelected({ snapshot, scope: { kind: 'link.apply', linkId: id(10) }, executionContext: context });
    assert.equal(selected.baselineTopology.links[0].geoRouting.enabled, false, 'desired edit cannot rewrite settled descriptor');
    assert.equal(selected.effectiveTopology.links[0].geoRouting.enabled, true);
});

for (const geo of [false, true]) test(`installed ${geo ? 'geo-only blocked path REQUIRED' : 'priority-only'} edit reaches actual worker publication`, async t => {
    const f = await baseline(), before = await inventory(); let accepted;
    await http(f, async put => {
        const result = await put({ expectedTopologyRevision: before.state.revision, autoDeploy: true, priority: 9,
            ...(geo ? { geoRouting: policy().geoRouting } : {}) }, `publication-${geo}`);
        assert.equal(result.status, 202, JSON.stringify(result)); accepted = result.body.job;
    });
    assert.deepEqual(publication(await inventory()), publication(before));
    const claimed = await f.consumer.claim(); assert.equal(String(claimed._id), accepted.jobId);
    const queued = await f.consumer.consumeVersioned(claimed);
    const result = await f.worker.run(queued.operationId);
    if (result.status !== 'succeeded') {
        const retained = await inventory(), op = retained.operations.find(row => String(row._id) === queued.operationId);
        t.diagnostic(JSON.stringify({ result, finalizationErrors: f.trace.filter(row => row[0] === 'finalization-error'),
            installedPath: op.installedPath, effectiveGroups: op.effectiveTopology.groups,
            heldTopologyAdmission: op.heldTopologyAdmission, locks: await models.NodeOperationLock.countDocuments(),
            ownerPointersUnchanged: JSON.stringify(retained.owners) === JSON.stringify(before.owners),
            groupUnchanged: JSON.stringify(retained.groups) === JSON.stringify(before.groups),
            credentialEpoch: retained.relay[0].secretRevision, jobStatus: (await f.service.get(accepted.jobId)).status }));
        assert.deepEqual(retained.owners, before.owners);
        assert.deepEqual(retained.groups, before.groups);
        assert.deepEqual(retained.relay, before.relay);
        assert.equal(op.heldTopologyAdmission, true);
        assert.equal(await models.NodeOperationLock.countDocuments({ operationId: queued.operationId }), 2);
        assert.equal((await f.service.get(accepted.jobId)).status, 'admitted');
    }
    assert.equal(result.status, 'succeeded', JSON.stringify(result));
    assert.equal(await f.consumer.settle(await models.TopologyCreateIntent.findById(accepted.jobId).lean()), true);
    assert.equal((await stack().service.get(accepted.jobId)).status, 'succeeded');
    const published = await inventory();
    assert.equal(published.relay[0].secretRevision, 41); assert.equal(published.relay[0].pskEncrypted, before.relay[0].pskEncrypted);
    assert.deepEqual(published.users, before.users);
    const op = published.operations.find(row => String(row._id) === queued.operationId);
    const path = published.groups[0].paths.find(row => row.pathKey === 'mine');
    assert.deepEqual(path.linkIds.map(String), geo ? [] : [id(10)]);
    assert.equal(path.enabled, true);
    assert.equal(path.priority, before.groups[0].paths[0].priority);
    assert.equal(op.heldTopologyAdmission, false);
    assert.equal(published.state.topologyAdmissionCount, 0);
    if (geo) {
        assert.deepEqual(op.installedPath.newPathLinkIds, []);
        assertBlockedCandidate(op);
    }
    assert.ok(published.owners.every(row => String(row.lastSettledOperation) === queued.operationId));
    const read = await f.deployment.readSelected({ snapshot: await f.draft.readDraft(),
        scope: { kind: 'link.apply', linkId: id(10) }, executionContext: context });
    assert.equal(read.baselineTopology.links[0].geoRouting.enabled, geo);
    assert.equal(read.baselineTopology.links[0].priority, 9);
    assert.equal(read.baselineTopology.links[0].tunnelUuid, before.links[0].tunnelUuid);
    assert.equal(published.counters[0].outstanding, 0); assert.equal(await models.NodeOperationLock.countDocuments(), 0);
});

test('installed policy persisted reload/replay, stale revision and conflicting key never duplicate or rewrite publication', async () => {
    await baseline(); const expected = await revision(); let first;
    await http(stack(), async put => { first = await put(policy({ expectedTopologyRevision: expected }), 'durable-installed-edit');
        assert.equal(first.status, 202, JSON.stringify(first)); });
    const before = await inventory();
    await http(stack({ prepareLink() { assert.fail('persisted replay must precede preparation'); } }), async put => {
        const replay = await put(policy({ expectedTopologyRevision: 0 }), 'durable-installed-edit');
        assert.equal(replay.status, 202, JSON.stringify(replay)); assert.deepEqual(replay.body.job, first.body.job);
        const conflict = await put(policy({ expectedTopologyRevision: expected + 1, priority: 88 }), 'durable-installed-edit');
        assert.equal(conflict.status, 409); assert.equal(conflict.body.error.code, 'TOPOLOGY_INTENT_KEY_CONFLICT');
    });
    await http(stack(), async put => {
        const stale = await put(policy({ expectedTopologyRevision: 0 }), 'new-stale-key');
        assert.equal(stale.status, 409); assert.equal(stale.body.error.code, 'STALE_TOPOLOGY_REVISION');
    });
    assert.deepEqual(await inventory(), before);
});

test('installed save-only PUT has no job despite persisted autoDeploy and preserves every settled descriptor/epoch', async () => {
    const f = await baseline();
    await http(f, async put => {
        const auto = await put(policy({ expectedTopologyRevision: await revision() }), 'auto-before-save');
        assert.equal(auto.status, 202, JSON.stringify(auto));
        const before = await inventory();
        const saved = await put({ expectedTopologyRevision: await revision(), priority: '12', geoRouting: { enabled: false, domains: [], geoip: [] } });
        assert.equal(saved.status, 200, JSON.stringify(saved)); assert.equal(saved.body.desiredSaved, true);
        assert.equal(saved.body.job, undefined); assert.equal(saved.body.autoDeployJob, undefined);
        const after = await inventory(); assert.equal(after.links[0].autoDeploy, true); assert.equal(after.links[0].priority, 12);
        assert.equal(after.state.revision, before.state.revision + 1); assert.equal(after.intents.length, 1);
        assert.deepEqual(after.counters, before.counters); assert.deepEqual(after.intents, before.intents);
        assert.deepEqual(publication(after), publication(before));
    });
});

for (const fault of ['post-draft-resources', 'post-intent-insert']) {
    test(`installed policy ${fault} aborts actual desired, revision and queue together`, async () => {
        await baseline(); const before = await inventory(); let injected = 0;
        const f = stack(fault === 'post-draft-resources' ? { resolveIntentResources: async ({ session }) => {
            assert.equal((await models.CascadeLink.findById(id(10)).session(session).lean()).priority, 9);
            assert.equal((await models.CascadeTopologyState.findById('singleton').session(session).lean()).revision, before.state.revision + 1);
            assert.equal((await models.CascadeLink.findById(id(10)).lean()).priority, before.links[0].priority,
                'outside reader cannot see the uncommitted desired update');
            injected++; throw Object.assign(Error('INJECTED after actual joined desired update'), { code: 'TOPOLOGY_INTENT_RESOURCES_UNAVAILABLE' });
        } } : {});
        const original = models.TopologyCreateIntent.create;
        if (fault === 'post-intent-insert') models.TopologyCreateIntent.create = async function (rows, options) {
            const saved = await original.call(this, rows, options);
            assert.equal(await this.countDocuments({ requestKey: `rollback-${fault}` }).session(options.session), 1);
            assert.equal(await this.countDocuments({ requestKey: `rollback-${fault}` }), 0);
            injected++; throw Error('INJECTED after real intent insertion, before commit');
        };
        const start = mongo.commands.length;
        try {
            await http(f, async put => {
                const result = await put(policy({ expectedTopologyRevision: before.state.revision }), `rollback-${fault}`);
                assert.ok(result.status >= 400, JSON.stringify(result)); assert.equal(result.body.job, undefined);
                assert.equal(result.body.desiredSaved, undefined);
            });
        } finally { models.TopologyCreateIntent.create = original; }
        assert.equal(injected, 1); assert.equal(f.trace.filter(row => row[0] === 'joined').length, 1);
        assert.deepEqual(await inventory(), before);
        const tx = transactionEvidence(mongo.commands.slice(start), 'abortTransaction');
        assert.equal(mongo.commands.slice(start).filter(row => row.name === 'commitTransaction').length, 0);
        assert.ok(tx.some(row => row.collection === models.TopologyIntentQueueState.collection.name && row.name === 'findAndModify'));
        if (fault === 'post-intent-insert') assert.ok(tx.some(row => row.collection === models.TopologyCreateIntent.collection.name && row.name === 'insert'));
    });
}

for (const [field, value] of [['tunnelUuid', 'different-key'], ['tunnelTransport', 'ws'], ['tunnelPort', 24444]]) {
    test(`installed normalized delta does not hide real ${field} migration`, async () => {
        const f = await baseline(), before = await inventory();
        await http(f, async put => {
            const result = await put(policy({ expectedTopologyRevision: before.state.revision, [field]: value }), `guard-${field}`);
            assert.equal(result.status, 409, JSON.stringify(result)); assert.equal(result.body.error.code, 'CASCADE_LINK_IN_USE');
        });
        assert.deepEqual(await inventory(), before);
    });
}

test('real Mongo retained-empty publication still rejects malformed path updates without changing the group', async () => {
    await baseline();
    const before = await models.CascadeRouteGroup.findById(id(60)).lean();
    const path = { pathKey: 'mine', linkIds: [], priority: 1, enabled: true };
    const cases = [
        [{ ...path, linkIds: undefined }], [{ ...path, linkIds: null }],
        [{ ...path, linkIds: ['not-an-object-id'] }], [{ ...path, pathKey: '' }],
        [{ ...path, priority: 0 }], [{ ...path, priority: -1 }], [{ ...path, priority: Infinity }],
        [path, { ...path, priority: 2 }],
    ];
    for (const paths of cases) {
        await assert.rejects(models.CascadeRouteGroup.updateOne({ _id: id(60) }, { $set: { paths } }, { runValidators: true }));
        assert.deepEqual(await models.CascadeRouteGroup.findById(id(60)).lean(), before);
    }
});

test('real Mongo late installed publication failure rolls back owner/group/epoch and retains admission and locks', async () => {
    const f = await baseline(), before = await inventory(); let accepted;
    await http(f, async request => {
        const response = await request(policy({ expectedTopologyRevision: before.state.revision }), 'late-publication-abort');
        assert.equal(response.status, 202, JSON.stringify(response)); accepted = response.body.job;
    });
    const claimed = await f.consumer.claim(), queued = await f.consumer.consumeVersioned(claimed);
    const original = models.CascadeRouteGroup.updateOne; let injected = 0;
    models.CascadeRouteGroup.updateOne = async function (filter, update, options) {
        const result = await original.call(this, filter, update, options);
        if (options?.session?.inTransaction() && update.$set?.paths) {
            assert.equal(result.matchedCount, 1);
            const inside = await this.findById(id(60)).session(options.session).lean();
            assert.deepEqual(inside.paths.find(path => path.pathKey === 'mine').linkIds, []);
            assert.deepEqual(await this.findById(id(60)).lean(), before.groups[0]);
            injected++; throw Error('INJECTED after actual validated empty-path write, before commit');
        }
        return result;
    };
    const start = mongo.commands.length; let result;
    try { result = await f.worker.run(queued.operationId); }
    finally { models.CascadeRouteGroup.updateOne = original; }
    assert.equal(injected, 1); assert.equal(result.status, 'committing');
    const after = await inventory(), op = after.operations.find(row => String(row._id) === queued.operationId);
    assert.deepEqual(after.owners, before.owners); assert.deepEqual(after.groups, before.groups);
    assert.deepEqual(after.relay, before.relay); assert.deepEqual(after.users, before.users);
    assert.equal(op.heldTopologyAdmission, true);
    assert.equal(after.state.topologyAdmissionCount, 1);
    assert.equal(await models.NodeOperationLock.countDocuments({ operationId: queued.operationId }), 2);
    assert.equal((await f.service.get(accepted.jobId)).status, 'admitted');
    assertBlockedCandidate(op);
    assert.ok(mongo.commands.slice(start).some(row => row.name === 'abortTransaction'));
});

test('real public DELETE to retained empty path and fresh POST recreate preserve nonempty peer and users', async () => {
    const f = await baseline({ peer: true }), before = await inventory();
    const peer = before.groups[0].paths.find(path => path.pathKey === 'peer');
    assert.deepEqual(peer.linkIds.map(String), [id(13)]);
    const peerBytes = f.files.get(id(4));
    let deleted, created;
    async function consume(job) {
        const claimed = await f.consumer.claim(); assert.equal(String(claimed._id), job.jobId);
        const queued = await f.consumer.consumeVersioned(claimed);
        assert.equal((await operation(queued.operationId)).heldTopologyAdmission, true);
        const result = await f.worker.run(queued.operationId);
        assert.equal(result.status, 'succeeded', JSON.stringify(result));
        assert.equal(await f.consumer.settle(await models.TopologyCreateIntent.findById(job.jobId).lean()), true);
        const op = await operation(queued.operationId);
        assert.equal(op.heldTopologyAdmission, false); assert.equal(await models.NodeOperationLock.countDocuments(), 0);
        assert.equal((await models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 0);
        return op;
    }
    await http(f, async request => {
        const response = await request({ expectedTopologyRevision: await revision() }, 'delete-to-empty', { method: 'DELETE' });
        assert.equal(response.status, 202, JSON.stringify(response)); deleted = response.body.job;
    });
    const retained = await models.CascadeLink.findById(id(10)).lean();
    assert.equal(retained.lifecycle.state, 'deleting'); assert.equal(String(retained.lifecycle.deleteJobId), deleted.jobId);
    assert.deepEqual((await inventory()).groups, before.groups, 'accepted deletion cannot publish early');
    const deletion = await consume(deleted); assertBlockedCandidate(deletion);
    assert.equal(await models.CascadeLink.findById(id(10)).lean(), null);
    const empty = await inventory();
    assert.deepEqual(empty.groups[0].paths.find(path => path.pathKey === 'mine').linkIds, []);
    assert.deepEqual(empty.groups[0].paths.find(path => path.pathKey === 'peer'), peer);
    const old = before.links.find(row => String(row._id) === id(10));
    await http(f, async request => {
        const response = await request({ expectedTopologyRevision: await revision(), autoDeploy: true,
            name: 'fresh recreated exit', portalNodeId: id(1), bridgeNodeId: id(2), mode: 'reverse',
            tunnelPort: old.tunnelPort, tunnelUuid: old.tunnelUuid, tunnelSecurity: 'none', tunnelTransport: 'tcp' },
        'recreate-after-empty', { method: 'POST' });
        assert.equal(response.status, 202, JSON.stringify(response)); created = response.body.job;
    });
    assert.notEqual(created.jobId, deleted.jobId); assert.notEqual(created.linkId, id(10));
    const recreated = await consume(created), after = await inventory();
    assert.deepEqual(recreated.installedPath.oldPathLinkIds, []);
    assert.deepEqual(after.groups[0].paths.find(path => path.pathKey === 'mine').linkIds.map(String), [created.linkId]);
    assert.deepEqual(after.groups[0].paths.find(path => path.pathKey === 'peer'), peer);
    assert.equal(f.files.get(id(4)), peerBytes);
    assert.deepEqual(after.users, before.users);
    const state = after.relay.find(row => String(row.node) === id(1)), prior = before.relay.find(row => String(row.node) === id(1));
    for (const key of ['pskEncrypted', 'secretRevision', 'clientCidr', 'localAddress', 'poolStart', 'poolEnd',
        'dnsServers', 'routeGroup', 'activePathKey', 'status', 'desiredState']) assert.deepEqual(state[key], prior[key]);
    assert.equal(after.links.find(row => String(row._id) === created.linkId).tunnelUuid, old.tunnelUuid);
    assert.equal(after.counters[0].outstanding, 0);
});
