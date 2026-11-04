'use strict';
// Actual coordinator/materializer/worker/finalizer/service/gates. Mongo and node
// transports are explicitly modeled. These tests make no live network calls.
process.env.PANEL_DOMAIN ||= 'panel.example.test';
process.env.ACME_EMAIL ||= 'admin@example.test';
process.env.ENCRYPTION_KEY ||= '01234567890123456789012345678901';
process.env.SESSION_SECRET ||= 'test-session-secret';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { fixture, id } = require('./cascadeAnyOrderSelectedApply.test');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const { L2tpSimpleService } = require('../services/l2tpSimpleService');
const { TopologyAttachIngressGate } = require('../services/topologyAttachIngressGate');
const { createTopologyPppReadinessGate } = require('../services/topologyPppReadinessGate');
const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
const { linkDesiredVersion } = require('../services/topologyIntentService');
const query = value => ({ select() { return this; }, session() { return this; }, sort() { return this; }, async lean() { return structuredClone(value()); } });
function installedFixture({ absent = false, mode = 'reverse' } = {}) {
    const f = fixture();
    for (const row of f.CascadeLink.rows) row.mode = mode;
    const group = { _id: id(60), name: 'preserved', mode, strategy: 'priority-failover', paths: [
        ...(!absent ? [{ pathKey: 'mine', linkIds: [], priority: 4, enabled: true }] : []),
        { pathKey: 'peer', linkIds: [], priority: 17, enabled: false }] };
    f.CascadeRouteGroup.rows.push(group, { _id: id(61), name: 'unrelated', mode, strategy: 'priority-failover', paths: [] });
    const state = { _id: id(70), node: id(1), routeGroup: id(60), activePathKey: 'mine', status: 'installed', desiredState: 'installed',
        secretRevision: 41, appliedTopologyRevision: 0, pskEncrypted: 'modeled-preserved-psk', clientCidr: '10.255.30.0/24',
        localAddress: '10.255.30.1', poolStart: '10.255.30.10', poolEnd: '10.255.30.250', dnsServers: ['1.1.1.1'],
        tproxyPort: 12345, fwmark: 100, routeTable: 100 };
    f.RelayL2tpState.rows.push(state);
    f.deployment.snapshotReader = new (require('../repositories/topologyDraftRepository').TopologyDraftRepository)({ ...f, transactionRunner: work => work(f.session) });
    const users = [{ _id: id(80), relayNode: id(1), login: 'kept-user', passwordEncrypted: 'kept-secret', ip: '10.255.30.10',
        enabled: true, desiredRevision: 41, appliedRevision: 41, syncStatus: 'synced', syncOperationId: id(81) }];
    const options = { readbackOk: true, prepares: [], plans: [], gateCalls: [] };
    const models = { ...f, L2tpUser: { find: () => query(() => users) }, L2tpOperation: { findOne: () => query(() => options.noSync ? null : ({
        _id: id(81), node: id(1), kind: 'sync_users', status: 'succeeded', plan: { operationId: id(81), relayId: id(1), desired: { credentialRevision: 41 } } })) } };

    const ingress = new TopologyAttachIngressGate({ nodeExecutionResolver: { async resolve() { return {
        async connect() {}, disconnect() {}, async exec(command, execOptions) {
            options.gateCalls.push('ingress');
            const main = { inbounds: [{ tag: `relay-l2tp-${id(60)}`, listen: '0.0.0.0', port: 12345, protocol: 'dokodemo-door',
                settings: { network: 'tcp,udp', followRedirect: true }, streamSettings: { sockopt: { tproxy: 'tproxy' } } }],
                outbounds: [{ tag: 'cascade-mine', protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: cascadePathIngressPort(id(60), 'mine') }] } }],
                routing: { rules: [{ type: 'field', inboundTag: [`relay-l2tp-${id(60)}`], outboundTag: 'cascade-mine' }] } };
            if (options.changeMain) options.changeMain(main);
            const setup = `import builtins,io,subprocess\nbuiltins.open=lambda *a,**k:io.StringIO(${JSON.stringify(JSON.stringify(main))})\nsubprocess.run=lambda *a,**k:type('Result',(),{'returncode':0,'stdout':'active\\n','stderr':''})()\n`;
            const result = spawnSync('python3', ['-'], { input: setup + execOptions.stdin, encoding: 'utf8' });
            return { code: result.status, stdout: result.stdout, stderr: result.stderr };
        } }; } } });
    const ppp = createTopologyPppReadinessGate({ ...models, executionContext: context, readOnly: true,
        NodeSSH: class { async exec() { options.gateCalls.push('users'); options.onUsers?.(); return { code: options.readbackOk ? 0 : 65, stderr: '', stdout: JSON.stringify({
            ok: options.readbackOk, code: 'USERS_VERIFIED', credentialRevision: 41, enabledUserCount: 1, managedUserCount: 1 }) + '\n' }; } } });
    const forbidden = () => { throw new Error('No credential or provisioning writes permitted'); };
    const service = new L2tpSimpleService({ ...models, allowRemoteExecution: true, topologyIngressGate: ingress, topologyPppReadinessGate: ppp,
        l2tpService: { install: forbidden, getOperation: forbidden }, stateManagementService: { configureRelay: forbidden, revealPsk: forbidden },
        userManagementService: { createUser: forbidden, deleteUser: forbidden, importUser: forbidden }, stateRepository: { getTopologyRevision: forbidden }, nodeSSHFactory: forbidden });
    f.worker.installedIngressPreparer = async ({ operationPlan: plan }) => {
        assert.ok(Object.isFrozen(plan));
        assert.equal(f.NodeOperationLock.rows.filter(row => row.operationId === plan.operationId).length, plan.resourceNodeIds.length);
        const proofPlan = options.changePlan ? options.changePlan(plan) : plan;
        options.plans.push(proofPlan);
        const proof = await service.prepareConfiguredRelayIngress({ operationPlan: proofPlan });
        options.prepares.push(proof); return proof;
    };
    return { ...f, state, group, users, options, service, ingress, ppp };
}
async function apply(f, linkId) {
    const queued = await f.coordinator.queue({ expectedTopologyRevision: f.CascadeTopologyState.rows[0].revision, scope: { kind: 'link.apply', linkId, linkIds: [linkId] } });
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.status, 'succeeded', JSON.stringify(result)); return queued;
}
async function remove(f, linkId, jobId = id(90)) {
    const link = f.CascadeLink.rows.find(row => row._id === linkId), desiredVersion = linkDesiredVersion(link);
    const resources = await f.coordinator.resolveIntentResourcesForQueue({ kind: 'link.delete', link, desiredVersion, session: f.session });
    link.lifecycle = { state: 'deleting', deleteJobId: jobId, desiredVersion };
    return f.coordinator.queueIntent({ session: f.session, executionContext: context, intentId: jobId,
        mutation: { kind: 'link.delete', linkId, desiredVersion }, expectedTopologyRevision: f.CascadeTopologyState.rows[0].revision, resourceNodeIds: resources });
}
for (const mode of ['forward', 'reverse']) test(`installed-path planner accepts incomplete ${mode} APPLY and pins kept-empty owner/peer epochs`, async () => {
    const f = installedFixture({ mode });
    Object.assign(f.CascadeLink.rows[0], { portalNode: id(3), bridgeNode: id(1) });
    const before = structuredClone({ groups: f.CascadeRouteGroup.rows, states: f.RelayL2tpState.rows });
    const selected = await f.deployment.readSelected({ snapshot: await f.deployment.snapshotReader.readDraft(f.session),
        scope: { kind: 'link.apply', linkId: id(10) }, executionContext: context, session: f.session });
    assert.equal(selected.routeState, 'no_bridge_exit');
    assert.deepEqual(selected.installedPath.oldPathLinkIds, []);
    assert.deepEqual(selected.installedPath.newPathLinkIds, []);
    assert.equal(selected.installedPath.ownerNodeId, id(1));
    assert.equal(selected.installedPath.ownerCredentialRevision, 41);
    assert.equal(selected.installedPath.ownerTopologyRevision, 0);
    assert.deepEqual(selected.installedPath.groupBefore, require('../domain/topologyDraft').projectGroups([f.group])[0]);
    assert.deepEqual(selected.effectiveTopology.groups, [selected.installedPath.groupBefore]);
    assert.deepEqual({ groups: f.CascadeRouteGroup.rows, states: f.RelayL2tpState.rows }, before);
    assert.equal(f.TopologyOperation.rows.length, 0); assert.equal(f.calls.length, 0);
});

for (const absent of [false, true]) for (const mode of ['forward', 'reverse']) {
    test(`actual worker installed publication absent=${absent} ${mode}, no-exit delete and reattach preserve peers/credentials`, async () => {
        const f = installedFixture({ absent, mode });
        const protectedState = structuredClone(f.state), protectedUsers = structuredClone(f.users);
        const peer = structuredClone(f.group.paths.find(path => path.pathKey === 'peer'));
        const other = structuredClone(f.CascadeRouteGroup.rows[1]);
        await apply(f, id(10));
        assert.deepEqual(f.group.paths.find(path => path.pathKey === 'mine').linkIds, [id(10)]);
        assert.equal(f.options.prepares.at(-1).pppInternetProof, 'unverified');
        assert.ok(f.options.gateCalls.includes('users')); assert.ok(f.options.gateCalls.includes('ingress'));
        const old = structuredClone(f.CascadeLink.rows[0]);
        const queued = await remove(f, id(10));
        const result = await f.worker.run(queued.operationId);
        assert.equal(result.status, 'succeeded', JSON.stringify(result));
        assert.deepEqual(f.group.paths.find(path => path.pathKey === 'mine').linkIds, []);
        assert.equal(f.options.prepares.at(-1).pppInternetProof, 'not_applicable');
        f.CascadeLink.rows.push({ ...old, status: 'pending', tunnelPort: old.tunnelPort + 100 }); f.CascadeTopologyState.rows[0].revision++;
        await apply(f, id(10));
        assert.deepEqual(f.group.paths.find(path => path.pathKey === 'peer'), peer);
        assert.deepEqual(f.CascadeRouteGroup.rows[1], other); assert.deepEqual(f.users, protectedUsers);
        for (const key of ['pskEncrypted', 'secretRevision', 'clientCidr', 'poolStart', 'poolEnd', 'routeGroup', 'activePathKey']) assert.deepEqual(f.state[key], protectedState[key]);
        assert.equal(f.NodeOperationLock.rows.length, 0);
    });
}
test('actual worker installed unreadable PPP/users does not publish or release ownership', async () => {
    const f = installedFixture(); f.options.readbackOk = false;
    const before = structuredClone(f.group);
    const queued = await f.coordinator.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: id(10), linkIds: [id(10)] } });
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.status, 'committing'); assert.deepEqual(f.group, before);
    assert.ok(f.NodeOperationLock.rows.length); assert.equal(f.CascadeLink.rows[0].appliedDescriptor, undefined);
});

// Real V2 executor + terminal coordinator/repository; only external accepted
// enrollment, remote command responses and Mongo transaction transport modeled.
function enableV2(f) {
    const { randomUUID } = require('node:crypto');
    const { freeze, runnerRequest, v2Receipt, simulatedConnectionAuthority } = require('./helpers/topologyV2Fixture');
    const { TopologyOperationExecutor } = require('../services/topologyOperationExecutor');
    const db = f.TopologyOperation.db;
    const bindings = fixture().TopologyOperation, enrollments = fixture().TopologyOperation;
    bindings.db = db; enrollments.db = db;
    const repository = f.worker.finalizer.repository;

    repository.TopologyExecutionBinding = bindings; repository.TopologyExecutionEnrollment = enrollments;
    Object.assign(f.session, { transaction: { transition() {} }, startTransaction() {}, async endSession() {}, async abortTransaction() {} });
    db.startSession = async () => f.session;
    const client = { db: () => ({ command: async () => ({ ok: 1 }) }) };
    db.getClient = () => client; f.session.client = client;
    let held = 0;
    const reader = {
        async readVerified(expected) {
            assert.ok(f.NodeOperationLock.rows.some(row => row.node === expected.nodeId && row.operationId === expected.operationId
                && row.generation === expected.generation), 'modeled authority requires the real worker lock');
            let binding = bindings.rows.find(row => row.nodeId === expected.nodeId && row.operationId === expected.operationId);
            if (!binding) {
                const owner = f.TopologyConfigOwner.rows.find(row => row.node === expected.nodeId);
                const record = { ...expected, attemptId: randomUUID(), bootId: randomUUID(), maintenanceId: randomUUID(),
                    predecessorGeneration: owner.lastSettledGeneration || 'none',
                    commandIds: Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close'].map(command => [command, randomUUID()])) };
                const extra = { enrollmentId: randomUUID(), ownerGeneration: owner.generation,
                    nodeIdentity: structuredClone(owner.nodeIdentity), endpoint: { ip: '192.0.2.1', port: 22, username: 'modeled' } };
                bindings.rows.push({ ...record, ...extra }); enrollments.rows.push({ ...record, ...extra, _id: extra.enrollmentId });
                binding = bindings.rows.at(-1);
            }
            const { enrollmentId, ownerGeneration, nodeIdentity, endpoint, ...record } = binding;
            return freeze(structuredClone(record));
        },
        async readVerifiedConnection(expected, binding) { return simulatedConnectionAuthority(binding); },
        async withVerifiedBinding(expected, work) { held++; try { return await work(await this.readVerified(expected), async () => {}); } finally { held--; } },
    };
    reader.withReadOnlyVerifiedBinding = reader.withVerifiedBinding;
    const events = [];
    const executor = new TopologyOperationExecutor({ ...context, executionBindingReader: reader,
        RunnerBootstrapper: class { async ensureRunner() { return { ok: true }; } },
        nodeExecutionResolver: { async resolve() { return { async writeFile() {}, async exec(command) {
            const request = runnerRequest(command); events.push(request.command);
            const binding = bindings.rows.find(row => row.operationId === request.operationId && row.nodeId === request.nodeId);
            const terminal = ['close', 'status'].includes(request.command)
                ? { terminal: true, phase: 'closed', terminalOutcome: 'verified', completedCommand: 'close' } : {};
            return { code: 0, stderr: '', stdout: JSON.stringify(v2Receipt(request, { bootId: binding.bootId, ...terminal })) + '\n' };
        } }; } } });
    const prepare = f.worker.installedIngressPreparer;
    f.worker = new (require('../workers/topologyOperationWorker').TopologyOperationWorker)({ executionContext: context,
        operationRepository: f.operations, selectedTopologyRepository: f.deployment, executor, finalizer: f.worker.finalizer,
        lockService: f.worker.lockService, clock: { now: () => new Date() }, workerId: 'selected-worker', leaseMs: 30000,
        allowUnprovenTestExecution: true,
        userResync: { async resyncPlan() { assert.ok(held); return { ok: true }; } },
        pppReadinessGate: { async verifyPlan() { throw new Error('Installed service owns these readbacks'); } },
        installedIngressPreparer: async input => { assert.ok(held); return prepare(input); },
    });
    return events;
}
for (const mode of ['forward', 'reverse']) test(`actual V2 worker installed ${mode} settles delete and owned empty path atomically`, async () => {
    const f = installedFixture({ mode }); const events = enableV2(f);
    await apply(f, id(10));
    const queued = await remove(f, id(10)); const result = await f.worker.run(queued.operationId);
    assert.equal(result.status, 'succeeded', JSON.stringify(result));
    assert.equal(f.CascadeLink.rows.some(row => row._id === id(10)), false);
    assert.deepEqual(f.group.paths.find(path => path.pathKey === 'mine').linkIds, []);
    const operation = f.TopologyOperation.rows.find(row => row._id === queued.operationId);
    assert.equal(operation.v2Terminal.state, 'proven');
    assert.equal(operation.v2Terminal.sideEffects.installedIngressProof.pppInternetProof, 'not_applicable');
    assert.equal(f.NodeOperationLock.rows.length, 0); assert.equal(operation.heldTopologyAdmission, false);
    assert.ok(events.includes('close')); assert.ok(events.includes('status'));
});

test('installed delete blocks only owned default path, keeping a nonempty geo peer and independent group', async () => {
    const f = installedFixture();
    // Establish the real settled G3 graph before modeling an already installed
    // group. Adding geo to an installed ingress is a separate gate handoff.
    f.RelayL2tpState.rows.splice(0); await apply(f, id(10));
    const main = f.CascadeLink.rows.find(row => row._id === id(10));
    f.CascadeLink.rows.push({ ...main, _id: id(13), bridgeNode: id(4), tunnelPort: 23500, status: 'pending',
        geoRouting: { enabled: true, geoip: ['ru'], domains: ['category-ru'] } });
    f.CascadeTopologyState.rows[0].revision++;
    await apply(f, id(13));
    f.group.paths.find(path => path.pathKey === 'mine').linkIds = [id(10)];
    f.state.appliedTopologyRevision = f.CascadeTopologyState.rows[0].revision;
    f.RelayL2tpState.rows.push(f.state);
    const peer = f.group.paths.find(path => path.pathKey === 'peer'); peer.linkIds = [id(13)]; peer.enabled = true;
    const protectedPeer = structuredClone(peer), protectedLink = structuredClone(f.CascadeLink.rows.find(row => row._id === id(13)));
    const other = structuredClone(f.CascadeRouteGroup.rows[1]);
    const queued = await remove(f, id(10)); const result = await f.worker.run(queued.operationId);
    assert.equal(result.status, 'succeeded', JSON.stringify(result));
    assert.deepEqual(f.group.paths.find(path => path.pathKey === 'mine').linkIds, []);
    assert.deepEqual(f.group.paths.find(path => path.pathKey === 'peer'), protectedPeer);
    assert.deepEqual(f.CascadeLink.rows.find(row => row._id === id(13)), protectedLink);
    assert.deepEqual(f.CascadeRouteGroup.rows[1], other);
    assert.equal(f.options.prepares.at(-1).pppInternetProof, 'not_applicable');
});
test('missing installed dependency is rejected before dispatch and releases only its no-dispatch ownership', async () => {
    const f = installedFixture(); f.worker.installedIngressPreparer = undefined;
    const queued = await f.coordinator.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: id(10), linkIds: [id(10)] } });
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.errorCode, 'TOPOLOGY_INSTALLED_INGRESS_UNAVAILABLE'); assert.equal(f.calls.length, 0);
    assert.equal(f.NodeOperationLock.rows.length, 0); assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 0);
});
test('installed geo ingress accepts generated conditional policy without falsely publishing client readiness', async () => {
    const f = installedFixture(); await apply(f, id(10));
    f.CascadeLink.rows.push({ ...f.CascadeLink.rows[0], _id: id(13), bridgeNode: id(4), tunnelPort: 23500, status: 'pending',
        geoRouting: { enabled: true, geoip: ['ru'], domains: ['category-ru'] } });
    f.CascadeTopologyState.rows[0].revision++;
    const before = structuredClone(f.group);
    const queued = await f.coordinator.queue({ expectedTopologyRevision: 8, scope: { kind: 'link.apply', linkId: id(13), linkIds: [id(13)] } });
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.status, 'succeeded', JSON.stringify(result));
    assert.deepEqual(f.group, before);
    assert.equal(f.options.prepares.at(-1).pppInternetProof, 'unverified');
    assert.equal(f.NodeOperationLock.rows.length, 0);
    assert.equal(f.CascadeLink.rows.find(row => row._id === id(13)).status, 'staged');
});
test('late tombstone CAS refusal rolls back owned publication, status, owner settlement and release together', async () => {
    const f = installedFixture(); await apply(f, id(10));
    const queued = await remove(f, id(10));
    const models = Object.values(f).filter(value => Array.isArray(value?.rows));
    // Explicit modeled transaction rollback, not a substitute for replica-set validation.
    f.worker.finalizer.repository.transactionRunner = async work => {
        const before = models.map(model => structuredClone(model.rows));
        try { return await work(f.session); }
        catch (error) { models.forEach((model, index) => model.rows.splice(0, model.rows.length, ...before[index])); throw error; }
    };
    f.CascadeLink.deleteOne = async () => ({ deletedCount: 0 });
    const group = structuredClone(f.CascadeRouteGroup.rows), states = structuredClone(f.RelayL2tpState.rows);
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.status, 'committing', JSON.stringify(result));
    assert.deepEqual(f.CascadeRouteGroup.rows, group); assert.deepEqual(f.RelayL2tpState.rows, states);
    assert.equal(f.CascadeLink.rows[0].lifecycle.deleteJobId, id(90));
    assert.equal(f.TopologyOperation.rows.find(row => row._id === queued.operationId).heldTopologyAdmission, true);
    assert.ok(f.NodeOperationLock.rows.length);
});
test('actual Mongoose private projection preserves installed/delete pins for durable job replay', async t => {
    const f = installedFixture(); await apply(f, id(10));
    const queued = await remove(f, id(10)); const source = f.TopologyOperation.rows.find(row => row._id === queued.operationId);
    const Model = require('../models/topologyOperationModel');
    const document = new Model(source); await document.validate();
    assert.deepEqual(document.installedPath, source.installedPath); assert.equal(document.deleteJobId, id(90));
    const findOne = Model.collection.findOne;
    t.after(() => { Model.collection.findOne = findOne; });
    Model.collection.findOne = async (_filter, options) => {
        // Actual Mongoose computes the projection; only driver IO is modeled.
        assert.equal(options.projection.installedPath, 1); assert.equal(options.projection.deleteJobId, 1);
        return document.toObject();
    };
    const repository = new (require('../repositories/topologyOperationRepository').TopologyOperationRepository)({ model: Model });
    const row = await repository.findSelectedDeleteByJobId(id(90), f.session);
    assert.equal(row.deleteJobId, id(90)); assert.deepEqual(row.installedPath, source.installedPath);
    assert.equal(require('../repositories/topologyOperationRepository').selectedAdmissionFingerprint(row), source.admissionFingerprint);
});

module.exports = { installedFixture, apply, remove, enableV2 };
