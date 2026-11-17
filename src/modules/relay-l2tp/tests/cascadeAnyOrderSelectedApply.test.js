'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const configPath = require.resolve('../../../../config');
require.cache[configPath] = { id: configPath, filename: configPath, loaded: true, exports: { panel: { domain: 'selected.invalid' }, xray: {} } };
const loggerPath = require.resolve('../../../utils/logger');
require.cache[loggerPath] = { id: loggerPath, filename: loggerPath, loaded: true, exports: { info() {}, warn() {}, error() {} } };
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { TopologyOperationCoordinator } = require('../services/topologyOperationCoordinator');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { TopologyOperationFinalizationRepository } = require('../repositories/topologyOperationFinalizationRepository');
const { TopologyOperationFinalizer } = require('../services/topologyOperationFinalizer');
const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../services/nodeOperationLockService');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const { linkDesiredVersion } = require('../services/topologyIntentService');
const id = n => n.toString(16).padStart(24, '0');
const sha = s => createHash('sha256').update(s).digest('hex');
function match(row, filter) {
    return Object.entries(filter).every(([key, value]) => {
        if (key === '$or') return value.some(f => match(row, f));
        if (key === '$and') return value.every(f => match(row, f));
        if (key === '$expr') return require('../domain/topologyOperationClaimBinding').matchesTopologyOperationClaimBinding(row, context);
        const get = (o, parts) => !parts.length ? o : Array.isArray(o) ? o.flatMap(x => get(x, parts)) : get(o?.[parts[0]], parts.slice(1));
        const actual = get(row, key.split('.'));
        if (Array.isArray(actual) && !Array.isArray(value) && (!value || typeof value !== 'object')) return actual.includes(value);
        if (value && typeof value === 'object' && !(value instanceof Date) && !Array.isArray(value)
            && Object.keys(value).some(k => k.startsWith('$'))) return Object.entries(value).every(([op, v]) => {
            if (op === '$size') return actual?.length === v;
            if (op === '$type') return typeof actual === 'number';
            if (op === '$exists') return (actual !== undefined) === v;
            if (op === '$nin') return Array.isArray(actual) ? actual.every(x => !v.includes(x)) : !v.includes(actual);
            if (op === '$in') return actual === undefined && v.includes(null) || (Array.isArray(actual) ? actual.some(x => v.includes(x)) : v.includes(actual));
            if (op === '$gt') return actual > v;
            if (op === '$gte') return actual >= v;
            if (op === '$lte') return actual <= v;
            if (op === '$eq') return same(actual, v);
            if (op === '$ne') return !same(actual, v);
            throw new Error(`Unsupported fixture predicate ${op}`);
        });
        return same(actual, value) || (key === '_id' && String(actual) === String(value));
    });
}
function model(rows, db) {
    const query = fn => {
        const q = { select() { return q; }, session() { return q; }, setOptions() { return q; }, read() { return q; },
            readConcern() { return q; }, maxTimeMS() { return q; }, lean: async () => structuredClone(fn()),
            then(a, b) { return q.lean().then(a, b); } };
        return q;
    };
    function update(row, change, filter = {}) {
        for (const [key, value] of Object.entries(change.$set || {})) {
            if (key.startsWith('nodes.$.')) row.nodes.find(n => n.node === filter['nodes.node'])[key.slice(8)] = structuredClone(value);
            else row[key] = structuredClone(value);
        }
        for (const [key, value] of Object.entries(change.$inc || {})) row[key] = (row[key] || 0) + value;
        for (const key of Object.keys(change.$unset || {})) delete row[key];
    }
    return { db, rows, find: f => query(() => rows.filter(r => match(r, f))),
        findById: k => query(() => rows.find(r => String(r._id) === String(k)) || null),
        findOne: f => query(() => rows.find(r => match(r, f)) || null),
        exists: f => query(() => rows.find(r => match(r, f)) ? { _id: 'exists' } : null),
        countDocuments: f => query(() => rows.filter(r => match(r, f)).length),
        create: async docs => { const many = Array.isArray(docs); const values = many ? docs : [docs];
            for (const doc of values) { if (rows.some(r => doc.node && r.node === doc.node)) throw Object.assign(new Error('duplicate'), { code: 11000 }); rows.push(structuredClone(doc)); }
            return structuredClone(many ? values : values[0]); },
        findOneAndUpdate: (f, u) => query(() => { const row = rows.find(r => match(r, f)); if (row) update(row, u, f); return row || null; }),
        updateOne: async (f, u) => { const row = rows.find(r => match(r, f)); if (row) update(row, u, f); return { matchedCount: row ? 1 : 0 }; },
        updateMany: async (f, u) => { const found = rows.filter(r => match(r, f)); found.forEach(r => update(r, u)); return { matchedCount: found.length }; },
        deleteOne: async f => { const index = rows.findIndex(r => match(r, f)); if (index >= 0) rows.splice(index, 1); return { deletedCount: index >= 0 ? 1 : 0 }; } };
}
function fixture() {
    const session = { inTransaction: () => true };
    const db = { startSession: async () => session };
    const transactionRunner = work => work(session); // LOCAL transaction-shaped seam, NOT Mongo rollback proof.
    const clock = { now: () => new Date() };
    const nodes = ['relay', 'bridge', 'portal', 'bridge'].map((cascadeRole, i) => ({ _id: id(i + 1), cascadeRole,
        type: 'xray', active: true, ip: `192.0.2.${i + 1}`, port: 443, xray: { security: 'none', transport: 'tcp' } }));
    const links = [{ _id: id(10), portalNode: id(1), bridgeNode: id(2), mode: 'reverse', active: true,
        status: 'pending', tunnelPort: 23451, tunnelUuid: '11111111-1111-4111-8111-111111111111', tunnelSecurity: 'none', tunnelTransport: 'tcp' },
    { _id: id(11), portalNode: id(3), bridgeNode: id(4), mode: 'forward', active: true,
        status: 'pending', tunnelPort: 23452, tunnelUuid: '22222222-2222-4222-8222-222222222222', tunnelSecurity: 'none', tunnelTransport: 'tcp' }];
    const owners = nodes.map((n, i) => ({ node: n._id, profile: n.cascadeRole === 'portal' ? 'xray-main' : 'xray-bridge',
        executionContext: context, owner: 'topology', generation: '11111111-1111-4111-8111-111111111111',
        nodeIdentity: { machineId: String(i + 1).repeat(32), sshHostKeySha256: String(i + 1).repeat(64) },
        originalSnapshot: { configSha256: sha('{}'), unitSha256: sha('unit'), serviceActive: 'inactive', serviceEnabled: 'disabled' },
        adoptionReceipt: { toGeneration: '11111111-1111-4111-8111-111111111111',
            proofId: '22222222-2222-4222-8222-222222222222', maintenanceId: '33333333-3333-4333-8333-333333333333', verifiedAt: new Date() } }));
    const models = { HyNode: model(nodes, db), CascadeLink: model(links, db), CascadeRouteGroup: model([], db),
        RelayL2tpState: model([], db), CascadeTopologyState: model([{ _id: 'singleton', revision: 7, deployedRevision: 3, remoteAdmissionCount: 0, topologyAdmissionCount: 0 }], db),
        TopologyOperation: model([], db), NodeOperationLock: model([], db), TopologyConfigOwner: model(owners, db), RemoteAdmission: model([], db) };
    db.models = models;
    const snapshotReader = { ...models, readDraft: async () => ({ revision: models.CascadeTopologyState.rows[0].revision,
        deployedRevision: 3, nodes: structuredClone(nodes), links: structuredClone(links), groups: [] }) };
    const deployment = new TopologyDeploymentRepository({ ...models, snapshotReader, transactionRunner });
    const operations = new TopologyOperationRepository({ model: models.TopologyOperation, topologyStateModel: models.CascadeTopologyState, selectedTopologyRepository: deployment });
    const finalization = new TopologyOperationFinalizationRepository({ ...models, transactionRunner, selectedTopologyRepository: deployment });
    const finalizer = new TopologyOperationFinalizer({ repository: finalization, clock });
    const lockService = new NodeOperationLockService({ repository: new NodeOperationLockRepository({ model: models.NodeOperationLock }), clock });
    const calls = [];
    const executor = { prepare: async c => { calls.push(['prepare', c.node]); return { backupId: 'backup', prepared: {} }; },
        commit: async c => { calls.push(['commit', c.node]); return { ok: true }; }, verify: async () => ({ ok: true }),
        cleanupPrepared: async () => ({ ok: true }), rollback: async () => ({ ok: true }) };
    const worker = new TopologyOperationWorker({ executionContext: context, operationRepository: operations, executor,
        finalizer, lockService, clock, workerId: 'selected-worker', leaseMs: 30000, allowUnprovenTestExecution: true,
        selectedTopologyRepository: deployment });
    const coordinator = new TopologyOperationCoordinator({ executionContext: context, topologyRepository: deployment,
        planMaterializer: new TopologyOperationPlanMaterializer(models), operationRepository: operations });
    return { ...models, coordinator, deployment, operations, worker, calls, executor, session };
}
test('selected source-less apply reaches actual worker and transaction-shaped publication after unrelated drift', async () => {
    const f = fixture();
    const queued = await f.coordinator.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: id(10), linkIds: [id(10)] } });
    const operation = f.TopologyOperation.rows[0];
    assert.equal(operation.admissionScope, 'selected');
    assert.equal(operation.desiredVersion, linkDesiredVersion(f.CascadeLink.rows[0]));
    assert.equal(operation.effectiveTopology.links[0].tunnelPort, 23451);
    f.CascadeTopologyState.rows[0].revision++;
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.status, 'succeeded', JSON.stringify(result));
    assert.equal(f.NodeOperationLock.rows.length, 0);
    assert.equal(operation.heldTopologyAdmission, false);
    assert.equal(f.CascadeTopologyState.rows[0].deployedRevision, 3);
    assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 0);
    assert.equal(f.CascadeLink.rows[0].status, 'staged');
    assert.equal(f.TopologyConfigOwner.rows[0].lastSettledOperation, queued.operationId);
    assert.ok(f.calls.some(([phase]) => phase === 'commit'));
});
const apply = (f, n, revision = f.CascadeTopologyState.rows[0].revision) => f.coordinator.queue({ expectedTopologyRevision: revision,
    scope: { kind: 'link.apply', linkId: id(n), linkIds: [id(n)] } });
test('same resources wait while independent selected admission survives retained uncertainty', async () => {
    const f = fixture();
    const first = await apply(f, 10);
    await assert.rejects(apply(f, 10, 8), { code: 'STALE_TOPOLOGY_REVISION' });
    f.executor.prepare = async () => { throw new Error('unknown writer outcome'); };
    assert.equal((await f.worker.run(first.operationId)).status, 'failed');
    assert.equal(f.NodeOperationLock.rows.length, 2);
    assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 1);
    // A new coordinator models another request/process, not its local replay map.
    const replay = new TopologyOperationCoordinator({ executionContext: context, topologyRepository: f.deployment,
        operationRepository: f.operations, planMaterializer: new TopologyOperationPlanMaterializer(f) });
    await assert.rejects(replay.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: id(10), linkIds: [id(10)] } }), { code: 'TOPOLOGY_DEPLOY_BUSY' });
    const independent = await apply(f, 11);
    f.executor.prepare = async () => ({ backupId: 'backup', prepared: {} });
    assert.equal((await f.worker.run(independent.operationId)).status, 'succeeded');
    assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 1);
    assert.equal(f.NodeOperationLock.rows.length, 2);
    assert.ok(f.NodeOperationLock.rows.every(row => row.operationId === first.operationId));
});
test('partial no-dispatch lock acquisition releases its exact generations and waits without spending attempts', async () => {
    const f = fixture();
    const queued = await apply(f, 10);
    f.NodeOperationLock.rows.push({ node: id(2), owner: 'winner', operationId: 'foreign', generation: 'winner-generation',
        remoteUncertain: true, leaseUntil: new Date(Date.now() + 30000) });
    const result = await f.worker.run(queued.operationId);
    assert.equal(result.errorCode, 'NODE_OPERATION_LOCK_CONFLICT');
    assert.equal(f.calls.length, 0);
    assert.deepEqual(f.NodeOperationLock.rows.map(row => row.generation), ['winner-generation']);
    assert.equal(f.TopologyOperation.rows[0].status, 'queued');
    assert.equal(f.TopologyOperation.rows[0].attempts, 0);
});
test('no settled pointer without exact adopted empty config refuses rather than adopting desired status', async () => {
    const f = fixture();
    f.CascadeLink.rows[0].status = 'deployed';
    f.TopologyConfigOwner.rows[0].originalSnapshot.configSha256 = sha('arbitrary classic config');
    await assert.rejects(apply(f, 10), { code: 'TOPOLOGY_OPERATION_QUEUE_FAILED' });
    assert.equal(f.TopologyOperation.rows.length, 0);
    assert.equal(f.NodeOperationLock.rows.length, 0);
});
test('owner physical identity and requested desired descriptor are rechecked under locks before prepare', async () => {
    for (const mutate of [f => { f.TopologyConfigOwner.rows[0].nodeIdentity.machineId = 'a'.repeat(32); },
        f => { f.CascadeLink.rows[0].tunnelPort++; }]) {
        const f = fixture();
        const queued = await apply(f, 10);
        mutate(f);
        const result = await f.worker.run(queued.operationId);
        assert.equal(result.status, 'failed');
        assert.equal(f.calls.length, 0);
        assert.equal(f.NodeOperationLock.rows.length, 0);
        assert.equal(f.TopologyOperation.rows[0].heldTopologyAdmission, false);
        assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 0);
    }
});
test('a known physical alias never obtains a second independent lock slot', async () => {
    const f = fixture();
    f.TopologyConfigOwner.rows[3].nodeIdentity = structuredClone(f.TopologyConfigOwner.rows[0].nodeIdentity);
    await assert.rejects(apply(f, 10), { code: 'TOPOLOGY_OPERATION_QUEUE_FAILED' });
    assert.equal(f.TopologyOperation.rows.length, 0);
});
test('joined intent admission persists exact desired pin without starting a worker in its transaction', async () => {
    const f = fixture();
    f.coordinator.operationWorker = { run() { throw new Error('execution inside transaction'); } };
    const version = linkDesiredVersion(f.CascadeLink.rows[0]);
    const resources = await f.coordinator.resolveIntentResourcesForQueue({ kind: 'link.apply', link: f.CascadeLink.rows[0], desiredVersion: version, session: f.session });
    const result = await f.coordinator.queueIntent({ session: f.session, executionContext: context, intentId: id(90),
        mutation: { kind: 'link.apply', linkId: id(10), desiredVersion: version }, expectedTopologyRevision: 7, resourceNodeIds: resources });
    assert.equal(f.TopologyOperation.rows[0].desiredVersion, version);
    assert.equal(f.TopologyOperation.rows[0]._id, result.operationId);
    assert.equal(f.calls.length, 0);
    assert.equal(JSON.stringify(result).includes('effectiveTopology'), false);
});
test('successor uses settled descriptors, not a save-only neighbor edit or a pending sibling', async () => {
    const f = fixture();
    const initial = await apply(f, 10);
    assert.equal((await f.worker.run(initial.operationId)).status, 'succeeded');
    f.CascadeLink.rows[0].tunnelPort = 29999; // save-only edit, deliberately not selected.
    f.CascadeLink.rows.push({ _id: id(12), portalNode: id(3), bridgeNode: id(1), mode: 'reverse', active: true,
        status: 'pending', tunnelPort: 23453, tunnelSecurity: 'none', tunnelTransport: 'tcp' });
    f.CascadeTopologyState.rows[0].revision++;
    const next = await apply(f, 12);
    const operation = f.TopologyOperation.rows.find(row => row._id === next.operationId);
    assert.deepEqual(operation.linkIds, [id(10), id(12)]);
    assert.equal(operation.effectiveTopology.links.find(link => link.id === id(10)).tunnelPort, 23451);
    const relay = operation.nodes.find(node => node.node === id(1));
    const config = JSON.parse(Buffer.from(relay.candidate.bytes).toString());
    assert.ok(config.inbounds.some(inbound => inbound.port === 23451), 'old applied listener must be preserved');
    assert.equal(config.inbounds.some(inbound => inbound.port === 29999), false, 'save-only edit must not dispatch');
    assert.equal((await f.worker.run(next.operationId)).status, 'succeeded');
    assert.equal(f.CascadeLink.rows.find(link => link._id === id(11)).status, 'pending');
});
test('default runtime wires selected readers, worker, settlement and joined writers', async () => {
    const f = fixture();
    const { createTopologyOperationRuntime } = require('../runtime/createTopologyOperationRuntime');
    const db = f.TopologyOperation.db;
    const runtime = createTopologyOperationRuntime({ ...f,
        L2tpUser: model([], db), L2tpOperation: model([], db), NodeSSH: class {},
        env: { PANEL_DOMAIN: context.hostIdentity, L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' },
        transactionRunner: work => work(f.session), createTopologyOperationExecutor: () => f.executor,
    });
    assert.ok(runtime instanceof TopologyOperationCoordinator);
    assert.equal(runtime.topologyRepository.selectedEnabled, true);
    assert.equal(runtime.intentDraftWriter.db, db);
    assert.equal(runtime.intentOperationAdmission.db, db);
    const worker = runtime.operationWorker;
    runtime.operationWorker = undefined; // deterministic scheduling, not a substituted worker.
    worker.userResync._syncService = { _getUsersForNode: async () => [], addXrayUser: async () => {} };
    const result = await runtime.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: id(11), linkIds: [id(11)] } });
    assert.equal((await worker.run(result.operationId)).status, 'succeeded');
    assert.equal(f.CascadeLink.rows[1].status, 'deployed');
    assert.equal(f.TopologyConfigOwner.rows[2].lastSettledOperation, result.operationId);
});
test('joined create draft writer uses the existing store and the exact outer session without worker execution', async () => {
    const f = fixture();
    const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
    const repository = new TopologyDraftRepository({ ...f, transactionRunner: () => { throw new Error('must join outer transaction'); } });
    const desired = f.CascadeLink.rows.splice(1, 1)[0];
    const writer = repository.createIntentDraftWriter({ selectedTopologyRepository: f.deployment });
    const result = await writer.createLink({ expectedTopologyRevision: 7, link: desired, session: f.session });
    assert.equal(result.revision, 8);
    assert.equal(f.CascadeLink.rows[1]._id, id(11));
    assert.equal(f.calls.length, 0);
    assert.equal(f.TopologyOperation.rows.length, 0);
    await assert.rejects(writer.createLink({ expectedTopologyRevision: 8, link: desired }), TypeError);
});
test('one-hop source-less installed attach finalizes only its owned path and preserves peer bytes and credentials', async () => {
    const f = fixture();
    const groupId = id(70);
    const peers = [{ pathKey: 'peer-a', linkIds: [id(60)], priority: 7, enabled: true },
        { pathKey: 'peer-b', linkIds: [id(61)], priority: 9, enabled: false }];
    f.CascadeRouteGroup.rows.push({ _id: groupId, paths: structuredClone(peers), name: 'shared' });
    f.RelayL2tpState.rows.push({ node: id(1), routeGroup: groupId, status: 'installed', desiredState: 'installed',
        activePathKey: 'main', appliedTopologyRevision: 3, secretRevision: 11, pppSecret: 'fixture-secret' });
    const leaseUntil = new Date(Date.now() + 30000);
    f.TopologyOperation.rows.push({ _id: 'owned-attach', status: 'committing', topologyRevision: 7, priorDeployedRevision: 3,
        heldTopologyAdmission: true, leaseOwner: 'worker', leaseUntil, kind: 'link.attach', linkId: id(10),
        linkIds: [id(10)], newPathLinkIds: [id(10)], groupId, pathKey: 'main', ownerNodeId: id(1), ownerTopologyRevision: 3, ownerCredentialRevision: 11 });
    f.CascadeTopologyState.rows[0].topologyAdmissionCount = 1;
    const repository = new TopologyOperationFinalizationRepository({ ...f, transactionRunner: work => work(f.session) });
    const result = await repository.finalizeSucceeded({ operationId: 'owned-attach', owner: 'worker', leaseUntil,
        topologyRevision: 7, priorDeployedRevision: 3, now: new Date() });
    assert.equal(result.scopeKind, 'link.attach');
    assert.deepEqual(f.CascadeRouteGroup.rows[0].paths.slice(0, 2), peers);
    assert.deepEqual(f.CascadeRouteGroup.rows[0].paths[2].linkIds, [id(10)]);
    assert.equal(f.RelayL2tpState.rows[0].secretRevision, 11);
    assert.equal(f.RelayL2tpState.rows[0].pppSecret, 'fixture-secret');
    assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 0);
});
test('selected V2 settlement joins exact owner pointers, node releases, scoped publication and one count decrement after unrelated drift', async () => {
    const f = fixture();
    await apply(f, 10); // independently retained admission remains after V2 finish.
    const queued = await apply(f, 11);
    const operation = f.TopologyOperation.rows.find(row => row._id === queued.operationId);
    const { randomUUID } = require('node:crypto');
    const db = f.TopologyOperation.db;
    const client = { db: () => ({ command: async () => ({ ok: 1 }) }) };
    const session = { inTransaction: () => true, client, transaction: { transition() {} },
        startTransaction() {}, endSession: async () => {}, abortTransaction: async () => {} };
    db.startSession = async () => session;
    db.getClient = () => client;
    const leaseUntil = new Date(Date.now() + 30000);
    operation.status = 'committing'; operation.attempts = 1;
    operation.leaseOwner = 'v2-worker'; operation.leaseUntil = leaseUntil;
    const bindings = [], rows = [], enrollments = [], proofs = [], ownerFences = [];
    for (const node of operation.nodes) {
        node.state = 'committed'; node.backupId = 'backup';
        const owner = f.TopologyConfigOwner.rows.find(row => row.node === node.node);
        const binding = { operationId: operation._id, nodeId: node.node, candidateHash: `sha256:${node.candidateHash}`,
            backupId: 'backup', targetProfile: node.targetProfile, executionContext: context.hostIdentity,
            topologyRevision: 7, priorDeployedRevision: 3, owner: 'v2-worker', attempt: 1,
            generation: randomUUID(), attemptId: randomUUID(), predecessorGeneration: 'none', bootId: randomUUID(), maintenanceId: randomUUID(),
            commandIds: Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close'].map(command => [command, randomUUID()])) };
        const enrollmentId = `enrolled:${node.node}`;
        const extra = { ownerGeneration: owner.generation, nodeIdentity: structuredClone(owner.nodeIdentity), endpoint: { ip: '192.0.2.1', port: 22, username: 'fixture' } };
        rows.push({ ...binding, ...extra, enrollmentId });
        enrollments.push({ ...binding, ...extra, _id: enrollmentId });
        f.NodeOperationLock.rows.push({ node: node.node, generation: binding.generation, operationId: operation._id,
            owner: 'v2-worker', leaseUntil, remoteUncertain: true });
        ownerFences.push(Object.fromEntries(['node', 'profile', 'executionContext', 'owner', 'generation', 'nodeIdentity', 'originalSnapshot', 'adoptionReceipt'].map(key => [key, structuredClone(owner[key])])));
        const proof = Object.fromEntries(['operationId', 'nodeId', 'candidateHash', 'backupId', 'targetProfile', 'executionContext', 'attemptId', 'generation', 'predecessorGeneration', 'bootId'].map(key => [key, binding[key]]));
        proofs.push({ ...proof, ok: true, command: 'status', commandId: binding.commandIds.close, protocolVersion: 2,
            completion: 'completed', phase: 'closed', terminal: true, ownershipRetained: true,
            terminalOutcome: 'verified', systemdJob: 'completed', serviceState: 'active:running', completedCommand: 'close' });
        bindings.push(binding);
    }
    operation.v2Terminal = { bindings, proofs, ownerFences, state: 'proven', sideEffects: { usersVerified: true, attachVerified: false, pppProof: [] } };
    f.CascadeTopologyState.rows[0].revision++;
    const repository = new TopologyOperationFinalizationRepository({ ...f, selectedTopologyRepository: f.deployment,
        TopologyExecutionBinding: model(rows, db), TopologyExecutionEnrollment: model(enrollments, db), transactionRunner: work => work(session) });
    const result = await repository.finalizeV2Succeeded({ operationId: operation._id, owner: 'v2-worker', leaseUntil,
        topologyRevision: 7, priorDeployedRevision: 3, now: new Date() });
    assert.equal(result.scopeKind, 'link.apply');
    assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 1);
    assert.equal(f.CascadeTopologyState.rows[0].deployedRevision, 3);
    assert.equal(f.NodeOperationLock.rows.length, 0);
    assert.equal(operation.heldTopologyAdmission, false);
    const baseline = await f.deployment.readSelected({ scope: { kind: 'link.apply', linkId: id(11) }, executionContext: context, session });
    assert.deepEqual(baseline.baselineTopology, { ...operation.effectiveTopology,
        nodes: operation.effectiveTopology.nodes.map(node => ({ ...node,
            profileConfig: Buffer.from(operation.nodes.find(entry => entry.node === node.id).candidate.bytes).toString('utf8') })) });
    await assert.rejects(repository.finalizeV2Succeeded({ operationId: operation._id, owner: 'v2-worker', leaseUntil,
        topologyRevision: 7, priorDeployedRevision: 3, now: new Date() }), { code: 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED' });
    assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 1);
});
test('endpoint change locks and cleans the old/new physical union without coupling future disconnected components', async () => {
    const f = fixture();
    assert.equal((await f.worker.run((await apply(f, 10)).operationId)).status, 'succeeded');
    Object.assign(f.CascadeLink.rows[0], { portalNode: id(3), bridgeNode: id(4) });
    f.CascadeTopologyState.rows[0].revision++;
    const queued = await apply(f, 10);
    const operation = f.TopologyOperation.rows.find(row => row._id === queued.operationId);
    assert.deepEqual(operation.resourceNodeIds, [id(1), id(2), id(3), id(4)]);
    assert.equal(operation.nodes.length, 4);
    assert.equal((await f.worker.run(queued.operationId)).status, 'succeeded');
    f.CascadeLink.rows.push({ _id: id(12), portalNode: id(1), bridgeNode: id(2), mode: 'reverse', active: true,
        status: 'pending', tunnelPort: 23453, tunnelSecurity: 'none', tunnelTransport: 'tcp' });
    f.CascadeTopologyState.rows[0].revision++;
    const next = await apply(f, 12);
    const clean = f.TopologyOperation.rows.find(row => row._id === next.operationId);
    assert.deepEqual(clean.resourceNodeIds, [id(1), id(2)]);
    assert.deepEqual(clean.baselineTopology, { nodes: operation.nodes.filter(entry => [id(1), id(2)].includes(entry.node)).map(entry => ({
        ...operation.baselineTopology.nodes.find(node => node.id === entry.node),
        profileConfig: Buffer.from(entry.candidate.bytes).toString('utf8') })), links: [], groups: [] });
    assert.equal((await f.worker.run(next.operationId)).status, 'succeeded');
});
test('counted remote admission permits independent selected work in either order while same node and drain remain blocked', async () => {
    const { RemoteAdmissionRepository } = require('../repositories/remoteAdmissionRepository');
    for (const first of ['topology', 'remote']) {
        const f = fixture();
        const remote = new RemoteAdmissionRepository({ ...f, transactionRunner: work => work(f.session) });
        let queued;
        if (first === 'topology') queued = await apply(f, 10);
        await remote.acquireInstall({ nodeId: id(4) });
        if (!queued) queued = await apply(f, 10);
        await assert.rejects(apply(f, 11), { code: 'TOPOLOGY_DEPLOY_BUSY' });
        await assert.rejects(remote.acquireInstall({ nodeId: id(1) }), { code: 'REMOTE_ADMISSION_BLOCKED' });
        assert.equal((await f.worker.run(queued.operationId)).status, 'succeeded');
        assert.equal(f.CascadeTopologyState.rows[0].remoteAdmissionCount, 1);
        assert.equal(f.CascadeTopologyState.rows[0].topologyAdmissionCount, 0);
        f.CascadeTopologyState.rows[0].remoteDrain = { ownerToken: 'foreign' };
        const replay = new TopologyOperationCoordinator({ executionContext: context, topologyRepository: f.deployment,
            operationRepository: f.operations, planMaterializer: new TopologyOperationPlanMaterializer(f) });
        await assert.rejects(replay.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: id(10), linkIds: [id(10)] } }), { code: 'TOPOLOGY_DEPLOY_BUSY' });
    }
});
test('joined create can save a pending neighbor while selected resources are occupied without changing the frozen apply', async () => {
    const f = fixture();
    const pending = { ...f.CascadeLink.rows.splice(1, 1)[0], bridgeNode: id(1), tunnelMode: 'reverse' };
    const first = await apply(f, 10);
    const originalFingerprint = f.TopologyOperation.rows[0].admissionFingerprint;
    const draft = new (require('../repositories/topologyDraftRepository').TopologyDraftRepository)({
        ...f, transactionRunner: () => { throw new Error('must join outer transaction'); },
    });
    const writer = draft.createIntentDraftWriter({ selectedTopologyRepository: f.deployment });
    let reached, resume;
    const started = new Promise(resolve => { reached = resolve; });
    const paused = new Promise(resolve => { resume = resolve; });
    const originalPrepare = f.executor.prepare;
    f.executor.prepare = async input => { reached(); await paused; return originalPrepare(input); };
    const running = f.worker.run(first.operationId);
    await Promise.race([started, running.then(result => { throw new Error(JSON.stringify(result)); })]);
    const heldLocks = structuredClone(f.NodeOperationLock.rows);
    try {
        const saved = await writer.createLink({ session: f.session, expectedTopologyRevision: 7, link: pending });
        assert.equal(saved.revision, 8);
        assert.equal(f.CascadeLink.rows.length, 2);
        assert.equal(f.calls.length, 0);
        assert.deepEqual(f.NodeOperationLock.rows, heldLocks);
        assert.equal(f.TopologyOperation.rows[0].admissionFingerprint, originalFingerprint);
    } finally { resume(); }
    assert.equal((await running).status, 'succeeded');
    assert.deepEqual(f.TopologyOperation.rows[0].effectiveTopology.links.map(row => row.id), [id(10)]);
    assert.equal(f.CascadeLink.rows.find(row => row._id === pending._id).status, 'pending');
});
test('strict model round trip retains selected descriptor, fingerprint and physical-resource identity', async () => {
    const f = fixture();
    const queued = await apply(f, 10);
    const source = f.TopologyOperation.rows[0];
    const Model = require('../models/topologyOperationModel');
    const hydrated = new Model(source);
    await hydrated.validate();
    const row = hydrated.toObject();
    assert.equal(String(row._id), queued.operationId);
    assert.equal(row.admissionScope, 'selected');
    assert.deepEqual(row.selectedOwnerPins, source.selectedOwnerPins);
    assert.equal(require('../repositories/topologyOperationRepository').selectedAdmissionFingerprint(row), source.admissionFingerprint);
    // Private snapshots/pins are not returned by the public status projection.
    assert.equal(JSON.stringify(await f.operations.findPublicById(queued.operationId)).includes('nodeIdentity'), false);
});
test('installed empty owner path is not silently reported as a selected apply without ingress publication', async () => {
    const f = fixture();
    const snapshot = await f.deployment.snapshotReader.readDraft();
    snapshot.installedRouteOwners = [{ nodeId: id(1), groupId: id(70), pathKey: 'main' }];
    await assert.rejects(f.deployment.readSelected({ snapshot, scope: { kind: 'link.apply', linkId: id(10) },
        executionContext: context, session: f.session }), { code: 'TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED' });
    assert.equal(f.calls.length, 0);
    assert.equal(f.TopologyOperation.rows.length, 0);
});
module.exports = { fixture, id, sha, model };
