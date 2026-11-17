'use strict';
// Public HTTP FullSync and subscription; only persistence/node receipts are
// modeled, using the existing selected-runtime fixture. No live traffic claim.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { randomUUID } = require('node:crypto');
const { fixture, id, model } = require('./cascadeAnyOrderSelectedApply.test');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const { TopologyOperationFinalizationRepository } = require('../repositories/topologyOperationFinalizationRepository');

function replaceModule(t, name, exports) {
    const key = require.resolve(name), previous = require.cache[key];
    require.cache[key] = { id: key, filename: key, loaded: true, exports };
    t.after(() => { if (previous) require.cache[key] = previous; else delete require.cache[key]; });
}
test('first public FullSync -> V2 settlement -> selected successor -> preserved actual subscription without a selected predecessor', async t => {

    const f = fixture();
    // Exact live shape: portal -> relay -> default bridge plus a geo leaf,
    // and the relay's installed-group ingress. A bare compiler is not equivalent.
    f.CascadeLink.rows.splice(0, f.CascadeLink.rows.length,
        { _id: id(10), portalNode: id(3), bridgeNode: id(1), mode: 'reverse', active: true, status: 'deployed', tunnelPort: 23451, tunnelSecurity: 'none', tunnelTransport: 'tcp' },
        { _id: id(11), portalNode: id(1), bridgeNode: id(4), mode: 'reverse', active: true, status: 'deployed', tunnelPort: 23452, tunnelSecurity: 'none', tunnelTransport: 'tcp' },
        { _id: id(12), portalNode: id(1), bridgeNode: id(2), mode: 'reverse', active: true, status: 'deployed', tunnelPort: 23453, tunnelSecurity: 'none', tunnelTransport: 'tcp', geoRouting: { enabled: true, domains: ['domain:example.ru'], geoip: [] } });
    f.CascadeRouteGroup.rows.push({ _id: id(60), mode: 'reverse', strategy: 'priority-failover',
        paths: [{ pathKey: 'main', linkIds: [id(11)], priority: 1, enabled: true }] });
    f.RelayL2tpState.rows.push({ node: id(1), status: 'installed', desiredState: 'installed',
        secretRevision: 2, routeGroup: id(60), activePathKey: 'main', appliedTopologyRevision: 3 });
    f.deployment.snapshotReader.readDraft = async () => ({ revision: f.CascadeTopologyState.rows[0].revision,
        deployedRevision: 3, nodes: structuredClone(f.HyNode.rows), links: structuredClone(f.CascadeLink.rows), groups: structuredClone(f.CascadeRouteGroup.rows) });
    const portal = f.HyNode.rows.find(n => n._id === id(3));
    Object.assign(portal, { name: 'preserved portal', status: 'online' });
    const user = { _id: id(90), userId: 'preserved-user', username: 'preserved-user', enabled: true,
        subscriptionToken: 'first-full-subscription', xrayUuid: '550e8400-e29b-41d4-a716-446655440000',
        nodes: [portal], groups: [], traffic: { tx: 0, rx: 0 }, trafficLimit: 0, hwidMode: 'off' };
    const noop = () => {};
    replaceModule(t, '../../../utils/logger', { info: noop, warn: noop, error: noop, debug: noop });
    replaceModule(t, '../../../services/cacheService', { getSubscription: async () => null, setSubscription: async () => {} });
    replaceModule(t, '../../../services/uaStatsService', { track: noop });
    replaceModule(t, '../../../services/sshPoolService', {}); // node transport is modeled; no global SSH housekeeping timer
    replaceModule(t, '../../../utils/helpers', { getSettings: async () => ({ loadBalancing: { hideOffline: false }, hwid: { enabled: false } }),
        getNodesByGroups: () => [], parseDurationSeconds: () => 0, normalizeHopInterval: x => x });
    const q = { populate() { return q; }, then(resolve, reject) { return Promise.resolve(user).then(resolve, reject); } };
    replaceModule(t, '../../../models/hyUserModel', { findOne: () => q });
    replaceModule(t, '../../l2tpActiveHostProvider', { l2tpActiveHostProvider: { getActiveHost: () => ({
        readAppliedNodePublication: input => f.deployment.readAppliedNodePublication({ ...input, executionContext: context }),
    }) } });
    const { createCascadeTopologyDeployRouter } = require('../../../routes/cascadeTopologyDeploy');
    const subscription = require('../../../routes/subscription');
    const pass = (req, res, next) => next();
    const app = express(); app.use(express.json());
    app.use('/api/cascade/topology', createCascadeTopologyDeployRouter({ topologyDeploymentService: f.coordinator,
        models: f, deploymentEnv: { PANEL_DOMAIN: context.hostIdentity, TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' },
        requireAuth: pass, requireScope: () => pass, csrf: pass, deployRateLimiter: pass, operationStatusRateLimiter: pass }));
    app.use('/api', subscription);
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    t.after(() => new Promise(resolve => server.close(resolve)));
    const base = 'http://127.0.0.1:' + server.address().port;
    const response = await fetch(base + '/api/cascade/topology/deploy', { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ expectedTopologyRevision: 7 }) });
    const queued = await response.json(); assert.equal(response.status, 202, JSON.stringify(queued));
    const op = f.TopologyOperation.rows[0];
    assert.equal(op.kind, undefined); assert.equal(op.admissionScope, undefined);
    assert.ok(op.fullTopology, 'full admission persists its actual hydrated input');
    assert.equal(f.TopologyOperation.rows.length, 1, 'there is NO selected predecessor');
    async function settle(op) {
    const db = f.TopologyOperation.db, client = { db: () => ({ command: async () => ({ ok: 1 }) }) };
    const session = { inTransaction: () => true, client, transaction: { transition() {} },
        startTransaction() {}, endSession: async () => {}, abortTransaction: async () => {} };
    db.startSession = async () => session; db.getClient = () => client;
    const leaseUntil = new Date(Date.now() + 30000);
    Object.assign(op, { status: 'committing', attempts: 1, leaseOwner: 'modeled-node-worker', leaseUntil });
    const bindings = [], proofs = [], ownerFences = [];
    for (const entry of op.nodes) {
        Object.assign(entry, { state: 'committed', backupId: 'backup' });
        const owner = f.TopologyConfigOwner.rows.find(o => o.node === entry.node);
        const binding = { operationId: op._id, nodeId: entry.node, targetProfile: entry.targetProfile,
            candidateHash: 'sha256:' + entry.candidateHash, backupId: 'backup', executionContext: context.hostIdentity,
            topologyRevision: op.topologyRevision, priorDeployedRevision: op.priorDeployedRevision, owner: op.leaseOwner, attempt: 1,
            generation: randomUUID(), attemptId: randomUUID(), predecessorGeneration: owner.lastSettledGeneration ?? 'none', bootId: randomUUID(), maintenanceId: randomUUID(),
            commandIds: Object.fromEntries(['prepare','commit','verify','rollback','close'].map(k => [k, randomUUID()])) };
        bindings.push(binding);
        ownerFences.push(Object.fromEntries(['node','profile','executionContext','owner','generation','nodeIdentity','originalSnapshot','adoptionReceipt'].map(k => [k, structuredClone(owner[k])])));
        const root = Object.fromEntries(['operationId','nodeId','candidateHash','backupId','targetProfile','executionContext','attemptId','generation','predecessorGeneration','bootId'].map(k => [k,binding[k]]));
        proofs.push({ ...root, ok: true, command: 'status', commandId: binding.commandIds.close, protocolVersion: 2,
            completion: 'completed', phase: 'closed', terminal: true, ownershipRetained: true, terminalOutcome: 'verified',
            systemdJob: 'completed', serviceState: 'active:running', completedCommand: 'close' });
        f.NodeOperationLock.rows.push({ node: entry.node, generation: binding.generation, operationId: op._id,
            owner: op.leaseOwner, leaseUntil, remoteUncertain: true });
    }
    op.v2Terminal = { state: 'proven', bindings, proofs, ownerFences, sideEffects: { usersVerified: true, attachVerified: false,
        pppProof: [{ relayNode: id(1), credentialRevision: 2 }] } };
    // Exact node/enrollment serialization for the real V2 finalizer, not direct
    // writes to settled pointers or success flags.

    const rows = bindings.map((b,i) => ({ ...b, enrollmentId: 'enrollment-'+i,
        ownerGeneration: ownerFences[i].generation, nodeIdentity: ownerFences[i].nodeIdentity,
        endpoint: { ip: '192.0.2.1', port: 22, username: 'fixture' } }));
    const enrollments = rows.map(row => ({ ...row, _id: row.enrollmentId }));
    const finalizer = new TopologyOperationFinalizationRepository({ ...f, selectedTopologyRepository: f.deployment,
        TopologyExecutionBinding: model(rows, db), TopologyExecutionEnrollment: model(enrollments, db), transactionRunner: work => work(session) });
    await finalizer.finalizeV2Succeeded({ operationId: op._id, owner: op.leaseOwner, leaseUntil,
        topologyRevision: op.topologyRevision, priorDeployedRevision: op.priorDeployedRevision, now: new Date() });
    assert.equal(op.status, 'succeeded'); assert.equal(op.heldTopologyAdmission, false);
    return session;
    }
    const selectedSession = await settle(op);
    portal.ip = '192.0.2.199'; f.CascadeLink.rows[0].tunnelPort++; f.CascadeTopologyState.rows[0].revision++;
    const sub = await fetch(base + '/api/files/first-full-subscription?format=xray-json');
    assert.equal(sub.status, 200, await sub.clone().text());
    const profiles = await sub.json(); assert.ok(profiles.length > 0);
    const endpoints = profiles.flatMap(p => p.outbounds || []).flatMap(o => o.settings?.vnext || []);
    assert.ok(endpoints.some(e => e.address === '192.0.2.3' && e.users.some(u => u.id === user.xrayUuid)),
        'real subscription uses the frozen applied endpoint and preserved user, NOT changed desired metadata');
    const digest = op.admissionFingerprint; op.fullTopology.links[0].tunnelPort++;
    const refused = await fetch(base + '/api/files/first-full-subscription?format=xray-json');
    assert.equal(refused.status, 500, 'tampered immutable representation never becomes a subscription baseline');
    assert.equal(op.admissionFingerprint, digest);
    op.fullTopology.links[0].tunnelPort--;
    // Correct desired drift, then admit the ordinary selected successor using
    // the same transaction boundary as the public intent consumer.
    portal.ip = '192.0.2.3'; f.CascadeLink.rows[0].tunnelPort--;
    const { linkDesiredVersion } = require('../services/topologyIntentService');
    const link = f.CascadeLink.rows.find(row => row._id === id(11));
    const desiredVersion = linkDesiredVersion(link);
    const resources = await f.coordinator.resolveIntentResourcesForQueue({ kind: 'link.apply', link, desiredVersion, session: selectedSession });
    const accepted = await f.coordinator.queueIntent({ session: selectedSession, executionContext: context, intentId: id(91),
        mutation: { kind: 'link.apply', linkId: link._id, desiredVersion }, expectedTopologyRevision: 8, resourceNodeIds: resources });
    const next = f.TopologyOperation.rows.find(row => row._id === accepted.operationId);
    assert.equal(next.kind, 'link.apply'); assert.equal(next.admissionScope, 'selected');
    await settle(next);
    const after = await fetch(base + '/api/files/first-full-subscription?format=xray-json');
    assert.equal(after.status, 200, await after.clone().text());
    const afterEndpoints = (await after.json()).flatMap(p => p.outbounds || []).flatMap(o => o.settings?.vnext || []);
    assert.ok(afterEndpoints.some(e => e.address === '192.0.2.3' && e.users.some(u => u.id === user.xrayUuid)));
});
test('ordinary unadmitted settlement preserves the unknown error audit for a real two-node TEST scope', async () => {
    const { fixture: runtimeFixture, TopologyIntentService } = require('./cascadeAnyOrderRuntimeFixture');
    const { linkDesiredVersion } = require('../services/topologyIntentService');
    const f = runtimeFixture({ roles: ['portal','bridge'] });
    const link = { _id: id(10), portalNode: id(1), bridgeNode: id(2), mode: 'reverse', active: true,
        status: 'pending', tunnelPort: 23451, tunnelSecurity: 'none', tunnelTransport: 'tcp' };
    f.data.CascadeLink.push(link);
    const resourceNodeIds = [id(1),id(2)];
    const service = new TopologyIntentService({ ...f.models, executionContext: context,
        resolveIntentResources: async () => resourceNodeIds,
        intentOperationAdmission: { db: f.models.TopologyOperation.db,
            queue: async () => { throw new Error('modeled local preparation failure BEFORE admission'); },
            inspectUnadmittedPreparation: async () => ({ status: 'valid', revision: 7, resourceNodeIds }) },
    });
    const accepted = await service.accept({ version: 2, kind: 'link.apply', expectedTopologyRevision: 7,
        requestKey: 'two-node-unadmitted-regression', linkId: id(10), desiredVersion: linkDesiredVersion(link) });
    await service.runOnce();
    assert.equal((await service.get(accepted.jobId)).errorCode, 'TOPOLOGY_INTENT_PREPARE_UNCERTAIN');
    const result = await service.settleUnadmittedPreparation({ jobId: accepted.jobId, expectedTopologyRevision: 7 });
    assert.equal(result.status, 'failed'); assert.equal(result.errorCode, 'TOPOLOGY_INTENT_PREPARE_FAILED');
    assert.equal(result.unadmittedPreparation.originalErrorCode, 'TOPOLOGY_INTENT_PREPARE_UNCERTAIN');
    assert.equal(result.unadmittedPreparation.observedCauseCode, 'VALID_PREFLIGHT_NO_ADMISSION');
    assert.equal(f.data.TopologyOperation.length, 0); assert.equal(f.calls.length, 0);
});
