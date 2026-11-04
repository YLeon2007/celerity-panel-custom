'use strict';
// Local persistence and network are explicitly MODELED. The actual repository,
// proof worker, published-profile source, client process orchestration and HTTP
// projection execute; this is not Xray, PPP traffic or rollout evidence.
process.env.PANEL_DOMAIN ||= 'panel.test.invalid';
process.env.ACME_EMAIL ||= 'admin@test.invalid';
process.env.ENCRYPTION_KEY ||= 'test-encryption-key-32-characters-long';
process.env.SESSION_SECRET ||= 'test-session-secret';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const { spawn } = require('node:child_process');
const express = require('express');
const { TopologyOperationRepository, selectedAdmissionFingerprint } = require('../repositories/topologyOperationRepository');
const { TopologyClientReadinessWorker } = require('../workers/topologyClientReadinessWorker');
const { TopologyClientProofExecutor } = require('../services/topologyClientProofExecutor');
const { TopologyPublishedProfileSource } = require('../services/topologyPublishedProfileSource');
const { TopologyClientProfileProbe } = require('../services/topologyClientProfileProbe');
const { createTopologySelectedPublicState } = require('../services/topologySelectedPublicState');
const { createCascadeTopologyDeployRouter } = require('../../../routes/cascadeTopologyDeploy');
test.after(() => require('../../../services/sshPoolService').closeAll());
const { linkDesiredVersion } = require('../services/topologyIntentService');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const id = n => n.toString(16).padStart(24, '0');
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const copy = v => v == null ? v : structuredClone(v);
const NOW = new Date('2026-11-04T12:00:00Z');
const UUID = '11111111-1111-4111-8111-111111111111';
function match(row, filter) {
    return Object.entries(filter).every(([key, value]) => {
        if (key === '$expr') return require('../domain/topologyOperationClaimBinding').matchesTopologyOperationClaimBinding(row, context);
        if (key === '$or') return value.some(f => match(row, f));
        if (key === '$and') return value.every(f => match(row, f));
        if (key === '$nor') return !value.some(f => match(row, f));
        const actual = key.split('.').reduce((v, k) => v?.[k], row);
        if (value && typeof value === 'object' && !(value instanceof Date) && !Array.isArray(value)
            && Object.keys(value).some(k => k.startsWith('$'))) return Object.entries(value).every(([op, v]) => {
            if (op === '$type') return Array.isArray(v) ? typeof actual === 'number' : typeof actual === v;
            if (op === '$regex') return new RegExp(v).test(actual);
            if (op === '$exists') return (actual !== undefined) === v;
            if (op === '$in') return v.includes(actual) || actual === undefined && v.includes(null);
            if (op === '$gte') return actual >= v;
            if (op === '$lt') return actual < v;
            if (op === '$lte') return actual <= v;
            if (op === '$gt') return actual > v;
            if (op === '$ne') return !same(actual, v);
            throw Error(`Unmodeled predicate ${op}`);
        });
        return value === null ? actual == null : same(actual, value);
    });
}
function model(rows) {
    const query = work => { const q = { select() { return q; }, session() { return q; }, sort() { return q; },
        lean: async () => copy(work()), then(a, b) { return q.lean().then(a, b); } }; return q; };
    return { async create() {}, find: filter => query(() => rows.filter(r => match(r, filter))),
        findOne: filter => query(() => rows.find(r => match(r, filter)) || null),
        findById: value => query(() => rows.find(r => String(r._id) === String(value)) || null),
        exists: filter => query(() => rows.some(r => match(r, filter)) ? { _id: id(90) } : null),
        findOneAndUpdate: (filter, update) => query(() => { const row = rows.find(r => match(r, filter)); if (!row) return null;
            apply(row, update); return row; }),
        async deleteOne() { assert.fail('proof never deletes persistence'); },
        async countDocuments(filter) { return rows.filter(row => match(row, filter)).length; },
        async updateOne(filter, update) { const row = rows.find(r => match(r, filter)); if (row) apply(row, update); return { matchedCount: row ? 1 : 0 }; },
    };
}
function apply(row, update) {
    Object.assign(row, copy(update.$set || {}));
    for (const [key, n] of Object.entries(update.$inc || {})) row[key] = (row[key] || 0) + n;
    for (const key of Object.keys(update.$unset || {})) delete row[key];
}
function fixture({ staged = false, blocked = false } = {}) {
    const calls = { clients: 0, curl: 0, ppp: 0, ssh: 0, profiles: 0 };
    const portal = { _id: id(1), name: 'Selected portal', type: 'xray', active: true, cascadeRole: 'portal', ip: '192.0.2.1', port: 443,
        xray: { transport: 'tcp', security: 'reality', realityPublicKey: 'public-key', realitySni: ['front.example'], realityShortIds: ['01234567'] } };
    const bridge = { _id: id(2), type: 'xray', active: true, cascadeRole: 'bridge', ip: '198.51.100.10', ssh: { username: 'fixture', password: 'private-ssh' } };
    if (staged) portal.cascadeRole = 'relay';
    const link = { _id: id(3), portalNode: portal._id, bridgeNode: bridge._id, tunnelPort: 23451, tunnelUuid: UUID, mode: 'reverse', active: true, status: 'deployed' };
    const nodes = [portal, bridge];
    const topology = { nodes: nodes.map(n => { const { _id, cascadeRole, ...rest } = copy(n); return { ...rest, id: _id, role: cascadeRole }; }),
        links: [{ id: link._id, source: portal._id, target: bridge._id, mode: 'reverse', tunnelPort: 23451, tunnelUuid: UUID, active: true }], groups: [] };
    const owners = nodes.map(n => ({ node: n._id, profile: n.cascadeRole === 'portal' ? 'xray-main' : 'xray-bridge',
        executionContext: context, owner: 'topology', generation: UUID, nodeIdentity: { machineId: '1'.repeat(32), sshHostKeySha256: '2'.repeat(64) },
        originalSnapshot: { configSha256: sha({}), unitSha256: sha('unit'), serviceActive: 'inactive', serviceEnabled: 'disabled' },
        adoptionReceipt: { toGeneration: UUID, proofId: UUID } }));
    // Minimal canonical no-op config fixture; this is not a deployment receipt.
    const { createHash } = require('node:crypto');
    const candidateFor = () => { const bytes = [...Buffer.from(`${JSON.stringify({ inbounds: [], outbounds: [], routing: { rules: [] } })}\n`)]; const hash = createHash('sha256').update(Buffer.from(bytes)).digest('hex');
        return { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1', bytes, sha256: hash }; };
    const op = { _id: id(4), executionContext: context, idempotencyKey: `topology:test:revision-7:host-${context.hostIdentity}:00000000-0000-0000-0000-000000000000`,
        topologyRevision: 7, priorDeployedRevision: 3, kind: blocked ? 'link.delete' : 'link.apply', linkId: link._id, linkIds: blocked ? [] : [link._id], ...(blocked ? {} : { staged }),
        status: 'succeeded', heldTopologyAdmission: false, admissionScope: 'selected', resourceNodeIds: nodes.map(n => n._id),
        baselineTopology: blocked ? topology : { nodes: [], links: [], groups: [] }, effectiveTopology: blocked ? { nodes: [], links: [], groups: [] } : topology,
        selectedOwnerPins: copy(owners), desiredVersion: linkDesiredVersion(link), routeState: blocked ? 'no_bridge_exit' : staged ? 'no_portal_input' : 'complete',
        ...(blocked ? { deleteJobId: id(40) } : {}),
        nodes: nodes.map(n => { const candidate = candidateFor(); return { node: n._id, nodeRef: n.cascadeRole === 'relay' ? 'relay-1' : n.cascadeRole,
            role: n.cascadeRole, targetProfile: n.cascadeRole === 'portal' ? 'xray-main' : 'xray-bridge', checks: [], state: 'committed', candidateHash: candidate.sha256, candidate }; }),
        clientReadiness: 'unverified', clientProofAttempts: 0, clientProofLeaseUntil: null, clientProofRetryAfter: null, clientProofLeaseOwner: '' };
    op.admissionFingerprint = selectedAdmissionFingerprint(op);
    owners.forEach(owner => Object.assign(owner, { lastSettledOperation: op._id, lastSettledRevision: 7, lastSettledGeneration: UUID }));
    const user = { userId: 'probe', enabled: true, xrayUuid: UUID, subscriptionToken: 'privateToken', nodes: [portal._id], groups: [] };
    const users = [user];
    const states = staged ? [{ _id: id(8), node: portal._id, desiredState: 'installed', status: 'installed', secretRevision: 2 }] : [];
    const pppUsers = staged ? [{ relayNode: portal._id, login: 'fixture-user', ip: '10.0.0.2', passwordEncrypted: 'private-ppp-ciphertext', enabled: true, desiredRevision: 2, appliedRevision: 2, syncStatus: 'synced', syncOperationId: id(9) }] : [];
    const links = blocked ? [] : [link];
    const models = { HyNode: model(nodes), CascadeLink: model(links), CascadeRouteGroup: model([]), RelayL2tpState: model(states),
        L2tpUser: model(pppUsers), TopologyConfigOwner: model(owners), TopologyOperation: model([op]), NodeOperationLock: model([]) };
    const source = new TopologyPublishedProfileSource({ HyUser: { findOne: () => ({ select() { return { lean: async () => copy(user) }; } }) }, probeUserId: 'probe',
        resolveAssignedUsers: async () => copy(users), fetchImpl: async () => { calls.profiles++;
            return { ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => JSON.stringify([{ remarks: portal.name,
                outbounds: [{ protocol: 'vless', tag: 'proxy', settings: { vnext: [{ address: portal.ip, port: 443, users: [{ id: user.xrayUuid, encryption: 'none' }] }] },
                    streamSettings: { network: 'tcp', security: 'reality', realitySettings: { publicKey: portal.xray.realityPublicKey, serverName: 'front.example', shortId: '01234567' } } }] }]) }; } });
    let afterCurl = () => {};
    const probe = new TopologyClientProfileProbe({ spawnClient: (_binary, args, opts) => { calls.clients++;
        return spawn(process.execPath, ['-e', `const fs=require('node:fs'),net=require('node:net');const c=JSON.parse(fs.readFileSync(process.argv[1]));net.createServer(s=>s.end()).listen(c.inbounds[0].port,'127.0.0.1');`, args[2]], opts); },
        runCurl: async () => { calls.curl++; await afterCurl(); return { stdout: '198.51.100.10\nPROBE_STATUS:200', stderr: '' }; } });
    const topologyRepository = { ...models, snapshotReader: { ...models },
        async readSelected() { return { baselineTopology: topology, effectiveTopology: topology, selectedOwnerPins: copy(owners), routeState: op.routeState }; } };
    const repository = new TopologyOperationRepository({ model: models.TopologyOperation, selectedTopologyRepository: topologyRepository });
    const executor = new TopologyClientProofExecutor({ ...models, NodeSSH: class { async connect() {} async exec() { calls.ssh++; return { code: 0, stdout: '198.51.100.10', stderr: '' }; } disconnect() {} },
        profileSource: source, profileProbe: probe, selectedTopologyRepository: topologyRepository,
        pppReadinessGate: { async verifyPlan() { calls.ppp++; return { ok: true, verifiedRelayCount: 1 }; } } });
    repository.clientProofExecutor = executor;
    let current = NOW;
    const worker = new TopologyClientReadinessWorker({ repository, probeOperation: op => executor.probeOperation(op), executionContext: context, owner: 'proof', now: () => current });
    const publicState = createTopologySelectedPublicState({ topologyRepository, operationRepository: repository, executionContext: context });
    return { op, nodes, owners, link, links, calls, user, users, states, pppUsers, models, executor, repository, worker, publicState,
        setAfterCurl(fn) { afterCurl = fn; }, setNow(value) { current = value; } };
}
function installModeledPppReadback(f) {
    const { TopologyPppReadinessGate } = require('../services/topologyPppReadinessGate');
    const operations = model([{ _id: id(9), node: f.nodes[0]._id, kind: 'sync_users', status: 'succeeded',
        plan: { operationId: id(9), relayId: f.nodes[0]._id, desired: { credentialRevision: 2 } } }]);
    f.executor.pppReadinessGate = new TopologyPppReadinessGate({ ...f.models, L2tpOperation: operations, readOnly: true,
        transportResolver: async () => ({ async verifyUsersReadOnly(expected) {
            f.calls.ppp++; assert.equal(expected.expectedCredentialRevision, 2);
            return { ok: true, code: 'USERS_VERIFIED', credentialRevision: 2, enabledUserCount: 1, managedUserCount: 1 };
        } }) });
}
async function route(f) {
    const app = express(), next = (req, res, next) => next();
    app.use(createCascadeTopologyDeployRouter({ models: f.models, readPublicOperation: f.publicState.readPublicOperation,
        requireAuth: next, requireScope: () => next, csrf: next, deployRateLimiter: next, operationStatusRateLimiter: next }));
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try { return await (await fetch(`http://127.0.0.1:${server.address().port}/operations/${f.op._id}`)).json(); }
    finally { await new Promise(resolve => server.close(resolve)); }
}
test('selected exact settled snapshot reaches claim → actual proof worker/client orchestration → completion → safe HTTP projection (modeled traffic)', async () => {
    const f = fixture();
    assert.equal(await f.worker.runOnce(), 'verified');
    assert.equal(f.calls.clients, 1); assert.equal(f.calls.curl, 1);
    const http = await route(f);
    assert.equal(http.status, 'succeeded');
    assert.equal(http.clientReadiness, 'verified');
    const publicOperation = await f.publicState.readPublicOperation(f.op._id);
    assert.equal(publicOperation.xrayReadiness, 'verified');
    assert.equal(publicOperation.pppReadiness, 'not_applicable');
    assert.equal(publicOperation.clientReadiness, 'verified');
    const text = JSON.stringify(publicOperation);
    for (const privateField of ['privateToken', UUID, 'effectiveTopology', 'selectedOwnerPins', 'candidate', 'private-ssh']) assert.equal(text.includes(privateField), false);
    assert.equal((await f.repository.findPublicById(f.op._id)).clientReadiness, 'verified');
});

test('a successful configured-user probe does not verify other assigned Xray users', async () => {
    const f = fixture();
    f.users.push({ userId: 'existing-user', xrayUuid: '22222222-2222-4222-8222-222222222222', enabled: true, nodes: [f.nodes[0]._id] });
    assert.equal(await f.worker.runOnce(), 'verified');
    const state = await f.publicState.readPublicOperation(f.op._id);
    assert.equal(state.xrayReadiness, 'unverified');
    assert.equal(state.clientReadiness, 'unverified');
    assert.equal(state.xrayInternetProof, 'verified');
    assert.equal((await route(f)).clientReadiness, 'unverified');
});

test('unrelated panel revision and saved neighbour edits do not stale exact selected proof', async () => {
    const f = fixture();
    let globalReads = 0;
    f.repository.topologyStateModel = { findById() { globalReads++; throw Error('global revision is unrelated'); } };
    const neighbour = { ...copy(f.link), _id: id(30), status: 'pending', tunnelPort: 24000 };
    f.links.push(neighbour);
    f.setAfterCurl(() => { neighbour.tunnelPort++; });
    assert.equal(await f.worker.runOnce(), 'verified');
    assert.equal(globalReads, 0);
    neighbour.tunnelUuid = 'saved-but-unapplied';
    assert.equal((await route(f)).clientReadiness, 'verified');
});

for (const [label, mutate] of [
    ['settled owner', f => { f.owners[0].lastSettledOperation = id(99); }],
    ['profile owner', f => { f.owners[0].profile = 'xray-bridge'; }],
    ['original config', f => { f.owners[0].originalSnapshot.configSha256 = 'f'.repeat(64); }],
    ['adoption receipt', f => { f.owners[0].adoptionReceipt.proofId = 'changed'; }],
    ['physical identity', f => { f.owners[0].nodeIdentity.machineId = 'changed'; }],
    ['requested content', f => { f.link.tunnelPort++; }],
    ['frozen config', f => { f.op.nodes[0].candidate.bytes[0]++; }],
    ['configuration metadata', f => { f.nodes[0].port++; }],
    ['probe credential', f => { f.user.xrayUuid = '22222222-2222-4222-8222-222222222222'; }],
    ['subscription credential', f => { f.user.subscriptionToken = 'replacedToken'; }],
    ['probe assignment', f => { f.users.splice(0); }],
    ['another assigned user', f => { f.users.push({ userId: 'other', xrayUuid: '22222222-2222-4222-8222-222222222222', enabled: true }); }],
]) test(`${label} drift invalidates a completed selected client proof`, async () => {
    const f = fixture();
    assert.equal(await f.worker.runOnce(), 'verified');
    mutate(f);
    assert.equal((await route(f)).clientReadiness, 'unverified');
    assert.equal((await f.repository.findPublicById(f.op._id)).clientReadiness, 'unverified');
});

test('credential mutation during actual client request cannot publish a late successful probe', async () => {
    const f = fixture(); f.setAfterCurl(() => { f.user.subscriptionToken = 'changedDuringProbe'; });
    assert.equal(await f.worker.runOnce(), 'unverified');
    assert.equal(f.calls.clients, 1); assert.equal(f.calls.curl, 1);
    assert.equal(f.op.clientProofCredentialDigest, undefined);
    assert.equal((await route(f)).clientReadiness, 'unverified');
});

test('staged source-less installed PPP is checked, but node readback never becomes PPP Internet proof', async () => {
    const f = fixture({ staged: true });
    installModeledPppReadback(f);
    assert.equal(await f.worker.runOnce(), 'unverified');
    assert.equal(f.calls.ppp, 1); assert.equal(f.calls.clients, 0);
    const state = await f.publicState.readPublicOperation(f.op._id);
    assert.equal(state.routeState, 'no_portal_input');
    assert.equal(state.xrayReadiness, 'not_applicable');
    assert.equal(state.pppReadiness, 'unverified'); assert.equal(state.pppInternetProof, 'unverified');
    f.states[0].secretRevision++;
    assert.equal((await route(f)).clientReadiness, 'unverified');
});

test('last-exit deletion is applied but Internet proof is not applicable, even with mutable verified flag', async () => {
    const f = fixture({ blocked: true });
    f.op.clientReadiness = 'verified'; f.op.clientProofRevision = 7;
    assert.equal(await f.worker.runOnce(), null);
    const state = await f.publicState.readPublicOperation(f.op._id);
    assert.equal(state.applicationState, 'applied'); assert.equal(state.routeState, 'no_bridge_exit');
    assert.equal(state.clientReadiness, 'unverified');
    assert.equal(state.xrayReadiness, 'not_applicable'); assert.equal(state.pppInternetProof, 'not_applicable');
    assert.equal(f.calls.clients + f.calls.ssh + f.calls.ppp, 0);
});

test('expired claim cannot complete after another generation reclaims selected proof', async () => {
    const f = fixture();
    const old = await f.repository.claimNextClientProof({ owner: 'old', now: NOW, leaseMs: 1000, executionContext: context });
    const later = new Date(NOW.getTime() + 1001);
    const next = await f.repository.claimNextClientProof({ owner: 'new', now: later, leaseMs: 1000, executionContext: context });
    assert.equal(next.clientProofAttempts, 2);
    assert.equal(await f.repository.completeClientProof({ operation: old, owner: 'old', now: later,
        executionContext: context, passed: true }), null);
    assert.equal(f.op.clientReadiness, 'unverified');
});

test('PPP epoch and node user readback stay separate from Xray-profile probe orchestration (modeled network)', async () => {
    const f = fixture({ staged: true });
    const relay = f.nodes[0];
    const portal = { ...copy(relay), _id: id(5), cascadeRole: 'portal' };
    f.nodes.push(portal); f.user.nodes = [portal._id];
    f.op.effectiveTopology.nodes.push({ ...copy(f.op.effectiveTopology.nodes[0]), id: portal._id, role: 'portal' });
    f.op.effectiveTopology.links.push({ id: id(6), source: portal._id, target: relay._id, mode: 'reverse', tunnelPort: 24001, active: true });
    f.op.linkIds.push(id(6)); f.op.resourceNodeIds.push(portal._id);
    f.op.nodes.push({ ...copy(f.op.nodes[0]), node: portal._id, nodeRef: 'portal', role: 'portal', targetProfile: 'xray-main' });
    const pin = { ...copy(f.op.selectedOwnerPins[0]), node: portal._id, profile: 'xray-main' };
    f.op.selectedOwnerPins.push(pin);
    f.owners.push({ ...copy(f.owners[0]), node: portal._id, profile: 'xray-main' });
    f.op.routeState = 'complete'; f.op.staged = false;
    f.op.effectiveTopology.groups.push({ _id: id(10), paths: [{ pathKey: 'main', enabled: true, linkIds: [f.link._id] }] });
    Object.assign(f.states[0], { routeGroup: id(10), activePathKey: 'main', appliedTopologyRevision: 7 });
    f.op.admissionFingerprint = selectedAdmissionFingerprint(f.op);
    installModeledPppReadback(f);
    assert.equal(await f.worker.runOnce(), 'verified');
    assert.equal(f.calls.ppp, 1); assert.equal(f.calls.curl, 1);
    const publicState = await f.publicState.readPublicOperation(f.op._id);
    assert.equal(publicState.xrayReadiness, 'verified');
    assert.equal(publicState.pppReadiness, 'unverified'); assert.equal(publicState.pppInternetProof, 'unverified');
    assert.equal(publicState.clientReadiness, 'unverified');
    assert.equal((await f.repository.findPublicById(f.op._id)).clientReadiness, 'unverified');
    assert.equal(JSON.stringify(publicState).includes('private-ppp-ciphertext'), false);
    f.states[0].secretRevision++;
    assert.equal((await f.publicState.readPublicOperation(f.op._id)).xrayReadiness, 'unverified');
    f.states[0].secretRevision--;
    f.pppUsers[0].passwordEncrypted = 'replaced-private-ciphertext';
    assert.equal((await f.publicState.readPublicOperation(f.op._id)).xrayReadiness, 'unverified');
});

test('default host shares the real selected repository with its scheduled proof worker and public reader', async () => {
    const f = fixture();
    const { createL2tpPanelHost } = require('../../createL2tpPanelHost');
    const moduleEntry = require('..');
    const db = { transaction: async () => assert.fail('proof must not run topology mutation transactions') };
    for (const name of ['TopologyCreateIntent', 'TopologyIntentQueueState', 'CascadeTopologyState', 'L2tpOperation', 'RemoteAdmission', 'TopologyExecutionBinding', 'TopologyExecutionEnrollment']) f.models[name] = model([]);
    Object.values(f.models).forEach(m => { m.db = db; }); db.models = f.models;
    let deployment, recovery;
    const noop = async () => ({ ok: true });
    const host = createL2tpPanelHost({ env: { PANEL_DOMAIN: context.hostIdentity, L2TP_EXECUTION_ENABLED: 'true',
        L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true', TOPOLOGY_PROBE_USER_ID: 'probe' },
        HyNode: f.models.HyNode, CascadeLink: f.models.CascadeLink, NodeSSH: f.executor.NodeSSH,
        moduleEntry: { ...moduleEntry, registerModels: () => f.models,
            createTopologyDeploymentService(options) { deployment = moduleEntry.createTopologyDeploymentService(options); return deployment; } },
        createTopologyOperationExecutor: () => ({ prepare: noop, commit: noop, verify: noop, rollback: noop, cleanupPrepared: noop }),
        Repository: class {}, createRepositoryAdapters: () => ({ nodeRepository: {}, stateRepository: {}, operationRepository: {} }),
        createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime: () => ({ runtime: { stateManagementService: {}, simpleService: {} }, start() {}, async stop() {} }),
        createTopologyRecoveryLifecycle(options) { recovery = options; return { start() {}, async stop() {} }; },
        clock: { now: () => NOW } });
    try {
        const repository = deployment.operationWorker.operationRepository;
        assert.ok(recovery.clientProofWorker.repository === repository);
        assert.ok(repository.clientProofExecutor.selectedTopologyRepository === deployment.operationWorker.selectedTopologyRepository);
        // Only the external subscription/user and process/network edges are modeled.
        repository.clientProofExecutor.profileSource = f.executor.profileSource;
        repository.clientProofExecutor.profileProbe = f.executor.profileProbe;
        assert.equal(await recovery.clientProofWorker.runOnce(), 'verified');
        assert.equal((await host.readPublicOperation(f.op._id)).clientReadiness, 'verified');
        assert.equal(f.calls.curl, 1);
    } finally { await host.stop(); }
});

test('private proof pins survive the actual operation schema without adopting legacy verified flags', async () => {
    const f = fixture();
    assert.equal(await f.worker.runOnce(), 'verified');
    const Operation = require('../models/topologyOperationModel');
    const document = new Operation(f.op);
    await document.validate();
    const roundTrip = new Operation(document.toObject());
    assert.equal(roundTrip.clientProofFingerprint, f.op.admissionFingerprint);
    assert.equal(roundTrip.clientProofCredentialDigest, f.op.clientProofCredentialDigest);
    assert.equal(Operation.schema.path('clientProofFingerprint').options.select, false);
    assert.equal(Operation.schema.path('clientProofCredentialDigest').options.select, false);
    const legacy = new Operation({ status: 'succeeded', topologyRevision: 7, priorDeployedRevision: 3 });
    assert.equal(legacy.clientProofFingerprint, undefined);
    assert.equal(legacy.clientProofCredentialDigest, undefined);
});

test('selected completion rechecks lease time after the awaited credential/owner snapshot', async () => {
    const f = fixture();
    const claim = await f.repository.claimNextClientProof({ owner: 'proof', now: NOW, executionContext: context });
    const proof = await f.executor.probeOperation(claim);
    const original = f.executor.readSelectedSnapshot.bind(f.executor);
    let current = NOW;
    f.executor.readSelectedSnapshot = async operation => { const result = await original(operation); current = new Date(NOW.getTime() + 120000); return result; };
    assert.equal(await f.repository.completeClientProof({ operation: claim, owner: 'proof', now: NOW,
        getNow: () => current, executionContext: context, passed: true, proof }), null);
    assert.equal(f.op.clientReadiness, 'unverified');
});

test('a passed bit without the successful selected executor evidence cannot publish proof', async () => {
    const f = fixture();
    const claim = await f.repository.claimNextClientProof({ owner: 'proof', now: NOW, executionContext: context });
    assert.equal(await f.repository.completeClientProof({ operation: claim, owner: 'proof', now: NOW,
        executionContext: context, passed: true }), 'unverified');
    f.op.clientReadiness = 'verified'; f.op.clientProofRevision = 7;
    assert.equal((await route(f)).clientReadiness, 'unverified');
});
