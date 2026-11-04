'use strict';
// Real default host/module/runtime, HTTP routes, v2 queue, coordinator,
// materializer, worker and finalizer. DB transactions and executor are MODELED;
// this is not Mongo atomicity, deployed Xray/SSH or client traffic evidence.
process.env.PANEL_DOMAIN ||= 'panel.test.invalid';
process.env.ACME_EMAIL ||= 'admin@test.invalid';
process.env.ENCRYPTION_KEY ||= 'test-encryption-key-32-characters-long';
process.env.SESSION_SECRET ||= 'test-session-secret';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const express = require('express');
const LinkSchema = require('../../../models/cascadeLinkModel');
const IntentSchema = require('../models/topologyCreateIntentModel');
const moduleEntry = require('..');
const { createL2tpPanelHost } = require('../../createL2tpPanelHost');
const { l2tpActiveHostProvider: provider } = require('../../l2tpActiveHostProvider');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const { createCascadeLinksRouter } = require('../../../routes/cascadeLinks');
const { createCascadeTopologyDeployRouter } = require('../../../routes/cascadeTopologyDeploy');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
const { TopologyDraftWriteService } = require('../services/topologyDraftWriteService');
const { TopologyIntentService } = require('../services/topologyIntentService');
const id = n => n.toString(16).padStart(24, '0');
const sha = s => createHash('sha256').update(s).digest('hex');
const copy = value => value === undefined ? undefined : structuredClone(value);
const env = Object.freeze({ PANEL_DOMAIN: context.hostIdentity, L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' });
test.after(() => require('../../../services/sshPoolService').closeAll());
function get(row, key) {
    const walk = (value, parts) => !parts.length ? value : Array.isArray(value)
        ? value.flatMap(child => walk(child, parts)) : walk(value?.[parts[0]], parts.slice(1));
    return walk(row, key.split('.'));
}
function matches(row, filter) {
    return Object.entries(filter).every(([key, value]) => {
        if (key === '$or') return value.some(f => matches(row, f));
        if (key === '$and') return value.every(f => matches(row, f));
        if (key === '$nor') return value.every(f => !matches(row, f));
        if (key === '$expr') return require('../domain/topologyOperationClaimBinding').matchesTopologyOperationClaimBinding(row, context);
        const actual = get(row, key);
        if (value && typeof value === 'object' && !(value instanceof Date) && !Array.isArray(value)
            && Object.keys(value).some(k => k.startsWith('$'))) return Object.entries(value).every(([op, v]) => {
            if (op === '$exists') return (actual !== undefined) === v;
            if (op === '$type') return typeof actual === 'number';
            if (op === '$size') return actual?.length === v;
            if (op === '$in') return actual === undefined && v.includes(null)
                || (Array.isArray(actual) ? actual.some(x => v.includes(x)) : v.includes(actual));
            if (op === '$nin') return Array.isArray(actual) ? actual.every(x => !v.includes(x)) : !v.includes(actual);
            if (op === '$gt') return actual > v;
            if (op === '$gte') return actual >= v;
            if (op === '$lt') return actual < v;
            if (op === '$lte') return actual <= v;
            if (op === '$eq') return same(actual, v);
            if (op === '$ne') return !same(actual, v);
            throw Error(`Unsupported modeled DB predicate ${op}`);
        });
        return same(actual, value) || (Array.isArray(actual) && actual.includes(value));
    });
}
function fixture() {
    let depth = 0;
    const calls = [], sessions = [], errors = [], deployments = [];
    const db = { async transaction(work) {
        const session = { inTransaction: () => depth > 0 };
        sessions.push(session); depth++;
        try { return await work(session); } finally { depth--; }
    } };
    const data = {
        HyNode: ['portal', 'relay', 'bridge', 'portal', 'bridge'].map((cascadeRole, i) => ({
            _id: id(i + 1), cascadeRole, type: 'xray', active: true,
            ip: `192.0.2.${i + 1}`, port: 443, xray: { security: 'none', transport: 'tcp' } })),
        CascadeLink: [], CascadeRouteGroup: [], RelayL2tpState: [], L2tpUser: [], L2tpOperation: [],
        CascadeTopologyState: [{ _id: 'singleton', revision: 7, deployedRevision: 3,
            remoteAdmissionCount: 0, topologyAdmissionCount: 0 }],
        TopologyOperation: [], NodeOperationLock: [], RemoteAdmission: [],
        TopologyCreateIntent: [], TopologyIntentQueueState: [], TopologyExecutionBinding: [], TopologyExecutionEnrollment: [],
    };
    data.TopologyConfigOwner = data.HyNode.map((node, i) => ({ node: node._id,
        profile: node.cascadeRole === 'portal' ? 'xray-main' : 'xray-bridge',
        executionContext: context, owner: 'topology', generation: '11111111-1111-4111-8111-111111111111',
        nodeIdentity: { machineId: String(i + 1).repeat(32), sshHostKeySha256: String(i + 1).repeat(64) },
        originalSnapshot: { configSha256: sha('{}'), unitSha256: sha('unit'), serviceActive: 'inactive', serviceEnabled: 'disabled' },
        adoptionReceipt: { toGeneration: '11111111-1111-4111-8111-111111111111', proofId: '22222222-2222-4222-8222-222222222222',
            maintenanceId: '33333333-3333-4333-8333-333333333333', verifiedAt: new Date() } }));
    function model(name) {
        function Model(input) { return new (name === 'CascadeLink' ? LinkSchema : IntentSchema)(input); }
        const rows = data[name];
        function query(work) {
            let sort, limit;
            const q = { select() { return q; }, session() { return q; }, populate() { return q; }, setOptions() { return q; },
                read() { return q; }, readConcern() { return q; }, maxTimeMS() { return q; },
                sort(value) { sort = value; return q; }, limit(value) { limit = value; return q; },
                async lean() { let result = work();
                    if (Array.isArray(result)) { result = [...result]; if (sort) result.sort((a, b) => {
                        for (const [key, dir] of Object.entries(sort)) { if (get(a, key) < get(b, key)) return -dir;
                            if (get(a, key) > get(b, key)) return dir; } return 0; });
                        if (limit) result = result.slice(0, limit); }
                    return copy(result);
                }, then(a, b) { return q.lean().then(a, b); } };
            return q;
        }
        function update(row, changes, filter) {
            for (const [key, value] of Object.entries(changes.$set || {})) {
                if (key.startsWith('nodes.$.')) row.nodes.find(n => n.node === filter['nodes.node'])[key.slice(8)] = copy(value);
                else row[key] = copy(value);
            }
            for (const [key, value] of Object.entries(changes.$inc || {})) row[key] = (row[key] || 0) + value;
            for (const key of Object.keys(changes.$unset || {})) delete row[key];
        }
        Object.assign(Model, { db, rows,
            find: f => query(() => rows.filter(r => matches(r, f))),
            findOne: f => query(() => rows.find(r => matches(r, f)) || null),
            findById: k => query(() => rows.find(r => String(r._id) === String(k)) || null),
            exists: f => query(() => rows.find(r => matches(r, f)) ? { _id: 'exists' } : null),
            countDocuments: f => query(() => rows.filter(r => matches(r, f)).length),
            async create(docs, options = {}) {
                if (name !== 'NodeOperationLock') assert.ok(options.session?.inTransaction(), `${name} create joins an active transaction`);
                const many = Array.isArray(docs);
                const result = (many ? docs : [docs]).map(doc => name === 'CascadeLink' ? JSON.parse(JSON.stringify(new LinkSchema(doc).toObject()))
                    : { ...copy(doc), ...(doc._id == null ? {} : { _id: String(doc._id) }) });
                for (const row of result) { if (row.node && rows.some(r => r.node === row.node)) throw Object.assign(Error('duplicate'), { code: 11000 }); rows.push(row); }
                return copy(many ? result : result[0]);
            },
            findOneAndUpdate: (f, u) => query(() => { const row = rows.find(r => matches(r, f)); if (row) update(row, u, f); return row || null; }),
            async updateOne(f, u) { const row = rows.find(r => matches(r, f)); if (row) update(row, u, f); return { matchedCount: row ? 1 : 0 }; },
            async updateMany(f, u) { const selected = rows.filter(r => matches(r, f)); selected.forEach(r => update(r, u, f)); return { matchedCount: selected.length }; },
            async deleteOne(f) { const index = rows.findIndex(r => matches(r, f)); if (index >= 0) rows.splice(index, 1); return { deletedCount: index >= 0 ? 1 : 0 }; },
        });
        return Model;
    }
    const models = Object.fromEntries(Object.keys(data).map(name => [name, model(name)]));
    models.CascadeLink.createDeleteIntentWriter = LinkSchema.createDeleteIntentWriter;
    db.models = models;
    let pause;
    const executor = { async prepare(input) {
        assert.equal(depth, 0, 'remote executor never runs in HTTP/admission transaction');
        if (pause) await pause();
        calls.push(['prepare', input.node]); return { backupId: 'modeled-backup', prepared: {} };
    }, async commit(input) { assert.equal(depth, 0); calls.push(['commit', input.node]); return { ok: true }; },
    verify: async () => ({ ok: true }), cleanupPrepared: async () => ({ ok: true }), rollback: async () => ({ ok: true }) };
    const timer = { callbacks: new Set(), setInterval(fn) { this.callbacks.add(fn); return fn; }, clearInterval(fn) { this.callbacks.delete(fn); },
        async tick() { for (const fn of this.callbacks) await fn(); } };
    function host(overrides = {}) {
        return createL2tpPanelHost({ env, ...models, NodeSSH: class { constructor() { assert.fail('no real SSH'); } },
            moduleEntry: { ...moduleEntry, registerModels: () => models,
                createTopologyDeploymentService(options) {
                    const service = moduleEntry.createTopologyDeploymentService(options);
                    deployments.push(service);
                    // Model only the subscription DB/RPC edge of the REAL resync.
                    service.operationWorker.userResync._syncService = {
                        _getUsersForNode: async () => [], addXrayUser: async () => {},
                    };
                    return service;
                } },
            createTopologyOperationExecutor: () => executor,
            // Keep actual L2TP runtime dormant; topology lifecycle is real and uses this finite test timer.
            requireAuth: (req, res, next) => next(), requireOnboarding: (req, res, next) => next(),
            csrf: (req, res, next) => next(), rateLimiter: (req, res, next) => next(), renderPage() {},
            workerLifecycle: { enabled: false, timer, intervalMs: 30000, logger: { error: (...args) => errors.push(args) } },
            ...overrides,
        });
    }
    return { models, data, calls, errors, sessions, host, timer, deployments, setPause(fn) { pause = fn; } };
}
function app(f) {
    const app = express(); app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    const draft = new TopologyDraftWriteService({ repository: new TopologyDraftRepository(f.models) });
    app.use('/links', createCascadeLinksRouter({ Link: f.models.CascadeLink, Node: f.models.HyNode,
        TopologyState: f.models.CascadeTopologyState, ClientProofOperation: f.models.TopologyOperation,
        topologyDraftWriteService: draft, deploymentEnv: env,
        maintainAutoL2tpPathsFn: async () => {}, invalidateSubscriptions: async () => {}, invalidateTopology: async () => {} }));
    const next = (req, res, next) => next();
    app.use('/topology', createCascadeTopologyDeployRouter({ models: f.models, deploymentEnv: env,
        requireAuth: next, requireScope: () => next, csrf: next, deployRateLimiter: next, operationStatusRateLimiter: next }));
    return app;
}
async function request(app, method, path, body, key = 'runtime-key') {
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
            method, headers: { 'content-type': 'application/json', 'idempotency-key': key },
            ...(method === 'GET' ? {} : { body: JSON.stringify(body) }),
        });
        return { status: response.status, body: await response.json() };
    } finally { await new Promise(resolve => server.close(resolve)); }
}
const createBody = (revision = 7, extra = {}) => ({ expectedTopologyRevision: revision,
    name: 'runtime selected', portalNodeId: id(2), bridgeNodeId: id(3), tunnelPort: 23451,
    tunnelSecurity: 'none', autoDeploy: true, ...extra });
async function waitFor(predicate, diagnostic = () => '') {
    for (let i = 0; i < 200; i++) { if (predicate()) return; await new Promise(resolve => setImmediate(resolve)); }
    assert.fail(`modeled lifecycle did not reach expected state: ${diagnostic()}`);
}
test('default host publishes the SAME real selected service and DB-only joined runtime adapters', async () => {
    const f = fixture(), host = f.host();
    try {
        assert.ok(host.selectedTopologyIntentService instanceof TopologyIntentService, 'selected v2 HTTP service is missing from default host');
        assert.ok(host.selectedTopologyIntentService === host.topologyIntentService);
        const dependencies = host.selectedTopologyIntentService.dependencies;
        assert.ok(dependencies.intentDraftWriter.db === f.models.CascadeLink.db);
        assert.strictEqual(dependencies.intentDraftWriter, f.deployments[0].intentDraftWriter);
        assert.equal(typeof dependencies.intentDraftWriter.createLink, 'function');
        assert.equal(typeof dependencies.intentDraftWriter.updateLink, 'function');
        assert.ok(dependencies.intentOperationAdmission.db === f.models.CascadeLink.db);
        assert.equal(typeof dependencies.resolveIntentResources, 'function');
        assert.equal(typeof dependencies.deleteIntentWriter.markDeleting, 'function');
        assert.equal(typeof dependencies.prepareLink, 'function');
        assert.equal(dependencies.prepareIngress, undefined, 'no remote preparation callback inside legacy consumer transaction');
        assert.equal(typeof host.readPublicOperation, 'function');
        assert.equal(typeof host.readLinkApplicationState, 'function');
        assert.deepEqual(f.calls, []);
    } finally { await host.stop(); }
});

test('default-host PUT Auto forwards joined update capability and local REALITY preparation through restart and settlement', async () => {
    const f = fixture(); let host = f.host(); provider.installActiveHost(host);
    try {
        const saved = await request(app(f), 'POST', '/links', createBody(7, {
            portalNodeId: id(1), bridgeNodeId: id(3), autoDeploy: false }));
        assert.equal(saved.status, 201, JSON.stringify(saved.body));
        const linkId = saved.body.createdLinkId;
        const body = { expectedTopologyRevision: 8, autoDeploy: true, tunnelSecurity: 'reality',
            tunnelPort: 23457, realityPrivateKey: '', realityPublicKey: '', realityShortIds: [] };
        const accepted = await request(app(f), 'PUT', `/links/${linkId}`, body, 'runtime-put');
        assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
        assert.equal(f.data.CascadeTopologyState[0].revision, 9);
        assert.equal(f.data.TopologyCreateIntent.length, 1);
        assert.equal(f.data.TopologyOperation.length, 0);
        assert.deepEqual(f.calls, []);
        const frozen = copy(f.data.CascadeLink[0]);
        assert.match(frozen.realityPrivateKey, /^[A-Za-z0-9_-]{43}$/);
        assert.doesNotMatch(JSON.stringify(accepted.body), new RegExp(frozen.realityPrivateKey));
        await host.stop(); provider.clearActiveHost(host);
        host = f.host(); provider.installActiveHost(host);
        const replay = await request(app(f), 'PUT', `/links/${linkId}`, {
            ...body, expectedTopologyRevision: 0 }, 'runtime-put');
        assert.deepEqual(replay.body.job, accepted.body.job);
        assert.deepEqual(f.data.CascadeLink[0], frozen);
        host.start();
        await waitFor(() => f.data.TopologyOperation.some(op => ['succeeded', 'failed'].includes(op.status)) || f.errors.length);
        assert.deepEqual(f.errors, []);
        assert.equal(f.data.TopologyOperation[0].status, 'succeeded');
        await f.timer.tick();
        const job = await request(app(f), 'GET', `/links/auto-deploy-jobs/${accepted.body.job.jobId}`);
        assert.equal(job.body.job.status, 'succeeded', JSON.stringify(job.body));
        assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 0);
        assert.equal(f.data.NodeOperationLock.length, 0);
    } finally { provider.clearActiveHost(host); await host.stop(); }
});

test('loopback HTTP Auto create resumes durable v2 job after host restart through real worker/finalizer', async () => {
    const f = fixture();
    let host = f.host(); provider.installActiveHost(host);
    const body = createBody(7, { portalNodeId: id(1), bridgeNodeId: id(3) });
    try {
        assert.ok(provider.getActiveHost()?.selectedTopologyIntentService instanceof TopologyIntentService);
        const accepted = await request(app(f), 'POST', '/links', body);
        assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
        assert.equal(f.data.TopologyCreateIntent.length, 1);
        assert.equal(f.data.TopologyOperation.length, 0, 'HTTP accepts a job, never dispatches/binds a worker');
        assert.deepEqual(f.calls, []);
        const generated = copy(f.data.CascadeLink[0]);
        await host.stop(); provider.clearActiveHost(host);
        host = f.host(); provider.installActiveHost(host);
        const replay = await request(app(f), 'POST', '/links', { ...body, expectedTopologyRevision: 1 });
        assert.equal(replay.body.job.jobId, accepted.body.job.jobId);
        assert.deepEqual(f.data.CascadeLink[0], generated, 'replay precedes UUID/REALITY generation');
        host.start();
        await waitFor(() => f.data.TopologyOperation.some(op => ['succeeded', 'failed', 'rolled_back'].includes(op.status))
            || f.data.TopologyCreateIntent.some(job => ['blocked', 'failed'].includes(job.status)) || f.errors.length,
        () => JSON.stringify({ jobs: f.data.TopologyCreateIntent, ops: f.data.TopologyOperation.map(op => ({ status: op.status })), errors: f.errors }));
        assert.deepEqual(f.errors, []);
        assert.equal(f.data.TopologyOperation.length, 1, JSON.stringify(f.data.TopologyCreateIntent));
        const operation = f.data.TopologyOperation[0];
        assert.equal(operation.status, 'succeeded', JSON.stringify(operation));
        assert.equal(operation.admissionScope, 'selected');
        assert.equal(operation.linkId, accepted.body.linkId);
        assert.ok(f.calls.some(([phase]) => phase === 'commit'));
        assert.equal(operation.heldTopologyAdmission, false);
        assert.equal(f.data.NodeOperationLock.length, 0);
        assert.equal(f.data.CascadeTopologyState[0].topologyAdmissionCount, 0);
        assert.ok(f.data.TopologyConfigOwner.filter(row => [id(1), id(3)].includes(row.node))
            .every(row => row.lastSettledOperation === operation._id));
        await f.timer.tick();
        const job = await request(app(f), 'GET', `/links/auto-deploy-jobs/${accepted.body.job.jobId}`);
        assert.equal(job.body.job.status, 'succeeded', JSON.stringify(job.body));
        assert.equal(job.body.job.operationId, operation._id);
        assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 0);
        const polled = await request(app(f), 'GET', `/topology/operations/${operation._id}`);
        assert.equal(polled.status, 200);
        assert.equal(polled.body.kind, 'link.apply');
        assert.equal(polled.body.linkId, accepted.body.linkId);
        assert.equal(polled.body.clientReadiness, 'unverified');
        const projected = await host.readLinkApplicationState({ links: [{ linkId: operation.linkId, desiredVersion: operation.desiredVersion }] });
        assert.equal(projected[0]?.applicationState, 'applied');
        assert.equal(projected[0]?.routeState, 'complete');
        assert.equal(projected[0]?.xrayReadiness, 'unverified');
        assert.equal(f.data.CascadeTopologyState[0].deployedRevision, 3);
    } finally { provider.clearActiveHost(host); await host.stop(); }
});

async function settleTick(f) {
    await new Promise(resolve => setImmediate(resolve));
    await f.timer.tick();
    assert.deepEqual(f.errors, []);
}
test('source-less HTTP create and explicit manual Deploy exclude save-only neighbours across restart', async () => {
    const f = fixture();
    f.data.RelayL2tpState.push({ node: id(2), status: 'not_installed', desiredState: 'absent', secretRevision: 0 });
    let host = f.host(); provider.installActiveHost(host);
    try {
        const saved = await request(app(f), 'POST', '/links', createBody(7, {
            portalNodeId: id(1), bridgeNodeId: id(2), autoDeploy: false, tunnelPort: 23452,
        }), 'save-only');
        assert.equal(saved.status, 201, JSON.stringify(saved.body));
        assert.equal(f.data.TopologyCreateIntent.length, 0);
        const accepted = await request(app(f), 'POST', '/links', createBody(8), 'source-less');
        assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
        host.start(); await settleTick(f);
        let operation = f.data.TopologyOperation[0];
        assert.equal(operation.status, 'succeeded', JSON.stringify({ status: operation.status, jobs: f.data.TopologyCreateIntent }));
        assert.equal(operation.staged, true);
        assert.equal(operation.routeState, 'no_portal_input');
        assert.deepEqual(operation.effectiveTopology.links.map(link => link.id), [accepted.body.linkId]);
        assert.equal(f.data.CascadeLink.find(link => link._id === saved.body.createdLinkId).status, 'pending');
        await host.stop(); provider.clearActiveHost(host);
        host = f.host(); provider.installActiveHost(host); host.start(); await settleTick(f);
        assert.equal(f.data.TopologyOperation.length, 1, 'restart does not activate pending save-only');
        const manual = await request(app(f), 'POST', '/topology/deploy', {
            expectedTopologyRevision: 9, linkId: saved.body.createdLinkId,
        }, 'manual-selected');
        assert.equal(manual.status, 202, JSON.stringify(manual.body));
        assert.equal(manual.body.job.kind, 'link.apply');
        assert.equal(f.data.TopologyOperation.length, 1, 'request only accepts durable intent');
        await settleTick(f);
        operation = f.data.TopologyOperation[1];
        assert.equal(operation.status, 'succeeded', JSON.stringify({ status: operation?.status, jobs: f.data.TopologyCreateIntent }));
        assert.equal(operation.routeState, 'complete');
        assert.deepEqual(new Set(operation.effectiveTopology.links.map(link => link.id)),
            new Set([saved.body.createdLinkId, accepted.body.linkId]));
        await settleTick(f);
        assert.ok(f.data.TopologyCreateIntent.every(job => job.status === 'succeeded'));
        assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 0);
    } finally { provider.clearActiveHost(host); await host.stop(); }
});

test('trusted bridge REALITY defaults and actual generator run only after persisted-key replay', async () => {
    const f = fixture();
    Object.assign(f.data.HyNode[2].xray, { realityDest: 'fixture.example:443', realitySni: ['fixture.example'] });
    let reads = 0;
    const find = f.models.HyNode.findById;
    f.models.HyNode.findById = value => { reads++; return find(value); };
    const host = f.host(); provider.installActiveHost(host);
    try {
        const body = createBody(7, { portalNodeId: id(1), tunnelSecurity: 'reality' });
        const first = await request(app(f), 'POST', '/links', body, 'real-credentials');
        assert.equal(first.status, 202, JSON.stringify(first.body));
        const link = copy(f.data.CascadeLink[0]);
        assert.equal(link.realityDest, 'fixture.example:443');
        assert.deepEqual(link.realitySni, ['fixture.example']);
        assert.match(link.realityPrivateKey, /^[A-Za-z0-9_-]{43}$/);
        const before = reads;
        Object.assign(f.data.HyNode[2].xray, { realityDest: 'different.example:443' });
        const replay = await request(app(f), 'POST', '/links', { ...body, expectedTopologyRevision: 1 }, 'real-credentials');
        assert.equal(replay.status, 202);
        assert.equal(reads, before, 'even mutable target defaults are read only after replay');
        assert.deepEqual(f.data.CascadeLink[0], link);
        assert.equal(replay.body.job.jobId, first.body.job.jobId);
        assert.deepEqual(f.calls, []);
    } finally { provider.clearActiveHost(host); await host.stop(); }
});

async function appliedFixture() {
    const f = fixture(), host = f.host(); provider.installActiveHost(host);
    const accepted = await request(app(f), 'POST', '/links', createBody(7, { portalNodeId: id(1) }));
    assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
    host.start(); await settleTick(f);
    const operation = f.data.TopologyOperation[0];
    assert.equal(operation.status, 'succeeded');
    await settleTick(f);
    return { f, host, operation, input: { links: [{ linkId: operation.linkId, desiredVersion: operation.desiredVersion }] } };
}
test('public selected freshness ignores unrelated global drift, never upgrades unscheduled client proof and redacts private data', async () => {
    const { f, host, operation, input } = await appliedFixture();
    try {
        f.data.CascadeTopologyState[0].revision += 100;
        operation.clientReadiness = 'verified'; operation.clientProofRevision = operation.topologyRevision;
        operation.password = 'private-secret'; operation.error = { stack: 'private-stack' };
        const publicOperation = await host.readPublicOperation(operation._id);
        assert.equal(publicOperation.routeState, 'complete');
        const states = await host.readLinkApplicationState(input);
        assert.equal(publicOperation.applicationState, 'applied');
        assert.equal(publicOperation.clientReadiness, 'unverified');
        assert.equal(states[0]?.applicationState, 'applied');
        assert.equal(states[0]?.xrayReadiness, 'unverified');
        const json = JSON.stringify({ publicOperation, states });
        for (const secret of ['effectiveTopology', 'baselineTopology', 'selectedOwnerPins', 'nodeIdentity',
            'candidate', 'private-secret', 'private-stack', f.data.CascadeLink[0].tunnelUuid]) assert.equal(json.includes(secret), false, secret);
        const http = await request(app(f), 'GET', '/links');
        assert.equal(http.body.links[0].appliedOperationId, operation._id);
        assert.equal(http.body.links[0].routeState, 'complete');
        assert.equal(http.body.links[0].clientReadiness, undefined);
        const proofClaim = f.models.TopologyOperation.findOneAndUpdate;
        let filter;
        f.models.TopologyOperation.findOneAndUpdate = (f, u, o) => { filter = f; return proofClaim(f, u, o); };
        await f.deployments[0].operationWorker.operationRepository.claimNextClientProof({ owner: 'proof',
            now: new Date(), executionContext: context });
        assert.deepEqual(filter.admissionScope, { $in: [null, 'selected'] }, 'selected claims use explicit settled eligibility and private fingerprint pins');
    } finally { provider.clearActiveHost(host); await host.stop(); }
});

test('owner/profile/adoption/content drift cannot be validated by selected public projections', async t => {
    for (const [name, mutate] of [
        ['owner context', f => { f.data.TopologyConfigOwner[0].executionContext = { ...context, hostIdentity: 'foreign.invalid' }; }],
        ['profile', f => { f.data.TopologyConfigOwner[0].profile = 'xray-bridge'; }],
        ['physical owner', f => { f.data.TopologyConfigOwner[0].nodeIdentity.machineId = 'f'.repeat(32); }],
        ['original config', f => { f.data.TopologyConfigOwner[0].originalSnapshot.configSha256 = 'f'.repeat(64); }],
        ['adoption', f => { f.data.TopologyConfigOwner[0].adoptionReceipt.proofId = '33333333-3333-4333-8333-333333333333'; }],
        ['content', f => { f.data.CascadeLink[0].tunnelPort++; }],
        ['fingerprint', f => { f.data.TopologyOperation[0].effectiveTopology.links[0].tunnelPort++; }],
        ['route fingerprint', f => { f.data.TopologyOperation[0].routeState = 'no_portal_input'; }],
    ]) await t.test(name, async () => {
        const { f, host, operation, input } = await appliedFixture();
        try {
            mutate(f);
            assert.deepEqual(await host.readLinkApplicationState(input), []);
            const publicOperation = await host.readPublicOperation(operation._id);
            assert.equal(publicOperation.applicationState, 'reconcile_required');
            assert.equal(publicOperation.clientReadiness, 'unverified');
            assert.equal(publicOperation.routeState, undefined);
        } finally { provider.clearActiveHost(host); await host.stop(); }
    });
});

test('selected public failures distinguish retained admission from already released terminal work', async () => {
    const { host, operation } = await appliedFixture();
    try {
        for (const status of ['failed', 'rolled_back']) {
            operation.status = status; operation.heldTopologyAdmission = false;
            assert.equal((await host.readPublicOperation(operation._id)).applicationState, 'not_applied');
            operation.heldTopologyAdmission = true;
            assert.equal((await host.readPublicOperation(operation._id)).applicationState, 'reconcile_required');
        }
    } finally { provider.clearActiveHost(host); await host.stop(); }
});

for (const port of [23451, 23459]) test(`loopback DELETE drains its real job through worker cleanup and settlement, then recreates at ${port}`, async () => {
    const { f, host, operation } = await appliedFixture();
    try {
        const original = copy(f.data.CascadeLink[0]);
        const before = f.data.TopologyOperation.length;
        const result = await request(app(f), 'DELETE', `/links/${operation.linkId}`, {
            expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
        }, 'delete-through-worker');
        assert.equal(result.status, 202, JSON.stringify(result.body));
        assert.equal(result.body.job.kind, 'link.delete');
        const jobId = result.body.job.jobId;
        const tombstone = f.data.CascadeLink.find(link => link._id === operation.linkId);
        assert.equal(String(tombstone.lifecycle.deleteJobId), jobId);
        assert.equal(f.data.TopologyOperation.length, before, 'HTTP does not bind an operation or remove the row');
        const replay = await request(app(f), 'DELETE', `/links/${operation.linkId}`, {
            expectedTopologyRevision: 0,
        }, 'delete-through-worker');
        assert.equal(replay.status, 202, JSON.stringify(replay.body));
        assert.equal(replay.body.job.jobId, jobId);
        let readbacks = 0;
        f.deployments[0].operationWorker.executor.verify = async () => {
            assert.ok(f.data.CascadeLink.some(link => link._id === operation.linkId), 'retain tombstone through cleanup readback');
            readbacks++; return { ok: true };
        };
        await settleTick(f);
        const cleanup = f.data.TopologyOperation[before];
        assert.equal(cleanup?.kind, 'link.delete', JSON.stringify(f.data.TopologyCreateIntent));
        assert.equal(cleanup.status, 'succeeded', JSON.stringify(cleanup));
        assert.equal(cleanup.deleteJobId, jobId);
        assert.ok(readbacks > 0);
        assert.ok(cleanup.nodes.some(node => node.checks.some(check => check.expectedState === 'absent')),
            'actual combined composer supplies removed-listener checks');
        assert.equal(f.data.CascadeLink.some(link => link._id === operation.linkId), false);
        assert.equal(cleanup.heldTopologyAdmission, false);
        assert.equal(f.data.NodeOperationLock.length, 0);
        assert.equal(f.data.CascadeTopologyState[0].topologyAdmissionCount, 0);
        await settleTick(f);
        const job = await request(app(f), 'GET', `/links/auto-deploy-jobs/${jobId}`);
        assert.equal(job.body.job.status, 'succeeded', JSON.stringify(job.body));
        assert.equal(job.body.job.operationId, cleanup._id);
        assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 0);
        assert.deepEqual((await request(app(f), 'GET', '/links')).body.links, []);
        f.deployments[0].operationWorker.executor.verify = async () => ({ ok: true });
        const recreated = await request(app(f), 'POST', '/links', createBody(f.data.CascadeTopologyState[0].revision, {
            portalNodeId: original.portalNode, bridgeNodeId: original.bridgeNode, tunnelPort: port,
        }), `recreate-${port}`);
        assert.equal(recreated.status, 202, JSON.stringify(recreated.body));
        assert.notEqual(recreated.body.linkId, operation.linkId);
        await settleTick(f); await settleTick(f);
        const applied = f.data.TopologyOperation.at(-1);
        assert.equal(applied.kind, 'link.apply'); assert.equal(applied.status, 'succeeded');
        assert.equal(applied.linkId, recreated.body.linkId);
        assert.deepEqual(applied.effectiveTopology.links.map(link => link.id), [recreated.body.linkId]);
        assert.equal(f.data.CascadeLink[0].tunnelPort, port);
        assert.equal(f.data.NodeOperationLock.length, 0);
        assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 0);
    } finally { provider.clearActiveHost(host); await host.stop(); }
});

test('loopback DELETE with unknown cleanup retains tombstone and exact ownership instead of reporting removal', async () => {
    const { f, host, operation } = await appliedFixture();
    try {
        const result = await request(app(f), 'DELETE', `/links/${operation.linkId}`, {
            expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
        }, 'unknown-delete');
        assert.equal(result.status, 202, JSON.stringify(result.body));
        f.setPause(async () => { throw new Error('modeled cleanup outcome unknown'); });
        await settleTick(f); await settleTick(f);
        const cleanup = f.data.TopologyOperation.at(-1);
        assert.equal(cleanup.kind, 'link.delete');
        assert.equal(cleanup.heldTopologyAdmission, true);
        assert.equal(f.data.CascadeLink[0].lifecycle.state, 'deleting');
        assert.equal(String(f.data.CascadeLink[0].lifecycle.deleteJobId), result.body.job.jobId);
        assert.ok(f.data.NodeOperationLock.every(lock => lock.operationId === cleanup._id));
        assert.ok(f.data.NodeOperationLock.length > 0);
        assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 1);
        const job = await request(app(f), 'GET', `/links/auto-deploy-jobs/${result.body.job.jobId}`);
        assert.notEqual(job.body.job.status, 'succeeded');
        const manual = await request(app(f), 'POST', '/topology/deploy', {
            expectedTopologyRevision: f.data.CascadeTopologyState[0].revision, linkId: operation.linkId,
        }, 'cannot-bypass-delete');
        assert.equal(manual.status, 409, JSON.stringify(manual.body));
        assert.equal(f.data.TopologyOperation.length, 2);
    } finally { provider.clearActiveHost(host); await host.stop(); }
});

test('active default composition injects both REAL installed gates and forwards the worker preparation callback without invoking it', async () => {
    const f = fixture();
    let preparation, deployment;
    const deny = () => assert.fail('composition must never dispatch, prepare, install or probe');
    f.models.CascadeTopologyState.db.startSession = deny;
    const host = f.host({
        workerLifecycle: { enabled: true, timer: f.timer }, NodeTransport: class {},
        createPreflightRunner: () => deny, createCandidateService: () => ({ buildCandidate: deny }),
        candidateNodeResolver: deny, candidateUserResolver: deny, configGenerator: deny, fragmentProvider: deny,
        operationMaterializer: deny, createUserSnapshotResolver: () => deny,
        createUserSyncReconciler: () => ({ finalizeVerifiedSync: deny }),
        secretBox: { encrypt: deny, decrypt: deny }, secretKey: 'modeled-secret-key',
        moduleEntry: { ...moduleEntry, registerModels: () => f.models,
            createTopologyDeploymentService(options) {
                preparation = options.installedIngressPreparer;
                deployment = moduleEntry.createTopologyDeploymentService(options);
                return deployment;
            } },
    });
    try {
        const { TopologyAttachIngressGate } = require('../services/topologyAttachIngressGate');
        const { L2tpSimpleService } = require('../services/l2tpSimpleService');
        const simple = host.runtime.simpleService;
        assert.ok(simple instanceof L2tpSimpleService);
        assert.ok(simple.topologyIngressGate instanceof TopologyAttachIngressGate);
        assert.ok(simple.topologyIngressGate === deployment.attachIngressGate);
        assert.ok(simple.topologyPppReadinessGate === deployment.installedPppReadinessGate);
        assert.equal(typeof simple.topologyPppReadinessGate.verifyPlan, 'function');
        const plan = Object.freeze({ kind: 'invalid-installed-plan' });
        await assert.rejects(preparation({ operationPlan: plan }), { code: 'INVALID_INGRESS_OPERATION' });
        assert.deepEqual(f.calls, []);
        assert.equal(f.data.TopologyOperation.length, 0);
    } finally { await host.stop(); }
});
