'use strict';
// Actual HTTP + real intent/draft services. Persistence is transaction-shaped
// local state, NOT Mongo rollback/ownership or remote deployment evidence.
process.env.PANEL_DOMAIN ||= 'panel.test.invalid';
process.env.ACME_EMAIL ||= 'admin@test.invalid';
process.env.ENCRYPTION_KEY ||= 'test-encryption-key-32-characters-long';
process.env.SESSION_SECRET ||= 'test-session-secret';
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const express = require('express');
const LinkModel = require('../../../models/cascadeLinkModel');
const { TopologyIntentService } = require('../services/topologyIntentService');
const { createCascadeLinksRouter } = require('../../../routes/cascadeLinks');
const { createCascadeTopologyDeployRouter } = require('../../../routes/cascadeTopologyDeploy');
const sshPool = require('../../../services/sshPoolService');
test.after(() => sshPool.closeAll());
const context = Object.freeze({ target: 'test', hostIdentity: 'test.infograd.online' });
const ids = Array.from({ length: 8 }, (_, i) => `507f1f77bcf86cd7994390${String(i).padStart(2, '0')}`);
const copy = value => value === undefined ? undefined : structuredClone(value);
function equal(a, b) { return String(a) === String(b); }
function matches(row, filter) {
    return Object.entries(filter).every(([key, value]) => {
        if (key === '$or') return value.some(part => matches(row, part));
        const actual = key.split('.').reduce((v, part) => v?.[part], row);
        if (value && typeof value === 'object' && !(value instanceof Date)) {
            return Object.entries(value).every(([op, expected]) => {
                if (op === '$in') return expected.some(v => equal(actual, v));
                if (op === '$nin') return expected.every(v => !equal(actual, v));
                if (op === '$exists') return (actual !== undefined) === expected;
                if (op === '$gt') return actual > expected;
                if (op === '$lt') return actual < expected;
                if (op === '$ne') return !equal(actual, expected);
                if (op === '$eq') return equal(actual, expected);
                throw Error(`Unsupported fixture predicate ${op}`);
            });
        }
        return equal(actual, value);
    });
}
function apply(row, update) {
    for (const [key, value] of Object.entries(update.$set || {})) row[key] = copy(value);
    for (const [key, value] of Object.entries(update.$inc || {})) row[key] = (row[key] || 0) + value;
    for (const key of Object.keys(update.$unset || {})) delete row[key];
}
function fixture() {
    const db = {};
    let data = {
        CascadeTopologyState: [{ _id: 'singleton', revision: 7, deployedRevision: 5, topologyAdmissionCount: 0, remoteAdmissionCount: 0 }],
        HyNode: ids.map((_id, i) => ({ _id, active: true, type: 'xray', cascadeRole: i % 2 ? 'bridge' : 'portal' })),
        CascadeLink: [], CascadeRouteGroup: [], RelayL2tpState: [], TopologyCreateIntent: [], TopologyIntentQueueState: [], TopologyOperation: [],
    };
    const trace = [];
    function model(name) {
        class Model {
            constructor(input) { return new LinkModel(input); }
            static db = db;
            static query(work) {
                let session, sort, limit;
                return {
                    session(value) { session = value; return this; }, select() { return this; }, populate() { return this; },
                    sort(value) { sort = value; return this; }, limit(value) { limit = value; return this; },
                    readConcern(value) { trace.push(['readConcern', value]); return this; },
                    read(value) { trace.push(['read', value]); return this; },
                    maxTimeMS(value) { trace.push(['maxTimeMS', value]); return this; },
                    async lean() {
                        const result = work(session?.data || data);
                        if (Array.isArray(result)) {
                            if (sort) result.sort((a, b) => a[Object.keys(sort)[0]] - b[Object.keys(sort)[0]]);
                            return copy(limit ? result.slice(0, limit) : result);
                        }
                        return copy(result);
                    },
                    then(resolve, reject) { return this.lean().then(resolve, reject); },
                };
            }
            static find(filter) { return this.query(state => state[name].filter(row => matches(row, filter))); }
            static findOne(filter) { return this.query(state => state[name].find(row => matches(row, filter)) || null); }
            static findById(_id) { return this.findOne({ _id }); }
            static exists(filter) { return this.findOne(filter); }
            static findOneAndUpdate(filter, update, options = {}) {
                return this.query(state => {
                    const row = state[name].find(candidate => matches(candidate, filter));
                    if (!row) return null;
                    apply(row, update); return row;
                }).session(options.session);
            }
            static async create(rows, { session } = {}) {
                trace.push(['create', name, session]);
                const state = session?.data || data;
                return rows.map(input => {
                    const row = JSON.parse(JSON.stringify(name === 'CascadeLink'
                        ? new LinkModel(input).toObject() : { _id: new mongoose.Types.ObjectId(), ...input }));
                    state[name].push(row); return row;
                });
            }
            static async updateOne(filter, update, { session } = {}) {
                trace.push(['update', name, session]);
                const row = (session?.data || data)[name].find(candidate => matches(candidate, filter));
                if (row) apply(row, update);
                return { matchedCount: row ? 1 : 0 };
            }
            static async deleteOne(filter, { session } = {}) {
                const rows = (session?.data || data)[name];
                const index = rows.findIndex(row => matches(row, filter));
                if (index >= 0) rows.splice(index, 1);
                return { deletedCount: index >= 0 ? 1 : 0 };
            }
        }
        return Model;
    }
    const dependencies = Object.fromEntries(Object.keys(data).map(name => [name, model(name)]));
    Object.assign(dependencies, { executionContext: context,
        async transactionRunner(work) {
            const session = { data: copy(data) };
            const result = await work(session);
            data = session.data;
            return result;
        },
        async resolveIntentResources({ link }) { return [String(link.portalNode), String(link.bridgeNode)].sort(); },
    });
    const link = (pair = 0) => ({ name: `link-${pair}`, portalNode: ids[pair * 2], bridgeNode: ids[pair * 2 + 1], tunnelPort: 10086 });
    return { dependencies, link, trace, get data() { return data; } };
}


function routers(f, extra = {}) {
    const service = new TopologyIntentService(f.dependencies);
    const { TopologyDraftWriteService } = require('../services/topologyDraftWriteService');
    const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
    const draft = new TopologyDraftWriteService({ repository: new TopologyDraftRepository(f.dependencies) });
    const app = express(); app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    app.use('/links', createCascadeLinksRouter({
        Link: f.dependencies.CascadeLink, Node: f.dependencies.HyNode,
        TopologyState: f.dependencies.CascadeTopologyState,
        ClientProofOperation: f.dependencies.TopologyOperation,
        topologyIntentService: service, topologyDraftWriteService: draft,
        deploymentEnv: {}, maintainAutoL2tpPathsFn: async () => {},
        invalidateSubscriptions: async () => {}, invalidateTopology: async () => {}, ...extra,
    }));
    const next = (req, res, next) => next();
    app.use('/topology', createCascadeTopologyDeployRouter({
        models: f.dependencies, topologyIntentService: service, deploymentEnv: {},
        topologyDeploymentService: { deploy() { throw Error('unexpected direct deploy'); }, queue() { throw Error('unexpected direct queue'); } },
        requireAuth: next, requireScope: () => next, csrf: next, deployRateLimiter: next, operationStatusRateLimiter: next,
    }));
    return app;
}
async function request(app, method, path, body, key = 'http-key') {
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
            method, headers: { 'content-type': 'application/json', ...(key === null ? {} : { 'idempotency-key': key }) },
            ...(method === 'GET' ? {} : { body: JSON.stringify(body) }),
        });
        return { status: response.status, body: await response.json() };
    } finally { await new Promise(resolve => server.close(resolve)); }
}
function createBody(f, overrides = {}) {
    const link = f.link();
    return { expectedTopologyRevision: 7, name: link.name, portalNodeId: link.portalNode,
        bridgeNodeId: link.bridgeNode, autoDeploy: true, ...overrides };
}
test('HTTP Auto create persists one link + v2 job; restart replay precedes generation', async () => {
    const f = fixture(); let generated = 0;
    f.dependencies.prepareLink = async link => ({ ...link, tunnelUuid: `generated-${++generated}` });
    const body = createBody(f);
    const first = await request(routers(f), 'POST', '/links', body);
    assert.equal(first.status, 202, JSON.stringify(first.body));
    assert.equal(f.data.CascadeLink.length, 1, 'accepted HTTP must save the desired link, not just a v1 payload');
    assert.equal(f.data.TopologyCreateIntent.length, 1);
    assert.equal(first.body.createdLinkId, f.data.CascadeLink[0]._id);
    assert.equal(first.body.linkId, first.body.createdLinkId);
    assert.equal(first.body.desiredSaved, true);
    assert.equal(first.body.job.kind, 'link.create');
    assert.deepEqual(first.body.autoDeployJob, first.body.job);
    assert.equal(first.body.operationId, undefined);
    const replay = await request(routers(f), 'POST', '/links', { ...body, expectedTopologyRevision: 1 });
    assert.deepEqual(replay.body.job, first.body.job);
    assert.equal(replay.body.createdLinkId, first.body.createdLinkId);
    assert.equal(f.data.CascadeLink.length, 1); assert.equal(generated, 1);
    const conflict = await request(routers(f), 'POST', '/links', { ...body, tunnelPort: 10087 });
    assert.equal(conflict.status, 409); assert.equal(conflict.body.error.code, 'TOPOLOGY_INTENT_KEY_CONFLICT');
});

test('HTTP manual apply uses durable v2 without direct queue; poll identity survives router restart', async () => {
    const f = fixture();
    const created = await request(routers(f), 'POST', '/links', createBody(f));
    const result = await request(routers(f), 'POST', '/topology/deploy', {
        expectedTopologyRevision: 8, linkId: created.body.linkId,
    }, 'manual-key');
    assert.equal(result.status, 202, JSON.stringify(result.body));
    assert.equal(result.body.job.kind, 'link.apply');
    assert.equal(result.body.linkId, created.body.linkId);
    assert.equal(f.data.CascadeLink.length, 1); assert.equal(f.data.TopologyCreateIntent.length, 2);
    const poll = await request(routers(f), 'GET', `/links/auto-deploy-jobs/${result.body.job.jobId}`);
    assert.deepEqual(poll.body.job, result.body.job);
    assert.deepEqual(poll.body.autoDeployJob, result.body.job);
    const replay = await request(routers(f), 'POST', '/topology/deploy', {
        expectedTopologyRevision: 1, linkId: created.body.linkId,
    }, 'manual-key');
    assert.deepEqual(replay.body.job, result.body.job);
});

test('HTTP applied DELETE retains descriptor + deleting job marker; even pending is not proof of no dispatch', async () => {
    const f = fixture();
    f.dependencies.deleteIntentWriter = LinkModel.createDeleteIntentWriter({ CascadeLink: f.dependencies.CascadeLink });
    const created = await request(routers(f), 'POST', '/links', createBody(f));
    f.data.CascadeLink[0].status = 'pending'; // Could have dispatched previously.
    const before = copy(f.data.CascadeLink[0]);
    const deleted = await request(routers(f), 'DELETE', `/links/${created.body.linkId}`, {
        expectedTopologyRevision: 8,
    }, 'delete-key');
    assert.equal(deleted.status, 202, JSON.stringify(deleted.body));
    assert.equal(deleted.body.job.kind, 'link.delete');
    assert.equal(deleted.body.linkId, before._id);
    assert.equal(f.data.CascadeLink.length, 1);
    assert.equal(f.data.CascadeLink[0].lifecycle.state, 'deleting');
    assert.equal(f.data.CascadeLink[0].lifecycle.deleteJobId, deleted.body.job.jobId);
    const markerSession = f.trace.find(([kind, name]) => kind === 'update' && name === 'CascadeLink')[2];
    assert.ok(f.trace.some(([kind, name, session]) => kind === 'create' && name === 'TopologyCreateIntent' && session === markerSession));
    const { lifecycle, ...retained } = f.data.CascadeLink[0];
    assert.deepEqual(retained, before, 'no desired/applied descriptor removed before cleanup');
    const replay = await request(routers(f), 'DELETE', `/links/${before._id}`, { expectedTopologyRevision: 1 }, 'delete-key');
    assert.deepEqual(replay.body.job, deleted.body.job);
    assert.equal(f.data.TopologyCreateIntent.length, 2);
    const snapshot = await request(routers(f), 'GET', '/links');
    assert.equal(snapshot.body.links[0].applicationState, 'deleting');
    assert.equal(snapshot.body.links[0].lifecycle.deleteJobId, deleted.body.job.jobId);
    const manual = await request(routers(f), 'POST', '/topology/deploy', { expectedTopologyRevision: 8, linkId: before._id }, 'too-late');
    assert.equal(manual.status, 409);
    assert.equal(manual.body.error.code, 'CASCADE_LINK_DELETING');
});

test('HTTP save-only excludes jobs; explicit PUT Auto persists edit then accepts the same v2 apply', async () => {
    const f = fixture(); let maintenance = 0;
    const app = () => routers(f, { maintainAutoL2tpPathsFn: async () => { maintenance++; } });
    const saved = await request(app(), 'POST', '/links', createBody(f, { autoDeploy: false }));
    assert.equal(saved.status, 201, JSON.stringify(saved.body));
    assert.equal(saved.body.desiredSaved, true);
    assert.equal(saved.body.job, undefined); assert.equal(f.data.TopologyCreateIntent.length, 0);
    const linkId = saved.body.createdLinkId;
    const edit = await request(app(), 'PUT', `/links/${linkId}`, { expectedTopologyRevision: 8, name: 'edited only' });
    assert.equal(edit.status, 200, JSON.stringify(edit.body)); assert.equal(edit.body.desiredSaved, true);
    assert.equal(f.data.TopologyCreateIntent.length, 0);
    const autoBody = { expectedTopologyRevision: 9, tunnelPort: 10088, autoDeploy: true };
    const applied = await request(app(), 'PUT', `/links/${linkId}`, autoBody, 'put-auto');
    assert.equal(applied.status, 202, JSON.stringify(applied.body));
    assert.equal(applied.body.job.kind, 'link.apply');
    assert.equal(applied.body.job.linkId, linkId); assert.deepEqual(applied.body.autoDeployJob, applied.body.job);
    assert.equal(f.data.CascadeLink[0].tunnelPort, 10088); assert.equal(f.data.TopologyCreateIntent.length, 1);
    assert.equal(maintenance, 2, 'native Auto must not run legacy ingress/path cutover before acceptance');
    const replay = await request(app(), 'PUT', `/links/${linkId}`, autoBody, 'put-auto');
    assert.equal(replay.status, 202, JSON.stringify(replay.body));
    assert.deepEqual(replay.body.job, applied.body.job); assert.equal(f.data.TopologyCreateIntent.length, 1);
    const after = await request(app(), 'PUT', `/links/${linkId}`, { expectedTopologyRevision: 10, name: 'metadata save' }, 'save-after-auto');
    assert.equal(after.status, 200, JSON.stringify(after.body)); assert.equal(after.body.job, undefined);
    assert.equal(f.data.TopologyCreateIntent.length, 1, 'persisted autoDeploy never activates an ordinary PUT');
});

test('HTTP malformed keys, malformed manual pins and queue overflow refuse without accepting a job', async () => {
    const f = fixture();
    const app = routers(f);
    for (const key of [null, 'bad key']) {
        const result = await request(app, 'POST', '/links', createBody(f), key);
        assert.equal(result.status, 400, JSON.stringify(result.body));
        assert.equal(result.body.error.code, 'INVALID_IDEMPOTENCY_KEY');
        assert.equal(result.body.error.phase, 'intent.accept'); assert.equal(result.body.error.nextAction, 'refresh_topology');
    }
    const created = await request(app, 'POST', '/links', createBody(f));
    const invalid = await request(app, 'POST', '/topology/deploy', {
        expectedTopologyRevision: 8, linkId: [created.body.linkId],
    }, 'array-link');
    assert.equal(invalid.status, 400);
    const changed = await request(app, 'POST', '/topology/deploy', {
        expectedTopologyRevision: 8, linkId: created.body.linkId, desiredVersion: 'a'.repeat(64),
    }, 'stale-pin');
    assert.equal(changed.status, 409); assert.equal(changed.body.error.code, 'TOPOLOGY_INTENT_DESIRED_VERSION_CONFLICT');
    assert.equal(changed.body.error.linkId, created.body.linkId); assert.equal(changed.body.error.phase, 'intent.accept');
    f.data.TopologyIntentQueueState[0].outstanding = 32;
    const full = await request(app, 'POST', '/links', createBody(f, {
        expectedTopologyRevision: 8, portalNodeId: ids[2], bridgeNodeId: ids[3],
    }), 'overflow');
    assert.equal(full.status, 503); assert.equal(full.body.error.code, 'TOPOLOGY_INTENT_BACKLOG_FULL');
    assert.equal(full.body.error.phase, 'intent.accept'); assert.equal(full.body.error.nextAction, 'retry_later');
    assert.equal(full.body.job, undefined); assert.equal(full.body.desiredSaved, undefined);
    assert.equal(f.data.CascadeLink.length, 1); assert.equal(f.data.TopologyCreateIntent.length, 1);
});

test('HTTP missing selected runtime closes native Auto/manual/delete without falling through to draft deletion or queue', async () => {
    const f = fixture(); let drafts = 0;
    const stored = JSON.parse(JSON.stringify(new LinkModel({ ...f.link(), tunnelUuid: 'never-output-secret' }).toObject()));
    f.data.CascadeLink.push(stored);
    const app = express(); app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    app.use('/links', createCascadeLinksRouter({ Link: f.dependencies.CascadeLink, Node: f.dependencies.HyNode,
        topologyIntentService: null, deploymentEnv: {}, topologyDraftWriteService: { deleteLink() { drafts++; } } }));
    const next = (req, res, next) => next();
    app.use('/topology', createCascadeTopologyDeployRouter({ models: f.dependencies, topologyIntentService: null,
        deploymentEnv: {}, topologyDeploymentService: { deploy() { drafts++; }, queue() { drafts++; } },
        requireAuth: next, requireScope: () => next, csrf: next, deployRateLimiter: next, operationStatusRateLimiter: next }));
    for (const [method, path, body] of [
        ['POST', '/links', createBody(f)],
        ['POST', '/topology/deploy', { expectedTopologyRevision: 7, linkId: stored._id }],
        ['DELETE', `/links/${stored._id}`, { expectedTopologyRevision: 7 }],
        ['PUT', `/links/${stored._id}`, { expectedTopologyRevision: 7, autoDeploy: true }],
    ]) {
        const result = await request(app, method, path, body);
        assert.equal(result.status, 503, JSON.stringify(result.body)); assert.equal(result.body.error.code, 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
    }
    assert.equal(drafts, 0); assert.deepEqual(f.data.CascadeLink, [stored]);
});

test('HTTP REALITY credentials are generated only inside first durable acceptance, never on restart replay', async () => {
    const { prepareIntentLink } = require('../../../routes/cascadeLinks');
    const f = fixture(); let generations = 0;
    f.dependencies.prepareLink = link => { generations++; return prepareIntentLink(link); };
    const body = createBody(f, { tunnelSecurity: 'reality' });
    const first = await request(routers(f), 'POST', '/links', body);
    assert.equal(first.status, 202, JSON.stringify(first.body));
    const stored = copy(f.data.CascadeLink[0]);
    assert.match(stored.realityPrivateKey, /^[A-Za-z0-9_-]{43}$/);
    assert.match(stored.realityPublicKey, /^[A-Za-z0-9_-]{43}$/);
    assert.match(stored.realityShortIds[0], /^[a-f0-9]{16}$/);
    const replay = await request(routers(f), 'POST', '/links', body);
    assert.deepEqual(replay.body.job, first.body.job); assert.equal(generations, 1);
    assert.deepEqual(f.data.CascadeLink[0], stored);
    assert.doesNotMatch(JSON.stringify(first.body), new RegExp(stored.realityPrivateKey));
});

test('HTTP delete marker rolls back with refused intent insertion and uses the exact outer session', async () => {
    const f = fixture(); f.dependencies.deleteIntentWriter = LinkModel.createDeleteIntentWriter({ CascadeLink: f.dependencies.CascadeLink });
    const created = await request(routers(f), 'POST', '/links', createBody(f));
    const before = copy(f.data.CascadeLink[0]);
    f.dependencies.TopologyCreateIntent.create = async () => { throw Error('modeled insertion fault'); };
    const result = await request(routers(f), 'DELETE', `/links/${created.body.linkId}`, { expectedTopologyRevision: 8 }, 'failed-delete');
    assert.equal(result.status, 500); assert.equal(result.body.job, undefined);
    assert.deepEqual(f.data.CascadeLink[0], before); assert.equal(f.data.TopologyCreateIntent.length, 1);
    assert.equal(f.data.TopologyIntentQueueState[0].outstanding, 1);
});

test('HTTP PUT key/content conflict is checked before editing the desired descriptor', async () => {
    const f = fixture();
    const saved = await request(routers(f), 'POST', '/links', createBody(f, { autoDeploy: false }));
    const path = `/links/${saved.body.createdLinkId}`;
    const first = await request(routers(f), 'PUT', path, { expectedTopologyRevision: 8, autoDeploy: true, tunnelPort: 10087 }, 'edit-key');
    assert.equal(first.status, 202, JSON.stringify(first.body));
    const before = copy(f.data.CascadeLink[0]);
    const changed = await request(routers(f), 'PUT', path, { expectedTopologyRevision: 9, autoDeploy: true, tunnelPort: 10088 }, 'edit-key');
    assert.equal(changed.status, 409, JSON.stringify(changed.body)); assert.equal(changed.body.error.code, 'TOPOLOGY_INTENT_KEY_CONFLICT');
    assert.deepEqual(f.data.CascadeLink[0], before); assert.equal(f.data.TopologyCreateIntent.length, 1);
});

test('HTTP selected proof cannot become ready from caller fields or a matching global revision', async () => {
    const f = fixture();
    const created = await request(routers(f), 'POST', '/links', createBody(f));
    Object.assign(f.data.CascadeLink[0], { status: 'online', clientReadiness: { status: 'ready' }, routeState: 'complete' });
    f.data.TopologyOperation.push({ _id: ids[7], kind: 'link.apply', admissionScope: 'selected',
        topologyRevision: 8, priorDeployedRevision: 5, clientProofRevision: 8,
        status: 'succeeded', clientReadiness: 'verified', linkIds: [created.body.linkId] });
    const result = await request(routers(f), 'GET', '/links');
    assert.equal(result.status, 200);
    assert.equal(result.body.links[0].clientReadiness, undefined);
    assert.equal(result.body.links[0].routeState, 'unknown');
    assert.equal(result.body.links[0].applicationState, 'applied');
    assert.equal(result.body.links[0].tunnelState, 'connected');
    const polled = await request(routers(f), 'GET', `/topology/operations/${ids[7]}`);
    assert.equal(polled.status, 200, JSON.stringify(polled.body));
    assert.equal(polled.body.clientReadiness, 'unverified');
    assert.equal(polled.body.kind, 'link.apply'); assert.equal(polled.body.phase, 'completed');
});

test('HTTP explicit trusted projection reports incomplete application and separate PPP/Xray outcomes, pin drift refuses green', async () => {
    const f = fixture();
    const created = await request(routers(f), 'POST', '/links', createBody(f));
    const reader = async ({ links }) => links.map(link => ({ ...link, operationId: ids[7],
        applicationState: 'applied', routeState: 'no_portal_input', tunnelState: 'connected',
        xrayReadiness: 'verified', pppReadiness: 'verified', secret: 'do-not-project' }));
    const result = await request(routers(f, { readLinkApplicationState: reader }), 'GET', '/links');
    const link = result.body.links[0];
    assert.equal(link.applicationState, 'applied'); assert.equal(link.routeState, 'no_portal_input');
    assert.equal(link.pppReadiness, 'verified'); assert.equal(link.xrayReadiness, 'unverified');
    assert.equal(link.clientReadiness, undefined); assert.equal(link.secret, undefined);
    const stale = await request(routers(f, { readLinkApplicationState: async input => (await reader(input)).map(row => ({ ...row, desiredVersion: 'b'.repeat(64), routeState: 'complete' })) }), 'GET', '/links');
    assert.equal(stale.body.links[0].routeState, 'unknown'); assert.equal(stale.body.links[0].clientReadiness, undefined);
});

test('real link schema retains a valid delete marker but leaves legacy links unmarked', async () => {
    const f = fixture();
    const link = new LinkModel({ ...f.link(), tunnelUuid: 'schema-secret' });
    assert.equal(link.lifecycle, undefined);
    link.lifecycle = { state: 'deleting', deleteJobId: ids[7], desiredVersion: 'c'.repeat(64) };
    await link.validate();
    assert.equal(link.toObject().lifecycle.state, 'deleting'); assert.equal(link.tunnelUuid, 'schema-secret');
    link.lifecycle.desiredVersion = 'invalid'; await assert.rejects(link.validate(), /desiredVersion/);
});

test('HTTP persisted binding polling and terminal DELETE replay do not need the removed desired row', async () => {
    const f = fixture(); f.dependencies.deleteIntentWriter = LinkModel.createDeleteIntentWriter({ CascadeLink: f.dependencies.CascadeLink });
    const created = await request(routers(f), 'POST', '/links', createBody(f));
    const path = `/links/${created.body.linkId}`;
    const removed = await request(routers(f), 'DELETE', path, { expectedTopologyRevision: 8 }, 'terminal-delete');
    const row = f.data.TopologyCreateIntent.find(row => row._id === removed.body.job.jobId);
    // Simulated finalizer persistence, NOT a claim of actual cleanup execution.
    Object.assign(row, { status: 'succeeded', operationId: ids[7], topologyRevision: 8 });
    f.data.CascadeLink.length = 0;
    const poll = await request(routers(f), 'GET', `/links/auto-deploy-jobs/${row._id}`);
    assert.equal(poll.body.job.operationId, ids[7]); assert.equal(poll.body.job.kind, 'link.delete');
    const replay = await request(routers(f), 'DELETE', path, { expectedTopologyRevision: 1 }, 'terminal-delete');
    assert.equal(replay.status, 202, JSON.stringify(replay.body)); assert.deepEqual(replay.body.job, poll.body.job);
    assert.equal(f.data.TopologyCreateIntent.length, 2); assert.equal(f.data.CascadeLink.length, 0);
});

test('HTTP PUT REALITY retry with empty edit controls preserves its first generated credentials and job', async () => {
    const f = fixture();
    const saved = await request(routers(f), 'POST', '/links', createBody(f, { autoDeploy: false }));
    const path = `/links/${saved.body.createdLinkId}`;
    const body = { expectedTopologyRevision: 8, autoDeploy: true, tunnelSecurity: 'reality',
        realityPrivateKey: '', realityPublicKey: '', realityShortIds: [] };
    const first = await request(routers(f), 'PUT', path, body, 'reality-edit');
    assert.equal(first.status, 202, JSON.stringify(first.body)); const before = copy(f.data.CascadeLink[0]);
    const replay = await request(routers(f), 'PUT', path, body, 'reality-edit');
    assert.equal(replay.status, 202, JSON.stringify(replay.body)); assert.deepEqual(replay.body.job, first.body.job);
    assert.deepEqual(f.data.CascadeLink[0], before); assert.equal(f.data.TopologyCreateIntent.length, 1);
});

test('HTTP retained terminal ownership projects reconcile, never client-ready; PPP wait is separate', async () => {
    const f = fixture();
    f.data.TopologyOperation.push({ _id: ids[7], status: 'failed', topologyRevision: 7,
        admissionScope: 'selected', heldTopologyAdmission: true, kind: 'link.delete', linkId: ids[6],
        clientReadiness: 'verified', reason: 'never-public-private-output' });
    const response = await request(routers(f), 'GET', `/topology/operations/${ids[7]}`);
    assert.equal(response.status, 200, JSON.stringify(response.body)); assert.equal(response.body.status, 'failed');
    assert.equal(response.body.phase, 'reconcile_required'); assert.equal(response.body.clientReadiness, 'unverified');
    assert.equal(response.body.waitingReason, 'TOPOLOGY_RECONCILE_REQUIRED');
    assert.equal(response.body.linkId, ids[6]); assert.equal(response.body.kind, 'link.delete');
    assert.doesNotMatch(JSON.stringify(response.body), /never-public-private-output/);
    Object.assign(f.data.TopologyOperation[0], { status: 'committing', pppWait: { relayNode: ids[0] } });
    const waiting = await request(routers(f), 'GET', `/topology/operations/${ids[7]}`);
    assert.equal(waiting.body.phase, 'waiting'); assert.equal(waiting.body.waitingReason, 'PPP_SYNC_PENDING');
});
