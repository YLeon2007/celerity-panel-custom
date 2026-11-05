'use strict';
// Real default host/module/runtime, HTTP routes, v2 queue, coordinator,
// materializer, worker and finalizer. DB transactions and executor are MODELED;
// this is not Mongo atomicity, deployed Xray/SSH or client traffic evidence.
process.env.PANEL_DOMAIN ||= 'panel.test.invalid';
process.env.ACME_EMAIL ||= 'admin@test.invalid';
process.env.ENCRYPTION_KEY ||= 'test-encryption-key-32-characters-long';
process.env.SESSION_SECRET ||= 'test-session-secret';
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
function get(row, key) {
    const walk = (value, parts) => !parts.length ? value : Array.isArray(value)
        ? value.flatMap(child => walk(child, parts)) : walk(value?.[parts[0]], parts.slice(1));
    return walk(row, key.split('.'));
}
function matches(row, filter, executionContext = context) {
    return Object.entries(filter).every(([key, value]) => {
        if (key === '$or') return value.some(f => matches(row, f, executionContext));
        if (key === '$and') return value.every(f => matches(row, f, executionContext));
        if (key === '$nor') return value.every(f => !matches(row, f, executionContext));
        if (key === '$expr') return require('../domain/topologyOperationClaimBinding').matchesTopologyOperationClaimBinding(row, executionContext);
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
function fixture({ roles = ['portal', 'relay', 'bridge', 'portal', 'bridge'],
    executionContext = context, deploymentEnv = env } = {}) {
    // Explicit synthetic server selection, fixed before owners/host/HTTP exist.
    assert.strictEqual(require('../domain/l2tpExecutionAuthorization').selectExecutionContext(executionContext), executionContext);
    assert.strictEqual(require('../runtime/createTopologyOperationRuntime').resolveTopologyExecutionContext(deploymentEnv), executionContext);
    const selected = (row, filter) => matches(row, filter, executionContext);
    let depth = 0;
    const calls = [], sessions = [], errors = [], deployments = [];
    const db = { async transaction(work) {
        const session = { inTransaction: () => depth > 0 };
        sessions.push(session); depth++;
        try { return await work(session); } finally { depth--; }
    } };
    const data = {
        HyNode: roles.map((cascadeRole, i) => ({
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
        executionContext, owner: 'topology', generation: '11111111-1111-4111-8111-111111111111',
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
                else {
                    const parts = key.split('.'); let target = row;
                    for (const part of parts.slice(0, -1)) target = target[part] ||= {};
                    target[parts.at(-1)] = copy(value);
                }
            }
            for (const [key, value] of Object.entries(changes.$inc || {})) row[key] = (row[key] || 0) + value;
            for (const key of Object.keys(changes.$unset || {})) delete row[key];
        }
        Object.assign(Model, { db, rows,
            find: f => query(() => rows.filter(r => selected(r, f))),
            findOne: f => query(() => rows.find(r => selected(r, f)) || null),
            findById: k => query(() => rows.find(r => String(r._id) === String(k)) || null),
            exists: f => query(() => rows.find(r => selected(r, f)) ? { _id: 'exists' } : null),
            countDocuments: f => query(() => rows.filter(r => selected(r, f)).length),
            async create(docs, options = {}) {
                if (name !== 'NodeOperationLock') assert.ok(options.session?.inTransaction(), `${name} create joins an active transaction`);
                const many = Array.isArray(docs);
                const result = (many ? docs : [docs]).map(doc => name === 'CascadeLink' ? JSON.parse(JSON.stringify(new LinkSchema(doc).toObject()))
                    : { ...copy(doc), ...(doc._id == null ? {} : { _id: String(doc._id) }) });
                for (const row of result) { if (row.node && rows.some(r => r.node === row.node)) throw Object.assign(Error('duplicate'), { code: 11000 }); rows.push(row); }
                return copy(many ? result : result[0]);
            },
            findOneAndUpdate: (f, u) => query(() => { const row = rows.find(r => selected(r, f)); if (row) update(row, u, f); return row || null; }),
            async updateOne(f, u) { const row = rows.find(r => selected(r, f)); if (row) update(row, u, f); return { matchedCount: row ? 1 : 0 }; },
            async updateMany(f, u) { const chosen = rows.filter(r => selected(r, f)); chosen.forEach(r => update(r, u, f)); return { matchedCount: chosen.length }; },
            async deleteOne(f) { const index = rows.findIndex(r => selected(r, f)); if (index >= 0) rows.splice(index, 1); return { deletedCount: index >= 0 ? 1 : 0 }; },
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
        return createL2tpPanelHost({ env: deploymentEnv, ...models, NodeSSH: class { constructor() { assert.fail('no real SSH'); } },
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
    return { executionContext, deploymentEnv, models, data, calls, errors, sessions, host, timer, deployments, setPause(fn) { pause = fn; } };
}
function app(f) {
    const app = express(); app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    const draft = new TopologyDraftWriteService({ repository: new TopologyDraftRepository(f.models) });
    app.use('/links', createCascadeLinksRouter({ Link: f.models.CascadeLink, Node: f.models.HyNode,
        TopologyState: f.models.CascadeTopologyState, ClientProofOperation: f.models.TopologyOperation,
        topologyDraftWriteService: draft, deploymentEnv: f.deploymentEnv,
        maintainAutoL2tpPathsFn: async () => {}, invalidateSubscriptions: async () => {}, invalidateTopology: async () => {} }));
    const next = (req, res, next) => next();
    app.use('/topology', createCascadeTopologyDeployRouter({ models: f.models, deploymentEnv: f.deploymentEnv,
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

async function settleTick(f) {
    await new Promise(resolve => setImmediate(resolve));
    await f.timer.tick();
    assert.deepEqual(f.errors, []);
}

module.exports = { fixture, app, request, createBody, waitFor, settleTick, id, sha, copy, env, context, provider, moduleEntry, TopologyIntentService };
