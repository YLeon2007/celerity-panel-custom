'use strict';

// Local HTTP/MCP ingress fixtures: no panel DB, transport, or production secrets.
const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');
const fs = require('node:fs');
const Module = require('node:module');
const { createCascadeLinksRouter } = require('../cascadeLinks');
const CascadeLink = require('../../models/cascadeLinkModel');
const { hasClassicLifecycleGrant } = require('../../services/classicLifecycleAuthorization');
test.after(() => require('../../services/sshPoolService').closeAll());

const PORTAL = '507f1f77bcf86cd799439031';
const BRIDGE = '507f1f77bcf86cd799439032';
const ID = '507f1f77bcf86cd799439021';
const CLASSIC = Object.freeze({
    PANEL_DOMAIN: 'lm1.infograd.online', L2TP_PRODUCTION_EXECUTION_ENABLED: 'true',
    L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
    CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true',
    CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: ID,
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false',
    CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'true',
    CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY: 'a'.repeat(64), // Synthetic non-production key.
});
const body = overrides => ({ expectedTopologyRevision: 7, name: 'synthetic',
    portalNodeId: PORTAL, bridgeNodeId: BRIDGE, mode: 'reverse', autoDeploy: false, ...overrides });
function query(value) {
    return { populate() { return this; }, sort() { return this; }, select() { return this; },
        lean: async () => value, then(resolve, reject) { return Promise.resolve(value).then(resolve, reject); } };
}
async function request(router, method, path, body, headers = {}) {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    app.use(router);
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
            method, headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
        });
        return { status: response.status, body: await response.json() };
    } finally { await new Promise(resolve => server.close(resolve)); }
}
function harness({ env = CLASSIC, insertError, coordinator = {}, intentService } = {}) {
    const calls = { creates: [], updates: [], draftDeletes: [], lifecycleDeletes: [] };
    const rows = [];
    const Link = { find: () => query(rows), findOne: async () => null,
        findById: id => query(rows.find(row => String(row._id) === String(id)) || null) };
    const Node = { findById: async id => ({ _id: id, name: 'synthetic node' }) };
    const draft = {
        async createLink(input) { calls.creates.push(input); if (insertError) throw insertError;
            rows.push({ ...input.link }); return { revision: 8, deployedRevision: 5 }; },
        async updateLink(input) { calls.updates.push(input); return { revision: 8, deployedRevision: 5 }; },
        async deleteLink(input) { calls.draftDeletes.push(input); rows.splice(0); return { revision: 8, deployedRevision: 5 }; },
    };
    const router = createCascadeLinksRouter({ Link, Node, deploymentEnv: env,
        topologyDraftWriteService: draft, topologyCoordinator: coordinator,
        topologyIntentService: intentService,
        maintainAutoL2tpPathsFn: async () => {}, invalidateSubscriptions: async () => {},
        invalidateTopology: async () => {},
    });
    return { router, rows, calls, Link, Node, draft };
}

// Load the actual MCP module with local persistence/cache/factory seams, keeping
// its schema parsing and lazy classic coordinator selection intact.
function mcpHarness(options = {}) {
    const h = harness(options);
    let factoryCalls = 0;
    const filename = require.resolve('../../mcp/tools/cascade');
    const loaded = new Module(filename, module);
    loaded.filename = filename;
    loaded.paths = Module._nodeModulePaths(require('node:path').dirname(filename));
    loaded.require = name => {
        if (name === '../../modules/l2tpActiveHostProvider') return { l2tpActiveHostProvider: { getActiveHost: () => ({ selectedTopologyIntentService: options.intentService }) } };
        if (name === '../../models/cascadeLinkModel') return h.Link;
        if (name === '../../models/hyNodeModel') return h.Node;
        if (name === '../../services/cacheService') return { invalidateAllSubscriptions: async () => {} };
        if (name.endsWith('/topologyDraftWriteService')) return { createTopologyDraftWriteService: () => h.draft };
        if (name === '../../services/classicScopedCascadeDeploymentService') return {
            ...require('../../services/classicScopedCascadeDeploymentService'),
            createClassicScopedCascadeDeploymentService: input => {
                factoryCalls++; assert.equal(input.env, process.env); return options.coordinator || {};
            },
        };
        return Module.prototype.require.call(loaded, name);
    };
    loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
    return { ...h, ...loaded.exports, factoryCalls: () => factoryCalls };
}
async function withEnv(env, work) {
    const saved = { ...process.env };
    // Explicit complete synthetic execution fixture, never inherit activation flags.
    for (const key of Object.keys(process.env)) if (/^(CLASSIC_TOPOLOGY_|TOPOLOGY_|L2TP_)/.test(key)) delete process.env[key];
    Object.assign(process.env, env);
    try { return await work(); } finally {
        for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
        Object.assign(process.env, saved);
    }
}

test('model stores only a valid optional hidden lifecycle grant without adopting legacy links', () => {
    const field = CascadeLink.schema.path('classicLifecycleGrant');
    assert.ok(field);
    assert.equal(field.options.select, false);
    assert.equal(field.options.default, undefined);
    const data = { name: 'synthetic', portalNode: PORTAL, bridgeNode: BRIDGE, tunnelUuid: 'synthetic' };
    assert.equal(new CascadeLink(data).classicLifecycleGrant, undefined);
    assert.equal(new CascadeLink({ ...data, classicLifecycleGrant: 'a'.repeat(64) }).validateSync(), undefined);
    for (const grant of ['A'.repeat(64), 'a'.repeat(63), 'g'.repeat(64), '']) {
        assert.ok(new CascadeLink({ ...data, classicLifecycleGrant: grant }).validateSync()?.errors.classicLifecycleGrant);
    }
});

test('MCP save-only create mints its own grant and strips client authorization fields', async () => {
    await withEnv(CLASSIC, async () => {
        const h = mcpHarness();
        const result = await h.manageCascade({ action: 'create', expectedTopologyRevision: 7,
            data: { ...body(), classicLifecycleGrant: 'b'.repeat(64) } }, () => {});
        assert.equal(result.success, true);
        assert.equal(hasClassicLifecycleGrant(h.rows[0], CLASSIC), true);
        assert.notEqual(h.rows[0].classicLifecycleGrant, 'b'.repeat(64));
        assert.equal(h.factoryCalls(), 0, 'save-only create must not construct deployment runtime');
    });
});

test('HTTP classic DELETE calls only checked lifecycle removal with exact revision', async () => {
    let input;
    const h = harness({ coordinator: { async deleteLink(value) {
        input = value; h.rows.splice(0); return { revision: 8, deployedRevision: 5 };
    } } });
    h.rows.push({ _id: ID, name: 'synthetic', status: 'online' });
    const response = await request(h.router, 'DELETE', `/${ID}`, { expectedTopologyRevision: 7 });
    assert.equal(response.status, 200);
    assert.deepEqual(input, { expectedTopologyRevision: 7, linkId: ID });
    assert.equal(h.calls.draftDeletes.length, 0);
    assert.equal(response.body.topologyRevision, 8);
    assert.equal(response.body.deployedRevision, 5);
    assert.deepEqual(response.body.links, []);
});

test('HTTP classic DELETE preserves the row on checked removal failure or unavailable coordinator', async () => {
    for (const coordinator of [{}, { async deleteLink() {
        throw Object.assign(new Error('checked removal failed'), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
    } }]) {
        const h = harness({ coordinator, env: { ...CLASSIC, CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'false' } });
        h.rows.push({ _id: ID, name: 'synthetic', status: 'online' });
        const response = await request(h.router, 'DELETE', `/${ID}`, { expectedTopologyRevision: 7 });
        assert.equal(response.status, 503);
        assert.equal(response.body.error.code, coordinator.deleteLink ? 'CLASSIC_DEPLOY_UNCERTAIN' : 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
        assert.equal(h.calls.draftDeletes.length, 0);
        assert.equal(h.rows.length, 1);
    }
});

test('MCP classic DELETE shares checked lifecycle removal and keeps its coordinator lazy', async () => {
    await withEnv(CLASSIC, async () => {
        let input;
        const h = mcpHarness({ coordinator: { async deleteLink(value) {
            input = value; h.rows.splice(0); return { revision: 8, deployedRevision: 5 };
        } } });
        h.rows.push({ _id: ID, name: 'synthetic' });
        assert.equal(h.factoryCalls(), 0);
        const result = await h.manageCascade({ action: 'delete', id: ID, expectedTopologyRevision: 7 });
        assert.equal(result.success, true);
        assert.equal(result.topologyRevision, 8);
        assert.deepEqual(input, { expectedTopologyRevision: 7, linkId: ID });
        assert.equal(h.factoryCalls(), 1);
        assert.equal(h.calls.draftDeletes.length, 0);
    });
});

test('MCP classic DELETE fails closed without lifecycle removal even when grants are disabled', async () => {
    await withEnv({ ...CLASSIC, CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'false' }, async () => {
        for (const coordinator of [{}, { async deleteLink() {
            throw Object.assign(new Error('checked removal failed'), { code: 'CLASSIC_DEPLOY_UNCERTAIN' });
        } }]) {
            const h = mcpHarness({ coordinator });
            h.rows.push({ _id: ID, name: 'synthetic' });
            await assert.rejects(h.manageCascade({ action: 'delete', id: ID, expectedTopologyRevision: 7 }),
                { code: coordinator.deleteLink ? 'CLASSIC_DEPLOY_UNCERTAIN' : 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' });
            assert.equal(h.calls.draftDeletes.length, 0);
            assert.equal(h.rows.length, 1);
        }
    });
});

test('MCP classic undeploy cannot bypass checked lifecycle DELETE', async () => {
    await withEnv(CLASSIC, async () => {
        const h = mcpHarness();
        const result = await h.manageCascade({ action: 'undeploy', id: ID });
        assert.equal(result.success, false);
        assert.equal(result.code, 'REVISION_SAFE_TOPOLOGY_DEPLOY_REQUIRED');
        assert.match(result.error, /delete/i);
        assert.equal(h.factoryCalls(), 0);
    });
});

test('HTTP classic auto create persists its grant but never logs blocked apply as deployed', async () => {
    const messages = [];
    const logger = require('../../utils/logger');
    const original = logger.info;
    logger.info = message => messages.push(message);
    try {
        const capability = {};
        const h = harness({ coordinator: {
            beginCreatedLinkCapability() { return capability; },
            confirmCreatedLinkCapability(actual) { assert.equal(actual, capability); },
            async queue() { throw new Error('must use trusted create capability'); },
            async queueCreatedLink(input, actual) {
                assert.equal(actual, capability);
                assert.equal(input.expectedTopologyRevision, 8);
                assert.equal(hasClassicLifecycleGrant(h.rows[0], CLASSIC), true);
                throw Object.assign(new Error('synthetic refusal'), { code: 'CLASSIC_DEPLOY_BUSY' });
            },
        } });
        const response = await request(h.router, 'POST', '/', body({ autoDeploy: true }));
        assert.equal(response.status, 201);
        assert.equal(response.body.autoDeployStatus, 'blocked');
        assert.equal(h.rows.length, 1);
        assert.ok(messages.some(message => /Created.*auto-deploy blocked/.test(message)));
        assert.ok(messages.every(message => !message.includes('Created and auto-deployed')));
    } finally { logger.info = original; }
});

test('grant issuance stays absent on forward, nonclassic and lifecycle-disabled creates', async () => {
    for (const [env, mode] of [
        [CLASSIC, 'forward'],
        [{ ...CLASSIC, CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false' }, 'reverse'],
        [{ ...CLASSIC, CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'false' }, 'reverse'],
    ]) {
        const h = harness({ env });
        const response = await request(h.router, 'POST', '/', body({ mode, classicLifecycleGrant: 'b'.repeat(64) }));
        assert.equal(response.status, 201);
        assert.equal(Object.hasOwn(h.rows[0], 'classicLifecycleGrant'), false);
        await withEnv(env, async () => {
            const mcp = mcpHarness();
            await mcp.manageCascade({ action: 'create', expectedTopologyRevision: 7,
                data: body({ mode, classicLifecycleGrant: 'b'.repeat(64) }) });
            assert.equal(Object.hasOwn(mcp.rows[0], 'classicLifecycleGrant'), false);
        });
    }
});

test('invalid lifecycle signing key refuses HTTP and MCP before draft insert', async () => {
    const env = { ...CLASSIC, CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY: 'invalid-synthetic' };
    const h = harness({ env });
    const response = await request(h.router, 'POST', '/', body());
    assert.equal(response.status, 503);
    assert.equal(response.body.error.code, 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
    assert.equal(h.calls.creates.length, 0);
    await withEnv(env, async () => {
        const mcp = mcpHarness();
        await assert.rejects(mcp.manageCascade({ action: 'create', expectedTopologyRevision: 7, data: body() }),
            { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' });
        assert.equal(mcp.calls.creates.length, 0);
    });
});

test('invalid lifecycle configuration never downgrades checked HTTP or MCP deletion to draft-only', async () => {
    for (const delta of [{ CLASSIC_TOPOLOGY_LIFECYCLE_SIGNING_KEY: 'invalid' },
        { CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED: 'false', CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: 'invalid' }]) {
        const env = { ...CLASSIC, ...delta }, h = harness({ env });
        h.rows.push({ _id: ID, name: 'legacy', status: 'online' });
        const response = await request(h.router, 'DELETE', `/${ID}`, { expectedTopologyRevision: 7 });
        assert.equal(response.status, 503);
        assert.equal(response.body.error.code, 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
        assert.equal(h.rows.length, 1); assert.equal(h.calls.draftDeletes.length, 0);
        await withEnv(env, async () => {
            const mcp = mcpHarness(); mcp.rows.push({ _id: ID, name: 'legacy' });
            await assert.rejects(mcp.manageCascade({ action: 'delete', id: ID, expectedTopologyRevision: 7 }),
                { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' });
            assert.equal(mcp.rows.length, 1); assert.equal(mcp.calls.draftDeletes.length, 0);
            assert.equal((await mcp.manageCascade({ action: 'undeploy', id: ID })).code, 'REVISION_SAFE_TOPOLOGY_DEPLOY_REQUIRED');
        });
    }
});

test('failed draft insert cannot persist a grant or confirm/apply a create capability', async () => {
    const insertError = Object.assign(new Error('synthetic stale revision'), { code: 'STALE_TOPOLOGY_REVISION' });
    let confirmations = 0, applications = 0;
    const h = harness({ insertError, coordinator: {
        beginCreatedLinkCapability: () => ({}),
        confirmCreatedLinkCapability() { confirmations++; },
        async queue() { applications++; },
        async queueCreatedLink() { applications++; },
    } });
    const response = await request(h.router, 'POST', '/', body({ autoDeploy: true }));
    assert.equal(response.status, 409);
    assert.equal(h.rows.length, 0);
    assert.equal(confirmations, 0);
    assert.equal(applications, 0);
    assert.equal(hasClassicLifecycleGrant(h.calls.creates[0].link, CLASSIC), true);
    await withEnv(CLASSIC, async () => {
        const mcp = mcpHarness({ insertError });
        await assert.rejects(mcp.manageCascade({ action: 'create', expectedTopologyRevision: 7, data: body() }),
            { code: 'STALE_TOPOLOGY_REVISION' });
        assert.equal(mcp.rows.length, 0);
        assert.equal(mcp.factoryCalls(), 0);
    });
});

test('HTTP and MCP updates cannot add or replace a durable grant on existing rows', async () => {
    const h = harness();
    h.rows.push({ _id: ID, name: 'legacy', status: 'pending' });
    const response = await request(h.router, 'PUT', `/${ID}`, {
        expectedTopologyRevision: 7, name: 'edited', classicLifecycleGrant: 'b'.repeat(64),
    });
    assert.equal(response.status, 200);
    assert.deepEqual(h.calls.updates[0].changes, { name: 'edited' });
    assert.equal(h.rows[0].classicLifecycleGrant, undefined);
    await withEnv(CLASSIC, async () => {
        const mcp = mcpHarness();
        mcp.rows.push({ _id: ID, name: 'legacy', status: 'pending' });
        await mcp.manageCascade({ action: 'update', id: ID, expectedTopologyRevision: 7,
            data: { name: 'edited', classicLifecycleGrant: 'b'.repeat(64) } });
        assert.deepEqual(mcp.calls.updates[0].changes, { name: 'edited' });
        assert.equal(mcp.rows[0].classicLifecycleGrant, undefined);
    });
});

test('nonclassic HTTP and MCP DELETE share selected intent acceptance without an unsafe raw draft deletion', async () => {
    const env = { ...CLASSIC, CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false' };
    const accepted = [];
    const job = { jobId: '507f1f77bcf86cd799439088', version: 2, kind: 'link.delete', linkId: ID,
        desiredSaved: true, status: 'waiting', acceptanceRevision: 8 };
    const intentService = { async accept(input) { accepted.push(input); return job; } };
    const h = harness({ env, intentService, coordinator: { deleteLink() { assert.fail('native cannot call classic coordinator'); } } });
    const row = { _id: ID, name: 'synthetic', portalNode: PORTAL, bridgeNode: BRIDGE, mode: 'reverse',
        active: true, tunnelPort: 12000, tunnelUuid: '00000000-0000-4000-8000-000000000001' };
    h.rows.push({ ...row });
    const response = await request(h.router, 'DELETE', `/${ID}`, { expectedTopologyRevision: 7 }, { 'Idempotency-Key': 'native-delete' });
    assert.equal(response.status, 202); assert.equal(response.body.job.jobId, job.jobId);
    assert.deepEqual(h.calls.draftDeletes, []); assert.equal(h.rows.length, 1, 'ack is not a cleanup receipt');
    await withEnv(env, async () => {
        const mcp = mcpHarness({ intentService });
        mcp.rows.push({ ...row });
        const result = await mcp.manageCascade({ action: 'delete', id: ID, expectedTopologyRevision: 7, requestKey: 'native-delete' });
        assert.equal(result.accepted, true); assert.equal(result.job.jobId, job.jobId);
        assert.deepEqual(mcp.calls.draftDeletes, []); assert.equal(mcp.rows.length, 1);
        assert.equal(mcp.factoryCalls(), 0);
        const deploy = await mcp.manageCascade({ action: 'deploy', id: ID });
        assert.equal(deploy.code, 'REVISION_SAFE_TOPOLOGY_DEPLOY_REQUIRED');
    });
    assert.equal(accepted.length, 2); assert.deepEqual(accepted[0], accepted[1]);
    assert.deepEqual(accepted[0], { version: 2, kind: 'link.delete', expectedTopologyRevision: 7,
        requestKey: 'native-delete', linkId: ID,
        desiredVersion: require('../../modules/relay-l2tp/services/topologyIntentService').linkDesiredVersion(row) });
});

test('HTTP save-only classic reverse create persists a server-issued durable grant in the draft insert', async () => {
    const h = harness();
    const response = await request(h.router, 'POST', '/', body({ classicLifecycleGrant: 'b'.repeat(64) }));
    assert.equal(response.status, 201);
    const link = h.calls.creates[0].link;
    assert.equal(hasClassicLifecycleGrant(link, CLASSIC), true);
    assert.notEqual(link.classicLifecycleGrant, 'b'.repeat(64));
    assert.equal(h.rows.length, 1);
    // Rehydration in another process requires no in-memory create capability.
    assert.equal(hasClassicLifecycleGrant(JSON.parse(JSON.stringify(h.rows[0])), CLASSIC), true);
});
