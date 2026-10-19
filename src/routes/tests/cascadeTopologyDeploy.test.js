'use strict';

process.env.PANEL_DOMAIN ||= 'panel.test.invalid';
process.env.ACME_EMAIL ||= 'admin@test.invalid';
process.env.ENCRYPTION_KEY ||= 'test-encryption-key-32-characters-long';
process.env.SESSION_SECRET ||= 'test-session-secret';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const express = require('express');
const sshPool = require('../../services/sshPoolService');
test.after(() => sshPool.closeAll());

const {
    createCascadeTopologyDeployRouter,
} = require('../cascadeTopologyDeploy');
const { buildSpec } = require('../../docs/openapi');
const { TopologyOperationCoordinator } = require('../../modules/relay-l2tp/services/topologyOperationCoordinator');

const ROOT_ENTRY_SOURCE = fs.readFileSync(path.resolve(__dirname, '../../../index.js'), 'utf8');
const CASCADE_ROUTE_SOURCE = fs.readFileSync(path.resolve(__dirname, '../cascade.js'), 'utf8');
const CASCADE_MCP_SOURCE = fs.readFileSync(
    path.resolve(__dirname, '../../mcp/tools/cascade.js'),
    'utf8',
);
const OPENAPI_SOURCE = fs.readFileSync(path.resolve(__dirname, '../../docs/openapi.js'), 'utf8');

async function request(router, {
    body = { expectedTopologyRevision: 7 },
    headers = {},
    pathname = '/deploy',
} = {}) {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => {
        if (req.headers['x-test-auth'] === 'api-read') {
            req.apiKey = { keyPrefix: 'test-read', scopes: ['nodes:read'] };
        }
        if (req.headers['x-test-auth'] === 'api-write') {
            req.apiKey = { keyPrefix: 'test-write', scopes: ['nodes:write'] };
        }
        next();
    });
    app.use(router);
    const server = await new Promise(resolve => {
        const candidate = app.listen(0, '127.0.0.1', () => resolve(candidate));
    });
    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${pathname}`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', ...headers },
            body: JSON.stringify(body),
        });
        return { status: response.status, body: await response.json(), headers: response.headers };
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => (error ? reject(error) : resolve()));
        });
    }
}

function guardHarness(calls) {
    return {
        requireAuth(req, res, next) {
            calls.push('auth');
            const auth = req.headers['x-test-auth'];
            if (auth === 'session') {
                req.session = { authenticated: true };
                return next();
            }
            if (auth === 'api-read') {
                req.apiKey = { keyPrefix: 'test-read', scopes: ['nodes:read'] };
                return next();
            }
            if (auth === 'api-write') {
                req.apiKey = { keyPrefix: 'test-write', scopes: ['nodes:write'] };
                return next();
            }
            return res.status(401).json({ error: 'authentication required' });
        },
        requireScope(scope) {
            return (req, res, next) => {
                calls.push(`scope:${scope}`);
                if (req.session?.authenticated || req.apiKey?.scopes?.includes(scope)) return next();
                return res.status(403).json({ error: 'insufficient scope', required: scope });
            };
        },
        csrf(req, res, next) {
            calls.push('csrf');
            if (req.headers['x-test-csrf'] === 'valid') return next();
            return res.status(403).json({ code: 'CSRF_TOKEN_INVALID' });
        },
        deployRateLimiter(req, res, next) {
            calls.push('rate');
            if (req.headers['x-test-rate-limit'] === 'blocked') {
                return res.status(429).json({ error: 'too many deployments' });
            }
            return next();
        },
        operationStatusRateLimiter(req, res, next) {
            calls.push('status-rate');
            if (req.headers['x-test-status-rate-limit'] === 'blocked') {
                return res.status(429).json({ error: 'too many status polls' });
            }
            return next();
        },
    };
}

function runIsolatedProbe(source) {
    const result = spawnSync(process.execPath, ['--eval', source], {
        cwd: path.resolve(__dirname, '../../..'),
        encoding: 'utf8',
        env: process.env,
        timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const output = result.stdout
        .split(/\r?\n/)
        .find(line => line.startsWith('PROBE_RESULT='));
    assert.ok(output, result.stdout);
    return JSON.parse(output.slice('PROBE_RESULT='.length));
}

async function requestOperationStatus(router, { id = '507f1f77bcf86cd799439021', headers = {} } = {}) {
    const app = express();
    app.use(express.json());
    app.use(router);
    const server = await new Promise(resolve => {
        const candidate = app.listen(0, '127.0.0.1', () => resolve(candidate));
    });
    try {
        const response = await fetch(
            `http://127.0.0.1:${server.address().port}/operations/${encodeURIComponent(id)}`,
            { method: 'GET', headers },
        );
        return { status: response.status, body: await response.json(), headers: response.headers };
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => (error ? reject(error) : resolve()));
        });
    }
}

function operationStatusHarness({ document = null, live = null, calls = [], projections = [], stateCalls = [] } = {}) {
    return {
        models: {
            TopologyOperation: {
                async create() {},
                async findOneAndUpdate() {},
                async updateOne() {},
                findById(id) {
                    calls.push(id);
                    return {
                        select(fields) { projections.push(fields); return this; },
                        lean: async () => document,
                    };
                },
            },
            CascadeTopologyState: {
                findById(id) {
                    stateCalls.push(id);
                    return {
                        select(fields) { stateCalls.push(fields); return this; },
                        lean: async () => live,
                    };
                },
            },
        },
        topologyDeploymentService: { async deploy() { return {}; } },
    };
}

test('mounts the deployment boundary without replacing topology transfer registration', () => {
    assert.match(
        ROOT_ENTRY_SOURCE,
        /const topologyTransferDraftsRoutes = require\('\.\/src\/routes\/topologyTransferDrafts'\);/,
    );
    assert.match(
        ROOT_ENTRY_SOURCE,
        /app\.use\('\/api\/cascade\/topology-transfer-drafts', topologyTransferDraftsRoutes\);/,
    );
    assert.match(
        ROOT_ENTRY_SOURCE,
        /const cascadeTopologyDeployRoutes = require\('\.\/src\/routes\/cascadeTopologyDeploy'\);/,
    );
    assert.match(
        ROOT_ENTRY_SOURCE,
        /app\.use\('\/api\/cascade\/topology', cascadeTopologyDeployRoutes\);/,
    );
});

test('deployment API enforces authentication, nodes:write scope, session CSRF, and rate limit', async () => {
    const calls = [];
    const serviceCalls = [];
    const topologyDeploymentService = {
        async deploy(input) {
            serviceCalls.push(input);
            return {
                operationId: 'operation-safe',
                topologyRevision: 7,
                deployedRevision: 7,
                nodeEvidence: [],
            };
        },
    };
    const router = createCascadeTopologyDeployRouter({
        topologyDeploymentService,
        ...guardHarness(calls),
    });

    const unauthenticated = await request(router);
    assert.equal(unauthenticated.status, 401);
    assert.deepEqual(calls, ['auth']);

    calls.length = 0;
    const wrongScope = await request(router, { headers: { 'x-test-auth': 'api-read' } });
    assert.equal(wrongScope.status, 403);
    assert.equal(wrongScope.body.required, 'nodes:write');
    assert.deepEqual(calls, ['auth', 'scope:nodes:write']);

    calls.length = 0;
    const missingCsrf = await request(router, { headers: { 'x-test-auth': 'session' } });
    assert.equal(missingCsrf.status, 403);
    assert.equal(missingCsrf.body.code, 'CSRF_TOKEN_INVALID');
    assert.deepEqual(calls, ['auth', 'scope:nodes:write', 'csrf']);

    calls.length = 0;
    const rateLimited = await request(router, {
        headers: {
            'x-test-auth': 'session',
            'x-test-csrf': 'valid',
            'x-test-rate-limit': 'blocked',
        },
    });
    assert.equal(rateLimited.status, 429);
    assert.deepEqual(calls, ['auth', 'scope:nodes:write', 'csrf', 'rate']);

    calls.length = 0;
    const allowedSession = await request(router, {
        headers: { 'x-test-auth': 'session', 'x-test-csrf': 'valid' },
    });
    assert.equal(allowedSession.status, 200);
    assert.equal(allowedSession.body.operationId, 'operation-safe');
    assert.deepEqual(calls, ['auth', 'scope:nodes:write', 'csrf', 'rate']);

    calls.length = 0;
    const allowedApiKey = await request(router, { headers: { 'x-test-auth': 'api-write' } });
    assert.equal(allowedApiKey.status, 200);
    assert.equal(allowedApiKey.body.operationId, 'operation-safe');
    assert.deepEqual(calls, ['auth', 'scope:nodes:write', 'rate']);
    assert.deepEqual(serviceCalls, [
        { expectedTopologyRevision: 7 },
        { expectedTopologyRevision: 7 },
    ]);
});

test('replacement API queues only an explicit scoped migration behind write guards', async () => {
    const ids = ['a', 'b', 'c', 'd'].map(char => char.repeat(24));
    const body = { expectedTopologyRevision: 7, groupId: ids[0], pathKey: 'main',
        oldLinkId: ids[1], newLinkId: ids[2], linkIds: [ids[2], ids[3]] };
    const calls = [];
    const queueInputs = [];
    const router = createCascadeTopologyDeployRouter({
        ...guardHarness(calls),
        topologyDeploymentService: {
            async deploy() { assert.fail('replacement cannot run full Sync'); },
            async queue(input) {
                queueInputs.push(input);
                return { operationId: ids[0], topologyRevision: 7, status: 'queued' };
            },
        },
    });
    assert.equal((await request(router, { pathname: '/replace', body })).status, 401);
    assert.equal((await request(router, { pathname: '/replace', body,
        headers: { 'x-test-auth': 'session' } })).status, 403);
    assert.deepEqual(queueInputs, []);
    const result = await request(router, { pathname: '/replace', body,
        headers: { 'x-test-auth': 'session', 'x-test-csrf': 'valid' } });
    assert.equal(result.status, 202);
    assert.deepEqual(result.body, { operationId: ids[0], topologyRevision: 7,
        status: 'queued', kind: 'link.replace' });
    assert.deepEqual(queueInputs, [{ expectedTopologyRevision: 7, scope: {
        kind: 'link.replace', linkId: ids[2], linkIds: [ids[2], ids[3]],
        oldLinkId: ids[1], groupId: ids[0], pathKey: 'main',
    } }]);
    const malformed = await request(router, { pathname: '/replace',
        body: { ...body, linkIds: [ids[2], ids[1]] },
        headers: { 'x-test-auth': 'api-write' } });
    assert.equal(malformed.status, 400);
    assert.equal(queueInputs.length, 1);
});

test('per-link deploy queues only the selected link and applied component, never an old pending edge', async () => {
    const selectedId = '507f1f77bcf86cd799439011';
    const appliedId = '507f1f77bcf86cd799439012';
    const pendingId = '507f1f77bcf86cd799439013';
    const calls = [];
    const queueInputs = [];
    const links = [
        { _id: selectedId, portalNode: 'p2', bridgeNode: 'r', active: true, status: 'pending' },
        { _id: appliedId, portalNode: 'r', bridgeNode: 'b', active: true, status: 'deployed' },
        { _id: pendingId, portalNode: 'p3', bridgeNode: 'r', active: true, status: 'pending' },
    ];
    const router = createCascadeTopologyDeployRouter({
        models: {
            CascadeLink: {
                find() { return { select() { return { lean: async () => links }; } }; },
            },
        },
        topologyDeploymentService: {
            async deploy() { assert.fail('per-link request must not call global deploy'); },
            async queue(input) {
                queueInputs.push(input);
                return { operationId: '507f1f77bcf86cd799439021', status: 'queued', topologyRevision: 7 };
            },
        },
        ...guardHarness(calls),
    });
    const response = await request(router, {
        body: { expectedTopologyRevision: 7, linkId: selectedId },
        headers: { 'x-test-auth': 'api-write' },
    });
    assert.equal(response.status, 202);
    assert.deepEqual(queueInputs, [{
        expectedTopologyRevision: 7,
        scope: { kind: 'link.apply', linkId: selectedId, linkIds: [selectedId, appliedId] },
    }]);
    assert.equal(response.body.operationId, '507f1f77bcf86cd799439021');
    assert.equal(response.body.status, 'queued');
});

test('manual domain Sync queues only the chosen confirmed component, not another domain or pending link', async () => {
    const selectedId = '507f1f77bcf86cd799439011';
    const companionId = '507f1f77bcf86cd799439012';
    const otherId = '507f1f77bcf86cd799439013';
    const pendingId = '507f1f77bcf86cd799439014';
    const inputs = [];
    const links = [
        { _id: selectedId, portalNode: 'p1', bridgeNode: 'r1', active: true, status: 'online', mode: 'forward' },
        { _id: companionId, portalNode: 'r1', bridgeNode: 'b1', active: true, status: 'staged', mode: 'reverse' },
        { _id: pendingId, portalNode: 'p3', bridgeNode: 'r1', active: true, status: 'pending' },
        { _id: otherId, portalNode: 'p2', bridgeNode: 'b2', active: true, status: 'deployed' },
    ];
    const router = createCascadeTopologyDeployRouter({
        models: { CascadeLink: { find() { return { select() { return { lean: async () => links }; } }; } } },
        topologyDeploymentService: {
            async deploy() { assert.fail('domain Sync must not call full deploy'); },
            async queue(input) {
                inputs.push(input);
                return { operationId: '507f1f77bcf86cd799439021', topologyRevision: 7, status: 'queued' };
            },
        },
        ...guardHarness([]),
    });
    const response = await request(router, {
        body: { expectedTopologyRevision: 7, domainLinkId: selectedId },
        headers: { 'x-test-auth': 'api-write' },
    });
    assert.equal(response.status, 202);
    assert.equal(response.body.kind, 'domain.reconcile');
    assert.deepEqual(inputs, [{ expectedTopologyRevision: 7, scope: {
        kind: 'domain.reconcile', linkId: selectedId, linkIds: [selectedId, companionId],
    } }]);
});

test('manual domain Sync traverses the route and pinned coordinator without enrolling old pending links', async () => {
    const anchor = '507f1f77bcf86cd799439011';
    const companion = '507f1f77bcf86cd799439012';
    const pending = '507f1f77bcf86cd799439013';
    const independent = '507f1f77bcf86cd799439014';
    const links = [
        { _id: anchor, portalNode: 'p1', bridgeNode: 'r1', active: true, status: 'online', mode: 'forward' },
        { _id: companion, portalNode: 'r1', bridgeNode: 'b1', active: true, status: 'staged', mode: 'reverse' },
        { _id: pending, portalNode: 'p3', bridgeNode: 'r1', active: true, status: 'pending', mode: 'reverse' },
        { _id: independent, portalNode: 'p2', bridgeNode: 'b2', active: true, status: 'deployed', mode: 'reverse' },
    ];
    const snapshot = {
        revision: 7, deployedRevision: 5, links,
        nodes: ['p1', 'r1', 'b1', 'p3', 'p2', 'b2'].map(_id => ({ _id, cascadeRole: 'relay' })),
        groups: [],
    };
    const materialized = [];
    const frozen = [];
    const session = { inTransaction: () => true };
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: { async admitTopology({ expectedRevision, prepare, admit }) {
            assert.equal(expectedRevision, 7);
            const pinned = { revision: 7, deployedRevision: 5, ...await prepare(snapshot, session) };
            await admit(pinned, session);
            return pinned;
        } },
        planMaterializer: { async materialize(input) {
            materialized.push(input);
            return { nodes: [] };
        } },
        operationRepository: { async createFrozen(input) { frozen.push(input); } },
        operationWorker: { async run() {} },
        validator: () => ({ valid: true }),
        compiler: () => ({ valid: true }),
    });
    const router = createCascadeTopologyDeployRouter({
        models: { CascadeLink: { find() { return { select() { return { lean: async () => links }; } }; } } },
        topologyDeploymentService: coordinator,
        ...guardHarness([]),
    });
    const response = await request(router, {
        body: { expectedTopologyRevision: 7, domainLinkId: anchor },
        headers: { 'x-test-auth': 'api-write' },
    });
    assert.equal(response.status, 202);
    assert.equal(response.body.kind, 'domain.reconcile');
    assert.equal(materialized.length, 1);
    assert.strictEqual(materialized[0].session, session);
    assert.equal(materialized[0].operationKind, 'domain.reconcile');
    assert.deepEqual(materialized[0].pinnedSnapshot.topology.links.map(link => [link.id, link.mode]),
        [[anchor, 'forward'], [companion, 'reverse']]);
    assert.deepEqual(materialized[0].pinnedSnapshot.topology.nodes.map(node => node.id),
        ['b1', 'p1', 'r1']);
    assert.deepEqual(frozen.map(input => [input.kind, input.linkIds]),
        [['domain.reconcile', [anchor, companion]]]);
    assert.strictEqual(frozen[0].session, session);
    assert.equal(frozen[0].heldTopologyAdmission, true);
    assert.match(frozen[0].admissionFingerprint, /^[a-f0-9]{64}$/);
});

test('manual domain Sync refuses a pending anchor and ambiguous request before queue', async () => {
    const pendingId = '507f1f77bcf86cd799439014';
    const router = createCascadeTopologyDeployRouter({
        models: { CascadeLink: { find() { return { select() { return { lean: async () => [
            { _id: pendingId, portalNode: 'p', bridgeNode: 'b', active: true, status: 'pending' },
        ] }; } }; } } },
        topologyDeploymentService: {
            async deploy() { assert.fail('must not deploy'); },
            async queue() { assert.fail('must not queue'); },
        }, ...guardHarness([]),
    });
    const headers = { 'x-test-auth': 'api-write' };
    const pending = await request(router, { body: { expectedTopologyRevision: 7, domainLinkId: pendingId }, headers });
    assert.equal(pending.status, 422);
    assert.equal(pending.body.error.code, 'INVALID_TOPOLOGY_DEPLOYMENT');
    const ambiguous = await request(router, { body: {
        expectedTopologyRevision: 7, domainLinkId: pendingId, linkId: pendingId,
    }, headers });
    assert.equal(ambiguous.status, 400);
});

test('per-link deploy does not expose backend failure text in response or log', async () => {
    const selectedId = '507f1f77bcf86cd799439011';
    const logged = [];
    const router = createCascadeTopologyDeployRouter({
        models: { CascadeLink: {
            find() { return { select() { return { lean: async () => [
                { _id: selectedId, portalNode: 'p', bridgeNode: 'r', active: true, status: 'pending' },
            ] }; } }; },
        } },
        topologyDeploymentService: {
            async deploy() { assert.fail('global deploy must not run'); },
            async queue() {
                const error = new Error('password=short-secret');
                error.code = 'TOPOLOGY_OPERATION_QUEUE_FAILED';
                throw error;
            },
        },
        routeLogger: { error(message) { logged.push(message); } },
        ...guardHarness([]),
    });
    const response = await request(router, {
        body: { expectedTopologyRevision: 7, linkId: selectedId },
        headers: { 'x-test-auth': 'api-write' },
    });
    assert.equal(response.status, 500);
    assert.equal(response.body.error.code, 'TOPOLOGY_OPERATION_QUEUE_FAILED');
    assert.doesNotMatch(JSON.stringify(response.body) + logged.join(' '), /short-secret|password=/);
});

test('known deployment slot contention returns safe 409 with explicit retry guidance', async () => {
    const selectedId = '507f1f77bcf86cd799439011';
    const router = createCascadeTopologyDeployRouter({
        models: { CascadeLink: {
            find() { return { select() { return { lean: async () => [
                { _id: selectedId, portalNode: 'p', bridgeNode: 'r', active: true, status: 'pending' },
            ] }; } }; },
        } },
        topologyDeploymentService: {
            async deploy() { assert.fail('global deploy must not run'); },
            async queue() {
                const error = new Error('password=never-leak');
                error.code = 'TOPOLOGY_DEPLOY_BUSY';
                error.retryable = true;
                throw error;
            },
        },
        ...guardHarness([]),
    });
    const response = await request(router, {
        body: { expectedTopologyRevision: 7, linkId: selectedId },
        headers: { 'x-test-auth': 'api-write' },
    });
    assert.equal(response.status, 409);
    assert.equal(response.body.error.code, 'TOPOLOGY_DEPLOY_BUSY');
    assert.equal(response.body.error.retryable, true);
    assert.doesNotMatch(JSON.stringify(response.body), /never-leak|password=/);
});

test('per-link deploy rejects malformed or disabled links without queueing', async () => {
    const disabledId = '507f1f77bcf86cd799439019';
    let reads = 0;
    const router = createCascadeTopologyDeployRouter({
        models: { CascadeLink: {
            find() {
                reads += 1;
                return { select() { return { lean: async () => [
                    { _id: disabledId, portalNode: 'p', bridgeNode: 'r', active: false, status: 'pending' },
                ] }; } };
            },
        } },
        topologyDeploymentService: {
            async deploy() { assert.fail('global deploy must not run'); },
            async queue() { assert.fail('disabled link must not queue'); },
        },
        ...guardHarness([]),
    });
    const headers = { 'x-test-auth': 'api-write' };
    const invalid = await request(router, {
        body: { expectedTopologyRevision: 7, linkId: 'not-an-id' }, headers,
    });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.body.error.code, 'INVALID_LINK_ID');
    assert.equal(reads, 0);
    const disabled = await request(router, {
        body: { expectedTopologyRevision: 7, linkId: disabledId }, headers,
    });
    assert.equal(disabled.status, 409);
    assert.equal(disabled.body.error.code, 'CASCADE_LINK_DISABLED');
});

test('default deployment rate limiter caps the boundary at ten requests per minute', async () => {
    const calls = [];
    let serviceCalls = 0;
    const guards = guardHarness(calls);
    delete guards.deployRateLimiter;
    const router = createCascadeTopologyDeployRouter({
        topologyDeploymentService: {
            async deploy() {
                serviceCalls += 1;
                return {
                    operationId: `operation-${serviceCalls}`,
                    topologyRevision: 7,
                    deployedRevision: 7,
                    nodeEvidence: [],
                };
            },
        },
        ...guards,
    });

    let response;
    for (let requestNumber = 1; requestNumber <= 11; requestNumber += 1) {
        response = await request(router, { headers: { 'x-test-auth': 'api-write' } });
        assert.equal(response.status, requestNumber <= 10 ? 200 : 429, `request ${requestNumber}`);
    }

    assert.deepEqual(response.body, {
        error: {
            code: 'TOPOLOGY_DEPLOY_RATE_LIMITED',
            message: 'Too many topology deployment requests',
        },
    });
    assert.equal(response.headers.get('ratelimit-limit'), '10');
    assert.equal(serviceCalls, 10);
});

test('deployment API rejects non-versioned or command-shaped requests before the service', async () => {
    const serviceCalls = [];
    const calls = [];
    const router = createCascadeTopologyDeployRouter({
        topologyDeploymentService: {
            async deploy(input) {
                serviceCalls.push(input);
                return {};
            },
        },
        ...guardHarness(calls),
    });
    const headers = { 'x-test-auth': 'api-write' };

    const missingRevision = await request(router, { body: {}, headers });
    assert.equal(missingRevision.status, 400);
    assert.equal(missingRevision.body.error.code, 'INVALID_TOPOLOGY_REVISION');

    const rawCommand = await request(router, {
        body: { expectedTopologyRevision: 7, command: 'systemctl restart xray' },
        headers,
    });
    assert.equal(rawCommand.status, 400);
    assert.equal(rawCommand.body.error.code, 'INVALID_REQUEST');
    assert.deepEqual(serviceCalls, []);
});

test('deployment API maps replacement reservation from the pinned coordinator to safe 409 for full and scoped requests', async () => {
    const linkId = '507f1f77bcf86cd799439011';
    const operationId = '507f1f77bcf86cd799439021';
    const headers = { 'x-test-auth': 'api-write' };
    for (const scope of [{}, { linkId }, { domainLinkId: linkId }]) {
        let admissionCalls = 0;
        let materializeCalls = 0;
        let createCalls = 0;
        const coordinator = new TopologyOperationCoordinator({
            topologyRepository: { async admitTopology({ expectedRevision }) {
                admissionCalls += 1;
                assert.equal(expectedRevision, 7);
                const error = new Error('reservation token=private-pin-secret');
                error.code = 'TOPOLOGY_REPLACEMENT_RESERVED';
                error.token = 'private-pin-secret';
                error.body = { password: 'private-body-secret' };
                error.diagnostic = 'private-diagnostic-secret';
                throw error;
            } },
            planMaterializer: { async materialize() { materializeCalls += 1; } },
            operationRepository: { async createFrozen() { createCalls += 1; } },
            idFactory: () => operationId,
        });
        const router = createCascadeTopologyDeployRouter({
            models: { CascadeLink: { find() { return { select() { return { lean: async () => [
                { _id: linkId, portalNode: 'p', bridgeNode: 'b', active: true, status: 'deployed' },
            ] }; } }; } } },
            topologyDeploymentService: coordinator,
            ...guardHarness([]),
        });
        const response = await request(router, {
            body: { expectedTopologyRevision: 7, ...scope }, headers,
        });
        assert.equal(response.status, 409, JSON.stringify(scope));
        assert.deepEqual(response.body, {
            error: {
                code: 'TOPOLOGY_REPLACEMENT_RESERVED',
                message: 'A topology replacement owns the deployment pin fence',
            },
            operationId,
            expectedTopologyRevision: 7,
        });
        assert.doesNotMatch(JSON.stringify(response.body), /token|body|password|diagnostic|private|queued|kind/i);
        assert.equal(admissionCalls, 1);
        assert.equal(materializeCalls, 0);
        assert.equal(createCalls, 0);
    }
});

test('deployment API keeps unknown service errors generic 500', async () => {
    const router = createCascadeTopologyDeployRouter({
        topologyDeploymentService: { async deploy() {
            const error = new Error('password=private-secret');
            error.code = 'UNEXPECTED_BACKEND_ERROR';
            error.token = 'private-token';
            throw error;
        } },
        routeLogger: { error(message) { assert.equal(message, '[Cascade Topology Deploy API] INTERNAL_ERROR'); } },
        ...guardHarness([]),
    });
    const response = await request(router, { headers: { 'x-test-auth': 'api-write' } });
    assert.equal(response.status, 500);
    assert.deepEqual(response.body, {
        error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
    assert.doesNotMatch(JSON.stringify(response.body), /private|password|token|UNEXPECTED_BACKEND_ERROR/);
});

test('deployment API maps stale revisions safely without leaking deployment internals', async () => {
    const calls = [];
    const router = createCascadeTopologyDeployRouter({
        topologyDeploymentService: {
            async deploy() {
                const error = new Error('The topology revision changed before deployment');
                error.code = 'STALE_TOPOLOGY_REVISION';
                error.operationId = 'operation-stale';
                error.expectedTopologyRevision = 6;
                error.topologyRevision = 7;
                error.rollbackToken = 'must-not-leak';
                error.diagnostic = 'ssh password must not leak';
                throw error;
            },
        },
        ...guardHarness(calls),
    });

    const response = await request(router, {
        body: { expectedTopologyRevision: 6 },
        headers: { 'x-test-auth': 'api-write' },
    });

    assert.equal(response.status, 409);
    assert.deepEqual(response.body, {
        error: {
            code: 'STALE_TOPOLOGY_REVISION',
            message: 'The topology revision changed before deployment',
        },
        operationId: 'operation-stale',
        expectedTopologyRevision: 6,
        topologyRevision: 7,
    });
    assert.doesNotMatch(JSON.stringify(response.body), /rollbackToken|password|diagnostic/);
});

test('default models satisfy the topology runtime wiring contract', () => {
    const relayL2tpModule = require('../../modules/relay-l2tp');
    const {
        unavailableTopologyDeploymentService,
    } = require('../../modules/relay-l2tp/services/topologyDeploymentService');
    const { DEFAULT_MODELS } = require('../cascadeTopologyDeploy');
    const service = relayL2tpModule.createTopologyDeploymentService({
        ...DEFAULT_MODELS,
        env: {
            L2TP_EXECUTION_ENABLED: 'true',
            L2TP_MIGRATIONS_ENABLED: 'true',
            TOPOLOGY_TEST_EXECUTION_ENABLED: 'true',
        },
    });
    assert.notStrictEqual(service, unavailableTopologyDeploymentService);
    assert.strictEqual(typeof service.deploy, 'function');
});

test('deployment API uses the module factory and returns a safe unavailable response', async () => {
    const calls = [];
    const models = { marker: 'default-topology-models' };
    let factoryDependencies;
    const router = createCascadeTopologyDeployRouter({
        createService(dependencies) {
            factoryDependencies = dependencies;
            return {
                async deploy() {
                    const error = new Error('Topology deployment capabilities are unavailable');
                    error.code = 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE';
                    error.registrationDetails = 'must-not-leak';
                    throw error;
                },
            };
        },
        models,
        ...guardHarness(calls),
    });

    const response = await request(router, {
        headers: { 'x-test-auth': 'api-write' },
    });

    assert.strictEqual(factoryDependencies, models);
    assert.equal(response.status, 503);
    assert.deepEqual(response.body, {
        error: {
            code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE',
            message: 'Topology deployment capabilities are unavailable',
        },
    });
    assert.doesNotMatch(JSON.stringify(response.body), /registrationDetails|must-not-leak/);
});

test('deployment API returns only the public deployment evidence contract', async () => {
    const calls = [];
    const router = createCascadeTopologyDeployRouter({
        topologyDeploymentService: {
            async deploy() {
                return {
                    operationId: 'operation-public',
                    topologyRevision: 7,
                    deployedRevision: 7,
                    nodeEvidence: [{
                        nodeId: 'node-1',
                        deploymentEvidenceId: 'deployment-public',
                        verificationEvidenceId: 'verification-public',
                        rollbackToken: 'must-not-leak',
                    }],
                    compiledTopology: { internalSecret: 'must-not-leak' },
                    diagnostic: 'ssh password must not leak',
                };
            },
        },
        ...guardHarness(calls),
    });

    const response = await request(router, {
        headers: { 'x-test-auth': 'api-write' },
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {
        operationId: 'operation-public',
        topologyRevision: 7,
        deployedRevision: 7,
        nodeEvidence: [{
            nodeId: 'node-1',
            deploymentEvidenceId: 'deployment-public',
            verificationEvidenceId: 'verification-public',
        }],
    });
    assert.doesNotMatch(
        JSON.stringify(response.body),
        /rollbackToken|compiledTopology|internalSecret|diagnostic|password/,
    );
});

test('deployment API returns 202 with only the strict queued operation projection', async () => {
    const calls = [];
    const router = createCascadeTopologyDeployRouter({
        topologyDeploymentService: {
            async deploy(input) {
                calls.push(input);
                return {
                    operationId: 'operation-queued',
                    topologyRevision: 7,
                    status: 'queued',
                    candidates: [{ bytes: 'candidate-secret' }],
                    compiledTopology: { password: 'must-not-leak' },
                };
            },
        },
        ...guardHarness([]),
    });

    const response = await request(router, {
        headers: { 'x-test-auth': 'api-write' },
    });

    assert.equal(response.status, 202);
    assert.deepEqual(response.body, {
        operationId: 'operation-queued',
        topologyRevision: 7,
        status: 'queued',
    });
    assert.deepEqual(calls, [{ expectedTopologyRevision: 7 }]);
    assert.doesNotMatch(JSON.stringify(response.body), /candidate|compiled|password|secret/i);
});

test('legacy deploy entry points are fail-closed while explicit undeploy remains separate', () => {
    assert.doesNotMatch(CASCADE_ROUTE_SOURCE, /cascadeService\.deployChain\s*\(/);
    assert.doesNotMatch(CASCADE_ROUTE_SOURCE, /cascadeService\.deployLink\s*\(/);
    assert.doesNotMatch(CASCADE_ROUTE_SOURCE, /req\.body\.autoDeploy|req\.body\.autoRedeploy/);
    assert.match(CASCADE_ROUTE_SOURCE, /LEGACY_CASCADE_DEPLOY_DISABLED/);
    assert.match(
        CASCADE_ROUTE_SOURCE,
        /router\.post\('\/links\/:id\/undeploy',[\s\S]*withLegacyCascadeUndeploy\([\s\S]*cascadeService\.undeployLink\(current\)/,
    );
    assert.equal((CASCADE_ROUTE_SOURCE.match(/cascadeService\.undeployLink\s*\(/g) || []).length, 1);
});

test('undeploy delegates to exact ownership without deleting durable operation history', () => {
    const start = CASCADE_ROUTE_SOURCE.indexOf("router.post('/links/:id/undeploy'");
    assert.notStrictEqual(start, -1, 'undeploy route must exist');
    const end = CASCADE_ROUTE_SOURCE.indexOf('router.', start + 1);
    const undeploy = CASCADE_ROUTE_SOURCE.slice(start, end === -1 ? undefined : end);
    assert.match(undeploy, /withLegacyCascadeUndeploy\(/,
        'undeploy must acquire the shared quiescence and ownership fence before teardown');
    assert.doesNotMatch(undeploy, /TopologyOperation\.deleteMany\(|CascadeTopologyState\.findOneAndUpdate\(/,
        'the legacy route must neither erase queue bindings nor reset deployed state outside the ownership fence');
});

test('legacy chain deployment is absent from docs and rejected by the live REST router', () => {
    const response = runIsolatedProbe(`
        const express = require('express');
        const router = require('./src/routes/cascade');
        const app = express();
        app.use(express.json());
        app.use((req, res, next) => {
            req.apiKey = { keyPrefix: 'test-write', scopes: ['nodes:write'] };
            next();
        });
        app.use(router);
        const server = app.listen(0, '127.0.0.1', async () => {
            const result = await fetch(
                \`http://127.0.0.1:\${server.address().port}/chain/deploy\`,
                {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify({ linkId: '507f1f77bcf86cd799439021' }),
                },
            );
            const body = await result.json();
            console.log('PROBE_RESULT=' + JSON.stringify({ status: result.status, body }));
            server.close(() => process.exit(0));
        });
    `);

    assert.equal(response.status, 410);
    assert.deepEqual(response.body, {
        error: {
            code: 'LEGACY_CASCADE_DEPLOY_DISABLED',
            message: 'Use POST /api/cascade/topology/deploy with expectedTopologyRevision',
        },
    });
    assert.equal(buildSpec('en').paths['/cascade/chain/deploy'], undefined);
});

test('MCP cascade mutations cannot bypass the revision-safe deploy boundary', () => {
    assert.doesNotMatch(CASCADE_MCP_SOURCE, /cascadeService\.deployLink\s*\(/);
    assert.match(CASCADE_MCP_SOURCE, /REVISION_SAFE_TOPOLOGY_DEPLOY_REQUIRED/);
    assert.equal((CASCADE_MCP_SOURCE.match(/cascadeService\.undeployLink\s*\(/g) || []).length, 1);
    const results = runIsolatedProbe(`
        const { manageCascade } = require('./src/mcp/tools/cascade');
        Promise.all([
            manageCascade({ action: 'deploy' }, () => {}),
            manageCascade({ action: 'reconnect' }, () => {}),
        ]).then(values => {
            console.log('PROBE_RESULT=' + JSON.stringify(values));
            process.exit(0);
        });
    `);
    assert.deepEqual(results, [{
        success: false,
        code: 'REVISION_SAFE_TOPOLOGY_DEPLOY_REQUIRED',
        error: 'Use POST /api/cascade/topology/deploy with expectedTopologyRevision',
    }, {
        success: false,
        code: 'REVISION_SAFE_TOPOLOGY_DEPLOY_REQUIRED',
        error: 'Reconnect the topology draft, then deploy its exact revision',
    }]);
});

test('operation status endpoint enforces authentication, nodes:read scope, and status rate limit', async () => {
    const calls = [];
    const findCalls = [];
    const document = {
        _id: '507f1f77bcf86cd799439021',
        topologyRevision: 7,
        status: 'queued',
    };
    const router = createCascadeTopologyDeployRouter({
        ...operationStatusHarness({ document, calls: findCalls }),
        ...guardHarness(calls),
    });

    const unauthenticated = await requestOperationStatus(router);
    assert.equal(unauthenticated.status, 401);
    assert.deepEqual(calls, ['auth']);

    calls.length = 0;
    const readKey = await requestOperationStatus(router, { headers: { 'x-test-auth': 'api-read' } });
    assert.equal(readKey.status, 200);
    assert.deepEqual(calls, ['auth', 'scope:nodes:read', 'status-rate']);

    calls.length = 0;
    const session = await requestOperationStatus(router, { headers: { 'x-test-auth': 'session' } });
    assert.equal(session.status, 200);
    assert.deepEqual(calls, ['auth', 'scope:nodes:read', 'status-rate']);

    calls.length = 0;
    const rateLimited = await requestOperationStatus(router, {
        headers: { 'x-test-auth': 'api-read', 'x-test-status-rate-limit': 'blocked' },
    });
    assert.equal(rateLimited.status, 429);
    assert.deepEqual(calls, ['auth', 'scope:nodes:read', 'status-rate']);

    // Read-only polling must never trip CSRF or the deploy rate limiter.
    assert.ok(!calls.includes('csrf'));
    assert.ok(!calls.includes('rate'));
    assert.deepEqual(findCalls, ['507f1f77bcf86cd799439021', '507f1f77bcf86cd799439021']);
});

test('operation status endpoint rejects malformed operation ids before touching the model', async () => {
    const findCalls = [];
    const router = createCascadeTopologyDeployRouter({
        ...operationStatusHarness({ calls: findCalls }),
        ...guardHarness([]),
    });
    const headers = { 'x-test-auth': 'api-read' };

    for (const id of ['not-an-object-id', '507f1f77bcf86cd79943902', '507f1f77bcf86cd7994390210', 'zz7f1f77bcf86cd799439021']) {
        const response = await requestOperationStatus(router, { id, headers });
        assert.equal(response.status, 400, id);
        assert.equal(response.body.error.code, 'INVALID_OPERATION_ID', id);
    }
    assert.deepEqual(findCalls, []);
});

test('operation status endpoint returns 404 for an unknown operation', async () => {
    const router = createCascadeTopologyDeployRouter({
        ...operationStatusHarness({ document: null }),
        ...guardHarness([]),
    });

    const response = await requestOperationStatus(router, { headers: { 'x-test-auth': 'api-read' } });
    assert.equal(response.status, 404);
    assert.equal(response.body.error.code, 'OPERATION_NOT_FOUND');
});

test('operation status endpoint returns only the strict public projection', async () => {
    const projections = [];
    const document = {
        _id: '507f1f77bcf86cd799439021',
        topologyRevision: 7,
        priorDeployedRevision: 6,
        deployedRevision: 7,
        status: 'committing',
        kind: 'link.apply',
        causeCode: 'SCOPE_LINK_UNCONFIRMED',
        reason: 'SCOPE_BASELINE_STALE',
        plan: { steps: [{ artifacts: 'must-not-leak' }] },
        reality: { fingerprint: 'must-not-leak' },
        user: 'must-not-leak',
        credentials: { password: 'must-not-leak' },
        nodes: [{
            node: '507f1f77bcf86cd799439099',
            candidate: { bytes: [1, 2, 3], sha256: 'candidate-secret' },
            candidateHash: 'candidate-secret',
        }],
        logs: [{ level: 'error', message: 'ssh password must-not-leak' }],
        leaseOwner: 'worker-host-identity',
        idempotencyKey: 'must-not-leak',
        __v: 0,
    };
    const router = createCascadeTopologyDeployRouter({
        ...operationStatusHarness({ document, projections }),
        ...guardHarness([]),
    });

    const response = await requestOperationStatus(router, { headers: { 'x-test-auth': 'api-read' } });
    assert.equal(response.status, 200);
    assert.deepEqual(projections, [
        'status topologyRevision priorDeployedRevision kind clientReadiness clientProofRevision clientProofState clientProofReason',
    ]);
    assert.deepEqual(response.body, {
        operationId: '507f1f77bcf86cd799439021',
        status: 'committing',
        topologyRevision: 7,
        clientReadiness: 'unverified',
    });
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.doesNotMatch(
        JSON.stringify(response.body),
        /plan|candidate|reality|user|credential|password|logs|leaseOwner|idempotency|must-not-leak|secret/i,
    );
});

test('operation status exposes verified client proof only for a live scoped revision', async () => {
    const stateCalls = [];
    const projections = [];
    const id = '507f1f77bcf86cd799439021';
    const router = createCascadeTopologyDeployRouter({
        ...operationStatusHarness({
            document: {
                _id: id, status: 'succeeded', topologyRevision: 7, priorDeployedRevision: 6,
                kind: 'link.apply', clientReadiness: 'verified', clientProofRevision: 7,
                nodes: [{ candidate: { bytes: 'secret' } }],
                clientProofReason: 'password=secret',
            },
            live: { revision: 7, deployedRevision: 6 }, stateCalls, projections,
        }),
        ...guardHarness([]),
    });
    const response = await requestOperationStatus(router, { headers: { 'x-test-auth': 'api-read' } });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {
        operationId: id, status: 'succeeded', topologyRevision: 7, clientReadiness: 'verified',
    });
    assert.deepEqual(stateCalls, ['singleton', 'revision deployedRevision']);
    assert.deepEqual(projections, [
        'status topologyRevision priorDeployedRevision kind clientReadiness clientProofRevision clientProofState clientProofReason',
    ]);
    assert.doesNotMatch(JSON.stringify(response.body), /secret|candidate|nodes|clientProofReason/);
});

test('operation status does not claim verified proof for stale, absent, or inconsistent state', async () => {
    const id = '507f1f77bcf86cd799439021';
    const headers = { 'x-test-auth': 'api-read' };
    for (const [live, proofRevision] of [
        [{ revision: 8, deployedRevision: 6 }, 7],
        [{ revision: 7, deployedRevision: 7 }, 7],
        [null, 7],
        [{ revision: 7, deployedRevision: 6 }, 5],
    ]) {
        const router = createCascadeTopologyDeployRouter({
            ...operationStatusHarness({
                document: { _id: id, status: 'succeeded', topologyRevision: 7,
                    priorDeployedRevision: 6, kind: 'link.apply', clientReadiness: 'verified',
                    clientProofRevision: proofRevision },
                live,
            }),
            ...guardHarness([]),
        });
        const response = await requestOperationStatus(router, { headers });
        assert.equal(response.status, 200);
        assert.deepEqual(response.body, { operationId: id, status: 'succeeded',
            topologyRevision: 7, clientReadiness: 'unverified' });
    }
});

test('operation status exposes only allowlisted unverified proof state, not arbitrary reasons', async () => {
    const id = '507f1f77bcf86cd799439021';
    const headers = { 'x-test-auth': 'api-read' };
    for (const [clientProofState, expected] of [
        ['active_unverified', 'active_unverified'],
        ['degraded', 'degraded'],
        ['password=secret', undefined],
    ]) {
        const router = createCascadeTopologyDeployRouter({
            ...operationStatusHarness({ document: {
                _id: id, status: 'succeeded', topologyRevision: 7,
                clientReadiness: 'unverified', clientProofState,
                clientProofReason: 'ssh password=secret', nodes: [{ candidate: 'secret' }],
            } }), ...guardHarness([]),
        });
        const response = await requestOperationStatus(router, { headers });
        assert.equal(response.status, 200);
        assert.deepEqual(response.body, { operationId: id, status: 'succeeded',
            topologyRevision: 7, clientReadiness: 'unverified',
            ...(expected ? { clientProofState: expected } : {}) });
        assert.doesNotMatch(JSON.stringify(response.body), /secret|candidate|nodes|clientProofReason/);
    }
});

test('operation status requires deployed revision for global proof', async () => {
    const id = '507f1f77bcf86cd799439021';
    const headers = { 'x-test-auth': 'api-read' };
    for (const [deployedRevision, readiness] of [[6, 'unverified'], [7, 'verified']]) {
        const router = createCascadeTopologyDeployRouter({
            ...operationStatusHarness({
                document: { _id: id, status: 'succeeded', topologyRevision: 7,
                    clientReadiness: 'verified', clientProofRevision: 7 },
                live: { revision: 7, deployedRevision },
            }), ...guardHarness([]),
        });
        const response = await requestOperationStatus(router, { headers });
        assert.equal(response.status, 200);
        assert.deepEqual(response.body, { operationId: id, status: 'succeeded',
            topologyRevision: 7, clientReadiness: readiness });
    }
});

test('operation status keeps internal model errors generic without logging secrets', async () => {
    const logged = [];
    const router = createCascadeTopologyDeployRouter({
        ...operationStatusHarness(), ...guardHarness([]),
        models: { TopologyOperation: {
            async create() {}, async findOneAndUpdate() {}, async updateOne() {},
            findById() { throw new Error('password=must-not-leak'); },
        } },
        routeLogger: { error(message) { logged.push(message); } },
    });
    const response = await requestOperationStatus(router, { headers: { 'x-test-auth': 'api-read' } });
    assert.equal(response.status, 500);
    assert.deepEqual(response.body, { error: { code: 'INTERNAL_ERROR', message: 'Internal server error' } });
    assert.doesNotMatch(JSON.stringify(response.body) + logged.join(' '), /password|must-not-leak/);
});

test('operation status endpoint covers the full status lifecycle', async () => {
    const headers = { 'x-test-auth': 'api-read' };
    for (const status of ['queued', 'committing', 'succeeded', 'failed', 'rolled_back']) {
        const router = createCascadeTopologyDeployRouter({
            ...operationStatusHarness({
                document: { _id: '507f1f77bcf86cd799439021', topologyRevision: 7, status },
            }),
            ...guardHarness([]),
        });
        const response = await requestOperationStatus(router, { headers });
        assert.equal(response.status, 200, status);
        assert.equal(response.body.status, status, status);
    }
});

test('operation status endpoint drops non-enum status, kind, causeCode, and reason', async () => {
    const router = createCascadeTopologyDeployRouter({
        ...operationStatusHarness({
            document: {
                _id: '507f1f77bcf86cd799439021',
                topologyRevision: 7,
                status: 'pwned; drop table',
                kind: 'rm -rf /',
                causeCode: 'ssh password leaked in freeform text',
                reason: 'freeform log message with details',
            },
        }),
        ...guardHarness([]),
    });

    const response = await requestOperationStatus(router, { headers: { 'x-test-auth': 'api-read' } });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {
        operationId: '507f1f77bcf86cd799439021',
        topologyRevision: 7,
        clientReadiness: 'unverified',
    });
});

test('OpenAPI advertises only the revision-safe topology deployment endpoint', () => {
    const english = buildSpec('en');
    const russian = buildSpec('ru');
    assert.equal(english.paths['/cascade/chain/deploy'], undefined);
    assert.equal(english.paths['/cascade/links/{id}/deploy'], undefined);
    const operation = english.paths['/cascade/topology/deploy'].post;
    assert.deepEqual(
        operation.requestBody.content['application/json'].schema,
        {
            type: 'object',
            additionalProperties: false,
            required: ['expectedTopologyRevision'],
            properties: {
                expectedTopologyRevision: {
                    type: 'integer',
                    minimum: 0,
                    maximum: Number.MAX_SAFE_INTEGER,
                },
                linkId: { type: 'string', pattern: '^[0-9a-fA-F]{24}$' },
                domainLinkId: { type: 'string', pattern: '^[0-9a-fA-F]{24}$' },
            },
        },
    );
    assert.deepEqual(operation['x-requiredScopes'], ['nodes:write']);
    assert.equal(operation['x-rateLimit'], '10 deploy requests per minute');
    assert.match(operation.description, /fails closed/i);
    assert.match(operation.description, /TOPOLOGY_DEPLOYMENT_UNAVAILABLE/);
    assert.deepEqual(
        operation.responses[202].content['application/json'].schema,
        {
            type: 'object',
            additionalProperties: false,
            required: ['operationId', 'topologyRevision', 'status'],
            properties: {
                operationId: { type: 'string' },
                topologyRevision: { type: 'integer', minimum: 0 },
                status: { type: 'string', enum: ['queued'] },
                kind: { type: 'string', enum: ['link.apply', 'domain.reconcile'] },
            },
        },
    );
    assert.match(english.info.description, /POST \/cascade\/topology\/deploy/);
    assert.doesNotMatch(english.info.description, /POST \/cascade\/chain\/deploy/);
    assert.match(russian.info.description, /POST \/cascade\/topology\/deploy/);
    assert.doesNotMatch(russian.info.description, /POST \/cascade\/chain\/deploy/);
    assert.match(
        russian.paths['/cascade/topology/deploy'].post.description,
        /TOPOLOGY_DEPLOYMENT_UNAVAILABLE/,
    );
    assert.doesNotMatch(JSON.stringify(english), /autoDeploy|autoRedeploy/);
    assert.doesNotMatch(OPENAPI_SOURCE, /['"]\/cascade\/chain\/deploy['"]/);
    assert.doesNotMatch(OPENAPI_SOURCE, /['"]\/cascade\/links\/\{id\}\/deploy['"]/);
});
