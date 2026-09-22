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

const {
    createCascadeTopologyDeployRouter,
} = require('../cascadeTopologyDeploy');
const { buildSpec } = require('../../docs/openapi');

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

test('legacy deploy entry points are fail-closed while explicit undeploy remains separate', () => {
    assert.doesNotMatch(CASCADE_ROUTE_SOURCE, /cascadeService\.deployChain\s*\(/);
    assert.doesNotMatch(CASCADE_ROUTE_SOURCE, /cascadeService\.deployLink\s*\(/);
    assert.doesNotMatch(CASCADE_ROUTE_SOURCE, /req\.body\.autoDeploy|req\.body\.autoRedeploy/);
    assert.match(CASCADE_ROUTE_SOURCE, /LEGACY_CASCADE_DEPLOY_DISABLED/);
    assert.match(
        CASCADE_ROUTE_SOURCE,
        /router\.post\('\/links\/:id\/undeploy',[\s\S]*cascadeService\.undeployLink\(link\)/,
    );
    assert.equal((CASCADE_ROUTE_SOURCE.match(/cascadeService\.undeployLink\s*\(/g) || []).length, 1);
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
            },
        },
    );
    assert.deepEqual(operation['x-requiredScopes'], ['nodes:write']);
    assert.equal(operation['x-rateLimit'], '10 deploy requests per minute');
    assert.match(operation.description, /fails closed/i);
    assert.match(operation.description, /TOPOLOGY_DEPLOYMENT_UNAVAILABLE/);
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
