'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');

const { createL2tpRouter } = require('../routes/panel');

async function request(router, { method = 'GET', path, body, headers = {} }) {
    const app = express();
    app.use(express.json());
    app.use(router);

    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
    });

    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
            method,
            headers: {
                ...(body === undefined ? {} : { 'content-type': 'application/json' }),
                ...headers,
            },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        const text = await response.text();
        const contentType = response.headers.get('content-type') || '';
        return {
            status: response.status,
            body: text && contentType.includes('application/json') ? JSON.parse(text) : text,
        };
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => (error ? reject(error) : resolve()));
        });
    }
}

function passThrough(req, res, next) {
    next();
}

function createRouter(dependencies) {
    return createL2tpRouter({
        requireOnboarding: passThrough,
        loadPanelOverview: async () => ({}),
        renderPage(res, data) {
            res.json(data);
        },
        ...dependencies,
    });
}

test('GET L2TP page requires authentication before loading panel data', async () => {
    let overviewCalls = 0;
    const router = createRouter({
        l2tpService: {},
        requireAuth(req, res) {
            res.status(401).send('authentication required');
        },
        csrf: passThrough,
        rateLimiter: passThrough,
        async loadPanelOverview() {
            overviewCalls += 1;
            return {};
        },
    });

    const response = await request(router, { path: '/l2tp' });

    assert.equal(response.status, 401);
    assert.equal(response.body, 'authentication required');
    assert.equal(overviewCalls, 0);
});

test('GET L2TP page requires completed onboarding before loading panel data', async () => {
    let overviewCalls = 0;
    const router = createRouter({
        l2tpService: {},
        requireAuth: passThrough,
        requireOnboarding(req, res) {
            res.status(409).send('onboarding required');
        },
        csrf: passThrough,
        rateLimiter: passThrough,
        async loadPanelOverview() {
            overviewCalls += 1;
            return {};
        },
    });

    const response = await request(router, { path: '/l2tp' });

    assert.equal(response.status, 409);
    assert.equal(response.body, 'onboarding required');
    assert.equal(overviewCalls, 0);
});

test('all L2TP status and operation routes require completed onboarding', async () => {
    let serviceCalls = 0;
    const serviceMethod = async () => {
        serviceCalls += 1;
        return {};
    };
    const router = createRouter({
        l2tpService: {
            getStatus: serviceMethod,
            preflight: serviceMethod,
            install: serviceMethod,
            getOperation: serviceMethod,
        },
        requireAuth: passThrough,
        requireOnboarding(req, res) {
            res.status(409).send('onboarding required');
        },
        csrf: passThrough,
        rateLimiter: passThrough,
    });
    const requests = [
        { path: '/nodes/relay-1/l2tp/status' },
        { method: 'POST', path: '/nodes/relay-1/l2tp/preflight', body: {} },
        { method: 'POST', path: '/nodes/relay-1/l2tp/install', body: {} },
        { path: '/l2tp/operations/operation-1' },
    ];

    for (const requestOptions of requests) {
        const response = await request(router, requestOptions);
        assert.equal(response.status, 409, requestOptions.path);
    }
    assert.equal(serviceCalls, 0);
});

test('GET node L2TP status is authenticated and delegates to the injected service', async () => {
    const calls = [];
    const router = createRouter({
        l2tpService: {
            async getStatus(nodeId) {
                calls.push({ method: 'getStatus', nodeId });
                return { status: 'installed', nodeId };
            },
        },
        requireAuth(req, res, next) {
            calls.push({ method: 'requireAuth' });
            next();
        },
        csrf: passThrough,
        rateLimiter: passThrough,
    });

    const response = await request(router, {
        path: '/nodes/node-17/l2tp/status',
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, { status: 'installed', nodeId: 'node-17' });
    assert.deepEqual(calls, [
        { method: 'requireAuth' },
        { method: 'getStatus', nodeId: 'node-17' },
    ]);
});

test('authentication and CSRF middleware can stop protected operations', async () => {
    let serviceCalls = 0;
    const unauthorizedRouter = createRouter({
        l2tpService: {
            async getStatus() {
                serviceCalls += 1;
                return {};
            },
        },
        requireAuth(req, res) {
            res.status(401).json({ error: 'authentication required' });
        },
        csrf: passThrough,
        rateLimiter: passThrough,
    });

    const unauthorized = await request(unauthorizedRouter, {
        path: '/nodes/protected/l2tp/status',
    });
    assert.equal(unauthorized.status, 401);

    const csrfRouter = createRouter({
        l2tpService: {
            async install() {
                serviceCalls += 1;
                return { operationId: 'must-not-be-created' };
            },
        },
        requireAuth: passThrough,
        csrf(req, res) {
            res.status(403).json({ error: 'invalid csrf token' });
        },
        rateLimiter: passThrough,
    });

    const forbidden = await request(csrfRouter, {
        method: 'POST',
        path: '/nodes/protected/l2tp/install',
        body: {},
    });
    assert.equal(forbidden.status, 403);
    assert.equal(serviceCalls, 0);
});

test('POST preflight enforces protection and passes only allowed body fields', async () => {
    const calls = [];
    const expectedInput = {
        clientCidr: '10.77.0.0/24',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        routeGroupId: 'route-group-1',
        expectedTopologyRevision: 17,
    };
    const middleware = method => (req, res, next) => {
        calls.push({ method });
        next();
    };
    const router = createRouter({
        l2tpService: {
            async preflight(nodeId, input) {
                calls.push({ method: 'preflight', nodeId, input });
                return { ok: true, checks: ['relay-role', 'route-group'] };
            },
        },
        requireAuth: middleware('requireAuth'),
        csrf: middleware('csrf'),
        rateLimiter: middleware('rateLimiter'),
    });

    const response = await request(router, {
        method: 'POST',
        path: '/nodes/node-18/l2tp/preflight',
        body: {
            ...expectedInput,
            routingMode: 'attacker-controlled',
            psk: 'must-not-reach-service',
            unexpected: true,
        },
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, { ok: true, checks: ['relay-role', 'route-group'] });
    assert.deepEqual(calls, [
        { method: 'requireAuth' },
        { method: 'csrf' },
        { method: 'rateLimiter' },
        { method: 'preflight', nodeId: 'node-18', input: expectedInput },
    ]);
});

test('POST install returns 202 with the queued operation id', async () => {
    const calls = [];
    const expectedInput = {
        clientCidr: '10.88.0.0/24',
        dnsServers: ['9.9.9.9'],
        routeGroupId: 'route-group-2',
        expectedTopologyRevision: 23,
    };
    const middleware = method => (req, res, next) => {
        calls.push({ method });
        next();
    };
    const router = createRouter({
        l2tpService: {
            async install(nodeId, input) {
                calls.push({ method: 'install', nodeId, input });
                return { operationId: 'operation-23' };
            },
        },
        requireAuth: middleware('requireAuth'),
        csrf: middleware('csrf'),
        rateLimiter: middleware('rateLimiter'),
    });

    const response = await request(router, {
        method: 'POST',
        path: '/nodes/node-23/l2tp/install',
        body: {
            ...expectedInput,
            nodeId: 'different-node',
            operationId: 'existing-operation',
        },
    });

    assert.equal(response.status, 202);
    assert.deepEqual(response.body, { operationId: 'operation-23' });
    assert.deepEqual(calls, [
        { method: 'requireAuth' },
        { method: 'csrf' },
        { method: 'rateLimiter' },
        { method: 'install', nodeId: 'node-23', input: expectedInput },
    ]);
});

test('GET L2TP operation is authenticated and delegates by operation id', async () => {
    const calls = [];
    const router = createRouter({
        l2tpService: {
            async getOperation(operationId) {
                calls.push({ method: 'getOperation', operationId });
                return { id: operationId, status: 'running', progress: 50 };
            },
        },
        requireAuth(req, res, next) {
            calls.push({ method: 'requireAuth' });
            next();
        },
        csrf: passThrough,
        rateLimiter: passThrough,
    });

    const response = await request(router, {
        path: '/l2tp/operations/operation-31',
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {
        id: 'operation-31',
        status: 'running',
        progress: 50,
    });
    assert.deepEqual(calls, [
        { method: 'requireAuth' },
        { method: 'getOperation', operationId: 'operation-31' },
    ]);
});

test('structured service error codes map to the documented HTTP statuses', async () => {
    const cases = [
        { code: 'INVALID_INPUT', status: 400 },
        { code: 'NODE_NOT_FOUND', status: 404 },
        { code: 'OPERATION_IN_PROGRESS', status: 409 },
        { code: 'PREFLIGHT_FAILED', status: 422 },
        { code: 'NO_HEALTHY_PATH', status: 422 },
        { code: 'INSTALL_PLAN_REJECTED', status: 422 },
    ];

    for (const { code, status } of cases) {
        const error = Object.assign(new Error(`service rejected ${code}`), { code });
        const router = createRouter({
            l2tpService: {
                async getStatus() {
                    throw error;
                },
            },
            requireAuth: passThrough,
            csrf: passThrough,
            rateLimiter: passThrough,
        });

        const response = await request(router, {
            path: `/nodes/node-${status}/l2tp/status`,
        });

        assert.equal(response.status, status, code);
        assert.deepEqual(response.body, {
            error: {
                code,
                message: `service rejected ${code}`,
            },
        });
    }
});

test('unexpected service errors return an opaque 500 response', async () => {
    const router = createRouter({
        l2tpService: {
            async getOperation() {
                throw new Error('ssh output containing secret-password');
            },
        },
        requireAuth: passThrough,
        csrf: passThrough,
        rateLimiter: passThrough,
    });

    const response = await request(router, {
        path: '/l2tp/operations/broken-operation',
    });

    assert.equal(response.status, 500);
    assert.deepEqual(response.body, {
        error: {
            code: 'INTERNAL_ERROR',
            message: 'Internal server error',
        },
    });
    assert.doesNotMatch(JSON.stringify(response.body), /secret-password|ssh output/);
});
