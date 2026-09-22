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
        userManagementService: {
            async createUser() {},
            async listUsers() { return []; },
            async updateUser() {},
            async disableUser() {},
        },
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
                return {
                    status: 'installed',
                    nodeId,
                    psk: 'must-not-be-returned',
                    pskEncrypted: 'must-not-be-returned',
                    ssh: { password: 'must-not-be-returned' },
                    rawCommand: 'must-not-be-returned',
                };
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

test('POST configure enforces every mutation guard and returns only safe desired state', async () => {
    const calls = [];
    const expectedInput = {
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        routeGroupId: 'route-group-1',
        psk: 'operator-supplied-secret',
    };
    const middleware = method => (req, res, next) => {
        calls.push({ method });
        next();
    };
    const router = createRouter({
        l2tpService: {},
        stateManagementService: {
            async configureRelay(nodeId, input) {
                calls.push({ method: 'configureRelay', nodeId, input });
                return {
                    node: nodeId,
                    desiredState: 'installed',
                    status: 'not_installed',
                    routeGroup: input.routeGroupId,
                    clientCidr: input.clientCidr,
                    localAddress: input.localAddress,
                    poolStart: input.poolStart,
                    poolEnd: input.poolEnd,
                    dnsServers: input.dnsServers,
                    tproxyPort: input.tproxyPort,
                    fwmark: input.fwmark,
                    routeTable: input.routeTable,
                    routingMode: 'route-group',
                    secretRevision: 1,
                    psk: input.psk,
                    pskEncrypted: 'encrypted-secret',
                    password: 'must-not-be-returned',
                    rawCommand: 'must-not-be-returned',
                };
            },
        },
        requireAuth: middleware('requireAuth'),
        requireOnboarding: middleware('requireOnboarding'),
        csrf: middleware('csrf'),
        rateLimiter: middleware('rateLimiter'),
    });

    const response = await request(router, {
        method: 'POST',
        path: '/nodes/node-19/l2tp/configure',
        body: {
            ...expectedInput,
            node: 'different-node',
            desiredState: 'absent',
            routingMode: 'attacker-controlled',
            password: 'must-not-reach-service',
            encryptedValue: 'must-not-reach-service',
            ssh: { command: 'must-not-reach-service' },
            argv: ['must-not-reach-service'],
        },
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {
        node: 'node-19',
        desiredState: 'installed',
        status: 'not_installed',
        routeGroup: 'route-group-1',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        routingMode: 'route-group',
        secretRevision: 1,
    });
    assert.deepEqual(calls, [
        { method: 'requireAuth' },
        { method: 'requireOnboarding' },
        { method: 'csrf' },
        { method: 'rateLimiter' },
        { method: 'configureRelay', nodeId: 'node-19', input: expectedInput },
    ]);
    assert.doesNotMatch(
        JSON.stringify(response.body),
        /operator-supplied-secret|encrypted-secret|must-not-be-returned/i,
    );
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

test('configure errors expose only allowlisted codes at stable HTTP statuses', async () => {
    const cases = [
        { code: 'INVALID_CLIENT_POOL', status: 400 },
        { code: 'ROUTE_GROUP_NOT_FOUND', status: 404 },
        { code: 'NODE_NOT_RELAY', status: 409 },
        { code: 'PSK_ENCRYPTION_FAILED', status: 422 },
    ];

    for (const { code, status } of cases) {
        const error = Object.assign(new Error(`safe ${code} rejection`), {
            code,
            details: { psk: 'must-not-be-returned' },
            rawCommand: 'must-not-be-returned',
        });
        const router = createRouter({
            l2tpService: {},
            stateManagementService: {
                async configureRelay() {
                    throw error;
                },
            },
            requireAuth: passThrough,
            csrf: passThrough,
            rateLimiter: passThrough,
        });

        const response = await request(router, {
            method: 'POST',
            path: `/nodes/node-${status}/l2tp/configure`,
            body: { generatePsk: true },
        });

        assert.equal(response.status, status, code);
        assert.deepEqual(response.body, {
            error: {
                code,
                message: `safe ${code} rejection`,
            },
        });
        assert.doesNotMatch(JSON.stringify(response.body), /must-not-be-returned/);
    }
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

test('L2TP user routes enforce auth, onboarding, CSRF, and rate limiting before service access', async () => {
    let serviceCalls = 0;
    const userManagementService = {
        async listUsers() { serviceCalls += 1; return []; },
        async createUser() { serviceCalls += 1; return {}; },
        async updateUser() { serviceCalls += 1; return {}; },
        async disableUser() { serviceCalls += 1; return {}; },
    };
    const unauthorized = createRouter({
        l2tpService: {},
        userManagementService,
        requireAuth(req, res) { res.status(401).send('authentication required'); },
        csrf: passThrough,
        rateLimiter: passThrough,
    });
    const unauthorizedResponse = await request(unauthorized, {
        path: '/nodes/relay-1/l2tp/users',
    });
    assert.equal(unauthorizedResponse.status, 401);

    const notOnboarded = createRouter({
        l2tpService: {},
        userManagementService,
        requireAuth: passThrough,
        requireOnboarding(req, res) { res.status(409).send('onboarding required'); },
        csrf: passThrough,
        rateLimiter: passThrough,
    });
    const onboardingResponse = await request(notOnboarded, {
        method: 'POST',
        path: '/nodes/relay-1/l2tp/users',
        body: {},
    });
    assert.equal(onboardingResponse.status, 409);

    const csrfRejected = createRouter({
        l2tpService: {},
        userManagementService,
        requireAuth: passThrough,
        csrf(req, res) { res.status(403).send('invalid csrf token'); },
        rateLimiter: passThrough,
    });
    const csrfResponse = await request(csrfRejected, {
        method: 'PATCH',
        path: '/nodes/relay-1/l2tp/users/user-1',
        body: { enabled: false },
    });
    assert.equal(csrfResponse.status, 403);

    const rateLimited = createRouter({
        l2tpService: {},
        userManagementService,
        requireAuth: passThrough,
        csrf: passThrough,
        rateLimiter(req, res) { res.status(429).send('rate limited'); },
    });
    const limitedResponse = await request(rateLimited, {
        path: '/nodes/relay-1/l2tp/users',
    });
    assert.equal(limitedResponse.status, 429);
    assert.equal(serviceCalls, 0);
});

test('POST L2TP user accepts only allowlisted fields and returns no password material', async () => {
    const calls = [];
    const middleware = method => (req, res, next) => {
        calls.push({ method });
        next();
    };
    const router = createRouter({
        l2tpService: {},
        userManagementService: {
            async createUser(nodeId, input) {
                calls.push({ method: 'createUser', nodeId, input });
                return {
                    id: 'user-1',
                    relayNode: nodeId,
                    login: input.login,
                    ip: input.ip,
                    enabled: input.enabled,
                    desiredRevision: 7,
                    appliedRevision: 0,
                    syncStatus: 'pending',
                    password: input.password,
                    passwordEncrypted: 'sealed-password',
                    rawCommand: 'must-not-be-returned',
                };
            },
        },
        requireAuth: middleware('requireAuth'),
        requireOnboarding: middleware('requireOnboarding'),
        csrf: middleware('csrf'),
        rateLimiter: middleware('rateLimiter'),
    });

    const response = await request(router, {
        method: 'POST',
        path: '/nodes/relay-1/l2tp/users',
        body: {
            login: 'alice',
            ip: '10.77.0.10',
            password: 'test-account-password',
            enabled: true,
            relayNode: 'attacker-selected-relay',
            desiredRevision: 999,
            passwordEncrypted: 'attacker-ciphertext',
            command: 'must-not-reach-service',
            argv: ['must-not-reach-service'],
        },
    });

    assert.equal(response.status, 201);
    assert.deepEqual(calls, [
        { method: 'requireAuth' },
        { method: 'requireOnboarding' },
        { method: 'csrf' },
        { method: 'rateLimiter' },
        {
            method: 'createUser',
            nodeId: 'relay-1',
            input: {
                login: 'alice',
                ip: '10.77.0.10',
                password: 'test-account-password',
                enabled: true,
            },
        },
    ]);
    assert.deepEqual(response.body, {
        id: 'user-1',
        relayNode: 'relay-1',
        login: 'alice',
        ip: '10.77.0.10',
        enabled: true,
        desiredRevision: 7,
        appliedRevision: 0,
        syncStatus: 'pending',
    });
    assert.doesNotMatch(
        JSON.stringify(response.body),
        /test-account-password|sealed-password|attacker-ciphertext|rawCommand|command|argv/,
    );
});

test('GET L2TP users returns a safe list including disabled state', async () => {
    const router = createRouter({
        l2tpService: {},
        userManagementService: {
            async listUsers(nodeId) {
                return [{
                    id: 'user-2',
                    relayNode: nodeId,
                    login: 'disabled',
                    ip: '10.77.0.11',
                    enabled: false,
                    desiredRevision: 4,
                    appliedRevision: 3,
                    syncStatus: 'pending',
                    passwordEncrypted: 'sealed-password',
                }];
            },
        },
        requireAuth: passThrough,
        csrf: passThrough,
        rateLimiter: passThrough,
    });

    const response = await request(router, {
        path: '/nodes/relay-1/l2tp/users',
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, [{
        id: 'user-2',
        relayNode: 'relay-1',
        login: 'disabled',
        ip: '10.77.0.11',
        enabled: false,
        desiredRevision: 4,
        appliedRevision: 3,
        syncStatus: 'pending',
    }]);
    assert.doesNotMatch(JSON.stringify(response.body), /sealed-password|password/i);
});

test('GET L2TP users exposes safe sync progress while fixing failure diagnostics', async () => {
    const failedAt = new Date('2026-09-22T10:00:00.000Z');
    const router = createRouter({
        l2tpService: {},
        userManagementService: {
            async listUsers(nodeId) {
                return [{
                    id: 'user-canary',
                    relayNode: nodeId,
                    login: 'canary',
                    ip: '10.77.0.99',
                    enabled: false,
                    desiredRevision: 9,
                    appliedRevision: 8,
                    syncStatus: 'error',
                    syncOperationId: 'operation-failed',
                    lastSyncedAt: failedAt,
                    lastErrorCode: 'SSH_FAILURE_CONTAINING_SECRET_PASSWORD',
                    lastError: 'password=canary-plaintext ssh stderr',
                    password: 'canary-plaintext',
                    passwordEncrypted: 'canary-ciphertext',
                }];
            },
        },
        requireAuth: passThrough,
        csrf: passThrough,
        rateLimiter: passThrough,
    });

    const response = await request(router, {
        path: '/nodes/relay-1/l2tp/users',
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, [{
        id: 'user-canary',
        relayNode: 'relay-1',
        login: 'canary',
        ip: '10.77.0.99',
        enabled: false,
        desiredRevision: 9,
        appliedRevision: 8,
        syncStatus: 'error',
        syncOperationId: 'operation-failed',
        lastSyncedAt: failedAt.toISOString(),
        lastErrorCode: 'L2TP_USER_SYNC_FAILED',
    }]);
    assert.doesNotMatch(
        JSON.stringify(response.body),
        /canary-plaintext|canary-ciphertext|SSH_FAILURE|ssh stderr|password/i,
    );
});

test('L2TP stale user and revision conflicts map to fixed safe 409 responses', async () => {
    const cases = [
        {
            code: 'L2TP_USER_STALE_REVISION',
            message: 'The L2TP user changed before this request was applied',
        },
        {
            code: 'L2TP_USER_REVISION_CONFLICT',
            message: 'The L2TP user revision conflicts with the current relay revision',
        },
    ];

    for (const { code, message } of cases) {
        const router = createRouter({
            l2tpService: {},
            userManagementService: {
                async listUsers() {
                    throw Object.assign(
                        new Error('database conflict password=canary-plaintext revision=99'),
                        {
                            code,
                            passwordEncrypted: 'canary-ciphertext',
                        },
                    );
                },
            },
            requireAuth: passThrough,
            csrf: passThrough,
            rateLimiter: passThrough,
        });

        const response = await request(router, {
            path: '/nodes/relay-1/l2tp/users',
        });

        assert.equal(response.status, 409, code);
        assert.deepEqual(response.body, {
            error: { code, message },
        });
        assert.doesNotMatch(
            JSON.stringify(response.body),
            /canary-plaintext|canary-ciphertext|database conflict|revision=99/i,
        );
    }
});

test('PATCH L2TP user safely disables or updates only allowlisted fields', async () => {
    const calls = [];
    const userManagementService = {
        async disableUser(nodeId, userId) {
            calls.push({ method: 'disableUser', nodeId, userId });
            return {
                id: userId,
                relayNode: nodeId,
                login: 'alice',
                ip: '10.77.0.10',
                enabled: false,
                desiredRevision: 8,
                passwordEncrypted: 'sealed-password',
            };
        },
        async updateUser(nodeId, userId, input) {
            calls.push({ method: 'updateUser', nodeId, userId, input });
            return {
                id: userId,
                relayNode: nodeId,
                login: input.login,
                ip: input.ip,
                enabled: input.enabled,
                desiredRevision: 9,
                password: input.password,
            };
        },
    };
    const router = createRouter({
        l2tpService: {},
        userManagementService,
        requireAuth: passThrough,
        csrf: passThrough,
        rateLimiter: passThrough,
    });

    const disabled = await request(router, {
        method: 'PATCH',
        path: '/nodes/relay-1/l2tp/users/user-1',
        body: { enabled: false, command: 'must-not-reach-service' },
    });
    const updated = await request(router, {
        method: 'PATCH',
        path: '/nodes/relay-1/l2tp/users/user-1',
        body: {
            login: 'alice-2',
            ip: '10.77.0.20',
            password: 'replacement-password',
            enabled: true,
            passwordEncrypted: 'attacker-ciphertext',
            rawCommand: 'must-not-reach-service',
        },
    });

    assert.deepEqual(calls, [
        { method: 'disableUser', nodeId: 'relay-1', userId: 'user-1' },
        {
            method: 'updateUser',
            nodeId: 'relay-1',
            userId: 'user-1',
            input: {
                login: 'alice-2',
                ip: '10.77.0.20',
                password: 'replacement-password',
                enabled: true,
            },
        },
    ]);
    assert.equal(disabled.status, 200);
    assert.equal(updated.status, 200);
    assert.equal(disabled.body.enabled, false);
    assert.equal(updated.body.enabled, true);
    assert.doesNotMatch(
        JSON.stringify([disabled.body, updated.body]),
        /sealed-password|replacement-password|attacker-ciphertext|rawCommand/,
    );
});
