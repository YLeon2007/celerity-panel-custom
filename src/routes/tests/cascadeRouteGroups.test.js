'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const express = require('express');

const CascadeRouteGroup = require('../../modules/relay-l2tp/models/cascadeRouteGroupModel');
const requireAuth = require('../../middleware/auth');
const cascadeRouteGroupsRouter = require('../cascadeRouteGroups');
const { createCascadeRouteGroupsRouter } = cascadeRouteGroupsRouter;

const GROUP_A = '507f1f77bcf86cd799439011';
const GROUP_B = '507f1f77bcf86cd799439012';
const LINK_A = '507f1f77bcf86cd799439021';
const LINK_B = '507f1f77bcf86cd799439022';
const NODE_A = '507f1f77bcf86cd799439031';
const NODE_B = '507f1f77bcf86cd799439032';
const NODE_C = '507f1f77bcf86cd799439033';

const ROOT_ENTRY_SOURCE = fs.readFileSync(path.resolve(__dirname, '../../../index.js'), 'utf8');

function queryResult(rows, calls) {
    return {
        select(value) {
            calls.select = value;
            return this;
        },
        sort(value) {
            calls.sort = value;
            return this;
        },
        async lean() {
            return rows;
        },
    };
}

function validBody(overrides = {}) {
    return {
        name: 'Primary route',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [{ pathKey: 'primary', linkIds: [LINK_A], priority: 1, enabled: true }],
        ...overrides,
    };
}

async function request(router, {
    method = 'GET',
    path = '/',
    body,
    authorize = true,
    apiKeyScopes,
    protect = false,
} = {}) {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => {
        if (apiKeyScopes !== undefined) {
            req.apiKey = { keyPrefix: 'test-key', scopes: apiKeyScopes };
        } else if (authorize) {
            req.session = { authenticated: true };
        }
        next();
    });
    if (protect) app.use(requireAuth);
    app.use(router);

    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
    });

    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
            method,
            headers: body === undefined ? {} : { 'content-type': 'application/json' },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        const text = await response.text();
        const contentType = response.headers.get('content-type') || '';
        return {
            status: response.status,
            body: text && contentType.includes('application/json') ? JSON.parse(text) : text,
            headers: response.headers,
        };
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => (error ? reject(error) : resolve()));
        });
    }
}

test('index mounts route-group CRUD behind shared session/API-key authentication', () => {
    assert.match(
        ROOT_ENTRY_SOURCE,
        /const cascadeRouteGroupsRoutes = require\('\.\/src\/routes\/cascadeRouteGroups'\);/,
    );
    assert.match(
        ROOT_ENTRY_SOURCE,
        /app\.use\('\/api\/cascade\/route-groups', requireAuth, cascadeRouteGroupsRoutes\);/,
    );
});

test('protected route-group CRUD rejects unauthenticated requests', async () => {
    const response = await request(cascadeRouteGroupsRouter, {
        authorize: false,
        protect: true,
    });

    assert.equal(response.status, 401);
    assert.deepEqual(response.body, { error: 'Authentication required' });
});

test('route-group reads require the nodes:read API-key scope', async () => {
    const RouteGroup = {
        find() {
            return queryResult([], {});
        },
    };
    const router = createCascadeRouteGroupsRouter({ RouteGroup });

    const denied = await request(router, { apiKeyScopes: ['nodes:write'] });
    assert.equal(denied.status, 403);
    assert.deepEqual(denied.body, {
        error: 'Insufficient permissions',
        required: 'nodes:read',
    });

    const allowed = await request(router, { apiKeyScopes: ['nodes:read'] });
    assert.equal(allowed.status, 200);
    assert.deepEqual(allowed.body, []);
});

test('route-group mutations require the nodes:write API-key scope', async () => {
    const RouteGroup = {
        async create() {
            throw new Error('insufficiently scoped request reached create');
        },
    };
    const Link = {
        find() {
            throw new Error('insufficiently scoped request reached link validation');
        },
    };
    const router = createCascadeRouteGroupsRouter({ RouteGroup, Link });

    const response = await request(router, {
        method: 'POST',
        body: {},
        apiKeyScopes: ['nodes:read'],
    });

    assert.equal(response.status, 403);
    assert.deepEqual(response.body, {
        error: 'Insufficient permissions',
        required: 'nodes:write',
    });
});

test('GET /route-groups returns a deterministic safe projection', async (t) => {
    const calls = {};
    const originalFind = CascadeRouteGroup.find;
    t.after(() => {
        CascadeRouteGroup.find = originalFind;
    });
    CascadeRouteGroup.find = filter => {
        calls.filter = filter;
        return queryResult([
            {
                _id: GROUP_B,
                name: 'Zulu',
                mode: 'reverse',
                strategy: 'priority-failover',
                paths: [{ pathKey: 'fallback', linkIds: [LINK_B], priority: 20, enabled: false }],
                __v: 4,
                internal: 'must-not-leak',
            },
            {
                _id: GROUP_A,
                name: 'Alpha',
                mode: 'forward',
                strategy: 'priority-failover',
                paths: [{ pathKey: 'primary', linkIds: [LINK_A, LINK_B], priority: 10 }],
                __v: 7,
            },
        ], calls);
    };

    const response = await request(cascadeRouteGroupsRouter, { path: '/' });

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, [
        {
            id: GROUP_A,
            name: 'Alpha',
            mode: 'forward',
            strategy: 'priority-failover',
            paths: [{
                pathKey: 'primary',
                linkIds: [LINK_A, LINK_B],
                priority: 10,
                enabled: true,
            }],
        },
        {
            id: GROUP_B,
            name: 'Zulu',
            mode: 'reverse',
            strategy: 'priority-failover',
            paths: [{
                pathKey: 'fallback',
                linkIds: [LINK_B],
                priority: 20,
                enabled: false,
            }],
        },
    ]);
    assert.deepEqual(calls.filter, {});
    assert.equal(calls.select, '_id name mode strategy paths.pathKey paths.linkIds paths.priority paths.enabled');
    assert.deepEqual(calls.sort, { name: 1, _id: 1 });
    assert.doesNotMatch(JSON.stringify(response.body), /internal|__v|must-not-leak/);
});

test('POST /route-groups creates a fixed-strategy group from ordered validated links', async () => {
    const calls = {};
    const RouteGroup = {
        async create(data) {
            calls.create = data;
            return { _id: GROUP_A, ...data, internal: 'must-not-leak' };
        },
    };
    const Link = {
        find(filter) {
            calls.linkFilter = filter;
            return queryResult([
                { _id: LINK_A, portalNode: NODE_A, bridgeNode: NODE_B, mode: 'forward' },
                { _id: LINK_B, portalNode: NODE_B, bridgeNode: NODE_C, mode: 'forward' },
            ], calls);
        },
    };
    const router = createCascadeRouteGroupsRouter({ RouteGroup, Link });

    const response = await request(router, {
        method: 'POST',
        path: '/',
        body: {
            name: '  Test L2TP route  ',
            mode: 'forward',
            paths: [{
                pathKey: 'primary',
                linkIds: [LINK_A, LINK_B],
                priority: 10,
                enabled: false,
                rawCommand: 'rm -rf /',
            }],
            rawShell: 'must-not-be-written',
            internal: 'must-not-be-written',
        },
    });

    assert.equal(response.status, 201);
    assert.deepEqual(calls.linkFilter, { _id: { $in: [LINK_A, LINK_B] } });
    assert.equal(calls.select, '_id portalNode bridgeNode mode');
    assert.deepEqual(calls.create, {
        name: 'Test L2TP route',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [{
            pathKey: 'primary',
            linkIds: [LINK_A, LINK_B],
            priority: 10,
            enabled: false,
        }],
    });
    assert.deepEqual(response.body, { id: GROUP_A, ...calls.create });
    assert.doesNotMatch(JSON.stringify(calls.create), /rawCommand|rawShell|internal|rm -rf/);
    assert.doesNotMatch(JSON.stringify(response.body), /must-not-leak|rawCommand|rawShell|internal/);
});

test('POST /route-groups rejects invalid, duplicate, and untyped v1 fields before database access', async () => {
    const RouteGroup = {
        async create() {
            throw new Error('invalid input reached create');
        },
    };
    const Link = {
        find() {
            throw new Error('invalid input reached link validation');
        },
    };
    const router = createCascadeRouteGroupsRouter({ RouteGroup, Link });
    const cases = [
        { body: [], error: 'Request body must be an object' },
        { body: validBody({ mode: 'direct' }), error: 'mode must be "reverse" or "forward"' },
        {
            body: validBody({ strategy: 'round-robin' }),
            error: 'strategy must be "priority-failover"',
        },
        {
            body: validBody({
                paths: [
                    { pathKey: 'duplicate', linkIds: [LINK_A], priority: 1 },
                    { pathKey: 'duplicate', linkIds: [LINK_B], priority: 2 },
                ],
            }),
            error: 'pathKey values must be unique',
        },
        {
            body: validBody({
                paths: [
                    { pathKey: 'primary', linkIds: [LINK_A], priority: 1 },
                    { pathKey: 'fallback', linkIds: [LINK_B], priority: 1 },
                ],
            }),
            error: 'path priorities must be unique',
        },
        {
            body: validBody({
                paths: [{ pathKey: 'primary', linkIds: [LINK_A, LINK_A], priority: 1 }],
            }),
            error: 'paths[0].linkIds must not contain duplicates',
        },
        {
            body: validBody({
                paths: [{ pathKey: 'primary', linkIds: [LINK_A], priority: '1' }],
            }),
            error: 'paths[0].priority must be a positive finite number',
        },
        {
            body: validBody({
                paths: [{ pathKey: 'primary', linkIds: [LINK_A], priority: 1, enabled: 'yes' }],
            }),
            error: 'paths[0].enabled must be a boolean',
        },
        {
            body: validBody({
                paths: [{ pathKey: 'primary', linkIds: ['not-an-object-id'], priority: 1 }],
            }),
            error: 'paths[0].linkIds[0] must be a valid link ID',
        },
    ];

    for (const input of cases) {
        const response = await request(router, { method: 'POST', body: input.body });
        assert.equal(response.status, 400, input.error);
        assert.deepEqual(response.body, { error: input.error });
    }
});

test('POST /route-groups returns structured missing, mode, and continuity link errors', async () => {
    const scenarios = [
        {
            name: 'missing link',
            body: validBody({
                paths: [{ pathKey: 'primary', linkIds: [LINK_A, LINK_B], priority: 1 }],
            }),
            links: [{ _id: LINK_A, portalNode: NODE_A, bridgeNode: NODE_B, mode: 'forward' }],
            details: [{
                code: 'UNKNOWN_LINK',
                groupId: 'new',
                pathKey: 'primary',
                linkId: LINK_B,
            }],
        },
        {
            name: 'mode mismatch',
            body: validBody(),
            links: [{ _id: LINK_A, portalNode: NODE_A, bridgeNode: NODE_B, mode: 'reverse' }],
            details: [{
                code: 'GROUP_MODE_MISMATCH',
                groupId: 'new',
                pathKey: 'primary',
                linkId: LINK_A,
                groupMode: 'forward',
                linkMode: 'reverse',
            }],
        },
        {
            name: 'discontinuous path',
            body: validBody({
                paths: [{ pathKey: 'primary', linkIds: [LINK_A, LINK_B], priority: 1 }],
            }),
            links: [
                { _id: LINK_A, portalNode: NODE_A, bridgeNode: NODE_B, mode: 'forward' },
                { _id: LINK_B, portalNode: NODE_C, bridgeNode: NODE_A, mode: 'forward' },
            ],
            details: [{
                code: 'DISCONTINUOUS_PATH',
                groupId: 'new',
                pathKey: 'primary',
                sourceNodeId: NODE_B,
                targetNodeId: NODE_C,
            }],
        },
    ];

    for (const scenario of scenarios) {
        const RouteGroup = {
            async create() {
                throw new Error(`${scenario.name} reached create`);
            },
        };
        const Link = {
            find() {
                return queryResult(scenario.links, {});
            },
        };
        const router = createCascadeRouteGroupsRouter({ RouteGroup, Link });
        const response = await request(router, { method: 'POST', body: scenario.body });

        assert.equal(response.status, 400, scenario.name);
        assert.deepEqual(response.body, {
            error: 'Invalid route group topology',
            details: scenario.details,
        });
    }
});

test('PUT and DELETE reject invalid route-group IDs before database access', async () => {
    const RouteGroup = {
        async findByIdAndUpdate() {
            throw new Error('invalid ID reached update');
        },
        async findByIdAndDelete() {
            throw new Error('invalid ID reached delete');
        },
    };
    const Link = {
        find() {
            throw new Error('invalid ID reached link validation');
        },
    };
    const router = createCascadeRouteGroupsRouter({ RouteGroup, Link });

    for (const method of ['PUT', 'DELETE']) {
        const response = await request(router, {
            method,
            path: '/invalid-id',
            body: method === 'PUT' ? validBody() : undefined,
        });
        assert.equal(response.status, 400);
        assert.deepEqual(response.body, { error: 'Invalid route group ID' });
    }
});

test('PUT and DELETE return 404 for missing route groups', async () => {
    const RouteGroup = {
        async findByIdAndUpdate() {
            return null;
        },
        async findByIdAndDelete() {
            return null;
        },
    };
    const Link = {
        find() {
            return queryResult([
                { _id: LINK_A, portalNode: NODE_A, bridgeNode: NODE_B, mode: 'forward' },
            ], {});
        },
    };
    const router = createCascadeRouteGroupsRouter({ RouteGroup, Link });

    const update = await request(router, {
        method: 'PUT',
        path: `/${GROUP_A}`,
        body: validBody(),
    });
    assert.equal(update.status, 404);
    assert.deepEqual(update.body, { error: 'Cascade route group not found' });

    const deletion = await request(router, {
        method: 'DELETE',
        path: `/${GROUP_A}`,
    });
    assert.equal(deletion.status, 404);
    assert.deepEqual(deletion.body, { error: 'Cascade route group not found' });
});

test('PUT /route-groups/:id replaces the writable schema after topology validation', async () => {
    const calls = {};
    const RouteGroup = {
        async findByIdAndUpdate(id, update, options) {
            calls.update = { id, update, options };
            return { _id: id, ...update.$set, __v: 9 };
        },
    };
    const Link = {
        find(filter) {
            calls.linkFilter = filter;
            return queryResult([
                { _id: LINK_A, portalNode: NODE_A, bridgeNode: NODE_B, mode: 'reverse' },
                { _id: LINK_B, portalNode: NODE_B, bridgeNode: NODE_C, mode: 'reverse' },
            ], calls);
        },
    };
    const router = createCascadeRouteGroupsRouter({ RouteGroup, Link });
    const body = {
        name: 'Updated route',
        mode: 'reverse',
        strategy: 'priority-failover',
        paths: [
            { pathKey: 'primary', linkIds: [LINK_A, LINK_B], priority: 1, enabled: true },
            { pathKey: 'fallback', linkIds: [LINK_B], priority: 2, enabled: false },
        ],
        createdAt: 'attacker-controlled',
    };

    const response = await request(router, {
        method: 'PUT',
        path: `/${GROUP_A}`,
        body,
    });

    assert.equal(response.status, 200);
    assert.deepEqual(calls.update, {
        id: GROUP_A,
        update: {
            $set: {
                name: body.name,
                mode: body.mode,
                strategy: body.strategy,
                paths: body.paths,
            },
        },
        options: { new: true, runValidators: true },
    });
    assert.deepEqual(response.body, {
        id: GROUP_A,
        name: body.name,
        mode: body.mode,
        strategy: body.strategy,
        paths: body.paths,
    });
    assert.doesNotMatch(JSON.stringify(calls.update), /createdAt|attacker-controlled/);
});

test('DELETE /route-groups/:id deletes locally without deployment side effects', async () => {
    const calls = [];
    const RouteGroup = {
        async findByIdAndDelete(id) {
            calls.push({ method: 'findByIdAndDelete', id });
            return { _id: id, name: 'Deleted route' };
        },
    };
    const Link = {
        find() {
            calls.push({ method: 'unexpected-link-query' });
            throw new Error('delete must not query or deploy links');
        },
    };
    const router = createCascadeRouteGroupsRouter({ RouteGroup, Link });

    const response = await request(router, {
        method: 'DELETE',
        path: `/${GROUP_A}`,
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, { success: true, id: GROUP_A });
    assert.deepEqual(calls, [{ method: 'findByIdAndDelete', id: GROUP_A }]);
});

test('route-group writes are rate limited', async () => {
    const RouteGroup = {
        async create(data) {
            return { _id: GROUP_A, ...data };
        },
    };
    const Link = {
        find() {
            return queryResult([
                { _id: LINK_A, portalNode: NODE_A, bridgeNode: NODE_B, mode: 'forward' },
            ], {});
        },
    };
    const router = createCascadeRouteGroupsRouter({ RouteGroup, Link });
    const body = {
        name: 'Rate-limited group',
        mode: 'forward',
        paths: [{ pathKey: 'primary', linkIds: [LINK_A], priority: 1, enabled: true }],
    };

    let response;
    for (let requestNumber = 1; requestNumber <= 31; requestNumber += 1) {
        response = await request(router, { method: 'POST', path: '/', body });
        assert.equal(response.status, requestNumber <= 30 ? 201 : 429, `request ${requestNumber}`);
    }
    assert.deepEqual(response.body, { error: 'Too many cascade route group changes' });
    assert.equal(response.headers.get('ratelimit-limit'), '30');
});
