'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const express = require('express');
const mongoose = require('mongoose');

const requireAuth = require('../../middleware/auth');
const cascadeRouteGroupsRouter = require('../cascadeRouteGroups');
const {
    ROUTE_GROUP_SELECT,
    TOPOLOGY_STATE_SELECT,
    createCascadeRouteGroupsRouter,
} = cascadeRouteGroupsRouter;

const GROUP_A = '507f1f77bcf86cd799439011';
const GROUP_B = '507f1f77bcf86cd799439012';
const LINK_A = '507f1f77bcf86cd799439021';
const LINK_B = '507f1f77bcf86cd799439022';

const ROOT_ENTRY_SOURCE = fs.readFileSync(path.resolve(__dirname, '../../../index.js'), 'utf8');

function queryResult(result, calls = {}, prefix = '') {
    return {
        select(value) {
            calls[`${prefix}select`] = value;
            return this;
        },
        sort(value) {
            calls[`${prefix}sort`] = value;
            return this;
        },
        async lean() {
            calls[`${prefix}lean`] = true;
            return result;
        },
    };
}

function createReadModels({ groups = [], revision = 7, deployedRevision = 5, calls = {} } = {}) {
    return {
        RouteGroup: {
            find(filter) {
                calls.groupFilter = filter;
                return queryResult(groups, calls, 'group');
            },
        },
        TopologyState: {
            findById(id) {
                calls.topologyId = id;
                return queryResult(
                    { revision, deployedRevision, internal: 'must-not-leak' },
                    calls,
                    'topology',
                );
            },
        },
    };
}

function validBody(overrides = {}) {
    return {
        expectedTopologyRevision: 7,
        name: 'Primary route',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [{ pathKey: 'primary', linkIds: [LINK_A], priority: 1, enabled: true }],
        ...overrides,
    };
}

function projectedGroup(id = GROUP_A, overrides = {}) {
    return {
        _id: id,
        name: 'Primary route',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [{ pathKey: 'primary', linkIds: [LINK_A], priority: 1, enabled: true }],
        ...overrides,
    };
}

async function request(router, {
    method = 'GET',
    path: requestPath = '/',
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
        const response = await fetch(`http://127.0.0.1:${server.address().port}${requestPath}`, {
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

test('route-group reads require nodes:read and writes require nodes:write', async () => {
    const models = createReadModels();
    const topologyDraftWriteService = {
        async createRouteGroup() {
            throw new Error('insufficiently scoped request reached write service');
        },
    };
    const router = createCascadeRouteGroupsRouter({ ...models, topologyDraftWriteService });

    const deniedRead = await request(router, { apiKeyScopes: ['nodes:write'] });
    assert.equal(deniedRead.status, 403);
    assert.equal(deniedRead.body.required, 'nodes:read');

    const allowedRead = await request(router, { apiKeyScopes: ['nodes:read'] });
    assert.equal(allowedRead.status, 200);
    assert.deepEqual(allowedRead.body, {
        topologyRevision: 7,
        deployedRevision: 5,
        routeGroups: [],
    });

    const deniedWrite = await request(router, {
        method: 'POST',
        body: validBody(),
        apiKeyScopes: ['nodes:read'],
    });
    assert.equal(deniedWrite.status, 403);
    assert.equal(deniedWrite.body.required, 'nodes:write');
});

test('GET returns the revisioned deterministic safe route-group projection', async () => {
    const calls = {};
    const models = createReadModels({
        calls,
        revision: 11,
        deployedRevision: 9,
        groups: [
            projectedGroup(GROUP_B, {
                name: 'Zulu',
                mode: 'reverse',
                paths: [{ pathKey: 'fallback', linkIds: [LINK_B], priority: 20, enabled: false }],
                internal: 'must-not-leak',
            }),
            projectedGroup(GROUP_A, {
                name: 'Alpha',
                paths: [{ pathKey: 'primary', linkIds: [LINK_A, LINK_B], priority: 10 }],
                __v: 7,
            }),
        ],
    });
    const router = createCascadeRouteGroupsRouter(models);

    const response = await request(router);

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {
        topologyRevision: 11,
        deployedRevision: 9,
        routeGroups: [
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
        ],
    });
    assert.deepEqual(calls.groupFilter, {});
    assert.equal(calls.groupselect, ROUTE_GROUP_SELECT);
    assert.deepEqual(calls.groupsort, { name: 1, _id: 1 });
    assert.equal(calls.topologyId, 'singleton');
    assert.equal(calls.topologyselect, TOPOLOGY_STATE_SELECT);
    assert.doesNotMatch(JSON.stringify(response.body), /internal|__v|must-not-leak/);
});

test('POST commits through the versioned draft boundary with a preallocated ObjectId', async () => {
    const calls = {};
    let persistedGroup;
    const models = createReadModels({ calls });
    models.RouteGroup.find = filter => {
        calls.groupFilter = filter;
        return queryResult(persistedGroup ? [persistedGroup] : [], calls, 'group');
    };
    models.RouteGroup.create = async () => {
        throw new Error('route must not write the model directly');
    };
    const topologyDraftWriteService = {
        async createRouteGroup(input) {
            calls.createRouteGroup = input;
            persistedGroup = input.routeGroup;
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const router = createCascadeRouteGroupsRouter({ ...models, topologyDraftWriteService });

    const response = await request(router, {
        method: 'POST',
        body: validBody({
            name: '  Test L2TP route  ',
            paths: [{ pathKey: 'primary', linkIds: [LINK_A], priority: 10, enabled: false }],
            rawShell: 'must-not-be-written',
        }),
    });

    assert.equal(response.status, 201);
    assert.equal(calls.createRouteGroup.expectedTopologyRevision, 7);
    assert.ok(calls.createRouteGroup.routeGroup._id instanceof mongoose.Types.ObjectId);
    assert.deepEqual(
        { ...calls.createRouteGroup.routeGroup, _id: String(calls.createRouteGroup.routeGroup._id) },
        {
            _id: String(calls.createRouteGroup.routeGroup._id),
            name: 'Test L2TP route',
            mode: 'forward',
            strategy: 'priority-failover',
            paths: [{
                pathKey: 'primary',
                linkIds: [LINK_A],
                priority: 10,
                enabled: false,
            }],
        },
    );
    assert.deepEqual(response.body, {
        topologyRevision: 8,
        deployedRevision: 5,
        routeGroups: [{
            id: String(calls.createRouteGroup.routeGroup._id),
            name: 'Test L2TP route',
            mode: 'forward',
            strategy: 'priority-failover',
            paths: [{
                pathKey: 'primary',
                linkIds: [LINK_A],
                priority: 10,
                enabled: false,
            }],
        }],
    });
    assert.doesNotMatch(JSON.stringify(calls.createRouteGroup), /rawShell|must-not-be-written/);
    assert.equal(calls.topologyId, undefined, 'mutation response uses committed revisions');
});

test('PUT replaces allowlisted fields through the draft service and preserves enabled paths', async () => {
    const calls = {};
    const body = validBody({
        expectedTopologyRevision: 12,
        name: 'Updated route',
        mode: 'reverse',
        paths: [
            { pathKey: 'primary', linkIds: [LINK_A, LINK_B], priority: 1, enabled: true },
            { pathKey: 'fallback', linkIds: [LINK_B], priority: 2, enabled: false },
        ],
        createdAt: 'attacker-controlled',
    });
    let groups = [];
    const models = createReadModels({ calls });
    models.RouteGroup.find = () => queryResult(groups, calls, 'group');
    models.RouteGroup.findByIdAndUpdate = async () => {
        throw new Error('route must not update the model directly');
    };
    const topologyDraftWriteService = {
        async updateRouteGroup(input) {
            calls.updateRouteGroup = input;
            groups = [{ _id: input.routeGroupId, ...input.changes }];
            return { revision: 13, deployedRevision: 10 };
        },
    };
    const router = createCascadeRouteGroupsRouter({ ...models, topologyDraftWriteService });

    const response = await request(router, {
        method: 'PUT',
        path: `/${GROUP_A}`,
        body,
    });

    assert.equal(response.status, 200);
    assert.deepEqual(calls.updateRouteGroup, {
        expectedTopologyRevision: 12,
        routeGroupId: GROUP_A,
        changes: {
            name: body.name,
            mode: body.mode,
            strategy: body.strategy,
            paths: body.paths,
        },
    });
    assert.deepEqual(response.body, {
        topologyRevision: 13,
        deployedRevision: 10,
        routeGroups: [{ id: GROUP_A, ...calls.updateRouteGroup.changes }],
    });
    assert.doesNotMatch(JSON.stringify(calls.updateRouteGroup), /createdAt|attacker-controlled/);
});

test('DELETE commits through the draft service and returns the updated snapshot', async () => {
    const calls = {};
    const models = createReadModels({ calls });
    models.RouteGroup.findByIdAndDelete = async () => {
        throw new Error('route must not delete the model directly');
    };
    const topologyDraftWriteService = {
        async deleteRouteGroup(input) {
            calls.deleteRouteGroup = input;
            return { revision: 15, deployedRevision: 10 };
        },
    };
    const router = createCascadeRouteGroupsRouter({ ...models, topologyDraftWriteService });

    const response = await request(router, {
        method: 'DELETE',
        path: `/${GROUP_A}`,
        body: { expectedTopologyRevision: 14 },
    });

    assert.equal(response.status, 200);
    assert.deepEqual(calls.deleteRouteGroup, {
        expectedTopologyRevision: 14,
        routeGroupId: GROUP_A,
    });
    assert.deepEqual(response.body, {
        topologyRevision: 15,
        deployedRevision: 10,
        routeGroups: [],
    });
});

test('POST, PUT, and DELETE require a non-negative safe integer topology revision', async () => {
    const models = createReadModels();
    let writes = 0;
    const topologyDraftWriteService = {
        async createRouteGroup() { writes += 1; },
        async updateRouteGroup() { writes += 1; },
        async deleteRouteGroup() { writes += 1; },
    };
    const router = createCascadeRouteGroupsRouter({ ...models, topologyDraftWriteService });
    const revisions = [undefined, '7', -1, 1.5, Number.MAX_SAFE_INTEGER + 1];

    for (const revision of revisions) {
        const postBody = validBody();
        const putBody = validBody();
        const deleteBody = {};
        if (revision !== undefined) {
            postBody.expectedTopologyRevision = revision;
            putBody.expectedTopologyRevision = revision;
            deleteBody.expectedTopologyRevision = revision;
        } else {
            delete postBody.expectedTopologyRevision;
            delete putBody.expectedTopologyRevision;
        }
        for (const candidate of [
            { method: 'POST', path: '/', body: postBody },
            { method: 'PUT', path: `/${GROUP_A}`, body: putBody },
            { method: 'DELETE', path: `/${GROUP_A}`, body: deleteBody },
        ]) {
            const response = await request(router, candidate);
            assert.equal(response.status, 400, `${candidate.method} revision ${String(revision)}`);
            assert.equal(response.body.error.code, 'INVALID_TOPOLOGY_REVISION');
        }
    }
    assert.equal(writes, 0);
});

test('route-group request validation rejects malformed typed fields before the draft service', async () => {
    const models = createReadModels();
    let writes = 0;
    const topologyDraftWriteService = {
        async createRouteGroup() { writes += 1; },
    };
    const router = createCascadeRouteGroupsRouter({ ...models, topologyDraftWriteService });
    const cases = [
        { body: validBody({ mode: 'direct' }), message: 'mode must be "reverse" or "forward"' },
        { body: validBody({ strategy: 'round-robin' }), message: 'strategy must be "priority-failover"' },
        {
            body: validBody({
                paths: [
                    { pathKey: 'duplicate', linkIds: [LINK_A], priority: 1 },
                    { pathKey: 'duplicate', linkIds: [LINK_B], priority: 2 },
                ],
            }),
            message: 'pathKey values must be unique',
        },
        {
            body: validBody({
                paths: [{ pathKey: 'primary', linkIds: [LINK_A], priority: 1, enabled: 'yes' }],
            }),
            message: 'paths[0].enabled must be a boolean',
        },
        {
            body: validBody({
                paths: [{ pathKey: 'primary', linkIds: ['not-an-object-id'], priority: 1 }],
            }),
            message: 'paths[0].linkIds[0] must be a valid link ID',
        },
    ];

    for (const candidate of cases) {
        const response = await request(router, { method: 'POST', body: candidate.body });
        assert.equal(response.status, 400, candidate.message);
        assert.deepEqual(response.body, {
            error: { code: 'INVALID_REQUEST', message: candidate.message },
        });
    }
    assert.equal(writes, 0);
});

test('PUT and DELETE reject invalid route-group IDs before the draft service', async () => {
    const models = createReadModels();
    let writes = 0;
    const topologyDraftWriteService = {
        async updateRouteGroup() { writes += 1; },
        async deleteRouteGroup() { writes += 1; },
    };
    const router = createCascadeRouteGroupsRouter({ ...models, topologyDraftWriteService });

    for (const method of ['PUT', 'DELETE']) {
        const response = await request(router, {
            method,
            path: '/invalid-id',
            body: method === 'PUT' ? validBody() : { expectedTopologyRevision: 7 },
        });
        assert.equal(response.status, 400);
        assert.equal(response.body.error.code, 'INVALID_ROUTE_GROUP_ID');
    }
    assert.equal(writes, 0);
});

test('draft boundary errors map to safe 400, 404, 409, 422, and 500 responses', async () => {
    const cases = [
        { code: 'INVALID_TOPOLOGY_REVISION', status: 400 },
        { code: 'CASCADE_ROUTE_GROUP_NOT_FOUND', status: 404 },
        { code: 'STALE_TOPOLOGY_REVISION', status: 409 },
        { code: 'CASCADE_ROUTE_GROUP_CONFLICT', status: 409 },
        { code: 'CASCADE_ROUTE_GROUP_IN_USE', status: 409 },
        {
            code: 'INVALID_TOPOLOGY_DRAFT',
            status: 422,
            errors: [{ code: 'UNKNOWN_LINK', linkId: LINK_B }],
        },
        { code: 'DATABASE_PASSWORD_LEAK', status: 500 },
    ];

    for (const candidate of cases) {
        const models = createReadModels();
        const topologyDraftWriteService = {
            async updateRouteGroup() {
                const error = new Error(`safe ${candidate.code}`);
                error.code = candidate.code;
                error.errors = candidate.errors;
                throw error;
            },
        };
        const router = createCascadeRouteGroupsRouter({ ...models, topologyDraftWriteService });
        const response = await request(router, {
            method: 'PUT',
            path: `/${GROUP_A}`,
            body: validBody(),
        });

        assert.equal(response.status, candidate.status, candidate.code);
        if (candidate.status === 500) {
            assert.deepEqual(response.body, {
                error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
            });
            assert.doesNotMatch(JSON.stringify(response.body), /DATABASE_PASSWORD_LEAK/);
        } else {
            assert.equal(response.body.error.code, candidate.code);
            assert.equal(response.body.error.message, `safe ${candidate.code}`);
            if (candidate.errors) assert.deepEqual(response.body.error.details, candidate.errors);
        }
    }
});

test('router constructs the topology draft service with all participating models', async () => {
    const calls = {};
    const models = createReadModels({ calls });
    const Node = { modelName: 'HyNode' };
    const Link = { modelName: 'CascadeLink' };
    const RelayState = { modelName: 'RelayL2tpState' };
    const createDraftWriteService = dependencies => {
        calls.dependencies = dependencies;
        return {
            async createRouteGroup() {
                return { revision: 8, deployedRevision: 5 };
            },
        };
    };
    const router = createCascadeRouteGroupsRouter({
        ...models,
        Node,
        Link,
        RelayState,
        createDraftWriteService,
    });

    const response = await request(router, { method: 'POST', body: validBody() });

    assert.equal(response.status, 201);
    assert.deepEqual(calls.dependencies, {
        HyNode: Node,
        CascadeLink: Link,
        CascadeRouteGroup: models.RouteGroup,
        CascadeTopologyState: models.TopologyState,
        RelayL2tpState: RelayState,
    });
});

test('route-group writes are rate limited', async () => {
    const models = createReadModels();
    const topologyDraftWriteService = {
        async createRouteGroup() {
            return { revision: 8, deployedRevision: 5 };
        },
    };
    const router = createCascadeRouteGroupsRouter({ ...models, topologyDraftWriteService });

    let response;
    for (let requestNumber = 1; requestNumber <= 31; requestNumber += 1) {
        response = await request(router, {
            method: 'POST',
            body: validBody(),
        });
        assert.equal(response.status, requestNumber <= 30 ? 201 : 429, `request ${requestNumber}`);
    }
    assert.deepEqual(response.body, { error: 'Too many cascade route group changes' });
    assert.equal(response.headers.get('ratelimit-limit'), '30');
});
