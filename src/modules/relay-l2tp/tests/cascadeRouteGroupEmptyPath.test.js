'use strict';
// Persistence represents a retained no-exit path. Public group replacement
// still requires an explicitly ordered nonempty path; it cannot publish state.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createCascadeRouteGroupsRouter } = require('../../../routes/cascadeRouteGroups');
const id = n => n.toString(16).padStart(24, '0');
const group = { _id: id(60), name: 'retained', mode: 'reverse', strategy: 'priority-failover',
    paths: [{ pathKey: 'mine', linkIds: [], priority: 4, enabled: true }] };
const query = value => ({ select() { return this; }, sort() { return this; }, async lean() { return value; } });
async function serve(work) {
    const calls = [];
    const router = createCascadeRouteGroupsRouter({
        RouteGroup: { find: () => query([structuredClone(group)]) },
        TopologyState: { findById: () => query({ revision: 7, deployedRevision: 5 }) },
        topologyDraftWriteService: {
            async createRouteGroup(input) { calls.push(['create', input]); return { revision: 8, deployedRevision: 5 }; },
            async updateRouteGroup(input) { calls.push(['update', input]); return { revision: 8, deployedRevision: 5 }; },
        },
    });
    const app = express(); app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    app.use(router);
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try {
        await work(async (method, body) => {
            const response = await fetch(`http://127.0.0.1:${server.address().port}/${method === 'PUT' ? id(60) : ''}`, {
                method, headers: { 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}),
            });
            return { status: response.status, body: await response.json() };
        }, calls);
    } finally { await new Promise(resolve => server.close(resolve)); }
}
test('public POST and PUT still refuse empty or missing group/path arrays before draft writes', async () => {
    await serve(async (request, calls) => {
        const { _id, ...body } = group;
        for (const method of ['POST', 'PUT']) {
            for (const paths of [[], undefined, group.paths,
                [{ pathKey: 'mine', priority: 4 }], [{ pathKey: 'mine', priority: 4, linkIds: null }]]) {
                const result = await request(method, { ...body, paths, expectedTopologyRevision: 7 });
                assert.equal(result.status, 400, JSON.stringify({ method, paths, result }));
                assert.equal(result.body.error.code, 'INVALID_REQUEST');
            }
        }
        assert.deepEqual(calls, []);
    });
});
test('public nonempty POST and PUT retain their versioned draft boundary', async () => {
    await serve(async (request, calls) => {
        const { _id, ...body } = group;
        const paths = [{ pathKey: 'mine', linkIds: [id(10)], priority: 4, enabled: true }];
        for (const method of ['POST', 'PUT']) {
            const result = await request(method, { ...body, paths, expectedTopologyRevision: 7 });
            assert.equal(result.status, method === 'POST' ? 201 : 200);
        }
        assert.equal(calls.length, 2);
        assert.deepEqual(calls.map(([kind]) => kind), ['create', 'update']);
        assert.deepEqual(calls[0][1].routeGroup.paths, paths);
        assert.deepEqual(calls[1][1].changes.paths, paths);
        assert.equal(calls[0][1].expectedTopologyRevision, 7);
        assert.equal(calls[1][1].expectedTopologyRevision, 7);
    });
});
test('public GET faithfully projects a retained enabled empty path without manufacturing egress', async () => {
    await serve(async request => {
        const result = await request('GET');
        assert.equal(result.status, 200);
        assert.deepEqual(result.body.routeGroups[0].paths, group.paths);
        assert.equal(result.body.topologyRevision, 7);
        assert.equal(result.body.deployedRevision, 5);
    });
});
