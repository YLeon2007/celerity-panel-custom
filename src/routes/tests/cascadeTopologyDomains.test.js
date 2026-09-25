'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');

const createRouter = require('../cascadeTopologyDeploy');

function chainable(result) {
    const chain = {
        select() { return chain; },
        lean() { return Promise.resolve(result); },
    };
    return chain;
}

function makeModels({ nodes = [], links = [], domainStates = [] } = {}) {
    return {
        HyNode: { find: () => chainable(nodes) },
        CascadeLink: { find: () => chainable(links) },
        CascadeTopologyState: { find: () => chainable(domainStates) },
        CascadeRouteGroup: {},
        RelayL2tpState: {},
        TopologyOperation: {},
        NodeOperationLock: {},
    };
}

function makeApp(models) {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => { req.apiKey = true; next(); });
    app.use('/api/cascade/topology', createRouter.createCascadeTopologyDeployRouter
        ? createRouter.createCascadeTopologyDeployRouter({
            models,
            requireAuth: (req, res, next) => next(),
            requireScope: () => (req, res, next) => next(),
            csrf: (req, res, next) => next(),
            deployRateLimiter: (req, res, next) => next(),
            routeLogger: { error() {}, info() {}, warn() {} },
        })
        : createRouter);
    return app;
}

async function getJson(app, path) {
    const server = await new Promise(resolve => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    try {
        const res = await fetch(`http://127.0.0.1:${server.address().port}${path}`);
        return { status: res.status, body: await res.json() };
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
}

test('GET /domains lists connected components with per-domain deployed revisions', async () => {
    const app = makeApp(makeModels({
        nodes: [
            { _id: 'pa', name: 'Portal A', cascadeRole: 'portal' },
            { _id: 'ba', name: 'Bridge A', cascadeRole: 'bridge' },
            { _id: 'pb', name: 'Portal B', cascadeRole: 'portal' },
            { _id: 'bb', name: 'Bridge B', cascadeRole: 'bridge' },
        ],
        links: [
            { _id: 'l1', portalNode: 'pa', bridgeNode: 'ba' },
            { _id: 'l2', portalNode: 'pb', bridgeNode: 'bb' },
        ],
        domainStates: [
            { _id: 'domain:ba', domainKey: 'ba', label: 'L', revision: 9, deployedRevision: 9 },
        ],
    }));

    const { status, body } = await getJson(app, '/api/cascade/topology/domains');
    assert.equal(status, 200);
    assert.equal(body.domains.length, 2);
    const deployed = body.domains.find(d => d.deployedRevision === 9);
    assert.ok(deployed, 'expected one domain with deployedRevision 9');
    assert.ok(deployed.label.includes('Portal A'));
    const fresh = body.domains.find(d => d.deployedRevision === null);
    assert.ok(fresh, 'expected one domain without a deployed revision');
});
