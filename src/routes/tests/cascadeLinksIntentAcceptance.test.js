'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createCascadeLinksRouter } = require('../cascadeLinks');
const sshPool = require('../../services/sshPoolService');

// The route import starts the SSH pool's recurring cleanup timer.
test.after(() => sshPool.closeAll());

const ids = ['507f1f77bcf86cd799439031', '507f1f77bcf86cd799439032'];
async function request(router, body, method = 'POST', route = '/') {
    const app = express(); app.use(express.json());
    app.use((req, res, next) => { req.session = { authenticated: true }; next(); });
    app.use(router);
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${route}`, {
            method, headers: { 'content-type': 'application/json', 'idempotency-key': 'rapid-1' },
            ...(method === 'GET' ? {} : { body: JSON.stringify(body) }),
        });
        const text = await response.text();
        let result; try { result = JSON.parse(text); } catch { result = text; }
        return { status: response.status, body: result };
    } finally { await new Promise(resolve => server.close(resolve)); }
}
test('autoDeploy accepts a persisted job without claiming a created link or advancing the draft', async () => {
    let mutations = 0; let accepted;
    const router = createCascadeLinksRouter({
        Node: { findById: async id => ({ _id: id, name: id }) },
        Link: { findOne: async () => null, find: () => ({ populate() { return this; }, sort() { return this; }, lean: async () => [] }) },
        topologyDraftWriteService: { async createLink() { mutations++; return { revision: 8 }; } },
        TopologyState: { findById: () => ({ select() { return this; }, lean: async () => ({ revision: 7 }) }) },
        topologyIntentService: { async accept(input) {
            accepted = input;
            return { jobId: '507f1f77bcf86cd799439040', status: 'waiting', acceptanceRevision: 7 };
        } },
        maintainAutoL2tpPathsFn: async () => undefined,
        prepareL2tpIngressFn: async () => ({ revision: 8 }),
        topologyCoordinator: { queue: async () => ({ operationId: 'fake', topologyRevision: 8, status: 'queued' }) },
        invalidateSubscriptions: async () => {}, invalidateTopology: async () => {},
    });
    const result = await request(router, {
        name: 'deferred', portalNodeId: ids[0], bridgeNodeId: ids[1],
        mode: 'forward', autoDeploy: true, expectedTopologyRevision: 7,
    });
    assert.equal(result.status, 202, JSON.stringify(result.body));
    assert.equal(mutations, 0);
    assert.equal(result.body.createdLinkId, undefined);
    assert.equal(result.body.autoDeployOperation, undefined);
    assert.equal(result.body.autoDeployJob.jobId, '507f1f77bcf86cd799439040');
    assert.equal(accepted.requestKey, 'rapid-1');
    assert.equal(accepted.expectedTopologyRevision, 7);
    assert.equal(accepted.link.autoDeploy, true);
});
test('missing supervised intent runtime refuses autoDeploy before any draft mutation', async () => {
    let mutations = 0;
    const query = () => ({ populate() { return this; }, sort() { return this; }, select() { return this; }, lean: async () => [] });
    const router = createCascadeLinksRouter({
        Node: { findById: async id => ({ _id: id, name: id }) }, Link: { findOne: async () => null, find: query },
        TopologyState: { findById: query }, topologyIntentService: null,
        topologyDraftWriteService: { async createLink() { mutations++; return { revision: 8 }; } },
        maintainAutoL2tpPathsFn: async () => undefined, prepareL2tpIngressFn: async () => ({ revision: 8 }),
        topologyCoordinator: { queue: async () => ({ operationId: 'unsafe', topologyRevision: 8, status: 'queued' }) },
        invalidateSubscriptions: async () => {}, invalidateTopology: async () => {},
    });
    const result = await request(router, { name: 'no-runtime', portalNodeId: ids[0], bridgeNodeId: ids[1], autoDeploy: true, expectedTopologyRevision: 7 });
    assert.equal(result.status, 503, JSON.stringify(result.body));
    assert.equal(mutations, 0);
    assert.equal(result.body.error.code, 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
});
test('accepted job status is queryable without pretending its proposed link exists', async () => {
    const jobId = '507f1f77bcf86cd799439040';
    const job = { jobId, status: 'waiting', acceptanceRevision: 7, ordinal: 1, attempts: 0 };
    const router = createCascadeLinksRouter({ topologyIntentService: { get: async id => { assert.equal(id, jobId); return job; } } });
    const result = await request(router, undefined, 'GET', `/auto-deploy-jobs/${jobId}`);
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.deepEqual(result.body, { autoDeployJob: job });
});
