'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');

const { createL2tpPanelHost } = require('../createL2tpPanelHost');

function passThrough(req, res, next) {
    next();
}

async function request(router, path) {
    const app = express();
    app.use(router);
    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
    });

    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`);
        return {
            status: response.status,
            body: await response.json(),
        };
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => (error ? reject(error) : resolve()));
        });
    }
}

test('builds the concrete repository adapters and composes a dormant runtime', () => {
    const HyNode = { modelName: 'HyNode' };
    const CascadeLink = { modelName: 'CascadeLink' };
    const models = {
        RelayL2tpState: { modelName: 'RelayL2tpState' },
        CascadeRouteGroup: { modelName: 'CascadeRouteGroup' },
        CascadeTopologyState: { modelName: 'CascadeTopologyState' },
        L2tpOperation: { modelName: 'L2tpOperation' },
        NodeOperationLock: { modelName: 'NodeOperationLock' },
    };
    const compilerData = { relays: [{ nodeId: 'relay-1', routeGroups: [] }] };
    const healthByPathKey = { 'group-a:primary': true };
    const compiler = () => ({ relays: [] });
    const topologyRuntimeConstructions = [];
    const repositoryConstructions = [];
    const adapterCalls = [];
    const overviewLoaderCalls = [];
    const runtimeCalls = [];
    let workerRuns = 0;

    class FakeTopologyRuntime {
        constructor(dependencies) {
            topologyRuntimeConstructions.push(dependencies);
        }
    }

    class FakeRepository {
        constructor(dependencies) {
            repositoryConstructions.push(dependencies);
        }
    }

    const adapters = {
        nodeRepository: { kind: 'node-repository' },
        stateRepository: { kind: 'state-repository' },
        operationRepository: { kind: 'operation-repository' },
    };
    const moduleEntry = {
        registerModels() {
            return models;
        },
    };
    const runtime = {
        service: { kind: 'l2tp-service' },
        router: { kind: 'l2tp-router' },
        worker: {
            runOnce() {
                workerRuns += 1;
            },
        },
    };
    const loadPanelOverview = async () => ({});
    const renderPage = () => {};

    const host = createL2tpPanelHost({
        requireAuth: passThrough,
        requireOnboarding: passThrough,
        csrf: passThrough,
        rateLimiter: passThrough,
        renderPage,
        compilerData,
        healthByPathKey,
        compiler,
        moduleEntry,
        HyNode,
        CascadeLink,
        TopologyRuntime: FakeTopologyRuntime,
        Repository: FakeRepository,
        createRepositoryAdapters(repository) {
            adapterCalls.push(repository);
            return adapters;
        },
        createPanelOverviewLoader(dependencies) {
            overviewLoaderCalls.push(dependencies);
            return loadPanelOverview;
        },
        createRuntime(dependencies) {
            runtimeCalls.push(dependencies);
            return runtime;
        },
    });

    assert.equal(topologyRuntimeConstructions.length, 1);
    assert.deepEqual(topologyRuntimeConstructions[0], {
        HyNode,
        CascadeLink,
        CascadeRouteGroup: models.CascadeRouteGroup,
        compiler,
        healthByPathKey,
    });
    assert.equal(repositoryConstructions.length, 1);
    assert.deepEqual(repositoryConstructions[0], {
        HyNode,
        RelayL2tpState: models.RelayL2tpState,
        CascadeRouteGroup: models.CascadeRouteGroup,
        CascadeTopologyState: models.CascadeTopologyState,
        L2tpOperation: models.L2tpOperation,
        compilerData,
        topologyRuntime: host.topologyRuntime,
    });
    assert.deepEqual(adapterCalls, [host.repository]);
    assert.deepEqual(overviewLoaderCalls, [{
        HyNode,
        RelayL2tpState: models.RelayL2tpState,
        CascadeTopologyState: models.CascadeTopologyState,
        CascadeRouteGroup: models.CascadeRouteGroup,
        L2tpOperation: models.L2tpOperation,
    }]);
    assert.equal(runtimeCalls.length, 1);
    assert.strictEqual(runtimeCalls[0].operationModel, models.L2tpOperation);
    assert.strictEqual(runtimeCalls[0].operationRepository, adapters.operationRepository);
    assert.strictEqual(runtimeCalls[0].nodeRepository, adapters.nodeRepository);
    assert.strictEqual(runtimeCalls[0].stateRepository, adapters.stateRepository);
    assert.strictEqual(runtimeCalls[0].requireAuth, passThrough);
    assert.strictEqual(runtimeCalls[0].requireOnboarding, passThrough);
    assert.strictEqual(runtimeCalls[0].csrf, passThrough);
    assert.strictEqual(runtimeCalls[0].rateLimiter, passThrough);
    assert.strictEqual(runtimeCalls[0].loadPanelOverview, loadPanelOverview);
    assert.strictEqual(runtimeCalls[0].renderPage, renderPage);
    assert.equal(typeof runtimeCalls[0].preflightRunner, 'function');
    assert.equal(typeof runtimeCalls[0].transport.uploadRootFile, 'function');
    assert.equal(typeof runtimeCalls[0].lockService.acquire, 'function');
    assert.equal(typeof runtimeCalls[0].clock.now, 'function');
    assert.equal(typeof runtimeCalls[0].workerId, 'string');
    assert.equal(typeof runtimeCalls[0].leaseMs, 'number');
    assert.strictEqual(host.moduleEntry, moduleEntry);
    assert.strictEqual(host.loadPanelOverview, loadPanelOverview);
    assert.ok(host.topologyRuntime instanceof FakeTopologyRuntime);
    assert.strictEqual(host.runtime, runtime);
    assert.equal(workerRuns, 0);
});

test('real panel runtime GET operation strips legacy nested secrets and error details', async () => {
    const legacyOperation = {
        _id: 'operation-legacy',
        status: 'failed',
        password: 'top-level-secret',
        plan: {
            ok: false,
            psk: 'plan-secret',
            error: {
                code: 'NO_HEALTHY_PATH',
                message: 'private failure detail',
                details: { password: 'nested-error-secret' },
            },
            steps: [{ type: 'verify', privateKey: 'nested-step-secret' }],
        },
    };
    const operationModel = {
        findById(operationId) {
            assert.equal(operationId, 'operation-legacy');
            const query = {
                select() { return this; },
                lean() { return Promise.resolve(legacyOperation); },
                then(resolve, reject) {
                    return Promise.resolve(legacyOperation).then(resolve, reject);
                },
            };
            return query;
        },
    };
    const models = {
        RelayL2tpState: {},
        CascadeRouteGroup: {},
        CascadeTopologyState: {},
        L2tpOperation: operationModel,
    };
    const host = createL2tpPanelHost({
        requireAuth: passThrough,
        requireOnboarding: passThrough,
        csrf: passThrough,
        rateLimiter: passThrough,
        renderPage() {},
        moduleEntry: { registerModels: () => models },
        HyNode: {},
        topologyRuntime: {},
        createPanelOverviewLoader: () => async () => ({}),
    });

    const response = await request(
        host.runtime.router,
        '/l2tp/operations/operation-legacy',
    );

    assert.equal(response.status, 200);
    assert.deepEqual(response.body, {
        _id: 'operation-legacy',
        status: 'failed',
        plan: {
            ok: false,
            error: { code: 'NO_HEALTHY_PATH' },
            steps: [{ type: 'verify' }],
        },
    });
    assert.doesNotMatch(
        JSON.stringify(response.body),
        /top-level-secret|plan-secret|private failure detail|nested-error-secret|nested-step-secret/,
    );
});
