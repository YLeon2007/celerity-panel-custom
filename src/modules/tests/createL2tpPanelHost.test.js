'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');

const { createL2tpPanelHost } = require('../createL2tpPanelHost');

const TOPOLOGY_ENABLED_ENV = Object.freeze({
    L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true',
    TOPOLOGY_TEST_EXECUTION_ENABLED: 'true',
});

function passThrough(req, res, next) {
    next();
}

async function request(router, pathOrOptions) {
    const options = typeof pathOrOptions === 'string'
        ? { path: pathOrOptions }
        : pathOrOptions;
    const app = express();
    app.use(express.json());
    app.use(router);
    const server = await new Promise(resolve => {
        const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
    });

    try {
        const response = await fetch(`http://127.0.0.1:${server.address().port}${options.path}`, {
            method: options.method || 'GET',
            headers: options.body === undefined ? {} : { 'content-type': 'application/json' },
            body: options.body === undefined ? undefined : JSON.stringify(options.body),
        });
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

test('builds the concrete repository adapters and composes a dormant runtime', async () => {
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
    assert.equal(typeof runtimeCalls[0].stateManagementService.configureRelay, 'function');
    await assert.rejects(
        runtimeCalls[0].stateManagementService.configureRelay('relay-1', {}),
        error => error?.code === 'L2TP_STATE_MANAGEMENT_UNAVAILABLE',
    );
    assert.equal(typeof runtimeCalls[0].userManagementService.listUsers, 'function');
    await assert.rejects(
        runtimeCalls[0].userManagementService.listUsers('relay-1'),
        error => error?.code === 'L2TP_USER_MANAGEMENT_UNAVAILABLE',
    );
    assert.strictEqual(runtimeCalls[0].requireAuth, passThrough);
    assert.strictEqual(runtimeCalls[0].requireOnboarding, passThrough);
    assert.strictEqual(runtimeCalls[0].csrf, passThrough);
    assert.strictEqual(runtimeCalls[0].rateLimiter, passThrough);
    assert.strictEqual(runtimeCalls[0].loadPanelOverview, loadPanelOverview);
    assert.strictEqual(runtimeCalls[0].renderPage, renderPage);
    assert.equal(typeof runtimeCalls[0].preflightRunner, 'function');
    assert.equal(typeof runtimeCalls[0].candidateService.buildCandidate, 'function');
    await assert.rejects(
        runtimeCalls[0].candidateService.buildCandidate(),
        error => error?.code === 'L2TP_XRAY_CANDIDATE_UNAVAILABLE',
    );
    assert.equal(typeof runtimeCalls[0].transport.uploadRootFile, 'function');
    assert.equal(typeof runtimeCalls[0].lockService.acquire, 'function');
    assert.equal(typeof runtimeCalls[0].stateReconciler, 'function');
    await assert.rejects(
        runtimeCalls[0].stateReconciler({ operation: { kind: 'install' } }),
        error => error?.code === 'L2TP_STATE_RECONCILER_UNAVAILABLE',
    );
    assert.equal(typeof runtimeCalls[0].clock.now, 'function');
    assert.equal(typeof runtimeCalls[0].workerId, 'string');
    assert.equal(typeof runtimeCalls[0].leaseMs, 'number');
    assert.strictEqual(host.moduleEntry, moduleEntry);
    assert.strictEqual(host.loadPanelOverview, loadPanelOverview);
    assert.ok(host.topologyRuntime instanceof FakeTopologyRuntime);
    assert.strictEqual(host.runtime, runtime);
    assert.equal(workerRuns, 0);
});

test('opted-in panel host passes the lock model to topology recovery and starts', () => {
    const models = {
        RelayL2tpState: {},
        CascadeRouteGroup: {},
        CascadeTopologyState: {},
        L2tpOperation: {},
        TopologyOperation: {},
        NodeOperationLock: {},
    };
    const topologyDependencies = [];
    let topologyWorker;
    let recoveryStarts = 0;
    const moduleEntry = {
        registerModels: () => models,
        createTopologyDeploymentService(dependencies) {
            topologyDependencies.push(dependencies);
            topologyWorker = { run: async () => {} };
            return { operationWorker: topologyWorker };
        },
    };

    const host = createL2tpPanelHost({
        env: TOPOLOGY_ENABLED_ENV,
        moduleEntry,
        topologyRuntime: {},
        Repository: class FakeRepository {},
        createRepositoryAdapters: () => ({
            nodeRepository: {},
            stateRepository: {},
            operationRepository: {},
        }),
        createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime: () => ({
            runtime: { stateManagementService: {} },
            start: () => ({}),
            async stop() {},
        }),
        createTopologyRecoveryLifecycle(dependencies) {
            assert.strictEqual(dependencies.worker, topologyWorker);
            return {
                start() {
                    recoveryStarts += 1;
                },
                async stop() {},
            };
        },
    });

    host.start();

    assert.equal(topologyDependencies.length, 1);
    assert.strictEqual(topologyDependencies[0].NodeOperationLock, models.NodeOperationLock);
    assert.equal(recoveryStarts, 1);
});

test('actual mounted configure route uses the state management service injected through the host runtime', async () => {
    const calls = [];
    const models = {
        RelayL2tpState: {},
        CascadeRouteGroup: {},
        CascadeTopologyState: {},
        L2tpOperation: {},
        NodeOperationLock: {},
    };
    const stateManagementService = {
        async configureRelay(nodeId, input) {
            calls.push({ nodeId, input });
            return {
                node: nodeId,
                desiredState: 'installed',
                status: 'not_installed',
                routeGroup: input.routeGroupId,
                clientCidr: input.clientCidr,
                pskEncrypted: 'must-not-be-returned',
            };
        },
    };
    const realModuleEntry = require('../relay-l2tp');
    const moduleEntry = {
        registerModels: () => models,
        registerRoutes: realModuleEntry.registerRoutes,
    };
    const host = createL2tpPanelHost({
        requireAuth: passThrough,
        requireOnboarding: passThrough,
        csrf: passThrough,
        rateLimiter: passThrough,
        renderPage() {},
        moduleEntry,
        HyNode: {},
        topologyRuntime: {},
        Repository: class FakeRepository {},
        createRepositoryAdapters: () => ({
            nodeRepository: {},
            stateRepository: {},
            operationRepository: {},
        }),
        createPanelOverviewLoader: () => async () => ({}),
        stateManagementService,
    });
    const mountedRouter = express.Router();

    host.moduleEntry.registerRoutes({
        panelRouter: mountedRouter,
        l2tpService: host.runtime.service,
        stateManagementService: host.runtime.stateManagementService,
        userManagementService: host.runtime.userManagementService,
        requireAuth: passThrough,
        requireOnboarding: passThrough,
        csrf: passThrough,
        rateLimiter: passThrough,
        loadPanelOverview: host.loadPanelOverview,
        renderPage() {},
    });

    const response = await request(mountedRouter, {
        method: 'POST',
        path: '/nodes/relay-17/l2tp/configure',
        body: {
            clientCidr: '10.77.0.0/24',
            routeGroupId: 'route-group-a',
            generatePsk: true,
            password: 'must-not-reach-service',
        },
    });

    assert.equal(response.status, 200);
    assert.deepEqual(calls, [{
        nodeId: 'relay-17',
        input: {
            clientCidr: '10.77.0.0/24',
            routeGroupId: 'route-group-a',
            generatePsk: true,
        },
    }]);
    assert.deepEqual(response.body, {
        node: 'relay-17',
        desiredState: 'installed',
        status: 'not_installed',
        routeGroup: 'route-group-a',
        clientCidr: '10.77.0.0/24',
    });
    assert.doesNotMatch(JSON.stringify(response.body), /must-not-be-returned/);
});

test('explicit opt-in wires the topology health provider with its bounded staleness', () => {
    const HyNode = { modelName: 'HyNode' };
    const CascadeLink = { modelName: 'CascadeLink' };
    const models = {
        RelayL2tpState: {},
        CascadeRouteGroup: { modelName: 'CascadeRouteGroup' },
        CascadeTopologyState: {},
        L2tpOperation: {},
    };
    const clock = { now: () => new Date('2026-09-22T12:00:00.000Z') };
    const compiler = () => ({ relays: [] });
    let topologyDependencies;

    class FakeTopologyRuntime {
        constructor(dependencies) {
            topologyDependencies = dependencies;
        }
    }

    class FakeRepository {}

    createL2tpPanelHost({
        moduleEntry: { registerModels: () => models },
        HyNode,
        CascadeLink,
        TopologyRuntime: FakeTopologyRuntime,
        Repository: FakeRepository,
        compiler,
        enableTopologyHealthProvider: true,
        topologyHealthMaxStalenessMs: 45_000,
        clock,
        createRepositoryAdapters: () => ({
            nodeRepository: {},
            stateRepository: {},
            operationRepository: {},
        }),
        createPanelOverviewLoader: () => async () => ({}),
        createRuntime: () => ({ worker: {} }),
    });

    assert.deepEqual(topologyDependencies, {
        HyNode,
        CascadeLink,
        CascadeRouteGroup: models.CascadeRouteGroup,
        compiler,
        enableHealthProvider: true,
        healthMaxStalenessMs: 45_000,
        clock,
    });
    assert.equal(Object.hasOwn(topologyDependencies, 'healthByPathKey'), false);
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

test('passes explicitly injected execution factories and candidate resolvers into composition', () => {
    const models = {
        RelayL2tpState: {},
        CascadeRouteGroup: {},
        CascadeTopologyState: {},
        L2tpOperation: {},
        NodeOperationLock: {},
    };
    class FakeNodeTransport {}
    const createPreflightRunner = () => async () => ({ ok: true });
    const createCandidateService = () => ({ async buildCandidate() {} });
    const candidateNodeResolver = async () => ({});
    const candidateUserResolver = async () => [];
    const configGenerator = () => '{}';
    const fragmentProvider = () => ({});
    let executionDependencies;

    createL2tpPanelHost({
        moduleEntry: { registerModels: () => models },
        HyNode: {},
        NodeTransport: FakeNodeTransport,
        createPreflightRunner,
        createCandidateService,
        candidateNodeResolver,
        candidateUserResolver,
        configGenerator,
        fragmentProvider,
        topologyRuntime: {},
        Repository: class FakeRepository {},
        createRepositoryAdapters: () => ({
            nodeRepository: {},
            stateRepository: {},
            operationRepository: {},
        }),
        createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime(dependencies) {
            executionDependencies = dependencies;
            return {
                runtime: { stateManagementService: {} },
                start() {},
                async stop() {},
            };
        },
    });

    assert.strictEqual(executionDependencies.NodeTransport, FakeNodeTransport);
    assert.strictEqual(executionDependencies.createPreflightRunner, createPreflightRunner);
    assert.strictEqual(executionDependencies.createCandidateService, createCandidateService);
    assert.strictEqual(executionDependencies.candidateNodeResolver, candidateNodeResolver);
    assert.strictEqual(executionDependencies.candidateUserResolver, candidateUserResolver);
    assert.strictEqual(executionDependencies.configGenerator, configGenerator);
    assert.strictEqual(executionDependencies.fragmentProvider, fragmentProvider);
});
