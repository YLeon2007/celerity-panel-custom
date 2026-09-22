'use strict';

const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const moduleEntry = require('./relay-l2tp');
const { compileTopology } = require('./relay-l2tp/domain/topologyCompiler');
const { L2tpStateRepository, createL2tpServiceRepositoryAdapters } = require('./relay-l2tp/repositories/l2tpStateRepository');
const { createPanelOverviewLoader } = require('./relay-l2tp/routes/panelOverview');
const { createL2tpRuntime } = require('./relay-l2tp/runtime/createL2tpRuntime');
const { createL2tpWorkerLifecycle } = require('./relay-l2tp/runtime/createL2tpWorkerLifecycle');
const { L2tpNodeTransport } = require('./relay-l2tp/services/l2tpNodeTransport');
const { createL2tpNodeTransportFactory } = require('./relay-l2tp/services/l2tpNodeTransportFactory');
const { NodeOperationLockRepository } = require('./relay-l2tp/services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('./relay-l2tp/services/nodeOperationLockService');
const { TopologyRuntimeService } = require('./relay-l2tp/services/topologyRuntimeService');

const DEFAULT_COMPILER_DATA = Object.freeze({ relays: Object.freeze([]) });
const DEFAULT_HEALTH_BY_PATH_KEY = Object.freeze({});
const DEFAULT_CLOCK = Object.freeze({ now: () => new Date() });
const DEFAULT_LEASE_MS = 30_000;
const DORMANT_LIFECYCLE_STATE = Object.freeze({
    enabled: false,
    running: false,
    inFlight: false,
});

function workerNotStartedError() {
    const error = new Error('The L2TP operation worker is not started by the panel host');
    error.code = 'L2TP_WORKER_NOT_STARTED';
    return error;
}

const dormantTransport = Object.freeze({
    async uploadRootFile() {
        throw workerNotStartedError();
    },
    async runArtifactCommand() {
        throw workerNotStartedError();
    },
});

const dormantLockService = Object.freeze({
    async acquire() {
        throw workerNotStartedError();
    },
    async release() {
        throw workerNotStartedError();
    },
});

const dormantLifecycle = Object.freeze({
    start() {
        return { ...DORMANT_LIFECYCLE_STATE };
    },
    async stop() {
        return { ...DORMANT_LIFECYCLE_STATE };
    },
});

function lifecycleSummary(state) {
    return {
        enabled: state?.enabled === true,
        running: state?.running === true,
        inFlight: state?.inFlight === true,
    };
}

async function unavailablePreflightRunner() {
    return {
        ok: false,
        checks: [],
        error: { code: 'L2TP_PREFLIGHT_RUNNER_UNAVAILABLE' },
    };
}

async function unavailableSecretResolver() {
    const error = new Error('L2TP secret resolver is unavailable');
    error.code = 'L2TP_SECRET_RESOLVER_UNAVAILABLE';
    throw error;
}

function createL2tpPanelHost({
    requireAuth,
    requireOnboarding,
    csrf,
    rateLimiter,
    renderPage,
    compilerData = DEFAULT_COMPILER_DATA,
    healthByPathKey = DEFAULT_HEALTH_BY_PATH_KEY,
    compiler = compileTopology,
    topologyRuntime: injectedTopologyRuntime,
    preflightRunner: injectedPreflightRunner,
    secretResolver = unavailableSecretResolver,
    artifactMaterializer,
    nodeSSHFactory,
    workerLifecycle,
    NodeTransport: RuntimeNodeTransport = L2tpNodeTransport,
    createTransportFactory: createNodeTransportFactory = createL2tpNodeTransportFactory,
    NodeOperationLockService: RuntimeLockService = NodeOperationLockService,
    NodeOperationLockRepository: RuntimeLockRepository = NodeOperationLockRepository,
    createWorkerLifecycle: createLifecycle = createL2tpWorkerLifecycle,
    clock = DEFAULT_CLOCK,
    workerId = `panel-${process.pid}`,
    leaseMs = DEFAULT_LEASE_MS,
    moduleEntry: injectedModuleEntry = moduleEntry,
    HyNode: injectedHyNode = HyNode,
    CascadeLink: injectedCascadeLink = CascadeLink,
    TopologyRuntime = TopologyRuntimeService,
    Repository = L2tpStateRepository,
    createRepositoryAdapters = createL2tpServiceRepositoryAdapters,
    createPanelOverviewLoader: createOverviewLoader = createPanelOverviewLoader,
    createRuntime = createL2tpRuntime,
} = {}) {
    const models = injectedModuleEntry.registerModels();
    const topologyRuntime = injectedTopologyRuntime ?? new TopologyRuntime({
        HyNode: injectedHyNode,
        CascadeLink: injectedCascadeLink,
        CascadeRouteGroup: models.CascadeRouteGroup,
        compiler,
        healthByPathKey,
    });
    const repository = new Repository({
        HyNode: injectedHyNode,
        RelayL2tpState: models.RelayL2tpState,
        CascadeRouteGroup: models.CascadeRouteGroup,
        CascadeTopologyState: models.CascadeTopologyState,
        L2tpOperation: models.L2tpOperation,
        compilerData,
        topologyRuntime,
    });
    const adapters = createRepositoryAdapters(repository);
    const loadPanelOverview = createOverviewLoader({
        HyNode: injectedHyNode,
        RelayL2tpState: models.RelayL2tpState,
        CascadeTopologyState: models.CascadeTopologyState,
        CascadeRouteGroup: models.CascadeRouteGroup,
        L2tpOperation: models.L2tpOperation,
    });
    const activeRuntimeReady = workerLifecycle?.enabled === true
        && typeof nodeSSHFactory === 'function'
        && typeof RuntimeNodeTransport === 'function'
        && typeof createNodeTransportFactory === 'function'
        && typeof RuntimeLockService === 'function'
        && typeof RuntimeLockRepository === 'function'
        && models.L2tpOperation
        && models.NodeOperationLock
        && typeof injectedPreflightRunner === 'function'
        && secretResolver !== unavailableSecretResolver
        && typeof secretResolver === 'function'
        && typeof artifactMaterializer === 'function'
        && typeof createLifecycle === 'function';
    const preflightRunner = activeRuntimeReady
        ? injectedPreflightRunner
        : unavailablePreflightRunner;
    let transport;
    let transportFactory;
    let lockService;
    if (activeRuntimeReady) {
        const lockRepository = new RuntimeLockRepository({
            model: models.NodeOperationLock,
        });
        lockService = new RuntimeLockService({
            repository: lockRepository,
            clock,
        });
        transportFactory = createNodeTransportFactory({
            nodeSSHFactory,
            NodeTransport: RuntimeNodeTransport,
        });
    } else {
        transport = dormantTransport;
        lockService = dormantLockService;
    }
    const runtime = createRuntime({
        operationModel: models.L2tpOperation,
        operationRepository: adapters.operationRepository,
        nodeRepository: adapters.nodeRepository,
        stateRepository: adapters.stateRepository,
        preflightRunner,
        secretResolver,
        ...(activeRuntimeReady
            ? { transportFactory, artifactMaterializer }
            : { transport }),
        lockService,
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        loadPanelOverview,
        renderPage,
        clock,
        workerId,
        leaseMs,
    });
    const lifecycle = activeRuntimeReady
        ? createLifecycle({
            ...workerLifecycle,
            worker: runtime.worker,
        })
        : dormantLifecycle;

    return {
        moduleEntry: injectedModuleEntry,
        topologyRuntime,
        repository,
        loadPanelOverview,
        runtime,
        start: () => lifecycleSummary(lifecycle.start()),
        stop: async () => lifecycleSummary(await lifecycle.stop()),
    };
}

module.exports = {
    createL2tpPanelHost,
};
