'use strict';

const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const moduleEntry = require('./relay-l2tp');
const { compileTopology } = require('./relay-l2tp/domain/topologyCompiler');
const { L2tpStateRepository, createL2tpServiceRepositoryAdapters } = require('./relay-l2tp/repositories/l2tpStateRepository');
const { createPanelOverviewLoader } = require('./relay-l2tp/routes/panelOverview');
const { createL2tpRuntime } = require('./relay-l2tp/runtime/createL2tpRuntime');
const { TopologyRuntimeService } = require('./relay-l2tp/services/topologyRuntimeService');

const DEFAULT_COMPILER_DATA = Object.freeze({ relays: Object.freeze([]) });
const DEFAULT_HEALTH_BY_PATH_KEY = Object.freeze({});
const DEFAULT_CLOCK = Object.freeze({ now: () => new Date() });
const DEFAULT_LEASE_MS = 30_000;

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

async function unavailablePreflightRunner() {
    return {
        ok: false,
        checks: [],
        error: { code: 'L2TP_PREFLIGHT_RUNNER_UNAVAILABLE' },
    };
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
    preflightRunner = unavailablePreflightRunner,
    transport = dormantTransport,
    lockService = dormantLockService,
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
    const runtime = createRuntime({
        operationModel: models.L2tpOperation,
        nodeRepository: adapters.nodeRepository,
        stateRepository: adapters.stateRepository,
        preflightRunner,
        transport,
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

    return {
        moduleEntry: injectedModuleEntry,
        topologyRuntime,
        repository,
        loadPanelOverview,
        runtime,
    };
}

module.exports = {
    createL2tpPanelHost,
};
