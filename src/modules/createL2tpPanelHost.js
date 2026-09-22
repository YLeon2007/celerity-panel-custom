'use strict';

const CascadeLink = require('../models/cascadeLinkModel');
const HyNode = require('../models/hyNodeModel');
const moduleEntry = require('./relay-l2tp');
const { compileTopology } = require('./relay-l2tp/domain/topologyCompiler');
const { L2tpStateRepository, createL2tpServiceRepositoryAdapters } = require('./relay-l2tp/repositories/l2tpStateRepository');
const { createPanelOverviewLoader } = require('./relay-l2tp/routes/panelOverview');
const { createL2tpExecutionRuntime } = require('./relay-l2tp/runtime/createL2tpExecutionRuntime');
const { createL2tpRuntime } = require('./relay-l2tp/runtime/createL2tpRuntime');
const { createL2tpWorkerLifecycle } = require('./relay-l2tp/runtime/createL2tpWorkerLifecycle');
const { TopologyRuntimeService } = require('./relay-l2tp/services/topologyRuntimeService');

const DEFAULT_COMPILER_DATA = Object.freeze({ relays: Object.freeze([]) });
const DEFAULT_CLOCK = Object.freeze({ now: () => new Date() });
const DEFAULT_LEASE_MS = 30_000;

function createL2tpPanelHost({
    requireAuth,
    requireOnboarding,
    csrf,
    rateLimiter,
    renderPage,
    compilerData = DEFAULT_COMPILER_DATA,
    healthByPathKey,
    enableTopologyHealthProvider = false,
    topologyHealthMaxStalenessMs,
    compiler = compileTopology,
    topologyRuntime: injectedTopologyRuntime,
    preflightRunner: injectedPreflightRunner,
    operationMaterializer,
    stateManagementService,
    secretBox,
    secretKey,
    NodeSSH,
    NodeTransport,
    workerLifecycle,
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
    createExecutionRuntime = createL2tpExecutionRuntime,
} = {}) {
    const models = injectedModuleEntry.registerModels();
    const topologyRuntimeDependencies = {
        HyNode: injectedHyNode,
        CascadeLink: injectedCascadeLink,
        CascadeRouteGroup: models.CascadeRouteGroup,
        compiler,
        ...(healthByPathKey !== undefined
            ? { healthByPathKey }
            : enableTopologyHealthProvider === true
                ? {
                    enableHealthProvider: true,
                    clock,
                    ...(topologyHealthMaxStalenessMs === undefined
                        ? {}
                        : { healthMaxStalenessMs: topologyHealthMaxStalenessMs }),
                }
                : {}),
    };
    const topologyRuntime = injectedTopologyRuntime ?? new TopologyRuntime(topologyRuntimeDependencies);
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
    const executionRuntime = createExecutionRuntime({
        workerLifecycle,
        HyNode: injectedHyNode,
        RelayL2tpState: models.RelayL2tpState,
        CascadeRouteGroup: models.CascadeRouteGroup,
        operationModel: models.L2tpOperation,
        lockModel: models.NodeOperationLock,
        NodeSSH,
        NodeTransport,
        preflightRunner: injectedPreflightRunner,
        operationMaterializer,
        stateManagementService,
        secretBox,
        secretKey,
        clock,
        createRuntime,
        createWorkerLifecycle: createLifecycle,
        runtimeDependencies: {
            operationModel: models.L2tpOperation,
            operationRepository: adapters.operationRepository,
            nodeRepository: adapters.nodeRepository,
            stateRepository: adapters.stateRepository,
            requireAuth,
            requireOnboarding,
            csrf,
            rateLimiter,
            loadPanelOverview,
            renderPage,
            clock,
            workerId,
            leaseMs,
        },
    });

    return {
        moduleEntry: injectedModuleEntry,
        topologyRuntime,
        repository,
        loadPanelOverview,
        stateManagementService: executionRuntime.runtime.stateManagementService,
        runtime: executionRuntime.runtime,
        start: executionRuntime.start,
        stop: executionRuntime.stop,
    };
}

module.exports = {
    createL2tpPanelHost,
};
