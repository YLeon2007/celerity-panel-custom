'use strict';

const { L2tpStateManagementRepository } = require('../repositories/l2tpStateManagementRepository');
const { materializeInstallOperation } = require('../services/l2tpOperationMaterializer');
const { L2tpNodeExecutionResolver } = require('../services/l2tpNodeExecutionResolver');
const { L2tpNodeTransport } = require('../services/l2tpNodeTransport');
const { createL2tpNodeTransportResolver } = require('../services/l2tpNodeTransportFactory');
const { L2tpStateManagementService } = require('../services/l2tpStateManagementService');
const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../services/nodeOperationLockService');
const defaultSecretBox = require('../services/secretBoxService');
const { createL2tpRuntime } = require('./createL2tpRuntime');
const { createL2tpWorkerLifecycle } = require('./createL2tpWorkerLifecycle');

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

const unavailableStateManagementService = Object.freeze({
    async configureRelay() {
        const error = new Error('L2TP state management is unavailable');
        error.code = 'L2TP_STATE_MANAGEMENT_UNAVAILABLE';
        throw error;
    },
});

function lifecycleSummary(state) {
    return {
        enabled: state?.enabled === true,
        running: state?.running === true,
        inFlight: state?.inFlight === true,
    };
}

function hasActiveExecutionDependencies({
    workerLifecycle,
    HyNode,
    RelayL2tpState,
    CascadeRouteGroup,
    operationModel,
    lockModel,
    NodeSSH,
    NodeTransport,
    preflightRunner,
    operationMaterializer,
    secretBox,
    secretKey,
    clock,
    runtimeDependencies,
    createRuntime,
    createWorkerLifecycle,
}) {
    return workerLifecycle?.enabled === true
        && HyNode
        && typeof HyNode.findById === 'function'
        && RelayL2tpState
        && CascadeRouteGroup
        && operationModel
        && lockModel
        && typeof NodeSSH === 'function'
        && typeof NodeTransport === 'function'
        && typeof preflightRunner === 'function'
        && typeof operationMaterializer === 'function'
        && secretBox
        && typeof secretBox.encrypt === 'function'
        && typeof secretBox.decrypt === 'function'
        && typeof secretKey === 'string'
        && secretKey.length > 0
        && clock
        && typeof clock.now === 'function'
        && runtimeDependencies
        && typeof runtimeDependencies === 'object'
        && !Array.isArray(runtimeDependencies)
        && typeof createRuntime === 'function'
        && typeof createWorkerLifecycle === 'function';
}

function createL2tpExecutionRuntime({
    workerLifecycle,
    HyNode,
    RelayL2tpState,
    CascadeRouteGroup,
    operationModel,
    lockModel,
    NodeSSH,
    NodeTransport = L2tpNodeTransport,
    preflightRunner,
    operationMaterializer = materializeInstallOperation,
    secretBox = defaultSecretBox,
    secretKey,
    stateManagementService,
    clock,
    runtimeDependencies,
    createRuntime = createL2tpRuntime,
    createWorkerLifecycle = createL2tpWorkerLifecycle,
} = {}) {
    const active = hasActiveExecutionDependencies({
        workerLifecycle,
        HyNode,
        RelayL2tpState,
        CascadeRouteGroup,
        operationModel,
        lockModel,
        NodeSSH,
        NodeTransport,
        preflightRunner,
        operationMaterializer,
        secretBox,
        secretKey,
        clock,
        runtimeDependencies,
        createRuntime,
        createWorkerLifecycle,
    });
    if (!active) {
        const runtime = createRuntime({
            ...runtimeDependencies,
            preflightRunner: unavailablePreflightRunner,
            transport: dormantTransport,
            lockService: dormantLockService,
            secretResolver: unavailableSecretResolver,
            stateManagementService: stateManagementService ?? unavailableStateManagementService,
        });
        return {
            runtime,
            start: () => lifecycleSummary(dormantLifecycle.start()),
            stop: async () => lifecycleSummary(await dormantLifecycle.stop()),
        };
    }

    const nodeExecutionResolver = new L2tpNodeExecutionResolver({ HyNode, NodeSSH });
    const transportResolver = createL2tpNodeTransportResolver({
        nodeExecutionResolver,
        NodeTransport,
    });
    const managementRepository = new L2tpStateManagementRepository({
        HyNode,
        RelayL2tpState,
        CascadeRouteGroup,
    });
    const managementService = new L2tpStateManagementService({
        repository: managementRepository,
        secretBox,
        secretKey,
    });
    const secretResolver = managementService.resolveOperationSecrets.bind(managementService);
    const lockRepository = new NodeOperationLockRepository({ model: lockModel });
    const lockService = new NodeOperationLockService({
        repository: lockRepository,
        clock,
    });
    const runtime = createRuntime({
        ...runtimeDependencies,
        preflightRunner,
        transportResolver,
        operationMaterializer,
        secretResolver,
        stateManagementService: stateManagementService ?? managementService,
        lockService,
    });
    const lifecycle = createWorkerLifecycle({
        ...workerLifecycle,
        worker: runtime.worker,
    });

    return {
        runtime,
        start: () => lifecycleSummary(lifecycle.start()),
        stop: async () => lifecycleSummary(await lifecycle.stop()),
    };
}

module.exports = {
    createL2tpExecutionRuntime,
};
