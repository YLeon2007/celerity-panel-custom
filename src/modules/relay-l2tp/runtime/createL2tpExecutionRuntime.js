'use strict';

const { L2tpStateManagementRepository } = require('../repositories/l2tpStateManagementRepository');
const { L2tpUserExecutionRepository } = require('../repositories/l2tpUserExecutionRepository');
const { L2tpNodeExecutionResolver } = require('../services/l2tpNodeExecutionResolver');
const { createL2tpNodeTransportResolver } = require('../services/l2tpNodeTransportFactory');
const { L2tpStateManagementService } = require('../services/l2tpStateManagementService');
const { L2tpUserResolver } = require('../services/l2tpUserResolver');
const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../services/nodeOperationLockService');
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

const unavailableCandidateService = Object.freeze({
    async buildCandidate() {
        const error = new Error('L2TP Xray candidate service is unavailable');
        error.code = 'L2TP_XRAY_CANDIDATE_UNAVAILABLE';
        throw error;
    },
});

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

function assertActiveExecutionDependencies({
    HyNode,
    RelayL2tpState,
    L2tpUser,
    CascadeRouteGroup,
    operationModel,
    lockModel,
    NodeSSH,
    NodeTransport,
    createPreflightRunner,
    createCandidateService,
    candidateNodeResolver,
    candidateUserResolver,
    configGenerator,
    fragmentProvider,
    operationMaterializer,
    secretBox,
    secretKey,
    clock,
    runtimeDependencies,
    createRuntime,
    createWorkerLifecycle,
}) {
    if (!HyNode || typeof HyNode.findById !== 'function') {
        throw new TypeError('Active L2TP execution requires HyNode.findById');
    }
    for (const [dependencyName, dependency] of Object.entries({
        RelayL2tpState,
        L2tpUser,
        CascadeRouteGroup,
        operationModel,
        lockModel,
    })) {
        if (!dependency) {
            throw new TypeError(`Active L2TP execution requires ${dependencyName}`);
        }
    }
    for (const [dependencyName, dependency] of Object.entries({
        NodeSSH,
        NodeTransport,
        createPreflightRunner,
        createCandidateService,
        candidateNodeResolver,
        candidateUserResolver,
        configGenerator,
        fragmentProvider,
        operationMaterializer,
        createRuntime,
        createWorkerLifecycle,
    })) {
        if (typeof dependency !== 'function') {
            throw new TypeError(`Active L2TP execution requires ${dependencyName} to be a function`);
        }
    }
    if (
        !secretBox
        || typeof secretBox.encrypt !== 'function'
        || typeof secretBox.decrypt !== 'function'
    ) {
        throw new TypeError('Active L2TP execution requires secretBox encrypt/decrypt functions');
    }
    if (typeof secretKey !== 'string' || secretKey.trim().length === 0) {
        throw new TypeError('Active L2TP execution requires a non-empty secretKey');
    }
    if (!clock || typeof clock.now !== 'function') {
        throw new TypeError('Active L2TP execution requires clock.now');
    }
    if (!runtimeDependencies || typeof runtimeDependencies !== 'object' || Array.isArray(runtimeDependencies)) {
        throw new TypeError('Active L2TP execution requires runtimeDependencies');
    }
}

function createL2tpExecutionRuntime({
    workerLifecycle,
    HyNode,
    RelayL2tpState,
    L2tpUser,
    CascadeRouteGroup,
    operationModel,
    lockModel,
    NodeSSH,
    NodeTransport,
    createPreflightRunner,
    createCandidateService,
    candidateNodeResolver,
    candidateUserResolver,
    configGenerator,
    fragmentProvider,
    operationMaterializer,
    secretBox,
    secretKey,
    stateManagementService,
    clock,
    runtimeDependencies,
    createRuntime = createL2tpRuntime,
    createWorkerLifecycle = createL2tpWorkerLifecycle,
} = {}) {
    if (workerLifecycle?.enabled !== true) {
        const runtime = createRuntime({
            ...runtimeDependencies,
            preflightRunner: unavailablePreflightRunner,
            candidateService: unavailableCandidateService,
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

    assertActiveExecutionDependencies({
        HyNode,
        RelayL2tpState,
        L2tpUser,
        CascadeRouteGroup,
        operationModel,
        lockModel,
        NodeSSH,
        NodeTransport,
        createPreflightRunner,
        createCandidateService,
        candidateNodeResolver,
        candidateUserResolver,
        configGenerator,
        fragmentProvider,
        operationMaterializer,
        secretBox,
        secretKey,
        clock,
        runtimeDependencies,
        createRuntime,
        createWorkerLifecycle,
    });

    const nodeExecutionResolver = new L2tpNodeExecutionResolver({ HyNode, NodeSSH });
    const transportResolver = createL2tpNodeTransportResolver({
        nodeExecutionResolver,
        NodeTransport,
    });
    const preflightRunner = createPreflightRunner({ transportResolver });
    if (typeof preflightRunner !== 'function') {
        throw new TypeError('Active L2TP execution createPreflightRunner must return a function');
    }
    const candidateService = createCandidateService({
        nodeResolver: candidateNodeResolver,
        userResolver: candidateUserResolver,
        configGenerator,
        fragmentProvider,
    });
    if (!candidateService || typeof candidateService.buildCandidate !== 'function') {
        throw new TypeError(
            'Active L2TP execution createCandidateService must return a candidate service',
        );
    }
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
    const userRepository = new L2tpUserExecutionRepository({ model: L2tpUser });
    const userResolver = new L2tpUserResolver({
        repository: userRepository,
        secretBox,
        secretKey,
    });
    const secretResolver = async operation => {
        const secrets = await managementService.resolveOperationSecrets(operation);
        const users = await userResolver.resolve(operation);
        return { ...secrets, users };
    };
    const lockRepository = new NodeOperationLockRepository({ model: lockModel });
    const lockService = new NodeOperationLockService({
        repository: lockRepository,
        clock,
    });
    const runtime = createRuntime({
        ...runtimeDependencies,
        preflightRunner,
        candidateService,
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
