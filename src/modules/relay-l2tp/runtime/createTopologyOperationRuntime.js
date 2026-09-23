'use strict';

const {
    TopologyDeploymentRepository,
} = require('../repositories/topologyDeploymentRepository');
const {
    TopologyDraftRepository,
} = require('../repositories/topologyDraftRepository');
const {
    TopologyOperationRepository,
} = require('../repositories/topologyOperationRepository');
const {
    TopologyOperationFinalizationRepository,
} = require('../repositories/topologyOperationFinalizationRepository');
const {
    TopologyNodeExecutionResolver,
} = require('../services/topologyNodeExecutionResolver');
const {
    TopologyNodeTransportFactory,
} = require('../services/topologyNodeTransportFactory');
const {
    TopologyOperationExecutor,
} = require('../services/topologyOperationExecutor');
const {
    TEST_TOPOLOGY_HOST_IDENTITY,
    TEST_TOPOLOGY_TARGET,
    TopologyOperationPlanMaterializer,
} = require('../services/topologyOperationPlanMaterializer');
const {
    TopologyOperationCoordinator,
} = require('../services/topologyOperationCoordinator');
const {
    TopologyOperationFinalizer,
} = require('../services/topologyOperationFinalizer');
const {
    unavailableTopologyDeploymentService,
} = require('../services/topologyDeploymentService');
const {
    TopologyRunnerBootstrapper,
} = require('../services/topologyRunnerBootstrapper');
const {
    TopologyOperationWorker,
} = require('../workers/topologyOperationWorker');

const REQUIRED_TEST_RUNTIME_FLAGS = Object.freeze([
    'L2TP_EXECUTION_ENABLED',
    'L2TP_MIGRATIONS_ENABLED',
    'TOPOLOGY_TEST_EXECUTION_ENABLED',
]);
const EXECUTOR_METHODS = Object.freeze([
    'prepare',
    'commit',
    'verify',
    'cleanupPrepared',
    'rollback',
]);
const DEFAULT_CLOCK = Object.freeze({ now: () => new Date() });
const DEFAULT_LEASE_MS = 30_000;

function isTopologyTestExecutionEnabled(env) {
    return Boolean(env)
        && typeof env === 'object'
        && REQUIRED_TEST_RUNTIME_FLAGS.every(flagName => env[flagName] === 'true');
}

function isTypedExecutor(executor) {
    return Boolean(executor)
        && typeof executor === 'object'
        && !Array.isArray(executor)
        && EXECUTOR_METHODS.every(methodName => typeof executor[methodName] === 'function');
}

function optional(value, name) {
    return value === undefined ? {} : { [name]: value };
}

function createTopologyOperationExecutor({
    HyNode,
    NodeSSH,
    hostIdentity,
    target,
} = {}) {
    if (target !== TEST_TOPOLOGY_TARGET
        || hostIdentity !== TEST_TOPOLOGY_HOST_IDENTITY) {
        return undefined;
    }
    const NodeSSHAdapter = NodeSSH === undefined
        ? require('../../../services/nodeSSH')
        : NodeSSH;
    const nodeExecutionResolver = new TopologyNodeExecutionResolver({
        HyNode,
        NodeSSH: NodeSSHAdapter,
        target,
        hostIdentity,
    });
    return new TopologyOperationExecutor({
        target,
        nodeExecutionResolver,
        NodeTransportFactory: TopologyNodeTransportFactory,
        RunnerBootstrapper: TopologyRunnerBootstrapper,
    });
}

function createTopologyOperationRuntime(dependencies = {}) {
    if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies)) {
        return unavailableTopologyDeploymentService;
    }

    const {
        env = process.env,
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        CascadeTopologyState,
        RelayL2tpState,
        TopologyOperation,
        NodeSSH,
        createTopologyOperationExecutor: executorFactoryOverride,
        transactionRunner,
        clock = DEFAULT_CLOCK,
        workerId = `topology-test-${process.pid}`,
        leaseMs = DEFAULT_LEASE_MS,
        SnapshotRepository = TopologyDraftRepository,
        DeploymentRepository = TopologyDeploymentRepository,
        PlanMaterializer = TopologyOperationPlanMaterializer,
        OperationRepository = TopologyOperationRepository,
        FinalizationRepository = TopologyOperationFinalizationRepository,
        Finalizer = TopologyOperationFinalizer,
        OperationWorker = TopologyOperationWorker,
        Coordinator = TopologyOperationCoordinator,
        lockService,
        validator,
        compiler,
        idFactory,
        onWorkerError,
    } = dependencies;

    const executorFactory = executorFactoryOverride === undefined
        ? executorDependencies => createTopologyOperationExecutor({
            ...executorDependencies,
            NodeSSH,
        })
        : executorFactoryOverride;
    if (!isTopologyTestExecutionEnabled(env)
        || typeof executorFactory !== 'function') {
        return unavailableTopologyDeploymentService;
    }

    try {
        const snapshotReader = new SnapshotRepository({
            HyNode,
            CascadeLink,
            CascadeRouteGroup,
            CascadeTopologyState,
            RelayL2tpState,
            ...optional(transactionRunner, 'transactionRunner'),
        });
        const topologyRepository = new DeploymentRepository({
            snapshotReader,
            CascadeTopologyState,
            ...optional(transactionRunner, 'transactionRunner'),
        });
        const planMaterializer = new PlanMaterializer({ HyNode, CascadeLink });
        const operationRepository = new OperationRepository({ model: TopologyOperation });
        const finalizationRepository = new FinalizationRepository({
            TopologyOperation,
            CascadeTopologyState,
            ...optional(transactionRunner, 'transactionRunner'),
        });
        const finalizer = new Finalizer({
            repository: finalizationRepository,
            clock,
        });
        const executor = executorFactory(Object.freeze({
            HyNode,
            hostIdentity: TEST_TOPOLOGY_HOST_IDENTITY,
            target: TEST_TOPOLOGY_TARGET,
        }));
        if (!isTypedExecutor(executor)) return unavailableTopologyDeploymentService;

        const operationWorker = new OperationWorker({
            operationRepository,
            executor,
            finalizer,
            lockService,
            workerId,
            leaseMs,
            clock,
        });
        return new Coordinator({
            topologyRepository,
            planMaterializer,
            operationRepository,
            operationWorker,
            ...optional(validator, 'validator'),
            ...optional(compiler, 'compiler'),
            ...optional(idFactory, 'idFactory'),
            ...optional(onWorkerError, 'onWorkerError'),
        });
    } catch {
        return unavailableTopologyDeploymentService;
    }
}

module.exports = {
    DEFAULT_LEASE_MS,
    EXECUTOR_METHODS,
    REQUIRED_TEST_RUNTIME_FLAGS,
    createTopologyOperationExecutor,
    createTopologyOperationRuntime,
    isTopologyTestExecutionEnabled,
    isTypedExecutor,
};
