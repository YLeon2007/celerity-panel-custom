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
    L2tpPppDriftSyncRepository,
} = require('../repositories/l2tpPppDriftSyncRepository');
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
const {
    TopologyUserResync,
} = require('../services/topologyUserResync');
const {
    createTopologyPppReadinessGate,
} = require('../services/topologyPppReadinessGate');
const { TopologyAttachIngressGate } = require('../services/topologyAttachIngressGate');
const {
    NodeOperationLockRepository,
} = require('../services/nodeOperationLockRepository');
const {
    NodeOperationLockService,
} = require('../services/nodeOperationLockService');

const { topologyExecutionContext, TOPOLOGY_EXECUTION_CONTEXTS } = require('../domain/topologyExecutionContext');

const REQUIRED_TEST_RUNTIME_FLAGS = Object.freeze([
    'L2TP_EXECUTION_ENABLED',
    'L2TP_MIGRATIONS_ENABLED',
    'TOPOLOGY_TEST_EXECUTION_ENABLED',
]);
const REQUIRED_PRODUCTION_RUNTIME_FLAGS = Object.freeze([
    'L2TP_EXECUTION_ENABLED',
    'L2TP_MIGRATIONS_ENABLED',
    'TOPOLOGY_PRODUCTION_EXECUTION_ENABLED',
]);

function resolveTopologyExecutionContext(env) {
    if (!env || typeof env !== 'object' || Array.isArray(env)) return undefined;
    const context = TOPOLOGY_EXECUTION_CONTEXTS.find(pair => pair.hostIdentity === env.PANEL_DOMAIN);
    if (!context) return undefined;
    const flags = context.target === 'test'
        ? REQUIRED_TEST_RUNTIME_FLAGS : REQUIRED_PRODUCTION_RUNTIME_FLAGS;
    return flags.every(flag => env[flag] === 'true') ? context : undefined;
}

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

function isTestWorkerExecutionAllowed(env) {
    return isTopologyTestExecutionEnabled(env)
        && env.PANEL_DOMAIN === TEST_TOPOLOGY_HOST_IDENTITY;
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
    if (!topologyExecutionContext(target, hostIdentity)) {
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
        hostIdentity,
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
        L2tpUser,
        L2tpOperation,
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
    const executionContext = resolveTopologyExecutionContext(env);
    if (!executionContext || typeof executorFactory !== 'function') {
        return unavailableTopologyDeploymentService;
    }

    try {
        const lockRepository = new NodeOperationLockRepository({
            model: dependencies.NodeOperationLock,
        });
        const lockService = new NodeOperationLockService({
            repository: lockRepository,
            clock,
        });
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
            TopologyOperation,
            ...optional(transactionRunner, 'transactionRunner'),
        });
        const planMaterializer = new PlanMaterializer({ HyNode, CascadeLink });
        const operationRepository = new OperationRepository({ model: TopologyOperation });
        const finalizationRepository = new FinalizationRepository({
            TopologyOperation,
            CascadeTopologyState,
            CascadeLink,
            CascadeRouteGroup,
            RelayL2tpState,
            ...optional(transactionRunner, 'transactionRunner'),
        });
        const finalizer = new Finalizer({
            repository: finalizationRepository,
            clock,
        });
        const executor = executorFactory(Object.freeze({
            HyNode,
            ...executionContext,
        }));
        if (!isTypedExecutor(executor)) return unavailableTopologyDeploymentService;

        const userResync = new TopologyUserResync({ HyNode });
        // The runtime always wires the real node runner verifier. Missing
        // execution/model capabilities make the runtime unavailable, not ready.
        const pppGateDependencies = {
            RelayL2tpState,
            L2tpUser: L2tpUser ?? require('../models/l2tpUserModel'),
            L2tpOperation: L2tpOperation ?? require('../models/l2tpOperationModel'),
            HyNode,
            NodeSSH: NodeSSH ?? require('../../../services/nodeSSH'),
        };
        const pppReadinessGate = createTopologyPppReadinessGate(pppGateDependencies);
        // The drift queue and read-only resume probe are only available on the
        // opt-in TEST host; the existing readiness check retains its behavior.
        const testHostAllowed = executionContext.target === 'test';
        const pppDriftSync = testHostAllowed
            ? new L2tpPppDriftSyncRepository({
                RelayL2tpState,
                L2tpOperation,
                ...optional(transactionRunner, 'transactionRunner'),
            })
            : undefined;
        const pppResumeReadinessGate = testHostAllowed
            ? createTopologyPppReadinessGate({ ...pppGateDependencies, readOnly: true })
            : undefined;
        const attachIngressGate = new TopologyAttachIngressGate({
            nodeExecutionResolver: new TopologyNodeExecutionResolver({
                HyNode,
                NodeSSH: NodeSSH ?? require('../../../services/nodeSSH'),
                ...executionContext,
            }),
        });
        const operationWorker = new OperationWorker({
            operationRepository,
            executor,
            finalizer,
            lockService,
            workerId,
            leaseMs,
            clock,
            ...optional(userResync, 'userResync'),
            pppReadinessGate,
            ...optional(pppDriftSync, 'pppDriftSync'),
            ...optional(pppResumeReadinessGate, 'pppResumeReadinessGate'),
            attachIngressGate,
            allowUnprovenTestExecution: testHostAllowed,
        });
        return new Coordinator({
            executionContext,
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
    REQUIRED_PRODUCTION_RUNTIME_FLAGS,
    resolveTopologyExecutionContext,
    createTopologyOperationExecutor,
    createTopologyOperationRuntime,
    isTopologyTestExecutionEnabled,
    isTestWorkerExecutionAllowed,
    isTypedExecutor,
};
