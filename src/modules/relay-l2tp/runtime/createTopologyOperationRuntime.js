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
    executionBindingReader,
    preinstalledRunnerAuthority,
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
    // Explicit trusted capabilities only; absence still refuses. Runtime assembly
    // validates the controller's canonical context through the held lifecycle.
    return new TopologyOperationExecutor({
        target,
        hostIdentity,
        nodeExecutionResolver,
        NodeTransportFactory: TopologyNodeTransportFactory,
        RunnerBootstrapper: TopologyRunnerBootstrapper,
        ...optional(executionBindingReader, 'executionBindingReader'),
        ...optional(preinstalledRunnerAuthority, 'preinstalledRunnerAuthority'),
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
        leaseMs: requestedLeaseMs,
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
    const ownerEnrollmentEnv = Object.freeze({ ...env });
    const executionContext = resolveTopologyExecutionContext(ownerEnrollmentEnv);
    // Allow several 15s SSH round trips while a tick or DB write is delayed.
    // A slow reservation is covered by renewal, not by this margin alone.
    const baseLease = requestedLeaseMs === undefined ? DEFAULT_LEASE_MS : requestedLeaseMs;
    const leaseMs = executionContext?.target === 'production' && Number.isSafeInteger(baseLease) && baseLease >= 2
        ? Math.max(120_000, baseLease) : baseLease;
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
            TopologyConfigOwner: dependencies.TopologyConfigOwner, NodeOperationLock: dependencies.NodeOperationLock,
            TopologyExecutionBinding: dependencies.TopologyExecutionBinding,
            TopologyExecutionEnrollment: dependencies.TopologyExecutionEnrollment,
            RemoteAdmission: dependencies.RemoteAdmission,
            ...optional(transactionRunner, 'transactionRunner'),
        });
        snapshotReader.selectedTopologyRepository = topologyRepository;
        const planMaterializer = new PlanMaterializer({ HyNode, CascadeLink });
        const operationRepository = new OperationRepository({ model: TopologyOperation, topologyStateModel: CascadeTopologyState,
            selectedTopologyRepository: topologyRepository });
        const finalizationRepository = new FinalizationRepository({
            selectedTopologyRepository: topologyRepository,
            TopologyOperation,
            CascadeTopologyState,
            CascadeLink,
            CascadeRouteGroup,
            RelayL2tpState,
            HyNode,
            L2tpUser,
            L2tpOperation,
            NodeOperationLock: dependencies.NodeOperationLock,
            TopologyExecutionBinding: dependencies.TopologyExecutionBinding,
            TopologyExecutionEnrollment: dependencies.TopologyExecutionEnrollment,
            TopologyConfigOwner: dependencies.TopologyConfigOwner,
            ...optional(transactionRunner, 'transactionRunner'),
        });
        const finalizer = new Finalizer({
            repository: finalizationRepository,
            clock,
        });
        let bindingStore, bindingLifecycle, preinstalledRunnerAuthority;
        // Reuse the lifecycle's exact controller-context pairing for either
        // canonical context; this constructs no controller or physical authority.
        if (dependencies.topologyExecutionAuthority !== undefined) {
            const { TopologyExecutionAuthorityLifecycle } = require('./topologyExecutionAuthorityLifecycle');
            const { TopologyExecutionBindingStore } = require('../repositories/topologyExecutionBindingStore');
            bindingLifecycle = new TopologyExecutionAuthorityLifecycle({ executionContext,
                controller: dependencies.topologyExecutionAuthority });
            // Trusted server controller selection only, snapshotted at assembly.
            // An unknown value refuses composition; no fallback to shell/SFTP.
            const runnerTransport = dependencies.topologyExecutionAuthority.runnerTransport;
            if (runnerTransport !== undefined && runnerTransport !== 'preinstalled-attested-v1') {
                return unavailableTopologyDeploymentService;
            }
            if (runnerTransport === 'preinstalled-attested-v1') preinstalledRunnerAuthority = bindingLifecycle;
            bindingStore = new TopologyExecutionBindingStore({ executionContext,
                withVerifiedAuthority: (challenge, work) => bindingLifecycle.withVerifiedAuthority(challenge, work),
                assertAuthorityHeld: () => bindingLifecycle.assertHeld(),
                checkPristinePair: pair => bindingLifecycle.checkPristineReservationPair(pair),
                Operation: TopologyOperation, Lock: dependencies.NodeOperationLock,
                Owner: dependencies.TopologyConfigOwner, Enrollment: dependencies.TopologyExecutionEnrollment,
                Binding: dependencies.TopologyExecutionBinding, HyNode });
        }
        const executor = executorFactory(Object.freeze({
            HyNode,
            ...executionContext,
            ...optional(bindingStore, 'executionBindingReader'),
            ...optional(preinstalledRunnerAuthority, 'preinstalledRunnerAuthority'),
        }));
        if (!isTypedExecutor(executor)) return unavailableTopologyDeploymentService;

        const userResync = new TopologyUserResync({ HyNode, restrictedRunner: Boolean(preinstalledRunnerAuthority),
            // The ordinary held production path also excludes the classic agent.
            // Bootstrap selection does not select the post-verify user writer.
            preferBoundRunner: Boolean(bindingLifecycle) && ((executionContext.target === 'production' && !preinstalledRunnerAuthority)
                || ownerEnrollmentEnv.TOPOLOGY_TEST_STARTUP_MODE === 'dedicated-runtime-v1') });
        // The runtime always wires the real node runner verifier. Missing
        // execution/model capabilities make the runtime unavailable, not ready.
        const pppGateDependencies = {
            restrictedRunner: Boolean(preinstalledRunnerAuthority),
            executionContext,
            enableProductionExecution: executionContext.target === 'production',
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
                executionContext,
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
            selectedTopologyRepository: topologyRepository,
            executionContext,
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
            ...optional(dependencies.installedIngressPreparer, 'installedIngressPreparer'),
            allowUnprovenTestExecution: testHostAllowed,
            ...optional(bindingStore, 'bindingProvisioner'),
            ...optional(bindingLifecycle, 'bindingLifecycle'),
        });
        const coordinator = new Coordinator({
            executionContext,
            topologyRepository,
            planMaterializer,
            operationRepository,
            operationWorker,
            intentDraftWriter: snapshotReader.createIntentDraftWriter?.({ selectedTopologyRepository: topologyRepository }),
            ...optional(validator, 'validator'),
            ...optional(compiler, 'compiler'),
            ...optional(idFactory, 'idFactory'),
            ...optional(onWorkerError, 'onWorkerError'),
        });
        coordinator.intentOperationAdmission = Object.freeze({ db: CascadeTopologyState.db,
            queue: input => coordinator.queueIntent(input),
            inspectUnadmittedPreparation: input => coordinator.inspectUnadmittedPreparation(input) });
        coordinator.resolveIntentResources = input => coordinator.resolveIntentResourcesForQueue(input);
        coordinator.attachIngressGate = attachIngressGate;
        coordinator.installedPppReadinessGate = createTopologyPppReadinessGate({ ...pppGateDependencies, readOnly: true });
        Object.assign(coordinator, require('../services/topologySelectedPublicState').createTopologySelectedPublicState({
            topologyRepository, operationRepository, executionContext,
        }));
        coordinator.readAppliedNodePublication = input => topologyRepository.readAppliedNodePublication({ ...input, executionContext });
        // Internal explicit command only; no HTTP/MCP or automatic startup call.
        coordinator.enrollTestOwners = ({ resumeOnly = false, onReconciled } = {}) => require('../../../../scripts/test-topology-owner').enrollTestOwners({
            env: ownerEnrollmentEnv, lifecycle: bindingLifecycle, store: bindingStore, resumeOnly, onReconciled,
            TopologyConfigOwner: dependencies.TopologyConfigOwner,
            TopologyExecutionEnrollment: dependencies.TopologyExecutionEnrollment,
            dedicatedModels: { ...dependencies, TopologyCreateIntent: require('../models/topologyCreateIntentModel'),
                TopologyIntentQueueState: require('../models/topologyIntentQueueStateModel') },
        });
        if (ownerEnrollmentEnv.TOPOLOGY_TEST_STARTUP_MODE === 'dedicated-runtime-v1' && executionContext.target === 'test') {
            const ownerEntry = require('../../../../scripts/test-topology-owner');
            const ownerModels = { ...dependencies, TopologyCreateIntent: require('../models/topologyCreateIntentModel') };
            coordinator.inspectTestOwnerHandback = () => ownerEntry.inspectTestOwnerHandback({ env: ownerEnrollmentEnv, models: ownerModels });
            coordinator.handbackTestOwners = expected => ownerEntry.handbackTestOwners({ env: ownerEnrollmentEnv, models: ownerModels,
                lifecycle: bindingLifecycle, authority: dependencies.topologyExecutionAuthority, expected });
            coordinator.settleUndispatchedPreparation = (operationId, onSettled) => require('../services/topologyUndispatchedPreparationSettlement')
                .settleUndispatchedPreparation({ models: dependencies, selected: topologyRepository, lifecycle: bindingLifecycle, finalizer, operationId, onSettled });
            operationRepository.claimUndispatchedPreparation = input => require('../repositories/topologyUndispatchedPreparationContinuation')
                .claimUndispatchedPreparation(dependencies,topologyRepository,bindingLifecycle,input);
            coordinator.resumeUndispatchedPreparation = (operationId,onSettled) => operationWorker.resumeUndispatchedPreparation(operationId,onSettled);
            operationRepository.claimClosedSettlement = input => require('../repositories/topologyUndispatchedPreparationContinuation')
                .claimClosedSettlement(dependencies,topologyRepository,bindingLifecycle,input);
            coordinator.resumeClosedSettlement = (operationId,onSettled) => operationWorker.resumeClosedSettlement(operationId,onSettled);
            operationRepository.claimPreparedCommit = input => require('../repositories/topologyUndispatchedPreparationContinuation')
                .claimPreparedCommit(dependencies,topologyRepository,bindingLifecycle,input);
            coordinator.resumePreparedCommit = (operationId,onSettled) => operationWorker.resumePreparedCommit(operationId,onSettled);
            operationRepository.claimBootstrapContinuation = input => require('../repositories/topologyBootstrapContinuation')
                .claimBootstrapContinuation(dependencies, topologyRepository, input);
            operationRepository.claimBindingReservationContinuation = input => require('../repositories/topologyBindingReservationContinuation')
                .claimBindingReservationContinuation(dependencies, topologyRepository, bindingLifecycle, input);
            coordinator.resumeBindingReservations = (operationId, onSettled) => operationWorker.resumeBindingReservations(operationId, onSettled);
            operationRepository.claimRetainedVerifyContinuation = input => require('../repositories/topologyRetainedVerifyContinuation')
                .claimRetainedVerifyContinuation(dependencies,topologyRepository,bindingLifecycle,input);
            coordinator.resumeRetainedVerification = (operationId,onSettled) => operationWorker.resumeRetainedVerification(operationId,onSettled);
            coordinator.resumeSettledRuntime = (operationId,onSettled) => operationWorker.resumeSettledRuntime(operationId,onSettled);
            coordinator.resumeBootstrapPreparation = (operationId, onSettled) => operationWorker.resumeBootstrapPreparation(operationId, onSettled);
            coordinator.resumeSettledBootstrap = (operationId, onSettled) => require('../services/topologyBootstrapCancellation')
                .resumeSettledBootstrap({models:dependencies,authority:dependencies.topologyExecutionAuthority,operationId,onSettled});
            coordinator.cancelBootstrapPreparation = (operationId, onSettled) => require('../services/topologyBootstrapCancellation')
                .cancelBootstrap({ models: dependencies, authority: dependencies.topologyExecutionAuthority, finalizer, operationId, onSettled });
        }
        if (executionContext.target === 'production' && bindingLifecycle) {
            const productionEntry = require('../services/productionOwnerEntry');
            let productionEnrollment;
            coordinator.enrollProductionOwners = async () => {
                if (!productionEnrollment) productionEnrollment = productionEntry.enrollProductionOwners({
                    lifecycle: bindingLifecycle, store: bindingStore, models: dependencies });
                return productionEnrollment;
            };
            coordinator.handbackProductionOwners = async acceptedCurrent => productionEntry.handbackProductionOwners({
                lifecycle: bindingLifecycle, authority: dependencies.topologyExecutionAuthority, models: dependencies,
                enrollment: await productionEnrollment, acceptedCurrent, env: ownerEnrollmentEnv });
        }
        coordinator.readTestEnrollment = async () => {
            if (ownerEnrollmentEnv.TOPOLOGY_TEST_STARTUP_MODE !== 'dedicated-runtime-v1') throw new Error('TEST_OWNER_CONTEXT_REQUIRED');
            const rows = await dependencies.TopologyExecutionEnrollment.find({ executionContext: executionContext.hostIdentity })
                .read('primary').readConcern('majority').maxTimeMS(5000).lean();
            const { acceptedExecutionEnrollment, enrollmentRuntimeBootId } = require('../repositories/topologyExecutionBindingStore');
            const current = await Promise.all(rows.map(async alias => acceptedExecutionEnrollment(alias,
                await dependencies.TopologyConfigOwner.findOne({ node: alias.nodeId, profile: alias.targetProfile })
                    .select('+executionEnrollment').read('primary').readConcern('majority').maxTimeMS(5000).lean())));
            return { status: rows.length ? 'enrolled_requires_runtime_reconciliation' : 'not_enrolled',
                nodes: current.map(n => ({ nodeId: n.nodeId, targetProfile: n.targetProfile, enrollmentId: n._id, ownerGeneration: n.ownerGeneration, enrollmentBootId: n.bootId, runtimeBootId: enrollmentRuntimeBootId(n) })) };
        };
        return coordinator;
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
