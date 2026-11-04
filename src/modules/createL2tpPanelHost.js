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
const { resolveL2tpExecutionAuthorization } = require('./relay-l2tp/domain/l2tpExecutionAuthorization');
const { TopologyRuntimeService } = require('./relay-l2tp/services/topologyRuntimeService');

const DEFAULT_COMPILER_DATA = Object.freeze({ relays: Object.freeze([]) });
const DEFAULT_CLOCK = Object.freeze({ now: () => new Date() });
const DEFAULT_LEASE_MS = 30_000;

function createL2tpPanelHost({
    env = process.env,
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
    createPreflightRunner,
    createCandidateService,
    candidateNodeResolver,
    candidateUserResolver,
    configGenerator,
    fragmentProvider,
    operationMaterializer,
    createUserSnapshotResolver,
    createUserSyncReconciler,
    stateManagementService,
    secretBox,
    secretKey,
    NodeSSH,
    // Server-owned external controller capability; never sourced from env or requests.
    topologyExecutionAuthority,
    createTopologyOperationExecutor,
    NodeTransport,
    workerLifecycle,
    topologyRecoveryScanLimit,
    createWorkerLifecycle: createLifecycle = createL2tpWorkerLifecycle,
    createTopologyRecoveryLifecycle,
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
    // Select once before any injected factory can change the source environment.
    const topologyEnv = Object.freeze({ ...env });
    const { isTopologyTestExecutionEnabled, resolveTopologyExecutionContext } = require(
        './relay-l2tp/runtime/createTopologyOperationRuntime'
    );
    const executionContext = resolveTopologyExecutionContext(topologyEnv);
    const l2tpExecutionAuthorization = resolveL2tpExecutionAuthorization(topologyEnv);
    if (topologyEnv.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'true'
        && topologyEnv.PANEL_DOMAIN !== 'lm1.infograd.online') {
        throw new TypeError('Opted-in topology recovery requires an operation worker with an exact execution identity');
    }
    const topologyExecutionRequested = (
        topologyEnv.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'true'
        && topologyEnv.L2TP_EXECUTION_ENABLED === 'true'
        && topologyEnv.L2TP_MIGRATIONS_ENABLED === 'true'
    ) || (topologyEnv.PANEL_DOMAIN !== 'lm1.infograd.online'
        && isTopologyTestExecutionEnabled(topologyEnv));
    if (topologyExecutionRequested && !executionContext) {
        throw new TypeError(
            'Opted-in topology recovery requires an operation worker with an exact execution identity',
        );
    }
    const testWorkerExecutionAllowed = executionContext?.target === 'test';
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
    let topologyDeploymentService;
    let topologyIntentService;
    let topologyRecoveryLifecycle;
    let executionRuntime;

    // The L2TP install worker may advance the topology revision (route-group
    // paths are rebuilt for the relay). Deploy automatically right after a
    // successful install so relay ingress listeners appear without a manual
    // chain sync. Late-bound: the topology runtime is created below.
    const deployTopologyAfterInstall = async () => {
        const service = topologyDeploymentService;
        if (!service || typeof service.deploy !== 'function') return;
        if (typeof adapters.stateRepository?.getTopologyRevision !== 'function') return;
        const revision = await adapters.stateRepository.getTopologyRevision();
        if (!Number.isSafeInteger(revision) || revision < 0) return;
        await service.deploy({ expectedTopologyRevision: revision });
    };

    const createExecution = () => createExecutionRuntime({
        workerLifecycle,
        HyNode: injectedHyNode,
        RelayL2tpState: models.RelayL2tpState,
        L2tpUser: models.L2tpUser,
        CascadeRouteGroup: models.CascadeRouteGroup,
        CascadeLink: injectedCascadeLink,
        CascadeTopologyState: models.CascadeTopologyState,
        operationModel: models.L2tpOperation,
        RemoteAdmission: models.RemoteAdmission,
        lockModel: models.NodeOperationLock,
        NodeSSH,
        NodeTransport,
        createPreflightRunner,
        createCandidateService,
        candidateNodeResolver,
        candidateUserResolver,
        configGenerator,
        fragmentProvider,
        operationMaterializer,
        createUserSnapshotResolver,
        createUserSyncReconciler,
        stateManagementService,
        secretBox,
        secretKey,
        clock,
        createRuntime,
        createWorkerLifecycle: createLifecycle,
        topologyIngressGate: topologyDeploymentService?.attachIngressGate,
        topologyPppReadinessGate: topologyDeploymentService?.installedPppReadinessGate,
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
            afterInstallSucceeded: deployTopologyAfterInstall,
            ...l2tpExecutionAuthorization,
        },
    });

    if (executionContext) {
        if (typeof injectedModuleEntry.createTopologyDeploymentService !== 'function') {
            throw new TypeError(
                'Opted-in topology recovery requires createTopologyDeploymentService',
            );
        }
        topologyDeploymentService = injectedModuleEntry.createTopologyDeploymentService({
            env: topologyEnv,
            executionContext,
            HyNode: injectedHyNode,
            CascadeLink: injectedCascadeLink,
            CascadeRouteGroup: models.CascadeRouteGroup,
            CascadeTopologyState: models.CascadeTopologyState,
            RelayL2tpState: models.RelayL2tpState,
            TopologyOperation: models.TopologyOperation,
            RemoteAdmission: models.RemoteAdmission,
            L2tpUser: models.L2tpUser,
            L2tpOperation: models.L2tpOperation,
            NodeOperationLock: models.NodeOperationLock,
            TopologyExecutionBinding: models.TopologyExecutionBinding,
            TopologyExecutionEnrollment: models.TopologyExecutionEnrollment,
            TopologyConfigOwner: models.TopologyConfigOwner,
            ...(topologyExecutionAuthority !== undefined
                ? { topologyExecutionAuthority } : {}),
            ...(createTopologyOperationExecutor === undefined ? {} : { createTopologyOperationExecutor }),
            installedIngressPreparer: ({ operationPlan }) => {
                const service = executionRuntime?.runtime?.simpleService;
                if (typeof service?.prepareConfiguredRelayIngress !== 'function') {
                    throw Object.assign(new Error('Installed ingress preparation unavailable'), { code: 'INGRESS_UNVERIFIED' });
                }
                return service.prepareConfiguredRelayIngress({ operationPlan });
            },
            NodeSSH,
            clock,
            workerId: `${workerId}-topology`,
            leaseMs,
        });
        if (typeof topologyDeploymentService?.operationWorker?.run !== 'function') {
            throw new TypeError('Opted-in topology recovery requires an operation worker');
        }
        // Context fencing does not activate production client proof. Keep this
        // separate queue TEST-only even when production execution opted in.
        let clientProofWorker;
        if (testWorkerExecutionAllowed && typeof topologyEnv.TOPOLOGY_PROBE_USER_ID === 'string'
            && topologyEnv.TOPOLOGY_PROBE_USER_ID.trim()) {
            const { TopologyOperationRepository } = require('./relay-l2tp/repositories/topologyOperationRepository');
            const { TopologyClientReadinessWorker } = require('./relay-l2tp/workers/topologyClientReadinessWorker');
            const { TopologyClientProofExecutor } = require('./relay-l2tp/services/topologyClientProofExecutor');
            const { TopologyPublishedProfileSource } = require('./relay-l2tp/services/topologyPublishedProfileSource');
            const proofRepository = topologyDeploymentService.operationWorker.operationRepository
                ?? new TopologyOperationRepository({ model: models.TopologyOperation, topologyStateModel: models.CascadeTopologyState });
            const proofExecutor = new TopologyClientProofExecutor({
                selectedTopologyRepository: topologyDeploymentService.operationWorker.selectedTopologyRepository,
                L2tpUser: models.L2tpUser,
                pppReadinessGate: topologyDeploymentService.installedPppReadinessGate,
                CascadeTopologyState: models.CascadeTopologyState,
                HyNode: injectedHyNode,
                CascadeLink: injectedCascadeLink,
                CascadeRouteGroup: models.CascadeRouteGroup,
                RelayL2tpState: models.RelayL2tpState,
                NodeSSH: NodeSSH ?? require('../services/nodeSSH'),
                profileSource: new TopologyPublishedProfileSource({ probeUserId: topologyEnv.TOPOLOGY_PROBE_USER_ID }),
            });
            proofRepository.clientProofExecutor = proofExecutor;
            clientProofWorker = new TopologyClientReadinessWorker({
                executionContext,
                repository: proofRepository,
                probeOperation: operation => proofExecutor.probeOperation(operation),
                now: () => clock.now(),
            });
        }
        if (typeof injectedModuleEntry.createTopologyIntentService === 'function') {
            topologyIntentService = injectedModuleEntry.createTopologyIntentService({
                ...models,
                executionContext,
                HyNode: injectedHyNode,
                CascadeLink: injectedCascadeLink,
                clock,
                intentOperationAdmission: topologyDeploymentService.intentOperationAdmission,
                intentDraftWriter: topologyDeploymentService.intentDraftWriter,
                resolveIntentResources: topologyDeploymentService.resolveIntentResources,
                ...(typeof injectedCascadeLink.createDeleteIntentWriter === 'function'
                    ? { deleteIntentWriter: injectedCascadeLink.createDeleteIntentWriter({ CascadeLink: injectedCascadeLink }) } : {}),
                prepareLink: async link => {
                    // Invoked by the real service only AFTER persisted-key replay.
                    // Defaults come from trusted node metadata, never HTTP fields.
                    const targetNode = await injectedHyNode.findById(link.bridgeNode).lean();
                    return require('../routes/cascadeLinks').prepareIntentLink(link, targetNode);
                },
            });
        }
        const recoveryFactory = createTopologyRecoveryLifecycle
            ?? require('./relay-l2tp/runtime/createTopologyOperationRecoveryLifecycle')
                .createTopologyOperationRecoveryLifecycle;
        topologyRecoveryLifecycle = recoveryFactory({
            env: topologyEnv,
            executionContext,
            operationModel: models.TopologyOperation,
            worker: topologyDeploymentService.operationWorker,
            ...(topologyIntentService ? { intentConsumer: topologyIntentService } : {}),
            ...(clientProofWorker ? { clientProofWorker } : {}),
            clock,
            intervalMs: workerLifecycle?.intervalMs,
            timer: workerLifecycle?.timer,
            logger: workerLifecycle?.logger,
            ...(topologyRecoveryScanLimit === undefined
                ? {}
                : { scanLimit: topologyRecoveryScanLimit }),
        });
    }

    executionRuntime = createExecution();

    return {
        moduleEntry: injectedModuleEntry,
        topologyRuntime,
        topologyIntentService,
        selectedTopologyIntentService: topologyIntentService,
        readLinkApplicationState: topologyDeploymentService?.readLinkApplicationState,
        readPublicOperation: topologyDeploymentService?.readPublicOperation,
        enrollTestOwners() {
            if (typeof topologyDeploymentService?.enrollTestOwners !== 'function') {
                throw new Error('TEST_DURABLE_ORIGINALS_CAPTURE_REQUIRED');
            }
            return topologyDeploymentService.enrollTestOwners();
        },
        repository,
        loadPanelOverview,
        stateManagementService: executionRuntime.runtime.stateManagementService,
        runtime: executionRuntime.runtime,
        start() {
            const executionState = executionRuntime.start();
            topologyRecoveryLifecycle?.start();
            return executionState;
        },
        async stop() {
            // Fence BOTH schedules before waiting for either remote invocation.
            // A failing lifecycle must not abandon the other dependency drain.
            const stop = lifecycle => {
                try { return lifecycle?.stop(); }
                catch (error) { return Promise.reject(error); }
            };
            const [recovery, execution] = await Promise.allSettled([
                stop(topologyRecoveryLifecycle), stop(executionRuntime),
            ]);
            if (recovery.status === 'rejected') throw recovery.reason;
            if (execution.status === 'rejected') throw execution.reason;
            return recovery.value?.drainUncertain === true
                ? { ...execution.value, drainUncertain: true }
                : execution.value;
        },
    };
}

module.exports = {
    createL2tpPanelHost,
};
