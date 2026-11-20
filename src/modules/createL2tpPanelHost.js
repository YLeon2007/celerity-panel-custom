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
    if(healthByPathKey===undefined && topologyEnv.TOPOLOGY_TEST_STARTUP_MODE==='dedicated-runtime-v1'
        && executionContext?.target==='test' && typeof topologyExecutionAuthority?.readCurrentHealth==='function') {
        healthByPathKey=require('./relay-l2tp/services/topologyDedicatedTestHealth').createDedicatedTestPathHealth({
            authority:topologyExecutionAuthority,CascadeLink:injectedCascadeLink,CascadeRouteGroup:models.CascadeRouteGroup});
    }
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
        // Native topology ingress is settled before install admission below.
        if (executionContext) return;
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
        prepareTopologyIngress: executionContext ? async input => {
            const { topologyManagesNodeConfig } = require('../services/topologyConfigOwnership');
            if (!await topologyManagesNodeConfig({ _id: input.nodeId }, topologyEnv)) return;
            if (typeof topologyDeploymentService?.prepareL2tpIngress !== 'function') throw new Error('TOPOLOGY_L2TP_INGRESS_UNAVAILABLE');
            return topologyDeploymentService.prepareL2tpIngress(input);
        } : undefined,
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
                    const listenerId = link.mode === 'forward' ? link.bridgeNode : link.portalNode;
                    const listenerNode = link.tunnelSecurity === 'reality'
                        ? await injectedHyNode.findById(listenerId).lean() : null;
                    return require('../routes/cascadeLinks').prepareIntentLink(link, listenerNode);
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
    const dedicatedActivation = topologyEnv.TOPOLOGY_TEST_STARTUP_MODE === 'dedicated-runtime-v1';
    let dedicatedStarted = false, dedicatedStopped = false, dedicatedEnrollment, activationFailed = false, dedicatedResult, activationConfirmed = false, bootstrapOperationId;
    let testHandback, testHandbackState;
    const activationId = require('node:crypto').randomUUID();
    const startConsumers = () => {
        if (dedicatedStopped) throw new Error('TEST_OWNER_STARTUP_MODE_CONFLICT');
        const state = executionRuntime.start();
        topologyRecoveryLifecycle?.start();
        dedicatedStarted = true;
        return state;
    };

    return {
        moduleEntry: injectedModuleEntry,
        topologyRuntime,
        topologyIntentService,
        selectedTopologyIntentService: topologyIntentService,
        readLinkApplicationState: topologyDeploymentService?.readLinkApplicationState,
        readPublicOperation: topologyDeploymentService?.readPublicOperation,
        readAppliedNodePublication: topologyDeploymentService?.readAppliedNodePublication,
        readBusinessReentryRestriction() {
            if (!executionContext) return Promise.resolve({ blocked: false });
            return require('./relay-l2tp/services/topologyReentryPolicy').readBusinessReentryRestriction({
                executionContext, TopologyConfigOwner: models.TopologyConfigOwner,
                TopologyOperation: models.TopologyOperation, TopologyExecutionBinding: models.TopologyExecutionBinding,
            });
        },
        ...(topologyEnv.TOPOLOGY_TEST_STARTUP_MODE === 'dedicated-runtime-v1' && executionContext?.target === 'test'
            && typeof topologyExecutionAuthority?.readCurrentHealth === 'function' ? {
                readNodePublicationHealth: require('./relay-l2tp/services/topologyDedicatedTestHealth')
                    .createDedicatedTestNodeHealth({ authority: topologyExecutionAuthority }),
            } : {}),
        beginBootstrapContinuation(operationId, cancel = false) {
            if (!dedicatedActivation || dedicatedStopped || dedicatedStarted || !/^[a-f0-9]{24}$/.test(operationId)
                || typeof topologyDeploymentService.resumeBootstrapPreparation !== 'function'
                || (dedicatedEnrollment && bootstrapOperationId !== operationId)) throw new Error('TEST_BOOTSTRAP_CONTINUATION_UNPROVEN');
            bootstrapOperationId = operationId;
            dedicatedEnrollment ??= Promise.resolve().then(async () => {
                try {
                    const result = await topologyDeploymentService[cancel === 'undispatched-failure' ? 'settleUndispatchedPreparation' : cancel === 'prepared' ? 'resumePreparedCommit' : cancel === 'closed' ? 'resumeClosedSettlement' : cancel === 'preparation' ? 'resumeUndispatchedPreparation' : cancel === 'runtime' ? 'resumeSettledRuntime' : cancel === 'verification' ? 'resumeRetainedVerification' : cancel === 'bindings' ? 'resumeBindingReservations' : cancel === 'settled' ? 'resumeSettledBootstrap' : cancel ? 'cancelBootstrapPreparation' : 'resumeBootstrapPreparation'](operationId, outcome => {
                        dedicatedResult = { status: cancel === 'undispatched-failure' ? 'undispatched_failure_settled' : cancel === 'runtime' ? 'settled_runtime_reconciled' : cancel === 'verification' ? 'verification_continued' : cancel === 'bindings' ? 'bindings_continued' : cancel ? 'bootstrap_cancelled' : 'bootstrap_continued', operationId: outcome.operationId, nodes: [] };
                        if (!dedicatedStopped) startConsumers();
                    });
                    if (result.status !== (cancel === 'undispatched-failure' ? 'failed' : cancel && !['bindings', 'verification', 'runtime', 'preparation', 'closed', 'prepared'].includes(cancel) ? 'cancelled' : 'succeeded') || !dedicatedResult) throw new Error('TEST_BOOTSTRAP_CONTINUATION_RETAINED');
                    activationConfirmed = true;
                    return result;
                } catch (error) {
                    activationFailed = true;
                    await Promise.allSettled([Promise.resolve().then(() => topologyRecoveryLifecycle?.stop()),
                        Promise.resolve().then(() => executionRuntime.stop())]);
                    dedicatedStarted = false;
                    throw error;
                }
            });
            dedicatedEnrollment.catch(() => {});
            return { activationId, operationId, status: activationFailed ? 'retained' : 'reconciling' };
        },
        beginTestActivation({ resumeOnly = false } = {}) {
            if (!dedicatedActivation || dedicatedStopped || bootstrapOperationId) throw new Error('TEST_OWNER_STARTUP_MODE_CONFLICT');
            // Admission is synchronous and bounded; the joined promise is owned
            // by this host, not by the HTTP socket. Failure is never retried.
            this.enrollTestOwners({ resumeOnly }).catch(() => {});
            return { activationId, status: activationConfirmed && dedicatedStarted ? 'active' : activationFailed ? 'retained' : 'reconciling' };
        },
        beginTestHandback() {
            if (!dedicatedActivation || executionContext?.target !== 'test' || !activationConfirmed || activationFailed) throw Error('TEST_OWNER_HANDBACK_UNPROVEN');
            if (!testHandback) {
                testHandbackState = { status: 'handing_back' };
                testHandback = Promise.resolve().then(async () => {
                    const pins = await topologyDeploymentService.inspectTestOwnerHandback();
                    const stopped = await this.stop();
                    if (stopped?.running !== false || stopped.inFlight !== false || stopped.drainUncertain === true) throw Error('TEST_OWNER_HANDBACK_UNPROVEN');
                    testHandbackState = await topologyDeploymentService.handbackTestOwners(pins);
                }).catch(error => { testHandbackState = { status: 'retained', code: error.code || 'TEST_OWNER_HANDBACK_UNPROVEN' }; });
            }
            return { ...testHandbackState };
        },
        async readTestActivationStatus() {
            // Bounded local snapshot: GET never starts remote/DB work. A fresh
            // process explicitly reports unreconciled, never prior HTTP success.
            return { activationId, status: testHandbackState?.status ?? (dedicatedStopped ? 'stopped' : activationConfirmed && dedicatedStarted ? 'active' : activationFailed ? 'retained' : dedicatedEnrollment ? 'reconciling' : 'reconciliation_required'),
                ...(testHandbackState ? { handback: testHandbackState } : {}),
                durableStatus: dedicatedResult ? (bootstrapOperationId ? 'bootstrap_operation_settled' : 'enrollment_reconciled') : 'unreconciled',
                ...(bootstrapOperationId ? { operationId: bootstrapOperationId } : {}),
                nodes: dedicatedResult?.nodes ?? [] };
        },
        async enrollTestOwners({ resumeOnly = false } = {}) {
            if (typeof topologyDeploymentService?.enrollTestOwners !== 'function') throw new Error('TEST_DURABLE_ORIGINALS_CAPTURE_REQUIRED');
            if (!dedicatedActivation) return topologyDeploymentService.enrollTestOwners();
            if (dedicatedStopped) throw new Error('TEST_OWNER_STARTUP_MODE_CONFLICT');
            dedicatedEnrollment ??= Promise.resolve().then(async () => {
                try {
                    const result = await topologyDeploymentService.enrollTestOwners({ resumeOnly, onReconciled: result => {
                        dedicatedResult = result;
                        if (!dedicatedStopped && !dedicatedStarted) startConsumers();
                    } });
                    if (!dedicatedResult) throw new Error('TEST_RECONCILIATION_CALLBACK_REQUIRED');
                    activationConfirmed = true;
                    return result;
                } catch (error) {
                    activationFailed = true;
                    await Promise.allSettled([Promise.resolve().then(() => topologyRecoveryLifecycle?.stop()),
                        Promise.resolve().then(() => executionRuntime.stop())]);
                    dedicatedStarted = false;
                    throw error;
                }
            });
            return dedicatedEnrollment;
        },
        enrollProductionOwners() {
            if (dedicatedStarted || dedicatedStopped || executionContext?.target !== 'production'
                || typeof topologyDeploymentService?.enrollProductionOwners !== 'function') throw new Error('PRODUCTION_OWNER_ENTRY_UNPROVEN');
            return topologyDeploymentService.enrollProductionOwners();
        },
        handbackProductionOwners(acceptedCurrent) {
            if (!dedicatedStopped || executionContext?.target !== 'production'
                || typeof topologyDeploymentService?.handbackProductionOwners !== 'function') throw new Error('PRODUCTION_OWNER_ENTRY_UNPROVEN');
            return topologyDeploymentService.handbackProductionOwners(acceptedCurrent);
        },
        repository,
        loadPanelOverview,
        stateManagementService: executionRuntime.runtime.stateManagementService,
        runtime: executionRuntime.runtime,
        start() {
            if (dedicatedActivation && !dedicatedStarted) return { enabled: true, running: false, activationRequired: true };
            return startConsumers();
        },
        async stop() {
            dedicatedStopped = true;
            // Fence BOTH schedules before waiting for either remote invocation.
            // A failing lifecycle must not abandon the other dependency drain.
            const stop = lifecycle => {
                try { return lifecycle?.stop(); }
                catch (error) { return Promise.reject(error); }
            };
            const drains = Promise.allSettled([stop(topologyRecoveryLifecycle), stop(executionRuntime)]);
            if (dedicatedEnrollment) await dedicatedEnrollment.catch(() => {});
            const [recovery, execution] = await drains;
            if (recovery.status === 'rejected') throw recovery.reason;
            if (execution.status === 'rejected') throw execution.reason;
            return recovery.value?.drainUncertain === true || (bootstrapOperationId && activationFailed)
                ? { ...execution.value, drainUncertain: true }
                : execution.value;
        },
    };
}

module.exports = {
    createL2tpPanelHost,
};
