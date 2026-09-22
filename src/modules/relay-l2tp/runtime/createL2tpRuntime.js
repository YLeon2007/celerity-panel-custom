'use strict';

const { createConfigFragmentRegistry } = require('../../../services/configFragmentRegistry');
const { createL2tpRouter } = require('../routes/panel');
const { L2tpOperationRepository } = require('../services/l2tpOperationRepository');
const { materializeInstallOperation } = require('../services/l2tpOperationMaterializer');
const { buildInstallPlan } = require('../services/l2tpProvisionPlanService');
const { L2tpRemoteExecutor } = require('../services/l2tpRemoteExecutor');
const { L2tpService } = require('../services/l2tpService');
const { buildL2tpXrayFragment } = require('../services/l2tpXrayFragmentProvider');
const { L2tpOperationWorker } = require('../workers/l2tpOperationWorker');

const PROVIDER_ID = 'relay-l2tp';
const REQUIRED_DEPENDENCIES = Object.freeze([
    'operationModel',
    'operationRepository',
    'nodeRepository',
    'stateRepository',
    'stateManagementService',
    'preflightRunner',
    'lockService',
    'secretResolver',
    'stateReconciler',
    'candidateService',
    'requireAuth',
    'requireOnboarding',
    'csrf',
    'rateLimiter',
    'loadPanelOverview',
    'renderPage',
    'clock',
    'workerId',
    'leaseMs',
]);

function assertDependencies(dependencies) {
    if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies)) {
        throw new TypeError('createL2tpRuntime dependencies are required');
    }
    for (const dependencyName of REQUIRED_DEPENDENCIES) {
        if (dependencies[dependencyName] === undefined || dependencies[dependencyName] === null) {
            throw new TypeError(`createL2tpRuntime requires ${dependencyName}`);
        }
    }
    const hasTransport = dependencies.transport !== undefined && dependencies.transport !== null;
    const hasTransportResolver = typeof dependencies.transportResolver === 'function';
    if (hasTransport === hasTransportResolver) {
        throw new TypeError('createL2tpRuntime requires exactly one transport or transportResolver');
    }
    if (
        dependencies.operationMaterializer !== undefined
        && typeof dependencies.operationMaterializer !== 'function'
    ) {
        throw new TypeError('createL2tpRuntime requires operationMaterializer to be a function');
    }
}

function hideInjectedDependencies(target, propertyNames) {
    for (const propertyName of propertyNames) {
        const descriptor = Object.getOwnPropertyDescriptor(target, propertyName);
        if (descriptor) {
            Object.defineProperty(target, propertyName, {
                ...descriptor,
                enumerable: false,
            });
        }
    }
}

function createL2tpRuntime(dependencies) {
    assertDependencies(dependencies);
    const {
        operationModel,
        operationRepository,
        nodeRepository,
        stateRepository,
        stateManagementService,
        preflightRunner,
        transport,
        transportResolver,
        lockService,
        secretResolver,
        stateReconciler,
        candidateService,
        operationMaterializer = materializeInstallOperation,
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        loadPanelOverview,
        renderPage,
        clock,
        workerId,
        leaseMs,
    } = dependencies;
    const workerOperationRepository = new L2tpOperationRepository({ model: operationModel });
    const service = new L2tpService({
        nodeRepository,
        stateRepository,
        operationRepository,
        planBuilder: buildInstallPlan,
        operationMaterializer,
        preflightRunner,
        clock,
    });
    const executor = new L2tpRemoteExecutor(
        transportResolver ? { transportResolver } : { transport },
    );
    const worker = new L2tpOperationWorker({
        operationRepository: workerOperationRepository,
        lockService,
        executor,
        secretResolver,
        stateReconciler,
        candidateService,
        operationMaterializer,
        workerId,
        leaseMs,
        clock,
    });
    hideInjectedDependencies(stateManagementService, [
        'repository',
        'secretBox',
        'secretKey',
        'randomBytes',
    ]);
    hideInjectedDependencies(service, [
        'nodeRepository',
        'stateRepository',
        'operationRepository',
        'planBuilder',
        'operationMaterializer',
        'preflightRunner',
        'clock',
    ]);
    hideInjectedDependencies(worker, [
        'operationRepository',
        'lockService',
        'executor',
        'secretResolver',
        'stateReconciler',
        'candidateService',
        'operationMaterializer',
        'clock',
        'timer',
    ]);
    const router = createL2tpRouter({
        l2tpService: service,
        stateManagementService,
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        loadPanelOverview,
        renderPage,
    });
    const configFragmentRegistry = createConfigFragmentRegistry([PROVIDER_ID]);
    configFragmentRegistry.register(PROVIDER_ID, buildL2tpXrayFragment);

    const runtime = {
        service,
        worker,
        router,
        configFragmentRegistry,
    };
    Object.defineProperty(runtime, 'stateManagementService', {
        value: stateManagementService,
        enumerable: false,
        writable: false,
        configurable: false,
    });
    return runtime;
}

module.exports = { createL2tpRuntime };
