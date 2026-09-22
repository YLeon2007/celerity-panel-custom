'use strict';

const { createConfigFragmentRegistry } = require('../../../services/configFragmentRegistry');
const { createL2tpRouter } = require('../routes/panel');
const { L2tpOperationRepository } = require('../services/l2tpOperationRepository');
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
    'preflightRunner',
    'transport',
    'lockService',
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
    } = dependencies;
    const workerOperationRepository = new L2tpOperationRepository({ model: operationModel });
    const service = new L2tpService({
        nodeRepository,
        stateRepository,
        operationRepository,
        planBuilder: buildInstallPlan,
        preflightRunner,
        clock,
    });
    const executor = new L2tpRemoteExecutor({ transport });
    const worker = new L2tpOperationWorker({
        operationRepository: workerOperationRepository,
        lockService,
        executor,
        workerId,
        leaseMs,
        clock,
    });
    hideInjectedDependencies(service, [
        'nodeRepository',
        'stateRepository',
        'operationRepository',
        'planBuilder',
        'preflightRunner',
        'clock',
    ]);
    hideInjectedDependencies(worker, [
        'operationRepository',
        'lockService',
        'executor',
        'clock',
    ]);
    const router = createL2tpRouter({
        l2tpService: service,
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        loadPanelOverview,
        renderPage,
    });
    const configFragmentRegistry = createConfigFragmentRegistry([PROVIDER_ID]);
    configFragmentRegistry.register(PROVIDER_ID, buildL2tpXrayFragment);

    return {
        service,
        worker,
        router,
        configFragmentRegistry,
    };
}

module.exports = { createL2tpRuntime };
