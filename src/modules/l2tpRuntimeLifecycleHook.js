'use strict';

const {
    createL2tpStartupLifecycle,
} = require('./createL2tpStartupLifecycle');
const {
    l2tpActiveHostProvider,
} = require('./l2tpActiveHostProvider');

const ROOT_LEASE_MS = 30_000;
const ROOT_WORKER_INTERVAL_MS = 30_000;
const CANDIDATE_NODE_XRAY_PROJECTION = Object.freeze([
    '_id',
    'type',
    'active',
    'cascadeRole',
    'ip',
    'port',
    'domain',
    'sni',
    'groups',
    'outbounds',
    'aclRules',
    'xray.accessLogs.enabled',
    'xray.apiPort',
    'xray.inboundTag',
    'xray.transport',
    'xray.security',
    'xray.flow',
    'xray.alpn',
    'xray.realityDest',
    'xray.realitySni',
    'xray.realityPrivateKey',
    'xray.realityShortIds',
    'xray.realitySpiderX',
    'xray.wsPath',
    'xray.wsHost',
    'xray.grpcServiceName',
    'xray.xhttpPath',
    'xray.xhttpHost',
    'xray.xhttpMode',
    'xray.fallbackDest',
    'xray.extraInbounds',
    'xray.tlsSource',
    'xray.manualCert',
    '+xray.manualKey',
]);

function parseL2tpExecutionEnabled(value) {
    if (value === undefined || value === 'false') return false;
    if (value === 'true') return true;
    throw new TypeError(
        'L2TP_EXECUTION_ENABLED must be exactly "true" or "false"; refusing startup',
    );
}

function createEnabledHostDependencies(factory) {
    if (typeof factory !== 'function') {
        throw new TypeError('L2TP enabled startup requires createHostDependencies');
    }
    const dependencies = factory();
    if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies)) {
        throw new TypeError('L2TP createHostDependencies must return an object');
    }
    for (const factoryName of ['createCandidateService', 'createPreflightRunner']) {
        if (typeof dependencies[factoryName] !== 'function') {
            throw new TypeError(`L2TP enabled startup requires explicit ${factoryName}`);
        }
    }
    return dependencies;
}

function createL2tpRuntimeLifecycleHook({
    env = process.env,
    createHostDependencies,
    createStartupLifecycle = createL2tpStartupLifecycle,
    activeHostProvider = l2tpActiveHostProvider,
} = {}) {
    const enabled = parseL2tpExecutionEnabled(env.L2TP_EXECUTION_ENABLED);
    const hostDependencies = enabled
        ? createEnabledHostDependencies(createHostDependencies)
        : {};
    const lifecycle = createStartupLifecycle({
        config: { enabled },
        hostDependencies,
        activeHostProvider,
    });
    lifecycle.start();
    return lifecycle;
}

function createL2tpRootHostDependencies({
    HyNode = require('../models/hyNodeModel'),
    NodeSSH = require('../services/nodeSSH'),
    NodeTransport = require('./relay-l2tp/services/l2tpNodeTransport').L2tpNodeTransport,
    L2tpXrayCandidateService = require('./relay-l2tp/services/l2tpXrayCandidateService')
        .L2tpXrayCandidateService,
    createPreflightRunner = require('./relay-l2tp/services/l2tpPreflightRunner')
        .createL2tpPreflightRunner,
    operationMaterializer = require('./relay-l2tp/services/l2tpOperationMaterializer')
        .materializeInstallOperation,
    secretBox = require('./relay-l2tp/services/secretBoxService'),
    secretKey = require('../../config').ENCRYPTION_KEY,
    syncService = require('../services/syncService'),
    candidateNodeResolver,
    candidateUserResolver,
    configGenerator = require('../services/configGenerator').generateXrayConfig,
    fragmentProvider = require('./relay-l2tp/services/l2tpXrayFragmentProvider')
        .buildL2tpXrayFragment,
    requireAuth = require('../routes/panel/helpers').requireAuth,
    requireOnboarding = require('../routes/panel/helpers').requireOnboarding,
    csrf = require('../routes/panel/csrf').requirePanelCsrf,
    rateLimiter = require('../routes/panel').l2tpRateLimiter,
    renderPage = require('../routes/panel').renderL2tpPage,
    clock = { now: () => new Date() },
    workerId = `panel-${process.pid}`,
    leaseMs = ROOT_LEASE_MS,
    intervalMs = ROOT_WORKER_INTERVAL_MS,
    timer = globalThis,
    logger = require('../utils/logger'),
} = {}) {
    if (
        candidateUserResolver === undefined
        && typeof syncService?._getUsersForNode !== 'function'
    ) {
        throw new TypeError('L2TP root startup requires syncService._getUsersForNode');
    }

    const resolvedCandidateNodeResolver = candidateNodeResolver ?? (async ({ nodeId } = {}) => (
        HyNode.findById(nodeId)
            .select(CANDIDATE_NODE_XRAY_PROJECTION.join(' '))
            .lean()
    ));
    const resolvedCandidateUserResolver = candidateUserResolver ?? (async node => {
        const users = await syncService._getUsersForNode(node);
        if (!Array.isArray(users)) return users;
        return users.map(user => ({
            userId: user?.userId,
            xrayUuid: user?.xrayUuid,
        }));
    });

    return {
        HyNode,
        NodeSSH,
        NodeTransport,
        createCandidateService({
            nodeResolver = resolvedCandidateNodeResolver,
            userResolver = resolvedCandidateUserResolver,
            configGenerator: injectedConfigGenerator = configGenerator,
            fragmentProvider: injectedFragmentProvider = fragmentProvider,
        } = {}) {
            return new L2tpXrayCandidateService({
                configGenerator: injectedConfigGenerator,
                userResolver,
                nodeResolver,
                fragmentProvider: injectedFragmentProvider,
            });
        },
        createPreflightRunner,
        candidateNodeResolver: resolvedCandidateNodeResolver,
        candidateUserResolver: resolvedCandidateUserResolver,
        configGenerator,
        fragmentProvider,
        operationMaterializer,
        secretBox,
        secretKey,
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        renderPage,
        clock,
        workerId,
        leaseMs,
        workerLifecycle: {
            intervalMs,
            timer,
            logger,
        },
    };
}

function createL2tpRootLifecycle({
    env = process.env,
    createHostDependencies = createL2tpRootHostDependencies,
    createRuntimeLifecycleHook = createL2tpRuntimeLifecycleHook,
    activeHostProvider = l2tpActiveHostProvider,
} = {}) {
    let lifecycle;
    let stopPromise;

    return {
        startAfterDatabase() {
            if (lifecycle === undefined) {
                lifecycle = createRuntimeLifecycleHook({
                    env,
                    createHostDependencies,
                    activeHostProvider,
                });
            }
            return lifecycle;
        },
        stop() {
            if (stopPromise === undefined) {
                stopPromise = lifecycle === undefined
                    ? Promise.resolve()
                    : Promise.resolve().then(() => lifecycle.stop());
            }
            return stopPromise;
        },
    };
}

module.exports = {
    createL2tpRootHostDependencies,
    createL2tpRootLifecycle,
    createL2tpRuntimeLifecycleHook,
    parseL2tpExecutionEnabled,
};
