'use strict';

const {
    createL2tpMigrationBootstrap,
} = require('./l2tpMigrationBootstrap');
const {
    createL2tpStartupLifecycle,
} = require('./createL2tpStartupLifecycle');
const {
    l2tpActiveHostProvider,
} = require('./l2tpActiveHostProvider');
const {
    DEFAULT_MAX_STALENESS_MS,
} = require('./relay-l2tp/services/topologyHealthSource');
const {
    PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT,
} = require('./relay-l2tp/domain/topologyExecutionContext');

function isProductionSchemaHost(env) {
    return env?.PANEL_DOMAIN === PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT.hostIdentity;
}

function productionSchemaConnectionOptions(env) {
    // Existing PROD data is not an initialized topology admission schema.
    // Never let model import/connection auto-create it ahead of the reviewed migration.
    return isProductionSchemaHost(env) ? { autoIndex: false, autoCreate: false } : {};
}

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

function createEnabledHostDependencies(factory, env) {
    if (typeof factory !== 'function') {
        throw new TypeError('L2TP enabled startup requires createHostDependencies');
    }
    const dependencies = factory({ env });
    if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies)) {
        throw new TypeError('L2TP createHostDependencies must return an object');
    }
    for (const factoryName of [
        'createCandidateService',
        'createPreflightRunner',
        'createUserSnapshotResolver',
        'createUserSyncReconciler',
    ]) {
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
        ? createEnabledHostDependencies(createHostDependencies, env)
        : {};
    const lifecycle = createStartupLifecycle({
        config: { enabled },
        hostDependencies,
        activeHostProvider,
    });
    lifecycle.start();
    if (typeof hostDependencies.topologyExecutionAuthority?.close === 'function') {
        const stop = lifecycle.stop.bind(lifecycle);
        let stopping;
        return { ...lifecycle, stop() {
            if (!stopping) stopping = Promise.resolve().then(stop).finally(() => hostDependencies.topologyExecutionAuthority.close());
            return stopping;
        } };
    }
    return lifecycle;
}

function createL2tpRootHostDependencies({
    env = process.env,
    HyNode = require('../models/hyNodeModel'),
    NodeSSH = require('../services/nodeSSH'),
    NodeTransport = require('./relay-l2tp/services/l2tpNodeTransport').L2tpNodeTransport,
    L2tpXrayCandidateService = require('./relay-l2tp/services/l2tpXrayCandidateService')
        .L2tpXrayCandidateService,
    createPreflightRunner = require('./relay-l2tp/services/l2tpPreflightRunner')
        .createL2tpPreflightRunner,
    operationMaterializer = require('./relay-l2tp/services/l2tpOperationMaterializer')
        .materializeInstallOperation,
    createUserSnapshotResolver = ({ userResolver } = {}) => {
        if (!userResolver || typeof userResolver.resolveSyncSnapshot !== 'function') {
            throw new TypeError('L2TP user snapshot resolver is unavailable');
        }
        return request => userResolver.resolveSyncSnapshot(request);
    },
    createUserSyncReconciler = ({ L2tpOperation, RelayL2tpState, L2tpUser, clock } = {}) => {
        const { L2tpUserSyncRepository } = require('./relay-l2tp/repositories/l2tpUserSyncRepository');
        const { L2tpUserSyncReconciler } = require('./relay-l2tp/services/l2tpUserSyncReconciler');
        return new L2tpUserSyncReconciler({
            repository: new L2tpUserSyncRepository({ L2tpOperation, RelayL2tpState, L2tpUser }),
            clock,
        });
    },
    secretBox = require('./relay-l2tp/services/secretBoxService'),
    secretKey = require('../../config').ENCRYPTION_KEY,
    syncService = require('../services/syncService'),
    candidateNodeResolver,
    candidateUserResolver,
    configGenerator = require('../services/configGenerator').generateXrayConfigWithApi,
    fragmentProvider = require('./relay-l2tp/services/l2tpXrayFragmentProvider')
        .buildL2tpXrayFragment,
    requireAuth = require('../routes/panel/helpers').requireAuth,
    requireOnboarding = require('../routes/panel/helpers').requireOnboarding,
    csrf = require('../routes/panel/csrf').requirePanelCsrf,
    rateLimiter = require('../routes/panel').l2tpRateLimiter,
    renderPage = require('../routes/panel').renderL2tpPage,
    clock = { now: () => new Date() },
    topologyHealthMaxStalenessMs = DEFAULT_MAX_STALENESS_MS,
    createTopologyExecutionAuthority = require('./relay-l2tp/runtime/testPhysicalController').createRootTestPhysicalAuthority,
    topologyExecutionAuthority,
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

    const authority = topologyExecutionAuthority ?? createTopologyExecutionAuthority({ env });
    return {
        env,
        ...(authority ? { topologyExecutionAuthority: authority } : {}),
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
        createUserSnapshotResolver,
        createUserSyncReconciler,
        secretBox,
        secretKey,
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        renderPage,
        clock,
        enableTopologyHealthProvider: true,
        topologyHealthMaxStalenessMs,
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
    createMigrationBootstrap = createL2tpMigrationBootstrap,
    ensureModelIndexes = options => require('./l2tpModelIndexReadiness').ensureL2tpModelIndexes(options),
    createHostDependencies = createL2tpRootHostDependencies,
    createRuntimeLifecycleHook = createL2tpRuntimeLifecycleHook,
    activeHostProvider = l2tpActiveHostProvider,
} = {}) {
    let lifecycle;
    let startPromise;
    let stopPromise;
    let stopRequested = false;

    return {
        startAfterDatabase() {
            if (startPromise === undefined) {
                startPromise = Promise.resolve().then(async () => {
                    if (stopRequested) return undefined;
                    parseL2tpExecutionEnabled(env.L2TP_EXECUTION_ENABLED);
                    const dormantProduction = isProductionSchemaHost(env);
                    if (dormantProduction && (env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'true'
                        || env.L2TP_PRODUCTION_EXECUTION_ENABLED === 'true')) {
                        throw new TypeError('PRODUCTION_SCHEMA_AUTHORITY_UNAVAILABLE');
                    }
                    if (!dormantProduction) {
                        const migrationBootstrap = createMigrationBootstrap({ env });
                        await migrationBootstrap.run();
                        if (stopRequested) return undefined;
                        await ensureModelIndexes();
                    }
                    if (stopRequested) return undefined;
                    lifecycle = createRuntimeLifecycleHook({
                        env: dormantProduction ? { ...env,
                            L2TP_EXECUTION_ENABLED: 'false',
                            L2TP_MIGRATIONS_ENABLED: 'false' } : env,
                        createHostDependencies,
                        activeHostProvider,
                    });
                    return lifecycle;
                });
            }
            return startPromise;
        },
        stop() {
            stopRequested = true;
            if (stopPromise === undefined) {
                stopPromise = startPromise === undefined
                    ? Promise.resolve()
                    : startPromise.then(
                        () => lifecycle?.stop(),
                        () => undefined,
                    );
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
    productionSchemaConnectionOptions,
};
