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
const {
    resolveL2tpExecutionAuthorization,
} = require('./relay-l2tp/domain/l2tpExecutionAuthorization');

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

function createEnabledHostDependencies(factory, env, ownerEnrollment) {
    if (typeof factory !== 'function') {
        throw new TypeError('L2TP enabled startup requires createHostDependencies');
    }
    const dependencies = factory({ env, ownerEnrollment });
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
    startWorkers = true,
    ownerEnrollment = false,
} = {}) {
    const enabled = parseL2tpExecutionEnabled(env.L2TP_EXECUTION_ENABLED);
    const hostDependencies = enabled
        ? createEnabledHostDependencies(createHostDependencies, env, ownerEnrollment)
        : {};
    const lifecycle = createStartupLifecycle({
        config: { enabled },
        hostDependencies,
        activeHostProvider,
    });
    if (startWorkers) lifecycle.start();
    if (typeof hostDependencies.topologyExecutionAuthority?.close === 'function') {
        const stop = lifecycle.stop.bind(lifecycle);
        let stopping, originalDrain;
        return { ...lifecycle,
            // Internal finite migration caller only: use the SAME consumer stop/join
            // without destroying the sole retained original holder before handback.
            drainForOriginalHandback() {
                if (!originalDrain) originalDrain = Promise.resolve().then(stop).then(state => {
                    if (state?.stopped !== true || state.running !== false || state.drainUncertain === true) {
                        throw new Error('TEST_ORIGINAL_CONSUMER_DRAIN_UNPROVEN');
                    }
                    hostDependencies.topologyExecutionAuthority.drainOriginals();
                });
                return originalDrain;
            },
            async handbackProductionOriginals(acceptedCurrent) {
                await this.drainForOriginalHandback();
                return lifecycle.handbackProductionOwners(acceptedCurrent);
            },
            stop() {
                if (!stopping) stopping = Promise.resolve().then(stop).finally(() => hostDependencies.topologyExecutionAuthority.close());
                return stopping;
            },
        };
    }
    return lifecycle;
}

function createL2tpRootHostDependencies({
    env = process.env,
    ownerEnrollment = false,
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
    createTopologyExecutionAuthority = require('./relay-l2tp/runtime/productionPhysicalAuthority').createRootTopologyExecutionAuthority,
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

    const configWriteEnv = Object.freeze({ ...env });
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

    const authority = topologyExecutionAuthority ?? createTopologyExecutionAuthority({ env, ownerEnrollment });
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
            const { withHeldL2tpNodeConfigWrite, assertHeldL2tpNodeConfigWrite } = require('../services/classicNodeConfigWrite');
            const preparation = new (require('node:async_hooks').AsyncLocalStorage)();
            const resolveExecutionNode = async nodeId => {
                await assertHeldL2tpNodeConfigWrite(nodeId);
                // The same held node also feeds the existing full MAIN writer.
                // Keep its generation/group/ACL/TLS fields, not just SSH inputs.
                const node = await HyNode.findById(nodeId).select([
                    ...CANDIDATE_NODE_XRAY_PROJECTION, 'name', 'xray.agentToken', 'xray.configPath',
                    'ssh.port', 'ssh.username', 'ssh.privateKey', 'ssh.password',
                ].join(' ')).lean();
                if (!node || String(node._id) !== String(nodeId) || node.type !== 'xray'
                    || node.active !== true || node.cascadeRole !== 'relay') throw new Error('NODE_EXECUTION_UNAVAILABLE');
                return node;
            };
            const readConfig = async (nodeId, profile) => {
                const executionNode = await resolveExecutionNode(nodeId);
                const ssh = new NodeSSH(executionNode);
                try {
                    await ssh.connect();
                    await assertHeldL2tpNodeConfigWrite(nodeId);
                    const path = profile === 'xray-bridge'
                        ? '/usr/local/etc/xray-bridge/config.json' : '/usr/local/etc/xray/config.json';
                    const current = await ssh.exec(`cat ${path}`);
                    if (current?.code !== 0 || typeof current.stdout !== 'string') throw new Error('CURRENT_XRAY_CONFIG_UNAVAILABLE');
                    await assertHeldL2tpNodeConfigWrite(nodeId);
                    return current.stdout;
                } finally { ssh.disconnect(); }
            };
            const { createTopologyL2tpInstallComposition, composeTopologyL2tpMainFragment } = require('./relay-l2tp/services/topologyL2tpInstallComposition');
            const topologyInstall = createTopologyL2tpInstallComposition({ env: configWriteEnv, HyNode, readConfig });
            const service = new L2tpXrayCandidateService({
                configGenerator: injectedConfigGenerator,
                userResolver,
                nodeResolver,
                fragmentProvider: injectedFragmentProvider,
                currentConfigResolver: async ({ node }) => {
                    const current = await readConfig(node._id, 'xray-main');
                    // Only a positively authorized topology first-install may
                    // normalize an actually empty MAIN. Classic sparse refusal stays.
                    if (preparation.getStore()?.topology && Object.keys(JSON.parse(current)).length === 0) {
                        return { inbounds: [], outbounds: [], routing: { rules: [] } };
                    }
                    return current;
                },
            });
            service.withLockedPreparation = (request, callback) => withHeldL2tpNodeConfigWrite(request,
                () => preparation.run({}, callback));
            service.verifyRestoredInstall = async operation => {
                const node = await HyNode.findById(operation.node).select([
                    'type', 'active', 'cascadeRole', 'ip', 'ssh.port', 'ssh.username', 'ssh.privateKey', 'ssh.password',
                ].join(' ')).lean();
                if (!node || node.type !== 'xray' || node.active !== true || node.cascadeRole !== 'relay') return { ok: false };
                const ssh = new NodeSSH(node);
                try {
                    await ssh.connect();
                    const result = await ssh.exec('python3 -', { timeout: 20000,
                        stdin: require('./relay-l2tp/services/l2tpRestoredInstallReadback').restoredInstallProbe(String(operation._id)) });
                    return result?.code === 0 && result.stderr === '' ? JSON.parse(result.stdout) : { ok: false };
                } finally { ssh.disconnect(); }
            };
            service.transformFragment = async ({ fragment }) => {
                const topology = preparation.getStore()?.topology;
                return topology ? composeTopologyL2tpMainFragment({ fragment, ...topology }) : fragment;
            };
            service.assertConfigWriteAllowed = async (nodeId, request) => {
                const { topologyManagesNodeConfig } = require('../services/topologyConfigOwnership');
                if (await topologyManagesNodeConfig({ _id: nodeId }, configWriteEnv)) {
                    await topologyInstall.authorize(String(nodeId), request);
                }
            };
            service.prepareIngress = async ({ plan }) => {
                const { topologyManagesNodeConfig } = require('../services/topologyConfigOwnership');
                if (await topologyManagesNodeConfig({ _id: plan.relayId }, configWriteEnv)) {
                    const scope = preparation.getStore();
                    if (!scope) throw new Error('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
                    scope.topology = await topologyInstall.prepare(plan);
                    return;
                }
                const relay = await resolveExecutionNode(plan.relayId);
                const CascadeRouteGroup = require('./relay-l2tp/models/cascadeRouteGroupModel');
                const CascadeLink = require('../models/cascadeLinkModel');
                const group = await CascadeRouteGroup.findById(plan.routeGroupId).lean();
                const path = group?.paths?.find(row => row.pathKey === plan.selectedPathKey && row.enabled !== false);
                const reject = () => { throw Object.assign(new Error('CLASSIC_L2TP_PATH_UNAVAILABLE'), { code: 'CLASSIC_L2TP_PATH_UNAVAILABLE' }); };
                if (!path?.linkIds?.length || !['forward', 'reverse'].includes(group.mode)) reject();
                const links = await CascadeLink.find({ _id: { $in: path.linkIds }, active: true,
                    status: { $in: ['online', 'deployed'] } }).populate('bridgeNode');
                const first = links.find(row => String(row._id) === String(path.linkIds[0]));
                const id = value => String(value?._id ?? value);
                if (links.length !== path.linkIds.length || !first || id(first.portalNode) !== String(relay._id)
                    || id(first.bridgeNode) !== plan.nextHopNodeId || (first.mode || 'reverse') !== group.mode) reject();
                // Refuse an unavailable/sparse MAIN before even the secondary
                // preparation writes. Candidate construction reads MAIN again
                // afterwards, so forward preparation is not overwritten.
                try {
                    const current = JSON.parse(await service.currentConfigResolver({ node: relay, plan }));
                    if (!Array.isArray(current?.inbounds) || !Array.isArray(current?.outbounds)
                        || !Array.isArray(current?.routing?.rules)) throw new Error();
                } catch {
                    throw Object.assign(new Error('CURRENT_XRAY_CONFIG_UNAVAILABLE'), { code: 'CURRENT_XRAY_CONFIG_UNAVAILABLE' });
                }
                const cascade = require('../services/cascadeService');
                if (group.mode === 'forward') {
                    if (await cascade._deployPortalConfig(relay) !== true) reject();
                } else {
                    const incoming = await CascadeLink.find({ bridgeNode: relay._id, active: true,
                        mode: { $ne: 'forward' }, status: { $in: ['online', 'deployed'] } }).populate('portalNode');
                    if (!incoming.length || incoming.some(row => !row.portalNode?._id)) reject();
                    if (await cascade._deployBridgeConfig(incoming[0], relay, incoming[0].portalNode, {
                        additionalUpstreams: incoming.slice(1).map(row => ({ link: row, portal: row.portalNode })),
                    }) !== true) reject();
                }
            };
            service.prepareNormalization = async ({ plan }) => {
                const scope = preparation.getStore();
                if (!scope) throw new Error('CLASSIC_CONFIG_WRITE_SCOPE_CLOSED');
                scope.topology = await topologyInstall.prepare(plan, { normalization: true });
            };
            service.normalizationReadback = async nodeId => {
                const node = await resolveExecutionNode(nodeId), ssh = new NodeSSH(node);
                try {
                    await ssh.connect();
                    await assertHeldL2tpNodeConfigWrite(nodeId);
                    const result = await ssh.exec('python3 -I -B -', { timeout: 20000, stdin:
                        require('./relay-l2tp/services/l2tpMainNormalization').normalizationProbe() });
                    if (result?.code !== 0 || result.stderr !== '') throw new Error('MAIN_NORMALIZATION_READBACK_FAILED');
                    await assertHeldL2tpNodeConfigWrite(nodeId);
                    return JSON.parse(result.stdout);
                } finally { ssh.disconnect(); }
            };
            return service;
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
    createTopologyExecutionAuthority = require('./relay-l2tp/runtime/productionPhysicalAuthority').createRootTopologyExecutionAuthority,
    productionDatabase = () => require('mongoose').connection.db,
} = {}) {
    let lifecycle;
    let productionAuthority;
    let startPromise;
    let stopPromise;
    let stopRequested = false;
    let ownerEnrollmentMode = false;

    return {
        enrollTestOwnersAfterDatabase() {
            if (startPromise !== undefined || stopRequested) return Promise.reject(new Error('TEST_OWNER_STARTUP_MODE_CONFLICT'));
            const ownerEnv = Object.freeze({ ...env });
            require('../../scripts/test-topology-owner').assertTestContext(ownerEnv);
            ownerEnrollmentMode = true;
            // The maintenance command requires an already installed schema. Do
            // not migrate/index or start consumers before durable capture.
            startPromise = Promise.resolve().then(async () => {
                if (stopRequested) throw new Error('TEST_OWNER_STARTUP_MODE_CONFLICT');
                lifecycle = createRuntimeLifecycleHook({ env: ownerEnv, createHostDependencies, activeHostProvider, startWorkers: false, ownerEnrollment: true });
                return lifecycle.enrollTestOwners();
            });
            return startPromise;
        },
        startAfterDatabase() {
            if (ownerEnrollmentMode) return Promise.reject(new Error('TEST_OWNER_STARTUP_MODE_CONFLICT'));
            if (startPromise === undefined) {
                startPromise = Promise.resolve().then(async () => {
                    if (stopRequested) return undefined;
                    parseL2tpExecutionEnabled(env.L2TP_EXECUTION_ENABLED);
                    const productionHost = isProductionSchemaHost(env);
                    if (productionHost && env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'true') {
                        // The schema hold attaches a one-use physical scope.
                        // Refuse read-only before constructing/opening it; keep
                        // the enrollment recheck under its existing held scope.
                        const policy = require('./relay-l2tp/services/topologyReentryPolicy');
                        if ((await policy.readBusinessReentryRestriction({ executionContext: PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT })).blocked) {
                            throw policy.businessReentryError();
                        }
                        const authority = productionAuthority = createTopologyExecutionAuthority({ env });
                        if (!authority) throw new TypeError('PRODUCTION_PHYSICAL_ACTIVATION_REQUIRED');
                        try {
                            const { verifyProductionStartupSchema } = require('./relay-l2tp/services/productionAdmissionReadiness');
                            const { isDeepStrictEqual } = require('node:util');
                            await authority.withHeldAuthority(PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT, capability =>
                                verifyProductionStartupSchema({ db: productionDatabase(), accepted: authority.admission,
                                    scope: { async assertHeld(challenge) {
                                        if (!isDeepStrictEqual(challenge, authority.admission)) throw new Error('PRODUCTION_ADMISSION_SCOPE_LOST');
                                        await capability.assertHeld();
                                    } } }));
                            if (stopRequested) { authority.close(); return undefined; }
                            // Same producer, original epoch and models. No generic
                            // migration/DDL, TEST controller or L2TP-only flag gate.
                            lifecycle = createRuntimeLifecycleHook({ env, activeHostProvider, startWorkers: false,
                                createHostDependencies: options => createHostDependencies({ ...options, topologyExecutionAuthority: authority }) });
                            await lifecycle.enrollProductionOwners();
                            if (stopRequested) { await lifecycle.stop(); return undefined; }
                            lifecycle.start();
                            return lifecycle;
                        } catch (error) { await lifecycle?.stop(); authority.close(); throw error; }
                    }
                    // L2TP has its own explicit PROD authorization; it does not
                    // activate topology execution or inherit the TEST bypass.
                    const dormantProduction = productionHost
                        && !resolveL2tpExecutionAuthorization(env).enableProductionExecution;
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
        async handbackProductionOriginalsAfterDatabase(acceptedCurrent) {
            if (startPromise === undefined || !productionAuthority || stopRequested) throw new Error('PRODUCTION_OWNER_ENTRY_UNPROVEN');
            await startPromise;
            return lifecycle.handbackProductionOriginals(acceptedCurrent);
        },
        stop() {
            stopRequested = true;
            if (stopPromise === undefined) {
                stopPromise = startPromise === undefined
                    ? Promise.resolve()
                    : startPromise.then(
                        () => lifecycle?.stop(),
                        () => lifecycle?.stop(),
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
