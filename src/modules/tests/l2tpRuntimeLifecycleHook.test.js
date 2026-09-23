'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { createL2tpPanelHost } = require('../createL2tpPanelHost');
const {
    DEFAULT_MAX_STALENESS_MS,
} = require('../relay-l2tp/services/topologyHealthSource');
const {
    createL2tpRootHostDependencies,
    createL2tpRootLifecycle,
    createL2tpRuntimeLifecycleHook,
    parseL2tpExecutionEnabled,
} = require('../l2tpRuntimeLifecycleHook');

const ENABLED_ENV = Object.freeze({
    L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true',
    TOPOLOGY_TEST_EXECUTION_ENABLED: 'true',
});

test('parses L2TP_EXECUTION_ENABLED as an exact disabled-by-default boolean', () => {
    assert.equal(parseL2tpExecutionEnabled(undefined), false);
    assert.equal(parseL2tpExecutionEnabled('false'), false);
    assert.equal(parseL2tpExecutionEnabled('true'), true);

    for (const value of ['', 'TRUE', 'False', '1', '0', true, false, null]) {
        assert.throws(
            () => parseL2tpExecutionEnabled(value),
            /L2TP_EXECUTION_ENABLED must be exactly "true" or "false"/,
            String(value),
        );
    }
});

test('disabled default starts no execution services and creates no worker timer', async () => {
    const executionState = { writes: 0 };
    const timer = {
        schedules: 0,
        setInterval() {
            this.schedules += 1;
            return {};
        },
        clearInterval() {},
    };
    let dependencyConstructions = 0;

    const lifecycle = createL2tpRuntimeLifecycleHook({
        env: {},
        createHostDependencies() {
            dependencyConstructions += 1;
            executionState.writes += 1;
            return {
                workerLifecycle: { timer },
            };
        },
    });

    assert.equal(dependencyConstructions, 0);
    assert.deepEqual(executionState, { writes: 0 });
    assert.equal(timer.schedules, 0);
    assert.deepEqual(lifecycle.start(), {
        enabled: false,
        started: false,
        running: false,
        stopped: false,
    });
    await lifecycle.stop();
    assert.equal(dependencyConstructions, 0);
    assert.deepEqual(executionState, { writes: 0 });
    assert.equal(timer.schedules, 0);
});

test('enabled mode requires explicit candidate and preflight factories before lifecycle creation', () => {
    let lifecycleCreations = 0;
    const createStartupLifecycle = () => {
        lifecycleCreations += 1;
        return { start() {}, async stop() {} };
    };

    assert.throws(
        () => createL2tpRuntimeLifecycleHook({
            env: { L2TP_EXECUTION_ENABLED: 'true' },
            createStartupLifecycle,
        }),
        /requires createHostDependencies/,
    );
    assert.throws(
        () => createL2tpRuntimeLifecycleHook({
            env: { L2TP_EXECUTION_ENABLED: 'true' },
            createHostDependencies: () => ({}),
            createStartupLifecycle,
        }),
        /requires explicit createCandidateService/,
    );
    assert.throws(
        () => createL2tpRuntimeLifecycleHook({
            env: { L2TP_EXECUTION_ENABLED: 'true' },
            createHostDependencies: () => ({ createCandidateService() {} }),
            createStartupLifecycle,
        }),
        /requires explicit createPreflightRunner/,
    );
    assert.equal(lifecycleCreations, 0);
});

test('enabled mode forwards factory dependencies and starts the lifecycle once', () => {
    const calls = [];
    const createCandidateService = () => ({ buildCandidate() {} });
    const createPreflightRunner = () => async () => ({ ok: true, checks: [] });
    const createUserSnapshotResolver = () => async () => ({ credentialRevision: 1, users: [] });
    const createUserSyncReconciler = () => ({ async finalizeVerifiedSync() { return { ok: true }; } });
    const hostDependencies = {
        createCandidateService,
        createPreflightRunner,
        createUserSnapshotResolver,
        createUserSyncReconciler,
        marker: 'explicit-host-dependencies',
    };
    const lifecycle = {
        start() {
            calls.push('start');
        },
        async stop() {},
    };
    const activeHostProvider = { marker: 'root-active-host-provider' };

    const result = createL2tpRuntimeLifecycleHook({
        env: { L2TP_EXECUTION_ENABLED: 'true' },
        activeHostProvider,
        createHostDependencies() {
            calls.push('dependencies');
            return hostDependencies;
        },
        createStartupLifecycle(options) {
            calls.push({ kind: 'lifecycle', options });
            return lifecycle;
        },
    });

    assert.strictEqual(result, lifecycle);
    assert.deepEqual(calls, [
        'dependencies',
        {
            kind: 'lifecycle',
            options: {
                config: { enabled: true },
                hostDependencies,
                activeHostProvider,
            },
        },
        'start',
    ]);
});

test('enabled runtime lifecycle passes the exact opt-in environment to lazy host creation', () => {
    let receivedOptions;
    const env = { ...ENABLED_ENV };
    const lifecycle = { start() {}, async stop() {} };

    createL2tpRuntimeLifecycleHook({
        env,
        createHostDependencies(options) {
            receivedOptions = options;
            return {
                createCandidateService() {},
                createPreflightRunner() {},
                createUserSnapshotResolver() {},
                createUserSyncReconciler() {},
            };
        },
        createStartupLifecycle() {
            return lifecycle;
        },
    });

    assert.deepEqual(receivedOptions, { env });
});

test('root lifecycle awaits migrations once after the database boundary before runtime startup', async () => {
    const calls = [];
    const lifecycle = {
        async stop() {
            calls.push('stop');
            return { stopped: true };
        },
    };
    const rootLifecycle = createL2tpRootLifecycle({
        env: { L2TP_EXECUTION_ENABLED: 'false' },
        createMigrationBootstrap(options) {
            calls.push({ kind: 'createMigrationBootstrap', options });
            return {
                async run() {
                    calls.push('migrate');
                    return {
                        enabled: false,
                        ran: false,
                        steps: [],
                        appliedMigrationIds: [],
                        skippedMigrationIds: [],
                    };
                },
            };
        },
        createHostDependencies() {
            throw new Error('disabled root lifecycle must not construct dependencies');
        },
        createRuntimeLifecycleHook(options) {
            calls.push({ kind: 'create', options });
            return lifecycle;
        },
    });

    assert.deepEqual(calls, []);
    const firstStart = rootLifecycle.startAfterDatabase();
    const secondStart = rootLifecycle.startAfterDatabase();
    assert.strictEqual(firstStart, secondStart);
    assert.strictEqual(await firstStart, lifecycle);
    assert.strictEqual(await secondStart, lifecycle);
    assert.equal(calls.length, 3);
    assert.equal(calls[0].kind, 'createMigrationBootstrap');
    assert.deepEqual(calls[0].options.env, { L2TP_EXECUTION_ENABLED: 'false' });
    assert.equal(calls[1], 'migrate');
    assert.equal(calls[2].kind, 'create');
    assert.deepEqual(calls[2].options.env, { L2TP_EXECUTION_ENABLED: 'false' });
    assert.equal(typeof calls[2].options.createHostDependencies, 'function');

    const firstStop = rootLifecycle.stop();
    const secondStop = rootLifecycle.stop();
    assert.strictEqual(firstStop, secondStop);
    assert.deepEqual(await firstStop, { stopped: true });
    assert.deepEqual(await secondStop, { stopped: true });
    assert.deepEqual(
        calls.map(call => call.kind ?? call),
        ['createMigrationBootstrap', 'migrate', 'create', 'stop'],
    );
});

test('application startup awaits the post-database L2TP lifecycle boundary', () => {
    const rootEntrySource = fs.readFileSync(path.resolve(__dirname, '../../../index.js'), 'utf8');

    assert.match(
        rootEntrySource,
        /await\s+l2tpRootLifecycle\.startAfterDatabase\(\);/,
    );
});

test('enabled migration failure blocks runtime creation, worker start, and active host publication', async () => {
    const migrationError = new Error('module migration failed');
    let migrationRuns = 0;
    let lifecycleCreations = 0;
    let workerStarts = 0;
    let activeHost = null;
    const activeHostProvider = {
        installActiveHost(host) {
            activeHost = host;
        },
        getActiveHost() {
            return activeHost;
        },
    };
    const rootLifecycle = createL2tpRootLifecycle({
        env: {
            L2TP_EXECUTION_ENABLED: 'true',
            L2TP_MIGRATIONS_ENABLED: 'true',
        },
        activeHostProvider,
        createMigrationBootstrap() {
            return {
                async run() {
                    migrationRuns += 1;
                    throw migrationError;
                },
            };
        },
        createHostDependencies() {
            workerStarts += 1;
            return {};
        },
        createRuntimeLifecycleHook() {
            lifecycleCreations += 1;
            workerStarts += 1;
            activeHostProvider.installActiveHost({ active: true });
            return { async stop() {} };
        },
    });

    const firstStart = rootLifecycle.startAfterDatabase();
    const secondStart = rootLifecycle.startAfterDatabase();
    assert.strictEqual(firstStart, secondStart);
    await assert.rejects(firstStart, error => error === migrationError);
    await assert.rejects(secondStart, error => error === migrationError);

    assert.equal(migrationRuns, 1);
    assert.equal(lifecycleCreations, 0);
    assert.equal(workerStarts, 0);
    assert.equal(activeHostProvider.getActiveHost(), null);
    assert.equal(await rootLifecycle.stop(), undefined);
});

test('root lifecycle propagates invalid enable configuration before creating dependencies', async () => {
    let dependencyConstructions = 0;
    const rootLifecycle = createL2tpRootLifecycle({
        env: { L2TP_EXECUTION_ENABLED: 'yes' },
        createHostDependencies() {
            dependencyConstructions += 1;
            return {};
        },
    });

    await assert.rejects(
        rootLifecycle.startAfterDatabase(),
        /L2TP_EXECUTION_ENABLED must be exactly "true" or "false"/,
    );
    assert.equal(dependencyConstructions, 0);
});

test('root host dependencies provide the exact safe candidate composition required by enabled startup', async () => {
    const env = { ...ENABLED_ENV };
    const candidateConstructions = [];
    const nodeQueries = [];
    class FakeCandidateService {
        constructor(dependencies) {
            candidateConstructions.push(dependencies);
        }

        async buildCandidate() {}
    }
    const createPreflightRunner = () => async () => ({ ok: true, checks: [] });
    const configGenerator = require('../../services/configGenerator').generateXrayConfig;
    const fragmentProvider = require('../relay-l2tp/services/l2tpXrayFragmentProvider')
        .buildL2tpXrayFragment;
    const node = { _id: 'node-a', groups: [] };
    const users = [{ userId: 'user-a' }];
    const candidateUserResolver = async resolvedNode => {
        assert.strictEqual(resolvedNode, node);
        return users;
    };
    const timer = { setInterval() {}, clearInterval() {} };
    const lifecycleLogger = { error() {} };
    const middleware = () => {};
    const HyNode = {
        findById(nodeId) {
            nodeQueries.push({ method: 'findById', nodeId });
            return {
                select(projection) {
                    nodeQueries.push({ method: 'select', projection });
                    return this;
                },
                async lean() {
                    nodeQueries.push({ method: 'lean' });
                    return node;
                },
            };
        },
    };

    const dependencies = createL2tpRootHostDependencies({
        env,
        HyNode,
        NodeSSH: class FakeNodeSSH {},
        NodeTransport: class FakeNodeTransport {},
        L2tpXrayCandidateService: FakeCandidateService,
        createPreflightRunner,
        operationMaterializer: async () => ({}),
        secretBox: { encrypt() {}, decrypt() {} },
        secretKey: 'root-secret-key',
        syncService: null,
        candidateUserResolver,
        requireAuth: middleware,
        requireOnboarding: middleware,
        csrf: middleware,
        rateLimiter: middleware,
        renderPage: middleware,
        clock: { now: () => new Date('2026-09-22T12:00:00.000Z') },
        workerId: 'root-worker',
        leaseMs: 30_000,
        intervalMs: 15_000,
        timer,
        logger: lifecycleLogger,
    });

    assert.strictEqual(dependencies.env, env);
    assert.strictEqual(dependencies.createPreflightRunner, createPreflightRunner);
    assert.strictEqual(dependencies.candidateUserResolver, candidateUserResolver);
    assert.strictEqual(dependencies.configGenerator, configGenerator);
    assert.strictEqual(dependencies.fragmentProvider, fragmentProvider);
    assert.equal(dependencies.enableTopologyHealthProvider, true);
    assert.equal(dependencies.topologyHealthMaxStalenessMs, DEFAULT_MAX_STALENESS_MS);
    assert.equal(typeof dependencies.candidateNodeResolver, 'function');

    assert.strictEqual(
        await dependencies.candidateNodeResolver({ nodeId: 'node-a' }),
        node,
    );
    assert.equal(nodeQueries[0].method, 'findById');
    assert.equal(nodeQueries[0].nodeId, 'node-a');
    assert.equal(nodeQueries[1].method, 'select');
    assert.match(nodeQueries[1].projection, /(?:^|\s)xray\.transport(?:\s|$)/);
    assert.match(nodeQueries[1].projection, /(?:^|\s)groups(?:\s|$)/);
    assert.doesNotMatch(nodeQueries[1].projection, /(?:^|\s)ssh(?:\.|\s|$)/);
    assert.deepEqual(nodeQueries[2], { method: 'lean' });

    const candidateService = dependencies.createCandidateService({
        nodeResolver: dependencies.candidateNodeResolver,
        userResolver: dependencies.candidateUserResolver,
        configGenerator: dependencies.configGenerator,
        fragmentProvider: dependencies.fragmentProvider,
    });
    assert.ok(candidateService instanceof FakeCandidateService);
    assert.deepEqual(candidateConstructions, [{
        configGenerator,
        userResolver: candidateUserResolver,
        nodeResolver: dependencies.candidateNodeResolver,
        fragmentProvider,
    }]);
    assert.deepEqual(await candidateConstructions[0].userResolver(node), users);
    assert.deepEqual(dependencies.workerLifecycle, {
        intervalMs: 15_000,
        timer,
        logger: lifecycleLogger,
    });
    assert.equal(Object.hasOwn(dependencies.workerLifecycle, 'enabled'), false);
});

test('enabled root composition selects only a current healthy downstream path', async () => {
    const now = new Date('2026-09-22T12:00:00.000Z');
    const maxStalenessMs = 30_000;
    const nodes = [
        {
            _id: 'portal-1',
            type: 'xray',
            active: true,
            cascadeRole: 'portal',
            status: 'online',
            agentStatus: 'online',
            agentLastSeen: now,
        },
        {
            _id: 'relay-1',
            type: 'xray',
            active: true,
            cascadeRole: 'relay',
            status: 'online',
            agentStatus: 'online',
            agentLastSeen: now,
        },
        {
            _id: 'bridge-1',
            type: 'xray',
            active: true,
            cascadeRole: 'bridge',
            status: 'online',
            agentStatus: 'online',
            agentLastSeen: now,
        },
    ];
    const links = [
        {
            _id: 'entry',
            active: true,
            portalNode: 'portal-1',
            bridgeNode: 'relay-1',
            mode: 'forward',
        },
        {
            _id: 'exit',
            active: true,
            portalNode: 'relay-1',
            bridgeNode: 'bridge-1',
            mode: 'forward',
        },
    ];
    const groups = [{
        _id: 'group-a',
        mode: 'forward',
        strategy: 'priority-failover',
        paths: [{ pathKey: 'primary', linkIds: ['entry', 'exit'], priority: 10 }],
    }];
    const createReadModel = rows => ({
        find() {
            return {
                select() { return this; },
                lean() { return Promise.resolve(rows); },
            };
        },
    });
    const HyNode = {
        ...createReadModel(nodes),
        findById() {
            throw new Error('candidate lookup must not run during topology health evaluation');
        },
    };
    const CascadeLink = createReadModel(links);
    const CascadeRouteGroup = createReadModel(groups);
    const middleware = () => {};
    const rootDependencies = createL2tpRootHostDependencies({
        HyNode,
        NodeSSH: class ForbiddenNodeSSH {
            constructor() {
                throw new Error('topology health must not open SSH connections');
            }
        },
        NodeTransport: class ForbiddenNodeTransport {
            constructor() {
                throw new Error('topology health must not construct remote transports');
            }
        },
        L2tpXrayCandidateService: class FakeCandidateService {},
        createPreflightRunner: () => async () => ({ ok: true, checks: [] }),
        operationMaterializer: async () => ({}),
        secretBox: { encrypt() {}, decrypt() {} },
        secretKey: 'root-secret-key',
        syncService: null,
        candidateUserResolver: async () => [],
        requireAuth: middleware,
        requireOnboarding: middleware,
        csrf: middleware,
        rateLimiter: middleware,
        renderPage: middleware,
        clock: { now: () => now },
        topologyHealthMaxStalenessMs: maxStalenessMs,
        timer: { setInterval() {}, clearInterval() {} },
        logger: { error() {} },
    });

    assert.equal(rootDependencies.enableTopologyHealthProvider, true);
    assert.equal(rootDependencies.topologyHealthMaxStalenessMs, maxStalenessMs);

    const host = createL2tpPanelHost({
        ...rootDependencies,
        CascadeLink,
        moduleEntry: {
            registerModels: () => ({
                RelayL2tpState: {},
                CascadeRouteGroup,
                CascadeTopologyState: {},
                L2tpOperation: {},
                L2tpUser: {},
                NodeOperationLock: {},
            }),
        },
        Repository: class FakeRepository {},
        createRepositoryAdapters: () => ({
            nodeRepository: {},
            stateRepository: {},
            operationRepository: {},
        }),
        createPanelOverviewLoader: () => async () => ({}),
        createExecutionRuntime: () => ({
            runtime: { stateManagementService: {} },
            start() {},
            async stop() {},
        }),
    });

    assert.equal(host.topologyRuntime.healthSource.maxStalenessMs, maxStalenessMs);
    assert.deepEqual(
        (await host.topologyRuntime.getRelayGroupPlan('relay-1', 'group-a')).decision,
        {
            decision: 'select',
            groupId: 'group-a',
            pathKey: 'primary',
            nextHopNodeId: 'bridge-1',
        },
    );

    nodes[2].agentLastSeen = new Date(now.getTime() - maxStalenessMs - 1);
    assert.deepEqual(
        (await host.topologyRuntime.getRelayGroupPlan('relay-1', 'group-a')).decision,
        { decision: 'block', error: { code: 'NO_HEALTHY_PATH' } },
    );

    nodes[2].agentLastSeen = now;
    nodes[2].agentStatus = 'unknown';
    assert.deepEqual(
        (await host.topologyRuntime.getRelayGroupPlan('relay-1', 'group-a')).decision,
        { decision: 'block', error: { code: 'NO_HEALTHY_PATH' } },
    );
});

test('root default candidate user resolver returns only fields required by Xray generation', async () => {
    const middleware = () => {};
    const users = [{
        _id: 'database-id',
        userId: 'user-a',
        xrayUuid: '00000000-0000-4000-8000-000000000001',
        password: 'must-not-reach-candidate-generation',
        subscriptionToken: 'must-not-reach-candidate-generation',
    }];
    const dependencies = createL2tpRootHostDependencies({
        HyNode: { findById() {} },
        NodeSSH: class FakeNodeSSH {},
        NodeTransport: class FakeNodeTransport {},
        L2tpXrayCandidateService: class FakeCandidateService {},
        createPreflightRunner: () => async () => ({ ok: true, checks: [] }),
        operationMaterializer: async () => ({}),
        secretBox: { encrypt() {}, decrypt() {} },
        secretKey: 'root-secret-key',
        syncService: {
            async _getUsersForNode() {
                return users;
            },
        },
        requireAuth: middleware,
        requireOnboarding: middleware,
        csrf: middleware,
        rateLimiter: middleware,
        renderPage: middleware,
        timer: { setInterval() {}, clearInterval() {} },
        logger: { error() {} },
    });

    const resolved = await dependencies.candidateUserResolver({ _id: 'node-a' });
    assert.deepEqual(resolved, [{
        userId: 'user-a',
        xrayUuid: '00000000-0000-4000-8000-000000000001',
    }]);
    assert.doesNotMatch(
        JSON.stringify(resolved),
        /database-id|must-not-reach-candidate-generation/,
    );
});
