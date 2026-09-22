'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    createL2tpRootHostDependencies,
    createL2tpRootLifecycle,
    createL2tpRuntimeLifecycleHook,
    parseL2tpExecutionEnabled,
} = require('../l2tpRuntimeLifecycleHook');

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
    const hostDependencies = {
        createCandidateService,
        createPreflightRunner,
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

test('root lifecycle starts only after the database boundary and stops its retained handle once', async () => {
    const calls = [];
    const lifecycle = {
        async stop() {
            calls.push('stop');
            return { stopped: true };
        },
    };
    const rootLifecycle = createL2tpRootLifecycle({
        env: { L2TP_EXECUTION_ENABLED: 'false' },
        createHostDependencies() {
            throw new Error('disabled root lifecycle must not construct dependencies');
        },
        createRuntimeLifecycleHook(options) {
            calls.push({ kind: 'create', options });
            return lifecycle;
        },
    });

    assert.deepEqual(calls, []);
    assert.strictEqual(rootLifecycle.startAfterDatabase(), lifecycle);
    assert.strictEqual(rootLifecycle.startAfterDatabase(), lifecycle);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].kind, 'create');
    assert.deepEqual(calls[0].options.env, { L2TP_EXECUTION_ENABLED: 'false' });
    assert.equal(typeof calls[0].options.createHostDependencies, 'function');

    const firstStop = rootLifecycle.stop();
    const secondStop = rootLifecycle.stop();
    assert.strictEqual(firstStop, secondStop);
    assert.deepEqual(await firstStop, { stopped: true });
    assert.deepEqual(await secondStop, { stopped: true });
    assert.deepEqual(calls.map(call => call.kind ?? call), ['create', 'stop']);
});

test('root lifecycle propagates invalid enable configuration before creating dependencies', () => {
    let dependencyConstructions = 0;
    const rootLifecycle = createL2tpRootLifecycle({
        env: { L2TP_EXECUTION_ENABLED: 'yes' },
        createHostDependencies() {
            dependencyConstructions += 1;
            return {};
        },
    });

    assert.throws(
        () => rootLifecycle.startAfterDatabase(),
        /L2TP_EXECUTION_ENABLED must be exactly "true" or "false"/,
    );
    assert.equal(dependencyConstructions, 0);
});

test('root host dependencies provide the exact safe candidate composition required by enabled startup', async () => {
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

    assert.strictEqual(dependencies.createPreflightRunner, createPreflightRunner);
    assert.strictEqual(dependencies.candidateUserResolver, candidateUserResolver);
    assert.strictEqual(dependencies.configGenerator, configGenerator);
    assert.strictEqual(dependencies.fragmentProvider, fragmentProvider);
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
