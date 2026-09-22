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

    const result = createL2tpRuntimeLifecycleHook({
        env: { L2TP_EXECUTION_ENABLED: 'true' },
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

test('root host dependencies provide explicit preflight and candidate factories', async () => {
    const candidateConstructions = [];
    const userResolverCalls = [];
    class FakeCandidateService {
        constructor(dependencies) {
            candidateConstructions.push(dependencies);
        }

        async buildCandidate() {}
    }
    const createPreflightRunner = () => async () => ({ ok: true, checks: [] });
    const generateXrayConfig = () => '{}';
    const node = { _id: 'node-a' };
    const users = [{ userId: 'user-a' }];
    const timer = { setInterval() {}, clearInterval() {} };
    const lifecycleLogger = { error() {} };
    const middleware = () => {};

    const dependencies = createL2tpRootHostDependencies({
        HyNode: { findById() {} },
        NodeSSH: class FakeNodeSSH {},
        NodeTransport: class FakeNodeTransport {},
        L2tpXrayCandidateService: FakeCandidateService,
        createPreflightRunner,
        operationMaterializer: async () => ({}),
        secretBox: { encrypt() {}, decrypt() {} },
        secretKey: 'root-secret-key',
        syncService: {
            async _getUsersForNode(resolvedNode) {
                userResolverCalls.push(resolvedNode);
                return users;
            },
        },
        generateXrayConfig,
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
    const nodeResolver = async () => node;
    const candidateService = dependencies.createCandidateService({ nodeResolver });
    assert.ok(candidateService instanceof FakeCandidateService);
    assert.deepEqual(candidateConstructions, [{
        configGenerator: generateXrayConfig,
        userResolver: candidateConstructions[0].userResolver,
        nodeResolver,
    }]);
    assert.deepEqual(await candidateConstructions[0].userResolver(node), users);
    assert.deepEqual(userResolverCalls, [node]);
    assert.deepEqual(dependencies.workerLifecycle, {
        intervalMs: 15_000,
        timer,
        logger: lifecycleLogger,
    });
    assert.equal(Object.hasOwn(dependencies.workerLifecycle, 'enabled'), false);
});
