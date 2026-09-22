'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { createL2tpWorkerLifecycle } = require('../runtime/createL2tpWorkerLifecycle');

function createFakeTimer() {
    const schedules = [];
    const cleared = [];

    return {
        schedules,
        cleared,
        setInterval(callback, intervalMs) {
            const handle = { callback, intervalMs };
            schedules.push(handle);
            return handle;
        },
        clearInterval(handle) {
            cleared.push(handle);
        },
    };
}

function createLifecycle(overrides = {}) {
    return createL2tpWorkerLifecycle({
        worker: { async runOnce() {} },
        intervalMs: 1_000,
        timer: createFakeTimer(),
        logger: { error() {} },
        ...overrides,
    });
}

test('is disabled by default and start schedules no work', () => {
    const timer = createFakeTimer();
    let runs = 0;
    const lifecycle = createLifecycle({
        worker: { async runOnce() { runs += 1; } },
        timer,
    });

    assert.deepEqual(lifecycle.start(), {
        enabled: false,
        running: false,
        inFlight: false,
    });
    assert.equal(timer.schedules.length, 0);
    assert.equal(runs, 0);
});

test('module import and enabled construction perform no timer or worker work', () => {
    const modulePath = require.resolve('../runtime/createL2tpWorkerLifecycle');
    const originalSetInterval = global.setInterval;
    let schedules = 0;
    let runs = 0;

    global.setInterval = () => {
        schedules += 1;
        return {};
    };
    delete require.cache[modulePath];
    try {
        const { createL2tpWorkerLifecycle: createFreshLifecycle } = require(modulePath);
        createFreshLifecycle({
            enabled: true,
            worker: { async runOnce() { runs += 1; } },
        });
    } finally {
        global.setInterval = originalSetInterval;
    }

    assert.equal(schedules, 0);
    assert.equal(runs, 0);
});

test('rejects non-boolean enablement instead of activating from truthy config', () => {
    for (const enabled of ['true', '1', 1, null]) {
        assert.throws(
            () => createLifecycle({ enabled }),
            /enabled must be a boolean/i,
        );
    }
});

test('rejects invalid polling intervals before scheduling', () => {
    for (const intervalMs of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '1000']) {
        assert.throws(
            () => createLifecycle({ intervalMs }),
            /intervalMs must be a positive integer/i,
        );
    }
});

test('rejects invalid injected lifecycle dependencies before scheduling', () => {
    assert.throws(
        () => createLifecycle({ worker: {} }),
        /worker\.runOnce/i,
    );
    assert.throws(
        () => createLifecycle({ timer: { setInterval() {} } }),
        /timer\.clearInterval/i,
    );
    assert.throws(
        () => createLifecycle({ logger: {} }),
        /logger\.error/i,
    );
});

test('enabled start creates exactly one periodic schedule', () => {
    const timer = createFakeTimer();
    const lifecycle = createLifecycle({ enabled: true, timer });

    assert.deepEqual(lifecycle.start(), {
        enabled: true,
        running: true,
        inFlight: false,
    });
    assert.deepEqual(lifecycle.start(), {
        enabled: true,
        running: true,
        inFlight: false,
    });
    assert.equal(timer.schedules.length, 1);
    assert.equal(timer.schedules[0].intervalMs, 1_000);
});

test('periodic ticks never overlap worker runs', async () => {
    const timer = createFakeTimer();
    const completions = [];
    let runs = 0;
    const lifecycle = createLifecycle({
        enabled: true,
        timer,
        worker: {
            runOnce() {
                runs += 1;
                return new Promise(resolve => completions.push(resolve));
            },
        },
    });

    lifecycle.start();
    const firstTick = timer.schedules[0].callback();
    const skippedTick = timer.schedules[0].callback();
    await Promise.resolve();

    assert.equal(runs, 1);
    await skippedTick;
    completions.shift()();
    await firstTick;

    const nextTick = timer.schedules[0].callback();
    await Promise.resolve();
    assert.equal(runs, 2);
    completions.shift()();
    await nextTick;
});

test('rejected worker runs are handled and logged without sensitive details', async () => {
    const timer = createFakeTimer();
    const logs = [];
    const lifecycle = createLifecycle({
        enabled: true,
        timer,
        worker: {
            async runOnce() {
                throw new Error('private-key-value');
            },
        },
        logger: {
            error(message, context) {
                logs.push({ message, context });
            },
        },
    });

    lifecycle.start();
    await timer.schedules[0].callback();

    assert.deepEqual(logs, [{
        message: 'L2TP worker run failed',
        context: { code: 'L2TP_WORKER_RUN_FAILED' },
    }]);
    assert.doesNotMatch(JSON.stringify(logs), /private-key-value/);
});

test('stop clears the schedule and prevents future work idempotently', async () => {
    const timer = createFakeTimer();
    let runs = 0;
    const lifecycle = createLifecycle({
        enabled: true,
        timer,
        worker: { async runOnce() { runs += 1; } },
    });

    lifecycle.start();
    const scheduledTick = timer.schedules[0].callback;

    assert.deepEqual(await lifecycle.stop(), {
        enabled: true,
        running: false,
        inFlight: false,
    });
    assert.deepEqual(timer.cleared, [timer.schedules[0]]);

    await scheduledTick();
    assert.equal(runs, 0);
    assert.deepEqual(await lifecycle.stop(), {
        enabled: true,
        running: false,
        inFlight: false,
    });
    assert.equal(timer.cleared.length, 1);
});

test('stop waits for an in-flight worker run before resolving', async () => {
    const timer = createFakeTimer();
    let finishRun;
    const lifecycle = createLifecycle({
        enabled: true,
        timer,
        worker: {
            runOnce() {
                return new Promise(resolve => { finishRun = resolve; });
            },
        },
    });

    lifecycle.start();
    timer.schedules[0].callback();
    await Promise.resolve();

    let stopped = false;
    const stopping = lifecycle.stop().then(state => {
        stopped = true;
        return state;
    });
    await Promise.resolve();
    assert.equal(stopped, false);
    assert.equal(timer.cleared.length, 1);

    finishRun();
    assert.deepEqual(await stopping, {
        enabled: true,
        running: false,
        inFlight: false,
    });
});
