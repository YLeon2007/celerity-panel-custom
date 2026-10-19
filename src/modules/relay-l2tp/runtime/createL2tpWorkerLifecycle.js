'use strict';

function createL2tpWorkerLifecycle({
    enabled = false,
    worker,
    intervalMs = 30_000,
    timer = globalThis,
    logger = { error() {} },
} = {}) {
    if (typeof enabled !== 'boolean') {
        throw new TypeError('L2TP worker lifecycle enabled must be a boolean');
    }
    if (!Number.isSafeInteger(intervalMs) || intervalMs <= 0) {
        throw new TypeError('L2TP worker lifecycle intervalMs must be a positive integer');
    }
    if (!worker || typeof worker.runOnce !== 'function') {
        throw new TypeError('L2TP worker lifecycle requires worker.runOnce');
    }
    if (!timer || typeof timer.setInterval !== 'function') {
        throw new TypeError('L2TP worker lifecycle requires timer.setInterval');
    }
    if (typeof timer.clearInterval !== 'function') {
        throw new TypeError('L2TP worker lifecycle requires timer.clearInterval');
    }
    if (!logger || typeof logger.error !== 'function') {
        throw new TypeError('L2TP worker lifecycle requires logger.error');
    }

    let schedule = null;
    let inFlight = null;
    // Sticky for this process lifetime: an idle/later successful tick cannot
    // attest completion or release ownership retained by an earlier invocation.
    let drainUncertain = false;

    function state() {
        return {
            enabled,
            running: schedule !== null,
            inFlight: inFlight !== null,
            ...(drainUncertain ? { drainUncertain: true } : {}),
        };
    }

    function runTick() {
        if (schedule === null || inFlight !== null) return Promise.resolve();

        const run = Promise.resolve().then(() => worker.runOnce());
        inFlight = run.then(result => {
            if (result?.drainUncertain === true
                || (result?.claimed === true && result.stopped === true)) drainUncertain = true;
        }).catch(() => {
            drainUncertain = true;
            try {
                logger.error('L2TP worker run failed', {
                    code: 'L2TP_WORKER_RUN_FAILED',
                });
            } catch {
                // A logger failure must not escape the supervised timer callback.
            }
        }).finally(() => {
            inFlight = null;
        });
        return inFlight;
    }

    return {
        start() {
            if (enabled && schedule === null) {
                schedule = timer.setInterval(runTick, intervalMs);
            }
            return state();
        },
        async stop() {
            if (schedule !== null) {
                timer.clearInterval(schedule);
                schedule = null;
            }
            const pendingRun = inFlight;
            if (pendingRun !== null) await pendingRun;
            return state();
        },
    };
}

module.exports = {
    createL2tpWorkerLifecycle,
};
