'use strict';

const {
    isTopologyTestExecutionEnabled,
} = require('./createTopologyOperationRuntime');

const DEFAULT_CLOCK = Object.freeze({ now: () => new Date() });
const DEFAULT_INTERVAL_MS = 30_000;
const DEFAULT_SCAN_LIMIT = 25;
const MAX_SCAN_LIMIT = 100;

function dormantState() {
    return {
        enabled: false,
        running: false,
        inFlight: false,
    };
}

function createDormantLifecycle() {
    return Object.freeze({
        start: dormantState,
        async stop() {
            return dormantState();
        },
    });
}

function recoveryFilter(now) {
    return {
        $or: [
            { status: 'queued' },
            {
                status: 'preparing',
                leaseUntil: { $lte: now },
                nodes: {
                    $not: {
                        $elemMatch: {
                            $or: [
                                { state: { $ne: 'pending' } },
                                { backupId: { $ne: '' } },
                            ],
                        },
                    },
                },
            },
        ],
    };
}

function isRecoveryCandidate(operation, now) {
    if (operation?.status === 'queued') return true;
    return operation?.status === 'preparing'
        && operation.leaseUntil instanceof Date
        && operation.leaseUntil <= now
        && Array.isArray(operation.nodes)
        && operation.nodes.every(node => node?.state === 'pending' && node?.backupId === '');
}

function createTopologyOperationRecoveryLifecycle(options = {}) {
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
        return createDormantLifecycle();
    }
    const env = options.env === undefined ? process.env : options.env;
    if (!isTopologyTestExecutionEnabled(env)) return createDormantLifecycle();

    const {
        operationModel,
        worker,
        clock = DEFAULT_CLOCK,
        intervalMs = DEFAULT_INTERVAL_MS,
        scanLimit = DEFAULT_SCAN_LIMIT,
        timer = globalThis,
        logger = { error() {} },
    } = options;
    if (!operationModel || typeof operationModel.find !== 'function') {
        throw new TypeError('Topology recovery lifecycle requires operationModel.find');
    }
    if (!worker || typeof worker.run !== 'function') {
        throw new TypeError('Topology recovery lifecycle requires worker.run');
    }
    if (!clock || typeof clock.now !== 'function') {
        throw new TypeError('Topology recovery lifecycle requires clock.now');
    }
    if (!Number.isSafeInteger(intervalMs) || intervalMs <= 0) {
        throw new TypeError('Topology recovery lifecycle intervalMs must be a positive integer');
    }
    if (!Number.isSafeInteger(scanLimit) || scanLimit <= 0 || scanLimit > MAX_SCAN_LIMIT) {
        throw new TypeError(`Topology recovery lifecycle scanLimit must be between 1 and ${MAX_SCAN_LIMIT}`);
    }
    if (!timer || typeof timer.setInterval !== 'function'
        || typeof timer.clearInterval !== 'function') {
        throw new TypeError('Topology recovery lifecycle requires timer setInterval/clearInterval functions');
    }
    if (!logger || typeof logger.error !== 'function') {
        throw new TypeError('Topology recovery lifecycle requires logger.error');
    }

    let schedule = null;
    let inFlight = null;
    let stopped = false;

    function state() {
        return {
            enabled: true,
            running: schedule !== null,
            inFlight: inFlight !== null,
        };
    }

    function logFailure(code) {
        try {
            logger.error('Topology operation recovery failed', { code });
        } catch {
            // Logger failures must not escape lifecycle supervision.
        }
    }

    async function scan() {
        const now = clock.now();
        const operations = await operationModel.find(recoveryFilter(now))
            .select('_id status leaseOwner leaseUntil nodes.state nodes.backupId')
            .sort({ createdAt: 1, _id: 1 })
            .limit(scanLimit)
            .lean();
        if (!Array.isArray(operations)) {
            throw new TypeError('Topology recovery scan must return an array');
        }

        const seen = new Set();
        for (const operation of operations) {
            if (!isRecoveryCandidate(operation, now)) continue;
            const operationId = operation?._id === null || operation?._id === undefined
                ? ''
                : String(operation._id);
            if (operationId.length === 0 || seen.has(operationId)) continue;
            seen.add(operationId);
            try {
                await worker.run(operationId);
            } catch {
                logFailure('TOPOLOGY_OPERATION_RECOVERY_RUN_FAILED');
            }
        }
    }

    function runTick() {
        if (schedule === null || inFlight !== null) return Promise.resolve();
        const run = Promise.resolve().then(scan);
        inFlight = run.catch(() => {
            logFailure('TOPOLOGY_OPERATION_RECOVERY_SCAN_FAILED');
        }).finally(() => {
            inFlight = null;
        });
        return inFlight;
    }

    return {
        start() {
            if (!stopped && schedule === null) {
                schedule = timer.setInterval(runTick, intervalMs);
                runTick();
            }
            return state();
        },
        async stop() {
            stopped = true;
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
    DEFAULT_INTERVAL_MS,
    DEFAULT_SCAN_LIMIT,
    MAX_SCAN_LIMIT,
    createTopologyOperationRecoveryLifecycle,
    recoveryFilter,
};
