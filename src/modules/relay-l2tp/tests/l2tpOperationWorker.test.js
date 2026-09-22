'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { L2tpOperationWorker } = require('../workers/l2tpOperationWorker');

const NOW = new Date('2026-09-22T10:00:00.000Z');

function createOperationRepository(initialOperations = []) {
    const operations = initialOperations.map(operation => ({ ...operation }));
    const calls = [];

    return {
        calls,
        operations,
        async claimNext(request) {
            calls.push({ method: 'claimNext', request });
            const operation = operations.find(candidate => candidate.status === 'queued');
            if (!operation) return null;

            operation.status = 'running';
            operation.leaseOwner = request.owner;
            return operation;
        },
        async renewLease(request) {
            calls.push({ method: 'renewLease', request });
            return true;
        },
        async recordStep(request) {
            calls.push({ method: 'recordStep', request });
        },
        async setStatus(request) {
            calls.push({ method: 'setStatus', request });
            const operation = operations.find(candidate => candidate.id === request.operationId);
            if (operation) operation.status = request.status;
        },
    };
}

function createDeferred() {
    let resolve;
    let reject;
    const promise = new Promise((resolvePromise, rejectPromise) => {
        resolve = resolvePromise;
        reject = rejectPromise;
    });
    return { promise, resolve, reject };
}

function createClock(initial = NOW) {
    let current = new Date(initial);
    return {
        now: () => new Date(current),
        advance(ms) {
            current = new Date(current.getTime() + ms);
        },
    };
}

function createTimer() {
    let nextId = 1;
    const intervals = new Map();
    const calls = [];

    return {
        calls,
        setInterval(callback, intervalMs) {
            const id = nextId++;
            calls.push({ method: 'setInterval', id, intervalMs });
            intervals.set(id, callback);
            return id;
        },
        clearInterval(id) {
            calls.push({ method: 'clearInterval', id });
            intervals.delete(id);
        },
        async tick() {
            const callbacks = [...intervals.values()];
            await Promise.all(callbacks.map(callback => callback()));
        },
        activeCount() {
            return intervals.size;
        },
    };
}

function createWorker(operationRepository, overrides = {}) {
    const lockService = {
        async renew() { return { ok: true }; },
        ...(overrides.lockService || {}),
    };

    return new L2tpOperationWorker({
        operationRepository,
        lockService,
        executor: overrides.executor || {},
        workerId: 'worker-1',
        leaseMs: overrides.leaseMs || 30_000,
        clock: overrides.clock || createClock(),
        timer: overrides.timer || createTimer(),
        renewalIntervalMs: overrides.renewalIntervalMs,
    });
}

test('runOnce reports idle when no queued operation can be claimed', async () => {
    const operationRepository = createOperationRepository();
    const worker = createWorker(operationRepository);

    const result = await worker.runOnce();

    assert.deepEqual(result, { claimed: false });
    assert.deepEqual(operationRepository.calls, [{
        method: 'claimNext',
        request: {
            owner: 'worker-1',
            leaseMs: 30_000,
            now: NOW,
        },
    }]);
});

test('runOnce refuses to succeed a plan without a verify step', async () => {
    const executed = [];
    const operationRepository = createOperationRepository([{
        id: 'operation-without-verify',
        node: 'node-3',
        status: 'queued',
        plan: { steps: [{ type: 'preflight' }, { type: 'commit' }] },
    }]);
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep({ step }) { executed.push(step.type); },
        },
    });

    const result = await worker.runOnce();

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-without-verify',
        status: 'failed',
    });
    assert.deepEqual(executed, []);
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'setStatus'),
        [{
            method: 'setStatus',
            request: {
                operationId: 'operation-without-verify',
                status: 'failed',
                progress: 0,
                errorCode: 'VERIFY_STEP_REQUIRED',
                errorMessage: 'L2TP operation plan must include a verify step',
                finishedAt: NOW,
                journal: {
                    at: NOW,
                    level: 'error',
                    code: 'VERIFY_STEP_REQUIRED',
                    message: 'L2TP operation plan must include a verify step',
                },
            },
        }],
    );
});

test('runOnce journals ordered step progress as the plan executes', async () => {
    const executed = [];
    const operationRepository = createOperationRepository([{
        id: 'operation-2',
        node: 'node-2',
        status: 'queued',
        plan: {
            steps: [
                { type: 'preflight' },
                { type: 'verify' },
                { type: 'commit' },
            ],
        },
    }]);
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep({ step }) {
                executed.push(step.type);
            },
        },
    });

    await worker.runOnce();

    assert.deepEqual(executed, ['preflight', 'verify', 'commit']);
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'recordStep'),
        [
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'preflight',
                    progress: 0,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_STARTED',
                        message: 'Started L2TP operation step: preflight',
                    },
                },
            },
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'preflight',
                    progress: 33,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_SUCCEEDED',
                        message: 'Completed L2TP operation step: preflight',
                    },
                },
            },
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'verify',
                    progress: 33,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_STARTED',
                        message: 'Started L2TP operation step: verify',
                    },
                },
            },
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'verify',
                    progress: 67,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_SUCCEEDED',
                        message: 'Completed L2TP operation step: verify',
                    },
                },
            },
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'commit',
                    progress: 67,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_STARTED',
                        message: 'Started L2TP operation step: commit',
                    },
                },
            },
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'commit',
                    progress: 100,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_SUCCEEDED',
                        message: 'Completed L2TP operation step: commit',
                    },
                },
            },
        ],
    );
});

test('renews operation and node leases while a step runs longer than the lease', async () => {
    const clock = createClock();
    const timer = createTimer();
    const step = createDeferred();
    const started = createDeferred();
    const lockRenewals = [];
    const operationRepository = createOperationRepository([{
        id: 'operation-long-step',
        node: 'node-long-step',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    const worker = createWorker(operationRepository, {
        clock,
        timer,
        lockService: {
            async acquire() { return { ok: true }; },
            async renew(request) {
                lockRenewals.push(request);
                return { ok: true };
            },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep() {
                started.resolve();
                await step.promise;
            },
        },
    });

    const run = worker.runOnce();
    await started.promise;

    for (const elapsedMs of [10_000, 10_000, 11_000]) {
        clock.advance(elapsedMs);
        await timer.tick();
    }
    step.resolve();

    const result = await run;
    const operationRenewals = operationRepository.calls
        .filter(call => call.method === 'renewLease')
        .map(call => call.request);

    assert.equal(result.status, 'succeeded');
    assert.deepEqual(
        operationRenewals.map(request => request.now),
        [
            NOW,
            new Date('2026-09-22T10:00:10.000Z'),
            new Date('2026-09-22T10:00:20.000Z'),
            new Date('2026-09-22T10:00:31.000Z'),
        ],
    );
    assert.equal(lockRenewals.length, 4);
    assert.ok(timer.calls[0].intervalMs < 30_000);
    assert.equal(timer.activeCount(), 0);
    assert.equal(timer.calls.filter(call => call.method === 'clearInterval').length, 1);
});

test('stops before a second step when operation lease renewal is rejected', async () => {
    const timer = createTimer();
    const step = createDeferred();
    const started = createDeferred();
    const executed = [];
    let renewals = 0;
    let rollbacks = 0;
    const operationRepository = createOperationRepository([{
        id: 'operation-lost-lease',
        node: 'node-lost-lease',
        status: 'queued',
        plan: { steps: [{ type: 'preflight' }, { type: 'verify' }] },
    }]);
    operationRepository.renewLease = async request => {
        operationRepository.calls.push({ method: 'renewLease', request });
        renewals += 1;
        return renewals === 1;
    };
    const worker = createWorker(operationRepository, {
        timer,
        lockService: {
            async acquire() { return { ok: true }; },
            async renew() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep({ step: currentStep }) {
                executed.push(currentStep.type);
                if (currentStep.type === 'preflight') {
                    started.resolve();
                    await step.promise;
                }
            },
            async rollback() { rollbacks += 1; },
        },
    });

    const run = worker.runOnce();
    await started.promise;
    await timer.tick();
    step.resolve();

    const result = await run;

    assert.deepEqual(executed, ['preflight']);
    assert.equal(rollbacks, 0);
    assert.equal(result.status, 'running');
    assert.equal(result.errorCode, 'L2TP_OPERATION_LEASE_LOST');
    assert.equal(
        operationRepository.calls.some(call => call.method === 'setStatus'),
        false,
    );
    assert.equal(timer.activeCount(), 0);
});

test('stops before a second step when node lock renewal rejects', async () => {
    const timer = createTimer();
    const step = createDeferred();
    const started = createDeferred();
    const executed = [];
    let lockRenewals = 0;
    const operationRepository = createOperationRepository([{
        id: 'operation-lock-renew-rejected',
        node: 'node-lock-renew-rejected',
        status: 'queued',
        plan: { steps: [{ type: 'preflight' }, { type: 'verify' }] },
    }]);
    const worker = createWorker(operationRepository, {
        timer,
        lockService: {
            async acquire() { return { ok: true }; },
            async renew() {
                lockRenewals += 1;
                if (lockRenewals > 1) throw new Error('lock store unavailable');
                return { ok: true };
            },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep({ step: currentStep }) {
                executed.push(currentStep.type);
                if (currentStep.type === 'preflight') {
                    started.resolve();
                    await step.promise;
                }
            },
        },
    });

    const run = worker.runOnce();
    await started.promise;
    await timer.tick();
    step.resolve();

    const result = await run;

    assert.deepEqual(executed, ['preflight']);
    assert.equal(result.status, 'running');
    assert.equal(result.errorCode, 'L2TP_LEASE_RENEWAL_FAILED');
    assert.equal(timer.activeCount(), 0);
});

test('does not overlap lease renewal calls when a renewal is still pending', async () => {
    const timer = createTimer();
    const step = createDeferred();
    const stepStarted = createDeferred();
    const renewal = createDeferred();
    const renewalStarted = createDeferred();
    let renewals = 0;
    let activeRenewals = 0;
    let maxActiveRenewals = 0;
    const operationRepository = createOperationRepository([{
        id: 'operation-slow-renewal',
        node: 'node-slow-renewal',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    operationRepository.renewLease = async request => {
        operationRepository.calls.push({ method: 'renewLease', request });
        renewals += 1;
        if (renewals === 1) return true;

        activeRenewals += 1;
        maxActiveRenewals = Math.max(maxActiveRenewals, activeRenewals);
        renewalStarted.resolve();
        await renewal.promise;
        activeRenewals -= 1;
        return true;
    };
    const worker = createWorker(operationRepository, {
        timer,
        lockService: {
            async acquire() { return { ok: true }; },
            async renew() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep() {
                stepStarted.resolve();
                await step.promise;
            },
        },
    });

    const run = worker.runOnce();
    await stepStarted.promise;
    const firstTick = timer.tick();
    await renewalStarted.promise;
    const secondTick = timer.tick();

    assert.equal(renewals, 2);
    assert.equal(maxActiveRenewals, 1);

    renewal.resolve();
    await Promise.all([firstTick, secondTick]);
    step.resolve();
    const result = await run;

    assert.equal(result.status, 'succeeded');
    assert.equal(renewals, 2);
    assert.equal(maxActiveRenewals, 1);
    assert.equal(timer.activeCount(), 0);
});

test('executor failure enters rolling back before rollback and finishes rolled back', async () => {
    const events = [];
    const operationRepository = createOperationRepository([{
        id: 'operation-rollback',
        node: 'node-rollback',
        status: 'queued',
        plan: {
            steps: [
                { type: 'backup' },
                { type: 'start_l2tp' },
                { type: 'verify' },
            ],
        },
    }]);
    const setStatus = operationRepository.setStatus;
    operationRepository.setStatus = async request => {
        events.push({ method: 'setStatus', status: request.status });
        return setStatus(request);
    };
    const executionError = Object.assign(new Error('start failed'), { code: 'START_FAILED' });
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep({ step }) {
                events.push({ method: 'executeStep', step: step.type });
                if (step.type === 'start_l2tp') throw executionError;
            },
            async rollback({ completedSteps, failedStep, error }) {
                events.push({
                    method: 'rollback',
                    completedSteps: completedSteps.map(step => step.type),
                    failedStep: failedStep.type,
                    error,
                });
            },
        },
    });

    const result = await worker.runOnce();

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-rollback',
        status: 'rolled_back',
    });
    assert.deepEqual(events, [
        { method: 'executeStep', step: 'backup' },
        { method: 'executeStep', step: 'start_l2tp' },
        { method: 'setStatus', status: 'rolling_back' },
        {
            method: 'rollback',
            completedSteps: ['backup'],
            failedStep: 'start_l2tp',
            error: executionError,
        },
        { method: 'setStatus', status: 'rolled_back' },
    ]);
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'setStatus'),
        [
            {
                method: 'setStatus',
                request: {
                    operationId: 'operation-rollback',
                    status: 'rolling_back',
                    step: 'start_l2tp',
                    progress: 33,
                    errorCode: 'START_FAILED',
                    errorMessage: 'start failed',
                    journal: {
                        at: NOW,
                        level: 'error',
                        code: 'L2TP_STEP_FAILED',
                        message: 'L2TP operation step failed: start_l2tp',
                    },
                },
            },
            {
                method: 'setStatus',
                request: {
                    operationId: 'operation-rollback',
                    status: 'rolled_back',
                    step: 'start_l2tp',
                    progress: 33,
                    errorCode: 'START_FAILED',
                    errorMessage: 'start failed',
                    finishedAt: NOW,
                    journal: {
                        at: NOW,
                        level: 'warn',
                        code: 'L2TP_OPERATION_ROLLED_BACK',
                        message: 'Rolled back L2TP operation after executor failure',
                    },
                },
            },
        ],
    );
});

test('rollback failure leaves the claimed operation terminally failed', async () => {
    const operationRepository = createOperationRepository([{
        id: 'operation-rollback-failed',
        node: 'node-rollback-failed',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    const executionError = Object.assign(new Error('verify failed'), { code: 'VERIFY_FAILED' });
    const rollbackError = Object.assign(new Error('rollback broke'), { code: 'ROLLBACK_FAILED' });
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep() { throw executionError; },
            async rollback() { throw rollbackError; },
        },
    });

    const result = await worker.runOnce();

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-rollback-failed',
        status: 'failed',
    });
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'setStatus'),
        [
            {
                method: 'setStatus',
                request: {
                    operationId: 'operation-rollback-failed',
                    status: 'rolling_back',
                    step: 'verify',
                    progress: 0,
                    errorCode: 'VERIFY_FAILED',
                    errorMessage: 'verify failed',
                    journal: {
                        at: NOW,
                        level: 'error',
                        code: 'L2TP_STEP_FAILED',
                        message: 'L2TP operation step failed: verify',
                    },
                },
            },
            {
                method: 'setStatus',
                request: {
                    operationId: 'operation-rollback-failed',
                    status: 'failed',
                    step: 'verify',
                    progress: 0,
                    errorCode: 'ROLLBACK_FAILED',
                    errorMessage: 'rollback broke',
                    finishedAt: NOW,
                    journal: {
                        at: NOW,
                        level: 'error',
                        code: 'L2TP_ROLLBACK_FAILED',
                        message: 'Failed to roll back L2TP operation',
                    },
                },
            },
        ],
    );
});

test('lock conflict fails the claimed operation without executing it', async () => {
    const lockCalls = [];
    let executions = 0;
    const operationRepository = createOperationRepository([{
        id: 'operation-lock-conflict',
        node: 'node-locked',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire(request) {
                lockCalls.push({ method: 'acquire', request });
                return { ok: false, error: { code: 'NODE_OPERATION_LOCK_CONFLICT' } };
            },
            async release(request) {
                lockCalls.push({ method: 'release', request });
            },
        },
        executor: {
            async executeStep() { executions += 1; },
        },
    });

    const result = await worker.runOnce();

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-lock-conflict',
        status: 'failed',
    });
    assert.equal(executions, 0);
    assert.deepEqual(lockCalls, [{
        method: 'acquire',
        request: {
            node: 'node-locked',
            owner: 'worker-1',
            operationId: 'operation-lock-conflict',
            leaseMs: 30_000,
        },
    }]);
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'setStatus'),
        [{
            method: 'setStatus',
            request: {
                operationId: 'operation-lock-conflict',
                status: 'failed',
                progress: 0,
                errorCode: 'NODE_OPERATION_LOCK_CONFLICT',
                errorMessage: 'Could not acquire node operation lock',
                finishedAt: NOW,
                journal: {
                    at: NOW,
                    level: 'error',
                    code: 'NODE_OPERATION_LOCK_CONFLICT',
                    message: 'Could not acquire node operation lock',
                },
            },
        }],
    );
});

test('success is persisted only after verify and before releasing the lock', async () => {
    const events = [];
    const operationRepository = createOperationRepository([{
        id: 'operation-success',
        node: 'node-success',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    const setStatus = operationRepository.setStatus;
    operationRepository.setStatus = async request => {
        events.push({ method: 'setStatus', status: request.status });
        return setStatus(request);
    };
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire(request) {
                events.push({ method: 'acquire', request });
                return { ok: true };
            },
            async release(request) {
                events.push({ method: 'release', request });
                return { ok: true };
            },
        },
        executor: {
            async executeStep({ step }) {
                events.push({ method: 'executeStep', step: step.type });
            },
        },
    });

    const result = await worker.runOnce();

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-success',
        status: 'succeeded',
    });
    assert.deepEqual(events, [
        {
            method: 'acquire',
            request: {
                node: 'node-success',
                owner: 'worker-1',
                operationId: 'operation-success',
                leaseMs: 30_000,
            },
        },
        { method: 'executeStep', step: 'verify' },
        { method: 'setStatus', status: 'succeeded' },
        {
            method: 'release',
            request: {
                node: 'node-success',
                owner: 'worker-1',
                operationId: 'operation-success',
            },
        },
    ]);
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'setStatus'),
        [{
            method: 'setStatus',
            request: {
                operationId: 'operation-success',
                status: 'succeeded',
                step: 'verify',
                progress: 100,
                errorCode: '',
                errorMessage: '',
                finishedAt: NOW,
                journal: {
                    at: NOW,
                    level: 'info',
                    code: 'L2TP_OPERATION_SUCCEEDED',
                    message: 'L2TP operation succeeded after verification',
                },
            },
        }],
    );
});

test('does not execute an operation twice after it has been claimed and completed', async () => {
    let executions = 0;
    const operationRepository = createOperationRepository([{
        id: 'operation-duplicate',
        node: 'node-duplicate',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep() { executions += 1; },
        },
    });

    const first = await worker.runOnce();
    const second = await worker.runOnce();

    assert.equal(first.status, 'succeeded');
    assert.deepEqual(second, { claimed: false });
    assert.equal(executions, 1);
});
