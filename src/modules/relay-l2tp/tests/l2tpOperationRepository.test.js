'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { L2tpOperationRepository } = require('../services/l2tpOperationRepository');

const NOW = new Date('2026-09-22T10:00:00.000Z');

function createModel(result = null) {
    const calls = [];

    return {
        calls,
        async findOneAndUpdate(query, update, options) {
            calls.push({ method: 'findOneAndUpdate', query, update, options });
            return result;
        },
        async updateOne(query, update, options) {
            calls.push({ method: 'updateOne', query, update, options });
            return result;
        },
    };
}

function createCasModel(operation) {
    const calls = [];
    const document = { logs: [], ...operation };

    return {
        calls,
        document,
        async updateOne(query, update, options) {
            calls.push({ method: 'updateOne', query, update, options });
            const matches = query._id === document._id
                && (query.status === undefined || query.status === document.status)
                && (query.leaseOwner === undefined || query.leaseOwner === document.leaseOwner)
                && (
                    query.leaseUntil === undefined
                    || document.leaseUntil > query.leaseUntil.$gt
                );
            if (!matches) {
                return { acknowledged: true, matchedCount: 0, modifiedCount: 0 };
            }

            Object.assign(document, update.$set);
            const pushedLogs = update.$push?.logs;
            if (pushedLogs) {
                document.logs.push(...pushedLogs.$each);
                document.logs = document.logs.slice(pushedLogs.$slice);
            }
            return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
        },
    };
}

test('claimNext query excludes running operations with unexpired foreign leases', async () => {
    const claimedOperation = { _id: 'operation-1', status: 'running' };
    const model = createModel(claimedOperation);
    const repository = new L2tpOperationRepository({ model });

    const result = await repository.claimNext({
        owner: 'worker-1',
        leaseMs: 30_000,
        now: NOW,
    });

    assert.equal(result, claimedOperation);
    assert.deepEqual(model.calls[0].query, {
        $or: [
            { status: 'queued' },
            {
                status: 'running',
                leaseUntil: { $lte: NOW },
            },
        ],
    });
});

test('claimNext starts a deterministic lease and returns the claimed operation', async () => {
    const model = createModel({ _id: 'operation-1', status: 'running' });
    const repository = new L2tpOperationRepository({ model });

    await repository.claimNext({
        owner: 'worker-1',
        leaseMs: 30_000,
        now: NOW,
    });

    assert.deepEqual(model.calls[0].update, {
        $set: {
            status: 'running',
            leaseOwner: 'worker-1',
            leaseUntil: new Date('2026-09-22T10:00:30.000Z'),
        },
        $inc: { attempts: 1 },
    });
    assert.deepEqual(model.calls[0].options, {
        new: true,
        sort: { createdAt: 1, _id: 1 },
        runValidators: true,
    });
});

test('renewLease extends only the current unexpired lease owned by the running worker', async () => {
    const model = createModel({ acknowledged: true, matchedCount: 1 });
    const repository = new L2tpOperationRepository({ model });

    const renewed = await repository.renewLease({
        operationId: 'operation-1',
        owner: 'worker-1',
        leaseMs: 30_000,
        now: NOW,
    });

    assert.equal(renewed, true);
    assert.deepEqual(model.calls, [{
        method: 'updateOne',
        query: {
            _id: 'operation-1',
            status: 'running',
            leaseOwner: 'worker-1',
            leaseUntil: { $gt: NOW },
        },
        update: {
            $set: {
                leaseUntil: new Date('2026-09-22T10:00:30.000Z'),
            },
        },
        options: { runValidators: true },
    }]);
});

test('succeedClaimed marks the currently claimed operation succeeded', async () => {
    const journal = {
        at: NOW,
        level: 'info',
        code: 'L2TP_OPERATION_SUCCEEDED',
        message: 'L2TP operation succeeded after verification',
    };
    const model = createCasModel({
        _id: 'operation-1',
        status: 'running',
        leaseOwner: 'worker-1',
        leaseUntil: new Date('2026-09-22T10:00:30.000Z'),
        errorCode: 'OLD_ERROR',
        errorMessage: 'old error',
    });
    const repository = new L2tpOperationRepository({ model });

    const succeeded = await repository.succeedClaimed({
        operationId: 'operation-1',
        owner: 'worker-1',
        now: NOW,
        step: 'verify',
        journal,
    });

    assert.equal(succeeded, true);
    assert.deepEqual(model.document, {
        _id: 'operation-1',
        status: 'succeeded',
        leaseOwner: 'worker-1',
        leaseUntil: new Date('2026-09-22T10:00:30.000Z'),
        step: 'verify',
        progress: 100,
        errorCode: '',
        errorMessage: '',
        finishedAt: NOW,
        logs: [journal],
    });
});

test('succeedClaimed rejects a stale owner after the lease changes hands', async () => {
    const operation = {
        _id: 'operation-1',
        status: 'running',
        leaseOwner: 'worker-2',
        leaseUntil: new Date('2026-09-22T10:00:30.000Z'),
    };
    const model = createCasModel(operation);
    const repository = new L2tpOperationRepository({ model });

    const succeeded = await repository.succeedClaimed({
        operationId: 'operation-1',
        owner: 'worker-1',
        now: NOW,
        step: 'verify',
        journal: { at: NOW, level: 'info', code: 'SUCCEEDED', message: 'done' },
    });

    assert.equal(succeeded, false);
    assert.deepEqual(model.document, { logs: [], ...operation });
});

test('succeedClaimed rejects a lease that has expired at the CAS time', async () => {
    const operation = {
        _id: 'operation-1',
        status: 'running',
        leaseOwner: 'worker-1',
        leaseUntil: NOW,
    };
    const model = createCasModel(operation);
    const repository = new L2tpOperationRepository({ model });

    const succeeded = await repository.succeedClaimed({
        operationId: 'operation-1',
        owner: 'worker-1',
        now: NOW,
        step: 'verify',
        journal: { at: NOW, level: 'info', code: 'SUCCEEDED', message: 'done' },
    });

    assert.equal(succeeded, false);
    assert.deepEqual(model.document, { logs: [], ...operation });
});

test('succeedClaimed rejects an operation outside the running status', async () => {
    const operation = {
        _id: 'operation-1',
        status: 'rolling_back',
        leaseOwner: 'worker-1',
        leaseUntil: new Date('2026-09-22T10:00:30.000Z'),
    };
    const model = createCasModel(operation);
    const repository = new L2tpOperationRepository({ model });

    const succeeded = await repository.succeedClaimed({
        operationId: 'operation-1',
        owner: 'worker-1',
        now: NOW,
        step: 'verify',
        journal: { at: NOW, level: 'info', code: 'SUCCEEDED', message: 'done' },
    });

    assert.equal(succeeded, false);
    assert.deepEqual(model.document, { logs: [], ...operation });
});

test('recordStep atomically stores progress and appends a bounded journal entry', async () => {
    const updateResult = { acknowledged: true, matchedCount: 1 };
    const model = createModel(updateResult);
    const repository = new L2tpOperationRepository({ model });
    const journal = {
        at: NOW,
        level: 'info',
        code: 'L2TP_STEP_SUCCEEDED',
        message: 'Completed L2TP operation step: verify',
    };

    const result = await repository.recordStep({
        operationId: 'operation-1',
        step: 'verify',
        progress: 67,
        journal,
    });

    assert.equal(result, updateResult);
    assert.deepEqual(model.calls, [{
        method: 'updateOne',
        query: { _id: 'operation-1' },
        update: {
            $set: {
                step: 'verify',
                progress: 67,
            },
            $push: {
                logs: {
                    $each: [journal],
                    $slice: -100,
                },
            },
        },
        options: { runValidators: true },
    }]);
});

test('setStatus persists only explicit lifecycle fields and a bounded journal entry', async () => {
    const updateResult = { acknowledged: true, matchedCount: 1 };
    const model = createModel(updateResult);
    const repository = new L2tpOperationRepository({ model });
    const journal = {
        at: NOW,
        level: 'error',
        code: 'VERIFY_FAILED',
        message: 'Verification failed',
    };

    const result = await repository.setStatus({
        operationId: 'operation-1',
        status: 'failed',
        step: 'verify',
        progress: 67,
        errorCode: 'VERIFY_FAILED',
        errorMessage: 'Verification failed',
        finishedAt: NOW,
        journal,
        leaseOwner: 'must-not-be-written',
    });

    assert.equal(result, updateResult);
    assert.deepEqual(model.calls, [{
        method: 'updateOne',
        query: { _id: 'operation-1' },
        update: {
            $set: {
                status: 'failed',
                step: 'verify',
                progress: 67,
                errorCode: 'VERIFY_FAILED',
                errorMessage: 'Verification failed',
                finishedAt: NOW,
            },
            $push: {
                logs: {
                    $each: [journal],
                    $slice: -100,
                },
            },
        },
        options: { runValidators: true },
    }]);
});

test('setStatus omits lifecycle fields that were not supplied', async () => {
    const model = createModel();
    const repository = new L2tpOperationRepository({ model });
    const journal = {
        at: NOW,
        level: 'error',
        code: 'VERIFY_STEP_REQUIRED',
        message: 'Verification step is required',
    };

    await repository.setStatus({
        operationId: 'operation-2',
        status: 'failed',
        progress: 0,
        errorCode: 'VERIFY_STEP_REQUIRED',
        errorMessage: 'Verification step is required',
        journal,
    });

    assert.deepEqual(model.calls[0].update.$set, {
        status: 'failed',
        progress: 0,
        errorCode: 'VERIFY_STEP_REQUIRED',
        errorMessage: 'Verification step is required',
    });
});
