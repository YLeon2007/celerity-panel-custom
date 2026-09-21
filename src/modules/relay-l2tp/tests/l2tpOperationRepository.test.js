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
