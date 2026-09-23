'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');

function queryResult(value) {
    return {
        lean() {
            return Promise.resolve(value);
        },
    };
}

test('adapts the lock model to the concrete lock-service repository contract', async () => {
    const calls = [];
    const currentLock = {
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseUntil: new Date('2026-09-22T12:01:00.000Z'),
    };
    const savedLock = { ...currentLock, owner: 'worker-b' };
    const model = {
        connectionString: 'mongodb://model-secret',
        findOne(filter) {
            calls.push({ method: 'findOne', filter });
            return queryResult(currentLock);
        },
        findOneAndUpdate(filter, update, options) {
            calls.push({ method: 'findOneAndUpdate', filter, update, options });
            return queryResult(savedLock);
        },
        async updateOne(filter, update, options) {
            calls.push({ method: 'updateOne', filter, update, options });
            return { matchedCount: 1 };
        },
        async deleteOne(filter) {
            calls.push({ method: 'deleteOne', filter });
            return { deletedCount: 1 };
        },
    };
    const repository = new NodeOperationLockRepository({ model });

    assert.deepEqual(Object.keys(repository), []);
    assert.strictEqual(repository.model, model);
    assert.doesNotMatch(JSON.stringify(repository), /model-secret/);
    assert.strictEqual(await repository.findByNode('node-a'), currentLock);
    assert.strictEqual(await repository.save(savedLock), savedLock);
    assert.equal(await repository.renewLease({
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        now: new Date('2026-09-22T12:00:00.000Z'),
        leaseUntil: new Date('2026-09-22T12:02:00.000Z'),
    }), true);
    assert.equal(await repository.deleteOwned({
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
    }), true);

    assert.deepEqual(calls, [
        { method: 'findOne', filter: { node: 'node-a' } },
        {
            method: 'findOneAndUpdate',
            filter: { node: 'node-a' },
            update: {
                $set: {
                    owner: 'worker-b',
                    operationId: 'operation-a',
                    leaseUntil: new Date('2026-09-22T12:01:00.000Z'),
                },
            },
            options: {
                upsert: true,
                new: true,
                runValidators: true,
                setDefaultsOnInsert: true,
            },
        },
        {
            method: 'updateOne',
            filter: {
                node: 'node-a',
                owner: 'worker-a',
                operationId: 'operation-a',
                leaseUntil: { $gt: new Date('2026-09-22T12:00:00.000Z') },
            },
            update: { $set: { leaseUntil: new Date('2026-09-22T12:02:00.000Z') } },
            options: { runValidators: true },
        },
        {
            method: 'deleteOne',
            filter: {
                node: 'node-a',
                owner: 'worker-a',
                operationId: 'operation-a',
            },
        },
    ]);
});

test('acquireLease atomically claims only absent, expired, or same-owner locks', async () => {
    const calls = [];
    const previousLock = {
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseUntil: new Date('2026-09-22T12:01:00.000Z'),
    };
    const model = {
        findOneAndUpdate(filter, update, options) {
            calls.push({ method: 'findOneAndUpdate', filter, update, options });
            return queryResult(previousLock);
        },
    };
    const repository = new NodeOperationLockRepository({ model });
    const now = new Date('2026-09-22T12:00:00.000Z');
    const leaseUntil = new Date('2026-09-22T12:02:00.000Z');

    assert.deepEqual(await repository.acquireLease({
        node: 'node-a',
        owner: 'worker-b',
        operationId: 'operation-b',
        now,
        leaseUntil,
    }), {
        acquired: true,
        previousLock,
    });
    assert.deepEqual(calls, [{
        method: 'findOneAndUpdate',
        filter: {
            node: 'node-a',
            $or: [
                { leaseUntil: { $lte: now } },
                { owner: 'worker-b', operationId: 'operation-b' },
            ],
        },
        update: {
            $set: {
                owner: 'worker-b',
                operationId: 'operation-b',
                leaseUntil,
            },
        },
        options: {
            upsert: true,
            new: false,
            runValidators: true,
            setDefaultsOnInsert: true,
        },
    }]);
});

test('acquireLease turns a unique-key race into a rejected claim', async () => {
    const currentLock = {
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseUntil: new Date('2026-09-22T12:01:00.000Z'),
    };
    const calls = [];
    const duplicateKey = Object.assign(new Error('duplicate key'), { code: 11000 });
    const model = {
        findOneAndUpdate() {
            calls.push('findOneAndUpdate');
            throw duplicateKey;
        },
        findOne(filter) {
            calls.push({ method: 'findOne', filter });
            return queryResult(currentLock);
        },
    };
    const repository = new NodeOperationLockRepository({ model });

    assert.deepEqual(await repository.acquireLease({
        node: 'node-a',
        owner: 'worker-b',
        operationId: 'operation-b',
        now: new Date('2026-09-22T12:00:00.000Z'),
        leaseUntil: new Date('2026-09-22T12:02:00.000Z'),
    }), {
        acquired: false,
        currentLock,
    });
    assert.deepEqual(calls, [
        'findOneAndUpdate',
        { method: 'findOne', filter: { node: 'node-a' } },
    ]);
});

test('reports unmatched renewals and owned deletions without model objects in results', async () => {
    const model = {
        async updateOne() { return { matchedCount: 0 }; },
        async deleteOne() { return { deletedCount: 0 }; },
    };
    const repository = new NodeOperationLockRepository({ model });

    assert.equal(await repository.renewLease({
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        now: new Date('2026-09-22T12:00:00.000Z'),
        leaseUntil: new Date('2026-09-22T12:01:00.000Z'),
    }), false);
    assert.equal(await repository.deleteOwned({
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
    }), false);
});
