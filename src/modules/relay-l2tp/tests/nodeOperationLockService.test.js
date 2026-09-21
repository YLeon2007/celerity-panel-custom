'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    NodeOperationLockService,
    RESULT_CODES,
} = require('../services/nodeOperationLockService');

const NOW = new Date('2026-09-21T12:00:00.000Z');

function createRepository(initialLocks = []) {
    const locks = new Map(initialLocks.map(lock => [String(lock.node), { ...lock }]));
    const calls = [];

    return {
        calls,
        async findByNode(node) {
            calls.push({ method: 'findByNode', node });
            return locks.get(String(node)) || null;
        },
        async save(lock) {
            calls.push({ method: 'save', lock: { ...lock } });
            locks.set(String(lock.node), { ...lock });
            return { ...lock };
        },
        async deleteByNode(node) {
            calls.push({ method: 'deleteByNode', node });
            return locks.delete(String(node));
        },
    };
}

function createService(repository) {
    return new NodeOperationLockService({
        repository,
        clock: { now: () => new Date(NOW) },
    });
}

test('acquire creates a lease when the node has no lock', async () => {
    const repository = createRepository();
    const service = createService(repository);

    const result = await service.acquire({
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseMs: 30_000,
    });

    assert.deepEqual(result, {
        ok: true,
        code: RESULT_CODES.ACQUIRED,
        lock: {
            node: 'node-a',
            owner: 'worker-a',
            operationId: 'operation-a',
            leaseUntil: new Date('2026-09-21T12:00:30.000Z'),
        },
    });
});

test('acquire rejects an active lease owned by another operation', async () => {
    const leaseUntil = new Date('2026-09-21T12:01:00.000Z');
    const repository = createRepository([{
        node: 'node-a',
        owner: 'worker-b',
        operationId: 'operation-b',
        leaseUntil,
    }]);
    const service = createService(repository);

    const result = await service.acquire({
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseMs: 30_000,
    });

    assert.deepEqual(result, {
        ok: false,
        error: {
            code: RESULT_CODES.CONFLICT,
            node: 'node-a',
            owner: 'worker-b',
            operationId: 'operation-b',
            leaseUntil,
        },
    });
    assert.equal(repository.calls.filter(call => call.method === 'save').length, 0);
});

test('acquire replaces an expired lease', async () => {
    const repository = createRepository([{
        node: 'node-a',
        owner: 'worker-b',
        operationId: 'operation-b',
        leaseUntil: new Date('2026-09-21T11:59:59.999Z'),
    }]);
    const service = createService(repository);

    const result = await service.acquire({
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseMs: 30_000,
    });

    assert.deepEqual(result, {
        ok: true,
        code: RESULT_CODES.ACQUIRED,
        lock: {
            node: 'node-a',
            owner: 'worker-a',
            operationId: 'operation-a',
            leaseUntil: new Date('2026-09-21T12:00:30.000Z'),
        },
    });
});

test('acquire renews an active lease for the same owner and operation', async () => {
    const repository = createRepository([{
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseUntil: new Date('2026-09-21T12:00:05.000Z'),
    }]);
    const service = createService(repository);

    const result = await service.acquire({
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseMs: 30_000,
    });

    assert.deepEqual(result, {
        ok: true,
        code: RESULT_CODES.RENEWED,
        lock: {
            node: 'node-a',
            owner: 'worker-a',
            operationId: 'operation-a',
            leaseUntil: new Date('2026-09-21T12:00:30.000Z'),
        },
    });
});

test('release removes a lease for the matching owner and operation', async () => {
    const repository = createRepository([{
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseUntil: new Date('2026-09-21T12:01:00.000Z'),
    }]);
    const service = createService(repository);

    const result = await service.release({
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
    });

    assert.deepEqual(result, {
        ok: true,
        code: RESULT_CODES.RELEASED,
        node: 'node-a',
    });
    assert.deepEqual(repository.calls.at(-1), {
        method: 'deleteByNode',
        node: 'node-a',
    });
});

test('release leaves a lease untouched unless owner and operation both match', async t => {
    const cases = [
        {
            name: 'different owner',
            owner: 'worker-b',
            operationId: 'operation-a',
        },
        {
            name: 'different operation',
            owner: 'worker-a',
            operationId: 'operation-b',
        },
    ];

    for (const releaseRequest of cases) {
        await t.test(releaseRequest.name, async () => {
            const repository = createRepository([{
                node: 'node-a',
                owner: 'worker-a',
                operationId: 'operation-a',
                leaseUntil: new Date('2026-09-21T12:01:00.000Z'),
            }]);
            const service = createService(repository);

            const result = await service.release({
                node: 'node-a',
                owner: releaseRequest.owner,
                operationId: releaseRequest.operationId,
            });

            assert.deepEqual(result, {
                ok: false,
                error: {
                    code: RESULT_CODES.NOT_OWNED,
                    node: 'node-a',
                },
            });
            assert.equal(
                repository.calls.some(call => call.method === 'deleteByNode'),
                false,
            );
        });
    }
});

test('acquireMany sorts node ids before making repository calls', async () => {
    const repository = createRepository();
    const service = createService(repository);

    const result = await service.acquireMany({
        nodeIds: ['node-c', 'node-a', 'node-b'],
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseMs: 30_000,
    });

    assert.equal(result.ok, true);
    assert.equal(result.code, RESULT_CODES.BATCH_ACQUIRED);
    assert.deepEqual(
        result.results.map(item => item.lock.node),
        ['node-a', 'node-b', 'node-c'],
    );
    assert.deepEqual(
        repository.calls
            .filter(call => call.method === 'findByNode')
            .map(call => call.node),
        ['node-a', 'node-b', 'node-c'],
    );
});

test('lock model stores lease identity and has one unique lock per node', () => {
    const NodeOperationLock = require('../models/nodeOperationLockModel');
    const { schema } = NodeOperationLock;

    assert.equal(schema.path('node').instance, 'ObjectId');
    assert.equal(schema.path('node').options.ref, 'HyNode');
    assert.equal(schema.path('node').options.required, true);
    assert.equal(schema.path('owner').instance, 'String');
    assert.equal(schema.path('owner').options.required, true);
    assert.equal(schema.path('operationId').instance, 'String');
    assert.equal(schema.path('operationId').options.required, true);
    assert.equal(schema.path('leaseUntil').instance, 'Date');
    assert.equal(schema.path('leaseUntil').options.required, true);

    const nodeIndex = schema.indexes().find(([fields]) => fields.node === 1);
    assert.ok(nodeIndex, 'node index exists');
    assert.equal(nodeIndex[1].unique, true);
});
