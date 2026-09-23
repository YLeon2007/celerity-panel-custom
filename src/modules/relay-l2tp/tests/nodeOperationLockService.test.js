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
        async acquireLease(request) {
            calls.push({ method: 'acquireLease', request: { ...request } });
            const currentLock = locks.get(String(request.node));
            const previousLock = currentLock ? { ...currentLock } : null;
            const eligible = !previousLock
                || previousLock.leaseUntil.getTime() <= request.now.getTime()
                || (String(previousLock.owner) === String(request.owner)
                    && String(previousLock.operationId) === String(request.operationId));
            if (!eligible) {
                return { acquired: false, currentLock: previousLock };
            }

            const lock = {
                node: request.node,
                owner: request.owner,
                operationId: request.operationId,
                leaseUntil: request.leaseUntil,
            };
            locks.set(String(request.node), { ...lock });
            return { acquired: true, previousLock };
        },
        async save(lock) {
            calls.push({ method: 'save', lock: { ...lock } });
            locks.set(String(lock.node), { ...lock });
            return { ...lock };
        },
        async renewLease(request) {
            calls.push({ method: 'renewLease', request: { ...request } });
            const lock = locks.get(String(request.node));
            const matches = lock
                && String(lock.owner) === String(request.owner)
                && String(lock.operationId) === String(request.operationId)
                && lock.leaseUntil.getTime() > request.now.getTime();
            if (!matches) return false;

            lock.leaseUntil = request.leaseUntil;
            return true;
        },
        async deleteOwned(request) {
            calls.push({ method: 'deleteOwned', request: { ...request } });
            const lock = locks.get(String(request.node));
            const matches = lock
                && String(lock.owner) === String(request.owner)
                && String(lock.operationId) === String(request.operationId);
            if (!matches) return false;

            locks.delete(String(request.node));
            return true;
        },
    };
}

function createService(repository) {
    return new NodeOperationLockService({
        repository,
        clock: { now: () => new Date(NOW) },
    });
}

function createConcurrentRepository(initialLock = null) {
    let currentLock = initialLock ? { ...initialLock } : null;
    const calls = [];
    const pendingReads = [];

    function releaseReads() {
        while (pendingReads.length > 0) {
            pendingReads.shift()(currentLock ? { ...currentLock } : null);
        }
    }

    return {
        calls,
        async findByNode(node) {
            calls.push({ method: 'findByNode', node });
            return new Promise(resolve => {
                pendingReads.push(lock => resolve(lock));
                if (pendingReads.length === 2) releaseReads();
            });
        },
        async save(lock) {
            calls.push({ method: 'save', lock: { ...lock } });
            currentLock = { ...lock };
            return { ...lock };
        },
        async acquireLease(request) {
            calls.push({ method: 'acquireLease', request: { ...request } });
            const previousLock = currentLock ? { ...currentLock } : null;
            const eligible = !previousLock
                || previousLock.leaseUntil.getTime() <= request.now.getTime()
                || (String(previousLock.owner) === String(request.owner)
                    && String(previousLock.operationId) === String(request.operationId));
            if (!eligible) {
                return { acquired: false, currentLock: previousLock };
            }

            currentLock = {
                node: request.node,
                owner: request.owner,
                operationId: request.operationId,
                leaseUntil: request.leaseUntil,
            };
            return { acquired: true, previousLock };
        },
        getCurrentLock() {
            return currentLock;
        },
    };
}

test('concurrent absent competitors allow only one acquire', async () => {
    const repository = createConcurrentRepository();
    const service = createService(repository);

    const results = await Promise.all([
        service.acquire({
            node: 'node-a',
            owner: 'worker-a',
            operationId: 'operation-a',
            leaseMs: 30_000,
        }),
        service.acquire({
            node: 'node-a',
            owner: 'worker-b',
            operationId: 'operation-b',
            leaseMs: 30_000,
        }),
    ]);

    assert.deepEqual(results.map(result => result.ok).sort(), [false, true]);
    assert.deepEqual(repository.getCurrentLock(), {
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseUntil: new Date('2026-09-21T12:00:30.000Z'),
    });
});

test('concurrent expired competitors allow only one replacement', async () => {
    const repository = createConcurrentRepository({
        node: 'node-a',
        owner: 'worker-expired',
        operationId: 'operation-expired',
        leaseUntil: new Date('2026-09-21T11:59:59.999Z'),
    });
    const service = createService(repository);

    const results = await Promise.all([
        service.acquire({
            node: 'node-a',
            owner: 'worker-a',
            operationId: 'operation-a',
            leaseMs: 30_000,
        }),
        service.acquire({
            node: 'node-a',
            owner: 'worker-b',
            operationId: 'operation-b',
            leaseMs: 30_000,
        }),
    ]);

    assert.deepEqual(results.map(result => result.ok).sort(), [false, true]);
    assert.deepEqual(repository.getCurrentLock(), {
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseUntil: new Date('2026-09-21T12:00:30.000Z'),
    });
});

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
    assert.equal(repository.calls.filter(call => call.method === 'findByNode').length, 0);
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

test('renew extends the current unexpired lease with an atomic ownership match', async () => {
    const repository = createRepository([{
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseUntil: new Date('2026-09-21T12:00:05.000Z'),
    }]);
    const service = createService(repository);

    const result = await service.renew({
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
    assert.deepEqual(repository.calls, [{
        method: 'renewLease',
        request: {
            node: 'node-a',
            owner: 'worker-a',
            operationId: 'operation-a',
            now: NOW,
            leaseUntil: new Date('2026-09-21T12:00:30.000Z'),
        },
    }]);
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
    assert.deepEqual(repository.calls, [{
        method: 'deleteOwned',
        request: {
            node: 'node-a',
            owner: 'worker-a',
            operationId: 'operation-a',
        },
    }]);
});

test('release cannot delete a successor that replaces the predecessor before deletion', async () => {
    const predecessor = {
        node: 'node-a',
        owner: 'worker-a',
        operationId: 'operation-a',
        leaseUntil: new Date('2026-09-21T12:01:00.000Z'),
    };
    const successor = {
        node: 'node-a',
        owner: 'worker-b',
        operationId: 'operation-b',
        leaseUntil: new Date('2026-09-21T12:02:00.000Z'),
    };
    let currentLock = { ...predecessor };
    const calls = [];
    const repository = {
        async findByNode(node) {
            calls.push({ method: 'findByNode', node });
            const observedLock = currentLock;
            currentLock = { ...successor };
            return observedLock;
        },
        async deleteByNode(node) {
            calls.push({ method: 'deleteByNode', node });
            if (!currentLock || String(currentLock.node) !== String(node)) return false;
            currentLock = null;
            return true;
        },
        async deleteOwned(request) {
            calls.push({ method: 'deleteOwned', request: { ...request } });
            currentLock = { ...successor };
            const matches = String(currentLock.node) === String(request.node)
                && String(currentLock.owner) === String(request.owner)
                && String(currentLock.operationId) === String(request.operationId);
            if (matches) currentLock = null;
            return matches;
        },
    };
    const service = createService(repository);

    const result = await service.release({
        node: predecessor.node,
        owner: predecessor.owner,
        operationId: predecessor.operationId,
    });

    assert.equal(calls.some(call => call.method === 'findByNode'), false);
    assert.deepEqual(result, {
        ok: false,
        error: {
            code: RESULT_CODES.NOT_OWNED,
            node: 'node-a',
        },
    });
    assert.deepEqual(currentLock, successor);
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
            assert.deepEqual(repository.calls, [{
                method: 'deleteOwned',
                request: {
                    node: 'node-a',
                    owner: releaseRequest.owner,
                    operationId: releaseRequest.operationId,
                },
            }]);
            assert.deepEqual(await repository.findByNode('node-a'), {
                node: 'node-a',
                owner: 'worker-a',
                operationId: 'operation-a',
                leaseUntil: new Date('2026-09-21T12:01:00.000Z'),
            });
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
            .filter(call => call.method === 'acquireLease')
            .map(call => call.request.node),
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
