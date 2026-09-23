'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    TopologyOperationFinalizationRepository,
} = require('../repositories/topologyOperationFinalizationRepository');

const NOW = new Date('2026-09-22T10:00:00.000Z');
const LEASE_UNTIL = new Date('2026-09-22T10:00:30.000Z');
const SESSION = Object.freeze({ id: 'topology-finalization-transaction' });

function clone(value) {
    return structuredClone(value);
}

function equalValue(left, right) {
    if (left instanceof Date && right instanceof Date) {
        return left.getTime() === right.getTime();
    }
    return left === right;
}

function matches(document, filter) {
    return Object.entries(filter).every(([key, expected]) => {
        const actual = document[key];
        if (expected && typeof expected === 'object' && !(expected instanceof Date)) {
            if (Object.hasOwn(expected, '$eq') && !equalValue(actual, expected.$eq)) return false;
            if (Object.hasOwn(expected, '$gt') && !(actual > expected.$gt)) return false;
            return true;
        }
        return equalValue(actual, expected);
    });
}

function applySet(document, update) {
    Object.assign(document, clone(update.$set || {}));
}

function createHarness(overrides = {}) {
    const store = {
        operation: {
            _id: 'operation-7',
            topologyRevision: 7,
            priorDeployedRevision: 5,
            status: 'committing',
            leaseOwner: 'worker-1',
            leaseUntil: LEASE_UNTIL,
            finishedAt: null,
            nodes: [{ candidate: { bytes: [1, 2, 3] }, secret: 'must-stay-untouched' }],
            ...(overrides.operation || {}),
        },
        topology: {
            _id: 'singleton',
            revision: 7,
            deployedRevision: 5,
            ...(overrides.topology || {}),
        },
    };
    const calls = [];
    const TopologyOperation = {
        updateOne(filter, update, options) {
            calls.push({ model: 'TopologyOperation', filter, update, options });
            if (!matches(store.operation, filter)) return Promise.resolve({ matchedCount: 0 });
            applySet(store.operation, update);
            return Promise.resolve({ matchedCount: 1, modifiedCount: 1 });
        },
    };
    const CascadeTopologyState = {
        updateOne(filter, update, options) {
            calls.push({ model: 'CascadeTopologyState', filter, update, options });
            if (!matches(store.topology, filter)) return Promise.resolve({ matchedCount: 0 });
            applySet(store.topology, update);
            return Promise.resolve({ matchedCount: 1, modifiedCount: 1 });
        },
    };
    const transactionRunner = async work => {
        const before = clone(store);
        calls.push({ transaction: 'begin', session: SESSION });
        try {
            const result = await work(SESSION);
            if (overrides.transactionError) throw overrides.transactionError;
            calls.push({ transaction: 'commit', session: SESSION });
            return result;
        } catch (error) {
            store.operation = before.operation;
            store.topology = before.topology;
            calls.push({ transaction: 'abort', session: SESSION });
            throw error;
        }
    };
    const repository = new TopologyOperationFinalizationRepository({
        TopologyOperation,
        CascadeTopologyState,
        transactionRunner,
    });
    return { calls, repository, store };
}

function request(overrides = {}) {
    return {
        operationId: 'operation-7',
        owner: 'worker-1',
        leaseUntil: LEASE_UNTIL,
        topologyRevision: 7,
        priorDeployedRevision: 5,
        now: NOW,
        ...overrides,
    };
}

test('atomically marks the leased committing operation succeeded and advances deployedRevision', async () => {
    const harness = createHarness();

    const finalized = await harness.repository.finalizeSucceeded(request());

    assert.deepEqual(finalized, {
        operationId: 'operation-7',
        topologyRevision: 7,
        deployedRevision: 7,
        finishedAt: NOW,
    });
    assert.deepEqual(harness.store.operation, {
        _id: 'operation-7',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        status: 'succeeded',
        leaseOwner: 'worker-1',
        leaseUntil: null,
        finishedAt: NOW,
        nodes: [{ candidate: { bytes: [1, 2, 3] }, secret: 'must-stay-untouched' }],
    });
    assert.deepEqual(harness.store.topology, {
        _id: 'singleton',
        revision: 7,
        deployedRevision: 7,
    });
    assert.deepEqual(harness.calls, [
        { transaction: 'begin', session: SESSION },
        {
            model: 'TopologyOperation',
            filter: {
                _id: 'operation-7',
                topologyRevision: 7,
                priorDeployedRevision: 5,
                status: 'committing',
                leaseOwner: 'worker-1',
                leaseUntil: { $eq: LEASE_UNTIL, $gt: NOW },
            },
            update: {
                $set: {
                    status: 'succeeded',
                    finishedAt: NOW,
                    leaseUntil: null,
                },
            },
            options: { runValidators: true, session: SESSION },
        },
        {
            model: 'CascadeTopologyState',
            filter: {
                _id: 'singleton',
                revision: 7,
                deployedRevision: 5,
            },
            update: { $set: { deployedRevision: 7 } },
            options: {
                runValidators: true,
                session: SESSION,
                timestamps: false,
            },
        },
        { transaction: 'commit', session: SESSION },
    ]);
    assert.doesNotMatch(JSON.stringify(harness.calls), /candidate|bytes|secret/i);
});

async function assertRejectedWithoutChanges(harness, candidateRequest = request()) {
    const before = clone(harness.store);

    const finalized = await harness.repository.finalizeSucceeded(candidateRequest);

    assert.equal(finalized, null);
    assert.deepEqual(harness.store, before);
    assert.equal(harness.calls.at(-1).transaction, 'abort');
}

test('rejects a stale lease owner without changing either document', async () => {
    const harness = createHarness({
        operation: { leaseOwner: 'worker-2' },
    });

    await assertRejectedWithoutChanges(harness);

    assert.deepEqual(
        harness.calls.filter(call => call.model).map(call => call.model),
        ['TopologyOperation'],
    );
});

test('rejects an expired lease without changing either document', async () => {
    const expiredLease = new Date('2026-09-22T09:59:59.999Z');
    const harness = createHarness({
        operation: { leaseUntil: expiredLease },
    });

    await assertRejectedWithoutChanges(harness, request({ leaseUntil: expiredLease }));

    assert.deepEqual(
        harness.calls.filter(call => call.model).map(call => call.model),
        ['TopologyOperation'],
    );
});

test('rolls back the operation when the topology revision changed', async () => {
    const harness = createHarness({ topology: { revision: 8 } });

    await assertRejectedWithoutChanges(harness);

    assert.deepEqual(
        harness.calls.filter(call => call.model).map(call => call.model),
        ['TopologyOperation', 'CascadeTopologyState'],
    );
});

test('rolls back the operation when the prior deployed revision changed', async () => {
    const harness = createHarness({ topology: { deployedRevision: 6 } });

    await assertRejectedWithoutChanges(harness);

    assert.deepEqual(
        harness.calls.filter(call => call.model).map(call => call.model),
        ['TopologyOperation', 'CascadeTopologyState'],
    );
});

test('rolls back both document updates when the transaction fails', async () => {
    const transactionError = new Error('transaction commit failed');
    const harness = createHarness({ transactionError });
    const before = clone(harness.store);

    await assert.rejects(
        harness.repository.finalizeSucceeded(request()),
        error => error === transactionError,
    );

    assert.deepEqual(harness.store, before);
    assert.deepEqual(
        harness.calls.filter(call => call.model).map(call => call.model),
        ['TopologyOperation', 'CascadeTopologyState'],
    );
    assert.equal(harness.calls.at(-1).transaction, 'abort');
});
