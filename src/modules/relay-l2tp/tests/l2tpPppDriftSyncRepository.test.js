'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const L2tpOperationModel = require('../models/l2tpOperationModel');
const { L2tpPppDriftSyncRepository } = require('../repositories/l2tpPppDriftSyncRepository');

const relayNode = '507f1f77bcf86cd799439011';
const revision = 7;
const now = new Date('2026-09-30T12:00:00.000Z');

function fixture() {
    const operations = [];
    const calls = [];
    const state = { node: relayNode, status: 'installed', desiredState: 'installed', secretRevision: revision,
        pppDriftQueueFence: 0 };
    const RelayL2tpState = {
        findOne(filter) {
            calls.push({ method: 'state.findOne', filter });
            return { select() { return this; }, lean: async () => ({ ...state }) };
        },
        findOneAndUpdate(filter, update, options) {
            calls.push({ method: 'state.findOneAndUpdate', filter, update, options });
            return { select() { return this; }, lean: async () => {
                assert.ok(options.session?.active);
                assert.deepEqual(update, { $inc: { pppDriftQueueFence: 1 } });
                if (state.node !== filter.node || state.status !== filter.status
                    || state.desiredState !== filter.desiredState
                    || state.secretRevision !== filter.secretRevision) return null;
                options.session.revision = state.secretRevision;
                options.session.fence = 1;
                return { secretRevision: state.secretRevision };
            } };
        },
    };
    const L2tpOperation = {
        findOne(filter) {
            calls.push({ method: 'operation.findOne', filter });
            const matches = operations.filter(op => op.node === filter.node && op.kind === filter.kind
                && (!filter.status || filter.status.$in.includes(op.status))
                && (!filter.idempotencyKey || op.idempotencyKey === filter.idempotencyKey));
            return { select() { return this; }, lean: async () => matches[0] ?? null };
        },
        countDocuments(filter) {
            calls.push({ method: 'operation.countDocuments', filter });
            return Promise.resolve(operations.filter(op => op.node === filter.node
                && op.kind === filter.kind && filter.idempotencyKey.test(op.idempotencyKey)).length);
        },
        async create(documents, options) {
            calls.push({ method: 'operation.create', documents, options });
            assert.ok(options.session?.active);
            assert.equal(options.session.fence, 1, 'state write precedes insert in the same session');
            for (const document of documents) {
                const op = new L2tpOperationModel(document);
                await op.validate();
                options.session.pending.push({ ...document, createdAt: now });
            }
            return documents;
        },
    };
    async function transactionRunner(work) {
        for (let retry = 0; retry < 2; retry += 1) {
            const session = { active: true, pending: [], fence: 0 };
            try {
                const result = await work(session);
                if (session.fence && state.secretRevision !== session.revision) {
                    throw Object.assign(new Error('write conflict'), { code: 112 });
                }
                for (const op of session.pending) {
                    if (operations.some(existing => existing.idempotencyKey === op.idempotencyKey)) {
                        throw Object.assign(new Error('duplicate key'),
                            { code: 11000, keyPattern: { idempotencyKey: 1 } });
                    }
                }
                state.pppDriftQueueFence += session.fence;
                operations.push(...session.pending);
                return result;
            } catch (error) {
                if (error.code !== 112 || retry === 1) throw error;
            } finally {
                session.active = false;
            }
        }
    }
    let nextId = 12;
    function makeRepository(executionContext) {
        return new L2tpPppDriftSyncRepository({ executionContext, RelayL2tpState, L2tpOperation, transactionRunner,
            operationIdFactory: () => `507f1f77bcf86cd7994390${nextId++}` });
    }
    return { operations, calls, state, RelayL2tpState, L2tpOperation, makeRepository };
}

test('enqueues a model-valid revision-keyed drift SYNC without credential material', async () => {
    const { operations, makeRepository } = fixture();
    const result = await makeRepository().enqueue({ relayNode, now });
    assert.deepEqual(result, { status: 'queued', operationId: operations[0]._id, attempts: 1 });
    assert.equal(operations[0].idempotencyKey, `ppp-drift-sync:${relayNode}:revision-${revision}:attempt-1`);
    assert.deepEqual(operations[0].plan, {
        ok: true, operationId: operations[0]._id, relayId: relayNode,
        desired: { credentialRevision: revision },
        steps: [{ type: 'backup' }, { type: 'sync_users', artifacts: [{ type: 'desired', path: 'desired.json' }] },
            { type: 'verify_users' }],
    });
    assert.doesNotMatch(JSON.stringify(operations), /password|ciphertext|plaintext|pskEncrypted/i);
});

test('an active user-edit SYNC prevents drift enqueue without spending a retry', async () => {
    const { operations, makeRepository } = fixture();
    operations.push({ _id: 'existing', node: relayNode, kind: 'sync_users', status: 'running',
        idempotencyKey: `sync-users:${relayNode}:revision-${revision}` });
    assert.deepEqual(await makeRepository().enqueue({ relayNode, now }),
        { status: 'active', operationId: 'existing' });
    assert.equal(operations.length, 1);
});

test('retry cooldown and exhaustion survive a repository restart', async () => {
    const { operations, makeRepository } = fixture();
    const first = await makeRepository().enqueue({ relayNode, now, retryIntervalMs: 1000 });
    operations[0].status = 'failed';
    operations[0].finishedAt = now;
    assert.deepEqual(await makeRepository().enqueue({ relayNode,
        now: new Date(now.getTime() + 999), retryIntervalMs: 1000 }),
    { status: 'cooldown', attempts: 1 });
    const second = await makeRepository().enqueue({ relayNode,
        now: new Date(now.getTime() + 1000), retryIntervalMs: 1000 });
    assert.equal(second.status, 'queued');
    assert.equal(second.attempts, 2);
    operations[1].status = 'failed';
    operations[1].finishedAt = new Date(now.getTime() + 1000);
    const third = await makeRepository().enqueue({ relayNode,
        now: new Date(now.getTime() + 2000), retryIntervalMs: 1000 });
    assert.equal(third.status, 'queued');
    assert.equal(third.attempts, 3);
    operations[2].status = 'failed';
    operations[2].finishedAt = new Date(now.getTime() + 2000);
    assert.deepEqual(await makeRepository().enqueue({ relayNode,
        now: new Date(now.getTime() + 3000), retryIntervalMs: 1000 }),
    { status: 'exhausted', attempts: 3 });
    assert.equal(first.status, 'queued');
    assert.equal(operations.length, 3);
});

test('rejects a revision superseded during durable attempt lookup', async () => {
    const { operations, state, L2tpOperation, makeRepository } = fixture();
    const countDocuments = L2tpOperation.countDocuments;
    L2tpOperation.countDocuments = async filter => {
        const count = await countDocuments(filter);
        state.secretRevision += 1;
        return count;
    };
    assert.deepEqual(await makeRepository().enqueue({ relayNode, now }), { status: 'unavailable' });
    assert.equal(operations.length, 0);
});

test('user edit between last state read and queue insert cannot enqueue stale PPP credentials', async () => {
    const { operations, state, RelayL2tpState, makeRepository } = fixture();
    const fence = RelayL2tpState.findOneAndUpdate;
    RelayL2tpState.findOneAndUpdate = (...args) => {
        // A user edit commits after the history read but before the
        // transactional CAS. A stale operation must not be inserted.
        state.secretRevision += 1;
        return fence(...args);
    };
    const result = await makeRepository().enqueue({ relayNode, now });
    assert.deepEqual(result, { status: 'unavailable' });
    assert.equal(operations.length, 0);
    assert.equal(state.pppDriftQueueFence, 0);
});

test('a conflicting user edit during the transaction rolls back the operation and fence', async () => {
    const { operations, state, L2tpOperation, makeRepository } = fixture();
    const create = L2tpOperation.create;
    let edited = false;
    L2tpOperation.create = async (...args) => {
        if (!edited) {
            // A separate writer attempts to change the same state document.
            // The transaction runner models the resulting write conflict and
            // retries against the now-superseded revision.
            state.secretRevision += 1;
            edited = true;
        }
        return create(...args);
    };
    assert.deepEqual(await makeRepository().enqueue({ relayNode, now }), { status: 'unavailable' });
    assert.equal(operations.length, 0);
    assert.equal(state.pppDriftQueueFence, 0);
});

test('insert failure aborts the state fence and a new instance can retry', async () => {
    const { operations, state, L2tpOperation, makeRepository } = fixture();
    const create = L2tpOperation.create;
    L2tpOperation.create = async (...args) => {
        await create(...args);
        throw new Error('insert interrupted');
    };
    await assert.rejects(makeRepository().enqueue({ relayNode, now }), /insert interrupted/);
    assert.equal(operations.length, 0);
    assert.equal(state.pppDriftQueueFence, 0);
    L2tpOperation.create = create;
    assert.equal((await makeRepository().enqueue({ relayNode, now })).status, 'queued');
    assert.equal(operations.length, 1);
    assert.equal(state.pppDriftQueueFence, 1);
});

test('without a transaction runner no state or operation is written', async () => {
    const { operations, state, RelayL2tpState, L2tpOperation } = fixture();
    const repository = new L2tpPppDriftSyncRepository({ RelayL2tpState, L2tpOperation });
    assert.deepEqual(await repository.enqueue({ relayNode, now }), { status: 'unavailable' });
    assert.equal(operations.length, 0);
    assert.equal(state.pppDriftQueueFence, 0);
});

test('a new credential revision has a fresh durable retry budget', async () => {
    const { operations, state, makeRepository } = fixture();
    await makeRepository().enqueue({ relayNode, now });
    operations[0].status = 'failed';
    state.secretRevision += 1;
    const queued = await makeRepository().enqueue({ relayNode, now });
    assert.deepEqual(queued, { status: 'queued', operationId: operations[1]._id, attempts: 1 });
    assert.equal(operations[1].plan.desired.credentialRevision, revision + 1);
});

test('uninstalled state and malformed requests fail closed without writes', async () => {
    const { operations, state, makeRepository } = fixture();
    state.status = 'degraded';
    assert.deepEqual(await makeRepository().enqueue({ relayNode, now }), { status: 'unavailable' });
    await assert.rejects(makeRepository().enqueue({ relayNode, now: new Date('bad') }), TypeError);
    await assert.rejects(makeRepository().enqueue({ relayNode: 'bad', now }), TypeError);
    assert.equal(operations.length, 0);
});

test('duplicate idempotency key returns persisted winner without another operation', async () => {
    const { operations, makeRepository } = fixture();
    const repository = makeRepository();
    // Both callers observe an empty store before either insert; only the
    // unique index may choose a winner, even across two service instances.
    const results = await Promise.all([
        repository.enqueue({ relayNode, now }),
        makeRepository().enqueue({ relayNode, now }),
    ]);
    assert.equal(operations.length, 1);
    assert.deepEqual(results.map(result => result.status).sort(), ['active', 'queued']);
    assert.equal(results[0].operationId, operations[0]._id);
    assert.equal(results[1].operationId, operations[0]._id);
});

test('drift queue stamps immutable server identity, never an enqueue payload identity', async () => {
    const { operations, makeRepository } = fixture();
    const selected = { target: 'production', hostIdentity: 'lm1.infograd.online' };
    const source = { ...selected };
    const repository = makeRepository(source);
    source.target = 'test';
    await repository.enqueue({ relayNode, now,
        executionContext: { target: 'test', hostIdentity: 'test.infograd.online' } });
    assert.deepEqual(operations[0].executionContext, selected);
});
