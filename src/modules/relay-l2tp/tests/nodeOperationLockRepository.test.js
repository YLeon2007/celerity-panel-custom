'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { NodeOperationLockRepository } = require('../services/nodeOperationLockRepository');

const now = new Date('2026-09-22T12:00:00.000Z');
const until = new Date('2026-09-22T12:02:00.000Z');
const identity = { node: 'node-a', owner: 'worker-a', operationId: 'op-a' };
const token = '11111111-1111-4111-8111-111111111111';

function fixture(existing = null) {
    let row = existing && { ...existing };
    const calls = [];
    const model = {
        async create(doc) {
            calls.push({ method: 'create', doc });
            if (row) throw Object.assign(new Error('duplicate key'), { code: 11000 });
            row = { ...doc };
            return { toObject: () => ({ ...row }) };
        },
        findOne(filter) {
            calls.push({ method: 'findOne', filter });
            return { lean: async () => row && { ...row } };
        },
        async updateOne(filter, update, options) {
            calls.push({ method: 'updateOne', filter, update, options });
            if (!row || Object.entries(filter).some(([key, value]) =>
                key === 'leaseUntil' ? !(row.leaseUntil > value.$gt)
                    : row[key] !== value)) return { matchedCount: 0 };
            row = { ...row, ...update.$set };
            return { matchedCount: 1 };
        },
        async deleteOne(filter) {
            calls.push({ method: 'deleteOne', filter });
            if (!row || Object.entries(filter).some(([key, value]) => row[key] !== value)) {
                return { deletedCount: 0 };
            }
            row = null;
            return { deletedCount: 1 };
        },
    };
    return { repository: new NodeOperationLockRepository({ model }), calls, getRow: () => row };
}

const claim = { ...identity, now, leaseUntil: until, generation: token };

test('unique insert stores uncertain generation atomically, never an update or upsert', async () => {
    const { repository, calls, getRow } = fixture();
    const result = await repository.acquireLease(claim);
    assert.deepEqual(result, { acquired: true, lock: { ...identity, generation: token, leaseUntil: until, remoteUncertain: true } });
    assert.deepEqual(getRow(), result.lock);
    assert.deepEqual(calls, [{ method: 'create', doc: result.lock }]);
});

for (const [name, row] of [
    ['expired foreign', { ...identity, owner: 'other', leaseUntil: new Date(now.getTime() - 1), generation: token, remoteUncertain: true }],
    ['active same-owner', { ...identity, leaseUntil: until, generation: token, remoteUncertain: true }],
    ['expired same-owner', { ...identity, leaseUntil: new Date(now.getTime() - 1), generation: token, remoteUncertain: true }],
    ['legacy missing fields', { ...identity, leaseUntil: new Date(now.getTime() - 1) }],
]) {
    test(`acquire conflicts with ${name} row without mutating it`, async () => {
        const { repository, calls, getRow } = fixture(row);
        assert.deepEqual(await repository.acquireLease({ ...claim, generation: 'new-token' }), {
            acquired: false, currentLock: row,
        });
        assert.deepEqual(getRow(), row);
        assert.deepEqual(calls.map(call => call.method), ['create', 'findOne']);
    });
}

test('concurrent first admissions serialize on the unique node key', async () => {
    const { repository, calls, getRow } = fixture();
    const results = await Promise.all([
        repository.acquireLease(claim),
        repository.acquireLease({ ...claim, owner: 'worker-b', generation: 'new-token' }),
    ]);
    assert.deepEqual(results.map(result => result.acquired), [true, false]);
    assert.deepEqual(results[1].currentLock, getRow());
    assert.deepEqual(calls.map(call => call.method), ['create', 'create', 'findOne']);
});

test('unrelated insert error propagates', async () => {
    const repository = new NodeOperationLockRepository({ model: { create: async () => { throw new Error('offline'); } } });
    await assert.rejects(repository.acquireLease(claim), /offline/);
});

test('renew requires generation and an active lease in atomic filter', async () => {
    const { repository, calls, getRow } = fixture({ ...identity, generation: token, leaseUntil: until, remoteUncertain: true });
    assert.equal(await repository.renewLease({ ...identity, now, leaseUntil: new Date(until.getTime() + 1000) }), false);
    assert.equal(await repository.renewLease({ ...identity, generation: 'stale', now, leaseUntil: new Date(until.getTime() + 1000) }), false);
    assert.equal(await repository.renewLease({ ...identity, generation: token, now, leaseUntil: new Date(until.getTime() + 1000) }), true);
    assert.equal(calls[0].filter.generation, 'stale');
    assert.deepEqual(calls[0].filter.leaseUntil, { $gt: now });
    assert.equal(getRow().remoteUncertain, true);
});

test('expired generation cannot be revived by renew', async () => {
    const { repository } = fixture({ ...identity, generation: token, leaseUntil: now, remoteUncertain: true });
    assert.equal(await repository.renewLease({ ...identity, generation: token, now, leaseUntil: until }), false);
});

test('save and deleteByNode refuse all bypasses', async () => {
    const { repository, calls } = fixture({ ...identity, generation: token, leaseUntil: until, remoteUncertain: true });
    assert.throws(() => repository.save({ ...identity, remoteUncertain: false }), /disabled|unsafe|forbidden/i);
    assert.throws(() => repository.deleteByNode(identity.node), /disabled|unsafe|forbidden/i);
    assert.deepEqual(calls, []);
});

for (const [name, row] of [
    ['active uncertain', { ...identity, generation: token, leaseUntil: until, remoteUncertain: true }],
    ['expired uncertain', { ...identity, generation: token, leaseUntil: now, remoteUncertain: true }],
    ['legacy', { ...identity, leaseUntil: now }],
]) {
    test(`deleteOwned never deletes ${name} row without proof`, async () => {
        const { repository, getRow } = fixture(row);
        assert.equal(await repository.deleteOwned(identity), false);
        assert.equal(await repository.deleteOwned({ ...identity, generation: token }), false);
        assert.deepEqual(getRow(), row);
    });
}

test('only a matching proven generation is deletable, never a stale generation', async () => {
    const row = { ...identity, generation: token, leaseUntil: until, remoteUncertain: false };
    const { repository, getRow, calls } = fixture(row);
    assert.equal(await repository.deleteOwned({ ...identity, generation: 'stale' }), false);
    assert.deepEqual(getRow(), row);
    assert.equal(await repository.deleteOwned({ ...identity, generation: token }), true);
    assert.equal(getRow(), null);
    assert.deepEqual(calls[1].filter, { ...identity, generation: token, remoteUncertain: false });
});
