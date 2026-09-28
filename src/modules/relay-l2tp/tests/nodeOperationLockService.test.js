'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { NodeOperationLockService, RESULT_CODES } = require('../services/nodeOperationLockService');

const now = new Date('2026-09-21T12:00:00.000Z');
const until = new Date('2026-09-21T12:00:30.000Z');
const identity = { node: 'node-a', owner: 'worker-a', operationId: 'operation-a' };
const request = { ...identity, leaseMs: 30_000 };
const generation = '11111111-1111-4111-8111-111111111111';
const clock = { now: () => new Date(now) };

function fixture(existing = null) {
    const rows = new Map(existing ? [[existing.node, { ...existing }]] : []);
    const calls = [];
    const repository = {
        calls,
        getRow: (node = 'node-a') => rows.get(node) || null,
        async acquireLease(input) {
            calls.push({ method: 'acquireLease', input });
            const row = rows.get(input.node);
            if (row) return { acquired: false, currentLock: { ...row } };
            const inserted = { node: input.node, owner: input.owner, operationId: input.operationId,
                generation: input.generation, leaseUntil: input.leaseUntil, remoteUncertain: true };
            rows.set(input.node, inserted);
            return { acquired: true, lock: { ...inserted } };
        },
        async renewLease(input) {
            calls.push({ method: 'renewLease', input });
            const row = rows.get(input.node);
            if (!row || !input.generation || row.generation !== input.generation ||
                row.owner !== input.owner || row.operationId !== input.operationId ||
                row.leaseUntil <= input.now) return false;
            row.leaseUntil = input.leaseUntil;
            return true;
        },
        async deleteVerifiedOwned(input) {
            calls.push({ method: 'deleteVerifiedOwned', input });
            const row = rows.get(input.node);
            if (!row || !input.generation || row.generation !== input.generation ||
                row.owner !== input.owner || row.operationId !== input.operationId ||
                row.remoteUncertain !== true) return false;
            rows.delete(input.node);
            return true;
        },
        async deleteOwned(input) {
            calls.push({ method: 'deleteOwned', input });
            const row = rows.get(input.node);
            if (!row || !input.generation || row.generation !== input.generation ||
                row.owner !== input.owner || row.operationId !== input.operationId ||
                row.remoteUncertain !== false) return false;
            rows.delete(input.node);
            return true;
        },
    };
    return { service: new NodeOperationLockService({ repository, clock }), repository };
}

test('acquire returns unique generation and remote-uncertain insert', async () => {
    const { service, repository } = fixture();
    const result = await service.acquire(request);
    assert.equal(result.ok, true);
    assert.equal(result.code, RESULT_CODES.ACQUIRED);
    assert.match(result.lock.generation, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    assert.deepEqual(result.lock, repository.getRow());
    assert.equal(repository.calls[0].input.generation, result.lock.generation);
    assert.equal(result.lock.remoteUncertain, true);
    assert.deepEqual(result.lock.leaseUntil, until);
});

test('successive admissions get fresh generations, even with same owner', async () => {
    const { service } = fixture();
    const first = await service.acquire(request);
    const other = await fixture().service.acquire(request);
    assert.notEqual(first.lock.generation, other.lock.generation);
});

test('newly acquired generation remains fenced even when its owner requests release', async () => {
    const { service, repository } = fixture();
    const acquired = await service.acquire(request);
    assert.equal(acquired.ok, true);
    const released = await service.release({ ...identity, generation: acquired.lock.generation });
    assert.equal(released.ok, false);
    assert.equal(repository.getRow().remoteUncertain, true);
    assert.equal((await service.acquire(request)).error.code, RESULT_CODES.CONFLICT);
    assert.equal(typeof service.markQuiescent, 'undefined');
});

for (const [name, lock] of [
    ['expired other owner', { ...identity, owner: 'other', generation, leaseUntil: now, remoteUncertain: true }],
    ['active same owner', { ...identity, generation, leaseUntil: until, remoteUncertain: true }],
    ['expired same owner', { ...identity, generation, leaseUntil: now, remoteUncertain: true }],
    ['legacy', { ...identity, leaseUntil: now }],
]) {
    test(`acquire rejects ${name} without reentrant dispatch`, async () => {
        const { service, repository } = fixture(lock);
        const result = await service.acquire(request);
        assert.equal(result.ok, false);
        assert.equal(result.error.code, RESULT_CODES.CONFLICT);
        assert.deepEqual(repository.getRow(), lock);
        assert.equal(repository.calls.length, 1);
    });
}

test('renew carries generation and refuses missing or stale token', async () => {
    const { service, repository } = fixture({ ...identity, generation, leaseUntil: until, remoteUncertain: true });
    assert.equal((await service.renew(request)).ok, false);
    assert.equal((await service.renew({ ...request, generation: 'stale' })).ok, false);
    const result = await service.renew({ ...request, generation });
    assert.equal(result.ok, true);
    assert.equal(result.code, RESULT_CODES.RENEWED);
    assert.equal(result.lock.generation, generation);
    assert.equal(repository.calls.at(-1).input.generation, generation);
});

test('release without generation refuses and never invokes deletion', async () => {
    const { service, repository } = fixture({ ...identity, generation, leaseUntil: until, remoteUncertain: true });
    const result = await service.release(identity);
    assert.equal(result.ok, false);
    assert.equal(repository.calls.length, 0);
    assert.deepEqual(repository.getRow().generation, generation);
});

for (const [name, lock] of [
    ['active uncertain', { ...identity, generation, leaseUntil: until, remoteUncertain: true }],
    ['expired uncertain', { ...identity, generation, leaseUntil: now, remoteUncertain: true }],
    ['legacy', { ...identity, leaseUntil: now }],
]) {
    test(`release cannot clear ${name}`, async () => {
        const { service, repository } = fixture(lock);
        const result = await service.release({ ...identity, generation });
        assert.equal(result.ok, false);
        assert.deepEqual(repository.getRow(), lock);
    });
}

test('late release with old generation cannot remove a proven successor', async () => {
    const successor = { ...identity, generation: 'new', remoteUncertain: false, leaseUntil: until };
    const { service, repository } = fixture(successor);
    const result = await service.release({ ...identity, generation });
    assert.equal(result.ok, false);
    assert.deepEqual(repository.getRow(), successor);
});

test('only a proven generation is released with a matching token', async () => {
    const { service, repository } = fixture({ ...identity, generation, remoteUncertain: false, leaseUntil: until });
    const result = await service.release({ ...identity, generation });
    assert.equal(result.ok, true);
    assert.equal(result.code, RESULT_CODES.RELEASED);
    assert.equal(repository.getRow(), null);
});

test('verified terminal success releases only its exact uncertain generation once', async () => {
    const {service,repository}=fixture({...identity,generation,leaseUntil:until,remoteUncertain:true});
    assert.equal((await service.releaseVerified({...identity,generation:'stale'})).ok,false);
    assert.ok(repository.getRow());
    assert.equal((await service.releaseVerified({...identity,generation})).ok,true);
    assert.equal(repository.getRow(),null);
    assert.equal((await service.releaseVerified({...identity,generation})).ok,false);
});

test('acquireMany sorts nodes and reports a blocked duplicate lock', async () => {
    const { service, repository } = fixture();
    const result = await service.acquireMany({ nodeIds: ['node-c', 'node-a', 'node-b', 'node-a'],
        owner: 'worker-a', operationId: 'operation-a', leaseMs: 30_000 });
    assert.deepEqual(result.results.map(item => item.ok), [true, false, true, true]);
    assert.equal(result.results[1].error.code, RESULT_CODES.CONFLICT);
    assert.deepEqual(repository.calls.map(call => call.input.node), ['node-a', 'node-a', 'node-b', 'node-c']);
});

test('lock schema has mandatory generation and uncertain state plus unique node index', () => {
    const model = require('../models/nodeOperationLockModel');
    const { schema } = model;
    assert.equal(schema.path('generation').options.required, true);
    assert.equal(schema.path('remoteUncertain').options.required, true);
    assert.equal(schema.path('remoteUncertain').options.default, undefined);
    assert.equal(schema.path('leaseUntil').options.required, true);
    assert.equal(schema.indexes().find(([fields]) => fields.node === 1)[1].unique, true);
});
