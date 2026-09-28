'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { L2tpOperationRepository } = require('../services/l2tpOperationRepository');

const NOW = new Date('2026-09-22T10:00:00.000Z');
const CLAIM = Object.freeze({
    operationId: 'operation-1', owner: 'worker-1', ownerGeneration: 2,
    expectedStatus: 'running', now: NOW,
});
const JOURNAL = Object.freeze({
    at: NOW, level: 'info', code: 'VERIFY_OK', message: 'Verified',
});
const FILTER = {
    _id: 'operation-1', status: 'running', leaseOwner: 'worker-1',
    ownerGeneration: 2, leaseUntil: { $gt: NOW },
};
const WRITES = [
    ['renewClaimed', { leaseMs: 30_000 }],
    ['recordClaimedStep', { step: 'verify', progress: 67, journal: JOURNAL }],
    ['transitionClaimed', { status: 'failed', finishedAt: NOW, journal: JOURNAL }],
    ['succeedGenerationClaimed', { step: 'verify', journal: JOURNAL }],
];

function fixture(overrides = {}) {
    const document = {
        _id: 'operation-1', status: 'running', leaseOwner: 'worker-1',
        ownerGeneration: 2, leaseUntil: new Date('2026-09-22T10:00:30.000Z'),
        logs: [], ...overrides,
    };
    const calls = [];
    return {
        document, calls,
        async updateOne(query, update, options) {
            calls.push({ query, update, options });
            if (query._id !== document._id || query.status !== document.status
                || query.leaseOwner !== document.leaseOwner
                || query.ownerGeneration !== document.ownerGeneration
                || !(document.leaseUntil > query.leaseUntil.$gt)) {
                return { matchedCount: 0 };
            }
            Object.assign(document, update.$set);
            if (update.$push) {
                document.logs.push(...update.$push.logs.$each);
                document.logs = document.logs.slice(update.$push.logs.$slice);
            }
            return { matchedCount: 1 };
        },
    };
}

for (const [method, fields] of WRITES) {
    test(`${method} fails closed on stale generation, expired lease, wrong status and unversioned rows`, async () => {
        for (const changed of [
            { ownerGeneration: 3 }, { ownerGeneration: undefined },
            { leaseUntil: NOW }, { status: 'rolling_back' },
        ]) {
            const model = fixture(changed);
            const before = structuredClone(model.document);
            const result = await new L2tpOperationRepository({ model })[method]({ ...CLAIM, ...fields });
            assert.equal(result, false);
            assert.deepEqual(model.calls[0].query, FILTER);
            assert.deepEqual(model.document, before);
        }
    });

    test(`${method} refuses invalid or missing claim fences before writing`, async () => {
        for (const changed of [
            { ownerGeneration: undefined }, { ownerGeneration: 0 }, { ownerGeneration: 1.5 },
            { ownerGeneration: Number.MAX_SAFE_INTEGER + 1 },
            { owner: '' }, { operationId: undefined }, { expectedStatus: undefined },
            { expectedStatus: 'queued' }, { expectedStatus: 'succeeded' },
            { now: undefined }, { now: new Date('invalid') },
        ]) {
            const model = fixture();
            assert.equal(await new L2tpOperationRepository({ model })[method]({
                ...CLAIM, ...fields, ...changed,
            }), false);
            assert.deepEqual(model.calls, []);
        }
    });
}

test('renewClaimed uses exact generation-fenced atomic filter and extends its lease', async () => {
    const model = fixture();
    assert.equal(await new L2tpOperationRepository({ model }).renewClaimed({ ...CLAIM, leaseMs: 60_000 }), true);
    assert.deepEqual(model.calls, [{
        query: FILTER,
        update: { $set: { leaseUntil: new Date('2026-09-22T10:01:00.000Z') } },
        options: { runValidators: true },
    }]);
});

test('recordClaimedStep uses exact filter and a bounded sanitized journal', async () => {
    const model = fixture();
    assert.equal(await new L2tpOperationRepository({ model }).recordClaimedStep({
        ...CLAIM, step: 'verify', progress: 67, journal: JOURNAL,
    }), true);
    assert.deepEqual(model.calls, [{
        query: FILTER,
        update: {
            $set: { step: 'verify', progress: 67 },
            $push: { logs: { $each: [JOURNAL], $slice: -100 } },
        }, options: { runValidators: true },
    }]);
});

test('transitionClaimed fences phase and writes only explicit lifecycle fields', async () => {
    const model = fixture();
    assert.equal(await new L2tpOperationRepository({ model }).transitionClaimed({
        ...CLAIM, status: 'rolling_back', step: 'rollback', progress: 70,
        journal: JOURNAL, leaseOwner: 'do-not-write',
    }), true);
    assert.deepEqual(model.calls, [{
        query: FILTER,
        update: {
            $set: { status: 'rolling_back', step: 'rollback', progress: 70 },
            $push: { logs: { $each: [JOURNAL], $slice: -100 } },
        }, options: { runValidators: true },
    }]);
});

test('succeedGenerationClaimed fences terminal success, clears errors and bounds logs', async () => {
    const model = fixture({ errorCode: 'OLD', errorMessage: 'old' });
    assert.equal(await new L2tpOperationRepository({ model }).succeedGenerationClaimed({
        ...CLAIM, step: 'verify', journal: JOURNAL,
    }), true);
    assert.deepEqual(model.calls, [{
        query: FILTER,
        update: {
            $set: {
                status: 'succeeded', step: 'verify', progress: 100,
                errorCode: '', errorMessage: '', finishedAt: NOW,
            },
            $push: { logs: { $each: [JOURNAL], $slice: -100 } },
        }, options: { runValidators: true },
    }]);
});

test('claimed journal writes discard extra credential fields', async () => {
    const credentialJournal = {
        ...JOURNAL, password: 'credential-secret', privateKey: 'ssh-secret',
    };
    for (const [method, fields] of WRITES.slice(1)) {
        const model = fixture();
        assert.equal(await new L2tpOperationRepository({ model })[method]({
            ...CLAIM, ...fields, journal: credentialJournal,
        }), true);
        assert.deepEqual(model.calls[0].update.$push.logs, {
            $each: [JOURNAL], $slice: -100,
        });
    }
});

test('rolling-back phase remains claimable by its current generation only', async () => {
    const model = fixture({ status: 'rolling_back' });
    assert.equal(await new L2tpOperationRepository({ model }).transitionClaimed({
        ...CLAIM, expectedStatus: 'rolling_back', status: 'rolled_back', journal: JOURNAL,
    }), true);
    assert.deepEqual(model.calls[0].query, { ...FILTER, status: 'rolling_back' });
});

test('invalid lease extensions and invalid transitions never reach the model', async () => {
    for (const leaseMs of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
        const model = fixture();
        assert.equal(await new L2tpOperationRepository({ model }).renewClaimed({
            ...CLAIM, leaseMs,
        }), false);
        assert.deepEqual(model.calls, []);
    }
    const model = fixture();
    assert.equal(await new L2tpOperationRepository({ model }).transitionClaimed({
        ...CLAIM, status: 'succeeded', journal: JOURNAL,
    }), false);
    assert.deepEqual(model.calls, []);
});

test('terminal success makes subsequent claimed progress a no-op', async () => {
    const model = fixture();
    const repository = new L2tpOperationRepository({ model });
    assert.equal(await repository.succeedGenerationClaimed({
        ...CLAIM, step: 'verify', journal: JOURNAL,
    }), true);
    const finished = structuredClone(model.document);
    assert.equal(await repository.recordClaimedStep({
        ...CLAIM, step: 'late', progress: 12, journal: JOURNAL,
    }), false);
    assert.deepEqual(model.document, finished);
    assert.deepEqual(model.calls[1].query, FILTER);
});

test('stale and valid same-owner generation CAS calls interleave without stale mutation', async () => {
    const model = fixture();
    const repository = new L2tpOperationRepository({ model });
    const [stale, valid] = await Promise.all([
        repository.recordClaimedStep({ ...CLAIM, ownerGeneration: 1, step: 'stale', progress: 33, journal: JOURNAL }),
        repository.recordClaimedStep({ ...CLAIM, step: 'verify', progress: 67, journal: JOURNAL }),
    ]);
    assert.deepEqual([stale, valid], [false, true]);
    assert.equal(model.document.step, 'verify');
    assert.equal(model.document.progress, 67);
    assert.deepEqual(model.document.logs, [JOURNAL]);
    assert.deepEqual(model.calls.map(call => call.query), [
        { ...FILTER, ownerGeneration: 1 }, FILTER,
    ]);
});
