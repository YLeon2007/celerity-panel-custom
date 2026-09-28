'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { L2tpOperationWorker } = require('../workers/l2tpOperationWorker');
const { L2tpOperationRepository } = require('../services/l2tpOperationRepository');

const NOW = new Date('2026-09-28T10:00:00Z');
function harness({ generation = 7, storedGeneration = generation, leaseUntil = new Date(NOW.getTime() + 30_000), plan = { steps: [] } } = {}) {
    const events = [];
    let status = 'running';
    const model = {
        async updateOne(filter, update) {
            events.push({ type: 'CAS', filter, update });
            if (filter.ownerGeneration !== storedGeneration || filter.status !== status ||
                filter.leaseUntil.$gt >= leaseUntil) return { matchedCount: 0 };
            if (update.$set.status) status = update.$set.status;
            return { matchedCount: 1 };
        },
    };
    const operationRepository = new L2tpOperationRepository({ model });
    const operation = { id: 'op-1', kind: 'install', node: 'node-1', status: 'running',
        admissionId: 'admission-1', ownerGeneration: generation, leaseOwner: 'worker-1', plan };
    const worker = new L2tpOperationWorker({
        operationRepository,
        remoteAdmissionRepository: {
            async claimQueuedInstall() { return operation; },
            async claimQueuedSyncUsers() { throw new Error('unexpected claim'); },
        },
        enableUnsafeExecutionForTests: true,
        lockService: {
            async acquire() { events.push({ type: 'lock' }); return { ok: true,
                lock: { generation: 'lock-uuid', remoteUncertain: true } }; },
            async renew(request) { events.push({ type: 'lock-renew', request }); return { ok: true }; },
            async release(request) { events.push({ type: 'lock-release', request }); return { ok: true }; },
        },
        executor: { async executeStep() { events.push({ type: 'SSH' }); } },
        workerId: 'worker-1', leaseMs: 30_000, clock: { now: () => new Date(NOW) },
        timer: { setInterval() { return 1; }, clearInterval() {} },
    });
    return { worker, events };
}

test('early failure is fenced by immutable generation and a stale claim never reports failed', async () => {
    const { worker, events } = harness({ storedGeneration: 8 });
    assert.deepEqual(await worker.runOnce(), { claimed: true, operationId: 'op-1',
        status: 'running', stopped: true, errorCode: 'L2TP_OPERATION_LEASE_LOST' });
    assert.deepEqual(events.map(e => e.type), ['CAS']);
    assert.equal(events[0].filter.ownerGeneration, 7);
    assert.equal(events[0].filter.status, 'running');
});

test('expired generation lease stops before lock acquisition or SSH', async () => {
    const { worker, events } = harness({ leaseUntil: new Date(NOW.getTime() - 1) });
    const result = await worker.runOnce();
    assert.equal(result.stopped, true);
    assert.equal(result.status, 'running');
    assert.deepEqual(events.map(e => e.type), ['CAS']);
});

test('absent generation refuses claim before writes, lock or SSH', async () => {
    const { worker, events } = harness({ generation: null });
    assert.deepEqual(await worker.runOnce(), { claimed: false, unavailable: true });
    assert.deepEqual(events, []);
});
