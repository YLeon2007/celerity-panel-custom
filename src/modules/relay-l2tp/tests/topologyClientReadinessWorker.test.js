'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { TopologyClientReadinessWorker } = require('../workers/topologyClientReadinessWorker');

const start = new Date('2026-09-30T10:00:00Z');
function fixture(overrides = {}) {
    const operation = { _id: 'op', status: 'succeeded', topologyRevision: 7,
        clientReadiness: 'unverified', clientProofAttempts: 0,
        clientProofRetryAfter: null, clientProofLeaseUntil: null,
        clientProofLeaseOwner: '', ...overrides };
    const live = { revision: 7, deployedRevision: 7 };
    const calls = [];
    const model = {
        async create() {},
        async findOneAndUpdate(query, update) {
            calls.push({ query, update });
            if (operation.status !== 'succeeded' || operation.clientReadiness !== 'unverified'
                || !Object.hasOwn(operation, 'clientProofAttempts')
                || operation.clientProofAttempts >= query.clientProofAttempts?.$lt
                || (operation.clientProofRetryAfter && operation.clientProofRetryAfter > query.$and?.[0]?.$or?.[0]?.clientProofRetryAfter?.$lte)
                || (operation.clientProofLeaseUntil && operation.clientProofLeaseUntil > query.$and?.[1]?.$or?.[0]?.clientProofLeaseUntil?.$lte)) return null;
            Object.assign(operation, update.$set);
            operation.clientProofAttempts += update.$inc.clientProofAttempts;
            return { ...operation };
        },
        async updateOne(query, update) {
            calls.push({ query, update });
            if (operation.status !== query.status || operation.clientReadiness !== query.clientReadiness
                || operation.clientProofLeaseOwner !== query.clientProofLeaseOwner
                || operation.clientProofAttempts !== query.clientProofAttempts
                || operation.topologyRevision !== query.topologyRevision
                || operation.clientProofLeaseUntil <= query.clientProofLeaseUntil.$gt) return { matchedCount: 0 };
            Object.assign(operation, update.$set);
            for (const key of Object.keys(update.$unset || {})) delete operation[key];
            return { matchedCount: 1 };
        },
        findById() { return { select() { return { lean: async () => ({ ...operation }) }; } }; },
    };
    const topologyStateModel = { findById() { return { select() { return { lean: async () => ({ ...live }) }; } }; } };
    const repository = new TopologyOperationRepository({ model, topologyStateModel });
    return { operation, live, calls, repository };
}
function worker(repository, probeOperation, extras = {}) {
    return new TopologyClientReadinessWorker({ repository, probeOperation,
        owner: 'worker-1', now: () => start, ...extras });
}

test('successful explicit client proof becomes verified only for live deployed revision', async () => {
    const f = fixture();
    const result = await worker(f.repository, async op => {
        assert.equal(op.topologyRevision, 7);
        assert.equal(op.status, 'succeeded');
        return { passed: true };
    }).runOnce();
    assert.equal(result, 'verified');
    assert.equal(f.operation.clientReadiness, 'verified');
    assert.equal(f.operation.clientProofRevision, 7);
    assert.equal((await f.repository.findPublicById('op')).clientReadiness, 'verified');
});

test('scoped autoDeploy proof stays verified when global deployed revision trails the draft', async () => {
    const f = fixture({ topologyRevision: 123, priorDeployedRevision: 111,
        kind: 'link.apply', linkId: 'link-1', linkIds: ['link-1'], staged: false });
    f.live.revision = 123;
    f.live.deployedRevision = 111;
    assert.equal(await worker(f.repository, async () => ({ passed: true })).runOnce(), 'verified');
    assert.equal((await f.repository.findPublicById('op')).clientReadiness, 'verified');
    f.live.deployedRevision = 112;
    assert.equal((await f.repository.findPublicById('op')).clientReadiness, 'unverified');
    f.live.deployedRevision = 111;
    f.live.revision = 124;
    assert.equal((await f.repository.findPublicById('op')).clientReadiness, 'unverified');
});

test('failed and unavailable probes retry after delay across worker restart without storing secrets', async () => {
    const f = fixture();
    const secret = 'secret-credential';
    const first = worker(f.repository, async () => { throw new Error(secret); });
    assert.equal(await first.runOnce(), 'unverified');
    assert.equal(f.operation.clientProofAttempts, 1);
    assert.equal(JSON.stringify(f.operation).includes(secret), false);
    assert.equal((await f.repository.findPublicById('op')).clientReadiness, 'unverified');
    assert.equal(await first.runOnce(), null);
    const after = new Date(f.operation.clientProofRetryAfter.getTime() + 1);
    const restarted = worker(f.repository, async () => ({ passed: false, error: secret }), { now: () => after });
    assert.equal(await restarted.runOnce(), 'unverified');
    assert.equal(f.operation.clientProofAttempts, 2);
    assert.equal(JSON.stringify(f.operation).includes(secret), false);
});

test('revision advancing during probe prevents verified CAS and public read fails closed afterward', async () => {
    const f = fixture();
    assert.equal(await worker(f.repository, async () => {
        f.live.revision = 8;
        return { passed: true };
    }).runOnce(), 'unverified');
    assert.notEqual(f.operation.clientReadiness, 'verified');
    f.live.revision = 7;
    f.live.deployedRevision = 7;
    const retryAt = new Date(f.operation.clientProofRetryAfter.getTime() + 1);
    assert.equal(await worker(f.repository, async () => ({ passed: true }),
        { now: () => retryAt }).runOnce(), 'verified');
    f.live.revision = 8;
    assert.equal((await f.repository.findPublicById('op')).clientReadiness, 'unverified');
});

test('concurrent workers cannot claim a second probe while the first holds its lease', async () => {
    const f = fixture();
    let finish;
    let probes = 0;
    const first = worker(f.repository, async () => {
        probes += 1;
        return new Promise(resolve => { finish = resolve; });
    });
    const running = first.runOnce();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(await worker(f.repository, async () => { probes += 1; return { passed: true }; }).runOnce(), null);
    finish({ passed: true });
    assert.equal(await running, 'verified');
    assert.equal(probes, 1);
});

test('legacy missing explicit proof fields and unrelated statuses are never scanned', async () => {
    for (const fields of [
        { clientReadiness: undefined },
        { clientProofAttempts: undefined },
        { status: 'committing' },
    ]) {
        const f = fixture(fields);
        assert.equal(await worker(f.repository, async () => { throw new Error('should not run'); }).runOnce(), null);
        assert.equal((await f.repository.findPublicById('op')).clientReadiness, 'unverified');
    }
});

test('unavailable injector exhausts bounded attempts and exposes only a safe degraded reason', async () => {
    const f = fixture();
    let current = start;
    const runner = worker(f.repository, undefined, { now: () => current });
    for (const expected of [1, 2, 3]) {
        assert.equal(await runner.runOnce(), 'unverified');
        assert.equal(f.operation.clientProofAttempts, expected);
        current = new Date(f.operation.clientProofRetryAfter.getTime() + 1);
    }
    assert.equal(await runner.runOnce(), null);
    assert.equal(f.operation.clientProofState, 'degraded');
    assert.deepEqual(await f.repository.findPublicById('op'), {
        status: 'succeeded', topologyRevision: 7, clientReadiness: 'unverified',
        clientProofState: 'degraded', clientProofReason: 'retry_exhausted',
    });
});

test('expired owner cannot publish a late proof after a new worker reclaims the operation', async () => {
    const f = fixture();
    const old = await f.repository.claimNextClientProof({ owner: 'old', now: start, leaseMs: 1000 });
    const later = new Date(start.getTime() + 1001);
    const claimed = await f.repository.claimNextClientProof({ owner: 'new', now: later, leaseMs: 1000 });
    assert.equal(claimed.clientProofAttempts, 2);
    assert.equal(await f.repository.completeClientProof({ operation: old, owner: 'old',
        now: later, passed: true }), null);
    assert.equal(f.operation.clientReadiness, 'unverified');
});
