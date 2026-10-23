'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { TopologyClientReadinessWorker } = require('../workers/topologyClientReadinessWorker');

const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const start = new Date('2026-09-30T10:00:00Z');
const key = (context, revision = 7) => `topology:${context.target}:revision-${revision}:host-${context.hostIdentity}:00000000-0000-0000-0000-000000000000`;

test('client-proof worker requires an exact canonical execution context without a TEST default', () => {
    const repository = { async claimNextClientProof() {}, async completeClientProof() {} };
    for (const executionContext of [undefined, null, {}, { target: 'test', hostIdentity: PROD.hostIdentity },
        { ...TEST, extra: true }, { ...PROD, extra: true }]) {
        assert.throws(() => new TopologyClientReadinessWorker({ repository, executionContext }), /execution context/i);
    }
});

test('client-proof worker snapshots canonical frozen TEST and PROD identities across caller mutation', async () => {
    for (const context of [TEST, PROD]) {
        const source = { ...context };
        const calls = [];
        const repository = {
            async claimNextClientProof(input) {
                calls.push(input.executionContext);
                Object.assign(source, context === TEST ? PROD : TEST);
                return { _id: 'op', executionContext: { ...context }, idempotencyKey: key(context),
                    topologyRevision: 7, status: 'succeeded', clientReadiness: 'unverified',
                    clientProofAttempts: 1, clientProofLeaseOwner: 'worker-1',
                    clientProofLeaseUntil: new Date(start.getTime() + 120000) };
            },
            async completeClientProof(input) { calls.push(input.executionContext); return 'verified'; },
        };
        const runner = worker(repository, async () => ({ passed: true }), { executionContext: source });
        assert.strictEqual(runner.executionContext, context);
        assert.ok(Object.isFrozen(runner.executionContext));
        assert.equal(await runner.runOnce(), 'verified');
        assert.deepEqual(calls, [context, context]);
        assert.ok(calls.every(value => value === context));
    }
});
function claimed(context, overrides = {}) {
    return { _id: 'op', executionContext: { ...context }, idempotencyKey: key(context), topologyRevision: 7,
        status: 'succeeded', clientReadiness: 'unverified', clientProofAttempts: 1,
        clientProofLeaseOwner: 'worker-1', clientProofLeaseUntil: new Date(start.getTime() + 120000), ...overrides };
}
function rejectedRows(context) {
    const foreign = context === TEST ? PROD : TEST;
    return [
        { executionContext: undefined }, { executionContext: foreign, idempotencyKey: key(foreign) },
        { executionContext: { ...context, extra: true } }, { executionContext: [{ ...context }] },
        { executionContext: { target: context.target, hostIdentity: foreign.hostIdentity } },
        { idempotencyKey: undefined }, { idempotencyKey: key(context, 8) },
        { idempotencyKey: key(context) + '\n' }, { idempotencyKey: [key(context)] },
        { idempotencyKey: key(context).replace(':host-', ':unexpected:host-') },
        { topologyRevision: '7' }, { topologyRevision: [7] }, { topologyRevision: 7.5 },
        { status: 'queued' }, { clientReadiness: undefined }, { clientReadiness: 'verified' },
        { kind: 'link.apply', staged: true }, { clientProofAttempts: undefined },
        { clientProofAttempts: 0 }, { clientProofAttempts: 4 }, { clientProofAttempts: 1.5 },
        { clientProofLeaseOwner: 'foreign' }, { clientProofLeaseUntil: start },
        { clientProofLeaseUntil: undefined }, { clientProofLeaseUntil: start.toISOString() },
    ];
}

test('bad client-proof claim adapters cannot probe or complete ineligible or malformed returned rows', async () => {
    for (const context of [TEST, PROD]) {
        for (const overrides of rejectedRows(context)) {
            let probes = 0;
            let completions = 0;
            const repository = { async claimNextClientProof() { return claimed(context, overrides); },
                async completeClientProof() { completions += 1; } };
            assert.equal(await worker(repository, async () => { probes += 1; }, { executionContext: context }).runOnce(), null,
                JSON.stringify(overrides));
            assert.equal(probes, 0);
            assert.equal(completions, 0);
        }
    }
});

test('client-proof binding and lease are rechecked after awaited claim and probe boundaries', async () => {
    for (const boundary of ['claim', 'probe']) {
        for (const change of ['expired', 'foreign', 'malformed']) {
            let current = start;
            const operation = claimed(TEST);
            let probes = 0;
            let completions = 0;
            const mutate = () => {
                if (change === 'expired') current = new Date(start.getTime() + 120000);
                if (change === 'foreign') Object.assign(operation, { executionContext: PROD, idempotencyKey: key(PROD) });
                if (change === 'malformed') operation.idempotencyKey += '\n';
            };
            const repository = {
                async claimNextClientProof() { await Promise.resolve(); if (boundary === 'claim') mutate(); return operation; },
                async completeClientProof() { completions += 1; },
            };
            assert.equal(await worker(repository, async () => {
                probes += 1; await Promise.resolve(); mutate(); return { passed: true };
            }, { now: () => current }).runOnce(), null, `${boundary}/${change}`);
            assert.equal(probes, boundary === 'claim' ? 0 : 1);
            assert.equal(completions, 0);
        }
    }
});

test('client-proof repository refuses invalid contexts and returned bindings before state reads or writes', async () => {
    let accesses = 0;
    const repository = new TopologyOperationRepository({ model: {
        async create() {}, async findOneAndUpdate() { accesses += 1; }, async updateOne() { accesses += 1; return { matchedCount: 1 }; },
    }, topologyStateModel: { findById() { accesses += 1; throw Error('must not read'); } } });
    for (const executionContext of [undefined, {}, { ...TEST, extra: true }, { target: TEST.target, hostIdentity: PROD.hostIdentity }]) {
        await assert.rejects(repository.claimNextClientProof({ executionContext, owner: 'worker-1', now: start }), /execution context/i);
        await assert.rejects(repository.completeClientProof({ operation: claimed(TEST), executionContext,
            owner: 'worker-1', now: start, passed: true }), /execution context/i);
    }
    for (const overrides of rejectedRows(TEST)) {
        assert.equal(await repository.completeClientProof({ operation: claimed(TEST, overrides), executionContext: TEST,
            owner: 'worker-1', now: start, passed: true }), null, JSON.stringify(overrides));
    }
    assert.equal(accesses, 0);
});

test('client-proof completion refuses a lease that expires during the awaited live revision read', async () => {
    let current = start;
    let updates = 0;
    const repository = new TopologyOperationRepository({ model: {
        async create() {}, async findOneAndUpdate() {}, async updateOne() { updates += 1; return { matchedCount: 1 }; },
    }, topologyStateModel: { findById() { return { select() { return { async lean() {
        await Promise.resolve(); current = new Date(start.getTime() + 120000);
        return { revision: 7, deployedRevision: 7 };
    } }; } }; } } });
    assert.equal(await repository.completeClientProof({ operation: claimed(TEST), executionContext: TEST,
        owner: 'worker-1', now: start, getNow: () => current, passed: true }), null);
    assert.equal(updates, 0);
});

test('client-proof claim projects execution binding and every proof eligibility field without secrets', async () => {
    let projection;
    const repository = new TopologyOperationRepository({ model: {
        async create() {}, async updateOne() {},
        async findOneAndUpdate(_filter, _update, options) { projection = options.projection; return null; },
    } });
    await repository.claimNextClientProof({ executionContext: TEST, owner: 'worker-1', now: start });
    for (const field of ['executionContext', 'idempotencyKey', 'staged', 'clientReadiness',
        'heldTopologyAdmission', 'pppWait', 'oldLinkId', 'oldPathLinkIds', 'groupId', 'pathKey',
        'ownerNodeId', 'ownerTopologyRevision', 'ownerCredentialRevision', 'newPathLinkIds']) {
        assert.equal(projection[field], 1, field);
    }
    assert.equal(Object.keys(projection).some(field => /candidate|backup|secret|credential(?!Revision)/i.test(field)), false);
});

function fixture(overrides = {}) {
    const operation = { _id: 'op', status: 'succeeded', topologyRevision: 7,
        executionContext: { ...TEST }, idempotencyKey: key(TEST, overrides.topologyRevision ?? 7),
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
        owner: 'worker-1', now: () => start, executionContext: TEST, ...extras });
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
    const old = await f.repository.claimNextClientProof({ executionContext: TEST, owner: 'old', now: start, leaseMs: 1000 });
    const later = new Date(start.getTime() + 1001);
    const claimed = await f.repository.claimNextClientProof({ executionContext: TEST, owner: 'new', now: later, leaseMs: 1000 });
    assert.equal(claimed.clientProofAttempts, 2);
    assert.equal(await f.repository.completeClientProof({ operation: old, owner: 'old', executionContext: TEST,
        now: later, passed: true }), null);
    assert.equal(f.operation.clientReadiness, 'unverified');
});
