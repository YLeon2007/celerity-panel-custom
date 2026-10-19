'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createTopologyOperationRecoveryLifecycle, recoveryFilter } = require('../runtime/createTopologyOperationRecoveryLifecycle');
const {
    TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST,
    PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD,
} = require('../domain/topologyExecutionContext');

const envFor = context => ({
    PANEL_DOMAIN: context.hostIdentity,
    L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true',
    [context === TEST ? 'TOPOLOGY_TEST_EXECUTION_ENABLED' : 'TOPOLOGY_PRODUCTION_EXECUTION_ENABLED']: 'true',
});
const now = new Date('2026-10-19T12:00:00.000Z');

function fixture({ context = PROD, env = envFor(context), rows = [] } = {}) {
    const calls = [];
    const lifecycle = createTopologyOperationRecoveryLifecycle({
        env, executionContext: context,
        operationModel: {
            find(filter) {
                calls.push({ method: 'find', filter });
                const query = {
                    select(projection) { calls.push({ method: 'select', projection }); return query; },
                    sort() { return query; }, limit() { return query; },
                    async lean() { return rows; },
                };
                return query;
            },
            updateOne() { assert.fail('recovery must not rewrite a row'); },
            deleteOne() { assert.fail('recovery must not release a row'); },
        },
        worker: { async run(id) { calls.push({ method: 'run', id }); } },
        clientProofWorker: { async runOnce() { calls.push({ method: 'proof' }); } },
        intentConsumer: { async runOnce() { calls.push({ method: 'intent' }); } },
        timer: { setInterval() { return {}; }, clearInterval() {} },
        clock: { now: () => now },
    });
    return { lifecycle, calls };
}

const queued = (id, context) => ({ _id: id, status: 'queued', executionContext: context });

test('standalone recovery filters cannot be built without a canonical host context', () => {
    for (const context of [undefined, null, { ...PROD }, { ...TEST }]) {
        assert.throws(() => recoveryFilter(now, context), TypeError);
    }
    assert.deepEqual(recoveryFilter(now, PROD), {
        executionContext: { ...PROD },
        $or: [
            { status: 'queued' },
            { status: { $in: ['preparing', 'committing', 'rolling_back'] }, leaseUntil: { $lte: now } },
        ],
    });
});

test('production recovery requires production opt-in, never the TEST flag', async () => {
    const env = { ...envFor(TEST), PANEL_DOMAIN: PROD.hostIdentity };
    const { lifecycle, calls } = fixture({ env, rows: [queued('prod', { ...PROD })] });
    assert.equal(lifecycle.start().enabled, false);
    await lifecycle.stop();
    assert.deepEqual(calls, []);
});

test('canonical production recovery scans and dispatches its persisted bound row without TEST opt-in', async () => {
    const { lifecycle, calls } = fixture({ rows: [queued('prod', { ...PROD })] });
    assert.equal(lifecycle.start().enabled, true);
    await lifecycle.stop();
    assert.deepEqual(calls.filter(call => call.method === 'run'), [{ method: 'run', id: 'prod' }]);
    assert.deepEqual(calls.find(call => call.method === 'find').filter.executionContext, PROD);
    assert.match(calls.find(call => call.method === 'select').projection, /\bexecutionContext\b/);
    assert.equal(calls.some(call => call.method === 'proof'), false,
        'unscoped client-proof claim queue must not run in production');
});

test('production recovery never claims the separate client-proof queue even with both flags enabled', async () => {
    const env = { ...envFor(PROD), TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
    const { lifecycle, calls } = fixture({ env, rows: [
        { ...queued('unbound-proof', undefined), status: 'succeeded', clientReadiness: 'unverified' },
        { ...queued('foreign-proof', { ...TEST }), status: 'succeeded', clientReadiness: 'unverified' },
    ] });
    lifecycle.start();
    await lifecycle.stop();
    assert.equal(calls.some(call => call.method === 'proof' || call.method === 'run'), false);
});

test('missing, cloned, cross-paired and env-mismatched host contexts are dormant before dependency reads', async () => {
    for (const context of [undefined, null, { ...PROD }, Object.freeze({ ...PROD }),
        { target: 'test', hostIdentity: PROD.hostIdentity }, TEST]) {
        let reads = 0;
        const lifecycle = createTopologyOperationRecoveryLifecycle({
            env: envFor(PROD), executionContext: context,
            get operationModel() { reads += 1; assert.fail('must not inspect persistence'); },
            get worker() { reads += 1; assert.fail('must not inspect worker'); },
        });
        assert.equal(lifecycle.start().enabled, false);
        assert.equal((await lifecycle.stop()).enabled, false);
        assert.equal(reads, 0);
    }
});

test('each host context requires every matching opt-in flag with exact string values', async () => {
    for (const context of [TEST, PROD]) {
        for (const key of Object.keys(envFor(context))) {
            for (const value of [undefined, false, true, 'TRUE', 'false']) {
                const env = { ...envFor(context), [key]: value };
                const { lifecycle, calls } = fixture({ context, env });
                assert.equal(lifecycle.start().enabled, false, `${context.target}:${key}:${value}`);
                await lifecycle.stop();
                assert.deepEqual(calls, []);
            }
        }
    }
});

test('queued and expired PPP recovery reject missing and foreign persisted identity before worker side effects', async () => {
    for (const context of [TEST, PROD]) {
        const foreign = context === TEST ? PROD : TEST;
        const rows = [
            queued('bound', { ...foreign }), // must not poison deduplication
            queued('bound', { ...context }),
            queued('extra-field', { ...context, untrusted: true }),
            queued('unbound', undefined), queued('null', null), queued('foreign', { ...foreign }),
            queued('cross', { target: context.target, hostIdentity: foreign.hostIdentity }),
            queued('clone-host', { target: context.target, hostIdentity: `${context.hostIdentity}.clone` }),
            queued('partial', { target: context.target }),
            queued('array', [{ ...context }]),
            ...[undefined, foreign, { target: foreign.target, hostIdentity: context.hostIdentity }].map((pair, i) => ({
                _id: `foreign-ppp-${i}`, status: 'committing', executionContext: pair,
                leaseUntil: new Date(now.getTime() - 1), pppWait: { relayNode: 'relay' },
                heldTopologyAdmission: true,
            })),
            { _id: 'bound-ppp', status: 'committing', executionContext: { ...context },
                leaseUntil: new Date(now.getTime() - 1), pppWait: { relayNode: 'relay' },
                heldTopologyAdmission: true },
        ];
        const before = structuredClone(rows);
        const { lifecycle, calls } = fixture({ context, rows });
        lifecycle.start();
        await lifecycle.stop();
        assert.deepEqual(calls.filter(call => call.method === 'run').map(call => call.id), ['bound', 'bound-ppp']);
        assert.deepEqual(calls.find(call => call.method === 'find').filter.executionContext, context);
        assert.deepEqual(rows, before, 'foreign ownership and admissions must remain untouched');
    }
});

test('selected recovery identity cannot change after source environment mutation', async () => {
    const env = envFor(PROD);
    const { lifecycle, calls } = fixture({ env, rows: [queued('prod', { ...PROD }), queued('test', { ...TEST })] });
    Object.assign(env, envFor(TEST));
    env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED = 'false';
    lifecycle.start();
    await lifecycle.stop();
    assert.deepEqual(calls.filter(call => call.method === 'run'), [{ method: 'run', id: 'prod' }]);
    assert.equal(calls.some(call => call.method === 'proof'), false);
});
