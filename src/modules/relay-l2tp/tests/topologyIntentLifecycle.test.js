'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTopologyOperationRecoveryLifecycle } = require('../runtime/createTopologyOperationRecoveryLifecycle');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT } = require('../domain/topologyExecutionContext');
const TEST_CONTEXT = TEST_TOPOLOGY_EXECUTION_CONTEXT;
test('intent admission and consumption reject missing or cross-paired server contexts before persistence', () => {
    const { TopologyIntentService } = require('../services/topologyIntentService');
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const db = {};
    const models = Object.fromEntries(['CascadeTopologyState', 'TopologyCreateIntent', 'TopologyIntentQueueState',
        'TopologyOperation', 'HyNode', 'CascadeLink', 'CascadeRouteGroup', 'RelayL2tpState'].map(name => [name, { db }]));
    for (const executionContext of [undefined, null, {}, { target: 'production' },
        { target: 'production', hostIdentity: 'test.infograd.online' },
        { target: 'test', hostIdentity: 'lm1.infograd.online' }]) {
        for (const Constructor of [TopologyIntentService, TopologyIntentConsumer]) {
            assert.throws(() => new Constructor({ ...models, executionContext }), /requires an exact server execution context/);
        }
    }
});
const env = { PANEL_DOMAIN: TEST_TOPOLOGY_EXECUTION_CONTEXT.hostIdentity,
    L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
test('intent transactions explicitly require primary snapshot reads and majority commit acknowledgement', async () => {
    const { TopologyIntentService } = require('../services/topologyIntentService');
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const options = [];
    const db = { transaction(work, settings) { options.push(settings); return work({}); } };
    const dependencies = Object.fromEntries(['CascadeTopologyState', 'TopologyCreateIntent', 'TopologyIntentQueueState',
        'TopologyOperation', 'HyNode', 'CascadeLink', 'CascadeRouteGroup', 'RelayL2tpState'].map(name => [name, { db }]));
    dependencies.executionContext = TEST_CONTEXT;
    await new TopologyIntentService(dependencies).transactionRunner(async () => undefined);
    await new TopologyIntentConsumer(dependencies).transactionRunner(async () => undefined);
    assert.deepEqual(options, Array.from({ length: 2 }, () => ({ readConcern: { level: 'snapshot' },
        writeConcern: { w: 'majority' }, readPreference: 'primary' })));
});
test('ambiguous intent acceptance explicitly confirms on the primary outside the transaction', async () => {
    const { TopologyIntentService, digest } = require('../services/topologyIntentService');
    const payload = { name: 'local-only', tunnelUuid: 'not-public' };
    const row = { executionContext: { target: 'test', hostIdentity: 'test.infograd.online' }, _id: 'intent-1', payloadHash: digest(payload), payload, status: 'waiting', acceptanceRevision: 7 };
    const db = {};
    const calls = [];
    class CascadeLink {
        static db = db;
        async validate() {}
        toObject() { return payload; }
    }
    const query = {
        session(value) { calls.push(['session', value]); return this; },
        readConcern(value) { calls.push(['readConcern', value]); return this; },
        read(value) { calls.push(['read', value]); return this; },
        maxTimeMS(value) { calls.push(['maxTimeMS', value]); return this; },
        async lean() { calls.push(['lean']); return row; },
    };
    const service = new TopologyIntentService({ executionContext: TEST_CONTEXT, CascadeLink,
        CascadeTopologyState: { db }, TopologyIntentQueueState: { db },
        TopologyCreateIntent: { db, findOne(filter) { calls.push(['findOne', filter]); return query; } },
        transactionRunner: async () => { throw { hasErrorLabel: label => label === 'UnknownTransactionCommitResult' }; },
    });
    const job = await service.accept({ expectedTopologyRevision: 7, requestKey: 'exact-key', link: payload });
    assert.deepEqual(calls, [['findOne', { requestKey: 'exact-key' }], ['session', null],
        ['readConcern', 'majority'], ['read', 'primary'], ['maxTimeMS', 5000], ['lean']]);
    assert.equal(job.jobId, 'intent-1');
    assert.equal(JSON.stringify(job).includes(payload.tunnelUuid), false);
});
test('the opt-in supervised startup consumes intents before scanning operations and stop joins its admitted transaction', async () => {
    let unblock; const gate = new Promise(resolve => { unblock = resolve; });
    const trace = []; let tick; let scheduled = 0;
    const lifecycle = createTopologyOperationRecoveryLifecycle({ env, executionContext: TEST_TOPOLOGY_EXECUTION_CONTEXT,
        timer: { setInterval(fn) { scheduled++; tick = fn; return 1; }, clearInterval() { trace.push('timer.stop'); } },
        intentConsumer: { async runOnce() { trace.push('intent.begin'); await gate; trace.push('intent.end'); } },
        operationModel: { find() { trace.push('operation.scan'); return { select() { return this; }, sort() { return this; }, limit() { return this; }, lean: async () => [] }; } },
        worker: { async run() { throw Error('no operations'); } },
    });
    assert.equal(scheduled, 0); assert.deepEqual(trace, []);
    lifecycle.start(); await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(trace, ['intent.begin']);
    let stopped = false; const pending = lifecycle.stop().then(() => { stopped = true; });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(stopped, false, 'stop cannot abandon the admitted intent mutation');
    unblock(); await pending;
    assert.deepEqual(trace, ['intent.begin', 'timer.stop', 'intent.end', 'operation.scan']);
    await tick(); assert.equal(trace.filter(value => value === 'intent.begin').length, 1);
    assert.equal(lifecycle.start().running, false, 'a stopped consumer must not reopen admission');
});
