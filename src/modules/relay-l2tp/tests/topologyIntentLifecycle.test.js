'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTopologyOperationRecoveryLifecycle } = require('../runtime/createTopologyOperationRecoveryLifecycle');
const env = { L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
test('intent transactions explicitly require primary snapshot reads and majority commit acknowledgement', async () => {
    const { TopologyIntentService } = require('../services/topologyIntentService');
    const { TopologyIntentConsumer } = require('../services/topologyIntentConsumer');
    const options = [];
    const db = { transaction(work, settings) { options.push(settings); return work({}); } };
    const dependencies = Object.fromEntries(['CascadeTopologyState', 'TopologyCreateIntent', 'TopologyIntentQueueState',
        'TopologyOperation', 'HyNode', 'CascadeLink', 'CascadeRouteGroup', 'RelayL2tpState'].map(name => [name, { db }]));
    await new TopologyIntentService(dependencies).transactionRunner(async () => undefined);
    await new TopologyIntentConsumer(dependencies).transactionRunner(async () => undefined);
    assert.deepEqual(options, Array.from({ length: 2 }, () => ({ readConcern: { level: 'snapshot' },
        writeConcern: { w: 'majority' }, readPreference: 'primary' })));
});
test('the opt-in supervised startup consumes intents before scanning operations and stop joins its admitted transaction', async () => {
    let unblock; const gate = new Promise(resolve => { unblock = resolve; });
    const trace = []; let tick; let scheduled = 0;
    const lifecycle = createTopologyOperationRecoveryLifecycle({ env,
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
