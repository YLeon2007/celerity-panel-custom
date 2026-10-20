'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../src/modules/relay-l2tp/domain/topologyExecutionContext');
const env = { PANEL_DOMAIN: TEST.hostIdentity, L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
const entry = () => require('./test-topology-owner');
test('explicit TEST owner entry refuses missing durable capture before any model/store access', async () => {
    assert.equal(typeof entry().enrollTestOwners, 'function');
    let writes = 0;
    await assert.rejects(entry().enrollTestOwners({ env,
        lifecycle: { run: work => work() },
        store: { preEnroll() { writes++; } },
        TopologyConfigOwner: { create() { writes++; } },
    }), /TEST_DURABLE_ORIGINALS_CAPTURE_REQUIRED/);
    assert.equal(writes, 0);
});
test('wrong host, production opt-in and missing TEST opt-in refuse before held authority', async () => {
    for (const patch of [{ PANEL_DOMAIN: 'lm1.infograd.online' }, { TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' },
        { L2TP_PRODUCTION_EXECUTION_ENABLED: 'true' }, { TOPOLOGY_TEST_EXECUTION_ENABLED: undefined }]) {
        let held = 0;
        await assert.rejects(entry().enrollTestOwners({ env: { ...env, ...patch },
            lifecycle: { run() { held++; } } }), /TEST_OWNER_CONTEXT_REQUIRED/);
        assert.equal(held, 0);
    }
});
test('CLI has a finite explicit verb and never accepts node IDs, JSON receipts or config paths', () => {
    for (const args of [[], ['startup'], ['enroll', '--node-id', '6ab18adc63913ebd4a917471'], ['enroll', '--config', '/tmp/pins.json']]) {
        const result = spawnSync(process.execPath, [path.join(__dirname, 'test-topology-owner.js'), ...args], { encoding: 'utf8' });
        assert.equal(result.status, 2);
        assert.match(result.stderr, /Usage: node scripts\/test-topology-owner.js enroll/);
        assert.equal(result.stdout, '');
    }
});
