'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { after } = require('node:test');

process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
const syncService = require('../syncService');
const sshPool = require('../sshPoolService');
after(() => sshPool.closeAll());

const FLAGS = ['L2TP_EXECUTION_ENABLED', 'L2TP_MIGRATIONS_ENABLED', 'TOPOLOGY_TEST_EXECUTION_ENABLED'];
function withFlags(values, fn) {
    const prior = FLAGS.map(k => process.env[k]);
    try {
        FLAGS.forEach((k, i) => { if (values[i]) process.env[k] = 'true'; else delete process.env[k]; });
        fn();
    } finally {
        FLAGS.forEach((k, i) => { if (prior[i] === undefined) delete process.env[k]; else process.env[k] = prior[i]; });
    }
}

test('topology owns full Xray config only for cascade roles with every live-test flag enabled', () => {
    withFlags([true, true, true], () => {
        for (const role of ['portal', 'relay', 'bridge']) assert.equal(syncService._topologyManagesNode({ cascadeRole: role }), true);
        assert.equal(syncService._topologyManagesNode({ cascadeRole: 'standalone' }), false);
    });
    for (let i = 0; i < FLAGS.length; i++) {
        const flags = [true, true, true]; flags[i] = false;
        withFlags(flags, () => {
            for (const role of ['portal', 'relay', 'bridge']) assert.equal(syncService._topologyManagesNode({ cascadeRole: role }), false);
        });
    }
});
