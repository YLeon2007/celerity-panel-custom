'use strict';

const assert = require('assert');

process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'test.example.com';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'test@example.com';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || '01234567890123456789012345678901';

const provision = require('../src/services/accessLogs/provisionService');

const base = { _id: 'node1', type: 'xray' };
assert.strictEqual(provision.isEligibleNode({ ...base, cascadeRole: 'standalone' }), true);
assert.strictEqual(provision.isEligibleNode({ ...base, cascadeRole: 'portal' }), true);
assert.strictEqual(provision.isEligibleNode({ ...base, cascadeRole: 'bridge' }), true,
    'bridge nodes must be eligible for xray-bridge access logs');
assert.strictEqual(provision.isEligibleNode({ ...base, cascadeRole: 'relay' }), false);
assert.strictEqual(provision.isEligibleNode({ ...base, type: 'hysteria', cascadeRole: 'bridge' }), false);
assert.strictEqual(provision.accessLogPathForNode({ ...base, cascadeRole: 'bridge' }), '/var/log/xray-bridge/access.log');
assert.strictEqual(provision.accessLogPathForNode({ ...base, cascadeRole: 'portal' }), '/var/log/xray/access.log');

const nodeSetupSource = require('fs').readFileSync(require.resolve('../src/services/nodeSetup'), 'utf8');
assert.ok(!nodeSetupSource.includes('rm -f /usr/local/bin/cc-agent\nARCH='),
    'agent setup must not delete the existing binary before download verification');
assert.ok(nodeSetupSource.includes('cc-agent.new') && nodeSetupSource.includes('SHA256SUMS'),
    'agent setup must download atomically and verify the release checksum');
assert.ok(nodeSetupSource.includes('existing cc-agent was preserved'),
    'agent setup download failures must explicitly preserve the previous binary');

const source = require('fs').readFileSync(require.resolve('../src/services/accessLogs/provisionService'), 'utf8');
assert.ok(source.includes("systemctl restart xray-bridge"), 'bridge reconciliation must restart xray-bridge');
assert.ok(source.includes("mode: { $ne: 'forward' }"), 'bridge reconciliation must preserve all active reverse links');

console.log('access logs bridge eligibility test passed');
