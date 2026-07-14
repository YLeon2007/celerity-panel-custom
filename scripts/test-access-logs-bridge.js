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

console.log('access logs bridge eligibility test passed');
