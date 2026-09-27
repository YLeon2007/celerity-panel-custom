'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
// The panel config validates environment at import; no live credentials or DB needed.
process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
const HyNode = require('../../models/hyNodeModel');
const { parseXrayFormFields, parseExtraInbounds } = require('../panel/helpers');

const root = path.resolve(__dirname, '../../..');

test('new Xray node and extra inbound use literal random by default, explicit value survives', () => {
    const node = new HyNode({ type: 'xray', name: 'test', ip: '127.0.0.1', xray: {
        extraInbounds: [{ id: 'extra1', port: 8443, inboundTag: 'extra1' }],
    } });
    assert.equal(node.xray.fingerprint, 'random');
    assert.equal(node.xray.extraInbounds[0].fingerprint, 'random');
    node.xray.fingerprint = 'firefox';
    assert.equal(node.xray.fingerprint, 'firefox');
});

test('blank fingerprint in a direct API/MCP create has the same default as omission', () => {
    const node = new HyNode({ type: 'xray', name: 'blank', ip: '127.0.0.1', xray: {
        fingerprint: '',
        extraInbounds: [{ id: 'extra1', port: 8443, inboundTag: 'extra1', fingerprint: '' }],
    } });
    assert.equal(node.xray.fingerprint, 'random');
    assert.equal(node.xray.extraInbounds[0].fingerprint, 'random');

    const legacy = HyNode.hydrate({ type: 'xray', name: 'legacy', ip: '127.0.0.1', xray: {
        fingerprint: '', extraInbounds: [{ id: 'extra1', port: 8443, inboundTag: 'extra1', fingerprint: '' }],
    } });
    assert.equal(legacy.xray.fingerprint, '', 'reading a saved legacy node does not rewrite it');
    assert.equal(legacy.xray.extraInbounds[0].fingerprint, '', 'reading a saved legacy inbound does not rewrite it');
});

test('form parser defaults an omitted extra inbound fingerprint and keeps an explicit main value', () => {
    const extras = parseExtraInbounds({
        xray_extra_id: 'e1', xray_extra_port: '8443', xray_extra_inboundTag: 'e1',
    });
    assert.equal(extras[0].fingerprint, 'random');
    assert.equal(parseXrayFormFields({ 'xray.fingerprint': 'safari' }).fingerprint, 'safari');
});

test('new node and wizard forms preselect Random, not Chrome', () => {
    const form = fs.readFileSync(path.join(root, 'views/partials/node-form/xray.ejs'), 'utf8');
    const wizard = fs.readFileSync(path.join(root, 'views/wizard.ejs'), 'utf8');
    assert.match(form, /!node\?\.xray\?\.fingerprint && f === 'random'/);
    assert.match(wizard, /<option value="random" selected>Random<\/option>/);
    assert.doesNotMatch(wizard, /<option value="chrome" selected>/);
});
