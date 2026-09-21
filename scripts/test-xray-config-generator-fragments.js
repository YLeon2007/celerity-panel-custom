'use strict';

process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'panel.example.test';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'test@example.test';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || '01234567890123456789012345678901';

const assert = require('node:assert/strict');
const test = require('node:test');

const { generateXrayConfig } = require('../src/services/configGenerator');

function baseNode() {
    return {
        port: 443,
        xray: {
            apiPort: 61000,
            inboundTag: 'vless-in',
            transport: 'tcp',
            security: 'none',
        },
        outbounds: [],
        aclRules: [],
    };
}

const users = [{
    xrayUuid: '00000000-0000-4000-8000-000000000001',
    userId: 'test-user',
}];

function canonicalFragment(overrides = {}) {
    return {
        id: 'relay-l2tp',
        inbounds: [{
            tag: 'relay-l2tp-in',
            listen: '127.0.0.1',
            port: 12345,
            protocol: 'dokodemo-door',
            settings: { network: 'tcp,udp' },
        }],
        outbounds: [{
            tag: 'relay-l2tp-out',
            protocol: 'blackhole',
        }],
        routingRules: [{
            type: 'field',
            inboundTag: ['relay-l2tp-in'],
            outboundTag: 'relay-l2tp-out',
        }],
        ...overrides,
    };
}

test('canonical fragments contribute Xray inbounds, outbounds, and routing rules', () => {
    const config = JSON.parse(generateXrayConfig(baseNode(), users, {
        fragments: [canonicalFragment()],
    }));

    assert(config.inbounds.some(inbound => inbound.tag === 'relay-l2tp-in'));
    assert(config.outbounds.some(outbound => outbound.tag === 'relay-l2tp-out'));
    assert(config.routing.rules.some(rule => (
        rule.outboundTag === 'relay-l2tp-out'
        && rule.inboundTag?.includes('relay-l2tp-in')
    )));
});

test('omitting fragments preserves legacy generator semantics byte for byte', () => {
    const legacyNode = baseNode();
    legacyNode.outbounds = [{
        type: 'socks5',
        name: 'direct',
        addr: '127.0.0.1:1080',
    }];

    const legacyOutput = generateXrayConfig(legacyNode, users);
    const emptyFragmentOutput = generateXrayConfig(legacyNode, users, { fragments: [] });

    assert.equal(emptyFragmentOutput, legacyOutput);
    assert.equal(
        JSON.parse(legacyOutput).outbounds.filter(outbound => outbound.tag === 'direct').length,
        2,
    );
});

test('fragment collisions surface the structured composer error before serialization', () => {
    const collidingFragment = canonicalFragment({
        inbounds: [{
            tag: 'API_INBOUND',
            listen: '127.0.0.1',
            port: 62000,
            protocol: 'dokodemo-door',
            settings: { network: 'tcp' },
        }],
    });

    assert.throws(
        () => generateXrayConfig(baseNode(), users, { fragments: [collidingFragment] }),
        {
            name: 'XrayConfigComposerError',
            code: 'DUPLICATE_INBOUND_TAG',
            tag: 'API_INBOUND',
        },
    );
});
