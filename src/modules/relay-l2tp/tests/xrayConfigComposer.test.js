'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { composeXrayConfig } = require('../services/xrayConfigComposer');

test('appends fragment collections in fragment id order', () => {
    const baseConfig = {
        inbounds: [{ tag: 'base-in', listen: '127.0.0.1', port: 1000 }],
        outbounds: [{ tag: 'base-out', protocol: 'freedom' }],
        routing: { domainStrategy: 'AsIs', rules: [{ id: 'base-rule' }] },
    };
    const fragments = [
        {
            id: 'zeta',
            inbounds: [{ tag: 'zeta-in', listen: '127.0.0.1', port: 3000 }],
            outbounds: [{ tag: 'zeta-out', protocol: 'blackhole' }],
            routingRules: [{ id: 'zeta-rule' }],
        },
        {
            id: 'alpha',
            inbounds: [{ tag: 'alpha-in', listen: '127.0.0.1', port: 2000 }],
            outbounds: [{ tag: 'alpha-out', protocol: 'freedom' }],
            routingRules: [{ id: 'alpha-rule' }],
        },
    ];

    assert.deepEqual(composeXrayConfig(baseConfig, fragments), {
        inbounds: [
            { tag: 'base-in', listen: '127.0.0.1', port: 1000 },
            { tag: 'alpha-in', listen: '127.0.0.1', port: 2000 },
            { tag: 'zeta-in', listen: '127.0.0.1', port: 3000 },
        ],
        outbounds: [
            { tag: 'base-out', protocol: 'freedom' },
            { tag: 'alpha-out', protocol: 'freedom' },
            { tag: 'zeta-out', protocol: 'blackhole' },
        ],
        routing: {
            domainStrategy: 'AsIs',
            rules: [
                { id: 'base-rule' },
                { id: 'alpha-rule' },
                { id: 'zeta-rule' },
            ],
        },
    });
});

test('rejects duplicate inbound tags with a structured error', () => {
    const baseConfig = {
        inbounds: [{ tag: 'shared-in', listen: '127.0.0.1', port: 1000 }],
        outbounds: [],
        routing: { rules: [] },
    };
    const fragments = [{
        id: 'relay-l2tp',
        inbounds: [{ tag: 'shared-in', listen: '127.0.0.1', port: 2000 }],
        outbounds: [],
        routingRules: [],
    }];

    assert.throws(
        () => composeXrayConfig(baseConfig, fragments),
        {
            name: 'XrayConfigComposerError',
            code: 'DUPLICATE_INBOUND_TAG',
            tag: 'shared-in',
        },
    );
});

test('rejects duplicate outbound tags with a structured error', () => {
    const baseConfig = { inbounds: [], outbounds: [], routing: { rules: [] } };
    const fragments = [
        {
            id: 'zeta',
            inbounds: [],
            outbounds: [{ tag: 'shared-out', protocol: 'blackhole' }],
            routingRules: [],
        },
        {
            id: 'alpha',
            inbounds: [],
            outbounds: [{ tag: 'shared-out', protocol: 'freedom' }],
            routingRules: [],
        },
    ];

    assert.throws(
        () => composeXrayConfig(baseConfig, fragments),
        {
            name: 'XrayConfigComposerError',
            code: 'DUPLICATE_OUTBOUND_TAG',
            tag: 'shared-out',
        },
    );
});

test('rejects duplicate inbound listeners with a structured error', () => {
    const baseConfig = {
        inbounds: [{ tag: 'base-in', listen: '0.0.0.0', port: 443 }],
        outbounds: [],
        routing: { rules: [] },
    };
    const fragments = [{
        id: 'relay-l2tp',
        inbounds: [{ tag: 'l2tp-in', listen: '0.0.0.0', port: 443 }],
        outbounds: [],
        routingRules: [],
    }];

    assert.throws(
        () => composeXrayConfig(baseConfig, fragments),
        {
            name: 'XrayConfigComposerError',
            code: 'DUPLICATE_INBOUND_LISTENER',
            listen: '0.0.0.0',
            port: 443,
        },
    );
});

test('rejects non-canonical fragments with a structured error', () => {
    const baseConfig = { inbounds: [], outbounds: [], routing: { rules: [] } };
    const fragments = [{
        id: 'relay-l2tp',
        inbounds: [],
        outbounds: [],
    }];

    assert.throws(
        () => composeXrayConfig(baseConfig, fragments),
        {
            name: 'XrayConfigComposerError',
            code: 'INVALID_XRAY_CONFIG_FRAGMENT',
            fragmentIndex: 0,
            fragmentId: 'relay-l2tp',
            field: 'routingRules',
        },
    );
});

test('rejects a malformed base config with a structured error', () => {
    const baseConfig = { inbounds: [], outbounds: [], routing: {} };

    assert.throws(
        () => composeXrayConfig(baseConfig, []),
        {
            name: 'XrayConfigComposerError',
            code: 'INVALID_BASE_XRAY_CONFIG',
            field: 'routing.rules',
        },
    );
});

test('rejects a malformed fragment collection with a structured error', () => {
    const baseConfig = { inbounds: [], outbounds: [], routing: { rules: [] } };

    assert.throws(
        () => composeXrayConfig(baseConfig, null),
        {
            name: 'XrayConfigComposerError',
            code: 'INVALID_XRAY_CONFIG_FRAGMENTS',
            field: 'fragments',
        },
    );
});

test('rejects duplicate fragment ids to keep composition deterministic', () => {
    const baseConfig = { inbounds: [], outbounds: [], routing: { rules: [] } };
    const fragments = [
        { id: 'relay-l2tp', inbounds: [], outbounds: [], routingRules: [{ id: 'one' }] },
        { id: 'relay-l2tp', inbounds: [], outbounds: [], routingRules: [{ id: 'two' }] },
    ];

    assert.throws(
        () => composeXrayConfig(baseConfig, fragments),
        {
            name: 'XrayConfigComposerError',
            code: 'DUPLICATE_XRAY_CONFIG_FRAGMENT_ID',
            fragmentId: 'relay-l2tp',
        },
    );
});
