'use strict';

process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'panel.example.test';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'test@example.test';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || '01234567890123456789012345678901';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    cascadePathIngressPort,
    cascadePathIngressTag,
} = require('../domain/cascadePathIngress');
const {
    applyCascadePathIngress,
    applyXrayApi,
    generateXrayConfig,
    generateXrayConfigWithApi,
} = require('../../../services/configGenerator');

test('derives deterministic per-path ingress ports inside the reserved range', () => {
    const first = cascadePathIngressPort('route-group-a', 'primary');
    const second = cascadePathIngressPort('route-group-a', 'primary');

    assert.equal(first, second);
    assert.equal(first, 19535);
    assert.equal(cascadePathIngressPort('route-group-a', 'secondary'), 19556);

    const samples = [
        cascadePathIngressPort('route-group-a', 'primary'),
        cascadePathIngressPort('route-group-a', 'secondary'),
        cascadePathIngressPort('group-1', 'main'),
        cascadePathIngressPort('group-1', 'failover'),
        cascadePathIngressPort('group-reverse', 'main'),
    ];
    for (const port of samples) {
        assert(Number.isSafeInteger(port));
        assert(port >= 18000 && port <= 19999, `port out of range: ${port}`);
        assert(![10086, 10087, 61000].includes(port), `port collides: ${port}`);
    }
    assert.notEqual(
        cascadePathIngressPort('route-group-a', 'primary'),
        cascadePathIngressPort('route-group-a', 'secondary'),
    );
    assert.notEqual(
        cascadePathIngressPort('route-group-a', 'primary'),
        cascadePathIngressPort('route-group-b', 'primary'),
    );
});

test('derives stable cascade-<pathKey> ingress tags', () => {
    assert.equal(cascadePathIngressTag('primary'), 'cascade-primary');
    assert.equal(cascadePathIngressTag('failover'), 'cascade-failover');
    assert.equal(cascadePathIngressTag('primary'), cascadePathIngressTag('primary'));
});

test('rejects non-string identities instead of deriving ambiguous ports', () => {
    for (const [groupId, pathKey] of [
        [undefined, 'primary'],
        ['route-group-a', undefined],
        [null, 'primary'],
        ['', 'primary'],
        ['route-group-a', ''],
        [42, 'primary'],
    ]) {
        assert.throws(() => cascadePathIngressPort(groupId, pathKey), { name: 'TypeError' });
        assert.throws(() => cascadePathIngressTag(pathKey), { name: 'TypeError' });
    }
});

function baseConfig() {
    return {
        inbounds: [],
        outbounds: [{ tag: 'block', protocol: 'blackhole' }],
        routing: { rules: [] },
    };
}

test('applyCascadePathIngress adds loopback socks inbounds and egress rules per path', () => {
    const config = baseConfig();
    applyCascadePathIngress(config, [
        { pathKey: 'primary', port: 19535, egressTag: 'portal-down-link-2' },
        { pathKey: 'secondary', port: 19556, egressTag: 'portal-down-link-2' },
    ]);

    assert.deepEqual(config.inbounds, [
        {
            tag: 'cascade-primary',
            listen: '127.0.0.1',
            port: 19535,
            protocol: 'socks',
            settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' },
        },
        {
            tag: 'cascade-secondary',
            listen: '127.0.0.1',
            port: 19556,
            protocol: 'socks',
            settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' },
        },
    ]);
    assert.deepEqual(config.routing.rules, [
        {
            type: 'field',
            inboundTag: ['cascade-primary'],
            outboundTag: 'portal-down-link-2',
        },
        {
            type: 'field',
            inboundTag: ['cascade-secondary'],
            outboundTag: 'portal-down-link-2',
        },
    ]);
    assert.deepEqual(config.outbounds, [{ tag: 'block', protocol: 'blackhole' }]);
});

test('applyCascadePathIngress is a no-op for empty ingress sets', () => {
    const config = baseConfig();
    applyCascadePathIngress(config, []);
    applyCascadePathIngress(config);
    assert.deepEqual(config, baseConfig());
});

function apiNode() {
    return {
        port: 443,
        xray: {
            apiPort: 61042,
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

test('generateXrayConfig no longer emits the unconditional API inbound', () => {
    const config = JSON.parse(generateXrayConfig(apiNode(), users));

    assert.equal(config.api, undefined);
    assert.equal(config.stats, undefined);
    assert.equal(config.policy, undefined);
    assert.equal(config.inbounds.some(inbound => inbound.tag === 'API_INBOUND'), false);
    assert.equal(
        config.routing.rules.some(rule => rule.inboundTag?.includes('API_INBOUND')),
        false,
    );
    assert(config.inbounds.some(inbound => inbound.tag === 'vless-in'));
});

test('generateXrayConfigWithApi restores the panel management API surface', () => {
    const withApi = JSON.parse(generateXrayConfigWithApi(apiNode(), users));

    assert.deepEqual(withApi.api, { services: ['HandlerService', 'StatsService'], tag: 'API' });
    assert.deepEqual(withApi.stats, {});
    assert.equal(typeof withApi.policy, 'object');
    assert.equal(withApi.inbounds[0].tag, 'API_INBOUND');
    assert.deepEqual(withApi.inbounds[0], {
        listen: '127.0.0.1',
        port: 61042,
        protocol: 'dokodemo-door',
        settings: { address: '127.0.0.1' },
        tag: 'API_INBOUND',
    });
    assert.deepEqual(withApi.routing.rules[0], {
        inboundTag: ['API_INBOUND'],
        outboundTag: 'API',
        type: 'field',
    });
    assert(withApi.inbounds.some(inbound => inbound.tag === 'vless-in'));
});

test('applyXrayApi validates the loopback API port', () => {
    const config = JSON.parse(generateXrayConfig(apiNode(), users));

    assert.throws(() => applyXrayApi(config, 0), { name: 'TypeError' });
    assert.throws(() => applyXrayApi(config, 65536), { name: 'TypeError' });
    assert.throws(() => applyXrayApi(config, '61000'), { name: 'TypeError' });
});
