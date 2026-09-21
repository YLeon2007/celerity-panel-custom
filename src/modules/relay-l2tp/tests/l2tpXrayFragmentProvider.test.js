'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { composeXrayConfig } = require('../services/xrayConfigComposer');
const { buildL2tpXrayFragment } = require('../services/l2tpXrayFragmentProvider');

function snapshot(overrides = {}) {
    return {
        plan: {
            relay: {
                id: 'relay-1',
                controlPlaneIps: ['198.51.100.10'],
            },
            group: { id: 'route-group-a' },
            paths: [
                {
                    pathKey: 'secondary',
                    healthy: true,
                    outboundTag: 'cascade-secondary',
                },
                {
                    pathKey: 'primary',
                    healthy: true,
                    outboundTag: 'cascade-primary',
                },
            ],
            selectedPathKey: 'primary',
        },
        tproxyPort: 12345,
        tags: {
            inbound: 'relay-l2tp-route-group-a',
            blockOutbound: 'block',
        },
        ...overrides,
    };
}

test('builds a canonical group-scoped TPROXY fragment for the selected healthy path', () => {
    const fragment = buildL2tpXrayFragment(snapshot());

    assert.deepEqual(fragment, {
        id: 'relay-l2tp',
        inbounds: [{
            tag: 'relay-l2tp-route-group-a',
            listen: '0.0.0.0',
            port: 12345,
            protocol: 'dokodemo-door',
            settings: {
                network: 'tcp,udp',
                followRedirect: true,
            },
            streamSettings: {
                sockopt: { tproxy: 'tproxy' },
            },
        }],
        outbounds: [],
        routingRules: [
            {
                type: 'field',
                inboundTag: ['relay-l2tp-route-group-a'],
                ip: ['geoip:private'],
                outboundTag: 'block',
            },
            {
                type: 'field',
                inboundTag: ['relay-l2tp-route-group-a'],
                ip: ['198.51.100.10'],
                outboundTag: 'block',
            },
            {
                type: 'field',
                inboundTag: ['relay-l2tp-route-group-a'],
                outboundTag: 'cascade-primary',
            },
        ],
    });

    assert.doesNotThrow(() => composeXrayConfig(
        {
            inbounds: [],
            outbounds: [
                { tag: 'block', protocol: 'blackhole' },
                { tag: 'cascade-primary', protocol: 'vless' },
            ],
            routing: { rules: [] },
        },
        [fragment],
    ));
});

test('routes only to block when the plan has no healthy selected path', () => {
    const blockedSnapshot = snapshot();
    blockedSnapshot.plan.paths = [
        { pathKey: 'primary', healthy: false, outboundTag: 'direct' },
        { pathKey: 'secondary', healthy: false, outboundTag: 'freedom' },
        { pathKey: 'tertiary', healthy: false, outboundTag: 'random' },
    ];

    const fragment = buildL2tpXrayFragment(blockedSnapshot);

    assert.deepEqual(
        fragment.routingRules.map(rule => rule.outboundTag),
        ['block', 'block', 'block'],
    );
    assert.equal(
        fragment.routingRules.some(rule => ['direct', 'freedom', 'random'].includes(rule.outboundTag)),
        false,
    );
    assert.deepEqual(fragment.outbounds, []);
});

test('is deterministic across plan ordering and excludes secret fields', () => {
    const firstSnapshot = snapshot();
    firstSnapshot.plan.relay.controlPlaneIps = ['203.0.113.20', '198.51.100.10'];
    firstSnapshot.plan.relay.privateKey = 'relay-private-key';
    firstSnapshot.plan.paths[0].password = 'path-password';
    firstSnapshot.psk = 'l2tp-preshared-secret';
    firstSnapshot.token = 'deployment-token';

    const permutedSnapshot = structuredClone(firstSnapshot);
    permutedSnapshot.plan.paths.reverse();
    permutedSnapshot.plan.relay.controlPlaneIps.reverse();

    const first = buildL2tpXrayFragment(firstSnapshot);
    const permuted = buildL2tpXrayFragment(permutedSnapshot);
    const serialized = JSON.stringify(first);

    assert.deepEqual(first, permuted);
    assert.doesNotMatch(serialized, /relay-private-key|path-password|l2tp-preshared-secret|deployment-token/);
    assert.doesNotMatch(serialized, /"(?:psk|password|privateKey|secret|token)"/i);
});
