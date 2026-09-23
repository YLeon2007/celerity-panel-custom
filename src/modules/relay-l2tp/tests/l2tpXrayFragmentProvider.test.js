'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { cascadePathIngressPort } = require('../domain/cascadePathIngress');
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
        outbounds: [{
            tag: 'cascade-primary',
            protocol: 'socks',
            settings: {
                servers: [{
                    address: '127.0.0.1',
                    port: cascadePathIngressPort('route-group-a', 'primary'),
                }],
            },
        }],
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

    assert.equal(fragment.outbounds[0].settings.servers[0].port, 19535);

    const composed = composeXrayConfig(
        {
            inbounds: [],
            outbounds: [
                { tag: 'block', protocol: 'blackhole' },
            ],
            routing: { rules: [] },
        },
        [fragment],
    );
    assert(composed.outbounds.some(outbound => outbound.tag === 'cascade-primary'));
});

test('points the cascade outbound at the deterministic per-path ingress port', () => {
    const secondarySnapshot = snapshot();
    secondarySnapshot.plan.selectedPathKey = 'secondary';

    const fragment = buildL2tpXrayFragment(secondarySnapshot);

    assert.deepEqual(fragment.outbounds, [{
        tag: 'cascade-secondary',
        protocol: 'socks',
        settings: {
            servers: [{
                address: '127.0.0.1',
                port: cascadePathIngressPort('route-group-a', 'secondary'),
            }],
        },
    }]);
    assert.equal(fragment.outbounds[0].settings.servers[0].port, 19556);
    assert.equal(
        fragment.routingRules.at(-1).outboundTag,
        'cascade-secondary',
    );
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

test('fails closed when the selected path exists but the group identity is missing', () => {
    const grouplessSnapshot = snapshot();
    delete grouplessSnapshot.plan.group;

    assert.throws(() => buildL2tpXrayFragment(grouplessSnapshot), { name: 'TypeError' });

    const emptyGroupSnapshot = snapshot();
    emptyGroupSnapshot.plan.group = { id: '' };
    assert.throws(() => buildL2tpXrayFragment(emptyGroupSnapshot), { name: 'TypeError' });
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

test('domain control-plane addresses go to the domain matcher, IPs stay in ip', () => {
    const fragment = buildL2tpXrayFragment(snapshot({
        plan: {
            ...snapshot().plan,
            relay: {
                id: 'relay-1',
                controlPlaneIps: ['relay.example.com', '198.51.100.10', '2001:db8::/32'],
            },
        },
    }));
    const rule = fragment.routingRules.find(
        candidate => candidate.inboundTag?.includes('relay-l2tp-route-group-a')
            && candidate.outboundTag === 'block'
            && (candidate.domain || (candidate.ip && !candidate.ip.includes('geoip:private'))),
    );
    assert.deepEqual(rule.domain, ['relay.example.com']);
    assert.deepEqual(rule.ip, ['198.51.100.10', '2001:db8::/32']);
});
