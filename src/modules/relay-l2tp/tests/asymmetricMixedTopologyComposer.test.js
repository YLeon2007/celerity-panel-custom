'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');
const { cascadePathIngressPort } = require('../domain/cascadePathIngress');

// Short portal path sorts first: pa -> rm; pb -> rb -> rm -> bd, rm -> bg (RU).
function inputFor(defaultMode, geoMode) {
    const nodes = [
        ['pa', 'portal'], ['pb', 'portal'], ['rb', 'relay'], ['rm', 'relay'],
        ['bd', 'bridge'], ['bg', 'bridge'],
    ].map(([id, role]) => ({ id, role }));
    const links = [
        { id: 'a', source: 'pa', target: 'rm', mode: 'forward' },
        { id: 'b', source: 'pb', target: 'rb', mode: 'reverse' },
        { id: 'c', source: 'rb', target: 'rm', mode: 'forward' },
        { id: 'd', source: 'rm', target: 'bd', mode: defaultMode },
        { id: 'g', source: 'rm', target: 'bg', mode: geoMode },
    ];
    return {
        snapshot: {
            nodes, links,
            groups: [{ id: 'pinned-group', paths: [
                { pathKey: 'main', linkIds: ['d'], enabled: true },
                { pathKey: 'off', linkIds: ['d'], enabled: false },
                { pathKey: 'other', linkIds: ['unrelated'], enabled: true },
            ] }],
        },
        nodeMetadata: nodes.map((node, index) => ({
            ...node, type: 'xray', active: true, ip: `192.0.2.${index + 1}`, port: 24001 + index,
            xray: { inboundTag: `client-${node.id}`, transport: 'tcp', security: 'none', extraInbounds: [] },
        })),
        linkMetadata: links.map((link, index) => ({
            id: link.id, tunnelPort: 10101 + index,
            ...(link.id === 'g' ? { geoRouting: { enabled: true, geoip: ['ru'], domains: ['category-ru'] } } : {}),
        })),
        compiledTopology: { valid: true, relays: [{ nodeId: 'rb' }, { nodeId: 'rm' }] },
    };
}

function configsOf(plan) {
    return new Map(plan.nodes.map(node => [node.nodeRef, JSON.parse(Buffer.from(node.candidate.bytes))]));
}

// Evaluate the generated ordered rules for a known public destination class.
// Skip handshake rules and unrelated/private-IP predicates, not earlier catch-alls.
function routeFor(config, inboundTag, destination) {
    return config.routing.rules.find(rule => (
        (!rule.inboundTag || rule.inboundTag.includes(inboundTag))
        && (!rule.domain || rule.domain.includes(destination))
        && (!rule.ip || rule.ip.includes(destination))
    ))?.outboundTag;
}

test('asymmetric staged fan-in keeps the terminal relay last in the ref contract', () => {
    const input = inputFor('forward', 'forward');
    input.snapshot.nodes = input.snapshot.nodes.filter(node => node.role !== 'bridge');
    input.snapshot.links = input.snapshot.links.filter(link => ['a', 'b', 'c'].includes(link.id));
    input.snapshot.groups = [];
    input.staged = true;
    const plan = composeFrozenTopologyDeploymentPlan(input);
    assert.equal(plan.staged, true);
    const configs = configsOf(plan);
    // Staged PPP readiness identifies the terminal by the highest relay ref.
    // The coordinator must mirror this contract, not number rm on first sight.
    const terminal = configs.get('relay-2');
    const branch = configs.get('relay-1');
    assert.deepEqual(terminal.inbounds.filter(inbound => inbound.tag.startsWith('fwd-hop-'))
        .map(inbound => inbound.port).sort(), [10101, 10103]);
    for (const inbound of terminal.inbounds.filter(inbound => inbound.tag.startsWith('fwd-hop-'))) {
        assert.equal(routeFor(terminal, inbound.tag, 'public-non-ru'), 'block');
    }
    assert.equal(branch.outbounds.find(outbound => outbound.tag.startsWith('tunnel-'))
        .settings.vnext[0].address, '192.0.2.2', 'rb dials pb');
    assert.equal(branch.outbounds.find(outbound => outbound.tag.startsWith('fwd-'))
        .settings.vnext[0].address, '192.0.2.4', 'rb forwards to rm');
    for (const config of configs.values()) {
        assert.equal(config.routing.rules.some(rule => ['direct', 'freedom'].includes(rule.outboundTag)), false);
    }
});

for (const defaultMode of ['forward', 'reverse']) {
    for (const geoMode of ['forward', 'reverse']) {
        test(`asymmetric mixed fan-in: L2TP obeys RU policy before ${defaultMode} default / ${geoMode} geo egress`, () => {
            const input = inputFor(defaultMode, geoMode);
            const plan = composeFrozenTopologyDeploymentPlan(input);
            assert.equal(plan.mode, 'mixed');
            const configs = configsOf(plan);
            assert.deepEqual([...configs.keys()].sort(), ['bridge', 'bridge-2', 'portal-1', 'portal-2', 'relay-1', 'relay-2']);

            // Complete fan-in refs follow first appearance: rm is relay-1, rb relay-2.
            const merge = configs.get('relay-1');
            const branch = configs.get('relay-2');
            assert.deepEqual(merge.inbounds.filter(inbound => inbound.tag.startsWith('fwd-hop-'))
                .map(inbound => inbound.port).sort(), [10101, 10103]);
            assert.equal(branch.outbounds.find(outbound => outbound.tag.startsWith('tunnel-'))
                .settings.vnext[0].address, '192.0.2.2', 'rb reverse tunnel dials pb, not pa');
            assert.equal(configs.get('portal-1').outbounds.find(outbound => outbound.tag.startsWith('fwd-'))
                .settings.vnext[0].address, '192.0.2.4', 'pa forward tunnel dials rm');
            assert.ok(configs.get('portal-2').inbounds.some(inbound => inbound.port === 10102));

            const ingress = merge.inbounds.find(inbound => inbound.tag === 'cascade-main');
            assert.equal(ingress?.listen, '127.0.0.1');
            assert.equal(ingress?.port, cascadePathIngressPort('pinned-group', 'main'));
            assert.ok(plan.nodes.find(node => node.nodeRef === 'relay-1').checks.some(check => (
                check.type === 'port' && check.port === ingress.port
            )));
            assert.equal(branch.inbounds.some(inbound => inbound.tag === 'cascade-main'), false,
                'pinned downstream path must not create ingress on rb');
            assert.equal(merge.inbounds.some(inbound => ['cascade-off', 'cascade-other'].includes(inbound.tag)), false);

            const geoTag = `${geoMode === 'forward' ? 'fwd' : 'portal'}-link-5`;
            const defaultTag = `${defaultMode === 'forward' ? 'fwd' : 'portal'}-link-2`;
            const sourceTags = ['cascade-main', ...merge.inbounds.filter(inbound => inbound.tag.startsWith('fwd-hop-'))
                .map(inbound => inbound.tag)];
            for (const sourceTag of sourceTags) {
                assert.equal(routeFor(merge, sourceTag, 'geoip:ru'), geoTag, `${sourceTag}: RU IP exits via geo bridge`);
                assert.equal(routeFor(merge, sourceTag, 'geosite:category-ru'), geoTag, `${sourceTag}: RU domain exits via geo bridge`);
                assert.equal(routeFor(merge, sourceTag, 'public-non-ru'), defaultTag, `${sourceTag}: other traffic uses pinned default`);
            }
            assert.equal(merge.routing.domainStrategy, 'IPOnDemand');
            for (const ref of ['portal-1', 'portal-2', 'relay-1', 'relay-2']) {
                const config = configs.get(ref);
                assert.equal(config.routing.rules.some(rule => (
                    rule.outboundTag === 'direct' || rule.outboundTag === 'freedom'
                )), false, `${ref}: no local direct egress rule`);
            }
            // Both exits terminate the correct link, rather than swapping per-node configs.
            for (const [ref, mode, port] of [['bridge', defaultMode, 10104], ['bridge-2', geoMode, 10105]]) {
                const exit = configs.get(ref);
                if (mode === 'forward') assert.ok(exit.inbounds.some(inbound => inbound.port === port));
                else assert.equal(exit.outbounds.find(outbound => outbound.tag.startsWith('tunnel-'))
                    .settings.vnext[0].port, port);
            }
        });
    }
}
