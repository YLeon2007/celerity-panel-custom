'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
const { planAdditiveScopedTransition } = require('../rebuildTransitActivationPlan');

const id = n => n.toString(16).padStart(24, '0');
const row = (n, cascadeRole) => ({ _id: id(n), cascadeRole, type: 'xray', active: true,
    ip: `192.0.2.${n}`, port: 22100 + n, xray: { security: 'none', apiPort: 23100 + n } });
const link = (n, from, to, opts) => ({ _id: id(100 + n), portalNode: id(from), bridgeNode: id(to), active: true,
    priority: n, mode: 'reverse', tunnelProtocol: 'vless', tunnelTransport: 'tcp', tunnelPort: 24100 + n,
    tunnelUuid: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`, tunnelEncryption: 'none', ...opts });
const config = (profiles, node, profile = 'main') => profiles.find(p => p.nodeId === id(node) && p.profile === profile).config;

function fixture() {
    const nodes = [row(1, 'portal'), row(2, 'portal'), row(3, 'relay'), row(4, 'relay'), row(5, 'relay'), row(6, 'bridge'), row(7, 'bridge')];
    const links = [link(1, 1, 3, { rebuildExit: { nodeId: id(7), relayGeo: false } }),
        link(2, 2, 3), link(3, 3, 4, { mode: 'forward' }), link(4, 4, 5), link(5, 5, 6), link(6, 5, 7)];
    const before = composeRebuildProfiles({ nodes, links: links.map(({ rebuildExit, ...edge }) => edge) });
    const after = composeRebuildProfiles({ nodes, links });
    return { before, after, composition: { nodes, links } };
}

const refused = reason => ({ code: 'REBUILD_SCOPE_STAGE_UNPROVED', reason });

test('orders listeners by downstream delivery, not the direction of reverse TCP dialing', () => {
    const f = fixture();
    const snapshot = structuredClone(f);
    const plan = planAdditiveScopedTransition(f);
    // The downstream reverse listener lives on 4, while the upstream forward
    // listener also lives on 4. Their dialers distinguish the two channels.
    assert.deepEqual(plan.listeners.map(x => x.nodeId), [id(4), id(4)]);
    assert.deepEqual(plan.dialers.map(x => x.nodeId), [id(5), id(3)]);
    assert.deepEqual(plan.listeners.map(x => x.channelId), plan.dialers.map(x => x.channelId));
    assert.match(plan.listeners[0].tag, /^rebuild-rp-conn-/);
    assert.match(plan.listeners[1].tag, /^fwd-hop-/);
    assert.deepEqual(plan.transit.map(x => x.nodeId), [id(5), id(4)]);
    assert.deepEqual(plan.ingress.map(x => x.nodeId), [id(3)]);
    for (const [node, phase] of [[5, 'transit'], [4, 'transit'], [3, 'ingress']]) {
        const op = plan[phase].find(p => p.nodeId === id(node));
        assert.deepEqual(op.before, config(f.before, node).routing);
        assert.deepEqual(op.after, config(f.after, node).routing);
        if (phase === 'transit') assert.deepEqual(op.append,
            op.after.rules.filter(r => r.ruleTag?.startsWith('rebuild-policy-transit-')));
    }
    assert.deepEqual(f, snapshot);
});

test('refuses nonadditive changes on every node, including existing portal listener and bridge sidecar', () => {
    const f = fixture();
    config(f.after, 2).inbounds.find(i => i.tag === 'vless-in').sniffing.routeOnly = false;
    assert.throws(() => planAdditiveScopedTransition(f), refused('existing_inbounds_changed'));
    const g = fixture();
    config(g.after, 6, 'bridge').log.loglevel = 'debug';
    assert.throws(() => planAdditiveScopedTransition(g), refused('bridge_changed'));
});

test('refuses a preceding unscoped route, an altered old route, and an incomplete ingress policy', () => {
    const f = fixture();
    const broad = { type: 'field', network: 'tcp', outboundTag: 'block' };
    config(f.before, 5).routing.rules.unshift(broad);
    config(f.after, 5).routing.rules.unshift(broad);
    assert.throws(() => planAdditiveScopedTransition(f), refused('scoped_rule_shadowed'));
    const append = fixture();
    config(append.before, 5).routing.rules.push(broad);
    config(append.after, 5).routing.rules.push(broad);
    assert.throws(() => planAdditiveScopedTransition(append), refused('transit_append_not_disjoint'));
    const g = fixture();
    config(g.after, 4).routing.rules.find(r => r.ruleTag === 'rebuild-policy-default').outboundTag = 'block';
    assert.throws(() => planAdditiveScopedTransition(g), refused('existing_rules_changed'));
    const h = fixture();
    const gateway = config(h.after, 3);
    gateway.routing.rules = gateway.routing.rules.filter(r => !r.ruleTag?.startsWith('rebuild-policy-portal-'));
    assert.throws(() => planAdditiveScopedTransition(h), refused('portal_default'));
});

test('refuses a second deployment over already-present scoped handlers and a conflicting bridge socket', () => {
    const f = fixture();
    assert.throws(() => planAdditiveScopedTransition({ ...f, before: f.after }), refused('channel_conflict'));
    const op = planAdditiveScopedTransition(f).listeners[0];
    const bridge = config(f.before, 4, 'bridge');
    bridge.inbounds.push({ ...op.config, tag: 'other-port-owner' });
    assert.throws(() => planAdditiveScopedTransition(f), refused('channel_conflict'));
});

test('accepts a candidate only if it exactly matches the composed policy and handlers', () => {
    const f = fixture();
    const transit = config(f.after, 5).routing.rules.find(r => r.ruleTag?.startsWith('rebuild-policy-transit-'));
    transit.outboundTag = 'block';
    assert.throws(() => planAdditiveScopedTransition(f), refused('desired_image_mismatch'));
    const g = fixture();
    const tag = planAdditiveScopedTransition(g).dialers[0].tag;
    config(g.after, 5).outbounds.find(r => r.tag === tag).streamSettings.security = 'tls';
    assert.throws(() => planAdditiveScopedTransition(g), refused('desired_image_mismatch'));
});
