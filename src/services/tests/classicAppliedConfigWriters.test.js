'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, withEnv, node, link, MAIN, BRIDGE } = require('./cascadeLegacyWriterFixture');
const parsed = (f, n, file = MAIN) => JSON.parse(f.files.get(f.key(n._id, file)));
const carries = (config, row) => JSON.stringify(config).includes(row.tunnelUuid);
const effects = f => f.events.filter(row => row.kind === 'upload' || row.kind === 'exec' && /systemctl/.test(row.command));

function setup(mode = 'reverse') {
    const nodes = [node(1), node(2, 'bridge'), node(3), node(4, 'bridge')];
    const working = link(20, nodes[0], nodes[1], { mode, status: 'pending' });
    const selected = link(21, nodes[0], nodes[1], { mode, status: 'pending' });
    const saved = link(22, nodes[0], nodes[3], { mode, status: 'pending' });
    const f = fixture({ nodes, links: [working] });
    f.links.push(selected, saved);
    return { f, working, selected, saved, nodes };
}
for (const mode of ['reverse', 'forward']) {
    test(`ordinary explicit ${mode} deploy applies only its selected pending link and preserves installed pending peers`, async () => withEnv({}, async () => {
        const { f, working, selected, saved, nodes } = setup(mode);
        await (mode === 'reverse' ? f.cascade._deployReverseLink(selected, nodes[0], nodes[1])
            : f.cascade._deployForwardLink(selected, nodes[0], nodes[1]));
        const main = parsed(f, nodes[0]);
        assert.equal(carries(main, working), true);
        assert.equal(carries(main, selected), true);
        assert.equal(carries(main, saved), false);
        const target = parsed(f, nodes[1], mode === 'reverse' ? BRIDGE : MAIN);
        assert.equal(carries(target, working), true);
        assert.equal(carries(target, selected), true);
        assert.equal(target.outbounds.some(row => row.tag === `fwd-${selected._id.slice(-8)}`), false, 'a selected incoming hop must not dial itself');
        assert.equal(f.links[2].status, 'pending');
        assert.equal(f.locks.size, 0);
    }));
}
for (const writer of ['sync', 'cascade']) {
    const run = (f, n) => writer === 'sync' ? f.sync.updateXrayNodeConfig(n) : f.cascade._deployPortalConfig(n);
    for (const defect of ['missing', 'malformed', 'unknown', 'partial', 'edited-credential', 'duplicate']) {
        test(`${writer} refuses ${defect} installed baseline before writes, without blocking a different component`, async () => withEnv({}, async () => {
            const f = fixture();
            const before = parsed(f, f.nodes[0]);
            if (defect === 'missing') f.files.delete(f.key(f.nodes[0]._id, MAIN));
            if (defect === 'malformed') f.files.set(f.key(f.nodes[0]._id, MAIN), '{not-json');
            if (defect === 'unknown') before.reverse.portals.push({ tag: 'unrecognized-peer', domain: 'private.invalid' });
            if (defect === 'partial') before.inbounds = before.inbounds.filter(row => !row.tag.startsWith('bridge-conn-'));
            if (defect === 'edited-credential') f.links[0].tunnelUuid = '22222222-2222-4222-8222-222222222222';
            if (defect === 'duplicate') before.reverse.portals.push(structuredClone(before.reverse.portals[0]));
            if (!['missing', 'malformed'].includes(defect)) f.files.set(f.key(f.nodes[0]._id, MAIN), JSON.stringify(before));
            const bytes = f.files.get(f.key(f.nodes[0]._id, MAIN));
            await assert.rejects(run(f, f.nodes[0]), error => error.code?.startsWith('CLASSIC_APPLIED_'));
            assert.equal(f.files.get(f.key(f.nodes[0]._id, MAIN)), bytes);
            assert.deepEqual(effects(f), []);
            assert.equal(await run(f, f.nodes[2]), true);
            assert.equal(f.locks.has(f.nodes[2]._id), false);
        }));
    }
    test(`${writer} retains unrelated inbounds, nonempty clients, credentials, routing and other profile bytes on two successful rewrites`, async () => withEnv({}, async () => {
        const { f, working, saved, nodes } = setup();
        const before = parsed(f, nodes[0]);
        const extra = { tag: 'retained-client', protocol: 'vless', port: 24443,
            settings: { clients: [{ id: '44444444-4444-4444-8444-444444444444', email: 'preserved' }] },
            streamSettings: { security: 'reality', realitySettings: { privateKey: 'dummy-private', shortIds: ['abcdef12'] } } };
        const rule = { type: 'field', inboundTag: [extra.tag], outboundTag: 'direct' };
        before.inbounds.push(extra); before.routing.rules.unshift(rule);
        f.files.set(f.key(nodes[0]._id, MAIN), JSON.stringify(before));
        f.files.set(f.key(nodes[0]._id, BRIDGE), 'other profile immutable bytes');
        for (let i = 0; i < 2; i++) {
            assert.equal(await run(f, nodes[0]), true);
            const after = parsed(f, nodes[0]);
            assert.deepEqual(after.inbounds.find(row => row.tag === extra.tag), extra);
            assert.deepEqual(after.routing.rules.find(row => row.inboundTag?.includes(extra.tag)), rule);
            assert.ok(after.inbounds.some(row => row.settings?.clients?.some(client => client.id === f.users[0].xrayUuid)));
            assert.equal(carries(after, working), true); assert.equal(carries(after, saved), false);
            assert.equal(f.files.get(f.key(nodes[0]._id, BRIDGE)), 'other profile immutable bytes');
            assert.equal(f.locks.size, 0);
        }
    }));
}
test('standalone forward-hop deploy retains installed pending peers and excludes absent save-only neighbors', async () => withEnv({}, async () => {
    const nodes = [node(1), { ...node(2, 'bridge'), type: 'hysteria' }, node(3), node(4)];
    const working = link(20, nodes[0], nodes[1], { mode: 'forward', status: 'pending' });
    const selected = link(21, nodes[2], nodes[1], { mode: 'forward', status: 'pending' });
    const saved = link(22, nodes[3], nodes[1], { mode: 'forward', status: 'pending' });
    const f = fixture({ nodes, links: [working, selected, saved] });
    f.files.set(f.key(nodes[1]._id, BRIDGE), f.generator.generateForwardHopConfig([working]));
    await f.cascade._deployForwardHopConfig(nodes[1], [selected]);
    const after = parsed(f, nodes[1], BRIDGE);
    assert.equal(carries(after, working), true);
    assert.equal(carries(after, selected), true);
    assert.equal(carries(after, saved), false);
    assert.equal(f.locks.size, 0);
}));

test('reverse relay rewrite recognizes its working pending upstream/downstream and excludes saved neighbors', async () => withEnv({}, async () => {
    const nodes = [node(1), node(2, 'relay'), node(3, 'bridge'), node(4, 'bridge')];
    const upstream = link(20, nodes[0], nodes[1], { status: 'pending' });
    const working = link(21, nodes[1], nodes[2], { status: 'pending' });
    const saved = link(22, nodes[1], nodes[3], { status: 'pending' });
    const f = fixture({ nodes, links: [upstream, working, saved] });
    const installed = f.generator.generateRelayConfig(upstream, nodes[0], [working]);
    f.files.set(f.key(nodes[1]._id, BRIDGE), installed);
    await f.cascade._deployBridgeConfig(upstream, nodes[1], nodes[0]);
    const after = parsed(f, nodes[1], BRIDGE);
    assert.equal(carries(after, upstream), true); assert.equal(carries(after, working), true);
    assert.equal(carries(after, saved), false);
    assert.deepEqual(after, JSON.parse(installed));
    assert.equal(f.locks.size, 0);
}));

test('undeploy last working reverse peer stops the service instead of activating an absent pending survivor', async () => withEnv({}, async () => {
    const nodes = [node(1), node(2, 'bridge'), node(3)];
    const removed = link(20, nodes[0], nodes[1]);
    const saved = link(21, nodes[2], nodes[1], { status: 'pending' });
    const f = fixture({ nodes, links: [removed] }); f.links.push(saved);
    await f.cascade.undeployLink(removed);
    assert.ok(f.events.some(row => row.kind === 'exec' && row.node === nodes[1]._id && row.command.includes('systemctl stop')));
    assert.equal(f.events.some(row => row.kind === 'upload' && row.node === nodes[1]._id), false);
    assert.equal(f.locks.size, 0);
}));

test('standalone forward-hop undeploy retains its installed pending neighbor without applying a saved one', async () => withEnv({}, async () => {
    const nodes = [node(1), { ...node(2, 'bridge'), type: 'hysteria' }, node(3), node(4)];
    const removed = link(20, nodes[0], nodes[1], { mode: 'forward' });
    const working = link(21, nodes[2], nodes[1], { mode: 'forward', status: 'pending' });
    const saved = link(22, nodes[3], nodes[1], { mode: 'forward', status: 'pending' });
    const f = fixture({ nodes, links: [removed, working, saved] });
    f.files.set(f.key(nodes[1]._id, BRIDGE), f.generator.generateForwardHopConfig([removed, working]));
    await f.cascade.undeployLink(removed);
    const after = parsed(f, nodes[1], BRIDGE);
    assert.equal(carries(after, working), true); assert.equal(carries(after, removed), false);
    assert.equal(carries(after, saved), false);
    assert.equal(f.events.some(row => row.kind === 'exec' && row.node === nodes[1]._id && row.command.includes('systemctl stop')), false);
    assert.equal(f.locks.size, 0);
}));

test('last-link undeploy refuses an unrecognized sidecar rather than stopping unrelated service', async () => withEnv({}, async () => {
    const nodes = [node(1), node(2, 'bridge')];
    const removed = link(20, nodes[0], nodes[1]);
    const f = fixture({ nodes, links: [removed] });
    f.files.set(f.key(nodes[1]._id, BRIDGE), 'not-json');
    await assert.rejects(f.cascade.undeployLink(removed), { code: 'CLASSIC_APPLIED_BASELINE_UNAVAILABLE' });
    assert.equal(f.files.get(f.key(nodes[1]._id, BRIDGE)), 'not-json');
    assert.equal(f.events.some(row => row.kind === 'exec' && row.node === nodes[1]._id && row.command.includes('systemctl')), false);
}));

test('reverse shared-bridge undeploy keeps a working pending neighbor but does not activate a saved peer', async () => withEnv({}, async () => {
    const nodes = [node(1), node(2, 'bridge'), node(3), node(4)];
    const removed = link(20, nodes[0], nodes[1]);
    const working = link(21, nodes[2], nodes[1], { status: 'pending' });
    const saved = link(22, nodes[3], nodes[1], { status: 'pending' });
    const f = fixture({ nodes, links: [removed, working] }); f.links.push(saved);
    await f.cascade.undeployLink(removed);
    const after = parsed(f, nodes[1], BRIDGE);
    assert.equal(carries(after, working), true);
    assert.equal(carries(after, saved), false);
    assert.equal(carries(after, removed), false);
    assert.equal(f.locks.size, 0);
}));
