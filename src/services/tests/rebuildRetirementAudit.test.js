'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { runRebuild, runRetireGraph } = require('../rebuildCoordinator');
const { assertNoIncidentLinks, assertNoRelayEnrollment } = require('../rebuildNodeDeleteGuard');
const { relayListKey } = require('../rebuildRelayAuthorization');
const { GRANTS, RETIRED } = require('../rebuildRelayGrantStore');

const [portal, retired, bridge, other, otherBridge] = ['1','2','3','4','5'].map(c => c.repeat(24));
const fixtureUuid = 'a0000000-0000-4000-8000-000000000001';
const link = (n, portalNode, bridgeNode, fields) => ({
    _id: String(n).padStart(24, '0'), portalNode, bridgeNode, mode: 'forward', active: true,
    tunnelPort: 41000 + n, tunnelUuid: `a0000000-0000-4000-8000-${String(n).padStart(12, '0')}`, ...fields,
});
const client = { tag: 'ordinary-vless', protocol: 'vless', port: 443,
    settings: { clients: [{ id: 'fixture-subscriber', email: 'subscriber' }] } };
const config = inbounds => ({ inbounds, outbounds: [{ tag: 'block', protocol: 'blackhole' }], routing: { rules: [] } });
function graph(inventory, { observedBridge = [], newBridge = [], newMain = [client] } = {}) {
    const phases = [];
    const deps = {
        global: fn => fn(), links: async () => inventory, withNodes: (_, fn) => fn(),
        build: async nodes => ({ candidates: nodes.flatMap(nodeId => ['main','bridge'].map(profile => ({
            nodeId, profile, config: config(nodeId !== bridge ? [] : profile === 'main' ? newMain : newBridge),
        }))) }),
        read: async (nodeId, profile) => config(nodeId !== bridge ? [] : profile === 'main' ? [client] : observedBridge),
        checkActivation: async () => {},
        stagePair: async () => phases.push('stage'), putPair: async () => phases.push('put'),
        finish: async () => phases.push('finish'),
    };
    return { phases, deps, preview: () => runRetireGraph(deps, { nodeId: retired, mode: 'abandon', preview: true }),
        confirm: expectedPreview => runRetireGraph(deps, { nodeId: retired, mode: 'abandon', preview: false, expectedPreview }) };
}

test('retirement refuses a shared tunnel identity without changing either link', async () => {
    const incident = link(1, retired, bridge, {
        active: false, tunnelUuid: 'updated-draft', rebuildApplied: {
            listener: bridge, mode: 'forward', protocol: 'vless', port: 41001, uuid: fixtureUuid,
        },
    });
    for (const remaining of [link(2, portal, bridge, { tunnelUuid: fixtureUuid }),
        link(2, other, otherBridge, { tunnelUuid: fixtureUuid.toUpperCase() }),
        link(2, other, otherBridge, { active: false, rebuildApplied: {
            listener: otherBridge, mode: 'forward', protocol: 'vless', port: 41002, uuid: fixtureUuid,
        } })]) {
        const inventory = [incident, remaining], original = structuredClone(inventory);
        const g = graph(inventory);
        await assert.rejects(g.preview(), { code: 'REBUILD_RETIRE_TUNNEL_CREDENTIAL_CONFLICT' });
        assert.deepEqual(g.phases, []);
        assert.deepEqual(inventory, original);
    }
});

test('retirement rechecks separately scoped link identities on confirm', async () => {
    const links = [link(1, retired, bridge), link(2, other, otherBridge)];
    const g = graph(links);
    const preview = await g.preview();
    assert.equal(preview.allowed, true);
    links[1].tunnelUuid = fixtureUuid;
    await assert.rejects(g.confirm(preview.previewId), { code: 'REBUILD_RETIRE_TUNNEL_CREDENTIAL_CONFLICT' });
    assert.deepEqual(g.phases, []);
});

test('retirement preserves unrelated subscriber interfaces in either profile', async () => {
    const row = link(1, retired, bridge);
    const g = graph([row], { observedBridge: [client] });
    const preview = await g.preview();
    assert.equal(preview.nodes.find(n => n.nodeId === bridge).profiles.find(p => p.profile === 'bridge').protectedChanged, true);
    assert.equal(preview.allowed, false);
    await assert.rejects(g.confirm(preview.previewId), { code: 'REBUILD_CLIENT_CHANGE' });
    assert.deepEqual(g.phases, []);

    // A generated tunnel can be subtracted without losing a subscriber port.
    const tunnel = { tag: 'fwd-hop-00000001', protocol: 'vless', port: row.tunnelPort,
        settings: { clients: [{ id: row.tunnelUuid }] } };
    const protectedPair = graph([row], { observedBridge: [client, tunnel], newBridge: [client] });
    assert.equal((await protectedPair.preview()).allowed, true);
    const ordinary = graph([row, link(2, portal, bridge)]);
    const regularPreview = await runRebuild(ordinary.deps, { linkId: row._id, preview: true });
    assert.equal(regularPreview.allowed, true);
    assert.equal(regularPreview.nodes.find(n => n.nodeId === bridge).profiles.find(p => p.profile === 'main').change, 'unchanged');
    assert.deepEqual(ordinary.phases, []);
});

test('the bare delete guard recognizes the graph compiler endpoint aliases', async () => {
    for (const field of ['source', 'target', 'rebuildApplied.listener']) {
        const Link = { collection: { findOne: async (filter, options) => {
            // Observe only graph references, not status or activity.
            assert.deepEqual(options.projection, { _id: 1 });
            const match = filter.$or.find(option => option[field]?.$in.some(id => String(id) === retired));
            return match ? { _id: 'fixture-link' } : null;
        } } };
        await assert.rejects(assertNoIncidentLinks(Link, retired), { code: 'REBUILD_NODE_HAS_LINKS' });
    }
});

test('bare delete ignores retired ENV enrollment but still honors current grant and account evidence', async () => {
    const envs = [
        { C3_REBUILD_L2TP_RELAY_ID: retired, C3_REBUILD_L2TP_RELAY_MACHINE_ID: 'a'.repeat(32) },
        { [relayListKey]: JSON.stringify([{ nodeId: retired, host: '192.0.2.8', port: 22, username: 'root',
            machineId: 'a'.repeat(32), sshHostKeySha256: 'b'.repeat(64) }]) },
    ];
    let tombstone = null, grant = null, replica = null;
    const Node = { db: { collection: name => ({ findOne: async filter => {
        if (name === RETIRED) { assert.deepEqual(filter, { _id: retired }); return tombstone; }
        assert.equal(name, GRANTS); assert.deepEqual(filter, { nodeId: retired }); return grant;
    } }) } };
    const Account = { collection: { findOne: async filter => {
        assert.equal(String(filter.relayNode.$in[0]), retired); return replica;
    } } };
    for (const env of envs) {
        tombstone = null;
        await assert.rejects(assertNoRelayEnrollment(Node, Account, retired, env), { code: 'REBUILD_NODE_RETIRE_REQUIRED' });
        tombstone = { _id: retired };
        await assertNoRelayEnrollment(Node, Account, retired, env);
        grant = { _id: 'fixture-grant' };
        await assert.rejects(assertNoRelayEnrollment(Node, Account, retired, env), { code: 'REBUILD_NODE_RETIRE_REQUIRED' });
        grant = null; replica = { _id: 'fixture-replica' };
        await assert.rejects(assertNoRelayEnrollment(Node, Account, retired, env), { code: 'REBUILD_NODE_RETIRE_REQUIRED' });
        replica = null;
    }
});
