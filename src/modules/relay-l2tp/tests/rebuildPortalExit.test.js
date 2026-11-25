'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { join } = require('node:path');
const test = require('node:test');
const { BSON } = require('mongoose').mongo;
const CascadeLink = require('../../../models/cascadeLinkModel');
const { composeRebuildRelayPair } = require('../../../services/rebuildRelayInstallSteps');
const { runRebuild, profilePreview } = require('../../../services/rebuildCoordinator');
const { compileRebuildGraph } = require('../domain/rebuildTopologyCompiler');
const { normalizeRebuildExit } = require('../domain/rebuildPortalExit');
const { composeRebuildProfiles, ingressTag, egressTag } = require('./helpers/rebuildComposerFixture');

const id = n => n.toString(16).padStart(24, '0');
const uuid = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const node = (n, cascadeRole, extra) => ({ _id: id(n), cascadeRole, type: 'xray', active: true,
    ip: `192.0.2.${n}`, port: 23000 + n, xray: { security: 'none', transport: 'tcp', inboundTag: `client-${n}` }, ...extra });
const edge = (n, source, target, extra) => ({ _id: id(n), portalNode: id(source), bridgeNode: id(target), active: true,
    tunnelPort: 13000 + n, tunnelUuid: uuid(n), tunnelEncryption: 'none', ...extra });
const geo = (domains, geoip = [], priority = 100) => ({ geoRouting: { enabled: true, domains, geoip }, priority });
const pick = (n, relayGeo) => ({ rebuildExit: { nodeId: id(n), ...(relayGeo === undefined ? {} : { relayGeo }) } });
const config = (profiles, n, profile = 'main') => profiles.find(p => p.nodeId === id(n) && p.profile === profile).config;
const portalRules = cfg => cfg.routing.rules.filter(rule => rule.ruleTag?.startsWith('rebuild-policy-portal-'));
const sharedRules = cfg => cfg.routing.rules.filter(rule => /^rebuild-policy-(?:geo-|default$)/.test(rule.ruleTag ?? ''));
const route = (cfg, ingress, selector = '') => cfg.routing.rules.find(rule => rule.inboundTag?.includes(ingress)
    && (!rule.domain || rule.domain.includes(selector)) && (!rule.ip || rule.ip.includes(selector)))?.outboundTag
    ?? cfg.outbounds[0].tag;
const clientSniff = (profiles, n) => config(profiles, n).inbounds.find(i => i.tag === `client-${n}`).sniffing.routeOnly;
const bytes = value => JSON.stringify(value);
const digest = text => createHash('sha256').update(text).digest('hex');
const INVALID = { code: 'REBUILD_PORTAL_EXIT_INVALID' };
const AMBIGUOUS = { code: 'REBUILD_PORTAL_EXIT_AMBIGUOUS' };
const UNSUPPORTED = { code: 'REBUILD_PORTAL_EXIT_UNSUPPORTED' };

const nodes = [node(1, 'portal'), node(2, 'portal'), node(3, 'portal'), node(4, 'relay', {
    aclRules: ['reject(denied.invalid)'],
}), node(5, 'bridge'), node(6, 'bridge'), node(7, 'bridge'), node(8, 'standalone')];
const a = edge(11, 1, 4, { mode: 'forward' });
const b = edge(12, 2, 4);
const c = edge(13, 3, 4);
const ordinary = edge(14, 4, 5);
const eu = edge(15, 4, 6, { mode: 'forward', ...geo(['full:geo.invalid'], ['ru'], 10) });
const us = edge(16, 4, 7, geo(['full:other.invalid'], [], 20));
const links = [us, b, ordinary, c, a, eu];
const enabled = links.map(link => link === a ? { ...a, ...pick(7) } : link === b ? { ...b, ...pick(6, false) } : link);
const controls = ['panel.invalid', '192.0.2.4'];
const tproxyPort = 32120;
const installed = { node: id(4), desiredState: 'installed', status: 'installed', routingMode: 'follow-relay',
    routingVersion: 1, secretRevision: 1, tproxyPort };
const input = { nodes, usersByNode: Object.fromEntries([1, 2, 3, 4].map(n => [id(n), [{ userId: `user-${n}`, xrayUuid: uuid(n) }]])),
    controlPlaneAddresses: controls };
const compose = (choices, states = []) => composeRebuildProfiles({ ...input, links: choices, followRelayStates: states });

// Keep this on the actual model; an inline nested path can add fields to old rows.
test('CascadeLink persists sparse desired and applied node choices, not link IDs', () => {
    const stock = { ...a, name: 'fixture' };
    const legacy = CascadeLink.hydrate(stock);
    for (const path of ['rebuildExit', 'rebuildAppliedExit']) {
        assert.ok(CascadeLink.schema.path(path)?.$isSingleNested);
        assert.equal(legacy[path], undefined);
        assert.equal(Object.hasOwn(legacy.toObject(), path), false);
        const cases = [
            [null, null],
            [{ nodeId: new BSON.ObjectId(id(7)) }, { nodeId: new BSON.ObjectId(id(7)), relayGeo: true }],
            [{ nodeId: id(6), relayGeo: false }, { nodeId: new BSON.ObjectId(id(6)), relayGeo: false }],
        ];
        for (const [value, expected] of cases) {
            const doc = new CascadeLink({ ...stock, [path]: value });
            assert.equal(doc.validateSync(), undefined);
            const raw = BSON.deserialize(BSON.serialize(doc.toObject()));
            assert.deepEqual(raw[path], expected);
            assert.deepEqual(normalizeRebuildExit(raw[path]), value === null ? null : {
                nodeId: expected.nodeId.toHexString(), relayGeo: expected.relayGeo,
            });
        }
        for (const value of [{}, { linkId: id(7) }, { nodeId: id(7), relayGeo: 'false' }, { nodeId: id(7), relayGeo: null },
            { nodeId: id(7), extra: true }]) {
            assert.ok(new CascadeLink({ ...stock, [path]: value }).validateSync());
        }
    }
    const empty = { nodeId: null, relayGeo: false };
    const desired = new CascadeLink({ ...stock, rebuildExit: empty });
    assert.equal(desired.validateSync(), undefined);
    assert.deepEqual(desired.toObject().rebuildExit, empty);
    assert.ok(new CascadeLink({ ...stock, rebuildAppliedExit: empty }).validateSync());
});

test('three portals get independent transit routing, including a geo link as a catch-all pick', () => {
    const profiles = compose(enabled);
    const baseline = compose(links);
    const relay = config(profiles, 4);
    const graph = compileRebuildGraph({ nodes, links: enabled });
    const ingress = [a, b, c].map(link => ingressTag(graph.byLinkId.get(link._id)));
    const exit = [ordinary, eu, us].map(link => egressTag(graph.byLinkId.get(link._id)));
    assert.deepEqual(ingress, ['fwd-hop-0000000b', 'rebuild-rp-ingress-0000000c', 'rebuild-rp-ingress-0000000d']);
    assert.deepEqual(exit, ['rebuild-rp-egress-0000000e', 'fwd-0000000f', 'rebuild-rp-egress-00000010']);
    assert.deepEqual([1, 2, 3].map((n, i) => route(config(profiles, n), `client-${n}`)),
        [a, b, c].map(link => egressTag(graph.byLinkId.get(link._id))));
    assert.equal(relay.inbounds.find(i => i.tag === ingress[0])?.protocol, 'vless');
    assert.deepEqual(relay.outbounds.filter(o => o.settings?.reverse).map(o => o.settings.reverse.tag), ingress.slice(1));
    const expectedLabels = ['0b-geo-0-domain', '0b-geo-0-ip', '0b-geo-1-domain', '0b-default', '0c-default'];
    assert.deepEqual(portalRules(relay).map(r => r.ruleTag), expectedLabels.map(label => `rebuild-policy-portal-000000${label}`));
    assert.deepEqual(portalRules(relay).map(r => r.inboundTag), [0, 0, 0, 0, 1].map(i => [ingress[i]]));
    const selectors = ['full:geo.invalid', 'geoip:ru', 'full:other.invalid', 'unmatched'];
    const routed = tag => selectors.map(selector => route(relay, tag, selector));
    assert.deepEqual(routed(ingress[0]), [exit[1], exit[1], exit[2], exit[2]]);
    assert.deepEqual(routed(ingress[1]), Array(4).fill(exit[1]));
    for (const tag of [ingress[2], 'client-4']) assert.deepEqual(routed(tag), [exit[1], exit[1], exit[2], exit[0]]);
    for (const tag of ['rebuild-rp-conn-00000010', 'unknown']) assert.deepEqual(routed(tag), Array(4).fill('block'));
    assert.equal(route(relay, 'API_INBOUND'), 'API');
    assert.equal(bytes(sharedRules(relay)), bytes(sharedRules(config(baseline, 4))));
    assert.equal(relay.routing.domainStrategy, 'IPOnDemand');
    assert.ok(relay.routing.rules.indexOf(portalRules(relay).at(-1)) < relay.routing.rules.indexOf(sharedRules(relay)[0]));
    const unchanged = p => p.nodeId !== id(4) && p.nodeId !== id(2) || p.profile === 'bridge';
    assert.equal(bytes(profiles.filter(unchanged)), bytes(baseline.filter(unchanged)));
    assert.equal(bytes(composeRebuildProfiles({ ...input, nodes: nodes.slice().reverse(), links: enabled.slice().reverse() })), bytes(profiles));
});

test('absent, null and null-pick overrides produce identical profile bytes', () => {
    const baseline = bytes(compose(links, [installed]));
    for (const value of [undefined, null, { nodeId: null }, { nodeId: null, relayGeo: false }]) {
        const noPick = links.map(link => link === b ? { ...b, rebuildExit: value } : link);
        assert.equal(bytes(compose(noPick, [installed])), baseline);
    }
});

test('a BSON pick and its canonical hex string produce the same profiles', () => {
    const bson = enabled.map(link => link._id === a._id ? {
        ...link, rebuildExit: { nodeId: new BSON.ObjectId(id(7)), relayGeo: true },
    } : link === us ? { ...us, bridgeNode: new BSON.ObjectId(id(7)) } : link);
    const profiles = compose(bson);
    assert.equal(portalRules(config(profiles, 4)).length, 5);
    assert.equal(bytes(profiles), bytes(compose(enabled)));
});

test('rejects malformed override payloads before they can be ignored or coerced', () => {
    for (const value of [false, [], new Date(), {}, { relayGeo: false }, { linkId: id(7) }, { nodeId: 7 }, { nodeId: id(7) + '\n' },
        { nodeId: id(10).toUpperCase() }, { nodeId: { toHexString: () => id(7) } }, { nodeId: { $oid: id(7) } },
        { nodeId: Object.create(BSON.ObjectId.prototype) },
        { nodeId: id(7), relayGeo: 'false' }, { nodeId: id(7), relayGeo: null },
        { nodeId: null, relayGeo: 0 }, { nodeId: null, extra: true }]) {
        assert.throws(() => compileRebuildGraph({ nodes, links: [...links.filter(l => l !== a), { ...a, rebuildExit: value }] }), INVALID);
    }
});

test('rejects wrong role, foreign, missing, inactive, deleting, and closed picks against the desired graph', () => {
    const moreNodes = [...nodes.filter(n => n._id !== id(8)), node(8, 'bridge'), node(9, 'relay'), node(10, 'relay')];
    const foreign = edge(21, 9, 8);
    const moreLinks = [...links.filter(l => l !== a), foreign, edge(22, 4, 10), edge(25, 1, 5)];
    const compile = (choice, choices = moreLinks) => compileRebuildGraph({ nodes: moreNodes, links: [...choices, choice] });
    for (const choice of [edge(23, 1, 5, pick(5)), edge(24, 9, 4, pick(5)), edge(23, 1, 5, { rebuildExit: { nodeId: null } }),
        { ...a, ...pick(8) }, { ...a, ...pick(10) }, { ...a, ...pick(99) }]) {
        assert.throws(() => compile(choice), INVALID);
    }
    for (const changes of [{ active: false }, { rebuildDelete: true }, { lifecycle: { state: 'deleting' } }, null]) {
        const other = links.filter(l => l !== a && l !== us);
        assert.throws(() => compile({ ...a, ...pick(7) }, changes === null ? other : [...other, { ...us, ...changes }]), INVALID);
    }
    assert.throws(() => compileRebuildGraph({
        nodes: moreNodes, links: [...links.filter(l => l !== a), { ...a, ...pick(8) }, foreign],
        affectedNodeIds: nodes.filter(n => n._id !== id(8)).map(n => n._id),
    }), INVALID, 'a valid link outside the scoped compile inventory is not a pick');
});

test('a pinned node uses its lowest-priority-number live edge, including geo, and survives channel removal', () => {
    const slow = edge(40, 4, 6, { priority: 200 });
    const fast = edge(41, 4, 6, geo(['full:fast.invalid'], [], 5));
    const secondRelay = node(9, 'relay');
    const foreign = edge(42, 9, 6, { priority: 1 });
    const wanted = (choices, selected) => {
        for (const ordered of [choices, choices.slice().reverse()]) {
            const graph = compileRebuildGraph({ nodes: [...nodes, secondRelay], links: [foreign, ...ordered] });
            const pick = graph.byLinkId.get(b._id).portalExit;
            assert.equal(pick.defaultLink, graph.byLinkId.get(selected._id));
            assert.deepEqual(pick.geoLinks, [], 'catch-all selection still includes geo with relayGeo off');
            const relay = config(composeRebuildProfiles({ ...input, links: ordered }), 4);
            assert.equal(route(relay, ingressTag(graph.byLinkId.get(b._id)), 'unmatched'), egressTag(pick.defaultLink));
        }
    };
    const base = [...enabled, slow];
    wanted([...base, fast], fast);
    for (const retired of [[], [{ ...fast, active: false }], [{ ...fast, rebuildDelete: true }],
        [{ ...fast, lifecycle: { state: 'deleting' } }]]) {
        wanted([...base, ...retired], eu);
        wanted([...base.filter(link => link !== eu), ...retired], slow);
    }
});

test('any live duplicate priority within the selected node blocks; other nodes and retired peers do not count', () => {
    for (const extra of [{ priority: 10 }, geo(['full:tied.invalid'], [], 10)]) {
        const tied = edge(41, 4, 6, extra);
        const faster = edge(42, 4, 6, { priority: 1 });
        for (const base of [enabled, [...enabled, faster]]) {
            for (const ordered of [[...base, tied], [tied, ...base.slice().reverse()]]) {
                assert.throws(() => compileRebuildGraph({ nodes, links: ordered }), AMBIGUOUS);
            }
        }
        for (const peer of [{ ...tied, active: false }, { ...tied, rebuildDelete: true },
            { ...tied, lifecycle: { state: 'deleting' } }, { ...tied, bridgeNode: id(5) }]) {
            const graph = compileRebuildGraph({ nodes, links: [...enabled, peer] });
            assert.equal(graph.byLinkId.get(b._id).portalExit.defaultLink.id, eu._id);
        }
    }
    const base = [...enabled.filter(link => link !== eu), edge(40, 4, 6, { priority: 100 })];
    const graph = compileRebuildGraph({ nodes, links: base });
    assert.equal(graph.byNodeId.get(id(4)).defaultLink, null, 'the shared default blocks a cross-target tie');
    assert.equal(graph.byLinkId.get(b._id).portalExit.defaultLink.id, id(40), 'the explicit node considers only its own edges');
});

test('requires a routed portal edge: ranked defaults and live geo are valid, shadowed or tied defaults are not', () => {
    const preferred = edge(30, 1, 5, { priority: 10 });
    const simultaneousGeo = edge(31, 1, 7, geo(['full:portal-only.invalid']));
    const base = [...links.filter(l => l !== a), preferred, simultaneousGeo];
    const opted = { ...a, ...pick(7) };
    for (const priority of [11, 10]) assert.throws(() => compose([...base, { ...opted, priority }]), UNSUPPORTED);
    assert.throws(() => compose([...base, { ...opted, ...geo(['full:portal-only.invalid'], [], 110) }]), UNSUPPORTED);
    for (const routed of [{ ...opted, priority: 9 }, { ...opted, ...geo(['full:relay-only.invalid']) }]) {
        const profiles = compose([...base, routed]);
        assert.ok(portalRules(config(profiles, 4)).length);
        assert.equal(route(config(profiles, 1), 'client-1', 'full:portal-only.invalid'), 'rebuild-rp-egress-0000001f');
        assert.equal(route(config(profiles, 1), 'client-1', routed.geoRouting ? 'full:relay-only.invalid' : ''), 'fwd-0000000b');
    }
});

test('resolves an explicitly selected terminal bridge through successive relays', () => {
    const next = edge(31, 4, 9, { mode: 'forward', priority: 5 });
    const last = edge(32, 9, 10, { priority: 3 });
    const exit = edge(33, 10, 11);
    const ru = edge(34, 10, 6, geo(['full:ru.invalid'], ['ru'], 1));
    const peers = [...nodes, node(9, 'relay'), node(10, 'relay'), node(11, 'bridge')];
    const rest = links.filter(l => l !== a);
    const compile = (useGeo, added = [next, last, exit, ru]) => compileRebuildGraph({
        nodes: peers, links: [...rest, ...added, { ...a, ...pick(11, useGeo) }],
    });
    for (const useGeo of [true, false]) {
        const graph = compile(useGeo);
        const policy = graph.byLinkId.get(a._id).portalExit;
        assert.deepEqual(policy.path.map(link => link.id), [next, last, exit].map(link => link._id));
        assert.equal(policy.defaultLink.id, exit._id);
        assert.deepEqual(policy.geoLinks.map(link => link.id), useGeo ? [ru._id] : []);
        assert.equal(graph.byNodeId.get(a.portalNode).carryDomain, useGeo);
        assert.equal(graph.byNodeId.get(next.bridgeNode).carryDomain, true, 'the shared policy still needs the domain');
    }
    const unordered = compile(true, [ru, exit, last, next]);
    assert.deepEqual(unordered.byLinkId.get(a._id).portalExit.path.map(link => link.id), [next, last, exit].map(link => link._id));
    assert.throws(() => compile(true, [last, exit, ru]), INVALID);
    const conflictingNext = edge(36, 4, 9, { priority: 5 });
    assert.throws(() => compile(true, [next, last, exit, ru, conflictingNext]), AMBIGUOUS);
    assert.throws(() => compile(true, [next, last, exit, ru, edge(37, 10, 4)]), { code: 'REBUILD_CYCLE' });
});

test('rejects selecting a relay or copying live geo relay branches; unused chains remain valid', () => {
    const secondRelay = node(9, 'relay');
    const tail = edge(30, 9, 7);
    const chain = edge(31, 4, 9, { priority: 5 });
    const other = links.filter(l => l !== a);
    const compile = (choice, intermediate = chain) => compileRebuildGraph({ nodes: [...nodes, secondRelay],
        links: [...other, intermediate, tail, { ...a, ...choice }] });
    assert.throws(() => compile(pick(9, false)), INVALID);
    assert.doesNotThrow(() => compile(pick(7)), 'a shared default is not part of the portal policy');
    const geoChain = { ...chain, ...geo(['full:multi-hop.invalid']) };
    assert.throws(() => compile(pick(7), geoChain), UNSUPPORTED);
    assert.doesNotThrow(() => compile(pick(7, false), geoChain));
});

test('copying a closed relay geo branch preserves its block instead of falling through to the pick', () => {
    const closed = edge(35, 4, 9, geo(['full:closed.invalid'], [], 1));
    const profiles = composeRebuildProfiles({ ...input, nodes: [...nodes, node(9, 'relay')], links: [...enabled, closed] });
    const relay = config(profiles, 4);
    assert.equal(route(relay, 'fwd-hop-0000000b', 'full:closed.invalid'), 'block');
    assert.equal(route(relay, 'rebuild-rp-ingress-0000000c', 'full:closed.invalid'), 'fwd-0000000f');
    assert.equal(route(relay, 'rebuild-rp-ingress-0000000d', 'full:closed.invalid'), 'block');
    assert.equal(route(relay, 'client-4', 'full:closed.invalid'), 'block');
});

test('reverse sniffing follows only the downstream policy actually used at each portal', () => {
    const baseline = compose(links, [installed]);
    const profiles = compose(enabled, [installed]);
    assert.deepEqual([1, 2, 3, 4].map(n => clientSniff(baseline, n)), [true, false, false, true]);
    assert.deepEqual([1, 2, 3, 4].map(n => clientSniff(profiles, n)), [true, true, false, true]);
    const ownGeo = edge(31, 2, 7, geo(['full:portal-only.invalid']));
    assert.equal(clientSniff(compose([...enabled, ownGeo]), 2), true, 'local portal geo needs no downstream hostname');
    const copied = enabled.map(link => link._id === b._id ? { ...b, ...pick(6, true) } : link);
    assert.equal(clientSniff(compose(copied), 2), false);
    const ipOnly = copied.map(link => [eu._id, us._id].includes(link._id) ? { ...link, ...geo([], ['ru']) } : link);
    assert.equal(clientSniff(compose(ipOnly), 2), true, 'relay IP-only rules do not need the hostname');
    const reverse = enabled.map(link => link._id === a._id ? { ...link, mode: 'reverse' } : link);
    assert.equal(clientSniff(compose(reverse), 1), false);
    const rankGeoToRelay = edge(32, 2, 4, { ...geo(['full:relay-only.invalid']), ...pick(7, true) });
    assert.equal(clientSniff(compose([...enabled, rankGeoToRelay]), 2), false, 'a routed reverse geo leg can require carry');
    assert.deepEqual(profilePreview(config(baseline, 2), config(profiles, 2), 'main').sections, ['inbounds']);
    assert.equal(profilePreview(config(baseline, 2), config(profiles, 2), 'main').protectedChanged, false);
});

test('the actual Rebuild snapshot drops tombstones and refuses a surviving pick without fallback or staging', async () => {
    const inv = enabled.map(link => link === us ? { ...link, rebuildDelete: true } : link);
    let builds = 0;
    const unexpected = () => assert.fail('cannot stage, activate or read live profiles for a missing pick');
    await assert.rejects(runRebuild({
        global: cb => cb(), withNodes: (_ids, cb) => cb(), links: async () => inv,
        build(affectedNodeIds, desired) {
            builds++;
            assert.ok(!desired.some(l => l._id === us._id));
            return { candidates: composeRebuildProfiles({ ...input, affectedNodeIds, links: desired }) };
        }, read: unexpected, stagePair: unexpected,
    }, { linkId: a._id, preview: true }), INVALID);
    assert.equal(builds, 1);
});

test('installed PPP receives byte-identical shared rules and guards, never portal-scoped policy', () => {
    const baseline = compose(links, [installed]);
    const profiles = compose(enabled, [installed]);
    const relay = config(profiles, 4);
    const ppp = `relay-l2tp-${id(4)}`;
    const socks = 'rebuild-relay-ingress';
    const isPpp = row => row.inboundTag?.some(tag => tag === ppp || tag === socks);
    assert.equal(bytes(relay.routing.rules.filter(isPpp)), bytes(config(baseline, 4).routing.rules.filter(isPpp)));
    assert.equal(bytes(relay.inbounds), bytes(config(baseline, 4).inbounds));
    assert.equal(portalRules(relay).length, 5);
    assert.ok(portalRules(relay).every(rule => !isPpp(rule)));
    for (const [selector, target] of [['full:panel.invalid', 'rebuild-l2tp-block'], ['geoip:private', 'rebuild-l2tp-block'],
        ['full:denied.invalid', 'block'], ['full:geo.invalid', 'fwd-0000000f'], ['geoip:ru', 'fwd-0000000f'],
        ['unmatched', 'rebuild-rp-egress-0000000e']]) assert.equal(route(relay, socks, selector), target);
    assert.equal(route(relay, ppp), 'rebuild-l2tp-handoff');
    assert.equal(route(relay, ppp, 'geoip:private'), 'rebuild-l2tp-block');
    for (const item of profiles) {
        const before = baseline.find(p => p.nodeId === item.nodeId && p.profile === item.profile);
        assert.equal(profilePreview(before.config, item.config, item.profile, true).protectedChanged, false);
    }
});

function installRelay(profile, carryDomain = false, relay = installed) {
    const main = bytes(profile);
    return composeRebuildRelayPair({ main, bridge: null }, {
        nodeId: relay.node, tproxyPort: relay.tproxyPort, controlPlaneAddresses: controls, carryDomain,
        mainSha256: digest(main), bridgeSha256: null,
    });
}

function checkDirect(cases) {
    // Exercise the stock pure guard called by host Apply before publication
    // and by Remove, without invoking the host entrypoint or any system I/O.
    const python = `
import json, runpy, sys
h = runpy.run_path(sys.argv[1])
f = json.load(sys.stdin)
for name, stock, candidate, *relays in f['cases']:
    try:
        record = {'data': h['b64'](candidate.encode())}
        relay = relays[0] if relays else {'node': f['node'], 'tproxyPort': f['tproxy']}
        clean, _, _ = h['subtract_follow_relay'](record, h['unique_profile'](record), None, relay['node'], relay['tproxyPort'])
        owned = h['transit_inbounds'](h['unique_profile'](record), h['apply_transit'](record))
        if name.startswith('chain-'):
            assert sum(26000 <= port < 32000 for port in owned.values()) == int(name.endswith('-listener')) * 2
        print(name, 'exact' if h['raw'](clean['main']).decode() == stock else 'wrong-inverse')
    except h['Refusal'] as exc:
        print(name, str(exc))
`;
    const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', python, join(__dirname, '../../../services/rebuildRelayDirectHost.py')], {
        input: bytes({ node: id(4), tproxy: tproxyPort, cases }), encoding: 'utf8', timeout: 5000,
    });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trimEnd().split('\n');
}

const chainFixture = (mode = 'reverse') => {
    const middle = edge(31, 4, 9, { mode, priority: 1 });
    const west = edge(32, 9, 5, { priority: 1 });
    const east = edge(33, 9, 10, { priority: 2 });
    const ru = edge(34, 9, 6, { ...geo(['full:ru.invalid'], ['ru'], 1), mode: 'forward' });
    const peers = [...nodes, node(9, 'relay'), node(10, 'bridge'), node(11, 'portal')];
    const tailIngress = { ...edge(36, 11, 9, { mode: 'forward' }), ...pick(5, false) };
    return { ...input, nodes: peers, links: [{ ...a, ...pick(10, true) }, { ...b, ...pick(10, false) },
        { ...c, ...pick(10, true) }, tailIngress, middle, west, east, ru], middle, west, east, ru, tailIngress };
};

test('scoped TCP channels share only identical suffixes; PPP keeps the base channel', () => {
    for (const mode of ['reverse', 'forward']) {
        const fixture = chainFixture(mode);
        const profiles = composeRebuildProfiles({ ...fixture, followRelayStates: [installed, { ...installed, node: id(9) }] });
        const head = config(profiles, 4), tail = config(profiles, 9);
        const [withGeo, withoutGeo, duplicate] = [a, b, c].map(link => route(head, ingressTag({ id: link._id, mode: link.mode ?? 'reverse' })));
        assert.equal(withGeo, duplicate);
        assert.notEqual(withGeo, withoutGeo);
        const shared = route(head, 'rebuild-relay-ingress', 'full:ru.invalid');
        assert.equal(shared, egressTag({ id: fixture.middle._id, mode }));
        assert.notEqual(shared, withGeo);
        assert.notEqual(shared, withoutGeo);
        const onTail = out => out.replace(/^fwd-/, 'fwd-hop-').replace(/^rebuild-rp-egress-/, 'rebuild-rp-ingress-');
        const eastTag = egressTag({ id: fixture.east._id, mode: 'reverse' });
        const ruTag = egressTag({ id: fixture.ru._id, mode: 'forward' });
        assert.equal(route(tail, onTail(withGeo), 'full:ru.invalid'), ruTag);
        assert.equal(route(tail, onTail(withGeo), 'geoip:ru'), ruTag);
        assert.equal(route(tail, onTail(withGeo), 'other'), eastTag);
        assert.equal(route(tail, onTail(withoutGeo), 'full:ru.invalid'), eastTag);
        assert.equal(route(tail, onTail(shared), 'full:ru.invalid'), ruTag);
        assert.equal(route(tail, 'rebuild-relay-ingress', 'full:ru.invalid'), ruTag);
        assert.equal(route(tail, 'rebuild-relay-ingress', 'other'), egressTag({ id: fixture.west._id, mode: 'reverse' }));
        assert.equal(route(tail, ingressTag({ id: fixture.tailIngress._id, mode: fixture.tailIngress.mode }), 'full:ru.invalid'),
            egressTag({ id: fixture.west._id, mode: 'reverse' }));
        const listeners = (mode === 'reverse' ? head : tail).inbounds.filter(row => /^(?:rebuild-rp-conn|fwd-hop)-/.test(row.tag)
            && row.port >= 26000 && row.port < 32000);
        assert.equal(listeners.length, 2);
        assert.equal(new Set(listeners.map(i => i.settings.clients[0].id)).size, 2);
        assert.ok(listeners.every(i => i.settings.clients[0].id !== fixture.middle.tunnelUuid));
        const legacy = composeRebuildProfiles({ ...fixture, links: fixture.links.map(({ rebuildExit, ...link }) => link),
            followRelayStates: [installed, { ...installed, node: id(9) }] });
        assert.deepEqual(sharedRules(tail), sharedRules(config(legacy, 9)));
        const scoped = tail.routing.rules.filter(r => r.ruleTag?.startsWith('rebuild-policy-transit-'));
        assert.ok(scoped.length > 2 && scoped.every(r => r.inboundTag.length === 1
            && !sharedRules(tail).some(s => s.inboundTag.includes(r.inboundTag[0]))));
        const remaining = composeRebuildProfiles({ ...fixture, links: fixture.links.filter(link => link._id !== b._id) });
        assert.equal(route(config(remaining, 4), ingressTag({ id: a._id, mode: a.mode })), withGeo);
        const allShared = composeRebuildProfiles({ ...fixture, links: fixture.links.map(link => link.rebuildExit
            ? { ...link, ...pick(5, true) } : link) });
        assert.equal(route(config(allShared, 4), ingressTag({ id: a._id, mode: a.mode })), shared);
        assert.throws(() => composeRebuildProfiles({ ...fixture, links: fixture.links.map(link => link === fixture.middle
            ? { ...link, tunnelTransport: 'kcp' } : link) }), { code: 'REBUILD_SCOPED_TRANSIT_TCP_REQUIRED' });
    }
});

test('a portal Geo pin works even if the shared terminal defaults tie', () => {
    const { middle, west, east, nodes } = chainFixture();
    const ingress = { ...a, ...geo(['full:choose.invalid']), ...pick(10, false) };
    const fixture = { ...input, nodes, links: [ingress, middle, west, { ...east, priority: west.priority }] };
    for (const links of [fixture.links, [...fixture.links, edge(37, 1, 5)]]) {
        const profiles = composeRebuildProfiles({ ...fixture, links });
        assert.equal(route(config(profiles, 1), 'client-1', 'full:choose.invalid'), egressTag({ id: a._id, mode: a.mode }));
        assert.equal(route(config(profiles, 9), ingressTag({ id: middle._id, mode: middle.mode })), 'block');
    }
    const profiles = composeRebuildProfiles({ ...fixture, links: [{ ...a, ...pick(10, false) }, ...fixture.links.slice(1)] });
    assert.equal(route(config(profiles, 1), 'client-1'), egressTag({ id: a._id, mode: a.mode }));
});

test('scoped channels consume prepared VLESS parameters without making them enumerable', () => {
    const fixture = chainFixture('forward');
    const { buildTransitChannels } = require('../services/rebuildTransitChannels');
    const encrypted = { ...fixture.middle, tunnelEncryption: 'vless-enc' };
    const parameters = { decryption: 'fixture-decryption', encryption: 'fixture-encryption' };
    Object.defineProperty(encrypted, '_rebuildVless', { value: parameters });
    const linked = { ...fixture, links: fixture.links.map(row => row === fixture.middle ? encrypted : row) };
    const channels = buildTransitChannels(compileRebuildGraph(linked));
    assert.equal(channels.artifacts.length, 2);
    for (const { link } of channels.artifacts) {
        assert.equal(link._rebuildVless, parameters);
        assert.equal(Object.keys(link).includes('_rebuildVless'), false);
    }
});

const stockCases = () => {
    const closed = edge(35, 4, 9, geo(['full:closed.invalid'], [], 1));
    const render = (choices, states = []) => config(compose(choices, states), 4);
    const renderClosed = (states = []) => config(composeRebuildProfiles({ ...input, nodes: [...nodes, node(9, 'relay')],
        links: [...enabled, closed], followRelayStates: states }), 4);
    const preferred = edge(41, 4, 6, { priority: 5 });
    const parallel = [...enabled, preferred];
    const fallback = [...enabled, { ...preferred, rebuildDelete: true }];
    return [
        ['no-pick', render(links), render(links, [installed])],
        ['forward-and-native', render(enabled), render(enabled, [installed])],
        ['closed-geo', renderClosed(), renderClosed([installed])],
        ['parallel-preferred', render(parallel), render(parallel, [installed])],
        ['parallel-fallback', render(fallback), render(fallback, [installed])],
        ...['reverse', 'forward'].flatMap(mode => {
            const fixture = chainFixture(mode), graph = compileRebuildGraph(fixture);
            const relays = [installed, { ...installed, node: id(9) }];
            const base = composeRebuildProfiles(fixture), live = composeRebuildProfiles({ ...fixture, followRelayStates: relays });
            return [4, 9].map((n, i) => [`chain-${mode}-${n}-${(mode === 'reverse') === (n === 4) ? 'listener' : 'dialer'}`,
                config(base, n), config(live, n), graph.byNodeId.get(id(n)).carryDomain, relays[i]]);
        }),
    ];
};

test('stock L2TP install matches the composer byte for byte with portal rules', () => {
    for (const [name, stock, applied, carryDomain, relay] of stockCases()) {
        assert.deepEqual(installRelay(stock, carryDomain, relay), { main: `${bytes(applied)}\n` }, name);
    }
});

test('DIRECT Apply/Remove accepts composer portal rules and subtracts to exact stock bytes', () => {
    const cases = stockCases();
    assert.deepEqual(checkDirect(cases.map(([name, stock, applied, , relay]) =>
        [name, `${bytes(stock)}\n`, `${bytes(applied)}\n`, ...(relay ? [relay] : [])])),
        cases.map(([name]) => `${name} exact`));
});

test('install and DIRECT reject a scoped channel joined to shared PPP policy or changed to non-TCP', () => {
    const cases = [];
    for (const mode of ['reverse', 'forward']) {
        const [, stock, applied, carry, relay] = stockCases().find(([name]) => name.startsWith(`chain-${mode}-9-`));
        const variants = {
            'joined-shared': (cfg, scope) => {
                for (const rule of sharedRules(cfg)) rule.inboundTag.splice(
                    rule.inboundTag.includes('rebuild-relay-ingress') ? -1 : rule.inboundTag.length, 0, scope);
            },
            'non-tcp': (cfg, scope) => {
                const row = [...cfg.inbounds, ...cfg.outbounds].find(i => i.tag === scope || i.settings?.reverse?.tag === scope);
                row.streamSettings.network = 'kcp';
            },
            'portal-label': (_cfg, _scope, rule) => { rule.ruleTag = rule.ruleTag.replace('-transit-', '-portal-'); },
        };
        const alter = (source, change) => {
            const cfg = structuredClone(source);
            const rule = cfg.routing.rules.find(r => r.ruleTag?.startsWith('rebuild-policy-transit-'));
            change(cfg, rule.inboundTag[0], rule);
            return cfg;
        };
        for (const [key, change] of Object.entries(variants)) {
            const name = `${mode}-${key}`;
            assert.throws(() => installRelay(alter(stock, change), carry, relay),
                { code: 'REBUILD_L2TP_XRAY_BASELINE_UNSUPPORTED' }, name);
            cases.push([name, null, bytes(alter(applied, change)), relay]);
        }
    }
    assert.deepEqual(checkDirect(cases), cases.map(([name]) => `${name} CANDIDATE_INVALID`));
});

test('install and DIRECT reject tampered portal rules without reclassifying them as shared policy', () => {
    const mutate = (profile, fn) => {
        const cfg = structuredClone(profile);
        fn(cfg.routing.rules, portalRules(cfg), cfg);
        return cfg;
    };
    const [, stock, applied] = stockCases()[1];
    const stockError = { code: 'REBUILD_L2TP_XRAY_BASELINE_UNSUPPORTED' };
    const tests = [
        ['uppercase', (_, p) => { p[0].ruleTag = p[0].ruleTag.replace('0000000b', '0000000B'); }],
        ['short-suffix', (_, p) => { p[0].ruleTag = p[0].ruleTag.replace('0000000b', '000000b'); }],
        ['trailing-newline', (_, p) => { p[0].ruleTag += '\n'; }],
        ['noncanonical-geo-index', (_, p) => { p[0].ruleTag = p[0].ruleTag.replace('-geo-0-', '-geo-00-'); }],
        ['arbitrary-label', (_, p) => { p[0].ruleTag = 'rebuild-policy-arbitrary'; }],
        ['unknown-portal-label', (_, p) => { p[0].ruleTag = 'rebuild-policy-portal-0000000b-extra'; }],
        ['wrong-forward', (_, p) => { p[0].inboundTag = ['rebuild-rp-ingress-0000000d']; }],
        ['wrong-native', (_, p) => { p.at(-1).inboundTag = ['rebuild-rp-conn-0000000c']; }],
        ['no-scope', (_, p) => { p[0].inboundTag = []; }],
        ['multiple-scopes', (_, p) => { p[0].inboundTag.push('rebuild-rp-ingress-0000000c'); }],
        ['subscriber', (_, p) => { p[0].inboundTag = ['client-4']; }],
        ['api', (_, p) => { p[0].inboundTag = ['API_INBOUND']; }],
        ['forward-socks-impostor', (_, p, c) => { c.inbounds.find(i => i.tag === p[0].inboundTag[0]).protocol = 'socks'; }],
        ['forward-subscriber-impostor', (_, p, c) => { c.inbounds.find(i => i.tag === p[0].inboundTag[0]).settings.clients[0].email = 'user'; }],
        ['native-outbound-impostor', (_, p, c) => { c.outbounds.find(o => o.settings?.reverse?.tag === p.at(-1).inboundTag[0]).protocol = 'vmess'; }],
        ['missing-native-settings', (_, p, c) => { delete c.outbounds.find(o => o.settings?.reverse?.tag === p.at(-1).inboundTag[0]).settings.reverse; }],
        ['ambiguous-forward-ingress', (_, p, c) => { c.outbounds.push({ tag: 'other-dial', protocol: 'vless',
            settings: { reverse: { tag: p[0].inboundTag[0] } } }); }],
        ['ambiguous-native-dialer', (_, p, c) => { const dialer = c.outbounds.find(o => o.settings?.reverse?.tag === p.at(-1).inboundTag[0]);
            c.outbounds.push({ tag: dialer.tag, protocol: 'vless' }); }],
        ['outside-shared-scope', (r, p) => { for (const rule of r.filter(row => /^rebuild-policy-(geo-|default$)/.test(row.ruleTag ?? ''))) {
            rule.inboundTag = rule.inboundTag.filter(tag => tag !== p[0].inboundTag[0]);
        } }],
        ['extra-key', (_, p) => { p[0].network = 'tcp'; }],
        ['wrong-selector', (_, p) => { p[0].ip = p[0].domain; delete p[0].domain; }],
        ['empty-geo', (_, p) => { p[0].domain = []; }],
        ['geo-on-default', (_, p) => { p.at(-1).domain = ['full:extra.invalid']; }],
        ['direct-target', (_, p, c) => { c.outbounds.push({ tag: 'direct', protocol: 'freedom' }); p[0].outboundTag = 'direct'; }],
        ['upstream-dial-target', (_, p) => { p[0].outboundTag = 'rebuild-rp-dial-0000000c'; }],
        ['unbound-native-target', (_, p, c) => { c.inbounds.find(i => i.tag === 'rebuild-rp-conn-00000010').tag += '-other'; }],
        ['missing-target', (_, p) => { p[0].outboundTag = 'fwd-12345678'; }],
        ['blocked-default', (_, p) => { p.at(-1).outboundTag = 'block'; }],
        ['ppp-scope', (_, p) => { p[0].inboundTag.push(`relay-l2tp-${id(4)}`); }],
        ['socks-scope', (_, p) => { p[0].inboundTag.push('rebuild-relay-ingress'); }],
        ['ppp-target', (_, p) => { p[0].outboundTag = 'rebuild-l2tp-handoff'; }],
        ['ppp-reference-in-selector', (_, p) => { p[0].domain.push(`relay-l2tp-${id(4)}`); }],
        ['duplicate-label', (r, p) => { r.splice(r.indexOf(p[0]), 0, structuredClone(p[0])); }],
        ['no-default', (r, p) => { r.splice(r.indexOf(p[3]), 1); }],
        ['geo-after-default', (r, p) => { r.splice(r.indexOf(p[3]), 0, ...r.splice(r.indexOf(p[0]), 1)); }],
        ['after-shared-geo', (r, p) => { r.splice(r.length - 1, 0, ...r.splice(r.indexOf(p.at(-1)), 1)); }],
    ];
    for (const [name, fn] of tests) assert.throws(() => installRelay(mutate(stock, fn)), stockError, name);
    assert.deepEqual(checkDirect(tests.map(([name, fn]) => [name, null, bytes(mutate(applied, fn))])),
        tests.map(([name]) => `${name} CANDIDATE_INVALID`));
});
