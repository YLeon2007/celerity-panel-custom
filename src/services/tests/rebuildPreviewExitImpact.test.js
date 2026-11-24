'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { addExitImpacts } = require('../rebuildPreviewExitImpact');
const ejs = require('ejs');
const express = require('express');
const { issuePanelCsrfToken } = require('../../routes/panel/csrf');
const { routerForRebuild } = require('../../routes/cascadeRebuild');
const { createRebuildService } = require('../rebuildService');
const { runRebuild } = require('../rebuildCoordinator');
const generator = require('../configGenerator');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
const { request } = require('./helpers/rebuildPanelRequest');

const nodes = ['portal', 'relay', 'bridge', 'bridge', 'portal'].map((cascadeRole, i) => ({
    _id: `node-${i}`, type: 'xray', cascadeRole, active: true, ip: `192.0.2.${i + 1}`, port: 23000 + i,
    xray: { security: 'none', transport: 'tcp', inboundTag: `clients-${i}`, apiPort: 24000 + i },
}));
const [portal, relay, exit, alternative, otherPortal] = nodes.map(n => n._id);
const link = (n, portalNode, bridgeNode, fields) => ({
    _id: String(n).padStart(24, '0'), portalNode, bridgeNode, active: true,
    mode: 'reverse', priority: n, tunnelPort: 25000 + n, tunnelEncryption: 'none',
    tunnelUuid: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`, ...fields,
});
const geo = { enabled: true, domains: ['full:geo.fixture.invalid'] };
const upstream = link(1, portal, relay);
const downstream = link(2, relay, exit, { mode: 'forward' });
const backup = link(3, relay, alternative);
const users = [{ userId: 'preview-fixture-subscriber', xrayUuid: '00000000-0000-4000-8000-000000000100' }];
const compose = links => composeRebuildProfiles({ nodes, links, usersByNode: { [portal]: users } });

function fixture(t, links, observed = compose(links)) {
    t.mock.method(generator, 'buildPanelInlineCertificate', () => null);
    const query = rows => ({ select() { return this; }, read() { return this; }, readConcern() { return this; },
        lean: async () => structuredClone(rows) });
    const noWrite = () => assert.fail('Preview must not write');
    const service = createRebuildService({
        env: { C3_REBUILD_ENABLED: 'true' }, locks: { run: fn => fn(async () => {}) },
        Node: { find: filter => query(nodes.filter(n => filter._id.$in.includes(n._id))) },
        Link: { find: filter => query(filter._id ? links.filter(l => filter._id.$in.includes(l._id)) : links), updateOne: noWrite },
        State: { find: () => query([]) }, assertNoRelayAccountIntent: async () => {}, cache: {},
        sync: { _getUsersForNode: async node => node._id === portal ? users : [] },
        connect: node => ({ requireSupportedCore: async () => {}, close: async () => {},
            read: async profile => structuredClone(observed.find(p => p.nodeId === node._id && p.profile === profile)?.config ?? null),
            stagePair: noWrite, putPair: noWrite }),
    });
    const app = express();
    app.use('/api/cascade', routerForRebuild({ service }));
    const session = { authenticated: true };
    const headers = { 'x-csrf-token': issuePanelCsrfToken({ session }) };
    const preview = async (row, remove = true) => {
        const response = await request(app, '/api/cascade/rebuild/preview', { session, headers, body: { linkId: row._id, remove } });
        assert.equal(response.status, 200);
        return JSON.parse(response.body);
    };
    preview.confirmRemove = (row, expectedPreview) => request(app, `/api/cascade/links/${row._id}`, { method: 'DELETE', session, headers,
        body: { expectedPreview } });
    return preview;
}

const impact = report => Object.fromEntries(report.nodes.filter(n => Object.hasOwn(n, 'exitImpact'))
    .map(n => [n.nodeId, n.exitImpact]));

test('Remove warns at the indirectly disconnected portal, not the relay or bridge', async t => {
    const preview = fixture(t, [upstream, downstream]);
    const result = await preview(downstream);
    assert.equal(result.allowed, true);
    assert.deepEqual(impact(result), { [portal]: 'lost' });
    assert.deepEqual(result.nodes.map(n => [n.nodeId, n.role]), [[portal, 'portal'], [relay, 'relay'], [exit, 'bridge']]);
    assert.deepEqual(Object.keys(result).sort(), ['allowed', 'nodes', 'previewId']);
    for (const n of result.nodes) {
        assert.deepEqual(Object.keys(n).sort(), n.nodeId === portal ? ['exitImpact', 'nodeId', 'profiles', 'role'] : ['nodeId', 'profiles', 'role']);
        assert.equal(n.profiles.length, 2);
        for (const p of n.profiles) {
            assert.deepEqual(Object.keys(p).sort(), ['change', 'profile', 'protectedChanged', 'sections']);
            assert.equal(p.protectedChanged, false);
        }
    }
    const wire = JSON.stringify(result);
    assert.ok(![users[0].xrayUuid, users[0].userId, upstream.tunnelUuid, 'outboundTag', 'routing.rules']
        .some(value => wire.includes(value)), 'no profile payloads in Preview');
    assert.equal((await preview(downstream)).previewId, result.previewId);
    const stale = await preview.confirmRemove(downstream, '0'.repeat(64));
    assert.equal(stale.status, 409);
    const refusal = JSON.parse(stale.body);
    assert.equal(refusal.error.code, 'REBUILD_PREVIEW_CHANGED');
    assert.deepEqual(refusal.preview, result);
});

test('Remove reports only default loss when a downstream geo-only route survives', async t => {
    const routedGeo = { ...backup, geoRouting: geo };
    const result = await fixture(t, [upstream, downstream, routedGeo])(downstream);
    assert.deepEqual(impact(result), { [portal]: 'default-lost' });
});

test('Remove warns when the only observed exit was geo-only', async t => {
    const routedGeo = { ...downstream, geoRouting: geo };
    const result = await fixture(t, [upstream, routedGeo])(routedGeo);
    assert.deepEqual(impact(result), { [portal]: 'lost' });
});

test('Remove does not call the remaining geo exit a new default loss if the observed policy was already geo-only', async t => {
    const saved = [upstream, downstream, { ...backup, geoRouting: geo }];
    const observed = compose([upstream, { ...downstream, geoRouting: geo }]);
    assert.deepEqual(impact(await fixture(t, saved, observed)(downstream)), {});
});

test('Remove does not warn when another default exit takes over', async t => {
    assert.deepEqual(impact(await fixture(t, [upstream, downstream, backup])(downstream)), {});
});

test('Remove warns without claiming a new loss when the observed managed policy was already blocked', async t => {
    const result = await fixture(t, [upstream, downstream], compose([upstream]))(downstream);
    assert.equal(result.allowed, true);
    assert.deepEqual(impact(result), { [portal]: 'blocked' });
});

test('Remove uses configured policy even when the last hop has no recognizable peer profile', async t => {
    const observed = compose([upstream, downstream]);
    observed.find(p => p.nodeId === exit && p.profile === 'bridge').config = null;
    assert.deepEqual(impact(await fixture(t, [upstream, downstream], observed)(downstream)), { [portal]: 'lost' });
});

test('ordinary Apply Preview does not report loss, even when reconciling a tombstone', async t => {
    const observed = compose([upstream, downstream]);
    const preview = fixture(t, [upstream, { ...downstream, rebuildDelete: true }], observed);
    assert.deepEqual(impact(await preview(downstream, false)), {});
});

test('Remove warns only the affected portal when removing its direct exit to a shared bridge', async t => {
    const direct = link(4, portal, exit);
    const other = link(5, otherPortal, exit);
    const result = await fixture(t, [direct, other])(direct);
    assert.ok(result.nodes.some(n => n.nodeId === otherPortal));
    assert.deepEqual(impact(result), { [portal]: 'lost' });
});

test('Remove keeps the no-exit warning and the existing protected-client refusal', async t => {
    const direct = link(4, portal, exit);
    const observed = compose([direct]);
    observed.find(p => p.nodeId === portal && p.profile === 'main').config.inbounds.find(i => i.tag === 'clients-0').port++;
    const preview = fixture(t, [direct], observed);
    const result = await preview(direct);
    assert.equal(result.allowed, false);
    assert.deepEqual(impact(result), { [portal]: 'lost' });
    const response = await preview.confirmRemove(direct, result.previewId);
    assert.equal(response.status, 409);
    assert.deepEqual(JSON.parse(response.body), { error: { code: 'REBUILD_CLIENT_CHANGE' }, preview: result });
});

test('A confirmed Remove with a no-exit warning still applies the composed profiles', async () => {
    const direct = link(4, portal, exit);
    const profiles = new Map(compose([direct]).map(p => [`${p.nodeId}:${p.profile}`, p.config]));
    const writes = [];
    const deps = {
        global: fn => fn(), withNodes: (ids, fn) => fn(), links: () => [direct],
        build: (ids, links) => ({ candidates: compose(links).filter(p => ids.includes(p.nodeId)) }),
        nodeRole: id => nodes.find(n => n._id === id)?.cascadeRole,
        read: (id, p) => profiles.get(`${id}:${p}`),
        stagePair: id => writes.push(`stage:${id}`), markDelete: id => writes.push(`mark:${id}`),
        putPair(id, pair) {
            writes.push(`put:${id}`);
            for (const p of pair) profiles.set(`${id}:${p.profile}`, p.config);
        },
        finish: () => writes.push('finish'),
    };
    const req = { linkId: direct._id, remove: true };
    const preview = await runRebuild(deps, { ...req, preview: true });
    assert.deepEqual(writes, []);
    assert.deepEqual(impact(preview), { [portal]: 'lost' });
    const result = await runRebuild(deps, { ...req, expectedPreview: preview.previewId });
    assert.deepEqual(writes, [`stage:${portal}`, `stage:${exit}`, `mark:${direct._id}`, `put:${portal}`, `put:${exit}`, 'finish']);
    assert.equal(result.previewId, preview.previewId);
    assert.deepEqual(impact(result), {});
    assert.deepEqual(profiles.get(`${portal}:main`), compose([]).find(p => p.nodeId === portal && p.profile === 'main').config);
});

test('Remove warns when a legacy default is replaced with a blocked policy', async t => {
    const reversed = link(4, portal, exit);
    const populated = { ...reversed, portalNode: nodes[0] };
    const observed = compose([]);
    const main = JSON.parse(generator.generateXrayConfigWithApi(nodes[0], users));
    generator.applyReversePortal(main, [populated], [nodes[0].xray.inboundTag]);
    observed.find(p => p.nodeId === portal && p.profile === 'main').config = main;
    assert.deepEqual(impact(await fixture(t, [reversed], observed)(reversed)), { [portal]: 'blocked' });
});

const previewNodes = nodes.map((node, index) => ({ ...node, _id: `a${String(index).padStart(23, '0')}`,
    name: ['Portal', 'Relay', 'Gateway', 'Other gateway', 'Shared portal'][index] }));
const [p, r, a, b, sibling] = previewNodes.map(n => n._id);
const inlet = link(10, p, r, { mode: 'forward' });
const siblingInlet = link(11, sibling, r);
const first = link(12, r, a, { mode: 'forward', name: 'Main channel' });
const second = link(13, r, a);
const geoRule = { enabled: true, domains: ['full:PRIVATE_MATCHER.fixture.invalid'] };
const geoEdge = link(14, r, b, { geoRouting: geoRule });
const sharedDefault = link(15, r, b, { priority: 1 });

function images(links, { scoped = false, geo = true } = {}) {
    return composeRebuildProfiles({ nodes: previewNodes,
        links: links.map(edge => scoped && edge._id === inlet._id
            ? { ...edge, rebuildExit: { nodeId: a, relayGeo: geo } } : edge) });
}

const publicTarget = (edge, name) => ({ nodeId: edge.bridgeNode, name, linkId: edge._id,
    ...(edge.name && { linkName: edge.name }) });

function exitReport(links, before, after, remove = false) {
    const result = previewNodes.map(({ _id: nodeId }) => ({ nodeId }));
    addExitImpacts(result, links, new Map(before.filter(row => row.profile === 'main').map(row => [row.nodeId, row.config])),
        after, id => previewNodes.find(node => node._id === id)?.cascadeRole,
        id => previewNodes.find(node => node._id === id)?.name, remove);
    return result;
}

test('Remove reports the observed forward channel switching to a reverse channel on the same gateway', () => {
    const links = [inlet, first, second, sharedDefault];
    const [result] = exitReport([{ ...inlet, mode: 'reverse', rebuildExit: { nodeId: b } },
        { ...first, mode: 'reverse' }, second, sharedDefault],
        images(links, { scoped: true }), images([inlet, second, sharedDefault], { scoped: true }), true);
    assert.deepEqual(result.portalExitChange, { before: publicTarget(first, 'Gateway'), after: publicTarget(second, 'Gateway') });
    assert.equal(result.exitImpact, undefined);
});

test('Geo-only portal reports the scoped gateway switch without inventing a default or exposing matchers', () => {
    const geoInlet = { ...inlet, geoRouting: geoRule };
    const links = [geoInlet, first, second, siblingInlet, sharedDefault];
    const report = exitReport(links, images([geoInlet, first, siblingInlet, sharedDefault], { scoped: true }),
        images([geoInlet, second, siblingInlet, sharedDefault], { scoped: true }));
    assert.deepEqual(report[0].portalExitGeoChange, { before: [publicTarget(first, 'Gateway')], after: [publicTarget(second, 'Gateway')] });
    assert.equal(report[0].portalExitChange, undefined);
    assert.equal(report.at(-1).portalExitGeoChange, undefined);
    assert.doesNotMatch(JSON.stringify(report), /PRIVATE_MATCHER|fwd-hop|rebuild-policy/);
});

test('Scoped geo change with the same default reports ordered targets only for the matching portal ingress', () => {
    const geoTwo = { ...second, geoRouting: { enabled: true, geoip: ['ru'] } };
    const links = [inlet, siblingInlet, first, geoEdge, geoTwo];
    const before = images(links, { scoped: true });
    const after = images(links.map(edge => edge === geoEdge ? { ...edge, priority: 1 } : edge), { scoped: true });
    const report = exitReport(links, before, after);
    assert.deepEqual(report[0].portalExitGeoChange, {
        before: [publicTarget(geoTwo, 'Gateway'), publicTarget(geoEdge, 'Other gateway')],
        after: [publicTarget(geoEdge, 'Other gateway'), publicTarget(geoTwo, 'Gateway')],
    });
    assert.ok(report.every(node => node.portalExitChange === undefined));
    assert.equal(report.at(-1).portalExitGeoChange, undefined);
});

test('Compare scoped geo match edits privately, and ignore pure shared relay geo repairs', () => {
    const links = [inlet, siblingInlet, first, geoEdge];
    const edited = links.map(edge => edge === geoEdge ? { ...edge, geoRouting: { enabled: true, domains: ['full:NEW_PRIVATE_MATCHER.invalid'] } } : edge);
    const before = images(links, { scoped: true });
    const report = exitReport(links, before, images(edited, { scoped: true }));
    const target = [publicTarget(geoEdge, 'Other gateway')];
    assert.deepEqual(report[0].portalExitGeoChange, { before: target, after: target });
    assert.equal(report.at(-1).portalExitGeoChange, undefined);
    assert.doesNotMatch(JSON.stringify(report), /PRIVATE_MATCHER/);
    const shared = exitReport(links, images([inlet, siblingInlet, first]), images(links));
    assert.ok(shared.every(node => !Object.keys(node).some(key => key.startsWith('portalExit'))));
});

test('Scoped relay geo policy can change its target or disappear while the observed default stays put', () => {
    const moved = { ...second, geoRouting: geoRule };
    const links = [inlet, siblingInlet, first, geoEdge, moved];
    const before = images([inlet, siblingInlet, first, geoEdge], { scoped: true });
    const after = images([inlet, siblingInlet, first, moved], { scoped: true });
    const [retargeted] = exitReport(links, before, after);
    assert.deepEqual(retargeted.portalExitGeoChange, {
        before: [publicTarget(geoEdge, 'Other gateway')], after: [publicTarget(moved, 'Gateway')],
    });
    const [disabled] = exitReport(links, before, images([inlet, siblingInlet, first, geoEdge], { scoped: true, geo: false }));
    assert.deepEqual(disabled.portalExitGeoChange, { before: [publicTarget(geoEdge, 'Other gateway')], after: [] });
    assert.equal(retargeted.portalExitChange, undefined);
    assert.equal(disabled.portalExitChange, undefined);
});

test('A scoped default terminates geo lookup before any later shared or foreign-ingress branches', () => {
    const links = [inlet, siblingInlet, first, geoEdge];
    const before = images(links, { scoped: true, geo: false });
    const after = images(links, { scoped: true, geo: false });
    const rules = after.find(row => row.nodeId === r && row.profile === 'main').config.routing.rules;
    const sharedGeo = rules.find(rule => rule.ruleTag === 'rebuild-policy-geo-0-domain');
    sharedGeo.domain = ['full:SHARED_REPAIR.fixture.invalid'];
    const suffix = inlet._id.slice(-8);
    // The prefix alone doesn't prove the rule applies to our portal's ingress.
    const scopedDefault = rules.findIndex(rule => rule.ruleTag === `rebuild-policy-portal-${suffix}-default`);
    rules.splice(scopedDefault, 0, { ...sharedGeo, ruleTag: `rebuild-policy-portal-${suffix}-geo-0-domain`,
        inboundTag: [`rebuild-rp-ingress-${siblingInlet._id.slice(-8)}`] });
    assert.ok(exitReport(links, before, after).every(node => !Object.keys(node).some(key => key.startsWith('portalExit'))));
});

const project = path.join(__dirname, '../../..');
async function previewDisplay(fields, modernMap, lang = 'en') {
    const messages = require(`../../locales/${lang}.json`);
    const t = key => key.split('.').reduce((obj, segment) => obj?.[segment], messages) ?? key;
    const html = await ejs.renderFile(path.join(project, 'views/partials/rebuild-preview.ejs'), { t, lang, modernMap });
    let text;
    const window = { confirm: message => { text = message; return false; } };
    const context = vm.createContext({ window, document: { getElementById: () => null } });
    vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
    vm.runInContext(fs.readFileSync(path.join(project, 'public/js/rebuild-preview.js'), 'utf8'), context);
    await window.C3RebuildPreview.confirmReport({ removing: false,
        lookupNode: () => ({ label: 'Portal', role: 'portal' }), report: { allowed: true, previewId: 'a'.repeat(64), nodes: [
            { nodeId: p, profiles: [{ change: 'replace', protectedChanged: false, sections: ['routing'] }], ...fields },
        ] } });
    return text;
}

test('Preview text names both channels even with the same gateway name and keeps legacy default-only output unchanged', async () => {
    const channel = { before: publicTarget(first, 'Gateway'), after: publicTarget(second, 'Gateway') };
    for (const modern of [false, true]) {
        assert.match(await previewDisplay({ portalExitChange: channel }, modern),
            /Default exit: Gateway \(Main channel · #00000012\) → Gateway \(#00000013\)/);
    }
    const ordinary = { before: { nodeId: a, name: 'Gateway' }, after: { nodeId: b, name: 'Other gateway' } };
    assert.equal(await previewDisplay({ portalExitChange: ordinary }, false), await previewDisplay({}, false));
    assert.match(await previewDisplay({ portalExitChange: ordinary }, true), /Default exit: Gateway → Other gateway/);
});

test('Preview text reports geo-only target and private matcher changes independently of a default change', async () => {
    const old = publicTarget(geoEdge, 'Other gateway');
    const swap = { before: [old], after: [publicTarget(second, 'Gateway')] };
    const geoText = await previewDisplay({ portalExitGeoChange: swap }, true);
    assert.match(geoText, /(?:Geo routes|Geo \(routing\)): Other gateway \(#00000014\) → Gateway \(#00000013\)/);
    assert.doesNotMatch(geoText, /Default exit/);
    const matcherOnly = { before: [old], after: [old] };
    const ru = await previewDisplay({ portalExitGeoChange: matcherOnly }, false, 'ru');
    assert.match(ru, /(?:Геомаршруты|Geo \(маршруты\)): меняются маршруты/);
    assert.doesNotMatch(ru, /PRIVATE_MATCHER|network\.rebuildPreview/);
});
