'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
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
        build: (ids, links) => compose(links).filter(p => ids.includes(p.nodeId)),
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
