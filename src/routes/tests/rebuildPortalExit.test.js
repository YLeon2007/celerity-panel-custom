'use strict';

process.env.C3_REBUILD_ENABLED = 'true';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const test = require('node:test');
const express = require('express');
const { Types: { ObjectId }, mongo: { BSON } } = require('mongoose');
const { request } = require('../../services/tests/helpers/rebuildPanelRequest');
const { issuePanelCsrfToken } = require('../panel/csrf');
const { routerForRebuild } = require('../cascadeRebuild');
const Link = require('../../models/cascadeLinkModel');
const Node = require('../../models/hyNodeModel');
const { createRebuildService } = require('../../services/rebuildService');
const { ingressTag, egressTag } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');

const ids = Object.fromEntries(['portal', 'relay', 'bridge', 'otherBridge', 'portalLink', 'exit', 'otherExit']
    .map((name, i) => [name, (i + 1).toString(16).padStart(24, '0')]));
const choose = (nodeId, relayGeo = true) => ({ nodeId, relayGeo });
const bson = value => BSON.deserialize(BSON.serialize(value));
const create = { name: 'Portal tunnel', portalNodeId: ids.portal, bridgeNodeId: ids.relay, tunnelSecurity: 'none' };

function fixture(t, { transport = false, createRelayDirect, serialMainAuthority } = {}) {
    const nodes = ['portal', 'relay', 'bridge', 'otherBridge'].map((name, i) => ({
        _id: new ObjectId(ids[name]), type: 'xray', active: true, name, cascadeRole: name.endsWith('Bridge') ? 'bridge' : name,
        ip: `192.0.2.${i + 1}`, port: 42000 + i,
        xray: { security: 'none', transport: 'tcp', inboundTag: 'client', apiPort: 43000 + i },
    }));
    const rows = [Link.castObject({ _id: ids.exit, portalNode: ids.relay, bridgeNode: ids.bridge, name: 'East',
        mode: 'reverse', active: true, tunnelPort: 44001, tunnelSecurity: 'none', tunnelProtocol: 'vless', tunnelEncryption: 'none',
        tunnelUuid: '3558f625-6822-4565-8dfb-d9460b33d312' }), Link.castObject({
        _id: ids.otherExit, portalNode: ids.relay, bridgeNode: ids.otherBridge, name: 'West', mode: 'forward',
        active: true, tunnelPort: 44002, tunnelSecurity: 'none', tunnelProtocol: 'vless', tunnelEncryption: 'none',
        tunnelUuid: '127631bf-c944-4260-ab85-8ce1440f1094' })];
    let held = false, failReadback = false;
    const effects = [];
    const generator = require('../../services/configGenerator');
    t.mock.method(generator, 'buildPanelInlineCertificate', () => null);
    const profiles = new Map(nodes.map(n => [String(n._id), { main: JSON.parse(generator.generateXrayConfigWithApi(n, [])), bridge: null }]));
    const env = { C3_REBUILD_ENABLED: 'true', PANEL_DOMAIN: 'panel.fixture.invalid', ENCRYPTION_KEY: '0'.repeat(64) };
    const service = createRebuildService({
        locks: { async run(fn) {
            assert.equal(held, false); held = true;
            try { return await fn(async () => assert.ok(held), () => assert.fail('retained lock')); }
            finally { held = false; }
        } },
        env, createRelayDirect, serialMainAuthority,
        assertNoRelayAccountIntent: async () => {},
        cache: { invalidateAllSubscriptions: async () => {} },
        sync: { _getUsersForNode: async () => [] },
        connect(node) {
            assert.ok(held);
            effects.push('connect');
            if (!transport) throw new Error('no transport expected');
            const pair = profiles.get(String(node._id));
            return { async requireSupportedCore() {}, async close() {},
                async read(profile, expectedMainSha256) {
                    const snapshot = structuredClone(pair[profile]);
                    if (expectedMainSha256) effects.push('readback');
                    if (failReadback && expectedMainSha256) snapshot.log = { loglevel: 'debug' };
                    return snapshot;
                },
                async stagePair() { effects.push('stage'); },
                async putPair(patches) { effects.push('activate'); for (const p of patches) pair[p.profile] = structuredClone(p.config); } };
        },
    });
    function matches(row, f) {
        return Object.entries(f).every(([k, v]) => {
            const x = k.split('.').reduce((o, key) => o?.[key], row);
            if (k === '$or') return v.some(part => matches(row, part));
            if (v?.$in) return v.$in.some(y => String(y) === String(x));
            if (v?.$ne !== undefined) return v.$ne !== x;
            if (v?.$exists !== undefined) return (x !== undefined) === v.$exists;
            return v === null ? x == null : v instanceof ObjectId ? v.equals(x) : x === v;
        });
    }
    const read = (docs, filter, options) => {
        const apply = require('mongoose/lib/helpers/projection/applyProjection');
        const projection = options?.projection;
        return docs.filter(row => matches(row, filter)).map(row => apply(bson(row),
            Object.values(projection ?? {}).includes(1) ? { _id: 1, ...projection } : projection));
    };
    for (const [model, docs] of [[Link, rows], [Node, nodes], [require('../../models/settingsModel'), []],
        [require('../../modules/relay-l2tp/models/relayL2tpStateModel'), []],
        [require('../../modules/relay-l2tp/models/cascadeTopologyStateModel'), []],
        [require('../../modules/relay-l2tp/models/l2tpUserModel'), []]]) {
        t.mock.method(model.collection, 'find', (f, o) => ({ toArray: async () => read(docs, f, o) }));
        t.mock.method(model.collection, 'findOne', async (f, o) => read(docs, f, o)[0] ?? null);
    }
    const sessionDB = new class FixtureTransaction {}();
    t.mock.method(Link.db, 'transaction', fn => { effects.push('finish'); return fn(sessionDB); });
    t.mock.method(Link.collection, 'deleteMany', async (filter, options) => {
        assert.ok(held); assert.equal(options.session, sessionDB);
        const deleted = rows.filter(row => matches(row, filter));
        for (const row of deleted) rows.splice(rows.indexOf(row), 1);
        return { acknowledged: true, deletedCount: deleted.length };
    });
    const insert = t.mock.method(Link.collection, 'insertOne', async row => {
        assert.ok(held); rows.push(bson(row)); return { acknowledged: true, insertedId: row._id };
    });
    const update = t.mock.method(Link.collection, 'updateOne', async (f, u, options) => {
        if (u.$set?.rebuildApplied) assert.equal(options.session, sessionDB);
        assert.ok(held); const row = rows.find(r => matches(r, f));
        if (row) {
            // The driver honors toBSON() on Mongoose's SingleNested update
            // values; a lean read cannot return those live documents.
            if (u.$set) Object.assign(row, bson(u.$set));
            for (const field of Object.keys(u.$unset ?? {})) delete row[field];
        }
        return { acknowledged: true, matchedCount: Number(!!row), modifiedCount: Number(!!row) };
    });
    t.mock.method(require('../../services/cascadeService'), '_invalidateTopologyCache', () => {});
    const app = express();
    app.use('/api/cascade', require('../../middleware/auth'), routerForRebuild({ service }));
    app.use('/api/cascade', require('../../middleware/auth'), require('../cascade'));
    app.use('/api/mcp', require('../../middleware/auth'), require('../mcp'));
    t.mock.method(require('../../services/rebuildService'), 'createRebuildService', () => service);
    const mcp = require('../../services/mcpService');
    const tool = (name, args, scopes = ['nodes:read', 'nodes:write']) => mcp.callTool(name, args, { scopes });
    const session = { authenticated: true };
    const headers = { 'x-csrf-token': issuePanelCsrfToken({ session }) };
    async function send(method, path, body) {
        const result = await request(app, `/api/cascade${path}`, { method, session, headers, body });
        return { status: result.status, json: JSON.parse(result.body) };
    }
    return { service, env, nodes, rows, profiles, effects, send, tool, insert, update, app, session, headers,
        failReadback: enabled => { failReadback = enabled; } };
}

test('mounted Rebuild API rejects malformed exit selectors before draft or transport effects', async t => {
    const { send, insert, update, effects } = fixture(t);
    for (const details of [
        { rebuildExit: [] }, { rebuildExit: {} }, { rebuildExit: { nodeId: [ids.bridge] } }, { rebuildExit: { linkId: ids.exit } },
        { rebuildExit: { nodeId: ids.bridge, relayGeo: 'false' } },
        { rebuildExit: { nodeId: ids.bridge, extra: true } },
        { 'rebuildExit.nodeId': ids.bridge }, { $set: { rebuildExit: choose(ids.bridge) } },
        { rebuildAppliedExit: choose(ids.bridge) },
    ]) {
        const result = await send('POST', '/links', { ...create, ...details });
        assert.deepEqual(result, { status: 400, json: { error: { code: Object.hasOwn(details, 'rebuildExit')
            ? 'REBUILD_PORTAL_EXIT_INVALID' : 'REBUILD_INVALID_REQUEST' } } }, JSON.stringify(details));
    }
    assert.equal(insert.mock.callCount() + update.mock.callCount(), 0);
    assert.deepEqual(effects, []);
});

test('mounted Rebuild delete/disable and relay retirement refuse a surviving portal reference', async t => {
    const { send, tool, rows, update, service, effects } = fixture(t);
    const receipt = { listener: new ObjectId(ids.portal), mode: 'reverse', protocol: 'vless', port: 42009, uuid: 'fixture' };
    rows.push({ _id: new ObjectId(ids.portalLink), portalNode: new ObjectId(ids.portal), bridgeNode: new ObjectId(ids.relay),
        active: true, rebuildExit: choose(new ObjectId(ids.otherBridge)), rebuildApplied: receipt, rebuildDesiredEdited: true,
        rebuildAppliedExit: choose(new ObjectId(ids.bridge)) });
    const topology = await send('GET', '/topology');
    assert.equal(topology.status, 200);
    const edge = topology.json.edges.find(({ data }) => data.linkId === ids.portalLink).data;
    assert.deepEqual(edge.rebuildExit, choose(ids.otherBridge));
    assert.deepEqual(edge.appliedRebuildExit, choose(ids.bridge));
    assert.equal(edge.hasUnappliedChanges, true);
    const listed = await tool('query', { resource: 'cascade', id: ids.portalLink });
    assert.deepEqual(listed.link.rebuildExit, choose(ids.otherBridge));
    assert.deepEqual(listed.link.appliedRebuildExit, choose(ids.bridge));
    assert.ok(!Object.hasOwn(listed.link, 'rebuildAppliedExit'));
    for (const [method, path, payload] of [
        ['POST', '/rebuild/preview', { linkId: ids.exit, remove: true }],
        ['DELETE', `/links/${ids.exit}`, { expectedPreview: 'a'.repeat(128) }],
        ['PUT', `/links/${ids.exit}`, { active: false }],
    ]) {
        const result = await send(method, path, payload);
        assert.deepEqual(result, { status: 409, json: { error: { code: 'REBUILD_EXIT_IN_USE', portalNames: ['portal'] } } });
    }
    // Retirement deletes incident rows, but a surviving portal node can still
    // run its old MAIN if the relay is retired without first clearing the pin.
    await assert.rejects(service.locks.run(verify => service.retireGraph({ nodeId: ids.relay, mode: 'abandon', preview: true }, verify)),
        { code: 'REBUILD_EXIT_IN_USE' });
    await assert.rejects(service.previewRetireRelay(ids.relay), { code: 'REBUILD_EXIT_IN_USE' });
    const veto = await tool('manage_cascade', { action: 'delete', id: ids.exit, expectedPreview: 'a'.repeat(128) });
    assert.deepEqual(veto, { error: 'REBUILD_EXIT_IN_USE', code: 'REBUILD_EXIT_IN_USE', status: 409, portalNames: ['portal'] });
    rows[2].rebuildAppliedExit = null;
    assert.equal((await tool('manage_cascade', { action: 'preview_remove', id: ids.otherExit })).code, 'REBUILD_EXIT_IN_USE');
    assert.equal(update.mock.callCount(), 0);
    assert.deepEqual(effects, []);
});

test('a duplicate geo edge survives removal, but removing the entire relay/target pair is refused', async t => {
    const { send, tool, rows, service, profiles, effects } = fixture(t, { transport: true });
    const { egressTag } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
    const duplicate = '00000000000000000000000d';
    rows[0].priority = 10;
    const sibling = { ...rows[0], _id: new ObjectId(duplicate), tunnelPort: 44003, priority: 20,
        tunnelUuid: 'acf62a77-770d-4757-aced-43c41ab2430c', geoRouting: { enabled: true, domains: ['fixture.invalid'] } };
    rows.push(sibling);
    const saved = await send('POST', '/links', { ...create, rebuildExit: choose(ids.bridge, false) });
    assert.equal(saved.status, 200);
    const linkId = saved.json.linkId;
    const first = await send('POST', '/rebuild/preview', { linkId });
    assert.equal(first.json.allowed, true);
    assert.equal((await send('POST', `/links/${linkId}/deploy`, { expectedPreview: first.json.previewId })).status, 200);
    const selectedChannel = () => profiles.get(ids.relay).main.routing.rules
        .find(rule => rule.ruleTag === `rebuild-policy-portal-${linkId.slice(-8)}-default`)?.outboundTag;
    assert.equal(selectedChannel(), egressTag({ id: ids.exit, mode: 'reverse' }));
    effects.length = 0;
    assert.deepEqual(await send('PUT', `/links/${ids.exit}`, { active: false, expectedPreview: first.json.previewId }),
        { status: 428, json: { error: { code: 'REBUILD_PREVIEW_REQUIRED' } } });
    assert.equal((await tool('manage_cascade', { action: 'update', id: ids.exit, data: { active: false } })).status, 428);
    assert.equal(rows[0].active, true);
    const previewRemove = () => send('POST', '/rebuild/preview', { linkId: ids.exit, remove: true });
    const veto = { status: 409, json: { error: { code: 'REBUILD_EXIT_IN_USE', portalNames: ['portal'] } } };
    sibling.rebuildDelete = true;
    assert.deepEqual(await previewRemove(), veto);
    delete sibling.rebuildDelete;
    sibling.active = false;
    assert.deepEqual(await previewRemove(), veto);
    sibling.active = true;
    sibling.lifecycle = { state: 'deleting' };
    assert.deepEqual(await previewRemove(), veto);
    delete sibling.lifecycle;
    sibling.portalNode = new ObjectId(ids.portal);
    assert.deepEqual(await previewRemove(), veto, 'the same target on a different source cannot replace the relay edge');
    sibling.portalNode = new ObjectId(ids.relay);
    await assert.rejects(service.previewRetireRelay(ids.relay), { code: 'REBUILD_EXIT_IN_USE' });
    assert.deepEqual(effects, []);
    const p = await previewRemove();
    assert.equal(p.status, 200, JSON.stringify(p.json));
    assert.equal(p.json.allowed, true);
    const removed = await send('DELETE', `/links/${ids.exit}`, { expectedPreview: p.json.previewId });
    assert.equal(removed.status, 200, JSON.stringify(removed.json));
    assert.ok(!rows.some(r => String(r._id) === ids.exit));
    assert.equal(selectedChannel(), egressTag({ id: duplicate, mode: 'reverse' }));
    assert.deepEqual((await send('GET', `/links/${linkId}`)).json.appliedRebuildExit, choose(ids.bridge, false));
    assert.deepEqual(await send('PUT', `/links/${duplicate}`, { active: false }), veto);
    assert.equal((await tool('manage_cascade', { action: 'update', id: duplicate, data: { active: false } })).code, 'REBUILD_EXIT_IN_USE');
});

test('mounted MCP checks panel CSRF for session Rebuild writes and admits an authenticated API key', async t => {
    const { app, session, headers, insert, update, effects } = fixture(t);
    const call = action => ({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'manage_cascade',
        arguments: action === 'create' ? { action, data: create } : { action, id: ids.exit } } });
    for (const [action, path, extra, code] of [
        ['create', '/api/mcp', {}, 'CSRF_TOKEN_INVALID'],
        ['update', '/api/mcp', {}, 'CSRF_TOKEN_INVALID'],
        ['delete', '/api/mcp', {}, 'CSRF_TOKEN_INVALID'],
        ['delete', '/api/mcp/messages?sessionId=fixture', {}, 'CSRF_TOKEN_INVALID'],
        ['create', '/api/mcp', { ...headers, origin: 'http://other.fixture.invalid' }, 'CSRF_ORIGIN_INVALID'],
    ]) {
        const r = await request(app, path, { session, headers: extra, body: call(action) });
        assert.equal(r.status, 403);
        assert.equal(JSON.parse(r.body).code, code);
    }
    assert.equal((await request(app, '/api/mcp', { body: call('create'), headers })).status, 401);
    const rpc = async (body, options) => {
        const r = await request(app, '/api/mcp', { body, ...options });
        assert.equal(r.status, 200);
        const frame = r.body.split('\n').find(line => line.startsWith('data: '));
        return frame ? JSON.parse(frame.slice(6)).result : JSON.parse(r.body).result;
    };
    const queried = await rpc({ id: 1, method: 'tools/call', params: { name: 'query', arguments: { resource: 'cascade' } } }, { session });
    assert.equal(JSON.parse(queried.content[0].text).links.length, 2);
    assert.equal(insert.mock.callCount() + update.mock.callCount(), 0);
    const viaSession = await rpc(call('create'), { session, headers });
    assert.equal(JSON.parse(viaSession.content[0].text).status, 'saved');
    const ApiKey = require('../../models/apiKeyModel');
    t.mock.method(ApiKey, 'findByKey', async key => key === 'fixture-key' ? { _id: ids.portal, scopes: ['mcp:enabled', 'nodes:write'] } : null);
    t.mock.method(ApiKey, 'findByIdAndUpdate', async () => {});
    t.mock.method(require('../../services/cacheService'), 'checkApiKeyRateLimit', async () => ({ allowed: true, limit: 10, count: 1 }));
    const viaKey = await rpc(call('create'), { headers: { authorization: 'Bearer fixture-key' } });
    assert.equal(JSON.parse(viaKey.content[0].text).status, 'saved');
    assert.equal(insert.mock.callCount(), 2);
    assert.deepEqual(effects, []);
});

test('REST and registered MCP reject wrong roles, stale targets, and schema-stripping aliases before effects', async t => {
    const { send, tool, nodes, rows, insert, effects } = fixture(t);
    async function invalid(data) {
        assert.deepEqual(await send('POST', '/links', data), { status: 400, json: { error: { code: 'REBUILD_PORTAL_EXIT_INVALID' } } });
        assert.equal((await tool('manage_cascade', { action: 'create', data })).code, 'REBUILD_PORTAL_EXIT_INVALID');
    }
    const selected = { ...create, rebuildExit: choose(ids.bridge) };
    await invalid({ ...selected, bridgeNodeId: ids.bridge });
    await invalid({ ...selected, portalNodeId: ids.relay, bridgeNodeId: ids.bridge });
    await invalid({ ...selected, rebuildExit: choose(ids.portalLink) });
    await invalid({ ...selected, rebuildExit: { linkId: ids.exit } });
    rows[0].active = false;
    await invalid(selected);
    rows[0].active = true; rows[0].rebuildDelete = true;
    await invalid(selected);
    delete rows[0].rebuildDelete; rows[0].lifecycle = { state: 'deleting' };
    await invalid(selected);
    delete rows[0].lifecycle; nodes[2].cascadeRole = 'relay';
    await invalid(selected);
    nodes[2].cascadeRole = 'bridge'; nodes[2].active = false;
    await invalid(selected);
    nodes[2].active = true; rows[0].portalNode = new ObjectId(ids.portal);
    await invalid(selected);
    const malformed = await tool('manage_cascade', { action: 'create', data: { ...create, 'rebuildExit.nodeId': ids.bridge } });
    assert.equal(malformed.code, 'REBUILD_INVALID_REQUEST');
    await assert.rejects(tool('manage_cascade', { action: 'create', data: selected }, ['nodes:read']), { code: 403 });
    await assert.rejects(tool('query', { resource: 'cascade' }, ['stats:read']), { code: 403 });
    assert.equal(insert.mock.callCount(), 0);
    assert.deepEqual(effects, []);
});

test('registered MCP creates and updates Rebuild drafts without Apply or host operations', async t => {
    const { tool, rows, effects } = fixture(t);
    const saved = await tool('manage_cascade', { action: 'create', data: create });
    assert.equal(saved.status, 'saved');
    assert.equal(saved.desiredSaved, true);
    const id = saved.linkId;
    const edited = await tool('manage_cascade', { action: 'update', id, data: { name: 'Edited in MCP' } });
    assert.equal(edited.status, 'saved');
    const row = rows.find(r => String(r._id) === id);
    assert.equal(row.name, 'Edited in MCP');
    assert.equal(row.rebuildDesiredEdited, true);
    assert.equal(row.rebuildApplied, null);
    assert.equal((await tool('manage_cascade', { action: 'delete', id })).status, 428);
    assert.deepEqual(effects, []);
});

test('mounted REST/MCP resolve a terminal bridge and guard its applied path on removal', async t => {
    const { send, tool, nodes, rows, insert, effects } = fixture(t);
    const tail = new ObjectId('00000000000000000000000a');
    const transit = new ObjectId('00000000000000000000000b');
    nodes.push({ _id: tail, name: 'Tail relay', cascadeRole: 'relay', type: 'xray', active: true });
    const via = { ...rows[0], _id: transit, bridgeNode: tail, priority: 1 };
    rows[0].portalNode = tail;
    rows.push(via, { ...via, _id: new ObjectId('00000000000000000000000c') });
    const spec = { ...create, rebuildExit: choose(ids.bridge, false) };
    const code = 'REBUILD_PORTAL_EXIT_AMBIGUOUS';
    assert.deepEqual(await send('POST', '/links', spec), { status: 409, json: { error: { code } } });
    assert.deepEqual(await tool('manage_cascade', { action: 'create', data: spec }), { status: 409, code, error: code });
    assert.equal(insert.mock.callCount(), 0);
    rows.pop();
    const saved = await send('POST', '/links', spec);
    assert.equal(saved.status, 200, JSON.stringify(saved.json));
    const ingress = rows.find(row => String(row._id) === saved.json.linkId);
    ingress.rebuildAppliedExit = ingress.rebuildExit;
    ingress.rebuildExit = choose(new ObjectId(ids.otherBridge), false);
    ingress.rebuildApplied = { listener: ingress.portalNode, mode: 'reverse', protocol: 'vless', port: 42009, uuid: 'fixture' };
    for (const linkId of [String(transit), ids.exit]) {
        const result = await send('POST', '/rebuild/preview', { linkId, remove: true });
        assert.deepEqual(result, { status: 409, json: { error: { code: 'REBUILD_EXIT_IN_USE', portalNames: ['portal'] } } });
    }
    assert.deepEqual(effects, []);
});

test('mounted REST/MCP refuse a relay exit, live geo transit and a non-routed portal ingress', async t => {
    const { send, tool, nodes, rows, insert, update, effects } = fixture(t);
    const extraRelay = new ObjectId('00000000000000000000000a');
    const chain = new ObjectId('00000000000000000000000b');
    const direct = new ObjectId('00000000000000000000000c');
    nodes.push({ _id: extraRelay, name: 'Extra relay', cascadeRole: 'relay', type: 'xray', active: true });
    rows.push({ ...rows[0], _id: chain, bridgeNode: extraRelay, priority: 30 },
        { ...rows[0], _id: direct, portalNode: extraRelay });
    rows[0].priority = 10;
    rows[1].priority = 20;
    const code = 'REBUILD_PORTAL_EXIT_UNSUPPORTED';
    async function unsupported(data, id) {
        assert.deepEqual(await send(id ? 'PUT' : 'POST', id ? `/links/${id}` : '/links', data), { status: 409, json: { error: { code } } });
        const mcp = await tool('manage_cascade', { action: id ? 'update' : 'create', ...(id && { id }), data });
        assert.deepEqual(mcp, { status: 409, code, error: code });
    }
    assert.deepEqual(await send('POST', '/links', { ...create, rebuildExit: choose(String(extraRelay), false) }),
        { status: 400, json: { error: { code: 'REBUILD_PORTAL_EXIT_INVALID' } } });
    rows[2].geoRouting = { enabled: true, domains: ['geo.fixture.invalid'] };
    await unsupported({ ...create, rebuildExit: choose(ids.bridge) });
    assert.equal(insert.mock.callCount() + update.mock.callCount(), 0);
    const success = await send('POST', '/links', { ...create, rebuildExit: choose(ids.bridge, false) });
    assert.equal(success.status, 200);
    rows.push({ ...rows[0], _id: new ObjectId(ids.portalLink), portalNode: new ObjectId(ids.portal), priority: 1 });
    await unsupported({ rebuildExit: choose(ids.bridge, false) }, success.json.linkId);
    const preview = await send('POST', '/rebuild/preview', { linkId: success.json.linkId });
    assert.deepEqual(preview, { status: 409, json: { error: { code } } });
    assert.equal((await send('PUT', `/links/${success.json.linkId}`, { rebuildExit: null })).status, 200);
    assert.equal(update.mock.callCount(), 1);
    assert.deepEqual(effects, []);
});

test('selector-only REST and MCP saves preserve live reverse observation and its timestamp binding', async t => {
    const { send, tool, rows, update, effects } = fixture(t);
    rows[0].priority = 10;
    rows[1].priority = 20;
    const ingress = Link.castObject({ ...create, _id: ids.portalLink, portalNode: ids.portal, bridgeNode: ids.relay,
        active: true, status: 'deployed', mode: 'reverse', tunnelPort: 44004, tunnelSecurity: 'reality',
        tunnelProtocol: 'vless', tunnelTransport: 'tcp', tunnelUuid: '96a46cab-0210-484d-8403-bd0fd054f460',
        tunnelEncryption: 'vless-enc', updatedAt: new Date(Date.now() - 5000), rebuildApplyEpoch: '5'.repeat(32),
        rebuildAppliedExit: null, rebuildApplied: { listener: ids.portal, mode: 'reverse', protocol: 'vless',
            port: 44004, uuid: '96a46cab-0210-484d-8403-bd0fd054f460' } });
    const proof = { version: 1, established: true, observedAt: new Date(), generation: createHash('sha256').update(JSON.stringify([
        ids.portalLink, ids.portal, ids.relay, ingress.tunnelPort, ingress.tunnelUuid, ingress.tunnelEncryption,
        ingress.updatedAt.getTime(), ingress.rebuildApplyEpoch,
    ])).digest('hex') };
    ingress.rebuildReverseObservation = proof;
    rows.push(ingress);
    const path = `/links/${ids.portalLink}`;
    const status = async () => (await send('GET', path)).json.status;
    assert.equal(await status(), 'online');
    const initial = bson(ingress);
    const saved = await send('PUT', path, { rebuildExit: choose(ids.otherBridge) });
    assert.equal(saved.status, 200, JSON.stringify(saved.json));
    assert.equal((await tool('manage_cascade', { action: 'update', id: ids.portalLink,
        data: { rebuildExit: choose(ids.otherBridge, false) } })).status, 'saved');
    assert.equal(update.mock.callCount(), 2);
    for (const { arguments: [, write] } of update.mock.calls) {
        assert.deepEqual(Object.keys(write.$set).sort(), ['rebuildDesiredEdited', 'rebuildExit']);
        assert.equal(write.$unset, undefined);
    }
    for (const key of ['updatedAt', 'status', 'rebuildReverseObservation', 'rebuildAppliedExit']) {
        assert.deepEqual(ingress[key], initial[key]);
    }
    assert.equal(await status(), 'online');
    assert.deepEqual(effects, []);
});

test('mounted Preview reports known default exit changes from MAIN, never from a desired-only lookup', async t => {
    const { send, nodes, rows, profiles, effects } = fixture(t, { transport: true });
    const createDraft = await send('POST', '/links', { ...create, tunnelEncryption: 'none' });
    assert.equal(createDraft.status, 200);
    const { linkId } = createDraft.json;
    const compose = require('../../modules/relay-l2tp/services/rebuildTopologyComposer').composeRebuildProfiles;
    rows[0].priority = 10; rows[1].priority = 20;
    for (const p of compose({ nodes, links: rows })) profiles.get(p.nodeId)[p.profile] = p.config;
    rows[1].priority = 5;
    const outcome = await send('POST', '/rebuild/preview', { linkId });
    assert.equal(outcome.status, 200);
    assert.deepEqual(outcome.json.nodes.find(n => n.nodeId === ids.portal).portalExitChange, {
        before: { nodeId: ids.bridge, name: 'bridge' }, after: { nodeId: ids.otherBridge, name: 'otherBridge' },
    });
    const old = profiles.get(ids.portal).main.routing.rules;
    profiles.get(ids.portal).main.routing.rules = old.filter(r => !r.ruleTag?.startsWith('rebuild-policy-'));
    const unknown = await send('POST', '/rebuild/preview', { linkId });
    assert.equal(unknown.status, 200);
    assert.ok(unknown.json.nodes.every(n => !Object.hasOwn(n, 'portalExitChange')));
    assert.ok(!effects.some(effect => ['stage', 'activate'].includes(effect)));
});

for (const chainApply of [false, true]) {
    test(`mounted routing-only two-relay exit applies and clears with chain flag ${chainApply ? 'on' : 'off'}`, async t => {
        const { send, nodes, rows, profiles, effects, env } = fixture(t, { transport: true,
            serialMainAuthority: async () => assert.fail('shared channels must use ordinary Apply') });
        if (chainApply) env.C3_REBUILD_CHAIN_APPLY = '1';
        nodes.find(node => String(node._id) === ids.otherBridge).cascadeRole = 'relay';
        rows[0].portalNode = new ObjectId(ids.otherBridge); // b → b6
        // rows[1] already connects r → b. Apply all physical links first.
        const saved = await send('POST', '/links', { ...create, tunnelEncryption: 'none' });
        assert.equal(saved.status, 200);
        const { linkId } = saved.json;
        const path = `/links/${linkId}`;
        const preview = async () => {
            const { status, json } = await send('POST', '/rebuild/preview', { linkId });
            assert.equal(status, 200);
            assert.equal(json.allowed, true, JSON.stringify(json.nodes.map(({ nodeId, profiles }) => ({ nodeId, profiles }))));
            assert.equal(json.transitBlocked, undefined);
            assert.ok(json.nodes.every(node => node.mainRestartCount === undefined));
            return json;
        };
        const apply = async report => {
            effects.length = 0;
            const result = await send('POST', `${path}/deploy`, { expectedPreview: report.previewId });
            assert.equal(result.status, 200, JSON.stringify(result.json));
            assert.deepEqual(effects.filter(effect => effect !== 'connect'), [
                ...Array(4).fill('stage'), ...Array(4).fill('activate'), ...Array(4).fill('readback'), 'finish',
            ]);
        };
        await apply(await preview());
        assert.equal(rows.length, 3);
        assert.ok(rows.every(row => row.rebuildApplied));
        const shared = structuredClone(profiles);
        const portal = rows.find(row => String(row._id) === linkId);
        const pick = choose(ids.bridge, false);
        const routeOnly = report => assert.deepEqual(report.nodes.flatMap(({ nodeId, profiles }) => profiles
            .filter(profile => profile.change !== 'unchanged').map(({ profile, sections }) => [nodeId, profile, sections])),
        [[ids.relay, 'main', ['routing']]]);

        assert.equal((await send('PUT', path, { rebuildExit: pick })).status, 200);
        const selected = await preview();
        routeOnly(selected);
        assert.deepEqual(selected.nodes.find(node => node.nodeId === ids.portal).portalExitPath.after.map(hop => hop.nodeId),
            [ids.relay, ids.otherBridge, ids.bridge]);
        await apply(selected);
        assert.deepEqual(portal.rebuildAppliedExit, choose(new ObjectId(ids.bridge), false));
        const rule = (id, tag) => profiles.get(id).main.routing.rules.find(r => r.ruleTag === tag);
        const ingress = { id: linkId, mode: portal.mode };
        const mid = { id: ids.otherExit, mode: rows[1].mode };
        const tail = { id: ids.exit, mode: rows[0].mode };
        assert.deepEqual(rule(ids.relay, `rebuild-policy-portal-${linkId.slice(-8)}-default`), {
            type: 'field', ruleTag: `rebuild-policy-portal-${linkId.slice(-8)}-default`,
            inboundTag: [ingressTag(ingress)], outboundTag: egressTag(mid),
        });
        assert.equal(rule(ids.otherBridge, 'rebuild-policy-default').outboundTag, egressTag(tail));
        assert.deepEqual(profiles.get(ids.otherBridge), shared.get(ids.otherBridge));

        assert.equal((await send('PUT', path, { rebuildExit: null })).status, 200);
        const clear = await preview();
        routeOnly(clear);
        await apply(clear);
        assert.equal(portal.rebuildAppliedExit, null);
        assert.deepEqual(profiles, shared);
    });
}

test('joined core: mounted draft → Preview/Apply → map and MCP readback preserve the old pin until clear is applied', async t => {
    assert.ok(Link.schema.path('rebuildExit') && Link.schema.path('rebuildAppliedExit'), 'joined core and applied-exit schema required');
    const { send, tool, rows, profiles, effects, update, failReadback } = fixture(t, { transport: true });
    rows[1].priority = 20;
    rows[1].geoRouting = { enabled: true, domains: ['PRIVATE_GEO_FIXTURE'], geoip: [] };
    const saved = await tool('manage_cascade', { action: 'create', data: create });
    assert.equal(saved.status, 'saved');
    const { linkId } = saved;
    const row = rows.find(r => String(r._id) === linkId);
    const path = `/links/${linkId}`;
    const preview = async () => {
        const result = await send('POST', '/rebuild/preview', { linkId });
        assert.equal(result.status, 200, JSON.stringify(result.json));
        assert.equal(result.json.allowed, true);
        return result.json;
    };
    const apply = async p => {
        const result = await send('POST', `${path}/deploy`, { expectedPreview: p.previewId });
        assert.equal(result.status, 200, JSON.stringify(result.json));
    };
    const graph = async () => {
        const result = await send('GET', '/topology');
        assert.equal(result.status, 200, JSON.stringify(result.json));
        assert.ok(!JSON.stringify(result.json).includes('PRIVATE_GEO_FIXTURE'));
        return result.json;
    };
    const map = async () => (await graph()).edges.find(edge => edge.data.linkId === linkId).data;
    assert.deepEqual(effects, [], 'draft must not perform host operations');
    assert.equal((await map()).appliedRebuildExit, undefined);
    await apply(await preview());
    const sharedProfiles = structuredClone(profiles);
    assert.equal(row.rebuildAppliedExit, null, 'BSON stores the known shared policy');
    assert.equal((await map()).appliedRebuildExit, null);
    assert.deepEqual(Object.keys(row.rebuildApplied).sort(), ['listener', 'mode', 'port', 'protocol', 'uuid']);
    const graphEdges = (await graph()).edges.map(edge => edge.data);
    const shared = graphEdges.find(edge => edge.linkId === ids.exit);
    assert.deepEqual([shared.canEdit, shared.priority, shared.geoRouting], [true, 100, { enabled: false }]);
    assert.deepEqual(graphEdges.find(edge => edge.linkId === ids.otherExit).geoRouting, { enabled: true });
    effects.length = 0;
    const beforeEdit = await preview();
    effects.length = 0;
    assert.equal((await send('PUT', path, { rebuildExit: { nodeId: ids.otherBridge } })).status, 200);
    const draft = await map();
    assert.deepEqual(draft.rebuildExit, choose(ids.otherBridge));
    assert.equal(draft.appliedRebuildExit, null);
    assert.equal(draft.hasUnappliedChanges, true);
    assert.deepEqual(effects, []);
    const stale = await send('POST', `${path}/deploy`, { expectedPreview: beforeEdit.previewId });
    assert.equal(stale.json.error.code, 'REBUILD_LINK_CHANGED');
    assert.deepEqual(effects, []);
    const pending = await preview();
    assert.deepEqual(pending.nodes.find(n => n.nodeId === ids.portal).portalExitChange, {
        before: { nodeId: ids.bridge, name: 'bridge' }, after: { nodeId: ids.otherBridge, name: 'otherBridge' },
    });
    assert.ok(pending.nodes.filter(n => n.nodeId !== ids.portal).every(n => !Object.hasOwn(n, 'portalExitChange')));
    assert.equal((await map()).appliedRebuildExit, null, 'Preview is not Apply');
    await apply(pending);
    const settled = await map();
    assert.deepEqual(settled.appliedRebuildExit, choose(ids.otherBridge));
    assert.deepEqual(row.rebuildAppliedExit, choose(new ObjectId(ids.otherBridge)));
    assert.deepEqual(Object.keys(row.rebuildApplied).sort(), ['listener', 'mode', 'port', 'protocol', 'uuid']);
    assert.equal(settled.hasUnappliedChanges, false);
    const detail = await send('GET', path);
    assert.equal(detail.status, 200);
    assert.deepEqual(detail.json.appliedRebuildExit, choose(ids.otherBridge));
    assert.ok(!Object.hasOwn(detail.json, 'rebuildAppliedExit'));
    assert.deepEqual((await tool('query', { resource: 'cascade', id: linkId })).link.appliedRebuildExit, choose(ids.otherBridge));
    assert.deepEqual((await tool('get_topology', {})).links.find(l => l._id.toString() === linkId).appliedRebuildExit, choose(ids.otherBridge));
    const beforeNoop = update.mock.callCount();
    assert.equal((await tool('manage_cascade', { action: 'update', id: linkId, data: { rebuildExit: choose(ids.otherBridge) } })).status, 'saved');
    assert.equal(update.mock.callCount(), beforeNoop);
    assert.equal((await map()).hasUnappliedChanges, false);
    assert.equal((await send('PUT', path, { rebuildExit: null })).status, 200);
    assert.equal(row.rebuildExit, null);
    assert.deepEqual(row.rebuildAppliedExit, choose(new ObjectId(ids.otherBridge)));
    assert.deepEqual((await map()).appliedRebuildExit, choose(ids.otherBridge));
    assert.equal((await send('DELETE', `/links/${ids.otherExit}`, { expectedPreview: 'a'.repeat(128) })).json.error.code, 'REBUILD_EXIT_IN_USE');
    const clear = await preview();
    assert.deepEqual(clear.nodes.find(n => n.nodeId === ids.portal).portalExitChange, {
        before: { nodeId: ids.otherBridge, name: 'otherBridge' }, after: { nodeId: ids.bridge, name: 'bridge' },
    });
    const beforeFailedApply = update.mock.callCount();
    const receipts = () => rows.map(({ rebuildApplied, rebuildAppliedExit, rebuildApplyEpoch }) => bson({
        rebuildApplied, rebuildAppliedExit, rebuildApplyEpoch,
    }));
    const beforeFailedReceipts = receipts();
    failReadback(true);
    assert.deepEqual(await send('POST', `${path}/deploy`, { expectedPreview: clear.previewId }),
        { status: 409, json: { error: { code: 'REBUILD_READBACK_MISMATCH' } } });
    failReadback(false);
    assert.equal(update.mock.callCount(), beforeFailedApply);
    assert.deepEqual(receipts(), beforeFailedReceipts);
    assert.deepEqual((await map()).appliedRebuildExit, choose(ids.otherBridge));
    assert.equal((await send('DELETE', `/links/${ids.otherExit}`, { expectedPreview: 'a'.repeat(128) })).json.error.code, 'REBUILD_EXIT_IN_USE');
    await apply(await preview());
    assert.deepEqual(profiles, sharedProfiles, 'the confirmed inverse restores the original shared profiles');
    assert.equal(row.rebuildAppliedExit, null);
    assert.equal((await map()).appliedRebuildExit, null);
    const savedClear = update.mock.callCount();
    assert.equal((await send('PUT', path, { rebuildExit: null })).status, 200);
    assert.equal(update.mock.callCount(), savedClear, 'equivalent clear does not create a new pending change');
    const removal = await tool('manage_cascade', { action: 'preview_remove', id: ids.otherExit });
    assert.ok(removal.preview?.allowed);
    assert.equal((await tool('manage_cascade', { action: 'delete', id: ids.otherExit, expectedPreview: removal.preview.previewId })).success, true);
    assert.ok(!rows.some(r => String(r._id) === ids.otherExit));
});

test('Install inventory joins the settled pick to its existing MAIN proof and refuses selector drift', async t => {
    const { profileBytes, profileSha256 } = require('../../services/rebuildTransport');
    let pinRow, cut, snapshotPin;
    const frames = [];
    const { service, env, send, rows, profiles, update } = fixture(t, { transport: true, createRelayDirect: async () => ({
        async proveAppliedMain(sha) {
            frames.push('prove');
            assert.equal(sha, snapshotPin);
            if (cut) {
                // Both images can still agree and compile. A change across
                // the two reads is independently a broken Install witness.
                pinRow.rebuildExit = pinRow.rebuildAppliedExit = choose(new ObjectId(ids.otherBridge), false);
            }
            return true;
        },
        async preflight() { frames.push('preflight'); return { machineId: env.C3_REBUILD_L2TP_RELAY_MACHINE_ID }; },
        async close() { frames.push('close'); },
        async install() { assert.fail('no Install dispatch'); },
    }) });
    rows[0].priority = 10;
    rows[1].priority = 20;
    const saved = await send('POST', '/links', { ...create, rebuildExit: choose(ids.otherBridge) });
    assert.equal(saved.status, 200);
    const { linkId } = saved.json;
    const p = await send('POST', '/rebuild/preview', { linkId });
    assert.equal((await send('POST', `/links/${linkId}/deploy`, { expectedPreview: p.json.previewId })).status, 200);
    pinRow = rows.find(row => String(row._id) === linkId);
    const liveMain = profiles.get(ids.relay).main;
    assert.ok(liveMain.routing.rules.some(r => r.ruleTag?.startsWith('rebuild-policy-portal-')));
    snapshotPin = profileSha256(profileBytes(liveMain));
    const db = require('../../modules/relay-l2tp/models/l2tpUserModel').db;
    t.mock.method(db, 'collection', name => {
        assert.equal(name, 'c3_rebuild_relay_accounts');
        return { findOne: async () => null };
    });
    Object.assign(env, { C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: ids.relay,
        C3_REBUILD_L2TP_RELAY_MACHINE_ID: 'a'.repeat(32) });
    const writes = update.mock.callCount();
    const notApplied = { code: 'REBUILD_L2TP_TOPOLOGY_NOT_APPLIED', outcome: 'refused' };
    // The positive control reaches the read-only host prerequisite, not an
    // install command. Neither a draft nor a drifting pin may get that far.
    await assert.rejects(service.installRelay(ids.relay), { code: 'REBUILD_L2TP_HOST_NOT_READY' });
    assert.deepEqual(frames.splice(0), ['prove', 'preflight', 'close']);
    const previous = pinRow.rebuildExit;
    pinRow.rebuildExit = null;
    await assert.rejects(service.installRelay(ids.relay), notApplied);
    assert.deepEqual(frames.splice(0), []);
    pinRow.rebuildExit = previous;
    cut = true;
    await assert.rejects(service.installRelay(ids.relay), notApplied);
    assert.deepEqual(frames, ['prove', 'close']);
    assert.deepEqual(profiles.get(ids.relay).main, liveMain);
    assert.equal(update.mock.callCount(), writes);
});

test.after(() => require('../../services/sshPoolService').closeAll());
