'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const express = require('express');
const mongoose = require('mongoose');
const { fixture } = require('../../modules/relay-l2tp/tests/helpers/installedEditMongoFixture');
const { routerForRebuild } = require('../../routes/cascadeRebuild');
const { createRebuildService } = require('../rebuildService');
const { bindProfileWire, pin } = require('./helpers/rebuildBoundProfileWire');
test.after(() => require('../sshPoolService').closeAll());

test('REALITY link settings persisted by the public rebuild HTTP routes', async t => {
    const f = fixture();
    t.after(() => f.stop());
    await f.start();
    const { HyNode: Node, CascadeLink: Link, RelayL2tpState: State } = f.models;
    const card = { realitySni: ['first.target.test', 'second.target.test'], realityDest: 'backend.target.test:8443' };
    const specs = [
        ['portal', { realitySni: ['source.test'], realityDest: 'source.test:443' }],
        ['bridge', card], ['bridge', { realitySni: [], realityDest: '' }],
        ['portal', { realitySni: [], realityDest: '' }], ['relay', card],
    ];
    const nodes = specs.map(([cascadeRole, xray], i) => ({ _id: new mongoose.Types.ObjectId(),
        active: true, type: 'xray', ip: `192.0.2.${i + 1}`, name: `sni-${i}`, cascadeRole, xray, xrayVersion: '26.3.27' }));
    const [source, target, empty, emptySource, relay] = nodes;
    relay.ssh = { port: 22, username: 'root', password: 'offline-fixture-auth' };
    await Node.collection.insertMany(nodes);
    const idOf = node => String(node._id), machineId = 'e'.repeat(32);
    const enrollment = { nodeId: idOf(relay), host: relay.ip, port: 22, username: 'root', machineId, sshHostKeySha256: pin };
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
        C3_REBUILD_L2TP_RELAYS_JSON: JSON.stringify([enrollment]) };
    const versions = new Map(nodes.map(node => [idOf(node), '26.3.27']));
    const probes = [], open = [], stages = [], writes = [];
    const fixtureTransport = node => ({
        async requireSupportedCore() {
            probes.push(idOf(node));
            assert.ok(await f.connection.db.collection('c3_rebuild_locks').findOne({ _id: 'apply' }), 'probe under the real reservation');
            const version = versions.get(idOf(node));
            if (!version) throw Object.assign(new Error('private transport diagnostic'), { code: 'REBUILD_XRAY_VERSION_UNKNOWN' });
            return version;
        },
        async close() {},
        async stagePair() { stages.push(idOf(node)); },
        async putPair() { writes.push(idOf(node)); },
    });
    bindProfileWire(t.mock.method.bind(t.mock), relay.ip, machineId, () => {
        open.push(idOf(relay)); return fixtureTransport(relay);
    });
    const service = createRebuildService({ env, sync: { _getUsersForNode: async () => [] },
        connect(node) { open.push(idOf(node)); assert.notEqual(idOf(node), idOf(relay), 'bound relay must not use the ordinary connector'); return fixtureTransport(node); } });
    const app = express(), csrf = randomUUID();
    app.use(express.json());
    app.use((req, _res, next) => { req.session = { authenticated: true, panelCsrfToken: csrf }; next(); });
    app.use('/api/cascade', routerForRebuild({ service, Node, Link }));
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    t.after(() => new Promise(resolve => server.close(resolve)));
    const url = `http://127.0.0.1:${server.address().port}/api/cascade`;
    async function request(method, path, payload) {
        const res = await fetch(url + path, { method, headers: { 'content-type': 'application/json', 'x-csrf-token': csrf }, body: JSON.stringify(payload) });
        return { status: res.status, body: await res.json() };
    }
    async function save(method, suffix, payload) {
        const { status, body: result } = await request(method, '/links' + suffix, payload);
        assert.equal(status, 200, result.error?.code);
        assert.equal(result.executionMode, 'rebuild');
        assert.equal(result.status, 'saved');
        return result.linkId;
    }
    const edge = (node, port, fields) => ({ name: `reality-${port}`, portalNodeId: idOf(source),
        bridgeNodeId: idOf(node), priority: 10, mode: 'forward', tunnelPort: port, autoDeploy: false, ...fields });
    const post = (node, port, fields) => save('POST', '', edge(node, port, fields));
    const settings = id => Link.findById(id).select('realitySni realityDest -_id').lean();
    const fingerprint = async id => (await Link.collection.findOne({ _id: new mongoose.Types.ObjectId(id) })).realityFingerprint;
    const noBusinessWrites = async (fn, dialer) => {
        const start = f.commands.length, firstProbe = probes.length, firstOpen = open.length;
        const before = await Link.collection.find({}).sort({ _id: 1 }).toArray();
        const result = await fn();
        assert.deepEqual(f.commands.slice(start).filter(c => ['insert', 'update', 'delete', 'findAndModify', 'commitTransaction'].includes(c.name)
            && c.collection !== 'c3_rebuild_locks'), [], 'no draft, key or other business persistence');
        assert.deepEqual(await Link.collection.find({}).sort({ _id: 1 }).toArray(), before);
        assert.equal(await f.connection.db.collection('c3_rebuild_locks').countDocuments(), 0);
        const selected = dialer ? [idOf(dialer)] : [];
        assert.deepEqual(open.slice(firstOpen), selected);
        assert.deepEqual(probes.slice(firstProbe), selected);
        assert.deepEqual(stages, []); assert.deepEqual(writes, []);
        return result;
    };
    function checkIssue({ status, body }, code, dialer, version, choice) {
        assert.equal(status, 409);
        assert.deepEqual(Object.keys(body).sort(), ['error', 'fingerprintIssue']);
        assert.deepEqual(body.error, { code });
        assert.deepEqual(Object.keys(body.fingerprintIssue).sort(), ['allowed', 'dialerId', 'fingerprint', 'version']);
        const { allowed, ...issue } = body.fingerprintIssue;
        assert.deepEqual(issue, { dialerId: idOf(dialer), version, fingerprint: choice });
        assert.ok(Array.isArray(allowed));
        if (version) { assert.ok(allowed.includes('chrome')); assert.ok(!allowed.includes('random')); }
    }
    const blank = { realitySni: [], realityDest: '' };
    await t.test('POST: forward inherits both fields from the listening bridge', async () => {
        assert.deepEqual(await settings(await post(target, 30101, { ...blank, tunnelSecurity: 'reality' })), card);
    });
    await t.test('POST: omitted mode uses reverse and inherits from the listening portal', async () => {
        assert.deepEqual(await settings(await post(target, 30105, { ...blank, mode: undefined, tunnelSecurity: 'reality' })), source.xray);
    });
    await t.test('POST: an empty listener falls back regardless of the dialing node', async () => {
        const fallback = { realitySni: ['www.google.com'], realityDest: 'www.google.com:443' };
        assert.deepEqual(await settings(await post(empty, 30102, { ...blank, tunnelSecurity: 'reality' })), fallback);
        assert.deepEqual(await settings(await post(target, 30106, { ...blank, mode: 'reverse', tunnelSecurity: 'reality', portalNodeId: String(emptySource._id) })), fallback);
    });
    await t.test('POST: explicit link SNI wins without suppressing target dest', async () => {
        const id = await post(target, 30103, { realitySni: ['explicit.test'], tunnelSecurity: 'reality' });
        assert.deepEqual(await settings(id), { realitySni: ['explicit.test'], realityDest: card.realityDest });
    });
    await t.test('PUT: an unrelated edit preserves saved link SNI and dest', async () => {
        const explicit = { realitySni: ['saved.test'], realityDest: 'saved-dest.test:9443' };
        const id = await post(target, 30104, { ...explicit, tunnelSecurity: 'reality' });
        assert.equal(await save('PUT', `/${id}`, { name: 'renamed-only', ...blank }), id);
        assert.deepEqual(await settings(id), explicit);
        assert.equal((await Link.findById(id).select('name').lean()).name, 'renamed-only');
    });
    await t.test('PUT: a genuinely empty stored SNI inherits independently of the saved dest', async () => {
        const id = await post(target, 30107, { mode: 'reverse', tunnelSecurity: 'reality' });
        await Link.collection.updateOne({ _id: new mongoose.Types.ObjectId(id) }, { $set: { realitySni: [], realityDest: 'saved.test:9443' } });
        await save('PUT', `/${id}`, { name: 'fill-only-empty' });
        assert.deepEqual(await settings(id), { realitySni: source.xray.realitySni, realityDest: 'saved.test:9443' });
    });
    await t.test('POST: implicit REALITY, explicit none; PUT never defaults an existing link to REALITY', async () => {
        const id = await post(target, 30108, {});
        const security = id => Link.findById(id).select('tunnelSecurity -_id').lean();
        assert.deepEqual(await security(id), { tunnelSecurity: 'reality' });
        assert.deepEqual(await settings(id), card);
        const none = await post(target, 30109, { tunnelSecurity: 'none' });
        await save('PUT', `/${none}`, { name: 'keep-none' });
        assert.deepEqual(await security(none), { tunnelSecurity: 'none' });
    });
    await t.test('POST defaults absent and blank native choice to chrome; PUT preserves random on 26.3.27', async () => {
        for (const [port, fields] of [[30110, {}], [30111, { realityFingerprint: '  ' }]]) {
            assert.equal(await fingerprint(await post(target, port, fields)), 'chrome');
        }
        const id = await post(target, 30112, { realityFingerprint: 'random' });
        for (const fields of [{}, { realityFingerprint: '' }, { realityFingerprint: 'random' }]) {
            await save('PUT', `/${id}`, { name: 'rename', ...fields });
            assert.equal(await fingerprint(id), 'random');
        }
    });
    await t.test('POST/PUT refuse against the current forward dialer before saving, including interactive autoDeploy', async () => {
        const id = await post(target, 30113, { realityFingerprint: 'random' });
        versions.set(idOf(source), '26.11.9');
        const code = 'REBUILD_REALITY_FINGERPRINT_UNSUPPORTED';
        for (const autoDeploy of [false, true]) {
            const input = { autoDeploy, interactivePreview: true, xrayVersion: '26.3.27', dialerVersion: '26.3.27' };
            checkIssue(await noBusinessWrites(() => request('POST', '/links', edge(target, 30114, { ...input, realityFingerprint: 'random' })), source), code, source, '26.11.9', 'random');
            checkIssue(await noBusinessWrites(() => request('PUT', `/links/${id}`, { ...input, name: 'refused' }), source), code, source, '26.11.9', 'random');
        }
        const opaqueChoice = { realityFingerprint: 'synthetic-private-text/should-not-be-echoed' };
        checkIssue(await noBusinessWrites(() => request('POST', '/links', edge(target, 30114, opaqueChoice)), source), code, source, '26.11.9', 'unknown');
        await save('PUT', `/${id}`, { name: 'fixed', realityFingerprint: 'chrome' });
        assert.equal(await fingerprint(id), 'chrome');
    });
    await t.test('reverse probes only the bridge, and a bound relay requires its authorized transport', async () => {
        versions.set(idOf(target), '26.11.9');
        const code = 'REBUILD_REALITY_FINGERPRINT_UNSUPPORTED';
        const reverse = { mode: 'reverse', autoDeploy: true, interactivePreview: true, realityFingerprint: 'random' };
        checkIssue(await noBusinessWrites(() => request('POST', '/links', edge(target, 30115, reverse)), target), code, target, '26.11.9', 'random');
        const reverseId = await post(target, 30115, { mode: 'reverse', realityFingerprint: 'chrome' });
        checkIssue(await noBusinessWrites(() => request('PUT', `/links/${reverseId}`, reverse), target), code, target, '26.11.9', 'random');

        versions.set(idOf(relay), '26.11.9');
        await State.collection.insertOne({ node: relay._id, status: 'installed', desiredState: 'installed' });
        checkIssue(await noBusinessWrites(() => request('POST', '/links', edge(relay, 30116, reverse)), relay), code, relay, '26.11.9', 'random');
        env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify([{ ...enrollment, host: '192.0.2.99' }]);
        assert.deepEqual(await noBusinessWrites(() => request('POST', '/links', edge(relay, 30116, reverse))),
            { status: 409, body: { error: { code: 'REBUILD_L2TP_BINDING_MISMATCH' } } });
        // That same bound relay is only the listener in forward mode. Its broken
        // grant must neither open a transport nor gate the portal-dialed draft.
        const first = open.length;
        const id = await post(relay, 30116, { realityFingerprint: 'chrome' });
        assert.deepEqual(open.slice(first), [idOf(source)]);
        assert.deepEqual(await settings(id), card);
    });
    await t.test('unavailable authoritative version cannot fall back to the card cache', async () => {
        versions.delete(idOf(source));
        assert.deepEqual(await noBusinessWrites(() => request('POST', '/links', edge(target, 30117, { xrayVersion: '26.3.27' })), source),
            { status: 409, body: { error: { code: 'REBUILD_XRAY_VERSION_UNKNOWN' } } });
    });
    await t.test('HTTP only projects allowlisted diagnostic fields on compatibility refusal', async t => {
        const text = 'synthetic-private-diagnostic';
        const issue = { dialerId: idOf(source), version: `26.11.9 ${text}`, fingerprint: text,
            allowed: ['chrome', text, 'chrome', { private: text }], raw: text };
        let code = 'REBUILD_REALITY_FINGERPRINT_UNSUPPORTED';
        t.mock.method(service, 'execute', async () => { throw Object.assign(new Error(text), { code, fingerprintIssue: issue }); });
        const preview = () => request('POST', '/rebuild/preview', { linkId: idOf(source) });
        assert.deepEqual(await preview(), { status: 409, body: { error: { code }, fingerprintIssue: {
            dialerId: idOf(source), version: null, fingerprint: 'unknown', allowed: ['chrome'],
        } } });
        code = 'REBUILD_XRAY_VERSION_UNKNOWN';
        assert.deepEqual(await preview(), { status: 409, body: { error: { code } } });
    });
});
