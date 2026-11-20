'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const express = require('express');
const mongoose = require('mongoose');
const { fixture } = require('../../modules/relay-l2tp/tests/helpers/installedEditMongoFixture');
const { routerForRebuild } = require('../../routes/cascadeRebuild');
const { createRebuildService } = require('../rebuildService');
test.after(() => require('../sshPoolService').closeAll());

test('REALITY link settings persisted by the public rebuild HTTP routes', async t => {
    const f = fixture();
    t.after(() => f.stop());
    await f.start();
    const { HyNode: Node, CascadeLink: Link } = f.models;
    const card = { realitySni: ['first.target.test', 'second.target.test'], realityDest: 'backend.target.test:8443' };
    const specs = [
        ['portal', { realitySni: ['source.test'], realityDest: 'source.test:443' }],
        ['bridge', card], ['bridge', { realitySni: [], realityDest: '' }],
        ['portal', { realitySni: [], realityDest: '' }],
    ];
    const nodes = specs.map(([cascadeRole, xray], i) => ({ _id: new mongoose.Types.ObjectId(),
        active: true, type: 'xray', ip: `192.0.2.${i + 1}`, name: `sni-${i}`, cascadeRole, xray }));
    await Node.collection.insertMany(nodes);
    const [source, target, empty, emptySource] = nodes;
    const service = createRebuildService({ env: { C3_REBUILD_ENABLED: 'true' },
        connect() { throw new Error('draft must not open a node transport'); } });
    const app = express(), csrf = randomUUID();
    app.use(express.json());
    app.use((req, _res, next) => { req.session = { authenticated: true, panelCsrfToken: csrf }; next(); });
    app.use('/api/cascade', routerForRebuild({ service, Node, Link }));
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    t.after(() => new Promise(resolve => server.close(resolve)));
    const url = `http://127.0.0.1:${server.address().port}/api/cascade/links`;
    async function save(method, suffix, payload) {
        const res = await fetch(url + suffix, { method, headers: { 'content-type': 'application/json', 'x-csrf-token': csrf }, body: JSON.stringify(payload) });
        assert.equal(res.status, 200);
        const result = await res.json();
        assert.equal(result.executionMode, 'rebuild');
        assert.equal(result.status, 'saved');
        return result.linkId;
    }
    const post = (node, port, fields) => save('POST', '', { name: `reality-${port}`, portalNodeId: String(source._id),
        bridgeNodeId: String(node._id), priority: 10, mode: 'forward', tunnelPort: port, autoDeploy: false, ...fields });
    const settings = id => Link.findById(id).select('realitySni realityDest -_id').lean();
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
});
