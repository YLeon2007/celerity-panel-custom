'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const express = require('express');
const mongoose = require('mongoose');
const { fixture } = require('../../modules/relay-l2tp/tests/helpers/installedEditMongoFixture');
const { routerForRebuild } = require('../../routes/cascadeRebuild');
const { createRebuildService } = require('../rebuildService');

test('REALITY link settings persisted by the public rebuild HTTP routes', async t => {
    const f = fixture();
    t.after(() => f.stop());
    await f.start();
    const { HyNode: Node, CascadeLink: Link } = f.models;
    const card = { realitySni: ['first.target.test', 'second.target.test'], realityDest: 'backend.target.test:8443' };
    const specs = [
        ['portal', { realitySni: ['source.test'], realityDest: 'source.test:443' }],
        ['bridge', card], ['bridge', { realitySni: [], realityDest: '' }],
    ];
    const nodes = specs.map(([cascadeRole, xray], i) => ({ _id: new mongoose.Types.ObjectId(),
        active: true, type: 'xray', ip: `192.0.2.${i + 1}`, name: `sni-${i}`, cascadeRole, xray }));
    await Node.collection.insertMany(nodes);
    const [source, target, empty] = nodes;
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
        bridgeNodeId: String(node._id), priority: 10, tunnelPort: port, tunnelSecurity: 'reality', autoDeploy: false, ...fields });
    const settings = id => Link.findById(id).select('realitySni realityDest -_id').lean();
    const blank = { realitySni: [], realityDest: '' };
    await t.test('POST: blank fields inherit both fields from the target, not the source', async () => {
        assert.deepEqual(await settings(await post(target, 30101, blank)), card);
    });
    await t.test('POST: only an empty target falls back to the global defaults', async () => {
        assert.deepEqual(await settings(await post(empty, 30102, blank)), { realitySni: ['www.google.com'], realityDest: 'www.google.com:443' });
    });
    await t.test('POST: explicit link SNI wins without suppressing target dest', async () => {
        const id = await post(target, 30103, { realitySni: ['explicit.test'] });
        assert.deepEqual(await settings(id), { realitySni: ['explicit.test'], realityDest: card.realityDest });
    });
    await t.test('PUT: an unrelated edit preserves saved link SNI and dest', async () => {
        const explicit = { realitySni: ['saved.test'], realityDest: 'saved-dest.test:9443' };
        const id = await post(target, 30104, explicit);
        assert.equal(await save('PUT', `/${id}`, { name: 'renamed-only' }), id);
        assert.deepEqual(await settings(id), explicit);
        assert.equal((await Link.findById(id).select('name').lean()).name, 'renamed-only');
    });
});
