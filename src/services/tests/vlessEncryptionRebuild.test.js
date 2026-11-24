'use strict';

const assert = require('node:assert/strict');
const { test, after } = require('node:test');
const { applyVlessEncryption, buildServerDecryption, deriveClientKey } = require('../../utils/vlessEncryption');
const generator = require('../configGenerator');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
const { runRebuild } = require('../rebuildCoordinator');
const { prepareLinks } = require('../rebuildLinkKeys');
const HyNode = require('../../models/hyNodeModel');
const cache = require('../cacheService');
const sync = require('../syncService');
const project = require('mongoose/lib/helpers/projection/applyProjection');
after(() => require('../sshPoolService').closeAll());

const portalId = '000000000000000000000001';
const bridgeId = '000000000000000000000002';
const linkId = '000000000000000000000003';
const users = [{ userId: 'fixture', xrayUuid: '10000000-0000-4000-8000-000000000001' }];
const subscriberTags = ['client-main', 'client-extra', 'client-existing'];
const portal = {
    _id: portalId, name: 'fixture-portal', type: 'xray', cascadeRole: 'portal', active: true, ip: '192.0.2.1', port: 443,
    xray: { inboundTag: subscriberTags[0], transport: 'tcp', security: 'tls', flow: 'xtls-rprx-vision',
        tlsSource: 'self-signed', fallbackDest: '8443', extraInbounds: [
            { id: 'extra', inboundTag: subscriberTags[1], port: 8444, transport: 'ws', security: 'none' },
            { id: 'existing', inboundTag: subscriberTags[2], port: 8445, transport: 'tcp', security: 'none' },
        ] },
};
const bridge = { _id: bridgeId, type: 'xray', cascadeRole: 'bridge', active: true, ip: '192.0.2.2' };
const reverse = {
    _id: linkId, portalNode: portalId, bridgeNode: bridgeId, active: true, mode: 'reverse', status: 'deployed',
    tunnelPort: 31443, tunnelProtocol: 'vless', tunnelTransport: 'tcp', tunnelSecurity: 'none',
    tunnelEncryption: 'vless-enc', tunnelUuid: '20000000-0000-4000-8000-000000000001',
};

async function fixtureKey(mode = 'native', ticket = '600s', previous) {
    const prefix = `mlkem768x25519plus.${mode}.${ticket}.`;
    const fields = { vlessEncryption: true, vlessEncryptionAuth: 'x25519', vlessEncryptionMode: mode,
        vlessEncryptionTicket: ticket };
    assert.equal(await applyVlessEncryption(fields, previous?.fields, { regenerate: Boolean(previous) }), null);
    const value = buildServerDecryption(fields);
    assert.ok(value.startsWith(prefix), 'fixture has an invalid wire prefix');
    const privateKey = value.slice(prefix.length);
    assert.ok(await deriveClientKey('x25519', privateKey) === fields.vlessEncryptionPublicKey, 'fixture key pair mismatched');
    return {
        fields, privateKey, value, redacted: prefix + '<redacted>',
    };
}

const inbound = (config, tag) => config.inbounds.find(row => row.tag === tag);
const main = profiles => profiles.find(p => p.nodeId === portalId && p.profile === 'main').config;
const tunnelBytes = profiles => JSON.stringify(profiles.map(p => ({ ...p, config: { ...p.config,
    inbounds: p.config.inbounds.filter(row => !subscriberTags.includes(row.tag)),
} })));

function assertNoKeys(output, ...keys) {
    const serialized = JSON.stringify(output);
    for (const { privateKey, fields } of keys) {
        assert.ok(!serialized.includes(privateKey) && !serialized.includes(fields.vlessEncryptionPrivateKey),
            'output includes VLESS private key material');
    }
}

test('compiled Rebuild portal preserves flow and unrelated profile bytes through enable and rotation', async () => {
    const [mainTag, extraTag, existingTag] = subscriberTags;
    const query = { read: () => query, readConcern: () => query, lean: async () => [reverse] };
    const links = await prepareLinks({ find: () => query }, [reverse], { privateInventory: true });
    const compose = node => composeRebuildProfiles({ nodes: [node, bridge], links, usersByNode: { [portalId]: users } });
    const off = compose(portal);
    assert.equal(inbound(main(off), mainTag).settings.decryption, 'none');
    assert.deepEqual(inbound(main(off), mainTag).settings.fallbacks, [{ dest: '8443' }]);

    const a = await fixtureKey('xorpub', '0s');
    const b = await fixtureKey('random', '12-36s');
    const c = await fixtureKey('xorpub', '0s', a);
    const enabled = structuredClone(portal);
    Object.assign(enabled.xray, a.fields, { fallbackDest: '' });
    Object.assign(enabled.xray.extraInbounds[0], b.fields);
    const on = compose(enabled);
    const actual = inbound(main(on), mainTag).settings;
    assert.ok(actual.decryption === a.value, 'compiled MAIN did not use its private decryption value');
    assert.equal(actual.fallbacks, undefined);
    assert.deepEqual(actual.clients, inbound(main(off), mainTag).settings.clients);
    assert.equal(actual.clients[0].flow, 'xtls-rprx-vision');
    assert.ok(inbound(main(on), extraTag).settings.decryption === b.value, 'extra inbound did not use its own key');
    assert.equal(inbound(main(on), extraTag).settings.clients[0].flow, undefined);
    assert.deepEqual(inbound(main(on), existingTag), inbound(main(off), existingTag));
    assert.ok(tunnelBytes(on) === tunnelBytes(off), 'unrelated tunnel/profile bytes changed on enable');

    Object.assign(enabled.xray, c.fields);
    const rotated = compose(enabled);
    assert.ok(inbound(main(rotated), mainTag).settings.decryption === c.value, 'compiled MAIN did not use the rotated key');
    assert.ok(inbound(main(rotated), extraTag).settings.decryption === b.value, 'rotation changed the extra key');
    assert.ok(tunnelBytes(rotated) === tunnelBytes(off), 'unrelated tunnel/profile bytes changed on rotation');

    // Real Rebuild protection & opaque confirmation digest. No installation path
    // may be reached while the protected live MAIN and desired MAIN differ.
    let before = off;
    let desired = on;
    const refuseEffect = () => assert.fail('Preview or protected-change refusal performed a write');
    const deps = { global: fn => fn(), withNodes: (_ids, fn) => fn(), links: () => [reverse],
        build: () => ({ candidates: desired }), read: (id, profile) => before.find(p => p.nodeId === id && p.profile === profile).config,
        stagePair: refuseEffect, putPair: refuseEffect, finish: refuseEffect };
    const change = await runRebuild(deps, { linkId, preview: true });
    assert.equal(change.allowed, false);
    assertNoKeys(change, a, b);
    await assert.rejects(runRebuild(deps, { linkId, expectedPreview: change.previewId }), error => {
        assertNoKeys({ ...error, message: error.message }, a, b);
        return error.code === 'REBUILD_CLIENT_CHANGE';
    });
    before = on;
    const steady = await runRebuild(deps, { linkId, preview: true });
    assert.equal(steady.allowed, true);
    desired = rotated;
    const rotate = await runRebuild(deps, { linkId, preview: true });
    assert.equal(rotate.allowed, false);
    assert.notEqual(rotate.previewId, steady.previewId);
    before = rotated;
    const rotatedSteady = await runRebuild(deps, { linkId, preview: true });
    assert.equal(rotatedSteady.allowed, true);
    assert.notEqual(rotatedSteady.previewId, steady.previewId, 'confirmation digest ignored actual key bytes');
    assertNoKeys([steady, rotate, rotatedSteady], a, b, c);

    const disabled = structuredClone(enabled);
    disabled.xray.vlessEncryption = false;
    disabled.xray.fallbackDest = portal.xray.fallbackDest;
    disabled.xray.extraInbounds[0].vlessEncryption = false;
    assert.ok(JSON.stringify(compose(disabled)) === JSON.stringify(off), 'disabling did not restore the original profile bytes');

    // Existing subscriber endpoints, including the untouched sibling extra on
    // the enabled portal and all endpoints when off, must render as before.
    const { generateClashYAML } = require('../../routes/subscription')._test;
    const proxies = node => require('yaml').parse(generateClashYAML(users[0], [node], null)).proxies;
    assert.deepEqual(proxies(disabled), proxies(portal));
    const existing = node => proxies(node).filter(p => p.port === 8445);
    assert.equal(existing(portal).length, 1);
    assert.deepEqual(existing(enabled), existing(portal));
});

test('generator redacts before decrypting and refuses an invalid enabled key instead of emitting none', async () => {
    const a = await fixtureKey();
    const node = structuredClone(portal);
    Object.assign(node.xray, a.fields);
    const generate = options => JSON.parse(generator.generateXrayConfigWithApi(node, users, options));
    assert.equal(inbound(generate({ redactSecrets: true }), subscriberTags[0]).settings.decryption, a.redacted);
    assertNoKeys(generate({ redactSecrets: true }), a);
    node.xray.vlessEncryptionPrivateKey = 'invalid-ciphertext-fixture';
    assert.throws(generate, error => error.code === 'VLESS_ENCRYPTION_KEY_INVALID'
        && !error.message.includes('invalid-ciphertext-fixture'));
    delete node.xray.vlessEncryptionPrivateKey;
    assert.equal(inbound(generate({ redactSecrets: true }), subscriberTags[0]).settings.decryption, a.redacted);
});

function projectionFixture(t, nodes) {
    const projections = [];
    const one = (row, projection) => {
        projections.push(projection);
        const result = project(structuredClone(row), projection);
        if (row) result._id = row._id;
        return result;
    };
    t.mock.method(HyNode.collection, 'findOne', async (filter, options) =>
        one(nodes.find(row => row._id === String(filter._id)), options.projection));
    t.mock.method(HyNode.collection, 'find', (filter, options) => ({ toArray: async () =>
        nodes.filter(row => filter._id.$in.some(id => String(id) === row._id)).map(row => one(row, options.projection)) }));
    return projections;
}

test('trusted reads select both hidden key paths without enriching a caller or a preview', async t => {
    const { loadVlessServerKeys } = require('../vlessServerConfig');
    const { createRebuildService } = require('../rebuildService');
    const a = await fixtureKey();
    const b = await fixtureKey('random', '30s');
    const row = structuredClone(portal);
    Object.assign(row.xray, a.fields, { fallbackDest: '' });
    Object.assign(row.xray.extraInbounds[0], b.fields);
    const projections = projectionFixture(t, [row, bridge]);
    const card = await HyNode.findById(portalId).lean();
    assertNoKeys(card, a, b);
    const loaded = await loadVlessServerKeys(card);
    const actual = JSON.parse(generator.generateXrayConfig(loaded, users));
    assert.ok(inbound(actual, subscriberTags[0]).settings.decryption === a.value, 'main key read was incomplete');
    assert.ok(inbound(actual, subscriberTags[1]).settings.decryption === b.value, 'extra key read was incomplete');
    assertNoKeys(card, a, b);
    assert.deepEqual(Object.keys(projections.at(-1)).filter(key => key !== '_id').sort(), [
        'xray.extraInbounds.id', 'xray.extraInbounds.vlessEncryptionPrivateKey', 'xray.extraInbounds.vlessEncryptionPublicKey',
        'xray.vlessEncryptionPrivateKey', 'xray.vlessEncryptionPublicKey',
    ]);
    const c = await fixtureKey('native', '600s', a);
    Object.assign(row.xray, c.fields);
    const stale = await loadVlessServerKeys(card);
    assert.throws(() => generator.generateXrayConfig(stale, users), { code: 'VLESS_ENCRYPTION_KEY_INVALID' });

    const query = rows => ({ read() { return this; }, readConcern() { return this; }, select() { return this; }, lean: async () => rows });
    const Link = { find: () => query([reverse]) };
    const env = { C3_REBUILD_ENABLED: 'true', ENCRYPTION_KEY: process.env.ENCRYPTION_KEY };
    const links = await prepareLinks(Link, [reverse], { env, privateInventory: true });
    const live = composeRebuildProfiles({ nodes: [row, bridge], links, usersByNode: { [portalId]: users } });
    const service = createRebuildService({ Node: HyNode, Link, env,
        State: { find: () => query([]) },
        locks: { run: fn => fn(async () => true, () => assert.fail('unexpected retain')) },
        sync: { _getUsersForNode: async node => String(node._id) === portalId ? users : [] },
        assertNoRelayAccountIntent: async () => {},
        connect: async node => ({
            async requireSupportedCore() { return '26.11.9'; }, async close() {},
            async read(profile) { return live.find(p => p.nodeId === String(node._id) && p.profile === profile).config; },
            async stagePair() { assert.fail('preview staged a config'); },
            async putPair() { assert.fail('preview installed a config'); },
        }),
    });
    const preview = await service.execute({ linkId, preview: true });
    assert.equal(preview.allowed, true, 'private Rebuild inventory did not reproduce current MAIN');
    assertNoKeys(preview, a, b, c);
});

test('classic sync gates on observed Xray version without touching topology-managed MAIN', async t => {
    const a = await fixtureKey();
    const row = { ...structuredClone(portal), cascadeRole: 'standalone', status: 'online' };
    Object.assign(row.xray, a.fields, { agentToken: 'synthetic-token' });
    const projections = projectionFixture(t, [row]);
    const writes = [];
    t.mock.method(HyNode.collection, 'findOneAndUpdate', async (_, update) => {
        writes.push(update.$set);
        Object.assign(row, update.$set);
        return { status: 'online', lastError: '', healthFailures: 0 };
    });
    t.mock.method(HyNode.collection, 'updateOne', async (_, update) => {
        writes.push(update.$set);
        return { acknowledged: true, matchedCount: 1 };
    });
    const calls = [];
    let managed = false;
    t.mock.method(sync, '_agentRequest', async (_, method, path) => {
        calls.push(`${method} ${path}`);
        if (managed && path === '/sync') return { status: 200, data: {} };
        assert.equal(method, 'GET');
        return { status: 200, data: path === '/info' ? { agent_version: '1.4.0', xray_version: '25.9.4' } : { xray_status: 'online' } };
    });
    t.mock.method(sync, '_getUsersForNode', async () => users);
    t.mock.method(sync, '_topologyManagesNode', async () => managed);
    t.mock.method(require('../nodeSSH').prototype, 'connect', () => assert.fail('unexpected SSH'));
    for (const method of ['invalidateNodes', 'invalidateAllSubscriptions', 'invalidateDashboardCounts']) {
        t.mock.method(cache, method, async () => {});
    }
    const node = await HyNode.findById(portalId).lean();
    await sync.checkXrayAgentHealth(node, { requireProof: true });
    const current = await HyNode.findById(portalId).lean();
    assert.equal(current.xrayVersion, '25.9.4');
    const readCount = projections.length;
    assert.equal(await sync.updateXrayNodeConfig(current), false);
    assert.equal(projections.length, readCount, 'incompatible version should not cause a private key read');
    assert.deepEqual(calls, ['GET /xray-health', 'GET /info']);
    assert.equal(writes.at(-1).status, 'error');
    assert.match(writes.at(-1).lastError, /VLESS Encryption requires Xray >= 25\.9\.5/);
    assertNoKeys(writes, a);

    managed = true;
    calls.length = 0;
    assert.equal(await sync.updateXrayNodeConfig(current), true);
    assert.equal(projections.length, readCount, 'topology-managed sync must not read server keys');
    assert.deepEqual(calls, ['POST /sync', 'GET /xray-health', 'GET /info']);
});

test('the panel config display redacts private VLESS material and suppresses raw errors', async t => {
    const express = require('express');
    const { request } = require('./helpers/rebuildPanelRequest');
    const nodeSetup = require('../nodeSetup');
    const a = await fixtureKey();
    const live = { inbounds: [{ protocol: 'vless', Settings: { Decryption: a.value } },
        { protocol: 'vless', settings: { decryption: 'none' } }] };
    let output = JSON.stringify(live), success = true, closed = 0;
    t.mock.method(HyNode, 'findById', async () => ({ type: 'xray', ssh: { password: 'synthetic' } }));
    t.mock.method(nodeSetup, 'connectSSH', async () => ({ end() { closed++; } }));
    t.mock.method(nodeSetup, 'execSSH', async () => ({ success, output, error: a.value }));
    const app = express();
    app.use('/panel', require('../../routes/panel/nodes'));
    const get = () => request(app, `/panel/nodes/${portalId}/get-config`, { method: 'GET' });
    const response = await get();
    assert.equal(response.status, 200);
    assert.equal(response.headers['cache-control'], 'no-store');
    assertNoKeys(response.body, a);
    const display = JSON.parse(JSON.parse(response.body).config);
    assert.equal(display.inbounds[0].Settings.Decryption, '<redacted>');
    assert.equal(display.inbounds[1].settings.decryption, 'none');
    assert.ok(live.inbounds[0].Settings.Decryption === a.value, 'rendering changed the actual config');
    output = `not JSON: ${a.value}`;
    const malformed = await get();
    assert.equal(malformed.status, 502);
    assertNoKeys(malformed.body, a);
    success = false;
    const failed = await get();
    assert.equal(JSON.parse(failed.body).success, false);
    assertNoKeys(failed.body, a);
    assert.equal(closed, 3);
});
