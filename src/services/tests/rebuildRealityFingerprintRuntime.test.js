'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createRebuildService } = require('../rebuildService');
const { createTransport } = require('../rebuildTransport');
const { assertRealityFingerprint } = require('../rebuildRealityFingerprint');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');
const generator = require('../configGenerator');
test.after(() => require.cache[require.resolve('../sshPoolService')]?.exports.closeAll());

const nodes = ['portal', 'relay', 'bridge', 'bridge'].map((cascadeRole, i) => ({
    _id: `node-${i}`, active: true, cascadeRole, type: 'xray', ip: `192.0.2.${i + 1}`, port: 23000 + i,
    xray: { security: 'none', inboundTag: `client-${i}`, apiPort: 24000 + i },
    // Stored version must not stand in for the checked binary, on any endpoint.
    xrayVersion: '26.3.27',
}));
const [portal, relay, bridge, backup] = nodes.map(node => node._id);
const edge = (n, portalNode, bridgeNode, fields) => ({
    _id: String(n).padStart(24, '0'), active: true, mode: 'reverse', priority: n, portalNode, bridgeNode,
    tunnelPort: 25000 + n, tunnelUuid: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`, ...fields,
});
const reality = { tunnelSecurity: 'reality', realityPrivateKey: 'fixture-private-key',
    realityPublicKey: 'fixture-public-key', realityShortIds: ['aabbccdd'], realitySni: ['decoy.invalid'] };
const forward = edge(1, portal, bridge, { ...reality, mode: 'forward', realityFingerprint: 'safari' });
const reverse = edge(2, portal, relay, { ...reality, realityFingerprint: 'firefox' });
const encrypted = edge(3, relay, bridge); // would persist a VLESS key on Apply
const removeTarget = edge(4, portal, backup, { tunnelEncryption: 'none' });
const outboundFingerprint = (profiles, nodeId, tag) => profiles.find(p => p.nodeId === nodeId && p.profile === 'main')
    .config.outbounds.find(o => o.tag === tag)?.streamSettings.realitySettings.fingerprint;
const banner = (version, revision = '676eaf6') => `Xray ${version} (Xray, Penetrates Everything.) ${revision} (go1.27.3 linux/amd64)\nA unified platform for anti-censorship.\n`;

const versionsFor = (dialerVersion, listenerVersion) => new Map([[portal, dialerVersion], [bridge, listenerVersion]]);
const unsupported = (endpointRole, endpointId, version, fingerprint, allowed = ['chrome', 'firefox', 'safari']) => ({
    code: 'REBUILD_REALITY_FINGERPRINT_UNSUPPORTED', fingerprintIssue: { endpointRole, endpointId, version, fingerprint, allowed },
});

test('either endpoint at 26.11+ triggers strict REALITY admission, with safe role/version diagnostics', () => {
    for (const version of ['26.11.0', '26.11.9', '26.12.1', '27.0.1']) {
        for (const [value, label] of [['random', 'random'], ['ios', 'ios'], ['edge', 'edge'], ['untrusted <stored> text', 'unknown']]) {
            const link = { ...forward, realityFingerprint: value };
            assert.throws(() => assertRealityFingerprint(link, versionsFor(version, '26.3.27')), unsupported('dialer', portal, version, label));
            assert.throws(() => assertRealityFingerprint(link, versionsFor('26.3.27', version)), unsupported('listener', bridge, version, label));
        }
        for (const value of [undefined, null, '', ' \t', 'chrome', 'firefox', 'safari']) {
            assert.equal(assertRealityFingerprint({ ...forward, realityFingerprint: value }, versionsFor('26.3.27', version)), value?.trim() || 'chrome');
        }
    }
    const legacy = { ...forward, realityFingerprint: 'random' };
    assert.equal(assertRealityFingerprint(legacy, versionsFor('26.10.31', '26.3.27')), 'random');
    for (const value of [undefined, 26.11, '26.11', '26.11.9\n', '26.11.9-custom', 'Xray 26.11.9']) {
        assert.throws(() => assertRealityFingerprint(legacy, versionsFor('26.3.27', value)), { code: 'REBUILD_XRAY_VERSION_UNKNOWN' });
    }
});

function fixture(t, reverseFingerprint = 'firefox') {
    t.mock.method(generator, 'buildPanelInlineCertificate', () => null);
    const links = structuredClone([forward, { ...reverse, realityFingerprint: reverseFingerprint }, encrypted, removeTarget]);
    const banners = new Map([[portal, banner('26.3.27')], [relay, banner('26.11.9')],
        [bridge, banner('26.11.9')], [backup, banner('26.3.27')]]);
    const files = new Map(composeRebuildProfiles({ nodes, links: [] }).map(p => [`${p.nodeId}:${p.profile}`, p.config]));
    const probes = [], writes = [], candidates = [];
    const query = rows => ({ select() { return this; }, read() { return this; }, readConcern() { return this; }, session() { return this; },
        lean: async () => structuredClone(rows) });
    const service = createRebuildService({
        Node: { find: filter => query(nodes.filter(n => filter._id.$in.includes(n._id))) },
        State: { find: () => query([]) }, sync: { _getUsersForNode: async () => [] },
        Link: {
            find: filter => query(filter._id ? links.filter(l => filter._id.$in.includes(l._id)) : links),
            db: { transaction: async fn => { writes.push('transaction'); await fn({}); } },
            async updateOne(filter, { $set }) {
                writes.push($set.rebuildDelete ? 'tombstone' : $set.status ? 'publish' : 'persist-keys');
                Object.assign(links.find(l => l._id === filter._id), $set);
                return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
            },
            async deleteMany(filter) {
                writes.push('delete');
                let deletedCount = 0;
                for (const id of filter._id.$in) {
                    const index = links.findIndex(l => l._id === id && l.rebuildDelete);
                    if (index !== -1) { links.splice(index, 1); deletedCount++; }
                }
                return { deletedCount };
            },
        },
        env: { C3_REBUILD_ENABLED: 'true', ENCRYPTION_KEY: process.env.ENCRYPTION_KEY },
        locks: { run: fn => fn(async () => {}) }, assertNoRelayAccountIntent: async () => {},
        cache: { invalidateAllSubscriptions: async () => { writes.push('invalidate'); } },
        compose(input) { const profiles = composeRebuildProfiles(input); candidates.push(profiles); return profiles; },
        connect: node => ({ ...createTransport(node, class {
            async connect() {}
            disconnect() {}
            async exec(command, options) {
                assert.equal(command, '/usr/local/bin/xray version');
                assert.equal(options.stdin, undefined);
                probes.push(node._id);
                return { code: 0, stdout: banners.get(node._id) };
            }
        }),
        read: async name => structuredClone(files.get(`${node._id}:${name}`)),
        checkActivation: async ({ readOnly }) => { if (!readOnly) writes.push('check-activation'); },
        prepareActivation: async () => { writes.push('prepare-activation'); },
        stagePair: async () => { writes.push('stage'); },
        putPair: async pair => {
            writes.push('put');
            for (const p of pair) files.set(`${p.nodeId}:${p.profile}`, structuredClone(p.config));
        } }),
    });
    return { service, banners, links, files, probes, writes, candidates };
}

test('Preview and Apply bind REALITY dialer AND listener identities, including same-triplet listener build drift', async t => {
    const f = fixture(t);
    // Removing a fourth edge exercises the tombstone gate while both REALITY dialers remain desired.
    const req = { linkId: removeTarget._id, remove: true };
    const { previewId, allowed } = await f.service.execute({ ...req, preview: true });
    assert.equal(allowed, true);
    const [first] = f.candidates;
    assert.equal(outboundFingerprint(first, portal, 'fwd-00000001'), 'safari');
    assert.equal(outboundFingerprint(first, relay, 'rebuild-rp-dial-00000002'), 'firefox');
    for (const [endpoint, changed] of [[bridge, banner('26.11.9', 'ffffffa')], [bridge, banner('27.0.0')], [relay, banner('26.11.10')], [portal, banner('26.3.28')]]) {
        const original = f.banners.get(endpoint);
        f.banners.set(endpoint, changed);
        await assert.rejects(f.service.execute({ ...req, expectedPreview: previewId }), { code: 'REBUILD_PREVIEW_CHANGED' });
        f.banners.set(endpoint, original);
        assert.deepEqual(f.candidates.at(-1), first);
        assert.deepEqual(f.writes, []);
    }
    assert.equal(f.candidates.length, 5);
    assert.deepEqual(f.probes, Array.from({ length: 5 }, () => [portal, relay, bridge, backup]).flat());
});

test('incompatible or unknown desired sibling endpoint refuses before composition or any effects', async t => {
    const f = fixture(t, 'random');
    const req = { linkId: forward._id }; // Anchor itself is compatible; the reverse sibling is not.
    await assert.rejects(f.service.execute({ ...req, preview: true }), unsupported('dialer', relay, '26.11.9', 'random'));
    f.banners.set(relay, banner('26.3.27'));
    const ticket = await f.service.execute({ ...req, preview: true });
    assert.equal(ticket.allowed, true);
    f.banners.set(portal, banner('27.0.1'));
    await assert.rejects(f.service.execute({ ...req, expectedPreview: ticket.previewId }), unsupported('listener', portal, '27.0.1', 'random'));
    f.banners.set(portal, 'unrecognizable banner');
    for (const options of [{ preview: true }, { expectedPreview: ticket.previewId }]) {
        await assert.rejects(f.service.execute({ ...req, ...options }), { code: 'REBUILD_XRAY_VERSION_UNKNOWN' });
    }
    assert.equal(f.candidates.length, 1);
    assert.deepEqual(f.writes, []);
});

test('an incompatible removed link does not block Preview or removal of that link', async t => {
    const f = fixture(t, 'random');
    const req = { linkId: reverse._id, remove: true };
    const { allowed, previewId } = await f.service.execute({ ...req, preview: true });
    assert.equal(allowed, true);
    assert.deepEqual(f.writes, []);
    // Relay is no longer a REALITY participant: a compatible core change there
    // must not stale the confirmation for the remaining REALITY endpoints.
    f.banners.set(relay, banner('26.11.10'));
    await f.service.execute({ ...req, expectedPreview: previewId });
    assert.ok(!f.links.some(l => l._id === reverse._id));
    for (const effect of ['stage', 'prepare-activation', 'persist-keys', 'tombstone', 'put', 'delete']) assert.ok(f.writes.includes(effect));
    assert.equal(outboundFingerprint(f.candidates.at(-1), portal, 'fwd-00000001'), 'safari');
    assert.equal(outboundFingerprint(f.candidates.at(-1), relay, 'rebuild-rp-dial-00000002'), undefined);
});

test('draft HTTP probes a pinned relay in either role under lock, reports the real endpoint and refuses before persistence', async t => {
    const express = require('express');
    const { routerForRebuild } = require('../../routes/cascadeRebuild');
    const Link = require('../../models/cascadeLinkModel');
    const { bindProfileWire, pin } = require('./helpers/rebuildBoundProfileWire');
    const source = '1'.repeat(24), target = '2'.repeat(24), machineId = 'e'.repeat(32);
    const relayNodes = [source, target].map((_id, i) => ({ _id, active: true, type: 'xray', cascadeRole: 'relay',
        ip: `192.0.2.${i + 1}`, xrayVersion: '26.3.27', ssh: { port: 22, username: 'root', password: 'offline-fixture-auth' } }));
    const query = rows => ({ select() { return this; }, lean: async () => structuredClone(rows) });
    const Node = { find: ({ _id }) => query(relayNodes.filter(n => _id.$in.includes(n._id))) };
    const State = { find: () => query([]) };
    const probes = [], saved = [];
    let held = false;
    t.mock.method(Link.prototype, 'save', async function () { saved.push(this.realityFingerprint); });
    const service = createRebuildService({ Node, State, Link, assertNoRelayAccountIntent: async () => {},
        env: { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: target,
            C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: pin },
        locks: { async run(fn) { held = true; try { return await fn(async () => assert.ok(held)); } finally { held = false; } } },
        connect(node) {
            assert.equal(node._id, source, 'the pinned relay must not use the ordinary connector');
            return createTransport(node, class {
                async connect() {}
                disconnect() {}
                async exec(command) {
                    assert.equal(command, '/usr/local/bin/xray version');
                    assert.ok(held);
                    probes.push(source);
                    return { code: 0, stdout: banner('26.3.27') };
                }
            });
        },
    });
    bindProfileWire(t.mock.method.bind(t.mock), relayNodes[1].ip, machineId, () => ({
        async requireSupportedCore() { assert.ok(held); probes.push(target); return '27.0.1'; },
        async close() {},
    }));
    const app = express(), csrf = 'fixture-csrf';
    app.use(express.json(), (req, _res, next) => { req.session = { authenticated: true, panelCsrfToken: csrf }; next(); });
    app.use(routerForRebuild({ service, Link, Node }));
    const server = await new Promise(resolve => { const handle = app.listen(0, '127.0.0.1', () => resolve(handle)); });
    t.after(() => new Promise(resolve => server.close(resolve)));
    const post = async (realityFingerprint, mode) => {
        const response = await fetch(`http://127.0.0.1:${server.address().port}/links`, {
            method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
            body: JSON.stringify({ name: 'mixed fixture', portalNodeId: source, bridgeNodeId: target, mode, tunnelPort: 24443,
                realityPrivateKey: 'A'.repeat(43), realityPublicKey: 'B'.repeat(43), realityFingerprint, autoDeploy: false }),
        });
        return { status: response.status, body: await response.json() };
    };
    for (const [mode, endpointRole] of [['forward', 'listener'], ['reverse', 'dialer']]) {
        const { code, fingerprintIssue } = unsupported(endpointRole, target, '27.0.1', 'safari', ['chrome', 'firefox']);
        assert.deepEqual(await post('safari', mode), { status: 409, body: { error: { code }, fingerprintIssue } });
        assert.deepEqual(saved, []);
    }
    const { code, fingerprintIssue } = unsupported('listener', target, '27.0.1', 'unknown', ['chrome', 'firefox']);
    assert.deepEqual(await post('fixture <private>', 'forward'), { status: 409, body: { error: { code }, fingerprintIssue } });
    assert.deepEqual(saved, []);
    const { status, body } = await post('firefox', 'forward');
    assert.equal(status, 200, JSON.stringify(body));
    assert.equal(body.desiredSaved, true);
    assert.deepEqual(saved, ['firefox']);
    assert.deepEqual(probes, [source, target, target, source, source, target, source, target]);
});
