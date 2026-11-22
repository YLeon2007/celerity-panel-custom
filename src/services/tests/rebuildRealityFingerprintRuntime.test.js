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
const forward = edge(1, portal, bridge, { ...reality, mode: 'forward', realityFingerprint: 'random' });
const reverse = edge(2, portal, relay, { ...reality, realityFingerprint: 'firefox' });
const encrypted = edge(3, relay, bridge); // would persist a VLESS key on Apply
const removeTarget = edge(4, portal, backup, { tunnelEncryption: 'none' });
const outboundFingerprint = (profiles, nodeId, tag) => profiles.find(p => p.nodeId === nodeId && p.profile === 'main')
    .config.outbounds.find(o => o.tag === tag)?.streamSettings.realitySettings.fingerprint;
const banner = (version, revision = '676eaf6') => `Xray ${version} (Xray, Penetrates Everything.) ${revision} (go1.27.3 linux/amd64)\nA unified platform for anti-censorship.\n`;

test('the pure policy accepts only exact triplets and never echoes unrecognized fingerprint text', () => {
    for (const value of [undefined, null, '', ' \t', 'chrome', 'firefox', 'safari']) {
        assert.equal(assertRealityFingerprint({ ...reverse, realityFingerprint: value }, '26.11.9'), value?.trim() || 'chrome');
    }
    for (const value of [undefined, 26.11, '26.11', '26.11.9\n', '26.11.9-custom', 'Xray 26.11.9']) {
        assert.throws(() => assertRealityFingerprint(reverse, value), { code: 'REBUILD_XRAY_VERSION_UNKNOWN' });
    }
    assert.throws(() => assertRealityFingerprint({ ...forward, realityFingerprint: 'untrusted <stored> text' }, '26.11.9'), {
        code: 'REBUILD_REALITY_FINGERPRINT_UNSUPPORTED',
        fingerprintIssue: { dialerId: portal, version: '26.11.9', fingerprint: 'unknown', allowed: ['chrome', 'firefox', 'safari'] },
    });
    for (const version of ['26.3.27', '26.10.31', '26.12.1', '27.11.1']) {
        assert.equal(assertRealityFingerprint(forward, version), 'random');
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
        checkActivation: async () => { writes.push('check-activation'); },
        prepareActivation: async () => { writes.push('prepare-activation'); },
        stagePair: async () => { writes.push('stage'); },
        putPair: async pair => {
            writes.push('put');
            for (const p of pair) files.set(`${p.nodeId}:${p.profile}`, structuredClone(p.config));
        } }),
    });
    return { service, banners, links, files, probes, writes, candidates };
}

test('Preview and Apply bind both REALITY dialers, even to patch and same-triplet build drift with identical profiles', async t => {
    const f = fixture(t);
    // Removing a fourth edge exercises the tombstone gate while both REALITY dialers remain desired.
    const req = { linkId: removeTarget._id, remove: true };
    const { previewId, allowed } = await f.service.execute({ ...req, preview: true });
    assert.equal(allowed, true);
    const [first] = f.candidates;
    assert.equal(outboundFingerprint(first, portal, 'fwd-00000001'), 'random');
    assert.equal(outboundFingerprint(first, relay, 'rebuild-rp-dial-00000002'), 'firefox');
    for (const [dialer, changed] of [[relay, banner('26.11.10')], [relay, banner('26.11.9', 'ffffffa')], [portal, banner('26.3.28')]]) {
        const original = f.banners.get(dialer);
        f.banners.set(dialer, changed);
        await assert.rejects(f.service.execute({ ...req, expectedPreview: previewId }), { code: 'REBUILD_PREVIEW_CHANGED' });
        f.banners.set(dialer, original);
        assert.deepEqual(f.candidates.at(-1), first);
        assert.deepEqual(f.writes, []);
    }
    assert.equal(f.candidates.length, 4);
    assert.deepEqual(f.probes, Array.from({ length: 4 }, () => [portal, relay, bridge, backup]).flat());
});

test('incompatible or unknown desired sibling dialer refuses before composition or any effects', async t => {
    const f = fixture(t, 'random');
    const req = { linkId: forward._id }; // Anchor itself is compatible; the reverse sibling is not.
    const issue = { dialerId: relay, version: '26.11.9', fingerprint: 'random', allowed: ['chrome', 'firefox', 'safari'] };
    const unsupported = { code: 'REBUILD_REALITY_FINGERPRINT_UNSUPPORTED', fingerprintIssue: issue };
    await assert.rejects(f.service.execute({ ...req, preview: true }), unsupported);
    f.banners.set(relay, banner('26.3.27'));
    const ticket = await f.service.execute({ ...req, preview: true });
    assert.equal(ticket.allowed, true);
    f.banners.set(relay, banner('26.11.9'));
    await assert.rejects(f.service.execute({ ...req, expectedPreview: ticket.previewId }), unsupported);
    f.banners.set(relay, 'unrecognizable banner');
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
    // Now the relay is only a listener/non-REALITY participant: compatible
    // changes there must not stale the confirmation for the remaining REALITY dialer.
    f.banners.set(relay, banner('26.11.10'));
    await f.service.execute({ ...req, expectedPreview: previewId });
    assert.ok(!f.links.some(l => l._id === reverse._id));
    for (const effect of ['stage', 'prepare-activation', 'persist-keys', 'tombstone', 'put', 'delete']) assert.ok(f.writes.includes(effect));
    assert.equal(outboundFingerprint(f.candidates.at(-1), portal, 'fwd-00000001'), 'random');
    assert.equal(outboundFingerprint(f.candidates.at(-1), relay, 'rebuild-rp-dial-00000002'), undefined);
});
