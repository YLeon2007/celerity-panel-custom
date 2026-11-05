'use strict';
// Local orchestration acceptance only. REAL classic generator, public transfer,
// selected reader/coordinator/materializer/queue/worker/finalizer; DB, transport,
// maintenance/exclusion and byte-aware restart accounting explicitly MODELED.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { randomUUID } = require('node:crypto');
const { manualTlsFixture, TEST_CERT, TEST_KEY, NODE_METADATA_SELECT, id, copy, sha, request } = require('./cascadeAnyOrderLegacyManualTlsFixture');
test.after(() => require('../../../services/sshPoolService').closeAll());
async function withoutCertificateFiles(work) {
    const originals = {}, attempts = [];
    for (const name of ['statSync', 'readFileSync', 'existsSync']) {
        originals[name] = fs[name];
        fs[name] = function(path, ...args) {
            if (typeof path === 'string' && (/\.(?:pem|crt|key)$/.test(path) || /caddy_data|greenlock\.d/.test(path))) {
                attempts.push([name, path]); throw Error('TEST_UNEXPECTED_CERTIFICATE_FILE_ACCESS');
            }
            return originals[name].call(this, path, ...args);
        };
    }
    try { await work(); assert.deepEqual(attempts, [], 'manual input must never consult certificate files'); }
    finally { for (const [name, original] of Object.entries(originals)) fs[name] = original; }
}
function preserved(f, original, history) {
    for (const node of f.topology.nodes) {
        const current = JSON.parse(f.physical.get(f.key(node.id, f.profileFor(node.id))));
        const before = JSON.parse(node.profileConfig);
        for (const tag of ['client-in', 'tls-extra', 'unrelated-client']) {
            const expected = before.inbounds.find(row => row.tag === tag);
            if (expected) assert.deepEqual(current.inbounds.filter(row => row.tag === tag), [expected], `${tag}: port, TLS settings, cert/key, ALPN, domain, UUID and flow retained`);
        }
        assert.deepEqual(current.outbounds.find(row => row.tag === 'unrelated-out'), before.outbounds.find(row => row.tag === 'unrelated-out'));
        assert.deepEqual(current.routing.rules.filter(row => row.inboundTag?.includes('unrelated-client')), before.routing.rules.filter(row => row.inboundTag?.includes('unrelated-client')));
        assert.deepEqual(current.policy, before.policy);
    }
    for (const [target, bytes] of original) if (!f.topology.nodes.some(node => target === f.key(node.id, f.profileFor(node.id)))) {
        assert.equal(f.physical.get(target), bytes, 'nonempty other profile must stay byte-identical');
    }
    for (const [index, owner] of f.data.TopologyConfigOwner.entries()) {
        for (const key of ['generation', 'originalSnapshot', 'adoptionReceipt', 'legacyAppliedTopology']) {
            assert.deepEqual(owner[key], history[index][key], `historical import ${key} is immutable`);
        }
    }
    assert.equal(f.data.CascadeLink.find(row => row._id === id(90)).status, 'pending');
    assert.equal(f.data.CascadeLink.find(row => row._id === id(91)).active, false);
    for (const op of f.data.TopologyOperation) {
        assert.equal(op.effectiveTopology.links.some(row => [id(90), id(91)].includes(row.id)), false);
    }
}
for (const variant of ['primary', 'extra']) test(`${variant} manual TLS: public adoption -> selected modeled apply/replay/revised no-op/delete/recreate preserves ingress and credentials`, async () => withoutCertificateFiles(async () => {
    const f = await manualTlsFixture(variant);
    try {
        assert.equal((await f.models.HyNode.findById(id(1)).lean()).xray.manualKey, undefined, 'actual Mongoose default excludes private key');
        assert.equal((await f.models.HyNode.findById(id(1)).select(NODE_METADATA_SELECT).lean()).xray.manualKey, TEST_KEY, 'actual Mongoose explicit projection retains private key');
        assert.equal(f.data.TopologyConfigOwner.length, 0);
        const tls = JSON.parse(f.topology.nodes[0].profileConfig).inbounds.find(row => row.tag === (variant === 'primary' ? 'client-in' : 'tls-extra'));
        assert.equal(tls.streamSettings.security, 'tls');
        assert.equal(tls.port, variant === 'primary' ? 443 : 24444);
        assert.equal(tls.streamSettings.tlsSettings.serverName, 'manual-tls-TEST-only.invalid');
        assert.deepEqual(tls.streamSettings.tlsSettings.alpn, variant === 'primary' ? ['http/1.1', 'h2'] : ['h2', 'http/1.1']);
        assert.equal(tls.streamSettings.tlsSettings.certificates[0].certificate.join('\n'), TEST_CERT.trim());
        assert.equal(tls.streamSettings.tlsSettings.certificates[0].key.join('\n'), TEST_KEY.trim());
        assert.equal(tls.settings.clients[0].id, '88888888-8888-4888-8888-888888888888');
        assert.equal(tls.settings.clients[0].flow, 'xtls-rprx-vision');
        const original = copy([...f.physical]);
        // Adopt BOTH nonempty profiles of EACH node publicly. Only actual
        // cascade profile imports descriptors; independent profile stays generic.
        for (const node of f.topology.nodes) {
            await f.adopt(node.id);
            await f.adopt(node.id, null, f.profileFor(node.id) === 'xray-main' ? 'xray-bridge' : 'xray-main');
        }
        assert.equal(f.stats().adoptionCAS, 4);
        assert.deepEqual([...f.physical], original, 'adoption performs no profile writes');
        assert.equal(f.calls.length, 0); assert.equal(f.data.TopologyOperation.length, 0);
        const history = copy(f.data.TopologyConfigOwner);
        const runtime = await f.start();
        const queryStart = f.queries.length;
        assert.deepEqual((await f.read()).baselineTopology, f.topology);
        assert.ok(f.queries.slice(queryStart).some(row => row.model === 'HyNode'
            && row.filter.cascadeRole?.$in && row.projection['xray.manualKey'] === 1), 'actual selected reader projects private key at the driver edge');
        const replayKey = randomUUID();
        const response = await f.deployRequest(id(10), replayKey), first = await f.drain(response);
        assert.ok(first.nodes.every(row => row.state === 'committed'));
        const current = await f.read();
        assert.deepEqual(current.baselineTopology.links, f.topology.links, 'original tunnel keys/security/UUID retained');
        for (const node of current.baselineTopology.nodes) {
            assert.equal(node.profileConfig, f.physical.get(f.key(node.id, f.profileFor(node.id))), 'fresh reader uses actual settled candidate, not historical import');
            if (node.role === 'portal') assert.equal(node.xray.manualKey, TEST_KEY);
        }
        preserved(f, original, history);
        const settledBytes = copy([...f.physical]), operationCount = f.data.TopologyOperation.length, callCount = f.calls.length;
        const replay = await f.deployRequest(id(10), replayKey);
        assert.equal(replay.status, 202, JSON.stringify(replay.body));
        assert.equal(replay.body.job.jobId, response.body.job.jobId);
        assert.equal(f.data.TopologyOperation.length, operationCount); assert.equal(f.calls.length, callCount);
        assert.deepEqual([...f.physical], settledBytes);
        // Public save-only adds a pending peer and advances revision without
        // changing applied descriptors or the canonical first-apply bytes.
        const saved = await request(f.http, 'POST', '/links', { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
            name: 'TEST-pending-revision', portalNodeId: id(1), bridgeNodeId: id(2), mode: 'reverse', tunnelPort: 25992,
            tunnelSecurity: 'none', autoDeploy: false }, randomUUID());
        assert.equal(saved.status, 201, JSON.stringify(saved.body));
        assert.deepEqual([...f.physical], settledBytes);
        const beforeNoop = f.calls.length;
        await f.deploy();
        assert.deepEqual([...f.physical], settledBytes, 'revised apply after canonical first apply is byte-no-op');
        assert.equal(f.calls.slice(beforeNoop).some(call => call[0] === 'modeled-write-restart'), false);
        assert.equal(f.calls.slice(beforeNoop).filter(call => call[0] === 'modeled-noop').length, 2);
        preserved(f, original, history);
        const removed = await f.remove(id(10));
        assert.equal(removed.effectiveTopology.links.length, 0);
        assert.equal(f.data.CascadeLink.some(row => row._id === id(10)), false);
        const afterDelete = await f.read(saved.body.createdLinkId);
        assert.equal(afterDelete.baselineTopology.links.length, 0, 'fresh reader publishes settled delete, not historical import');
        for (const node of afterDelete.baselineTopology.nodes) assert.equal(node.profileConfig, f.physical.get(f.key(node.id, f.profileFor(node.id))));
        const blocked = JSON.parse(f.physical.get(f.key(id(1), 'xray-main')));
        for (const tag of ['client-in', ...(variant === 'extra' ? ['tls-extra'] : [])]) {
            const rules = blocked.routing.rules.filter(row => row.inboundTag?.includes(tag));
            assert.ok(rules.length > 0);
            const first = rules[0], out = blocked.outbounds.find(row => row.tag === first.outboundTag);
            assert.equal(out?.protocol, 'blackhole', `${tag}: absent exit must block, never direct`);
            assert.equal(first.domain, undefined, 'no-exit block is unconditional');
        }
        preserved(f, original, history);
        const recreated = await request(f.http, 'POST', '/links', { expectedTopologyRevision: f.data.CascadeTopologyState[0].revision,
            name: 'TEST-recreated', portalNodeId: id(1), bridgeNodeId: id(2), mode: 'reverse', tunnelPort: 25000,
            tunnelSecurity: variant === 'extra' ? 'reality' : 'none', autoDeploy: true }, randomUUID());
        await f.drain(recreated);
        const linkId = recreated.body.createdLinkId;
        assert.ok(linkId);
        const fresh = await f.read(linkId);
        assert.deepEqual(fresh.baselineTopology.links.map(row => row.id), [linkId]);
        for (const node of fresh.baselineTopology.nodes) assert.equal(node.profileConfig, f.physical.get(f.key(node.id, f.profileFor(node.id))));
        const restoredPortal = JSON.parse(f.physical.get(f.key(id(1), 'xray-main')));
        for (const tag of ['client-in', ...(variant === 'extra' ? ['tls-extra'] : [])]) {
            const first = restoredPortal.routing.rules.find(row => row.inboundTag?.includes(tag));
            assert.ok(first);
            assert.notEqual(restoredPortal.outbounds.find(row => row.tag === first.outboundTag)?.protocol, 'blackhole', 'recreate removes the retained no-exit block');
        }
        preserved(f, original, history);
        assert.equal(f.data.CascadeLink.find(row => row._id === saved.body.createdLinkId).status, 'pending');
        assert.ok(f.queries.some(row => row.model === 'HyNode' && row.projection['xray.manualKey'] === 1), 'real driver projection observed');
        assert.ok(runtime.operationWorker);
    } finally { await f.close(); }
}));

const mismatch = 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH';
const unsupported = 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED';
const alteredPem = value => value.replace(/\n([A-Za-z0-9])/, (_, first) => `\n${first === 'A' ? 'B' : 'A'}`);
const negativeCases = [
    ['changed certificate with old observed bytes', t => { t.nodes[0].xray.manualCert = alteredPem(TEST_CERT); }, mismatch],
    ['changed private key with old observed bytes', t => { t.nodes[0].xray.manualKey = alteredPem(TEST_KEY); }, mismatch],
    ['raw-byte drift despite equivalent JSON', t => { t.nodes[0].profileConfig += '\n'; }, 'CONFIG_LEGACY_IMPORT_READBACK_MISMATCH'],
    ...['manualCert', 'manualKey'].flatMap(field => [
        [`absent ${field}`, t => { delete t.nodes[0].xray[field]; }, unsupported],
        [`empty ${field}`, t => { t.nodes[0].xray[field] = ''; }, unsupported],
        [`whitespace ${field}`, t => { t.nodes[0].xray[field] = ' \r\n\t'; }, unsupported],
    ]),
    ...['panel', 'acme', 'self-signed', undefined].map(source => [`node TLS source ${source ?? 'absent'}`, t => {
        if (source === undefined) delete t.nodes[0].xray.tlsSource;
        else t.nodes[0].xray.tlsSource = source;
        for (const extra of t.nodes[0].xray.extraInbounds || []) extra.tlsSource = 'manual';
    }, unsupported]),
    ['manual TLS on bridge metadata', t => { t.nodes[1].xray = copy(t.nodes[0].xray); t.nodes[1].xray.security = 'tls'; }, unsupported],
    ['manual TLS on relay metadata', t => { t.nodes[1].role = 'relay'; t.nodes[1].xray = copy(t.nodes[0].xray); t.nodes[1].xray.security = 'tls'; }, unsupported],
    ['TLS tunnel', t => { t.links[0].tunnelSecurity = 'tls'; }, unsupported],
    ['forward TLS ingress', t => { t.links[0].mode = 'forward'; }, unsupported],
    ['nonempty imported group', t => { t.groups.push({ _id: id(50), paths: [{ linkIds: [id(10)], pathKey: 'unobserved', enabled: true }] }); }, unsupported],
    ['pending imported peer', t => { t.links[0].status = 'pending'; }, 'CONFIG_LEGACY_IMPORT_INVALID'],
    ['inactive imported peer', t => { t.links[0].active = false; }, 'CONFIG_LEGACY_IMPORT_INVALID'],
];
for (const variant of ['primary', 'extra']) for (const [name, change, code] of negativeCases) {
    test(`${variant} manual TLS refuses ${name} without adoption CAS`, async () => withoutCertificateFiles(async () => {
        const f = await manualTlsFixture(variant);
        try {
            const proposed = copy(f.topology), before = copy([...f.physical]); change(proposed);
            await assert.rejects(f.adopt(id(1), proposed), { code });
            assert.equal(f.stats().adoptionCAS, 0);
            assert.equal(f.data.TopologyConfigOwner.length, 1);
            assert.equal(f.data.TopologyConfigOwner[0].owner, 'classic');
            assert.equal(f.data.TopologyConfigOwner[0].adoptionReceipt, undefined);
            assert.equal(f.data.TopologyConfigOwner[0].legacyAppliedTopology, undefined);
            assert.equal(f.data.TopologyOperation.length, 0);
            assert.deepEqual([...f.physical], before);
            assert.equal(f.calls.length, 0);
            if (code === unsupported || code === 'CONFIG_LEGACY_IMPORT_INVALID') assert.equal(f.stats().maintenanceCalls, 0);
        } finally { await f.close(); }
    }));
}
for (const variant of ['primary', 'extra']) for (const [name, change] of [
    ['missing TLS listener', (config, tag) => { config.inbounds = config.inbounds.filter(row => row.tag !== tag); }],
    ['duplicate TLS listener', (config, tag) => { config.inbounds.push(copy(config.inbounds.find(row => row.tag === tag))); }],
    ['TLS certificate metadata substitution', (config, tag) => { config.inbounds.find(row => row.tag === tag).streamSettings.tlsSettings.certificates[0].certificate[1] += 'A'; }],
    ['TLS private-key metadata substitution', (config, tag) => { config.inbounds.find(row => row.tag === tag).streamSettings.tlsSettings.certificates[0].key[1] += 'A'; }],
    ['TLS ALPN mismatch', (config, tag) => { config.inbounds.find(row => row.tag === tag).streamSettings.tlsSettings.alpn = ['h3']; }],
    ['TLS domain mismatch', (config, tag) => { config.inbounds.find(row => row.tag === tag).streamSettings.tlsSettings.serverName = 'foreign.invalid'; }],
    ['TLS port mismatch', (config, tag) => { config.inbounds.find(row => row.tag === tag).port++; }],
]) test(`${variant} manual TLS refuses honest-readback ${name}`, async () => withoutCertificateFiles(async () => {
    const f = await manualTlsFixture(variant);
    try {
        const proposed = copy(f.topology), config = JSON.parse(proposed.nodes[0].profileConfig);
        change(config, variant === 'primary' ? 'client-in' : 'tls-extra');
        proposed.nodes[0].profileConfig = JSON.stringify(config);
        f.physical.set(f.key(id(1), 'xray-main'), proposed.nodes[0].profileConfig);
        await assert.rejects(f.adopt(id(1), proposed), { code: mismatch });
        assert.equal(f.stats().maintenanceCalls, 1, 'honest hash reaches exact artifact verification');
        assert.equal(f.stats().adoptionCAS, 0);
        assert.equal(f.data.TopologyConfigOwner[0].owner, 'classic');
        assert.equal(f.data.TopologyOperation.length, 0);
    } finally { await f.close(); }
}));
for (const variant of ['primary', 'extra']) test(`${variant} manual TLS partial profile adoption refuses selected baseline until public peer adoption`, async () => withoutCertificateFiles(async () => {
    const f = await manualTlsFixture(variant);
    try {
        await f.adopt(id(1));
        await f.start();
        await assert.rejects(f.read(), { code: 'TOPOLOGY_CONFIG_OWNER_REQUIRED' });
        assert.equal(f.calls.length, 0); assert.equal(f.data.TopologyOperation.length, 0);
        await f.adopt(id(2));
        assert.deepEqual((await f.read()).baselineTopology, f.topology);
        assert.equal((await f.models.TopologyConfigOwner.findOne({ node: id(1), profile: 'xray-main' }).lean()).legacyAppliedTopology, undefined);
        assert.deepEqual((await f.models.TopologyConfigOwner.findOne({ node: id(1), profile: 'xray-main' }).select('+legacyAppliedTopology').lean()).legacyAppliedTopology, f.topology);
        // The real strict immutable owner schema/BSON codec retains private
        // manual input and exact historical bytes, without synthetic settlement.
        const mongoose = require('mongoose'), Owner = require('../../../models/topologyConfigOwnerModel');
        for (const original of f.data.TopologyConfigOwner) {
            const doc = new Owner(original); await doc.validate();
            const restored = Owner.hydrate(mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize(doc.toObject())));
            assert.deepEqual(restored.legacyAppliedTopology, f.topology);
            assert.equal(restored.legacyAppliedTopology.nodes[0].xray.manualKey, TEST_KEY);
            assert.equal(restored.lastSettledOperation, undefined);
        }
    } finally { await f.close(); }
}));

test('extra TLS source is inherited from node even when extra claims panel', async () => withoutCertificateFiles(async () => {
    const f = await manualTlsFixture('extra');
    try {
        const proposed = copy(f.topology);
        proposed.nodes[0].xray.extraInbounds[0].tlsSource = 'panel';
        for (const node of proposed.nodes) await f.adopt(node.id, proposed);
        await f.start();
        assert.deepEqual((await f.read()).baselineTopology, proposed, 'per-extra claim cannot override manual node source');
    } finally { await f.close(); }
}));
