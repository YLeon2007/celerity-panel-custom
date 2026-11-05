'use strict';
// Real public producers, Mongo/schema/transactions/projections, actual store,
// claim/worker/typed executor, unchanged path-rebased runner and branded V2
// close/status/settlement. Physical exclusion, SSH, Xray and systemd are MODELED.
// No TLS traffic, physical authority or production activation is claimed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { isDeepStrictEqual: same } = require('node:util');
const fs = require('node:fs');
const path = require('node:path');
const { manualTlsMongoFixture, mongoFixture, TEST_CERT, TEST_KEY, NODE_METADATA_SELECT, sha, evidence, copy, id } = require('./cascadeAnyOrderLegacyManualTlsMongoFixture');
const { TopologyDraftWriteService } = require('../services/topologyDraftWriteService');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
const mongo = mongoFixture();
test.before(() => mongo.start());
test.after(async () => {
    evidence('loaded-dependencies', { files: Object.fromEntries(Object.keys(require.cache)
        .filter(file => file.includes('/node_modules/')).sort().map(file => [file, sha(fs.readFileSync(file))])) });
    await mongo.stop();
});
const plain = value => JSON.parse(JSON.stringify(value));
const equalPrivate = (actual, expected, message) => assert.ok(same(actual, expected), message);
async function withoutCertificateFiles(work) {
    const originals = {}, attempts = [];
    for (const name of ['statSync', 'readFileSync', 'existsSync']) {
        originals[name] = fs[name];
        fs[name] = function(file, ...args) {
            if (typeof file === 'string' && (/\.(?:pem|crt|key)$/.test(file) || /caddy_data|greenlock\.d/.test(file))) {
                attempts.push([name, file]); throw Error('TEST_UNEXPECTED_CERTIFICATE_FILE_ACCESS');
            }
            return originals[name].call(this, file, ...args);
        };
    }
    try { return await work(); }
    finally {
        for (const [name, original] of Object.entries(originals)) fs[name] = original;
        assert.deepEqual(attempts, [], 'descriptor-backed manual TLS never reads certificate files');
    }
}
const owners = f => f.models.TopologyConfigOwner.find({}).sort({ node: 1, profile: 1 }).select('+legacyAppliedTopology +profileTargetPin').lean();
function assertTls(f, node = f.nodes[0]) {
    assert.equal(node.xray.tlsSource, 'manual', 'manual source belongs to the portal node');
    for (const extra of node.xray.extraInbounds || []) assert.equal(extra.tlsSource, undefined, 'extra does not invent a separate certificate authority');
    const config = JSON.parse(f.readProfile(f.hosts.get(node.id), 'xray-main').config);
    const tag = f.variant === 'primary' ? 'client-in' : 'tls-extra';
    const tls = config.inbounds.find(row => row.tag === tag);
    assert.ok(tls); assert.equal(tls.protocol, 'vless'); assert.equal(tls.port, f.variant === 'primary' ? 443 : 24444);
    assert.equal(tls.streamSettings.security, 'tls'); assert.equal(tls.streamSettings.network, 'tcp');
    assert.equal(tls.streamSettings.tlsSettings.serverName, 'manual-tls-TEST-only.invalid');
    assert.deepEqual(tls.streamSettings.tlsSettings.alpn, f.variant === 'primary' ? ['http/1.1', 'h2'] : ['h2', 'http/1.1']);
    assert.equal(sha(tls.streamSettings.tlsSettings.certificates[0].certificate.join('\n')), sha(TEST_CERT.trim()));
    assert.equal(sha(tls.streamSettings.tlsSettings.certificates[0].key.join('\n')), sha(TEST_KEY.trim()));
    assert.equal(tls.settings.clients[0].id, '88888888-8888-4888-8888-888888888888');
    assert.equal(tls.settings.clients[0].email, 'portal-existing@invalid');
    assert.equal(tls.settings.clients[0].flow, 'xtls-rprx-vision');
    if (f.variant === 'extra') assert.equal(config.inbounds.find(row => row.tag === 'client-in').streamSettings.security, 'none');
}
async function preserved(f, history) {
    assertTls(f);
    for (const host of f.hosts.values()) {
        const original = JSON.parse(host.original[host.profile].config), current = JSON.parse(f.readProfile(host, host.profile).config);
        for (const tag of ['client-in', 'tls-extra', 'unrelated-ingress']) {
            const kept = original.inbounds.find(row => row.tag === tag);
            if (kept) equalPrivate(current.inbounds.filter(row => row.tag === tag), [kept], `${tag}: full listener/settings/clients preserved exactly once`);
        }
        assert.deepEqual(current.policy, original.policy);
        assert.deepEqual(current.outbounds.find(row => row.tag === 'unrelated-out'), original.outbounds.find(row => row.tag === 'unrelated-out'));
        assert.deepEqual(current.routing.rules.filter(row => row.outboundTag === 'unrelated-out'), original.routing.rules.filter(row => row.outboundTag === 'unrelated-out'));
    }
    const currentOwners = await owners(f); assert.equal(currentOwners.length, 4);
    for (const before of history) {
        const after = currentOwners.find(row => String(row.node) === String(before.node) && row.profile === before.profile);
        for (const key of ['generation', 'originalSnapshot', 'adoptionReceipt', 'legacyAppliedTopology']) {
            equalPrivate(after[key], before[key], `immutable original owner/import ${key}`);
        }
    }
    f.assertUntouched();
    assert.equal((await f.models.CascadeLink.findById(id(90)).lean()).status, 'pending');
    assert.equal((await f.models.CascadeLink.findById(id(91)).lean()).active, false);
    for (const op of await f.models.TopologyOperation.find({}).select('+effectiveTopology').lean()) {
        assert.equal(op.effectiveTopology.links.some(row => [id(90), id(91)].includes(row.id)), false, 'saved/inactive peers never activated');
    }
}
async function settled(f, op, history) {
    assert.equal(op.status, 'succeeded'); assert.equal(op.heldTopologyAdmission, false); assert.equal(op.admissionScope, 'selected');
    assert.equal(op.nodes.length, 2); assert.equal(new Set(op.nodes.map(node => String(node.node))).size, 2);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 0);
    assert.equal((await f.models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 0);
    assert.equal(op.v2Terminal.state, 'proven'); assert.equal(op.v2Terminal.bindings.length, 2); assert.equal(op.v2Terminal.proofs.length, 2);
    const currentOwners = await owners(f), enrollments = await f.models.TopologyExecutionEnrollment.find({}).lean();
    const bindings = await f.models.TopologyExecutionBinding.find({ operationId: String(op._id) }).lean();
    assert.equal(enrollments.length, 2); assert.equal(bindings.length, 2);
    for (const node of op.nodes) {
        const nodeId = String(node.node), host = f.hosts.get(nodeId);
        const owner = currentOwners.find(row => String(row.node) === nodeId && row.profile === host.profile);
        const enrollment = enrollments.find(row => row.nodeId === nodeId), binding = bindings.find(row => row.nodeId === nodeId);
        const terminal = op.v2Terminal.bindings.find(row => row.nodeId === nodeId), proof = op.v2Terminal.proofs.find(row => row.nodeId === nodeId);
        const pin = op.selectedOwnerPins.find(row => row.node === nodeId);
        assert.equal(owner.owner, 'topology'); assert.equal(owner.generation, enrollment.ownerGeneration);
        assert.equal(owner.generation, binding.ownerGeneration); assert.equal(terminal.generation, binding.generation);
        assert.equal(pin.generation, owner.generation);
        equalPrivate(pin.originalSnapshot, plain(owner.originalSnapshot), 'original snapshot persists in selected operation carrier');
        equalPrivate(pin.adoptionReceipt, plain(owner.adoptionReceipt), 'original adoption receipt persists in selected operation carrier');
        equalPrivate(owner.legacyAppliedTopology, f.topology, 'historical import bytes remain unchanged in real owner collection');
        assert.equal(owner.lastSettledOperation, String(op._id)); assert.equal(owner.lastSettledGeneration, binding.generation);
        assert.equal(owner.lastSettledCloseId, binding.commandIds.close);
        assert.equal(node.state, 'committed'); assert.equal(node.role, host.node.role); assert.equal(node.targetProfile, host.profile);
        assert.equal(sha(f.readProfile(host, host.profile).config), node.candidateHash);
        equalPrivate(f.readProfile(host, host.profile).config, Buffer.from(node.candidate.bytes).toString(), 'runner committed exact persisted candidate bytes');
        assert.equal(proof.command, 'status'); assert.equal(proof.terminal, true); assert.equal(proof.terminalOutcome, 'verified');
        assert.equal(proof.commandId, binding.commandIds.close); assert.equal(proof.generation, binding.generation);
        assert.notEqual(binding.proofId, owner.adoptionReceipt.proofId);
        for (const carrier of [owner, node, enrollment, binding, terminal]) assert.equal(Object.hasOwn(carrier, 'profileTargetPin'), false, 'reverse uses unchanged role/profile contract');
    }
    for (const topology of [op.baselineTopology, op.effectiveTopology]) {
        const portal = topology.nodes.find(row => row.id === f.nodes[0].id);
        if (portal) assert.equal(sha(portal.xray.manualKey), sha(TEST_KEY), 'private manual key survives operation schema/BSON/claim round trip');
    }
    await preserved(f, history);
    evidence('manual-tls-settled', { variant: f.variant, operationId: String(op._id), kind: op.kind,
        nodes: op.nodes.map(row => ({ node: String(row.node), targetProfile: row.targetProfile, candidateHash: row.candidateHash })),
        terminalProofs: op.v2Terminal.proofs.map(row => ({ command: row.command, commandId: row.commandId, generation: row.generation })),
        boundary: 'real Mongo/worker/executor/runner/V2; modeled physical exclusion, SSH, Xray, sockets and systemd; no TLS traffic' });
}
async function fresh(f, linkId, expectedIds) {
    const selected = await f.read(linkId);
    assert.deepEqual(selected.baselineTopology.links.map(row => row.id).sort(), expectedIds);
    for (const node of selected.baselineTopology.nodes) {
        const host = f.hosts.get(node.id);
        equalPrivate(node.profileConfig, f.readProfile(host, host.profile).config, 'fresh repository resolves current committed candidate, not historical original');
        if (node.role === 'portal') assert.equal(sha(node.xray.manualKey), sha(TEST_KEY));
    }
    return selected;
}
function assertTunnel(f, op, link) {
    const portal = JSON.parse(Buffer.from(op.nodes.find(row => row.role === 'portal').candidate.bytes));
    const bridge = JSON.parse(Buffer.from(op.nodes.find(row => row.role === 'bridge').candidate.bytes));
    const listener = portal.inbounds.find(row => row.port === link.tunnelPort);
    assert.ok(listener); assert.equal(listener.settings.clients[0].id, link.tunnelUuid);
    assert.equal(listener.streamSettings.security, link.tunnelSecurity);
    const dialer = bridge.outbounds.find(row => row.settings?.vnext?.some(peer => peer.port === link.tunnelPort));
    assert.ok(dialer); assert.equal(dialer.settings.vnext[0].users[0].id, link.tunnelUuid);
    if (link.tunnelSecurity === 'reality') {
        assert.equal(sha(listener.streamSettings.realitySettings.privateKey), sha(link.realityPrivateKey));
        assert.equal(dialer.streamSettings.realitySettings.publicKey, link.realityPublicKey);
    }
    assert.equal(f.link.tunnelPort, link.tunnelPort);
}
for (const variant of ['primary', 'extra']) test(`${variant} manual TLS Mongo: public adopt/preEnroll -> durable apply/replay/revised byte-no-op/delete-empty/new-ID recreate -> fresh V2 read`, { timeout: 240000 }, async t => withoutCertificateFiles(async () => {
    const f = await manualTlsMongoFixture(t, mongo, variant);
    const portalId = f.nodes[0].id;
    assert.equal((await f.models.HyNode.findById(portalId).lean()).xray.manualKey, undefined);
    assert.equal(sha((await f.models.HyNode.findById(portalId).select(NODE_METADATA_SELECT).lean()).xray.manualKey), sha(TEST_KEY));
    assert.equal(await f.models.TopologyConfigOwner.countDocuments(), 0);
    assert.equal(await f.models.TopologyExecutionEnrollment.countDocuments(), 0);
    assert.equal(await f.models.TopologyExecutionBinding.countDocuments(), 0);
    assertTls(f);
    await f.adopt(); assert.equal(f.stats.adoptionCAS, 4); f.assertOriginalFiles();
    assert.equal(f.events.length, 0); assert.equal(await f.models.TopologyOperation.countDocuments(), 0);
    const history = await owners(f);
    for (const owner of history) {
        assert.equal((await f.models.TopologyConfigOwner.findById(owner._id).lean()).legacyAppliedTopology, undefined);
        assert.equal(owner.lastSettledOperation, undefined);
        if (owner.legacyAppliedTopology) assert.equal(sha(owner.legacyAppliedTopology.nodes[0].xray.manualKey), sha(TEST_KEY));
    }
    await f.enroll();
    const queryStart = mongo.commands.length;
    equalPrivate((await f.read(f.link.id)).baselineTopology, f.topology, 'publicly adopted exact legacy snapshot is selected baseline');
    assert.ok(mongo.commands.slice(queryStart).some(row => row.collection === f.models.HyNode.collection.name
        && row.projection?.['xray.manualKey'] === 1), 'actual Mongo selected-reader command projects private manual key');
    const request = await f.applyRequest(), job = await f.service.acceptVersioned(request), first = await f.drain(job);
    await settled(f, first, history); assertTunnel(f, first, f.link);
    for (const host of f.hosts.values()) assert.deepEqual(f.events.filter(row => row.node === host.node.id).map(row => row.command), ['prepare', 'commit', 'verify', 'close', 'status']);
    const selected = await fresh(f, f.link.id, [f.link.id]);
    assert.ok(selected.baselineTopology.nodes.some(node => node.profileConfig !== f.topology.nodes.find(row => row.id === node.id).profileConfig), 'canonical candidate differs from historical import');
    const eventCount = f.events.length, operationCount = await f.models.TopologyOperation.countDocuments(), bindingCount = await f.models.TopologyExecutionBinding.countDocuments();
    const replay = await f.service.acceptVersioned(request);
    assert.equal(replay.jobId, job.jobId); assert.equal((await f.worker.run(String(first._id))).status, 'succeeded');
    assert.equal(f.events.length, eventCount); assert.equal(await f.models.TopologyOperation.countDocuments(), operationCount);
    assert.equal(await f.models.TopologyExecutionBinding.countDocuments(), bindingCount);
    const beforeNoop = [...f.hosts.values()].map(host => f.readProfile(host, host.profile));
    const profileInodes = () => [...f.hosts.values()].map(host => {
        const file = path.join(host.root, 'usr/local/etc', host.profile === 'xray-main' ? 'xray' : 'xray-bridge', 'config.json');
        const stat = fs.statSync(file, { bigint: true });
        return [stat.dev, stat.ino, stat.mtimeNs, stat.size];
    });
    const beforeNoopInodes = profileInodes();
    const oldRevision = await f.revision();
    const writes = new TopologyDraftWriteService({ repository: new TopologyDraftRepository(f.models) });
    await writes.updateLink({ expectedTopologyRevision: oldRevision, linkId: f.link.id, changes: { name: 'same manual TLS bytes, new revision' } });
    assert.ok(await f.revision() > oldRevision);
    const again = await f.apply(); assert.notEqual(String(again._id), String(first._id));
    await settled(f, again, history); assertTunnel(f, again, f.link);
    assert.deepEqual(again.nodes.map(row => row.candidateHash), first.nodes.map(row => row.candidateHash));
    equalPrivate([...f.hosts.values()].map(host => f.readProfile(host, host.profile)), beforeNoop, 'actual runner byte-no-op leaves profile and modeled restart counters unchanged');
    equalPrivate(profileInodes(), beforeNoopInodes, 'actual runner no-op does not replace or rewrite either config inode');
    await fresh(f, f.link.id, [f.link.id]);
    const removed = await f.remove(); await settled(f, removed, history);
    assert.deepEqual(removed.effectiveTopology.links, []); assert.equal(await f.models.CascadeLink.findById(f.link.id).lean(), null);
    await fresh(f, id(90), []);
    const blocked = JSON.parse(f.readProfile(f.hosts.get(portalId), 'xray-main').config);
    for (const tag of ['client-in', ...(variant === 'extra' ? ['tls-extra'] : [])]) {
        const firstRule = blocked.routing.rules.find(row => row.inboundTag?.includes(tag)); assert.ok(firstRule);
        assert.equal(blocked.outbounds.find(row => row.tag === firstRule.outboundTag)?.protocol, 'blackhole');
        assert.equal(firstRule.domain, undefined); assert.equal(firstRule.ip, undefined, 'no-exit ingress block is unconditional');
        assert.deepEqual(Object.keys(firstRule).sort(), ['inboundTag', 'outboundTag', 'type']);
        for (const earlier of blocked.routing.rules.slice(0, blocked.routing.rules.indexOf(firstRule))) {
            if (earlier.inboundTag && !earlier.inboundTag.includes(tag)) continue;
            assert.equal(blocked.outbounds.find(row => row.tag === earlier.outboundTag)?.protocol, 'blackhole', 'no earlier matching direct/active fallback can bypass the no-exit block');
        }
    }
    assert.equal(blocked.inbounds.some(row => row.port === f.link.tunnelPort), false, 'old reverse tunnel listener removed');
    const { op: recreated, link } = await f.recreate(); assert.notEqual(String(link._id), f.link.id);
    await settled(f, recreated, history); assertTunnel(f, recreated, link);
    assert.deepEqual(recreated.baselineTopology.links, []); await fresh(f, String(link._id), [String(link._id)]);
    const restored = JSON.parse(f.readProfile(f.hosts.get(portalId), 'xray-main').config);
    for (const tag of ['client-in', ...(variant === 'extra' ? ['tls-extra'] : [])]) {
        const firstRule = restored.routing.rules.find(row => row.inboundTag?.includes(tag)); assert.ok(firstRule);
        assert.notEqual(restored.outbounds.find(row => row.tag === firstRule.outboundTag)?.protocol, 'blackhole', 'recreate removes stale no-exit block');
    }
    assert.equal(await f.models.TopologyExecutionEnrollment.countDocuments(), 2);
    assert.equal(await f.models.TopologyExecutionBinding.countDocuments(), 8);
    assert.equal(await f.models.TopologyOperation.countDocuments(), 4);
    for (const host of f.hosts.values()) {
        const bindings = await f.models.TopologyExecutionBinding.find({ nodeId: host.node.id }).sort({ topologyRevision: 1 }).lean();
        for (let index = 1; index < bindings.length; index++) {
            assert.equal(bindings[index].predecessorBindingId, bindings[index - 1]._id);
            assert.equal(bindings[index].predecessorGeneration, bindings[index - 1].generation);
        }
        const log = fs.readFileSync(path.join(host.root, 'systemctl.log'), 'utf8');
        assert.equal(log.split('\n').some(line => line.startsWith('stop ')), false, 'neither shared profile service is stopped');
    }
}));

const negativeCases = [
    ['certificate metadata drift', topology => { topology.nodes[0].xray.manualCert += 'TEST-drift'; }, 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH'],
    ['private-key metadata drift', topology => { topology.nodes[0].xray.manualKey += 'TEST-drift'; }, 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH'],
    ['raw bytes with old readback hash', topology => { topology.nodes[0].profileConfig += '\n'; }, 'CONFIG_LEGACY_IMPORT_READBACK_MISMATCH'],
    ['missing private manual key', topology => { delete topology.nodes[0].xray.manualKey; }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
    ['honest-readback TLS key substitution', (topology, f) => {
        const node = topology.nodes[0], config = JSON.parse(node.profileConfig);
        config.inbounds.find(row => row.tag === (f.variant === 'primary' ? 'client-in' : 'tls-extra')).streamSettings.tlsSettings.certificates[0].key[1] += 'A';
        node.profileConfig = JSON.stringify(config); f.hosts.get(node.id).put('/usr/local/etc/xray/config.json', node.profileConfig);
    }, 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH'],
];
for (const variant of ['primary', 'extra']) for (const [name, mutate, code] of negativeCases) {
    test(`${variant} manual TLS Mongo refuses ${name} before adoption CAS`, { timeout: 30000 }, async t => withoutCertificateFiles(async () => {
        const f = await manualTlsMongoFixture(t, mongo, variant), proposed = copy(f.topology); mutate(proposed, f);
        const profiles = () => [...f.hosts.values()].flatMap(host => Object.keys(host.original).map(profile => f.readProfile(host, profile)));
        const before = profiles();
        await assert.rejects(f.adoptOne(f.nodes[0].id, proposed), { code });
        equalPrivate(profiles(), before, 'failed public adoption writes neither profile nor service state');
        assert.equal(f.stats.adoptionCAS, 0);
        const owner = (await owners(f))[0]; assert.equal(owner.owner, 'classic');
        assert.equal(owner.adoptionReceipt, undefined); assert.equal(owner.legacyAppliedTopology, undefined);
        assert.equal(await f.models.TopologyOperation.countDocuments(), 0); assert.equal(f.events.length, 0);
        assert.equal(await f.models.TopologyExecutionEnrollment.countDocuments(), 0);
        assert.equal(f.stats.maintenanceCalls, code === 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED' ? 0 : 1);
        evidence('manual-tls-negative', { variant, case: name, code, adoptionCAS: f.stats.adoptionCAS });
    }));
}
for (const variant of ['primary', 'extra']) test(`${variant} manual TLS Mongo: partial public import and persisted private snapshot corruption fail closed`, { timeout: 30000 }, async t => withoutCertificateFiles(async () => {
    const f = await manualTlsMongoFixture(t, mongo, variant), portalId = f.nodes[0].id;
    await f.adoptOne(portalId);
    await assert.rejects(f.read(f.link.id), { code: 'TOPOLOGY_CONFIG_OWNER_REQUIRED' });
    assert.equal(f.events.length, 0); assert.equal(await f.models.TopologyOperation.countDocuments(), 0);
    await f.adoptOne(f.nodes[1].id);
    equalPrivate((await f.read(f.link.id)).baselineTopology, f.topology, 'complete public import reaches exact selected baseline');
    const owner = await f.models.TopologyConfigOwner.findOne({ node: portalId, profile: 'xray-main' }).select('+legacyAppliedTopology').lean();
    assert.equal(sha(owner.legacyAppliedTopology.nodes[0].xray.manualKey), sha(TEST_KEY));
    assert.equal(owner.lastSettledOperation, undefined);
    // Raw corruption is an adversarial control, not an authority/success seed.
    const changed = await f.models.TopologyConfigOwner.collection.updateOne({ _id: owner._id },
        { $set: { 'legacyAppliedTopology.nodes.0.xray.manualKey': TEST_KEY + 'TEST-drift' } });
    assert.equal(changed.modifiedCount, 1);
    const drifted = await f.models.TopologyConfigOwner.findById(owner._id).select('+legacyAppliedTopology').lean();
    assert.equal(sha(drifted.legacyAppliedTopology.nodes[0].xray.manualKey), sha(TEST_KEY + 'TEST-drift'));
    await assert.rejects(f.read(f.link.id), { code: 'TOPOLOGY_LEGACY_IMPORT_MISMATCH' });
    assert.equal(f.events.length, 0); assert.equal(await f.models.TopologyOperation.countDocuments(), 0);
    assert.equal(await f.models.TopologyExecutionBinding.countDocuments(), 0);
    evidence('manual-tls-negative', { variant, case: 'partial import then private persisted snapshot drift',
        codes: ['TOPOLOGY_CONFIG_OWNER_REQUIRED', 'TOPOLOGY_LEGACY_IMPORT_MISMATCH'], dispatches: 0 });
}));
