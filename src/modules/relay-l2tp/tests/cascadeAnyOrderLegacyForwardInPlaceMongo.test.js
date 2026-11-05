'use strict';
// Run native now with --test-name-pattern='native positive'. Forward-positive
// bodies are intentionally real assertions, not skips/expected-refusal greens:
// execute them only after B1 integration. No alternate verifier/seed path.
const test = require('node:test');
const assert = require('node:assert/strict');
const { nativeFixture, mongoFixture, context, sha, evidence } = require('./cascadeAnyOrderLegacyForwardNativeFixture');
const { TopologyDraftWriteService } = require('../services/topologyDraftWriteService');
const { TopologyDraftRepository } = require('../repositories/topologyDraftRepository');
const mongo = mongoFixture();
test.before(() => mongo.start());
test.after(() => mongo.stop());
async function assertSettled(f, op, { forward = false } = {}) {
    assert.equal(op.status, 'succeeded'); assert.equal(op.heldTopologyAdmission, false);
    assert.equal(op.admissionScope, 'selected'); assert.equal(op.nodes.length, 2);
    assert.equal(new Set(op.nodes.map(node => String(node.node))).size, 2);
    assert.equal(await f.models.NodeOperationLock.countDocuments(), 0);
    assert.equal((await f.models.CascadeTopologyState.findById('singleton').lean()).topologyAdmissionCount, 0);
    assert.equal(op.v2Terminal.state, 'proven'); assert.equal(op.v2Terminal.bindings.length, 2);
    assert.equal(op.v2Terminal.proofs.length, 2);
    const owners = await f.models.TopologyConfigOwner.find({}).select('+legacyAppliedTopology +profileTargetPin').lean();
    const enrollments = await f.models.TopologyExecutionEnrollment.find({}).lean();
    const bindings = await f.models.TopologyExecutionBinding.find({ operationId: String(op._id) }).lean();
    assert.equal(owners.length, 2); assert.equal(enrollments.length, 2); assert.equal(bindings.length, 2);
    for (const node of op.nodes) {
        const id = String(node.node), host = f.hosts.get(id), actual = f.readProfile(host, host.profile);
        const owner = owners.find(row => String(row.node) === id);
        const enrollment = enrollments.find(row => row.nodeId === id);
        const binding = bindings.find(row => row.nodeId === id);
        const terminal = op.v2Terminal.bindings.find(row => row.nodeId === id);
        const proof = op.v2Terminal.proofs.find(row => row.nodeId === id);
        assert.equal(node.role, host.node.role); assert.equal(node.targetProfile, host.profile);
        assert.equal(owner.owner, 'topology'); assert.equal(owner.generation, enrollment.ownerGeneration);
        assert.equal(owner.lastSettledOperation, String(op._id)); assert.equal(owner.lastSettledGeneration, binding.generation);
        assert.equal(owner.lastSettledCloseId, binding.commandIds.close);
        assert.equal(proof.command, 'status'); assert.equal(proof.terminal, true); assert.equal(proof.terminalOutcome, 'verified');
        assert.equal(proof.commandId, binding.commandIds.close); assert.equal(proof.generation, binding.generation);
        assert.notEqual(binding.proofId, owner.adoptionReceipt.proofId);
        assert.equal(node.state, 'committed'); assert.equal(actual.config, Buffer.from(node.candidate.bytes).toString());
        assert.equal(sha(actual.config), node.candidateHash);
        assert.deepEqual(owner.legacyAppliedTopology, f.topology, 'original import remains historical, not rewritten to current bytes');
        const original = JSON.parse(host.original[host.profile].config), current = JSON.parse(actual.config);
        for (const tag of ['client-in', 'unrelated-ingress']) {
            const kept = original.inbounds.find(row => row.tag === tag);
            if (kept) assert.deepEqual(current.inbounds.find(row => row.tag === tag), kept);
        }
        assert.deepEqual(current.policy, original.policy);
        assert.deepEqual(current.outbounds.find(row => row.tag === 'unrelated-out'), original.outbounds.find(row => row.tag === 'unrelated-out'));
        assert.deepEqual(current.routing.rules.filter(row => row.outboundTag === 'unrelated-out'), original.routing.rules.filter(row => row.outboundTag === 'unrelated-out'));
        if (forward) {
            assert.equal(host.profile, 'xray-main');
            const pin = owner.profileTargetPin; assert.ok(pin); assert.equal(pin.role, host.node.role);
            assert.equal(pin.ownerGeneration, owner.generation);
            for (const carrier of [node, enrollment, binding, terminal,
                op.selectedOwnerPins.find(row => row.node === id)]) assert.deepEqual(carrier.profileTargetPin, pin);
        } else for (const carrier of [owner, node, enrollment, binding, terminal]) assert.equal(Object.hasOwn(carrier, 'profileTargetPin'), false);
    }
    f.assertUntouched();
    evidence('settled', { operationId: String(op._id), mode: f.link.mode, security: f.link.tunnelSecurity,
        nodes: op.nodes.map(node => ({ node: String(node.node), role: node.role, targetProfile: node.targetProfile, hash: node.candidateHash })),
        terminalProofs: op.v2Terminal.proofs.map(proof => ({ command: proof.command, generation: proof.generation, commandId: proof.commandId })),
        boundary: 'real Mongo/worker/executor/runner; modeled physical exclusion, SSH, Xray, listeners and systemd' });
}
function assertForwardTunnel(f, op, link) {
    for (const node of op.nodes) {
        const candidate = JSON.parse(Buffer.from(node.candidate.bytes));
        if (node.role === 'bridge') {
            assert.ok(node.checks.some(check => check.type === 'port' && check.port === link.tunnelPort && check.expectedState === 'listening'));
            assert.equal(node.checks.some(check => check.type === 'port' && check.port === link.tunnelPort && check.expectedState === 'absent'), false);
            const listeners = candidate.inbounds.filter(row => row.port === link.tunnelPort);
            assert.equal(listeners.length, 1); const listener = listeners[0];
            assert.equal(listener.settings.clients[0].id, link.tunnelUuid);
            assert.equal(listener.streamSettings.security, link.tunnelSecurity);
            if (link.tunnelSecurity === 'reality') assert.equal(listener.streamSettings.realitySettings.privateKey, link.realityPrivateKey);
        } else {
            const dialers = candidate.outbounds.filter(row => row.protocol === 'vless'
                && row.settings?.vnext?.some(peer => peer.port === link.tunnelPort));
            assert.equal(dialers.length, 1);
            assert.equal(dialers[0].settings.vnext[0].users[0].id, link.tunnelUuid);
            if (link.tunnelSecurity === 'reality') assert.equal(dialers[0].streamSettings.realitySettings.publicKey, link.realityPublicKey);
        }
        assert.equal(f.readProfile(f.hosts.get(String(node.node)), 'xray-main').config, Buffer.from(node.candidate.bytes).toString());
    }
}
async function assertFreshRead(f, linkId, expectedIds) {
    const selected = await f.read(linkId);
    assert.deepEqual(selected.baselineTopology.links.map(link => link.id).sort(), expectedIds);
    for (const node of selected.baselineTopology.nodes) assert.equal(node.profileConfig,
        f.readProfile(f.hosts.get(node.id), f.profileFor(node)).config, 'new repository reads settled current candidate, never historical original');
    return selected;
}
async function assertReplay(f, op, linkId) {
    const before = f.events.length;
    assert.equal((await f.worker.run(String(op._id))).status, 'succeeded');
    assert.equal(String((await f.apply(linkId))._id), String(op._id));
    assert.equal(f.events.length, before, 'settled replay neither dispatches nor creates a binding');
    assert.equal(await f.models.TopologyExecutionBinding.countDocuments({ operationId: String(op._id) }), 2);
}
test('native positive: public reverse import -> preEnroll -> selected coordinator -> durable worker -> real runner close/status -> V2 settlement -> fresh read', { timeout: 180000 }, async t => {
    const f = await nativeFixture(t, mongo);
    assert.equal(await f.models.TopologyConfigOwner.countDocuments(), 0);
    assert.equal(await f.models.TopologyExecutionEnrollment.countDocuments(), 0);
    assert.equal(await f.models.TopologyExecutionBinding.countDocuments(), 0);
    assert.equal(await f.models.TopologyOperation.countDocuments(), 0);
    await f.adopt(); await f.enroll();
    const selected = await f.read(f.link.id);
    assert.deepEqual(selected.baselineTopology, f.topology);
    const op = await f.apply(); await assertSettled(f, op);
    assert.deepEqual(op.nodes.map(node => node.targetProfile).sort(), ['xray-bridge', 'xray-main']);
    for (const host of f.hosts.values()) assert.deepEqual(f.events.filter(row => row.node === host.node.id).map(row => row.command),
        ['prepare', 'commit', 'verify', 'close', 'status']);
    await assertFreshRead(f, f.link.id, [f.link.id]); await assertReplay(f, op, f.link.id);
});
test('native positive serial: same harness performs byte-no-op and public delete-empty/recreate with actual successor bindings', { timeout: 240000 }, async t => {
    const f = await nativeFixture(t, mongo);
    await f.adopt(); await f.enroll();
    const first = await f.apply(); await assertSettled(f, first);
    const beforeRestarts = [...f.hosts.values()].map(host => f.readProfile(host, host.profile).restarts);
    const writes = new TopologyDraftWriteService({ repository: new TopologyDraftRepository(f.models) });
    await writes.updateLink({ expectedTopologyRevision: await f.revision(), linkId: f.link.id, changes: { name: 'native byte-no-op' } });
    const again = await f.apply(); await assertSettled(f, again);
    assert.notEqual(String(again._id), String(first._id));
    assert.deepEqual(again.nodes.map(node => node.candidateHash), first.nodes.map(node => node.candidateHash));
    assert.deepEqual([...f.hosts.values()].map(host => f.readProfile(host, host.profile).restarts), beforeRestarts);
    const deleted = await f.remove(); await assertSettled(f, deleted);
    assert.deepEqual(deleted.effectiveTopology.links, []);
    assert.equal(await f.models.CascadeLink.findById(f.link.id).lean(), null);
    const { op: recreated, link } = await f.recreate();
    assert.notEqual(String(link._id), f.link.id); await assertSettled(f, recreated);
    await assertFreshRead(f, String(link._id), [String(link._id)]);
    assert.equal(await f.models.TopologyExecutionEnrollment.countDocuments(), 2);
    assert.equal(await f.models.TopologyExecutionBinding.countDocuments(), 8);
});
for (const security of ['none', 'reality']) test(`forward positive pending B1: ${security} public import -> apply/replay/no-op -> delete empty -> recreate new ID, same MAIN owner pin`, { timeout: 240000 }, async t => {
    const f = await nativeFixture(t, mongo, { mode: 'forward', security });
    await f.adopt(); await f.enroll();
    const first = await f.apply(); await assertSettled(f, first, { forward: true });
    const originals = await f.models.TopologyConfigOwner.find({}).select('+profileTargetPin +legacyAppliedTopology').lean();
    const pinSnapshot = originals.map(owner => ({ node: String(owner.node), generation: owner.generation, pin: owner.profileTargetPin }));
    const unchangedLink = await f.models.CascadeLink.findById(f.link.id).select('+realityPrivateKey').lean();
    assert.equal(unchangedLink.tunnelUuid, f.link.tunnelUuid); assert.equal(unchangedLink.tunnelPort, f.link.tunnelPort);
    assertForwardTunnel(f, first, f.link);
    await assertReplay(f, first, f.link.id); await assertFreshRead(f, f.link.id, [f.link.id]);
    const beforeRestarts = [...f.hosts.values()].map(host => f.readProfile(host, host.profile).restarts);
    // Ordinary public draft mutation advances revision, forcing a new durable
    // byte-no-op deployment rather than satisfying only cached idempotency.
    const writes = new TopologyDraftWriteService({ repository: new TopologyDraftRepository(f.models) });
    await writes.updateLink({ expectedTopologyRevision: await f.revision(), linkId: f.link.id, changes: { name: 'same bytes, new revision' } });
    const again = await f.apply(); assert.notEqual(String(again._id), String(first._id));
    await assertSettled(f, again, { forward: true }); assertForwardTunnel(f, again, f.link);
    assert.deepEqual(again.nodes.map(node => node.candidateHash), first.nodes.map(node => node.candidateHash));
    assert.deepEqual([...f.hosts.values()].map(host => f.readProfile(host, host.profile).restarts), beforeRestarts);
    const removed = await f.remove(); await assertSettled(f, removed, { forward: true });
    assert.deepEqual(removed.effectiveTopology.links, []); assert.equal(await f.models.CascadeLink.findById(f.link.id).lean(), null);
    for (const host of f.hosts.values()) {
        const current = JSON.parse(f.readProfile(host, 'xray-main').config);
        assert.equal(current.inbounds.some(row => row.port === f.link.tunnelPort), false);
        assert.equal(current.outbounds.some(row => row.settings?.vnext?.some(peer => peer.port === f.link.tunnelPort)), false);
    }
    const { op: recreated, link } = await f.recreate();
    assert.notEqual(String(link._id), f.link.id); await assertSettled(f, recreated, { forward: true });
    assertForwardTunnel(f, recreated, link);
    assert.deepEqual(recreated.baselineTopology.links, []);
    await assertFreshRead(f, String(link._id), [String(link._id)]);
    const currentOwners = await f.models.TopologyConfigOwner.find({}).select('+profileTargetPin').lean();
    assert.deepEqual(currentOwners.map(owner => ({ node: String(owner.node), generation: owner.generation, pin: owner.profileTargetPin })), pinSnapshot);
    assert.equal(await f.models.TopologyExecutionEnrollment.countDocuments(), 2, 'no re-enrollment or profile relabel');
    assert.equal(await f.models.TopologyExecutionBinding.countDocuments(), 8, 'four genuine serial operations, two targets each');
    for (const host of f.hosts.values()) {
        const log = require('node:fs').readFileSync(require('node:path').join(host.root, 'systemctl.log'), 'utf8');
        assert.equal(log.includes('xray-bridge.service'), false, 'no independent SIDECAR service IO');
        assert.equal(log.split('\n').some(line => line.startsWith('stop ')), false, 'shared MAIN never stopped');
    }
});
