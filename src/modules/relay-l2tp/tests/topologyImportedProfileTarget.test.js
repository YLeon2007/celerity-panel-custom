'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash } = require('node:crypto');
const mongoose = require('mongoose');
const { serialize, deserialize } = require('bson');
const contract = require('../models/topologyExecutionBindingContract');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const P = '111111111111111111111111', B = '222222222222222222222222', L = '333333333333333333333333';
const EPOCH = '11111111-1111-4111-8111-111111111111';
const RUNNER = '22222222-2222-4222-8222-222222222222';
const sha = value => createHash('sha256').update(value).digest('hex');
const helper = () => require('../services/topologyProfileTarget');
const pin = (nodeId = B, role = 'bridge') => ({ version: 1, layout: 'legacy-forward-main', nodeId, role,
    targetProfile: 'xray-main', ownerGeneration: EPOCH, descriptorSha256: 'a'.repeat(64), ownerEvidenceSha256: 'b'.repeat(64) });
const expected = () => ({ executionContext: TEST.hostIdentity, operationId: L, nodeId: B,
    candidateHash: `sha256:${'c'.repeat(64)}`, backupId: 'backup', targetProfile: 'xray-bridge',
    topologyRevision: 2, priorDeployedRevision: 1, owner: 'worker', attempt: 1, generation: RUNNER });
function topology() {
    return { nodes: [{ id: P, role: 'portal', type: 'xray', active: true, ip: '192.0.2.1',
        xray: { security: 'none', transport: 'tcp' }, profileConfig: '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n' },
    { id: B, role: 'bridge', type: 'xray', active: true, ip: '192.0.2.2',
        xray: { security: 'none', transport: 'tcp' }, profileConfig: '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n' }],
    links: [{ id: L, source: P, target: B, mode: 'forward', active: true, tunnelUuid: EPOCH,
        tunnelPort: 2443, tunnelSecurity: 'none', tunnelTransport: 'tcp', tunnelProtocol: 'vless' }], groups: [] };
}
function owner() {
    const descriptor = topology();
    return { executionContext: { ...TEST }, node: B, profile: 'xray-main', owner: 'topology', generation: EPOCH,
        nodeIdentity: { machineId: 'a'.repeat(32), sshHostKeySha256: 'b'.repeat(64) },
        originalSnapshot: { configSha256: sha(descriptor.nodes[1].profileConfig), unitSha256: 'c'.repeat(64),
            serviceActive: 'active', serviceEnabled: 'enabled' },
        adoptionReceipt: { proofId: RUNNER, maintenanceId: RUNNER, fromGeneration: RUNNER, toGeneration: EPOCH,
            oldBackendInstanceId: 'old-instance', oldPid: 42, oldProcessStartTime: '123', verifiedAt: '2026-11-04T00:00:00.000Z' },
        legacyAppliedTopology: descriptor };
}
function selected() {
    const pins = [pin(P, 'portal'), pin()];
    return { admissionScope: 'selected', kind: 'link.apply', executionContext: { ...TEST },
        resourceNodeIds: [P, B], baselineTopology: topology(), effectiveTopology: topology(), linkId: L, linkIds: [L],
        nodes: pins.map(p => ({ node: p.nodeId, role: p.role, targetProfile: p.targetProfile, profileTargetPin: p })),
        selectedOwnerPins: pins.map(p => ({ node: p.nodeId, profile: p.targetProfile, owner: 'topology',
            generation: p.ownerGeneration, executionContext: { ...TEST }, profileTargetPin: { ...p } })) };
}
// Qualification positives use the real classic generators/fixed verifier,
// not the intentionally shape-only digest fixtures above.
function qualifiedOwner() {
    const root = owner(), descriptor = root.legacyAppliedTopology;
    const generator = require('../../../services/configGenerator');
    const link = { ...descriptor.links[0], _id: L, portalNode: descriptor.nodes[0], bridgeNode: descriptor.nodes[1] };
    for (const node of descriptor.nodes) {
        node.port = 24443;
        const config = JSON.parse(generator.generateXrayConfig({ ...node, _id: node.id }, []));
        if (node.role === 'portal') generator.applyForwardChain(config, [link], ['vless-in']);
        else generator.applyForwardHopInbound(config, [link]);
        node.profileConfig = JSON.stringify(config) + '\n';
    }
    root.originalSnapshot.configSha256 = sha(descriptor.nodes[1].profileConfig);
    return root;
}
const invalid = fn => assert.throws(fn, { code: 'TOPOLOGY_PROFILE_TARGET_INVALID' });
const stale = fn => assert.throws(fn, { code: 'TOPOLOGY_PROFILE_TARGET_STALE' });

test('additive exact keys preserve native V1 arrays and add only a valid present pin', () => {
    const native = expected();
    assert.equal(contract.expectedKeysFor(native), contract.EXPECTED_KEYS);
    assert.equal(contract.recordKeysFor(native), contract.RECORD_KEYS);
    const imported = { ...native, targetProfile: 'xray-main', profileTargetPin: pin() };
    assert.deepEqual(contract.expectedKeysFor(imported), [...contract.EXPECTED_KEYS, 'profileTargetPin']);
    assert.deepEqual(contract.recordKeysFor(imported), [...contract.RECORD_KEYS, 'profileTargetPin']);
    assert.equal(imported.generation, RUNNER, 'runner generation is not the owner epoch');
    for (const value of [null, undefined, [], {}, { ...pin(), version: 2 }, { ...pin(), nodeId: P }]) {
        invalid(() => contract.expectedKeysFor({ ...imported, profileTargetPin: value }));
        invalid(() => contract.recordKeysFor({ ...imported, profileTargetPin: value }));
    }
    assert.equal(contract.exact({ ...native, extra: true }, contract.expectedKeysFor(native)), false);
});

test('native expected/record projection keeps old serialized keys and values byte-for-byte', () => {
    const native = expected();
    assert.equal(JSON.stringify(Object.fromEntries(contract.expectedKeysFor(native).map(k => [k, native[k]]))), JSON.stringify(native));
    assert.equal(Object.hasOwn(native, 'profileTargetPin'), false);
    const row = { ...native, attemptId: RUNNER, predecessorGeneration: 'none', commandIds: { prepare: RUNNER }, bootId: RUNNER, maintenanceId: RUNNER };
    assert.equal(JSON.stringify(Object.fromEntries(contract.recordKeysFor(row).map(k => [k, row[k]]))), JSON.stringify(row));
    assert.deepEqual(contract.EXPECTED_KEYS, ['executionContext', 'operationId', 'nodeId', 'candidateHash', 'backupId',
        'targetProfile', 'topologyRevision', 'priorDeployedRevision', 'owner', 'attempt', 'generation']);
});

test('unchanged native fingerprint input has a pinned old hash and no added pin keys', () => {
    const content = '{"inbounds":[],"outbounds":[{"tag":"direct"}],"routing":{"rules":[]}}\n';
    const hash = sha(content);
    const operation = { _id: L, executionContext: { ...TEST },
        idempotencyKey: `topology:test:revision-2:host-test.infograd.online:${EPOCH}`,
        topologyRevision: 2, priorDeployedRevision: 1, kind: 'link.apply', staged: false,
        nodes: [{ node: B, nodeRef: 'bridge', role: 'bridge', targetProfile: 'xray-bridge', checks: [],
            candidateHash: hash, candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1',
                bytes: [...Buffer.from(content)], sha256: hash } }] };
    const before = JSON.stringify(operation);
    helper().assertSelectedProfileTargets(operation);
    const { selectedAdmissionFingerprint } = require('../repositories/topologyOperationRepository');
    // Captured from unchanged repository at 1ac013e; not computed by a new
    // pin-aware fingerprint algorithm (that consumer belongs to A1).
    assert.equal(selectedAdmissionFingerprint(operation), '7919e5d343d2fcd9e39675ed86ec6a182ca52b5f1f78d932bc5ef9c8ae1adf78');
    assert.equal(JSON.stringify(operation), before);
    assert.equal(Object.hasOwn(operation.nodes[0], 'profileTargetPin'), false);
});

test('resolver retains strict native placement/default and fixed paths', () => {
    for (const role of ['portal', 'bridge', 'relay']) {
        const profile = role === 'portal' ? 'xray-main' : 'xray-bridge';
        const resolved = helper().resolveTopologyProfileTarget({ nodeId: B, role });
        assert.equal(resolved.targetProfile, profile);
        assert.equal(resolved.serviceUnit, role === 'portal' ? 'xray.service' : 'xray-bridge.service');
        invalid(() => helper().resolveTopologyProfileTarget({ nodeId: B, role, targetProfile: profile === 'xray-main' ? 'xray-bridge' : 'xray-main' }));
    }
    invalid(() => helper().resolveTopologyProfileTarget({ nodeId: B, role: 'unknown' }));
    invalid(() => helper().resolveTopologyProfileTarget({ nodeId: B.toUpperCase() + 'A', role: 'portal' }));
});

test('resolver permits only pin-matched real role MAIN as pure shape, never authority', () => {
    const resolved = helper().resolveTopologyProfileTarget({ nodeId: B, role: 'bridge', targetProfile: 'xray-main', profileTargetPin: pin() });
    assert.deepEqual(resolved, { targetProfile: 'xray-main', configPath: '/usr/local/etc/xray/config.json',
        serviceUnit: 'xray.service', serviceUnitPath: '/etc/systemd/system/xray.service' });
    for (const change of [{ nodeId: P }, { role: 'portal' }, { targetProfile: 'xray-bridge' }, { targetProfile: undefined }]) {
        invalid(() => helper().resolveTopologyProfileTarget({ nodeId: B, role: 'bridge', targetProfile: 'xray-main', profileTargetPin: pin(), ...change }));
    }
    invalid(() => helper().resolveTopologyProfileTarget({ nodeId: B, role: 'bridge', profileTargetPin: pin() }));
});

test('malformed-present pin never becomes a native fallback', () => {
    const base = { nodeId: P, role: 'portal', targetProfile: 'xray-main' };
    for (const value of [null, undefined, [], {}, { ...pin(P, 'portal'), version: '1' },
        { ...pin(P, 'portal'), layout: 'other' }, { ...pin(P, 'portal'), extra: undefined },
        { ...pin(P, 'portal'), descriptorSha256: 'A'.repeat(64) }, { ...pin(P, 'portal'), ownerGeneration: 'NOT-A-UUID' }]) {
        invalid(() => helper().resolveTopologyProfileTarget({ ...base, profileTargetPin: value }));
    }
});

test('pin shape copy and deterministic digest projection are frozen without mutating input', () => {
    const input = pin(), copy = helper().assertProfileTargetPin(input);
    assert.notStrictEqual(copy, input); assert.deepEqual(copy, input);
    assert.equal(Object.isFrozen(copy), true); assert.equal(Object.isFrozen(input), false);
    input.ownerGeneration = RUNNER; assert.equal(copy.ownerGeneration, EPOCH);
    assert.throws(() => { copy.role = 'portal'; }, TypeError);
    assert.equal(Object.isFrozen(helper().importedProfileTargetDigests(owner())), true);
});

test('canonical digest mechanics preserve array order and exact profile strings', () => {
    const { canonicalProfileTargetJSON, importedProfileTargetDigests } = helper();
    assert.equal(canonicalProfileTargetJSON({ z: [2, { b: 1, a: 2 }], a: 'x\n' }), '{"a":"x\\n","z":[2,{"a":2,"b":1}]}');
    const root = owner(), original = importedProfileTargetDigests(root);
    const reordered = { ...root, legacyAppliedTopology: { groups: [], links: root.legacyAppliedTopology.links, nodes: root.legacyAppliedTopology.nodes } };
    assert.deepEqual(importedProfileTargetDigests(reordered), original);
    const order = structuredClone(root); order.legacyAppliedTopology.nodes.reverse();
    assert.notEqual(importedProfileTargetDigests(order).descriptorSha256, original.descriptorSha256);
    const bytes = structuredClone(root); bytes.legacyAppliedTopology.nodes[0].profileConfig += ' ';
    assert.notEqual(importedProfileTargetDigests(bytes).descriptorSha256, original.descriptorSha256);
    assert.equal(original.descriptorSha256, sha(canonicalProfileTargetJSON(root.legacyAppliedTopology)));
    const { executionContext, node, profile, generation, nodeIdentity, originalSnapshot, adoptionReceipt } = root;
    assert.equal(original.ownerEvidenceSha256, sha(canonicalProfileTargetJSON({ executionContext, node, profile,
        owner: 'topology', generation, nodeIdentity, originalSnapshot, adoptionReceipt, descriptorSha256: original.descriptorSha256 })));
});

test('plain JSON and real BSON/Mongoose serialization yield identical digest mechanics', () => {
    const root = owner(), bson = { ...root, node: new mongoose.Types.ObjectId(B),
        adoptionReceipt: { ...root.adoptionReceipt, verifiedAt: new Date(root.adoptionReceipt.verifiedAt) } };
    assert.deepEqual(helper().importedProfileTargetDigests(deserialize(serialize(bson))), helper().importedProfileTargetDigests(root));
    const Owner = require('../../../models/topologyConfigOwnerModel');
    const doc = new Owner(bson);
    assert.equal(doc.validateSync(), undefined);
    assert.deepEqual(helper().importedProfileTargetDigests(doc.toObject()), helper().importedProfileTargetDigests(root));
    assert.deepEqual(helper().importedProfileTargetDigests(doc), helper().importedProfileTargetDigests(root));
});

test('settlement metadata is excluded but descriptor/root/owner epoch is digest-bound', () => {
    const root = owner(), original = helper().importedProfileTargetDigests(root);
    const settled = { ...root, _id: new mongoose.Types.ObjectId(), createdAt: new Date(), updatedAt: new Date(),
        executionBindingCheck: 'changed', lastSettledOperation: L, lastSettledGeneration: RUNNER,
        lastSettledRevision: 9, lastSettledCloseId: RUNNER, profileTargetPin: pin() };
    assert.deepEqual(helper().importedProfileTargetDigests(settled), original);
    for (const change of [r => { r.nodeIdentity.machineId = 'd'.repeat(32); },
        r => { r.originalSnapshot.unitSha256 = 'd'.repeat(64); },
        r => { r.adoptionReceipt.oldPid++; }, r => { r.generation = '33333333-3333-4333-8333-333333333333'; r.adoptionReceipt.toGeneration = r.generation; }]) {
        const changed = structuredClone(root); change(changed);
        assert.notEqual(helper().importedProfileTargetDigests(changed).ownerEvidenceSha256, original.ownerEvidenceSha256);
    }
});

test('serialization rejects type repair, unknown JSON values and noncanonical dates', () => {
    for (const value of [{ a: undefined }, { a: NaN }, { a: new Date() }, { a: new mongoose.Types.ObjectId() }, new Array(1)]) {
        invalid(() => helper().canonicalProfileTargetJSON(value));
    }
    for (const change of [r => { r.node = { toHexString: () => B }; }, r => { r.node = 'ABCDEF'.repeat(4); },
        r => { r.adoptionReceipt.verifiedAt = '2026-11-04'; }, r => { r.adoptionReceipt.verifiedAt = new Date('bad'); },
        r => { r.generation = EPOCH.toUpperCase().replace('1111', 'ABCD'); }]) {
        const root = owner(); change(root); invalid(() => helper().importedProfileTargetDigests(root));
    }
});

test('full owner projector qualifies classic forward bytes and still refuses unqualified roots', () => {
    const root = qualifiedOwner();
    assert.deepEqual(helper().projectImportedProfileTargetPin(root), { ...pin(), ...helper().importedProfileTargetDigests(root) });
    assert.throws(() => helper().projectImportedProfileTargetPin(owner()), { code: 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH' });
    for (const change of [r => { r.owner = 'classic'; }, r => { r.handbackReceipt = null; },
        r => { r.adoptionReceipt.toGeneration = RUNNER; }, r => { r.node = P; },
        r => { r.profile = 'xray-bridge'; }, r => { r.legacyAppliedTopology.links[0].tunnelProtocol = ''; },
        r => { r.legacyAppliedTopology.links[0].tunnelTransport = 'ws'; },
        r => { r.legacyAppliedTopology.groups.push({}); }, r => { r.executionContext.extra = true; },
        r => { r.originalSnapshot.configSha256 = 'd'.repeat(64); }]) {
        const changed = structuredClone(root); change(changed);
        assert.throws(() => helper().projectImportedProfileTargetPin(changed));
    }
});

test('unsupported public forward layouts stay closed before authority or model access', async () => {
    const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
    let accessed = 0;
    const transfer = new TopologyConfigTransfer({ executionContext: TEST,
        withVerifiedMaintenance: async () => { accessed++; throw new Error('must not dispatch'); },
        TopologyConfigOwner: new Proxy({}, { get() { accessed++; throw new Error('must not access DB'); } }) });
    for (const change of [t => { t.links[0].tunnelSecurity = 'tls'; }, t => { t.groups.push({ _id: L, paths: [] }); },
        t => { t.links.push({ ...t.links[0], id: P, mode: 'reverse' }); }]) {
        const descriptor = topology(); change(descriptor);
        await assert.rejects(transfer.adopt({ node: B, profile: 'xray-main', generation: RUNNER,
            proofRef: 'modeled-contract-only', legacyTopology: descriptor }), { code: 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED' });
    }
    assert.equal(accessed, 0);
});

test('full pin verification requires saved pin and independent exact context; no caller verifier seam', () => {
    const root = qualifiedOwner();
    stale(() => helper().verifyImportedProfileTargetPin({ owner: root, profileTargetPin: pin(), executionContext: TEST }));
    invalid(() => helper().verifyImportedProfileTargetPin({ owner: root, profileTargetPin: null, executionContext: TEST }));
    root.profileTargetPin = { ...pin(), ...helper().importedProfileTargetDigests(root) };
    const target = root.profileTargetPin;
    stale(() => helper().verifyImportedProfileTargetPin({ owner: root, profileTargetPin: target, executionContext: { ...TEST, extra: true } }));
    stale(() => helper().verifyImportedProfileTargetPin({ owner: root, profileTargetPin: { ...target, descriptorSha256: 'd'.repeat(64) }, executionContext: TEST }));
    assert.deepEqual(helper().verifyImportedProfileTargetPin({ owner: root, profileTargetPin: target, executionContext: TEST }), target);
});

test('changed independent root is stale before exact forward artifact qualification', () => {
    const root = qualifiedOwner(), target = { ...pin(), ...helper().importedProfileTargetDigests(root) };
    root.profileTargetPin = target;
    for (const change of [r => { r.originalSnapshot.unitSha256 = 'd'.repeat(64); },
        r => { r.nodeIdentity.machineId = 'd'.repeat(32); }, r => { r.adoptionReceipt.oldPid++; },
        r => { r.generation = '33333333-3333-4333-8333-333333333333'; r.adoptionReceipt.toGeneration = r.generation; },
        r => { r.legacyAppliedTopology.nodes[0].profileConfig += ' '; }, r => { r.handbackReceipt = {}; }]) {
        const changed = structuredClone(root); change(changed);
        stale(() => helper().verifyImportedProfileTargetPin({ owner: changed, profileTargetPin: target, executionContext: TEST }));
    }
    assert.deepEqual(helper().verifyImportedProfileTargetPin({ owner: root, profileTargetPin: target, executionContext: TEST }), target);
});

test('selected pure contract allows bounded apply/delete/recreate and does not constrain native graphs', () => {
    helper().assertSelectedProfileTargets(selected());
    const deletion = selected(); deletion.kind = 'link.delete'; deletion.effectiveTopology = { nodes: [], links: [], groups: [] }; deletion.linkIds = [];
    helper().assertSelectedProfileTargets(deletion);
    const recreate = selected(); recreate.baselineTopology = { nodes: [], links: [], groups: [] };
    helper().assertSelectedProfileTargets(recreate);
    const native = { nodes: [{ node: B, role: 'bridge', targetProfile: 'xray-bridge' }], selectedOwnerPins: [] };
    const before = JSON.stringify(native); helper().assertSelectedProfileTargets(native); assert.equal(JSON.stringify(native), before);
});

test('selected pure contract rejects partial/mismatched pin carriers and broader imported graphs', () => {
    for (const change of [r => { delete r.nodes[1].profileTargetPin; }, r => { r.nodes.push({ ...r.nodes[0] }); },
        r => { r.selectedOwnerPins[1].profileTargetPin = undefined; }, r => { r.selectedOwnerPins[1].generation = RUNNER; },
        r => { r.selectedOwnerPins[1].profile = 'xray-bridge'; }, r => { r.selectedOwnerPins[1].node = P; },
        r => { r.selectedOwnerPins[1].profileTargetPin.ownerEvidenceSha256 = 'd'.repeat(64); },
        r => { r.nodes[1].profileTargetPin.descriptorSha256 = 'd'.repeat(64); r.selectedOwnerPins[1].profileTargetPin.descriptorSha256 = 'd'.repeat(64); },
        r => { r.admissionScope = 'full'; }, r => { r.kind = 'domain.reconcile'; }, r => { r.installedPath = {}; },
        r => { r.resourceNodeIds.push(L); }, r => { r.resourceNodeIds[1] = P; },
        r => { r.effectiveTopology.links[0].mode = 'reverse'; }, r => { r.effectiveTopology.groups.push({}); },
        r => { r.effectiveTopology.nodes[1].role = 'relay'; }, r => { r.effectiveTopology.links[0].tunnelSecurity = 'tls'; },
        r => { r.linkIds = []; }, r => { r.effectiveTopology.nodes = []; }]) {
        const operation = selected(); change(operation); invalid(() => helper().assertSelectedProfileTargets(operation));
    }
});

function enrollmentInput() {
    return { _id: RUNNER, executionContext: TEST.hostIdentity, nodeId: B, targetProfile: 'xray-main',
        endpoint: { ip: '192.0.2.2', port: 22, username: 'root' },
        nodeIdentity: { machineId: 'a'.repeat(32), sshHostKeySha256: 'b'.repeat(64) },
        ownerGeneration: EPOCH, predecessorGeneration: 'none', bootId: RUNNER, proofId: RUNNER, maintenanceId: RUNNER };
}
test('strict pin schema factory rejects missing/extra/coerced fields without defaults', () => {
    const { createProfileTargetPinSchema } = require('../models/topologyProfileTargetPinSchema');
    const schema = createProfileTargetPinSchema();
    assert.equal(schema.options.strict, 'throw'); assert.equal(schema.options._id, false);
    const Model = mongoose.model('A0PinContract', schema);
    assert.equal(new Model(pin()).validateSync(), undefined);
    for (const change of [p => { p.extra = true; }, p => { delete p.role; }, p => { p.version = '1'; },
        p => { p.nodeId = new mongoose.Types.ObjectId(B); }, p => { p.ownerGeneration = 1; }, p => { p.version = 2; }]) {
        const value = pin(); change(value); let error;
        try { error = new Model(value).validateSync(); } catch (e) { error = e; }
        assert.ok(error, JSON.stringify(value));
    }
});

test('common schemas inherit an optional immutable exact pin; old rows remain absent', () => {
    const Enrollment = require('../models/topologyExecutionEnrollmentModel');
    const Binding = require('../models/topologyExecutionBindingModel');
    for (const Model of [Enrollment, Binding]) {
        const path = Model.schema.path('profileTargetPin');
        assert.ok(path); assert.equal(path.options.immutable, true); assert.equal(path.options.default, undefined);
    }
    const old = new Enrollment(enrollmentInput()); assert.equal(old.validateSync(), undefined);
    assert.equal(Object.hasOwn(old.toObject(), 'profileTargetPin'), false);
    const imported = new Enrollment({ ...enrollmentInput(), profileTargetPin: pin() });
    assert.equal(imported.validateSync(), undefined);
    assert.deepEqual(imported.toObject().profileTargetPin, pin());
    for (const value of [undefined, null, [], {}, { ...pin(), version: '1' }, { ...pin(), extra: undefined },
        { ...pin(), nodeId: P }, { ...pin(), ownerGeneration: RUNNER }]) {
        const doc = new Enrollment({ ...enrollmentInput(), profileTargetPin: value });
        assert.ok(doc.validateSync(), `must refuse ${JSON.stringify(value)}`);
    }
    const row = { ...enrollmentInput(), ...expected(), targetProfile: 'xray-main', profileTargetPin: pin(),
        enrollmentId: RUNNER, attemptId: RUNNER, commandIds: Object.fromEntries(contract.COMMANDS.map(k => [k, RUNNER])),
        commandTokens: contract.COMMANDS.map((_, i) => `00000000-0000-4000-8000-00000000000${i}`) };
    assert.equal(new Binding(row).validateSync(), undefined, 'owner epoch differs from binding/runner generation');
});
