'use strict';
// Pure internal composition inputs are MODELED, not public imported authority.
// Reader qualification uses the real verifier; never inject one.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const mongoose = require('mongoose');
const generator = require('../../../services/configGenerator');
const Owner = require('../../../models/topologyConfigOwnerModel');
const { importedProfileTargetDigests } = require('../services/topologyProfileTarget');
const { composeFrozenTopologyDeploymentPlan: compose } = require('../services/frozenTopologyDeploymentPlanComposer');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { TopologyOperationCoordinator, projectTopologyOperationStatus } = require('../services/topologyOperationCoordinator');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { linkDesiredVersion } = require('../services/topologyIntentService');
const { compileTopology } = require('../domain/topologyCompiler');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: context } = require('../domain/topologyExecutionContext');
const copy = value => structuredClone(value);
const id = n => n.toString(16).padStart(24, '0');
const sha = value => createHash('sha256').update(value).digest('hex');
function fixture(security = 'none') {
    const nodes = ['portal', 'bridge'].map((role, i) => ({ id: id(i + 1), role, type: 'xray', active: true,
        ip: `192.0.2.${i + 1}`, port: 24443 + i, xray: { security, transport: 'tcp', inboundTag: 'client-in', extraInbounds: [],
            ...(security === 'reality' ? { realityPrivateKey: 'modeled-client-private', realityDest: 'decoy.invalid:443', realityShortIds: ['1234abcd'] } : {}) } }));
    const link = { id: id(10), source: id(1), target: id(2), mode: 'forward', active: true, priority: 1,
        tunnelUuid: '11111111-1111-4111-8111-111111111111', tunnelPort: 25000, tunnelSecurity: security, tunnelTransport: 'tcp',
        ...(security === 'reality' ? { realityPrivateKey: 'modeled-tunnel-private', realityPublicKey: 'modeled-tunnel-public',
            realityDest: 'decoy.invalid:443', realitySni: ['decoy.invalid'], realityShortIds: ['1234abcd'] } : {}) };
    const populated = { ...link, _id: link.id, portalNode: { ...nodes[0], _id: id(1) }, bridgeNode: { ...nodes[1], _id: id(2) } };
    for (const node of nodes) {
        const config = JSON.parse(generator.generateXrayConfig({ ...node, _id: node.id }, []));
        config.inbounds.find(item => item.tag === 'client-in').settings.clients.push({ id: randomUUID(), email: `kept-${node.role}@invalid` });
        if (node.role === 'portal') generator.applyForwardChain(config, [populated], ['client-in']);
        else generator.applyForwardHopInbound(config, [populated]);
        config.inbounds.push({ tag: 'unrelated-in', port: 27000, protocol: 'socks', settings: { auth: 'noauth' } });
        config.outbounds.push({ tag: 'unrelated-out', protocol: 'blackhole' });
        config.routing.rules.push({ type: 'field', inboundTag: ['unrelated-in'], outboundTag: 'unrelated-out' });
        config.policy = { levels: { 0: { statsUserUplink: true } } };
        node.profileConfig = JSON.stringify(config, null, 2) + '\n';
    }
    const topology = { nodes, links: [link], groups: [] };
    const owners = nodes.map((node, i) => {
        const generation = randomUUID();
        const owner = { node: node.id, profile: 'xray-main', executionContext: copy(context), owner: 'topology', generation,
            nodeIdentity: { machineId: String(i + 1).repeat(32), sshHostKeySha256: String(i + 1).repeat(64) },
            originalSnapshot: { configSha256: sha(node.profileConfig), unitSha256: sha('modeled-unit'), serviceActive: 'active', serviceEnabled: 'enabled' },
            adoptionReceipt: { proofId: randomUUID(), maintenanceId: randomUUID(), fromGeneration: randomUUID(), toGeneration: generation,
                oldBackendInstanceId: 'modeled', oldPid: 42, oldProcessStartTime: 'modeled', verifiedAt: '2026-11-05T00:00:00.000Z' }, legacyAppliedTopology: copy(topology) };
        // Digest mechanics only; does NOT qualify a root or bypass real verifier.
        owner.profileTargetPin = { version: 1, layout: 'legacy-forward-main', nodeId: node.id, role: node.role,
            targetProfile: 'xray-main', ownerGeneration: generation, ...importedProfileTargetDigests(owner) };
        return owner;
    });
    const selectedOwnerPins = owners.map(({ legacyAppliedTopology, ...pin }) => copy(pin));
    const plan = (before = topology, after = topology, pins = selectedOwnerPins) => compose({ snapshot: after,
        baselineTopology: before, compiledTopology: compileTopology(after), selectedOwnerPins: pins, staged: true });
    return { topology, owners, selectedOwnerPins, plan };
}
const configs = plan => new Map(plan.nodes.map(node => [node.node, JSON.parse(Buffer.from(node.candidate.bytes))]));
function assertPreserved(original, plan) {
    const current = configs(plan);
    for (const node of original.nodes) {
        const before = JSON.parse(node.profileConfig), after = current.get(node.id);
        for (const tag of ['client-in', 'unrelated-in']) assert.deepEqual(after.inbounds.find(item => item.tag === tag), before.inbounds.find(item => item.tag === tag));
        assert.deepEqual(after.outbounds.find(item => item.tag === 'unrelated-out'), before.outbounds.find(item => item.tag === 'unrelated-out'));
        assert.deepEqual(after.policy, before.policy);
        assert.deepEqual(after.routing.rules.filter(rule => rule.outboundTag === 'unrelated-out'), before.routing.rules.filter(rule => rule.outboundTag === 'unrelated-out'));
    }
    assert.equal(plan.nodes.length, 2);
    for (const entry of plan.nodes) {
        assert.equal(entry.targetProfile, 'xray-main');
        assert.equal(entry.configPath, '/usr/local/etc/xray/config.json');
        assert.equal(entry.serviceUnit, 'xray.service');
        assert.ok(entry.profileTargetPin);
        assert.ok(entry.checks.some(check => check.type === 'service' && check.expectedState === 'active'));
    }
    assert.equal(plan.nodes.find(node => node.node === id(2)).role, 'bridge');
}
for (const security of ['none', 'reality']) test(`pure ${security}: selected carrier keeps MAIN clients through apply/replay/delete/recreate`, () => {
    const f = fixture(security), historical = copy(f.owners);
    const first = f.plan(); assertPreserved(f.topology, first);
    for (const node of f.topology.nodes) assert.deepEqual(configs(first).get(node.id), JSON.parse(node.profileConfig),
        'first apply retains the exact semantic profile, including original tunnel ID/UUID/REALITY keys');
    assert.deepEqual(first.nodes.find(node => node.node === id(2)).checks.filter(check => check.type === 'port'),
        [{ type: 'port', protocol: 'tcp', port: 25000, expectedState: 'listening' }]);
    const current = copy(f.topology);
    for (const node of current.nodes) node.profileConfig = Buffer.from(first.nodes.find(entry => entry.node === node.id).candidate.bytes).toString();
    const replay = f.plan(current, current); assertPreserved(f.topology, replay);
    assert.deepEqual(replay.nodes.map(node => node.candidate), first.nodes.map(node => node.candidate));
    const empty = { nodes: copy(current.nodes), links: [], groups: [] };
    const deleted = f.plan(current, empty); assertPreserved(f.topology, deleted);
    assert.deepEqual(deleted.nodes.find(node => node.node === id(2)).checks.filter(check => check.type === 'port'),
        [{ type: 'port', protocol: 'tcp', port: 25000, expectedState: 'absent' }]);
    for (const node of empty.nodes) node.profileConfig = Buffer.from(deleted.nodes.find(entry => entry.node === node.id).candidate.bytes).toString();
    const recreated = copy(empty); recreated.links = [{ ...copy(current.links[0]), id: id(20), tunnelPort: 25020, tunnelUuid: randomUUID() }];
    const result = f.plan(empty, recreated); assertPreserved(f.topology, result);
    assert.deepEqual(result.nodes.find(node => node.node === id(2)).checks.filter(check => check.type === 'port'),
        [{ type: 'port', protocol: 'tcp', port: 25020, expectedState: 'listening' }]);
    assert.deepEqual(f.owners, historical, 'original root/pin never updated from candidates');
});
test('actual strict owner schema: private optional raw pin, BSON roundtrip, no lifetime immutability', async () => {
    const f = fixture(), native = copy(f.owners[0]); delete native.profileTargetPin;
    const absent = new Owner(native); await absent.validate(); assert.equal(Object.hasOwn(absent.toObject(), 'profileTargetPin'), false);
    const field = Owner.schema.path('profileTargetPin'); assert.ok(field); assert.equal(field.options.select, false); assert.notEqual(field.options.immutable, true);
    const doc = new Owner(f.owners[0]); await doc.validate();
    const roundtrip = Owner.hydrate(mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize(doc.toObject())));
    assert.deepEqual(roundtrip.toObject().profileTargetPin, f.owners[0].profileTargetPin);
    roundtrip.profileTargetPin = { ...f.owners[0].profileTargetPin, ownerGeneration: randomUUID() };
    await roundtrip.validate(); assert.notEqual(roundtrip.profileTargetPin.ownerGeneration, f.owners[0].profileTargetPin.ownerGeneration);
    for (const value of [undefined, null, [], {}, { ...f.owners[0].profileTargetPin, version: '1' }, { ...f.owners[0].profileTargetPin, extra: true }]) {
        await assert.rejects(new Owner({ ...native, profileTargetPin: value }).validate());
    }
});
test('materializer forwards selected owner carrier without hydrating mutable desired', async () => {
    const f = fixture();
    const materializer = new TopologyOperationPlanMaterializer({ HyNode: { find() { assert.fail('no desired nodes'); } }, CascadeLink: { find() { assert.fail('no desired links'); } } });
    const plan = await materializer.materialize({ ...context, operationKind: 'link.apply', pinnedSnapshot: { topology: f.topology, compiled: compileTopology(f.topology) },
        baselineTopology: f.topology, effectiveTopology: f.topology, selectedOwnerPins: f.selectedOwnerPins });
    assertPreserved(f.topology, plan);
});
for (const [name, mutate] of [
    // Only modeled carrier inputs are supplied; the authority boundary below
    // uses the real verifier instead of accepting this shape as proof.
    ['partial carrier', pins => pins.pop()], ['malformed-present pin', pins => { pins[1].profileTargetPin = null; }],
    ['different descriptor', pins => { pins[1].profileTargetPin.descriptorSha256 = 'f'.repeat(64); }],
    ['owner epoch drift', pins => { pins[1].generation = randomUUID(); }],
]) test(`pure composition refuses ${name}`, () => {
    const f = fixture(), pins = copy(f.selectedOwnerPins); mutate(pins);
    assert.throws(() => f.plan(f.topology, f.topology, pins), { code: 'TOPOLOGY_PROFILE_TARGET_INVALID' });
});
test('coordinator forwards modeled trusted selection pins through the real materializer before durable admission', async () => {
    // A carrier test, not adoption authority. Stop at the DB admission seam;
    // B1 root and A1 fingerprint/writer remain separate integration gates.
    const f = fixture(), snapshot = { revision: 7, deployedRevision: 0, nodes: [], links: [], groups: [] };
    const selected = { baselineTopology: f.topology, effectiveTopology: f.topology,
        resourceNodeIds: f.topology.nodes.map(node => node.id), linkIds: [id(10)], selectedOwnerPins: f.selectedOwnerPins,
        desiredVersion: 'a'.repeat(64), routeState: { complete: true } };
    let carried;
    const topologyRepository = { selectedEnabled: true, readSelected: async () => copy(selected),
        assertSelectedAvailable: async () => {}, async admitTopology({ prepare }) {
            carried = await prepare(snapshot, {});
            throw Error('MODELED_STOP_BEFORE_ADMISSION');
        } };
    const operationRepository = { async createFrozen() { assert.fail('durable admission is outside this carrier test'); } };
    const coordinator = new TopologyOperationCoordinator({ topologyRepository, operationRepository,
        planMaterializer: new TopologyOperationPlanMaterializer({ HyNode: { find() { assert.fail('no desired nodes'); } },
            CascadeLink: { find() { assert.fail('no desired links'); } } }), executionContext: context, idFactory: () => id(70) });
    await assert.rejects(coordinator.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: id(10), linkIds: [id(10)] } }));
    assert.ok(carried, 'real coordinator preparation and materializer completed');
    assert.deepEqual(carried.selectedOwnerPins, f.selectedOwnerPins);
    assert.ok(carried.frozenPlan.nodes.every(node => node.profileTargetPin && node.targetProfile === 'xray-main'));
});
test('imported composition retains the native fail-closed incomplete REALITY guard', () => {
    const f = fixture('reality'), after = copy(f.topology);
    delete after.links[0].realityPrivateKey;
    assert.throws(() => f.plan(f.topology, after), { code: 'INCOMPLETE_REALITY_PARAMETERS' });
});
test('public operation whitelist never exports the private imported carrier or descriptors', () => {
    const f = fixture(), plan = f.plan();
    const view = projectTopologyOperationStatus({ _id: id(70), topologyRevision: 7, status: 'succeeded',
        selectedOwnerPins: f.selectedOwnerPins, baselineTopology: f.topology, effectiveTopology: f.topology, nodes: plan.nodes });
    const text = JSON.stringify(view);
    for (const field of ['profileTargetPin', 'selectedOwnerPins', 'baselineTopology', 'effectiveTopology', 'legacyAppliedTopology', 'candidate', 'configPath']) {
        assert.equal(text.includes(`"${field}"`), false, field);
    }
    assert.equal(text.includes(f.owners[0].profileTargetPin.descriptorSha256), false);
});
test('raw descriptor and desired metadata alone do not permit Bridge MAIN', () => {
    const f = fixture();
    assert.throws(() => f.plan(f.topology, f.topology, []), { code: 'TOPOLOGY_PROFILE_BASELINE_MISMATCH' });
});
for (const security of ['none', 'reality']) {
    test(`raw ${security}: no pin refuses baseline artifacts before profile preservation`, () => {
        const f = fixture(security), original = copy(f.topology);
        // Both an unchanged desired graph and a deletion must check the actual
        // baseline; neither duplicate base tags nor desired placement is a guard.
        for (const after of [f.topology, { nodes: [], links: [], groups: [] }]) {
            assert.throws(() => f.plan(f.topology, after, []), {
                code: 'TOPOLOGY_PROFILE_BASELINE_MISMATCH',
                message: 'The verified profile does not match its owned cascade artifacts',
            });
        }
        assert.deepEqual(f.topology, original);
    });
    test(`native ${security}: unpinned forward apply/replay/delete keeps role-default targets`, () => {
        const f = fixture(security), native = copy(f.topology), empty = { nodes: [], links: [], groups: [] };
        for (const node of native.nodes) delete node.profileConfig;
        const first = f.plan(empty, native, []);
        for (const node of native.nodes) node.profileConfig = Buffer.from(first.nodes.find(entry => entry.node === node.id).candidate.bytes).toString();
        const replay = f.plan(native, native, []);
        assert.deepEqual(replay.nodes.map(node => node.candidate), first.nodes.map(node => node.candidate));
        const deleted = f.plan(native, empty, []);
        for (const plan of [first, replay, deleted]) for (const node of plan.nodes) {
            assert.equal(node.targetProfile, node.role === 'portal' ? 'xray-main' : 'xray-bridge');
            assert.equal(Object.hasOwn(node, 'profileTargetPin'), false);
        }
        assert.ok(deleted.nodes.find(node => node.role === 'bridge').checks.some(check =>
            check.type === 'port' && check.port === 25000 && check.expectedState === 'absent'));
    });
}
// Real Mongoose queries/casting/projections over a disconnected modeled driver.
// This is negative qualification, NOT seeded authority / public adoption.
async function withOwnerDriver(rows, work) {
    const prior = Owner.collection.collection, buffer = Owner.collection.buffer;
    const sift = require('sift').default, reads = [];
    const project = (row, options) => {
        const result = mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize(row));
        for (const field of ['legacyAppliedTopology', 'profileTargetPin']) if (options.projection?.[field] === 0) delete result[field];
        return result;
    };
    Owner.collection.buffer = false;
    Owner.collection.collection = { find(filter, options) { reads.push(copy(options)); return { toArray: async () => rows.filter(sift(filter)).map(row => project(row, options)) }; },
        async findOne(filter, options) { reads.push(copy(options)); const row = rows.find(sift(filter)); return row ? project(row, options) : null; } };
    try { return await work(reads); } finally { Owner.collection.collection = prior; Owner.collection.buffer = buffer; }
}
function reader(f) {
    const query = values => { const q = { select() { return q; }, lean: async () => copy(values) }; return q; };
    const nodes = f.topology.nodes.map(({ id: _id, role: cascadeRole, profileConfig, ...rest }) => ({ ...rest, _id, cascadeRole }));
    const links = f.topology.links.map(({ id: _id, source: portalNode, target: bridgeNode, ...rest }) => ({ ...rest, _id, portalNode, bridgeNode }));
    return new TopologyDeploymentRepository({ snapshotReader: { readDraft: async () => ({}), HyNode: { find: () => query(nodes) },
        CascadeLink: { find: () => query(links), findById: key => query(links.find(link => link._id === key) || null) } },
        CascadeTopologyState: { findOneAndUpdate() {} }, TopologyConfigOwner: Owner, TopologyOperation: {}, NodeOperationLock: {}, transactionRunner: async work => work({}) });
}
for (const [name, mutate, code = 'TOPOLOGY_LEGACY_IMPORT_MISMATCH'] of [
    ['missing pin', owner => { delete owner.profileTargetPin; }], ['malformed pin', owner => { owner.profileTargetPin = null; }],
    ['stale root', owner => { owner.originalSnapshot.unitSha256 = 'f'.repeat(64); }],
    // Recognition now succeeds, but the independently owned SIDECAR below
    // aliases the bridge's physical identity. This is not public adoption proof.
    ['shape-only matching root with a physical-alias SIDECAR', () => {}, 'TOPOLOGY_PHYSICAL_NODE_ALIAS'],
]) test(`reader refuses ${name} instead of silently selecting an independent SIDECAR`, async () => {
    const f = fixture(); mutate(f.owners[0]);
    const rows = f.owners.map(owner => ({ ...owner, node: new mongoose.Types.ObjectId(owner.node) }));
    rows.push({ ...copy(rows[1]), profile: 'xray-bridge', legacyAppliedTopology: undefined, profileTargetPin: undefined,
        originalSnapshot: { configSha256: sha('{"nonempty":"independent-sidecar"}') } });
    delete rows[2].legacyAppliedTopology; delete rows[2].profileTargetPin;
    await withOwnerDriver(rows, async reads => {
        await assert.rejects(reader(f).readSelected({ scope: { kind: 'link.apply', linkId: id(10) }, executionContext: context }), { code });
        assert.ok(reads.length);
        assert.notEqual(reads[0].projection?.legacyAppliedTopology, 0);
        assert.notEqual(reads[0].projection?.profileTargetPin, 0);
    });
});
test('isSelectedCurrent refuses newly present private pin on a native operation even if generation/identity match', async () => {
    const f = fixture();
    const pin = copy(f.selectedOwnerPins[0]); delete pin.profileTargetPin;
    const row = { ...copy(f.owners[0]), node: new mongoose.Types.ObjectId(pin.node), lastSettledOperation: id(70), profileTargetPin: null };
    const link = { ...f.topology.links[0], _id: id(10), portalNode: id(1), bridgeNode: id(2) };
    const operation = { _id: id(70), linkId: id(10), selectedOwnerPins: [pin], desiredVersion: linkDesiredVersion(link) };
    await withOwnerDriver([row], async reads => {
        assert.equal(await reader(f).isSelectedCurrent(operation), false);
        assert.notEqual(reads[0].projection?.profileTargetPin, 0, 'actual owner query must not silently drop private pin');
    });
});
test('pure composition accepts exact current native forward artifacts in MAIN, without reimporting historical bytes', () => {
    const f = fixture(), current = copy(f.topology), link = current.links[0];
    const ref = `link-${sha(`celerity-topology-link:${link.id}`).slice(0, 8)}`;
    const populated = { ...link, _id: ref, portalNode: { ...current.nodes[0], _id: id(1) }, bridgeNode: { ...current.nodes[1], _id: id(2) } };
    for (const node of current.nodes) {
        const config = JSON.parse(node.profileConfig);
        config.inbounds = config.inbounds.filter(item => !item.tag.startsWith('fwd-'));
        config.outbounds = config.outbounds.filter(item => !item.tag.startsWith('fwd-'));
        config.routing.rules = config.routing.rules.filter(rule => !rule.outboundTag?.startsWith('fwd-') && !rule.inboundTag?.some(tag => tag.startsWith('fwd-')));
        if (node.role === 'portal') generator.applyForwardChain(config, [populated], ['client-in']);
        else generator.applyForwardHopInbound(config, [populated]);
        node.profileConfig = JSON.stringify(config);
    }
    const plan = f.plan(current, current); assertPreserved(f.topology, plan);
    assert.equal(configs(plan).get(id(2)).inbounds.find(item => item.tag.startsWith('fwd-hop-')).tag, `fwd-hop-${ref.slice(-8)}`);
    assert.deepEqual(plan.nodes.map(node => node.profileTargetPin), [f.owners[1].profileTargetPin, f.owners[0].profileTargetPin]);
});
test('pure delete with no effective endpoint descriptors keeps MAIN active and portal fail-closed', () => {
    const f = fixture(), plan = f.plan(f.topology, { nodes: [], links: [], groups: [] });
    assertPreserved(f.topology, plan);
    assert.ok(configs(plan).get(id(1)).routing.rules.some(rule => rule.outboundTag === 'block' && rule.inboundTag?.includes('client-in')));
    assert.equal(configs(plan).get(id(2)).inbounds.some(item => item.tag.startsWith('fwd-')), false);
});
for (const [name, mutate] of [
    ['missing listener', config => { config.inbounds = config.inbounds.filter(item => !item.tag.startsWith('fwd-hop-')); }],
    ['duplicate listener', config => { config.inbounds.push(copy(config.inbounds.find(item => item.tag.startsWith('fwd-hop-')))); }],
    ['wrong tunnel UUID', config => { config.inbounds.find(item => item.tag.startsWith('fwd-hop-')).settings.clients[0].id = randomUUID(); }],
    ['unrepresented reserved rule', config => { config.routing.rules.push({ type: 'field', inboundTag: ['fwd-hop-foreign'], outboundTag: 'direct' }); }],
]) test(`pure pin shape cannot authorize ${name} in current readback`, () => {
    const f = fixture(), before = copy(f.topology), config = JSON.parse(before.nodes[1].profileConfig);
    mutate(config); before.nodes[1].profileConfig = JSON.stringify(config);
    assert.throws(() => f.plan(before, f.topology), { code: 'TOPOLOGY_PROFILE_BASELINE_MISMATCH' });
});
