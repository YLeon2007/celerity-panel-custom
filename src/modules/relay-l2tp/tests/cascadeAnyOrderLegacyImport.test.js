'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const configPath = require.resolve('../../../../config');
require.cache[configPath] = { id: configPath, filename: configPath, loaded: true, exports: { panel: { domain: 'legacy.invalid' }, xray: {} } };
const loggerPath = require.resolve('../../../utils/logger');
require.cache[loggerPath] = { id: loggerPath, filename: loggerPath, loaded: true, exports: { info() {}, warn() {}, error() {} } };
const generator = require('../../../services/configGenerator');
const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const id = n => n.toString(16).padStart(24, '0');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
// Query-aware, transaction-shaped local persistence; NOT Mongo/physical evidence.
function model(rows, db) {
    const match = (row, f) => Object.entries(f).every(([k, v]) => v?.$in ? v.$in.includes(row[k]) : same(row[k], v));
    const query = fn => {
        let includeImported = false;
        const q = { select(fields) { includeImported ||= fields.split(/\s+/).includes('+legacyAppliedTopology'); return q; },
            session() { return q; }, read() { return q; }, readConcern() { return q; }, maxTimeMS() { return q; },
            lean: async () => {
                const result = structuredClone(fn());
                // Mirror the actual schema's private-field projection, so a
                // no-op select double cannot hide missing internal selection.
                if (!includeImported) for (const row of Array.isArray(result) ? result : [result]) {
                    if (row) delete row.legacyAppliedTopology;
                }
                return result;
            }, then(a, b) { return q.lean().then(a, b); } };
        return q;
    };
    return { rows, db, collection: { indexes: async () => [{ key: { node: 1, profile: 1 }, unique: true }] },
        create: async docs => { rows.push(...structuredClone(docs)); return docs; },
        find: f => query(() => rows.filter(r => match(r, f))),
        findById: key => query(() => rows.find(r => String(r._id) === key) || null),
        findOne: f => query(() => rows.find(r => match(r, f)) || null),
        findOneAndUpdate: (f, change) => query(() => {
            const row = rows.find(r => match(r, f)); if (!row) return null;
            Object.assign(row, structuredClone(change.$set || {}));
            for (const key of Object.keys(change.$unset || {})) delete row[key];
            return row;
        }) };
}
function fixture(context = TEST, { relay = false } = {}) {
    const session = { inTransaction: () => true };
    const db = { transaction: work => work(session) };
    const nodes = (relay ? ['portal', 'relay', 'bridge'] : ['portal', 'bridge']).map((role, i) => ({
        id: id(i + 1), role, type: 'xray', active: true, ip: `192.0.2.${i + 1}`, port: 24443,
        xray: { inboundTag: 'client-in', security: 'none', transport: 'tcp', extraInbounds: [] } }));
    const links = nodes.slice(1).map((n, i) => ({ id: id(10 + i), source: nodes[i].id, target: n.id,
        mode: 'reverse', active: true, tunnelPort: 25000 + i, tunnelUuid: `${i + 1}`.repeat(8) + '-1111-4111-8111-111111111111',
        tunnelSecurity: 'none', tunnelTransport: 'tcp', tunnelDomain: 'old-tunnel.invalid', priority: 1 }));
    const populated = links.map(link => ({ ...link, _id: link.id,
        portalNode: { ...nodes.find(n => n.id === link.source), cascadeRole: nodes.find(n => n.id === link.source).role },
        bridgeNode: { ...nodes.find(n => n.id === link.target), cascadeRole: nodes.find(n => n.id === link.target).role } }));
    const foreignClient = { tag: 'unrelated-client', port: 26000, protocol: 'vless', settings: {
        clients: [{ id: '99999999-9999-4999-8999-999999999999', email: 'unchanged@invalid', flow: 'xtls-rprx-vision' }], decryption: 'none' } };
    for (const node of nodes) {
        const incoming = populated.filter(link => link.target === node.id), outgoing = populated.filter(link => link.source === node.id);
        let config;
        if (node.role === 'portal') {
            config = JSON.parse(generator.generateXrayConfig({ ...node, _id: node.id }, []));
            config.inbounds.find(row => row.tag === 'client-in').settings.clients.push({ id: '88888888-8888-4888-8888-888888888888', email: 'existing@invalid' });
            generator.applyReversePortal(config, outgoing, ['client-in']);
        } else if (node.role === 'relay') config = JSON.parse(generator.generateRelayConfig(incoming[0], incoming[0].portalNode, outgoing));
        else config = JSON.parse(generator.generateCombinedBridgeConfig(incoming));
        config.inbounds ||= [];
        config.inbounds.push(structuredClone(foreignClient));
        config.outbounds.push({ tag: 'unrelated-out', protocol: 'blackhole' });
        config.routing.rules.push({ type: 'field', inboundTag: ['unrelated-client'], outboundTag: 'unrelated-out' });
        config.policy = { levels: { 0: { statsUserUplink: true } } };
        node.profileConfig = JSON.stringify(config, null, 2) + '\n';
    }
    const topology = { nodes, links, groups: [] };
    // This map explicitly models node config/unit/service readback and restoration,
    // not real SSH, systemd, physical quiescence or a remote backup implementation.
    const physical = new Map(nodes.map(n => [n.id, { config: n.profileConfig, unit: `dummy-unit-${n.id}\n`, active: 'active', enabled: 'enabled' }]));
    let held = false;
    const Owner = model([], db);
    const transfer = new TopologyConfigTransfer({ executionContext: context, TopologyConfigOwner: Owner,
        withVerifiedMaintenance: async ({ binding }, work) => {
            held = true;
            const current = physical.get(binding.node);
            await work({ status: 'verified', authority: 'external-maintenance-v1', binding: structuredClone(binding),
                proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
                oldBackend: { instanceId: 'dummy-classic', pid: 42, processStartTime: 'dummy-start', processTree: 'stopped', dispatch: 'disabled' },
                readback: { source: 'node-readback', configSha256: sha(current.config), unitSha256: sha(current.unit),
                    serviceActive: current.active, serviceEnabled: current.enabled } });
            held = false;
        } });
    const desiredNodes = nodes.map(({ id, role, profileConfig, ...rest }) => ({ ...rest, _id: id, cascadeRole: role }));
    const desiredLinks = links.map(({ id, source, target, ...rest }) => ({ ...rest, _id: id, portalNode: source, bridgeNode: target, status: 'online' }));
    desiredLinks.push({ ...desiredLinks[0], _id: id(90), status: 'pending', tunnelPort: 25990 });
    desiredLinks.push({ ...desiredLinks[0], _id: id(91), active: false, tunnelPort: 25991 });
    const HyNode = model(desiredNodes, db), CascadeLink = model(desiredLinks, db), Operation = model([], db);
    const State = model([{ _id: 'singleton', revision: 7 }], db);
    const repository = new TopologyDeploymentRepository({ snapshotReader: { HyNode, CascadeLink, readDraft: async () => ({}) },
        CascadeTopologyState: State, TopologyConfigOwner: Owner, TopologyOperation: Operation, NodeOperationLock: {}, transactionRunner: db.transaction });
    const initialize = async node => transfer.initializeClassic({ node: node.id, profile: node.role === 'portal' ? 'xray-main' : 'xray-bridge',
        nodeIdentity: { machineId: String(nodes.indexOf(node) + 1).repeat(32), sshHostKeySha256: String(nodes.indexOf(node) + 1).repeat(64) } });
    const adopt = async (node, snapshot = topology) => {
        const classic = await initialize(node);
        return transfer.adopt({ node: node.id, profile: classic.profile, generation: classic.generation, proofRef: 'dummy-readonly-snapshot', legacyTopology: snapshot });
    };
    const read = () => repository.readSelected({ scope: { kind: 'link.apply', linkId: links[0].id }, executionContext: context, session });
    return { context, topology, physical, Owner, Operation, desiredLinks, repository, transfer, adopt, read, held: () => held };
}
for (const context of [TEST, PROD]) test(`${context.target}: imports actual classic-generated exact prior descriptors without operations or activation of pending neighbors`, async () => {
    const f = fixture(context, { relay: true });
    const original = structuredClone(f.topology), physical = structuredClone([...f.physical]);
    for (const node of f.topology.nodes) await f.adopt(node);
    // A later save-only neighbor edit must not enter the imported baseline.
    f.desiredLinks[1].tunnelPort = 25999;
    f.desiredLinks[1].tunnelUuid = '77777777-7777-4777-8777-777777777777';
    const selected = await f.read();
    assert.deepEqual(selected.baselineTopology, original);
    assert.deepEqual(selected.effectiveTopology.links.find(link => link.id === id(11)), original.links[1]);
    assert.equal(selected.effectiveTopology.links.length, 2);
    assert.equal(f.desiredLinks.find(link => link._id === id(90)).status, 'pending');
    assert.equal(f.desiredLinks.find(link => link._id === id(91)).active, false);
    assert.deepEqual([...f.physical], physical, 'adoption/import must never upload or rewrite a config');
    assert.equal(f.Operation.rows.length, 0, 'import must not manufacture a successful operation/readback');
    for (const owner of f.Owner.rows) {
        assert.equal(owner.lastSettledOperation, undefined);
        assert.deepEqual(owner.legacyAppliedTopology, original);
        assert.equal(owner.adoptionReceipt.toGeneration, owner.generation);
    }
});

for (const context of [TEST, PROD]) test(`${context.target}: public handback restores exact original profiles and remains compatible with the classic ownership reader`, async () => {
    const f = fixture(context);
    for (const node of f.topology.nodes) await f.adopt(node);
    const originalPhysical = structuredClone([...f.physical]);
    const generations = f.Owner.rows.map(row => row.generation);
    const first = f.Owner.rows[0], current = f.physical.get(String(first.node));
    const request = { node: first.node, profile: first.profile, generation: first.generation, proofRef: 'dummy-restoration' };
    for (const [field, changed] of [['config', '{}\n'], ['unit', 'different-unit'], ['active', 'inactive'], ['enabled', 'disabled']]) {
        const prior = current[field]; current[field] = changed;
        await assert.rejects(f.transfer.handback(request), { code: 'CONFIG_RESTORATION_MISMATCH' });
        assert.equal(f.held(), true, 'failed modeled physical restoration retains exclusion');
        assert.equal(first.owner, 'topology'); assert.equal(first.generation, generations[0]);
        current[field] = prior; // Explicit modeled physical restoration, not a DB flag.
    }
    for (const row of [...f.Owner.rows]) {
        const before = structuredClone(row);
        const restored = await f.transfer.handback({ node: row.node, profile: row.profile, generation: row.generation, proofRef: 'dummy-restoration' });
        assert.equal(restored.owner, 'classic');
        assert.equal(restored.handbackReceipt.fromGeneration, before.generation);
        assert.equal(restored.handbackReceipt.toGeneration, restored.generation);
        assert.deepEqual(restored.adoptionReceipt, before.adoptionReceipt);
        assert.equal(restored.legacyAppliedTopology, undefined, 'ordinary transfer return must not expose private descriptors');
        assert.deepEqual(row.legacyAppliedTopology, f.topology, 'original import remains private historical evidence');
        assert.equal(restored.lastSettledOperation, undefined);
    }
    assert.deepEqual([...f.physical], originalPhysical);
    assert.equal(f.Operation.rows.length, 0);
    assert.equal(f.held(), false);
    await assert.rejects(f.read(), { code: 'TOPOLOGY_CONFIG_OWNER_REQUIRED' });
    // Exercise the unchanged public classic protocol, including Date receipt
    // equality and native owner rows. Only DB/history reads are local seams.
    const mongoose = require('mongoose');
    const Operation = require('../models/topologyOperationModel');
    const previousDb = mongoose.connection.db, previousExists = Operation.exists;
    mongoose.connection.db = { collection(name) {
        assert.equal(name, 'topologyconfigowners');
        return { find(filter) { return { toArray: async () => structuredClone(f.Owner.rows.filter(row => row.node === String(filter.node))) }; } };
    } };
    Operation.exists = async () => false;
    try {
        const { topologyManagesNodeConfig } = require('../../../services/topologyConfigOwnership');
        for (const node of f.topology.nodes) assert.equal(await topologyManagesNodeConfig({ _id: node.id, cascadeRole: node.role },
            { PANEL_DOMAIN: context.hostIdentity }), false);
    } finally { mongoose.connection.db = previousDb; Operation.exists = previousExists; }
});

for (const [name, mutate, code] of [
    ['changed UUID descriptor', t => { t.links[0].tunnelUuid = randomUUID(); }, 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH'],
    ['changed endpoint', t => { t.nodes[0].ip = '192.0.2.99'; }, 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH'],
    ['different raw bytes', t => { t.nodes[1].profileConfig += '\n'; }, 'CONFIG_LEGACY_IMPORT_READBACK_MISMATCH'],
    ['pending inclusion', t => { t.links[0].status = 'pending'; }, 'CONFIG_LEGACY_IMPORT_INVALID'],
    ['inactive inclusion', t => { t.links[0].active = false; }, 'CONFIG_LEGACY_IMPORT_INVALID'],
    ['classic forward MAIN layout', t => { t.links[0].mode = 'forward'; }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
    ['TLS extra inbound with live certificate dependency', t => { t.nodes[0].xray.extraInbounds = [{ inboundTag: 'tls-extra', security: 'tls', tlsSource: 'panel' }]; }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
    ['unobserved installed policy', t => { t.groups.push({ _id: id(50), paths: [{ linkIds: [id(10)], pathKey: 'unverified', enabled: true }] }); }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
]) test(`import refuses ${name} before publishing topology ownership`, async () => {
    const f = fixture(), snapshot = structuredClone(f.topology);
    mutate(snapshot);
    // Verify the dialer as well: this catches endpoint/credential drift even
    // when the local listener still happens to match.
    await assert.rejects(f.adopt(f.topology.nodes[1], snapshot), { code });
    assert.equal(f.Owner.rows[0].owner, 'classic');
    assert.equal(f.Owner.rows[0].adoptionReceipt, undefined);
    assert.equal(f.Owner.rows[0].legacyAppliedTopology, undefined);
    assert.equal(f.Operation.rows.length, 0);
});

test('an incomplete per-profile import is not an applied component', async () => {
    const f = fixture();
    await f.adopt(f.topology.nodes[0]);
    await assert.rejects(f.read(), { code: 'TOPOLOGY_CONFIG_OWNER_REQUIRED' });
    await f.adopt(f.topology.nodes[1]);
    const row = f.Owner.rows[1];
    row.legacyAppliedTopology.links[0].priority = 42; // No generator effect, but a different accepted policy inventory.
    await assert.rejects(f.read(), { code: 'TOPOLOGY_LEGACY_IMPORT_MISMATCH' });
    row.legacyAppliedTopology = structuredClone(f.topology);
    assert.deepEqual((await f.read()).baselineTopology, f.topology);
});

test('legacy owner snapshot is private, has no default, and survives the actual strict Mongoose/BSON schema', async () => {
    const mongoose = require('mongoose');
    const Owner = require('../../../models/topologyConfigOwnerModel');
    const f = fixture();
    const adopted = await f.adopt(f.topology.nodes[0]);
    const row = new Owner(adopted); await row.validate();
    const reloaded = Owner.hydrate(mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize(row.toObject())));
    assert.deepEqual(reloaded.toObject().legacyAppliedTopology, f.topology);
    assert.equal(Owner.schema.path('legacyAppliedTopology').options.select, false);
    assert.equal(new Owner({}).legacyAppliedTopology, undefined);
});

for (const [name, change] of [
    ['missing listener', config => { config.inbounds = config.inbounds.filter(item => !item.tag.startsWith('bridge-conn-')); }],
    ['duplicate connector', config => { config.inbounds.push(structuredClone(config.inbounds.find(item => item.tag.startsWith('bridge-conn-')))); }],
    ['missing route', config => { config.routing.rules = config.routing.rules.filter(item => item.outboundTag !== 'portal-0000000a'); }],
    ['extra old shared-profile tunnel', config => { config.reverse.portals.push({ tag: 'old-generic-portal', domain: 'unrepresented.invalid' }); }],
    ['changed client key metadata', config => { config.inbounds.find(item => item.tag === 'client-in').streamSettings.security = 'reality'; }],
]) test(`import rejects ${name} even when its bytes match the physical adoption readback`, async () => {
    const f = fixture(), snapshot = structuredClone(f.topology), node = snapshot.nodes[0];
    const config = JSON.parse(node.profileConfig); change(config);
    node.profileConfig = JSON.stringify(config);
    f.physical.get(node.id).config = node.profileConfig;
    await assert.rejects(f.adopt(f.topology.nodes[0], snapshot), { code: 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH' });
    assert.equal(f.Owner.rows[0].owner, 'classic');
    assert.equal(f.Owner.rows[0].legacyAppliedTopology, undefined);
});

test('actual old single-bridge generator layout is recognized without rewriting its tags or users', async () => {
    const f = fixture(), [portal, bridge] = f.topology.nodes, link = f.topology.links[0];
    const populatedPortal = { ...portal, _id: portal.id, cascadeRole: portal.role };
    const config = JSON.parse(generator.generateBridgeConfig({ ...link, _id: link.id, portalNode: populatedPortal }, populatedPortal));
    bridge.profileConfig = JSON.stringify(config) + '\n';
    f.physical.get(bridge.id).config = bridge.profileConfig;
    for (const node of f.topology.nodes) await f.adopt(node);
    assert.deepEqual((await f.read()).baselineTopology, f.topology);
});

test('REALITY link keys and installed client metadata are carried verbatim from actual classic generation', async () => {
    const f = fixture(), [portal, bridge] = f.topology.nodes, link = f.topology.links[0];
    Object.assign(link, { tunnelSecurity: 'reality', realityPrivateKey: 'dummy-private-no-credential-source',
        realityPublicKey: 'dummy-public-no-credential-source', realityShortIds: ['1234abcd'],
        realityDest: 'decoy.invalid:443', realitySni: ['decoy.invalid'], realityFingerprint: 'chrome' });
    const populated = { ...link, _id: link.id, portalNode: { ...portal, _id: portal.id } };
    const config = JSON.parse(generator.generateXrayConfig({ ...portal, _id: portal.id }, []));
    const runtimeClient = { id: '66666666-6666-4666-8666-666666666666', email: 'kept@invalid', flow: 'xtls-rprx-vision' };
    config.inbounds.find(row => row.tag === 'client-in').settings.clients.push(runtimeClient);
    generator.applyReversePortal(config, [populated], ['client-in']);
    portal.profileConfig = JSON.stringify(config);
    bridge.profileConfig = generator.generateCombinedBridgeConfig([populated]);
    for (const node of f.topology.nodes) { f.physical.get(node.id).config = node.profileConfig; await f.adopt(node); }
    const imported = (await f.read()).baselineTopology;
    assert.deepEqual(imported.links[0], link);
    assert.deepEqual(JSON.parse(imported.nodes[0].profileConfig).inbounds.find(row => row.tag === 'client-in').settings.clients, [runtimeClient]);
});

test('caller edits after adoption starts cannot alter the copied inventory, and unknown commit retains its real snapshot', async () => {
    const f = fixture(), node = f.topology.nodes[0];
    const classic = await f.transfer.initializeClassic({ node: node.id, profile: 'xray-main',
        nodeIdentity: { machineId: '1'.repeat(32), sshHostKeySha256: '1'.repeat(64) } });
    const proposed = structuredClone(f.topology);
    const original = structuredClone(proposed);
    const tx = f.Owner.db.transaction;
    f.Owner.db.transaction = async work => { await tx(work); throw new Error('modeled unknown commit delivery'); };
    const pending = f.transfer.adopt({ node: node.id, profile: classic.profile, generation: classic.generation,
        proofRef: 'dummy-observation', legacyTopology: proposed });
    proposed.links[0].tunnelUuid = randomUUID();
    await assert.rejects(pending, /modeled unknown commit delivery/);
    assert.equal(f.held(), true);
    assert.equal(f.Owner.rows[0].owner, 'topology');
    assert.deepEqual(f.Owner.rows[0].legacyAppliedTopology, original);
    assert.equal(f.Operation.rows.length, 0);
});

test('an endpoint save-only edit retains the exact old imported endpoints in the cleanup resource union', async () => {
    const f = fixture();
    for (const node of f.topology.nodes) await f.adopt(node);
    const newNode = { ...structuredClone(f.repository.snapshotReader.HyNode.rows[1]), _id: id(3), ip: '192.0.2.3' };
    f.repository.snapshotReader.HyNode.rows.push(newNode);
    f.physical.set(id(3), { config: '{}\n', unit: 'dummy-new-unit', active: 'inactive', enabled: 'disabled' });
    const classic = await f.transfer.initializeClassic({ node: id(3), profile: 'xray-bridge',
        nodeIdentity: { machineId: '3'.repeat(32), sshHostKeySha256: '3'.repeat(64) } });
    await f.transfer.adopt({ node: id(3), profile: classic.profile, generation: classic.generation, proofRef: 'dummy-empty-profile' });
    f.desiredLinks[0].bridgeNode = id(3);
    const selected = await f.read();
    assert.deepEqual(selected.baselineTopology.links[0], f.topology.links[0]);
    assert.equal(selected.effectiveTopology.links[0].target, id(3));
    assert.deepEqual(selected.resourceNodeIds, [id(1), id(2), id(3)]);
});

test('a shared legacy bridge imports both old links and refuses an omitted peer profile artifact', async () => {
    const f = fixture(), [portal, bridge] = f.topology.nodes;
    const secondPortal = { ...structuredClone(portal), id: id(3), ip: '192.0.2.3' };
    const peer = { ...structuredClone(f.topology.links[0]), id: id(12), source: secondPortal.id, tunnelPort: 25012,
        tunnelUuid: '33333333-3333-4333-8333-333333333333' };
    const populated = [f.topology.links[0], peer].map(link => ({ ...link, _id: link.id,
        portalNode: { ...(link.source === portal.id ? portal : secondPortal), _id: link.source } }));
    const main = JSON.parse(generator.generateXrayConfig({ ...secondPortal, _id: secondPortal.id }, []));
    generator.applyReversePortal(main, [populated[1]], ['client-in']);
    secondPortal.profileConfig = JSON.stringify(main);
    bridge.profileConfig = generator.generateCombinedBridgeConfig(populated);
    f.physical.get(bridge.id).config = bridge.profileConfig;
    f.physical.set(secondPortal.id, { config: secondPortal.profileConfig, unit: 'dummy-peer-unit', active: 'active', enabled: 'enabled' });
    f.topology.nodes.push(secondPortal); f.topology.links.push(peer);
    f.repository.snapshotReader.HyNode.rows.push({ ...secondPortal, _id: secondPortal.id, cascadeRole: 'portal' });
    f.desiredLinks.push({ ...peer, _id: peer.id, portalNode: peer.source, bridgeNode: peer.target, status: 'online' });
    // Snapshot omission cannot classify a real peer's reverse bridge as foreign.
    const incomplete = { ...structuredClone(f.topology), nodes: structuredClone(f.topology.nodes.slice(0, 2)), links: [structuredClone(f.topology.links[0])] };
    const classic = await f.transfer.initializeClassic({ node: bridge.id, profile: 'xray-bridge',
        nodeIdentity: { machineId: '2'.repeat(32), sshHostKeySha256: '2'.repeat(64) } });
    await assert.rejects(f.transfer.adopt({ node: bridge.id, profile: classic.profile, generation: classic.generation,
        proofRef: 'dummy-readonly', legacyTopology: incomplete }), { code: 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH' });
    await f.transfer.adopt({ node: bridge.id, profile: classic.profile, generation: classic.generation,
        proofRef: 'dummy-readonly', legacyTopology: f.topology });
    await f.adopt(portal); await f.adopt(secondPortal);
    const selected = await f.read();
    assert.deepEqual(selected.baselineTopology.links, f.topology.links);
    assert.deepEqual(selected.resourceNodeIds, [id(1), id(2), id(3)]);
});

test('conversion prerequisite: actual descriptor materialization still refuses old classic artifact identities before dispatch', async () => {
    const f = fixture(TEST, { relay: true });
    for (const node of f.topology.nodes) await f.adopt(node);
    const selected = await f.read();
    const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
    const { compileTopology } = require('../domain/topologyCompiler');
    const materializer = new TopologyOperationPlanMaterializer({
        HyNode: { find() { assert.fail('verified imported descriptors must not rehydrate mutable nodes'); } },
        CascadeLink: { find() { assert.fail('verified imported descriptors must not rehydrate mutable links'); } } });
    await assert.rejects(materializer.materialize({ target: TEST.target, hostIdentity: TEST.hostIdentity, operationKind: 'link.apply',
        pinnedSnapshot: { revision: 7, topology: selected.effectiveTopology, compiled: compileTopology(selected.effectiveTopology) },
        baselineTopology: selected.baselineTopology, effectiveTopology: selected.effectiveTopology }),
    { code: 'TOPOLOGY_PROFILE_BASELINE_MISMATCH' });
    // This is an explicit unresolved generator seam, NOT a completed migration.
    const { legacyProfileArtifacts } = require('../../../services/topologyConfigTransfer');
    const portal = legacyProfileArtifacts(f.topology, id(1));
    const relay = legacyProfileArtifacts(f.topology, id(2));
    assert.equal(portal.inbounds[0].tag, 'bridge-conn-0000000a');
    assert.equal(relay.outbounds[0].tag, 'tunnel-up');
    assert.equal(f.Operation.rows.length, 0);
});
