'use strict';
// Public producer -> real schemas/BSON/queries -> selected composition/writer.
// Persistence transactions and held node IO are explicitly MODELED, not Mongo,
// SSH, systemd, physical exclusion, Xray validation or worker settlement proof.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const mongoose = require('mongoose');
const sift = require('sift').default;
const configPath = require.resolve('../../../../config');
require.cache[configPath] = { id: configPath, filename: configPath, loaded: true, exports: { panel: { domain: 'fixture.invalid' }, xray: {} } };
const generator = require('../../../services/configGenerator');
const { TopologyConfigTransfer, verifyLegacyAppliedProfile, legacyProfileArtifacts } = require('../../../services/topologyConfigTransfer');
const { verifyImportedProfileTargetPin, projectImportedProfileTargetPin } = require('../services/topologyProfileTarget');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TopologyOperationRepository, selectedAdmissionFingerprint } = require('../repositories/topologyOperationRepository');
const { TopologyOperationCoordinator, projectTopologyOperationStatus } = require('../services/topologyOperationCoordinator');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');
const { compileTopology } = require('../domain/topologyCompiler');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const id = n => n.toString(16).padStart(24, '0');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const copy = value => structuredClone(value);
const bson = value => mongoose.mongo.BSON.deserialize(mongoose.mongo.BSON.serialize(value));
function topology(security = 'none', clientSecurity = security, linkFields = {}) {
    const nodes = ['portal', 'bridge'].map((role, i) => ({ id: id(i + 1), role, type: 'xray', active: true,
        ip: `192.0.2.${i + 1}`, port: 24443 + i, xray: { security: clientSecurity, transport: 'tcp', inboundTag: 'client-in',
            extraInbounds: [], ...(clientSecurity === 'reality' ? { realityPrivateKey: 'modeled-client-private',
                realityDest: 'decoy.invalid:443', realitySni: ['decoy.invalid'], realityShortIds: ['1234abcd'] } : {}) } }));
    const link = { id: id(10), source: id(1), target: id(2), mode: 'forward', active: true, priority: 1,
        tunnelUuid: '11111111-1111-4111-8111-111111111111', tunnelPort: 25000, tunnelSecurity: security,
        ...(security === 'reality' ? { realityPrivateKey: 'modeled-tunnel-private', realityPublicKey: 'modeled-tunnel-public',
            realityDest: 'decoy.invalid:443', realitySni: ['decoy.invalid'], realityShortIds: ['1234abcd'] } : {}), ...linkFields };
    // Deliberately omit protocol/transport: only the real vless/TCP defaults.
    const populated = { ...link, _id: link.id, portalNode: { ...nodes[0], _id: id(1) }, bridgeNode: { ...nodes[1], _id: id(2) } };
    for (const node of nodes) {
        const config = JSON.parse(generator.generateXrayConfig({ ...node, _id: node.id }, []));
        config.inbounds.find(row => row.tag === 'client-in').settings.clients.push({ id: randomUUID(), email: `kept-${node.role}@invalid` });
        if (node.role === 'portal') generator.applyForwardChain(config, [populated], ['client-in']);
        else generator.applyForwardHopInbound(config, [populated]);
        config.inbounds.push({ tag: 'independent-in', protocol: 'socks', port: 27000, settings: { auth: 'noauth' } });
        config.outbounds.push({ tag: 'independent-out', protocol: 'blackhole' });
        config.routing.rules.push({ type: 'field', inboundTag: ['independent-in'], outboundTag: 'independent-out' });
        config.policy = { levels: { 0: { statsUserUplink: true } } };
        node.profileConfig = JSON.stringify(config, null, 2) + '\n';
    }
    return { nodes, links: [link], groups: [] };
}
function fixture(descriptor = topology()) {
    const connection = mongoose.createConnection();
    const session = { inTransaction: () => true, client: connection.getClient() };
    const events = [], inventories = new Map();
    let held = false, confirmationFault;
    function model(name, source, initial = []) {
        const schema = source.schema.clone(); schema.set('autoCreate', false); schema.set('autoIndex', false);
        const Model = connection.model(`B1${name}`, schema, name);
        const rows = initial.map(bson); inventories.set(name, rows);
        const project = (row, options) => {
            if (!row) return null;
            const result = bson(row);
            // Real Mongoose creates these projections, including select:false.
            // Other inclusion projections are unnecessary for this bounded path;
            // retain full internal row but enforce all schema-private exclusions.
            for (const [key, path] of Object.entries(schema.paths)) if (path.options.select === false
                && options.projection?.[key] === 0) delete result[key];
            return result;
        };
        const record = (method, filter, options = {}, update) => {
            events.push({ name, method, filter: bson(filter || {}), options: { ...options }, ...(update ? { update: bson(update) } : {}), held });
        };
        const updateRow = (row, update) => {
            for (const [key, value] of Object.entries(update.$set || {})) row[key] = bson({ value }).value;
            for (const key of Object.keys(update.$unset || {})) delete row[key];
            for (const [key, value] of Object.entries(update.$inc || {})) row[key] = (row[key] || 0) + value;
        };
        Model.collection.buffer = false;
        Model.collection.collection = {
            async indexes() { return schema.indexes().map(([key, options]) => ({ key, ...options })); },
            async insertOne(doc, options) { record('insertOne', {}, options); rows.push(bson(doc)); return { acknowledged: true, insertedId: doc._id }; },
            async findOne(filter, options) {
                record('findOne', filter, options);
                const row = rows.find(sift(filter));
                const result = project(row, options);
                if (confirmationFault && name === 'Owner' && filter.owner === 'topology' && !options.session) confirmationFault(result);
                return result;
            },
            find(filter, options) { record('find', filter, options); return { toArray: async () => rows.filter(sift(filter)).map(row => project(row, options)) }; },
            async findOneAndUpdate(filter, update, options) {
                record('findOneAndUpdate', filter, options, update);
                // Sift does not compare Dates nested inside an equality
                // document faithfully. Mongo's whole-document equality is exact;
                // retain that boundary after the actual Mongoose/BSON casting.
                const { isDeepStrictEqual } = require('node:util');
                const native = bson(filter);
                const row = rows.find(value => Object.entries(native).every(([key, expected]) =>
                    key.startsWith('$') || key.includes('.') || expected && typeof expected === 'object'
                        && Object.keys(expected).some(field => field.startsWith('$'))
                        ? sift({ [key]: expected })(value) : isDeepStrictEqual(value[key], expected)));
                if (!row) return null;
                const before = bson(row); updateRow(row, update);
                return project(options.returnDocument === 'after' ? row : before, options);
            },
            async updateOne(filter, update, options) {
                record('updateOne', filter, options, update);
                const row = rows.find(sift(filter)); if (row) updateRow(row, update);
                return { acknowledged: true, matchedCount: row ? 1 : 0, modifiedCount: row ? 1 : 0 };
            },
        };
        return Model;
    }
    connection.transaction = async (work, options) => {
        const saved = new Map([...inventories].map(([name, rows]) => [name, rows.map(bson)]));
        events.push({ method: 'transaction', options, held });
        try { return await work(session); }
        catch (error) { for (const [name, rows] of inventories) rows.splice(0, rows.length, ...saved.get(name)); throw error; }
    };
    const Owner = model('Owner', require('../../../models/topologyConfigOwnerModel'));
    const Operation = model('Operation', require('../models/topologyOperationModel'));
    const State = model('State', require('../models/cascadeTopologyStateModel'), [{ _id: 'singleton', revision: 7, deployedRevision: 0,
        topologyAdmissionCount: 0, remoteAdmissionCount: 0 }]);
    const Lock = model('Lock', require('../models/nodeOperationLockModel'));
    const HyNode = model('HyNode', require('../../../models/hyNodeModel'), descriptor.nodes.map(({ id: _id, role: cascadeRole, profileConfig, ...rest }) =>
        ({ ...rest, _id: new mongoose.Types.ObjectId(_id), cascadeRole })));
    const CascadeLink = model('CascadeLink', require('../../../models/cascadeLinkModel'), descriptor.links.map(({ id: _id, source, target, ...rest }) =>
        ({ ...rest, _id: new mongoose.Types.ObjectId(_id), portalNode: new mongoose.Types.ObjectId(source), bridgeNode: new mongoose.Types.ObjectId(target), status: 'online' })));
    const emptyModel = { db: connection };
    const snapshotReader = { HyNode, CascadeLink, CascadeRouteGroup: emptyModel, RelayL2tpState: emptyModel,
        readDraft: async () => ({ revision: 7, deployedRevision: 0, nodes: inventories.get('HyNode').map(bson),
            links: inventories.get('CascadeLink').map(bson), groups: [] }) };
    const repository = new TopologyDeploymentRepository({ snapshotReader, CascadeTopologyState: State, TopologyConfigOwner: Owner,
        TopologyOperation: Operation, NodeOperationLock: Lock, transactionRunner: work => connection.transaction(work) });
    const physical = new Map(descriptor.nodes.flatMap(node => [
        [`${node.id}:xray-main`, { config: node.profileConfig, unit: `modeled-main-${node.id}`, active: 'active', enabled: 'enabled' }],
        [`${node.id}:xray-bridge`, { config: JSON.stringify({ inbounds: [{ tag: 'independent-sidecar', port: 29000 }], outbounds: [{ tag: 'direct', protocol: 'freedom' }] }),
            unit: `modeled-sidecar-${node.id}`, active: 'active', enabled: 'enabled' }],
    ]));
    const transfer = new TopologyConfigTransfer({ executionContext: TEST, TopologyConfigOwner: Owner,
        async withVerifiedMaintenance({ binding }, work) {
            held = true;
            const observed = physical.get(`${binding.node}:${binding.profile}`);
            try {
                await work({ status: 'verified', authority: 'external-maintenance-v1', binding: copy(binding),
                    proofId: randomUUID(), maintenanceId: randomUUID(), maintenance: 'held', allWriters: 'drained',
                    oldBackend: { instanceId: 'modeled-classic', pid: 42, processStartTime: 'modeled-start', processTree: 'stopped', dispatch: 'disabled' },
                    readback: { source: 'node-readback', configSha256: sha(observed.config), unitSha256: sha(observed.unit),
                        serviceActive: observed.active, serviceEnabled: observed.enabled } });
            } finally { held = false; }
        } });
    const initialize = node => transfer.initializeClassic({ node: node.id, profile: 'xray-main',
        nodeIdentity: { machineId: String(descriptor.nodes.indexOf(node) + 1).repeat(32), sshHostKeySha256: String(descriptor.nodes.indexOf(node) + 1).repeat(64) } });
    const adopt = async (node, legacyTopology = descriptor) => {
        const classic = await initialize(node);
        assert.equal(classic.profileTargetPin, undefined); assert.equal(classic.legacyAppliedTopology, undefined);
        return transfer.adopt({ node: node.id, profile: 'xray-main', generation: classic.generation, proofRef: 'modeled-held-readback', legacyTopology });
    };
    const read = () => repository.readSelected({ scope: { kind: 'link.apply', linkId: id(10) }, executionContext: TEST });
    const coordinator = new TopologyOperationCoordinator({ topologyRepository: repository,
        operationRepository: new TopologyOperationRepository({ model: Operation }),
        planMaterializer: new TopologyOperationPlanMaterializer({ HyNode: { find() { assert.fail('no mutable hydration'); } },
            CascadeLink: { find() { assert.fail('no mutable hydration'); } } }), executionContext: TEST, idFactory: () => id(70) });
    return { descriptor, Owner, Operation, transfer, repository, physical, inventories, events, initialize, adopt, read, coordinator,
        fault: fn => { confirmationFault = fn; } };
}
for (const security of ['none', 'reality']) test(`public ${security}: adoption atomically pins both MAIN roots and reaches real selected durable composition`, async () => {
    const f = fixture(topology(security)), original = copy(f.descriptor), physical = copy([...f.physical]);
    for (const node of f.descriptor.nodes) await f.adopt(node);
    const owners = await f.Owner.find().select('+legacyAppliedTopology +profileTargetPin').lean();
    for (const owner of owners) {
        assert.ok(owner.node instanceof mongoose.Types.ObjectId);
        assert.ok(owner.adoptionReceipt.verifiedAt instanceof Date);
        assert.deepEqual(owner.legacyAppliedTopology, original);
        assert.deepEqual(verifyImportedProfileTargetPin({ owner, profileTargetPin: owner.profileTargetPin, executionContext: TEST }), owner.profileTargetPin);
        assert.equal(owner.profileTargetPin.ownerGeneration, owner.generation);
    }
    const writes = f.events.filter(event => event.name === 'Owner' && event.method === 'findOneAndUpdate');
    assert.equal(writes.length, 2);
    for (const event of writes) {
        assert.equal(event.held, true); assert.equal(event.options.runValidators, true);
        assert.ok(event.options.session);
        for (const key of ['profileTargetPin', 'legacyAppliedTopology', 'originalSnapshot', 'adoptionReceipt', 'generation', 'owner']) assert.ok(Object.hasOwn(event.update.$set, key));
    }
    const confirmations = f.events.filter(event => event.name === 'Owner' && event.method === 'findOne' && event.filter.owner === 'topology');
    assert.equal(confirmations.length, 2);
    for (const event of confirmations) {
        assert.equal(event.held, true); assert.deepEqual(event.options.readConcern, { level: 'majority' });
        assert.equal(event.options.readPreference.mode, 'primary');
        assert.notEqual(event.options.projection?.legacyAppliedTopology, 0);
        assert.notEqual(event.options.projection?.profileTargetPin, 0);
    }
    const selected = await f.read(); assert.deepEqual(selected.baselineTopology, original);
    const queued = await f.coordinator.queue({ expectedTopologyRevision: 7, scope: { kind: 'link.apply', linkId: id(10), linkIds: [id(10)] } });
    assert.equal(queued.status, 'queued');
    const durable = await f.Operation.findById(queued.operationId).select('+admissionScope +resourceNodeIds +desiredVersion +selectedOwnerPins +baselineTopology +effectiveTopology').lean();
    assert.equal(durable.admissionFingerprint, selectedAdmissionFingerprint(durable));
    assert.equal(durable.nodes.length, 2); assert.equal(new Set(durable.nodes.map(node => String(node.node))).size, 2);
    for (const node of original.nodes) {
        const entry = durable.nodes.find(entry => String(entry.node) === node.id);
        assert.equal(entry.role, node.role); assert.equal(entry.targetProfile, 'xray-main');
        assert.deepEqual(entry.profileTargetPin, owners.find(owner => String(owner.node) === node.id).profileTargetPin);
        assert.deepEqual(JSON.parse(Buffer.from(entry.candidate.bytes)), JSON.parse(node.profileConfig), 'first apply keeps all clients, unrelated fragments, UUID/keys/port');
    }
    assert.ok(durable.nodes.find(node => node.role === 'bridge').checks.some(check => check.type === 'port' && check.expectedState === 'listening'));
    const replay = composeFrozenTopologyDeploymentPlan({ snapshot: selected.effectiveTopology, baselineTopology: selected.baselineTopology,
        selectedOwnerPins: selected.selectedOwnerPins, compiledTopology: compileTopology(selected.effectiveTopology) });
    for (const entry of durable.nodes) assert.deepEqual(entry.candidate.bytes, replay.nodes.find(node => node.node === String(entry.node)).candidate.bytes);
    assert.deepEqual([...f.physical], physical, 'MODELED main/sidecar bytes/unit/state unchanged: no upload exists here');
    assert.equal(f.inventories.get('Operation').length, 1);
    assert.equal(durable.status, 'queued', 'no worker/finalizer success fabricated');
    const publicView = JSON.stringify(projectTopologyOperationStatus(durable));
    for (const key of ['profileTargetPin', 'legacyAppliedTopology', 'selectedOwnerPins', 'candidate', 'baselineTopology']) assert.equal(publicView.includes(`"${key}"`), false);
    assert.equal((await f.Owner.findOne()).profileTargetPin, undefined, 'actual default query keeps pin private');
});
for (const [security, clientSecurity] of [['none', 'reality'], ['reality', 'none']]) test(`public tunnel ${security} independently supports MAIN client ${clientSecurity}`, async () => {
    const f = fixture(topology(security, clientSecurity));
    for (const node of f.descriptor.nodes) await f.adopt(node);
    assert.deepEqual((await f.read()).baselineTopology, f.descriptor);
});
test('forward descriptor verification checks peer completeness and returns exact accepted bytes/defaults', () => {
    const descriptor = topology(); descriptor.links[0].status = 'online';
    for (const node of descriptor.nodes) {
        assert.deepEqual(verifyLegacyAppliedProfile(descriptor, { node: node.id, profile: 'xray-main', originalSnapshot: { configSha256: sha(node.profileConfig) } }), descriptor);
        const artifacts = legacyProfileArtifacts(descriptor, node.id);
        assert.equal(artifacts.inbounds.some(row => row.tag === 'client-in'), false, 'MAIN base is never owned tunnel delta');
    }
    const broken = copy(descriptor), peer = broken.nodes[1];
    const config = JSON.parse(peer.profileConfig); config.inbounds = config.inbounds.filter(row => !row.tag.startsWith('fwd-'));
    peer.profileConfig = JSON.stringify(config);
    assert.throws(() => verifyLegacyAppliedProfile(broken, { node: descriptor.nodes[0].id, profile: 'xray-main',
        originalSnapshot: { configSha256: sha(descriptor.nodes[0].profileConfig) } }), { code: 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH' });
});
for (const [name, mutate] of [
    ['missing pin', row => { delete row.profileTargetPin; }], ['malformed pin', row => { row.profileTargetPin = null; }],
    ['snapshot drift', row => { row.originalSnapshot.unitSha256 = 'f'.repeat(64); }],
    ['receipt drift', row => { row.adoptionReceipt.oldPid++; }],
    ['generation drift', row => { row.generation = randomUUID(); }],
    ['descriptor mismatch', row => { row.legacyAppliedTopology.links[0].priority = 9; }],
]) test(`publicly produced root refuses ${name} on selected read without operation creation`, async () => {
    const f = fixture(); for (const node of f.descriptor.nodes) await f.adopt(node);
    mutate(f.inventories.get('Owner')[0]);
    await assert.rejects(f.read(), { code: 'TOPOLOGY_LEGACY_IMPORT_MISMATCH' });
    assert.equal(f.inventories.get('Operation').length, 0);
});
test('partial public adoption has no applied authority; generic Bridge MAIN never substitutes for a pin', async () => {
    const f = fixture(); await f.adopt(f.descriptor.nodes[0]);
    await assert.rejects(f.read());
    const bridge = f.descriptor.nodes[1], classic = await f.initialize(bridge);
    await f.transfer.adopt({ node: bridge.id, profile: 'xray-main', generation: classic.generation, proofRef: 'modeled-generic' });
    assert.equal(f.inventories.get('Owner')[1].profileTargetPin, undefined);
    await assert.rejects(f.read());
    assert.equal(f.inventories.get('Operation').length, 0);
});
for (const [name, mutate, code] of [
    ['TLS tunnel', t => { t.links[0].tunnelSecurity = 'tls'; }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
    ['empty protocol', t => { t.links[0].tunnelProtocol = ''; }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
    ['wrong protocol', t => { t.links[0].tunnelProtocol = 'vmess'; }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
    ['empty transport', t => { t.links[0].tunnelTransport = ''; }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
    ['wrong transport', t => { t.links[0].tunnelTransport = 'ws'; }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
    ['TLS MAIN client', t => { t.nodes[1].xray.security = 'tls'; }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
    ['groups', t => { t.groups.push({ _id: id(20), paths: [] }); }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
    ['mixed layout', t => { t.links.push({ ...t.links[0], id: id(20), mode: 'reverse' }); }, 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED'],
    ['wrong UUID', t => { t.links[0].tunnelUuid = randomUUID(); }, 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH'],
]) test(`public forward import refuses ${name}`, async () => {
    const f = fixture(), bad = copy(f.descriptor); mutate(bad);
    await assert.rejects(f.adopt(f.descriptor.nodes[0], bad), { code });
    assert.equal(f.inventories.get('Owner')[0].owner, 'classic');
});
for (const [name, mutate] of [
    ['missing listener', c => { c.inbounds = c.inbounds.filter(row => !row.tag.startsWith('fwd-')); }],
    ['duplicate listener', c => { c.inbounds.push(copy(c.inbounds.find(row => row.tag.startsWith('fwd-')))); }],
    ['foreign reserved route', c => { c.routing.rules.push({ type: 'field', inboundTag: ['fwd-hop-foreign'], outboundTag: 'direct' }); }],
    ['reverse artifact', c => { c.reverse = { portals: [{ tag: 'foreign', domain: 'foreign.invalid' }] }; }],
    ['client key mismatch', c => { c.inbounds.find(row => row.tag === 'client-in').streamSettings.security = 'reality'; }],
]) test(`forward readback with ${name} cannot publish a pin`, async () => {
    const descriptor = topology(), bridge = descriptor.nodes[1], config = JSON.parse(bridge.profileConfig); mutate(config);
    bridge.profileConfig = JSON.stringify(config);
    const f = fixture(descriptor);
    await assert.rejects(f.adopt(bridge), { code: 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH' });
    assert.equal(f.inventories.get('Owner')[0].profileTargetPin, undefined);
});
test('checked client and tunnel REALITY metadata cannot omit their actual private keys', async () => {
    for (const change of [t => { delete t.nodes[1].xray.realityPrivateKey; }, t => { delete t.links[0].realityPrivateKey; },
        t => { delete t.links[0].realityPublicKey; }]) {
        const descriptor = topology('reality'); change(descriptor);
        // Regenerate missing-key bytes faithfully, not a descriptor/readback
        // mismatch that would conceal a permissive generator default.
        const populated = { ...descriptor.links[0], _id: id(10), portalNode: descriptor.nodes[0], bridgeNode: descriptor.nodes[1] };
        for (const node of descriptor.nodes) {
            const config = JSON.parse(generator.generateXrayConfig(node, []));
            if (node.role === 'portal') generator.applyForwardChain(config, [populated], ['client-in']);
            else generator.applyForwardHopInbound(config, [populated]);
            node.profileConfig = JSON.stringify(config);
        }
        const f = fixture(descriptor);
        await assert.rejects(f.adopt(descriptor.nodes[0]), { code: 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH' });
        assert.equal(f.inventories.get('Owner')[0].owner, 'classic');
    }
});
test('ordered generated forward rules cannot be reordered, removed or duplicated', () => {
    const descriptor = topology('none', 'none', { geoRouting: { enabled: true, domains: ['example'], geoip: ['us'] } });
    const portal = descriptor.nodes[0], observed = { node: portal.id, profile: 'xray-main', originalSnapshot: { configSha256: sha(portal.profileConfig) } };
    assert.deepEqual(verifyLegacyAppliedProfile(descriptor, observed), descriptor);
    const owned = rule => rule.outboundTag?.startsWith('fwd-');
    assert.ok(JSON.parse(portal.profileConfig).routing.rules.filter(owned).length >= 2);
    for (const change of [rules => rules.reverse(), rules => rules.slice(1), rules => [...rules, copy(rules[0])]]) {
        const bad = copy(descriptor), config = JSON.parse(bad.nodes[0].profileConfig);
        config.routing.rules = [...config.routing.rules.filter(rule => !owned(rule)), ...change(config.routing.rules.filter(owned))];
        bad.nodes[0].profileConfig = JSON.stringify(config);
        assert.throws(() => verifyLegacyAppliedProfile(bad, { ...observed, originalSnapshot: { configSha256: sha(bad.nodes[0].profileConfig) } }),
            { code: 'CONFIG_LEGACY_IMPORT_PROFILE_MISMATCH' });
    }
});
test('an already adopted generation cannot be repinned by replaying public adopt', async () => {
    const f = fixture(), node = f.descriptor.nodes[0];
    const classic = await f.initialize(node), request = { node: node.id, profile: 'xray-main', generation: classic.generation,
        proofRef: 'modeled-held-readback', legacyTopology: f.descriptor };
    await f.transfer.adopt(request);
    const rows = f.inventories.get('Owner').map(bson), count = f.events.filter(event => event.method === 'findOneAndUpdate').length;
    await assert.rejects(f.transfer.adopt(request), { code: 'CONFIG_OWNERSHIP_CONFLICT' });
    assert.deepEqual(f.inventories.get('Owner'), rows);
    assert.equal(f.events.filter(event => event.method === 'findOneAndUpdate').length, count);
});
test('majority confirmation requalifies the full root and pin inside held adoption scope', async () => {
    for (const mutate of [row => { delete row.profileTargetPin; }, row => { row.originalSnapshot.unitSha256 = 'f'.repeat(64); },
        row => { row.profileTargetPin.ownerEvidenceSha256 = 'f'.repeat(64); }, row => { row.adoptionReceipt.oldPid++; }]) {
        const f = fixture(); f.fault(mutate);
        await assert.rejects(f.adopt(f.descriptor.nodes[0]), { code: 'CONFIG_TRANSFER_UNCONFIRMED' });
        assert.equal(f.inventories.get('Owner')[0].owner, 'topology', 'unknown confirmation does not undo committed ownership');
    }
});
test('handback keeps private pin history but a new generic adoption clears both stale private fields', async () => {
    const f = fixture(), node = f.descriptor.nodes[1]; await f.adopt(node);
    const prior = bson(f.inventories.get('Owner')[0]);
    const returned = await f.transfer.handback({ node: node.id, profile: 'xray-main', generation: prior.generation, proofRef: 'modeled-restored-original' });
    assert.equal(returned.profileTargetPin, undefined); assert.equal(returned.legacyAppliedTopology, undefined);
    const history = f.inventories.get('Owner')[0]; assert.deepEqual(history.profileTargetPin, prior.profileTargetPin);
    assert.throws(() => projectImportedProfileTargetPin(history));
    await f.transfer.adopt({ node: node.id, profile: 'xray-main', generation: returned.generation, proofRef: 'modeled-generic' });
    assert.equal(history.profileTargetPin, undefined); assert.equal(history.legacyAppliedTopology, undefined);
    await assert.rejects(f.read());
});
