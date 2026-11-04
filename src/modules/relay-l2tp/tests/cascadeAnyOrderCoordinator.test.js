'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { TopologyOperationCoordinator } = require('../services/topologyOperationCoordinator');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const TopologyOperation = require('../models/topologyOperationModel');

const id = value => value.toString(16).padStart(24, '0');
const ids = { p: id(1), r: id(2), b1: id(3), b2: id(4), other: id(5), pr: id(11), rb1: id(12), rb2: id(13), pending: id(14) };
const session = { inTransaction: () => true };
const context = { target: 'test', hostIdentity: 'test.infograd.online' };

function fixture(modes = ['reverse', 'forward', 'reverse']) {
    const nodes = [['p', 'portal'], ['r', 'relay'], ['b1', 'bridge'], ['b2', 'bridge'], ['other', 'bridge']]
        .map(([name, role], index) => ({
            _id: ids[name], cascadeRole: role, type: 'xray', active: true,
            ip: `192.0.2.${index + 1}`, port: 24001 + index,
            xray: { inboundTag: `client-${name}`, transport: 'tcp', security: 'none', extraInbounds: [] },
        }));
    const links = [['pr', 'p', 'r'], ['rb1', 'r', 'b1'], ['rb2', 'r', 'b2'], ['pending', 'r', 'other']]
        .map(([name, source, target], index) => ({
            _id: ids[name], portalNode: ids[source], bridgeNode: ids[target], active: true,
            mode: modes[index] || 'reverse', status: 'pending', tunnelPort: 12001 + index,
            tunnelSecurity: 'none', tunnelTransport: 'tcp',
            ...(name === 'rb2' ? { geoRouting: { enabled: true, geoip: ['ru'], domains: [] } } : {}),
        }));
    return { revision: 7, deployedRevision: 5, nodes, links, groups: [] };
}

function setup(snapshot, { mutatePlan = plan => plan } = {}) {
    const saved = [];
    const reads = [];
    const model = rows => ({
        find(filter) {
            reads.push(structuredClone(filter));
            return {
                select() { return this; }, session(actual) { assert.equal(actual, session); return this; },
                async lean() { return structuredClone(rows.filter(row => filter._id.$in.includes(row._id)
                    && row.active === true && (!filter.type || row.type === filter.type))); },
            };
        },
    });
    const repository = new TopologyOperationRepository({ model: {
        async create(documents, options) {
            assert.equal(options.session, session);
            const document = new TopologyOperation(documents[0]);
            await document.validate();
            // Real schema + BSON serializer/deserializer, no MongoDB claims.
            const bson = require('mongoose').mongo.BSON;
            const stored = bson.deserialize(bson.serialize(document.toObject()));
            saved.push(stored);
            return [TopologyOperation.hydrate(stored)];
        },
        findOneAndUpdate() {}, updateOne() {},
    } });
    const materializer = new TopologyOperationPlanMaterializer({ HyNode: model(snapshot.nodes), CascadeLink: model(snapshot.links) });
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: {
            async admitTopology({ expectedRevision, prepare, admit }) {
                assert.equal(expectedRevision, snapshot.revision);
                const pinned = { revision: snapshot.revision, deployedRevision: snapshot.deployedRevision,
                    ...await prepare(snapshot, session) };
                await admit(pinned, session);
                return pinned;
            },
        },
        planMaterializer: { async materialize(input) { return mutatePlan(await materializer.materialize(input)); } },
        operationRepository: repository,
    });
    return { coordinator, repository, saved, reads };
}

function selectedSnapshots() {
    const snapshot = fixture();
    const node = name => {
        const raw = snapshot.nodes.find(row => row._id === ids[name]);
        const { _id, cascadeRole, ...metadata } = raw;
        return { id: _id, role: cascadeRole, ...metadata };
    };
    const link = name => {
        const raw = snapshot.links.find(row => row._id === ids[name]);
        const { _id, portalNode, bridgeNode, active, status, ...metadata } = raw;
        return { id: _id, source: portalNode, target: bridgeNode, ...metadata };
    };
    const baselineTopology = { nodes: ['r', 'b1'].map(node), links: [link('rb1')], groups: [] };
    const effectiveTopology = { nodes: ['p', 'r', 'b1'].map(node), links: [link('pr'), link('rb1')], groups: [] };
    return { baselineTopology, effectiveTopology, resourceNodeIds: [ids.p, ids.r, ids.b1] };
}

async function frozenInput() {
    const snapshot = fixture();
    snapshot.links.find(link => link._id === ids.rb1).status = 'staged';
    const { coordinator, saved } = setup(snapshot);
    await coordinator.queue({ expectedTopologyRevision: 7,
        scope: { kind: 'link.apply', linkId: ids.pr, linkIds: [ids.pr, ids.rb1] } });
    const document = saved[0];
    // Reconstruct only the public repository input metadata; the candidates
    // were generated through the actual coordinator/materializer above.
    const target = require('../services/frozenTopologyDeploymentPlanComposer').TARGETS_BY_ROLE;
    return {
        operationId: id(99), executionContext: context,
        idempotencyKey: 'topology:test:revision-7:link.apply:fixture:host-test.infograd.online:11111111-2222-4333-8444-555555555555',
        topologyRevision: 7, priorDeployedRevision: 5,
        kind: 'link.apply', linkId: ids.pr, linkIds: [ids.pr, ids.rb1], staged: false,
        heldTopologyAdmission: true, admissionFingerprint: 'a'.repeat(64), session,
        nodes: document.nodes.map(node => ({ ...node, node: String(node.node), ...target[node.role] })),
    };
}

function permutations(values) {
    return values.length ? values.flatMap((value, index) =>
        permutations(values.filter((_, other) => index !== other)).map(rest => [value, ...rest])) : [[]];
}

// This simulates already-settled legacy status inputs between queue calls; it
// does not claim worker execution, selected admission or applied publication.
for (const [graph, keys] of [['G2', ['pr', 'rb1']], ['G3', ['pr', 'rb1', 'rb2']]]) {
    for (const modes of [['reverse', 'forward', 'reverse'], ['forward', 'reverse', 'forward']]) {
        for (const order of permutations(keys)) {
            test(`${graph} coordinator assembly ${order.join(';')} ${modes.join('/')} excludes unrelated pending`, async () => {
                const snapshot = fixture(modes);
                const { coordinator, saved, reads } = setup(snapshot);
                const seen = [];
                for (const key of order) {
                    seen.push(ids[key]);
                    const result = await coordinator.queue({ expectedTopologyRevision: snapshot.revision,
                        scope: { kind: 'link.apply', linkId: ids[key], linkIds: [...seen] } });
                    const incomplete = !seen.includes(ids.pr) || !seen.includes(ids.rb1);
                    assert.equal(result.staged, incomplete);
                    const persisted = saved.at(-1);
                    assert.equal(persisted.admissionScope, undefined, 'do not opt into the incomplete selected protocol');
                    const roles = Object.fromEntries(persisted.nodes.map(node => [String(node.node), node.role]));
                    for (const link of snapshot.links.filter(link => seen.includes(link._id))) {
                        assert.ok(roles[link.portalNode]);
                        assert.ok(roles[link.bridgeNode]);
                    }
                    const candidates = persisted.nodes.map(node => JSON.parse(Buffer.from(node.candidate.bytes)));
                    assert.equal(JSON.stringify(candidates).includes('12004'), false);
                    for (const link of snapshot.links.filter(link => seen.includes(link._id))) {
                        const listeners = candidates.flatMap(config => config.inbounds)
                            .filter(inbound => inbound.port === link.tunnelPort);
                        assert.equal(listeners.length, 1);
                        const listenerId = link.mode === 'reverse' ? link.portalNode : link.bridgeNode;
                        const listener = persisted.nodes.find(node => String(node.node) === listenerId);
                        assert.ok(listener.checks.some(check => check.type === 'port' && check.port === link.tunnelPort));
                    }
                    for (const link of snapshot.links.filter(link => seen.includes(link._id))) {
                        link.status = incomplete ? 'staged' : 'deployed';
                    }
                    snapshot.revision += 1;
                }
                assert.equal(reads.some(filter => filter._id.$in.includes(ids.pending) || filter._id.$in.includes(ids.other)), false);
                assert.deepEqual(saved.at(-1).linkIds.sort(), keys.map(key => ids[key]).sort());
            });
        }
    }
}

test('source-less G3 binds real materializer candidates to physical nodes through the coordinator', async () => {
    const snapshot = fixture();
    snapshot.links.find(link => link._id === ids.rb1).status = 'staged';
    const { coordinator, saved } = setup(snapshot);
    const queued = await coordinator.queue({ expectedTopologyRevision: 7,
        scope: { kind: 'link.apply', linkId: ids.rb2, linkIds: [ids.rb1, ids.rb2] } });
    assert.equal(queued.staged, true);
    assert.deepEqual(Object.fromEntries(saved[0].nodes.map(node => [node.nodeRef, String(node.node)])), {
        'bridge': ids.b1, 'bridge-2': ids.b2, 'relay-1': ids.r,
    });
});

test('effective selector preserves verified applied descriptors across save-only edits and ignores pending neighbors', () => {
    const { selectEffectiveTopology } = require('../services/topologyOperationCoordinator');
    const { baselineTopology, effectiveTopology: desiredTopology } = selectedSnapshots();
    const desired = structuredClone(desiredTopology);
    const baseline = structuredClone(baselineTopology);
    desired.links.find(link => link.id === ids.rb1).mode = 'reverse';
    desired.links.find(link => link.id === ids.rb1).tunnelPort = 65000;
    desired.nodes.find(node => node.id === ids.r).xray.inboundTag = 'saved-only-edit';
    desired.nodes.push({ ...desired.nodes[2], id: ids.other });
    desired.links.push({ ...desired.links[1], id: ids.pending, target: ids.other, tunnelPort: 12999 });
    const result = selectEffectiveTopology({ verifiedBaselineTopology: baseline,
        desiredTopology: desired, scope: { kind: 'link.apply', linkId: ids.pr, linkIds: [ids.pr] } });
    assert.deepEqual(result.baselineTopology, baselineTopology);
    assert.deepEqual(result.effectiveTopology.links.find(link => link.id === ids.rb1), baseline.links[0]);
    assert.equal(result.effectiveTopology.nodes.find(node => node.id === ids.r).xray.inboundTag, 'client-r');
    assert.deepEqual(result.effectiveTopology.links.map(link => link.id).sort(), [ids.pr, ids.rb1]);
    assert.deepEqual(result.resourceNodeIds, [ids.p, ids.r, ids.b1]);
    assert.equal(result.routeState, 'complete');
    assert.deepEqual(result.affectedGroupIds, []);
    assert.ok(Object.isFrozen(result.effectiveTopology.links[0]));
    assert.equal(desired.links.find(link => link.id === ids.rb1).tunnelPort, 65000);
    assert.deepEqual(baseline, baselineTopology);
    assert.throws(() => selectEffectiveTopology({ desiredTopology: desired,
        scope: { kind: 'link.apply', linkId: ids.pr, linkIds: [ids.pr] } }), { code: 'APPLIED_BASELINE_REQUIRED' });
});

test('effective selector reports missing portal/exit honestly and never fabricates an empty baseline', () => {
    const { selectEffectiveTopology } = require('../services/topologyOperationCoordinator');
    const { effectiveTopology: desired } = selectedSnapshots();
    // Explicit simulated verified absence, not an imported legacy snapshot.
    const verifiedBaselineTopology = { nodes: [], links: [], groups: [] };
    for (const [linkId, routeState] of [[ids.pr, 'no_bridge_exit'], [ids.rb1, 'no_portal_input']]) {
        const result = selectEffectiveTopology({ verifiedBaselineTopology, desiredTopology: desired,
            scope: { kind: 'link.apply', linkId } });
        assert.equal(result.routeState, routeState);
        assert.deepEqual(result.baselineTopology, verifiedBaselineTopology);
        assert.deepEqual(result.effectiveTopology.links.map(link => link.id), [linkId]);
    }
});

test('selected worker claims are enabled while unintegrated selected client-proof scheduling stays disabled', async () => {
    const claims = [];
    const repository = new TopologyOperationRepository({ model: {
        create() {}, updateOne() {},
        async findOneAndUpdate(filter) { claims.push(filter); return null; },
    } });
    await repository.claim({ operationId: id(99), owner: 'local-worker', leaseMs: 30000,
        now: new Date('2026-01-01T00:00:00Z'), executionContext: context });
    await repository.claimNextClientProof({ owner: 'local-proof', now: new Date('2026-01-01T00:00:00Z'), executionContext: context });
    assert.equal(claims.length, 3);
    for (const filter of claims.slice(0, 2)) assert.deepEqual(filter.admissionScope, { $in: [null, 'selected'] });
    assert.deepEqual(claims[2].admissionScope, { $exists: false });
});

test('selected snapshot writes reject partial identities, missing endpoints and narrowed resource unions before insert', async () => {
    const input = await frozenInput();
    const invalid = [
        value => { delete value.admissionScope; },
        value => { delete value.baselineTopology; },
        value => { value.resourceNodeIds = [ids.p, ids.r]; },
        value => { value.resourceNodeIds.push(ids.other); },
        value => { value.effectiveTopology.links.push(value.effectiveTopology.links[0]); },
        value => { value.effectiveTopology.links.pop(); },
        value => { value.effectiveTopology.nodes = value.effectiveTopology.nodes.filter(node => node.id !== ids.b1); },
        value => { value.admissionScope = 'global'; },
    ];
    let writes = 0;
    const repository = new TopologyOperationRepository({ model: {
        async create() { writes += 1; assert.fail('malformed snapshots cannot be written'); },
        findOneAndUpdate() {}, updateOne() {},
    } });
    for (const change of invalid) {
        const candidate = { ...input, admissionScope: 'selected', ...selectedSnapshots() };
        change(candidate);
        await assert.rejects(repository.createFrozen(candidate), /selected|snapshot|resource/i);
        const { session: ignored, ...fields } = candidate;
        await assert.rejects(new TopologyOperation({ ...fields, status: 'queued' }).validate(), /selected|snapshot|resource/i);
    }
    assert.equal(writes, 0);
});

test('effective selection retains old/new endpoint and route-group unions but does not adopt desired-only policy', () => {
    const { selectEffectiveTopology } = require('../services/topologyOperationCoordinator');
    const { effectiveTopology: baseline } = selectedSnapshots();
    baseline.groups = [{ _id: id(21), mode: 'reverse', strategy: 'priority-failover',
        paths: [{ pathKey: 'main', linkIds: [ids.pr, ids.rb1], priority: 1, enabled: true }] }];
    const desired = structuredClone(baseline);
    desired.nodes.push({ ...desired.nodes[2], id: ids.b2 });
    desired.links.find(link => link.id === ids.rb1).target = ids.b2;
    desired.groups[0].paths[0].priority = 99;
    desired.groups.push({ _id: id(22), mode: 'reverse', strategy: 'priority-failover', paths: [] });
    const result = selectEffectiveTopology({ verifiedBaselineTopology: baseline, desiredTopology: desired,
        scope: { kind: 'link.apply', linkId: ids.rb1 } });
    assert.deepEqual(result.resourceNodeIds, [ids.p, ids.r, ids.b1, ids.b2]);
    assert.deepEqual(result.affectedGroupIds, [id(21)]);
    assert.deepEqual(result.effectiveTopology.groups, baseline.groups);
    assert.equal(result.effectiveTopology.links.find(link => link.id === ids.rb1).target, ids.b2);
    assert.equal(result.baselineTopology.links.find(link => link.id === ids.rb1).target, ids.b1);
    assert.equal(result.effectiveTopology.nodes.some(node => node.id === ids.b1), false);
});

test('materialized physical identity handles source-less refs and refuses partial, foreign and duplicated bindings', () => {
    const { nodeIdsByRef } = require('../services/topologyOperationCoordinator');
    const topology = { nodes: [{ id: ids.r, role: 'relay' }, { id: ids.b1, role: 'bridge' }],
        links: [{ source: ids.r, target: ids.b1 }] };
    const nodes = [{ node: ids.r, nodeRef: 'relay-1', role: 'relay' },
        { node: ids.b1, nodeRef: 'bridge', role: 'bridge' }];
    assert.deepEqual([...nodeIdsByRef(topology, { nodes })], [['relay-1', ids.r], ['bridge', ids.b1]]);
    for (const edit of [
        value => { delete value[0].node; },
        value => { value[0].node = ids.other; },
        value => { value[0].nodeRef = 'portal'; },
        value => { value[0].nodeRef = 'relay-3'; },
        value => { value.push(value[0]); },
        value => { value.pop(); },
    ]) {
        const value = structuredClone(nodes);
        edit(value);
        assert.throws(() => nodeIdsByRef(topology, { nodes: value }), { code: 'INVALID_TOPOLOGY_DEPLOYMENT' });
    }
});

test('selected snapshots survive repository, real Mongoose schema and BSON round-trip without adopting legacy rows', async () => {
    const input = await frozenInput();
    const snapshots = selectedSnapshots();
    let stored;
    const repository = new TopologyOperationRepository({ model: {
        async create(documents) {
            const document = new TopologyOperation(documents[0]);
            await document.validate();
            const bson = require('mongoose').mongo.BSON;
            stored = bson.deserialize(bson.serialize(document.toObject()));
            return [TopologyOperation.hydrate(stored)];
        }, findOneAndUpdate() {}, updateOne() {},
    } });
    await repository.createFrozen({ ...input, admissionScope: 'selected', ...snapshots });
    assert.equal(stored.admissionScope, 'selected');
    assert.deepEqual(stored.resourceNodeIds, snapshots.resourceNodeIds);
    assert.deepEqual(stored.baselineTopology, snapshots.baselineTopology);
    assert.deepEqual(stored.effectiveTopology, snapshots.effectiveTopology);
    snapshots.effectiveTopology.links[0].tunnelPort = 65000;
    assert.equal(stored.effectiveTopology.links[0].tunnelPort, 12001);
    const legacy = new TopologyOperation({ topologyRevision: 1, priorDeployedRevision: 0, status: 'queued' });
    await legacy.validate();
    for (const field of ['admissionScope', 'resourceNodeIds', 'baselineTopology', 'effectiveTopology']) {
        assert.equal(legacy.toObject()[field], undefined);
        assert.equal(TopologyOperation.schema.path(field).options.select, false, `${field} is private`);
        assert.equal(TopologyOperation.schema.path(field).options.immutable, true, `${field} is frozen`);
        const projected = require('../services/topologyOperationCoordinator').projectTopologyOperationStatus(stored);
        assert.equal(Object.hasOwn(projected, field), false, `${field} is absent from public status`);
    }
});
