'use strict';
// Retained no-pin negative controls, NOT the old cross-profile migration goal.
// Real public producer/worker/settlement positives live in the Mongo suite.
// Diagnostic proposed nodes below are NOT imported/dispatch authority.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const { forwardFixture, context, id, key, copy, model, targets, freeze, candidate } = require('./cascadeAnyOrderLegacyForwardFixture');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const { TopologyOperationPlanMaterializer } = require('../services/topologyOperationPlanMaterializer');
const { composeFrozenTopologyDeploymentPlan } = require('../services/frozenTopologyDeploymentPlanComposer');
const { compileTopology } = require('../domain/topologyCompiler');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');
const { TopologyOperationExecutor } = require('../services/topologyOperationExecutor');
const { durablePlan } = require('../workers/topologyOperationWorker');
const { TopologyExecutionBindingStore } = require('../repositories/topologyExecutionBindingStore');

function selectedRepository(f, onOwnerRead = () => {}) {
    const nodes = f.nodes.map(({ id, role, profileConfig, ...fields }) => ({ ...copy(fields), _id: id, cascadeRole: role }));
    const { id: linkId, source, target, ...fields } = f.link;
    const Owner = { ...f.Owner, find(filter) { onOwnerRead(); return f.Owner.find(filter); } };
    return new TopologyDeploymentRepository({ snapshotReader: {
        HyNode: model(nodes, f.db),
        CascadeLink: model([{ ...copy(fields), _id: linkId, portalNode: source, bridgeNode: target }], f.db),
        readDraft: async () => ({}) },
    CascadeTopologyState: model([{ _id: 'singleton', revision: 7 }], f.db),
    TopologyOperation: model([], f.db), TopologyConfigOwner: Owner, NodeOperationLock: {}, transactionRunner: f.db.transaction });
}
function materializer() {
    return new TopologyOperationPlanMaterializer({
        HyNode: { find() { assert.fail('descriptor conversion must not read mutable node metadata'); } },
        CascadeLink: { find() { assert.fail('descriptor conversion must not read mutable link metadata'); } } });
}
function convert(before, after = before) {
    return materializer().materialize({ ...context, operationKind: 'link.apply',
        pinnedSnapshot: { revision: 7, topology: after, compiled: compileTopology(after) },
        baselineTopology: before, effectiveTopology: after });
}
async function genericAdopt(f) {
    for (const node of f.nodes) for (const profile of ['xray-main', 'xray-bridge']) await f.adopt(node, profile);
    assert.ok(f.Owner.rows.every(owner => owner.legacyAppliedTopology === undefined
        && owner.lastSettledOperation === undefined), 'public generic adoption supplies no layout/terminal authority');
}
function nativePlan(f) {
    const snapshot = copy(f.topology);
    snapshot.nodes.forEach(node => delete node.profileConfig);
    return composeFrozenTopologyDeploymentPlan({ snapshot, nodeMetadata: snapshot.nodes, linkMetadata: snapshot.links,
        compiledTopology: compileTopology(snapshot), staged: true, hopByHop: true });
}
function projected(node) { return freeze({ ...copy(node), candidateHash: node.candidate.sha256 }); }
function proposedInPlaceBridge(f) {
    const native = nativePlan(f).nodes.find(node => node.role === 'bridge');
    // Identity/bytes come from the real installed classic generator, not an
    // invented cleanup or a sidecar→MAIN migration. Still only diagnostic data:
    // a generic adopted owner cannot authorize native conversion of this node.
    return projected({ ...native, ...targets['xray-main'], candidate: candidate(JSON.parse(f.nodes[1].profileConfig)),
        checks: [{ type: 'service', serviceUnit: 'xray.service', expectedState: 'active' },
            { type: 'port', protocol: 'tcp', port: f.link.tunnelPort, expectedState: 'listening' }] });
}
async function bindingBoundary(node) {
    const reads = [];
    const executor = new TopologyOperationExecutor({ ...context,
        nodeExecutionResolver: { resolve() { assert.fail('no credentials/transport in prerequisite probes'); } },
        executionBindingReader: { async readVerified(expected) {
            reads.push(copy(expected)); throw Error('MODELED_BINDING_BOUNDARY');
        } } });
    let error;
    try { await executor.prepare({ operationId: id(100), topologyRevision: 7, priorDeployedRevision: 6,
        executionFence: freeze({ owner: 'inplace-probe', attempt: 1, generation: randomUUID() }), node }); }
    catch (caught) { error = caught; }
    return { error, reads };
}

for (const security of ['none', 'reality']) {
    test(`no-pin ${security}: raw forward before-descriptor is not imported placement authority`, async () => {
        const f = forwardFixture(security); await genericAdopt(f);
        const original = copy([...f.physical]);
        await assert.rejects(convert(f.topology), { code: 'TOPOLOGY_PROFILE_BASELINE_MISMATCH' });
        assert.deepEqual([...f.physical], original);
    });
}

test('control: public generic MAIN adoption cannot make selected reader infer imported forward layout or use nonempty sidecar as baseline', async () => {
    const f = forwardFixture(); await genericAdopt(f);
    let reads = 0;
    await assert.rejects(selectedRepository(f, () => reads++).readSelected({ scope: { kind: 'link.apply', linkId: f.link.id }, executionContext: context }),
        { code: 'APPLIED_BASELINE_REQUIRED' });
    assert.equal(reads, 1);
    assert.equal(f.Owner.rows.length, 4);
    assert.ok(f.Owner.rows.every(owner => owner.lastSettledOperation === undefined));
});

test('control: native default placement survives repository → durable worker plan → typed executor binding boundary', async () => {
    const f = forwardFixture(); await genericAdopt(f);
    const nodes = nativePlan(f).nodes.map(projected);
    let created;
    const repository = new TopologyOperationRepository({ model: {
        async create(docs) { created = copy(docs[0]); return docs; }, async updateOne() {}, async findOneAndUpdate() {},
    } });
    await repository.createFrozen({ operationId: id(100), executionContext: context,
        idempotencyKey: `topology:test:revision-7:host-${context.hostIdentity}:${randomUUID()}`,
        topologyRevision: 7, priorDeployedRevision: 6, heldTopologyAdmission: true, admissionFingerprint: 'a'.repeat(64),
        nodes, session: f.session });
    const plan = durablePlan({ ...created, status: 'preparing' }, id(100));
    assert.deepEqual(plan.nodes.map(node => key(node.node, node.targetProfile)).sort(),
        [key(id(1), 'xray-main'), key(id(2), 'xray-bridge')]);
    const boundary = await bindingBoundary(plan.nodes.find(node => node.role === 'bridge'));
    assert.equal(boundary.error?.code, 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN');
    assert.equal(boundary.reads.length, 1);
    // No admitted/claimed operation is persisted by this diagnostic model.
});

test('control: an in-place MAIN target is still refused at repository, durable worker and executor before binding/dispatch', async () => {
    const f = forwardFixture(); await genericAdopt(f);
    const bridge = proposedInPlaceBridge(f), portal = nativePlan(f).nodes.find(node => node.role === 'portal');
    const nodes = [projected(portal), bridge];
    assert.equal(new Set(nodes.map(node => node.node)).size, nodes.length, 'NOT a duplicate-node/cross-profile refusal');
    assert.equal(bridge.role, 'bridge');
    let writes = 0;
    const repository = new TopologyOperationRepository({ model: {
        async create() { writes++; assert.fail('unsupported target must not persist'); }, async updateOne() {}, async findOneAndUpdate() {},
    } });
    await assert.rejects(repository.createFrozen({ operationId: id(100), executionContext: context,
        idempotencyKey: `topology:test:revision-7:host-${context.hostIdentity}:${randomUUID()}`,
        topologyRevision: 7, priorDeployedRevision: 6, nodes }), /requires bound node metadata/);
    assert.equal(writes, 0);
    assert.throws(() => durablePlan({ _id: id(100), status: 'preparing', topologyRevision: 7, priorDeployedRevision: 6,
        nodes: nodes.map(node => ({ ...copy(node), state: 'pending', backupId: '' })) }, id(100)), /Invalid durable topology candidate/);
    const boundary = await bindingBoundary(bridge);
    assert.equal(boundary.error?.code, 'INVALID_FROZEN_NODE_PLAN');
    assert.equal(boundary.reads.length, 0);
});

test('control: cross-profile execution and arbitrary target/layout overrides stay unsupported', async () => {
    const f = forwardFixture(); await genericAdopt(f);
    const native = nativePlan(f).nodes.map(projected), main = proposedInPlaceBridge(f);
    const operation = nodes => ({ _id: id(100), status: 'preparing', topologyRevision: 7, priorDeployedRevision: 6,
        nodes: nodes.map(node => ({ ...copy(node), state: 'pending', backupId: '' })) });
    assert.throws(() => durablePlan(operation([...native, main]), id(100)), /Invalid durable topology candidate/);
    assert.throws(() => durablePlan(operation([...native, native[0]]), id(100)), /Invalid durable topology operation/);
    for (const override of [{ profileLayout: 'legacy-forward-main' }, { importedOwner: copy(f.Owner.rows[0]) },
        { authorizedTarget: 'xray-main' }]) {
        const boundary = await bindingBoundary(freeze({ ...copy(main), ...override }));
        assert.equal(boundary.error?.code, 'INVALID_FROZEN_NODE_PLAN');
        assert.equal(boundary.reads.length, 0);
    }
});

// Finite MODELLED persistence probe of the ACTUAL store's preEnroll entry.
// Publicly produced owner rows are BSON-roundtripped through the real schema.
// No enrollment is inserted; the positive controls stop at insertMany. This is
// not Mongo atomicity/index/physical-authority evidence and creates no binding.
async function enrollmentBoundary(f, node, profile) {
    const mongoose = require('mongoose'), BSON = mongoose.mongo.BSON, ObjectId = mongoose.Types.ObjectId;
    const source = f.Owner.rows.find(row => row.node === node.id && row.profile === profile);
    const OwnerSchema = require('../../../models/topologyConfigOwnerModel');
    const document = new OwnerSchema(source); await document.validate();
    const owner = BSON.deserialize(BSON.serialize(document.toObject()));
    const endpoint = { ip: node.ip, port: 22, username: 'synthetic' };
    const nodeRow = { _id: new ObjectId(node.id), active: true, type: 'xray', cascadeRole: node.role,
        ip: endpoint.ip, ssh: { port: endpoint.port, username: endpoint.username } };
    const events = [];
    const get = (value, field) => field.split('.').reduce((at, key) => at?.[key], value);
    const type = value => value instanceof ObjectId ? 'objectId' : value instanceof Date ? 'date'
        : Array.isArray(value) ? 'array' : typeof value === 'number' ? 'double'
            : typeof value === 'boolean' ? 'bool' : typeof value === 'string' ? 'string'
                : value && typeof value === 'object' ? 'object' : 'missing';
    const eq = (a, b) => a instanceof ObjectId || b instanceof ObjectId ? String(a) === String(b) : same(a, b);
    const expr = (value, row) => {
        if (typeof value === 'string' && value.startsWith('$')) return get(row, value.slice(1));
        if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
        if (Object.hasOwn(value, '$literal')) return value.$literal;
        if (value.$type) return type(expr(value.$type, row));
        if (value.$and) return value.$and.every(part => expr(part, row));
        if (value.$in) return expr(value.$in[1], row).includes(expr(value.$in[0], row));
        if (value.$eq) return eq(expr(value.$eq[0], row), expr(value.$eq[1], row));
        assert.fail('unmodeled expression');
    };
    const matches = (row, filter) => Object.entries(filter).every(([field, wanted]) => {
        if (field === '$expr') return expr(wanted, row);
        const value = get(row, field);
        if (wanted && typeof wanted === 'object' && !(wanted instanceof ObjectId) && !(wanted instanceof Date)) {
            if (Object.hasOwn(wanted, '$exists')) return (value !== undefined) === wanted.$exists;
            if (wanted.$in) return wanted.$in.includes(value);
        }
        return eq(value, wanted);
    });
    let active = false;
    const session = { startTransaction() { active = true; }, inTransaction: () => active,
        async abortTransaction() { events.push({ action: 'abort' }); active = false; },
        async commitTransaction() { assert.fail('diagnostic must not commit enrollment'); }, async endSession() {} };
    const db = { getClient: () => ({ options: {}, topology: { description: { type: 'ReplicaSetWithPrimary' } } }),
        async startSession() { return session; } };
    const schemas = {
        Owner: OwnerSchema,
        Lock: require('../models/nodeOperationLockModel'),
        Enrollment: require('../models/topologyExecutionEnrollmentModel'),
        Binding: require('../models/topologyExecutionBindingModel'),
    };
    const query = value => { const q = { session() { return q; }, setOptions() { return q; },
        read() { return q; }, readConcern() { return q; }, select() { return q; }, async lean() { return value; } }; return q; };
    const models = Object.fromEntries(['Operation', 'Lock', 'Owner', 'Enrollment', 'Binding', 'HyNode'].map(name => [name, {
        db, collection: { async indexes() { return (schemas[name]?.schema.indexes() || []).map(([key, options]) => ({ key, ...options })); } },
        findOne(filter) {
            events.push({ model: name, action: 'read', filter });
            const row = name === 'Owner' ? owner : name === 'HyNode' ? nodeRow : null;
            return query(row && matches(row, filter) ? row : null);
        },
        async updateOne(filter, change) {
            const row = name === 'Owner' ? owner : name === 'HyNode' ? nodeRow : null;
            const matchedCount = row && matches(row, filter) ? 1 : 0;
            events.push({ model: name, action: 'cas', filter, matchedCount });
            if (matchedCount) Object.assign(row, change.$set);
            return { matchedCount };
        },
        async insertMany() { events.push({ model: name, action: 'insert-boundary' }); throw Error('MODELED_STOP_BEFORE_ENROLLMENT_INSERT'); },
    }]));
    const predecessor = randomUUID(), boot = randomUUID(), maintenance = randomUUID();
    const store = new TopologyExecutionBindingStore({ executionContext: context, ...models,
        withVerifiedAuthority: async (challenge, work) => work({
            authority: 'external-execution-maintenance-v1', status: 'verified', challenge: copy(challenge),
            proofId: randomUUID(), maintenanceId: maintenance, maintenance: 'held', allWriters: 'drained', bootstrapWriters: 'excluded',
            physicalIdentity: copy(source.nodeIdentity), owner: 'topology',
            connectionAttestation: { authority: 'server-physical-ssh-endpoint-v1', endpoint, physicalIdentity: copy(source.nodeIdentity),
                maintenanceId: maintenance, aliases: 'excluded', hostKeyDigest: 'raw-ssh-public-key-sha256', endpointReassignment: 'excluded' },
            predecessor: { generation: predecessor, bootId: boot, status: 'pre-enrolled' },
            oldBackend: { instanceId: 'modeled-classic', pid: 42, processStartTime: 'modeled-start', processTree: 'stopped', dispatch: 'disabled' },
        }) });
    await assert.rejects(store.preEnroll(freeze({ nodeId: node.id, targetProfile: profile, endpoint,
        nodeIdentity: copy(source.nodeIdentity), ownerGeneration: source.generation, predecessorGeneration: predecessor, bootId: boot })),
    { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    return events;
}

test('control: actual preEnroll reaches insert boundary for native Portal MAIN and Bridge SIDECAR, but rejects Bridge MAIN at role CAS', async () => {
    const f = forwardFixture(); await genericAdopt(f);
    for (const [node, profile, expectedMatch] of [[f.nodes[0], 'xray-main', 1], [f.nodes[1], 'xray-bridge', 1], [f.nodes[1], 'xray-main', 0]]) {
        const events = await enrollmentBoundary(f, node, profile);
        assert.equal(events.find(event => event.model === 'Owner' && event.action === 'cas')?.matchedCount, 1,
            'exact public owner generation/readback accepted before the role gate');
        const gate = events.find(event => event.model === 'HyNode' && event.action === 'cas');
        assert.equal(gate?.matchedCount, expectedMatch);
        assert.deepEqual(gate.filter.cascadeRole.$in, profile === 'xray-main' ? ['portal'] : ['relay', 'bridge']);
        assert.equal(events.filter(event => event.action === 'insert-boundary').length, expectedMatch);
        assert.equal(events.filter(event => event.action === 'abort').length, 1);
    }
    assert.ok(f.Owner.rows.every(owner => owner.executionBindingCheck === undefined), 'probe mutates only disposable model copies');
});
