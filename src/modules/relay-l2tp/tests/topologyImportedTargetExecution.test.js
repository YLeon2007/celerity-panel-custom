'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash } = require('node:crypto');
const { freeze } = require('../models/topologyExecutionBindingContract');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');
const { TopologyOperationRepository, selectedAdmissionFingerprint } = require('../repositories/topologyOperationRepository');
const { TopologyOperationExecutor } = require('../services/topologyOperationExecutor');
const { TopologyNodeTransportFactory } = require('../services/topologyNodeTransportFactory');
const { TopologyRunnerBootstrapper, TOPOLOGY_RUNNER_SHA256 } = require('../services/topologyRunnerBootstrapper');
const Operation = require('../models/topologyOperationModel');
const P = '111111111111111111111111', B = '222222222222222222222222', L = '333333333333333333333333', O = '444444444444444444444444';
const EPOCH = '11111111-1111-4111-8111-111111111111', RUNNER = '22222222-2222-4222-8222-222222222222';
// These are PURE modeled carrier forms, not publicly adopted owner authority.
function pin(nodeId, role) { return { version: 1, layout: 'legacy-forward-main', nodeId, role,
    targetProfile: 'xray-main', ownerGeneration: EPOCH, descriptorSha256: 'a'.repeat(64), ownerEvidenceSha256: 'b'.repeat(64) }; }
function node(nodeId, role) {
    const content = '{"inbounds":[],"outbounds":[{"tag":"direct"}],"routing":{"rules":[]}}\n';
    const hash = createHash('sha256').update(content).digest('hex');
    return { node: nodeId, nodeRef: role, role, targetProfile: 'xray-main', profileTargetPin: pin(nodeId, role),
        configPath: '/usr/local/etc/xray/config.json', serviceUnit: 'xray.service', serviceUnitPath: '/etc/systemd/system/xray.service',
        candidateHash: hash, candidate: { mediaType: 'application/vnd.celerity.xray-topology-node+json;version=1', bytes: [...Buffer.from(content)], sha256: hash }, checks: [] };
}
function selected() {
    const nodes = [node(P, 'portal'), node(B, 'bridge')];
    const topology = { nodes: nodes.map(n => ({ id: n.node, role: n.role, type: 'xray', active: true })),
        links: [{ id: L, source: P, target: B, mode: 'forward', active: true, tunnelUuid: EPOCH,
            tunnelPort: 2443, tunnelSecurity: 'none', tunnelTransport: 'tcp', tunnelProtocol: 'vless' }], groups: [] };
    return { operationId: O, executionContext: { ...TEST }, idempotencyKey: `topology:test:revision-2:host-test.infograd.online:${EPOCH}`,
        topologyRevision: 2, priorDeployedRevision: 1, admissionScope: 'selected', resourceNodeIds: [P, B],
        baselineTopology: structuredClone(topology), effectiveTopology: topology, kind: 'link.apply', staged: false,
        linkId: L, linkIds: [L], selectedOwnerPins: nodes.map(n => ({ node: n.node, profile: n.targetProfile,
            owner: 'topology', generation: EPOCH, executionContext: { ...TEST }, profileTargetPin: { ...n.profileTargetPin } })), nodes };
}
function repository(model = {}) { return new TopologyOperationRepository({ model: { async create(rows) { return rows; }, async findOneAndUpdate() {}, async updateOne() {}, ...model } }); }

test('modeled selected pin survives real repository/strict operation schema and independent JSON copies', async () => {
    const input = selected(); input.admissionFingerprint = selectedAdmissionFingerprint(input);
    const result = await repository({ async create(rows) { const doc = new Operation(rows[0]); await doc.validate(); return [doc]; } })
        .createFrozen({ ...input, heldTopologyAdmission: true, session: { inTransaction: () => true } });
    const raw = result.toObject();
    assert.deepEqual(raw.nodes.map(n => n.profileTargetPin), input.nodes.map(n => n.profileTargetPin));
    assert.equal(raw.nodes[1].role, 'bridge'); assert.equal(raw.nodes[1].targetProfile, 'xray-main');
    assert.equal(selectedAdmissionFingerprint({ ...raw, operationId: O }), input.admissionFingerprint);
    assert.deepEqual(JSON.parse(JSON.stringify(raw)).nodes[1].profileTargetPin, input.nodes[1].profileTargetPin);
});

test('imported fingerprint covers pin and actual MAIN, without changing the caller role', () => {
    const operation = selected(), before = JSON.stringify(operation), original = selectedAdmissionFingerprint(operation);
    const changed = structuredClone(operation);
    changed.nodes[1].profileTargetPin.ownerEvidenceSha256 = 'c'.repeat(64);
    changed.selectedOwnerPins[1].profileTargetPin.ownerEvidenceSha256 = 'c'.repeat(64);
    assert.notEqual(selectedAdmissionFingerprint(changed), original);
    assert.equal(JSON.stringify(operation), before);
    const bad = structuredClone(operation); bad.nodes[1].targetProfile = 'xray-bridge';
    assert.throws(() => selectedAdmissionFingerprint(bad));
});

test('repository refuses unselected/missing-owner/mismatched pin and duplicate physical entries before write', async () => {
    let writes = 0; const repo = repository({ async create(rows) { writes++; return rows; } });
    for (const change of [o => { delete o.admissionScope; delete o.resourceNodeIds; delete o.baselineTopology; delete o.effectiveTopology; },
        o => { delete o.selectedOwnerPins[1].profileTargetPin; }, o => { o.nodes[1].profileTargetPin = null; },
        o => { o.nodes.push(structuredClone(o.nodes[1])); }, o => { o.nodes[1].role = 'portal'; }]) {
        const input = selected(); change(input);
        await assert.rejects(repo.createFrozen({ ...input, heldTopologyAdmission: true, admissionFingerprint: 'a'.repeat(64), session: { inTransaction: () => true } }));
    }
    assert.equal(writes, 0);
});

test('executor projects a modeled Bridge MAIN pin but binding refusal precedes credentials/bootstrap/transport', async () => {
    const calls = [];
    const executor = new TopologyOperationExecutor({ ...TEST,
        nodeExecutionResolver: { async resolve() { calls.push('credentials'); throw Error('not allowed'); } },
        executionBindingReader: { async readVerified(expected) { calls.push(expected); throw Error('no independent owner authority'); } } });
    await assert.rejects(executor.prepare({ operationId: O, topologyRevision: 2, priorDeployedRevision: 1,
        executionFence: freeze({ owner: 'worker', attempt: 1, generation: RUNNER }), node: freeze(node(B, 'bridge')) }),
    error => error.code === 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' && error.remoteOutcomeUncertain === false);
    assert.equal(calls.length, 1); assert.deepEqual(calls[0].profileTargetPin, pin(B, 'bridge'));
    assert.equal(calls[0].generation, RUNNER); assert.notEqual(calls[0].generation, calls[0].profileTargetPin.ownerGeneration);
});

test('executor compares independent pin copies deeply and never treats shape equality as connection authority', async () => {
    const { bindingRecord } = require('./helpers/topologyV2Fixture');
    const context = { operationId: O, topologyRevision: 2, priorDeployedRevision: 1,
        executionFence: freeze({ owner: 'worker', attempt: 1, generation: RUNNER }), node: freeze(node(B, 'bridge')) };
    for (const variant of ['equal-copy', 'stripped', 'changed', 'extra', 'shallow-frozen']) {
        const calls = [], copy = JSON.parse(JSON.stringify(context.node.profileTargetPin));
        let durable = { ...bindingRecord(context), profileTargetPin: copy };
        if (variant === 'stripped') delete durable.profileTargetPin;
        if (variant === 'changed') durable.profileTargetPin.ownerEvidenceSha256 = 'e'.repeat(64);
        if (variant === 'extra') durable.profileTargetPin.untrusted = true;
        durable = variant === 'shallow-frozen' ? Object.freeze(durable) : freeze(durable);
        const executor = new TopologyOperationExecutor({ ...TEST,
            nodeExecutionResolver: { async resolve() { calls.push('credentials'); } },
            executionBindingReader: { async readVerified() { calls.push('binding'); return durable; },
                async readVerifiedConnection() { calls.push('connection'); throw Error('no independent authority'); } } });
        await assert.rejects(executor.prepare(context), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        assert.deepEqual(calls, variant === 'equal-copy' ? ['binding', 'connection'] : ['binding']);
    }
});

test('factory pure target placement preserves actual role and excludes pin from credential resolver input', async () => {
    const calls = [];
    class Transport { constructor(options) { this.options = options; } }
    const factory = new TopologyNodeTransportFactory({ executionContext: TEST.hostIdentity, NodeTransport: Transport,
        nodeExecutionResolver: { async resolve(value) { calls.push(value); return { async exec() {} }; } } });
    await factory.create({ nodeId: B, role: 'bridge', profileTargetPin: pin(B, 'bridge') });
    assert.deepEqual(calls, [{ nodeId: B, role: 'bridge' }]);
    for (const value of [null, undefined, { ...pin(B, 'bridge'), role: 'portal' }]) {
        await assert.rejects(factory.create({ nodeId: B, role: 'bridge', profileTargetPin: value }));
    }
    assert.equal(calls.length, 1);
});

test('modeled pinned MAIN bootstrap never inspects/installs SIDECAR or rewrites MAIN unit', async () => {
    const commands = [];
    const bootstrapper = new TopologyRunnerBootstrapper({ ...TEST, nodeId: B, role: 'bridge', profileTargetPin: pin(B, 'bridge'),
        nodeSSH: { async exec(command) { commands.push(command); return command.includes('sha256sum')
            ? { code: 0, stderr: '', stdout: `${TOPOLOGY_RUNNER_SHA256.slice(7)}  /usr/local/bin/celerity-topology-node-runner-v2\n750\n` }
            : { code: 0, stdout: '', stderr: '' }; }, async writeFile() { throw Error('runner already exists'); } } });
    assert.equal((await bootstrapper.ensureRunner()).changed, false);
    assert.equal(commands.length, 2);
    assert.equal(commands.some(c => c.includes('xray-bridge') || c.includes('/etc/systemd/') || c.includes('restart')), false);
});

function durableOperation() {
    const operation = selected();
    operation._id = O; operation.status = 'preparing'; operation.attempts = 1; operation.heldTopologyAdmission = true;
    operation.nodes = operation.nodes.map(n => {
        const { configPath, serviceUnit, serviceUnitPath, ...metadata } = n;
        return { ...metadata, state: 'pending', backupId: '' };
    });
    operation.admissionFingerprint = selectedAdmissionFingerprint(operation);
    return operation;
}
function workerFixture(operation, reserveBinding) {
    const { TopologyOperationWorker } = require('../workers/topologyOperationWorker');
    const events = [], leaseUntil = new Date(Date.now() + 60000);
    const worker = new TopologyOperationWorker({ executionContext: TEST, workerId: 'worker', leaseMs: 30000,
        clock: { now: () => new Date() }, timer: { setInterval() { return 1; }, clearInterval() {} },
        executor: { executionProtocolVersion: 2, async prepare() { events.push('dispatch'); throw Error('forbidden'); },
            async commit() {}, async verify() {}, async cleanupPrepared() {}, async rollback() {} },
        finalizer: { async finalizeSucceeded() { events.push('publish'); }, async probeV2Settlement() { return null; } },
        operationRepository: { async claim() { return operation; }, async renewLease() { return true; }, async recordNode() { return true; },
            async setPhase() { return true; }, async finishClaimed() { events.push('invalid-plan'); return true; } },
        selectedTopologyRepository: { async verifySelected() { events.push('independent-selected-read');
            // No qualified producer/root exists yet. We stop at binding provisioning,
            // never use this modeled callback to dispatch or claim authorization.
        } },
        bindingProvisioner: { executionContext: TEST, reserveBinding },
        bindingLifecycle: { executionContext: TEST, async run(work) { return work(); }, async assertHeld() {} },
        lockService: { async acquire() { return { ok: true, lock: { generation: RUNNER, leaseUntil } }; },
            async renew() { return { ok: true }; }, async release() { events.push('release'); } } });
    return { worker, events };
}
test('worker rehydrates serialized pin/actual role and carries identical expected pin to refusing provisioner', async () => {
    const expected = [], operation = durableOperation();
    const { worker, events } = workerFixture(operation, async value => {
        expected.push(value);
        assert.equal(Object.isFrozen(value.profileTargetPin), true);
        if (value.nodeId === B) throw Error('no qualified owner/binding authority');
    });
    const outcome = await worker.run(O);
    assert.equal(outcome.errorCode, 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN');
    assert.deepEqual(expected.map(e => e.profileTargetPin), operation.nodes.map(n => n.profileTargetPin));
    assert.deepEqual(expected.map(e => e.targetProfile), ['xray-main', 'xray-main']);
    assert.equal(expected[1].generation, RUNNER);
    assert.deepEqual(events, ['independent-selected-read']);
});

test('worker rejects stale/missing selected pins, changed fingerprint and duplicate physical metadata before binding', async () => {
    for (const change of [o => { delete o.selectedOwnerPins[1].profileTargetPin; },
        o => { o.admissionFingerprint = 'c'.repeat(64); }, o => { o.nodes.push(structuredClone(o.nodes[1])); },
        o => { o.nodes[1].role = 'portal'; }, o => { delete o.nodes[1].profileTargetPin; }]) {
        const operation = durableOperation(); change(operation); let bindings = 0;
        const { worker, events } = workerFixture(operation, async () => { bindings++; });
        assert.equal((await worker.run(O)).status, 'failed'); assert.equal(bindings, 0);
        assert.deepEqual(events, ['invalid-plan']);
    }
});

test('pin operation cannot publish through the native TEST-only finalization shortcut', async () => {
    const { TopologyOperationFinalizationRepository } = require('../repositories/topologyOperationFinalizationRepository');
    let writes = 0, selectedReads = 0;
    const operation = durableOperation();
    const query = value => ({ select() { return this; }, session() { return this; }, async lean() { return value; } });
    const repo = new TopologyOperationFinalizationRepository({
        TopologyOperation: { findById() { return query(operation); }, async updateOne() { writes++; } },
        CascadeTopologyState: { async updateOne() { writes++; } }, transactionRunner: work => work({}),
        selectedTopologyRepository: { async verifySelected() { selectedReads++; } } });
    assert.equal(await repo.finalizeSucceeded({ operationId: O, owner: 'worker', leaseUntil: new Date(Date.now() + 60000),
        topologyRevision: 2, priorDeployedRevision: 1, now: new Date() }), null);
    assert.equal(writes, 0); assert.equal(selectedReads, 0);
});

function ownerRoot() {
    const { importedProfileTargetDigests } = require('../services/topologyProfileTarget');
    const topology = selected().baselineTopology;
    topology.nodes.forEach(n => { n.profileConfig = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n'; });
    const root = { executionContext: { ...TEST }, node: B, profile: 'xray-main', owner: 'topology', generation: EPOCH,
        nodeIdentity: { machineId: 'a'.repeat(32), sshHostKeySha256: 'b'.repeat(64) },
        originalSnapshot: { configSha256: createHash('sha256').update(topology.nodes[1].profileConfig).digest('hex'),
            unitSha256: 'c'.repeat(64), serviceActive: 'active', serviceEnabled: 'enabled' },
        adoptionReceipt: { proofId: RUNNER, maintenanceId: RUNNER, fromGeneration: RUNNER, toGeneration: EPOCH,
            oldBackendInstanceId: 'modeled-old', oldPid: 42, oldProcessStartTime: '123', verifiedAt: new Date('2026-11-04T00:00:00.000Z') },
        legacyAppliedTopology: topology };
    root.profileTargetPin = { ...pin(B, 'bridge'), ...importedProfileTargetDigests(root) };
    return root;
}
function modeledModels(owner) {
    // Real Mongoose queries/schemas with a disconnected, in-process modeled
    // driver. No global ready-state mutation, server, database or authority seed.
    const mongoose = require('mongoose'), { serialize, deserialize } = require('bson');
    const db = mongoose.createConnection(), events = [];
    db.getClient = () => ({ options: {}, topology: { description: { type: 'ReplicaSetWithPrimary' } } });
    const paths = { Operation: '../models/topologyOperationModel', Lock: '../models/nodeOperationLockModel',
        Owner: '../../../models/topologyConfigOwnerModel', Enrollment: '../models/topologyExecutionEnrollmentModel',
        Binding: '../models/topologyExecutionBindingModel', HyNode: '../../../models/hyNodeModel' };
    const models = {};
    for (const [name, path] of Object.entries(paths)) {
        const schema = require(path).schema.clone();
        if (name === 'Owner') {
            // Explicit pending B0 private-field contract, only for projection
            // refusal tests. This is not an adopted imported authority fixture.
            schema.add({ profileTargetPin: { type: require('../models/topologyProfileTargetPinSchema').createProfileTargetPinSchema(),
                default: undefined, select: false, set: require('../services/topologyProfileTarget').assertProfileTargetPin } });
        }
        const model = db.model(`A1${name}`, schema);
        model.collection.buffer = false;
        model.collection.collection = {
            async indexes() { return schema.indexes().filter(([, options]) => options.unique).map(([key]) => ({ key, unique: true })); },
            async findOne(filter, options) {
                events.push({ name, filter, options });
                if (name !== 'Owner') throw Error('no other modeled driver read allowed');
                const row = deserialize(serialize({ ...owner, node: new mongoose.Types.ObjectId(owner.node) }));
                for (const [key, value] of Object.entries(options.projection || {})) if (value === 0) delete row[key];
                return row;
            },
            async updateOne() { events.push('write'); throw Error('writes forbidden'); },
            async insertMany() { events.push('write'); throw Error('writes forbidden'); },
        };
        models[name] = model;
    }
    return { models, events };
}
test('store preEnroll keeps seven caller keys and explicitly selects private root before authority/any mutation', async () => {
    const { TopologyExecutionBindingStore } = require('../repositories/topologyExecutionBindingStore');
    const { verifyImportedProfileTargetPin } = require('../services/topologyProfileTarget');
    const root = ownerRoot();
    assert.throws(() => verifyImportedProfileTargetPin({ owner: root, profileTargetPin: root.profileTargetPin, executionContext: TEST }),
        { code: 'CONFIG_LEGACY_IMPORT_LAYOUT_UNSUPPORTED' }, 'B1 remains the real qualification dependency');
    const { models, events } = modeledModels(root); let authority = 0;
    const store = new TopologyExecutionBindingStore({ executionContext: TEST, ...models,
        async withVerifiedAuthority() { authority++; } });
    const input = { nodeId: B, targetProfile: 'xray-main', endpoint: { ip: '192.0.2.2', port: 22, username: 'synthetic' },
        nodeIdentity: root.nodeIdentity, ownerGeneration: EPOCH, predecessorGeneration: 'none', bootId: RUNNER };
    await assert.rejects(store.preEnroll({ ...input, profileTargetPin: root.profileTargetPin }), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.equal(events.length, 0);
    // The actual schema enforces private projection on an ordinary read.
    const publicRoot = await models.Owner.findOne({ node: B }).lean();
    assert.equal(Object.hasOwn(publicRoot, 'profileTargetPin'), false);
    assert.equal(Object.hasOwn(publicRoot, 'legacyAppliedTopology'), false);
    events.length = 0;
    await assert.rejects(store.preEnroll(input), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.equal(authority, 0); assert.equal(events.length, 1);
    assert.equal(events[0].name, 'Owner');
    assert.notEqual(events[0].options.projection?.legacyAppliedTopology, 0);
    assert.notEqual(events[0].options.projection?.profileTargetPin, 0);
    assert.equal(events[0].options.readPreference?.mode || events[0].options.readPreference, 'primary');
    assert.deepEqual(events[0].options.readConcern, { level: 'majority' });
});
test('store rejects missing/stale owner pins and changed private roots before authority, transactions or credential lookup', async () => {
    const { TopologyExecutionBindingStore } = require('../repositories/topologyExecutionBindingStore');
    for (const change of [o => { delete o.profileTargetPin; }, o => { o.profileTargetPin = null; },
        o => { o.profileTargetPin.ownerGeneration = RUNNER; }, o => { o.generation = RUNNER; },
        o => { o.legacyAppliedTopology.nodes[1].profileConfig += '\n'; },
        o => { o.originalSnapshot.unitSha256 = 'd'.repeat(64); },
        o => { o.adoptionReceipt.oldPid++; }, o => { o.handbackReceipt = {}; }]) {
        const root = ownerRoot(); change(root);
        const { models, events } = modeledModels(root); let authority = 0;
        const store = new TopologyExecutionBindingStore({ executionContext: TEST, ...models,
            async withVerifiedAuthority() { authority++; } });
        await assert.rejects(store.preEnroll({ nodeId: B, targetProfile: 'xray-main',
            endpoint: { ip: '192.0.2.2', port: 22, username: 'synthetic' }, nodeIdentity: root.nodeIdentity,
            ownerGeneration: EPOCH, predecessorGeneration: 'none', bootId: RUNNER }), { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
        assert.equal(authority, 0); assert.equal(events.length, 1); assert.equal(events[0].name, 'Owner');
    }
});

function settlementFixture(imported = false) {
    const { ObjectId, serialize, deserialize } = require('bson');
    const sift = require('sift').default, { randomUUID } = require('node:crypto');
    const { bindingRecord } = require('./helpers/topologyV2Fixture');
    const { TopologyOperationFinalizationRepository } = require('../repositories/topologyOperationFinalizationRepository');
    const clone = row => deserialize(serialize(row));
    const operation = durableOperation(), events = [];
    if (!imported) {
        operation.admissionScope = 'full'; operation.resourceNodeIds = []; operation.selectedOwnerPins = [];
        operation.kind = 'domain.sync'; delete operation.linkId; delete operation.linkIds; delete operation.staged;
        delete operation.baselineTopology; delete operation.effectiveTopology;
        operation.nodes = [operation.nodes[0]]; delete operation.nodes[0].profileTargetPin;
    }
    operation.status = 'committing'; operation.leaseOwner = 'worker'; operation.leaseUntil = new Date(Date.now() + 60000);
    const tables = { TopologyOperation: [operation], CascadeTopologyState: [{ _id: 'singleton', revision: 2,
        deployedRevision: 1, topologyAdmissionCount: 1 }], NodeOperationLock: [], TopologyConfigOwner: [],
    TopologyExecutionBinding: [], TopologyExecutionEnrollment: [] };
    const contexts = [], bindings = [];
    for (const metadata of operation.nodes) {
        const owner = ownerRoot(); owner.node = metadata.node;
        if (imported) {
            owner.profileTargetPin = { ...pin(metadata.node, metadata.role),
                ...require('../services/topologyProfileTarget').importedProfileTargetDigests(owner) };
            metadata.profileTargetPin = owner.profileTargetPin;
            operation.selectedOwnerPins.find(p => p.node === metadata.node).profileTargetPin = owner.profileTargetPin;
        } else { delete owner.profileTargetPin; delete owner.legacyAppliedTopology; }
        const plan = node(metadata.node, metadata.role);
        if (!imported) delete plan.profileTargetPin; else plan.profileTargetPin = owner.profileTargetPin;
        const context = { operationId: O, topologyRevision: 2, priorDeployedRevision: 1,
            executionFence: freeze({ owner: 'worker', attempt: 1, generation: RUNNER }), node: freeze(plan) };
        const binding = freeze({ ...bindingRecord(context), attemptId: randomUUID(), bootId: randomUUID(), maintenanceId: randomUUID(),
            ...(imported ? { profileTargetPin: owner.profileTargetPin } : {}),
            commandIds: Object.fromEntries(['prepare', 'commit', 'verify', 'rollback', 'close'].map(k => [k, randomUUID()])) });
        metadata.state = 'committed'; metadata.backupId = binding.backupId;
        const common = { nodeId: binding.nodeId, targetProfile: binding.targetProfile, executionContext: binding.executionContext,
            bootId: binding.bootId, maintenanceId: binding.maintenanceId, nodeIdentity: owner.nodeIdentity,
            endpoint: { ip: '192.0.2.2', port: 22, username: 'synthetic' }, ownerGeneration: EPOCH,
            ...(imported ? { profileTargetPin: owner.profileTargetPin } : {}) };
        const enrollmentId = randomUUID();
        tables.TopologyExecutionEnrollment.push({ _id: enrollmentId, ...common });
        tables.TopologyExecutionBinding.push({ _id: randomUUID(), ...common, ...binding, enrollmentId,
            ownerReceiptProofId: owner.adoptionReceipt.proofId });
        tables.TopologyConfigOwner.push(owner);
        tables.NodeOperationLock.push({ node: new ObjectId(metadata.node), operationId: O,
            owner: 'worker', generation: RUNNER, remoteUncertain: true, leaseUntil: operation.leaseUntil });
        bindings.push(binding); contexts.push(context);
    }
    if (imported) operation.admissionFingerprint = selectedAdmissionFingerprint(operation);
    // The state is BSON-serialized between each modeled persistence boundary.
    // No Mongo/physical proof is asserted by this in-process adapter.
    operation._id = new ObjectId(O);
    operation.nodes.forEach(n => { n.node = new ObjectId(n.node); });
    const client = { db: () => ({ async command() { events.push('commit'); return { ok: 1 }; } }) };
    const db = { async startSession() { events.push('session'); let active = false;
        return { client, transaction: { transition() { active = false; } }, startTransaction() { active = true; },
            inTransaction: () => active, async abortTransaction() { active = false; events.push('abort'); }, async endSession() {} }; },
    getClient: () => client };
    const models = {};
    const match = filter => row => Object.entries(filter).every(([key, value]) => {
        const current = key.split('.').reduce((o, k) => o?.[k], row);
        // Mongo's direct embedded-document equality, not sift's object-identity
        // shortcut. Operator predicates still use sift in this bounded model.
        if (value?.constructor === Object && Object.keys(value).every(k => !k.startsWith('$'))) {
            return require('node:util').isDeepStrictEqual(current, value);
        }
        return sift({ [key]: value })(row);
    });
    function query(name, filter) {
        let fields = '';
        return { select(value) { fields = value; return this; }, session() { return this; }, read() { return this; },
            readConcern() { return this; }, setOptions() { return this; }, async lean() {
                events.push({ read: name, fields });
                const found = tables[name].find(match(filter)); if (!found) return null;
                const copy = clone(found);
                if (name === 'TopologyConfigOwner') for (const field of ['profileTargetPin', 'legacyAppliedTopology']) {
                    if (!fields.includes('+' + field)) delete copy[field];
                }
                return copy;
            } };
    }
    function set(row, path, value, remove = false) {
        const keys = path.split('.'), last = keys.pop(); let target = row;
        for (const k of keys) target = target[k] ??= {};
        if (remove) delete target[last]; else target[last] = value;
    }
    for (const name of Object.keys(tables)) models[name] = { db,
        findOne: filter => query(name, filter), findById: id => query(name, { _id: id }),
        async updateOne(filter, update) {
            const row = tables[name].find(match(filter)); if (!row) return { matchedCount: 0, modifiedCount: 0 };
            events.push({ write: name });
            for (const [k, v] of Object.entries(update.$set || {})) set(row, k, clone({ v }).v);
            for (const k of Object.keys(update.$unset || {})) set(row, k, null, true);
            for (const [k, v] of Object.entries(update.$inc || {})) row[k] = (row[k] || 0) + v;
            return { matchedCount: 1, modifiedCount: 1 };
        }, async deleteOne(filter) {
            const index = tables[name].findIndex(match(filter));
            if (index === -1) return { deletedCount: 0 }; events.push({ write: name }); tables[name].splice(index, 1);
            return { deletedCount: 1 };
        } };
    return { tables, events, contexts, bindings, models,
        request: { operationId: O, owner: 'worker', now: new Date(), leaseUntil: operation.leaseUntil, topologyRevision: 2, priorDeployedRevision: 1 },
        repository: new TopologyOperationFinalizationRepository({ ...models, transactionRunner: () => { throw Error('legacy transaction forbidden'); },
            selectedTopologyRepository: { async verifySelected() { events.push('modeled-selected-read'); } } }) };
}
async function nativeTerminalProof(context, binding) {
    const { bindingReader, v2Receipt } = require('./helpers/topologyV2Fixture');
    const reader = bindingReader([binding]);
    reader.withVerifiedBinding = async (expected, work) => work(await reader.readVerified(expected), async () => {});
    const terminal = { phase: 'closed', terminal: true, terminalOutcome: 'verified', completedCommand: 'close' };
    const executor = new TopologyOperationExecutor({ ...TEST, executionBindingReader: reader,
        nodeExecutionResolver: { async resolve() { return {}; } }, RunnerBootstrapper: class { async ensureRunner() {} },
        NodeTransportFactory: class { async create() {
            return Object.fromEntries(['prepare', 'commit', 'verify', 'close', 'status'].map(command => [command,
                async request => v2Receipt({ ...request, command }, { bootId: binding.bootId,
                    ...(['close', 'status'].includes(command) ? terminal : {}) })]));
        } } });
    const prepared = await executor.prepare(context), lifecycle = { ...context, backupId: prepared.backupId, prepared: prepared.prepared };
    await executor.commit(lifecycle); await executor.verify(lifecycle);
    return executor.close(lifecycle);
}
test('real V2 native settlement persists/rereads unchanged record and ownerFence shapes, then releases atomically', async () => {
    const f = settlementFixture(), { repository, request } = f;
    await repository.beginV2Closure({ ...request, bindings: f.bindings });
    const probe = await repository.probeV2Settlement({ operationId: O });
    assert.deepEqual(probe.terminal.bindings, f.bindings);
    assert.equal(Object.hasOwn(probe.terminal.bindings[0], 'profileTargetPin'), false);
    assert.deepEqual(Object.keys(probe.terminal.ownerFences[0]).sort(),
        ['node', 'profile', 'executionContext', 'owner', 'generation', 'nodeIdentity', 'originalSnapshot', 'adoptionReceipt'].sort());
    const proof = await nativeTerminalProof(f.contexts[0], f.bindings[0]);
    assert.equal(require('../services/topologyOperationExecutor').isTopologyTerminalProof(proof), true);
    await repository.persistV2TerminalProofs({ ...request, proofs: [proof],
        sideEffects: { usersVerified: true, attachVerified: false, pppProof: [] } });
    await repository.finalizeV2Succeeded(request);
    const done = await repository.probeV2Settlement({ operationId: O });
    assert.equal(done.status, 'succeeded'); assert.equal(done.retained, false);
    assert.equal(f.tables.CascadeTopologyState[0].topologyAdmissionCount, 0);
    assert.equal(f.tables.NodeOperationLock.length, 0);
    assert.equal(f.events.filter(e => e === 'commit').length, 3);
});
test('V2 imported intent and read-only probe revalidate real owner root and refuse B1-closed forms without mutation', async () => {
    const f = settlementFixture(true);
    await assert.rejects(f.repository.beginV2Closure({ ...f.request, bindings: f.bindings }),
        { code: 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED' });
    assert.equal(f.events.some(e => e.write), false);
    const ownerFence = owner => Object.fromEntries(['node', 'profile', 'executionContext', 'owner', 'generation',
        'nodeIdentity', 'originalSnapshot', 'adoptionReceipt'].map(k => [k, owner[k]]));
    // Modeled serialized terminal carrier only, NOT a produced/accepted intent.
    f.tables.TopologyOperation[0].v2Terminal = { bindings: f.bindings,
        ownerFences: f.tables.TopologyConfigOwner.map(ownerFence), proofs: [], state: 'closing' };
    await assert.rejects(f.repository.probeV2Settlement({ operationId: O }), { code: 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED' });
    assert.equal(f.events.some(e => e.write), false);
    assert.equal(f.tables.TopologyOperation[0].heldTopologyAdmission, true);
    assert.equal(f.tables.NodeOperationLock.length, 2);
    assert.ok(f.events.some(e => e.read === 'TopologyConfigOwner' && e.fields.includes('+legacyAppliedTopology') && e.fields.includes('+profileTargetPin')));
});

test('actual terminal operation schema/BSON carries modeled pin records but never adds pin to the legacy ownerFence', async () => {
    const { serialize, deserialize } = require('bson');
    const f = settlementFixture(true), input = f.tables.TopologyOperation[0];
    input.v2Terminal = { bindings: f.bindings, ownerFences: f.tables.TopologyConfigOwner.map(owner => ({
        node: owner.node, profile: owner.profile, executionContext: owner.executionContext, owner: owner.owner,
        generation: owner.generation, nodeIdentity: owner.nodeIdentity, originalSnapshot: owner.originalSnapshot,
        adoptionReceipt: owner.adoptionReceipt })), proofs: [], state: 'closing' };
    const doc = new Operation(input); await doc.validate();
    const serialized = deserialize(serialize(doc.toObject()));
    assert.deepEqual(serialized.v2Terminal.bindings.map(row => row.profileTargetPin), f.bindings.map(row => row.profileTargetPin));
    assert.equal(Object.hasOwn(serialized.v2Terminal.ownerFences[1], 'profileTargetPin'), false);
    assert.equal(serialized.v2Terminal.bindings[1].generation, RUNNER);
    assert.equal(serialized.v2Terminal.bindings[1].profileTargetPin.ownerGeneration, EPOCH);
});

test('terminal executor recovery retains pin/actual role and refuses before credentials or status on failed binding proof', async () => {
    const { bindingRecord } = require('./helpers/topologyV2Fixture');
    const metadata = freeze(node(B, 'bridge'));
    const record = freeze({ ...bindingRecord({ operationId: O, topologyRevision: 2, priorDeployedRevision: 1,
        executionFence: freeze({ owner: 'worker', attempt: 1, generation: RUNNER }), node: metadata }), profileTargetPin: metadata.profileTargetPin });
    const events = [];
    const executor = new TopologyOperationExecutor({ ...TEST,
        nodeExecutionResolver: { async resolve() { events.push('credentials'); } },
        executionBindingReader: { async readVerified() { throw Error('not used'); },
            async withReadOnlyVerifiedBinding(expected) { events.push(expected); throw Error('unqualified root'); } } });
    await assert.rejects(executor.probeTerminalBinding(record, 'bridge'), /unqualified root/);
    assert.deepEqual(events[0].profileTargetPin, metadata.profileTargetPin);
    assert.equal(events[0].generation, RUNNER);
    assert.equal(events.length, 1);
    for (const role of [undefined, 'portal']) await assert.rejects(executor.probeTerminalBinding(record, role),
        { code: 'TOPOLOGY_EXECUTION_BINDING_UNPROVEN' });
    assert.equal(events.length, 1);
});
