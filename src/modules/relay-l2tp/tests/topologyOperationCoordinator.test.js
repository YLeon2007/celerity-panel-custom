'use strict';

process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'panel.example.test';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'admin@example.test';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    TEST_TOPOLOGY_HOST_IDENTITY,
    TEST_TOPOLOGY_TARGET,
} = require('../services/topologyOperationPlanMaterializer');
const {
    TopologyOperationCoordinator,
} = require('../services/topologyOperationCoordinator');
const {
    TopologyDeploymentRepository,
} = require('../repositories/topologyDeploymentRepository');
const { TopologyOperationRepository } = require('../repositories/topologyOperationRepository');

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    Object.values(value).forEach(deepFreeze);
    return Object.freeze(value);
}

function snapshot() {
    return {
        revision: 7,
        deployedRevision: 5,
        nodes: [
            { _id: 'portal-1', cascadeRole: 'portal' },
            { _id: 'bridge-1', cascadeRole: 'bridge' },
        ],
        links: [{
            _id: 'link-1',
            portalNode: 'portal-1',
            bridgeNode: 'bridge-1',
            mode: 'forward',
            active: true,
        }],
        groups: [],
    };
}

function materializedPlan() {
    return deepFreeze({
        schemaVersion: 1,
        mode: 'forward',
        nodes: [
            {
                nodeRef: 'bridge',
                role: 'bridge',
                candidate: { sha256: 'bridge-hash', bytes: [98] },
                checks: [],
            },
            {
                nodeRef: 'portal',
                role: 'portal',
                candidate: { sha256: 'portal-hash', bytes: [112] },
                checks: [],
            },
        ],
    });
}

const fakeSession = Object.freeze({ inTransaction: () => true });
async function admitFakeSnapshot(value, { expectedRevision, prepare, admit }, deployedRevision = value.deployedRevision) {
    assert.equal(expectedRevision, value.revision);
    const prepared = await prepare(value, fakeSession);
    const pinned = { revision: value.revision, deployedRevision, ...prepared };
    await admit(pinned, fakeSession);
    return pinned;
}

test('legacy full deploy refuses pending links before composing or marking all links', async () => {
    const currentSnapshot = snapshot();
    currentSnapshot.links[0].status = 'deployed';
    currentSnapshot.links.push({
        _id: 'link-old-pending', portalNode: 'portal-2',
        bridgeNode: 'bridge-1', mode: 'reverse', active: true, status: 'pending',
    });
    let materialized = false;
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: {
            async admitTopology(input) { return admitFakeSnapshot(currentSnapshot, input); },
        },
        planMaterializer: {
            async materialize() { materialized = true; return materializedPlan(); },
        },
        operationRepository: { async createFrozen() { throw new Error('must not persist'); } },
        validator: () => ({ valid: true }),
        compiler: () => ({ valid: true }),
    });
    await assert.rejects(
        coordinator.queue({ expectedTopologyRevision: 7 }),
        error => error.code === 'INVALID_TOPOLOGY_DEPLOYMENT'
            && error.causeCode === 'UNCONFIRMED_LINK_IN_FULL_DEPLOY',
    );
    assert.equal(materialized, false);
});

test('queue keeps materialization, counted admission and frozen insert inside one transaction', async () => {
    const calls = [];
    const session = { inTransaction: () => true };
    let committed = false;
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: { async admitTopology({ expectedRevision, prepare, admit }) {
            assert.equal(expectedRevision, 7);
            calls.push('read');
            const prepared = await prepare(snapshot(), session);
            calls.push('cas');
            await admit({ revision: 7, deployedRevision: 5, ...prepared }, session);
            committed = true;
            calls.push('commit');
            return { revision: 7, deployedRevision: 5, ...prepared };
        } },
        planMaterializer: { async materialize(input) {
            assert.strictEqual(input.session, session);
            calls.push('materialize');
            return materializedPlan();
        } },
        operationRepository: { async createFrozen(input) {
            assert.strictEqual(input.session, session);
            assert.equal(committed, false);
            calls.push('insert');
            return { _id: input.operationId };
        } },
        operationWorker: { async run() {
            assert.equal(committed, true);
            calls.push('worker');
        } },
        validator: () => ({ valid: true }),
        compiler: () => ({ valid: true }),
        idFactory: () => 'operation-atomic',
    });
    const result = await coordinator.queue({ expectedTopologyRevision: 7 });
    assert.equal(result.operationId, 'operation-atomic');
    assert.deepEqual(calls, ['read', 'materialize', 'cas', 'insert', 'commit', 'worker']);
});

test('ambiguous commit acknowledges only exact held operation identity without starting worker', async () => {
    let inserted;
    let workerRuns = 0;
    const ambiguous = new Error('private commit detail');
    ambiguous.hasErrorLabel = label => label === 'UnknownTransactionCommitResult';
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: { async admitTopology({ prepare, admit }) {
            const session = { inTransaction: () => true };
            const prepared = await prepare(snapshot(), session);
            await admit({ revision: 7, deployedRevision: 5, ...prepared }, session);
            throw ambiguous;
        } },
        planMaterializer: { async materialize() { return materializedPlan(); } },
        operationRepository: {
            async createFrozen(input) { inserted = input; },
            async findAdmissionById(id) {
                assert.equal(id, 'operation-ambiguous');
                return { _id: id, topologyRevision: 7, priorDeployedRevision: 5,
                    heldTopologyAdmission: true, admissionFingerprint: inserted.admissionFingerprint,
                    status: 'queued' };
            },
        },
        operationWorker: { async run() { workerRuns += 1; } },
        validator: () => ({ valid: true }),
        compiler: () => ({ valid: true }),
        idFactory: () => 'operation-ambiguous',
    });
    const result = await coordinator.queue({ expectedTopologyRevision: 7 });
    assert.equal(result.operationId, 'operation-ambiguous');
    assert.match(inserted.admissionFingerprint, /^[a-f0-9]{64}$/);
    assert.equal(workerRuns, 0);
});

test('ambiguous commit rejects mismatched or unavailable readback without leaking details or starting worker', async () => {
    const ambiguous = new Error('private commit detail');
    ambiguous.hasErrorLabel = label => label === 'UnknownTransactionCommitResult';
    for (const readback of [
        null,
        { _id: 'different-operation', topologyRevision: 7, priorDeployedRevision: 5,
            heldTopologyAdmission: true, status: 'queued' },
        { _id: 'operation-ambiguous', topologyRevision: 8, priorDeployedRevision: 5,
            heldTopologyAdmission: true, status: 'queued' },
        { _id: 'operation-ambiguous', topologyRevision: 7, priorDeployedRevision: 5,
            heldTopologyAdmission: false, status: 'queued' },
        { _id: 'operation-ambiguous', topologyRevision: 7, priorDeployedRevision: 5,
            heldTopologyAdmission: true, admissionFingerprint: 'b'.repeat(64), status: 'queued' },
        { _id: 'operation-ambiguous', topologyRevision: 7, priorDeployedRevision: 4,
            heldTopologyAdmission: true, status: 'queued' },
        { _id: 'operation-ambiguous', topologyRevision: 7, priorDeployedRevision: 5,
            heldTopologyAdmission: true, status: 'unexpected' },
    ]) {
        let inserted;
        let workerRuns = 0;
        const coordinator = new TopologyOperationCoordinator({
            topologyRepository: { async admitTopology({ prepare, admit }) {
                const prepared = await prepare(snapshot(), fakeSession);
                await admit({ revision: 7, deployedRevision: 5, ...prepared }, fakeSession);
                throw ambiguous;
            } },
            planMaterializer: { async materialize() { return materializedPlan(); } },
            operationRepository: {
                async createFrozen(input) { inserted = input; },
                async findAdmissionById(id) {
                    assert.equal(id, 'operation-ambiguous');
                    return readback && { ...readback,
                        admissionFingerprint: readback.admissionFingerprint ?? inserted.admissionFingerprint };
                },
            },
            operationWorker: { async run() { workerRuns += 1; } },
            validator: () => ({ valid: true }),
            compiler: () => ({ valid: true }),
            idFactory: () => 'operation-ambiguous',
        });
        await assert.rejects(coordinator.queue({ expectedTopologyRevision: 7 }), error => {
            assert.equal(error.code, 'TOPOLOGY_OPERATION_QUEUE_FAILED');
            assert.doesNotMatch(JSON.stringify(error), /private commit detail/);
            return true;
        });
        assert.equal(workerRuns, 0);
    }
});

test('queues one frozen fixed-test operation and starts only the injected worker', async () => {
    const calls = [];
    const currentSnapshot = snapshot();
    const topologyRepository = {
        async admitTopology(input) {
            const { expectedRevision } = input;
            calls.push({ method: 'admitTopology', expectedRevision });
            return admitFakeSnapshot(currentSnapshot, input);
        },
    };
    const planMaterializer = {
        async materialize(input) {
            calls.push({ method: 'materialize', input });
            return materializedPlan();
        },
    };
    const operationRepository = {
        async createFrozen(input) {
            calls.push({ method: 'createFrozen', input });
            return { _id: input.operationId, status: 'queued', ...input };
        },
    };
    const operationWorker = {
        async run(operationId) {
            calls.push({ method: 'worker.run', operationId });
            return { claimed: false, operationId };
        },
    };
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository,
        planMaterializer,
        operationRepository,
        operationWorker,
        validator: () => ({ valid: true, errors: [] }),
        compiler: () => ({ valid: true, errors: [], relays: [] }),
        idFactory(idempotencyKey) {
            calls.push({ method: 'idFactory', idempotencyKey });
            return 'operation-public';
        },
    });

    const result = await coordinator.queue({ expectedTopologyRevision: 7 });
    await Promise.resolve();

    assert.deepEqual(result, {
        operationId: 'operation-public',
        topologyRevision: 7,
        status: 'queued',
    });
    assert.equal(calls.filter(call => call.method === 'materialize').length, 1);
    const materialize = calls.find(call => call.method === 'materialize');
    assert.equal(materialize.input.target, TEST_TOPOLOGY_TARGET);
    assert.equal(materialize.input.hostIdentity, TEST_TOPOLOGY_HOST_IDENTITY);
    assert.deepEqual(materialize.input.pinnedSnapshot.topology, {
        nodes: [
            { id: 'bridge-1', role: 'bridge' },
            { id: 'portal-1', role: 'portal' },
        ],
        links: [{
            id: 'link-1',
            source: 'portal-1',
            target: 'bridge-1',
            mode: 'forward',
            geo: false,
        }],
        groups: [],
    });
    const frozenInput = calls.find(call => call.method === 'createFrozen').input;
    assert.equal(frozenInput.operationId, 'operation-public');
    assert.match(
        frozenInput.idempotencyKey,
        /^topology:test:revision-7:[0-9a-f-]{36}$/,
        'each queue run must use a unique idempotency key suffix so node-side runner state never collides',
    );
    assert.equal(frozenInput.topologyRevision, 7);
    assert.equal(frozenInput.priorDeployedRevision, 5);
    assert.strictEqual(frozenInput.session, fakeSession);
    assert.equal(frozenInput.heldTopologyAdmission, true);
    assert.match(frozenInput.admissionFingerprint, /^[a-f0-9]{64}$/);
    assert.ok(Array.isArray(frozenInput.nodes));
    const durableNodes = calls.find(call => call.method === 'createFrozen').input.nodes;
    assert.equal(Object.isFrozen(durableNodes), true);
    assert.deepEqual(durableNodes.map(node => ({
        node: node.node,
        candidateHash: node.candidateHash,
    })), [
        { node: 'bridge-1', candidateHash: 'bridge-hash' },
        { node: 'portal-1', candidateHash: 'portal-hash' },
    ]);
    assert.deepEqual(calls.find(call => call.method === 'worker.run'), {
        method: 'worker.run',
        operationId: 'operation-public',
    });
    assert.doesNotMatch(JSON.stringify(result), /candidate|bytes|secret/i);
    assert.equal(calls.some(call => call.method === 'markDeployed'), false);
});

test('stale revisions expose only safe revision context and do not materialize or start work', async () => {
    const calls = [];
    const stale = new Error('database topology secret must not escape');
    stale.code = 'STALE_TOPOLOGY_REVISION';
    stale.topologyRevision = 8;
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: {
            async admitTopology(input) {
                calls.push({ method: 'admitTopology', input });
                throw stale;
            },
        },
        planMaterializer: {
            async materialize(input) {
                calls.push({ method: 'materialize', input });
            },
        },
        operationRepository: {
            async createFrozen(input) {
                calls.push({ method: 'createFrozen', input });
            },
        },
        operationWorker: {
            async run(plan) {
                calls.push({ method: 'worker.run', plan });
            },
        },
        idFactory: () => 'operation-stale',
    });

    await assert.rejects(
        coordinator.queue({ expectedTopologyRevision: 7 }),
        error => {
            assert.equal(error.name, 'TopologyOperationCoordinatorError');
            assert.equal(error.code, 'STALE_TOPOLOGY_REVISION');
            assert.equal(error.operationId, 'operation-stale');
            assert.equal(error.expectedTopologyRevision, 7);
            assert.equal(error.topologyRevision, 8);
            assert.doesNotMatch(error.message, /database|secret/i);
            return true;
        },
    );
    assert.deepEqual(calls.map(call => call.method), ['admitTopology']);
});

test('held reservation returns a safe typed queue conflict without materialization or persistence', async () => {
    const calls = [];
    const topologyRepository = new TopologyDeploymentRepository({
        snapshotReader: { async readDraft() {
            calls.push('readDraft');
            return { ...snapshot(), replacementReservation: { ownerToken: 'private-token' } };
        } },
        CascadeTopologyState: { findOneAndUpdate() { calls.push('pin.cas'); throw new Error('must not pin'); } },
        transactionRunner: async work => work(fakeSession),
    });
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository,
        planMaterializer: { async materialize() { calls.push('materialize'); } },
        operationRepository: { async createFrozen() { calls.push('createFrozen'); } },
        operationWorker: { async run() { calls.push('worker.run'); } },
        idFactory: () => 'operation-held',
    });
    await assert.rejects(coordinator.queue({ expectedTopologyRevision: 7 }), error => {
        assert.equal(error.name, 'TopologyOperationCoordinatorError');
        assert.equal(error.code, 'TOPOLOGY_REPLACEMENT_RESERVED');
        assert.equal(error.operationId, 'operation-held');
        assert.doesNotMatch(JSON.stringify(error), /private-token/);
        return true;
    });
    assert.deepEqual(calls, ['readDraft']);
});

test('reservation injected between draft read and singleton CAS never queues an operation', async () => {
    const calls = [];
    const state = { revision: 7, deployedRevision: 5, topologyAdmissionCount: 0 };
    const session = fakeSession;
    const topologyRepository = new TopologyDeploymentRepository({
        snapshotReader: { async readDraft(candidateSession) {
            assert.strictEqual(candidateSession, session);
            calls.push('readDraft');
            return snapshot();
        } },
        CascadeTopologyState: { findOneAndUpdate(filter, update, options) {
            assert.strictEqual(options.session, session);
            calls.push('admission.cas');
            assert.equal(filter.topologyAdmissionCount, 0);
            assert.deepEqual(update.$inc, { topologyAdmissionCount: 1 });
            // Simulate a concurrent reservation after the transaction's read.
            state.replacementReservation = { ownerToken: 'private-token' };
            const matches = filter._id === 'singleton' && filter.revision === state.revision
                && (filter.replacementReservation?.$exists !== false
                    || state.replacementReservation === undefined);
            return { select() { return this; }, session(actual) {
                assert.strictEqual(actual, session);
                return this;
            }, lean: async () => matches ? { ...state } : null };
        } },
        transactionRunner: async work => work(session),
    });
    const operations = [];
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository,
        planMaterializer: { async materialize() {
            calls.push('materialize');
            return materializedPlan();
        } },
        operationRepository: { async createFrozen(operation) {
            operations.push(operation);
            calls.push('createFrozen');
        } },
        operationWorker: { async run() { calls.push('worker.run'); } },
        validator: () => ({ valid: true }),
        compiler: () => ({ valid: true }),
        idFactory: () => 'operation-race',
    });
    await assert.rejects(coordinator.queue({ expectedTopologyRevision: 7 }), error => {
        assert.equal(error.name, 'TopologyOperationCoordinatorError');
        assert.equal(error.code, 'TOPOLOGY_OPERATION_QUEUE_FAILED');
        assert.doesNotMatch(JSON.stringify(error), /private-token/);
        return true;
    });
    assert.deepEqual(calls, ['readDraft', 'materialize', 'admission.cas']);
    assert.deepEqual(operations, []);
});

test('invalid pinned topology is sanitized before any plan or worker call', async () => {
    const calls = [];
    const currentSnapshot = snapshot();
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: {
            async admitTopology({ prepare }) {
                calls.push({ method: 'admitTopology' });
                return prepare(currentSnapshot, fakeSession);
            },
        },
        planMaterializer: {
            async materialize(input) {
                calls.push({ method: 'materialize', input });
            },
        },
        operationRepository: {
            async createFrozen(input) {
                calls.push({ method: 'createFrozen', input });
            },
        },
        operationWorker: {
            async run(plan) {
                calls.push({ method: 'worker.run', plan });
            },
        },
        validator: () => ({
            valid: false,
            errors: [{
                code: 'INVALID_LINK',
                path: 'links[0]',
                diagnostic: 'ssh-password-canary',
            }],
        }),
        idFactory: () => 'operation-invalid',
    });

    await assert.rejects(
        coordinator.queue({ expectedTopologyRevision: 7 }),
        error => {
            assert.equal(error.code, 'INVALID_TOPOLOGY_DEPLOYMENT');
            assert.equal(error.operationId, 'operation-invalid');
            assert.deepEqual(error.errors, [{ code: 'INVALID_LINK', path: 'links[0]' }]);
            assert.doesNotMatch(JSON.stringify(error), /password|diagnostic|canary/i);
            return true;
        },
    );
    assert.deepEqual(calls.map(call => call.method), ['admitTopology']);
});

test('plan validation failures surface as 422 INVALID_TOPOLOGY_DEPLOYMENT with the reason', async () => {
    const { FrozenTopologyDeploymentPlanError } = require('../services/frozenTopologyDeploymentPlanComposer');
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: {
            async admitTopology(input) {
                return admitFakeSnapshot(snapshot(), input);
            },
        },
        planMaterializer: {
            async materialize() {
                throw new FrozenTopologyDeploymentPlanError(
                    'MISSING_TOPOLOGY_LINK',
                    'Topology v1 requires one link between every adjacent node',
                );
            },
        },
        operationRepository: {
            async createFrozen() {
                throw new Error('must not create an operation for an invalid plan');
            },
        },
        operationWorker: {
            async run() {
                throw new Error('must not start work for an invalid plan');
            },
        },
        validator: () => ({ valid: true, errors: [] }),
        idFactory: () => 'operation-incomplete-chain',
    });

    await assert.rejects(
        coordinator.queue({ expectedTopologyRevision: 7 }),
        error => {
            assert.equal(error.code, 'INVALID_TOPOLOGY_DEPLOYMENT');
            assert.equal(
                error.message,
                'Topology v1 requires one link between every adjacent node',
            );
            assert.equal(error.causeCode, 'MISSING_TOPOLOGY_LINK');
            return true;
        },
    );
});

test('duplicate frozen insert fails closed without acknowledging a different operation or running work', async () => {
    for (const existingStatus of ['succeeded', 'failed', 'rolled_back']) {
        const calls = [];
        const duplicate = new Error('E11000 duplicate key error');
        duplicate.code = 11000;
        const coordinator = new TopologyOperationCoordinator({
            topologyRepository: {
                async admitTopology(input) {
                    const { expectedRevision } = input;
                    calls.push({ method: 'admitTopology', expectedRevision });
                    return admitFakeSnapshot(snapshot(), input, 7);
                },
            },
            planMaterializer: {
                async materialize() {
                    calls.push({ method: 'materialize' });
                    return materializedPlan();
                },
            },
            operationRepository: {
                async createFrozen() {
                    calls.push({ method: 'createFrozen' });
                    throw duplicate;
                },
                async findAdmissionById(operationId) {
                    calls.push({ method: 'findAdmissionById', operationId });
                    return { status: existingStatus, topologyRevision: 7 };
                },
            },
            operationWorker: {
                async run(operationId) {
                    calls.push({ method: 'worker.run', operationId });
                },
            },
            validator: () => ({ valid: true, errors: [] }),
            compiler: () => ({ valid: true, errors: [], relays: [] }),
            idFactory: () => 'operation-dup',
        });

        await assert.rejects(coordinator.deploy({ expectedTopologyRevision: 7 }), error => {
            assert.equal(error.code, 'TOPOLOGY_OPERATION_QUEUE_FAILED');
            assert.doesNotMatch(error.message, /E11000|duplicate key/i);
            return true;
        });
        await Promise.resolve();

        assert.equal(calls.some(call => call.method === 'findAdmissionById'), false,
            'a duplicate insert is not an ambiguous commit and cannot acknowledge any existing record');
        assert.equal(calls.some(call => call.method === 'worker.run'), false,
            `worker must not re-run for an existing ${existingStatus} operation`);
    }
});

test('a cached idempotent result whose operation was purged (undeploy) is re-queued from scratch', async () => {
    const calls = [];
    let persisted = { status: 'succeeded', topologyRevision: 7 };
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: {
            async admitTopology(input) {
                const { expectedRevision } = input;
                calls.push({ method: 'admitTopology', expectedRevision });
                return admitFakeSnapshot(snapshot(), input);
            },
        },
        planMaterializer: {
            async materialize() {
                calls.push({ method: 'materialize' });
                return materializedPlan();
            },
        },
        operationRepository: {
            async createFrozen(input) {
                calls.push({ method: 'createFrozen', operationId: input.operationId, idempotencyKey: input.idempotencyKey });
                persisted = { status: 'queued', topologyRevision: 7 };
            },
            async findPublicById(operationId) {
                calls.push({ method: 'findPublicById', operationId });
                return persisted;
            },
        },
        operationWorker: {
            async run(operationId) {
                calls.push({ method: 'worker.run', operationId });
            },
        },
        validator: () => ({ valid: true, errors: [] }),
        compiler: () => ({ valid: true, errors: [], relays: [] }),
        idFactory: () => 'operation-purged',
    });

    const first = await coordinator.queue({ expectedTopologyRevision: 7 });
    assert.equal(first.status, 'queued');

    // Undeploy purges the operation record; the cached promise must not short-circuit.
    persisted = null;
    const second = await coordinator.queue({ expectedTopologyRevision: 7 });

    assert.deepEqual(second, {
        operationId: 'operation-purged',
        topologyRevision: 7,
        status: 'queued',
    });
    assert.equal(calls.filter(call => call.method === 'createFrozen').length, 2);
    assert.equal(calls.filter(call => call.method === 'worker.run').length, 2);
    const keys = calls
        .filter(call => call.method === 'createFrozen')
        .map(call => call.idempotencyKey);
    assert.ok(keys.every(key => /^topology:test:revision-7:[0-9a-f-]{36}$/.test(key)));
    assert.notEqual(keys[0], keys[1],
        'a re-queued operation must get a fresh idempotency key so node-side runner state does not collide');
});

test('projects a deterministic status without candidates, leases, backups, or invalid states', () => {
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: { async admitTopology() {} },
        planMaterializer: { async materialize() {} },
        operationRepository: { async createFrozen() {} },
    });
    const status = coordinator.projectStatus({
        _id: 'operation-status',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        status: 'preparing',
        leaseOwner: 'worker-secret',
        nodes: [
            {
                node: 'node-b',
                state: 'raw-secret-state',
                candidateHash: 'candidate-secret',
                backupId: 'backup-secret',
            },
            {
                node: 'node-a',
                state: 'prepared',
                candidate: { bytes: 'candidate-secret' },
            },
        ],
    });

    assert.deepEqual(status, {
        operationId: 'operation-status',
        topologyRevision: 7,
        status: 'preparing',
        nodes: [{ nodeId: 'node-a', state: 'prepared' }],
    });
    assert.doesNotMatch(JSON.stringify(status), /candidate|lease|worker|backup|secret/i);
});

// ---------------------------------------------------------------------------
// Scoped queueing: an explicit per-link autoDeploy event reconciles only the
// affected component. Confirmed-deployed links plus the explicitly requested
// link form the effective graph; preexisting pending links are never pulled
// in silently, even when they share a relay with the requested link.
// ---------------------------------------------------------------------------

function scopedSnapshot(overrides = {}) {
    return {
        revision: 8,
        deployedRevision: 5,
        nodes: [
            { _id: 'portal-1', cascadeRole: 'portal' },
            { _id: 'relay-1', cascadeRole: 'relay' },
            { _id: 'bridge-1', cascadeRole: 'bridge' },
            { _id: 'portal-2', cascadeRole: 'portal' },
        ],
        links: [
            {
                _id: 'link-pr',
                portalNode: 'portal-1',
                bridgeNode: 'relay-1',
                mode: 'reverse',
                active: true,
                status: 'pending',
            },
            {
                _id: 'link-rb',
                portalNode: 'relay-1',
                bridgeNode: 'bridge-1',
                mode: 'reverse',
                active: true,
                status: 'deployed',
            },
            {
                // Preexisting pending link on the same relay: never deployed
                // by the operator, so a scoped reconcile must exclude it.
                _id: 'link-pending',
                portalNode: 'portal-2',
                bridgeNode: 'relay-1',
                mode: 'reverse',
                active: true,
                status: 'pending',
            },
        ],
        groups: [],
        ...overrides,
    };
}

function scopedHarness(snapshotValue, calls = []) {
    return {
        topologyRepository: {
            async admitTopology(input) {
                const { expectedRevision } = input;
                calls.push({ method: 'admitTopology', expectedRevision });
                return admitFakeSnapshot(snapshotValue, input);
            },
        },
        planMaterializer: {
            async materialize(input) {
                calls.push({ method: 'materialize', input });
                return materializedPlan();
            },
        },
        operationRepository: {
            async createFrozen(input) {
                calls.push({ method: 'createFrozen', input });
                return { _id: input.operationId, status: 'queued', ...input };
            },
        },
        operationWorker: {
            async run(operationId) {
                calls.push({ method: 'worker.run', operationId });
                return { claimed: false, operationId };
            },
        },
        validator: () => ({ valid: true, errors: [] }),
        compiler: () => ({ valid: true, errors: [], relays: [] }),
        idFactory(idempotencyKey) {
            calls.push({ method: 'idFactory', idempotencyKey });
            return 'operation-scoped';
        },
    };
}

test('scoped queue pins only the requested component and never pulls in pending links', async () => {
    const calls = [];
    const snapshot = scopedSnapshot();
    snapshot.links[0].status = 'deployed';
    const coordinator = new TopologyOperationCoordinator(scopedHarness(snapshot, calls));

    const result = await coordinator.queue({
        expectedTopologyRevision: 8,
        scope: {
            kind: 'domain.reconcile',
            linkId: 'link-pr',
            linkIds: ['link-rb', 'link-pr'],
        },
    });
    await Promise.resolve();

    assert.equal(result.operationId, 'operation-scoped');
    assert.equal(result.status, 'queued');
    assert.equal(result.kind, 'domain.reconcile');
    assert.equal(result.linkId, 'link-pr');

    const materialize = calls.find(call => call.method === 'materialize');
    const topology = materialize.input.pinnedSnapshot.topology;
    assert.deepEqual(
        topology.links.map(link => link.id).sort(),
        ['link-pr', 'link-rb'],
        'the preexisting pending link must not enter the effective graph',
    );
    assert.deepEqual(
        topology.nodes.map(node => node.id).sort(),
        ['bridge-1', 'portal-1', 'relay-1'],
        'nodes of excluded pending links must not enter the scoped plan',
    );

    const frozen = calls.find(call => call.method === 'createFrozen');
    assert.equal(frozen.input.kind, 'domain.reconcile');
    assert.equal(frozen.input.linkId, 'link-pr');
    assert.deepEqual(frozen.input.linkIds, ['link-pr', 'link-rb']);
    assert.equal(calls.filter(call => call.method === 'worker.run').length, 1);

    const key = calls.find(call => call.method === 'idFactory').idempotencyKey;
    assert.ok(
        key.startsWith('topology:test:revision-8:domain.reconcile:'),
        `scoped idempotency key must be distinguishable from the legacy full sync key, got ${key}`,
    );
});

test('scoped queue rejects a preexisting pending link even when a caller includes its id', async () => {
    const calls = [];
    const coordinator = new TopologyOperationCoordinator(scopedHarness(scopedSnapshot(), calls));

    await assert.rejects(
        coordinator.queue({ expectedTopologyRevision: 8, scope: {
            kind: 'domain.reconcile', linkId: 'link-pr',
            linkIds: ['link-pr', 'link-rb', 'link-pending'],
        } }),
        error => error.code === 'INVALID_TOPOLOGY_DEPLOYMENT'
            && error.causeCode === 'SCOPE_LINK_UNCONFIRMED',
    );
    assert.equal(calls.filter(call => call.method === 'materialize').length, 0);
    assert.equal(calls.filter(call => call.method === 'createFrozen').length, 0);
    assert.equal(calls.filter(call => call.method === 'worker.run').length, 0);
});

test('scoped queue rejects a baseline link with raw undefined or null status', async () => {
    for (const kind of ['link.apply', 'domain.reconcile']) {
        for (const status of [undefined, null]) {
            const snapshot = scopedSnapshot();
            snapshot.links[0].status = 'deployed';
            snapshot.links[1].status = status;
            const calls = [];
            const coordinator = new TopologyOperationCoordinator(scopedHarness(snapshot, calls));
            await assert.rejects(coordinator.queue({ expectedTopologyRevision: 8, scope: {
                kind, linkId: 'link-pr', linkIds: ['link-pr', 'link-rb'],
            } }), error => error.code === 'INVALID_TOPOLOGY_DEPLOYMENT'
                && ['SCOPE_LINK_UNCONFIRMED', 'SCOPE_DOMAIN_AMBIGUOUS'].includes(error.causeCode));
            assert.equal(calls.filter(call => call.method === 'materialize').length, 0);
            assert.equal(calls.filter(call => call.method === 'createFrozen').length, 0);
        }
    }
});

test('domain reconcile refuses a pending anchor before materialization', async () => {
    const calls = [];
    const coordinator = new TopologyOperationCoordinator(scopedHarness(scopedSnapshot(), calls));
    await assert.rejects(coordinator.queue({ expectedTopologyRevision: 8, scope: {
        kind: 'domain.reconcile', linkId: 'link-pr', linkIds: ['link-pr', 'link-rb'],
    } }), error => error.code === 'INVALID_TOPOLOGY_DEPLOYMENT'
        && error.causeCode === 'SCOPE_LINK_UNCONFIRMED');
    assert.equal(calls.filter(call => call.method === 'createFrozen').length, 0);
});

test('domain reconcile refuses an omitted or foreign confirmed link in its pinned component', async () => {
    const snapshot = scopedSnapshot();
    snapshot.links[0].status = 'online';
    snapshot.nodes.push({ _id: 'portal-3', cascadeRole: 'portal' },
        { _id: 'bridge-3', cascadeRole: 'bridge' });
    snapshot.links.push({ _id: 'link-foreign', portalNode: 'portal-3',
        bridgeNode: 'bridge-3', active: true, status: 'deployed', mode: 'forward' });
    for (const linkIds of [['link-pr'], ['link-pr', 'link-rb', 'link-foreign']]) {
        const calls = [];
        const coordinator = new TopologyOperationCoordinator(scopedHarness(snapshot, calls));
        await assert.rejects(coordinator.queue({ expectedTopologyRevision: 8, scope: {
            kind: 'domain.reconcile', linkId: 'link-pr', linkIds,
        } }), error => error.code === 'INVALID_TOPOLOGY_DEPLOYMENT'
            && error.causeCode === 'SCOPE_DOMAIN_AMBIGUOUS');
        assert.equal(calls.filter(call => call.method === 'materialize').length, 0);
    }
});

test('domain reconcile pins mixed modes in one domain, excluding pending and independent domains', async () => {
    const snapshot = scopedSnapshot();
    snapshot.links[0].status = 'online';
    snapshot.links[0].mode = 'forward';
    snapshot.nodes.push({ _id: 'portal-3', cascadeRole: 'portal' },
        { _id: 'bridge-3', cascadeRole: 'bridge' });
    snapshot.links.push({ _id: 'link-foreign', portalNode: 'portal-3',
        bridgeNode: 'bridge-3', active: true, status: 'deployed', mode: 'forward' });
    const calls = [];
    const coordinator = new TopologyOperationCoordinator(scopedHarness(snapshot, calls));
    const result = await coordinator.queue({ expectedTopologyRevision: 8, scope: {
        kind: 'domain.reconcile', linkId: 'link-pr', linkIds: ['link-pr', 'link-rb'],
    } });
    assert.equal(result.kind, 'domain.reconcile');
    assert.deepEqual(calls.find(call => call.method === 'materialize').input.pinnedSnapshot.topology.links
        .map(link => [link.id, link.mode]), [['link-pr', 'forward'], ['link-rb', 'reverse']]);
    assert.deepEqual(calls.find(call => call.method === 'createFrozen').input.linkIds,
        ['link-pr', 'link-rb']);
});

test('scoped queue accepts a staged baseline link as physically applied', async () => {
    const calls = [];
    const snapshot = scopedSnapshot();
    // A previous link.apply applied portal-1 -> relay-1 to its endpoints but
    // the component is not client-ready yet: staged is a valid baseline,
    // unlike the old pending link on the same relay.
    snapshot.links[0].status = 'staged';
    snapshot.links.push({
        _id: 'link-new-hop',
        portalNode: 'relay-1',
        bridgeNode: 'bridge-1',
        mode: 'reverse',
        active: true,
        status: 'pending',
    });
    snapshot.links = snapshot.links.filter(link => link._id !== 'link-rb');
    const coordinator = new TopologyOperationCoordinator(scopedHarness(snapshot, calls));

    const result = await coordinator.queue({
        expectedTopologyRevision: 8,
        scope: {
            kind: 'link.apply',
            linkId: 'link-new-hop',
            linkIds: ['link-new-hop', 'link-pr'],
        },
    });
    await Promise.resolve();

    assert.equal(result.status, 'queued');
    const materialize = calls.find(call => call.method === 'materialize');
    assert.equal(materialize.input.operationKind, 'link.apply');
    const frozen = calls.find(call => call.method === 'createFrozen');
    assert.equal(frozen.input.staged, false);
    assert.deepEqual(
        materialize.input.pinnedSnapshot.topology.links.map(link => link.id).sort(),
        ['link-new-hop', 'link-pr'],
        'the staged first hop joins the effective graph; the pending shared-relay link stays out',
    );
});

test('scoped queue rejects an inactive requested link', async () => {
    const calls = [];
    const snapshot = scopedSnapshot();
    snapshot.links[0].active = false;
    const coordinator = new TopologyOperationCoordinator(scopedHarness(snapshot, calls));
    await assert.rejects(
        coordinator.queue({ expectedTopologyRevision: 8, scope: {
            kind: 'link.apply', linkId: 'link-pr', linkIds: ['link-pr'],
        } }),
        error => error.code === 'INVALID_TOPOLOGY_DEPLOYMENT'
            && error.causeCode === 'SCOPE_LINK_MISSING',
    );
    assert.equal(calls.filter(call => call.method === 'materialize').length, 0);
});

test('legacy unscoped queue keeps the full-sync idempotency key and records no scope', async () => {
    const calls = [];
    const allConfirmed = scopedSnapshot();
    allConfirmed.links.forEach(link => { link.status = 'deployed'; });
    const coordinator = new TopologyOperationCoordinator({
        ...scopedHarness(allConfirmed, calls),
        planMaterializer: {
            async materialize(input) {
                calls.push({ method: 'materialize', input });
                return {
                    nodes: [
                        { nodeRef: 'portal-1', role: 'portal', candidateHash: 'hash-1' },
                        { nodeRef: 'portal-2', role: 'portal', candidateHash: 'hash-2' },
                        { nodeRef: 'relay-1', role: 'relay', candidateHash: 'hash-3' },
                        { nodeRef: 'bridge', role: 'bridge', candidateHash: 'hash-4' },
                    ],
                };
            },
        },
    });

    await coordinator.queue({ expectedTopologyRevision: 8 });
    await Promise.resolve();

    const materialize = calls.find(call => call.method === 'materialize');
    assert.equal(materialize.input.pinnedSnapshot.topology.links.length, 3,
        'legacy full sync still sees every active link');
    const frozen = calls.find(call => call.method === 'createFrozen');
    assert.equal(frozen.input.kind, undefined);
    assert.equal(frozen.input.linkId, undefined);
    const key = calls.find(call => call.method === 'idFactory').idempotencyKey;
    assert.ok(key.startsWith('topology:test:revision-8:'),
        `legacy key must keep its shape, got ${key}`);
    assert.ok(!key.includes('domain.reconcile') && !key.includes('domain.sync'));
});

test('invalid operation scopes are rejected before any topology pin', async () => {
    const calls = [];
    const coordinator = new TopologyOperationCoordinator(scopedHarness(scopedSnapshot(), calls));

    for (const scope of [
        { kind: 'domain.nuke', linkId: 'link-pr', linkIds: ['link-pr'] },
        { kind: 'domain.reconcile', linkId: '', linkIds: ['link-pr'] },
        { kind: 'domain.reconcile', linkId: 'link-pr', linkIds: [] },
        { kind: 'domain.reconcile', linkId: 'link-pr', linkIds: ['link-rb'] },
        { kind: 'domain.reconcile', linkId: 'link-pr', linkIds: ['link-pr', 'link-pr'] },
        'domain.reconcile',
    ]) {
        await assert.rejects(
            coordinator.queue({ expectedTopologyRevision: 8, scope }),
            error => error?.code === 'INVALID_REQUEST',
            `scope ${JSON.stringify(scope)} must be rejected`,
        );
    }
    assert.equal(calls.filter(call => call.method === 'admitTopology').length, 0);
});

test('scope referencing a missing pinned link fails closed with SCOPE_LINK_MISSING', async () => {
    const calls = [];
    const coordinator = new TopologyOperationCoordinator(scopedHarness(scopedSnapshot(), calls));

    await assert.rejects(
        coordinator.queue({
            expectedTopologyRevision: 8,
            scope: { kind: 'link.apply', linkId: 'link-pr', linkIds: ['link-pr', 'link-gone'] },
        }),
        error => error?.code === 'INVALID_TOPOLOGY_DEPLOYMENT'
            && error?.causeCode === 'SCOPE_LINK_MISSING',
    );
    assert.equal(calls.filter(call => call.method === 'createFrozen').length, 0);
    assert.equal(calls.filter(call => call.method === 'worker.run').length, 0);
});

test('groups fully outside the scope are dropped; mixed groups fail with SCOPE_GROUP_CONFLICT', async () => {
    const withOutsideGroup = scopedSnapshot({
        groups: [{
            _id: 'group-outside',
            mode: 'reverse',
            paths: [{ pathKey: 'default', linkIds: ['link-pending'], priority: 100 }],
        }],
    });
    withOutsideGroup.links[0].status = 'deployed';
    const calls = [];
    const coordinator = new TopologyOperationCoordinator(scopedHarness(withOutsideGroup, calls));
    await coordinator.queue({
        expectedTopologyRevision: 8,
        scope: { kind: 'domain.reconcile', linkId: 'link-pr', linkIds: ['link-pr', 'link-rb'] },
    });
    const materialize = calls.find(call => call.method === 'materialize');
    assert.deepEqual(materialize.input.pinnedSnapshot.topology.groups, [],
        'a route group that only references other components must be excluded');

    const withMixedGroup = scopedSnapshot({
        groups: [{
            _id: 'group-mixed',
            mode: 'reverse',
            paths: [{ pathKey: 'default', linkIds: ['link-pr', 'link-pending'], priority: 100 }],
        }],
    });
    withMixedGroup.links[0].status = 'deployed';
    const mixedCalls = [];
    const mixedCoordinator = new TopologyOperationCoordinator(scopedHarness(withMixedGroup, mixedCalls));
    await assert.rejects(
        mixedCoordinator.queue({
            expectedTopologyRevision: 8,
            scope: { kind: 'domain.reconcile', linkId: 'link-pr', linkIds: ['link-pr', 'link-rb'] },
        }),
        error => error?.code === 'INVALID_TOPOLOGY_DEPLOYMENT'
            && error?.causeCode === 'SCOPE_GROUP_CONFLICT',
    );
    assert.equal(mixedCalls.filter(call => call.method === 'createFrozen').length, 0);
});

function attachSnapshot() {
    return {
        revision: 12, deployedRevision: 9,
        nodes: ['p', 'r1', 'r2', 'b', 'foreign'].map((id, index) => ({
            _id: id, cascadeRole: index === 0 || index === 4 ? 'portal'
                : index === 3 ? 'bridge' : 'relay',
        })),
        links: [
            { _id: 'zpr1', portalNode: 'p', bridgeNode: 'r1', mode: 'reverse', active: true, status: 'staged' },
            { _id: 'yr1r2', portalNode: 'r1', bridgeNode: 'r2', mode: 'reverse', active: true, status: 'staged' },
            { _id: 'ar2b', portalNode: 'r2', bridgeNode: 'b', mode: 'reverse', active: true, status: 'pending' },
            { _id: 'foreignr1', portalNode: 'foreign', bridgeNode: 'r1', mode: 'reverse', active: true, status: 'pending' },
        ],
        groups: [{ _id: 'g', mode: 'reverse', strategy: 'priority-failover', paths: [] }],
        activeRouteGroupIds: ['g'], installedRouteGroupIds: ['g'],
        installedRouteOwners: [{ groupId: 'g', nodeId: 'r1', pathKey: 'main',
            ownerTopologyRevision: 9, ownerCredentialRevision: 4 }],
    };
}

const attachRequest = { expectedTopologyRevision: 12,
    scope: { kind: 'link.apply', linkId: 'ar2b', linkIds: ['zpr1', 'yr1r2', 'ar2b'] } };

function attachHarness(snapshotValue, calls) {
    return {
        ...scopedHarness(snapshotValue, calls),
        planMaterializer: { async materialize(input) {
            calls.push({ method: 'materialize', input });
            return deepFreeze({ staged: false, nodes: [
                { nodeRef: 'portal', role: 'portal', candidateHash: 'p' },
                { nodeRef: 'relay-1', role: 'relay', candidateHash: 'r1' },
                { nodeRef: 'relay-2', role: 'relay', candidateHash: 'r2' },
                { nodeRef: 'bridge', role: 'bridge', candidateHash: 'b' },
            ] });
        } },
    };
}

test('third POST attaches a private installed-owner path from the transactional snapshot', async () => {
    const value = attachSnapshot();
    const before = structuredClone(value);
    const calls = [];
    const result = await new TopologyOperationCoordinator(attachHarness(value, calls)).queue(attachRequest);
    assert.deepEqual(value, before, 'queue must not publish the path in the group');
    assert.equal(result.kind, 'link.attach');
    assert.equal(result.ownerNodeId, 'r1');
    assert.equal(result.ownerTopologyRevision, 9);
    assert.equal(result.ownerCredentialRevision, 4);
    assert.deepEqual(result.newPathLinkIds, ['yr1r2', 'ar2b']);
    const materialize = calls.find(call => call.method === 'materialize').input;
    assert.equal(materialize.operationKind, 'link.attach');
    assert.deepEqual(materialize.pinnedSnapshot.topology.links.map(link => link.id), ['ar2b', 'yr1r2', 'zpr1']);
    assert.deepEqual(materialize.pinnedSnapshot.topology.groups[0].paths[0].linkIds, ['yr1r2', 'ar2b']);
    const frozen = calls.find(call => call.method === 'createFrozen').input;
    for (const field of ['kind', 'linkId', 'groupId', 'pathKey', 'ownerNodeId']) {
        assert.equal(frozen[field], result[field], field);
    }
    assert.deepEqual(frozen.linkIds, ['ar2b', 'yr1r2', 'zpr1']);
    assert.deepEqual(frozen.newPathLinkIds, ['yr1r2', 'ar2b']);
    assert.match(frozen.idempotencyKey, /:link\.attach:ar2b:/);
    assert(calls.some(call => call.method === 'idFactory'
        && call.idempotencyKey === frozen.idempotencyKey),
    'the operation ID must be derived from the effective transactional scope');
    assert.match(frozen.admissionFingerprint, /^[a-f0-9]{64}$/);
    assert.equal(frozen.staged, undefined, 'attach is distinct from staged apply');
    assert.equal(materialize.pinnedSnapshot.topology.links.some(link => link.id === 'foreignr1'), false);
});

test('first two staged POSTs remain link.apply even with an empty installed group', async () => {
    for (const [linkId, linkIds] of [
        ['zpr1', ['zpr1']], ['yr1r2', ['zpr1', 'yr1r2']],
    ]) {
        const value = attachSnapshot();
        value.links = value.links.filter(link => linkIds.includes(link._id));
        value.links.find(link => link._id === linkId).status = 'pending';
        const calls = [];
        const harness = scopedHarness(value, calls);
        harness.planMaterializer = { async materialize(input) {
            calls.push({ method: 'materialize', input });
            return { staged: true, nodes: [
                { nodeRef: 'portal', role: 'portal', candidateHash: 'p' },
                { nodeRef: 'relay-1', role: 'relay', candidateHash: 'r1' },
                ...(linkId === 'yr1r2'
                    ? [{ nodeRef: 'relay-2', role: 'relay', candidateHash: 'r2' }] : []),
            ] };
        } };
        const result = await new TopologyOperationCoordinator(harness)
            .queue({ expectedTopologyRevision: 12, scope: { kind: 'link.apply', linkId, linkIds } });
        assert.equal(result.kind, 'link.apply');
        assert.equal(calls.find(call => call.method === 'materialize').input.operationKind, 'link.apply');
        assert.equal(calls.find(call => call.method === 'createFrozen').input.kind, 'link.apply');
        assert.equal(calls.find(call => call.method === 'createFrozen').input.staged, true);
    }
});

test('attach fails closed on missing or ambiguous transactional owner identity', async () => {
    for (const change of [
        value => { delete value.installedRouteOwners[0].pathKey; },
        value => { delete value.installedRouteOwners[0].ownerTopologyRevision; },
        value => { delete value.installedRouteOwners[0].ownerCredentialRevision; },
        value => { value.installedRouteOwners.push({ ...value.installedRouteOwners[0] }); },
        value => { value.installedRouteOwners[0].nodeId = 'foreign'; },
    ]) {
        const value = attachSnapshot();
        change(value);
        const calls = [];
        await assert.rejects(new TopologyOperationCoordinator(attachHarness(value, calls))
            .queue(attachRequest), error => error.code === 'INVALID_TOPOLOGY_DEPLOYMENT');
        assert.equal(calls.some(call => call.method === 'createFrozen'), false);
        assert.equal(calls.some(call => call.method === 'worker.run'), false);
    }
});

test('attach rejects competing confirmed exits and foreign path ownership before admission', async () => {
    for (const change of [
        value => { value.links.push({ _id: 'competing', portalNode: 'r1', bridgeNode: 'b',
            mode: 'reverse', active: true, status: 'staged' }); },
        value => { value.groups.push({ _id: 'foreign-group', mode: 'reverse',
            paths: [{ pathKey: 'other', linkIds: ['yr1r2'], enabled: false }] }); },
    ]) {
        const value = attachSnapshot();
        change(value);
        const calls = [];
        await assert.rejects(new TopologyOperationCoordinator(attachHarness(value, calls))
            .queue(attachRequest), error => error.code === 'INVALID_TOPOLOGY_DEPLOYMENT');
        assert.equal(calls.some(call => call.method === 'createFrozen'), false);
    }
});

test('attach rejects a stale revision and caller-supplied owner/body fields', async () => {
    const calls = [];
    const harness = attachHarness(attachSnapshot(), calls);
    harness.topologyRepository = { async admitTopology() {
        const stale = new Error('private database detail');
        stale.code = 'STALE_TOPOLOGY_REVISION';
        stale.topologyRevision = 13;
        throw stale;
    } };
    await assert.rejects(new TopologyOperationCoordinator(harness).queue(attachRequest),
        error => error.code === 'STALE_TOPOLOGY_REVISION' && error.topologyRevision === 13);
    assert.equal(calls.some(call => call.method === 'createFrozen'), false);
    const valid = new TopologyOperationCoordinator(attachHarness(attachSnapshot(), calls));
    for (const input of [
        { ...attachRequest, groupId: 'g' },
        { ...attachRequest, scope: { ...attachRequest.scope, ownerNodeId: 'foreign' } },
        { ...attachRequest, scope: { ...attachRequest.scope, newPathLinkIds: ['ar2b'] } },
    ]) {
        await assert.rejects(valid.queue(input), error => error.code === 'INVALID_REQUEST');
    }
    assert.equal(calls.some(call => call.method === 'admitTopology'), false);
});

test('attach admission fingerprint and persisted key bind owner revisions and ordered suffix', async () => {
    const identities = [];
    for (const credentialRevision of [4, 5]) {
        const value = attachSnapshot();
        value.installedRouteOwners[0].ownerCredentialRevision = credentialRevision;
        const calls = [];
        await new TopologyOperationCoordinator(attachHarness(value, calls)).queue(attachRequest);
        identities.push(calls.find(call => call.method === 'createFrozen').input);
    }
    assert.notEqual(identities[0].admissionFingerprint, identities[1].admissionFingerprint);
    assert.notEqual(identities[0].idempotencyKey.slice(0, -36),
        identities[1].idempotencyKey.slice(0, -36));
    assert.deepEqual(identities[0].newPathLinkIds, ['yr1r2', 'ar2b']);
});

test('ambiguous attach commit acknowledges only the effective operation fingerprint', async () => {
    for (const matches of [true, false]) {
        const calls = [];
        const harness = attachHarness(attachSnapshot(), calls);
        const original = harness.topologyRepository;
        harness.topologyRepository = { async admitTopology(input) {
            await original.admitTopology(input);
            const error = new Error('private commit detail');
            error.hasErrorLabel = label => label === 'UnknownTransactionCommitResult';
            throw error;
        } };
        harness.operationRepository.findAdmissionById = async operationId => {
            const frozen = calls.find(call => call.method === 'createFrozen').input;
            assert.equal(operationId, frozen.operationId);
            return { _id: operationId, topologyRevision: 12, priorDeployedRevision: 9,
                heldTopologyAdmission: true, status: 'queued',
                admissionFingerprint: matches ? frozen.admissionFingerprint : '0'.repeat(64) };
        };
        const coordinator = new TopologyOperationCoordinator(harness);
        if (matches) {
            const result = await coordinator.queue(attachRequest);
            assert.equal(result.kind, 'link.attach');
            assert.deepEqual(result.newPathLinkIds, ['yr1r2', 'ar2b']);
        } else {
            await assert.rejects(coordinator.queue(attachRequest),
                error => error.code === 'TOPOLOGY_OPERATION_QUEUE_FAILED');
        }
        assert.equal(calls.some(call => call.method === 'worker.run'), false);
    }
});

test('attach admission requires durable repository support for ordered suffix and owner fence', async () => {
    let document;
    const repository = new TopologyOperationRepository({ model: {
        async create([input]) { document = input; return [{ _id: input._id }]; },
        findOneAndUpdate() {}, updateOne() {},
    } });
    await repository.createFrozen({
        operationId: 'a'.repeat(24), topologyRevision: 12, priorDeployedRevision: 9,
        nodes: [], kind: 'link.attach', linkId: 'a'.repeat(24),
        linkIds: ['a'.repeat(24), 'b'.repeat(24), 'c'.repeat(24)],
        groupId: 'd'.repeat(24), pathKey: 'main', ownerNodeId: 'e'.repeat(24),
        ownerTopologyRevision: 111, ownerCredentialRevision: 41,
        newPathLinkIds: ['b'.repeat(24), 'a'.repeat(24)],
        heldTopologyAdmission: true, admissionFingerprint: 'f'.repeat(64),
        session: fakeSession,
    });
    assert.equal(document.kind, 'link.attach');
    assert.equal(document.ownerTopologyRevision, 111);
    assert.equal(document.ownerCredentialRevision, 41);
    assert.deepEqual(document.newPathLinkIds, ['b'.repeat(24), 'a'.repeat(24)]);
});
