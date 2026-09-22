'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    TEST_TOPOLOGY_HOST_IDENTITY,
    TEST_TOPOLOGY_TARGET,
} = require('../services/topologyOperationPlanMaterializer');
const {
    TopologyOperationCoordinator,
} = require('../services/topologyOperationCoordinator');

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

test('queues one frozen fixed-test operation and starts only the injected worker', async () => {
    const calls = [];
    const currentSnapshot = snapshot();
    const topologyRepository = {
        async pinTopology({ expectedRevision, prepare }) {
            calls.push({ method: 'pinTopology', expectedRevision });
            const prepared = await prepare(currentSnapshot);
            return {
                revision: currentSnapshot.revision,
                deployedRevision: currentSnapshot.deployedRevision,
                ...prepared,
            };
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
        async run(plan) {
            calls.push({ method: 'worker.run', plan });
            return { claimed: false, operationId: plan.operationId };
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
        }],
        groups: [],
    });
    assert.deepEqual(calls.find(call => call.method === 'createFrozen').input, {
        operationId: 'operation-public',
        idempotencyKey: 'topology:test:revision-7',
        topologyRevision: 7,
        priorDeployedRevision: 5,
        nodes: calls.find(call => call.method === 'worker.run').plan.nodes,
    });
    const workerPlan = calls.find(call => call.method === 'worker.run').plan;
    assert.equal(Object.isFrozen(workerPlan), true);
    assert.deepEqual(workerPlan.nodes.map(node => ({
        node: node.node,
        candidateHash: node.candidateHash,
    })), [
        { node: 'bridge-1', candidateHash: 'bridge-hash' },
        { node: 'portal-1', candidateHash: 'portal-hash' },
    ]);
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
            async pinTopology(input) {
                calls.push({ method: 'pinTopology', input });
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
    assert.deepEqual(calls.map(call => call.method), ['pinTopology']);
});

test('invalid pinned topology is sanitized before any plan or worker call', async () => {
    const calls = [];
    const currentSnapshot = snapshot();
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: {
            async pinTopology({ prepare }) {
                calls.push({ method: 'pinTopology' });
                return prepare(currentSnapshot);
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
    assert.deepEqual(calls.map(call => call.method), ['pinTopology']);
});

test('projects a deterministic status without candidates, leases, backups, or invalid states', () => {
    const coordinator = new TopologyOperationCoordinator({
        topologyRepository: { async pinTopology() {} },
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
