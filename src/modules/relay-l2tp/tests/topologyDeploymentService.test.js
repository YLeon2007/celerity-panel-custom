'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    TopologyDeploymentService,
    createTopologyDeploymentService,
} = require('../services/topologyDeploymentService');

function validSnapshot() {
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
        groups: [{
            _id: 'group-1',
            mode: 'forward',
            strategy: 'priority-failover',
            paths: [{ pathKey: 'primary', linkIds: ['link-1'], priority: 1 }],
        }],
    };
}

function createNodeDeployer(calls = []) {
    return {
        async applyNode(input) {
            calls.push({ method: 'applyNode', input });
            return { ok: true, changed: false };
        },
        async verifyNode(input) {
            calls.push({ method: 'verifyNode', input });
            return { ok: true };
        },
        async rollbackNode(input) {
            calls.push({ method: 'rollbackNode', input });
            return { ok: true };
        },
    };
}

test('rejects a stale expected topology revision before any node side effect', async () => {
    const nodeCalls = [];
    const stale = new Error('mutable database details must not escape');
    stale.code = 'STALE_TOPOLOGY_REVISION';
    stale.expectedTopologyRevision = 6;
    stale.topologyRevision = 7;
    const repository = {
        async pinTopology({ expectedRevision }) {
            assert.equal(expectedRevision, 6);
            throw stale;
        },
        async markDeployed() {
            assert.fail('a stale deployment must not advance deployedRevision');
        },
    };
    const nodeDeployer = {
        async applyNode(input) {
            nodeCalls.push(input);
        },
        async verifyNode(input) {
            nodeCalls.push(input);
        },
        async rollbackNode(input) {
            nodeCalls.push(input);
        },
    };
    const service = new TopologyDeploymentService({
        repository,
        nodeDeployer,
        idFactory: () => 'operation-stale',
    });

    await assert.rejects(
        service.deploy({ expectedTopologyRevision: 6 }),
        error => {
            assert.equal(error.code, 'STALE_TOPOLOGY_REVISION');
            assert.equal(error.operationId, 'operation-stale');
            assert.equal(error.expectedTopologyRevision, 6);
            assert.equal(error.topologyRevision, 7);
            assert.doesNotMatch(error.message, /database details/);
            return true;
        },
    );
    assert.deepEqual(nodeCalls, []);
});

test('compile failure aborts the pinned full topology before deploying any node', async () => {
    const calls = [];
    let prepared = false;
    let markCalls = 0;
    const repository = {
        async pinTopology({ expectedRevision, prepare }) {
            assert.equal(expectedRevision, 7);
            const result = await prepare(validSnapshot());
            prepared = true;
            return { revision: 7, deployedRevision: 5, ...result };
        },
        async markDeployed() {
            markCalls += 1;
        },
    };
    const compilerInputs = [];
    const service = new TopologyDeploymentService({
        repository,
        nodeDeployer: createNodeDeployer(calls),
        validator: topology => {
            assert.deepEqual(topology.nodes.map(node => node.id), ['bridge-1', 'portal-1']);
            assert.deepEqual(topology.links.map(link => link.id), ['link-1']);
            assert.deepEqual(topology.groups.map(group => group._id), ['group-1']);
            return { valid: true, errors: [] };
        },
        compiler: topology => {
            compilerInputs.push(topology);
            return {
                valid: false,
                errors: [{ code: 'UNCOMPILABLE_ROUTE_GROUP', groupId: 'group-1' }],
                relays: [],
            };
        },
        idFactory: () => 'operation-compile-failure',
    });

    await assert.rejects(
        service.deploy({ expectedTopologyRevision: 7 }),
        error => {
            assert.equal(error.code, 'INVALID_TOPOLOGY_DEPLOYMENT');
            assert.equal(error.operationId, 'operation-compile-failure');
            assert.deepEqual(error.errors, [{
                code: 'UNCOMPILABLE_ROUTE_GROUP',
                groupId: 'group-1',
            }]);
            return true;
        },
    );
    assert.equal(prepared, false);
    assert.equal(compilerInputs.length, 1);
    assert.deepEqual(calls, []);
    assert.equal(markCalls, 0);
});

test('fails fast and rolls back only nodes changed by this deployment operation', async () => {
    const trace = [];
    let markCalls = 0;
    const snapshot = validSnapshot();
    const repository = {
        async pinTopology({ prepare }) {
            return {
                revision: snapshot.revision,
                deployedRevision: snapshot.deployedRevision,
                ...(await prepare(snapshot)),
            };
        },
        async markDeployed() {
            markCalls += 1;
        },
    };
    const nodeDeployer = {
        async applyNode(input) {
            trace.push({ method: 'applyNode', nodeId: input.nodeId, input });
            if (input.nodeId === 'bridge-1') {
                return {
                    ok: true,
                    changed: true,
                    rollbackToken: { secretBackupPath: '/must/not/escape' },
                };
            }
            return {
                ok: false,
                changed: false,
                failureCode: 'REMOTE_APPLY_FAILED',
                diagnostic: 'ssh password must not escape',
            };
        },
        async verifyNode(input) {
            trace.push({ method: 'verifyNode', nodeId: input.nodeId, input });
            return { ok: true, diagnostic: 'must not escape' };
        },
        async rollbackNode(input) {
            trace.push({ method: 'rollbackNode', nodeId: input.nodeId, input });
            return { ok: true };
        },
    };
    let nextId = 0;
    const service = new TopologyDeploymentService({
        repository,
        nodeDeployer,
        validator: () => ({ valid: true, errors: [] }),
        compiler: () => ({ valid: true, errors: [], relays: [] }),
        idFactory: kind => `${kind}-${++nextId}`,
    });

    await assert.rejects(
        service.deploy({ expectedTopologyRevision: 7 }),
        error => {
            assert.equal(error.code, 'NODE_DEPLOY_FAILED');
            assert.equal(error.operationId, 'operation-1');
            assert.equal(error.topologyRevision, 7);
            assert.equal(error.failedNodeId, 'portal-1');
            assert.deepEqual(error.changedNodeIds, ['bridge-1']);
            assert.deepEqual(error.rolledBackNodeIds, ['bridge-1']);
            assert.doesNotMatch(JSON.stringify(error), /password|secretBackupPath|must not escape/);
            return true;
        },
    );

    assert.deepEqual(trace.map(({ method, nodeId }) => ({ method, nodeId })), [
        { method: 'applyNode', nodeId: 'bridge-1' },
        { method: 'verifyNode', nodeId: 'bridge-1' },
        { method: 'applyNode', nodeId: 'portal-1' },
        { method: 'rollbackNode', nodeId: 'bridge-1' },
    ]);
    const rollback = trace.find(entry => entry.method === 'rollbackNode').input;
    assert.deepEqual(rollback.rollbackToken, { secretBackupPath: '/must/not/escape' });
    assert.equal(rollback.operationId, 'operation-1');
    assert.equal(rollback.topologyRevision, 7);
    assert.equal(markCalls, 0);
});

test('advances deployedRevision to the pinned revision only after every node verifies', async () => {
    const trace = [];
    const snapshot = validSnapshot();
    const repository = {
        async pinTopology({ expectedRevision, prepare }) {
            trace.push({ method: 'pinTopology', expectedRevision });
            return {
                revision: 7,
                deployedRevision: 5,
                ...(await prepare(snapshot)),
            };
        },
        async markDeployed(input) {
            trace.push({ method: 'markDeployed', input });
            return { revision: 7, deployedRevision: 7 };
        },
    };
    const nodeDeployer = {
        async applyNode(input) {
            trace.push({ method: 'applyNode', nodeId: input.nodeId });
            assert.equal(Object.isFrozen(input.topology), true);
            assert.equal(Object.isFrozen(input.compiledTopology), true);
            return input.nodeId === 'bridge-1'
                ? { ok: true, changed: true, rollbackToken: 'bridge-operation-backup' }
                : { ok: true, changed: false };
        },
        async verifyNode(input) {
            trace.push({ method: 'verifyNode', nodeId: input.nodeId });
            return { ok: true, remoteDiagnostic: 'must-not-be-returned' };
        },
        async rollbackNode(input) {
            trace.push({ method: 'rollbackNode', nodeId: input.nodeId });
            return { ok: true };
        },
    };
    const ids = [
        'operation-safe-id',
        'deploy-bridge-evidence',
        'verify-bridge-evidence',
        'deploy-portal-evidence',
        'verify-portal-evidence',
    ];
    const service = new TopologyDeploymentService({
        repository,
        nodeDeployer,
        validator: () => ({ valid: true, errors: [] }),
        compiler: () => ({
            valid: true,
            errors: [],
            relays: [],
            internalSecret: 'must-not-be-returned',
        }),
        idFactory: () => ids.shift(),
    });

    const result = await service.deploy({ expectedTopologyRevision: 7 });

    assert.deepEqual(trace.map(entry => entry.method), [
        'pinTopology',
        'applyNode',
        'verifyNode',
        'applyNode',
        'verifyNode',
        'markDeployed',
    ]);
    assert.deepEqual(trace.at(-1).input, {
        expectedRevision: 7,
        expectedDeployedRevision: 5,
    });
    assert.deepEqual(result, {
        operationId: 'operation-safe-id',
        topologyRevision: 7,
        deployedRevision: 7,
        nodeEvidence: [
            {
                nodeId: 'bridge-1',
                deploymentEvidenceId: 'deploy-bridge-evidence',
                verificationEvidenceId: 'verify-bridge-evidence',
            },
            {
                nodeId: 'portal-1',
                deploymentEvidenceId: 'deploy-portal-evidence',
                verificationEvidenceId: 'verify-portal-evidence',
            },
        ],
    });
    assert.doesNotMatch(JSON.stringify(result), /rollbackToken|internalSecret|remoteDiagnostic|backup/);
});

test('factory fails closed until all typed node deployment capabilities are registered', async () => {
    const service = createTopologyDeploymentService({
        cascadeNodeDeployer: { async deployNode() {} },
    });

    await assert.rejects(
        service.deploy({ expectedTopologyRevision: 7 }),
        error => {
            assert.equal(error.code, 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE');
            assert.equal(error.message, 'Topology deployment capabilities are unavailable');
            return true;
        },
    );
});

test('factory adapts typed node deployment capabilities without raw command inputs', async () => {
    const repositoryDependencies = [];
    const adapterCalls = [];
    const models = {
        HyNode: { model: 'nodes' },
        CascadeLink: { model: 'links' },
        CascadeRouteGroup: { model: 'groups' },
        CascadeTopologyState: { model: 'topology-state' },
        RelayL2tpState: { model: 'relay-state' },
    };
    const transactionRunner = async work => work({ id: 'factory-session' });
    class SnapshotRepository {
        constructor(dependencies) {
            repositoryDependencies.push({ kind: 'snapshot', dependencies });
        }

        async readDraft() {}
    }
    class DeploymentRepository {
        constructor(dependencies) {
            repositoryDependencies.push({ kind: 'deployment', dependencies });
            this.snapshotReader = dependencies.snapshotReader;
        }

        async pinTopology() {}

        async markDeployed() {}
    }
    const cascadeNodeDeployer = {
        async deployNode(input) {
            adapterCalls.push({ method: 'deployNode', input });
            return { ok: true, changed: true, rollbackToken: 'typed-backup' };
        },
    };
    const cascadeNodeVerifier = {
        async verifyNode(input) {
            adapterCalls.push({ method: 'verifyNode', input });
            return { ok: true };
        },
    };
    const cascadeNodeRestorer = {
        async restoreNode(input) {
            adapterCalls.push({ method: 'restoreNode', input });
            return { ok: true };
        },
    };

    const service = createTopologyDeploymentService({
        ...models,
        cascadeNodeDeployer,
        cascadeNodeVerifier,
        cascadeNodeRestorer,
        transactionRunner,
        SnapshotRepository,
        DeploymentRepository,
    });
    const typedInput = {
        operationId: 'operation-factory',
        topologyRevision: 9,
        nodeId: 'node-1',
        node: { id: 'node-1', cascadeRole: 'relay' },
        topology: { nodes: [], links: [], groups: [] },
        compiledTopology: { valid: true, relays: [] },
    };
    const rollbackInput = {
        operationId: 'operation-factory',
        topologyRevision: 9,
        nodeId: 'node-1',
        rollbackToken: 'typed-backup',
    };

    assert.deepEqual(await service.nodeDeployer.applyNode(typedInput), {
        ok: true,
        changed: true,
        rollbackToken: 'typed-backup',
    });
    assert.deepEqual(await service.nodeDeployer.verifyNode(typedInput), { ok: true });
    assert.deepEqual(await service.nodeDeployer.rollbackNode(rollbackInput), { ok: true });

    assert.deepEqual(adapterCalls, [
        { method: 'deployNode', input: typedInput },
        { method: 'verifyNode', input: typedInput },
        { method: 'restoreNode', input: rollbackInput },
    ]);
    assert.equal(
        adapterCalls.some(call => Object.keys(call.input).some(key => (
            ['command', 'args', 'argv', 'shell', 'stdin'].includes(key)
        ))),
        false,
    );
    assert.deepEqual(repositoryDependencies, [
        {
            kind: 'snapshot',
            dependencies: { ...models, transactionRunner },
        },
        {
            kind: 'deployment',
            dependencies: {
                snapshotReader: service.repository.snapshotReader,
                CascadeTopologyState: models.CascadeTopologyState,
                transactionRunner,
            },
        },
    ]);
});
