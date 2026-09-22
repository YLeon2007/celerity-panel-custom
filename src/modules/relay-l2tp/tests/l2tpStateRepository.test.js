'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    createL2tpServiceRepositoryAdapters,
    L2tpStateRepository,
    NODE_SAFE_SELECT,
    OPERATION_SAFE_SELECT,
    STATE_SAFE_SELECT,
} = require('../repositories/l2tpStateRepository');

function createQueryModel(result = null) {
    const calls = [];

    function query() {
        return {
            select(paths) {
                calls.push({ method: 'select', paths });
                return this;
            },
            lean(options) {
                calls.push({ method: 'lean', options });
                return Promise.resolve(result);
            },
        };
    }

    return {
        calls,
        findById(id) {
            calls.push({ method: 'findById', id });
            return query();
        },
        findOne(filter) {
            calls.push({ method: 'findOne', filter });
            return query();
        },
        async create(fields) {
            calls.push({ method: 'create', fields });
            return result;
        },
    };
}

function createRepository(overrides = {}) {
    return new L2tpStateRepository({
        HyNode: overrides.HyNode || createQueryModel(),
        RelayL2tpState: overrides.RelayL2tpState || createQueryModel(),
        CascadeRouteGroup: overrides.CascadeRouteGroup || createQueryModel(),
        CascadeTopologyState: overrides.CascadeTopologyState || createQueryModel(),
        L2tpOperation: overrides.L2tpOperation || createQueryModel(),
        compilerData: overrides.compilerData || { relays: [] },
        topologyRuntime: overrides.topologyRuntime,
    });
}

test('service adapters expose the repository method names expected by L2tpService', async () => {
    const calls = [];
    const repository = {
        async findNodeById(id) { calls.push(['findNodeById', id]); return 'node'; },
        async findByNodeId(id) { calls.push(['findByNodeId', id]); return 'state'; },
        async findRouteGroupById(id) { calls.push(['findRouteGroupById', id]); return 'group'; },
        async getTopologyRevision() { calls.push(['getTopologyRevision']); return 17; },
        async getRelayGroupPlan(nodeId, groupId) {
            calls.push(['getRelayGroupPlan', nodeId, groupId]);
            return 'relay-plan';
        },
        async findOperation(id) { calls.push(['findOperation', id]); return 'operation'; },
        async createQueuedOperation(input) {
            calls.push(['createQueuedOperation', input]);
            return 'created-operation';
        },
    };
    const { nodeRepository, stateRepository, operationRepository }
        = createL2tpServiceRepositoryAdapters(repository);
    const operationInput = { node: 'relay-1', plan: { steps: [{ type: 'verify' }] } };

    assert.equal(await nodeRepository.findById('relay-1'), 'node');
    assert.equal(await stateRepository.findByNodeId('relay-1'), 'state');
    assert.equal(await stateRepository.findRouteGroupById('group-a'), 'group');
    assert.equal(await stateRepository.getTopologyRevision(), 17);
    assert.equal(await stateRepository.getRelayGroupPlan('relay-1', 'group-a'), 'relay-plan');
    assert.equal(await operationRepository.findById('operation-1'), 'operation');
    assert.equal(await operationRepository.create(operationInput), 'created-operation');
    assert.deepEqual(calls, [
        ['findNodeById', 'relay-1'],
        ['findByNodeId', 'relay-1'],
        ['findRouteGroupById', 'group-a'],
        ['getTopologyRevision'],
        ['getRelayGroupPlan', 'relay-1', 'group-a'],
        ['findOperation', 'operation-1'],
        ['createQueuedOperation', operationInput],
    ]);
});

test('findNodeById returns a lean node without password-bearing fields', async () => {
    const node = { _id: 'relay-1', cascadeRole: 'relay' };
    const HyNode = createQueryModel(node);
    const repository = createRepository({ HyNode });

    assert.strictEqual(await repository.findNodeById('relay-1'), node);
    assert.equal(typeof NODE_SAFE_SELECT, 'string');
    for (const path of ['-obfs.password', '-outbounds.password', '-ssh.password']) {
        assert.ok(NODE_SAFE_SELECT.split(/\s+/).includes(path), path);
    }
    assert.deepEqual(HyNode.calls, [
        { method: 'findById', id: 'relay-1' },
        { method: 'select', paths: NODE_SAFE_SELECT },
        { method: 'lean', options: undefined },
    ]);
});

test('findByNodeId returns lean L2TP state with encrypted PSK excluded explicitly', async () => {
    const state = { node: 'relay-1', status: 'installed' };
    const RelayL2tpState = createQueryModel(state);
    const repository = createRepository({ RelayL2tpState });

    assert.strictEqual(await repository.findByNodeId('relay-1'), state);
    assert.equal(STATE_SAFE_SELECT, '-pskEncrypted');
    assert.deepEqual(RelayL2tpState.calls, [
        { method: 'findOne', filter: { node: 'relay-1' } },
        { method: 'select', paths: STATE_SAFE_SELECT },
        { method: 'lean', options: undefined },
    ]);
});

test('findRouteGroupById returns a lean route group without mutating it', async () => {
    const routeGroup = { _id: 'group-a', paths: [] };
    const CascadeRouteGroup = createQueryModel(routeGroup);
    const repository = createRepository({ CascadeRouteGroup });

    assert.strictEqual(await repository.findRouteGroupById('group-a'), routeGroup);
    assert.deepEqual(CascadeRouteGroup.calls, [
        { method: 'findById', id: 'group-a' },
        { method: 'lean', options: undefined },
    ]);
});

test('getTopologyRevision reads only the singleton revision', async () => {
    const CascadeTopologyState = createQueryModel({ revision: 17 });
    const repository = createRepository({ CascadeTopologyState });

    assert.equal(await repository.getTopologyRevision(), 17);
    assert.deepEqual(CascadeTopologyState.calls, [
        { method: 'findById', id: 'singleton' },
        { method: 'select', paths: 'revision' },
        { method: 'lean', options: undefined },
    ]);
});

test('getTopologyRevision defaults to zero without creating missing state', async () => {
    const CascadeTopologyState = createQueryModel(null);
    const repository = createRepository({ CascadeTopologyState });

    assert.equal(await repository.getTopologyRevision(), 0);
    assert.equal(CascadeTopologyState.calls.some(call => call.method === 'create'), false);
});

test('getRelayGroupPlan returns the requested route group from injected compiler data', async () => {
    const expectedPlan = {
        groupId: 'group-b',
        candidates: [{ pathKey: 'secondary' }],
        decision: { decision: 'select', pathKey: 'secondary' },
    };
    const compilerData = {
        relays: [
            { nodeId: 'relay-2', routeGroups: [{ groupId: 'group-a' }] },
            {
                nodeId: 'relay-1',
                routeGroups: [
                    { groupId: 'group-a' },
                    expectedPlan,
                ],
            },
        ],
    };
    const repository = createRepository({ compilerData });

    assert.strictEqual(
        await repository.getRelayGroupPlan('relay-1', 'group-b'),
        expectedPlan,
    );
});

test('getRelayGroupPlan delegates to an injected topology runtime instead of static data', async () => {
    const calls = [];
    const runtimePlan = {
        groupId: 'group-live',
        candidates: [],
        decision: { decision: 'block', error: { code: 'NO_HEALTHY_PATH' } },
    };
    const topologyRuntime = {
        async getRelayGroupPlan(relayId, groupId) {
            calls.push({ relayId, groupId });
            return runtimePlan;
        },
    };
    const repository = createRepository({
        topologyRuntime,
        compilerData: {
            relays: [{
                nodeId: 'relay-1',
                routeGroups: [{ groupId: 'group-static' }],
            }],
        },
    });

    const result = await repository.getRelayGroupPlan('relay-1', 'group-live');

    assert.strictEqual(result, runtimePlan);
    assert.deepEqual(calls, [{ relayId: 'relay-1', groupId: 'group-live' }]);
});

test('findOperation returns a lean operation through an explicit secret-free allowlist', async () => {
    const operation = {
        _id: 'operation-1',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    };
    const L2tpOperation = createQueryModel(operation);
    const repository = createRepository({ L2tpOperation });

    assert.deepEqual(await repository.findOperation('operation-1'), operation);

    const selectedPaths = OPERATION_SAFE_SELECT.split(/\s+/);
    for (const path of ['_id', 'node', 'status', 'progress', 'plan', 'topologyRevision', 'routeGroupId']) {
        assert.ok(selectedPaths.includes(path), `${path} should be readable`);
    }
    for (const secretPath of ['psk', 'password', 'pskEncrypted']) {
        assert.equal(selectedPaths.includes(secretPath), false, `${secretPath} must not be readable`);
    }
    assert.ok(selectedPaths.every(path => !path.startsWith('-')), 'projection must be an allowlist');
    assert.deepEqual(L2tpOperation.calls, [
        { method: 'findById', id: 'operation-1' },
        { method: 'select', paths: OPERATION_SAFE_SELECT },
        { method: 'lean', options: undefined },
    ]);
});

test('findOperation strips plaintext secrets from legacy operation data', async () => {
    const L2tpOperation = createQueryModel({
        _id: 'operation-legacy',
        status: 'queued',
        progress: 0,
        psk: 'top-level-psk',
        password: 'top-level-password',
        plan: {
            ok: true,
            steps: [{ type: 'verify', password: 'step-password' }],
            psk: 'plan-psk',
        },
        logs: [{
            at: new Date('2026-09-22T10:00:00.000Z'),
            level: 'info',
            code: 'QUEUED',
            message: 'Operation queued',
            password: 'log-password',
        }],
    });
    const repository = createRepository({ L2tpOperation });

    const operation = await repository.findOperation('operation-legacy');

    assert.deepEqual(operation, {
        _id: 'operation-legacy',
        status: 'queued',
        progress: 0,
        plan: {
            ok: true,
            steps: [{ type: 'verify' }],
        },
        logs: [{
            at: new Date('2026-09-22T10:00:00.000Z'),
            level: 'info',
            code: 'QUEUED',
            message: 'Operation queued',
        }],
    });
    assert.doesNotMatch(JSON.stringify(operation), /psk|password/i);
});

test('createQueuedOperation persists a durable secret-free plan from explicit fields only', async () => {
    const createdOperation = { _id: '507f1f77bcf86cd799439011', status: 'queued' };
    const L2tpOperation = createQueryModel(createdOperation);
    const repository = createRepository({ L2tpOperation });
    const plan = {
        ok: true,
        operationId: '507f1f77bcf86cd799439011',
        topologyRevision: 17,
        relayId: 'relay-1',
        routeGroupId: 'group-a',
        selectedPathKey: 'primary',
        nextHopNodeId: 'bridge-1',
        desired: {
            clientCidr: '10.77.0.0/24',
            localAddress: '10.77.0.1',
            poolStart: '10.77.0.10',
            poolEnd: '10.77.0.200',
            dnsServers: ['1.1.1.1'],
            tproxyPort: 12345,
            fwmark: 77,
            routeTable: 177,
            credentialRevision: 9,
            psk: 'desired-psk',
        },
        steps: [
            {
                type: 'preflight',
                artifacts: [{
                    type: 'desired',
                    path: 'desired.json',
                    content: '{"psk":"nested-password"}',
                }],
                password: 'nested-password',
            },
            { type: 'verify' },
        ],
        psk: 'nested-psk',
        password: 'nested-password',
        unknown: 'must-not-be-stored',
    };

    const result = await repository.createQueuedOperation({
        _id: '507f1f77bcf86cd799439011',
        node: 'relay-1',
        kind: 'install',
        idempotencyKey: 'install:relay-1:17',
        requestedBy: 'admin-1',
        topologyRevision: 17,
        routeGroupId: 'group-a',
        plan,
        status: 'succeeded',
        progress: 100,
        psk: 'must-not-be-stored',
        password: 'must-not-be-stored',
        unknown: 'must-not-be-stored',
    });

    assert.strictEqual(result, createdOperation);
    assert.deepEqual(L2tpOperation.calls, [{
        method: 'create',
        fields: {
            _id: '507f1f77bcf86cd799439011',
            node: 'relay-1',
            kind: 'install',
            status: 'queued',
            idempotencyKey: 'install:relay-1:17',
            requestedBy: 'admin-1',
            topologyRevision: 17,
            routeGroupId: 'group-a',
            plan: {
                ok: true,
                operationId: '507f1f77bcf86cd799439011',
                topologyRevision: 17,
                relayId: 'relay-1',
                routeGroupId: 'group-a',
                selectedPathKey: 'primary',
                nextHopNodeId: 'bridge-1',
                desired: {
                    clientCidr: '10.77.0.0/24',
                    localAddress: '10.77.0.1',
                    poolStart: '10.77.0.10',
                    poolEnd: '10.77.0.200',
                    dnsServers: ['1.1.1.1'],
                    tproxyPort: 12345,
                    fwmark: 77,
                    routeTable: 177,
                    credentialRevision: 9,
                },
                steps: [{
                    type: 'preflight',
                    artifacts: [{ type: 'desired', path: 'desired.json' }],
                }, { type: 'verify' }],
            },
        },
    }]);
    assert.equal(plan.psk, 'nested-psk', 'input plan must not be mutated');
});
