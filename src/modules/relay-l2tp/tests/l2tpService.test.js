'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { L2tpService } = require('../services/l2tpService');

const NOW = new Date('2026-09-22T10:00:00.000Z');

function createService(overrides = {}) {
    return new L2tpService({
        nodeRepository: overrides.nodeRepository || {
            async findById() { return null; },
        },
        stateRepository: overrides.stateRepository || {
            async findByNodeId() { return null; },
        },
        operationRepository: overrides.operationRepository || {},
        planBuilder: overrides.planBuilder || (() => ({ ok: true, steps: [] })),
        preflightRunner: overrides.preflightRunner || (async () => ({ ok: true, checks: [] })),
        clock: overrides.clock || { now: () => new Date(NOW) },
    });
}

test('status returns a safe projection of the stored L2TP state', async () => {
    const service = createService({
        nodeRepository: {
            async findById(nodeId) {
                assert.equal(nodeId, 'relay-1');
                return { id: nodeId, cascadeRole: 'relay' };
            },
        },
        stateRepository: {
            async findByNodeId(nodeId) {
                assert.equal(nodeId, 'relay-1');
                return {
                    node: nodeId,
                    desiredState: 'installed',
                    status: 'installed',
                    routeGroup: 'group-a',
                    operationId: 'operation-9',
                    appliedTopologyRevision: 9,
                    lastErrorCode: '',
                    pskEncrypted: 'must-not-leak',
                };
            },
        },
    });

    assert.deepEqual(await service.status('relay-1'), {
        nodeId: 'relay-1',
        role: 'relay',
        desiredState: 'installed',
        status: 'installed',
        routeGroupId: 'group-a',
        operationId: 'operation-9',
        appliedTopologyRevision: 9,
        lastErrorCode: '',
    });
});

test('status rejects an unknown node with a structured not-found error', async () => {
    let stateLookups = 0;
    const service = createService({
        stateRepository: {
            async findByNodeId() {
                stateLookups += 1;
                return null;
            },
        },
    });

    await assert.rejects(
        service.status('missing-node'),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'NODE_NOT_FOUND');
            assert.equal(error.nodeId, 'missing-node');
            return true;
        },
    );
    assert.equal(stateLookups, 0);
});

test('getStatus exposes the status contract expected by the route factory', async () => {
    const service = createService({
        nodeRepository: {
            async findById() { return { id: 'relay-route', cascadeRole: 'relay' }; },
        },
        stateRepository: {
            async findByNodeId() {
                return { desiredState: 'installed', status: 'queued' };
            },
        },
    });

    assert.deepEqual(await service.getStatus('relay-route'), {
        nodeId: 'relay-route',
        role: 'relay',
        desiredState: 'installed',
        status: 'queued',
        routeGroupId: null,
        operationId: null,
        appliedTopologyRevision: null,
        lastErrorCode: '',
    });
});

test('getOperation returns the durable operation by id', async () => {
    const operation = {
        id: 'operation-11',
        status: 'running',
        progress: 50,
    };
    const service = createService({
        operationRepository: {
            async findById(operationId) {
                assert.equal(operationId, 'operation-11');
                return operation;
            },
        },
    });

    assert.strictEqual(await service.getOperation('operation-11'), operation);
});

test('getOperation rejects an unknown durable operation with a structured code', async () => {
    const service = createService({
        operationRepository: {
            async findById() { return null; },
        },
    });

    await assert.rejects(
        service.getOperation('operation-missing'),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'OPERATION_NOT_FOUND');
            assert.equal(error.operationId, 'operation-missing');
            return true;
        },
    );
});

function installContext(overrides = {}) {
    return {
        node: { id: 'relay-1', cascadeRole: 'relay' },
        state: {
            node: 'relay-1',
            desiredState: 'installed',
            status: 'not_installed',
            routeGroup: 'group-a',
            clientCidr: '10.66.0.0/24',
            dnsServers: ['9.9.9.9'],
        },
        routeGroup: { id: 'group-a', name: 'primary' },
        topologyRevision: 17,
        relayGroupPlan: {
            groupId: 'group-a',
            candidates: [{ pathKey: 'primary', healthy: true, nextHopNodeId: 'bridge-1' }],
            decision: {
                decision: 'select',
                groupId: 'group-a',
                pathKey: 'primary',
                nextHopNodeId: 'bridge-1',
            },
        },
        input: {
            clientCidr: '10.77.0.0/24',
            dnsServers: ['1.1.1.1'],
            routeGroupId: 'group-a',
            expectedTopologyRevision: 17,
        },
        ...overrides,
    };
}

function createContextRepositories(context = installContext()) {
    return {
        nodeRepository: {
            async findById(nodeId) {
                return nodeId === context.node.id ? context.node : null;
            },
        },
        stateRepository: {
            async findByNodeId(nodeId) {
                return nodeId === context.node.id ? context.state : null;
            },
            async findRouteGroupById(routeGroupId) {
                return routeGroupId === context.routeGroup.id ? context.routeGroup : null;
            },
            async getTopologyRevision() {
                return context.topologyRevision;
            },
            async getRelayGroupPlan(nodeId, routeGroupId) {
                assert.equal(nodeId, context.node.id);
                assert.equal(routeGroupId, context.routeGroup.id);
                return context.relayGroupPlan;
            },
        },
    };
}

test('preflight validates injected state and delegates to the injected runner', async () => {
    const context = installContext();
    const repositories = createContextRepositories(context);
    const expectedResult = { ok: true, checks: [{ code: 'OS_SUPPORTED', ok: true }] };
    const calls = [];
    const service = createService({
        ...repositories,
        preflightRunner: async request => {
            calls.push(request);
            return expectedResult;
        },
    });

    assert.strictEqual(await service.preflight(context.node.id, context.input), expectedResult);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0], {
        node: context.node,
        relay: { ...context.node, role: 'relay' },
        state: context.state,
        desired: {
            ...context.state,
            clientCidr: context.input.clientCidr,
            dnsServers: context.input.dnsServers,
            routeGroup: 'group-a',
        },
        routeGroup: context.routeGroup,
        relayGroupPlan: context.relayGroupPlan,
        topologyRevision: 17,
        input: context.input,
    });
});

test('preflight rejects a non-relay node before loading L2TP state', async () => {
    let stateLookups = 0;
    const context = installContext({ node: { id: 'bridge-1', cascadeRole: 'bridge' } });
    const service = createService({
        nodeRepository: {
            async findById() { return context.node; },
        },
        stateRepository: {
            async findByNodeId() {
                stateLookups += 1;
                return context.state;
            },
        },
    });

    await assert.rejects(
        service.preflight(context.node.id, context.input),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'NODE_NOT_RELAY');
            assert.equal(error.nodeId, 'bridge-1');
            assert.equal(error.role, 'bridge');
            return true;
        },
    );
    assert.equal(stateLookups, 0);
});

test('preflight rejects an unknown node with NODE_NOT_FOUND', async () => {
    const context = installContext();
    const service = createService();

    await assert.rejects(
        service.preflight('missing-node', context.input),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'NODE_NOT_FOUND');
            assert.equal(error.nodeId, 'missing-node');
            return true;
        },
    );
});

test('preflight rejects a desired state other than installed before route lookup', async () => {
    let routeLookups = 0;
    const context = installContext({
        state: {
            node: 'relay-1',
            desiredState: 'absent',
            status: 'not_installed',
            routeGroup: null,
        },
    });
    const service = createService({
        nodeRepository: {
            async findById() { return context.node; },
        },
        stateRepository: {
            async findByNodeId() { return context.state; },
            async findRouteGroupById() {
                routeLookups += 1;
                return context.routeGroup;
            },
        },
    });

    await assert.rejects(
        service.preflight(context.node.id, context.input),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'DESIRED_STATE_NOT_INSTALLED');
            assert.equal(error.desiredState, 'absent');
            return true;
        },
    );
    assert.equal(routeLookups, 0);
});

test('preflight requires an explicit route group before repository lookup', async () => {
    let routeLookups = 0;
    const context = installContext();
    const service = createService({
        nodeRepository: {
            async findById() { return context.node; },
        },
        stateRepository: {
            async findByNodeId() { return context.state; },
            async findRouteGroupById() {
                routeLookups += 1;
                return context.routeGroup;
            },
        },
    });

    await assert.rejects(
        service.preflight(context.node.id, {
            ...context.input,
            routeGroupId: undefined,
        }),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'ROUTE_GROUP_REQUIRED');
            return true;
        },
    );
    assert.equal(routeLookups, 0);
});

test('install rejects a missing route group with a structured error', async () => {
    const context = installContext();
    let routeLookups = 0;
    let planCalls = 0;
    const service = createService({
        nodeRepository: {
            async findById() { return context.node; },
        },
        stateRepository: {
            async findByNodeId() { return context.state; },
            async findRouteGroupById() {
                routeLookups += 1;
                return context.routeGroup;
            },
        },
        planBuilder: () => {
            planCalls += 1;
            return { ok: true, steps: [] };
        },
    });

    await assert.rejects(
        service.install(context.node.id, {
            ...context.input,
            routeGroupId: undefined,
        }),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'ROUTE_GROUP_REQUIRED');
            assert.equal(error.nodeId, 'relay-1');
            return true;
        },
    );
    assert.equal(routeLookups, 0);
    assert.equal(planCalls, 0);
});

test('install requires an explicit integer topology revision', async () => {
    const context = installContext();
    let routeLookups = 0;
    let planCalls = 0;
    const service = createService({
        nodeRepository: {
            async findById() { return context.node; },
        },
        stateRepository: {
            async findByNodeId() { return context.state; },
            async findRouteGroupById() {
                routeLookups += 1;
                return context.routeGroup;
            },
        },
        planBuilder: () => {
            planCalls += 1;
            return { ok: true, steps: [] };
        },
    });

    await assert.rejects(
        service.install(context.node.id, {
            ...context.input,
            expectedTopologyRevision: '17',
        }),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'INVALID_TOPOLOGY_REVISION');
            assert.equal(error.nodeId, 'relay-1');
            assert.equal(error.expectedTopologyRevision, '17');
            return true;
        },
    );
    assert.equal(routeLookups, 0);
    assert.equal(planCalls, 0);
});

test('install rejects an unknown route group before topology or planning', async () => {
    const context = installContext();
    let topologyLookups = 0;
    let relayPlanLookups = 0;
    let planCalls = 0;
    const service = createService({
        nodeRepository: {
            async findById() { return context.node; },
        },
        stateRepository: {
            async findByNodeId() { return context.state; },
            async findRouteGroupById() { return null; },
            async getTopologyRevision() {
                topologyLookups += 1;
                return context.topologyRevision;
            },
            async getRelayGroupPlan() {
                relayPlanLookups += 1;
                return context.relayGroupPlan;
            },
        },
        planBuilder: () => {
            planCalls += 1;
            return { ok: true, steps: [] };
        },
    });

    await assert.rejects(
        service.install(context.node.id, context.input),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'ROUTE_GROUP_NOT_FOUND');
            assert.equal(error.nodeId, 'relay-1');
            assert.equal(error.routeGroupId, 'group-a');
            return true;
        },
    );
    assert.equal(topologyLookups, 0);
    assert.equal(relayPlanLookups, 0);
    assert.equal(planCalls, 0);
});

test('install rejects a stale topology revision before relay-plan, preflight, or planning', async () => {
    const context = installContext();
    let relayPlanLookups = 0;
    let preflightCalls = 0;
    let planCalls = 0;
    let operationCreates = 0;
    const service = createService({
        nodeRepository: {
            async findById() { return context.node; },
        },
        stateRepository: {
            async findByNodeId() { return context.state; },
            async findRouteGroupById() { return context.routeGroup; },
            async getTopologyRevision() { return context.topologyRevision; },
            async getRelayGroupPlan() {
                relayPlanLookups += 1;
                return context.relayGroupPlan;
            },
        },
        preflightRunner: async () => {
            preflightCalls += 1;
            return { ok: true };
        },
        planBuilder: () => {
            planCalls += 1;
            return { ok: true, steps: [] };
        },
        operationRepository: {
            async create() { operationCreates += 1; },
        },
    });

    await assert.rejects(
        service.install(context.node.id, {
            ...context.input,
            expectedTopologyRevision: 16,
        }),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'STALE_TOPOLOGY_REVISION');
            assert.equal(error.nodeId, 'relay-1');
            assert.equal(error.expectedTopologyRevision, 16);
            assert.equal(error.topologyRevision, 17);
            return true;
        },
    );
    assert.equal(relayPlanLookups, 0);
    assert.equal(preflightCalls, 0);
    assert.equal(planCalls, 0);
    assert.equal(operationCreates, 0);
});

test('install requires a relay-group plan before preflight or planning', async () => {
    const context = installContext({ relayGroupPlan: null });
    const repositories = createContextRepositories(context);
    let preflightCalls = 0;
    let planCalls = 0;
    const service = createService({
        ...repositories,
        preflightRunner: async () => {
            preflightCalls += 1;
            return { ok: true };
        },
        planBuilder: () => {
            planCalls += 1;
            return { ok: true, steps: [] };
        },
    });

    await assert.rejects(
        service.install(context.node.id, context.input),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'PREFLIGHT_FAILED');
            assert.equal(error.failureCode, 'RELAY_GROUP_PLAN_REQUIRED');
            assert.equal(error.nodeId, 'relay-1');
            assert.equal(error.routeGroupId, 'group-a');
            return true;
        },
    );
    assert.equal(preflightCalls, 0);
    assert.equal(planCalls, 0);
});

test('install rejects a failed preflight without building or persisting a plan', async () => {
    const context = installContext();
    const repositories = createContextRepositories(context);
    const preflightResult = {
        ok: false,
        checks: [{ code: 'OS_SUPPORTED', ok: false }],
        error: { code: 'UNSUPPORTED_OS' },
    };
    let planCalls = 0;
    let operationCreates = 0;
    const service = createService({
        ...repositories,
        preflightRunner: async () => preflightResult,
        planBuilder: () => {
            planCalls += 1;
            return { ok: true, steps: [] };
        },
        operationRepository: {
            async create() { operationCreates += 1; },
        },
    });

    await assert.rejects(
        service.install(context.node.id, context.input),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'PREFLIGHT_FAILED');
            assert.equal(error.nodeId, 'relay-1');
            assert.equal(error.failureCode, 'UNSUPPORTED_OS');
            assert.deepEqual(error.checks, preflightResult.checks);
            return true;
        },
    );
    assert.equal(planCalls, 0);
    assert.equal(operationCreates, 0);
});

test('install validates context, builds a plan, and persists one queued operation', async () => {
    const context = installContext();
    const repositories = createContextRepositories(context);
    const events = [];
    const plan = {
        ok: true,
        topologyRevision: 17,
        relayId: 'relay-1',
        routeGroupId: 'group-a',
        steps: [{ type: 'preflight' }, { type: 'verify' }, { type: 'commit' }],
    };
    const operationRepository = {
        async create(operation) {
            events.push({ method: 'create', operation });
            return operation;
        },
    };
    const service = createService({
        ...repositories,
        operationRepository,
        preflightRunner: async request => {
            events.push({ method: 'preflightRunner', request });
            return { ok: true, checks: [{ code: 'READY', ok: true }] };
        },
        planBuilder: request => {
            events.push({ method: 'planBuilder', request });
            return plan;
        },
    });

    const result = await service.install(context.node.id, context.input);

    assert.deepEqual(Object.keys(result), ['operationId']);
    assert.match(result.operationId, /^[0-9a-f]{24}$/);
    assert.equal(events.length, 3);
    assert.equal(events[0].method, 'preflightRunner');
    assert.deepEqual(events[1], {
        method: 'planBuilder',
        request: {
            operationId: result.operationId,
            topologyRevision: 17,
            relay: { ...context.node, role: 'relay' },
            routeGroup: context.routeGroup,
            relayGroupPlan: context.relayGroupPlan,
            desired: {
                ...context.state,
                clientCidr: context.input.clientCidr,
                dnsServers: context.input.dnsServers,
                routeGroup: 'group-a',
            },
        },
    });
    assert.deepEqual(events[2], {
        method: 'create',
        operation: {
            _id: result.operationId,
            node: 'relay-1',
            kind: 'install',
            status: 'queued',
            idempotencyKey: 'install:relay-1:revision-17',
            progress: 0,
            attempts: 0,
            plan,
            createdAt: NOW,
        },
    });
});
