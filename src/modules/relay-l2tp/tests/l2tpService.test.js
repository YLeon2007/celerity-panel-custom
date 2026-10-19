'use strict';
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../domain/topologyExecutionContext');

const assert = require('node:assert/strict');
const test = require('node:test');

const { materializeInstallOperation } = require('../services/l2tpOperationMaterializer');
const { buildInstallPlan } = require('../services/l2tpProvisionPlanService');
const { L2tpService } = require('../services/l2tpService');

const NOW = new Date('2026-09-22T10:00:00.000Z');

function createService(overrides = {}) {
    return new L2tpService({ executionContext: TEST,
        nodeRepository: overrides.nodeRepository || {
            async findById() { return null; },
        },
        stateRepository: overrides.stateRepository || {
            async findByNodeId() { return null; },
        },
        operationRepository: overrides.operationRepository || {},
        planBuilder: overrides.planBuilder || (() => ({ ok: true, steps: [] })),
        operationMaterializer: overrides.operationMaterializer || (({ plan }) => ({
            persistedPlan: plan,
        })),
        preflightRunner: overrides.preflightRunner || (async () => ({ ok: true, checks: [] })),
        remoteAdmissionRepository: overrides.remoteAdmissionRepository,
        lockService: overrides.lockService || {
            async acquire() { return { ok: true, lock: { generation: 'test-lock' } }; },
            async releaseVerified() { return { ok: true }; },
        },
        enableInstallAdmission: overrides.enableInstallAdmission,
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
            secretRevision: 9,
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
    const admissions = [];
    const service = createService({
        ...repositories,
        remoteAdmissionRepository: {
            async acquire(request) { admissions.push(['acquire', request]); return 'admission-1'; },
            async release(id) { admissions.push(['release', id]); },
            async markRecoveryRequired(id) { admissions.push(['recovery', id]); },
        },
        preflightRunner: async request => {
            calls.push(request);
            request.onVerifiedRemoteComplete();
            return expectedResult;
        },
    });

    assert.strictEqual(await service.preflight(context.node.id, context.input), expectedResult);
    assert.deepEqual(admissions, [['acquire', { nodeId: 'relay-1' }], ['release', 'admission-1']]);
    assert.equal(calls.length, 1);
    assert.equal(typeof calls[0].onVerifiedRemoteComplete, 'function');
    assert.deepEqual({ ...calls[0], onVerifiedRemoteComplete: undefined }, {
        executionContext: TEST,
        node: context.node,
        relay: { ...context.node, role: 'relay' },
        state: context.state,
        desired: {
            ...context.state,
            credentialRevision: context.state.secretRevision,
            clientCidr: context.input.clientCidr,
            dnsServers: context.input.dnsServers,
            routeGroup: 'group-a',
        },
        routeGroup: context.routeGroup,
        relayGroupPlan: context.relayGroupPlan,
        topologyRevision: 17,
        input: context.input,
        onVerifiedRemoteComplete: undefined,
    });
});

test('preflight requires exact node lock and retains counted admission when lock acquisition is uncertain', async () => {
    const context = installContext();
    const repositories = createContextRepositories(context);
    const admissions = [];
    let runnerCalled = false;
    const service = createService({
        ...repositories,
        remoteAdmissionRepository: {
            async acquire(request) { admissions.push(['acquire', request]); return 'admission-lock-uncertain'; },
            async release(id) { admissions.push(['release', id]); },
            async markRecoveryRequired(id) { admissions.push(['recovery', id]); },
        },
        lockService: {
            async acquire() { throw new Error('lock store unavailable'); },
            async releaseVerified() { throw new Error('must not release'); },
        },
        preflightRunner: async () => { runnerCalled = true; return { ok: true }; },
    });

    await assert.rejects(
        service.preflight(context.node.id, context.input),
        /lock store unavailable/,
    );
    assert.equal(runnerCalled, false);
    assert.deepEqual(admissions, [
        ['acquire', { nodeId: 'relay-1' }],
        ['recovery', 'admission-lock-uncertain'],
    ]);
});

test('preflight retains counted admission when exact lock release is not verified', async () => {
    const context = installContext();
    const repositories = createContextRepositories(context);
    const admissions = [];
    const service = createService({
        ...repositories,
        remoteAdmissionRepository: {
            async acquire() { return 'admission-release-uncertain'; },
            async release() { admissions.push('release'); },
            async markRecoveryRequired(id) { admissions.push(['recovery', id]); },
        },
        lockService: {
            async acquire() { return { ok: true, lock: { generation: 'lock-1' } }; },
            async releaseVerified() { return { ok: false }; },
        },
        preflightRunner: async request => {
            request.onVerifiedRemoteComplete();
            return { ok: false, error: { code: 'PREFLIGHT_FAILED' } };
        },
    });

    await assert.rejects(
        service.preflight(context.node.id, context.input),
        { code: 'PREFLIGHT_FENCE_RELEASE_FAILED' },
    );
    assert.deepEqual(admissions, [['recovery', 'admission-release-uncertain']]);
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

test('install exact node lock conflict rejects before any remote side effect', async () => {
    const context = installContext();
    const events = [];
    const service = createService({
        ...createContextRepositories(context), enableInstallAdmission: true,
        remoteAdmissionRepository: {
            async acquireInstall() { events.push('admit'); return 'admission-1'; },
            async release(id) { events.push(`release:${id}`); },
            async queueInstall() { events.push('queue'); },
            async markRecoveryRequired() { events.push('recovery'); },
        },
        lockService: {
            async acquire() { events.push('lock-conflict'); return { ok: false }; },
            async releaseVerified() { events.push('lock-release'); },
        },
        preflightRunner: async request => {
            events.push('remote-side-effect');
            request.onVerifiedRemoteComplete();
            return { ok: true };
        },
    });
    await assert.rejects(service.install(context.node.id, context.input),
        { code: 'NODE_OPERATION_LOCK_CONFLICT' });
    assert.deepEqual(events, ['admit', 'lock-conflict', 'release:admission-1']);
});

for (const result of [undefined, { ok: true }, { lock: { generation: 'unknown' } }]) {
    test(`install indeterminate lock acquisition ${JSON.stringify(result)} retains count before transport`, async () => {
        const context = installContext();
        const events = [];
        const service = createService({
            ...createContextRepositories(context), enableInstallAdmission: true,
            remoteAdmissionRepository: {
                async acquireInstall() { return 'admission-1'; },
                async release() { events.push('release'); },
                async queueInstall() { events.push('queue'); },
                async markRecoveryRequired(id) { events.push(`recovery:${id}`); },
            },
            lockService: { async acquire() { return result; }, async releaseVerified() { events.push('unlock'); } },
            preflightRunner: async () => { events.push('remote'); },
        });
        await assert.rejects(service.install(context.node.id, context.input), { code: 'NODE_LOCK_UNAVAILABLE' });
        assert.deepEqual(events, ['recovery:admission-1']);
    });
}

for (const lockService of [{}, { acquire: async () => { throw new Error('unexpected acquire'); } }]) {
    test('install without a complete exact-lock API fails before admission or transport', async () => {
        const context = installContext();
        const events = [];
        const service = createService({
            ...createContextRepositories(context), enableInstallAdmission: true, lockService,
            remoteAdmissionRepository: {
                async acquireInstall() { events.push('admit'); }, async release() {},
                async queueInstall() {}, async markRecoveryRequired() {},
            },
            preflightRunner: async () => { events.push('remote'); },
        });
        await assert.rejects(service.install(context.node.id, context.input), { code: 'REMOTE_ADMISSION_UNAVAILABLE' });
        assert.deepEqual(events, []);
    });
}

for (const ok of [true, false]) {
    test(`install verified ${ok ? 'success' : 'refusal'} releases exact preflight lock before admission handoff`, async () => {
        const context = installContext();
        const events = [];
        let exactLock;
        const service = createService({
            ...createContextRepositories(context), enableInstallAdmission: true,
            remoteAdmissionRepository: {
                async acquireInstall() { events.push('admit'); return 'admission-1'; },
                async release() { events.push('release-count'); },
                async queueInstall({ operationDocument }) {
                    assert.notEqual(operationDocument._id, exactLock.operationId);
                    events.push('queue');
                },
                async markRecoveryRequired() { events.push('recovery'); },
            },
            lockService: {
                async acquire(request) {
                    assert.equal(request.node, 'relay-1');
                    assert.match(request.owner, /^install-preflight:/);
                    assert.match(request.operationId, /^preflight:relay-1:/);
                    exactLock = { ...request, generation: 'exact-generation', remoteUncertain: true };
                    events.push('lock');
                    return { ok: true, lock: exactLock };
                },
                async releaseVerified(lock) {
                    assert.strictEqual(lock, exactLock);
                    events.push('release-lock');
                    return { ok: true };
                },
            },
            preflightRunner: async request => {
                events.push('remote');
                request.onVerifiedRemoteComplete();
                return { ok };
            },
        });
        if (ok) await service.install(context.node.id, context.input);
        else await assert.rejects(service.install(context.node.id, context.input), { code: 'PREFLIGHT_FAILED' });
        assert.deepEqual(events, ['admit', 'lock', 'remote', 'release-lock', ok ? 'queue' : 'release-count']);
    });
}

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
        enableInstallAdmission: true,
        remoteAdmissionRepository: {
            async acquireInstall() { return 'admission-1'; },
            async release(id) { assert.equal(id, 'admission-1'); },
            async queueInstall() { throw new Error('refusal must not queue'); },
            async markRecoveryRequired() { throw new Error('verified refusal must release'); },
        },
        preflightRunner: async request => {
            request.onVerifiedRemoteComplete();
            return preflightResult;
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

test('install rejects a fail-closed plan without persisting an operation', async () => {
    const context = installContext();
    const repositories = createContextRepositories(context);
    let operationCreates = 0;
    const service = createService({
        ...repositories,
        enableInstallAdmission: true,
        remoteAdmissionRepository: {
            async acquireInstall() { return 'admission-1'; },
            async release(id) { assert.equal(id, 'admission-1'); },
            async queueInstall() { throw new Error('rejected plan must not queue'); },
            async markRecoveryRequired() { throw new Error('attested completion must release'); },
        },
        preflightRunner: async request => {
            request.onVerifiedRemoteComplete();
            return { ok: true, checks: [] };
        },
        planBuilder: () => ({
            ok: false,
            error: {
                code: 'NO_HEALTHY_PATH',
                details: 'must not escape the service',
            },
            steps: [],
        }),
        operationRepository: {
            async create() { operationCreates += 1; },
        },
    });

    await assert.rejects(
        service.install(context.node.id, context.input),
        error => {
            assert.equal(error.name, 'L2tpServiceError');
            assert.equal(error.code, 'NO_HEALTHY_PATH');
            assert.equal(error.nodeId, 'relay-1');
            assert.equal(error.routeGroupId, 'group-a');
            assert.equal(Object.hasOwn(error, 'plan'), false);
            assert.doesNotMatch(JSON.stringify(error), /must not escape/);
            return true;
        },
    );
    assert.equal(operationCreates, 0);
});

test('install without explicit test opt-in fails closed before transport or persistence', async () => {
    const context = installContext();
    const calls = [];
    const service = createService({
        ...createContextRepositories(context),
        remoteAdmissionRepository: {
            async acquireInstall() { calls.push('acquire'); },
            async queueInstall() { calls.push('queue'); },
        },
        preflightRunner: async () => { calls.push('ssh'); return { ok: true }; },
        operationRepository: { async create() { calls.push('create'); } },
    });
    await assert.rejects(service.install(context.node.id, context.input),
        { code: 'REMOTE_ADMISSION_UNAVAILABLE' });
    assert.deepEqual(calls, []);
});

test('retry after a rolled-back install at the same revision uses a fresh durable attempt key', async () => {
    const context = installContext();
    const keys = new Set();
    const service = createService({
        ...createContextRepositories(context),
        enableInstallAdmission: true,
        remoteAdmissionRepository: {
            async acquireInstall() { return 'admission-' + (keys.size + 1); },
            async queueInstall({ operationDocument }) {
                const key = operationDocument.idempotencyKey;
                if (keys.has(key)) throw Object.assign(new Error('duplicate key'), { code: 11000 });
                keys.add(key);
            },
            async release() { throw new Error('successful handoff cannot release'); },
            async markRecoveryRequired() { throw new Error('successful handoff cannot recover'); },
        },
        preflightRunner: async request => {
            request.onVerifiedRemoteComplete();
            return { ok: true, checks: [] };
        },
        planBuilder: request => ({
            ok: true, operationId: request.operationId, relayId: 'relay-1', topologyRevision: 17,
        }),
    });
    const first = await service.install(context.node.id, context.input);
    // The first operation later rolled back; topology revision and desired state did not change.
    const second = await service.install(context.node.id, context.input);
    assert.notEqual(first.operationId, second.operationId);
    assert.equal(keys.size, 2);
});

test('opted-in install acquires before SSH and queues the same counted operation without release', async () => {
    const context = installContext();
    const events = [];
    const service = createService({
        ...createContextRepositories(context),
        enableInstallAdmission: true,
        remoteAdmissionRepository: {
            async acquireInstall(request) {
                events.push(['acquire', request]);
                return 'admission-1';
            },
            async queueInstall(request) { events.push(['queue', request]); },
            async release() { throw new Error('must not release after handoff'); },
            async markRecoveryRequired() { throw new Error('must not recover after handoff'); },
        },
        preflightRunner: async request => {
            events.push(['preflight', request]);
            request.onVerifiedRemoteComplete();
            return { ok: true, checks: [] };
        },
        planBuilder: request => {
            events.push(['plan', request]);
            return { ok: true, operationId: request.operationId, relayId: 'relay-1', topologyRevision: 17 };
        },
        operationRepository: { async create() { throw new Error('legacy create forbidden'); } },
    });
    const result = await service.install(context.node.id, context.input);
    assert.match(result.operationId, /^[0-9a-f]{24}$/);
    assert.deepEqual(events.map(event => event[0]), ['acquire', 'preflight', 'plan', 'queue']);
    assert.deepEqual(events[0][1], { nodeId: 'relay-1' });
    assert.equal(typeof events[1][1].onVerifiedRemoteComplete, 'function');
    assert.equal(events[2][1].operationId, result.operationId);
    assert.equal(events[3][1].admissionId, 'admission-1');
    assert.equal(events[3][1].operationDocument._id, result.operationId);
    assert.equal(events[3][1].operationDocument.plan.operationId, result.operationId);
});

test('opted-in install requires full admission API before SSH', async () => {
    const context = installContext();
    let transportCalls = 0;
    const service = createService({
        ...createContextRepositories(context),
        enableInstallAdmission: true,
        remoteAdmissionRepository: { async acquireInstall() { throw new Error('unexpected acquire'); } },
        preflightRunner: async () => { transportCalls += 1; },
    });
    await assert.rejects(service.install(context.node.id, context.input),
        { code: 'REMOTE_ADMISSION_UNAVAILABLE' });
    assert.equal(transportCalls, 0);
});

for (const [name, runner] of [
    ['missing attestation', async () => ({ ok: true })],
    ['invalid response', async request => { request.onVerifiedRemoteComplete(); return { ok: 'true' }; }],
    ['invalid attested error', async request => {
        request.onVerifiedRemoteComplete();
        return { ok: false, error: { code: 'PREFLIGHT_RESPONSE_INVALID' } };
    }],
    ['runner exception', async () => { throw new Error('SSH upload timed out'); }],
    ['attested runner exception', async request => {
        request.onVerifiedRemoteComplete();
        throw new Error('SSH command timed out');
    }],
]) {
    test(`install ${name} retains count and marks recovery without planning`, async () => {
        const context = installContext();
        const events = [];
        const service = createService({
            ...createContextRepositories(context),
            enableInstallAdmission: true,
            preflightRunner: runner,
            lockService: {
                async acquire() { events.push('lock'); return { ok: true, lock: { generation: 'held-lock' } }; },
                async releaseVerified() { events.push('unlock'); return { ok: true }; },
            },
            planBuilder: () => { events.push('plan'); },
            remoteAdmissionRepository: {
                async acquireInstall() { events.push('acquire'); return 'admission-1'; },
                async queueInstall() { events.push('queue'); },
                async release() { events.push('release'); },
                async markRecoveryRequired(id) { events.push(`recover:${id}`); },
            },
        });
        await assert.rejects(service.install(context.node.id, context.input));
        assert.deepEqual(events, ['acquire', 'lock', 'recover:admission-1']);
    });
}

test('attested materialization failure releases once; release failure propagates without retry', async () => {
    const context = installContext();
    const events = [];
    const releaseError = new Error('release commit unknown');
    const service = createService({
        ...createContextRepositories(context),
        enableInstallAdmission: true,
        preflightRunner: async request => {
            request.onVerifiedRemoteComplete();
            return { ok: true };
        },
        operationMaterializer: () => { throw new Error('materialization failed'); },
        remoteAdmissionRepository: {
            async acquireInstall() { return 'admission-1'; },
            async release() { events.push('release'); throw releaseError; },
            async queueInstall() { events.push('queue'); },
            async markRecoveryRequired() { events.push('recover'); },
        },
    });
    await assert.rejects(service.install(context.node.id, context.input), error => error === releaseError);
    assert.deepEqual(events, ['release']);
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
    const service = createService({
        ...repositories,
        enableInstallAdmission: true,
        remoteAdmissionRepository: {
            async acquireInstall() { events.push({ method: 'acquire' }); return 'admission-1'; },
            async queueInstall({ admissionId, operationDocument }) {
                events.push({ method: 'queue', admissionId, operation: operationDocument });
            },
            async release() { throw new Error('must not release'); },
            async markRecoveryRequired() { throw new Error('must not recover'); },
        },
        operationRepository: { async create() { throw new Error('legacy create forbidden'); } },
        preflightRunner: async request => {
            events.push({ method: 'preflightRunner', request });
            request.onVerifiedRemoteComplete();
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
    assert.equal(events.length, 4);
    assert.equal(events[0].method, 'acquire');
    assert.equal(events[1].method, 'preflightRunner');
    assert.deepEqual(events[2], {
        method: 'planBuilder',
        request: {
            operationId: result.operationId,
            topologyRevision: 17,
            relay: { ...context.node, role: 'relay' },
            routeGroup: context.routeGroup,
            relayGroupPlan: context.relayGroupPlan,
            desired: {
                ...context.state,
                credentialRevision: context.state.secretRevision,
                clientCidr: context.input.clientCidr,
                dnsServers: context.input.dnsServers,
                routeGroup: 'group-a',
            },
        },
    });
    assert.deepEqual(events[3], {
        method: 'queue',
        admissionId: 'admission-1',
        operation: {
            _id: result.operationId,
            executionContext: TEST,
            node: 'relay-1',
            kind: 'install',
            status: 'queued',
            idempotencyKey: `install:relay-1:revision-17:attempt-${result.operationId}`,
            progress: 0,
            attempts: 0,
            plan,
            createdAt: NOW,
        },
    });
});

test('definite precommit duplicate releases only the unqueued admission and permits retry', async () => {
    const context = installContext();
    const events = [];
    const duplicate = Object.assign(new Error('E11000'),
        { code: 11000, installQueuePreCommitAbort: true });
    const service = createService({
        ...createContextRepositories(context), enableInstallAdmission: true,
        preflightRunner: async request => { request.onVerifiedRemoteComplete(); return { ok: true }; },
        planBuilder: buildInstallPlan,
        operationMaterializer: materializeInstallOperation,
        remoteAdmissionRepository: {
            async acquireInstall() { events.push('acquire'); return 'admission-1'; },
            async queueInstall() { events.push('queue'); throw duplicate; },
            async release() { events.push('release'); return true; },
            async markRecoveryRequired() { events.push('recover'); },
        },
    });
    await assert.rejects(service.install(context.node.id, context.input),
        { code: 'INSTALL_OPERATION_CONFLICT' });
    assert.deepEqual(events, ['acquire', 'queue', 'release']);
});

test('terminal duplicate is not deleted or retried and leaves new admission counted', async () => {
    const context = installContext();
    const events = [];
    const duplicate = Object.assign(new Error('E11000 duplicate key'), { code: 11000 });
    const service = createService({
        ...createContextRepositories(context),
        enableInstallAdmission: true,
        preflightRunner: async request => {
            request.onVerifiedRemoteComplete();
            return { ok: true };
        },
        planBuilder: buildInstallPlan,
        operationMaterializer: materializeInstallOperation,
        remoteAdmissionRepository: {
            async acquireInstall() { events.push('acquire'); return 'admission-1'; },
            async queueInstall() { events.push('queue'); throw duplicate; },
            async release() { events.push('release'); },
            async markRecoveryRequired() { events.push('recover'); },
        },
        operationRepository: {
            async create() { throw new Error('legacy create forbidden'); },
            async deleteById() { events.push('delete'); },
        },
    });
    await assert.rejects(service.install(context.node.id, context.input),
        { code: 'INSTALL_OPERATION_CONFLICT' });
    assert.deepEqual(events, ['acquire', 'queue']);
});

test('active duplicate without proven counted admission is not reported as success', async () => {
    const context = installContext();
    const events = [];
    const duplicate = Object.assign(new Error('E11000 duplicate key'), { code: 11000 });
    const service = createService({
        ...createContextRepositories(context),
        enableInstallAdmission: true,
        preflightRunner: async request => {
            request.onVerifiedRemoteComplete();
            return { ok: true };
        },
        planBuilder: buildInstallPlan,
        operationMaterializer: materializeInstallOperation,
        remoteAdmissionRepository: {
            async acquireInstall() { events.push('acquire'); return 'admission-1'; },
            async queueInstall() { events.push('queue'); throw duplicate; },
            async release() { events.push('release'); },
            async markRecoveryRequired() { events.push('recover'); },
        },
        operationRepository: {
            async findByIdempotencyKey() { return { _id: 'legacy-op', status: 'running' }; },
            async deleteById() { events.push('delete'); },
        },
    });
    await assert.rejects(service.install(context.node.id, context.input),
        { code: 'INSTALL_OPERATION_CONFLICT' });
    assert.deepEqual(events, ['acquire', 'queue']);
});

test('ambiguous queue commit succeeds only after exact admission-operation readback', async () => {
    const context = installContext();
    let requested;
    const events = [];
    const service = createService({
        ...createContextRepositories(context),
        enableInstallAdmission: true,
        preflightRunner: async request => {
            request.onVerifiedRemoteComplete();
            return { ok: true };
        },
        planBuilder: ({ operationId }) => ({ ok: true, operationId, relayId: 'relay-1', topologyRevision: 17 }),
        remoteAdmissionRepository: {
            async acquireInstall() { return 'admission-1'; },
            async queueInstall(request) { requested = request; throw new Error('commit timed out'); },
            async findInstallHandoff(request) {
                events.push(request);
                return {
                    admission: {
                        _id: 'admission-1', nodeId: 'relay-1', kind: 'install',
                        phase: 'queued', operationId: requested.operationDocument._id,
                    },
                    operation: {
                        ...requested.operationDocument, admissionId: 'admission-1',
                    },
                };
            },
            async release() { throw new Error('must not release'); },
            async markRecoveryRequired() { throw new Error('must not recover'); },
        },
    });
    const result = await service.install(context.node.id, context.input);
    assert.equal(result.operationId, requested.operationDocument._id);
    assert.deepEqual(events, [{ admissionId: 'admission-1', operationId: result.operationId }]);
});

test('ambiguous queue readback with wrong admission link fails closed', async () => {
    const context = installContext();
    const events = [];
    const service = createService({
        ...createContextRepositories(context),
        enableInstallAdmission: true,
        preflightRunner: async request => {
            request.onVerifiedRemoteComplete();
            return { ok: true };
        },
        planBuilder: ({ operationId }) => ({ ok: true, operationId, relayId: 'relay-1', topologyRevision: 17 }),
        remoteAdmissionRepository: {
            async acquireInstall() { return 'admission-1'; },
            async queueInstall() { events.push('queue'); throw new Error('commit timed out'); },
            async findInstallHandoff() {
                events.push('read');
                return { admission: { phase: 'queued', operationId: 'other' }, operation: null };
            },
            async release() { events.push('release'); },
            async markRecoveryRequired() { events.push('recover'); },
        },
    });
    await assert.rejects(service.install(context.node.id, context.input));
    assert.deepEqual(events, ['queue', 'read']);
});

test('install materializes a secret-safe durable payload after validation and before persistence', async () => {
    const psk = 'service-psk-must-not-persist';
    const password = 'service-password-must-not-persist';
    const base = installContext();
    const context = installContext({
        state: {
            ...base.state,
            localAddress: '10.77.0.1',
            poolStart: '10.77.0.10',
            poolEnd: '10.77.0.200',
            tproxyPort: 12345,
            fwmark: 77,
            routeTable: 177,
            secretRevision: 9,
            psk,
            users: [{ login: 'alice', password }],
        },
    });
    const repositories = createContextRepositories(context);
    const events = [];
    let createdOperation;
    const service = createService({
        ...repositories,
        enableInstallAdmission: true,
        remoteAdmissionRepository: {
            async acquireInstall() { return 'admission-1'; },
            async queueInstall({ operationDocument }) {
                events.push('persist');
                createdOperation = operationDocument;
            },
            async release() { throw new Error('must not release'); },
            async markRecoveryRequired() { throw new Error('must not recover'); },
        },
        preflightRunner: async request => {
            events.push('preflight');
            request.onVerifiedRemoteComplete();
            return { ok: true, checks: [] };
        },
        planBuilder: request => {
            events.push('plan');
            return buildInstallPlan(request);
        },
        operationMaterializer: request => {
            events.push('materialize');
            return materializeInstallOperation(request);
        },
        operationRepository: {
            async create() { throw new Error('legacy create forbidden'); },
        },
    });

    const result = await service.install(context.node.id, context.input);

    assert.deepEqual(events, ['preflight', 'plan', 'materialize', 'persist']);
    assert.equal(createdOperation.plan.operationId, result.operationId);
    assert.equal(
        createdOperation.plan.desired.credentialRevision,
        context.state.secretRevision,
        'install plan must pin the current relay credential (secret) revision',
    );
    assert.deepEqual(
        createdOperation.plan.steps.find(step => step.type === 'preflight').artifacts,
        [{ type: 'desired', path: 'desired.json' }],
    );
    assert.deepEqual(
        createdOperation.plan.steps.find(step => step.type === 'stage_managed_files').artifacts,
        [{ type: 'artifact', path: 'artifacts.json' }],
    );
    const persisted = JSON.stringify(createdOperation);
    assert.doesNotMatch(persisted, new RegExp(psk));
    assert.doesNotMatch(persisted, new RegExp(password));
    assert.doesNotMatch(persisted, /"(?:psk|password|content)"\s*:/i);
    assert.deepEqual(result, { operationId: createdOperation._id });
});
