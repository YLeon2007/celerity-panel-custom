'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { createL2tpPanelHost } = require('../createL2tpPanelHost');
const {
    L2tpUserManagementRepository,
    SAFE_USER_SELECT,
} = require('../relay-l2tp/repositories/l2tpUserManagementRepository');
const { createL2tpRuntime } = require('../relay-l2tp/runtime/createL2tpRuntime');
const {
    VERIFIED_STATE_SAFE_SELECT,
} = require('../relay-l2tp/repositories/l2tpStateManagementRepository');
const { L2tpNodeTransport } = require('../relay-l2tp/services/l2tpNodeTransport');
const { materializeInstallOperation } = require('../relay-l2tp/services/l2tpOperationMaterializer');
const { createL2tpPreflightRunner } = require('../relay-l2tp/services/l2tpPreflightRunner');
const { L2tpRemoteExecutor } = require('../relay-l2tp/services/l2tpRemoteExecutor');
const {
    L2tpUserManagementService,
} = require('../relay-l2tp/services/l2tpUserManagementService');
const { buildL2tpXrayFragment } = require('../relay-l2tp/services/l2tpXrayFragmentProvider');
const { L2tpXrayCandidateService } = require('../relay-l2tp/services/l2tpXrayCandidateService');
const { NodeOperationLockRepository } = require('../relay-l2tp/services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../relay-l2tp/services/nodeOperationLockService');
const { L2tpOperationWorker } = require('../relay-l2tp/workers/l2tpOperationWorker');
const { generateXrayConfig } = require('../../services/configGenerator');

function passThrough(req, res, next) {
    next();
}

function queryResult(result, calls, kind) {
    return {
        select(fields) {
            calls.push({ kind: `${kind}.select`, fields });
            return this;
        },
        sort(order) {
            calls.push({ kind: `${kind}.sort`, order });
            return this;
        },
        lean() {
            calls.push({ kind: `${kind}.lean` });
            return Promise.resolve(result);
        },
    };
}

function createActiveHost(overrides = {}) {
    const calls = [];
    const runtimeCalls = [];
    const preflightFactoryCalls = [];
    const candidateFactoryCalls = [];
    const userSnapshotFactoryCalls = [];
    const userSyncFactoryCalls = [];
    let scheduledTick;
    const executionNode = {
        _id: 'node-a',
        name: 'Relay A',
        ip: '192.0.2.10',
        type: 'xray',
        active: true,
        cascadeRole: 'relay',
        ssh: {
            port: 22,
            username: 'root',
            privateKey: 'encrypted-private-key',
        },
    };
    const executionState = {
        node: 'node-a',
        desiredState: 'installed',
        secretRevision: 7,
        pskEncrypted: 'sealed-psk',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
    };
    const executionUsers = [{
        relayNode: 'node-a',
        login: 'alice',
        ip: '10.77.0.10',
        enabled: true,
        desiredRevision: 4,
        passwordEncrypted: 'sealed-alice-password',
    }];
    const HyNode = {
        findById(nodeId) {
            calls.push({ kind: 'HyNode.findById', nodeId });
            return queryResult(executionNode, calls, 'HyNode');
        },
    };
    const RelayL2tpState = {
        findOne(filter) {
            calls.push({ kind: 'RelayL2tpState.findOne', filter });
            return queryResult(executionState, calls, 'RelayL2tpState');
        },
        findOneAndUpdate(filter, update, options) {
            calls.push({ kind: 'RelayL2tpState.findOneAndUpdate', filter, update, options });
            return queryResult(executionState, calls, 'RelayL2tpState');
        },
    };
    const L2tpUser = {
        find(filter) {
            calls.push({ kind: 'L2tpUser.find', filter });
            return queryResult(executionUsers, calls, 'L2tpUser');
        },
        findOne() {
            throw new Error('not used while listing users');
        },
        findOneAndUpdate() {
            throw new Error('not used while listing users');
        },
        create() {
            throw new Error('not used while listing users');
        },
    };
    const models = {
        RelayL2tpState,
        L2tpUser,
        CascadeRouteGroup: { modelName: 'CascadeRouteGroup' },
        CascadeTopologyState: { modelName: 'CascadeTopologyState' },
        L2tpOperation: { modelName: 'L2tpOperation' },
        NodeOperationLock: { modelName: 'NodeOperationLock' },
    };

    class FakeNodeSSH {
        constructor(node) {
            this.node = node;
            calls.push({ kind: 'NodeSSH.construct', node });
        }

        async exec(command, options) {
            calls.push({ kind: 'NodeSSH.exec', command, options });
            return { code: 0, stdout: '', stderr: '' };
        }
    }

    const timer = {
        setInterval(callback, intervalMs) {
            calls.push({ kind: 'timer.setInterval', intervalMs });
            scheduledTick = callback;
            return { kind: 'schedule' };
        },
        clearInterval(schedule) {
            calls.push({ kind: 'timer.clearInterval', schedule });
        },
    };
    const secretBox = {
        encrypt() {
            throw new Error('not used by execution');
        },
        decrypt(envelope, key) {
            calls.push({ kind: 'secretBox.decrypt', envelope, key });
            if (envelope === 'sealed-psk') return 'resolved-psk';
            if (envelope === 'sealed-alice-password') return 'resolved-alice-password';
            throw new Error('unknown encrypted value');
        },
    };
    const adapters = {
        nodeRepository: {
            async findById(nodeId) {
                calls.push({ kind: 'nodeRepository.findById', nodeId });
                return executionNode;
            },
        },
        stateRepository: {
            async findByNodeId(nodeId) {
                calls.push({ kind: 'stateRepository.findByNodeId', nodeId });
                return executionState;
            },
            async findRouteGroupById(routeGroupId) {
                calls.push({ kind: 'stateRepository.findRouteGroupById', routeGroupId });
                return { id: routeGroupId };
            },
            async getTopologyRevision() {
                calls.push({ kind: 'stateRepository.getTopologyRevision' });
                return 17;
            },
            async getRelayGroupPlan(nodeId, routeGroupId) {
                calls.push({ kind: 'stateRepository.getRelayGroupPlan', nodeId, routeGroupId });
                return { groupId: routeGroupId };
            },
        },
        operationRepository: {
            async create(operation) {
                calls.push({ kind: 'operationRepository.create', operation });
            },
        },
    };
    const candidateNodeResolver = async request => {
        calls.push({ kind: 'candidateNodeResolver', request });
        return executionNode;
    };
    const candidateUserResolver = async node => {
        calls.push({ kind: 'candidateUserResolver', node });
        return [];
    };
    const createPreflightRunner = dependencies => {
        preflightFactoryCalls.push(dependencies);
        return createL2tpPreflightRunner(dependencies);
    };
    const createCandidateService = dependencies => {
        candidateFactoryCalls.push(dependencies);
        return new L2tpXrayCandidateService(dependencies);
    };
    const createUserSnapshotResolver = dependencies => {
        userSnapshotFactoryCalls.push(dependencies);
        return async request => ({
            credentialRevision: request.credentialRevision,
            users: await dependencies.userResolver.resolve({
                ...request,
                kind: 'install',
            }),
        });
    };
    const userSyncReconciler = {
        async finalizeVerifiedSync() {
            return { ok: true };
        },
    };
    const createUserSyncReconciler = dependencies => {
        userSyncFactoryCalls.push(dependencies);
        return userSyncReconciler;
    };

    const host = createL2tpPanelHost({
        requireAuth: passThrough,
        requireOnboarding: passThrough,
        csrf: passThrough,
        rateLimiter: passThrough,
        renderPage() {},
        moduleEntry: { registerModels: () => models },
        HyNode,
        CascadeLink: {},
        topologyRuntime: {},
        Repository: class FakeRepository {},
        createRepositoryAdapters: () => adapters,
        createPanelOverviewLoader: () => async () => ({}),
        workerLifecycle: {
            enabled: true,
            intervalMs: 2_500,
            timer,
            logger: { error() {} },
        },
        NodeSSH: FakeNodeSSH,
        NodeTransport: L2tpNodeTransport,
        createPreflightRunner,
        createCandidateService,
        createUserSnapshotResolver,
        createUserSyncReconciler,
        candidateNodeResolver,
        candidateUserResolver,
        configGenerator: generateXrayConfig,
        fragmentProvider: buildL2tpXrayFragment,
        operationMaterializer: materializeInstallOperation,
        secretBox,
        secretKey: 'execution-secret-key',
        createRuntime(dependencies) {
            runtimeCalls.push(dependencies);
            return createL2tpRuntime(dependencies);
        },
        ...overrides,
    });

    return {
        calls,
        candidateDependencies: {
            configGenerator: generateXrayConfig,
            fragmentProvider: buildL2tpXrayFragment,
            nodeResolver: candidateNodeResolver,
            userResolver: candidateUserResolver,
        },
        candidateFactoryCalls,
        getScheduledTick: () => scheduledTick,
        host,
        preflightFactoryCalls,
        runtimeCalls,
        userSnapshotFactoryCalls,
        userSyncFactoryCalls,
        userSyncReconciler,
        userManagementDependencies: {
            HyNode,
            L2tpUser,
            L2tpOperation: models.L2tpOperation,
            RelayL2tpState,
            secretBox,
        },
    };
}

test('explicit complete activation wires execution factories lazily and starts only on request', async () => {
    const {
        calls,
        candidateDependencies,
        candidateFactoryCalls,
        getScheduledTick,
        host,
        preflightFactoryCalls,
        runtimeCalls,
        userManagementDependencies,
        userSnapshotFactoryCalls,
        userSyncFactoryCalls,
        userSyncReconciler,
    } = createActiveHost();

    assert.equal(runtimeCalls.length, 1);
    assert.deepEqual(
        Object.keys(runtimeCalls[0]).filter(key => [
            'transport',
            'transportFactory',
            'transportResolver',
            'artifactMaterializer',
            'operationMaterializer',
            'preflightRunner',
            'candidateService',
            'secretResolver',
            'userSnapshotResolver',
            'userSyncReconciler',
            'stateReconciler',
        ].includes(key)),
        [
            'preflightRunner',
            'candidateService',
            'transportResolver',
            'operationMaterializer',
            'secretResolver',
            'userSnapshotResolver',
            'userSyncReconciler',
            'stateReconciler',
        ],
    );
    assert.equal(preflightFactoryCalls.length, 1);
    assert.strictEqual(
        preflightFactoryCalls[0].transportResolver,
        runtimeCalls[0].transportResolver,
    );
    assert.deepEqual(candidateFactoryCalls, [candidateDependencies]);
    assert.ok(runtimeCalls[0].candidateService instanceof L2tpXrayCandidateService);
    assert.ok(host.runtime.worker instanceof L2tpOperationWorker);
    assert.ok(host.runtime.worker.executor instanceof L2tpRemoteExecutor);
    assert.ok(host.runtime.worker.lockService instanceof NodeOperationLockService);
    assert.ok(host.runtime.worker.lockService.repository instanceof NodeOperationLockRepository);
    assert.strictEqual(host.runtime.worker.candidateService, runtimeCalls[0].candidateService);
    assert.strictEqual(host.runtime.worker.userSyncReconciler, userSyncReconciler);
    assert.strictEqual(host.runtime.worker.stateReconciler, runtimeCalls[0].stateReconciler);
    assert.strictEqual(runtimeCalls[0].operationMaterializer, materializeInstallOperation);
    assert.equal(userSnapshotFactoryCalls.length, 1);
    assert.equal(typeof userSnapshotFactoryCalls[0].userResolver.resolve, 'function');
    assert.deepEqual(userSyncFactoryCalls, [{
        L2tpOperation: userManagementDependencies.L2tpOperation,
        RelayL2tpState: userManagementDependencies.RelayL2tpState,
        L2tpUser: userManagementDependencies.L2tpUser,
        clock: runtimeCalls[0].clock,
    }]);
    assert.deepEqual(calls, []);
    assert.equal(getScheduledTick(), undefined);
    assert.equal(
        Object.prototype.propertyIsEnumerable.call(host.runtime.worker, 'secretResolver'),
        false,
    );
    assert.doesNotMatch(JSON.stringify(host.runtime), /execution-secret-key|resolved-psk|sealed-psk/);

    assert.deepEqual(host.start(), {
        enabled: true,
        running: true,
        inFlight: false,
    });
    assert.deepEqual(calls, [{ kind: 'timer.setInterval', intervalMs: 2_500 }]);
    assert.equal(typeof getScheduledTick(), 'function');

    const secrets = await host.runtime.worker.secretResolver({
        kind: 'install',
        node: 'node-a',
        credentialRevision: 7,
        secret: 'psk',
    });
    assert.deepEqual(secrets, {
        psk: 'resolved-psk',
        users: [{
            login: 'alice',
            password: 'resolved-alice-password',
            ip: '10.77.0.10',
        }],
    });
    assert.deepEqual(await host.runtime.worker.userSnapshotResolver({
        operationId: 'operation-sync-7',
        kind: 'sync_users',
        nodeId: 'node-a',
        credentialRevision: 7,
    }), {
        credentialRevision: 7,
        users: [{
            login: 'alice',
            password: 'resolved-alice-password',
            ip: '10.77.0.10',
        }],
    });
    assert.deepEqual(
        calls.map(call => call.kind),
        [
            'timer.setInterval',
            'RelayL2tpState.findOne',
            'RelayL2tpState.select',
            'RelayL2tpState.lean',
            'secretBox.decrypt',
            'L2tpUser.find',
            'L2tpUser.select',
            'L2tpUser.sort',
            'L2tpUser.lean',
            'secretBox.decrypt',
            'L2tpUser.find',
            'L2tpUser.select',
            'L2tpUser.sort',
            'L2tpUser.lean',
            'secretBox.decrypt',
        ],
    );
    assert.doesNotMatch(
        JSON.stringify(host.runtime),
        /resolved-alice-password|sealed-alice-password/,
    );

    await host.runtime.worker.executor.executeStep({
        operation: { _id: 'operation-a', node: 'node-a' },
        step: { type: 'commit' },
    });

    assert.deepEqual(
        calls.map(call => call.kind),
        [
            'timer.setInterval',
            'RelayL2tpState.findOne',
            'RelayL2tpState.select',
            'RelayL2tpState.lean',
            'secretBox.decrypt',
            'L2tpUser.find',
            'L2tpUser.select',
            'L2tpUser.sort',
            'L2tpUser.lean',
            'secretBox.decrypt',
            'L2tpUser.find',
            'L2tpUser.select',
            'L2tpUser.sort',
            'L2tpUser.lean',
            'secretBox.decrypt',
            'HyNode.findById',
            'HyNode.select',
            'HyNode.lean',
            'NodeSSH.construct',
            'NodeSSH.exec',
        ],
    );
    assert.equal(calls.filter(call => call.kind === 'NodeSSH.construct').length, 1);
    assert.equal(calls.find(call => call.kind === 'HyNode.findById').nodeId, 'node-a');
});

test('active preflight resolves transport only on demand without operations, secrets, or candidates', async () => {
    const { calls, host } = createActiveHost();

    assert.deepEqual(calls, []);

    const result = await host.runtime.service.preflight('node-a', {
        routeGroupId: 'group-a',
        expectedTopologyRevision: 17,
    });

    assert.deepEqual(result, {
        ok: false,
        checks: [],
        error: { code: 'PREFLIGHT_RESPONSE_INVALID' },
    });
    assert.equal(calls.filter(call => call.kind === 'NodeSSH.construct').length, 1);
    assert.equal(calls.filter(call => call.kind === 'NodeSSH.exec').length, 2);
    assert.equal(calls.some(call => call.kind === 'operationRepository.create'), false);
    assert.equal(calls.some(call => call.kind === 'secretBox.decrypt'), false);
    assert.equal(calls.some(call => call.kind === 'candidateNodeResolver'), false);
    assert.equal(calls.some(call => call.kind === 'candidateUserResolver'), false);
});

test('active worker reconciler persists verified install state through the management service', async () => {
    const { calls, host, runtimeCalls } = createActiveHost();
    const verifiedAt = new Date('2026-09-22T10:00:00.000Z');
    const operation = {
        id: 'operation-17',
        node: 'node-a',
        kind: 'install',
        plan: {
            operationId: 'operation-17',
            relayId: 'node-a',
            topologyRevision: 17,
            selectedPathKey: 'primary',
            desired: { credentialRevision: 7 },
        },
    };

    assert.deepEqual(calls, []);
    const result = await host.runtime.worker.stateReconciler({ operation, verifiedAt });

    assert.strictEqual(host.runtime.worker.stateReconciler, runtimeCalls[0].stateReconciler);
    assert.deepEqual(calls, [
        {
            kind: 'RelayL2tpState.findOneAndUpdate',
            filter: {
                node: 'node-a',
                desiredState: 'installed',
                secretRevision: 7,
            },
            update: {
                $set: {
                    status: 'installed',
                    operationId: 'operation-17',
                    appliedTopologyRevision: 17,
                    activePathKey: 'primary',
                    lastVerifiedAt: verifiedAt,
                    lastErrorCode: '',
                    lastError: '',
                },
            },
            options: { new: true, runValidators: true },
        },
        { kind: 'RelayL2tpState.select', fields: VERIFIED_STATE_SAFE_SELECT },
        { kind: 'RelayL2tpState.lean' },
    ]);
    assert.deepEqual(result, {
        node: 'node-a',
        desiredState: 'installed',
        secretRevision: 7,
    });
    assert.doesNotMatch(JSON.stringify(result), /psk|sealed-psk/);
});

test('active runtime composes model-backed user management without enumerating credentials', async () => {
    const {
        calls,
        host,
        runtimeCalls,
        userManagementDependencies,
    } = createActiveHost();
    const service = host.runtime.userManagementService;

    assert.ok(service instanceof L2tpUserManagementService);
    assert.strictEqual(runtimeCalls[0].userManagementService, service);
    assert.ok(service.repository instanceof L2tpUserManagementRepository);
    assert.strictEqual(service.repository.HyNode, userManagementDependencies.HyNode);
    assert.strictEqual(service.repository.L2tpUser, userManagementDependencies.L2tpUser);
    assert.strictEqual(
        service.repository.L2tpOperation,
        userManagementDependencies.L2tpOperation,
    );
    assert.strictEqual(service.repository.RelayL2tpState, userManagementDependencies.RelayL2tpState);
    assert.strictEqual(service.secretBox, userManagementDependencies.secretBox);
    assert.deepEqual(calls, []);

    const users = await service.listUsers('node-a');

    assert.deepEqual(users, [{
        relayNode: 'node-a',
        login: 'alice',
        ip: '10.77.0.10',
        enabled: true,
        desiredRevision: 4,
    }]);
    assert.deepEqual(calls.map(call => call.kind), [
        'HyNode.findById',
        'HyNode.select',
        'HyNode.lean',
        'L2tpUser.find',
        'L2tpUser.select',
        'L2tpUser.sort',
        'L2tpUser.lean',
    ]);
    assert.equal(calls.find(call => call.kind === 'L2tpUser.select').fields, SAFE_USER_SELECT);
    assert.equal(calls.some(call => call.kind === 'secretBox.decrypt'), false);
    assert.doesNotMatch(JSON.stringify(users), /sealed-alice-password|password/i);
});

test('enabled activation rejects missing factories and resolvers before runtime composition', () => {
    for (const [dependencyName, overrides] of [
        ['secretKey', { secretKey: undefined }],
        ['createPreflightRunner', { createPreflightRunner: undefined }],
        ['createCandidateService', { createCandidateService: undefined }],
        ['candidateNodeResolver', { candidateNodeResolver: undefined }],
        ['candidateUserResolver', { candidateUserResolver: undefined }],
        ['configGenerator', { configGenerator: undefined }],
        ['fragmentProvider', { fragmentProvider: undefined }],
    ]) {
        assert.throws(
            () => createActiveHost(overrides),
            new RegExp(dependencyName, 'i'),
            dependencyName,
        );
    }
});

test('non-boolean activation stays dormant with fail-closed runtime services', async () => {
    const {
        calls,
        candidateFactoryCalls,
        getScheduledTick,
        host,
        preflightFactoryCalls,
        runtimeCalls,
    } = createActiveHost({ workerLifecycle: { enabled: 'true' } });

    assert.deepEqual(calls, []);
    assert.deepEqual(preflightFactoryCalls, []);
    assert.deepEqual(candidateFactoryCalls, []);
    assert.equal(getScheduledTick(), undefined);
    assert.deepEqual(host.start(), {
        enabled: false,
        running: false,
        inFlight: false,
    });
    assert.deepEqual(await runtimeCalls[0].preflightRunner(), {
        ok: false,
        checks: [],
        error: { code: 'L2TP_PREFLIGHT_RUNNER_UNAVAILABLE' },
    });
    await assert.rejects(
        runtimeCalls[0].candidateService.buildCandidate(),
        error => error?.code === 'L2TP_XRAY_CANDIDATE_UNAVAILABLE',
    );
    await assert.rejects(
        runtimeCalls[0].stateManagementService.configureRelay('node-a', {}),
        error => error?.code === 'L2TP_STATE_MANAGEMENT_UNAVAILABLE',
    );
    for (const [methodName, args] of [
        ['createUser', ['node-a', {}]],
        ['listUsers', ['node-a']],
        ['updateUser', ['node-a', 'user-a', {}]],
        ['disableUser', ['node-a', 'user-a']],
    ]) {
        await assert.rejects(
            host.runtime.userManagementService[methodName](...args),
            error => error?.code === 'L2TP_USER_MANAGEMENT_UNAVAILABLE',
            methodName,
        );
    }
    await assert.rejects(
        host.runtime.worker.secretResolver({ kind: 'install' }),
        error => error?.code === 'L2TP_SECRET_RESOLVER_UNAVAILABLE',
    );
    assert.strictEqual(host.runtime.worker.stateReconciler, runtimeCalls[0].stateReconciler);
    await assert.rejects(
        host.runtime.worker.stateReconciler({ operation: { kind: 'install' } }),
        error => error?.code === 'L2TP_STATE_RECONCILER_UNAVAILABLE',
    );
    assert.deepEqual(calls, []);
});
