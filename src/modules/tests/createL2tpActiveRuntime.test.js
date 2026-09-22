'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { createL2tpPanelHost } = require('../createL2tpPanelHost');
const { createL2tpRuntime } = require('../relay-l2tp/runtime/createL2tpRuntime');
const { L2tpNodeTransport } = require('../relay-l2tp/services/l2tpNodeTransport');
const { materializeInstallOperation } = require('../relay-l2tp/services/l2tpOperationMaterializer');
const { createL2tpPreflightRunner } = require('../relay-l2tp/services/l2tpPreflightRunner');
const { L2tpRemoteExecutor } = require('../relay-l2tp/services/l2tpRemoteExecutor');
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
    };
    const models = {
        RelayL2tpState,
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
            return 'resolved-psk';
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
    };
}

test('explicit complete activation wires preflight and candidate factories lazily and starts only on request', async () => {
    const {
        calls,
        candidateDependencies,
        candidateFactoryCalls,
        getScheduledTick,
        host,
        preflightFactoryCalls,
        runtimeCalls,
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
        ].includes(key)),
        [
            'preflightRunner',
            'candidateService',
            'transportResolver',
            'operationMaterializer',
            'secretResolver',
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
    assert.strictEqual(runtimeCalls[0].operationMaterializer, materializeInstallOperation);
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
    assert.deepEqual(secrets, { psk: 'resolved-psk' });
    assert.deepEqual(
        calls.map(call => call.kind),
        [
            'timer.setInterval',
            'RelayL2tpState.findOne',
            'RelayL2tpState.select',
            'RelayL2tpState.lean',
            'secretBox.decrypt',
        ],
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
    await assert.rejects(
        host.runtime.worker.secretResolver({ kind: 'install' }),
        error => error?.code === 'L2TP_SECRET_RESOLVER_UNAVAILABLE',
    );
    assert.deepEqual(calls, []);
});
