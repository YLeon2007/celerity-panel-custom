'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { createL2tpPanelHost } = require('../createL2tpPanelHost');
const { createL2tpRuntime } = require('../relay-l2tp/runtime/createL2tpRuntime');
const { materializeInstallOperation } = require('../relay-l2tp/services/l2tpOperationMaterializer');
const { L2tpRemoteExecutor } = require('../relay-l2tp/services/l2tpRemoteExecutor');
const { NodeOperationLockRepository } = require('../relay-l2tp/services/nodeOperationLockRepository');
const { NodeOperationLockService } = require('../relay-l2tp/services/nodeOperationLockService');
const { L2tpOperationWorker } = require('../relay-l2tp/workers/l2tpOperationWorker');

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
        nodeRepository: { kind: 'node-repository' },
        stateRepository: { kind: 'state-repository' },
        operationRepository: { kind: 'operation-repository' },
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
        preflightRunner: async () => ({ ok: true, checks: [] }),
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
        getScheduledTick: () => scheduledTick,
        host,
        runtimeCalls,
    };
}

test('explicit complete activation wires the real runtime lazily and starts only on request', async () => {
    const { calls, getScheduledTick, host, runtimeCalls } = createActiveHost();

    assert.equal(runtimeCalls.length, 1);
    assert.deepEqual(
        Object.keys(runtimeCalls[0]).filter(key => [
            'transport',
            'transportFactory',
            'transportResolver',
            'artifactMaterializer',
            'operationMaterializer',
            'secretResolver',
        ].includes(key)),
        ['transportResolver', 'operationMaterializer', 'secretResolver'],
    );
    assert.ok(host.runtime.worker instanceof L2tpOperationWorker);
    assert.ok(host.runtime.worker.executor instanceof L2tpRemoteExecutor);
    assert.ok(host.runtime.worker.lockService instanceof NodeOperationLockService);
    assert.ok(host.runtime.worker.lockService.repository instanceof NodeOperationLockRepository);
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

test('incomplete or non-boolean activation remains dormant without execution side effects', async () => {
    for (const overrides of [
        { secretKey: undefined },
        { workerLifecycle: { enabled: 'true' } },
    ]) {
        const { calls, getScheduledTick, host } = createActiveHost(overrides);

        assert.deepEqual(calls, []);
        assert.equal(getScheduledTick(), undefined);
        assert.deepEqual(host.start(), {
            enabled: false,
            running: false,
            inFlight: false,
        });
        assert.deepEqual(calls, []);
        await assert.rejects(
            host.runtime.worker.secretResolver({ kind: 'install' }),
            error => error?.code === 'L2TP_SECRET_RESOLVER_UNAVAILABLE',
        );
        assert.deepEqual(calls, []);
    }
});
