'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync, readdirSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { createL2tpPanelHost } = require('../createL2tpPanelHost');
const {
    TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST,
    PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD,
} = require('../relay-l2tp/domain/topologyExecutionContext');

// Activate only L2TP here; topology recovery has its own independent opt-in.
const PROD_ENV = Object.freeze({
    PANEL_DOMAIN: PROD.hostIdentity,
    L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true',
    L2TP_PRODUCTION_EXECUTION_ENABLED: 'true',
});
const {
    L2tpUserManagementRepository,
    SAFE_USER_SELECT,
} = require('../relay-l2tp/repositories/l2tpUserManagementRepository');
const { createL2tpRuntime } = require('../relay-l2tp/runtime/createL2tpRuntime');
const {
    VERIFIED_STATE_SAFE_SELECT,
} = require('../relay-l2tp/repositories/l2tpStateManagementRepository');
const { L2tpNodeTransport } = require('../relay-l2tp/services/l2tpNodeTransport');
const { INSPECT_COMMAND } = require('../relay-l2tp/services/l2tpArtifactBootstrapper');
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

function installedL2tpBundleInspection() {
    const directory = path.join(__dirname, '../relay-l2tp/node-artifacts/l2tp');
    return readdirSync(directory)
        .filter(name => (name.endsWith('.sh') || name.endsWith('.py')) && name !== 'install.sh')
        .sort()
        .map(name => `${createHash('sha256').update(readFileSync(path.join(directory, name))).digest('hex')}  /usr/local/lib/celerity/relay-l2tp/${name}`)
        .join('\n');
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
        session() { return this; },
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
        find() {
            throw new Error('not used outside the simple facade');
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
        find() {
            throw new Error('not used outside the simple facade');
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
    const admissionGate = overrides.admissionReady === true ? { remoteAdmissionCount: 0 } : null;
    const admissionRecords = new Map();
    const testSession = { id: 'active-runtime-state-fence' };
    const admissionSession = {
        withTransaction: async work => work(), endSession: async () => {},
    };
    const db = { transaction: work => work(testSession), startSession: async () => admissionSession };
    RelayL2tpState.db = db;
    const models = {
        RelayL2tpState,
        L2tpUser,
        CascadeRouteGroup: {
            modelName: 'CascadeRouteGroup',
            find() {
                throw new Error('not used outside the simple facade');
            },
        },
        CascadeTopologyState: {
            modelName: 'CascadeTopologyState',
            db,
            async updateOne(filter, update, options) {
                calls.push({ kind: 'CascadeTopologyState.updateOne', filter, update, options });
                assert.strictEqual(options.session, admissionSession);
                // Legacy singleton has no remoteAdmissionCount; Mongo's $gte:0 cannot match it.
                if (!admissionGate || filter.remoteAdmissionCount?.$gte !== undefined
                    && admissionGate.remoteAdmissionCount < filter.remoteAdmissionCount.$gte
                    || filter.remoteAdmissionCount?.$gt !== undefined
                    && admissionGate.remoteAdmissionCount <= filter.remoteAdmissionCount.$gt) {
                    return { matchedCount: 0 };
                }
                admissionGate.remoteAdmissionCount += update.$inc.remoteAdmissionCount;
                return { matchedCount: 1 };
            },
            findById(id) {
                calls.push({ kind: 'CascadeTopologyState.findById', id });
                return queryResult({ stateTransitionRevision: 0 }, calls, 'CascadeTopologyState');
            },
            findOneAndUpdate(filter, update, options) {
                calls.push({ kind: 'CascadeTopologyState.findOneAndUpdate', filter, update, options });
                return queryResult({ stateTransitionRevision: 1 }, calls, 'CascadeTopologyState');
            },
        },
        RemoteAdmission: { db,
            findOne(filter) {
                const record = [...admissionRecords.values()].find(candidate => {
                    return Object.entries(filter).every(([key, expected]) => {
                        if (expected && typeof expected === 'object' && '$in' in expected) {
                            return expected.$in.includes(candidate[key]);
                        }
                        if (expected && typeof expected === 'object' && '$exists' in expected) {
                            return (candidate[key] !== undefined) === expected.$exists;
                        }
                        return candidate[key] === expected;
                    });
                });
                return queryResult(record ?? null, calls, 'RemoteAdmission');
            },
            async create(documents, options) {
                assert.strictEqual(options.session, admissionSession);
                if (!admissionGate) throw new Error('blocked admission must not create a record');
                for (const document of documents) admissionRecords.set(document._id, { ...document });
            },
            async updateOne(filter, update, options) {
                assert.strictEqual(options.session, admissionSession);
                const record = admissionRecords.get(filter._id);
                if (!record || record.phase !== filter.phase) return { matchedCount: 0 };
                Object.assign(record, update.$set);
                return { matchedCount: 1 };
            },
        },
        L2tpOperation: {
            modelName: 'L2tpOperation', db,
            async updateOne(filter, update, options) {
                calls.push({ kind: 'L2tpOperation.updateOne', filter, update, options });
                assert.strictEqual(options.session, testSession);
                return { matchedCount: 1 };
            },
        },
        NodeOperationLock: {
            modelName: 'NodeOperationLock', db,
            async create(document) {
                calls.push({ kind: 'NodeOperationLock.create', document });
                return { ...document };
            },
            async updateOne(filter, update, options) {
                calls.push({ kind: 'NodeOperationLock.updateOne', filter, update, options });
                assert.strictEqual(options.session, testSession);
                return { matchedCount: 1 };
            },
            async deleteOne(filter) {
                calls.push({ kind: 'NodeOperationLock.deleteOne', filter });
                return { deletedCount: 1 };
            },
        },
    };

    class FakeNodeSSH {
        constructor(node) {
            this.node = node;
            calls.push({ kind: 'NodeSSH.construct', node });
        }

        async exec(command, options) {
            calls.push({ kind: 'NodeSSH.exec', command, options });
            if (command === INSPECT_COMMAND) {
                const runner = readFileSync(path.join(
                    __dirname, '../relay-l2tp/node-artifacts/l2tp/runner.sh',
                ));
                return {
                    code: 0,
                    stdout: installedL2tpBundleInspection(),
                    stderr: '',
                };
            }
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
        env: PROD_ENV,
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
        admissionGate,
        admissionRecords,
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
        testSession,
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
    assert.strictEqual(host.runtime.service.remoteAdmissionRepository,
        runtimeCalls[0].remoteAdmissionRepository);
    assert.equal(typeof runtimeCalls[0].remoteAdmissionRepository.acquire, 'function');
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
    assert.strictEqual(runtimeCalls[0].remoteAdmissionRepository.L2tpOperation,
        userManagementDependencies.L2tpOperation);
    assert.strictEqual(host.runtime.worker.remoteAdmissionRepository,
        runtimeCalls[0].remoteAdmissionRepository);
    assert.strictEqual(runtimeCalls[0].executionContext, PROD);
    assert.equal(runtimeCalls[0].enableProductionExecution, true);
    assert.equal(runtimeCalls[0].enableUnsafeExecutionForTests, false);
    assert.equal(runtimeCalls[0].enableInstallAdmission, true);
    for (const component of [host.runtime.service, host.runtime.worker,
        host.runtime.worker.executor, preflightFactoryCalls[0]]) {
        assert.strictEqual(component.executionContext, PROD);
        assert.equal(component.enableProductionExecution, true);
        assert.equal(Object.isFrozen(component.executionContext), true);
    }
    assert.throws(() => { host.runtime.worker.executionContext = TEST; }, TypeError);
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
    assert.equal(calls.some(call => call.kind.startsWith('NodeSSH.')), false);
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
    assert.equal(calls.some(call => call.kind.startsWith('NodeSSH.')), false);

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
    assert.equal(calls.some(call => call.kind.startsWith('NodeSSH.')), false);

    const callsBeforeExecution = calls.slice();
    for (const executionContext of [undefined, TEST,
        { target: PROD.target, hostIdentity: TEST.hostIdentity }]) {
        await assert.rejects(host.runtime.worker.executor.executeStep({
            operation: { _id: 'operation-a', node: 'node-a', executionContext },
            step: { type: 'commit' },
        }), { code: 'L2TP_EXECUTION_NOT_AUTHORIZED' });
    }
    assert.deepEqual(calls, callsBeforeExecution);

    const operation = Object.freeze({
        _id: 'operation-a', node: 'node-a', executionContext: PROD,
    });
    assert.equal(Object.isFrozen(operation.executionContext), true);
    assert.deepEqual(await host.runtime.worker.executor.executeStep({
        operation,
        step: { type: 'commit' },
    }), { ok: true, operationId: 'operation-a', step: 'commit' });

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
            'NodeSSH.exec',
        ],
    );
    assert.equal(calls.filter(call => call.kind === 'NodeSSH.construct').length, 1);
    assert.equal(calls.find(call => call.kind === 'HyNode.findById').nodeId, 'node-a');
    assert.deepEqual(calls.filter(call => call.kind === 'NodeSSH.exec'), [
        { kind: 'NodeSSH.exec', command: INSPECT_COMMAND, options: undefined },
        {
            kind: 'NodeSSH.exec',
            command: '/usr/local/bin/celerity-l2tp-artifact-runner --operation-id operation-a --command commit',
            options: { timeout: 120000 },
        },
    ]);
});

test('host without server authorization rejects install and preflight before persistence or transport', async () => {
    for (const env of [
        {},
        { ...PROD_ENV, PANEL_DOMAIN: TEST.hostIdentity },
        { ...PROD_ENV, L2TP_PRODUCTION_EXECUTION_ENABLED: undefined },
    ]) {
        const { host, calls, admissionGate, preflightFactoryCalls, candidateFactoryCalls } =
            createActiveHost({ admissionReady: true, env });
        for (const method of ['install', 'preflight']) {
            await assert.rejects(host.runtime.service[method]('node-a', {
                routeGroupId: 'group-a', expectedTopologyRevision: 17,
            }), { code: 'L2TP_EXECUTION_NOT_AUTHORIZED' });
        }
        assert.deepEqual(await host.runtime.worker.runOnce(), { claimed: false, unavailable: true });
        assert.deepEqual(host.start(), { enabled: false, running: false, inFlight: false });
        assert.equal(admissionGate.remoteAdmissionCount, 0);
        assert.deepEqual(preflightFactoryCalls, []);
        assert.deepEqual(candidateFactoryCalls, []);
        assert.deepEqual(calls, []);
    }
});

test('active preflight fails closed at admission before transport on a missing singleton', async () => {
    const { calls, host } = createActiveHost();
    assert.deepEqual(calls, []);
    assert.equal(calls.some(call => call.kind.startsWith('NodeSSH.')), false);
    // The assembled legacy singleton lacks a remote admission counter;
    // it must refuse before transport rather than inventing an empty gate.
    await assert.rejects(host.runtime.service.preflight('node-a', {
        routeGroupId: 'group-a', expectedTopologyRevision: 17,
    }), { code: 'REMOTE_ADMISSION_BLOCKED' });
    assert.deepEqual(calls.filter(call => call.kind === 'CascadeTopologyState.updateOne').map(call => ({
        filter: call.filter, update: call.update,
    })), [{
        filter: { _id: 'singleton', remoteDrain: { $exists: false },
            replacementReservation: { $exists: false }, topologyAdmissionCount: 0,
            remoteAdmissionCount: { $gte: 0 } },
        update: { $inc: { remoteAdmissionCount: 1 } },
    }]);
    assert.equal(calls.filter(call => call.kind === 'NodeSSH.construct').length, 0);
    assert.equal(calls.filter(call => call.kind === 'NodeSSH.exec').length, 0);
    assert.equal(calls.some(call => call.kind === 'operationRepository.create'), false);
});

test('assembled active host preserves uncertain worker drain results', async () => {
    const { host, getScheduledTick } = createActiveHost();
    host.runtime.worker.runOnce = async () => ({ claimed: true, status: 'failed', stopped: true,
        errorCode: 'REMOTE_COMMAND_OUTCOME_UNCERTAIN' });
    host.start(); await getScheduledTick()();
    assert.equal((await host.stop()).drainUncertain, true);
});

test('active preflight with admission reaches upload and retains an uncertain response', async () => {
    const { calls, host, admissionRecords, admissionGate } = createActiveHost({ admissionReady: true });
    const result = await host.runtime.service.preflight('node-a', {
        routeGroupId: 'group-a', expectedTopologyRevision: 17,
    });
    assert.deepEqual(result, { ok: false, checks: [], error: { code: 'PREFLIGHT_RESPONSE_INVALID' } });
    assert.equal(admissionGate.remoteAdmissionCount, 1);
    assert.equal([...admissionRecords.values()][0].phase, 'recovery_required');
    const remoteCalls = calls.filter(call => call.kind === 'NodeSSH.exec');
    assert.equal(remoteCalls.length, 3);
    assert.equal(remoteCalls[0].command, INSPECT_COMMAND);
    const match = remoteCalls[1].command.match(/^\/usr\/local\/bin\/celerity-l2tp-artifact-receiver --operation-id (preflight-[0-9a-f]{24}) --artifact-name desired\.json$/);
    assert.ok(match);
    assert.deepEqual(JSON.parse(remoteCalls[1].options.stdin), {
        clientCidr: '10.77.0.0/24', localAddress: '10.77.0.1',
        poolStart: '10.77.0.10', poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1'], tproxyPort: 12345, fwmark: 77, routeTable: 177,
    });
    assert.deepEqual(remoteCalls[2], {
        kind: 'NodeSSH.exec',
        command: `/usr/local/bin/celerity-l2tp-artifact-runner --operation-id ${match[1]} --command preflight`,
        options: { timeout: 120000 },
    });
});

test('active worker reconciler persists verified install state through the management service', async () => {
    const { calls, host, runtimeCalls, testSession } = createActiveHost();
    const verifiedAt = new Date('2026-09-22T10:00:00.000Z');
    const operation = {
        id: 'operation-17',
        admissionId: 'admission-17',
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
    const result = await host.runtime.worker.stateReconciler({ operation, verifiedAt,
        claim: { owner: 'worker-1', ownerGeneration: 2 }, lockGeneration: 'lock-17' });

    assert.strictEqual(host.runtime.worker.stateReconciler, runtimeCalls[0].stateReconciler);
    const fences = calls.filter(call => ['L2tpOperation.updateOne', 'NodeOperationLock.updateOne']
        .includes(call.kind));
    assert.deepEqual(fences.map(call => call.kind),
        ['L2tpOperation.updateOne', 'NodeOperationLock.updateOne']);
    assert.equal(fences[0].filter.admissionId, 'admission-17');
    assert.equal(fences[0].filter.ownerGeneration, 2);
    assert.equal(fences[1].filter.generation, 'lock-17');
    assert.deepEqual(calls.filter(call => !fences.includes(call)), [
        { kind: 'CascadeTopologyState.findById', id: 'singleton' },
        { kind: 'CascadeTopologyState.select', fields: 'stateTransitionRevision replacementReservation' },
        { kind: 'CascadeTopologyState.lean' },
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
            options: { new: true, runValidators: true, session: testSession },
        },
        { kind: 'RelayL2tpState.select', fields: VERIFIED_STATE_SAFE_SELECT },
        { kind: 'RelayL2tpState.lean' },
        {
            kind: 'CascadeTopologyState.findOneAndUpdate',
            filter: { _id: 'singleton', stateTransitionRevision: 0,
                replacementReservation: { $exists: false } },
            update: { $inc: { stateTransitionRevision: 1 } },
            options: { new: true, upsert: false, session: testSession },
        },
        { kind: 'CascadeTopologyState.select', fields: 'stateTransitionRevision' },
        { kind: 'CascadeTopologyState.lean' },
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
