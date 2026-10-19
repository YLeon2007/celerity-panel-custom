'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { L2tpOperationWorker } = require('../workers/l2tpOperationWorker');
const { L2tpService } = require('../services/l2tpService');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST, PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');

const { L2tpNodeExecutionResolver } = require('../services/l2tpNodeExecutionResolver');
const { createL2tpNodeTransportResolver } = require('../services/l2tpNodeTransportFactory');
const { L2tpPreflightRunner } = require('../services/l2tpPreflightRunner');
const { L2tpRemoteExecutor } = require('../services/l2tpRemoteExecutor');

test('server environment selection preserves TEST flags and needs a separate literal production opt-in', () => {
    const { resolveL2tpExecutionAuthorization } = require('../domain/l2tpExecutionAuthorization');
    const flags = { L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
        TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
    const testAuthorization = resolveL2tpExecutionAuthorization({ ...flags, PANEL_DOMAIN: TEST.hostIdentity });
    assert.equal(testAuthorization.executionContext, TEST);
    assert.equal(testAuthorization.enableUnsafeExecutionForTests, true);
    assert.equal(testAuthorization.enableInstallAdmission, true);
    assert.equal(testAuthorization.enableProductionExecution, false);
    for (const PANEL_DOMAIN of [undefined, PROD.hostIdentity, TEST.hostIdentity + ' ', TEST.hostIdentity.toUpperCase()]) {
        assert.equal(resolveL2tpExecutionAuthorization({ ...flags, PANEL_DOMAIN }).executionContext, undefined);
    }
    for (const field of Object.keys(flags)) {
        assert.equal(resolveL2tpExecutionAuthorization({ ...flags, PANEL_DOMAIN: TEST.hostIdentity,
            [field]: true }).executionContext, undefined);
    }
    for (const optIn of [undefined, false, true, 'TRUE', 'true ']) {
        assert.equal(resolveL2tpExecutionAuthorization({ ...flags, PANEL_DOMAIN: PROD.hostIdentity,
            L2TP_PRODUCTION_EXECUTION_ENABLED: optIn }).executionContext, undefined);
    }
    const env = { ...flags, TOPOLOGY_TEST_EXECUTION_ENABLED: undefined,
        PANEL_DOMAIN: PROD.hostIdentity, L2TP_PRODUCTION_EXECUTION_ENABLED: 'true' };
    for (const field of ['L2TP_EXECUTION_ENABLED', 'L2TP_MIGRATIONS_ENABLED']) {
        assert.equal(resolveL2tpExecutionAuthorization({ ...env, [field]: 'false' }).executionContext, undefined);
    }
    const productionAuthorization = resolveL2tpExecutionAuthorization(env);
    env.PANEL_DOMAIN = TEST.hostIdentity;
    assert.equal(productionAuthorization.executionContext, PROD);
    assert.equal(productionAuthorization.enableUnsafeExecutionForTests, false);
    assert.equal(productionAuthorization.enableProductionExecution, true);
    assert.equal(productionAuthorization.enableInstallAdmission, true);
    assert.equal(Object.isFrozen(productionAuthorization), true);
});

function workerHarness(options = {}) {
    const calls = [];
    const worker = new L2tpOperationWorker({
        enableUnsafeExecutionForTests: true,
        remoteAdmissionRepository: {
            async recoverSettledAdmissions(request) { calls.push(['recover', request]); },
            async claimQueuedInstall(request) { calls.push(['install', request]); return null; },
            async claimQueuedSyncUsers(request) { calls.push(['sync', request]); return null; },
        },
        workerId: 'worker', leaseMs: 30000,
        clock: { now: () => new Date('2026-10-19T00:00:00Z') },
        ...options,
    });
    return { worker, calls };
}

test('PROD cannot recover or claim with TEST flags alone', async () => {
    const { worker, calls } = workerHarness({ executionContext: PROD });
    assert.deepEqual(await worker.runOnce(), { claimed: false, unavailable: true });
    assert.deepEqual(calls, []);
});

test('missing, malformed and cross-paired server contexts cannot claim', async () => {
    for (const executionContext of [undefined, {}, { ...TEST, hostIdentity: PROD.hostIdentity },
        { ...PROD, hostIdentity: TEST.hostIdentity }, { ...TEST, target: 'TEST' },
        { ...TEST, extra: true }]) {
        const { worker, calls } = workerHarness({ executionContext, enableProductionExecution: true });
        assert.deepEqual(await worker.runOnce(), { claimed: false, unavailable: true });
        assert.deepEqual(calls, []);
    }
});

test('authorized TEST and separately opted-in PROD bind immutable claim requests', async () => {
    for (const selected of [TEST, PROD]) {
        const source = { ...selected };
        const { worker, calls } = workerHarness({ executionContext: source,
            enableUnsafeExecutionForTests: selected === TEST, enableProductionExecution: selected === PROD });
        source.target = 'bad';
        assert.deepEqual(await worker.runOnce(), { claimed: false });
        assert.equal(calls.length, 3);
        for (const [, request] of calls) {
            assert.deepEqual(request.executionContext, selected);
            assert.equal(Object.isFrozen(request.executionContext), true);
        }
        assert.throws(() => { worker.executionContext = TEST; }, TypeError);
    }
});

test('standalone preflight and install authorize before persistence or counted admission', async () => {
    for (const executionContext of [undefined, { ...TEST, hostIdentity: PROD.hostIdentity }, PROD]) {
        const service = new L2tpService({ executionContext, enableInstallAdmission: true,
            nodeRepository: { async findById() { assert.fail('must reject before persistence'); } } });
        for (const method of ['preflight', 'install']) {
            await assert.rejects(service[method]('node', {}), { code: 'L2TP_EXECUTION_NOT_AUTHORIZED' });
        }
    }
});

function installContext(executionContext) {
    return { executionContext, node: { id: 'relay' }, relay: { id: 'relay', role: 'relay' },
        desired: { desiredState: 'installed', clientCidr: '10.77.0.0/24', localAddress: '10.77.0.1',
            poolStart: '10.77.0.2', poolEnd: '10.77.0.9', dnsServers: ['1.1.1.1'],
            tproxyPort: 12345, fwmark: 77, routeTable: 177 },
        routeGroup: {}, relayGroupPlan: {}, topologyRevision: 1 };
}

test('direct preflight rejects missing/cross operation binding before resolver or artifact calls', async () => {
    for (const selected of [TEST, PROD]) {
        for (const binding of [undefined, {}, selected === TEST ? PROD : TEST]) {
            let resolved = 0;
            const runner = new L2tpPreflightRunner({ executionContext: selected,
                enableProductionExecution: true,
                transportResolver: async () => { resolved++; throw new Error('unexpected'); } });
            assert.equal((await runner.run(installContext(binding))).error.code,
                'L2TP_EXECUTION_NOT_AUTHORIZED');
            assert.equal(resolved, 0);
        }
    }
});

test('authorized direct preflight binds context without putting identity in remote artifact payload', async () => {
    for (const selected of [TEST, PROD]) {
        const source = { ...selected };
        const calls = [];
        const runner = new L2tpPreflightRunner({ executionContext: source,
            enableProductionExecution: selected === PROD,
            transportResolver: async request => {
                calls.push(request);
                return { async uploadRootFile(request) { calls.push(request); },
                    async runArtifactCommand(request) { calls.push(request); return { ok: true, checks: [
                        { check: 'os', status: 'ok', id: 'debian', version: '13' },
                        { check: 'client_cidr', status: 'ok', cidr: '10.77.0.0/24' },
                        { check: 'xray', status: 'ok', version: '26' },
                        { check: 'xray_config', status: 'ok', path: '/usr/local/etc/xray/config.json' },
                        { check: 'xray_unit', status: 'ok', unit: 'xray.service' },
                    ] }; } };
            } });
        source.hostIdentity = 'bad';
        assert.equal((await runner.run(installContext(selected))).ok, true);
        assert.equal(calls[0].executionContext, selected);
        assert.equal(Object.isFrozen(calls[0].executionContext), true);
        assert.doesNotMatch(JSON.stringify(calls.slice(1)), /hostIdentity|executionContext/);
    }
});

test('node resolver and transport factory reject unbound/crossed and non-opted PROD before NodeSSH/Agent', async () => {
    for (const selected of [undefined, TEST, PROD]) {
        const resolver = new L2tpNodeExecutionResolver({ executionContext: selected,
            HyNode: { findById() { assert.fail('no node lookup'); } },
            NodeSSH: class { constructor() { assert.fail('no SSH'); } } });
        for (const binding of [undefined, selected === TEST ? PROD : TEST]) {
            await assert.rejects(resolver.resolve('relay', binding), { code: 'L2TP_EXECUTION_NOT_AUTHORIZED' });
        }
    }
    for (const selected of [undefined, PROD]) {
        const resolver = createL2tpNodeTransportResolver({ executionContext: selected,
            nodeExecutionResolver: { async resolve() { assert.fail('no SSH'); } } });
        await assert.rejects(resolver({ nodeId: 'relay', executionContext: selected }),
            { code: 'L2TP_EXECUTION_NOT_AUTHORIZED' });
    }
});

test('executor denies direct unbound/cross operations before even injected transport', async () => {
    for (const selected of [TEST, PROD]) {
        const executor = new L2tpRemoteExecutor({ executionContext: selected, enableProductionExecution: true,
            transport: { async runArtifactCommand() { assert.fail('no transport'); } } });
        for (const binding of [undefined, selected === TEST ? PROD : TEST]) {
            await assert.rejects(executor.executeStep({ operation: { id: 'op', executionContext: binding },
                step: { type: 'verify' } }), { code: 'L2TP_EXECUTION_NOT_AUTHORIZED' });
        }
    }
});

test('direct transport cannot bootstrap, upload or issue read-only commands without server authorization', async () => {
    const { L2tpNodeTransport } = require('../services/l2tpNodeTransport');
    for (const executionContext of [undefined, {}, { ...TEST, hostIdentity: PROD.hostIdentity }, PROD]) {
        const transport = new L2tpNodeTransport({ executionContext,
            nodeSSH: { async exec() { assert.fail('no SSH/Agent'); } },
            artifactBootstrapper: { async ensureArtifact() { assert.fail('no bootstrap'); } } });
        for (const method of ['uploadRootFile', 'runArtifactCommand', 'verifyUsersReadOnly']) {
            await assert.rejects(transport[method]({}), { code: 'L2TP_EXECUTION_NOT_AUTHORIZED' });
        }
    }
});

test('authorized production transport runs fixed commands only after explicit server opt-in', async () => {
    const { L2tpNodeTransport } = require('../services/l2tpNodeTransport');
    const calls = [];
    const source = { ...PROD };
    const transport = new L2tpNodeTransport({ executionContext: source, enableProductionExecution: true,
        nodeSSH: { async exec(command) { calls.push(command); return { code: 0 }; } },
        artifactBootstrapper: { async ensureArtifact() { calls.push('bootstrap'); } } });
    source.hostIdentity = TEST.hostIdentity;
    assert.equal((await transport.runArtifactCommand({ operationId: 'prod-bound', command: 'verify' })).ok, true);
    assert.equal((await transport.runArtifactCommand({ operationId: 'prod-bound', command: 'commit' })).ok, true);
    assert.deepEqual(calls, ['bootstrap',
        '/usr/local/bin/celerity-l2tp-artifact-runner --operation-id prod-bound --command verify',
        '/usr/local/bin/celerity-l2tp-artifact-runner --operation-id prod-bound --command commit']);
    assert.equal(transport.executionContext, PROD);
});

test('durable operation schema retains exact context and rejects crossed or partial identities', async () => {
    const Model = require('../models/l2tpOperationModel');
    const fields = { node: '507f1f77bcf86cd799439011', kind: 'install', status: 'queued',
        idempotencyKey: 'install-one', plan: { steps: [] } };
    for (const executionContext of [TEST, PROD]) {
        const document = new Model({ ...fields, executionContext });
        await document.validate();
        assert.deepEqual(document.toObject().executionContext, executionContext);
    }
    for (const executionContext of [{}, { target: 'test' }, { ...TEST, hostIdentity: PROD.hostIdentity },
        { ...PROD, hostIdentity: TEST.hostIdentity }, { ...TEST, hostIdentity: TEST.hostIdentity + ' ' }]) {
        const document = new Model({ ...fields, executionContext });
        await assert.rejects(document.validate());
    }
    assert.equal(Model.schema.path('executionContext').options.immutable, true);
});

test('unauthorized active execution composition stays dormant before factories or model access', async () => {
    const { createL2tpExecutionRuntime } = require('../runtime/createL2tpExecutionRuntime');
    for (const executionContext of [undefined, {}, PROD, { ...TEST, hostIdentity: PROD.hostIdentity }]) {
        const host = createL2tpExecutionRuntime({ workerLifecycle: { enabled: true },
            runtimeDependencies: { executionContext },
            createRuntime: options => ({ options }),
            createPreflightRunner() { assert.fail('no preflight factory'); },
        });
        assert.deepEqual(host.start(), { enabled: false, running: false, inFlight: false });
        assert.equal((await host.runtime.options.preflightRunner()).ok, false);
        assert.deepEqual(await host.stop(), { enabled: false, running: false, inFlight: false });
    }
});

test('execution composition snapshots context before injected factories and carries it to lazy transport', async () => {
    const { createL2tpExecutionRuntime } = require('../runtime/createL2tpExecutionRuntime');
    const source = { ...PROD };
    const db = { startSession() { assert.fail('no DB session'); } };
    const model = new Proxy({ db }, { get(target, key) { return target[key] ?? (() => {}); } });
    let preflightOptions;
    let runtimeOptions;
    const transports = [];
    const host = createL2tpExecutionRuntime({
        workerLifecycle: { enabled: true, timer: { setInterval() { return 1; }, clearInterval() {} } },
        HyNode: { find() {}, findById() { return { select() { return this; }, lean: async () => ({
            _id: 'relay', active: true, type: 'xray', cascadeRole: 'relay', ssh: {} }) }; } },
        RelayL2tpState: model, L2tpUser: model, CascadeRouteGroup: model, CascadeTopologyState: model,
        RemoteAdmission: model, operationModel: model, lockModel: model,
        NodeSSH: class {}, NodeTransport: class { constructor(options) { transports.push(options); } },
        createPreflightRunner(options) { preflightOptions = options; source.target = 'test'; return async () => {}; },
        createCandidateService: () => ({ buildCandidate() {} }), candidateNodeResolver() {},
        candidateUserResolver() {}, configGenerator() {}, fragmentProvider() {}, operationMaterializer() {},
        createUserSnapshotResolver: () => async () => ({}),
        createUserSyncReconciler: () => ({ finalizeVerifiedSync() {} }),
        secretBox: { encrypt() {}, decrypt() {} }, secretKey: 'local-test-key', clock: { now: () => new Date() },
        runtimeDependencies: { executionContext: source, enableProductionExecution: true,
            stateRepository: { getTopologyRevision() {} }, enableInstallAdmission: true },
        createRuntime(options) { runtimeOptions = options; return { service: { install() {}, getOperation() {} }, worker: { async runOnce() {} } }; },
    });
    assert.equal(preflightOptions.executionContext, PROD);
    assert.equal(preflightOptions.enableProductionExecution, true);
    assert.equal(runtimeOptions.executionContext, PROD);
    assert.equal(runtimeOptions.enableProductionExecution, true);
    await runtimeOptions.transportResolver({ nodeId: 'relay', executionContext: PROD });
    assert.equal(transports[0].executionContext, PROD);
    assert.equal(transports[0].enableProductionExecution, true);
    assert.equal(host.start().running, true);
    assert.equal((await host.stop()).running, false);
});
