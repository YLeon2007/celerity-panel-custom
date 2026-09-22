'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const test = require('node:test');

const { createL2tpRuntime } = require('../runtime/createL2tpRuntime');
const { L2tpOperationRepository } = require('../services/l2tpOperationRepository');
const { buildInstallPlan } = require('../services/l2tpProvisionPlanService');
const { L2tpRemoteExecutor } = require('../services/l2tpRemoteExecutor');
const { L2tpService } = require('../services/l2tpService');
const { L2tpOperationWorker } = require('../workers/l2tpOperationWorker');

function createDependencies() {
    return {
        operationModel: {
            async create() {},
            async findById() {},
            async findOneAndUpdate() {},
            async updateOne() {},
        },
        operationRepository: {
            async create() {},
            async findById() {},
        },
        nodeRepository: { async findById() {} },
        stateRepository: { async findByNodeId() {} },
        stateManagementService: {
            repository: { connectionString: 'mongodb://state-management-secret' },
            secretBox: { privateKey: 'secret-box-private-key' },
            secretKey: 'state-management-secret-key',
            randomBytes() {},
            async configureRelay() {},
        },
        userManagementService: {
            repository: { connectionString: 'mongodb://user-management-secret' },
            secretBox: { privateKey: 'user-secret-box-private-key' },
            secretKey: 'user-management-secret-key',
            async createUser() {},
            async listUsers() { return []; },
            async updateUser() {},
            async disableUser() {},
        },
        preflightRunner: async () => ({ ok: true }),
        transport: {
            async uploadRootFile() {},
            async runArtifactCommand() {},
        },
        lockService: {
            async acquire() {},
            async release() {},
        },
        secretResolver: async () => ({
            psk: 'resolved-in-memory-only',
            users: [],
        }),
        stateReconciler: async () => ({ status: 'installed' }),
        candidateService: { async buildCandidate() {} },
        requireAuth(req, res, next) { next(); },
        requireOnboarding(req, res, next) { next(); },
        csrf(req, res, next) { next(); },
        rateLimiter(req, res, next) { next(); },
        async loadPanelOverview() { return {}; },
        renderPage() {},
        clock: { now: () => new Date('2026-09-22T10:00:00.000Z') },
        workerId: 'l2tp-worker-1',
        leaseMs: 30_000,
    };
}

test('composes the L2TP service, worker, router, and fragment registry', () => {
    const dependencies = createDependencies();

    const runtime = createL2tpRuntime(dependencies);

    assert.deepEqual(Object.keys(runtime), [
        'service',
        'worker',
        'router',
        'configFragmentRegistry',
    ]);
    assert.ok(runtime.service instanceof L2tpService);
    assert.strictEqual(runtime.service.nodeRepository, dependencies.nodeRepository);
    assert.strictEqual(runtime.service.stateRepository, dependencies.stateRepository);
    assert.strictEqual(runtime.service.operationRepository, dependencies.operationRepository);
    assert.strictEqual(runtime.service.planBuilder, buildInstallPlan);
    assert.strictEqual(runtime.service.preflightRunner, dependencies.preflightRunner);
    assert.strictEqual(runtime.service.clock, dependencies.clock);
    assert.strictEqual(runtime.stateManagementService, dependencies.stateManagementService);
    assert.strictEqual(runtime.userManagementService, dependencies.userManagementService);
    assert.equal(
        Object.prototype.propertyIsEnumerable.call(runtime, 'stateManagementService'),
        false,
    );
    assert.equal(
        Object.prototype.propertyIsEnumerable.call(runtime, 'userManagementService'),
        false,
    );

    assert.ok(runtime.worker instanceof L2tpOperationWorker);
    assert.ok(runtime.worker.operationRepository instanceof L2tpOperationRepository);
    assert.strictEqual(runtime.worker.operationRepository.model, dependencies.operationModel);
    assert.ok(runtime.worker.executor instanceof L2tpRemoteExecutor);
    assert.strictEqual(runtime.worker.executor.transport, dependencies.transport);
    assert.strictEqual(runtime.worker.lockService, dependencies.lockService);
    assert.strictEqual(runtime.worker.secretResolver, dependencies.secretResolver);
    assert.strictEqual(runtime.worker.stateReconciler, dependencies.stateReconciler);
    assert.strictEqual(runtime.worker.candidateService, dependencies.candidateService);
    assert.equal(typeof runtime.worker.operationMaterializer, 'function');
    assert.strictEqual(
        runtime.service.operationMaterializer,
        runtime.worker.operationMaterializer,
    );
    assert.strictEqual(runtime.worker.clock, dependencies.clock);
    assert.equal(runtime.worker.workerId, dependencies.workerId);
    assert.equal(runtime.worker.leaseMs, dependencies.leaseMs);

    assert.equal(typeof runtime.router, 'function');
    const [fragment] = runtime.configFragmentRegistry.compose({
        plan: {
            relay: { controlPlaneIps: ['198.51.100.10'] },
            paths: [{
                pathKey: 'primary',
                healthy: true,
                outboundTag: 'cascade-primary',
            }],
            selectedPathKey: 'primary',
        },
        tags: {
            inbound: 'relay-l2tp-route-group-a',
            blockOutbound: 'block',
        },
        tproxyPort: 12345,
    });
    assert.equal(fragment.id, 'relay-l2tp');
});

test('does not surface injected model or transport secrets', () => {
    const dependencies = createDependencies();
    dependencies.operationModel.connectionString = 'mongodb://model-secret';
    dependencies.transport.privateKey = 'transport-private-key';
    dependencies.secretResolver.privateKey = 'resolver-private-key';
    dependencies.candidateService.privateKey = 'candidate-private-key';

    const runtime = createL2tpRuntime(dependencies);
    const serializedRuntime = JSON.stringify(runtime);

    assert.doesNotMatch(serializedRuntime, /model-secret/);
    assert.doesNotMatch(serializedRuntime, /transport-private-key/);
    assert.doesNotMatch(serializedRuntime, /resolver-private-key/);
    assert.doesNotMatch(serializedRuntime, /state-management-secret/);
    assert.doesNotMatch(serializedRuntime, /secret-box-private-key/);
    assert.doesNotMatch(serializedRuntime, /user-management-secret/);
    assert.doesNotMatch(serializedRuntime, /user-secret-box-private-key/);
    assert.doesNotMatch(serializedRuntime, /candidate-private-key/);
    assert.equal(Object.hasOwn(runtime, 'operationModel'), false);
    assert.equal(Object.hasOwn(runtime, 'transport'), false);
    for (const propertyName of ['repository', 'secretBox', 'secretKey', 'randomBytes']) {
        assert.equal(
            Object.prototype.propertyIsEnumerable.call(
                runtime.stateManagementService,
                propertyName,
            ),
            false,
            propertyName,
        );
    }
    for (const propertyName of ['repository', 'secretBox', 'secretKey']) {
        assert.equal(
            Object.prototype.propertyIsEnumerable.call(
                runtime.userManagementService,
                propertyName,
            ),
            false,
            propertyName,
        );
    }
    for (const propertyName of [
        'operationRepository',
        'lockService',
        'executor',
        'secretResolver',
        'stateReconciler',
        'candidateService',
        'operationMaterializer',
        'clock',
        'timer',
    ]) {
        assert.equal(
            Object.prototype.propertyIsEnumerable.call(runtime.worker, propertyName),
            false,
            propertyName,
        );
    }
});

test('construction performs no timer, worker, persistence, transport, or root-router work', () => {
    const calls = [];
    const unexpected = name => () => {
        calls.push(name);
        throw new Error(`unexpected construction side effect: ${name}`);
    };
    const dependencies = createDependencies();
    dependencies.operationModel = {
        create: unexpected('operationModel.create'),
        findById: unexpected('operationModel.findById'),
        findOneAndUpdate: unexpected('operationModel.findOneAndUpdate'),
        updateOne: unexpected('operationModel.updateOne'),
        connect: unexpected('operationModel.connect'),
    };
    dependencies.preflightRunner = unexpected('preflightRunner');
    dependencies.transport = {
        uploadRootFile: unexpected('transport.uploadRootFile'),
        runArtifactCommand: unexpected('transport.runArtifactCommand'),
        connect: unexpected('transport.connect'),
    };
    dependencies.lockService = {
        acquire: unexpected('lockService.acquire'),
        release: unexpected('lockService.release'),
    };
    dependencies.secretResolver = unexpected('secretResolver');
    dependencies.clock = { now: unexpected('clock.now') };
    dependencies.panelRouter = { use: unexpected('panelRouter.use') };

    const originalSetInterval = global.setInterval;
    let runtime;
    global.setInterval = unexpected('global.setInterval');
    try {
        runtime = createL2tpRuntime(dependencies);
    } finally {
        global.setInterval = originalSetInterval;
    }

    assert.deepEqual(calls, []);
    assert.equal(typeof runtime.worker.runOnce, 'function');
    assert.equal(typeof runtime.router, 'function');
});

test('construction does not access local files or open network clients or servers', () => {
    const calls = [];
    const blockedMethods = [
        [fs, 'readFileSync', 'fs.readFileSync'],
        [fs, 'writeFileSync', 'fs.writeFileSync'],
        [fs, 'openSync', 'fs.openSync'],
        [fs, 'createReadStream', 'fs.createReadStream'],
        [fs, 'createWriteStream', 'fs.createWriteStream'],
        [net, 'connect', 'net.connect'],
        [net, 'createConnection', 'net.createConnection'],
        [net, 'createServer', 'net.createServer'],
        [http, 'request', 'http.request'],
        [http, 'get', 'http.get'],
        [http, 'createServer', 'http.createServer'],
        [https, 'request', 'https.request'],
        [https, 'get', 'https.get'],
        [https, 'createServer', 'https.createServer'],
    ];
    const originals = blockedMethods.map(([target, method]) => target[method]);

    try {
        for (const [target, method, label] of blockedMethods) {
            target[method] = () => {
                calls.push(label);
                throw new Error(`unexpected construction side effect: ${label}`);
            };
        }
        createL2tpRuntime(createDependencies());
    } finally {
        blockedMethods.forEach(([target, method], index) => {
            target[method] = originals[index];
        });
    }

    assert.deepEqual(calls, []);
});

test('composes an injected lazy transport resolver and materializer without resolving transport', () => {
    const dependencies = createDependencies();
    const resolverCalls = [];
    const transportResolver = async request => {
        resolverCalls.push(request);
        return {
            async uploadRootFile() {},
            async runArtifactCommand() {},
        };
    };
    const operationMaterializer = async () => ({
        persistedPlan: { steps: [] },
        remoteArtifacts: [],
    });
    delete dependencies.transport;
    dependencies.transportResolver = transportResolver;
    dependencies.operationMaterializer = operationMaterializer;

    const runtime = createL2tpRuntime(dependencies);

    assert.deepEqual(resolverCalls, []);
    assert.strictEqual(runtime.worker.executor.transportResolver, transportResolver);
    assert.strictEqual(runtime.worker.operationMaterializer, operationMaterializer);
    assert.strictEqual(runtime.service.operationMaterializer, operationMaterializer);
    assert.equal(Object.prototype.propertyIsEnumerable.call(runtime.worker.executor, 'transportResolver'), false);
});

test('rejects every missing explicit runtime dependency before composition', () => {
    assert.throws(
        () => createL2tpRuntime(),
        /dependencies/i,
    );

    const dependencyNames = [
        'operationModel',
        'operationRepository',
        'nodeRepository',
        'stateRepository',
        'stateManagementService',
        'userManagementService',
        'preflightRunner',
        'transport',
        'lockService',
        'secretResolver',
        'stateReconciler',
        'candidateService',
        'requireAuth',
        'requireOnboarding',
        'csrf',
        'rateLimiter',
        'loadPanelOverview',
        'renderPage',
        'clock',
        'workerId',
        'leaseMs',
    ];
    for (const dependencyName of dependencyNames) {
        const dependencies = createDependencies();
        delete dependencies[dependencyName];
        assert.throws(
            () => createL2tpRuntime(dependencies),
            new RegExp(dependencyName, 'i'),
        );
    }
});
