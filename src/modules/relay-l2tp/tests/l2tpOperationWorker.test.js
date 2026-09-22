'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { materializeInstallOperation } = require('../services/l2tpOperationMaterializer');
const { L2tpRemoteExecutor } = require('../services/l2tpRemoteExecutor');
const { buildInstallPlan, INSTALL_STEP_TYPES } = require('../services/l2tpProvisionPlanService');
const { L2tpOperationWorker } = require('../workers/l2tpOperationWorker');

const NOW = new Date('2026-09-22T10:00:00.000Z');

function createOperationRepository(initialOperations = []) {
    const operations = initialOperations.map(operation => ({ ...operation }));
    const calls = [];

    return {
        calls,
        operations,
        async claimNext(request) {
            calls.push({ method: 'claimNext', request });
            const operation = operations.find(candidate => candidate.status === 'queued');
            if (!operation) return null;

            operation.status = 'running';
            operation.leaseOwner = request.owner;
            return operation;
        },
        async renewLease(request) {
            calls.push({ method: 'renewLease', request });
            return true;
        },
        async recordStep(request) {
            calls.push({ method: 'recordStep', request });
        },
        async setStatus(request) {
            calls.push({ method: 'setStatus', request });
            const operation = operations.find(candidate => candidate.id === request.operationId);
            if (operation) operation.status = request.status;
        },
    };
}

function createDeferred() {
    let resolve;
    let reject;
    const promise = new Promise((resolvePromise, rejectPromise) => {
        resolve = resolvePromise;
        reject = rejectPromise;
    });
    return { promise, resolve, reject };
}

function createClock(initial = NOW) {
    let current = new Date(initial);
    return {
        now: () => new Date(current),
        advance(ms) {
            current = new Date(current.getTime() + ms);
        },
    };
}

function createTimer() {
    let nextId = 1;
    const intervals = new Map();
    const calls = [];

    return {
        calls,
        setInterval(callback, intervalMs) {
            const id = nextId++;
            calls.push({ method: 'setInterval', id, intervalMs });
            intervals.set(id, callback);
            return id;
        },
        clearInterval(id) {
            calls.push({ method: 'clearInterval', id });
            intervals.delete(id);
        },
        async tick() {
            const callbacks = [...intervals.values()];
            await Promise.all(callbacks.map(callback => callback()));
        },
        activeCount() {
            return intervals.size;
        },
    };
}

function createWorker(operationRepository, overrides = {}) {
    const lockService = {
        async renew() { return { ok: true }; },
        ...(overrides.lockService || {}),
    };

    return new L2tpOperationWorker({
        operationRepository,
        lockService,
        executor: overrides.executor || {},
        secretResolver: overrides.secretResolver,
        operationMaterializer: overrides.operationMaterializer,
        candidateService: overrides.candidateService,
        workerId: 'worker-1',
        leaseMs: overrides.leaseMs || 30_000,
        clock: overrides.clock || createClock(),
        timer: overrides.timer || createTimer(),
        renewalIntervalMs: overrides.renewalIntervalMs,
    });
}

function createInstallOperation(id = 'operation-install') {
    const desired = {
        desiredState: 'installed',
        routeGroup: 'group-a',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        secretRevision: 9,
    };
    const plan = buildInstallPlan({
        operationId: id,
        topologyRevision: 17,
        relay: { id: 'relay-1', role: 'relay' },
        routeGroup: { id: 'group-a' },
        relayGroupPlan: {
            groupId: 'group-a',
            candidates: [{
                pathKey: 'primary',
                healthy: true,
                nextHopNodeId: 'bridge-1',
            }],
            decision: {
                decision: 'select',
                groupId: 'group-a',
                pathKey: 'primary',
                nextHopNodeId: 'bridge-1',
            },
        },
        desired,
    });
    const { persistedPlan } = materializeInstallOperation({ plan, desired });

    return {
        operation: {
            id,
            node: 'relay-1',
            kind: 'install',
            status: 'queued',
            plan: persistedPlan,
        },
        secrets: { psk: 'worker-jit-psk-secret' },
    };
}

test('claims an install once and resolves its PSK once before typed artifact uploads', async () => {
    const secret = 'worker-jit-psk-secret';
    const candidateContent = '{"inbounds":[{"tag":"relay-l2tp-group-a"}],"outbounds":[],"routing":{"rules":[]}}';
    const { operation } = createInstallOperation('operation-jit');
    const operationRepository = createOperationRepository([operation]);
    const resolverCalls = [];
    const candidateCalls = [];
    const lockCalls = [];
    const transportCalls = [];
    const executor = new L2tpRemoteExecutor({
        transport: {
            async uploadRootFile(request) {
                transportCalls.push({ method: 'uploadRootFile', request });
            },
            async runArtifactCommand(request) {
                transportCalls.push({ method: 'runArtifactCommand', request });
            },
        },
    });
    const worker = createWorker(operationRepository, {
        executor,
        operationMaterializer: materializeInstallOperation,
        candidateService: {
            async buildCandidate(request) {
                candidateCalls.push(request);
                assert.equal(
                    operationRepository.operations[0].status,
                    'running',
                    'operation must be claimed first',
                );
                assert.deepEqual(transportCalls, [], 'candidate must be built before remote work');
                return {
                    operationId: request.plan.operationId,
                    content: candidateContent,
                };
            },
        },
        secretResolver: async request => {
            resolverCalls.push(request);
            assert.equal(
                operationRepository.operations[0].status,
                'running',
                'operation must be claimed first',
            );
            assert.deepEqual(transportCalls, [], 'secrets must resolve before the first upload');
            return {
                psk: secret,
                users: [{
                    login: 'alice',
                    password: 'alice-current-password',
                    ip: '10.77.0.10',
                }],
            };
        },
        lockService: {
            async acquire(request) {
                lockCalls.push({ method: 'acquire', request });
                return { ok: true };
            },
            async renew() { return { ok: true }; },
            async release(request) {
                lockCalls.push({ method: 'release', request });
                return { ok: true };
            },
        },
    });

    const first = await worker.runOnce();
    const second = await worker.runOnce();

    assert.deepEqual(first, {
        claimed: true,
        operationId: 'operation-jit',
        status: 'succeeded',
    });
    assert.deepEqual(second, { claimed: false });
    assert.deepEqual(resolverCalls, [{
        operationId: 'operation-jit',
        kind: 'install',
        nodeId: 'relay-1',
        credentialRevision: 9,
        secret: 'psk',
    }]);
    assert.deepEqual(candidateCalls, [{ plan: operation.plan }]);
    assert.deepEqual(lockCalls.map(call => call.method), ['acquire', 'release']);

    const uploads = transportCalls.filter(call => call.method === 'uploadRootFile');
    assert.equal(uploads.length, 3);
    assert.deepEqual(
        uploads.map(call => ({
            type: call.request.type,
            path: call.request.path,
        })),
        [
            { type: 'desired', path: 'desired.json' },
            { type: 'artifact', path: 'artifacts.json' },
            { type: 'xrayCandidate', path: 'xray-candidate.json' },
        ],
    );
    assert.deepEqual(JSON.parse(uploads[0].request.content), {
        clientCidr: '10.77.0.0/24',
        users: [{
            login: 'alice',
            password: 'alice-current-password',
            ipAddress: '10.77.0.10',
            enabled: true,
        }],
    });
    assert.match(uploads[1].request.content, new RegExp(secret));
    assert.equal(uploads[2].request.content, candidateContent);
    assert.deepEqual(
        transportCalls
            .filter(call => call.method === 'runArtifactCommand')
            .map(call => call.request.command),
        INSTALL_STEP_TYPES,
    );
    assert.ok(
        transportCalls.indexOf(uploads[0])
            < transportCalls.findIndex(call => (
                call.method === 'runArtifactCommand'
                && call.request.command === 'preflight'
            )),
    );
    assert.ok(
        transportCalls.indexOf(uploads[1])
            < transportCalls.findIndex(call => (
                call.method === 'runArtifactCommand'
                && call.request.command === 'stage_managed_files'
            )),
    );
    assert.ok(
        transportCalls.indexOf(uploads[2])
            < transportCalls.findIndex(call => (
                call.method === 'runArtifactCommand'
                && call.request.command === 'compose_xray_fragment'
            )),
    );
    const externallyVisible = JSON.stringify({
        operation,
        repositoryCalls: operationRepository.calls,
        first,
        second,
    });
    assert.doesNotMatch(externallyVisible, new RegExp(secret));
    assert.doesNotMatch(externallyVisible, /alice-current-password/);
    assert.equal(externallyVisible.includes(candidateContent), false);
    assert.equal(Object.hasOwn(operation.plan.desired, 'users'), false);
    assert.equal(
        operation.plan.steps.some(step => (
            step.artifacts?.some(artifact => Object.hasOwn(artifact, 'content'))
        )),
        false,
    );
});

test('rejects invalid claimed install plans before resolving secrets or remote work', async () => {
    const { operation: validOperation } = createInstallOperation('operation-invalid-plan');
    const cases = [
        {
            name: 'rejected plan',
            expectedCode: 'INSTALL_PLAN_REJECTED',
            plan: { ...validOperation.plan, ok: false },
        },
        {
            name: 'unknown step',
            expectedCode: 'INVALID_INSTALL_PLAN',
            plan: {
                ...validOperation.plan,
                steps: validOperation.plan.steps.map((step, index) => (
                    index === 1 ? { type: 'unknown_step' } : step
                )),
            },
        },
        {
            name: 'duplicate step',
            expectedCode: 'INVALID_INSTALL_PLAN',
            plan: {
                ...validOperation.plan,
                steps: [
                    validOperation.plan.steps[0],
                    validOperation.plan.steps[0],
                    ...validOperation.plan.steps.slice(1),
                ],
            },
        },
    ];

    for (const testCase of cases) {
        let resolverCalls = 0;
        let candidateCalls = 0;
        let lockCalls = 0;
        const transportCalls = [];
        const operationRepository = createOperationRepository([{
            ...validOperation,
            id: `operation-${testCase.name.replaceAll(' ', '-')}`,
            status: 'queued',
            plan: testCase.plan,
        }]);
        const worker = createWorker(operationRepository, {
            operationMaterializer: materializeInstallOperation,
            candidateService: {
                async buildCandidate() {
                    candidateCalls += 1;
                    return { operationId: 'must-not-build', content: '{}' };
                },
            },
            secretResolver: async () => {
                resolverCalls += 1;
                return { psk: 'must-not-resolve' };
            },
            executor: new L2tpRemoteExecutor({
                transport: {
                    async uploadRootFile(request) { transportCalls.push(request); },
                    async runArtifactCommand(request) { transportCalls.push(request); },
                },
            }),
            lockService: {
                async acquire() {
                    lockCalls += 1;
                    return { ok: true };
                },
                async renew() { return { ok: true }; },
                async release() {},
            },
        });

        const result = await worker.runOnce();
        const [failure] = operationRepository.calls.filter(call => call.method === 'setStatus');

        assert.equal(result.status, 'failed', testCase.name);
        assert.equal(resolverCalls, 0, testCase.name);
        assert.equal(candidateCalls, 0, testCase.name);
        assert.equal(lockCalls, 0, testCase.name);
        assert.deepEqual(transportCalls, [], testCase.name);
        assert.equal(failure.request.errorCode, testCase.expectedCode, testCase.name);
    }
});

test('candidate rejection is sanitized and performs no secret resolution or remote work', async () => {
    const leakedCandidate = 'candidate-error-must-not-leak';
    for (const code of ['BLOCKED_TOPOLOGY', 'XRAY_CONFIG_GENERATION_FAILED']) {
        const { operation } = createInstallOperation(`operation-${code.toLowerCase()}`);
        const operationRepository = createOperationRepository([operation]);
        const transportCalls = [];
        let resolverCalls = 0;
        const worker = createWorker(operationRepository, {
            operationMaterializer: materializeInstallOperation,
            candidateService: {
                async buildCandidate() {
                    throw Object.assign(new Error(`${code}: ${leakedCandidate}`), { code });
                },
            },
            secretResolver: async () => {
                resolverCalls += 1;
                return { psk: 'must-not-resolve' };
            },
            executor: new L2tpRemoteExecutor({
                transport: {
                    async uploadRootFile(request) { transportCalls.push(request); },
                    async runArtifactCommand(request) { transportCalls.push(request); },
                },
            }),
            lockService: {
                async acquire() { return { ok: true }; },
                async renew() { return { ok: true }; },
                async release() { return { ok: true }; },
            },
        });

        const result = await worker.runOnce();
        const statuses = operationRepository.calls.filter(call => call.method === 'setStatus');

        assert.deepEqual(result, {
            claimed: true,
            operationId: operation.id,
            status: 'failed',
        });
        assert.equal(resolverCalls, 0);
        assert.deepEqual(transportCalls, []);
        assert.deepEqual(statuses.map(call => call.request.status), ['failed']);
        assert.equal(statuses[0].request.errorCode, 'XRAY_CANDIDATE_FAILED');
        assert.equal(statuses[0].request.errorMessage, 'Failed to build the L2TP Xray candidate');
        assert.doesNotMatch(
            JSON.stringify({ result, repositoryCalls: operationRepository.calls }),
            new RegExp(leakedCandidate),
        );
    }
});

test('secret resolution failure is sanitized and performs no remote command or rollback', async () => {
    const leakedSecret = 'resolver-error-must-not-leak';
    const { operation } = createInstallOperation('operation-resolver-failure');
    const operationRepository = createOperationRepository([operation]);
    const transportCalls = [];
    const lockCalls = [];
    const worker = createWorker(operationRepository, {
        operationMaterializer: materializeInstallOperation,
        candidateService: {
            async buildCandidate({ plan }) {
                return {
                    operationId: plan.operationId,
                    content: '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}',
                };
            },
        },
        secretResolver: async () => {
            throw Object.assign(new Error(`vault failure: ${leakedSecret}`), {
                code: leakedSecret,
            });
        },
        executor: new L2tpRemoteExecutor({
            transport: {
                async uploadRootFile(request) { transportCalls.push(request); },
                async runArtifactCommand(request) { transportCalls.push(request); },
            },
        }),
        lockService: {
            async acquire() { return { ok: true }; },
            async renew() { return { ok: true }; },
            async release(request) {
                lockCalls.push(request);
                return { ok: true };
            },
        },
    });

    const result = await worker.runOnce();
    const statuses = operationRepository.calls.filter(call => call.method === 'setStatus');

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-resolver-failure',
        status: 'failed',
    });
    assert.deepEqual(transportCalls, []);
    assert.equal(lockCalls.length, 1);
    assert.deepEqual(statuses.map(call => call.request.status), ['failed']);
    assert.equal(statuses[0].request.errorCode, 'SECRET_RESOLUTION_FAILED');
    assert.equal(
        statuses[0].request.errorMessage,
        'Failed to resolve L2TP operation secrets',
    );
    assert.doesNotMatch(
        JSON.stringify({ result, repositoryCalls: operationRepository.calls }),
        new RegExp(leakedSecret),
    );
});

test('combined secret resolution failure is sanitized and uploads no user artifacts', async () => {
    const leakedPassword = 'resolver-error-user-password-must-not-leak';
    const { operation } = createInstallOperation('operation-user-resolver-failure');
    const operationRepository = createOperationRepository([operation]);
    const transportCalls = [];
    const lockCalls = [];
    let pskResolutions = 0;
    const worker = createWorker(operationRepository, {
        operationMaterializer: materializeInstallOperation,
        candidateService: {
            async buildCandidate({ plan }) {
                return {
                    operationId: plan.operationId,
                    content: '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}',
                };
            },
        },
        secretResolver: async () => {
            pskResolutions += 1;
            throw Object.assign(new Error(`decrypt failure: ${leakedPassword}`), {
                code: 'L2TP_USER_DECRYPTION_FAILED',
            });
        },
        executor: new L2tpRemoteExecutor({
            transport: {
                async uploadRootFile(request) { transportCalls.push(request); },
                async runArtifactCommand(request) { transportCalls.push(request); },
            },
        }),
        lockService: {
            async acquire() { return { ok: true }; },
            async renew() { return { ok: true }; },
            async release(request) {
                lockCalls.push(request);
                return { ok: true };
            },
        },
    });

    const result = await worker.runOnce();
    const statuses = operationRepository.calls.filter(call => call.method === 'setStatus');

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-user-resolver-failure',
        status: 'failed',
    });
    assert.equal(pskResolutions, 1);
    assert.deepEqual(transportCalls, []);
    assert.equal(lockCalls.length, 1);
    assert.deepEqual(statuses.map(call => call.request.status), ['failed']);
    assert.equal(statuses[0].request.errorCode, 'SECRET_RESOLUTION_FAILED');
    assert.equal(
        statuses[0].request.errorMessage,
        'Failed to resolve L2TP operation secrets',
    );
    assert.doesNotMatch(
        JSON.stringify({ result, repositoryCalls: operationRepository.calls }),
        new RegExp(leakedPassword),
    );
});

test('runOnce reports idle when no queued operation can be claimed', async () => {
    const operationRepository = createOperationRepository();
    const worker = createWorker(operationRepository);

    const result = await worker.runOnce();

    assert.deepEqual(result, { claimed: false });
    assert.deepEqual(operationRepository.calls, [{
        method: 'claimNext',
        request: {
            owner: 'worker-1',
            leaseMs: 30_000,
            now: NOW,
        },
    }]);
});

test('runOnce refuses to succeed a plan without a verify step', async () => {
    const executed = [];
    const operationRepository = createOperationRepository([{
        id: 'operation-without-verify',
        node: 'node-3',
        status: 'queued',
        plan: { steps: [{ type: 'preflight' }, { type: 'commit' }] },
    }]);
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep({ step }) { executed.push(step.type); },
        },
    });

    const result = await worker.runOnce();

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-without-verify',
        status: 'failed',
    });
    assert.deepEqual(executed, []);
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'setStatus'),
        [{
            method: 'setStatus',
            request: {
                operationId: 'operation-without-verify',
                status: 'failed',
                progress: 0,
                errorCode: 'VERIFY_STEP_REQUIRED',
                errorMessage: 'L2TP operation plan must include a verify step',
                finishedAt: NOW,
                journal: {
                    at: NOW,
                    level: 'error',
                    code: 'VERIFY_STEP_REQUIRED',
                    message: 'L2TP operation plan must include a verify step',
                },
            },
        }],
    );
});

test('runOnce journals ordered step progress as the plan executes', async () => {
    const executed = [];
    const operationRepository = createOperationRepository([{
        id: 'operation-2',
        node: 'node-2',
        status: 'queued',
        plan: {
            steps: [
                { type: 'preflight' },
                { type: 'verify' },
                { type: 'commit' },
            ],
        },
    }]);
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep({ step }) {
                executed.push(step.type);
            },
        },
    });

    await worker.runOnce();

    assert.deepEqual(executed, ['preflight', 'verify', 'commit']);
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'recordStep'),
        [
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'preflight',
                    progress: 0,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_STARTED',
                        message: 'Started L2TP operation step: preflight',
                    },
                },
            },
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'preflight',
                    progress: 33,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_SUCCEEDED',
                        message: 'Completed L2TP operation step: preflight',
                    },
                },
            },
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'verify',
                    progress: 33,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_STARTED',
                        message: 'Started L2TP operation step: verify',
                    },
                },
            },
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'verify',
                    progress: 67,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_SUCCEEDED',
                        message: 'Completed L2TP operation step: verify',
                    },
                },
            },
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'commit',
                    progress: 67,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_STARTED',
                        message: 'Started L2TP operation step: commit',
                    },
                },
            },
            {
                method: 'recordStep',
                request: {
                    operationId: 'operation-2',
                    step: 'commit',
                    progress: 100,
                    journal: {
                        at: NOW,
                        level: 'info',
                        code: 'L2TP_STEP_SUCCEEDED',
                        message: 'Completed L2TP operation step: commit',
                    },
                },
            },
        ],
    );
});

test('renews operation and node leases while a step runs longer than the lease', async () => {
    const clock = createClock();
    const timer = createTimer();
    const step = createDeferred();
    const started = createDeferred();
    const lockRenewals = [];
    const operationRepository = createOperationRepository([{
        id: 'operation-long-step',
        node: 'node-long-step',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    const worker = createWorker(operationRepository, {
        clock,
        timer,
        lockService: {
            async acquire() { return { ok: true }; },
            async renew(request) {
                lockRenewals.push(request);
                return { ok: true };
            },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep() {
                started.resolve();
                await step.promise;
            },
        },
    });

    const run = worker.runOnce();
    await started.promise;

    for (const elapsedMs of [10_000, 10_000, 11_000]) {
        clock.advance(elapsedMs);
        await timer.tick();
    }
    step.resolve();

    const result = await run;
    const operationRenewals = operationRepository.calls
        .filter(call => call.method === 'renewLease')
        .map(call => call.request);

    assert.equal(result.status, 'succeeded');
    assert.deepEqual(
        operationRenewals.map(request => request.now),
        [
            NOW,
            new Date('2026-09-22T10:00:10.000Z'),
            new Date('2026-09-22T10:00:20.000Z'),
            new Date('2026-09-22T10:00:31.000Z'),
        ],
    );
    assert.equal(lockRenewals.length, 4);
    assert.ok(timer.calls[0].intervalMs < 30_000);
    assert.equal(timer.activeCount(), 0);
    assert.equal(timer.calls.filter(call => call.method === 'clearInterval').length, 1);
});

test('stops before a second step when operation lease renewal is rejected', async () => {
    const timer = createTimer();
    const step = createDeferred();
    const started = createDeferred();
    const executed = [];
    let renewals = 0;
    let rollbacks = 0;
    const operationRepository = createOperationRepository([{
        id: 'operation-lost-lease',
        node: 'node-lost-lease',
        status: 'queued',
        plan: { steps: [{ type: 'preflight' }, { type: 'verify' }] },
    }]);
    operationRepository.renewLease = async request => {
        operationRepository.calls.push({ method: 'renewLease', request });
        renewals += 1;
        return renewals === 1;
    };
    const worker = createWorker(operationRepository, {
        timer,
        lockService: {
            async acquire() { return { ok: true }; },
            async renew() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep({ step: currentStep }) {
                executed.push(currentStep.type);
                if (currentStep.type === 'preflight') {
                    started.resolve();
                    await step.promise;
                }
            },
            async rollback() { rollbacks += 1; },
        },
    });

    const run = worker.runOnce();
    await started.promise;
    await timer.tick();
    step.resolve();

    const result = await run;

    assert.deepEqual(executed, ['preflight']);
    assert.equal(rollbacks, 0);
    assert.equal(result.status, 'running');
    assert.equal(result.errorCode, 'L2TP_OPERATION_LEASE_LOST');
    assert.equal(
        operationRepository.calls.some(call => call.method === 'setStatus'),
        false,
    );
    assert.equal(timer.activeCount(), 0);
});

test('stops before a second step when node lock renewal rejects', async () => {
    const timer = createTimer();
    const step = createDeferred();
    const started = createDeferred();
    const executed = [];
    let lockRenewals = 0;
    const operationRepository = createOperationRepository([{
        id: 'operation-lock-renew-rejected',
        node: 'node-lock-renew-rejected',
        status: 'queued',
        plan: { steps: [{ type: 'preflight' }, { type: 'verify' }] },
    }]);
    const worker = createWorker(operationRepository, {
        timer,
        lockService: {
            async acquire() { return { ok: true }; },
            async renew() {
                lockRenewals += 1;
                if (lockRenewals > 1) throw new Error('lock store unavailable');
                return { ok: true };
            },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep({ step: currentStep }) {
                executed.push(currentStep.type);
                if (currentStep.type === 'preflight') {
                    started.resolve();
                    await step.promise;
                }
            },
        },
    });

    const run = worker.runOnce();
    await started.promise;
    await timer.tick();
    step.resolve();

    const result = await run;

    assert.deepEqual(executed, ['preflight']);
    assert.equal(result.status, 'running');
    assert.equal(result.errorCode, 'L2TP_LEASE_RENEWAL_FAILED');
    assert.equal(timer.activeCount(), 0);
});

test('does not overlap lease renewal calls when a renewal is still pending', async () => {
    const timer = createTimer();
    const step = createDeferred();
    const stepStarted = createDeferred();
    const renewal = createDeferred();
    const renewalStarted = createDeferred();
    let renewals = 0;
    let activeRenewals = 0;
    let maxActiveRenewals = 0;
    const operationRepository = createOperationRepository([{
        id: 'operation-slow-renewal',
        node: 'node-slow-renewal',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    operationRepository.renewLease = async request => {
        operationRepository.calls.push({ method: 'renewLease', request });
        renewals += 1;
        if (renewals === 1) return true;

        activeRenewals += 1;
        maxActiveRenewals = Math.max(maxActiveRenewals, activeRenewals);
        renewalStarted.resolve();
        await renewal.promise;
        activeRenewals -= 1;
        return true;
    };
    const worker = createWorker(operationRepository, {
        timer,
        lockService: {
            async acquire() { return { ok: true }; },
            async renew() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep() {
                stepStarted.resolve();
                await step.promise;
            },
        },
    });

    const run = worker.runOnce();
    await stepStarted.promise;
    const firstTick = timer.tick();
    await renewalStarted.promise;
    const secondTick = timer.tick();

    assert.equal(renewals, 2);
    assert.equal(maxActiveRenewals, 1);

    renewal.resolve();
    await Promise.all([firstTick, secondTick]);
    step.resolve();
    const result = await run;

    assert.equal(result.status, 'succeeded');
    assert.equal(renewals, 2);
    assert.equal(maxActiveRenewals, 1);
    assert.equal(timer.activeCount(), 0);
});

test('executor failure enters rolling back before rollback and finishes rolled back', async () => {
    const events = [];
    const operationRepository = createOperationRepository([{
        id: 'operation-rollback',
        node: 'node-rollback',
        status: 'queued',
        plan: {
            steps: [
                { type: 'backup' },
                { type: 'start_l2tp' },
                { type: 'verify' },
            ],
        },
    }]);
    const setStatus = operationRepository.setStatus;
    operationRepository.setStatus = async request => {
        events.push({ method: 'setStatus', status: request.status });
        return setStatus(request);
    };
    const executionError = Object.assign(new Error('start failed'), { code: 'START_FAILED' });
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep({ step }) {
                events.push({ method: 'executeStep', step: step.type });
                if (step.type === 'start_l2tp') throw executionError;
            },
            async rollback({ completedSteps, failedStep, error }) {
                events.push({
                    method: 'rollback',
                    completedSteps: completedSteps.map(step => step.type),
                    failedStep: failedStep.type,
                    error,
                });
            },
        },
    });

    const result = await worker.runOnce();

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-rollback',
        status: 'rolled_back',
    });
    assert.deepEqual(events, [
        { method: 'executeStep', step: 'backup' },
        { method: 'executeStep', step: 'start_l2tp' },
        { method: 'setStatus', status: 'rolling_back' },
        {
            method: 'rollback',
            completedSteps: ['backup'],
            failedStep: 'start_l2tp',
            error: executionError,
        },
        { method: 'setStatus', status: 'rolled_back' },
    ]);
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'setStatus'),
        [
            {
                method: 'setStatus',
                request: {
                    operationId: 'operation-rollback',
                    status: 'rolling_back',
                    step: 'start_l2tp',
                    progress: 33,
                    errorCode: 'START_FAILED',
                    errorMessage: 'start failed',
                    journal: {
                        at: NOW,
                        level: 'error',
                        code: 'L2TP_STEP_FAILED',
                        message: 'L2TP operation step failed: start_l2tp',
                    },
                },
            },
            {
                method: 'setStatus',
                request: {
                    operationId: 'operation-rollback',
                    status: 'rolled_back',
                    step: 'start_l2tp',
                    progress: 33,
                    errorCode: 'START_FAILED',
                    errorMessage: 'start failed',
                    finishedAt: NOW,
                    journal: {
                        at: NOW,
                        level: 'warn',
                        code: 'L2TP_OPERATION_ROLLED_BACK',
                        message: 'Rolled back L2TP operation after executor failure',
                    },
                },
            },
        ],
    );
});

test('rollback failure leaves the claimed operation terminally failed', async () => {
    const operationRepository = createOperationRepository([{
        id: 'operation-rollback-failed',
        node: 'node-rollback-failed',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    const executionError = Object.assign(new Error('verify failed'), { code: 'VERIFY_FAILED' });
    const rollbackError = Object.assign(new Error('rollback broke'), { code: 'ROLLBACK_FAILED' });
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep() { throw executionError; },
            async rollback() { throw rollbackError; },
        },
    });

    const result = await worker.runOnce();

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-rollback-failed',
        status: 'failed',
    });
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'setStatus'),
        [
            {
                method: 'setStatus',
                request: {
                    operationId: 'operation-rollback-failed',
                    status: 'rolling_back',
                    step: 'verify',
                    progress: 0,
                    errorCode: 'VERIFY_FAILED',
                    errorMessage: 'verify failed',
                    journal: {
                        at: NOW,
                        level: 'error',
                        code: 'L2TP_STEP_FAILED',
                        message: 'L2TP operation step failed: verify',
                    },
                },
            },
            {
                method: 'setStatus',
                request: {
                    operationId: 'operation-rollback-failed',
                    status: 'failed',
                    step: 'verify',
                    progress: 0,
                    errorCode: 'ROLLBACK_FAILED',
                    errorMessage: 'rollback broke',
                    finishedAt: NOW,
                    journal: {
                        at: NOW,
                        level: 'error',
                        code: 'L2TP_ROLLBACK_FAILED',
                        message: 'Failed to roll back L2TP operation',
                    },
                },
            },
        ],
    );
});

test('lock conflict fails the claimed operation without executing it', async () => {
    const lockCalls = [];
    let executions = 0;
    const operationRepository = createOperationRepository([{
        id: 'operation-lock-conflict',
        node: 'node-locked',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire(request) {
                lockCalls.push({ method: 'acquire', request });
                return { ok: false, error: { code: 'NODE_OPERATION_LOCK_CONFLICT' } };
            },
            async release(request) {
                lockCalls.push({ method: 'release', request });
            },
        },
        executor: {
            async executeStep() { executions += 1; },
        },
    });

    const result = await worker.runOnce();

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-lock-conflict',
        status: 'failed',
    });
    assert.equal(executions, 0);
    assert.deepEqual(lockCalls, [{
        method: 'acquire',
        request: {
            node: 'node-locked',
            owner: 'worker-1',
            operationId: 'operation-lock-conflict',
            leaseMs: 30_000,
        },
    }]);
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'setStatus'),
        [{
            method: 'setStatus',
            request: {
                operationId: 'operation-lock-conflict',
                status: 'failed',
                progress: 0,
                errorCode: 'NODE_OPERATION_LOCK_CONFLICT',
                errorMessage: 'Could not acquire node operation lock',
                finishedAt: NOW,
                journal: {
                    at: NOW,
                    level: 'error',
                    code: 'NODE_OPERATION_LOCK_CONFLICT',
                    message: 'Could not acquire node operation lock',
                },
            },
        }],
    );
});

test('success is persisted only after verify and before releasing the lock', async () => {
    const events = [];
    const operationRepository = createOperationRepository([{
        id: 'operation-success',
        node: 'node-success',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    const setStatus = operationRepository.setStatus;
    operationRepository.setStatus = async request => {
        events.push({ method: 'setStatus', status: request.status });
        return setStatus(request);
    };
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire(request) {
                events.push({ method: 'acquire', request });
                return { ok: true };
            },
            async release(request) {
                events.push({ method: 'release', request });
                return { ok: true };
            },
        },
        executor: {
            async executeStep({ step }) {
                events.push({ method: 'executeStep', step: step.type });
            },
        },
    });

    const result = await worker.runOnce();

    assert.deepEqual(result, {
        claimed: true,
        operationId: 'operation-success',
        status: 'succeeded',
    });
    assert.deepEqual(events, [
        {
            method: 'acquire',
            request: {
                node: 'node-success',
                owner: 'worker-1',
                operationId: 'operation-success',
                leaseMs: 30_000,
            },
        },
        { method: 'executeStep', step: 'verify' },
        { method: 'setStatus', status: 'succeeded' },
        {
            method: 'release',
            request: {
                node: 'node-success',
                owner: 'worker-1',
                operationId: 'operation-success',
            },
        },
    ]);
    assert.deepEqual(
        operationRepository.calls.filter(call => call.method === 'setStatus'),
        [{
            method: 'setStatus',
            request: {
                operationId: 'operation-success',
                status: 'succeeded',
                step: 'verify',
                progress: 100,
                errorCode: '',
                errorMessage: '',
                finishedAt: NOW,
                journal: {
                    at: NOW,
                    level: 'info',
                    code: 'L2TP_OPERATION_SUCCEEDED',
                    message: 'L2TP operation succeeded after verification',
                },
            },
        }],
    );
});

test('does not execute an operation twice after it has been claimed and completed', async () => {
    let executions = 0;
    const operationRepository = createOperationRepository([{
        id: 'operation-duplicate',
        node: 'node-duplicate',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    }]);
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep() { executions += 1; },
        },
    });

    const first = await worker.runOnce();
    const second = await worker.runOnce();

    assert.equal(first.status, 'succeeded');
    assert.deepEqual(second, { claimed: false });
    assert.equal(executions, 1);
});

test('releases the per-operation execution transport after a claimed operation finishes', async () => {
    const releases = [];
    const operation = {
        id: 'operation-release-transport',
        node: 'node-release-transport',
        status: 'queued',
        plan: { steps: [{ type: 'verify' }] },
    };
    const operationRepository = createOperationRepository([operation]);
    const worker = createWorker(operationRepository, {
        lockService: {
            async acquire() { return { ok: true }; },
            async release() { return { ok: true }; },
        },
        executor: {
            async executeStep() {},
            releaseOperation(claimedOperation) {
                releases.push(claimedOperation);
            },
        },
    });

    const result = await worker.runOnce();

    assert.equal(result.status, 'succeeded');
    assert.equal(releases.length, 1);
    assert.strictEqual(releases[0], operationRepository.operations[0]);
});
