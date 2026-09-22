'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { L2tpNodeTransport } = require('../services/l2tpNodeTransport');

function createNodeSSHFacade() {
    const calls = [];

    return {
        calls,
        async exec(command, options) {
            calls.push(options === undefined
                ? { method: 'exec', command }
                : { method: 'exec', command, options });
            return { code: 0, stdout: '', stderr: '' };
        },
        async writeFile(path, content) {
            calls.push({ method: 'writeFile', path, content });
        },
    };
}

test('exposes only the two typed remote executor transport methods', () => {
    const transport = new L2tpNodeTransport({ nodeSSH: createNodeSSHFacade() });

    assert.deepEqual(
        Object.getOwnPropertyNames(Object.getPrototypeOf(transport)),
        ['constructor', 'uploadRootFile', 'runArtifactCommand'],
    );
    assert.equal(transport.exec, undefined);
});

test('uploadRootFile sends an exact typed artifact to the fixed receiver over stdin', async () => {
    const nodeSSH = createNodeSSHFacade();
    const transport = new L2tpNodeTransport({ nodeSSH });
    const content = '{"psk":"transport-secret"}\n';

    const result = await transport.uploadRootFile({
        operationId: 'operation-17',
        type: 'desired',
        path: 'desired.json',
        content,
        owner: 'root',
        group: 'root',
        mode: 0o600,
    });

    assert.deepEqual(nodeSSH.calls, [
        {
            method: 'exec',
            command: '/usr/local/bin/celerity-l2tp-artifact-receiver --operation-id operation-17 --artifact-name desired.json',
            options: { stdin: content },
        },
    ]);
    assert.equal(nodeSSH.calls[0].command.includes(content), false);
    assert.deepEqual(result, {
        ok: true,
        path: '/var/lib/celerity/l2tp/operations/operation-17/desired.json',
    });
});

test('uploadRootFile maps the exact candidate type and staging name to candidate/xray.json', async () => {
    const nodeSSH = createNodeSSHFacade();
    const transport = new L2tpNodeTransport({ nodeSSH });
    const content = '{"marker":"candidate-content-must-use-stdin"}';

    const result = await transport.uploadRootFile({
        operationId: 'operation-xray-candidate',
        type: 'xrayCandidate',
        path: 'xray-candidate.json',
        content,
        owner: 'root',
        group: 'root',
        mode: 0o600,
    });

    assert.deepEqual(nodeSSH.calls, [{
        method: 'exec',
        command: '/usr/local/bin/celerity-l2tp-artifact-receiver --operation-id operation-xray-candidate --artifact-name xray-candidate.json',
        options: { stdin: content },
    }]);
    assert.equal(nodeSSH.calls[0].command.includes(content), false);
    assert.deepEqual(result, {
        ok: true,
        path: '/var/lib/celerity/l2tp/operations/operation-xray-candidate/candidate/xray.json',
    });
});

test('uploadRootFile accepts only exact typed artifact names', async () => {
    const acceptedNodeSSH = createNodeSSHFacade();
    const transport = new L2tpNodeTransport({ nodeSSH: acceptedNodeSSH });

    await transport.uploadRootFile({
        operationId: 'operation-typed',
        type: 'artifact',
        path: 'artifacts.json',
        content: '{}',
        owner: 'root',
        group: 'root',
        mode: 0o600,
    });
    assert.equal(acceptedNodeSSH.calls.length, 1);

    for (const { type, path } of [
        { type: 'desired', path: 'artifacts.json' },
        { type: 'artifact', path: 'desired.json' },
        { type: 'desired', path: 'other.json' },
        { type: 'shell', path: 'desired.json' },
        { type: undefined, path: 'desired.json' },
        { type: 'xrayCandidate', path: 'candidate/xray.json' },
        { type: 'xrayCandidate', path: 'xray.json' },
        { type: 'artifact', path: 'xray-candidate.json' },
        { type: 'xray_candidate', path: 'xray-candidate.json' },
    ]) {
        const nodeSSH = createNodeSSHFacade();
        const candidate = new L2tpNodeTransport({ nodeSSH });
        await assert.rejects(
            candidate.uploadRootFile({
                operationId: 'operation-typed',
                type,
                path,
                content: '{}',
                owner: 'root',
                group: 'root',
                mode: 0o600,
            }),
            error => {
                assert.equal(error.name, 'L2tpNodeTransportError');
                assert.equal(error.code, 'ARTIFACT_NOT_ALLOWED');
                assert.equal(error.message, 'Artifact is not allowed for L2TP root upload');
                assert.equal(Object.hasOwn(error, 'path'), false);
                assert.equal(Object.hasOwn(error, 'type'), false);
                return true;
            },
        );
        assert.deepEqual(nodeSSH.calls, []);
    }
});

test('runArtifactCommand maps every typed command to the fixed artifact runner', async () => {
    const nodeSSH = createNodeSSHFacade();
    const transport = new L2tpNodeTransport({ nodeSSH });
    const commands = [
        'preflight',
        'install_runtime',
        'backup',
        'stage_managed_files',
        'compose_xray_fragment',
        'validate_xray',
        'validate_nft',
        'activate_xray',
        'apply_firewall_policy',
        'start_l2tp',
        'sync_users',
        'verify',
        'commit',
        'rollback',
    ];

    for (const command of commands) {
        assert.deepEqual(
            await transport.runArtifactCommand({ operationId: 'operation-18', command }),
            command === 'preflight'
                ? {
                    ok: false,
                    checks: [],
                    error: { code: 'PREFLIGHT_RESPONSE_INVALID' },
                }
                : { ok: true, operationId: 'operation-18', command },
        );
    }

    assert.deepEqual(
        nodeSSH.calls,
        commands.map(command => ({
            method: 'exec',
            command: `/usr/local/bin/celerity-l2tp-artifact-runner --operation-id operation-18 --command ${command}`,
        })),
    );
});

test('preflight returns only validated structured output from the fixed artifact runner', async () => {
    const secret = 'preflight-transport-output-secret';
    const stdout = [
        '{"check":"os","status":"ok","id":"debian","version":"13"}',
        '{"check":"client_cidr","status":"ok","cidr":"10.77.0.0/24"}',
        '{"check":"xray","status":"ok","version":"Xray 26.3.27"}',
        '{"check":"xray_config","status":"ok","path":"/usr/local/etc/xray/config.json"}',
        '{"check":"xray_unit","status":"ok","unit":"xray.service"}',
    ].join('\n') + '\n';
    const nodeSSH = {
        calls: [],
        async exec(command) {
            this.calls.push({ method: 'exec', command });
            return { code: 0, stdout, stderr: secret };
        },
    };
    const transport = new L2tpNodeTransport({ nodeSSH });

    const result = await transport.runArtifactCommand({
        operationId: 'preflight-operation',
        command: 'preflight',
    });

    assert.deepEqual(nodeSSH.calls, [{
        method: 'exec',
        command: '/usr/local/bin/celerity-l2tp-artifact-runner --operation-id preflight-operation --command preflight',
    }]);
    assert.deepEqual(result, {
        ok: true,
        checks: [
            { check: 'os', status: 'ok', id: 'debian', version: '13' },
            { check: 'client_cidr', status: 'ok', cidr: '10.77.0.0/24' },
            { check: 'xray', status: 'ok', version: 'Xray 26.3.27' },
            {
                check: 'xray_config',
                status: 'ok',
                path: '/usr/local/etc/xray/config.json',
            },
            { check: 'xray_unit', status: 'ok', unit: 'xray.service' },
        ],
    });
    assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
});

test('preflight exposes a validated artifact failure without remote diagnostics', async () => {
    const secret = 'preflight-artifact-failure-secret';
    const nodeSSH = {
        async exec() {
            return {
                code: 69,
                stdout: `${JSON.stringify({
                    check: 'os',
                    status: 'error',
                    code: 'UNSUPPORTED_OS',
                    id: 'alpine',
                    version: '3.20',
                    diagnostics: secret,
                    node: { ssh: { password: secret } },
                })}\n`,
                stderr: secret,
            };
        },
    };
    const transport = new L2tpNodeTransport({ nodeSSH });

    const result = await transport.runArtifactCommand({
        operationId: 'preflight-failed',
        command: 'preflight',
    });

    assert.deepEqual(result, {
        ok: false,
        checks: [{
            check: 'os',
            status: 'error',
            code: 'UNSUPPORTED_OS',
            id: 'alpine',
            version: '3.20',
        }],
        error: { code: 'UNSUPPORTED_OS' },
    });
    assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
});

test('preflight fails closed on empty, malformed, or unrecognized command output', async t => {
    const secret = 'unvalidated-preflight-output-secret';
    const responses = [
        { code: 0, stdout: '', stderr: secret },
        { code: 0, stdout: '{not-json}\n', stderr: secret },
        {
            code: 0,
            stdout: `${JSON.stringify({ check: 'ssh', status: 'ok', output: secret })}\n`,
            stderr: secret,
        },
        {
            code: 70,
            stdout: `${JSON.stringify({
                check: 'xray',
                status: 'error',
                code: secret,
            })}\n`,
            stderr: secret,
        },
    ];

    for (const [index, response] of responses.entries()) {
        await t.test(String(index), async () => {
            const transport = new L2tpNodeTransport({
                nodeSSH: { async exec() { return response; } },
            });

            const result = await transport.runArtifactCommand({
                operationId: `preflight-invalid-${index}`,
                command: 'preflight',
            });

            assert.deepEqual(result, {
                ok: false,
                checks: [],
                error: { code: 'PREFLIGHT_RESPONSE_INVALID' },
            });
            assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
        });
    }
});

test('rejects invalid operation ids before invoking the NodeSSH facade', async () => {
    const invalidOperationIds = [
        '',
        '../operation',
        'operation/child',
        String.raw`operation\\child`,
        'operation;id',
        `operation-${'a'.repeat(120)}`,
        null,
    ];

    for (const operationId of invalidOperationIds) {
        const nodeSSH = createNodeSSHFacade();
        const transport = new L2tpNodeTransport({ nodeSSH });

        for (const invoke of [
            () => transport.uploadRootFile({
                operationId,
                path: 'desired.json',
                content: '{}',
                owner: 'root',
                group: 'root',
                mode: 0o600,
            }),
            () => transport.runArtifactCommand({ operationId, command: 'verify' }),
        ]) {
            await assert.rejects(invoke, error => {
                assert.equal(error.name, 'L2tpNodeTransportError');
                assert.equal(error.code, 'INVALID_OPERATION_ID');
                assert.equal(error.message, 'Invalid L2TP operation id');
                assert.equal(Object.hasOwn(error, 'operationId'), false);
                return true;
            });
        }

        assert.deepEqual(nodeSSH.calls, []);
    }
});

test('rejects unknown artifact commands before invoking the NodeSSH facade', async () => {
    const unknownCommands = [
        '',
        'run_ui_shell',
        'verify; id',
        'PREflight',
        null,
    ];

    for (const command of unknownCommands) {
        const nodeSSH = createNodeSSHFacade();
        const transport = new L2tpNodeTransport({ nodeSSH });

        await assert.rejects(
            transport.runArtifactCommand({ operationId: 'operation-19', command }),
            error => {
                assert.equal(error.name, 'L2tpNodeTransportError');
                assert.equal(error.code, 'UNKNOWN_ARTIFACT_COMMAND');
                assert.equal(error.message, 'Unsupported L2TP artifact command');
                assert.equal(Object.hasOwn(error, 'command'), false);
                return true;
            },
        );
        assert.deepEqual(nodeSSH.calls, []);
    }
});

test('rejects non-root artifact paths before invoking the NodeSSH facade', async () => {
    const invalidPaths = [
        '',
        '.',
        '..',
        '../desired.json',
        'nested/desired.json',
        String.raw`nested\\desired.json`,
        '/desired.json',
        '.hidden.json',
        'desired json',
        'desired.json;id',
        null,
    ];

    for (const path of invalidPaths) {
        const nodeSSH = createNodeSSHFacade();
        const transport = new L2tpNodeTransport({ nodeSSH });

        await assert.rejects(
            transport.uploadRootFile({
                operationId: 'operation-20',
                path,
                content: '{}',
                owner: 'root',
                group: 'root',
                mode: 0o600,
            }),
            error => {
                assert.equal(error.name, 'L2tpNodeTransportError');
                assert.equal(error.code, 'INVALID_ARTIFACT_PATH');
                assert.equal(error.message, 'Invalid L2TP root artifact path');
                assert.equal(Object.hasOwn(error, 'path'), false);
                return true;
            },
        );
        assert.deepEqual(nodeSSH.calls, []);
    }
});

test('rejects artifact metadata that is not root-owned mode 0600 before the facade', async () => {
    const invalidMetadata = [
        { owner: 'celerity', group: 'root', mode: 0o600 },
        { owner: 'root', group: 'celerity', mode: 0o600 },
        { owner: 'root', group: 'root', mode: 0o644 },
        { owner: 'root', group: 'root', mode: '0600' },
    ];

    for (const metadata of invalidMetadata) {
        const nodeSSH = createNodeSSHFacade();
        const transport = new L2tpNodeTransport({ nodeSSH });

        await assert.rejects(
            transport.uploadRootFile({
                operationId: 'operation-21',
                type: 'desired',
                path: 'desired.json',
                content: '{}',
                ...metadata,
            }),
            error => {
                assert.equal(error.name, 'L2tpNodeTransportError');
                assert.equal(error.code, 'ROOT_FILE_METADATA_REQUIRED');
                assert.equal(error.message, 'L2TP operation artifacts must be root-owned mode 0600');
                return true;
            },
        );
        assert.deepEqual(nodeSSH.calls, []);
    }
});

test('sanitizes every NodeSSH upload failure without exposing content or remote output', async () => {
    const secret = 'upload-transport-secret';
    const failures = [
        {
            async exec() { throw new Error(`receiver failed: ${secret}`); },
        },
        {
            async exec() { return { code: 73, stdout: secret, stderr: '' }; },
        },
        {
            async exec() { return { code: 73, stdout: '', stderr: secret }; },
        },
    ];

    for (const nodeSSH of failures) {
        const transport = new L2tpNodeTransport({ nodeSSH });

        await assert.rejects(
            transport.uploadRootFile({
                operationId: 'operation-22',
                type: 'desired',
                path: 'desired.json',
                content: `{"psk":"${secret}"}`,
                owner: 'root',
                group: 'root',
                mode: 0o600,
            }),
            error => {
                assert.equal(error.name, 'L2tpNodeTransportError');
                assert.equal(error.code, 'REMOTE_UPLOAD_FAILED');
                assert.equal(error.message, 'Failed to upload an L2TP operation artifact');
                assert.equal(Object.hasOwn(error, 'cause'), false);
                assert.doesNotMatch(JSON.stringify(error), new RegExp(secret));
                return true;
            },
        );
    }
});

test('sanitizes rejected and nonzero artifact runner failures', async () => {
    const secret = 'runner-transport-secret';
    const facades = [
        {
            async exec() { throw new Error(`runner failed: ${secret}`); },
            async writeFile() {},
        },
        {
            async exec() { return { code: 70, stdout: secret, stderr: secret }; },
            async writeFile() {},
        },
    ];

    for (const nodeSSH of facades) {
        const transport = new L2tpNodeTransport({ nodeSSH });

        await assert.rejects(
            transport.runArtifactCommand({ operationId: 'operation-23', command: 'verify' }),
            error => {
                assert.equal(error.name, 'L2tpNodeTransportError');
                assert.equal(error.code, 'REMOTE_COMMAND_FAILED');
                assert.equal(error.message, 'Failed to run an L2TP artifact command');
                assert.equal(Object.hasOwn(error, 'cause'), false);
                assert.doesNotMatch(JSON.stringify(error), new RegExp(secret));
                return true;
            },
        );
    }
});

test('rejects non-string artifact content before invoking the NodeSSH facade', async () => {
    for (const content of [null, Buffer.from('{}'), { psk: 'secret' }]) {
        const nodeSSH = createNodeSSHFacade();
        const transport = new L2tpNodeTransport({ nodeSSH });

        await assert.rejects(
            transport.uploadRootFile({
                operationId: 'operation-24',
                type: 'desired',
                path: 'desired.json',
                content,
                owner: 'root',
                group: 'root',
                mode: 0o600,
            }),
            error => {
                assert.equal(error.name, 'L2tpNodeTransportError');
                assert.equal(error.code, 'INVALID_ARTIFACT_CONTENT');
                assert.equal(error.message, 'Invalid L2TP artifact content');
                return true;
            },
        );
        assert.deepEqual(nodeSSH.calls, []);
    }
});
