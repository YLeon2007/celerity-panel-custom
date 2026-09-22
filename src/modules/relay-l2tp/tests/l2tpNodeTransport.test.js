'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { L2tpNodeTransport } = require('../services/l2tpNodeTransport');

function createNodeSSHFacade() {
    const calls = [];

    return {
        calls,
        async exec(command) {
            calls.push({ method: 'exec', command });
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

test('uploadRootFile writes a root-only file below the fixed operation root', async () => {
    const nodeSSH = createNodeSSHFacade();
    const transport = new L2tpNodeTransport({ nodeSSH });
    const content = '{"psk":"transport-secret"}\n';

    const result = await transport.uploadRootFile({
        operationId: 'operation-17',
        path: 'desired.json',
        content,
        owner: 'root',
        group: 'root',
        mode: 0o600,
    });

    assert.deepEqual(nodeSSH.calls, [
        {
            method: 'exec',
            command: 'install -d -o root -g root -m 0700 -- /var/lib/celerity/l2tp/operations/operation-17/',
        },
        {
            method: 'writeFile',
            path: '/var/lib/celerity/l2tp/operations/operation-17/desired.json',
            content,
        },
        {
            method: 'exec',
            command: 'chown root:root -- /var/lib/celerity/l2tp/operations/operation-17/desired.json && chmod 0600 -- /var/lib/celerity/l2tp/operations/operation-17/desired.json',
        },
    ]);
    assert.deepEqual(result, {
        ok: true,
        path: '/var/lib/celerity/l2tp/operations/operation-17/desired.json',
    });
});

test('runArtifactCommand maps every typed command to the fixed artifact runner', async () => {
    const nodeSSH = createNodeSSHFacade();
    const transport = new L2tpNodeTransport({ nodeSSH });
    const commands = [
        'preflight',
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
            { ok: true, operationId: 'operation-18', command },
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
            async exec() { throw new Error(`mkdir failed: ${secret}`); },
            async writeFile() { throw new Error('must not write'); },
        },
        {
            execCalls: 0,
            async exec() {
                this.execCalls += 1;
                return { code: 0, stdout: '', stderr: '' };
            },
            async writeFile() { throw new Error(`sftp failed: ${secret}`); },
        },
        {
            execCalls: 0,
            async exec() {
                this.execCalls += 1;
                if (this.execCalls === 2) {
                    return { code: 73, stdout: secret, stderr: secret };
                }
                return { code: 0, stdout: '', stderr: '' };
            },
            async writeFile() {},
        },
    ];

    for (const nodeSSH of failures) {
        const transport = new L2tpNodeTransport({ nodeSSH });

        await assert.rejects(
            transport.uploadRootFile({
                operationId: 'operation-22',
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
