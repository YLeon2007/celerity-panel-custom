'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
    INSPECT_COMMAND,
    L2tpArtifactBootstrapper,
    L2tpArtifactBootstrapperError,
} = require('../services/l2tpArtifactBootstrapper');

const RUNNER_DIGEST = createHash('sha256')
    .update(readFileSync(path.join(
        __dirname,
        '..',
        'node-artifacts',
        'l2tp',
        'runner.sh',
    )))
    .digest('hex');

function facade(execImpl) {
    const calls = [];
    return {
        calls,
        async exec(command, options) {
            calls.push({ command, hasStdin: options?.stdin !== undefined });
            return execImpl(command, options);
        },
    };
}

test('skips upload when the installed runner digest matches', async () => {
    const nodeSSH = facade(async () => ({
        code: 0,
        stdout: `${RUNNER_DIGEST}  /usr/local/lib/celerity/relay-l2tp/runner.sh\n`,
        stderr: '',
    }));
    const bootstrapper = new L2tpArtifactBootstrapper({ nodeSSH, createHash });

    const result = await bootstrapper.ensureArtifact();

    assert.deepEqual(result, { ok: true, changed: false });
    assert.equal(nodeSSH.calls.length, 1);
    assert.equal(nodeSSH.calls[0].command, INSPECT_COMMAND);
});

test('uploads the pinned bundle and runs install.sh when missing', async () => {
    const nodeSSH = facade(async command => {
        if (command === INSPECT_COMMAND) {
            return { code: 0, stdout: 'missing\n', stderr: '' };
        }
        if (command.startsWith('/usr/bin/bash -- ')) {
            return { code: 0, stdout: '{"status":"ok"}\n', stderr: '' };
        }
        return { code: 0, stdout: '', stderr: '' };
    });
    const bootstrapper = new L2tpArtifactBootstrapper({ nodeSSH, createHash });

    const result = await bootstrapper.ensureArtifact();

    assert.deepEqual(result, { ok: true, changed: true });
    const uploads = nodeSSH.calls.filter(call => call.hasStdin);
    assert.equal(uploads.length >= 18, true, 'bundle payloads uploaded');
    assert.equal(
        nodeSSH.calls.some(call => call.command.startsWith('/usr/bin/bash -- ')),
        true,
        'install.sh executed',
    );
    assert.equal(
        nodeSSH.calls[nodeSSH.calls.length - 1].command.startsWith('/usr/bin/rm -rf'),
        true,
        'staging cleaned up',
    );
});

test('fails closed when install.sh rejects the bundle', async () => {
    const nodeSSH = facade(async command => {
        if (command === INSPECT_COMMAND) {
            return { code: 0, stdout: 'missing\n', stderr: '' };
        }
        if (command.startsWith('/usr/bin/bash -- ')) {
            return { code: 65, stdout: '', stderr: '{"status":"error","code":"INVALID_PACKAGE"}\n' };
        }
        return { code: 0, stdout: '', stderr: '' };
    });
    const bootstrapper = new L2tpArtifactBootstrapper({ nodeSSH, createHash });

    await assert.rejects(
        () => bootstrapper.ensureArtifact(),
        error => error instanceof L2tpArtifactBootstrapperError,
    );
    assert.equal(
        nodeSSH.calls[nodeSSH.calls.length - 1].command.startsWith('/usr/bin/rm -rf'),
        true,
        'staging cleaned up even on failure',
    );
});
