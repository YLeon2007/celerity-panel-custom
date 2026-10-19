'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync, readdirSync } = require('node:fs');
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

const ARTIFACT_DIR = path.join(__dirname, '..', 'node-artifacts', 'l2tp');
const BUNDLE_INSPECTION = readdirSync(ARTIFACT_DIR)
    .filter(name => (name.endsWith('.sh') || name.endsWith('.py')) && name !== 'install.sh')
    .sort()
    .map(name => `${createHash('sha256').update(readFileSync(path.join(ARTIFACT_DIR, name))).digest('hex')}  /usr/local/lib/celerity/relay-l2tp/${name}`)
    .join('\n');

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

test('install.sh pins every shipped L2TP payload to its actual digest', () => {
    const directory = path.join(__dirname, '..', 'node-artifacts', 'l2tp');
    const installer = readFileSync(path.join(directory, 'install.sh'), 'utf8');
    const pins = Object.fromEntries([...installer.matchAll(
        /\[([^\]]+)\]='([0-9a-f]{64})'/g,
    )].map(match => [match[1], match[2]]));
    const payloads = Object.keys(pins).sort();
    const actual = Object.fromEntries(payloads.map(name => [
        name,
        createHash('sha256').update(readFileSync(path.join(directory, name))).digest('hex'),
    ]));
    assert.deepEqual(pins, actual);
    assert.equal(payloads.length, 18);
});

test('skips upload when the installed runner digest matches', async () => {
    const nodeSSH = facade(async () => ({
        code: 0,
        stdout: BUNDLE_INSPECTION,
        stderr: '',
    }));
    const bootstrapper = new L2tpArtifactBootstrapper({ nodeSSH, createHash });

    const result = await bootstrapper.ensureArtifact();

    assert.deepEqual(result, { ok: true, changed: false });
    assert.equal(nodeSSH.calls.length, 1);
    assert.equal(nodeSSH.calls[0].command, INSPECT_COMMAND);
});

test('mismatched installed helper forces a full bootstrap despite matching runner', async () => {
    const mismatched = BUNDLE_INSPECTION.replace(
        /^(?:[0-9a-f]{64})  \/usr\/local\/lib\/celerity\/relay-l2tp\/receive-artifact\.py$/m,
        `${'0'.repeat(64)}  /usr/local/lib/celerity/relay-l2tp/receive-artifact.py`,
    );
    const nodeSSH = facade(async command => {
        if (command === INSPECT_COMMAND) return { code: 0, stdout: mismatched, stderr: '' };
        if (command.startsWith('/usr/bin/bash -- ')) {
            return { code: 0, stdout: '{"status":"ok"}\n', stderr: '' };
        }
        return { code: 0, stdout: '', stderr: '' };
    });
    const bootstrapper = new L2tpArtifactBootstrapper({ nodeSSH, createHash });

    const result = await bootstrapper.ensureArtifact();

    assert.deepEqual(result, { ok: true, changed: true });
    assert.equal(nodeSSH.calls.some(call => call.hasStdin), true);
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

test('uncertain install.sh SSH outcome retains staging and never issues cleanup', async () => {
    const nodeSSH = facade(async command => {
        if (command === INSPECT_COMMAND) return { code: 0, stdout: 'missing\n', stderr: '' };
        if (command.startsWith('/usr/bin/bash -- ')) throw new Error('ssh timeout with private details');
        return { code: 0, stdout: '', stderr: '' };
    });
    const bootstrapper = new L2tpArtifactBootstrapper({ nodeSSH, createHash });
    await assert.rejects(bootstrapper.ensureArtifact(), error =>
        error instanceof L2tpArtifactBootstrapperError
        && error.remoteOutcomeUncertain === true
        && !JSON.stringify(error).includes('private details'));
    assert.equal(nodeSSH.calls.at(-1).command.startsWith('/usr/bin/bash -- '), true);
    assert.equal(nodeSSH.calls.some(c => c.command === '/usr/bin/rm -rf -- /var/lib/celerity/l2tp-bootstrap'), false);
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
