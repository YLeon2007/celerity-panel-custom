'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
    ENSURE_CONFIG_DIRS_COMMAND: ENSURE_DIRS_COMMAND,
    TOPOLOGY_RUNNER_MODE,
    TOPOLOGY_RUNNER_PATH,
    TOPOLOGY_RUNNER_SHA256,
    TopologyRunnerBootstrapper,
} = require('../services/topologyRunnerBootstrapper');

const RUNNER_PATH = '/usr/local/bin/celerity-topology-node-runner';
const UPLOAD_PATH = '/usr/local/bin/.celerity-topology-node-runner.upload';
const NEXT_PATH = '/usr/local/bin/.celerity-topology-node-runner.next';
const RUNNER_DIGEST = '6cb69f9fcc712f032c1a76f53dcc91e8ac6152ce87ca14bdde4d4742e2391099';
const INSPECT_COMMAND = [
    `if /usr/bin/test -f ${RUNNER_PATH} && /usr/bin/test ! -L ${RUNNER_PATH}; then`,
    `/usr/bin/sha256sum -- ${RUNNER_PATH}`,
    `&& /usr/bin/stat -c '%a' -- ${RUNNER_PATH};`,
    'else',
    "/usr/bin/printf '%s\\n' missing;",
    'fi',
].join(' ');
const INSTALL_COMMAND = [
    `/usr/bin/printf '%s  %s\\n' '${RUNNER_DIGEST}' '${UPLOAD_PATH}'`,
    '| /usr/bin/sha256sum --check --status -',
    `&& /usr/bin/install -m 0750 -- ${UPLOAD_PATH} ${NEXT_PATH}`,
    `&& /usr/bin/mv -fT -- ${NEXT_PATH} ${RUNNER_PATH}`,
    `&& /usr/bin/rm -f -- ${UPLOAD_PATH}`,
].join(' ');
const installedReadback = {
    code: 0,
    stdout: `${RUNNER_DIGEST}  ${RUNNER_PATH}\n750\n`,
    stderr: '',
};
function runnerSource() {
    return readFileSync(path.join(
        __dirname,
        '..',
        'node-artifacts',
        'topology',
        'runner.sh',
    ));
}

test('ensureRunner atomically installs the pinned topology runner with fixed NodeSSH operations', async () => {
    const calls = [];
    const nodeSSH = {
        async exec(command) {
            calls.push({ method: 'exec', command });
            if (command === INSTALL_COMMAND || command === ENSURE_DIRS_COMMAND) {
                return { code: 0, stdout: '', stderr: '' };
            }
            return calls.filter(call => call.method === 'exec' && call.command === INSPECT_COMMAND).length === 1
                ? { code: 0, stdout: 'missing\n', stderr: '' }
                : installedReadback;
        },
        async writeFile(remotePath, content) {
            calls.push({ method: 'writeFile', remotePath, content });
        },
    };
    const bootstrapper = new TopologyRunnerBootstrapper({ nodeSSH, target: 'test' });

    const result = await bootstrapper.ensureRunner();

    assert.deepEqual(result, {
        ok: true,
        changed: true,
        sha256: `sha256:${RUNNER_DIGEST}`,
        mode: '0750',
    });
    assert.equal(Object.isFrozen(result), true);
    assert.deepEqual(calls, [
        { method: 'exec', command: INSPECT_COMMAND },
        { method: 'exec', command: ENSURE_DIRS_COMMAND },
        { method: 'writeFile', remotePath: UPLOAD_PATH, content: runnerSource() },
        { method: 'exec', command: INSTALL_COMMAND },
        { method: 'exec', command: INSPECT_COMMAND },
    ]);
    assert.deepEqual(
        Object.getOwnPropertyNames(Object.getPrototypeOf(bootstrapper)),
        ['constructor', 'ensureRunner'],
    );
    assert.equal(bootstrapper.exec, undefined);
    assert.equal(bootstrapper.writeFile, undefined);
    assert.deepEqual(Object.keys(bootstrapper), []);
});

test('ensureRunner is idempotent when the pinned hash and mode are already installed', async () => {
    const calls = [];
    const nodeSecret = 'stored-node-private-key-secret';
    const nodeSSH = {
        node: { ssh: { privateKey: nodeSecret } },
        async exec(command) {
            calls.push({ method: 'exec', command });
            if (command === ENSURE_DIRS_COMMAND) {
                return { code: 0, stdout: '', stderr: '' };
            }
            return installedReadback;
        },
        async writeFile(remotePath, content) {
            calls.push({ method: 'writeFile', remotePath, content });
        },
    };
    const bootstrapper = new TopologyRunnerBootstrapper({ nodeSSH, target: 'test' });

    assert.deepEqual(await bootstrapper.ensureRunner(), {
        ok: true,
        changed: false,
        sha256: `sha256:${RUNNER_DIGEST}`,
        mode: '0750',
    });
    assert.deepEqual(calls, [
        { method: 'exec', command: INSPECT_COMMAND },
        { method: 'exec', command: ENSURE_DIRS_COMMAND },
    ]);
    assert.doesNotMatch(JSON.stringify({ bootstrapper }), new RegExp(nodeSecret));
});

test('ensureRunner upgrades an outdated hash or mode through the same fixed atomic path', async () => {
    const outdatedStates = [
        `${'0'.repeat(64)}  ${RUNNER_PATH}\n750\n`,
        `${RUNNER_DIGEST}  ${RUNNER_PATH}\n755\n`,
    ];

    for (const outdated of outdatedStates) {
        const calls = [];
        let inspections = 0;
        const nodeSSH = {
            async exec(command) {
                calls.push({ method: 'exec', command });
                if (command === INSTALL_COMMAND || command === ENSURE_DIRS_COMMAND) {
                    return { code: 0, stdout: '', stderr: '' };
                }
                inspections += 1;
                return inspections === 1
                    ? { code: 0, stdout: outdated, stderr: '' }
                    : installedReadback;
            },
            async writeFile(remotePath, content) {
                calls.push({ method: 'writeFile', remotePath, content });
            },
        };
        const bootstrapper = new TopologyRunnerBootstrapper({ nodeSSH, target: 'test' });

        assert.equal((await bootstrapper.ensureRunner()).changed, true);
        assert.deepEqual(calls, [
            { method: 'exec', command: INSPECT_COMMAND },
            { method: 'exec', command: ENSURE_DIRS_COMMAND },
            { method: 'writeFile', remotePath: UPLOAD_PATH, content: runnerSource() },
            { method: 'exec', command: INSTALL_COMMAND },
            { method: 'exec', command: INSPECT_COMMAND },
        ]);
    }
});

test('accepts only a resolved NodeSSH facade and the fixed test target', async () => {
    const calls = [];
    const nodeSSH = {
        async exec(...args) {
            calls.push({ method: 'exec', args });
            return installedReadback;
        },
        async writeFile(...args) {
            calls.push({ method: 'writeFile', args });
        },
    };
    const rawSecret = 'request-runner-secret-canary';
    const invalidOptions = [
        undefined,
        {},
        { nodeSSH, target: 'production' },
        { nodeSSH, target: 'staging' },
        { nodeSSH, target: { toString: () => 'test' } },
        { nodeSSH, target: 'test', path: '/tmp/request-runner' },
        { nodeSSH, target: 'test', command: 'id' },
        { nodeSSH, target: 'test', argv: ['sh', '-c', 'id'] },
        { nodeSSH, target: 'test', env: { TOKEN: rawSecret } },
        { nodeSSH, target: 'test', runnerBody: rawSecret },
        { nodeSSH: { exec: nodeSSH.exec }, target: 'test' },
        { nodeSSH: { writeFile: nodeSSH.writeFile }, target: 'test' },
    ];

    for (const options of invalidOptions) {
        assert.throws(() => new TopologyRunnerBootstrapper(options), error => {
            assert.equal(error.name, 'TopologyRunnerBootstrapperError');
            assert.equal(error.code, 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE');
            assert.equal(error.message, 'Topology runner bootstrap is unavailable');
            assert.equal(Object.hasOwn(error, 'cause'), false);
            assert.doesNotMatch(
                JSON.stringify(error),
                /request-runner-secret-canary|\/tmp|\bid\b|production|staging/,
            );
            return true;
        });
    }
    assert.deepEqual(calls, []);

    const bootstrapper = new TopologyRunnerBootstrapper({ nodeSSH, target: 'test' });
    await assert.rejects(
        bootstrapper.ensureRunner({ path: '/tmp/request-runner', runnerBody: rawSecret }),
        error => {
            assert.equal(error.code, 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE');
            assert.doesNotMatch(JSON.stringify(error), /request-runner-secret-canary|\/tmp/);
            return true;
        },
    );
    assert.deepEqual(calls, []);
});

test('rejects transfer, install, hash, and mode readback failures with one safe error', async () => {
    const remoteSecret = 'remote-bootstrap-secret-canary';
    const cleanupCommand = `/usr/bin/rm -f -- ${UPLOAD_PATH} ${NEXT_PATH}`;
    const failures = [
        {
            name: 'transfer',
            async writeFile() {
                throw new Error(remoteSecret);
            },
            readback: installedReadback,
        },
        {
            name: 'install hash',
            async writeFile() {},
            install: { code: 1, stdout: '', stderr: remoteSecret },
            readback: installedReadback,
        },
        {
            name: 'installed hash',
            async writeFile() {},
            install: { code: 0, stdout: '', stderr: '' },
            readback: {
                code: 0,
                stdout: `${'f'.repeat(64)}  ${RUNNER_PATH}\n750\n`,
                stderr: '',
            },
        },
        {
            name: 'installed mode',
            async writeFile() {},
            install: { code: 0, stdout: '', stderr: '' },
            readback: {
                code: 0,
                stdout: `${RUNNER_DIGEST}  ${RUNNER_PATH}\n755\n`,
                stderr: '',
            },
        },
        {
            name: 'malformed readback',
            async writeFile() {},
            install: { code: 0, stdout: '', stderr: '' },
            readback: { code: 0, stdout: `${remoteSecret}\n`, stderr: '' },
        },
    ];

    for (const failure of failures) {
        const commands = [];
        let inspections = 0;
        const nodeSSH = {
            async exec(command) {
                commands.push(command);
                if (command === cleanupCommand || command === ENSURE_DIRS_COMMAND) {
                    return { code: 0, stdout: '', stderr: '' };
                }
                if (command === INSTALL_COMMAND) return failure.install;
                inspections += 1;
                return inspections === 1
                    ? { code: 0, stdout: 'missing\n', stderr: '' }
                    : failure.readback;
            },
            writeFile: failure.writeFile,
        };
        const bootstrapper = new TopologyRunnerBootstrapper({ nodeSSH, target: 'test' });

        await assert.rejects(bootstrapper.ensureRunner(), error => {
            assert.equal(error.name, 'TopologyRunnerBootstrapperError', failure.name);
            assert.equal(error.code, 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE', failure.name);
            assert.equal(error.message, 'Topology runner bootstrap is unavailable', failure.name);
            assert.equal(Object.hasOwn(error, 'cause'), false, failure.name);
            assert.doesNotMatch(JSON.stringify(error), new RegExp(remoteSecret), failure.name);
            return true;
        });
        assert.equal(commands.at(-1), cleanupCommand, failure.name);
        assert.equal(commands.every(command => [
            INSPECT_COMMAND,
            INSTALL_COMMAND,
            ENSURE_DIRS_COMMAND,
            cleanupCommand,
        ].includes(command)), true, failure.name);
    }
});

test('pins the exported SHA-256 and mode to the exact checked-in runner source', () => {
    const sourceDigest = createHash('sha256').update(runnerSource()).digest('hex');

    assert.equal(TOPOLOGY_RUNNER_PATH, RUNNER_PATH);
    assert.equal(TOPOLOGY_RUNNER_MODE, '0750');
    assert.equal(TOPOLOGY_RUNNER_SHA256, `sha256:${sourceDigest}`);
    assert.equal(sourceDigest, RUNNER_DIGEST);
});

test('all fixed remote commands are valid non-interactive shell programs', () => {
    for (const command of [INSPECT_COMMAND, INSTALL_COMMAND, ENSURE_DIRS_COMMAND]) {
        const checked = spawnSync('/bin/sh', ['-n', '-c', command], { encoding: 'utf8' });
        assert.equal(checked.status, 0, checked.stderr);
        assert.equal(checked.stdout, '');
    }
});
