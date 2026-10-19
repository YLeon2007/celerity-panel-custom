'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const {
    existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync,
    statSync, symlinkSync, writeFileSync,
} = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
    ENSURE_CONFIG_DIRS_COMMAND: ENSURE_DIRS_COMMAND,
    TOPOLOGY_RUNNER_MODE,
    TOPOLOGY_RUNNER_PATH,
    TOPOLOGY_RUNNER_SHA256,
    TopologyRunnerBootstrapper,
} = require('../services/topologyRunnerBootstrapper');

const TEST_AUTHORIZATION = Object.freeze({
    target: 'test', hostIdentity: 'test.infograd.online', role: 'relay',
});

const RUNNER_PATH = '/usr/local/bin/celerity-topology-node-runner';
const UPLOAD_PATH = '/usr/local/bin/.celerity-topology-node-runner.upload';
const NEXT_PATH = '/usr/local/bin/.celerity-topology-node-runner.next';
const RUNNER_DIGEST = '5dac7c11d85776aa93622ed6a6036b841ba43fe9db5db4b0fe2744b7dce1a030';
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
const BRIDGE_UNIT_PATH = '/etc/systemd/system/xray-bridge.service';
const BRIDGE_UNIT_SOURCE = [
    '[Unit]',
    'Description=Xray Bridge (Cascade Tunnel)',
    'After=network.target nss-lookup.target',
    '',
    '[Service]',
    'User=nobody',
    'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE',
    'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE',
    'NoNewPrivileges=true',
    'Type=simple',
    'ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray-bridge/config.json',
    'Restart=on-failure',
    'RestartSec=5',
    'LimitNOFILE=1048576',
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    '',
    '',
].join('\n');
const BRIDGE_UNIT_DIGEST = createHash('sha256').update(BRIDGE_UNIT_SOURCE).digest('hex');
const INSPECT_UNIT_COMMAND = [
    '/usr/bin/systemctl show --property=FragmentPath --property=DropInPaths -- xray-bridge.service',
    `&& if /usr/bin/test -f ${BRIDGE_UNIT_PATH} && /usr/bin/test ! -L ${BRIDGE_UNIT_PATH}; then`,
    `/usr/bin/sha256sum -- ${BRIDGE_UNIT_PATH};`,
    `elif /usr/bin/test -e ${BRIDGE_UNIT_PATH} || /usr/bin/test -L ${BRIDGE_UNIT_PATH}; then`,
    "/usr/bin/printf '%s\\n' unsafe;",
    'else',
    "/usr/bin/printf '%s\\n' missing;",
    'fi',
].join(' ');
const INSTALL_UNIT_COMMAND = [
    `(/usr/bin/test ! -e ${BRIDGE_UNIT_PATH} && /usr/bin/test ! -L ${BRIDGE_UNIT_PATH}`,
    `&& set -C && umask 022 && /usr/bin/printf '%s' '${BRIDGE_UNIT_SOURCE}' > ${BRIDGE_UNIT_PATH})`,
    '&& /usr/bin/systemctl daemon-reload',
].join(' ');
const missingUnitReadback = { code: 0, stdout: 'FragmentPath=\nDropInPaths=\nmissing\n', stderr: '' };
const matchingUnitReadback = {
    code: 0,
    stdout: `FragmentPath=${BRIDGE_UNIT_PATH}\nDropInPaths=\n${BRIDGE_UNIT_DIGEST}  ${BRIDGE_UNIT_PATH}\n`,
    stderr: '',
};

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
            if (command === INSPECT_UNIT_COMMAND) return matchingUnitReadback;
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
    const bootstrapper = new TopologyRunnerBootstrapper({ nodeSSH, ...TEST_AUTHORIZATION });

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
        { method: 'exec', command: INSPECT_UNIT_COMMAND },
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
            if (command === INSPECT_UNIT_COMMAND) return matchingUnitReadback;
            if (command === ENSURE_DIRS_COMMAND) {
                return { code: 0, stdout: '', stderr: '' };
            }
            return installedReadback;
        },
        async writeFile(remotePath, content) {
            calls.push({ method: 'writeFile', remotePath, content });
        },
    };
    const bootstrapper = new TopologyRunnerBootstrapper({ nodeSSH, ...TEST_AUTHORIZATION });

    assert.deepEqual(await bootstrapper.ensureRunner(), {
        ok: true,
        changed: false,
        sha256: `sha256:${RUNNER_DIGEST}`,
        mode: '0750',
    });
    assert.deepEqual(calls, [
        { method: 'exec', command: INSPECT_COMMAND },
        { method: 'exec', command: INSPECT_UNIT_COMMAND },
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
                if (command === INSPECT_UNIT_COMMAND) return matchingUnitReadback;
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
        const bootstrapper = new TopologyRunnerBootstrapper({ nodeSSH, ...TEST_AUTHORIZATION });

        assert.equal((await bootstrapper.ensureRunner()).changed, true);
        assert.deepEqual(calls, [
            { method: 'exec', command: INSPECT_COMMAND },
            { method: 'exec', command: INSPECT_UNIT_COMMAND },
            { method: 'exec', command: ENSURE_DIRS_COMMAND },
            { method: 'writeFile', remotePath: UPLOAD_PATH, content: runnerSource() },
            { method: 'exec', command: INSTALL_COMMAND },
            { method: 'exec', command: INSPECT_COMMAND },
        ]);
    }
});

test('accepts only a resolved NodeSSH facade, exact options and zero method arguments', async () => {
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
        { nodeSSH, ...TEST_AUTHORIZATION, path: '/tmp/request-runner' },
        { nodeSSH, ...TEST_AUTHORIZATION, command: 'id' },
        { nodeSSH, ...TEST_AUTHORIZATION, argv: ['sh', '-c', 'id'] },
        { nodeSSH, ...TEST_AUTHORIZATION, env: { TOKEN: rawSecret } },
        { nodeSSH, ...TEST_AUTHORIZATION, runnerBody: rawSecret },
        { nodeSSH: { exec: nodeSSH.exec }, ...TEST_AUTHORIZATION },
        { nodeSSH: { writeFile: nodeSSH.writeFile }, ...TEST_AUTHORIZATION },
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

    const bootstrapper = new TopologyRunnerBootstrapper({ nodeSSH, ...TEST_AUTHORIZATION });
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
                if (command === INSPECT_UNIT_COMMAND) return matchingUnitReadback;
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
        const bootstrapper = new TopologyRunnerBootstrapper({ nodeSSH, ...TEST_AUTHORIZATION });

        await assert.rejects(bootstrapper.ensureRunner(), error => {
            assert.equal(error.name, 'TopologyRunnerBootstrapperError', failure.name);
            assert.equal(error.code, 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE', failure.name);
            assert.equal(error.message, 'Topology runner bootstrap is unavailable', failure.name);
            assert.equal(Object.hasOwn(error, 'cause'), false, failure.name);
            assert.doesNotMatch(JSON.stringify(error), new RegExp(remoteSecret), failure.name);
            return true;
        });
        assert.deepEqual(commands, [
            INSPECT_COMMAND, INSPECT_UNIT_COMMAND, ENSURE_DIRS_COMMAND,
            ...(failure.name === 'transfer' ? [] : [INSTALL_COMMAND]),
            ...(['transfer', 'install hash'].includes(failure.name) ? [] : [INSPECT_COMMAND]),
            cleanupCommand,
        ], failure.name);
        assert.equal(commands.every(command => [
            INSPECT_COMMAND,
            INSTALL_COMMAND,
            ENSURE_DIRS_COMMAND,
            INSPECT_UNIT_COMMAND,
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

test('authorizes only explicit exact TEST and production host pairs with a known role', () => {
    const calls = [];
    const nodeSSH = {
        async exec(command) { calls.push(command); },
        async writeFile(...args) { calls.push(args); },
    };
    for (const role of ['portal', 'relay', 'bridge']) {
        for (const [target, hostIdentity] of [
            ['test', 'test.infograd.online'],
            ['production', 'lm1.infograd.online'],
        ]) {
            assert.doesNotThrow(() => new TopologyRunnerBootstrapper({
                nodeSSH, target, hostIdentity, role,
            }));
        }
    }
    for (const authorization of [
        { target: 'test' },
        { target: 'production' },
        { ...TEST_AUTHORIZATION, hostIdentity: 'lm1.infograd.online' },
        { ...TEST_AUTHORIZATION, target: 'production' },
        { ...TEST_AUTHORIZATION, target: 'staging' },
        { ...TEST_AUTHORIZATION, hostIdentity: 'TEST.infograd.online' },
        { ...TEST_AUTHORIZATION, hostIdentity: 'test.infograd.online.' },
        { ...TEST_AUTHORIZATION, hostIdentity: 'https://test.infograd.online' },
        { ...TEST_AUTHORIZATION, hostIdentity: { toString: () => 'test.infograd.online' } },
        { ...TEST_AUTHORIZATION, role: undefined },
        { ...TEST_AUTHORIZATION, role: 'standalone' },
        { ...TEST_AUTHORIZATION, role: 'legacy' },
        { ...TEST_AUTHORIZATION, role: { toString: () => 'portal' } },
        { ...TEST_AUTHORIZATION, command: 'id' },
    ]) {
        assert.throws(() => new TopologyRunnerBootstrapper({ nodeSSH, ...authorization }), {
            code: 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE',
        });
    }
    assert.deepEqual(calls, []);
});

test('portal reuses the runner without inspecting, rewriting or reloading an unrelated bridge unit', async () => {
    const calls = [];
    const portalDirs = '/usr/bin/install -d -m 0755 -o root -g root /usr/local/etc/xray';
    const nodeSSH = {
        async exec(command) {
            calls.push({ method: 'exec', command });
            if (command === INSPECT_COMMAND) return installedReadback;
            return { code: 0, stdout: '', stderr: '' };
        },
        async writeFile(...args) { calls.push({ method: 'writeFile', args }); },
    };
    const bootstrapper = new TopologyRunnerBootstrapper({
        nodeSSH, target: 'production', hostIdentity: 'lm1.infograd.online', role: 'portal',
    });
    assert.equal((await bootstrapper.ensureRunner()).changed, false);
    assert.deepEqual(calls, [
        { method: 'exec', command: INSPECT_COMMAND },
        { method: 'exec', command: portalDirs },
    ]);
    assert.doesNotMatch(JSON.stringify(calls), /xray-bridge|systemctl/);
});

test('managed relay and bridge refuse a differing legacy unit before every remote write', async () => {
    for (const role of ['relay', 'bridge']) {
        const calls = [];
        const nodeSSH = {
            async exec(command) {
                calls.push({ method: 'exec', command });
                if (command === INSPECT_COMMAND) return installedReadback;
                if (command === INSPECT_UNIT_COMMAND) return {
                    ...matchingUnitReadback,
                    stdout: matchingUnitReadback.stdout.replace(BRIDGE_UNIT_DIGEST, '0'.repeat(64)),
                };
                return { code: 0, stdout: '', stderr: '' };
            },
            async writeFile(...args) { calls.push({ method: 'writeFile', args }); },
        };
        await assert.rejects(new TopologyRunnerBootstrapper({
            nodeSSH, ...TEST_AUTHORIZATION, role,
        }).ensureRunner(), { code: 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE' });
        assert.deepEqual(calls, [
            { method: 'exec', command: INSPECT_COMMAND },
            { method: 'exec', command: INSPECT_UNIT_COMMAND },
        ]);
    }
});

test('managed roles reuse the matching unit without rewriting it or reloading systemd', async () => {
    for (const role of ['relay', 'bridge']) {
        const calls = [];
        const nodeSSH = {
            async exec(command) {
                calls.push(command);
                if (command === INSPECT_COMMAND) return installedReadback;
                if (command === INSPECT_UNIT_COMMAND) return matchingUnitReadback;
                return { code: 0, stdout: '', stderr: '' };
            },
            async writeFile() { assert.fail('matching runner must not be uploaded'); },
        };
        const result = await new TopologyRunnerBootstrapper({
            nodeSSH, target: 'production', hostIdentity: 'lm1.infograd.online', role,
        }).ensureRunner();
        assert.equal(result.changed, false);
        assert.deepEqual(calls, [
            INSPECT_COMMAND,
            INSPECT_UNIT_COMMAND,
            '/usr/bin/install -d -m 0755 -o root -g root /usr/local/etc/xray /usr/local/etc/xray-bridge',
        ]);
    }
});

test('fresh managed nodes create the fixed unit without clobber and read it back before runner upload', async () => {
    for (const role of ['relay', 'bridge']) {
        for (const runnerPresent of [false, true]) {
            const calls = [];
            let runnerInspections = 0;
            let unitInspections = 0;
            const nodeSSH = {
                async exec(command) {
                    calls.push({ method: 'exec', command });
                    if (command === INSPECT_COMMAND) return runnerPresent || runnerInspections++ > 0
                        ? installedReadback : { code: 0, stdout: 'missing\n', stderr: '' };
                    if (command === INSPECT_UNIT_COMMAND) return unitInspections++ > 0
                        ? matchingUnitReadback : missingUnitReadback;
                    if ([ENSURE_DIRS_COMMAND, INSTALL_UNIT_COMMAND, INSTALL_COMMAND].includes(command)) {
                        return { code: 0, stdout: '', stderr: '' };
                    }
                    assert.fail(`unexpected command: ${command}`);
                },
                async writeFile(remotePath, content) {
                    calls.push({ method: 'writeFile', remotePath, content });
                },
            };
            const result = await new TopologyRunnerBootstrapper({
                nodeSSH, target: 'production', hostIdentity: 'lm1.infograd.online', role,
            }).ensureRunner();
            assert.equal(result.changed, true);
            assert.deepEqual(calls, [
                { method: 'exec', command: INSPECT_COMMAND },
                { method: 'exec', command: INSPECT_UNIT_COMMAND },
                { method: 'exec', command: ENSURE_DIRS_COMMAND },
                { method: 'exec', command: INSTALL_UNIT_COMMAND },
                { method: 'exec', command: INSPECT_UNIT_COMMAND },
                ...runnerPresent ? [] : [
                    { method: 'writeFile', remotePath: UPLOAD_PATH, content: runnerSource() },
                    { method: 'exec', command: INSTALL_COMMAND },
                    { method: 'exec', command: INSPECT_COMMAND },
                ],
            ]);
        }
    }
});

test('unit inspection accepts either systemd property order without relaxing exact matching', async () => {
    const calls = [];
    const nodeSSH = {
        async exec(command) {
            calls.push(command);
            if (command === INSPECT_COMMAND) return installedReadback;
            if (command === INSPECT_UNIT_COMMAND) return {
                ...matchingUnitReadback,
                stdout: matchingUnitReadback.stdout.replace(
                    `FragmentPath=${BRIDGE_UNIT_PATH}\nDropInPaths=\n`,
                    `DropInPaths=\nFragmentPath=${BRIDGE_UNIT_PATH}\n`,
                ),
            };
            assert.equal(command, ENSURE_DIRS_COMMAND);
            return { code: 0, stdout: '', stderr: '' };
        },
        async writeFile() { assert.fail('must reuse matching runner'); },
    };
    assert.equal((await new TopologyRunnerBootstrapper({
        nodeSSH, ...TEST_AUTHORIZATION,
    }).ensureRunner()).changed, false);
    assert.deepEqual(calls, [INSPECT_COMMAND, INSPECT_UNIT_COMMAND, ENSURE_DIRS_COMMAND]);
});

test('unsafe unit observations fail closed before directories, reload, upload or cleanup', async () => {
    const unsafe = [
        undefined,
        { ...matchingUnitReadback, code: 1 },
        { ...matchingUnitReadback, stderr: 'remote-secret-canary' },
        { ...matchingUnitReadback, stdout: null },
        { ...matchingUnitReadback, stdout: `${matchingUnitReadback.stdout}extra\n` },
        { ...matchingUnitReadback, stdout: matchingUnitReadback.stdout.replace('DropInPaths=', 'Unknown=') },
        { ...matchingUnitReadback, stdout: matchingUnitReadback.stdout.replace('DropInPaths=', 'DropInPaths=/etc/systemd/system/xray-bridge.service.d/legacy.conf') },
        { ...matchingUnitReadback, stdout: matchingUnitReadback.stdout.replace(`FragmentPath=${BRIDGE_UNIT_PATH}`, 'FragmentPath=/lib/systemd/system/xray-bridge.service') },
        { ...missingUnitReadback, stdout: `FragmentPath=${BRIDGE_UNIT_PATH}\nDropInPaths=\nmissing\n` },
        { ...missingUnitReadback, stdout: 'FragmentPath=\nDropInPaths=\nunsafe\n' },
        { ...matchingUnitReadback, stdout: matchingUnitReadback.stdout.replace(`FragmentPath=${BRIDGE_UNIT_PATH}`, 'FragmentPath=') },
    ];
    for (const observation of unsafe) {
        for (const role of ['relay', 'bridge']) {
            const calls = [];
            const nodeSSH = {
                async exec(command) {
                    calls.push(command);
                    if (command === INSPECT_COMMAND) return { code: 0, stdout: 'missing\n', stderr: '' };
                    assert.equal(command, INSPECT_UNIT_COMMAND);
                    return observation;
                },
                async writeFile() { assert.fail('unsafe unit must not start upload'); },
            };
            await assert.rejects(new TopologyRunnerBootstrapper({
                nodeSSH, ...TEST_AUTHORIZATION, role,
            }).ensureRunner(), error => {
                assert.equal(error.code, 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE');
                assert.doesNotMatch(JSON.stringify(error), /remote-secret-canary|legacy/);
                return true;
            });
            assert.deepEqual(calls, [INSPECT_COMMAND, INSPECT_UNIT_COMMAND]);
        }
    }
});

test('unit creation or readback failures never start runner transfer or attempt unit cleanup', async () => {
    for (const failure of ['dirs', 'install-rejected', 'install-throws', 'readback-missing', 'readback-differs', 'readback-throws']) {
        const calls = [];
        let inspections = 0;
        const nodeSSH = {
            async exec(command) {
                calls.push(command);
                if (command === INSPECT_COMMAND) return { code: 0, stdout: 'missing\n', stderr: '' };
                if (command === INSPECT_UNIT_COMMAND) {
                    if (inspections++ === 0) return missingUnitReadback;
                    if (failure === 'readback-throws') throw new Error('remote-secret-canary');
                    return failure === 'readback-missing' ? missingUnitReadback : {
                        ...matchingUnitReadback,
                        stdout: matchingUnitReadback.stdout.replace(BRIDGE_UNIT_DIGEST, '0'.repeat(64)),
                    };
                }
                if (command === ENSURE_DIRS_COMMAND) return {
                    code: failure === 'dirs' ? 1 : 0, stdout: '', stderr: '',
                };
                assert.equal(command, INSTALL_UNIT_COMMAND);
                if (failure === 'install-throws') throw new Error('remote-secret-canary');
                return { code: failure === 'install-rejected' ? 1 : 0, stdout: '', stderr: '' };
            },
            async writeFile() { assert.fail('unverified unit must not start upload'); },
        };
        await assert.rejects(new TopologyRunnerBootstrapper({
            nodeSSH, ...TEST_AUTHORIZATION,
        }).ensureRunner(), { code: 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE' });
        assert.deepEqual(calls, [
            INSPECT_COMMAND, INSPECT_UNIT_COMMAND, ENSURE_DIRS_COMMAND,
            ...failure === 'dirs' ? [] : [INSTALL_UNIT_COMMAND],
            ...failure.startsWith('readback-') ? [INSPECT_UNIT_COMMAND] : [],
        ], failure);
    }
});

test('portal installs a missing runner using only its main config directory and fixed runner paths', async () => {
    const calls = [];
    let inspections = 0;
    const portalDirs = '/usr/bin/install -d -m 0755 -o root -g root /usr/local/etc/xray';
    const nodeSSH = {
        async exec(command) {
            calls.push({ method: 'exec', command });
            if (command === INSPECT_COMMAND) return inspections++ > 0
                ? installedReadback : { code: 0, stdout: 'missing\n', stderr: '' };
            assert.ok([portalDirs, INSTALL_COMMAND].includes(command));
            return { code: 0, stdout: '', stderr: '' };
        },
        async writeFile(remotePath, content) {
            calls.push({ method: 'writeFile', remotePath, content });
        },
    };
    assert.equal((await new TopologyRunnerBootstrapper({
        nodeSSH, ...TEST_AUTHORIZATION, role: 'portal',
    }).ensureRunner()).changed, true);
    assert.deepEqual(calls, [
        { method: 'exec', command: INSPECT_COMMAND },
        { method: 'exec', command: portalDirs },
        { method: 'writeFile', remotePath: UPLOAD_PATH, content: runnerSource() },
        { method: 'exec', command: INSTALL_COMMAND },
        { method: 'exec', command: INSPECT_COMMAND },
    ]);
});

test('fixed unit shell creates exact bytes and refuses files, symlinks and a post-inspection race locally', () => {
    // Execute the same command proven above at the mocked remote boundary,
    // remapping only fixed paths and systemctl into an isolated scratch dir.
    const root = mkdtempSync(path.join(os.tmpdir(), 'topology-bootstrap-unit-'));
    const unitPath = path.join(root, 'xray-bridge.service');
    const tracePath = path.join(root, 'systemctl.calls');
    const systemctlPath = path.join(root, 'systemctl');
    const testPath = path.join(root, 'test-race');
    const sentinel = 'unrelated legacy service\n';
    writeFileSync(systemctlPath, [
        '#!/bin/sh',
        'if [ "$1" = show ]; then',
        "  printf 'FragmentPath=%s\\nDropInPaths=\\n' \"$FRAGMENT\"",
        'else',
        '  printf \'%s\\n\' "$*" >> "$TRACE"',
        'fi',
        '',
    ].join('\n'), { mode: 0o700 });
    const remap = command => command.replaceAll(BRIDGE_UNIT_PATH, unitPath)
        .replaceAll('/usr/bin/systemctl', systemctlPath);
    const run = (command, fragment = '') => spawnSync('/bin/sh', ['-c', command], {
        encoding: 'utf8', env: { ...process.env, FRAGMENT: fragment, TRACE: tracePath },
    });
    try {
        assert.equal(run(remap(INSPECT_UNIT_COMMAND)).stdout, missingUnitReadback.stdout);
        const installed = run(remap(INSTALL_UNIT_COMMAND));
        assert.equal(installed.status, 0, installed.stderr);
        assert.equal(readFileSync(unitPath, 'utf8'), BRIDGE_UNIT_SOURCE);
        assert.equal(statSync(unitPath).mode & 0o777, 0o644);
        assert.equal(readFileSync(tracePath, 'utf8'), 'daemon-reload\n');
        const inspected = run(remap(INSPECT_UNIT_COMMAND), unitPath);
        assert.equal(inspected.status, 0, inspected.stderr);
        assert.equal(inspected.stdout.replaceAll(unitPath, BRIDGE_UNIT_PATH), matchingUnitReadback.stdout);

        for (const state of ['file', 'directory', 'symlink', 'dangling-symlink', 'race']) {
            rmSync(unitPath, { recursive: true, force: true });
            rmSync(tracePath, { force: true });
            const targetPath = path.join(root, 'legacy-target');
            writeFileSync(targetPath, sentinel);
            let command = remap(INSTALL_UNIT_COMMAND);
            if (state === 'file') writeFileSync(unitPath, sentinel);
            if (state === 'directory') mkdirSync(unitPath);
            if (state === 'symlink') symlinkSync(targetPath, unitPath);
            if (state === 'dangling-symlink') symlinkSync(path.join(root, 'absent'), unitPath);
            if (state === 'race') {
                writeFileSync(testPath, [
                    '#!/bin/sh',
                    'if [ "$1" = "!" ] && [ "$2" = "-L" ]; then',
                    `  printf '%s\\n' 'unrelated legacy service' > "$3"`,
                    'fi',
                    'exec /usr/bin/test "$@"',
                    '',
                ].join('\n'), { mode: 0o700 });
                command = command.replaceAll('/usr/bin/test', testPath);
            }
            const refused = run(command);
            assert.notEqual(refused.status, 0, state);
            assert.equal(existsSync(tracePath), false, `${state}: no daemon-reload`);
            assert.equal(readFileSync(targetPath, 'utf8'), sentinel, state);
            if (state === 'file' || state === 'race') {
                assert.equal(readFileSync(unitPath, 'utf8'), sentinel, state);
            } else if (state.includes('symlink')) {
                assert.equal(lstatSync(unitPath).isSymbolicLink(), true, state);
            } else {
                assert.equal(lstatSync(unitPath).isDirectory(), true, state);
            }
        }
    } finally {
        rmSync(root, { recursive: true, force: true });
    }
});

test('all fixed remote commands are valid non-interactive shell programs', () => {
    for (const command of [INSPECT_COMMAND, INSPECT_UNIT_COMMAND, INSTALL_UNIT_COMMAND, INSTALL_COMMAND, ENSURE_DIRS_COMMAND]) {
        const checked = spawnSync('/bin/sh', ['-n', '-c', command], { encoding: 'utf8' });
        assert.equal(checked.status, 0, checked.stderr);
        assert.equal(checked.stdout, '');
    }
});
