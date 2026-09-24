'use strict';

const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const path = require('node:path');

const TOPOLOGY_RUNNER_PATH = '/usr/local/bin/celerity-topology-node-runner';
const TOPOLOGY_RUNNER_UPLOAD_PATH = '/usr/local/bin/.celerity-topology-node-runner.upload';
const TOPOLOGY_RUNNER_NEXT_PATH = '/usr/local/bin/.celerity-topology-node-runner.next';
const TOPOLOGY_RUNNER_MODE = '0750';
const TOPOLOGY_RUNNER_SOURCE = readFileSync(path.join(
    __dirname,
    '..',
    'node-artifacts',
    'topology',
    'runner.sh',
));
const TOPOLOGY_RUNNER_DIGEST = createHash('sha256')
    .update(TOPOLOGY_RUNNER_SOURCE)
    .digest('hex');
const TOPOLOGY_RUNNER_SHA256 = `sha256:${TOPOLOGY_RUNNER_DIGEST}`;
const INSPECT_COMMAND = Object.freeze([
    `if /usr/bin/test -f ${TOPOLOGY_RUNNER_PATH} && /usr/bin/test ! -L ${TOPOLOGY_RUNNER_PATH}; then`,
    `/usr/bin/sha256sum -- ${TOPOLOGY_RUNNER_PATH}`,
    `&& /usr/bin/stat -c '%a' -- ${TOPOLOGY_RUNNER_PATH};`,
    'else',
    "/usr/bin/printf '%s\\n' missing;",
    'fi',
].join(' '));
const INSTALL_COMMAND = Object.freeze([
    `/usr/bin/printf '%s  %s\\n' '${TOPOLOGY_RUNNER_DIGEST}' '${TOPOLOGY_RUNNER_UPLOAD_PATH}'`,
    '| /usr/bin/sha256sum --check --status -',
    `&& /usr/bin/install -m ${TOPOLOGY_RUNNER_MODE} -- ${TOPOLOGY_RUNNER_UPLOAD_PATH} ${TOPOLOGY_RUNNER_NEXT_PATH}`,
    `&& /usr/bin/mv -fT -- ${TOPOLOGY_RUNNER_NEXT_PATH} ${TOPOLOGY_RUNNER_PATH}`,
    `&& /usr/bin/rm -f -- ${TOPOLOGY_RUNNER_UPLOAD_PATH}`,
].join(' '));
const CLEANUP_COMMAND = Object.freeze(
    `/usr/bin/rm -f -- ${TOPOLOGY_RUNNER_UPLOAD_PATH} ${TOPOLOGY_RUNNER_NEXT_PATH}`,
);
// The node runner's strict prepare requires the target profile's config
// parent (e.g. /usr/local/etc/xray-bridge) to exist as a real directory,
// and commit/verify drive the xray-bridge.service unit. Fresh relay nodes
// only have the main xray profile, so ensure the dirs and the unit upfront.
const ENSURE_CONFIG_DIRS_COMMAND = Object.freeze([
    '/usr/bin/install -d -m 0755 -o root -g root /usr/local/etc/xray /usr/local/etc/xray-bridge',
    '&& if /usr/bin/test ! -f /etc/systemd/system/xray-bridge.service; then',
    `/usr/bin/printf '%b\\n' '${[
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
    ].join('\\n')}' > /etc/systemd/system/xray-bridge.service`,
    '&& /usr/bin/systemctl daemon-reload; fi',
].join(' '));

/**
 * @typedef {Readonly<{code: number, stdout: string, stderr: string}>} NodeSSHResult
 * @typedef {Object} TopologyRunnerNodeSSH
 * @property {(command: string) => Promise<NodeSSHResult>} exec
 * @property {(remotePath: string, content: Buffer) => Promise<void>} writeFile
 * @typedef {Readonly<{
 *   ok: true,
 *   changed: boolean,
 *   sha256: string,
 *   mode: '0750'
 * }>} EnsureRunnerResult
 */

class TopologyRunnerBootstrapperError extends Error {
    constructor() {
        super('Topology runner bootstrap is unavailable');
        this.name = 'TopologyRunnerBootstrapperError';
        this.code = 'TOPOLOGY_RUNNER_BOOTSTRAP_UNAVAILABLE';
    }
}

function hasExactKeys(value, expectedKeys) {
    return Boolean(value)
        && typeof value === 'object'
        && !Array.isArray(value)
        && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expectedKeys);
}

function parseInspection(result) {
    if (!result || typeof result !== 'object'
        || result.code !== 0
        || result.stderr !== ''
        || typeof result.stdout !== 'string') {
        throw new TopologyRunnerBootstrapperError();
    }
    if (result.stdout === 'missing\n') return null;

    const match = /^([a-f0-9]{64})  \/usr\/local\/bin\/celerity-topology-node-runner\n([0-7]{3,4})\n$/.exec(
        result.stdout,
    );
    if (!match) throw new TopologyRunnerBootstrapperError();
    return Object.freeze({ digest: match[1], mode: match[2].padStart(4, '0') });
}

function isSilentSuccess(result) {
    return Boolean(result)
        && typeof result === 'object'
        && result.code === 0
        && result.stdout === ''
        && result.stderr === '';
}

function success(changed) {
    return Object.freeze({
        ok: true,
        changed,
        sha256: TOPOLOGY_RUNNER_SHA256,
        mode: TOPOLOGY_RUNNER_MODE,
    });
}

class TopologyRunnerBootstrapper {
    /** @type {TopologyRunnerNodeSSH} */
    #nodeSSH;

    constructor(options) {
        if (!hasExactKeys(options, ['nodeSSH', 'target'])
            || options.target !== 'test'
            || !options.nodeSSH
            || typeof options.nodeSSH !== 'object'
            || typeof options.nodeSSH.exec !== 'function'
            || typeof options.nodeSSH.writeFile !== 'function') {
            throw new TopologyRunnerBootstrapperError();
        }
        this.#nodeSSH = options.nodeSSH;
    }

    /** @returns {Promise<EnsureRunnerResult>} */
    async ensureRunner() {
        if (arguments.length !== 0) throw new TopologyRunnerBootstrapperError();

        let transferStarted = false;
        try {
            const current = parseInspection(await this.#nodeSSH.exec(INSPECT_COMMAND));
            if (!isSilentSuccess(await this.#nodeSSH.exec(ENSURE_CONFIG_DIRS_COMMAND))) {
                throw new TopologyRunnerBootstrapperError();
            }
            if (current?.digest === TOPOLOGY_RUNNER_DIGEST
                && current.mode === TOPOLOGY_RUNNER_MODE) {
                return success(false);
            }

            transferStarted = true;
            await this.#nodeSSH.writeFile(
                TOPOLOGY_RUNNER_UPLOAD_PATH,
                Buffer.from(TOPOLOGY_RUNNER_SOURCE),
            );
            if (!isSilentSuccess(await this.#nodeSSH.exec(INSTALL_COMMAND))) {
                throw new TopologyRunnerBootstrapperError();
            }

            const installed = parseInspection(await this.#nodeSSH.exec(INSPECT_COMMAND));
            if (installed?.digest !== TOPOLOGY_RUNNER_DIGEST
                || installed.mode !== TOPOLOGY_RUNNER_MODE) {
                throw new TopologyRunnerBootstrapperError();
            }
            return success(true);
        } catch {
            if (transferStarted) {
                try {
                    await this.#nodeSSH.exec(CLEANUP_COMMAND);
                } catch {
                    // Preserve the one safe public error.
                }
            }
            throw new TopologyRunnerBootstrapperError();
        }
    }
}

module.exports = {
    ENSURE_CONFIG_DIRS_COMMAND,
    TOPOLOGY_RUNNER_MODE,
    TOPOLOGY_RUNNER_PATH,
    TOPOLOGY_RUNNER_SHA256,
    TopologyRunnerBootstrapper,
    TopologyRunnerBootstrapperError,
};
