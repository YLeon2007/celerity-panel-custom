'use strict';

const { readFileSync, readdirSync } = require('node:fs');
const path = require('node:path');

// The L2TP artifact bundle (runner + receiver + step scripts) must exist on a
// relay before any artifact command (preflight/apply/…) can run. Fresh nodes
// do not have it, which used to surface as a bare PREFLIGHT_FAILED. This
// bootstrapper mirrors the topology runner bootstrap: verify the installed
// runner digest, otherwise upload the pinned bundle and let its own
// hash-verifying install.sh lay it down.
const ARTIFACT_SOURCE_DIR = path.join(__dirname, '..', 'node-artifacts', 'l2tp');
const RUNNER_LINK = '/usr/local/bin/celerity-l2tp-artifact-runner';
const RECEIVER_LINK = '/usr/local/bin/celerity-l2tp-artifact-receiver';
const INSTALLED_RUNNER = '/usr/local/lib/celerity/relay-l2tp/runner.sh';
const STAGING_DIR = '/var/lib/celerity/l2tp-bootstrap';

const INSPECT_COMMAND = Object.freeze([
    `if /usr/bin/test -x ${RUNNER_LINK} && /usr/bin/test -x ${RECEIVER_LINK} && /usr/bin/test -f ${INSTALLED_RUNNER}; then`,
    `/usr/bin/sha256sum -- ${INSTALLED_RUNNER};`,
    'else',
    "printf 'missing\\n';",
    'fi',
].join(' '));

class L2tpArtifactBootstrapperError extends Error {
    constructor(message = 'Failed to bootstrap the L2TP node artifact') {
        super(message);
        this.name = 'L2tpArtifactBootstrapperError';
    }
}

function localArtifactFiles() {
    return readdirSync(ARTIFACT_SOURCE_DIR)
        .filter(name => name.endsWith('.sh') || name.endsWith('.py'))
        .sort();
}

function localRunnerDigest(createHash) {
    return createHash('sha256')
        .update(readFileSync(path.join(ARTIFACT_SOURCE_DIR, 'runner.sh')))
        .digest('hex');
}

function isSilentSuccess(result) {
    return Boolean(result)
        && result.code === 0
        && (result.stdout ?? '') === ''
        && (result.stderr ?? '') === '';
}

class L2tpArtifactBootstrapper {
    #nodeSSH;
    #createHash;

    constructor({ nodeSSH, createHash }) {
        if (!nodeSSH || typeof nodeSSH.exec !== 'function') {
            throw new TypeError('L2tpArtifactBootstrapper requires nodeSSH.exec');
        }
        if (typeof createHash !== 'function') {
            throw new TypeError('L2tpArtifactBootstrapper requires createHash');
        }
        this.#nodeSSH = nodeSSH;
        this.#createHash = createHash;
    }

    async ensureArtifact() {
        const expectedDigest = localRunnerDigest(this.#createHash);
        const inspected = await this.#nodeSSH.exec(INSPECT_COMMAND);
        if (inspected && inspected.code === 0
            && typeof inspected.stdout === 'string'
            && inspected.stdout.trim().split(/\s+/)[0] === expectedDigest) {
            return { ok: true, changed: false };
        }

        if (!isSilentSuccess(await this.#nodeSSH.exec(
            `/usr/bin/rm -rf -- ${STAGING_DIR} && /usr/bin/install -d -o 0 -g 0 -m 0700 -- ${STAGING_DIR}`,
        ))) {
            throw new L2tpArtifactBootstrapperError();
        }

        try {
            for (const name of localArtifactFiles()) {
                const content = readFileSync(path.join(ARTIFACT_SOURCE_DIR, name));
                const uploaded = await this.#nodeSSH.exec(
                    `/usr/bin/tee -- ${STAGING_DIR}/${name} >/dev/null && /usr/bin/chmod 0755 -- ${STAGING_DIR}/${name}`,
                    { stdin: content },
                );
                if (!isSilentSuccess(uploaded)) {
                    throw new L2tpArtifactBootstrapperError();
                }
            }

            const installed = await this.#nodeSSH.exec(
                `/usr/bin/bash -- ${STAGING_DIR}/install.sh`,
                { timeout: 120000 },
            );
            if (!installed || installed.code !== 0
                || typeof installed.stdout !== 'string'
                || !installed.stdout.includes('"status":"ok"')) {
                throw new L2tpArtifactBootstrapperError();
            }
        } finally {
            await this.#nodeSSH.exec(`/usr/bin/rm -rf -- ${STAGING_DIR}`).catch(() => {});
        }

        return { ok: true, changed: true };
    }
}

function createL2tpArtifactBootstrapper(dependencies) {
    return new L2tpArtifactBootstrapper(dependencies);
}

module.exports = {
    INSPECT_COMMAND,
    L2tpArtifactBootstrapper,
    L2tpArtifactBootstrapperError,
    createL2tpArtifactBootstrapper,
};
