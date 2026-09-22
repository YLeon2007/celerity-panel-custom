'use strict';

const REMOTE_OPERATIONS_ROOT = '/var/lib/celerity/l2tp/operations';
const ARTIFACT_RUNNER_PATH = '/usr/local/bin/celerity-l2tp-artifact-runner';
const ARTIFACT_COMMANDS = Object.freeze([
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
]);
const ARTIFACT_COMMAND_SET = new Set(ARTIFACT_COMMANDS);
const OPERATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const ROOT_FILE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;

class L2tpNodeTransportError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'L2tpNodeTransportError';
        this.code = code;
    }
}

function assertOperationId(operationId) {
    if (typeof operationId !== 'string' || !OPERATION_ID_PATTERN.test(operationId)) {
        throw new L2tpNodeTransportError(
            'INVALID_OPERATION_ID',
            'Invalid L2TP operation id',
        );
    }
}

function assertRootFilePath(path) {
    if (typeof path !== 'string' || !ROOT_FILE_PATTERN.test(path)) {
        throw new L2tpNodeTransportError(
            'INVALID_ARTIFACT_PATH',
            'Invalid L2TP root artifact path',
        );
    }
}

function assertRootFileMetadata({ owner, group, mode }) {
    if (owner !== 'root' || group !== 'root' || mode !== 0o600) {
        throw new L2tpNodeTransportError(
            'ROOT_FILE_METADATA_REQUIRED',
            'L2TP operation artifacts must be root-owned mode 0600',
        );
    }
}

function assertArtifactContent(content) {
    if (typeof content !== 'string') {
        throw new L2tpNodeTransportError(
            'INVALID_ARTIFACT_CONTENT',
            'Invalid L2TP artifact content',
        );
    }
}

function assertArtifactCommand(command) {
    if (!ARTIFACT_COMMAND_SET.has(command)) {
        throw new L2tpNodeTransportError(
            'UNKNOWN_ARTIFACT_COMMAND',
            'Unsupported L2TP artifact command',
        );
    }
}

function assertSuccessfulExec(result) {
    if (result && Object.hasOwn(result, 'code') && result.code !== 0) {
        throw new Error('Remote command returned nonzero');
    }
}

class L2tpNodeTransport {
    constructor({ nodeSSH }) {
        this.nodeSSH = nodeSSH;
    }

    async uploadRootFile({ operationId, path, content, owner, group, mode }) {
        assertOperationId(operationId);
        assertRootFilePath(path);
        assertRootFileMetadata({ owner, group, mode });
        assertArtifactContent(content);

        const operationRoot = `${REMOTE_OPERATIONS_ROOT}/${operationId}/`;
        const remotePath = `${operationRoot}${path}`;

        try {
            assertSuccessfulExec(await this.nodeSSH.exec(
                `install -d -o root -g root -m 0700 -- ${operationRoot}`,
            ));
            await this.nodeSSH.writeFile(remotePath, content);
            assertSuccessfulExec(await this.nodeSSH.exec(
                `chown root:root -- ${remotePath} && chmod 0600 -- ${remotePath}`,
            ));
        } catch {
            throw new L2tpNodeTransportError(
                'REMOTE_UPLOAD_FAILED',
                'Failed to upload an L2TP operation artifact',
            );
        }

        return { ok: true, path: remotePath };
    }

    async runArtifactCommand({ operationId, command }) {
        assertOperationId(operationId);
        assertArtifactCommand(command);

        try {
            assertSuccessfulExec(await this.nodeSSH.exec(
                `${ARTIFACT_RUNNER_PATH} --operation-id ${operationId} --command ${command}`,
            ));
        } catch {
            throw new L2tpNodeTransportError(
                'REMOTE_COMMAND_FAILED',
                'Failed to run an L2TP artifact command',
            );
        }

        return { ok: true, operationId, command };
    }
}

module.exports = {
    ARTIFACT_COMMANDS,
    ARTIFACT_RUNNER_PATH,
    L2tpNodeTransport,
    L2tpNodeTransportError,
    REMOTE_OPERATIONS_ROOT,
};
