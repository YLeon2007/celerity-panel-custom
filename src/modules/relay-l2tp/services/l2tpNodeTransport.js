'use strict';

const { parsePreflightExecResult } = require('./l2tpPreflightResult');

const REMOTE_OPERATIONS_ROOT = '/var/lib/celerity/l2tp/operations';
const ARTIFACT_RUNNER_PATH = '/usr/local/bin/celerity-l2tp-artifact-runner';
const ARTIFACT_RECEIVER_PATH = '/usr/local/bin/celerity-l2tp-artifact-receiver';
const ARTIFACT_COMMANDS = Object.freeze([
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
    'sync-users',
    'verify-users',
    'verify',
    'commit',
    'rollback',
]);
const ARTIFACT_COMMAND_SET = new Set(ARTIFACT_COMMANDS);
const OPERATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const ROOT_FILE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;
const ROOT_ARTIFACTS = Object.freeze({
    desired: Object.freeze({
        stagingPath: 'desired.json',
        remotePath: 'desired.json',
    }),
    artifact: Object.freeze({
        stagingPath: 'artifacts.json',
        remotePath: 'artifacts.json',
    }),
    xrayCandidate: Object.freeze({
        stagingPath: 'xray-candidate.json',
        remotePath: 'candidate/xray.json',
    }),
});
const ROOT_FILE_REQUEST_KEYS = Object.freeze([
    'content',
    'group',
    'mode',
    'operationId',
    'owner',
    'path',
    'type',
]);
const VERIFY_USER_RESULT_KEYS = Object.freeze([
    'code',
    'credentialRevision',
    'enabledUserCount',
    'managedUserCount',
    'ok',
]);
const VERIFY_USER_FAILURE_STATUSES = Object.freeze({
    MANAGED_USERS_MISSING: new Set([65]),
    MANAGED_USERS_EXTRA: new Set([65]),
    MANAGED_USERS_DUPLICATE: new Set([65]),
    MANAGED_USERS_ALTERED: new Set([65]),
    DISABLED_USERS_PRESENT: new Set([65]),
    MANAGED_BLOCK_INVALID: new Set([65]),
    CHAP_SECRETS_INVALID: new Set([65, 66, 77]),
});
const VERIFY_USER_FAILURE_CODES = new Set(Object.keys(VERIFY_USER_FAILURE_STATUSES));

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

function assertRootArtifact(type, path) {
    const artifact = Object.hasOwn(ROOT_ARTIFACTS, type)
        ? ROOT_ARTIFACTS[type]
        : null;
    if (artifact && artifact.stagingPath !== path) {
        throw new L2tpNodeTransportError(
            'ARTIFACT_NOT_ALLOWED',
            'Artifact is not allowed for L2TP root upload',
        );
    }
    assertRootFilePath(path);
    if (!artifact) {
        throw new L2tpNodeTransportError(
            'ARTIFACT_NOT_ALLOWED',
            'Artifact is not allowed for L2TP root upload',
        );
    }
    return artifact;
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

function assertRootFileRequest(request) {
    if (
        !request
        || typeof request !== 'object'
        || Array.isArray(request)
        || Object.keys(request).some(key => !ROOT_FILE_REQUEST_KEYS.includes(key))
    ) {
        throw new L2tpNodeTransportError(
            'INVALID_ARTIFACT_REQUEST',
            'Invalid L2TP artifact upload request',
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

function assertCommandExpectation(request) {
    const isVerification = request.command === 'verify-users';
    const expectedKeys = isVerification
        ? [
            'command',
            'expectedCredentialRevision',
            'expectedEnabledUserCount',
            'operationId',
        ]
        : ['command', 'operationId'];
    const actualKeys = Object.keys(request).sort();
    if (
        JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)
        || (isVerification && (
            !Number.isSafeInteger(request.expectedCredentialRevision)
            || request.expectedCredentialRevision < 1
            || !Number.isSafeInteger(request.expectedEnabledUserCount)
            || request.expectedEnabledUserCount < 0
        ))
    ) {
        throw new L2tpNodeTransportError(
            'INVALID_COMMAND_EXPECTATION',
            'Invalid L2TP artifact command expectation',
        );
    }
}

function parseVerifyUsersExecResult(result, expectedCredentialRevision, expectedEnabledUserCount) {
    if (
        !result
        || typeof result !== 'object'
        || typeof result.stdout !== 'string'
        || (result.stderr !== undefined && result.stderr !== '')
        || !result.stdout.endsWith('\n')
    ) {
        throw new Error('Invalid user verification response');
    }
    const serialized = result.stdout.slice(0, -1);
    if (!serialized || /[\r\n]/.test(serialized)) {
        throw new Error('Invalid user verification response');
    }

    let value;
    try {
        value = JSON.parse(serialized);
    } catch {
        throw new Error('Invalid user verification response');
    }
    if (
        !value
        || typeof value !== 'object'
        || Array.isArray(value)
        || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(VERIFY_USER_RESULT_KEYS)
        || typeof value.ok !== 'boolean'
        || value.credentialRevision !== expectedCredentialRevision
        || value.enabledUserCount !== expectedEnabledUserCount
        || !Number.isSafeInteger(value.managedUserCount)
        || value.managedUserCount < 0
        || typeof value.code !== 'string'
    ) {
        throw new Error('Invalid user verification response');
    }
    const status = Object.hasOwn(result, 'code') ? result.code : undefined;
    if (value.ok) {
        if (
            status !== 0
            || value.code !== 'USERS_VERIFIED'
            || value.managedUserCount !== expectedEnabledUserCount
        ) {
            throw new Error('Invalid user verification response');
        }
    } else if (
        !Number.isInteger(status)
        || status === 0
        || !VERIFY_USER_FAILURE_CODES.has(value.code)
        || !VERIFY_USER_FAILURE_STATUSES[value.code].has(status)
    ) {
        throw new Error('Invalid user verification response');
    }
    return {
        ok: value.ok,
        credentialRevision: value.credentialRevision,
        enabledUserCount: value.enabledUserCount,
        managedUserCount: value.managedUserCount,
        code: value.code,
    };
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

    async uploadRootFile(request) {
        assertRootFileRequest(request);
        const {
            operationId,
            type,
            path,
            content,
            owner,
            group,
            mode,
        } = request;
        assertOperationId(operationId);
        const artifact = assertRootArtifact(type, path);
        assertRootFileMetadata({ owner, group, mode });
        assertArtifactContent(content);

        const remotePath = `${REMOTE_OPERATIONS_ROOT}/${operationId}/${artifact.remotePath}`;

        try {
            assertSuccessfulExec(await this.nodeSSH.exec(
                `${ARTIFACT_RECEIVER_PATH} --operation-id ${operationId} --artifact-name ${path}`,
                { stdin: content },
            ));
        } catch {
            throw new L2tpNodeTransportError(
                'REMOTE_UPLOAD_FAILED',
                'Failed to upload an L2TP operation artifact',
            );
        }

        return { ok: true, path: remotePath };
    }

    async runArtifactCommand(request) {
        if (!request || typeof request !== 'object' || Array.isArray(request)) {
            throw new L2tpNodeTransportError(
                'INVALID_COMMAND_EXPECTATION',
                'Invalid L2TP artifact command expectation',
            );
        }
        const {
            operationId,
            command,
            expectedCredentialRevision,
            expectedEnabledUserCount,
        } = request;
        assertOperationId(operationId);
        assertArtifactCommand(command);
        assertCommandExpectation(request);

        let result;
        try {
            result = await this.nodeSSH.exec(
                `${ARTIFACT_RUNNER_PATH} --operation-id ${operationId} --command ${command}`,
            );
            if (command !== 'preflight' && command !== 'verify-users') assertSuccessfulExec(result);
        } catch {
            throw new L2tpNodeTransportError(
                'REMOTE_COMMAND_FAILED',
                'Failed to run an L2TP artifact command',
            );
        }

        if (command === 'preflight') return parsePreflightExecResult(result);
        if (command === 'verify-users') {
            try {
                return parseVerifyUsersExecResult(
                    result,
                    expectedCredentialRevision,
                    expectedEnabledUserCount,
                );
            } catch {
                throw new L2tpNodeTransportError(
                    'REMOTE_COMMAND_FAILED',
                    'Failed to run an L2TP artifact command',
                );
            }
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
