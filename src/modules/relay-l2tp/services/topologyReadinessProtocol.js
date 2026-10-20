'use strict';
const { createHash } = require('node:crypto');
const READINESS_COMMANDS = Object.freeze(['verify-ppp-users', 'restore-users']);
const exact = (v, keys) => v && typeof v === 'object' && !Array.isArray(v)
    && JSON.stringify(Reflect.ownKeys(v).sort()) === JSON.stringify([...keys].sort());
const safe = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value) && !['.', '..'].includes(value);
function readinessCommandId(command, verifyCommandId) {
    if (!READINESS_COMMANDS.includes(command) || !safe(verifyCommandId)) throw new Error('Invalid readiness identity');
    return createHash('sha256').update(`topology-readiness-v1:${command}:${verifyCommandId}`).digest('hex');
}
function validReadiness(command, value) {
    if (command === 'restore-users') return exact(value, ['bootId', 'snapshotSha256', 'userCount'])
        && safe(value.bootId) && typeof value.snapshotSha256 === 'string' && /^[a-f0-9]{64}$/.test(value.snapshotSha256)
        && Number.isSafeInteger(value.userCount) && value.userCount >= 1 && value.userCount <= 4096;
    return command === 'verify-ppp-users'
        && exact(value, ['bootId', 'operationId', 'expectedCredentialRevision', 'expectedEnabledUserCount'])
        && safe(value.bootId) && safe(value.operationId)
        && Number.isSafeInteger(value.expectedCredentialRevision) && value.expectedCredentialRevision >= 1
        && Number.isSafeInteger(value.expectedEnabledUserCount) && value.expectedEnabledUserCount >= 0;
}
function parseReadinessReceipt(result, command, request) {
    if (result?.code !== 0 || result.stderr !== '' || typeof result.stdout !== 'string'
        || !result.stdout.endsWith('\n') || /[\r\n]/.test(result.stdout.slice(0, -1))) throw new Error('Unconfirmed readiness');
    const receipt = JSON.parse(result.stdout);
    if (JSON.stringify(receipt) + '\n' !== result.stdout) throw new Error('Unconfirmed readiness');
    const { readiness, snapshot: _snapshot, ...binding } = request;
    const checksSha256 = createHash('sha256').update(JSON.stringify(readiness)).digest('hex');
    const fields = { ...binding, protocolVersion: 2, completion: 'completed', phase: 'verified',
        ownershipRetained: true, bootId: readiness.bootId, checksSha256 };
    if (!exact(receipt, [...Object.keys(fields), 'result']) || Object.entries(fields).some(([k, v]) => receipt[k] !== v)) {
        throw new Error('Unconfirmed readiness');
    }
    const value = receipt.result;
    if (command === 'restore-users') {
        if (!exact(value, ['ok', 'code', 'userCount', 'inboundCount']) || value.ok !== true
            || value.code !== 'XRAY_USERS_RESTORED' || value.userCount !== readiness.userCount
            || !Number.isSafeInteger(value.inboundCount) || value.inboundCount < 1 || value.inboundCount > 64) {
            throw new Error('Unconfirmed readiness');
        }
        return Object.freeze({ ...value });
    }
    if (!exact(value, ['ok', 'code', 'credentialRevision', 'enabledUserCount', 'managedUserCount'])
        || value.ok !== true || value.code !== 'USERS_VERIFIED'
        || value.credentialRevision !== readiness.expectedCredentialRevision
        || value.enabledUserCount !== readiness.expectedEnabledUserCount
        || value.managedUserCount !== readiness.expectedEnabledUserCount) throw new Error('Unconfirmed readiness');
    return Object.freeze({ ...value });
}
module.exports = { READINESS_COMMANDS, readinessCommandId, validReadiness, parseReadinessReceipt };
