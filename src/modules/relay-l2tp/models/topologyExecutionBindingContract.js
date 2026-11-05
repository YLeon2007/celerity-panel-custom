'use strict';
const mongoose = require('mongoose');
const { TOPOLOGY_EXECUTION_CONTEXTS } = require('../domain/topologyExecutionContext');
const { assertProfileTargetPin } = require('../services/topologyProfileTarget');
const { createProfileTargetPinSchema } = require('./topologyProfileTargetPinSchema');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const ID = /^[a-f0-9]{24}$/;
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const COMMANDS = Object.freeze(['prepare', 'commit', 'verify', 'rollback', 'close']);
const EXPECTED_KEYS = Object.freeze(['executionContext', 'operationId', 'nodeId', 'candidateHash', 'backupId',
    'targetProfile', 'topologyRevision', 'priorDeployedRevision', 'owner', 'attempt', 'generation']);
const RECORD_KEYS = Object.freeze([...EXPECTED_KEYS, 'attemptId', 'predecessorGeneration', 'commandIds', 'bootId', 'maintenanceId']);
const IMPORTED_EXPECTED_KEYS = Object.freeze([...EXPECTED_KEYS, 'profileTargetPin']);
const IMPORTED_RECORD_KEYS = Object.freeze([...RECORD_KEYS, 'profileTargetPin']);
function keysFor(value, nativeKeys, importedKeys) {
    if (!value || !Object.hasOwn(value, 'profileTargetPin')) return nativeKeys;
    const pin = assertProfileTargetPin(value.profileTargetPin);
    if (pin.nodeId !== value.nodeId || pin.targetProfile !== value.targetProfile) {
        throw Object.assign(new Error('TOPOLOGY_PROFILE_TARGET_INVALID'), { code: 'TOPOLOGY_PROFILE_TARGET_INVALID' });
    }
    // Do not compare pin.ownerGeneration with binding.generation: the latter is
    // the short-lived lock/runner epoch, not the permanent adopted owner epoch.
    return importedKeys;
}
function expectedKeysFor(value) { return keysFor(value, EXPECTED_KEYS, IMPORTED_EXPECTED_KEYS); }
function recordKeysFor(value) { return keysFor(value, RECORD_KEYS, IMPORTED_RECORD_KEYS); }
const strict = { _id: false, versionKey: false, strict: 'throw' };
function exact(value, keys) {
    return value && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function freeze(value) {
    if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
    return value;
}
function failure(suffix = 'UNPROVEN') {
    const code = `TOPOLOGY_EXECUTION_BINDING_${suffix}`;
    return Object.assign(new Error(code), { code });
}
// Exact V2 fresh `status` of the persisted close command. This is protocol
// data, not release authority; only the held external attestor may supply it.
const TERMINAL_BINDING_KEYS = ['operationId', 'nodeId', 'candidateHash', 'backupId', 'targetProfile',
    'executionContext', 'attemptId', 'generation', 'predecessorGeneration'];
const TERMINAL_KEYS = [...TERMINAL_BINDING_KEYS, 'ok', 'command', 'commandId', 'protocolVersion',
    'completion', 'phase', 'terminal', 'ownershipRetained', 'terminalOutcome', 'bootId',
    'systemdJob', 'serviceState', 'completedCommand'];
function validTerminalReceipt(receipt, binding) {
    return exact(receipt, TERMINAL_KEYS) && receipt.ok === true && receipt.command === 'status'
        && receipt.protocolVersion === 2 && receipt.completion === 'completed' && receipt.phase === 'closed'
        && receipt.terminal === true && receipt.ownershipRetained === true && receipt.completedCommand === 'close'
        && ['verified', 'rolledback', 'cancelled'].includes(receipt.terminalOutcome)
        && (receipt.terminalOutcome === 'cancelled'
            ? receipt.systemdJob === 'not-applicable' && receipt.serviceState === 'not-applicable'
            : receipt.systemdJob === 'completed' && (receipt.serviceState === 'active:running'
                || receipt.terminalOutcome === 'rolledback' && receipt.serviceState === 'inactive:dead'))
        && TERMINAL_BINDING_KEYS.every(key => typeof receipt[key] === 'string' && receipt[key] === binding[key])
        && typeof receipt.commandId === 'string' && UUID.test(receipt.commandId)
        && typeof receipt.bootId === 'string' && UUID.test(receipt.bootId)
        && receipt.commandId === binding.commandIds.close && receipt.bootId === binding.bootId;
}
function immutable(schema) {
    schema.pre('save', function () { if (!this.isNew) throw failure('IMMUTABLE'); });
    schema.pre(['updateOne', 'updateMany', 'findOneAndUpdate', 'replaceOne', 'findOneAndReplace',
        'deleteOne', 'deleteMany', 'findOneAndDelete', 'bulkWrite'], function () { throw failure('IMMUTABLE'); });
}
function string(match) { return { type: String, required: true, immutable: true, ...(match ? { match } : {}) }; }
const endpointSchema = new mongoose.Schema({ ip: string(),
    port: { type: Number, required: true, immutable: true, min: 1, max: 65535, validate: Number.isSafeInteger },
    username: string() }, strict);
const identitySchema = new mongoose.Schema({ machineId: string(/^[a-f0-9]{32}$/),
    sshHostKeySha256: string(/^[a-f0-9]{64}$/) }, strict);
const common = () => ({
    _id: string(UUID), executionContext: { ...string(), enum: TOPOLOGY_EXECUTION_CONTEXTS.map(context => context.hostIdentity) },
    nodeId: string(ID), targetProfile: { ...string(), enum: ['xray-main', 'xray-bridge'] },
    endpoint: { type: endpointSchema, required: true, immutable: true },
    nodeIdentity: { type: identitySchema, required: true, immutable: true },
    ownerGeneration: string(UUID), predecessorGeneration: string(/^(?:none|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/), bootId: string(UUID),
    proofId: string(UUID), maintenanceId: string(UUID),
    profileTargetPin: { type: createProfileTargetPinSchema(), default: undefined, immutable: true,
        // Validate the raw value before Mongoose can cast or discard fields.
        // An explicitly present undefined/null is malformed, not native absence.
        set: assertProfileTargetPin,
        validate(value) {
            if (value === undefined) return true; // genuinely absent old row
            try {
                const pin = assertProfileTargetPin(value);
                return pin.nodeId === this.nodeId && pin.targetProfile === this.targetProfile
                    && pin.ownerGeneration === this.ownerGeneration;
            } catch { return false; }
        } },
});
module.exports = { UUID, ID, TOKEN, COMMANDS, EXPECTED_KEYS, RECORD_KEYS, expectedKeysFor, recordKeysFor, exact, freeze, failure, immutable,
    string, common, strict, validTerminalReceipt };
