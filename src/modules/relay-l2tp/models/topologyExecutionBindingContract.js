'use strict';
const mongoose = require('mongoose');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const ID = /^[a-f0-9]{24}$/;
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const COMMANDS = Object.freeze(['prepare', 'commit', 'verify', 'rollback', 'close']);
const EXPECTED_KEYS = Object.freeze(['executionContext', 'operationId', 'nodeId', 'candidateHash', 'backupId',
    'targetProfile', 'topologyRevision', 'priorDeployedRevision', 'owner', 'attempt', 'generation']);
const RECORD_KEYS = Object.freeze([...EXPECTED_KEYS, 'attemptId', 'predecessorGeneration', 'commandIds', 'bootId', 'maintenanceId']);
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
function immutable(schema) {
    schema.pre('save', function () { if (!this.isNew) throw failure('IMMUTABLE'); });
    schema.pre(['updateOne', 'updateMany', 'findOneAndUpdate', 'replaceOne', 'findOneAndReplace',
        'deleteOne', 'deleteMany', 'findOneAndDelete', 'bulkWrite'], function () { throw failure('IMMUTABLE'); });
}
function string(match) { return { type: String, required: true, immutable: true, ...(match ? { match } : {}) }; }
const identitySchema = new mongoose.Schema({ machineId: string(/^[a-f0-9]{32}$/),
    sshHostKeySha256: string(/^[a-f0-9]{64}$/) }, strict);
const common = () => ({
    _id: string(UUID), executionContext: { ...string(), enum: [PROD.hostIdentity] },
    nodeId: string(ID), targetProfile: { ...string(), enum: ['xray-main', 'xray-bridge'] },
    nodeIdentity: { type: identitySchema, required: true, immutable: true },
    ownerGeneration: string(UUID), predecessorGeneration: string(UUID), bootId: string(UUID),
    proofId: string(UUID), maintenanceId: string(UUID),
});
module.exports = { UUID, ID, TOKEN, COMMANDS, EXPECTED_KEYS, RECORD_KEYS, exact, freeze, failure, immutable,
    string, common, strict };
