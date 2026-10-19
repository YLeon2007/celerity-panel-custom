'use strict';
const mongoose = require('mongoose');
const strict = { _id: false, versionKey: false, strict: 'throw' };
const digest = { type: String, required: true, match: /^[a-f0-9]{64}$/ };
const contextSchema = new mongoose.Schema({
    target: { type: String, required: true, enum: ['production'] },
    hostIdentity: { type: String, required: true, enum: ['lm1.infograd.online'] },
}, strict);
const identitySchema = new mongoose.Schema({
    machineId: { type: String, required: true, match: /^[a-f0-9]{32}$/ },
    sshHostKeySha256: digest,
}, strict);
const snapshotSchema = new mongoose.Schema({
    configSha256: digest, unitSha256: digest,
    serviceActive: { type: String, required: true, enum: ['active', 'inactive'] },
    serviceEnabled: { type: String, required: true, enum: ['enabled', 'disabled', 'masked'] },
}, strict);
const receiptSchema = new mongoose.Schema({
    proofId: { type: String, required: true }, maintenanceId: { type: String, required: true },
    fromGeneration: { type: String, required: true }, toGeneration: { type: String, required: true },
    oldBackendInstanceId: { type: String, required: true }, oldPid: { type: Number, required: true },
    oldProcessStartTime: { type: String, required: true }, verifiedAt: { type: Date, required: true },
}, strict);
const schema = new mongoose.Schema({
    executionContext: { type: contextSchema, required: true, immutable: true },
    node: { type: mongoose.Schema.Types.ObjectId, required: true, immutable: true },
    profile: { type: String, required: true, immutable: true, enum: ['xray-main', 'xray-bridge'] },
    nodeIdentity: { type: identitySchema, required: true, immutable: true },
    originalSnapshot: { type: snapshotSchema },
    adoptionReceipt: { type: receiptSchema },
    handbackReceipt: { type: receiptSchema },
    // No defaults: an unbound/cloned/legacy row is not an adoption permit.
    owner: { type: String, required: true, enum: ['classic', 'topology'] },
    generation: { type: String, required: true, match: /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/ },
}, { timestamps: true, strict: 'throw', versionKey: false });
// Global node/profile uniqueness also prevents a foreign-context clone occupying
// a second ownership slot. Context remains an explicit predicate on every CAS.
schema.index({ node: 1, profile: 1 }, { unique: true });
module.exports = mongoose.model('TopologyConfigOwner', schema);
