'use strict';
const mongoose = require('mongoose');
const executionContextField = require('./topologyExecutionContextSchema');
const schema = new mongoose.Schema({
    executionContext: executionContextField(true),
    requestKey: { type: String, required: true, immutable: true, maxlength: 128 },
    payloadHash: { type: String, required: true, immutable: true },
    version: { type: Number, required: true, enum: [1, 2], immutable: true },
    kind: { type: String, enum: ['link.create', 'link.apply', 'link.delete'], immutable: true,
        required() { return this.version === 2; } },
    linkId: { type: mongoose.Schema.Types.ObjectId, ref: 'CascadeLink', immutable: true,
        required() { return this.version === 2; } },
    // Content-addressed configuration version, not Mongoose's non-incremented __v.
    nodeActivation: { type: mongoose.Schema.Types.Mixed, default: undefined, immutable: true,
        validate(value) { if (value === undefined) return true; try { require('../services/topologyNodeActivation').nodeActivation(value); return this.version === 2 && this.kind === 'link.apply'; } catch { return false; } } },
    desiredVersion: { type: String, match: /^[a-f0-9]{64}$/, immutable: true,
        required() { return this.version === 2; } },
    // Refreshable planning hint before admission; bound operation resources never change.
    resourceNodeIds: { type: [String], default: undefined,
        required() { return this.version === 2; },
        validate: value => value === undefined || (value.length > 0 && value.length <= 128
            && value.every(id => /^[a-f0-9]{24}$/.test(id))
            && new Set(value).size === value.length && value.join() === [...value].sort().join()) },
    payload: { type: mongoose.Schema.Types.Mixed, required: true, immutable: true, select: false },
    ordinal: { type: Number, required: true, min: 1, immutable: true },
    acceptanceRevision: { type: Number, required: true, min: 0, immutable: true },
    status: { type: String, required: true, enum: ['waiting', 'claimed', 'admitted', 'succeeded', 'failed', 'blocked'] },
    attempts: { type: Number, required: true, default: 0, min: 0 },
    generation: { type: Number, required: true, default: 0, min: 0 },
    leaseOwner: String,
    leaseUntil: Date,
    nextAttemptAt: Date,
    operationIdempotencyKey: String,
    operationId: { type: mongoose.Schema.Types.ObjectId, ref: 'TopologyOperation' },
    topologyRevision: Number,
    priorDeployedRevision: Number,
    admissionFingerprint: String,
    createdLinkId: { type: mongoose.Schema.Types.ObjectId,
        required() { return this.version === 2 && this.kind === 'link.create'; } },
    errorCode: String,
    // Explicit no-admission settlement retains the original unknown label;
    // the newly observed refusal is not substituted for historical causality.
    unadmittedPreparation: { type: new mongoose.Schema({
        originalErrorCode: { type: String, enum: ['TOPOLOGY_INTENT_PREPARE_UNCERTAIN'], required: true },
        observedCauseCode: { type: String, enum: ['MULTIPLE_DEFAULT_EGRESS', 'VALID_PREFLIGHT_NO_ADMISSION'], required: true },
        revision: { type: Number, min: 0, required: true },
        generation: { type: Number, min: 1, required: true },
        confirmedAt: { type: Date, required: true },
    }, { _id: false }), default: undefined },
    waitingReason: String,
}, { timestamps: true });
schema.index({ requestKey: 1 }, { unique: true });
schema.index({ ordinal: 1 }, { unique: true });
schema.index({ operationId: 1 }, { unique: true, sparse: true });
schema.index({ status: 1, ordinal: 1 });
module.exports = mongoose.model('TopologyCreateIntent', schema);
