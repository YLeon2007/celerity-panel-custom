'use strict';
const mongoose = require('mongoose');
const executionContextField = require('./topologyExecutionContextSchema');
const schema = new mongoose.Schema({
    executionContext: executionContextField(true),
    requestKey: { type: String, required: true, immutable: true, maxlength: 128 },
    payloadHash: { type: String, required: true, immutable: true },
    version: { type: Number, required: true, enum: [1], immutable: true },
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
    createdLinkId: mongoose.Schema.Types.ObjectId,
    errorCode: String,
}, { timestamps: true });
schema.index({ requestKey: 1 }, { unique: true });
schema.index({ ordinal: 1 }, { unique: true });
schema.index({ operationId: 1 }, { unique: true, sparse: true });
schema.index({ status: 1, ordinal: 1 });
module.exports = mongoose.model('TopologyCreateIntent', schema);
