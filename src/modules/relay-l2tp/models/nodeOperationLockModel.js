'use strict';

const mongoose = require('mongoose');

const nodeOperationLockSchema = new mongoose.Schema({
    node: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HyNode',
        required: true,
    },
    owner: {
        type: String,
        required: true,
        trim: true,
    },
    operationId: {
        type: String,
        required: true,
        trim: true,
    },
    leaseUntil: {
        type: Date,
        required: true,
    },
    generation: {
        type: String,
        required: true,
    },
    // No default: missing values on legacy rows must never be considered clean.
    remoteUncertain: {
        type: Boolean,
        required: true,
    },
}, { timestamps: true });

nodeOperationLockSchema.index({ node: 1 }, { unique: true });

module.exports = mongoose.model('NodeOperationLock', nodeOperationLockSchema);
