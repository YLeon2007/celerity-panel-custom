'use strict';

const mongoose = require('mongoose');

const cascadeTopologyStateSchema = new mongoose.Schema({
    _id: {
        type: String,
        enum: ['singleton'],
        default: 'singleton',
    },
    revision: {
        type: Number,
        default: 0,
        min: 0,
    },
    // State-only transactions conflict with path writers without changing topology revision.
    stateTransitionRevision: { type: Number, default: 0, min: 0 },
    deployedRevision: {
        type: Number,
        default: 0,
        min: 0,
    },
    // Reserved for a future replacement workflow; no acquisition path is enabled yet.
    // Keep the epoch after release so an old owner token cannot be reused as authority.
    replacementEpoch: {
        type: Number,
        default: 0,
        min: 0,
    },
    replacementReservation: {
        type: new mongoose.Schema({
            ownerToken: { type: String, required: true },
            epoch: { type: Number, required: true, min: 1 },
        }, { _id: false }),
        default: undefined,
    },
}, { timestamps: true });

module.exports = mongoose.model('CascadeTopologyState', cascadeTopologyStateSchema);
