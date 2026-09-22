'use strict';

const mongoose = require('mongoose');

const MODULE_STATE_ID = 'relay-l2tp';

const relayL2tpMigrationStateSchema = new mongoose.Schema({
    _id: {
        type: String,
        enum: [MODULE_STATE_ID],
        default: MODULE_STATE_ID,
    },
    version: {
        type: Number,
        required: true,
        default: 0,
        min: 0,
    },
    appliedMigrationIds: {
        type: [{ type: String, required: true }],
        default: [],
    },
    lastAppliedAt: {
        type: Date,
        default: null,
    },
}, { strict: true, versionKey: false });

module.exports = mongoose.model(
    'RelayL2tpMigrationState',
    relayL2tpMigrationStateSchema,
);
