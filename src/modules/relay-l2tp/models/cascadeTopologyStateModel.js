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
    deployedRevision: {
        type: Number,
        default: 0,
        min: 0,
    },
}, { timestamps: true });

module.exports = mongoose.model('CascadeTopologyState', cascadeTopologyStateSchema);
