'use strict';

const mongoose = require('mongoose');

const cascadeTopologyStateSchema = new mongoose.Schema({
    // 'singleton' keeps the global draft revision fence (and the legacy
    // single-domain deployedRevision); 'domain:<key>' documents track the
    // deployed revision of one topology domain (a connected component of
    // the link graph).
    _id: {
        type: String,
        default: 'singleton',
    },
    domainKey: {
        type: String,
        default: null,
    },
    label: {
        type: String,
        default: null,
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
