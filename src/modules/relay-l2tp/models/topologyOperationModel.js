'use strict';

const mongoose = require('mongoose');

const OPERATION_STATUSES = [
    'queued',
    'preparing',
    'committing',
    'rolling_back',
    'succeeded',
    'failed',
    'rolled_back',
];
const NODE_STATES = [
    'pending',
    'prepared',
    'committed',
    'failed',
    'rolled_back',
];

const topologyNodeSchema = new mongoose.Schema({
    node: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HyNode',
        required: true,
    },
    state: {
        type: String,
        enum: NODE_STATES,
        required: true,
    },
    candidateHash: { type: String, default: '', trim: true },
    backupId: { type: String, default: '', trim: true },
}, { _id: false, strict: true });

const topologyOperationSchema = new mongoose.Schema({
    topologyRevision: {
        type: Number,
        required: true,
        min: 0,
    },
    status: {
        type: String,
        enum: OPERATION_STATUSES,
        required: true,
    },
    nodes: { type: [topologyNodeSchema], default: [] },
}, { timestamps: true });

module.exports = mongoose.model('TopologyOperation', topologyOperationSchema);
