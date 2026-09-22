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
const CANDIDATE_MEDIA_TYPE = 'application/vnd.celerity.xray-topology-node+json;version=1';
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;

const topologyCheckSchema = new mongoose.Schema({
    type: {
        type: String,
        enum: ['service', 'port'],
        required: true,
    },
    serviceUnit: { type: String },
    protocol: { type: String, enum: ['tcp'] },
    port: { type: Number, min: 1, max: 65535 },
    expectedState: {
        type: String,
        enum: ['active', 'listening'],
        required: true,
    },
}, { _id: false, strict: true });

const topologyCandidateSchema = new mongoose.Schema({
    mediaType: {
        type: String,
        enum: [CANDIDATE_MEDIA_TYPE],
        required: true,
    },
    bytes: {
        type: [{ type: Number, min: 0, max: 255 }],
        required: true,
        validate: bytes => bytes.length > 0 && bytes.length <= 4 * 1024 * 1024,
    },
    sha256: {
        type: String,
        match: DIGEST_PATTERN,
        required: true,
    },
}, { _id: false, strict: true });

const topologyNodeSchema = new mongoose.Schema({
    node: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HyNode',
        required: true,
    },
    nodeRef: {
        type: String,
        match: /^(?:portal|bridge|relay-[1-9][0-9]*)$/,
        required: true,
    },
    role: {
        type: String,
        enum: ['portal', 'relay', 'bridge'],
        required: true,
    },
    targetProfile: {
        type: String,
        enum: ['xray-main', 'xray-bridge'],
        required: true,
    },
    checks: {
        type: [topologyCheckSchema],
        required: true,
        default: undefined,
    },
    state: {
        type: String,
        enum: NODE_STATES,
        required: true,
    },
    candidateHash: {
        type: String,
        match: DIGEST_PATTERN,
        required: true,
    },
    candidate: {
        type: topologyCandidateSchema,
        required: true,
    },
    backupId: { type: String, default: '', trim: true },
}, { _id: false, strict: true });

const topologyOperationSchema = new mongoose.Schema({
    topologyRevision: {
        type: Number,
        required: true,
        min: 0,
    },
    priorDeployedRevision: {
        type: Number,
        required: true,
        min: 0,
    },
    status: {
        type: String,
        enum: OPERATION_STATUSES,
        required: true,
    },
    attempts: { type: Number, min: 0, default: 0, required: true },
    leaseOwner: { type: String, default: '', trim: true },
    leaseUntil: { type: Date, default: null },
    finishedAt: { type: Date, default: null },
    nodes: { type: [topologyNodeSchema], default: [] },
}, { timestamps: true });

module.exports = mongoose.model('TopologyOperation', topologyOperationSchema);
