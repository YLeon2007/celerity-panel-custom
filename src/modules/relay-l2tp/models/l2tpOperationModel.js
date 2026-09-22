'use strict';

const mongoose = require('mongoose');

const OPERATION_KINDS = [
    'preflight',
    'install',
    'remove',
    'repair',
    'verify',
    'sync_users',
    'disconnect_user',
    'rotate_psk',
    'change_route_group',
];
const OPERATION_STATUSES = [
    'queued',
    'running',
    'rolling_back',
    'succeeded',
    'failed',
    'rolled_back',
    'cancelled',
];

const operationLogEntrySchema = new mongoose.Schema({
    at: { type: Date, default: Date.now, required: true },
    level: { type: String, required: true, trim: true },
    code: { type: String, required: true, trim: true },
    message: { type: String, required: true, trim: true },
}, { _id: false, strict: true });

const operationPlanArtifactSchema = new mongoose.Schema({
    type: { type: String, required: true, trim: true },
    path: { type: String, required: true, trim: true },
}, { _id: false, strict: true });

const operationPlanStepSchema = new mongoose.Schema({
    type: { type: String, required: true, trim: true },
    artifacts: {
        type: [operationPlanArtifactSchema],
        default: undefined,
    },
}, { _id: false, strict: true });

const operationPlanDesiredSchema = new mongoose.Schema({
    clientCidr: { type: String, trim: true },
    localAddress: { type: String, trim: true },
    poolStart: { type: String, trim: true },
    poolEnd: { type: String, trim: true },
    dnsServers: { type: [String], default: undefined },
    tproxyPort: { type: Number },
    fwmark: { type: Number },
    routeTable: { type: Number },
    credentialRevision: { type: Number, min: 0 },
}, { _id: false, strict: true });

const operationPlanErrorSchema = new mongoose.Schema({
    code: { type: String, required: true, trim: true },
}, { _id: false, strict: true });

const operationPlanSchema = new mongoose.Schema({
    ok: { type: Boolean },
    operationId: { type: String, trim: true },
    topologyRevision: { type: Number, min: 0 },
    relayId: { type: String, trim: true },
    routeGroupId: { type: String, trim: true },
    selectedPathKey: { type: String, trim: true },
    nextHopNodeId: { type: String, trim: true },
    desired: { type: operationPlanDesiredSchema },
    error: { type: operationPlanErrorSchema },
    steps: {
        type: [operationPlanStepSchema],
        required: true,
        default: undefined,
    },
}, { _id: false, strict: true });

const l2tpOperationSchema = new mongoose.Schema({
    node: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HyNode',
        required: true,
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'L2tpUser',
        default: null,
    },
    kind: {
        type: String,
        enum: OPERATION_KINDS,
        required: true,
    },
    status: {
        type: String,
        enum: OPERATION_STATUSES,
        required: true,
    },
    idempotencyKey: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        index: true,
    },
    plan: {
        type: operationPlanSchema,
        required: true,
        immutable: true,
    },
    topologyRevision: { type: Number, min: 0, default: null },
    routeGroupId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'CascadeRouteGroup',
        default: null,
    },
    step: { type: String, default: '', trim: true },
    progress: {
        type: Number,
        min: 0,
        max: 100,
        default: 0,
        required: true,
    },
    attempts: { type: Number, min: 0, default: 0, required: true },
    leaseOwner: { type: String, default: '', trim: true },
    leaseUntil: { type: Date, default: null },
    logs: { type: [operationLogEntrySchema], default: [] },
    backupId: { type: String, default: '', trim: true },
    errorCode: { type: String, default: '', trim: true },
    errorMessage: { type: String, default: '' },
    requestedBy: { type: String, default: '', trim: true },
    startedAt: { type: Date, default: null },
    finishedAt: { type: Date, default: null },
}, { timestamps: true });

module.exports = mongoose.model('L2tpOperation', l2tpOperationSchema);
