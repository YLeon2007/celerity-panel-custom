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
const SYNC_USERS_STEP_TYPES = Object.freeze(['backup', 'sync_users', 'verify_users']);

function plainObject(value) {
    return value && typeof value.toObject === 'function'
        ? value.toObject()
        : value;
}

function hasExactKeys(value, expectedKeys) {
    const plain = plainObject(value);
    return plain
        && typeof plain === 'object'
        && !Array.isArray(plain)
        && Object.keys(plain).sort().join('\0') === [...expectedKeys].sort().join('\0');
}

function isValidSyncUsersPlan(plan, operation) {
    if (operation.kind !== 'sync_users') return true;
    const plain = plainObject(plan);
    const desired = plainObject(plain?.desired);
    const steps = plain?.steps?.map(plainObject);
    const credentialRevision = desired?.credentialRevision;
    if (
        !hasExactKeys(plain, ['ok', 'operationId', 'relayId', 'desired', 'steps'])
        || plain.ok !== true
        || plain.operationId !== String(operation._id)
        || plain.relayId !== String(operation.node)
        || !hasExactKeys(desired, ['credentialRevision'])
        || !Number.isSafeInteger(credentialRevision)
        || credentialRevision < 1
        || !Array.isArray(steps)
        || steps.length !== SYNC_USERS_STEP_TYPES.length
        || steps.some((step, index) => step?.type !== SYNC_USERS_STEP_TYPES[index])
        || !hasExactKeys(steps[0], ['type'])
        || !hasExactKeys(steps[2], ['type'])
        || !hasExactKeys(steps[1], ['type', 'artifacts'])
        || !Array.isArray(steps[1].artifacts)
        || steps[1].artifacts.length !== 1
    ) {
        return false;
    }
    const artifact = plainObject(steps[1].artifacts[0]);
    return hasExactKeys(artifact, ['type', 'path'])
        && artifact.type === 'desired'
        && artifact.path === 'desired.json';
}

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
        validate: {
            validator(plan) {
                return isValidSyncUsersPlan(plan, this);
            },
            message: 'sync_users operations require an exact durable plan',
            type: 'syncUsersPlan',
        },
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
