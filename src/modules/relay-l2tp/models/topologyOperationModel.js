'use strict';

const mongoose = require('mongoose');
const { validNodeRef } = require('../services/topologyNodeRef');

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
        validate: {
            validator(value) { return validNodeRef(this.role, value); },
            message: 'nodeRef must match its node role',
        },
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
    // No default: legacy full-sync operations have no scoped identity.
    kind: { type: String, enum: ['link.apply', 'domain.reconcile', 'link.replace', 'link.attach'] },
    linkId: { type: String, match: /^[a-f0-9]{24}$/i },
    linkIds: { type: [{ type: String, match: /^[a-f0-9]{24}$/i }], default: undefined },
    // Ordered route beginning at the installed owner; linkIds is the full scoped set.
    newPathLinkIds: { type: [{ type: String, match: /^[a-f0-9]{24}$/i }], default: undefined },
    oldLinkId: { type: String, match: /^[a-f0-9]{24}$/i },
    groupId: { type: String, match: /^[a-f0-9]{24}$/i },
    pathKey: { type: String, trim: true },
    ownerNodeId: { type: String, match: /^[a-f0-9]{24}$/i },
    // Frozen installed-owner and PPP credential epochs for an unpublished attach.
    ownerTopologyRevision: { type: Number, min: 0 },
    ownerCredentialRevision: { type: Number, min: 0 },
    oldPathLinkIds: { type: [{ type: String, match: /^[a-f0-9]{24}$/i }], default: undefined },
    // Only link.apply records whether the frozen plan has a terminal relay.
    staged: { type: Boolean },
    // Remains held through failure/rollback until a proven-safe transactional release.
    heldTopologyAdmission: { type: Boolean },
    admissionFingerprint: { type: String, match: DIGEST_PATTERN },
    status: {
        type: String,
        enum: OPERATION_STATUSES,
        required: true,
    },
    // Execution succeeded does not establish client-visible ingress/egress.
    // Legacy documents without this field must also be treated as unverified.
    clientReadiness: {
        type: String,
        enum: ['unverified', 'verified'],
        default: 'unverified',
        required: true,
    },
    // Explicit only on new operations; legacy rows are not scheduled for proof.
    clientProofAttempts: { type: Number, min: 0, max: 3 },
    clientProofRetryAfter: { type: Date, default: undefined },
    clientProofLeaseOwner: { type: String, default: undefined },
    clientProofLeaseUntil: { type: Date, default: undefined },
    clientProofRevision: { type: Number, min: 0 },
    clientProofState: { type: String, enum: ['active_unverified', 'degraded'] },
    clientProofReason: { type: String, enum: ['probe_unavailable', 'probe_failed', 'revision_stale', 'retry_exhausted'] },
    attempts: { type: Number, min: 0, default: 0, required: true },
    leaseOwner: { type: String, default: '', trim: true },
    leaseUntil: { type: Date, default: null },
    finishedAt: { type: Date, default: null },
    nodes: { type: [topologyNodeSchema], default: [] },
}, { timestamps: true });

topologyOperationSchema.pre('validate', function validateScopedIdentity() {
    if (this.clientReadiness === 'verified' && this.status !== 'succeeded') {
        throw new Error('Client readiness requires successful execution');
    }
    if (this.clientReadiness === 'verified'
        && (!Number.isSafeInteger(this.clientProofRevision)
            || this.clientProofRevision !== this.topologyRevision)) {
        throw new Error('Client readiness requires proof for frozen topology revision');
    }
    const scoped = this.kind !== undefined || this.linkId !== undefined
        || this.linkIds !== undefined || this.staged !== undefined
        || this.oldLinkId !== undefined || this.groupId !== undefined
        || this.pathKey !== undefined || this.oldPathLinkIds !== undefined
        || this.ownerNodeId !== undefined || this.ownerTopologyRevision !== undefined
        || this.ownerCredentialRevision !== undefined || this.newPathLinkIds !== undefined;
    if (!scoped) return;
    const ids = this.linkIds;
    if (!this.kind || typeof this.linkId !== 'string'
        || !Array.isArray(ids) || ids.length === 0
        || new Set(ids).size !== ids.length || !ids.includes(this.linkId)
        || (this.kind === 'link.apply' ? typeof this.staged !== 'boolean'
            : this.staged !== undefined)
        || (this.kind === 'link.attach'
            ? this.oldLinkId !== undefined || this.oldPathLinkIds !== undefined
                || typeof this.groupId !== 'string' || !this.groupId
                || this.pathKey !== 'main'
                || typeof this.ownerNodeId !== 'string' || !this.ownerNodeId
                || !Array.isArray(this.newPathLinkIds)
                || this.newPathLinkIds.length < 2
                || this.newPathLinkIds.length >= ids.length
                || new Set(this.newPathLinkIds).size !== this.newPathLinkIds.length
                || this.newPathLinkIds.at(-1) !== this.linkId
                || !this.newPathLinkIds.every(id => ids.includes(id))
                || !Number.isSafeInteger(this.ownerTopologyRevision)
                || this.ownerTopologyRevision < 0
                || !Number.isSafeInteger(this.ownerCredentialRevision)
                || this.ownerCredentialRevision < 0
            : this.ownerTopologyRevision !== undefined
                || this.ownerCredentialRevision !== undefined
                || this.newPathLinkIds !== undefined)
        || (this.kind === 'link.replace'
            ? typeof this.oldLinkId !== 'string' || this.oldLinkId === this.linkId
                || ids.includes(this.oldLinkId) || typeof this.groupId !== 'string'
                || typeof this.pathKey !== 'string' || !this.pathKey
                || typeof this.ownerNodeId !== 'string' || !this.ownerNodeId
                || !Array.isArray(this.oldPathLinkIds) || this.oldPathLinkIds.length < 2
                || this.oldPathLinkIds.at(-1) !== this.oldLinkId
                || new Set(this.oldPathLinkIds).size !== this.oldPathLinkIds.length
            : this.kind === 'link.attach' ? false
                : this.oldLinkId !== undefined || this.groupId !== undefined
                || this.pathKey !== undefined || this.oldPathLinkIds !== undefined
                || this.ownerNodeId !== undefined)) {
        throw new Error('Incomplete scoped topology operation identity');
    }
});

topologyOperationSchema.index(
    { status: 1, clientReadiness: 1, clientProofRetryAfter: 1, clientProofLeaseUntil: 1 },
    { partialFilterExpression: { status: 'succeeded', clientReadiness: 'unverified',
        clientProofAttempts: { $lt: 3 } } },
);

module.exports = mongoose.model('TopologyOperation', topologyOperationSchema);
