const mongoose = require('mongoose');

const LOGIN_PATTERN = /^[A-Za-z0-9._@-]{1,64}$/;
const SYNC_STATUSES = ['pending', 'syncing', 'synced', 'error', 'delete_pending'];

function isCanonicalIpv4(value) {
    if (typeof value !== 'string') return false;
    const octets = value.split('.');
    return octets.length === 4
        && octets.every(octet => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255);
}

const l2tpUserSchema = new mongoose.Schema({
    login: {
        type: String,
        required: true,
        match: LOGIN_PATTERN,
    },
    relayNode: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HyNode',
        required: true,
    },
    passwordEncrypted: {
        type: String,
        required: true,
        select: false,
    },
    ip: {
        type: String,
        required: true,
        validate: {
            validator: isCanonicalIpv4,
            message: 'ip must be a canonical IPv4 address',
        },
    },
    enabled: { type: Boolean, default: true },
    comment: { type: String, default: '' },

    desiredRevision: { type: Number, default: 0 },
    appliedRevision: { type: Number, default: 0 },
    syncStatus: {
        type: String,
        enum: SYNC_STATUSES,
        default: 'pending',
    },
    syncOperationId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'L2tpOperation',
        default: null,
    },
    lastSyncedAt: { type: Date, default: null },
    lastErrorCode: { type: String, default: '' },
    lastError: { type: String, default: '' },

    createdBy: { type: String, default: '' },
    updatedBy: { type: String, default: '' },
}, { timestamps: true });

l2tpUserSchema.index({ relayNode: 1, login: 1 }, { unique: true });
l2tpUserSchema.index({ relayNode: 1, ip: 1 }, { unique: true });
l2tpUserSchema.index({ relayNode: 1, enabled: 1 });
l2tpUserSchema.index({ syncStatus: 1 });

module.exports = mongoose.model('L2tpUser', l2tpUserSchema);
