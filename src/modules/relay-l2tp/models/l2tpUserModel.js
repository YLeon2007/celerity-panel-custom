const mongoose = require('mongoose');

const LOGIN_PATTERN = /^[A-Za-z0-9._@-]{1,64}$/;
const SYNC_STATUSES = ['pending', 'syncing', 'synced', 'error', 'delete_pending'];

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
    enabled: { type: Boolean, default: true },
    comment: { type: String, default: '' },

    desiredRevision: { type: Number, default: 0 },
    appliedRevision: { type: Number, default: 0 },
    syncStatus: {
        type: String,
        enum: SYNC_STATUSES,
        default: 'pending',
    },
    lastSyncedAt: { type: Date, default: null },
    lastErrorCode: { type: String, default: '' },
    lastError: { type: String, default: '' },

    createdBy: { type: String, default: '' },
    updatedBy: { type: String, default: '' },
}, { timestamps: true });

l2tpUserSchema.index({ relayNode: 1, login: 1 }, { unique: true });
l2tpUserSchema.index({ relayNode: 1, enabled: 1 });
l2tpUserSchema.index({ syncStatus: 1 });

module.exports = mongoose.model('L2tpUser', l2tpUserSchema);
