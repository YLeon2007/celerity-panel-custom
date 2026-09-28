'use strict';

const mongoose = require('mongoose');

// _id is the unique invocation identity. No TTL: an uncertain SSH attempt
// remains counted until an operator/authoritative recovery proves quiescence.
const remoteAdmissionSchema = new mongoose.Schema({
    _id: { type: String, required: true },
    nodeId: { type: String, required: true },
    kind: { type: String, enum: ['standalone_preflight', 'install', 'sync_users'], required: true },
    phase: { type: String, enum: ['running', 'queued', 'recovery_required', 'completed'], required: true },
    operationId: { type: String },
    // Populated by counted queued claims; older running admissions stay valid.
    leaseOwner: { type: String },
    ownerGeneration: { type: Number, required: true, min: 1 },
}, { timestamps: true, strict: 'throw' });

// Scope uniqueness to new sync_users admissions: legacy install rows need no migration.
remoteAdmissionSchema.index({ operationId: 1 }, { unique: true,
    partialFilterExpression: { kind: 'sync_users', operationId: { $type: 'string' } } });

module.exports = mongoose.model('RemoteAdmission', remoteAdmissionSchema);
