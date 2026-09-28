'use strict';

const mongoose = require('mongoose');

// _id is the unique invocation identity. No TTL: an uncertain SSH attempt
// remains counted until an operator/authoritative recovery proves quiescence.
const remoteAdmissionSchema = new mongoose.Schema({
    _id: { type: String, required: true },
    nodeId: { type: String, required: true },
    kind: { type: String, enum: ['standalone_preflight'], required: true },
    phase: { type: String, enum: ['running', 'recovery_required', 'completed'], required: true },
    ownerGeneration: { type: Number, required: true, min: 1 },
}, { timestamps: true, strict: 'throw' });

module.exports = mongoose.model('RemoteAdmission', remoteAdmissionSchema);
