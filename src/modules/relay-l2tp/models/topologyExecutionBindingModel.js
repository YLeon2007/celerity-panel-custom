'use strict';
const mongoose = require('mongoose');
const { common, immutable, string, strict, UUID, ID, TOKEN, COMMANDS } = require('./topologyExecutionBindingContract');
const commandSchema = new mongoose.Schema(Object.fromEntries(COMMANDS.map(key => [key, string(UUID)])), strict);
const schema = new mongoose.Schema({ ...common(),
    enrollmentId: string(UUID), operationId: string(ID), candidateHash: string(/^sha256:[a-f0-9]{64}$/),
    backupId: string(TOKEN), owner: string(TOKEN), generation: string(UUID), attemptId: string(UUID),
    topologyRevision: { type: Number, required: true, immutable: true, min: 0, validate: Number.isSafeInteger },
    priorDeployedRevision: { type: Number, required: true, immutable: true, min: 0, validate: Number.isSafeInteger },
    attempt: { type: Number, required: true, immutable: true, min: 1, validate: Number.isSafeInteger },
    predecessorBindingId: { type: String, immutable: true, match: UUID },
    predecessorReceipt: { type: mongoose.Schema.Types.Mixed, immutable: true },
    commandIds: { type: commandSchema, required: true, immutable: true },
    commandTokens: { type: [String], required: true, immutable: true, default: undefined,
        validate: values => values.length === COMMANDS.length && new Set(values).size === COMMANDS.length && values.every(value => UUID.test(value)) },
}, { strict: 'throw', versionKey: false });
// One immutable child per predecessor: retries cannot fork the serial lineage.
// Enrollment remains the permanent global physical/key/endpoint reservation.
// A previously installed enrollmentId_1 unique index requires a separately
// authorized offline replacement; this dormant store never runs index-drop DDL.
schema.index({ operationId: 1, nodeId: 1, targetProfile: 1 }, { unique: true });
schema.index({ enrollmentId: 1, predecessorGeneration: 1 }, { unique: true });
schema.index({ enrollmentId: 1, generation: 1 }, { unique: true });
schema.index({ attemptId: 1 }, { unique: true });
schema.index({ commandTokens: 1 }, { unique: true });
immutable(schema);
module.exports = mongoose.model('TopologyExecutionBinding', schema);
