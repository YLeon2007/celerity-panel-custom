'use strict';

const mongoose = require('mongoose');

const lifecycleIdentity = {
    operationId: { type: String, required: true,
        match: /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/ },
    action: { type: String, required: true, enum: ['link.apply', 'link.delete'] },
    linkId: { type: String, required: true, match: /^[a-f0-9]{24}$/i },
    epoch: { type: Number, required: true, min: 1 },
    nodeIds: { type: [String], required: true, default: undefined,
        validate: v => Array.isArray(v) && v.length === 2 && v[0] !== v[1]
            && v.every(id => /^[a-f0-9]{24}$/i.test(id)) },
    baselineLinkIds: { type: [String], required: true, default: undefined,
        validate: v => Array.isArray(v) && new Set(v).size === v.length
            && v.every(id => /^[a-f0-9]{24}$/i.test(id)) },
    topologyRevision: { type: Number, required: true, min: 0 },
    deployedRevision: { type: Number, required: true, min: 0 },
};
const lifecycleOptions = { _id: false, versionKey: false, strict: 'throw' };

const cascadeTopologyStateSchema = new mongoose.Schema({
    _id: {
        type: String,
        enum: ['singleton'],
        default: 'singleton',
    },
    revision: {
        type: Number,
        default: 0,
        min: 0,
    },
    // State-only transactions conflict with path writers without changing topology revision.
    stateTransitionRevision: { type: Number, default: 0, min: 0 },
    deployedRevision: {
        type: Number,
        default: 0,
        min: 0,
    },
    // Shared non-expiring draft/deployment fence. Legacy undeploy can acquire
    // it only while quiescent; topology replacement acquisition remains disabled.
    // Keep the epoch after release so an old owner token cannot be reused as authority.
    replacementEpoch: {
        type: Number,
        default: 0,
        min: 0,
    },
    // Never infer an absent counter as zero: legacy singleton needs an explicit
    // audited initialization before standalone remote admissions can begin.
    remoteAdmissionCount: { type: Number, min: 0 },
    // Explicitly audited initialization only. Missing legacy state is not zero.
    // Queue admission increments this on the same transaction as the operation.
    topologyAdmissionCount: { type: Number, min: 0 },
    // Non-expiring dispatch identity remains with the reservation on every
    // unknown remote/commit outcome. It is diagnostic evidence, not retry authority.
    classicLifecycleAttempt: { type: new mongoose.Schema({ ...lifecycleIdentity,
        phase: { type: String, required: true, enum: ['dispatching'] },
    }, lifecycleOptions), default: undefined },
    classicLifecycleLastSettlement: { type: new mongoose.Schema({ ...lifecycleIdentity,
        phase: { type: String, required: true, enum: ['succeeded'] },
        revision: { type: Number, required: true, min: 0 },
    }, lifecycleOptions), default: undefined },
    remoteDrain: {
        type: new mongoose.Schema({
            ownerToken: { type: String, required: true },
            epoch: { type: Number, required: true, min: 1 },
        }, { _id: false }),
        default: undefined,
    },
    replacementReservation: {
        type: new mongoose.Schema({
            ownerToken: { type: String, required: true },
            epoch: { type: Number, required: true, min: 1 },
        }, { _id: false }),
        default: undefined,
    },
}, { timestamps: true });

module.exports = mongoose.model('CascadeTopologyState', cascadeTopologyStateSchema);
