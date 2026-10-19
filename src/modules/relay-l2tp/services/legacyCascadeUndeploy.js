'use strict';

const { randomUUID } = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const completionScope = new AsyncLocalStorage();

function uncertain() {
    return Object.assign(new Error('Legacy undeploy remote completion is unproved; ownership retained for operator recovery'), {
        code: 'LEGACY_CASCADE_UNDEPLOY_UNCERTAIN',
    });
}

// The HTTP callback discards its return value and MCP returns a link document.
// Track actual service completion in this async scope, not callback truthiness.
// Any failed/pending invocation poisons the scope, even if its caller catches it
// or later runs a successful teardown. Only checked service paths may use this.
async function trackLegacyCascadeUndeploy(work) {
    const scope = completionScope.getStore();
    if (scope?.closed) throw uncertain();
    if (scope) scope.started++;
    try {
        const result = await work();
        if (result?.success !== true || result?.remoteQuiescent !== true) throw uncertain();
        if (scope) scope.completed++;
        return result;
    } catch (error) {
        if (scope) scope.failed = true;
        throw error;
    }
}
const CascadeTopologyState = require('../models/cascadeTopologyStateModel');
const TopologyOperation = require('../models/topologyOperationModel');
const TopologyCreateIntent = require('../models/topologyCreateIntentModel');
const TopologyIntentQueueState = require('../models/topologyIntentQueueStateModel');
const NodeOperationLock = require('../models/nodeOperationLockModel');

function busy() {
    return Object.assign(new Error('Legacy undeploy requires an initialized, quiescent topology; finish or recover queued work first'), {
        code: 'LEGACY_CASCADE_UNDEPLOY_BUSY',
    });
}

// Non-expiring ownership of the existing draft/deployment/remote reservation
// fence. Never run external work in a retryable Mongo transaction callback.
async function withLegacyCascadeUndeploy(work) {
    const connection = CascadeTopologyState.db;
    if (typeof work !== 'function' || typeof connection?.transaction !== 'function'
        || [TopologyOperation, TopologyCreateIntent, TopologyIntentQueueState, NodeOperationLock]
            .some(model => model.db !== connection)) throw busy();
    const ownerToken = `legacy-undeploy:${randomUUID()}`;
    const claimed = await connection.transaction(async session => {
        const state = await CascadeTopologyState.findById('singleton').session(session).lean();
        if (!state || !Number.isSafeInteger(state.revision) || state.revision < 0
            || state.revision >= Number.MAX_SAFE_INTEGER
            || !Number.isSafeInteger(state.deployedRevision) || state.deployedRevision < 0
            || !Number.isSafeInteger(state.replacementEpoch) || state.replacementEpoch < 0
            || state.replacementEpoch >= Number.MAX_SAFE_INTEGER
            || state.topologyAdmissionCount !== 0 || state.remoteAdmissionCount !== 0
            || state.replacementReservation !== undefined || state.remoteDrain !== undefined) throw busy();
        // Also reject orphaned/legacy workers and queue bindings whose counter
        // cannot prove quiescence. Preserve every operation and intent record.
        if (await TopologyOperation.exists({ $or: [
            { status: { $nin: ['succeeded', 'failed', 'rolled_back'] } },
            { heldTopologyAdmission: true },
        ] }).session(session)
            || await TopologyCreateIntent.exists({ status: { $nin: ['succeeded', 'failed'] } }).session(session)
            || await TopologyIntentQueueState.exists({ outstanding: { $ne: 0 } }).session(session)
            || await NodeOperationLock.exists({}).session(session)) throw busy();
        const epoch = state.replacementEpoch + 1;
        const result = await CascadeTopologyState.findOneAndUpdate({
            _id: 'singleton', revision: state.revision, deployedRevision: state.deployedRevision,
            replacementEpoch: state.replacementEpoch, topologyAdmissionCount: 0, remoteAdmissionCount: 0,
            replacementReservation: { $exists: false }, remoteDrain: { $exists: false },
        }, {
            $set: { replacementReservation: { ownerToken, epoch }, deployedRevision: 0 },
            $inc: { revision: 1, replacementEpoch: 1 },
        }, { session, new: true, runValidators: true, upsert: false }).lean();
        if (!result) throw busy();
        return { revision: result.revision, epoch };
    }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });

    // Throw/unknown acquisition means zero external calls. A throw/crash after
    // acquisition retains the reservation for explicit operator recovery.
    const scope = { started: 0, completed: 0, failed: false, closed: false };
    let result;
    try { result = await completionScope.run(scope, work); } finally { scope.closed = true; }
    if (scope.failed || scope.started === 0 || scope.completed !== scope.started) throw uncertain();
    const released = await CascadeTopologyState.findOneAndUpdate({
        _id: 'singleton', revision: claimed.revision, deployedRevision: 0,
        topologyAdmissionCount: 0, remoteAdmissionCount: 0, replacementEpoch: claimed.epoch,
        'replacementReservation.ownerToken': ownerToken, 'replacementReservation.epoch': claimed.epoch,
    }, { $unset: { replacementReservation: '' } }, { new: true, upsert: false }).lean();
    if (!released) throw Object.assign(new Error('Legacy undeploy ownership could not be released; operator recovery required'), {
        code: 'LEGACY_CASCADE_UNDEPLOY_FENCE_LOST',
    });
    return result;
}

module.exports = { withLegacyCascadeUndeploy, trackLegacyCascadeUndeploy };
