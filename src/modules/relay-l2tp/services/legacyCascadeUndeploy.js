'use strict';

const { randomUUID } = require('node:crypto');
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
    const result = await work();
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

module.exports = { withLegacyCascadeUndeploy };
