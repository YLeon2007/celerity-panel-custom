'use strict';

const { randomUUID } = require('node:crypto');
const { Types } = require('mongoose');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');

const fail = code => Object.assign(new Error(code), { code });
const STATE_CHANGED = 'REBUILD_L2TP_RESERVATION_CHANGED';
const write = { writeConcern: { w: 'majority' }, timestamps: false, setDefaultsOnInsert: false };
const read = query => query.read('primary').readConcern('majority').lean();
// Each filter binds a unique _id. Use multi forms to opt out of the Mongo
// driver's automatic retryable-write replay, even on retryWrites clients.
const updateOnce = (model, filter, update, options = write) => model.updateMany(filter, update, options);
const deleteOnce = (model, filter) => model.deleteMany(filter, write);

const emptyFields = ['pskEncrypted', 'pskHint', 'backupId', 'managedVersion', 'configFingerprint', 'rebuildInstallToken',
    'rebuildMachineId', 'activePathKey', 'routeGroup', 'routingVersion', 'operationId', 'installedAt', 'lastVerifiedAt',
    'lastSyncAt', 'appliedTopologyRevision'];
const zeroFields = ['secretRevision', 'pppDriftQueueFence', 'replacementFence'];
function isPristine(row) {
    return row == null || (row.status === 'not_installed' && row.desiredState === 'absent'
        && [undefined, null, 'route-group'].includes(row.routingMode)
        && zeroFields.every(key => row[key] == null || row[key] === 0)
        && emptyFields.every(key => row[key] == null || row[key] === ''));
}
const matchField = (row, key) => !Object.hasOwn(row, key) ? { $exists: false }
    : row[key] === null ? { $eq: null, $exists: true } : row[key];
const exact = (row, keys = Object.keys(row)) => Object.fromEntries([...new Set(keys)].map(key => [key, matchField(row, key)]));
const requireOne = (result, field) => {
    if (result?.acknowledged !== true || result[field] !== 1) throw fail(STATE_CHANGED);
};

function createStore(State, User) {
    async function snapshot(nodeId) {
        const prior = await read(State.findOne({ node: nodeId }).select('+pskEncrypted +rebuildInstallToken +rebuildMachineId'));
        const pristine = isPristine(prior) && !(await read(User.findOne({ relayNode: nodeId }).select('_id')));
        return { prior, pristine };
    }
    const occupied = id => read(State.find({ node: { $ne: id }, status: { $ne: 'not_installed' } }).select('clientCidr'));

    async function reserve({ nodeId, prior, machineId, backupId, state, user }) {
        const now = new Date();
        const stateId = prior?._id ?? nodeId;
        const fields = {
            ...state, status: 'installing', desiredState: 'installed', backupId,
            routingMode: FOLLOW_RELAY_MODE, routingVersion: FOLLOW_RELAY_VERSION,
            rebuildInstallToken: randomUUID(), rebuildMachineId: machineId, updatedAt: now,
        };
        const key = { _id: stateId, node: nodeId };
        if (prior) {
            const before = exact(prior, [...Object.keys(fields), ...zeroFields, ...emptyFields]);
            requireOne(await updateOnce(State, { ...key, ...before }, { $set: fields }), 'matchedCount');
        } else {
            // Unique node index also excludes an independently created row with another _id.
            requireOne(await updateOnce(State, { ...key, rebuildInstallToken: fields.rebuildInstallToken },
                { $setOnInsert: { ...key, ...fields, createdAt: now } }, { ...write, upsert: true }), 'upsertedCount');
        }
        const fence = { ...key, ...exact(fields) };
        // Credentials are durable *before* dispatch; an SSH acknowledgement loss
        // cannot strand an installation with credentials only in process memory.
        const account = { _id: new Types.ObjectId(), relayNode: nodeId, ...user, appliedRevision: 0,
            syncStatus: 'pending', createdAt: now, updatedAt: now };
        requireOne(await updateOnce(User, { _id: account._id }, { $setOnInsert: account },
            { ...write, upsert: true }), 'upsertedCount');
        return { fence, fields, prior, account };
    }

    async function verifyReservation({ fence, account }) {
        const [state, user] = await Promise.all([
            read(State.findOne(fence).select('_id')), read(User.findOne(exact(account)).select('_id')),
        ]);
        if (!state || !user) throw fail(STATE_CHANGED);
    }

    async function finish({ fence, account }, verifyLock) {
        const now = new Date();
        requireOne(await updateOnce(User, exact(account), { $set: { appliedRevision: account.desiredRevision,
            syncStatus: 'synced', updatedAt: now, lastSyncedAt: now } }), 'matchedCount');
        await verifyLock();
        requireOne(await updateOnce(State, fence, { $set: { status: 'installed', installedAt: now, lastVerifiedAt: now,
            lastSyncAt: now, lastError: '', lastErrorCode: '', updatedAt: now } }), 'matchedCount');
    }

    async function restore({ fence, fields, prior, account }, verifyLock) {
        requireOne(await deleteOnce(User, exact(account)), 'deletedCount');
        await verifyLock();
        if (!prior) {
            requireOne(await deleteOnce(State, fence), 'deletedCount');
            return;
        }
        const set = {}, unset = {};
        for (const key of Object.keys(fields)) {
            if (Object.hasOwn(prior, key)) set[key] = prior[key];
            else unset[key] = '';
        }
        const update = { ...(Object.keys(set).length && { $set: set }), ...(Object.keys(unset).length && { $unset: unset }) };
        requireOne(await updateOnce(State, fence, update), 'matchedCount');
    }
    return { snapshot, occupied, reserve, verifyReservation, finish, restore };
}

module.exports = { createStore, read };
