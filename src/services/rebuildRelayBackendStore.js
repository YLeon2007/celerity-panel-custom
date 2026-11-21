'use strict';

const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { Types } = require('mongoose');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');
const { transactOnce } = require('./rebuildRelayInstallTransaction');
const { readDirectory, checkDirectory, writeDirectory, logicalAccount } = require('./rebuildRelayDirectory');

const fail = code => Object.assign(new Error(code), { code });
const STATE_CHANGED = 'REBUILD_L2TP_RESERVATION_CHANGED';
const write = { timestamps: false, setDefaultsOnInsert: false };
const writeIn = session => session ? { ...write, session } : { ...write, writeConcern: { w: 'majority' } };
const read = (query, session) => session ? query.session(session).lean() : query.read('primary').readConcern('majority').lean();
// Each write binds a unique _id. Use multi forms so singleton writes also opt
// out of the Mongo driver's automatic retryable-write replay.
const updateOnce = (model, filter, update, options) => model.updateMany(filter, update, options);
const deleteOnce = (model, filter, options) => model.deleteMany(filter, options);

const privateStateFields = '+pskEncrypted +rebuildInstallToken +rebuildMachineId';
const accountKeys = ['_id', 'relayNode', 'login', 'ip', 'passwordEncrypted', 'enabled', 'desiredRevision', 'appliedRevision',
    'syncStatus', 'syncOperationId', 'lastSyncedAt', 'createdAt', 'updatedAt', 'createdBy', 'updatedBy', 'comment',
    'lastError', 'lastErrorCode'];
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
const byId = (a, b) => String(a._id).localeCompare(String(b._id));

function createStore(State, User, listMode) {
    async function snapshot(nodeId) {
        const prior = await read(State.findOne({ node: nodeId }).select(privateStateFields));
        const pristine = isPristine(prior) && !(await read(User.findOne({ relayNode: nodeId }).select('_id')));
        return { prior, pristine };
    }
    async function sourceRows(id, session) {
        const states = await read(State.find(id == null ? {} : { node: { $ne: id } }).select(privateStateFields), session);
        const users = await read(User.find({}).select('+passwordEncrypted'), session);
        return { states: states.sort(byId), users: users.sort(byId), directory: await readDirectory(User.db, session) };
    }

    // List enrollment joins state and accounts even for the first relay, with
    // no source and only one login. Only legacy no-list supports standalone.
    const mutate = work => listMode ? transactOnce(State, User, work) : work();

    async function reserve({ nodeId, prior, machineId, backupId, state, accounts, sourceSnapshot, inherited }, verifyLock) {
        if (!Array.isArray(accounts) || accounts.length === 0 || (!listMode && accounts.length !== 1)) throw fail(STATE_CHANGED);
        const now = new Date();
        const stateId = prior?._id ?? nodeId;
        const fields = {
            ...state, status: 'installing', desiredState: 'installed', backupId,
            routingMode: FOLLOW_RELAY_MODE, routingVersion: FOLLOW_RELAY_VERSION,
            rebuildInstallToken: randomUUID(), rebuildMachineId: machineId, updatedAt: now,
        };
        const key = { _id: stateId, node: nodeId };
        const fence = { ...key, ...exact({ ...prior, ...fields }, [...Object.keys(fields), ...zeroFields, ...emptyFields]) };
        const replicas = accounts.map(account => ({ _id: new Types.ObjectId(), relayNode: new Types.ObjectId(nodeId),
            ...account, appliedRevision: 0, syncStatus: 'pending', createdAt: now, updatedAt: now }));
        const reservation = { nodeId, fence, fields, prior, replicas, directory: sourceSnapshot.directory, inherited };
        return mutate(async session => {
            // Prepare can take time. Recheck the source and absence of target
            // accounts before making any row durable.
            if (!equal(await sourceRows(nodeId, session), sourceSnapshot)) throw fail(STATE_CHANGED);
            await verifyLock();
            const options = writeIn(session);
            if (prior) {
                const before = exact(prior, [...Object.keys(fields), ...zeroFields, ...emptyFields]);
                requireOne(await updateOnce(State, { ...key, ...before }, { $set: fields }, options), 'matchedCount');
            } else {
                // The unique node index excludes any independently created row.
                requireOne(await updateOnce(State, { ...key, rebuildInstallToken: fields.rebuildInstallToken },
                    { $setOnInsert: { ...key, ...fields, createdAt: now } }, { ...options, upsert: true }), 'upsertedCount');
            }
            // Credentials are durable *before* dispatch, as one complete set.
            for (const row of replicas) {
                requireOne(await updateOnce(User, { _id: row._id }, { $setOnInsert: row },
                    { ...options, upsert: true }), 'upsertedCount');
            }
            await verifyLock();
            return reservation;
        });
    }

    async function verifyReservation({ nodeId, fence, replicas, directory }, session) {
        await checkDirectory(User.db, directory, session);
        if (!(await read(State.findOne(fence).select('_id'), session))) throw fail(STATE_CHANGED);
        const rows = await read(User.find({ relayNode: nodeId }).select('+passwordEncrypted').limit(replicas.length + 1), session);
        const byRowId = new Map(rows.map(row => [String(row._id), row]));
        if (rows.length !== replicas.length || replicas.some(row => {
            const current = byRowId.get(String(row._id));
            return !current || !equal(exact(row, accountKeys), exact(current, accountKeys));
        })) throw fail(STATE_CHANGED);
    }

    function finish(reservation, verifyLock) {
        return mutate(async session => {
            await verifyReservation(reservation, session);
            await verifyLock();
            const now = new Date(), options = writeIn(session);
            for (const row of reservation.replicas) {
                requireOne(await updateOnce(User, exact(row, accountKeys), { $set: { appliedRevision: row.desiredRevision,
                    syncStatus: 'synced', updatedAt: now, lastSyncedAt: now } }, options), 'matchedCount');
            }
            if (listMode && !reservation.directory) {
                await writeDirectory(User.db, null, reservation.inherited ?? reservation.replicas.map(logicalAccount), session);
            }
            await verifyLock();
            requireOne(await updateOnce(State, reservation.fence, { $set: { status: 'installed', installedAt: now,
                lastVerifiedAt: now, lastSyncAt: now, lastError: '', lastErrorCode: '', updatedAt: now } }, options), 'matchedCount');
            if (session) await verifyLock();
        });
    }

    function restore(reservation, verifyLock) {
        const { fence, fields, prior, replicas } = reservation;
        return mutate(async session => {
            await verifyReservation(reservation, session);
            await verifyLock();
            const options = writeIn(session);
            for (const row of replicas) requireOne(await deleteOnce(User, exact(row, accountKeys), options), 'deletedCount');
            await verifyLock();
            if (!prior) {
                requireOne(await deleteOnce(State, fence, options), 'deletedCount');
            } else {
                const set = {}, unset = {};
                for (const key of Object.keys(fields)) {
                    if (Object.hasOwn(prior, key)) set[key] = prior[key];
                    else unset[key] = '';
                }
                const update = { ...(Object.keys(set).length && { $set: set }), ...(Object.keys(unset).length && { $unset: unset }) };
                requireOne(await updateOnce(State, fence, update, options), 'matchedCount');
            }
            if (session) await verifyLock();
        });
    }
    return { snapshot, sourceRows, reserve, verifyReservation, finish, restore };
}

module.exports = { createStore, read };
