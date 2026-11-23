'use strict';

const { createHash, createHmac } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { mongo: { BSON }, Types } = require('mongoose');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');

const BLOCKED = 'REBUILD_L2TP_INSTALL_RECOVERY_BLOCKED';
const changed = () => Object.assign(new Error(BLOCKED), { code: BLOCKED });
const validActor = actor => typeof actor === 'string' && actor.length > 0 && actor.length <= 256
    && actor.trim() === actor && !/[\p{C}\u2028\u2029]/u.test(actor);
const hex = (s, size) => typeof s === 'string' && s.length === size && /^[a-f0-9]+$/.test(s);
const idEq = (value, id) => value instanceof Types.ObjectId && String(value) === id;
const digest = value => createHash('sha256').update(BSON.serialize(value)).digest('hex');
const sign = (key, value) => createHmac('sha256', key).update(BSON.serialize(value)).digest('hex');
const bsonTypes = { promoteValues: false };
const maxCopies = 241; // The stock first-install pool spans .10–.250.
const opts = session => ({ ...bsonTypes, timeoutMS: 5000, ...(session ? { session }
    : { readPreference: 'primary', readConcern: { level: 'majority' } }) });
// Version 2 authenticates every business field, but not advisory progress.
// Keep the original full BSON hash for historical v1 receipts.
const stateImage = (row, version) => version === 1 ? row
    : Object.fromEntries(Object.entries(row).filter(([key]) => key !== 'installProgress'));
const recoveryStateCas = (row, version) => version === 1 ? exact(row, 'node') : {
    _id: row._id, node: row.node,
    $expr: { $eq: [{ $arrayToObject: { $filter: { input: { $objectToArray: '$$ROOT' }, as: 'field',
        cond: { $ne: ['$$field.k', 'installProgress'] } } } }, { $literal: stateImage(row, version) }] },
};
const plain = row => BSON.deserialize(BSON.serialize(row));
const exact = (row, owner) => ({ _id: row._id, [owner]: row[owner],
    $expr: { $eq: ['$$ROOT', { $literal: row }] } });
const requireOne = (reply, count) => {
    if (reply?.acknowledged !== true || reply[count] !== 1) throw changed();
};

function checkState(state, nodeId, backupId, machineId) {
    if (!idEq(state?.node, nodeId) || !(state._id instanceof Types.ObjectId) || state.status !== 'installing'
        || state.desiredState !== 'installed' || state.rebuildMachineId !== machineId || state.backupId !== backupId
        || !hex(backupId, 32) || state.routingMode !== FOLLOW_RELAY_MODE || Number(state.routingVersion) !== FOLLOW_RELAY_VERSION
        || Number(state.secretRevision) !== 1 || typeof state.rebuildInstallToken !== 'string'
        || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}(?![\s\S])/.test(state.rebuildInstallToken)) throw changed();
}

function createRecoveryStore(State, User) {
    const states = State.collection, users = User.collection;
    const scoped = (collection, field, id, limit, session) => collection.find({ [field]: new Types.ObjectId(id) },
        { ...opts(session), sort: { _id: 1 }, limit }).toArray();
    async function snapshot(id, session) {
        const stateRows = await scoped(states, 'node', id, 2, session);
        if (stateRows.length > 1) throw changed();
        return stateRows[0] ?? null;
    }
    async function images(nodeId, backupId, machineId, session) {
        const state = await snapshot(nodeId, session);
        checkState(state, nodeId, backupId, machineId);
        const copies = await scoped(users, 'relayNode', nodeId, maxCopies + 1, session);
        if (!copies.length || copies.length > maxCopies || copies.some(row => !idEq(row.relayNode, nodeId)
            || !(row._id instanceof Types.ObjectId) || row.syncStatus !== 'pending' || Number(row.appliedRevision) !== 0)) throw changed();
        return { state, copies };
    }
    async function capture({ nodeId, backupId, machineId, actor, key, authority, prior, replicas, packagePreparation }, session) {
        const { state, copies } = await images(nodeId, backupId, machineId, session);
        const expected = new Map(replicas.map(row => [String(row._id), row]));
        if (copies.length !== replicas.length || copies.some(row => !equal(plain(row), expected.get(String(row._id))))) throw changed();
        const before = prior && BSON.serialize(prior);
        if (before && before.length > 64 * 1024) throw changed();
        if (packagePreparation !== undefined && !hex(packagePreparation, 64)) throw changed();
        const payload = { version: 2, nodeId, backupId, actor, prior: before ? new BSON.Binary(before) : null,
            packagePreparation: packagePreparation ?? null,
            stateHash: digest(stateImage(state, 2)), copiesHash: digest({ copies }) };
        // Bind the actor, grant/source, endpoint, pinned key, machine and DB
        // images to the current encryption key without persisting the key.
        return { ...payload, seal: sign(key, { ...payload, authority }) };
    }
    async function checked(receipt, authority, key, session) {
        const { version, nodeId, backupId, actor, prior, packagePreparation, stateHash, copiesHash, seal } = receipt;
        if (![1, 2].includes(version) || !(prior === null || (prior instanceof BSON.Binary && prior.length() <= 64 * 1024))
            || !hex(seal, 64) || !hex(stateHash, 64) || !hex(copiesHash, 64)
            || (packagePreparation !== null && !hex(packagePreparation, 64))
            || seal !== sign(key, { version, nodeId, backupId, actor, prior, packagePreparation, stateHash, copiesHash, authority })) throw changed();
        const { state, copies } = await images(nodeId, backupId, authority.binding.machineId, session);
        if (digest(stateImage(state, version)) !== stateHash || digest({ copies }) !== copiesHash) throw changed();
        const before = prior && BSON.deserialize(prior.value(), bsonTypes);
        if (before && (!idEq(before.node, nodeId) || !idEq(before._id, String(state._id))
            || before.status !== 'not_installed' || before.desiredState !== 'absent')) throw changed();
        return { state, copies, before, version };
    }
    async function restore({ state, copies, before, version }, session) {
        for (const row of copies) requireOne(await users.deleteMany(exact(row, 'relayNode'), { session }), 'deletedCount');
        if (before) {
            requireOne(await states.updateMany(recoveryStateCas(state, version), [{ $replaceWith: { $literal: before } }],
                { session }), 'matchedCount');
        } else {
            requireOne(await states.deleteMany(recoveryStateCas(state, version), { session }), 'deletedCount');
        }
    }
    return { snapshot, capture, checked, restore };
}

const grantIdentity = fence => ({ binding: { ...fence.binding }, source: fence.source ?? null,
    generation: fence.generation ?? null, listMode: fence.listMode });
module.exports = { BLOCKED, changed, createRecoveryStore, grantIdentity, plain, validActor };
