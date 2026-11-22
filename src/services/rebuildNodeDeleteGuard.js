'use strict';

const { Types: { ObjectId } } = require('mongoose');
const { relayListKey, parseRelayBindingList } = require('./rebuildRelayAuthorization');
const { GRANTS, RETIRED, legacyBinding } = require('./rebuildRelayGrantStore');

const fail = code => Object.assign(new Error(code), { code });
const unavailable = () => fail('REBUILD_NODE_DELETE_UNAVAILABLE');
const readOptions = session => ({ maxTimeMS: 5000, ...(session ? { session }
    : { readPreference: 'primary', readConcern: { level: 'majority' } }) });

async function assertNoIncidentLinks(Link, id, session) {
    let link;
    try {
        const ids = [new ObjectId(id), String(id).toLowerCase()];
        link = await Link.collection.findOne({ $or: ['portalNode', 'bridgeNode', 'source', 'target', 'rebuildApplied.listener']
            .map(field => ({ [field]: { $in: ids } })) }, { ...readOptions(session), projection: { _id: 1 } });
    } catch { throw unavailable(); }
    // Never filter by active, status, or deletion intent. A persisted
    // tombstone still roots both of its endpoints until graph settlement.
    if (link !== null) throw fail('REBUILD_NODE_HAS_LINKS');
}

async function assertNoRelayEnrollment(Node, L2tpUser, id, env = process.env) {
    let managed;
    try {
        id = String(id).toLowerCase();
        const options = { ...readOptions(), projection: { _id: 1 } };
        const configured = Object.hasOwn(env, relayListKey)
            ? parseRelayBindingList(env[relayListKey], unavailable, { checkUniqueness: false }).some(row => row.nodeId === id)
            : legacyBinding(env)?.nodeId === id;
        // A restored card does not resurrect the retired ENV authorization.
        // This suppresses only ENV, not any current persisted grant or replica.
        const retired = configured ? await Node.db.collection(RETIRED).findOne({ _id: id }, options) : null;
        if (retired !== null && retired?._id !== id) throw unavailable();
        managed = (configured && retired === null)
            || await Node.db.collection(GRANTS).findOne({ nodeId: id }, options)
            || await L2tpUser.collection.findOne({ relayNode: { $in: [new ObjectId(id), id] } }, options);
    } catch { throw unavailable(); }
    if (managed) throw fail('REBUILD_NODE_RETIRE_REQUIRED');
}

module.exports = { assertNoIncidentLinks, assertNoRelayEnrollment };
