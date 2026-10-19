'use strict';

// Deliberately NOT an initializer. No application startup imports, writes, index
// builds, ownership markers, transaction commits, or authority callbacks exist.
const { createHash } = require('node:crypto');
const { mongo } = require('mongoose');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT } = require('../domain/topologyExecutionContext');
const HISTORY_COLLECTIONS = Object.freeze(['topologyoperations', 'topologycreateintents',
    'topologyintentqueuestates', 'l2tpoperations', 'nodeoperationlocks', 'remoteadmissions',
    'topologyexecutionbindings', 'topologyexecutionenrollments', 'cascaderoutegroups']);
const COLLECTIONS = Object.freeze(['cascadelinks', 'cascadetopologystates', ...HISTORY_COLLECTIONS]);
const READ_OPTIONS = Object.freeze({ readPreference: 'primary', readConcern: { level: 'majority' },
    maxTimeMS: 2000, timeoutMS: 2000 });

// Reviewed against source schemas, not dynamically loaded models: importing an
// application model on an open default connection could auto-create indexes.
const EXPECTED_INDEXES = {
    cascadelinks: [[{ portalNode: 1 }], [{ bridgeNode: 1 }], [{ active: 1, status: 1 }]],
    cascadetopologystates: [],
    topologyoperations: [[{ status: 1, clientReadiness: 1, clientProofRetryAfter: 1, clientProofLeaseUntil: 1 },
        { partialFilterExpression: { status: 'succeeded', clientReadiness: 'unverified', clientProofAttempts: { $lt: 3 } } }]],
    topologycreateintents: [[{ requestKey: 1 }, { unique: true }], [{ ordinal: 1 }, { unique: true }],
        [{ operationId: 1 }, { unique: true, sparse: true }], [{ status: 1, ordinal: 1 }]],
    topologyintentqueuestates: [],
    l2tpoperations: [[{ idempotencyKey: 1 }, { unique: true }]],
    nodeoperationlocks: [[{ node: 1 }, { unique: true }]],
    remoteadmissions: [[{ operationId: 1 }, { unique: true,
        partialFilterExpression: { kind: 'sync_users', operationId: { $type: 'string' } } }]],
    topologyexecutionbindings: [[{ operationId: 1, nodeId: 1, targetProfile: 1 }, { unique: true }],
        [{ enrollmentId: 1 }, { unique: true }], [{ attemptId: 1 }, { unique: true }],
        [{ commandTokens: 1 }, { unique: true }]],
    topologyexecutionenrollments: [[{ nodeId: 1, targetProfile: 1 }, { unique: true }],
        [{ 'nodeIdentity.machineId': 1, targetProfile: 1 }, { unique: true }],
        [{ 'nodeIdentity.sshHostKeySha256': 1, targetProfile: 1 }, { unique: true }],
        [{ 'nodeIdentity.machineId': 1 }, { unique: true }],
        [{ 'nodeIdentity.sshHostKeySha256': 1 }, { unique: true }],
        [{ 'endpoint.ip': 1, 'endpoint.port': 1 }, { unique: true }]],
    cascaderoutegroups: [],
};
function indexStatus(collection, actual) {
    const expected = [[{ _id: 1 }], ...EXPECTED_INDEXES[collection]].map(([key, options = {}]) => ({
        key, name: Object.keys(key).join() === '_id' ? '_id_'
            : Object.entries(key).map(([field, direction]) => `${field}_${direction}`).join('_'), ...options,
    }));
    let missing = false;
    for (const wanted of expected) {
        const index = actual.find(item => item.name === wanted.name);
        if (!index) { missing = true; continue; }
        if (Object.keys(index).some(key => !['v', 'key', 'name', 'unique', 'sparse',
            'partialFilterExpression', 'background'].includes(key))
            || JSON.stringify(Object.entries(index.key)) !== JSON.stringify(Object.entries(wanted.key))
            || Boolean(index.unique) !== Boolean(wanted.unique)
            || Boolean(index.sparse) !== Boolean(wanted.sparse)
            || JSON.stringify(canonical(index.partialFilterExpression))
                !== JSON.stringify(canonical(wanted.partialFilterExpression))) return 'conflict';
    }
    if (actual.some(index => !expected.some(wanted => wanted.name === index.name))) return 'conflict';
    return missing ? 'missing' : 'exact-ready';
}

function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object') return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, canonical(value[key])]));
    return value;
}
function rawDocumentFingerprint(document) {
    return createHash('sha256').update(JSON.stringify(canonical(
        mongo.BSON.EJSON.serialize(document, { relaxed: false })))).digest('hex');
}

async function readObservation(db) {
    const blockers = [];
    const metadata = await db.listCollections({ name: { $in: COLLECTIONS } },
        { readPreference: 'primary', maxTimeMS: 2000, timeoutMS: 2000 }).toArray();
    metadata.sort((a, b) => a.name.localeCompare(b.name));
    const observed = {}, indexes = {}, indexEvidence = {};
    for (const name of COLLECTIONS) {
        const entry = metadata.find(item => item.name === name);
        if (!entry) {
            observed[name] = null;
            blockers.push(`COLLECTION_MISSING:${name}`);
        } else if (entry.type !== 'collection' || Object.keys(entry.options || {}).length) {
            observed[name] = undefined;
            blockers.push(`COLLECTION_OPTIONS_UNRESOLVED:${name}`);
        } else {
            observed[name] = await db.collection(name).find({}, READ_OPTIONS)
                .sort({ _id: 1 }).limit(name === 'cascadelinks' ? 11 : 1).toArray();
            indexEvidence[name] = await db.collection(name).listIndexes(
                { readPreference: 'primary', maxTimeMS: 2000, timeoutMS: 2000 }).toArray();
            indexEvidence[name].sort((a, b) => a.name.localeCompare(b.name));
            indexes[name] = indexStatus(name, indexEvidence[name]);
            if (indexes[name] !== 'exact-ready') blockers.push(`INDEX_${indexes[name].toUpperCase()}:${name}`);
        }
        indexes[name] ||= 'unresolved';
    }
    return { observed, indexes, blockers,
        fingerprint: rawDocumentFingerprint({ metadata, observed, indexEvidence }) };
}

async function inspectProductionAdmissionInitialization({ db, serverContext,
    expectedDatabaseName, acceptedClassicLinks } = {}) {
    if (serverContext !== PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT
        || typeof expectedDatabaseName !== 'string' || !expectedDatabaseName
        || db?.databaseName !== expectedDatabaseName
        || !Array.isArray(acceptedClassicLinks) || acceptedClassicLinks.length !== 10
        || acceptedClassicLinks.some(pin => !pin || Object.keys(pin).sort().join(',') !== 'id,sha256'
            || typeof pin.id !== 'string' || !/^[a-f0-9]{24}$/.test(pin.id)
            || typeof pin.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(pin.sha256))
        || new Set(acceptedClassicLinks.map(pin => pin.id)).size !== 10) {
        throw Object.assign(new Error('PRODUCTION_INITIALIZATION_INPUT_REFUSED'),
            { code: 'PRODUCTION_INITIALIZATION_INPUT_REFUSED' });
    }
    // Copy accepted inputs before the first await; no later environment reread.
    acceptedClassicLinks = acceptedClassicLinks.map(pin => ({ ...pin }));
    let initial, confirmation;
    try {
        initial = await readObservation(db);
        confirmation = await readObservation(db);
    } catch {
        // No raw Mongo errors/causes: they can contain credential-bearing data.
        throw Object.assign(new Error('PRODUCTION_INITIALIZATION_OBSERVATION_UNCONFIRMED'),
            { code: 'PRODUCTION_INITIALIZATION_OBSERVATION_UNCONFIRMED' });
    }
    const { observed, indexes } = confirmation;
    const observationStable = initial.fingerprint === confirmation.fingerprint;
    const blockers = ['EXTERNAL_MAINTENANCE_AUTHORITY_UNAVAILABLE',
        'PRODUCTION_ACCEPTED_PIN_AUTHORITY_UNAVAILABLE', ...initial.blockers, ...confirmation.blockers];
    if (!observationStable) blockers.push('OBSERVATION_DRIFT');
    const links = observed.cascadelinks || [];
    const states = observed.cascadetopologystates;
    const history = Object.fromEntries(HISTORY_COLLECTIONS.map(name => [name,
        observed[name] === null ? 'missing' : observed[name] === undefined ? 'unresolved'
            : observed[name].length ? 'present' : 'empty-observed']));
    for (const name of HISTORY_COLLECTIONS) {
        if (history[name] === 'present') blockers.push(`HISTORY_REQUIRES_REVIEW:${name}`);
    }
    if (states?.length) blockers.push('EXISTING_SINGLETON_REQUIRES_SEPARATE_REVIEW');
    const matchesAcceptedPins = links.length === 10 && acceptedClassicLinks.length === 10
        && links.filter(row => row.mode === 'reverse').length === 8
        && links.filter(row => row.mode === 'forward').length === 2
        && links.every(row => row._id instanceof mongo.ObjectId
            && row.portalNode instanceof mongo.ObjectId && row.bridgeNode instanceof mongo.ObjectId
            && row.active === true && ['deployed', 'online'].includes(row.status)
            && acceptedClassicLinks.some(pin => pin.id === String(row._id)
                && pin.sha256 === rawDocumentFingerprint(row)));
    return {
        mode: 'preflight-only', ready: false, initialized: false,
        singleton: { presence: states === null ? 'collection-missing' : states === undefined ? 'unresolved'
            : states.length ? 'present' : 'missing' },
        history, indexes, observationStable,
        zeroWorkObserved: observationStable && Object.values(history).every(value => value === 'empty-observed'),
        inventory: { matchesAcceptedPins, reverse: links.filter(row => row.mode === 'reverse').length,
            forward: links.filter(row => row.mode === 'forward').length },
        blockers: [...new Set([...blockers,
            ...(!matchesAcceptedPins ? ['CLASSIC_LINK_INVENTORY_UNRESOLVED'] : [])])],
    };
}

module.exports = { inspectProductionAdmissionInitialization, rawDocumentFingerprint };
