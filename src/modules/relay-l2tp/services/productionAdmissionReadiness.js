'use strict';
// Read-only verification of the existing initializer's independently accepted
// first-activation baseline. NOT an initializer, authority or startup bypass.
// The operational caller must already possess the SAME held maintenance scope.
const { mongo } = require('mongoose');
const { isDeepStrictEqual: equal } = require('node:util');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const { REVIEWED_MANIFEST, REVIEWED_MANIFEST_SHA256 } = require('./productionAdmissionInitializer');
const { rawDocumentFingerprint: fingerprint } = require('./productionAdmissionInitializationPreflight');
const OPTIONS = Object.freeze({ readPreference: 'primary', maxTimeMS: 2000, timeoutMS: 2000 });
const READ = Object.freeze({ ...OPTIONS, readConcern: { level: 'majority' } });
const STATE_KEYS = ['_id', 'revision', 'deployedRevision', 'stateTransitionRevision',
    'replacementEpoch', 'remoteAdmissionCount', 'topologyAdmissionCount'];
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
function fail(code) { throw Object.assign(new Error(code), { code }); }
function exact(value, keys) {
    return value && typeof value === 'object' && !Array.isArray(value)
        && equal(Object.keys(value).sort(), [...keys].sort());
}
function validAccepted(value, db) {
    const required = ['serverContext', 'databaseName', 'maintenanceGeneration', 'deployment', 'acceptedClassicLinks',
        'initialState', 'manifestSha256', 'acceptedMissingCollections'];
    const optional = Object.hasOwn(value || {}, 'acceptedOfflineClassicLinkIds') ? ['acceptedOfflineClassicLinkIds'] : [];
    return exact(value, [...required, ...optional]) && equal(value.serverContext, PROD)
        && typeof value.databaseName === 'string' && value.databaseName.length > 0
        && db?.databaseName === value.databaseName && typeof db.client?.startSession === 'function'
        && typeof value.maintenanceGeneration === 'string' && UUID.test(value.maintenanceGeneration)
        && exact(value.deployment, ['setName', 'replicaSetId'])
        && typeof value.deployment.setName === 'string' && value.deployment.setName.length > 0
        && typeof value.deployment.replicaSetId === 'string' && /^[a-f0-9]{24}$/.test(value.deployment.replicaSetId)
        && value.manifestSha256 === REVIEWED_MANIFEST_SHA256
        && exact(value.initialState, STATE_KEYS) && value.initialState._id === 'singleton'
        && STATE_KEYS.slice(1).every(key => Number.isSafeInteger(value.initialState[key]) && value.initialState[key] >= 0)
        && value.initialState.revision === value.initialState.deployedRevision
        && value.initialState.remoteAdmissionCount === 0 && value.initialState.topologyAdmissionCount === 0
        && Array.isArray(value.acceptedClassicLinks) && value.acceptedClassicLinks.length === 10
        && value.acceptedClassicLinks.every(pin => exact(pin, ['id', 'sha256'])
            && typeof pin.id === 'string' && /^[a-f0-9]{24}$/.test(pin.id)
            && typeof pin.sha256 === 'string' && /^[a-f0-9]{64}$/.test(pin.sha256))
        && new Set(value.acceptedClassicLinks.map(pin => pin.id)).size === 10
        && Array.isArray(value.acceptedMissingCollections)
        && new Set(value.acceptedMissingCollections.map(entry => entry?.name)).size === value.acceptedMissingCollections.length
        && value.acceptedMissingCollections.every(entry => exact(entry, ['name', 'options']) && exact(entry.options, [])
            && entry.name !== 'cascadelinks' && REVIEWED_MANIFEST.collections.some(row => row.name === entry.name))
        && (!optional.length || (Array.isArray(value.acceptedOfflineClassicLinkIds)
            && new Set(value.acceptedOfflineClassicLinkIds).size === value.acceptedOfflineClassicLinkIds.length
            && value.acceptedOfflineClassicLinkIds.every(id => value.acceptedClassicLinks.some(pin => pin.id === id))));
}
function indexesMatch(actual, expected) {
    return actual.length === expected.length && actual.every(index => {
        const wanted = expected.find(value => value.name === index.name);
        return wanted && !Object.hasOwn(index, 'buildUUID')
            && Object.keys(index).every(key => ['v', 'name', 'key', 'unique', 'sparse', 'partialFilterExpression', 'background'].includes(key))
            && equal(Object.entries(index.key), Object.entries(wanted.key))
            && Boolean(index.unique) === Boolean(wanted.unique) && Boolean(index.sparse) === Boolean(wanted.sparse)
            && equal(index.partialFilterExpression ?? null, wanted.partialFilterExpression ?? null);
    }) && new Set(actual.map(index => index.name)).size === expected.length;
}
function validStartupAccepted(value, db) {
    return exact(value, ['serverContext', 'databaseName', 'maintenanceGeneration', 'deployment', 'manifestSha256'])
        && equal(value.serverContext, PROD) && db?.databaseName === value.databaseName
        && typeof value.databaseName === 'string' && value.databaseName.length > 0
        && typeof db.client?.startSession === 'function' && UUID.test(value.maintenanceGeneration)
        && exact(value.deployment, ['setName', 'replicaSetId']) && typeof value.deployment.setName === 'string'
        && value.deployment.setName.length > 0 && /^[a-f0-9]{24}$/.test(value.deployment.replicaSetId)
        && value.manifestSha256 === REVIEWED_MANIFEST_SHA256;
}
async function verifyAdmission({ db, accepted: input, scope } = {}, startup = false) {
    // No model import/init/createIndexes, receipts, repair, counter initialization,
    // history retirement, DDL, transaction, startup, SSH or execution is performed.
    const accepted = structuredClone(input);
    if (!(startup ? validStartupAccepted(accepted, db) : validAccepted(accepted, db))) fail('PRODUCTION_ADMISSION_INPUT_REFUSED');
    let stateSha256;
    if (typeof scope?.assertHeld !== 'function') fail('PRODUCTION_ADMISSION_SCOPE_REQUIRED');
    let open = true;
    const check = async () => {
        try {
            if (!open || await scope.assertHeld(accepted) !== undefined || !open) throw new Error();
        } catch { fail('PRODUCTION_ADMISSION_SCOPE_LOST'); }
    };
    const guarded = async work => { await check(); const value = await work(); await check(); return value; };
    const deployment = async () => {
        const { config } = await guarded(() => db.client.db('admin').command({ replSetGetConfig: 1 }, OPTIONS));
        const hello = await guarded(() => db.client.db('admin').command({ hello: 1 }, OPTIONS));
        if (config?._id !== accepted.deployment.setName
            || String(config?.settings?.replicaSetId) !== accepted.deployment.replicaSetId
            || hello.setName !== accepted.deployment.setName || hello.isWritablePrimary !== true) {
            fail('PRODUCTION_ADMISSION_DEPLOYMENT_MISMATCH');
        }
    };
    async function readIndexes(entry) {
        // The reviewed manifest has bounded small index sets. Refuse a nonzero
        // cursor rather than treating an incomplete/foreign inventory as ready.
        // Raw includeBuildUUIDs is required: collection.listIndexes hides builds.
        let session, cursorId = mongo.Long.ZERO;
        try {
            await check(); session = db.client.startSession({ causalConsistency: false });
            const reply = await guarded(() => db.command({ listIndexes: entry.name, includeBuildUUIDs: true,
                cursor: { batchSize: entry.indexes.length + 1 }, maxTimeMS: 2000 }, { ...OPTIONS, session, promoteLongs: false }));
            const cursor = reply?.cursor;
            if (cursor?.id instanceof mongo.Long) cursorId = cursor.id;
            if (reply?.ok !== 1 || reply.writeConcernError || reply.writeErrors?.length || reply.errorLabels?.length
                || !cursor || !(cursor.id instanceof mongo.Long) || cursor.ns !== `${accepted.databaseName}.${entry.name}`
                || !Array.isArray(cursor.firstBatch) || !cursor.id.isZero()
                || !indexesMatch(cursor.firstBatch, entry.indexes)) fail('PRODUCTION_ADMISSION_INDEX_MISMATCH');
        } finally {
            try {
                if (!cursorId.isZero()) {
                    const reply = await guarded(() => db.command({ killCursors: entry.name, cursors: [cursorId] }, { ...OPTIONS, session }));
                    const ids = [...(reply?.cursorsKilled || []), ...(reply?.cursorsNotFound || [])];
                    if (reply?.ok !== 1 || reply.writeConcernError || reply.writeErrors?.length || reply.errorLabels?.length
                        || !Array.isArray(reply.cursorsKilled) || !Array.isArray(reply.cursorsNotFound)
                        || !Array.isArray(reply.cursorsAlive) || reply.cursorsAlive.length
                        || !Array.isArray(reply.cursorsUnknown) || reply.cursorsUnknown.length
                        || ids.length !== 1 || !(ids[0] instanceof mongo.Long) || !ids[0].equals(cursorId)) {
                        fail('PRODUCTION_ADMISSION_OBSERVATION_UNCONFIRMED');
                    }
                }
            } finally {
                // Local session disposal is joined even after scope revocation.
                if (session) { await session.endSession(); await check(); }
            }
        }
    }
    async function observe() {
        const names = REVIEWED_MANIFEST.collections.map(entry => entry.name);
        const rows = await guarded(() => db.listCollections({ name: { $in: names } }, OPTIONS).toArray());
        if (rows.length !== names.length || rows.some(row => !names.includes(row.name) || row.type !== 'collection'
            || Object.keys(row.options || {}).length || !(row.info?.uuid instanceof mongo.Binary)
            || row.info.uuid.sub_type !== 4 || row.info.uuid.length() !== 16)
            || new Set(rows.map(row => row.name)).size !== names.length) fail('PRODUCTION_ADMISSION_CATALOG_MISMATCH');
        for (const entry of REVIEWED_MANIFEST.collections) await readIndexes(entry);
        const states = await guarded(() => db.collection('cascadetopologystates').find({}, READ).limit(2).toArray());
        if (states.length !== 1 || (startup
            ? states[0]._id !== 'singleton' || STATE_KEYS.slice(1).some(key => !Number.isSafeInteger(states[0][key]) || states[0][key] < 0)
            : fingerprint(states[0]) !== fingerprint(accepted.initialState))) {
            fail('PRODUCTION_ADMISSION_STATE_MISMATCH');
        }
        stateSha256 = fingerprint(states[0]);
        // Ordinary restart is NOT the first-install inventory. Preserve current
        // counters, history, locks, reservations and successful settled pointers;
        // their existing consumers/CAS guards decide admission and recovery.
        if (startup) return fingerprint({ catalog: rows.map(row => ({ name: row.name, uuid: row.info.uuid }))
            .sort((a, b) => a.name.localeCompare(b.name)), states });
        const links = await guarded(() => db.collection('cascadelinks').find({}, READ).sort({ _id: 1 }).limit(11).toArray());
        if (links.length !== 10 || links.filter(row => row.mode === 'reverse').length !== 8
            || links.filter(row => row.mode === 'forward').length !== 2
            || links.some(row => !(row._id instanceof mongo.ObjectId) || !(row.portalNode instanceof mongo.ObjectId)
                || !(row.bridgeNode instanceof mongo.ObjectId) || row.active !== true
                || !(['online', 'deployed'].includes(row.status)
                    || (row.status === 'offline' && accepted.acceptedOfflineClassicLinkIds?.includes(String(row._id))))
                || !accepted.acceptedClassicLinks.some(pin => pin.id === String(row._id) && pin.sha256 === fingerprint(row)))) {
            fail('PRODUCTION_ADMISSION_PIN_MISMATCH');
        }
        return fingerprint({ catalog: rows.map(row => ({ name: row.name, uuid: row.info.uuid }))
            .sort((a, b) => a.name.localeCompare(b.name)), links, states });
    }
    try {
        await check(); await deployment();
        const initial = await observe();
        await deployment();
        if (initial !== await observe()) fail('PRODUCTION_ADMISSION_OBSERVATION_DRIFT');
        await check();
        // Schema observation is not owner-generation enrollment, remote exclusion,
        // original-byte provenance, runtime readiness or activation permission.
        return Object.freeze({ schemaVerified: true, initialized: false, executionEnabled: false,
            stateSha256, manifestSha256: accepted.manifestSha256 });
    } catch (error) {
        if (typeof error?.code === 'string' && /^PRODUCTION_ADMISSION_[A-Z_]+$/.test(error.code)) fail(error.code);
        fail('PRODUCTION_ADMISSION_OBSERVATION_UNCONFIRMED');
    } finally { open = false; }
}
module.exports = {
    verifyInitializedProductionAdmission: options => verifyAdmission(options, false),
    verifyProductionStartupSchema: options => verifyAdmission(options, true),
};
