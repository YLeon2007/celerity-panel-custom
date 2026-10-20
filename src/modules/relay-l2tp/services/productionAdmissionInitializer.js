'use strict';

// Dormant server-maintenance API. Deliberately not imported by runtime/startup.
const { mongo } = require('mongoose');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT } = require('../domain/topologyExecutionContext');
const { rawDocumentFingerprint: fingerprint } = require('./productionAdmissionInitializationPreflight');
const HISTORY = ['topologyoperations', 'topologycreateintents', 'topologyintentqueuestates',
    'l2tpoperations', 'nodeoperationlocks', 'remoteadmissions', 'topologyexecutionbindings',
    'topologyexecutionenrollments', 'cascaderoutegroups'];
const INDEXES = {
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
        [{ enrollmentId: 1 }, { unique: true }], [{ attemptId: 1 }, { unique: true }], [{ commandTokens: 1 }, { unique: true }]],
    topologyexecutionenrollments: [[{ nodeId: 1, targetProfile: 1 }, { unique: true }],
        [{ 'nodeIdentity.machineId': 1, targetProfile: 1 }, { unique: true }],
        [{ 'nodeIdentity.sshHostKeySha256': 1, targetProfile: 1 }, { unique: true }],
        [{ 'nodeIdentity.machineId': 1 }, { unique: true }], [{ 'nodeIdentity.sshHostKeySha256': 1 }, { unique: true }],
        [{ 'endpoint.ip': 1, 'endpoint.port': 1 }, { unique: true }]],
    cascaderoutegroups: [],
};
function freeze(value) {
    if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
    return value;
}
const REVIEWED_MANIFEST = freeze({ version: 'production-admission-insert-only-v1',
    collections: Object.entries(INDEXES).map(([name, definitions]) => ({ name, options: {},
        indexes: [[{ _id: 1 }], ...definitions].map(([key, options = {}]) => ({ key,
            name: Object.keys(key).join() === '_id' ? '_id_'
                : Object.entries(key).map(([field, direction]) => `${field}_${direction}`).join('_'), ...options })) })) });
const REVIEWED_MANIFEST_SHA256 = fingerprint(REVIEWED_MANIFEST);
const BUDGET = { readPreference: 'primary', maxTimeMS: 2000, timeoutMS: 2000 };
const MAJORITY = { ...BUDGET, readConcern: { level: 'majority' } };
const STATE_KEYS = ['_id', 'revision', 'deployedRevision', 'stateTransitionRevision',
    'replacementEpoch', 'remoteAdmissionCount', 'topologyAdmissionCount'];
class InitializationError extends Error {
    constructor(code) { super(code); this.code = code; }
}
function fail(code) { throw new InitializationError(code); }
function exactKeys(value, keys) {
    return value && !Array.isArray(value) && typeof value === 'object'
        && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function same(a, b) { return fingerprint(a) === fingerprint(b); }

function createProductionAdmissionInitializer({ db, serverContext, expectedDatabaseName,
    expectedDeployment, acceptedClassicLinks, initialState, acceptedManifestSha256,
    maintenanceAuthority, maintenanceGeneration } = {}) {
    if (serverContext !== PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT
        || typeof expectedDatabaseName !== 'string' || !expectedDatabaseName
        || db?.databaseName !== expectedDatabaseName || !db?.client
        || !exactKeys(expectedDeployment, ['setName', 'replicaSetId'])
        || typeof expectedDeployment.setName !== 'string' || !expectedDeployment.setName
        || typeof expectedDeployment.replicaSetId !== 'string' || !/^[a-f0-9]{24}$/.test(expectedDeployment.replicaSetId)
        || typeof maintenanceGeneration !== 'string'
        || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(maintenanceGeneration)
        || acceptedManifestSha256 !== REVIEWED_MANIFEST_SHA256
        || !Array.isArray(acceptedClassicLinks) || acceptedClassicLinks.length !== 10
        || acceptedClassicLinks.some(pin => !exactKeys(pin, ['id', 'sha256'])
            || typeof pin.id !== 'string' || !/^[a-f0-9]{24}$/.test(pin.id)
            || typeof pin.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(pin.sha256))
        || new Set(acceptedClassicLinks.map(pin => pin.id)).size !== 10
        || !exactKeys(initialState, STATE_KEYS) || initialState._id !== 'singleton'
        || STATE_KEYS.slice(1).some(key => !Number.isSafeInteger(initialState[key]) || initialState[key] < 0)
        || initialState.revision !== initialState.deployedRevision
        || initialState.remoteAdmissionCount !== 0 || initialState.topologyAdmissionCount !== 0) {
        fail('PRODUCTION_INITIALIZATION_INPUT_REFUSED');
    }
    // A trusted server dependency, never a request field/boolean or default adapter.
    if (!maintenanceAuthority || typeof maintenanceAuthority.withHeldMaintenance !== 'function') {
        fail('EXTERNAL_MAINTENANCE_AUTHORITY_UNAVAILABLE');
    }
    const hold = maintenanceAuthority.withHeldMaintenance.bind(maintenanceAuthority);
    const challenge = freeze({ serverContext, databaseName: expectedDatabaseName, maintenanceGeneration,
        deployment: { ...expectedDeployment }, acceptedClassicLinks: acceptedClassicLinks.map(pin => ({ ...pin })),
        initialState: { ...initialState }, manifestSha256: acceptedManifestSha256 });
    let attempted = false;
    return Object.freeze({ async initialize() {
        if (attempted) fail('PRODUCTION_INITIALIZATION_ALREADY_ATTEMPTED');
        attempted = true;
        let active = true, invoked = false, completed = false, result;
        try {
            const returned = await hold(challenge, async scope => {
                if (!active || invoked) fail('PRODUCTION_INITIALIZATION_SCOPE_REFUSED');
                invoked = true;
                if (typeof scope?.assertHeld !== 'function' || typeof scope?.retainUnknown !== 'function') {
                    fail('PRODUCTION_INITIALIZATION_SCOPE_REFUSED');
                }
                const assertHeld = scope.assertHeld.bind(scope), retainUnknown = scope.retainUnknown.bind(scope);
                let session, ddlAttempted = false, commitAttempted = false, uncertain = false;
                async function check() {
                    if (!active || db.databaseName !== challenge.databaseName) fail('PRODUCTION_INITIALIZATION_SCOPE_LOST');
                    // Success is completion of the held capability check, not a truthy flag.
                    let answer;
                    try { answer = await assertHeld(challenge); }
                    catch { fail('PRODUCTION_INITIALIZATION_SCOPE_LOST'); }
                    if (answer !== undefined || !active) fail('PRODUCTION_INITIALIZATION_SCOPE_LOST');
                }
                async function guarded(fn) {
                    await check();
                    let value;
                    try { value = await fn(); }
                    catch (error) { await check(); throw error; }
                    await check();
                    return value;
                }
                async function deploymentCheck() {
                    const { config } = await guarded(() => db.client.db('admin').command({ replSetGetConfig: 1 }, BUDGET));
                    const hello = await guarded(() => db.client.db('admin').command({ hello: 1 }, BUDGET));
                    if (config?._id !== challenge.deployment.setName
                        || String(config?.settings?.replicaSetId) !== challenge.deployment.replicaSetId
                        || hello.setName !== challenge.deployment.setName || hello.isWritablePrimary !== true) {
                        fail('PRODUCTION_INITIALIZATION_DEPLOYMENT_REFUSED');
                    }
                }
                async function catalog() {
                    const rows = await guarded(() => db.listCollections({ name: { $in: Object.keys(INDEXES) } }, BUDGET).toArray());
                    if (rows.length !== Object.keys(INDEXES).length || rows.some(row => row.type !== 'collection'
                        || Object.keys(row.options || {}).length || !row.info?.uuid)) fail('PRODUCTION_INITIALIZATION_CATALOG_REFUSED');
                    return rows.map(row => ({ name: row.name, uuid: row.info.uuid })).sort((a, b) => a.name.localeCompare(b.name));
                }
                async function planIndexes() {
                    const additions = [];
                    for (const entry of REVIEWED_MANIFEST.collections) {
                        const actual = await guarded(() => db.collection(entry.name).listIndexes(BUDGET).toArray());
                        for (const index of actual) {
                            const wanted = entry.indexes.find(value => value.name === index.name);
                            if (!wanted || Object.keys(index).some(key => !['v', 'key', 'name', 'unique', 'sparse',
                                'partialFilterExpression', 'background'].includes(key))
                                || JSON.stringify(Object.entries(index.key)) !== JSON.stringify(Object.entries(wanted.key))
                                || Boolean(index.unique) !== Boolean(wanted.unique)
                                || Boolean(index.sparse) !== Boolean(wanted.sparse)
                                || !same(index.partialFilterExpression ?? null, wanted.partialFilterExpression ?? null)) {
                                fail('PRODUCTION_INITIALIZATION_INDEX_CONFLICT');
                            }
                        }
                        for (const wanted of entry.indexes) {
                            if (!actual.some(index => index.name === wanted.name)) {
                                if (wanted.name === '_id_') fail('PRODUCTION_INITIALIZATION_INDEX_CONFLICT');
                                additions.push({ collection: entry.name, index: wanted });
                            }
                        }
                    }
                    return additions;
                }
                async function inventory(options, expectedState) {
                    const links = await guarded(() => db.collection('cascadelinks').find({}, options).sort({ _id: 1 }).limit(11).toArray());
                    if (links.length !== 10 || links.filter(row => row.mode === 'reverse').length !== 8
                        || links.filter(row => row.mode === 'forward').length !== 2
                        || links.some(row => !(row._id instanceof mongo.ObjectId) || !(row.portalNode instanceof mongo.ObjectId)
                            || !(row.bridgeNode instanceof mongo.ObjectId) || row.active !== true
                            || !['online', 'deployed'].includes(row.status)
                            || !challenge.acceptedClassicLinks.some(pin => pin.id === String(row._id) && pin.sha256 === fingerprint(row)))) {
                        fail('PRODUCTION_INITIALIZATION_PIN_DRIFT');
                    }
                    for (const name of HISTORY) {
                        if ((await guarded(() => db.collection(name).find({}, options).limit(1).toArray())).length) {
                            fail('PRODUCTION_INITIALIZATION_HISTORY_PRESENT');
                        }
                    }
                    const states = await guarded(() => db.collection('cascadetopologystates').find({}, options).limit(2).toArray());
                    if (expectedState ? states.length !== 1 || !same(states[0], expectedState) : states.length !== 0) {
                        fail(expectedState ? 'PRODUCTION_INITIALIZATION_READBACK_MISMATCH' : 'PRODUCTION_INITIALIZATION_STATE_PRESENT');
                    }
                }
                // Driver commitTransaction() itself retries some errors even without withTransaction.
                // Issue exactly one raw command instead. Close local driver bookkeeping only;
                // transition never sends a command or proves server commit/abort.
                async function finishOnce(command, state) {
                    if (typeof session.transaction?.transition !== 'function') fail('PRODUCTION_INITIALIZATION_DRIVER_REFUSED');
                    try {
                        const reply = await db.client.db('admin').command({ [command]: 1,
                            ...(session.transaction.recoveryToken ? { recoveryToken: session.transaction.recoveryToken } : {}),
                            writeConcern: { w: 'majority', wtimeout: 2000 }, maxTimeMS: 2000 },
                        { session, ...BUDGET });
                        // Db.command is raw: ok:1 does NOT reject writeConcernError.
                        if (reply.ok !== 1 || reply.writeConcernError || reply.writeErrors?.length
                            || reply.errorLabels?.length) fail('PRODUCTION_INITIALIZATION_TRANSACTION_UNCONFIRMED');
                        return reply;
                    } finally { session.transaction.transition(state); }
                }
                try {
                    await deploymentCheck();
                    const baseline = await catalog();
                    const additions = await planIndexes();
                    // Avoid DDL on an already inadmissible baseline.
                    await inventory(MAJORITY);
                    for (const addition of additions) {
                        await check();
                        ddlAttempted = true;
                        const { key, ...options } = addition.index;
                        await guarded(() => db.collection(addition.collection).createIndex(key,
                            { ...options, ...BUDGET, writeConcern: { w: 'majority', wtimeoutMS: 2000 } }));
                    }
                    if ((await planIndexes()).length || !same(baseline, await catalog())) fail('PRODUCTION_INITIALIZATION_SCHEMA_DRIFT');
                    await deploymentCheck();
                    session = db.client.startSession({ causalConsistency: false });
                    if (typeof session.transaction?.transition !== 'function') fail('PRODUCTION_INITIALIZATION_DRIVER_REFUSED');
                    session.startTransaction({ readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
                    await inventory({ ...BUDGET, session });
                    await guarded(() => db.collection('cascadetopologystates').insertOne({ ...challenge.initialState },
                        { session, ...BUDGET }));
                    await check();
                    commitAttempted = true;
                    await guarded(() => finishOnce('commitTransaction', 'TRANSACTION_COMMITTED'));
                    await deploymentCheck();
                    await inventory(MAJORITY, challenge.initialState);
                    if ((await planIndexes()).length || !same(baseline, await catalog())) fail('PRODUCTION_INITIALIZATION_SCHEMA_DRIFT');
                    await guarded(() => session.endSession());
                    session = undefined;
                    await check();
                    result = Object.freeze({ initialized: true, ready: false, dormant: true,
                        mode: 'insert-only', stateSha256: fingerprint(challenge.initialState) });
                    completed = true;
                    return result;
                } catch (error) {
                    uncertain = ddlAttempted || commitAttempted;
                    if (session?.inTransaction() && !commitAttempted) {
                        try { await finishOnce('abortTransaction', 'TRANSACTION_ABORTED'); }
                        catch { uncertain = true; }
                    }
                    if (session) {
                        try { await session.endSession(); await check(); }
                        catch { uncertain = true; }
                        session = undefined;
                    }
                    // Never delete, repair, compensate or retry. The adapter must latch this
                    // before any outer cleanup; failure to latch also cannot authorize release.
                    if (uncertain || (error instanceof InitializationError && error.code === 'PRODUCTION_INITIALIZATION_SCOPE_LOST')) {
                        try { await retainUnknown(challenge); } catch { /* adapter remains fail-closed by contract */ }
                        fail('PRODUCTION_INITIALIZATION_UNKNOWN_HOLD');
                    }
                    if (error instanceof InitializationError) fail(error.code);
                    fail('PRODUCTION_INITIALIZATION_REFUSED');
                }
            });
            if (!completed || returned !== result) fail('PRODUCTION_INITIALIZATION_SCOPE_REFUSED');
            return result;
        } catch (error) {
            // No raw Mongo errors, URI, owner tokens or credential-bearing records escape.
            if (error instanceof InitializationError) fail(error.code);
            fail('PRODUCTION_INITIALIZATION_UNKNOWN_HOLD');
        } finally { active = false; }
    } });
}

module.exports = { createProductionAdmissionInitializer, REVIEWED_MANIFEST, REVIEWED_MANIFEST_SHA256 };
