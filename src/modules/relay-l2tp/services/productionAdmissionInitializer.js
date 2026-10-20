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
        [{ enrollmentId: 1, predecessorGeneration: 1 }, { unique: true }],
        [{ enrollmentId: 1, generation: 1 }, { unique: true }], [{ attemptId: 1 }, { unique: true }], [{ commandTokens: 1 }, { unique: true }]],
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
    maintenanceAuthority, maintenanceGeneration, acceptedMissingCollections = [] } = {}) {
    if (serverContext !== PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT
        || typeof expectedDatabaseName !== 'string' || !expectedDatabaseName
        || db?.databaseName !== expectedDatabaseName || !db?.client
        || !exactKeys(expectedDeployment, ['setName', 'replicaSetId'])
        || typeof expectedDeployment.setName !== 'string' || !expectedDeployment.setName
        || typeof expectedDeployment.replicaSetId !== 'string' || !/^[a-f0-9]{24}$/.test(expectedDeployment.replicaSetId)
        || typeof maintenanceGeneration !== 'string'
        || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(maintenanceGeneration)
        || acceptedManifestSha256 !== REVIEWED_MANIFEST_SHA256
        || !Array.isArray(acceptedMissingCollections)
        || Array.from(acceptedMissingCollections).some(entry => !exactKeys(entry, ['name', 'options'])
            || typeof entry.name !== 'string' || entry.name === 'cascadelinks'
            || !Object.hasOwn(INDEXES, entry.name) || !exactKeys(entry.options, [])
            || Object.getPrototypeOf(entry.options) !== Object.prototype)
        || new Set(acceptedMissingCollections.map(entry => entry.name)).size !== acceptedMissingCollections.length
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
        initialState: { ...initialState }, manifestSha256: acceptedManifestSha256,
        acceptedMissingCollections: acceptedMissingCollections.map(entry => ({ name: entry.name, options: {} })) });
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
                const expectedMissing = challenge.acceptedMissingCollections.map(entry => entry.name);
                async function catalog(missing = []) {
                    const rows = await guarded(() => db.listCollections({ name: { $in: Object.keys(INDEXES) } }, BUDGET).toArray());
                    if (rows.length !== Object.keys(INDEXES).length - missing.length
                        || rows.some(row => missing.includes(row.name) || row.type !== 'collection'
                            || Object.keys(row.options || {}).length || !(row.info?.uuid instanceof mongo.Binary)
                            || row.info.uuid.sub_type !== 4 || row.info.uuid.length() !== 16)
                        || Object.keys(INDEXES).some(name => !missing.includes(name) && !rows.some(row => row.name === name))) {
                        fail('PRODUCTION_INITIALIZATION_CATALOG_REFUSED');
                    }
                    return rows.map(row => ({ name: row.name, uuid: row.info.uuid })).sort((a, b) => a.name.localeCompare(b.name));
                }
                async function requireCatalog(baseline, missing = []) {
                    if (!same(baseline, await catalog(missing))) fail('PRODUCTION_INITIALIZATION_SCHEMA_DRIFT');
                }
                async function readIndexes(entry) {
                    // runCursorCommand sends this exact listIndexes command and bounded
                    // native getMore calls (no retry/resume wrapper). Unlike db.command,
                    // its GetMoreOperation suppresses invalid CSOT maxTimeMS on non-awaitData.
                    const cursor = db.runCursorCommand({ listIndexes: entry.name,
                        includeBuildUUIDs: true, cursor: { batchSize: 2 }, maxTimeMS: 2000 },
                    { readPreference: 'primary', timeoutMS: 2000 }).setBatchSize(2);
                    try {
                        const indexes = [];
                        while (await guarded(() => cursor.hasNext())) {
                            const index = await guarded(() => cursor.next());
                            // Ordinary listIndexes() hides this field. Never unwrap/use a
                            // building spec or wait for a foreign build to become ready.
                            if (Object.hasOwn(index, 'buildUUID')) {
                                uncertain = true;
                                fail('PRODUCTION_INITIALIZATION_INDEX_BUILD_PRESENT');
                            }
                            indexes.push(index);
                            if (indexes.length > entry.indexes.length) fail('PRODUCTION_INITIALIZATION_INDEX_CONFLICT');
                        }
                        return indexes;
                    } finally { await guarded(() => cursor.close()); }
                }
                async function planIndexes(missing = []) {
                    const additions = [];
                    for (const entry of REVIEWED_MANIFEST.collections) {
                        if (missing.includes(entry.name)) {
                            additions.push(...entry.indexes.filter(index => index.name !== '_id_')
                                .map(index => ({ collection: entry.name, index })));
                            continue;
                        }
                        const actual = await readIndexes(entry);
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
                async function inventory(options, expectedState, missing = []) {
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
                        // Absence is independently accepted catalog state, never inferred empty history.
                        if (missing.includes(name)) continue;
                        if ((await guarded(() => db.collection(name).find({}, options).limit(1).toArray())).length) {
                            fail('PRODUCTION_INITIALIZATION_HISTORY_PRESENT');
                        }
                    }
                    if (missing.includes('cascadetopologystates')) return;
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
                async function createdCatalog(receipt) {
                    // A compatible Mongo `create` can return ok:1 for a FOREIGN existing
                    // namespace. Only this transaction's expanded create events prove origin.
                    // Raw cursor commands deliberately have no driver change-stream resume/retry.
                    if (!(receipt.operationTime instanceof mongo.Timestamp)
                        || !Number.isSafeInteger(session.serverSession?.txnNumber)) {
                        fail('PRODUCTION_INITIALIZATION_CREATION_UNCONFIRMED');
                    }
                    const txnNumber = mongo.Long.fromNumber(session.serverSession.txnNumber);
                    let cursor;
                    try {
                        const reply = await guarded(() => db.command({ aggregate: 1,
                            pipeline: [{ $changeStream: { showExpandedEvents: true,
                                startAtOperationTime: receipt.operationTime } },
                            { $match: { operationType: 'create', 'lsid.id': session.id.id, txnNumber } }],
                            cursor: { batchSize: 0 }, maxTimeMS: 2000 }, { ...BUDGET, session }));
                        cursor = reply.cursor;
                        if (!cursor || cursor.ns !== `${challenge.databaseName}.$cmd.aggregate`
                            || !Array.isArray(cursor.firstBatch) || !(cursor.id instanceof mongo.Long)) {
                            fail('PRODUCTION_INITIALIZATION_CREATION_UNCONFIRMED');
                        }
                        let events = cursor.firstBatch;
                        if (events.length < expectedMissing.length && !cursor.id.isZero()) {
                            const more = await guarded(() => db.command({ getMore: cursor.id,
                                collection: '$cmd.aggregate', batchSize: expectedMissing.length + 1,
                                maxTimeMS: 2000 }, { ...BUDGET, session }));
                            cursor = more.cursor;
                            if (!cursor || cursor.ns !== `${challenge.databaseName}.$cmd.aggregate`
                                || !Array.isArray(cursor.nextBatch) || !(cursor.id instanceof mongo.Long)) {
                                fail('PRODUCTION_INITIALIZATION_CREATION_UNCONFIRMED');
                            }
                            events = [...events, ...cursor.nextBatch];
                        }
                        if (events.length !== expectedMissing.length
                            || new Set(events.map(event => event.ns?.coll)).size !== expectedMissing.length
                            || events.some(event => event.operationType !== 'create'
                                || event.ns?.db !== challenge.databaseName || !expectedMissing.includes(event.ns?.coll)
                                || !same(event.lsid?.id, session.id.id) || String(event.txnNumber) !== String(txnNumber)
                                || !(event.collectionUUID instanceof mongo.Binary)
                                || event.collectionUUID.sub_type !== 4 || event.collectionUUID.length() !== 16)) {
                            fail('PRODUCTION_INITIALIZATION_CREATION_UNCONFIRMED');
                        }
                        return events.map(event => ({ name: event.ns.coll, uuid: event.collectionUUID }));
                    } finally {
                        if (cursor?.id instanceof mongo.Long && !cursor.id.isZero()) {
                            await guarded(() => db.command({ killCursors: '$cmd.aggregate', cursors: [cursor.id] }, { ...BUDGET, session }));
                        }
                    }
                }
                try {
                    await deploymentCheck();
                    let baseline = await catalog(expectedMissing);
                    const additions = await planIndexes(expectedMissing);
                    // Avoid ALL DDL on an already inadmissible or changed baseline.
                    await inventory(MAJORITY, undefined, expectedMissing);
                    await requireCatalog(baseline, expectedMissing);
                    if (expectedMissing.length) {
                        session = db.client.startSession({ causalConsistency: false });
                        if (typeof session.transaction?.transition !== 'function'
                            || !Number.isSafeInteger(session.serverSession?.txnNumber)) {
                            fail('PRODUCTION_INITIALIZATION_DRIVER_REFUSED');
                        }
                        // Mongo only allows explicit collection creation at local read concern.
                        // Majority is required on the single raw commit; no transaction retries.
                        session.startTransaction({ readConcern: { level: 'local' },
                            writeConcern: { w: 'majority' }, readPreference: 'primary' });
                        for (const entry of challenge.acceptedMissingCollections) {
                            await requireCatalog(baseline, expectedMissing);
                            await check();
                            ddlAttempted = true;
                            const reply = await guarded(() => db.command({ create: entry.name, ...entry.options,
                                maxTimeMS: 2000 }, { session, ...BUDGET }));
                            if (reply.ok !== 1 || reply.writeConcernError || reply.writeErrors?.length || reply.errorLabels?.length) {
                                fail('PRODUCTION_INITIALIZATION_CREATION_UNCONFIRMED');
                            }
                        }
                        await check();
                        commitAttempted = true;
                        const receipt = await guarded(() => finishOnce('commitTransaction', 'TRANSACTION_COMMITTED'));
                        const created = await createdCatalog(receipt);
                        baseline = [...baseline, ...created].sort((a, b) => a.name.localeCompare(b.name));
                        await requireCatalog(baseline);
                        // Require the EXACT reviewed additions, not foreign index adoption.
                        if (!same(additions, await planIndexes())) fail('PRODUCTION_INITIALIZATION_SCHEMA_DRIFT');
                        await guarded(() => session.endSession());
                        session = undefined;
                        commitAttempted = false;
                    }
                    for (const addition of additions) {
                        await requireCatalog(baseline);
                        await check();
                        ddlAttempted = true;
                        const { key, ...options } = addition.index;
                        await guarded(() => db.collection(addition.collection).createIndex(key,
                            { ...options, ...BUDGET, writeConcern: { w: 'majority', wtimeoutMS: 2000 } }));
                    }
                    await deploymentCheck();
                    if ((await planIndexes()).length) fail('PRODUCTION_INITIALIZATION_SCHEMA_DRIFT');
                    await requireCatalog(baseline);
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
                    uncertain ||= ddlAttempted || commitAttempted;
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
                    if (uncertain || (error instanceof InitializationError && [
                        'PRODUCTION_INITIALIZATION_SCOPE_LOST', 'PRODUCTION_INITIALIZATION_INDEX_BUILD_PRESENT'].includes(error.code))) {
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
