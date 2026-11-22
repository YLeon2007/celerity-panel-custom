'use strict';

const { randomUUID } = require('node:crypto');
const { setTimeout: delay } = require('node:timers/promises');
const { Connection, mongo: { Db }, Types: { ObjectId } } = require('mongoose');
const { relayListKey, relayListLimit, relayBindingFields, normalizeRelayBinding, parseRelayBindingList,
    assertUniqueRelayBindings, RelayGrantConflict, relayInstallEnabled } = require('./rebuildRelayAuthorization');

const GRANTS = 'c3_rebuild_l2tp_relay_grants';
const RETIRED = 'c3_rebuild_l2tp_retired_relays';
const AUDIT = 'c3_rebuild_l2tp_relay_grant_audit';
const LEGACY_ID = 'C3_REBUILD_L2TP_RELAY_ID';
const LEGACY_MACHINE = 'C3_REBUILD_L2TP_RELAY_MACHINE_ID';
const LEGACY_PIN = 'C3_REBUILD_L2TP_SSH_SHA256';
const authorityKeys = [relayListKey, LEGACY_ID, LEGACY_MACHINE, LEGACY_PIN];
const indexKeys = [{ nodeId: 1 }, { machineId: 1 }, { sshHostKeySha256: 1 }, { host: 1, port: 1 }];
const grantActions = new Set(['grant', 'reconfirm', 'revoke']);
const auditActions = new Set([...grantActions, 'probe', 'verify', 'confirm']);
const auditOutcomes = new Set(['success', 'denied', 'unknown']);
const auditCodes = new Set(['OK', 'REBUILD_BUSY', 'REBUILD_LOCK_LOST', 'REBUILD_LOCK_RELEASE_UNCONFIRMED', ...[
    'INSTALL_DISABLED', 'BINDING_MISMATCH', 'SSH_PIN_INVALID', 'SSH_ENDPOINT_INVALID', 'GRANT_CONFLICT',
    'GRANT_CHANGED', 'GRANT_INVALID', 'GRANT_ENV_INVALID', 'GRANT_REGISTRY_INVALID', 'GRANT_PERSISTENCE_UNAVAILABLE',
    'GRANT_LEGACY_SINGLETON_IN_USE',
    'GRANT_OUTCOME_UNKNOWN', 'ADMISSION_INVALID_REQUEST', 'ADMISSION_CHALLENGE_INVALID', 'ADMISSION_DISABLED',
    'ADMISSION_UNAVAILABLE', 'ACCOUNTS_BLOCKED', 'ACCOUNTS_PERSISTENCE_UNAVAILABLE', 'IDENTITY_CHANGED', 'IDENTITY_UNAVAILABLE',
].map(suffix => `REBUILD_L2TP_${suffix}`)]);
const timeLimits = { maxTimeMS: 5000, timeoutMS: 5000 };
const majority = { w: 'majority' };
const read = session => ({ ...timeLimits, ...(session && { session }), ...(!session?.inTransaction() && {
    readPreference: 'primary', readConcern: { level: 'majority' },
}) });
const write = session => ({ timeoutMS: timeLimits.timeoutMS, ...(session ? { session } : { writeConcern: majority }) });
const bindingFields = row => Object.fromEntries(relayBindingFields.map(key => [key, row?.[key]]));
const validId = id => typeof id === 'string' && id.length === 24 && /^[0-9a-f]+$/.test(id);
const validMachine = id => typeof id === 'string' && id.length === 32 && /^[0-9a-f]+$/.test(id);
const validPin = pin => typeof pin === 'string' && pin.length === 64 && /^[0-9a-f]+$/.test(pin);
const validActor = actor => typeof actor === 'string' && actor.trim() === actor && actor.length > 0 && actor.length <= 256
    && !/[\p{C}\u2028\u2029]/u.test(actor);
const validDate = at => at instanceof Date && Number.isFinite(at.getTime());
const validGeneration = id => typeof id === 'string' && id.length === 36
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id);
const unset = value => value === undefined || value === '';

class GrantError extends Error {
    constructor(code) {
        super(code);
        this.code = code;
    }
}
const error = suffix => new GrantError(`REBUILD_L2TP_GRANT_${suffix}`);
const envInvalid = () => error('ENV_INVALID');
const registryInvalid = () => error('REGISTRY_INVALID');
const invalid = () => error('INVALID');
const unavailable = () => error('PERSISTENCE_UNAVAILABLE');
const outcomeUnknown = () => Object.assign(error('OUTCOME_UNKNOWN'), { retryAllowed: false });
function safeError(cause) {
    if (cause instanceof RelayGrantConflict || cause instanceof GrantError) return cause;
    if (cause?.code === 11000) {
        const key = cause.keyPattern;
        const field = key?.nodeId ? 'nodeId' : key?.machineId ? 'machineId' : key?.sshHostKeySha256 ? 'sshHostKeySha256'
            : key?.host && key?.port ? 'endpoint' : null;
        return new RelayGrantConflict(field, ['db', 'db']);
    }
    return cause?.code === 112 ? error('CHANGED') : unavailable();
}

function projectGrant(row) {
    const binding = normalizeRelayBinding(bindingFields(row), registryInvalid);
    const { createdBy, createdAt, confirmedBy, confirmedAt, generation } = row;
    if (binding.host !== row.host || !validActor(createdBy) || !validActor(confirmedBy)
        || !validDate(createdAt) || !validDate(confirmedAt) || !validGeneration(generation)) throw registryInvalid();
    return { ...binding, createdBy, createdAt, confirmedBy, confirmedAt, generation };
}

function legacyBinding(env) {
    const nodeId = env[LEGACY_ID], machineId = env[LEGACY_MACHINE], sshHostKeySha256 = env[LEGACY_PIN];
    if ([nodeId, machineId, sshHostKeySha256].every(unset)) return;
    // The old route-only check doesn't require a configured pin. The original
    // resolver still enforces it for SSH; a union requires it unconditionally.
    if (!validId(nodeId) || !validMachine(machineId) || (!unset(sshHostKeySha256) && !validPin(sshHostKeySha256))) throw envInvalid();
    return { nodeId, machineId, sshHostKeySha256 };
}

const withSource = (bindings, source) => bindings.map(binding => ({ binding, source }));
function listOverlay(entries) {
    const json = JSON.stringify(entries.map(({ binding }) => binding));
    if (json.length > relayListLimit) throw registryInvalid();
    return json;
}

function createRelayGrantStore({ db, env = process.env }) {
    function requireDb() {
        if (typeof db?.collection !== 'function' || (db.readyState !== undefined && db.readyState !== 1)) throw unavailable();
    }
    const grantsCollection = () => db.collection(GRANTS);
    async function readRetired(ids, session) {
        const retired = new Set();
        if (!ids.length) return retired;
        // Use the same driver DB that backs Mongoose, including when a driver
        // adapter is injected at Connection.db. The older collection-only
        // adapter implements just the grant registry, not retirement storage.
        const native = db instanceof Db ? db : db.db;
        if (native === undefined && !(db instanceof Connection)) return retired;
        if (typeof native?.collection !== 'function') throw unavailable();
        const collection = native.collection(RETIRED);
        const keys = [...new Set(ids)];
        for (let offset = 0; offset < keys.length; offset += 1024) {
            const batch = new Set(keys.slice(offset, offset + 1024));
            const rows = await collection.find({ _id: { $in: [...batch] } }, {
                ...read(session), projection: { _id: 1 }, limit: batch.size + 1,
            }).toArray();
            if (!Array.isArray(rows) || rows.some(row => !batch.delete(row?._id))) throw registryInvalid();
            for (const row of rows) retired.add(row._id);
        }
        return retired;
    }
    // DDL happens outside the mutation transaction. Never publish a grant
    // until Mongo has acknowledged the four full unique indexes.
    async function ensureCollections() {
        await grantsCollection().createIndexes(indexKeys.map(key => ({ key, unique: true,
            name: `${Object.keys(key).join('_')}_unique`, collation: { locale: 'simple' } })), { ...timeLimits, writeConcern: majority });
        // Explicitly create the audit namespace before the first snapshot
        // transaction. Collection fixtures may model it as already present.
        if (typeof db.createCollection === 'function') {
            try { await db.createCollection(AUDIT, { ...timeLimits, writeConcern: majority }); }
            catch (cause) { if (cause?.code !== 48) throw cause; }
        }
    }

    async function registry(config, session, needLegacyEndpoint = false, nodeIds = []) {
        requireDb();
        const hasList = Object.hasOwn(config, relayListKey);
        let singleton = hasList ? undefined : legacyBinding(config);
        let envBindings = hasList ? parseRelayBindingList(config[relayListKey], envInvalid, { checkUniqueness: false }) : [];
        // The binding array has a smaller serialization limit; cap records
        // separately so a corrupt collection cannot exhaust memory on readers.
        const cursor = await grantsCollection().find({}, { ...read(session), limit: 1025 });
        const rows = await cursor.toArray();
        if (!Array.isArray(rows) || rows.length > 1024) throw registryInvalid();
        const grants = rows.map(projectGrant);
        const retired = await readRetired([
            ...nodeIds, ...(singleton ? [singleton.nodeId] : envBindings.map(row => row.nodeId)),
            ...grants.map(row => row.nodeId),
        ], session);
        // A committed retirement deletes the DB grant in the same transaction.
        // Never emit a DB grant if a later read observes that node's retirement.
        if (grants.some(row => retired.has(row.nodeId))) throw registryInvalid();
        // Suppress only committed node IDs, before the inventory/uniqueness
        // checks: a retired card is gone and its address may be reused.
        if (singleton && retired.has(singleton.nodeId)) {
            singleton = undefined;
            for (const key of [LEGACY_ID, LEGACY_MACHINE, LEGACY_PIN]) delete config[key];
        }
        if (hasList && envBindings.some(row => retired.has(row.nodeId))) {
            envBindings = envBindings.filter(row => !retired.has(row.nodeId));
            config[relayListKey] = JSON.stringify(envBindings);
        }
        if (singleton && (needLegacyEndpoint || grants.length)) {
            // Do not invent a port/login or trust a submitted endpoint. The
            // legacy binding comes from the same inventory as the SSH card.
            const nodes = db.models?.HyNode?.collection?.collectionName ?? 'hynodes';
            const card = await db.collection(nodes).findOne({ _id: new ObjectId(singleton.nodeId) }, {
                ...read(session), projection: { _id: 1, ip: 1, 'ssh.port': 1, 'ssh.username': 1 },
            });
            if (String(card?._id) !== singleton.nodeId || card?.ssh?.username !== 'root') throw envInvalid();
            const binding = { ...singleton, host: card.ip, port: card.ssh.port, username: card.ssh.username };
            normalizeRelayBinding(binding, envInvalid);
            envBindings.push(binding);
        }
        const entries = [...withSource(envBindings, 'env'), ...withSource(grants.map(bindingFields), 'db')];
        assertUniqueRelayBindings(entries);
        return { grants, entries, singleton, retired };
    }

    async function snapshot({ session, nodeIds = [] } = {}) {
        try {
            const config = { ...env };
            const { grants, entries, singleton, retired } = await registry(config, session, false, nodeIds.filter(validId));
            const sources = new Map(entries.map(({ binding, source }) => [binding.nodeId, source]));
            if (singleton) sources.set(singleton.nodeId, 'env');
            // Leave pure ENV unchanged, including legacy singleton's no-list
            // mode. DB-only and mixed registries use the synchronous list ABI.
            if (grants.length) config[relayListKey] = listOverlay(entries);
            return { env: Object.freeze(config), grants, sourceFor: nodeId => sources.get(nodeId) ?? null,
                isRetired: nodeId => retired.has(nodeId) };
        } catch (cause) {
            throw safeError(cause);
        }
    }

    async function putAudit({ action, nodeId, actor, outcome, code }, session) {
        const row = {
            action: auditActions.has(action) ? action : 'unknown',
            nodeId: validId(nodeId) ? nodeId : null,
            actor: validActor(actor) ? actor : null, // supplied by the authenticated server-side caller
            at: new Date(),
            outcome: auditOutcomes.has(outcome) ? outcome : 'unknown',
            code: auditCodes.has(code) ? code : code === undefined && outcome === 'success' ? 'OK'
                : 'REBUILD_L2TP_GRANT_AUDIT_UNCLASSIFIED',
        };
        const result = await db.collection(AUDIT).insertOne(row, write(session));
        if (result?.acknowledged !== true) throw unavailable();
    }

    // The caller records refusals (including pre-store probe/authorization
    // failures) through this API. Success of a grant change is recorded below
    // in its own transaction, never in a follow-up best-effort write.
    async function audit(event) {
        try { requireDb(); await putAudit(event); }
        catch { throw unavailable(); }
    }

    function checkMutation({ action, binding, expectedGeneration }, { grants, entries }) {
        const { nodeId } = binding;
        const current = grants.find(row => row.nodeId === nodeId);
        const source = entries.find(entry => entry.binding.nodeId === nodeId)?.source;
        if (source === 'env' || (action === 'grant' && current)) throw new RelayGrantConflict('nodeId', [source, 'db']);
        if (action !== 'grant' && (!current || current.generation !== expectedGeneration)) throw error('CHANGED');
        if (action !== 'revoke') {
            const kept = entries.filter(entry => !current || entry.source !== 'db' || entry.binding.nodeId !== nodeId);
            const nextEntries = [...kept, { binding, source: 'db' }];
            assertUniqueRelayBindings(nextEntries);
            listOverlay(nextEntries); // Do not persist a union the synchronous resolver would refuse.
        }
        return current;
    }

    async function apply(changes, session) {
        const { action, binding, expectedGeneration, actor } = changes;
        const { nodeId } = binding;
        const config = { ...env };
        if (!relayInstallEnabled(config)) throw new GrantError('REBUILD_L2TP_INSTALL_DISABLED');
        const view = await registry({ ...config }, session, true, [nodeId]);
        const checkEnv = () => {
            if (!relayInstallEnabled(env) || authorityKeys.some(key => config[key] !== env[key]
                || Object.hasOwn(config, key) !== Object.hasOwn(env, key))) throw error('CHANGED');
        };
        checkEnv();
        if (view.retired.has(nodeId)) throw error('CHANGED');
        const current = checkMutation(changes, view);
        const options = write(session);
        const filter = { nodeId, generation: expectedGeneration };
        const collection = grantsCollection();
        let next = null;
        if (action === 'revoke') {
            if (view.singleton && view.grants.length === 1) {
                // Admission holds the global rebuild writer lock. Use the same
                // transaction as the grant CAS: the last DB grant supplies list
                // semantics for this ENV relay. Legacy Remove can only prove
                // its original bootstrap, not an arbitrary CHAP projection.
                const node = new ObjectId(view.singleton.nodeId);
                const probe = { ...read(session), projection: { _id: 1 } };
                if (await db.collection('relayl2tpstates').findOne({ node,
                    $nor: [{ status: 'not_installed', desiredState: 'absent' }],
                }, probe) || await db.collection('l2tpusers').findOne({ relayNode: node }, probe)) {
                    throw error('LEGACY_SINGLETON_IN_USE');
                }
                // A directory without live projections intentionally survives
                // Remove; it neither authorizes a cohort nor prevents revoke.
            }
            const result = await collection.deleteOne(filter, options);
            if (result?.acknowledged !== true || result.deletedCount !== 1) throw error('CHANGED');
        } else {
            const now = new Date();
            next = { ...binding, createdBy: current?.createdBy ?? actor, createdAt: current?.createdAt ?? now,
                confirmedBy: actor, confirmedAt: now, generation: randomUUID() };
            if (current) {
                const result = await collection.updateOne(filter, { $set: next }, options);
                if (result?.acknowledged !== true || result.matchedCount !== 1) throw error('CHANGED');
            } else {
                const result = await collection.insertOne({ ...next }, options);
                if (result?.acknowledged !== true) throw unavailable();
            }
        }
        await putAudit({ action, nodeId, actor, outcome: 'success', code: 'OK' }, session);
        checkEnv();
        return next;
    }

    async function abort(session) {
        if (session?.inTransaction()) await session.abortTransaction();
    }

    async function observedConflict(changes) {
        // A simultaneous unique-index contender can surface as WriteConflict
        // before the winner is majority-visible. Observe only, never replay the
        // grant or its audit. Keep CHANGED unless a collision actually appears.
        for (let attempt = 1; attempt <= 4; attempt++) {
            await delay(10 * attempt);
            try { checkMutation(changes, await registry({ ...env }, undefined, true)); }
            catch (cause) { return cause instanceof RelayGrantConflict ? cause : undefined; }
        }
    }

    async function mutate({ action, binding, expectedGeneration, actor, session } = {}) {
        try {
            if (!grantActions.has(action) || !validActor(actor) || !validId(binding?.nodeId)) throw invalid();
            if (action === 'grant' ? expectedGeneration != null : !validGeneration(expectedGeneration)) throw error('CHANGED');
            const changes = { action, binding: action === 'revoke' ? { nodeId: binding.nodeId }
                : normalizeRelayBinding(bindingFields(binding), invalid), expectedGeneration, actor };
            requireDb();
            if (!relayInstallEnabled(env)) throw new GrantError('REBUILD_L2TP_INSTALL_DISABLED');
            if (session && !session.inTransaction()) throw unavailable();
            await ensureCollections();
            if (session) return await apply(changes, session);

            const admin = db.getClient().db('admin');
            const own = await db.startSession();
            let commitAttempted = false;
            try {
                if (typeof own.transaction?.transition !== 'function' || typeof admin?.command !== 'function') throw unavailable();
                own.startTransaction({ readConcern: { level: 'snapshot' }, readPreference: 'primary', writeConcern: majority });
                const result = await apply(changes, own);
                const { recoveryToken } = own.transaction;
                // The driver's commitTransaction can retry even with retryWrites:false.
                // Use the same one-shot command boundary as rebuildRelayInstallTransaction.
                commitAttempted = true;
                const reply = await admin.command({ commitTransaction: 1,
                    ...(recoveryToken && { recoveryToken }), writeConcern: { ...majority, wtimeout: timeLimits.maxTimeMS },
                    maxTimeMS: timeLimits.maxTimeMS }, { session: own, ...timeLimits, readPreference: 'primary' });
                if (reply?.ok !== 1 || reply.writeConcernError || reply.writeErrors?.length || reply.errorLabels?.length) {
                    throw outcomeUnknown();
                }
                return result;
            } catch (cause) {
                if (commitAttempted) throw outcomeUnknown();
                try { await abort(own); } catch { throw cause; }
                if (cause?.code === 112 && changes.action !== 'revoke' && !own.inTransaction()) {
                    const conflict = await observedConflict(changes);
                    if (conflict) throw conflict;
                }
                throw cause;
            } finally {
                try {
                    // This is local bookkeeping, not proof that Mongo committed.
                    // endSession would auto-abort if the transaction is still active.
                    if (commitAttempted) own.transaction.transition('TRANSACTION_COMMITTED');
                    if (!commitAttempted || !own.inTransaction()) await own.endSession();
                } catch { /* Preserve known success or the original refusal/unknown outcome. */ }
            }
        } catch (cause) {
            // A caller-owned transaction must not commit a staged grant when
            // its audit or any later validation failed.
            try { await abort(session); } catch { throw unavailable(); }
            throw safeError(cause);
        }
    }

    return { snapshot, mutate, audit };
}

module.exports = { createRelayGrantStore, GRANTS, RETIRED, authorityKeys: Object.freeze(authorityKeys), legacyBinding };
