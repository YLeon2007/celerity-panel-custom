'use strict';

const { createHash, randomBytes } = require('node:crypto');
const { types: { isProxy } } = require('node:util');

const COLLECTION = 'rebuild_l2tp_cleanup_consents_v1';
const TTL_MS = 600_000;
const CHECK = 'L2TP_FOREIGN_CONFIG';
const ACTION = 'l2tp-cleanup-consent';
const WRITE_CONCERN = Object.freeze({ w: 'majority' });
const SIMPLE = Object.freeze({ locale: 'simple' });
const fail = code => Object.assign(new Error(`REBUILD_L2TP_CLEANUP_CONSENT_${code}`), {
    code: `REBUILD_L2TP_CLEANUP_CONSENT_${code}`,
});

// Digest-bearing leaves in the canonical DIRECT foreign-config-v2 wire order
// (f23aa19). Diagnostic-only/manual/runtime findings are not candidates.
const PATHS = Object.freeze({
    SWAN_PROFILE_PRESENT: '/etc/strongswan.d/celerity-rebuild-l2tp.conf',
    IKE_PROFILE_PRESENT: '/etc/ipsec.d/celerity-rebuild-l2tp.conf',
    OPTIONS_PRESENT: '/etc/ppp/options.xl2tpd',
    STARTER_NOT_STOCK: '/etc/ipsec.conf',
    SECRETS_NOT_EMPTY: '/etc/ipsec.secrets',
    CHAP_NOT_EMPTY: '/etc/ppp/chap-secrets',
    LNS_NOT_STOCK: '/etc/xl2tpd/xl2tpd.conf',
    XRAY_UNIT_0666: '/etc/systemd/system/xray.service',
    XRAY_BRIDGE_UNIT_0666: '/etc/systemd/system/xray-bridge.service',
    NFT_DIR_PRESENT: '/etc/celerity-rebuild-l2tp/ingress.nft',
    DROPIN_PRESENT: '/etc/systemd/system/xl2tpd.service.d/50-celerity-rebuild-l2tp.conf',
    MODULES_LOAD_FOREIGN: '/etc/modules-load.d/c3-l2tp.conf',
    NETWORK_UNIT_ORPHANED: '/etc/systemd/system/celerity-rebuild-l2tp-network.service',
    LEGACY_NFT_PRESENT: '/etc/nftables.d/celerity-l2tp.nft',
});
const KEYS = Object.keys(PATHS);
const hasXray = keys => keys.includes('XRAY_UNIT_0666') || keys.includes('XRAY_BRIDGE_UNIT_0666');
const sha = value => createHash('sha256').update(value).digest('hex');
const hex = (value, length) => typeof value === 'string' && value.length === length && /^[a-f0-9]+$/.test(value);
const bounded = value => typeof value === 'string' && value.length > 0 && value.length <= 256
    && !/[\p{C}\u2028\u2029]/u.test(value);
const uuid4 = value => typeof value === 'string' && value.length === 36
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const literal = value => ({ $literal: value });

function ownData(value, name) {
    const d = Object.getOwnPropertyDescriptor(value, name);
    return d?.enumerable && Object.hasOwn(d, 'value') ? d.value : undefined;
}

function record(value, names) {
    if (!value || typeof value !== 'object' || isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype
        || Reflect.ownKeys(value).length !== names.length) return [];
    return names.map(name => ownData(value, name));
}

function identity(scope) {
    const [nodeId, actor, sessionId, generation] = record(scope, ['nodeId', 'actor', 'sessionId', 'generation']);
    if (!hex(nodeId, 24) || !bounded(actor) || actor.trim() !== actor || !bounded(sessionId) || !uuid4(generation)) return;
    return { nodeId, actor, generation, sessionSha256: sha(sessionId) };
}

function canonicalKeys(value) {
    if (isProxy(value) || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
        || !value.length || value.length > KEYS.length || Reflect.ownKeys(value).length !== value.length + 1) return;
    let prev = -1;
    const keys = [];
    for (let i = 0; i < value.length; i++) {
        const key = ownData(value, i);
        const index = KEYS.indexOf(key);
        if (index <= prev) return;
        prev = index;
        keys.push(key);
    }
    return keys;
}

function observation(value) {
    const [check, inputKeys, cleanable, manual, digest] = record(value, ['check', 'keys', 'cleanable', 'manual', 'digest']);
    if (check !== CHECK || cleanable !== true || manual !== false || !hex(digest, 64)) return;
    const keys = canonicalKeys(inputKeys);
    if (keys) return { keys, digestSha256: sha(`foreign-config-v2\0${digest}`) };
}

function safeAudit(row, owner) {
    const [action, nodeId, actor, issuedAt, consumedAt, inputKeys, paths, result] = record(row?.audit,
        ['action', 'nodeId', 'actor', 'issuedAt', 'consumedAt', 'keys', 'paths', 'result']);
    const keys = canonicalKeys(inputKeys);
    if (action !== ACTION || nodeId !== owner.nodeId || actor !== owner.actor || !keys
        || !Array.isArray(paths) || paths.length !== keys.length || !keys.every((key, i) => paths[i] === PATHS[key])
        || !(issuedAt instanceof Date) || !(consumedAt instanceof Date)
        || !(issuedAt <= consumedAt && consumedAt - issuedAt < TTL_MS)
        || !['changed', 'xray-opt-in-required', 'consumed'].includes(result)) throw fail('UNAVAILABLE');
    return Object.freeze({ action, nodeId, actor, issuedAt: issuedAt.toISOString(), consumedAt: consumedAt.toISOString(),
        keys: Object.freeze(keys), paths: Object.freeze(keys.map(key => PATHS[key])), result });
}

async function dbCall(call) {
    try { return await call(); } catch { throw fail('UNAVAILABLE'); }
}

// `db` is a connected native Mongo Db (e.g. mongooseConnection.db); use the
// collection unsharded or shard by its unique _id. Call ensureIndexes at startup.
// Scope is from authenticated server context and the *current* persisted relay
// admission UUID, never a posted scope or an ENV/lock token. Both observations
// come from the pinned producer; fresh is reread under the caller's writer
// fence. This module neither holds that fence nor authorizes host dispatch.
// Only confirmation {token, fixXrayUnitMode} comes from the browser.
function createRelayCleanupConsentStore({ db } = {}) {
    if (typeof db?.collection !== 'function') throw new TypeError('Native Mongo Db required');
    const collection = db.collection(COLLECTION);

    async function ensureIndexes() {
        // Only unused tickets have expiresAt. Spent rows retain a safe audit and
        // private _id; read/export the audit field only, always excluding _id.
        await dbCall(() => collection.createIndex({ expiresAt: 1 }, {
            name: 'cleanup_consent_expiry', expireAfterSeconds: 0, writeConcern: WRITE_CONCERN,
        }));
        await dbCall(() => collection.createIndex({ 'audit.backupId': 1 }, {
            name: 'cleanup_consent_install', unique: true, partialFilterExpression: { 'audit.backupId': { $exists: true } },
            writeConcern: WRITE_CONCERN,
        }));
    }

    async function issue(scope, proof) {
        const owner = identity(scope);
        const observed = observation(proof);
        if (!owner || !observed) throw fail('INVALID');
        const token = await dbCall(() => randomBytes(32).toString('hex'));
        const _id = sha(token);
        const reply = await dbCall(() => collection.updateMany({ _id, state: { $exists: false } }, [{ $set: {
            version: 1, state: 'issued', owner: literal(owner), proof: literal(observed),
            paths: literal(observed.keys.map(key => PATHS[key])),
            issuedAt: '$$NOW', expiresAt: { $add: ['$$NOW', TTL_MS] },
        } }], { upsert: true, collation: SIMPLE, writeConcern: WRITE_CONCERN }));
        if (reply?.acknowledged !== true || reply.matchedCount !== 0 || reply.modifiedCount !== 0
            || reply.upsertedCount !== 1 || reply.upsertedId !== _id) throw fail('UNAVAILABLE');
        return Object.freeze({ token });
    }

    async function consume(scope, confirmation, fresh) {
        const owner = identity(scope);
        const [token, mode] = record(confirmation, ['token', 'fixXrayUnitMode']);
        if (!owner || !hex(token, 64) || typeof mode !== 'boolean') throw fail('INVALID');
        const observed = observation(fresh);
        const resultForSameProof = !observed ? 'changed' : hasXray(observed.keys) === mode ? 'consumed'
            : mode ? 'changed' : 'xray-opt-in-required';
        const _id = sha(token);
        // The driver's updateMany is non-retryable even with retryWrites=true.
        // Unique _id + issued state + exact scope permits only one transition.
        // A same-scope stale/manual observation burns, but is never a grant.
        // Mongo's clock enforces expiration even before the TTL sweep runs.
        const reply = await dbCall(() => collection.updateMany({ _id, version: 1, state: 'issued', $expr: { $and: [
            { $eq: ['$owner', literal(owner)] },
            { $eq: [{ $type: '$issuedAt' }, 'date'] },
            { $eq: ['$expiresAt', { $add: ['$issuedAt', TTL_MS] }] },
            { $lte: ['$issuedAt', '$$NOW'] }, { $lt: ['$$NOW', '$expiresAt'] },
        ] } }, [{ $set: {
            state: 'spent', audit: { action: ACTION, issuedAt: '$issuedAt', consumedAt: '$$NOW',
                nodeId: literal(owner.nodeId), actor: literal(owner.actor), keys: '$proof.keys', paths: '$paths',
                result: observed ? { $cond: [{ $eq: ['$proof', literal(observed)] }, resultForSameProof, 'changed'] } : 'changed' },
        } }, { $unset: ['owner', 'proof', 'paths', 'issuedAt', 'expiresAt'] }],
        { upsert: false, collation: SIMPLE, writeConcern: WRITE_CONCERN }));
        if (reply?.acknowledged !== true || reply.upsertedCount !== 0) throw fail('UNAVAILABLE');
        if (reply.matchedCount === 0 && reply.modifiedCount === 0) throw fail('REQUIRED');
        if (reply.matchedCount !== 1 || reply.modifiedCount !== 1) throw fail('UNAVAILABLE');

        // Read only the safe audit, exclusively after an acknowledged CAS win.
        const row = await dbCall(() => collection.findOne({ _id, version: 1, state: 'spent' }, {
            projection: { _id: 0, audit: 1 }, readConcern: { level: 'majority' }, readPreference: 'primary', collation: SIMPLE,
        }));
        const audit = safeAudit(row, owner);
        if (audit.result === 'changed') throw fail('CHANGED');
        if (audit.result === 'xray-opt-in-required') throw fail('XRAY_OPT_IN_REQUIRED');
        if (resultForSameProof !== 'consumed' || audit.keys.length !== observed.keys.length
            || !audit.keys.every((key, i) => observed.keys[i] === key)) throw fail('UNAVAILABLE');
        return Object.freeze({ keys: audit.keys, fixXrayUnitMode: mode, audit });
    }

    async function finish(scope, confirmation, result) {
        const owner = identity(scope);
        const [token, mode] = record(confirmation, ['token', 'fixXrayUnitMode']);
        if (!owner || !hex(token, 64) || typeof mode !== 'boolean' || !['installed', 'rolled_back', 'refused', 'unknown'].includes(result)) {
            throw fail('INVALID');
        }
        const reply = await dbCall(() => collection.updateMany({ _id: sha(token), version: 1, state: 'spent',
            'audit.result': 'consumed', 'audit.actor': owner.actor, 'audit.nodeId': owner.nodeId,
            'audit.finish': { $exists: false } }, [{ $set: {
            'audit.finish': { at: '$$NOW', result: literal(result) },
        } }], { upsert: false, collation: SIMPLE, writeConcern: WRITE_CONCERN }));
        if (reply?.acknowledged !== true || reply.matchedCount !== 1 || reply.modifiedCount !== 1) throw fail('UNAVAILABLE');
    }
    async function bind(scope, confirmation, backupId) {
        const owner = identity(scope);
        const [token, mode] = record(confirmation, ['token', 'fixXrayUnitMode']);
        if (!owner || !hex(token, 64) || typeof mode !== 'boolean' || !hex(backupId, 32)) throw fail('INVALID');
        const reply = await dbCall(() => collection.updateMany({ _id: sha(token), version: 1, state: 'spent',
            'audit.result': 'consumed', 'audit.nodeId': owner.nodeId, 'audit.actor': owner.actor,
            'audit.finish': { $exists: false }, 'audit.backupId': { $exists: false } },
        { $set: { 'audit.backupId': backupId } }, { collation: SIMPLE, writeConcern: WRITE_CONCERN }));
        if (reply?.acknowledged !== true || reply.matchedCount !== 1 || reply.modifiedCount !== 1) throw fail('UNAVAILABLE');
    }

    async function finishRecovery({ nodeId, actor, backupId }, result) {
        if (!hex(nodeId, 24) || !bounded(actor) || !hex(backupId, 32) || !['absent', 'rolled_back'].includes(result)) throw fail('INVALID');
        const reply = await dbCall(() => collection.updateMany({ version: 1, state: 'spent', 'audit.result': 'consumed',
            'audit.nodeId': nodeId, 'audit.actor': actor, 'audit.backupId': backupId,
            'audit.recovery': { $exists: false } }, [{ $set: { 'audit.recovery': { at: '$$NOW', result: literal(result) } } }],
        { collation: SIMPLE, writeConcern: WRITE_CONCERN }));
        if (reply?.acknowledged !== true || reply.matchedCount !== reply.modifiedCount || reply.matchedCount > 1) throw fail('UNAVAILABLE');
    }

    return Object.freeze({ ensureIndexes, issue, consume, bind, finish, finishRecovery });
}

module.exports = { createRelayCleanupConsentStore };
