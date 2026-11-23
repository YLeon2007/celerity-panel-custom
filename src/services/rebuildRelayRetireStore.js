'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { mongo: { BSON }, Types: { ObjectId } } = require('mongoose');
const { assertNoIncidentLinks } = require('./rebuildNodeDeleteGuard');
const { assertNoPendingRelayAccounts } = require('./rebuildRelayAccountsStore');
const { isPristine } = require('./rebuildRelayBackendStore');
const { inspectAccountSources } = require('./rebuildRelayAccountInventory');
const { collectionName: DIRECTORY, readDirectory, sameAccounts, writeDirectory, conflict } = require('./rebuildRelayDirectory');
const { GRANTS, RETIRED, authorityKeys, legacyBinding } = require('./rebuildRelayGrantStore');
const { relayListKey, parseRelayBindingList } = require('./rebuildRelayAuthorization');

const fail = code => Object.assign(new Error(code), { code });
const changed = () => fail('REBUILD_NODE_RETIRE_CHANGED');
const unavailable = () => fail('REBUILD_NODE_RETIRE_UNAVAILABLE');
const stateConflict = () => fail('REBUILD_NODE_RETIRE_STATE_CONFLICT');
const safe = cause => typeof cause?.code === 'string' && /^REBUILD_[A-Z0-9_]+(?![\s\S])/.test(cause.code)
    ? cause : [11000, 112].includes(cause?.code) ? changed() : unavailable();
const read = session => ({ maxTimeMS: 5000, ...(session ? { session } : {
    readPreference: 'primary', readConcern: { level: 'majority' },
}) });
const unpack = (raw, options) => raw == null ? null : BSON.deserialize(Buffer.from(raw, 'base64'), options);
const pack = raw => raw == null ? null : raw.toString('base64');
const one = async (collection, filter, session, options) => pack(await collection.findOne(filter, { ...read(session), raw: true, ...options }));
async function many(collection, filter, session, limit) {
    const rows = await collection.find(filter, { ...read(session), raw: true, sort: { _id: 1 }, limit: limit + 1 }).toArray();
    if (rows.length > limit) throw stateConflict();
    return rows.map(pack);
}
const requireOne = result => {
    if (result?.acknowledged !== true || result.deletedCount !== 1) throw changed();
};
async function deleteExact(collection, raw, session) {
    const row = unpack(raw, { promoteValues: false, bsonRegExp: true });
    requireOne(await collection.deleteOne({ _id: row._id, $expr: { $eq: ['$$ROOT', { $literal: row }] } },
        { session, collation: { locale: 'simple' } }));
}

const simple = { locale: 'simple' };
const exactBson = { promoteValues: false, bsonRegExp: true };
const leaf = path => ({ type: { $type: path }, value: path });
const list = (path, item) => ({ type: { $type: path }, value: { $cond: [
    { $isArray: path }, { $map: { input: path, as: 'item', in: item('$$item') } }, path,
] } });
// A telemetry-only object (e.g. freshly created accessLogs) adds no authority
// leaves. Explicit null and malformed non-object containers remain distinct.
const section = (path, keys, children = {}) => ({ $cond: [
    { $in: [{ $type: path }, ['object', 'missing']] }, { type: 'object', value: {
        ...Object.fromEntries(keys.map(key => [key, leaf(`${path}.${key}`)])),
        ...Object.fromEntries(Object.entries(children).map(([key, build]) => [key, build(`${path}.${key}`)])),
    } }, leaf(path),
] });

// HyNode authority for Retire/Remove and the Rebuild graph: legacy and current
// roles, endpoint (including both SSH credentials), group user selection and
// the client MAIN profile. Include published/provisioned Xray credentials and
// access-log auth and its applied config receipt. Timer/callback writers:
// syncService: status, healthFailures, lastError, lastSync, onlineUsers,
// traffic.{tx,rx,lastUpdate}, agentStatus/LastSeen/Version, xrayVersion;
// accessLogs: status, lastError, lastReconcileAt, lastBatchAt (spoolBytes /
// droppedEvents are also observations). Mongoose adds updatedAt. The 5s Xray
// poll updates the online cache; cascade health / chart jobs write other rows.
// L2TP routing, install identity and account authority live in separate rows;
// those still use full BSON, not this card projection.
const inboundFields = [
    'inboundTag', 'transport', 'security', 'flow', 'fingerprint',
    'realityDest', 'realityPrivateKey', 'realityPublicKey', 'realitySpiderX',
    'wsPath', 'wsHost', 'grpcServiceName', 'xhttpPath', 'xhttpHost', 'xhttpMode', 'fallbackDest',
];
const values = path => list(path, leaf);
const inboundLists = { alpn: values, fingerprintPool: values, realitySni: values, realityShortIds: values };
const nodeImage = section('$$ROOT', [
    '_id', 'name', 'type', 'active', 'cascadeRole', 'role', 'ip', 'domain', 'sni', 'port', 'useCustomConfig',
], {
    groups: values, aclRules: values,
    ssh: path => section(path, ['port', 'username', 'privateKey', 'password']),
    xray: path => section(path, [...inboundFields, 'tlsSource', 'acmeEmail', 'manualCert', 'manualKey',
        'apiPort', 'agentPort', 'agentToken', 'agentTls'], {
        ...inboundLists,
        extraInbounds: path => list(path, entry => section(entry, [...inboundFields, 'id', 'label', 'uniqueName', 'port'], inboundLists)),
        accessLogs: path => section(path, ['enabled', 'ingestTokenEncrypted', 'ingestTokenHash', 'appliedFingerprint']),
    }),
});
// Computed inclusion projection: no Mongoose defaults/casting, no implicit
// array traversal, and a missing value has its own type (not BSON null).
const readNode = (collection, _id, session) => one(collection, { _id }, session, {
    projection: { _id: 1, image: nodeImage }, collation: simple,
});
async function deleteNode(collection, _id, raw, session) {
    // Re-read at the write boundary in the same transaction. Raw equality also
    // checks wire distinctions Mongo's value comparator can equate (e.g. -0).
    // A concurrent write to this document after the snapshot conflicts on delete.
    if (await readNode(collection, _id, session) !== raw) throw changed();
    const expected = unpack(raw, exactBson);
    // Do not use a lossy decoded image as a query operand (e.g. BSON undefined).
    if (pack(BSON.serialize(expected)) !== raw) throw unavailable();
    requireOne(await collection.deleteOne({ _id, $expr: { $eq: [nodeImage, { $literal: expected.image }] } },
        { session, collation: simple }));
}

// Internal graph finalizer only. The caller owns the Rebuild writer/node locks,
// remote proofs, graph link CAS, session/transaction, and cache publication.
function createRetireStore({ Link, Node, State, L2tpUser, env = process.env }) {
    const db = Node.db;
    const HyUser = db?.models?.HyUser ?? require('../models/hyUserModel');
    if (!db || [Link, State, L2tpUser, HyUser].some(model => model.db !== db)) throw unavailable();
    const images = new WeakMap();
    const readEnv = () => Object.fromEntries([...authorityKeys, 'C3_REBUILD_L2TP_INSTALL_ENABLED', 'C3_REBUILD_ENABLED', 'ENCRYPTION_KEY']
        .filter(key => Object.hasOwn(env, key)).map(key => [key, env[key]]));

    async function view(id, session, expectedNode) {
        await assertNoPendingRelayAccounts(db, session);
        const config = readEnv();
        const _id = new ObjectId(id), refs = { $in: [_id, id] };
        const node = await readNode(Node.collection, _id, session);
        // A former relay changing role (or disappearing) is definite drift
        // on recheck; on the first preview it simply is not an eligible target.
        if (expectedNode !== undefined && node !== expectedNode) return null;
        const card = unpack(node)?.image?.value;
        if (card?.type?.value !== 'xray' || card.cascadeRole?.value !== 'relay') throw stateConflict();
        const states = await many(State.collection, { node: refs }, session, 1);
        const accounts = await many(L2tpUser.collection, { relayNode: refs }, session, 2048);
        const grants = db.collection(GRANTS), retired = db.collection(RETIRED);
        const grantRows = await many(grants, { nodeId: id }, session, 1);
        if (await one(retired, { _id: id }, session)) throw changed();
        const singleton = Object.hasOwn(config, relayListKey) ? undefined : legacyBinding(config);
        if (Object.hasOwn(config, relayListKey)) parseRelayBindingList(config[relayListKey], unavailable, { checkUniqueness: false });

        // Same no-downgrade gate as revoking the last DB grant. Do not put a
        // remaining live legacy singleton back on the bootstrap-only ABI.
        if (grantRows.length && singleton && singleton.nodeId !== id && !await one(retired, { _id: singleton.nodeId }, session)
            && !await grants.findOne({ nodeId: { $ne: id } }, { ...read(session), projection: { _id: 1 } })) {
            const ref = { $in: [new ObjectId(singleton.nodeId), singleton.nodeId] };
            const options = { ...read(session), projection: { _id: 1 } };
            if (await State.collection.findOne({ node: ref, $nor: [{ status: 'not_installed', desiredState: 'absent' }] }, options)
                || await L2tpUser.collection.findOne({ relayNode: ref }, options)) throw fail('REBUILD_L2TP_GRANT_LEGACY_SINGLETON_IN_USE');
        }

        const directory = await one(db.collection(DIRECTORY), { _id: 'directory' }, session);
        const catalog = directory === null ? null : await readDirectory(db, session);
        if (!equal(unpack(directory), catalog)) throw changed();
        const state = unpack(states[0]);
        let sources, backfill;
        if (accounts.length || !isPristine(state)) {
            // An owned, settled install has a bootstrap and a complete synced
            // projection. An arbitrary operation/partial install is not ours.
            if (!state || state.status !== 'installed' || state.desiredState !== 'installed') throw stateConflict();
            if (catalog) {
                const { legacy } = inspectAccountSources({ rows: { states: [state], users: accounts.map(row => unpack(row)) }, listMode: true });
                if (!legacy || !sameAccounts(catalog.accounts, legacy)) throw conflict();
            } else {
                // No canonical directory: compare the complete legacy cohort,
                // ordered by persisted _id so the chosen logical IDs are stable.
                sources = {
                    states: await many(State.collection, {}, session, 1024),
                    users: await many(L2tpUser.collection, {}, session, 65536),
                };
                if (!equal(sources.states.filter(row => String(unpack(row).node) === id), states)
                    || !equal(sources.users.filter(row => String(unpack(row).relayNode) === id), accounts)) throw changed();
                backfill = inspectAccountSources({ rows: {
                    states: sources.states.map(row => unpack(row)), users: sources.users.map(row => unpack(row)),
                }, listMode: true }).legacy;
                if (!backfill) throw conflict();
            }
        }
        if (!equal(config, readEnv())) throw changed();
        return { id, node, states, accounts, grantRows, config, directory, sources, backfill };
    }

    async function capture(nodeId) {
        try {
            const id = String(nodeId).toLowerCase();
            if (!/^[a-f0-9]{24}$/.test(id)) throw stateConflict();
            const image = await view(id);
            const token = Object.freeze(Object.create(null));
            images.set(token, image);
            return token;
        } catch (cause) { throw safe(cause); }
    }

    // Immutable BSON images: only the node card uses the authority projection.
    // Other rows include hidden/unknown fields and preserve field order. Query
    // row order is normalized by _id. The graph caller owns/fences links.
    // Only same-store tokens compare; neither raw data nor fingerprints escape.
    function sameSnapshot(a, b) {
        return images.has(a) && images.has(b) && equal(images.get(a), images.get(b));
    }

    const matchesNode = (snapshot, raw) => images.has(snapshot) && images.get(snapshot).node === raw;
    async function isCurrent(snapshot) {
        try {
            const before = images.get(snapshot);
            return !!before && equal(await view(before.id, undefined, before.node), before);
        } catch (cause) { throw safe(cause); }
    }

    async function finish(snapshot, session, verify) {
        let joined = false;
        try {
            const before = images.get(snapshot);
            if (!before || typeof verify !== 'function' || session?.client !== db.getClient() || !session.inTransaction()) throw unavailable();
            // No retry of a finalizer with a previously consumed capability.
            images.delete(snapshot);
            joined = true;
            const check = async () => {
                if (await verify() === false || !session.inTransaction()) throw fail('REBUILD_LOCK_LOST');
                if (!equal(before.config, readEnv())) throw changed();
            };
            await check();
            await assertNoIncidentLinks(Link, before.id, session);
            if (!equal(await view(before.id, session, before.node), before)) throw changed();
            await check();
            if (before.backfill) await writeDirectory(db, null, before.backfill, session);
            for (const raw of before.accounts) await deleteExact(L2tpUser.collection, raw, session);
            for (const raw of before.states) await deleteExact(State.collection, raw, session);
            for (const raw of before.grantRows) await deleteExact(db.collection(GRANTS), raw, session);
            // Node-ID tombstones suppress both ENV formats after restart, without
            // reserving the endpoint or changing process.env. DB grants are gone.
            const retired = await db.collection(RETIRED).insertOne({ _id: before.id }, { session });
            if (retired?.acknowledged !== true) throw unavailable();
            const node = { $in: [new ObjectId(before.id), before.id] };
            if ((await HyUser.collection.updateMany({ nodes: node }, { $pull: { nodes: node } }, { session }))?.acknowledged !== true) throw unavailable();
            await deleteNode(Node.collection, new ObjectId(before.id), before.node, session);
            await check();
        } catch (cause) {
            // A consumed finalizer failure also cancels the staged graph
            // writes. The caller still owns session cleanup and must not commit.
            try { if (joined && session.inTransaction()) await session.abortTransaction(); }
            catch { /* Keep the primary refusal. */ }
            throw safe(cause);
        }
    }

    return Object.freeze({ capture, sameSnapshot, matchesNode, isCurrent, finish });
}

// Build transport input from the very same observation we compare. No second
// endpoint query and no raw card or health sample can select the target.
function probeCard(raw) {
    const card = unpack(raw)?.image?.value;
    if (!card || card.ssh?.type !== 'object' || card.xray?.type !== 'object') throw unavailable();
    const pick = (section, keys) => Object.fromEntries(keys.filter(key => Object.hasOwn(section[key], 'value'))
        .map(key => [key, section[key].value]));
    return { ...pick(card, ['_id', 'name', 'ip', 'type', 'role', 'cascadeRole', 'useCustomConfig']),
        ssh: pick(card.ssh.value, ['port', 'username', 'password', 'privateKey']),
        xray: pick(card.xray.value, ['agentTls', 'agentPort', 'agentToken']) };
}

module.exports = { createRetireStore, readNode, probeCard };
