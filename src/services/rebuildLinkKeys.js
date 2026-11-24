'use strict';

const {
    createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes,
} = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');

const { linkSnapshot, keyEnvelopeField: FIELD, fullLinkRead } = require('./rebuildLinkSnapshot');
const { deriveX25519PublicKey, formatDecryption, formatEncryption } = require('../utils/xrayVlessWire');
const DOMAIN = 'celerity/rebuild/link-vless/v1';
const MODE = 'native', TICKET = '600s';
const SERVER = formatDecryption(MODE, TICKET);
const CLIENT = formatEncryption(MODE);
const batches = new WeakMap();
const missing = Symbol('no envelope');

class LinkKeyError extends Error {
    constructor(code) { super(code); this.code = code; }
}
const fail = code => new LinkKeyError(code);
const needsKey = link => (link.mode !== 'forward' || (link.tunnelProtocol ?? 'vless') === 'vless')
    && (link.tunnelSecurity ?? 'none') === 'none' && link.tunnelEncryption !== 'none';

function subkeys(env) {
    // Do not import config/cryptoService: no dotenv side effect, shared passphrase
    // cipher or legacy decryptSafe plaintext fallback. This is a required root.
    const root = env?.ENCRYPTION_KEY;
    if (typeof root !== 'string' || root.trim().length < 32) throw fail('REBUILD_LINK_KEY_UNAVAILABLE');
    const derive = purpose => Buffer.from(hkdfSync('sha256', root, DOMAIN, purpose, 32));
    return { wrap: derive('envelope'), seed: derive('legacy-seed') };
}

function decode(value, bytes) {
    if (typeof value !== 'string' || value.length !== Math.ceil(bytes * 4 / 3)) throw fail('REBUILD_LINK_KEY_INVALID');
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.length !== bytes || decoded.toString('base64url') !== value) throw fail('REBUILD_LINK_KEY_INVALID');
    return decoded;
}

function open(wrap, id, envelope) {
    let seed;
    try {
        if (typeof envelope !== 'string' || envelope.length !== 86) throw fail('REBUILD_LINK_KEY_INVALID');
        const [version, nonce, ciphertext, tag, extra] = envelope.split('.');
        if (version !== 'v1' || extra !== undefined) throw fail('REBUILD_LINK_KEY_INVALID');
        const cipher = createDecipheriv('aes-256-gcm', wrap, decode(nonce, 12), { authTagLength: 16 });
        cipher.setAAD(Buffer.from(`${DOMAIN}:${id}`));
        cipher.setAuthTag(decode(tag, 16));
        seed = cipher.update(decode(ciphertext, 32));
        cipher.final();
        return seed;
    } catch {
        seed?.fill(0);
        throw fail('REBUILD_LINK_KEY_INVALID');
    }
}

function seal(wrap, id, seed) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', wrap, nonce, { authTagLength: 16 });
    cipher.setAAD(Buffer.from(`${DOMAIN}:${id}`));
    const ciphertext = Buffer.concat([cipher.update(seed), cipher.final()]);
    return `v1.${[nonce, ciphertext, cipher.getAuthTag()].map(x => x.toString('base64url')).join('.')}`;
}

function keyFor(keys, id, envelope) {
    // Only an absent envelope uses the deterministic per-link bootstrap seed.
    // The immutable storage identity, not editable tunnel settings, owns it.
    return envelope === missing ? createHmac('sha256', keys.seed).update(id).digest() : open(keys.wrap, id, envelope);
}

function xraySettings(seed) {
    return Object.freeze({
        decryption: formatDecryption(MODE, TICKET, seed.toString('base64url')),
        encryption: formatEncryption(MODE, deriveX25519PublicKey(seed)),
    });
}

function tunnelSettings(link) {
    if (!needsKey(link)) return null;
    const keys = Object.hasOwn(link ?? {}, '_rebuildVless') && link._rebuildVless;
    const formatted = (value, prefix) => typeof value === 'string' && value.startsWith(prefix)
        && /^[A-Za-z0-9_-]{43}$/.test(value.slice(prefix.length));
    if (!formatted(keys?.decryption, SERVER) || !formatted(keys?.encryption, CLIENT)) {
        throw fail('REBUILD_LINK_KEY_NOT_PREPARED');
    }
    return { decryption: keys.decryption, encryption: keys.encryption };
}

async function readRows(Link, links, session, privateInventory = false) {
    if (!links.length) return [];
    const ids = links.map(link => String(link?._id));
    if (new Set(ids).size !== links.length || ids.some(id => !/^[a-f0-9]{24}$/.test(id))) throw fail('REBUILD_LINK_CHANGED');
    let rows;
    try {
        const filter = { _id: { $in: ids } };
        const query = (privateInventory ? Link.find(filter, null, fullLinkRead) : Link.find(filter).select(`+${FIELD}`)).read('primary');
        rows = await (session ? query.session(session) : query.readConcern('majority')).lean();
    } catch {
        throw fail('REBUILD_LINK_KEY_READ_FAILED');
    }
    if (!Array.isArray(rows)) throw fail('REBUILD_LINK_KEY_READ_FAILED');
    const byId = new Map(rows.map(row => [String(row._id), row]));
    return links.map((link, i) => {
        const row = byId.get(ids[i]);
        if (!row) throw fail('REBUILD_LINK_CHANGED');
        const draft = linkSnapshot(row), expected = linkSnapshot(link);
        const envelope = Object.hasOwn(draft, FIELD) ? draft[FIELD] : missing;
        if (!privateInventory) {
            delete draft[FIELD];
            delete expected[FIELD];
        }
        if (!isDeepStrictEqual(draft, expected)) {
            throw fail('REBUILD_LINK_CHANGED');
        }
        // Null, empty, malformed or undecryptable are never legacy absence.
        return { id: ids[i], envelope };
    });
}

async function checkGuard(verify) {
    try { await verify(); } catch { throw fail('REBUILD_LOCK_LOST'); }
}

/**
 * Read phase: pass the freshly read, unpopulated lean desired rows. Set
 * privateInventory when the inventory included fields hidden by the schema;
 * verify them too, but never return them with the prepared links. Use the
 * returned copies to compose candidates. No key writes occur in this phase.
 *
 * Apply phase: after version/capability, client-change and preview-ID checks,
 * pass that SAME returned array with { persist: true, verify, env }, under
 * the held rebuild lock and before activating profiles. Keep verify checks at
 * subsequent dispatch boundaries. Use the already-composed candidates.
 *
 * Keep these copies in the rebuild process. The non-enumerable _rebuildVless
 * is intentionally omitted by serialization and spreads; a composer that
 * projects links must explicitly carry it to the internal tunnel helpers.
 */
async function prepareLinks(Link, links, { persist = false, verify, env = process.env, privateInventory = false } = {}) {
    let keys;
    try {
        keys = links.some(needsKey) ? subkeys(env) : null;
        if (!persist) {
            const rows = await readRows(Link, links, undefined, privateInventory);
            const prepared = links.map((link, i) => {
                const copy = { ...link };
                delete copy[FIELD];
                delete copy.rebuildApplied;
                delete copy.classicLifecycleGrant;
                if (needsKey(link)) {
                    const { id, envelope: stored } = rows[i];
                    const seed = keyFor(keys, id, stored);
                    try { Object.defineProperty(copy, '_rebuildVless', { value: xraySettings(seed) }); }
                    finally { seed.fill(0); }
                }
                return Object.freeze(copy);
            });
            batches.set(prepared, { Link, rows, privateRows: privateInventory ? links.map(linkSnapshot) : null });
            return Object.freeze(prepared);
        }

        const batch = batches.get(links);
        if (batch?.Link !== Link) throw fail('REBUILD_LINK_KEY_NOT_PREPARED');
        if (typeof verify !== 'function') throw fail('REBUILD_LINK_KEY_APPLY_GUARD_REQUIRED');
        await checkGuard(verify);
        const hasMissing = batch.rows.some((row, i) => needsKey(links[i]) && row.envelope === missing);
        const confirm = async session => {
            const latest = await readRows(Link, batch.privateRows ?? links, session, batch.privateRows !== null);
            const writes = [];
            for (const [i, { id, envelope }] of latest.entries()) {
                if (envelope !== batch.rows[i].envelope) throw fail('REBUILD_LINK_CHANGED');
                if (!needsKey(links[i])) continue;
                const seed = keyFor(keys, id, envelope);
                try {
                    if (!isDeepStrictEqual(xraySettings(seed), tunnelSettings(links[i]))) {
                        throw fail('REBUILD_LINK_CHANGED');
                    }
                    if (envelope === missing) writes.push([id, seal(keys.wrap, id, seed)]);
                } finally { seed.fill(0); }
            }
            for (const [id, envelope] of writes) {
                await checkGuard(verify);
                // Working-field equality was checked inside the transaction.
                // A concurrent row mutation conflicts with this write, and the
                // existence CAS separately forbids overwriting any envelope.
                const result = await Link.updateOne({ _id: id, [FIELD]: { $exists: false } },
                    { $set: { [FIELD]: envelope } }, { session, timestamps: false, runValidators: true });
                if (result?.acknowledged === true && result.matchedCount === 0) throw fail('REBUILD_LINK_CHANGED');
                if (result?.acknowledged !== true || result.matchedCount !== 1 || result.modifiedCount !== 1) {
                    throw fail('REBUILD_LINK_KEY_STORE_FAILED');
                }
            }
            await checkGuard(verify);
        };
        if (hasMissing) {
            await Link.db.transaction(confirm, { readPreference: 'primary', readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' } });
            await checkGuard(verify);
        } else {
            await confirm();
        }
        return links;
    } catch (error) {
        if (error instanceof LinkKeyError) throw error;
        // No DB responses, ciphertext, plaintext, or raw crypto causes escape.
        throw fail(persist ? 'REBUILD_LINK_KEY_STORE_FAILED' : 'REBUILD_LINK_KEY_INVALID');
    } finally {
        keys?.seed.fill(0);
        keys?.wrap.fill(0);
    }
}

module.exports = { prepareLinks, tunnelSettings };
