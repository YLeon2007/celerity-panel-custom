'use strict';

const crypto = require('node:crypto');
const { PREFIX, deriveX25519PublicKey, formatDecryption, formatEncryption } = require('./xrayVlessWire');
const { t } = require('../middleware/i18n');

const MIN_XRAY_VERSION = '25.9.5';
const AUTH_VALUES = Object.freeze(['x25519', 'mlkem768']);
const MODE_VALUES = Object.freeze(['native', 'xorpub', 'random']);
const DEFAULT_AUTH = 'x25519', DEFAULT_MODE = 'native', DEFAULT_TICKET = '600s';
const MAX_TICKET_SECONDS = 86400;
const MAIN_ID = 'main';
const ENABLED = 'vlessEncryption', AUTH = 'vlessEncryptionAuth', MODE = 'vlessEncryptionMode', TICKET = 'vlessEncryptionTicket';
const PRIVATE = 'vlessEncryptionPrivateKey', PUBLIC = 'vlessEncryptionPublicKey', REGEN = 'vlessEncryptionRegenerate';
const FIELDS = Object.freeze([ENABLED, AUTH, MODE, TICKET, PRIVATE, PUBLIC]);
const PRIVATE_PATHS = [`xray.${PRIVATE}`, `xray.extraInbounds.${PRIVATE}`];
const PRIVATE_KEY_EXCLUDE = PRIVATE_PATHS.map(p => `-${p}`).join(' ');
const PRIVATE_KEY_SELECT = PRIVATE_PATHS.map(p => `+${p}`).join(' ');
const KEY_BYTES = Object.freeze({ x25519: Object.freeze({ server: 32, client: 32 }),
    mlkem768: Object.freeze({ server: 64, client: 1184 }) });

// Independent of SSH/password wrapping and of celerity/rebuild/link-vless/v1.
// AAD binds the authenticated binary seed to this domain and its algorithm.
const DOMAIN = 'celerity/xray/client-inbound-vless/v1';
// ID id-alg-ml-kem-768; PKCS#8 privateKey is an OCTET STRING containing seed [0].
const MLKEM_PKCS8_SEED = Buffer.from('3054020100300b060960864801650304040204428040', 'hex');
const MLKEM_SPKI = Buffer.from('308204b2300b0609608648016503040402038204a100', 'hex');
const MLKEM_UNAVAILABLE = 'VLESS_ENCRYPTION_MLKEM_UNAVAILABLE';
const INVALID = 'VLESS_ENCRYPTION_KEY_INVALID';
const ROOT_UNAVAILABLE = 'VLESS_ENCRYPTION_ROOT_UNAVAILABLE';

// Use only literal message keys and validated version/position or fixed parameters.
// Background callers without a request keep their existing English diagnostics.
function message(translate, key, params = {}) {
    const path = `nodes.xrayVlessEnc${key}`;
    return (translate?.(path) ?? t(path, 'en')).replace(/\{(\w+)\}/g,
        (token, name) => Object.hasOwn(params, name) ? params[name] : token);
}

function keyMessage(code, translate) {
    return message(translate, code === MLKEM_UNAVAILABLE ? 'MlkemUnavailable'
        : code === ROOT_UNAVAILABLE ? 'KeyStorageUnavailable' : 'KeyInvalid');
}

function keyError(code = INVALID) {
    return Object.assign(new Error(keyMessage(code)), { code });
}

function normalizeTicket(value) {
    if (value === undefined || value === null) return DEFAULT_TICKET;
    if (typeof value !== 'string') return null;
    const raw = value.trim().toLowerCase();
    if (!raw) return DEFAULT_TICKET;
    const match = /^(\d{1,5})(?:-(\d{1,5}))?s$/.exec(raw);
    if (!match) return null;
    const from = Number(match[1]);
    if (match[2] === undefined) return from <= MAX_TICKET_SECONDS ? `${from}s` : null;
    const to = Number(match[2]);
    return from >= 1 && to >= from && to <= MAX_TICKET_SECONDS ? `${from}-${to}s` : null;
}

function decode(value, bytes) {
    if (typeof value !== 'string' || value.length !== Math.ceil(bytes * 4 / 3)) throw keyError();
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.length === bytes && decoded.toString('base64url') === value) return decoded;
    decoded.fill(0);
    throw keyError();
}

function wrapKey() {
    // No config/dotenv import and no legacy plaintext fallback.
    const root = process.env.ENCRYPTION_KEY;
    if (typeof root !== 'string' || root.trim().length < 32) throw keyError(ROOT_UNAVAILABLE);
    return Buffer.from(crypto.hkdfSync('sha256', root, DOMAIN, 'envelope', 32));
}

function seal(auth, seed) {
    const key = wrapKey();
    try {
        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
        cipher.setAAD(`${DOMAIN}:${auth}`, { encoding: 'utf8' });
        const ciphertext = Buffer.concat([cipher.update(seed), cipher.final()]);
        return `v1.${[nonce, ciphertext, cipher.getAuthTag()].map(x => x.toString('base64url')).join('.')}`;
    } finally {
        key.fill(0);
    }
}

function open(auth, envelope) {
    const bytes = KEY_BYTES[auth].server;
    if (typeof envelope !== 'string' || envelope.length !== 43 + Math.ceil(bytes * 4 / 3)) throw keyError();
    const [version, nonce, ciphertext, tag, extra] = envelope.split('.');
    if (version !== 'v1' || extra !== undefined) throw keyError();
    const key = wrapKey();
    let seed;
    try {
        const cipher = crypto.createDecipheriv('aes-256-gcm', key, decode(nonce, 12), { authTagLength: 16 });
        cipher.setAAD(`${DOMAIN}:${auth}`, { encoding: 'utf8' });
        cipher.setAuthTag(decode(tag, 16));
        seed = cipher.update(decode(ciphertext, bytes));
        cipher.final();
        return seed;
    } catch {
        seed?.fill(0);
        throw keyError();
    } finally {
        key.fill(0);
    }
}

let mlkemNativeUnavailable = false;

function deriveMLKEMNative(seed) {
    const der = Buffer.concat([MLKEM_PKCS8_SEED, seed]);
    try {
        let privateKey;
        try {
            privateKey = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
        } catch (error) {
            // The exact seed-only DER format is unsupported on Node 20/OpenSSL 3.0.
            // Only that capability failure selects the portable provider.
            if (error.code === 'ERR_OSSL_UNSUPPORTED') return null;
            throw error;
        }
        const spki = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
        if (spki.length !== MLKEM_SPKI.length + KEY_BYTES.mlkem768.client
            || !spki.subarray(0, MLKEM_SPKI.length).equals(MLKEM_SPKI)) throw keyError(MLKEM_UNAVAILABLE);
        return spki.subarray(MLKEM_SPKI.length).toString('base64url');
    } finally {
        der.fill(0);
    }
}

function derive(auth, seed) {
    if (auth === 'x25519') return deriveX25519PublicKey(seed);
    try {
        if (!mlkemNativeUnavailable) {
            const publicKey = deriveMLKEMNative(seed);
            if (publicKey !== null) return publicKey;
            mlkemNativeUnavailable = true;
        }
        // The portable Go build is not a validated FIPS module.
        if (!crypto.getFips()) return require('./mlkem768Portable')(seed);
    } catch {
        // Do not expose provider, artifact path, or key details.
    }
    throw keyError(MLKEM_UNAVAILABLE);
}

async function deriveClientKey(auth, serverKey) {
    if (!AUTH_VALUES.includes(auth)) throw keyError();
    const seed = decode(serverKey, KEY_BYTES[auth].server);
    try {
        return derive(auth, seed);
    } catch (error) {
        throw keyError(error.code === MLKEM_UNAVAILABLE ? MLKEM_UNAVAILABLE : INVALID);
    } finally {
        seed.fill(0);
    }
}

function generate(auth) {
    const seed = crypto.randomBytes(KEY_BYTES[auth].server);
    try {
        const clientKey = derive(auth, seed);
        return { [PRIVATE]: seal(auth, seed), [PUBLIC]: clientKey };
    } finally {
        seed.fill(0);
    }
}

const hasStoredMaterial = inbound => inbound?.[ENABLED] === true
    || inbound?.[PRIVATE] !== undefined || inbound?.[PUBLIC] !== undefined;
const inherited = (next, prev, name, fallback) => next[name] !== undefined ? next[name]
    : prev?.[name] !== undefined ? prev[name] : fallback;
function conflictsWithFallback(inbound, prev) {
    const fallback = inbound.fallbackDest ?? prev?.fallbackDest ?? '';
    return (inbound.transport ?? prev?.transport ?? 'tcp') === 'tcp'
        && (inbound.security ?? prev?.security) === 'tls' && (typeof fallback !== 'string' || !!fallback.trim());
}

// Settle only feature fields. Validating the previous pair before an auth
// switch also prevents corrupted/unselected keys becoming an implicit rotation.
function settle(next, prev, regenerate, translate) {
    const enabled = inherited(next, prev, ENABLED, false);
    if (typeof enabled !== 'boolean') return message(translate, 'EnabledInvalid');
    const stored = hasStoredMaterial(prev);
    if (!enabled) {
        if (!stored) return {};
        // Disable is always possible, even if the root/runtime or key has
        // become unusable. Keep dormant keys/settings; don't rekey while off.
        return { [ENABLED]: false, ...Object.fromEntries(FIELDS.slice(1)
            .filter(name => prev[name] !== undefined).map(name => [name, prev[name]])) };
    }
    const auth = inherited(next, prev, AUTH, DEFAULT_AUTH);
    const mode = inherited(next, prev, MODE, DEFAULT_MODE);
    const ticket = normalizeTicket(inherited(next, prev, TICKET, DEFAULT_TICKET));
    if (!AUTH_VALUES.includes(auth)) return message(translate, 'AuthInvalid');
    if (!MODE_VALUES.includes(mode)) return message(translate, 'ModeInvalid');
    if (!ticket) return message(translate, 'TicketFormatInvalid', { max: MAX_TICKET_SECONDS });
    if (conflictsWithFallback(next, prev)) {
        return message(translate, 'ClearFallback');
    }
    const settings = { [ENABLED]: true, [AUTH]: auth, [MODE]: mode, [TICKET]: ticket };
    try {
        if (stored && !regenerate) {
            const oldAuth = prev[AUTH];
            if (!AUTH_VALUES.includes(oldAuth)) throw keyError();
            const seed = open(oldAuth, prev[PRIVATE]);
            try {
                if (derive(oldAuth, seed) !== prev[PUBLIC]) throw keyError();
            } finally {
                seed.fill(0);
            }
            if (auth === oldAuth) return { ...settings, [PRIVATE]: prev[PRIVATE], [PUBLIC]: prev[PUBLIC] };
        }
        return { ...settings, ...generate(auth) };
    } catch (error) {
        return keyMessage(error?.code, translate);
    }
}

function commit(inbound, fields) {
    for (const name of [...FIELDS, REGEN]) delete inbound[name];
    Object.assign(inbound, fields);
}

async function applyVlessEncryption(next, prev, { regenerate = false, label = 'Inbound' } = {}) {
    if (!next) return null;
    const result = settle(next, prev, regenerate === true);
    if (typeof result === 'string') return `${label}: ${result}`;
    commit(next, result);
    return null;
}

const extrasOf = xray => Array.isArray(xray?.extraInbounds) ? xray.extraInbounds : [];
const stableExtraId = item => typeof item?.id === 'string' && item.id.trim() && item.id !== MAIN_ID ? item.id : null;

/** Prepare a plain Xray write candidate against the privately projected stored Xray object.
 * Call versionError(candidate, trustedHealthVersion) before persisting the result.
 * When extras are omitted this is a main-field-only patch, not an array replacement.
 */
async function applyVlessEncryptionToXray(nextXray, prevXray, regenerateIds = [], translate) {
    if (!nextXray) return null;
    const regenerate = new Set(typeof regenerateIds !== 'string' && typeof regenerateIds?.[Symbol.iterator] === 'function'
        ? regenerateIds : []);
    const pending = [];
    const main = settle(nextXray, prevXray, regenerate.has(MAIN_ID), translate);
    if (typeof main === 'string') return message(translate, 'MainError', { message: main });
    pending.push([nextXray, main]);

    const extras = extrasOf(nextXray);
    const previous = new Map();
    const ambiguous = new Set();
    for (const item of extrasOf(prevXray)) {
        const id = stableExtraId(item);
        if (!id) continue;
        if (previous.has(id) && (hasStoredMaterial(item) || hasStoredMaterial(previous.get(id)))) ambiguous.add(id);
        previous.set(id, item);
    }
    const counts = new Map();
    for (const item of extras) {
        const id = stableExtraId(item);
        counts.set(id, (counts.get(id) || 0) + 1);
    }
    for (const [i, inbound] of extras.entries()) {
        const extraError = error => message(translate, 'ExtraError', { number: i + 1, message: error });
        if (!inbound || typeof inbound !== 'object' || Array.isArray(inbound)) {
            return extraError(message(translate, 'InboundInvalid'));
        }
        const id = stableExtraId(inbound);
        if (ambiguous.has(id) || ((inbound[ENABLED] === true || hasStoredMaterial(previous.get(id)) || regenerate.has(id))
            && (!id || counts.get(id) !== 1))) {
            return extraError(message(translate, 'InboundIdInvalid'));
        }
        const result = settle(inbound, previous.get(id), regenerate.has(id), translate);
        if (typeof result === 'string') return extraError(result);
        pending.push([inbound, result]);
    }
    for (const [inbound, fields] of pending) commit(inbound, fields);
    return null;
}

function takeRegenerateIds(xray) {
    if (!xray || typeof xray !== 'object') return [];
    const ids = xray[REGEN] === true ? [MAIN_ID] : [];
    delete xray[REGEN];
    for (const inbound of extrasOf(xray)) {
        if (!inbound || typeof inbound !== 'object') continue;
        if (inbound[REGEN] === true && stableExtraId(inbound)) ids.push(inbound.id);
        delete inbound[REGEN];
    }
    return ids;
}

function buildServerDecryption(inbound, { redactSecrets = false } = {}) {
    if (inbound?.[ENABLED] !== true) return 'none';
    const auth = inbound[AUTH], mode = inbound[MODE], ticket = normalizeTicket(inbound[TICKET]);
    if (redactSecrets === true) return formatDecryption(MODE_VALUES.includes(mode) ? mode : DEFAULT_MODE, ticket || DEFAULT_TICKET, '<redacted>');
    if (!AUTH_VALUES.includes(auth) || !MODE_VALUES.includes(mode) || !ticket || conflictsWithFallback(inbound)) throw keyError();
    let seed;
    try {
        seed = open(auth, inbound[PRIVATE]);
        // Upstream's main emitter does not project the public field. Where
        // supplied, refuse mismatches rather than serving inconsistent keys.
        if (inbound[PUBLIC] !== undefined && derive(auth, seed) !== inbound[PUBLIC]) throw keyError();
        return formatDecryption(mode, ticket, seed.toString('base64url'));
    } catch {
        throw keyError();
    } finally {
        seed?.fill(0);
    }
}

function buildClientEncryption(inbound) {
    if (inbound?.[ENABLED] !== true || !AUTH_VALUES.includes(inbound[AUTH]) || !MODE_VALUES.includes(inbound[MODE])) return null;
    try {
        decode(inbound[PUBLIC], KEY_BYTES[inbound[AUTH]].client);
        return formatEncryption(inbound[MODE], inbound[PUBLIC]);
    } catch {
        return null;
    }
}

function hasEnabledInbound(xray) {
    return xray?.[ENABLED] === true || extrasOf(xray).some(inbound => inbound?.[ENABLED] === true);
}

/** Only pass health-observed xrayVersion, never the request body's value.
 * cc-agent supplies the bare release token from `xray version`, not its banner.
 */
function versionError(xray, version, _nodeName = 'node', translate) {
    if (!hasEnabledInbound(xray)) return null;
    const match = typeof version === 'string' && /^v?(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})$/.exec(version);
    if (!match || match[0] !== version) return message(translate, 'HealthUnknown', { minimum: MIN_XRAY_VERSION });
    const observed = match.slice(1).map(Number);
    const minimum = MIN_XRAY_VERSION.split('.').map(Number);
    const firstDifference = observed.findIndex((part, i) => part !== minimum[i]);
    return firstDifference !== -1 && observed[firstDifference] < minimum[firstDifference]
        ? message(translate, 'HealthOld', { minimum: MIN_XRAY_VERSION, observed: observed.join('.') }) : null;
}

function stripVlessEncryptionKeys(xray, { keepPublic = false } = {}) {
    if (!xray) return xray;
    const strip = inbound => {
        delete inbound[PRIVATE];
        if (!keepPublic) delete inbound[PUBLIC];
        delete inbound[REGEN];
        return inbound;
    };
    strip(xray);
    if (Array.isArray(xray.extraInbounds)) {
        xray.extraInbounds = xray.extraInbounds.map(item => item && strip(
            typeof item.toObject === 'function' ? item.toObject() : { ...item }));
    }
    return xray;
}

function redactNode(node) {
    if (!node) return node;
    const plain = typeof node.toObject === 'function' ? node.toObject() : { ...node };
    if (plain.xray) plain.xray = stripVlessEncryptionKeys(typeof plain.xray.toObject === 'function'
        ? plain.xray.toObject() : { ...plain.xray }, { keepPublic: true });
    return plain;
}

module.exports = {
    PREFIX, MIN_XRAY_VERSION, AUTH_VALUES, MODE_VALUES, DEFAULT_AUTH, DEFAULT_MODE, DEFAULT_TICKET, KEY_BYTES,
    FIELDS, PRIVATE_KEY_EXCLUDE, PRIVATE_KEY_SELECT, message,
    normalizeTicket, applyVlessEncryption, applyVlessEncryptionToXray, takeRegenerateIds,
    buildServerDecryption, buildClientEncryption, hasEnabledInbound, versionError,
    stripVlessEncryptionKeys, redactNode, deriveClientKey,
};
