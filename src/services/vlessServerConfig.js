'use strict';

const { redactKcpConfigValue } = require('../utils/cascadeTransport');
const { PRIVATE_KEY_SELECT, hasEnabledInbound } = require('../utils/vlessEncryption');

const KEY = 'vlessEncryptionPrivateKey';
const PUBLIC = 'vlessEncryptionPublicKey';
const KEY_PROJECTION = [
    ...PRIVATE_KEY_SELECT.trim().split(/\s+/).map(path => path.replace(/^\+/, '')),
    `xray.${PUBLIC}`, `xray.extraInbounds.id`, `xray.extraInbounds.${PUBLIC}`,
].join(' ');

/** Load only secrets for the generator, never enrich the caller's node object. */
async function loadVlessServerKeys(node, Node = require('../models/hyNodeModel')) {
    if (!hasEnabledInbound(node?.xray)) return node;
    // Read by identity and join the key to the published half from the input
    // snapshot. A rotation between reads must fail closed, not mix key pairs.
    let fresh;
    try {
        fresh = await Node.findById(node._id).select(KEY_PROJECTION)
            .read('primary').readConcern('majority').maxTimeMS(5000).lean();
    } catch {
        throw Object.assign(new Error('Could not load VLESS Encryption server keys.'), { code: 'VLESS_ENCRYPTION_KEY_INVALID' });
    }
    const plain = typeof node.toObject === 'function' ? node.toObject({ transform: false }) : node;
    const xray = { ...plain.xray };
    const copyKey = (inbound, stored) => {
        if (inbound.vlessEncryption === true) {
            inbound[KEY] = inbound[PUBLIC] && inbound[PUBLIC] === stored?.[PUBLIC] ? stored[KEY] : undefined;
        }
        return inbound;
    };
    const extras = new Map();
    for (const row of fresh?.xray?.extraInbounds ?? []) {
        if (row?.id) extras.set(row.id, extras.has(row.id) ? null : row);
    }
    if (Array.isArray(xray.extraInbounds)) {
        xray.extraInbounds = xray.extraInbounds.map(inbound => copyKey({ ...inbound }, extras.get(inbound.id)));
    }
    return { ...plain, xray: copyKey(xray, fresh?.xray) };
}

/** Management display is not a config export. Never return unparsed Xray text. */
function redactXrayConfig(text) {
    // Parse errors in Node can quote the input; do not propagate them.
    const invalid = () => new Error('Could not read Xray configuration safely.');
    let config;
    try { config = JSON.parse(text); } catch { throw invalid(); }
    if (!config || typeof config !== 'object' || Array.isArray(config)
        || (config.inbounds != null && !Array.isArray(config.inbounds))) throw invalid();
    // Go's JSON decoder also accepts mixed-case field names. Strip decryption
    // members (including the internal reverse listener) from the display only.
    return JSON.stringify(config, (key, value) => {
        const field = key.toLowerCase();
        if (field === 'vlessencryptionprivatekey' || (field === 'decryption' && value !== 'none')) return '<redacted>';
        return redactVlessDiagnostics(redactKcpConfigValue(key, value));
    }, 2);
}

// Xray may echo the complete decryption value in runtime diagnostics. The
// `0rtt` form is the published client value, not the server secret.
function redactVlessDiagnostics(text) {
    return typeof text === 'string' ? text.replace(
        /mlkem768x25519plus\.[A-Za-z0-9_-]+\.(?!0rtt\.)[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+/g,
        '<redacted VLESS decryption>',
    ) : text;
}

module.exports = { loadVlessServerKeys, redactXrayConfig, redactVlessDiagnostics };
