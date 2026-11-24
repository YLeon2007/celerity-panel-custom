'use strict';

// Shared by the active-node cache and settled publication reader. Keep server
// configuration (including VLESS/REALITY private keys, TLS keys and agent
// credentials) out of both boundaries, even if new fields are added to xray.
const INBOUND_FIELDS = [
    'transport', 'security', 'flow', 'fingerprint', 'fingerprintPool', 'alpn',
    'realityPublicKey', 'realitySni', 'realityShortIds', 'realitySpiderX',
    'wsPath', 'wsHost', 'grpcServiceName', 'xhttpPath', 'xhttpHost', 'xhttpMode',
    'vlessEncryption', 'vlessEncryptionAuth', 'vlessEncryptionMode', 'vlessEncryptionPublicKey',
];
const MAIN_FIELDS = [...INBOUND_FIELDS, 'tlsSource'];
const EXTRA_FIELDS = [...INBOUND_FIELDS, 'port', 'label', 'uniqueName'];

function pick(source, fields) {
    return Object.fromEntries(fields.filter(field => source[field] !== undefined).map(field => [field, source[field]]));
}

function projectSubscriptionXray(xray) {
    const projected = pick(xray, MAIN_FIELDS);
    if (Array.isArray(xray.extraInbounds)) {
        projected.extraInbounds = xray.extraInbounds.map(inbound => inbound && pick(inbound, EXTRA_FIELDS));
    }
    return projected;
}

module.exports = { projectSubscriptionXray };
