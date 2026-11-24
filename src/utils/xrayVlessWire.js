'use strict';

const { createPrivateKey, createPublicKey } = require('node:crypto');

const PREFIX = 'mlkem768x25519plus';
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

function deriveX25519PublicKey(seed) {
    const der = Buffer.concat([X25519_PKCS8_PREFIX, seed]);
    try {
        const priv = createPrivateKey({ key: der, type: 'pkcs8', format: 'der' });
        return createPublicKey(priv).export({ format: 'jwk' }).x;
    } finally {
        der.fill(0);
    }
}

const formatDecryption = (mode, ticket, key = '') => `${PREFIX}.${mode}.${ticket}.${key}`;
const formatEncryption = (mode, key = '') => `${PREFIX}.${mode}.0rtt.${key}`;

module.exports = { PREFIX, deriveX25519PublicKey, formatDecryption, formatEncryption };
