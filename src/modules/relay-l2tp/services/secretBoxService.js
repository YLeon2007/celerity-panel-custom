'use strict';

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;

function deriveKey(key) {
    if (typeof key !== 'string' || key.length === 0) {
        throw new TypeError('key must be a non-empty string');
    }

    return crypto.createHash('sha256').update(key, 'utf8').digest();
}

function encrypt(plaintext, key) {
    if (typeof plaintext !== 'string' || plaintext.length === 0) {
        throw new TypeError('plaintext must be a non-empty string');
    }

    const iv = crypto.randomBytes(IV_BYTES);
    const cipher = crypto.createCipheriv(ALGORITHM, deriveKey(key), iv);
    const ciphertext = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    return `v1:${iv.toString('hex')}:${tag.toString('hex')}:${ciphertext.toString('hex')}`;
}

function decrypt(envelope, key) {
    if (typeof envelope !== 'string' || envelope.length === 0) {
        throw new TypeError('envelope must be a non-empty string');
    }

    const [version, ivHex, tagHex, ciphertextHex, ...extra] = envelope.split(':');
    if (
        version !== 'v1'
        || extra.length > 0
        || !/^[0-9a-f]{24}$/.test(ivHex)
        || !/^[0-9a-f]{32}$/.test(tagHex)
        || !/^[0-9a-f]+$/.test(ciphertextHex)
        || ciphertextHex.length % 2 !== 0
    ) {
        throw new Error('invalid secret envelope');
    }

    const decipher = crypto.createDecipheriv(
        ALGORITHM,
        deriveKey(key),
        Buffer.from(ivHex, 'hex'),
    );
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));

    return Buffer.concat([
        decipher.update(Buffer.from(ciphertextHex, 'hex')),
        decipher.final(),
    ]).toString('utf8');
}

module.exports = {
    encrypt,
    decrypt,
};
