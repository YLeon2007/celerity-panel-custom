'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { encrypt, decrypt } = require('../services/secretBoxService');

const KEY = 'relay-l2tp-test-key';
const PLAINTEXT = 'vpn-shared-secret';

test('encrypt/decrypt round-trips plaintext in a v1 envelope', () => {
    const envelope = encrypt(PLAINTEXT, KEY);

    assert.match(envelope, /^v1:[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]+$/);
    assert.ok(!envelope.includes(PLAINTEXT));
    assert.strictEqual(decrypt(envelope, KEY), PLAINTEXT);
});

test('encrypt uses a fresh IV for identical plaintext', () => {
    const firstCiphertext = encrypt(PLAINTEXT, KEY).split(':')[3];
    const secondCiphertext = encrypt(PLAINTEXT, KEY).split(':')[3];

    assert.notStrictEqual(firstCiphertext, secondCiphertext);
});

test('decrypt rejects a tampered ciphertext', () => {
    const parts = encrypt(PLAINTEXT, KEY).split(':');
    parts[3] = `${parts[3][0] === '0' ? '1' : '0'}${parts[3].slice(1)}`;

    assert.throws(() => decrypt(parts.join(':'), KEY));
});

test('decrypt rejects the wrong key', () => {
    const envelope = encrypt(PLAINTEXT, KEY);

    assert.throws(() => decrypt(envelope, 'different-key'));
});

test('encrypt rejects empty plaintext', () => {
    assert.throws(() => encrypt('', KEY));
});
