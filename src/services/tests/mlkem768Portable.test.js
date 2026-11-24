'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const ve = require('../../utils/vlessEncryption');

const PRIV = 'vlessEncryptionPrivateKey', PUB = 'vlessEncryptionPublicKey';
const mlkem = { vlessEncryption: true, vlessEncryptionAuth: 'mlkem768' };
const unavailable = 'VLESS_ENCRYPTION_MLKEM_UNAVAILABLE';
const pkcs8 = Buffer.from('3054020100300b060960864801650304040204428040', 'hex');
const { createPrivateKey } = crypto;
function opensslPublic(seed) {
    const der = Buffer.concat([pkcs8, seed]);
    try {
        return crypto.createPublicKey(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }))
            .export({ format: 'der', type: 'spki' }).subarray(-1184);
    } finally {
        der.fill(0);
    }
}
const lookup = id => require.resolve(`../../utils/${id}`);

let oldRoot;
before(() => {
    oldRoot = process.env.ENCRYPTION_KEY;
    process.env.ENCRYPTION_KEY = 'fixture wrapping root for offline ML-KEM tests';
});
after(() => {
    if (oldRoot === undefined) delete process.env.ENCRYPTION_KEY;
    else process.env.ENCRYPTION_KEY = oldRoot;
});

// NIST ACVP-Server ML-KEM-keyGen-FIPS203, group 2 case 26 (d || z, SHA-256(ek)).
// See scripts/mlkem768/README.md for the exact upstream revision and fixture hashes.
const seed = Buffer.from('e34a701c4c87582f42264ee422d3c684d97611f2523efe0c998af05056d693dca'
    + '85768f3486bd32a01bf9a8f21ea938e648eae4e5448c34c3eb88820b159eedd', 'hex');
const expected = '7799c9d8eef172aa78c073514f2f039c240de8c5cb61bca82ba0bc46041ce279';
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

async function checkKat() {
    const key = Buffer.from(await ve.deriveClientKey('mlkem768', seed.toString('base64url')), 'base64url');
    assert.equal(key.length, 1184);
    assert.equal(hash(key), expected);
}

function nativeUnsupported(t) {
    const original = crypto.createPrivateKey;
    return t.mock.method(crypto, 'createPrivateKey', function (options) {
        if (options.key?.subarray(0, pkcs8.length).equals(pkcs8)) {
            throw Object.assign(new Error('synthetic native decode failure'), { code: 'ERR_OSSL_UNSUPPORTED' });
        }
        return original.call(this, options);
    });
}

function freshHelper() {
    delete require.cache[lookup('vlessEncryption')];
    return require('../../utils/vlessEncryption');
}

test('X25519 RFC 7748 Alice KAT, actual rotation and off do not load the portable backend', async () => {
    const helper = freshHelper();
    assert.equal(helper.buildServerDecryption({ ...mlkem, vlessEncryption: false }), 'none');
    const xSeed = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex');
    const xPub = Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex');
    assert.equal(await helper.deriveClientKey('x25519', xSeed.toString('base64url')), xPub.toString('base64url'));
    await assert.rejects(helper.deriveClientKey('mlkem768', 'invalid'), { code: 'VLESS_ENCRYPTION_KEY_INVALID' });
    const first = { vlessEncryption: true }, rotated = {};
    assert.equal(await helper.applyVlessEncryptionToXray(first), null);
    assert.equal(await helper.applyVlessEncryptionToXray(rotated, first, ['main']), null);
    assert.ok(first[PUB] !== rotated[PUB] && first[PRIV] !== rotated[PRIV]);
    for (const item of [first, rotated]) {
        const serverSeed = helper.buildServerDecryption(item).split('.').at(-1);
        assert.ok(item[PUB] === await helper.deriveClientKey('x25519', serverSeed));
    }
    assert.equal(require.cache[lookup('mlkem768Portable')], undefined);
});

test('default backend on this runtime passes the independent ML-KEM-768 ACVP KAT', async () => {
    let native;
    try { native = opensslPublic(seed); } catch (error) {
        assert.equal(error.code, 'ERR_OSSL_UNSUPPORTED');
    }
    if (native) assert.equal(hash(native), expected);
    await checkKat();
    assert.equal(Boolean(require.cache[lookup('mlkem768Portable')]), !native);
});

test('forced portable: independent KAT, authenticated pair validation, publication and rotation', async t => {
    let native;
    try { native = opensslPublic(seed); } catch (error) {
        assert.equal(error.code, 'ERR_OSSL_UNSUPPORTED');
    }
    const nativeProbe = nativeUnsupported(t);
    const NativeInstance = WebAssembly.Instance;
    let instances = 0;
    let memory;
    t.mock.method(WebAssembly, 'Instance', function (module, imports) {
        const instance = new NativeInstance(module, imports);
        instances++;
        memory = instance.exports.memory;
        return instance;
    });
    const helper = freshHelper();
    const publicKey = await helper.deriveClientKey('mlkem768', seed.toString('base64url'));
    assert.equal(hash(Buffer.from(publicKey, 'base64url')), expected);
    assert.equal(nativeProbe.mock.callCount(), 1);
    assert.ok(require.cache[lookup('mlkem768Portable')]);
    assert.equal(memory.buffer.byteLength, 4 * 1024 * 1024);
    assert.ok(new Uint8Array(memory.buffer).every(byte => byte === 0));
    assert.throws(() => memory.grow(1), RangeError);
    const first = { ...mlkem }, noOp = {}, rotated = {};
    assert.equal(await helper.applyVlessEncryptionToXray(first), null);
    assert.equal(await helper.applyVlessEncryptionToXray(noOp, structuredClone(first)), null);
    assert.ok(noOp[PUB] === first[PUB] && noOp[PRIV] === first[PRIV]);
    assert.equal(await helper.applyVlessEncryptionToXray(rotated, first, ['main']), null);
    assert.ok(first[PUB] !== rotated[PUB] && first[PRIV] !== rotated[PRIV]);
    for (const item of [first, rotated]) {
        const raw = helper.buildServerDecryption(item).split('.').at(-1);
        assert.ok(raw.length === 86 && !item[PRIV].includes(raw));
        assert.ok(item[PUB] === await helper.deriveClientKey('mlkem768', raw));
        if (native) {
            const bytes = Buffer.from(raw, 'base64url');
            try { assert.ok(opensslPublic(bytes).toString('base64url') === item[PUB]); }
            finally { bytes.fill(0); }
        }
    }
    assert.match(await helper.applyVlessEncryptionToXray({}, { ...first, [PUB]: rotated[PUB] }), /regenerate/);
    assert.throws(() => helper.buildServerDecryption({ ...first, [PUB]: rotated[PUB] }), { code: 'VLESS_ENCRYPTION_KEY_INVALID' });
    const switched = { vlessEncryptionAuth: 'x25519' };
    assert.equal(await helper.applyVlessEncryptionToXray(switched, rotated), null);
    assert.equal(switched[PUB].length, 43);
    assert.equal(nativeProbe.mock.callCount(), 1);
    // Nothing in the consumer publication path may load/instantiate WASM or use the sealed seed.
    const previousInstances = instances;
    assert.ok(helper.buildClientEncryption({ ...rotated, [PRIV]: undefined }) === `mlkem768x25519plus.native.0rtt.${rotated[PUB]}`);
    assert.equal(await helper.applyVlessEncryptionToXray({ vlessEncryption: false }, rotated), null);
    assert.equal(instances, previousInstances);
});

test('a missing or changed portable artifact fails closed with a sanitized error', async t => {
    nativeUnsupported(t);
    const portable = lookup('mlkem768Portable');
    const original = fs.readFileSync;
    let mode = 'missing';
    t.mock.method(fs, 'readFileSync', (path, ...args) => {
        if (typeof path === 'string' && path.endsWith('/mlkem768.wasm')) {
            if (mode === 'missing') throw new Error('private path must not escape');
            const bytes = original(path);
            bytes[bytes.length - 1] ^= 1;
            return bytes;
        }
        return original(path, ...args);
    });
    delete require.cache[portable];
    const helper = freshHelper();
    for (const failure of ['missing', 'corrupt']) {
        mode = failure;
        await assert.rejects(helper.deriveClientKey('mlkem768', seed.toString('base64url')),
            error => error.code === unavailable && !error.cause && !error.message.includes('private path'));
        const candidate = { ...mlkem };
        assert.match(await helper.applyVlessEncryptionToXray(candidate), /ML-KEM-768 is unavailable/);
        assert.deepEqual(candidate, mlkem);
    }
});

test('portable runtime wipes the seed even when derivation traps', async t => {
    nativeUnsupported(t);
    const NativeInstance = WebAssembly.Instance;
    let memory;
    let sawSeed = false;
    t.mock.method(WebAssembly, 'Instance', function (module, imports) {
        const { exports } = new NativeInstance(module, imports);
        memory = exports.memory;
        return { exports: { ...exports, derive() {
            sawSeed = seed.equals(new Uint8Array(memory.buffer, exports.buffer(), seed.length));
            throw new WebAssembly.RuntimeError('synthetic derivation trap');
        } } };
    });
    await assert.rejects(freshHelper().deriveClientKey('mlkem768', seed.toString('base64url')), { code: unavailable });
    assert.ok(sawSeed && new Uint8Array(memory.buffer).every(byte => byte === 0));
});

test('FIPS mode does not fall back to the unvalidated portable module', async t => {
    nativeUnsupported(t);
    t.mock.method(crypto, 'getFips', () => 1);
    const portable = lookup('mlkem768Portable');
    delete require.cache[portable];
    await assert.rejects(freshHelper().deriveClientKey('mlkem768', seed.toString('base64url')), { code: unavailable });
    assert.equal(require.cache[portable], undefined);
});
