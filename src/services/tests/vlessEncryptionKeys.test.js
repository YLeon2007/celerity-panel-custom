'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash, createHmac, createPrivateKey, createPublicKey, createCipheriv, hkdfSync } = require('node:crypto');
const HyNode = require('../../models/hyNodeModel');
const { prepareLinks, tunnelSettings } = require('../rebuildLinkKeys');
const ve = () => require('../../utils/vlessEncryption');
const PRIV = 'vlessEncryptionPrivateKey', PUB = 'vlessEncryptionPublicKey';
const nodeData = xray => ({ type: 'xray', name: 'fixture', ip: '192.0.2.1', xray });
const extra = (id, settings) => ({ id, inboundTag: `fixture-${id}`, port: 1443, ...settings });
const enabled = { vlessEncryption: true };

async function apply(next, prev, ids) {
    assert.equal(await ve().applyVlessEncryptionToXray(next, prev, ids), null);
    return next;
}

function rejectsKey(fn) {
    assert.throws(fn, error => error.code === 'VLESS_ENCRYPTION_KEY_INVALID' && !error.cause);
}

const hash = value => createHash('sha256').update(value).digest('hex');

test('model refuses an enabled main or extra on create without a trusted version (including forged body version)', async () => {
    for (const xray of [enabled, { extraInbounds: [extra('a', enabled)] }]) {
        for (const xrayVersion of [undefined, '26.11.9']) {
            const doc = new HyNode({ ...nodeData(xray), xrayVersion });
            await assert.rejects(() => doc.validate(), /requires Xray >= 25\.9\.5/);
        }
    }
});

test('version gate requires a valid trusted release for main and extra, and ignores off', () => {
    for (const xray of [enabled, { extraInbounds: [extra('a', enabled)] }]) {
        for (const value of [undefined, null, '', 'unknown', 'custom build 26.11.9', '25.9.5-rc.1', '25.9.5\nanything', 26, '25.9.4', '24.99.99', '1.8.24', '25.09.5', '26.0.0 junk']) {
            assert.match(ve().versionError(xray, value), /requires Xray >= 25\.9\.5/);
        }
        for (const value of ['25.9.5', 'v25.9.5', '25.10.0', '26.0.0']) {
            assert.equal(ve().versionError(xray, value), null);
        }
    }
    assert.equal(ve().versionError({}, ''), null);
    assert.equal(ve().versionError({ extraInbounds: [{ vlessEncryption: false }] }), null);
});

test('legacy off is sparse; caller keys and flags never become persisted fields', async () => {
    const xray = await apply({ vlessEncryption: false, [PRIV]: 'untrusted', [PUB]: 'untrusted',
        extraInbounds: [extra('a', { [PRIV]: 'untrusted', vlessEncryption: false })] });
    const doc = new HyNode(nodeData(xray));
    await doc.validate();
    const legacy = HyNode.hydrate({ ...nodeData(xray), _id: doc._id });
    await legacy.validate();
    for (const inbound of [xray, ...xray.extraInbounds, doc.xray.toObject(), doc.xray.extraInbounds[0].toObject(),
        legacy.xray.toObject(), legacy.xray.extraInbounds[0].toObject()]) {
        assert.ok(ve().FIELDS.every(key => !Object.hasOwn(inbound, key)));
        assert.equal(ve().buildServerDecryption(inbound), 'none');
        assert.equal(ve().buildClientEncryption(inbound), null);
    }
    const flags = { vlessEncryptionRegenerate: 'true', extraInbounds: [
        extra('a', { vlessEncryptionRegenerate: true }), extra('b', { vlessEncryptionRegenerate: 1 }),
        extra('main', { vlessEncryptionRegenerate: true }),
    ] };
    assert.deepEqual(ve().takeRegenerateIds(flags), ['a']);
    assert.deepEqual(ve().takeRegenerateIds(flags), []);
    for (const bad of ['true', 'false', 1, 0, null, {}, []]) {
        assert.match(await ve().applyVlessEncryptionToXray({ vlessEncryption: bad }), /boolean/);
        await assert.rejects(() => new HyNode(nodeData({ vlessEncryption: bad })).validate(), /must be a boolean/);
    }
});

test('X25519 wire, sealed persistence, no-op, disable/re-enable, explicit rotation and stable extra IDs', async t => {
    const xray = await apply({ ...enabled, vlessEncryptionMode: 'xorpub', vlessEncryptionTicket: '0030-0040S',
        [PRIV]: 'untrusted', [PUB]: 'untrusted', extraInbounds: [extra('a', enabled), extra('b', enabled)] });
    const server = ve().buildServerDecryption(xray), client = ve().buildClientEncryption(xray);
    const seed = server.split('.').at(-1);
    const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'),
        Buffer.from(seed, 'base64url')]), type: 'pkcs8', format: 'der' });
    assert.ok(server === `mlkem768x25519plus.xorpub.30-40s.${seed}` && seed.length === 43);
    assert.ok(client === `mlkem768x25519plus.xorpub.0rtt.${createPublicKey(privateKey).export({ format: 'jwk' }).x}`);
    assert.ok(xray[PRIV] !== seed && !xray[PRIV].includes(seed));
    assert.ok(xray[PRIV] !== 'untrusted' && xray[PUB] !== 'untrusted');
    const doc = new HyNode(nodeData(xray));
    doc.$locals.vlessEncryptionXrayVersion = '25.9.5';
    let row;
    t.mock.method(HyNode.collection, 'insertOne', async value => { row = structuredCloneExceptId(value); return { insertedId: value._id }; });
    t.mock.method(HyNode.collection, 'findOne', async (_filter, options) => {
        const copy = structuredCloneExceptId(row);
        for (const path of Object.keys(options.projection || {})) {
            if (options.projection[path] !== 0) continue;
            if (path === `xray.${PRIV}`) delete copy.xray[PRIV];
            if (path === `xray.extraInbounds.${PRIV}`) copy.xray.extraInbounds.forEach(item => delete item[PRIV]);
        }
        return copy;
    });
    await doc.save();
    const publicRead = await HyNode.findById(doc._id).lean();
    const stored = await HyNode.findById(doc._id).select(ve().PRIVATE_KEY_SELECT).lean();
    const selectedDoc = await HyNode.findById(doc._id).select(ve().PRIVATE_KEY_SELECT);
    const explicitPublicRead = await HyNode.findById(doc._id).select(ve().PRIVATE_KEY_EXCLUDE).lean();
    for (const value of [publicRead, explicitPublicRead, ve().redactNode(stored), ve().redactNode(doc),
        JSON.parse(JSON.stringify(doc)), JSON.parse(JSON.stringify(selectedDoc))]) {
        assert.ok(!Object.hasOwn(value.xray, PRIV) && value.xray.extraInbounds.every(i => !Object.hasOwn(i, PRIV)));
        assert.ok(value.xray[PUB] === xray[PUB]);
    }
    assert.ok(stored.xray[PRIV] === xray[PRIV] && stored.xray.extraInbounds[0][PRIV] === xray.extraInbounds[0][PRIV]);
    assert.ok(ve().buildServerDecryption(stored.xray) === server && ve().buildClientEncryption(stored.xray) === client);
    const redacted = ve().buildServerDecryption(stored.xray, { redactSecrets: true });
    assert.equal(redacted, 'mlkem768x25519plus.xorpub.30-40s.<redacted>');
    const clone = structuredClone(stored.xray);
    ve().stripVlessEncryptionKeys(clone);
    assert.ok([clone, ...clone.extraInbounds].every(i => !Object.hasOwn(i, PRIV) && !Object.hasOwn(i, PUB)));

    const noop = await apply({ extraInbounds: [extra('b'), extra('a')] }, stored.xray);
    assert.ok(noop[PRIV] === xray[PRIV] && noop[PUB] === xray[PUB]);
    assert.ok(noop.extraInbounds[0][PRIV] === xray.extraInbounds[1][PRIV] && noop.extraInbounds[1][PUB] === xray.extraInbounds[0][PUB]);
    const off = await apply({ vlessEncryption: false }, stored.xray);
    assert.equal(ve().buildServerDecryption(off), 'none');
    assert.ok((await apply({ ...enabled }, off))[PRIV] === xray[PRIV]);
    const rotated = await apply({ extraInbounds: [extra('b'), extra('a')] }, stored.xray, ['a']);
    assert.ok(rotated[PRIV] === xray[PRIV] && rotated.extraInbounds[0][PRIV] === xray.extraInbounds[1][PRIV]);
    assert.ok(rotated.extraInbounds[1][PRIV] !== xray.extraInbounds[0][PRIV] && rotated.extraInbounds[1][PUB] !== xray.extraInbounds[0][PUB]);
    const updated = await apply({ vlessEncryptionMode: 'random', vlessEncryptionTicket: '0s' }, stored.xray);
    assert.ok(updated[PRIV] === xray[PRIV] && ve().buildServerDecryption(updated) === `mlkem768x25519plus.random.0s.${seed}`);
    const originalVersion = HyNode.hydrate({ ...nodeData(xray), _id: doc._id, xrayVersion: '25.9.4' });
    originalVersion.xray.vlessEncryptionMode = 'random';
    originalVersion.xrayVersion = '26.11.9';
    await assert.rejects(() => originalVersion.validate(), /no valid version from node health/);
});

function structuredCloneExceptId(value) {
    const { _id, ...rest } = value;
    return { ...structuredClone(rest), _id };
}

test('corrupt/missing keys and mismatched pairs fail closed until explicit rotation', async () => {
    const good = await apply({ ...enabled });
    const different = await apply({ ...enabled });
    const raw = ve().buildServerDecryption(good).split('.').at(-1);
    const parts = good[PRIV].split('.');
    parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
    for (const previous of [{ ...good, [PRIV]: parts.join('.') }, { ...good, [PRIV]: raw }, { ...good, [PRIV]: null },
        { ...good, [PRIV]: undefined }, { ...good, [PUB]: different[PUB] }, { ...good, [PUB]: 'junk' }, { ...enabled }]) {
        const candidate = { ...enabled };
        assert.match(await ve().applyVlessEncryptionToXray(candidate, previous), /regenerate/);
        assert.ok(!Object.hasOwn(candidate, PRIV));
        const recovered = await apply(candidate, previous, ['main']);
        assert.ok(recovered[PUB] !== good[PUB]);
    }
    rejectsKey(() => ve().buildServerDecryption({ ...good, [PRIV]: raw, inboundTag: 'never-echo-tag' }));
    rejectsKey(() => ve().buildServerDecryption({ ...good, [PUB]: different[PUB] }));
    assert.equal(ve().buildClientEncryption({ ...good, [PUB]: 'junk' }), null);
});

test('wrong or unavailable wrapping root does not rekey or expose storage inputs', async () => {
    const good = await apply({ ...enabled });
    const root = process.env.ENCRYPTION_KEY;
    try {
        process.env.ENCRYPTION_KEY = 'fixture wrong root: not an active credential';
        const next = { ...enabled };
        assert.match(await ve().applyVlessEncryptionToXray(next, good), /regenerate/);
        rejectsKey(() => ve().buildServerDecryption(good));
        delete process.env.ENCRYPTION_KEY;
        assert.match(await ve().applyVlessEncryptionToXray(next), /key storage is unavailable/);
        const off = await apply({ vlessEncryption: false }, good);
        assert.ok(off[PRIV] === good[PRIV]);
        assert.equal(ve().buildServerDecryption(off), 'none');
    } finally {
        process.env.ENCRYPTION_KEY = root;
    }
});

test('fallback conflict, invalid settings and ambiguous extra IDs are rejected', async () => {
    const tls = { security: 'tls', fallbackDest: ' fixture.invalid:443 ' };
    assert.match(await ve().applyVlessEncryptionToXray({ ...enabled, ...tls }), /Main inbound: .*fallback/);
    assert.match(await ve().applyVlessEncryptionToXray({ extraInbounds: [extra('a', { ...enabled, ...tls })] }), /Extra inbound #1: .*fallback/);
    await apply({ ...tls });
    await apply({ ...enabled, ...tls, transport: 'ws' });
    for (const value of [true, '-1s', '0-1s', '2-1s', '86401s', '2s.extra']) {
        assert.match(await ve().applyVlessEncryptionToXray({ ...enabled, vlessEncryptionTicket: value }), /ticket/);
    }
    assert.match(await ve().applyVlessEncryptionToXray({ ...enabled, vlessEncryptionAuth: 'bad' }), /auth/);
    assert.match(await ve().applyVlessEncryptionToXray({ ...enabled, vlessEncryptionMode: 'bad' }), /mode/);
    for (const extraInbounds of [[extra('a', enabled), extra('a')], [extra('main', enabled)], [extra('', enabled)]]) {
        assert.match(await ve().applyVlessEncryptionToXray({ extraInbounds }), /ID/);
    }
    const previous = await apply({ extraInbounds: [extra('a', enabled)] });
    previous.extraInbounds.push(extra('a'));
    assert.match(await ve().applyVlessEncryptionToXray({ extraInbounds: [extra('a')] }, previous), /ID/);
});

test('link legacy seed, persisted envelope and wire retain exact pre-port bytes, and domains are isolated', async () => {
    const root = 'synthetic link root for compatibility fixture';
    const env = { ENCRYPTION_KEY: root };
    const draft = { _id: '0000000000000000000000ab', mode: 'reverse', active: true };
    const domain = 'celerity/rebuild/link-vless/v1';
    const subkey = (usage, secret = root) => Buffer.from(hkdfSync('sha256', secret, domain, usage, 32));
    const seed = createHmac('sha256', subkey('legacy-seed')).update(draft._id).digest();
    const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), seed]);
    const pub = createPublicKey(createPrivateKey({ key: pkcs8, type: 'pkcs8', format: 'der' })).export({ format: 'jwk' }).x;
    const expected = JSON.stringify({ decryption: `mlkem768x25519plus.native.600s.${seed.toString('base64url')}`,
        encryption: `mlkem768x25519plus.native.0rtt.${pub}` });
    const linkEnvelope = (secret, nonce = Buffer.alloc(12, 3)) => {
        const cipher = createCipheriv('aes-256-gcm', subkey('envelope', secret), nonce);
        cipher.setAAD(Buffer.from(`${domain}:${draft._id}`));
        return `v1.${[nonce, Buffer.concat([cipher.update(seed), cipher.final()]), cipher.getAuthTag()].map(x => x.toString('base64url')).join('.')}`;
    };
    let row = draft;
    const query = { select: () => query, read: () => query, readConcern: () => query, session: () => query, lean: async () => [row] };
    const Link = {
        find: () => query,
        db: { transaction: async fn => fn({}) },
        updateOne: async (_, { $set }) => {
            row = { ...row, ...$set };
            return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
        },
    };
    for (const envelope of [undefined, linkEnvelope(root)]) {
        row = envelope ? { ...draft, rebuildVlessKeyEnvelope: envelope } : draft;
        const [link] = await prepareLinks(Link, [draft], { env });
        assert.ok(JSON.stringify(tunnelSettings(link)) === expected, 'link wire differs');
    }
    row = draft;
    const prepared = await prepareLinks(Link, [draft], { env });
    await prepareLinks(Link, prepared, { env, persist: true, verify: async () => {} });
    const persisted = row.rebuildVlessKeyEnvelope;
    assert.ok(persisted === linkEnvelope(root, Buffer.from(persisted.split('.')[1], 'base64url')), 'link envelope differs');
    const client = await apply({ ...enabled });
    rejectsKey(() => ve().buildServerDecryption({ ...client, [PRIV]: linkEnvelope(process.env.ENCRYPTION_KEY) }));
});
