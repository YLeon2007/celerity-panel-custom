'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createPrivateKey, createPublicKey, randomBytes } = require('node:crypto');
const { prepareLinks, tunnelSettings } = require('../rebuildLinkKeys');

const FIELD = 'rebuildVlessKeyEnvelope';
const env = { ENCRYPTION_KEY: randomBytes(32).toString('hex') };
const row = (n = 1, patch = {}) => ({
    _id: n.toString(16).padStart(24, '0'), tunnelUuid: `synthetic-${n}`,
    active: true, updatedAt: new Date(100), ...patch,
});
const wrongRoot = { ENCRYPTION_KEY: randomBytes(32).toString('hex') };

// Never let assert.rejects or equality diffs show crypto, DB or fixture values.
async function refuses(code, fn) {
    let safe = false;
    try { await fn(); } catch (error) {
        safe = error.code === code && error.message === code && !Object.hasOwn(error, 'cause');
    }
    assert.ok(safe, `expected sanitized ${code}`);
}

function storage(input) {
    let rows = new Map(input.map(r => [r._id, { ...r }]));
    const calls = { reads: 0, transactions: 0, writes: 0, guard: 0 };
    const faults = {};
    const Link = {
        find(filter) {
            let session;
            const q = {
                select(fields) { assert.equal(fields, `+${FIELD}`); return q; },
                read(mode) { assert.equal(mode, 'primary'); return q; },
                readConcern(level) { assert.equal(level, 'majority'); return q; },
                session(s) { session = s; return q; },
                async lean() {
                    calls.reads++;
                    if (faults.read) throw new Error(faults.read);
                    return [...(session?.rows || rows).values()]
                        .filter(r => filter._id.$in.includes(r._id)).map(r => ({ ...r }));
                },
            };
            return q;
        },
        async updateOne(filter, update, options) {
            const index = ++calls.writes;
            assert.ok(options.session && calls.guard > 0, 'write must have a guard and session');
            assert.equal(options.timestamps, false);
            const target = options.session.rows.get(filter._id);
            assert.ok(filter[FIELD]?.$exists === false, 'CAS requires physical absence');
            assert.ok(Object.keys(update).join() === '$set' && Object.keys(update.$set).join() === FIELD,
                'must update only the envelope');
            if (!target || Object.hasOwn(target, FIELD) || faults.cas === index) return { acknowledged: true, matchedCount: 0, modifiedCount: 0 };
            if (faults.noModify === index) return { acknowledged: true, matchedCount: 1, modifiedCount: 0 };
            target[FIELD] = update.$set[FIELD];
            return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
        },
        db: { async transaction(fn, options) {
            calls.transactions++;
            assert.ok(options.readConcern.level === 'snapshot' && options.writeConcern.w === 'majority');
            const session = { rows: new Map([...rows].map(([id, r]) => [id, { ...r }])) };
            const result = await fn(session);
            if (faults.commit) throw new Error(faults.commit);
            rows = session.rows;
            return result;
        } },
    };
    const verify = async () => { calls.guard++; };
    return { Link, calls, faults, verify, get: id => rows.get(id) };
}

function same(a, b) {
    return a.decryption === b.decryption && a.encryption === b.encryption;
}

const preview = (db, rows, opts = {}) => prepareLinks(db.Link, rows, { env, ...opts });
const apply = (db, links, opts = {}) => prepareLinks(db.Link, links, { env, persist: true, verify: db.verify, ...opts });

test('legacy forward and reverse VLESS get stable, distinct and paired Xray keys without writes', async () => {
    const rows = [row(1, { mode: 'reverse' }), row(2, { mode: 'forward', tunnelProtocol: 'vless', tunnelSecurity: 'none' })];
    const db = storage(rows);
    const first = await preview(db, rows);
    const next = await preview(db, rows);
    const [a, b] = first.map(tunnelSettings);
    assert.ok(same(a, tunnelSettings(next[0])) && same(b, tunnelSettings(next[1])), 'preview keys changed');
    assert.ok(a.decryption !== b.decryption && a.encryption !== b.encryption, 'keys reused across links');
    for (const settings of [a, b]) {
        const decoded = /^mlkem768x25519plus\.native\.600s\.([A-Za-z0-9_-]{43})$/.exec(settings.decryption);
        assert.ok(decoded, 'unexpected inbound format');
        const prefix = Buffer.from('302e020100300506032b656e04220420', 'hex');
        const privateKey = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([prefix, Buffer.from(decoded[1], 'base64url')]) });
        const publicKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
        assert.ok(settings.encryption === `mlkem768x25519plus.native.0rtt.${publicKey}`, 'X25519 public key is not paired');
    }
    assert.equal(db.calls.transactions, 0);
    assert.equal(db.calls.writes, 0);
    assert.ok(rows.every(r => !Object.hasOwn(r, '_rebuildVless')), 'draft was mutated');
});

test('Apply stores only sealed material, reuses key on fresh preparation, and never serializes keys with links', async () => {
    const rows = [row(1), row(2)];
    const db = storage(rows);
    const prepared = await preview(db, rows);
    const applied = await apply(db, prepared);
    assert.equal(db.calls.writes, 2);
    assert.equal(db.calls.transactions, 1);
    const revisited = await preview(db, rows);
    await apply(db, revisited);
    assert.equal(db.calls.writes, 2);
    for (let i = 0; i < rows.length; i++) {
        const { decryption, encryption } = tunnelSettings(prepared[i]);
        assert.ok(same(tunnelSettings(applied[i]), tunnelSettings(revisited[i])), 'persisted key changed');
        const stored = db.get(rows[i]._id)[FIELD];
        assert.ok(/^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{22}$/.test(stored), 'not a sealed envelope');
        const clear = decryption.split('.').at(-1);
        const dialer = encryption.split('.').at(-1);
        const runtime = JSON.stringify({ link: prepared[i], spread: { ...prepared[i] } });
        for (const text of [runtime, JSON.stringify(db.get(rows[i]._id))]) {
            assert.ok(!text.includes(clear) && !text.includes(dialer) && !text.includes('_rebuildVless'), 'runtime material leaked');
        }
        assert.ok(!runtime.includes(FIELD) && !runtime.includes(stored), 'envelope leaked');
        const nodeConfig = JSON.stringify({ inbound: { decryption }, outbound: { encryption } });
        assert.ok(!nodeConfig.includes(FIELD) && !nodeConfig.includes(stored), 'envelope leaked to node config');
    }
    assert.ok(db.get(rows[0]._id)[FIELD].split('.')[1] !== db.get(rows[1]._id)[FIELD].split('.')[1], 'nonce reused');
});

test('TLS, REALITY and forward VMess need no key; eligible unprepared link cannot downgrade', async () => {
    const rows = [row(1, { tunnelSecurity: 'tls' }), row(2, { tunnelSecurity: 'reality' }),
        row(3, { mode: 'forward', tunnelProtocol: 'vmess' })];
    const db = storage(rows);
    const links = await preview(db, rows, { env: {} });
    await apply(db, links, { env: {} });
    assert.ok(links.every(link => tunnelSettings(link) === null), 'unneeded settings populated');
    assert.equal(db.calls.writes, 0);
    await refuses('REBUILD_LINK_KEY_NOT_PREPARED', () => tunnelSettings(row()));
    await refuses('REBUILD_LINK_KEY_NOT_PREPARED', () => tunnelSettings(row(1, {
        _rebuildVless: { decryption: 'none', encryption: 'none' },
    })));
});

test('explicit none skips key preparation and envelope writes, with or without an old envelope', async () => {
    const rows = [row(1, { mode: 'forward', tunnelSecurity: 'none', tunnelEncryption: 'none' }),
        row(2, { mode: 'reverse', tunnelEncryption: 'none' })];
    const db = storage([rows[0], { ...rows[1], [FIELD]: 'unused-legacy-envelope' }]);
    const prepared = await preview(db, rows, { env: {} });
    await apply(db, prepared, { env: {} });
    assert.ok(prepared.every(link => !Object.hasOwn(link, '_rebuildVless') && tunnelSettings(link) === null));
    assert.equal(db.calls.transactions, 0);
    assert.equal(db.calls.writes, 0);
    assert.equal(Object.hasOwn(db.get(rows[0]._id), FIELD), false);
    assert.equal(db.get(rows[1]._id)[FIELD], 'unused-legacy-envelope');
});

test('rejects bad roots, malformed ciphertext, tampering, and copying a valid envelope from another link', async () => {
    const rows = [row(1), row(2)];
    const db = storage(rows);
    for (const key of [undefined, '', ' '.repeat(32), 'short']) {
        await refuses('REBUILD_LINK_KEY_UNAVAILABLE', () => preview(db, rows, { env: { ENCRYPTION_KEY: key } }));
    }
    const prepared = await preview(db, rows);
    await refuses('REBUILD_LINK_CHANGED', () => apply(db, prepared, { env: wrongRoot }));
    assert.equal(db.calls.writes, 0);
    await apply(db, prepared);
    await refuses('REBUILD_LINK_KEY_INVALID', () => preview(db, rows, { env: wrongRoot }));
    const sealed = db.get(rows[0]._id)[FIELD];
    const fields = sealed.split('.');
    fields[2] = (fields[2][0] === 'A' ? 'B' : 'A') + fields[2].slice(1);
    for (const corrupt of [undefined, null, '', [], { value: sealed }, sealed.slice(3), fields.join('.')]) {
        db.get(rows[0]._id)[FIELD] = corrupt;
        await refuses('REBUILD_LINK_KEY_INVALID', () => preview(db, rows));
    }
    db.get(rows[0]._id)[FIELD] = db.get(rows[1]._id)[FIELD];
    await refuses('REBUILD_LINK_KEY_INVALID', () => preview(db, rows));
    assert.equal(db.calls.writes, 2);
});

test('Apply refuses unguarded, detached or stale prepared candidates without writes', async () => {
    const rows = [row(1), row(2)];
    const db = storage(rows);
    const prepared = await preview(db, rows);
    await refuses('REBUILD_LINK_KEY_NOT_PREPARED', () => apply(db, [...prepared]));
    await refuses('REBUILD_LINK_KEY_APPLY_GUARD_REQUIRED', () => apply(db, prepared, { verify: undefined }));
    await refuses('REBUILD_LOCK_LOST', () => apply(db, prepared, { verify() {
        throw Object.assign(new Error(env.ENCRYPTION_KEY), { code: 'REBUILD_LOCK_LOST' });
    } }));
    db.get(rows[1]._id).tunnelUuid = 'changed-without-timestamp-change';
    await refuses('REBUILD_LINK_CHANGED', () => apply(db, prepared));
    await refuses('REBUILD_LINK_CHANGED', () => preview(db, rows));
    assert.equal(db.calls.writes, 0);
});

test('health updates do not invalidate a link snapshot or undo the key CAS', async () => {
    const draft = row(1, { status: 'deployed', lastError: '', latencyMs: null });
    const db = storage([draft]);
    const telemetry = { status: 'offline', lastHealthCheck: new Date(200), latencyMs: 5,
        lastError: 'fixture health check', updatedAt: new Date(201) };
    // First update between the inventory read and the private-key read.
    Object.assign(db.get(draft._id), telemetry);
    const prepared = await preview(db, [draft]);
    assert.equal(db.calls.writes, 0);
    // A second update between preparation and the transactional key recheck.
    Object.assign(telemetry, { status: 'online', lastHealthCheck: new Date(300),
        latencyMs: 6, lastError: '', updatedAt: new Date(301) });
    Object.assign(db.get(draft._id), telemetry);
    await apply(db, prepared);
    assert.equal(db.calls.writes, 1);
    assert.deepEqual(Object.fromEntries(Object.keys(telemetry).map(k => [k, db.get(draft._id)[k]])), telemetry);
    // Same result on the majority-read path with the envelope already present.
    const stored = await preview(db, [draft]);
    db.get(draft._id).status = 'offline';
    await apply(db, stored);
    assert.equal(db.calls.writes, 1);
});

test('strict key recheck still refuses each working-field edit even with health drift', async () => {
    for (const change of [{ tunnelPort: 41001 }, { mode: 'forward' }, { realityPrivateKey: 'synthetic' },
        { active: false }, { rebuildDelete: true }, { geoRouting: { status: 'nested working field' } }]) {
        const draft = row(1, { mode: 'reverse', tunnelPort: 41000 });
        const db = storage([draft]);
        const prepared = await preview(db, [draft]);
        Object.assign(db.get(draft._id), change, { status: 'online', updatedAt: new Date(200) });
        await refuses('REBUILD_LINK_CHANGED', () => apply(db, prepared));
        assert.equal(db.calls.writes, 0);
    }
});

test('private inventory verifies hidden link fields without returning them to the composer', async () => {
    const draft = row(1, { tunnelSecurity: 'reality', [FIELD]: 'unused-fixture-envelope',
        rebuildApplied: { port: 8443 }, classicLifecycleGrant: 'fixture-grant' });
    const db = storage([draft]);
    const prepared = await preview(db, [draft], { privateInventory: true });
    for (const field of [FIELD, 'rebuildApplied', 'classicLifecycleGrant']) {
        assert.equal(Object.hasOwn(prepared[0], field), false);
    }
    db.get(draft._id).rebuildApplied = { port: 8444 };
    await refuses('REBUILD_LINK_CHANGED', () => apply(db, prepared));
    db.get(draft._id).rebuildApplied = draft.rebuildApplied;
    db.get(draft._id)[FIELD] = 'changed-fixture-envelope';
    await refuses('REBUILD_LINK_CHANGED', () => preview(db, [draft], { privateInventory: true }));
    await refuses('REBUILD_LINK_CHANGED', () => apply(db, prepared));
    assert.equal(db.calls.writes, 0);
});

test('CAS drift, ambiguous result and commit errors refuse Apply; no partial batch persists in the transaction model', async () => {
    for (const opts of [{ cas: 2 }, { noModify: 2 }, { commit: env.ENCRYPTION_KEY }]) {
        const rows = [row(1), row(2)];
        const db = storage(rows);
        const prepared = await preview(db, rows);
        Object.assign(db.faults, opts);
        await refuses(opts.cas ? 'REBUILD_LINK_CHANGED' : 'REBUILD_LINK_KEY_STORE_FAILED', () => apply(db, prepared));
        assert.equal(db.calls.writes, 2);
        assert.ok(rows.every(r => !Object.hasOwn(db.get(r._id), FIELD)), 'partial batch committed');
    }
});

test('lock loss between link writes aborts earlier CAS writes before commit', async () => {
    const rows = [row(1), row(2)];
    const db = storage(rows);
    const prepared = await preview(db, rows);
    await refuses('REBUILD_LOCK_LOST', () => apply(db, prepared, { async verify() {
        if (db.calls.writes) throw new Error(env.ENCRYPTION_KEY);
        await db.verify();
    } }));
    assert.equal(db.calls.writes, 1);
    assert.ok(rows.every(r => !Object.hasOwn(db.get(r._id), FIELD)), 'partial batch committed after guard loss');
});

test('competing Apply cannot replace an initialized envelope; fresh preview reuses it', async () => {
    const rows = [row()];
    const db = storage(rows);
    const first = await preview(db, rows);
    const concurrent = await preview(db, rows);
    await apply(db, first);
    const winner = db.get(rows[0]._id)[FIELD];
    await refuses('REBUILD_LINK_CHANGED', () => apply(db, concurrent));
    const next = await preview(db, rows);
    assert.ok(same(tunnelSettings(first[0]), tunnelSettings(next[0])), 'winner settings changed');
    assert.ok(db.get(rows[0]._id)[FIELD] === winner, 'winner was overwritten');
    assert.equal(db.calls.writes, 1);
});

test('stored seed remains authoritative through a desired row edit', async () => {
    const before = row();
    const db = storage([before]);
    const prepared = await preview(db, [before]);
    await apply(db, prepared);
    Object.assign(db.get(before._id), { tunnelUuid: 'synthetic-replacement', updatedAt: new Date(101) });
    const { [FIELD]: ignored, ...edited } = db.get(before._id);
    const next = await preview(db, [edited]);
    assert.ok(same(tunnelSettings(prepared[0]), tunnelSettings(next[0])), 'key changed after edit');
    await apply(db, next);
    assert.equal(db.calls.writes, 1);
});

test('a read error is not treated as verified absence and discloses no underlying error', async () => {
    const rows = [row()];
    const db = storage(rows);
    const prepared = await preview(db, rows);
    db.faults.read = env.ENCRYPTION_KEY;
    await refuses('REBUILD_LINK_KEY_READ_FAILED', () => preview(db, rows));
    await refuses('REBUILD_LINK_KEY_READ_FAILED', () => apply(db, prepared));
    assert.equal(db.calls.writes, 0);
});
