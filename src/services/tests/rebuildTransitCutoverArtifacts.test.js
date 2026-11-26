'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomBytes, randomUUID } = require('node:crypto');
const { test } = require('node:test');
const { createCutoverArtifactStore } = require('../rebuildTransitCutoverArtifacts');

function fixture(t) {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'cutover-artifacts-'));
    t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
    const directory = path.join(parent, 'private');
    fs.mkdirSync(directory, { mode: 0o700 });
    const key = randomBytes(32);
    const ctx = { plan: { scope: 'fixture', operationId: randomUUID(), fenceId: randomUUID(), planDigest: 'a'.repeat(64) },
        step: { id: 'change-1' } };
    return { parent, directory, key, ctx, store: createCutoverArtifactStore({ directory, key }),
        file: pin => path.join(directory, `${pin.id}.sealed`) };
}
const refused = { code: 'REBUILD_CUTOVER_ARTIFACT_UNPROVED', message: 'REBUILD_CUTOVER_ARTIFACT_UNPROVED' };

test('exact binary preimage survives reopening; only opaque pins and ciphertext are published', t => {
    const f = fixture(t);
    const bytes = Buffer.concat([Buffer.from('synthetic credential\n'), Buffer.from([0, 255, 128])]);
    const pin = f.store.seal(f.ctx, 'before', bytes);
    assert.deepEqual(Object.keys(pin), ['id', 'sha256']);
    assert.equal(fs.readFileSync(f.file(pin)).includes(bytes), false);
    assert.equal(fs.statSync(f.file(pin)).mode & 0o7777, 0o600);
    const fresh = createCutoverArtifactStore({ directory: f.directory, key: f.key });
    assert.deepEqual(fresh.read(f.ctx, 'before', pin), bytes);
    assert.notEqual(f.store.seal(f.ctx, 'before', bytes).sha256, pin.sha256);
    assert.throws(() => createCutoverArtifactStore({ directory: f.directory, key: randomBytes(32) })
        .read(f.ctx, 'before', pin), refused);
});

test('artifact cannot be substituted across operation, fence, scope, plan, step, side or pin', t => {
    const f = fixture(t);
    const pin = f.store.seal(f.ctx, 'before', Buffer.from('before'));
    const changes = { scope: 'other', operationId: randomUUID(), fenceId: randomUUID(), planDigest: 'b'.repeat(64) };
    for (const [field, value] of Object.entries(changes)) assert.throws(() =>
        f.store.read({ ...f.ctx, plan: { ...f.ctx.plan, [field]: value } }, 'before', pin), refused);
    assert.throws(() => f.store.read({ ...f.ctx, step: { id: 'other' } }, 'before', pin), refused);
    for (const side of ['desired', 'confirmed', '../before']) assert.throws(() => f.store.read(f.ctx, side, pin), refused);
    assert.throws(() => f.store.read(f.ctx, 'before', { ...pin, id: '../outside' }), refused);
    assert.throws(() => f.store.read(f.ctx, 'before', { ...pin, sha256: 'f'.repeat(64) }), refused);
});

test('stale path and artifact generations, unsafe file types, mode and ciphertext are refused', t => {
    const f = fixture(t);
    const pin = f.store.seal(f.ctx, 'confirmed', Buffer.from('readback'));
    const file = f.file(pin), twin = path.join(f.parent, 'twin');
    fs.linkSync(file, twin);
    assert.throws(() => f.store.read(f.ctx, 'confirmed', pin), refused);
    fs.unlinkSync(twin);
    fs.chmodSync(file, 0o644);
    assert.throws(() => f.store.read(f.ctx, 'confirmed', pin), refused);
    fs.chmodSync(file, 0o600);
    fs.renameSync(file, twin);
    fs.symlinkSync(twin, file);
    assert.throws(() => f.store.read(f.ctx, 'confirmed', pin), refused);
    fs.unlinkSync(file);
    fs.renameSync(twin, file);
    const packet = fs.readFileSync(file);
    packet[packet.length - 1] ^= 1;
    fs.writeFileSync(file, packet);
    assert.throws(() => f.store.read(f.ctx, 'confirmed', pin), refused);
    const old = path.join(f.parent, 'old');
    fs.renameSync(f.directory, old);
    fs.mkdirSync(f.directory, { mode: 0o700 });
    assert.throws(() => f.store.seal(f.ctx, 'before', Buffer.from('must not land')), refused);
    assert.deepEqual(fs.readdirSync(f.directory), []);
});

test('no artifact receipt on write sync failure; callers cannot smuggle object inputs', t => {
    const f = fixture(t);
    const mock = t.mock.method(fs, 'fsyncSync', () => { throw new Error('synthetic sync failure'); });
    assert.throws(() => f.store.seal(f.ctx, 'before', Buffer.from('no pin')), refused);
    mock.mock.restore();
    assert.throws(() => f.store.seal(f.ctx, 'before', { bytes: 'not exact bytes' }), refused);
    assert.deepEqual(f.store.read(f.ctx, 'desired', f.store.seal(f.ctx, 'desired', Buffer.alloc(0))), Buffer.alloc(0));
});

test('post-drain artifacts bind marked step, direction and side without changing legacy AAD', t => {
    const f = fixture(t);
    const step = { ...f.ctx.step, phase: 'selector', window: 'main-agent' };
    const ctx = { plan: { ...f.ctx.plan, steps: [step] }, step };
    const bytes = Buffer.from('MAIN after final flush\n');
    const original = f.store.seal(f.ctx, 'before', bytes);
    const pin = f.store.seal(ctx, 'publication-forward-before', bytes);
    const fresh = createCutoverArtifactStore({ directory: f.directory, key: f.key });
    assert.deepEqual(fresh.read(ctx, 'before', original), bytes);
    assert.deepEqual(fresh.read(ctx, 'publication-forward-before', pin), bytes);
    for (const side of ['before', 'publication-forward-desired', 'publication-rollback-before']) {
        assert.throws(() => fresh.read(ctx, side, pin), refused);
    }
    assert.throws(() => fresh.read(f.ctx, 'publication-forward-before', pin), refused);
    assert.throws(() => fresh.seal({ ...ctx, plan: { ...ctx.plan, steps: [] } }, 'publication-forward-before', bytes), refused);
});

test('the maximum raw MAIN fits its authenticated before and confirmed snapshots', t => {
    const f = fixture(t);
    const step = { ...f.ctx.step, phase: 'selector', window: 'main-agent' };
    const ctx = { plan: { ...f.ctx.plan, steps: [step] }, step };
    const raw = Buffer.alloc(8 * 1024 * 1024, 0x61);
    const image = { data: raw.toString('base64'), metadata: [0o640, 0, 0], generation: ['123', '456', '789'] };
    const snapshot = Buffer.from(JSON.stringify({ ...image, xray: [1234, '1'.repeat(32)] }));
    const drained = Buffer.from(JSON.stringify(image));
    const fresh = createCutoverArtifactStore({ directory: f.directory, key: f.key });
    for (const [side, data] of [['before', snapshot], ['publication-forward-before', drained],
        ['confirmed', snapshot], ['publication-rollback-before', drained], ['desired', raw]]) {
        const pin = f.store.seal(ctx, side, data);
        assert(fresh.read(ctx, side, pin).equals(data));
        if (side === 'before' || side === 'confirmed') assert.throws(() => fresh.read(f.ctx, side, pin), refused);
    }
    assert.throws(() => f.store.seal(ctx, 'desired', snapshot), refused);
    assert.throws(() => f.store.seal(f.ctx, 'before', snapshot), refused);
    assert.throws(() => f.store.seal(ctx, 'before', Buffer.alloc(4 * Math.ceil(raw.length / 3) + 1025)), refused);
});
