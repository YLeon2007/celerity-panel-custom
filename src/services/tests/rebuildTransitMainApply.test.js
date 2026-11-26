'use strict';
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const { once } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const test = require('node:test');
const { makeLocks, withNode, nodeLockVerifier } = require('../rebuildLocks');
const { createFileCutoverJournal } = require('../rebuildTransitCutoverJournal');
const { createCutoverArtifactStore } = require('../rebuildTransitCutoverArtifacts');
const { runJournaledMainApply } = require('../rebuildTransitMainApply');

const id = '0'.repeat(24), hash = input => createHash('sha256').update(input).digest('hex');
const config = (route, user) => ({ inbounds: [
    { tag: 'vless-in', protocol: 'vless', settings: { decryption: 'none', clients: [{ id: user, email: 'fixture@example.invalid' }] } },
    { tag: 'transit', protocol: 'vless', settings: { clients: [{ id: 'static' }] } },
], routing: { rules: [{ inboundTag: ['transit'], outboundTag: route }] }, outbounds: [{ tag: 'a' }, { tag: 'b' }] });

// Only persistence is modeled at the panel lock boundary; original lock
// promotion, journal, seal/open, and a separate Python host run unchanged.
function lockStore() {
    let row;
    function matches(q) {
        return row && Object.entries(q).every(([k, v]) => k === '$expr' ?
            (assert.deepEqual(v.$eq[0], '$$ROOT'), JSON.stringify(row) === JSON.stringify(v.$eq[1].$literal)) :
            k === 'cutover' && v.$exists === false ? !Object.hasOwn(row, k) : row[k] === v);
    }
    const copy = () => structuredClone(row);
    return { copy,
        async insertOne(value) { assert(!row); row = structuredClone(value); return { acknowledged: true }; },
        async findOne(q) { return matches(q) ? copy() : null; },
        async updateMany(q, change) {
            const count = Number(!!matches(q));
            if (count) Object.assign(row, structuredClone(change.$set));
            return { acknowledged: true, matchedCount: count, modifiedCount: count };
        },
        async deleteMany(q) {
            const count = Number(!!matches(q));
            if (count) row = null;
            return { acknowledged: true, deletedCount: count };
        },
    };
}

function fixture(t, { fault = '', loseSync = false, rejectBefore = false, rotated = false, changedFlow = false,
    replaceBeforeInverse = false, refusalAction = 'stop', refusalReply } = {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'c3-main-join.'));
    const journalPath = path.join(root, 'journal'), artifactPath = path.join(root, 'artifacts');
    const main = path.join(root, 'MAIN');
    for (const dir of [journalPath, artifactPath, path.join(root, 'slice'), path.join(root, 'lock')]) fs.mkdirSync(dir, { mode: 0o700 });
    fs.writeFileSync(main, JSON.stringify(config('a', 'initial')), { mode: 0o640 });
    const store = lockStore(), locks = makeLocks(store), journal = createFileCutoverJournal({ directory: journalPath });
    const artifacts = createCutoverArtifactStore({ directory: artifactPath, key: randomBytes(32) });
    let scope;
    const events = [], children = [];
    const savedError = [];
    t.after(async () => {
        for (const { child, done } of children) { if (child.exitCode === null) child.kill(); await done; }
        fs.rmSync(root, { recursive: true });
    });
    const state = () => journal.read(scope);
    const verifyLock = () => nodeLockVerifier(id)() && store.copy()?.cutover?.scope === scope;
    const opts = {
        journal, artifacts, heldNodeIds: [id], transitions: [{ id: 'relay-a', nodeId: id, phase: 'prepare', before: config('a', 'initial'),
            after: config('b', 'obsolete'), managed: ['vless-in'], authoritySha256: 'c'.repeat(64) }],
        async verifyFence(plan) { scope = plan.scope; return nodeLockVerifier(id)(); },
        async openWindow(target, { verifyBeforeFrame }) {
            assert.equal(target, id);
            assert(verifyLock());
            const child = spawn('/usr/bin/python3', ['-B', path.join(__dirname, 'rebuildTransitMainWireHost.py'), '--fixture', root, fault, '10', 'held'],
                { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin', TMPDIR: root, HOME: root, C3_SYNTHETIC_SYNC_USERS: '1' } });
            const done = once(child, 'close');
            children.push({ child, done });
            child.stderr.on('data', chunk => savedError.push(chunk.toString()));
            const lines = readline.createInterface({ input: child.stdout })[Symbol.asyncIterator]();
            const phases = { stop: 'agent-stop', capture: 'agent-stop', publish: 'main-publication', restart: 'xray-restart', start: 'agent-start',
                reconcile: 'agent-reconcile', verify: 'agent-reconcile' };
            return {
                async request(frame) {
                    assert(await verifyBeforeFrame());
                    assert(verifyLock());
                    if (Object.hasOwn(phases, frame.action) || frame.action === 'read') {
                        assert.equal(state().pending?.checkpoint ?? undefined, phases[frame.action]);
                        events.push(frame.action);
                    }
                    if (frame.action === refusalAction && refusalReply) return refusalReply;
                    child.stdin.write(`${JSON.stringify(frame)}\n`);
                    const next = await lines.next();
                    assert.equal(next.done, false, savedError.join(''));
                    return JSON.parse(next.value);
                },
                async finish() {
                    child.stdin.end();
                    assert.deepEqual(await done, [0, null], savedError.join(''));
                    assert((await lines.next()).done);
                },
                abort() { child.kill(); },
            };
        },
        async verifySnapshot(target, phase, snap) {
            assert.equal(target, id);
            if (phase === 'before' && rejectBefore) return false;
            return fs.readFileSync(main).equals(Buffer.from(snap.data, 'base64'));
        },
        async verifyAgentEndpoint(node, target) { return node === id && target === id && verifyLock(); },
        async readAgentManagedFlows(node, target, snapshot) {
            assert(verifyLock());
            assert.equal(node, id);
            assert.equal(target, id);
            assert(fs.readFileSync(main).equals(Buffer.from(snapshot.data, 'base64')));
            return new Map([['vless-in', changedFlow ? 'xtls-rprx-vision' : '']]);
        },
        async syncNodeUsers(node, { verifyFence, verifyPayload }) {
            assert.equal(node, id);
            assert(await verifyFence(id));
            const users = Object.freeze([Object.freeze({ id: rotated ? 'rotated' : 'drained', email: 'fixture@example.invalid', flow: '' })]);
            if (!await verifyPayload(id, users)) throw Object.assign(new Error('refused before POST'), { code: 'REBUILD_NODE_USER_SYNC_PAYLOAD_UNPROVED' });
            events.push('sync');
            if (loseSync) throw Object.assign(new Error('fixture-private'), { code: 'REBUILD_NODE_USER_SYNC_UNCONFIRMED' });
            assert(await verifyPayload(id, users));
            assert(await verifyFence(id));
            return { added: 0, removed: 0, total: 1, errors: 0 };
        },
        async prove() {
            if (replaceBeforeInverse) {
                const other = `${main}.identical`;
                fs.copyFileSync(main, other);
                fs.renameSync(other, main);
                return false; // known transit proof failure calls for inverse
            }
            return verifyLock();
        },
        async verifyTerminal(ctx, latest) {
            assert(verifyLock());
            assert.equal(ctx.direction, 'forward');
            assert(fs.readFileSync(main).equals(Buffer.from(latest.get(id).data, 'base64')));
            return Buffer.from('synthetic verified causal evidence');
        },
        async settle(status, pins) {
            assert(verifyLock());
            assert.equal(status, 'applied');
            assert.equal(pins.get(id), hash(fs.readFileSync(main)));
            assert.notEqual(pins.get(id), hash(JSON.stringify(config('b', 'obsolete'))));
            assert.equal(state().confirmed.length, 1);
            const contender = spawn('/usr/bin/flock', ['--nonblock', path.join(root, 'lock'), '/usr/bin/true'], { stdio: 'ignore' });
            assert.deepEqual(await once(contender, 'close'), [1, null]);
            events.push('settle');
            return true;
        },
        async observe() { assert.fail('must not auto-reconcile'); },
    };
    return { store, main, events, state, run: () => locks.run((_, retain) => withNode(id, () => runJournaledMainApply({ ...opts, retain }))) };
}

const complete = ['read', 'stop', 'capture', 'publish', 'restart', 'start', 'reconcile'];
for (const changed of ['rotated', 'changedFlow']) test(`joined MAIN wire: ${changed} cannot be admitted as no-op sync`, async t => {
    const f = fixture(t, { [changed]: true });
    await assert.rejects(f.run(), { code: 'REBUILD_MAIN_CUTOVER_UNRESOLVED', retryAllowed: false,
        failure: { phase: 'agent-reconcile', reason: 'REBUILD_NODE_USER_SYNC_PAYLOAD_UNPROVED' } });
    assert.deepEqual(f.events, complete);
    assert.equal(f.store.copy().allowStaleUnlock, false);
});
test('joined MAIN wire: panel ACK and exact final pin follow one fenced sync, not the candidate hash', async t => {
    const f = fixture(t);
    assert.deepEqual(await f.run(), { status: 'applied', retryAllowed: false, failure: null });
    assert.deepEqual(f.events, [...complete, 'sync', 'verify', 'settle']);
    assert.equal(f.state().status, 'applied');
    assert.deepEqual(JSON.parse(fs.readFileSync(f.main)), config('b', 'drained'));
    assert.equal(f.store.copy(), null);
});
test('joined MAIN wire: refusal after reconcile retains intent and never replays sync', async t => {
    const f = fixture(t, { loseSync: true });
    await assert.rejects(f.run(), { code: 'REBUILD_MAIN_CUTOVER_UNRESOLVED', retryAllowed: false,
        failure: { phase: 'agent-reconcile', reason: 'REBUILD_NODE_USER_SYNC_UNCONFIRMED' } });
    assert.deepEqual(f.events, [...complete, 'sync']);
    assert.equal(f.state().status, 'unknown');
    assert.equal(f.state().pending.checkpoint, 'agent-reconcile');
    assert.equal(f.store.copy().allowStaleUnlock, false);
});
test('joined MAIN wire: no-effect refusal before stop releases the promoted owner', async t => {
    const f = fixture(t, { rejectBefore: true });
    assert.equal((await f.run()).status, 'not-dispatched');
    assert.deepEqual(f.events, ['read']);
    assert.equal(f.state().status, 'not-dispatched');
    assert.equal(f.store.copy(), null);
});
test('joined MAIN wire: only exact authority refusal frames carry manager check IDs', async t => {
    const reason = 'REBUILD_MAIN_AUTHORITY_UNPROVED';
    const checks = ['cc-agent.service:RequiredBy', 'xray.service:ActiveState', 'list-jobs',
        'active-invocations', 'shutdown.target:ActiveState'];
    for (const [refusalReply, expected] of [
        [{ ok: false, reason, checks }, { reason, checks }],
        [{ ok: false, reason }, { reason }],
        ...[
            { ok: false, reason, checks: [...checks, 'xray.service:Requires=private.target'] },
            { ok: false, reason, checks: ['list-jobs\n'] },
            { ok: false, reason, checks: [] },
            { ok: false, reason, checks, stderr: '/etc/private' },
            { ok: false, reason: 'REBUILD_AGENT_STOP_UNCONFIRMED', checks },
        ].map(reply => [reply, { reason: 'REBUILD_MAIN_PROOF_UNCONFIRMED' }]),
    ]) {
        const f = fixture(t, { refusalReply });
        await assert.rejects(f.run(), { code: 'REBUILD_MAIN_CUTOVER_UNRESOLVED', retryAllowed: false,
            failure: { phase: 'agent-stop', ...expected } });
        assert.deepEqual(f.events, ['read', 'stop']);
        assert.equal(f.state().status, 'unknown');
        assert.equal(f.store.copy().allowStaleUnlock, false);
    }
});
test('joined MAIN wire: initial hold refusal keeps checks without claiming settled handback', async t => {
    const reason = 'REBUILD_MAIN_AUTHORITY_UNPROVED', checks = ['xray.service:PartOf'];
    const f = fixture(t, { refusalAction: 'hold', refusalReply: { ok: false, reason, checks } });
    await assert.rejects(f.run(), { code: 'REBUILD_MAIN_CUTOVER_UNRESOLVED', retryAllowed: false,
        failure: { phase: null, reason, checks } });
    assert.deepEqual(f.events, []);
    assert.equal(f.state().status, 'not-dispatched');
    assert.equal(f.store.copy().allowStaleUnlock, false);
});
test('joined MAIN wire: inverse refuses a byte-identical replacement before its second stop', async t => {
    const f = fixture(t, { replaceBeforeInverse: true });
    await assert.rejects(f.run(), { code: 'REBUILD_MAIN_CUTOVER_UNRESOLVED', retryAllowed: false,
        failure: { phase: null, reason: 'REBUILD_MAIN_CAS_UNPROVED' } });
    assert.deepEqual(f.events, [...complete, 'sync', 'verify', 'read']);
    assert.equal(f.state().confirmed.length, 1);
    assert.equal(f.state().restored.length, 0);
    assert.equal(f.store.copy().allowStaleUnlock, false);
});
test('joined MAIN wire: a restart timeout after native effect remains pending without start or promotion cleanup', async t => {
    const f = fixture(t, { fault: 'restart-ack' });
    await assert.rejects(f.run(), { code: 'REBUILD_MAIN_CUTOVER_UNRESOLVED', retryAllowed: false,
        failure: { phase: 'xray-restart', reason: 'REBUILD_MAIN_RESTART_UNCONFIRMED' } });
    assert.deepEqual(f.events, complete.slice(0, 5));
    assert.equal(f.state().pending.checkpoint, 'xray-restart');
    assert.equal(f.store.copy().allowStaleUnlock, false);
});
