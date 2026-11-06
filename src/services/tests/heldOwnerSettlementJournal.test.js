'use strict';
// Real journal and scratch filesystem IO only. These tests grant no physical
// authority and do not model or exercise Mongo transactions.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { HeldOwnerSettlementJournal } = require('../heldOwnerSettlementJournal');
const UNKNOWN = /OWNER_SETTLEMENT_JOURNAL_UNKNOWN_RETAINED/;
function plan(count = 5) {
    return { revision: 7, deployedRevision: 6, nodes: Array.from({ length: count }, (_v, i) => ({
        nodeId: (i + 1).toString(16).padStart(24, '0'), targetProfile: i === 0 ? 'xray-main' : 'xray-bridge',
        enrollmentId: randomUUID(), ownerGeneration: randomUUID(),
    })) };
}
function fixture(t, savedPlan = plan()) {
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR, 'owner-journal-membership-'));
    const directory = path.join(root, 'journal'); fs.mkdirSync(directory, { mode: 0o700 });
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const options = { directory, uid: process.getuid(), fixtureRoot: root };
    const journal = new HeldOwnerSettlementJournal(options), file = path.join(directory, 'owner-settlement.json');
    return { journal, file, options, savedPlan,
        bytes: () => fs.readFileSync(file), read: () => JSON.parse(fs.readFileSync(file)),
        settle(ids = savedPlan.nodes.map(n => n.nodeId)) {
            for (const id of ids) { journal.beforeNode(id); journal.afterNode(id, randomUUID()); }
        } };
}

test('completion rejects a foreign replacement even when five confirmations match the saved cardinality', t => {
    const f = fixture(t); f.journal.start(f.savedPlan);
    f.settle([...f.savedPlan.nodes.slice(0, -1).map(n => n.nodeId), 'f'.repeat(24)]);
    const before = f.bytes(); assert.throws(() => f.journal.complete(), UNKNOWN);
    assert.deepEqual(f.bytes(), before); assert.equal(f.read().phase, 'settling-held');
});

test('completion rejects a missing saved-plan owner without changing the checkpoint', t => {
    const f = fixture(t, plan(2)); f.journal.start(f.savedPlan);
    f.settle([f.savedPlan.nodes[0].nodeId]);
    const before = f.bytes(); assert.throws(() => f.journal.complete(), UNKNOWN);
    assert.deepEqual(f.bytes(), before); assert.equal(f.read().settled.length, 1);
});

test('five confirmations cannot replace the cardinality of a two-node saved plan', t => {
    const f = fixture(t, plan(2)); f.journal.start(f.savedPlan);
    f.settle([...f.savedPlan.nodes.map(n => n.nodeId), 'a'.repeat(24), 'b'.repeat(24), 'c'.repeat(24)]);
    const before = f.bytes(); assert.throws(() => f.journal.complete(), UNKNOWN);
    assert.deepEqual(f.bytes(), before);
});

test('duplicate confirmation is refused and cannot stand in for the missing owner', t => {
    const f = fixture(t, plan(2)); f.journal.start(f.savedPlan);
    const first = f.savedPlan.nodes[0].nodeId; f.settle([first]);
    const before = f.bytes();
    assert.throws(() => f.journal.beforeNode(first), UNKNOWN);
    assert.throws(() => f.journal.afterNode(first, randomUUID()), UNKNOWN);
    assert.throws(() => f.journal.complete(), UNKNOWN);
    assert.deepEqual(f.bytes(), before);
});

test('completion refuses duplicate membership in a malformed saved plan', t => {
    // Direct journal defense; the public settlement service rejects this plan
    // before start. Five distinct confirmations must not hide the duplicate.
    const f = fixture(t), ids = f.savedPlan.nodes.map(n => n.nodeId);
    f.savedPlan.nodes[1] = structuredClone(f.savedPlan.nodes[0]);
    f.journal.start(f.savedPlan); f.settle(ids);
    const before = f.bytes(); assert.throws(() => f.journal.complete(), UNKNOWN);
    assert.deepEqual(f.bytes(), before);
});

test('in-flight and unknown-node acknowledgements cannot complete an otherwise full saved set', t => {
    const f = fixture(t); f.journal.start(f.savedPlan); f.settle();
    const unknown = 'f'.repeat(24); f.journal.beforeNode(unknown);
    const before = f.bytes();
    assert.throws(() => f.journal.afterNode('e'.repeat(24), randomUUID()), UNKNOWN);
    assert.throws(() => f.journal.complete(), UNKNOWN);
    assert.deepEqual(f.bytes(), before); assert.equal(f.read().inFlightNode, unknown);
});

test('completion uses the saved plan clone rather than later caller membership edits', t => {
    const f = fixture(t, plan(2)), saved = structuredClone(f.savedPlan);
    f.journal.start(f.savedPlan);
    f.savedPlan.nodes = plan(5).nodes;
    f.settle(saved.nodes.map(n => n.nodeId).reverse()); f.journal.complete();
    const row = f.read();
    assert.deepEqual(row.plan, saved); assert.equal(row.phase, 'settled-held');
    assert.deepEqual(row.settled.map(n => n.nodeId).sort(), saved.nodes.map(n => n.nodeId).sort());
});

test('every durable write keeps real file fsync before parent fsync including legacy-five completion and commit', t => {
    const f = fixture(t), syncs = [], sync = fs.fsyncSync;
    t.mock.method(fs, 'fsyncSync', fd => {
        syncs.push(fs.fstatSync(fd).isDirectory() ? 'parent' : 'file'); return sync(fd);
    });
    f.journal.start(f.savedPlan); f.settle(f.savedPlan.nodes.map(n => n.nodeId).reverse());
    f.journal.complete(); f.journal.committed('a'.repeat(64));
    assert.deepEqual(syncs, Array.from({ length: 1 + 2 * 5 + 2 }, () => ['file', 'parent']).flat());
    const row = f.read(); assert.equal(row.version, 1); assert.equal(row.phase, 'irreversibly-committed');
    assert.equal(fs.statSync(f.file).mode & 0o777, 0o600);
    assert.equal(fs.existsSync(f.file + '.next'), false);
});

test('existing journal refuses replay without overwriting either settling or committed state', t => {
    for (const committed of [false, true]) {
        const f = fixture(t); f.journal.start(f.savedPlan);
        if (committed) { f.settle(); f.journal.complete(); f.journal.committed('a'.repeat(64)); }
        const before = f.bytes(), replay = new HeldOwnerSettlementJournal(f.options);
        assert.throws(() => replay.start(f.savedPlan), { code: 'EEXIST' });
        assert.throws(() => replay.start(f.savedPlan), UNKNOWN);
        assert.deepEqual(f.bytes(), before);
    }
});

test('a preexisting next file is never overwritten and poisons this writer even after its removal', t => {
    const f = fixture(t); f.journal.start(f.savedPlan);
    const next = f.file + '.next'; fs.writeFileSync(next, 'retained unknown write', { mode: 0o600, flag: 'wx' });
    const before = f.bytes();
    assert.throws(() => f.journal.beforeNode(f.savedPlan.nodes[0].nodeId), UNKNOWN);
    assert.equal(fs.readFileSync(next, 'utf8'), 'retained unknown write'); assert.deepEqual(f.bytes(), before);
    fs.unlinkSync(next);
    assert.throws(() => f.journal.beforeNode(f.savedPlan.nodes[0].nodeId), UNKNOWN);
    assert.deepEqual(f.bytes(), before);
});

test('unknown completion parent-fsync outcome retains its written phase and poisons further writes', t => {
    const f = fixture(t); f.journal.start(f.savedPlan); f.settle();
    const sync = fs.fsyncSync; let failed = false;
    t.mock.method(fs, 'fsyncSync', fd => {
        if (!failed && fs.fstatSync(fd).isDirectory()) { failed = true; throw new Error('MODELED parent fsync acknowledgement lost'); }
        return sync(fd);
    });
    assert.throws(() => f.journal.complete(), /parent fsync acknowledgement lost/);
    // Rename really occurred. The failed parent fsync cannot be called durable
    // success; no retry, commit acknowledgement, or rollback is authorized.
    const before = f.bytes(); assert.equal(f.read().phase, 'settled-held');
    assert.throws(() => f.journal.complete(), UNKNOWN);
    assert.throws(() => f.journal.committed('a'.repeat(64)), UNKNOWN);
    assert.deepEqual(f.bytes(), before);
    assert.throws(() => new HeldOwnerSettlementJournal(f.options).start(f.savedPlan), { code: 'EEXIST' });
    assert.deepEqual(f.bytes(), before);
});

test('on-disk plan drift cannot replace saved membership and remains poisoned after byte restoration', t => {
    const f = fixture(t); f.journal.start(f.savedPlan); f.settle();
    const original = f.bytes(), row = f.read(); row.plan.nodes[0].nodeId = 'f'.repeat(24);
    fs.writeFileSync(f.file, JSON.stringify(row) + '\n'); const drifted = f.bytes();
    assert.throws(() => f.journal.complete(), UNKNOWN); assert.deepEqual(f.bytes(), drifted);
    fs.writeFileSync(f.file, original);
    assert.throws(() => f.journal.complete(), UNKNOWN); assert.deepEqual(f.bytes(), original);
});

test('phase guards retain the irreversible committed state and reject every valid replay mutation', t => {
    const f = fixture(t); assert.throws(() => f.journal.complete(), UNKNOWN);
    f.journal.start(f.savedPlan); f.settle(); f.journal.complete();
    assert.throws(() => f.journal.complete(), UNKNOWN);
    f.journal.committed('a'.repeat(64)); const before = f.bytes();
    const id = f.savedPlan.nodes[0].nodeId;
    for (const action of [() => f.journal.start(f.savedPlan), () => f.journal.beforeNode(id),
        () => f.journal.afterNode(id, randomUUID()), () => f.journal.complete(), () => f.journal.committed('b'.repeat(64))])
        assert.throws(action, UNKNOWN);
    assert.deepEqual(f.bytes(), before);
});
