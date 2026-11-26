'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash, randomBytes } = require('node:crypto');
const { mongo: { BSON }, Types: { ObjectId } } = require('mongoose');
const { createRebuildService } = require('../rebuildService');
const { makeLocks, nodeLockVerifier } = require('../rebuildLocks');
const { createFileCutoverJournal } = require('../rebuildTransitCutoverJournal');
const { createCutoverArtifactStore } = require('../rebuildTransitCutoverArtifacts');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/services/rebuildTopologyComposer');

const id = n => n.toString(16).padStart(24, '0');
const oid = n => new ObjectId(id(n));
const sha = data => createHash('sha256').update(data).digest('hex');
const json = data => Buffer.from(JSON.stringify(data));
const clone = value => BSON.deserialize(BSON.serialize(value));
const nodes = ['portal', 'relay', 'relay', 'bridge', 'bridge'].map((cascadeRole, i) => ({ _id: oid(i + 1), cascadeRole,
    type: 'xray', active: true, ip: `192.0.2.${i + 1}`, port: 22001 + i, xray: { security: 'none', apiPort: 23001 + i } }));
const links = [1, 2, 3, 4].map(n => ({ _id: oid(100 + n), portalNode: oid(n === 4 ? 3 : n), bridgeNode: oid(n + 1), active: true,
    priority: n, mode: n === 2 ? 'forward' : 'reverse', tunnelProtocol: 'vless', tunnelTransport: 'tcp', tunnelPort: 24000 + n,
    tunnelUuid: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`, tunnelEncryption: 'none',
    ...(n === 1 && { rebuildExit: { nodeId: oid(5), relayGeo: false }, rebuildAppliedExit: null }),
    rebuildDesiredEdited: true, rebuildAppliedMainSha256: 'd'.repeat(64), foreign: { value: n } }));
const anchor = String(links[0]._id);
const query = rows => ({ select() { return this; }, read() { return this; }, readConcern() { return this; },
    session() { return this; }, lean: async () => rows.map(clone) });
const unknown = { code: 'REBUILD_MAIN_CUTOVER_UNRESOLVED', retryAllowed: false };
test.after(() => require.cache[require.resolve('../sshPoolService')]?.exports.closeAll());

// Real service, planner, adapter, local locks, journal, artifacts and BSON.
// Native-host observation is modeled. Optional native store executes the exact
// transaction, command and BSON CAS against a disposable real replica set.
function fixture(t, fault, native, mounted = false) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'c3-panel-serial.'));
    t.after(() => fs.rmSync(root, { recursive: true }));
    for (const dir of ['journal', 'artifacts']) fs.mkdirSync(path.join(root, dir), { mode: 0o700 });
    const journal = createFileCutoverJournal({ directory: path.join(root, 'journal') });
    const artifacts = createCutoverArtifactStore({ directory: path.join(root, 'artifacts'), key: randomBytes(32) });
    const events = [], counts = { open: 0, begin: 0, write: 0, commit: 0, abort: 0, invalidate: 0 };
    let lock, stored = links.map(clone), scope;
    const match = q => lock && Object.entries(q).every(([k, v]) => k === '$expr' ?
        (assert.equal(v.$eq[0], '$$ROOT'), BSON.serialize(lock).equals(BSON.serialize(v.$eq[1].$literal))) : lock[k] === v);
    const locks = makeLocks({
        async insertOne(row) {
            if (lock) throw Object.assign(new Error('duplicate'), { code: 11000 });
            lock = clone(row); return { acknowledged: true };
        },
        async findOne(q) { return match(q) ? clone(lock) : null; },
        async updateMany(q, { $set }) {
            assert(match(q)); Object.assign(lock, $set); return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
        },
        async deleteMany(q) {
            assert(match(q));
            if (lock.cutover) {
                events.push('release');
                if (fault === 'release-ack') return { acknowledged: false };
            }
            lock = null; return { acknowledged: true, deletedCount: 1 };
        },
    });
    const state = () => scope && journal.read(scope);
    const fenced = () => lock?.cutover?.scope === scope && lock?.allowStaleUnlock === false &&
        nodes.every(({ _id }) => nodeLockVerifier(String(_id))());
    class Session {
        transaction = { transition: value => { assert.equal(value, 'TRANSACTION_COMMITTED'); this.active = false; } };
        startTransaction(opts) {
            assert(fenced()); assert.equal(state().status, 'applied'); assert.equal(opts.readConcern.level, 'snapshot');
            counts.begin++; this.active = true; this.rows = stored.map(clone);
        }
        inTransaction() { return this.active; }
        async abortTransaction() { counts.abort++; this.active = false; }
        async endSession() { assert(!this.active); }
        async commitTransaction() { assert.fail('retryable driver helper'); }
    }
    let session;
    const db = {
        async startSession() { session = new Session(); return session; },
        transaction() { assert.fail('retryable body'); },
        getClient: () => ({ db(name) {
            assert.equal(name, 'admin');
            return { async command(command, opts) {
                assert.equal(command.commitTransaction, 1); assert.equal(command.writeConcern.w, 'majority');
                assert.equal(opts.session, session); assert(fenced()); assert(session.inTransaction());
                counts.commit++; stored = session.rows;
                if (fault === 'commit') throw Error('modeled lost reply after commit');
                if (fault === 'postread') stored[0].rebuildAppliedExit.relayGeo = true;
                return { ok: 1 };
            } };
        } }),
    };
    const Link = { db, find: () => query(stored), collection: {
        find(filter, opts) {
            assert.deepEqual(filter, { $or: [{ active: true }, { rebuildDelete: true }] });
            assert.equal(opts.raw, true);
            if (opts.session) assert.equal(opts.session, session);
            else assert.equal(opts.readConcern.level, 'majority');
            return { async *[Symbol.asyncIterator]() {
                for (const row of (opts.session ? session.rows : stored)) yield BSON.serialize(row);
            } };
        },
        async updateMany(filter, update, opts) {
            counts.write++;
            assert(fenced()); assert.equal(opts.session, session); assert(session.inTransaction());
            const row = session.rows.find(v => v._id.equals(filter._id));
            assert.equal(filter.$expr.$eq[0], '$$ROOT');
            assert(BSON.serialize(row).equals(BSON.serialize(filter.$expr.$eq[1].$literal)));
            if (fault === 'cas' && counts.write === 2) return { acknowledged: true, matchedCount: 0, modifiedCount: 0 };
            Object.assign(row, clone(update.$set));
            for (const key of Object.keys(update.$unset)) delete row[key];
            if (fault === 'write-ack' && counts.write === 2) return { acknowledged: false, matchedCount: 1, modifiedCount: 1 };
            if (fault === 'readback' && counts.write === 2) row.rebuildApplied.uuid = 'wrong';
            return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
        },
    } };
    const before = composeRebuildProfiles({ nodes, links: links.map(({ rebuildExit, ...link }) => link) });
    const after = composeRebuildProfiles({ nodes, links });
    const current = new Map(before.filter(row => row.profile === 'main').map(({ nodeId, config }) =>
        [nodeId, { data: Buffer.from(JSON.stringify(config, null, 2)).toString('base64'), metadata: [0, 0, 416],
            generation: ['1', '1', '1'], xray: [10, '1'.repeat(32)] }]));
    const bytes = data => Buffer.from(data, 'base64');
    const frame = value => ({ ok: true, value: structuredClone(value) });
    const managed = 'vless-in';
    const clientList = config => config.inbounds.find(i => i.tag === managed).settings.clients;
    const authority = async ({ ids, verify }) => {
        await verify();
        const peers = new Map(ids.map(n => [n, { authoritySha256: sha(n), managed: [managed],
            async readMainSha256() { return sha(bytes(current.get(n).data)); }, async verify(target, digest) {
            assert.equal(target, n); assert.equal(digest, sha(n)); return !(fault === 'peer' && n === id(1));
        } }]));
        return { before: fault === 'admission-profile' ? before.map((p, i) => i ? p :
            { ...p, config: { ...p.config, log: { loglevel: 'error' } } }) : before, peers, journal, artifacts,
            async verifyFence(plan) { scope = plan.scope; return true; },
            async openWindow(n, { verifyBeforeFrame }) {
                assert.notEqual(n, id(1), 'untouched portal must not have a writer');
                assert(fenced()); counts.open++;
                let staged, held = false, releasing = false;
                return { async request({ action, target, desiredSha256 }) {
                    assert(await verifyBeforeFrame());
                    if (action === 'hold') { assert(!held); held = true; return frame(null); }
                    assert(held && !releasing);
                    if (action === 'release') { releasing = true; return frame(null); }
                    if (['check', 'discard-read'].includes(action)) return frame(null);
                    const snap = current.get(n);
                    if (action === 'stop') {
                        const config = JSON.parse(bytes(snap.data));
                        clientList(config).splice(0, Infinity, { id: 'drained-fixture-user', email: 'fixture@example.invalid' });
                        snap.data = json(config).toString('base64');
                    }
                    if (action === 'capture') {
                        const config = JSON.parse(bytes(target));
                        clientList(config).splice(0, Infinity, ...clientList(JSON.parse(bytes(snap.data))));
                        staged = json(config);
                        const { xray, ...preimage } = snap;
                        return frame({ before: preimage, desired: staged.toString('base64') });
                    }
                    if (action === 'publish') {
                        assert.equal(sha(staged), desiredSha256);
                        snap.data = staged.toString('base64');
                        snap.generation[1] = String(Number(snap.generation[1]) + 1);
                        const { xray, ...out } = snap;
                        return frame(out);
                    }
                    if (action === 'restart') {
                        const pid = snap.xray[0] + 1;
                        snap.xray = [pid, pid.toString(16).padStart(32, '0')];
                    }
                    return frame(['stop', 'start'].includes(action) ? null : snap);
                }, async finish() { assert(fenced() && held && releasing); held = false; }, abort() { held = false; } };
            },
            async verifySnapshot(n, phase, snap) { return fenced() && snap.data === current.get(n).data; },
            async verifyAgentEndpoint(n, target) { return fenced() && n === target; },
            async readAgentManagedFlows(n, target, snap) {
                assert.equal(n, target);
                assert.equal(snap.data, current.get(n).data);
                return new Map([[managed, '']]);
            },
            async syncNodeUsers() { assert.fail('host authority must not supply the panel sync dispatcher'); },
            async prove() { return fenced() && fault !== 'rollback'; },
            async verifyTerminal(ctx, latest) {
                for (const [n, snap] of latest) assert.deepEqual(snap, current.get(n));
                if (fault === 'drift') stored[0].foreign = { added: true };
                // The adapter must hash its original snapshot, not this copy.
                for (const snap of latest.values()) snap.data = 'bad';
                return { evidence: Buffer.from(`modeled-${ctx.direction}-route-proof`),
                    unchangedMainPins: fault === 'no-pin' ? new Map() : new Map(ids.filter(n => !latest.has(n)).map(n => [n, sha(bytes(current.get(n).data))])) };
            },
            async observe() { assert.fail('must not auto-reconcile'); },
        };
    };
    const sync = { async _getUsersForNode() { assert(mounted); return []; }, async syncRebuildNodeUsersAfterResume(n, { verifyFence, verifyPayload }) {
        assert(await verifyFence(n));
        const users = Object.freeze(clientList(JSON.parse(bytes(current.get(n).data))).map(row => Object.freeze({ ...row, flow: '' })));
        assert(await verifyPayload(n, users)); assert(await verifyPayload(n, users));
        return { added: 0, removed: 0, errors: 0, total: users.length };
    } };
    const selectedDb = native?.db ?? db;
    const make = serialMainAuthority => createRebuildService({ Link: native ?? Link,
        Node: { db: selectedDb, find: () => query(nodes) }, State: { db: selectedDb, find: () => query([]) },
        L2tpUser: { db: selectedDb }, sync, locks, env: { C3_REBUILD_ENABLED: 'true',
            ...(mounted && serialMainAuthority && { C3_REBUILD_CHAIN_APPLY: '1' }) }, assertNoRelayAccountIntent: async () => {},
        connect(node) {
            assert(mounted, 'ordinary SSH must not enter');
            const n = String(node._id);
            return { async requireSupportedCore() {}, async close() {
                if (fault === 'reader-close' && n === String(nodes[0]._id) && counts.closeArmed) throw new Error('modeled reader close');
            },
                async read(profile) {
                    if (profile === 'main') return JSON.parse(bytes(current.get(n).data));
                    return structuredClone(before.find(p => p.nodeId === n && p.profile === profile).config);
                },
                async checkMainRoutingService() { return true; },
                async stagePair() { assert.fail('scoped MAIN must never enter legacy staging'); },
                async putPair() { assert.fail('scoped MAIN must never enter legacy activation'); },
            };
        }, serialMainAuthority,
        cache: { async invalidateAllSubscriptions() { assert(fenced()); counts.invalidate++; events.push('invalidate'); } },
    });
    return { service: make(authority), ordinary: make(), current, after, counts, events, state, artifacts,
        lock: () => lock, stored: () => stored.map(clone) };
}

test('real replica set accepts exact wire BSON and one raw majority COMMIT', { skip: !process.env.C3_MONGOD }, async t => {
    const mongo = require('../../modules/relay-l2tp/tests/helpers/installedEditMongoFixture').fixture();
    t.after(() => mongo.stop());
    await mongo.start();
    const realLink = mongo.models.CascadeLink;
    const collection = realLink.collection;
    const seed = links.map(clone);
    seed[0].foreign.typeWitness = new BSON.Long(7);
    await collection.insertMany(seed, { writeConcern: { w: 'majority' } });
    const f = fixture(t, undefined, realLink);
    const countBefore = mongo.commands.length;
    assert.equal((await f.service.applySerialMain(anchor)).status, 'applied');
    assert.equal(f.lock(), null);
    const calls = mongo.commands.slice(countBefore);
    const writes = calls.filter(c => c.name === 'update' && c.collection === collection.collectionName);
    assert.equal(writes.length, links.length);
    const commit = calls.filter(c => c.name === 'commitTransaction');
    assert.equal(commit.length, 1);
    assert.equal(commit[0].writeConcern.w, 'majority');
    assert(writes.every(c => c.lsid === commit[0].lsid && c.txnNumber === commit[0].txnNumber && c.autocommit === false));
    assert.equal(calls.filter(c => c.name === 'abortTransaction').length, 0);
    const stored = await collection.find({}, { readPreference: 'primary', readConcern: { level: 'majority' }, promoteValues: false })
        .sort({ _id: 1 }).toArray();
    assert.equal(stored[0].foreign.typeWitness._bsontype, 'Long');
    for (const row of stored) {
        assert.equal(row.rebuildAppliedMainSha256, sha(Buffer.from(f.current.get(String(row.portalNode)).data, 'base64')));
        assert.equal(Object.hasOwn(row, 'rebuildDesiredEdited'), false);
    }
});

test('request flags cannot install serial authority or bypass confirmation', async t => {
    const f = fixture(t);
    assert.equal(f.ordinary.applySerialMain, undefined);
    await assert.rejects(f.ordinary.execute({ linkId: anchor, serialMainAuthority: true }), { code: 'REBUILD_SCOPED_TRANSIT_APPLY_UNAVAILABLE' });
    assert.equal(f.counts.open, 0); assert.equal(f.counts.begin, 0);
});

test('ordinary Apply consumes the same preview and uses only the joined MAIN path with trusted admission', async t => {
    const f = fixture(t, undefined, undefined, true);
    const preview = await f.service.execute({ linkId: anchor, preview: true });
    assert.equal(preview.allowed, true);
    assert(preview.nodes.some(node => node.mainRestartCount > 0));
    assert.equal(f.counts.open, 0);
    await assert.rejects(f.service.execute({ linkId: anchor, serialMainAuthority: true }), { code: 'REBUILD_SCOPED_TRANSIT_APPLY_UNAVAILABLE' });
    await assert.rejects(f.service.execute({ linkId: anchor, expectedPreview: preview.previewId.slice(0, 64) + 'd'.repeat(64) }),
        { code: 'REBUILD_PREVIEW_CHANGED' });
    assert.equal(f.counts.open, 0); assert.equal(f.counts.begin, 0);
    assert.equal((await f.service.execute({ linkId: anchor, expectedPreview: preview.previewId })).previewId, preview.previewId);
    assert.equal(f.state().status, 'applied');
    assert.equal(f.counts.commit, 1);
    assert.equal(f.lock(), null);
});

test('ordinary Apply drains Preview readers before it can dispatch a held write', async t => {
    const f = fixture(t, 'reader-close', undefined, true);
    const { previewId: expectedPreview } = await f.service.execute({ linkId: anchor, preview: true });
    f.counts.closeArmed = true;
    await assert.rejects(f.service.execute({ linkId: anchor, expectedPreview }), { code: 'REBUILD_TRANSPORT_CLEANUP_FAILED' });
    assert.equal(f.state(), undefined);
    assert.equal(f.counts.open, 0);
    assert.equal(f.lock(), null);
});

for (const outer of [false, true]) test(`ordinary Apply classifies lost lock handback after verified commit (outer=${outer})`, async t => {
    const f = fixture(t, 'release-ack', undefined, true);
    const { previewId: expectedPreview } = await f.service.execute({ linkId: anchor, preview: true });
    const apply = verify => f.service.execute({ linkId: anchor, expectedPreview }, verify);
    await assert.rejects(outer ? f.service.locks.run(apply) : apply(),
        { code: 'REBUILD_LOCK_RELEASE_UNCONFIRMED', settledMain: true });
    assert.equal(f.state().status, 'applied');
    assert.equal(f.counts.commit, 1);
    assert.equal(f.lock()?.allowStaleUnlock, false);
    await assert.rejects(apply(), { code: 'REBUILD_BUSY' });
    assert.equal(f.counts.commit, 1);
});

test('ordinary Apply rebinds the authority baseline before opening the journaled writer', async t => {
    const f = fixture(t, 'admission-profile', undefined, true);
    const { previewId: expectedPreview } = await f.service.execute({ linkId: anchor, preview: true });
    await assert.rejects(f.service.execute({ linkId: anchor, expectedPreview }), { code: 'REBUILD_PREVIEW_CHANGED' });
    assert.equal(f.counts.open, 0);
    assert.equal(f.lock(), null);
});

test('ordinary Apply under the original outer owner reports inverse only after successful handback', async t => {
    const f = fixture(t, 'rollback', undefined, true);
    const { previewId: expectedPreview } = await f.service.execute({ linkId: anchor, preview: true });
    const result = await f.service.locks.run(async verify => {
        const outcome = await f.service.execute({ linkId: anchor, expectedPreview }, verify);
        assert(f.lock()?.cutover);
        return outcome;
    });
    assert.equal(result.status, 'rolled-back');
    assert.equal(result.allowed, false);
    assert.equal(f.state().status, 'rolled-back');
    assert.equal(f.counts.commit, 0);
    assert.equal(f.lock(), null);
});

test('serial settlement publishes independently confirmed changed and unchanged MAIN pins in one transaction', async t => {
    const f = fixture(t);
    assert.deepEqual(await f.service.applySerialMain(anchor), { status: 'applied', retryAllowed: false, failure: null });
    const stored = f.stored();
    assert.equal(f.state().status, 'applied'); assert.equal(f.lock(), null);
    assert.deepEqual(f.events, ['invalidate', 'release']);
    assert.equal(f.counts.begin, 1); assert.equal(f.counts.commit, 1); assert.equal(f.counts.abort, 0);
    assert.equal(f.counts.write, links.length); assert.equal(f.counts.invalidate, 1);
    assert.deepEqual(stored[0].rebuildAppliedExit, links[0].rebuildExit);
    const { plan, terminalProof } = f.state();
    const evidence = f.artifacts.read({ plan, step: { id: 'terminal-forward' } }, 'confirmed', terminalProof).toString();
    assert.deepEqual(JSON.parse(evidence.split('\n')[0]), ['rebuild-panel-main-v1', 'forward', nodes.map(({ _id }) => {
        const n = String(_id);
        return [n, sha(n), sha(Buffer.from(f.current.get(n).data, 'base64'))];
    })]);
    for (const [i, link] of stored.entries()) {
        const n = String(link.portalNode), candidate = f.after.find(row => row.nodeId === n && row.profile === 'main').config;
        assert.equal(link.rebuildAppliedMainSha256, sha(Buffer.from(f.current.get(n).data, 'base64')));
        assert.notEqual(link.rebuildAppliedMainSha256, sha(json(candidate)));
        assert.equal(link.rebuildApplied.uuid, links[i].tunnelUuid); assert.match(link.rebuildApplyEpoch, /^[a-f0-9]{32}$/);
        assert.equal(Object.hasOwn(link, 'rebuildDesiredEdited'), false); assert.deepEqual(link.foreign, links[i].foreign);
    }
});

test('missing independent proof for an untouched portal refuses before opening a writer', async t => {
    const f = fixture(t, 'peer');
    await assert.rejects(f.service.applySerialMain(anchor), { code: 'REBUILD_MAIN_AUTHORITY_UNPROVED' });
    assert.equal(f.counts.open, 0); assert.equal(f.counts.begin, 0); assert.equal(f.lock(), null);
});

test('confirmed rollback writes no panel business state', async t => {
    const f = fixture(t, 'rollback');
    assert.equal((await f.service.applySerialMain(anchor)).status, 'rolled-back');
    assert.equal(f.counts.begin, 0); assert.deepEqual(f.stored(), links); assert.equal(f.lock(), null);
});

for (const [fault, begins, writes, commits, aborts] of [
    ['no-pin', 0, 0, 0, 0], ['drift', 1, 0, 0, 1], ['cas', 1, 2, 0, 1], ['write-ack', 1, 2, 0, 1], ['readback', 1, links.length, 0, 1],
    ['commit', 1, links.length, 1, 0], ['postread', 1, links.length, 1, 0],
]) test(`serial ${fault}: unknown, exact retained fence, no replay`, async t => {
    const f = fixture(t, fault);
    await assert.rejects(f.service.applySerialMain(anchor), unknown);
    assert(f.counts.open > 0);
    const lock = f.lock();
    assert.equal(lock.allowStaleUnlock, false); assert.equal(lock.cutover.scope, f.state().plan.scope);
    assert.deepEqual([f.counts.begin, f.counts.write, f.counts.commit, f.counts.abort], [begins, writes, commits, aborts]);
    assert.equal(f.counts.invalidate, 0);
    for (const row of f.stored()) assert.equal(row.rebuildAppliedMainSha256 === 'd'.repeat(64), !commits);
    const after = { ...f.counts };
    await assert.rejects(f.service.applySerialMain(anchor), { code: 'REBUILD_BUSY' });
    assert.deepEqual(f.counts, after); assert.deepEqual(f.lock(), lock);
});
