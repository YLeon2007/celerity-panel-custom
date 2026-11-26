'use strict';

// Ordinary panel service and real disposable Mongo. Only the injected host
// authority, Preview transport and agent lifecycle/sync are modeled. The
// parent owns the Xray children and maps each admitted step to its separately
// byte-pinned native fixture boot image.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { createHash, randomBytes } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { mongo: { BSON }, Types: { ObjectId } } = require('/source/node_modules/mongoose');
const { createRebuildService } = require('/source/src/services/rebuildService');
const { makeLocks, nodeLockVerifier } = require('/source/src/services/rebuildLocks');
const { createFileCutoverJournal } = require('/source/src/services/rebuildTransitCutoverJournal');
const { createCutoverArtifactStore } = require('/source/src/services/rebuildTransitCutoverArtifacts');
const { fixture } = require('/source/src/modules/relay-l2tp/tests/helpers/installedEditMongoFixture');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const clone = row => BSON.deserialize(BSON.serialize(row));
const managed = ['vless-in'];
const bytes = snapshot => Buffer.from(snapshot.data, 'base64');
const clients = snapshot => JSON.parse(bytes(snapshot)).inbounds.find(row => row.tag === managed[0]).settings.clients;
const limit = 256 * 1024;
// Application dependencies can log to stdout on the real settlement path.
// Keep their output out of the parent's request/reply stream.
const responseFd = Number(process.argv[4]);
function emit(value) {
    const frame = Buffer.from(JSON.stringify(value) + '\n');
    assert(frame.length <= limit);
    for (let sent = 0; sent < frame.length;) sent += fs.writeSync(responseFd, frame, sent);
}
function request(action, body = {}) {
    emit({ action, ...body });
    const buffer = Buffer.alloc(limit);
    for (let size = 0; size < buffer.length;) {
        const n = fs.readSync(0, buffer, size, buffer.length - size, null);
        assert(n > 0);
        size += n;
        if (buffer[size - 1] === 10) return JSON.parse(buffer.subarray(0, size));
    }
    assert.fail('oversized fixture reply');
}

async function run(operation, mongo) {
    const input = JSON.parse(fs.readFileSync('composer-output.json', 'utf8'));
    const { nodes: cards, links: draft, before, steps } = input.transition.panel;
    const names = new Map(input.profiles.map(row => [row.nodeId, row.name]));
    const owner = id => names.get(id);
    const links = draft.map(row => ({ ...row, _id: new ObjectId(row._id), portalNode: new ObjectId(row.portalNode),
        bridgeNode: new ObjectId(row.bridgeNode), ...(row.rebuildExit && {
            rebuildExit: { ...row.rebuildExit, nodeId: new ObjectId(row.rebuildExit.nodeId) }, rebuildDesiredEdited: true,
        }) }));
    const nodes = cards.map(row => ({ ...row, _id: new ObjectId(row._id), name: owner(row._id) }));
    const { versions } = request('manifest');
    const coreIdentities = new Map(cards.map(({ _id }) => [_id, versions[owner(_id)]]));
    const dialerVersions = new Map([...coreIdentities].map(([id, [version]]) => [id, version]));
    const usersByNode = new Map(cards.map(({ _id }) => [_id, input.users[owner(_id)] ? [input.users[owner(_id)]] : []]));
    const Link = mongo.models.CascadeLink;
    const store = mongo.connection.collection('c3_rebuild_locks');
    const locks = makeLocks(store);
    await Link.collection.insertMany(links, { writeConcern: { w: 'majority' } });
    const readLinks = () => Link.collection.find({}, { readPreference: 'primary', readConcern: { level: 'majority' }, raw: true }).sort({ _id: 1 }).toArray();
    const original = await readLinks();
    const initial = new Map(cards.map(({ _id: id }) => [id, request('snapshot', { owner: owner(id) })]));
    const snapshot = id => request('snapshot', { owner: owner(id) });
    const directory = `panel-${operation}-journal`;
    fs.mkdirSync(directory, { mode: 0o700 });
    const journal = createFileCutoverJournal({ directory: `/work/${directory}` });
    const artifacts = createCutoverArtifactStore({ directory: `/work/${directory}`, key: randomBytes(32) });
    const byId = new Map(steps.map(step => [step.id, step]));
    const restored = operation === 'rollback';
    let plan, openReaders = 0, opened = 0, closed = 0, invalidated = 0;
    const reconciles = [];
    const sync = {
        async _getUsersForNode(node) { return usersByNode.get(String(node._id)); },
        async syncRebuildNodeUsersAfterResume(id, { verifyFence, verifyPayload }) {
            assert(await verifyFence(id));
            const users = Object.freeze(clients(initial.get(id)).map(({ id, email, flow = '' }) => Object.freeze({ id, email, flow })));
            assert(await verifyPayload(id, users));
            assert(await verifyPayload(id, users));
            reconciles.push(id);
            return { added: 0, removed: 0, errors: 0, total: users.length };
        },
    };
    const service = createRebuildService({ Link, Node: { db: Link.db, find({ _id: { $in } }) {
        return { select() { return this; }, read() { return this; }, readConcern() { return this; },
            async lean() { return nodes.filter(n => $in.some(id => n._id.equals(id))).map(clone); } };
    } }, State: { db: Link.db, find() {
        return { select() { return this; }, read() { return this; }, readConcern() { return this; }, session() { return this; }, async lean() { return []; } };
    } }, L2tpUser: { db: Link.db }, locks, sync, env: { C3_REBUILD_ENABLED: 'true', PANEL_DOMAIN: 'panel.fixture.invalid' },
    assertNoRelayAccountIntent: async () => {}, cache: { async invalidateAllSubscriptions() { invalidated++; } },
    connect(node) {
        openReaders++;
        const id = String(node._id), [version, buildDigest] = coreIdentities.get(id);
        return { async requireSupportedCoreIdentity() { return { version, buildDigest }; }, async close() { openReaders--; },
            async read(profile) { return profile === 'main' ? JSON.parse(bytes(snapshot(id))) :
                structuredClone(before.find(p => p.nodeId === id && p.profile === profile).config); },
            async stagePair() { assert.fail('legacy staging entered'); },
            async putPair() { assert.fail('legacy activation entered'); },
        };
    },
    async serialMainAuthority({ ids, verify }) {
        await verify();
        assert.equal(openReaders, 0);
        assert.deepEqual([...ids].sort(), [...initial.keys()].sort());
        const owns = new Map(ids.map(id => [id, nodeLockVerifier(id)]));
        const peers = new Map(ids.map(id => {
            const pin = sha(Buffer.from(JSON.stringify([id, initial.get(id)])));
            return [id, { authoritySha256: pin, managed, async verify(n, digest) { return n === id && digest === pin && owns.get(id)(); } }];
        }));
        return { before: before.map(row => row.profile === 'main' ? { ...row, config: JSON.parse(bytes(snapshot(row.nodeId))) } : row),
            coreIdentities, profiles: { dialerVersions, usersByNode, controlPlaneAddresses: ['panel.fixture.invalid', '127.0.0.1'] }, peers, journal, artifacts,
            async verifyFence(candidate) {
                assert.deepEqual(candidate.steps.map(s => [s.id, s.phase]), steps.map(s => [s.id, s.phase]));
                plan ??= candidate;
                return equal(plan, candidate) && [...owns.values()].every(check => check());
            },
            async openWindow(id, { verifyOwner, verifyBeforeFrame }) {
                assert(await verifyOwner());
                opened++;
                let held = false, releasing = false, staged;
                const reply = value => ({ ok: true, value });
                return { async request({ action, target, beforeSha256, desiredSha256 }) {
                    assert(await verifyBeforeFrame());
                    if (action === 'hold') { assert(!held); held = true; return reply(null); }
                    assert(held && !releasing);
                    if (action === 'release') { assert(!staged); releasing = true; return reply(null); }
                    if (['check', 'discard-read'].includes(action)) return reply(null);
                    if (action === 'read') return reply(snapshot(id));
                    const { pending } = journal.read(plan.scope);
                    const { step: { id: step }, direction, checkpoint } = pending;
                    assert.equal(byId.get(step).nodeId, id);
                    assert.equal(checkpoint, { stop: 'agent-stop', capture: 'agent-stop', publish: 'main-publication',
                        restart: 'xray-restart', start: 'agent-start', reconcile: 'agent-reconcile', verify: 'agent-reconcile' }[action]);
                    if (action === 'stop' || action === 'start') return reply(null); // modeled lifecycle
                    if (action === 'capture') {
                        assert(!staged);
                        const { xray, ...preimage } = snapshot(id);
                        assert(equal(clients(preimage), clients({ data: target })), 'fixture clients changed during modeled drain');
                        staged = { before: preimage, desired: target };
                        return reply(staged);
                    }
                    if (action === 'publish') {
                        assert.equal(sha(Buffer.from(JSON.stringify(staged.before))), beforeSha256);
                        assert.equal(sha(bytes({ data: staged.desired })), desiredSha256);
                        const { xray, ...written } = request('publish', { owner: owner(id), step, direction, ...staged });
                        staged = undefined;
                        return reply(written);
                    }
                    if (action === 'restart') return reply(request('restart', { owner: owner(id), step, direction }));
                    assert(['reconcile', 'verify'].includes(action));
                    return reply(snapshot(id));
                }, async finish() { assert(held && releasing); closed++; }, abort() { held = false; } };
            },
            async verifySnapshot(id, _phase, snap) { return equal(snapshot(id), snap); },
            async verifyAgentEndpoint(id, n, snap) { return id === n && equal(snapshot(id), snap); },
            async readAgentManagedFlows() { return new Map([[managed[0], '']]); },
            async prove() { return request('prepared') === true; },
            async verifyTerminal(ctx, latest) {
                const unchangedMainPins = new Map();
                for (const id of ids) {
                    const observed = snapshot(id);
                    if (latest.has(id)) assert(equal(observed, latest.get(id)), 'terminal ACK differs from observed MAIN');
                    else {
                        assert(equal(observed, initial.get(id)), 'untouched MAIN or serving generation changed');
                        unchangedMainPins.set(id, sha(bytes(observed)));
                    }
                }
                const records = request('terminal', { direction: ctx.direction });
                assert(records.length > 0 && records.every(row => row.actual === row.expected));
                if (restored && ctx.direction === 'forward') return false; // existing wrong-origin drill
                return { evidence: Buffer.from(JSON.stringify(records)), unchangedMainPins };
            },
            async observe() { assert.fail('ordinary Apply must not replay'); },
        };
    } });
    const linkId = String(links[0]._id);
    const nCommands = mongo.commands.length;
    const preview = await service.execute({ linkId, preview: true });
    assert.equal(preview.allowed, true, 'ordinary Preview refused the serial fixture');
    const planned = preview.nodes.flatMap(n => Array(n.mainRestartCount ?? 0).fill(n.nodeId)).sort();
    assert.deepEqual(planned, steps.map(s => s.nodeId).sort());
    assert.equal(opened, 0);
    const result = await service.locks.run(async verify => {
        const result = await service.execute({ linkId, expectedPreview: preview.previewId }, verify);
        assert.equal((await store.findOne({ _id: 'apply' }))?.cutover?.scope, plan?.scope);
        return result;
    }, { allowStaleUnlock: false });
    assert.equal(result.previewId, preview.previewId);
    assert.equal(result.allowed, !restored);
    assert.equal(result.status, restored ? 'rolled-back' : undefined);
    assert.equal(await store.findOne({ _id: 'apply' }), null);
    assert.equal(openReaders, 0);
    assert.equal(opened, cards.length);
    assert.equal(closed, opened);
    const state = journal.read(plan.scope);
    assert.equal(state.status, restored ? 'rolled-back' : 'applied');
    assert(!state.pending);
    assert.deepEqual(state.confirmed.map(row => row.step.id), steps.map(s => s.id));
    assert.deepEqual(state.restored.map(row => row.step.id), restored ? steps.map(s => s.id).reverse() : []);
    assert.equal(reconciles.length, state.confirmed.length + state.restored.length);
    const terminal = artifacts.read({ plan, step: { id: `terminal-${restored ? 'rollback' : 'forward'}` } }, 'confirmed', state.terminalProof);
    const counts = mongo.commands.slice(nCommands);
    const commits = counts.filter(cmd => cmd.name === 'commitTransaction');
    const writes = counts.filter(cmd => cmd.name === 'update' && cmd.collection === Link.collection.collectionName);
    assert.equal(commits.length, restored ? 0 : 1);
    assert.equal(writes.length, restored ? 0 : links.length);
    assert.equal(invalidated, commits.length);
    const stored = await readLinks();
    if (restored) assert.deepEqual(stored, original);
    else {
        const [commit] = commits;
        assert.equal(commit.writeConcern.w, 'majority');
        assert(writes.every(w => w.lsid === commit.lsid && w.txnNumber === commit.txnNumber && w.autocommit === false));
        const [, side, pins] = JSON.parse(terminal.toString().split('\n')[0]);
        assert.equal(side, 'forward');
        assert.equal(pins.length, cards.length);
        const digests = new Map(pins.map(([id, , digest]) => [id, digest]));
        for (const raw of stored) {
            const link = BSON.deserialize(raw), id = String(link.portalNode);
            assert.equal(link.rebuildAppliedMainSha256, digests.get(id));
            assert.equal(link.rebuildAppliedMainSha256, sha(bytes(snapshot(id))));
            assert.equal(Object.hasOwn(link, 'rebuildDesiredEdited'), false);
        }
    }
    return { status: state.status, confirmed: state.confirmed.length, restored: state.restored.length,
        head: state.head, terminalSha256: sha(terminal), commits: commits.length, writes: writes.length, invalidated, peers: closed,
        preview: 'ordinary execute; same outer owner', authority: 'modeled host and agent; native local Xray and MongoDB' };
}

async function main() {
    process.umask(0o077);
    const [mode, parentNet] = process.argv.slice(2);
    const net = fs.readlinkSync('/proc/self/ns/net');
    const devices = fs.readFileSync('/proc/net/dev', 'utf8').trimEnd().split('\n').slice(2).map(row => row.split(':')[0].trim());
    assert(process.cwd() === '/work' && !fs.existsSync('/etc/resolv.conf') && equal(devices, ['lo']) &&
        /^net:\[\d+\]$/.test(parentNet) && net !== parentNet && ['apply', 'rollback'].includes(mode) &&
        process.env.C3_MONGOD === '/tools/mongod' && Number.isSafeInteger(responseFd) && responseFd > 2);
    process.env.TMPDIR = '/home/leon/.hermes/cache/scratch/matrix-db';
    process.env.C3_INSTALLED_EDIT_MONGO_EVIDENCE = `/work/panel-${mode}-mongo`;
    const mongo = fixture();
    let result;
    try {
        await mongo.start();
        result = await run(mode, mongo);
    } finally { await mongo.stop(); }
    assert.equal(mongo.lifecycle.exitCode, 0);
    emit({ action: 'done', ...result, mongoExit: mongo.lifecycle.exitCode });
}
main().catch(error => {
    // Only synthetic input is present, but keep the outer verdict categorical.
    const failure = error.failure ? JSON.stringify(error.failure) : '';
    process.stderr.write(`serial Apply fixture refused: ${error.code || error.name} ${failure}\n${(error.stack || '').split('\n').filter(row => row.trim().startsWith('at ')).slice(0, 6).join('\n')}\n`);
    process.exitCode = 1;
});
