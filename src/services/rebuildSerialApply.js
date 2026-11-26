'use strict';

const { createHash, randomBytes } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { mongo: { BSON }, Types: { ObjectId } } = require('mongoose');
const { withNodes, nodeLockVerifier } = require('./rebuildLocks');
const { componentFor, profilePreview } = require('./rebuildCoordinator');
const { prepareLinks } = require('./rebuildLinkKeys');
const { keyEnvelopeField } = require('./rebuildLinkSnapshot');
const { appliedLink } = require('./rebuildAppliedLink');
const { isKcp, isReverse, unverified } = require('./rebuildReverseLinkHealth');
const { storedExit } = require('./rebuildExit');
const { planSerialScopedTransition } = require('./rebuildTransitActivationPlan');
const { runJournaledMainApply } = require('./rebuildTransitMainApply');
const { transactOnce } = require('./rebuildRelayInstallTransaction');

const MAX = 128;
const inventoryLimit = 2048;
const id = /^[a-f0-9]{24}(?![\s\S])/;
const sha = /^[a-f0-9]{64}(?![\s\S])/;
const isSha = value => typeof value === 'string' && sha.test(value);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => Object.assign(new Error(code), { code });
const need = (ok, code = 'REBUILD_MAIN_AUTHORITY_UNPROVED') => { if (!ok) throw fail(code); };
const changed = 'REBUILD_LINK_CHANGED';
const unavailable = 'REBUILD_SCOPED_TRANSIT_APPLY_UNAVAILABLE';
const read = session => ({ timeoutMS: 5000, ...(session ? { session } : {
    readPreference: 'primary', readConcern: { level: 'majority' },
}) });
const typed = { promoteValues: false, bsonRegExp: true };
const unpack = (bytes, options) => BSON.deserialize(bytes, options);
// Ignore only concurrent health telemetry we do not write, never business
// metadata (including the edit flag and any unknown field).
const telemetry = ['status', 'lastError', 'lastHealthCheck', 'latencyMs', 'updatedAt', 'rebuildReverseObservation'];
function image(row, written = []) {
    const omit = new Set(telemetry.filter(key => !written.includes(key)));
    return BSON.serialize(Object.fromEntries(Object.keys(row).sort().filter(key => !omit.has(key)).map(key => [key, row[key]])));
}
function publication(link, roles, pins) {
    const source = String(link.portalNode), main = pins.get(source);
    need(isSha(main));
    const portalIngress = roles.get(source) === 'portal' && roles.get(String(link.bridgeNode)) === 'relay';
    const exit = storedExit(link.rebuildExit);
    const $set = { ...(isReverse(link) ? unverified : { status: 'deployed', lastError: '' }), rebuildApplied: appliedLink(link),
        rebuildApplyEpoch: randomBytes(16).toString('hex'), rebuildAppliedMainSha256: main, updatedAt: new Date(),
        ...(portalIngress ? { rebuildAppliedExit: exit ? { ...exit, nodeId: new ObjectId(exit.nodeId) } : null } : {}) };
    const $unset = { rebuildReverseObservation: '', rebuildDesiredEdited: '', rebuildKcpApplied: '',
        ...(!portalIngress ? { rebuildAppliedExit: '' } : {}) };
    return { $set, $unset };
}

// Construction-time, in-process seam only. No ordinary SSH connector or route
// can supply admission. The authority provider must hold independently pinned
// peers for the entire roster, including untouched peers, and prove preserved
// routes/user reconciliation. No provider is installed by the shipped panel.
function createSerialApply({ Link, Node, State, env, locks, gate, compose, readStates, publishedKeyMismatch, invalidate, admit, syncNodeUsers }) {
    return async linkId => {
        gate();
        need(typeof linkId === 'string' && id.test(linkId), 'REBUILD_INVALID_REQUEST');
        need(Link.db && Link.db === Node.db && Link.db === State.db, unavailable);
        const scope = async session => {
            const cursor = Link.collection.find({ $or: [{ active: true }, { rebuildDelete: true }] },
                { ...read(session), raw: true, limit: inventoryLimit + 1, batchSize: 16 });
            const all = [];
            let size = 0;
            for await (const bytes of cursor) {
                size += bytes.length;
                need(all.length < inventoryLimit && size <= 16 * 1024 * 1024, unavailable);
                all.push({ bytes, row: unpack(bytes) });
            }
            const anchor = all.find(({ row }) => String(row._id) === linkId)?.row;
            need(anchor?.active === true && !anchor.rebuildDelete, changed);
            const ids = componentFor(all.map(({ row }) => row), [anchor.portalNode, anchor.bridgeNode]);
            const members = new Set(ids);
            const rows = all.filter(({ row }) => members.has(String(row.portalNode)) && members.has(String(row.bridgeNode)))
                .sort((a, b) => String(a.row._id).localeCompare(String(b.row._id)));
            need(ids.length <= MAX && ids.every(n => id.test(n)) && rows.length <= MAX, unavailable);
            return { ids, rows };
        };
        return locks.run(async (verify, retain) => {
            const { ids } = await scope();
            return withNodes(ids, async () => {
                const original = await scope();
                need(equal(original.ids, ids), changed);
                const links = original.rows.map(({ row }) => row);
                // The serial planner is additive, TCP, MAIN-only. Do not
                // combine it with tombstone deletion, new link keys or L2TP
                // route-mode migration; those have different write contracts.
                need(links.every(row => row.active === true && !row.rebuildDelete && !row.lifecycle && !isKcp(row) &&
                    [row._id, row.portalNode, row.bridgeNode].every(value => value instanceof ObjectId)), unavailable);
                const nodes = await Node.find({ _id: { $in: ids } }).select('+xray.manualKey').read('primary').readConcern('majority').lean();
                need(nodes.length === ids.length && nodes.every(node => node.active === true && node.type === 'xray' &&
                    !node.useCustomConfig && !publishedKeyMismatch(node)), unavailable);
                const roles = new Map(nodes.map(node => [String(node._id), node.role ?? node.cascadeRole]));
                need(ids.every(node => roles.has(node)), unavailable);
                const states = await readStates(ids);
                need([...states.values()].every(row => row.routingMode === 'follow-relay' && row.routingVersion === 1), unavailable);
                const root = env.ENCRYPTION_KEY;
                const prepared = await prepareLinks(Link, links, { env, privateInventory: true });
                need(prepared.every((link, i) => !Object.hasOwn(link, '_rebuildVless') || Object.hasOwn(links[i], keyEnvelopeField)), unavailable);
                const nodeFences = ids.map(nodeLockVerifier);
                const locked = async () => {
                    await verify();
                    need(nodeFences.every(owns => owns()) && env.ENCRYPTION_KEY === root);
                };
                await locked();
                const copy = row => unpack(BSON.serialize(row));
                // These are private, read-only composition inputs. No host
                // writer may be opened by admit(); that belongs to the adapter.
                const authority = await admit({ ids: Object.freeze([...ids]), nodes: nodes.map(copy),
                    links: links.map(copy), states: new Map([...states].map(([n, row]) => [n, copy(row)])), verify: locked });
                const { before, profiles, peers, journal, artifacts, verifyFence, openWindow, verifySnapshot,
                    verifyAgentEndpoint, readAgentManagedFlows, prove, verifyTerminal, observe } = authority ?? {};
                need(journal && artifacts && peers instanceof Map && peers.size === ids.length &&
                    ids.every(n => isSha(peers.get(n)?.authoritySha256) && typeof peers.get(n)?.verify === 'function') &&
                    new Set(ids.map(n => peers.get(n).authoritySha256)).size === ids.length &&
                    [verifyFence, openWindow, verifySnapshot, verifyAgentEndpoint, readAgentManagedFlows, syncNodeUsers,
                        prove, verifyTerminal, observe].every(fn => typeof fn === 'function'));
                const pinned = new Map(ids.map(n => {
                    const peer = peers.get(n);
                    return [n, { digest: peer.authoritySha256, verify: peer.verify.bind(peer),
                        managed: Array.isArray(peer.managed) ? [...peer.managed] : undefined }];
                }));
                const composition = { ...profiles, nodes, links: prepared, affectedNodeIds: ids, followRelayStates: [...states.values()] };
                const after = compose(composition);
                const steps = planSerialScopedTransition({ before, after, composition, allowMainRestart: true });
                need(steps.length > 0 && steps.length <= MAX && !after.some(row => profilePreview(
                    before.find(p => p.nodeId === row.nodeId && p.profile === row.profile)?.config, row.config, row.profile, true).protectedChanged), unavailable);
                const transitions = steps.map(step => ({ ...step, authoritySha256: pinned.get(step.nodeId).digest,
                    managed: pinned.get(step.nodeId).managed }));
                const touched = new Set(steps.map(step => step.nodeId));
                const untouched = ids.filter(node => !touched.has(node));
                const fenced = async plan => {
                    await locked();
                    need(await verifyFence(plan) === true);
                    for (const [node, peer] of pinned) need(await peer.verify(node, peer.digest, plan) === true);
                    await locked();
                    return true;
                };
                const checkScope = async (expected, session) => {
                    const fresh = await scope(session);
                    need(equal(fresh.ids, ids) && fresh.rows.length === original.rows.length &&
                        fresh.rows.every(({ bytes, row }) => {
                            const pin = expected.get(String(row._id));
                            return pin && image(unpack(bytes, typed), pin.written).equals(pin.bytes);
                        }), changed);
                    return fresh.rows;
                };
                const preimages = new Map(original.rows.map(({ bytes, row }) => {
                    const exact = unpack(bytes, typed);
                    need(BSON.serialize(exact).equals(bytes), changed);
                    return [String(row._id), { bytes: image(exact) }];
                }));
                const checkStates = async session => need(equal(await readStates(ids, session), states), 'REBUILD_L2TP_STATE_TRANSITION');
                // Also recheck admission's DB scope before the adapter can
                // dispatch, but don't touch any business records here.
                await checkScope(preimages);
                await checkStates();
                await locked();
                let terminal, consumed = false, published = false;
                const result = await runJournaledMainApply({ journal, artifacts, transitions, retain, verifyFence: fenced,
                    openWindow, verifySnapshot, verifyAgentEndpoint, readAgentManagedFlows, syncNodeUsers, prove, observe,
                    async verifyTerminal(ctx, latest) {
                        terminal = undefined;
                        // A verifier gets a copy, not the snapshots the adapter
                        // will hash. Missing unchanged-host evidence is unknown,
                        // not affirmative mismatch or permission to invert.
                        const proof = await verifyTerminal(ctx, structuredClone(latest));
                        if (proof === false) return false;
                        need(Buffer.isBuffer(proof?.evidence) && proof.evidence.length > 0);
                        const unchanged = proof.unchangedMainPins;
                        let confirmed;
                        if (ctx.direction === 'forward') {
                            need(unchanged instanceof Map && unchanged.size === untouched.length && untouched.every(n => isSha(unchanged.get(n))) &&
                                latest.size === touched.size && [...touched].every(n => latest.has(n)));
                            confirmed = new Map([...latest].map(([n, snap]) => [n, digest(Buffer.from(snap.data, 'base64'))]));
                        }
                        const pins = confirmed && new Map([...confirmed, ...unchanged]);
                        // Bind the panel's exact publication pins (including
                        // untouched MAINs) into the journaled terminal artifact.
                        const manifest = ids.map(n => [n, pinned.get(n).digest, pins?.get(n) ?? null]);
                        const bytes = Buffer.concat([Buffer.from(JSON.stringify(['rebuild-panel-main-v1', ctx.direction, manifest]) + '\n'), proof.evidence]);
                        terminal = { ctx, confirmed, pins, digest: digest(bytes) };
                        return bytes;
                    },
                    // The only caller is this invocation's real journaled
                    // adapter, after a durable terminal record and drained writer.
                    async settle(status, changedPins, plan) {
                        need(!consumed && terminal && equal(terminal.ctx.plan, plan));
                        consumed = true; // before any await; no settlement replay
                        const final = journal.read(plan.scope);
                        const terminalFence = async (all = true) => {
                            if (all) await fenced(plan);
                            else await locked();
                            const live = journal.read(plan.scope);
                            need(live && equal(live.plan, plan) && live.status === status && live.head === final?.head &&
                                !live.pending && live.terminalProof);
                            if (all) need(digest(artifacts.read(terminal.ctx, 'confirmed', live.terminalProof)) === terminal.digest);
                        };
                        await terminalFence();
                        if (status === 'rolled-back' && terminal.ctx.direction === 'rollback') return true;
                        need(status === 'applied' && terminal.ctx.direction === 'forward' && equal(changedPins, terminal.confirmed));
                        const updates = new Map(links.map(link => [String(link._id), publication(link, roles, terminal.pins)]));
                        const postimages = new Map();
                        await transactOnce(Link, State, async session => {
                            await terminalFence();
                            const fresh = await checkScope(preimages, session);
                            await checkStates(session);
                            for (const { bytes, row } of fresh) {
                                const expected = unpack(bytes, typed);
                                // Reject lossy BSON before using it as a CAS operand.
                                need(BSON.serialize(expected).equals(bytes), changed);
                                const update = updates.get(String(row._id));
                                await terminalFence(false);
                                const ack = await Link.collection.updateMany({ _id: row._id,
                                    $expr: { $eq: ['$$ROOT', { $literal: expected }] } }, update,
                                { session, collation: { locale: 'simple' } });
                                need(ack?.acknowledged === true && ack.matchedCount === 1 && ack.modifiedCount === 1, changed);
                                Object.assign(expected, unpack(BSON.serialize(update.$set), typed));
                                for (const key of Object.keys(update.$unset)) delete expected[key];
                                const written = [...Object.keys(update.$set), ...Object.keys(update.$unset)];
                                postimages.set(String(row._id), { bytes: image(expected, written), written });
                            }
                            await checkScope(postimages, session);
                            await terminalFence(); // last await inside the one-shot transaction
                        });
                        await checkScope(postimages); // independent majority readback; never retry COMMIT
                        await checkStates();
                        await terminalFence();
                        await invalidate();
                        await terminalFence();
                        published = true;
                        return true;
                    },
                });
                need(result.status !== 'applied' || published, 'REBUILD_MAIN_CUTOVER_UNRESOLVED');
                return result;
            });
        });
    };
}

module.exports = { createSerialApply };
