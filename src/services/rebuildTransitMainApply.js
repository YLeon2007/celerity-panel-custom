'use strict';
const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: equal, TextDecoder } = require('node:util');
const { createScopedCutoverExecutor } = require('./rebuildTransitCutoverJournal');
const { cutoverOwner, nodeLockVerifier } = require('./rebuildLocks');

const MAX = 8 * 1024 * 1024;
const MAX_FRAME = 8 * Math.ceil(MAX / 3) + 1024;
const SHA = /^[a-f0-9]{64}(?![\s\S])/;
const phases = ['prepare', 'selector', 'portal'];
const bytes = value => Buffer.from(JSON.stringify(value));
const sha = value => createHash('sha256').update(value).digest('hex');
const own = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype &&
    Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const match = (re, value) => typeof value === 'string' && re.test(value);
const error = code => Object.assign(new Error(code), { code });
const need = (okay, code = 'REBUILD_MAIN_PROOF_UNCONFIRMED') => { if (!okay) throw error(code); };
const unresolved = failure => Object.assign(error('REBUILD_MAIN_CUTOVER_UNRESOLVED'), { failure: failure ?? null, retryAllowed: false });
const drift = 'REBUILD_MAIN_CAS_UNPROVED';
const directReceiptReasons = [
    'REBUILD_DIRECT_RECEIPT_UNPROVED', 'REBUILD_DIRECT_RECEIPT_LAYOUT_UNSUPPORTED',
    'REBUILD_DIRECT_RECEIPT_REQUIRES_NETWORK', 'REBUILD_DIRECT_RECEIPT_MAIN_DRIFT',
    'REBUILD_DIRECT_RECEIPT_WRITER_EXCLUSION_UNPROVED', 'REBUILD_DIRECT_RECEIPT_FINAL_UNPROVED',
    'REBUILD_DIRECT_RECEIPT_WRITE_UNCONFIRMED',
];
const json = data => JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data));
function raw(data) {
    need(typeof data === 'string' && 0 < data.length && data.length <= 4 * Math.ceil(MAX / 3));
    const decoded = Buffer.from(data, 'base64');
    need(decoded.length <= MAX && decoded.toString('base64') === data);
    return decoded;
}
function image(value, withRuntime) {
    need(own(value, ['data', 'metadata', 'generation', ...(withRuntime ? ['xray'] : [])]));
    const { data, metadata, generation, xray } = value;
    raw(data);
    need(Array.isArray(metadata) && metadata.length === 3 && metadata.every(n => Number.isSafeInteger(n) && n >= 0));
    need(Array.isArray(generation) && generation.length === 3 && generation.every(n => match(/^(0|[1-9][0-9]{0,24})(?![\s\S])/, n)));
    if (withRuntime) need(Array.isArray(xray) && xray.length === 2 && Number.isSafeInteger(xray[0]) && xray[0] > 0 &&
        match(/^[a-f0-9]{32}(?![\s\S])/, xray[1]) && !/^0+$/.test(xray[1]));
    return Object.freeze({ data, metadata: Object.freeze([...metadata]), generation: Object.freeze([...generation]),
        ...(withRuntime ? { xray: Object.freeze([...xray]) } : {}) });
}
function separated(data, managed) {
    const topology = json(data), byTag = new Map();
    need(Array.isArray(topology?.inbounds));
    for (const row of topology.inbounds) {
        if (!managed.includes(row?.tag)) continue;
        need(!byTag.has(row.tag) && Array.isArray(row.settings?.clients), drift);
        byTag.set(row.tag, row.settings.clients);
        delete row.settings.clients;
    }
    need(byTag.size === managed.length, drift);
    return { topology, clients: managed.map(tag => byTag.get(tag)) };
}
function sameTopology(a, b, managed) {
    return equal(separated(a, managed).topology, separated(b, managed).topology);
}

// cc-agent's persister renders the pinned per-inbound Flow, not User.Flow
// from the panel request. Compare every managed array to the exact submitted
// roster before relying on stock /sync's zero-delta ACK.
function stockSyncIsNoop(data, managed, flows, users) {
    if (!(flows instanceof Map) || flows.size !== managed.length) return false;
    const expect = new Map();
    const ids = new Set();
    for (const user of users) {
        if (!own(user, ['id', 'email', 'flow']) || typeof user.email !== 'string' || user.email.length === 0 ||
            typeof user.id !== 'string' || user.id.length === 0 || typeof user.flow !== 'string' ||
            expect.has(user.email) || ids.has(user.id)) return false;
        expect.set(user.email, user.id);
        ids.add(user.id);
    }
    return separated(data, managed).clients.every((rows, i) => {
        const flow = flows.get(managed[i]);
        if (typeof flow !== 'string' || rows.length !== expect.size) return false;
        const seen = new Set();
        for (const row of rows) {
            if (!row || typeof row.email !== 'string' || typeof row.id !== 'string' || !expect.has(row.email) ||
                expect.get(row.email) !== row.id || seen.has(row.email) ||
                (Object.hasOwn(row, 'flow') ? row.flow : '') !== flow) return false;
            seen.add(row.email);
        }
        return true;
    });
}
const alwaysUnknown = new Set([
    'REBUILD_AGENT_STOP_UNCONFIRMED', 'REBUILD_AGENT_EXCLUSION_UNPROVED', 'REBUILD_AGENT_START_UNCONFIRMED',
    'REBUILD_AGENT_RECONCILE_UNPROVED', 'REBUILD_MAIN_PUBLICATION_UNCONFIRMED', 'REBUILD_MAIN_RESTART_UNCONFIRMED',
    'REBUILD_MAIN_RUNTIME_UNPROVED', 'REBUILD_MAIN_LOCK_UNPROVED', 'REBUILD_MAIN_AUTHORITY_UNPROVED',
    'REBUILD_MAIN_WIRE_SETTLEMENT', 'REBUILD_CUTOVER_ARTIFACT_UNPROVED',
    'REBUILD_NODE_USER_SYNC_UNCONFIRMED', 'REBUILD_NODE_USER_SYNC_PREPARE_FAILED', 'REBUILD_NODE_USER_SYNC_FENCE_UNPROVED', drift,
    'REBUILD_NODE_USER_SYNC_PAYLOAD_UNPROVED',
    ...directReceiptReasons,
]);
async function request(channel, action, fields) {
    const response = await channel.request({ action, ...fields });
    if (own(response, ['ok', 'reason']) && response.ok === false && alwaysUnknown.has(response.reason)) throw error(response.reason);
    need(own(response, ['ok', 'value']) && response.ok === true);
    return response.value;
}

// Private panel-side composition. All callbacks are trusted, bounded bindings,
// never request arguments. `openWindow` must attach the exact admitted node to
// HostMainWire under one pinned SSH connection and verify before each write.
// `verifySnapshot` independently binds live host/agent identity and profile
// evidence; a wire reply alone cannot ACK. `readAgentManagedFlows` returns
// the independently verified per-tag flow of the exact running agent for this
// snapshot; a config read without process/endpoint proof does not qualify.
// `settle` publishes graph state only
// for an applied terminal proof and must not replay ambiguous commits.
async function runJournaledMainApply({ journal, artifacts, retain, transitions, verifyFence,
    openWindow, verifySnapshot, verifyAgentEndpoint, readAgentManagedFlows, syncNodeUsers, prove, verifyTerminal, settle, observe }) {
    const owner = cutoverOwner(retain);
    need(owner && Array.isArray(transitions) && transitions.length > 0 && transitions.length <= 128 &&
        [verifyFence, openWindow, verifySnapshot, verifyAgentEndpoint, readAgentManagedFlows, syncNodeUsers, prove, verifyTerminal, settle, observe]
            .every(fn => typeof fn === 'function'), 'REBUILD_MAIN_AUTHORITY_UNPROVED');
    const rows = new Map(), nodeFences = new Map(), steps = [];
    let rank = 0;
    for (const { id, nodeId, phase, before, after, managed, authoritySha256 } of transitions) {
        const next = phases.indexOf(phase);
        need(match(/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}(?![\s\S])/, id) && !rows.has(id) && next >= rank &&
            match(/^[a-f0-9]{24}(?![\s\S])/, nodeId) && match(SHA, authoritySha256) &&
            Array.isArray(managed) && managed.length > 0 && managed.length <= 64 && new Set(managed).size === managed.length &&
            managed.every(tag => match(/^[A-Za-z0-9_.:-]{1,128}(?![\s\S])/, tag)));
        rank = next;
        const row = { id, nodeId, phase, before: bytes(before), after: bytes(after), managed: [...managed].sort(), authoritySha256 };
        need([row.before, row.after].every(data => data.length > 0 && data.length <= MAX));
        need(!sameTopology(row.before, row.after, row.managed));
        rows.set(id, row);
        nodeFences.set(nodeId, nodeLockVerifier(nodeId));
        steps.push(Object.freeze({ id, phase, window: 'main-agent' }));
    }
    const operationId = randomUUID(), fenceId = randomUUID();
    const plan = Object.freeze({ scope: operationId, operationId, fenceId, steps: Object.freeze(steps),
        planDigest: sha(bytes([...rows.values()].map(({ id, nodeId, phase, before, after, managed, authoritySha256 }) =>
            [id, nodeId, phase, sha(before), sha(after), managed, authoritySha256]))) });
    const { steps: _, ...identity } = plan;
    const ownsNodes = () => [...nodeFences.values()].every(owns => owns());
    need(ownsNodes() && await verifyFence(plan) === true && ownsNodes(), 'REBUILD_MAIN_AUTHORITY_UNPROVED');
    const reservation = await owner.promote(identity);
    let active, failure, terminal;
    const fact = (state, ctx) => state && equal(state.plan, plan) && equal(ctx.plan, plan);
    function current(ctx) {
        const state = journal.read(plan.scope);
        need(fact(state, ctx), 'REBUILD_MAIN_AUTHORITY_UNPROVED');
        return state;
    }
    const fenced = async ctx => ownsNodes() && await reservation.verify() === true && await verifyFence(ctx.plan) === true && ownsNodes();
    function seal(ctx, side, data) { return artifacts.seal(ctx, side, data); }
    function pub(ctx, side) { return `publication-${ctx.direction}-${side}`; }
    function reopen(ctx, side, pin) { return artifacts.read(ctx, side, pin); }
    function history(ctx, row) {
        const pins = [...ctx.history.confirmed, ...ctx.history.restored];
        const latest = pins.findLast(entry => rows.get(entry.step.id)?.nodeId === row.nodeId);
        if (!latest) return null;
        return readConfirmed(latest);
    }
    function readConfirmed(entry) {
        return image(json(reopen({ plan, step: entry.step }, 'confirmed', entry.confirmed ?? entry.artifacts?.confirmed)), true);
    }
    function discard() {
        const prior = active;
        active = undefined;
        if (prior && !prior.closed) prior.channel.abort();
    }
    async function open(ctx) {
        const row = rows.get(ctx.step.id);
        need(!active && row);
        const local = { row, ctx, frameCtx: ctx, closed: false };
        const verifyBeforeFrame = async () => {
            if (active !== local || local.closed) return false;
            const frameCtx = local.frameCtx;
            const state = current(frameCtx);
            const pending = state.pending;
            // Read before the forward step intent (or in its inverse intent)
            // has no host effects. Every other frame requires a durable phase.
            if (local.action !== 'read' && (pending?.step.id !== ctx.step.id || pending.direction !== ctx.direction ||
                pending.checkpoint !== local.checkpoint)) return false;
            return await fenced(frameCtx) && active === local && !local.closed && local.frameCtx === frameCtx &&
                current(frameCtx).head === state.head;
        };
        const channel = await openWindow(row.nodeId, { verifyBeforeFrame, maxFrameBytes: MAX_FRAME, plan, step: ctx.step, direction: ctx.direction });
        active = Object.assign(local, { channel });
        const baseline = image(await send(ctx, undefined, 'read'), true);
        const latest = history(ctx, row);
        if (latest) need(equal(baseline.xray, latest.xray) && equal(baseline.metadata, latest.metadata), drift);
        const expected = ctx.direction === 'rollback' ? raw(latest?.data) : row.before;
        need(sameTopology(raw(baseline.data), expected, row.managed), drift);
        need(await verifySnapshot(row.nodeId, 'before', baseline, ctx) === true);
        active.baseline = baseline;
        return baseline;
    }
    async function send(ctx, checkpoint, action, fields) {
        need(active && active.ctx.step.id === ctx.step.id && active.ctx.direction === ctx.direction);
        Object.assign(active, { frameCtx: ctx, checkpoint, action });
        return request(active.channel, action, fields);
    }
    function remember(ctx, err) {
        if (failure) return;
        let phase = null;
        try { phase = current(ctx).pending?.checkpoint ?? null; } catch { /* Journal authority lost. */ }
        failure = Object.freeze({ phase, reason: alwaysUnknown.has(err?.code) ? err.code : 'REBUILD_MAIN_PROOF_UNCONFIRMED' });
    }
    let verified;
    const executor = createScopedCutoverExecutor({ journal, adapter: {
        verifyFence: fenced,
        async capture(ctx) {
            try {
                const baseline = await open(ctx);
                return { before: seal(ctx, 'before', bytes(baseline)), desired: seal(ctx, 'desired', active.row.after) };
            } catch (err) { try { remember(ctx, err); } finally { discard(); } throw err; }
        },
        async captureMainPublication(ctx) {
            const back = ctx.direction === 'rollback';
            const original = back ? ctx.history.confirmed.find(entry => entry.step.id === ctx.step.id) : null;
            const target = back
                ? raw(json(reopen(ctx, 'publication-forward-before', original.publication.before)).data)
                : reopen(ctx, 'desired', ctx.artifacts.desired);
            if (!back) need(equal(active.baseline, image(json(reopen(ctx, 'before', ctx.artifacts.before)), true)), drift);
            const capture = await send(ctx, 'agent-stop', 'capture', { target: target.toString('base64') });
            need(own(capture, ['before', 'desired']));
            const before = image(capture.before, false), desired = raw(capture.desired), { managed } = active.row;
            need(equal(before.metadata, active.baseline.metadata) && sameTopology(raw(before.data), raw(active.baseline.data), managed) &&
                sameTopology(desired, target, managed) && equal(separated(desired, managed).clients, separated(raw(before.data), managed).clients), drift);
            return { before: seal(ctx, pub(ctx, 'before'), bytes(before)), desired: seal(ctx, pub(ctx, 'desired'), desired) };
        },
        async dispatch(ctx, submit) {
            verified = undefined;
            try {
                if (ctx.direction === 'rollback') await open(ctx);
                return await submit(async checkpoint => {
                    let written, restarted;
                    let prev = await checkpoint('agent-stop', null, async current =>
                        need(await send(current, 'agent-stop', 'stop') === null));
                    prev = await checkpoint('main-publication', prev, async current => {
                        const before = reopen(current, pub(current, 'before'), current.publication.before);
                        const desired = reopen(current, pub(current, 'desired'), current.publication.desired);
                        written = image(await send(current, 'main-publication', 'publish', { beforeSha256: sha(before), desiredSha256: sha(desired) }), false);
                        const old = image(json(before), false);
                        need(raw(written.data).equals(desired) && equal(written.metadata, old.metadata) &&
                            !equal(written.generation.slice(0, 2), old.generation.slice(0, 2)), drift);
                    });
                    prev = await checkpoint('xray-restart', prev, async current => {
                        restarted = image(await send(current, 'xray-restart', 'restart'), true);
                        const { xray, ...main } = restarted;
                        need(equal(main, written) && xray[1] !== active.baseline.xray[1]);
                    });
                    prev = await checkpoint('agent-start', prev, async current =>
                        need(await send(current, 'agent-start', 'start') === null));
                    return checkpoint('agent-reconcile', prev, async current => {
                        const settled = image(await send(current, 'agent-reconcile', 'reconcile'), true);
                        need(equal(settled, restarted), drift);
                        const nodeId = active.row.nodeId;
                        const verifySyncFence = async target => {
                            const state = journal.read(plan.scope);
                            return fact(state, current) && state.pending?.step.id === ctx.step.id &&
                                state.pending.direction === ctx.direction && state.pending.checkpoint === 'agent-reconcile' &&
                                await fenced(current) && await verifyAgentEndpoint(nodeId, target, settled, current) === true &&
                                await fenced(current) && journal.read(plan.scope)?.head === state.head;
                        };
                        let payloadProofs = 0, provedUsers;
                        const ack = await syncNodeUsers(nodeId, { verifyFence: verifySyncFence,
                            async verifyPayload(target, users) {
                                if (!Array.isArray(users) || !Object.isFrozen(users) || !users.every(Object.isFrozen) ||
                                    payloadProofs > 1 || (payloadProofs === 1 && provedUsers !== users) || !await verifySyncFence(target)) return false;
                                const flows = await readAgentManagedFlows(nodeId, target, settled, current);
                                if (!stockSyncIsNoop(raw(settled.data), active.row.managed, flows, users) ||
                                    !await verifySyncFence(target)) return false;
                                provedUsers = users;
                                payloadProofs++;
                                return true;
                            },
                        });
                        need(payloadProofs === 2 && own(ack, ['added', 'removed', 'errors', 'total']) && ack.errors === 0 &&
                            ack.added === 0 && ack.removed === 0 && ack.total === provedUsers.length,
                            'REBUILD_NODE_USER_SYNC_UNCONFIRMED');
                        verified = image(await send(current, 'agent-reconcile', 'verify'), true);
                        need(equal(verified, settled), drift);
                        await active.channel.finish();
                        active.closed = true;
                        return verified;
                    });
                });
            } catch (err) { remember(ctx, err); throw err; }
            finally { discard(); }
        },
        async verify(ctx, reply) {
            need(verified && reply === verified && await verifySnapshot(rows.get(ctx.step.id).nodeId, 'after', verified, ctx) === true);
            return seal(ctx, 'confirmed', bytes(verified));
        },
        async prove(ctx) { return await prove(ctx) === true; },
        async verifyTerminal(ctx) {
            const latest = new Map();
            for (const entry of [...ctx.confirmed, ...ctx.restored]) {
                latest.set(rows.get(entry.step.id).nodeId, readConfirmed(entry));
            }
            const evidence = await verifyTerminal(ctx, latest);
            if (evidence === false) return false;
            need(Buffer.isBuffer(evidence) && evidence.length > 0);
            const pin = seal(ctx, 'confirmed', evidence);
            terminal = { ctx, pin, latest };
            return pin;
        },
        observe,
    } });
    try {
        let result;
        try { result = await executor.execute(plan); } finally { discard(); }
        const final = current({ plan });
        if (result.status === 'applied' || result.status === 'rolled-back') {
            need(terminal && equal(final.terminalProof, terminal.pin) && final.status === result.status && !final.pending);
            need(await fenced({ plan }));
            const pins = new Map([...terminal.latest].map(([node, snapshot]) => [node, sha(raw(snapshot.data))]));
            need(await settle(result.status, pins, plan) === true);
            await reservation.settle(async () => await fenced({ plan }) && current({ plan }).head === final.head);
        } else if (result.status === 'not-dispatched' && final.status === 'not-dispatched' && !final.pending && !final.confirmed.length) {
            await reservation.settle(async () => await fenced({ plan }) && current({ plan }).head === final.head);
        } else throw unresolved(failure);
        return { ...result, failure: failure ?? null };
    } catch (err) {
        remember({ plan }, err);
        throw unresolved(failure);
    }
}

module.exports = { runJournaledMainApply };
