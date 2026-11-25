'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const MAX_STEPS = 128;
const MAX_BYTES = 512 * 1024;
const PHASES = ['prepare', 'selector', 'portal'];
const ZERO = '0'.repeat(64);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const LABEL = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}$/;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const matches = (regex, value) => typeof value === 'string' && regex.test(value);
const outcome = status => ({ status, retryAllowed: false });
const fail = code => Object.assign(new Error(code), { code });
const invalid = () => fail('REBUILD_CUTOVER_INVALID');
const uncertain = () => fail('REBUILD_CUTOVER_JOURNAL_UNCERTAIN');
const need = value => { if (!value) throw uncertain(); };
const exact = (record, keys) => record && Object.getPrototypeOf(record) === Object.prototype
    && Reflect.ownKeys(record).length === keys.length
    && keys.every(key => Object.hasOwn(Object.getOwnPropertyDescriptor(record, key) ?? {}, 'value'));

// All labels and pins are non-secret. A plan digest identifies a separately
// approved immutable manifest; neither the manifest nor its raw config is logged.
function checkedPlan(value) {
    need(exact(value, ['scope', 'operationId', 'fenceId', 'planDigest', 'steps']));
    const { scope, operationId, fenceId, planDigest, steps } = value;
    need(matches(LABEL, scope) && matches(UUID, operationId) && matches(UUID, fenceId) && matches(SHA256, planDigest));
    need(Array.isArray(steps) && steps.length > 0 && steps.length <= MAX_STEPS);
    let phase = 0;
    const ids = new Set();
    const checked = [];
    for (let index = 0; index < steps.length; index++) {
        const step = Object.getOwnPropertyDescriptor(steps, index)?.value;
        need(exact(step, ['id', 'phase']) && matches(LABEL, step.id) && !ids.has(step.id));
        const next = PHASES.indexOf(step.phase);
        need(next >= phase);
        phase = next;
        ids.add(step.id);
        checked.push({ id: step.id, phase: step.phase });
    }
    return { scope, operationId, fenceId, planDigest, steps: checked };
}

function pin(value) {
    need(exact(value, ['id', 'sha256']) && matches(UUID, value.id) && matches(SHA256, value.sha256));
    return { id: value.id, sha256: value.sha256 };
}
function captured(value) {
    need(exact(value, ['before', 'desired']));
    return { before: pin(value.before), desired: pin(value.desired) };
}
const nextForward = state => state.plan.steps[state.confirmed.length];
const nextInverse = state => state.confirmed[state.confirmed.length - state.restored.length - 1];

// One state machine is used for both the writer and fresh readers. A pending
// intent, even with a current before-image, can never be turned into an ACK by it.
function advance(state, event, scope) {
    if (!state) {
        need(exact(event, ['type', 'version', 'plan']) && event.type === 'start' && event.version === 1);
        const plan = checkedPlan(event.plan);
        need(plan.scope === scope);
        return { plan, status: 'interrupted', proved: false, pending: null,
            confirmed: [], restored: [], refusal: null, rollbackRefusal: null };
    }
    need(['interrupted', 'unknown'].includes(state.status) && !state.rollbackRefusal);
    switch (event.type) {
    case 'proved':
        need(exact(event, ['type']) && !state.pending && !state.refusal && !state.proved && nextForward(state)?.phase !== 'prepare');
        state.proved = true;
        break;
    case 'stop':
        need(exact(event, ['type', 'reason']) && !state.pending && !state.refusal);
        need(['capture', 'fence', 'proof'].includes(event.reason));
        state.refusal = { step: nextForward(state) ?? null, reason: event.reason };
        if (event.reason === 'fence' && state.confirmed.length) state.status = 'blocked';
        break;
    case 'intent': {
        need(!state.pending);
        if (event.direction === 'forward') {
            need(exact(event, ['type', 'direction', 'stepId', 'artifacts']) && !state.refusal);
            const step = nextForward(state);
            need(step?.id === event.stepId && (step.phase === 'prepare' || state.proved));
            state.pending = { direction: 'forward', step, artifacts: captured(event.artifacts) };
        } else {
            need(exact(event, ['type', 'direction', 'stepId']) && event.direction === 'rollback');
            need(state.refusal && state.refusal.reason !== 'fence');
            const original = nextInverse(state);
            need(original?.step.id === event.stepId);
            state.pending = { direction: 'rollback', step: original.step, artifacts: original.artifacts };
        }
        state.status = 'unknown';
        break;
    }
    case 'ack': {
        need(exact(event, ['type', 'confirmed']) && state.pending);
        const { direction, step, artifacts } = state.pending;
        const confirmed = pin(event.confirmed);
        if (direction === 'forward') state.confirmed.push({ step, artifacts: { ...artifacts, confirmed } });
        else state.restored.push({ step, confirmed });
        state.pending = null;
        state.status = 'interrupted';
        break;
    }
    case 'not-dispatched': {
        need(exact(event, ['type', 'reason']) && state.pending && ['fence', 'handoff'].includes(event.reason));
        const refusal = { step: state.pending.step, reason: event.reason };
        if (state.pending.direction === 'forward') state.refusal = refusal;
        else state.rollbackRefusal = refusal;
        state.status = state.rollbackRefusal || (event.reason === 'fence' && state.confirmed.length) ? 'blocked' : 'interrupted';
        state.pending = null;
        break;
    }
    case 'finish':
        need(exact(event, ['type', 'status']) && !state.pending);
        if (event.status === 'applied') need(!state.refusal && state.proved && !nextForward(state));
        else if (event.status === 'rolled-back') need(state.refusal && state.confirmed.length && !nextInverse(state));
        else need(event.status === 'not-dispatched' && state.refusal && !state.confirmed.length);
        state.status = event.status;
        break;
    default: throw uncertain();
    }
    return state;
}

function encode(prev, event) {
    const body = JSON.stringify({ prev, event });
    const head = sha256(body);
    return { head, bytes: Buffer.from(JSON.stringify({ prev, event, sha256: head }) + '\n') };
}
function decode(scope, bytes) {
    const text = bytes.toString('utf8');
    need(text.endsWith('\n') && Buffer.from(text).equals(bytes));
    let head = ZERO, state = null;
    const lines = text.slice(0, -1).split('\n');
    need(lines.length <= 4 * MAX_STEPS + 4);
    for (const line of lines) {
        const { event } = JSON.parse(line);
        const record = encode(head, event);
        need(record.bytes.toString('utf8') === line + '\n');
        state = advance(state, event, scope);
        head = record.head;
    }
    return { ...state, head };
}

const { O_RDONLY, O_WRONLY, O_CREAT, O_EXCL, O_APPEND, O_NOFOLLOW, O_DIRECTORY, O_NONBLOCK } = fs.constants;
const statOpts = { bigint: true };
const sameFile = (a, b) => a.dev === b.dev && a.ino === b.ino;
const privateRegular = st => st.isFile() && st.uid === BigInt(process.geteuid()) && st.nlink === 1n
    && (st.mode & 0o7777n) === 0o600n && st.size <= BigInt(MAX_BYTES);
const stores = new WeakMap();

/**
 * Use a stable, pre-provisioned, durably linked 0700 directory on a local POSIX
 * filesystem with working exclusive create, append and fsync semantics. Never
 * delete, move or truncate a scope's file for retry. Share the directory and the
 * stable conflict-scope key across contenders (not one directory/key per attempt).
 * All path ancestors and same-UID writers must be trusted. This file does not
 * replace the adapter's independently enforced effect fence or sibling guards.
 */
function createFileCutoverJournal({ directory } = {}) {
    if (typeof directory !== 'string' || !path.isAbsolute(directory) || path.resolve(directory) !== directory) throw invalid();
    let identity;
    function verifyDir(dir) {
        const st = fs.fstatSync(dir, statOpts);
        need(st.isDirectory() && st.uid === BigInt(process.geteuid()) && (st.mode & 0o7777n) === 0o700n);
        need(sameFile(st, fs.lstatSync(directory, statOpts)) && (!identity || sameFile(st, identity)));
        identity ??= st;
    }
    function openDir() {
        const dir = fs.openSync(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        try { verifyDir(dir); return dir; } catch (err) { fs.closeSync(dir); throw err; }
    }
    function inspect(dir, file, writer) {
        verifyDir(dir);
        let fd;
        try { fd = fs.openSync(file, O_RDONLY | O_NOFOLLOW | O_NONBLOCK); }
        catch (err) {
            if (err.code !== 'ENOENT' || writer !== undefined) throw err;
            verifyDir(dir);
            return null;
        }
        try {
            const before = fs.fstatSync(fd, statOpts);
            need(privateRegular(before) && (writer === undefined || sameFile(before, fs.fstatSync(writer, statOpts))));
            const bytes = Buffer.alloc(Number(before.size));
            for (let offset = 0; offset < bytes.length;) {
                const got = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
                need(got > 0);
                offset += got;
            }
            const after = fs.fstatSync(fd, statOpts), named = fs.lstatSync(file, statOpts);
            need(privateRegular(named) && sameFile(named, before) && after.size === before.size
                && after.mtimeNs === before.mtimeNs && after.ctimeNs === before.ctimeNs);
            verifyDir(dir);
            return bytes;
        } finally { fs.closeSync(fd); }
    }
    const filename = scope => path.join(directory, `cutover-${sha256(scope)}.jsonl`);
    function read(scope) {
        if (!matches(LABEL, scope)) throw invalid();
        try {
            const dir = openDir();
            try {
                const bytes = inspect(dir, filename(scope));
                return bytes === null ? null : decode(scope, bytes);
            } finally { fs.closeSync(dir); }
        } catch { throw uncertain(); }
    }
    async function reserve(plan, run) {
        const file = filename(plan.scope), dir = openDir();
        try {
            let fd;
            try { fd = fs.openSync(file, O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW, 0o600); }
            catch (err) { if (err.code === 'EEXIST') return outcome('already-recorded'); throw err; }
            try {
                let expected = Buffer.alloc(0), state = null;
                const assertCurrent = () => need(inspect(dir, file, fd).equals(expected));
                function record(event) {
                    assertCurrent();
                    const candidate = advance(structuredClone(state), event, plan.scope);
                    const { head, bytes } = encode(state?.head ?? ZERO, event);
                    need(expected.length + bytes.length <= MAX_BYTES);
                    // Never repair partial writes. A torn tail is a fence, not
                    // permission to use a previous valid prefix or dispatch again.
                    need(fs.writeSync(fd, bytes) === bytes.length);
                    fs.fsyncSync(fd);
                    fs.fsyncSync(dir);
                    expected = Buffer.concat([expected, bytes]);
                    assertCurrent();
                    state = { ...candidate, head };
                    return structuredClone(state);
                }
                record({ type: 'start', version: 1, plan });
                return await run({ record, assertCurrent, state: () => structuredClone(state) });
            } finally { fs.closeSync(fd); }
        } finally { fs.closeSync(dir); }
    }
    // Pin the provisioned directory now, rather than first trusting a path after
    // awaiting the adapter. No directory or journal file is silently created here.
    try { fs.closeSync(openDir()); } catch { throw uncertain(); }
    const journal = Object.freeze({ read });
    stores.set(journal, reserve);
    return journal;
}

function frozen(value) {
    if (value && typeof value === 'object') {
        for (const member of Object.values(value)) frozen(member);
        Object.freeze(value);
    }
    return value;
}

/**
 * Trusted adapter contract (methods may be async; use bounded native operations):
 * - verifyFence({plan, ...}): true only for the exact live scope, manifest,
 *   both version/identity pins and original exclusion fence. The caller must hold
 *   that authority across execution and not release it on an unresolved outcome.
 * - capture({plan, step, direction}): {before, desired}. Both are authenticated,
 *   durable encrypted artifacts, reopened and pinned by {id: UUID, sha256: hex}
 *   (hash of ciphertext). Preserve exact bytes/metadata and runtime preimage;
 *   do not mutate targets. Artifacts are bound to this operation, scope and step.
 * - dispatch(ctx, submit): transport setup may happen outside submit, but *every*
 *   possible target mutation must be inside the one submit(() => nativeHandoff())
 *   invocation. Return that exact awaited opaque receipt after required cleanup.
 *   At handoff enforce native CAS, identities, scope, pins and deadlines; rollback
 *   uses the original before pin and requires the ACKed generation (confirmed).
 * - verify(ctx, nativeReply): independently authenticate the settled effect and
 *   exact readback (not just the reply); return a durable encrypted artifact pin
 *   including the observed generations, or refuse. No target mutations here.
 * - prove({plan, confirmed}): true only after the read-only preparation proof
 *   (including old and new path checks). Called once before selectors or portals.
 * - observe(journalState): read-only 'before' | 'after' | 'mixed' | 'unavailable'.
 *   These report observations, never absence of an old in-flight writer.
 *
 * Inverse steps are allowed only during the original invocation, under the same
 * fence, on a known stop and in reverse ACK order. Returning from execute or
 * restarting the controller never grants retry, resume, or handback authority.
 */
function createScopedCutoverExecutor({ journal, adapter } = {}) {
    const reserve = stores.get(journal);
    if (!reserve || !['verifyFence', 'capture', 'dispatch', 'verify', 'prove', 'observe']
        .every(method => typeof adapter?.[method] === 'function')) throw invalid();
    async function checkFence(ctx) {
        try { return await adapter.verifyFence(ctx) === true; } catch { return false; }
    }

    async function perform(tx, plan, direction, step, artifacts) {
        const record = direction === 'forward'
            ? { type: 'intent', direction, stepId: step.id, artifacts }
            : { type: 'intent', direction, stepId: step.id };
        const ctx = frozen({ plan, ...tx.record(record).pending });
        let open = true, called = false, checkingHandoff = false, entered = false, duplicate = false;
        let fenceLost = false, journalLost = false, receipt, nativeReply, returned;
        function submit(effect) {
            const attempt = (async () => {
                if (!open) throw invalid();
                if (called || typeof effect !== 'function') { duplicate = true; throw invalid(); }
                called = true;
                checkingHandoff = true;
                const held = await checkFence(ctx);
                checkingHandoff = false;
                if (!held) { fenceLost = true; throw invalid(); }
                if (!open) throw invalid();
                try { tx.assertCurrent(); } catch { journalLost = true; throw uncertain(); }
                entered = true; // latch before a single potentially effectful handoff
                nativeReply = await effect();
                receipt = Object.freeze({});
                return receipt;
            })();
            // A detached submit cannot authorize an ACK or emit an unhandled rejection.
            attempt.catch(() => {});
            return attempt;
        }
        if (await checkFence(ctx)) {
            try { returned = await adapter.dispatch(ctx, submit); }
            catch { /* Never trust a thrown or returned no-send claim after handoff. */ }
            finally { open = false; }
        } else { open = false; fenceLost = true; }
        if (journalLost) return 'unknown';
        if (!entered) {
            // An adapter that detached a still-running authority check has not
            // joined it. Revocation proves zero handoff, not continuous fencing.
            const reason = fenceLost || checkingHandoff ? 'fence' : 'handoff';
            tx.record({ type: 'not-dispatched', reason });
            return reason;
        }
        if (duplicate || !receipt || returned !== receipt || !await checkFence(ctx)) return 'unknown';
        let confirmed;
        try { confirmed = pin(await adapter.verify(ctx, nativeReply)); } catch { return 'unknown'; }
        if (!await checkFence(ctx)) return 'unknown';
        tx.record({ type: 'ack', confirmed });
        return 'ack';
    }

    async function run(tx, plan) {
        const stop = reason => tx.record({ type: 'stop', reason });
        const finish = status => { tx.record({ type: 'finish', status }); return outcome(status); };
        for (;;) {
            const state = tx.state(), step = nextForward(state);
            const ctx = frozen({ plan, step: step ?? null, direction: 'forward' });
            if (!await checkFence(ctx)) { stop('fence'); break; }
            if (!state.proved && step?.phase !== 'prepare') {
                let proved = false;
                try { proved = await adapter.prove(frozen({ plan, confirmed: state.confirmed })) === true; } catch { /* refused */ }
                if (!await checkFence(ctx)) { stop('fence'); break; }
                if (!proved) { stop('proof'); break; }
                tx.record({ type: 'proved' });
            }
            if (!step) return finish('applied');
            let artifacts;
            try { artifacts = captured(await adapter.capture(ctx)); } catch { stop('capture'); break; }
            if (!await checkFence(ctx)) { stop('fence'); break; }
            const result = await perform(tx, plan, 'forward', step, artifacts);
            if (result === 'unknown') return outcome('unknown');
            if (result !== 'ack') break;
        }

        let state = tx.state();
        if (!state.confirmed.length) return finish('not-dispatched');
        if (state.refusal.reason === 'fence') return outcome('blocked');
        for (let original; (original = nextInverse(state)); state = tx.state()) {
            const result = await perform(tx, plan, 'rollback', original.step);
            if (result !== 'ack') return outcome(result === 'unknown' ? 'unknown' : 'blocked');
        }
        return finish('rolled-back');
    }

    return Object.freeze({
        async execute(input) {
            let plan;
            try { plan = frozen(checkedPlan(input)); } catch { throw invalid(); }
            try { return await reserve(plan, tx => run(tx, plan)); }
            catch { return outcome('unknown'); }
        },
        async reconcile(scope) {
            const state = journal.read(scope);
            if (!state) return { journal: null, observation: null, retryAllowed: false };
            const ctx = frozen({ plan: state.plan, ...state.pending });
            let observation = 'unavailable';
            if (await checkFence(ctx)) {
                try {
                    const observed = await adapter.observe(frozen(state));
                    if (['before', 'after', 'mixed'].includes(observed) && await checkFence(ctx)) observation = observed;
                } catch { /* unavailable */ }
            }
            need(journal.read(scope)?.head === state.head);
            return { journal: state, observation, retryAllowed: false };
        }
    });
}

module.exports = { createFileCutoverJournal, createScopedCutoverExecutor };
