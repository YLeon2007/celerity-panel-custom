'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const MAX_STEPS = 128;
const MAX_BYTES = 512 * 1024;
const PHASES = ['prepare', 'selector', 'portal'];
const MAIN_PHASES = ['agent-stop', 'main-publication', 'xray-restart', 'agent-start', 'agent-reconcile'];
const mainWindow = step => step.window === 'main-agent';
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
function checkedPlan(value, version = 3) {
    need(exact(value, ['scope', 'operationId', 'fenceId', 'planDigest', 'steps']));
    const { scope, operationId, fenceId, planDigest, steps } = value;
    need(matches(LABEL, scope) && matches(UUID, operationId) && matches(UUID, fenceId) && matches(SHA256, planDigest));
    need(Array.isArray(steps) && steps.length > 0 && steps.length <= MAX_STEPS);
    let phase = 0;
    const ids = new Set();
    const checked = [];
    for (let index = 0; index < steps.length; index++) {
        const step = Object.getOwnPropertyDescriptor(steps, index)?.value;
        const window = version === 3 && exact(step, ['id', 'phase', 'window']) && mainWindow(step);
        need((window || exact(step, ['id', 'phase'])) && matches(LABEL, step.id) && !ids.has(step.id));
        const next = PHASES.indexOf(step.phase);
        need(next >= phase);
        phase = next;
        ids.add(step.id);
        checked.push({ id: step.id, phase: step.phase, ...(window && { window: 'main-agent' }) });
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
const forwardComplete = state => !state.refusal && state.proved && !nextForward(state);
const inverseComplete = state => state.refusal && state.confirmed.length && !nextInverse(state);

function mainPublication(state, value) {
    const pins = captured(value);
    const { direction, artifacts } = state.pending;
    const original = direction === 'rollback' ? nextInverse(state).publication : undefined;
    const ids = [...Object.values(artifacts), ...Object.values(original ?? {})].map(artifact => artifact.id);
    need(pins.before.id !== pins.desired.id && !ids.includes(pins.before.id) && !ids.includes(pins.desired.id));
    return pins;
}

// One state machine is used for both the writer and fresh readers. A pending
// intent, even with a current before-image, can never be turned into an ACK by it.
function advance(state, event, scope) {
    if (!state) {
        need(exact(event, ['type', 'version', 'plan']) && event.type === 'start' && [1, 2, 3].includes(event.version));
        const plan = checkedPlan(event.plan, event.version);
        need(plan.scope === scope && (event.version !== 3 || plan.steps.some(mainWindow)));
        return { plan, version: event.version, status: 'interrupted', proved: false, pending: null,
            terminalProof: null, terminalFailure: null,
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
        need(['capture', 'fence', 'proof'].includes(event.reason)
            || (state.version >= 2 && event.reason === 'terminal-proof' && forwardComplete(state)));
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
        if (mainWindow(state.pending.step)) state.pending.checkpoint = null;
        state.status = 'unknown';
        break;
    }
    case 'checkpoint': {
        const pending = state.pending;
        need(state.version === 3 && pending && mainWindow(pending.step));
        const phase = MAIN_PHASES[MAIN_PHASES.indexOf(pending.checkpoint) + 1];
        const publication = phase === 'main-publication';
        need(phase && exact(event, publication ? ['type', 'phase', 'artifacts'] : ['type', 'phase']) && event.phase === phase);
        if (publication) pending.publication = mainPublication(state, event.artifacts);
        pending.checkpoint = phase;
        break;
    }
    case 'ack': {
        need(exact(event, ['type', 'confirmed']) && state.pending);
        const { direction, step, artifacts, checkpoint, publication } = state.pending;
        need(!mainWindow(step) || checkpoint === MAIN_PHASES.at(-1));
        const window = publication ? { publication } : {};
        const confirmed = pin(event.confirmed);
        if (direction === 'forward') state.confirmed.push({ step, artifacts: { ...artifacts, confirmed }, ...window });
        else state.restored.push({ step, confirmed, ...window });
        state.pending = null;
        state.status = 'interrupted';
        break;
    }
    case 'not-dispatched': {
        need(exact(event, ['type', 'reason']) && state.pending && !state.pending.checkpoint
            && ['fence', 'handoff'].includes(event.reason));
        const refusal = { step: state.pending.step, reason: event.reason };
        if (state.pending.direction === 'forward') state.refusal = refusal;
        else state.rollbackRefusal = refusal;
        state.status = state.rollbackRefusal || (event.reason === 'fence' && state.confirmed.length) ? 'blocked' : 'interrupted';
        state.pending = null;
        break;
    }
    case 'terminal-blocked':
        need(state.version >= 2 && !state.pending && exact(event, ['type', 'direction', 'reason'])
            && ['fence', 'proof'].includes(event.reason)
            && (event.direction === 'forward' ? forwardComplete(state) : event.direction === 'rollback' && inverseComplete(state)));
        state.terminalFailure = { direction: event.direction, reason: event.reason };
        state.status = 'blocked';
        break;
    case 'finish': {
        const requiresProof = state.version >= 2 && event.status !== 'not-dispatched';
        need(!state.pending && exact(event, requiresProof ? ['type', 'status', 'proof'] : ['type', 'status']));
        if (event.status === 'applied') need(forwardComplete(state));
        else if (event.status === 'rolled-back') need(inverseComplete(state));
        else need(event.status === 'not-dispatched' && state.refusal && !state.confirmed.length);
        if (requiresProof) state.terminalProof = pin(event.proof);
        state.status = event.status;
        break;
    }
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
    const legacyLimit = 4 * MAX_STEPS + 4;
    need(lines.length <= legacyLimit + 2 * MAIN_PHASES.length * MAX_STEPS);
    for (const line of lines) {
        const { event } = JSON.parse(line);
        const record = encode(head, event);
        need(record.bytes.toString('utf8') === line + '\n');
        state = advance(state, event, scope);
        need(state.version === 3 || lines.length <= legacyLimit);
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
                record({ type: 'start', version: plan.steps.some(mainWindow) ? 3 : 2, plan });
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
 *   At handoff enforce native CAS, identities, scope, pins and deadlines. An
 *   inverse uses the original before pin, but its CAS uses the latest ACK for
 *   that target. A later step's inverse may have restored the bytes under a
 *   fresh generation. `history` contains just the durable forward/inverse ACKs,
 *   in each direction's execution order; `artifacts.confirmed` is the original
 *   forward effect's pin, not necessarily the current generation.
 * - A step with `window: 'main-agent'` opts the journal into v3. For that step
 *   only, `submit(async checkpoint => ...)` replaces the undivided handoff.
 *   Await `checkpoint(phase, previous, action)` for each MAIN_PHASES entry;
 *   pass null first, then the preceding opaque receipt, and return the final
 *   receipt from the effect. Each action receives the frozen current context.
 *   It must join and verify its native phase before returning; throw on missing
 *   or uncertain results. Never dispatch outside these action callbacks.
 * - captureMainPublication(ctx) is required for marked steps. After the stop
 *   has settled it must independently prove the drain and seal/reopen exact
 *   live before and authorized desired images as fresh {before, desired} pins,
 *   preserving post-drain managed clients. Bind the artifacts to this step,
 *   operation, direction and live generation, and derive the inverse from the
 *   original intent and latest ACK, not from a changed plan. Do not mutate MAIN
 *   here. The journal passes those immutable pins in `ctx.publication`; the
 *   publication action must use them for the actual native byte/generation CAS.
 * - verify(ctx, nativeReply): independently authenticate the settled effect and
 *   exact readback (not just the reply); return a durable encrypted artifact pin
 *   including the observed generations, or refuse. For a marked step, ctx has
 *   the final checkpoint and publication pins; nativeReply is the final
 *   action's reply. No target mutations here.
 * - prove({plan, confirmed}): true only after the read-only preparation proof
 *   (including old and new path checks). Called once before selectors or portals.
 * - verifyTerminal({plan, direction, confirmed, restored, step}): read-only on
 *   targets. Return an encrypted artifact pin for the complete final wire,
 *   runtime and boot verification. `step` is the terminal artifact namespace.
 *   Return false only for a known mismatch; a forward mismatch may reverse ACKs
 *   under the original fence and native CAS. An unavailable observation (throw),
 *   a lost fence or unproved restoration retains the scope without replay.
 * - observe(journalState): read-only 'before' | 'after' | 'mixed' | 'unavailable'.
 *   These report observations, never absence of an old in-flight writer.
 *
 * Inverse steps are allowed only during the original invocation, under the same
 * fence, on a known stop and in reverse ACK order. Returning from execute or
 * restarting the controller never grants retry, resume, or handback authority.
 */
function createScopedCutoverExecutor({ journal, adapter } = {}) {
    const reserve = stores.get(journal);
    if (!reserve || !['verifyFence', 'capture', 'dispatch', 'verify', 'prove', 'verifyTerminal', 'observe']
        .every(method => typeof adapter?.[method] === 'function')) throw invalid();
    async function checkFence(ctx) {
        try { return await adapter.verifyFence(ctx) === true; } catch { return false; }
    }

    const history = ({ confirmed, restored }) => ({ confirmed, restored });
    async function perform(tx, plan, direction, step, artifacts) {
        const record = direction === 'forward'
            ? { type: 'intent', direction, stepId: step.id, artifacts }
            : { type: 'intent', direction, stepId: step.id };
        const state = tx.record(record);
        const ctx = frozen({ plan, ...state.pending, history: history(state) });
        const window = mainWindow(step);
        let phaseCtx = ctx;
        let open = true, called = false, checkingHandoff = false, entered = false, duplicate = false;
        let fenceLost = false, journalLost = false, receipt, nativeReply, returned;
        let phaseOpen = false, phaseFailed = false, index = 0, previous = null;
        const usable = () => open && phaseOpen && !phaseFailed && !duplicate;
        function assertPhaseCurrent() {
            if (!usable()) throw invalid();
            tx.assertCurrent();
        }
        function checkpoint(phase, predecessor, action) {
            const exactArity = arguments.length === 3;
            const attempt = (async () => {
                try {
                    if (!usable() || previous === undefined || index === MAIN_PHASES.length || phase !== MAIN_PHASES[index]
                        || predecessor !== previous || !exactArity || typeof action !== 'function') throw invalid();
                    previous = undefined; // consume before waiting or calling untrusted I/O
                    assertPhaseCurrent();
                    if (!await checkFence(phaseCtx)) throw invalid();
                    assertPhaseCurrent();
                    let artifacts;
                    if (phase === 'main-publication') {
                        artifacts = captured(await adapter.captureMainPublication(phaseCtx));
                        assertPhaseCurrent();
                        if (!await checkFence(frozen({ ...phaseCtx, publication: artifacts }))) throw invalid();
                        assertPhaseCurrent();
                    }
                    const { pending } = tx.record({ type: 'checkpoint', phase, ...(artifacts && { artifacts }) });
                    phaseCtx = frozen({ ...ctx, ...pending });
                    if (!await checkFence(phaseCtx)) throw invalid();
                    assertPhaseCurrent();
                    nativeReply = await action(phaseCtx);
                    assertPhaseCurrent();
                    index++;
                    return previous = Object.freeze({});
                } catch (err) {
                    phaseFailed = true; // a swallowed refusal cannot reuse or advance this window
                    throw err;
                }
            })();
            attempt.catch(() => {});
            return attempt;
        }
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
                if (window) {
                    phaseOpen = true;
                    try {
                        const completed = await effect(checkpoint);
                        if (!usable() || index !== MAIN_PHASES.length || completed !== previous) throw invalid();
                    } finally { phaseOpen = false; }
                } else nativeReply = await effect();
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
        if (journalLost || (window && (phaseFailed || duplicate || checkingHandoff))) return 'unknown';
        if (!entered) {
            // An adapter that detached a still-running authority check has not
            // joined it. Revocation proves zero handoff, not continuous fencing.
            const reason = fenceLost || checkingHandoff ? 'fence' : 'handoff';
            tx.record({ type: 'not-dispatched', reason });
            return reason;
        }
        if (duplicate || !receipt || returned !== receipt || !await checkFence(phaseCtx)
            || (window && (phaseFailed || duplicate))) return 'unknown';
        let confirmed;
        try { confirmed = pin(await adapter.verify(phaseCtx, nativeReply)); } catch { return 'unknown'; }
        if (!await checkFence(phaseCtx) || (window && (phaseFailed || duplicate))) return 'unknown';
        tx.record({ type: 'ack', confirmed });
        return 'ack';
    }

    async function run(tx, plan) {
        const stop = reason => tx.record({ type: 'stop', reason });
        const finish = (status, proof) => {
            tx.record({ type: 'finish', status, ...(proof && { proof }) });
            return outcome(status);
        };
        async function terminal(direction) {
            const { confirmed, restored } = tx.state();
            const ctx = frozen({ plan, step: { id: `terminal-${direction}` }, direction, confirmed, restored });
            const block = reason => { tx.record({ type: 'terminal-blocked', direction, reason }); return outcome('blocked'); };
            if (!await checkFence(ctx)) return block('fence');
            let proof, mismatch = false;
            try {
                const observed = await adapter.verifyTerminal(ctx);
                if (observed === false) mismatch = true;
                else proof = pin(observed);
            } catch { /* read/verification failure is not an established mismatch */ }
            if (!await checkFence(ctx)) return block('fence');
            if (proof) return finish(direction === 'forward' ? 'applied' : 'rolled-back', proof);
            if (direction !== 'forward' || !mismatch) return block('proof');
            stop('terminal-proof');
            return null;
        }
        for (;;) {
            const state = tx.state(), step = nextForward(state);
            const ctx = frozen({ plan, step: step ?? null, direction: 'forward', history: history(state) });
            if (!await checkFence(ctx)) { stop('fence'); break; }
            if (!state.proved && step?.phase !== 'prepare') {
                let proved = false;
                try { proved = await adapter.prove(frozen({ plan, confirmed: state.confirmed })) === true; } catch { /* refused */ }
                if (!await checkFence(ctx)) { stop('fence'); break; }
                if (!proved) { stop('proof'); break; }
                tx.record({ type: 'proved' });
            }
            if (!step) {
                const result = await terminal('forward');
                if (result) return result;
                break;
            }
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
        return terminal('rollback');
    }

    return Object.freeze({
        async execute(input) {
            let plan;
            try { plan = frozen(checkedPlan(input)); } catch { throw invalid(); }
            if (plan.steps.some(mainWindow) && typeof adapter.captureMainPublication !== 'function') throw invalid();
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
