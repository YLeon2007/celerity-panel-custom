'use strict';

const assert = require('node:assert/strict');
const { fork } = require('node:child_process');
const { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } = require('node:crypto');
const { once } = require('node:events');
const fs = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createFileCutoverJournal, createScopedCutoverExecutor } = require('../rebuildTransitCutoverJournal');

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const beforeImage = Buffer.from('private synthetic auth material\u0000\r\n');
const plan = {
    scope: 'test-chain', operationId: randomUUID(), fenceId: randomUUID(), planDigest: digest('approved manifest'),
    steps: [['downstream', 'prepare'], ['upstream', 'prepare'], ['relay-selector', 'selector'],
        ['portal', 'portal']].map(([id, phase]) => ({ id, phase }))
};
const runtime = (root, id) => path.join(root, `runtime-${id}`);
const effects = root => fs.existsSync(path.join(root, 'effects'))
    ? fs.readFileSync(path.join(root, 'effects'), 'utf8').trim().split('\n') : [];
const hold = () => new Promise(() => {});

function fixture(root, journal, actions = {}) {
    const key = fs.readFileSync(path.join(root, 'fixture-key'));
    const fence = () => fs.readFileSync(path.join(root, 'fixture-fence'), 'utf8');
    const artifactFile = id => path.join(root, 'artifacts', id);
    const aad = (ctx, id) => JSON.stringify([ctx.plan.scope, ctx.plan.operationId, ctx.plan.fenceId,
        ctx.plan.planDigest, ctx.step.id, id]);
    function save(ctx, image) {
        const id = randomUUID(), iv = randomBytes(12);
        const cipher = createCipheriv('aes-256-gcm', key, iv);
        cipher.setAAD(Buffer.from(aad(ctx, id)));
        const bytes = Buffer.concat([iv, cipher.update(image), cipher.final(), cipher.getAuthTag()]);
        const fd = fs.openSync(artifactFile(id), 'wx', 0o600);
        try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
        const dir = fs.openSync(path.dirname(artifactFile(id)), 'r');
        try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
        const handle = { id, sha256: digest(bytes) };
        assert.deepEqual(load(ctx, handle), image);
        return handle;
    }
    function load(ctx, { id, sha256 }) {
        const bytes = fs.readFileSync(artifactFile(id));
        assert.equal(digest(bytes), sha256);
        const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
        decipher.setAAD(Buffer.from(aad(ctx, id)));
        decipher.setAuthTag(bytes.subarray(-16));
        return Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]);
    }
    return {
        seal: save, open: load,
        async verifyFence({ plan: p }) { return fence() === p.fenceId; },
        async capture(ctx) {
            if (actions.beforeCapture) await actions.beforeCapture(ctx);
            const current = fs.readFileSync(runtime(root, ctx.step.id));
            return { before: save(ctx, current), desired: save(ctx, Buffer.concat([current, Buffer.from(ctx.step.id)])) };
        },
        async dispatch(ctx, submit) {
            if (actions.beforeSubmit) await actions.beforeSubmit(ctx, submit);
            const ack = await submit(async () => {
                assert.equal(fence(), ctx.plan.fenceId);
                const current = journal.read(ctx.plan.scope);
                assert.equal(current.pending.step.id, ctx.step.id);
                assert.equal(current.pending.direction, ctx.direction);
                assert.deepEqual(current.pending.artifacts, ctx.artifacts);
                const target = runtime(root, ctx.step.id);
                const before = load(ctx, ctx.direction === 'forward' ? ctx.artifacts.before : ctx.artifacts.confirmed);
                const desired = load(ctx, ctx.direction === 'forward' ? ctx.artifacts.desired : ctx.artifacts.before);
                assert.deepEqual(fs.readFileSync(target), before);
                const fd = fs.openSync(target, 'w');
                try { fs.writeFileSync(fd, desired); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
                fs.appendFileSync(path.join(root, 'effects'), `${ctx.direction}:${ctx.step.id}\n`);
                if (actions.afterEffect) await actions.afterEffect(ctx);
                return { privateDiagnostic: beforeImage }; // never journal raw remote replies
            });
            return ack;
        },
        async verify(ctx, reply) {
            assert.deepEqual(reply.privateDiagnostic, beforeImage);
            const current = fs.readFileSync(runtime(root, ctx.step.id));
            const desired = load(ctx, ctx.direction === 'forward' ? ctx.artifacts.desired : ctx.artifacts.before);
            assert.deepEqual(current, desired);
            const confirmed = save(ctx, current);
            if (actions.verified) await actions.verified(ctx);
            return confirmed;
        },
        async prove({ plan: p, confirmed }) {
            assert.equal(confirmed.length, p.steps.filter(s => s.phase === 'prepare').length);
            assert(effects(root).every(line => p.steps.filter(s => s.phase === 'prepare').some(s => line === `forward:${s.id}`)));
            return actions.prove ? actions.prove() : true;
        },
        async verifyTerminal(ctx) {
            if (actions.terminal) {
                const result = await actions.terminal(ctx);
                if (result !== true) return result;
            }
            const restored = ctx.direction === 'rollback';
            assert.equal(ctx.confirmed.length, restored ? ctx.restored.length : ctx.plan.steps.length);
            for (const step of ctx.plan.steps) {
                const actual = fs.readFileSync(runtime(root, step.id));
                assert.deepEqual(actual, restored ? beforeImage : Buffer.concat([beforeImage, Buffer.from(step.id)]));
            }
            const proof = save(ctx, Buffer.from(ctx.direction));
            if (actions.beforeTerminalFinish) await actions.beforeTerminalFinish(ctx);
            return proof;
        },
        async observe(state) {
            if (!state.pending) return 'unavailable';
            const ctx = { plan: state.plan, ...state.pending };
            const current = fs.readFileSync(runtime(root, ctx.step.id));
            const before = load(ctx, ctx.publication?.before ?? (ctx.direction === 'forward' ? ctx.artifacts.before : ctx.artifacts.confirmed));
            const after = load(ctx, ctx.publication?.desired ?? (ctx.direction === 'forward' ? ctx.artifacts.desired : ctx.artifacts.before));
            return current.equals(before) ? 'before' : current.equals(after) ? 'after' : 'mixed';
        }
    };
}

function scratch(t) {
    const root = fs.mkdtempSync(path.join(tmpdir(), 'c3-cutover-journal-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    for (const name of ['journal', 'artifacts']) fs.mkdirSync(path.join(root, name), { mode: 0o700 });
    fs.writeFileSync(path.join(root, 'fixture-key'), randomBytes(32), { mode: 0o600 });
    fs.writeFileSync(path.join(root, 'fixture-fence'), plan.fenceId, { mode: 0o600 });
    for (const step of plan.steps) fs.writeFileSync(runtime(root, step.id), beforeImage, { mode: 0o600 });
    return root;
}
const fileJournal = root => createFileCutoverJournal({ directory: path.join(root, 'journal') });
function journalFile(root) {
    const entries = fs.readdirSync(path.join(root, 'journal'));
    assert.equal(entries.length, 1);
    return path.join(root, 'journal', entries[0]);
}
function executor(root, actions) {
    const journal = fileJournal(root);
    return { journal, adapter: fixture(root, journal, actions) };
}

// Separate process: test only passes the disposable root, safe plan, and a fault
// name. No effect target is an operational service or a native Xray process.
if (process.argv[2] === '--cutover-child') {
    const [root, mode] = process.argv.slice(3);
    process.once('message', async p => {
        const pause = async () => {
            // Removing the once('message') listener can unref Node's IPC
            // channel; a pending Promise alone cannot keep the process alive.
            process.channel.ref();
            process.send({ boundary: mode });
            await hold();
        };
        const binding = executor(root, {
            beforeSubmit: async ctx => {
                if (mode === 'before-submit' && ctx.step.id === 'upstream') await pause();
                if (mode === 'inverse-effect' && ctx.direction === 'forward' && ctx.step.id === 'portal') throw Error('fixture refusal');
            },
            afterEffect: async ctx => {
                if ((mode === 'lost-reply' && ctx.step.id === 'upstream') ||
                    (mode === 'inverse-effect' && ctx.direction === 'rollback')) await pause();
            },
            verified: async ctx => { if (mode === 'lost-ack' && ctx.step.id === 'upstream') await pause(); },
            beforeCapture: async ctx => { if (mode === 'after-durable-ack' && ctx.step.id === 'relay-selector') await pause(); },
            beforeTerminalFinish: async ctx => { if (mode === 'after-terminal-proof' && ctx.direction === 'forward') await pause(); }
        });
        if (mode === 'reopen' && p.steps.some(step => step.window)) {
            binding.adapter.captureMainPublication = () => assert.fail('fresh reader attempted publication capture');
        }
        const service = createScopedCutoverExecutor(binding);
        try {
            const result = mode === 'reopen'
                ? { observation: await service.reconcile(p.scope), replay: await service.execute({ ...p, operationId: randomUUID() }) }
                : await service.execute(p);
            process.send(result, () => process.disconnect());
        } catch (err) {
            process.send({ error: err.message }, () => process.disconnect());
        }
    });
} else {
    async function child(t, root, mode, input = plan) {
        const worker = fork(__filename, ['--cutover-child', root, mode], { execArgv: [], stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
        const exited = once(worker, 'exit');
        t.after(async () => { if (worker.exitCode === null && worker.signalCode === null) worker.kill('SIGKILL'); await exited; });
        worker.send(input);
        const result = await Promise.race([once(worker, 'message').then(([msg]) => msg), exited.then(([code, signal]) => {
            throw new Error(`fixture exited before boundary: ${code}/${signal}`);
        })]);
        return { worker, exited, result };
    }

    test('proof bars selectors, portals are last, and only encrypted pins get journaled', async t => {
        const root = scratch(t), binding = executor(root);
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(plan)).status, 'applied');
        assert.deepEqual(effects(root), plan.steps.map(step => `forward:${step.id}`));
        assert.equal(binding.journal.read(plan.scope).confirmed.length, 4);
        assert.equal(binding.journal.read(plan.scope).proved, true);
        assert.equal(binding.journal.read(plan.scope).version, 2);
        assert.match(binding.journal.read(plan.scope).terminalProof?.sha256 ?? '', /^[a-f0-9]{64}$/);
        const file = journalFile(root), bytes = fs.readFileSync(file);
        assert.equal(fs.statSync(file).mode & 0o777, 0o600);
        assert(!bytes.includes(beforeImage.subarray(0, 28)));
        assert(!bytes.includes(Buffer.from('privateDiagnostic')));
        assert(!fs.readdirSync(path.join(root, 'artifacts')).some(id =>
            fs.readFileSync(path.join(root, 'artifacts', id)).includes(beforeImage.subarray(0, 28))));
        assert.equal((await service.execute(plan)).status, 'already-recorded');
        assert.deepEqual(fs.readFileSync(file), bytes);
    });

    test('a definitive terminal forward mismatch rolls back all acknowledged moves including portals', async t => {
        const root = scratch(t), rounds = [];
        const binding = executor(root, { terminal(ctx) {
            rounds.push({ direction: ctx.direction, effects: effects(root) });
            return ctx.direction === 'rollback';
        } });
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(plan)).status, 'rolled-back');
        const forward = plan.steps.map(step => `forward:${step.id}`);
        const inverse = plan.steps.toReversed().map(step => `rollback:${step.id}`);
        assert.deepEqual(rounds, [{ direction: 'forward', effects: forward },
            { direction: 'rollback', effects: [...forward, ...inverse] }]);
        const stored = binding.journal.read(plan.scope);
        assert.deepEqual(stored.refusal, { step: null, reason: 'terminal-proof' });
        assert.match(stored.terminalProof.sha256, /^[a-f0-9]{64}$/);
    });

    for (const mode of ['read-failed', 'invalid-receipt', 'rollback-mismatch', 'fence-lost']) {
        test(`terminal ${mode} keeps the scope blocked and reconciliation read-only`, async t => {
            const root = scratch(t);
            const binding = executor(root, { terminal() {
                if (mode === 'read-failed') throw new Error('unavailable');
                if (mode === 'invalid-receipt') return 'truthy';
                if (mode === 'fence-lost') {
                    fs.writeFileSync(path.join(root, 'fixture-fence'), randomUUID());
                    return true;
                }
                return false;
            } });
            const service = createScopedCutoverExecutor(binding);
            assert.equal((await service.execute(plan)).status, 'blocked');
            const stored = binding.journal.read(plan.scope);
            assert.equal(stored.pending, null);
            assert.equal(stored.terminalProof, null);
            assert.equal(stored.terminalFailure.direction, mode === 'rollback-mismatch' ? 'rollback' : 'forward');
            assert.equal(stored.terminalFailure.reason, mode === 'fence-lost' ? 'fence' : 'proof');
            const forward = plan.steps.map(step => `forward:${step.id}`);
            const expected = mode === 'rollback-mismatch' ? [...forward, ...plan.steps.toReversed().map(step => `rollback:${step.id}`)] : forward;
            assert.deepEqual(effects(root), expected);
            const record = fs.readFileSync(journalFile(root));
            assert.equal((await service.reconcile(plan.scope)).retryAllowed, false);
            assert.equal((await service.execute({ ...plan, operationId: randomUUID() })).status, 'already-recorded');
            assert.deepEqual(fs.readFileSync(journalFile(root)), record);
            assert.deepEqual(effects(root), expected);
        });
    }

    test('definite no handoff unwinds only acknowledged moves, in inverse order', async t => {
        const root = scratch(t), binding = executor(root, { beforeSubmit(ctx) {
            if (ctx.step.id === 'portal') throw Error('known refusal before submit');
        } });
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(plan)).status, 'rolled-back');
        const forward = plan.steps.slice(0, -1).map(step => step.id);
        assert.deepEqual(effects(root), [...forward.map(id => `forward:${id}`), ...forward.toReversed().map(id => `rollback:${id}`)]);
        const stored = binding.journal.read(plan.scope);
        assert.equal(stored.refusal.step.id, 'portal');
        assert.equal(stored.pending, null);
        for (const step of plan.steps) assert.deepEqual(fs.readFileSync(runtime(root, step.id)), beforeImage);
    });

    test('first known pre-submit refusal is not unknown and a saved callback cannot dispatch later', async t => {
        const root = scratch(t);
        let stale;
        const service = createScopedCutoverExecutor(executor(root, { beforeSubmit(ctx, submit) { stale = submit; throw null; } }));
        assert.equal((await service.execute(plan)).status, 'not-dispatched');
        await assert.rejects(async () => stale(() => assert.fail('late handoff')));
        assert.deepEqual(effects(root), []);
    });

    test('unproved route rolls back preparation without entering selectors', async t => {
        const root = scratch(t);
        const service = createScopedCutoverExecutor(executor(root, { prove: () => false }));
        assert.equal((await service.execute(plan)).status, 'rolled-back');
        assert.deepEqual(effects(root), ['forward:downstream', 'forward:upstream', 'rollback:upstream', 'rollback:downstream']);
    });

    test('a fence lost between intent readback and handoff prevents dispatch and any unwind', async t => {
        const root = scratch(t), binding = executor(root, { beforeSubmit(ctx) {
            if (ctx.step.id === 'upstream') fs.writeFileSync(path.join(root, 'fixture-fence'), randomUUID());
        } });
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(plan)).status, 'blocked');
        assert.equal(binding.journal.read(plan.scope).refusal.step.id, 'upstream');
        assert.equal((await service.reconcile(plan.scope)).observation, 'unavailable');
        assert.deepEqual(effects(root), ['forward:downstream']);
    });

    test('a late affirmative authority check cannot revive a detached submit', async t => {
        const root = scratch(t), binding = executor(root);
        const { dispatch, verifyFence } = binding.adapter;
        let detached, release;
        const delayed = new Promise(resolve => { release = resolve; });
        let gate = false;
        binding.adapter.verifyFence = ctx => gate && ctx.step?.id === 'upstream' ? delayed : verifyFence(ctx);
        binding.adapter.dispatch = (ctx, submit) => {
            if (ctx.step.id !== 'upstream') return dispatch(ctx, submit);
            gate = true;
            detached = submit(() => assert.fail('detached handoff'));
        };
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(plan)).status, 'blocked');
        release(true);
        await assert.rejects(detached, { code: 'REBUILD_CUTOVER_INVALID' });
        assert.deepEqual(effects(root), ['forward:downstream']);
    });

    test('a byte-identical replacement journal cannot authorize the original writer', async t => {
        const root = scratch(t), binding = executor(root, { beforeSubmit(ctx) {
            if (ctx.step.id !== 'upstream') return;
            const file = journalFile(root), replacement = path.join(root, 'replacement');
            fs.writeFileSync(replacement, fs.readFileSync(file), { mode: 0o600 });
            fs.renameSync(replacement, file);
        } });
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(plan)).status, 'unknown');
        assert.equal(binding.journal.read(plan.scope).pending.step.id, 'upstream');
        assert.deepEqual(effects(root), ['forward:downstream']);
        assert.equal((await service.execute(plan)).status, 'already-recorded');
    });

    test('a forged no-dispatch result after handoff cannot grant rollback', async t => {
        const root = scratch(t), binding = executor(root, { afterEffect(ctx) {
            if (ctx.step.id === 'upstream') throw Object.assign(Error('lost reply'), { notDispatched: true });
        } });
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(plan)).status, 'unknown');
        assert.equal(binding.journal.read(plan.scope).pending.step.id, 'upstream');
        assert.equal((await service.reconcile(plan.scope)).observation, 'after');
        assert.deepEqual(effects(root), ['forward:downstream', 'forward:upstream']);
    });

    test('failed independent verification leaves an intent, not an ACK', async t => {
        const root = scratch(t), binding = executor(root, { verified() { throw Error('verification unavailable'); } });
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(plan)).status, 'unknown');
        assert.equal(binding.journal.read(plan.scope).confirmed.length, 0);
        assert.equal((await service.reconcile(plan.scope)).observation, 'after');
        assert.deepEqual(effects(root), ['forward:downstream']);
    });

    const uncertain = { code: 'REBUILD_CUTOVER_JOURNAL_UNCERTAIN' };
    function lastEvent(root) {
        const lines = fs.readFileSync(journalFile(root), 'utf8').trimEnd().split('\n');
        return JSON.parse(lines.at(-1)).event;
    }

    const mainPhases = ['agent-stop', 'main-publication', 'xray-restart', 'agent-start', 'agent-reconcile'];
    const mainPlan = { ...plan, steps: [{ ...plan.steps[0], window: 'main-agent' }] };

    function mainFixture(root, actions = {}) {
        const binding = executor(root), { journal, adapter } = binding;
        const trace = [], publications = [];
        const clients = { forward: Buffer.from('drained clients A'), rollback: Buffer.from('drained clients B') };
        const withClients = (image, direction) => actions.drain ? Buffer.concat([image, clients[direction]]) : image;
        adapter.captureMainPublication = async ctx => {
            assert.equal(journal.read(plan.scope).pending.checkpoint, 'agent-stop');
            assert.equal(trace.at(-1), `${ctx.direction}:agent-stop`);
            const before = fs.readFileSync(runtime(root, ctx.step.id));
            const desired = adapter.open(ctx, ctx.direction === 'forward' ? ctx.artifacts.desired : ctx.artifacts.before);
            const pins = { before: adapter.seal(ctx, before), desired: adapter.seal(ctx, withClients(desired, ctx.direction)) };
            publications.push(pins);
            return actions.capture ? actions.capture(ctx, pins) : pins;
        };
        const { dispatch, verify } = adapter;
        adapter.dispatch = (ctx, submit) => ctx.step.window !== 'main-agent' ? dispatch(ctx, submit) : submit(async checkpoint => {
            let previous = null;
            for (const phase of mainPhases) {
                const action = async phaseCtx => {
                    const { pending } = journal.read(plan.scope);
                    assert.equal(pending.checkpoint, phase);
                    assert.deepEqual(pending.artifacts, ctx.artifacts);
                    assert.equal(lastEvent(root).type, 'checkpoint');
                    assert.deepEqual(phaseCtx.publication, pending.publication);
                    if (phase === 'agent-stop' && actions.drain) {
                        const file = runtime(root, ctx.step.id);
                        const liveTopology = adapter.open(ctx, ctx.direction === 'forward' ? ctx.artifacts.before : ctx.artifacts.desired);
                        fs.writeFileSync(file, withClients(liveTopology, ctx.direction));
                    }
                    if (phase === 'main-publication') {
                        assert.deepEqual(pending.publication, publications.at(-1));
                        assert(Object.isFrozen(phaseCtx.publication.before));
                        const file = runtime(root, ctx.step.id);
                        assert.deepEqual(fs.readFileSync(file), adapter.open(ctx, phaseCtx.publication.before));
                        fs.writeFileSync(file, adapter.open(ctx, phaseCtx.publication.desired));
                    }
                    trace.push(`${ctx.direction}:${phase}`);
                    if (actions.afterAction) await actions.afterAction(ctx, phase);
                    return { privateDiagnostic: beforeImage };
                };
                previous = actions.atCheckpoint
                    ? await actions.atCheckpoint(checkpoint, phase, previous, action)
                    : await checkpoint(phase, previous, action);
            }
            return previous;
        });
        adapter.verify = (ctx, reply) => {
            if (ctx.step.window !== 'main-agent') return verify(ctx, reply);
            assert.deepEqual(reply.privateDiagnostic, beforeImage);
            assert.equal(ctx.checkpoint, mainPhases.at(-1));
            assert.deepEqual(ctx.publication, publications.at(-1));
            const current = fs.readFileSync(runtime(root, ctx.step.id));
            assert.deepEqual(current, adapter.open(ctx, ctx.publication.desired));
            return adapter.seal(ctx, current);
        };
        adapter.verifyTerminal = ctx => {
            assert.deepEqual(ctx.confirmed[0].publication, publications[0]);
            const rollback = ctx.direction === 'rollback';
            if (rollback) assert.deepEqual(ctx.restored[0].publication, publications[1]);
            const step = ctx.plan.steps[0];
            const expected = rollback ? beforeImage : Buffer.concat([beforeImage, Buffer.from(step.id)]);
            assert.deepEqual(fs.readFileSync(runtime(root, step.id)), withClients(expected, ctx.direction));
            return actions.inverse && !rollback ? false : adapter.seal(ctx, Buffer.from(ctx.direction));
        };
        return { ...binding, trace, publications };
    }

    for (const inverse of [false, true]) {
        test(`v3 durable MAIN window with terminal proof (${inverse ? 'inverse' : 'forward'})`, async t => {
            const root = scratch(t), binding = mainFixture(root, { inverse, drain: true });
            const service = createScopedCutoverExecutor(binding);
            assert.deepEqual(await service.execute(mainPlan), { status: inverse ? 'rolled-back' : 'applied', retryAllowed: false });
            const state = fileJournal(root).read(plan.scope);
            assert.equal(state.version, 3);
            assert.deepEqual(state.plan, mainPlan);
            assert.equal(state.pending, null);
            assert.match(state.terminalProof.sha256, /^[a-f0-9]{64}$/);
            assert.deepEqual(binding.trace, [
                ...mainPhases.map(phase => `forward:${phase}`),
                ...(inverse ? mainPhases.map(phase => `rollback:${phase}`) : [])
            ]);
            const [forward, rollback] = binding.publications;
            const ctx = { plan, step: mainPlan.steps[0] };
            assert.deepEqual(binding.adapter.open(ctx, forward.before), Buffer.concat([beforeImage, Buffer.from('drained clients A')]));
            assert.notDeepEqual(forward.before, state.confirmed[0].artifacts.before);
            if (inverse) {
                assert.notDeepEqual(rollback.before, forward.desired);
                assert.deepEqual(binding.adapter.open(ctx, rollback.before), Buffer.concat([
                    beforeImage, Buffer.from(`${ctx.step.id}drained clients B`)
                ]));
                assert.deepEqual(fs.readFileSync(runtime(root, ctx.step.id)), Buffer.concat([beforeImage, Buffer.from('drained clients B')]));
            }
        });
    }

    for (const direction of ['forward', 'rollback']) {
        test(`v3 lost ${direction} publication reply preserves pending pins and never starts or replays`, async t => {
            const inverse = direction === 'rollback';
            const root = scratch(t), binding = mainFixture(root, { inverse, afterAction(ctx, phase) {
                if (ctx.direction === direction && phase === 'main-publication') {
                    throw Object.assign(Error('fixture lost reply'), { notDispatched: true });
                }
            } });
            const service = createScopedCutoverExecutor(binding);
            assert.deepEqual(await service.execute(mainPlan), { status: 'unknown', retryAllowed: false });
            const before = fs.readFileSync(journalFile(root));
            const fresh = await child(t, root, 'reopen', mainPlan);
            const { journal, observation, retryAllowed } = fresh.result.observation;
            assert.equal(journal.pending.direction, direction);
            assert.equal(journal.pending.checkpoint, 'main-publication');
            assert.deepEqual(journal.pending.publication, binding.publications.at(-1));
            assert.equal(journal.confirmed.length, Number(inverse));
            assert.equal(journal.restored.length, 0);
            assert.equal(journal.terminalProof, null);
            assert.equal(observation, 'after');
            assert.equal(retryAllowed, false);
            assert.deepEqual(binding.trace, [
                ...(inverse ? mainPhases.map(phase => `forward:${phase}`) : []),
                `${direction}:agent-stop`, `${direction}:main-publication`
            ]);
            assert.equal(fresh.result.replay.status, 'already-recorded');
            assert.deepEqual(await fresh.exited, [0, null]);
            assert.deepEqual(fs.readFileSync(journalFile(root)), before);
        });
    }

    const invalid = { code: 'REBUILD_CUTOVER_INVALID' };
    for (const fault of ['order', 'altered receipt', 'surplus pins', 'duplicate']) {
        test(`v3 ${fault} is sticky even when the adapter catches the refusal`, async t => {
            const root = scratch(t);
            const binding = mainFixture(root, { async atCheckpoint(checkpoint, phase, previous, action) {
                if (phase !== 'main-publication') return checkpoint(phase, previous, action);
                const forbidden = () => assert.fail('invalid checkpoint dispatched');
                const invalidArgs = {
                    order: ['xray-restart', previous, forbidden],
                    'altered receipt': [phase, { ...previous }, forbidden],
                    'surplus pins': [phase, previous, forbidden, { desired: {} }],
                    duplicate: ['agent-stop', null, forbidden]
                };
                await assert.rejects(checkpoint(...invalidArgs[fault]), invalid);
                return checkpoint(phase, previous, action);
            } });
            const service = createScopedCutoverExecutor(binding);
            assert.equal((await service.execute(mainPlan)).status, 'unknown');
            assert.equal(binding.journal.read(plan.scope).pending.checkpoint, 'agent-stop');
            assert.equal(binding.publications.length, 0);
            assert.deepEqual(binding.trace, ['forward:agent-stop']);
        });
    }

    test('v3 rejects stale intent pins in place of newly authenticated post-drain pins', async t => {
        const root = scratch(t), binding = mainFixture(root, { capture: ctx => ctx.artifacts });
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(mainPlan)).status, 'unknown');
        const { pending } = binding.journal.read(plan.scope);
        assert.equal(pending.checkpoint, 'agent-stop');
        assert.equal(pending.publication, undefined);
        assert.deepEqual(binding.trace, ['forward:agent-stop']);
    });

    test('v3 revokes a detached checkpoint waiting for a live fence and refuses late reuse', async t => {
        const root = scratch(t), binding = mainFixture(root), { adapter } = binding;
        const { promise, resolve } = Promise.withResolvers();
        let detached, saved, waiting = false, effects = 0;
        const verifyFence = adapter.verifyFence;
        adapter.verifyFence = ctx => waiting ? promise : verifyFence(ctx);
        adapter.dispatch = (ctx, submit) => submit(checkpoint => {
            saved = checkpoint;
            waiting = true;
            detached = checkpoint('agent-stop', null, () => { effects++; });
            return {}; // not the joined final receipt
        });
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(mainPlan)).status, 'unknown');
        resolve(true);
        await assert.rejects(detached, invalid);
        await assert.rejects(saved('agent-stop', null, () => { effects++; }), invalid);
        assert.equal(effects, 0);
        assert.equal(binding.journal.read(plan.scope).pending.checkpoint, null);
    });

    test('v3 ignores a completed native tail without the original final checkpoint receipt', async t => {
        const root = scratch(t), binding = mainFixture(root);
        const { dispatch } = binding.adapter;
        binding.adapter.dispatch = (ctx, submit) => dispatch(ctx, effect => submit(async checkpoint => {
            await effect(checkpoint);
            return Object.freeze({});
        }));
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(mainPlan)).status, 'unknown');
        assert.deepEqual(binding.trace, mainPhases.map(phase => `forward:${phase}`));
        assert.equal(binding.journal.read(plan.scope).pending.checkpoint, 'agent-reconcile');
        assert.equal(binding.journal.read(plan.scope).confirmed.length, 0);
    });

    for (const fault of ['fence lost during capture', 'journal replaced during capture', 'lost checkpoint sync reply']) {
        test(`v3 ${fault} prevents publication and leaves the previous intent intact`, async t => {
            const root = scratch(t);
            const binding = mainFixture(root, { capture(ctx, pins) {
                if (fault === 'fence lost during capture') {
                    fs.writeFileSync(path.join(root, 'fixture-fence'), randomUUID());
                } else if (fault === 'journal replaced during capture') {
                    const file = journalFile(root), replacement = path.join(root, 'replacement');
                    fs.writeFileSync(replacement, fs.readFileSync(file), { mode: 0o600 });
                    fs.renameSync(replacement, file);
                }
                return pins;
            } });
            let syncLost = false;
            if (fault === 'lost checkpoint sync reply') {
                const sync = fs.fsyncSync;
                t.mock.method(fs, 'fsyncSync', fd => {
                    sync(fd);
                    if (binding.publications.length && lastEvent(root).phase === 'main-publication') {
                        syncLost = true;
                        throw Error('fixture lost fsync reply');
                    }
                });
            }
            const service = createScopedCutoverExecutor(binding);
            assert.equal((await service.execute(mainPlan)).status, 'unknown');
            assert.equal(syncLost, fault === 'lost checkpoint sync reply');
            const { pending } = fileJournal(root).read(plan.scope);
            assert.equal(pending.checkpoint, syncLost ? 'main-publication' : 'agent-stop');
            assert.deepEqual(binding.trace, ['forward:agent-stop']);
            assert.deepEqual(fs.readFileSync(runtime(root, mainPlan.steps[0].id)), beforeImage);
            assert.equal((await service.execute(mainPlan)).status, 'already-recorded');
        });
    }

    test('v3 complete checkpoints and ACK still require independent terminal proof', async t => {
        const root = scratch(t), binding = mainFixture(root);
        binding.adapter.verifyTerminal = () => { throw Error('fixture terminal proof unavailable'); };
        const service = createScopedCutoverExecutor(binding);
        assert.deepEqual(await service.execute(mainPlan), { status: 'blocked', retryAllowed: false });
        const state = binding.journal.read(plan.scope);
        assert.equal(state.confirmed.length, 1);
        assert.equal(state.pending, null);
        assert.equal(state.terminalProof, null);
        assert.deepEqual(state.terminalFailure, { direction: 'forward', reason: 'proof' });
    });

    test('v3 marker is explicit and needs a publication capture hook before reservation', async t => {
        const root = scratch(t), binding = executor(root), service = createScopedCutoverExecutor(binding);
        await assert.rejects(service.execute(mainPlan), invalid);
        await assert.rejects(service.execute({ ...mainPlan, steps: [{ ...mainPlan.steps[0], window: 'other' }] }), invalid);
        assert.equal(binding.journal.read(plan.scope), null);
        assert.equal((await service.execute(plan)).status, 'applied');
        assert.equal(binding.journal.read(plan.scope).version, 2);
    });

    test('v3 mixed plan gives an unmarked step the original submit contract', async t => {
        const root = scratch(t), binding = mainFixture(root), { adapter } = binding;
        const input = { ...mainPlan, steps: [mainPlan.steps[0], plan.steps[1]] };
        const { dispatch, verifyTerminal } = adapter;
        adapter.dispatch = (ctx, submit) => dispatch(ctx, ctx.step.window ? submit : effect => submit((...args) => {
            assert.equal(args.length, 0);
            assert.equal(ctx.checkpoint, undefined);
            return effect();
        }));
        adapter.verifyTerminal = ctx => {
            assert.deepEqual(effects(root), [`forward:${input.steps[1].id}`]);
            assert.equal(ctx.confirmed[1].publication, undefined);
            return verifyTerminal(ctx);
        };
        const service = createScopedCutoverExecutor(binding);
        assert.equal((await service.execute(input)).status, 'applied');
        assert.equal(binding.journal.read(plan.scope).version, 3);
        assert.deepEqual(binding.trace, mainPhases.map(phase => `forward:${phase}`));
    });

    function writeFrames(root, events) {
        let prev = '0'.repeat(64);
        const bytes = Buffer.from(events.map(event => {
            const sha256 = digest(JSON.stringify({ prev, event }));
            const line = JSON.stringify({ prev, event, sha256 }) + '\n';
            prev = sha256;
            return line;
        }).join(''));
        const file = path.join(root, 'journal', `cutover-${digest(plan.scope)}.jsonl`);
        fs.writeFileSync(file, bytes, { mode: 0o600 });
        return { file, bytes };
    }

    test('historical v1 accepts proof-less finish, v2 does not downgrade terminal proof', async t => {
        const root = scratch(t), binding = executor(root), service = createScopedCutoverExecutor(binding);
        const step = plan.steps[0], input = { ...plan, steps: [step] };
        const receipt = { id: randomUUID(), sha256: digest('historical artifact') };
        const events = [{ type: 'start', version: 1, plan: input },
            { type: 'intent', direction: 'forward', stepId: step.id, artifacts: { before: receipt, desired: receipt } },
            { type: 'ack', confirmed: receipt }, { type: 'proved' }, { type: 'finish', status: 'applied' }];
        const { file, bytes } = writeFrames(root, events);
        assert.equal((await service.reconcile(plan.scope)).journal.status, 'applied');
        assert.equal((await service.execute(input)).status, 'already-recorded');
        assert.deepEqual(fs.readFileSync(file), bytes);
        writeFrames(root, [{ ...events[0], version: 2 }, ...events.slice(1)]);
        assert.throws(() => binding.journal.read(plan.scope), uncertain);
        for (const version of [1, 2]) {
            writeFrames(root, [{ type: 'start', version, plan: mainPlan }]);
            assert.throws(() => binding.journal.read(plan.scope), uncertain);
        }
    });

    test('v3 rejects rehashed checkpoints and ACKs that cannot follow the durable intent', async t => {
        const root = scratch(t), journal = fileJournal(root);
        const step = mainPlan.steps[0];
        const artifacts = Object.fromEntries(['before', 'desired'].map(side => [side, { id: randomUUID(), sha256: digest(side) }]));
        const intent = { type: 'intent', direction: 'forward', stepId: step.id, artifacts };
        const marker = { type: 'checkpoint', phase: 'agent-stop' };
        const start = { type: 'start', version: 3, plan: mainPlan };
        const publication = { type: 'checkpoint', phase: 'main-publication', artifacts };
        const phases = mainPhases.map(phase => phase === 'main-publication'
            ? { ...publication, artifacts: { before: { ...artifacts.before, id: randomUUID() }, desired: { ...artifacts.desired, id: randomUUID() } } }
            : { type: 'checkpoint', phase });
        for (const frames of [[start, intent, publication], [start, intent, marker, marker],
            [start, intent, marker, publication], [start, intent, marker, { type: 'ack', confirmed: artifacts.desired }],
            [start, intent, marker, { type: 'not-dispatched', reason: 'handoff' }],
            [{ ...start, plan: { ...mainPlan, steps: [plan.steps[0], { ...plan.steps[1], window: step.window }] } }, intent, marker],
            [start, intent, ...phases, { type: 'ack', confirmed: artifacts.desired }, { type: 'proved' }, { type: 'finish', status: 'applied' }]]) {
            writeFrames(root, frames);
            assert.throws(() => journal.read(plan.scope), uncertain);
        }
    });

    for (const fault of ['file-fsync', 'directory-fsync', 'readback']) {
        test(`intent ${fault} failure cannot reach first handoff`, async t => {
            const root = scratch(t), binding = executor(root);
            const service = createScopedCutoverExecutor(binding);
            const originalSync = fs.fsyncSync;
            const journalDir = fs.statSync(path.join(root, 'journal'), { bigint: true });
            let fileSynced = false, directorySynced = false;
            t.mock.method(fs, 'fsyncSync', fd => {
                const st = fs.fstatSync(fd, { bigint: true });
                const isDirectory = st.dev === journalDir.dev && st.ino === journalDir.ino;
                const file = fs.statSync(journalFile(root), { bigint: true });
                const isJournal = st.dev === file.dev && st.ino === file.ino;
                const intent = (isJournal || isDirectory) && lastEvent(root).type === 'intent';
                if (intent && isJournal && fault === 'file-fsync') throw Error('fixture file sync failure');
                if (intent && isDirectory && fault === 'directory-fsync') throw Error('fixture directory sync failure');
                originalSync(fd);
                if (intent && isJournal) fileSynced = true;
                if (intent && isDirectory) {
                    directorySynced = true;
                    if (fault === 'readback') fs.appendFileSync(journalFile(root), 'torn tail');
                }
            });
            assert.equal((await service.execute(plan)).status, 'unknown');
            assert.equal(fileSynced, fault !== 'file-fsync');
            assert.equal(directorySynced, fault === 'readback');
            assert.deepEqual(effects(root), []);
            if (fault === 'readback') assert.throws(() => fileJournal(root).read(plan.scope), uncertain);
            else assert.equal(fileJournal(root).read(plan.scope).pending.step.id, 'downstream');
            assert.equal((await service.execute({ ...plan, operationId: randomUUID() })).status, 'already-recorded');
        });
    }

    test('loss of the ACK fsync reply never advances to the next step, even with ACK bytes surviving', async t => {
        const root = scratch(t), binding = executor(root);
        const service = createScopedCutoverExecutor(binding);
        const originalSync = fs.fsyncSync;
        let faulted = false;
        t.mock.method(fs, 'fsyncSync', fd => {
            const st = fs.fstatSync(fd, { bigint: true });
            const file = fs.statSync(journalFile(root), { bigint: true });
            originalSync(fd);
            if (st.dev === file.dev && st.ino === file.ino && lastEvent(root).type === 'ack') {
                faulted = true;
                throw Error('fixture lost sync result');
            }
        });
        assert.equal((await service.execute(plan)).status, 'unknown');
        assert.equal(faulted, true);
        assert.equal(fileJournal(root).read(plan.scope).confirmed.length, 1);
        assert.deepEqual(effects(root), ['forward:downstream']);
        assert.equal((await service.execute(plan)).status, 'already-recorded');
    });

    test('scope is independent of attempt ID; invalid ordering is refused before consuming a scope', async t => {
        const root = scratch(t), binding = executor(root);
        const service = createScopedCutoverExecutor(binding);
        await assert.rejects(service.execute({ ...plan, steps: plan.steps.toReversed() }), { code: 'REBUILD_CUTOVER_INVALID' });
        assert.equal(binding.journal.read(plan.scope), null);
        // Use a pre-dispatch refusal to keep the same fixture images pristine.
        binding.adapter.dispatch = () => {};
        assert.equal((await service.execute(plan)).status, 'not-dispatched');
        assert.equal((await service.execute({ ...plan, operationId: randomUUID() })).status, 'already-recorded');
        assert.equal((await service.execute({ ...plan, scope: 'independent-chain' })).status, 'not-dispatched');
    });

    for (const [mode, observed, trace, step, direction] of [
        ['before-submit', 'before', ['forward:downstream'], 'upstream', 'forward'],
        ['lost-reply', 'after', ['forward:downstream', 'forward:upstream'], 'upstream', 'forward'],
        ['lost-ack', 'after', ['forward:downstream', 'forward:upstream'], 'upstream', 'forward'],
        ['inverse-effect', 'after', ['forward:downstream', 'forward:upstream', 'forward:relay-selector', 'rollback:relay-selector'],
            'relay-selector', 'rollback']
    ]) {
        test(`SIGKILL at ${mode}: fresh process only observes, never replays`, { timeout: 10000 }, async t => {
            const root = scratch(t), { worker, exited, result } = await child(t, root, mode);
            assert.deepEqual(result, { boundary: mode });
            const durable = fileJournal(root).read(plan.scope);
            assert.equal(durable.pending.step.id, step);
            assert.equal(durable.pending.direction, direction);
            assert.equal(durable.confirmed.some(c => c.step.id === step), direction === 'rollback');
            assert.deepEqual(effects(root), trace);
            const original = fs.readFileSync(journalFile(root));
            // A competing writer must also refuse while the actual original PID is alive.
            const concurrent = createScopedCutoverExecutor(executor(root));
            assert.equal((await concurrent.execute({ ...plan, operationId: randomUUID() })).status, 'already-recorded');
            assert(worker.kill('SIGKILL'));
            assert.deepEqual(await exited, [null, 'SIGKILL']);
            const fresh = await child(t, root, 'reopen');
            assert.equal(fresh.result.observation.observation, observed);
            assert.deepEqual(fresh.result.observation.journal, durable);
            assert.equal(fresh.result.observation.retryAllowed, false);
            assert.equal(fresh.result.replay.status, 'already-recorded');
            assert.deepEqual(await fresh.exited, [0, null]);
            assert.deepEqual(effects(root), trace);
            assert.deepEqual(fs.readFileSync(journalFile(root)), original);
        });
    }

    test('SIGKILL after durable ACKs cannot resume the acknowledged prefix', { timeout: 10000 }, async t => {
        const root = scratch(t), { worker, exited, result } = await child(t, root, 'after-durable-ack');
        assert.deepEqual(result, { boundary: 'after-durable-ack' });
        const journal = fileJournal(root).read(plan.scope);
        assert.equal(journal.pending, null);
        assert.equal(journal.status, 'interrupted');
        assert.deepEqual(journal.confirmed.map(c => c.step.id), ['downstream', 'upstream']);
        assert(worker.kill('SIGKILL'));
        assert.deepEqual(await exited, [null, 'SIGKILL']);
        const fresh = await child(t, root, 'reopen');
        assert.deepEqual(fresh.result.observation.journal, journal);
        assert.equal(fresh.result.replay.status, 'already-recorded');
        assert.deepEqual(await fresh.exited, [0, null]);
        assert.deepEqual(effects(root), ['forward:downstream', 'forward:upstream']);
    });

    test('SIGKILL after terminal artifact but before finish cannot certify or replay Apply', { timeout: 10000 }, async t => {
        const root = scratch(t), { worker, exited, result } = await child(t, root, 'after-terminal-proof');
        assert.deepEqual(result, { boundary: 'after-terminal-proof' });
        const journal = fileJournal(root).read(plan.scope);
        assert.equal(journal.pending, null);
        assert.equal(journal.status, 'interrupted');
        assert.equal(journal.terminalProof, null);
        assert.deepEqual(journal.confirmed.map(c => c.step), plan.steps);
        const trace = plan.steps.map(step => `forward:${step.id}`);
        assert.deepEqual(effects(root), trace);
        const original = fs.readFileSync(journalFile(root));
        assert(worker.kill('SIGKILL'));
        assert.deepEqual(await exited, [null, 'SIGKILL']);
        const fresh = await child(t, root, 'reopen');
        assert.deepEqual(fresh.result.observation.journal, journal);
        assert.equal(fresh.result.observation.retryAllowed, false);
        assert.equal(fresh.result.replay.status, 'already-recorded');
        assert.deepEqual(await fresh.exited, [0, null]);
        assert.deepEqual(effects(root), trace);
        assert.deepEqual(fs.readFileSync(journalFile(root)), original);
    });
}
