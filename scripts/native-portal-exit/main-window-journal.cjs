'use strict';

// Private native fixture, not an SSH receiver or an Apply entrypoint.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const { createHash, randomBytes, randomUUID } = require('node:crypto');
const { createFileCutoverJournal, createScopedCutoverExecutor } = require('/src/services/rebuildTransitCutoverJournal');
const { createCutoverArtifactStore } = require('/src/services/rebuildTransitCutoverArtifacts');

const bytes = value => Buffer.from(JSON.stringify(value));
const sha = value => createHash('sha256').update(value).digest('hex');
const phases = ['agent-stop', 'main-publication', 'xray-restart', 'agent-start', 'agent-reconcile'];
const directory = '/work/cutover';
const scope = 'native-agent-window';
const emit = frame => {
    const data = Buffer.concat([bytes(frame), Buffer.from('\n')]);
    assert(data.length < 16384 && fs.writeSync(1, data) === data.length);
};
function request(action, fields = {}) {
    emit({ action, ...fields });
    const buf = Buffer.alloc(16384);
    for (let n = 0; n < buf.length; n++) {
        assert.equal(fs.readSync(0, buf, n, 1, null), 1);
        if (buf[n] !== 10) continue;
        const reply = JSON.parse(buf.subarray(0, n));
        assert(reply.ok === true);
        return reply.value;
    }
    throw Error('oversize fixture frame');
}
function syncDir(path) {
    const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

async function main() {
    process.umask(0o077);
    const ns = fs.readlinkSync('/proc/self/ns/net');
    assert.equal(process.cwd(), '/work');
    assert(/^net:\[\d+\]$/.test(process.env.C3_CUTOVER_PARENT_NETNS ?? '') && ns !== process.env.C3_CUTOVER_PARENT_NETNS);
    assert.deepEqual(fs.readFileSync('/proc/net/dev', 'utf8').trimEnd().split('\n').slice(2)
        .map(line => line.split(':')[0].trim()), ['lo']);
    assert(!fs.existsSync('/etc/resolv.conf') && !fs.existsSync('/run/systemd/private'));
    const mode = process.argv[2];
    assert(['rollback', 'timeout'].includes(mode));
    fs.mkdirSync(directory, { mode: 0o700 });
    syncDir('/work');
    const key = randomBytes(32);
    const journal = createFileCutoverJournal({ directory });
    const artifacts = createCutoverArtifactStore({ directory, key });
    const manifest = request('manifest');
    const step = { id: 'main-window', phase: 'selector', window: 'main-agent' };
    const plan = { scope, operationId: randomUUID(), fenceId: randomUUID(),
        planDigest: sha(bytes([ns, mode, manifest, step])), steps: [step] };
    const snapshot = (ctx, side) => JSON.parse(artifacts.read(ctx, side, ctx.artifacts[side]));
    const pubSide = (ctx, side) => `publication-${ctx.direction}-${side}`;
    const publication = (ctx, side) => JSON.parse(artifacts.read(ctx, pubSide(ctx, side), ctx.publication[side]));
    const executor = createScopedCutoverExecutor({ journal, adapter: {
        verifyFence: ctx => ctx.plan.planDigest === plan.planDigest,
        prove: () => true,
        capture(ctx) {
            assert.deepEqual(request('capture'), manifest.before);
            return { before: artifacts.seal(ctx, 'before', bytes(manifest.before)),
                desired: artifacts.seal(ctx, 'desired', bytes(manifest.desired)) };
        },
        captureMainPublication(ctx) {
            const restore = ctx.direction === 'rollback';
            const original = restore ? ctx.history.confirmed.at(-1) : null;
            const expected = restore ? JSON.parse(artifacts.read(ctx, 'confirmed', original.artifacts.confirmed)) : snapshot(ctx, 'before');
            const target = restore ? publication({ ...ctx, direction: 'forward', publication: original.publication }, 'before') : snapshot(ctx, 'desired');
            const { before, desired } = request('drained-capture', { direction: ctx.direction, expected, target });
            assert.equal(before.topology, expected.topology);
            assert.equal(desired.topology, target.topology);
            return { before: artifacts.seal(ctx, pubSide(ctx, 'before'), bytes(before)),
                desired: artifacts.seal(ctx, pubSide(ctx, 'desired'), bytes(desired)) };
        },
        dispatch(ctx, submit) {
            return submit(async checkpoint => {
                let prev = null;
                for (const phase of phases) prev = await checkpoint(phase, prev, current => {
                    const state = journal.read(scope);
                    assert.equal(state.pending.checkpoint, phase);
                    assert.equal(state.pending.direction, ctx.direction);
                    const images = phase === 'main-publication' ? { before: publication(current, 'before'), desired: publication(current, 'desired') } : {};
                    return request(phase, { direction: ctx.direction, ...images });
                });
                return prev;
            });
        },
        verify(ctx, result) {
            assert.deepEqual(request('verify', { direction: ctx.direction }), result);
            const target = publication(ctx, 'desired');
            const before = publication(ctx, 'before');
            assert.equal(result.topology, target.topology);
            assert.notEqual(result.pid, before.pid);
            assert.notEqual(result.file.ino, before.file.ino);
            return artifacts.seal(ctx, 'confirmed', bytes(result));
        },
        verifyTerminal(ctx) {
            const result = request('terminal', { direction: ctx.direction });
            if (ctx.direction === 'forward') return false; // deliberate terminal-origin veto for the inverse drill
            assert.equal(result.topology, manifest.before.topology);
            return artifacts.seal(ctx, 'confirmed', bytes(result));
        },
        observe: () => request('observe'),
    } });
    const result = await executor.execute(plan);
    assert.equal(result.retryAllowed, false);
    if (mode === 'timeout') {
        assert.equal(result.status, 'unknown');
        const observed = await executor.reconcile(scope);
        assert.equal(observed.observation, 'before');
        assert.equal(observed.journal.pending.checkpoint, 'agent-stop');
        assert.equal(observed.journal.confirmed.length, 0);
        assert.equal(observed.retryAllowed, false);
        assert.equal((await executor.execute(plan)).status, 'already-recorded');
    } else {
        const state = journal.read(scope);
        assert.equal(state.status, 'rolled-back');
        assert.equal(state.version, 3);
        assert.equal(state.confirmed.length, 1);
        assert.equal(state.restored.length, 1);
        assert(state.terminalProof && !state.pending);
    }
    emit({ action: 'done', status: result.status });
}
main().catch(err => {
    // Test diagnostics must not include IPC frames (fixture images have clients).
    process.stderr.write(`native MAIN journal refused (${err.code ?? err.name})\n`);
    process.exitCode = 1;
});
