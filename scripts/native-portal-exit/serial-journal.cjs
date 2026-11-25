'use strict';

// Only the private native fixture may drive this entry. The parent owns the
// Xray children, boot files and test traffic; stdin is its dedicated reply pipe.
const fs = require('node:fs');
const { createHash, randomBytes, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createFileCutoverJournal, createScopedCutoverExecutor } = require('/source/src/services/rebuildTransitCutoverJournal');
const { createCutoverArtifactStore } = require('/source/src/services/rebuildTransitCutoverArtifacts');

const need = value => { if (!value) throw Error('serial cutover fixture refused'); };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const bytes = value => Buffer.from(JSON.stringify(value));
const emit = value => {
    const frame = Buffer.from(JSON.stringify(value) + '\n');
    need(frame.length <= 4096 && fs.writeSync(1, frame) === frame.length);
};
function request(action, body = {}) {
    emit({ action, ...body });
    const buffer = Buffer.alloc(16384);
    let size = 0;
    while (size < buffer.length) {
        const n = fs.readSync(0, buffer, size, buffer.length - size, null);
        need(n > 0);
        size += n;
        if (buffer[size - 1] === 10) return JSON.parse(buffer.subarray(0, size));
    }
    throw Error('fixture reply too large');
}
function syncDir(path) {
    const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function prepareStore(directory) {
    fs.mkdirSync(directory, { mode: 0o700 });
    syncDir('/work');
    const file = `${directory}/fixture.key`;
    const key = randomBytes(32);
    const fd = fs.openSync(file, 'wx', 0o600);
    try { fs.writeFileSync(fd, key); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    syncDir(directory);
    const read = fs.readFileSync(file);
    need(key.equals(read));
    return read;
}

async function main() {
    process.umask(0o077);
    const [mode, parentNet] = process.argv.slice(2);
    const net = fs.readlinkSync('/proc/self/ns/net');
    const devices = fs.readFileSync('/proc/net/dev', 'utf8').trimEnd().split('\n').slice(2).map(row => row.split(':')[0].trim());
    need(process.cwd() === '/work' && !fs.existsSync('/etc/resolv.conf') && equal(devices, ['lo'])
        && /^net:\[\d+\](?![\s\S])/.test(parentNet) && net !== parentNet && ['apply', 'rollback'].includes(mode));
    const manifest = request('manifest');
    const { steps, initial } = manifest;
    need(steps.every(({ id, owner }) => /^[a-z]+-[1-9][0-9]*(?![\s\S])/.test(id)
        && /^[a-z][a-z0-9]*(?![\s\S])/.test(owner) && Object.hasOwn(initial, owner)));
    const entries = new Map(steps.map(step => [step.id, step]));
    const images = (step, side) => {
        const { owner, id } = step;
        const image = fs.readFileSync(`${owner}-serial-${id}-${side}.json`);
        need(sha(image) === step[side]);
        return image;
    };
    const scope = 'fixture-serial-main';
    const directory = `/work/serial-${mode}-journal`;
    const key = prepareStore(directory);
    const journal = createFileCutoverJournal({ directory });
    const artifacts = createCutoverArtifactStore({ directory, key });
    const plan = { scope, operationId: randomUUID(), fenceId: randomUUID(),
        planDigest: sha(bytes({ net, mode, manifest })), steps: steps.map(({ id, phase }) => ({ id, phase })) };
    const ack = (ctx, owner) => {
        // A later inverse on this owner may have recreated its boot bytes
        // under a new PID and inode. Use that newly ACKed generation for CAS.
        const matches = row => entries.get(row.step.id).owner === owner;
        const inverse = ctx.history.restored.findLast(matches);
        const latest = inverse ?? ctx.history.confirmed.findLast(matches);
        return latest ? JSON.parse(artifacts.read({ ...ctx, step: latest.step }, 'confirmed',
            inverse ? inverse.confirmed : latest.artifacts.confirmed)) : initial[owner];
    };
    const snapshot = owner => request('snapshot', { owner });
    const readImage = (ctx, step, side, artifact) => {
        const image = artifacts.read(ctx, artifact, ctx.artifacts[artifact]);
        need(image.equals(images(step, side)));
        return image;
    };
    const executor = createScopedCutoverExecutor({ journal, adapter: {
        verifyFence: ({ plan: candidate }) => equal(candidate, plan) && request('fence') === true,
        capture(ctx) {
            const step = entries.get(ctx.step.id);
            const before = snapshot(step.owner);
            need(equal(before, ack(ctx, step.owner)) && before.boot === step.before);
            return { before: artifacts.seal(ctx, 'before', images(step, 'before')),
                desired: artifacts.seal(ctx, 'desired', images(step, 'after')) };
        },
        dispatch(ctx, submit) {
            const step = entries.get(ctx.step.id), forward = ctx.direction === 'forward';
            const from = readImage(ctx, step, forward ? 'before' : 'after', forward ? 'before' : 'desired');
            const to = readImage(ctx, step, forward ? 'after' : 'before', forward ? 'desired' : 'before');
            const before = ack(ctx, step.owner);
            need(before.boot === sha(from) && equal(snapshot(step.owner), before));
            return submit(() => {
                need(request('restart', { id: step.id, direction: ctx.direction, before, target: sha(to) }) === true);
                return before;
            });
        },
        verify(ctx, before) {
            const step = entries.get(ctx.step.id), after = snapshot(step.owner);
            need(after.boot === (ctx.direction === 'forward' ? step.after : step.before)
                && after.pid !== before.pid && after.ino !== before.ino && after.binary === before.binary
                && after.mode === before.mode && after.uid === before.uid && after.gid === before.gid);
            return artifacts.seal(ctx, 'confirmed', bytes(after));
        },
        prove: () => request('prepared') === true,
        verifyTerminal(ctx) {
            for (const owner of Object.keys(initial)) {
                need(equal(snapshot(owner), ack({ ...ctx, history: ctx }, owner)));
            }
            const terminal = request('terminal', { direction: ctx.direction });
            if (mode === 'rollback' && ctx.direction === 'forward') {
                // An explicit wrong-origin criterion for the rollback drill.
                need(equal(terminal.map(row => row.actual), ['B', 'A']));
                return false;
            }
            need(terminal.length > 0 && terminal.every(row => row.actual === row.expected));
            return artifacts.seal(ctx, 'confirmed', bytes(terminal));
        },
        observe: () => 'unavailable',
    } });
    const result = await executor.execute(plan);
    need(result.status === (mode === 'apply' ? 'applied' : 'rolled-back'));
    const state = journal.read(scope);
    need(state?.status === result.status && state.confirmed.length === steps.length && !state.pending
        && state.restored.length === (mode === 'rollback' ? steps.length : 0));
    const step = { id: `terminal-${mode === 'rollback' ? 'rollback' : 'forward'}` };
    artifacts.read({ plan, step }, 'confirmed', state.terminalProof);
    emit({ action: 'done', status: state.status, confirmed: state.confirmed.length, restored: state.restored.length, head: state.head });
}

main().catch(() => { process.stderr.write('serial cutover fixture refused\n'); process.exitCode = 1; });
