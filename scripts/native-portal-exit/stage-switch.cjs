'use strict';

// Private fixture only. The observation covers one live selector's rule tags
// and actions, not arbitrary predicates or the full runtime/boot state.
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const { createHash, randomBytes, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createFileCutoverJournal, createScopedCutoverExecutor } = require('/source/src/services/rebuildTransitCutoverJournal');
const { createCutoverArtifactStore } = require('/source/src/services/rebuildTransitCutoverArtifacts');

const [mode, port, pid, parentNet, binary] = process.argv.slice(2);
const read = fs.readFileSync;
const need = condition => { if (!condition) throw Error('fixture cutover refused'); };
const sha = data => createHash('sha256').update(data).digest('hex');
const json = file => JSON.parse(read(file));
const exercise = ['apply', 'rollback'].includes(mode);
const directory = exercise ? `/work/selector-${mode}-journal` : '/work/selector-journal';
const scope = 'fixture-gateway';
const files = { before: 'staged-routes.json', desired: 'desired-routes.json' };
const bootFile = 'gateway-main.json';
const keyPath = `${directory}/fixture.key`;

function call(executable, args) {
    const r = spawnSync(executable, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 3500 });
    need(!r.error && r.status === 0 && !r.stderr);
    return r.stdout;
}
function syncDir() {
    const fd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function publish(name, bytes) {
    const fd = fs.openSync(name, 'wx', 0o600);
    try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    syncDir();
    need(read(name).equals(bytes));
}
const api = (command, ...args) => call(binary, ['api', command, `--server=127.0.0.1:${port}`, ...args]);
const rules = view => json(files[view]).routing.rules.map(r => [r.ruleTag ?? '', r.outboundTag ?? '']);
const current = () => JSON.parse(api('lsrules')).rules.map(r => [r.ruleTag ?? '', r.tag ?? '']);

function boundGeneration() {
    const cmdline = read(`/proc/${pid}/cmdline`, 'utf8').split('\0');
    need(equal(cmdline, [binary, 'run', '-c', bootFile, '']) && fs.readlinkSync(`/proc/${pid}/exe`) === binary);
    const start = read(`/proc/${pid}/stat`, 'utf8').split(') ').at(-1).split(' ')[19];
    const sockets = call('/usr/bin/ss', ['-H', '-ltnp', `( sport = :${port} )`]).trim().split('\n');
    need(/^\d+(?![\s\S])/.test(start) && sockets.length === 1 && sockets[0].split(/\s+/)[3] === `127.0.0.1:${port}`
        && sockets[0].includes(`pid=${pid},`));
    return { pid, start, binary, port, boot: sha(read(bootFile)), before: sha(read(files.before)), desired: sha(read(files.desired)) };
}

async function main() {
    process.umask(0o077);
    const net = fs.readlinkSync('/proc/self/ns/net');
    const devices = read('/proc/net/dev', 'utf8').trimEnd().split('\n').slice(2).map(line => line.split(':')[0].trim());
    need((exercise || ['lost', 'observe'].includes(mode)) && process.cwd() === '/work' && !fs.existsSync('/etc/resolv.conf')
        && equal(devices, ['lo']) && /^net:\[\d+\](?![\s\S])/.test(parentNet) && net !== parentNet
        && /^(?:[1-9]\d{0,4})(?![\s\S])/.test(port) && Number(port) < 65536
        && /^[1-9]\d*(?![\s\S])/.test(pid) && Number(pid) > 1 && binary === '/tools/relay-xray');
    const bind = boundGeneration();
    const wire = exercise ? json('selector-wire.json') : null;
    if (wire) need(Number.isInteger(wire.port) && wire.port > 0 && wire.port < 65536
        && typeof wire.A === 'string' && typeof wire.B === 'string' && wire.A !== wire.B);
    const planDigest = sha(JSON.stringify({ ...bind, net, wire, ...(exercise && { mode }) }));
    need(!equal(rules('before'), rules('desired')));
    if (mode !== 'observe') {
        fs.mkdirSync(directory, { mode: 0o700 });
        // Ensure the journal root itself is durably linked before reserving it.
        const fd = fs.openSync('/work', fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
        try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
        publish(keyPath, randomBytes(32));
    }
    const journal = createFileCutoverJournal({ directory });
    const artifacts = createCutoverArtifactStore({ directory, key: read(keyPath) });
    const checkArtifact = (ctx, side) => need(artifacts.read(ctx, side, ctx.artifacts[side]).equals(read(files[side])));
    const live = () => ({ generation: boundGeneration(), rules: current() });
    const bytes = record => Buffer.from(JSON.stringify(record));
    const wireProofs = [];
    function probeWire(direction) {
        const path = `/proof-selector-${randomUUID()}`;
        const body = call('/usr/bin/curl', ['-q', '--silent', '--show-error', '--fail', '--max-time', '2',
            '--noproxy', '', '--socks5-hostname', `127.0.0.1:${wire.port}`, `http://127.0.0.42:18080${path}`]);
        const marker = ['A', 'B'].find(side => wire[side] === body);
        need(marker);
        const result = { direction, path, marker };
        wireProofs.push(result);
        return result;
    }
    const executor = createScopedCutoverExecutor({ journal, adapter: {
        verifyFence: ({ plan }) => plan.planDigest === planDigest && equal(boundGeneration(), bind),
        capture: ctx => ({ before: artifacts.seal(ctx, 'before', read(files.before)),
            desired: artifacts.seal(ctx, 'desired', read(files.desired)) }),
        async dispatch(ctx, submit) {
            need(mode === 'lost' || exercise);
            return submit(() => {
                checkArtifact(ctx, 'before');
                checkArtifact(ctx, 'desired');
                const rollback = ctx.direction === 'rollback';
                if (rollback) need(exercise && artifacts.read(ctx, 'confirmed', ctx.artifacts.confirmed).equals(bytes(live())));
                else need(equal(current(), rules('before')));
                api('adrules', files[rollback ? 'before' : 'desired']);
                if (exercise) return;
                // The real Xray action returned. The writer must die before
                // returning the handoff receipt or looking at live readback.
                process.kill(process.pid, 'SIGKILL');
            });
        },
        verify(ctx) {
            need(exercise);
            const observed = live();
            need(equal(observed.rules, rules(ctx.direction === 'forward' ? 'desired' : 'before')));
            return artifacts.seal(ctx, 'confirmed', bytes(observed));
        },
        prove: () => equal(current(), rules('before')), // Wire proofs were done by the parent.
        verifyTerminal(ctx) {
            need(exercise);
            const observed = live(), forward = ctx.direction === 'forward';
            const receipt = (forward ? ctx.confirmed : ctx.restored)[0];
            const pin = forward ? receipt.artifacts.confirmed : receipt.confirmed;
            need(artifacts.read({ ...ctx, step: receipt.step }, 'confirmed', pin).equals(bytes(observed)));
            const traffic = probeWire(ctx.direction);
            // The rollback drill deliberately requires the old wire marker even
            // after the switch. This is a known mismatch, not a lost response.
            if (traffic.marker !== (forward && mode === 'apply' ? 'B' : 'A')) return false;
            return artifacts.seal(ctx, 'confirmed', bytes({ observed, traffic }));
        },
        observe(state) {
            need(mode === 'observe' && state.pending?.direction === 'forward');
            const ctx = { plan: state.plan, ...state.pending };
            checkArtifact(ctx, 'before');
            checkArtifact(ctx, 'desired');
            const rows = current();
            return ['before', 'desired'].find(side => equal(rows, rules(side)))?.replace('desired', 'after') ?? 'mixed';
        },
    } });
    if (mode !== 'observe') {
        const result = await executor.execute({ scope, operationId: randomUUID(), fenceId: randomUUID(), planDigest,
            steps: [{ id: 'switch_ingress', phase: 'selector' }] });
        need(exercise && result.status === (mode === 'apply' ? 'applied' : 'rolled-back'));
        const state = journal.read(scope);
        need(state.version === 2 && state.status === result.status && state.terminalProof && state.pending === null);
        const direction = mode === 'apply' ? 'forward' : 'rollback';
        artifacts.read({ plan: state.plan, step: { id: `terminal-${direction}` } }, 'confirmed', state.terminalProof);
        process.stdout.write(JSON.stringify({ status: result.status, wireProofs }));
        return;
    }
    const result = await executor.reconcile(scope);
    need(result.journal?.pending?.step.id === 'switch_ingress' && result.journal.status === 'unknown'
        && result.journal.confirmed.length === 0 && result.journal.proved && result.retryAllowed === false);
    process.stdout.write(JSON.stringify({ observation: result.observation, retryAllowed: result.retryAllowed,
        pending: result.journal.pending.step.id, acknowledged: false, head: result.journal.head }));
}

main().catch(() => { process.stderr.write('selector fixture refused\n'); process.exitCode = 1; });
