'use strict';

// Private fixture only. The observation covers one live selector's rule tags
// and actions, not arbitrary predicates or the full runtime/boot state.
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const { createHash, createCipheriv, createDecipheriv, randomBytes, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createFileCutoverJournal, createScopedCutoverExecutor } = require('/source/src/services/rebuildTransitCutoverJournal');

const [mode, port, pid, parentNet, binary] = process.argv.slice(2);
const read = fs.readFileSync;
const need = condition => { if (!condition) throw Error('fixture cutover refused'); };
const sha = data => createHash('sha256').update(data).digest('hex');
const json = file => JSON.parse(read(file));
const directory = '/work/selector-journal';
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

function seal(ctx, side) {
    const id = randomUUID(), iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', read(keyPath), iv);
    c.setAAD(Buffer.from(`${ctx.plan.planDigest}:${ctx.plan.operationId}:${ctx.step.id}:${side}:${id}`));
    const ciphertext = Buffer.concat([c.update(read(files[side])), c.final()]);
    const packet = Buffer.concat([iv, c.getAuthTag(), ciphertext]);
    publish(`${directory}/${id}.sealed`, packet);
    return { id, sha256: sha(packet) };
}
function verifyArtifact(ctx, side) {
    const pin = ctx.artifacts[side], packet = read(`${directory}/${pin.id}.sealed`);
    need(sha(packet) === pin.sha256);
    const d = createDecipheriv('aes-256-gcm', read(keyPath), packet.subarray(0, 12));
    d.setAAD(Buffer.from(`${ctx.plan.planDigest}:${ctx.plan.operationId}:${ctx.step.id}:${side}:${pin.id}`));
    d.setAuthTag(packet.subarray(12, 28));
    need(Buffer.concat([d.update(packet.subarray(28)), d.final()]).equals(read(files[side])));
}

async function main() {
    process.umask(0o077);
    const net = fs.readlinkSync('/proc/self/ns/net');
    const devices = read('/proc/net/dev', 'utf8').trimEnd().split('\n').slice(2).map(line => line.split(':')[0].trim());
    need(['lost', 'observe'].includes(mode) && process.cwd() === '/work' && !fs.existsSync('/etc/resolv.conf')
        && equal(devices, ['lo']) && /^net:\[\d+\](?![\s\S])/.test(parentNet) && net !== parentNet
        && /^(?:[1-9]\d{0,4})(?![\s\S])/.test(port) && Number(port) < 65536
        && /^[1-9]\d*(?![\s\S])/.test(pid) && Number(pid) > 1 && binary === '/tools/relay-xray');
    const bind = boundGeneration();
    const planDigest = sha(JSON.stringify({ ...bind, net }));
    need(!equal(rules('before'), rules('desired')));
    if (mode === 'lost') {
        fs.mkdirSync(directory, { mode: 0o700 });
        // Ensure the journal root itself is durably linked before reserving it.
        const fd = fs.openSync('/work', fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
        try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
        publish(keyPath, randomBytes(32));
    }
    const journal = createFileCutoverJournal({ directory });
    const executor = createScopedCutoverExecutor({ journal, adapter: {
        verifyFence: ({ plan }) => plan.planDigest === planDigest && equal(boundGeneration(), bind),
        capture: ctx => ({ before: seal(ctx, 'before'), desired: seal(ctx, 'desired') }),
        async dispatch(ctx, submit) {
            need(mode === 'lost' && ctx.direction === 'forward');
            return submit(() => {
                verifyArtifact(ctx, 'before');
                verifyArtifact(ctx, 'desired');
                need(equal(current(), rules('before')));
                api('adrules', files.desired);
                // The real Xray action returned. The writer must die before
                // returning the handoff receipt or looking at live readback.
                process.kill(process.pid, 'SIGKILL');
            });
        },
        verify: () => { throw Error('lost reply fixture cannot verify the writer'); },
        prove: () => equal(current(), rules('before')), // Wire proofs were done by the parent.
        observe(state) {
            need(mode === 'observe' && state.pending?.direction === 'forward');
            const ctx = { plan: state.plan, ...state.pending };
            verifyArtifact(ctx, 'before');
            verifyArtifact(ctx, 'desired');
            const rows = current();
            return ['before', 'desired'].find(side => equal(rows, rules(side)))?.replace('desired', 'after') ?? 'mixed';
        },
    } });
    if (mode === 'lost') {
        // Success means this process never produces a reply.
        await executor.execute({ scope, operationId: randomUUID(), fenceId: randomUUID(), planDigest,
            steps: [{ id: 'switch_ingress', phase: 'selector' }] });
        throw Error('writer unexpectedly survived');
    }
    const result = await executor.reconcile(scope);
    need(result.journal?.pending?.step.id === 'switch_ingress' && result.journal.status === 'unknown'
        && result.journal.confirmed.length === 0 && result.journal.proved && result.retryAllowed === false);
    process.stdout.write(JSON.stringify({ observation: result.observation, retryAllowed: result.retryAllowed,
        pending: result.journal.pending.step.id, acknowledged: false, head: result.journal.head }));
}

main().catch(() => { process.stderr.write('selector fixture refused\n'); process.exitCode = 1; });
