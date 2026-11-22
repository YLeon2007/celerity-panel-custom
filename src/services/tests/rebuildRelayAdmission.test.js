'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { spawnSync } = require('node:child_process');
const { createRebuildRelayAdmission } = require('../rebuildRelayAdmission');
const { makeLocks, withNode } = require('../rebuildLocks');
const { normalizeRelayBinding } = require('../rebuildRelayAuthorization');

const nodeId = 'a'.repeat(24), pin = 'b'.repeat(64), machine = 'c'.repeat(32);
const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true' };
const conflict = { code: 'REBUILD_L2TP_GRANT_CONFLICT' };
const changed = { code: 'REBUILD_L2TP_IDENTITY_CHANGED' };
const invalid = { code: 'REBUILD_L2TP_ADMISSION_CHALLENGE_INVALID' };
const endpoint = { nodeId, host: 'relay.example', port: 2222, username: 'root' };
const binding = { ...endpoint, machineId: machine, sshHostKeySha256: pin };
const card = { _id: nodeId, active: true, type: 'xray', cascadeRole: 'relay', ip: 'Relay.Example.',
    ssh: { port: 2222, username: 'root', password: 'fixture-only' }, privateValue: 'never public' };
const clear = { states: [], accounts: null, operation: null, admission: null, operationLock: null };

function fixture(options = {}) {
    const f = { node: structuredClone(card), row: null, calls: [], writes: [], audits: [], now: 0 };
    let lock;
    const locks = makeLocks({
        async insertOne(row) {
            if (lock) throw Object.assign(new Error(), { code: 11000 });
            lock = row;
        },
        async findOne({ token }) { return lock?.token === token ? lock : null; },
        async deleteMany({ token }) {
            assert.equal(token, lock?.token);
            lock = null;
            return { acknowledged: !f.loseRelease, deletedCount: 1 };
        },
    });
    f.locks = locks;
    const store = {
        async snapshot() {
            if (f.snapshotError) throw f.snapshotError;
            const row = f.row && { ...f.row };
            const source = f.source ?? (row ? 'db' : null);
            return { env, grants: row ? [row] : [], sourceFor: () => source };
        },
        async mutate(input) {
            assert.ok(lock);
            assert.equal(input.expectedGeneration, f.row?.generation ?? null);
            f.writes.push(input);
            if (f.writeError) throw f.writeError;
            f.row = input.action === 'revoke' ? null : { ...input.binding, generation: 'generation-' + f.writes.length };
            return { privateValue: 'never public' };
        },
        async audit(input) { f.audits.push(input); },
    };
    const probe = {
        async probeKey(node) {
            assert.equal(node.ip, endpoint.host);
            assert.ok(!Object.hasOwn(node.ssh, 'password'));
            f.calls.push('key');
            return f.pin ?? pin;
        },
        async readMachine(node, expectedPin) {
            assert.equal(node.ip, endpoint.host);
            assert.equal(node.ssh.password, 'fixture-only');
            f.calls.push('machine');
            if (f.pin && f.pin !== expectedPin) throw Object.assign(new Error('private stderr'), changed);
            await f.onMachine?.();
            return f.machine ?? machine;
        },
    };
    const service = createRebuildRelayAdmission({ db: {}, env, store, probe, locks,
        // The sibling store slice owns the shared validator. This focused
        // fixture also runs on the detached baseline without that slice.
        normalizeBinding: normalizeRelayBinding ?? (row => ({ ...row, host: row.host.toLowerCase().replace(/\.$/, '') })),
        loadNode: async () => structuredClone(f.node),
        assertNoPending: async () => {
            assert.ok(lock);
            if (f.pending) throw Object.assign(new Error(), { code: 'REBUILD_L2TP_ACCOUNTS_BLOCKED' });
        },
        readFootprint: async () => { assert.ok(lock); return structuredClone(f.footprint ?? clear); },
        witnessAbsent: async (_node, b) => {
            assert.ok(lock);
            assert.deepEqual(b, binding);
            f.calls.push('absence');
            await f.onWitness?.();
            return Object.hasOwn(f, 'absence') ? f.absence : true;
        },
        clock: () => f.now, ...options });
    f.perform = (action, challenge, more) => service.perform({ action, nodeId, actor: 'operator', sessionId: 'session-secret',
        ...(challenge !== undefined && { challenge }), ...more });
    f.approve = async () => f.perform('verify', (await f.perform('probe')).challenge);
    return f;
}

test('probe is credential-free; verify and confirm both read pinned identity and only confirm writes', async () => {
    const f = fixture();
    const first = await f.perform('probe');
    assert.deepEqual(first, { ...endpoint, sshHostKeySha256: pin, challenge: first.challenge });
    assert.deepEqual(f.calls, ['key']);
    const verified = await f.perform('verify', first.challenge);
    assert.deepEqual(verified, { ...binding, challenge: verified.challenge });
    assert.notEqual(verified.challenge, first.challenge);
    assert.deepEqual(f.writes, []);
    assert.deepEqual(await f.perform('confirm', verified.challenge, { ...binding, machineId: 'f'.repeat(32) }),
        { ...binding, source: 'db' });
    assert.deepEqual(f.calls, ['key', 'machine', 'machine']);
    assert.deepEqual(f.writes, [{ action: 'grant', binding, expectedGeneration: null, actor: 'operator' }]);
    assert.deepEqual(f.audits.map(x => [x.action, x.outcome]), [['probe', 'success'], ['verify', 'success']]);
    assert.ok(f.audits.every(x => JSON.stringify(x).indexOf('session-secret') < 0));
});

test('phase, actor, session and node scope are checked before any further SSH; concurrent use wins once', async () => {
    const f = fixture();
    const { challenge } = await f.perform('probe');
    await assert.rejects(f.perform('confirm', challenge), invalid);
    for (const other of [{ actor: 'other' }, { sessionId: 'other' }, { nodeId: 'e'.repeat(24) }]) {
        await assert.rejects(f.perform('verify', challenge, other), invalid);
    }
    assert.deepEqual(f.calls, ['key']);
    const [a, b] = await Promise.allSettled([f.perform('verify', challenge), f.perform('verify', challenge)]);
    assert.equal(a.status, 'fulfilled');
    assert.equal(b.reason.code, invalid.code);
    await f.perform('confirm', a.value.challenge);
    await assert.rejects(f.perform('confirm', a.value.challenge), invalid);
    assert.equal(f.writes.length, 1);
});

test('challenges expire at the boundary and confirmation cannot write after a slow observation', async () => {
    const f = fixture({ ttlMs: 50, maxChallenges: 2 });
    const { challenge } = await f.perform('probe');
    f.now = 50;
    await assert.rejects(f.perform('verify', challenge), invalid);
    const { challenge: confirmed } = await f.approve();
    f.onMachine = () => { f.now = 100; };
    await assert.rejects(f.perform('confirm', confirmed), invalid);
    assert.deepEqual(f.writes, []);
});

test('both phases reject card drift and generation changes; changed key or machine is not availability failure', async () => {
    for (const mutate of [f => { f.node.ssh.port++; }, f => { f.node.cascadeRole = 'bridge'; }, f => { f.pin = 'a'.repeat(64); }]) {
        const f = fixture();
        const { challenge } = await f.perform('probe');
        mutate(f);
        await assert.rejects(f.perform('verify', challenge), changed);
        await assert.rejects(f.perform('verify', challenge), invalid);
        assert.deepEqual(f.writes, []);
    }
    for (const mutate of [f => { f.machine = 'd'.repeat(32); }, f => { f.onMachine = () => { f.node.active = false; }; }]) {
        const f = fixture();
        const { challenge } = await f.approve();
        mutate(f);
        await assert.rejects(f.perform('confirm', challenge), changed);
        assert.deepEqual(f.writes, []);
    }
    const f = fixture();
    f.row = { ...binding, generation: 'before' };
    const { challenge } = await f.approve();
    f.row.generation = 'after';
    await assert.rejects(f.perform('confirm', challenge), conflict);
    assert.deepEqual(f.writes, []);
});

test('ENV is read only; DB reconfirm uses exact old generation without modifying ownership', async () => {
    const f = fixture();
    f.source = 'env';
    await assert.rejects(f.perform('probe'), conflict);
    await assert.rejects(f.perform('revoke'), conflict);
    assert.deepEqual(f.calls, []);
    f.source = 'db';
    f.row = { ...binding, generation: 'previous' };
    const state = { node: nodeId, status: 'installed', desiredState: 'installed', rebuildMachineId: machine };
    f.footprint = { states: [state], accounts: { _id: 'account' }, operation: null, admission: null, operationLock: null };
    await f.perform('confirm', (await f.approve()).challenge);
    assert.deepEqual(f.writes, [{ action: 'reconfirm', binding, expectedGeneration: 'previous', actor: 'operator' }]);
    f.machine = 'd'.repeat(32);
    await assert.rejects(f.perform('confirm', (await f.approve()).challenge), conflict);
    assert.equal(f.writes.length, 1);
    assert.equal(state.rebuildMachineId, machine);
});

test('revoke requires a current strict host witness under Apply exclusion and pending fences survive', async () => {
    const f = fixture();
    f.row = { ...binding, generation: 'previous' };
    f.pending = true;
    await assert.rejects(f.perform('revoke'), { code: 'REBUILD_L2TP_ACCOUNTS_BLOCKED' });
    assert.deepEqual(f.calls, []);
    f.pending = false;
    for (const value of [undefined, null, false, 'absent']) {
        f.absence = value;
        await assert.rejects(f.perform('revoke'), conflict);
    }
    f.absence = true;
    f.onWitness = () => assert.rejects(f.locks.run(() => assert.fail('Apply entered')), { code: 'REBUILD_BUSY' });
    assert.deepEqual(await f.perform('revoke'), { nodeId, source: null });
    assert.deepEqual(f.writes, [{ action: 'revoke', binding, expectedGeneration: 'previous', actor: 'operator' }]);
});

test('revoke rejects contradictory DB inventory before reading an uninstalled witness', async () => {
    for (const patch of [{ states: [{ node: nodeId, status: 'not_installed', desiredState: 'absent', backupId: 'receipt' }] },
        { states: [{ node: nodeId, status: 'unknown', desiredState: 'absent' }] }, { accounts: {} }, { operation: {} },
        { admission: {} }, { operationLock: {} }, { accounts: undefined }]) {
        const f = fixture();
        f.row = { ...binding, generation: 'previous' };
        f.footprint = { ...clear, ...patch };
        await assert.rejects(f.perform('revoke'), conflict);
        assert.deepEqual(f.calls, []);
        assert.deepEqual(f.writes, []);
    }
});

test('bounded challenge storage frees expired slots', async () => {
    const f = fixture({ ttlMs: 10, maxChallenges: 1 });
    const { challenge } = await f.perform('probe');
    await assert.rejects(f.perform('probe'), { code: 'REBUILD_L2TP_ADMISSION_UNAVAILABLE' });
    assert.equal(f.audits.at(-1).outcome, 'denied');
    f.now = 10;
    const next = await f.perform('probe');
    await assert.rejects(f.perform('verify', challenge), invalid);
    await f.perform('verify', next.challenge);
});

test('the real node lock holds confirm behind an earlier writer until its ticket expires', async () => {
    const f = fixture({ ttlMs: 10 });
    const { challenge } = await f.approve();
    let entered, release;
    const holding = new Promise(resolve => { entered = resolve; });
    const hold = withNode(nodeId, () => new Promise(resolve => { release = resolve; entered(); }));
    await holding;
    const request = f.perform('confirm', challenge);
    try {
        await new Promise(setImmediate);
        assert.deepEqual(f.calls, ['key', 'machine']);
        assert.deepEqual(f.writes, []);
        f.now = 10;
    } finally { release(); }
    await hold;
    await assert.rejects(request, invalid);
    assert.deepEqual(f.writes, []);
});

test('revoke rechecks footprint, endpoint and generation after the host witness', async () => {
    for (const [hook, error] of [[f => { f.footprint = { ...clear, accounts: {} }; }, conflict],
        [f => { f.node.ip = 'replacement.example'; }, changed],
        [f => { f.row.generation = 'other'; }, conflict]]) {
        const f = fixture();
        f.row = { ...binding, generation: 'previous' };
        f.onWitness = () => hook(f);
        await assert.rejects(f.perform('revoke'), error);
        assert.deepEqual(f.calls, ['absence']);
        assert.deepEqual(f.writes, []);
    }
});

test('store conflicts disclose only the safe detail; unknown writes never replay or report success', async () => {
    for (const [input, expected, auditOutcome] of [
        [{ code: conflict.code, field: 'endpoint' }, { ...conflict, detail: 'endpoint', outcome: 'refused' }, 'denied'],
        [{ code: 'REBUILD_L2TP_GRANT_CHANGED' }, { ...conflict, detail: 'grant-changed', outcome: 'refused' }, 'denied'],
        [{ code: 'REBUILD_L2TP_GRANT_OUTCOME_UNKNOWN', detail: 'private fixture' },
            { code: 'REBUILD_L2TP_GRANT_OUTCOME_UNKNOWN', outcome: 'unknown', retryAllowed: false }, 'unknown'],
    ]) {
        const f = fixture();
        f.writeError = Object.assign(new Error('private fixture'), input);
        const { challenge } = await f.approve();
        await assert.rejects(f.perform('confirm', challenge), error => {
            assert.equal(error.message, expected.code);
            for (const [key, value] of Object.entries(expected)) assert.equal(error[key], value);
            assert.ok(!JSON.stringify(error).includes('private fixture'));
            return true;
        });
        assert.deepEqual(f.audits.at(-1), { action: 'confirm', nodeId, actor: 'operator', outcome: auditOutcome, code: expected.code });
        await assert.rejects(f.perform('confirm', challenge), invalid);
        assert.equal(f.writes.length, 1);
    }
});

// Run the emitted Python observer with all external observations replaced.
// No fixture invokes systemctl, ip, nft, SSH, or reads real host state.
const hostModel = String.raw`import contextlib, io, json, stat, sys, types
code = sys.stdin.read()
body, tail = code.rsplit("\ntry:\n    observe()", 1)
assert tail == "\nexcept Exception:\n    sys.exit(1)\n"
g = {}
exec(compile(body, "<witness>", "exec"), g)
machine = b"c" * 32 + b"\n"
fixture = {
    "/etc/machine-id": machine,
    "/proc/net/udp": b"sl local_address rem_address\n",
    "/proc/net/udp6": b"sl local_address remote_address\n",
    "/proc/net/dev": b"header\nheader\nlo: 0\n",
}
system = "/etc/systemd/system"
vault = "/var/lib/celerity-rebuild-l2tp-direct"
token = "e" * 32
prefix = vault + "/" + token
receipt = json.dumps({"phase": "installed-chap-v2:" + token, "backupId": token, "machineId": machine.strip().decode()}).encode()
attempt = json.dumps({"baseline": "f" * 64}).encode()
clean_outputs = {
    ("-j", "list", "tables"): b'{"nftables": [{"metainfo": {} }]}',
    ("-j", "-4", "rule", "show"): b'[{"priority":0},{"priority":32766},{"priority":32767}]',
    ("-j", "-4", "route", "show", "table", "all"): b'[{"type":"local", "dst":"127.0.0.1"}]',
    ("xfrm", "policy", "list"): b"",
    ("xfrm", "state", "list", "nokeys"): b"",
}
inode = types.SimpleNamespace(st_ino=11, st_dev=7, st_uid=0, st_mode=stat.S_IFDIR | 0o700)
def exercise(good, files=None, outputs=None, record=False, unavailable=False, active=False):
    data = fixture | (files or {})
    values = clean_outputs | (outputs or {})
    released = []
    def lstat(path):
        if path == vault and prefix + "/manifest.json" in data:
            return inode
        if path in data:
            return object()
        raise FileNotFoundError()
    def open_dir(path, flags):
        assert path == system and not flags & (1 | 2 | 64)
        return 88
    def read(path, limit):
        assert len(data[path]) <= limit
        return data[path]
    def command(program, *args, codes=(0,)):
        if program == "/usr/bin/systemctl":
            state = b"active" if active else b"inactive"
            return 1, b"LoadState=not-found\nActiveState=" + state + b"\nSubState=dead\nJob=\n"
        if unavailable and args == ("-j", "list", "tables"):
            raise OSError()
        return 0, values[args]
    g["os"] = types.SimpleNamespace(geteuid=lambda: 0, open=open_dir, O_RDONLY=0, O_DIRECTORY=65536,
        O_NOFOLLOW=131072, lstat=lstat, scandir=lambda path: contextlib.nullcontext([
            types.SimpleNamespace(name=token, path=prefix, is_dir=lambda **kw: not kw["follow_symlinks"])]),
        stat=lambda path, **kw: inode, fstat=lambda fd: inode, close=released.append)
    g["fcntl"] = types.SimpleNamespace(flock=lambda fd, flags: None, LOCK_SH=1, LOCK_NB=4)
    g["sys"] = types.SimpleNamespace(argv=["-c", "recorded-absent" if record else "no-record"])
    g.update(read=read, command=command)
    result = io.StringIO()
    with contextlib.redirect_stdout(result):
        try:
            g["observe"]()
        except (ValueError, KeyError, OSError):
            assert not good
        else:
            assert good
    assert released == [88]
    assert result.getvalue() == ("absent:" + machine.decode() if good else "")
exercise(True)
exercise(True, {prefix + "/manifest.json": receipt, prefix + "/remove-attempt.json": attempt}, record=True)
exercise(False, {prefix + "/manifest.json": receipt, prefix + "/remove-attempt.json": attempt})
exercise(False, {prefix + "/manifest.json": receipt}, record=True)
exercise(False, {system + "/xl2tpd.service.d": b""})
exercise(False, {"/etc/ppp/chap-secrets": b"# BEGIN CELERITY MANAGED L2TP USERS"})
exercise(False, {"/proc/net/udp": b"sl local_address rem_address\n0: 00000000:06A5 0000:0\n"})
exercise(False, outputs={("-j", "list", "tables"): b'{"nftables":[{"table":{"name":"celerity_rebuild_l2tp"}}]}'})
exercise(False, outputs={("-j", "-4", "route", "show", "table", "all"): b'[{"type":"local","dst":"default"}]'})
exercise(False, outputs={("xfrm", "policy", "list"): b"nonempty"})
exercise(False, unavailable=True)
exercise(False, active=True)
`;

test('the default revoke witness uses one pinned read-only SSH command and demands an exact receipt', async () => {
    let response, closes = 0;
    const commands = [];
    class SSH {
        constructor(node, options) {
            assert.equal(node.ssh.password, 'fixture-only');
            assert.deepEqual(options, { expectedHostKeySha256: pin, expectedEndpoint: { ip: endpoint.host, port: 2222, username: 'root' } });
        }
        async connectDirectOnce(ms) { assert.equal(ms, 5000); assert.equal(this.usePool, false); }
        async exec(command, options) {
            assert.deepEqual(options, { timeout: 17000 });
            const match = /^\/usr\/bin\/timeout -k 1s 15s \/usr\/bin\/python3 -I -B -c '([^']+)' (no-record|recorded-absent)(?![\s\S])/.exec(command);
            assert.ok(match);
            assert.ok(!command.includes(endpoint.host) && !command.includes(pin) && !command.includes('fixture-only'));
            commands.push(match[2]);
            if (commands.length === 1) {
                const result = spawnSync('python3', ['-I', '-B', '-c', hostModel],
                    { input: match[1], encoding: 'utf8', timeout: 5000 });
                assert.equal(result.status, 0, result.stderr);
            }
            return response;
        }
        disconnect() { closes++; }
    }
    const f = fixture({ witnessAbsent: undefined, SSH });
    f.row = { ...binding, generation: 'previous' };
    const receipt = { code: 0, stderr: '', stdout: `absent:${machine}\n` };
    for (const overrides of [{ code: 1 }, { stderr: 'private fixture' }, { stdout: `absent:${machine}\n\n` }]) {
        response = { ...receipt, ...overrides };
        await assert.rejects(f.perform('revoke'), conflict);
    }
    response = { ...receipt, stdout: `absent:${'d'.repeat(32)}\n` };
    await assert.rejects(f.perform('revoke'), changed);
    f.footprint = { ...clear, states: [{ node: nodeId, status: 'not_installed', desiredState: 'absent', replacementFence: 2 }] };
    response = receipt;
    await f.perform('revoke');
    assert.deepEqual(commands, ['no-record', 'no-record', 'no-record', 'no-record', 'recorded-absent']);
    assert.equal(closes, commands.length);
    assert.equal(f.writes.length, 1);
});

test('lock-release uncertainty after acknowledged mutation is not reported as refusal or replayed', async () => {
    const f = fixture();
    const { challenge } = await f.approve();
    f.loseRelease = true;
    await assert.rejects(f.perform('confirm', challenge), { code: 'REBUILD_LOCK_RELEASE_UNCONFIRMED', outcome: 'applied' });
    assert.equal(f.writes.length, 1);
    assert.equal(f.audits.length, 2);
    await assert.rejects(f.perform('confirm', challenge), invalid);
    assert.equal(f.writes.length, 1);
});
