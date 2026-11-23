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
const sshHostKeyType = 'ssh-ed25519';
const card = { _id: nodeId, active: true, type: 'xray', cascadeRole: 'relay', ip: 'Relay.Example.',
    ssh: { port: 2222, username: 'root', password: 'fixture-only' }, privateValue: 'never public' };
const clear = { states: [], accounts: null, operation: null, admission: null, operationLock: null };
const installed = { _id: 'fixture-state', node: nodeId, status: 'installed', desiredState: 'installed',
    routingMode: 'follow-relay', routingVersion: 1, secretRevision: 1, rebuildMachineId: machine,
    rebuildInstallToken: '00000000-0000-4000-8000-000000000001', backupId: 'e'.repeat(32),
    clientCidr: '10.255.16.0/24', tproxyPort: 12345, fwmark: 100, routeTable: 100 };

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
            return { sshHostKeySha256: f.pin ?? pin, sshHostKeyType };
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
    assert.deepEqual(first, { ...endpoint, sshHostKeySha256: pin, sshHostKeyType, challenge: first.challenge });
    assert.deepEqual(f.calls, ['key']);
    const verified = await f.perform('verify', first.challenge);
    assert.deepEqual(verified, { ...binding, sshHostKeyType, challenge: verified.challenge });
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

test('explicit installed key rotation dispatches only the pinned read-only ownership check and CASes the old generation', async () => {
    const newPin = 'd'.repeat(64);
    const requests = [];
    let closes = 0;
    class SSH {
        constructor(node, opts) {
            assert.equal(node.ssh.password, 'fixture-only');
            assert.deepEqual(opts, { expectedHostKeySha256: newPin,
                expectedEndpoint: { ip: endpoint.host, port: endpoint.port, username: endpoint.username } });
        }
        async connectDirectOnce(ms) { assert.equal(ms, 5000); assert.equal(this.usePool, false); }
        async exec(command, { stdin }) {
            assert.match(command, /^\/usr\/bin\/timeout .* \/usr\/bin\/python3 -I -B -c /);
            assert.ok(!command.includes(newPin) && !command.includes('fixture-only'));
            const request = JSON.parse(stdin);
            requests.push(request);
            assert.equal(request.action, 'check-apply-network', 'no mutating host action');
            return { code: 0, stderr: '', stdout: `${JSON.stringify({ ok: true, backupId: installed.backupId, proof: pin })}\n` };
        }
        disconnect() { closes++; }
    }
    const f = fixture({ SSH });
    f.row = { ...binding, generation: 'previous' };
    f.footprint = { ...clear, states: [structuredClone(installed)], accounts: { _id: 'account' } };
    const before = structuredClone(f.footprint);
    f.pin = newPin;
    const { challenge } = await f.approve();
    assert.deepEqual(requests, []);
    assert.deepEqual(await f.perform('confirm', challenge), { ...binding, sshHostKeySha256: newPin, source: 'db' });
    assert.deepEqual(requests, [{ action: 'check-apply-network', machineId: machine, backupId: installed.backupId,
        network: { clientCidr: installed.clientCidr, tproxyPort: installed.tproxyPort, fwmark: installed.fwmark, routeTable: installed.routeTable } }]);
    assert.equal(closes, 1);
    assert.deepEqual(f.footprint, before);
    assert.deepEqual(f.writes, [{ action: 'reconfirm', binding: { ...binding, sshHostKeySha256: newPin },
        expectedGeneration: 'previous', actor: 'operator' }]);
    await assert.rejects(f.perform('confirm', challenge), invalid);
    assert.equal(requests.length, 1);
});

test('installed rotation refuses unproved receipt, changed footprint and pending intent without granting', async () => {
    for (const reason of ['unproved', 'receipt-drift', 'grant-drift', 'candidate-machine', 'endpoint', 'missing-grant', 'fenced', 'pending']) {
        let witnessed = 0;
        const f = fixture({ witnessInstalled: async () => {
            witnessed++;
            if (reason === 'receipt-drift') f.footprint.states[0].backupId = 'a'.repeat(32);
            if (reason === 'grant-drift') f.row.generation = 'successor';
            return reason !== 'unproved';
        } });
        f.row = reason === 'missing-grant' ? null : { ...binding, generation: 'previous', ...(reason === 'endpoint' && { port: 22 }) };
        f.footprint = { ...clear, states: [structuredClone(installed)] };
        if (reason === 'fenced') f.footprint.states[0].replacementFence = 1;
        f.pin = 'd'.repeat(64);
        if (reason === 'candidate-machine') f.machine = 'a'.repeat(32);
        const { challenge } = await f.approve();
        f.pending = reason === 'pending';
        await assert.rejects(f.perform('confirm', challenge), reason === 'pending' ? { code: 'REBUILD_L2TP_ACCOUNTS_BLOCKED' } : conflict, reason);
        assert.equal(witnessed, ['unproved', 'receipt-drift', 'grant-drift'].includes(reason) ? 1 : 0, reason);
        assert.deepEqual(f.writes, [], reason);
    }
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
        [{ code: conflict.code, field: 'endpoint', sources: ['env', 'db'], keyValue: 'private fixture' },
            { ...conflict, detail: 'endpoint', sources: ['env', 'db'], outcome: 'refused' }, 'denied'],
        [{ code: conflict.code, field: 'endpoint', sources: ['db', 'private fixture'] },
            { ...conflict, detail: 'endpoint', outcome: 'refused' }, 'denied'],
        [{ code: conflict.code, field: 'private fixture', sources: ['env', 'db'] },
            { ...conflict, outcome: 'refused' }, 'denied'],
        [{ code: 'REBUILD_L2TP_GRANT_CHANGED' }, { ...conflict, detail: 'grant-changed', outcome: 'refused' }, 'denied'],
        [{ code: 'REBUILD_L2TP_GRANT_OUTCOME_UNKNOWN', detail: 'private fixture' },
            { code: 'REBUILD_L2TP_GRANT_OUTCOME_UNKNOWN', outcome: 'unknown', retryAllowed: false }, 'unknown'],
    ]) {
        const f = fixture();
        f.writeError = Object.assign(new Error('private fixture'), input);
        const { challenge } = await f.approve();
        await assert.rejects(f.perform('confirm', challenge), error => {
            assert.equal(error.message, expected.code);
            assert.deepEqual({ ...error }, expected);
            if (expected.sources) assert.notEqual(error.sources, input.sources);
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
const hostModel = String.raw`import contextlib, io, json, os, sys, tempfile, types
from pathlib import Path
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
main = "/usr/local/etc/xray/config.json"
bridge = "/usr/local/etc/xray-bridge/config.json"
chap = "/etc/ppp/chap-secrets"
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
def exercise(good, files=None, **kwargs):
    with tempfile.TemporaryDirectory() as tmp:
        return observe(Path(tmp), good, fixture | (files or {}), **kwargs)

def observe(root, good, data, outputs=None, record=False, unavailable=False, active=False,
            owners=None, modes=None, link=None, xattr=None, changed=False, nobody=4242, case="baseline"):
    values = clean_outputs | (outputs or {})
    def local(path):
        assert path.startswith("/") and ".." not in path.split("/")
        return root / path.lstrip("/")
    os.umask(0o022)
    local(system).mkdir(parents=True, mode=0o700)
    for path, value in data.items():
        target = local(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if value is not None:
            target.write_bytes(value)
    if local(vault).exists():
        local(vault).chmod(0o700)
    if link:
        kind, path = link
        target = local(path)
        moved = root / "moved"
        target.rename(moved)
        (target.symlink_to if kind == "symlink" else target.hardlink_to)(moved)
    for path, mode in (modes or {}).items():
        local(path).chmod(mode)
    uids = {local(path).stat().st_ino: uid for path, uid in (owners or {}).items()}
    attrs = {local(xattr).stat().st_ino: ["user.fixture"]} if xattr else {}
    directories = set()
    def metadata(st):
        return types.SimpleNamespace(st_uid=uids.get(st.st_ino, 0), st_mode=st.st_mode, st_dev=st.st_dev,
            st_ino=st.st_ino, st_nlink=st.st_nlink, st_size=st.st_size)
    def open_path(path, flags, *, dir_fd=None):
        assert (flags & os.O_ACCMODE) == os.O_RDONLY and not flags & (os.O_CREAT | os.O_TRUNC)
        if dir_fd is not None:
            assert dir_fd in directories and "/" not in path and path not in (".", "..")
        fd = os.open(local(path) if dir_fd is None else path, flags, dir_fd=dir_fd)
        if flags & os.O_DIRECTORY:
            directories.add(fd)
        return fd
    def close(fd):
        directories.remove(fd)
        os.close(fd)
    def getpwnam(name):
        assert name == "nobody"
        if nobody is None:
            raise KeyError(name)
        return types.SimpleNamespace(pw_uid=nobody)
    def command(program, *args, codes=(0,)):
        if program == "/usr/bin/systemctl":
            state = b"active" if active else b"inactive"
            return 1, b"LoadState=not-found\nActiveState=" + state + b"\nSubState=dead\nJob=\n"
        if unavailable and args == ("-j", "list", "tables"):
            raise OSError()
        if changed and args == ("xfrm", "state", "list", "nokeys"):
            local("/etc/machine-id").write_bytes(b"d" * 32 + b"\n")
        return 0, values[args]
    # Exercise the real reader and Linux open/link/mode semantics on fixture files;
    # UID and xattr observations are modeled so the suite needs no privilege.
    g["os"] = types.SimpleNamespace(geteuid=lambda: 0, open=open_path, fdopen=os.fdopen, close=close,
        O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY, O_NOFOLLOW=os.O_NOFOLLOW, O_NONBLOCK=os.O_NONBLOCK,
        lstat=lambda path: metadata(local(path).lstat()),
        scandir=lambda path: contextlib.nullcontext([
            types.SimpleNamespace(name=token, path=prefix, is_dir=lambda **kw: not kw["follow_symlinks"])]),
        stat=lambda path, **kw: metadata(os.stat(local(path), **kw)), fstat=lambda fd: metadata(os.fstat(fd)),
        listxattr=lambda fd: attrs.get(os.fstat(fd).st_ino, []))
    g["fcntl"] = types.SimpleNamespace(flock=lambda fd, flags: None, LOCK_SH=1, LOCK_NB=4)
    g["sys"] = types.SimpleNamespace(argv=["-c", "recorded-absent" if record else "no-record"])
    g.update(command=command, pwd=types.SimpleNamespace(getpwnam=getpwnam))
    result = io.StringIO()
    with contextlib.redirect_stdout(result):
        try:
            g["observe"]()
        except (ValueError, KeyError, OSError) as error:
            assert not good, case + ": " + repr(error)
        else:
            assert good, case + ": unexpected absence receipt"
    assert not directories, case + ": leaked directory descriptor"
    assert result.getvalue() == ("absent:" + machine.decode() if good else ""), case
    return result.getvalue()
exercise(True)
exercise(True, {main: b"{}", bridge: b"{}"}, nobody=None, case="root profiles do not need an account lookup")
for profile in (main, bridge):
    clean = {profile: b"{}"}
    parent = str(Path(profile).parent)
    exercise(True, clean, owners={profile: 4242}, modes={profile: 0o640}, case="clean nobody-owned " + profile)
    exercise(False, clean, owners={profile: 65534}, case="unexpected owner despite typical nobody uid")
    exercise(False, clean, owners={profile: 4242}, nobody=None, case="expected owner unavailable")
    for owner in (0, 4242):
        for mode in (0o660, 0o642, 0o4640, 0o2640, 0o1640):
            exercise(False, clean, owners={profile: owner}, modes={profile: mode}, case="unsafe mode " + oct(mode))
        exercise(False, clean, owners={profile: owner}, xattr=profile, case="extended attributes")
        for kind in ("symlink", "hardlink"):
            exercise(False, clean, owners={profile: owner}, link=(kind, profile), case=kind)
    exercise(False, {profile: None, profile + "/child": b""}, case="nonregular profile")
    exercise(False, clean, owners={parent: 4242}, case="non-root Xray directory")
    exercise(False, clean, modes={parent: 0o775}, case="writable Xray directory")
    exercise(False, clean, link=("symlink", parent), case="symlink Xray directory")
    exercise(False, {profile: b"rebuild-relay-ingress"}, owners={profile: 4242}, case="managed ingress retained")
exercise(False, {chap: b""}, owners={chap: 4242}, case="PPP file remains root-only")
exercise(False, owners={"/etc/machine-id": 4242}, case="machine-id remains root-only")
exercise(False, {"/proc/net/udp6": None}, case="missing required witness")
exercise(False, changed=True, case="machine changed during observation")
removed = {prefix + "/manifest.json": receipt, prefix + "/remove-attempt.json": attempt}
success = exercise(True, removed | {main: b"{}", bridge: b"{}"}, record=True, owners={main: 4242}, case="recorded Remove")
exercise(False, removed, record=True, owners={prefix + "/manifest.json": 4242}, case="manifest remains root-only")
exercise(False, removed, record=True, owners={prefix + "/remove-attempt.json": 4242}, case="Remove attempt remains root-only")
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
sys.stdout.write(success)
`;

test('the default revoke witness uses one pinned read-only SSH command and demands an exact receipt', async () => {
    let response, observer, closes = 0;
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
                observer = spawnSync('python3', ['-I', '-B', '-c', hostModel],
                    { input: match[1], encoding: 'utf8', timeout: 5000 });
            }
            return response;
        }
        disconnect() { closes++; }
    }
    const f = fixture({ witnessAbsent: undefined, SSH });
    f.row = { ...binding, generation: 'previous' };
    const receipt = { code: 0, stderr: '', stdout: `absent:${machine}\n` };
    for (const overrides of [{ code: 1 }, { stderr: 'private fixture' }, { stdout: '' }, { stdout: `absent:${machine}\n\n` }]) {
        response = { ...receipt, ...overrides };
        await assert.rejects(f.perform('revoke'), { ...conflict, detail: 'host-absence-unproved' });
        assert.equal(observer?.status, 0, observer?.stderr || observer?.error?.message);
    }
    response = { ...receipt, stdout: `absent:${'d'.repeat(32)}\n` };
    await assert.rejects(f.perform('revoke'), changed);
    assert.deepEqual(f.writes, []);
    f.footprint = { ...clear, states: [{ node: nodeId, status: 'not_installed', desiredState: 'absent', replacementFence: 2 }] };
    response = { code: observer.status, stdout: observer.stdout, stderr: observer.stderr };
    assert.deepEqual(await f.perform('revoke'), { nodeId, source: null });
    assert.deepEqual(commands, [...Array(5).fill('no-record'), 'recorded-absent']);
    assert.equal(closes, commands.length);
    assert.deepEqual(f.writes, [{ action: 'revoke', binding, expectedGeneration: 'previous', actor: 'operator' }]);
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
