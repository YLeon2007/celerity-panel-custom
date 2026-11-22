'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createRelayDirect } = require('../rebuildRelayDirect');
const { readSessionCensus } = require('../rebuildRelayCounts');

const nodeId = 'a'.repeat(24), machineId = 'b'.repeat(32), changed = 'e'.repeat(32), pin = 'c'.repeat(64);
const node = { _id: nodeId, ip: '192.0.2.19', ssh: { username: 'root', port: 22 } };
const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
    C3_REBUILD_L2TP_RELAY_ID: nodeId, C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: pin };
const binding = { nodeId, backupId: 'd'.repeat(32), network: {
    clientCidr: '10.255.1.0/24', tproxyPort: 12345, fwmark: 77, routeTable: 177,
} };
const user = { login: 'fixture', password: 'private-fixture', ipAddress: '10.255.1.3', enabled: true };
const lock = async () => true;
const machine = (id = machineId) => ({ code: 0, stdout: `${id}\n`, stderr: '' });
const reply = value => ({ code: 0, stdout: JSON.stringify(value) + '\n', stderr: '' });
const counts = { activeSessions: 0, activeIpsec: 0, census: 'a'.repeat(64) };
const identity = { code: 'REBUILD_L2TP_IDENTITY_CHANGED' };
const unknown = { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN' };

function fixture(observations, respond) {
    const calls = [];
    let connections = 0;
    class SSH {
        async connectDirectOnce() {
            assert.equal(this.usePool, false);
            assert.equal(++connections, 1);
            return this.exec.bind(this);
        }
        connect() { return this.connectDirectOnce(); }
        disconnect() { calls.push('disconnect'); }
        async exec(command, options, verify) {
            if (command === '/usr/bin/head -c 34 /etc/machine-id') {
                calls.push('attest');
                assert.ok(!Object.hasOwn(options, 'stdin'));
                assert.equal(verify, undefined);
                assert.ok(options.timeout > 0);
                const result = observations.shift();
                if (result instanceof Error) throw result;
                return result;
            }
            const payload = JSON.parse(options.stdin);
            calls.push(`open:${payload.action}`);
            await verify?.();
            calls.push(`stdin:${payload.action}`);
            assert.equal(payload.machineId, machineId);
            assert.ok(!command.includes(user.password));
            return respond(payload);
        }
    }
    return { remote: createRelayDirect({ node, env, SSH }), calls };
}

for (const [name, invoke] of Object.entries({
    'check-chap': remote => remote.checkChap(binding, [], [user], lock),
    'session-count': remote => remote.readSessionCount({ ...binding, currentUsers: [user] }),
    'prepare-remove': remote => remote.prepareRemove({ ...binding, currentUsers: [user] }),
})) {
    test(`${name}: first operation refuses a changed machine without opening the payload channel`, async () => {
        const { remote, calls } = fixture([machine(changed)], () => reply(counts));
        const attempted = invoke(remote);
        const rejected = await attempted.then(() => null, e => e);
        assert.deepEqual(calls, ['attest', 'disconnect']);
        assert.equal(rejected?.code, identity.code);
        await assert.rejects(invoke(remote), { code: 'REBUILD_L2TP_DIRECT_UNAVAILABLE' });
        assert.deepEqual(calls, ['attest', 'disconnect']);
    });
}

test('only exact, successful and silent machine observations attest; unavailable does not mean changed', async () => {
    for (const observation of [null, { ...machine(changed), code: 1 }, { ...machine(changed), stderr: user.password },
        { ...machine(), stdout: `${machineId}\n\n` }, { ...machine(), stdout: ` ${machineId}\n` },
        { ...machine(), stdout: `${machineId}\r\n` }, machine(''), machine('not-a-machine-id'), new Error(user.password)]) {
        const { remote, calls } = fixture([observation], () => reply(counts));
        await assert.rejects(remote.readSessionCount(binding), error => {
            assert.equal(error.code, unknown.code);
            assert.ok(!error.remoteOutcomeUncertain && !error.cause);
            assert.ok(!String(error.stack).includes(user.password));
            return true;
        });
        assert.deepEqual(calls, ['attest', 'disconnect']);
    }
});

test('first and subsequent census operations attest on the same connection, and late mismatch suppresses the next payload', async () => {
    const { remote, calls } = fixture([machine(), { ...machine(), stdout: machineId }, machine(changed)], payload => {
        assert.deepEqual(payload, { action: 'session-count', machineId, ...binding, currentUsers: [user] });
        return reply(counts);
    });
    for (let i = 0; i < 2; i++) assert.deepEqual(await remote.readSessionCount({ ...binding, currentUsers: [user] }), counts);
    await assert.rejects(remote.readSessionCount(binding), identity);
    assert.deepEqual(calls, ['attest', 'open:session-count', 'stdin:session-count', 'attest', 'open:session-count',
        'stdin:session-count', 'attest', 'disconnect']);
});

test('census preserves an exact under-lock identity refusal even with a matching transport attestation', async () => {
    const { remote, calls } = fixture([machine()], () => ({ code: 70, stdout: '', stderr: 'DIRECT_IDENTITY\n' }));
    await assert.rejects(readSessionCensus(remote, binding), identity);
    assert.deepEqual(calls, ['attest', 'open:session-count', 'stdin:session-count', 'disconnect']);
});

test('census never exposes a tainted or unproved identity refusal as a changed machine', async () => {
    const exact = { code: 70, stdout: '', stderr: 'DIRECT_IDENTITY\n' };
    for (const result of [{ ...exact, stdout: user.password }, { ...exact, code: 1 },
        { ...exact, stderr: exact.stderr + '\n' }, { ...exact, stderr: 'DIRECT_NO_WRITE_IDENTITY\n' },
        { ...exact, stderr: 'DIRECT_SESSION_COUNT_UNPROVED\n' }]) {
        const { remote, calls } = fixture([machine()], () => result);
        assert.equal(await readSessionCensus(remote, binding), null);
        assert.deepEqual(calls, ['attest', 'open:session-count', 'stdin:session-count']);
        await remote.close();
    }
});

test('the packed host independently checks machine ID under its real flock before actions and on census readback', async () => {
    let packed;
    class SSH {
        async connectDirectOnce() {
            return (command, options) => {
                if (command === '/usr/bin/head -c 34 /etc/machine-id') return machine();
                packed = command;
                assert.equal(JSON.parse(options.stdin).action, 'session-count');
                return reply(counts);
            };
        }
        disconnect() {}
    }
    const remote = createRelayDirect({ node, env, SSH });
    assert.deepEqual(await remote.readSessionCount({ ...binding, currentUsers: [user] }), counts);
    await remote.close();
    const harness = String.raw`
import contextlib, fcntl, io, json, os, shlex, sys, tempfile
command, stdin = json.load(sys.stdin)
base = json.loads(stdin)
scope = {'__name__': 'fixture'}
exec(shlex.split(command)[-1], scope)
expected = base['machineId'].encode('ascii')
changed = b'e' * 32

with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as root:
    def audit(event, args):
        if event.startswith('socket.') or event.startswith('os.exec') or event in {
                'subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.kill', 'os.killpg'}:
            raise AssertionError(event)
        if event == 'open' and not (isinstance(args[0], int) or args[0] == root
                                    or args[0].startswith(root + '/')):
            raise AssertionError('unexpected open: ' + str(args[0]))

    sys.addaudithook(audit)
    scope['SYSTEM'] = root
    @contextlib.contextmanager
    def directory(path):
        assert path == root
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)
    scope['directory'] = directory
    scope['os'] = type('FixtureOS', (), {'__getattr__': lambda self, name: getattr(os, name),
                                         'geteuid': lambda self: 0})()
    # Refuse access to every host observer/effect not explicitly modeled.
    forbidden = []
    def deny(*args, **kwargs):
        forbidden.append(True)
        raise AssertionError('unexpected host call')
    for observer in ('observe_install', 'observe_removal', 'sync_chap', 'command', 'unit'):
        scope[observer] = deny

    def lock_held():
        with scope['directory'](root) as witness:
            try:
                fcntl.flock(witness, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
        return False

    def invoke(action, values, expected_code, expected_out, expected_err, probes=0):
        for flag in ('NO_INSTALL_WRITES', 'REMOVE_ENTERED', 'CHAP_ENTERED'):
            scope[flag] = False
        identity = iter(values)
        seen = []
        def read(path, limit=34):
            assert path == '/etc/machine-id' and limit == 34 and lock_held()
            leaf = next(identity)
            return None if leaf is None else scope['entry'](leaf, 0o444, 0, 0)
        def open_identity(path, mode):
            assert path == '/etc/machine-id' and mode == 'rb'
            seen.append(lock_held())
            return io.BytesIO(next(identity))
        def preflight(machine, **kw):
            return {'machineId': scope['require_machine'](machine), 'ppp': True,
                    'masked': False, 'unitsLoaded': True}
        samples = []
        def census(_):
            assert lock_held()
            samples.append(True)
            return {'activeSessions': 0, 'activeIpsec': 0, 'census': 'a' * 64}
        scope.update(read=read, open=open_identity, preflight=preflight, relay_session_census=census)
        sys.stdin = io.TextIOWrapper(io.BytesIO(json.dumps({**base, 'action': action,
            **({'desiredUsers': base['currentUsers']} if action == 'check-chap' else {})}).encode()))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = scope['main']()
        assert (code, out.getvalue(), err.getvalue()) == (expected_code, expected_out, expected_err), (action, code, out.getvalue(), err.getvalue())
        assert len(samples) == probes and not forbidden and not lock_held()
        if action != 'session-count':
            assert seen == [False, True]
        assert next(identity, 'done') == 'done', action

    census_reply = '{"activeSessions":0,"activeIpsec":0,"census":"' + 'a' * 64 + '"}\n'
    invoke('session-count', [expected, expected + b'\n'], 0, census_reply, '', 1)
    invoke('session-count', [changed], 70, '', 'DIRECT_IDENTITY\n')
    invoke('session-count', [expected, changed], 70, '', 'DIRECT_IDENTITY\n', 1)
    for unavailable in (None, b'x', changed + b'\n\n'):
        invoke('session-count', [unavailable], 70, '', 'DIRECT_SESSION_COUNT_UNPROVED\n')
    for action in ('check-chap', 'sync-chap', 'prepare-remove', 'remove', 'check', 'install'):
        refusal = 'DIRECT_NO_WRITE_IDENTITY\n' if action == 'install' else 'DIRECT_IDENTITY\n'
        invoke(action, [expected, changed], 70, '', refusal)
`;
    const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', harness], {
        input: JSON.stringify([packed, JSON.stringify({ action: 'session-count', machineId, ...binding, currentUsers: [user] })]),
        encoding: 'utf8', timeout: 5000,
    });
    assert.ifError(result.error);
    assert.deepEqual([result.status, result.stdout, result.stderr], [0, '', '']);
});
