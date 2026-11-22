'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { existsSync, readFileSync, readlinkSync } = require('node:fs');
const { join } = require('node:path');
const { createRelayDirect } = require('../rebuildRelayDirect');
const attested = require('./helpers/rebuildRelayDirectWire');
const { runFreshRelayInstall } = require('../rebuildRelayInstall');

const nodeId = 'a'.repeat(24);
const machineId = 'b'.repeat(32);
const pin = 'c'.repeat(64);
const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
    C3_REBUILD_L2TP_RELAY_ID: nodeId, C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: pin };
const node = { _id: nodeId, ip: '192.0.2.19', ssh: { username: 'root', port: 22 } };
const sha = data => createHash('sha256').update(data).digest('hex');
const main = JSON.stringify({ inbounds: [{ tag: 'fwd-hop-a', protocol: 'vless', port: 443 }],
    outbounds: [{ tag: 'block', protocol: 'blackhole' }], routing: { rules: [
        { type: 'field', ruleTag: 'rebuild-policy-default', inboundTag: ['fwd-hop-a'], outboundTag: 'block' },
    ] } });
const desired = { psk: 'fixture-only-shared-secret', users: [
    { login: 'fixture', password: 'fixture-only-user-password', ipAddress: '10.255.1.10', enabled: true },
], clientCidr: '10.255.1.0/24', localAddress: '10.255.1.1', poolStart: '10.255.1.10', poolEnd: '10.255.1.50',
mtu: 1380, mru: 1370, dnsServers: ['1.1.1.1'], routeTable: 177, fwmark: 77, tproxyPort: 12345 };
const args = { nodeId, desired, controlPlaneAddresses: ['panel.invalid'], carryDomain: false };
const ok = body => ({ code: 0, stdout: JSON.stringify(body) + '\n', stderr: '' });
const ready = { machineId, ppp: true, masked: false, unitsLoaded: true };
const observation = { ...ready, main, bridge: null, mainSha256: sha(main), bridgeSha256: null, baseline: 'd'.repeat(64) };
const pending = { ...ready, ppp: false, unitsLoaded: false, pppPreparation: true, nativePreparation: true };
const pendingSnapshot = { ...observation, ppp: false, unitsLoaded: false };

function fixture(handler = () => {}) {
    const calls = [];
    let firstCommand;
    class SSH {
        constructor(selected, options) {
            assert.equal(selected, node);
            assert.deepEqual(options, { expectedEndpoint: { ip: node.ip, port: 22, username: 'root' }, expectedHostKeySha256: pin });
            this.usePool = true;
        }
        async connect() { assert.equal(this.usePool, false); calls.push('connect'); }
        disconnect() { calls.push('close'); }
        async exec(command, options) {
            const input = JSON.parse(options.stdin);
            assert.ok(options.timeout > 0 && options.timeout <= 150000);
            assert.ok(Buffer.byteLength(command) + 1 <= 128 * 1024, 'fits Linux MAX_ARG_STRLEN');
            assert.ok(!command.includes(desired.psk) && !command.includes(desired.users[0].password));
            firstCommand ??= command;
            assert.equal(command === firstCommand, true, 'wire data does not influence the install command');
            calls.push(input.action);
            const result = await handler(input);
            if (result !== undefined) return result;
            if (input.action === 'preflight') return ok(ready);
            if (input.action === 'prepare') return ok(observation);
            return ok({ ok: true, backupId: input.backupId });
        }
    }
    return { remote: createRelayDirect({ node, env, SSH: attested(SSH, machineId) }), calls };
}

test('requires authority and canonical ssh2 pin before construction', () => {
    const SSH = class { constructor() { assert.fail(); } };
    for (const override of [{ C3_REBUILD_L2TP_SSH_SHA256: undefined }, { C3_REBUILD_L2TP_SSH_SHA256: 'SHA256:abc' },
        { C3_REBUILD_ENABLED: 'false' }, { C3_REBUILD_L2TP_RELAY_MACHINE_ID: undefined }]) {
        assert.throws(() => createRelayDirect({ node, env: { ...env, ...override }, SSH }));
    }
});

test('the exact SSH command shell and Python stdin reject invalid framing locally', async () => {
    class SSH {
        connect() {}
        disconnect() {}
        exec(command) {
            // Malformed identity is rejected even under root, before reading
            // machine identity or invoking any host-side commands.
            const result = spawnSync('/bin/sh', ['-c', command], {
                input: '{"action":"preflight","machineId":"invalid"}', encoding: 'utf8', timeout: 5000,
            });
            assert.equal(result.status, 70, result.stderr || result.error?.message);
            assert.equal(result.stdout, '');
            assert.equal(result.stderr, 'DIRECT_PREREQUISITE\n');
            return { code: result.status, stdout: result.stdout, stderr: result.stderr };
        }
    }
    const remote = createRelayDirect({ node, env, SSH: attested(SSH, machineId) });
    await assert.rejects(remote.preflight(), { code: 'REBUILD_L2TP_DIRECT_PREREQUISITE' });
    await remote.close();
});

test('DIRECT bootstrap compiles the three exact repo sources without loading them from the host', async () => {
    const fingerprints = [
        '../rebuildRelayDirectHost.py', '../rebuildRelayStockRuntime.py',
        '../../modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py',
    ].map(file => sha(readFileSync(join(__dirname, file))));
    const probe = String.raw`
import hashlib, json, os, shlex, sys
command, request, expected = json.load(sys.stdin)
assert os.getcwd() == '/' and '' not in sys.path and '/' not in sys.path
argv = shlex.split(command)
assert argv[:-1] == ['/usr/bin/timeout', '-k', '4s', '125s', '/usr/bin/python3', '-I', '-B', '-c']
assert json.loads(request)['action'] == 'preflight'
assert json.loads(request)['machineId'] not in command
sources, faults = [], []
def audit(event, args):
    if event == 'compile' and isinstance(args[0], bytes):
        sources.append(hashlib.sha256(args[0]).hexdigest())
    if (event in {'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'} or event.startswith('socket.')
            or event == 'open' and isinstance(args[0], str) and args[0].endswith(
                ('rebuildRelayDirectHost.py', 'rebuildRelayStockRuntime.py', 'ensure-xl2tpd-unit.py'))):
        faults.append(event)
        raise AssertionError('unexpected external source or dispatch')
sys.addaudithook(audit)
host = {'__name__': 'fixture_host'}
exec(compile(argv[-1], '<DIRECT command>', 'exec'), host)
assert not faults, faults
assert sorted(digest for digest in sources if digest in expected) == sorted(expected), 'missing or duplicated source'
for name, function in [('C3_STOCK_RUNTIME', 'verify_package'), ('C3_STOCK_ENSURE', 'ensure')]:
    scope = host[name]
    assert type(scope) is dict and scope['__name__'] not in ('__main__', host['__name__'])
    assert scope[function].__globals__ is scope
assert host['C3_STOCK_RUNTIME']['__name__'] != host['C3_STOCK_ENSURE']['__name__']
`;
    class SSH {
        connect() {}
        disconnect() {}
        exec(command, { stdin }) {
            const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', probe], {
                input: JSON.stringify([command, stdin, fingerprints]), encoding: 'utf8', timeout: 5000, cwd: '/', env: {},
            });
            // Check outside the driver's exception sanitizer.
            outcome = [result.status, result.stdout, result.stderr || result.error?.message || ''];
            return ok(ready);
        }
    }
    let outcome;
    const remote = createRelayDirect({ node, env, SSH: attested(SSH, machineId) });
    try { assert.deepEqual(await remote.preflight(), ready); }
    finally { await remote.close(); }
    assert.deepEqual(outcome, [0, '', '']);
});

test('prepare and validate before mutation, bind private desired and lock, then read back', async () => {
    const { remote, calls } = fixture(input => {
        if (input.action === 'check' || input.action === 'install') {
            assert.ok(Object.values(input.files).some(value => Buffer.from(value, 'base64').toString().includes(desired.psk)));
            assert.ok(Object.values(input.files).some(value => Buffer.from(value, 'base64').toString().includes('mtu 1380\nmru 1370')));
        }
    });
    assert.deepEqual(await remote.preflight(), ready);
    const plan = await remote.prepare(args);
    assert.match(plan.backupId, /^[a-f0-9]{32}$/);
    assert.ok(!JSON.stringify(plan).includes(desired.psk));
    assert.equal(plan.getDesired().psk, desired.psk);
    assert.deepEqual(calls, ['connect', 'preflight', 'preflight', 'prepare', 'check']);
    await assert.rejects(remote.install({ ...plan }, async () => {}));
    await assert.rejects(remote.install(plan, async () => { throw Error('lease lost'); }));
    assert.ok(!calls.includes('install'));
    await remote.install(plan, async () => calls.push('lock'));
    assert.equal(await remote.verify(plan), true);
    await remote.close();
    assert.deepEqual(calls.slice(5), ['lock', 'install', 'verify', 'close']);
});

// Consumer frames for the native prerequisite; the Python host decides eligibility.
test('DIRECT admits a pending native snapshot only with a fresh matching same-peer preflight', async () => {
    for (const ppp of [false, true]) {
        const { remote, calls } = fixture(({ action }) => {
            if (action === 'preflight') return ok({ ...pending, ppp });
            if (action === 'prepare') return ok({ ...pendingSnapshot, ppp });
        });
        try {
            const plan = await remote.prepare(args);
            assert.match(plan.backupId, /^[a-f0-9]{32}$/);
            assert.deepEqual(calls, ['connect', 'preflight', 'prepare', 'check']);
        } finally { await remote.close(); }
    }
    let preflights = 0;
    const { remote, calls } = fixture(({ action }) => action === 'preflight'
        ? ok(++preflights === 1 ? pending : ready) : action === 'prepare' ? ok(pendingSnapshot) : undefined);
    try {
        assert.deepEqual(await remote.preflight(), pending);
        await assert.rejects(remote.prepare(args), { code: 'REBUILD_L2TP_HOST_NOT_READY', check: 'VPN_UNITS_NOT_LOADED' });
        assert.deepEqual(calls, ['connect', 'preflight', 'preflight', 'prepare']);
    } finally { await remote.close(); }
});

test('malformed native capability, forged snapshot capability and readiness drift cannot reach candidate check', async () => {
    const unknown = 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN';
    const notReady = 'REBUILD_L2TP_HOST_NOT_READY';
    const mismatch = 'REBUILD_L2TP_INSTALL_IDENTITY_MISMATCH';
    for (const [preflight, prepare, code] of [
        [ok({ ...ready, unitsLoaded: false }), null, notReady],
        [ok({ ...pending, nativePreparation: 1 }), null, unknown],
        [ok({ ...pending, nativePreparation: false }), null, unknown],
        [ok({ ...pending, pppPreparation: undefined }), null, unknown],
        [ok({ ...pending, pppPreparation: 1 }), null, unknown],
        [ok({ ...pending, unitsLoaded: true }), null, unknown],
        [ok({ ...pending, masked: true }), null, unknown],
        [ok({ ...pending, ppp: 0 }), null, unknown],
        [ok({ ...pending, extra: true }), null, unknown],
        [{ ...ok(pending), stdout: ok(pending).stdout.replace('{', '{"nativePreparation":false,') }, null, unknown],
        [ok({ ...pending, machineId: 'e'.repeat(32) }), null, mismatch],
        [ok(pending), ok({ ...pendingSnapshot, machineId: 'e'.repeat(32) }), mismatch],
        [ok(pending), ok({ ...pendingSnapshot, masked: true }), notReady],
        [ok(pending), ok({ ...pendingSnapshot, unitsLoaded: undefined }), unknown],
        [ok(pending), ok({ ...pendingSnapshot, nativePreparation: true }), unknown],
        [ok(pending), ok({ ...pendingSnapshot, pppPreparation: true }), unknown],
        [ok(ready), ok({ ...pendingSnapshot, nativePreparation: true }), unknown],
        [ok(pending), ok(observation), notReady],
        [ok(ready), ok(pendingSnapshot), notReady],
    ]) {
        const { remote, calls } = fixture(({ action }) => action === 'preflight' ? preflight
            : action === 'prepare' ? prepare : undefined);
        try {
            await assert.rejects(remote.prepare(args), { code });
            assert.deepEqual(calls, ['connect', 'preflight', ...(prepare ? ['prepare'] : []),
                ...(code === mismatch ? ['close'] : [])]);
        } finally { await remote.close(); }
    }
});

test('install checks require exact frames; the check alone never permits cleanup', async () => {
    const partial = 'DIRECT_PPP_MODULES_LOAD_FAILED\n';
    const noWrite = 'DIRECT_NO_WRITE_PPP_MODULES_LOAD_FAILED\n';
    const frame = (stderr, stdout = '', code = 70) => ({ code, stdout, stderr });
    for (const [result, trusted, unchanged, retained = false] of [
        [frame(partial), true, false, true], [frame(noWrite), true, true],
        [frame('DIRECT_PREREQUISITE\n'), true, false],
        [frame(noWrite + '\n'), false, false], [frame(noWrite.trimEnd()), false, false],
        [frame(noWrite.replace('\n', '\r\n')), false, false], [frame(noWrite, 'fixture-private'), false, false],
        [frame(noWrite, '', 1), false, false], [frame('DIRECT_NO_WRITE_FUTURE_CHECK\n'), false, false],
        [frame('DIRECT_NO_WRITE_PPP_MODULES_LOAD_FAILED fixture-private\n'), false, false],
        [frame('DIRECT_IKE_ACTIVE_RULE_220\n'), false, false], [frame('', '', 75), false, false],
    ]) {
        const { remote, calls } = fixture(({ action }) => action === 'install' ? result : undefined);
        const plan = await remote.prepare(args);
        await assert.rejects(remote.install(plan, () => true), error => {
            assert.equal(error.commandSettled === true, trusted && !retained);
            assert.equal(error.prerequisitePartial === true, retained);
            assert.equal(error.noHostChanges === true, unchanged);
            assert.equal(error.remoteOutcomeUncertain === true, !trusted);
            assert.equal(error.check, !trusted ? undefined
                : result.stderr === 'DIRECT_PREREQUISITE\n' ? 'HOST_INSTALL' : 'PPP_MODULES_LOAD_FAILED');
            assert.doesNotMatch(JSON.stringify(error) + error.message, /fixture-private|FUTURE_CHECK/);
            return true;
        });
        assert.equal(await remote.rollback(plan, () => true), trusted && !unchanged && !retained);
        assert.equal(calls.includes('rollback'), trusted && !unchanged && !retained);
        await remote.close();
    }
});

test('invalid read-only framing cannot produce an install check or prepare a write', async () => {
    for (const result of [
        { code: 70, stdout: '', stderr: 'DIRECT_NO_WRITE_XRAY_DROPIN_UNSUPPORTED\n' },
        { code: 70, stdout: 'fixture-private', stderr: 'DIRECT_XRAY_DROPIN_UNSUPPORTED\n' },
        { code: 70, stdout: '', stderr: 'DIRECT_XRAY_DROPIN_UNSUPPORTED\n\n' },
        { code: 0, stdout: '{"ok":false,"ok":true}\n', stderr: '' },
    ]) {
        const { remote, calls } = fixture(({ action }) => action === 'check' ? result : undefined);
        await assert.rejects(remote.prepare(args), { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN' });
        assert.deepEqual(calls, ['connect', 'preflight', 'prepare', 'check']);
        await remote.close();
    }
});

const nftMarkerProbe = String.raw`
import json, os, runpy, subprocess, sys

# Never write into the caller's netns. Only netlink table/ordinary chain
# operations here: no TPROXY modules, service, SSH, PPP, or stand fixture.
assert os.readlink('/proc/self/ns/net') != sys.argv[2]
host = runpy.run_path(sys.argv[1])
req = json.load(sys.stdin)
network, token = req['network'], req['token']
other = 'f' * 32 if token != 'f' * 32 else 'e' * 32
raw = req['nft'].encode()
name = host['TABLE']
header, sep, _ = raw.partition(b'    chain prerouting {\n')
assert sep, 'missing first generated chain'
batch = header + b'    chain marker_probe {\n    }\n}\n'


def nft(*args, data=None):
    return subprocess.run(['/usr/sbin/nft', *args], input=data, capture_output=True, timeout=5, env={'LC_ALL': 'C'})


def checked(*args, data=None):
    result = nft(*args, data=data)
    assert result.returncode == 0, result.stderr.decode()
    return result.stdout


def snapshot():
    return json.loads(checked('-j', '-a', 'list', 'ruleset'))


assert all('metainfo' in row for row in snapshot()['nftables']), 'netns starts with a nonempty ruleset'
if sys.argv[3] == 'fresh':
    checked('-f', '-', data=batch)
    tables = [row['table'] for row in snapshot()['nftables'] if 'table' in row]
    assert len(tables) == 1 and tables[0].get('comment') == token, 'generated operation marker missing from kernel table'
    assert host['nft_marker'](raw, token)
    assert not host['nft_marker'](raw, other)
    legacy = f'create table inet {name}\ntable inet {name} {{\n    comment "{token}"\n}}\n'.encode()
    assert not host['nft_marker'](legacy, token)
    assert not host['nft_marker'](raw.removeprefix(b'create '), token)
    assert host['nft_projection'](token) is not None
else:
    comment = f'    comment "{other}"\n' if sys.argv[3] == 'foreign' else ''
    checked('-f', '-', data=f'create table inet {name} {{\n{comment}    chain original {{\n    }}\n}}\n'.encode())
    before = snapshot()
    # Use the real readback in both pristine-Install and operation-token checks.
    for expected in ('', token):
        try:
            host['network_projection'](network, expected)
        except host['Refusal'] as error:
            assert str(error) == 'ROLLBACK_DRIFT', str(error)
        else:
            raise AssertionError('network guard admitted an existing table')
    assert snapshot() == before
    # Even if a competing table appears after the guard, the exclusive kernel
    # transaction cannot insert the generated chain or overwrite the marker.
    result = nft('-f', '-', data=batch)
    assert result.returncode != 0 and b'File exists' in result.stderr, result.stderr.decode()
    assert snapshot() == before, 'existing kernel table changed despite refusal'
`;


test('generated nft operation marker persists on exclusive creation; existing tables stay unchanged', async t => {
    const unshare = '/usr/bin/unshare';
    const opts = ['--user', '--map-root-user', '--net', '--'];
    if (process.platform !== 'linux' || ![unshare, '/usr/sbin/nft', '/usr/sbin/ip',
        '/usr/bin/python3', '/sys/module/nf_tables'].every(existsSync)) {
        t.skip('requires Linux with nftables already loaded and local namespace tools');
        return;
    }
    const probe = spawnSync(unshare, [...opts, '/usr/bin/true'], { encoding: 'utf8', timeout: 3000 });
    if (probe.status !== 0 && /Operation not permitted|Permission denied/.test(probe.stderr ?? '')) {
        t.skip('unprivileged user/network namespaces unavailable');
        return;
    }
    assert.equal(probe.status, 0, probe.stderr || probe.error?.message);
    let generated;
    const { remote } = fixture(request => {
        if (request.action === 'check') generated = { token: request.backupId, network: request.network,
            nft: Buffer.from(request.files.nft, 'base64').toString('utf8') };
    });
    try { await remote.prepare(args); } finally { await remote.close(); }
    assert.ok(generated);
    const netns = readlinkSync('/proc/self/ns/net');
    const host = join(__dirname, '..', 'rebuildRelayDirectHost.py');
    for (const mode of ['fresh', 'unmarked', 'foreign']) await t.test(mode, () => {
        const result = spawnSync(unshare, [...opts, '/usr/bin/python3', '-I', '-B', '-c', nftMarkerProbe, host, netns, mode],
            { input: JSON.stringify(generated), encoding: 'utf8', timeout: 12000 });
        assert.equal(result.status, 0, result.stderr || result.error?.message);
    });
});

test('masked or wrong machine and invalid generated addresses cannot dispatch writes', async () => {
    for (const response of [{ ...ready, machineId: 'e'.repeat(32) }, { ...ready, masked: true }, { ...ready, ppp: false }]) {
        const { remote, calls } = fixture(() => ok(response));
        await assert.rejects(remote.prepare(args));
        assert.deepEqual(calls, ['connect', 'preflight', ...(response.machineId !== machineId ? ['close'] : [])]);
        await remote.close();
    }
    const { remote, calls } = fixture();
    await assert.rejects(remote.prepare({ ...args, desired: { ...desired, localAddress: '10.255.1.10' } }));
    assert.deepEqual(calls, []);
});

test('wire receipt for settled install refusal releases the coordinator to attempt verified rollback', async () => {
    const { remote } = fixture(input => input.action === 'install'
        ? { code: 70, stderr: 'DIRECT_COMMAND_FAILED\n', stdout: '' } : undefined);
    const plan = await remote.prepare(args);
    await assert.rejects(remote.install(plan, async () => {}), { code: 'REBUILD_L2TP_DIRECT_COMMAND_FAILED', commandSettled: true });
    assert.equal(await remote.rollback(plan, async () => {}), true);
    await remote.close();
});

test('IKE admission codes survive prepare, check and settled no-write install refusals', async () => {
    for (const reason of ['IKE_ACTIVE_RULE_220', 'RULE_220_CONFLICT', 'IKE_ACTIVE_UNMANAGED']) {
        for (const action of ['prepare', 'check', 'install']) {
            const stderr = `DIRECT_${action === 'install' ? 'NO_WRITE_' : ''}${reason}\n`;
            const { remote, calls } = fixture(request => request.action === action ? { code: 70, stdout: '', stderr } : undefined);
            const db = [];
            await assert.rejects(runFreshRelayInstall(nodeId, {
                authorize: () => true, machineId, lock: fn => fn(async () => true),
                inventory: async () => ({ eligible: true, pristine: true }), connect: async () => remote,
                prepare: async () => remote.prepare(args), verifyReservation: async () => {},
                reserve: async () => db.push('reserve'), restore: async () => db.push('restore'),
                finish: async () => assert.fail('must not finish a refused install'),
            }), { code: action === 'install' ? 'REBUILD_L2TP_INSTALL_FAILED' : 'REBUILD_L2TP_DIRECT_PREREQUISITE',
                check: reason, outcome: 'refused' });
            assert.deepEqual(db, action === 'install' ? ['reserve', 'restore'] : []);
            assert.ok(!calls.includes('rollback') && !calls.includes('verify'));
            assert.equal(calls.at(-2), action);
        }
    }
});

test('fresh runtime gate needs an exact no-write receipt after install dispatch', async () => {
    for (const reason of ['RUNTIME_PACKAGE_AUTOSTART_UNSAFE', 'RUNTIME_NATIVE_UNIT_REQUIRED']) {
        for (const noWrite of [false, true]) {
            const stderr = `DIRECT_${noWrite ? 'NO_WRITE_' : ''}${reason}\n`;
            const { remote } = fixture(req => req.action === 'install' ? { code: 70, stdout: '', stderr } : undefined);
            const plan = await remote.prepare(args);
            await assert.rejects(remote.install(plan, async () => {}), noWrite ?
                { code: 'REBUILD_L2TP_DIRECT_PREREQUISITE', check: reason, noHostChanges: true, commandSettled: true } :
                { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', remoteOutcomeUncertain: true });
            assert.equal(await remote.rollback(plan, async () => {}), false);
            await remote.close();
        }
    }
});

test('IKE refusal without the exact install no-write frame leaves the outcome unknown', async () => {
    for (const stderr of ['DIRECT_IKE_ACTIVE_RULE_220\n', 'DIRECT_NO_WRITE_IKE_ACTIVE_RULE_220\n\n']) {
        const { remote } = fixture(request => request.action === 'install' ? { code: 70, stdout: '', stderr } : undefined);
        const plan = await remote.prepare(args);
        await assert.rejects(remote.install(plan, async () => {}), { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', remoteOutcomeUncertain: true });
        assert.equal(await remote.rollback(plan, async () => {}), false);
        await remote.close();
    }
});

test('definite nonzero permits exact rollback, but SSH failure, signal, timeout or lost receipt never do', async () => {
    for (const outcome of [{ code: 70, stderr: 'DIRECT_COMMAND_FAILED\n', stdout: '' }, { code: 70 }, { code: null }, { code: 75 }, { code: 0, stdout: '{}' }, new Error(desired.psk)]) {
        const { remote, calls } = fixture(input => {
            if (input.action !== 'install') return undefined;
            if (outcome instanceof Error) throw outcome;
            return { stderr: desired.psk, ...outcome };
        });
        const plan = await remote.prepare(args);
        const uncertain = outcome.code !== 70 || outcome.stderr !== 'DIRECT_COMMAND_FAILED\n';
        await assert.rejects(remote.install(plan, async () => {}), err => {
            assert.equal(err.remoteOutcomeUncertain === true, uncertain);
            assert.ok(!String(err.stack).includes(desired.psk));
            return true;
        });
        assert.equal(await remote.rollback(plan, async () => {}), !uncertain);
        assert.equal(calls.includes('rollback'), !uncertain);
        assert.equal(await remote.rollback(plan, async () => {}), false);
        await remote.close();
    }
});
