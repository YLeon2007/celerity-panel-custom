'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { mkdtempSync, rmSync } = require('node:fs');
const { join } = require('node:path');

// The relay's systemctl show emits the following three separate rows, not one
// property containing a list. Only this managed oneshot may repeat ExecStart.
const unitHarness = String.raw`
import pathlib, sys
h = {'__name__': 'fixture'}
exec(compile(pathlib.Path(sys.argv[1]).read_bytes(), sys.argv[1], 'exec'), h)
net, x = h['NET_UNIT'], h['X']
lines = [
    'ExecStart={ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/celerity-rebuild-l2tp/ingress.nft ; ignore_errors=no ; start_time=[Fri 2026-11-20 14:15:46 CET] ; stop_time=[Fri 2026-11-20 14:15:46 CET] ; pid=32666 ; code=exited ; status=0 }',
    'ExecStart={ path=/usr/sbin/ip ; argv[]=/usr/sbin/ip -4 route add local 0.0.0.0/0 dev lo table 100 ; ignore_errors=no ; start_time=[Fri 2026-11-20 14:15:46 CET] ; stop_time=[Fri 2026-11-20 14:15:46 CET] ; pid=32672 ; code=exited ; status=0 }',
    'ExecStart={ path=/usr/sbin/ip ; argv[]=/usr/sbin/ip -4 rule add priority 10077 from 10.255.191.0/24 fwmark 100 table 100 ; ignore_errors=no ; start_time=[Fri 2026-11-20 14:15:46 CET] ; stop_time=[Fri 2026-11-20 14:15:46 CET] ; pid=32678 ; code=exited ; status=0 }',
]

def show(name, rows, kind='oneshot', tail=()):
    def command(*args, **kwargs):
        assert args[:4] == ('/usr/bin/systemctl', '--no-pager', 'show', '--all')
        assert args[-1] == name and kwargs == {'unit_show': True}
        return ('\n'.join([f'Type={kind}', *rows, 'LoadState=loaded', 'ActiveState=active', 'SubState=exited', *tail]) + '\n').encode()
    h['command'] = command
    return h['unit'](name)

info = show(net, lines)
assert info['ExecStart'] == ' '.join(line.split('=', 1)[1] for line in lines)
assert {k: info[k] for k in ('Type', 'LoadState', 'ActiveState', 'SubState')} == {
    'Type': 'oneshot', 'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'exited'}
assert show(x, lines[:1], 'simple')['ExecStart'] == lines[0].split('=', 1)[1]
for name, rows, kind, tail in (
    (x, lines, 'oneshot', ()),
    (net, lines, 'simple', ()),
    (net, lines[:2], 'oneshot', ()),
    (net, lines + lines[:1], 'oneshot', ()),
    (net, lines[:2] + ['ExecStart='], 'oneshot', ()),
    (net, lines, 'oneshot', ('ActiveState=active',)),
):
    try:
        show(name, rows, kind, tail)
    except h['Refusal'] as error:
        assert str(error) == 'PREREQUISITE'
    else:
        raise AssertionError('accepted unexpected duplicate property rows')
`;

test('DIRECT unit reader preserves the real three-row managed oneshot ExecStart only', () => {
    const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', unitHarness,
        join(__dirname, '..', 'rebuildRelayDirectHost.py')], { encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 0, result.stderr || String(result.error));
});

// Exercise the real file publication/manifest/rollback code in a disposable
// in-worktree root. Runtime facts and privileged UID are modeled; no host
// commands, sockets, or service manager are called by this harness.
const harness = String.raw`
import contextlib, json, os, pathlib, runpy, sys
source, root, scenario = sys.argv[1:]
network_fixture = runpy.run_path(str(pathlib.Path(source).parent / 'tests/helpers/rebuildRelayNetworkFixture.py'))
os.umask(0o077)
h = {'__name__': 'fixture'}
exec(compile(pathlib.Path(source).read_bytes(), source, 'exec'), h)
root = pathlib.Path(root)
h['NETWORK_RUN'] = str(root / 'run')
for k in ('MAIN', 'BRIDGE', 'SYSTEM', 'NET', 'DROP_DIR', 'DROP', 'NFT_DIR', 'NFT_FILE', 'VAULT'):
    h[k] = str(root) + h[k]
h['NAMES'] = {k: str(root) + v for k, v in h['NAMES'].items()}
XL, IKE, X, B, NET = (h[k] for k in ('XL','IKE','X','B','NET_UNIT'))
names = h['NAMES']
R = h['Refusal']
for key, p in names.items():
    if key not in ('drop', 'nft'):
        pathlib.Path(p).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(h['VAULT']).parent.mkdir(parents=True, exist_ok=True)
for k in ('main', 'lns', 'starter', 'secrets', 'chap'):
    pathlib.Path(names[k]).write_bytes(b'original-' + k.encode())

real_os = os
class FixtureStat:
    def __init__(self, value):
        self.value = value
        self.st_uid = self.st_gid = 0
    def __getattr__(self, name):
        return getattr(self.value, name)
class FixtureOS:
    def __getattr__(self, name):
        return getattr(real_os, name)
    def fstat(self, fd):
        return FixtureStat(real_os.fstat(fd))
    def fchown(self, fd, uid, gid):
        assert uid == gid == 0 and os.readlink('/proc/self/fd/' + str(fd)).startswith(str(root) + '/')
    def geteuid(self):
        return 0
h['os'] = FixtureOS()
@contextlib.contextmanager
def directory(path, private=False):
    assert pathlib.Path(path).is_relative_to(root)
    fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY)
    try:
        if private:
            assert os.fstat(fd).st_mode & 0o777 == 0o700
        yield fd
    finally:
        os.close(fd)
h['directory'] = directory
h['boot'] = lambda: 'boot-fixture'
h['preflight'] = lambda machine, **kwargs: {'machineId': machine, 'ppp': True, 'unitsLoaded': True, 'masked': False}
h['vpn_empty'] = lambda **kw: True
h['working'] = lambda u: u['ActiveState'] == 'active'
h['native_vpn'] = lambda info, name: True
units = {}
for name in (XL, IKE, X, B, NET):
    units[name] = dict(LoadState='not-found' if name == NET else 'loaded', ActiveState='inactive',
        SubState='dead', MainPID='0', InvocationID='', UnitFileState='disabled', DropInPaths='',
        NeedDaemonReload='no', FragmentPath='' if name == NET else '/fixture/' + name)
units[X].update(ActiveState='active', SubState='running', MainPID='1', InvocationID='original')
original_units = {k: dict(v) for k, v in units.items()}
before = dict(boot='boot-fixture', files={k: h['read'](p) for k, p in names.items()},
              units=original_units, bridge=None, globalFiles={}, sockets=[['tcp', '127.0.0.1', 8080]])
h['unit'] = lambda name: dict(units[name])
h['observe'] = lambda machine, d, transit, **kw: before
# Already-prepared PPP; the joined fixture exercises actual preparation.
h['observe_ppp_preparation'] = lambda *, fresh=True: dict(missing=[], persist=False, builtin=[], policy='fixture')
h['apply_ppp_preparation'] = lambda expected: h['need'](expected == h['observe_ppp_preparation'](), 'BASELINE_CHANGED')
h['require_network_observers'] = lambda: None
h['validate_profiles'] = lambda after: None
policy = dict(nft=None, rule=False, route=False)
commands = []
h['network_projection'] = lambda d, t, **kw: dict(policy)
h['nft_projection'] = lambda t: policy['nft']
h['no_jobs'] = lambda names: None
h['xray_users'] = lambda record, info, rows, transit: before['sockets']
h['sock_rows'] = lambda: []

def sc(*args, **kw):
    commands.append(args)
    if args[0] == 'daemon-reload':
        if os.path.exists(h['NET']):
            units[NET].update(LoadState='loaded', FragmentPath=h['NET'])
        else:
            units[NET] = dict(original_units[NET])
        units[XL]['DropInPaths'] = h['DROP'] if os.path.exists(h['DROP']) else ''
    if args[0] == 'restart':
        units[X].update(ActiveState='active', MainPID='2', InvocationID='new' + str(len(commands)))
    if args[0] == 'start':
        policy.update(nft='fixture-nft-digest', rule=True, route=True)
        units[IKE].update(ActiveState='active', MainPID='4', InvocationID='ike')
        units[NET].update(ActiveState='active', InvocationID='net')
        if scenario == 'known-failure':
            units[XL].update(ActiveState='failed', SubState='failed')
            raise R('COMMAND_FAILED')
        units[XL].update(ActiveState='active', MainPID='3', InvocationID='lns')
    if args[0] == 'stop':
        n = args[1]
        overrides = {k: units[n][k] for k in ('LoadState', 'FragmentPath', 'DropInPaths')}
        units[n] = dict(original_units[n], **overrides)
h['sc'] = sc

def command(*args, **kw):
    commands.append(args)
    if args[:3] == ('/usr/sbin/ip', '-4', 'rule'):
        policy['rule'] = False
    elif args[:3] == ('/usr/sbin/ip', '-4', 'route'):
        policy['route'] = False
    elif args == ('/usr/sbin/nft', '-c', '-f', '-'):
        assert pathlib.Path(h['manifest_path'](token)).is_file()
    elif args == ('/usr/sbin/nft', 'delete', 'table', 'inet', h['TABLE']):
        policy['nft'] = None
    else:
        raise RuntimeError('unexpected command')
h['command'] = command

def installed_runtime(d, token, baseline, after):
    assert policy == {'nft': 'fixture-nft-digest', 'rule': True, 'route': True}
    assert all(h['read'](names[k]) == v for k, v in after.items())
    return dict(nft=policy['nft'], invocations=[units[n]['InvocationID'] for n in (X, XL, IKE, NET)],
                files=h['file_generations']())
h['installed_runtime'] = installed_runtime

d = dict(clientCidr='10.255.1.0/24', tproxyPort=12345, fwmark=77, routeTable=177)
token = 'd' * 32
machine = 'a' * 32
machine_file = root / 'etc/machine-id'
machine_file.write_text(machine + '\n', encoding='ascii')
h['open'] = lambda path, *args, **kw: open(machine_file if path == '/etc/machine-id' else path, *args, **kw)
baseline = h['dispatch'](dict(action='prepare', machineId=machine, network=d))['baseline']
req = dict(machineId=machine, backupId=token, baseline=baseline, network=d)
raw = dict(main=h['encode']({'inbounds': [{'tag':'relay-l2tp-a','port':12345},
    {'tag':'rebuild-relay-ingress','listen':'127.0.0.1','port':23456}]}),
    nft=network_fixture['nft_source'](source, d, token),
    **{k: ('generated-' + k).encode() for k in ('ike','lns','options','chap','secrets')})
files = {k: h['b64'](v) for k,v in raw.items()}
assert h['dispatch'](dict(req, action='check', files=files)) == {'ok': True, 'backupId': token}
assert not commands and not os.path.exists(h['VAULT'])
try:
    assert h['dispatch'](dict(req, action='install', files=files)) == {'ok': True, 'backupId': token}
    assert scenario != 'known-failure'
except R as e:
    assert scenario == 'known-failure' and str(e) == 'COMMAND_FAILED'
assert h['read'](names['main']) != before['files']['main']
assert os.stat(h['manifest_path'](token)).st_mode & 0o777 == 0o600
if scenario == 'fenced-restore':
    path, original, backup = h['read_manifest'](token)
    epoch = 'installed-chap-v2:' + 'e'*32
    for malformed in (epoch + '\n', epoch.upper(), epoch[:-1]):
        replacement = h['entry'](h['encode'](dict(backup, phase=malformed)))
        h['write'](path, original, replacement)
        for action in ('verify', 'rollback'):
            count = len(commands)
            try: h['dispatch'](dict(req, action=action))
            except R as error: assert str(error) in ('ROLLBACK_DRIFT', 'RUNTIME_UNPROVED')
            else: raise AssertionError('malformed installed phase accepted')
            assert len(commands) == count and h['read'](path) == replacement
        original = replacement
    h['write'](path, original, h['entry'](h['encode'](dict(backup, phase=epoch))))
if scenario != 'known-failure':
    assert h['dispatch'](dict(req, action='verify')) == {'ok': True, 'backupId': token}
if scenario in ('same-bytes-drift', 'changed-file'):
    p = pathlib.Path(names['main'])
    q = p.with_name('replace')
    q.write_bytes(p.read_bytes() if scenario == 'same-bytes-drift' else b'foreign')
    q.replace(p)
    count = len(commands)
    try:
        h['dispatch'](dict(req, action='rollback'))
    except R as e:
        assert str(e) == 'ROLLBACK_DRIFT'
    else:
        raise AssertionError('later file generation was overwritten')
    assert len(commands) == count
else:
    assert h['dispatch'](dict(req, action='rollback')) == {'ok': True, 'backupId': token}
    assert {k: h['read'](p) for k,p in names.items()} == before['files']
    assert not any(policy.values())
    manifest = json.loads(h['raw'](h['read'](h['manifest_path'](token), h['MAX_FILE'])))
    assert manifest['phase'] == 'rolled-back'
    assert all(args[0:2] not in (('stop', X), ('stop', B), ('restart', B)) for args in commands)
    for wrong in (token, '../another', 'e' * 32):
        try:
            h['dispatch'](dict(req, backupId=wrong, action='rollback'))
        except (R, FileNotFoundError):
            pass
        else:
            raise AssertionError('stale or foreign backup accepted')
print('ok')
`;

for (const scenario of ['install-and-restore', 'fenced-restore', 'known-failure', 'same-bytes-drift', 'changed-file']) {
    test(`host payload: ${scenario} (real files, modeled systemd/nft/PPP)`, () => {
        const dir = mkdtempSync(join(process.cwd(), '.direct-local-fixture-'));
        try {
            const result = spawnSync('python3', ['-I', '-B', '-c', harness,
                join(__dirname, '../rebuildRelayDirectHost.py'), dir, scenario], { encoding: 'utf8', timeout: 10000 });
            assert.equal(result.status, 0, result.stderr || result.error?.message);
            assert.equal(result.stdout, 'ok\n');
        } finally { rmSync(dir, { recursive: true, force: true }); }
    });
}
