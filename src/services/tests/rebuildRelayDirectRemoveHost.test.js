'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { createInterface } = require('node:readline');
const { createHash } = require('node:crypto');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { gunzipSync } = require('node:zlib');
const { createRelayDirect } = require('../rebuildRelayDirect');
const attested = require('./helpers/rebuildRelayDirectWire');
const { composeRebuildRelayPair } = require('../rebuildRelayInstallSteps');
const composeRebuildRelayMain = (...args) => composeRebuildRelayPair(...args).main;
const { composeRebuildProfiles, syntheticTunnelSettings } = require('../../modules/relay-l2tp/tests/helpers/rebuildComposerFixture');

const nodeId = 'a'.repeat(24), backupId = 'b'.repeat(32), machineId = 'c'.repeat(32);
const network = { clientCidr: '10.255.1.0/24', tproxyPort: 12345, fwmark: 77, routeTable: 177 };
const relay = { _id: nodeId, cascadeRole: 'relay', type: 'xray', active: true, ip: '192.0.2.19', port: 22001,
    xray: { inboundTag: 'client', security: 'none', transport: 'tcp', apiPort: 31001 } };
const controls = ['panel.invalid', '192.0.2.19'];
const compose = (nodes, links, users, installed) => composeRebuildProfiles({ nodes, links,
    controlPlaneAddresses: controls, usersByNode: { [nodeId]: users }, followRelayStates: installed ? [{
        node: nodeId, routingMode: 'follow-relay', routingVersion: 1, status: 'installed', desiredState: 'installed',
        secretRevision: 1, tproxyPort: network.tproxyPort,
    }] : [],
}).find(p => p.nodeId === nodeId && p.profile === 'main').config;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

function loadChapEpochLegacySource() {
    // Frozen test data, not a runtime module. See tests/fixtures/README.md.
    const path = join(__dirname, '../../../tests/fixtures/rebuildRelayDirectHost-chap-epoch.py.gz');
    const size = 173197;
    const bytes = gunzipSync(readFileSync(path), { maxOutputLength: size });
    assert.equal(bytes.length, size, 'chap-epoch legacy fixture byte length mismatch');
    assert.equal(sha(bytes), '687c355fe82a73c388c50aff66ba6435f34e48d2281f6a707de30ddf799cc7d0',
        'chap-epoch legacy fixture SHA-256 mismatch');
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
}

const old = JSON.stringify(compose([relay], [], [], false));
const installed = composeRebuildRelayMain({ main: old, bridge: null }, {
    nodeId, controlPlaneAddresses: controls, carryDomain: false, tproxyPort: network.tproxyPort,
    mainSha256: sha(old), bridgeSha256: null,
});
const exits = [2, 3].map(n => ({ ...relay, _id: String(n).repeat(24), ip: `192.0.2.${n}`, cascadeRole: 'bridge' }));
const links = exits.map((node, i) => ({ _id: `changed-${i}`, portalNode: nodeId, bridgeNode: node._id,
    mode: i === 0 ? 'reverse' : 'forward', _rebuildVless: syntheticTunnelSettings(i),
    tunnelPort: 20002 + i, tunnelUuid: `00000000-0000-4000-8000-00000000000${i}`,
    ...(i === 1 && { geoRouting: { enabled: true, domains: ['full:geo.invalid'], geoip: ['ru'] } }),
}));
const laterArgs = [[{ ...relay, port: 22011, aclRules: ['reject(example.invalid)', 'reject(all)'] }, ...exits], links,
    [{ userId: 'new-user', xrayUuid: '00000000-0000-4000-8000-000000000005' }]];
const applied = compose(...laterArgs, true);
const expected = compose(...laterArgs, false);

// Actual helper, file IO, flock, manifest, parser, and mutation sequence.
// No subprocess can run a real systemctl, ip, nft, Xray, ss or IPsec command.
const fixture = String.raw`
import contextlib, copy, ctypes, errno, io, json, os, pathlib, runpy, shlex, subprocess, sys, types
from pathlib import Path
source, tmp, scenario = sys.argv[1:]
joined_epoch = scenario.startswith('epoch-remove-')
network_fixture = runpy.run_path(str(Path(source).parent / 'tests/helpers/rebuildRelayNetworkFixture.py'))
f = json.loads(sys.stdin.readline()) if scenario == 'retire-active' or joined_epoch else json.load(sys.stdin)
root = Path(tmp)
os.umask(0o077)
h = {'__name__': 'fixture'}
mock_faults = []
def no_host_dispatch(event, _):
    if event in {'subprocess.Popen','os.system','os.posix_spawn','os.exec','os.fork','os.kill','os.killpg'} or event.startswith('socket.'):
        mock_faults.append(event)
        raise AssertionError('non-modeled host dispatch')
sys.addaudithook(no_host_dispatch)
if 'command' in f:
    argv = shlex.split(f['command'])
    limits = ['1s', '9s'] if joined_epoch else ['1s', '22s'] if scenario == 'retire-active' else ['4s', '125s']
    assert argv[:-1] == ['/usr/bin/timeout', '-k', *limits,
                         '/usr/bin/python3', '-I', '-B', '-c']
    exec(compile(argv[-1], '<DIRECT command>', 'exec'), h)
else:
    exec(compile(Path(source).read_bytes(), source, 'exec'), h)
def forbidden_signal(*args):
    mock_faults.append('unexpected pidfd signal')
    raise AssertionError('unexpected pidfd signal')
h['signal'] = types.SimpleNamespace(pidfd_send_signal=forbidden_signal, SIGTERM=15)
for k in ('MAIN', 'BRIDGE', 'XRAY', 'SYSTEM', 'NET', 'DROP_DIR', 'DROP', 'NFT_DIR', 'NFT_FILE', 'VAULT'):
    h[k] = str(root) + h[k]
h['NAMES'] = {k: str(root) + v for k, v in h['NAMES'].items()}
P, R, Refusal = h['NAMES'], h['read'], h['Refusal']
X, B, XL, IKE, NET = [h[k] for k in ('X', 'B', 'XL', 'IKE', 'NET_UNIT')]
for k, p in P.items():
    if k not in ('nft', 'drop'):
        Path(p).parent.mkdir(parents=True, exist_ok=True)
Path(h['VAULT']).parent.mkdir(parents=True, exist_ok=True)
Path(h['XRAY']).parent.mkdir(parents=True)
Path(h['XRAY']).write_text('modeled executable')
Path(h['BRIDGE']).parent.mkdir(parents=True)
for k, data in dict(main=f['old'], starter='# initial\n', lns='# stock\n', secrets='# initial\n', chap='# initial\n').items():
    Path(P[k]).write_text(data)
if scenario.startswith('chap-unterminated-'):
    Path(P['chap']).write_bytes(b'# original comment with opaque byte \xff')

def stat(value):
    return types.SimpleNamespace(st_uid=0, st_gid=0, **{k: getattr(value, k) for k in ('st_mode','st_nlink','st_size','st_dev','st_ino','st_ctime_ns')})
class FixtureOS:
    def __getattr__(self, name): return getattr(os, name)
    def lstat(self, path):
        return os.lstat(root / path.lstrip('/') if path.startswith('/run/') else path)
    def listdir(self, path):
        return os.listdir(root / 'run' if path == '/run' else path)
    def fstat(self, fd): return stat(os.fstat(fd))
    def stat(self, path, *args, **kw):
        if path.startswith('/proc/'):
            return types.SimpleNamespace(st_uid=0, st_gid=0)
        return os.stat(path, *args, **kw)
    def fchown(self, fd, uid, gid):
        assert uid == gid == 0 and os.readlink('/proc/self/fd/' + str(fd)).startswith(tmp + '/')
    def geteuid(self): return 0
h['os'] = FixtureOS()
(root / 'run').mkdir(exist_ok=True)
h['NETWORK_RUN'] = str(root / 'run')
@contextlib.contextmanager
def directory(path, private=False):
    assert Path(path).is_relative_to(root)
    fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY)
    try:
        if private: assert os.fstat(fd).st_mode & 0o777 == 0o700
        yield fd
    finally:
        os.close(fd)
h['directory'] = directory
machine_file = root / 'etc/machine-id'
machine_file.write_text(f['machineId'] + '\n')
h['read'] = lambda path, *args: R(str(machine_file) if path == '/etc/machine-id' else path, *args)
h['open'] = lambda path, *args, **kw: open(machine_file if path == '/etc/machine-id' else path, *args, **kw)

def preflight(machine, *, fresh=False):
    h['need'](machine == f['machineId'], 'IDENTITY')
    return dict(machineId=machine, ppp=True, masked=False, unitsLoaded=True)
h['preflight'] = preflight
# Already-prepared PPP; the joined fixture exercises actual preparation.
h['observe_ppp_preparation'] = lambda: dict(missing=[], persist=False, builtin=[], policy='fixture')
h['apply_ppp_preparation'] = lambda expected: h['need'](expected == h['observe_ppp_preparation'](), 'BASELINE_CHANGED')
h['require_network_observers'] = lambda: None
if not joined_epoch:
    h['boot'] = lambda: 'fixture-boot'
    h['ppp_empty'] = lambda: not (testing and scenario == 'active-ppp')
h['in_cgroup'] = lambda pid, info: pid == info['MainPID']
def modeled_xray_argv(info, path=None):
    expected_unit = B if path == h['BRIDGE'] else X
    h['need'](info['MainPID'] == units[expected_unit]['MainPID'] and h['working'](info), 'RUNTIME_UNPROVED')
    return info['MainPID']
original_xray_argv = h['xray_argv']
h['xray_argv'] = modeled_xray_argv
units = {}
for n in (X, B, XL, IKE, NET):
    units[n] = dict(LoadState='loaded' if n != NET else 'not-found', ActiveState='inactive', SubState='dead',
        MainPID='0', InvocationID='', NeedDaemonReload='no', DropInPaths='', User='', Group='', PrivateNetwork='no',
        UnitFileState='enabled' if n in (X, XL) else ('disabled' if n != NET else ''),
        FragmentPath='/usr/lib/systemd/system/' + n if n != NET else '', KillMode='control-group',
        Requires='sysinit.target system.slice' if n != NET else '', After='', ExecStartPre='', ExecStartPost='',
        RequiredBy='', BoundBy='', ConsistsOf='', PropagatesStopTo='', Conflicts='shutdown.target', ConflictedBy='',
        Wants='', BindsTo='', Upholds='', Type='simple', EnvironmentFiles='', ExecStopPost='')
units[XL]['ExecStart'] = '{ path=/usr/sbin/xl2tpd ; argv[]=/usr/sbin/xl2tpd -D ; }'
if scenario == 'chap-inspect-active' or joined_epoch:
    fragment = Path(h['SYSTEM'], XL)
    unit_helper = Path(source).parent.parent / 'modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py'
    fragment.write_bytes(runpy.run_path(str(unit_helper))['UNIT'] if joined_epoch else b'modeled native unit')
    fragment.chmod(0o644)
    if not joined_epoch: h['NATIVE_XL_SHA'] = h['digest'](fragment.read_bytes())
    units[XL].update(FragmentPath=str(fragment), ControlGroup=h['SESSION_GROUP'])
    h['SESSION_GLOBAL'] = {}
    h['session_binary'] = lambda path: (path, 'modeled stock binary generation')
    h['pwd'] = types.SimpleNamespace(getpwnam=h['pwd'].getpwnam, getpwuid=lambda uid: types.SimpleNamespace(pw_dir='/root'))
    for leaf in ('ip-pre-up.d', 'ip-up.d', 'ip-down.d'):
        folder = root / 'etc/ppp' / leaf
        folder.mkdir()
        if leaf != 'ip-pre-up.d': (folder / '0000usepeerdns').touch()
    (root / 'root').mkdir()
    @contextlib.contextmanager
    def session_directory(path, private=False):
        projected = (path in ('/etc/ppp', '/root') or path.startswith('/etc/ppp/') or
                     joined_epoch and path in ('/etc/ipsec.d', '/proc', '/sys/fs/cgroup' + h['SESSION_GROUP']))
        with directory(str(root) + path if projected else path, private) as fd:
            yield fd
    h['directory'] = session_directory
units[IKE]['ExecStart'] = '{ path=/usr/sbin/ipsec ; argv[]=/usr/sbin/ipsec start --nofork ; }'
units[X].update(ActiveState='active', SubState='running', MainPID='10', InvocationID='old-main')
if joined_epoch:
    epoch = '12345678-1234-1234-1234-123456789abc'
    group_path = '/sys/fs/cgroup' + h['SESSION_GROUP']
    group = root / group_path[1:]
    group.mkdir(parents=True)
    (group / 'cgroup.stat').write_bytes(b'nr_descendants 0\nnr_dying_descendants 0\n')
    proc_net = root / 'proc/self/net'
    proc_net.mkdir(parents=True)
    (proc_net / 'pppol2tp').write_bytes(h['SESSION_L2TP_HEADER'])
    lstat = h['os'].lstat
    h['os'].lstat = lambda path: os.lstat(group) if path == group_path else lstat(path)
    def pidfd_open(pid):
        assert pid == int(units[XL]['MainPID'])
        return os.open(group, os.O_DIRECTORY)
    h['os'].pidfd_open = pidfd_open
    starts = {}
    def proc_open(path, *args, **kw):
        if path == '/proc/sys/kernel/random/boot_id': return io.StringIO(epoch + '\n')
        if path == '/proc/devices': return io.BytesIO(b'Character devices:\n108 ppp\n\nBlock devices:\n')
        if path == '/proc/net/dev': return io.StringIO('Inter-| Receive | Transmit\n face |bytes\n lo: 0\n')
        if path.startswith('/proc/') and path.endswith('/stat'):
            pid = path.split('/')[2]
            return io.BytesIO(f"{pid} (fixture) S {'0 ' * 18}{starts[pid]}\n".encode())
        assert path == '/etc/machine-id', path
        return open(machine_file, *args, **kw)
    @contextlib.contextmanager
    def session_process(proc, pid, main, binaries, watch):
        assert pid == main == int(units[XL]['MainPID'])
        watch()
        yield None, starts[str(pid)], b'/usr/sbin/xl2tpd\0-D\0'
    @contextlib.contextmanager
    def route_socket(family, kind, protocol):
        assert (family, kind, protocol) == (16, 3, 0)
        def bind(addr): assert addr == (0, 17)
        yield types.SimpleNamespace(bind=bind)
    h.update(open=proc_open, ppp_device=lambda: True, session_fs=lambda *_: None,
             session_process=session_process, select=types.SimpleNamespace(POLLIN=1,
                 poll=lambda: types.SimpleNamespace(register=lambda *_: None, poll=lambda _: [])),
             socket=types.SimpleNamespace(AF_NETLINK=16, SOCK_RAW=1, SOCK_NONBLOCK=2, socket=route_socket))
if scenario.startswith('xtls-'):
    start = f"{h['XRAY']} run -config {h['MAIN']}"
    xtls = Path(h['SYSTEM'], 'xray.service.d', '10-donot_touch_single_conf.conf')
    xtls.parent.mkdir()
    xtls_bytes = f'# Do not edit; create a separate override instead.\n\n[Service]\nExecStart=\nExecStart={start}\n'.encode()
    xtls.write_bytes(xtls_bytes)
    xtls.chmod(0o644)
    xtls_inode = xtls.stat().st_ino
    units[X].update(DropInPaths=str(xtls), ExecStart=f"{{ path={h['XRAY']} ; argv[]={start} ; ignore_errors=no ; "
                                                   'start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }')
    def proc_cmdline(path, mode):
        if path == '/etc/machine-id':
            return open(machine_file, mode)
        assert (path, mode) == ('/proc/' + units[X]['MainPID'] + '/cmdline', 'rb')
        return io.BytesIO(b'\0'.join(arg.encode() for arg in (h['XRAY'], 'run', '-config', h['MAIN'], '')))
    def realpath(path):
        assert path == '/proc/' + units[X]['MainPID'] + '/exe'
        return h['XRAY']
    class XtlsOS(FixtureOS):
        path = types.SimpleNamespace(realpath=realpath, **{k: getattr(os.path, k) for k in
                                     ('split', 'basename', 'lexists', 'join', 'dirname')})
    h.update(xray_argv=lambda info, path=h['MAIN']: original_xray_argv(info, path), os=XtlsOS(), open=proc_cmdline)
stock_units = copy.deepcopy(units)
stock_rules = [{'priority': n, 'src': 'all', 'table': t} for n, t in [(0, 255), (32766, 254), (32767, 253)]]
foreign_rule = dict(priority=10078, src='198.51.100.0/24', table=201)
foreign_route = dict(dst='198.51.100.0/24', table=201, dev='fixture0')
network, token = f['network'], f['backupId']
nft = network_fixture['nft_source'](source, network, token).decode()
nft_rows = network_fixture['nft_rows'](network, token)
policy = {'nft': False, 'rule': False, 'route': False}
changes, checks = [], []
testing = False
udp_address, udp_port = '192.0.2.19', 54453
after_preview = False
ipsec_live = False
ipsec_appears_at_recount = False

def sc(*args):
    cmd, *rest = args
    if args == ('list-jobs','--no-legend','--plain'):
        pending_after = {'xl-stop-job': ('stop', XL), 'xl-reset-job': ('reset-failed', XL)}.get(scenario)
        return f'42 {XL} stop running\n'.encode() if pending_after in changes else b''
    changes.append(args)
    if args == ('daemon-reload',):
        if Path(h['NET']).exists():
            net_bytes = Path(h['NET']).read_bytes()
            lines = net_bytes.decode().splitlines()
            pre = next((line.split('=', 1)[1] for line in lines if line.startswith('ExecStartPre=')), '')
            legacy = f'Requires={X}' in lines
            units[NET].update(LoadState='loaded', FragmentPath=h['NET'], UnitFileState='static',
                              Type='oneshot', Requires=X if legacy else '', Wants='' if legacy else X, RequiredBy=XL,
                              After=next(line.split('=', 1)[1] for line in lines if line.startswith('After=')),
                              ExecStartPre=f'{{ path=/usr/bin/systemctl ; argv[]={pre} ; ignore_errors=no ; }}' if pre else '',
                              ExecStart=network_fixture['systemctl_start'](net_bytes, 'quoted' if scenario == 'apply' else 'native'))
            units[XL].update(DropInPaths=h['DROP'], Requires=f'{NET} {IKE}', After=f'{NET} {IKE}')
            units[X]['RequiredBy'], units[IKE]['RequiredBy'] = (NET if legacy else ''), XL
        else:
            for n in (NET, XL, IKE): units[n] = dict(stock_units[n])
            units[X]['RequiredBy'] = ''
    elif cmd == 'start' and rest == [XL]:
        for n, pid, sub in [(XL,'11','running'), (IKE,'12','running'), (NET,'0','exited')]:
            units[n].update(ActiveState='active', SubState=sub, MainPID=pid,
                            InvocationID=({XL:'b', IKE:'c', NET:'d'}[n] * 32 if joined_epoch else
                                          '1'*32 if n == XL and scenario == 'chap-inspect-active' else n + '-installed'))
        policy.update(nft=True, rule=True, route=True)
    elif args == ('restart', X):
        invocation = f'{40 + len(changes):032x}' if joined_epoch else 'main-' + str(len(changes))
        units[X].update(MainPID=str(40 + len(changes)), InvocationID=invocation)
    elif cmd in ('stop', 'reset-failed') and len(rest) == 1 and rest[0] in (XL, IKE, NET):
        if testing and scenario == 'unknown-stop':
            raise Refusal('COMMAND_FAILED')
        if args == ('stop', XL) and scenario == 'chap-sync-remove':
            chap.write_bytes(chap.read_bytes() + b'\n# appended during Remove\r\n')
        if args == ('stop', XL) and scenario == 'chap-unterminated-list-suffix':
            chap.write_bytes(chap.read_bytes() + suffix)
        name = rest[0]
        if testing and cmd == 'stop' and ((name == XL and scenario.startswith(('xl-stop-', 'xl-reset-')))
                                          or (name == IKE and scenario == 'ike-stop-failed')):
            # The stop client can succeed even when xl2tpd exits 1 on SIGTERM.
            units[name].update(ActiveState='failed', SubState='failed',
                               MainPID='11' if scenario == 'xl-stop-live-pid' else '0')
            if scenario == 'xl-stop-nonzero':
                raise Refusal('COMMAND_FAILED')
        else:
            units[name].update(ActiveState='inactive', SubState='dead', InvocationID='',
                               MainPID='11' if args == ('reset-failed', XL) and scenario == 'xl-reset-live-pid' else '0')
    else:
        raise AssertionError(args)
    return b''
def command(*a, data=None):
    global l2tp_reads, ipsec_live, ipsec_appears_at_recount
    if len(a) == 6 and a[:4] == ('/usr/bin/systemctl','--no-pager','show','--all'):
        flag, name = a[4:]
        assert flag.startswith('--property=') and name in units
        return ''.join(f'{key}={units[name].get(key, "")}\n' for key in flag.removeprefix('--property=').split(',')).encode()
    if a[:2] == ('/usr/bin/systemctl','--no-pager'): return sc(*a[2:])
    if a[0] == '/usr/bin/setpriv':
        assert a == ('/usr/bin/setpriv','--reuid=0','--regid=0','--init-groups',h['XRAY'],
                     'run','-test','-format','json','-config',a[-1]) and a[-1] in (h['MAIN'],'stdin:')
        checks.append(a[-1])
        if a[-1] == 'stdin:' and testing:
            assert json.loads(data) == (f['expected'] if scenario.startswith('apply') else json.loads(f['old']))
            if scenario == 'invalid-candidate': raise Refusal('CANDIDATE_INVALID')
        return b''
    if a == ('/usr/sbin/nft', '-c', '-f', '-'): return b''
    if scenario == 'apply-quiescent-dependent':
        if a == ('/usr/bin/stat','-f','--format=%T','/sys/fs/cgroup/system.slice'):
            return b'cgroup2fs\n'
        if a == ('/usr/bin/find','-P','/sys/fs/cgroup/system.slice','-mindepth','1','-maxdepth','1',
                 '-name','xl2tpd.service','-printf','%y\n'):
            return b'd\n'
        if a == ('/usr/bin/head','-c','1024','/sys/fs/cgroup/system.slice/xl2tpd.service/cgroup.events'):
            return b'populated 1\nfrozen 0\n' if group_populated else b'populated 0\nfrozen 0\n'
        if a == ('/usr/bin/ps','-ww','-e','-o','pid=','-o','comm='):
            return b'    1 systemd\n   40 ps\n' + (b'  999 pppd\n' if stray_pppd else b'')
        if a == ('/usr/bin/ss','-H','-aun','sport = :1701'):
            return b''
        if a == ('/usr/sbin/ip','-j','-details','link','show'):
            return b'[{"ifindex":1,"ifname":"lo","link_type":"loopback"}]\n'
        if a == ('/usr/bin/head','-c','1048577','/proc/self/net/pppol2tp'):
            l2tp_reads += 1
            return h['SESSION_L2TP_HEADER'] + (b'\nTUNNEL \'tunl 1\', Y 0\n 00000000 0/0/0 0/0/0\n'
                                              if l2tp_reads >= lingering_from else b'')
    if a == ('/usr/bin/ss','-H','-lntup'):
        rows = []
        for name, path in [(X,h['MAIN']), (B,h['BRIDGE'])]:
            if units[name]['ActiveState'] != 'active': continue
            for i in json.loads(Path(path).read_text())['inbounds']:
                rows.append(('tcp',i.get('listen','0.0.0.0'),i['port'],units[name]['MainPID']))
                if i['tag'].startswith('relay-l2tp-') or i['protocol'] == 'socks':
                    rows.append(('udp',i.get('listen','0.0.0.0'),i['port'],units[name]['MainPID']))
                if i['tag'] == 'retained-udp':
                    assert name == X and i['port'] == udp_port and i['listen'] == udp_address
                    assert i['protocol'] == 'dokodemo-door' and i['settings']['network'] == ['tcp','udp']
                    if not (testing and scenario == 'udp-missing-preview'):
                        wrong_address = testing and scenario == 'udp-wrong-address-final' and not policy['nft']
                        rows.append(('udp','192.0.2.20' if wrong_address else udp_address,udp_port,units[X]['MainPID']))
        for name, ports in [(XL,[1701]), (IKE,[500,4500])]:
            if units[name]['ActiveState'] == 'active':
                rows.extend(('udp','0.0.0.0',port,units[name]['MainPID']) for port in ports)
        if foreign_l2tp_listener: rows.append(('udp','0.0.0.0',1701,'999'))
        if testing and scenario == 'foreign-listener': rows.append(('tcp','0.0.0.0',network['tproxyPort'],'999'))
        if testing and scenario == 'lingering-listener' and ('restart', X) in changes:
            rows.append(('tcp','0.0.0.0',network['tproxyPort'],'999'))
        if testing and scenario == 'udp-wrong-owner-preview':
            rows.append(('udp',udp_address,udp_port,'999'))
        if testing and scenario == 'udp-outbound-preview' and not after_preview:
            # This can even share the configured port on a distinct local address.
            rows.extend([('udp','192.0.2.20',udp_port,units[X]['MainPID']), ('udp','0.0.0.0',21153,units[X]['MainPID'])])
        if testing and scenario == 'udp-outbound-restart':
            ports = (54001, 21153) if ('restart',X) not in changes else ((54002,) if policy['nft'] else (21154,))
            rows.extend(('udp','0.0.0.0',port,units[X]['MainPID']) for port in ports)
        return ''.join(f'{proto} {"UNCONN" if proto == "udp" else "LISTEN"} 0 0 {addr}:{port} 0.0.0.0:* users:(("fixture",pid={pid},fd=3))\n'
                       for proto,addr,port,pid in rows).encode()
    if len(a) == 5 and a[:3] == (h['XRAY'],'api','inbounduser') and a[-1].startswith('-tag='):
        tag = a[-1].split('=',1)[1]
        clients = next(i['settings']['clients'] for i in json.loads(Path(P['main']).read_text())['inbounds'] if i['tag'] == tag)
        if testing and scenario == 'dynamic-user': clients += [{'id':'secret-fixture-only'}]
        return h['encode']({'users': [{'email': c.get('email',''), 'level': c.get('level',0),
            'account': {'id': c['id'], 'flow': c.get('flow',''), 'reverse': c.get('reverse'),
                        '_TypedMessage_':'xray.proxy.vless.Account'}} for c in clients]})
    if a == ('/usr/sbin/ipsec','statusall'):
        extra = '   foreign: secret-fixture-only\n' if testing and scenario == 'foreign-ike' else ''
        connection = '   celerity-l2tp: transport\n' if units[IKE]['ActiveState'] == 'active' else ''
        if ipsec_live:
            return (b'Status:\nConnections:\n   celerity-l2tp: transport\nSecurity Associations (1 up, 0 connecting):\n'
                    b'celerity-l2tp[9]: ESTABLISHED 3 seconds ago, 192.0.2.1[192.0.2.1]...203.0.113.99[203.0.113.99]\n'
                    b'celerity-l2tp[9]: IKEv1 SPIs: 8877665544332211_i 0011223344556677_r*\n'
                    b'celerity-l2tp{4}:  INSTALLED, TRANSPORT, reqid 1, ESP in UDP SPIs: abcdef11_i fedcba11_o\n'
                    b'celerity-l2tp{5}:  REKEYED, TRANSPORT, reqid 1, expires in 12 seconds\n')
        if ipsec_appears_at_recount:
            ipsec_appears_at_recount = False
            ipsec_live = True  # Initial Remove observation was still idle.
        return ('Status:\nConnections:\n' + connection + extra + 'Security Associations (0 up, 0 connecting):\n  none\n').encode()
    if a == ('/usr/sbin/ip','xfrm','state','list','nokeys') and ipsec_live:
        return b'fixture-only transform (no keys)\n'
    if a in (('/usr/sbin/ip','xfrm','policy','list'),('/usr/sbin/ip','xfrm','policy','list','nosock'),
             ('/usr/sbin/ip','xfrm','state','list','nokeys')): return b''
    if a == ('/usr/sbin/ip','-j','-N','-4','rule','show'):
        # The epoch cases keep the stock RPDB required by reattestation.
        rules = stock_rules + ([foreign_rule] if testing and not joined_epoch else [])
        if policy['rule']:
            rules += [dict(priority=h['PRIORITY'], src=network['clientCidr'], table=network['routeTable'], fwmark='0x4d')]
        if testing and scenario == 'foreign-rule': rules += [dict(foreign_rule, table=network['routeTable'])]
        return h['encode'](rules)
    if a == ('/usr/sbin/ip','-j','-N','-4','route','show','table','all'):
        return h['encode'](([foreign_route] if testing and not joined_epoch else []) + ([dict(dst='default', table=network['routeTable'],
            dev='lo', type='local', scope='host')] if policy['route'] else []))
    if a == ('/usr/sbin/nft','-j','list','tables'):
        return h['encode']({'nftables': [{'table': {'family':'inet','name':'foreign'}}] +
            (nft_rows[1:2] if policy['nft'] else [])})
    if a == ('/usr/sbin/nft','-j','-s','-a','list','table','inet',h['TABLE']):
        result = copy.deepcopy(nft_rows)
        if testing and scenario == 'nft-drift':
            result[-1]['rule']['expr'][-1] = {'accept': None}
        return h['encode']({'nftables': result})
    if a == ('/usr/sbin/nft','-j','-s','list','table','inet',h['TABLE']):
        return h['encode']({'nftables': [{'table': {'family':'inet','name':h['TABLE'],'comment':token,
            'handle': 2 if testing and scenario == 'nft-drift' else 1}}]})
    rule = ('-4','rule','del','priority',str(h['PRIORITY']),'from',network['clientCidr'],'fwmark','77','table','177')
    route = ('-4','route','del','local','0.0.0.0/0','dev','lo','table','177')
    if a == ('/usr/sbin/ip', *rule): policy['rule'] = False
    elif a == ('/usr/sbin/ip', *route): policy['route'] = scenario == 'lingering-route'
    elif a == ('/usr/sbin/nft','delete','table','inet',h['TABLE']): policy['nft'] = False
    else: raise AssertionError('unexpected modeled command: ' + str(a))
    changes.append(a)
    return b''
def run(a, input=None, **kw):
    try:
        stdout = command(*a, data=input)
        status = int(a[:3] == ('/usr/bin/systemctl','--no-pager','show') and units[a[-1]]['LoadState'] == 'not-found')
    except Refusal:
        stdout, status = b'', 1
    except Exception as error:
        mock_faults.append((type(error).__name__, a))
        raise
    if testing and scenario == 'xl-stop-timeout' and a[2:] == ('stop', XL):
        raise subprocess.TimeoutExpired(a, kw['timeout'])
    return types.SimpleNamespace(stdout=stdout, stderr=b'', returncode=status)
subprocess = h['subprocess']
h['subprocess'] = types.SimpleNamespace(run=run, PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL, TimeoutExpired=subprocess.TimeoutExpired)
stray_pppd = foreign_l2tp_listener = False
before = dict(boot=h['boot'](), files={k: R(p) for k,p in P.items()}, units=stock_units, bridge=None,
              globalFiles={}, installBoot=False, ikeSockets=[],
              sockets=h['owned_sockets'](h['sock_rows'](), units[X]['MainPID']))
if scenario == 'apply-quiescent-dependent': before['transit'] = []
h['observe'] = lambda m,d,transit,**kw: before
req = {k: f[k] for k in ('network','backupId','machineId')}
begin = b'# BEGIN CELERITY MANAGED L2TP USERS\n'
end = b'# END CELERITY MANAGED L2TP USERS\n'
old_row = b'"alice" l2tpd "test-old" 10.255.1.10\n'
new_row = b'"bob" l2tpd "test-new" 10.255.1.11\n'
foreign = b'elsewhere other "foreign # value" *\r\n# opaque \xff'
retirement_test = f.get('retirement', '')
cohort = retirement_test.startswith('cohort-')
nat = retirement_test in ('cohort-nat', 'cohort-two-nat', 'cohort-nat-drift', 'cohort-wrong-encap')
files = dict(main=f['installed'], nft=nft, chap=(begin + old_row + (new_row if cohort else b'') + end).decode(),
             lns='ip range = 10.255.1.10-10.255.1.19\n', **{k: 'secret-fixture-only' for k in ('ike','options','secrets')})
if scenario == 'chap-inspect-active' or joined_epoch:
    files['lns'] = ('[global]\nport = 1701\n\n[lns default]\n' + files['lns'] + 'local ip = 10.255.1.1\n'
                    'require authentication = yes\npppoptfile = /etc/ppp/options.xl2tpd\nlength bit = yes\n')
    files['options'] = ('auth\nrefuse-pap\nrefuse-chap\nrefuse-mschap\nrequire-mschap-v2\nrefuse-eap\nname l2tpd\n'
                        'mtu 1400\nmru 1400\nnoipv6\nnodefaultroute\nms-dns 192.0.2.53\n')
baseline = h['dispatch'](dict(req, action='prepare'))['baseline']
payload = {k:h['b64'](v.encode()) for k,v in files.items()}
assert h['dispatch'](dict(req, action='check', files=payload, baseline=baseline))['ok']
assert not Path(h['NET']).exists() and not any(policy.values()) and not changes
assert h['dispatch'](dict(req, action='install', files=payload, baseline=baseline))['ok']
assert Path(h['NET']).read_bytes() == h['network_unit'](network, False, backup_id=token, nft_sha256=h['digest'](nft.encode()))
manifest = Path(h['manifest_path'](token))
manifest_saved = manifest.read_bytes(), manifest.stat().st_ino
intent = manifest.with_name('remove-attempt.json')
if scenario.startswith('apply'):
    Path(P['main']).with_suffix('.apply').write_text(json.dumps(f['applied']))
    Path(P['main']).with_suffix('.apply').replace(P['main'])
    Path(h['BRIDGE']).write_text('{"inbounds":[{"tag":"neighbor","protocol":"vless","port":30201}],"outbounds":[],"routing":{"rules":[]}}')
    units[B].update(ActiveState='active',SubState='running',MainPID='90',InvocationID='new-bridge')
    units[X].update(MainPID='35',InvocationID='apply-main')
    if scenario == 'apply-quiescent-dependent':
        units[NET].update(ActiveState='failed',SubState='failed',InvocationID='apply-net')
        units[XL].update(ActiveState='inactive',SubState='dead',MainPID='0')
l2tp_reads, lingering_from, group_populated = 0, float('inf'), False
side, side_unit = R(h['BRIDGE']), dict(units[B])
changes.clear()
testing = True
req['nodeId'] = f['nodeId']
suffix = b''
if scenario.endswith('-suffix') or scenario == 'chap-unterminated-separated':
    # Preserve an actual unmanaged row, with its original EOF and CRLF bytes.
    suffix = (b'\n' if scenario == 'chap-unterminated-separated' else b'') + foreign
    if scenario == 'chap-unterminated-list-suffix':
        req['currentUsers'] = [dict(login='alice', password='test-old', ipAddress='10.255.1.10', enabled=True)]
    else:
        Path(P['chap']).write_bytes(Path(P['chap']).read_bytes() + suffix)
if scenario == 'foreign-drop': Path(h['DROP_DIR'], 'foreign.conf').write_text('untouched')
if scenario == 'foreign-network-witness':
    foreign_witness = Path(h['network_witness_path'](token))
    foreign_witness.parent.mkdir(exist_ok=True)
    foreign_witness.symlink_to('missing')
if scenario == 'foreign-dep': units[X]['RequiredBy'] += ' ' + B
if scenario in ('vpn-generation', 'chap-legacy-replaced'):
    p = Path(P['chap' if scenario.startswith('chap') else 'lns']); q = p.with_suffix('.new')
    q.write_bytes(p.read_bytes()); q.chmod(p.stat().st_mode & 0o777); q.replace(p)
chap = Path(P['chap'])
old_users = [dict(login='alice', password='test-old', ipAddress='10.255.1.10', enabled=True)]
new_users = [dict(login='bob', password='test-new', ipAddress='10.255.1.11', enabled=True),
             dict(login='disabled', password='not-written', ipAddress='10.255.1.12', enabled=False)]
chap_preimage = h['raw'](before['files']['chap'])
stock_chap = chap_preimage + b'\n'  # Install adds this separator before the managed block.
if scenario == 'apply-quiescent-dependent':
    chap.write_bytes(stock_chap + begin + new_row + end)
    req['currentUsers'] = new_users
if scenario == 'ambiguous':
    cfg = json.loads(Path(P['main']).read_text())
    cfg['routing']['rules'].insert(0, dict(type='field', outboundTag='rebuild-l2tp-block', inboundTag=['client']))
    Path(P['main']).write_text(json.dumps(cfg))
if scenario == 'ambiguous-shared':
    cfg = json.loads(Path(P['main']).read_text())
    cfg['routing']['rules'].insert(0, dict(type='field', outboundTag='block', inboundTag=['rebuild-relay-ingress','API_INBOUND']))
    Path(P['main']).write_text(json.dumps(cfg))
if scenario == 'duplicate-json':
    p = Path(P['main']); p.write_text(p.read_text().replace('{','{"inbounds":[],',1))
if scenario == 'wrong-network': req['network'] = dict(network, tproxyPort=12346)
if scenario == 'wrong-machine': req['machineId'] = 'f'*32
if scenario == 'wrong-node': req['nodeId'] = 'f'*24
if scenario == 'missing-manifest': req['backupId'] = 'f'*32

def wire(action, *, stdin=None, helper=h, **kw):
    global wire_action
    wire_action = action
    stdout, stderr = io.StringIO(), io.StringIO()
    saved = sys.stdin
    try:
        helper['REMOVE_ENTERED'] = False  # one invocation per process on the host
        helper['REATTEST_ENTERED'] = False
        helper['CHAP_ENTERED'] = False
        helper['NETWORK_UPGRADE_ENTERED'] = False
        sys.stdin = types.SimpleNamespace(buffer=io.BytesIO(
            stdin.encode() if stdin is not None else h['encode'](dict(req, action=action, **kw))))
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = helper['main']()
    finally: sys.stdin = saved
    assert not mock_faults, mock_faults
    assert all(marker not in stdout.getvalue() + stderr.getvalue() for marker in (
        'secret-fixture-only', '203.0.113.99', '8877665544332211', 'abcdef11'))
    return code, stdout.getvalue(), stderr.getvalue()

def snapshot():
    return sorted((str(p.relative_to(root)), p.lstat().st_ino, p.lstat().st_ctime_ns,
                   p.read_bytes() if p.is_file() else None) for p in root.rglob('*'))

if joined_epoch:
    req['currentUsers'] = old_users
    selected = (X, XL, IKE, NET)
    starts.update((units[n]['MainPID'], i + 100) for i, n in enumerate(selected[:-1]))
    (group / 'cgroup.procs').write_text(units[XL]['MainPID'] + '\n')
    prior = wire('session-count')
    assert prior[0] == 0 and prior[2] == '', prior
    prior = json.loads(prior[1])
    assert prior['activeSessions'] == prior['activeIpsec'] == 0 and len(prior['census']) == 64, prior
    original_manifest = json.loads(manifest.read_bytes())
    if scenario == 'epoch-remove-reboot':
        epoch = '12345678-1234-1234-1234-123456789abd'
        transitioned = zip(selected, 'abcd', ('31', '32', '33', '0'))
        for row in nft_rows:
            value = next(iter(row.values()))
            if 'handle' in value: value['handle'] += 100
    else:
        assert scenario == 'epoch-remove-xl2tpd-restart'
        transitioned = [(XL, 'b', '32')]
    for n, invocation, pid in transitioned:
        units[n].update(InvocationID=invocation * 31 + 'f', MainPID=pid)
        starts[pid] = 200 + int(pid)
    (group / 'cgroup.procs').write_text(units[XL]['MainPID'] + '\n')
    initial = snapshot()
    binding = {k: req[k] for k in ('machineId', 'nodeId', 'backupId', 'network')}
    expected_census = baseline = None
    for i, action in enumerate(('session-count', 'reattest-runtime', 'session-count', 'prepare-remove',
                                'session-count', 'prepare-remove', 'remove')):
        if i == 0:
            frame = f
        else:
            line = sys.stdin.readline()
            if not line: break  # JS reports an aborted caller; it also asserts the complete action sequence.
            frame = json.loads(line)
        limits = ['1s', '9s'] if action == 'session-count' else ['4s', '125s']
        assert shlex.split(frame['command']) == ['/usr/bin/timeout', '-k', *limits, '/usr/bin/python3', '-I', '-B', '-c', argv[-1]]
        params = binding if action == 'reattest-runtime' else req
        if action == 'remove': params = dict(req, baseline=baseline, expectedCensus=expected_census)
        assert json.loads(frame['stdin']) == dict(params, action=action)
        ipsec_live = i in (2, 3)  # Independent host activity, not an input to DIRECT.
        result = wire(action, stdin=frame['stdin'])
        if i == 0:
            assert result == (70, '', 'DIRECT_RUNTIME_REATTEST_REQUIRED\n'), result
        elif i == 3:
            assert result == (70, '', 'DIRECT_REMOVE_IPSEC_BUSY\n'), result
        else:
            assert result[0] == 0 and result[2] == '', (action, result, changes)
            reply = json.loads(result[1])
            if action == 'reattest-runtime':
                assert reply == dict(ok=True, backupId=token)
                refreshed = dict(original_manifest['runtime'], boot=epoch,
                                 invocations=[units[n]['InvocationID'] for n in selected],
                                 pids=[units[n]['MainPID'] for n in selected])
                assert json.loads(manifest.read_bytes()) == dict(original_manifest, runtime=refreshed)
                after = snapshot()
                own = {str(p.relative_to(root)) for p in (manifest, manifest.parent)}
                assert [row for row in after if row[0] not in own] == [row for row in initial if row[0] not in own]
                initial = after
            elif action == 'session-count':
                assert reply['activeSessions'] == 0 and reply['activeIpsec'] == int(ipsec_live), reply
                expected_census = reply['census']
                assert len(expected_census) == 64 and expected_census != prior['census']
            elif action == 'prepare-remove':
                baseline = reply['baseline']
                assert reply == dict(ok=True, machineId=f['machineId'], backupId=token, baseline=baseline) and len(baseline) == 64
            else:
                assert reply == dict(ok=True, backupId=token, removed=True)
        if action != 'remove':
            assert snapshot() == initial and not changes and not intent.exists()
        else:
            assert json.loads(intent.read_bytes()) == dict(baseline=baseline)
            assert changes[:3] == [('stop', XL), ('stop', IKE), ('stop', NET)] and ('restart', X) in changes
            assert not any(policy.values()) and all(B not in cmd for cmd in changes)
            assert not Path(h['DROP_DIR']).exists() and not Path(h['NFT_DIR']).exists()
            assert json.loads(Path(P['main']).read_text()) == json.loads(f['old'])
            assert all(R(p) == before['files'][k] for k, p in P.items() if k != 'main')
            assert json.loads(manifest.read_bytes()) == dict(original_manifest, runtime=refreshed)
        print(json.dumps(result), flush=True)
    sys.exit(0)

if scenario.startswith('retire-'):
    # Same emitted helper bytes as the SSH transport. The file/manifest and
    # flock are real scratch objects; no kernel VPN socket or signal is used.
    retirement = f['retirement']
    units[IKE]['ControlGroup'] = '/system.slice/' + IKE
    req['currentUsers'] = old_users + (new_users[:1] if cohort else [])
    group = os.open(root, os.O_DIRECTORY | os.O_RDONLY)
    native_read, base_command = h['session_read'], command
    (root / 'proc').mkdir()
    (root / 'proc/12').mkdir()
    (root / 'proc/12/stat').write_bytes(b'12 (charon) ' + b'0 ' * 19 + b'808\n')
    base_directory = h['directory']
    @contextlib.contextmanager
    def retire_directory(path, private=False):
        with base_directory(str(root / 'proc') if path == '/proc' else path, private) as fd:
            yield fd
    h['directory'] = retire_directory
    events, cap, gate = [], b'max\n', False
    ppp_clients = {0, 1} if cohort else {0}
    ike_clients = set(ppp_clients)
    sa_ids = [9, 19, 29]
    ppp = ipsec_live = True  # Legacy idle/stop fixture booleans.
    altered, rebound = False, False
    src = '192.0.2.1'
    def dst(i): return '203.0.113.' + str(99 + (0 if retirement == 'cohort-shared-peer' else i))
    def spis(i): return (f'{0xabcdef11 + i:08x}', f'{0xfedcba11 + i:08x}')
    def ike_spis(i): return (f'{0x8877665544332211 + i:016x}', f'{0x0011223344556677 + i:016x}')
    original_readlink = os.readlink
    h['os'].readlink = lambda path, *a, **kw: '/usr/lib/ipsec/charon' if path == '/proc/12/exe' else original_readlink(path, *a, **kw)
    owner = ('fixture-boot', units[XL]['InvocationID'], 11, '42', 'proof', 'chap')
    def ppp_sample(_, proc, fd, selected, hold, watch, *, revoke=False):
        assert selected == owner
        assert revoke
        for pid in [11, *(501 + i for i in ppp_clients)]: hold(pid)
        watch()
        return 131, [((31+(0 if retirement == 'cohort-shared-tunnel' else i), 32+i,
                       41+(0 if retirement == 'cohort-shared-tunnel' else i), 42+i), '10.255.1.1', f'10.255.1.{10+i}',
                      501+i, 1337+int(altered), 77+i, 22+i, (1, 7, 8+i)) for i in sorted(ppp_clients)]
    h.update(session_owner=lambda _, **kw: owner, session_sample=ppp_sample, session_fs=lambda *_: None,
             revoke_peer_logins=lambda rows, users: {r[3]: login for r in rows for login, ip in users.items() if r[2] == ip},
             session_census=lambda _: dict(activeSessions=len(ppp_clients), census='a'*64),
             live_modules=lambda _: set() if retirement == 'no-l2tp-netlink' else {'l2tp_netlink'},
             ppp_empty=lambda: not ppp, retire_group_same=lambda fd: fd == group)

    @contextlib.contextmanager
    def ppp_directory(path, private=False):
        if path == '/sys/fs/cgroup' + h['SESSION_GROUP']: yield group
        else:
            with retire_directory(path, private) as fd: yield fd
    h['directory'] = ppp_directory
    h['os'].lstat = lambda path, *a, **kw: os.lstat(root if path == '/sys/fs/cgroup' + h['SESSION_GROUP'] else path, *a, **kw)
    route_watchers = set()
    pfd_set = set()
    def pidfd_open(pid):
        assert pid in (11, 12) or pid - 501 in ppp_clients
        fd = pid + 1000
        assert fd not in pfd_set, 'did not keep the original pidfd'
        pfd_set.add(fd)
        return fd
    h['os'].pidfd_open = pidfd_open
    h['os'].close = lambda fd: pfd_set.remove(fd) if fd in pfd_set else os.close(fd)

    def session_read(fd, name, size):
        if fd == group:
            if name == 'pids.max': return cap
            assert name == 'pids.current'
            return f'{len(ppp_clients) + 1}\n'.encode() if units[XL]['ActiveState'] == 'active' else b'0\n'
        return native_read(fd, name, size)
    def write_pids(fd, limit):
        global cap, altered, rebound
        assert fd == group and gate
        events.append('fence-ppp' if limit == b'0\n' else 'restore-ppp')
        cap = limit
        if retirement in ('fenced-drift', 'cleanup-unknown') and cap == b'0\n': altered = True
        if cap == b'0\n' and retirement == 'cohort-ike-arrival': ike_clients.add(2)
        if cap == b'0\n' and retirement == 'cohort-nat-drift': rebound = True
    def signal_ppp(pfd, sig):
        global ppp
        i = pfd - 1501
        assert pfd in pfd_set and sig == h['signal'].SIGTERM and i in ppp_clients and gate and cap == b'0\n' and intent.exists()
        events.append('disconnect-ppp')
        ppp_clients.remove(i)
        ppp = bool(ppp_clients)
        for route in route_watchers: route.pending = True
        if retirement == 'cohort-survivor-drift': sa_ids[1] = 20
    class Poll:
        def __init__(self): self.fds = set()
        def register(self, fd, mask): self.fds.add(fd)
        def unregister(self, fd): self.fds.remove(fd)
        def poll(self, _):
            return [(fd, 1) for fd in self.fds if (fd.pending if isinstance(fd, Route) else
                                                    fd >= 1501 and fd - 1501 not in ppp_clients)]
    h.update(session_read=session_read, retire_write_pids=write_pids,
             select=types.SimpleNamespace(poll=Poll, POLLIN=1),
             signal=types.SimpleNamespace(SIGTERM=15, pidfd_send_signal=signal_ppp))
    original_write = h['write']
    def retire_write(path, *args, **kwargs):
        original_write(path, *args, **kwargs)
        if path == str(intent) and retirement == 'late-intent-drift': sa_ids[0] = 10
        if path == str(intent) and retirement == 'late-intent-chap-drift':
            chap.write_bytes(chap.read_bytes().replace(old_row, new_row))
    h['write'] = retire_write

    def attribute(k, v):
        k, v = k.encode(), str(v).encode()
        return bytes((3, len(k))) + k + len(v).to_bytes(2, 'big') + v
    def section(k, children):
        k = k.encode()
        return bytes((1, len(k))) + k + children + b'\x02'
    def listing(k, v):
        k, v = k.encode(), v.encode()
        return bytes((4, len(k))) + k + b'\x05' + len(v).to_bytes(2, 'big') + v + b'\x06'
    def encapped(i): return nat and (i == 0 or retirement == 'cohort-two-nat')
    def remote_port(i): return 60123 + i + (100 if rebound else 0)
    def ike_event(i):
        spi_in, spi_out = spis(i)
        initiator, responder = ike_spis(i)
        child_id = 4+i
        child = b''.join(attribute(*kv) for kv in {'uniqueid': child_id, 'name': 'celerity-l2tp', 'state': 'INSTALLED',
            'mode': 'TRANSPORT', 'protocol': 'ESP', 'reqid': 1+i, 'spi-in': spi_in, 'spi-out': spi_out}.items())
        if encapped(i): child += attribute('encap', 'yes')
        child += listing('local-ts', src+'/32[udp/l2f]') + listing('remote-ts', dst(i)+'/32[udp/1701]')
        sa = b''.join(attribute(*kv) for kv in {'uniqueid': sa_ids[i], 'version': 1, 'state': 'ESTABLISHED',
            'local-host': src, 'remote-host': dst(i), 'initiator-spi': initiator, 'responder-spi': responder,
            'local-port': 4500 if encapped(i) else 500, 'remote-port': remote_port(i) if encapped(i) else 500}.items())
        children = section(f'celerity-l2tp-{child_id}', child)
        if retirement == 'cohort-shared-child' and i == 1: children += section('celerity-l2tp-extra', child)
        return b'\x07\x07list-sa' + section('celerity-l2tp', sa + section('child-sas', children))
    class Route:
        def __init__(self): self.pending = False
        def __enter__(self): route_watchers.add(self); return self
        def __exit__(self, *_): route_watchers.remove(self)
        def bind(self, address): assert address == (0, 17)
    class Vici:
        def __init__(self, *args): self.pending = b''
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def settimeout(self, t): assert t > 0
        def connect(self, p):
            assert p == '/run/charon.vici'
            if retirement == 'no-vici': raise FileNotFoundError()
        def getsockopt(self, *a): return h['struct'].pack('=iII', 12, 0, 0)
        def recv(self, n):
            value, self.pending = self.pending[:n], self.pending[n:]
            return value
        def sendall(self, frame):
            global ipsec_live
            assert not self.pending and int.from_bytes(frame[:4], 'big') == len(frame)-4
            name, data = frame[6:6+frame[5]], frame[6+frame[5]:]
            replies = [b'\x05']
            if name == b'list-sa': assert frame[4] in (3, 4) and not data
            elif name == b'list-sas':
                assert frame[4] == 0 and not data
                replies = [ike_event(i) for i in sorted(ike_clients, reverse=True)]
                if retirement == 'extra-sa': replies *= 2
                replies.append(b'\x01')
            else:
                assert name == b'terminate' and frame[4] == 0
                i, = [i for i in ike_clients if data == attribute('ike-id', sa_ids[i]) + attribute('timeout', 2000)]
                assert i not in ppp_clients and gate and cap == b'0\n' and intent.exists()
                events.append('disconnect-ike')
                ike_clients.remove(i)
                if retirement == 'cohort-late-ike-arrival': ike_clients.add(2)
                ipsec_live = bool(ike_clients)
                if retirement == 'lost-terminate': replies = []
                else: replies = [b'\x01' + attribute('success', 'yes') + attribute('matches', 1) + attribute('terminated', 1)]
            self.pending = b''.join(len(item).to_bytes(4, 'big') + item for item in replies)
    s = h['socket']
    h['socket'] = types.SimpleNamespace(socket=lambda family, *_: Route() if family == s.AF_NETLINK else Vici(),
        **{k: getattr(s, k) for k in ('AF_UNIX', 'SOCK_STREAM', 'SOL_SOCKET', 'SO_PEERCRED', 'AF_NETLINK',
                                      'SOCK_RAW', 'SOCK_NONBLOCK')})

    gate_name = 'celerity_retire_' + token
    cgroup_match = f'socket cgroupv2 level 2 "system.slice/{IKE}" drop'
    matches = (f'udp dport 500 {cgroup_match}', f'udp dport 4500 @th,64,32 0x0 {cgroup_match}')
    gates = ('/usr/sbin/nft','-a','-s','-y','list','table','inet',gate_name)
    def commands(*a, data=None):
        global gate
        if a == ('/usr/bin/ss', '-H', '-aunp', '--cgroup', '-A', 'udp'):
            scope = IKE if retirement != 'wrong-socket-cgroup' else 'other.service'
            rows = b''.join(l + f' cgroup:/system.slice/{XL if b":1701 " in l else scope}\n'.encode()
                            for l in base_command('/usr/bin/ss', '-H', '-lntup').splitlines() if l.startswith(b'udp '))
            if gate and retirement == 'queued-ike':
                rows = b'\n'.join(l.replace(b'UNCONN 0 ', b'UNCONN 128 ', 1) if b':500 ' in l else l
                                  for l in rows.split(b'\n'))
            for i in sorted(ppp_clients):
                socket_pid = 999 if retirement == 'foreign-l2tp-socket' else 11
                row = (f'ESTAB 0 0 {src}:1701 {dst(i)}:1701 users:(("xl2tpd",pid={socket_pid},fd={4+i})) '
                       f'cgroup:/system.slice/{XL}\n').encode()
                rows += row * (2 if retirement == 'cohort-duplicate-socket' and i == 1 else 1)
            if not ipsec_live and retirement == 'late-foreign-l2tp':
                rows += b'ESTAB 0 0 192.0.2.1:1701 203.0.113.100:1701 users:(("other",pid=999,fd=3)) cgroup:/system.slice/other.service\n'
            return rows + (b'ESTAB 0 0 192.0.2.1:500 203.0.113.100:500 users:(("fixture",pid=999,fd=3))\n'
                           if retirement == 'foreign-socket' else b'')
        if a == ('/usr/sbin/ip','l2tp','show','tunnel'):
            assert retirement != 'no-l2tp-netlink'
            # Model a single control tunnel lingering after the only PPP exit;
            # in a cohort the closed calls' tunnels disappear immediately.
            return ''.join(f'Tunnel {31+i}, encap UDP\n  From {src} to {dst(i) if retirement != "wrong-tunnel" else "203.0.113.100"}\n'
                           f'  Peer tunnel {41+i}\n  UDP source / dest ports: 1701/1701\n  UDP checksum: enabled\n'
                           for i in (sorted(ppp_clients) if cohort else [0] if units[XL]['ActiveState'] == 'active' else [])).encode()
        if a == ('/usr/sbin/ip','-j','-details','link','show'):
            return h['encode']([{'ifindex': 1, 'link_type': 'loopback'}] +
                               [{'ifindex': 22+i, 'link_type': 'ppp'} for i in ppp_clients])
        if a == ('/usr/sbin/ipsec', 'statusall') and ike_clients:
            status = f'Status:\nConnections:\n   celerity-l2tp: transport\nSecurity Associations ({len(ike_clients)} up, 0 connecting):\n'
            for i in sorted(ike_clients):
                initiator, responder = ike_spis(i)
                spi_in, spi_out = spis(i)
                esp = 'ESP in UDP' if encapped(i) else 'ESP'
                status += (f'celerity-l2tp[{sa_ids[i]}]: ESTABLISHED 3 seconds ago, {src}[{src}]...{dst(i)}[{dst(i)}]\n'
                           f'celerity-l2tp[{sa_ids[i]}]: IKEv1 SPIs: {initiator}_i {responder}_r*\n'
                           f'celerity-l2tp{{{4+i}}}:  INSTALLED, TRANSPORT, reqid {1+i}, {esp} SPIs: {spi_in}_i {spi_out}_o\n')
            return status.encode()
        if a == ('/usr/sbin/ip','xfrm','state','list','nokeys') and ipsec_live:
            states = []
            for i in sorted(ike_clients):
                spi_in, spi_out = spis(i)
                for x,y,spi,sport,dport in ((src,dst(i),spi_out,4500,remote_port(i)), (dst(i),src,spi_in,remote_port(i),4500)):
                    states.append(f'src {x} dst {y}\n\tproto esp spi 0x{spi} reqid {1+i} mode transport\n\treplay-window 32\n')
                    if encapped(i):
                        bad = retirement == 'cohort-wrong-encap' and x == src
                        states[-1] += f'\tencap type espinudp sport {sport} dport {dport+bad} addr 0.0.0.0\n'
            if retirement == 'foreign-transform': states += [states[0].replace('fedcba11','a1234567')]
            return ''.join(states).encode()
        if a == ('/usr/sbin/ip','xfrm','policy','list','nosock') and ipsec_live:
            policies = [f'src {x}/32 dst {y}/32 proto udp sport 1701 dport 1701\n\tdir {di} priority 350000 ptype main\n'
                        f'\ttmpl src 0.0.0.0 dst 0.0.0.0\n\t\tproto esp reqid {1+i} mode transport\n'
                        for i in sorted(ike_clients) for x,y,di in ((src,dst(i),'out'),(dst(i),src,'in'))]
            if retirement == 'cohort-foreign-policy': policies += [policies[-1].replace('203.0.113.100','203.0.113.106')]
            return ''.join(policies).encode()
        if a in (('/usr/sbin/nft','-c','-f','-'), ('/usr/sbin/nft','-f','-')):
            def batch(rules):
                return (f'create table inet {gate_name}\n'
                        f'add chain inet {gate_name} ingress {{ type filter hook input priority -10; policy accept; }}\n'
                        + ''.join(f'add rule inet {gate_name} ingress {rule}\n' for rule in rules)).encode()
            assert not gate
            assert data == batch(matches)
            if a[1] == '-c':
                if retirement == 'gate-unsupported': raise Refusal('COMMAND_FAILED')
                return b''
            events.append('fence-ike')
            gate = True
            return b''
        if a == gates:
            assert gate
            assert units[IKE]['ActiveState'] == 'active'
            return (f'table inet {gate_name} {{ # handle 8\n\tchain ingress {{ # handle 1\n'
                    '\t\ttype filter hook input priority -10; policy accept;\n'
                    + ''.join(f'\t\t{rule} # handle {2+i}\n' for i, rule in enumerate(matches)) + '\t}\n}\n').encode()
        if a == ('/usr/sbin/nft','-j','list','tables') and gate:
            value = json.loads(base_command(*a))
            value['nftables'].append({'table': {'family':'inet', 'name':gate_name}})
            return h['encode'](value)
        if a == ('/usr/sbin/nft','delete','table','inet','handle','8'):
            assert gate
            events.append('restore-ike')
            if retirement == 'cleanup-unknown': raise Refusal('COMMAND_FAILED')
            gate = False
            return b''
        if a[2:3] == ('stop',) and a[-1] in (XL,IKE):
            assert not ppp and not ipsec_live and cap == b'0\n' and gate
            events.append('stop-xl' if a[-1] == XL else 'stop-ike')
        return base_command(*a, data=data)
    command = commands  # all host subprocesses go to the model, including systemctl
    initial = snapshot()
    params = dict(retirement=True, drain=True)
    def send(result): print(json.dumps(result), flush=True)
    def received(action, **extra):
        frame = json.loads(sys.stdin.readline())
        cmd = shlex.split(frame['command'])
        assert cmd == ['/usr/bin/timeout', '-k', '4s', '125s', '/usr/bin/python3', '-I', '-B', '-c', argv[-1]]
        assert json.loads(frame['stdin']) == dict(req, action=action, **extra)
        return wire(action, stdin=frame['stdin'])
    count_result = wire('retirement-count', stdin=f['stdin'])
    assert count_result[0] == 0 and not count_result[2], count_result
    proof = json.loads(count_result[1])
    assert snapshot() == initial and not changes and not events
    refusal = (70, '', 'DIRECT_REMOVE_PREVIEW_CHANGED\n')
    if retirement in f['unproved']:
        assert proof['activeClients'] is None
        assert wire('prepare-remove', **params, expectedCensus=proof['census']) == refusal
        assert snapshot() == initial and not events and not changes
        send(count_result)
    else:
        assert proof['activeClients'] == proof['activeSessions'] == proof['activeIpsec'] == (2 if cohort else 1), proof
        assert wire('prepare-remove')[0] == 70  # standalone Remove cannot arm this drain
        send(count_result)
        params['expectedCensus'] = proof['census']
        preparation = received('prepare-remove', **params)
        assert preparation[0] == 0 and not preparation[2], preparation
        baseline = json.loads(preparation[1])['baseline']
        assert snapshot() == initial and not changes and not events
        send(preparation)
        if retirement == 'same-count-drift': sa_ids[0] = 10
        if retirement == 'cohort-same-count-drift': sa_ids[0], sa_ids[1] = sa_ids[1], sa_ids[0]

        result = received('remove', baseline=baseline, **params)
        if retirement in f['successful']:
            assert json.loads(result[1]) == dict(ok=True, backupId=token, removed=True), result
            n = proof['activeClients']
            assert events == ['fence-ike','fence-ppp'] + ['disconnect-ppp']*n + ['disconnect-ike']*n + \
                ['stop-xl','stop-ike','restore-ppp','restore-ike'], events
            assert not ppp and not ipsec_live and intent.exists() and not any(policy.values())
            assert not gate and cap == b'max\n' and chap.read_bytes() == chap_preimage
        elif retirement in ('lost-terminate', 'late-foreign-l2tp'):
            assert result == (75, '', '') and not changes and intent.exists() and gate and cap == b'0\n'
            assert events == ['fence-ike','fence-ppp','disconnect-ppp','disconnect-ike']
            assert wire('remove', baseline=baseline, **params)[0] != 0
            assert events.count('disconnect-ppp') == events.count('disconnect-ike') == 1
        elif retirement in ('late-intent-drift', 'late-intent-chap-drift'):
            assert events == ['fence-ike','fence-ppp'], events
            assert result == (75, '', '') and not changes and intent.exists() and gate and cap == b'0\n'
            assert ppp and ipsec_live
            if retirement == 'late-intent-chap-drift':
                assert new_row in chap.read_bytes() and old_row not in chap.read_bytes()
                assert wire('remove', baseline=baseline, **params)[0] != 0
                assert events == ['fence-ike','fence-ppp'], events
        elif retirement == 'cohort-survivor-drift':
            assert result == (75, '', '') and not changes and intent.exists() and gate and cap == b'0\n'
            assert events == ['fence-ike','fence-ppp','disconnect-ppp'] and ppp_clients == {1} and ike_clients == {0,1}
        elif retirement == 'cohort-late-ike-arrival':
            assert result == (75, '', '') and not changes and intent.exists() and gate and cap == b'0\n'
            assert events == ['fence-ike','fence-ppp','disconnect-ppp','disconnect-ppp','disconnect-ike']
            assert not ppp_clients and len(ike_clients) == 2 and 2 in ike_clients
        elif retirement == 'cleanup-unknown':
            assert result == (75, '', '') and not changes and not intent.exists() and gate and cap == b'max\n'
            assert events == ['fence-ike','fence-ppp','restore-ppp','restore-ike']
        else:
            assert result == refusal and snapshot() == initial and not changes and not gate and cap == b'max\n', (result, events)
            expected = {'fenced-drift': ['fence-ike','fence-ppp','restore-ppp','restore-ike'],
                        'cohort-ike-arrival': ['fence-ike','fence-ppp','restore-ppp','restore-ike'],
                        'cohort-nat-drift': ['fence-ike','fence-ppp','restore-ppp','restore-ike'],
                        'queued-ike': ['fence-ike','fence-ppp','restore-ppp','restore-ike']}.get(retirement, [])
            assert events == expected
        send(result)
    assert not pfd_set and not route_watchers
    os.close(group)
    sys.exit(0)

if scenario.startswith('xtls-'):
    def xtls_wire(action, **extra):
        return wire(action, stdin=h['encode'](dict(
            {k: req[k] for k in ('machineId', 'network', 'backupId')}, action=action, **extra)).decode())
    install_baseline = baseline  # Use the acknowledged pre-install digest, not the now-mutated fixture.
    testing = False  # No foreign policy during the install-bound phases.
    a = xtls_wire('verify', baseline=install_baseline)
    assert a[0] == 0, a
    units[X]['DropInPaths'] = ''
    assert xtls_wire('verify', baseline=install_baseline) == (70, '', 'DIRECT_XRAY_DROPIN_UNSUPPORTED\n')
    units[X]['DropInPaths'] = str(xtls)
    if scenario == 'xtls-rollback':
        a = xtls_wire('rollback', baseline=install_baseline)
        assert a[0] == 0 and json.loads(manifest.read_bytes())['phase'] == 'rolled-back', a
        assert R(P['main']) == before['files']['main'] and not any(policy.values())
        assert xtls.read_bytes() == xtls_bytes and xtls.stat().st_ino == xtls_inode
        print('ok')
        sys.exit(0)
    testing = True
    a = xtls_wire('check-apply-network')
    assert a[0] == 0, a
    apply_proof = json.loads(a[1])['proof']
    assert xtls_wire('prepare-apply-network') == a
    assert xtls_wire('verify-apply-network', proof=apply_proof) == a
    xtls.write_bytes(xtls_bytes + b'Environment=FOREIGN=1\n')
    drifted = snapshot()
    assert xtls_wire('restart-apply-network', proof=apply_proof) == (70, '', 'DIRECT_XRAY_DROPIN_UNSUPPORTED\n')
    assert not changes and snapshot() == drifted
    xtls.write_bytes(xtls_bytes)
    assert xtls_wire('restart-apply-network', proof=apply_proof) == a
    assert xtls_wire('verify-apply-network', proof=apply_proof) == a
    assert changes == [('restart', X)]
    changes.clear()
initial = snapshot()
if scenario == 'chap-epoch':
    # Run the exact historical helper with the same modeled system and real
    # flock/files as the current helper. Its dispatch, manifest and CHAP code
    # are not replaced. Verify it can write before testing its late refusal.
    legacy = {'__name__': 'legacy_fixture'}
    exec(compile(f['legacySource'], '<a406947 DIRECT host>', 'exec'), legacy)
    legacy.update({k: h[k] for k in ('MAIN', 'BRIDGE', 'XRAY', 'SYSTEM', 'NET', 'DROP_DIR', 'DROP', 'NFT_DIR',
                                     'NFT_FILE', 'VAULT', 'NAMES', 'os', 'directory', 'preflight', 'boot',
                                     'signal', 'subprocess')})
    params = dict(currentUsers=old_users, desiredUsers=[], revokedLogin='alice')
    refusal = (70, '', 'DIRECT_CHAP_REFUSED\n')
    drains = []
    def drain(*_):
        drains.append(True)
        return dict(sessionsTerminated=0, complete=True)
    h['revoke_ppp'] = legacy['revoke_ppp'] = drain
    def ack(action, **kw):
        code, out, err = wire(action, **kw)
        assert (code, err) == (0, ''), (action, code, err)
        return json.loads(out)
    ok = dict(ok=True, backupId=token)
    assert ack('check-chap', helper=legacy, **params) == dict(ok, changed=True)
    assert ack('sync-chap', helper=legacy, currentUsers=old_users, desiredUsers=[]) == dict(ok, changed=True)
    assert ack('sync-chap', currentUsers=[], desiredUsers=old_users) == dict(ok, changed=True)
    initial = snapshot()
    original_manifest = json.loads(manifest.read_bytes())
    assert ack('read-chap-generation') == dict(ok, generation=None)
    saved_legacy_sync = h['encode'](dict(req, action='sync-chap', **params)).decode()
    saved_first_fence = h['encode'](dict(req, action='fence-chap', **params, generation=None)).decode()
    assert wire('fence-chap', currentUsers=new_users, desiredUsers=[], generation=None) == refusal
    assert wire('fence-chap', **params) == refusal  # no CAS preimage
    with directory(h['SYSTEM']) as contender:
        h['fcntl'].flock(contender, h['fcntl'].LOCK_SH | h['fcntl'].LOCK_NB)
        assert wire('fence-chap', stdin=saved_first_fence) == (75, '', '')
    assert snapshot() == initial and not changes and not drains
    manifest_name = str(manifest.relative_to(root))
    file_rows = lambda: [row for row in snapshot() if row[-1] is not None and row[0] != manifest_name]
    untouched = file_rows()
    assert ack('fence-chap', stdin=saved_first_fence) == dict(ok, fenced=True)
    first = ack('check-chap', **params)['generation']
    assert len(first) == 32
    assert json.loads(manifest.read_bytes()) == dict(original_manifest, phase='installed-chap-v2:' + first)
    retired = snapshot()
    # Recovery sees the original CHAP and can cancel. The older encoded
    # helper with a still-valid CHAP preimage cannot write or reach PPP.
    assert ack('inspect-chap', currentUsers=old_users, desiredUsers=[]) == dict(
        ok, projection='original', activeTargetSessions=0, generation=first)
    assert wire('sync-chap', helper=legacy, stdin=saved_legacy_sync) == refusal
    assert wire('sync-chap', stdin=saved_legacy_sync) == refusal
    assert wire('fence-chap', stdin=saved_first_fence) == refusal
    assert snapshot() == retired and file_rows() == untouched and not changes and not drains
    stale_sync = h['encode'](dict(req, action='sync-chap', **params, generation=first)).decode()
    second_fence = h['encode'](dict(req, action='fence-chap', **params, generation=first)).decode()
    assert ack('fence-chap', stdin=second_fence) == dict(ok, fenced=True)
    second = ack('read-chap-generation')['generation']
    assert len(second) == 32 and first != second
    assert json.loads(manifest.read_bytes()) == dict(original_manifest, phase='installed-chap-v2:' + second)
    retired = snapshot()
    assert wire('sync-chap', stdin=stale_sync) == refusal
    assert wire('fence-chap', stdin=second_fence) == refusal
    assert snapshot() == retired and file_rows() == untouched and not changes and not drains
    assert ack('sync-chap', **params, generation=ack('check-chap', **params)['generation']) == dict(
        ok, changed=True, sessionsTerminated=0, complete=True)
    assert drains == [True] and not changes
    # The managed block is now desired; a new fence still rotates without
    # changing CHAP. The prior epoch cannot drain even on a no-op.
    untouched = file_rows()
    assert ack('fence-chap', **params, generation=second) == dict(ok, fenced=True)
    post_fence = snapshot()
    blocked = [dict(old_users[0], enabled=False)]
    assert wire('sync-chap', **{**params, 'currentUsers': blocked}, generation=second) == refusal
    assert snapshot() == post_fence and file_rows() == untouched and drains == [True]
    apply = {k: req[k] for k in ('machineId', 'backupId', 'network')}
    def apply_ack(action, **kw):
        return ack(action, stdin=h['encode'](dict(apply, action=action, **kw)).decode())
    proof = apply_ack('check-apply-network')['proof']
    assert apply_ack('prepare-apply-network')['proof'] == proof
    assert apply_ack('verify-apply-network', proof=proof)['proof'] == proof
    req['currentUsers'] = []
    h['collect_session_census'] = lambda _: dict(activeSessions=0, census='e'*64)
    count = ack('session-count')
    assert count['activeSessions'] == count['activeIpsec'] == 0 and len(count['census']) == 64
    manifest_saved = manifest.read_bytes(), manifest.stat().st_ino
    initial = snapshot()
if scenario == 'chap-inspect-active':
    observation = f['observation']
    if observation != 'create':
        target_row = old_row if observation not in ('desired', 'desired-idle') else b''
        neighbor = new_row.replace(b'test-new', b'wrong-password') if observation == 'mixed' else new_row
        chap.write_bytes(stock_chap + begin + target_row + neighbor + end + foreign)
    if observation == 'failed':
        units[XL].update(ActiveState='failed', SubState='failed', MainPID='0')
    if observation == 'fenced-original':
        params = {k: v for k, v in json.loads(f['stdin']).items() if k in ('currentUsers', 'desiredUsers', 'revokedLogin')}
        code, stdout, stderr = wire('fence-chap', generation=None, **params)
        assert (code, json.loads(stdout), stderr) == (0, dict(ok=True, backupId=token, fenced=True), '')
    before_inspect = snapshot()
    samples = identity_reads = 0
    calls = {pid: ((1, pid, 2, pid), '10.255.1.1', peer, pid, pid + 10, pid + 20, pid + 30, [1,pid,2])
             for pid, peer in [(501, '10.255.1.10'), (502, '10.255.1.11'), (503, '10.255.1.10')]}

    # Model native PPP objects and pppd state only at the reader seams.
    @contextlib.contextmanager
    def view(owner):
        assert observation not in ('create', 'failed', 'mixed', 'exclusive-held')
        assert owner[1:3] == ('1'*32, 11)
        def sample():
            global samples
            samples += 1
            if observation in ('getfd-eperm', 'getfd-esrch'):
                def getfd(*args):
                    ctypes.set_errno(errno.EPERM if observation == 'getfd-eperm' else errno.ESRCH)
                    return -1
                with h['session_dup'](types.SimpleNamespace(pidfd_getfd=getfd), 12, 13):
                    raise AssertionError('failed pidfd_getfd yielded a descriptor')
            if observation == 'other-eperm':
                raise PermissionError(errno.EPERM, 'FIXTURE_PRIVATE_DETAIL')
            if observation == 'timeout':
                raise subprocess.TimeoutExpired(['FIXTURE_PRIVATE_DETAIL'], 0)
            if observation == 'in-flight':
                raise Refusal('IN_FLIGHT')
            pids = (502,) if observation == 'desired-idle' else (501, 502, 503)
            start = 100 if observation != 'session-drift' or samples == 1 else 101
            return start, [calls[pid] for pid in pids]
        def watch():
            if observation == 'watch-drift':
                raise Refusal(h['SESSION_UNKNOWN'])
        yield sample, forbidden_signal, watch

    def peer_logins(rows, users):
        global identity_reads, before_inspect
        assert users == {'alice': '10.255.1.10', 'bob': '10.255.1.11'}
        identity_reads += 1
        if observation == 'identity-drift' and identity_reads == 2:
            raise Refusal(h['SESSION_UNKNOWN'])
        if (observation, identity_reads) in (('file-drift', 1), ('manifest-drift', 2)):
            # External same-byte inode replacement during the observation.
            assert snapshot() == before_inspect
            victim = chap if observation == 'file-drift' else manifest
            replacement = victim.with_suffix('.replacement')
            replacement.write_bytes(victim.read_bytes())
            replacement.replace(victim)
            before_inspect = snapshot()
        return {call[3]: 'bob' if call[3] == 502 else 'alice' for call in rows}

    h.update(revoke_ppp_view=view, revoke_peer_logins=peer_logins)
    with directory(h['SYSTEM']) as contender:
        h['fcntl'].flock(contender, (h['fcntl'].LOCK_EX if observation == 'exclusive-held' else h['fcntl'].LOCK_SH)
                         | h['fcntl'].LOCK_NB)
        result = wire('inspect-chap', stdin=f['stdin'])
    assert snapshot() == before_inspect and not changes and not intent.exists()
    if observation in ('original', 'fenced-original', 'desired', 'desired-idle', 'identity-drift', 'file-drift', 'manifest-drift', 'watch-drift'):
        assert samples >= 2 and identity_reads >= 2, 'did not sample PPP identities under the host frame'
    elif observation == 'session-drift':
        assert samples >= 2 and identity_reads >= 1, 'did not reach the changing session observations'
    elif observation in ('getfd-eperm', 'getfd-esrch', 'other-eperm', 'timeout', 'in-flight'):
        assert samples == 1 and not identity_reads
    else:
        assert not samples and not identity_reads
    print(json.dumps(result))
    sys.exit(0)
if scenario.startswith('chap-sync-'):
    chap.write_bytes(stock_chap + begin + old_row + end + foreign)
    params = dict(currentUsers=old_users, desiredUsers=new_users)
    changed = {'ok': True, 'backupId': token, 'changed': True}
    no_change = dict(changed, changed=False)
    def expect(action, payload, **kw):
        code, stdout, stderr = wire(action, **kw)
        assert code == 0 and not stderr and json.loads(stdout) == payload, (code, stderr)
    initial = snapshot()
    expect('check-chap', changed, **params)
    expect('inspect-chap', dict(ok=True, backupId=token, projection='original', activeTargetSessions=0), **params)
    assert snapshot() == initial and not changes
    if scenario == 'chap-sync-drift':
        # A file looking exactly like DESIRED does not authorize replay.
        chap.write_bytes(stock_chap + begin + new_row + end + foreign)
        pre = snapshot()
        expect('inspect-chap', dict(ok=True, backupId=token, projection='desired', activeTargetSessions=0), **params)
        assert wire('check-chap', **params) == (70, '', 'DIRECT_CHAP_REFUSED\n')
        assert wire('sync-chap', **params) == (70, '', 'DIRECT_CHAP_REFUSED\n')
        assert snapshot() == pre and not changes
    elif scenario == 'chap-sync-guards':
        invalid_blocks = {
            'missing': stock_chap + foreign,
            'nested': stock_chap + begin + begin + old_row + end + foreign,
            'duplicate-marker': stock_chap + begin + old_row + end + b'  ' + end,
            'duplicate-row': stock_chap + begin + old_row + old_row + end,
            'drift-password': stock_chap + begin + old_row.replace(b'test-old', b'test-other') + end,
            'drift-address': stock_chap + begin + old_row.replace(b'.10', b'.12') + end,
            'no-end-lf': stock_chap + begin + old_row + end.rstrip(b'\n'),
            'foreign-current-login': stock_chap + begin + old_row + end + b"'alice' * dummy *\n",
            'foreign-desired-login': stock_chap + b'bob l2tpd dummy *\n' + begin + old_row + end,
            'disabled-login': stock_chap + begin + old_row + end + b'disabled l2tpd dummy *\n',
            'wildcard': stock_chap + begin + old_row + end + b'"*" "l2tpd" dummy *\n',
            'ambiguous-foreign': stock_chap + begin + old_row + end + b'"unfinished dummy *\n',
            'continued': stock_chap + b'outsider other dummy \\\n' + begin + old_row + end,
        }
        for label, invalid in invalid_blocks.items():
            chap.write_bytes(invalid)
            pre = snapshot()
            assert wire('check-chap', **params) == (70, '', 'DIRECT_CHAP_REFUSED\n'), label
            assert wire('sync-chap', **params) == (70, '', 'DIRECT_CHAP_REFUSED\n'), label
            assert wire('inspect-chap', **params) == (70, '', 'DIRECT_INSPECT_CHAP_PROJECTION_UNPROVED\n'), label
            assert snapshot() == pre and not changes, label
        chap.write_bytes(stock_chap + begin + old_row + end + foreign)
        chap.chmod(0o644)
        pre = snapshot()
        assert wire('sync-chap', **params) == (70, '', 'DIRECT_CHAP_REFUSED\n') and snapshot() == pre
        chap.chmod(0o600)
        chap.rename(chap.with_suffix('.original'))
        chap.symlink_to(chap.with_suffix('.original'))
        assert wire('sync-chap', **params) == (70, '', 'DIRECT_CHAP_REFUSED\n')
        assert chap.is_symlink() and chap.read_bytes() == stock_chap + begin + old_row + end + foreign
        chap.unlink()
        chap.with_suffix('.original').rename(chap)
        pre = snapshot()
        for invalid in ([dict(new_users[0], ipAddress='10.255.1.20')], [dict(new_users[0], password='@indirect')],
                        [new_users[0], dict(new_users[0], login='duplicate-ip')]):
            assert wire('check-chap', currentUsers=old_users, desiredUsers=invalid) == (70, '', 'DIRECT_CHAP_REFUSED\n')
        with directory(h['SYSTEM']) as held:
            h['fcntl'].flock(held, h['fcntl'].LOCK_SH | h['fcntl'].LOCK_NB)
            for action in ('check-chap', 'sync-chap'):
                assert wire(action, **params) == (75, '', '')
        assert snapshot() == pre and not changes
        escaped = [dict(old_users[0], password='quote" slash\\ and # hash')]
        expect('sync-chap', changed, currentUsers=old_users, desiredUsers=escaped)
        assert chap.read_bytes() == stock_chap + begin + b'"alice" l2tpd "quote\\" slash\\\\ and # hash" 10.255.1.10\n' + end + foreign
        expect('sync-chap', changed, currentUsers=escaped, desiredUsers=[])
        assert chap.read_bytes() == stock_chap + begin + end + foreign
    elif scenario == 'chap-sync-unknown':
        write = h['write']
        def lost(path, *args, **kwargs):
            assert path == str(chap)
            write(path, *args, **kwargs)
            raise Refusal('RUNTIME_UNPROVED')
        h['write'] = lost
        assert wire('sync-chap', **params) == (75, '', '')
        assert chap.read_bytes() == stock_chap + begin + new_row + end + foreign and not changes
    elif scenario == 'chap-sync-revoke':
        chap.write_bytes(stock_chap + begin + old_row + new_row + end + foreign)
        current = old_users + new_users
        desired = [dict(old_users[0], enabled=False)] + new_users
        prior = snapshot()
        expect('check-chap', changed, currentUsers=current, desiredUsers=desired, revokedLogin='alice')
        assert snapshot() == prior and not changes
        for substitute in (new_users[1:], [dict(desired[0], password='replaced')] + new_users):
            assert wire('sync-chap', currentUsers=current, desiredUsers=substitute, revokedLogin='alice') == (70, '', 'DIRECT_CHAP_REFUSED\n')
        assert snapshot() == prior
        drain_calls = []
        def drain(request, blocked, record, *rest):
            assert request['revokedLogin'] == 'alice' and blocked['currentUsers'] == desired
            assert h['raw'](record) == chap.read_bytes() == stock_chap + begin + new_row + end + foreign
            with directory(h['SYSTEM']) as contender:
                try:
                    h['fcntl'].flock(contender, h['fcntl'].LOCK_SH | h['fcntl'].LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError('lost DIRECT flock')
            drain_calls.append(request['currentUsers'])
            return {'sessionsTerminated': 2 if len(drain_calls) == 1 else 0, 'complete': len(drain_calls) == 1}
        h['revoke_ppp'] = drain
        expect('sync-chap', dict(changed, sessionsTerminated=2, complete=True),
               currentUsers=current, desiredUsers=desired, revokedLogin='alice')
        prior = snapshot()
        expect('sync-chap', dict(no_change, sessionsTerminated=0, complete=False),
               currentUsers=desired, desiredUsers=desired, revokedLogin='alice')
        assert snapshot() == prior and len(drain_calls) == 2 and not changes
    else:
        def other_files():
            return [w for w in snapshot() if w[-1] is not None and w[0] != str(chap.relative_to(root))]
        other_before = other_files()
        expect('sync-chap', changed, **params)
        assert chap.read_bytes() == stock_chap + begin + new_row + end + foreign and not changes
        assert other_files() == other_before
        # New no-op cannot toggle disabled rows on disk or replace the inode.
        initial = snapshot()
        expect('inspect-chap', dict(ok=True, backupId=token, projection='desired', activeTargetSessions=0), **params)
        expect('sync-chap', no_change, currentUsers=new_users, desiredUsers=new_users[:1])
        assert snapshot() == initial
        assert wire('prepare-remove') == (70, '', 'DIRECT_ROLLBACK_DRIFT\n')  # changed block, no DB projection
        assert wire('prepare-remove', currentUsers=old_users) == (70, '', 'DIRECT_ROLLBACK_DRIFT\n')
        assert snapshot() == initial and not changes and not intent.exists()
        req['currentUsers'] = new_users
    if scenario != 'chap-sync-remove':
        assert (manifest.read_bytes(), manifest.stat().st_ino) == manifest_saved and not intent.exists()
        print('ok')
        sys.exit(0)
    initial = snapshot()
a = wire('prepare-remove')
assert snapshot() == initial and not changes and not intent.exists()
if scenario in ('udp-missing-preview','udp-wrong-owner-preview'):
    assert a == (70, '', 'DIRECT_RUNTIME_UNPROVED\n'), a
elif scenario == 'udp-unproved-transport':
    assert a == (70, '', 'DIRECT_CANDIDATE_INVALID\n'), a
elif scenario in ('foreign-drop','foreign-dep','vpn-generation','foreign-ike','foreign-rule','foreign-listener', 'dynamic-user','ambiguous',
                'foreign-network-witness',
                'ambiguous-shared','duplicate-json','nft-drift','invalid-candidate','active-ppp','wrong-network','wrong-node',
                'wrong-machine','missing-manifest'):
    assert a[0] == 70 and a[1] == '' and a[2].startswith('DIRECT_'), a
    if scenario == 'invalid-candidate': assert a[2] == 'DIRECT_CANDIDATE_INVALID\n' and checks[-2:] == [h['MAIN'], 'stdin:']
    if scenario == 'dynamic-user': assert a[2] == 'DIRECT_PROFILE_USERS\n'
    if scenario == 'foreign-network-witness':
        assert a == (70, '', 'DIRECT_ROLLBACK_DRIFT\n') and foreign_witness.is_symlink() and all(policy.values())
else:
    assert a[0] == 0 and a[2] == '', a
    proof = json.loads(a[1])
    assert set(proof) == {'ok','machineId','backupId','baseline'}
    if scenario == 'udp-outbound-preview':
        after_preview = True
        assert wire('prepare-remove') == a, 'outbound UDP changed the Remove baseline'
        assert snapshot() == initial and not changes and not intent.exists()
    stale = {'stale-main': Path(P['main']), 'apply-stale-bridge': Path(h['BRIDGE']), 'stale-manifest': manifest}
    if scenario in stale:
        p = stale[scenario]
        q = p.with_suffix('.new'); q.write_bytes(p.read_bytes()); q.replace(p)
    if scenario == 'chap-sync-remove':
        # Unrelated edit after prepare, including CRLF and a non-UTF8 comment.
        chap.write_bytes(b'# later prefix\r\n' + chap.read_bytes())
    recheck = snapshot()
    censuses = []
    census_mode = scenario.removeprefix('census-') if scenario.startswith('census-') else None
    expected = 'e' * 64
    deadline = h['DEADLINE']
    if census_mode is not None:
        def census(request):
            assert request == req
            assert h['DEADLINE'] < deadline and h['DEADLINE'] <= h['time'].monotonic() + 7
            with directory(h['SYSTEM']) as contender:
                try:
                    mode = h['fcntl'].LOCK_SH if wire_action == 'remove' else h['fcntl'].LOCK_EX
                    h['fcntl'].flock(contender, mode | h['fcntl'].LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError('census not under the expected DIRECT flock')
            assert not changes and not intent.exists()
            censuses.append(request)
            if census_mode == 'unknown':
                raise Refusal('SESSION_COUNT_UNPROVED')
            if census_mode == 'timeout':
                raise subprocess.TimeoutExpired([], 7)
            return {'activeSessions': int(census_mode == 'busy'),
                    'census': 'f' * 64 if census_mode == 'changed' and wire_action == 'remove' else 'e' * 64}
        h['collect_session_census'] = census
        if census_mode in ('idle', 'changed', 'ipsec-race'):
            preview = wire('session-count')
            assert preview[0] == 0 and preview[2] == '', preview
            expected = json.loads(preview[1])['census']
            censuses.clear()

        if census_mode == 'ipsec-race':
            ipsec_live = True
            preview = wire('session-count')
            assert preview[0] == 0 and preview[2] == '', preview
            count = json.loads(preview[1])
            assert count['activeSessions'] == 0 and count['activeIpsec'] == 1 and len(count['census']) == 64
            censuses.clear()
            assert wire('prepare-remove') == (70, '', 'DIRECT_REMOVE_IPSEC_BUSY\n')
            assert wire('remove', baseline=proof['baseline'], expectedCensus=expected) == (70, '', 'DIRECT_REMOVE_IPSEC_BUSY\n')
            assert snapshot() == recheck and not changes and not intent.exists()
            ipsec_live = False
            ipsec_appears_at_recount = True
    if scenario == 'apply-quiescent-dependent':
        preview = wire('session-count')
        assert preview[0] == 0 and preview[2] == '', preview
        count = json.loads(preview[1])
        expected = count['census']
        assert count['activeSessions'] == count['activeIpsec'] == 0 and len(expected) == 64
        assert snapshot() == recheck and not changes and not intent.exists()
        assert l2tp_reads == 2
        # Use the same live SA for the read-only census and both Remove guards.
        checked_vpn_empty = h['vpn_empty']
        vpn_empty_calls = []
        def record_vpn_empty(**kwargs):
            result = checked_vpn_empty(**kwargs)
            vpn_empty_calls.append(result)
            return result
        h['vpn_empty'] = record_vpn_empty
        ipsec_live = True
        code, stdout, stderr = wire('session-count')
        assert (code, stderr) == (0, ''), (code, stderr)
        busy = json.loads(stdout)
        assert busy['activeSessions'] == 0 and busy['activeIpsec'] == 1 and len(busy['census']) == 64, busy
        assert busy['census'] != expected and not vpn_empty_calls
        assert wire('prepare-remove') == (70, '', 'DIRECT_REMOVE_IPSEC_BUSY\n') and vpn_empty_calls == [False]
        assert wire('remove', baseline=proof['baseline'], expectedCensus=busy['census']) == (
            70, '', 'DIRECT_REMOVE_IPSEC_BUSY\n') and vpn_empty_calls == [False, False]
        foreign_l2tp_listener = True
        code, stdout, stderr = wire('session-count')
        assert (code, json.loads(stdout), stderr) == (0, {'activeSessions': None, 'activeIpsec': 1, 'census': None}, '')
        foreign_l2tp_listener = False

        revoke = dict(currentUsers=new_users, desiredUsers=new_users, revokedLogin='disabled')
        for stray_pppd in (False, True):
            code, stdout, stderr = wire('inspect-chap', **revoke)
            if stray_pppd:
                assert (code, stdout, stderr) == (70, '', 'DIRECT_INSPECT_PPP_UNPROVED\n')
            else:
                assert (code, stderr) == (0, ''), (code, stderr)
                assert json.loads(stdout) == dict(ok=True, backupId=token, projection='both', activeTargetSessions=0)
            code, stdout, stderr = wire('sync-chap', **revoke)
            assert (code, stderr) == (0, ''), (code, stderr)
            assert json.loads(stdout) == dict(ok=True, backupId=token, changed=False, sessionsTerminated=0,
                                              complete=not stray_pppd)
        stray_pppd = False
        assert vpn_empty_calls == [False, False] and snapshot() == recheck and not changes and not intent.exists()
        h['vpn_empty'] = checked_vpn_empty
        ipsec_live = False
        clean_reads = l2tp_reads
        group_populated = True
        code, stdout, stderr = wire('session-count')
        assert (code, json.loads(stdout), stderr) == (0, {'activeSessions': None, 'activeIpsec': 0, 'census': None}, '')
        assert l2tp_reads == clean_reads
        group_populated = False
        lingering_from = l2tp_reads + 1
        code, stdout, stderr = wire('session-count')
        assert (code, json.loads(stdout), stderr) == (0, {'activeSessions': None, 'activeIpsec': 0, 'census': None}, '')
        lingering_from = l2tp_reads + 2  # first final sample clean; second sees a residual tunnel
        assert wire('remove', baseline=proof['baseline'], expectedCensus=expected) == (70, '', 'DIRECT_REMOVE_REFUSED\n')
        assert l2tp_reads == lingering_from
        assert snapshot() == recheck and not changes and not intent.exists()
        lingering_from = float('inf')
    b = wire('remove', baseline=proof['baseline'], **({'expectedCensus': expected}
        if census_mode or scenario == 'apply-quiescent-dependent' else {}))
    assert len(censuses) == int(census_mode is not None) and h['DEADLINE'] == deadline
    if census_mode == 'ipsec-race':
        assert b == (70,'','DIRECT_REMOVE_IPSEC_BUSY\n') and not changes and snapshot() == recheck and not intent.exists()
    elif scenario in stale or census_mode in ('unknown', 'busy', 'changed'):
        assert b == (70,'','DIRECT_REMOVE_REFUSED\n') and not changes and snapshot() == recheck and not intent.exists()
    elif census_mode == 'timeout':
        assert b == (75,'','') and not changes and snapshot() == recheck and not intent.exists()
    elif scenario != 'xl-stop-failed' and (scenario.startswith(('xl-stop-', 'xl-reset-')) or scenario == 'ike-stop-failed'):
        assert b == (75,'','') and intent.is_file(), (b, changes)
        assert changes == [('stop', XL)] + ([('stop', IKE)] if scenario == 'ike-stop-failed' else
            [('reset-failed', XL)] if scenario.startswith('xl-reset-') else []), changes
        assert all(policy.values()) and wire('prepare-remove')[0] != 0
    elif scenario in ('unknown-stop','lingering-listener','lingering-route'):
        assert b == (75,'','') and intent.is_file(), b
        assert policy['route'] and policy['nft']
        assert wire('prepare-remove')[0] != 0
    elif scenario == 'udp-wrong-address-final':
        assert b == (75,'','') and intent.is_file(), b
        assert not any(policy.values())  # readiness passed; the final listener proof did not
    else:
        assert b[0] == 0 and b[2] == '' and json.loads(b[1]) == dict(ok=True, backupId=token, removed=True), (b, changes)
        if scenario == 'xl-stop-failed':
            assert changes[:4] == [('stop', XL), ('reset-failed', XL), ('stop', IKE), ('stop', NET)], changes
        if scenario == 'normal':
            assert ('reset-failed', XL) not in changes
        assert json.loads(Path(P['main']).read_text()) == (f['expected'] if scenario.startswith('apply') else json.loads(f['old']))
        assert R(h['BRIDGE']) == side and units[B] == side_unit
        assert all(R(p) == before['files'][k] for k,p in P.items() if k not in ('main','chap'))
        preserved = b'# later prefix\r\n' + stock_chap + foreign + b'\n# appended during Remove\r\n'
        # Without foreign edits the separator disappears with the block. The
        # edited prefix above no longer matches the preimage; preserve it whole.
        if suffix:
            separator = b'\n' if scenario in ('chap-unterminated-legacy-suffix', 'chap-unterminated-list-suffix') else b''
            preserved = chap_preimage + separator + suffix
        elif scenario != 'chap-sync-remove':
            preserved = chap_preimage
        assert chap.read_bytes() == preserved
        assert R(P['chap'])['mode'] == 0o600
        assert not any(policy.values()) and intent.is_file() and wire('prepare-remove')[0] != 0
        assert not Path(h['DROP_DIR']).exists() and not Path(h['NFT_DIR']).exists()
        assert not list((root / 'run').glob('celerity-rebuild-l2tp-network-*'))
        assert all(B not in cmd for cmd in changes) and ('restart',X) in changes
        if scenario == 'xtls-apply-remove':
            assert xtls.read_bytes() == xtls_bytes and xtls.stat().st_ino == xtls_inode
        assert h['ip']('rule','show')[-1] == foreign_rule and h['ip']('route','show','table','all') == [foreign_route]
    if scenario != 'stale-manifest': assert (manifest.read_bytes(), manifest.stat().st_ino) == manifest_saved
print('ok')
`;

for (const scenario of ['normal', 'xtls-apply-remove', 'xtls-rollback', 'apply', 'apply-quiescent-dependent',
    'stale-main', 'stale-manifest', 'apply-stale-bridge', 'vpn-generation', 'chap-epoch',
    'chap-legacy-replaced', 'chap-sync-remove', 'chap-sync-drift', 'chap-sync-guards', 'chap-sync-unknown', 'chap-sync-revoke',
    'chap-unterminated-clean', 'chap-unterminated-legacy-suffix', 'chap-unterminated-list-suffix', 'chap-unterminated-separated',
    'chap-terminated-suffix',
    'foreign-drop', 'foreign-dep', 'foreign-ike', 'foreign-rule', 'foreign-listener', 'ambiguous', 'ambiguous-shared',
    'duplicate-json', 'nft-drift', 'foreign-network-witness', 'invalid-candidate', 'active-ppp', 'wrong-network', 'wrong-machine', 'wrong-node',
    'missing-manifest', 'dynamic-user', 'unknown-stop', 'lingering-listener', 'lingering-route',
    'xl-stop-failed', 'xl-stop-nonzero', 'xl-stop-timeout', 'xl-stop-job', 'xl-stop-live-pid',
    'xl-reset-job', 'xl-reset-live-pid', 'ike-stop-failed',
    'census-idle', 'census-unknown', 'census-busy', 'census-changed', 'census-timeout', 'census-ipsec-race',
    'udp-outbound-preview', 'udp-outbound-restart', 'udp-missing-preview', 'udp-wrong-owner-preview', 'udp-wrong-address-final',
    'udp-unproved-transport']) {
    test(`direct remove fixture: ${scenario}`, () => {
        const dir = mkdtempSync(join(process.cwd(), '.direct-remove-fixture-'));
        try {
            const stock = JSON.parse(old);
            if (scenario.startsWith('udp-')) stock.inbounds.push({ tag: 'retained-udp',
                listen: '192.0.2.19', port: 54453, protocol: 'dokodemo-door',
                settings: { network: ['tcp', 'udp'], address: '127.0.0.1', port: 53 } });
            if (scenario === 'udp-unproved-transport') {
                stock.inbounds.find(i => i.protocol === 'vless').streamSettings = {
                    network: 'xhttp', security: 'tls', tlsSettings: { alpn: ['h3'] },
                };
            }
            const main = scenario.startsWith('udp-') ? JSON.stringify(stock) : old;
            const withUdp = main === old ? installed : composeRebuildRelayMain({ main, bridge: null }, {
                nodeId, controlPlaneAddresses: controls, carryDomain: false, tproxyPort: network.tproxyPort,
                mainSha256: sha(main), bridgeSha256: null,
            });
            const legacySource = scenario === 'chap-epoch' ? loadChapEpochLegacySource() : undefined;
            const result = spawnSync('python3', ['-I', '-B', '-c', fixture, join(__dirname, '../rebuildRelayDirectHost.py'), dir, scenario],
                { input: JSON.stringify({ old: main, installed: withUdp, applied, expected, network, backupId, nodeId, machineId, legacySource }), encoding: 'utf8', timeout: 10000 });
            assert.equal(result.status, 0, result.stderr || result.error?.message);
            assert.equal(result.stdout, 'ok\n');
        } finally { rmSync(dir, { recursive: true, force: true }); }
    });
}

for (const epoch of ['reboot', 'xl2tpd-restart']) {
    test(`DIRECT census auto-reattest and Remove: ${epoch}`, async () => {
        const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: nodeId,
            C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: 'd'.repeat(64) };
        const node = { _id: nodeId, ip: relay.ip, ssh: { port: 22, username: 'root' } };
        const currentUsers = [{ login: 'alice', password: 'test-old', ipAddress: '10.255.1.10', enabled: true }];
        const dir = mkdtempSync(join(process.cwd(), '.direct-epoch-fixture-'));
        let worker, exit, replies;
        let workerStderr = '';
        const actions = [];
        class SSH {
            connect() {}
            disconnect() {}
            async exec(command, { stdin }, verify) {
                await verify();
                actions.push(JSON.parse(stdin).action);
                let frame = { command, stdin };
                if (!worker) {
                    frame = { ...frame, old, installed, network, backupId, nodeId, machineId };
                    worker = spawn('/usr/bin/python3', ['-I', '-B', '-c', fixture,
                        join(__dirname, '../rebuildRelayDirectHost.py'), dir, `epoch-remove-${epoch}`], { env: {}, timeout: 10000 });
                    exit = new Promise(resolve => worker.once('close', resolve));
                    worker.on('error', error => { workerStderr += error.message; });
                    worker.stdin.on('error', error => { workerStderr += error.message; });
                    worker.stderr.setEncoding('utf8').on('data', text => { workerStderr += text; });
                    replies = createInterface({ input: worker.stdout })[Symbol.asyncIterator]();
                }
                worker.stdin.write(`${JSON.stringify(frame)}\n`);
                const reply = await replies.next();
                assert.ok(!reply.done, 'missing emitted host reply');
                const [code, stdout, stderr] = JSON.parse(reply.value);
                return { code, stdout, stderr };
            }
        }
        const remote = createRelayDirect({ node, env, SSH: attested(SSH, machineId), verifyRemoveStdin: true });
        const input = { nodeId, backupId, network, currentUsers };
        const held = () => true;
        try {
            const busy = await remote.readSessionCount(input, held);
            assert.deepEqual(busy, { activeSessions: 0, activeIpsec: 1, census: busy.census });
            assert.match(busy.census, /^[a-f0-9]{64}$/);
            await assert.rejects(remote.prepareRemove({ ...input, expectedCensus: busy.census }, held), {
                code: 'REBUILD_L2TP_DIRECT_REMOVE_IPSEC_BUSY',
            });
            const idle = await remote.readSessionCount(input, held);
            assert.deepEqual(idle, { activeSessions: 0, activeIpsec: 0, census: idle.census });
            assert.match(idle.census, /^[a-f0-9]{64}$/);
            assert.notEqual(idle.census, busy.census);
            const plan = await remote.prepareRemove({ ...input, expectedCensus: idle.census }, held);
            assert.equal(await remote.remove(plan, held), true);
            assert.deepEqual(actions, ['session-count', 'reattest-runtime', 'session-count', 'prepare-remove',
                'session-count', 'prepare-remove', 'remove']);
        } finally {
            try {
                await remote.close();
                if (worker) {
                    worker.stdin.end();
                    assert.equal(await exit, 0, workerStderr);
                    assert.equal(workerStderr, '');
                }
            } finally { rmSync(dir, { recursive: true, force: true }); }
        }
    });
}

test('active retirement through the emitted DIRECT helper', async t => {
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: nodeId,
        C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: 'd'.repeat(64) };
    const node = { _id: nodeId, ip: relay.ip, ssh: { port: 22, username: 'root' } };
    const successful = ['normal', 'cohort-plain', 'cohort-nat', 'cohort-two-nat'];
    const unproved = ['foreign-transform', 'foreign-socket', 'wrong-socket-cgroup', 'wrong-tunnel', 'extra-sa', 'no-vici',
        'foreign-l2tp-socket', 'no-l2tp-netlink', 'cohort-shared-peer', 'cohort-shared-child', 'cohort-foreign-policy',
        'cohort-wrong-encap', 'cohort-shared-tunnel', 'cohort-duplicate-socket'];
    const uncertain = ['lost-terminate', 'cleanup-unknown', 'late-intent-drift', 'late-intent-chap-drift', 'late-foreign-l2tp',
        'cohort-survivor-drift', 'cohort-late-ike-arrival'];
    const changed = ['same-count-drift', 'fenced-drift', 'queued-ike', 'gate-unsupported', 'cohort-same-count-drift',
        'cohort-ike-arrival', 'cohort-nat-drift'];
    for (const retirement of [...successful, ...changed, ...uncertain, ...unproved]) {
        await t.test(retirement, async () => {
            let worker, result, replies;
            let workerStderr = '';
            const cohort = retirement.startsWith('cohort-');
            const currentUsers = [{ login: 'alice', password: 'test-old', ipAddress: '10.255.1.10', enabled: true }];
            if (cohort) currentUsers.push({ login: 'bob', password: 'test-new', ipAddress: '10.255.1.11', enabled: true });
            const dir = mkdtempSync(join(process.cwd(), '.direct-retirement-fixture-'));
            class SSH {
                connect() { assert.equal(this.usePool, false); }
                disconnect() {}
                async exec(command, { stdin }, verify) {
                    assert.ok(currentUsers.every(user => !command.includes(user.password)));
                    await verify();
                    let frame = { command, stdin };
                    if (!worker) {
                        frame = { ...frame, old, installed, network, backupId, nodeId, machineId, retirement, unproved, successful };
                        worker = spawn('/usr/bin/python3', ['-I', '-B', '-c', fixture,
                            join(__dirname, '../rebuildRelayDirectHost.py'), dir, 'retire-active'], { env: {} });
                        result = new Promise(resolve => {
                            worker.on('error', error => { workerStderr += error.message; });
                            worker.on('close', resolve);
                        });
                        worker.stdin.on('error', error => { workerStderr += error.message; });
                        worker.stderr.setEncoding('utf8').on('data', text => { workerStderr += text; });
                        replies = createInterface({ input: worker.stdout })[Symbol.asyncIterator]();
                    }
                    worker.stdin.write(`${JSON.stringify(frame)}\n`);
                    const reply = await replies.next();
                    assert.ok(!reply.done, 'missing emitted host reply');
                    const [code, stdout, stderr] = JSON.parse(reply.value);
                    return { code, stdout, stderr };
                }
            }
            const remote = createRelayDirect({ node, env, SSH: attested(SSH, machineId), verifyRemoveStdin: true });
            try {
                const input = { nodeId, backupId, network, currentUsers };
                const proof = await remote.readRetirementCount(input);
                assert.equal(proof.activeClients, unproved.includes(retirement) ? null : cohort ? 2 : 1);
                if (proof.activeClients === null) return;
                const plan = await remote.prepareRemove({ ...input, retirement: true, drain: true, expectedCensus: proof.census });
                const removing = remote.remove(plan, () => true);
                if (successful.includes(retirement)) assert.equal(await removing, true);
                else if (uncertain.includes(retirement)) {
                    await assert.rejects(removing, { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', remoteOutcomeUncertain: true });
                } else await assert.rejects(removing, { code: 'REBUILD_L2TP_DIRECT_REMOVE_PREVIEW_CHANGED', commandSettled: true });
                assert.equal(await remote.remove(plan, () => assert.fail('replay')), false);
            } finally {
                try {
                    await remote.close();
                    if (worker) {
                        worker.stdin.end();
                        const status = await result;
                        assert.equal(status, 0, workerStderr);
                        assert.equal(workerStderr, '');
                    }
                } finally { rmSync(dir, { recursive: true, force: true }); }
            }
        });
    }
});

test('inspectChap uses a full pinned transport and host frame without writes or signals', async t => {
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: nodeId,
        C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: 'd'.repeat(64) };
    const node = { _id: nodeId, ip: relay.ip, ssh: { port: 22, username: 'root' } };
    const alice = { login: 'alice', password: 'test-old', ipAddress: '10.255.1.10', enabled: true };
    const bob = { login: 'bob', password: 'test-new', ipAddress: '10.255.1.11', enabled: true };
    const installation = { nodeId, backupId, network };
    for (const [observation, projection, activeTargetSessions, inspectionReason] of [
        ['original', 'original', 2], ['fenced-original', 'original', 2], ['desired', 'desired', 2],
        ['desired-idle', 'desired', 0], ['create', 'original', 0],
        ...['failed', 'mixed'].map(mode => [mode, null, null, 'chap-projection-unproved']),
        ...['session-drift', 'identity-drift', 'getfd-esrch', 'other-eperm'].map(mode => [mode, null, null, 'ppp-unproved']),
        ...['file-drift', 'manifest-drift', 'watch-drift'].map(mode => [mode, null, null, 'inspect-readback-unproved']),
        ['getfd-eperm', null, null, 'pidfd-getfd-eperm'], ['exclusive-held'], ['timeout'], ['in-flight'],
    ]) {
        await t.test(observation, async () => {
            const create = observation === 'create';
            const currentUsers = create ? [alice] : [alice, bob], desiredUsers = create ? [alice, bob] : [bob];
            const revokedLogin = create ? undefined : 'alice';
            const guards = [];
            let calls = 0;
            let fixtureFailure;
            class SSH {
                constructor(selected, options) {
                    assert.equal(selected, node);
                    assert.deepEqual(options, { expectedEndpoint: { ip: node.ip, ...node.ssh }, expectedHostKeySha256: 'd'.repeat(64) });
                }
                connect() { assert.equal(this.usePool, false); }
                disconnect() {}
                exec(command, { stdin }) {
                    ++calls;
                    const dir = mkdtempSync(join(process.cwd(), '.direct-inspect-fixture-'));
                    try {
                        assert.ok(!command.includes(alice.password) && !command.includes(bob.password));
                        assert.deepEqual(JSON.parse(stdin), { action: 'inspect-chap', machineId, ...installation,
                            currentUsers, desiredUsers, ...(revokedLogin && { revokedLogin }) });
                        const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', fixture,
                            join(__dirname, '../rebuildRelayDirectHost.py'), dir, 'chap-inspect-active'], {
                            input: JSON.stringify({ old, installed, network, backupId, nodeId, machineId, observation, command, stdin }),
                            encoding: 'utf8', timeout: 10000, env: {},
                        });
                        assert.equal(result.status, 0, result.stderr || result.error?.message);
                        const [code, stdout, stderr] = JSON.parse(result.stdout);
                        return { code, stdout, stderr };
                    } catch (error) { fixtureFailure = error; throw error; }
                    finally { rmSync(dir, { recursive: true, force: true }); }
                }
            }
            const remote = createRelayDirect({ node, env, SSH: attested(SSH, machineId) });
            try {
                const result = remote.inspectChap(installation, currentUsers, desiredUsers, () => { guards.push(calls); }, revokedLogin);
                if (projection) {
                    assert.deepEqual(await result, { projection, activeTargetSessions });
                    assert.deepEqual(guards, [0, 1]);
                } else {
                    await assert.rejects(result, error => {
                        assert.equal(error.code, inspectionReason
                            ? 'REBUILD_L2TP_DIRECT_INSPECT_UNPROVED' : 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN');
                        assert.equal(error.inspectionReason, inspectionReason);
                        assert.doesNotMatch(JSON.stringify(error), /FIXTURE_PRIVATE_DETAIL/);
                        return true;
                    });
                }
                assert.equal(calls, 1);
            } finally {
                await remote.close();
                if (fixtureFailure) throw fixtureFailure;
            }
        });
    }
});
