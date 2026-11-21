'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { mkdtempSync, rmSync } = require('node:fs');
const { join } = require('node:path');
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
import contextlib, copy, io, json, os, pathlib, sys, types
from pathlib import Path
source, tmp, scenario = sys.argv[1:]
f = json.load(sys.stdin)
root = Path(tmp)
os.umask(0o077)
h = {'__name__': 'fixture'}
mock_faults = []
def no_host_dispatch(event, _):
    if event in {'subprocess.Popen','os.system','os.posix_spawn','os.exec','os.fork'} or event.startswith('socket.'):
        mock_faults.append(event)
        raise AssertionError('non-modeled host dispatch')
sys.addaudithook(no_host_dispatch)
exec(compile(Path(source).read_bytes(), source, 'exec'), h)
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
    return types.SimpleNamespace(st_uid=0, st_gid=0, **{k: getattr(value, k) for k in ('st_mode','st_nlink','st_size')})
class FixtureOS:
    def __getattr__(self, name): return getattr(os, name)
    def fstat(self, fd): return stat(os.fstat(fd))
    def stat(self, path, *args, **kw):
        if path.startswith('/proc/'):
            return types.SimpleNamespace(st_uid=0, st_gid=0)
        return os.stat(path, *args, **kw)
    def fchown(self, fd, uid, gid):
        assert uid == gid == 0 and os.readlink('/proc/self/fd/' + str(fd)).startswith(tmp + '/')
    def geteuid(self): return 0
h['os'] = FixtureOS()
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

def preflight(machine):
    h['need'](machine == f['machineId'], 'IDENTITY')
    return dict(machineId=machine, ppp=True, masked=False, unitsLoaded=True)
h['preflight'] = preflight
h['boot'] = lambda: 'fixture-boot'
h['ppp_empty'] = lambda: not (testing and scenario == 'active-ppp')
h['in_cgroup'] = lambda pid, info: pid == info['MainPID']
def modeled_xray_argv(info, path=None):
    expected_unit = B if path == h['BRIDGE'] else X
    h['need'](info['MainPID'] == units[expected_unit]['MainPID'] and h['working'](info), 'RUNTIME_UNPROVED')
    return info['MainPID']
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
units[IKE]['ExecStart'] = '{ path=/usr/sbin/ipsec ; argv[]=/usr/sbin/ipsec start --nofork ; }'
units[X].update(ActiveState='active', SubState='running', MainPID='10', InvocationID='old-main')
stock_units = copy.deepcopy(units)
stock_rules = [{'priority': n, 'src': 'all', 'table': t} for n, t in [(0, 255), (32766, 254), (32767, 253)]]
foreign_rule = dict(priority=10078, src='198.51.100.0/24', table=201)
foreign_route = dict(dst='198.51.100.0/24', table=201, dev='fixture0')
network, token = f['network'], f['backupId']
policy = {'nft': False, 'rule': False, 'route': False}
changes, checks = [], []
testing = False
udp_address, udp_port = '192.0.2.19', 54453
after_preview = False

def sc(*args):
    cmd, *rest = args
    if args == ('list-jobs','--no-legend','--plain'):
        pending_after = {'xl-stop-job': ('stop', XL), 'xl-reset-job': ('reset-failed', XL)}.get(scenario)
        return f'42 {XL} stop running\n'.encode() if pending_after in changes else b''
    changes.append(args)
    if args == ('daemon-reload',):
        if Path(h['NET']).exists():
            lines = Path(h['NET']).read_text().splitlines()
            pre = next((line.split('=', 1)[1] for line in lines if line.startswith('ExecStartPre=')), '')
            legacy = f'Requires={X}' in lines
            units[NET].update(LoadState='loaded', FragmentPath=h['NET'], UnitFileState='static',
                              Type='oneshot', Requires=X if legacy else '', Wants='' if legacy else X, RequiredBy=XL,
                              After=next(line.split('=', 1)[1] for line in lines if line.startswith('After=')),
                              ExecStartPre=f'{{ path=/usr/bin/systemctl ; argv[]={pre} ; ignore_errors=no ; }}' if pre else '')
            units[XL].update(DropInPaths=h['DROP'], Requires=f'{NET} {IKE}', After=f'{NET} {IKE}')
            units[X]['RequiredBy'], units[IKE]['RequiredBy'] = (NET if legacy else ''), XL
        else:
            for n in (NET, XL, IKE): units[n] = dict(stock_units[n])
            units[X]['RequiredBy'] = ''
    elif cmd == 'start' and rest == [XL]:
        for n, pid, sub in [(XL,'11','running'), (IKE,'12','running'), (NET,'0','exited')]:
            units[n].update(ActiveState='active', SubState=sub, MainPID=pid, InvocationID=n + '-installed')
        policy.update(nft=True, rule=True, route=True)
    elif args == ('restart', X):
        units[X].update(MainPID=str(40 + len(changes)), InvocationID='main-' + str(len(changes)))
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
    global l2tp_reads
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
            return b'    1 systemd\n   40 ps\n'
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
        return ('Status:\nConnections:\n' + connection + extra + 'Security Associations (0 up, 0 connecting):\n  none\n').encode()
    if a in (('/usr/sbin/ip','xfrm','policy','list'),('/usr/sbin/ip','xfrm','policy','list','nosock'),
             ('/usr/sbin/ip','xfrm','state','list','nokeys')): return b''
    if a == ('/usr/sbin/ip','-j','-N','-4','rule','show'):
        rules = stock_rules + ([foreign_rule] if testing else [])
        if policy['rule']:
            rules += [dict(priority=h['PRIORITY'], src=network['clientCidr'], table=network['routeTable'], fwmark='0x4d')]
        if testing and scenario == 'foreign-rule': rules += [dict(foreign_rule, table=network['routeTable'])]
        return h['encode'](rules)
    if a == ('/usr/sbin/ip','-j','-N','-4','route','show','table','all'):
        return h['encode'](([foreign_route] if testing else []) + ([dict(dst='default', table=network['routeTable'],
            dev='lo', type='local', scope='host')] if policy['route'] else []))
    if a == ('/usr/sbin/nft','-j','list','tables'):
        return h['encode']({'nftables': [{'table': {'family':'inet','name':'foreign'}}] +
            ([{'table': {'family':'inet','name':h['TABLE']}}] if policy['nft'] else [])})
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
before = dict(boot=h['boot'](), files={k: R(p) for k,p in P.items()}, units=stock_units, bridge=None,
              globalFiles={}, installBoot=False, ikeSockets=[],
              sockets=h['owned_sockets'](h['sock_rows'](), units[X]['MainPID']))
h['observe'] = lambda m,d,transit: before
req = {k: f[k] for k in ('network','backupId','machineId')}
nft = f'create table inet {h["TABLE"]} {{\n    comment "{token}"\n}}\n'
begin = b'# BEGIN CELERITY MANAGED L2TP USERS\n'
end = b'# END CELERITY MANAGED L2TP USERS\n'
old_row = b'"alice" l2tpd "test-old" 10.255.1.10\n'
new_row = b'"bob" l2tpd "test-new" 10.255.1.11\n'
foreign = b'elsewhere other "foreign # value" *\r\n# opaque \xff'
files = dict(main=f['installed'], nft=nft, chap=(begin + old_row + end).decode(),
             lns='ip range = 10.255.1.10-10.255.1.19\n', **{k: 'secret-fixture-only' for k in ('ike','options','secrets')})
assert h['dispatch'](dict(req, action='install', files={k:h['b64'](v.encode()) for k,v in files.items()},
    baseline=h['digest'](h['encode'](before))))['ok']
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
if scenario == 'apply-quiescent-dependent': req['transit'] = []
if scenario == 'foreign-drop': Path(h['DROP_DIR'], 'foreign.conf').write_text('untouched')
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

def wire(action, **kw):
    stdout, stderr = io.StringIO(), io.StringIO()
    saved = sys.stdin
    try:
        h['CHAP_ENTERED'] = False  # one invocation per process on the host
        sys.stdin = types.SimpleNamespace(buffer=io.BytesIO(h['encode'](dict(req, action=action, **kw))))
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = h['main']()
    finally: sys.stdin = saved
    assert not mock_faults, mock_faults
    assert 'secret-fixture-only' not in stdout.getvalue() + stderr.getvalue()
    return code, stdout.getvalue(), stderr.getvalue()

def snapshot():
    return sorted((str(p.relative_to(root)), p.lstat().st_ino, p.lstat().st_ctime_ns,
                   p.read_bytes() if p.is_file() else None) for p in root.rglob('*'))

initial = snapshot()
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
    assert snapshot() == initial and not changes
    if scenario == 'chap-sync-drift':
        # A file looking exactly like DESIRED does not authorize replay.
        chap.write_bytes(stock_chap + begin + new_row + end + foreign)
        pre = snapshot()
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
        def lost(*args):
            write(*args)
            raise Refusal('RUNTIME_UNPROVED')
        h['write'] = lost
        assert wire('sync-chap', **params) == (75, '', '')
        assert chap.read_bytes() == stock_chap + begin + new_row + end + foreign and not changes
    else:
        def other_files():
            return [w for w in snapshot() if w[-1] is not None and w[0] != str(chap.relative_to(root))]
        other_before = other_files()
        expect('sync-chap', changed, **params)
        assert chap.read_bytes() == stock_chap + begin + new_row + end + foreign and not changes
        assert other_files() == other_before
        # New no-op cannot toggle disabled rows on disk or replace the inode.
        initial = snapshot()
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
                'ambiguous-shared','duplicate-json','nft-drift','invalid-candidate','active-ppp','wrong-network','wrong-node',
                'wrong-machine','missing-manifest'):
    assert a[0] == 70 and a[1] == '' and a[2].startswith('DIRECT_'), a
    if scenario == 'invalid-candidate': assert a[2] == 'DIRECT_CANDIDATE_INVALID\n' and checks[-2:] == [h['MAIN'], 'stdin:']
    if scenario == 'dynamic-user': assert a[2] == 'DIRECT_PROFILE_USERS\n'
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
                    h['fcntl'].flock(contender, h['fcntl'].LOCK_SH | h['fcntl'].LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError('destructive census not under the exclusive Remove flock')
            assert not changes and not intent.exists()
            censuses.append(request)
            if census_mode == 'unknown':
                raise Refusal('SESSION_COUNT_UNPROVED')
            if census_mode == 'timeout':
                raise subprocess.TimeoutExpired([], 7)
            return {'activeSessions': int(census_mode == 'busy'), 'census': 'f' * 64 if census_mode == 'changed' else expected}
        h['collect_session_census'] = census
    if scenario == 'apply-quiescent-dependent':
        preview = wire('session-count')
        assert preview[0] == 0 and preview[2] == '', preview
        count = json.loads(preview[1])
        expected = count['census']
        assert count['activeSessions'] == 0 and len(expected) == 64
        assert snapshot() == recheck and not changes and not intent.exists()
        assert l2tp_reads == 2
        group_populated = True
        assert wire('session-count') == (70, '', 'DIRECT_SESSION_COUNT_UNPROVED\n') and l2tp_reads == 2
        group_populated = False
        lingering_from = l2tp_reads + 1
        assert wire('session-count') == (70, '', 'DIRECT_SESSION_COUNT_UNPROVED\n')
        lingering_from = l2tp_reads + 2  # first final sample clean; second sees a residual tunnel
        assert wire('remove', baseline=proof['baseline'], expectedCensus=expected) == (70, '', 'DIRECT_REMOVE_REFUSED\n')
        assert l2tp_reads == lingering_from
        assert snapshot() == recheck and not changes and not intent.exists()
        lingering_from = float('inf')
    b = wire('remove', baseline=proof['baseline'], **({'expectedCensus': expected}
        if census_mode or scenario == 'apply-quiescent-dependent' else {}))
    assert len(censuses) == int(census_mode is not None) and h['DEADLINE'] == deadline
    if scenario in stale or census_mode in ('unknown', 'busy', 'changed'):
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
        assert all(B not in cmd for cmd in changes) and ('restart',X) in changes
        assert h['ip']('rule','show')[-1] == foreign_rule and h['ip']('route','show','table','all') == [foreign_route]
    if scenario != 'stale-manifest': assert (manifest.read_bytes(), manifest.stat().st_ino) == manifest_saved
print('ok')
`;

for (const scenario of ['normal', 'apply', 'apply-quiescent-dependent', 'stale-main', 'stale-manifest', 'apply-stale-bridge', 'vpn-generation',
    'chap-legacy-replaced', 'chap-sync-remove', 'chap-sync-drift', 'chap-sync-guards', 'chap-sync-unknown',
    'chap-unterminated-clean', 'chap-unterminated-legacy-suffix', 'chap-unterminated-list-suffix', 'chap-unterminated-separated',
    'chap-terminated-suffix',
    'foreign-drop', 'foreign-dep', 'foreign-ike', 'foreign-rule', 'foreign-listener', 'ambiguous', 'ambiguous-shared',
    'duplicate-json', 'nft-drift', 'invalid-candidate', 'active-ppp', 'wrong-network', 'wrong-machine', 'wrong-node',
    'missing-manifest', 'dynamic-user', 'unknown-stop', 'lingering-listener', 'lingering-route',
    'xl-stop-failed', 'xl-stop-nonzero', 'xl-stop-timeout', 'xl-stop-job', 'xl-stop-live-pid',
    'xl-reset-job', 'xl-reset-live-pid', 'ike-stop-failed',
    'census-idle', 'census-unknown', 'census-busy', 'census-changed', 'census-timeout',
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
            const result = spawnSync('python3', ['-I', '-B', '-c', fixture, join(__dirname, '../rebuildRelayDirectHost.py'), dir, scenario],
                { input: JSON.stringify({ old: main, installed: withUdp, applied, expected, network, backupId, nodeId, machineId }), encoding: 'utf8', timeout: 10000 });
            assert.equal(result.status, 0, result.stderr || result.error?.message);
            assert.equal(result.stdout, 'ok\n');
        } finally { rmSync(dir, { recursive: true, force: true }); }
    });
}
