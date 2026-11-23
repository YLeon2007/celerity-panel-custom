'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { mkdirSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { composeRebuildRelayPair } = require('../rebuildRelayInstallSteps');
const { composeRebuildProfiles, syntheticTunnelSettings } = require('../../modules/relay-l2tp/tests/helpers/rebuildComposerFixture');
const stockSwan = require('./helpers/rebuildRelayStockSwan');

const nodeId = 'a'.repeat(24), backupId = 'b'.repeat(32), machineId = 'c'.repeat(32);
const network = { clientCidr: '10.255.1.0/24', tproxyPort: 12345, fwmark: 77, routeTable: 177 };
const sharedTag = 'rebuild-relay-ingress', sharedPort = 24081; // Not the generated MAIN handoff port.
const relay = { _id: nodeId, type: 'xray', cascadeRole: 'relay', active: true, ip: '192.0.2.19', port: 22001,
    xray: { inboundTag: 'client', security: 'none', transport: 'tcp', apiPort: 31001 } };
const exit = { ...relay, _id: 'd'.repeat(24), ip: '192.0.2.20', cascadeRole: 'bridge' };
const link = { _id: 'changed-forward', portalNode: nodeId, bridgeNode: exit._id, mode: 'forward',
    _rebuildVless: syntheticTunnelSettings(0), tunnelPort: 20002, tunnelUuid: '00000000-0000-4000-8000-000000000003' };
const user = n => ({ userId: `user-${n}`, xrayUuid: `00000000-0000-4000-8000-00000000000${n}` });
const controls = ['panel.invalid', relay.ip];
const compose = (nodes, links, users, installed = false) => composeRebuildProfiles({ nodes, links,
    controlPlaneAddresses: controls, usersByNode: { [nodeId]: users }, followRelayStates: installed ? [{
        node: nodeId, routingMode: 'follow-relay', routingVersion: 1, status: 'installed', desiredState: 'installed',
        secretRevision: 1, tproxyPort: network.tproxyPort,
    }] : [],
}).filter(p => p.nodeId === nodeId).map(p => p.config);
const [localMain, emptyBridge] = compose([relay, exit], [link], [user(1)]);
const main = structuredClone(localMain), bridge = structuredClone(emptyBridge);
const listen = (tag, port) => ({ tag, port, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' } });
bridge.inbounds.push(listen(sharedTag, sharedPort), listen('neighbor', 24082));
bridge.outbounds.push(...main.outbounds.splice(1));
bridge.routing.rules.push(...main.routing.rules.filter(r => r.ruleTag?.startsWith('rebuild-policy-'))
    .map(r => ({ ...r, inboundTag: [sharedTag, 'neighbor'] })));
bridge.routing.domainStrategy = 'AsIs';
main.routing.rules = main.routing.rules.filter(r => !r.ruleTag?.startsWith('rebuild-policy-'));
main.outbounds.push({ tag: 'shared-policy', protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: sharedPort }] } });
main.routing.rules.push({ type: 'field', inboundTag: [main.inbounds[0].tag], outboundTag: 'shared-policy' });
// Preserve exact preimage bytes as well as semantic contents in the split case.
const stringify = cfg => JSON.stringify(cfg) + '\n';
const sha = s => s === null ? null : createHash('sha256').update(s).digest('hex');
function installPair(main, bridge) {
    return composeRebuildRelayPair({ main, bridge }, { nodeId, controlPlaneAddresses: controls, carryDomain: false,
        tproxyPort: network.tproxyPort, mainSha256: sha(main), bridgeSha256: sha(bridge) });
}
const geoExit = { ...exit, _id: 'e'.repeat(24), ip: '192.0.2.21' };
const geoLink = { ...link, _id: 'changed-geo', bridgeNode: geoExit._id, tunnelPort: 20003,
    _rebuildVless: syntheticTunnelSettings(1), tunnelUuid: '00000000-0000-4000-8000-000000000004',
    geoRouting: { enabled: true, domains: ['full:geo.invalid'], geoip: ['ru'] } };
const laterArgs = [[{ ...relay, port: 22011, aclRules: ['reject(denied.invalid)', 'reject(all)'] }, exit, geoExit], [link, geoLink], [user(2)]];
const [applied, appliedSide] = compose(...laterArgs, true);
const [expected, appliedEmptySide] = compose(...laterArgs);
// Another current, active BRIDGE. Its independent policy and TCP+UDP listener
// are not part of the install receipt or the MAIN inverse.
appliedSide.inbounds.push(listen('current-bridge', 24083));
appliedSide.outbounds.push({ tag: 'current-exit', protocol: 'freedom' });
appliedSide.routing.rules.push({ type: 'field', inboundTag: ['current-bridge'], outboundTag: 'current-exit' });

// Files, manifest, flock, parsing, proof and mutation order are the real host
// helper. Only the local host boundary (systemctl, kernel/proc, Xray commands,
// filesystem root and numeric ownership) is modeled. No network or host tools.
const fixture = String.raw`
import contextlib, copy, io, itertools, json, os, runpy, socket, stat, sys
from pathlib import Path
from types import SimpleNamespace as NS
source, root, scenario = sys.argv[1:]
network_fixture = runpy.run_path(str(Path(source).parent / 'tests/helpers/rebuildRelayNetworkFixture.py'))
root, f = Path(root), json.load(sys.stdin)
os.umask(0o077)
h = {'__name__': 'fixture'}
exec(compile(Path(source).read_bytes(), source, 'exec'), h)
probes = []
class Associate:
    def __init__(self, family, kind):
        assert (family, kind) == (socket.AF_INET, socket.SOCK_STREAM)
        self.writes = []
    def __enter__(self): return self
    def __exit__(self, *_): probes.append(self.writes)
    def settimeout(self, seconds): assert 0 < seconds <= 1
    def connect(self, endpoint):
        ports = [i['port'] for cfg in loaded.values() for i in cfg['inbounds'] if i['tag'] == 'rebuild-relay-ingress']
        assert endpoint[0] == '127.0.0.1' and endpoint[1] in ports
        if not scenario.endswith('-associate'): raise ConnectionRefusedError()
    def sendall(self, data): self.writes.append(data)
    def recv(self, size):
        assert self.writes == [b'\x05\x01\x00', b'\x05\x03\x00\x01' + bytes(6)][:len(self.writes)]
        return {2:b'\x05\x00', 4:b'\x05\x00\x00\x01', 6:b'\x7f\x00\x00\x01\xc4\x00'}[size]
h['socket'] = NS(AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM, socket=Associate)
P = h['NAMES']
X, B, XL, IKE, NET, MAIN, BRIDGE, XRAY, SYSTEM = [h[k] for k in ('X','B','XL','IKE','NET_UNIT','MAIN','BRIDGE','XRAY','SYSTEM')]
req = {k:f[k] for k in ('machineId','network','backupId')}
d, token = req['network'], req['backupId']
nft = network_fixture['nft_source'](source, d, token).decode()
nft_rows = network_fixture['nft_rows'](d, token)

def backing(path):
    assert path.startswith('/') and '..' not in Path(path).parts
    return root / path[1:]

def put(path, content, owner=(0,0), replace=False):
    dst = backing(path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    p = dst.with_suffix('.new') if replace else dst
    p.write_bytes(content if isinstance(content, bytes) else content.encode())
    p.chmod(0o640)
    owners[p.stat().st_ino] = owner
    if replace: p.replace(dst)

owners = {}
put(XRAY, 'executable')
put(MAIN, f['main'], (65534,65534))
if f['bridge'] is not None: put(BRIDGE, f['bridge'], (0,65534))
for k in ('lns','starter','secrets','chap'): put(P[k], '# stock\n')
put(P['starter'], '# stock\nconfig setup\ninclude /etc/ipsec.d/*.conf\n')
put(h['PPP_PATH'], h['raw'](h['ppp_config']()))
backing(h['PPP_PATH']).chmod(0o644)
for path in (SYSTEM, str(Path(P['ike']).parent), str(Path(h['VAULT']).parent)):
    backing(path).mkdir(parents=True, exist_ok=True)

class PathBoundary:
    def __getattr__(self, name):
        assert name in ('split','join','dirname','basename'), name
        return getattr(os.path, name)
    def lexists(self, path): return os.path.lexists(backing(path))
    def realpath(self, path):
        pid = path.split('/')[2]
        assert path == f'/proc/{pid}/exe'
        return XRAY if not (scenario == 'bridge-exe' and pid == units[B]['MainPID'] and removing) else '/wrong'

class OSBoundary:
    path = PathBoundary()
    def __getattr__(self, name):
        assert name in ('O_RDONLY','O_DIRECTORY','O_NOFOLLOW','O_NONBLOCK','O_WRONLY','O_CREAT','O_EXCL',
                        'fdopen','listxattr','mkdir','rmdir','fsync','close','fchmod','link','replace','unlink','listdir','umask',
                        'major','minor','makedev'), name
        return getattr(os, name)
    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is None:
            assert path == '/' and flags & os.O_DIRECTORY
            return os.open(root, flags, mode)
        assert path not in ('','.','..') and '/' not in path
        return os.open(path, flags, mode, dir_fd=dir_fd)
    def fstat(self, fd):
        st = os.fstat(fd)
        uid, gid = owners.get(st.st_ino, (0,0))
        return NS(**{**{k:getattr(st,k) for k in dir(st) if k.startswith('st_')}, 'st_uid':uid, 'st_gid':gid})
    def readlink(self, path):
        assert path == '/proc/self/ns/user'
        return 'user:[4026531837]'
    def lstat(self, path):
        if path == '/dev/ppp': return NS(st_mode=stat.S_IFCHR, st_rdev=os.makedev(108,0))
        return os.lstat(backing(path))
    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        if dir_fd is not None: return os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        assert path in ('/proc/'+units[X]['MainPID'], '/proc/'+units[B]['MainPID'])
        return NS(st_uid=65534, st_gid=65534)
    def fchown(self, fd, uid, gid): owners[os.fstat(fd).st_ino] = uid, gid
    def geteuid(self): return 0

units = {}
for n in (X,B,XL,IKE,NET):
    units[n] = dict(LoadState='loaded' if n != NET else 'not-found', ActiveState='inactive', SubState='dead',
        MainPID='0', InvocationID='', NeedDaemonReload='no', DropInPaths='', User='', PrivateNetwork='no',
        UnitFileState='enabled' if n in (X,XL) else ('disabled' if n != NET else ''),
        FragmentPath='/usr/lib/systemd/system/'+n if n != NET else '', KillMode='control-group', Type='simple',
        ControlGroup='/system.slice/'+n)
for n, path, pid, present in [(X,MAIN,'101',True),(B,BRIDGE,'102',f['bridge'] is not None)]:
    units[n].update(User='nobody', ExecStart=f'{{ path={XRAY} ; argv[]={XRAY} run -config {path} ; }}')
    if present: units[n].update(ActiveState='active', SubState='running', MainPID=pid, InvocationID=f'{int(pid):032x}', UnitFileState='enabled')
units[XL]['ExecStart'] = '{ path=/usr/sbin/xl2tpd ; argv[]=/usr/sbin/xl2tpd -D ; }'
units[IKE]['ExecStart'] = '{ path=/usr/sbin/ipsec ; argv[]=/usr/sbin/ipsec start --nofork ; }'
stock = copy.deepcopy(units)
loaded = {n:json.loads(backing(p).read_bytes()) for n,p in [(X,MAIN),(B,BRIDGE)] if backing(p).exists()}
policy = {'rule':False,'route':False,'nft':False}
changes, checks = [], []
restarts = itertools.count(301)
removing = False

def proc(path, mode='r'):
    facts = {'/etc/machine-id': f['machineId']+'\n', '/proc/devices':'Character devices:\n108 ppp\nBlock devices:\n',
             '/proc/self/status':'CapEff:\t0000000000010000\n', '/proc/sys/kernel/modules_disabled':'0\n',
             '/proc/cmdline':'root=fixture\n', '/proc/modules':''.join(f'{n} 4096 0 - Live 0x0\n' for n in
                ('ppp_generic','l2tp_ppp','inet_diag','tcp_diag','udp_diag','nfnetlink','nf_tables','xfrm_user')),
             '/proc/sys/kernel/random/boot_id':'fixture-boot\n', '/proc/net/dev':'header\nheader\n eth0: 0\n',
             '/proc/201/cgroup':'0::'+units[IKE]['ControlGroup']+'\n'}
    for n, cfg in [(X,MAIN),(B,BRIDGE)]:
        if units[n]['ActiveState'] == 'active':
            facts['/proc/'+units[n]['MainPID']+'/cmdline'] = '\0'.join((XRAY,'run','-config',cfg,''))
    assert path in facts, path
    return io.BytesIO(facts[path].encode()) if mode == 'rb' else io.StringIO(facts[path])

def load(n, path, generation):
    units[n].update(ActiveState='active',SubState='running',MainPID=str(generation),InvocationID=f'{generation:032x}')
    loaded[n] = json.loads(backing(path).read_bytes())

def run(argv, **kw):
    exe,*a = argv
    def reply(value=b'', code=0):
        return NS(returncode=code, stdout=value if isinstance(value,bytes) else value.encode(), stderr=b'')
    def js(value): return reply(h['encode'](value))
    if exe == '/usr/bin/systemd-detect-virt':
        assert a in (['--container'], ['--chroot'])
        return reply('none\n' if a == ['--container'] else '', 1)
    if exe == h['MODPROBE']:
        if a == ['--showconfig']: return reply()
        if a[:2] == ['--show-depends','--'] and len(a) == 3 and a[2] in h['OBSERVERS']:
            return reply(f'insmod /lib/modules/fixture/{a[2]}.ko\n')
        assert a[:3] == ['--show-depends','--use-blacklist','--'] and a[3:] in (['ppp_generic'], ['l2tp_ppp']), a
        return reply(f'insmod /lib/modules/fixture/{a[3]}.ko\n')
    if exe == '/usr/bin/systemctl':
        assert a.pop(0) == '--no-pager'
        op,*rest = a
        if op == 'show':
            assert len(rest) == 3 and rest[0] == '--all' and rest[1].startswith('--property=')
            info = (dict(LoadState='loaded', ActiveState='inactive', UnitFileState='static', NeedDaemonReload='no',
                         FragmentPath='/usr/lib/systemd/system/systemd-modules-load.service')
                    if rest[2] == 'systemd-modules-load.service' else units[rest[2]])
            rows = []
            for k in rest[1].split('=',1)[1].split(','):
                value = info.get(k,'')
                rows.extend(f'{k}={entry}\n' for entry in (value if isinstance(value,list) else [value]))
            return reply(''.join(rows), 1 if info['LoadState'] == 'not-found' else 0)
        if op == 'list-jobs':
            assert rest == ['--no-legend','--plain']
            return reply()
        if op == 'show-environment':
            assert not rest
            return reply('LANG=C\n')
        changes.append(tuple(a))
        if op == 'daemon-reload':
            if backing(P['net']).exists():
                net_bytes = backing(P['net']).read_bytes()
                lines = net_bytes.decode().splitlines()
                pre = next((l.removeprefix('ExecStartPre=') for l in lines if l.startswith('ExecStartPre=')), '')
                legacy = f'Requires={X}' in lines
                units[NET].update(LoadState='loaded', FragmentPath=P['net'], UnitFileState='static', Type='oneshot',
                                  Requires=X if legacy else '', Wants='' if legacy else X, RequiredBy=XL,
                                  ExecStart=network_fixture['systemctl_start'](net_bytes),
                                  After=next(l.removeprefix('After=') for l in lines if l.startswith('After=')),
                                  ExecStartPre=f'{{ path=/usr/bin/systemctl ; argv[]={pre} ; ignore_errors=no ; }}' if pre else '')
                units[XL].update(DropInPaths=h['DROP'],Requires=NET+' '+IKE,After=NET+' '+IKE)
                units[X]['RequiredBy'], units[IKE]['RequiredBy'] = (NET if legacy else ''), XL
            else:
                for n in (XL,IKE,NET): units[n] = dict(stock[n])
                units[X]['RequiredBy'] = ''
        elif op == 'restart' and rest[0] in (X,B):
            n = rest[0]; load(n, MAIN if n == X else BRIDGE, next(restarts))
        elif op == 'start' and rest == [NET]:
            assert units[NET]['ActiveState'] == 'inactive' and not any(policy.values())
            units[NET].update(ActiveState='active',SubState='exited',InvocationID=f'{203:032x}')
            policy.update(rule=True,route=True,nft=True)
        elif op == 'start' and rest == [XL]:
            assert units[NET]['ActiveState'] == 'active' and all(policy.values())
            for n,generation in [(XL,202),(IKE,201)]:
                units[n].update(ActiveState='active',MainPID=str(generation),SubState='running',InvocationID=f'{generation:032x}')
        elif op == 'stop' and len(rest) == 1 and rest[0] in (XL,IKE,NET):
            units[rest[0]].update(ActiveState='inactive',SubState='dead',MainPID='0',InvocationID='')
        else: raise AssertionError(a)
        return reply()
    if exe == '/usr/bin/dpkg-query' and a[1] == '-f=$'+'{db:Status-Abbrev}': return reply('ii ')
    if exe == '/usr/bin/setpriv':
        assert a[:4] == ['--reuid=65534','--regid=65534','--init-groups',XRAY]
        checks.append(json.loads(kw['input'] if a[-1] == 'stdin:' else backing(a[-1]).read_bytes()))
        return reply()
    if exe == XRAY and a[:2] == ['api','inbounduser']:
        clients = next(i['settings']['clients'] for i in loaded[X]['inbounds'] if i['tag'] == a[-1].split('=',1)[1])
        if removing and (scenario == 'dynamic-user' or scenario == 'post-user' and ('restart',X) in changes):
            clients = clients + [{'id':'unrepresented'}]
        return js({'users':[dict(email=c.get('email',''), account={'_TypedMessage_':'xray.proxy.vless.Account',
            **{k:c[k] for k in ('id','flow','reverse') if k in c}}) for c in clients]})
    if exe == '/usr/bin/ss' and a == ['-H','-lntup']:
        rows = []
        for name,cfg in loaded.items():
            for i in cfg['inbounds']:
                tag = i['tag']
                protos = ['tcp','udp'] if tag.startswith('relay-l2tp-') or i['protocol'] == 'socks' else ['tcp']
                for proto in protos:
                    if proto == 'udp' and tag == 'rebuild-relay-ingress' and scenario.endswith('-associate'): continue
                    if removing and proto == 'udp' and tag == 'rebuild-relay-ingress' and (
                        scenario.endswith('missing-udp') or scenario == 'post-bridge-udp' and ('restart',B) in changes): continue
                    address, pid = i.get('listen','0.0.0.0'), units[name]['MainPID']
                    if removing and proto == 'udp' and tag == 'rebuild-relay-ingress':
                        if scenario == 'split-wrong-udp-address': address = '0.0.0.0'
                        if scenario == 'local-wrong-udp-pid': pid = '999'
                    rows.append((proto,address,i['port'],pid))
        for n,ports in [(XL,[1701]),(IKE,[500,4500])]:
            if units[n]['ActiveState'] == 'active':
                rows.extend(('udp','0.0.0.0',p,units[n]['MainPID']) for p in ports)
        if removing and scenario == 'foreign-handoff': rows.append(('udp','127.0.0.1',f['sharedPort'],'999'))
        return reply(''.join(f'{p} LISTEN 0 0 {a}:{n} *:* users:(("fixture",pid={pid},fd=3))\n' for p,a,n,pid in rows))
    if exe == '/usr/sbin/ipsec' and a == ['statusall']:
        assert units[IKE]['ActiveState'] == 'active'
        # Native stroke prints an explicit 'none' row for an idle SA inventory.
        # The older residual guard tolerates its absence; the census does not.
        empty = '' if scenario == 'missing-ipsec-idle-witness' else '  none\n'
        return reply('Status of IKE charon daemon:\nConnections:\n'
                     'celerity-l2tp:  %any...%any  IKEv1\n'
                     'celerity-l2tp:   child:  dynamic[udp/l2f] === dynamic[udp] TRANSPORT\n'
                     'Security Associations (0 up, 0 connecting):\n' + empty)
    if exe == '/usr/sbin/ip':
        if a in (['xfrm','policy','list'],['xfrm','policy','list','nosock'],['xfrm','state','list','nokeys']): return reply()
        if a == ['-j','-N','-4','addr','show']: return js([])
        if a == ['-j','-N','-6','rule','show']:
            return js([dict(priority=0,src='all',table=255),dict(priority=32766,src='all',table=254)])
        if a == ['-j','-N','-4','rule','show']:
            rules = [dict(priority=p,src='all',table=t) for p,t in [(0,255),(32766,254),(32767,253)]]
            if policy['rule']: rules.append(dict(priority=h['PRIORITY'],src=d['clientCidr'],table=d['routeTable'],fwmark=hex(d['fwmark'])))
            if removing: rules.append(dict(priority=10078,src='198.51.100.0/24',table=201))
            return js(rules)
        if a == ['-j','-N','-4','route','show','table','all']:
            routes = [dict(dst='198.51.100.0/24',table=201,dev='fixture0')] if removing else []
            if policy['route']: routes.append(dict(dst='default',table=d['routeTable'],dev='lo',type='local',scope='host'))
            return js(routes)
        expect = {'rule':['priority',str(h['PRIORITY']),'from',d['clientCidr'],'fwmark',str(d['fwmark']),'table',str(d['routeTable'])],
                  'route':['local','0.0.0.0/0','dev','lo','table',str(d['routeTable'])]}
        assert a[:1] == ['-4'] and a[2] == 'del' and a[3:] == expect[a[1]], a
        policy[a[1]] = False; changes.append(tuple(a)); return reply()
    if exe == '/usr/sbin/nft':
        foreign = dict(table=dict(family='inet',name='foreign',comment='keep'))
        if a == ['-j','list','tables']: return js(dict(nftables=[foreign]+(nft_rows[1:2] if policy['nft'] else [])))
        if a == ['-j','-s','-a','list','table','inet',h['TABLE']]:
            assert policy['nft']
            return js(dict(nftables=nft_rows))
        if a == ['-c','-f','-']: return reply()
        assert a == ['delete','table','inet',h['TABLE']], a
        policy['nft'] = False; changes.append(tuple(a)); return reply()
    raise AssertionError(argv)

faults = []
def model(fn):
    def checked(*args, **kw):
        try: return fn(*args, **kw)
        except Exception as e:
            faults.append((fn.__name__, args[0], type(e).__name__))
            raise
    return checked

def no_host_dispatch(event, _):
    if event in {'subprocess.Popen','os.system','os.posix_spawn','os.exec','os.fork'} or event.startswith('socket.'):
        faults.append(('unexpected host dispatch',event))
        raise AssertionError('unmodeled host dispatch')

sys.addaudithook(no_host_dispatch)
h.update(os=OSBoundary(),open=model(proc),pwd=NS(getpwnam=lambda name:NS(pw_uid=65534,pw_gid=65534)),
    subprocess=NS(run=model(run),PIPE=-1,DEVNULL=-3,TimeoutExpired=h['subprocess'].TimeoutExpired))
# The shared policy observer has its own globals; its /run lookup must also use backing().
h['_NETWORK_POLICY']['os'] = NS(lstat=h['os'].lstat)

def wire(action, **extra):
    out, err = io.StringIO(),io.StringIO()
    sys.stdin = NS(buffer=io.BytesIO(h['encode'](dict(req,action=action,**extra))))
    with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err): status=h['main']()
    assert not faults, faults
    return status,out.getvalue(),err.getvalue()

status, out, err = wire('prepare')
assert status == 0, err
baseline = json.loads(out)['baseline']
files = dict(f['installed'],nft=nft,chap='# BEGIN CELERITY MANAGED L2TP USERS\n# END CELERITY MANAGED L2TP USERS\n',
             **{k:'fixture-only' for k in ('ike','lns','options','secrets')})
if scenario == 'non-invertible-receipt':
    cfg = json.loads(files['bridge'])
    cfg['routing']['rules'][-1]['inboundTag'] = ['neighbor']
    files['bridge'] = json.dumps(cfg)
a = wire('install',baseline=baseline,files={k:h['b64'](v.encode()) for k,v in files.items()})
assert a[0] == 0, a
manifest = backing(h['manifest_path'](token))
receipt = manifest.read_bytes(),manifest.stat().st_ino
intent = manifest.with_name('remove-attempt.json')
if scenario == 'apply-associate':
    def apply_ack(action, **extra):
        r = wire(action, **extra)
        assert r[0] == 0 and r[2] == '', r
        return json.loads(r[1])['proof']
    proof = apply_ack('check-apply-network')
    assert apply_ack('prepare-apply-network') == proof
    assert apply_ack('verify-apply-network', proof=proof) == proof
    # Publish the effective pair after verify-before-restart. Only the old
    # MAIN is live at restart entry; the new MAIN owns the handoff afterward.
    units[B].update(ActiveState='inactive',SubState='dead',MainPID='0',InvocationID='')
    del loaded[B]
    put(MAIN,f['applied'],(0,65534),replace=True)
    put(BRIDGE,f['appliedSide'],(65534,65534),replace=True)
    assert apply_ack('restart-apply-network', proof=proof) == proof
    h['NETWORK_UPGRADE_ENTERED'] = False  # The next wire frame runs in a fresh process in production.
    load(B, BRIDGE, 402)
    assert apply_ack('verify-apply-network', proof=proof) == proof
    # A conflicting fixed UDP row cannot be rescued by a server that would
    # otherwise return a valid UDP ASSOCIATE response.
    live_rows = h['sock_rows']
    handoff_port = next(i['port'] for i in loaded[X]['inbounds'] if i['tag'] == 'rebuild-relay-ingress')
    h['sock_rows'] = lambda: live_rows() + [('udp', '0.0.0.0', handoff_port, ['999'])]
    before_probe = len(probes)
    refusal = wire('verify-apply-network', proof=proof)
    assert refusal == (70, '', 'DIRECT_RUNTIME_UNPROVED\n'), refusal
    assert len(probes) == before_probe
    h['sock_rows'] = live_rows
req['nodeId'] = f['nodeId']
if scenario.startswith('apply') and scenario != 'apply-associate':
    put(MAIN,f['applied'],(65534 if scenario == 'apply-nobody-main' else 0,65534),replace=True)
    put(BRIDGE,f['appliedEmptySide' if scenario == 'apply-empty-bridge' else 'appliedSide'],(65534,65534),replace=True)
    load(X,MAIN,401); load(B,BRIDGE,402)
    if scenario == 'apply-empty-bridge':
        units[B].update(ActiveState='inactive',SubState='dead',MainPID='0',InvocationID='',UnitFileState='disabled')
        del loaded[B]
    if scenario == 'apply-mixed':
        put(BRIDGE,f['installed']['bridge'],(65534,65534),replace=True); load(B,BRIDGE,403)
if scenario in ('replace-main','replace-bridge'):
    path = MAIN if scenario.endswith('main') else BRIDGE
    put(path,backing(path).read_bytes(),owners[backing(path).stat().st_ino],replace=True)
if scenario == 'restart-bridge': load(B,BRIDGE,477)
if scenario == 'restart-main': load(X,MAIN,478)
if scenario == 'changed-split':
    cfg = copy.deepcopy(loaded[B]); cfg['routing']['domainStrategy'] = 'AsIs'
    put(BRIDGE,json.dumps(cfg),(0,65534),replace=True); load(B,BRIDGE,479)
if scenario == 'foreign-dependency': units[B]['RequiredBy'] = 'foreign.service'
if scenario == 'wrong-node': req['nodeId'] = 'e'*24

changes.clear(); checks.clear(); removing=True

def snapshots():
    return sorted((str(p.relative_to(root)),p.lstat().st_ino,p.lstat().st_ctime_ns,p.read_bytes() if p.is_file() else None)
                  for p in root.rglob('*'))

before = snapshots()
side_before, main_before = h['read'](BRIDGE), h['read'](MAIN)
bridge_unit = dict(units[B])
old_sockets = h['owned_sockets'](h['sock_rows'](),bridge_unit['MainPID'])
a = wire('prepare-remove')
assert snapshots() == before and not changes and not intent.exists()
negative = {**dict.fromkeys(('replace-main','replace-bridge','changed-split','foreign-dependency'), 'ROLLBACK_DRIFT'),
            **dict.fromkeys(('restart-bridge','restart-main'), 'RUNTIME_REATTEST_REQUIRED'),
            **dict.fromkeys(('foreign-handoff','split-missing-udp','local-missing-udp','bridge-exe',
                             'split-wrong-udp-address','local-wrong-udp-pid'), 'RUNTIME_UNPROVED'),
            **dict.fromkeys(('wrong-node','apply-mixed','non-invertible-receipt'), 'CANDIDATE_INVALID'),
            'dynamic-user':'PROFILE_USERS'}
if scenario in negative:
    assert a == (70,'','DIRECT_'+negative[scenario]+'\n'), a
    if scenario in ('split-wrong-udp-address','local-wrong-udp-pid','foreign-handoff'):
        assert not probes, 'invalid fixed sockets must not fall through to negotiation'
else:
    assert a[0] == 0, a
    proof = json.loads(a[1])['baseline']
    assert json.loads(f['expected']) in checks
    if scenario == 'apply-stale-bridge':
        cfg = backing(BRIDGE)
        put(BRIDGE,cfg.read_bytes(),owners[cfg.stat().st_ino],replace=True); now = snapshots()
    a = wire('remove',baseline=proof)
    if scenario == 'apply-stale-bridge':
        assert a == (70,'','DIRECT_REMOVE_REFUSED\n') and snapshots() == now and not changes and not intent.exists(), a
    elif scenario == 'missing-ipsec-idle-witness':
        assert a == (70,'','DIRECT_REMOVE_REFUSED\n') and snapshots() == before and not changes and not intent.exists(), a
        assert all(policy.values())
    elif scenario in ('post-bridge-udp','post-user'):
        assert a == (75,'','') and intent.exists() and all(policy.values()), a
        assert ('restart',X) in changes and ('restart',B) in changes
    else:
        assert a[0] == 0 and json.loads(a[1]) == dict(ok=True,backupId=token,removed=True), a
        assert ('restart',X) in changes and not any(policy.values()) and intent.exists()
        assert not backing(h['SWAN_PROFILE']).exists() and units[IKE]['MainPID'] == '0'
        main_after, side_after = h['read'](MAIN),h['read'](BRIDGE)
        assert json.loads(h['raw'](main_after)) == json.loads(f['expected'])
        assert {**main_after,'data':None} == {**main_before,'data':None}
        if f['split'] and not scenario.startswith('apply'):
            assert ('restart',B) in changes and bridge_unit['InvocationID'] != units[B]['InvocationID']
            assert h['raw'](side_after) == f['bridge'].encode() and h['raw'](main_after) == f['main'].encode()
            assert {**side_after,'data':None} == {**side_before,'data':None}
            assert json.loads(f['bridge']) in checks
            assert h['owned_sockets'](h['sock_rows'](),units[B]['MainPID']) == old_sockets
        else:
            assert all(B not in change for change in changes) and units[B] == bridge_unit and side_after == side_before
        assert h['ip']('rule','show')[-1]['table'] == 201 and h['ip']('route','show','table','all')[0]['table'] == 201
        assert 'foreign' in [r['name'] for r in h['nft_tables']()]
        if scenario.endswith('-associate'):
            assert len(probes) >= (6 if scenario == 'split-associate' else 3)
            assert all(len(writes) == 2 for writes in probes)
assert (manifest.read_bytes(),manifest.stat().st_ino) == receipt
print('ok')
`;

for (const scenario of ['split', 'split-associate', 'apply', 'apply-associate', 'apply-nobody-main', 'apply-empty-bridge', 'local', 'local-associate', 'replace-main', 'replace-bridge', 'restart-bridge', 'restart-main',
    'changed-split', 'foreign-dependency', 'wrong-node', 'foreign-handoff', 'split-missing-udp', 'local-missing-udp',
    'split-wrong-udp-address', 'local-wrong-udp-pid',
    'dynamic-user', 'bridge-exe', 'apply-mixed', 'non-invertible-receipt', 'apply-stale-bridge', 'missing-ipsec-idle-witness',
    'post-bridge-udp', 'post-user']) {
    test(`DIRECT remove layout: ${scenario}`, () => {
        const split = !scenario.startsWith('local');
        const originals = { main: stringify(split ? main : localMain), bridge: split ? stringify(bridge) : null };
        const dir = mkdtempSync(join(process.cwd(), '.remove-layout-fixture-'));
        try {
            mkdirSync(join(dir, 'etc'), { mode: 0o755 });
            stockSwan.seed(dir);
            writeFileSync(join(dir, 'etc/machine-id'), machineId + '\n', { mode: 0o644 });
            const result = spawnSync('python3', ['-I', '-B', '-c', fixture, join(__dirname, '../rebuildRelayDirectHost.py'), dir, scenario], {
                input: JSON.stringify({ ...originals, installed: installPair(originals.main, originals.bridge), split,
                    applied: stringify(applied), appliedSide: stringify(appliedSide), appliedEmptySide: stringify(appliedEmptySide),
                    expected: scenario.startsWith('apply') ? stringify(expected) : originals.main,
                    nodeId, backupId, machineId, network, sharedPort }), encoding: 'utf8', timeout: 15000,
            });
            assert.equal(result.status, 0, result.stderr || result.error?.message);
            assert.equal(result.stdout, 'ok\n');
        } finally { rmSync(dir, { recursive: true, force: true }); }
    });
}
