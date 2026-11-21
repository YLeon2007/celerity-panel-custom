"""Local SSH endpoint for DIRECT install and removal. Never calls host commands."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path

import shlex
import stat
import sys
from types import SimpleNamespace
from typing import Any

parser = argparse.ArgumentParser()
parser.add_argument('root', type=Path)
parser.add_argument('scenario')
args = parser.parse_args()
root, scenario = args.root, args.scenario
line = sys.stdin.buffer.readline()
command_line = shlex.split(json.loads(line))
wire = sys.stdin.buffer.read()
request = json.loads(wire)
timeout = ['1s', '9s'] if request['action'] == 'session-count' else ['4s', '125s']
assert command_line[:-1] == ['/usr/bin/timeout', '-k', *timeout, '/usr/bin/python3', '-I', '-B', '-c']
state_path = root / 'manager.json'
s = json.loads(state_path.read_text())
h: dict[str, Any] = {'__name__': 'direct_fixture'}

def no_host_dispatch(event, _):
    if event in {'subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.exec', 'os.fork'} or event.startswith('socket.'):
        s.setdefault('faults', []).append(event)
        raise AssertionError('non-modeled host dispatch')

sys.addaudithook(no_host_dispatch)
exec(compile(command_line[-1], '<DIRECT command>', 'exec'), h)
# Seed pre-fix Install through the existing fixture, not by adopting the live
# generation under test. Apply/Remove run the candidate without this override.
if s.get('legacyNetwork') and request['action'] in ('prepare', 'check', 'install', 'verify') and 'network_unit' in h:
    render = h['network_unit']
    h['network_unit'] = lambda d, sidecar, *, legacy=False: render(d, sidecar, legacy=True)
XL, IKE, X, B, NET = (h[k] for k in ('XL', 'IKE', 'X', 'B', 'NET_UNIT'))
MAIN, BRIDGE, SYSTEM = (h[k] for k in ('MAIN', 'BRIDGE', 'SYSTEM'))
STOCK_UID = 65534
XRAY_PATHS = {X: MAIN, B: BRIDGE}

def xray_path(pid):
    return next(p for n, p in XRAY_PATHS.items()
                if pid != '0' and s['units'][n]['MainPID'] == pid and n in s['running'])

def backing(path):
    assert str(path).startswith('/') and '..' not in Path(path).parts
    return root / str(path).lstrip('/')

def fake_stat(value, uid=0, gid=0):
    return SimpleNamespace(**{key: (uid if key == 'st_uid' else gid if key == 'st_gid' else getattr(value, key))
                              for key in dir(value) if key.startswith('st_')})


class LocalPath:
    def __getattr__(self, name):
        assert name in ('split', 'basename', 'dirname', 'join'), name
        return getattr(os.path, name)

    def lexists(self, path):
        return os.path.lexists(backing(path))

    def realpath(self, path):
        proc, pid, leaf = path.strip('/').split('/')
        assert (proc, leaf) == ('proc', 'exe')
        xray_path(pid)
        return h['XRAY']


class LocalOS:
    path = LocalPath()

    def __getattr__(self, name):
        assert name in ('O_RDONLY', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_WRONLY', 'O_CREAT', 'O_EXCL', 'O_DIRECTORY',
                        'fdopen', 'listxattr', 'mkdir', 'rmdir', 'fsync', 'close', 'fchmod', 'link',
                        'replace', 'unlink', 'listdir', 'umask', 'major', 'minor', 'readlink', 'symlink', 'uname'), name
        return getattr(os, name)

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        # Project only the initial '/' descriptor. The real production
        # openat/nofollow traversal and file protocol run under this root.
        if dir_fd is None:
            assert path == '/' and flags & os.O_DIRECTORY
            return os.open(root, flags, mode)
        assert path not in ('', '.', '..') and '/' not in path
        parent = os.readlink('/proc/self/fd/' + str(dir_fd))
        assert parent == str(root) or parent.startswith(str(root) + '/')
        return os.open(path, flags, mode, dir_fd=dir_fd)

    def geteuid(self):
        return 0

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        if dir_fd is not None:
            return fake_stat(os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks))
        proc, pid = path.strip('/').split('/')
        assert proc == 'proc'
        xray_path(pid)
        return SimpleNamespace(st_uid=STOCK_UID, st_gid=STOCK_UID)

    def lstat(self, path):
        if path == '/dev/ppp':
            return SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=os.makedev(108, 0))
        return os.lstat(backing(path))

    def fstat(self, fd):
        v = os.fstat(fd)
        return fake_stat(v, *s['owners'].get(str(v.st_ino), [0, 0]))

    def fchown(self, fd, uid, gid):
        assert os.readlink('/proc/self/fd/' + str(fd)).startswith(str(root) + '/')
        assert uid in (0, STOCK_UID) and gid in (0, STOCK_UID)
        s['owners'][str(os.fstat(fd).st_ino)] = [uid, gid]


def stock_open(path, mode='r'):
    if path == '/etc/machine-id' and s.get('cohort'):
        return backing(path).open(mode)
    facts = {'/etc/machine-id': s['machine'] + '\n', '/proc/devices': 'Character devices:\n108 ppp\nBlock devices:\n',
             '/proc/net/dev': 'header\nheader\n eth0: 0\n', '/proc/sys/kernel/random/boot_id': 'fixture-boot\n',
             '/proc/999/cgroup': '0::/system.slice/foreign.service\n'}
    if s['units'][IKE]['ActiveState'] == 'active':
        facts[f"/proc/{s['charonPid']}/cgroup"] = '0::/system.slice/' + IKE + '\n'
    for name, config in XRAY_PATHS.items():
        if name in s['running']:
            facts[f"/proc/{s['units'][name]['MainPID']}/cmdline"] = '\0'.join((h['XRAY'], 'run', '-config', config, ''))
    assert path in facts, path
    return io.BytesIO(facts[path].encode()) if mode == 'rb' else io.StringIO(facts[path])


def reloaded():
    units = s['units']
    if backing(h['NET']).exists():
        net = backing(h['NET']).read_text()
        legacy = f'Requires={X}\n' in net
        assert legacy != (f'Wants={X}\n' in net) and 'Type=oneshot\n' in net
        commands = [line.removeprefix('ExecStart=') for line in net.splitlines() if line.startswith('ExecStart=')]
        # systemctl show emits one property row per command on the real relay.
        records = [f'{{ path={cmd.split()[0]} ; argv[]={cmd} ; ignore_errors=no ; '
                   'start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0 }' for cmd in commands]
        pre = next((line.removeprefix('ExecStartPre=') for line in net.splitlines() if line.startswith('ExecStartPre=')), '')
        units[NET].update(LoadState='loaded', FragmentPath=h['NET'], UnitFileState='static',
                          Type='oneshot', Requires=X if legacy else '', Wants='' if legacy else X,
                          After=next(line.removeprefix('After=') for line in net.splitlines() if line.startswith('After=')),
                          RequiredBy=XL, ExecStart=records, ExecStartPre=f'{{ path={pre.split()[0]} ; argv[]={pre} ; ignore_errors=no ; }}' if pre else '')
        units[X]['RequiredBy'] = NET if legacy else ''
        units[IKE]['RequiredBy'] = XL
    else:
        units[NET] = dict(s['original'][NET])
        units[X]['RequiredBy'] = units[IKE]['RequiredBy'] = ''
    units[XL]['DropInPaths'] = h['DROP'] if backing(h['DROP']).is_file() else ''
    units[XL]['Requires'] = NET + ' ' + IKE if units[XL]['DropInPaths'] else ''
    units[XL]['After'] = units[XL]['Requires']
    units[XL]['UnitFileState'] = 'enabled' if backing(h['XL_BOOT']).is_symlink() else 'disabled'


def stop(name):
    s['units'][name].update(ActiveState='inactive', SubState='dead', MainPID='0', InvocationID='')
    s['running'].pop(name, None)
    if name == IKE:
        s['ikeConnection'] = False


def start(name):
    info = s['units'][name]
    assert info['LoadState'] == 'loaded'
    s['nextPid'] += 1
    pid = s['nextPid']
    info.update(ActiveState='active', SubState='exited' if name == NET else 'running',
                MainPID='0' if name == NET else str(pid), InvocationID=f'{pid:032x}')
    if name in XRAY_PATHS:
        s['running'][name] = json.loads(backing(XRAY_PATHS[name]).read_bytes())
    elif name == IKE:
        s['nextPid'] += 1
        s['charonPid'] = str(s['nextPid'])
        s['ikeConnection'] = backing(h['NAMES']['ike']).exists()


def sockets():
    result = list(s['foreign']['sockets'])
    for n, profile in s['running'].items():
        info = s['units'][n]
        assert info['ActiveState'] == 'active'
        for inbound in profile['inbounds']:
            protocols = ['tcp', 'udp'] if inbound['protocol'] == 'socks' or inbound['tag'].startswith('relay-l2tp-') else ['tcp']
            address = inbound.get('listen', '0.0.0.0')
            if scenario == 'transit-loopback-listener' and inbound['tag'] == 'rebuild-rp-conn-eeeeeeee':
                address = '127.0.0.1'
            result.extend((proto, address, inbound['port'], info['MainPID']) for proto in protocols)
    if s['units'][IKE]['ActiveState'] == 'active':
        result.extend(('udp', '0.0.0.0', port, s['charonPid']) for port in (500, 4500))
    if s['units'][XL]['ActiveState'] == 'active' and scenario not in ('settled', 'sidecar-refusal'):
        result.append(('udp', '0.0.0.0', 1701, s['units'][XL]['MainPID']))
    return result


def run(argv, **kwargs):
    prog, *v = argv
    def reply(value: bytes | str = b'', code=0):
        return SimpleNamespace(returncode=code, stdout=value if isinstance(value, bytes) else value.encode(), stderr=b'')
    def js(value):
        return reply(json.dumps(value))
    if prog == '/usr/bin/systemctl':
        assert v.pop(0) == '--no-pager'
        action, *rest = v
        if action == 'show':
            assert len(rest) == 3 and rest[0] == '--all' and rest[1].startswith('--property=')
            info = s['units'][rest[2]]
            rows = []
            for k in rest[1].split('=', 1)[1].split(','):
                value = info.get(k, '')
                rows.extend(f'{k}={entry}\n' for entry in (value if isinstance(value, list) else [value]))
            return reply(''.join(rows), 1 if info['LoadState'] == 'not-found' else 0)
        if action == 'list-jobs':
            assert rest == ['--no-legend', '--plain']
            return reply()
        if action == 'show-environment':
            assert not rest
            return reply(s['managerEnvironment'])
        s['effects'].append(v)
        if v == ['daemon-reload']:
            if request['action'] == 'prepare-apply-network' and s.get('failApplyReload'):
                return reply(code=1)
            reloaded()
        elif action == 'restart' and len(rest) == 1 and rest[0] in (X, B, IKE):
            if rest == [X] and s['units'][NET]['ActiveState'] == 'active' and X in s['units'][NET]['Requires'].split():
                stop(XL)
                stop(NET)
                s.pop('ppp', None)
            start(rest[0])
        elif action == 'start' and rest == [XL]:
            assert s['units'][NET]['LoadState'] == 'loaded' and s['units'][X]['ActiveState'] == 'active'
            assert set(s['units'][XL]['Requires'].split()) == {NET, IKE}
            d = request['network']
            unit_lines = backing(h['NET']).read_text().splitlines()
            assert [line for line in unit_lines if line.startswith('ExecStart=')] == [
                f"ExecStart=/usr/sbin/nft -f {h['NFT_FILE']}",
                f"ExecStart=/usr/sbin/ip -4 route add local 0.0.0.0/0 dev lo table {d['routeTable']}",
                f"ExecStart=/usr/sbin/ip -4 rule add priority {h['PRIORITY']} from {d['clientCidr']} fwmark {d['fwmark']} table {d['routeTable']}",
            ]
            assert h['nft_marker'](backing(h['NFT_FILE']).read_bytes(), request['backupId'])
            assert not s['rule'] and not s['route'] and s['nft'] is None
            s['rule'] = dict(priority=h['PRIORITY'], src=d['clientCidr'], table=str(d['routeTable']), fwmark=hex(d['fwmark']))
            s['route'] = dict(type='local', dst='default', dev='lo', table=str(d['routeTable']), scope='254')
            s['nft'] = request['backupId']
            start(NET)
            if s['units'][IKE]['ActiveState'] != 'active':
                start(IKE)
            if scenario == 'unacknowledged-start':
                s['units'][XL].update(ActiveState='failed', SubState='failed')
                return reply(code=1)
            start(XL)
        elif action == 'start' and rest == [IKE]:
            start(IKE)
        elif action in ('stop', 'reset-failed') and len(rest) == 1 and rest[0] in (XL, IKE, NET):
            stop(rest[0])
        else:
            raise AssertionError('unexpected manager mutation: ' + action)
        return reply()
    if prog == '/usr/bin/dpkg-query':
        assert len(v) == 3 and v[0] == '-W'
        if v[1] == '-f=${Conffiles}':
            assert v[2:] == ['xl2tpd']
            return reply(' /etc/xl2tpd/xl2tpd.conf ' + s['lnsMd5'] + '\n')
        assert v[1] == '-f=${db:Status-Abbrev}' and v[2] in s['packages']
        return reply('ii ' if scenario != 'package' or v[2] != 'ppp' else '', 1 if scenario == 'package' and v[2] == 'ppp' else 0)
    if prog == '/usr/bin/ss' and v == ['-H', '-lntup']:
        return reply(''.join(f'{p} LISTEN 0 0 {a}:{n} *:* users:(("fixture",pid={pid},fd=3))\n' for p, a, n, pid in sockets()))
    if prog == '/usr/sbin/ip':
        if v == ['-j', '-N', '-4', 'rule', 'show']:
            return js(s['stockRules'] + s['foreign']['rules'] + ([s['rule']] if s['rule'] else []))
        if v == ['-j', '-N', '-6', 'rule', 'show']:
            return js(s['rules6'])
        if v == ['-j', '-N', '-4', 'route', 'show', 'table', 'all']:
            return js(s['foreign']['routes'] + ([s['route']] if s['route'] else []))
        if v == ['-j', '-N', '-4', 'addr', 'show']:
            return js([dict(addr_info=[dict(local=s.get('address', '192.0.2.4'), prefixlen=24)])])
        if v in (['xfrm', 'policy', 'list'], ['xfrm', 'policy', 'list', 'nosock'], ['xfrm', 'state', 'list', 'nokeys']):
            return reply()
        if v[:3] == ['-4', 'rule', 'del'] and s['rule']:
            r = s['rule']
            assert v == ['-4', 'rule', 'del', 'priority', str(r['priority']), 'from', r['src'],
                         'fwmark', str(int(r['fwmark'], 0)), 'table', r['table']]
            s['effects'].append(v)
            s['rule'] = None
            return reply()
        if v[:3] == ['-4', 'route', 'del'] and s['route']:
            assert v == ['-4', 'route', 'del', 'local', '0.0.0.0/0', 'dev', s['route']['dev'], 'table', s['route']['table']]
            s['effects'].append(v)
            s['route'] = None
            return reply()
    if prog == '/usr/sbin/nft':
        table = dict(table=dict(family='inet', name=h['TABLE'], comment=s['nft']))
        if v == ['-j', 'list', 'tables']:
            return js(dict(nftables=s['foreign']['tables'] + ([table] if s['nft'] else [])))
        if v == ['-j', '-s', 'list', 'table', 'inet', h['TABLE']]:
            return js(dict(nftables=[table]))
        if v == ['-c', '-f', '-']:
            assert h['nft_marker'](kwargs['input'], request['backupId'])
            return reply()
        if v == ['delete', 'table', 'inet', h['TABLE']]:
            assert s['nft'] == request['backupId']
            s['nft'] = None
            s['effects'].append(v)
            return reply()
    if prog == '/usr/sbin/ipsec' and v == ['statusall']:
        assert s['units'][IKE]['ActiveState'] == 'active'
        connection = '  celerity-l2tp:  fixture-connection\n' if s['ikeConnection'] else ''
        return reply('Status of IKE charon daemon:\nConnections:\n' + connection
                     + 'Security Associations (0 up, 0 connecting):\n  none\n')
    if prog == h['XRAY'] and v[:2] == ['api', 'inbounduser']:
        assert len(v) == 4 and v[3].startswith('-tag=')
        profile = s['running'][X]
        api = next(i for i in profile['inbounds'] if i['tag'] == 'API_INBOUND')
        assert v[2] == f"--server=127.0.0.1:{api['port']}"
        tag = v[3][5:]
        s.setdefault('inboundUserCalls', []).append(tag)
        clients = next(i['settings']['clients'] for i in profile['inbounds'] if i['tag'] == tag)
        # Real Xray enumerates its email index, not its UUID index.
        clients = [a for a in clients if a.get('email')]
        if scenario == 'transit-missing-client' and tag == 'vless-in':
            return js({})
        if not clients and scenario == 'main':
            return js({})  # protobuf JSON omits empty repeated fields
        if scenario == 'user-rpc-error':
            return SimpleNamespace(returncode=0, stdout=b'{}', stderr=b'RPC failed\n')
        return js({'users': [{'email': a.get('email', ''), 'level': a.get('level', 0), 'account': {'_TypedMessage_': 'xray.proxy.vless.Account',
                           **{k: a[k] for k in ('id', 'flow', 'reverse') if k in a}}} for a in clients]})
    if prog == '/usr/bin/setpriv':
        assert v[:3] == ['--reuid=65534', '--regid=65534', '--init-groups']
        assert len(v) == 10 and v[3:9] == [h['XRAY'], 'run', '-test', '-format', 'json', '-config']
        assert v[-1] in ('stdin:', MAIN, BRIDGE)
        candidate = json.loads(kwargs['input'] if v[-1] == 'stdin:' else backing(v[-1]).read_bytes())
        assert isinstance(candidate['inbounds'], list)
        return reply()
    raise AssertionError('unexpected command: ' + repr(argv))


def modeled_run(argv, **kwargs):
    try:
        return run(argv, **kwargs)
    except Exception as error:
        s.setdefault('faults', []).append([type(error).__name__, list(argv)])
        raise

def modeled_open(path, mode='r'):
    try:
        return stock_open(path, mode)
    except AssertionError:
        s.setdefault('faults', []).append(['unmodeled observer', path])
        raise


def modeled_session_collection(query):
    # There are no real PPP processes or kernel PPP objects in the fixture.
    # Model collection, not the DIRECT dispatch/lock, CHAP validation, or
    # Remove's comparison against the receipt under the exclusive lock.
    assert request['action'] in ('session-count', 'remove')
    s.setdefault('censusCalls', []).append(request['action'])
    _, manifest, backup, _ = h['owned_installation'](query)
    _, _, rows = h['owned_chap'](h['read'](h['NAMES']['chap']), backup,
                                h['chap_expected'](query, h['read'](h['NAMES']['lns'])))
    xl = h['unit'](XL)
    assert xl['ActiveState'] == 'active' and xl['InvocationID'] == backup['runtime']['invocations'][1]
    count = s.get('activeSessions', 0)
    return {'activeSessions': count, 'census': h['digest'](h['encode']([
        'fixture-only-session-collection', query['nodeId'], query['machineId'], query['backupId'],
        h['digest'](h['raw'](manifest)), h['chap_rows_digest'](rows), xl['InvocationID'], count,
    ]))}


h.update(os=LocalOS(), open=modeled_open,
         subprocess=SimpleNamespace(run=modeled_run, PIPE=-1, DEVNULL=-3, TimeoutExpired=h['subprocess'].TimeoutExpired))
if s.get('cohort'):
    assert h['pwd'].getpwnam('nobody').pw_uid == h['grp'].getgrnam('nogroup').gr_gid == STOCK_UID
    assert h['pwd'].getpwuid(0).pw_dir == '/root'
    h['collect_session_census'] = modeled_session_collection
else:
    h.update(pwd=SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=STOCK_UID, pw_gid=STOCK_UID)),
             grp=SimpleNamespace(getgrnam=lambda name: SimpleNamespace(gr_gid=STOCK_UID)))
# Model a real external baseline change after CHECK, but no DIRECT mutations.
if scenario == 'prewrite' and request['action'] == 'install':
    backing('/etc/ppp/options').write_bytes(b'# external change\n')
product_refusal = h['need']

def observe_refusal(condition, code):
    if not condition:
        caller = sys._getframe(1)
        s['lastRefusal'] = [code, caller.f_code.co_name, caller.f_lineno]
    return product_refusal(condition, code)

h['need'] = observe_refusal
s['lastRefusal'] = None
try:
    sys.stdin = io.TextIOWrapper(io.BytesIO(wire))
    status = h['main']()
finally:
    s['sockets'] = sockets()
    state_path.write_text(json.dumps(s))
sys.exit(status)
