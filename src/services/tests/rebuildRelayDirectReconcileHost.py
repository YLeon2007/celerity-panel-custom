# Executed only by the socket-free DIRECT transport test, with an empty env.
import contextlib
import copy
import fcntl
import io
import json
import os
import pathlib
import runpy
import shlex
import stat
import sys
import tempfile
from types import SimpleNamespace
from typing import Any

frame = json.load(sys.stdin)
source = shlex.split(frame['command'])[-1]
request = frame['wire']
old = frame.get('old')
HOST = pathlib.Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
NETWORK_FIXTURE = runpy.run_path(str(HOST.parent / 'tests/helpers/rebuildRelayNetworkFixture.py'))


def deny_native(event, args):
    if event in ('os.system', 'os.exec', 'os.posix_spawn', 'os.kill', 'subprocess.Popen') or event.startswith('socket.'):
        raise AssertionError('native dispatch forbidden in recovery fixture')


sys.addaudithook(deny_native)


def load(src) -> dict[str, Any]:
    scope: dict[str, Any] = {'__name__': 'c3_fixture'}
    exec(compile(src, '<fixture DIRECT>', 'exec'), scope)
    return scope


class FixtureStat:
    def __init__(self, result):
        self.result = result
        self.st_uid = self.st_gid = 0

    def __getattr__(self, key):
        return getattr(self.result, key)


class FixtureOS:
    def __getattr__(self, key):
        return getattr(os, key)

    def fstat(self, fd):
        return FixtureStat(os.fstat(fd))

    def stat(self, path, **kwargs):
        return FixtureStat(os.stat(path if kwargs.get('dir_fd') is not None else physical(path), **kwargs))

    def lstat(self, path):
        return FixtureStat(os.lstat(physical(path)))

    def geteuid(self):
        return 0

    def fchown(self, fd, uid, gid):
        assert uid == gid == 0 and pathlib.Path(os.readlink(f'/proc/self/fd/{fd}')).is_relative_to(root)


def physical(path):
    assert path.startswith('/') and '..' not in path.split('/')
    return root / path[1:]


@contextlib.contextmanager
def directory(path, private=False):
    assert path.startswith('/') and '..' not in path.split('/')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.strip('/').split('/'):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        if private:
            assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o700
        yield fd
    finally:
        os.close(fd)


def run_host(h, payload=request):
    orig = sys.stdin
    sys.stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = h['main']()
    finally:
        sys.stdin = orig
    return code, out.getvalue(), err.getvalue()


def model(scope):
    observers = ('inet_diag', 'tcp_diag', 'udp_diag', 'nfnetlink', 'nf_tables', 'xfrm_user')
    observe_policy = scope['network_projection']

    def die(*args, **kwargs):
        unexpected.append('unmodeled host observer')
        raise AssertionError('unmodeled host observer')

    def require_machine(machine):
        scope['need'](machine == request['machineId'], 'IDENTITY')
        return machine

    def command(*args, **kwargs):
        if args[:3] == ('/usr/bin/dpkg-query', '-W', r'-f=${Status}\n${Conffiles}'):
            from hashlib import md5
            stock = {'starter': b'config setup\n', 'secrets': b'# empty\n', 'lns': b'; factory\n'}
            paths = {'strongswan-starter': ('starter', 'secrets'), 'xl2tpd': ('lns',)}[args[-1]]
            return b'install ok installed\n' + b''.join(
                f' {names[key]} {md5(stock[key], usedforsecurity=False).hexdigest()}\n'.encode() for key in paths)
        if scenario == 'rollback-policy-start' and args == ('/usr/sbin/nft', '-j', 'list', 'tables'):
            return scope['encode']({'nftables': nft_rows[:2] if state['nft'] else nft_rows[:1]})
        if scenario == 'rollback-policy-start' and args == ('/usr/sbin/nft', '-j', '-s', '-a', 'list', 'table', 'inet', scope['TABLE']):
            assert state['nft']
            return scope['encode']({'nftables': nft_rows})
        if args[:-1] in ((scope['MODPROBE'], '--show-depends', '--'),
                         (scope['MODPROBE'], '--show-depends', '--use-blacklist', '--')):
            assert args[-1] in state['missing']
            reads.append(('module-metadata', args[-1]))
            return f'insmod /lib/modules/fixture/kernel/{args[-1]}.ko\n'.encode()
        if args == ('/usr/bin/ps', '-ww', '-e', '-o', 'pid=', '-o', 'comm='):
            reads.append(('processes',))
            return b'  1 systemd\n  8 xray\n  9 xray\n 10 ps\n' + (b' 11 charon\n' if state['stray_ike'] else b'')
        if args == ('/usr/sbin/ip', '-j', '-details', 'link', 'show'):
            reads.append(('links',))
            links = [{'ifname': 'lo', 'link_type': 'loopback'}, {'ifname': 'eth0', 'link_type': 'ether'}]
            if state['vpn']:
                links.append({'ifname': 'renamed0', 'link_type': 'ppp'})
            return scope['encode'](links)
        if args == ('/usr/sbin/ip', '-j', '-N', '-4', 'rule', 'show'):
            rules = [dict(priority=priority, src='all', table=str(table))
                     for priority, table in ((0, 255), (32766, 254), (32767, 253))]
            if state['rule']:
                d = request['network']
                rules.insert(1, dict(priority=scope['PRIORITY'], src=d['clientCidr'], table=str(d['routeTable']), fwmark=d['fwmark']))
            return scope['encode'](rules)
        if args == ('/usr/sbin/ip', '-j', '-N', '-4', 'route', 'show', 'table', 'all'):
            routes = [dict(type='local', dst='default', dev='lo', scope='host', table=str(request['network']['routeTable']))]
            return scope['encode'](routes if state['route'] else [])
        if args == ('/usr/sbin/ip', '-j', '-N', '-6', 'rule', 'show'):
            reads.append(('swan-rules',))
            rules = [dict(priority=0, src='all', table='255'), dict(priority=32766, src='all', table='254')]
            if state['swan_drift']:
                rules.insert(1, dict(priority=220, table='220'))
            return scope['encode'](rules)
        if args[:3] == ('/usr/sbin/ip', '-4', 'rule'):
            state['rule'] = False
        elif args[:3] == ('/usr/sbin/ip', '-4', 'route'):
            state['route'] = False
        elif args == ('/usr/sbin/nft', 'delete', 'table', 'inet', scope['TABLE']):
            state['nft'] = None
        elif args[1:2] == ('-c',) and args[0] == '/usr/sbin/nft':
            return b''
        else:
            return die()
        effects.append(args)
        return b''

    def sc(verb, *args, **kwargs):
        if verb == 'list-jobs':
            return b'7 xl2tpd.service start running\n' if state['busy'] else b''
        effects.append((verb, *args))
        if verb == 'daemon-reload':
            if physical(scope['NET']).exists():
                units[NET].update(LoadState='loaded', FragmentPath=scope['NET'])
                if scenario == 'rollback-policy-start':
                    unit = physical(scope['NET']).read_bytes()
                    units[NET].update(Type='oneshot', UnitFileState='static', User='', Group='', NeedDaemonReload='no',
                        PrivateNetwork='no',
                        Wants=X, Requires='', After=X,
                        ExecStart=NETWORK_FIXTURE['systemctl_start'](unit),
                        ExecStartPre=f'{{ path=/usr/bin/systemctl ; argv[]={scope["NETWORK_START_CHECK"]} ; ignore_errors=no ; pid=0 }}')
                units[XL]['DropInPaths'] = scope['DROP']
            else:
                units[NET] = copy.deepcopy(original[NET])
                units[XL]['DropInPaths'] = ''
        elif verb == 'restart':
            units[X]['InvocationID'] = 'f' * 32
        elif verb == 'start':
            if args == (NET,) and scenario == 'rollback-policy-start':
                state.update(route=True, nft='fixture-owned-nft')
                if state['unverified']:
                    units[NET].update(ActiveState='failed', SubState='failed', InvocationID='3' * 32)
                    raise scope['Refusal']('COMMAND_FAILED')
                state['rule'] = True
                units[NET].update(ActiveState='active', SubState='exited', InvocationID='4' * 32)
                return b''
            assert args == (XL,)
            if scenario == 'rollback-policy-start':
                assert ('start', NET) in effects and units[NET]['ActiveState'] == 'active' and state['rule']
            state.update(rule=True, route=True, nft='fixture-owned-nft')
            for n, ch in zip((XL, IKE, NET), '123'):
                if n == NET and scenario == 'rollback-policy-start':
                    continue
                units[n].update(ActiveState='active', MainPID=ch, InvocationID=ch * 32)
        elif verb == 'stop':
            (name,) = args
            units[name].update({k: original[name][k] for k in ('ActiveState', 'SubState', 'MainPID', 'InvocationID')})
        else:
            return die()
        return b''

    def installed_runtime(d, token, before, after):
        scope['need'](not state['unverified'], 'COMMAND_FAILED')
        return dict(nft=state['nft'], invocations=[units[u]['InvocationID'] for u in (X, XL, IKE, NET)],
                    files=scope['file_generations'](after), bootEnrollment=None)

    def swan_started_units(before):
        return [units[u]['InvocationID'] for u in (XL, IKE, NET)]

    def network_projection(*args, **kwargs):
        reads.append(('policy',))
        if state['missing'].intersection(('nfnetlink', 'nf_tables')):
            return die()
        if state['offline']:
            raise OSError('unavailable observer; fixture-only detail')
        return observe_policy(*args, **kwargs)

    def passive_open(path, mode='r'):
        reads.append(('file', path))
        if path in ('/proc/net/udp', '/proc/net/udp6'):
            assert mode == 'rb'
            return io.BytesIO(b'  sl  local_address rem_address st tx_queue rx_queue\n')
        assert mode == 'r'
        if path == '/proc/modules':
            return io.StringIO(''.join(f'{name} 4096 0 - Live 0x0\n' for name in observers if name not in state['missing']))
        return die()

    def sock_rows():
        reads.append(('sockets',))
        if state['missing'].intersection(('inet_diag', 'tcp_diag', 'udp_diag')):
            return die()
        return state['sockets']

    def vpn_empty(**_):
        reads.append(('xfrm',))
        if 'xfrm_user' in state['missing']:
            return die()
        return not state['vpn']

    scope.update(os=FixtureOS(), directory=directory, require_machine=require_machine, boot=lambda: state['boot'],
                 preflight=lambda machine, **_: dict(machineId=require_machine(machine), masked=False),
                 command=command, sc=sc, network_projection=network_projection, sock_rows=sock_rows,
                 vpn_empty=vpn_empty, ppp_device=die, ppp_registered=die, open=passive_open,
                 unit=lambda name: copy.deepcopy(units[name]), working=lambda u: u['ActiveState'] == 'active',
                 native_vpn=lambda info, name: True, xray_users=lambda *args: before['sockets'],
                 installed_runtime=installed_runtime, same_xray_dropin=lambda *a: None,
                 retained_xray_dropin=lambda *a: None, removal_dependencies=lambda *a, **kw: None,
                 removal_native=lambda *a, **kw: True, removal_vpn_runtime=lambda *a: None,
                 applying_vpn_ownership=lambda *a: None, swan_default_environment=lambda *a: None,
                 swan_started_units=swan_started_units, swan_inputs=lambda *a: 'fixture-stock',
                 apply_ppp_preparation=lambda *a: None,
                 observe_ppp_preparation=lambda: before['pppModules'], observe=lambda *a, **kw: before,
                 candidate=lambda *a: after, validate_profiles=lambda *a: None,
                 nft_projection=lambda token: state['nft'], ike_include_matches=lambda *a: True)


def put(path, data):
    physical(path).parent.mkdir(parents=True, exist_ok=True)
    physical(path).write_bytes(data)


def produce_package(phase, **overrides):
    value = {**scope, 'phase': phase, 'backupId': request['backupId'], 'packagePreparation': 'd' * 64, **overrides}
    put(package_path, h['encode'](value))


def legacy_install():
    req = dict(action='install', machineId=request['machineId'], backupId=request['backupId'], network=request['network'],
               baseline=h['digest'](h['encode'](before)))
    return run_host(legacy, req)


def read_manifest():
    return h['read_manifest'](request['backupId'])[2]


def snapshot():
    def image(path):
        info = path.lstat()
        payload = os.readlink(path) if stat.S_ISLNK(info.st_mode) else path.read_bytes() if path.is_file() else None
        return str(path.relative_to(root)), (info.st_ino, info.st_mode, info.st_uid, info.st_gid, payload)
    return sorted(image(path) for path in root.rglob('*'))


with tempfile.TemporaryDirectory(prefix='rebuild-host-recovery-', dir=os.getcwd()) as temp:
    root = pathlib.Path(temp)
    os.umask(0o077)
    h = load(source)
    legacy = load(old or source)
    h['NETWORK_RUN'] = legacy['NETWORK_RUN'] = str(root / 'run')
    XL, IKE, X, B, NET = (h[k] for k in ('XL', 'IKE', 'X', 'B', 'NET_UNIT'))
    units = {name: dict(LoadState='not-found' if name == NET else 'loaded', UnitFileState='disabled',
                        ActiveState='inactive', SubState='dead', MainPID='0', InvocationID='', DropInPaths='',
                        FragmentPath='' if name == NET else '/vendor/' + name) for name in (XL, IKE, X, B, NET)}
    for name in h['FRESH_VPN_UNITS']:
        units.setdefault(name, {**units[NET], 'UnitFileState': ''})
    units[X].update(ActiveState='active', SubState='running', MainPID='8', InvocationID='e' * 32)
    original = {name: copy.deepcopy(units[name]) for name in h['UNITS']}
    state: dict[str, Any] = dict(boot='ab12cdef-1234-5678-aaaa-123456789abc', sockets=[], busy=False, vpn=False,
                 rule=False, route=False, nft=None, offline=False, unverified=False, missing=set(), stray_ike=False,
                 swan_drift=False)
    effects, reads, unexpected = [], [], []
    model(h)
    model(legacy)
    for p in (h['SYSTEM'], h['VAULT'], '/etc/ipsec.d', '/usr/sbin', '/etc/default', '/var/lib/apt', '/etc/strongswan.d'):
        physical(p).mkdir(parents=True, exist_ok=True)
    simple: dict[str, Any] = dict(inbounds=[dict(tag='management', port=80)], outbounds=[], routing=dict(rules=[]))
    put(h['MAIN'], h['encode'](simple))
    names = h['NAMES']
    for key, data in [('chap', b'# stock\n'), ('starter', b'config setup\n'), ('secrets', b'# empty\n'), ('lns', b'; factory\n')]:
        put(names[key], data)
    global_paths = {'/etc/ppp/options', h['SWAN_CONF'], h['XL_DEFAULT']}
    with directory(h['SYSTEM']) as fd:
        scope = h['package_scope'](request['machineId'], fd)
    before: dict[str, Any] = dict(boot=scope['boot'], installLock=scope['installLock'], files={k: h['read'](p) for k, p in names.items()},
                  units=original, bridge=None, globalFiles={p: None for p in global_paths}, sockets=[['tcp', '127.0.0.1', 80]],
                  installBoot=False, ikeSockets=[], swanInputs='fixture-stock', pppModules=dict(missing=[], persist=False))
    before['files']['swan'] = None
    main_after = {**simple, 'inbounds': [*simple['inbounds'], dict(tag='relay-l2tp-' + request['nodeId'], port=12345)]}
    after = {k: h['entry'](b'fixture ' + k.encode()) for k in names}
    after.update(main=h['entry'](h['encode'](main_after)), swan=h['entry'](h['SWAN_SETTINGS'], 0o644))
    vault = h['VAULT']
    token_dir = vault + '/' + request['backupId']
    manifest = token_dir + '/manifest.json'
    package_path = vault + '/packages-' + request['backupId'] + '.json'
    scenario = frame['scenario']
    if scenario == 'rollback-policy-start':
        nft = NETWORK_FIXTURE['nft_source'](HOST, request['network'], request['backupId'])
        nft_rows = NETWORK_FIXTURE['nft_rows'](request['network'], request['backupId'])
        after.update(nft=h['entry'](nft, 0o644), net=h['entry'](h['network_unit'](
            request['network'], False, backup_id=request['backupId'], nft_sha256=h['digest'](nft)), 0o644))
    else:
        after['net'] = h['entry'](legacy['network_unit'](request['network'], False), 0o644)
    if scenario == 'missing':
        pass
    elif scenario.startswith('mismatch-'):
        field, value = {'mismatch-token': ('backupId', 'd' * 32), 'mismatch-machine': ('machineId', 'd' * 32),
                        'mismatch-boot': ('boot', 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'),
                        'mismatch-lock': ('installLock', [1, 1]), 'mismatch-plan': ('packagePreparation', 'a' * 64)}[scenario]
        produce_package('ready', **{field: value})
    elif scenario == 'preparing':
        produce_package('preparing')
    else:
        produce_package('refused' if scenario.startswith('refused') else 'ready')
    if 'cold' in scenario and scenario != 'rollback-cold':
        state['missing'].add('xfrm_user')
    if scenario in ('cold-nft-unavailable', 'cold-socket-unavailable'):
        state['missing'].add('nf_tables' if scenario == 'cold-nft-unavailable' else 'udp_diag')
    if scenario in ('ready-cold-retained-bridge', 'ready-retained-bridge', 'cold-bridge-drift'):
        # Retained graph-owned SOCKS; new Xray may only have the fixed TCP bind.
        # This is neither the DIRECT MAIN ingress nor permission to probe SOCKS.
        tag = h['FOLLOW_RELAY_SOCKS']
        bridge: dict[str, Any] = dict(inbounds=[dict(tag=tag, protocol='socks', port=24081, listen='127.0.0.1',
                                     settings=dict(auth='noauth', udp=True, ip='127.0.0.1'))],
                      outbounds=[dict(tag='block', protocol='blackhole')],
                      routing=dict(rules=[dict(type='field', inboundTag=[tag], outboundTag='block')]))
        if scenario == 'cold-bridge-drift':
            bridge['routing']['rules'][0]['outboundTag'] = h['FOLLOW_RELAY_BLOCK']
        put(h['BRIDGE'], h['encode'](bridge))
        baseline = copy.deepcopy(simple)
        baseline['outbounds'].append(dict(tag='relay-policy', protocol='socks',
                                          settings=dict(servers=[dict(address='127.0.0.1', port=24081)])))
        baseline['routing']['rules'].append(dict(type='field', inboundTag=['management'], outboundTag='relay-policy'))
        put(h['MAIN'], h['encode'](baseline))
        before['files']['main'] = h['read'](h['MAIN'])
        before['bridge'] = h['read'](h['BRIDGE'])
        units[B].update(ActiveState='active', SubState='running', MainPID='9')
        units[XL].update(UnitFileState='generated', FragmentPath='/run/systemd/generator.late/' + XL)
        state['sockets'] = [('tcp', '127.0.0.1', 24081, ['9'])]
    if scenario == 'refused-cold':
        for name in (XL, IKE):
            units[name].update(LoadState='not-found', UnitFileState='', FragmentPath='')
        for key in ('starter', 'lns', 'secrets'):
            physical(names[key]).unlink()
    if scenario == 'pending':
        put(vault + '/' + h['PACKAGE_PENDING'], b'private pending evidence')
    if scenario in ('empty-token-dir', 'cold-partial-token'):
        physical(token_dir).mkdir()
    if scenario == 'cold-partial-token':
        put(token_dir + '/.direct-interrupted', b'partial same-token evidence')
    if scenario == 'symlink-receipt':
        physical(package_path).unlink()
        physical(package_path).symlink_to('missing')
    if scenario == 'trace-policy':
        put('/usr/sbin/policy-rc.d', b'private containment')
    if scenario == 'trace-config':
        put(h['MAIN'], h['encode'](main_after))
    if scenario == 'detached-vault-foreign-chap':
        # Same reserved backupId and terminal package receipt, no manifest,
        # but the operator restored a pre-Install foreign configuration.
        put(names['chap'], b'fixture-user * fixture-value *\n')
    if scenario == 'trace-ppp':
        put(h['PPP_PATH'], b'private prerequisite')
    if scenario in ('trace-network', 'cold-network-drift'):
        state['rule'] = True
    if scenario == 'cold-nft-trace':
        state['nft'] = 'fixture-owned-nft'
    if scenario == 'cold-swan-drift':
        state['swan_drift'] = True
    if scenario in ('trace-listener', 'cold-listener'):
        state['sockets'] = [('udp', '*', 1701, ['8'])]
    if scenario == 'unavailable':
        state['offline'] = True
    if scenario == 'jobs':
        state['busy'] = True
    if scenario == 'cold-stray-ike':
        state['stray_ike'] = True
    if scenario in ('cold-ppp', 'warm-vpn'):
        state['vpn'] = True
    if scenario in ('rollback', 'rollback-applying', 'rollback-policy-start', 'rollback-partial', 'rollback-postcondition', 'already-rolled-back',
                    'drift-rolled-back', 'rollback-receipt-fsync', 'manifest-lock', 'manifest-node', 'manifest-network', 'rollback-cold'):
        state['unverified'] = scenario in ('rollback-applying', 'rollback-partial', 'rollback-policy-start')
        assert legacy_install()[0] == (70 if state['unverified'] else 0), 'stock control must reach intended phase'
        backup = read_manifest()
        if scenario == 'rollback-cold':
            state['missing'].add('xfrm_user')
        if scenario in ('rollback-partial', 'manifest-lock'):
            if scenario == 'rollback-partial':
                del backup['swanStart']
            else:
                backup['before']['installLock'] = [1, 1]
            put(manifest, h['encode'](backup))
        if scenario in ('already-rolled-back', 'drift-rolled-back', 'rollback-receipt-fsync'):
            rollback_request = dict(action='rollback', machineId=request['machineId'], backupId=request['backupId'],
                                    network=request['network'], baseline=h['digest'](h['encode'](before)))
            assert run_host(legacy, rollback_request)[0] == 0
            if scenario == 'drift-rolled-back':
                state['route'] = True
        if scenario == 'rollback-postcondition':
            prior = h['sc']
            def break_postcondition(verb, *args, **kwargs):
                result = prior(verb, *args, **kwargs)
                if verb == 'daemon-reload':
                    state['route'] = True
                return result
            h['sc'] = break_postcondition
    effects.clear()
    reads.clear()
    preimage = snapshot()
    absent_cases = ('ready', 'refused', 'ready-cold-retained-bridge', 'ready-retained-bridge', 'refused-cold')
    fence_path = token_dir + '/' + h['INSTALL_ABSENT']
    if scenario in absent_cases:
        write = h['write']

        def write_fence(path, before, after):
            assert path == fence_path and before is None
            with directory(h['SYSTEM']) as probe:
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return write(path, before, after)
                unexpected.append('fence write outside the exclusive Install flock')
                raise AssertionError(unexpected[-1])

        h['write'] = write_fence
    payload = request
    if scenario == 'manifest-node':
        payload = {**request, 'nodeId': 'e' * 24}
    if scenario == 'manifest-network':
        payload = {**request, 'network': {**request['network'], 'routeTable': 178}}
    if scenario == 'rollback-receipt-fsync':
        # The prior terminal name is visible. A failed directory sync must
        # prevent an ACK, without replaying any service or file effects.
        target = physical(token_dir).stat()
        fsync, faults = os.fsync, []

        def fail_sync(fd):
            live = os.fstat(fd)
            if (live.st_dev, live.st_ino) == (target.st_dev, target.st_ino):
                faults.append(True)
                raise OSError('injected directory sync failure')
            return fsync(fd)

        os.fsync = fail_sync
        try:
            refusal = run_host(h, payload)
        finally:
            os.fsync = fsync
        assert refusal == (75, '', '') and faults == [True] and snapshot() == preimage and not effects
        code, out, err = run_host(h, payload)
    elif scenario == 'concurrent':
        with directory(h['SYSTEM']) as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code, out, err = run_host(h, payload)
    else:
        code, out, err = run_host(h, payload)
    if scenario in absent_cases:
        assert not effects and code == 0 and json.loads(out)['result'] == 'absent', (code, out, reads)
        assert not physical(manifest).exists()
        assert sorted(row.name for row in physical(token_dir).iterdir()) == [h['INSTALL_ABSENT']]
        assert [(p, data) for p, data in snapshot() if p not in (token_dir[1:], fence_path[1:])] == preimage
        assert ('sockets',) in reads and ('policy',) in reads
        if 'cold' in scenario:
            assert all(key in reads for key in (('links',), ('processes',), ('swan-rules',), ('module-metadata', 'xfrm_user')))
            assert ('xfrm',) not in reads
        else:
            assert ('xfrm',) in reads
        if scenario.startswith('ready'):
            # Old receiver was already dispatched but not yet under flock.
            sealed = snapshot()
            mkdir = legacy['mkdir']
            rejected = []

            def watch_mkdir(path, *args, **kwargs):
                try:
                    return mkdir(path, *args, **kwargs)
                except legacy['Refusal'] as error:
                    if str(error) == 'ROLLBACK_DRIFT' and path == token_dir and not kwargs.get('exist_ok'):
                        rejected.append(path)
                    raise
            legacy['mkdir'] = watch_mkdir
            cold = state['missing'].copy()
            if old:
                # The historical receiver insists on all providers at entry.
                # Let it reach mkdir even if they become available later.
                state['missing'].clear()
            try:
                result = legacy_install()
                assert result[0] == 70, result
            finally:
                state['missing'] = cold
            assert rejected == [token_dir], (result, rejected)
            assert snapshot() == sealed and not effects
            assert run_host(h, payload) == (code, out, err)
    elif scenario == 'rollback-policy-start':
        # Recovery without the prior start receipt must remain unknown. The
        # explicit rollback of this settled Install failure has its own proof.
        assert (code, out, err) == (75, '', '') and snapshot() == preimage and not effects
        rollback_request = dict(action='rollback', machineId=request['machineId'], backupId=request['backupId'],
                                network=request['network'], baseline=h['digest'](h['encode'](before)))
        assert h['dispatch'](rollback_request)['ok']
        assert read_manifest()['phase'] == 'rolled-back'
        assert ('stop', NET) in effects and not any(('stop', n) in effects for n in (XL, IKE))
        assert state['nft'] is None and not state['rule'] and not state['route']
        assert not physical(h['NET']).exists() and not physical(h['NFT_FILE']).exists()
        assert not (root / 'run').exists()
        new_token = '7' * 32
        nft = NETWORK_FIXTURE['nft_source'](HOST, request['network'], new_token)
        nft_rows = NETWORK_FIXTURE['nft_rows'](request['network'], new_token)
        after.update(nft=h['entry'](nft, 0o644), net=h['entry'](h['network_unit'](
            request['network'], False, backup_id=new_token, nft_sha256=h['digest'](nft)), 0o644))
        effects.clear()
        state['unverified'] = False
        retry = {**rollback_request, 'action': 'install', 'backupId': new_token}
        assert h['dispatch'](retry)['ok']
        assert effects.index(('start', NET)) < effects.index(('start', XL))
        assert h['network_projection'](request['network'], new_token, pinned=True)['rule']
        assert h['read_manifest'](new_token)[2]['phase'] == 'installed' and not (root / 'run').exists()
    elif scenario in ('rollback', 'rollback-applying', 'already-rolled-back', 'rollback-receipt-fsync'):
        assert code == 0 and json.loads(out)['result'] == 'rolled_back'
        assert read_manifest()['phase'] == 'rolled-back' and h['read'](h['MAIN']) == before['files']['main']
        assert state['nft'] is None and not state['rule'] and not state['route']
        if scenario in ('rollback', 'rollback-applying'):
            assert effects
        else:
            assert not effects
    else:
        assert (code, out, err) == (75, '', '')
        if scenario != 'rollback-postcondition':
            assert snapshot() == preimage and not effects
        else:
            assert effects and read_manifest()['phase'] == 'rolling-back'
    assert not unexpected, unexpected
    print(json.dumps(dict(code=code, stdout=out, stderr=err)))
