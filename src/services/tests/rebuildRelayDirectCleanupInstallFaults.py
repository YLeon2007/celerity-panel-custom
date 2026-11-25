"""Run with C3_FOREIGN_PARENT_NETNS=$(readlink /proc/self/ns/net) unshare -Urn -- python3 -B <this file>."""
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import random
import re
import runpy
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
CLEANUP = runpy.run_path(str(HERE / 'rebuildRelayDirectCleanupHost.py'))
MACHINE, NETWORK, TOKEN, CHAP = (CLEANUP[k] for k in ('MACHINE', 'NETWORK', 'TOKEN', 'CHAP'))
NETWORK_FIXTURE = runpy.run_path(str(HERE / 'helpers/rebuildRelayNetworkFixture.py'))
NODE = 'd' * 24
CHALLENGE = 'e' * 32
DEPENDENCIES = ('After Before Wants WantedBy Requires RequiredBy BindsTo BoundBy PartOf ConsistsOf '
                'Conflicts ConflictedBy PropagatesStopTo Upholds Triggers TriggeredBy').split()


class CleanupInstallFaults(CLEANUP['Cleanup']):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertNotEqual(os.readlink('/proc/self/ns/net'), os.environ['C3_FOREIGN_PARENT_NETNS'])
        self.addCleanup(os.umask, os.umask(0o022))
        CLEANUP['ForeignConfigFixture'].setUp(self)
        h = self.h
        self.enterContext(patch('subprocess.Popen', side_effect=AssertionError('unexpected child')))
        self.enterContext(patch('socket.socket', side_effect=AssertionError('unexpected socket')))
        self.seed()
        self.path('/var/lib').mkdir(parents=True)
        self.put(h['MAIN'], b'{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}\n')
        self.put(h['NAMES']['chap'], CHAP, 0o640)
        self.X, self.XL, self.IKE, self.NET = (h[k] for k in ('X', 'XL', 'IKE', 'NET_UNIT'))
        self.manifest = self.path(h['manifest_path'](TOKEN))
        self.fence = self.path(h['VAULT'] + '/foreign-cleanup.pending')
        self.effects, self.marks, self.births = [], [], {}
        self.loaded_drop = self.loaded_net = b''
        self.policy = [False, False, False]  # nft, route, RPDB
        self.nft_rows = NETWORK_FIXTURE['nft_rows'](NETWORK, TOKEN)
        self.cut = None
        self.shuffle = random.Random(25713)
        self.orders = {}
        self.dependency_drift = False
        self.native_boot_link = False
        self.user_drift = False
        self.rules = [dict(priority=n, src='all', table=t) for n, t in ((0, 255), (32766, 254), (32767, 253))]
        self.swan = b'# synthetic stock strongSwan defaults\n'
        self.put(h['SWAN_CONF'], self.swan, 0o644)
        for path in (h['SWAN_DIR'] + '/charon', '/run'):
            self.path(path).mkdir(parents=True)
        starter = b'config setup\ninclude /etc/ipsec.d/*.conf\n'
        path = h['NAMES']['starter']
        self.put(path, starter, 0o644)
        self.stock['strongswan-starter'] = (f' {path} {hashlib.md5(starter, usedforsecurity=False).hexdigest()}\n'.encode()
                                           + self.stock['strongswan-starter'].splitlines(keepends=True)[1])
        self.xray_fragment = h['SYSTEM'] + '/' + self.X
        self.put(self.xray_fragment, b'[Service]\n', 0o644)
        # Use the real observer, candidate compiler, file/manifest writers and rollback.
        # Model only service/kernel APIs, packaged stock bytes, profile validation and Xray process/API observations.
        lexists = os.path.lexists
        self.enterContext(patch('os.path.lexists', side_effect=lambda p: lexists(self.path(p))))
        h.update(command=self.model_command, observe_ppp_preparation=lambda **_: {'missing': []},
                 remove_generation=self.generation, validate_profiles=lambda _: None,
                 open=self.model_open, sock_rows=self.socket_rows, xray_users=self.xray_users,
                 in_cgroup=lambda pid, info: pid == info['MainPID'], NETWORK_RUN=str(self.path('/run')),
                 STOCK_SWAN_SHA=h['digest'](h['encode']({'strongswan.conf': [0o644, 0, h['digest'](self.swan)]})),
                 apply_ppp_preparation=lambda _: self.reached('cleanup-complete'),
                 stock_runtime_root=lambda: self.temp,
                 C3_REPLACEMENT=runpy.run_path(str(HERE.parent / 'rebuildRelayReplacement.py')),
                 C3_PACKAGE_GUARD=runpy.run_path(str(HERE.parent / 'rebuildRelayPackageGuard.py')))
        self.original_main = self.running_main = self.path(h['MAIN']).read_bytes()
        base_progress = h['install_progress']

        def progress(mark):
            base_progress(mark)
            self.marks.append(mark)
            if mark == 'restart':
                self.reached('restart-progress')

        base_write = h['write']

        def write(path, before, after, **kwargs):
            if self.cut is not None and path == h['manifest_path'](TOKEN) and after is not None:
                incoming = json.loads(h['raw'](after))
                previous = json.loads(h['raw'](before)) if before is not None else {}
                if incoming.get('swanStart') and not previous.get('swanStart'):
                    self.reached('before-swan-start-record')
                    result = base_write(path, before, after, **kwargs)
                    self.reached('after-swan-start-record')
                    return result
                if (incoming.get('foreignJournal', {}).get('installSettled') is True
                        and previous.get('foreignJournal', {}).get('installSettled') is False):
                    result = base_write(path, before, after, **kwargs)
                    if self.effects == [['daemon-reload']]:
                        self.reached('install-reloaded')
                    elif self.effects[-1:] == [['restart', self.X]]:
                        self.reached('xray-restarted')
                    return result
                tail = incoming.get('foreignJournal', {}).get('rollbackTail', {})
                old_tail = previous.get('foreignJournal', {}).get('rollbackTail', {})
                if tail.get('step') != old_tail.get('step'):
                    result = base_write(path, before, after, **kwargs)
                    self.reached('rollback-' + tail.get('step', 'projected'))
                    return result
            result = base_write(path, before, after, **kwargs)
            if path in (h['MAIN'], h['SWAN_PROFILE']) and self.manifest.exists() and (
                    json.loads(self.manifest.read_bytes())['phase'] == 'rolling-back'):
                self.reached('rollback-main' if path == h['MAIN'] else 'rollback-swan')
            return result

        h.update(install_progress=progress, write=write)
        self.prepare_xray_observers()
        boot_enroll = h['enroll_boot']

        def enroll(target, expected=None):
            boot_enroll(target, expected)
            if expected is not None:
                self.reached('rollback-boot-unlinked')

        h['enroll_boot'] = enroll
        # A failure to cut must not be confused with reaching verified Install.
        h['installed_runtime'] = lambda *_: self.fail('Install passed the selected cut')

    def reached(self, phase):
        if self.cut is not None:
            self.cut(phase)

    def model_open(self, path, mode='r'):
        if path == '/proc/net/dev' and mode == 'r':
            return io.StringIO('fixture header\nfixture header\n lo: 0\n')
        return self.read_kernel(path, mode)

    def socket_rows(self):
        rows = [('tcp', '127.0.0.1', 9999, [self.births.get(self.X, ['7'])[0]])]
        if self.running_main != self.original_main:
            rows.extend((proto, '0.0.0.0', NETWORK['tproxyPort'], rows[0][3]) for proto in ('tcp', 'udp'))
        for name, ports in ((self.XL, (1701,)), (self.IKE, (500, 4500))):
            if name in self.births:
                rows.extend(('udp', '0.0.0.0', port, [self.births[name][0]]) for port in ports)
        return rows

    def xray_users(self, profile, info, rows, *_):
        def users(data):
            return [i for i in json.loads(data)['inbounds'] if i.get('protocol') == 'vless']
        self.h['need'](not self.user_drift and users(self.running_main) == users(self.h['raw'](profile)), 'PROFILE_USERS')
        return self.h['owned_sockets'](rows, info['MainPID'])

    def model_unit(self, name):
        h = self.h
        if name not in h['UNITS']:
            return dict(LoadState='not-found', ActiveState='inactive', SubState='dead', MainPID='0')
        self.net_loaded = bool(self.loaded_net)
        self.drop_loaded = h['DROP'] if self.loaded_drop else ''
        props = self.legacy_unit(name)
        props['User'] = props['Group'] = ''
        if name == self.XL:
            leaf = self.path(h['DROP'])
            props['NeedDaemonReload'] = 'yes' if (leaf.read_bytes() if leaf.exists() else b'') != self.loaded_drop else 'no'
            if self.native_boot_link:
                props['UnitFileState'] = ('enabled' if self.loaded_drop or self.path(h['XL_BOOT']).is_symlink()
                                          else 'disabled')
        if name == self.NET:
            if not self.loaded_net:
                props['InvocationID'] = ''
            else:
                props.update(UnitFileState='static', Type='oneshot',
                             ExecStart=NETWORK_FIXTURE['systemctl_start'](self.loaded_net))
                for field in ('Requires', 'Wants', 'After', 'ExecStartPre'):
                    line = next((value for value in self.loaded_net.decode().splitlines() if value.startswith(field + '=')), '')
                    if line:
                        value = line.split('=', 1)[1]
                        props[field] = (f'{{ path={value.split()[0]} ; argv[]={value} ; ignore_errors=no ; }}'
                                        if field == 'ExecStartPre' else value)
        if name in self.births:
            pid, birth = self.births[name]
            props.update(ActiveState='active', SubState='exited' if name == self.NET else 'running',
                         MainPID=pid, InvocationID=birth, ControlGroup='/system.slice/' + name)
        elif name == self.X:
            props.update(ActiveState='active', SubState='running', MainPID='7', InvocationID='1' * 32,
                         ControlGroup='/system.slice/' + name)
        if name == self.X:
            props.update(Before=self.NET if self.loaded_net else '', WantedBy=self.NET if self.loaded_net else '')
        return props

    def model_command(self, *args, **opts):
        h = self.h
        if args[:4] == ('/usr/bin/systemctl', '--no-pager', 'show', '--all'):
            name = args[-1]
            props = self.model_unit(name)
            if name in (self.X, self.XL, self.IKE, self.NET) and props['LoadState'] == 'loaded':
                for key in ('After', 'Wants'):
                    words = sorted(set(props.get(key, '').split()) | {'basic.target', 'sysinit.target', 'network.target'})
                    if key == 'After' and self.dependency_drift:
                        words.append('foreign.service')
                    self.shuffle.shuffle(words)
                    props[key] = ' '.join(words)
                    self.orders.setdefault((name, key), set()).add(props[key])
            keys = args[-2].removeprefix('--property=').split(',')
            return ''.join(f'{k}={props[k]}\n' for k in keys if k in props).encode()
        if args[:2] == ('/usr/bin/systemctl', '--no-pager'):
            op, *names = args[2:]
            if op == 'show-environment':
                return b'LANG=C\n'
            if op in ('daemon-reload', 'restart', 'start', 'stop'):
                self.effects.append([op, *names])
                if op == 'daemon-reload':
                    self.assertEqual(stat.S_IMODE(self.path(self.xray_fragment).stat().st_mode), 0o644)
                    self.loaded_drop, self.loaded_net = (self.path(h[k]).read_bytes() if self.path(h[k]).exists() else b''
                                                         for k in ('DROP', 'NET'))
                    if self.manifest.exists() and json.loads(self.manifest.read_bytes())['phase'] == 'rolling-back':
                        self.reached('rollback-reload-unacknowledged')
                elif (op, names) == ('restart', [self.X]):
                    gen = self.effects.count(['restart', self.X])
                    self.births[self.X] = [str(20 + gen), f'{20 + gen:032x}']
                    self.running_main = self.path(h['MAIN']).read_bytes()
                    if self.manifest.exists() and json.loads(self.manifest.read_bytes())['phase'] == 'rolling-back':
                        self.reached('rollback-xray-unacknowledged')
                elif (op, names) == ('start', [self.NET]):
                    self.policy[:] = [True, True, True]
                    self.births[self.NET] = ['0', '3' * 32]
                elif (op, names) == ('start', [self.XL]):
                    self.assertIn(self.NET, self.births)
                    self.births.update({self.XL: ['11', '4' * 32], self.IKE: ['12', '5' * 32]})
                elif op == 'stop' and names[0] in (self.XL, self.IKE, self.NET):
                    del self.births[names[0]]
                else:
                    self.fail(f'unmodeled manager mutation: {args}')
                return b''
        if args == ('/usr/sbin/ipsec', 'statusall'):
            return b'Connections:\n  celerity-l2tp: transport\nSecurity Associations (0 up, 0 connecting):\n  none\n'
        if args[:3] == ('/usr/sbin/nft', '-c', '-f'):
            return b''
        if args in (('/usr/sbin/nft', '-j', '-s', 'list', 'table', 'inet', h['TABLE']),
                    ('/usr/sbin/nft', '-j', '-s', '-a', 'list', 'table', 'inet', h['TABLE'])):
            self.assertTrue(self.policy[0])
            return h['encode']({'nftables': self.nft_rows})
        if args == ('/usr/sbin/nft', '-j', 'list', 'tables'):
            return h['encode']({'nftables': self.nft_rows[:2] if self.policy[0] else []})
        if args == ('/usr/sbin/ip', '-j', '-N', '-4', 'rule', 'show') and self.policy[2]:
            return h['encode']([*self.rules, dict(priority=h['PRIORITY'], src=NETWORK['clientCidr'],
                                                  fwmark=NETWORK['fwmark'], table=NETWORK['routeTable'])])
        if args == ('/usr/sbin/ip', '-j', '-N', '-4', 'route', 'show', 'table', 'all') and self.policy[1]:
            return h['encode']([dict(type='local', dst='default', dev='lo', scope='host', table=NETWORK['routeTable'])])
        if args == ('/usr/sbin/ip', '-j', '-N', '-4', 'addr', 'show'):
            return b'[]'
        if args == ('/usr/sbin/ip', 'xfrm', 'policy', 'list'):
            return b''
        for i, deletion in enumerate((('/usr/sbin/nft', 'delete', 'table', 'inet', h['TABLE']),
                                      ('/usr/sbin/ip', '-4', 'route', 'del', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', str(NETWORK['routeTable'])),
                                      ('/usr/sbin/ip', '-4', 'rule', 'del', 'priority', str(h['PRIORITY']), 'from', NETWORK['clientCidr'],
                                       'fwmark', str(NETWORK['fwmark']), 'table', str(NETWORK['routeTable'])))):
            if args == deletion:
                self.assertTrue(self.policy[i])
                self.policy[i] = False
                return b''
        return self.command(*args, **opts)

    def exact_snapshot(self):
        rows = {}
        for leaf in self.temp.rglob('*'):
            st = leaf.lstat()
            content = os.readlink(leaf) if leaf.is_symlink() else leaf.read_bytes() if leaf.is_file() else None
            rows[leaf.relative_to(self.temp).as_posix()] = (st.st_mode, st.st_uid, st.st_gid, content)
        return rows

    def plan(self, *, with_xray=False):
        original = self.exact_snapshot()
        if with_xray:
            code, out, err = self.run_host()
            self.assertEqual((code, out), (70, ''))
            kind, keys, digest, cleanable = err.strip().split(' ')
            self.assertEqual((kind, keys, cleanable), ('DIRECT_L2TP_FOREIGN_CONFIG', 'CHAP_NOT_EMPTY,XRAY_UNIT_0666',
                                                      'CHAP_NOT_EMPTY,XRAY_UNIT_0666'))
            auth = dict(digest=digest, fixXrayUnitMode=True, at='2026-11-25T08:25:00.000Z')
        else:
            auth = self.consent()
        frame = self.prepare(auth)
        h = self.h
        # Deliberately different from the original MAIN, with the real Recover node tag.
        main = dict(inbounds=[dict(tag='relay-l2tp-' + NODE, port=NETWORK['tproxyPort']),
                              dict(tag='rebuild-relay-ingress', listen='127.0.0.1', port=23456)],
                    outbounds=[], routing={'rules': []})
        frame['files'] = {k: h['b64'](v) for k, v in dict(
            main=h['encode'](main), nft=h['managed_nft_bytes'](NETWORK, TOKEN), ike=b'# fixture IKE\n',
            lns=b'# fixture LNS\n', options=b'# fixture options\n', secrets=b'# fixture secrets\n',
            chap=b'# fixture install block\n').items()}
        self.assertEqual(self.run_host('check', **frame)[0], 0)
        self.assertEqual(self.exact_snapshot(), original)
        return frame, original

    def run_wire(self, action, **request):
        wire = json.dumps(dict(action=action, machineId=MACHINE, **request)).encode()
        out = io.StringIO()
        with tempfile.TemporaryFile(mode='w+') as err:
            with patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(wire))), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = self.h['main']()
            err.seek(0)
            return code, out.getvalue(), err.read()

    def process_cut(self, frame, phase, effects, *, files=True, started=False, rollback=False, before_install_reload=False):
        # A real SIGKILL: no exception handler, finally block or original helper
        # process survives. The evidence file transfers only the modeled external world;
        # it is not a recovery receipt or a quiescence override.
        with tempfile.TemporaryFile(dir=self.temp.parent) as evidence:
            pid = os.fork()
            if pid == 0:
                try:
                    def cut(mark):
                        if rollback and mark == ('restart-progress' if before_install_reload else 'xray-restarted'):
                            raise self.h['Refusal']('INJECTED_FAULT')
                        if mark == phase:
                            with self.directory(self.h['SYSTEM']) as fd:
                                with self.assertRaises(BlockingIOError):
                                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            evidence.write(json.dumps([mark, self.effects, self.marks, self.births, self.policy,
                                                       self.loaded_drop.hex(), self.loaded_net.hex(),
                                                       self.running_main.hex()]).encode())
                            evidence.flush()
                            os.kill(os.getpid(), signal.SIGKILL)
                    self.cut = cut
                    result = self.run_wire('install', **frame, progress=True)
                    evidence.write(json.dumps(result).encode())
                    evidence.flush()
                finally:
                    os._exit(1)
            _, status = os.waitpid(pid, 0)
            evidence.seek(0)
            report = evidence.read()
        self.assertTrue(report, 'Install child failed before writing cut evidence')
        witness = json.loads(report)
        self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL, witness)
        mark, self.effects, self.marks, self.births, self.policy, drop, net, main = witness
        self.loaded_drop, self.loaded_net, self.running_main = map(bytes.fromhex, (drop, net, main))

        self.assertEqual((mark, self.effects), (phase, effects))
        self.assertEqual(self.marks, ['foreignCleanup', 'restart'] if files else ['foreignCleanup'])
        backup = json.loads(self.manifest.read_bytes())
        journal = backup['foreignJournal']
        self.assertTrue(journal['edits'])
        self.assertEqual(len(journal['done']), len(journal['edits']))
        self.assertTrue(self.fence.is_file())
        self.assertNotEqual(self.path(self.h['NAMES']['chap']).read_bytes(), CHAP)
        self.assertEqual(self.path(self.h['SWAN_PROFILE']).exists(), files and (not rollback or phase in ('rollback-files', 'rollback-main')))
        self.assertEqual(self.path(self.h['MAIN']).read_bytes() != self.original_main, files and (not rollback or phase == 'rollback-files'))
        self.assertEqual(backup.get('swanStart'), [self.births[n][1] for n in self.h['SWAN_START_UNITS']] if started else None)

    def assert_restored(self, original):
        # The terminal backup is intentionally retained; every other byte, type,
        # mode and UID/GID must equal the original across the entire fixture.
        actual = self.exact_snapshot()
        manifest = self.manifest.relative_to(self.temp)
        for parent in (manifest.parent, manifest.parent.parent):
            self.assertEqual(actual.pop(parent.as_posix()), (stat.S_IFDIR | 0o700, 0, 0, None))
        mode, uid, gid, record = actual.pop(manifest.as_posix())
        self.assertEqual((mode, uid, gid), (stat.S_IFREG | 0o600, 0, 0))
        self.assertEqual(json.loads(record)['phase'], 'rolled-back')
        self.assertEqual(actual, original)
        self.assertEqual(self.running_main, self.original_main)
        self.assertFalse(set(self.births) & {self.XL, self.IKE, self.NET})
        self.assertEqual(self.policy, [False, False, False])

    def recover(self, original):
        args = dict(network=NETWORK, backupId=TOKEN, nodeId=NODE, challenge=CHALLENGE)
        code, out, err = self.run_wire('reconcile-install', **args)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(json.loads(out), dict(machineId=MACHINE, nodeId=NODE, backupId=TOKEN,
                                               challenge=CHALLENGE, result='rolled_back'))
        self.assert_restored(original)
        effects, snapshot = self.effects.copy(), self.exact_snapshot()
        self.assertEqual(self.run_wire('reconcile-install', **args), (code, out, err))
        self.assertEqual((self.effects, self.exact_snapshot()), (effects, snapshot))

    def assert_recover_blocked(self):
        effects, snapshot = self.effects.copy(), self.exact_snapshot()
        code, out, err = self.run_wire('reconcile-install', network=NETWORK, backupId=TOKEN,
                                       nodeId=NODE, challenge=CHALLENGE)
        self.assertEqual((code, out), (75, ''))
        self.assertTrue(not err or re.fullmatch(r'DIRECT_UNCERTAIN_ROLLBACK_(DRIFT|UNPROVED) (guard|verify|xray)\n', err), err)
        self.assertTrue(self.fence.is_file())
        self.assertEqual((self.effects, self.exact_snapshot()), (effects, snapshot))

    def test_recover_after_completed_cleanup(self):
        frame, original = self.plan()
        self.process_cut(frame, 'cleanup-complete', [], files=False)
        self.recover(original)

    def test_recover_after_restart_progress_before_install_reload(self):
        frame, original = self.plan()
        self.process_cut(frame, 'restart-progress', [])
        self.recover(original)

    def test_recover_after_install_reload(self):
        frame, original = self.plan()
        self.process_cut(frame, 'install-reloaded', [['daemon-reload']])
        self.recover(original)

    def test_recover_after_xray_restart(self):
        frame, original = self.plan()
        self.process_cut(frame, 'xray-restarted', [['daemon-reload'], ['restart', self.X]])
        self.recover(original)

    def prepare_xray_observers(self):
        self.h['xray_argv'] = lambda info, _path=None: info['MainPID']
        self.h['reattest_process'] = lambda pid, _info: int(pid)

    def test_unit_canonicalizes_only_dependency_sets(self):
        h = self.h
        ordering = 'sysinit.target basic.target sysinit.target'
        ordered = '/first /second { keep ; verbatim }'
        props = {**dict.fromkeys(DEPENDENCIES, ordering), 'ExecStart': ordered, 'DropInPaths': '/b /a'}
        props.update(LoadState='loaded', ActiveState='inactive')
        h['command'] = lambda *_, **__: ''.join(f'{k}={v}\n' for k, v in props.items()).encode()
        got = h['unit'](self.X)
        self.assertEqual({k: got[k] for k in DEPENDENCIES}, dict.fromkeys(DEPENDENCIES, 'basic.target sysinit.target'))
        self.assertEqual((got['ExecStart'], got['DropInPaths']), (ordered, '/b /a'))

    def test_resume_rolling_back_after_settled_reload(self):
        self.prepare_xray_observers()
        frame, original = self.plan()
        effects = [['daemon-reload'], ['restart', self.X], ['daemon-reload']]
        self.process_cut(frame, 'rollback-reloaded', effects, rollback=True)
        self.assertEqual(json.loads(self.manifest.read_bytes())['phase'], 'rolling-back')
        self.assertNotEqual(self.running_main, self.original_main)
        self.jobs = f'11 {self.X} restart running\n'.encode()
        self.assert_recover_blocked()
        self.jobs = b''
        birth = self.births[self.X]
        self.births[self.X] = ['99', 'f' * 32]
        self.assert_recover_blocked()
        self.births[self.X] = birth
        self.user_drift = True
        self.assert_recover_blocked()
        self.user_drift = False
        self.dependency_drift = True
        self.assert_recover_blocked()
        self.dependency_drift = False
        self.recover(original)
        self.assertEqual(self.effects, [*effects, ['restart', self.X]])

    def test_rolling_back_with_replaced_unit_does_not_restart(self):
        frame, _ = self.plan()
        self.process_cut(frame, 'rollback-reloaded', [['daemon-reload'], ['restart', self.X], ['daemon-reload']], rollback=True)
        self.path(self.xray_fragment).write_bytes(b'[Service]\nExecStop=/bin/false\n')
        self.assert_recover_blocked()

    def test_recover_after_first_rollback_write(self):
        self.resume_cut('rollback-files', [])

    def test_recover_after_first_rollback_file(self):
        self.resume_cut('rollback-main', [])

    def test_recover_after_last_rollback_file(self):
        self.resume_cut('rollback-swan', [])

    def test_recover_after_rollback_unlinks_owned_boot_enrollment(self):
        h = self.h
        self.native_boot_link = True
        unit = b'[Service]\nExecStart=/usr/sbin/xl2tpd -D\n[Install]\nWantedBy=multi-user.target\n'
        h['NATIVE_XL_SHA'] = h['digest'](unit)
        self.put(h['SYSTEM'] + '/' + self.XL, unit, 0o644)
        self.resume_cut('rollback-boot-unlinked', [])

    def test_recover_after_acknowledged_rollback_restart(self):
        self.resume_cut('rollback-restarted', [['daemon-reload'], ['restart', self.X]], step='restarted')

    def resume_cut(self, cut, extra, *, step='files'):
        frame, original = self.plan()
        effects = [['daemon-reload'], ['restart', self.X], *extra]
        self.process_cut(frame, cut, effects, rollback=True)
        tail = json.loads(self.manifest.read_bytes())['foreignJournal']['rollbackTail']
        self.assertEqual(tail['step'], step)
        self.recover(original)
        self.assertEqual(self.effects, [['daemon-reload'], ['restart', self.X], ['daemon-reload'], ['restart', self.X]])

    def omit_rollback_tail(self):
        h = self.h
        backup = json.loads(self.manifest.read_bytes())
        record = h['entry'](h['encode'](backup))
        del backup['foreignJournal']['rollbackTail']
        h['write'](h['manifest_path'](TOKEN), record, h['entry'](h['encode'](backup)))

    def test_recover_legacy_early_without_tail(self):
        frame, original = self.plan()
        self.process_cut(frame, 'rollback-files', [], rollback=True, before_install_reload=True)
        self.omit_rollback_tail()
        self.recover(original)
        self.assertEqual(self.effects, [['daemon-reload']])

    def test_resume_files_refuses_republished_swan_postimage(self):
        frame, _ = self.plan()
        self.process_cut(frame, 'rollback-files', [['daemon-reload'], ['restart', self.X]], rollback=True)
        leaf = self.path(self.h['SWAN_PROFILE'])
        data = leaf.read_bytes()
        leaf.unlink()
        leaf.write_bytes(data)
        self.assert_recover_blocked()

    def test_unacknowledged_rollback_restart_stays_fenced(self):
        self.prepare_xray_observers()
        frame, _ = self.plan()
        self.process_cut(frame, 'rollback-xray-unacknowledged',
                         [['daemon-reload'], ['restart', self.X], ['daemon-reload'], ['restart', self.X]], rollback=True)
        self.assertEqual(json.loads(self.manifest.read_bytes())['phase'], 'rolling-back')
        self.assertEqual(self.running_main, self.original_main)
        self.assert_recover_blocked()

    def test_unacknowledged_rollback_reload_stays_fenced(self):
        frame, _ = self.plan()
        self.process_cut(frame, 'rollback-reload-unacknowledged',
                         [['daemon-reload'], ['restart', self.X], ['daemon-reload']], rollback=True)
        self.assertEqual(json.loads(self.manifest.read_bytes())['phase'], 'rolling-back')
        self.assert_recover_blocked()
        self.omit_rollback_tail()
        self.assert_recover_blocked()

    def test_inline_rollback_timeout_has_stage_but_does_not_ack_rollback(self):
        self.prepare_xray_observers()
        frame, _ = self.plan()
        def cut(mark):
            if mark == 'xray-restarted':
                raise self.h['Refusal']('INJECTED_FAULT')
            if mark == 'rollback-xray-unacknowledged':
                raise subprocess.TimeoutExpired([], 0)
        self.cut = cut
        code, out, err = self.run_wire('install', **frame, progress=True)
        self.assertEqual((code, out, err.splitlines()[-1]), (75, '', 'DIRECT_UNCERTAIN_ROLLBACK_TIMEOUT xray'))
        self.assertEqual(json.loads(self.manifest.read_bytes())['phase'], 'rolling-back')
        self.assertTrue(self.fence.exists())

    def test_recover_after_xl_start_and_durable_swan_start_record(self):
        frame, original = self.plan()
        self.process_cut(frame, 'after-swan-start-record',
                         [['daemon-reload'], ['restart', self.X], ['start', self.NET], ['start', self.XL]], started=True)
        self.jobs = f'17 {self.XL} stop waiting\n'.encode()
        self.assert_recover_blocked()
        self.jobs = b''
        self.recover(original)

    def test_process_cut_after_xl_start_without_receipt_stays_fenced(self):
        frame, _ = self.plan()
        self.process_cut(frame, 'before-swan-start-record',
                         [['daemon-reload'], ['restart', self.X], ['start', self.NET], ['start', self.XL]])
        self.assert_recover_blocked()

    def test_sync_refusal_after_xl_start_receipt(self):
        self.sync_rollback('after-swan-start-record')

    def test_sync_refusal_after_restart_progress(self):
        self.sync_rollback('restart-progress')
        self.assertGreater(len(self.orders[self.IKE, 'After']), 1)

    def test_legacy_applying_and_missing_boot_are_not_rebound(self):
        frame, _ = self.plan()
        self.process_cut(frame, 'restart-progress', [])
        manifest = json.loads(self.manifest.read_bytes())
        checked = self.h['entry'](self.h['encode'](manifest))
        del manifest['foreignJournal']['installSettled']
        legacy = self.h['entry'](self.h['encode'](manifest))
        self.h['write'](self.h['manifest_path'](TOKEN), checked, legacy)
        self.assert_recover_blocked()
        manifest['before'].pop('boot')
        self.h['write'](self.h['manifest_path'](TOKEN), legacy, self.h['entry'](self.h['encode'](manifest)))
        with self.directory(self.h['SYSTEM']) as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            scope = self.h['package_scope'](MACHINE, fd)
            with self.assertRaisesRegex(self.h['Refusal'], '^IN_FLIGHT$'):
                self.h['recovery_manifest'](dict(backupId=TOKEN, network=NETWORK), scope)
            with self.assertRaisesRegex(self.h['Refusal'], '^IN_FLIGHT$'):
                self.h['cleanup_guard'](manifest, fd, None)
            with self.assertRaisesRegex(self.h['Refusal'], '^IN_FLIGHT$'):
                self.h['cleanup_fence'](manifest)
        self.assert_recover_blocked()

    def test_recover_after_xray_restart_restores_unit_mode(self):
        generator = (HERE.parent / 'configGenerator.js').read_bytes()
        unit = re.search(rb'function generateXraySystemdService\(\) \{\n    return `([^`]+)`;', generator)
        assert unit is not None
        self.put(self.xray_fragment, unit[1], 0o666)
        # This fixture models the service's procfs evidence, not its filesystem edit.
        self.h['xray_argv'] = lambda info, _path=None: info['MainPID']
        self.h['reattest_process'] = lambda pid, _info: int(pid)
        frame, original = self.plan(with_xray=True)
        self.process_cut(frame, 'xray-restarted', [['daemon-reload'], ['daemon-reload'], ['restart', self.X]])
        self.assertEqual(stat.S_IMODE(self.path(self.xray_fragment).stat().st_mode), 0o644)
        self.recover(original)

    def sync_rollback(self, phase):
        frame, original = self.plan()
        reached = []

        def cut(mark):
            if mark == phase:
                reached.append(mark)
                raise self.h['Refusal']('COMMAND_FAILED')

        self.cut = cut
        try:
            code, out, err = self.run_wire('install', **frame, progress=True)
        finally:
            self.cut = None
        self.assertEqual(reached, [phase])
        self.assertEqual((code, out, err), (70, '', 'DIRECT_PROGRESS foreignCleanup\nDIRECT_PROGRESS restart\nDIRECT_COMMAND_FAILED\n'))
        # The controller's FOREIGN_CONFIG_RESTORED is downstream of this host ACK.
        self.assert_restored(original)
        self.recover(original)


def load_tests(loader, _suite, _pattern):
    return unittest.TestSuite(CleanupInstallFaults(name) for name in vars(CleanupInstallFaults) if name.startswith('test_'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
