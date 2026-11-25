"""The host window's real file/JSON checks, with a denying manager fixture."""
import copy
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest

MOD = pathlib.Path(__file__).resolve().parents[1] / 'rebuildTransitMainWindow.py'
spec = importlib.util.spec_from_file_location('main_window', MOD)
assert spec is not None and spec.loader is not None
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def profile(exit='a', users=()):
    return {'inbounds': [{'tag': 'vless-in', 'protocol': 'vless', 'settings': {
        'decryption': 'none', 'clients': list(users)}}, {'tag': 'transit', 'protocol': 'vless',
        'settings': {'clients': [{'id': 'static'}]}}],
        'routing': {'rules': [{'inboundTag': ['transit'], 'outboundTag': exit}]},
        'outbounds': [{'tag': 'a'}, {'tag': 'b'}]}


class System:
    def __init__(self, root):
        self.root = root
        self.cg = root / 'cc-agent.service'
        self.cg.mkdir()
        self.events = self.cg / 'cgroup.events'
        self.events.write_text('populated 1\nfrozen 0\n')
        self.inv = 'a' * 32
        self.active = True
        self.job = ''
        self.now = 0
        self.terminal_time = 19
        self.trace = []
        self.stop_error = False
        self.start_error = False
        self.keep_process = False
        self.temp: pathlib.Path | None = None
        self.generation = 1
        self.xray_generation = 1
        self.xray_job = ''
        self.agent_props = {}
        self.result = 'success'
        self.log_tail = ''

    def __call__(self, argv, timeout):
        self.trace.append(tuple(argv))
        assert timeout > 0
        cmd = argv[1]
        if argv[0] == '/usr/bin/journalctl':
            assert argv[-1] == '_SYSTEMD_INVOCATION_ID=' + self.inv
            if not self.active:
                return '[main] Shutdown complete\n'
            if self.now >= self.terminal_time:
                return '[main] Startup stats discarded (cold-start reset)\n' + self.log_tail
            return ''
        assert argv[0] == '/usr/bin/systemctl'
        if argv[-1] == 'xray.service':
            assert cmd == 'show'
            row = dict(Id=argv[-1], LoadState='loaded', NeedDaemonReload='no', ActiveState='active',
                       SubState='running', Job=self.xray_job, MainPID=str(self.xray_generation + 500),
                       InvocationID=f'{self.xray_generation + 300:032x}',
                       ExecStart='{ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config '
                                 '/usr/local/etc/xray/config.json ; ignore_errors=no ; }')
            return ''.join(f'{k}={row[k]}\n' for k in m.XRAY_PROPS)
        assert argv[-1] == 'cc-agent.service'
        if cmd == 'show':
            row = dict.fromkeys(m.AGENT_EMPTY, '') | dict(Id=argv[-1], LoadState='loaded', NeedDaemonReload='no',
                       Type='simple', KillMode='control-group', TriggeredBy='',
                       ExecStart='{ path=/usr/local/bin/cc-agent ; argv[]=/usr/local/bin/cc-agent ; ignore_errors=no ; }',
                       ActiveState='active' if self.active else 'inactive',
                       SubState='running' if self.active else 'dead', Job=self.job,
                       ControlGroup='/system.slice/cc-agent.service' if self.active else '',
                       MainPID=str(100 + self.generation) if self.active else '0',
                       InvocationID=self.inv if self.active else '', Result=self.result,
                       ExecMainCode='0' if self.active else '1', ExecMainStatus='0',
                       InactiveEnterTimestampMonotonic=str(self.generation * 1000),
                       Conflicts='shutdown.target', ConflictedBy='', Requires='system.slice sysinit.target',
                       FragmentPath='/etc/systemd/system/cc-agent.service') | self.agent_props
            keys = [a.removeprefix('--property=') for a in argv if a.startswith('--property=')]
            return ''.join(f'{key}={row[key]}\n' for key in keys)
        if cmd == 'stop':
            if self.stop_error:
                self.job = '18'
                raise subprocess.TimeoutExpired(argv, timeout)
            self.active = False
            self.events.write_text('populated ' + ('1' if self.keep_process else '0') + '\nfrozen 0\n')
            if self.temp:
                self.temp.touch()
            return ''
        if cmd == 'start':
            if self.start_error:
                raise subprocess.TimeoutExpired(argv, timeout)
            self.active = True
            self.inv = 'b' * 32
            self.generation += 1
            self.events.write_text('populated 1\nfrozen 0\n')
            return ''
        raise AssertionError(argv)

    def sleep(self, n):
        self.now += n


class Host(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.main = self.root / 'config.json'
        self.main.write_text(json.dumps(profile()))
        self.manager = System(self.root)
        self.guard = m.AgentWindow(self.manager, main=self.main, cgroup_root=self.root,
                                  clock=lambda: self.manager.now, sleep=self.manager.sleep)

    def assertCode(self, code, callback):
        with self.assertRaises(m.WindowError) as ctx:
            callback()
        self.assertEqual(ctx.exception.code, code)

    def test_join_recheck_start_and_wait_for_pinned_reconcile(self):
        self.guard.quiesce()
        self.guard.require_quiet()
        self.main.write_text(json.dumps(profile('b')))
        self.guard.require_quiet()
        self.manager.xray_generation += 1
        self.guard.join_xray_restart()
        self.guard.resume()
        self.guard.wait_reconciled()
        self.assertGreaterEqual(self.manager.now, 19)
        self.assertEqual(self.guard.phase, 'reconciled')
        self.assertEqual([cmd[1] for cmd in self.manager.trace if cmd[1] in ('start', 'stop')], ['stop', 'start'])
        self.assertCode('REBUILD_AGENT_WINDOW_STATE', self.guard.resume)

    def test_stop_timeout_never_allows_publish_restart_or_automatic_start(self):
        before = self.main.read_bytes()
        self.manager.stop_error = True
        self.assertCode('REBUILD_AGENT_STOP_UNCONFIRMED', self.guard.quiesce)
        self.assertEqual(self.guard.phase, 'stop-unconfirmed')
        self.assertCode('REBUILD_AGENT_WINDOW_STATE', self.guard.require_quiet)
        self.assertCode('REBUILD_AGENT_WINDOW_STATE', self.guard.resume)
        self.assertCode('REBUILD_AGENT_WINDOW_STATE', self.guard.quiesce)
        self.assertEqual(self.main.read_bytes(), before)
        self.assertNotIn('start', [cmd[1] for cmd in self.manager.trace])

    def test_terminated_systemctl_does_not_authorize_pending_service_transaction(self):
        self.guard.quiesce()
        self.manager.job = '19'
        self.assertCode('REBUILD_AGENT_EXCLUSION_UNPROVED', self.guard.require_quiet)
        self.assertEqual(self.guard.phase, 'exclusion-lost')
        self.manager.job = ''
        self.assertCode('REBUILD_AGENT_WINDOW_STATE', self.guard.require_quiet)

    def test_cgroup_descendant_or_leftover_temp_file_refuses(self):
        for name in ('cgroup', 'temp'):
            with self.subTest(name=name):
                root = self.root / name
                root.mkdir()
                mgr = System(root)
                mgr.keep_process = name == 'cgroup'
                mgr.temp = root / '.config.json-pending.tmp' if name == 'temp' else None
                wnd = m.AgentWindow(mgr, main=root / 'config.json', cgroup_root=root,
                                    clock=lambda: mgr.now, sleep=mgr.sleep)
                self.assertCode('REBUILD_AGENT_EXCLUSION_UNPROVED', wnd.quiesce)

    def test_agent_start_timeout_is_not_success_or_retried(self):
        self.guard.quiesce()
        self.manager.start_error = True
        self.assertCode('REBUILD_AGENT_START_UNCONFIRMED', self.guard.resume)
        self.assertEqual(self.guard.phase, 'start-unconfirmed')
        self.assertCode('REBUILD_AGENT_WINDOW_STATE', self.guard.resume)

    def test_startup_readback_refuses_unavailable_or_error(self):
        self.guard.quiesce()
        self.guard.resume()
        self.manager.log_tail = '[main] Startup config reflush: synthetic error\n'
        self.assertCode('REBUILD_AGENT_RECONCILE_UNPROVED', self.guard.wait_reconciled)
        self.assertEqual(self.guard.phase, 'reconcile-unconfirmed')

    def test_publish_cas_preserves_file_metadata_and_witnesses_own_inode(self):
        self.main.chmod(0o640)
        self.guard.quiesce()
        before = self.guard.read_main()
        desired = json.dumps(profile('b')).encode()
        after = self.guard.publish_main(before, desired)
        self.assertEqual(self.guard.read_main(), after)
        self.assertEqual(after.data, desired)
        self.assertEqual(after.metadata, before.metadata)
        self.assertNotEqual(after.generation, before.generation)
        self.assertCode('REBUILD_AGENT_WINDOW_STATE', lambda: self.guard.publish_main(after, before.data))

    def test_identical_bytes_replacement_and_final_exclusion_loss_refuse(self):
        for reason in ('inode', 'agent'):
            with self.subTest(reason=reason):
                root = self.root / reason
                root.mkdir()
                mgr = System(root)
                path = root / 'config.json'
                path.write_text(json.dumps(profile()))
                wnd = m.AgentWindow(mgr, main=path, cgroup_root=root)
                wnd.quiesce()
                before = wnd.read_main()
                if reason == 'inode':
                    twin = root / 'replacement'
                    twin.write_bytes(before.data)
                    twin.replace(path)
                else:
                    quiet = wnd.require_quiet

                    def fault_at_rename():
                        if list(root.glob('.c3-main-*')):
                            mgr.active = True
                        quiet()

                    wnd.require_quiet = fault_at_rename
                with self.assertRaises(m.WindowError):
                    wnd.publish_main(before, json.dumps(profile('b')).encode())
                self.assertEqual(path.read_bytes(), before.data)
                self.assertFalse(list(root.glob('.c3-main-*')))

    def test_queued_xray_heal_vetoes_stop_before_or_publish_after_drain(self):
        self.manager.xray_job = '8'
        self.assertCode('REBUILD_AGENT_EXCLUSION_UNPROVED', self.guard.quiesce)
        self.assertNotIn('stop', [a[1] for a in self.manager.trace])
        self.manager.xray_job = ''
        self.guard.quiesce()
        self.manager.xray_job = '8'
        self.assertCode('REBUILD_AGENT_EXCLUSION_UNPROVED', self.guard.require_quiet)
        self.assertEqual(self.guard.phase, 'exclusion-lost')

    def test_stop_hooks_dependency_activation_and_later_quiet_generation_refuse(self):
        for key in ('ExecStopPost', 'PropagatesStopTo', 'UpheldBy', 'DropInPaths'):
            self.manager.agent_props = {key: 'unexpected'}
            self.assertCode('REBUILD_AGENT_EXCLUSION_UNPROVED', self.guard.quiesce)
        self.assertNotIn('stop', [a[1] for a in self.manager.trace])
        self.manager.agent_props = {}
        self.guard.quiesce()
        self.manager.generation += 1  # invisible stop/start/stop would otherwise look inactive
        self.assertCode('REBUILD_AGENT_EXCLUSION_UNPROVED', self.guard.require_quiet)

    def test_reconcile_refuses_truncated_invocation_conflict_or_restarted_xray(self):
        for name in ('truncated', 'conflict', 'xray-restart'):
            with self.subTest(name=name):
                root = self.root / name
                root.mkdir()
                mgr = System(root)
                wnd = m.AgentWindow(mgr, main=root / 'config.json', cgroup_root=root,
                                    clock=lambda: mgr.now, sleep=mgr.sleep)
                wnd.quiesce()
                wnd.resume()
                if name == 'truncated':
                    mgr.log_tail = 'unverified\n' * 128
                if name == 'conflict':
                    mgr.log_tail = '[store] Preserving users and Xray config until full /sync: fixture\n'
                if name == 'xray-restart':
                    mgr.xray_generation += 1
                self.assertCode('REBUILD_AGENT_RECONCILE_UNPROVED', wnd.wait_reconciled)


class Images(unittest.TestCase):
    def test_managed_namespace_follows_agent_and_excludes_only_exact_clients(self):
        tags = m.managed_inbounds({'inbounds': [{'tag': 'vless-in', 'flow': ''}]})
        orig = profile()
        updated = profile(users=[{'id': 'later'}])
        self.assertEqual(m.topology_bytes(orig, tags), m.topology_bytes(updated, tags))
        for mutate in (lambda p: p['routing']['rules'][0].update(outboundTag='b'),
                       lambda p: p['outbounds'][0].update(tag='changed'),
                       lambda p: p['inbounds'][0]['settings'].update(decryption='changed'),
                       lambda p: p['inbounds'][1]['settings'].update(clients=[])):
            other = copy.deepcopy(updated)
            mutate(other)
            self.assertNotEqual(m.topology_bytes(orig, tags), m.topology_bytes(other, tags))

    def test_rollback_takes_fresh_users_only(self):
        fresh = profile('b', [{'email': 'new', 'id': 'new'}])
        previous = profile('a', [{'email': 'old', 'id': 'old'}])
        restore = m.merge_clients(previous, fresh, m.managed_inbounds({}))
        self.assertEqual(restore, profile('a', [{'email': 'new', 'id': 'new'}]))
        self.assertEqual(previous['inbounds'][0]['settings']['clients'][0]['email'], 'old')

    def test_managed_tags_and_malformed_profiles_fail_closed(self):
        self.assertEqual(m.managed_inbounds({'inbounds': [], 'inbound_tag': 'extra'}), frozenset({'extra'}))
        for bad in ({'Inbounds': [{'tag': 'transit'}]}, {'inbounds': [{'tag': 'x'}, {'tag': 'x'}]},
                    {'inbound_tag': ''}):
            with self.assertRaises(m.WindowError):
                m.managed_inbounds(bad)
        for bad in (profile() | {'inbounds': []}, profile() | {'inbounds': [profile()['inbounds'][0]] * 2}):
            with self.assertRaises(m.WindowError):
                m.merge_clients(bad, profile(), frozenset({'vless-in'}))


if __name__ == '__main__':
    unittest.main()
