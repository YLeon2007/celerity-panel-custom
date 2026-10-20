"""Local fixtures only: not deployed-host or external authority evidence."""
import importlib.util
import pathlib
import shlex
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('isolation', HERE / 'isolation.py')
assert spec is not None
m = importlib.util.module_from_spec(spec)
# This first RED test intentionally reports missing enforcement, not an import error.
if spec.loader and (HERE / 'isolation.py').exists():
    spec.loader.exec_module(m)


class ProtocolTests(unittest.TestCase):
    def test_only_exact_test_runner_argv_is_admitted(self):
        self.assertTrue(hasattr(m, 'parse_runner'), 'restricted node runner is missing')
        plan = {'nodeId': '6ab18adc63913ebd4a917471', 'targetProfile': 'xray-main'}
        args = ['--command', 'close', '--operation-id', 'op-1', '--node-id', plan['nodeId'],
                '--candidate-hash', 'sha256:' + 'a' * 64, '--backup-id', 'backup-1',
                '--target-profile', 'xray-main', '--execution-context', 'test.infograd.online',
                '--attempt-id', 'attempt-1', '--generation', 'generation-1',
                '--predecessor-generation', 'none', '--command-id', 'close-1']
        original = shlex.join([m.RUNNER, *args])
        self.assertEqual(m.parse_runner(original, plan), args)
        for bad in [original + '; id', 'bash -c id', original.replace('test.infograd.online', 'lm1.infograd.online'),
                    original.replace('xray-main', 'xray-bridge'), original + ' --root /tmp',
                    original.replace('close-1', '../escape'), 'internal-sftp', 'scp -t /etc/passwd']:
            with self.subTest(command=bad), self.assertRaises(m.Refusal):
                m.parse_runner(bad, plan)


class PlanTests(unittest.TestCase):
    def plan(self):
        return {'version': 1, 'context': 'test.infograd.online',
                'nodeId': '6ab18adc63913ebd4a917471', 'endpointIp': '132.243.230.19',
                'targetProfile': 'xray-main', 'machineId': 'a' * 32,
                'bootId': '01234567-89ab-cdef-0123-456789abcdef', 'sshHostKeySha256': 'b' * 64,
                'maintenanceId': 'maintenance-1', 'runnerSha256': 'c' * 64,
                'maintenanceConfigSha256': 'd' * 64, 'maintenanceUnitSha256': 'e' * 64,
                'runtimePins': {'/bin/bash': 'f' * 64, '/usr/bin/python3': '1' * 64},
                'isolateUnits': ['ssh.service', 'ssh.socket', 'cc-agent.service', 'cron.service',
                                 'atd.service', 'certbot.service', 'certbot.timer', 'session-1.scope'],
                'keepCgroups': ['/init.scope', '/system.slice/' + m.MAINT_UNIT,
                                '/system.slice/xray.service'], 'unitFilePins': {}}

    def test_shared_panel_and_prod_are_never_adopted(self):
        self.assertTrue(hasattr(m, 'validate_plan'), 'reviewed TEST plan validator is missing')
        p = self.plan()
        m.validate_plan(p)
        for key, value in [('nodeId', '6ab189dc63913ebd4a917399'),
                           ('context', 'lm1.infograd.online'), ('endpointIp', '212.119.42.100'),
                           ('targetProfile', 'xray-bridge'), ('bootId', ['boot']),
                           ('isolateUnits', ['xray.service']), ('keepCgroups', ['/']),
                           ('extra', True)]:
            with self.subTest(key=key), self.assertRaises(m.Refusal):
                m.validate_plan({**p, key: value})


import copy
import json

def json_bytes(value):
    return (json.dumps(value) + '\n').encode()
import os
import tempfile
from unittest.mock import patch


def fixture_hold(engine):
    engine.apply({'fixture': 'guard'})
    engine.host.session = {'pid': 125, 'start': '101'}
    engine.confirm_access()


class EngineTests(PlanTests):
    """Explicit simulated unit adapter, actual disk journal syscalls. Not authority."""
    class FixtureHost:
        def __init__(self):
            self.events = []
            self.bad = None
            self.alive = True
            self.groups_empty = True

        def check_prerequisites(self, p):
            if self.bad:
                raise m.Refusal(self.bad)

        def check_inventory(self, p, held=False):
            return {'processes': [], 'jobsPresent': False}

        def unit(self, name):
            return {'ControlGroup': '/system.slice/' + name, 'KillMode': 'control-group', 'ActiveState': 'active'}

        def snapshot_mask(self, name):
            return {'kind': 'absent'}

        def write_mask(self, name):
            self.events.append(('mask', name))

        def stop(self, name):
            self.events.append(('stop', name))

        def reload(self):
            self.events.append(('reload',))

        def assert_stopped(self, name, group):
            if not self.groups_empty:
                raise m.Refusal('WRITER_DESCENDANT_REMAINS')

        def boot_ticks(self):
            return '100'

        def operator_session(self):
            return getattr(self, 'session', {'pid': 123, 'start': '90'})

        def guard_check(self, guard, session=None):
            if not self.alive:
                raise m.Refusal('RECOVERY_GUARD_LOST')
            return {'session': {'pid': 99999999, 'start': 'fixture-only'}}

        def assert_runner_terminal(self, p, dispatched):
            self.events.append(('terminal-readback',))

        def restore_mask(self, name, saved):
            self.events.append(('restore', name))

    def engine(self, root):
        self.assertTrue(hasattr(m, 'Engine'), 'durable isolation controller is missing')
        return m.Engine(pathlib.Path(root), self.plan(), self.FixtureHost())

    def test_no_hold_until_a_new_post_drain_independent_maintenance_login(self):
        with tempfile.TemporaryDirectory() as root:
            e = self.engine(root)
            e.host.boot_ticks = lambda: '100'
            session = {'pid': 123, 'start': '90'}
            e.host.operator_session = lambda: session
            result = e.apply({'fixture': 'guard'})
            self.assertEqual(result['phase'], 'awaiting-fresh-login', 'live pre-drain channels do not prove new authentication')
            with self.assertRaises(m.Refusal):
                e.assert_held()
            for stale in [{'pid': 123, 'start': '90'}, {'pid': 124, 'start': '99'}, {'pid': 124, 'start': '100'}]:
                session = stale
                with self.assertRaisesRegex(m.Refusal, 'POST_DRAIN_FRESH_LOGIN_REQUIRED'):
                    e.confirm_access()
                self.assertEqual(e.read()['phase'], 'awaiting-fresh-login')
            session = {'pid': 125, 'start': '101'}
            self.assertEqual(e.confirm_access()['phase'], 'held')
            self.assertEqual(e.assert_held()['phase'], 'held')

    def test_debian_process_killmode_ssh_gets_exact_pinned_drain_after_all_stops(self):
        with tempfile.TemporaryDirectory() as root:
            e = self.engine(root)
            unit = e.host.unit
            e.host.unit = lambda name: {**unit(name), 'Id': name, **(
                {'KillMode': 'process'} if name == 'ssh.service' else {})}
            pin = {'device': 1, 'inode': 42}
            def prepare(name, item):
                self.assertEqual(name, 'ssh.service')
                self.assertEqual(item['ControlGroup'], '/system.slice/ssh.service')
                return pin
            def drain(name, saved):
                self.assertEqual(saved['sshDrain'], pin)
                self.assertEqual(set(x[1] for x in e.host.events if x[0] == 'stop'), set(e.plan['isolateUnits']))
                self.assertEqual(e.read()['saved'][name]['sshDrain'], pin)
                e.host.events.append(('ssh-drain', name))
            e.host.prepare_ssh_drain = prepare
            e.host.drain_ssh = drain
            fixture_hold(e)
            self.assertIn(('ssh-drain', 'ssh.service'), e.host.events)
            self.assertEqual(e.read()['phase'], 'held')

    def test_process_killmode_other_services_still_refuse_before_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            e = self.engine(root)
            unit = e.host.unit
            e.host.unit = lambda name: {**unit(name), **(
                {'KillMode': 'process'} if name == 'cc-agent.service' else {})}
            with self.assertRaisesRegex(m.Refusal, 'UNSAFE_KILL_MODE'):
                fixture_hold(e)
            self.assertEqual(e.host.events, [])
            self.assertIsNone(e.read())

    def test_containment_precedes_held_and_restore_never_restarts(self):
        with tempfile.TemporaryDirectory() as root:
            e = self.engine(root)
            fixture_hold(e)
            self.assertEqual(e.read()['phase'], 'held')
            first_stop = next(i for i, x in enumerate(e.host.events) if x[0] == 'stop')
            self.assertTrue(all(x[0] != 'mask' for x in e.host.events[first_stop:]))
            e.restore()
            self.assertEqual(e.read()['phase'], 'masks-restored-no-restart')
            self.assertFalse(any(x[0] == 'start' for x in e.host.events))
            with self.assertRaises(m.Refusal):
                fixture_hold(e)

    def test_live_descendant_keeps_sticky_unknown_and_blocks_dispatch_restore(self):
        with tempfile.TemporaryDirectory() as root:
            e = self.engine(root)
            e.host.groups_empty = False
            with self.assertRaisesRegex(m.Refusal, 'WRITER_DESCENDANT_REMAINS'):
                fixture_hold(e)
            self.assertEqual(e.read()['phase'], 'isolating')
            with self.assertRaises(m.Refusal):
                e.assert_held()
            with self.assertRaises(m.Refusal):
                e.restore()

    def test_structurally_corrupt_journal_cannot_drop_required_masks(self):
        with tempfile.TemporaryDirectory() as root:
            e = self.engine(root)
            fixture_hold(e)
            data = json.loads(pathlib.Path(root, 'journal.json').read_bytes())
            data['saved'] = {}
            pathlib.Path(root, 'journal.json').write_bytes(json_bytes(data))
            with self.assertRaises(m.Refusal):
                e.assert_held()

    def test_dispatch_requires_full_exact_receipt_before_clearing_inflight(self):
        with tempfile.TemporaryDirectory() as root:
            e = self.engine(root)
            fixture_hold(e)
            args = ['--command', 'close', '--operation-id', 'op-1', '--node-id', e.plan['nodeId'],
                    '--candidate-hash', 'sha256:' + 'a' * 64, '--backup-id', 'backup-1',
                    '--target-profile', e.plan['targetProfile'], '--execution-context', e.plan['context'],
                    '--attempt-id', 'attempt-1', '--generation', 'generation-1',
                    '--predecessor-generation', 'none', '--command-id', 'close-1']
            # A pinned runner is trusted, but malformed/cross-operation delivery
            # cannot be recorded as confirmed. This subprocess is explicitly fake.
            wrong = {'ok': True, 'protocolVersion': 2, 'bootId': e.plan['bootId'],
                     'nodeId': e.plan['nodeId'], 'targetProfile': e.plan['targetProfile'],
                     'operationId': 'foreign-operation'}
            fake = m.subprocess.CompletedProcess([], 0, json_bytes(wrong), b'')
            def fixture_run(*unused, **kw):
                self.assertGreaterEqual(kw['pass_fds'][0], 10, 'runner heredoc reserves fd 3')
                os.fstat(kw['pass_fds'][0])
                self.assertNotIn('CELERITY_TOPOLOGY_ROOT', kw['env'])
                return fake
            with patch.object(m.subprocess, 'run', side_effect=fixture_run), self.assertRaises(m.Refusal):
                e.dispatch(shlex.join([m.RUNNER, *args]), b'', 0)
            self.assertIsNotNone(e.read()['dispatchInFlight'])
            with self.assertRaises(m.Refusal):
                e.restore()

    def test_guard_loss_drift_or_uncertain_file_cannot_grant_hold(self):
        with tempfile.TemporaryDirectory() as root:
            e = self.engine(root)
            fixture_hold(e)
            e.host.alive = False
            with self.assertRaises(m.Refusal):
                e.assert_held()
            e.host.alive = True
            e.host.bad = 'BOOT_CHANGED'
            with self.assertRaises(m.Refusal):
                e.assert_held()
            e.host.bad = None
            pathlib.Path(root, 'journal.json.next').write_text('{}')
            with self.assertRaises(m.Refusal):
                e.assert_held()


class LinuxFixtureTests(unittest.TestCase):
    def test_exact_ssh_cgroup_pin_and_mask_are_checked_before_kill_syscall(self):
        # Real filesystem/open/fstat/write, simulated cgroup files (not kernel proof).
        with tempfile.TemporaryDirectory() as root, patch.object(m, 'MASK_ROOT', root):
            root = pathlib.Path(root)
            group = root / 'group'; group.mkdir()
            (group / 'cgroup.kill').write_bytes(b'')
            (group / 'cgroup.events').write_text('populated 0\n')
            (root / 'ssh.service').symlink_to('/dev/null')
            item = {'Id': 'ssh.service', 'ControlGroup': '/system.slice/ssh.service', 'KillMode': 'process'}
            stopped = {'LoadState': 'masked', 'ActiveState': 'inactive', 'MainPID': '0',
                       'Job': '', 'ControlGroup': item['ControlGroup']}
            real_open = os.open
            def fixture_open(path, *args, **kw):
                if path == '/sys/fs/cgroup/system.slice/ssh.service':
                    path = group
                return real_open(path, *args, **kw)
            host = m.Host()
            with patch.object(m.os, 'open', side_effect=fixture_open), patch.object(host, 'unit', return_value=stopped):
                pin = host.prepare_ssh_drain('ssh.service', item)
                saved = {'unit': item, 'oldCgroup': item['ControlGroup'], 'sshDrain': pin}
                with self.assertRaisesRegex(m.Refusal, 'SSH_CGROUP_IDENTITY_CHANGED'):
                    host.drain_ssh('ssh.service', {**saved, 'sshDrain': {**pin, 'inode': pin['inode'] + 1}})
                self.assertEqual((group / 'cgroup.kill').read_bytes(), b'')
                (root / 'ssh.service').unlink()
                with self.assertRaisesRegex(m.Refusal, 'SSH_ENTRY_NOT_STOPPED'):
                    host.drain_ssh('ssh.service', saved)
                self.assertEqual((group / 'cgroup.kill').read_bytes(), b'')
                (root / 'ssh.service').symlink_to('/dev/null')
                host.drain_ssh('ssh.service', saved)
                self.assertEqual((group / 'cgroup.kill').read_bytes(), b'1\n')
                for name, changed in [('cc-agent.service', item), ('ssh.service', {**item, 'Id': 'cc-agent.service'}),
                                      ('ssh.service', {**item, 'ControlGroup': '/system.slice'})]:
                    with self.subTest(name=name, changed=changed), self.assertRaises(m.Refusal):
                        host.prepare_ssh_drain(name, changed)

    def test_runtime_prerequisite_refuses_unpreserved_old_sshd_before_apply(self):
        self.assertTrue(hasattr(m.Host, 'check_ssh_runtime'), 'shared directory preservation is not verified')
        good = {'RuntimeDirectory': 'sshd', 'RuntimeDirectoryMode': '0755',
                'RuntimeDirectoryPreserve': 'yes', 'User': 'root', 'Group': 'root', 'ActiveState': 'active'}
        plan = PlanTests().plan()
        for old_preserve in ['no', '', 'yes']:
            def unit(name):
                return {**good, **({'RuntimeDirectoryPreserve': old_preserve} if name == 'ssh.service' else {})}
            with self.subTest(old_preserve=old_preserve), patch.object(m.Host, 'unit', side_effect=unit):
                if old_preserve == 'yes':
                    m.Host().check_ssh_runtime(plan)
                else:
                    with self.assertRaisesRegex(m.Refusal, 'SSH_RUNTIME_PRESERVATION_REQUIRED'):
                        m.Host().check_ssh_runtime(plan)
        with patch.object(m.Host, 'unit', return_value={**good, 'RuntimeDirectory': ''}), \
             self.assertRaisesRegex(m.Refusal, 'MAINT_RUNTIME_OWNERSHIP_REQUIRED'):
            m.Host().check_ssh_runtime(plan)

    def test_maintenance_unit_owns_shared_sshd_runtime_directory_without_preinstall_side_effects(self):
        import configparser
        config = configparser.ConfigParser(interpolation=None)
        config.read(HERE / 'c3-test-maintenance-sshd.service')
        service = config['Service']
        self.assertEqual(service.get('RuntimeDirectory'), 'sshd', 'sshd privilege separation directory has no independent owner')
        self.assertEqual(service.get('RuntimeDirectoryMode'), '0755')
        self.assertEqual(service.get('RuntimeDirectoryPreserve'), 'yes')
        old = configparser.ConfigParser(interpolation=None)
        old.read(HERE / 'normal-ssh-runtime.conf')
        self.assertEqual(old['Service'].get('RuntimeDirectoryPreserve'), 'yes')
        self.assertEqual(service.get('User'), 'root')
        self.assertEqual(service.get('Group'), 'root')

    def test_recovery_guard_requires_fresh_bidirectional_ssh_channel_response(self):
        self.assertTrue(hasattr(m, 'recovery_roundtrip'), 'guard only checked local sshd PID, not live recovery channel')
        import subprocess
        for response, succeeds in [({'recoveryResponse': 'a' * 64}, True),
                                   ({'recoveryResponse': 'b' * 64}, False), (None, False)]:
            code = ('import importlib.util; s=importlib.util.spec_from_file_location("m",' + repr(str(HERE / 'isolation.py')) + '); '
                    'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                    'm.recovery_roundtrip("' + 'a' * 64 + '"); print("confirmed",flush=True)')
            child = subprocess.Popen([sys.executable, '-I', '-c', code], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                assert child.stdout is not None
                challenge = json.loads(child.stdout.readline())
                self.assertEqual(challenge, {'recoveryChallenge': 'a' * 64})
                out, _ = child.communicate(json_bytes(response) if response else b'', timeout=5)
                self.assertEqual(child.returncode == 0, succeeds)
                if succeeds:
                    self.assertIn(b'confirmed', out)
            finally:
                if child.poll() is None:
                    child.kill(); child.wait()

    def test_openssh_repeated_allowusers_does_not_overwrite_operator(self):
        self.assertTrue(hasattr(m, 'parse_sshd_effective'), 'OpenSSH repeated-value parser missing')
        parsed = m.parse_sshd_effective('allowusers c3-test-operator\nallowusers c3-test-runner\nport 2222\n')
        self.assertEqual(parsed['allowusers'], 'c3-test-operator c3-test-runner')
        parsed = m.parse_sshd_effective('port 22\nport 2222\n')
        self.assertNotEqual(parsed['port'], '2222', 'extra SSH listener must not be hidden')

    def test_real_mask_snapshot_restore_preserves_file_alias_absence_and_xattr(self):
        with tempfile.TemporaryDirectory() as root, patch.object(m, 'MASK_ROOT', root):
            host = m.Host()
            regular = pathlib.Path(root, 'custom.service')
            regular.write_bytes(b'[Service]\nExecStart=/bin/false\n'); regular.chmod(0o640)
            os.setxattr(regular, 'user.c3-fixture', b'metadata')
            pathlib.Path(root, 'alias.service').symlink_to('custom.service')
            for name in ['custom.service', 'alias.service', 'absent.service']:
                before = host.snapshot_mask(name)
                host.write_mask(name)
                self.assertEqual(os.readlink(pathlib.Path(root, name)), '/dev/null')
                host.restore_mask(name, before)
                self.assertEqual(host.snapshot_mask(name), before)
            self.assertEqual(os.getxattr(regular, 'user.c3-fixture'), b'metadata')

    def test_proc_start_identity_and_atomic_journal_are_real_syscalls(self):
        ident = m.proc_identity(os.getpid())
        self.assertEqual(ident['pid'], os.getpid())
        self.assertTrue(ident['start'].isdecimal())
        with tempfile.TemporaryDirectory() as root:
            m.atomic_json(root, 'journal.json', {'pid': ident})
            self.assertEqual(json.loads(pathlib.Path(root, 'journal.json').read_bytes()), {'pid': ident})
            self.assertEqual(pathlib.Path(root, 'journal.json').stat().st_mode & 0o777, 0o600)
            pathlib.Path(root, 'journal.json.next').write_bytes(b'uncertain')
            with self.assertRaises(FileExistsError):
                m.atomic_json(root, 'journal.json', {'overwritten': True})
            self.assertNotIn('overwritten', json.loads(pathlib.Path(root, 'journal.json').read_bytes()))

    def test_inventory_rejects_unknown_timer_socket_process_or_pending_job(self):
        plan = PlanTests().plan()
        base = {'jobsPresent': False, 'units': {}, 'unitFilePins': {}, 'processes': []}
        for change in [
            {'jobsPresent': True},
            {'units': {'new.timer': {'LoadState': 'loaded', 'ActiveState': 'active'}}},
            {'units': {'sshd-vsock.socket': {'LoadState': 'not-found', 'ActiveState': 'active'}}},
            {'units': {'new.timer': {'LoadState': 'masked', 'ActiveState': 'inactive', 'Triggers': 'new.service'}}},
            {'processes': [{'cgroup': '/user.slice/user-0.slice/session-999.scope'}]},
            {'processes': [{'cgroup': '/system.slice/unreviewed.service'}]},
        ]:
            with self.subTest(change=change), patch.object(m.Host, 'inventory', return_value={**base, **change}), \
                 patch.object(m.Host, 'unit', return_value={'ControlGroup': ''}), self.assertRaises(m.Refusal):
                m.Host().check_inventory(plan, held=True)

    def test_fake_root_actual_v2_runner_two_generations_and_replay_retention(self):
        # Actual pinned artifact code + actual subprocess/fsync/flock. Physical,
        # systemd, SSH and cgroups are explicitly simulated, NOT live authority.
        with tempfile.TemporaryDirectory() as root:
            root = pathlib.Path(root)
            state = root / 'controller'; state.mkdir()
            fixture = root / 'node'
            def put(path, value, mode=0o600):
                p = fixture / path; p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(value); p.chmod(mode)
            boot = PlanTests().plan()['bootId']
            put('proc/sys/kernel/random/boot_id', boot + '\n')
            (fixture / 'var/lib').mkdir(parents=True)
            put('usr/local/etc/xray/config.json', '{"old":true}\n')
            (fixture / 'usr/local/share/xray').mkdir(parents=True)
            put('usr/local/bin/xray', '#!/bin/sh\nexit 0\n', 0o700)
            put('usr/bin/systemctl', '#!/bin/sh\ncase "$1" in\nshow) printf "Job=\\nActiveState=active\\nSubState=running\\n";;\n*) exit 0;;\nesac\n', 0o700)
            runner = HERE.parents[1] / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
            e = m.Engine(state, PlanTests().plan(), EngineTests.FixtureHost())
            fixture_hold(e)
            content = b'{"inbounds":[],"outbounds":[]}\n'
            def original(command, generation='generation-1', predecessor='none'):
                args = ['--command', command, '--operation-id', 'op-' + generation,
                        '--node-id', e.plan['nodeId'], '--candidate-hash', 'sha256:' + m.digest(content),
                        '--backup-id', 'backup-' + generation, '--target-profile', 'xray-main',
                        '--execution-context', 'test.infograd.online', '--attempt-id', 'attempt-' + generation,
                        '--generation', generation, '--predecessor-generation', predecessor,
                        '--command-id', command + '-' + generation]
                return shlex.join([m.RUNNER, *args])
            lock = os.open(state / 'lock', os.O_RDWR | os.O_CREAT, 0o600)
            try:
                m.fcntl.flock(lock, m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
                with patch.object(m, 'RUNNER', str(runner)), patch.object(m, 'CLEAN_ENV',
                     {**m.CLEAN_ENV, 'CELERITY_TOPOLOGY_ROOT': str(fixture)}):
                    for command in ['prepare', 'rollback', 'close']:
                        result = json.loads(e.dispatch(original(command), content if command == 'prepare' else b'', lock))
                        self.assertEqual(result['command'], command)
                    result = json.loads(e.dispatch(original('close', 'generation-2', 'generation-1'), b'', lock))
                    self.assertTrue(result['terminal'])
                    result = json.loads(e.dispatch(original('status', 'generation-2', 'generation-1').replace('status-generation-2', 'close-generation-2'), b'', lock))
                    self.assertTrue(result['terminal'])
                    with self.assertRaises(m.Refusal):
                        e.dispatch(original('prepare'), content, lock)
                    self.assertIsNotNone(e.read()['dispatchInFlight'])
                    with self.assertRaises(m.Refusal):
                        e.restore()
            finally:
                os.close(lock)


if __name__ == '__main__':
    unittest.main()
