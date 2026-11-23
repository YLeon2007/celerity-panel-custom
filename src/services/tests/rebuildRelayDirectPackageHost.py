"""Fixture-only tests: python3 -B src/services/tests/rebuildRelayDirectPackageHost.py."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from test_rebuild_relay_packages import HERE, Host, KEYRING, LATE, POLICY, SYSTEM, THIRD_PARTY, g, package_ownership


HOST = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
MACHINE = '1' * 32
TOKEN = '2' * 32
BOOT = '12345678-1234-1234-1234-123456789abc'
CTL = ('/usr/bin/systemctl', '--system', '--no-pager', '--no-ask-password', '--full')
APT = ('/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL=C',
       'DEBIAN_FRONTEND=noninteractive', 'UCF_FORCE_CONFFOLD=1', f'APT_CONFIG=/proc/{os.getpid()}/fd/7',
       '/usr/bin/apt-get')
APT_UPDATE = APT + ('--error-on=any', 'update')
APT_INSTALL = APT + ('-y', '--no-install-recommends', '--no-install-suggests', '--no-remove', '--no-upgrade',
                     'install', 'xl2tpd=1')


class GuardRefusal(Exception):
    pass


class Adapter(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o022))  # Debian fixture dirs must not be group-writable.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.system = self.root / 'system'
        self.system.mkdir()
        self.vault = self.root / 'vault'
        self.h: dict[str, Any] = {'__name__': 'fixture'}
        exec(compile(HOST.read_bytes(), str(HOST), 'exec'), self.h)
        self.installed = False
        self.plan: dict[str, Any] = dict(missing=['xl2tpd'], versions={'xl2tpd': 'fixture-v1'})
        self.guard_calls = []
        self.effects = []
        self.synced = []

        @contextlib.contextmanager
        def directory(path, private=False):
            self.assertTrue(Path(path).is_relative_to(self.root))
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                yield fd
            finally:
                os.close(fd)

        class FixtureOS:
            def __getattr__(inner, name):
                return getattr(os, name)

            @staticmethod
            def geteuid():
                return 0

            @staticmethod
            def umask(_):
                pass

            @staticmethod
            def fchown(fd, uid, gid):
                assert (uid, gid) == (0, 0)  # Model owner, retain real bytes/fsync/flock.

            @staticmethod
            def fsync(fd):
                os.fsync(fd)
                self.synced.append(os.readlink(f'/proc/self/fd/{fd}'))

            @staticmethod
            def fstat(fd):
                st = os.fstat(fd)
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                                       0, 0, st.st_size, st.st_atime, st.st_mtime, st.st_ctime))

        def machine(value):
            self.h['need'](value == self.machine, 'IDENTITY')
            return self.machine

        self.machine = MACHINE
        self.host_command = self.h['command']
        self.h.update(SYSTEM=str(self.system), VAULT=str(self.vault), os=FixtureOS(),
                      directory=directory, boot=lambda: BOOT, require_machine=machine,
                      ppp_device=lambda: None, unit=lambda name: {'LoadState': 'loaded'},
                      command=self.command, stock_runtime_root=lambda: self.root,
                      C3_PACKAGE_GUARD={'Refusal': GuardRefusal, 'observe': self.observe, 'prepare': self.prepare})
        self.popen_patch = patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected real command'))
        self.popen_patch.start()
        self.addCleanup(self.popen_patch.stop)

    def command(self, *argv, **kw):
        self.assertEqual(argv[0], '/usr/bin/dpkg-query')
        if not self.installed:
            raise self.h['Refusal'](kw['refusal'])
        return b'ii '

    def observe(self, root, run):
        self.assertEqual(root, self.root)
        self.guard_calls.append('observe')
        return self.plan

    def settled_install(self, argv, end, cap, *, may_write):
        self.assertEqual(argv, APT_INSTALL)
        self.assertTrue(time.monotonic() < end <= self.h['DEADLINE'])
        self.assertEqual(cap, self.h['PACKAGE_MAX_OUTPUT'])
        self.assertTrue(may_write)
        return 0, b'', b''

    def prepare(self, root, run, expected, enter):
        self.assertEqual(root, self.root)
        self.assertEqual(expected, self.plan)
        fd = os.open(self.system, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        finally:
            os.close(fd)
        self.guard_calls.append('prepare')
        intent = json.loads((self.vault / self.h['PACKAGE_PENDING']).read_bytes())
        receipt = self.vault / f"packages-{intent['backupId']}.json"
        self.assertEqual(json.loads(receipt.read_bytes()), intent)
        self.assertEqual(intent['phase'], 'preparing')
        self.assertIn(str(self.vault.parent), self.synced)
        self.assertGreaterEqual(self.synced.count(str(self.vault)), 2)
        enter()
        with patch.dict(self.h, bounded_status=self.settled_install):
            self.assertEqual(run(APT_INSTALL, 78), (0, b'', b''))
        self.effects.append('package guard effects')
        self.installed = True

    def wire(self, action, **params):
        request = dict(action=action, machineId=MACHINE, **params)
        return self.raw_wire(json.dumps(request).encode())

    def raw_wire(self, request):
        stdin = io.TextIOWrapper(io.BytesIO(request))
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, 'stdin', stdin), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = self.h['main']()
        return status, stdout.getvalue(), stderr.getvalue()

    def offered(self):
        status, stdout, stderr = self.wire('preflight')
        self.assertEqual((status, stderr), (0, ''))
        self.assertFalse(self.vault.exists())
        offer = json.loads(stdout)
        self.assertEqual(set(offer), {'machineId', 'packagePreparation'})
        self.assertEqual(offer['machineId'], MACHINE)
        self.assertRegex(offer['packagePreparation'], r'^[a-f0-9]{64}$')
        return offer['packagePreparation']

    def test_offer_and_ack_are_exact_and_install_directory_is_unclaimed(self):
        proof = self.offered()
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof),
                         (0, f'{{"ok":true,"backupId":"{TOKEN}","packagesReady":true}}\n', ''))
        self.assertEqual(self.guard_calls, ['observe', 'observe', 'prepare'])
        self.assertEqual(len(self.effects), 1)
        self.assertFalse((self.vault / TOKEN).exists())
        # Stock Install can still create its normal operation directory.
        self.h['mkdir'](str(self.vault / TOKEN), 0o700)
        self.assertEqual(self.wire('preflight'), (0, f'{{"machineId":"{MACHINE}","ppp":false,"masked":false,'
                                                   '"unitsLoaded":true,"pppPreparation":true}\n', ''))
        self.installed = False  # Even if the old plan becomes eligible again: no replay.
        self.assertNotEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof)[0], 0)
        self.assertEqual(len(self.effects), 1)

    def test_only_explicit_missing_preflight_can_observe(self):
        self.assertEqual(self.wire('prepare'), (70, '', 'DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE\n'))
        self.assertFalse(self.guard_calls)
        self.h['command'] = lambda *_, **kw: (_ for _ in ()).throw(OSError('synthetic-private'))
        self.assertEqual(self.wire('preflight'), (70, '', 'DIRECT_PREREQUISITE\n'))
        self.assertFalse(self.guard_calls)
        self.assertFalse(self.vault.exists())

    def test_plan_boot_and_lock_rechecked_before_intent(self):
        proof = self.offered()
        self.plan = dict(self.plan, versions={'xl2tpd': 'changed'})
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof),
                         (70, '', 'DIRECT_BASELINE_CHANGED\n'))
        self.plan['versions']['xl2tpd'] = 'fixture-v1'
        self.h['boot'] = lambda: BOOT.replace('abc', 'abd')
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof)[0], 70)
        self.h['boot'] = lambda: BOOT
        self.system.rename(self.root / 'old-system')
        self.system.mkdir()
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof)[0], 70)
        self.assertFalse(self.effects)
        self.assertFalse(self.vault.exists())

    def test_pre_enter_refusal_is_sanitized_but_effects_remain_pending(self):
        proof = self.offered()

        def refuse(root, run, expected, enter):
            raise GuardRefusal('synthetic-private\nDIRECT_NO_WRITE_FORGED')

        guard = self.h['C3_PACKAGE_GUARD']
        guard['prepare'] = refuse
        result = self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof)
        self.assertEqual(result, (70, '', 'DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE\n'))
        self.assertFalse(self.effects)
        def entered_refusal(root, run, expected, enter):
            self.prepare(root, run, expected, enter)
            refuse(root, run, expected, enter)

        guard['prepare'] = entered_refusal
        result = self.wire('prepare-packages', backupId='3' * 32, packagePreparation=proof)
        self.assertEqual(result, (75, '', ''))
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.wire('preflight'), (75, '', ''))
        self.assertEqual(self.wire('prepare'), (75, '', ''))
        self.assertEqual(self.wire('install'), (75, '', ''))
        self.assertEqual(self.wire('prepare-packages', backupId='4' * 32, packagePreparation=proof), (75, '', ''))
        self.assertEqual(len(self.effects), 1)

    def test_package_plan_lookalikes_and_details_are_redacted_at_both_guard_boundaries(self):
        proof = self.offered()
        guard = self.h['C3_PACKAGE_GUARD']
        generic = (70, '', 'DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE\n')
        for index, args in enumerate((('PACKAGE_APT_PLAN_FIXTURE_PRIVATE',),
                                      ('PACKAGE_APT_PLAN\n/fixture/private',),
                                      ('PACKAGE_APT_PLAN', '/fixture/private'), ('PACKAGE_APT_PLAN',))):
            with self.subTest(args=args):
                def refuse(*_):
                    error = GuardRefusal(*args)
                    if args == ('PACKAGE_APT_PLAN',):
                        error.add_note('/fixture/private cleanup status')
                    raise error

                with patch.dict(guard, observe=refuse):
                    self.assertEqual(self.wire('preflight'), generic)
                with patch.dict(guard, prepare=refuse):
                    self.assertEqual(self.wire('prepare-packages', backupId=f'{index:032x}', packagePreparation=proof),
                                     generic)
        self.assertFalse(self.effects)
        self.assertFalse((self.vault / self.h['PACKAGE_PENDING']).exists())

    def test_identity_drift_after_intent_blocks_enter(self):
        proof = self.offered()

        def change(root, run, expected, enter):
            self.machine = 'a' * 32
            enter()
            self.fail('effect grant after identity change')

        self.h['C3_PACKAGE_GUARD']['prepare'] = change
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', ''))
        self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).exists())
        self.assertFalse(self.effects)

    def test_fsync_failure_does_not_enter_guard(self):
        proof = self.offered()

        def fail_sync(fd):
            raise OSError('fixture failure')

        self.h['os'].fsync = fail_sync
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', ''))
        self.assertEqual(self.guard_calls, ['observe', 'observe'])
        self.assertFalse(self.effects)

    def test_settled_failure_status_is_not_timeout_or_raw_output(self):
        proof = self.offered()
        commands = []

        def transport(argv, end, cap, *, may_write):
            self.assertLessEqual(end, self.h['DEADLINE'])
            self.assertEqual(cap, self.h['PACKAGE_MAX_OUTPUT'])
            commands.append((argv, may_write))
            if argv[-1] == 'check':
                return 0, b'', b''
            return 100, b'synthetic-private', b'synthetic-private'

        def prepare(root, run, expected, enter):
            self.assertEqual(run(APT + ('-s', 'check'), 6), (0, b'', b''))
            enter()
            self.assertEqual(run(APT_INSTALL, 78)[0], 100)
            raise GuardRefusal('synthetic-private')

        self.h.update(bounded_status=transport)
        self.h['C3_PACKAGE_GUARD']['prepare'] = prepare
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', ''))
        self.assertEqual([may_write for _, may_write in commands], [False, True])
        self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).exists())

    def test_unsettled_transport_is_sticky_even_when_guard_catches_it(self):
        proof = self.offered()
        commands = []

        def timed_out(argv, *_args, **_kwargs):
            commands.append(argv)
            raise subprocess.TimeoutExpired(argv, 1, output=b'synthetic-private')

        def prepare(root, run, expected, enter):
            enter()
            with self.assertRaises(subprocess.TimeoutExpired):
                run(APT_INSTALL, 78)
            with self.assertRaises(subprocess.TimeoutExpired):
                run(CTL + ('daemon-reload',), 12)
            return None  # A swallowed failure must not promote pending to ready.

        self.h.update(bounded_status=timed_out)
        self.h['C3_PACKAGE_GUARD']['prepare'] = prepare
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', ''))
        self.assertEqual(len(commands), 1)
        self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).exists())

    def test_late_guard_return_cannot_publish_ready(self):
        proof = self.offered()

        def late(root, run, expected, enter):
            self.prepare(root, run, expected, enter)
            self.h['DEADLINE'] = time.monotonic()

        self.h['C3_PACKAGE_GUARD']['prepare'] = late
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', ''))
        self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).exists())
        self.assertEqual(len(self.effects), 1)

    def test_protected_update_then_install_settles(self):
        proof = self.offered()
        calls = []

        def child(argv, end, cap, *, may_write):
            self.assertTrue(may_write)
            self.assertTrue(time.monotonic() < end <= self.h['DEADLINE'])
            self.assertEqual(cap, self.h['PACKAGE_MAX_OUTPUT'])
            self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).is_file())
            calls.append(argv)
            return 0, b'', b''

        def prepare(root, run, expected, enter):
            enter()
            self.assertEqual(run(APT_UPDATE, 20), (0, b'', b''))
            self.assertTrue(run.update_settled)
            self.assertFalse(run.apt_dispatched or run.apt_settled)
            self.assertEqual(run(APT_INSTALL, 78), (0, b'', b''))

        self.h['bounded_status'] = child
        self.h['C3_PACKAGE_GUARD']['prepare'] = prepare
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof),
                         (0, f'{{"ok":true,"backupId":"{TOKEN}","packagesReady":true}}\n', ''))
        self.assertEqual(calls, [APT_UPDATE, APT_INSTALL])

    def test_update_without_install_cannot_publish_ready(self):
        proof = self.offered()
        completed = []

        def prepare(root, run, expected, enter):
            enter()
            completed.append(run(APT_UPDATE, 20))

        self.h['bounded_status'] = lambda *a, **kw: (0, b'', b'')
        self.h['C3_PACKAGE_GUARD']['prepare'] = prepare
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', ''))
        self.assertEqual(completed, [(0, b'', b'')])
        self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).is_file())

    def test_update_consumes_the_same_absolute_deadline_as_install(self):
        proof = self.offered()
        deadline = self.h['DEADLINE']
        now = deadline - 115 + 80  # Count elapsed receiver time; selection cannot restart the clock.
        calls = []

        def child(argv, end, cap, *, may_write):
            nonlocal now
            calls.append((argv, end - now, may_write))
            now = now + 70 if argv == APT_UPDATE else end
            return 0, b'', b''  # The install's zero status arrives at the clipped deadline.

        def prepare(root, run, expected, enter):
            enter()
            run(APT_UPDATE, 78)
            run(APT_INSTALL, 78)

        self.h.update(time=SimpleNamespace(monotonic=lambda: now), bounded_status=child)
        self.h['C3_PACKAGE_GUARD']['prepare'] = prepare
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', ''))
        self.assertEqual(calls, [(APT_UPDATE, 78, True), (APT_INSTALL, 60, True)])
        self.assertEqual(self.h['DEADLINE'], deadline)
        self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).is_file())

    def test_update_admission_rejects_wrong_shape_phase_and_replay(self):
        malformed = (APT_UPDATE[7:], APT + ('update',), APT_UPDATE + ('-q',),
                     (*APT_UPDATE[:6], 'APT_CONFIG=/etc/apt/apt.conf', *APT_UPDATE[7:]))
        cases = ([(False, (), APT_UPDATE)] + [(True, (), argv) for argv in malformed] +
                 [(True, (argv,), APT_UPDATE) for argv in (APT_UPDATE, APT_INSTALL)])
        for entered, prior, attempt in cases:
            with self.subTest(entered=entered, prior=prior, attempt=attempt):
                calls = []
                self.h['bounded_status'] = lambda argv, *a, **kw: (calls.append(argv) or 0, b'', b'')
                run = self.h['PackageRunner']()
                run.entered = entered
                for argv in prior:
                    self.assertEqual(run(argv, 20)[0], 0)
                with self.assertRaises(subprocess.TimeoutExpired):
                    run(attempt, 20)
                self.assertTrue(run.failed)
                self.assertEqual(calls, list(prior))
                self.assertEqual(run.remaining, self.h['PACKAGE_MAX_COMMANDS'] - len(prior))

    def test_failed_update_blocks_install_and_publication_even_if_swallowed(self):
        for status, second in ((100, APT_INSTALL), (100, APT_UPDATE), (0, APT_INSTALL), (-15, APT_INSTALL),
                               (None, CTL + ('daemon-reload',))):
            with self.subTest(status=status, second=second), tempfile.TemporaryDirectory(dir=self.root) as temp:
                self.vault = Path(temp) / 'vault'
                self.h['VAULT'] = str(self.vault)
                proof = self.offered()
                calls, outcomes = [], []

                def child(argv, end, cap, *, may_write):
                    self.assertTrue(may_write)
                    calls.append(argv)
                    if status is None:
                        raise subprocess.TimeoutExpired(argv, 20, output=b'synthetic-private')
                    return status, b'synthetic-private', b'synthetic-private'

                def prepare(root, run, expected, enter):
                    enter()
                    try:
                        code = run(APT_UPDATE, 20)[0]
                    except subprocess.TimeoutExpired:
                        code = None
                    outcomes.append((code, run.failed, run.update_dispatched, run.update_settled))
                    try:
                        run(second, 20)
                    except subprocess.TimeoutExpired:
                        outcomes.append((run.failed, run.apt_dispatched, run.apt_settled))

                self.h['bounded_status'] = child
                self.h['C3_PACKAGE_GUARD']['prepare'] = prepare
                self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', ''))
                self.assertEqual(calls, [APT_UPDATE])
                first = (status, False) if status in (0, 100) else (None, True)
                self.assertEqual(outcomes, [(*first, True, False), (True, False, False)])
                self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).is_file())

    def test_observer_cannot_dispatch_and_budget_is_shared(self):
        calls = []
        self.h.update(bounded_status=lambda *args, **kwargs: (calls.append(args[0]) or 0, b'', b''),
                      PACKAGE_MAX_COMMANDS=2)
        guard = self.h['C3_PACKAGE_GUARD']

        def observe(root, run):
            run(APT + ('-s', 'check'), 6)
            return self.plan

        for writer in (CTL + ('daemon-reload',), APT_UPDATE):
            guard['observe'] = lambda root, run: run(writer, 12)
            self.assertEqual(self.wire('preflight'), (75, '', ''))
            self.assertFalse(calls)
        guard['observe'] = observe
        proof = self.offered()
        calls.clear()

        def prepare(root, run, expected, enter):
            observe(root, run)
            observe(root, run)
            enter()

        guard['prepare'] = prepare
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', ''))
        self.assertEqual(len(calls), 2)
        self.assertFalse(self.effects)

    def model_real_guard(self, *, empty_indexes=False):
        host = Host(self, self.root)
        self.system = host.p(SYSTEM)
        pending = self.vault / self.h['PACKAGE_PENDING']
        receipt = self.vault / f'packages-{TOKEN}.json'
        if empty_indexes:
            host.p('/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease').unlink()

        def child_status(argv, end, cap, *, may_write):
            if may_write and not host.effects:
                self.assertEqual(receipt.read_bytes(), pending.read_bytes())
                self.assertEqual(json.loads(pending.read_bytes())['phase'], 'preparing')
                host.effects.append('enter')
            return host.run(argv, 78)

        self.h.update(SYSTEM=str(self.system), bounded_status=child_status,
                      C3_PACKAGE_GUARD={'Refusal': g.Refusal, 'observe': g.observe, 'prepare': g.prepare})
        ownership = patch.dict(vars(g), package_ownership(host.root, host.archive_owners))
        ownership.start()
        self.addCleanup(ownership.stop)
        return host, receipt, pending

    def test_live_source_ignored_but_busy_apt_lock_and_bad_keyring_refuse(self):
        host, _, _ = self.model_real_guard()
        host.put('/etc/apt/sources.list.d/operator.list', THIRD_PARTY)
        proof = self.offered()
        with host.p('/var/lib/apt/lists/lock').open('r+b') as lock:
            request = struct.pack('=hh4xqqi4x', fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
            fcntl.fcntl(lock.fileno(), fcntl.F_OFD_SETLK, request)
            self.assertEqual(self.wire('preflight'), (70, '', 'DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE\n'))
        self.assertEqual(self.offered(), proof)
        host.p(KEYRING).chmod(0o666)
        frame = (70, '', 'DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE\n')
        self.assertEqual(self.wire('preflight'), frame)
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), frame)
        self.assertFalse(self.vault.exists())
        self.assertEqual(host.effects, [])

    def test_foreign_unit_is_diagnostic_but_failed_service_observation_is_not(self):
        host, _, _ = self.model_real_guard()
        host.link('/run/systemd/system/strongswan-starter.service', '/opt/private-fixture.service')
        self.assertEqual(self.wire('preflight'), (70, '', 'DIRECT_PACKAGE_SERVICES_UNSAFE\n'))
        run = host.run
        with patch.object(host, 'run', side_effect=lambda argv, timeout:
                          (1, b'', b'private fixture') if argv[:5] == CTL else run(argv, timeout)):
            self.assertEqual(self.wire('preflight'), (70, '', 'DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE\n'))
        self.assertEqual(host.effects, [])
        self.assertFalse(self.vault.exists())

    def test_unrecognized_service_properties_do_not_certify_unsafe_service_diagnostic(self):
        host, _, _ = self.model_real_guard()
        show = host._show

        def unrecognized(unit):
            rc, out, err = show(unit)
            return rc, out.replace(b'ActiveState=inactive\n', b'ActiveState=private-fixture\n'), err

        with patch.object(host, '_show', side_effect=unrecognized):
            self.assertEqual(self.wire('preflight'), (70, '', 'DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE\n'))
        self.assertFalse(self.vault.exists())

    def test_scope_change_during_preflight_suppresses_index_diagnostic(self):
        host, _, _ = self.model_real_guard()
        # Keep a real diagnostic producer, now the lists observer rather than
        # the deleted live-source parser.
        host.p('/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease').rename(
            host.p('/var/lib/apt/lists/foreign_InRelease'))
        self.assertEqual(self.wire('preflight'), (70, '', 'DIRECT_PACKAGE_INDEXES_UNVERIFIED\n'))
        observe = g.observe

        def observe_then_drift(*args):
            try:
                return observe(*args)
            finally:
                self.machine = '3' * 32

        with patch.dict(self.h['C3_PACKAGE_GUARD'], observe=observe_then_drift):
            self.assertEqual(self.wire('preflight'), (75, '', ''))
        self.assertFalse(self.vault.exists())

    def test_update_exec_failure_is_not_an_index_diagnostic(self):
        host, receipt, pending = self.model_real_guard(empty_indexes=True)
        proof = self.offered()
        run = host.run
        with patch.object(host, 'run', side_effect=lambda argv, timeout:
                          (127, b'', b'private fixture') if argv[-3:] == g.UPDATE else run(argv, timeout)):
            self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', ''))
        self.assertEqual(receipt.read_bytes(), pending.read_bytes())
        self.assertEqual(json.loads(pending.read_bytes())['phase'], 'preparing')

    def test_guard_pre_enter_service_refusal_publishes_only_refused_receipt(self):
        host, receipt, pending = self.model_real_guard()
        proof = self.offered()
        run = host.run

        def service_changes_after_intent(argv, timeout):
            host.active = pending.exists()
            return run(argv, timeout)

        with patch.object(host, 'run', side_effect=service_changes_after_intent):
            self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof),
                             (70, '', 'DIRECT_PACKAGE_SERVICES_UNSAFE\n'))
        self.assertEqual(json.loads(receipt.read_bytes())['phase'], 'refused')
        self.assertFalse(pending.exists())
        self.assertEqual(host.effects, [])

    def assert_update_diagnostic(self, mode, stderr, *, after_update=None):
        host, receipt, pending = self.model_real_guard(empty_indexes=True)
        proof = self.offered()
        intent = []

        def capture_intent():
            intent.append(pending.read_bytes())
            if after_update is not None:
                after_update(host)

        host.update_mode = mode
        host.after_update = capture_intent
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', stderr))
        self.assertEqual(host.effects, ['enter', 'update'])
        self.assertEqual(host.apt_count, 0)
        self.assertFalse((self.vault / TOKEN).exists())
        self.assertEqual(pending.read_bytes(), receipt.read_bytes())
        if intent:
            self.assertEqual(pending.read_bytes(), intent[0])
        self.assertEqual(json.loads(pending.read_bytes())['phase'], 'preparing')
        self.machine = MACHINE
        self.assertEqual(self.wire('preflight'), (75, '', ''))

    def test_failed_strict_signed_update_keeps_pending_with_index_diagnostic(self):
        self.assert_update_diagnostic('bad-signature', 'DIRECT_UNCERTAIN_PACKAGE_INDEXES_UNVERIFIED\n')

    def test_failed_signed_index_hash_join_keeps_pending_with_index_diagnostic(self):
        self.assert_update_diagnostic('tampered', 'DIRECT_UNCERTAIN_PACKAGE_INDEXES_UNVERIFIED\n')

    def test_observed_unsafe_service_after_update_keeps_pending_with_service_diagnostic(self):
        self.assert_update_diagnostic('ok', 'DIRECT_UNCERTAIN_PACKAGE_SERVICES_UNSAFE\n',
                                      after_update=lambda host: setattr(host, 'active', True))

    def test_keyring_change_after_update_keeps_pending(self):
        self.assert_update_diagnostic('ok', '', after_update=lambda host: host.put(KEYRING, 'different keyring bytes'))

    def test_update_timeout_does_not_carry_index_diagnostic(self):
        self.assert_update_diagnostic('timeout', '')

    def test_update_child_loss_does_not_carry_index_diagnostic(self):
        def lost_child(_):
            raise ChildProcessError('no status witness')

        self.assert_update_diagnostic('bad-signature', '', after_update=lost_child)

    def test_index_failure_at_deadline_does_not_carry_diagnostic(self):
        clock = SimpleNamespace(monotonic=time.monotonic)
        self.h['time'] = clock
        fetched = g._fetched_indexes

        def expire_after_check(*args):
            try:
                fetched(*args)
            except g.Refusal:
                end = self.h['DEADLINE']
                clock.monotonic = lambda: end
                raise

        with patch.object(g, '_fetched_indexes', side_effect=expire_after_check):
            self.assert_update_diagnostic('tampered', '')

    def test_observed_index_failure_is_not_attributed_after_machine_drift(self):
        self.assert_update_diagnostic('bad-signature', '', after_update=lambda _: setattr(self, 'machine', '3' * 32))

    def test_unsafe_service_with_lost_containment_cleanup_has_no_diagnostic(self):
        host, receipt, pending = self.model_real_guard()
        proof = self.offered()
        reload = host._reload

        def activate_after_reload():
            result = reload()
            host.active = True
            return result

        with patch.object(host, '_reload', side_effect=activate_after_reload), patch.object(
                g, '_remove_owned', side_effect=OSError('cleanup unconfirmed')) as cleanup:
            self.assertEqual(self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof), (75, '', ''))
            cleanup.assert_called_once()
        self.assertEqual(host.effects, ['enter', 'reload'])
        self.assertEqual(host.apt_count, 0)
        self.assertEqual(pending.read_bytes(), receipt.read_bytes())
        self.assertEqual(json.loads(pending.read_bytes())['phase'], 'preparing')
        self.assertTrue(host.p(POLICY).is_file())

    def prepare_with_real_guard(self, host, *, preflight_calls, empty_indexes=False):
        if empty_indexes:
            host.p('/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease').unlink()
        self.system = host.p(SYSTEM)
        pending = self.vault / self.h['PACKAGE_PENDING']
        receipt = self.vault / f'packages-{TOKEN}.json'
        configured_limit = self.h['PACKAGE_MAX_COMMANDS']
        runners, writes, probes = [], [], []
        runner_type = self.h['PackageRunner']
        deadline = self.h['DEADLINE']

        def new_runner():
            run = runner_type()
            runners.append(run)
            return run

        def child_status(argv, end, maximum, *, may_write):
            self.assertEqual(maximum, 256 * 1024)
            selected = deadline if len(runners) == 1 else deadline - 115 + 210
            self.assertEqual(self.h['DEADLINE'], selected)
            self.assertTrue(time.monotonic() < end <= selected)
            apt = argv[7:9] == ('/usr/bin/apt-get', '-y')
            update = argv[7:] == APT_UPDATE[7:]
            self.assertEqual(may_write, apt or update or argv == CTL + ('daemon-reload',))
            if may_write:
                self.assertTrue(runners[-1].entered)
                if not writes:
                    intent = json.loads(pending.read_bytes())
                    self.assertEqual(intent, json.loads(receipt.read_bytes()))
                    self.assertEqual((intent['phase'], intent['packagePreparation']), ('preparing', proof))
                    with self.h['directory'](str(self.system)) as fd, self.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    # The first writer is the refresh on an empty cache, or the
                    # reload with containment already in place otherwise.
                    host.effects.append('enter')
                writes.append('update' if update else 'apt' if apt else 'reload')
            if apt or update:
                self.assertTrue(77 < end - time.monotonic() <= 78)
            if apt:
                self.assertEqual(runners[-1].update_settled, empty_indexes)
            return host.run(argv, 78 if apt or update else 6)

        def child_run(argv, **_):
            self.assertEqual(argv[:3], ('/usr/bin/dpkg-query', '-W', '-f=${db:Status-Abbrev}'))
            self.assertEqual(len(argv), 4)
            name = argv[3]
            probes.append(name)
            return (subprocess.CompletedProcess(argv, 0, b'ii ', b'') if name in host.installed else
                    subprocess.CompletedProcess(argv, 1, b'', b''))

        required = self.h['REQUIRED_PACKAGES']
        until_missing = required[:next(i for i, n in enumerate(required) if n not in host.installed) + 1]
        self.h.update(SYSTEM=str(self.system), stock_runtime_root=lambda: self.root,
                      PackageRunner=new_runner, command=self.host_command, bounded_status=child_status,
                      C3_PACKAGE_GUARD={'Refusal': g.Refusal, 'observe': g.observe, 'prepare': g.prepare})
        with patch.object(subprocess, 'run', side_effect=child_run), patch.dict(
                vars(g), package_ownership(host.root, host.archive_owners)):
            proof = self.offered()
            self.assertEqual(len(runners), 1)
            self.assertEqual(configured_limit - runners[0].remaining, preflight_calls)
            self.assertEqual(len(host.calls), preflight_calls)
            self.assertEqual(host.effects, [])
            if empty_indexes:
                self.assertFalse(any(argv[0] == '/usr/bin/env' for argv in host.calls))
            result = self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof)
        # The initial missing-package probes are outside both counters.
        self.assertEqual(probes, list(until_missing) * 2)
        self.assertEqual(len(runners), 2)
        self.assertEqual(writes, (['update'] if empty_indexes else []) + ['reload', 'apt', 'reload', 'reload'])
        if empty_indexes:
            prepared = host.calls[preflight_calls:]
            first_apt = next(i for i, argv in enumerate(prepared) if argv[0] == '/usr/bin/env')
            self.assertEqual(first_apt, 2 * preflight_calls)  # Two re-observations, neither with a solver.
            apt_calls = [a[7:] for a in prepared if a[0] == '/usr/bin/env']
            self.assertEqual(apt_calls[:2], [APT_UPDATE[7:], ('/usr/bin/apt-get', '-s', 'check')])
            self.assertEqual(sum(a[0] == '/usr/bin/apt-cache' for a in apt_calls), 2 * len(host.candidates))
        self.assertEqual(host.effects, ['enter', *writes])
        self.assertEqual(host.apt_count, 1)
        self.assertFalse(runners[0].entered or runners[0].failed or runners[0].update_dispatched)
        run = runners[1]
        self.assertTrue(run.entered and run.apt_dispatched and run.apt_settled)
        self.assertEqual((run.update_dispatched, run.update_settled), (empty_indexes, empty_indexes))
        self.assertEqual(configured_limit - run.remaining, len(host.calls) - preflight_calls)
        return result, run, receipt, pending

    def assert_real_guard_ready(self, host, attempt, *, prepare_calls):
        result, run, receipt, pending = attempt
        self.assertEqual((result, self.h['PACKAGE_MAX_COMMANDS'] - run.remaining, run.failed),
                         ((0, f'{{"ok":true,"backupId":"{TOKEN}","packagesReady":true}}\n', ''), prepare_calls, False))
        self.assertEqual(json.loads(receipt.read_bytes())['phase'], 'ready')
        self.assertFalse(pending.exists())
        self.assertFalse((self.vault / TOKEN).exists())
        self.assertFalse(os.path.lexists(host.p(POLICY)))
        self.assertFalse(any(self.system.glob('*.service')))
        self.assertFalse(any(self.root.rglob('.relay-package-*')))

    def test_real_guard_historical_clean_plan_fits_runner_budget(self):
        self.assert_historical_clean_plan(empty_indexes=False, preflight_calls=46, prepare_calls=258)

    def test_real_guard_empty_indexes_historical_plan_fits_runner_budget(self):
        self.assert_historical_clean_plan(empty_indexes=True, preflight_calls=32, prepare_calls=277)

    def assert_historical_clean_plan(self, *, empty_indexes, preflight_calls, prepare_calls):
        host = Host(self, self.root)
        host.stock_solver()
        self.assertEqual(len(host.candidates), 12)
        survivor = host.link(SYSTEM + '/multi-user.target.wants/operator.service', '/opt/operator.service')
        expected = host.installed | {n: (v, a) for n, (v, a, _) in host.candidates.items()}
        attempt = self.prepare_with_real_guard(host, preflight_calls=preflight_calls, empty_indexes=empty_indexes)
        self.assert_real_guard_ready(host, attempt, prepare_calls=prepare_calls)
        self.assertEqual(host.installed, expected)
        self.assertEqual(survivor.readlink(), Path('/opt/operator.service'))
        for name in ('strongswan-starter.service', 'nftables.service'):
            self.assertFalse(any(self.system.glob(f'*.wants/{name}')))
        self.assertFalse(any(host.p('/etc').glob('rc?.d/S??xl2tpd')))
        for i in '0123456':
            self.assertEqual(host.p(f'/etc/rc{i}.d/K01xl2tpd').readlink(), Path('../init.d/xl2tpd'))

    def max_plan_host(self):
        host = Host(self, self.root)
        version, arch, depends = host.candidates.pop('strongswan')
        host._install()  # Seed the already-installed, disabled service owners.
        for link in host.p(SYSTEM).glob('*.wants/*.service'):
            link.unlink()
        for link in host.p('/etc').glob('rc?.d/S??xl2tpd'):
            link.rename(link.with_name('K' + link.name[1:]))
        host.p(LATE + '/xl2tpd.service').write_bytes((HERE / 'helpers/trixie-xl2tpd-generated.fixture').read_bytes())
        host.link(LATE + '/l2tpd.service', 'xl2tpd.service')
        for name in ('ipsec', 'strongswan-starter', 'nftables'):
            host.put(f'/etc/init.d/{name}', '#!/bin/sh\nexit 0\n', 0o755)
        # One missing metapackage with 47 hard dependencies. The four SysV
        # scripts are present in every layout, so all seven query their md5sums.
        deps = [f'libfixture{i:02}' for i in range(1, g.MAX_PLAN)]
        host.candidates = {'strongswan': (version, arch, ', '.join([depends, *deps])),
                           **{name: ('1.0-1', 'amd64', 'libc6') for name in deps}}
        self.assertEqual(len(host.candidates), 48)
        return host

    def test_real_guard_max_plan_fits_exact_runner_budget(self):
        host = self.max_plan_host()
        self.assertEqual(self.h['PACKAGE_MAX_COMMANDS'], 391)
        attempt = self.prepare_with_real_guard(host, preflight_calls=86)
        self.assert_real_guard_ready(host, attempt, prepare_calls=391)
        self.assertEqual(attempt[1].remaining, 0)

    def test_real_guard_exhausted_budget_retains_pending(self):
        self.assert_real_guard_one_short(empty_indexes=False, preflight_calls=86, prepare_calls=391)

    def test_real_guard_empty_indexes_max_plan_fits_runner_budget(self):
        host = self.max_plan_host()
        attempt = self.prepare_with_real_guard(host, preflight_calls=36, empty_indexes=True)
        self.assert_real_guard_ready(host, attempt, prepare_calls=378)
        self.assertEqual(attempt[1].remaining, 13)

    def test_real_guard_empty_indexes_one_short_retains_pending(self):
        self.assert_real_guard_one_short(empty_indexes=True, preflight_calls=36, prepare_calls=378)

    def assert_real_guard_one_short(self, *, empty_indexes, preflight_calls, prepare_calls):
        host = self.max_plan_host()
        self.h['PACKAGE_MAX_COMMANDS'] = prepare_calls - 1  # Deny only the final readback of this path.
        result, run, receipt, pending = self.prepare_with_real_guard(host, preflight_calls=preflight_calls,
                                                                   empty_indexes=empty_indexes)
        self.assertEqual((result, run.remaining, run.failed), ((75, '', ''), 0, True))
        self.assertEqual(len(host.calls) - preflight_calls, prepare_calls - 1)
        self.assertEqual(host.calls[-1], ('/usr/bin/dpkg', '--audit'))
        self.assertEqual(receipt.read_bytes(), pending.read_bytes())
        intent = json.loads(pending.read_bytes())
        self.assertEqual(intent['phase'], 'preparing')
        self.assertTrue(host.p(POLICY).is_file())
        calls = len(host.calls)
        # No replay or additional admitted children even though APT settled.
        self.assertEqual(self.wire('preflight'), (75, '', ''))
        self.assertEqual(self.wire('prepare-packages', backupId=TOKEN,
                                   packagePreparation=intent['packagePreparation']), (75, '', ''))
        with self.assertRaises(subprocess.TimeoutExpired):
            run(('/usr/bin/dpkg', '--audit'), 6)
        self.assertEqual(len(host.calls), calls)

    def test_bounded_runner_joins_local_synthetic_child_and_caps_native_pipes(self):
        self.popen_patch.stop()
        cmd = (sys.executable, '-I', '-B', '-c', 'import sys; print("out"); print("err", file=sys.stderr); sys.exit(7)')
        result = self.h['stock_runtime_command'](*cmd)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (7, 'out\n', 'err\n'))
        for fd in (1, 2):
            with self.subTest(fd=fd), self.assertRaises(subprocess.TimeoutExpired):
                self.h['stock_runtime_command'](sys.executable, '-I', '-B', '-c',
                                               f'import os; os.write({fd}, b"x" * 300000)')
        with self.assertRaises(subprocess.TimeoutExpired):
            self.h['bounded_status']((sys.executable, '-I', '-B', '-c',
                                      'import os,time; os.close(1); os.close(2); time.sleep(5)'),
                                     time.monotonic() + 0.1, 4096)

    def test_request_rejects_extra_keys_duplicate_keys_and_non_identifier(self):
        proof = self.offered()
        bad = (
            self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof, argv=['not allowed']),
            self.wire('prepare-packages', backupId='../outside', packagePreparation=proof),
            self.raw_wire(f'{{"action":"prepare-packages","machineId":"{MACHINE}","backupId":"{TOKEN}",'
                          f'"backupId":"{TOKEN}","packagePreparation":"{proof}"}}'.encode()),
        )
        self.assertTrue(all(status == 70 and not stdout for status, stdout, _ in bad))
        self.assertFalse(self.effects)
        self.assertFalse(self.vault.exists())


if __name__ == '__main__':
    unittest.main()
