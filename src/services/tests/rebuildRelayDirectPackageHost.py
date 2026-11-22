"""Fixture-only tests: python3 -B src/services/tests/rebuildRelayDirectPackageHost.py."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Any
from unittest.mock import patch

from test_rebuild_relay_packages import HERE, Host, LATE, POLICY, SYSTEM, g


HOST = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
MACHINE = '1' * 32
TOKEN = '2' * 32
BOOT = '12345678-1234-1234-1234-123456789abc'
CTL = ('/usr/bin/systemctl', '--system', '--no-pager', '--no-ask-password', '--full')
APT = ('/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL=C',
       'DEBIAN_FRONTEND=noninteractive', 'UCF_FORCE_CONFFOLD=1', f'APT_CONFIG=/proc/{os.getpid()}/fd/7',
       '/usr/bin/apt-get')
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

    def test_observer_cannot_dispatch_and_budget_is_shared(self):
        calls = []
        self.h.update(bounded_status=lambda *args, **kwargs: (calls.append(args[0]) or 0, b'', b''),
                      PACKAGE_MAX_COMMANDS=2)
        guard = self.h['C3_PACKAGE_GUARD']

        def observe(root, run):
            run(APT + ('-s', 'check'), 6)
            return self.plan

        def mutate(root, run):
            run(CTL + ('daemon-reload',), 12)
            self.fail('observer could launch a manager writer')

        guard['observe'] = mutate
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

    def prepare_with_real_guard(self, host, *, preflight_calls):
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
            self.assertTrue(time.monotonic() < end <= deadline)
            apt = argv[7:9] == ('/usr/bin/apt-get', '-y')
            self.assertEqual(may_write, apt or argv == CTL + ('daemon-reload',))
            if may_write:
                self.assertTrue(runners[-1].entered)
                if not writes:
                    intent = json.loads(pending.read_bytes())
                    self.assertEqual(intent, json.loads(receipt.read_bytes()))
                    self.assertEqual((intent['phase'], intent['packagePreparation']), ('preparing', proof))
                    with self.h['directory'](str(self.system)) as fd, self.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    # The actual guard has already created its owned artifacts.
                    # Record the verified grant for the command model's ordering assertions.
                    host.effects.append('enter')
                writes.append('apt' if apt else 'reload')
            if apt:
                self.assertTrue(77 < end - time.monotonic() <= 78)
            return host.run(argv, 78 if apt else 6)

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
        with patch.object(subprocess, 'run', side_effect=child_run), patch.object(
                g, '_owner', side_effect=lambda st: (st.st_uid, st.st_gid) == (os.getuid(), os.getgid())):
            proof = self.offered()
            self.assertEqual(len(runners), 1)
            self.assertEqual(configured_limit - runners[0].remaining, preflight_calls)
            self.assertEqual(len(host.calls), preflight_calls)
            self.assertEqual(host.effects, [])
            result = self.wire('prepare-packages', backupId=TOKEN, packagePreparation=proof)
        # The initial missing-package probes are outside both counters.
        self.assertEqual(probes, list(until_missing) * 2)
        self.assertEqual(len(runners), 2)
        self.assertEqual(writes, ['reload', 'apt', 'reload', 'reload'])
        self.assertEqual(host.effects, ['enter', *writes])
        self.assertEqual(host.apt_count, 1)
        self.assertFalse(runners[0].failed)
        run = runners[1]
        self.assertTrue(run.entered and run.apt_dispatched and run.apt_settled)
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
        host = Host(self, self.root)
        host.stock_solver()
        self.assertEqual(len(host.candidates), 12)
        survivor = host.link(SYSTEM + '/multi-user.target.wants/operator.service', '/opt/operator.service')
        expected = host.installed | {n: (v, a) for n, (v, a, _) in host.candidates.items()}
        self.assert_real_guard_ready(host, self.prepare_with_real_guard(host, preflight_calls=46), prepare_calls=258)
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
        host = self.max_plan_host()
        self.h['PACKAGE_MAX_COMMANDS'] -= 1  # Deny the very last readback in the same full path.
        result, run, receipt, pending = self.prepare_with_real_guard(host, preflight_calls=86)
        self.assertEqual((result, run.remaining, run.failed), ((75, '', ''), 0, True))
        self.assertEqual(len(host.calls) - 86, 390)
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
