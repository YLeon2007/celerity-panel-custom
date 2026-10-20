"""Local filesystem/flock and runner tests; SSH/systemd/UID are fixtures, not live."""
import json
import os
import pathlib
import shlex
import tempfile
import unittest
from unittest.mock import patch

import test_isolation as fixtures
m = fixtures.m


class DispatchClosureTests(unittest.TestCase):
    def test_any_closed_or_unfinished_marker_refuses_actual_dispatch_before_effects(self):
        for filename in ('restore-admission.json', 'restore-admission.json.next'):
            for raw in (b'{}', b'incomplete', b''):
                with self.subTest(filename=filename, raw=raw), tempfile.TemporaryDirectory() as root:
                    e = m.Engine(root, fixtures.PlanTests().plan(), fixtures.EngineTests.FixtureHost())
                    fixtures.fixture_hold(e)
                    pathlib.Path(root, filename).write_bytes(raw)
                    values = ['close', 'op', e.plan['nodeId'], 'sha256:' + 'a' * 64,
                              'backup', e.plan['targetProfile'], e.plan['context'], 'attempt', 'gen', 'none', 'close']
                    argv = [v for pair in zip(['--' + k for k in m.NAMES], values) for v in pair]
                    with patch.object(m.subprocess, 'run') as run:
                        with self.assertRaisesRegex(m.Refusal, 'DISPATCH_ADMISSION_CLOSED_RETAINED'):
                            e.dispatch(shlex.join([m.RUNNER, *argv]), b'', 0)
                        run.assert_not_called()
                    self.assertEqual(e.read()['dispatchCount'], 0)
                    self.assertEqual(e.assert_held()['phase'], 'held')


class CloseOperationTests(unittest.TestCase):
    def test_missing_runner_journal_and_failed_marker_fsync_retain_dispatch_block(self):
        for fault in ('missing-journal', 'marker-fsync'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                root = pathlib.Path(root); e = m.Engine(root, fixtures.PlanTests().plan(), fixtures.EngineTests.FixtureHost())
                fixtures.fixture_hold(e); e.host.held_current_runner_head = m.Host().held_current_runner_head
                lock = os.open(root / 'lock', os.O_RDWR | os.O_CREAT, 0o600)
                try:
                    with (patch.object(m.os, 'geteuid', return_value=0),
                          patch.object(m, 'RUNNER_FENCES', str(root / 'absent')),
                          patch.object(m, 'secure_file', side_effect=lambda path: pathlib.Path(path).read_bytes())):
                        if fault == 'marker-fsync':
                            with patch.object(m.os, 'fsync', side_effect=OSError('fixture fsync error')):
                                with self.assertRaises(OSError): e.close_dispatch(lock)
                            self.assertTrue((root / 'restore-admission.json.next').exists())
                        else:
                            with self.assertRaises(FileNotFoundError): e.close_dispatch(lock)
                            self.assertTrue((root / 'restore-admission.json').exists())
                        with self.assertRaises(m.Refusal): e.assert_dispatch_open()
                        with self.assertRaises(m.Refusal): e.restore()
                        self.assertFalse(any(x[0] == 'restore' for x in e.host.events))
                finally:
                    os.close(lock)

    def test_root_and_exact_outer_lock_and_independent_login_are_mandatory(self):
        with tempfile.TemporaryDirectory() as root:
            root = pathlib.Path(root); e = m.Engine(root, fixtures.PlanTests().plan(), fixtures.EngineTests.FixtureHost())
            fixtures.fixture_hold(e)
            lock = os.open(root / 'lock', os.O_RDWR | os.O_CREAT, 0o600)
            foreign = os.open(root / 'foreign', os.O_RDWR | os.O_CREAT, 0o600)
            try:
                with patch.object(m.os, 'geteuid', return_value=1), self.assertRaisesRegex(m.Refusal, 'ROOT_REQUIRED'):
                    e.close_dispatch(lock)
                with patch.object(m.os, 'geteuid', return_value=0), self.assertRaisesRegex(m.Refusal, 'OUTER_LOCK_REQUIRED'):
                    e.close_dispatch(foreign)
                real_guard = e.host.guard_check
                def guard(ident, session=None):
                    if session is not None: raise m.Refusal('FRESH_INDEPENDENT_SESSION_REQUIRED')
                    return real_guard(ident)
                with patch.object(m.os, 'geteuid', return_value=0), patch.object(e.host, 'guard_check', side_effect=guard), \
                     self.assertRaisesRegex(m.Refusal, 'FRESH_INDEPENDENT_SESSION_REQUIRED'):
                    e.close_dispatch(lock)
                self.assertFalse((root / 'restore-admission.json').exists())
            finally:
                os.close(lock); os.close(foreign)

    def test_actual_runner_head_closure_is_sticky_and_holds_both_mutexes(self):
        self.assertTrue(hasattr(m.Engine, 'close_dispatch'), 'root close-dispatch path missing')
        source = pathlib.Path(__file__).resolve().parents[2] / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
        with tempfile.TemporaryDirectory() as root:
            root = pathlib.Path(root); node = root / 'node'; state = root / 'state'; state.mkdir()
            boot = node / 'proc/sys/kernel/random/boot_id'; boot.parent.mkdir(parents=True)
            p = fixtures.PlanTests().plan(); boot.write_text(p['bootId'])
            (node / 'var/lib').mkdir(parents=True)
            e = m.Engine(state, p, fixtures.EngineTests.FixtureHost()); fixtures.fixture_hold(e)
            e.host.held_current_runner_head = m.Host().held_current_runner_head
            values = ['close', 'op', p['nodeId'], 'sha256:' + 'a' * 64, 'backup', p['targetProfile'],
                      p['context'], 'attempt', 'gen', 'none', 'close']
            argv = [v for pair in zip(['--' + k for k in m.NAMES], values) for v in pair]
            result = m.subprocess.run(['unshare', '--user', '--map-root-user', '/bin/bash', str(source), *argv],
                env={**m.CLEAN_ENV, 'CELERITY_TOPOLOGY_ROOT': str(node)}, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            fence = node / 'var/lib/celerity/topology/fences'
            lock = os.open(state / 'lock', os.O_RDWR | os.O_CREAT, 0o600)
            try:
                m.fcntl.flock(lock, m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
                # UID and systemd/recovery adapter are simulated; files/flocks and runner are real.
                with patch.object(m, 'RUNNER_FENCES', str(fence)), patch.object(m.os, 'geteuid', return_value=0), \
                     patch.object(m, 'secure_file', side_effect=lambda path: pathlib.Path(path).read_bytes()):
                    output = e.close_dispatch(lock)
                    self.assertEqual(output['nodeEffects'], 'drained')
                    marker = json.loads((state / 'restore-admission.json').read_bytes())
                    self.assertEqual(marker, {'version': 1, 'planHash': e.plan_hash,
                        'maintenanceId': p['maintenanceId'], 'nodeId': p['nodeId'], 'bootId': p['bootId'], 'state': 'closed'})
                    with self.assertRaisesRegex(m.Refusal, 'DISPATCH_ADMISSION_CLOSED_RETAINED'):
                        e.dispatch(shlex.join([m.RUNNER, *argv]), b'', lock)
                    reopened = m.Engine(state, p, e.host)
                    with self.assertRaises(m.Refusal): reopened.assert_dispatch_open()
                    self.assertEqual((state / 'restore-admission.json').stat().st_mode & 0o777, 0o600)
                    self.assertEqual(e.assert_held()['phase'], 'held')
                    journal = fence / p['targetProfile'] / 'journal.json'
                    marker_raw = (state / 'restore-admission.json').read_bytes()
                    # An independently opened fd cannot acquire the held runner
                    # mutex; closure must preserve the marker on that uncertainty.
                    runner_lock = os.open(fence / p['targetProfile'] / 'lock', os.O_RDWR)
                    try:
                        m.fcntl.flock(runner_lock, m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
                        with self.assertRaises(BlockingIOError): e.close_dispatch(lock)
                    finally:
                        os.close(runner_lock)
                    self.assertEqual((state / 'restore-admission.json').read_bytes(), marker_raw)
                    good = json.loads(journal.read_bytes())
                    for fault in ('running', 'missing-quiescence', 'old-boot', 'old-unknown', 'unfinished'):
                        actual = json.loads(json.dumps(good))
                        if fault == 'running': actual['generations']['gen']['commands']['close']['state'] = 'running'
                        elif fault == 'missing-quiescence': del actual['generations']['gen']['commands']['close']['receipt']['systemdJob']
                        elif fault == 'old-boot': actual['bootId'] = 'old'
                        elif fault == 'old-unknown': actual['generations']['older'] = {'phase': 'unknown'}
                        journal.write_text(json.dumps(actual))
                        unfinished = journal.with_name('journal.next')
                        if fault == 'unfinished': unfinished.write_text('{}')
                        with self.subTest(fault=fault), self.assertRaises(m.Refusal): e.close_dispatch(lock)
                        if unfinished.exists(): unfinished.unlink()
                        self.assertEqual((state / 'restore-admission.json').read_bytes(), marker_raw)
                    actual = good
                    actual['generations']['successor'] = {**actual['generations']['gen'], 'phase': 'verified'}
                    actual['head'] = 'successor'; journal.write_text(json.dumps(actual))
                    with self.assertRaisesRegex(m.Refusal, 'RUNNER_TERMINAL_UNPROVEN'):
                        e.close_dispatch(lock)
                    self.assertEqual(json.loads((state / 'restore-admission.json').read_bytes()), marker)
            finally:
                os.close(lock)


if __name__ == '__main__':
    unittest.main()
