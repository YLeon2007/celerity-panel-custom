"""Actual engines/files/journals; UID/SSH/guard/systemd explicitly SIMULATED."""
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

import test_isolation as ti
from test_node_originals import Fixture, n
m = ti.m
RECOVERY = {'pid': 99123, 'start': '111'}
OPERATOR = {'pid': 99124, 'start': '112'}


def assemble(f):
    plan = ti.PlanTests().plan()
    plan.update(f.plan)
    host = ti.EngineTests.FixtureHost()
    host.physical = f.engine.host.physical
    host.held_current_runner_head = m.Host().held_current_runner_head
    f.engine = m.Engine(f.path(n.STATE), plan, host)
    ti.fixture_hold(f.engine)
    f.plan = plan
    f.put(n.HELPER, (Path(__file__).parent / 'isolation.py').read_bytes())
    f.accepted.update(n.identity(f.engine))
    f.accepted['isolationSha256'] = n.sha(f.path(n.HELPER).read_bytes())
    f.put(n.ACCEPTED, n.canonical(f.accepted))
    host.session = OPERATOR.copy()
    f.guard_checks = []
    def guard_check(guard, session=None):
        f.guard_checks.append(session)
        if session == RECOVERY:
            raise m.Refusal('FRESH_INDEPENDENT_SESSION_REQUIRED')
        return {'session': RECOVERY}
    host.guard_check = guard_check
    f.writer = n.NodeOriginals(f.engine, m, fixture=f.fixture)
    return host


class ReviewRegressionTests(unittest.TestCase):
    def test_recovery_session_cannot_capture_or_publish_originals(self):
        with Fixture() as f:
            host = assemble(f)
            host.session = RECOVERY.copy()
            with self.assertRaisesRegex(m.Refusal, 'FRESH_INDEPENDENT_SESSION_REQUIRED'):
                f.writer.capture()
            self.assertFalse(f.path(n.BUNDLE).exists())
            self.assertEqual(f.system.events, [])

    def test_recovery_session_cannot_restore_after_independent_capture_and_close(self):
        with Fixture() as f:
            host = assemble(f)
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            host.session = RECOVERY.copy()
            before = f.path(f.config).read_bytes()
            with self.assertRaisesRegex(m.Refusal, 'FRESH_INDEPENDENT_SESSION_REQUIRED'):
                n.NodeOriginals(f.engine, m, fixture=f.fixture).restore()
            self.assertEqual(f.path(f.config).read_bytes(), before)
            self.assertFalse(f.path(n.RESTORE_STATE).exists())
            self.assertEqual(f.system.events, [])
            self.assertEqual(f.fs.read_json(n.ADMISSION)['state'], 'closed')

    def test_operator_session_loss_between_prepare_and_effect_retains_scope(self):
        with Fixture() as f:
            host = assemble(f)
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            writer = n.NodeOriginals(f.engine, m, fixture=f.fixture)
            with writer.restoration_hold() as held:
                host.session = RECOVERY.copy()
                with self.assertRaisesRegex(m.Refusal, 'FRESH_INDEPENDENT_SESSION_REQUIRED'):
                    held.restore()
                self.assertEqual(f.system.events, [])
                self.assertFalse(f.path(n.RESTORE_STATE).exists())
                host.session = OPERATOR.copy()
                with self.assertRaises(n.Refusal):
                    held.restore()  # Session repair cannot un-revoke a failed scope.

    def test_close_retry_requires_successful_file_and_parent_fsync_after_rename_failure(self):
        with Fixture() as f:
            assemble(f)
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            f.path(n.ADMISSION).unlink()  # Only the synthetic fixture marker.
            lock = os.open(f.path(n.OUTER_LOCK), os.O_RDWR)
            real_fsync = os.fsync
            calls = []
            def fail_directory(fd):
                kind = 'directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file'
                calls.append(kind)
                if kind == 'directory':
                    raise OSError('fixture post-rename parent fsync failure')
                return real_fsync(fd)
            try:
                with (patch.object(m.os, 'geteuid', return_value=0),
                      patch.object(m, 'RUNNER_FENCES', str(f.path('/var/lib/celerity/topology/fences'))),
                      patch.object(m, 'secure_file', side_effect=lambda path: Path(path).read_bytes())):
                    with patch.object(m.os, 'fsync', side_effect=fail_directory):
                        with self.assertRaises(OSError):
                            f.engine.close_dispatch(lock)
                    marker = f.path(n.ADMISSION).read_bytes()
                    self.assertFalse(f.path(n.ADMISSION + '.next').exists())
                    calls.clear()
                    with patch.object(m.os, 'fsync', side_effect=fail_directory):
                        with self.assertRaises(OSError):
                            f.engine.close_dispatch(lock)
                    self.assertIn('file', calls)
                    self.assertIn('directory', calls)
                    calls.clear()
                    def successful(fd):
                        calls.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
                        return real_fsync(fd)
                    with patch.object(m.os, 'fsync', side_effect=successful):
                        result = f.engine.close_dispatch(lock)
                    self.assertEqual(result['nodeEffects'], 'drained')
                    self.assertIn('file', calls)
                    self.assertIn('directory', calls)
                    self.assertEqual(f.path(n.ADMISSION).read_bytes(), marker)
                    with self.assertRaises(m.Refusal):
                        f.engine.assert_dispatch_open()
            finally:
                os.close(lock)


if __name__ == '__main__':
    unittest.main()
