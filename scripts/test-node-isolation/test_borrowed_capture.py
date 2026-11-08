"""Actual original Engine/apply/flock/capture; root and login authority modeled."""
from contextlib import contextmanager
import copy
import fcntl
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import coordinated_capture as capture
import test_node_originals as originals
import test_v2_abort_return as returning

n, isolation = originals.n, returning.m


@contextmanager
def original_owner():
    with originals.DualFixture() as fixture:
        root = fixture.path(n.STATE)
        (root/'masks').mkdir()
        (root/'fences').mkdir()
        plan = returning.plan()
        host = returning.Host(plan)
        host.physical = lambda: {key:plan[key] for key in ('machineId','bootId','sshHostKeySha256')}
        root_os = SimpleNamespace(**vars(os))
        root_os.geteuid = lambda: 0
        with returning.accepted_files(), patch.object(isolation, 'os', root_os), \
             patch.object(isolation, 'MASK_ROOT', str(root/'masks')), \
             patch.object(isolation, 'RUNNER_FENCES', str(root/'fences')):
            engine = isolation.Engine(root, plan, host)
            with fixture.fs.lock(n.OUTER_LOCK) as descriptor:
                engine._outer_lock_fd = descriptor
                engine.apply(fixture.guard)
                before = host.operator_session()
                host.operator_session = lambda: {'pid':before['pid']+1, 'start':str(int(before['start'])+1)}
                engine.confirm_access(lock_fd=descriptor)
                fixture.put(isolation.INVENTORY, n.canonical(returning.inventory()))
                helper = (Path(__file__).parent/'isolation.py').read_bytes()
                fixture.put(n.HELPER, helper)
                accepted = {**fixture.accepted, **n.identity(engine), 'isolationSha256':n.sha(helper),
                            'profiles':{'xray-main':copy.deepcopy(fixture.accepted['profiles']['xray-main'])}}
                fixture.put(n.ACCEPTED, n.canonical(accepted))
                for profile in ('xray-main','xray-bridge'):
                    fixture.path(n.runner_lock(profile)).unlink(missing_ok=True)
                fixture.engine = engine
                fixture.writer = n.NodeOriginals(engine, isolation, fixture=fixture.fixture)
                yield fixture, descriptor


class BorrowedCaptureTests(unittest.TestCase):
    def assert_held(self, fixture, descriptor):
        os.fstat(descriptor)
        with fixture.fs.opened(n.OUTER_LOCK) as competitor:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_normal_capture_and_scope_disposal_keep_original_ofd(self):
        with original_owner() as (fixture, descriptor):
            original_lock = fixture.writer.fs.lock
            with capture.CaptureHold(fixture.writer, n, outer_lock_fd=descriptor) as held:
                self.assertEqual(held.locks[n.OUTER_LOCK], descriptor)
                held.capture()
                self.assert_held(fixture, descriptor)
                with self.assertRaisesRegex(capture.Refusal, 'CAPTURE_REPLAY_FORBIDDEN'):
                    held.capture()
            self.assertEqual(fixture.writer.fs.lock, original_lock)
            self.assert_held(fixture, descriptor)
            self.assertTrue(fixture.path(n.BUNDLE).is_file())
            with self.assertRaisesRegex(isolation.Refusal, 'EARLY_RETURN_DOWNSTREAM_UNKNOWN_RETAINED'):
                fixture.engine.abort_return(descriptor)
            self.assertTrue(fixture.path(n.BUNDLE).is_file())

    def test_scope_exception_does_not_close_or_unlock_borrowed_fd(self):
        with original_owner() as (fixture, descriptor):
            failure = RuntimeError('scope failure')
            with self.assertRaises(RuntimeError) as caught:
                with capture.CaptureHold(fixture.writer, n, outer_lock_fd=descriptor):
                    raise failure
            self.assertIs(caught.exception, failure)
            self.assert_held(fixture, descriptor)
            self.assertEqual(fixture.engine.abort_return(descriptor)['returnState'], 'OLD')

    def test_failed_capture_partial_store_is_retained_without_early_old(self):
        with original_owner() as (fixture, descriptor):
            fixture.put(n.profile_paths('xray-main')[0], b'{"inbounds":[],"drift":true}')
            with capture.CaptureHold(fixture.writer, n, outer_lock_fd=descriptor) as held:
                with self.assertRaisesRegex(n.Refusal, 'ORIGINAL_PIN_MISMATCH_RETAINED'):
                    held.capture()
                self.assertFalse(held.active)
            self.assert_held(fixture, descriptor)
            self.assertTrue(fixture.path(n.STORE).is_dir())
            self.assertFalse(fixture.path(n.BUNDLE).exists())
            with self.assertRaisesRegex(isolation.Refusal, 'EARLY_RETURN_DOWNSTREAM_UNKNOWN_RETAINED'):
                fixture.engine.abort_return(descriptor)
            self.assertTrue(fixture.path(n.STORE).is_dir())

    def test_setup_guard_failure_keeps_fd_and_prepublication_return(self):
        with original_owner() as (fixture, descriptor):
            fixture.engine.host.alive = False
            with self.assertRaisesRegex(isolation.Refusal, 'RECOVERY_GUARD_LOST'):
                with capture.CaptureHold(fixture.writer, n, outer_lock_fd=descriptor):
                    self.fail('lost guard admitted')
            self.assert_held(fixture, descriptor)
            self.assertFalse(fixture.path(n.STORE).exists())
            fixture.engine.host.alive = True
            self.assertEqual(fixture.engine.abort_return(descriptor)['returnState'], 'OLD')

    def test_malformed_foreign_and_separate_same_inode_fd_cannot_publish(self):
        with original_owner() as (fixture, descriptor):
            foreign = os.open(fixture.root/'foreign-lock', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                fcntl.flock(foreign, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with fixture.fs.opened(n.OUTER_LOCK) as separate:
                    for invalid in (True, 'fd', -1, foreign, separate):
                        with self.subTest(descriptor=invalid):
                            with self.assertRaisesRegex(capture.Refusal, 'CAPTURE_ORIGINAL_APPLY_OWNER_REQUIRED'):
                                with capture.CaptureHold(fixture.writer, n, outer_lock_fd=invalid):
                                    self.fail('foreign descriptor admitted')
                            os.fstat(foreign)
                            self.assert_held(fixture, descriptor)
                            self.assertFalse(fixture.path(n.STORE).exists())
            finally:
                os.close(foreign)

    def test_unlocked_original_fd_is_not_reacquired(self):
        with original_owner() as (fixture, descriptor):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            with self.assertRaisesRegex(isolation.Refusal, 'EARLY_RETURN_OUTER_LOCK_LOST_RETAINED'):
                with capture.CaptureHold(fixture.writer, n, outer_lock_fd=descriptor):
                    self.fail('unlocked descriptor admitted')
            with fixture.fs.opened(n.OUTER_LOCK) as competitor:
                fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(competitor, fcntl.LOCK_UN)
            self.assertFalse(fixture.path(n.STORE).exists())

    def test_replaced_outer_path_refuses_without_closing_original(self):
        with self.assertRaisesRegex(n.Refusal, 'LOCK_REPLACED_RETAINED'):
            with original_owner() as (fixture, descriptor):
                fixture.path(n.OUTER_LOCK).rename(fixture.root/'original-lock')
                fixture.put(n.OUTER_LOCK, b'')
                with self.assertRaisesRegex(isolation.Refusal, 'EARLY_RETURN_OUTER_LOCK_LOST_RETAINED'):
                    with capture.CaptureHold(fixture.writer, n, outer_lock_fd=descriptor):
                        self.fail('replacement admitted')
                os.fstat(descriptor)
                self.assertFalse(fixture.path(n.STORE).exists())

    def test_new_engine_cannot_adopt_original_owner(self):
        with original_owner() as (fixture, descriptor):
            original = fixture.writer.engine
            adopted = isolation.Engine(original.directory, original.plan, original.host)
            adopted._outer_lock_fd = descriptor
            fixture.writer.engine = adopted
            with self.assertRaisesRegex(capture.Refusal, 'CAPTURE_ORIGINAL_APPLY_OWNER_REQUIRED'):
                with capture.CaptureHold(fixture.writer, n, outer_lock_fd=descriptor):
                    self.fail('new engine admitted')
            fixture.writer.engine = original
            self.assert_held(fixture, descriptor)
            self.assertFalse(fixture.path(n.STORE).exists())


if __name__ == '__main__':
    unittest.main()
