"""Offline MAIN session: real file CAS/flock, modeled systemd/journal/runtime."""
import json
import os
import pathlib
import select
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from rebuildTransitMainWindowHost import System, profile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from rebuildTransitMainSession import DIRECT_LOCK, HostMainSession, WindowError


# Same directory-flock syscall and flags as DIRECT, in a fresh process that
# does not inherit the session's fd. No system binaries or sockets involved.
COMPETITOR = '''
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(23)
print('held', flush=True)
if sys.argv[2] == 'hold':
    assert sys.stdin.read() == ''
'''


def config(route='a', users=()):
    return json.dumps(profile(route, users), indent=2).encode() + b'\n'


class Host(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        self.main = root / 'config.json'
        self.main.write_bytes(config(users=[{'id': 'initial'}]))
        self.main.chmod(0o640)
        self.loaded_main = json.loads(self.main.read_bytes())
        self.lock = root / 'system'
        self.lock.mkdir()
        self.cg = root / 'system.slice'
        self.cg.mkdir()
        self.manager = System(self.cg)
        self.allow_authority = True
        self.allow_runtime = True
        self.runtime_proofs = []
        self.on_authority = lambda: None
        self.on_runtime = lambda phase: None
        self.on_command = lambda command: None
        self.old_dir = self.lock.with_name('retired-system')

    def authority(self):
        self.on_authority()
        return self.allow_authority

    def runtime(self, phase, observation):
        self.runtime_proofs.append(phase)
        self.assertEqual(observation.main.data, self.main.read_bytes())
        self.assertEqual(observation.xray.pid, self.manager.xray_generation + 500)
        self.assertEqual(json.loads(observation.main.data), self.loaded_main)
        self.on_runtime(phase)
        return self.allow_runtime

    def run_model(self, argv, timeout):
        self.on_command(argv[1])
        if argv[1] == 'restart':
            self.assertEqual(argv, ['/usr/bin/systemctl', 'restart', '--job-mode=fail', '--', 'xray.service'])
            self.assertGreater(timeout, 0)
            self.manager.trace.append(tuple(argv))
            self.manager.xray_generation += 1
            self.loaded_main = json.loads(self.main.read_bytes())
            return ''
        if argv[1] == 'start':
            self.assertEqual(argv, ['/usr/bin/systemctl', 'start', '--job-mode=fail', '--', 'cc-agent.service'])
            # The modeled service creates its own cgroup on start.
            self.manager.cg.mkdir()
        if argv[1] == 'stop':
            self.assertEqual(argv, ['/usr/bin/systemctl', 'stop', '--job-mode=fail', '--', 'cc-agent.service'])
        result = self.manager(argv, timeout)
        if argv[1] == 'stop':
            # Stock systemd 257: inactive/dead, PID 0 and cgroup removed.
            self.manager.events.unlink()
            self.manager.cg.rmdir()
        return result

    def session(self):
        return HostMainSession(self.run_model, self.authority, self.runtime, frozenset({'vless-in'}),
                               main=self.main, cgroup_root=self.cg, lock_dir=self.lock,
                               clock=lambda: self.manager.now, sleep=self.manager.sleep)

    def competitor_args(self, path, mode):
        return [sys.executable, '-BI', '-c', COMPETITOR, str(path), mode]

    def competitor(self, *, path=None):
        return subprocess.run(self.competitor_args(path or self.lock, 'probe'), stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=5).returncode

    def effects(self):
        return [argv[1] for argv in self.manager.trace if argv[1] in ('stop', 'restart', 'start')]

    def capture(self, session):
        original = session.read()
        session.stop()
        return session.capture(original, config('b', [{'id': 'stale'}]))

    def assert_sticky(self, session, code, call):
        with self.assertRaises(WindowError) as error:
            call()
        self.assertEqual(error.exception.code, code)
        trace = list(self.manager.trace)
        for retry in (call, session.read, session.stop, session.restart, session.start, session.reconcile):
            with self.assertRaises(WindowError):
                retry()
        self.assertEqual(self.manager.trace, trace)

    def test_unproved_live_baseline_refuses_before_stop(self):
        original = self.main.read_bytes()
        with self.session() as session:
            self.allow_runtime = False
            self.assert_sticky(session, 'REBUILD_MAIN_RUNTIME_UNPROVED', session.read)
        self.assertEqual(self.runtime_proofs, ['baseline'])
        self.assertEqual(self.effects(), [])
        self.assertEqual(self.main.read_bytes(), original)

    def test_one_directory_flock_spans_all_phases(self):
        self.assertEqual(DIRECT_LOCK, pathlib.Path('/etc/systemd/system'))
        self.assertEqual(self.competitor(), 0)
        with self.session() as session:
            self.assertEqual(self.competitor(), 23)
            original = session.read()
            # Shutdown flush wins after the pre-stop read. Only managed
            # clients may vary, and the CAS must use that final inode.
            def shutdown_flush(command):
                if command == 'stop':
                    temp = self.main.with_name('agent-stage')
                    temp.write_bytes(config(users=[{'id': 'drained'}]))
                    temp.chmod(0o640)
                    os.replace(temp, self.main)
                    self.loaded_main = profile(users=[{'id': 'drained'}])
            self.on_command = shutdown_flush
            session.stop()
            self.assertEqual(self.competitor(), 23)
            publication = session.capture(original, config('b', [{'id': 'stale'}]))
            self.assertEqual(self.competitor(), 23)
            self.assertNotEqual(publication.before.generation, original.main.generation)
            self.assertEqual(publication.before.data, self.main.read_bytes())
            self.assertEqual(json.loads(publication.desired), profile('b', [{'id': 'drained'}]))
            written = session.publish(publication.before, publication.desired)
            self.assertEqual(self.competitor(), 23)
            self.assertEqual(written.data, publication.desired)
            self.assertEqual(written.metadata, publication.before.metadata)
            self.assertNotEqual(written.generation, publication.before.generation)
            restarted = session.restart()
            self.assertEqual(self.competitor(), 23)
            self.assertNotEqual(restarted.xray, original.xray)
            session.start()
            self.assertEqual(self.competitor(), 23)
            reconciled = session.reconcile()
            self.assertEqual(self.competitor(), 23)
            self.assertEqual(session.read(), reconciled)
            self.assertEqual(reconciled, restarted)
        self.assertEqual(self.competitor(), 0)
        self.assertEqual(self.effects(), ['stop', 'restart', 'start'])
        self.assertIn('restart', self.runtime_proofs)
        self.assertIn('reconcile', self.runtime_proofs)
        self.assertGreaterEqual(self.manager.now, self.manager.terminal_time)
        with self.assertRaises(WindowError):
            with session:
                self.fail('closed window was reused')

    def test_separate_direct_holder_refuses_entry_without_callbacks(self):
        self.on_authority = lambda: self.fail('authority called before acquiring the lock')
        with subprocess.Popen(self.competitor_args(self.lock, 'hold'),
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE) as holder:
            assert holder.stdin is not None and holder.stdout is not None
            try:
                self.assertTrue(select.select([holder.stdout], [], [], 5)[0])
                self.assertEqual(holder.stdout.readline(), b'held\n')
                with self.assertRaises(WindowError) as error:
                    with self.session():
                        self.fail('entered a busy DIRECT scope')
                self.assertEqual(error.exception.code, 'REBUILD_MAIN_LOCK_UNPROVED')
                self.assertEqual(self.manager.trace, [])
            finally:
                holder.stdin.close()
                try:
                    self.assertEqual(holder.wait(timeout=5), 0)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    raise
        self.assertEqual(self.competitor(), 0)

    def test_lock_replacement_inside_affirmative_authority_is_sticky(self):
        with self.session() as session:
            session.read()

            def replace():
                self.lock.rename(self.old_dir)
                self.lock.mkdir()
                self.on_authority = lambda: None
            self.on_authority = replace
            self.assert_sticky(session, 'REBUILD_MAIN_LOCK_UNPROVED', session.stop)
            self.assertEqual(self.competitor(path=self.old_dir), 23)
            self.assertEqual(self.competitor(), 0)
            self.lock.rmdir()
            self.old_dir.rename(self.lock)
            with self.assertRaises(WindowError):
                session.stop()
            self.assertEqual(self.effects(), [])
        self.assertEqual(self.competitor(), 0)

    def test_authority_revoked_after_staging_prevents_replace(self):
        with self.session() as session:
            publication = self.capture(session)

            def revoke_after_stage():
                if any(self.main.parent.glob('.c3-main-*')):
                    self.allow_authority = False
            self.on_authority = revoke_after_stage
            self.assert_sticky(session, 'REBUILD_MAIN_AUTHORITY_UNPROVED',
                               lambda: session.publish(publication.before, publication.desired))
            self.assertEqual(self.main.read_bytes(), publication.before.data)
            self.assertFalse(list(self.main.parent.glob('.c3-main-*')))
        self.assertEqual(self.effects(), ['stop'])

    def test_same_byte_replacement_before_publish_fails_cas(self):
        with self.session() as session:
            p = self.capture(session)
            twin = self.main.with_name('twin')
            twin.write_bytes(p.before.data)
            twin.chmod(0o640)
            twin.replace(self.main)
            self.assert_sticky(session, 'REBUILD_MAIN_CAS_UNPROVED', lambda: session.publish(*p))
        self.assertEqual(self.effects(), ['stop'])

    def test_post_replace_directory_sync_ack_loss_is_not_replayed(self):
        with self.session() as session:
            p = self.capture(session)
            fsync = os.fsync

            def lost_ack(fd):
                fsync(fd)
                if stat.S_ISDIR(os.fstat(fd).st_mode) and self.main.read_bytes() == p.desired:
                    raise OSError('fixture lost the completed directory sync acknowledgement')

            with patch.object(os, 'fsync', lost_ack):
                self.assert_sticky(session, 'REBUILD_MAIN_PUBLICATION_UNCONFIRMED', lambda: session.publish(*p))
            self.assertEqual(self.main.read_bytes(), p.desired)
            self.assertFalse(list(self.main.parent.glob('.c3-main-*')))
            self.assertEqual(self.competitor(), 23)
        self.assertEqual(self.effects(), ['stop'])

    def test_artifact_substitution_fails_before_writing(self):
        with self.session() as session:
            original = session.read()
            session.stop()
            target = config('b', [{'id': 'initial'}])
            p = session.capture(original, target)
            self.assertEqual(p.desired, target)
            self.assert_sticky(session, 'REBUILD_MAIN_CAS_UNPROVED',
                               lambda: session.publish(p.before, config('a')))
            self.assertEqual(self.main.read_bytes(), p.before.data)
        self.assertEqual(self.effects(), ['stop'])

    def test_topology_drift_after_read_refuses_to_stop(self):
        with self.session() as session:
            session.read()
            self.main.write_bytes(config('b', [{'id': 'initial'}]))
            self.assert_sticky(session, 'REBUILD_MAIN_CAS_UNPROVED', session.stop)
        self.assertEqual(self.effects(), [])

    def test_restart_effect_with_lost_reply_is_not_replayed(self):
        real_run = self.run_model

        def lost_reply(argv, timeout):
            result = real_run(argv, timeout)
            if argv[1] == 'restart':
                raise subprocess.TimeoutExpired(argv, timeout)
            return result
        self.run_model = lost_reply
        with self.session() as session:
            p = self.capture(session)
            session.publish(*p)
            self.assert_sticky(session, 'REBUILD_MAIN_RESTART_UNCONFIRMED', session.restart)
            self.assertEqual(self.main.read_bytes(), p.desired)
            self.assertEqual(self.manager.xray_generation, 2)
        self.assertEqual(self.effects(), ['stop', 'restart'])

    def test_runtime_callback_cannot_adopt_later_generation(self):
        with self.session() as session:
            p = self.capture(session)
            session.publish(*p)

            def replace(phase):
                if phase == 'restart':
                    self.manager.xray_generation += 1
            self.on_runtime = replace
            with self.assertRaises(WindowError):
                session.restart()
            with self.assertRaises(WindowError):
                session.start()
        self.assertEqual(self.effects(), ['stop', 'restart'])

    def test_reconcile_rejects_same_byte_republication_during_startup(self):
        with self.session() as session:
            p = self.capture(session)
            session.publish(*p)
            session.restart()
            session.start()
            twin = self.main.with_name('twin')
            twin.write_bytes(p.desired)
            twin.chmod(0o640)
            twin.replace(self.main)
            self.assert_sticky(session, 'REBUILD_MAIN_CAS_UNPROVED', session.reconcile)
        self.assertEqual(self.effects(), ['stop', 'restart', 'start'])

    def test_startup_receipt_does_not_replace_runtime_authority(self):
        with self.session() as session:
            p = self.capture(session)
            session.publish(*p)
            session.restart()
            session.start()
            self.allow_runtime = False
            self.assert_sticky(session, 'REBUILD_MAIN_RUNTIME_UNPROVED', session.reconcile)
            self.assertGreaterEqual(self.manager.now, self.manager.terminal_time)
        self.assertEqual(self.effects(), ['stop', 'restart', 'start'])

    def test_exit_never_restarts_agent_after_partial_window(self):
        with self.session() as session:
            self.capture(session)
        self.assertEqual(self.effects(), ['stop'])
        self.assertFalse(self.manager.active)
        self.assertEqual(self.competitor(), 0)


if __name__ == '__main__':
    unittest.main()
