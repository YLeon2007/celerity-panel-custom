"""Original host session over local subprocess pipes; no real manager or network."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import rebuildTransitMainSessionHost as model
from rebuildTransitMainSession import HostMainSession, WindowError
from rebuildTransitMainWire import HostMainWire
from rebuildTransitMainWindow import MAX_MAIN


def compact(value):
    return json.dumps(value, separators=(',', ':')).encode('ascii')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def target(data):
    return base64.b64encode(data).decode('ascii')


def fixture(root, fault, seconds):
    main, cgroup, lock = (root / name for name in ('MAIN', 'slice', 'lock'))
    manager = model.System(cgroup)
    deadline = time.monotonic() + seconds

    def record(action):
        with (root / 'trace').open('a') as trace:
            trace.write(action + '\n')

    def runner(argv, timeout):
        timeout = min(timeout, deadline - time.monotonic())
        if timeout <= 0:
            raise subprocess.TimeoutExpired(argv, timeout)
        command = argv[1]
        if command == 'restart':
            assert argv == ['/usr/bin/systemctl', 'restart', '--job-mode=fail', '--', 'xray.service']
            manager.xray_generation += 1
            record(command)
            if fault == 'drop-restart-reply':
                while not (root / 'release').exists() and time.monotonic() < deadline:
                    time.sleep(0.005)
                assert (root / 'release').exists()
            if fault == 'restart-ack':
                raise subprocess.TimeoutExpired(argv, timeout)
            return ''
        if command == 'start':
            manager.cg.mkdir()
        result = manager(argv, timeout)
        if command == 'stop':
            manager.events.unlink()
            manager.cg.rmdir()
            # Simulate the old writer winning with a final client-only change.
            stage = root / 'agent-stage'
            user = {'id': 'drained'}
            if os.environ.get('C3_SYNTHETIC_SYNC_USERS') == '1':
                user['email'] = 'fixture@example.invalid'
            stage.write_bytes(model.config(users=[user]))
            stage.chmod(0o640)
            stage.replace(main)
        if command in ('stop', 'start'):
            record(command)
        return result

    def factory(end):
        assert end == deadline
        record('factory')
        if fault == 'unsafe-refusal':
            raise WindowError('REBUILD_AGENT_EXCLUSION_UNPROVED private path or config')
        return HostMainSession(runner, lambda: time.monotonic() < end,
                               lambda phase, snap: snap.main.data == main.read_bytes(), {'vless-in'},
                               main=main, cgroup_root=cgroup, lock_dir=lock,
                               clock=lambda: manager.now, sleep=manager.sleep)

    def settlement(action, snapshot, end):
        assert end == deadline and snapshot.main.data == main.read_bytes()
        record(action)
        return fault != action

    def lose_publication_ack(fd):
        fsync(fd)
        if stat.S_ISDIR(os.fstat(fd).st_mode) and json.loads(main.read_bytes())['routing']['rules'][0]['outboundTag'] == 'b':
            record('publication-ack-lost')
            raise OSError('completed directory fsync; modeled lost acknowledgement')

    wire = HostMainWire(factory,
                        on_reconcile=lambda *args: settlement('settle-reconcile', *args),
                        on_verify=lambda *args: settlement('settle-verify', *args))
    if fault == 'publication-ack':
        fsync = os.fsync
        with patch.object(os, 'fsync', lose_publication_ack):
            result = wire.serve(0, 1, deadline=deadline)
    else:
        result = wire.serve(0, 1, deadline=deadline)
    assert wire.serve(0, 1, deadline=deadline) != 0  # no second session, even after success
    return result


class Wire(unittest.TestCase):
    def open(self, fault='', seconds=6.0, initial=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = root = Path(tmp.name)
        self.main = root / 'MAIN'
        self.before = model.config(users=[{'id': 'initial'}]) if initial is None else initial
        self.main.write_bytes(self.before)
        self.main.chmod(0o640)
        self.lock = root / 'lock'
        self.lock.mkdir()
        (root / 'slice').mkdir()
        self.child = child = subprocess.Popen([sys.executable, '-B', __file__, '--fixture', str(root), fault, str(seconds)],
                                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                              bufsize=0)
        assert child.stdin is not None and child.stdout is not None and child.stderr is not None
        self.input, self.output, self.errors = child.stdin, child.stdout, child.stderr
        self.pending = bytearray()

        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=6)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()
        self.addCleanup(cleanup)

    def reply(self):
        end = time.monotonic() + 7
        start = 0
        while (split := self.pending.find(b'\n', start)) < 0:
            self.assertTrue(select.select([self.output], [], [], max(0, end - time.monotonic()))[0])
            data = self.output.read(65536)
            self.assertTrue(data, 'EOF before a complete reply')
            start = len(self.pending)
            self.pending.extend(data)
        raw, self.pending = self.pending[:split], self.pending[split + 1:]
        return json.loads(raw)

    def write(self, raw):
        pending = memoryview(raw)
        while pending:
            count = self.input.write(pending)
            assert count
            pending = pending[count:]

    def send(self, action, **fields):
        self.write(compact({'action': action, **fields}) + b'\n')
        return self.reply()

    def ok(self, action, **fields):
        reply = self.send(action, **fields)
        self.assertEqual(set(reply), {'ok', 'value'})
        self.assertIs(reply['ok'], True)
        return reply['value']

    def finish(self, status, *, drained=True):
        self.input.close()
        result = self.child.wait(timeout=7)
        self.assertEqual(self.errors.read(), b'')
        if status:
            self.assertGreater(result, 0)
        else:
            self.assertEqual(result, 0)
        if drained:
            self.assertEqual(self.pending + self.output.read(), b'')
        self.assert_lock(False)

    def trace(self):
        path = self.root / 'trace'
        return path.read_text().splitlines() if path.exists() else []

    def assert_lock(self, busy):
        fd = os.open(self.lock, os.O_RDONLY | os.O_DIRECTORY)
        try:
            if busy:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def capture(self):
        first = self.ok('read')
        self.assertIsNone(self.ok('stop'))
        capture = self.ok('capture', target=target(model.config('b', [{'id': 'stale'}])))
        self.assertEqual(set(capture), {'before', 'desired'})
        return first, capture

    def publication(self, capture):
        # Model reopening exact panel artifacts, not reusing the receive buffers
        # or mistaking encrypted artifact-store pins for plaintext digests.
        before_path, desired_path = self.root / 'before', self.root / 'desired'
        before_path.write_bytes(compact(capture['before']))
        desired_path.write_bytes(base64.b64decode(capture['desired']))
        return dict(beforeSha256=digest(before_path.read_bytes()), desiredSha256=digest(desired_path.read_bytes()))

    def refuse(self, reason, reply=None):
        self.assertEqual(self.reply() if reply is None else reply, {'ok': False, 'reason': reason})
        self.finish(1)

    def test_full_duplex_sequence_and_original_lock_through_terminal_eof(self):
        self.open()
        self.assert_lock(False)
        first, capture = self.capture()
        self.assert_lock(True)
        self.assertEqual(set(first), {'data', 'metadata', 'generation', 'xray'})
        self.assertEqual(base64.b64decode(first['data']), self.before)
        drained = capture['before']
        before = self.main.stat()
        self.assertEqual(drained['generation'], [str(before.st_dev), str(before.st_ino), str(before.st_ctime_ns)])
        self.assertGreater(int(drained['generation'][2]), 2 ** 53)
        self.assertNotEqual(drained['generation'], first['generation'])
        self.assertEqual(drained['metadata'], [0o640, before.st_uid, before.st_gid])
        self.assertEqual(base64.b64decode(drained['data']), self.main.read_bytes())
        desired = base64.b64decode(capture['desired'])
        self.assertEqual(json.loads(desired), model.profile('b', [{'id': 'drained'}]))
        published = self.ok('publish', **self.publication(capture))
        self.assertEqual(base64.b64decode(published['data']), desired)
        self.assertEqual(self.main.read_bytes(), desired)
        self.assertNotEqual(published['generation'], drained['generation'])
        restarted = self.ok('restart')
        self.assertEqual(restarted['xray'][0], 502)
        self.assertNotEqual(restarted['xray'], first['xray'])
        self.assertIsNone(self.ok('start'))
        self.assertEqual(self.ok('reconcile'), restarted)
        self.assertEqual(self.ok('verify'), restarted)
        self.assert_lock(True)
        self.assertIsNone(self.child.poll())
        self.finish(0)
        self.assertEqual(self.trace(), ['factory', 'stop', 'restart', 'start', 'settle-reconcile', 'settle-verify'])

    def test_stop_requires_read_and_cannot_be_replayed(self):
        self.open()
        self.refuse('REBUILD_MAIN_WIRE_PHASE', self.send('stop'))
        self.assertEqual(self.trace(), [])
        self.open()
        self.ok('read')
        self.ok('stop')
        self.refuse('REBUILD_MAIN_WIRE_PHASE', self.send('stop'))
        self.assertEqual(self.trace(), ['factory', 'stop'])

    def test_strict_frame_schemas(self):
        for raw in (b'{"action":"read","action":"read"}\n', b'{"action":"read","extra":null}\n',
                    b'{"action":NaN}\n', b'{"action":[]}\n', b'["read"]\n', b'{"action":"r\xffead"}\n',
                    b'{"action":"Read"}\n', b'{}\n', b'\n'):
            with self.subTest(raw=raw):
                self.open()
                self.input.write(raw)
                self.refuse('REBUILD_MAIN_WIRE_REQUEST')
                self.assertEqual(self.trace(), [])

    def test_pipelined_phase_is_not_dispatched(self):
        self.open()
        self.input.write(b'{"action":"read"}\n{"action":"stop"}\n')
        self.refuse('REBUILD_MAIN_WIRE_PHASE')
        self.assertEqual(self.trace(), [])

    def test_capture_base64_is_strict_and_raw_size_is_bounded(self):
        for invalid in ('YR==', 'aA', '', 'aA-_', 'aA==\n', 7, None):
            with self.subTest(invalid=invalid):
                self.open()
                self.ok('read')
                self.ok('stop')
                self.refuse('REBUILD_MAIN_WIRE_REQUEST', self.send('capture', target=invalid))
                self.assertEqual(self.trace(), ['factory', 'stop'])
        self.open()
        self.ok('read')
        self.ok('stop')
        self.refuse('REBUILD_MAIN_WIRE_LIMIT', self.send('capture', target=target(b'x' * (MAX_MAIN + 1))))

    def test_incomplete_frame_and_early_eof_fail_without_followup(self):
        self.open()
        self.input.write(b'{"action":"read"}')
        self.input.close()
        self.refuse('REBUILD_MAIN_WIRE_EOF')
        self.assertEqual(self.trace(), [])
        self.open()
        self.capture()
        self.input.close()
        self.refuse('REBUILD_MAIN_WIRE_EOF')
        self.assertEqual(self.trace(), ['factory', 'stop'])
        self.assertEqual(json.loads(self.main.read_bytes()), model.profile(users=[{'id': 'drained'}]))

    def test_max_size_capture_over_real_pipes(self):
        self.open()
        self.ok('read')
        self.ok('stop')
        data = model.config('b', [{'id': 'drained'}]).ljust(MAX_MAIN, b' ')
        capture = self.ok('capture', target=target(data))
        self.assertEqual(base64.b64decode(capture['desired']), data)
        self.input.close()
        self.refuse('REBUILD_MAIN_WIRE_EOF')

    def test_lost_restart_ack_is_distinct_and_does_not_start(self):
        self.open('restart-ack')
        _, capture = self.capture()
        self.ok('publish', **self.publication(capture))
        self.refuse('REBUILD_MAIN_RESTART_UNCONFIRMED', self.send('restart'))
        self.assertEqual(self.main.read_bytes(), base64.b64decode(capture['desired']))
        self.assertEqual(self.trace(), ['factory', 'stop', 'restart'])

    def test_lost_publication_ack_leaves_the_exact_effect_without_restart(self):
        self.open('publication-ack')
        _, capture = self.capture()
        self.refuse('REBUILD_MAIN_PUBLICATION_UNCONFIRMED', self.send('publish', **self.publication(capture)))
        self.assertEqual(self.main.read_bytes(), base64.b64decode(capture['desired']))
        self.assertEqual(self.trace(), ['factory', 'stop', 'publication-ack-lost'])

    def test_broken_reply_pipe_after_restart_has_no_followup(self):
        self.open('drop-restart-reply')
        _, capture = self.capture()
        self.ok('publish', **self.publication(capture))
        self.write(b'{"action":"restart"}\n')
        end = time.monotonic() + 3
        while 'restart' not in self.trace() and time.monotonic() < end:
            time.sleep(0.005)
        self.assertEqual(self.trace(), ['factory', 'stop', 'restart'])
        self.assert_lock(True)
        self.output.close()
        (self.root / 'release').touch()
        self.assertGreater(self.child.wait(timeout=3), 0)
        self.finish(1, drained=False)
        self.assertEqual(self.trace(), ['factory', 'stop', 'restart'])

    def test_reopened_artifact_checks_full_image_and_desired_bytes(self):
        for changed in ('generation', 'metadata', 'data', 'desired'):
            with self.subTest(changed=changed):
                self.open()
                _, capture = self.capture()
                before = self.main.read_bytes()
                if changed == 'desired':
                    capture['desired'] = target(base64.b64decode(capture['desired']) + b'\n')
                elif changed == 'generation':
                    capture['before']['generation'][2] += '0'
                elif changed == 'metadata':
                    capture['before']['metadata'][0] = 0o600
                else:
                    capture['before']['data'] = target(before.strip())
                self.refuse('REBUILD_MAIN_CAS_UNPROVED', self.send('publish', **self.publication(capture)))
                self.assertEqual(self.main.read_bytes(), before)
                self.assertEqual(self.trace(), ['factory', 'stop'])

    def test_same_bytes_new_inode_after_capture_still_fails_native_cas(self):
        self.open()
        _, capture = self.capture()
        before = self.main.read_bytes()
        stage = self.root / 'other-writer'
        stage.write_bytes(before)
        stage.chmod(0o640)
        stage.replace(self.main)
        self.refuse('REBUILD_MAIN_CAS_UNPROVED', self.send('publish', **self.publication(capture)))
        self.assertEqual(self.main.read_bytes(), before)
        self.assertEqual(self.trace(), ['factory', 'stop'])

    def test_reconcile_without_verify_is_not_complete_and_trailing_data_is_refused(self):
        for trailing in (None, b'{"action":"verify"}\n'):
            with self.subTest(trailing=trailing):
                self.open()
                _, capture = self.capture()
                self.ok('publish', **self.publication(capture))
                self.ok('restart')
                self.ok('start')
                self.ok('reconcile')
                if trailing is None:
                    self.input.close()
                    self.refuse('REBUILD_MAIN_WIRE_EOF')
                    self.assertNotIn('settle-verify', self.trace())
                else:
                    self.ok('verify')
                    self.input.write(trailing)
                    self.refuse('REBUILD_MAIN_WIRE_PHASE')
                    self.assertEqual(self.trace().count('settle-verify'), 1)

    def test_settlement_veto_never_acknowledges_phase(self):
        for phase in ('reconcile', 'verify'):
            with self.subTest(phase=phase):
                self.open('settle-' + phase)
                _, capture = self.capture()
                self.ok('publish', **self.publication(capture))
                self.ok('restart')
                self.ok('start')
                if phase == 'verify':
                    self.ok('reconcile')
                self.refuse('REBUILD_MAIN_WIRE_SETTLEMENT', self.send(phase))
                self.assertEqual(self.trace()[-1], 'settle-' + phase)

    def test_refusals_are_allowlisted(self):
        self.open('unsafe-refusal')
        self.refuse('REBUILD_MAIN_WIRE_UNCONFIRMED', self.send('read'))
        self.assertEqual(self.trace(), ['factory'])

    def test_non_capture_frame_limit_and_absolute_deadline(self):
        self.open()
        self.input.write(b' ' * 4096)
        self.refuse('REBUILD_MAIN_WIRE_LIMIT')
        self.assertEqual(self.trace(), [])
        self.open(seconds=0.8)
        self.ok('read')
        self.input.write(b'{"act')  # partial next request cannot reset the deadline
        self.assertGreater(self.child.wait(timeout=3), 0)
        self.finish(1)
        self.assertEqual(self.trace(), ['factory'])

    def test_output_backpressure_expires_without_a_complete_reply(self):
        data = model.config().ljust(1024 * 1024, b' ')
        self.open(seconds=1.5, initial=data)
        self.write(b'{"action":"read"}\n')
        self.assertTrue(select.select([self.output], [], [], 1.5)[0])
        self.assertGreater(self.child.wait(timeout=4), 0)  # never consume the blocked reply
        partial = self.output.read()
        self.assertTrue(partial.startswith(b'{"ok":true,'))
        self.assertNotIn(b'\n', partial)
        self.finish(1)
        self.assertEqual(self.trace(), ['factory'])


if __name__ == '__main__':
    if sys.argv[1:2] == ['--fixture']:
        raise SystemExit(fixture(Path(sys.argv[2]), sys.argv[3], float(sys.argv[4])))
    unittest.main()
