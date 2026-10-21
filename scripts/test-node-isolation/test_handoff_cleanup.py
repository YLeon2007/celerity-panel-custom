"""PROTOCOL-1: real disposable pipes/processes/files; root/kernel/SSH SIMULATED."""
import errno
import os
import socket
import threading
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import owner_restoration_channel as bridge
import test_coordinated_restore as ct
import test_irreversible_handback as it


class CleanupTests(unittest.TestCase):
    def test_real_pipe_close_error_preserves_phase_and_attempts_every_channel(self):
        for phase in ('precommit', 'precommit-cleanup', 'commit-unknown', 'committed-primary', 'committed-cleanup', 'completed'):
            with self.subTest(phase=phase):
                c = ct.load_c()
                with it.combined_fixture(c) as f:
                    held = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
                    calls, restorations = [], []
                    primary = RuntimeError('SIMULATED primary acknowledgement loss')
                    try:
                        with self.assertRaises(BaseException) as failed:
                            with held.restore_scope():
                                for channel in held.nodes:
                                    close = channel.close
                                    def tracked(close=close, node=channel.node):
                                        calls.append(node)
                                        return close()
                                    channel.close = tracked
                                stream = held.nodes[0].process.stdin
                                close = stream.close
                                restorations.append((stream, close))
                                def eio():
                                    close()
                                    raise OSError(errno.EIO, 'SIMULATED actual pipe close acknowledgement EIO')
                                stream.close = eio
                                if phase == 'precommit':
                                    raise primary
                                if phase == 'commit-unknown':
                                    atomic = f.fs.atomic
                                    def lost_ack(path, *args, **kwargs):
                                        result = atomic(path, *args, **kwargs)
                                        if path == c.COMMIT:
                                            raise primary
                                        return result
                                    f.fs.atomic = lost_ack
                                if phase != 'precommit-cleanup':
                                    held.commit_handoff(it.settlement_proof(f, c))
                                    held.activate_classic()
                                    if phase == 'committed-primary':
                                        raise primary
                                    if phase == 'completed':
                                        held.finish_handoff()
                        expected = ('COORDINATED_RESTORE_UNKNOWN_RETAINED' if phase.startswith('precommit') else
                                    'COMMIT_UNKNOWN_NO_ACTIVATION' if phase == 'commit-unknown' else
                                    'COMMITTED_ACTIVATION_UNKNOWN')
                        self.assertEqual(getattr(failed.exception, 'code', None), expected)
                        if phase in ('precommit', 'commit-unknown', 'committed-primary'):
                            self.assertIs(failed.exception, primary, 'cleanup must not replace the primary exception')
                        self.assertEqual(calls, list(f.config['nodes']), 'every channel gets one bounded disposal attempt')
                        self.assertTrue(all(p.poll() is not None for p in f.children))
                        self.assertTrue(all(ch.process.stdout.closed for ch in held.nodes))
                        self.assertTrue(getattr(failed.exception, 'cleanup_errors', ()))
                        self.assertFalse(held.active)
                        self.assertFalse(held.handoff_completed)
                        if phase == 'commit-unknown':
                            self.assertFalse(f.fs.absent(c.COMMIT))
                            self.assertTrue(f.fs.absent(c.ACTIVATION))
                        if phase == 'completed':
                            self.assertNotEqual(f.fs.read_json(c.INTENT)['phase'], 'handoff-completed')
                        # Durable intent/COMMIT is never deleted or replayed.
                        with self.assertRaises(RuntimeError):
                            with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope():
                                self.fail('cleanup cannot authorize replay')
                        for node in f.fixtures:
                            self.assertEqual(node.fs.read_json(ct.t.n.ADMISSION)['state'], 'closed')
                    finally:
                        for stream, close in restorations:
                            stream.close = close
                        # RED baselines intentionally skip production disposal.
                        for child in f.children:
                            child.stdin.close(); child.stdout.close()

    def test_real_bridge_completion_waits_for_required_cleanup_and_refuses_cleanup_failure(self):
        for fault in (False, True):
            with self.subTest(cleanup_eio=fault):
                c = ct.load_c()
                with it.combined_fixture(c) as f:
                    path = f.root / 'o.sock'
                    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    listener.bind(str(path)); listener.listen(1)
                    code = '''import os,sys
from pathlib import Path
import test_node_originals as t
import coordinated_restore as c
import owner_restoration_channel as b
fs=t.n.Files(t.n.Fixture(Path(sys.argv[1]),os.getuid(),os.getgid(),None))
channel=c.RestorationChannel(fs,fixture_socket=sys.argv[2])
try:
 channel.__enter__()
 b.serve(channel,lifetime=30)
finally:
 channel.close()
'''
                    held = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
                    replies, closed, errors = [], [], []
                    complete_ack = threading.Event()
                    child = thread = None
                    def operator():
                        try:
                            for op in ('check', 'commit-handoff', 'activate-classic', 'complete-handoff'):
                                request = {'version': 1, 'op': op, 'nonce': os.urandom(32).hex()}
                                if op == 'commit-handoff': request['proof'] = it.settlement_proof(f, c)
                                child.stdin.write(c.canonical(request) + b'\n'); child.stdin.flush()
                                raw = child.stdout.readline()
                                if not raw:
                                    return
                                reply = c.decode(raw)
                                self.assertEqual(reply['op'], 'checked' if op == 'check' else op + '-ack')
                                replies.append(reply['op'])
                                if op == 'complete-handoff':
                                    complete_ack.set()
                                    self.assertEqual(closed, list(f.config['nodes']))
                        except BaseException as error:
                            errors.append(error)
                    def run():
                        nonlocal child, thread
                        with held.restore_scope():
                            for index, channel in enumerate(held.nodes):
                                close = channel.close
                                def tracked(close=close, node=channel.node, first=index == 0):
                                    if first:
                                        self.assertFalse(complete_ack.wait(.1), 'completion preceded required cleanup')
                                    close()
                                    closed.append(node)
                                channel.close = tracked
                            if fault:
                                stream = held.nodes[0].process.stdin
                                close = stream.close
                                def eio():
                                    close()
                                    raise OSError(errno.EIO, 'SIMULATED actual pipe close EIO')
                                self.addCleanup(setattr, stream, 'close', close)
                                stream.close = eio
                            child = subprocess.Popen([sys.executable, '-B', '-c', code, str(f.root), str(path)],
                                cwd=ct.HERE, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            thread = threading.Thread(target=operator)
                            thread.start()
                            held.serve_owner(listener)
                    try:
                        if fault:
                            with self.assertRaises(BaseException) as failed: run()
                            self.assertEqual(failed.exception.code, 'COMMITTED_ACTIVATION_UNKNOWN')
                        else:
                            run()
                        thread.join(5)
                        self.assertFalse(thread.is_alive())
                        out, err = child.communicate(timeout=5)
                        self.assertEqual(errors, [])
                        self.assertEqual('complete-handoff-ack' in replies, not fault)
                        self.assertEqual(held.handoff_completed, not fault)
                        self.assertTrue(all(p.returncode == 0 for p in f.children), 'node exits must stay natural')
                        if not fault:
                            self.assertEqual((child.returncode, out, err), (0, b'', b''))
                        else:
                            self.assertNotEqual(child.returncode, 0)
                    finally:
                        listener.close()
                        if child is not None and child.poll() is None:
                            child.kill(); child.communicate(timeout=3)
                        if thread is not None: thread.join(5)

    def test_coordinator_main_listener_close_never_masks_commit_or_prints_success(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from types import SimpleNamespace
        for primary_present in (True, False):
            with self.subTest(primary=primary_present):
                c = ct.load_c()
                with it.combined_fixture(c) as f:
                    key = b'SIMULATED operator key; never used for SSH'
                    f.config['keySha256'] = c.sha(key)
                    f.fs.atomic(c.CONFIG, c.canonical(f.config))
                    for node in f.fixtures: node.put(c.CONFIG, c.canonical(f.config))
                    (f.root / c.KEY.lstrip('/')).parent.mkdir(mode=0o700)
                    f.fs.atomic(c.KEY, key, new=True)
                    f.fs.atomic(c.LOCK, b'', new=True)
                    path = str(f.root / 'main.sock')
                    primary = RuntimeError('SIMULATED lost activation acknowledgement')
                    base = c.Coordinator
                    class LocalCoordinator(base):
                        def __init__(self, config, fs, spawn, *, origin):
                            super().__init__(config, fs, f.spawn, origin=origin)
                        def serve_owner(self, listener):
                            self.commit_handoff(it.settlement_proof(f, c))
                            self.activate_classic()
                            if primary_present: raise primary
                            self.finish_handoff()
                    originals = (ct.HERE / 'node_originals.py').read_bytes()
                    source = (ct.HERE / 'coordinated_restore.py').read_bytes()
                    def trusted(name):
                        return c.canonical(f.config) if name == c.CONFIG else originals if name == c.ORIGINALS else source
                    close = socket.socket.close
                    def eio(sock):
                        try: target = sock.getsockname() == path
                        except OSError: target = False
                        close(sock)
                        if target: raise OSError(errno.EIO, 'SIMULATED actual listener close acknowledgement EIO')
                    output = StringIO()
                    absent = f.fs.absent
                    def fixture_absent(name):
                        return not os.path.exists(path) if name == path else absent(name)
                    with patch.object(f.fs, 'absent', fixture_absent), patch.object(c, 'trusted_read', trusted), \
                         patch.object(c, 'load_module', return_value=SimpleNamespace(Files=lambda: f.fs)), \
                         patch.object(c, 'local_origin', return_value=f.origin), \
                         patch.object(c, 'Coordinator', LocalCoordinator), patch.object(c, 'SOCKET', path), \
                         patch.object(c.os, 'geteuid', return_value=0), \
                         patch.object(c.sys, 'argv', ['SIMULATED-coordinator', 'restore']), \
                         patch.object(c.signal, 'signal'), patch.object(c.signal, 'alarm'), \
                         patch.object(socket.socket, 'close', eio), redirect_stdout(output):
                        with self.assertRaises(BaseException) as failed: c.main()
                    self.assertEqual(getattr(failed.exception, 'code', None), 'COMMITTED_ACTIVATION_UNKNOWN', repr(failed.exception))
                    if primary_present: self.assertIs(failed.exception, primary)
                    self.assertTrue(failed.exception.cleanup_errors)
                    self.assertEqual(output.getvalue(), '', 'no success result before listener cleanup')
                    self.assertFalse(f.fs.absent(c.COMMIT))

    def test_main_outer_real_lock_close_preserves_phase_and_precedes_success(self):
        from contextlib import contextmanager, redirect_stdout
        from io import StringIO
        from types import SimpleNamespace
        for phase in ('completed', 'committed-primary', 'commit-unknown', 'precommit-primary', 'output-failed'):
            with self.subTest(phase=phase):
                c = ct.load_c()
                with it.combined_fixture(c) as f:
                    key = b'SIMULATED operator key; never used for SSH'
                    f.config['keySha256'] = c.sha(key)
                    f.fs.atomic(c.CONFIG, c.canonical(f.config))
                    for node in f.fixtures: node.put(c.CONFIG, c.canonical(f.config))
                    (f.root / c.KEY.lstrip('/')).parent.mkdir(mode=0o700)
                    f.fs.atomic(c.KEY, key, new=True)
                    f.fs.atomic(c.LOCK, b'', new=True)
                    path = str(f.root / 'lock.sock')
                    primary = RuntimeError('SIMULATED primary phase acknowledgement loss')
                    instances, target, disposed = [], [None], []
                    base = c.Coordinator
                    class LocalCoordinator(base):
                        def __init__(self, config, fs, spawn, *, origin):
                            super().__init__(config, fs, f.spawn, origin=origin)
                            instances.append(self)
                        def serve_owner(self, listener):
                            if phase == 'precommit-primary': raise primary
                            if phase == 'commit-unknown':
                                atomic = f.fs.atomic
                                def lost_ack(name, *args, **kwargs):
                                    result = atomic(name, *args, **kwargs)
                                    if name == c.COMMIT: raise primary
                                    return result
                                f.fs.atomic = lost_ack
                            self.commit_handoff(it.settlement_proof(f, c))
                            self.activate_classic()
                            if phase == 'committed-primary': raise primary
                            self.finish_handoff()
                    originals = (ct.HERE / 'node_originals.py').read_bytes()
                    source = (ct.HERE / 'coordinated_restore.py').read_bytes()
                    def trusted(name):
                        return c.canonical(f.config) if name == c.CONFIG else originals if name == c.ORIGINALS else source
                    real_lock, close = f.fs.lock, os.close
                    @contextmanager
                    def tracked_lock(name):
                        with real_lock(name) as fd:
                            target[0] = fd
                            yield fd
                    def eio(fd):
                        wanted = phase != 'output-failed' and not disposed and fd == target[0] and bool(instances)
                        close(fd)  # Real exact outer lock descriptor is closed, then acknowledgement is lost.
                        if wanted:
                            disposed.append(fd)
                            raise OSError(errno.EIO, 'SIMULATED outer lock close acknowledgement EIO')
                    class BrokenOutput(StringIO):
                        def write(self, text):
                            raise BrokenPipeError(errno.EPIPE, 'SIMULATED final result output loss')
                    absent = f.fs.absent
                    output = BrokenOutput() if phase == 'output-failed' else StringIO()
                    def fixture_absent(name):
                        return not os.path.exists(path) if name == path else absent(name)
                    with patch.object(f.fs, 'absent', fixture_absent), patch.object(f.fs, 'lock', tracked_lock), \
                         patch.object(c, 'trusted_read', trusted), \
                         patch.object(c, 'load_module', return_value=SimpleNamespace(Files=lambda: f.fs)), \
                         patch.object(c, 'local_origin', return_value=f.origin), \
                         patch.object(c, 'Coordinator', LocalCoordinator), patch.object(c, 'SOCKET', path), \
                         patch.object(c.os, 'geteuid', return_value=0), \
                         patch.object(c.sys, 'argv', ['SIMULATED-coordinator', 'restore']), \
                         patch.object(c.signal, 'signal'), patch.object(c.signal, 'alarm'), \
                         patch.object(os, 'close', eio), redirect_stdout(output):
                        with self.assertRaises(BaseException) as failed: c.main()
                    expected = ('COORDINATED_RESTORE_UNKNOWN_RETAINED' if phase == 'precommit-primary' else
                                'COMMIT_UNKNOWN_NO_ACTIVATION' if phase == 'commit-unknown' else
                                'COMMITTED_ACTIVATION_UNKNOWN')
                    self.assertEqual(getattr(failed.exception, 'code', None), expected)
                    if phase not in ('completed', 'output-failed'): self.assertIs(failed.exception, primary)
                    self.assertTrue(getattr(failed.exception, 'cleanup_errors', ()))
                    self.assertEqual(len(disposed), 0 if phase == 'output-failed' else 1)
                    self.assertEqual(output.getvalue(), '', 'no success JSON before outer lock disposal')
                    self.assertTrue(all(p.poll() is not None for p in f.children))
                    if phase != 'precommit-primary': self.assertFalse(f.fs.absent(c.COMMIT))
                    if phase == 'commit-unknown': self.assertTrue(f.fs.absent(c.ACTIVATION))

    def test_real_process_disposal_is_bounded_through_terminate_wait_and_kill_errors(self):
        c = ct.load_c()
        for fault in ('terminate', 'wait', 'kill', 'timeout'):
            with self.subTest(fault=fault):
                code = 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print("ready",flush=True); time.sleep(20)'
                child = subprocess.Popen([sys.executable, '-B', '-c', code], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
                self.assertEqual(child.stdout.readline(), b'ready\n')
                channel = c.Channel(child, 'SIMULATED-node', {}, 'a'*64, {}, time.monotonic()+10)
                terminate, wait, kill = child.terminate, child.wait, child.kill
                calls = []
                def term():
                    calls.append('terminate')
                    terminate()
                    if fault == 'terminate':
                        kill()  # test-local child shutdown; report the real terminate acknowledgement as lost
                        raise OSError(errno.EIO, 'SIMULATED lost terminate acknowledgement')
                def bounded_wait(timeout):
                    self.assertEqual(timeout, 3)
                    calls.append('wait')
                    if fault == 'wait' and calls.count('wait') == 1:
                        raise OSError(errno.EIO, 'SIMULATED wait syscall error')
                    return wait(timeout=timeout)
                def checked_kill():
                    calls.append('kill')
                    kill()
                    if fault == 'kill': raise OSError(errno.EIO, 'SIMULATED lost kill acknowledgement')
                started = time.monotonic()
                try:
                    with patch.object(child, 'terminate', term), patch.object(child, 'wait', bounded_wait), \
                         patch.object(child, 'kill', checked_kill):
                        with self.assertRaises(RuntimeError) as failed:
                            channel.close()
                    self.assertTrue(failed.exception.cleanup_errors)
                    self.assertTrue(child.stdin.closed and child.stdout.closed)
                    self.assertIsNotNone(child.poll())
                    self.assertEqual(calls, ['terminate', 'wait'] if fault == 'terminate' else ['terminate', 'wait', 'kill', 'wait'])
                    self.assertLess(time.monotonic()-started, 7)
                finally:
                    if child.poll() is None: kill()
                    wait(timeout=3)
                    child.stdin.close(); child.stdout.close(); child.stderr.close()

    def test_bridge_main_secondary_real_socket_failure_does_not_mask_protocol_failure(self):
        c = ct.load_c()
        channel = c.RestorationChannel(fs=object())
        channel.commit_attempted = channel.committed = True
        left, right = socket.socketpair()
        channel.conn, channel.active = left, True
        readfd, writefd = os.pipe()
        os.write(writefd, b'{"version":1,"op":"forbidden","nonce":"' + b'a'*64 + b'"}\n')
        os.close(writefd)
        # Only trusted bootstrap/root identity are SIMULATED. The bridge parser,
        # phase classifier and actual RestorationChannel/socket disposal run.
        source = b'import test_handoff_cleanup as fixture\nRestorationChannel=fixture.bridge_channel_factory\n'
        config = {'coordinatorSha256': bridge.hashlib.sha256(source).hexdigest(),
                  'bridgeSha256': bridge.hashlib.sha256(b'SIMULATED pinned bridge').hexdigest()}
        def trusted(path):
            return c.canonical(config) if path == bridge.CONFIG else source if path == bridge.COORDINATOR else b'SIMULATED pinned bridge'
        close, serve = socket.socket.close, bridge.serve
        def eio(sock):
            close(sock)
            if sock is left: raise OSError(errno.EIO, 'SIMULATED actual bridge socket close EIO')
        try:
            with patch.object(sys.modules[__name__], 'bridge_channel_factory', lambda: channel, create=True), \
                 patch.object(type(channel), '__enter__', lambda self: self), \
                 patch.object(bridge, 'trusted_read', trusted), \
                 patch.object(bridge.os, 'geteuid', return_value=0), \
                 patch.object(bridge.sys, 'argv', ['SIMULATED-bridge']), \
                 patch.object(bridge.signal, 'signal'), patch.object(bridge.signal, 'alarm'), \
                 patch.object(bridge, 'serve', lambda ch: serve(ch, reader=readfd)), \
                 patch.object(socket.socket, 'close', eio):
                with self.assertRaises(RuntimeError) as failed:
                    bridge.main()
            self.assertEqual(failed.exception.code, 'COMMITTED_ACTIVATION_UNKNOWN')
            self.assertEqual(str(failed.exception), 'OWNER_RESTORATION_CHANNEL_UNKNOWN_RETAINED')
            self.assertTrue(failed.exception.cleanup_errors)
            self.assertIsNone(channel.conn)
        finally:
            os.close(readfd); close(left); close(right)

    def test_actual_socket_close_preserves_primary_and_classifies_cleanup_only(self):
        for committed, primary_present in ((False, True), (True, True), (True, False)):
            with self.subTest(committed=committed, primary=primary_present):
                c = ct.load_c()
                channel = c.RestorationChannel(fs=object())
                channel.commit_attempted = True
                channel.committed = committed
                left, right = socket.socketpair()
                channel.conn, channel.active = left, True
                primary = RuntimeError('SIMULATED primary protocol loss')
                close = socket.socket.close
                def eio(sock):
                    close(sock)
                    if sock is left:
                        raise OSError(errno.EIO, 'SIMULATED actual UDS close acknowledgement EIO')
                try:
                    with patch.object(socket.socket, 'close', eio):
                        if primary_present:
                            # __exit__ must not replace an in-flight error.
                            try:
                                raise primary
                            except RuntimeError:
                                channel.__exit__(RuntimeError, primary, primary.__traceback__)
                        else:
                            with self.assertRaises(OSError) as failed:
                                channel.close()
                            primary = failed.exception
                    self.assertEqual(primary.code, 'COMMITTED_ACTIVATION_UNKNOWN' if committed else 'COMMIT_UNKNOWN_NO_ACTIVATION')
                    self.assertTrue(primary.cleanup_errors)
                    self.assertIsNone(channel.conn)
                    self.assertFalse(channel.active)
                    channel.close()  # never retry an uncertain close
                finally:
                    close(left); close(right)


if __name__ == '__main__':
    unittest.main()
