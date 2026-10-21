"""Finite fresh owner seam; physical/UID inventory is explicitly simulated."""
import copy
import os
from pathlib import Path
import sys
import unittest

import coordinated_restore as c
import fresh_classic_launch as fresh
from test_fresh_classic_launch import PolicyBoundaryTests


HERE = Path(__file__).resolve().parent


class ReadinessPathTests(unittest.TestCase):
    def test_fixed_classic_readiness_path_replaces_dynamic_health(self):
        m, policy = PolicyBoundaryTests().policy()
        policy['ingress']['path'] = '/classic-ready'
        self.assertIs(m.validate(policy), policy)
        policy['ingress']['path'] = '/health'
        with self.assertRaises(c.Refusal):
            m.validate(policy)


class FreshCompositionTests(unittest.TestCase):
    def test_distinct_terminal_grammar_exists_without_legacy_activation(self):
        import owner_restoration_channel as bridge
        self.assertTrue(callable(getattr(c.Coordinator, 'serve_fresh_owner', None)), 'distinct same-held root composition missing')
        self.assertTrue(callable(getattr(c.RestorationChannel, 'fresh_handoff', None)), 'distinct terminal channel missing')
        self.assertTrue(callable(getattr(bridge, 'serve_fresh', None)), 'distinct finite fresh bridge missing')

    def test_actual_same_held_coordinator_bridge_freshlaunch_exec_positive(self):
        import contextlib
        import json
        import socket
        import subprocess
        import threading
        from pathlib import Path
        from test_prepared_resume import prepared_fixture
        m = fresh
        with prepared_fixture(m) as f:
            listener_path = f.outer.root / 'owner.sock'
            listener = socket.socket(socket.AF_UNIX); listener.bind(str(listener_path)); listener.listen(1)
            code = '''import os,sys
from pathlib import Path
import coordinated_restore as c
import owner_restoration_channel as b
import test_node_originals as t
fs=t.n.Files(t.n.Fixture(Path(sys.argv[1]),os.getuid(),os.getgid(),None))
channel=c.RestorationChannel(fs,fixture_socket=sys.argv[2])
try:
 channel.__enter__(); b.serve_fresh(channel,lifetime=60)
finally: channel.close()
'''
            child = subprocess.Popen([sys.executable, '-B', '-c', code, str(f.outer.root), str(listener_path)],
                                     cwd=HERE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, bufsize=0)
            errors = []
            def operator():
                try:
                    for op in ('check', 'fresh-handback'):
                        request = {'version': 1, 'op': op, 'nonce': os.urandom(32).hex()}
                        if op == 'fresh-handback':
                            # Model a slow public DB phase beyond the ordinary
                            # accept budget; the real preparer must still be T.
                            import time, fcntl
                            time.sleep(5.1)
                            self.assertEqual(Path(f'/proc/{f.supervisor.pid}/stat').read_text().rsplit(')',1)[1].split()[0], 'T')
                            for node in f.fixtures:
                                for path in node.writer.lock_paths:
                                    with node.path(path).open('rb') as lock:
                                        with self.assertRaises(BlockingIOError):
                                            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                            request['proof'] = f.proof
                        child.stdin.write(json.dumps(request, separators=(',', ':')).encode() + b'\n'); child.stdin.flush()
                        reply = json.loads(child.stdout.readline())
                        self.assertEqual(reply['op'], 'checked' if op == 'check' else 'fresh-handback-ack')
                        if op == 'fresh-handback': self.assertEqual(len(reply['commitSha256']), 64)
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=operator)
            try:
                held = f.held
                thread.start()
                held.serve_fresh_owner(listener, platform=f.platform, socket_path=f.socket)
                held.complete_fresh_owner()
                thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(f.count(), 1)
                self.assertTrue(held.handoff_completed)
                self.assertTrue((f.outer.fs.read_json(c.COMMIT))['activationSet'] == ['fresh-classic-process'])
            finally:
                listener.close()
                if child.poll() is None: child.kill()
                out, err = child.communicate(timeout=5)
                if err: print('FRESH BRIDGE STDERR:', err.decode(), file=sys.stderr)
                thread.join(5)

    def test_trusted_loader_binds_exact_running_coordinator_module(self):
        self.assertTrue(callable(getattr(c, 'load_fresh', None)), 'same-module trusted fresh loader missing')
        from unittest.mock import patch
        source = (Path(__file__).parent / 'fresh_classic_launch.py').read_bytes()
        policy = {'files': {c.FRESH: c.sha(source)}}
        with patch.object(c, 'trusted_read', side_effect=lambda path: source if path == c.FRESH else c.canonical(policy)):
            module = c.load_fresh()
        self.assertIs(module.c, c)
        self.assertIs(module.c.Coordinator, c.Coordinator)
        with self.assertRaisesRegex(c.Refusal, 'ACTUAL_HELD_COORDINATOR_REQUIRED'):
            module.FreshLaunch(object())


if __name__ == '__main__':
    unittest.main()
