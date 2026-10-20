"""Actual five-node restore flocks + UDS + bridge; UID/physical/systemd SIMULATED."""
import fcntl
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import unittest

import coordinated_restore as c
import test_coordinated_restore as tc
import test_node_originals as t

HERE = Path(__file__).resolve().parent
OWNER = '''import os, sys
from pathlib import Path
import coordinated_restore as c
import test_node_originals as t
import owner_restoration_channel as b
fs = t.n.Files(t.n.Fixture(Path(sys.argv[1]), os.getuid(), os.getgid(), None))
channel = c.RestorationChannel(fs, fixture_socket=sys.argv[2])
try:
    channel.__enter__()
    b.serve(channel, lifetime=8)
finally:
    channel.close()
'''


class OwnerRestorationBridgeTests(unittest.TestCase):
    def run_bridge(self, *, malformed=False):
        with tc.cfixture(c) as f:
            # Short owned UDS below approved TMPDIR, not nested fixture paths.
            sock = str(f.root / 'o.sock')
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(sock)
            listener.listen(1)
            errors = []
            child = None
            try:
                with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope() as held:
                    def server():
                        try:
                            held.serve_owner(listener)
                        except BaseException as e:
                            errors.append(e)
                    thread = threading.Thread(target=server)
                    thread.start()
                    child = subprocess.Popen([sys.executable, '-c', OWNER, str(f.root), sock], cwd=HERE,
                                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, bufsize=0)
                    assert child.stdin is not None and child.stdout is not None and child.stderr is not None
                    try:
                        frame = {'version': 1, 'op': 'check', 'nonce': 'a'*64}
                        child.stdin.write(json.dumps(frame).encode() + b'\n')
                        self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                        self.assertEqual(json.loads(child.stdout.readline()), {**frame, 'op': 'checked'})
                        self.assertTrue(held.active)
                        # Prove original open-file-description locks are STILL
                        # held during the actual bridge acknowledgement.
                        for fixture in f.fixtures:
                            for path in (t.n.OUTER_LOCK, *(t.n.runner_lock(p) for p in fixture.writer.profiles)):
                                with open(fixture.path(path), 'rb') as competitor:
                                    with self.assertRaises(BlockingIOError):
                                        fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            self.assertEqual(fixture.fs.read_json(t.n.ADMISSION)['state'], 'closed')
                        if malformed:
                            frame['op'] = 'finish'  # intentionally NOT supported
                        else:
                            # A different idle node dies; no new acknowledgement
                            # can authorize a later owner CAS.
                            held.nodes[2].process.kill()
                            held.nodes[2].process.wait(timeout=3)
                        child.stdin.write(json.dumps(frame).encode() + b'\n')
                        self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                        self.assertEqual(child.stdout.readline(), b'')
                        child.wait(timeout=3)
                        self.assertNotEqual(child.returncode, 0)
                    finally:
                        if child.poll() is None:
                            child.kill()
                            child.wait(timeout=3)
                        for stream in (child.stdin, child.stdout, child.stderr):
                            stream.close()
                        thread.join(timeout=4)
                        self.assertFalse(thread.is_alive())
                        self.assertTrue(errors)
                        self.assertFalse(held.active)
            except c.Refusal:
                # Scope final checkpoint MUST refuse after channel revocation.
                pass
            finally:
                listener.close()
            for fixture in f.fixtures:
                self.assertEqual(fixture.fs.read_json(t.n.ADMISSION)['state'], 'closed')
            self.assertNotEqual(f.fs.read_json(c.INTENT)['phase'], 'scope-closed-retained')

    def test_actual_channel_checks_all_original_locks_and_revokes_after_one_node_dies(self):
        self.run_bridge()

    def test_bridge_has_no_finish_or_release_verb(self):
        self.run_bridge(malformed=True)


if __name__ == '__main__':
    unittest.main()
