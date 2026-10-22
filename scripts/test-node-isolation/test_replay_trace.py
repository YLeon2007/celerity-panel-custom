"""Regression for low-interference replay observations, not physical authority."""
import array
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

import coordinated_restore as c
import fresh_classic_launch as fresh
import test_prepared_resume as prepared


class ReplayTraceTests(unittest.TestCase):
    def test_real_prepared_launch_records_same_witnesses_without_global_profiler(self):
        self.assertTrue(hasattr(prepared, 'trace_replay'), 'scoped replay tracing missing')
        prior = sys.getprofile()
        with prepared.prepared_fixture() as f:
            with patch.object(sys, 'setprofile', side_effect=AssertionError('global profiler distorts bounded replay')):
                with prepared.trace_replay(f.root):
                    module = c.load_fresh(f.fs)
                    result = module.FreshLaunch(f.held, f.platform, socket_path=f.socket).run_prepared(f.proof)
                    self.assertIs(sys.getprofile(), prior)
            import json
            events = [json.loads(line) for line in (f.root/'controller.jsonl').read_text().splitlines()]
            self.assertEqual(sum(e['event'] == 'sendmsg' for e in events), 1)
            listening = [e['value'] for e in events if e['event'] == '_control_listening']
            self.assertIn(False, listening)
            self.assertIn(True, listening)
            self.assertEqual(result['code'], 'COMMITTED_FRESH_ACTIVATION_CONFIRMED')
            self.assertEqual(f.count(), 1)
            self.assertEqual(f.fs.read_json(fresh.SUPERVISOR_ATTEMPT)['phase'], 'completed')
            self.assertTrue(all(n.fs.read_json('/fixture-live.json')['candidateFrozen'] for n in f.fixtures))
        self.assertIs(sys.getprofile(), prior)

    def test_sendmsg_wrapper_forwards_actual_scm_rights_and_restores_on_error(self):
        self.assertTrue(hasattr(prepared, 'trace_replay'), 'scoped replay tracing missing')
        original = socket.socket.sendmsg
        with tempfile.TemporaryDirectory(prefix='trace-') as directory:
            a, b = socket.socketpair()
            fd = os.memfd_create('trace-proof', os.MFD_CLOEXEC)
            try:
                os.write(fd, b'actual owned descriptor')
                error = RuntimeError('preserve exact primary')
                with self.assertRaises(RuntimeError) as caught:
                    with prepared.trace_replay(Path(directory)):
                        self.assertEqual(a.sendmsg([b'x'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))]), 1)
                        raw, ancillary, flags, address = b.recvmsg(1, socket.CMSG_SPACE(array.array('i').itemsize))
                        self.assertEqual(raw, b'x')
                        received = array.array('i'); received.frombytes(ancillary[0][2])
                        self.assertEqual(len(received), 1)
                        try: self.assertEqual(os.pread(received[0], 100, 0), b'actual owned descriptor')
                        finally: os.close(received[0])
                        raise error
                self.assertIs(caught.exception, error)
                self.assertIs(socket.socket.sendmsg, original)
            finally:
                os.close(fd); a.close(); b.close()


if __name__ == '__main__':
    unittest.main()
