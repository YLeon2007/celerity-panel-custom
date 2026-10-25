#!/usr/bin/env python3
"""Real own-child cleanup after pidfd pin refusal; no databases or historical PIDs."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('actual_fixture', ROOT / 'tests/lifecycleVnextApplication.test.py')
assert spec is not None and spec.loader is not None
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
EVIDENCE = Path(os.environ['C3_REAL_EVIDENCE'])


class PeerOwnershipTests(unittest.TestCase):
    def exercise_pin_refusal(self, fail_on):
        with tempfile.TemporaryDirectory(prefix='peer-pin-', dir=os.environ['TMPDIR']) as base:
            base = Path(base)
            evidence = base / 'evidence'
            evidence.mkdir()
            fixture_dir = base / 'fixture'
            fixture_dir.mkdir()
            source = fixture_dir / 'app'
            source.mkdir()
            (source / 'owned').write_text('readonly source')
            (source / 'owned').chmod(0o444)
            source.chmod(0o555)
            fixture = type('OwnFixture', (), dict(
                dir=fixture_dir, peers=[],
                peer=classmethod(app.ActualAppTests.peer.__func__),
                stop_peers=classmethod(app.ActualAppTests.stop_peers.__func__)))
            spawned, calls, cleanup_errors = [], [], []
            real_popen = subprocess.Popen
            real_open = os.pidfd_open
            fault = OSError(24, 'injected pidfd pin refusal after successful spawn')

            def spawn(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                spawned.append(child)
                return child

            def pin(pid, *args):
                calls.append(pid)
                if len(calls) == fail_on:
                    raise fault
                return real_open(pid, *args)

            try:
                with mock.patch.object(app, 'EVIDENCE', evidence), \
                     mock.patch.object(app.subprocess, 'Popen', side_effect=spawn), \
                     mock.patch.object(app.os, 'pidfd_open', side_effect=pin):
                    with self.assertRaises(OSError) as raised:
                        for i in range(fail_on):
                            fixture.peer(sys.executable, ['-I', '-B', '-c', 'import time;time.sleep(60)'], f'peer-{i}')
                    self.assertIs(raised.exception, fault)
                    self.assertEqual(len(spawned), fail_on)
                    try:
                        fixture.stop_peers()
                    except ExceptionGroup as exc:
                        # These synthetic peers terminate with -SIGTERM rather than a DB's exit 0.
                        cleanup_errors = [str(e) for e in exc.exceptions]
                    self.assertTrue(all(p.poll() is not None for p in spawned),
                                    'successfully spawned peer omitted from cleanup after pin refusal')
                    self.assertFalse(fixture_dir.exists())
                    exits = json.loads((evidence / 'peer-exits.json').read_text())
                    self.assertEqual(len(exits), fail_on)
                    self.assertEqual({e['peer'] for e in exits}, {f'peer-{i}' for i in range(fail_on)})
                    self.assertTrue(all(not e['forced'] for e in exits))
                    self.assertEqual(len(calls), fail_on, 'cleanup must not reopen historical PIDs')
                    for _, _, fd in fixture.peers:
                        if fd is not None:
                            with self.assertRaises(OSError):
                                os.fstat(fd)
                    (EVIDENCE / f'pin-refusal-{fail_on}.json').write_text(json.dumps(dict(
                        spawned=fail_on, pinAttempts=len(calls), originalErrorPreserved=True,
                        allChildrenReaped=True, fixtureRemoved=True, exits=exits,
                        cleanupErrors=cleanup_errors), indent=2))
            finally:
                # Emergency exact-own Popen cleanup also protects the intentional RED run.
                for p in spawned:
                    if p.poll() is None:
                        p.kill()
                    p.wait(timeout=5)
                if source.exists():
                    source.chmod(0o755)

    def test_first_peer_pin_failure_still_stops_and_reaps_owned_child(self):
        self.exercise_pin_refusal(1)

    def test_second_peer_pin_failure_still_cleans_every_owned_child(self):
        self.exercise_pin_refusal(2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
