"""Actual dispatch/attestor consumers; root, remote and physical facts modeled.

Only runner payload process/files are real. No host/root/remote mutations.
"""
import base64
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import test_isolation as fixture
import test_physical_attestor as attestor_fixture

m = fixture.m
a = attestor_fixture.a
V2 = '/usr/local/bin/celerity-topology-node-runner-v2'
OLD = '/usr/local/bin/celerity-topology-node-runner'
SOURCE = Path(__file__).resolve().parents[2] / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'


class FixedV2Route(unittest.TestCase):
    def test_dispatch_22_24_v2_args_and_refuse_legacy_path_and_12_14_args(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote = root / 'remote'; remote.mkdir()
            engine = fixture.EngineTests().engine(root)
            fixture.fixture_hold(engine)
            fd = os.open(root / 'lock', os.O_RDWR | os.O_CREAT, 0o600)
            self.addCleanup(os.close, fd)
            values = ['close', 'op-1', engine.plan['nodeId'], 'sha256:' + 'a' * 64,
                      'backup-1', 'xray-main', 'test.infograd.online', 'attempt-1',
                      'generation-1', 'none', 'close-1']
            args = [word for name, value in zip(m.NAMES, values) for word in ('--' + name, value)]
            calls = []
            real_run = subprocess.run
            def runner(argv, **kwargs):
                calls.append(argv)
                self.assertEqual(argv[:2], ['/bin/bash', V2])
                env = dict(kwargs.pop('env'), CELERITY_TOPOLOGY_ROOT=str(remote))
                return real_run(['/bin/bash', str(SOURCE), *argv[2:]], env=env, **kwargs)
            boot = remote / 'proc/sys/kernel/random/boot_id'
            boot.parent.mkdir(parents=True); boot.write_text(engine.plan['bootId'] + '\n')
            (remote / 'var/lib').mkdir(parents=True)
            with patch.object(m.subprocess, 'run', runner):
                result = engine.dispatch(shlex.join([V2, *args]), b'', fd)
                self.assertEqual(m.decode_json(result)['phase'], 'closed')
                # 24-argument verify reaches the actual dispatch/runner boundary;
                # unknown generation refuses and retains in-flight ownership.
                verify = list(args); verify[1] = 'verify'; verify[-1] = 'verify-1'
                verify += ['--checks', base64.urlsafe_b64encode(b'[]').decode().rstrip('=')]
                with self.assertRaisesRegex(m.Refusal, 'RUNNER_OUTCOME_UNKNOWN_RETAINED'):
                    engine.dispatch(shlex.join([V2, *verify]), b'', fd)
                self.assertIsNotNone(engine.read()['dispatchInFlight'])
                before = (root / 'journal.json').read_bytes()
                for path in (OLD, V2):
                    for legacy in (args[:12], verify[:12] + verify[-2:]):
                        with self.assertRaisesRegex(m.Refusal, 'NOT_FIXED_RUNNER|INVALID_ARGV'):
                            engine.dispatch(shlex.join([path, *legacy]), b'', fd)
                with self.assertRaisesRegex(m.Refusal, 'NOT_FIXED_RUNNER'):
                    engine.dispatch(shlex.join([OLD, *args]), b'', fd)
                self.assertEqual((root / 'journal.json').read_bytes(), before)
            self.assertEqual([len(call) - 2 for call in calls], [22, 24])
            self.assertEqual(m.RUNNER, V2)
            self.assertEqual(hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                             '442663660ec974646b7969c457efd94cc17c57fe0e7a518be8a494480cf26765')

    def test_attestor_reads_and_reports_only_fixed_v2_path_with_metadata_guards(self):
        calls = []
        info = SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o100750)
        def read(path, directory=False):
            calls.append(path)
            if directory:
                return b'', SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o40755)
            self.assertEqual(path, V2)
            return SOURCE.read_bytes(), info
        value = a.installation('xray-main', None, read=read)
        self.assertEqual(value['runner']['path'], V2)
        self.assertNotIn(OLD, calls)
        self.assertEqual(value['runner']['sha256'], 'sha256:' + hashlib.sha256(SOURCE.read_bytes()).hexdigest())
        for field, wrong in [('st_uid', 1), ('st_gid', 1), ('st_mode', 0o100755), ('st_mode', 0o120750)]:
            original = getattr(info, field); setattr(info, field, wrong)
            with self.assertRaisesRegex(RuntimeError, 'UNSAFE_RUNNER'):
                a.installation('xray-main', None, read=read)
            setattr(info, field, original)


if __name__ == '__main__':
    unittest.main()
