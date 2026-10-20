"""Actual scratch file bytes; root UID and independent systemd are SIMULATED."""
import base64
import hashlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('snapshot_attestor', Path(__file__).with_name('physical_attestor.py'))
assert spec is not None and spec.loader is not None
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class SnapshotTests(unittest.TestCase):
    def test_snapshot_carries_exact_original_binary_bytes_and_independent_service_readback(self):
        self.assertTrue(hasattr(a, 'config_snapshot'), 'finite original-byte snapshot is missing')
        with tempfile.TemporaryDirectory() as root:
            paths = {'config': str(Path(root) / 'config.json'), 'unit': str(Path(root) / 'xray.service')}
            config, unit = b'{"private":"not-for-logs"}\r\n', b'[Service]\n# exact\x00\xff\n'
            Path(paths['config']).write_bytes(config)
            Path(paths['unit']).write_bytes(unit)
            for p in paths.values():
                Path(p).chmod(0o600)
            def read(p):
                st = Path(p).lstat()
                return Path(p).read_bytes(), SimpleNamespace(st_uid=0, st_gid=0, st_mode=st.st_mode)
            state = {'Id': 'xray.service', 'LoadState': 'loaded', 'FragmentPath': paths['unit'],
                     'DropInPaths': '', 'ActiveState': 'active', 'UnitFileState': 'enabled', 'Job': ''}
            calls = []
            host = SimpleNamespace(unit=lambda name: (calls.append(name), dict(state))[1])
            result = a.config_snapshot('xray-main', host, read=read, paths=paths)
            self.assertEqual(base64.b64decode(result['configBase64'], validate=True), config)
            self.assertEqual(base64.b64decode(result['unitBase64'], validate=True), unit)
            self.assertEqual(result['readback'], {'source': 'node-readback', 'configSha256': hashlib.sha256(config).hexdigest(),
                             'unitSha256': hashlib.sha256(unit).hexdigest(), 'serviceActive': 'active', 'serviceEnabled': 'enabled'})
            self.assertEqual(calls, ['xray.service', 'xray.service'])
            self.assertEqual(Path(paths['config']).read_bytes(), config)
            self.assertEqual(Path(paths['unit']).read_bytes(), unit)
            for field, bad in [('Job', '23/start'), ('DropInPaths', '/override.conf'), ('FragmentPath', '/other'),
                               ('ActiveState', 'activating'), ('UnitFileState', 'static'), ('LoadState', 'not-found')]:
                original = state[field]
                state[field] = bad
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    a.config_snapshot('xray-main', host, read=read, paths=paths)
                state[field] = original
            state['ActiveState'] = 'inactive'
            self.assertEqual(a.config_snapshot('xray-main', host, read=read, paths=paths)['readback']['serviceActive'], 'inactive')
            Path(paths['unit']).chmod(0o666)
            with self.assertRaises(RuntimeError):
                a.config_snapshot('xray-main', host, read=read, paths=paths)

    def test_finite_request_does_not_accept_restore_paths_or_new_operation_grammar(self):
        import io
        import json
        import os
        import signal
        previous = signal.getsignal(signal.SIGALRM)
        try:
            for extra in ({'operation': 'restore'}, {'configPath': '/other'}, {'bytes': 'untrusted'}):
                reader, writer = os.pipe()
                os.write(writer, (json.dumps({'nonce': 'a' * 64, 'predecessor': None, **extra}) + '\n').encode())
                os.close(writer)
                with os.fdopen(reader, 'r') as inp, self.assertRaisesRegex(RuntimeError, 'INVALID_ATTESTATION_REQUEST'):
                    # Rejection precedes engine/state/filesystem access entirely.
                    a.serve(None, SimpleNamespace(decode_json=json.loads), None, inp=inp, out=io.StringIO())
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    def test_snapshot_refuses_mid_read_drift_oversize_and_symlinks_without_writing(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            paths = {'config': str(root / 'config'), 'unit': str(root / 'unit')}
            for p in paths.values():
                Path(p).write_bytes(b'original')
                Path(p).chmod(0o600)
            state = {'Id': 'xray.service', 'LoadState': 'loaded', 'FragmentPath': paths['unit'],
                     'DropInPaths': '', 'ActiveState': 'active', 'UnitFileState': 'enabled', 'Job': ''}
            def read(p):
                st = Path(p).lstat()
                return Path(p).read_bytes(), SimpleNamespace(st_uid=0, st_gid=0, st_mode=st.st_mode)
            calls = []
            def changing_unit(_):
                calls.append(1)
                return {**state, 'ActiveState': 'active' if len(calls) == 1 else 'inactive'}
            with self.assertRaisesRegex(RuntimeError, 'CONFIG_SERVICE_CHANGED'):
                a.config_snapshot('xray-main', SimpleNamespace(unit=changing_unit), read=read, paths=paths)
            count = {}
            def changing_read(p):
                raw, st = read(p)
                count[p] = count.get(p, 0) + 1
                return (b'changed-after-observation' if count[p] > 1 else raw), st
            host = SimpleNamespace(unit=lambda _: dict(state))
            with self.assertRaisesRegex(RuntimeError, 'CONFIG_BYTES_CHANGED'):
                a.config_snapshot('xray-main', host, read=changing_read, paths=paths)
            Path(paths['config']).write_bytes(b'x' * (512 * 1024 + 1))
            with self.assertRaisesRegex(RuntimeError, 'UNSAFE_CONFIG_SNAPSHOT'):
                a.config_snapshot('xray-main', host, read=read, paths=paths)
            Path(paths['config']).unlink()
            Path(paths['config']).symlink_to(paths['unit'])
            with self.assertRaisesRegex(RuntimeError, 'UNSAFE_CONFIG_SNAPSHOT'):
                a.config_snapshot('xray-main', host, read=read, paths=paths)
            self.assertEqual(Path(paths['unit']).read_bytes(), b'original')


if __name__ == '__main__':
    unittest.main()
