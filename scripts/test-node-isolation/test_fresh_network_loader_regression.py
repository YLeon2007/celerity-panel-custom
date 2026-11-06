"""Real fixed server loader IO; controlled fstat at the checked-read boundary.

Disposable files/descriptor walks, read bytes, hashes and compilation are real.
Only installed-root rebasing, root ownership and the named post-read stat field
are modeled. No atime reset, warm-up, source-pin replacement or kernel IO.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = '/usr/local/libexec/c3-test-fresh-network.py'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_atime', 'st_mtime', 'st_ctime', 'st_atime_ns',
          'st_mtime_ns', 'st_ctime_ns')


def server_entry():
    spec = importlib.util.spec_from_file_location('loader_regression_entry', HERE/'fresh_network_exec.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def checked_read(root, entry, target, changed=None):
    """Only target fstat after the actual os.read gets a controlled difference."""
    real_open, real_fstat, real_read = os.open, os.fstat, os.read
    identity = (target.stat().st_dev, target.stat().st_ino)
    observed = {'reads': 0, 'afterStats': 0, 'rawSha256': None, 'before': None, 'after': None}
    def is_target(s):
        return (s.st_dev, s.st_ino) == identity
    def opened(path, *args, **kwargs):
        return real_open(root if path == '/' else path, *args, **kwargs)
    def read(fd, size):
        raw = real_read(fd, size)
        if is_target(real_fstat(fd)):
            observed['reads'] += 1
            observed['rawSha256'] = hashlib.sha256(raw).hexdigest()
        return raw
    def fstat(fd):
        original = real_fstat(fd)
        values = {name: getattr(original, name) for name in FIELDS}
        values.update(st_uid=0, st_gid=0)  # existing unprivileged root fixture seam
        if is_target(original):
            # Deterministic across filesystem mount options and second boundaries.
            values.update(st_atime=1.0, st_atime_ns=1_000_000_000)
            if observed['reads']:
                values.update(st_atime=2.0, st_atime_ns=2_000_000_000)
                if changed is not None:
                    values[changed] += 1  # ns-only drift for mtime/ctime cases
                observed['afterStats'] += 1
                observed['after'] = dict(values)
            else:
                observed['before'] = dict(values)
        return SimpleNamespace(**values)
    with patch.object(entry.os, 'open', side_effect=opened), \
         patch.object(entry.os, 'read', side_effect=read), \
         patch.object(entry.os, 'fstat', side_effect=fstat):
        yield observed


class ServerLoaderRegressionTests(unittest.TestCase):
    @contextmanager
    def fixture(self, wrong_bytes=False):
        entry = server_entry()
        raw = (HERE/'fresh_network.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), entry.PINS[SOURCE])
        with tempfile.TemporaryDirectory(prefix='loader-regression-') as d:
            root = Path(d)
            target = root/SOURCE.lstrip('/')
            target.parent.mkdir(parents=True)
            target.write_bytes(raw + (b'\nraise AssertionError("UNPINNED_EXECUTION")\n' if wrong_bytes else b''))
            target.chmod(0o644)
            for directory in (root, root/'usr', root/'usr/local', target.parent):
                directory.chmod(0o755)
            yield root, entry, target

    def assert_checked_boundary(self, observed):
        self.assertEqual(observed['reads'], 1)
        self.assertEqual(observed['afterStats'], 1)
        return {key for key in FIELDS if observed['before'][key] != observed['after'][key]}

    def test_exact_pinned_bytes_execute_after_read_atime_only_change(self):
        with self.fixture() as (root, entry, target):
            with checked_read(root, entry, target) as observed:
                try:
                    module = entry.load(SOURCE)
                except RuntimeError as exc:
                    self.assertEqual(self.assert_checked_boundary(observed), {'st_atime', 'st_atime_ns'})
                    self.assertEqual(observed['rawSha256'], entry.PINS[SOURCE])
                    self.fail('exact pinned bytes with only read-atime drift must execute; loader refused: '+str(exc))
            self.assertEqual(self.assert_checked_boundary(observed), {'st_atime', 'st_atime_ns'})
            self.assertEqual(observed['rawSha256'], entry.PINS[SOURCE])
            self.assertEqual(module.B132_MACHINE, '03ab697936cc4040aa9357936e136744')
            self.assertTrue(callable(module.Controller))

    def test_each_stable_metadata_change_refuses_at_actual_load_boundary(self):
        for field in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
                      'st_size', 'st_mtime_ns', 'st_ctime_ns'):
            with self.subTest(controlled_fstat_field=field), self.fixture() as (root, entry, target):
                with checked_read(root, entry, target, field) as observed:
                    with self.assertRaisesRegex(RuntimeError, '^INSTALLED_SOURCE_PIN_REQUIRED$'):
                        entry.load(SOURCE)
                self.assertEqual(self.assert_checked_boundary(observed), {'st_atime', 'st_atime_ns', field})
                self.assertEqual(observed['rawSha256'], entry.PINS[SOURCE])

    def test_wrong_real_file_bytes_refuse_before_compilation(self):
        with self.fixture(wrong_bytes=True) as (root, entry, target):
            with checked_read(root, entry, target) as observed:
                with self.assertRaisesRegex(RuntimeError, '^INSTALLED_SOURCE_PIN_REQUIRED$'):
                    entry.load(SOURCE)
            self.assertEqual(self.assert_checked_boundary(observed), {'st_atime', 'st_atime_ns'})
            self.assertNotEqual(observed['rawSha256'], entry.PINS[SOURCE])


if __name__ == '__main__':
    unittest.main()
