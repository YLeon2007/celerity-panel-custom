"""Focused real immutable-payload regression; no DB, main, npm or network."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PACK = '/home/leon/celerity-prod-release-20261019/full-production-20261023/runner-v2-ppp-mode-pack-child/pack-fixed-runner-v2-v2'
EVIDENCE = Path(os.environ['OWNER_RUNTIME_EVIDENCE'])
spec = importlib.util.spec_from_file_location('owner_node_dependencies', HERE/'owner_node_dependencies.py')
assert spec is not None and spec.loader is not None
product = importlib.util.module_from_spec(spec)
spec.loader.exec_module(product)
NODE = shutil.which('node')
assert NODE is not None, 'local Node executable required'


class OwnerDependenciesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=EVIDENCE)
        self.root = Path(self.temp.name)/'owner'
        self.root.mkdir(mode=0o700)
        fd = product.io.open_directory(PACK)
        try:
            for source, entry in product.owner_sources().items():
                raw, _ = product.io.read_file(fd, 'host-source'+entry['installed'])
                dest = self.root/source
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw)
                dest.chmod(entry['modeIntent'])
        finally:
            os.close(fd)

    def tearDown(self):
        self.temp.cleanup()

    def probe(self):
        script = """
const path = require('path');
const {createRequire} = require('module');
const root = process.argv[1];
const req = createRequire(path.join(root, 'scripts/test-node-isolation/settle-fresh-held-owner.js'));
const resolved = req.resolve('mongoose');
if (!resolved.startsWith(root+'/node_modules/')) throw Error('foreign dependency');
const mongoose = req('mongoose');
if (mongoose.connection.readyState !== 0) throw Error('unexpected connection');
for (const source of JSON.parse(process.argv[2])) req(path.join(root, source));
if (mongoose.connection.readyState !== 0) throw Error('unexpected connection');
console.log(JSON.stringify({resolved, version:mongoose.version, loadedSources:JSON.parse(process.argv[2]).length, dbConnected:false, mainInvoked:false}));
"""
        sources = [s for s in product.owner_sources() if s.endswith('.js')]
        return subprocess.run([NODE, '--no-addons', '-e', script, str(self.root), json.dumps(sources)],
                              env={'PATH':'/usr/bin:/bin','HOME':str(self.root)}, capture_output=True, text=True, timeout=30)

    def test_original_missing_dependency_then_real_resolution_and_load(self):
        before = self.probe()
        self.assertNotEqual(before.returncode, 0)
        self.assertIn('MODULE_NOT_FOUND', before.stderr)
        delivered = subprocess.run([sys.executable, '-I', '-B', str(HERE/'owner_node_dependencies.py'),
                                    '--pack', PACK, '--owner-root', str(self.root)],
                                   capture_output=True, text=True, timeout=120)
        self.assertEqual(delivered.returncode, 0, delivered.stderr)
        report = json.loads(delivered.stdout)
        self.assertEqual(report['dependencyFiles'], 9509)
        self.assertFalse(report['installedAccepted'])
        after = self.probe()
        self.assertEqual(after.returncode, 0, after.stderr)
        print('NODE_LOAD '+after.stdout.strip())
        print('STAGE_REPORT '+json.dumps(report, sort_keys=True))
        with self.assertRaisesRegex(product.io.Refusal, '^OUTPUT_EXISTS$'):
            product.stage(PACK, str(self.root))
        self.assertEqual(self.probe().returncode, 0)

    def test_lock_and_source_mismatch_refused(self):
        for source in ('package-lock.json', 'scripts/test-node-isolation/settle-fresh-held-owner.js'):
            path = self.root/source
            raw = path.read_bytes()
            path.write_bytes(raw+b'\n')
            with self.assertRaisesRegex(product.io.Refusal, '^OWNER_SOURCE_MISMATCH$'):
                product.stage(PACK, str(self.root))
            self.assertFalse((self.root/'node_modules').exists())
            path.write_bytes(raw)

    def test_existing_empty_directory_and_symlink_preserved(self):
        target = self.root/'node_modules'
        target.mkdir()
        with self.assertRaisesRegex(product.io.Refusal, '^OUTPUT_EXISTS$'):
            product.stage(PACK, str(self.root))
        target.rmdir()
        target.symlink_to(self.root/'absent')
        with self.assertRaisesRegex(product.io.Refusal, '^OUTPUT_EXISTS$'):
            product.stage(PACK, str(self.root))
        self.assertTrue(target.is_symlink())

    def test_donor_manifest_mismatch_refused(self):
        donor = Path(self.temp.name)/'bad-pack'
        donor.mkdir(mode=0o700)
        (donor/'pack-manifest.json').write_text('{}\n')
        (donor/'pack-manifest.json').chmod(0o600)
        with self.assertRaisesRegex(product.io.Refusal, '^DONOR_MANIFEST_MISMATCH$'):
            product.stage(str(donor), str(self.root))
        self.assertFalse((self.root/'node_modules').exists())

    def test_incomplete_or_symlink_dependency_payload_refused(self):
        donor = Path(self.temp.name)/'damaged-pack'
        donor.mkdir(mode=0o700)
        fd = product.io.open_directory(PACK)
        try:
            for name in ('pack-manifest.json', 'candidate/manifest.json', 'candidate/report.json',
                         'profile.json', 'host-dependency-intents.json'):
                raw, _ = product.io.read_file(fd, name)
                dest = donor/name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw)
                dest.chmod(0o600)
        finally:
            os.close(fd)
        deps = donor/'candidate/root/app/node_modules'
        deps.mkdir(parents=True, mode=0o755)
        with self.assertRaisesRegex(product.io.Refusal, '^DEPENDENCY_PAYLOAD_MISMATCH$'):
            product.stage(str(donor), str(self.root))
        (deps/'mongoose').symlink_to(Path(PACK)/'candidate/root/app/node_modules/mongoose')
        with self.assertRaises(product.io.Refusal):
            product.stage(str(donor), str(self.root))
        self.assertFalse((self.root/'node_modules').exists())

    def test_frozen_control_and_dependency_atimes_unchanged(self):
        fd = product.io.open_directory(PACK)
        try:
            for name in ('pack-manifest.json', 'candidate/manifest.json',
                         'candidate/root/app/node_modules/mongoose/package.json'):
                _, before = product.io.read_file(fd, name)
                _, after = product.io.read_file(fd, name)
                self.assertEqual(before.st_atime_ns, after.st_atime_ns)
        finally:
            os.close(fd)

    def test_source_symlink_refused(self):
        path = self.root/'package-lock.json'
        path.unlink()
        path.symlink_to(HERE.parent.parent/'package-lock.json')
        with self.assertRaises((product.io.Refusal, OSError)):
            product.stage(PACK, str(self.root))
        self.assertFalse((self.root/'node_modules').exists())

    def test_atomic_noreplace_racing_winner(self):
        fd = product.io.open_directory(str(self.root))
        try:
            (self.root/'stage').mkdir()
            (self.root/'node_modules').mkdir()
            with self.assertRaisesRegex(product.io.Refusal, '^OUTPUT_EXISTS$'):
                product.io.publish_noreplace(fd, 'stage', 'node_modules')
            self.assertTrue((self.root/'stage').is_dir())
            self.assertTrue((self.root/'node_modules').is_dir())
        finally:
            os.close(fd)


class BootstrapTests(unittest.TestCase):
    def test_cli_bootstrap_disposable_frozen_old_atime(self):
        with tempfile.TemporaryDirectory(dir=EVIDENCE) as temp:
            root = Path(temp)
            names = ('fresh_install_source_pack.py', 'fresh_install_source_pack_runner_v2_v2.py',
                     'fresh_install_source_pack_runner_v2_v2_profile.json')
            for name in (*names, 'owner_node_dependencies.py'):
                source = (Path(os.environ['OWNER_STAGE_SOURCE']) if
                          name == 'owner_node_dependencies.py' and 'OWNER_STAGE_SOURCE' in os.environ
                          else HERE/name)
                fd = os.open(source, os.O_RDONLY | os.O_NOATIME | os.O_NOFOLLOW)
                with os.fdopen(fd, 'rb') as stream:
                    (root/name).write_bytes(stream.read())
                (root/name).chmod(0o400)
                os.utime(root/name, ns=(1_000_000_000, 2_000_000_000))
            before = {name: (root/name).stat().st_atime_ns for name in names}
            run = subprocess.run([sys.executable, '-I', '-B', str(root/'owner_node_dependencies.py'),
                                  '--help'], capture_output=True, text=True, timeout=15)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual({name: (root/name).stat().st_atime_ns for name in names}, before)


class TinyStageFaultTests(unittest.TestCase):
    """Real ordinary directories/FDs; empty synthetic payload, not pack evidence."""
    def run_stage(self, fault):
        import ast
        import errno
        from types import SimpleNamespace

        source = Path(os.environ.get('OWNER_STAGE_SOURCE', HERE/'owner_node_dependencies.py'))
        fd = os.open(source, os.O_RDONLY | os.O_NOATIME | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            tree = ast.parse(stream.read())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'stage')
        class Refusal(Exception):
            pass
        def need(ok, code):
            if not ok:
                raise Refusal(code)
        with tempfile.TemporaryDirectory(dir=EVIDENCE) as temp:
            pack, owner = Path(temp)/'pack', Path(temp)/'owner'
            deps = pack/'candidate/root/app/node_modules'
            deps.mkdir(parents=True)
            owner.mkdir()
            opened, closed, roles = [], [], {}
            replaced = False
            def hold(path, flags, **kw):
                if fault == 'open' and str(path).startswith('.owner-'):
                    raise OSError(errno.EMFILE, 'injected open before allocation')
                result = os.open(path, flags, **kw)
                opened.append(result)
                roles[result] = str(path)
                return result
            def close(fd):
                closed.append(fd)
                os.close(fd)  # Linux has released this FD; never retry an EIO.
                if fault in ('close-success', 'close-refusal') or (
                        fault == 'close-readback' and roles[fd] == 'node_modules'):
                    raise OSError(errno.EIO, 'injected uncertain close reply')
            def fchmod(fd, mode):
                if fault == 'fchmod':
                    raise OSError(errno.EIO, 'injected fchmod')
                os.fchmod(fd, mode)
            def stat_(path, **kw):
                nonlocal replaced
                if fault == 'identity' and str(path).startswith('.owner-'):
                    raise OSError(errno.EIO, 'injected stat')
                result = os.stat(path, **kw)
                if fault == 'foreign' and not replaced and str(path).startswith('.owner-') and len(opened) >= 4:
                    # Actual replacement inode, not impossible fstat fiction.
                    os.rename(path, str(path)+'-retained', src_dir_fd=kw['dir_fd'], dst_dir_fd=kw['dir_fd'])
                    os.mkdir(path, dir_fd=kw['dir_fd'])
                    replaced = True
                    return os.stat(path, **kw)
                return result
            def fsync_tree(fd):
                if fault in ('rmtree', 'close-refusal'):
                    raise Refusal('PRIMARY_REFUSAL')
            def fsync(fd):
                if fault == 'fsync-published':
                    raise OSError(errno.EIO, 'injected postpublish fsync')
                os.fsync(fd)
            def scan(fd, mode):
                if fault == 'readback' and roles[fd] == 'node_modules':
                    raise Refusal('READBACK_REFUSAL')
                return {}, {'': 'snapshot'}
            def rmtree(path, **kw):
                if fault == 'rmtree':
                    raise OSError(errno.EIO, 'injected rmtree')
                shutil.rmtree(path, **kw)
            def publish(fd, src, dst):
                if fault == 'rename-refused':
                    raise Refusal('OUTPUT_EXISTS')
                os.rename(src, dst, src_dir_fd=fd, dst_dir_fd=fd)
                if fault == 'rename-lost':
                    raise OSError(errno.EIO, 'injected lost rename reply')
            fake_os = SimpleNamespace(**{n: getattr(os, n) for n in
                ('listdir', 'mkdir', 'fstat', 'fsync', 'O_RDONLY')})
            fake_os.open, fake_os.close, fake_os.fchmod, fake_os.stat = hold, close, fchmod, stat_
            fake_os.fsync = fsync
            io = SimpleNamespace(Refusal=Refusal, need=need, path_parts=lambda *a: None,
                open_directory=lambda p: hold(p, os.O_RDONLY | os.O_DIRECTORY),
                DIR_FLAGS=os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME,
                scan=scan, directory_modes=lambda s: {'': 0o755},
                fsync_tree=fsync_tree, publish_noreplace=publish)
            fixed = SimpleNamespace(SOURCE='synthetic', SOURCE_TREE='synthetic', PROFILE_PIN='synthetic',
                                    PROFILE={'dependencyPin': 'synthetic'})
            namespace = dict(os=fake_os, io=io, fixed=fixed, uuid=__import__('uuid'),
                shutil=SimpleNamespace(rmtree=rmtree), stat=__import__('stat'),
                checked_owner=lambda fd: {}, donor_controls=lambda fd: ({}, {'': 0o755}),
                same_path=lambda *a: None, DONOR_MANIFEST_PIN='synthetic', LOCK_PIN='synthetic')
            exec(compile(ast.Module(body=[function], type_ignores=[]), '<stage-fault>', 'exec'), namespace)
            error = None
            try:
                namespace['stage'](str(pack), str(owner))
            except Exception as exc:
                error = exc
            result = dict(error=error, names=sorted(p.name for p in owner.iterdir()),
                          opened=opened, closed=closed, roles=roles, Refusal=Refusal)
            # Test harness only: close leaked descriptors after observing kernel state.
            for fd in opened:
                if fd not in closed:
                    os.close(fd)
            return result

    def test_created_stage_open_fchmod_identity_and_foreign_inode(self):
        for fault in ('open', 'fchmod', 'identity', 'foreign'):
            with self.subTest(fault=fault):
                r = self.run_stage(fault)
                self.assertIsInstance(r['error'], r['Refusal'])
                if fault in ('open', 'fchmod'):
                    self.assertEqual(str(r['error']), 'DEPENDENCY_STAGE_REFUSED')
                    self.assertEqual(r['names'], [])
                else:
                    self.assertEqual(str(r['error']), 'DEPENDENCY_CLEANUP_UNKNOWN')
                    self.assertTrue(r['names'])
                self.assertCountEqual(r['closed'], r['opened'])

    def test_close_success_refusal_readback_and_cleanup_errors(self):
        for fault in ('close-success', 'close-refusal', 'close-readback', 'rmtree',
                      'rename-lost', 'rename-refused', 'fsync-published', 'readback'):
            with self.subTest(fault=fault):
                r = self.run_stage(fault)
                self.assertIsInstance(r['error'], r['Refusal'])
                published = fault in ('close-success', 'close-readback', 'rename-lost',
                                      'fsync-published', 'readback')
                expected = ('DEPENDENCY_PUBLICATION_UNKNOWN_RETAIN_OUTPUT' if published else
                            'OUTPUT_EXISTS' if fault == 'rename-refused' else 'DEPENDENCY_CLEANUP_UNKNOWN')
                self.assertEqual(str(r['error']), expected)
                self.assertCountEqual(r['closed'], r['opened'])
                self.assertEqual(len(r['closed']), len(set(r['closed'])))
                if published:
                    self.assertEqual(r['names'], ['node_modules'])
                elif fault == 'rename-refused':
                    self.assertEqual(r['names'], [])
                else:
                    self.assertEqual(str(r['error'].__cause__), 'PRIMARY_REFUSAL')


class OpenDirectoryFaultTests(unittest.TestCase):
    """Execute actual traversal+stage AST; only close-reply failures are injected."""
    def probe(self, final_close) -> dict:
        import ast
        import errno
        from types import SimpleNamespace
        fd = os.open(HERE/'owner_node_dependencies.py', os.O_RDONLY | os.O_NOATIME | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            tree = ast.parse(stream.read())
        nodes: list[ast.stmt] = [n for n in tree.body if isinstance(n, ast.FunctionDef) and
                 n.name in ('open_directory', 'stage')]
        class Refusal(Exception):
            pass
        def need(ok, reason):
            if not ok:
                raise Refusal(reason)
        def parts(path, absolute):
            assert absolute and path.startswith('/')
            return path.split('/')[1:]
        with tempfile.TemporaryDirectory(dir=EVIDENCE) as temp:
            root = Path(temp)
            sentinel = root/'sentinel'
            sentinel.write_bytes(b'disposable independently owned descriptor')
            target_close = len(parts(str(root), True))+1 if final_close else 1
            opened, calls, identities = [], [], []
            replacement = None
            injected = False
            def open_(path, flags, **kw):
                result = os.open(path, flags, **kw)
                opened.append(result)
                info = os.fstat(result)
                identities.append((result, info.st_dev, info.st_ino))
                return result
            def close_(handle):
                nonlocal injected, replacement
                calls.append(handle)
                os.close(handle)  # Linux released it; EIO does not license retry.
                if not injected and len(calls) == target_close:
                    injected = True
                    if not final_close:
                        replacement = os.open(sentinel, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME)
                        assert replacement == handle, 'No real FD reuse; no claim'
                    raise OSError(errno.EIO, 'injected close-after-release reply')
            fake_os = SimpleNamespace(**{n: getattr(os, n) for n in
                ('O_PATH', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC')})
            fake_os.open, fake_os.close = open_, close_
            io = SimpleNamespace(Refusal=Refusal, need=need, path_parts=parts,
                DIR_FLAGS=os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME)
            namespace: dict = dict(os=fake_os, io=io)
            exec(compile(ast.Module(body=nodes, type_ignores=[]), '<actual-traversal-stage>', 'exec'), namespace)
            io.open_directory = namespace['open_directory']
            error = None
            try:
                namespace['stage'](str(root), str(root.parent/(root.name+'-unused-owner')))
            except Exception as exc:
                error = exc
            live_owned = []
            for handle, dev, ino in identities:
                try:
                    now = os.fstat(handle)
                except OSError as exc:
                    assert exc.errno == errno.EBADF
                else:
                    if (now.st_dev, now.st_ino) == (dev, ino):
                        live_owned.append(handle)
            sentinel_alive = None
            if replacement is not None:
                try:
                    now = os.fstat(replacement)
                except OSError as exc:
                    assert exc.errno == errno.EBADF
                    sentinel_alive = False
                else:
                    sentinel_alive = (now.st_dev, now.st_ino) == (sentinel.stat().st_dev, sentinel.stat().st_ino)
            # Dispose only this probe's handles after recording product behavior.
            for handle in set(opened + ([] if replacement is None else [replacement])):
                try:
                    os.fstat(handle)
                except OSError as exc:
                    assert exc.errno == errno.EBADF
                else:
                    os.close(handle)
            return dict(error=error, Refusal=Refusal, opened=opened, calls=calls,
                        live=live_owned, sentinel_alive=sentinel_alive, injected=injected)

    def test_traversal_close_never_retries_reused_fd(self):
        result = self.probe(False)
        self.assertTrue(result['injected'])
        self.assertTrue(result['sentinel_alive'], result)
        self.assertEqual(result['live'], [], result)
        self.assertEqual(len(result['calls']), len(result['opened']), result)
        self.assertIsInstance(result['error'], result['Refusal'])
        self.assertEqual(str(result['error']), 'DEPENDENCY_CLEANUP_UNKNOWN')
        self.assertIsInstance(result['error'].__cause__, OSError)

    def test_final_close_closes_unreturned_read_fd(self):
        result = self.probe(True)
        self.assertTrue(result['injected'])
        self.assertEqual(result['live'], [], result)
        self.assertEqual(len(result['calls']), len(result['opened']), result)
        self.assertIsInstance(result['error'], result['Refusal'])
        self.assertEqual(str(result['error']), 'DEPENDENCY_CLEANUP_UNKNOWN')
        self.assertIsInstance(result['error'].__cause__, OSError)


if __name__ == '__main__':
    unittest.main()
