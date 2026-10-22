"""Offline tests only: no installed paths, processes, services or network touched."""
import os
from pathlib import Path
import hashlib
import json
import shutil
import stat
import subprocess
import sys
from contextlib import ExitStack
from unittest.mock import patch
import tempfile
import unittest

import fresh_install_source_pack as pack

SCRATCH = Path('/home/leon/.hermes/cache/scratch')


class Fixture:
    """Real disposable Git/filesystem; tiny candidate pins are TEST-ONLY replacements.

    No fabricated application/runtime is ever presented as actual-candidate proof.
    Production CLI has no pin/count/closure override.
    """
    def __enter__(self):
        self.stack = ExitStack()
        tmp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='sourcepack-fixture-', dir=SCRATCH))
        self.root = Path(tmp)
        self.repo = self.root/'repo'
        self.repo.mkdir()
        actual = Path(__file__).resolve().parents[2]
        for name in set(pack.HOST_SOURCES) | {'index.js'}:
            src = actual/name
            dest = self.repo/name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            dest.chmod(stat.S_IMODE(src.stat().st_mode))
        def git(*args):
            return subprocess.check_output(['/usr/bin/git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL)
        self.git = git
        git('init', '-q')
        git('-c', 'user.name=Offline fixture', '-c', 'user.email=fixture@invalid', 'add', '.')
        git('-c', 'user.name=Offline fixture', '-c', 'user.email=fixture@invalid', 'commit', '-qm', 'fixture')
        self.commit = git('rev-parse', 'HEAD').decode().strip()
        self.candidate = self.root/'candidate'
        self.candidate.mkdir(mode=0o700)
        image = self.candidate/'root'
        image.mkdir(mode=0o755)
        self.manifest = {}
        entries = {'/app/index.js': (self.repo/'index.js').read_bytes(),
                   '/app/package.json': (self.repo/'package.json').read_bytes(),
                   '/app/package-lock.json': (self.repo/'package-lock.json').read_bytes(),
                   '/app/node_modules/mongoose/package.json': b'{"fixture":true}',
                   '/runtime/node': b'fixture-node-not-executable',
                   '/usr/bin/python3': b'fixture-python-not-executable',
                   '/lib64/ld-linux-x86-64.so.2': b'fixture-loader-not-executable',
                   '/etc/classic.json': b'private-fixture-settings'}
        entries.update({key: (self.repo/value).read_bytes() for key, value in pack.SUPERVISORS.items()})
        for key, raw in entries.items():
            dest = image/key[1:]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            dest.chmod(0o644)
            self.manifest[key] = pack.sha(raw)
        (image/'empty-preserved').mkdir()
        self.counts = dict(sourceFiles=6, dependencyFiles=1, runtimeFiles=3, elfFiles=0,
                           payloadFiles=len(entries), installedPackages=1, lockPackages=1, expectedOptionalAbsences=0)
        report = dict(schema='c3-classic-root-candidate-report/v1', candidate=True,
                      physicalAccepted=False, runtimeProposal=True, sourceCommit=self.commit,
                      sourceTree=git('rev-parse', 'HEAD^{tree}').decode().strip(), counts=self.counts)
        (self.candidate/'manifest.json').write_bytes(pack.encode(self.manifest))
        (self.candidate/'report.json').write_bytes(pack.encode(report))
        for control in ('manifest.json', 'report.json'):
            (self.candidate/control).chmod(0o644)
        for base, dirs, files in os.walk(image):
            Path(base).chmod(0o755)
        self.output = self.root/'pack'
        modes = {key: stat.S_IMODE((image/key[1:]).stat().st_mode) for key in entries}
        directories = {'/': 0o755}
        directories.update({'/' + p.relative_to(image).as_posix(): 0o755 for p in image.rglob('*') if p.is_dir()})
        for key, value in dict(BASE=self.commit, BUILT_FROM=self.commit, COUNTS=self.counts,
                               MODE_PIN=pack.sha(pack.encode(modes)), DIRECTORY_PIN=pack.sha(pack.encode(directories)),
                               MANIFEST_PIN=pack.sha((self.candidate/'manifest.json').read_bytes()),
                               REPORT_PIN=pack.sha((self.candidate/'report.json').read_bytes())).items():
            self.stack.enter_context(patch.object(pack, key, value))
        return self

    def build(self):
        return pack.build(str(self.repo), str(self.candidate), str(self.output))

    def assert_no_stage(self, test):
        test.assertFalse(self.output.exists())
        test.assertEqual(list(self.root.glob('.pack.partial-*')), [])

    def __exit__(self, *args):
        return self.stack.__exit__(*args)


class PublicationTests(unittest.TestCase):
    def test_linux_noreplace_preserves_racing_empty_winner(self):
        self.assertIsNotNone(pack, 'fixed offline source-pack implementation missing')
        with tempfile.TemporaryDirectory(prefix='sourcepack-test-', dir=SCRATCH) as tmp:
            root = Path(tmp)
            (root/'stage').mkdir()
            (root/'stage'/'owned').write_bytes(b'owned')
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                # An empty destination is the case ordinary rename would overwrite.
                (root/'winner').mkdir()
                inode = (root/'winner').stat().st_ino
                with self.assertRaisesRegex(pack.Refusal, 'OUTPUT_EXISTS'):
                    pack.publish_noreplace(fd, 'stage', 'winner')
                self.assertEqual((root/'winner').stat().st_ino, inode)
                self.assertEqual(list((root/'winner').iterdir()), [])
                self.assertEqual((root/'stage'/'owned').read_bytes(), b'owned')
            finally:
                os.close(fd)


class BuildTests(unittest.TestCase):
    def test_private_complete_fixed_pack_has_no_fabricated_policy(self):
        self.assertTrue(hasattr(pack, 'build'), 'fixed pack builder missing')
        with Fixture() as f:
            result = pack.build(str(f.repo), str(f.candidate), str(f.output))
            self.assertEqual(result, f.output)
            report = json.loads((f.output/'report.json').read_text())
            self.assertIs(report['physicalAccepted'], False)
            self.assertIs(report['operationalGO'], False)
            self.assertEqual(report['candidateBuiltFrom'], f.commit)
            bootstrap = json.loads((f.output/'bootstrap-files.json').read_text())
            self.assertEqual(bootstrap, f.manifest)
            self.assertNotIn('inventory', bootstrap)
            self.assertNotIn('/etc/c3-test-fresh-classic.json', bootstrap)
            self.assertEqual((f.output/'candidate'/'root'/'etc'/'classic.json').read_bytes(), b'private-fixture-settings')
            self.assertNotIn('private-fixture-settings', (f.output/'report.json').read_text())
            self.assertEqual(stat.S_IMODE(f.output.stat().st_mode), 0o700)
            self.assertTrue((f.output/'candidate'/'root'/'empty-preserved').is_dir())
            self.assertEqual(stat.S_IMODE((f.output/'candidate'/'root').stat().st_mode), 0o755)
            self.assertEqual(pack.verify_pack(str(f.output))['physicalAccepted'], False)
            (f.output/'unlisted-empty').mkdir(mode=0o700)
            with self.assertRaisesRegex(pack.Refusal, 'PACK_CONTENT_DRIFT'):
                pack.verify_pack(str(f.output))


class RefusalTests(unittest.TestCase):
    def test_malformed_paths_rejected_before_any_write(self):
        for bad in ('relative', '/a/../b', '/a/./b', '/a//b', '/a/', '/a\x00b', '/a\nb'):
            with self.subTest(bad=repr(bad)), self.assertRaises(pack.Refusal):
                pack.build(bad, bad, bad)

    def test_duplicate_nonfinite_and_bad_utf8_json(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'\xff'):
            with self.subTest(raw=repr(raw)), self.assertRaises(pack.Refusal):
                pack.decode(raw)

    def test_candidate_changed_missing_extra_and_wrong_mode(self):
        for fault in ('changed', 'missing', 'extra', 'symlink', 'hardlink', 'fifo', 'mode', 'xattr'):
            with self.subTest(fault=fault), Fixture() as f:
                target = f.candidate/'root'/'runtime'/'node'
                if fault == 'changed': target.write_bytes(b'drift')
                elif fault == 'missing': target.unlink()
                elif fault == 'extra':
                    target = target.with_name('extra'); target.write_bytes(b'extra'); target.chmod(0o644)
                elif fault == 'symlink':
                    target.unlink(); target.symlink_to(f.repo/'index.js')
                elif fault == 'hardlink': os.link(target, f.root/'second-link')
                elif fault == 'fifo': target.unlink(); os.mkfifo(target)
                elif fault == 'mode': target.chmod(0o755 | stat.S_ISUID)
                elif fault == 'xattr': os.setxattr(target, 'user.sourcepack-test', b'no')
                with self.assertRaises(pack.Refusal): f.build()
                f.assert_no_stage(self)

    def test_candidate_executable_mode_and_empty_directory_membership_are_exact(self):
        for fault in ('executable-mode', 'empty-directory'):
            with self.subTest(fault=fault), Fixture() as f:
                if fault == 'executable-mode':
                    (f.candidate/'root'/'runtime'/'node').chmod(0o755)
                else:
                    target = f.candidate/'root'/'unaccepted-empty'; target.mkdir(); target.chmod(0o755)
                with self.assertRaises(pack.Refusal): f.build()
                f.assert_no_stage(self)

    def test_control_pin_and_provenance_refusal(self):
        for fault in ('manifest', 'report', 'provenance', 'source-mismatch', 'escape'):
            with self.subTest(fault=fault), Fixture() as f:
                if fault in ('manifest', 'report'):
                    (f.candidate/(fault + '.json')).write_bytes(b'{}')
                elif fault == 'provenance':
                    doc = json.loads((f.candidate/'report.json').read_bytes()); doc['sourceCommit'] = '0'*40
                    raw = pack.encode(doc); (f.candidate/'report.json').write_bytes(raw)
                    f.stack.enter_context(patch.object(pack, 'REPORT_PIN', pack.sha(raw)))
                else:
                    doc = dict(f.manifest)
                    if fault == 'escape': doc['/app/../escaped'] = doc.pop('/app/index.js')
                    else:
                        (f.candidate/'root'/'app'/'index.js').write_bytes(b'not committed')
                        doc['/app/index.js'] = pack.sha(b'not committed')
                    raw = pack.encode(doc); (f.candidate/'manifest.json').write_bytes(raw)
                    f.stack.enter_context(patch.object(pack, 'MANIFEST_PIN', pack.sha(raw)))
                with self.assertRaises(pack.Refusal): f.build()
                f.assert_no_stage(self)

    def test_missing_dirty_hidden_dirty_noncommitted_and_committed_drift_sources(self):
        for fault in ('missing', 'dirty', 'hidden-dirty', 'noncommitted', 'committed-drift'):
            with self.subTest(fault=fault), Fixture() as f:
                name = pack.PREFIX + 'coordinated_fresh_restore.py'
                target = f.repo/name
                if fault == 'missing': target.unlink()
                elif fault in ('dirty', 'hidden-dirty', 'committed-drift'):
                    if fault == 'hidden-dirty': f.git('update-index', '--assume-unchanged', name)
                    target.write_bytes(target.read_bytes() + b'\n# drift\n')
                    if fault == 'committed-drift':
                        f.git('add', name)
                        f.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid', 'commit', '-qm', 'drift')
                elif fault == 'noncommitted':
                    f.git('rm', '--cached', name)
                    f.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid', 'commit', '-qm', 'remove')
                    # Ignore the no-longer-tracked file to reach the committed-blob refusal.
                    (f.repo/'.git'/'info'/'exclude').write_text(name + '\n')
                with self.assertRaises(pack.Refusal): f.build()
                f.assert_no_stage(self)

    def test_symlink_ancestors_never_followed(self):
        for which in ('repo', 'candidate', 'output', 'source-directory', 'root-directory', 'control'):
            with self.subTest(which=which), Fixture() as f:
                if which in ('repo', 'candidate'):
                    original = getattr(f, which); original.rename(f.root/'real'); original.symlink_to(f.root/'real', target_is_directory=True)
                elif which == 'output': f.output.symlink_to(f.root/'outside')
                elif which == 'source-directory':
                    original = f.repo/'src'; original.rename(f.root/'real-src'); original.symlink_to(f.root/'real-src', target_is_directory=True)
                elif which == 'root-directory':
                    original = f.candidate/'root'/'app'; original.rename(f.root/'real-app'); original.symlink_to(f.root/'real-app', target_is_directory=True)
                elif which == 'control':
                    original = f.candidate/'manifest.json'; original.rename(f.root/'real-manifest'); original.symlink_to(f.root/'real-manifest')
                with self.assertRaises(pack.Refusal): f.build()
                self.assertEqual(list(f.root.glob('.pack.partial-*')), [])

    def test_input_namespace_replacement_after_export_is_refused(self):
        with Fixture() as f:
            real = pack.write_file
            def swap(fd, name, raw, mode=0o600):
                real(fd, name, raw, mode)
                if name == 'pack-manifest.json':
                    f.candidate.rename(f.root/'old-candidate')
                    shutil.copytree(f.root/'old-candidate', f.candidate)
            with patch.object(pack, 'write_file', side_effect=swap), self.assertRaisesRegex(pack.Refusal, 'INPUT_DIRECTORY_CHANGED|CANDIDATE_CONTROL_CHANGED'):
                f.build()
            f.assert_no_stage(self)

    def test_late_source_and_candidate_byte_changes_refuse_and_cleanup(self):
        for which in ('source', 'candidate', 'control-same-bytes', 'source-metadata'):
            with self.subTest(which=which), Fixture() as f:
                real = pack.write_file
                def mutate(fd, name, raw, mode=0o600):
                    real(fd, name, raw, mode)
                    if name == 'pack-manifest.json':
                        target = f.repo/pack.PREFIX/'coordinated_fresh_restore.py' if which.startswith('source') else f.candidate/'root'/'runtime'/'node'
                        if which == 'control-same-bytes':
                            target = f.candidate/'report.json'; contents = target.read_bytes(); target.unlink(); target.write_bytes(contents); target.chmod(0o644)
                        elif which == 'source-metadata':
                            st = target.stat(); os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns+1000000))
                        else: target.write_bytes(target.read_bytes() + b'changed')
                with patch.object(pack, 'write_file', side_effect=mutate), self.assertRaises(pack.Refusal):
                    f.build()
                f.assert_no_stage(self)

    def test_output_parent_must_be_private_and_no_symlink_ancestors(self):
        with Fixture() as f:
            f.root.chmod(0o755)
            with self.assertRaisesRegex(pack.Refusal, 'PRIVATE_OUTPUT_PARENT_REQUIRED'): f.build()
            f.root.chmod(0o700)
            link = f.root/'alias'; link.symlink_to(f.root, target_is_directory=True)
            with self.assertRaises(pack.Refusal):
                pack.build(str(f.repo), str(f.candidate), str(link/'pack'))
            f.assert_no_stage(self)


class FaultTests(unittest.TestCase):
    def test_existing_and_racing_empty_destination_are_not_overwritten(self):
        for race in (False, True):
            with self.subTest(race=race), Fixture() as f:
                real = pack.publish_noreplace
                winner = []
                def publish(fd, stage, output):
                    f.output.mkdir(mode=0o700); winner.append(f.output.stat().st_ino)
                    real(fd, stage, output)
                if not race:
                    f.output.mkdir(mode=0o700); winner.append(f.output.stat().st_ino)
                with patch.object(pack, 'publish_noreplace', side_effect=publish), self.assertRaisesRegex(pack.Refusal, 'OUTPUT_EXISTS'):
                    f.build()
                self.assertEqual(f.output.stat().st_ino, winner[0])
                self.assertEqual(list(f.output.iterdir()), [])
                self.assertEqual(list(f.root.glob('.pack.partial-*')), [])

    def test_late_real_partial_report_write_failure_cleans_only_stage(self):
        with Fixture() as f:
            unrelated = f.root/'unrelated'; unrelated.write_bytes(b'retain')
            original = os.fdopen
            class BrokenWriter:
                def __init__(self, stream): self.stream = stream
                def __enter__(self): return self
                def __exit__(self, *args): self.stream.close()
                def write(self, raw):
                    self.stream.write(raw[:11]); self.stream.flush()
                    raise OSError('private-fixture-settings must never leak')
            def fdopen(fd, *args, **kwargs):
                stream = original(fd, *args, **kwargs)
                path = os.readlink('/proc/self/fd/' + str(fd))
                return BrokenWriter(stream) if path.endswith('/report.json') and '.partial-' in path and '/candidate/' not in path else stream
            with patch.object(pack.os, 'fdopen', side_effect=fdopen), self.assertRaisesRegex(pack.Refusal, '^PACK_BUILD_REFUSED$'):
                f.build()
            f.assert_no_stage(self)
            self.assertEqual(unrelated.read_bytes(), b'retain')

    def test_late_file_and_directory_fsync_failures_never_publish(self):
        for which in ('file', 'directory'):
            with self.subTest(which=which), Fixture() as f:
                real = os.fsync
                def fsync(fd):
                    real(fd)  # Real Linux fd and fsync, then injected failure at the boundary.
                    path = os.readlink('/proc/self/fd/' + str(fd))
                    late_file = path.endswith('/pack-manifest.json')
                    late_dir = stat.S_ISDIR(os.fstat(fd).st_mode) and '.partial-' in path
                    if (which == 'file' and late_file) or (which == 'directory' and late_dir):
                        raise OSError('injected fsync failure')
                with patch.object(pack.os, 'fsync', side_effect=fsync), self.assertRaises(pack.Refusal): f.build()
                f.assert_no_stage(self)

    def test_postrename_parent_fsync_failure_is_unknown_and_output_retained(self):
        with Fixture() as f:
            real = os.fsync
            def fsync(fd):
                real(fd)
                st = os.fstat(fd)
                if f.output.exists() and (st.st_dev, st.st_ino) == (f.root.stat().st_dev, f.root.stat().st_ino):
                    raise OSError('after rename')
            with patch.object(pack.os, 'fsync', side_effect=fsync), self.assertRaisesRegex(pack.Refusal, 'PUBLICATION_DURABILITY_OR_READBACK_UNKNOWN'):
                f.build()
            self.assertTrue(f.output.is_dir())
            self.assertIs(pack.verify_pack(str(f.output))['operationalGO'], False)
            with self.assertRaisesRegex(pack.Refusal, 'OUTPUT_EXISTS'): f.build()

    def test_owned_stage_replacement_is_not_deleted(self):
        with Fixture() as f:
            real = pack.fsync_tree
            saved = []
            def swap(fd):
                real(fd)
                if not saved:
                    # Replace only the outer owned stage, after its real recursive fsync.
                    path = Path(os.readlink('/proc/self/fd/' + str(fd)))
                    if path.parent == f.root:
                        retained = f.root/'retained-owned-stage'; path.rename(retained)
                        path.mkdir(mode=0o700); (path/'foreign').write_bytes(b'foreign')
                        saved.append(path)
            with patch.object(pack, 'fsync_tree', side_effect=swap), self.assertRaisesRegex(pack.Refusal, 'OWNED_STAGE_CHANGED'):
                f.build()
            self.assertEqual((saved[0]/'foreign').read_bytes(), b'foreign')
            self.assertTrue((f.root/'retained-owned-stage'/'pack-manifest.json').is_file())
            self.assertFalse(f.output.exists())

    def test_published_readback_failure_is_unknown_not_rollback(self):
        with Fixture() as f:
            real = pack.verify_pack_fd
            calls = []
            def verify(fd):
                calls.append(fd)
                if f.output.exists(): raise OSError('published readback failed')
                return real(fd)
            with patch.object(pack, 'verify_pack_fd', side_effect=verify), self.assertRaisesRegex(pack.Refusal, 'PUBLICATION_DURABILITY_OR_READBACK_UNKNOWN'):
                f.build()
            self.assertTrue(f.output.is_dir())
            self.assertIs(pack.verify_pack(str(f.output))['operationalGO'], False)

    def test_rename_completed_but_wrapper_lost_reply_retains_output_unknown(self):
        with Fixture() as f:
            real = pack.publish_noreplace
            def lose(fd, stage, output):
                real(fd, stage, output)
                raise OSError('private-fixture-settings')
            with patch.object(pack, 'publish_noreplace', side_effect=lose), self.assertRaisesRegex(pack.Refusal, 'PUBLICATION.*UNKNOWN'):
                f.build()
            self.assertTrue(f.output.is_dir())
            self.assertFalse(list(f.root.glob('.pack.partial-*')))

    def test_cleanup_failure_is_redacted_and_retains_unpublished_stage(self):
        with Fixture() as f:
            real = pack.write_file
            def fail(fd, name, raw, mode=0o600):
                real(fd, name, raw, mode)
                if name == 'report.json': raise OSError('private-fixture-settings')
            with patch.object(pack, 'write_file', side_effect=fail), patch.object(pack.shutil, 'rmtree', side_effect=OSError('private-fixture-settings')):
                with self.assertRaisesRegex(pack.Refusal, '^PACK_CLEANUP_REFUSED$'):
                    f.build()
            self.assertFalse(f.output.exists())
            self.assertEqual(len(list(f.root.glob('.pack.partial-*'))), 1)

    def test_cli_refusals_redact_input_oserror_values(self):
        with Fixture() as f:
            proc = subprocess.run([sys.executable, '-I', '-B', str(Path(pack.__file__)),
                '--repo', str(f.repo), '--candidate', str(f.candidate),
                '--output', str(f.root/'private-fixture-settings'/'pack')],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, b'')
            self.assertEqual(proc.stderr, b'REFUSAL PACK_BUILD_REFUSED\n')


class GitTrustTests(unittest.TestCase):
    def test_repo_state_and_cli_never_execute_repository_clean_filter(self):
        from shlex import quote
        with Fixture() as f:
            marker = f.root/'clean-filter-executed'
            hook = f.root/'clean-hook'
            hook.write_text('#!/bin/sh\nprintf executed > ' + quote(str(marker)) + '\n/bin/cat\n')
            hook.chmod(0o700)
            name = pack.PREFIX + 'owner_restoration_channel.py'
            target = f.repo/name
            original = target.read_bytes()
            (f.repo/'.git/info/attributes').write_text(name + ' filter=arbitrary-review-name\n')
            f.git('config', 'filter.arbitrary-review-name.clean', str(hook))
            f.git('config', 'filter.arbitrary-review-name.required', 'true')

            def touch():
                info = target.stat()
                os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))

            touch()
            f.git('status', '--porcelain=v1')
            self.assertTrue(marker.is_file(), 'positive control did not execute clean filter')
            marker.unlink()
            touch()
            with self.subTest('repo_state'):
                pack.repo_state(str(f.repo))
                self.assertFalse(marker.exists(), 'repo_state executed repository clean filter')
            marker.unlink(missing_ok=True)
            touch()
            proc = subprocess.run([sys.executable, '-I', '-B', str(Path(pack.__file__)),
                '--repo', str(f.repo), '--candidate', str(f.candidate),
                '--output', str(f.output)], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stderr, b'REFUSAL GIT_REFUSED\n')
            self.assertFalse(marker.exists(), 'exact production CLI executed repository clean filter')
            self.assertEqual(target.read_bytes(), original)
            f.assert_no_stage(self)

    def test_raw_cleanliness_rejects_hidden_bytes_modes_index_and_untracked_files(self):
        for kind in ('assume-unchanged', 'skip-worktree', 'mode', 'index', 'untracked'):
            with self.subTest(kind), Fixture() as f:
                name = pack.PREFIX + 'owner_restoration_channel.py'
                target = f.repo/name
                self.assertEqual(pack.repo_state(str(f.repo))[0], f.commit)
                if kind in ('assume-unchanged', 'skip-worktree'):
                    f.git('update-index', '--' + kind, name)
                    target.write_bytes(target.read_bytes() + b'\n# changed raw bytes\n')
                    self.assertEqual(f.git('status', '--porcelain=v1'), b'')
                elif kind == 'mode':
                    f.git('config', 'core.filemode', 'false')
                    target.chmod(0o644 if target.stat().st_mode & 0o111 else 0o755)
                    self.assertEqual(f.git('status', '--porcelain=v1'), b'')
                elif kind == 'index':
                    oid = subprocess.check_output(['/usr/bin/git', '-C', str(f.repo),
                        'hash-object', '-w', '--stdin'], input=b'foreign staged bytes').decode().strip()
                    mode = f.git('ls-files', '--stage', '--', name).split()[0].decode()
                    f.git('update-index', '--cacheinfo', mode, oid, name)
                else:
                    (f.repo/'foreign-untracked').write_bytes(b'not committed')
                with self.assertRaisesRegex(pack.Refusal, 'DIRTY_SOURCE'):
                    pack.repo_state(str(f.repo))
                f.assert_no_stage(self)

    def test_raw_cleanliness_refuses_committed_symlinks_and_submodules(self):
        for kind in ('symlink', 'submodule'):
            with self.subTest(kind), Fixture() as f:
                if kind == 'symlink':
                    (f.repo/'foreign-entry').symlink_to('index.js')
                    f.git('add', 'foreign-entry')
                else:
                    f.git('update-index', '--add', '--cacheinfo', '160000', f.commit, 'foreign-entry')
                f.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid', 'commit', '-qm', kind)
                with self.assertRaisesRegex(pack.Refusal, 'SOURCE_NOT_REGULAR_COMMITTED'):
                    pack.repo_state(str(f.repo))
                f.assert_no_stage(self)

    def test_repo_state_and_cli_never_execute_repository_process_filter(self):
        from shlex import quote
        with Fixture() as f:
            marker = f.root/'process-filter-executed'
            hook = f.root/'process-hook'
            hook.write_text('#!/bin/sh\nprintf executed > ' + quote(str(marker)) + '\nexit 1\n')
            hook.chmod(0o700)
            name = pack.PREFIX + 'owner_restoration_channel.py'
            target = f.repo/name
            (f.repo/'.git/info/attributes').write_text(name + ' filter=another-name\n')
            f.git('config', 'filter.another-name.process', str(hook))
            f.git('config', 'filter.another-name.required', 'true')
            info = target.stat()
            os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
            control = subprocess.run(['/usr/bin/git', '-C', str(f.repo), 'status', '--porcelain=v1'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertNotEqual(control.returncode, 0)
            self.assertTrue(marker.is_file(), 'positive control did not execute process filter')
            marker.unlink()
            self.assertEqual(pack.repo_state(str(f.repo))[0], f.commit)
            self.assertFalse(marker.exists())
            proc = subprocess.run([sys.executable, '-I', '-B', str(Path(pack.__file__)),
                '--repo', str(f.repo), '--candidate', str(f.candidate),
                '--output', str(f.output)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stderr, b'REFUSAL GIT_REFUSED\n')
            self.assertFalse(marker.exists(), 'exact production CLI executed repository process filter')
            f.assert_no_stage(self)

    def test_repo_state_and_cli_never_execute_repository_fsmonitor(self):
        from shlex import quote
        with Fixture() as f:
            marker = f.root/'fsmonitor-executed'
            hook = f.root/'fsmonitor-hook'
            hook.write_text('#!/bin/sh\nprintf executed > ' + quote(str(marker)) +
                            '\nprintf "token\\0"\n')
            hook.chmod(0o700)
            f.git('config', 'core.fsmonitor', str(hook))
            # Prove the local Git hook is executable without production overrides.
            f.git('status', '--porcelain=v1')
            self.assertTrue(marker.is_file())
            marker.unlink()
            pack.repo_state(str(f.repo))
            self.assertFalse(marker.exists(), 'repo-local fsmonitor executed before source validation')
            proc = subprocess.run([sys.executable, '-I', '-B', str(Path(pack.__file__)),
                '--repo', str(f.repo), '--candidate', str(f.candidate),
                '--output', str(f.output)], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(proc.returncode, 2)  # Tiny fixture lacks the real fixed BASE.
            self.assertEqual(proc.stderr, b'REFUSAL GIT_REFUSED\n')
            self.assertFalse(marker.exists(), 'production CLI executed repo-local fsmonitor')
            f.assert_no_stage(self)

    def test_fixed_commit_reads_ignore_replace_refs_and_reject_replaced_worktree(self):
        with Fixture() as f:
            name = pack.PREFIX + 'owner_restoration_channel.py'
            original = (f.repo/name).read_bytes()
            oid = f.git('rev-parse', f.commit + ':' + name).decode().strip()
            replacement = b'# inert replacement object regression\n'
            new_oid = subprocess.check_output(['/usr/bin/git', '-C', str(f.repo),
                'hash-object', '-w', '--stdin'], input=replacement).decode().strip()
            f.git('replace', oid, new_oid)
            self.assertEqual(f.git('cat-file', 'blob', oid), replacement)
            (f.repo/name).write_bytes(replacement)
            raw, _ = pack.committed(str(f.repo), f.commit, name)
            self.assertEqual(raw, original, 'fixed revision returned replacement object bytes')
            fd = pack.open_directory(str(f.repo))
            try:
                with self.assertRaisesRegex(pack.Refusal, 'SOURCE_WORKTREE_DRIFT'):
                    pack.source_bytes(str(f.repo), fd, f.commit, name)
            finally:
                os.close(fd)
            f.assert_no_stage(self)


class ClosureTests(unittest.TestCase):
    def test_exact_js_literal_and_dynamic_model_import_closure(self):
        import posixpath
        import re
        root = Path(__file__).resolve().parents[2]
        pending = [pack.PREFIX + 'settle-fresh-held-owner.js']
        seen, external, dynamic = set(), set(), set()
        while pending:
            name = pending.pop()
            if name in seen: continue
            seen.add(name)
            raw = (root/name).read_text()
            requires = re.findall(r'''require\(\s*['"]([^'"]+)['"]\s*\)''', raw)
            if name == pending_entry():
                requires += re.findall(r'''bind\([^,]+,\s*['"]([^'"]+)['"]\)''', raw)
            if re.search(r'''require\((?!\s*['"])''', raw): dynamic.add(name)
            for spec in requires:
                if spec.startswith('.'):
                    target = posixpath.normpath(posixpath.join(posixpath.dirname(name), spec))
                    pending.append(target if target.endswith('.js') else target + '.js')
                else: external.add(spec)
        self.assertEqual(seen, set(pack.JS_SOURCES))
        self.assertEqual(dynamic, {pending_entry()})
        self.assertEqual(external, {'mongoose', 'node:child_process', 'node:crypto', 'node:fs', 'node:path', 'node:util'})
        self.assertEqual(len(set(pack.HOST_SOURCES.values())), len(pack.HOST_SOURCES))


def pending_entry():
    return pack.PREFIX + 'settle-fresh-held-owner.js'


if __name__ == '__main__':
    unittest.main()
