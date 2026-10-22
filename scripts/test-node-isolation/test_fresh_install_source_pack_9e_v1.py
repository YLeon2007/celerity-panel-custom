"""Real fixed9e artifacts only; no fixture pins or acceptance monkeypatches."""
import importlib.util
import json
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from unittest.mock import patch
import os
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
CANDIDATE=Path('/home/leon/.hermes/cache/scratch/c3-fixed9e-jxaruiv1/candidate')
import fresh_install_source_pack_9e_v1 as product

class Fixed9eTests(unittest.TestCase):
    def test_public_full_pack_readback(self):
        self.assertIsNotNone(product)
        report=product.verify_pack(str(CANDIDATE.parent/'pack-fixed9e-v1'))
        self.assertIs(report['physicalAccepted'],False)
        self.assertIs(report['operationalGO'],False)
        self.assertEqual(report['counts']['payloadFiles'],10518)

    def test_verified_fixed9e_candidate(self):
        self.assertIsNotNone(product, 'explicit versioned fixed9e product is missing')
        self.assertEqual(product.PROFILE['sourceCommit'], '9e1b9897539750c3fef02b98055967d1a7edbbec')
        repo_fd=product.open_directory(str(REPO))
        fd=product.open_directory(str(CANDIDATE))
        try:
            manifest,report,files,snapshot=product.verify_candidate(str(REPO),repo_fd,product.SOURCE,fd)
            self.assertEqual(len(manifest),10518)
            self.assertEqual(report['sourceCommit'],product.SOURCE)
        finally:
            os.close(fd);os.close(repo_fd)


PACK=CANDIDATE.parent/'pack-fixed9e-v1'
OLD=Path('/home/leon/.hermes/cache/scratch/c3-current-root-jaxwrjtj/candidate')
DIAGNOSTIC=Path('/home/leon/.hermes/cache/scratch/c3-cold-causal-ce7760dc/candidate')
SCRATCH=Path('/home/leon/.hermes/cache/scratch')

class FullArtifactAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A byte-for-byte copy of the actual complete public CLI artifact.
        cls.temp=tempfile.TemporaryDirectory(prefix='fixed9e-adversarial-',dir=SCRATCH)
        cls.pack=Path(cls.temp.name)/'full-pack'
        shutil.copytree(PACK,cls.pack)
        cls.cli=[sys.executable,'-B',str(HERE/'fresh_install_source_pack_9e_v1.py'),'--profile','fixed9e-v1']

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextmanager
    def changed(self,*names):
        names=(*names,'pack-manifest.json')
        before={name:((self.pack/name).read_bytes(),stat.S_IMODE((self.pack/name).stat().st_mode))
                if (self.pack/name).exists() else None for name in names}
        try:
            yield
        finally:
            for name,value in before.items():
                target=self.pack/name
                if target.is_symlink() or target.exists():target.unlink()
                if value is not None:
                    target.write_bytes(value[0]);target.chmod(value[1])

    def rehash(self):
        fd=product.open_directory(str(self.pack))
        try:files,snapshot=product.scan(fd)
        finally:os.close(fd)
        files.pop('pack-manifest.json')
        path=self.pack/'pack-manifest.json'
        doc=product.decode(path.read_bytes())
        doc.update(files=files,directories=product.directory_modes(snapshot))
        path.write_bytes(product.encode(doc))

    def reject(self,code=None):
        with self.assertRaisesRegex(product.Refusal,code or '.+'):
            product.verify_pack(str(self.pack))

    def test_public_checker_actual_cli(self):
        r=subprocess.run(self.cli+['check','--pack',str(PACK)],capture_output=True,timeout=90)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn(b'physicalAccepted=false operationalGO=false',r.stdout)

    def test_old_and_samepayload_wrongsource_diagnostic_candidates_refused(self):
        self.assertEqual((DIAGNOSTIC/'manifest.json').read_bytes(),(CANDIDATE/'manifest.json').read_bytes())
        for path in (OLD,DIAGNOSTIC):
            fd=product.open_directory(str(path))
            try:
                with self.assertRaisesRegex(product.Refusal,'CANDIDATE_PIN_MISMATCH'):
                    product.candidate_content(fd)
            finally:os.close(fd)

    def test_revision_is_explicit_not_a_caller_pin(self):
        fd=product.open_directory(str(REPO))
        cfd=product.open_directory(str(CANDIDATE))
        try:
            with self.assertRaisesRegex(product.Refusal,'FIXED_SOURCE_REQUIRED'):
                product.verify_candidate(str(REPO),fd,'7f47ddb94a1fc63d8a5c3600bc031f6eae9feef3',cfd)
        finally:os.close(cfd);os.close(fd)

    def test_payload_and_inner_and_outer_rehash_cannot_authorize_changed_bytes(self):
        name='candidate/root/app/index.js'
        with self.changed(name,'candidate/manifest.json','bootstrap-files.json'):
            path=self.pack/name;path.write_bytes(path.read_bytes()+b'\n// drift\n')
            for control in ('candidate/manifest.json','bootstrap-files.json'):
                p=self.pack/control;doc=product.decode(p.read_bytes())
                doc['/app/index.js']=product.sha(path.read_bytes());p.write_bytes(product.encode(doc))
            self.rehash();self.reject('CANDIDATE_PIN_MISMATCH')

    def test_dependency_runtime_and_supervisor_bytes_remain_anchored(self):
        names=['candidate/root/runtime/node','candidate/root/usr/local/libexec/c3-test-coordinated-restore.py']
        manifest=product.decode((CANDIDATE/'manifest.json').read_bytes())
        names.append('candidate/root'+next(k for k in manifest if k.startswith('/app/node_modules/')))
        for name in names:
            with self.subTest(name=name),self.changed(name):
                path=self.pack/name;path.write_bytes(path.read_bytes()+b'X')
                self.rehash();self.reject('CANDIDATE_ROOT_MISMATCH')

    def test_all_host_bindings_and_type_exact_intents_are_fixed(self):
        expected=product.expected_host_intents()
        self.assertEqual(product.decode((PACK/'host-intents.json').read_bytes()),expected)
        network='scripts/test-node-isolation/c3-test-fresh-network.service'
        self.assertEqual(expected[network]['installedPathIntent'],'/etc/systemd/system/c3-test-fresh-network.service')
        for field,value in [('installedPathIntent','/foreign'),('uidIntent',False),('installed',0),('modeIntent',488.0)]:
            with self.subTest(field=field),self.changed('host-intents.json'):
                path=self.pack/'host-intents.json';doc=product.decode(path.read_bytes())
                # Non-network mapping was outside the old checker's finite anchor.
                doc['scripts/test-node-isolation/coordinated_restore.py'][field]=value
                path.write_bytes(product.encode(doc));self.rehash();self.reject('PACK_AUTHORITY_DRIFT')

    def test_host_source_all_categories_and_networkunit_reject_rehash(self):
        sources=['scripts/test-node-isolation/coordinated_restore.py',
                 'src/services/heldTestOwnerSettlement.js',
                 'scripts/test-node-isolation/c3-test-fresh-network.service']
        for source in sources:
            name='host-source'+product.PROFILE['hostSources'][source]['installed']
            with self.subTest(source=source),self.changed(name):
                p=self.pack/name;p.write_bytes(p.read_bytes()+b'X')
                self.rehash();self.reject('HOST_SOURCE_DRIFT')

    def test_payload_file_mode_rehash_refused(self):
        name='candidate/root/app/index.js'
        with self.changed(name):
            (self.pack/name).chmod(0o755);self.rehash();self.reject('CANDIDATE_MODE_PIN_MISMATCH')

    def test_control_file_mode_rehash_refused(self):
        name='host-intents.json'
        with self.changed(name):
            (self.pack/name).chmod(0o644);self.rehash();self.reject('PACK_AUTHORITY_DRIFT')

    def test_extra_and_missing_payload_and_control_files_refused(self):
        for name in ('extra','candidate/root/app/extra'):
            with self.subTest(extra=name),self.changed(name):
                p=self.pack/name;p.write_bytes(b'extra');p.chmod(0o600 if name=='extra' else 0o644)
                self.rehash();self.reject('PACK_EXACT_MEMBERSHIP_OR_MODE_DRIFT|CANDIDATE_ROOT_MISMATCH')
        for name in ('bootstrap-files.json','candidate/root/app/index.js'):
            with self.subTest(missing=name),self.changed(name):
                (self.pack/name).unlink();self.rehash();self.reject()

    def test_extra_directory_and_directory_modes_refused(self):
        for name in ('unexpected-empty','candidate/root/unexpected-empty'):
            p=self.pack/name
            try:
                p.mkdir(mode=0o700 if name=='unexpected-empty' else 0o755)
                self.rehash();self.reject('PACK_DIRECTORY_DRIFT|CANDIDATE_DIRECTORY_PIN_MISMATCH')
            finally:p.rmdir();self.rehash()
        p=self.pack/'candidate/root/app'
        try:
            p.chmod(0o700);self.rehash();self.reject('DIRECTORY_MODE_DRIFT')
        finally:p.chmod(0o755);self.rehash()

    def test_symlinks_are_not_followed(self):
        name='candidate/root/app/index.js'
        with self.changed(name):
            p=self.pack/name;p.unlink();p.symlink_to(REPO/'index.js')
            self.reject()

    def test_nogo_report_profile_and_dependencyintents_cannot_be_reauthorized(self):
        for name in ('profile.json','report.json','host-dependency-intents.json','network-source-pins.json'):
            with self.subTest(name=name),self.changed(name):
                path=self.pack/name;doc=product.decode(path.read_bytes())
                doc['operationalGO']=True
                path.write_bytes(product.encode(doc));self.rehash();self.reject('PACK_AUTHORITY_DRIFT')

    def test_actual_cli_requires_versioned_selection_and_has_no_pin_override(self):
        for argv in (['check','--pack',str(PACK)],
                     ['--profile','legacy','check','--pack',str(PACK)],
                     ['--profile','fixed9e-v1','check','--pack',str(PACK),'--manifest-pin','0'*64]):
            r=subprocess.run([sys.executable,'-B',str(HERE/'fresh_install_source_pack_9e_v1.py'),*argv],capture_output=True,timeout=10)
            self.assertEqual(r.returncode,2)

    def test_actual_legacy_cli_still_refuses_current_source_without_publication(self):
        target=Path(self.temp.name)/'legacy-refused'
        r=subprocess.run([sys.executable,'-B',str(HERE/'fresh_install_source_pack.py'),
                '--repo',str(REPO),'--candidate',str(OLD),'--output',str(target)],capture_output=True,timeout=90)
        self.assertEqual(r.returncode,2,r.stdout)
        self.assertEqual(r.stderr,b'REFUSAL BASE_SOURCE_DRIFT\n')
        self.assertFalse(target.exists())
        self.assertEqual(list(target.parent.glob('.legacy-refused.partial-*')),[])

    def test_actual_publication_refuses_existing_output(self):
        r=subprocess.run(self.cli+['build','--repo',str(REPO),'--candidate',str(CANDIDATE),
                                 '--output',str(PACK)],capture_output=True,timeout=10)
        self.assertEqual(r.returncode,2)
        self.assertEqual(r.stderr,b'REFUSAL OUTPUT_EXISTS\n')
        self.assertIs(product.verify_pack(str(PACK))['operationalGO'],False)


class FullArtifactPublicationFaultTests(unittest.TestCase):
    """Only IO fault injection; no acceptance pin/source/profile replacement."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fixed9e-publication-',dir=SCRATCH)
        self.output=Path(self.temp.name)/'pack'

    def tearDown(self):self.temp.cleanup()

    def build(self):return product.build(str(REPO),str(CANDIDATE),str(self.output))

    def absent(self):
        self.assertFalse(self.output.exists())
        self.assertEqual(list(Path(self.temp.name).glob('.pack.partial-*')),[])

    def test_actual_noreplace_preserves_racing_empty_destination(self):
        original=product.publish_noreplace
        winner=[]
        def race(parent,stage,target):
            self.output.mkdir(mode=0o700)
            winner.append(self.output.stat().st_ino)
            return original(parent,stage,target)
        with patch.object(product,'publish_noreplace',race):
            with self.assertRaisesRegex(product.Refusal,'^OUTPUT_EXISTS$'):self.build()
        self.assertEqual(self.output.stat().st_ino,winner[0])
        self.assertEqual(list(self.output.iterdir()),[])
        self.assertEqual(list(Path(self.temp.name).glob('.pack.partial-*')),[])

    def test_actual_partial_report_fault_never_publishes(self):
        original=product.write_file
        def fault(fd,name,raw,mode=0o600):
            original(fd,name,raw,mode)
            if name=='report.json':raise OSError('private-fault-text-never-returned')
        with patch.object(product,'write_file',fault):
            with self.assertRaisesRegex(product.Refusal,'^PACK_BUILD_REFUSED$'):self.build()
        self.absent()

    def test_actual_directory_durability_fault_never_publishes(self):
        original=product.fsync_tree
        def fault(fd):
            original(fd)
            raise OSError('private-fault-text-never-returned')
        with patch.object(product,'fsync_tree',fault):
            with self.assertRaisesRegex(product.Refusal,'^PACK_BUILD_REFUSED$'):self.build()
        self.absent()

    def test_actual_postrename_parent_fsync_fault_retains_unknown_output(self):
        original=os.fsync
        parent=Path(self.temp.name).stat()
        def fault(fd):
            st=os.fstat(fd)
            if (st.st_dev,st.st_ino)==(parent.st_dev,parent.st_ino):
                raise OSError('private-durability-fault')
            return original(fd)
        with patch.object(os,'fsync',fault):
            with self.assertRaisesRegex(product.Refusal,'^PACK_PUBLICATION_DURABILITY_OR_READBACK_UNKNOWN$'):self.build()
        self.assertTrue(self.output.is_dir())
        self.assertIs(product.verify_pack(str(self.output))['operationalGO'],False)

    def test_actual_lost_rename_reply_retains_unknown_output(self):
        original=product.publish_noreplace
        def fault(parent,stage,target):
            original(parent,stage,target)
            raise OSError('lost-reply')
        with patch.object(product,'publish_noreplace',fault):
            with self.assertRaisesRegex(product.Refusal,'^PACK_PUBLICATION_DURABILITY_OR_READBACK_UNKNOWN$'):self.build()
        self.assertIs(product.verify_pack(str(self.output))['physicalAccepted'],False)

    def test_actual_published_readback_fault_retains_unknown_output(self):
        original=product.verify_pack_fd
        def fault(fd):
            if self.output.exists():raise product.Refusal('INJECTED_READBACK_REFUSAL')
            return original(fd)
        with patch.object(product,'verify_pack_fd',fault):
            with self.assertRaisesRegex(product.Refusal,'^PACK_PUBLICATION_DURABILITY_OR_READBACK_UNKNOWN$'):self.build()
        self.assertIs(product.verify_pack(str(self.output))['operationalGO'],False)

if __name__=='__main__':unittest.main()
