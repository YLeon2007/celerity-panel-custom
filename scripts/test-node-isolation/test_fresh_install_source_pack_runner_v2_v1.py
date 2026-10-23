"""Actual complete runner-V2 artifacts; no acceptance-pin monkeypatches.

Reuse selected immutable b7 test bodies in a private test-module namespace only.
Historical product modules, acceptance maps and test files remain untouched.
"""
import ast
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
EVIDENCE = Path('/home/leon/celerity-prod-release-20261019/full-production-20261023/runner-v2-source-pack-child')
CANDIDATE = EVIDENCE/'candidate-runner-v2'
PACK = EVIDENCE/'pack-fixed-runner-v2-v1'
HISTORICAL = EVIDENCE.parent/'fixed-b7-source-pack-child'
import fresh_install_source_pack_runner_v2_v1 as product

# Private namespace: assign test inputs, never legacy producer globals.
prior = types.ModuleType('_runner_v2_reused_historical_test_bodies')
prior.__file__ = str(HERE/'test_fresh_install_source_pack_b7_v1.py')
exec(compile(Path(prior.__file__).read_bytes(), prior.__file__, 'exec'), prior.__dict__)
prior.product, prior.REPO, prior.EVIDENCE = product, REPO, EVIDENCE
prior.CANDIDATE, prior.PACK, prior.OLD = CANDIDATE, PACK, HISTORICAL/'candidate-b7'

class FixedRunnerV2Tests(unittest.TestCase):
    def test_separately_named_fixed_product_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('fresh_install_source_pack_runner_v2_v1'))

    def test_actual_full_candidate_and_fixed_source_tree(self):
        fd=product.open_directory(str(REPO)); cfd=product.open_directory(str(CANDIDATE))
        try:
            manifest,report,files,snapshot=product.verify_candidate(str(REPO),fd,product.SOURCE,cfd)
            self.assertEqual(report['sourceCommit'],'0d46025b1aad315c995d175531fe5e8fdfa66287')
            self.assertEqual(report['sourceTree'],'0e5c341817564d3f25e0306009e2618073c17e38')
            self.assertEqual(len(manifest),product.COUNTS['payloadFiles'])
            with self.assertRaisesRegex(product.Refusal,'FIXED_SOURCE_REQUIRED'):
                product.verify_candidate(str(REPO),fd,'b7be583ee6d8b095ed3f1556ec5906af3627b85d',cfd)
        finally: os.close(cfd); os.close(fd)

    def test_exact_host_delta_and_four_actual_consumers(self):
        import fresh_install_source_pack_b7_v1 as old
        before,after=old.PROFILE['hostSources'],product.PROFILE['hostSources']
        self.assertEqual(set(before),set(after))
        changed={k for k in before if before[k]!=after[k]}
        runner='src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
        self.assertEqual(changed,{'scripts/test-node-isolation/isolation.py','scripts/test-node-isolation/physical_attestor.py',runner})
        self.assertEqual(after[runner],{**before[runner],'installed':'/usr/local/bin/celerity-topology-node-runner-v2'})
        self.assertEqual(after[runner]['sha256'],'442663660ec974646b7969c457efd94cc17c57fe0e7a518be8a494480cf26765')
        consumers=['scripts/test-node-isolation/isolation.py','scripts/test-node-isolation/physical_attestor.py',
                   'src/modules/relay-l2tp/services/topologyNodeTransport.js','src/modules/relay-l2tp/services/topologyRunnerBootstrapper.js']
        for name in consumers:
            raw,mode=product.committed(str(REPO),product.SOURCE,name)
            self.assertIn(b'/usr/local/bin/celerity-topology-node-runner-v2',raw,name)
            self.assertNotIn(b'/usr/local/bin/celerity-topology-node-runner\'',raw,name)
        for name,spec in after.items():
            self.assertEqual(product.sha(product.committed(str(REPO),product.SOURCE,name)[0]),spec['sha256'],name)
        intents=product.decode((PACK/'host-intents.json').read_bytes())
        self.assertEqual(intents,product.expected_host_intents())
        self.assertFalse(any(v['installedPathIntent']=='/usr/local/bin/celerity-topology-node-runner' for v in intents.values()))
        self.assertEqual(before[runner]['installed'],'/usr/local/bin/celerity-topology-node-runner')

    def test_historical_b7_real_checker_positive_current_source_refusal(self):
        import fresh_install_source_pack_b7_v1 as old
        self.assertIs(old.verify_pack(str(HISTORICAL/'pack-fixed-b7-v1'))['operationalGO'],False)
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as temp:
            output=Path(temp)/'must-not-publish'
            r=subprocess.run([sys.executable,'-I','-B',str(HERE/'fresh_install_source_pack_b7_v1.py'),
                '--profile','fixed-b7-v1','build','--repo',str(REPO),'--candidate',str(HISTORICAL/'candidate-b7'),
                '--output',str(output)],capture_output=True,timeout=100)
            self.assertEqual(r.returncode,2,r.stdout)
            self.assertEqual(r.stderr,b'REFUSAL SOURCE_WORKTREE_DRIFT\n')
            self.assertFalse(output.exists())

    def test_actual_cli_fixed_selection_no_pin_override(self):
        for argv in (['check','--pack',str(PACK)],['--profile','fixed-b7-v1','check','--pack',str(PACK)],
                     ['--profile','fixed-runner-v2-v1','check','--pack',str(PACK),'--manifest-pin','0'*64]):
            r=subprocess.run([sys.executable,'-I','-B',str(HERE/'fresh_install_source_pack_runner_v2_v1.py'),*argv],capture_output=True,timeout=10)
            self.assertEqual(r.returncode,2)

    def test_profile_file_is_hash_bound(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as temp:
            for name in ('fresh_install_source_pack.py','fresh_install_source_pack_runner_v2_v1.py','fresh_install_source_pack_runner_v2_v1_profile.json'):
                shutil.copyfile(HERE/name,Path(temp)/name)
            p=Path(temp)/'fresh_install_source_pack_runner_v2_v1_profile.json'
            doc=product.decode(p.read_bytes());doc['sourceTree']='0'*40;p.write_bytes(product.encode(doc))
            r=subprocess.run([sys.executable,'-I','-B',str(Path(temp)/'fresh_install_source_pack_runner_v2_v1.py'),
                '--profile','fixed-runner-v2-v1','check','--pack',str(PACK)],capture_output=True,timeout=10)
            self.assertNotEqual(r.returncode,0);self.assertIn(b'PRODUCT_SOURCE_DRIFT',r.stderr)

class FullArtifactAdversarialTests(unittest.TestCase):
    setUpClass=classmethod(prior.FullArtifactAdversarialTests.setUpClass.__func__)
    tearDownClass=classmethod(prior.FullArtifactAdversarialTests.tearDownClass.__func__)
    changed=prior.FullArtifactAdversarialTests.changed
    rehash=prior.FullArtifactAdversarialTests.rehash
    reject=prior.FullArtifactAdversarialTests.reject

# Retain real payload/mode/control/membership/outer-rewrite tests; no old CLI positives.
for name in (
 'test_payload_and_inner_and_outer_rehash_cannot_authorize_changed_bytes',
 'test_dependency_runtime_and_supervisor_bytes_remain_anchored',
 'test_all_host_bindings_and_type_exact_intents_are_fixed',
 'test_dependency_intents_type_coercions_refused_after_rehash',
 'test_outer_manifest_types_cannot_authorize_drift',
 'test_host_source_all_categories_and_networkunit_reject_rehash',
 'test_payload_file_mode_rehash_refused','test_control_file_mode_rehash_refused',
 'test_extra_and_missing_payload_and_control_files_refused',
 'test_extra_directory_and_directory_modes_refused','test_symlinks_are_not_followed',
 'test_nogo_report_profile_and_dependencyintents_cannot_be_reauthorized'):
    setattr(FullArtifactAdversarialTests,name,getattr(prior.FullArtifactAdversarialTests,name))

class FullArtifactPublicationFaultTests(unittest.TestCase):
    setUp=prior.FullArtifactPublicationFaultTests.setUp
    tearDown=prior.FullArtifactPublicationFaultTests.tearDown
    build=prior.FullArtifactPublicationFaultTests.build
    absent=prior.FullArtifactPublicationFaultTests.absent

for name in ('test_actual_noreplace_preserves_racing_empty_destination',
             'test_actual_partial_report_fault_never_publishes',
             'test_actual_postrename_parent_fsync_fault_retains_unknown_output',
             'test_actual_lost_rename_reply_retains_unknown_output',
             'test_actual_published_readback_fault_retains_unknown_output'):
    setattr(FullArtifactPublicationFaultTests,name,getattr(prior.FullArtifactPublicationFaultTests,name))

class FixedRunnerV2ClosureTests(unittest.TestCase):
    test_same_payload_wrong_commit_or_tree_report_refused=prior.FixedB7ClosureTests.test_same_payload_wrong_commit_or_tree_report_refused
    test_edited_and_symlink_worktree_sources_refused=prior.FixedB7ClosureTests.test_edited_and_symlink_worktree_sources_refused
    test_observer_pins_match_every_mapped_byte=prior.FixedB7ClosureTests.test_observer_pins_match_every_mapped_b7_byte

if __name__ == '__main__':
    unittest.main()
