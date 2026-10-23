"""Real complete fixed-runner-v2-v2 artifacts; metadata-only PPP0755 correction.

Reused historical bodies are private new-namespace regression coverage, not new
independent RED cycles. Runtime AST seams are modeled, never real root execution.
"""
import ast
import copy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import types
from types import SimpleNamespace
import unittest
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
B = Path('/home/leon/celerity-prod-release-20261019/full-production-20261023')
EVIDENCE = B/'runner-v2-ppp-mode-pack-child'
CANDIDATE = B/'runner-v2-source-pack-child/candidate-runner-v2'
PACK = EVIDENCE/'pack-fixed-runner-v2-v2'
V1PACK = B/'runner-v2-source-pack-parent/reproduced-pack-fixed-runner-v2-v1'
PPP = 'src/modules/relay-l2tp/node-artifacts/l2tp/verify-users.sh'
RUNNER = 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
import fresh_install_source_pack_runner_v2_v2 as product
import fresh_install_source_pack_runner_v2_v1 as v1

# Only test-input rebinding in this private namespace; no historical module globals.
prior = types.ModuleType('_runner_v2_v2_private_historical_bodies')
prior.__file__ = str(HERE/'test_fresh_install_source_pack_b7_v1.py')
exec(compile(Path(prior.__file__).read_bytes(), prior.__file__, 'exec'), prior.__dict__)
prior.product, prior.REPO, prior.EVIDENCE = product, REPO, EVIDENCE
prior.CANDIDATE, prior.PACK = CANDIDATE, PACK
prior.SCRATCH = EVIDENCE/'tmp'
prior.SCRATCH.mkdir(mode=0o700, exist_ok=True)

class FixedRunnerV2V2Tests(unittest.TestCase):
    def test_separately_named_fixed_product_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('fresh_install_source_pack_runner_v2_v2'),
                             'separately versioned PPP0755 product is missing')

    def test_type_exact_complete_profile_and_all48_intents_one_semantic_delta(self):
        before, after = v1.PROFILE, copy.deepcopy(product.PROFILE)
        self.assertEqual(len(after['hostSources']), 48)
        self.assertIs(type(after['hostSources'][PPP]['modeIntent']), int)
        self.assertEqual(after['hostSources'][PPP]['modeIntent'], 493)
        after['hostSources'][PPP]['modeIntent'] = 488
        after['profile'], after['schema'] = before['profile'], before['schema']
        self.assertEqual(product.encode(after), product.encode(before))
        old = product.decode((V1PACK/'host-intents.json').read_bytes())
        new = product.decode((PACK/'host-intents.json').read_bytes())
        self.assertEqual(product.encode(new), product.encode(product.expected_host_intents()))
        self.assertEqual(len(new), 48)
        self.assertEqual(new[PPP], {**old[PPP], 'modeIntent':493})
        new[PPP]['modeIntent'] = 488
        self.assertEqual(product.encode(new), product.encode(old))
        self.assertEqual(product.PROFILE['hostSources'][RUNNER]['modeIntent'], 488)

    def test_actual_producer_derivation_only_ppp_changes(self):
        # Evaluate the actual emitted-mode expression independently of the checker.
        def expression(name):
            tree = ast.parse((HERE/name).read_bytes())
            build = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name=='build')
            node = next(n for n in ast.walk(build) if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id=='mode' for t in n.targets))
            return compile(ast.Expression(node.value), '<actual producer mode expression>', 'eval')
        a=expression('fresh_install_source_pack_runner_v2_v1.py')
        b=expression('fresh_install_source_pack_runner_v2_v2.py')
        changed=[]
        for source,spec in product.PROFILE['hostSources'].items():
            scope=dict(source=source,installed=spec['installed'])
            old,new=eval(a,{},scope),eval(b,{},scope)
            self.assertIs(type(new),int)
            self.assertEqual(new,spec['modeIntent'])
            if old!=new: changed.append(source)
        self.assertEqual(changed,[PPP])

    def test_real_full_checker_cli_positive0755(self):
        r=subprocess.run([sys.executable,'-I','-B',str(HERE/'fresh_install_source_pack_runner_v2_v2.py'),
            '--profile','fixed-runner-v2-v2','check','--pack',str(PACK)],capture_output=True,timeout=120)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn(b'FIXED_RUNNER_V2_V2_OFFLINE_ONLY',r.stdout)
        self.assertIs(product.verify_pack(str(PACK))['installed'],False)

    def test_candidate_fixed_source_and_all_payload_controls_unchanged(self):
        fd=product.open_directory(str(REPO)); cfd=product.open_directory(str(CANDIDATE))
        try:
            manifest,report,files,snapshot=product.verify_candidate(str(REPO),fd,product.SOURCE,cfd)
            self.assertEqual(len(manifest),10518)
            self.assertEqual(report['sourceCommit'],'0d46025b1aad315c995d175531fe5e8fdfa66287')
            self.assertEqual(report['sourceTree'],'0e5c341817564d3f25e0306009e2618073c17e38')
        finally: os.close(cfd); os.close(fd)
        a=product.decode((V1PACK/'pack-manifest.json').read_bytes())
        b=product.decode((PACK/'pack-manifest.json').read_bytes())
        self.assertEqual(product.encode(a['directories']),product.encode(b['directories']))
        self.assertEqual(set(a['files']),set(b['files']))
        changed={n for n in a['files'] if product.encode(a['files'][n])!=product.encode(b['files'][n])}
        self.assertEqual(changed,{'host-intents.json','profile.json','report.json'})
        for n in ('candidate/manifest.json','candidate/report.json','host-dependency-intents.json',
                  'bootstrap-files.json','network-source-pins.json','observer-source-pins.json'):
            self.assertEqual((V1PACK/n).read_bytes(),(PACK/n).read_bytes(),n)

    def test_v1_real_positive_unchanged_and_rejects_new_product(self):
        self.assertEqual(product.sha((V1PACK/'pack-manifest.json').read_bytes()),
                         '1c33499c79a22115645b32c5862235b68a6e931f69bc26b61d77af59b1ea4dfc')
        self.assertIs(v1.verify_pack(str(V1PACK))['operationalGO'],False)
        with self.assertRaisesRegex(v1.Refusal,'^PACK_SCHEMA$'): v1.verify_pack(str(PACK))
        with self.assertRaisesRegex(product.Refusal,'^PACK_SCHEMA$'): product.verify_pack(str(V1PACK))

    def test_historical_positive_and_current_source_refusals_without_repins(self):
        import fresh_install_source_pack_b7_v1 as b7
        import fresh_install_source_pack_9e_v1 as n9
        for old,path in ((b7,B/'fixed-b7-source-pack-child/pack-fixed-b7-v1'),
            (n9,B.parent/'full-production-20261022/current-source-pack-profile-parent/reproduced-pack-fixed9e-v1')):
            self.assertIs(old.verify_pack(str(path))['operationalGO'],False)
            fd=old.open_directory(str(REPO))
            try:
                with self.assertRaisesRegex(old.Refusal,'SOURCE_WORKTREE_DRIFT'):
                    old.source_bytes(str(REPO),fd,old.SOURCE,'scripts/test-node-isolation/isolation.py')
            finally: os.close(fd)
        fd=product.open_directory(str(REPO))
        try:
            with self.assertRaisesRegex(product.core.Refusal,'BASE_SOURCE_DRIFT|PHYSICAL_SOURCE_DRIFT'):
                product.core.source_bytes(str(REPO),fd,product.SOURCE,'scripts/test-node-isolation/isolation.py')
        finally: os.close(fd)
        legacy=B.parent/'active-enable-20261021/install-sourcepack/full-pack'
        # Frozen legacy pre-network artifact refusal, never a fabricated new-source positive.
        legacy=Path('/home/leon/celerity-prod-release-20261019/active-enable-20261021/install-sourcepack/full-pack')
        self.assertFalse((legacy/'network-source-pins.json').exists())
        with self.assertRaisesRegex(product.core.Refusal,'^PACK_VERIFICATION_REFUSED$'):
            product.core.verify_pack(str(legacy))

    def test_fixed_cli_has_no_mode_profile_or_pin_override(self):
        for argv in (['check','--pack',str(PACK)],['--profile','fixed-runner-v2-v1','check','--pack',str(PACK)],
            ['--profile','fixed-runner-v2-v2','check','--pack',str(PACK),'--mode','493'],
            ['--profile','fixed-runner-v2-v2','check','--pack',str(PACK),'--manifest-pin','0'*64]):
            r=subprocess.run([sys.executable,'-I','-B',str(HERE/'fresh_install_source_pack_runner_v2_v2.py'),*argv],capture_output=True,timeout=10)
            self.assertEqual(r.returncode,2)

    def test_profile_is_hash_bound(self):
        with tempfile.TemporaryDirectory(dir=prior.SCRATCH) as temp:
            for n in ('fresh_install_source_pack.py','fresh_install_source_pack_runner_v2_v2.py','fresh_install_source_pack_runner_v2_v2_profile.json'):
                shutil.copyfile(HERE/n,Path(temp)/n)
            path=Path(temp)/'fresh_install_source_pack_runner_v2_v2_profile.json'
            doc=product.decode(path.read_bytes());doc['hostSources'][PPP]['modeIntent']=488
            path.write_bytes(product.encode(doc))
            r=subprocess.run([sys.executable,'-I','-B',str(Path(temp)/'fresh_install_source_pack_runner_v2_v2.py'),
                '--profile','fixed-runner-v2-v2','check','--pack',str(PACK)],capture_output=True,timeout=10)
            self.assertNotEqual(r.returncode,0);self.assertIn(b'PRODUCT_SOURCE_DRIFT',r.stderr)

    def test_actual_unchanged_runtime_ast0755_and0750_modeled_boundary(self):
        runner_raw=(REPO/'src/modules/relay-l2tp/node-artifacts/topology/runner.sh').read_bytes()
        embedded=runner_raw.split(b"3<<'FENCE_PY'\n",1)[1].split(b'\nFENCE_PY',1)[0]
        runner_tree=ast.parse(embedded)
        function=next(n for n in runner_tree.body if isinstance(n,ast.FunctionDef) and n.name=='verify_ppp')
        class GateRefusal(Exception): pass
        class ReachedDispatch(Exception): pass
        cases=[]
        for label,mode,uid,kind,drift in [
            ('root0755',0o755,0,stat.S_IFREG,False),('root0750',0o750,0,stat.S_IFREG,False),
            ('group_writable',0o775,0,stat.S_IFREG,False),('world_writable',0o757,0,stat.S_IFREG,False),
            ('foreign_uid',0o755,1,stat.S_IFREG,False),('symlink',0o755,0,stat.S_IFLNK,False),
            ('byte_drift',0o755,0,stat.S_IFREG,True)]:
            calls=[]
            def lstat(path):
                return SimpleNamespace(st_uid=uid if path.endswith('verify-users.sh') else 0,
                    st_mode=(kind|mode) if path.endswith('verify-users.sh') else stat.S_IFDIR|0o755)
            def refuse(code): raise GateRefusal(code)
            def run(argv,**kwargs):
                calls.append({'argv':argv,'env':kwargs['env'],'pass_fds':list(kwargs['pass_fds']),'timeout':kwargs['timeout']})
                raise ReachedDispatch()
            ns=dict(os=SimpleNamespace(lstat=lstat),stat=stat,hashlib=hashlib,subprocess=SimpleNamespace(run=run,PIPE=-1),
                open=lambda *a,**kw:io.BytesIO((REPO/PPP).read_bytes()+(b'\n' if drift else b'')),refuse=refuse)
            exec(compile(ast.Module(body=[function],type_ignores=[]),'<unchanged actual verify_ppp AST>','exec'),ns)
            try: ns['verify_ppp']('',{'operationId':'local-mode-probe'},19)
            except GateRefusal as e: outcome=str(e)
            except ReachedDispatch: outcome='REACHED_SUBPROCESS_BOUNDARY_NO_EXECUTION'
            expected='REACHED_SUBPROCESS_BOUNDARY_NO_EXECUTION' if label in ('root0755','root0750') else 'PPP_VERIFIER_PIN_MISMATCH' if drift else 'UNTRUSTED_PPP_VERIFIER'
            assert outcome==expected,(label,outcome)
            cases.append(dict(case=label,mode=oct(mode),outcome=outcome,calls=calls))

class FullArtifactAdversarialTests(unittest.TestCase):
    setUpClass=classmethod(prior.FullArtifactAdversarialTests.setUpClass.__func__)
    tearDownClass=classmethod(prior.FullArtifactAdversarialTests.tearDownClass.__func__)
    changed=prior.FullArtifactAdversarialTests.changed
    rehash=prior.FullArtifactAdversarialTests.rehash
    reject=prior.FullArtifactAdversarialTests.reject


    def test_ppp_exact_mode_types_path_hash_refused_after_outer_rehash(self):
        cases=[('modeIntent',488),('modeIntent',493.0),('modeIntent',True),
               ('modeIntent',False),('installedPathIntent','/foreign'),('sha256','0'*64),
               ('uidIntent',False),('gidIntent',0.0)]
        for field,value in cases:
            with self.subTest(field=field,value=value),self.changed('host-intents.json'):
                path=self.pack/'host-intents.json';doc=product.decode(path.read_bytes())
                doc[PPP][field]=value;path.write_bytes(product.encode(doc))
                self.rehash();self.reject('PACK_AUTHORITY_DRIFT')

    def test_runner0750_and_historical_wrong_path_remain_fixed(self):
        for field,value in [('modeIntent',493),('installedPathIntent','/usr/local/bin/celerity-topology-node-runner')]:
            with self.subTest(field=field),self.changed('host-intents.json'):
                path=self.pack/'host-intents.json';doc=product.decode(path.read_bytes())
                doc[RUNNER][field]=value;path.write_bytes(product.encode(doc))
                self.rehash();self.reject('PACK_AUTHORITY_DRIFT')

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

class FixedRunnerV2V2ClosureTests(unittest.TestCase):
    test_same_payload_wrong_commit_or_tree_report_refused=prior.FixedB7ClosureTests.test_same_payload_wrong_commit_or_tree_report_refused
    test_edited_and_symlink_worktree_sources_refused=prior.FixedB7ClosureTests.test_edited_and_symlink_worktree_sources_refused
    test_observer_pins_match_every_mapped_byte=prior.FixedB7ClosureTests.test_observer_pins_match_every_mapped_b7_byte


if __name__ == '__main__':
    unittest.main()
