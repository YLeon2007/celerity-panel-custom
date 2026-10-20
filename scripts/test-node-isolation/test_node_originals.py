"""Real fsync/atomic local files; UID, kernel, SSH and systemd SIMULATED.

Production never consumes fixture root or an environment-selected executable.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
from types import SimpleNamespace
spec = importlib.util.spec_from_file_location('node_originals', HERE / 'node_originals.py')
n = SimpleNamespace()
if spec and spec.loader and (HERE / 'node_originals.py').exists():
    n = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(n)


class OriginalsTests(unittest.TestCase):
    def test_capture_survives_process_object_loss_then_restores_actual_bytes_metadata_and_readback(self):
        self.assertTrue(hasattr(n,'NodeOriginals'), 'durable fixed-file capture and restoration primitive missing')
        with Fixture() as f:
            receipt = f.writer.capture()
            bundle = f.fs.read_json(n.BUNDLE)
            self.assertEqual(bundle['profiles']['xray-bridge']['files']['config']['data'],
                             base64.b64encode(f.original).decode())
            self.assertNotIn('private-original', json.dumps(receipt))
            self.assertEqual(f.fs.info(n.BUNDLE)['mode'], 0o600)
            f.mutate_and_admit(receipt)
            writer = n.NodeOriginals(f.engine, f.module, fixture=f.fixture)
            result = writer.restore()
            self.assertEqual(f.path(f.config).read_bytes(), f.original)
            self.assertEqual(f.path(f.config).stat().st_mode & 0o777, 0o600)
            self.assertEqual(os.getxattr(f.path(f.config), 'user.fixture'), b'original-xattr')
            self.assertTrue(result['ownershipRetained'])
            self.assertEqual(f.fs.read_json(n.ADMISSION)['state'], 'closed')
            self.assertEqual(f.engine.phase, 'held')
            self.assertEqual(f.fs.read_json(n.RESTORE_STATE)['phase'], 'verified-retained')
            self.assertEqual(f.system.states['xray-bridge.service']['ActiveState'], 'active')
            self.assertTrue(f.system.events)


    def test_guard_loss_between_atomic_files_blocks_second_write_and_keeps_intent(self):
        with Fixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            f.put(f.unit, b'[Service]\n# accepted candidate unit\n')
            f.restore_pins['profiles'][f.profile]['files'] = f.writer_files()
            f.put(n.RESTORE_ACCEPTED, n.canonical(f.restore_pins))
            atomic = f.fs.atomic
            def lose_after_config(path, *args, **kwargs):
                atomic(path, *args, **kwargs)
                if path == f.config:
                    f.engine.phase = 'lost'
            f.writer.fs.atomic = lose_after_config
            with self.assertRaises(RuntimeError):
                f.writer.restore()
            self.assertEqual(f.path(f.unit).read_bytes(), b'[Service]\n# accepted candidate unit\n',
                             'guard loss must forbid the next fixed-file mutation')
            self.assertEqual(f.fs.read_json(n.RESTORE_STATE)['phase'], 'restoring-retained')
            self.assertEqual(f.fs.read_json(n.ADMISSION)['state'], 'closed')

    def test_nonterminal_close_receipt_cannot_be_blessed_by_current_journal_hash(self):
        with Fixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            path = n.runner_journal(f.profile)
            journal = f.fs.read_json(path)
            journal['generations']['generation-1']['commands']['close-1']['receipt']['terminal'] = False
            raw = n.canonical(journal)
            f.put(path,raw)
            f.restore_pins['profiles'][f.profile]['journalSha256'] = n.sha(raw)
            f.put(n.RESTORE_ACCEPTED,n.canonical(f.restore_pins))
            with self.assertRaises(RuntimeError):
                f.writer.restore()
            self.assertEqual(f.system.events, [])
            self.assertTrue(f.fs.absent(n.RESTORE_STATE))

    def test_zero_exit_rpc_without_exact_user_readback_retains_failure(self):
        with RuntimeFixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            f.system.action('restart','xray.service')
            writer = n.NodeOriginals(f.engine,f.module,fixture=f.fixture)
            rpc = writer.rpc
            # Simulate the documented Xray adu exit-zero partial failure only;
            # all snapshot/removal/readback RPCs still hit real loopback Xray.
            writer.rpc = lambda args,data=None: b'partial failure' if args[0]=='adu' else rpc(args,data)
            with self.assertRaisesRegex(n.Refusal,'RUNTIME_RESTORE_READBACK'):
                writer.restore()
            self.assertEqual(f.fs.read_json(n.RESTORE_STATE)['phase'],'restoring-retained')
            self.assertEqual(f.fs.read_json(n.ADMISSION)['state'],'closed')

    def test_historical_close_cannot_replace_current_head_even_with_accepted_full_journal_hash(self):
        with Fixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            path = n.runner_journal(f.profile)
            journal = f.fs.read_json(path)
            successor = copy.deepcopy(journal['generations']['generation-1'])
            successor['binding'].update(generation='generation-2',predecessorGeneration='generation-1')
            close = successor['commands'].pop('close-1')
            close['receipt'].update(generation='generation-2',predecessorGeneration='generation-1',commandId='close-2')
            successor['commands']['close-2'] = close
            journal['generations']['generation-2'] = successor
            # Both receipts are closed, but the alleged head omits its successor.
            raw = n.canonical(journal)
            f.put(path,raw)
            f.restore_pins['profiles'][f.profile]['journalSha256'] = n.sha(raw)
            f.put(n.RESTORE_ACCEPTED,n.canonical(f.restore_pins))
            with self.assertRaisesRegex(n.Refusal,'RUNNER_HEAD_UNKNOWN'):
                f.writer.restore()
            self.assertEqual(f.system.events,[])
            self.assertTrue(f.fs.absent(n.RESTORE_STATE))

    def test_runtime_original_users_are_restored_after_real_loopback_xray_restart(self):
        self.assertTrue(hasattr(n,'NodeOriginals'), 'durable runtime snapshot missing')
        with RuntimeFixture() as f:
            receipt = f.writer.capture()
            original_users = f.writer.runtime(f.original, 'active')
            self.assertEqual(original_users['inbounds']['subscription'][0]['email'], 'original@example.test')
            self.assertEqual(original_users['inbounds']['subscription'][0]['flow'], 'xtls-rprx-vision')
            f.mutate_and_admit(receipt)
            f.system.action('restart', 'xray.service')
            restored = n.NodeOriginals(f.engine, f.module, fixture=f.fixture).restore()
            self.assertTrue(restored['ownershipRetained'])
            self.assertEqual(f.writer.runtime(f.original, 'active'), original_users)
            self.assertEqual(f.path(f.config).read_bytes(), f.original)


class SafetyTests(unittest.TestCase):
    def test_capture_is_one_shot_and_independent_pin_drift_never_adopts(self):
        with Fixture() as f:
            f.put(f.config,b'{"inbounds":[],"foreign":"not-original"}')
            with self.assertRaisesRegex(n.Refusal,'ORIGINAL_PIN_MISMATCH'):
                f.writer.capture()
            self.assertTrue(f.fs.absent(n.BUNDLE))
            f.put(f.config,f.original)
            f.writer.capture()
            with self.assertRaisesRegex(n.Refusal,'EXISTING_ORIGINALS'):
                f.writer.capture()
            self.assertEqual(f.system.events,[])

    def test_restore_refuses_all_missing_or_changed_authority_before_any_service_effect(self):
        cases = ['admission-missing','admission-open','admission-foreign-node','admission-foreign-boot',
                 'admission-foreign-maintenance','admission-foreign-plan','admission-bool-version',
                 'hook-missing','bundle-missing','bundle-next','bundle-corrupt','restore-next','partial',
                 'current-bytes','current-xattr','service-job','service-loaded-drift','service-fragment',
                 'service-dropin','journal-next','journal-missing','journal-head-drift','journal-running',
                 'guard-lost','guard-replaced','boot-drift','accepted-pins-drift','current-pins-missing']
        for case in cases:
            with self.subTest(case=case), Fixture() as f:
                receipt = f.writer.capture()
                f.mutate_and_admit(receipt)
                if case.startswith('admission-') and case != 'admission-missing':
                    marker = f.fs.read_json(n.ADMISSION)
                    key,value = {'admission-open':('state','open'), 'admission-foreign-node':('nodeId','foreign'),
                        'admission-foreign-boot':('bootId','foreign'), 'admission-foreign-maintenance':('maintenanceId','foreign'),
                        'admission-foreign-plan':('planHash','e'*64),'admission-bool-version':('version',True)}[case]
                    marker[key] = value
                    f.put(n.ADMISSION,n.canonical(marker))
                elif case == 'admission-missing':
                    f.path(n.ADMISSION).unlink()
                elif case == 'hook-missing':
                    del f.module.RESTORE_ADMISSION_VERSION
                elif case in ('bundle-missing','journal-missing','current-pins-missing'):
                    f.path({'bundle-missing':n.BUNDLE,'journal-missing':n.runner_journal(f.profile),
                            'current-pins-missing':n.RESTORE_ACCEPTED}[case]).unlink()
                elif case in ('bundle-next','restore-next','partial','journal-next'):
                    path = {'bundle-next':n.BUNDLE+'.next','restore-next':n.RESTORE_STATE+'.next',
                            'partial':n.RESTORE_STATE,'journal-next':str(Path(n.runner_journal(f.profile)).with_name('journal.next'))}[case]
                    f.put(path,b'{}')
                elif case == 'bundle-corrupt':
                    f.put(n.BUNDLE,b'{"corrupt":true}')
                elif case == 'current-bytes':
                    f.put(f.config,b'{"inbounds":[],"foreign-drift":true}')
                elif case == 'current-xattr':
                    os.setxattr(f.path(f.config),'user.fixture',b'foreign')
                elif case.startswith('service-'):
                    k,v = {'service-job':('Job','4/start'),'service-loaded-drift':('NeedDaemonReload','yes'),
                           'service-fragment':('FragmentPath','/foreign'),'service-dropin':('DropInPaths','/override')}[case]
                    f.system.states['xray-bridge.service'][k] = v
                elif case in ('journal-head-drift','journal-running'):
                    path = n.runner_journal(f.profile)
                    value = f.fs.read_json(path)
                    if case == 'journal-head-drift':
                        value['head'] = 'unknown'
                    else:
                        value['generations']['generation-1']['commands']['close-1']['state'] = 'running'
                    raw = n.canonical(value)
                    f.put(path,raw)
                    # Even separately accepted checksum never licenses unknown work.
                    f.restore_pins['profiles'][f.profile]['journalSha256'] = n.sha(raw)
                    f.put(n.RESTORE_ACCEPTED,n.canonical(f.restore_pins))
                elif case == 'guard-lost':
                    f.engine.phase = 'lost'
                elif case == 'guard-replaced':
                    f.guard = {**f.guard,'start':'1000'}
                elif case == 'boot-drift':
                    f.plan['bootId'] = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
                elif case == 'accepted-pins-drift':
                    f.accepted['xraySha256'] = 'e'*64
                    f.put(n.ACCEPTED,n.canonical(f.accepted))
                before = f.path(f.config).read_bytes()
                with self.assertRaises((RuntimeError,OSError,KeyError,ValueError)):
                    f.writer.restore()
                self.assertEqual(f.system.events,[], 'preflight refusal must have zero systemd mutations')
                self.assertEqual(f.path(f.config).read_bytes(),before)
                self.assertTrue(f.path(n.ADMISSION).exists() or case=='admission-missing')

    def test_symlink_hardlink_foreign_mode_and_parent_link_fail_closed(self):
        for case in ('file-link','parent-link','bundle-link','hardlink','writable-file','writable-parent'):
            with self.subTest(case=case), Fixture() as f:
                receipt = f.writer.capture()
                f.mutate_and_admit(receipt)
                if case in ('file-link','hardlink'):
                    target = f.path(f.config)
                    foreign = target.with_name('foreign')
                    target.rename(foreign)
                    if case == 'file-link':
                        target.symlink_to(foreign)
                    else:
                        os.link(foreign,target)
                elif case == 'parent-link':
                    parent = f.path(f.config).parent
                    foreign = parent.with_name('foreign-dir')
                    parent.rename(foreign)
                    parent.symlink_to(foreign)
                elif case == 'bundle-link':
                    target = f.path(n.BUNDLE)
                    foreign = target.with_name('foreign')
                    target.rename(foreign)
                    target.symlink_to(foreign)
                elif case == 'writable-file':
                    f.path(f.config).chmod(0o666)
                else:
                    f.path(f.config).parent.chmod(0o777)
                with self.assertRaises((RuntimeError,OSError)):
                    f.writer.restore()
                self.assertEqual(f.system.events,[])

    def test_nonblocking_real_locks_exclude_an_inherited_child(self):
        import fcntl
        import subprocess
        import time
        for path_kind in ('outer','runner'):
            with self.subTest(path=path_kind), Fixture() as f:
                receipt = f.writer.capture()
                f.mutate_and_admit(receipt)
                path = n.OUTER_LOCK if path_kind=='outer' else n.runner_lock(f.profile)
                fd = os.open(f.path(path),os.O_RDWR)
                fcntl.flock(fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
                child = subprocess.Popen([sys.executable,'-c','import sys; sys.stdin.buffer.read(1)'],
                                         stdin=subprocess.PIPE,pass_fds=(fd,))
                os.close(fd)  # The accepted descendant, not this supervisor, owns it now.
                try:
                    started = time.monotonic()
                    with self.assertRaises(BlockingIOError):
                        f.writer.restore()
                    self.assertLess(time.monotonic()-started,1)
                    self.assertEqual(f.system.events,[])
                    self.assertTrue(f.fs.absent(n.RESTORE_STATE))
                finally:
                    child.communicate(b'x',timeout=5)
                self.assertEqual(child.returncode,0)

    def test_bundle_file_fsync_failure_never_publishes_and_cannot_be_retried(self):
        from unittest.mock import patch
        with Fixture() as f:
            real = os.fsync
            def broken(fd):
                if os.readlink('/proc/self/fd/'+str(fd)).endswith('/originals.json.next'):
                    raise OSError('simulated fsync failure (not a storage claim)')
                return real(fd)
            with patch.object(n.os,'fsync',side_effect=broken), self.assertRaises(OSError):
                f.writer.capture()
            self.assertTrue(f.fs.absent(n.BUNDLE))
            self.assertFalse(f.fs.absent(n.BUNDLE+'.next'))
            with self.assertRaises(RuntimeError):
                f.writer.capture()
            self.assertEqual(f.path(f.config).read_bytes(),f.original)
            self.assertEqual(f.system.events,[])

    def test_partial_restore_is_durable_and_a_new_instance_never_replays(self):
        with Fixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            atomic = f.writer.fs.atomic
            def fail_unit(path,*args,**kwargs):
                if path == f.unit:
                    raise OSError('simulated partial restore')
                return atomic(path,*args,**kwargs)
            f.writer.fs.atomic = fail_unit
            with self.assertRaises(OSError):
                f.writer.restore()
            self.assertEqual(f.path(f.config).read_bytes(),f.original)
            before = list(f.system.events)
            with self.assertRaisesRegex(RuntimeError,'PARTIAL_RESTORE'):
                n.NodeOriginals(f.engine,f.module,fixture=f.fixture).restore()
            self.assertEqual(f.system.events,before)
            self.assertEqual(f.fs.read_json(n.RESTORE_STATE)['phase'],'restoring-retained')
            self.assertEqual(f.fs.read_json(n.ADMISSION)['state'],'closed')

    def test_fsync_precedes_first_service_mutation_and_original_readback_is_exact(self):
        from unittest.mock import patch
        with Fixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            real_sync, real_action = os.fsync, f.system.action
            durable = []
            def sync(fd):
                durable.append(os.readlink('/proc/self/fd/'+str(fd)))
                real_sync(fd)
            def action(*args,**kwargs):
                self.assertTrue(any(p.endswith('/restore.json.next') for p in durable))
                self.assertTrue(any(p.endswith('/originals') for p in durable))
                return real_action(*args,**kwargs)
            f.system.action = action
            with patch.object(n.os,'fsync',side_effect=sync):
                f.writer.restore()
            self.assertEqual(f.writer_files(),f.accepted['profiles'][f.profile]['files'])

    def test_final_readback_mismatch_retains_closed_admission_and_failure_intent(self):
        with Fixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            action = f.system.action
            def corrupt(verb,*args,**kwargs):
                action(verb,*args,**kwargs)
                if verb == 'restart':
                    f.put(f.config,b'{"inbounds":[],"unexpected":true}')
            f.system.action = corrupt
            with self.assertRaisesRegex(RuntimeError,'RESTORE_EXACT_READBACK'):
                f.writer.restore()
            self.assertEqual(f.fs.read_json(n.RESTORE_STATE)['phase'],'restoring-retained')
            self.assertEqual(f.fs.read_json(n.ADMISSION)['state'],'closed')

    def test_original_inactive_disabled_state_is_restored_without_start(self):
        with Fixture() as f:
            state = f.system.states['xray-bridge.service']
            state.update(ActiveState='inactive',UnitFileState='disabled')
            f.accepted['profiles'][f.profile]['service'] = copy.deepcopy(state)
            f.put(n.ACCEPTED,n.canonical(f.accepted))
            f.writer = n.NodeOriginals(f.engine,f.module,fixture=f.fixture)
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            state.update(ActiveState='active',UnitFileState='enabled')
            f.restore_pins['profiles'][f.profile]['service'] = copy.deepcopy(state)
            f.put(n.RESTORE_ACCEPTED,n.canonical(f.restore_pins))
            f.writer.restore()
            self.assertNotIn(('restart','xray-bridge.service'),f.system.events)
            self.assertIn(('disable','xray-bridge.service'),f.system.events)
            self.assertEqual(f.system.unit('xray-bridge.service')['UnitFileState'],'disabled')

    def test_capture_and_restore_through_actual_isolation_engine_retains_held_phase(self):
        import test_isolation as isolation_fixture
        with Fixture() as f:
            plan = isolation_fixture.PlanTests().plan()
            plan.update(f.plan)
            host = isolation_fixture.EngineTests.FixtureHost()
            host.physical = f.engine.host.physical
            f.engine = isolation_fixture.m.Engine(f.path(n.STATE),plan,host)
            isolation_fixture.fixture_hold(f.engine)
            f.plan = plan
            f.accepted.update(n.identity(f.engine))
            f.put(n.ACCEPTED,n.canonical(f.accepted))
            f.writer = n.NodeOriginals(f.engine,f.module,fixture=f.fixture)
            before = f.engine.read()
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            f.writer.restore()
            self.assertEqual(f.engine.read(),before)
            self.assertEqual(f.engine.read()['phase'],'held')
            self.assertFalse(any(e[0]=='restore' for e in host.events))

    def test_104_143_201_72_restores_and_reads_both_xray_units_without_touching_ppp(self):
        with DualFixture() as f:
            originals = {p: f.writer.snapshot(p) for p in f.writer.profiles}
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            n.NodeOriginals(f.engine,f.module,fixture=f.fixture).restore()
            for profile in ('xray-main','xray-bridge'):
                self.assertEqual(f.writer.snapshot(profile),originals[profile])
                self.assertIn(('restart',n.service_name(profile)),f.system.events)
            self.assertEqual(f.path('/etc/ppp/chap-secrets').read_bytes(),b'PPP-untouched-fixture')
            self.assertEqual({e[1] for e in f.system.events if e[1]}, {'xray.service','xray-bridge.service'})

    def test_inactive_vless_runtime_is_not_inferred_empty(self):
        with Fixture() as f:
            raw = n.canonical({"inbounds":[{"tag":"sub","protocol":"vless","settings":{"clients":[]}}]})
            with self.assertRaisesRegex(n.Refusal,"INACTIVE_VLESS_RUNTIME_UNPROVEN"):
                f.writer.runtime_layout(raw,"inactive")
            self.assertEqual(f.system.events,[])

    def test_runtime_layout_without_exact_loopback_handler_readback_is_refused(self):
        for config in ({'inbounds':[{'tag':'sub','protocol':'vless','settings':{'clients':[]}}]},
                       {'inbounds':[{'tag':'unreviewed','protocol':'trojan'}]},
                       {'inbounds':'unknown'}):
            with self.subTest(config=config), Fixture() as f:
                f.original = n.canonical(config)
                f.put(f.config,f.original)
                f.accepted['profiles'][f.profile]['files'] = f.writer_files()
                f.put(n.ACCEPTED,n.canonical(f.accepted))
                f.writer = n.NodeOriginals(f.engine,f.module,fixture=f.fixture)
                with self.assertRaisesRegex(n.Refusal,'RUNTIME'):
                    f.writer.capture()
                self.assertTrue(f.fs.absent(n.BUNDLE))
                self.assertEqual(f.system.events,[])

    def test_independent_restore_process_uses_only_durable_bundle_not_private_cache(self):
        import subprocess
        with Fixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            code = '''import json, os, sys
from pathlib import Path
from types import SimpleNamespace
import test_node_originals as t
n=t.n
root=Path(sys.argv[1])
fixture=n.Fixture(root,os.getuid(),os.getgid(),None)
fs=n.Files(fixture)
accepted=fs.read_json(n.ACCEPTED)
bundle=fs.read_json(n.BUNDLE)
plan={k:accepted[k] for k in n.IDENTITY}
engine=SimpleNamespace(plan=plan,plan_hash=accepted['planHash'])
engine.assert_held=lambda: {'guard':bundle['guard'],'dispatchInFlight':None,'dispatchCount':1}
engine.host=SimpleNamespace(physical=lambda:{k:plan[k] for k in ('machineId','bootId','sshHostKeySha256')},operator_session=lambda:{'pid':78,'start':'999'})
def guard_check(guard,session=None):
 if guard!=bundle['guard'] or session!={'pid':78,'start':'999'}: raise n.Refusal('FRESH_INDEPENDENT_SESSION_REQUIRED')
 return {'session':{'pid':77,'start':'998'}}
engine.host.guard_check=guard_check
f=SimpleNamespace(unit=n.profile_paths(plan['targetProfile'])[1])
system=t.SimulatedSystem(f)
system.states[n.service_name(plan['targetProfile'])]=fs.read_json(n.RESTORE_ACCEPTED)['profiles'][plan['targetProfile']]['service']
fixture.system=system
result=n.NodeOriginals(engine,SimpleNamespace(RESTORE_ADMISSION_VERSION=1),fixture=fixture).restore()
print(json.dumps({'receipt':result,'service':system.unit(n.service_name(plan['targetProfile']))}))
'''
            result = subprocess.run([sys.executable,'-c',code,str(f.root)],cwd=HERE,
                        capture_output=True,timeout=15,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
            self.assertEqual(result.returncode,0,result.stderr.decode())
            outcome = json.loads(result.stdout)
            self.assertTrue(outcome['receipt']['ownershipRetained'])
            self.assertEqual(outcome['service'],f.accepted['profiles'][f.profile]['service'])
            self.assertEqual(f.path(f.config).read_bytes(),f.original)
            self.assertEqual(f.fs.read_json(n.RESTORE_STATE)['phase'],'verified-retained')
            self.assertEqual(f.fs.read_json(n.ADMISSION)['state'],'closed')

    def test_finite_child_output_is_kernel_bounded_and_never_reported(self):
        with self.assertRaisesRegex(n.Refusal,'OUTPUT_LIMIT'):
            n.bounded_run([sys.executable,'-c','import os; os.write(1,b"x"*4096)'],limit=512)

    def test_cli_has_no_fake_root_or_arbitrary_operation_and_redacts_errors(self):
        import subprocess
        for args in (['--root','/foreign'],['restore','/foreign'],['dispatch'],['capture']):
            result = subprocess.run([sys.executable,str(HERE/'node_originals.py'),*args],
                       input=b'private-original-secret',capture_output=True,timeout=5,
                       env={**os.environ,'CELERITY_TOPOLOGY_ROOT':'/foreign','C3_NODE_ORIGINALS_ROOT':'/foreign'})
            self.assertEqual(result.returncode,75)
            self.assertEqual(result.stdout,b'')
            self.assertEqual(json.loads(result.stderr),{'ok':False,'code':'NODE_ORIGINALS_UNKNOWN_RETAINED','ownershipRetained':True})


class Fixture:
    def __enter__(self):
        from types import SimpleNamespace
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.fixture = n.Fixture(self.root, os.getuid(), os.getgid(), None)
        self.fs = n.Files(self.fixture)
        self.node = '6ab18d9c63913ebd4a917670'
        self.profile = 'xray-bridge'
        self.plan = {'context': 'test.infograd.online', 'nodeId': self.node, 'endpointIp': '50.114.160.63',
                     'targetProfile': self.profile, 'machineId': 'a'*32,
                     'bootId': '01234567-89ab-cdef-0123-456789abcdef', 'sshHostKeySha256': 'b'*64,
                     'maintenanceId': 'maintenance-1'}
        self.guard = {'pid': 77, 'start': '998', 'socket': '/fixed-recovery.sock'}
        self.engine = SimpleNamespace(plan=self.plan, plan_hash='c'*64, phase='held')
        self.engine.assert_held = self.held
        self.engine.host = SimpleNamespace(physical=lambda: {k:self.plan[k] for k in
                                                          ('machineId','bootId','sshHostKeySha256')},
                                          operator_session=lambda: {'pid': 78, 'start': '999'})
        def guard_check(guard, session=None):
            if guard != self.guard or session != {'pid': 78, 'start': '999'}:
                raise n.Refusal('FRESH_INDEPENDENT_SESSION_REQUIRED')
            return {'session': {'pid': 77, 'start': '998'}}
        self.engine.host.guard_check = guard_check
        self.module = SimpleNamespace(RESTORE_ADMISSION_VERSION=1)
        self.config, self.unit = n.profile_paths(self.profile)
        self.original = b'{"inbounds":[],"private-original":"secret"}\n'
        self.put(self.config, self.original)
        os.setxattr(self.path(self.config), 'user.fixture', b'original-xattr')
        self.put(self.unit, b'[Service]\nExecStart=/usr/local/bin/xray run -c '+self.config.encode()+b'\n')
        for path in (n.OUTER_LOCK, n.runner_lock(self.profile)):
            self.put(path, b'')
        self.put(n.HELPER, b'independently reviewed fixture helper')
        self.system = SimulatedSystem(self)
        self.fixture.system = self.system
        self.accepted = {**n.identity(self.engine), 'version':1,
                         'isolationSha256': hashlib.sha256(self.path(n.HELPER).read_bytes()).hexdigest(),
                         'xraySha256': 'd'*64,
                         'profiles': {self.profile: {'files':self.writer_files(),
                                      'service':copy.deepcopy(self.system.states['xray-bridge.service']),
                                      'runtimeSha256': n.sha(n.canonical({'mode':'none','inbounds':{}}))}}}
        self.put(n.ACCEPTED, n.canonical(self.accepted))
        self.writer = n.NodeOriginals(self.engine, self.module, fixture=self.fixture)
        return self

    def held(self):
        if self.engine.phase != 'held':
            raise RuntimeError('GUARD_LOST')
        return {'guard': self.guard, 'dispatchCount':0, 'dispatchInFlight':None}

    def path(self, fixed):
        return self.root / fixed.lstrip('/')

    def put(self, path, raw):
        target = self.path(path)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for parent in target.parents:
            if parent == self.root.parent:
                break
            parent.chmod(0o700)
        target.write_bytes(raw)
        target.chmod(0o600)

    def writer_files(self):
        return {name:self.fs.info(path) for name,path in zip(('config','unit'), (self.config,self.unit))}

    def mutate_and_admit(self, receipt):
        self.put(self.config, b'{"inbounds":[],"candidate":"changed"}')
        os.setxattr(self.path(self.config), 'user.fixture', b'candidate-xattr')
        self.system.states['xray-bridge.service']['ActiveState'] = 'inactive'
        # The actual runner writes this new closed generation; no receipt facade.
        import subprocess
        self.put('/proc/sys/kernel/random/boot_id', (self.plan['bootId']+'\n').encode())
        self.path(n.runner_lock(self.profile)).unlink()
        runner = HERE.parents[1] / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
        values = {'command':'close','operation-id':'operation-1','node-id':self.node,
                  'candidate-hash':'sha256:'+'e'*64,'backup-id':'backup-1','target-profile':self.profile,
                  'execution-context':self.plan['context'],'attempt-id':'attempt-1','generation':'generation-1',
                  'predecessor-generation':'none','command-id':'close-1'}
        args = [item for k,v in values.items() for item in ('--'+k,v)]
        result = subprocess.run(['/bin/bash',str(runner),*args],capture_output=True,timeout=8,
                          env={**os.environ,'CELERITY_TOPOLOGY_ROOT':str(self.root)})
        if result.returncode != 0 or result.stderr:
            raise AssertionError('Actual disposable runner close failed: '+result.stderr.decode())
        self.put(n.ADMISSION, n.canonical({'version':1,'planHash':self.engine.plan_hash,
                    'nodeId':self.node,'bootId':self.plan['bootId'],
                    'maintenanceId':self.plan['maintenanceId'],'state':'closed'}))
        self.restore_pins = {'version':1, **n.identity(self.engine), 'bundleSha256':receipt['bundleSha256'],
                             'profiles':{self.profile:{'files':self.writer_files(),
                              'service':copy.deepcopy(self.system.states['xray-bridge.service']),
                              'journalSha256':n.sha(self.path(n.runner_journal(self.profile)).read_bytes())}}}
        self.put(n.RESTORE_ACCEPTED, n.canonical(self.restore_pins))

    def __exit__(self, *args):
        self.tmp.cleanup()


class SimulatedSystem:
    def __init__(self, fixture):
        self.fixture = fixture
        self.events = []
        self.states = {'xray-bridge.service':{'Id':'xray-bridge.service','LoadState':'loaded',
             'FragmentPath':fixture.unit,'DropInPaths':'','ActiveState':'active','UnitFileState':'enabled','Job':'','NeedDaemonReload':'no'}}

    def unit(self, service):
        return copy.deepcopy(self.states[service])

    def action(self, verb, service=None, locks=()):
        self.events.append((verb,service))
        if verb in ('restart','stop'):
            self.states[service]['ActiveState'] = 'active' if verb=='restart' else 'inactive'
        if verb in ('enable','disable'):
            self.states[service]['UnitFileState'] = 'enabled' if verb=='enable' else 'disabled'


class DualFixture(Fixture):
    def __enter__(self):
        super().__enter__()
        self.node = '6ab4b53bc4c0304573e06c72'
        self.plan.update(nodeId=self.node,endpointIp='104.143.201.72')
        config, unit = n.profile_paths('xray-main')
        self.put(config,self.original)
        self.put(unit,b'[Service]\n# preserved original main service\n')
        self.put(n.runner_lock('xray-main'),b'')
        self.put('/etc/ppp/chap-secrets',b'PPP-untouched-fixture')
        self.system.states['xray.service'] = {**self.system.states['xray-bridge.service'],
                                            'Id':'xray.service','FragmentPath':unit}
        self.accepted.update(n.identity(self.engine))
        self.accepted['profiles']['xray-main'] = {'files':{k:self.fs.info(p) for k,p in
                           zip(('config','unit'),n.profile_paths('xray-main'))},
                      'service':copy.deepcopy(self.system.states['xray.service']),
                      'runtimeSha256':n.sha(n.canonical({'mode':'none','inbounds':{}}))}
        self.put(n.ACCEPTED,n.canonical(self.accepted))
        self.writer = n.NodeOriginals(self.engine,self.module,fixture=self.fixture)
        return self

    def mutate_and_admit(self,receipt):
        import subprocess
        super().mutate_and_admit(receipt)
        profile = 'xray-main'
        config, unit = n.profile_paths(profile)
        self.put(config,b'{"inbounds":[],"candidate-main":"changed"}')
        self.put(unit,b'[Service]\n# accepted candidate main unit\n')
        self.path(n.runner_lock(profile)).unlink()
        runner = HERE.parents[1] / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
        values = {'command':'close','operation-id':'op-main','node-id':self.node,'candidate-hash':'sha256:'+'a'*64,
                  'backup-id':'backup-main','target-profile':profile,'execution-context':self.plan['context'],
                  'attempt-id':'attempt-main','generation':'generation-main','predecessor-generation':'none','command-id':'close-main'}
        args = [item for k,v in values.items() for item in ('--'+k,v)]
        result = subprocess.run(['/bin/bash',str(runner),*args],capture_output=True,timeout=8,
                         env={**os.environ,'CELERITY_TOPOLOGY_ROOT':str(self.root)})
        if result.returncode != 0 or result.stderr:
            raise AssertionError('Actual second-profile disposable runner close failed')
        self.restore_pins['profiles'][profile] = {'files':{k:self.fs.info(p) for k,p in
                           zip(('config','unit'),n.profile_paths(profile))},
                 'service':copy.deepcopy(self.system.states['xray.service']),
                 'journalSha256':n.sha(self.fs.read(n.runner_journal(profile))[0])}
        self.put(n.RESTORE_ACCEPTED,n.canonical(self.restore_pins))


class RuntimeFixture(Fixture):
    """Disposable real loopback Xray; fake systemd only owns this exact Popen."""
    def __enter__(self):
        try:
            return self._start()
        except BaseException:
            if hasattr(self,'system') and hasattr(self.system,'child'):
                self.system.action('stop','xray.service')
            if hasattr(self,'tmp'):
                self.tmp.cleanup()
            raise

    def _start(self):
        import socket
        import subprocess
        import time
        super().__enter__()
        source = Path(os.environ.get('C3_ORIGINALS_TEST_XRAY',
                    '/home/leon/.cache/c3-happ-lab-20260929/root/opt/happ/bin/core/xray'))
        if not source.is_file():
            raise AssertionError('Pinned real Xray fixture executable required (no skips)')
        self.node, self.profile = '6ab18adc63913ebd4a917471', 'xray-main'
        self.plan.update(nodeId=self.node,endpointIp='132.243.230.19',targetProfile=self.profile)
        self.config, self.unit = n.profile_paths(self.profile)
        self.put(n.XRAY,source.read_bytes())
        self.path(n.XRAY).chmod(0o750)
        # Kernel reserves the API port until immediately before this exact child.
        sock = socket.socket()
        sock.bind(('127.0.0.1',0))
        self.port = sock.getsockname()[1]
        sock.close()
        config = {'log':{'loglevel':'none'}, 'api':{'tag':'API','services':['HandlerService']},
                  'inbounds':[{'tag':'API_INBOUND','listen':'127.0.0.1','port':self.port,
                       'protocol':'dokodemo-door','settings':{'address':'127.0.0.1'}},
                      {'tag':'subscription','listen':'127.0.0.1','port':0,'protocol':'vless',
                       'settings':{'clients':[],'decryption':'none'}}],
                  'outbounds':[{'protocol':'freedom','tag':'direct'}],
                  'routing':{'rules':[{'type':'field','inboundTag':['API_INBOUND'],'outboundTag':'API'}]}}
        # A real listener requires a separate free subscription port.
        sock = socket.socket()
        sock.bind(('127.0.0.1',0))
        config['inbounds'][1]['port'] = sock.getsockname()[1]
        sock.close()
        self.original = n.canonical(config)
        self.put(self.config,self.original)
        self.put(self.unit,b'[Service]\n# fixed original main unit\n')
        self.put(n.runner_lock(self.profile),b'')
        f = self
        class RuntimeSystem(SimulatedSystem):
            def __init__(self):
                self.events, self.child = [], None
                self.states = {'xray.service':{'Id':'xray.service','LoadState':'loaded','FragmentPath':f.unit,
                          'DropInPaths':'','ActiveState':'inactive','UnitFileState':'enabled','Job':'','NeedDaemonReload':'no'}}
            def action(self,verb,service=None,locks=()):
                self.events.append((verb,service))
                if verb in ('restart','stop'):
                    if self.child:
                        self.child.terminate()
                        self.child.wait(timeout=5)
                        self.child = None
                    if verb == 'restart':
                        self.child = subprocess.Popen([str(f.path(n.XRAY)),'run','-c',str(f.path(f.config))],
                                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                        env=n.CLEAN_ENV)
                        deadline = time.monotonic()+5
                        while True:
                            if self.child.poll() is not None:
                                raise AssertionError('Disposable Xray failed to start')
                            try:
                                with socket.create_connection(('127.0.0.1',f.port),timeout=.1):
                                    break
                            except OSError:
                                if time.monotonic() > deadline:
                                    raise AssertionError('Disposable Xray readiness deadline')
                                time.sleep(.02)
                    self.states[service]['ActiveState'] = 'active' if verb=='restart' else 'inactive'
        self.system = RuntimeSystem()
        self.fixture.system = self.system
        self.system.action('restart','xray.service')
        self.accepted.update(n.identity(self.engine))
        self.accepted['xraySha256'] = n.sha(source.read_bytes())
        # Actual dynamic user exists ONLY via RPC, never in original config bytes.
        user = {'id':'11111111-2222-4333-8444-555555555555','email':'original@example.test','level':0,'flow':'xtls-rprx-vision'}
        addition = {'inbounds':[{**config['inbounds'][1],'settings':{'decryption':'none','clients':[user]}}]}
        added = subprocess.run([str(self.path(n.XRAY)),'api','adu','--server=127.0.0.1:'+str(self.port),'/dev/stdin'],
                      input=n.canonical(addition),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
        if added.returncode != 0 or added.stderr:
            raise AssertionError('Disposable real RPC setup refused')
        self.accepted['profiles'] = {self.profile:{'files':self.writer_files(),
                   'service':copy.deepcopy(self.system.states['xray.service']),
                   'runtimeSha256':n.sha(n.canonical({'mode':'rpc','inbounds':{'subscription':[user]}}))}}
        self.put(n.ACCEPTED,n.canonical(self.accepted))
        self.writer = n.NodeOriginals(self.engine,self.module,fixture=self.fixture)
        return self

    def mutate_and_admit(self,receipt):
        # Reuse exact journal/admission fixture grammar without losing the API.
        state = self.system.states['xray.service']
        self.system.states['xray-bridge.service'] = state
        super().mutate_and_admit(receipt)
        config = json.loads(self.original)
        config['inbounds'][1]['settings']['clients'] = [{'id':'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee','email':'candidate@example.test'}]
        self.put(self.config,n.canonical(config))
        self.restore_pins['profiles'][self.profile]['files'] = self.writer_files()
        self.restore_pins['profiles'][self.profile]['service']['ActiveState'] = 'active'
        self.put(n.RESTORE_ACCEPTED,n.canonical(self.restore_pins))

    def __exit__(self,*args):
        try:
            self.system.action('stop','xray.service')
        finally:
            super().__exit__(*args)


if __name__ == '__main__':
    unittest.main()
