"""Real files/fsync/flocks; UID, SSH, kernel and systemd explicitly SIMULATED."""
from contextlib import ExitStack
import fcntl
import importlib.util
import os
from pathlib import Path
import unittest
import test_node_originals as t

HERE = Path(__file__).resolve().parent


def load():
    path = HERE / 'coordinated_capture.py'
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location('coordinated_capture', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CaptureHoldTests(unittest.TestCase):
    def test_actual_capture_has_all_open_locks_before_publication_and_keeps_them(self):
        c = load()
        self.assertIsNotNone(c, 'actual durable capture hold is missing')
        with t.DualFixture() as f:
            atomic = f.writer.fs.atomic
            def publication(path, *args, **kwargs):
                if path == t.n.BUNDLE:
                    for lock in (t.n.OUTER_LOCK,):
                        with open(f.path(lock), 'rb') as competitor:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return atomic(path, *args, **kwargs)
            f.writer.fs.atomic = publication
            with c.CaptureHold(f.writer, t.n) as held:
                self.assertFalse(f.path(t.n.BUNDLE).exists())
                held.capture()
                held.check()
                bundle = f.fs.read_json(t.n.BUNDLE)
                self.assertEqual(set(bundle['profiles']), {'xray-main', 'xray-bridge'})
                for lock in held.locks:
                    with open(f.path(lock), 'rb') as competitor:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(RuntimeError):
                held.check()
            self.assertEqual(f.system.events, [])
            self.assertTrue(f.fs.absent(t.n.RESTORE_STATE))


class FiveNodeTests(unittest.TestCase):
    def test_all_five_real_locks_precede_first_bundle_and_scope_is_not_replayable(self):
        import coordinated_capture as a
        import coordinated_restore as c
        from capture_fixture import CaptureFixture
        with CaptureFixture() as f:
            atomic = f.fs.atomic
            seen = []
            def record(path, raw, *args, **kwargs):
                if path == a.INTENT and a.decode(raw)['phase'] == 'capturing-retained' and not seen:
                    for node in f.fixtures:
                        self.assertFalse(node.path(t.n.BUNDLE).exists())
                        with open(node.path(t.n.OUTER_LOCK), 'rb') as competitor:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    seen.append(True)
                return atomic(path, raw, *args, **kwargs)
            f.fs.atomic = record
            coordinator = a.Coordinator(f.config,f.fs,f.spawn,c,origin=f.origin)
            with coordinator.capture_scope() as held:
                self.assertEqual(seen,[True])
                self.assertIsNone(held.check())
                self.assertEqual(f.fs.read_json(a.INTENT)['phase'],'captured-held')
                for node in f.fixtures:
                    bundle = node.fs.read_json(t.n.BUNDLE)
                    self.assertEqual(set(bundle['profiles']),set(node.writer.profiles))
                    self.assertEqual(bundle['acceptedSha256'],a.sha(a.canonical(node.accepted)))
                    self.assertEqual(node.path(node.config).read_bytes(),node.original)
                    self.assertFalse(node.path(t.n.RESTORE_STATE).exists())
                    self.assertEqual(node.system.events,[])
            with self.assertRaises(RuntimeError): held.check()
            with self.assertRaises(RuntimeError):
                with a.Coordinator(f.config,f.fs,f.spawn,c,origin=f.origin).capture_scope():
                    self.fail('historical capture is not a live hold')

    def test_installed_observer_cannot_reacquire_capture_outer_lock_known_default_blocker(self):
        import subprocess
        import sys
        import coordinated_capture as a
        import coordinated_restore as c
        from capture_fixture import CaptureFixture
        with CaptureFixture() as f:
            with a.Coordinator(f.config,f.fs,f.spawn,c,origin=f.origin).capture_scope():
                root = f.fixtures[0].path(t.n.STATE)
                code = '''import json,sys
from types import SimpleNamespace
import physical_attestor as p
m=SimpleNamespace(STATE=sys.argv[1],decode_json=json.loads)
p.observe=lambda *_: (_ for _ in ()).throw(AssertionError('MUST_NOT_REACH_OBSERVE'))
p.serve(None,m,None)
'''
                result = subprocess.run([sys.executable,'-c',code,str(root)],cwd=HERE,
                    input=a.canonical({'nonce':'a'*64,'predecessor':None})+b'\n',capture_output=True,timeout=3,
                    env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.stdout,b'')
                self.assertIn(b'BlockingIOError',result.stderr)
                self.assertNotIn(b'MUST_NOT_REACH_OBSERVE',result.stderr)

    def test_any_live_channel_eof_stickily_revokes_without_replay_or_restore(self):
        import coordinated_capture as a
        import coordinated_restore as c
        from capture_fixture import CaptureFixture
        with CaptureFixture() as f:
            with self.assertRaises(RuntimeError):
                with a.Coordinator(f.config,f.fs,f.spawn,c,origin=f.origin).capture_scope() as held:
                    f.children[2].kill(); f.children[2].wait(timeout=3)
                    with self.assertRaises(RuntimeError): held.check()
                    self.assertFalse(held.active)
                    with self.assertRaises(RuntimeError): held.check()
            self.assertEqual(f.fs.read_json(a.INTENT)['phase'],'captured-held')
            for node in f.fixtures:
                self.assertFalse(node.path(t.n.RESTORE_STATE).exists())
                self.assertEqual(node.path(node.config).read_bytes(),node.original)

    def test_missing_last_guard_refuses_before_any_capture_publication(self):
        import coordinated_capture as a
        import coordinated_restore as c
        from capture_fixture import CaptureFixture
        with CaptureFixture() as f:
            f.fixtures[-1].put('/fixture-live.json',a.canonical({'held':False}))
            with self.assertRaises(RuntimeError):
                with a.Coordinator(f.config,f.fs,f.spawn,c,origin=f.origin).capture_scope():
                    self.fail('missing guard accepted')
            for node in f.fixtures:
                self.assertFalse(node.path(t.n.BUNDLE).exists())
            self.assertEqual(f.fs.read_json(a.INTENT)['phase'],'acquiring-retained')

    def test_postcapture_drift_is_sticky_even_when_repaired(self):
        import coordinated_capture as a
        import coordinated_restore as c
        from capture_fixture import CaptureFixture
        with CaptureFixture() as f:
            coordinator = a.Coordinator(f.config,f.fs,f.spawn,c,origin=f.origin)
            with self.assertRaises(RuntimeError):
                with coordinator.capture_scope() as held:
                    node = f.fixtures[-1]
                    node.put(node.config,b'{"inbounds":[],"drift":true}')
                    with self.assertRaises(RuntimeError): held.check()
                    node.put(node.config,node.original)
                    self.assertFalse(held.active)
                    with self.assertRaises(RuntimeError): held.check()
            self.assertEqual(f.fs.read_json(a.INTENT)['phase'],'captured-held')

    def test_actual_fsync_failure_leaves_partial_bytes_and_no_success(self):
        from unittest.mock import patch
        a = load()
        with t.Fixture() as f:
            real = os.fsync
            def fsync(fd):
                if os.readlink('/proc/self/fd/'+str(fd)).endswith('/originals.json.next'):
                    raise OSError('SIMULATED storage failure')
                return real(fd)
            with a.CaptureHold(f.writer,t.n) as held:
                with patch.object(os,'fsync',side_effect=fsync), self.assertRaises(OSError):
                    held.capture()
                with self.assertRaises(RuntimeError): held.check()
            self.assertFalse(f.path(t.n.BUNDLE).exists())
            self.assertTrue(f.path(t.n.BUNDLE+'.next').exists())
            self.assertEqual(f.system.events,[])

    def test_config_and_fixed_ssh_reject_missing_node_aliases_profile_and_unaccepted_pins(self):
        import copy
        import coordinated_capture as a
        from capture_fixture import CaptureFixture
        with CaptureFixture() as f:
            for case in ('missing','alias','key','dual','owner','extra','version'):
                config = copy.deepcopy(f.config)
                ids = list(config['nodes'])
                if case == 'missing': del config['nodes'][ids[0]]
                if case == 'alias': config['nodes'][ids[0]]['identity']['machineId'] = config['nodes'][ids[1]]['identity']['machineId']
                if case == 'key': config['nodes'][ids[0]]['hostKey'] = 'not-a-key'
                if case == 'dual': config['nodes'][ids[3]]['profiles'] = ['xray-bridge']
                if case == 'owner': config['ownerChallenge']['nodes'][0]['originalSnapshot']['configSha256'] = True
                if case == 'extra': config['command'] = 'shell'
                if case == 'version': config['version'] = True
                with self.subTest(case=case), self.assertRaises((RuntimeError,ValueError,TypeError)):
                    a.validate(config)
            for node in a.NODES:
                argv = a.ssh_argv(f.config,node)
                self.assertEqual(argv[-1],a.COMMAND)
                for flag in ('ControlMaster=no','ControlPath=none','IdentityAgent=none','StrictHostKeyChecking=yes','ProxyCommand=none','ProxyJump=none'):
                    self.assertIn(flag,argv)


if __name__ == '__main__':
    unittest.main()