"""Local filesystem/flocks/protocol; root, physical/SSH/systemd SIMULATED."""
import base64
import fcntl
import importlib.util
import os
from pathlib import Path
import unittest
import test_node_originals as t

HERE = Path(__file__).resolve().parent


class HeldRestoreTests(unittest.TestCase):
    def test_boolean_or_forged_scope_cannot_substitute_for_real_open_lock_scope(self):
        import time
        with t.Fixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            writer = t.n.NodeOriginals(f.engine, f.module, fixture=f.fixture)
            writer.deadline = time.monotonic() + 10
            alleged = t.n._HeldRestoration(writer)
            alleged._active = True
            alleged._prepared = writer._prepare_restore()
            with self.assertRaises(RuntimeError):
                alleged.restore()
            self.assertTrue(f.fs.absent(t.n.RESTORE_STATE))
            self.assertEqual(f.system.events, [])

    def test_failed_held_readback_latches_revocation_even_if_bytes_are_repaired(self):
        with t.Fixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            with f.writer.restoration_hold() as held:
                held.restore()
                f.put(f.config, b'{"inbounds":[],"foreign":true}')
                with self.assertRaises(RuntimeError):
                    held.verify()
                f.put(f.config, f.original)
                with self.assertRaises(RuntimeError):
                    held.check()

    def test_actual_restore_reuses_held_descriptors_and_keeps_every_lock_after_readback(self):
        with t.DualFixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            self.assertTrue(hasattr(f.writer, 'restoration_hold'),
                            'persistent restoration lock scope is missing')
            with f.writer.restoration_hold() as held:
                for path in (t.n.OUTER_LOCK, *(t.n.runner_lock(p) for p in f.writer.profiles)):
                    with open(f.path(path), 'rb') as competitor:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = held.restore()
                self.assertTrue(result['ok'])
                held.verify()
                for path in f.writer.lock_paths:
                    with open(f.path(path), 'rb') as competitor:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(RuntimeError):
                held.verify()
            self.assertEqual(f.fs.read_json(t.n.ADMISSION)['state'], 'closed')


from contextlib import ExitStack
import copy
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace


class cfixture:
    """Real subprocess channels and files; UID/SSH/physical/systemd/kernel simulated."""
    def __init__(self, c):
        self.c = c

    def __enter__(self):
        c = self.c
        self.stack = ExitStack()
        self.fixtures, self.children = [], []
        self.tmp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(self.tmp)
        self.fs = t.n.Files(t.n.Fixture(self.root, os.getuid(), os.getgid(), None))
        self.origin = {'machineId': 'f'*32, 'bootId': 'ffffffff-ffff-ffff-ffff-ffffffffffff',
                       'cgroup': '0::/simulated-root-operator', 'uid': 0, 'pid': os.getpid(), 'start': c.proc_start(os.getpid())}
        self.config = {'version': 1, 'context': 'test.infograd.online', 'lifetimeSeconds': 80,
                       'origin': {k:v for k,v in self.origin.items() if k not in ('pid', 'start')},
                       'keySha256': 'f'*64, 'nodes': {}}
        for index, (node, (endpoint, profile)) in enumerate(c.NODES.items()):
            f = self.stack.enter_context(t.DualFixture() if endpoint == '104.143.201.72' else t.Fixture())
            f.node, f.profile = node, profile
            f.plan.update(nodeId=node, endpointIp=endpoint, targetProfile=profile, machineId=c.sha(node.encode())[:32])
            key = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes([index+1])*32
            f.plan['sshHostKeySha256'] = c.sha(key)
            if profile == 'xray-main':
                f.config, f.unit = t.n.profile_paths(profile)
                f.put(f.config, f.original)
                f.put(f.unit, b'[Service]\n# original main fixture\n')
                f.put(t.n.runner_lock(profile), b'')
                state = f.system.states['xray-bridge.service']
                state.update(Id='xray.service', FragmentPath=f.unit)
                f.system.states['xray.service'] = state
            f.accepted.update(t.n.identity(f.engine))
            profiles = ['xray-main','xray-bridge'] if endpoint == '104.143.201.72' else [profile]
            f.accepted['profiles'] = {p: {'files': {k:f.fs.info(path) for k,path in zip(('config','unit'),t.n.profile_paths(p))},
                  'service': f.system.unit(t.n.service_name(p)), 'runtimeSha256': c.sha(c.canonical({'mode':'none','inbounds':{}}))} for p in profiles}
            f.put(t.n.ACCEPTED, c.canonical(f.accepted))
            f.writer = t.n.NodeOriginals(f.engine, f.module, fixture=f.fixture)
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            f.put(c.SELF, (HERE / 'coordinated_restore.py').read_bytes())
            f.put(c.ORIGINALS, (HERE / 'node_originals.py').read_bytes())
            pin = {'identity': t.n.identity(f.engine), 'profiles': profiles, 'guard': f.guard,
                   'hostKey': base64.b64encode(key).decode(),
                   'files': {name: c.sha(f.fs.read(path)[0]) for name,path in {'self':c.SELF, 'originals':c.ORIGINALS,
                        'isolation':t.n.HELPER, 'accepted':t.n.ACCEPTED, 'restoreAccepted':t.n.RESTORE_ACCEPTED}.items()}}
            if node == '6ab189dc63913ebd4a917399':
                for name, path in (('shared', c.SHARED), ('freezer', c.FREEZER)):
                    f.put(path, ('independently pinned SIMULATED ' + name).encode())
                    pin['files'][name] = c.sha(f.fs.read(path)[0])
            self.config['nodes'][node] = pin
            f.put('/fixture-live.json', c.canonical({'held': True, 'candidateFrozen': True}))
            f.put('/fixture-services.json', c.canonical(f.system.states))
            self.fixtures.append(f)
        for f in self.fixtures:
            f.put(c.CONFIG, c.canonical(self.config))
        path = self.root / c.CONFIG.lstrip('/')
        path.parent.mkdir(parents=True, mode=0o700)
        path.write_bytes(c.canonical(self.config)); path.chmod(0o600)
        directory = self.root / c.STATE.lstrip('/')
        directory.mkdir(parents=True, mode=0o700)
        for leaf in (path.parent, directory):
            for parent in (leaf, *leaf.parents):
                if parent == self.root.parent:
                    break
                parent.chmod(0o700)
        return self

    def spawn(self, node):
        f = self.fixtures[list(self.config['nodes']).index(node)]
        child = subprocess.Popen([sys.executable, '-c', CHILD, str(f.root)], cwd=HERE,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'}, bufsize=0)
        self.children.append(child)
        return child

    def __exit__(self, *args):
        for child in self.children:
            if child.poll() is None:
                child.kill(); child.wait(timeout=3)
            if child.stderr:
                stderr = child.stderr.read()
                child.stderr.close()
                if stderr:
                    print('SIMULATED CHILD:', stderr.decode(), file=sys.stderr)
        self.stack.close()


CHILD = '''import json, os, sys, time
from pathlib import Path
from types import SimpleNamespace
import test_node_originals as t
import coordinated_restore as c
n=t.n
root=Path(sys.argv[1])
fixture=n.Fixture(root, os.getuid(), os.getgid(), None)
fs=n.Files(fixture)
accepted=fs.read_json(n.ACCEPTED)
bundle=fs.read_json(n.BUNDLE)
plan={k:accepted[k] for k in n.IDENTITY}
engine=SimpleNamespace(plan=plan,plan_hash=accepted['planHash'])
def held():
    n.need(fs.read_json('/fixture-live.json')['held'], 'SIMULATED_GUARD_LOST')
    return {'guard':bundle['guard'],'dispatchInFlight':None,'dispatchCount':1}
engine.assert_held=held
engine.host=SimpleNamespace(physical=lambda:{k:plan[k] for k in ('machineId','bootId','sshHostKeySha256')},
                            operator_session=lambda:{'pid':78,'start':'999'})
def guard_check(guard,session=None):
    n.need(guard==bundle['guard'] and session=={'pid':78,'start':'999'}, 'FRESH_INDEPENDENT_SESSION_REQUIRED')
    n.need(fs.read_json('/fixture-live.json')['held'], 'SIMULATED_GUARD_LOST')
    return {'session':{'pid':77,'start':'998'}}
engine.host.guard_check=guard_check
system=t.SimulatedSystem(SimpleNamespace(unit=n.profile_paths(plan['targetProfile'])[1]))
system.states=fs.read_json('/fixture-services.json')
fixture.system=system
original_action=system.action
def action(*args,**kwargs):
    n.need(fs.absent('/fixture-fail-effect'), 'SIMULATED_EFFECT_FAILURE')
    if not fs.absent('/fixture-block-effect'):
        (root/'fixture-block-entered').write_bytes(b'blocked-before-simulated-effect')
        with open(root/'fixture-block-effect', 'rb') as blocked:
            blocked.read(1)
    return original_action(*args,**kwargs)
system.action=action
writer=n.NodeOriginals(engine,SimpleNamespace(RESTORE_ADMISSION_VERSION=1),fixture=fixture)
shared=SimpleNamespace(check_hold=lambda *_:{'candidateClosure':{'group':'SIMULATED'}} if fs.read_json('/fixture-live.json')['candidateFrozen'] else {})
try:
    c.NodeServer(writer,n,fs.read_json(c.CONFIG),c.Wire(0,1,time.monotonic()+80),shared=shared).serve()
except BaseException:
    raise SystemExit(75)
'''


def load_c():
    spec = importlib.util.spec_from_file_location('coordinated_restore', HERE / 'coordinated_restore.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CoordinatedProtocolTests(unittest.TestCase):
    def test_root_peer_socket_challenges_are_fresh_and_no_transferable_go_is_exported(self):
        import socket
        import time
        c = load_c()
        self.assertTrue(hasattr(c, 'RestorationChannel'), 'fixed root-channel client capability missing')
        with cfixture(c) as f:
            # Short UDS below approved scratch; sun_path must remain bounded.
            path = f.root / 'owner.sock'
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path)); listener.listen(1)
            client_code = '''import os, sys
from pathlib import Path
import test_node_originals as t
import coordinated_restore as c
fs=t.n.Files(t.n.Fixture(Path(sys.argv[2]),os.getuid(),os.getgid(),None))
with c.RestorationChannel(fs,fixture_socket=sys.argv[1]) as restoration:
    nonce=restoration.nonce
    assert restoration.check() is None
    assert restoration.nonce != nonce
    assert restoration.active
assert restoration.active is False
try:
    restoration.check()
except RuntimeError:
    pass
else:
    raise AssertionError('escaped capability')
'''
            with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope() as held:
                client = subprocess.Popen([sys.executable, '-c', client_code, str(path), str(f.root)], cwd=HERE,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
                try:
                    held.serve_owner(listener)
                finally:
                    out, err = client.communicate(timeout=5)
                    listener.close()
                self.assertEqual(client.returncode, 0, err.decode())
                self.assertEqual(out, b'')

    def test_owner_eof_latches_revocation_even_if_trusted_caller_swallows_error(self):
        import socket
        c = load_c()
        with cfixture(c) as f:
            path = f.root / 'owner.sock'
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path)); listener.listen(1)
            coordinator = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
            with self.assertRaises(RuntimeError):
                with coordinator.restore_scope() as held:
                    client = subprocess.Popen([sys.executable, '-c',
                        'import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1]); s.close()',
                        str(path)])
                    try:
                        with self.assertRaises((RuntimeError, OSError)):
                            held.serve_owner(listener)
                    finally:
                        client.wait(timeout=3); listener.close()
                    self.assertFalse(held.active, 'owner EOF must permanently revoke the same scope')
                    with self.assertRaises(RuntimeError):
                        held.check()

    def test_loss_of_idle_peer_interrupts_a_blocked_restore_channel(self):
        import threading
        import time
        c = load_c()
        with cfixture(c) as f:
            os.mkfifo(f.fixtures[0].path('/fixture-block-effect'), 0o600)
            observed = threading.Event()
            stop = threading.Event()
            def kill_idle_peer_after_effect_entry():
                deadline = time.monotonic() + 10
                while not stop.wait(.005) and time.monotonic() < deadline:
                    if f.fixtures[0].path('/fixture-block-entered').exists():
                        observed.set()
                        f.children[-1].kill()
                        return
            killer = threading.Thread(target=kill_idle_peer_after_effect_entry)
            killer.start()
            coordinator = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(RuntimeError, 'OTHER_CHANNEL_LOST'):
                    with coordinator.restore_scope():
                        self.fail('loss must interrupt a blocked different peer')
            finally:
                stop.set(); killer.join(timeout=2)
            self.assertTrue(observed.is_set())
            self.assertFalse(killer.is_alive())
            self.assertLess(time.monotonic() - started, 12)
            self.assertFalse(coordinator.active)
            self.assertEqual(f.fs.read_json(c.INTENT)['restoredNodes'], [])
            for node in f.fixtures:
                self.assertNotEqual(node.path(node.config).read_bytes(), node.original)
                self.assertEqual(node.fs.read_json(t.n.ADMISSION)['state'], 'closed')

    def test_node_protocol_rejects_replay_unknown_fields_and_boolean_sequence_before_effects(self):
        import time
        c = load_c()
        for case in ('replay', 'nonce', 'extra', 'boolean-seq', 'foreign-origin', 'foreign-command'):
            with self.subTest(case=case), cfixture(c) as f:
                node = f.fixtures[0]
                child = f.spawn(node.node)
                channel = c.Channel(child, node.node, f.config['nodes'][node.node], 'a'*64, f.origin, time.monotonic()+8)
                try:
                    channel.start([])
                    frame = {'version':1,'op':'restore','nodeId':node.node,'nodeNonce':channel.hello['nodeNonce'],
                             'coordinatorNonce':'a'*64,'seq':1,'challenge':'b'*64,'origin':f.origin}
                    if case == 'replay': frame['seq'] = 0
                    if case == 'nonce': frame['nodeNonce'] = 'c'*64
                    if case == 'extra': frame['go'] = True
                    if case == 'boolean-seq': frame['seq'] = True
                    if case == 'foreign-origin': frame['origin'] = {**f.origin,'pid':123456}
                    if case == 'foreign-command': frame['op'] = 'shell'
                    channel.wire.send(frame)
                    with self.assertRaisesRegex(RuntimeError, 'EOF'):
                        channel.wire.receive()
                    self.assertTrue(node.fs.absent(t.n.RESTORE_STATE))
                    self.assertEqual(node.fs.read_json(t.n.ADMISSION)['state'], 'closed')
                finally:
                    channel.close()

    def test_any_channel_eof_revokes_capability_without_reopening_or_replay(self):
        c = load_c()
        with cfixture(c) as f:
            coordinator = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
            with self.assertRaises(RuntimeError):
                with coordinator.restore_scope() as held:
                    f.children[2].kill(); f.children[2].wait(timeout=3)
                    with self.assertRaises(RuntimeError):
                        held.check()
                    self.assertFalse(held.active)
                    with self.assertRaises(RuntimeError):
                        held.check()
            self.assertEqual(f.fs.read_json(c.INTENT)['phase'], 'restored-held')
            with self.assertRaisesRegex(RuntimeError, 'PARTIAL'):
                with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope():
                    self.fail('must never replay a retained attempt')
            for node in f.fixtures:
                self.assertEqual(node.fs.read_json(t.n.ADMISSION)['state'], 'closed')

    def test_independent_pins_and_closed_current_heads_are_required_before_any_node_effect(self):
        c = load_c()
        for case in ('source-pin', 'accepted-pin', 'head', 'admission', 'candidate-unfrozen', 'guard-lost'):
            with self.subTest(case=case), cfixture(c) as f:
                node = f.fixtures[-1]
                if case in ('source-pin', 'accepted-pin', 'head'):
                    path = {'source-pin': c.ORIGINALS, 'accepted-pin': t.n.RESTORE_ACCEPTED,
                            'head': t.n.runner_journal(node.profile)}[case]
                    node.put(path, b'{}')
                elif case == 'admission':
                    node.put(t.n.ADMISSION, b'{}')
                else:
                    node.put('/fixture-live.json', c.canonical({'held':case != 'guard-lost',
                                                           'candidateFrozen':case != 'candidate-unfrozen'}))
                with self.assertRaises((RuntimeError, OSError)):
                    with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope():
                        self.fail('unknown node cannot authorize restoration')
                for other in f.fixtures:
                    self.assertTrue(other.fs.absent(t.n.RESTORE_STATE))
                    self.assertNotEqual(other.path(other.config).read_bytes(), other.original)
                self.assertEqual(f.fs.read_json(c.INTENT)['phase'], 'acquiring-retained')

    def test_partial_node_effect_retains_exact_known_progress_and_no_success_capability(self):
        c = load_c()
        with cfixture(c) as f:
            f.fixtures[1].put('/fixture-fail-effect', b'1')
            coordinator = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
            with self.assertRaises(RuntimeError):
                with coordinator.restore_scope():
                    self.fail('partial restoration cannot publish live authority')
            intent = f.fs.read_json(c.INTENT)
            self.assertEqual(intent['phase'], 'restoring-retained')
            self.assertEqual(intent['restoredNodes'], [f.fixtures[0].node])
            self.assertEqual(f.fixtures[0].path(f.fixtures[0].config).read_bytes(), f.fixtures[0].original)
            self.assertEqual(f.fixtures[1].fs.read_json(t.n.RESTORE_STATE)['phase'], 'restoring-retained')
            for node in f.fixtures[2:]:
                self.assertTrue(node.fs.absent(t.n.RESTORE_STATE))
            self.assertFalse(coordinator.active)

    def test_fixed_ssh_surface_and_config_refuse_aliases_unknown_nodes_and_user_commands(self):
        c = load_c()
        with cfixture(c) as f:
            for case in ('missing-node', 'foreign-node', 'alias', 'hostkey', 'endpoint', 'dual-profile', 'extra', 'bool-version'):
                config = copy.deepcopy(f.config)
                ids = list(config['nodes'])
                pin = config['nodes'][ids[0]]
                if case == 'missing-node': del config['nodes'][ids[0]]
                if case == 'foreign-node': config['nodes']['foreign'] = pin
                if case == 'alias': pin['identity']['machineId'] = config['nodes'][ids[1]]['identity']['machineId']
                if case == 'hostkey': pin['hostKey'] = base64.b64encode(b'foreign').decode()
                if case == 'endpoint': pin['identity']['endpointIp'] += '; command'
                if case == 'dual-profile': config['nodes'][ids[3]]['profiles'] = ['xray-bridge']
                if case == 'extra': config['command'] = 'arbitrary'
                if case == 'bool-version': config['version'] = True
                with self.subTest(case=case), self.assertRaises((RuntimeError, ValueError, TypeError)):
                    c.validate(config)
            for node in c.NODES:
                argv = c.ssh_argv(f.config, node)
                self.assertEqual(argv[-1], c.COMMAND)
                for option in ('ControlMaster=no', 'ControlPath=none', 'ProxyCommand=none', 'ProxyJump=none',
                               'BatchMode=yes', 'StrictHostKeyChecking=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none'):
                    self.assertIn(option, argv)
                self.assertNotIn('sftp', argv)
        for args in (['--root','/foreign'], ['restore','/foreign'], ['node-hold'], ['dispatch']):
            result = subprocess.run([sys.executable, str(HERE/'coordinated_restore.py'), *args],
                                    input=b'private-secret', capture_output=True, timeout=3,
                                    env={**os.environ,'C3_COORDINATED_RESTORE_ROOT':'/foreign'})
            self.assertEqual(result.returncode, 75)
            self.assertEqual(result.stdout, b'')
            self.assertNotIn(b'private-secret', result.stderr)

    def test_five_subprocess_helpers_keep_actual_locks_across_restore_and_root_scope(self):
        spec = importlib.util.spec_from_file_location('coordinated_restore', HERE / 'coordinated_restore.py')
        self.assertTrue((HERE / 'coordinated_restore.py').exists(),
                        'actual foreground coordination helper missing')
        c = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(c)
        with cfixture(c) as f:
            with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope() as held:
                held.check()
                self.assertEqual(len(held.nodes), 5)
                for node in f.fixtures:
                    self.assertEqual(node.path(node.config).read_bytes(), node.original)
                    for path in (t.n.OUTER_LOCK, *(t.n.runner_lock(p) for p in node.writer.profiles)):
                        with open(node.path(path), 'rb') as other:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(f.fs.read_json(c.INTENT)['phase'], 'restored-held')
            with self.assertRaises(RuntimeError):
                held.check()
            for node in f.fixtures:
                self.assertEqual(node.fs.read_json(t.n.ADMISSION)['state'], 'closed')


if __name__ == '__main__':
    unittest.main()
