"""Real local originals/flocks/process/UDS codec; physical/SSH/systemd MODELED.

No Mongo or remote execution. Settlement rows below are validator-only modeled
proofs; public owner CAS is exercised separately by the JS persistence fixture.
"""
import copy
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch
import test_irreversible_handback as ih
import coordinated_restore as c
import test_coordinated_restore as ct

HERE = Path(__file__).resolve().parent


class V2TerminalTests(unittest.TestCase):
    def test_inventory_physical_membership_profiles_and_source_drift_refuse_before_effects(self):
        with ct.cfixture(c, v2=True) as f, patch.object(c, 'trusted_read', lambda path: f.fs.read(path)[0]):
            for kind in ('missing', 'foreign', 'profile', 'physical', 'endpoint', 'origin', 'inventory-pin', 'identity-pin'):
                config = copy.deepcopy(f.config); node = next(iter(config['nodes'])); pin = config['nodes'][node]
                if kind == 'missing': del config['nodes'][node]
                if kind == 'foreign': config['nodes']['f'*24] = config['nodes'].pop(node)
                if kind == 'profile': pin['profiles'] = ['xray-main', 'xray-bridge']
                if kind == 'physical': pin['identity']['machineId'] = 'e'*32
                if kind == 'endpoint': pin['identity']['endpointIp'] = '104.143.201.72'
                if kind == 'origin': config['origin']['machineId'] = 'f'*32
                if kind == 'inventory-pin': config['inventorySha256'] = 'f'*64
                if kind == 'identity-pin': pin['identity']['inventorySha256'] = 'f'*64
                with self.subTest(kind=kind), self.assertRaises(Exception): c.validate(config)
            helper = f.root/ct.t.n.HELPER.lstrip('/'); helper.write_bytes(b'unaccepted-source')
            with self.assertRaisesRegex(RuntimeError, 'SOURCE_PIN'): c.validate(f.config)
            self.assertTrue(f.fs.absent(c.INTENT)); self.assertEqual(f.children, [])

    def test_v2_stale_owner_proofs_and_duplicate_holds_cannot_commit(self):
        import test_fresh_classic_launch as ft
        fresh = ft.load()
        with terminal_fixture() as f, patch.object(c, 'trusted_read', lambda path: f.fs.read(path)[0]):
            with self.assertRaisesRegex(RuntimeError, 'REVOKED'), c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope() as held:
                for kind in ('missing', 'duplicate', 'foreign', 'profile', 'generation', 'physical'):
                    proof = ih.settlement_proof(f, c); n = proof['nodes'][0]
                    if kind == 'missing': proof['nodes'].pop()
                    if kind == 'duplicate': proof['nodes'][1] = copy.deepcopy(n)
                    if kind == 'foreign': n['nodeId'] = 'f'*24
                    if kind == 'profile': n['targetProfile'] = 'xray-bridge'
                    if kind == 'generation': n['owner']['generation'] = n['priorOwnerGeneration']
                    if kind == 'physical': n['owner']['nodeIdentity']['machineId'] = 'f'*32
                    with self.subTest(kind=kind):
                        with self.assertRaises(RuntimeError): held.commit_handoff(proof)
                        with self.assertRaises(RuntimeError): fresh.settlement(held, proof)
                    self.assertFalse(held.commit_attempted); self.assertTrue(f.fs.absent(c.COMMIT))
                held.nodes[1].node = held.nodes[0].node
                with self.assertRaisesRegex(RuntimeError, 'ACTIVE_HOLDS'): held.check()
                self.assertFalse(held.active)
                # Scope revocation is sticky, including after repairing the ID.
                held.nodes[1].node = list(f.config['nodes'])[1]
                with self.assertRaisesRegex(RuntimeError, 'REVOKED'): held.check()
                self.assertEqual(held.failure_code(), 'COORDINATED_RESTORE_UNKNOWN_RETAINED')

    def test_live_inventory_drift_revokes_without_refresh_or_terminal_commit(self):
        import isolation
        with ct.cfixture(c, v2=True) as f, patch.object(c, 'trusted_read', lambda path: f.fs.read(path)[0]):
            coordinator = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
            with self.assertRaisesRegex(RuntimeError, 'REVOKED'), coordinator.restore_scope() as held:
                inventory = copy.deepcopy(f.inventory)
                inventory['nodes'][0]['physical']['bootId'] = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
                (f.root/isolation.INVENTORY.lstrip('/')).write_bytes(c.canonical(inventory))
                with self.assertRaises(Exception): held.check()
                self.assertFalse(held.active)
                with self.assertRaisesRegex(RuntimeError, 'REVOKED'): held.check()
                self.assertTrue(f.fs.absent(c.COMMIT))
            self.assertEqual(coordinator.failure_code(), 'COORDINATED_RESTORE_UNKNOWN_RETAINED')

    def test_v2_partial_restore_and_unknown_commit_retain_original_intents_no_activation(self):
        for kind in ('restore', 'commit-fsync'):
            with self.subTest(kind=kind), terminal_fixture() as f, patch.object(c, 'trusted_read', lambda path: f.fs.read(path)[0]):
                if kind == 'restore': f.fixtures[-1].put('/fixture-fail-effect', b'1')
                coordinator = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
                with self.assertRaises((RuntimeError, OSError)):
                    with coordinator.restore_scope() as held:
                        atomic = f.fs.atomic
                        def failed_commit(path, raw, *args, **kwargs):
                            atomic(path, raw, *args, **kwargs)
                            if path == c.COMMIT: raise OSError('MODELED unknown parent fsync after durable write')
                        f.fs.atomic = failed_commit
                        held.commit_handoff(ih.settlement_proof(f, c))
                self.assertFalse(coordinator.active)
                self.assertFalse(f.fixtures[-1].path('/classic-activated').exists())
                if kind == 'restore':
                    self.assertEqual(f.fs.read_json(c.INTENT)['restoredNodes'], [f.fixtures[0].node])
                else:
                    self.assertEqual(coordinator.failure_code(), 'COMMIT_UNKNOWN_NO_ACTIVATION')
                    self.assertFalse(f.fs.absent(c.COMMIT))
                with self.assertRaisesRegex(RuntimeError, 'PARTIAL'):
                    with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope(): self.fail('replayed')

    def test_two_node_fresh_terminal_uses_existing_coordinator_not_legacy_activation(self):
        import test_fresh_classic_launch as ft
        m = ft.load()
        # MODELED sealed root/UID/ingress. This is NOT the ordinary native artifact
        # and does not accept a B132 launch policy or alter frozen source packs.
        with ft.launch_fixture(m, v2=True) as f:
            result = f.launch()
            self.assertEqual(result['code'], 'COMMITTED_FRESH_ACTIVATION_CONFIRMED')
            self.assertEqual(f.count(), 1)
            self.assertEqual(set(f.fs.read_json(c.COMMIT)['nodePeers']), set(f.outer.config['nodes']))
            self.assertFalse(f.outer.fixtures[-1].path('/classic-activated').exists())
            with self.assertRaisesRegex(RuntimeError, 'REPLAY'): f.launch()

    def test_two_node_terminal_commit_belongs_to_same_live_holders_and_never_replays(self):
        with terminal_fixture() as f, patch.object(c, 'trusted_read', lambda path: f.fs.read(path)[0]):
            with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope() as held:
                proof = ih.settlement_proof(f, c)
                digest = held.commit_handoff(proof)
                self.assertEqual(set(f.fs.read_json(c.COMMIT)['nodePeers']), set(f.config['nodes']))
                held.activate_classic()
                self.assertEqual(f.fixtures[-1].path('/classic-activated').read_text(), digest)
                held.finish_handoff()
                self.assertTrue(held.handoff_completed)
                self.assertFalse(held.active)
                with self.assertRaisesRegex(RuntimeError, 'REPLAY'): held.commit_handoff(proof)
            self.assertEqual(f.fs.read_json(c.INTENT)['phase'], 'handoff-completed')

    def test_two_node_parser_callers_restore_actual_originals_and_live_owner_channel(self):
        with ct.cfixture(c, v2=True) as f, patch.object(c, 'trusted_read', lambda path: f.fs.read(path)[0]):
            self.assertIs(c.validate(f.config), f.config)
            for node, pin in f.config['nodes'].items():
                argv = c.ssh_argv(f.config, node)
                self.assertEqual(argv[-2], 'c3-test-operator@' + pin['identity']['endpointIp'])
                self.assertEqual(argv[-1], c.COMMAND)
            listener = socket.socket(socket.AF_UNIX)
            sock = str(f.root/'o.sock'); listener.bind(sock); listener.listen(1)
            code = '''import os,sys
from pathlib import Path
import test_node_originals as t
import coordinated_restore as c
fs=t.n.Files(t.n.Fixture(Path(sys.argv[1]),os.getuid(),os.getgid(),None))
c.trusted_read=lambda path:fs.read(path)[0]
with c.RestorationChannel(fs,fixture_socket=sys.argv[2]) as channel:
 assert channel.check() is None
'''
            try:
                with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope() as held:
                    self.assertEqual({n.node for n in held.nodes}, set(f.config['nodes']))
                    for node in f.fixtures:
                        self.assertEqual(node.path(node.config).read_bytes(), node.original)
                        self.assertEqual(set(node.fs.read_json(ct.t.n.BUNDLE)['profiles']), set(node.writer.profiles))
                    client = subprocess.Popen([sys.executable, '-B', '-c', code, str(f.root), sock], cwd=HERE,
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    try:
                        held.serve_owner(listener)
                    finally:
                        out, err = client.communicate(timeout=5)
                    self.assertEqual((client.returncode, out, err), (0, b'', b''))
            finally:
                listener.close()


class terminal_fixture(ct.cfixture):
    def __init__(self):
        super().__init__(c, v2=True, maintenance_id='12345678-1234-4234-8234-123456789abc')

    def __enter__(self):
        super().__enter__()
        atomic = self.fs.atomic
        def same_host(path, raw, *args, **kwargs):
            result = atomic(path, raw, *args, **kwargs)
            if path == c.COMMIT:
                self.fixtures[-1].put(path, raw)  # MODELED same-physical-host alias
            return result
        self.fs.atomic = same_host
        return self

    def spawn(self, node):
        f = self.fixtures[list(self.config['nodes']).index(node)]
        old = "shared=SimpleNamespace(check_hold=lambda *_:{'candidateClosure':{'group':'SIMULATED'}} if fs.read_json('/fixture-live.json')['candidateFrozen'] else {})"
        new = '''def shared_check(*args, **kwargs):
 c.need(fs.read_json('/fixture-live.json')['candidateFrozen'])
 if kwargs.get('command')=='activate-classic':
  c.need(c.sha(fs.read(c.COMMIT)[0])==kwargs['commit_sha'])
  (root/'classic-activated').write_text(kwargs['commit_sha'])
 return {'candidateClosure':{'group':'SIMULATED'}}
shared=SimpleNamespace(check_hold=shared_check)'''
        code = ct.CHILD.replace(old, new)
        assert code != ct.CHILD
        child = subprocess.Popen([sys.executable, '-B', '-c', code, str(f.root)], cwd=HERE,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.children.append(child)
        return child


def fixture_meta(f):
    import base64
    return {'root': str(f.root), 'socket': str(f.root/'j.sock'), 'restore': f.config, 'inventory': getattr(f, 'inventory', None),
        'acceptedOriginalsBase64': {n.node: base64.b64encode(n.fs.read(ct.t.n.ACCEPTED)[0]).decode() for n in f.fixtures}}


def serve_js():
    """Local same-Coordinator fixture; no Mongo/physical/root authority."""
    import json
    with terminal_fixture() as f, patch.object(c, 'trusted_read', lambda path: f.fs.read(path)[0]):
        sock = str(f.root/'j.sock')
        listener = socket.socket(socket.AF_UNIX); listener.bind(sock); listener.listen(1)
        try:
            with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope() as held:
                print(json.dumps(fixture_meta(f)), flush=True)
                held.serve_owner(listener)
            print(json.dumps({'commit': f.fs.read_json(c.COMMIT), 'intent': f.fs.read_json(c.INTENT)}), flush=True)
        finally:
            listener.close()


if __name__ == '__main__':
    if sys.argv[1:] == ['serve-js']:
        serve_js()
    elif sys.argv[1:] == ['meta-js']:
        import json
        with terminal_fixture() as fixture:
            print(json.dumps(fixture_meta(fixture)), flush=True)
    elif sys.argv[1:] == ['meta-v1-js']:
        import json
        with ct.cfixture(c, maintenance_id='12345678-1234-4234-8234-123456789abc') as fixture:
            print(json.dumps(fixture_meta(fixture)), flush=True)
    else:
        unittest.main()
