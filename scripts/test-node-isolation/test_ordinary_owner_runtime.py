"""Local ordinary files/OFD/pidfd/UDS; privileged/PID1 seams are models."""
import array
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

f = load('ordinary_freezer', HERE.parent/'panel-host-freezer.py')
n = load('ordinary_network', HERE/'fresh_network.py')
c = load('ordinary_control', HERE/'fresh_network_control.py')

class LiveSuccessionTests(unittest.TestCase):
    def test_actual_locked_journal_crosses_rights_without_reopen_or_unlock(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = f.Journal(Path(directory)/'host')
            class Kernel:
                def verify(self, expected, frozen, dead): pass  # modeled cgroup freezer
                def live_capabilities(self, expected): return []
                def check_live_capabilities(self):
                    for row,fd in self._live:
                        assert f.capability(fd,row['role'],row['kind'],row.get('binding')) == row
            original = f.Fence({'groups': {}, 'freezeOrder': []}, Kernel(), journal, 'owner')
            original.phase = 'held'; original.record('held')
            left, right = socket.socketpair()
            result = []; errors = []
            def receive():
                try: result.append(f.LiveFenceOffer.receive(right, expected_peer=os.getpid()))
                except BaseException as error: errors.append(error)
            thread = threading.Thread(target=receive); thread.start()
            offer = original.stage_live('a'*64)
            offer.send(left)
            thread.join(3)
            self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
            received = result[0]
            shared = received.fds[0]
            fcntl.flock(shared, fcntl.LOCK_EX|fcntl.LOCK_NB)
            independent = os.open(journal.path, os.O_RDONLY|os.O_DIRECTORY)
            try:
                with self.assertRaises(BlockingIOError): fcntl.flock(independent, fcntl.LOCK_EX|fcntl.LOCK_NB)
                original.surrender_live(offer.sha256, 'b'*64)
                with self.assertRaisesRegex(RuntimeError, 'passive'): original.record('held')
                original.check()  # passive is read-only, no second journal writer
                successor = f.Fence.accept_live(received,Kernel())
                transcript = f.live_sha(f.live_encode({'liveOfferSha256':offer.sha256,'commitSha256':'b'*64}))
                successor.consume_live('b'*64,transcript)
                successor.check()
                with self.assertRaisesRegex(RuntimeError,'escrow'): successor.consume_live('b'*64,transcript)
                with self.assertRaisesRegex(RuntimeError,'passive'): successor.record('held')
            finally:
                os.close(independent); received.close(); left.close(); right.close(); os.close(journal.fd)

    def test_receive_collects_all_rights_before_rejecting_truncation(self):
        # Actual SO_PASSCRED inserts credentials before installed SCM_RIGHTS.
        left,right = socket.socketpair(); right.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        fd = os.open(HERE,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        before = len(os.listdir('/proc/self/fd'))
        try:
            left.sendmsg([b'F'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
            with self.assertRaisesRegex(n.Refusal,'CLOSED_SERVING_RIGHTS_REQUIRED'):
                c.receive_rights(right,n,1)
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)
        finally: os.close(fd); left.close(); right.close()


class CompositionTests(unittest.TestCase):
    def test_existing_policy_digest_meanings_are_bound_before_network_preparation(self):
        import coordinated_restore as restore
        # Pure root-file composition; no seeded COMMIT/grant and no effect seam.
        source, fresh, shared_source, isolation_source, freezer = (b'coordinator',b'fresh',b'shared',b'isolation',b'freezer')
        from test_fresh_network import plan
        network = plan(); network['ordinaryOwner']={'version':1,'stopConfigSha256':n.digest(n.encode(n.stopped_config(network)))}
        network_raw = n.encode(network)
        shared = {'version':2,'machineId':network['machine'],'bootId':network['boot'],
                  'hostHold':{'networkPlanSha256':n.digest(network_raw),'freezerSha256':n.digest(freezer)}}
        config = {'version':2,'origin':{'machineId':network['machine'],'bootId':network['boot']},'nodes':{
            'shared':{'identity':{'planHash':restore.sha(restore.canonical(shared))},'files':{
                'shared':restore.sha(shared_source),'isolation':restore.sha(isolation_source),'freezer':restore.sha(freezer)}}}}
        policy = {'inventory':{'coordinatorSha256':restore.sha(restore.canonical(config)),
                  'sourceSha256':restore.sha(source),'networkPlanSha256':n.digest(network_raw)},
                  'files':{restore.SELF:restore.sha(source),restore.FRESH:restore.sha(fresh)}}
        root = {'version':2,'networkPlanSha256':n.digest(network_raw),'coordinatorSha256':restore.sha(source)}
        inputs={restore.SELF:source,restore.FRESH:fresh,restore.SHARED:shared_source,
                '/usr/local/libexec/c3-test-node-isolation':isolation_source,restore.FREEZER:freezer,
                '/etc/c3-test-node-isolation.json':restore.canonical(shared),'/etc/c3-test-fresh-network.json':network_raw}
        class Files:
            def read(self,path):return inputs[path],{}
            def read_json(self,path):return restore.decode(self.read(path)[0])
        with patch.object(restore,'shared_node',return_value='shared'):
            self.assertEqual(restore.network_composition(Files(),config,root,policy),shared)
            policy['inventory']['coordinatorSha256']=restore.sha(source)
            with self.assertRaisesRegex(restore.Refusal,'NETWORK_COMPOSITION_BINDING_REQUIRED'):
                restore.network_composition(Files(),config,root,policy)

class CustodyTests(unittest.TestCase):
    def test_full_dump_named_subtraction_and_dead_original_pidfd(self):
        self.assertTrue(hasattr(c, 'PID1Store'), 'product main has no PID1 custody implementation')
        with tempfile.TemporaryDirectory() as directory:
            journal = f.Journal(Path(directory)/'host')
            process = subprocess.Popen([sys.executable, '-c', 'pass'])
            dead = os.pidfd_open(process.pid); self.assertEqual(process.wait(), 0)
            rows = [f.capability(journal.fd, 'host.journal', 'journal'),
                    f.capability(dead, 'network.dead', 'pidfd')]
            class Store(c.PID1Store):
                def __init__(self):
                    self.m = n; self.generation = 'a'*32; self.table = []; self.notices = []
                def notify(self, payload, fds=()):
                    self.notices.append(payload)
                    fields = dict(line.split('=',1) for line in payload.splitlines())
                    if 'FDSTORE' in fields:
                        self.table.append(self.row(fields['FDNAME'], f.capability(fds[0], 'x', 'x')))
                    elif 'FDSTOREREMOVE' in fields:
                        self.table = [r for r in self.table if r[0] != fields['FDNAME']]
                def barrier(self): self.notices.append('barrier')
                def dump(self): return [list(row) for row in self.table]
            store = Store(); bindings = store.stage(rows, [journal.fd, dead])
            self.assertTrue(all('FDPOLL=0' in x for x in store.notices if 'FDSTORE=1' in x))
            self.assertTrue(select_readable(dead))
            store.remove([bindings[1]], bindings)
            self.assertEqual(len(store.dump()), 1)
            with self.assertRaises(n.Refusal): store.verify(bindings)
            store.remove([bindings[0]], bindings[:1]); self.assertEqual(store.dump(), [])
            os.close(dead); os.close(journal.fd)


def select_readable(fd):
    import select
    return bool(select.select([fd], [], [], 0)[0])


class StopConfigTests(unittest.TestCase):
    def test_stop_is_unique_handler_replacement_preserving_types_and_routes(self):
        p = {'newConfig': {'apps': {'routes': [{'handle': [{'handler': 'reverse_proxy',
             'upstreams': [{'dial': n.PUBLIC+':3000'}]}], 'terminal': False}]}, 'zero': 0}}
        expected = {'apps': {'routes': [{'handle': [{'handler': 'static_response', 'status_code': 503,
                    'body': 'c3-classic-stopped-v1\n'}], 'terminal': False}]}, 'zero': 0}
        self.assertEqual(n.encode(n.stopped_config(p)), n.encode(expected))
        self.assertEqual(p['newConfig']['zero'], 0)
        p['newConfig']['apps']['routes'][0]['handle'][0]['upstreams'].append({'dial':'foreign:3000'})
        with self.assertRaises(n.Refusal): n.stopped_config(p)

if __name__ == '__main__': unittest.main()
