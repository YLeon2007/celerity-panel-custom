"""Real pipes/five NodeServers and flocks; physical/root/systemd authority simulated."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

import test_coordinated_restore as t
import test_irreversible_handback as it


def load_c():
    revision = os.environ.get('C3_PARALLEL_BASELINE')
    if not revision:
        return t.load_c()
    # Immutable RED replay: never reset/edit another owner's checked-out file.
    import types
    raw = subprocess.check_output(['git', 'show', revision+':scripts/test-node-isolation/coordinated_restore.py'], cwd=t.HERE)
    module = types.ModuleType('coordinated_restore_baseline')
    exec(compile(raw, '<immutable-coordinated-restore-baseline>', 'exec'), module.__dict__)
    return module


BARRIER = '''
original_shared = shared.check_hold
def check_shared(*args, **kwargs):
    if kwargs.get('command') == 'activate-classic':
        raw = fs.read(c.COMMIT)[0]
        assert c.sha(raw) == kwargs['commit_sha']
        (root/'classic-activated').write_text(kwargs['commit_sha'])
    return original_shared(*args)
shared.check_hold = check_shared
original_receive = c.Wire.receive
round_number = 0
def receive(self, watch=()):
    global round_number
    frame = original_receive(self, watch)
    gate = Path(sys.argv[2])
    if (gate/'enabled').exists() and frame['op'] == 'check':
        round_number += 1
        (gate/(str(round_number)+'-'+plan['nodeId'])).touch()
        until = time.monotonic()+1
        while not all((gate/(str(round_number)+'-'+node)).exists()
                      for node in c.NODES if not (gate/('released-'+node)).exists()):
            if time.monotonic() >= until:
                raise RuntimeError('ALL_REQUESTS_BARRIER_TIMEOUT')
            time.sleep(.001)
    if frame['op'] == 'release':
        (gate/('released-'+plan['nodeId'])).touch()
    return frame
c.Wire.receive = receive
original_send = c.Wire.send
def send(self, value):
    fault_path = Path(sys.argv[2])/'fault.json'
    if value.get('op') == 'check-held' and fault_path.exists():
        faults = json.loads(fault_path.read_text())
        fault = faults.get(plan['nodeId'])
        if fault == 'eof':
            os._exit(75)
        if fault == 'partial':
            os.write(1, b'{')
            time.sleep(2)
            return
        if fault == 'silent':
            time.sleep(2)
            return
        if fault:
            value = dict(value)
            if fault == 'extra':
                value['go'] = True
            elif fault in ('version', 'seq'):
                value[fault] = True
            elif fault == 'operator':
                value[fault] = {'pid':79, 'start':'999'}
            elif fault == 'origin':
                value[fault] = {**value[fault], 'pid': value[fault]['pid']+1}
            elif fault == 'pid':
                value[fault] += 1
            elif fault == 'restored':
                value[fault] = False
            else:
                value[fault] = '0'*64
    return original_send(self, value)
c.Wire.send = send
'''


class BarrierFixture(t.cfixture):
    def __enter__(self):
        super().__enter__()
        self.gate = self.root/'barrier'
        self.gate.mkdir()
        atomic = self.fs.atomic
        def alias(path, raw, *args, **kwargs):
            result = atomic(path, raw, *args, **kwargs)
            if path == self.c.COMMIT:
                # Explicitly simulated shared physical-host path alias.
                self.fixtures[-1].put(path, raw)
            return result
        self.fs.atomic = alias
        return self

    def spawn(self, node):
        f = self.fixtures[list(self.config['nodes']).index(node)]
        code = t.CHILD.replace('try:\n    c.NodeServer', BARRIER+'\ntry:\n    c.NodeServer')
        child = subprocess.Popen([sys.executable, '-c', code, str(f.root), str(self.gate)],
                                 cwd=t.HERE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, bufsize=0,
                                 env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'})
        self.children.append(child)
        return child


class ParallelCheckpoints(unittest.TestCase):
    def test_five_actual_servers_receive_every_check_before_any_reply(self):
        c = load_c()
        with BarrierFixture(c) as f:
            coordinator = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
            with coordinator.restore_scope() as held:
                (f.gate/'enabled').touch()
                deadlines = [channel.wire.deadline for channel in held.nodes]
                # A serial implementation cannot receive its first reply: all
                # five children must observe this round's request first.
                started = time.monotonic()
                held.check()
                elapsed = time.monotonic()-started
                self.assertLess(elapsed, 1)
                self.assertEqual([channel.wire.deadline for channel in held.nodes], deadlines)
                self.assertEqual(len(list(f.gate.glob('1-*'))), 5)
                for fixture in f.fixtures:
                    self.assertEqual(fixture.path(fixture.config).read_bytes(), fixture.original)
                    self.assertEqual(fixture.fs.read_json(t.t.n.ADMISSION)['state'], 'closed')

    def test_all_suffix_checks_precede_each_sequential_release_and_natural_reap(self):
        import fcntl
        c = load_c()
        with BarrierFixture(c) as f:
            held = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
            with held.restore_scope():
                digest = held.commit_handoff(it.settlement_proof(f, c))
                held.activate_classic()
                self.assertEqual((f.fixtures[-1].root/'classic-activated').read_text(), digest)
                check = held.check
                def checked_then_enable():
                    check()
                    (f.gate/'enabled').touch()
                held.check = checked_then_enable
                started = time.monotonic()
                held.finish_handoff()
                elapsed = time.monotonic()-started
                self.assertLess(elapsed, 1)
                self.assertTrue(held.handoff_completed)
                self.assertFalse(held.active)
                self.assertEqual([len(list(f.gate.glob(str(i)+'-*'))) for i in range(1, 6)], [5, 4, 3, 2, 1])
                self.assertEqual([child.returncode for child in f.children], [0]*5)
                self.assertTrue(all(channel.process.stdin.closed and channel.process.stdout.closed for channel in held.nodes))
                self.assertEqual(f.fs.read_json(c.INTENT)['phase'], 'handoff-completed')
            for fixture in f.fixtures:
                for path in (t.t.n.OUTER_LOCK, *(t.t.n.runner_lock(p) for p in fixture.writer.profiles)):
                    with open(fixture.path(path), 'rb') as competitor:
                        fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(fixture.fs.read_json(t.t.n.ADMISSION)['state'], 'closed')
            print('suffix-checks-seconds='+str(elapsed))


class FiveServerFaults(unittest.TestCase):
    def assert_faults_retained(self, cases):
        for fault in cases:
            with self.subTest(fault=fault):
                c = load_c()
                with BarrierFixture(c) as f:
                    held = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
                    with self.assertRaises(c.Refusal):
                        with held.restore_scope():
                            (f.gate/'enabled').touch()
                            faults = {held.nodes[-1].node: fault}
                            if fault == 'partial-eof':
                                faults = {held.nodes[0].node: 'partial', held.nodes[-1].node: 'eof'}
                            (f.gate/'fault.json').write_text(json.dumps(faults))
                            if fault == 'silent':
                                deadline = time.monotonic()+.3
                                for channel in held.nodes:
                                    channel.wire.deadline = deadline
                            started = time.monotonic()
                            with self.assertRaises(c.Refusal):
                                held.check()
                            self.assertLess(time.monotonic()-started, .8)
                            self.assertFalse(held.active)
                            with self.assertRaisesRegex(c.Refusal, 'REVOKED'):
                                held.check()
                    self.assertEqual(len(list(f.gate.glob('1-*'))), 5)
                    self.assertEqual(list(f.gate.glob('released-*')), [])
                    self.assertEqual(f.fs.read_json(c.INTENT)['phase'], 'restored-held')
                    self.assertTrue(f.fs.absent(c.COMMIT))
                    self.assertTrue(all(child.poll() is not None for child in f.children))
                    for fixture in f.fixtures:
                        self.assertEqual(fixture.fs.read_json(t.t.n.ADMISSION)['state'], 'closed')
                    with self.assertRaisesRegex(c.Refusal, 'PARTIAL'):
                        with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope():
                            self.fail('fault cannot authorize replay')

    def test_exact_request_challenge_and_nonce_proofs_are_not_relaxed(self):
        self.assert_faults_retained(('challenge', 'nodeNonce', 'coordinatorNonce', 'nodeId'))

    def test_strict_schema_and_original_restoration_proofs_are_not_relaxed(self):
        self.assert_faults_retained(('version', 'seq', 'restored', 'extra'))

    def test_accepted_pins_and_process_session_identity_are_not_relaxed(self):
        self.assert_faults_retained(('pinSha256', 'guardSha256', 'pid', 'start', 'operator', 'origin'))

    def test_partial_frame_cannot_hide_other_node_eof_or_timeout(self):
        self.assert_faults_retained(('partial-eof', 'silent'))

    def test_suffix_fault_prevents_every_release_and_preserves_committed_classification(self):
        c = load_c()
        with BarrierFixture(c) as f:
            held = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
            with self.assertRaises(c.Refusal) as failed:
                with held.restore_scope():
                    held.commit_handoff(it.settlement_proof(f, c))
                    held.activate_classic()
                    check = held.check
                    def enable_suffix_fault():
                        check()
                        (f.gate/'enabled').touch()
                        (f.gate/'fault.json').write_text(json.dumps({held.nodes[-1].node: 'operator'}))
                    held.check = enable_suffix_fault
                    held.finish_handoff()
            self.assertEqual(failed.exception.code, 'COMMITTED_ACTIVATION_UNKNOWN')
            self.assertFalse(held.active)
            self.assertFalse(held.handoff_completed)
            self.assertEqual(list(f.gate.glob('released-*')), [])
            self.assertNotEqual(f.fs.read_json(c.INTENT)['phase'], 'handoff-completed')
            self.assertFalse(f.fs.absent(c.COMMIT))
            self.assertEqual(f.fs.read_json(c.ACTIVATION)['confirmed'], [c.SHARED_NODE])


if __name__ == '__main__':
    unittest.main()
