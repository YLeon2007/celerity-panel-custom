"""Real verifier/journal over disposable proc/cgroup FILE fixtures, NOT kernel authority."""
import copy
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import test_shared_host as fixtures
m, s = fixtures.m, fixtures.s
spec = importlib.util.spec_from_file_location('candidate_freezer', fixtures.HERE.parent / 'panel-host-freezer.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)


class CandidateClosureTests(unittest.TestCase):
    def build(self, root, arm=True):
        root = pathlib.Path(root); proc = root / 'proc'; cg = root / 'cg'
        proc.mkdir(); cg.mkdir(); p = fixtures.plan(); e = p['hostHold']['expected']
        machine = root / 'machine'; machine.write_text(p['machineId'])
        boot = proc / 'sys/kernel/random/boot_id'; boot.parent.mkdir(parents=True); boot.write_text(p['bootId'])
        class FileKernel(f.LinuxKernel):
            # cgroup acknowledgements and systemd are explicitly simulated.
            def freeze(self, group, value):
                self.calls.append((group, value))
                if group == self.candidate and value:
                    row = json.loads(self.journal_path.read_bytes())
                    assert row['pending'] == {'action': 'freeze-candidate', 'group': group}
                    assert all((self.group(g) / 'cgroup.freeze').read_text() == '1' for g in e['freezeOrder'])
                path = self.group(group)
                (path / 'cgroup.freeze').write_text(str(int(value)))
                (path / 'cgroup.events').write_text('frozen ' + str(int(value)) + '\npopulated 1\n')
            def prepare_relaunch(self, expected, owner, persist):
                expected['relaunch'] = fixtures.HostRecordTests().record()['expected']['relaunch']
            def split_proxies(self, *args):
                pass
        kernel = FileKernel(proc=proc, cgroup=cg, machine=machine); kernel.calls = []
        kernel.journal_path = root / 'journal/hold.json'
        for c in e['containers']:
            self.put_pid(kernel, c['init']['pid'], 1, c['init']['pid'], c['cgroup'])
            c['init'] = kernel.pid(c['init']['pid'])
        for g in e['groups']:
            path = cg / g.lstrip('/'); path.mkdir(parents=True)
            for name, value in {'cgroup.type': 'domain', 'cgroup.freeze': '0',
                'cgroup.events': 'frozen 0\npopulated 1\n', 'cgroup.procs': '\n'.join(
                    str(c['init']['pid']) for c in e['containers'] if c['cgroup'] == g)}.items():
                (path / name).write_text(value)
        e['groups'] = {g: kernel.pin(g) for g in e['groups']}
        kernel.pins = {g: pin['inode'] for g, pin in e['groups'].items()}
        kernel.candidate = next(c['cgroup'] for c in e['containers'] if c['name'] == 'c3-test-candidate')
        journal = f.Journal(root / 'journal'); self.addCleanup(os.close, journal.fd)
        fence = f.Fence(e, kernel, journal, p['hostHold']['owner'])
        if arm: fence.arm()
        return p, kernel, fence

    def put_pid(self, kernel, pid, parent, session, group):
        path = kernel.proc / str(pid); path.mkdir(exist_ok=True)
        fields = ['S', str(parent)] + ['0'] * 20; fields[3] = str(session); fields[19] = str(pid)
        (path / 'stat').write_text(str(pid) + ' (payload) ' + ' '.join(fields))
        (path / 'comm').write_text('payload'); (path / 'cgroup').write_text('0::' + group)
        if not (path / 'exe').is_symlink(): (path / 'exe').symlink_to('/payload')

    def test_remote_effects_missing_is_explicit_partial_after_actual_local_closures(self):
        self.assertTrue(hasattr(s.make_engine('/unused', fixtures.plan(), m,
                        fixtures.fixtures.EngineTests.FixtureHost()), 'close_candidate'),
                        'shared candidate/effect drain entry missing')
        with tempfile.TemporaryDirectory() as root:
            p, kernel, fence = self.build(root)
            # Execute actual candidate transition through the transport seam; only
            # node runner/UID/SSH here are simulated. Separate tests use real runner.
            state = pathlib.Path(root) / 'node-state'; state.mkdir()
            host = fixtures.fixtures.EngineTests.FixtureHost()
            engine = s.make_engine(state, p, m, host)
            fixtures.fixtures.fixture_hold(engine)
            lock = os.open(state / 'lock', os.O_RDWR | os.O_CREAT, 0o600)
            self.addCleanup(os.close, lock)
            def close_hold(*args, **kwargs):
                self.assertEqual(kwargs, {'command': 'close-candidate'})
                fence.close_candidate(fence.owner)
                return fence.expected
            from contextlib import contextmanager
            @contextmanager
            def local_runner(plan):
                self.assertTrue((state / 'restore-admission.json').exists())
                yield {'head': 'fixture-closed', 'journalSha256': 'a' * 64}
            host.held_current_runner_head = local_runner
            with patch.object(s, 'check_hold', side_effect=close_hold), \
                 patch.object(m.os, 'geteuid', return_value=0), \
                 patch.object(m, 'secure_file', side_effect=lambda path: pathlib.Path(path).read_bytes()):
                output = engine.close_candidate(lock)
                self.assertEqual(output['status'], 'partial-unknown-retained')
                self.assertEqual(output['localNodeEffects'], 'drained')
                self.assertEqual(output['candidate'], 'closed')
                self.assertEqual(output['unknownNodes'], sorted(m.TEST_NODES))
                self.assertIs(output['handbackAllowed'], False)
            with self.assertRaises(m.Refusal): engine.restore()
            self.assertTrue(all(value for group, value in kernel.calls))

    def test_partial_transition_and_journal_failure_never_thaw(self):
        for fault in ('before-intent', 'after-freeze', 'after-kernel-readback'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                p, kernel, fence = self.build(root)
                real_save, real_freeze = fence.journal.save, kernel.freeze
                def save(row):
                    if fault == 'before-intent' and row.get('pending', {}).get('action') == 'freeze-candidate':
                        raise OSError('fixture fsync failure')
                    if fault == 'after-kernel-readback' and 'candidateClosure' in row.get('expected', {}):
                        raise OSError('fixture fsync failure')
                    real_save(row)
                def freeze(group, value):
                    real_freeze(group, value)
                    if fault == 'after-freeze' and group == kernel.candidate:
                        raise TimeoutError('fixture timeout after kernel write')
                with patch.object(fence.journal, 'save', side_effect=save), patch.object(kernel, 'freeze', side_effect=freeze):
                    with self.assertRaises((OSError, TimeoutError)):
                        fence.close_candidate(fence.owner)
                self.assertEqual(fence.phase, 'unknown')
                with self.assertRaises(RuntimeError): fence.restore(fence.owner)
                for group in fence.original['freezeOrder']:
                    self.assertEqual((kernel.group(group) / 'cgroup.freeze').read_text(), '1')
                self.assertTrue(all(value for group, value in kernel.calls))

    def test_orphaned_exec_session_is_never_accepted_as_candidate_descendant(self):
        with tempfile.TemporaryDirectory() as root:
            p, kernel, fence = self.build(root)
            init = next(c['init'] for c in fence.expected['containers'] if c['name'] == 'c3-test-candidate')
            self.put_pid(kernel, 2000, init['pid'], 2000, kernel.candidate)
            (kernel.group(kernel.candidate) / 'cgroup.procs').write_text(str(init['pid']) + '\n2000\n')
            with self.assertRaisesRegex(RuntimeError, 'unproven survivor session'):
                fence.close_candidate(fence.owner)
            self.assertNotIn((kernel.candidate, True), kernel.calls)
            self.assertEqual(fence.phase, 'unknown')

    def test_exact_candidate_descendants_close_without_freezing_survivors_or_thaw(self):
        self.assertTrue(hasattr(f.Fence, 'close_candidate'), 'finite candidate closure missing')
        with tempfile.TemporaryDirectory() as root:
            p, kernel, fence = self.build(root)
            init = next(c['init'] for c in fence.expected['containers'] if c['name'] == 'c3-test-candidate')
            self.put_pid(kernel, 2000, init['pid'], init['pid'], kernel.candidate)
            (kernel.group(kernel.candidate) / 'cgroup.procs').write_text(str(init['pid']) + '\n2000\n')
            fence.close_candidate(fence.owner)
            self.assertEqual(fence.frozen, [*fence.original['freezeOrder'], kernel.candidate])
            self.assertEqual(len(fence.expected['groups'][kernel.candidate]['members']), 2)
            row = json.loads((pathlib.Path(root) / 'journal/hold.json').read_bytes())
            s.verify_record(row, p, kernel, m)
            self.assertEqual(fence.check()['candidate'], 'closed')
            for c in fence.expected['containers']:
                if c['name'] in ('hysteria-mongo', 'hysteria-redis', 'hysteria-caddy'):
                    self.assertEqual((kernel.group(c['cgroup']) / 'cgroup.freeze').read_text(), '0')
            with self.assertRaises(RuntimeError): fence.restore(fence.owner)
            self.assertTrue(all(value for group, value in kernel.calls))
            (kernel.group(kernel.candidate) / 'cgroup.freeze').write_text('0')
            with self.assertRaises(m.Refusal): s.verify_record(row, p, kernel, m)


class HostFrameTests(unittest.TestCase):
    build = CandidateClosureTests.build
    put_pid = CandidateClosureTests.put_pid
    def test_actual_root_peer_frame_transition_and_eof_keep_all_fences(self):
        import multiprocessing
        import time
        real_peer = s.peer_identity
        def fixture_uid(conn):
            pid, uid, gid = real_peer(conn)
            return pid, 0, gid  # UID is simulated; socket peer PID/start/nonce are real.
        class Host:
            def operator_session(self):
                return {k: m.proc_identity(os.getppid())[k] for k in ('pid', 'start')}
            def guard_check(self, *args): pass  # SSH is explicitly simulated.
        with tempfile.TemporaryDirectory(prefix='c3hc-') as root:
            p, kernel, unused = self.build(root, arm=False)
            kernel.journal_path = pathlib.Path(root) / 'host/hold.json'
            m.atomic_json(root, 'guard.json', {'fixture': True})
            readfd, writefd = os.pipe()
            def child():
                os.close(writefd)
                with patch.object(f, 'capture', return_value=p['hostHold']['expected']), \
                     patch.object(s, 'peer_identity', side_effect=fixture_uid), \
                     patch.object(m, 'secure_file', side_effect=lambda path: pathlib.Path(path).read_bytes()):
                    try: s.serve_hold(p, root, m, f, kernel, Host(), readfd)
                    except m.Refusal as error:
                        if str(error) != 'HOST_CONTROLLER_CHANNEL_LOST': raise
            proc = multiprocessing.get_context('fork').Process(target=child)
            proc.start(); os.close(readfd)
            try:
                deadline = time.monotonic() + 5
                while not pathlib.Path(root, 'host-guard.json').exists() and proc.is_alive() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(pathlib.Path(root, 'host-guard.json').exists())
                with patch.object(s, 'peer_identity', side_effect=fixture_uid), \
                     patch.object(s, 'load_freezer', return_value=(f, kernel)), \
                     patch.object(m, 'secure_file', side_effect=lambda path: pathlib.Path(path).read_bytes()):
                    before = s.check_hold(p, root, m)
                    self.assertNotIn('candidateClosure', before)
                    closed = s.check_hold(p, root, m, command='close-candidate')
                    self.assertEqual(closed['candidateClosure'], {'group': kernel.candidate})
                    self.assertEqual(s.check_hold(p, root, m), closed)
                    with self.assertRaisesRegex(m.Refusal, 'INVALID_HOST_OPERATION'):
                        s.check_hold(p, root, m, command='restore')
                    os.close(writefd); writefd = None
                    proc.join(5); self.assertFalse(proc.is_alive()); self.assertEqual(proc.exitcode, 0)
                    row = json.loads(kernel.journal_path.read_bytes())
                    self.assertEqual(row['phase'], 'unknown')
                    for group in [*p['hostHold']['expected']['freezeOrder'], kernel.candidate]:
                        self.assertEqual((kernel.group(group) / 'cgroup.freeze').read_text(), '1')
                    with self.assertRaises((m.Refusal, OSError)): s.check_hold(p, root, m)
            finally:
                if writefd is not None: os.close(writefd)
                if proc.is_alive(): proc.terminate(); proc.join(5)


if __name__ == '__main__':
    unittest.main()
