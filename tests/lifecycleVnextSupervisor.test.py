#!/usr/bin/env python3
"""Real process tests. No PID1/cgroup/ns/handback authority is modelled as real."""
import hashlib
import array
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / 'scripts/test-node-isolation/lifecycle_vnext_supervisor.py'
BOOTSTRAP = ROOT / 'scripts/test-node-isolation/lifecycle_vnext_bootstrap.cjs'
BOOT = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
NODE = os.environ.get('C3_NODE', '/home/leon/.local/bin/node')


def wait_for(fn, seconds=5):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = fn()
        if value:
            return value
        time.sleep(.02)
    raise AssertionError('finite observation timeout')


def events(file):
    if not file.exists():
        return []
    return [json.loads(line) for line in file.read_text().splitlines()]


def owner_main(config):
    """Disposable real owner; the test process remains an independent observer."""
    c = json.loads(Path(config).read_text())
    owner = os.pidfd_open(os.getpid())
    inherited = [owner, c['controlFd'], c['observerFd'], *c['peerFds']]
    args = [sys.executable, '-I', '-B', str(ENTRY), '--local-fixture',
            '--role', c['role'], '--owner-fd', str(owner),
            '--control-fd', str(c['controlFd']), '--invocation', c['invocation'],
            '--fixture-observer-fd', str(c['observerFd']),
            '--token', c['token'], '--deadline-ns', str(c['deadline']),
            '--boot-id', BOOT, '--grace-ms', str(c['graceMs']),
            '--artifact', c['artifact'], '--index-sha256', c['indexHash'],
            '--bootstrap', str(BOOTSTRAP), '--node', NODE,
            '--settings', c['settings'], '--events', c['events']]
    for fd in c['peerFds']:
        args += ['--peer-fd', str(fd)]
    code = 1
    for phase in c.get('schedule', [{}]):
        phase_args = list(args)
        for key, value in phase.items():
            phase_args[phase_args.index('--' + key) + 1] = str(value)
        with open(c['log'], 'ab', buffering=0) as log:
            supervisor = subprocess.Popen(phase_args, pass_fds=inherited, stdout=log, stderr=log)
        code = supervisor.wait()
        if code != 0:
            break
    os.close(owner)
    os.close(c['controlFd'])
    os.close(c['observerFd'])
    for fd in c['peerFds']:
        os.close(fd)
    Path(c['ownerExit']).write_text(json.dumps({'supervisorExit': code}))
    return code


def receive_original_fds(channel, expected):
    """Own every received FD immediately; transfer ownership only after ALL checks.

    No journal PID/startticks lookup. DEAD pidfds are valid retained originals.
    MSG_CTRUNC can deliver a partial rights list: close that list on refusal;
    Linux closes undisclosed excess rights. Never close sender/unrelated FDs.
    """
    owned = []
    try:
        data, ancillary, flags, _ = channel.recvmsg(4096, socket.CMSG_SPACE(8 * array.array('i').itemsize),
                                                   socket.MSG_CMSG_CLOEXEC)
        invalid = False
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds = array.array('i')
                size = len(raw) - len(raw) % fds.itemsize
                fds.frombytes(raw[:size])
                owned.extend(fds)
                invalid |= size != len(raw)
            else:
                invalid = True
        if invalid or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or not data or len(owned) != 2:
            raise ValueError('FIXTURE_RIGHTS_PACKET_REFUSED')
        if json.loads(data) != expected:
            raise ValueError('FIXTURE_INVOCATION_BINDING_REFUSED')
        for fd in owned:
            if os.readlink('/proc/self/fd/' + str(fd)) != 'anon_inode:[pidfd]':
                raise ValueError('FIXTURE_PIDFD_REQUIRED')
        result = tuple(owned)
        owned.clear()
        return result
    finally:
        for fd in owned:
            os.close(fd)


class Invocation:
    def __init__(self, test, role='F', lifetime: float=4, artifact=None, settings=None,
                 peer=None, grace_ms=250, evidence=None, sequential=False):
        self.test = test
        self.dir = Path(tempfile.mkdtemp(prefix='lifecycle-', dir=os.environ['TMPDIR']))
        self.app_fd = self.supervisor_fd = self.owner_fd = None
        self.owner = self.control = self.observer = None
        self.pending_peer_fds = []
        self._closed = False
        self.evidence = self.dir
        test.addCleanup(self.cleanup)
        base = os.environ.get('C3_REAL_EVIDENCE')
        self.evidence = Path(evidence) if evidence else Path(base) / self.dir.name if base else self.dir
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.file = self.evidence / 'events.jsonl'
        self.deadline = time.monotonic_ns() + int(lifetime * 1e9)
        self.control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        test.addCleanup(child_control.close)
        self.observer, child_observer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        test.addCleanup(child_observer.close)
        self.invocation = os.urandom(16).hex()
        self.token = os.urandom(32).hex()
        if artifact is None:
            artifact = self.dir / 'artifact'
            artifact.mkdir()
            (artifact / 'index.js').write_text("process.on('SIGTERM',()=>process.exit(0)); setInterval(()=>{},50);\n")
        artifact = Path(artifact)
        peer_fds = [os.pidfd_open(peer.pid)] if peer else []
        self.pending_peer_fds = peer_fds
        c = dict(role=role, controlFd=child_control.fileno(), observerFd=child_observer.fileno(), peerFds=peer_fds,
                 invocation=self.invocation, token=self.token, deadline=self.deadline,
                 graceMs=grace_ms, artifact=str(artifact), settings=str(settings or self.dir / 'unused.json'),
                 indexHash=hashlib.sha256((artifact / 'index.js').read_bytes()).hexdigest(),
                 events=str(self.file), log=str(self.evidence / 'application.log'),
                 ownerExit=str(self.evidence / 'owner-exit.json'))
        self.binding = dict(schema='c3-local-fixture-original-pidfds/1', invocation=self.invocation,
                            role=role, bootId=BOOT, deadlineNs=self.deadline, indexSha256=c['indexHash'])
        self.next_phase = dict(role='R', invocation=os.urandom(16).hex(), token=os.urandom(32).hex(),
                               events=str(self.evidence / 'rollback-events.jsonl'))
        if sequential:
            c['schedule'] = [{}, self.next_phase]
        self.config = self.dir / 'config.json'
        self.config.write_text(json.dumps(c))
        try:
            self.owner = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                                          '--owner', str(self.config)],
                                         pass_fds=(child_control.fileno(), child_observer.fileno(), *peer_fds))
            # Own unreaped Popen child, NOT journal authority. Owner self-open in
            # owner_main remains once for the entire original F/R deadline.
            self.owner_fd = os.pidfd_open(self.owner.pid)
        finally:
            child_control.close()
            child_observer.close()
            for fd in peer_fds:
                os.close(fd)
            self.pending_peer_fds = []

    def started(self):
        event = wait_for(lambda: next((e for e in events(self.file) if e['event'] == 'STARTED'), None))
        if self.app_fd is not None or self.supervisor_fd is not None:
            raise ValueError('FIXTURE_HANDOFF_ALREADY_OWNED')
        expected = dict(self.binding, invocation=self.invocation)
        if not select.select([self.observer], [], [], 5)[0]:
            raise ValueError('FIXTURE_HANDOFF_TIMEOUT')
        self.app_fd, self.supervisor_fd = receive_original_fds(self.observer, expected)
        with (self.evidence / 'original-fd-handoffs.jsonl').open('a') as stream:
            stream.write(json.dumps(dict(metadata=expected, source='SCM_RIGHTS original retained descriptors',
                                        appDead=bool(select.select([self.app_fd], [], [], 0)[0]),
                                        supervisorDead=bool(select.select([self.supervisor_fd], [], [], 0)[0]))) + '\n')
        return event

    def send(self, invocation=None, token=None, action='STOP'):
        self.control.send(json.dumps(dict(invocation=invocation or self.invocation,
                                         token=token or self.token, action=action)).encode())

    def finished(self, timeout=5):
        if self.app_fd is not None:
            assert select.select([self.app_fd], [], [], timeout)[0], 'exact app still alive'
        self.owner.wait(timeout=timeout)
        return wait_for(lambda: next((e for e in events(self.file) if e['event'] == 'EXIT'), None), timeout)

    def cleanup(self):
        if self._closed:
            return
        self._closed = True
        errors = []
        def attempt(fn):
            try:
                return fn()
            except Exception as exc:
                errors.append(exc)
        # Refused/partial handoff has NO signal authority. Control EOF lets the
        # retained owner wait/reap supervisor and app before removing their tree.
        for fd in self.pending_peer_fds:
            attempt(lambda: os.close(fd))
        self.pending_peer_fds = []
        for channel in [self.control, self.observer]:
            if channel is not None:
                attempt(channel.close)
        fds = [fd for fd in [self.app_fd, self.supervisor_fd, self.owner_fd] if fd is not None]
        for fd in fds:
            try:
                signal.pidfd_send_signal(fd, signal.SIGCONT)
            except ProcessLookupError:
                pass
            except Exception as exc:
                errors.append(exc)
        if self.owner is not None:
            try:
                self.owner.wait(timeout=5)
            except subprocess.TimeoutExpired as exc:
                errors.append(exc)
                # Emergency cleanup of proven retained originals only. Popen's
                # own unreaped child remains safe if its pidfd open had failed.
                for fd in fds:
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except Exception as error:
                        errors.append(error)
                attempt(self.owner.kill)
                attempt(lambda: self.owner.wait(timeout=5))
        all_dead = self.owner is None or self.owner.returncode is not None
        for fd in fds:
            if not select.select([fd], [], [], 5)[0]:
                all_dead = False
                errors.append(AssertionError('owned invocation did not exit'))
            attempt(lambda: os.close(fd))
        self.app_fd = self.supervisor_fd = self.owner_fd = None
        if all_dead:
            attempt(lambda: shutil.rmtree(self.dir))
        if self.evidence != self.dir:
            attempt(lambda: (self.evidence / 'fixture-cleanup.json').write_text(json.dumps(
                dict(path=str(self.dir), removed=not self.dir.exists(), allOwnedDead=all_dead,
                     ownerExit=self.owner.returncode if self.owner else None, errors=[str(e) for e in errors]))))
        if errors:
            raise ExceptionGroup('fixture cleanup failures (primary test failure retained by unittest)', errors)


class LifetimeTests(unittest.TestCase):
    def test_original_fd_packet_validation_and_exact_disposal(self):
        binding = dict(schema='c3-local-fixture-original-pidfds/1', invocation='a'*32,
                       role='F', bootId=BOOT, deadlineNs=123, indexSha256='b'*64)
        cases = ['valid', 'json', 'invocation', 'bootId', 'deadlineNs', 'role', 'indexSha256',
                 'one-fd', 'extra-fds', 'not-pidfd', 'payload-trunc', 'rights-trunc', 'eof']
        original = os.pidfd_open(os.getpid())
        other = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        try:
            for case in cases:
                with self.subTest(packet=case):
                    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    try:
                        metadata = dict(binding)
                        if case in metadata:
                            metadata[case] = 'wrong'
                        packet = b'not json' if case == 'json' else json.dumps(metadata).encode()
                        if case == 'payload-trunc':
                            packet += b' ' * 5000
                        fds = [original, original]
                        if case == 'one-fd':
                            fds = [original]
                        elif case == 'extra-fds':
                            fds = [original] * 3
                        elif case == 'rights-trunc':
                            fds = [original] * 24
                        elif case == 'not-pidfd':
                            fds = [original, other]  # first valid, second fails: partial validation
                        if case == 'eof':
                            sender.close()
                        else:
                            sender.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))])
                        before = set(os.listdir('/proc/self/fd'))
                        with mock.patch.object(os, 'close', wraps=os.close) as close:
                            if case == 'valid':
                                got = receive_original_fds(receiver, binding)
                                self.assertEqual(close.call_count, 0)
                                for fd in got:
                                    self.assertFalse(os.get_inheritable(fd))
                                    os.close(fd)
                            else:
                                with self.assertRaises(ValueError):
                                    receive_original_fds(receiver, binding)
                                closed = [c.args[0] for c in close.call_args_list]
                                self.assertEqual(len(closed), len(set(closed)), 'received FD closed twice')
                                self.assertTrue(set(closed).isdisjoint({original, other, receiver.fileno(), sender.fileno()}))
                                expected_count = 0 if case == 'eof' else 8 if case == 'rights-trunc' else len(fds)
                                self.assertEqual(len(closed), expected_count)
                        self.assertEqual(set(os.listdir('/proc/self/fd')), before, 'received FD leak')
                        os.fstat(original)
                        os.fstat(other)
                    finally:
                        receiver.close()
                        sender.close()
        finally:
            os.close(original)
            os.close(other)

    def test_refused_handoff_keeps_safe_cleanup_without_signal_authority(self):
        run = Invocation(self)
        run.binding['bootId'] = 'wrong'
        before = set(os.listdir('/proc/self/fd'))
        with self.assertRaisesRegex(ValueError, 'BINDING_REFUSED'):
            run.started()
        self.assertIsNone(run.app_fd)
        self.assertIsNone(run.supervisor_fd)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)
        run.cleanup()
        self.assertFalse(run.dir.exists())
        self.assertEqual(run.owner.returncode, 0)

    def test_control_eof_stops_exact_child(self):
        run = Invocation(self)
        run.started()
        run.control.close()
        event = run.finished()
        self.assertEqual(event['reason'], 'CONTROL_LOST')
        self.assertEqual(event['appExit'], 0)

    def test_delayed_observer_after_reap_never_reopens_journal_pid(self):
        run = Invocation(self, lifetime=1, grace_ms=250)
        self.assertEqual(run.owner.wait(timeout=4), 0)
        self.assertTrue(any(e['event'] == 'EXIT' for e in events(run.file)))
        with mock.patch.object(os, 'pidfd_open', side_effect=AssertionError('historical journal PID reopened')):
            event = run.started()
        self.assertEqual(event['deadlineNs'], run.deadline)
        for fd in [run.app_fd, run.supervisor_fd]:
            self.assertTrue(select.select([fd], [], [], 0)[0], 'original DEAD descriptor required')
            with self.assertRaises(ProcessLookupError):
                signal.pidfd_send_signal(fd, 0)

    def test_owner_sigkill_F_and_R(self):
        for role in ['F', 'R']:
            with self.subTest(role=role):
                run = Invocation(self, role=role)
                run.started()
                signal.pidfd_send_signal(run.owner_fd, signal.SIGKILL)
                e = run.finished()
                self.assertEqual(e['reason'], 'OWNER_DEAD')
                self.assertEqual(e['supervisorExit'], 0)
                self.assertLess(e['finishedNs'], run.deadline)

    def test_stopped_owner_original_deadline_includes_grace_F_and_R(self):
        for role in ['F', 'R']:
            with self.subTest(role=role):
                run = Invocation(self, role=role, lifetime=1.5, grace_ms=300)
                run.started()
                signal.pidfd_send_signal(run.owner_fd, signal.SIGSTOP)
                self.assertTrue(select.select([run.app_fd], [], [], 3)[0])
                e = wait_for(lambda: next((e for e in events(run.file) if e['event'] == 'EXIT'), None))
                self.assertEqual(e['reason'], 'DEADLINE')
                self.assertLessEqual(e['stopNs'], run.deadline - 300_000_000 + 80_000_000)
                self.assertLess(e['finishedNs'], run.deadline)
                signal.pidfd_send_signal(run.owner_fd, signal.SIGCONT)
                run.owner.wait(timeout=3)

    def test_exact_stop_wrong_invocation_and_token(self):
        run = Invocation(self)
        run.started()
        foreign = subprocess.Popen([NODE, '-e', 'setInterval(()=>{},100)'])
        foreign_fd = os.pidfd_open(foreign.pid)
        try:
            run.send(invocation='foreign')
            run.send(token='wrong')
            wait_for(lambda: len([e for e in events(run.file) if e['event'] == 'CONTROL_REFUSED']) == 2)
            self.assertFalse(select.select([run.app_fd], [], [], 0)[0])
            run.send()
            e = run.finished()
            self.assertEqual(e['reason'], 'EXACT_STOP')
            self.assertEqual(e['appExit'], 0)
            self.assertEqual(e['supervisorExit'], 0)
            self.assertFalse(e['forced'])
            self.assertFalse(select.select([foreign_fd], [], [], 0)[0])
        finally:
            signal.pidfd_send_signal(foreign_fd, signal.SIGTERM)
            foreign.wait(timeout=3)
            os.close(foreign_fd)

    def test_peer_death_stops_app_without_repin(self):
        peer = subprocess.Popen([NODE, '-e', 'setInterval(()=>{},100)'])
        try:
            run = Invocation(self, peer=peer)
            run.started()
            peer.terminate()
            peer.wait(timeout=3)
            e = run.finished()
            self.assertEqual(e['reason'], 'PEER_DEAD')
        finally:
            if peer.poll() is None:
                peer.kill()
                peer.wait()

    def test_app_death_is_failure_not_restart(self):
        run = Invocation(self)
        run.started()
        signal.pidfd_send_signal(run.app_fd, signal.SIGKILL)
        e = run.finished()
        self.assertEqual(e['reason'], 'APP_DEAD')
        self.assertEqual(e['supervisorExit'], 1)
        self.assertEqual(len([x for x in events(run.file) if x['event'] == 'STARTED']), 1)

    def test_supervisor_death_kernel_parent_death_fence(self):
        run = Invocation(self)
        run.started()
        signal.pidfd_send_signal(run.supervisor_fd, signal.SIGKILL)
        self.assertTrue(select.select([run.app_fd], [], [], 3)[0])
        run.owner.wait(timeout=3)
        self.assertFalse(any(e['event'] == 'EXIT' for e in events(run.file)), 'not a natural exit claim')

    def test_no_precommit_D_even_with_boolean_commit_file(self):
        run = Invocation(self, role='D')
        (run.dir / 'commit.json').write_text('{"durable":true,"allFive":true}')
        self.assertNotEqual(run.owner.wait(timeout=3), 0)
        self.assertFalse(any(e['event'] == 'STARTED' for e in events(run.file)))

    def test_late_start_cannot_renew_deadline(self):
        run = Invocation(self, lifetime=.05, grace_ms=300)
        self.assertNotEqual(run.owner.wait(timeout=3), 0)
        self.assertFalse(any(e['event'] == 'STARTED' for e in events(run.file)))

    def test_hung_app_forced_exit_is_not_natural(self):
        run = Invocation(self, lifetime=1.5)
        run.started()
        signal.pidfd_send_signal(run.app_fd, signal.SIGSTOP)
        e = run.finished(timeout=4)
        self.assertEqual(e['reason'], 'DEADLINE')
        self.assertTrue(e['forced'])
        self.assertEqual(e['appExit'], -signal.SIGKILL)
        self.assertLessEqual(e['killNs'], run.deadline)
        self.assertEqual(e['supervisorExit'], 1)


class EvidenceResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.successes = []
        self.subtests = []
        self.started_names = []
        self.completed_names = []

    def startTest(self, test):
        self.started_names.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.completed_names.append(test.id())
        super().stopTest(test)

    def addSuccess(self, test):
        self.successes.append(test.id())
        super().addSuccess(test)

    def addSubTest(self, test, subtest, err):
        self.subtests.append(dict(name=subtest.id(), passed=err is None))
        super().addSubTest(test, subtest, err)

    def stopTestRun(self):
        super().stopTestRun()
        if os.environ.get('C3_REAL_EVIDENCE'):
            directory = Path(os.environ['C3_REAL_EVIDENCE'])
            directory.mkdir(parents=True, exist_ok=True)
            with (directory / 'unittest-results.json').open('x') as stream:
                json.dump(dict(started=len(self.started_names), completed=len(self.completed_names),
                               startedNames=self.started_names, completedNames=self.completed_names,
                               passed=self.wasSuccessful(), successes=self.successes,
                               subtests=self.subtests, failures=len(self.failures), errors=len(self.errors),
                               skipped=len(self.skipped)), stream, indent=2)


def test_main():
    unittest.main(testRunner=unittest.TextTestRunner(verbosity=2, resultclass=EvidenceResult))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--owner':
        sys.exit(owner_main(sys.argv[2]))
    test_main()
