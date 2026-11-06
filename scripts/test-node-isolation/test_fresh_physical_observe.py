"""Local real-process evidence; root/systemd/namespace facts explicitly modeled."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SCRATCH = '/home/leon/.hermes/cache/scratch'


def load(name='fresh_physical'):
    spec = importlib.util.spec_from_file_location(name, HERE/(name+'.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class RunPlanTests(unittest.TestCase):
    def test_closed_independent_plan_retains_original_deadline_and_identity(self):
        m = load()
        self.assertTrue(hasattr(m, 'RunPlan'), 'missing independent original run-plan contract')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp:
            path = Path(tmp)/'plan'
            deadline = time.monotonic_ns()+2_000_000_000
            raw = m.encode(dict(version=1, context=m.CONTEXT, bootId=m.boot_id(),
                                deadlineMonotonicNs=deadline))
            path.write_bytes(raw); path.chmod(0o444)
            # Only ownership/trusted parent traversal is modeled, not snapshot IO.
            with patch.object(m, 'RUN_PLAN', str(path)), patch.object(m, 'trusted_open',
                    side_effect=lambda path: os.open(path, m.FILE)):
                plan = m.RunPlan()
                self.assertEqual(plan.deadline_ns, deadline)
                self.assertEqual(plan.digest, m.sha(raw))
                plan.check()
                replacement = path.with_suffix('.next')
                replacement.write_bytes(raw); replacement.chmod(0o444); replacement.replace(path)
                with self.assertRaisesRegex(m.Refusal, 'RUN_PLAN_DRIFT'): plan.check()


    def test_plan_rejects_missing_extra_wrong_clock_boot_type_and_ceiling(self):
        m = load()
        with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp:
            path = Path(tmp)/'plan'
            valid = dict(version=1, context=m.CONTEXT, bootId=m.boot_id(),
                         deadlineMonotonicNs=time.monotonic_ns()+1_000_000_000)
            cases = [('extra', dict(valid, extra=True)), ('missing', {k:v for k,v in valid.items() if k != 'bootId'}),
                     ('boot', dict(valid, bootId='foreign')), ('bool', dict(valid, deadlineMonotonicNs=True)),
                     ('float', dict(valid, deadlineMonotonicNs=float(valid['deadlineMonotonicNs']))),
                     ('version-bool', dict(valid, version=True)), ('expired', dict(valid, deadlineMonotonicNs=1)),
                     ('ceiling', dict(valid, deadlineMonotonicNs=time.monotonic_ns()+601_000_000_000))]
            with patch.object(m, 'RUN_PLAN', str(path)), patch.object(m, 'trusted_open',
                    side_effect=lambda path: os.open(path, m.FILE)):
                with self.assertRaises(FileNotFoundError): m.RunPlan()
                for name, plan in cases:
                    with self.subTest(name=name):
                        if path.exists(): path.chmod(0o600)
                        path.write_bytes(m.encode(plan)); path.chmod(0o444)
                        with self.assertRaisesRegex(m.Refusal, 'FIXED_ORIGINAL_RUN_PLAN_REQUIRED'): m.RunPlan()
                path.chmod(0o600); path.write_bytes(m.encode(valid)); path.chmod(0o644)
                with self.assertRaisesRegex(m.Refusal, 'IMMUTABLE_INPUT_REQUIRED'): m.RunPlan()
                path.unlink(); target = Path(tmp)/'target'; target.write_bytes(m.encode(valid)); path.symlink_to(target)
                with self.assertRaises(OSError): m.RunPlan()

    def test_watch_main_does_not_create_resources_or_wait_without_independent_plan(self):
        m = load()
        with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp, patch.object(m, 'RUN_PLAN', tmp+'/missing'), \
                patch.object(m, 'trusted_open', side_effect=lambda path: os.open(path, m.FILE)), \
                patch.object(m.OwnedTree, 'create') as create, patch.object(m, 'verify_input') as inputs:
            with self.assertRaises(FileNotFoundError): m.watch_main()
            create.assert_not_called(); inputs.assert_not_called()

    def test_exec_caller_cannot_dispatch_construction_after_prepare_ceiling(self):
        import array
        import socket
        import struct
        import threading
        from contextlib import ExitStack
        m = load()
        with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp, ExitStack() as stack:
            root = Path(tmp); files = {'/fixture': 'a'*64}
            (root/'plan').write_bytes(m.encode(dict(version=1, context=m.CONTEXT, bootId=m.boot_id(),
                deadlineMonotonicNs=time.monotonic_ns()+2_000_000_000))); (root/'plan').chmod(0o444)
            (root/'input').mkdir(); (root/'input/resource-plan.json').write_bytes(m.encode(dict(files=files)))
            for k,v in dict(RUN_PLAN=str(root/'plan'), INPUT=str(root/'input'), CONTROL=str(root/'control'),
                            REGISTER=str(root/'register'), PREPARE_SECONDS=.05).items():
                stack.enter_context(patch.object(m, k, v))
            stack.enter_context(patch.object(m, 'trusted_open', side_effect=lambda path: os.open(path, m.FILE)))
            stack.enter_context(patch.object(m, 'trusted_read', side_effect=lambda path,*a: Path(path).read_bytes()))
            read_text = Path.read_text
            stack.enter_context(patch.object(Path, 'read_text', lambda path,*a,**kw:
                m.CGROUP if str(path) == '/proc/self/cgroup' else read_text(path,*a,**kw)))
            # Only SO_PEERCRED UID/GID are modeled, not registration/rights/pidfd.
            unpack = struct.unpack
            stack.enter_context(patch.object(struct, 'unpack', side_effect=lambda fmt, data:
                (unpack(fmt,data)[0],0,0) if fmt == '3i' else unpack(fmt,data)))
            stack.enter_context(patch.object(m, 'verify_input', side_effect=lambda:
                (time.sleep(.1), dict(files=files))[1]))
            construct = stack.enter_context(patch.object(m, 'construct'))
            listener, _ = m.bind_owned(m.REGISTER, socket.SOCK_SEQPACKET); stack.callback(listener.close)
            control, _ = m.bind_owned(m.CONTROL); stack.callback(control.close); listener.listen(1)
            server_errors = []
            def serve():
                try:
                    channel,_ = listener.accept()
                    with channel:
                        self.assertEqual(channel.recv(4096), b'PREPARE\n')
                        raw = m.encode(dict(generation='a'*64, filesSha256=m.sha(m.encode(files))))
                        channel.sendmsg([raw], [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[control.fileno()]))])
                except BaseException as error: server_errors.append(error)
            thread=threading.Thread(target=serve); thread.start()
            try:
                with self.assertRaisesRegex(m.Refusal, 'PREPARATION_DEADLINE'): m.exec_main()
                construct.assert_not_called()
            finally:
                thread.join(timeout=2)
            self.assertEqual(server_errors, [])

    def test_original_ceiling_rechecked_after_delayed_finally_cleanup(self):
        with WatchFixture() as f:
            f.accept()
            raw = (f.root/'plan').read_bytes()
            (f.root/'plan').chmod(0o600)
            (f.root/'plan').write_bytes(raw)  # same bytes, changed immutable inode metadata
            (f.root/'finish').touch()
            f.watch.wait(timeout=3)
            self.assertNotEqual(f.watch.returncode, 0, 'watch_main returned naturally after final input drift')
            self.assertEqual(f.lease.check(stopped=True)['state'], 'T')


def wait_for(predicate, seconds=3):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        if predicate(): return
        time.sleep(.005)
    raise AssertionError('fixture rendezvous timeout')


def watcher_fixture(root):
    """Real watch_main/finally, sockets/rights/files/processes. UID/ns/systemd modeled."""
    import fcntl
    import signal
    import struct
    m = load()
    root = Path(root)
    files = {'/fixture': 'a'*64}
    m.RESOURCE = str(root/'resources'); m.CONTROL = str(root/'control')
    m.REGISTER = str(root/'register'); m.ACCEPTANCE = str(root/'acceptance')
    m.RUN_PLAN = str(root/'plan')
    m.trusted_open = lambda path, directory=False: os.open(path, m.DIR if directory else m.FILE)
    m.trusted_read = lambda path, *args: Path(path).read_bytes()
    m.verify_input = lambda: {'files': files}
    m.join_private_network = lambda plan: None
    m.constructor_peer = lambda channel: struct.unpack('3i', channel.getsockopt(1, 17, 12))[0]
    original_text = Path.read_text
    def text(path, *args, **kw):
        if str(path) == '/proc/self/cgroup': return m.WATCH_GROUP
        return original_text(path, *args, **kw)
    Path.read_text = text
    m.watcher_properties = lambda deadline: dict(MainPID=str(os.getpid()), ExecMainPID=str(os.getpid()),
        InvocationID='b'*32, ActiveState='active', SubState='running')
    def phase(lease, inode):
        lease.check(stopped=True)
        if (Path('/proc')/str(lease.pid)/'fd/3').stat().st_ino != inode: raise m.Refusal('FD_DRIFT')
        with (root/'lock').open('r+b') as stream:
            try: fcntl.flock(stream, fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: pass
            else: raise m.Refusal('LOCK_NOT_HELD')
    m.check_prepared_resources = phase
    real_unlink = m.unlink_owned_socket
    def unlink(path, identity):
        if path == m.REGISTER:
            (root/'finally-entered').touch()
            while not (root/'finish').exists(): time.sleep(.005)
            if (root/'cleanup-fail').exists(): raise OSError('modeled unlink failure')
        real_unlink(path, identity)
    m.unlink_owned_socket = unlink
    def abandoned(*_): raise m.Refusal('EXTERNAL_PREPARATION_ABANDONED')
    signal.signal(signal.SIGTERM, abandoned)
    signal.signal(signal.SIGINT, abandoned)
    m.watch_main()


def supervisor_fixture(root):
    import fcntl
    import signal
    import struct
    m = load(); root = Path(root)
    m.CONTROL = str(root/'control'); m.REGISTER = str(root/'register')
    m.RUN_PLAN = str(root/'plan'); m.INPUT = str(root/'input')
    m.trusted_open = lambda path, directory=False: os.open(path, m.DIR if directory else m.FILE)
    m.trusted_read = lambda path,*a: Path(path).read_bytes()
    m.verify_input = lambda: m.decode((root/'input/resource-plan.json').read_bytes())
    original_text = Path.read_text
    Path.read_text = lambda path,*a,**kw: m.CGROUP if str(path) == '/proc/self/cgroup' else original_text(path,*a,**kw)
    unpack = struct.unpack
    struct.unpack = lambda fmt,data: (unpack(fmt,data)[0],0,0) if fmt == '3i' else unpack(fmt,data)
    def construct(plan, control):
        # Kernel/UID construction modeled, actual exec_main registration/rights,
        # independent plan, real process stop, held lock and fd3 are exercised.
        lock = (root/'lock').open('w+b'); fcntl.flock(lock, fcntl.LOCK_EX)
        held_lock = fcntl.fcntl(lock.fileno(), fcntl.F_DUPFD_CLOEXEC, 10)
        os.dup2(control.fileno(), 3, inheritable=True)
        os.kill(os.getpid(), signal.SIGSTOP)
        time.sleep(20)
    m.construct = construct
    m.exec_main()


class WatchFixture:
    def __init__(self, seconds=8): self.seconds = seconds

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.root = Path(self.temp.name); self.m = m = load()
        self.deadline = time.monotonic_ns()+int(self.seconds*1_000_000_000)
        (self.root/'plan').write_bytes(m.encode(dict(version=1, context=m.CONTEXT,
            bootId=m.boot_id(), deadlineMonotonicNs=self.deadline)))
        (self.root/'plan').chmod(0o444)
        m.INPUT = str(self.root/'input'); Path(m.INPUT).mkdir()
        (Path(m.INPUT)/'resource-plan.json').write_bytes(m.encode(dict(version=1, context=m.CONTEXT,
            files={'/fixture': 'a'*64}, networkNamespace=dict(device=1, inode=2))))
        self.log = (self.root/'child.log').open('wb')
        def spawn(function):
            return subprocess.Popen([sys.executable, '-I', '-B', '-c',
                'import sys; sys.path.insert(0,sys.argv[1]); import test_fresh_physical_observe as t; '
                'getattr(t,sys.argv[2])(sys.argv[3])', str(HERE), function, str(self.root)],
                stdout=self.log, stderr=self.log)
        self.watch = spawn('watcher_fixture')
        wait_for(lambda: (self.root/'register').exists() or self.watch.poll() is not None)
        if self.watch.poll() is not None: raise AssertionError('watcher fixture failed')
        self.supervisor = spawn('supervisor_fixture')
        wait_for(lambda: self.supervisor.poll() is None and
                 Path(f'/proc/{self.supervisor.pid}/stat').read_text().rsplit(')', 1)[1].split()[0] == 'T')
        self.generation = m.decode((self.root/'resources/generation.json').read_bytes())
        self.policy = dict(context=m.CONTEXT, files={'/fixture': 'a'*64})
        policy_path = self.root/'resources/root'/m.POLICY[1:]
        policy_path.parent.mkdir(parents=True); policy_path.write_bytes(m.encode(self.policy))
        m.RESOURCE = str(self.root/'resources'); m.RUN_PLAN = str(self.root/'plan')
        m.REGISTER = str(self.root/'register'); m.CONTROL = str(self.root/'control')
        m.ACCEPTANCE = str(self.root/'acceptance')
        m.trusted_open = lambda path, directory=False: os.open(path, m.DIR if directory else m.FILE)
        m.trusted_read = lambda path, *args: Path(path).read_bytes()
        m.POLICY = str(self.root/'host-policy'); Path(m.POLICY).write_bytes(m.encode(self.policy))
        m.verify_input = lambda: {'files': self.policy['files']}
        # Physical consumer predicate is explicitly modeled; real state/start remains checked.
        self.consumer = lambda policy, pid: m.need(pid == self.supervisor.pid and
            m.ProcessLease.snapshot(self.lease)['state'] == 'T', 'STOPPED_SINGLE_SUPERVISOR_REQUIRED')
        self.lease = m.ProcessLease(self.supervisor.pid)
        m.watcher_properties = self.properties
        return self

    def properties(self, deadline):
        code = self.watch.poll()
        return dict(MainPID=str(self.watch.pid) if code is None else '0', ExecMainPID=str(self.watch.pid),
            InvocationID='b'*32, ActiveState='active' if code in (None, 0) else 'failed',
            SubState='running' if code is None else ('exited' if code == 0 else 'failed'),
            ExecMainCode='1' if code is not None and code >= 0 else ('2' if code is not None else '0'),
            ExecMainStatus=str(code if code is not None and code >= 0 else (abs(code) if code else 0)),
            Result='success' if code in (None, 0) else 'exit-code')

    def accept(self):
        a = {k: self.generation[k] for k in ('version', 'context', 'generation', 'supervisor', 'filesSha256')}
        a['policySha256'] = self.m.sha(self.m.encode(self.policy))
        (self.root/'acceptance').write_bytes(self.m.encode(a))
        wait_for(lambda: (self.root/'finally-entered').exists())

    def __exit__(self, *_):
        (self.root/'finish').touch()
        for p in (self.watch, self.supervisor):
            if p.poll() is None: p.kill()
            p.wait(timeout=3)
        self.lease.close(); self.log.close(); self.temp.cleanup()


class PropertyTests(unittest.TestCase):
    def test_real_systemd_active_exited_empty_controlgroup_is_not_replaced_invocation(self):
        m = load()
        values = dict(MainPID='0', ExecMainPID='123', InvocationID='b'*32, ActiveState='active',
            SubState='exited', ExecMainCode='1', ExecMainStatus='0', Result='success', Type='exec',
            Restart='no', RemainAfterExit='yes', ControlGroup='', NeedDaemonReload='no',
            FragmentPath='/etc/systemd/system/'+m.WATCH_UNIT, DropInPaths='', RestartForceExitStatus='')
        from types import SimpleNamespace
        with patch.object(subprocess, 'run', return_value=SimpleNamespace(stdout=''.join(
                k+'='+v+'\n' for k,v in values.items()).encode())) as query:
            self.assertEqual(m.watcher_properties(time.monotonic()+1), values)
            self.assertEqual(query.call_args.args[0][:3], ['/usr/bin/systemctl', 'show', m.WATCH_UNIT])
            self.assertNotIn('shell', query.call_args.kwargs)
            self.assertLessEqual(query.call_args.kwargs['timeout'], 1)


class NaturalObservationTests(unittest.TestCase):
    def test_actual_watch_main_finally_natural_positive_not_acceptance_visibility(self):
        with WatchFixture() as f:
            self.assertIn('watcherObservation', f.generation,
                          'generation lacks exact watcher invocation association')
            observer = load('fresh_physical_observe')
            with observer.Observation(f.m, f.consumer) as captured:
                f.accept()
                self.assertIsNone(f.watch.poll(), 'acceptance must precede watcher exit')
                import threading
                results = []
                thread = threading.Thread(target=lambda: results.append(captured.wait()))
                thread.start(); time.sleep(.05)
                self.assertTrue(thread.is_alive(), 'acceptance alone is not natural release')
                (f.root/'finish').touch(); thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
                self.assertEqual(results[0]['code'], 'WATCHER_NATURAL_RELEASE_OBSERVED_UNACCEPTED')
                self.assertFalse(results[0]['physicalAccepted'])
                self.assertEqual(f.lease.check(stopped=True)['state'], 'T')
                self.assertFalse((f.root/'register').exists())
                self.assertTrue((f.root/'control').exists())


    def test_pidfd_death_after_running_property_snapshot_rechecks_same_invocation(self):
        with WatchFixture() as f:
            observer = load('fresh_physical_observe')
            with observer.Observation(f.m, f.consumer) as captured:
                f.accept()
                actual = f.properties
                first = [True]
                def query(deadline):
                    values = actual(deadline)
                    if first[0]:
                        first[0] = False
                        self.assertEqual(values['SubState'], 'running')
                        (f.root/'finish').touch(); f.watch.wait(timeout=3)
                    return values
                f.m.watcher_properties = query
                result = captured.wait()
                self.assertEqual(result['code'], 'WATCHER_NATURAL_RELEASE_OBSERVED_UNACCEPTED')
                self.assertEqual(result['watcherObservation']['deadlineMonotonicNs'], f.deadline)
                f.lease.check(stopped=True)

    def test_original_death_between_pidfd_poll_and_live_identity_read_is_reobserved(self):
        with WatchFixture() as f:
            observer = load('fresh_physical_observe')
            with observer.Observation(f.m, f.consumer) as captured:
                f.accept()
                original = captured.watcher.check
                def dying():
                    (f.root/'finish').touch(); f.watch.wait(timeout=3)
                    return original()
                captured.watcher.check = dying
                result = captured.wait()
                self.assertEqual(result['code'], 'WATCHER_NATURAL_RELEASE_OBSERVED_UNACCEPTED')
                f.lease.check(stopped=True)

    def test_dead_original_without_terminal_publication_refuses_at_original_deadline(self):
        with WatchFixture(seconds=.8) as f:
            observer = load('fresh_physical_observe')
            with observer.Observation(f.m, f.consumer) as captured:
                f.accept(); running = f.properties(captured.run.deadline)
                (f.root/'finish').touch(); f.watch.wait(timeout=3)
                f.m.watcher_properties = lambda deadline: running
                with self.assertRaisesRegex(f.m.Refusal, 'ORIGINAL_RUN_DEADLINE'): captured.wait()
                f.lease.check(stopped=True)

    def test_replaced_control_path_is_not_original_held_resource(self):
        with WatchFixture() as f:
            observer = load('fresh_physical_observe')
            with observer.Observation(f.m, f.consumer) as captured:
                f.accept()
                (f.root/'control').unlink()
                replacement, _ = f.m.bind_owned(str(f.root/'control'))
                try:
                    with self.assertRaisesRegex(f.m.Refusal, 'OBSERVED_RESOURCE_PATH_DRIFT'): captured.check()
                finally: replacement.close()
                f.lease.check(stopped=True)

    def test_observer_rejects_nonclosed_or_foreign_resource_plan_before_wait(self):
        for field,value in (('extra', True), ('version', True), ('context', 'foreign'),
                            ('networkNamespace', dict(device=True, inode=2))):
            with self.subTest(field=field), WatchFixture() as f:
                observer = load('fresh_physical_observe')
                path = Path(f.m.INPUT)/'resource-plan.json'
                plan = f.m.decode(path.read_bytes()); plan[field] = value; path.write_bytes(f.m.encode(plan))
                with self.assertRaisesRegex(f.m.Refusal, 'EXACT_OBSERVED_RESOURCE_PLAN_REQUIRED'):
                    with observer.Observation(f.m, f.consumer): pass

    def test_failed_cleanup_after_acceptance_is_unknown_retained(self):
        with WatchFixture() as f:
            observer = load('fresh_physical_observe')
            with observer.Observation(f.m, f.consumer) as captured:
                (f.root/'cleanup-fail').touch(); f.accept(); (f.root/'finish').touch()
                f.watch.wait(timeout=3)
                self.assertNotEqual(f.watch.returncode, 0)
                with self.assertRaisesRegex(f.m.Refusal, 'NATURAL_WATCHER_SUCCESS_UNKNOWN'): captured.wait()
                f.lease.check(stopped=True)
                self.assertTrue((f.root/'resources').is_dir()); self.assertTrue((f.root/'control').exists())
                self.assertTrue((f.root/'register').exists())

    def test_signal_and_crash_after_acceptance_are_not_natural_release(self):
        import signal
        for sig in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signal=sig), WatchFixture() as f:
                observer = load('fresh_physical_observe')
                with observer.Observation(f.m, f.consumer) as captured:
                    f.accept(); f.watch.send_signal(sig); f.watch.wait(timeout=3)
                    with self.assertRaisesRegex(f.m.Refusal, 'NATURAL_WATCHER_SUCCESS_UNKNOWN'): captured.wait()
                    f.lease.check(stopped=True)
                    self.assertTrue((f.root/'resources').is_dir())

    def test_stale_replaced_invocation_and_pid_are_refused_during_wait(self):
        for field, value in (('InvocationID', 'c'*32), ('ExecMainPID', '1'), ('MainPID', '1')):
            with self.subTest(field=field), WatchFixture() as f:
                observer = load('fresh_physical_observe')
                with observer.Observation(f.m, f.consumer) as captured:
                    actual = f.properties
                    f.m.watcher_properties = lambda deadline: dict(actual(deadline), **{field: value})
                    with self.assertRaisesRegex(f.m.Refusal, 'WATCHER_INVOCATION_DRIFT|ORIGINAL_LIVE_WATCHER_REQUIRED'):
                        captured.wait()
                    f.lease.check(stopped=True)

    def test_stale_watcher_pid_start_and_supervisor_start_refuse_capture(self):
        for target, key, value in (('watcherObservation', 'pid', 1), ('watcherObservation', 'start', '1'),
                                    ('supervisor', 'start', '1')):
            with self.subTest(target=target, key=key), WatchFixture() as f:
                f.generation[target][key] = value
                (f.root/'resources/generation.json').write_bytes(f.m.encode(f.generation))
                observer = load('fresh_physical_observe')
                with self.assertRaises((f.m.Refusal, OSError)):
                    observer.Observation(f.m, f.consumer)
                f.lease.check(stopped=True)

    def test_early_supervisor_resume_refuses_without_signaling_it(self):
        import signal
        with WatchFixture() as f:
            observer = load('fresh_physical_observe')
            with observer.Observation(f.m, f.consumer) as captured:
                f.accept()
                # Adversarial EXTERNAL fixture resumer; product observer never signals.
                signal.pidfd_send_signal(f.lease.fd, signal.SIGCONT)
                wait_for(lambda: f.lease.snapshot()['state'] != 'T')
                with self.assertRaisesRegex(f.m.Refusal, 'STOPPED_PREPARATION_REQUIRED'): captured.wait()
                self.assertIsNone(f.supervisor.poll())

    def test_generation_and_plan_drift_after_capture_refuse(self):
        for target in ('resources/generation.json', 'plan', 'host-policy', 'input/resource-plan.json'):
            with self.subTest(target=target), WatchFixture() as f:
                observer = load('fresh_physical_observe')
                with observer.Observation(f.m, f.consumer) as captured:
                    f.accept()
                    path = f.root/target; raw = path.read_bytes()
                    other = path.with_suffix('.next'); other.write_bytes(raw); other.chmod(0o444)
                    other.replace(path)
                    with self.assertRaisesRegex(f.m.Refusal, 'RUN_PLAN_DRIFT|OBSERVATION_INPUT_DRIFT'): captured.wait()
                    f.lease.check(stopped=True)

    def test_original_deadline_expires_while_accepted_watcher_still_in_finally(self):
        with WatchFixture(seconds=.8) as f:
            observer = load('fresh_physical_observe')
            with observer.Observation(f.m, f.consumer) as captured:
                f.accept()
                with self.assertRaisesRegex(f.m.Refusal, 'ORIGINAL_RUN_DEADLINE'): captured.wait()
                self.assertIsNone(f.watch.poll()); f.lease.check(stopped=True)

    def test_no_renewal_at_stopped_barrier_without_acceptance(self):
        with WatchFixture(seconds=.8) as f:
            wait_for(lambda: (f.root/'finally-entered').exists(), seconds=2)
            (f.root/'finish').touch(); f.watch.wait(timeout=3)
            self.assertNotEqual(f.watch.returncode, 0)
            f.supervisor.wait(timeout=3)
            self.assertFalse((f.root/'resources').exists())
            self.assertFalse((f.root/'control').exists())

    def test_observer_must_capture_original_watcher_alive(self):
        with WatchFixture() as f:
            f.accept(); (f.root/'finish').touch(); f.watch.wait(timeout=3)
            observer = load('fresh_physical_observe')
            with self.assertRaises((f.m.Refusal, OSError)):
                observer.Observation(f.m, f.consumer)
            f.lease.check(stopped=True)

    def test_forged_success_properties_while_watcher_alive_cannot_complete(self):
        with WatchFixture() as f:
            observer = load('fresh_physical_observe')
            with observer.Observation(f.m, f.consumer) as captured:
                f.accept()
                values = f.properties(f.m.RunPlan().deadline)
                values.update(MainPID='0', SubState='exited', ExecMainCode='1', ExecMainStatus='0', Result='success')
                f.m.watcher_properties = lambda deadline: values
                with self.assertRaisesRegex(f.m.Refusal, 'ORIGINAL_LIVE_WATCHER_REQUIRED'): captured.wait()
                self.assertIsNone(f.watch.poll()); f.lease.check(stopped=True)


INSTALLED_SOURCES = {
    '/usr/local/libexec/c3-test-fresh-physical.py': 'fresh_physical.py',
    '/usr/local/libexec/c3-test-fresh-physical-exec.py': 'fresh_physical_exec.py',
    '/usr/local/libexec/c3-test-fresh-physical-watch.py': 'fresh_physical_watch.py',
    '/usr/local/libexec/c3-test-coordinated-restore.py': 'coordinated_restore.py',
    '/usr/local/libexec/c3-test-fresh-classic.py': 'fresh_classic_launch.py',
    '/etc/systemd/system/c3-test-fresh-prepare-watch.service': 'c3-test-fresh-prepare-watch.service',
    '/etc/systemd/system/c3-test-fresh-classic.service': 'c3-test-fresh-classic.service',
}


class ObserverSourcePinTests(unittest.TestCase):
    """Exercise main's actual pin guard; never load/launch operational modules."""

    def check_entry(self, pins=None, altered=None, accepted=False):
        from contextlib import ExitStack
        o = load('fresh_physical_observe')
        snapshots = {}
        for path, name in INSTALLED_SOURCES.items():
            source = HERE/name
            info = source.stat()
            snapshots[path] = (source.read_bytes(),
                               (info.st_dev, info.st_ino, info.st_size,
                                info.st_mtime_ns, info.st_ctime_ns))
        if altered is not None:
            raw, identity = snapshots[altered]
            snapshots[altered] = (raw+b'\n# local wrong-source control\n', identity)

        class PinGuardPassed(Exception):
            pass

        with ExitStack() as stack:
            if pins is not None:
                stack.enter_context(patch.dict(o.SOURCE_PINS, pins))
            stack.enter_context(patch.object(sys, 'argv', [str(HERE/'fresh_physical_observe.py')]))
            # Only fixed entry identity and installed-path/ownership IO are modeled.
            # SHA256 and the decision in main() are real, over current source bytes.
            for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
                stack.enter_context(patch.object(os, name, return_value=0))
            stack.enter_context(patch.object(os, 'readlink', return_value='modeled-host-namespace'))
            read = stack.enter_context(patch.object(o, 'source_snapshot', side_effect=snapshots.__getitem__))
            module = stack.enter_context(patch.object(o.types, 'ModuleType', side_effect=PinGuardPassed))
            if accepted:
                with self.assertRaises(PinGuardPassed): o.main()
                module.assert_called_once_with('physical')
            else:
                with self.assertRaisesRegex(RuntimeError, '^OBSERVATION_SOURCE_PIN_REQUIRED$'): o.main()
                module.assert_not_called()
            self.assertEqual([call.args[0] for call in read.call_args_list], list(INSTALLED_SOURCES))

    def test_actual_main_accepts_current_source_bytes_before_module_loading(self):
        self.check_entry(accepted=True)

    def test_actual_main_rejects_each_stale_pin_before_module_loading(self):
        for path, stale in (
                ('/usr/local/libexec/c3-test-coordinated-restore.py',
                 '8b8f8565b1d337a1f44a6554115b0e60f0a3d86dd24bfc3853e003dd481b2a76'),
                ('/usr/local/libexec/c3-test-fresh-classic.py',
                 '3bbc1c708fb89da5f8048e7f6c1af4da00e7ceaa05d66fc9da0f3f7ee63cb85e')):
            with self.subTest(path=path): self.check_entry(pins={path: stale})

    def test_actual_main_rejects_each_changed_source_before_module_loading(self):
        for path in ('/usr/local/libexec/c3-test-coordinated-restore.py',
                     '/usr/local/libexec/c3-test-fresh-classic.py'):
            with self.subTest(path=path): self.check_entry(altered=path)


class ObserverEntryTests(unittest.TestCase):
    def test_exact_runtime_source_closure_matches_current_sources_without_old_pack_repin(self):
        m = load('fresh_physical_observe')
        import hashlib
        self.assertEqual(set(m.SOURCE_PINS), set(INSTALLED_SOURCES), 'observer lacks fixed reviewed source closure')
        for path, name in INSTALLED_SOURCES.items():
            self.assertEqual(m.SOURCE_PINS[path], hashlib.sha256((HERE/name).read_bytes()).hexdigest())

    def test_observer_fixed_cli_refuses_unprivileged_and_arguments_without_writes(self):
        for args in ([], ['observe'], ['--deadline=600']):
            with self.subTest(args=args):
                p = subprocess.run([sys.executable, '-I', '-B', str(HERE/'fresh_physical_observe.py'), *args],
                    capture_output=True, timeout=3, env=dict(PYTHONPATH='/foreign', INVOCATION_ID='b'*32))
                self.assertEqual(p.returncode, 75); self.assertEqual(p.stdout, b'')
                self.assertEqual(p.stderr, b'REFUSAL WATCHER_RELEASE_UNKNOWN_RETAINED\n')

    def test_fixed_main_loads_pinned_modules_and_observes_actual_watcher_finally(self):
        import contextlib
        import io
        from contextlib import ExitStack
        with WatchFixture() as f, ExitStack() as stack:
            o = load('fresh_physical_observe')
            self.assertEqual(set(o.SOURCE_PINS), set(INSTALLED_SOURCES), 'runtime closure unavailable')
            # Only installed path/ownership/systemd/physical consumer seams are modeled.
            # Runtime loader compiles actual current hash-pinned source bytes.
            def source(path):
                p = HERE/INSTALLED_SOURCES[path]
                s = p.stat()
                return p.read_bytes(), (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            stack.enter_context(patch.object(o, 'source_snapshot', side_effect=source))
            for name in ('getuid','geteuid','getgid','getegid'):
                stack.enter_context(patch.object(os, name, return_value=0))
            readlink = os.readlink
            stack.enter_context(patch.object(os, 'readlink', side_effect=lambda path,*a,**kw:
                readlink(str(path).replace('/proc/1/ns/', '/proc/self/ns/'),*a,**kw)))
            real_observation = o.Observation
            def assembled(m, prepared, source_check):
                self.assertEqual(m.sha((HERE/'fresh_physical.py').read_bytes()), o.SOURCE_PINS[o.PHYSICAL])
                self.assertIn('fresh', prepared.__code__.co_freevars)
                for name in ('RUN_PLAN','INPUT','RESOURCE','POLICY','REGISTER','CONTROL','ACCEPTANCE','trusted_read',
                             'trusted_open','watcher_properties'):
                    setattr(m, name, getattr(f.m, name))
                captured = real_observation(m, f.consumer, source_check)
                f.accept(); self.assertIsNone(f.watch.poll()); (f.root/'finish').touch()
                return captured
            stack.enter_context(patch.object(o, 'Observation', side_effect=assembled))
            output = io.StringIO()
            with contextlib.redirect_stdout(output): o.main()
            result = json.loads(output.getvalue())
            self.assertEqual(result['code'], 'WATCHER_NATURAL_RELEASE_OBSERVED_UNACCEPTED')
            self.assertFalse(result['physicalAccepted']); self.assertFalse(result['operationalGO'])
            self.assertEqual(result['watcherObservation']['pid'], f.watch.pid)
            f.lease.check(stopped=True)


if __name__ == '__main__': unittest.main()
