"""Disposable unprivileged process/file evidence; no physical kernel acceptance."""
import importlib.util
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from unittest.mock import patch
import threading
import struct
import fcntl
import json

HERE = Path(__file__).resolve().parent
SCRATCH = '/home/leon/.hermes/cache/scratch'


def load():
    spec = importlib.util.spec_from_file_location('physical', HERE/'fresh_physical.py')
    module = importlib.util.module_from_spec(spec)
    if spec.loader is None or not (HERE/'fresh_physical.py').exists():
        return None
    spec.loader.exec_module(module)
    return module


class OwnedLifecycleTests(unittest.TestCase):
    def test_expired_stopped_process_is_killed_and_only_owned_tree_removed(self):
        m = load()
        self.assertIsNotNone(m, 'missing real physical lifecycle implementation')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp:
            root = Path(temp)
            foreign = root/'foreign'; foreign.mkdir(); (foreign/'keep').write_bytes(b'keep')
            owned = m.OwnedTree.create(root/'owned')
            (owned.path/'payload').write_bytes(b'private')
            p = subprocess.Popen([sys.executable, '-I', '-B', '-c',
                                  'import os,signal; os.kill(os.getpid(),signal.SIGSTOP)'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                _, status = os.waitpid(p.pid, os.WUNTRACED)
                self.assertTrue(os.WIFSTOPPED(status))
                with m.ProcessLease(p.pid) as lease:
                    with self.assertRaisesRegex(m.Refusal, 'PREPARATION_DEADLINE'):
                        m.wait_prepared(lease, time.monotonic()-.01, lambda: None)
                    lease.abandon()
                p.wait(timeout=3)
                self.assertEqual(p.returncode, -signal.SIGKILL)
                owned.dispose()
                self.assertFalse((root/'owned').exists())
                self.assertEqual((foreign/'keep').read_bytes(), b'keep')
            finally:
                if p.poll() is None: p.kill(); p.wait()
                owned.close()


class AcceptanceTests(unittest.TestCase):
    def test_stopped_positive_requires_independent_exact_acceptance_without_signal(self):
        m = load()
        self.assertTrue(hasattr(m, 'wait_acceptance'), 'independent acceptance wait missing')
        p = subprocess.Popen([sys.executable, '-I', '-B', '-c',
                              'import os,signal; os.kill(os.getpid(),signal.SIGSTOP)'])
        try:
            os.waitpid(p.pid, os.WUNTRACED)
            with m.ProcessLease(p.pid) as lease:
                policy = {'context': m.CONTEXT, 'files': {'/test': 'a'*64}}
                expected = {'version': 1, 'context': m.CONTEXT,
                            'supervisor': {'pid': p.pid, 'start': lease.start},
                            'generation': 'b'*64, 'filesSha256': m.sha(m.encode(policy['files'])),
                            'policySha256': m.sha(m.encode(policy))}
                result = m.wait_acceptance(lease, time.monotonic()+1, lambda: expected,
                                           policy['files'], 'b'*64, lambda: policy, lambda: None)
                self.assertEqual(result, expected)
                self.assertEqual(lease.check()['state'], 'T')
                self.assertTrue(lease.released)
                with self.assertRaisesRegex(m.Refusal, 'RELEASED_PREPARATION_NOT_OWNED'):
                    lease.abandon()
        finally:
            p.kill(); p.wait(timeout=3)

    def test_source_map_drift_and_late_acceptance_do_not_release(self):
        m = load()
        self.assertTrue(hasattr(m, 'wait_acceptance'), 'independent acceptance wait missing')
        for fault in ('source', 'late', 'supervisor'):
            with self.subTest(fault=fault):
                p = subprocess.Popen([sys.executable, '-I', '-B', '-c',
                                      'import os,signal; os.kill(os.getpid(),signal.SIGSTOP)'])
                try:
                    os.waitpid(p.pid, os.WUNTRACED)
                    with m.ProcessLease(p.pid) as lease:
                        files = {'/test': 'a'*64}
                        policy = {'context': m.CONTEXT, 'files': files if fault != 'source' else {'/test': 'c'*64}}
                        acceptance = {'version': 1, 'context': m.CONTEXT,
                                      'supervisor': {'pid': p.pid + (fault == 'supervisor'), 'start': lease.start},
                                      'generation': 'b'*64, 'filesSha256': m.sha(m.encode(files)),
                                      'policySha256': m.sha(m.encode(policy))}
                        def read():
                            if fault == 'late': time.sleep(.03)
                            return acceptance
                        with self.assertRaisesRegex(m.Refusal, 'SOURCE_MAP_DRIFT|ACCEPTANCE_DEADLINE|EXACT_INDEPENDENT_ACCEPTANCE_REQUIRED'):
                            m.wait_acceptance(lease, time.monotonic()+.01, read, files, 'b'*64,
                                              lambda: policy, lambda: None)
                        self.assertFalse(lease.released)
                        lease.abandon()
                finally:
                    if p.poll() is None: p.kill()
                    p.wait(timeout=3)


class DescriptorTests(unittest.TestCase):
    def test_real_anonymous_stdio_fd3_stop_and_no_inherited_extra(self):
        m = load()
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp:
            path = str(Path(temp)/'control')
            control, identity = m.bind_owned(path)
            extra = os.open(Path(temp)/'extra', os.O_RDWR|os.O_CREAT, 0o600)
            code = '''import os,signal,socket,sys
import fresh_physical as m
control=socket.socket(fileno=int(sys.argv[1]))
m.anonymous_stdio_and_control(control)
os.kill(os.getpid(),signal.SIGSTOP)
'''
            p = subprocess.Popen([sys.executable, '-B', '-c', code, str(control.fileno())],
                                 cwd=HERE, pass_fds=(control.fileno(), extra))
            try:
                _, status = os.waitpid(p.pid, os.WUNTRACED)
                self.assertTrue(os.WIFSTOPPED(status))
                proc = Path('/proc')/str(p.pid)/'fd'
                self.assertEqual({p.name for p in proc.iterdir()}, {'0', '1', '2', '3'})
                for fd in ('0', '1', '2'):
                    self.assertTrue(os.readlink(proc/fd).startswith('/memfd:c3-supervisor-stdio'))
                    self.assertEqual((proc/fd).stat().st_size, 0)
                self.assertEqual((proc/'3').stat().st_ino, os.fstat(control.fileno()).st_ino)
                self.assertEqual(control.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), 0)
            finally:
                p.kill(); p.wait(timeout=3)
                os.close(extra); control.close(); m.unlink_owned_socket(path, identity)

    def test_socket_collision_and_foreign_replacement_are_preserved(self):
        m = load()
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp:
            path = Path(temp)/'control'
            control, identity = m.bind_owned(str(path))
            try:
                with self.assertRaises(OSError): m.bind_owned(str(path))
                path.unlink(); path.write_bytes(b'foreign')
                with self.assertRaisesRegex(m.Refusal, 'OWNED_SOCKET_REPLACED'):
                    m.unlink_owned_socket(str(path), identity)
                self.assertEqual(path.read_bytes(), b'foreign')
            finally: control.close()

    def test_replaced_owned_tree_is_not_deleted(self):
        m = load()
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp:
            path = Path(temp)/'owned'
            owned = m.OwnedTree.create(path)
            try:
                path.rename(Path(temp)/'original'); path.mkdir(); (path/'foreign').write_bytes(b'keep')
                with self.assertRaisesRegex(m.Refusal, 'OWNED_RESOURCE_REPLACED'): owned.dispose()
                self.assertEqual((path/'foreign').read_bytes(), b'keep')
            finally: owned.close()


class AssembledWatchTests(unittest.TestCase):
    def exercise(self, accept):
        m = load()
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp, ExitStack() as stack:
            root = Path(temp)
            resource = root/'resources'
            files = {'/usr/local/libexec/c3-test-coordinated-restore.py': 'a'*64,
                     '/usr/local/libexec/c3-test-fresh-classic.py': 'b'*64}
            for name, value in {'RESOURCE': str(resource), 'CONTROL': str(root/'control'),
                                'REGISTER': str(root/'register'), 'ACCEPTANCE': str(root/'acceptance'),
                                'ACCEPT_SECONDS': .3, 'PREPARE_SECONDS': 3}.items():
                stack.enter_context(patch.object(m, name, value))
            # Explicitly MODELED root ownership, input installation and UID/cgroup
            # authority. Channels, rights, memfds, stopped PID/start, flock, deadline,
            # exact independent acceptance, pidfd kill and owned cleanup are REAL.
            stack.enter_context(patch.object(m, 'verify_input', return_value={'files': files}))
            joined = []
            stack.enter_context(patch.object(m, 'join_private_network', side_effect=lambda plan: joined.append('modeled private net')))
            real_bind = m.bind_owned
            def bind(path, *args):
                self.assertEqual(joined, ['modeled private net'], 'control must be CREATED in the final netns')
                return real_bind(path, *args)
            stack.enter_context(patch.object(m, 'bind_owned', side_effect=bind))
            stack.enter_context(patch.object(m, 'trusted_read', side_effect=lambda path, *args: Path(path).read_bytes()))
            def peer(channel):
                pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                self.assertEqual(uid, os.getuid()); self.assertEqual(gid, os.getgid())
                return pid
            stack.enter_context(patch.object(m, 'constructor_peer', side_effect=peer))
            def phase(lease, inode):
                lease.check(stopped=True)
                proc = Path('/proc')/str(lease.pid)/'fd'
                self.assertEqual((proc/'3').stat().st_ino, inode)
                for fd in ('0', '1', '2'):
                    self.assertTrue(os.readlink(proc/fd).startswith('/memfd:c3-supervisor-stdio'))
                with (root/'lock').open('r+b') as lock:
                    with self.assertRaises(BlockingIOError): fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
            stack.enter_context(patch.object(m, 'check_prepared_resources', side_effect=phase))
            result = []
            def watch():
                try: m.watch_main(); result.append('released')
                except BaseException as error: result.append(error)
            thread = threading.Thread(target=watch)
            thread.start()
            deadline = time.monotonic()+3
            while not (root/'register').exists() and thread.is_alive() and time.monotonic()<deadline: time.sleep(.005)
            code = '''import os,sys,socket,json
from pathlib import Path
import fresh_physical as m
import fresh_classic_launch as fresh
root=Path(sys.argv[1]); m.CONTROL=str(root/'control')
files=json.loads(sys.argv[2])
with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as channel:
 channel.connect(str(root/'register')); channel.send(b'PREPARE\\n')
 control=m.receive_control(channel,files)
m.anonymous_stdio_and_control(control)
# Root ownership/private namespace facts are MODELED; lock and original
# PreparationSupervisorFiles SIGSTOP/source-map predicate are real.
fresh.c.trusted_read=lambda path:(root/'resources/root/etc/c3-test-fresh-classic.json').read_bytes()
with (root/'lock').open('w+b') as lock:
 import fcntl
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 fresh.PreparationSupervisorFiles(files).read_json(fresh.POLICY)
(root/'returned').write_text('returned')
'''
            p = subprocess.Popen([sys.executable, '-B', '-c', code, str(root), json.dumps(files)], cwd=HERE)
            try:
                stop_deadline = time.monotonic()+3
                while time.monotonic()<stop_deadline:
                    if p.poll() is not None: self.fail('test child died before real preparation stop')
                    if Path(f'/proc/{p.pid}/stat').read_text().rsplit(')', 1)[1].split()[0] == 'T': break
                    time.sleep(.005)
                else: self.fail('test child never stopped')
                if accept:
                    policy = {'context': m.CONTEXT, 'files': files}
                    path = resource/'root/etc/c3-test-fresh-classic.json'; path.parent.mkdir(parents=True)
                    path.write_bytes(m.encode(policy))
                    generation = json.loads((resource/'generation.json').read_bytes())
                    acceptance = {k: generation[k] for k in ('version', 'context', 'generation', 'supervisor', 'filesSha256')}
                    acceptance['policySha256'] = m.sha(m.encode(policy))
                    (root/'acceptance').write_bytes(m.encode(acceptance))
                thread.join(timeout=4)
                self.assertFalse(thread.is_alive(), 'watcher did not terminate within external lease')
                if accept:
                    self.assertEqual(result, ['released'])
                    self.assertEqual(Path(f'/proc/{p.pid}/stat').read_text().rsplit(')', 1)[1].split()[0], 'T')
                    self.assertTrue(resource.exists()); self.assertTrue((root/'control').exists())
                    self.assertFalse((root/'returned').exists())
                else:
                    self.assertEqual(len(result), 1); self.assertRegex(str(result[0]), 'ACCEPTANCE_DEADLINE')
                    p.wait(timeout=3); self.assertEqual(p.returncode, -signal.SIGKILL)
                    self.assertFalse(resource.exists()); self.assertFalse((root/'control').exists())
                    self.assertFalse((root/'returned').exists())
                self.assertFalse((root/'register').exists())
            finally:
                if p.poll() is None: p.kill()
                p.wait(timeout=3); thread.join(timeout=4)

    def test_real_watchdog_abandons_expired_preparer_without_read_or_exec(self): self.exercise(False)
    def test_real_watchdog_releases_only_separately_pinned_stopped_preparer(self): self.exercise(True)


class ConstructionPlanTests(unittest.TestCase):
    def test_real_copy_and_reader_safe_bootstrap_under_actual_umask_0077(self):
        m = load()
        assert m is not None
        with tempfile.TemporaryDirectory(dir=SCRATCH) as temp, ExitStack() as stack:
            root = Path(temp)
            inputs = root/'inputs'; image = inputs/'root'; image.mkdir(parents=True)
            resources = root/'resources'
            previous_umask = os.umask(0o077)
            try:
                owned = m.OwnedTree.create(resources)
            finally:
                os.umask(previous_umask)
            stack.callback(owned.close)
            names = [m.PREPARER, '/usr/local/libexec/c3-test-coordinated-restore.py',
                     '/usr/local/libexec/c3-test-fresh-classic.py', '/runtime/node', '/app/index.js',
                     '/usr/bin/python3', '/etc/classic.json']
            files = {}
            for name in names:
                path = image/name[1:]; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'NONEXECUTABLE local modeled-kernel fixture '+name.encode())
                files[name] = m.sha(path.read_bytes())
            # The independently accepted source-pack payload directories are 0755;
            # copytree must restore them despite the REAL service umask below.
            for directory, _, _ in os.walk(image): Path(directory).chmod(0o755)
            nsdir = root/'netns'; nsdir.mkdir(); (nsdir/'c3-test-fresh-classic').write_bytes(b'modeled nsfs')
            ns = (nsdir/'c3-test-fresh-classic').stat()
            plan = {'version': 1, 'context': m.CONTEXT, 'files': files,
                    'networkNamespace': {'device': ns.st_dev, 'inode': ns.st_ino}}
            events = []
            class ExecReached(Exception): pass
            def execute(path, argv, env):
                events.append(('exec', path, argv, env)); raise ExecReached()
            # This is NOT mount/namespace/UID/capability execution evidence. Only
            # copy, hashing, exclusive bootstrap/lock files and source map are real.
            stack.enter_context(patch.object(m, 'INPUT', str(inputs)))
            stack.enter_context(patch.object(m, 'RESOURCE', str(resources)))
            stack.enter_context(patch.object(m, 'trusted_read', side_effect=lambda path, *args: Path(path).read_bytes()))
            stack.enter_context(patch.object(m, 'trusted_open', side_effect=lambda path, **kw: os.open(nsdir, m.DIR)))
            stack.enter_context(patch.object(fcntl, 'ioctl', return_value=0x40000000))
            original_stat = os.stat
            stack.enter_context(patch.object(m.os, 'stat', side_effect=lambda path, *args, **kw:
                                original_stat('/proc/self/ns/net' if str(path) == '/proc/1/ns/net' else path, *args, **kw)))
            stack.enter_context(patch.object(m, 'kernel_call', side_effect=lambda *args: events.append(('kernel', *args))))
            stack.enter_context(patch.object(m, 'mount', side_effect=lambda *args: events.append(('mount', *args))))
            def before_modeled_identity_drop():
                # Real inode/mode proof BEFORE drop, not a real UID65531 read.
                # Root ownership, readonly remount and identity stay MODELED.
                policy = resources/'root'/m.POLICY[1:]
                self.assertEqual(policy.stat().st_mode & 0o777, 0o644,
                                 'bootstrap must be reader-safe despite service UMask=0077')
                self.assertEqual(json.loads(policy.read_bytes()), {'files': files})
                copied = resources/'root'
                self.assertEqual(resources.stat().st_mode & 0o777, 0o700,
                                 'host root-control ancestor must stay private')
                for directory, _, _ in os.walk(image):
                    target = copied/Path(directory).relative_to(image)
                    self.assertEqual(target.stat().st_mode & 0o777, 0o755,
                                     'trusted_read needs read/search on copied directories')
                # REAL underlying mkdir modes are 0700 under UMask=0077. They
                # are covered by mounts BEFORE drop: proc's root is root:root
                # 0555; state is UID/GID65531 0700 via the exact tmpfs options.
                # We assert the mount contract, NOT invented live mounted modes.
                for name in ('proc', 'state'):
                    self.assertEqual((copied/name).stat().st_mode & 0o777, 0o700)
                self.assertIn(('mount', 'proc', str(copied/'proc'), 'proc', 1|2|4|8), events)
                self.assertIn(('mount', 'tmpfs', str(copied/'state'), 'tmpfs', 2|4|8,
                               'size=16777216,nr_inodes=1024,mode=0700,uid=65531,gid=65531'), events)
                self.assertIn(('lock-owner-modeled', 65531, 65531), events)
                self.assertFalse((copied/'.old-root').exists())
                self.assertIn(('mount', None, '/', None, 4096|32|1|2|4), events)
                events.append(('identity',))
            stack.enter_context(patch.object(m, 'drop_identity', side_effect=before_modeled_identity_drop))
            stack.enter_context(patch.object(m, 'anonymous_stdio_and_control', side_effect=lambda control: events.append(('fd-remap',))))
            stack.enter_context(patch.object(m.os, 'chdir', side_effect=lambda path: events.append(('chdir', str(path)))))
            original_rmdir = os.rmdir
            stack.enter_context(patch.object(m.os, 'rmdir', side_effect=lambda path: original_rmdir(resources/'root/.old-root')))
            def modeled_lock_owner(fd, uid, gid):
                self.assertEqual(os.readlink(f'/proc/self/fd/{fd}'), str(resources/'root/state/launch.lock'))
                self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o600)
                events.append(('lock-owner-modeled', uid, gid))
            stack.enter_context(patch.object(m.os, 'fchown', side_effect=modeled_lock_owner))
            stack.enter_context(patch.object(m.os, 'execve', side_effect=execute))
            # RLIMIT_CORE is modeled; umask is REAL and restored even on RED.
            import resource
            stack.enter_context(patch.object(resource, 'setrlimit'))
            previous_umask = os.umask(0o077)
            try:
                with self.assertRaises(ExecReached): m.construct(plan, None)
            finally:
                self.assertEqual(os.umask(previous_umask), 0o077)
            copied = resources/'root'
            self.assertEqual(json.loads((copied/m.POLICY[1:]).read_bytes()), {'files': files})
            self.assertEqual((copied/'state/launch.lock').stat().st_mode & 0o777, 0o600)
            self.assertEqual({name: m.sha((copied/name[1:]).read_bytes()) for name in files}, files)
            self.assertIn(('kernel', 'unshare', 0x00020000|0x08000000|0x04000000), events)
            self.assertIn(('mount', None, '/', None, 4096|32|1|2|4), events)
            self.assertIn(('mount', 'proc', str(copied/'proc'), 'proc', 1|2|4|8), events)
            self.assertLess(events.index(('identity',)), events.index(('fd-remap',)))
            self.assertEqual(events[-1], ('exec', '/usr/bin/python3',
                             ['/usr/bin/python3', '-I', '-B', m.PREPARER], {'LC_ALL': 'C'}))


class ProcessLeaseFaultTests(unittest.TestCase):
    def test_failed_initial_identity_read_closes_owned_pidfd(self):
        m = load()
        p = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(10)'])
        try:
            before = set(os.listdir('/proc/self/fd'))
            with patch.object(m.ProcessLease, 'snapshot', side_effect=m.Refusal('PREPARATION_PROCESS_LOST')):
                with self.assertRaisesRegex(m.Refusal, 'PREPARATION_PROCESS_LOST'): m.ProcessLease(p.pid)
            self.assertEqual(set(os.listdir('/proc/self/fd')), before)
            self.assertIsNone(p.poll())
        finally: p.kill(); p.wait(timeout=3)


class FixedEntryAndPackTests(unittest.TestCase):
    def test_resource_stage_is_fixed_disk_path_not_run_tmpfs(self):
        with patch.dict(os.environ, {'C3_ROOT': '/arbitrary', 'RESOURCE': '/arbitrary',
                                     'C3_RESOURCE': '/arbitrary'}):
            m = load()
        assert m is not None
        self.assertEqual(m.RESOURCE, '/var/lib/c3-test-fresh-resources')

    def test_fixed_entries_refuse_unprivileged_and_all_arguments(self):
        for name in ('fresh_physical_exec.py', 'fresh_physical_watch.py'):
            for arguments in ([], ['prepare'], ['--root=/arbitrary']):
                with self.subTest(name=name, arguments=arguments):
                    p = subprocess.run([sys.executable, '-I', '-B', str(HERE/name), *arguments],
                                       env={'PYTHONPATH': '/arbitrary', 'C3_ROOT': '/arbitrary'},
                                       capture_output=True, timeout=3)
                    self.assertEqual(p.returncode, 75)
                    self.assertEqual(p.stdout, b'')
                    self.assertEqual(p.stderr, b'REFUSAL FIXED_ROOT_NO_ARGUMENT_ENTRY_REQUIRED\n')

    def test_wrapper_and_source_pack_pins_bind_exact_source_and_units(self):
        import ast
        import fresh_install_source_pack as pack
        digest = pack.sha((HERE/'fresh_physical.py').read_bytes())
        for name in ('fresh_physical_exec.py', 'fresh_physical_watch.py'):
            tree = ast.parse((HERE/name).read_bytes())
            pins = [node.value.value for node in tree.body if isinstance(node, ast.Assign) and
                    any(isinstance(target, ast.Name) and target.id == 'MODULE_SHA256' for target in node.targets)]
            self.assertEqual(pins, [digest])
        for relative, pin in pack.PHYSICAL_SOURCE_PINS.items():
            self.assertEqual(pack.sha((HERE.parents[1]/relative).read_bytes()), pin)
            self.assertIn(relative, pack.HOST_SOURCES)
        unit = (HERE/'c3-test-fresh-classic.service').read_bytes()
        self.assertIn(b'Restart=no\n', unit); self.assertIn(b'KillMode=process\n', unit)
        self.assertIn(b'ExecStart=/usr/bin/python3 -I -B /usr/local/libexec/c3-test-fresh-physical-exec.py\n', unit)

    def test_pack_export_contains_exact_new_sources_without_provisioning_claim(self):
        import fresh_install_source_pack as pack
        from test_fresh_install_source_pack import Fixture
        with Fixture() as f:
            f.build()
            report = pack.verify_pack(str(f.output))
            self.assertTrue(report['unitIncluded']); self.assertTrue(report['resourceConstructorIncluded'])
            self.assertTrue(report['preparationLifecycleImplemented'])
            self.assertFalse(report['provisioningImplemented']); self.assertFalse(report['physicalAccepted'])
            self.assertFalse(report['operationalGO']); self.assertFalse(report['resourcePolicyIncluded'])
            intents = json.loads((f.output/'host-intents.json').read_bytes())
            for relative, pin in pack.PHYSICAL_SOURCE_PINS.items():
                self.assertEqual(intents[relative]['sha256'], pin)
                self.assertEqual(pack.sha((f.output/intents[relative]['packPath']).read_bytes()), pin)

    def test_new_committed_source_drift_refuses_before_export(self):
        import fresh_install_source_pack as pack
        from test_fresh_install_source_pack import Fixture
        with Fixture() as f:
            name = pack.PREFIX+'fresh_physical.py'
            path = f.repo/name; path.write_bytes(path.read_bytes()+b'\n# unreviewed\n')
            f.git('add', name)
            f.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid', 'commit', '-qm', 'drift')
            with self.assertRaisesRegex(pack.Refusal, 'PHYSICAL_SOURCE_DRIFT'): f.build()
            f.assert_no_stage(self)


if __name__ == '__main__': unittest.main()
