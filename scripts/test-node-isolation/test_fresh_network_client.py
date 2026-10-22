"""Local AF_UNIX/process proof. Root UID, machine, kernel effects are modeled."""
import copy
from contextlib import ExitStack
import importlib.util
import json
import os
import select
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('fresh_network')
control = load('fresh_network_control')
existing = load('test_fresh_network')


def fixture_server(root):
    """Real control.run → real Lease.peer → real Controller.prepare, no kernel IO."""
    root = Path(root)
    m.INPUT = str(root/'plan'); m.LEASE = str(root/'lease')
    m.SOCKET = str(root/'s'); m.STATE = str(root/'state')
    m.trusted_read = lambda path: Path(path).read_bytes()  # modeled installed ownership only
    m.trusted_fd = lambda path, directory=False: os.open(
        root if path in ('/run', '/run/netns') else path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if directory else 0))
    # Every actual credential PID survives; only UID/GID values are modeled.
    real_peer = control.Lease.peer
    class RootPeer:
        def __init__(self, channel): self.channel = channel
        def getsockopt(self, *args):
            pid, uid, gid = struct.unpack('3i', self.channel.getsockopt(*args))
            (root/'peer').write_text(json.dumps({'pid': pid, 'uid': uid, 'gid': gid}))
            return struct.pack('3i', pid, 0, 0)
    control.Lease.peer = lambda self, channel: real_peer(self, RootPeer(channel))
    real_check = control.Lease.check
    # The original check's proc status requires root; provide a modeled Uid line
    # while retaining actual /proc start, pidfd, deadline and immutable input reads.
    real_read_text = Path.read_text
    def read_text(path, *args, **kwargs):
        result = real_read_text(path, *args, **kwargs)
        if str(path).startswith('/proc/') and path.name == 'status':
            result = '\n'.join('Uid:\t0\t0\t0\t0' if x.startswith('Uid:') else x
                               for x in result.splitlines())
        return result
    class Kernel(existing.ModelKernel):
        def observation(self):
            self.call('observe')
            return {'namespace': [7, 8], 'snapshots': {
                role: {'links': [], 'addresses': [], 'routes': [], 'rules': []}
                for role in ('host', 'fresh', *m.ROLES)},
                'configSha256': m.digest(m.encode(self.current))}
        def close(self): (root/'effects').write_text(json.dumps(self.calls))
    m.Linux = Kernel
    mode = (root/'mode').read_text() if (root/'mode').exists() else ''
    if mode == 'listen-delay':
        real_chmod = control.os.chmod
        def chmod(path, mode):
            real_chmod(path, mode)
            if path == m.SOCKET: time.sleep(.3)
        control.os.chmod = chmod
    real_send = control.send
    def send(channel, value, module):
        value = copy.deepcopy(value)
        sequence = value.get('sequence', 0)
        if mode == 'ackloss' and sequence:
            channel.close(); raise OSError('MODELED_ACK_LOSS_AFTER_COMMAND')
        if mode == 'input-drift' and sequence:
            (root/'lease').write_bytes((root/'lease').read_bytes()+b' ')
        if mode == 'nested-float': value['observation']['snapshots']['fresh']['links'] = [{'ifindex': 1.0}]
        if mode == 'nested-depth':
            for _ in range(40): value['observation']['snapshots']['fresh']['links'] = [{'x': value['observation']['snapshots']['fresh']['links']}]
        if mode == 'nested-bool-drift': value['observation']['snapshots']['fresh']['links'] = [{'metric': [True if sequence else 1]}]
        if mode == 'bool-version': value['version'] = True
        if mode == 'bool-sequence': value['sequence'] = False
        if mode == 'wrong-sequence': value['sequence'] = 99
        if mode == 'wrong-generation': value['generation'] = 'f'*32
        if mode == 'wrong-phase': value['phase'] = 'cutover'
        if mode == 'go-int': value['operationalGO'] = 0
        if mode == 'go-true': value['operationalGO'] = True
        if mode == 'accepted-int': value['physicalAccepted'] = 0
        if mode == 'namespace-bool': value['observation']['namespace'][0] = True
        if mode == 'snapshot-shape': value['observation']['snapshots']['fresh']['routes'] = {}
        if mode == 'extra': value['COMMIT'] = True
        raw = module.encode(value)
        if mode == 'duplicate-key': raw = b'{"version":1,'+raw[1:]
        if mode == 'nan': raw = raw.replace(b'"version":1', b'"version":NaN')
        if mode == 'utf16': raw = raw.decode().encode('utf-16')
        if mode == 'badutf8': raw = b'\xff'
        frame = struct.pack('!I', len(raw))+raw
        if mode == 'zero': frame = struct.pack('!I', 0)
        if mode == 'oversize': frame = struct.pack('!I', module.LIMIT+1)
        if mode == 'truncated-header': frame = frame[:2]
        if mode == 'truncated-body': frame = frame[:-2]
        if mode == 'eof': frame = b''
        if mode == 'duplicate-frame': frame += frame
        if mode in ('fragment', 'slow-fragment'):
            for index, byte in enumerate(frame):
                channel.sendall(bytes([byte]))
                if mode == 'slow-fragment' and index == 0: time.sleep(3.2)
        else: channel.sendall(frame)
        if mode in ('truncated-header', 'truncated-body', 'eof', 'zero', 'oversize'):
            channel.shutdown(socket.SHUT_WR)
    control.send = send
    real_identity = m.identity
    m.identity = lambda path: real_identity(str(path).replace('/proc/1/ns/', '/proc/self/ns/'))
    try:
        with patch.object(control.os, 'getuid', return_value=0), \
             patch.object(control.os, 'geteuid', return_value=0), \
             patch.object(control.os, 'getgid', return_value=0), \
             patch.object(control.os, 'getegid', return_value=0), \
             patch.object(Path, 'read_text', read_text):
            control.run(m)
        (root/'result').write_text('abandoned')
    except BaseException as exc:
        (root/'result').write_text(type(exc).__name__+':'+str(exc))
        raise


def fixture_client(root):
    """Actual digest-loading entry/main in a distinct PID; parent alone issues lease.

    Only installed ownership/root traversal/host identity are modeled. The actual
    pinned bytes are descriptor-read, hashed, compiled and executed by entry.load.
    """
    root = Path(root); entry = load('fresh_network_client_exec')
    installed = root/'installed'; real_open, real_fstat = os.open, os.fstat
    real_load = entry.load
    failures = []
    class RootStat:
        st_uid = st_gid = 0
        def __init__(self, original): self.original = original
        def __getattr__(self, name): return getattr(self.original, name)
    def checked_load(path):
        def open_source(name, flags, *args, **kwargs):
            return real_open(installed if name == '/' else name, flags, *args, **kwargs)
        with patch.object(entry.os, 'open', side_effect=open_source), \
             patch.object(entry.os, 'fstat', side_effect=lambda fd: RootStat(real_fstat(fd))):
            try:
                module = real_load(path)
            except BaseException as exc:
                os.write(2, ('FIXTURE_LOAD:'+type(exc).__name__+':'+str(exc)+'\n').encode()); raise
        if path.endswith('/c3-test-fresh-network.py'):
            module.INPUT = str(root/'plan'); module.LEASE = str(root/'lease'); module.SOCKET = str(root/'s')
            module.trusted_fd = lambda name, directory=False: real_open(
                installed/name.lstrip('/') if name.startswith('/usr/local/libexec/') else name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if directory else 0))
            module.trusted_read = lambda name: Path(name).read_bytes()
        elif path.endswith('/c3-test-fresh-network-control.py'):
            class Status:
                def __init__(self, *args): self.path = Path(*args)
                def read_text(self):
                    return '\n'.join('Uid:\t0\t0\t0\t0' if x.startswith('Uid:') else x
                                     for x in self.path.read_text().splitlines())
            module.Path = Status
        elif path.endswith('/c3-test-fresh-network-client.py'):
            module._host = lambda network, p, pid, start: network.need(
                pid == os.getpid() and network.proc_start(pid) == start, 'EXACT_REAL_CLIENT_PID_REQUIRED')
            module._root_stat = lambda *args: None
            module._server_host = lambda *args: None
            real_cred = module._peercred
            module._peercred = lambda channel: (real_cred(channel)[0], 0, 0)
            real_run = module.run
            def run(*args):
                try: return real_run(*args)
                except BaseException as exc:
                    failures.append(type(exc).__name__+':'+str(exc)); raise
            module.run = run
        return module
    entry.load = checked_load
    writes = []; sockets = []
    def audit(event, args):
        if event == 'socket.__new__':
            if args[1:3] != (socket.AF_UNIX, socket.SOCK_STREAM): raise AssertionError('ONLY_UNIX_CLIENT_ALLOWED')
            sockets.append(os.getpid())
        if event == 'open' and args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            writes.append(event); raise AssertionError('CLIENT_WRITE_FORBIDDEN')
        if event in ('os.remove', 'os.rename', 'os.mkdir', 'os.kill', 'subprocess.Popen', 'os.fork'):
            writes.append(event); raise AssertionError('CLIENT_EFFECT_FORBIDDEN')
    sys.addaudithook(audit)
    with patch.object(entry.os, 'getresuid', return_value=(0, 0, 0)), \
         patch.object(entry.os, 'getresgid', return_value=(0, 0, 0)), \
         patch.object(entry.sys, 'argv', ['/usr/local/libexec/c3-test-fresh-network-client-exec.py']):
        result = entry.main()
    os.write(2, json.dumps({'writes': writes, 'socketPIDs': sockets, 'errors': failures, 'abandonACK': result == 0}).encode()+b'\n')
    if result: raise SystemExit(result)


def read_line(channel, seconds=4):
    end = time.monotonic()+seconds; raw = bytearray()
    while b'\n' not in raw:
        if not select.select([channel], [], [], max(0, end-time.monotonic()))[0]:
            raise AssertionError('fixture output timeout')
        part = os.read(channel.fileno(), 1)
        if not part: raise AssertionError('fixture premature EOF')
        raw.extend(part)
    return json.loads(raw)


class Harness:
    """Owned local processes/files; only root/host installation facts are modeled."""
    def __init__(self, case, mode='', seconds=8):
        self.case, self.mode, self.seconds = case, mode, seconds
        self.stack = ExitStack(); self.child = None; self.holders = []

    def __enter__(self):
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(
            prefix='nh-', dir='/home/leon/.hermes/cache/scratch/nh')))
        self.case.assertLess(len(os.fsencode(self.root/'s')), 104)
        (self.root/'state').mkdir(); (self.root/'mode').write_text(self.mode)
        self.client = load('fresh_network_client')
        self.p = existing.plan(); self.p['deadline'] = int(time.time())+self.seconds
        self.raw = m.encode(self.p); (self.root/'plan').write_bytes(self.raw)
        self.paths = {m.LIB: HERE/'fresh_network.py',
                      self.client.CONTROL: HERE/'fresh_network_control.py',
                      self.client.SERVER_ENTRY: HERE/'fresh_network_exec.py',
                      self.client.CLIENT: HERE/'fresh_network_client.py'}
        self.client.__source_sha256__ = m.digest(self.paths[self.client.CLIENT].read_bytes())
        installed = self.root/'installed'
        for destination, source in self.paths.items():
            target = installed/destination.lstrip('/'); target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes()); target.chmod(0o644)
            for parent in (installed, installed/'usr', installed/'usr/local', installed/'usr/local/libexec'):
                parent.chmod(0o755)
        def trusted_fd(path, directory=False):
            return os.open(self.paths.get(path, path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                           (os.O_DIRECTORY if directory else 0))
        def host(module, plan, pid, start):
            module.need(module.proc_start(pid) == start, 'REAL_PID_START_REQUIRED')
        def peercred(channel):
            pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            self.case.assertEqual((uid, gid), (os.getuid(), os.getgid()))
            return pid, 0, 0
        class Status:
            def __init__(self, *args): self.path = Path(*args)
            def read_text(self):
                return '\n'.join('Uid:\t0\t0\t0\t0' if x.startswith('Uid:') else x
                                 for x in self.path.read_text().splitlines())
        for obj, name, value in ((m, 'INPUT', str(self.root/'plan')), (m, 'LEASE', str(self.root/'lease')),
                                  (m, 'SOCKET', str(self.root/'s')), (m, 'trusted_fd', trusted_fd),
                                  (m, 'trusted_read', lambda path: Path(path).read_bytes()),
                                  (self.client, '_host', host), (self.client, '_root_stat', lambda *args: None),
                                  (self.client, '_server_host', lambda *args: None),
                                  (self.client, '_peercred', peercred), (control, 'Path', Status)):
            self.stack.enter_context(patch.object(obj, name, value))
        return self

    def lease(self, **changes):
        value = {'version': 1, 'context': m.CONTEXT, 'generation': self.p['generation'],
                 'boot': self.p['boot'], 'planSha256': m.digest(self.raw),
                 'holder': {'pid': os.getpid(), 'start': m.proc_start(os.getpid())},
                 'deadline': self.p['deadline'], 'operations': ['observe', 'cutover', 'return', 'abandon']}
        value.update(changes)
        (self.root/'lease').write_bytes(m.encode(value))
        return value

    def holder(self):
        value = self.client.Holder(m, control); self.holders.append(value)
        return value

    def server(self):
        self.child = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__)), '--server', str(self.root)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return self.child

    def operator(self):
        child = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__)), '--client', str(self.root)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.stack.callback(self.stop_operator, child)
        observation = read_line(child.stdout)
        self.lease(holder=observation['holder']); self.server()
        prepared = read_line(child.stdout)
        self.case.assertEqual(prepared['phase'], 'prepared')
        return child, observation

    @staticmethod
    def stop_operator(child):
        if child.poll() is None: child.kill()
        child.communicate(timeout=3)

    def effects(self):
        if self.child is not None and self.child.poll() is None:
            self.child.communicate(timeout=4)
        return json.loads((self.root/'effects').read_text()) if (self.root/'effects').exists() else []

    def __exit__(self, *exc):
        try:
            for holder in self.holders: holder.close()
            if self.child is not None:
                if self.child.poll() is None:
                    try: self.child.communicate(timeout=4)
                    except subprocess.TimeoutExpired: self.child.kill(); self.child.communicate(timeout=3)
                else: self.child.communicate(timeout=3)
        finally: self.stack.close()


class ClientTests(unittest.TestCase):
    def test_h1_real_single_connection_exact_peer_prepare_observe_abandon(self):
        self.assertTrue((HERE/'fresh_network_client.py').is_file(),
                        'missing finite exact-PID network holder client')
        client = load('fresh_network_client')
        with tempfile.TemporaryDirectory(prefix='nh-', dir='/home/leon/.hermes/cache/scratch/nh') as tmp:
            root = Path(tmp); (root/'state').mkdir()
            self.assertLess(len(os.fsencode(root/'s')), 104)
            p = existing.plan(); p['deadline'] = int(time.time())+8; raw = m.encode(p)
            (root/'plan').write_bytes(raw)
            lease = {'version': 1, 'context': m.CONTEXT, 'generation': p['generation'],
                     'boot': p['boot'], 'planSha256': m.digest(raw),
                     'holder': {'pid': os.getpid(), 'start': m.proc_start(os.getpid())},
                     'deadline': p['deadline'], 'operations': ['observe', 'cutover', 'return', 'abandon']}
            (root/'lease').write_bytes(m.encode(lease))
            child = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__)), '--server', tmp],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                paths = {m.LIB: HERE/'fresh_network.py',
                         client.CONTROL: HERE/'fresh_network_control.py',
                         client.SERVER_ENTRY: HERE/'fresh_network_exec.py',
                         client.CLIENT: HERE/'fresh_network_client.py'}
                def trusted_fd(path, directory=False):
                    return os.open(paths.get(path, path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                                   (os.O_DIRECTORY if directory else 0))
                def host(module, plan, pid, start):
                    module.need(module.proc_start(pid) == start, 'REAL_PID_START_REQUIRED')
                def peercred(channel):
                    pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    self.assertEqual((uid, gid), (os.getuid(), os.getgid()))
                    return pid, 0, 0
                with patch.object(m, 'INPUT', str(root/'plan')), patch.object(m, 'LEASE', str(root/'lease')), \
                     patch.object(m, 'SOCKET', str(root/'s')), patch.object(m, 'trusted_fd', side_effect=trusted_fd), \
                     patch.object(m, 'trusted_read', side_effect=lambda path: Path(path).read_bytes()), \
                     patch.object(client, '_host', side_effect=host), \
                     patch.object(client, '_root_stat'), patch.object(client, '_server_host'), \
                     patch.object(client, '_peercred', side_effect=peercred), \
                     patch.object(control.Lease, 'check', lambda self: m.need(
                         m.proc_start(self.holder['pid']) == self.holder['start'] and
                         Path(m.INPUT).read_bytes() == self.raw_plan and Path(m.LEASE).read_bytes() == self.raw,
                         'MODELED_ROOT_REAL_INPUT_CHECK')):
                    client.__source_sha256__ = m.digest(paths[client.CLIENT].read_bytes())
                    holder = client.Holder(m, control)
                    try:
                        try:
                            result = holder.connect()
                        except BaseException:
                            if child.poll() is not None:
                                _, err = child.communicate(timeout=3)
                                print('SERVER_FIXTURE_ERROR:', err.decode(), file=sys.stderr)
                            raise
                        self.assertEqual(result['phase'], 'prepared')
                        self.assertIs(result['physicalAccepted'], False)
                        self.assertIs(result['operationalGO'], False)
                        self.assertEqual(holder.dispatch('observe')['sequence'], 1)
                        self.assertEqual(holder.dispatch('abandon'), {'phase': 'abandoned', 'operationalGO': False})
                    finally:
                        holder.close()
                stdout, stderr = child.communicate(timeout=4)
                self.assertEqual(child.returncode, 0, stderr.decode())
                self.assertEqual(json.loads((root/'peer').read_text())['pid'], os.getpid())
                self.assertEqual((root/'result').read_text(), 'abandoned')
                effects = json.loads((root/'effects').read_text())
                self.assertIn('create', effects)
                self.assertIn('remove', effects)
                self.assertNotIn('write-config', effects)
            finally:
                if child.poll() is None: child.kill(); child.communicate(timeout=3)


    def test_h2_first_read_atime_is_not_input_mutation(self):
        with Harness(self) as h:
            path = h.root/'first-read'; path.write_bytes(b'independently installed')
            os.utime(path, ns=(1, 2))
            item = h.client.Input(m, str(path))
            try:
                self.assertEqual(item.raw, b'independently installed')
                item.check()
            finally: item.close()

    def test_h4_fixed_finite_pipe_entry_exists(self):
        client = load('fresh_network_client')
        self.assertTrue(callable(getattr(client, 'run', None)),
                        'missing finite exact-PID entry with independent rendezvous')

    def test_h4_distinct_child_rendezvous_cutover_not_terminal_and_zero_authority_writes(self):
        with Harness(self, seconds=15) as h:
            child = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__)), '--client', str(h.root)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                observation = read_line(child.stdout)
                self.assertFalse((h.root/'lease').exists())
                self.assertEqual(observation['holder']['pid'], child.pid)
                self.assertEqual(observation['holder']['start'], m.proc_start(child.pid))
                self.assertIs(observation['accepted'], False)
                deadline = observation['deadline']
                h.lease(holder=observation['holder']); h.server()
                prepared = read_line(child.stdout)
                self.assertEqual(prepared['phase'], 'prepared')
                for op, phase in (('observe', 'prepared'), ('cutover', 'cutover'),
                                  ('return', 'returned'), ('abandon', 'abandoned')):
                    for byte in (op+'\n').encode():
                        child.stdin.write(bytes([byte])); child.stdin.flush()
                    reply = read_line(child.stdout)
                    self.assertEqual(reply['phase'], phase)
                    self.assertIs(reply['operationalGO'], False)
                    if phase == 'cutover': self.assertIsNone(child.poll(), 'cutover must keep SAME holder alive')
                _, stderr = child.communicate(timeout=4)
                self.assertEqual(child.returncode, 0, stderr.decode())
                self.assertEqual(json.loads(stderr), {'writes': [], 'socketPIDs': [child.pid], 'errors': [], 'abandonACK': True})
                self.assertEqual(m.decode((h.root/'lease').read_bytes())['deadline'], deadline)
                self.assertEqual(json.loads((h.root/'peer').read_text())['pid'], child.pid)
                self.assertEqual(h.effects().count('write-config'), 2)
            finally:
                if child.poll() is None: child.kill()
                _, err = child.communicate(timeout=3)
                if child.returncode != 0: print('CLIENT_FIXTURE_ERROR:', err.decode(), file=sys.stderr)

    def test_h1_waits_for_listen_without_using_a_probe_connection(self):
        with Harness(self, 'listen-delay') as h:
            h.lease(); holder = h.holder(); h.server()
            self.assertEqual(holder.connect()['phase'], 'prepared')
            self.assertEqual(holder.dispatch('abandon')['phase'], 'abandoned')

    def test_h8_digest_loading_fixed_entry_is_present(self):
        self.assertTrue((HERE/'fresh_network_client_exec.py').is_file(), 'missing digest-loading fixed entry')
        entry = load('fresh_network_client_exec')
        self.assertEqual(entry.PINS['/usr/local/libexec/c3-test-fresh-network-client.py'],
                         m.digest((HERE/'fresh_network_client.py').read_bytes()))
        child = subprocess.run([sys.executable, '-I', '-B', str(HERE/'fresh_network_client_exec.py'), 'forbidden'],
                               capture_output=True, timeout=3)
        self.assertNotEqual(child.returncode, 0)
        self.assertNotIn(b'Traceback', child.stderr)

    def test_h3_real_reply_fault_matrix_is_sticky_without_next_mutation(self):
        modes = ('zero', 'oversize', 'truncated-header', 'truncated-body', 'eof', 'duplicate-key',
                 'wrong-sequence', 'bool-version', 'bool-sequence', 'wrong-generation', 'wrong-phase',
                 'go-int', 'go-true', 'accepted-int', 'namespace-bool', 'snapshot-shape', 'extra',
                 'duplicate-frame', 'badutf8', 'utf16', 'nan', 'slow-fragment')
        for mode in modes:
            with self.subTest(mode=mode), Harness(self, mode) as h:
                h.lease(); h.server(); holder = h.holder()
                with self.assertRaises((m.Refusal, UnicodeError, TimeoutError)): holder.connect()
                self.assertTrue(holder.attempted); self.assertTrue(holder.failed)
                for op in ('cutover', 'return', 'abandon'):
                    with self.assertRaises(m.Refusal): holder.dispatch(op)
                with self.assertRaises(m.Refusal): holder.connect()
                holder.close()
                self.assertNotIn('write-config', h.effects())
                self.assertNotIn('remove', h.effects())

    def test_h3_fragmented_requests_and_replies_use_same_pid_socket(self):
        with Harness(self, 'fragment') as h:
            h.lease(); h.server(); holder = h.holder()
            self.assertEqual(holder.connect()['phase'], 'prepared')
            real = holder.channel
            class Fragment:
                def __getattr__(self, name): return getattr(real, name)
                def fileno(self): return real.fileno()
                def sendall(self, raw):
                    for byte in raw: real.sendall(bytes([byte]))
            holder.channel = Fragment()
            self.assertEqual(holder.dispatch('observe')['sequence'], 1)
            self.assertEqual(holder.dispatch('abandon')['phase'], 'abandoned')
            holder.close()
            self.assertEqual(json.loads((h.root/'peer').read_text())['pid'], os.getpid())
            self.assertEqual(h.effects().count('create'), 1)

    def test_h4_ack_loss_input_drift_and_recursive_bool_drift_retain_cutover(self):
        for mode in ('ackloss', 'input-drift', 'nested-bool-drift'):
            with self.subTest(mode=mode), Harness(self, mode) as h:
                h.lease(); h.server(); holder = h.holder(); holder.connect()
                with self.assertRaises((m.Refusal, OSError)): holder.dispatch('cutover')
                self.assertEqual(holder.phase, 'unknown-retained')
                for op in ('return', 'abandon', 'cutover'):
                    with self.assertRaises(m.Refusal): holder.dispatch(op)
                holder.close()
                effects = h.effects()
                self.assertEqual(effects.count('write-config'), 1)
                self.assertNotIn('remove', effects)

    def test_h2_foreign_stale_or_nonexact_lease_refuses_before_connect(self):
        with Harness(self) as h:
            valid = h.lease()
        mutations = {'holder': {'pid': os.getpid()+1, 'start': m.proc_start(os.getpid())},
                     'version': True, 'context': 'prod.infograd.online', 'generation': 'f'*32,
                     'boot': '33333333-3333-3333-3333-333333333333', 'planSha256': 'f'*64,
                     'deadline': int(time.time())-1, 'operations': ['observe', 'cutover', 'abandon']}
        for field, value in mutations.items():
            with self.subTest(field=field), Harness(self) as h:
                h.lease(**{field: value}); holder = h.holder()
                with self.assertRaises(m.Refusal): holder.connect()
                self.assertFalse(holder.attempted)
                self.assertEqual(holder.phase, 'unknown-retained')
        for holder_value in ({'pid': True, 'start': '1'}, {'pid': os.getpid(), 'start': '0'},
                             {'pid': os.getpid(), 'start': 1}):
            with self.subTest(holder=holder_value), Harness(self) as h:
                h.lease(holder=holder_value); holder = h.holder()
                with self.assertRaises(m.Refusal): holder.connect()
                self.assertFalse(holder.attempted)

    def test_h2_peer_uid_gid_and_socket_replacement_are_not_adopted(self):
        for wrong in ('uid', 'gid', 'self'):
            with self.subTest(wrong=wrong), Harness(self) as h:
                h.lease(); holder = h.holder(); h.server()
                actual = h.client._peercred
                def credential(channel):
                    pid, uid, gid = actual(channel)
                    return (os.getpid() if wrong == 'self' else pid,
                            1 if wrong == 'uid' else uid, 1 if wrong == 'gid' else gid)
                with patch.object(h.client, '_peercred', side_effect=credential):
                    with self.assertRaises(m.Refusal): holder.connect()
                holder.close()
                self.assertNotIn('remove', h.effects())
        with Harness(self) as h:
            h.lease(); h.server(); holder = h.holder(); holder.connect()
            os.rename(h.root/'s', h.root/'old-s')
            with socket.socket(socket.AF_UNIX) as other:
                other.bind(str(h.root/'s')); os.chmod(h.root/'s', 0o600)
                with self.assertRaises(m.Refusal): holder.dispatch('cutover')
            self.assertEqual(holder.phase, 'unknown-retained')
            holder.close(); self.assertNotIn('write-config', h.effects())

    def test_h2_input_replacement_same_bytes_source_drift_and_dead_pidfd_latch(self):
        for fault in ('plan-replace', 'lease-drift', 'source-drift', 'pidfd-death'):
            with self.subTest(fault=fault), Harness(self) as h:
                # Source checks still read real ordinary inodes, never edit repository bytes.
                source = h.root/'client-copy'; source.write_bytes((HERE/'fresh_network_client.py').read_bytes())
                h.paths[h.client.CLIENT] = source
                h.lease(); h.server(); holder = h.holder(); holder.connect()
                dead = None
                try:
                    if fault == 'plan-replace':
                        (h.root/'replacement').write_bytes(h.raw); os.replace(h.root/'replacement', h.root/'plan')
                    if fault == 'lease-drift': (h.root/'lease').write_bytes((h.root/'lease').read_bytes()+b' ')
                    if fault == 'source-drift': source.write_bytes(source.read_bytes()+b'\n')
                    if fault == 'pidfd-death':
                        dead = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'pass'])
                        fd = os.pidfd_open(dead.pid); dead.wait(timeout=3)
                        os.close(holder.pidfd); holder.pidfd = fd
                    with self.assertRaises(m.Refusal): holder.dispatch('cutover')
                    self.assertTrue(holder.failed)
                    with self.assertRaises(m.Refusal): holder.dispatch('abandon')
                    holder.close(); self.assertNotIn('write-config', h.effects())
                finally:
                    if dead is not None and dead.poll() is None: dead.kill(); dead.wait(timeout=3)

    def test_h4_expiry_does_not_reset_for_missing_lease_or_server(self):
        for lease_present in (False, True):
            with self.subTest(lease_present=lease_present), Harness(self, seconds=1) as h:
                if lease_present: h.lease()
                holder = h.holder(); end = holder.end; begin = time.monotonic()
                with self.assertRaises(m.Refusal): holder.connect()
                self.assertLess(time.monotonic()-begin, 1.5)
                self.assertEqual(holder.end, end)
                self.assertFalse(holder.attempted)
                self.assertEqual(holder.phase, 'unknown-retained')

    def test_h4_close_fault_poison_and_dispose_other_owned_descriptors(self):
        with Harness(self) as h:
            holder = h.holder(); fd = holder.pidfd
            real_close = os.close
            def close(value):
                real_close(value)
                if value == fd: raise OSError('MODELED_CLOSE_ACK_LOSS')
            with patch.object(h.client.os, 'close', side_effect=close):
                with self.assertRaises(OSError): holder.close()
            self.assertEqual(holder.phase, 'unknown-retained')
            for item in holder.inputs:
                with self.assertRaises(OSError): os.fstat(item.fd)
            with self.assertRaises(m.Refusal): holder.dispatch('abandon')

    def test_h4_abandon_ack_allows_servers_normal_later_unlink_not_a_lifetime_claim(self):
        with Harness(self) as h:
            h.lease(); h.server(); holder = h.holder(); holder.connect()
            actual = m.decode
            def decode(raw):
                value = actual(raw)
                if type(value) is dict and value.get('phase') == 'abandoned':
                    h.child.communicate(timeout=3)
                    self.assertEqual(h.child.returncode, 0)
                    self.assertFalse((h.root/'s').exists())
                return value
            with patch.object(m, 'decode', side_effect=decode):
                self.assertEqual(holder.dispatch('abandon')['phase'], 'abandoned')
            holder.close()

    def test_h4_real_idle_heartbeat_keeps_original_absolute_deadline(self):
        with Harness(self, seconds=15) as h:
            child, observation = h.operator()
            start = time.monotonic(); reply = read_line(child.stdout, seconds=12)
            self.assertGreaterEqual(time.monotonic()-start, 9)
            self.assertEqual((reply['phase'], reply['sequence']), ('prepared', 1))
            self.assertEqual(m.decode((h.root/'lease').read_bytes())['deadline'], observation['deadline'])
            child.stdin.write(b'abandon\n'); child.stdin.flush()
            self.assertEqual(read_line(child.stdout)['phase'], 'abandoned')
            _, stderr = child.communicate(timeout=3)
            self.assertEqual(child.returncode, 0, stderr.decode())

    def test_h4_operator_eof_invalid_verb_and_cutover_eof_never_cleanup(self):
        for operation in (b'', b'COMMIT\n', b'observe;\n', b'cutover\n'):
            with self.subTest(operation=operation), Harness(self) as h:
                child, _ = h.operator()
                if operation:
                    child.stdin.write(operation); child.stdin.flush()
                    if operation == b'cutover\n':
                        self.assertEqual(read_line(child.stdout)['phase'], 'cutover')
                        self.assertIsNone(child.poll())
                child.stdin.close(); child.stdin = None
                _, stderr = child.communicate(timeout=3)
                self.assertNotEqual(child.returncode, 0)
                self.assertEqual(json.loads(stderr)['writes'], [])
                self.assertFalse(json.loads(stderr)['abandonACK'])
                effects = h.effects()
                self.assertNotIn('remove', effects)
                self.assertEqual(effects.count('write-config'), int(operation == b'cutover\n'))

    def test_h4_partial_operator_line_has_finite_nonrenewable_bound(self):
        with Harness(self) as h:
            child, _ = h.operator()
            child.stdin.write(b'c'); child.stdin.flush()
            start = time.monotonic(); child.wait(timeout=4.5)
            self.assertGreaterEqual(time.monotonic()-start, 2.5)
            _, stderr = child.communicate(timeout=1)
            self.assertNotEqual(child.returncode, 0)
            self.assertFalse(json.loads(stderr)['abandonACK'])
            self.assertNotIn('write-config', h.effects())
            self.assertNotIn('remove', h.effects())

    def test_h8_loader_refuses_changed_installed_client_before_socket(self):
        with Harness(self) as h:
            target = h.root/'installed/usr/local/libexec/c3-test-fresh-network-client.py'
            target.write_bytes(target.read_bytes()+b'\nraise RuntimeError("MUST_NOT_EXECUTE")\n')
            child = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__)), '--client', str(h.root)],
                                   input=b'', capture_output=True, timeout=3)
            self.assertNotEqual(child.returncode, 0)
            self.assertEqual(child.stdout, b'')
            self.assertNotIn(b'MUST_NOT_EXECUTE', child.stderr)
            self.assertIn(b'INSTALLED_SOURCE_PIN_REQUIRED', child.stderr)
            self.assertIn(b'"socketPIDs": []', child.stderr)

    def test_h5_independent_fixed_resource_plan_consumed_without_selfacceptance(self):
        physical = load('fresh_physical')
        with Harness(self) as h:
            stage = h.root/'resources'; payload = stage/'root'; payload.mkdir(parents=True)
            # Independently selected fixture intent BEFORE creating the payload;
            # never infer an accepted map from a scan or the constructor reply.
            names = (physical.PREPARER, '/usr/local/libexec/c3-test-coordinated-restore.py',
                     '/usr/local/libexec/c3-test-fresh-classic.py', '/runtime/node', '/app/index.js',
                     '/usr/bin/python3', '/etc/classic.json')
            content = {name: ('independent fixture '+name).encode() for name in names}
            accepted = {'version': 1, 'context': physical.CONTEXT,
                        'files': {name: physical.sha(raw) for name, raw in content.items()},
                        'networkNamespace': {'device': 7, 'inode': 8}}
            for name, raw in content.items():
                path = payload/name.lstrip('/'); path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw); path.chmod(0o644)
            for path in [payload, *[x for x in payload.rglob('*') if x.is_dir()]]: path.chmod(0o755)
            planpath = stage/'resource-plan.json'; planpath.write_bytes(physical.encode(accepted))
            real_lstat = Path.lstat
            class RootStat:
                st_uid = st_gid = 0
                def __init__(self, value): self.value = value
                def __getattr__(self, name): return getattr(self.value, name)
            with patch.object(physical, 'INPUT', str(stage)), \
                 patch.object(physical, 'trusted_read', lambda path, *args: Path(path).read_bytes()), \
                 patch.object(physical, 'trusted_open', lambda path, directory=False: os.open(
                     path, os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0))), \
                 patch.object(Path, 'lstat', lambda path: RootStat(real_lstat(path))):
                self.assertEqual(physical.verify_input(), accepted)
                for invalid in (True, 7.0):
                    changed = copy.deepcopy(accepted); changed['networkNamespace']['device'] = invalid
                    planpath.write_bytes(physical.encode(changed))
                    with self.assertRaisesRegex(physical.Refusal, 'INDEPENDENT_NETWORK'): physical.verify_input()
                planpath.write_bytes(physical.encode(accepted))
                (payload/'app/index.js').write_bytes(b'foreign')
                with self.assertRaisesRegex(physical.Refusal, 'RESOURCE_INPUT_CLOSURE_DRIFT'): physical.verify_input()

    def test_h6_h7_no_resume_coordinator_publisher_or_arbitrary_dispatch_surface(self):
        import ast
        forbidden = {'kill', 'killpg', 'fork', 'execv', 'execve', 'system', 'popen', 'Popen',
                     'Coordinator', 'run_prepared', 'serve_fresh_owner', 'restore_scope', 'setns', 'unshare'}
        for name in ('fresh_network_client.py', 'fresh_network_client_exec.py'):
            tree = ast.parse((HERE/name).read_text())
            calls = {x.func.attr if isinstance(x.func, ast.Attribute) else x.func.id
                     for x in ast.walk(tree) if isinstance(x, ast.Call) and isinstance(x.func, (ast.Name, ast.Attribute))}
            self.assertFalse(calls & forbidden)
        client = load('fresh_network_client')
        self.assertEqual(client.OPERATIONS, ('observe', 'cutover', 'return', 'abandon'))
        self.assertEqual(client.SOURCE_PINS[m.LIB], m.digest((HERE/'fresh_network.py').read_bytes()))
        self.assertEqual(client.SOURCE_PINS[client.CONTROL], m.digest((HERE/'fresh_network_control.py').read_bytes()))

    def test_h3_recursive_reply_types_and_depth_fail_sticky(self):
        for mode in ('nested-float', 'nested-depth'):
            with self.subTest(mode=mode), Harness(self, mode) as h:
                h.lease(); h.server(); holder = h.holder()
                with self.assertRaises(m.Refusal): holder.connect()
                self.assertEqual(holder.phase, 'unknown-retained')
                for op in ('observe', 'cutover', 'return', 'abandon'):
                    with self.assertRaises(m.Refusal): holder.dispatch(op)
                holder.close()
                self.assertNotIn('remove', h.effects())


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--server': fixture_server(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == '--client': fixture_client(sys.argv[2])
    else: unittest.main()
