#!/usr/bin/python3 -I -B
"""Throwaway Linux kernel feasibility probe. No Docker, IP sockets or privileges.

Run: /usr/bin/python3 -I -B spikes/test-lifecycle-vnext/kernel_probe.py
Only private AF_UNIX endpoints and exact disposable children are affected.
This is NOT a lifecycle implementation or a namespace/cgroup isolation test.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time


class Drift(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise Drift(reason)


def ident(st):
    return [st.st_dev, st.st_ino]


def frame(sock, value):
    sock.sendall(json.dumps(value, sort_keys=True).encode() + b'\n')


def receive(sock):
    raw = bytearray()
    while not raw.endswith(b'\n'):
        part = sock.recv(1)
        if not part:
            raise RuntimeError('CONTROL_EOF')
        raw.extend(part)
        if len(raw) > 8192:
            raise RuntimeError('FRAME_LIMIT')
    return json.loads(raw)


def owned_child(path, control_fd):
    """Real disposable server; command acknowledgements follow actual changes."""
    control = socket.socket(fileno=control_fd)
    control.settimeout(5)
    listener = None

    def listen():
        new = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        new.bind(path)
        new.listen(4)
        new.settimeout(2)
        return new

    try:
        listener = listen()
        frame(control, {'pid': os.getpid(), 'fd': listener.fileno()})
        while True:
            ready, _, _ = select.select([control, listener], [], [], 5)
            if not ready:
                return 3
            if control in ready:
                command = receive(control)['command']
                if command == 'exit':
                    frame(control, {'exiting': True})
                    return 0
                if command not in ('rotate', 'replace-same-fd'):
                    return 4
                # Allocate replacement before closing old FD: no socket-inode
                # reuse can accidentally make the negative test pass.
                os.unlink(path)
                new = listen()
                old_fd = listener.fileno()
                listener.close()
                if command == 'replace-same-fd':
                    os.dup2(new.fileno(), old_fd, inheritable=False)
                    listener = socket.socket(fileno=old_fd)
                    new.close()
                else:
                    listener = new
                frame(control, {'rotated': True, 'fd': listener.fileno()})
            if listener in ready:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(2)
                    try:
                        frame(conn, receive(conn))  # real bytes, not identity authority
                    except (OSError, RuntimeError):
                        # A rejected peer may disconnect before sending a frame.
                        pass
    finally:
        if listener is not None:
            listener.close()
        control.close()


class Child:
    def __init__(self, path):
        self.path = str(path)
        self.control, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.control.settimeout(3)
        self.p = subprocess.Popen(
            [sys.executable, '-I', '-B', str(Path(__file__).resolve()),
             '--owned-child', self.path, str(remote.fileno())],
            pass_fds=(remote.fileno(),), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        remote.close()
        # Open once for the exact child, while Popen still owns its wait status.
        self.pidfd = os.pidfd_open(self.p.pid)
        self.ready = receive(self.control)
        need(self.ready['pid'] == self.p.pid, 'CHILD_HANDSHAKE_PID')

    def command(self, command):
        frame(self.control, {'command': command})
        return receive(self.control)

    def terminate_exact(self):
        # Never numeric kill, killpg, or a PID obtained from external input.
        if self.p.poll() is None:
            signal.pidfd_send_signal(self.pidfd, signal.SIGTERM)

    def close(self):
        try:
            if self.p.poll() is None:
                try:
                    self.command('exit')
                    self.p.wait(timeout=2)
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    self.terminate_exact()
                    self.p.wait(timeout=2)
        finally:
            self.control.close()
            os.close(self.pidfd)
            if self.p.stderr is not None:
                self.p.stderr.close()


class Pin:
    """Owned-FD observation, not authority to adopt or stop an arbitrary process.

    Numeric PID only bootstraps a proc dirfd while the exact owned pidfd is live.
    Subsequent /proc reads are relative to that retained directory, not PID lookup.
    Before/after liveness is NOT atomic exclusion: production needs a writer fence.
    """
    def __init__(self, child):
        self.child = child
        self.fds = []
        try:
            self.capture(child)
        except BaseException:
            self.close()
            raise

    def capture(self, child):
        self.pidfd = self.hold(os.dup(child.pidfd))
        self.alive()
        self.proc = self.hold(os.open('/proc/' + str(child.p.pid),
                                     os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))
        self.ns = {n: self.hold(os.open('ns/' + n, os.O_RDONLY | os.O_CLOEXEC,
                                      dir_fd=self.proc))
                   for n in ('net', 'mnt', 'pid', 'user')}
        self.exe = self.hold(os.open('exe', os.O_PATH | os.O_CLOEXEC, dir_fd=self.proc))
        self.cgroup_text = self.read('cgroup').decode().strip()
        need(self.cgroup_text.startswith('0::/'), 'UNIFIED_CGROUP_REQUIRED')
        cgpath = self.cgroup_text[3:]
        need('..' not in Path(cgpath).parts, 'CGROUP_NAMESPACE_PATH_UNRESOLVED')
        # Host-visible cgroup v2 is a prerequisite, not silently synthesized.
        self.cgpath = Path('/sys/fs/cgroup') / cgpath.lstrip('/')
        self.cgfd = self.hold(os.open(self.cgpath, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))
        self.sockfd = child.ready['fd']
        self.baseline = self.snapshot()
        self.alive()

    def hold(self, fd):
        self.fds.append(fd)
        return fd

    def read(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC, dir_fd=self.proc)
        try:
            chunks = []
            while True:
                part = os.read(fd, 65536)
                if not part:
                    return b''.join(chunks)
                chunks.append(part)
        finally:
            os.close(fd)

    def alive(self):
        need(not select.select([self.pidfd], [], [], 0)[0], 'PINNED_PROCESS_EXITED')

    def snapshot(self):
        self.alive()
        rawstat = self.read('stat').decode()
        start = rawstat[rawstat.rindex(')') + 2:].split()[19]
        ns = {n: ident(os.stat('ns/' + n, dir_fd=self.proc)) for n in self.ns}
        need(ns == {n: ident(os.fstat(fd)) for n, fd in self.ns.items()}, 'NAMESPACE_DRIFT')
        need(ident(os.stat('exe', dir_fd=self.proc)) == ident(os.fstat(self.exe)), 'EXECUTABLE_DRIFT')
        need(self.read('cgroup').decode().strip() == self.cgroup_text, 'CGROUP_MEMBERSHIP_DRIFT')
        need(ident(os.stat(self.cgpath)) == ident(os.fstat(self.cgfd)), 'CGROUP_PATH_DRIFT')
        owned_socket = os.readlink('fd/' + str(self.sockfd), dir_fd=self.proc)
        need(owned_socket.startswith('socket:['), 'OWNED_SOCKET_DRIFT')
        pathst = os.lstat(self.child.path)
        need(stat.S_ISSOCK(pathst.st_mode), 'ENDPOINT_TYPE_DRIFT')
        result = {'pid': self.child.p.pid, 'start_ticks': start, 'namespaces': ns,
                  'exe': ident(os.fstat(self.exe)), 'cgroup': self.cgroup_text,
                  'cgroup_directory': ident(os.fstat(self.cgfd)),
                  'mountinfo_sha256': hashlib.sha256(self.read('mountinfo')).hexdigest(),
                  'socket_fd': self.sockfd, 'socket_link': owned_socket,
                  'endpoint_path_identity': ident(pathst)}
        self.alive()
        return result

    def check(self):
        try:
            current = self.snapshot()
        except FileNotFoundError:
            self.alive()
            raise Drift('OWNED_SOCKET_DRIFT') from None
        for key, value in self.baseline.items():
            need(current[key] == value, 'PIN_DRIFT:' + key)
        return current

    def endpoint(self):
        self.alive()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(2)
            conn.connect(self.child.path)
            peer = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            need(peer == (self.child.p.pid, os.getuid(), os.getgid()), 'ENDPOINT_PEER_DRIFT')
            self.check()
            challenge = {'nonce': os.urandom(16).hex()}
            frame(conn, challenge)
            need(receive(conn) == challenge, 'ENDPOINT_BYTES_DRIFT')
            self.check()
            return {'peer_pid': peer[0], 'peer_uid': peer[1], 'peer_gid': peer[2],
                    'actual_echo_verified': True}

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


def refused(call, expected):
    try:
        call()
    except Drift as error:
        need(str(error) == expected, 'WRONG_REFUSAL:' + str(error))
        return {'expected_refusal': expected, 'observed_refusal': str(error)}
    raise AssertionError('DRIFT_WAS_ACCEPTED')


def run():
    scratch = Path('/home/leon/.hermes/cache/scratch')
    need(Path(os.environ.get('TMPDIR', '')) == scratch, 'CONFIGURED_SCRATCH_REQUIRED')
    need(scratch.is_dir(), 'SCRATCH_MISSING')
    original_fds = set(os.listdir('/proc/self/fd'))
    tests = []
    with tempfile.TemporaryDirectory(prefix='c3-vnext-', dir=scratch) as tmp:
        path = Path(tmp) / 'app.sock'
        children, pins = [], []
        try:
            child = Child(path)
            children.append(child)
            pin = Pin(child)
            pins.append(pin)
            observed = pin.check()
            tests.append({'name': 'valid_pinned_proc_and_endpoint', 'status': 'pass',
                          'observation': observed, 'connection': pin.endpoint()})
            child.command('rotate')
            tests.append({'name': 'same_process_socket_fd_drift', 'status': 'pass',
                          **refused(pin.check, 'OWNED_SOCKET_DRIFT')})
            # New pin is only a test setup, NOT production drift recovery/adoption.
            child.ready['fd'] = child.command('rotate')['fd']
            stable = Pin(child)
            pins.append(stable)
            stable.check()
            need(child.command('replace-same-fd')['fd'] == stable.sockfd,
                 'SAME_FD_TEST_SETUP_FAILED')
            tests.append({'name': 'same_pid_same_fd_listener_inode_drift', 'status': 'pass',
                          **refused(stable.check, 'PIN_DRIFT:socket_link')})
            stable = Pin(child)  # independent negative-test setup, never recovery
            pins.append(stable)
            os.unlink(path)
            foreign = Child(path)  # same executable, UID and response; different PID
            children.append(foreign)
            tests.append({'name': 'same_label_foreign_endpoint_rejected', 'status': 'pass',
                          **refused(stable.endpoint, 'ENDPOINT_PEER_DRIFT')})
            child.terminate_exact()
            need(child.p.wait(timeout=2) == -signal.SIGTERM, 'EXACT_CHILD_STOP_FAILED')
            need(select.select([stable.pidfd], [], [], 1)[0], 'PIDFD_NOT_READABLE_AFTER_EXIT')
            tests.append({'name': 'dead_pinned_process_rejected', 'status': 'pass',
                          **refused(stable.check, 'PINNED_PROCESS_EXITED')})
            need(foreign.p.poll() is None, 'FOREIGN_CHILD_WAS_SIGNALED')
            survivor = Pin(foreign)
            pins.append(survivor)
            tests.append({'name': 'pidfd_stop_only_exact_owned_child', 'status': 'pass',
                          'stopped_pid': child.p.pid, 'stopped_exit': child.p.returncode,
                          'other_owned_child_alive': True, 'survivor': survivor.endpoint()})
            foreign.command('exit')
            need(foreign.p.wait(timeout=2) == 0, 'NATURAL_CHILD_EXIT_FAILED')
            tests.append({'name': 'disposable_server_natural_exit', 'status': 'pass', 'exit': 0})
        finally:
            for pin in reversed(pins):
                pin.close()
            for child in reversed(children):
                child.close()
            need(all(child.p.poll() is not None for child in children), 'CHILD_NOT_REAPED')
    need(not Path(tmp).exists(), 'SCRATCH_NOT_REMOVED')
    need(set(os.listdir('/proc/self/fd')) == original_fds, 'OBSERVER_FD_LEAK')
    return {'schema': 'c3-test-lifecycle-vnext-kernel-spike/1', 'status': 'pass',
            'full_lifecycle_implemented': False, 'simulated_tests': [],
            'real_primitives': ['proc-dirfd', 'pidfd_open', 'pidfd_send_signal(SIGTERM)',
                                'retained-namespace-fds', 'retained-cgroup-dirfd',
                                'retained-exe-fd', 'AF_UNIX', 'SO_PEERCRED'],
            'not_tested': ['private namespaces', 'exclusive cgroup', 'EMPTY namespace',
                           'TCP/Caddy endpoint binding', 'freeze', 'restart policy',
                           'durable owner transfer', 'application', 'Xray/PPP E2E'],
            'scratch_removed': True, 'owned_children_reaped': True,
            'observer_fd_leak': False, 'tests': tests}


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--owned-child':
        raise SystemExit(owned_child(sys.argv[2], int(sys.argv[3])))
    if len(sys.argv) != 1:
        raise SystemExit('No public arguments; run the fixed local probe.')
    started = time.monotonic_ns()
    try:
        result = run()
        code = 0
    except Exception as error:
        result = {'schema': 'c3-test-lifecycle-vnext-kernel-spike/1', 'status': 'failed',
                  'error_type': type(error).__name__, 'error': str(error),
                  'full_lifecycle_implemented': False}
        code = 1
    result['duration_ns'] = time.monotonic_ns() - started
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    raise SystemExit(code)
