#!/usr/bin/python3
"""Attach-only PROD guard for an independently accepted, PRE-FROZEN universe.

No cgroup/systemd/remote writes exist. The operator must exclude every old writer
and every future dispatch source BEFORE this process starts. This checker never
infers completeness from its inventory. Frozen scopes remain frozen on disposal.
"""
import array
import ctypes
import fcntl
import importlib.util
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time

_spec = importlib.util.spec_from_file_location('_prod_authority_codec', Path(__file__).with_name('authority_helper.py'))
_codec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_codec)
need, exact, decode, canonical, trusted, private_read, sha = (
    _codec.need, _codec.exact, _codec.decode, _codec.canonical, _codec.trusted, _codec.private_read, _codec.sha)
POLICY = Path('/etc/celerity/prod-admission-exclusion.json')


def require_cgroup2(fd):
    # Linux statfs starts with a native signed long f_type. Oversized aligned
    # buffer covers the remaining ABI fields without guessing their layout.
    buffer = (ctypes.c_long * 64)()
    libc = ctypes.CDLL(None, use_errno=True)
    need(libc.fstatfs(fd, ctypes.byref(buffer)) == 0 and buffer[0] == 0x63677270)


_MASK_STATE = {'LoadState': 'masked', 'UnitFileState': 'masked', 'ActiveState': 'inactive',
               'SubState': 'dead', 'MainPID': '0', 'ControlPID': '0'}


def _properties(unit):
    result = subprocess.run(['/usr/bin/systemctl', 'show', '--no-pager',
                             '--property=' + ','.join(['Id', 'ControlGroup', *_MASK_STATE]), '--', unit],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=1, check=True, env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'})
    pairs = [line.split('=', 1) for line in result.stdout.decode('ascii').splitlines()]
    need(len(pairs) == len(_MASK_STATE) + 2 and all(len(x) == 2 for x in pairs))
    return dict(pairs)


def check_masked_writer(pin, root, cgroup_root, uid, properties=_properties):
    # A mask prevents future starts. Neither it nor an empty cgroup alone
    # establishes that an already running writer has stopped.
    need(exact(pin, 'unit cgroup') and isinstance(pin['unit'], str)
         and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,179}\.service', pin['unit'])
         and pin['cgroup'] == '/system.slice/' + pin['unit'])
    unit = pin['unit']
    directory = trusted(root / 'etc/systemd/system', uid, root)
    mask = directory / unit
    st = mask.lstat()
    need(st.st_uid == uid and stat.S_ISLNK(st.st_mode) and os.readlink(mask) == '/dev/null')
    state = properties(unit)
    need(state == {'Id': unit, 'ControlGroup': state.get('ControlGroup'), **_MASK_STATE}
         and state['ControlGroup'] in ('', pin['cgroup']))
    parent = trusted(cgroup_root / 'system.slice', uid, cgroup_root)
    group = parent / unit
    try:
        fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        need(state['ControlGroup'] == '')
        return
    try:
        if cgroup_root == Path('/sys/fs/cgroup'):
            require_cgroup2(fd)
        with os.fdopen(os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)) as events:
            need(dict(line.split() for line in events).get('populated') == '0')
        original, current = os.fstat(fd), group.lstat()
        need((original.st_dev, original.st_ino) == (current.st_dev, current.st_ino))
    finally:
        os.close(fd)


def check_runtime_peer(conn, pidfd):
    # The reconnectable contract is private to the installed runtime observer,
    # never the finite admission/initialization helper. Pin the actual Unix
    # connecting task (SO_PEERPIDFD), not a reopened historical PID.
    pid, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(pid > 1 and uid == 0 and not select.select([pidfd], [], [], 0)[0])
    proc = Path('/proc') / str(pid)
    script = '/usr/local/libexec/c3-production-physical.py'
    trusted(script)
    need(proc.joinpath('cmdline').read_bytes() == b'/usr/bin/python3\0-I\0-B\0' + os.fsencode(script) + b'\0'
         and os.path.samefile(proc / 'exe', '/usr/bin/python3')
         and not select.select([pidfd], [], [], 0)[0])


class ExclusionGuard:
    def __init__(self, policy, *, owner_uid=0, trusted_root=Path('/'),
                 cgroup_root=Path('/sys/fs/cgroup'), allow_empty_for_test=False):
        self.policy = decode(canonical(policy))
        self.uid, self.root, self.cgroup_root = owner_uid, Path(trusted_root), Path(cgroup_root)
        self.poisoned, self.closed, self.lock, self.journal = False, False, None, None
        self.empty_test = allow_empty_for_test
        self.listener = None
        try:
            need(type(policy.get('version')) is int and policy['version'] in (1, 2))
            runtime = policy['version'] == 2
            inventory = 'maskedWriters' if runtime else 'scopes'
            need(exact(policy, 'version generation holderId bootId challengeSha256 lock journal socket ' + inventory)
                 and all(_codec.uuid_ok(policy[k]) for k in ('generation', 'holderId', 'bootId'))
                 and isinstance(policy['challengeSha256'], str) and re.fullmatch('[a-f0-9]{64}', policy['challengeSha256'])
                 and isinstance(policy[inventory], list) and 1 <= len(policy[inventory]) <= 64
                 and len({pin['unit' if runtime else 'path'] for pin in policy[inventory]}) == len(policy[inventory]))
            for name in ('lock', 'journal', 'socket'):
                trusted(Path(policy[name]).parent, self.uid, self.root, private=True)
            self.journal = os.open(policy['journal'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            self._record()
            self.lock = os.open(policy['lock'], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # exactly ONE acquisition for lifetime
            self.check()
        except BaseException as primary:
            try:
                self.close()
            except BaseException as cleanup:
                primary.cleanup_errors = [*getattr(primary, 'cleanup_errors', []), cleanup]
            raise

    def _record(self):
        raw = canonical({'version': self.policy['version'], 'generation': self.policy['generation'],
                         'holderId': self.policy['holderId'], 'state': 'unknown-retained'}) + b'\n'
        need(os.write(self.journal, raw) == len(raw))
        os.fsync(self.journal)
        fd = os.open(Path(self.policy['journal']).parent, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def check(self):
        try:
            need(not self.closed and not self.poisoned
                 and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == self.policy['bootId'])
            if self.policy['version'] == 2:
                for pin in self.policy['maskedWriters']:
                    check_masked_writer(pin, self.root, self.cgroup_root, self.uid)
                return
            for pin in self.policy['scopes']:
                need(exact(pin, 'path device inode processes'))
                group = trusted(pin['path'], self.uid, self.cgroup_root)
                if self.cgroup_root == Path('/sys/fs/cgroup'):
                    fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        require_cgroup2(fd)
                    finally:
                        os.close(fd)
                st = group.stat()
                need((st.st_dev, st.st_ino) == (pin['device'], pin['inode'])
                     and group.joinpath('cgroup.freeze').read_text() == '1\n'
                     and dict(line.split() for line in group.joinpath('cgroup.events').read_text().splitlines()).get('frozen') == '1'
                     and isinstance(pin['processes'], list) and (pin['processes'] or self.empty_test))
                expected = {}
                for process in pin['processes']:
                    need(exact(process, 'pid startTicks') and type(process['pid']) is int and process['pid'] > 1
                         and isinstance(process['startTicks'], str) and re.fullmatch('[0-9]+', process['startTicks'])
                         and process['pid'] not in expected)
                    expected[process['pid']] = process['startTicks']
                actual = set()
                files = list(group.rglob('cgroup.procs'))
                need(0 < len(files) <= 4096)
                for file in files:
                    trusted(file, self.uid, self.cgroup_root)
                    pids = file.read_text().split()
                    need(len(pids) <= 4096)
                    actual.update(int(pid) for pid in pids)
                need(actual == set(expected))
                for pid, start in expected.items():
                    proc = Path('/proc') / str(pid)
                    need(proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19] == start)
                    membership = proc.joinpath('cgroup').read_text().strip()
                    relative = '/' + str(group.relative_to(self.cgroup_root))
                    need(membership == '0::' + relative or membership.startswith('0::' + relative + '/'))
                need(group.joinpath('cgroup.freeze').read_text() == '1\n')
        except BaseException:
            self.poisoned = True  # repaired observations NEVER revive authority
            raise

    def serve_connection(self, conn):
        try:
            return self._serve_connection(conn)
        except BaseException:
            self.poisoned = True
            raise

    def _serve_connection(self, conn):
        buffer = b''
        attached, frame_started = False, None
        while True:
            self.check()
            need(frame_started is None or time.monotonic() - frame_started < 2)
            if not select.select([conn], [], [], 0.1)[0]:
                continue
            chunk = conn.recv(8192)
            if not chunk:
                need(not buffer)
                return  # EOF closes observer only, not this guard's lock/freeze
            if frame_started is None:
                frame_started = time.monotonic()
            buffer += chunk
            need(len(buffer) <= _codec.LIMIT)
            if b'\n' not in buffer:
                continue
            need(buffer.endswith(b'\n') and buffer.count(b'\n') == 1)
            request = decode(buffer)
            buffer = b''
            need(exact(request, 'version nonce verb generation holderId challengeSha256')
                 and type(request['version']) is int and request['version'] == 1 and isinstance(request['nonce'], str)
                 and re.fullmatch('[a-f0-9]{64}', request['nonce'])
                 and request['verb'] in ('attach', 'check', 'retain')
                 and all(request[key] == self.policy[key] for key in ('generation', 'holderId', 'challengeSha256')))
            need(self.policy['version'] == 1 or request['verb'] != 'retain')
            need((request['verb'] == 'attach') != attached)
            attached = True
            frame_started = None
            self.check()
            reply = canonical({**request, 'state': 'held-retained'}) + b'\n'
            if request['verb'] == 'attach':
                need(conn.sendmsg([reply], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [self.lock]))]) == len(reply))
            else:
                conn.sendall(reply)
            self.check()

    def serve_runtime_observer(self, conn):
        # Linux SO_PEERPIDFD; no numeric-PID fallback on older kernels.
        fd = conn.getsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_PEERPIDFD', 77))
        try:
            os.set_inheritable(fd, False)
            check_runtime_peer(conn, fd)
            self.serve_connection(conn)
            # Clean socket EOF alone does not mean the helper (or its copy of
            # the flock FD) has exited. Never accept concurrently with it.
            while not select.select([fd], [], [], 0.1)[0]:
                self.check()
            self.check()
        finally:
            os.close(fd)

    def serve(self):
        # No unlink/rebind recovery: an existing socket/journal is never adopted.
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(self.policy['socket'])
        os.chmod(self.policy['socket'], 0o600)
        self.listener.listen(1)
        self.listener.settimeout(0.1)
        used = False
        while True:
            try:
                self.check()
                try:
                    conn, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(2)
                    if self.policy['version'] == 2:
                        self.serve_runtime_observer(conn)
                    else:
                        need(not used)
                        used = True  # v1 maintenance is strictly one-use
                        self.serve_connection(conn)
            except BaseException:
                self.poisoned = True
                # Remain resident with actual OFD retained after ambiguity.
                # Never busy-spin and never try to repair/reacquire/rearm.
                while True:
                    time.sleep(1)

    def close(self):
        if self.closed:
            return
        self.closed = True
        errors = []
        for name in ('listener', 'lock', 'journal'):
            resource = getattr(self, name)
            setattr(self, name, None)
            if resource is not None:
                try:
                    resource.close() if name == 'listener' else os.close(resource)
                except BaseException as error:
                    errors.append(error)
        # cgroup.freeze is NEVER written, sockets/journals/locks NEVER removed.
        if errors:
            raise _codec.Refusal()


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        return 1
    guard = None
    try:
        guard = ExclusionGuard(decode(private_read(POLICY)))
        guard.serve()
    except BaseException:
        return 1
    finally:
        if guard:
            guard.close()


if __name__ == '__main__':
    sys.exit(main())
