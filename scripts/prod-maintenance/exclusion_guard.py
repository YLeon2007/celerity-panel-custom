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


class ExclusionGuard:
    def __init__(self, policy, *, owner_uid=0, trusted_root=Path('/'),
                 cgroup_root=Path('/sys/fs/cgroup'), allow_empty_for_test=False):
        self.policy = decode(canonical(policy))
        self.uid, self.root, self.cgroup_root = owner_uid, Path(trusted_root), Path(cgroup_root)
        self.poisoned, self.closed, self.lock, self.journal = False, False, None, None
        self.empty_test = allow_empty_for_test
        self.listener = None
        try:
            need(exact(policy, 'version generation holderId bootId challengeSha256 scopes lock journal socket')
                 and type(policy['version']) is int and policy['version'] == 1 and _codec.uuid_ok(policy['generation'])
                 and _codec.uuid_ok(policy['holderId']) and _codec.uuid_ok(policy['bootId'])
                 and isinstance(policy['challengeSha256'], str) and re.fullmatch('[a-f0-9]{64}', policy['challengeSha256'])
                 and isinstance(policy['scopes'], list) and 1 <= len(policy['scopes']) <= 64
                 and len({pin['path'] for pin in policy['scopes']}) == len(policy['scopes']))
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
        raw = canonical({'version': 1, 'generation': self.policy['generation'],
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
                    need(not used)
                    used = True  # no reattach/retry, even after a clean observer EOF
                    conn.settimeout(2)
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
