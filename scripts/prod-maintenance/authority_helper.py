#!/usr/bin/python3
"""Fixed PROD held-exclusion broker; NEVER arms, unlocks, thaws or resumes.

Root must independently install/accept the guard and its exclusion scope. Guard
channels outlive this broker and EOF MUST NOT release their physical fences.
This protocol transfers the guard's existing flock OFD, not a new acquisition.
"""
import array
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import sys
import time
import uuid

POLICY = Path('/etc/celerity/prod-admission-maintenance.json')
LIMIT = 131072
CODE = 'PROD_MAINTENANCE_UNKNOWN_RETAINED'


class Refusal(Exception):
    def __init__(self):
        super().__init__(CODE)


def need(ok):
    if not ok:
        raise Refusal()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(obj, keys):
    return isinstance(obj, dict) and set(obj) == set(keys.split())


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result)
            result[key] = value
        return result
    def invalid(_):
        raise Refusal()
    need(len(raw) <= LIMIT)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def trusted(path, uid=0, root=Path('/'), private=False):
    path, root = Path(path), Path(root)
    need(path.is_absolute() and str(path) == os.path.normpath(path)
         and (path == root or root in path.parents))
    current = path
    while True:
        st = current.lstat()
        need(st.st_uid == uid and not st.st_mode & 0o022 and not stat.S_ISLNK(st.st_mode))
        if current == path and private:
            need(not st.st_mode & 0o077)
        if current == root:
            break
        current = current.parent
    return path


def private_read(path, uid=0, root=Path('/')):
    path = trusted(path, uid, root, private=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_size <= LIMIT
             and (st.st_dev, st.st_ino) == (path.lstat().st_dev, path.lstat().st_ino))
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(LIMIT + 1)
        need(len(raw) <= LIMIT)
        return raw
    finally:
        os.close(fd)


def uuid_ok(value):
    return isinstance(value, str) and str(uuid.UUID(value)) == value


class HeldAuthority:
    def __init__(self, policy, *, owner_uid=0, trusted_root=Path('/')):
        self.policy = decode(canonical(policy))
        self.uid, self.root = owner_uid, Path(trusted_root)
        self.guards, self.closed, self.poisoned = [], False, False
        self.unknown, self.completed = False, False
        self.journal = None
        self.deadline = time.monotonic() + policy.get('lifetimeMs', 0) / 1000
        try:
            need(exact(policy, 'version generation challenge bootId guards journal lifetimeMs')
                 and type(policy['version']) is int and policy['version'] == 1 and uuid_ok(policy['generation'])
                 and policy['challenge'].get('serverContext') == {'target': 'production', 'hostIdentity': 'lm1.infograd.online'}
                 and type(policy['lifetimeMs']) is int and 100 <= policy['lifetimeMs'] <= 300000
                 and uuid_ok(policy['bootId'])
                 and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == policy['bootId']
                 and isinstance(policy['guards'], list) and 1 <= len(policy['guards']) <= 32)
            self.challenge_sha = sha(canonical(policy['challenge']))
            need(len({p['socket'] for p in policy['guards']}) == len(policy['guards'])
                 and len({p['holderId'] for p in policy['guards']}) == len(policy['guards']))
            journal = Path(policy['journal'])
            trusted(journal.parent, self.uid, self.root, private=True)
            self.journal = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            self._record('unknown-retained')  # fsync before any capability request
            for pin in policy['guards']:
                need(exact(pin, 'socket pid startTicks executableSha256 argvSha256 holderId lock sources')
                     and type(pin['pid']) is int and pin['pid'] > 1
                     and isinstance(pin['startTicks'], str) and re.fullmatch(r'[0-9]+', pin['startTicks'])
                     and uuid_ok(pin['holderId'])
                     and all(isinstance(pin[k], str) and re.fullmatch(r'[a-f0-9]{64}', pin[k])
                             for k in ('executableSha256', 'argvSha256'))
                     and exact(pin['lock'], 'path device inode')
                     and isinstance(pin['sources'], list) and 1 <= len(pin['sources']) <= 8
                     and len({entry['path'] for entry in pin['sources']}) == len(pin['sources']))
                if self.root == Path('/'):
                    need([entry['path'] for entry in pin['sources']] == [
                        '/usr/local/libexec/c3-prod-maintenance/authority_helper.py',
                        '/usr/local/libexec/c3-prod-maintenance/exclusion_guard.py'])
                    need(Path(f'/proc/{pin["pid"]}/cmdline').read_bytes() ==
                         b'/usr/bin/python3.13\x00-I\x00/usr/local/libexec/c3-prod-maintenance/exclusion_guard.py\x00')
                trusted(pin['socket'], self.uid, self.root)
                need(stat.S_ISSOCK(Path(pin['socket']).lstat().st_mode))
                trusted(pin['lock']['path'], self.uid, self.root)
                guard = {'pin': pin, 'socket': socket.socket(socket.AF_UNIX), 'fd': None, 'pidfd': None}
                self.guards.append(guard)
                guard['socket'].settimeout(self.remaining())
                guard['socket'].connect(pin['socket'])
                pid, uid, _gid = struct.unpack('3i', guard['socket'].getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                need(uid == self.uid and pid == pin['pid'])
                guard['pidfd'] = os.pidfd_open(pid, 0)
                self._identity(guard)
                self._exchange(guard, 'attach', receive_fd=True)
                self._identity(guard)
        except BaseException as primary:
            self.poisoned = True
            try:
                self._dispose()
            except BaseException as cleanup:
                primary.cleanup_errors = [*getattr(primary, 'cleanup_errors', []), cleanup]
            raise

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        need(remaining > 0 and not self.closed and not self.poisoned)
        return min(remaining, 2.0)

    def _record(self, state):
        raw = canonical({'version': 1, 'generation': self.policy['generation'],
                         'challengeSha256': self.challenge_sha, 'state': state}) + b'\n'
        os.lseek(self.journal, 0, os.SEEK_SET)
        written = os.write(self.journal, raw)
        need(written == len(raw))
        os.ftruncate(self.journal, len(raw))
        os.fsync(self.journal)
        directory = os.open(Path(self.policy['journal']).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _identity(self, guard):
        self.remaining()
        pin = guard['pin']
        need(not select.select([guard['pidfd']], [], [], 0)[0])
        base = Path('/proc') / str(pin['pid'])
        need(base.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19] == pin['startTicks']
             and sha(base.joinpath('exe').read_bytes()) == pin['executableSha256']
             and sha(base.joinpath('cmdline').read_bytes()) == pin['argvSha256'])
        for entry in pin['sources']:
            need(exact(entry, 'path sha256') and isinstance(entry['sha256'], str)
                 and re.fullmatch('[a-f0-9]{64}', entry['sha256'])
                 and sha(private_read(entry['path'], self.uid, self.root)) == entry['sha256'])
        trusted(pin['socket'], self.uid, self.root)
        # Socket pathname replacement is not a new acceptable guard.
        socket_st = Path(pin['socket']).lstat()
        identity = (socket_st.st_dev, socket_st.st_ino)
        need(guard.setdefault('socketIdentity', identity) == identity)
        if guard['fd'] is not None:
            st = os.fstat(guard['fd'])
            path_st = Path(pin['lock']['path']).lstat()
            need(stat.S_ISREG(st.st_mode) and st.st_uid == self.uid and not st.st_mode & 0o022
                 and (st.st_dev, st.st_ino) == (pin['lock']['device'], pin['lock']['inode'])
                 and (path_st.st_dev, path_st.st_ino) == (st.st_dev, st.st_ino))
            # Inspect the transferred OFD's kernel lock; NEVER acquire/reacquire.
            locks = [line.split() for line in Path(f'/proc/self/fdinfo/{guard["fd"]}').read_text().splitlines()
                     if line.startswith('lock:')]
            need(len(locks) == 1)
            fields = locks[0]
            need(fields[2:5] == ['FLOCK', 'ADVISORY', 'WRITE'] and fields[5] == str(pin['pid'])
                 and fields[7:] == ['0', 'EOF'])
            major, minor, inode = fields[6].split(':')
            need(int(major, 16) == os.major(st.st_dev) and int(minor, 16) == os.minor(st.st_dev)
                 and int(inode) == st.st_ino)
        self.remaining()

    def _exchange(self, guard, verb, receive_fd=False):
        self.remaining()
        sock = guard['socket']
        sock.settimeout(self.remaining())
        need(not select.select([sock], [], [], 0)[0])  # idle EOF/data is sticky loss
        request = {'version': 1, 'nonce': os.urandom(32).hex(), 'verb': verb,
                   'generation': self.policy['generation'], 'holderId': guard['pin']['holderId'],
                   'challengeSha256': self.challenge_sha}
        sock.sendall(canonical(request) + b'\n')
        raw, fds = b'', []
        try:
            while b'\n' not in raw:
                sock.settimeout(self.remaining())
                part, ancillary, flags, _ = sock.recvmsg(LIMIT + 1 - len(raw), socket.CMSG_SPACE(32 * array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
                invalid_ancillary = False
                # Collect ALL installed rights before validating anything else.
                for level, kind, data in ancillary:
                    if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                        values = array.array('i')
                        values.frombytes(data[:len(data) - len(data) % values.itemsize])
                        fds.extend(values)
                    else:
                        invalid_ancillary = True
                need(not invalid_ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                need(part)
                raw += part
                need(len(raw) <= LIMIT)
            need(raw.endswith(b'\n') and raw.count(b'\n') == 1
                 and len(fds) == (1 if receive_fd else 0))
            reply = decode(raw)
            need(isinstance(reply, dict) and type(reply.get('version')) is int
                 and reply == {**request, 'state': 'held-retained'})
            if receive_fd:
                guard['fd'] = fds.pop()
            self.remaining()
        finally:
            errors = []
            for fd in fds:
                try:
                    os.close(fd)
                except OSError as error:
                    errors.append(error)
            if errors:
                primary = sys.exception()
                if primary is None:
                    raise Refusal()
                primary.cleanup_errors = [*getattr(primary, 'cleanup_errors', []), *errors]

    def check(self, challenge):
        try:
            need(canonical(challenge) == canonical(self.policy['challenge']))
            self.remaining()
            for guard in self.guards:
                self._identity(guard)
                self._exchange(guard, 'check')
                self._identity(guard)
            # Recheck earlier peers after serial waits, including idle revocation.
            for guard in self.guards:
                self._identity(guard)
                need(not select.select([guard['socket']], [], [], 0)[0])
        except BaseException:
            self.poisoned = True
            raise

    def retain_unknown(self, challenge):
        self.unknown = True  # latch BEFORE transport; no retry/release even on failure
        self._record('unknown-retained')
        self.check(challenge)
        for guard in self.guards:
            self._exchange(guard, 'retain')

    def complete(self, challenge):
        need(not self.unknown)
        self.check(challenge)
        self.completed = True

    def _dispose(self):
        errors = []
        # No LOCK_UN, finish/release frame, thaw, process signal or reactivation.
        for guard in self.guards:
            for resource in ('fd', 'socket', 'pidfd'):
                value = guard.get(resource)
                guard[resource] = None
                if value is not None:
                    try:
                        value.close() if resource == 'socket' else os.close(value)
                    except BaseException as error:
                        errors.append(error)
        if self.journal is not None:
            fd, self.journal = self.journal, None
            try:
                os.close(fd)
            except BaseException as error:
                errors.append(error)
        if errors:
            raise Refusal()

    def close(self):
        if self.closed:
            return
        primary = None
        try:
            if not self.poisoned:
                self.check(self.policy['challenge'])
            if self.completed and not self.unknown and not self.poisoned:
                self._record('completed-dormant-retained')
        except BaseException as error:
            primary = error
        self.closed = True
        try:
            self._dispose()
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                primary.cleanup_errors = [*getattr(primary, 'cleanup_errors', []), error]
        if primary:
            raise primary


def serve(input_fd=0, output_fd=1, *, policy_path=POLICY, owner_uid=0, trusted_root=Path('/')):
    """Library test seam rebases private paths/UID only; CLI has NO options."""
    held = None
    try:
        policy = decode(private_read(policy_path, owner_uid, trusted_root))
        held = HeldAuthority(policy, owner_uid=owner_uid, trusted_root=trusted_root)
        buffer = b''
        while True:
            need(select.select([input_fd], [], [], held.remaining())[0])
            chunk = os.read(input_fd, 8192)
            need(chunk)
            buffer += chunk
            need(len(buffer) <= LIMIT)
            if b'\n' not in buffer:
                continue
            need(buffer.endswith(b'\n') and buffer.count(b'\n') == 1)
            request = decode(buffer)
            buffer = b''
            need(exact(request, 'version nonce verb challenge') and type(request['version']) is int and request['version'] == 1
                 and isinstance(request['nonce'], str) and re.fullmatch('[a-f0-9]{64}', request['nonce']))
            verb = request['verb']
            if verb == 'check':
                held.check(request['challenge'])
            elif verb == 'retain':
                held.retain_unknown(request['challenge'])
            elif verb == 'close':
                held.complete(request['challenge'])
                held.close()  # required fallible cleanup BEFORE acknowledging
            else:
                raise Refusal()
            raw = canonical({'version': 1, 'nonce': request['nonce'], 'verb': verb,
                             'state': 'closed-retained' if verb == 'close' else 'held-retained'}) + b'\n'
            need(os.write(output_fd, raw) == len(raw))
            if verb == 'close':
                return 0
    except BaseException:
        return 1  # no credentials, paths, raw JSON, exception causes or stderr
    finally:
        if held is not None:
            try:
                held.close()
            except BaseException:
                pass  # failure already cannot acknowledge success or release guards


if __name__ == '__main__':
    if len(sys.argv) != 1 or os.geteuid() != 0:
        sys.exit(1)
    sys.exit(serve())
