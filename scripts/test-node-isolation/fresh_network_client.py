#!/usr/bin/python3 -I
"""Finite exact-PID holder; unchanged protocol, no publication or recovery.

Only the digest-loading fixed entry may call run(). Independent installed inputs,
root operator pipe provenance and writer/cleanup exclusion remain prerequisites.
"""
import fcntl
import os
from pathlib import Path
import select
import socket
import stat
import struct
import time

CONTROL = '/usr/local/libexec/c3-test-fresh-network-control.py'
SERVER_ENTRY = '/usr/local/libexec/c3-test-fresh-network-exec.py'
CLIENT = '/usr/local/libexec/c3-test-fresh-network-client.py'
SOURCE_PINS = {
    '/usr/local/libexec/c3-test-fresh-network.py': '6c6c5e3b528f12e5c2d578922c50fa2982906c1e97389948ecff7d55c4cb08ec',
    CONTROL: 'ced8d6264424f65f5f9d6f5c9b1f9de731953d196026e513ed6e3f13a0cd88ac',
    SERVER_ENTRY: '5fdb07e09177ce1b616d8506d325089e48e50560fee9a03757e4bc0850760167',
}
OPERATIONS = ('observe', 'cutover', 'return', 'abandon')
IO_SECONDS = 3
HEARTBEAT_SECONDS = 10
MAX_REQUESTS = 128


def _root_stat(m, s):
    m.need(s.st_uid == s.st_gid == 0 and not s.st_mode & 0o022,
           'ROOT_OWNED_INPUT_REQUIRED')


def _host(m, p, pid, start):
    m.need(os.getpid() == pid and m.proc_start(pid) == start and
           os.getresuid() == os.getresgid() == (0, 0, 0), 'EXACT_ROOT_HOLDER_REQUIRED')
    status = Path('/proc/self/status').read_text().splitlines()
    m.need('Uid:\t0\t0\t0\t0' in status and 'Gid:\t0\t0\t0\t0' in status,
           'EXACT_ROOT_HOLDER_REQUIRED')
    m.need(Path('/etc/machine-id').read_text().strip() == p['machine'] and
           Path('/proc/sys/kernel/random/boot_id').read_text().strip() == p['boot'],
           'ACCEPTED_TEST_HOST_REQUIRED')
    for ns in ('pid', 'mnt', 'net'):
        m.need(m.identity('/proc/self/ns/'+ns) == m.identity('/proc/1/ns/'+ns),
               'HOST_NAMESPACES_REQUIRED')
    m.need(m.identity('/proc/self/ns/net') == p['hostNetns'], 'ACCEPTED_HOST_NET_REQUIRED')


def _peercred(channel):
    return struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))


def _server_host(m, pid):
    status = Path('/proc', str(pid), 'status').read_text().splitlines()
    m.need('Uid:\t0\t0\t0\t0' in status and 'Gid:\t0\t0\t0\t0' in status,
           'ROOT_SERVER_REQUIRED')
    m.need(Path('/proc', str(pid), 'cmdline').read_bytes() ==
           b'/usr/bin/python3\0-I\0-B\0'+SERVER_ENTRY.encode()+b'\0',
           'FIXED_INSTALLED_SERVER_REQUIRED')
    m.need(m.identity('/proc/'+str(pid)+'/exe') == m.identity('/usr/bin/python3'),
           'FIXED_SERVER_PYTHON_REQUIRED')
    for ns in ('pid', 'mnt', 'net'):
        m.need(m.identity('/proc/'+str(pid)+'/ns/'+ns) == m.identity('/proc/1/ns/'+ns),
               'HOST_SERVER_NAMESPACES_REQUIRED')


def _json_types(m, value):
    # ip -j observations admit ordinary JSON rows, not float/int coercions or
    # unbounded recursive work. Row contents are evidence, NEVER accepted policy.
    pending = [(value, 0)]; count = 0
    while pending:
        item, depth = pending.pop(); count += 1
        m.need(depth <= 32 and count <= 100000, 'BOUNDED_JSON_TREE_REQUIRED')
        kind = type(item)
        m.need(kind in (dict, list, str, int, bool, type(None)), 'EXACT_JSON_TYPES_REQUIRED')
        if kind is dict:
            m.need(all(type(key) is str for key in item), 'JSON_STRING_KEYS_REQUIRED')
            pending.extend((child, depth+1) for child in item.values())
        elif kind is list:
            pending.extend((child, depth+1) for child in item)


def _stable(s):
    # Reading may update atime. All identity/ownership/mode/size/mtime/ctime
    # (nanoseconds, not float-rounded os.stat_result equality) remain fixed.
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


class Input:
    """Retained trusted regular inode and exact bytes; never creates an input."""
    def __init__(self, m, path):
        self.m, self.path = m, path
        self.fd = m.trusted_fd(path)
        try:
            self.s = os.fstat(self.fd)
            m.need(stat.S_ISREG(self.s.st_mode) and self.s.st_nlink == 1 and
                   self.s.st_size <= m.LIMIT, 'REGULAR_INPUT_REQUIRED')
            self.raw = os.pread(self.fd, m.LIMIT+1, 0)
            self.check()
        except BaseException:
            os.close(self.fd)
            raise

    def check(self):
        m = self.m
        fd = m.trusted_fd(self.path)
        try:
            m.need(_stable(os.fstat(fd)) == _stable(self.s) == _stable(os.fstat(self.fd)) and
                   os.pread(fd, m.LIMIT+1, 0) == self.raw and
                   _stable(os.fstat(fd)) == _stable(self.s), 'IMMUTABLE_INSTALLED_INPUT_DRIFT')
        finally:
            os.close(fd)

    def close(self):
        os.close(self.fd)


class Holder:
    def __init__(self, m, control):
        self.m, self.control = m, control
        self.inputs = []; self.lease = None; self.channel = None
        self.pidfd = self.serverfd = self.socketfd = None
        self.attempted = self.failed = self.closed = self.abandon_ack = False
        self.phase = 'new'; self.sequence = 0; self.baseline = None
        self.pid = os.getpid(); self.start = m.proc_start(self.pid)
        try:
            self.pidfd = os.pidfd_open(self.pid)
            self.plan = self.pin(m.INPUT)
            self.p = m.validate_plan(m.decode(self.plan.raw))
            remaining = self.p['deadline']-time.time()
            m.need(0 < remaining <= 600, 'FINITE_INSTALLED_DEADLINE_REQUIRED')
            self.end = time.monotonic()+remaining  # captured ONCE, before rendezvous
            pins = dict(SOURCE_PINS)
            pins[CLIENT] = globals().get('__source_sha256__')
            for path, digest in pins.items():
                m.need(type(digest) is str and m.digest(self.pin(path).raw) == digest,
                       'INSTALLED_SOURCE_PIN_REQUIRED')
            self.check()
        except BaseException:
            self.poison()
            self.close()
            raise

    def pin(self, path):
        item = Input(self.m, path)
        self.inputs.append(item)
        return item

    def poison(self):
        self.failed = True
        self.phase = 'unknown-retained'

    def check(self):
        m = self.m
        try:
            m.need(not self.failed and not self.closed and
                   time.monotonic() < self.end and time.time() < self.p['deadline'],
                   'FINITE_HOLDER_LOST')
            m.need(not select.select([self.pidfd], [], [], 0)[0], 'HOLDER_DEAD')
            _host(m, self.p, self.pid, self.start)
            for item in self.inputs: item.check()
            if self.lease is not None:
                m.need(self.lease.holder == {'pid': self.pid, 'start': self.start}, 'EXACT_CURRENT_PID_LEASE_REQUIRED')
                self.lease.check()
            if self.socketfd is not None and not self.abandon_ack:
                parent = m.trusted_fd(str(Path(m.SOCKET).parent), directory=True)
                try: s = os.stat(Path(m.SOCKET).name, dir_fd=parent, follow_symlinks=False)
                finally: os.close(parent)
                held = os.fstat(self.socketfd)
                _root_stat(m, s)
                m.need(stat.S_ISSOCK(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600 and
                       s.st_nlink == 1 and (s.st_dev, s.st_ino) == (held.st_dev, held.st_ino) and
                       not os.listxattr(m.SOCKET, follow_symlinks=False), 'TRUSTED_SOCKET_DRIFT')
            if self.serverfd is not None:
                pid, uid, gid = _peercred(self.channel)
                m.need((pid, uid, gid) == (self.serverpid, 0, 0), 'EXACT_ROOT_SERVER_LOST')
                # The checked abandon reply precedes the server's own unlink and
                # exit. Its later liveness is not promised by this old protocol.
                if not self.abandon_ack:
                    m.need(m.proc_start(pid) == self.serverstart and
                           not select.select([self.serverfd], [], [], 0)[0], 'EXACT_ROOT_SERVER_LOST')
                    _server_host(m, pid)
            # Input/proc read work must not consume the remaining dispatch budget.
            m.need(time.monotonic() < self.end and time.time() < self.p['deadline'], 'FINITE_HOLDER_LOST')
        except BaseException:
            self.poison()
            raise

    def observation(self):
        self.check()
        return {'version': 1, 'context': self.m.CONTEXT, 'generation': self.p['generation'],
                'holder': {'pid': self.pid, 'start': self.start}, 'deadline': self.p['deadline'],
                'accepted': False, 'physicalAccepted': False, 'operationalGO': False}

    def _wait(self):
        self.check()
        time.sleep(min(.05, max(0, self.end-time.monotonic())))

    def connect(self):
        m = self.m
        try:
            m.need(not self.attempted and self.phase == 'new', 'NO_RECONNECT_OR_ADOPTION')
            # Only absence may wait. Present malformed/replaced inputs never retry.
            while True:
                self.check()
                try: os.lstat(m.LEASE); break
                except FileNotFoundError: self._wait()
            item = self.pin(m.LEASE)
            value = m.decode(item.raw)
            m.keys(value, 'version context generation boot planSha256 holder deadline operations')
            m.keys(value['holder'], 'pid start')
            m.need(type(value['holder']['pid']) is int and value['holder']['pid'] == self.pid and
                   type(value['holder']['start']) is str and value['holder']['start'] == self.start and
                   value['operations'] == list(OPERATIONS), 'EXACT_CURRENT_PID_LEASE_REQUIRED')
            self.lease = self.control.Lease(m, self.p, self.plan.raw)
            while True:
                self.check()
                try: os.lstat(m.SOCKET); break
                except FileNotFoundError: self._wait()
            parent = m.trusted_fd(str(Path(m.SOCKET).parent), directory=True)
            try:
                self.socketfd = os.open(Path(m.SOCKET).name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=parent)
            finally:
                os.close(parent)
            self.check()
            # A bound pathname is visible BEFORE listen(). Read the existing
            # kernel listener flag; never consume the one connection as a probe.
            while True:
                rows = [row.split() for row in Path('/proc/self/net/unix').read_text().splitlines()[1:]]
                rows = [row for row in rows if len(row) == 8 and row[7] == m.SOCKET]
                m.need(len(rows) <= 1, 'AMBIGUOUS_LISTENER_REFUSED')
                if rows and rows[0][3] == '00010000' and rows[0][4:6] == ['0001', '01']: break
                self._wait()
            self.check()
            self.channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.attempted = True  # BEFORE first connect; even refused connect cannot retry
            self.channel.settimeout(self.budget(time.monotonic()+IO_SECONDS))
            self.check()
            self.channel.connect(m.SOCKET)  # the leased PID itself creates AND connects
            pid, uid, gid = _peercred(self.channel)
            m.need(pid != self.pid and uid == gid == 0, 'INDEPENDENT_ROOT_SERVER_REQUIRED')
            self.serverpid, self.serverstart = pid, m.proc_start(pid)
            self.serverfd = os.pidfd_open(pid)
            self.check()
            result = self.receive('prepared', 0)
            self.phase = 'prepared'
            return result
        except BaseException:
            self.poison()
            raise

    def budget(self, end):
        self.check()
        remaining = min(end, self.end)-time.monotonic()
        self.m.need(remaining > 0, 'FINITE_IO_TIMEOUT')
        return remaining

    def quiet(self, terminal=False):
        if select.select([self.channel], [], [], 0)[0]:
            value = self.channel.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            self.m.need(terminal and not value, 'UNSOLICITED_REPLY_OR_EOF_RETAINED')

    def receive(self, phase, sequence):
        m = self.m
        end = time.monotonic()+IO_SECONDS
        def exact(size):
            raw = bytearray()
            while len(raw) < size:
                self.channel.settimeout(self.budget(end))
                block = self.channel.recv(size-len(raw))
                m.need(block, 'REPLY_EOF_RETAINED')
                raw.extend(block)
            return bytes(raw)
        size = struct.unpack('!I', exact(4))[0]
        m.need(0 < size <= m.LIMIT, 'BOUNDED_REPLY_REQUIRED')
        result = m.decode(exact(size).decode('utf-8'))
        _json_types(m, result)
        if phase == 'abandoned':
            m.keys(result, 'phase operationalGO')  # actual server's deliberately small ACK
            m.need(type(result['phase']) is str and result['phase'] == phase and
                   result['operationalGO'] is False, 'ABANDON_ACK_REQUIRED')
            self.abandon_ack = True  # only validated explicit teardown; never cutover
        else:
            m.keys(result, 'version context generation phase sequence observation physicalAccepted operationalGO')
            m.need(type(result['version']) is int and result['version'] == 1 and
                   type(result['sequence']) is int and result['sequence'] == sequence and
                   result['context'] == m.CONTEXT and result['generation'] == self.p['generation'] and
                   result['phase'] == phase and result['physicalAccepted'] is False and
                   result['operationalGO'] is False, 'EXACT_UNACCEPTED_REPLY_REQUIRED')
            observation = result['observation']
            m.keys(observation, 'namespace snapshots configSha256')
            ns = observation['namespace']
            m.need(type(ns) is list and len(ns) == 2 and all(type(x) is int and x > 0 for x in ns) and
                   ns != self.p['hostNetns'], 'UNACCEPTED_NS_OBSERVATION_REQUIRED')
            m.keys(observation['snapshots'], 'host fresh caddy mongo redis')
            for snapshot in observation['snapshots'].values():
                m.keys(snapshot, 'links addresses routes rules')
                for rows in snapshot.values():
                    m.need(type(rows) is list and all(type(x) is dict for x in rows), 'SNAPSHOT_ROWS_REQUIRED')
            m.pin(observation['configSha256'])
            expected = self.p['newConfig'] if phase == 'cutover' else self.p['oldConfig']
            m.need(observation['configSha256'] == m.digest(m.encode(expected)), 'CONFIG_OBSERVATION_DRIFT')
            baseline = m.encode({'namespace': ns, 'snapshots': observation['snapshots']})
            if self.baseline is None: self.baseline = baseline
            else: m.need(baseline == self.baseline, 'RECURSIVE_SNAPSHOT_TYPE_OR_VALUE_DRIFT')
        self.check()  # ACK is not authority to bypass expired/changed inputs
        self.quiet(terminal=phase == 'abandoned')
        return result

    def dispatch(self, operation):
        m = self.m
        try:
            self.check()
            m.need(type(operation) is str and operation in OPERATIONS and
                   self.phase in ('prepared', 'cutover', 'returned') and
                   self.sequence < MAX_REQUESTS, 'FINITE_CLOSED_OPERATION_REQUIRED')
            phase = self.phase if operation == 'observe' else {
                ('prepared', 'cutover'): 'cutover', ('cutover', 'return'): 'returned',
                ('prepared', 'abandon'): 'abandoned', ('returned', 'abandon'): 'abandoned',
            }.get((self.phase, operation))
            m.need(phase is not None, 'PHASE_TRANSITION_REFUSED')
            self.quiet()
            raw = m.encode({'generation': self.p['generation'], 'sequence': self.sequence+1,
                            'operation': operation})
            m.need(len(raw) <= 4096, 'BOUNDED_REQUEST_REQUIRED')
            self.channel.settimeout(self.budget(time.monotonic()+IO_SECONDS))
            self.check()
            self.channel.sendall(struct.pack('!I', len(raw))+raw)
            result = self.receive(phase, self.sequence+1)
            self.sequence += 1; self.phase = phase
            return result
        except BaseException:
            self.poison()
            raise

    def close(self):
        # Descriptor disposal only. Never send return/abandon or unlink any path.
        # Continue owned descriptor disposal after a close fault, but never hide it.
        errors = []
        if self.closed: return
        if self.phase != 'abandoned' or not self.abandon_ack: self.poison()
        self.closed = True
        for item in [self.channel, self.lease, *reversed(self.inputs)]:
            if item is not None:
                try: item.close()
                except BaseException as exc: errors.append(exc)
        for fd in (self.socketfd, self.serverfd, self.pidfd):
            if fd is not None:
                try: os.close(fd)
                except BaseException as exc: errors.append(exc)
        if errors:
            self.poison()
            raise errors[0]


def _pipe(m, fd, access):
    s = os.fstat(fd)
    _root_stat(m, s)
    m.need(stat.S_ISFIFO(s.st_mode) and s.st_nlink == 1 and
           os.readlink('/proc/self/fd/'+str(fd)) == 'pipe:['+str(s.st_ino)+']' and
           fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == access,
           'PREOPENED_ROOT_ANONYMOUS_OPERATOR_PIPES_REQUIRED')
    return (s.st_dev, s.st_ino)


def _emit(holder, value):
    raw = holder.m.encode(value)
    holder.m.need(len(raw) <= holder.m.LIMIT, 'BOUNDED_OBSERVATION_REQUIRED')
    end = time.monotonic()+IO_SECONDS
    while raw:
        holder.check()
        holder.m.need(select.select([], [1], [], holder.budget(end))[1], 'OPERATOR_OUTPUT_TIMEOUT')
        try: count = os.write(1, raw)
        except BlockingIOError: continue
        holder.m.need(count > 0, 'OPERATOR_OUTPUT_LOST')
        raw = raw[count:]
    holder.check()


def run(m, control):
    """Fixed fd0 literal-verb pipe and fd1 JSON evidence pipe; never a UI/daemon.

    Independently trusted root invocation must supply these pipes. Inode ownership
    cannot prove the identity of every retained writer: that exclusion is external.
    No path, JSON policy, argv, callback or environment is selected by this channel.
    """
    pins = (_pipe(m, 0, os.O_RDONLY), _pipe(m, 1, os.O_WRONLY))
    flags = [fcntl.fcntl(fd, fcntl.F_GETFL) for fd in (0, 1)]
    holder = None
    try:
        for fd in (0, 1): os.set_blocking(fd, False)
        holder = Holder(m, control)
        _emit(holder, holder.observation())  # actual PID/start; explicitly NOT authority
        _emit(holder, holder.connect())
        heartbeat = time.monotonic()+HEARTBEAT_SECONDS
        line = bytearray(); line_end = None; commands = 0
        while holder.phase != 'abandoned':
            holder.check()
            m.need(pins == (_pipe(m, 0, os.O_RDONLY), _pipe(m, 1, os.O_WRONLY)), 'OPERATOR_PIPE_DRIFT')
            now = time.monotonic()
            if line_end is not None: m.need(now < line_end, 'OPERATOR_PARTIAL_LINE_TIMEOUT')
            until = min(heartbeat, holder.end, line_end if line_end is not None else holder.end)
            ready = select.select([0, holder.channel, holder.pidfd, holder.serverfd], [], [],
                                  max(0, min(.1, until-now)))[0]
            if holder.channel in ready: holder.quiet()
            if 0 in ready:
                byte = os.read(0, 1)
                m.need(byte, 'OPERATOR_EOF_UNKNOWN_RETAINED')
                if line_end is None: line_end = time.monotonic()+IO_SECONDS
                line.extend(byte)
                m.need(len(line) <= 8, 'CLOSED_OPERATOR_VERB_REQUIRED')
                if byte == b'\n':
                    operation = bytes(line[:-1]).decode('ascii')
                    m.need(operation in OPERATIONS and commands < 64, 'FINITE_OPERATOR_SELECTION_REQUIRED')
                    commands += 1
                    _emit(holder, holder.dispatch(operation))
                    line.clear(); line_end = None
                    heartbeat = time.monotonic()+HEARTBEAT_SECONDS
            if holder.phase != 'abandoned' and time.monotonic() >= heartbeat:
                _emit(holder, holder.dispatch('observe'))  # read-only heartbeat, never renewal
                heartbeat = time.monotonic()+HEARTBEAT_SECONDS
        holder.check()
    except BaseException:
        if holder is not None: holder.poison()
        raise
    finally:
        try:
            if holder is not None: holder.close()
        finally:
            # A restore/close fault is failure, including after an abandon ACK.
            for fd, original in enumerate(flags): fcntl.fcntl(fd, fcntl.F_SETFL, original)
