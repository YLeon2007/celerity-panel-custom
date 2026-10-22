#!/usr/bin/python3 -I
"""Fixed TEST physical construction primitives. No inventory/GO producer.

Privileged entry points are separate, no-argument files. Programmatic seams below
are for disposable local tests, never CLI/environment-selected paths or actions.
"""
import array
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import time

CONTEXT = 'test.infograd.online'
INPUT = '/var/lib/c3-test-fresh-input'
RESOURCE = '/var/lib/c3-test-fresh-resources'
REGISTER = '/run/c3-test-fresh-register.sock'
CONTROL = '/run/c3-test-fresh-classic.sock'
ACCEPTANCE = '/etc/c3-test-fresh-physical-acceptance.json'
NETNS = '/run/netns/c3-test-fresh-classic'
POLICY = '/etc/c3-test-fresh-classic.json'
PREPARER = '/usr/local/libexec/c3-test-fresh-prepare.py'
CGROUP = '0::/system.slice/c3-test-fresh-classic.service'
PREPARE_SECONDS = 120
ACCEPT_SECONDS = 600
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class Refusal(RuntimeError):
    pass


def need(ok, code):
    if not ok: raise Refusal(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()


def decode(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            need(k not in result, 'DUPLICATE_JSON_KEY')
            result[k] = v
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: need(False, 'INVALID_JSON'))
    except (ValueError, UnicodeError):
        raise Refusal('INVALID_JSON') from None


def trusted_open(path, directory=False):
    """Every component root-owned, no symlinks or writable parent traversal."""
    parts = Path(path).parts
    need(str(Path(path)) == path and path.startswith('/') and '..' not in parts,
         'FIXED_TRUSTED_PATH_REQUIRED')
    fd = os.open('/', DIR)
    try:
        for index, part in enumerate(parts[1:]):
            child = os.open(part, DIR if directory or index < len(parts)-2 else FILE, dir_fd=fd)
            os.close(fd); fd = child
            s = os.fstat(fd)
            need(s.st_uid == s.st_gid == 0 and not s.st_mode & 0o022 and
                 not os.listxattr(fd), 'UNTRUSTED_RESOURCE_PATH')
        return fd
    except BaseException:
        os.close(fd); raise


def trusted_read(path, limit=8*1024*1024):
    fd = trusted_open(path)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_size <= limit, 'UNTRUSTED_RESOURCE_FILE')
        raw = b''
        while len(raw) <= limit:
            block = os.read(fd, min(65536, limit+1-len(raw)))
            if not block: break
            raw += block
        after = os.fstat(fd)
        def identity(s):
            return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid,
                    s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) <= limit and identity(before) == identity(after), 'RESOURCE_READ_DRIFT')
        return raw
    finally: os.close(fd)


class OwnedTree:
    """Only a freshly mkdir'd tree; replacement is retained, never adopted."""
    def __init__(self, path, parent, fd, identity):
        self.path, self.parent, self.fd, self.identity = Path(path), parent, fd, identity

    @classmethod
    def create(cls, path):
        path = Path(path)
        parent = os.open(path.parent, DIR)
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
            fd = os.open(path.name, DIR, dir_fd=parent)
            s = os.fstat(fd)
            return cls(path, parent, fd, (s.st_dev, s.st_ino))
        except BaseException:
            os.close(parent); raise

    def check(self):
        s = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        need((s.st_dev, s.st_ino) == self.identity and stat.S_ISDIR(s.st_mode),
             'OWNED_RESOURCE_REPLACED')

    def dispose(self):
        self.check()
        # shutil's dir_fd implementation is symlink-attack resistant on Linux.
        need(shutil.rmtree.avoids_symlink_attacks, 'SAFE_CLEANUP_UNAVAILABLE')
        shutil.rmtree(self.path.name, dir_fd=self.parent)
        os.fsync(self.parent)

    def close(self):
        for name in ('fd', 'parent'):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd); setattr(self, name, None)


class ProcessLease:
    """pidfd-only owned process signaling; never numeric PID kill fallback."""
    def __init__(self, pid):
        self.pid = pid
        self.fd = os.pidfd_open(pid, 0)
        try: self.start = self.snapshot()['start']
        except BaseException:
            os.close(self.fd); self.fd = None
            raise
        self.released = False

    def snapshot(self):
        need(not select.select([self.fd], [], [], 0)[0], 'PREPARATION_PROCESS_LOST')
        raw = (Path('/proc')/str(self.pid)/'stat').read_text()
        fields = raw.rsplit(')', 1)[1].split()
        return {'state': fields[0], 'start': fields[19]}

    def check(self, stopped=False):
        value = self.snapshot()
        need(value['start'] == self.start, 'PREPARATION_PID_REUSED')
        if stopped: need(value['state'] == 'T', 'STOPPED_PREPARATION_REQUIRED')
        return value

    def abandon(self):
        need(not self.released, 'RELEASED_PREPARATION_NOT_OWNED')
        if not select.select([self.fd], [], [], 0)[0]:
            signal.pidfd_send_signal(self.fd, signal.SIGKILL, None, 0)
        need(bool(select.select([self.fd], [], [], 5)[0]), 'OWNED_PROCESS_DEATH_UNKNOWN')

    def close(self):
        if self.fd is not None: os.close(self.fd); self.fd = None

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def wait_prepared(lease, deadline, checkpoint):
    while True:
        need(time.monotonic() < deadline, 'PREPARATION_DEADLINE')
        checkpoint()
        value = lease.check()
        need(time.monotonic() < deadline, 'PREPARATION_DEADLINE')
        if value['state'] == 'T': return value
        time.sleep(min(.01, max(0, deadline-time.monotonic())))


def wait_acceptance(lease, deadline, read_acceptance, files, generation, read_policy, checkpoint):
    """Release signal ownership only to a separately accepted exact stopped PID.

    Independent acceptance MUST exclude all SIGCONT until this wait returns and
    the external watchdog unit has exited successfully. A written acceptance file
    alone is NOT a release receipt or authorization to resume.
    """
    while True:
        need(time.monotonic() < deadline, 'ACCEPTANCE_DEADLINE')
        lease.check(stopped=True); checkpoint()
        acceptance = read_acceptance()
        if acceptance is not None:
            policy = read_policy()
            need(type(policy) is dict and policy.get('files') == files and
                 policy.get('context') == CONTEXT, 'PREPARATION_SOURCE_MAP_DRIFT')
            expected = {'version': 1, 'context': CONTEXT,
                        'supervisor': {'pid': lease.pid, 'start': lease.start},
                        'generation': generation, 'filesSha256': sha(encode(files)),
                        'policySha256': sha(encode(policy))}
            need(type(acceptance) is dict and acceptance == expected and
                 type(acceptance.get('version')) is int and
                 type(acceptance.get('supervisor', {}).get('pid')) is int,
                 'EXACT_INDEPENDENT_ACCEPTANCE_REQUIRED')
            checkpoint(); lease.check(stopped=True)
            need(time.monotonic() < deadline, 'ACCEPTANCE_DEADLINE')
            lease.released = True  # no signal/cleanup authority after this line
            return acceptance
        need(time.monotonic() < deadline, 'ACCEPTANCE_DEADLINE')
        time.sleep(min(.02, max(0, deadline-time.monotonic())))


def bind_owned(path, kind=socket.SOCK_STREAM):
    """No unlink-before-bind: any existing object is an explicit refusal."""
    listener = socket.socket(socket.AF_UNIX, kind)
    try:
        old = os.umask(0o177)
        try: listener.bind(path)
        finally: os.umask(old)
        info = os.lstat(path)
        need(stat.S_IMODE(info.st_mode) == 0o600, 'PRIVATE_SOCKET_REQUIRED')
        return listener, (info.st_dev, info.st_ino)
    except BaseException:
        listener.close(); raise


def unlink_owned_socket(path, identity):
    info = os.lstat(path)
    need(stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == identity,
         'OWNED_SOCKET_REPLACED')
    os.unlink(path)


def anonymous_stdio_and_control(control):
    """Only 0-3 survive exec. Caller must already have finished privileged setup."""
    fds = [os.memfd_create('c3-supervisor-stdio', os.MFD_CLOEXEC) for _ in range(3)]
    control_copy = os.dup(control.fileno())
    try:
        # Preserve source descriptors before dup2 overwrites any of 0-3.
        import fcntl
        copies = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10) for fd in [*fds, control_copy]]
        try:
            for number, fd in enumerate(copies): os.dup2(fd, number, inheritable=True)
        finally:
            for fd in copies: os.close(fd)
    finally:
        for fd in [*fds, control_copy]:
            if fd > 3: os.close(fd)
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd > 3:
            try: os.close(fd)
            except OSError as error:
                if error.errno != errno.EBADF: raise


def kernel_call(name, *args):
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, name, None)
    need(function is not None, 'REQUIRED_KERNEL_PRIMITIVE_UNAVAILABLE')
    if function(*args) != 0: raise Refusal('KERNEL_'+name.upper()+'_REFUSED')


def mount(source, target, filesystem, flags, data=None):
    values = [None if value is None else os.fsencode(value) for value in (source, target, filesystem)]
    kernel_call('mount', *values, ctypes.c_ulong(flags), None if data is None else os.fsencode(data))


def drop_identity():
    # Must clear the bounding set while CAP_SETPCAP is still effective.
    for capability in range(64):
        libc = ctypes.CDLL(None, use_errno=True)
        present = libc.prctl(23, capability, 0, 0, 0)  # PR_CAPBSET_READ
        if present < 0:
            need(ctypes.get_errno() == errno.EINVAL, 'CAPABILITY_BOUNDING_READ_REFUSED')
            continue
        if present: kernel_call('prctl', 24, capability, 0, 0, 0)
    kernel_call('prctl', 47, 4, 0, 0, 0)  # PR_CAP_AMBIENT_CLEAR_ALL
    os.setgroups([])
    os.setresgid(65531, 65531, 65531)
    os.setresuid(65531, 65531, 65531)
    # Explicitly clear inherited/permitted/effective capabilities after setuid.
    class Header(ctypes.Structure): _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
    kernel_call('capset', ctypes.byref(Header(0x20080522, 0)), ctypes.byref((Data*2)()))
    kernel_call('prctl', 38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(os.getresuid() == os.getresgid() == (65531,)*3 and not os.getgroups() and
         all(int(status[k], 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')) and
         status['NoNewPrivs'].strip() == '1', 'IDENTITY_DROP_READBACK_REFUSED')


def verify_input():
    """Independently installed input, never an existing candidate edited in place."""
    plan = decode(trusted_read(INPUT+'/resource-plan.json'))
    need(type(plan) is dict and set(plan) == {'version', 'context', 'files', 'networkNamespace'} and
         type(plan['version']) is int and plan['version'] == 1 and plan['context'] == CONTEXT,
         'FIXED_RESOURCE_PLAN_REQUIRED')
    files = plan['files']
    need(type(files) is dict and 0 < len(files) <= 50000 and
         {PREPARER, '/usr/local/libexec/c3-test-coordinated-restore.py',
          '/usr/local/libexec/c3-test-fresh-classic.py', '/runtime/node', '/app/index.js',
          '/usr/bin/python3', '/etc/classic.json'} <= files.keys() and POLICY not in files,
         'COMPLETE_BOOTSTRAP_FILES_REQUIRED')
    for path, pin in files.items():
        need(type(path) is str and path.startswith('/') and str(Path(path)) == path and
             '..' not in Path(path).parts and path not in ('/', '/proc', '/state') and
             not path.startswith(('/proc/', '/state/')) and type(pin) is str and len(pin) == 64 and
             all(c in '0123456789abcdef' for c in pin), 'INVALID_RESOURCE_PIN')
    actual = {}
    root = INPUT+'/root'
    fd = trusted_open(root, directory=True); os.close(fd)
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in [*dirs, *names]:
            path = Path(directory)/name
            info = path.lstat()
            need(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o6022 and
                 not os.listxattr(path) and (stat.S_ISDIR(info.st_mode) or
                 (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)), 'UNSAFE_INPUT_ENTRY')
            if stat.S_ISREG(info.st_mode):
                relative = '/'+str(path.relative_to(root))
                actual[relative] = sha(trusted_read(str(path), 256*1024*1024))
    need(actual == files, 'RESOURCE_INPUT_CLOSURE_DRIFT')
    need(not any((Path(root)/name).exists() for name in ('proc', 'state', '.old-root')),
         'RESERVED_INPUT_DIRECTORY')
    ns = plan['networkNamespace']
    need(type(ns) is dict and set(ns) == {'device', 'inode'} and
         all(type(ns[k]) is int and ns[k] > 0 for k in ns), 'INDEPENDENT_NETWORK_NAMESPACE_PIN_REQUIRED')
    return plan


def join_private_network(plan):
    """Join the independently pinned nsfs netns without inventing host routes."""
    # nsfs handles aren't regular trusted files. Traverse their parents normally.
    parent = trusted_open('/run/netns', directory=True)
    try: netfd = os.open('c3-test-fresh-classic', os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=parent)
    finally: os.close(parent)
    try:
        s = os.fstat(netfd)
        import fcntl
        need({'device': s.st_dev, 'inode': s.st_ino} == plan['networkNamespace'] and
             fcntl.ioctl(netfd, 0xb703) == 0x40000000 and  # NS_GET_NSTYPE == CLONE_NEWNET
             (s.st_dev, s.st_ino) != (os.stat('/proc/1/ns/net').st_dev, os.stat('/proc/1/ns/net').st_ino),
             'FIXED_PRIVATE_NETWORK_NAMESPACE_REQUIRED')
        kernel_call('setns', netfd, 0x40000000)
    finally: os.close(netfd)


def construct(plan, control):
    """Actually construct private mount/ipc/uts namespaces, join fixed private net.

    No network routes, veths, host mounts or service actions are synthesized here.
    A separately provisioned pinned netns with real TEST ingress is mandatory.
    """
    kernel_call('unshare', 0x00020000 | 0x08000000 | 0x04000000)  # NEWNS|NEWIPC|NEWUTS
    mount(None, '/', None, 1 << 18 | 16384)  # MS_PRIVATE|MS_REC: no host propagation
    join_private_network(plan)
    root = Path(RESOURCE)/'root'
    need(not root.exists(), 'RESOURCE_ROOT_EXISTS')
    shutil.copytree(INPUT+'/root', root, symlinks=False)
    # Copy is private root-controlled staging; compare every copied byte before use.
    copied = {}
    for directory, _, names in os.walk(root):
        for name in names:
            path = Path(directory)/name
            copied['/'+str(path.relative_to(root))] = sha(trusted_read(str(path), 256*1024*1024))
    need(copied == plan['files'], 'COPIED_RESOURCE_CLOSURE_DRIFT')
    bootstrap = encode({'files': plan['files']})
    policy = root/POLICY.lstrip('/')
    fd = os.open(policy, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o644)
    try:
        # The service keeps UMask=0077. Creation mode alone becomes 0600,
        # unreadable by the fixed preparer after drop_identity(). Only root may
        # write this bootstrap; the final root remount also makes it read-only.
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(bootstrap); stream.flush(); os.fsync(fd)
    finally: os.close(fd)
    for name in ('proc', 'state', '.old-root'): (root/name).mkdir(mode=0o755)
    mount(str(root), str(root), None, 4096)  # MS_BIND
    mount('proc', str(root/'proc'), 'proc', 1|2|4|8)  # RDONLY NOSUID NODEV NOEXEC
    mount('tmpfs', str(root/'state'), 'tmpfs', 2|4|8,
          'size=16777216,nr_inodes=1024,mode=0700,uid=65531,gid=65531')
    fd = os.open(root/'state'/'launch.lock', os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    try: os.fchown(fd, 65531, 65531); os.fsync(fd)
    finally: os.close(fd)
    os.chdir(root)
    # Linux x86_64 only, explicit architecture refusal instead of syscall guessing.
    need(os.uname().machine == 'x86_64', 'SUPPORTED_PIVOT_ROOT_ARCH_REQUIRED')
    kernel_call('syscall', ctypes.c_long(155), b'.', b'.old-root')
    os.chdir('/')
    kernel_call('umount2', b'/.old-root', 2)  # MNT_DETACH, only inside new mount namespace
    os.rmdir('/.old-root')
    mount(None, '/', None, 4096|32|1|2|4)  # BIND REMOUNT RDONLY NOSUID NODEV
    os.umask(0o077)
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    drop_identity()
    anonymous_stdio_and_control(control)
    os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', '-B', PREPARER], {'LC_ALL': 'C'})


def receive_control(channel, expected_files):
    """One bounded seqpacket, all delivered rights owned even on refusal."""
    rights = array.array('i')
    try:
        raw, ancillary, flags, _ = channel.recvmsg(4096, socket.CMSG_SPACE(256*rights.itemsize))
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                rights.frombytes(data[:len(data)-len(data)%rights.itemsize])
        need(not flags and len(rights) == 1 and len(ancillary) == 1 and
             ancillary[0][:2] == (socket.SOL_SOCKET, socket.SCM_RIGHTS), 'EXACT_PREBOUND_RIGHT_REQUIRED')
        message = decode(raw)
        need(type(message) is dict and set(message) == {'generation', 'filesSha256'} and
             type(message['generation']) is str and len(message['generation']) == 64 and
             all(c in '0123456789abcdef' for c in message['generation']) and
             message['filesSha256'] == sha(encode(expected_files)), 'WATCHDOG_BOOTSTRAP_DRIFT')
        result = socket.socket(fileno=rights[0])
        rights.pop()
        try:
            need(result.family == socket.AF_UNIX and result.type == socket.SOCK_STREAM and
                 result.getsockname() == CONTROL and
                 result.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0,
                 'FIXED_UNLISTENED_CONTROL_REQUIRED')
            return result
        except BaseException:
            result.close(); raise
    finally:
        for fd in rights: os.close(fd)


def exec_main():
    """ExecStart: same PID becomes isolated fixed preparer; never forks a backend."""
    need(Path('/proc/self/cgroup').read_text().strip() == CGROUP, 'FIXED_FRESH_UNIT_REQUIRED')
    # Register ownership BEFORE the expensive full root scan/copy. The external
    # watcher can terminate this PID even if construction never reaches SIGSTOP.
    plan = decode(trusted_read(INPUT+'/resource-plan.json'))
    need(type(plan) is dict and type(plan.get('files')) is dict, 'FIXED_RESOURCE_PLAN_REQUIRED')
    deadline = time.monotonic()+PREPARE_SECONDS
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        while True:
            need(time.monotonic() < deadline, 'WATCHDOG_CONNECTION_DEADLINE')
            try:
                channel.connect(REGISTER); break
            except (FileNotFoundError, ConnectionRefusedError): time.sleep(.02)
        channel.settimeout(min(2, max(.001, deadline-time.monotonic())))
        import struct
        _, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(uid == gid == 0, 'ROOT_WATCHDOG_PEER_REQUIRED')
        need(channel.send(b'PREPARE\n') == 8, 'WATCHDOG_REGISTRATION_REFUSED')
        control = receive_control(channel, plan['files'])
    try:
        need(verify_input() == plan, 'RESOURCE_PLAN_DRIFT')
        construct(plan, control)
    finally: control.close()


def check_prepared_resources(lease, control_inode):
    """Observe the real held-lock barrier, not merely any external SIGSTOP."""
    lease.check(stopped=True)
    proc = Path('/proc')/str(lease.pid)
    status = dict(line.split(':', 1) for line in (proc/'status').read_text().splitlines() if ':' in line)
    need(status['Uid'].split() == ['65531']*4 and status['Gid'].split() == ['65531']*4 and
         not status['Groups'].split() and status['NoNewPrivs'].strip() == '1' and
         all(int(status[k], 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')),
         'PREPARATION_IDENTITY_REQUIRED')
    need((proc/'cgroup').read_text().strip() == CGROUP and
         [p.name for p in (proc/'task').iterdir()] == [str(lease.pid)], 'SOLE_PREPARATION_TASK_REQUIRED')
    group = Path('/sys/fs/cgroup/system.slice/c3-test-fresh-classic.service')
    need((group/'cgroup.procs').read_text().split() == [str(lease.pid)] and
         (group/'cgroup.freeze').read_text().strip() == '0', 'SOLE_UNFROZEN_PREPARATION_REQUIRED')
    actual = {p.name: os.readlink(p) for p in (proc/'fd').iterdir()}
    need(set(actual) == {'0', '1', '2', '3', '4', '5'} and
         actual['4'] == '/state' and actual['5'] == '/state/launch.lock', 'HELD_LOCK_DESCRIPTOR_PHASE_REQUIRED')
    for number in ('0', '1', '2'):
        s = (proc/'fd'/number).stat()
        need(stat.S_ISREG(s.st_mode) and s.st_size == 0 and
             actual[number].startswith('/memfd:c3-supervisor-stdio'), 'EMPTY_ANONYMOUS_STDIO_REQUIRED')
    s = (proc/'fd/3').stat()
    need(stat.S_ISSOCK(s.st_mode) and s.st_ino == control_inode and
         actual['3'] == 'socket:['+str(control_inode)+']', 'PREBOUND_DESCRIPTOR_DRIFT')
    import fcntl
    fd = os.open(proc/'root/state/launch.lock', os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        try: fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: pass
        else: raise Refusal('PREPARATION_LOCK_NOT_HELD')
    finally: os.close(fd)
    need(not (proc/'root/state/launch.json').exists() and
         not (proc/'root/state/launch.json.next').exists(), 'PREPARATION_ALREADY_ATTEMPTED')
    lease.check(stopped=True)


def write_generation(owned, lease, generation, files):
    raw = encode({'version': 1, 'context': CONTEXT, 'generation': generation,
                  'supervisor': {'pid': lease.pid, 'start': lease.start},
                  'filesSha256': sha(encode(files)), 'accepted': False})
    fd = os.open('generation.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=owned.fd)
    try:
        need(os.write(fd, raw) == len(raw), 'GENERATION_RECORD_SHORT_WRITE')
        os.fsync(fd); os.fsync(owned.fd)
    finally: os.close(fd)


def constructor_peer(channel):
    import struct
    pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(uid == gid == 0 and
         (Path('/proc')/str(pid)/'cgroup').read_text().strip() == CGROUP,
         'FIXED_ROOT_CONSTRUCTOR_PEER_REQUIRED')
    return pid


def watch_main():
    """External finite owner in a DIFFERENT unit/cgroup. Never SIGCONT or GO.

    Until a separate exact acceptance is read and this service exits successfully,
    the independent operator MUST keep all coordinators/resumers excluded. After
    release this code never signals, removes roots or unlinks the control socket.
    """
    import struct
    deadline = time.monotonic()+PREPARE_SECONDS
    need(not os.path.lexists(ACCEPTANCE), 'STALE_ACCEPTANCE_PRESENT')
    plan = verify_input()
    owned = OwnedTree.create(RESOURCE)
    listener = control = lease = None
    registered = False
    register_identity = control_identity = None
    primary = None
    try:
        # AF_UNIX sockets belong to the creator's network namespace. Bind in the
        # SAME pinned namespace as the supervisor or its /proc/PID/net/unix table
        # cannot satisfy the real prepared-listen consumer predicate.
        join_private_network(plan)
        listener, register_identity = bind_owned(REGISTER, socket.SOCK_SEQPACKET)
        control, control_identity = bind_owned(CONTROL)
        control_inode = os.fstat(control.fileno()).st_ino
        listener.listen(1)
        listener.settimeout(max(.001, deadline-time.monotonic()))
        channel, _ = listener.accept()
        with channel:
            pid = constructor_peer(channel)
            registered = True
            lease = ProcessLease(pid)
            generation = os.urandom(32).hex()
            write_generation(owned, lease, generation, plan['files'])
            channel.settimeout(min(2, max(.001, deadline-time.monotonic())))
            need(channel.recv(4096) == b'PREPARE\n', 'FIXED_PREPARE_REGISTRATION_REQUIRED')
            raw = encode({'generation': generation, 'filesSha256': sha(encode(plan['files']))})
            need(channel.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                         array.array('i', [control.fileno()]))]) == len(raw),
                 'CONTROL_RIGHT_DISPATCH_UNKNOWN')
        control.close(); control = None
        wait_prepared(lease, deadline, owned.check)
        check_prepared_resources(lease, control_inode)
        def acceptance():
            try: return decode(trusted_read(ACCEPTANCE, 16384))
            except FileNotFoundError: return None
        def policy():
            # Read from our host-side owned staging alias: /proc/PID/root's magic
            # symlink is deliberately not accepted by trusted_open.
            return decode(trusted_read(RESOURCE+'/root'+POLICY))
        def checkpoint():
            owned.check(); check_prepared_resources(lease, control_inode)
        wait_acceptance(lease, time.monotonic()+ACCEPT_SECONDS, acceptance,
                        plan['files'], generation, policy, checkpoint)
        # No GO/accepted inventory output. Unit Result=success is release of our
        # own preparation lease only; independent final acceptance is still external.
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_errors = []
        def cleanup(action):
            try: action()
            except BaseException as error: cleanup_errors.append(error)
        if lease is None or not lease.released:
            dead = not registered
            if registered and lease is None:
                cleanup_errors.append(Refusal('OWNED_PROCESS_DEATH_UNKNOWN'))
            if lease is not None:
                try: lease.abandon(); dead = True
                except BaseException as error: cleanup_errors.append(error)
            if dead:
                cleanup(owned.dispose)
                if control_identity is not None:
                    cleanup(lambda: unlink_owned_socket(CONTROL, control_identity))
        if register_identity is not None:
            cleanup(lambda: unlink_owned_socket(REGISTER, register_identity))
        for item in (listener, control, lease, owned):
            if item is not None: cleanup(item.close)
        if cleanup_errors:
            if primary is not None: primary.cleanup_errors = cleanup_errors
            else: raise Refusal('PHYSICAL_CLEANUP_UNKNOWN') from None
