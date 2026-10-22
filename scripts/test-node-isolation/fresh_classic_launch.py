#!/usr/bin/python3 -I
"""Dormant TEST-only one-shot exec from a separately provisioned sealed supervisor.

No install/provision/recovery CLI. Existing classic thaw is never called.
Platform is the read-only root/kernel inventory boundary; tests explicitly model
that boundary, never Popen/exec, HTTP, proc socket identity, journals or flocks.
"""
import array
import ctypes
import errno
import fcntl
import select
import signal
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import resource
import socket
import stat
import struct
import subprocess
import time
from contextlib import contextmanager

# The isolated installed CLI never imports from cwd/PYTHONPATH or executes .pyc.
# Programmatic local tests use the ordinary sibling module explicitly.
if 'c' in globals():
    pass  # Trusted coordinator loader injects its exact live module identity.
elif __name__ != '__main__':
    import coordinated_restore as c
else:
    import types
    def bootstrap_read(path):
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        try:
            for part in Path(path).parts[1:]:
                child=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                os.close(fd); fd=child; s=os.fstat(fd)
                if s.st_uid != 0 or s.st_gid != 0 or s.st_mode & 0o022:
                    raise RuntimeError('UNTRUSTED_BOOTSTRAP')
            if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > 8388608:
                raise RuntimeError('UNTRUSTED_BOOTSTRAP_FILE')
            return os.read(fd,8388609)
        finally: os.close(fd)
    accepted=json.loads(bootstrap_read('/etc/c3-test-fresh-classic.json'))
    path='/usr/local/libexec/c3-test-coordinated-restore.py'
    raw=bootstrap_read(path)
    if hashlib.sha256(raw).hexdigest() != accepted['files'][path]:
        raise RuntimeError('COORDINATOR_SOURCE_PIN_REQUIRED')
    c=types.ModuleType('coordinated_restore'); c.__file__=path
    exec(compile(raw,path,'exec'),c.__dict__)

POLICY = '/etc/c3-test-fresh-classic.json'
SOCKET = '/run/c3-test-fresh-classic.sock'
ATTEMPT = c.STATE + '/fresh-launch-attempt.json'
SUPERVISOR_ATTEMPT = '/state/launch.json'
LOCK = '/state/launch.lock'
ACTIVATION = ['fresh-classic-process']
READY_BODY_SHA256 = '437210538daa3691735d03ab798dbba7bef28404e621f17ea569a6b28c370da6'
CGROUP = '/system.slice/c3-test-fresh-classic.service'
ENV = {'C3_SETTINGS':'/etc/classic.json', 'NODE_ENV':'production'}


def need(value, code):
    if not value:
        raise c.Refusal(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def start(pid):
    return c.proc_start(pid)


def http_probe(ip, port):
    conn = http.client.HTTPConnection(ip, port, timeout=.5)
    try:
        conn.request('GET', '/classic-ready', headers={'Connection':'close'})
        response = conn.getresponse()
        body = response.read(65537)
        need(response.status == 200 and len(body) <= 65536, 'SERVING_HTTP_REFUSED')
        return body
    finally:
        conn.close()


def bound_http_probe(pid,ip,port):
    conn=http.client.HTTPConnection(ip,port,timeout=.5)
    try:
        conn.request('GET','/classic-ready',headers={'Connection':'keep-alive'})
        response=conn.getresponse(); body=response.read(65537)
        need(response.status == 200 and len(body) <= 65536 and conn.sock is not None, 'KEEPALIVE_SERVING_PROOF_REQUIRED')
        clientip,clientport=conn.sock.getsockname()
        def endpoint(address,number): return socket.inet_aton(address)[::-1].hex().upper()+f':{number:04X}'
        rows=[x.split() for x in (Path('/proc')/str(pid)/'net/tcp').read_text().splitlines()[1:]]
        matching={x[9] for x in rows if x[1] == endpoint(ip,port) and x[2] == endpoint(clientip,clientport) and x[3] == '01'}
        owned=set()
        for path in (Path('/proc')/str(pid)/'fd').iterdir():
            try: target=os.readlink(path)
            except FileNotFoundError: continue
            if re.fullmatch(r'socket:\[[0-9]+\]',target): owned.add(target[8:-1])
        need(len(matching & owned) == 1,'HTTP_RESPONSE_NOT_BOUND_TO_SERVING_PID')
        return body
    finally: conn.close()


def observe(pid, ip, port):
    """Actual host PID/start + inode-owned LISTEN, never a child success receipt."""
    proc = Path('/proc')/str(pid)
    before = start(pid)
    sockets = set()
    for fd in (proc/'fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if re.fullmatch(r'socket:\[[0-9]+\]', target):
            sockets.add(target[8:-1])
    address = socket.inet_aton(ip)[::-1].hex().upper()+f':{port:04X}'
    listeners = [line.split()[9] for line in (proc/'net/tcp').read_text().splitlines()[1:]
                 if line.split()[1] == address and line.split()[3] == '0A']
    owned = sockets.intersection(listeners)
    need(len(owned) == 1, 'SERVING_PID_SOCKET_BINDING_REQUIRED')
    result = {'pid':pid, 'start':before, 'cgroup':(proc/'cgroup').read_text().strip(),
              'socketInode':owned.pop(), 'bodySha256':digest(bound_http_probe(pid,ip,port))}
    need(start(pid) == before, 'SERVING_PID_REUSED')
    return result


def validate(policy):
    need(type(policy) is dict and set(policy) == {'version','context','executable','source','settings','files',
                         'environment','uid','gid','cgroup','ingress','inventory'}, 'EXACT_FRESH_POLICY_REQUIRED')
    need(type(policy['version']) is int and policy['version'] == 1 and
         policy['context'] == 'test.infograd.online' and
         (policy['executable'],policy['source'],policy['settings']) ==
         ('/runtime/node','/app/index.js','/etc/classic.json') and
         type(policy['environment']) is dict and policy['environment'] == ENV and
         type(policy['uid']) is int and type(policy['gid']) is int and policy['uid'] == policy['gid'] == 65531 and
         policy['cgroup'] == CGROUP, 'FIXED_FRESH_CONSTRUCTION_REQUIRED')
    need(type(policy['files']) is dict and len(policy['files']) <= 50000 and
         {policy['executable'],policy['source'],policy['settings']} <= policy['files'].keys(), 'SOURCE_SETTINGS_CLOSURE_REQUIRED')
    for path, pin in policy['files'].items():
        need(type(path) is str and path.startswith('/') and '..' not in Path(path).parts and
             str(Path(path)) == path and type(pin) is str and c.DIGEST.fullmatch(pin), 'INVALID_CLOSURE_PIN')
    ingress = policy['ingress']
    need(type(ingress) is dict and set(ingress) == {'ip','port','path','bodySha256'} and ingress['ip'] == '212.119.42.100' and
         type(ingress['port']) is int and ingress['port'] == 3000 and ingress['path'] == '/classic-ready' and
         type(ingress['bodySha256']) is str and ingress['bodySha256'] == READY_BODY_SHA256, 'FIXED_TEST_INGRESS_REQUIRED')
    inv=policy['inventory']
    need(type(inv) is dict and set(inv) == {'supervisor','root','namespaces','mountinfoSha256','routesSha256',
         'coordinatorSha256','sourceSha256','unitSha256','fdPins','hostNamespaces'}, 'INDEPENDENT_RESOURCE_INVENTORY_REQUIRED')
    need(all(type(inv[k]) is str and c.DIGEST.fullmatch(inv[k]) for k in
         ('mountinfoSha256','routesSha256','coordinatorSha256','sourceSha256','unitSha256')), 'INVALID_INVENTORY_PIN')
    supervisor=inv['supervisor']
    need(type(supervisor) is dict and set(supervisor) == {'pid','start'} and
         type(supervisor['pid']) is int and supervisor['pid'] > 0 and
         type(supervisor['start']) is str and re.fullmatch(r'[0-9]+',supervisor['start']), 'INVALID_SUPERVISOR_PIN')
    need(type(inv['root']) is list and len(inv['root']) == 2 and
         all(type(x) is int and x >= 0 for x in inv['root']), 'INVALID_ROOT_PIN')
    for key in ('namespaces','hostNamespaces'):
        need(type(inv[key]) is dict and set(inv[key]) == {'mnt','net','ipc','uts'} and
             all(type(x) is str and x for x in inv[key].values()), 'INVALID_NAMESPACE_PIN')
    need(type(inv['fdPins']) is dict and all(type(k) is str and re.fullmatch(r'[0-9]+',k) and
         type(v) is list and len(v) == 3 and all(type(x) is int and x >= 0 for x in v)
         for k,v in inv['fdPins'].items()), 'INVALID_DESCRIPTOR_PIN')
    return policy


def verify_files(policy, paths):
    """Hash real accepted file bytes; tests may map only the modeled root paths."""
    for name, expected in policy['files'].items():
        path=paths(name)
        with open(path,'rb') as stream:
            before=os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_size <= 256*1024*1024, 'CLOSURE_FILE_REQUIRED')
            hasher=hashlib.sha256()
            while True:
                block=stream.read(65536)
                if not block: break
                hasher.update(block)
            after=os.fstat(stream.fileno())
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and
             hasher.hexdigest() == expected, 'EXECUTABLE_SOURCE_SETTINGS_CLOSURE_DRIFT')


@contextmanager
def retained_path_identity(path):
    # Follow the proc root magic link deliberately, not a pathname/stat fallback.
    fd=os.open(path,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC); primary=None
    try:
        info=os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode), 'FRESH_ROOT_DIRECTORY_REQUIRED')
        raw=(Path('/proc/self/fdinfo')/str(fd)).read_bytes()
        rows=[line.split(':',1)[1].strip() for line in raw.decode().splitlines() if line.startswith('mnt_id:')]
        need(len(raw) <= 65536 and len(rows) == 1 and re.fullmatch(r'[1-9][0-9]*',rows[0]), 'ROOT_FDINFO_MOUNT_ID_REQUIRED')
        yield info,int(rows[0])  # retain ownership through mountinfo comparison
    except BaseException as error:
        primary=error; raise
    finally:
        try: os.close(fd)
        except BaseException:
            if primary is None: raise


RESOURCE_PLAN = '/var/lib/c3-test-fresh-input/resource-plan.json'
NETNS = '/run/netns/c3-test-fresh-classic'
_NEWNET = 0x40000000
_PROBE_LIMIT = 4096


def _input_snapshot(fs, path):
    # Trusted descriptor walk; retain raw bytes AND identity, not JSON equality
    # (which admits true/1). Replacements with identical bytes also refuse.
    with fs.opened(path) as fd:
        before=os.fstat(fd)
        need(before.st_size <= 8388608, 'CONTROLLER_INPUT_LIMIT')
        raw=os.pread(fd,8388609,0); after=os.fstat(fd)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        identity=tuple(getattr(before,k) for k in fields)
        need(len(raw) == before.st_size and len(raw) <= 8388608 and
             identity == tuple(getattr(after,k) for k in fields),
             'CONTROLLER_INPUT_DRIFT')
        return raw,identity


class _ControllerNamespace:
    """Private fixed read-only probe boundary, never an owner or constructor.

    No callbacks/commands/paths from requests, environment, policy or CLI. Only
    the fixture-gated Platform injection can model kernel facts in local tests.
    """
    def __init__(self, fs, policy):
        self.fs=fs; self.policy=policy; self.fd=None; self.supervisor_fd=None
        self.serving_fd=None; self.serving=None

    def _host(self):
        need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
             'ROOT_CONTROLLER_PROBE_REQUIRED')
        for ns in ('pid','mnt','net'):
            need(os.readlink('/proc/self/ns/'+ns) == os.readlink('/proc/1/ns/'+ns),
                 'HOST_CONTROLLER_VIEW_REQUIRED')

    def _host_net(self):
        return os.readlink('/proc/1/ns/net')

    def _open_net(self):
        fd=None
        try:
            with self.fs.opened('/run/netns',directory=True) as parent:
                fd=os.open('c3-test-fresh-classic',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            return fd
        except BaseException as primary:
            # Own the leaf even if directory-context disposal fails AFTER open.
            if fd is not None:
                try: os.close(fd)
                except BaseException as error:
                    primary.cleanup_errors=(*getattr(primary,'cleanup_errors',()),error)
            raise

    def _type(self):
        return fcntl.ioctl(self.fd,0xb703)  # NS_GET_NSTYPE also proves nsfs

    def _net(self, pid):
        info=os.stat('/proc/'+str(pid)+'/ns/net')
        return info.st_dev,info.st_ino

    def _join(self):
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.setns(self.fd,_NEWNET) != 0:
            raise OSError(ctypes.get_errno(),'CONTROLLER_NET_SETNS_REFUSED')

    def _serving_group(self):
        return '0::'+CGROUP

    def _observe(self, pid):
        return observe(pid,'212.119.42.100',3000)  # existing literal proof unchanged

    def acquire(self):
        self._host()
        self.inputs={path:_input_snapshot(self.fs,path) for path in (POLICY,RESOURCE_PLAN)}
        self.policy_bytes=c.canonical(self.policy)
        need(c.canonical(c.decode(self.inputs[POLICY][0])) == self.policy_bytes,
             'ACCEPTED_FRESH_POLICY_DRIFT')
        plan=c.decode(self.inputs[RESOURCE_PLAN][0])
        need(type(plan) is dict and set(plan) == {'version','context','files','networkNamespace'} and
             type(plan['version']) is int and plan['version'] == 1 and
             plan['context'] == 'test.infograd.online' and
             c.canonical(plan['files']) == c.canonical(self.policy['files']),
             'ACCEPTED_RESOURCE_PLAN_REQUIRED')
        pin=plan['networkNamespace']
        need(type(pin) is dict and set(pin) == {'device','inode'} and
             all(type(pin[k]) is int and pin[k] > 0 for k in pin), 'ACCEPTED_NETNS_PIN_REQUIRED')
        self.identity=(pin['device'],pin['inode'])
        self.fd=self._open_net()
        supervisor=self.policy['inventory']['supervisor']
        self.supervisor_fd=os.pidfd_open(supervisor['pid'],0)
        self.check()
        return self

    def check(self):
        self._host()
        need(c.canonical(self.policy) == self.policy_bytes, 'CONTROLLER_POLICY_MEMORY_DRIFT')
        need(all(_input_snapshot(self.fs,path) == value for path,value in self.inputs.items()),
             'CONTROLLER_ACCEPTED_INPUT_DRIFT')
        info=os.fstat(self.fd)
        need((info.st_dev,info.st_ino) == self.identity and
             info.st_uid == self.fs.uid and info.st_gid == self.fs.gid and not info.st_mode & 0o022 and
             self._type() == _NEWNET and
             self.identity != self._net(1), 'ACCEPTED_PRIVATE_NETNS_REQUIRED')
        # Opening is never authority: the fixed path must still name the retained
        # accepted object, but is NEVER substituted for the retained FD.
        other=self._open_net(); primary=None
        try:
            now=os.fstat(other)
            need((now.st_dev,now.st_ino) == self.identity,'ACCEPTED_NETNS_REPLACED')
        except BaseException as error:
            primary=error; raise
        finally:
            try: os.close(other)
            except BaseException as error:
                if primary is None: raise
                primary.cleanup_errors=(*getattr(primary,'cleanup_errors',()),error)
        supervisor=self.policy['inventory']['supervisor']
        need(not select.select([self.supervisor_fd],[],[],0)[0] and
             start(supervisor['pid']) == supervisor['start'] and
             self._net(supervisor['pid']) == self.identity and
             self.policy['inventory']['namespaces']['net'] == f'net:[{self.identity[1]}]' and
             self.policy['inventory']['hostNamespaces']['net'] == self._host_net(),
             'ACCEPTED_SUPERVISOR_NETNS_DRIFT')
        self._serving_identity()

    def bind_serving(self, expected):
        self.serving=dict(expected)
        self.serving_fd=os.pidfd_open(expected['pid'],0)
        self._serving_identity()

    def _serving_identity(self):
        if self.serving is None: return
        pid=self.serving['pid']
        need(not select.select([self.serving_fd],[],[],0)[0] and
             start(pid) == self.serving['start'] and self._net(pid) == self.identity and
             (Path('/proc')/str(pid)/'cgroup').read_text().strip() == self._serving_group(),
             'SERVING_IDENTITY_DRIFT')

    def child_observe(self, pid, expected):
        # Inherited authority descriptors have already closed. No fs/h/lease
        # method is called here; this is observation, not fresh acceptance.
        self._host()
        need(not select.select([self.supervisor_fd],[],[],0)[0], 'PROBE_SUPERVISOR_LOST')
        before={ns:os.readlink('/proc/self/ns/'+ns) for ns in ('pid','mnt','user','ipc','uts','cgroup')}
        info=os.fstat(self.fd)
        need((info.st_dev,info.st_ino) == self.identity and self._type() == _NEWNET,
             'RETAINED_PROBE_NETNS_DRIFT')
        self._join()
        need(self._net('self') == self.identity and
             before == {ns:os.readlink('/proc/self/ns/'+ns) for ns in before},
             'PROBE_NET_MEMBERSHIP_REQUIRED')
        self._serving_identity()
        need(self._net(pid) == self.identity, 'SERVING_NETNS_DRIFT')
        result=self._observe(pid)
        self._serving_identity()
        need(self._net(pid) == self.identity and result == expected and
             result['cgroup'] == self._serving_group() and
             result['bodySha256'] == self.policy['ingress']['bodySha256'], 'ACTUAL_SERVING_REQUIRED')
        return result

    def close(self):
        errors=[]
        for name in ('fd','supervisor_fd','serving_fd'):
            fd=getattr(self,name); setattr(self,name,None)
            if fd is not None:
                try: os.close(fd)
                except BaseException as error: errors.append(error)
        if errors: raise errors[0]


def _probe_child(target, writer, pid, expected, deadline):
    # fork inherits ALL root authority, including OFD flocks and pipe writers.
    # Close it before setns/TCP, not just on exec (this child never execs).
    status=1
    try:
        def expired(*_): raise c.Refusal('CONTROLLER_PROBE_TIMEOUT')
        signal.signal(signal.SIGALRM,expired)
        remaining=deadline-time.monotonic()
        need(remaining > 0,'CONTROLLER_PROBE_TIMEOUT')
        signal.setitimer(signal.ITIMER_REAL,remaining)
        keep={writer,target.fd,target.supervisor_fd,target.serving_fd}
        fds=[int(x) for x in os.listdir('/proc/self/fd')]
        for fd in fds:
            if fd in keep: continue
            try: os.fstat(fd)
            except OSError as error:
                if error.errno == errno.EBADF: continue  # closed fd-directory iterator
                raise
            os.close(fd)  # close errors are refusal, never a success frame
        result=target.child_observe(pid,expected)
        target.close()  # checked owned-fd disposal BEFORE publishing success
        raw=c.canonical(result)
        need(len(raw) <= _PROBE_LIMIT, 'PROBE_RESULT_LIMIT')
        need(os.write(writer,raw) == len(raw), 'PROBE_WRITE_UNKNOWN')
        os.close(writer); status=0
    except BaseException:
        pass  # bounded EOF/nonzero status, no untrusted exception serialization
    os._exit(status)


def _controller_observe(target, expected, held, deadline):
    need(type(expected) is dict and set(expected) == {'pid','start','cgroup','socketInode','bodySha256'} and
         type(expected['pid']) is int and expected['pid'] > 0 and
         all(type(expected[k]) is str for k in ('start','cgroup','socketInode','bodySha256')),
         'EXACT_SERVING_RESULT_REQUIRED')
    target.bind_serving(expected)
    target.check(); held.check()
    # Reserve cleanup inside (never after) the enclosing wire/hold budget.
    # A stuck kernel task can still refuse REAP_UNKNOWN; no unbounded wait.
    now=time.monotonic()
    io_deadline=deadline-min(.1,max(0,(deadline-now)/4))
    reader,writer=os.pipe2(os.O_CLOEXEC|os.O_NONBLOCK); child=None; reaped=False; primary=None
    try:
        need(time.monotonic() < deadline,'CONTROLLER_PROBE_TIMEOUT')
        child=os.fork()
        if child == 0: _probe_child(target,writer,expected['pid'],expected,io_deadline)
        os.close(writer); writer=None
        raw=b''
        while True:
            remaining=io_deadline-time.monotonic()
            need(remaining > 0,'CONTROLLER_PROBE_TIMEOUT')
            ready=select.select([reader,*held.watch()],[],[],remaining)[0]
            need(ready and all(fd == reader for fd in ready),'CONTROLLER_PROBE_HOLD_LOST')
            part=os.read(reader,_PROBE_LIMIT+1-len(raw)); raw+=part
            need(len(raw) <= _PROBE_LIMIT,'PROBE_RESULT_LIMIT')
            if not part: break
        while True:
            got,status=os.waitpid(child,os.WNOHANG)
            if got: reaped=True; break
            need(time.monotonic() < io_deadline,'CONTROLLER_PROBE_REAP_TIMEOUT')
            time.sleep(min(.001,max(0,io_deadline-time.monotonic())))
        need(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,'CONTROLLER_PROBE_FAILED')
        result=c.decode(raw)
        need(c.canonical(result) == c.canonical(expected),'CONTROLLER_PROBE_RESULT_REFUSED')
        target.check(); held.check()
        need(time.monotonic() < deadline,'CONTROLLER_PROBE_TIMEOUT')
        return result
    except BaseException as error:
        primary=error; raise
    finally:
        errors=[]
        if child and not reaped:
            try: os.kill(child,signal.SIGKILL)
            except ProcessLookupError: pass
            except BaseException as error: errors.append(error)
            # No unbounded wait, even on a stuck kernel task. Only this exact
            # owned child is signaled; never the serving/supervisor processes.
            try:
                while True:
                    got,_=os.waitpid(child,os.WNOHANG)
                    if got: break
                    need(time.monotonic() < deadline,'CONTROLLER_PROBE_REAP_UNKNOWN')
                    time.sleep(min(.001,max(0,deadline-time.monotonic())))
            except BaseException as error: errors.append(error)
        for fd in (reader,writer):
            if fd is not None:
                try: os.close(fd)
                except BaseException as error: errors.append(error)
        if errors:
            if primary is None: raise errors[0]
            primary.cleanup_errors=(*getattr(primary,'cleanup_errors',()),*errors)


class Platform:
    """Read-only enforcement, NOT construction or attestation from a receipt.

    Supported setup: private read-only root + ro proc + private rw /state only,
    dedicated UID, zero caps/NNP, dedicated cgroup and net/mnt/ipc/uts namespaces.
    Accepted exact namespace, mount, route and root identities are supplied by a
    separate root installation/acceptance process. No automatic inventory capture.
    """
    def check(self, policy):
        validate(policy)
        p = Path('/proc/self')
        inv = policy['inventory']
        need(set(inv) == {'supervisor','root','namespaces','mountinfoSha256','routesSha256',
                         'coordinatorSha256','sourceSha256','unitSha256','fdPins','hostNamespaces'}, 'INDEPENDENT_RESOURCE_INVENTORY_REQUIRED')
        need(os.geteuid() == os.getegid() == 65531 and not os.getgroups(), 'DEDICATED_SUPERVISOR_IDENTITY_REQUIRED')
        status = dict(line.split(':',1) for line in (p/'status').read_text().splitlines() if ':' in line)
        need(all(int(status[k],16) == 0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) and
             status['NoNewPrivs'].strip() == '1', 'CAPABILITY_FREE_NNP_REQUIRED')
        need((p/'cgroup').read_text().strip() == '0::'+CGROUP, 'FRESH_CGROUP_REQUIRED')
        need(set(inv['namespaces']) == {'mnt','net','ipc','uts'}, 'EXACT_NAMESPACES_REQUIRED')
        for ns, pin in inv['namespaces'].items():
            need(os.readlink(p/'ns'/ns) == pin and pin != inv['hostNamespaces'][ns], 'PRIVATE_NAMESPACE_REQUIRED')
        self.root_mount(policy,p)
        need(digest((p/'net/route').read_bytes()+(p/'net/fib_trie').read_bytes()) == inv['routesSha256'], 'INGRESS_ROUTE_DRIFT')
        # Full root closure, not just node/index.js. No symlink, hardlink, device,
        # socket, writable file, xattr, or unlisted application/library is admitted.
        actual = {}
        for directory, dirs, names in os.walk('/', followlinks=False):
            if directory == '/': dirs[:] = [x for x in dirs if x not in ('proc','state')]
            for name in [*dirs,*names]:
                path = Path(directory)/name; info=path.lstat()
                need(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022 and
                     not info.st_mode & 0o6000 and not os.listxattr(path), 'UNTRUSTED_ROOT_ENTRY')
                if stat.S_ISDIR(info.st_mode): continue
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'SPECIAL_OR_LINKED_ROOT_ENTRY')
                # Policy is separately pinned by the root controller; exclude its
                # self-referential digest from the complete artifact manifest.
                if str(path) == POLICY: continue
                need(info.st_size <= 256*1024*1024, 'ROOT_FILE_LIMIT')
                actual[str(path)] = digest(path.read_bytes())
        need(actual == policy['files'], 'EXECUTABLE_SOURCE_SETTINGS_CLOSURE_DRIFT')
        # Validate every file-backed mapping, including Python/loader/libc, against
        # that root. Anonymous supervisor memory is trusted pinned source execution,
        # never copied from the old Node. Executable anonymous/deleted maps refuse.
        for line in (p/'maps').read_text().splitlines():
            fields=line.split(None,5)
            if len(fields) == 6 and fields[5].startswith('/'):
                need(fields[5] in actual and '(deleted)' not in fields[5], 'MAPPED_SOURCE_OUTSIDE_FRESH_ROOT')
                mapped=os.stat(fields[5])
                device=':'.join(f'{x:02x}' for x in (os.major(mapped.st_dev),os.minor(mapped.st_dev)))
                need(str(mapped.st_ino) == fields[4] and device == fields[3], 'STALE_MAPPED_FILE_IDENTITY')
            elif 'x' in fields[1]:
                need(len(fields) == 6 and fields[5] in ('[vdso]','[vsyscall]'), 'ANONYMOUS_EXECUTABLE_MAPPING')

    def root_mount(self, policy, p):
        inv=policy['inventory']
        with retained_path_identity(p/'root') as (root,mount_id):
            need([root.st_dev,root.st_ino] == inv['root'], 'FRESH_ROOT_IDENTITY_REQUIRED')
            mounts = (p/'mountinfo').read_bytes()
            need(len(mounts) <= 1048576 and digest(mounts) == inv['mountinfoSha256'], 'MOUNT_INVENTORY_DRIFT')
            targets = set()
            for line in mounts.decode().splitlines():
                fields = line.split(); sep = fields.index('-'); target = fields[4]; opts=set(fields[5].split(','))
                need(target not in targets and target in ('/','/proc','/state') and
                     {'nodev','nosuid'} <= opts and not any(':' in x for x in fields[6:sep]), 'EXACT_NO_DEVICE_PRIVATE_MOUNTS_REQUIRED')
                need(('rw' in opts and fields[sep+1] == 'tmpfs' and 'noexec' in opts) if target == '/state'
                     else ('ro' in opts and 'rw' not in opts), 'READ_ONLY_SOURCE_ROOT_REQUIRED')
                if target == '/proc': need(fields[sep+1] == 'proc' and fields[3] == '/', 'WHOLE_READONLY_PROC_REQUIRED')
                if target == '/': need(fields[0] == str(mount_id), 'FRESH_ROOT_MOUNT_IDENTITY_REQUIRED')
                targets.add(target)
            need(targets == {'/','/proc','/state'}, 'EXACT_RESOURCE_MOUNTS_REQUIRED')

    def entry_fds(self, policy):
        actual={}
        for leaf in Path('/proc/self/fd').iterdir():
            try:
                fd=int(leaf.name); info=os.fstat(fd); target=os.readlink(leaf)
            except FileNotFoundError: continue
            except OSError: continue  # transient FD used by the fd-directory iterator
            if fd in (0,1,2):
                need(stat.S_ISREG(info.st_mode) and target.startswith('/memfd:c3-supervisor-stdio'), 'FRESH_ANONYMOUS_STDIO_REQUIRED')
            elif fd == 3:
                need(stat.S_ISSOCK(info.st_mode), 'PREBOUND_CONTROL_SOCKET_REQUIRED')
            else:
                need(target in ('/state','/state/launch.lock'), 'UNACCEPTED_INHERITED_DESCRIPTOR')
            actual[str(fd)]=[info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode)]
        need(actual == policy['inventory']['fdPins'], 'INDEPENDENT_FRESH_DESCRIPTOR_PINS_REQUIRED')

    def paths(self, policy):
        return [policy['executable'],policy['source']], dict(ENV), '/app'

    def supervisor(self, policy, pid):
        inv=policy['inventory']; expected=inv['supervisor']
        need(expected == {'pid':pid,'start':start(pid)}, 'ACCEPTED_SUPERVISOR_REQUIRED')
        proc=Path('/proc')/str(pid)
        verify_files(policy,lambda name: proc/'root'/name.lstrip('/'))
        need(inv['hostNamespaces'] == {ns:os.readlink(Path('/proc/1/ns')/ns) for ns in ('mnt','net','ipc','uts')}, 'HOST_NAMESPACE_PIN_DRIFT')
        for ns,pin in inv['namespaces'].items():
            need(os.readlink(proc/'ns'/ns) == pin and pin != inv['hostNamespaces'][ns], 'SUPERVISOR_NAMESPACE_DRIFT')
        need((proc/'cgroup').read_text().strip() == '0::'+CGROUP, 'SUPERVISOR_CGROUP_DRIFT')
        group=Path('/sys/fs/cgroup')/CGROUP.lstrip('/')
        need((group/'cgroup.procs').read_text().split() == [str(pid)] and
             (group/'cgroup.freeze').read_text().strip() == '0', 'FRESH_SINGLE_SUPERVISOR_CGROUP_REQUIRED')
        need(digest(c.trusted_read(c.SELF)) == inv['sourceSha256'], 'COORDINATOR_SOURCE_DRIFT')
        unit=c.trusted_read('/etc/systemd/system/c3-test-fresh-classic.service')
        need(digest(unit) == inv['unitSha256'] and b'Restart=no\n' in unit and
             b'KillMode=process\n' in unit, 'ONE_SHOT_INDEPENDENT_SUPERVISOR_REQUIRED')
        # Read actual loaded properties; a file pin alone cannot exclude Restart.
        r=subprocess.run(['/usr/bin/systemctl','show','c3-test-fresh-classic.service',
                          '--property=MainPID,Restart,KillMode,ControlGroup,NeedDaemonReload,RestartForceExitStatus'],
                         env=c.CLEAN_ENV,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2,check=True)
        values=dict(line.split('=',1) for line in r.stdout.decode().splitlines())
        need(values == {'MainPID':str(pid),'Restart':'no','KillMode':'process',
                        'ControlGroup':CGROUP,'NeedDaemonReload':'no','RestartForceExitStatus':''}, 'LOADED_SUPERVISOR_DRIFT')
        return expected

    def prepared(self, policy, pid):
        """Controller readback of the accepted stopped generation, never capture."""
        self.supervisor(policy, pid)  # source/files, namespaces, sole cgroup, loaded unit
        proc=Path('/proc')/str(pid)
        status=dict(line.split(':',1) for line in (proc/'status').read_text().splitlines() if ':' in line)
        need(status['State'].split()[0] == 'T' and
             [p.name for p in (proc/'task').iterdir()] == [str(pid)], 'STOPPED_SINGLE_SUPERVISOR_REQUIRED')
        need(status['Uid'].split() == ['65531']*4 and status['Gid'].split() == ['65531']*4 and
             not status['Groups'].split(), 'DEDICATED_SUPERVISOR_IDENTITY_REQUIRED')
        need(all(int(status[k],16) == 0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) and
             status['NoNewPrivs'].strip() == '1', 'CAPABILITY_FREE_NNP_REQUIRED')
        self.root_mount(policy,proc)
        need(digest((proc/'net/route').read_bytes()+(proc/'net/fib_trie').read_bytes()) ==
             policy['inventory']['routesSha256'], 'INGRESS_ROUTE_DRIFT')
        with (proc/'root'/POLICY.lstrip('/')).open('rb') as stream:
            raw=stream.read(8388609)
        need(len(raw) <= 8388608 and c.canonical(c.decode(raw)) == c.canonical(policy),
             'SUPERVISOR_POLICY_DRIFT')
        actual={}
        for leaf in (proc/'fd').iterdir():
            info=leaf.stat()
            actual[leaf.name]=[info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode)]
        need(actual == policy['inventory']['fdPins'] and {'0','1','2','3'} <= actual.keys() and
             actual['3'][2] == stat.S_IFSOCK, 'INDEPENDENT_FRESH_DESCRIPTOR_PINS_REQUIRED')
        for fd in ('0','1','2'):
            need(actual[fd][2] == stat.S_IFREG and
                 os.readlink(proc/'fd'/fd).startswith('/memfd:c3-supervisor-stdio'),
                 'FRESH_ANONYMOUS_STDIO_REQUIRED')
        need(start(pid) == policy['inventory']['supervisor']['start'], 'ACCEPTED_SUPERVISOR_REQUIRED')

    def controller_namespace(self, fs, policy):
        return _ControllerNamespace(fs,policy)

    def endpoint(self, policy):
        return policy['ingress']['ip'],policy['ingress']['port']

    def observe(self, policy, pid):
        result=observe(pid,*self.endpoint(policy))
        need(result['cgroup'] == '0::'+CGROUP, 'SERVING_CGROUP_DRIFT')
        return result


def settlement(held, proof):
    # Same current all-five ownership contract as the existing irreversible path;
    # distinct activation set. No existing-backend permit is accepted or relabeled.
    need(type(proof) is dict and set(proof) == {'context','revision','deployedRevision','quietSha256','nodes'} and
         proof['context'] == held.config['context'] and type(proof['quietSha256']) is str and c.DIGEST.fullmatch(proof['quietSha256']) and
         all(type(proof[k]) is int and proof[k] >= 0 for k in ('revision','deployedRevision')), 'SETTLEMENT_REQUIRED')
    need(type(proof['nodes']) is list and len(proof['nodes']) == 5 and
         all(type(n) is dict and type(n.get('nodeId')) is str for n in proof['nodes']) and
         {n['nodeId'] for n in proof['nodes']} == set(c.NODES), 'EXACT_FIVE_OWNERS_REQUIRED')
    for item in proof['nodes']:
        need(set(item) == {'nodeId','targetProfile','enrollmentId','enrollmentSha256','priorOwnerGeneration','owner'} and
             type(item['enrollmentSha256']) is str and type(item['owner']) is dict and
             {'owner','generation','handbackReceipt','nodeIdentity'} <= item['owner'].keys() and
             type(item['owner']['handbackReceipt']) is dict and
             {'fromGeneration','toGeneration'} <= item['owner']['handbackReceipt'].keys() and
             type(item['owner']['nodeIdentity']) is dict, 'EXACT_GENERATION_REQUIRED')
        pin=held.config['nodes'][item['nodeId']]; owner=item['owner']
        need(set(item) == {'nodeId','targetProfile','enrollmentId','enrollmentSha256','priorOwnerGeneration','owner'} and
             item['targetProfile'] == pin['identity']['targetProfile'] and c.DIGEST.fullmatch(item['enrollmentSha256']) and
             owner['owner'] == 'classic' and owner['generation'] != item['priorOwnerGeneration'] and
             owner['handbackReceipt']['fromGeneration'] == item['priorOwnerGeneration'] and
             owner['handbackReceipt']['toGeneration'] == owner['generation'] and
             owner['nodeIdentity'] == {k:pin['identity'][k] for k in ('machineId','sshHostKeySha256')}, 'EXACT_GENERATION_REQUIRED')


class FreshLaunch:
    """Internal trusted-root composition; no caller launch callback or public CLI.

    Requires the actual already-open Coordinator; neither a bool nor JSON receipt
    supplies its live lexical authority. Only the separate fixed fresh root
    composition admits the terminal bridge; no application/request/env selection.
    """
    def __init__(self, held, platform=None, *, socket_path=None):
        need(type(held) is c.Coordinator, 'ACTUAL_HELD_COORDINATOR_REQUIRED')
        need(socket_path is None or held.fs.fixture is not None, 'FIXTURE_SOCKET_FORBIDDEN')
        need(platform is None or held.fs.fixture is not None, 'SIMULATED_PLATFORM_FORBIDDEN')
        self.held=held; self.platform=platform or Platform(); self.path=socket_path or SOCKET
        self.used=False

    def _control_listening(self, policy):
        """Observe fd3's kernel AF_UNIX row; NEVER probe-connect the sole accept."""
        pid=policy['inventory']['supervisor']['pid']; proc=Path('/proc')/str(pid)
        info=(proc/'fd/3').stat(); pin=policy['inventory']['fdPins'].get('3')
        need(pin == [info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode)] and
             stat.S_ISSOCK(info.st_mode) and os.readlink(proc/'fd/3') == f'socket:[{info.st_ino}]',
             'PREPARED_CONTROL_FD_DRIFT')
        with (proc/'net/unix').open('rb') as stream: raw=stream.read(1048577)
        need(len(raw) <= 1048576, 'PREPARED_UNIX_TABLE_LIMIT')
        rows=[line.split(None,7) for line in raw.decode().splitlines()[1:]]
        matching=[row for row in rows if len(row) >= 7 and row[6] == str(info.st_ino)]
        need(len(matching) == 1 and len(matching[0]) == 8 and matching[0][7] == self.path and
             matching[0][4:6] == ['0001','01'] and matching[0][3] in ('00000000','00010000'),
             'PREPARED_CONTROL_SOCKET_REQUIRED')
        return matching[0][3] == '00010000'

    def _resume_prepared(self, policy):
        h=self.held
        need(not h.prepared_resume_attempted, 'PREPARED_RESUME_REPLAY_FORBIDDEN')
        h.prepared_resume_attempted=True  # latch even validation/readiness faults
        pid=policy['inventory']['supervisor']['pid']; fd=None
        try:
            fd=os.pidfd_open(pid,0)  # no PID-based signal fallback
            def identity():
                need(not c.select.select([fd],[],[],0)[0] and
                     start(pid) == policy['inventory']['supervisor']['start'], 'PREPARED_SUPERVISOR_LOST')
            identity(); self.platform.prepared(policy,pid)
            need((Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[0] == 'T',
                 'STOPPED_SINGLE_SUPERVISOR_REQUIRED')
            need(not self._control_listening(policy), 'PREPARED_SOCKET_ALREADY_LISTENING')
            h.check(); identity()
            c.signal.pidfd_send_signal(fd,c.signal.SIGCONT,None,0)  # exactly one attempt
            deadline=min(h.deadline,time.monotonic()+3)
            deadlines=[(channel.wire,channel.wire.deadline) for channel in h.nodes]
            try:
                # All-five checkpoints share the readiness budget too; a silent
                # peer cannot stretch this wait to the outer restoration lease.
                for wire,old in deadlines: wire.deadline=min(old,deadline)
                while True:
                    h.check(); identity()
                    need(time.monotonic() < deadline, 'PREPARED_LISTEN_TIMEOUT')
                    listening=self._control_listening(policy)
                    identity()
                    if listening: return fd
                    time.sleep(min(.01,max(0,deadline-time.monotonic())))
            finally:
                for wire,old in deadlines: wire.deadline=old
        except BaseException as primary:
            if fd is not None:
                try: os.close(fd)
                except BaseException as error:
                    primary.cleanup_errors=(*getattr(primary,'cleanup_errors',()),error)
            raise

    def run_prepared(self, proof):
        """Fixed fresh-owner composition only, after public all-five settlement."""
        return self._run(proof, prepared=True)

    def run(self, proof):
        return self._run(proof, prepared=False)  # ordinary supervisor path unchanged

    def _run(self, proof, *, prepared):
        need(not self.used, 'FRESH_LAUNCH_REPLAY_FORBIDDEN'); self.used=True
        h=self.held; fs=h.fs; conn=None; primary=None; lifetime=None; target=None
        confirmation_attempted=False
        try:
            h.check(); settlement(h,proof)
            need(not h.commit_attempted and all(fs.absent(p) and fs.absent(p+'.next')
                 for p in (c.COMMIT,c.ACTIVATION,ATTEMPT)), 'HANDOFF_REPLAY_FORBIDDEN')
            policy=validate(fs.read_json(POLICY)); pin=digest(c.canonical(policy))
            need(policy['inventory']['coordinatorSha256'] == digest(c.canonical(h.config)),
                 'ACCEPTED_COORDINATOR_REQUIRED')
            if fs.fixture is None:
                with fs.opened('/run',directory=True) as fd:
                    s=os.stat(Path(SOCKET).name,dir_fd=fd,follow_symlinks=False)
                    need(stat.S_ISSOCK(s.st_mode) and s.st_uid == s.st_gid == 0 and
                         stat.S_IMODE(s.st_mode) == 0o600, 'ROOT_PREPROVISIONED_SOCKET_REQUIRED')
            if prepared:
                need(globals().get('_LOADED_SOURCE_SHA256') == policy['files'].get(c.FRESH) and
                     policy['files'].get(c.SELF) == policy['inventory']['sourceSha256'],
                     'EXECUTED_FRESH_SOURCE_DRIFT')
            target=self.platform.controller_namespace(fs,policy)
            target.acquire()  # BEFORE resume or irreversible COMMIT
            if prepared:
                lifetime=self._resume_prepared(policy)
            conn=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); conn.settimeout(3); conn.connect(self.path)
            pid,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            need(uid == (os.getuid() if fs.fixture else 65531), 'SUPERVISOR_UID_REQUIRED')
            supervisor=self.platform.supervisor(policy,pid)
            if prepared:
                need(supervisor == policy['inventory']['supervisor'] and
                     not c.select.select([lifetime],[],[],0)[0], 'PREPARED_SUPERVISOR_LOST')
            wire=c.Wire(conn.fileno(),conn.fileno(),time.monotonic()+5)
            hello=wire.receive()
            need(set(hello) == {'op','nonce','policySha256'} and hello['op'] == 'prepared' and
                 c.DIGEST.fullmatch(hello['nonce']) and hello['policySha256'] == pin, 'SOURCE_PREFLIGHT_REQUIRED')
            h.check()
            if prepared:
                need(c.canonical(fs.read_json(POLICY)) == c.canonical(policy), 'ACCEPTED_FRESH_POLICY_DRIFT')
            target.check(); h.check()
            row={'version':1,'context':h.config['context'],'nonce':h.nonce,
                 'configSha256':c.sha(c.canonical(h.config)), 'restoreIntent':h.intent,
                 'nodePins':h.config['nodes'], 'nodePeers':{x.node:{'pid':x.hello['pid'],'start':x.hello['start']} for x in h.nodes},
                 'settlement':proof, 'activationSet':ACTIVATION, 'freshPolicySha256':pin,'supervisor':supervisor}
            h.commit_attempted=True
            fs.atomic(c.COMMIT,c.canonical(row),new=True)
            need(fs.read_json(c.COMMIT) == row,'COMMIT_UNKNOWN_NO_ACTIVATION')
            h.commit_sha=c.sha(c.canonical(row)); h.check()
            for channel in h.nodes: channel.request('commit-phase',h.watch(channel),commit_sha=h.commit_sha)
            h.activation_attempted=True
            attempt={'commitSha256':h.commit_sha,'phase':'attempted','serving':None}
            fs.atomic(ATTEMPT,c.canonical(attempt),new=True); h.check()
            with fs.opened(c.COMMIT) as fd:
                raw=c.canonical({'op':'exec','nonce':hello['nonce'],'commitSha256':h.commit_sha})+b'\n'
                need(conn.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))]) == len(raw), 'EXEC_DISPATCH_UNKNOWN')
            reply=wire.receive(h.watch())
            need(set(reply) == {'op','serving'} and reply['op'] == 'serving', 'EXEC_RESULT_UNKNOWN')
            deadline=min(h.deadline,wire.deadline,*(x.wire.deadline for x in h.nodes))
            serving=_controller_observe(target,reply['serving'],h,deadline)
            need(serving == reply['serving'] and serving['bodySha256'] == policy['ingress']['bodySha256'], 'ACTUAL_SERVING_REQUIRED')
            target.check(); h.check()
            need(time.monotonic() < deadline,'CONTROLLER_CONFIRMATION_TIMEOUT')
            attempt.update(phase='confirmed',serving=serving)
            confirmation_attempted=True
            fs.atomic(ATTEMPT,c.canonical(attempt)); need(fs.read_json(ATTEMPT) == attempt,'CONFIRMATION_FSYNC_UNKNOWN')
            target.check(); h.check()
            need(time.monotonic() < deadline,'CONTROLLER_CONFIRMATION_TIMEOUT')
            if lifetime is not None:
                fd=lifetime; lifetime=None; os.close(fd)
            target.close(); target=None
            need(time.monotonic() < deadline,'CONTROLLER_CONFIRMATION_TIMEOUT')
            h.activation_confirmed=True; h.finish_handoff()
            wire.send({'op':'complete','commitSha256':h.commit_sha})
            need(wire.receive() == {'op':'complete-ack'}, 'SUPERVISOR_COMPLETION_UNKNOWN')
            conn.close(); conn=None
            return {'code':'COMMITTED_FRESH_ACTIVATION_CONFIRMED','activationSet':ACTIVATION,
                    'candidate':'closed','serving':serving}
        except BaseException as error:
            primary=error; error.code=h.failure_code()
            if h.commit_sha and confirmation_attempted:
                # A prior confirmation write is not a terminal success if any
                # subsequent identity/close/hold/ack boundary fails. No rollback.
                h.activation_confirmed=False
                try: fs.atomic(ATTEMPT,c.canonical({'commitSha256':h.commit_sha,'phase':'committed-activation-unknown','serving':None}))
                except BaseException as cleanup:
                    error.cleanup_errors=(*getattr(error,'cleanup_errors',()),cleanup)
            raise
        finally:
            try:
                c.dispose_socket(conn,h.failure_code(),primary)
            except BaseException as error:
                primary=primary or error
                raise
            finally:
                errors=[]
                if target is not None:
                    try: target.close()
                    except BaseException as error: errors.append(error)
                if lifetime is not None:
                    try: os.close(lifetime)
                    except BaseException as error: errors.append(error)
                if errors:
                    failure=primary if primary is not None else errors[0]
                    failure.code=h.failure_code()
                    failure.cleanup_errors=(*getattr(failure,'cleanup_errors',()),*errors)
                    if primary is None: raise failure


class SupervisorFiles:
    """Fixed root-readable policy and dedicated UID-owned private tmpfs journal.

    No host state directory is mounted into the fresh root. The only host object
    received is one root-owned mode-0600 COMMIT regular FD, immediately closed.
    """
    fixture=None
    uid=0

    @contextmanager
    def directory(self):
        fd=os.open('/state',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            s=os.fstat(fd)
            need(s.st_uid == s.st_gid == 65531 and stat.S_IMODE(s.st_mode) == 0o700, 'PRIVATE_FRESH_STATE_REQUIRED')
            yield fd
        finally: os.close(fd)

    def read_json(self,path):
        need(path == POLICY,'FIXED_SUPERVISOR_POLICY_ONLY')
        return c.decode(c.trusted_read(path))

    def absent(self,path):
        need(path in (SUPERVISOR_ATTEMPT,SUPERVISOR_ATTEMPT+'.next'),'FIXED_SUPERVISOR_JOURNAL_ONLY')
        with self.directory() as fd:
            try: os.stat(Path(path).name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError: return True
            return False

    @contextmanager
    def lock(self,path):
        import fcntl
        need(path == LOCK,'FIXED_SUPERVISOR_LOCK_ONLY')
        with self.directory() as directory:
            fd=os.open('launch.lock',os.O_RDWR|os.O_NOFOLLOW,dir_fd=directory)
            try:
                s=os.fstat(fd)
                need(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 65531 and
                     s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600,'ACCEPTED_SUPERVISOR_LOCK_REQUIRED')
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                yield fd
                now=os.stat('launch.lock',dir_fd=directory,follow_symlinks=False)
                need((now.st_dev,now.st_ino) == (s.st_dev,s.st_ino),'SUPERVISOR_LOCK_REPLACED')
            finally: os.close(fd)

    def atomic(self,path,raw,new=False):
        need(path == SUPERVISOR_ATTEMPT and len(raw) <= 131072,'FIXED_SUPERVISOR_JOURNAL_ONLY')
        with self.directory() as directory:
            if new: need(self.absent(path),'SUPERVISOR_REPLAY_FORBIDDEN')
            fd=os.open('launch.json.next',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as out:
                out.write(raw); out.flush(); os.fsync(out.fileno())
            if new:
                os.link('launch.json.next','launch.json',src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
                os.unlink('launch.json.next',dir_fd=directory)
            else: os.replace('launch.json.next','launch.json',src_dir_fd=directory,dst_dir_fd=directory)
            os.fsync(directory)
            fd=os.open('launch.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
            try: need(os.read(fd,131073) == raw,'SUPERVISOR_JOURNAL_READBACK_FAILED')
            finally: os.close(fd)


class PreparationSupervisorFiles(SupervisorFiles):
    """Separate fixed preparer only: one self-stop while supervise holds lock.

    Root installation independently observes this stopped process and finalizes
    policy/mount/fd pins before resuming it. No inventory is generated or accepted
    here. The ordinary supervisor CLI does not instantiate this class.
    """
    def __init__(self, bootstrap_files):
        need(type(bootstrap_files) is dict and 0 < len(bootstrap_files) <= 50000 and
             {c.SELF, c.FRESH} <= bootstrap_files.keys() and
             all(type(pin) is str and c.DIGEST.fullmatch(pin) for pin in bootstrap_files.values()),
             'FRESH_PREPARATION_BOOTSTRAP_REQUIRED')
        self._bootstrap_files = dict(bootstrap_files)
        self._preparation_consumed = False

    def read_json(self, path):
        need(path == POLICY, 'FIXED_SUPERVISOR_POLICY_ONLY')
        need(not self._preparation_consumed, 'FRESH_PREPARATION_REPLAY_FORBIDDEN')
        self._preparation_consumed = True
        # No temporary pipe, receipt, socket exchange or extra inherited FD.
        # SIGCONT is not GO: every original Platform check still follows.
        os.kill(os.getpid(), c.signal.SIGSTOP)
        policy = super().read_json(path)
        need(type(policy) is dict and policy.get('files') == self._bootstrap_files,
             'FRESH_PREPARATION_SOURCE_DRIFT')
        return policy


@contextmanager
def commit_frame(conn):
    """Own every installed rights FD before rejecting any ancillary semantics."""
    fds=array.array('i'); primary=None
    try:
        raw,anc,flags,_=conn.recvmsg(4096,socket.CMSG_SPACE(12)+socket.CMSG_SPACE(256*fds.itemsize))
        for level,kind,data in anc:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                # Even malformed framing must dispose all complete installed FDs.
                fds.frombytes(data[:len(data)-len(data)%fds.itemsize])
        need(all(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS and
                 len(data)%fds.itemsize == 0 for level,kind,data in anc), 'COMMIT_FD_REQUIRED')
        need(not flags and len(fds) == 1 and raw.endswith(b'\n'), 'EXACT_COMMIT_FRAME_REQUIRED')
        yield raw,fds[0]
    except BaseException as error:
        primary=error; raise
    finally:
        errors=[]
        for fd in fds:
            try: os.close(fd)
            except BaseException as error: errors.append(error)
        if errors and primary is None: raise errors[0]


def supervise(listener, fs, platform=None, *, fault=None):
    """One-shot accepted service, never restarted by this code, child not rolled back.

    Socket activation and /state/launch.lock MUST be preprovisioned independently.
    The launch channel is finite; this independent supervisor waits for the one
    child lifetime. No retry, kill, refreeze, rollback or journal adoption exists.
    fault is a local programmatic test seam, absent from every CLI grammar.
    """
    need(platform is None or fs.fixture is not None, 'SIMULATED_PLATFORM_FORBIDDEN')
    need(fault is None or fs.fixture is not None, 'FAULT_INJECTION_FORBIDDEN')
    platform=platform or Platform(); child=None; committed=False
    with fs.lock(LOCK):
        need(fs.absent(SUPERVISOR_ATTEMPT) and fs.absent(SUPERVISOR_ATTEMPT+'.next'), 'SUPERVISOR_REPLAY_FORBIDDEN')
        policy=validate(fs.read_json(POLICY)); platform.check(policy)
        if fs.fixture is None: platform.entry_fds(policy)
        listener.listen(1)  # bind peer credentials to this supervisor, not its provisioner
        listener.settimeout(5); conn,_=listener.accept(); listener.close()
        try:
            pid,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            need(uid == fs.uid, 'ROOT_COORDINATOR_PEER_REQUIRED')
            conn.settimeout(5); wire=c.Wire(conn.fileno(),conn.fileno(),time.monotonic()+8)
            nonce=os.urandom(32).hex(); pin=digest(c.canonical(policy))
            wire.send({'op':'prepared','nonce':nonce,'policySha256':pin})
            with commit_frame(conn) as (raw,fd):
                req=c.decode(raw)
                need(set(req) == {'op','nonce','commitSha256'} and req['op'] == 'exec' and req['nonce'] == nonce,'ONE_SHOT_EXEC_FRAME_REQUIRED')
                info=os.fstat(fd)
                need(stat.S_ISREG(info.st_mode) and info.st_uid == fs.uid and stat.S_IMODE(info.st_mode) == 0o600 and
                     info.st_nlink == 1 and info.st_size <= 131072,'ROOT_DURABLE_COMMIT_REQUIRED')
                commitraw=os.pread(fd,131073,0); commit=c.decode(commitraw)
                need(digest(commitraw) == req['commitSha256'] and commit['activationSet'] == ACTIVATION and
                     commit['context'] == 'test.infograd.online' and commit['freshPolicySha256'] == pin and
                     commit['supervisor'] == {'pid':os.getpid(),'start':start(os.getpid())} and
                     commit['restoreIntent']['origin']['pid'] == pid and commit['restoreIntent']['origin']['start'] == start(pid) and
                     set(commit['nodePeers']) == set(c.NODES),'SAME_HELD_PEER_FRESH_COMMIT_REQUIRED')
                need(commit['configSha256'] == policy['inventory']['coordinatorSha256'], 'ACCEPTED_COORDINATOR_REQUIRED')
                committed=True
            platform.check(policy)
            row={'phase':'exec-attempted','commitSha256':req['commitSha256'],'serving':None}
            fs.atomic(SUPERVISOR_ATTEMPT,c.canonical(row),new=True)
            argv,env,cwd=platform.paths(policy)
            # New anonymous regular stdio only, never /dev, a host log, old FD or
            # controller pipe. close_fds discards listener, commit, journal/lock.
            stdio=[os.memfd_create('c3-fresh-stdio',os.MFD_CLOEXEC) for _ in range(3)]
            try:
                def limits():
                    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                    resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576))
                # One unchanged startup budget includes Popen itself. A late
                # successful probe is unknown, never authority to confirm.
                deadline=time.monotonic()+3
                child=subprocess.Popen(argv,cwd=cwd,env=env,stdin=stdio[0],stdout=stdio[1],stderr=stdio[2],
                                       close_fds=True,start_new_session=True,preexec_fn=limits)
            finally:
                for fd in stdio: os.close(fd)
            # Test-only durable child identity lets the harness clean up after
            # deliberately lost results without adding any production recovery.
            if fs.fixture is not None:
                (fs.fixture.root/'fresh'/f'serving-{child.pid}.json').write_text(json.dumps({'pid':child.pid}))
            while True:
                need(child.poll() is None and time.monotonic() < deadline,'POSTEXEC_SERVING_UNKNOWN')
                try:
                    serving=platform.observe(policy,child.pid)
                    need(serving['bodySha256'] == policy['ingress']['bodySha256'],'SERVING_RESPONSE_DRIFT')
                except (OSError,RuntimeError,http.client.HTTPException):
                    need(child.poll() is None and time.monotonic() < deadline,'POSTEXEC_SERVING_UNKNOWN')
                    time.sleep(.02)  # observation only, NEVER repeat exec
                    continue
                # Blocking observation can finish outside the budget or after
                # child death. Preserve the full proof but refuse late success;
                # these guards do not bound HTTP/proc syscall return latency.
                need(child.poll() is None and time.monotonic() < deadline,'POSTEXEC_SERVING_UNKNOWN')
                break
            if fault == 'eof': return
            if fault == 'timeout': time.sleep(6)
            if fault == 'death': os.kill(os.getpid(),9)
            row.update(phase='serving',serving=serving)
            if fault == 'fsync': raise OSError('SIMULATED postexec fsync failure')
            fs.atomic(SUPERVISOR_ATTEMPT,c.canonical(row))
            wire.send({'op':'serving','serving':serving})
            need(wire.receive() == {'op':'complete','commitSha256':req['commitSha256']}, 'FINITE_COMPLETION_REQUIRED')
            row['phase']='completed'; fs.atomic(SUPERVISOR_ATTEMPT,c.canonical(row))
            wire.send({'op':'complete-ack'})
        except BaseException:
            if committed:
                # No success reply and no effect reversal. Original durable
                # exec-attempted journal remains sticky even if this write fails.
                try: fs.atomic(SUPERVISOR_ATTEMPT,c.canonical({'phase':'committed-activation-unknown','commitSha256':req['commitSha256']}),new=fs.absent(SUPERVISOR_ATTEMPT))
                except BaseException: pass
            raise
        finally:
            conn.close()
        if child is not None:
            child.wait()  # independent serving lifetime; no restart or caller tie


if __name__ == '__main__':
    import sys
    need(sys.argv[1:] == ['supervisor'], 'FIXED_SUPERVISOR_CLI_REQUIRED')
    # fd3 is a separately accepted prebound root socket, not created by this CLI.
    supervise(socket.socket(fileno=3),SupervisorFiles())
