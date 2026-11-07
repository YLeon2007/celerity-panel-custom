#!/usr/bin/python3 -I
"""Four finite selected-TEST caller connections. Not a controller or an issuer.

Trusted ROOT callers supply independently accepted inputs. No input is accepted
because it was measured here. This module never restores, thaws or retries.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import time
import types

ROOT_UID = 0
P_NODE = '6aecd36265572a55acf7c677'
B_NODE = '6aed089795ea4b863887d717'
LOADER = '/usr/local/libexec/c3-test-fresh-network-client-exec.py'
OBSERVER = '/usr/local/libexec/c3-test-fresh-physical-observe.py'
FREEZER = '/usr/local/libexec/c3-panel-host-freezer.py'
CLEAN_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
LIMIT = 8 * 1024 * 1024


def need(ok, code):
    if not ok: raise RuntimeError(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def snapshot(path):
    """Checked noatime/nofollow bytes, including every directory; no pyc reads."""
    need(Path(path).is_absolute() and len(Path(path).parts) > 1 and '..' not in Path(path).parts, 'ABSOLUTE_INPUT_REQUIRED')
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOATIME | os.O_NOFOLLOW | os.O_CLOEXEC)
    primary = None
    try:
        for i, part in enumerate(Path(path).parts[1:]):
            directory = i < len(Path(path).parts)-2
            flags = (os.O_PATH if directory else os.O_RDONLY) | os.O_NOATIME | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if directory: flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            previous, fd = fd, child  # register new descriptor before retiring old
            os.close(previous)
            s = os.fstat(fd)
            need(s.st_uid in (0, ROOT_UID) and not s.st_mode & 0o022 and
                 (directory or not os.listxattr(fd)), 'UNTRUSTED_CALLER_INPUT')
        stable = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
                             s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        before = stable(s)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= LIMIT, 'BOUNDED_REGULAR_INPUT_REQUIRED')
        chunks = []; total = 0
        while True:
            chunk = os.read(fd, min(65536, LIMIT+1-total))
            if not chunk: break
            chunks.append(chunk); total += len(chunk)
            need(total <= LIMIT, 'CALLER_INPUT_LIMIT')
        need(before == stable(os.fstat(fd)) and total == s.st_size, 'CALLER_INPUT_DRIFT')
        return b''.join(chunks), before
    except BaseException as error:
        primary = error; raise
    finally:
        try: os.close(fd)
        except BaseException as error:
            if primary is None: raise
            primary.add_note('input disposal: '+str(error))


def checked_loader(loader_sha256):
    """Reuse the existing noatime buffer loader, independently hash-bound."""
    raw, _ = snapshot(LOADER)
    need(sha(raw) == loader_sha256, 'CALLER_LOADER_PIN_REQUIRED')
    m = types.ModuleType('finite_caller_checked_loader'); m.__file__ = LOADER
    exec(compile(raw, LOADER, 'exec'), m.__dict__)
    return m


def remaining(end):
    seconds = end-time.monotonic()
    need(seconds > 0, 'ORIGINAL_CALLER_DEADLINE_EXPIRED')
    return seconds


def read_line(child, buffers, end, limit=65536):
    """Drain real stdout AND stderr, with EOF and bounded partial frames."""
    while b'\n' not in buffers['out']:
        streams = [s for s, k in ((child.stdout, 'out'), (child.stderr, 'err')) if k not in buffers['eof']]
        need('out' not in buffers['eof'], 'CALLER_CHILD_EOF_UNKNOWN')
        ready = select.select(streams, [], [], remaining(end))[0]
        need(ready, 'CALLER_CHILD_TIMEOUT')
        for stream in ready:
            key = 'out' if stream is child.stdout else 'err'
            block = os.read(stream.fileno(), 65536)
            if not block: buffers['eof'].add(key)
            else:
                buffers[key].extend(block)
                need(len(buffers[key]) <= limit, 'BOUNDED_CALLER_CHILD_OUTPUT_REQUIRED')
    line, _, tail = buffers['out'].partition(b'\n'); buffers['out'] = bytearray(tail)
    remaining(end)
    return bytes(line)+b'\n'


def write_pipe(stream, raw, end):
    os.set_blocking(stream.fileno(), False)
    while raw:
        need(select.select([], [stream], [], remaining(end))[1], 'CALLER_PIPE_TIMEOUT')
        try: count = os.write(stream.fileno(), raw)
        except BlockingIOError: continue
        need(count > 0, 'CALLER_PIPE_LOST'); raw = raw[count:]
    remaining(end)


def dispose_pipe_child(child, primary=None):
    """Only own registered Popen, never a historical PID; visit every stream."""
    errors = []
    for name in ('stdin', 'stdout', 'stderr'):
        stream = getattr(child, name); setattr(child, name, None)
        if stream is not None:
            try: stream.close()
            except BaseException as error: errors.append(error)
    try:
        # Prefer bounded natural EOF finish, then dispose this exact own child.
        try: child.wait(timeout=.2)
        except subprocess.TimeoutExpired:
            child.terminate()
            try: child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=1)
    except BaseException as error: errors.append(error)
    if primary is not None:
        for error in errors: primary.add_note('owned caller child disposal: '+str(error))
    elif errors:
        for error in errors[1:]: errors[0].add_note('owned caller child disposal: '+str(error))
        raise errors[0]


def recovery_argv(node, *, carrier, key, known_hosts, known_hosts_sha256, jump=None):
    """Exact selected endpoint/carrier; jump is separately accepted P port-22 SSH.

    P maintenance port 2222 disables forwarding: it is NOT a usable jump server.
    A via-P carrier requires explicit accepted jump user/key/port, never fallback.
    """
    expected = {P_NODE: '10.203.61.2', B_NODE: '10.203.61.1'}
    # inventory_node returns the full endpoint for the restricted RUNNER account.
    # Recovery deliberately uses the separate fixed operator account below.
    need(node.get('nodeId') in expected and node.get('endpoint') ==
         {'ip': expected.get(node.get('nodeId')), 'port': 2222, 'username': 'c3-test-runner'} and
         type(node['endpoint']['port']) is int, 'EXACT_SELECTED_ENDPOINT_REQUIRED')
    mapping = {'P-public': (P_NODE, '104.143.201.72'), 'P-private': (P_NODE, '10.203.61.2'),
               'B-public': (B_NODE, '132.243.230.19'), 'B-private': (B_NODE, '10.203.61.1'),
               'B-private-via-P': (B_NODE, '10.203.61.1')}
    need(carrier in mapping and mapping[carrier][0] == node['nodeId'], 'ACCEPTED_SELECTED_CARRIER_REQUIRED')
    host = mapping[carrier][1]
    for path in (key, known_hosts):
        need(type(path) is str and re.fullmatch(r'/[A-Za-z0-9_./-]+', path) and '..' not in Path(path).parts,
             'LITERAL_ACCEPTED_SSH_PATH_REQUIRED')
    raw, _ = snapshot(known_hosts)
    need(sha(raw) == known_hosts_sha256, 'ACCEPTED_KNOWN_HOSTS_PIN_REQUIRED')
    tokens = {line.split()[0] for line in raw.decode('ascii').splitlines() if line and not line.startswith('#')}
    need('['+host+']:2222' in tokens, 'EXACT_CARRIER_HOST_KEY_REQUIRED')
    base = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+known_hosts,
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=2',
            '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2']
    argv = base + ['-p', '2222', '-i', key]
    if carrier == 'B-private-via-P':
        need(type(jump) is dict and set(jump) == {'user', 'key', 'port'} and jump['port'] == 22 and
             type(jump['user']) is str and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', jump['user']) and
             type(jump['key']) is str and re.fullmatch(r'/[A-Za-z0-9_./-]+', jump['key']) and
             '..' not in Path(jump['key']).parts, 'INDEPENDENT_P_JUMP_INPUT_REQUIRED')
        need('104.143.201.72' in tokens, 'EXACT_JUMP_HOST_KEY_REQUIRED')
        proxy = base + ['-p', '22', '-i', jump['key'], '-W', '%h:%p', jump['user']+'@104.143.201.72']
        argv += ['-o', 'ProxyCommand='+shlex.join(proxy)]
    else: need(jump is None, 'UNSELECTED_JUMP_REFUSED')
    return argv + ['c3-test-operator@'+host, 'sudo -n /usr/local/libexec/c3-test-node-isolation guard']


def holder_greeting(invocation):
    """Borrow the existing creator, never reap its holder or reset its budget."""
    m = invocation.m
    need(not hasattr(invocation, '_finite_caller_greeting'), 'ONE_ORIGINAL_GREETING_REQUIRED')
    invocation.budget()
    raw = invocation.holder_line(); value = m.decode(raw)
    m.keys(value, 'version context generation holder deadline accepted physicalAccepted operationalGO')
    m.need(type(value['version']) is int and value['version'] == 1 and value['context'] == m.CONTEXT and
           value['generation'] == invocation.p['generation'] and
           value['holder'] == {'pid': invocation.pid, 'start': invocation.start} and
           value['deadline'] == invocation.p['deadline'] and
           all(value[k] is False for k in ('accepted', 'physicalAccepted', 'operationalGO')),
           'EXACT_UNACCEPTED_CHILD_OBSERVATION_REQUIRED')
    invocation.budget()
    invocation._finite_caller_greeting = raw
    return raw  # caller must obtain independent acceptance AFTER this observation


def publish_lease(path, raw):
    """No replace, no automatic cleanup after uncertainty; exact accepted bytes."""
    directory, name = str(Path(path).parent), Path(path).name
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME | os.O_NOFOLLOW | os.O_CLOEXEC)
    primary = None; output = None
    try:
        s = os.fstat(fd)
        need(s.st_uid == ROOT_UID and not s.st_mode & 0o022, 'ROOT_LEASE_DIRECTORY_REQUIRED')
        stage = name+'.finite-next'
        output = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o400, dir_fd=fd)
        tail = raw
        while tail:
            count = os.write(output, tail); need(count > 0, 'LEASE_WRITE_UNKNOWN_RETAINED'); tail = tail[count:]
        os.fchmod(output, 0o400); os.fsync(output)
        retired, output = output, None; os.close(retired)
        rename = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
        need(rename is not None, 'LINUX_NOREPLACE_REQUIRED')
        if rename(fd, os.fsencode(stage), fd, os.fsencode(name), 1) != 0:
            code = ctypes.get_errno(); raise OSError(code, os.strerror(code))
        os.fsync(fd)
    except BaseException as error:
        primary = error; raise
    finally:
        errors = []
        for owned in (output, fd):
            if owned is not None:
                try: os.close(owned)
                except BaseException as error: errors.append(error)
        if primary is not None:
            for error in errors: primary.add_note('lease publication disposal: '+str(error))
        elif errors: raise errors[0]


def lease_then_prepare(invocation, control, greeting_raw, *, accepted_greeting_sha256,
                       accepted_lease_raw, accepted_lease_sha256, start_network):
    """Consume ROOT's separately issued hash-bound lease, not observation authority.

    start_network is ROOT's explicit action for the existing fixed service. Its
    unknown result is not retried. Creator owns all holder/settlement disposal.
    """
    m = invocation.m; invocation.budget()
    need(getattr(invocation, '_finite_caller_greeting', None) == greeting_raw and
         not getattr(invocation, '_finite_caller_lease_attempted', False), 'ONE_ORIGINAL_LEASE_RENDEZVOUS_REQUIRED')
    need(type(accepted_lease_raw) is bytes and sha(greeting_raw) == accepted_greeting_sha256 and
         sha(accepted_lease_raw) == accepted_lease_sha256, 'INDEPENDENT_ROOT_INPUT_PINS_REQUIRED')
    greeting = m.decode(greeting_raw)
    need(greeting['holder'] == {'pid': invocation.pid, 'start': invocation.start} and
         greeting['deadline'] == invocation.p['deadline'] and greeting.get('accepted') is False,
         'EXACT_ORIGINAL_GREETING_REQUIRED')
    raw_plan = m.trusted_read(m.INPUT)
    need(m.decode(raw_plan) == invocation.p, 'ORIGINAL_PLAN_DRIFT')
    # Use the real existing closed Lease validator BEFORE publishing. Only its
    # fixed lease read is projected from the separately accepted ROOT byte input;
    # PID/start/deadline/proc checks and original plan reads remain real.
    view = types.SimpleNamespace(**vars(m))
    view.trusted_read = lambda path: accepted_lease_raw if path == m.LEASE else m.trusted_read(path)
    lease = control.Lease(view, invocation.p, raw_plan)
    primary = None
    try:
        need(lease.holder == greeting['holder'], 'EXACT_ACCEPTED_HOLDER_REQUIRED')
        invocation.budget()
        invocation._finite_caller_lease_attempted = True  # before first publication; unknown cannot replay
        publish_lease(m.LEASE, accepted_lease_raw)
        lease.m = m; lease.check()  # actual fixed-file readback, no success on write alone
        invocation.budget()
        start_network()  # only after independent publication/actual Lease validation
        invocation.budget(); lease.check()
        raw = invocation.holder_line()  # ACTUAL prepared line, never pre-lease wait
        value = m.decode(raw)
        m.need(value.get('phase') == 'prepared' and value.get('generation') == invocation.p['generation'] and
               value.get('sequence') == 0 and value.get('physicalAccepted') is False and
               value.get('operationalGO') is False, 'ACTUAL_UNACCEPTED_PREPARED_REPLY_REQUIRED')
        lease.check(); invocation.budget()
        return raw
    except BaseException as error:
        primary = error; raise
    finally:
        try: lease.close()
        except BaseException as error:
            if primary is None: raise
            primary.add_note('accepted lease validation disposal: '+str(error))


def observe_initialized(observer, physical, prepared, source_check, *, deadline_ns, emit):
    """In the finite child: pin originals, ACK initialization, retain SAME object."""
    need(type(deadline_ns) is int, 'ORIGINAL_OBSERVER_DEADLINE_REQUIRED')
    end = deadline_ns / 1_000_000_000
    need(0 < remaining(end) <= 600, 'ORIGINAL_OBSERVER_DEADLINE_REQUIRED')
    def expire(*_): raise TimeoutError('ORIGINAL_OBSERVER_DEADLINE_EXPIRED')
    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, remaining(end))
    observation = None; primary = None
    try:
        try:
            observation = observer.Observation(physical, prepared, source_check)
            need(observation.run.deadline_ns <= deadline_ns, 'OBSERVER_RUN_EXCEEDS_ORIGINAL_DEADLINE')
            remaining(end); observation.run.check()
            emit({'observerInitialized': dict(generation=observation.generation['generation'],
                  watcherObservation=dict(observation.binding), supervisor=dict(observation.generation['supervisor']),
                  deadlineMonotonicNs=observation.run.deadline_ns), 'physicalAccepted': False, 'operationalGO': False})
            result = observation.wait()  # independent acceptance AFTER ACK, SAME object
        except BaseException as error:
            primary = error; raise
        finally:
            if observation is not None:
                try: observation.close()
                except BaseException as error:
                    if primary is None: raise
                    primary.add_note('observer required disposal: '+str(error))
        source_check(); observation.run.check(); remaining(end)
        emit({'observerResult': result})  # required close completed BEFORE final result
    except BaseException as error:
        primary = error; raise
    finally:
        errors = []
        try: signal.setitimer(signal.ITIMER_REAL, 0)
        except BaseException as error: errors.append(error)
        try: signal.signal(signal.SIGALRM, previous)
        except BaseException as error: errors.append(error)
        if primary is not None:
            for error in errors: primary.add_note('observer timer disposal: '+str(error))
        elif errors: raise errors[0]


class ObserverChild:
    """Only this single finite read-only child; no physical acceptance publisher."""
    def __init__(self, *, deadline_ns, loader_sha256, source_pins):
        self.end = deadline_ns / 1_000_000_000
        self.ready_seen = self.finish_attempted = self.closed = False
        self.buffers = {'out': bytearray(), 'err': bytearray(), 'eof': set()}
        need(0 < remaining(self.end) <= 600, 'FINITE_OBSERVER_SCOPE_REQUIRED')
        self.child = subprocess.Popen(['/usr/bin/python3', '-I', '-B', str(Path(__file__).absolute()),
            'observer-child'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=CLEAN_ENV, bufsize=0)  # register BEFORE write/constructor readiness can fail
        self.pidfd = None
        try:
            self.pidfd = os.pidfd_open(self.child.pid)
            self.deadline_ns = deadline_ns
            config = dict(deadlineMonotonicNs=deadline_ns, loaderSha256=loader_sha256, sourcePins=source_pins)
            write_pipe(self.child.stdin, json.dumps(config).encode()+b'\n', self.end)
            stream, self.child.stdin = self.child.stdin, None
            stream.close()
        except BaseException as primary:
            self.close(primary); raise

    def ready(self):
        need(not self.ready_seen and not self.closed, 'ONE_OBSERVER_INITIALIZATION_REQUIRED')
        value = json.loads(read_line(self.child, self.buffers, self.end))
        need(set(value) == {'observerInitialized', 'physicalAccepted', 'operationalGO'} and
             value['physicalAccepted'] is False and value['operationalGO'] is False,
             'REAL_OBSERVER_INITIALIZATION_REQUIRED')
        ready = value['observerInitialized']
        need(set(ready) == {'generation', 'watcherObservation', 'supervisor', 'deadlineMonotonicNs'} and
             ready['deadlineMonotonicNs'] <= self.deadline_ns, 'ORIGINAL_OBSERVER_READY_BINDING_REQUIRED')
        self.ready_seen = True
        self.check_initialized()
        return value  # not permission to accept merely by possession of stdout

    def check_initialized(self):
        need(self.ready_seen and not self.closed and self.pidfd is not None and
             not select.select([self.pidfd], [], [], 0)[0], 'INITIALIZED_OBSERVER_LOST')
        remaining(self.end)

    def finish(self):
        need(self.ready_seen and not self.finish_attempted and not self.closed, 'ONE_OBSERVER_FINISH_REQUIRED')
        self.finish_attempted = True
        value = json.loads(read_line(self.child, self.buffers, self.end))
        need(set(value) == {'observerResult'}, 'EXACT_OBSERVER_RESULT_REQUIRED')
        while self.buffers['eof'] != {'out', 'err'}:
            streams = [s for s,k in ((self.child.stdout,'out'),(self.child.stderr,'err')) if k not in self.buffers['eof']]
            ready = select.select(streams, [], [], remaining(self.end))[0]
            need(ready, 'OBSERVER_DISPOSAL_TIMEOUT')
            for stream in ready:
                key = 'out' if stream is self.child.stdout else 'err'
                block = os.read(stream.fileno(), 65536)
                if not block: self.buffers['eof'].add(key)
                else:
                    self.buffers[key].extend(block)
                    need(len(self.buffers[key]) <= 65536, 'OBSERVER_OUTPUT_LIMIT')
        need(not self.buffers['out'] and self.child.wait(timeout=remaining(self.end)) == 0,
             'OBSERVER_REQUIRED_NATURAL_EXIT_UNKNOWN')
        remaining(self.end)
        return value['observerResult']

    def close(self, primary=None):
        if self.closed: return
        self.closed = True
        errors = []
        try: dispose_pipe_child(self.child, primary)
        except BaseException as error: errors.append(error)
        fd, self.pidfd = self.pidfd, None
        if fd is not None:
            try: os.close(fd)
            except BaseException as error: errors.append(error)
        if primary is not None:
            for error in errors: primary.add_note('observer child disposal: '+str(error))
        elif errors: raise errors[0]

    def __enter__(self): return self
    def __exit__(self, _t, error, _tb): self.close(error)


def observer_child(config):
    need(os.getresuid() == os.getresgid() == (0, 0, 0), 'ROOT_OBSERVER_CALLER_REQUIRED')
    for ns in ('pid', 'mnt', 'net', 'user'):
        need(os.readlink('/proc/self/ns/'+ns) == os.readlink('/proc/1/ns/'+ns), 'HOST_OBSERVER_VIEW_REQUIRED')
    need(type(config) is dict and set(config) == {'deadlineMonotonicNs', 'loaderSha256', 'sourcePins'} and
         type(config['deadlineMonotonicNs']) is int, 'EXACT_OBSERVER_CALLER_INPUT_REQUIRED')
    end = config['deadlineMonotonicNs']/1_000_000_000
    need(0 < remaining(end) <= 600, 'ORIGINAL_OBSERVER_DEADLINE_REQUIRED')
    def expire(*_): raise TimeoutError('ORIGINAL_OBSERVER_DEADLINE_EXPIRED')
    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, remaining(end))  # before ANY source loading
    loader = checked_loader(config['loaderSha256']); pins = config['sourcePins']
    loader.PINS = dict(pins)  # independent reviewed caller pins, not measured acceptance
    observer = loader.load(OBSERVER)
    need(set(pins) == set(observer.SOURCE_PINS) | {OBSERVER}, 'EXACT_OBSERVER_SOURCE_CLOSURE_REQUIRED')
    inputs = {p: snapshot(p) for p in pins}
    need(all(sha(v[0]) == pins[p] for p,v in inputs.items()), 'ACCEPTED_OBSERVER_SOURCE_PINS_REQUIRED')
    def sources():
        need(all(snapshot(p) == v for p,v in inputs.items()), 'OBSERVER_CALLER_SOURCE_DRIFT')
    physical = loader.load(observer.PHYSICAL)
    c = loader.load(observer.COORDINATED)
    fresh = types.ModuleType('finite_caller_fresh'); fresh.__file__ = observer.FRESH
    fresh.c = c  # inject BEFORE executing, preserving original loader/module identity
    exec(compile(inputs[observer.FRESH][0], observer.FRESH, 'exec'), fresh.__dict__)
    def prepared(policy, pid):
        fresh.validate(policy); fresh.Platform().prepared(policy, pid)
        fd3 = (Path('/proc')/str(pid)/'fd/3').stat().st_ino
        with physical.ProcessLease(pid) as lease: physical.check_prepared_resources(lease, fd3)
    end = config['deadlineMonotonicNs']/1_000_000_000
    def emit(value): write_pipe(sys.stdout.buffer, physical.encode(value), end)
    observe_initialized(observer, physical, prepared, sources,
                        deadline_ns=config['deadlineMonotonicNs'], emit=emit)


def capture_b_originals(freezer, accepted_node):
    """Actual LinuxKernel/precheck/capture API. Result is UNACCEPTED inventory."""
    need(accepted_node.get('nodeId') == B_NODE and accepted_node.get('endpoint') ==
         {'ip': '10.203.61.1', 'port': 2222, 'username': 'c3-test-runner'} and
         type(accepted_node['endpoint']['port']) is int, 'EXACT_ACCEPTED_B_NODE_REQUIRED')
    machine = accepted_node['physical']['machineId']
    need(type(machine) is str and re.fullmatch('[a-f0-9]{32}', machine), 'ACCEPTED_B_MACHINE_REQUIRED')
    kernel = freezer.LinuxKernel()
    kernel.barrier = freezer.SystemdRelaunchBarrier()
    freezer.host_precheck(kernel, expected_machine_id=machine)
    return freezer.capture(kernel)  # no accepted:true, hostHold, COMMIT or receipt


def load_b_capture_api(*, loader_sha256, freezer_sha256):
    loader = checked_loader(loader_sha256)
    loader.PINS = {FREEZER: freezer_sha256}
    return loader.load(FREEZER)


if __name__ == '__main__':
    # Only the finite read-only observer is an executable subprocess entry.
    # Recovery, issuer action and capture stay explicit ROOT-caller functions.
    if sys.argv[1:] != ['observer-child']: raise SystemExit('import by the reviewed ROOT caller; no activation CLI')
    try:
        # Deadline must arrive promptly even before a RunPlan can be loaded.
        if not select.select([0], [], [], 2)[0]: raise TimeoutError('OBSERVER_INPUT_TIMEOUT')
        raw = os.read(0, 65537)
        need(len(raw) <= 65536 and raw.endswith(b'\n'), 'BOUNDED_OBSERVER_INPUT_REQUIRED')
        observer_child(json.loads(raw))
    except BaseException:
        os.write(2, b'OBSERVER_UNKNOWN_RETAINED; no acceptance, cleanup or replay\n')
        raise SystemExit(75)


def serve_recovery(argv, *, end, on_ready):
    """Finite foreground responder. Server retains real independent-ancestry checks."""
    need(0 < remaining(end) <= 600, 'FINITE_RECOVERY_SCOPE_REQUIRED')
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=CLEAN_ENV, bufsize=0)  # own registry at birth
    primary = None
    try:
        buffers = {'out': bytearray(), 'err': bytearray(), 'eof': set()}
        ready_seen = False
        while True:
            try: raw = read_line(child, buffers, end, 4096)
            except RuntimeError as error:
                if str(error) != 'CALLER_CHILD_EOF_UNKNOWN': raise
                need(ready_seen and not buffers['out'] and child.wait(timeout=remaining(end)) == 0,
                     'RECOVERY_EXIT_UNKNOWN')
                remaining(end); return
            value = json.loads(raw)
            if set(value) == {'recoveryChallenge'}:
                nonce = value['recoveryChallenge']
                need(ready_seen and type(nonce) is str and re.fullmatch('[a-f0-9]{64}', nonce), 'EXACT_RECOVERY_NONCE_REQUIRED')
                # Unmodified nonce, same server's two-second contract; no retries.
                write_pipe(child.stdin, json.dumps({'recoveryResponse': nonce}).encode()+b'\n',
                           min(end, time.monotonic()+2))
            else:
                need(not ready_seen and set(value) == {'guardReady', 'identity', 'session'} and
                     value['guardReady'] is True and type(value['identity']) is dict and
                     set(value['identity']) == {'pid', 'start', 'socket'} and
                     type(value['session']) is dict and set(value['session']) == {'pid', 'start'} and
                     all(type(v['pid']) is int and v['pid'] > 0 and type(v['start']) is str and
                         re.fullmatch('[1-9][0-9]*', v['start']) for v in (value['identity'], value['session'])) and
                     type(value['identity']['socket']) is str and value['identity']['socket'].startswith('/'),
                     'EXACT_RECOVERY_GREETING_REQUIRED')
                ready_seen = True; on_ready(value)  # observation, NOT physical acceptance
    except BaseException as error:
        primary = error; raise
    finally: dispose_pipe_child(child, primary)
