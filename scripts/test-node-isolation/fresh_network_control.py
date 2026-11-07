#!/usr/bin/python3 -I
"""Root-only held-owner control protocol for the fixed network constructor.

Installation and lease publication belong to the independent operator. No CLI
paths, environment commands, auto-recovery or GO exist. An unknown outcome leaves
all kernel resources and journal tombstones untouched.
"""
import os
from pathlib import Path
import select
import socket
import stat
import struct
import time


def receive(channel, module):
    header = b''
    while len(header) < 4:
        block = channel.recv(4-len(header))
        module.need(block, 'CONTROL_EOF_RETAINED')
        header += block
    size = struct.unpack('!I', header)[0]
    module.need(0 < size <= 4096, 'CONTROL_FRAME_REFUSED')
    raw = b''
    while len(raw) < size:
        block = channel.recv(size-len(raw))
        module.need(block, 'CONTROL_EOF_RETAINED')
        raw += block
    return module.decode(raw)


def send(channel, value, module):
    raw = module.encode(value)
    module.need(len(raw) <= module.LIMIT, 'CONTROL_REPLY_OVERFLOW')
    channel.sendall(struct.pack('!I', len(raw))+raw)


UNIT = 'c3-test-fresh-network.service'
ANCHOR = 'multi-user.target'
ISOLATION_PLAN = '/etc/c3-test-node-isolation.json'
HOST_STATE = '/var/lib/c3-test-node-isolation'
TERMINAL = '/run/c3-test-fresh-network-owner.sock'


def manager_show(m, unit):
    import subprocess
    keys = ('Id Names LoadState ActiveState SubState FragmentPath DropInPaths Wants WantedBy Refs '
            'MainPID ExecMainPID InvocationID ControlGroup Job Result Type Restart NotifyAccess '
            'FileDescriptorStoreMax FileDescriptorStorePreserve LimitNOFILE StartLimitBurst StartLimitIntervalUSec')
    out = subprocess.run(['/usr/bin/systemctl', 'show', '--all', unit,
          *['--property='+key for key in keys.split()]], check=True, timeout=3,
          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    m.need(len(out) <= 65536, 'MANAGER_REPLY_LIMIT')
    return dict(line.split('=', 1) for line in out.decode().splitlines() if '=' in line)


def existing_anchor(m):
    """Read-only runtime edge contract. Never enables/starts an anchor or service."""
    anchor, owner = manager_show(m, ANCHOR), manager_show(m, UNIT)
    m.need(anchor.get('Id') == ANCHOR and set(anchor.get('Names', '').split()) ==
           {'multi-user.target','runlevel2.target','runlevel3.target','runlevel4.target'} and
           anchor.get('FragmentPath') == '/usr/lib/systemd/system/multi-user.target' and
           anchor.get('LoadState') == 'loaded' and anchor.get('ActiveState') == 'active' and
           not anchor.get('DropInPaths') and not anchor.get('Refs') and UNIT in anchor.get('Wants','').split(),
           'ACTIVE_EXISTING_ANCHOR_EDGE_REQUIRED')
    m.need(owner.get('Id') == UNIT and owner.get('Names','').split() == [UNIT] and
           owner.get('FragmentPath') == '/etc/systemd/system/'+UNIT and not owner.get('DropInPaths') and
           not owner.get('Refs') and ANCHOR in owner.get('WantedBy','').split() and
           owner.get('LoadState') == 'loaded' and owner.get('ActiveState') == 'active' and
           owner.get('SubState') == 'running' and owner.get('MainPID') == owner.get('ExecMainPID') == str(os.getpid()) and
           owner.get('ControlGroup') == '/system.slice/'+UNIT and owner.get('Job','') in ('', '0') and
           owner.get('Result') == 'success' and owner.get('Type') == 'exec' and owner.get('Restart') == 'no' and
           owner.get('NotifyAccess') == 'main' and owner.get('FileDescriptorStoreMax') == '16384' and
           owner.get('FileDescriptorStorePreserve') == 'yes' and int(owner.get('LimitNOFILE','0')) >= 65536 and
           int(owner.get('StartLimitBurst','0')) > 0, 'EXACT_ORDINARY_UNIT_REQUIRED')
    invocation = owner.get('InvocationID','')
    m.need(len(invocation) == 32 and all(x in '0123456789abcdef' for x in invocation), 'OWNER_INVOCATION_REQUIRED')
    return invocation


class PID1Store:
    """Actual unit-main notify socket, barrier and full v255 Service Dump API."""
    def __init__(self, m, generation):
        self.m, self.generation = m, generation
        self.invocation = existing_anchor(m)
        self.address = os.environ.get('NOTIFY_SOCKET', '')
        m.need(self.address.startswith(('/', '@')) and len(self.address) <= 107, 'PID1_NOTIFY_SOCKET_REQUIRED')
        if self.address.startswith('@'): self.address = '\0'+self.address[1:]

    @staticmethod
    def row(name, row):
        # Only manager Dump omits RAW_O_LARGEFILE. Raw actual F_GETFL stays exact.
        return [name, row['mode'], os.major(row['dev']), os.minor(row['dev']), row['ino'],
                os.major(row['rdev']), os.minor(row['rdev']), row['path'], row['flags'] & ~0o100000]

    def notify(self, payload, fds=()):
        import array
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM|socket.SOCK_CLOEXEC) as conn:
            conn.settimeout(3); conn.connect(self.address)
            anc = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))] if fds else []
            self.m.need(conn.sendmsg([payload.encode()], anc) == len(payload.encode()), 'FDSTORE_SEND_UNKNOWN')

    def barrier(self):
        reader, writer = os.pipe2(os.O_CLOEXEC)
        try:
            self.notify('BARRIER=1', (writer,))
            fd, writer = writer, None; os.close(fd)
            self.m.need(select.select([reader], [], [], 3)[0] and os.read(reader, 1) == b'', 'FDSTORE_BARRIER_UNKNOWN')
        finally:
            if writer is not None: os.close(writer)
            os.close(reader)

    def dump(self):
        import subprocess
        def bus(args):
            out = subprocess.run(['/usr/bin/busctl', '--json=short', *args], check=True,
                 timeout=3, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
            self.m.need(len(out) <= 8*1024*1024, 'FDSTORE_DUMP_LIMIT')
            return self.m.decode(out)
        unit = bus(['call','org.freedesktop.systemd1','/org/freedesktop/systemd1',
                    'org.freedesktop.systemd1.Manager','GetUnit','s',UNIT])
        self.m.need(unit.get('type') == 'o' and len(unit.get('data',[])) == 1, 'FDSTORE_UNIT_OBJECT_REQUIRED')
        value = bus(['call','org.freedesktop.systemd1',unit['data'][0],
                     'org.freedesktop.systemd1.Service','DumpFileDescriptorStore'])
        self.m.need(value.get('type') == 'a(suuutuusu)' and len(value.get('data',[])) == 1 and
                    type(value['data'][0]) is list, 'FDSTORE_FULL_DUMP_REQUIRED')
        return value['data'][0]

    def verify(self, bindings):
        actual = self.dump()
        self.m.need(all(type(r) is list and len(r) == 9 and type(r[0]) is str for r in actual) and
                    len({r[0] for r in actual}) == len(actual) and
                    self.m.encode(sorted(actual)) == self.m.encode(sorted([self.row(b['name'], b['capability'])
                                                                        for b in bindings])), 'FDSTORE_CUSTODY_UNKNOWN')
        return self.m.digest(self.m.encode(sorted(actual)))

    def stage(self, rows, fds, previous=()):
        self.m.need(len(rows) == len(fds) and len(rows)+len(previous) <= 16384, 'FDSTORE_ENVELOPE_EXCEEDED')
        self.verify(previous)
        result = list(previous)
        for row, fd in zip(rows, fds):
            name = 'c3.'+self.generation+'.'+row['role']
            self.m.need(len(name) <= 255 and all(c.isalnum() or c in '._-' for c in name) and
                        name not in {r['name'] for r in result}, 'FDSTORE_CLOSED_NAME_REQUIRED')
            binding = {'name': name, 'capability': row}
            self.notify('FDSTORE=1\nFDPOLL=0\nFDNAME='+name, (fd,))
            self.barrier(); result.append(binding); self.verify(result)
        return result

    def remove(self, remove, bindings):
        current = list(bindings); self.verify(current)
        for binding in remove:
            self.m.need(binding in current, 'FDSTORE_FOREIGN_REMOVAL_REFUSED')
            self.notify('FDSTOREREMOVE=1\nFDNAME='+binding['name'])
            self.barrier(); current.remove(binding); self.verify(current)
        return current

    def inherited(self, bindings, inherited=None):
        rights = inherited if inherited is not None else InheritedRights(self.m)
        try:
            fds = rights.match(bindings)
            self.verify(bindings)
            if inherited is None: rights.release()
            return fds
        except BaseException as primary:
            rights.close(primary)
            raise


class InheritedRights:
    """Acquire the entire installed range before any grant/source/manager read."""
    def __init__(self, m):
        self.m, self.owned = m, []
        count = os.environ.get('LISTEN_FDS','')
        m.need(count.isascii() and count.isdecimal() and len(count) <= 5 and int(count) <= 16384,
               'FDSTORE_INHERITANCE_REQUIRED')
        self.owned = list(range(3,3+int(count)))
        try:
            for fd in self.owned: os.set_inheritable(fd,False)
            m.need(os.environ.get('LISTEN_PID') == str(os.getpid()),'EXACT_LISTEN_PID_REQUIRED')
            self.names = os.environ.get('LISTEN_FDNAMES','').split(':') if self.owned else []
        except BaseException as primary:
            self.close(primary); raise

    def match(self, bindings):
        import fcntl
        m = self.m
        m.need(len(self.names) == len(self.owned) == len(bindings) and len(set(self.names)) == len(self.names) and
               set(self.names) == {b['name'] for b in bindings},'FDSTORE_FOREIGN_OR_MISSING_RIGHTS')
        by_name = dict(zip(self.names,self.owned))
        for binding in bindings:
            fd = by_name[binding['name']]; row = binding['capability']; s = os.fstat(fd)
            m.need((s.st_dev,s.st_ino,s.st_mode,s.st_rdev,fcntl.fcntl(fd,fcntl.F_GETFL),os.readlink('/proc/self/fd/'+str(fd))) ==
                   (row['dev'],row['ino'],row['mode'],row['rdev'],row['flags'],row['path']),
                   'FDSTORE_ORIGINAL_CAPABILITY_LOST')
        return [by_name[b['name']] for b in bindings]

    def release(self):
        self.owned = []

    def close(self, primary=None):
        owned,self.owned = self.owned,[]  # retire numbers before the single close attempt
        errors = []
        for fd in owned:
            try: os.close(fd)
            except BaseException as error: errors.append(error)
        if errors:
            if primary is not None:
                primary.cleanup_errors = (*getattr(primary,'cleanup_errors',()),*errors)
            else: raise errors[0]


def cleanup_bindings(bindings):
    return [b for b in bindings if b['capability']['role'] == 'network.ns.fresh' or
            b['capability']['role'].startswith('serving.')]


def reconcile_cleanup(m, store, pending):
    """Read-only classification; partial/foreign Dump is never a retry permit."""
    m.keys(pending,'before after remove')
    before,after,remove = (pending[k] for k in ('before','after','remove'))
    m.need(m.encode(remove) == m.encode(cleanup_bindings(before)) and remove and
           m.encode(after) == m.encode([b for b in before if b not in remove]),'EXACT_PENDING_CLEANUP_REQUIRED')
    try:
        store.verify(before)
        return before
    except m.Refusal:
        store.verify(after)
        return after


def fixed_module(m, path, pin):
    import types
    raw = m.trusted_read(path)
    m.need(m.digest(raw) == pin, 'ORDINARY_FIXED_SOURCE_DRIFT')
    module = types.ModuleType('c3_ordinary_'+Path(path).stem.replace('-','_'))
    module.__file__ = path
    import sys
    sys.modules[module.__name__] = module
    exec(compile(raw, path, 'exec'), module.__dict__)
    return module


class HostFenceChannel:
    """Original PID/start/socket pinned once; no replacement guard or JSON adoption."""
    def __init__(self, m, p, raw, lease, invocation):
        self.m, self.p, self.raw, self.lease = m, p, raw, lease
        self.plan_raw = m.trusted_read(ISOLATION_PLAN); self.plan = m.decode(self.plan_raw)
        hold = self.plan.get('hostHold', {})
        m.need(self.plan.get('version') == 2 and hold.get('networkPlanSha256') == m.digest(raw) and
               self.plan.get('machineId') == p['machine'] and self.plan.get('bootId') == p['boot'] and
               '/system.slice/'+UNIT in self.plan.get('keepCgroups', []), 'V2_SHARED_NETWORK_BINDING_REQUIRED')
        pins = self.plan['runtimePins']
        isolation = '/usr/local/libexec/c3-test-node-isolation'
        shared_path = '/usr/local/libexec/c3-test-shared-host.py'
        self.isolation = fixed_module(m, isolation, pins[isolation])
        self.shared = fixed_module(m, shared_path, pins[shared_path])
        self.shared.validate_plan(self.plan, self.isolation)
        self.freezer = fixed_module(m, '/usr/local/libexec/c3-panel-host-freezer.py', hold['freezerSha256'])
        self.identity = m.decode(m.trusted_read(HOST_STATE+'/host-guard.json'))
        self.shared.check_identity(self.identity, self.plan, HOST_STATE, self.isolation)
        self.pidfd = os.pidfd_open(self.identity['pid'])
        self.socket_identity = m.identity(self.identity['socket'])
        self.binding = {'pid':os.getpid(),'start':m.proc_start(os.getpid()),'invocation':invocation,
                        'networkPlanSha256':m.digest(raw),'leaseSha256':m.digest(lease.raw)}

    def check(self):
        return self.request('network-check')

    def request(self, op, **extra):
        m = self.m
        self.lease.check()
        m.need(not select.select([self.pidfd],[],[],0)[0] and
               m.proc_start(self.identity['pid']) == self.identity['start'] and
               m.identity(self.identity['socket']) == self.socket_identity and
               m.trusted_read(ISOLATION_PLAN) == self.plan_raw, 'ORIGINAL_HOST_PRODUCER_LOST')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(min(120 if op == 'restore-network-old' else 3, max(.001,self.p['deadline']-time.time())))
            conn.connect(self.identity['socket'])
            pid,uid,gid = struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            m.need((pid,uid,gid) == (self.identity['pid'],0,0), 'ORIGINAL_HOST_PEER_REQUIRED')
            nonce = os.urandom(32).hex()
            conn.sendall(m.encode({'command':op,'nonce':nonce,'owner':self.identity['owner'],
                         'planHash':self.identity['planHash'],'network':self.binding,**extra})+b'\n')
            if op == 'stage-network-successor':
                offer = self.freezer.LiveFenceOffer.receive(conn, expected_peer=pid)
                self.lease.check()
                return offer
            raw = b''
            while not raw.endswith(b'\n') and len(raw) <= 8192:
                part = conn.recv(8193-len(raw)); m.need(part,'HOST_SUCCESSION_REPLY_LOST'); raw += part
            value = m.decode(raw)
            expected = {'nonce','identity','recordSha256'} | ({'transcriptSha256'} if op == 'surrender-network-successor' else
                       {'returnState'} if op == 'restore-network-old' else set())
            record_raw = m.trusted_read(HOST_STATE+'/host/hold.json')
            m.need(set(value) == expected and value['nonce'] == nonce and value['identity'] == self.identity and
                   m.digest(record_raw) == value['recordSha256'], 'HOST_SUCCESSION_REPLY_DRIFT')
            if op == 'restore-network-old':
                original = self.plan['hostHold']['expected']
                m.need(value['returnState'] == 'OLD' and m.decode(record_raw) == {
                    'phase':'restored','owner':self.identity['owner'],'pending':None,'originalExpected':original,
                    'expected':original,'frozen':[],'dead':False}, 'HOST_RETURN_OUTCOME_UNKNOWN')
            self.lease.check()
            return value

    def close(self):
        fd,self.pidfd = self.pidfd,None
        if fd is not None: os.close(fd)


class TemporaryAuthority:
    def __init__(self, lease, host): self.lease, self.host = lease, host
    def check(self):
        self.lease.check(); self.host.check(); self.lease.check()


class OrdinaryAuthority:
    """No holder/guard/Docker/supervisor liveness dependency after consumption."""
    def __init__(self, m, controller, fence, store, bindings, receipt):
        self.m,self.controller,self.fence,self.store = m,controller,fence,store
        self.bindings,self.receipt = bindings,receipt
        self.raw_plan = m.trusted_read(m.INPUT)
    def check(self):
        self.m.need(self.receipt.get('authorityPhase') == 'ordinary-owned', 'ORDINARY_GRANT_REQUIRED')
        if getattr(self.controller,'stop_deadline',None) is not None:
            self.m.need(time.monotonic() < self.controller.stop_deadline,'FINITE_STOP_BUDGET_EXPIRED')
        self.m.need(self.m.trusted_read(self.m.INPUT) == self.raw_plan, 'ORDINARY_INPUT_DRIFT')
        self.fence.check()
        self.store.verify(self.bindings)


def receive_rights(conn, m, count):
    import array
    owned = []
    try:
        data, anc, flags, _ = conn.recvmsg(1, socket.CMSG_SPACE(253*array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
        invalid = False
        for level, kind, body in anc:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array('i'); usable = len(body)-len(body)%values.itemsize
                values.frombytes(body[:usable]); owned.extend(values); invalid |= usable != len(body)
            else: invalid = True
        m.need(not invalid and not flags & (socket.MSG_CTRUNC|socket.MSG_TRUNC) and
               data == b'F' and len(owned) == count, 'CLOSED_SERVING_RIGHTS_REQUIRED')
        for fd in owned: os.set_inheritable(fd,False)
        return owned
    except BaseException as primary:
        for fd in owned:
            try: os.close(fd)
            except BaseException as error: primary.cleanup_errors = (*getattr(primary,'cleanup_errors',()),error)
        raise


def publish(m, journal, name, value, *, new=True):
    m.need(name in ('ordinary-owned.json','ordinary-state.json','recovery-association.json'), 'CLOSED_STATE_LEAF_REQUIRED')
    raw = m.encode(value); next_name = name+'.next'
    if new:
        try: os.stat(name,dir_fd=journal.fd,follow_symlinks=False)
        except FileNotFoundError: pass
        else: m.need(False,'ORDINARY_STATE_REPLAY_REFUSED')
    fd = os.open(next_name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=journal.fd)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd,view); m.need(count > 0,'ORDINARY_STATE_SHORT_WRITE'); view = view[count:]
        os.fsync(fd)
    finally: os.close(fd)
    os.rename(next_name,name,src_dir_fd=journal.fd,dst_dir_fd=journal.fd); os.fsync(journal.fd)
    fd = os.open(name,os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=journal.fd)
    try: m.need(os.read(fd,len(raw)+1) == raw,'ORDINARY_STATE_FSYNC_UNKNOWN')
    finally: os.close(fd)
    return m.digest(raw)


class OwnerRuntime:
    """One existing main's temporary → escrow → ordinary state machine."""
    def __init__(self,m,controller,lease,host,store):
        self.m,self.c,self.lease,self.host,self.store = m,controller,lease,host,store
        self.offer = self.fence = self.preparation = self.receipt = None
        self.bindings = []; self.accepted_bindings = None; self.pending_cleanup = None
        self.pending = None; self.coordinator = None
        self.coordinator_pidfd = None; self.finished = False
        self.terminal_deadline = None

    @classmethod
    def recover(cls,m,p,raw,store,inherited=None):
        """Read-only same-generation reconstruction ONLY from PID1 inheritance."""
        rights = inherited if inherited is not None else InheritedRights(m)
        try:
            result = cls._recover(m,p,raw,store,rights)
            rights.release()  # exact offer/kernel/journal now own the descriptors
            return result
        except BaseException as primary:
            rights.close(primary)
            raise

    @classmethod
    def _recover(cls,m,p,raw,store,inherited):
        root = Path(m.STATE)/p['generation']
        state = m.decode(m.trusted_read(str(root/'ordinary-state.json')))
        receipt = m.decode(m.trusted_read(str(root/'ordinary-owned.json')))
        residual = state['phase'] in ('network-removed-host-held','network-cleanup-pending')
        m.need(state['version'] == 1 and state['phase'] in ('ordinary-owned','parked-serving',
               'network-removed-host-held','network-cleanup-pending') and
               state['receiptSha256'] == m.digest(m.encode(receipt)) and receipt['authorityPhase'] == 'ordinary-owned' and
               receipt['networkPlanSha256'] == m.digest(raw) and receipt['generation'] == p['generation'] and
               receipt['boot'] == p['boot'], 'EXACT_ACCEPTED_RECOVERY_GRANT_REQUIRED')
        accepted = state.get('acceptedBindings',state['bindings'])
        m.need(m.digest(m.encode(accepted)) == receipt['acceptedFdStoreManifestSha256'], 'RECOVERY_CLOSED_MANIFEST_REQUIRED')
        pending = state.get('pendingCleanup')
        if residual:
            after = [b for b in accepted if b not in cleanup_bindings(accepted)]
            if state['phase'] == 'network-cleanup-pending':
                m.need(pending is not None and m.encode(state['bindings']) == m.encode(accepted) and
                       m.encode(pending['before']) == m.encode(accepted) and
                       m.encode(pending['after']) == m.encode(after), 'EXACT_PENDING_CLEANUP_REQUIRED')
                bindings = reconcile_cleanup(m,store,pending)
            else:
                m.need(pending is None and m.encode(state['bindings']) == m.encode(after), 'EXACT_RESIDUAL_MANIFEST_REQUIRED')
                bindings = after
        else:
            m.need(pending is None and m.encode(state['bindings']) == m.encode(accepted), 'RECOVERY_CLOSED_MANIFEST_REQUIRED')
            bindings = accepted
        fds = store.inherited(bindings,inherited)
        by_role = {b['capability']['role']:fd for b,fd in zip(bindings,fds)}
        shared_raw = m.trusted_read(ISOLATION_PLAN); shared_plan = m.decode(shared_raw)
        m.need(m.digest(shared_raw) == receipt['isolationPlanSha256'] and
               shared_plan['hostHold']['networkPlanSha256'] == m.digest(raw), 'RECOVERY_INPUT_DRIFT')
        freezer = fixed_module(m,'/usr/local/libexec/c3-panel-host-freezer.py',receipt['hostFence']['freezerSha256'])
        original = state['hostOffer']; host_rows = original['manifest']
        offer = freezer.LiveFenceOffer(original['state'],host_rows,[by_role[r['role']] for r in host_rows],received=True)
        m.need(offer.sha256 == receipt['hostFence']['liveOfferSha256'], 'RECOVERY_ORIGINAL_OFFER_REQUIRED')
        kernel = freezer.LinuxKernel(); kernel.barrier = freezer.SystemdRelaunchBarrier()
        fence = freezer.Fence.accept_live(offer,kernel)
        fence.consume_live(receipt['commitSha256'],receipt['hostFenceHandoffTranscriptSha256'])
        journal = object.__new__(m.Journal); journal.fd = by_role['network.journal']; journal.path = root
        s = os.fstat(journal.fd); journal.identity = (s.st_dev,s.st_ino); journal.counter = state['counter']
        m.need(m.identity(root) == [s.st_dev,s.st_ino] and
               not any(name.endswith('.next') for name in os.listdir(journal.fd)), 'RECOVERY_PENDING_IO_RETAINED')
        numbered = sorted(name for name in os.listdir(journal.fd) if len(name) == 11 and name[:6].isdigit() and name.endswith('.json'))
        m.need(numbered == ['%06d.json'%i for i in range(journal.counter)], 'RECOVERY_JOURNAL_OUTCOME_UNKNOWN')
        k = object.__new__(m.Linux); snapshot = state['network']; k.p = p
        k.fds = {r.removeprefix('network.ns.'):fd for r,fd in by_role.items()
                 if r.startswith('network.ns.') and (not residual or r != 'network.ns.fresh')}
        k.pidfds = {r.removeprefix('network.pid.'):fd for r,fd in by_role.items() if r.startswith('network.pid.')}
        k.peer_exes = {r.removeprefix('network.exe.'):fd for r,fd in by_role.items() if r.startswith('network.exe.')}
        k.host_fd = k.fds.get('host'); k.netns_fd = k.fds.get('fresh'); k.pids = snapshot['pids']; k.peer_pins = snapshot['peerPins']
        m.need(residual or k.host_fd is not None and k.netns_fd is not None,'RECOVERY_NETWORK_FDS_REQUIRED')
        k.residual_only = residual
        k.path_identity = snapshot['pathIdentity']; k.path_state = snapshot['pathState']
        k.sealed = snapshot['sealed']; k.firewall_seal = snapshot['firewallSeal']; k.node_table_seal = snapshot['nodeTableSeal']
        k.node_forward_seal = snapshot['nodeForwardSeal']; k.owned = {(a,b):v for a,b,v in snapshot['owned']}
        k.loopback_links = set(snapshot['loopbackLinks']); k.target_hold = None
        k.runtime_settings = snapshot['runtimeSettings'].encode() if snapshot['runtimeSettings'] is not None else None
        k.verification_mode = 'succeeded-original-fence'; k.original_fence_check = fence.check
        k.serving_live = None if residual else {'serving':snapshot['serving'],'rows':snapshot['servingRows'],
            'fds':[by_role[r['role']] for r in snapshot['servingRows']],'freezer':freezer,'empty':False}
        if residual:
            m.need(k.sealed is None and k.firewall_seal is None and not k.owned and k.path_state == 'absent' and
                   snapshot['serving'] is None and snapshot['servingRows'] == [],'RECOVERY_REMOVAL_NOT_CONFIRMED')
        def no_temporary_authority(): m.need(False,'TEMPORARY_RECOVERY_FORBIDDEN')
        controller = m.Controller(p,k,journal,guard=no_temporary_authority)
        controller.end = state['originalMonotonicEnd']; controller.seq = state['sequence']; controller.baseline = state['baseline']
        controller.phase = 'network-removed-host-held' if residual else state['phase']
        result = cls(m,controller,None,None,store)
        result.offer = offer; result.fence = fence; result.receipt = receipt; result.preparation = receipt
        result.bindings = bindings; result.accepted_bindings = accepted; result.finished = True
        controller.ordinary_authority = OrdinaryAuthority(m,controller,fence,store,bindings,receipt)
        m.need((residual or m.digest(m.encode(result.resources())) == receipt['resourceSealSha256']) and
               m.digest(m.encode(controller.baseline)) == receipt['baselineSha256'], 'RECOVERY_RESOURCE_SEAL_DRIFT')
        commit_raw = m.trusted_read(HOST_STATE+'/handoff-commit.json')
        m.need(m.digest(commit_raw) == receipt['commitSha256'] and
               m.decode(commit_raw)['networkHandoff']['preparationSha256'] == m.digest(m.encode({
                   key:receipt[key] for key in ('version context machine boot generation networkPlanSha256 isolationPlanSha256 '
                   'hostPlanHash ownerUnit ownerInvocationId ownerPid ownerStart coordinator temporaryHolder holderSequence '
                   'leaseSha256 originalDeadline originalMonotonicEnd hostFence freshNetns resourceSealSha256 baselineSha256 '
                   'fdManifestSha256 stopConfigSha256').split()})), 'RECOVERY_SAME_COMMIT_REQUIRED')
        result.read_ordinary()
        if pending is not None:
            # Only the exact pre-Dump permits named subtraction; exact post
            # skips it. Network/resource effects are NEVER replayed here.
            if m.encode(bindings) == m.encode(pending['before']):
                result.bindings = store.remove(pending['remove'],bindings)
                controller.ordinary_authority.bindings = result.bindings
                retired = {by_role[b['capability']['role']] for b in pending['remove']}
                inherited.owned = [fd for fd in inherited.owned if fd not in retired]
                errors = []
                for fd in retired:
                    try: os.close(fd)
                    except BaseException as error: errors.append(error)
                m.need(not errors,'NETWORK_FD_DISPOSAL_UNKNOWN')
            store.verify(result.bindings)
        association = {'version':1,'grantSha256':state['receiptSha256'],'originalInvocationId':state['originalInvocationId'],
            'newInvocationId':store.invocation,'ownerUnit':UNIT,'ownerPid':os.getpid(),'ownerStart':m.proc_start(os.getpid()),
            'closedNames':[b['name'] for b in result.bindings],'snapshotSha256':m.digest(m.encode(result.bindings)),
            'originalMonotonicEnd':state['originalMonotonicEnd']}
        journal.append({'kind':'recovery-association','value':association})
        publish(m,journal,'recovery-association.json',association,new=False)
        result.persist_state()
        return result

    def abandon_temporary(self,request):
        """Finite explicit pre-capture OLD return; never a post-COMMIT fallback."""
        m,c,k = self.m,self.c,self.c.k
        m.keys(request,'generation sequence operation')
        m.need(not c.failed and not getattr(self,'old_return_started',False) and c.phase == 'prepared' and
               self.pending is None and self.preparation is None and self.receipt is None and self.offer is None and
               request == {'generation':c.p['generation'],'sequence':c.seq+1,'operation':'abandon'},
               'KNOWN_OLD_PRECAPTURE_ONLY')
        self.old_return_started = True  # uncertain release/ACK is not replayable
        try:
            self.lease.check()
            self.host.request('restore-network-old')  # authenticated original holder/Fence roundtrip
            # OLD has been confirmed. Do not call the held-Fence checker again.
            c.guard = self.lease.check
            k.leave_fence_rendezvous()
            c.live()
            return c.command(request)
        except BaseException:
            c.failed = True; c.phase = 'unknown-retained'
            raise

    def park_holder(self, request):
        m,c = self.m,self.c
        m.keys(request,'generation sequence operation')
        m.need(self.pending is None and request == {'generation':c.p['generation'],'sequence':c.seq+1,'operation':'handoff'} and
               c.phase == 'prepared', 'EXACT_TERMINAL_HOLDER_REQUEST_REQUIRED')
        c.live(); c.seq += 1
        c.j.append({'kind':'command','sequence':c.seq,'operation':'handoff'})
        self.pending = request
        self.terminal_deadline = min(c.end,time.monotonic()+115)

    def peer(self,conn,coordinator=None):
        m = self.m
        pid,uid,gid = struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        m.need(uid == gid == 0,'ROOT_COORDINATOR_REQUIRED')
        if self.coordinator is None:
            intent = m.decode(m.trusted_read(HOST_STATE+'/coordinated-restore.json'))
            m.need(coordinator is not None and intent['phase'] == 'restored-held' and
                   coordinator == {'pid':pid,'start':m.proc_start(pid),'nonce':intent['nonce']} and
                   {k:intent['origin'][k] for k in ('pid','start')} == {k:coordinator[k] for k in ('pid','start')},
                   'SAME_ORIGINAL_COORDINATOR_REQUIRED')
            self.coordinator = coordinator; self.coordinator_pidfd = os.pidfd_open(pid)
        m.need(pid == self.coordinator['pid'] and m.proc_start(pid) == self.coordinator['start'] and
               not select.select([self.coordinator_pidfd],[],[],0)[0], 'ORIGINAL_COORDINATOR_LOST')

    def prepare_ordinary(self,coordinator):
        m,c,k = self.m,self.c,self.c.k
        m.need(self.pending is not None and self.preparation is None and c.phase == 'prepared', 'ONE_PENDING_HANDOFF_REQUIRED')
        c.live(); self.lease.check()
        offer = self.host.request('stage-network-successor',coordinator=coordinator)
        self.offer = offer  # own before semantics
        original_kernel = self.host.freezer.LinuxKernel()
        original_kernel.barrier = self.host.freezer.SystemdRelaunchBarrier()
        self.fence = self.host.freezer.Fence.accept_live(offer,original_kernel)
        self.host.shared.verify_record(self.host.shared.read_record(HOST_STATE,self.host.isolation),
                                       self.host.plan,self.fence.kernel,self.host.isolation)
        rows,fds = list(offer.rows),list(offer.fds)
        for group, values, kind in (('ns',k.fds,'nsfs'),('pid',k.pidfds,'pidfd'),('exe',k.peer_exes,'exe')):
            for role,fd in sorted(values.items()):
                rows.append(self.host.freezer.capability(fd,'network.'+group+'.'+role,kind)); fds.append(fd)
        rows.append(self.host.freezer.capability(c.j.fd,'network.journal','journal')); fds.append(c.j.fd)
        m.need(len(rows)+7 <= 16384,'PRECOMMIT_SERVING_FD_CAPACITY_REQUIRED')
        self.bindings = self.store.stage(rows,fds)
        preparation = {'version':1,'context':m.CONTEXT,'machine':c.p['machine'],'boot':c.p['boot'],
            'generation':c.p['generation'],'networkPlanSha256':m.digest(self.host.raw),
            'isolationPlanSha256':m.digest(self.host.plan_raw),'hostPlanHash':self.host.identity['planHash'],
            'ownerUnit':UNIT,'ownerInvocationId':self.store.invocation,'ownerPid':os.getpid(),
            'ownerStart':m.proc_start(os.getpid()),'coordinator':coordinator,'temporaryHolder':self.lease.holder,
            'holderSequence':c.seq,'leaseSha256':m.digest(self.lease.raw),'originalDeadline':c.p['deadline'],
            'originalMonotonicEnd':c.end,'hostFence':{'owner':self.host.identity['owner'],
            'originalGuard':{key:self.host.identity[key] for key in ('pid','start')},
            'recordSha256':m.digest(m.trusted_read(HOST_STATE+'/host/hold.json')),
            'freezerSha256':self.host.plan['hostHold']['freezerSha256'],'liveOfferSha256':offer.sha256},
            'freshNetns':m.identity(m.NETNS),'resourceSealSha256':m.digest(m.encode(self.resources())),
            'baselineSha256':m.digest(m.encode(c.baseline)),'fdManifestSha256':m.digest(m.encode(rows)),
            'stopConfigSha256':c.p['ordinaryOwner']['stopConfigSha256']}
        c.j.append({'kind':'network-preparation','value':preparation,'fdBindings':self.bindings})
        c.live(); self.preparation = preparation
        return preparation

    def resources(self):
        k = self.c.k
        return {'network':k.sealed,'nft':k.firewall_seal,'nodeTable':getattr(k,'node_table_seal',None),
                'nodeForward':getattr(k,'node_forward_seal',[]),'owned':[
                    [where,name,value] for (where,name),value in sorted(k.owned.items())]}

    def handoff_binding(self):
        m,p = self.m,self.preparation
        return {'version':1,'preparationSha256':m.digest(m.encode(p)),'generation':p['generation'],
                'networkPlanSha256':p['networkPlanSha256'],'recipientInvocationId':p['ownerInvocationId'],
                'resourceSealSha256':p['resourceSealSha256'],'fdManifestSha256':p['fdManifestSha256'],
                'disposition':'ordinary-fresh'}

    def accept_ordinary(self,conn,request):
        m,c,k = self.m,self.c,self.c.k
        m.need(self.preparation is not None and self.receipt is None and c.phase == 'prepared','ONE_PREPARED_GRANT_REQUIRED')
        fds = receive_rights(conn,m,7)
        rows = request['manifest']
        # Transfer into kernel-owned registry before any semantic validation.
        k.accept_serving_live(request['serving'],fds,rows,self.host.freezer)
        c.live()
        raw = os.pread(fds[4],131073,0); commit = m.decode(raw); commit_sha = m.digest(raw)
        policy_raw = os.pread(fds[5],8*1024*1024+1,0); policy = m.decode(policy_raw)
        attempt = m.decode(os.pread(fds[6],131073,0))
        m.need(commit_sha == request['commitSha256'] and commit['networkHandoff'] == self.handoff_binding() and
               commit['nonce'] == self.coordinator['nonce'] and commit['restoreIntent']['origin']['pid'] == self.coordinator['pid'] and
               commit['freshPolicySha256'] == m.digest(m.encode(policy)) and
               policy['inventory']['networkPlanSha256'] == self.preparation['networkPlanSha256'] and
               attempt == {'commitSha256':commit_sha,'phase':'confirmed','serving':request['serving']}, 'SAME_COMMIT_SERVING_BINDING_REQUIRED')
        for fd,path in ((fds[4],HOST_STATE+'/handoff-commit.json'),(fds[5],'/etc/c3-test-fresh-classic.json'),
                        (fds[6],HOST_STATE+'/fresh-launch-attempt.json')):
            s = os.fstat(fd)
            m.need(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0 and not s.st_mode & 0o022,
                   'ROOT_FIXED_SERVING_INPUT_REQUIRED')
            expected = m.trusted_fd(path)
            try:
                check = os.fstat(expected)
                m.need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns) ==
                       (check.st_dev,check.st_ino,check.st_size,check.st_mtime_ns,check.st_ctime_ns),
                       'FIXED_SERVING_INPUT_REPLACED')
            finally: os.close(expected)
        self.bindings = self.store.stage(rows,fds,self.bindings)
        c.checked_probe(k.direct_probe); k.caddy_probe()
        c.effect('caddy-exact-new-config',lambda:k.config(c.p['newConfig']))
        m.need(m.encode(k.config()) == m.encode(c.p['newConfig']),'CADDY_WRITE_UNCONFIRMED')
        public = k.public_probe(); direct = k.direct_probe(); c.live()
        surrender = self.host.request('surrender-network-successor',commitSha256=commit_sha)
        # From here, all failures are handoff-unknown, never OLD/temporary authority.
        c.phase = 'handoff-unknown'
        self.lease.check(); self.offer.check(); self.fence.consume_live(commit_sha,surrender['transcriptSha256'])
        self.store.verify(self.bindings)
        receipt = {**self.preparation,'commitSha256':commit_sha,'serving':{
            'pid':request['serving']['pid'],'start':request['serving']['start'],'netns':m.identity(m.NETNS),
            'exeSha256':self.fd_sha(fds[2]),'cgroupInode':os.fstat(fds[3]).st_ino},
            'servingFdManifestSha256':m.digest(m.encode(rows)),
            'acceptedFdStoreManifestSha256':m.digest(m.encode(self.bindings)),
            'caddyNewConfigSha256':m.digest(m.encode(c.p['newConfig'])),'publicServingCheck':public,
            'directServingCheck':direct,'hostFenceHandoffTranscriptSha256':surrender['transcriptSha256'],
            'authorityPhase':'ordinary-owned'}
        self.lease.check()
        receipt_sha = publish(m,c.j,'ordinary-owned.json',receipt)
        # A visible receipt after failed publication is NOT a successful grant.
        self.receipt = receipt; self.accepted_bindings = list(self.bindings); c.phase = 'ordinary-owned'
        c.ordinary_authority = OrdinaryAuthority(m,c,self.fence,self.store,self.bindings,receipt)
        k.verification_mode = 'succeeded-original-fence'; k.original_fence_check = self.fence.check
        self.persist_state()
        self.read_ordinary()
        return {'commitSha256':commit_sha,'networkOwnershipSha256':receipt_sha}

    def fd_sha(self,fd):
        import hashlib
        sha = hashlib.sha256(); offset = 0
        while block := os.pread(fd,65536,offset): offset += len(block); sha.update(block)
        return sha.hexdigest()

    def read_ordinary(self):
        m,c = self.m,self.c
        m.need(self.receipt is not None,'ORDINARY_ACCEPTANCE_REQUIRED')
        c.live()
        m.need(m.trusted_read(str(c.j.path/'ordinary-owned.json')) == m.encode(self.receipt),'ORDINARY_RECEIPT_DRIFT')
        if c.phase not in ('network-removed-host-held','parked-serving'):
            m.need(m.encode(c.k.config()) == m.encode(c.p['newConfig']),'ORDINARY_CADDY_DRIFT')
            c.k.direct_probe(); c.k.public_probe()
        c.live()
        return {'commitSha256':self.receipt['commitSha256'],'networkOwnershipSha256':m.digest(m.encode(self.receipt))}

    def stop(self):
        try:
            return self._stop()
        except BaseException:
            self.c.failed = True; self.c.phase = 'unknown-retained'
            raise

    def _stop(self):
        """No app kill, no OLD return. Proven EMPTY alone permits exact removal."""
        m,c,k = self.m,self.c,self.c.k
        c.stop_deadline = time.monotonic()+25
        m.need(self.receipt is not None and not c.failed and c.phase in
               ('ordinary-owned','parked-serving','network-removed-host-held'), 'STOP_WITHOUT_ACCEPTED_GRANT_RETAINED')
        if c.phase == 'network-removed-host-held':
            self.fence.check(); self.store.verify(self.bindings)
            return {'status':'NETWORK_REMOVED_HOST_HOLDS_RETAINED'}
        live = k.serving_live
        self.fence.check(); self.store.verify(self.bindings)
        if not select.select([live['fds'][0]],[],[],0)[0]:
            c.phase = 'parked-serving'; self.persist_state()
            return {'status':'PARKED_SERVING_HOST_HOLDS_RETAINED'}
        # Death is original pidfd readability, not a historical PID lookup.
        # The held exact cgroup must have no tasks; all-thread netns census too.
        cg = live['fds'][3]
        fd = os.open('cgroup.procs',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=cg)
        try: m.need(os.read(fd,65537).strip() == b'', 'APPLICATION_CGROUP_NOT_EMPTY')
        finally: os.close(fd)
        k.require_empty_namespace()
        live['empty'] = True; c.phase = 'stop-empty'; c.live()
        c.j.append({'kind':'ordinary-empty','generation':c.p['generation']})
        self.persist_state()
        stopped = m.stopped_config(c.p)
        m.need(m.encode(k.config()) == m.encode(c.p['newConfig']), 'STOP_CADDY_BASELINE_REQUIRED')
        c.effect('caddy-exact-stopped-config',lambda:k.config(stopped))
        m.need(m.encode(k.config()) == m.encode(stopped), 'STOP_CADDY_WRITE_UNKNOWN')
        k.stopped_probe()
        c.effect('remove-owned-ordinary-network',lambda:k.remove(c.baseline,ordinary=True))
        # Named subtraction retains every original host Fence capability.
        remove = cleanup_bindings(self.bindings)
        c.j.append({'kind':'intent','effect':'fdstore-network-subtraction','names':[b['name'] for b in remove]})
        self.pending_cleanup = {'before':list(self.bindings),'after':[b for b in self.bindings if b not in remove],
                                'remove':remove}
        k.residual_only = True; k.sealed = None; k.firewall_seal = None
        c.phase = 'network-cleanup-pending'
        self.persist_state()  # durable exact pre/post endpoints BEFORE the first remove
        self.bindings = self.store.remove(remove,self.bindings)
        c.ordinary_authority.bindings = self.bindings
        # Retire every own fresh namespace and serving duplicate before one close.
        owned = list(live['fds']); live['fds'] = []
        fresh_fd = k.fds.pop('fresh'); owned.append(fresh_fd); k.netns_fd = None
        errors = []
        for fd in set(owned):
            try: os.close(fd)
            except BaseException as error: errors.append(error)
        m.need(not errors,'NETWORK_FD_DISPOSAL_UNKNOWN')
        k.serving_live = None; k.sealed = None; k.firewall_seal = None
        self.pending_cleanup = None
        c.phase = 'network-removed-host-held'
        self.fence.check(); self.store.verify(self.bindings)
        # Full residual checkpoint retains the exact original offer and grant.
        self.persist_state()
        return {'status':'NETWORK_REMOVED_HOST_HOLDS_RETAINED'}

    def finish_temporary_scope(self,holder):
        m,c = self.m,self.c
        m.need(not self.finished and self.receipt is not None and time.monotonic() < self.terminal_deadline,
               'FINITE_TERMINAL_COMPLETION_REQUIRED')
        intent = m.decode(m.trusted_read(HOST_STATE+'/coordinated-restore.json'))
        m.need(intent['phase'] == 'handoff-completed' and intent['nonce'] == self.coordinator['nonce'],
               'SAME_COORDINATOR_CLEANUP_REQUIRED')
        self.host.request('finish-network-successor',commitSha256=self.receipt['commitSha256'])
        remaining = self.terminal_deadline-time.monotonic()
        m.need(remaining > 0 and select.select([self.host.pidfd],[],[],remaining)[0], 'PASSIVE_HOST_DISPOSAL_UNKNOWN')
        result = {**self.pending,**self.read_ordinary()}
        send(holder,result,m)
        holder.settimeout(max(.001,self.terminal_deadline-time.monotonic()))
        m.need(receive(holder,m) == {'op':'holder-disposed',**result},'HOLDER_REQUIRED_DISPOSAL_UNKNOWN')
        remaining = self.terminal_deadline-time.monotonic()
        m.need(remaining > 0 and select.select([self.lease.pidfd],[],[],remaining)[0] and holder.recv(1) == b'',
               'ORIGINAL_HOLDER_NATURAL_DISPOSAL_UNKNOWN')
        self.finished = True
        return self.read_ordinary()

    def persist_state(self):
        k,c = self.c.k,self.c
        state = {'version':1,'receiptSha256':self.m.digest(self.m.encode(self.receipt)),
            'phase':c.phase,'bindings':self.bindings,'acceptedBindings':self.accepted_bindings or self.bindings,
            'pendingCleanup':self.pending_cleanup,'hostOffer':{'state':self.offer.state,'manifest':self.offer.rows},
            'network':{'pids':k.pids,'peerPins':k.peer_pins,'sealed':k.sealed,'firewallSeal':k.firewall_seal,
             'nodeTableSeal':getattr(k,'node_table_seal',None),'nodeForwardSeal':getattr(k,'node_forward_seal',[]),
             'owned':[[a,b,v] for (a,b),v in sorted(k.owned.items())],'pathIdentity':k.path_identity,
             'pathState':k.path_state,'loopbackLinks':sorted(getattr(k,'loopback_links',[])),
             'runtimeSettings':getattr(k,'runtime_settings',None).decode() if getattr(k,'runtime_settings',None) is not None else None,
             'serving':k.serving_live['serving'] if k.serving_live is not None and not getattr(k,'residual_only',False) else None,
             'servingRows':k.serving_live['rows'] if k.serving_live is not None and not getattr(k,'residual_only',False) else []},
             'baseline':c.baseline,'sequence':c.seq,'counter':c.j.counter,'originalMonotonicEnd':c.end,
             'originalInvocationId':self.preparation['ownerInvocationId']}
        publish(self.m,c.j,'ordinary-state.json',state,new=False)


class TerminalClient:
    """Pinned same-Coordinator peer, selected only by accepted root policy."""
    def __init__(self,m,held,policy):
        self.m,self.held,self.policy = m,held,policy
        self.conn = None; self.pidfd = None; self.used = False; self.preparation = None
        raw = m.trusted_read(m.INPUT); plan = m.validate_plan(m.decode(raw))
        m.need(held.config['version'] == 2 and 'ordinaryOwner' in plan and
               policy['inventory'].get('networkPlanSha256') == m.digest(raw), 'ROOT_SELECTED_NETWORK_PATH_REQUIRED')
        self.raw,self.plan = raw,plan
        shared = m.decode(m.trusted_read(ISOLATION_PLAN))
        m.need(shared.get('version') == 2 and shared['hostHold'].get('networkPlanSha256') == m.digest(raw),
               'SHARED_POLICY_NETWORK_BINDING_REQUIRED')
        self.freezer = fixed_module(m,'/usr/local/libexec/c3-panel-host-freezer.py',shared['hostHold']['freezerSha256'])
        self.conn = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); self.conn.settimeout(3)
        self.socket_identity = m.identity(TERMINAL); self.conn.connect(TERMINAL)
        self.pid,self.uid,self.gid = struct.unpack('3i',self.conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        self.start = m.proc_start(self.pid); self.pidfd = os.pidfd_open(self.pid)
        owner = manager_show(m,UNIT)
        m.need(self.uid == self.gid == 0 and owner.get('MainPID') == owner.get('ExecMainPID') == str(self.pid) and
               owner.get('ControlGroup') == '/system.slice/'+UNIT and owner.get('ActiveState') == 'active' and
               owner.get('SubState') == 'running' and not owner.get('DropInPaths'), 'PINNED_NETWORK_MAIN_REQUIRED')
        self.invocation = owner['InvocationID']
        self.check()

    def check(self):
        m = self.m
        m.need(self.conn is not None and not select.select([self.pidfd],[],[],0)[0] and
               m.proc_start(self.pid) == self.start and m.identity(TERMINAL) == self.socket_identity and
               m.trusted_read(m.INPUT) == self.raw and
               struct.unpack('3i',self.conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)) == (self.pid,0,0),
               'NETWORK_TERMINAL_PEER_LOST')

    def request(self,op,**extra):
        self.check(); self.conn.settimeout(max(.001,min(3,self.held.deadline-time.monotonic())))
        send(self.conn,{'op':op,**extra},self.m)
        result = receive(self.conn,self.m)
        self.check(); return result

    def prepare_ordinary(self):
        m,h = self.m,self.held
        m.need(not self.used,'NETWORK_PREPARATION_REPLAY_REFUSED'); self.used=True
        coordinator = {'pid':h.origin['pid'],'start':h.origin['start'],'nonce':h.nonce}
        p = self.request('prepare-ordinary',coordinator=coordinator)
        fields = ('version context machine boot generation networkPlanSha256 isolationPlanSha256 hostPlanHash ownerUnit '
                  'ownerInvocationId ownerPid ownerStart coordinator temporaryHolder holderSequence leaseSha256 originalDeadline '
                  'originalMonotonicEnd hostFence freshNetns resourceSealSha256 baselineSha256 fdManifestSha256 stopConfigSha256')
        m.keys(p,fields)
        m.need(p['version'] == 1 and p['networkPlanSha256'] == m.digest(self.raw) and p['ownerUnit'] == UNIT and
               p['ownerInvocationId'] == self.invocation and p['ownerPid'] == self.pid and p['ownerStart'] == self.start and
               p['coordinator'] == coordinator and p['stopConfigSha256'] == self.plan['ordinaryOwner']['stopConfigSha256'],
               'EXACT_NETWORK_PREPARATION_REQUIRED')
        self.preparation = p
        return {'version':1,'preparationSha256':m.digest(m.encode(p)),'generation':p['generation'],
                'networkPlanSha256':p['networkPlanSha256'],'recipientInvocationId':p['ownerInvocationId'],
                'resourceSealSha256':p['resourceSealSha256'],'fdManifestSha256':p['fdManifestSha256'],
                'disposition':'ordinary-fresh'}

    def accept_ordinary(self,serving):
        import array

        m,h = self.m,self.held
        fds = []
        try:
            pid = serving['pid']
            for opener in (lambda:os.pidfd_open(pid),lambda:os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY|os.O_CLOEXEC),
                lambda:os.open('/proc/'+str(pid)+'/exe',os.O_RDONLY|os.O_CLOEXEC),
                lambda:os.open('/sys/fs/cgroup/system.slice/c3-test-fresh-classic.service',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)):
                fds.append(opener())
            for path in (HOST_STATE+'/handoff-commit.json','/etc/c3-test-fresh-classic.json',HOST_STATE+'/fresh-launch-attempt.json'):
                fd = m.trusted_fd(path); fds.append(fd)
            roles = ('serving.pid','serving.net','serving.exe','serving.cgroup','serving.commit','serving.policy','serving.attempt')
            kinds = ('pidfd','nsfs','exe','cgroup','file','file','file')
            rows = [self.freezer.capability(fd,role,kind) for fd,role,kind in zip(fds,roles,kinds)]
            self.check()
            send(self.conn,{'op':'accept-ordinary','serving':serving,'commitSha256':h.commit_sha,'manifest':rows},m)
            m.need(self.conn.sendmsg([b'F'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))]) == 1,
                   'SERVING_RIGHTS_SEND_UNKNOWN')
            result = receive(self.conn,m); self.check()
            m.keys(result,'commitSha256 networkOwnershipSha256'); m.pin(result['networkOwnershipSha256'])
            m.need(result['commitSha256'] == h.commit_sha,'NETWORK_COMMIT_MISMATCH')
            return result
        finally:
            errors = []
            for fd in fds:
                try: os.close(fd)
                except BaseException as error: errors.append(error)
            if errors: raise errors[0]

    def finish_temporary_scope(self): return self.request('finish-temporary-scope')
    def read_ordinary(self): return self.request('read-ordinary')
    def close(self):
        errors=[]
        conn,self.conn = self.conn,None; fd,self.pidfd = self.pidfd,None
        for item in (conn,fd):
            if item is not None:
                try: item.close() if item is conn else os.close(item)
                except BaseException as error: errors.append(error)
        if errors: raise errors[0]


def coordinator_network(held,policy):
    """Called only by the fixed fresh root composition, never a proof/env switch."""
    import types
    shared_raw = trusted_bootstrap(ISOLATION_PLAN)
    shared = __import__('json').loads(shared_raw)
    pins = shared['runtimePins']
    path = '/usr/local/libexec/c3-test-fresh-network.py'
    raw = trusted_bootstrap(path)
    import hashlib
    if hashlib.sha256(raw).hexdigest() != pins[path]: raise RuntimeError('NETWORK_SOURCE_PIN_REQUIRED')
    module = types.ModuleType('c3_coordinator_network'); module.__file__=path
    exec(compile(raw,path,'exec'),module.__dict__)
    return TerminalClient(module,held,policy)


def trusted_bootstrap(path):
    # Fixed-root source closure, read without executing an unpinned loader/pyc.
    fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOATIME|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        parts = Path(path).parts[1:]
        for index,part in enumerate(parts):
            child = os.open(part,os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW|os.O_CLOEXEC|
                            (os.O_DIRECTORY if index < len(parts)-1 else 0),dir_fd=fd)
            previous,fd = fd,child; os.close(previous)
            s = os.fstat(fd)
            if s.st_uid != 0 or s.st_gid != 0 or s.st_mode & 0o022: raise RuntimeError('UNTRUSTED_NETWORK_SOURCE')
        raw = os.read(fd,8*1024*1024+1)
        if len(raw) > 8*1024*1024: raise RuntimeError('NETWORK_SOURCE_LIMIT')
        return raw
    finally: os.close(fd)


class Lease:
    def __init__(self, m, p, raw_plan):
        self.m, self.p, self.raw_plan = m, p, raw_plan
        self.raw = m.trusted_read(m.LEASE)
        value = m.decode(self.raw)
        m.keys(value, 'version context generation boot planSha256 holder deadline operations')
        m.need(type(value['version']) is int and value['version'] == 1 and value['context'] == m.CONTEXT and
               value['generation'] == p['generation'] and value['boot'] == p['boot'] and
               value['planSha256'] == m.digest(raw_plan) and type(value['deadline']) is int and
               value['deadline'] == p['deadline'] and 0 < value['deadline']-time.time() <= 600,
               'INDEPENDENT_LIVE_LEASE_REQUIRED')
        m.keys(value['holder'], 'pid start')
        m.integer(value['holder']['pid'])
        m.need(type(value['holder']['start']) is str and value['holder']['start'].isdigit() and
               value['operations'] == ['observe', 'cutover', 'return', 'abandon']+(['handoff'] if 'ordinaryOwner' in p else []), 'CLOSED_OWNER_LEASE_REQUIRED')
        self.holder = value['holder']
        self.pidfd = os.pidfd_open(self.holder['pid'])
        self.revoked = False
        self.check()

    def check(self):
        m = self.m
        try:
            m.need(not self.revoked and not select.select([self.pidfd], [], [], 0)[0] and
                   m.proc_start(self.holder['pid']) == self.holder['start'] and
                   time.time() < self.p['deadline'], 'OWNER_LEASE_LOST')
            status = Path('/proc', str(self.holder['pid']), 'status').read_text().splitlines()
            m.need('Uid:\t0\t0\t0\t0' in status and
                   m.trusted_read(m.INPUT) == self.raw_plan and m.trusted_read(m.LEASE) == self.raw,
                   'OWNER_OR_ACCEPTED_INPUT_DRIFT')
        except BaseException:
            self.revoked = True
            raise

    def peer(self, channel):
        pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        self.m.need(uid == gid == 0 and pid == self.holder['pid'], 'EXACT_ROOT_OWNER_REQUIRED')
        self.check()

    def close(self):
        os.close(self.pidfd)


def unlink_owned_control(m, controller, socket_identity):
    def operation():
        controller.live()
        m.need(m.identity(m.SOCKET) == socket_identity and stat.S_ISSOCK(os.lstat(m.SOCKET).st_mode),
               'CONTROL_SOCKET_OWNERSHIP_LOST')
        os.unlink(m.SOCKET)
        m.need(not os.path.lexists(m.SOCKET), 'CONTROL_SOCKET_UNLINK_UNCONFIRMED')
    return controller.effect('control-socket-unlink', operation)


def _listener(m,path):
    m.need(not os.path.lexists(path),'STALE_CONTROL_SOCKET_RETAINED')
    listener = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        listener.bind(path); os.chmod(path,0o600); listener.listen(2); listener.settimeout(.2)
        return listener
    except BaseException:
        listener.close(); raise


def run_ordinary(m,p,raw,inherited=None):
    rights = inherited if inherited is not None else (InheritedRights(m) if os.environ.get('LISTEN_FDS') else None)
    try:
        return _run_ordinary(m,p,raw,rights)
    except BaseException as primary:
        if rights is not None: rights.close(primary)
        raise
    finally:
        if rights is not None: rights.close()


def _run_ordinary(m,p,raw,inherited):
    """The existing Type=exec unit remains main and owns every ordinary check."""
    import signal
    store = PID1Store(m,p['generation'])  # active existing anchor before escrow or acceptance
    owner = lease = host = controller = kernel = journal = holder = terminal_peer = None
    holder_server = terminal_server = None
    stopping = [False]
    previous = {sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT)}
    for sig in previous: signal.signal(sig,lambda *_:stopping.__setitem__(0,True))
    try:
        if inherited is not None:
            owner = OwnerRuntime.recover(m,p,raw,store,inherited)
            controller,kernel,journal = owner.c,owner.c.k,owner.c.j
        else:
            store.verify([])
            lease = Lease(m,p,raw)
            host = HostFenceChannel(m,p,raw,lease,store.invocation)
            kernel = m.Linux(p); journal = m.Journal(Path(m.STATE)/p['generation'],p)
            controller = m.Controller(p,kernel,journal,guard=lease.check)
            owner = OwnerRuntime(m,controller,lease,host,store)
            holder_server = _listener(m,m.SOCKET)
            holder_server.settimeout(3); holder,_ = holder_server.accept(); holder.settimeout(3); lease.peer(holder)
            holder_server.close(); holder_server = None
            initial = controller.prepare()
            kernel.enter_fence_rendezvous(host.check)
            controller.guard = TemporaryAuthority(lease,host).check
            send(holder,initial,m)
        # A reconstructed owner has no original temporary caller to serve.
        # Do not adopt/unlink stale sockets or reopen a terminal channel.
        if inherited is None: terminal_server = _listener(m,TERMINAL)
        parked = False
        while True:
            if stopping[0]:
                stopping[0] = False
                try:
                    result = owner.stop()
                    print(m.encode(result).decode(),flush=True)
                except BaseException as error:
                    print(m.encode({'status':'STOP_UNKNOWN_HOST_HOLDS_RETAINED','reason':type(error).__name__}).decode(),flush=True)
                    raise
                return result
            if parked:
                time.sleep(.2); continue
            try:
                if owner.receipt is None:
                    lease.check()
                    if owner.pending is not None:
                        m.need(time.monotonic() < owner.terminal_deadline,'FINITE_HANDOFF_WAIT_EXPIRED')
                    else:
                        if select.select([holder],[],[],.1)[0]:
                            request = receive(holder,m)
                            if request.get('operation') == 'handoff': owner.park_holder(request)
                            else:
                                m.need(request.get('operation') in ('observe','abandon'),'TERMINAL_OWNS_FRESH_CUTOVER')
                                result = owner.abandon_temporary(request) if request['operation'] == 'abandon' else controller.command(request)
                                send(holder,result,m)
                                if controller.phase == 'abandoned':
                                    unlink_owned_control(m,controller,m.identity(m.SOCKET))
                                    return
                    if controller.phase == 'new': continue
                else:
                    owner.read_ordinary()
                    if terminal_server is None:
                        time.sleep(.2); continue
                if terminal_peer is None:
                    if not select.select([terminal_server],[],[],.1)[0]: continue
                    terminal_peer,_ = terminal_server.accept(); terminal_peer.settimeout(3)
                if not select.select([terminal_peer],[],[],.1)[0]: continue
                request = receive(terminal_peer,m)
                op = request.get('op')
                if op == 'prepare-ordinary':
                    m.keys(request,'op coordinator'); owner.peer(terminal_peer,request['coordinator'])
                    result = owner.prepare_ordinary(request['coordinator'])
                elif op == 'accept-ordinary':
                    m.keys(request,'op serving commitSha256 manifest'); owner.peer(terminal_peer)
                    result = owner.accept_ordinary(terminal_peer,request)
                elif op == 'finish-temporary-scope':
                    m.keys(request,'op'); owner.peer(terminal_peer); result = owner.finish_temporary_scope(holder)
                    holder.close(); holder = None
                elif op == 'read-ordinary':
                    m.keys(request,'op'); owner.peer(terminal_peer); result = owner.read_ordinary()
                else: m.need(False,'CLOSED_TERMINAL_OPERATION_REQUIRED')
                send(terminal_peer,result,m)
                if op == 'read-ordinary' and owner.finished:
                    terminal_peer.close(); terminal_peer = None
            except BaseException as error:
                # No grant synthesis, reattempt, OLD return, app kill or clear.
                parked = True
                print(m.encode({'status':'UNKNOWN_RETAINED','reason':type(error).__name__}).decode(),flush=True)
    finally:
        errors = []
        for sig,value in previous.items(): signal.signal(sig,value)
        for obj in (terminal_peer,terminal_server,holder,holder_server,host,lease,kernel,journal,
                    owner.offer if owner is not None else None):
            if obj is not None:
                try: obj.close()
                except BaseException as error: errors.append(error)
        if owner is not None and owner.coordinator_pidfd is not None:
            fd,owner.coordinator_pidfd = owner.coordinator_pidfd,None
            try: os.close(fd)
            except BaseException as error: errors.append(error)
        if errors: raise errors[0]


def run(m):
    rights = InheritedRights(m) if os.environ.get('LISTEN_FDS') else None
    try:
        return _run(m,rights)
    except BaseException as primary:
        if rights is not None: rights.close(primary)
        raise
    finally:
        if rights is not None: rights.close()


def _run(m,inherited):
    m.need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
           'ROOT_ONLY_FIXED_NETWORK_ENTRY')
    m.need(m.identity('/proc/self/ns/mnt') == m.identity('/proc/1/ns/mnt') and
           m.identity('/proc/self/ns/pid') == m.identity('/proc/1/ns/pid'), 'HOST_PID_MOUNT_NAMESPACES_REQUIRED')
    raw = m.trusted_read(m.INPUT)
    p = m.validate_plan(m.decode(raw))
    if 'ordinaryOwner' in p:
        return run_ordinary(m,p,raw,inherited)
    m.need(inherited is None,'LEGACY_INHERITANCE_REFUSED')
    lease = Lease(m, p, raw)
    kernel = journal = listener = None
    socket_identity = None
    try:
        # Parent paths are independently preinstalled root-controlled directories.
        for path in ('/run/netns', m.STATE, '/run'):
            fd = m.trusted_fd(path, directory=True)
            os.close(fd)
        journal = m.Journal(Path(m.STATE)/p['generation'], p)
        kernel = m.Linux(p)
        controller = m.Controller(p, kernel, journal, guard=lease.check)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # bind never unlinks/adopts an existing path; this process keeps exact inode.
        listener.bind(m.SOCKET)
        os.chmod(m.SOCKET, 0o600)
        socket_identity = m.identity(m.SOCKET)
        listener.listen(1)
        listener.settimeout(max(.01, min(3, p['deadline']-time.time())))
        # No networking effects until exact independently accepted owner connects.
        channel, _ = listener.accept()
        with channel:
            lease.peer(channel)
            channel.settimeout(3)
            result = controller.prepare()
            send(channel, result, m)
            while controller.phase != 'abandoned':
                lease.peer(channel)
                m.need(m.identity(m.SOCKET) == socket_identity, 'CONTROL_SOCKET_REPLACED')
                channel.settimeout(max(.01, min(30, p['deadline']-time.time())))
                command = receive(channel, m)
                result = controller.command(command)
                lease.peer(channel)
                send(channel, result, m)
        # Only normal confirmed abandonment permits exact-owned socket unlink.
        unlink_owned_control(m, controller, socket_identity)
        controller.live()
        journal.append({'kind': 'terminal-abandoned', 'generation': p['generation']})
    finally:
        if listener is not None: listener.close()
        if kernel is not None: kernel.close()
        if journal is not None: journal.close()
        lease.close()
