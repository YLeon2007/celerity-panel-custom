"""Local ordinary files/OFD/pidfd/UDS; privileged/PID1 seams are models."""
import array
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

f = load('ordinary_freezer', HERE.parent/'panel-host-freezer.py')
n = load('ordinary_network', HERE/'fresh_network.py')
c = load('ordinary_control', HERE/'fresh_network_control.py')

class LiveSuccessionTests(unittest.TestCase):
    def test_actual_locked_journal_crosses_rights_without_reopen_or_unlock(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = f.Journal(Path(directory)/'host')
            class Kernel:
                def verify(self, expected, frozen, dead): pass  # modeled cgroup freezer
                def live_capabilities(self, expected): return []
                def check_live_capabilities(self):
                    for row,fd in self._live:
                        assert f.capability(fd,row['role'],row['kind'],row.get('binding')) == row
            original = f.Fence({'groups': {}, 'freezeOrder': []}, Kernel(), journal, 'owner')
            original.phase = 'held'; original.record('held')
            left, right = socket.socketpair()
            result = []; errors = []
            def receive():
                try: result.append(f.LiveFenceOffer.receive(right, expected_peer=os.getpid()))
                except BaseException as error: errors.append(error)
            thread = threading.Thread(target=receive); thread.start()
            offer = original.stage_live('a'*64)
            offer.send(left)
            thread.join(3)
            self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
            received = result[0]
            shared = received.fds[0]
            fcntl.flock(shared, fcntl.LOCK_EX|fcntl.LOCK_NB)
            independent = os.open(journal.path, os.O_RDONLY|os.O_DIRECTORY)
            try:
                with self.assertRaises(BlockingIOError): fcntl.flock(independent, fcntl.LOCK_EX|fcntl.LOCK_NB)
                original.surrender_live(offer.sha256, 'b'*64)
                with self.assertRaisesRegex(RuntimeError, 'passive'): original.record('held')
                original.check()  # passive is read-only, no second journal writer
                successor = f.Fence.accept_live(received,Kernel())
                transcript = f.live_sha(f.live_encode({'liveOfferSha256':offer.sha256,'commitSha256':'b'*64}))
                successor.consume_live('b'*64,transcript)
                successor.check()
                with self.assertRaisesRegex(RuntimeError,'escrow'): successor.consume_live('b'*64,transcript)
                with self.assertRaisesRegex(RuntimeError,'passive'): successor.record('held')
            finally:
                os.close(independent); received.close(); left.close(); right.close(); os.close(journal.fd)

    def test_receive_collects_all_rights_before_rejecting_truncation(self):
        # Actual SO_PASSCRED inserts credentials before installed SCM_RIGHTS.
        left,right = socket.socketpair(); right.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        fd = os.open(HERE,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        before = len(os.listdir('/proc/self/fd'))
        try:
            left.sendmsg([b'F'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
            with self.assertRaisesRegex(n.Refusal,'CLOSED_SERVING_RIGHTS_REQUIRED'):
                c.receive_rights(right,n,1)
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)
        finally: os.close(fd); left.close(); right.close()


class CompositionTests(unittest.TestCase):
    def test_existing_policy_digest_meanings_are_bound_before_network_preparation(self):
        import coordinated_restore as restore
        # Pure root-file composition; no seeded COMMIT/grant and no effect seam.
        source, fresh, shared_source, isolation_source, freezer = (b'coordinator',b'fresh',b'shared',b'isolation',b'freezer')
        from test_fresh_network import plan
        network = plan(); network['ordinaryOwner']={'version':1,'stopConfigSha256':n.digest(n.encode(n.stopped_config(network)))}
        network_raw = n.encode(network)
        shared = {'version':2,'machineId':network['machine'],'bootId':network['boot'],
                  'hostHold':{'networkPlanSha256':n.digest(network_raw),'freezerSha256':n.digest(freezer)}}
        config = {'version':2,'origin':{'machineId':network['machine'],'bootId':network['boot']},'nodes':{
            'shared':{'identity':{'planHash':restore.sha(restore.canonical(shared))},'files':{
                'shared':restore.sha(shared_source),'isolation':restore.sha(isolation_source),'freezer':restore.sha(freezer)}}}}
        policy = {'inventory':{'coordinatorSha256':restore.sha(restore.canonical(config)),
                  'sourceSha256':restore.sha(source),'networkPlanSha256':n.digest(network_raw)},
                  'files':{restore.SELF:restore.sha(source),restore.FRESH:restore.sha(fresh)}}
        root = {'version':2,'networkPlanSha256':n.digest(network_raw),'coordinatorSha256':restore.sha(source)}
        inputs={restore.SELF:source,restore.FRESH:fresh,restore.SHARED:shared_source,
                '/usr/local/libexec/c3-test-node-isolation':isolation_source,restore.FREEZER:freezer,
                '/etc/c3-test-node-isolation.json':restore.canonical(shared),'/etc/c3-test-fresh-network.json':network_raw}
        class Files:
            def read(self,path):return inputs[path],{}
            def read_json(self,path):return restore.decode(self.read(path)[0])
        with patch.object(restore,'shared_node',return_value='shared'):
            self.assertEqual(restore.network_composition(Files(),config,root,policy),shared)
            policy['inventory']['coordinatorSha256']=restore.sha(source)
            with self.assertRaisesRegex(restore.Refusal,'NETWORK_COMPOSITION_BINDING_REQUIRED'):
                restore.network_composition(Files(),config,root,policy)

class PolicyByteBindingTests(unittest.TestCase):
    def test_received_policy_bytes_not_network_reencoding_bind_the_same_commit(self):
        from types import SimpleNamespace
        import copy
        # Unit-only input fixtures; genuine COMMIT production is exercised by the
        # integration test. Stop at the next fixed-inode guard, never mint a grant.
        class FixedInputReached(Exception): pass
        with tempfile.TemporaryDirectory() as directory:
            policy = {'inventory': {'networkPlanSha256': 'a'*64}}
            raw_policy = json.dumps(policy,sort_keys=True,separators=(',',':')).encode()
            self.assertNotEqual(raw_policy,n.encode(policy))
            preparation = dict(networkPlanSha256='a'*64, generation='g', ownerInvocationId='i',
                               resourceSealSha256='b'*64, fdManifestSha256='c'*64)
            kernel = SimpleNamespace(accept_serving_live=lambda *args:None)
            owner = c.OwnerRuntime(n,SimpleNamespace(k=kernel,phase='prepared',live=lambda:None),None,
                                   SimpleNamespace(freezer=None),None)
            owner.preparation=preparation; owner.coordinator={'nonce':'n','pid':os.getpid()}
            serving={'pid':os.getpid(),'start':n.proc_start(os.getpid())}
            commit={'networkHandoff':owner.handoff_binding(),'nonce':'n',
                    'restoreIntent':{'origin':{'pid':os.getpid()}},'freshPolicySha256':n.digest(raw_policy)}
            for fault in (None,'policy-bytes','commit','handoff','nonce','origin','plan','attempt','serving'):
                with self.subTest(fault=fault):
                    value=copy.deepcopy(commit); raw=raw_policy
                    if fault=='handoff': value['networkHandoff']['generation']='other'
                    if fault=='nonce': value['nonce']='other'
                    if fault=='origin': value['restoreIntent']['origin']['pid']+=1
                    if fault=='policy-bytes': raw=n.encode(policy)  # same object, different exact bytes
                    if fault=='plan': raw=json.dumps({'inventory':{'networkPlanSha256':'f'*64}}).encode(); value['freshPolicySha256']=n.digest(raw)
                    commit_raw=n.encode(value); commit_sha=n.digest(commit_raw)
                    attempt={'commitSha256':commit_sha,'phase':'confirmed','serving':serving}
                    if fault=='attempt': attempt['phase']='pending'
                    if fault=='serving': attempt['serving']={**serving,'start':'0'}
                    request={'commitSha256':'0'*64 if fault=='commit' else commit_sha,'serving':serving,'manifest':[]}
                    fds=[]
                    try:
                        for index,data in enumerate((b'',b'',b'',b'',commit_raw,raw,n.encode(attempt))):
                            path=Path(directory)/str(index); path.write_bytes(data); path.chmod(0o600)
                            fds.append(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC))
                        real_stat=os.fstat
                        def root(fd):
                            s=real_stat(fd)
                            return SimpleNamespace(st_mode=s.st_mode,st_uid=0,st_gid=0)
                        with patch.object(c,'receive_rights',return_value=fds),patch.object(os,'fstat',root),\
                             patch.object(n,'trusted_fd',side_effect=FixedInputReached):
                            expected=self.assertRaises(FixedInputReached) if fault is None else self.assertRaisesRegex(
                                n.Refusal,'^SAME_COMMIT_SERVING_BINDING_REQUIRED$')
                            with expected: owner.accept_ordinary(None,request)
                    finally:
                        for fd in fds: os.close(fd)


class CustodyTests(unittest.TestCase):
    def test_full_dump_named_subtraction_and_dead_original_pidfd(self):
        self.assertTrue(hasattr(c, 'PID1Store'), 'product main has no PID1 custody implementation')
        with tempfile.TemporaryDirectory() as directory:
            journal = f.Journal(Path(directory)/'host')
            process = subprocess.Popen([sys.executable, '-c', 'pass'])
            dead = os.pidfd_open(process.pid); self.assertEqual(process.wait(), 0)
            rows = [f.capability(journal.fd, 'host.journal', 'journal'),
                    f.capability(dead, 'network.dead', 'pidfd')]
            class Store(c.PID1Store):
                def __init__(self):
                    self.m = n; self.generation = 'a'*32; self.table = []; self.notices = []
                def notify(self, payload, fds=()):
                    self.notices.append(payload)
                    fields = dict(line.split('=',1) for line in payload.splitlines())
                    if 'FDSTORE' in fields:
                        self.table.append(self.row(fields['FDNAME'], f.capability(fds[0], 'x', 'x')))
                    elif 'FDSTOREREMOVE' in fields:
                        self.table = [r for r in self.table if r[0] != fields['FDNAME']]
                def barrier(self): self.notices.append('barrier')
                def dump(self): return [list(row) for row in self.table]
            store = Store(); bindings = store.stage(rows, [journal.fd, dead])
            self.assertTrue(all('FDPOLL=0' in x for x in store.notices if 'FDSTORE=1' in x))
            self.assertTrue(select_readable(dead))
            store.remove([bindings[1]], bindings)
            self.assertEqual(len(store.dump()), 1)
            with self.assertRaises(n.Refusal): store.verify(bindings)
            store.remove([bindings[0]], bindings[:1]); self.assertEqual(store.dump(), [])
            os.close(dead); os.close(journal.fd)


def select_readable(fd):
    import select
    return bool(select.select([fd], [], [], 0)[0])


class KnownOldTests(unittest.TestCase):
    def test_actual_authenticated_host_restore_virgin_partial_and_unknown(self):
        import contextlib
        import multiprocessing
        import struct
        import time
        from types import SimpleNamespace
        import test_v2_abort_return as old
        m,s=old.m,old.shared
        from test_fresh_network import plan
        real_socket=socket.socket
        class RootSocket(real_socket):
            def getsockopt(self,level,opt,*args):
                value=super().getsockopt(level,opt,*args)
                if level==socket.SOL_SOCKET and opt==socket.SO_PEERCRED:
                    pid,_,_=struct.unpack('3i',value); return struct.pack('3i',pid,0,0)
                return value
        for partial,fault in ((False,None),(True,None),(False,'handoff-commit.json.next'),(False,'peer')):
            with self.subTest(partial=partial,fault=fault),tempfile.TemporaryDirectory() as directory:
                root=Path(directory); p=old.plan(True); network=plan()
                network.update(machine=p['machineId'],boot=p['bootId'],ordinaryOwner={'version':1})
                raw=n.encode(network); p['hostHold']['networkPlanSha256']=n.digest(raw)
                p['keepCgroups'].append('/system.slice/'+c.UNIT)
                files={m.INVENTORY:n.encode(old.inventory()),'/etc/c3-test-fresh-network.json':raw}
                for installed,local in (('/usr/local/libexec/c3-test-node-isolation','isolation.py'),
                    ('/usr/local/libexec/c3-test-shared-host.py','shared_host.py'),
                    ('/usr/local/libexec/c3-test-fresh-network.py','fresh_network.py'),
                    ('/usr/local/libexec/c3-test-fresh-network-control.py','fresh_network_control.py'),
                    ('/usr/local/libexec/c3-test-fresh-network-exec.py','fresh_network_exec.py')):
                    with os.fdopen(os.open(HERE/local,os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW),'rb') as h: files[installed]=h.read()
                    p['runtimePins'][installed]=n.digest(files[installed])
                files['/etc/systemd/system/'+c.UNIT]=b'modeled installed unit'
                p['unitFilePins']['/etc/systemd/system/'+c.UNIT]=n.digest(files['/etc/systemd/system/'+c.UNIT])
                lease_raw=n.encode({'planSha256':n.digest(raw),'generation':network['generation'],
                    'operations':['observe','cutover','return','abandon','handoff'],'deadline':network['deadline']})
                files['/etc/c3-test-fresh-network-lease.json']=lease_raw
                (root/'guard.json').write_text('{}'); (root/'masks').mkdir()
                (root/'plan.json').write_bytes(n.encode(p)); files[c.ISOLATION_PLAN]=n.encode(p)
                def read(path,*args,**kwargs):
                    if str(path) in files: return files[str(path)]
                    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW),'rb') as handle: return handle.read()
                class Kernel(old.fixture.FixtureKernelSurvivors):
                    def __init__(self): self.frozen=[]
                    def verify(self,expected,frozen,dead=False): assert frozen==self.frozen and not dead
                    def prepare_relaunch(self,expected,*args): expected['relaunch']=old.fixture.HostRecordTests().record()['expected']['relaunch']
                    def freeze(self,group,value): (self.frozen.append if value else self.frozen.remove)(group)
                    def split_proxies(self,*args): pass
                    def restore_proxies(self,*args): pass
                    def restore_relaunch(self,expected,*args): del expected['relaunch']
                class GuardHost(m.Host):
                    def operator_session(self): return {k:m.proc_identity(os.getppid())[k] for k in ('pid','start')}
                    def guard_check(self,*args): pass
                parent_pid=os.getpid(); start=m.proc_identity(parent_pid)['start']
                invocation='1'*32
                def systemctl(argv,**kwargs):
                    assert argv[:4]==['/usr/bin/systemctl','show','--all',c.UNIT]
                    fields={'Id':c.UNIT,'Names':c.UNIT,'MainPID':str(parent_pid),'ExecMainPID':str(parent_pid),
                        'InvocationID':invocation,'ControlGroup':'/system.slice/'+c.UNIT,'FragmentPath':'/etc/systemd/system/'+c.UNIT,
                        'DropInPaths':'','LoadState':'loaded','ActiveState':'active','SubState':'running','Job':''}
                    return SimpleNamespace(stdout='\n'.join(k+'='+v for k,v in fields.items()).encode())
                real_text=Path.read_text
                def text(path,*args,**kwargs):
                    if str(path)=='/proc/'+str(parent_pid)+'/cgroup': return '0::/system.slice/'+c.UNIT+'\n'
                    return real_text(path,*args,**kwargs)
                rfd,wfd=os.pipe()
                def child():
                    os.close(wfd)
                    real_lock_check=m.Engine.require_outer_lock
                    def lock_check(engine,fd):
                        with patch.object(m.os,'geteuid',return_value=0): return real_lock_check(engine,fd)
                    with patch.object(m,'secure_file',side_effect=read),patch.object(f,'capture',return_value=p['hostHold']['expected']),\
                         patch.object(socket,'socket',RootSocket),patch.object(subprocess,'run',side_effect=systemctl),\
                         patch.object(Path,'read_text',text),patch.object(m,'RUNNER_FENCES',str(root/'fences')),\
                         patch.object(m.Engine,'require_outer_lock',lock_check):
                        try: s.serve_hold(p,root,m,f,Kernel(),GuardHost(),rfd)
                        except BaseException as error:
                            (root/'refusal').write_text(str(error)); raise SystemExit(75)
                proc=multiprocessing.get_context('fork').Process(target=child); proc.start(); os.close(rfd)
                host=None
                try:
                    end=time.monotonic()+5
                    while not (root/'host-guard.json').exists() and proc.is_alive() and time.monotonic()<end: time.sleep(.01)
                    self.assertTrue((root/'host-guard.json').exists(),read(root/'refusal').decode() if (root/'refusal').exists() else 'owner not ready')
                    host=object.__new__(c.HostFenceChannel)
                    host.m=n; host.p=network; host.raw=raw; host.plan=p; host.plan_raw=n.encode(p)
                    host.lease=SimpleNamespace(check=lambda:None); host.identity=n.decode(read(root/'host-guard.json'))
                    host.pidfd=os.pidfd_open(proc.pid); host.socket_identity=n.identity(host.identity['socket'])
                    host.binding={'pid':parent_pid,'start':start,'invocation':invocation,
                                  'networkPlanSha256':n.digest(raw),'leaseSha256':n.digest(lease_raw)}
                    with patch.object(c,'HOST_STATE',str(root)),patch.object(n,'trusted_read',side_effect=read),\
                         patch.object(m,'secure_file',side_effect=read),patch.object(socket,'socket',RootSocket):
                        host.check()  # real pre-arm rendezvous and same original Fence
                        if partial:
                            node=old.Host(p); node.fail_checkpoint=True
                            with old.modeled_root(root),patch.object(m,'MASK_ROOT',str(root/'masks')),\
                                 patch.object(m,'RUNNER_FENCES',str(root/'fences')),patch.object(m.os,'geteuid',return_value=0):
                                engine=s.make_engine(root,p,m,node)
                                lock=os.open(root/'lock',os.O_CREAT|os.O_RDWR,0o600); fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                                engine._outer_lock_fd=lock
                                try: self.assertEqual(engine.apply({})['returnState'],'OLD')
                                finally: os.close(lock)
                            self.assertEqual(node.states,node.original)
                            self.assertTrue(proc.is_alive())  # waits for authenticated network consumer
                        if fault=='handoff-commit.json.next': (root/fault).write_text('{}')
                        if fault=='peer': host.binding={**host.binding,'invocation':'2'*32}
                        if fault:
                            with self.assertRaises(n.Refusal): host.request('restore-network-old')
                        else:
                            events=[]
                            class NetworkKernel(n.Linux):
                                def __init__(self):
                                    self.verification_mode='original-fence-held'; self.original_fence_check=host.check
                                def check(self):
                                    if self.verification_mode=='docker-live':
                                        assert n.decode(read(root/'host/hold.json'))['phase']=='restored'
                                        events.append('docker-live')  # daemon/kernel RPC facts modeled
                                def remove(self,baseline):
                                    assert self.verification_mode=='docker-live' and 'docker-live' in events
                                    events.append('resource-abandon')  # privileged network IO modeled
                            (root/'network').mkdir()
                            journal=n.Journal(root/'network'/network['generation'],network)
                            ctl=n.Controller(network,NetworkKernel(),journal); ctl.phase='prepared'; ctl.baseline={}
                            runtime=c.OwnerRuntime(n,ctl,host.lease,host,None)
                            left,right=socket.socketpair()
                            try:
                                request={'generation':network['generation'],'sequence':1,'operation':'abandon'}
                                result=runtime.abandon_temporary(request)
                                c.send(left,result,n)
                                self.assertEqual(c.receive(right,n),{'phase':'abandoned','operationalGO':False})
                                self.assertLess(events.index('docker-live'),events.index('resource-abandon'))
                            finally: left.close(); right.close(); journal.close()
                    proc.join(5); self.assertFalse(proc.is_alive()); self.assertEqual(proc.exitcode,75 if fault else 0)
                    record=n.decode(read(root/'host/hold.json'))
                    self.assertEqual(record['phase'],'unknown' if fault else 'restored')
                    self.assertEqual(record['frozen'],p['hostHold']['expected']['freezeOrder'] if fault else [])
                finally:
                    if host is not None: host.close()
                    os.close(wfd); proc.join(.3)
                    if proc.is_alive(): proc.terminate(); proc.join(5)
                    self.assertFalse(proc.is_alive())

    def test_known_old_then_docker_live_then_holder_abandon_and_no_retry(self):
        from types import SimpleNamespace
        from test_fresh_network import plan
        for fault in (None,'restore','docker'):
            with self.subTest(fault=fault):
                events=[]; p=plan()
                class Kernel(n.Linux):
                    def __init__(self):
                        self.verification_mode='original-fence-held'; self.original_fence_check=lambda:None
                    def check(self):
                        if self.verification_mode=='docker-live':
                            events.append('docker-live')
                            if fault=='docker': raise n.Refusal('Docker readback unknown')
                    def remove(self, baseline):
                        self.assert_old(); events.append('holder-abandon')
                    def assert_old(self):
                        assert self.verification_mode=='docker-live' and 'restore-OLD' in events
                class Host:
                    def request(self,op):
                        self.assert_op(op); events.append('restore-OLD')
                        if fault=='restore': raise n.Refusal('restoration unknown')
                        return {'returnState':'OLD','recordSha256':'a'*64}
                    def assert_op(self,op): assert op=='restore-network-old'
                class Journal:
                    def append(self,row): events.append(row['kind'])
                k=Kernel(); lease=SimpleNamespace(check=lambda:None)
                ctl=n.Controller(p,k,Journal()); ctl.phase='prepared'; ctl.baseline={}
                owner=c.OwnerRuntime(n,ctl,lease,Host(),None)
                request={'generation':p['generation'],'sequence':1,'operation':'abandon'}
                if fault:
                    with self.assertRaises(n.Refusal): owner.abandon_temporary(request)
                    before=list(events)
                    with self.assertRaises(n.Refusal): owner.abandon_temporary(request)
                    self.assertEqual(events,before)
                    self.assertNotIn('holder-abandon',events)
                else:
                    self.assertEqual(owner.abandon_temporary(request)['phase'],'abandoned')
                    self.assertLess(events.index('restore-OLD'),events.index('docker-live'))
                    self.assertLess(events.index('docker-live'),events.index('holder-abandon'))
                    with self.assertRaises(n.Refusal): owner.abandon_temporary(request)
                for attr,value in (('preparation',{}),('receipt',{}),('pending',{})):
                    other=c.OwnerRuntime(n,ctl,lease,Host(),None); setattr(other,attr,value)
                    with self.assertRaises(n.Refusal): other.abandon_temporary(request)


class RecoveryTests(unittest.TestCase):
    def test_inherited_rights_are_owned_before_first_grant_read(self):
        # A subprocess gives LISTEN_FDS its real 3..N range without borrowing
        # descriptors from the test runner. No manager/privileged operation.
        script = '''
import os, sys
sys.path.insert(0, sys.argv[1])
import fresh_network as n, fresh_network_control as c
fd = os.open('/dev/null', os.O_RDONLY)
if fd != 3:
    os.dup2(fd, 3); os.close(fd)
os.set_inheritable(3, True)
os.environ.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS='1', LISTEN_FDNAMES='untrusted')
def refused(path):
    assert not os.get_inheritable(3), 'grant read preceded inherited ownership'
    raise n.Refusal('grant unavailable')
n.trusted_read = refused
try:
    c.OwnerRuntime.recover(n, {'generation':'a'*32}, b'plan', object())
except n.Refusal as error:
    assert str(error) == 'grant unavailable', str(error)
else:
    raise AssertionError('grant unexpectedly accepted')
try: os.fstat(3)
except OSError: pass
else: raise AssertionError('unaccepted inherited FD leaked')
'''
        result = subprocess.run([sys.executable,'-c',script,str(HERE)],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_residual_restart_and_pending_pre_post_never_replay_resource_removal(self):
        # State/grant fixture models a previously accepted owner. This is recovery
        # coverage, NOT genuine producer-to-COMMIT acceptance (separate harness).
        from types import SimpleNamespace
        from test_fresh_network import plan
        for phase,dump_phase in (('network-removed-host-held','after'),
                                 ('network-cleanup-pending','before'),('network-cleanup-pending','after')):
            with self.subTest(phase=phase,dump=dump_phase), tempfile.TemporaryDirectory() as directory:
                p=plan(); raw=n.encode(p); root=Path(directory)/p['generation']
                network_journal=n.Journal(root,p); host_journal=f.Journal(Path(directory)/'host')
                class Kernel:
                    def verify(self,*args): pass  # modeled privileged frozen host
                    def check_live_capabilities(self): pass
                    def live_capabilities(self,*args): return []
                original=f.Fence({'groups':{},'freezeOrder':[]},Kernel(),host_journal,'original')
                original.phase='held'; original.record('held'); offer=original.stage_live('a'*64)
                extra=[os.open(directory,os.O_RDONLY|os.O_DIRECTORY) for _ in range(2)]
                rows=offer.rows+[f.capability(network_journal.fd,'network.journal','journal'),
                    f.capability(extra[0],'network.ns.fresh','journal'),f.capability(extra[1],'serving.pid','journal')]
                bindings=[{'name':'fixture.'+r['role'],'capability':r} for r in rows]
                after=bindings[:-2]; current=bindings if dump_phase=='before' else after
                inherited=object.__new__(c.InheritedRights); inherited.m=n
                inherited.owned=[os.dup(fd) for fd in ([host_journal.fd,network_journal.fd,*extra] if dump_phase=='before' else
                                                      [host_journal.fd,network_journal.fd])]
                inherited.names=[b['name'] for b in current]; received=list(inherited.owned)
                class Store(c.PID1Store):
                    def __init__(self): self.m=n; self.invocation='new'; self.current=current; self.removed=[]
                    def verify(self,bs): n.need(n.encode(bs)==n.encode(self.current),'FDSTORE_CUSTODY_UNKNOWN')
                    def remove(self,rs,bs):
                        self.verify(bs); self.removed.extend(rs)
                        self.current=[b for b in bs if b not in rs]; return self.current
                store=Store(); shared=n.encode({'hostHold':{'networkPlanSha256':n.digest(raw)}})
                fields=('version context machine boot generation networkPlanSha256 isolationPlanSha256 hostPlanHash ownerUnit '
                    'ownerInvocationId ownerPid ownerStart coordinator temporaryHolder holderSequence leaseSha256 originalDeadline '
                    'originalMonotonicEnd hostFence freshNetns resourceSealSha256 baselineSha256 fdManifestSha256 stopConfigSha256').split()
                receipt=dict.fromkeys(fields)
                receipt.update(version=1,generation=p['generation'],boot=p['boot'],networkPlanSha256=n.digest(raw),
                    isolationPlanSha256=n.digest(shared),hostFence={'freezerSha256':'c'*64,'liveOfferSha256':offer.sha256},
                    baselineSha256=n.digest(n.encode({})),ownerInvocationId='original')
                preparation=n.digest(n.encode(receipt))
                commit_raw=n.encode({'networkHandoff':{'preparationSha256':preparation}})
                commit_sha=n.digest(commit_raw)
                transcript=original.surrender_live(offer.sha256,commit_sha)
                receipt.update(authorityPhase='ordinary-owned',commitSha256=commit_sha,
                    hostFenceHandoffTranscriptSha256=transcript,acceptedFdStoreManifestSha256=n.digest(n.encode(bindings)))
                state={'version':1,'phase':phase,'bindings':bindings if phase.endswith('pending') else current,'acceptedBindings':bindings,
                    'pendingCleanup':{'before':bindings,'after':after,'remove':bindings[-2:]} if phase.endswith('pending') else None,
                    'receiptSha256':n.digest(n.encode(receipt)),'hostOffer':{'state':offer.state,'manifest':offer.rows},
                    'network':{'pids':{},'peerPins':{},'pathIdentity':None,'pathState':'absent','sealed':None,
                    'firewallSeal':None,'nodeTableSeal':None,'nodeForwardSeal':[],'owned':[],'loopbackLinks':[],
                    'runtimeSettings':None,'serving':None,'servingRows':[]},'counter':network_journal.counter,
                    'sequence':0,'baseline':{},'originalMonotonicEnd':0,'originalInvocationId':'original'}
                c.publish(n,network_journal,'ordinary-owned.json',receipt)
                c.publish(n,network_journal,'ordinary-state.json',state)
                def real_read(path):
                    # Scratch ancestry is user-owned; root UID/path authority is
                    # explicitly modeled, while leaf IO is actual noatime/nofollow.
                    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NOATIME),'rb') as handle:
                        return handle.read()
                def read(path):
                    if path==c.ISOLATION_PLAN: return shared
                    if path==n.INPUT: return raw
                    if path==c.HOST_STATE+'/handoff-commit.json': return commit_raw
                    return real_read(path)
                real_decode=n.decode
                freezer=SimpleNamespace(LiveFenceOffer=f.LiveFenceOffer,Fence=f.Fence,LinuxKernel=Kernel,SystemdRelaunchBarrier=lambda:None)
                result=None
                try:
                    with patch.object(n,'STATE',directory),patch.object(n,'trusted_read',side_effect=read),\
                         patch.object(c,'fixed_module',return_value=freezer),\
                         patch.object(n.Linux,'remove',side_effect=AssertionError('resource replay')),\
                         patch.object(n.Linux,'inspect',side_effect=AssertionError('Docker restart dependency')):
                        result=c.OwnerRuntime.recover(n,p,raw,store,inherited)
                        self.assertEqual(result.c.phase,'network-removed-host-held')
                        if dump_phase=='before':
                            for fd in received[-2:]:
                                with self.assertRaises(OSError): os.fstat(fd)
                        self.assertEqual(result.bindings,after)
                        self.assertEqual(result.stop()['status'],'NETWORK_REMOVED_HOST_HOLDS_RETAINED')
                        self.assertEqual(store.removed,bindings[-2:] if dump_phase=='before' else [])
                        saved=real_decode(real_read(str(root/'ordinary-state.json')))
                        self.assertEqual(saved['phase'],'network-removed-host-held')
                        self.assertIsNone(saved['pendingCleanup'])
                        result.c.live()  # original deadline=0, no temporary authority
                finally:
                    inherited.close()
                    if result is not None:
                        result.c.k.close(); result.c.j.close(); result.offer.close()
                    for fd in extra: os.close(fd)
                    os.close(host_journal.fd); network_journal.close()

    def test_pending_subtraction_accepts_only_exact_pre_or_post_dump(self):
        rows = [{'name':'host','capability':{'role':'host.journal'}},
                {'name':'fresh','capability':{'role':'network.ns.fresh'}},
                {'name':'serving','capability':{'role':'serving.pid'}}]
        pending = {'before':rows,'after':rows[:1],'remove':rows[1:]}
        class Store:
            def __init__(self, current): self.current=current; self.removed=[]
            def verify(self, expected): n.need(self.current==expected,'FDSTORE_CUSTODY_UNKNOWN')
            def remove(self, remove, bindings):
                self.verify(bindings); self.removed.extend(remove)
                self.current=[b for b in bindings if b not in remove]; return self.current
        for current in (rows,rows[:1]):
            store=Store(current)
            actual=c.reconcile_cleanup(n,store,pending)
            self.assertEqual(actual,current)
            self.assertEqual(store.removed,[])  # classification is read-only
        for current in (rows[:2],[],rows+[{'name':'foreign'}]):
            with self.assertRaises(n.Refusal): c.reconcile_cleanup(n,Store(current),pending)
        changed={**pending,'after':rows[:2]}
        with self.assertRaises(n.Refusal): c.reconcile_cleanup(n,Store(rows),changed)


class StopRuntimeTests(unittest.TestCase):
    def test_empty_and_exact_503_precede_cleanup_and_pending_checkpoint_precedes_subtraction(self):
        from types import SimpleNamespace
        from test_fresh_network import plan
        for fault in (None,'live','tasks','status','body','remove','subtract'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                events=[]; p=plan(); raw=n.encode(p); root=Path(directory)/p['generation']; journal=n.Journal(root,p)
                process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)' if fault=='live' else 'pass'])
                pidfd=os.pidfd_open(process.pid)
                if fault!='live': self.assertEqual(process.wait(timeout=3),0)
                group=Path(directory)/'cgroup'; group.mkdir(); (group/'cgroup.procs').write_bytes(b'123\n' if fault=='tasks' else b'')
                serving=[pidfd,os.open(directory,os.O_RDONLY|os.O_DIRECTORY),os.open('/dev/null',os.O_RDONLY),
                    os.open(group,os.O_RDONLY|os.O_DIRECTORY),*[os.open('/dev/null',os.O_RDONLY) for _ in range(3)]]
                fresh=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
                class Kernel(n.Linux):
                    def __init__(self):
                        self.serving_live={'fds':serving,'serving':{},'rows':[],'empty':False}
                        self.fds={'fresh':fresh}; self.pidfds={}; self.peer_exes={}; self.target_hold=None; self.netns_fd=fresh
                        self.p=p; self.pids={}; self.peer_pins={}; self.path_identity=None; self.path_state='mounted'
                        self.sealed={}; self.firewall_seal={}; self.owned={}; self.loopback_links=set(); self.current=p['newConfig']
                    def check(self): events.append('check')  # modeled kernel/cgroup authority
                    def require_empty_namespace(self): events.append('EMPTY')
                    def config(self,value=None):
                        if value is not None: self.current=value; events.append('stopped-config')
                        return self.current
                    def remove(self,baseline,ordinary=False):
                        assert ordinary and self.serving_live['empty'] and self.current==n.stopped_config(p)
                        assert '503' in events
                        events.append('resource-cleanup')
                        if fault=='remove': raise n.Refusal('resource outcome unknown')
                        self.sealed=None; self.firewall_seal=None; self.path_state='absent'
                k=Kernel(); ctl=n.Controller(p,k,journal,guard=lambda:(_ for _ in ()).throw(AssertionError('temporary authority')))
                ctl.phase='ordinary-owned'; ctl.baseline={}; ctl.end=0
                owner=c.OwnerRuntime(n,ctl,None,None,None); owner.offer=SimpleNamespace(state={},rows=[])
                owner.receipt={'authorityPhase':'ordinary-owned','commitSha256':'b'*64}
                owner.preparation={'ownerInvocationId':'original'}; owner.fence=SimpleNamespace(check=lambda:None)
                bindings=[{'name':'host','capability':{'role':'host.journal'}},
                    {'name':'fresh','capability':{'role':'network.ns.fresh'}},
                    *[{'name':'s'+str(i),'capability':{'role':'serving.'+str(i)}} for i in range(7)]]
                owner.bindings=bindings; owner.accepted_bindings=bindings
                class Store:
                    def verify(self,rows): pass  # modeled PID1 custody
                    def remove(self,rows,current):
                        saved=n.decode((root/'ordinary-state.json').read_bytes())
                        assert saved['phase']=='network-cleanup-pending'
                        assert saved['pendingCleanup']=={'before':bindings,'after':bindings[:1],'remove':bindings[1:]}
                        assert saved['network']['serving'] is None
                        events.append('named-subtraction')
                        if fault=='subtract': raise n.Refusal('FDSTORE uncertain')
                        return bindings[:1]
                owner.store=Store()
                class HTTPS:
                    def __init__(self,*args,**kwargs): pass
                    def request(self,*args): pass
                    def getresponse(self):
                        return SimpleNamespace(status=200 if fault=='status' else 503,
                            read=lambda limit:b'wrong' if fault=='body' else b'c3-classic-stopped-v1\n')
                    def close(self): events.append('503' if fault not in ('status','body') else 'bad-503')
                try:
                    with patch.object(n,'trusted_read',return_value=raw),patch.object(n.http.client,'HTTPSConnection',HTTPS):
                        ctl.ordinary_authority=c.OrdinaryAuthority(n,ctl,owner.fence,owner.store,bindings,owner.receipt)
                        if fault in ('tasks','status','body','remove','subtract'):
                            with self.assertRaises(n.Refusal): owner.stop()
                            before=list(events)
                            with self.assertRaises(n.Refusal): owner.stop()
                            self.assertEqual(events,before)
                        else:
                            result=owner.stop()
                            self.assertEqual(result['status'],'PARKED_SERVING_HOST_HOLDS_RETAINED' if fault=='live' else
                                             'NETWORK_REMOVED_HOST_HOLDS_RETAINED')
                    if fault in ('live','tasks','status','body'): self.assertNotIn('resource-cleanup',events)
                    if fault is None:
                        self.assertLess(events.index('EMPTY'),events.index('503'))
                        self.assertLess(events.index('503'),events.index('resource-cleanup'))
                        self.assertLess(events.index('resource-cleanup'),events.index('named-subtraction'))
                        saved=n.decode((root/'ordinary-state.json').read_bytes())
                        self.assertEqual(saved['phase'],'network-removed-host-held')
                        self.assertEqual(saved['bindings'],bindings[:1]); self.assertEqual(saved['acceptedBindings'],bindings)
                        self.assertIsNone(saved['pendingCleanup'])
                finally:
                    k.close(); journal.close()
                    if process.poll() is None: process.terminate()
                    process.wait(timeout=3)


class StopConfigTests(unittest.TestCase):
    def test_stop_is_unique_handler_replacement_preserving_types_and_routes(self):
        p = {'newConfig': {'apps': {'routes': [{'handle': [{'handler': 'reverse_proxy',
             'upstreams': [{'dial': n.PUBLIC+':3000'}]}], 'terminal': False}]}, 'zero': 0}}
        expected = {'apps': {'routes': [{'handle': [{'handler': 'static_response', 'status_code': 503,
                    'body': 'c3-classic-stopped-v1\n'}], 'terminal': False}]}, 'zero': 0}
        self.assertEqual(n.encode(n.stopped_config(p)), n.encode(expected))
        self.assertEqual(p['newConfig']['zero'], 0)
        p['newConfig']['apps']['routes'][0]['handle'][0]['upstreams'].append({'dial':'foreign:3000'})
        with self.assertRaises(n.Refusal): n.stopped_config(p)

if __name__ == '__main__': unittest.main()
