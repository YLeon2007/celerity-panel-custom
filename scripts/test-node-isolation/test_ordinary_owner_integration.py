"""Genuine ordinary-owner tracer bullet (not physical/PID1 acceptance).

Only privileged identity, cgroup/netns/network and PID1 facts are modeled. The
producer/Coordinator/receiver/bridge implementations, COMMIT, journals, flocks,
UDS, SCM_RIGHTS, pidfds, Popen, serving HTTP and natural exits are real. No COMMIT
or ordinary grant is inserted by this fixture; failures remain failing tests.

Run native plumbing control separately from the ordinary positive:
  python3 -B -m unittest test_ordinary_owner_integration.NativeControl -v
  python3 -B -m unittest test_ordinary_owner_integration.OrdinaryPositive -v
Set C3_ORDINARY_EVIDENCE to a fresh owned directory to retain receipts.
"""
import contextlib
import copy
import fcntl
import hashlib
import importlib.util
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
import threading
import time
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import coordinated_restore as restore
import fresh_classic_launch as fresh
import fresh_network as network
import fresh_network_control as control
import fresh_network_invocation as creator
import isolation
import shared_host as shared
import test_coordinated_restore as ct
import test_node_originals as originals
import test_prepared_resume as prepared
import test_shared_host as host_fixture
from test_fresh_classic_launch import inventory_fixture
from test_fresh_network import plan as network_plan
# The established host fixture registers its actual isolation module for the
# node fixtures. Use that same module instance for the modeled input builder.
isolation = sys.modules['isolation']

spec = importlib.util.spec_from_file_location('ordinary_integration_freezer', HERE.parent/'panel-host-freezer.py')
freezer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(freezer)


def read_noatime(path):
    fd = os.open(path, os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        chunks = []
        while chunk := os.read(fd, 1024*1024): chunks.append(chunk)
        return b''.join(chunks)
    finally:
        os.close(fd)


def source_map():
    return {restore.SELF: HERE/'coordinated_restore.py', restore.FRESH: HERE/'fresh_classic_launch.py',
            restore.SHARED: HERE/'shared_host.py', restore.FREEZER: HERE.parent/'panel-host-freezer.py',
            '/usr/local/libexec/c3-test-node-isolation': HERE/'isolation.py',
            '/usr/local/libexec/c3-test-fresh-network.py': HERE/'fresh_network.py',
            '/usr/local/libexec/c3-test-fresh-network-control.py': HERE/'fresh_network_control.py',
            '/usr/local/libexec/c3-test-fresh-network-exec.py': HERE/'fresh_network_exec.py',
            '/usr/local/libexec/c3-test-fresh-network-client.py': HERE/'fresh_network_client.py',
            '/usr/local/libexec/c3-test-fresh-network-client-exec.py': HERE/'fresh_network_client_exec.py'}


class Ledger:
    def __init__(self, name):
        self.name = name
        parent = os.environ.get('C3_ORDINARY_EVIDENCE')
        self.path = Path(parent)/name if parent else None
        if self.path: self.path.mkdir(parents=True, exist_ok=False)
        self.rows = []
        paths=set(source_map().values())|{Path(__file__).resolve(),REPO/'tests/ordinaryOwnerRuntime.integration.test.js',
            HERE/'owner_restoration_channel.py'}
        for module in tuple(sys.modules.values()):
            file=getattr(module,'__file__',None)
            if isinstance(file,str) and Path(file).resolve().parent==HERE:
                paths.add(Path(file).resolve())
        self.sources = {str(p.relative_to(REPO)): hashlib.sha256(read_noatime(p)).hexdigest()
                        for p in sorted(paths)}
    def record(self, stage, **values):
        row = {'stage': stage, **values}; self.rows.append(row)
        if self.path:
            with (self.path/'events.jsonl').open('a') as out:
                out.write(json.dumps(row, sort_keys=True)+'\n'); out.flush(); os.fsync(out.fileno())
    def finish(self, error=None):
        self.record('result', status='RED' if error else 'PASS',
                    error=None if error is None else str(error),
                    exception=None if error is None else type(error).__name__,
                    traceback=None if error is None else ''.join(traceback.format_exception(error)))
        if self.path:
            (self.path/'source-sha256.json').write_text(json.dumps(self.sources, indent=2)+'\n')
        for name, sha in self.sources.items():
            assert hashlib.sha256(read_noatime(REPO/name)).hexdigest() == sha, name


class ModeledKernel(host_fixture.FixtureKernelSurvivors):
    """Modeled freezer/cgroup/PID1 observations, actual product Fence lifecycle."""
    def __init__(self): self.frozen = []; self._live = []
    def verify(self, expected, frozen, dead=False):
        assert not dead
        assert frozen == self.frozen
    def prepare_relaunch(self, expected, owner, persist):
        expected['relaunch'] = {'owner': owner, 'dropins': [
            {'path':'/run/systemd/system/'+unit+'.d/90-c3-test-host-isolation.conf','createdDirectory':True}
            for unit in ('docker.service','containerd.service')]}
    def freeze(self, group, value):
        assert value is True; self.frozen.append(group)
    def split_proxies(self, *args): pass
    def survivor_descendants(self, group, init): return {init['pid']: init}
    def live_capabilities(self, expected):
        if self._live is None: self._live = []
        return self._live
    def check_live_capabilities(self):
        for row, fd in self._live or []:
            assert freezer.capability(fd,row['role'],row['kind'],**row['binding']) == row


class ModeledStore(control.PID1Store):
    """PID1 duplication/full Dump modeled; actual FD ownership and store logic."""
    def __init__(self, generation):
        self.m = network; self.generation = generation; self.invocation = 'e'*32
        self.table = {}
    def notify(self, payload, fds=()):
        fields = dict(line.split('=',1) for line in payload.splitlines())
        name = fields['FDNAME']
        if 'FDSTORE' in fields:
            assert fields['FDPOLL'] == '0' and name not in self.table
            self.table[name] = os.dup(fds[0])
        else:
            assert fields['FDSTOREREMOVE'] == '1'
            os.close(self.table.pop(name))
    def barrier(self): pass  # explicitly modeled manager completion
    def dump(self):
        return [self.row(name, freezer.capability(fd,'unused','unused')) for name,fd in self.table.items()]
    def close(self):
        for name in list(self.table): os.close(self.table.pop(name))


class ModeledNetwork(network.Linux):
    """Network effects are modeled; serving descriptor checks stay real below."""
    def __init__(self, p, root, port):
        self.p=p; self.root=root; self.port=port; self.current=copy.deepcopy(p['oldConfig'])
        self.fds={'host':os.open('/proc/self/ns/net',os.O_RDONLY|os.O_CLOEXEC)}
        self.pidfds={}; self.peer_exes={}; self.pids={}; self.peer_pins={}
        self.path_identity=None; self.path_state='absent'; self.sealed=None; self.firewall_seal=None
        self.node_table_seal=None; self.node_forward_seal=[]; self.owned={}; self.loopback_links=set()
        self.runtime_settings=None
        self.serving_live: dict | None=None
        self.target_hold=None; self.original_fence_check=None
    def check(self):
        if self.original_fence_check: self.original_fence_check()
        self.check_serving_live()
    def preflight(self): return {'modeledNetworkBaseline':True}
    def create_namespace(self):
        self.netns_fd=os.open('/proc/self/ns/net',os.O_RDONLY|os.O_CLOEXEC)
        self.fds['fresh']=self.netns_fd; self.path_state='mounted'
        self.path_identity=network.identity('/proc/self/ns/net')
    def firewall(self): self.firewall_seal={'modeledDefaultDrop':True}
    def connect(self, role): self.owned[('fresh',role)]={'modeled':True}
    def seal(self): self.sealed={'modeledPrivateNetwork':True}
    def observation(self):
        # Topology/snapshots are privileged models, in the actual protocol shape.
        return {'namespace':network.identity('/proc/self/ns/net'),
                'snapshots':{role:{key:[] for key in ('links','addresses','routes','rules')}
                             for role in ('host','fresh','caddy','mongo','redis')},
                'configSha256':network.digest(network.encode(self.current))}
    def check_serving_live(self):
        live=self.serving_live
        if live is None: return
        for fd,row in zip(live['fds'],live['rows']):
            assert freezer.capability(fd,row['role'],row['kind'],**row['binding']) == row
        pid=live['serving']['pid']
        assert not select.select([live['fds'][0]],[],[],0)[0]
        assert network.proc_start(pid) == live['serving']['start']
        for index,path in ((1,'ns/net'),(2,'exe')):
            a=os.stat('/proc/'+str(pid)+'/'+path); b=os.fstat(live['fds'][index])
            assert (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)
        # UID/cgroup placement and private ns topology, NOT PID identity, modeled.
    def direct_probe(self):
        assert self.serving_live is not None
        return hashlib.sha256(fresh.bound_http_probe(self.serving_live['serving']['pid'],'127.0.0.1',self.port)).hexdigest()
    def public_probe(self): return self.direct_probe()  # explicitly modeled Caddy/TLS path
    def caddy_probe(self): return self.direct_probe()
    def config(self, value=None):
        if value is not None: self.current=copy.deepcopy(value)
        return copy.deepcopy(self.current)
    def close(self):
        owned=[*self.fds.values(),*(self.serving_live['fds'] if self.serving_live else [])]
        self.fds={}; self.serving_live=None
        for fd in owned: os.close(fd)


@contextlib.contextmanager
def prepared_v2(ordinary, expected_failure=False):
    """Reuse supported prepared fixture; alter only independently modeled inputs."""
    original_factory=ct.cfixture
    original_validate=isolation.validate_inventory
    original_dual=originals.DualFixture
    configuration={}
    p=network_plan()
    if expected_failure: p['deadline']=int(time.time())+30
    p['ordinaryOwner']={'version':1,'stopConfigSha256':network.digest(network.encode(network.stopped_config(p)))}
    raw=network.encode(p)
    sources={name:read_noatime(path) for name,path in source_map().items()}
    def accepted_inventory(value):
        shared_id=value['sharedNodeId']
        pin=next(x for x in value['nodes'] if x['nodeId']==shared_id)
        # This is the independent modeled machine acceptance, before the actual
        # inventory validator, original capture, restoration and owner settlement.
        pin['physical']['machineId']=p['machine']; pin['physical']['bootId']=p['boot']
        original_validate(value)
        plan=host_fixture.plan()
        plan.update(version=2,inventorySha256=restore.sha(restore.canonical(value)),
                    nodeId=shared_id,endpointIp=pin['endpoint']['ip'],**pin['physical'],
                    maintenanceId='12345678-1234-4234-8234-123456789abc')
        plan['hostHold']['expected']['host']={k:plan[k] for k in ('machineId','bootId')}
        plan['hostHold'].update(freezerSha256=restore.sha(sources[restore.FREEZER]),networkPlanSha256=network.digest(raw))
        plan['keepCgroups'].append('/system.slice/'+control.UNIT)
        plan['runtimePins']={**plan['runtimePins'],**{name:restore.sha(sources[name]) for name in isolation.NETWORK_RUNTIME_PINS}}
        plan['unitFilePins']['/etc/systemd/system/'+control.UNIT]=restore.sha(read_noatime(HERE/'c3-test-fresh-network.service'))
        configuration.update(plan=plan,inventory=value,shared_id=shared_id)
        return value
    class PhysicalPlan(dict):
        def update(self, *args, **kwargs):
            values=dict(*args,**kwargs)
            if values.get('nodeId') == configuration['shared_id']:
                values.update(machineId=p['machine'],bootId=p['boot'])
            super().update(values)
    class AcceptedDual(original_dual):
        def __enter__(self):
            result=super().__enter__()
            self.plan=PhysicalPlan(self.plan); self.engine.plan=self.plan
            self.engine.plan_hash=restore.sha(restore.canonical(configuration['plan']))
            return result
        def put(self,path,raw):
            if path in (restore.SHARED,restore.FREEZER): raw=sources[path]
            return super().put(path,raw)
    @contextlib.contextmanager
    def factory(c, **kwargs):
        with original_factory(c,**kwargs,v2=True) as outer:
            with patch.object(restore,'trusted_read',lambda path:outer.fs.read(path)[0]):
                if ordinary:
                    for name,data in sources.items():
                        if name not in (restore.SELF,restore.FRESH) and outer.fs.absent(name):
                            outer.fs.atomic(name,data,new=True)
                    outer.fs.atomic(control.ISOLATION_PLAN,restore.canonical(configuration['plan']),new=True)
                    outer.fs.atomic(network.INPUT,raw,new=True)
                    root={'version':2,'coordinatorSha256':restore.sha(sources[restore.SELF]),'networkPlanSha256':network.digest(raw)}
                    outer.fs.atomic('/etc/celerity/topology-test-fresh-owner-settlement.json',restore.canonical(root),new=True)
                yield outer
    def inventory(m,config):
        value=inventory_fixture(m,config)
        if ordinary: value['networkPlanSha256']=network.digest(raw)
        return value
    original_mkdir=Path.mkdir
    def prepared_directory(path,mode=0o777,parents=False,exist_ok=False):
        # Existing v1 prepared fixture creates this ancestor without exist_ok;
        # accepted v2 isolation/source delivery has already constructed it.
        if str(path).endswith('/usr/local/libexec') and path.is_dir(): exist_ok=True
        return original_mkdir(path,mode=mode,parents=parents,exist_ok=exist_ok)
    with patch.object(isolation,'validate_inventory',accepted_inventory), \
         patch.object(originals,'DualFixture',AcceptedDual), \
         patch.object(ct,'cfixture',factory), \
         patch.object(Path,'mkdir',prepared_directory), \
         patch('test_fresh_classic_launch.inventory_fixture',inventory):
        manager=prepared.prepared_fixture(fault='expected-refusal' if expected_failure else None)
        fixture=manager.__enter__()
        fixture.network_plan=p; fixture.shared_plan=configuration['plan']
        try:
            yield fixture
        except BaseException as primary:
            try: manager.__exit__(type(primary),primary,primary.__traceback__)
            except BaseException as cleanup:
                if cleanup is not primary:
                    primary.add_note('prepared-fixture disposal also failed: '+str(cleanup))
            raise
        else:
            manager.__exit__(None,None,None)


BRIDGE = '''import os,sys
from pathlib import Path
import coordinated_restore as c
import owner_restoration_channel as bridge
import test_node_originals as t
root=Path(sys.argv[1]); fs=t.n.Files(t.n.Fixture(root,os.getuid(),os.getgid(),None))
c.trusted_read=lambda path:fs.read(path)[0]
channel=c.RestorationChannel(fs,fixture_socket=sys.argv[2])
try:
 channel.__enter__(); bridge.serve_fresh(channel,lifetime=70)
finally: channel.close()
'''


def js_input(fixture, path, ordinary, ledger, holder_fault=None):
    nodes=[]
    for node,pin in fixture.held.config['nodes'].items():
        accepted=fixture.fixtures[list(fixture.held.config['nodes']).index(node)].accepted
        profile=pin['identity']['targetProfile']; original=accepted['profiles'][profile]
        nodes.append({'nodeId':node,'targetProfile':profile,'endpoint':next(x['endpoint'] for x in fixture.outer.inventory['nodes'] if x['nodeId']==node),
                      'physical':{k:pin['identity'][k] for k in ('machineId','bootId','sshHostKeySha256')},
                      'maintenanceId':pin['identity']['maintenanceId'],
                      'originalSnapshot':{'configSha256':original['files']['config']['sha256'],
                          'unitSha256':original['files']['unit']['sha256'],'serviceActive':original['service']['ActiveState'],
                          'serviceEnabled':original['service']['UnitFileState']}})
    value={'ordinary':ordinary,'expectUnknown':bool(holder_fault),'nodes':nodes,'inventory':fixture.outer.inventory,
           'inventorySha256':fixture.held.config['inventorySha256'],'root':str(fixture.outer.root),
           'socket':str(path),'python':sys.executable,'bridgeSource':BRIDGE,'cwd':str(HERE),
           'evidenceDirectory':str(Path(os.environ['C3_ORDINARY_EVIDENCE'])/ledger.name)
                               if os.environ.get('C3_ORDINARY_EVIDENCE') else None,
           'bridgeSources':{str(HERE/name):hashlib.sha256(read_noatime(HERE/name)).hexdigest()
                            for name in ('coordinated_restore.py','owner_restoration_channel.py')},
           'networkPlanSha256':network.digest(network.encode(fixture.network_plan)) if ordinary else None}
    target=fixture.outer.root/'consumer.json'; target.write_text(json.dumps(value))
    return target


def holder_process(root, fault=None):
    """Real checked client loader + run/Holder, only installed-root/host facts modeled."""
    import fresh_network_client_exec as entry
    root=Path(root); real_open=os.open; real_stat=os.stat; real_lstat=os.lstat; real_fstat=os.fstat
    real_text=Path.read_text; real_bytes=Path.read_bytes
    p=network.decode(read_noatime(root/network.INPUT.lstrip('/')))
    server=os.getppid()
    def mapped(path):
        text=os.fspath(path)
        if text=='/': return str(root)
        if text.startswith(('/etc/','/usr/local/')): return str(root/text.lstrip('/'))
        return path
    def opened(path,flags,*args,**kwargs):
        return real_open(mapped(path) if kwargs.get('dir_fd') is None else path,flags,*args,**kwargs)
    def root_stat(value):
        class AcceptedRoot:
            def __getattr__(self,key):
                return 0 if key in ('st_uid','st_gid') else getattr(value,key)
        return AcceptedRoot()
    def trusted_fd(path,directory=False):
        return real_open(mapped(path),os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW|os.O_CLOEXEC|
                         (os.O_DIRECTORY if directory else 0))
    def trusted_read(path):
        fd=trusted_fd(path)
        try: return os.read(fd,network.LIMIT+1)
        finally: os.close(fd)
    def text(path,*args,**kwargs):
        name=str(path)
        if name=='/etc/machine-id': return p['machine']+'\n'
        if name=='/proc/sys/kernel/random/boot_id': return p['boot']+'\n'
        value=real_text(path,*args,**kwargs)
        if name.startswith('/proc/') and name.endswith('/status'):
            value='\n'.join('Uid:\t0\t0\t0\t0' if line.startswith('Uid:') else
                            'Gid:\t0\t0\t0\t0' if line.startswith('Gid:') else line
                            for line in value.splitlines())+'\n'
        return value
    def cmdline(path,*args,**kwargs):
        if str(path)=='/proc/'+str(server)+'/cmdline':
            return b'/usr/bin/python3\0-I\0-B\0/usr/local/libexec/c3-test-fresh-network-exec.py\0'
        return real_bytes(path,*args,**kwargs)
    def peer(channel):
        pid,uid,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        assert pid==server and (uid,gid)==(os.getuid(),os.getgid())
        return pid,0,0
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(os,'open',opened))
        stack.enter_context(patch.object(os,'fstat',lambda fd:root_stat(real_fstat(fd))))
        stack.enter_context(patch.object(os,'stat',lambda path,*a,**kw:root_stat(real_stat(mapped(path) if kw.get('dir_fd') is None else path,*a,**kw))))
        stack.enter_context(patch.object(os,'lstat',lambda path,*a,**kw:root_stat(real_lstat(mapped(path) if kw.get('dir_fd') is None else path,*a,**kw))))
        stack.enter_context(patch.object(os,'getresuid',lambda:(0,0,0)))
        stack.enter_context(patch.object(os,'getresgid',lambda:(0,0,0)))
        stack.enter_context(patch.object(Path,'read_text',text))
        stack.enter_context(patch.object(Path,'read_bytes',cmdline))
        # The actual checked loader hashes the installed copies; no loader shim
        # or substituted run/Holder/receive/dispatch/close implementation.
        m=entry.load('/usr/local/libexec/c3-test-fresh-network.py')
        c=entry.load('/usr/local/libexec/c3-test-fresh-network-control.py')
        client=entry.load('/usr/local/libexec/c3-test-fresh-network-client.py')
        # Local fixture models root ptrace capability, never kernel exit status.
        stack.enter_context(patch.object(c,'holder_exit_access',lambda *args:None,create=True))
        original_identity=m.identity
        def identity(path):
            if str(path) in {f'/proc/{pid}/ns/net' for pid in ('self','1',str(server))}: return p['hostNetns']
            if str(path) in ('/proc/1/ns/pid','/proc/1/ns/mnt','/proc/1/ns/user'):
                return original_identity('/proc/self/ns/'+str(path).rsplit('/',1)[1])
            if str(path)=='/usr/bin/python3': return original_identity('/proc/'+str(server)+'/exe')
            return original_identity(path)
        stack.enter_context(patch.object(m,'identity',identity))
        stack.enter_context(patch.object(m,'trusted_fd',trusted_fd))
        stack.enter_context(patch.object(m,'trusted_read',trusted_read))
        stack.enter_context(patch.object(m,'SOCKET',str(root/'h.sock')))
        stack.enter_context(patch.object(client,'_peercred',peer))
        sent=[]
        real_send=c.send; real_close=socket.socket.close; real_fcntl=fcntl.fcntl
        def sent_frame(channel,value,m):
            result=real_send(channel,value,m)
            if value.get('op')=='holder-disposed': sent.append(channel)
            return result
        def closed(channel):
            required=channel in sent and channel.fileno()!=-1
            real_close(channel)
            if fault=='channel-close' and required:
                os.write(2,b'required channel close failed after actual close\n')
                raise OSError('required channel close failed after actual close')
        def flags(fd,op,*args):
            result=real_fcntl(fd,op,*args)
            if fault=='pipe-restore' and sent and fd==0 and op==fcntl.F_SETFL:
                os.write(2,b'required operator pipe flags restore failed after actual restore\n')
                raise OSError('required operator pipe flags restore failed after actual restore')
            return result
        stack.enter_context(patch.object(c,'send',sent_frame))
        stack.enter_context(patch.object(socket.socket,'close',closed))
        stack.enter_context(patch.object(fcntl,'fcntl',flags))
        before=set(os.listdir('/proc/self/fd'))
        try: client.run(m,c)  # genuine operator pipes, input pins, handoff and disposal
        except OSError:
            if fault and sent: raise SystemExit(75)
            raise
        assert set(os.listdir('/proc/self/fd'))==before,'actual holder leaked descriptors'
        os.write(2,json.dumps({'actualClientRunReturned':True,'ownedDescriptorsDisposed':True,
                              'clientSha256':client.__source_sha256__,'loaderPins':entry.PINS}).encode()+b'\n')


def read_holder_line(child):
    end=time.monotonic()+5; raw=bytearray()
    while not raw.endswith(b'\n'):
        assert select.select([child.stdout],[],[],max(0,end-time.monotonic()))[0], 'actual holder output timeout'
        block=os.read(child.stdout.fileno(),1)
        if not block:
            raise AssertionError('actual holder premature EOF: '+child.stderr.read().decode())
        raw.extend(block)
    return json.loads(raw)


@contextlib.contextmanager
def receiver(f, ledger, holder_fault=None):
    """Actual receiver and original Fence with real producer child and rights."""
    root=f.outer.root; hostroot=root/control.HOST_STATE.lstrip('/')
    # Coordinator owns this directory already; original host shares it, no copy.
    plan=f.shared_plan; p=f.network_plan
    unit='/etc/systemd/system/'+control.UNIT
    target=root/unit.lstrip('/')
    target.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    for parent in target.parents:
        if parent == root.parent: break
        parent.chmod(0o700)
    f.fs.atomic(unit,read_noatime(HERE/'c3-test-fresh-network.service'),new=True)
    fdread,fdwrite=os.pipe()
    host_errors=root/'producer-error.json'
    producer_pid=os.fork()
    if producer_pid == 0:
        os.close(fdwrite)
        class Host:
            def operator_session(self): return {'pid':os.getppid(),'start':network.proc_start(os.getppid())}
            def guard_check(self,*args): pass  # external recovery hold modeled
        original_peer=shared.peer_identity
        def root_peer(conn):
            pid,uid,gid=original_peer(conn); return pid,0,0
        k=ModeledKernel()
        def fixed_read(path):
            name=str(path)
            return read_noatime(root/name.lstrip('/')) if name.startswith(('/etc/','/usr/local/','/var/lib/')) else read_noatime(path)
        def show(args,**kwargs):
            if args[:3] != ['/usr/bin/systemctl','show','--all']: raise AssertionError(args)
            peer=json.loads((root/'receiver-peer.json').read_text())
            row={'Id':control.UNIT,'Names':control.UNIT,'MainPID':str(peer['pid']),'ExecMainPID':str(peer['pid']),
                 'InvocationID':'e'*32,'ControlGroup':'/system.slice/'+control.UNIT,'FragmentPath':'/etc/systemd/system/'+control.UNIT,
                 'DropInPaths':'','LoadState':'loaded','ActiveState':'active','SubState':'running','Job':'0'}
            return SimpleNamespace(stdout=''.join(k+'='+v+'\n' for k,v in row.items()).encode())
        original_text=Path.read_text
        def proc_text(path,*args,**kwargs):
            if str(path)=='/proc/'+str(os.getppid())+'/cgroup': return '0::/system.slice/'+control.UNIT+'\n'
            return original_text(path,*args,**kwargs)
        try:
            isolation.atomic_json(hostroot,'guard.json',{'modeled':'independent-recovery'})
            with patch.object(isolation,'secure_file',fixed_read),patch.object(shared,'peer_identity',root_peer), \
                 patch.object(freezer,'capture',return_value=copy.deepcopy(plan['hostHold']['expected'])), \
                 patch.object(subprocess,'run',show),patch.object(Path,'read_text',proc_text):
                shared.serve_hold(plan,str(hostroot),isolation,freezer,k,Host(),fdread)
            os._exit(0)
        except BaseException as error:
            try: host_errors.write_text(json.dumps({'error':str(error),'traceback':traceback.format_exc()}))
            finally: os._exit(73)
    os.close(fdread)
    producer_fd=os.pidfd_open(producer_pid)
    holder_path=root/'h.sock'; holder_server=socket.socket(socket.AF_UNIX)
    holder_server.bind(str(holder_path)); holder_path.chmod(0o600); holder_server.listen(1); holder_server.settimeout(5)
    original_popen=subprocess.Popen
    def fixed_holder(argv,**kwargs):
        assert tuple(argv)==creator.HOLDER_ARGV
        return original_popen([sys.executable,'-I','-B',str(Path(__file__).resolve()),'--holder',str(root),
                               *([holder_fault] if holder_fault else [])],cwd=HERE,**kwargs)
    with patch.object(subprocess,'Popen',fixed_holder), \
         patch.object(network,'trusted_read',return_value=network.encode(p)):
        invocation=creator.Invocation(network)
    holder=invocation.holder
    assert holder is not None
    holder_channel=None
    (root/'receiver-peer.json').write_text(json.dumps({'pid':os.getpid()}))
    store=ModeledStore(p['generation']); journal=network.Journal(root/'network-generation',p)
    kernel=ModeledNetwork(p,root,f.port)
    host=None; owner=None; terminal=None; thread=None; errors=[]; stop=threading.Event()
    real_socket=socket.socket; real_text=Path.read_text
    real_open=os.open; real_fstat=os.fstat; real_stat=os.stat; real_lstat=os.lstat
    original_fs_uid,original_fs_gid=f.fs.uid,f.fs.gid
    # Fixed installed paths, root UID and trusted-root ancestor permissions are
    # modeled. Actual owned fixture inodes, timestamps and descriptors stay real.
    def mapped(path):
        text=os.fspath(path)
        if text=='/run/c3-test-fresh-network-owner.sock': return str(root/'n.sock')
        if text=='/run/netns/c3-test-fresh-classic': return '/proc/self/ns/net'
        if text=='/sys/fs/cgroup/system.slice/c3-test-fresh-classic.service': return str(root/'modeled-serving-cgroup')
        if text=='/': return str(root)
        if text.startswith(('/etc/','/usr/local/','/var/lib/c3-test-node-isolation/')): return str(root/text.lstrip('/'))
        return path
    (root/'modeled-serving-cgroup').mkdir()
    def open_root(path,flags,*args,**kwargs): return real_open(mapped(path) if kwargs.get('dir_fd') is None else path,flags,*args,**kwargs)
    def root_metadata(value, ancestor=False):
        class RootStat:
            _original=value
            def __getattr__(self,key):
                if key in ('st_uid','st_gid'): return 0
                if key == 'st_mode' and ancestor: return value.st_mode & ~0o022
                return getattr(value,key)
            def __eq__(self,other): return value == getattr(other,'_original',other)
        return RootStat()
    def stat_root(path,*args,**kwargs):
        target=mapped(path) if kwargs.get('dir_fd') is None else path
        if str(target)=='/proc/1/ns/user': target='/proc/self/ns/user'  # privileged host-userns observation modeled
        value=real_stat(target,*args,**kwargs)
        return root_metadata(value,Path(target) in root.parents) if str(target).startswith(str(root)) or Path(target) in root.parents else value
    def lstat_root(path,*args,**kwargs):
        target=mapped(path) if kwargs.get('dir_fd') is None else path
        value=real_lstat(target,*args,**kwargs)
        return root_metadata(value,Path(target) in root.parents) if str(target).startswith(str(root)) or Path(target) in root.parents else value
    def root_fstat(fd):
        value=real_fstat(fd)
        try: name=os.readlink('/proc/self/fd/'+str(fd))
        except OSError: return value
        if name.startswith(str(root)):
            # Preserve nanosecond fields; os.stat_result(list) drops them.
            return root_metadata(value)
        return value
    class RootSocket(real_socket):
        def connect(self,path):
            return super().connect(mapped(path) if isinstance(path,(str,bytes)) else path)
        def getsockopt(self,level,opt,*args):
            result=super().getsockopt(level,opt,*args)
            if (level,opt)==(socket.SOL_SOCKET,socket.SO_PEERCRED):
                names=(self.getsockname(),self.getpeername())
                if any(str(name) in (str(root/'n.sock'),str(root/'h.sock'),str(hostroot/'host.sock')) for name in names):
                    pid,uid,gid=struct.unpack('3i',result); return struct.pack('3i',pid,0,0)
            return result
    def text_root(path,*args,**kwargs):
        if str(path)=='/proc/'+str(holder.pid)+'/status':
            return real_text(path,*args,**kwargs).replace('Uid:\t1000\t1000\t1000\t1000','Uid:\t0\t0\t0\t0')
        return real_text(path,*args,**kwargs)
    def trusted_fd(path,directory=False):
        return real_open(mapped(path),os.O_RDONLY|os.O_NOATIME|os.O_CLOEXEC|
                         (os.O_DIRECTORY if directory else os.O_NOFOLLOW))
    def trusted_read(path):
        fd=trusted_fd(path)
        try: return os.read(fd,8*1024*1024+1)
        finally: os.close(fd)
    real_run=subprocess.run
    def manager(args,**kwargs):
        if args[:3]==['/usr/bin/systemctl','show','--all']:
            return SimpleNamespace(stdout=('MainPID='+str(os.getpid())+'\nExecMainPID='+str(os.getpid())+'\nControlGroup=/system.slice/'+control.UNIT+'\nActiveState=active\nSubState=running\nDropInPaths=\nInvocationID='+'e'*32+'\n').encode())
        return real_run(args,**kwargs)
    try:
        observation=read_holder_line(holder)
        assert observation['holder']=={'pid':holder.pid,'start':network.proc_start(holder.pid)}
        ledger.record('actual-holder-observation',value=observation)
        lease_raw=network.encode({'version':1,'context':network.CONTEXT,'generation':p['generation'],'boot':p['boot'],
            'planSha256':network.digest(network.encode(p)),'holder':observation['holder'],
            'deadline':p['deadline'],'operations':['observe','cutover','return','abandon','handoff']})
        f.fs.atomic(network.LEASE,lease_raw,new=True)
        deadline=time.monotonic()+5
        while not (hostroot/'host-guard.json').exists():
            if host_errors.exists(): raise AssertionError(host_errors.read_text())
            assert time.monotonic()<deadline,'original producer readiness timeout'
            time.sleep(.005)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(network,'trusted_read',trusted_read))
            stack.enter_context(patch.object(network,'trusted_fd',trusted_fd))
            stack.enter_context(patch.object(network,'NETNS','/proc/self/ns/net'))
            stack.enter_context(patch.object(control,'HOST_STATE',str(hostroot)))
            stack.enter_context(patch.object(control,'holder_exit_access',lambda *args:None,create=True))
            stack.enter_context(patch.object(os,'open',open_root))
            f.fs.uid=f.fs.gid=0
            stack.callback(setattr,f.fs,'uid',original_fs_uid)
            stack.callback(setattr,f.fs,'gid',original_fs_gid)
            stack.enter_context(patch.object(os,'stat',stat_root))
            stack.enter_context(patch.object(os,'lstat',lstat_root))
            stack.enter_context(patch.object(os,'fstat',root_fstat))
            stack.enter_context(patch.object(os,'geteuid',lambda:0))
            stack.enter_context(patch.object(socket,'socket',RootSocket))
            stack.enter_context(patch.object(Path,'read_text',text_root))
            stack.enter_context(patch.object(subprocess,'run',manager))
            lease=control.Lease(network,p,network.encode(p))
            # Original constructor and fixed loaders are exercised, not replaced.
            host=control.HostFenceChannel(network,p,network.encode(p),lease,store.invocation)
            # Only the loaded kernel seam is modeled; original Fence/offer methods
            # and loaded shared verification remain unchanged.
            stack.enter_context(patch.object(host.freezer,'LinuxKernel',ModeledKernel))
            stack.enter_context(patch.object(host.freezer,'SystemdRelaunchBarrier',lambda:None))
            initial_kernel=host.freezer.LinuxKernel
            class AcceptedKernel(initial_kernel):
                def verify(self,expected,frozen,dead=False): self.frozen=list(frozen); super().verify(expected,frozen,dead)
            stack.enter_context(patch.object(host.freezer,'LinuxKernel',AcceptedKernel))
            controller=network.Controller(p,kernel,journal,guard=lease.check)
            initial=controller.prepare(); host.check()
            holder_channel=holder_server.accept()[0]; holder_server.close()
            lease.peer(holder_channel)
            control.send(holder_channel,initial,network)
            prepared_reply=read_holder_line(holder)
            assert prepared_reply==initial
            ledger.record('actual-holder-prepared',value=prepared_reply)
            invocation.begin_handoff()
            # Close the candidate through the actual original host protocol.
            identity=host.identity
            with RootSocket(socket.AF_UNIX) as conn:
                conn.connect(identity['socket'])
                conn.sendall(network.encode({'command':'close-candidate','nonce':'f'*64,'owner':identity['owner'],'planHash':identity['planHash']})+b'\n')
                assert conn.recv(8192)
            controller.guard=control.TemporaryAuthority(lease,host).check
            owner=control.OwnerRuntime(network,controller,lease,host,store)
            owner.park_holder(control.receive(holder_channel,network))
            ledger.record('original-producer-prepared',pid=producer_pid,holderPid=holder.pid)
            terminal=real_socket(socket.AF_UNIX); terminal.bind(str(root/'n.sock')); terminal.listen(1); terminal.settimeout(.2)
            def exit_witness():
                raw=os.pread(lease.exit_stat_fd,8193,0)
                fields=control.holder_stat(network,raw,lease.holder)
                ledger.record('original-holder-kernel-exit',holder=lease.holder,state=fields[0].decode(),
                              waitStatus=int(fields[49]),pidfdReadable=bool(select.select([lease.pidfd],[],[],0)[0]),
                              statSha256=network.digest(raw),privilegedPtraceAccess='modeled',
                              originalCreator=os.getpid(),holderParent=int(fields[1]),
                              creatorHasNotReaped=holder.returncode is None)
                assert int(fields[1])==os.getpid() and holder.returncode is None
            def serve():
                conn=None; request=None
                try:
                    while not stop.is_set():
                        try: conn,_=terminal.accept(); break
                        except socket.timeout: continue
                    if conn is None: return
                    with conn:
                        conn.settimeout(4)
                        while not stop.is_set():
                            request=control.receive(conn,network); op=request['op']
                            owner.peer(conn,request.get('coordinator'))
                            if op=='prepare-ordinary': result=owner.prepare_ordinary(request['coordinator'])
                            elif op=='accept-ordinary': result=owner.accept_ordinary(conn,request)
                            elif op=='read-ordinary': result=owner.read_ordinary()
                            elif op=='finish-temporary-scope':
                                result=owner.finish_temporary_scope(holder_channel)
                                exit_witness()
                            else: raise AssertionError(op)
                            ledger.record(op,result=result)
                            if op=='accept-ordinary':
                                assert owner.c.k.serving_live is not None and owner.fence is not None
                                commit_raw,policy_raw,attempt_raw=[os.pread(fd,8*1024*1024+1,0)
                                    for fd in owner.c.k.serving_live['fds'][4:7]]
                                commit=network.decode(commit_raw)
                                assert commit['freshPolicySha256']==network.digest(policy_raw)
                                ledger.record('accepted-same-commit',commit=commit,grant=owner.receipt,
                                    commitSha256=network.digest(commit_raw),policyRawSha256=network.digest(policy_raw),
                                    networkEncodedPolicySha256=network.digest(network.encode(network.decode(policy_raw))),
                                    attempt=network.decode(attempt_raw),receiverFencePhase=owner.fence.phase)
                            control.send(conn,result,network)
                            if op=='read-ordinary' and owner.finished: return
                except BaseException as error:
                    errors.append(error)
                    if request and request.get('op')=='finish-temporary-scope': exit_witness()
                    try:
                        live=owner.c.k.serving_live
                        if live is not None:
                            raw_inputs=[os.pread(fd,8*1024*1024+1,0) for fd in live['fds'][4:7]]
                            actual=[network.decode(raw) for raw in raw_inputs]
                            ledger.record('same-commit-inputs',commit=actual[0],policy=actual[1],attempt=actual[2],
                                          coordinator=owner.coordinator,preparation=owner.preparation,request=request,
                                          receivedCommitSha256=network.digest(raw_inputs[0]),
                                          receivedPolicySha256=network.digest(raw_inputs[1]),
                                          receiverEncodedPolicySha256=network.digest(network.encode(actual[1])),
                                          handoffBindingMatches=actual[0]['networkHandoff']==owner.handoff_binding())
                    except BaseException as observation:
                        error.add_note('input observation also failed: '+str(observation))
                    ledger.record('receiver-error',error=str(error),traceback=traceback.format_exc())
            thread=threading.Thread(target=serve,daemon=True); thread.start()
            yield owner,errors,producer_fd,invocation
            if holder_fault:
                assert len(errors)==1 and str(errors[0])=='ORIGINAL_HOLDER_EXIT_STATUS_UNKNOWN',errors
                assert not owner.finished and owner.finish_attempted
                # An uncertain finish cannot send/replay disposal or replace the
                # original committed grant, Fence/OFD, custody or serving task.
                with unittest.TestCase().assertRaisesRegex(network.Refusal,'FINITE_TERMINAL_COMPLETION_REQUIRED'):
                    owner.finish_temporary_scope(holder_channel)
                owner.fence.check()
                expected=[owner.store.row(b['name'],b['capability']) for b in owner.bindings]
                actual=owner.store.dump()
                # FreshLaunch records committed-activation-unknown by replacing
                # ATTEMPT. The held original inode remains, its proc link gains
                # '(deleted)'; the strict product Dump verifier must NOT waive it.
                for row in actual:
                    before=next(r for r in expected if r[0]==row[0])
                    if before[7].endswith('/fresh-launch-attempt.json'):
                        assert row==[*before[:7],before[7]+' (deleted)',*before[8:]],(row,before)
                    else: assert row==before,(row,before)
                assert len(actual)==len(expected)
                with unittest.TestCase().assertRaisesRegex(network.Refusal,'FDSTORE_CUSTODY_UNKNOWN'):
                    owner.store.verify(owner.bindings)
                live=owner.c.k.serving_live
                assert not select.select([live['fds'][0]],[],[],0)[0]
                assert network.proc_start(live['serving']['pid'])==live['serving']['start']
                assert network.digest(network.encode(owner.receipt))==f.held.network_receipt['networkOwnershipSha256']
                ledger.record('terminal-unknown-retained',originalFenceHeld=True,originalCustodyDescriptorsRetained=True,
                              strictDumpReadback='FDSTORE_CUSTODY_UNKNOWN',servingAlive=True,finished=owner.finished)
            else:
                if errors: raise errors[0]
                assert owner.finished, 'original temporary scope did not finish'
            # The actual creator, not this fixture, owns the retention/reap
            # boundary. Unknown settlement waits for the ORIGINAL 30s test plan.
            invocation.close()
            holder_out=bytes(invocation.buffers['holderStdout'])
            holder_err=bytes(invocation.buffers['holderStderr'])
            assert holder.returncode==(75 if holder_fault else 0),holder_err.decode()
            handed_off=json.loads(holder_out)
            assert owner.pending is not None
            assert handed_off=={**owner.pending,**f.held.network_receipt}
            disposal={'requiredCleanupFault':holder_fault,'stderr':holder_err.decode()} if holder_fault else json.loads(holder_err)
            if not holder_fault: assert disposal['actualClientRunReturned'] and disposal['ownedDescriptorsDisposed']
            ledger.record('actual-holder-natural-exit',exit=holder.returncode,reply=handed_off,disposal=disposal)
            with unittest.TestCase().assertRaises(ChildProcessError): os.waitpid(holder.pid,os.WNOHANG)
            ledger.record('original-creator-reaped',pid=holder.pid,exit=holder.returncode,
                          afterPublicSettlement=True,retentionSource='fresh_network_invocation.Invocation',
                          uncertainDeadlineBarrier=bool(holder_fault))
            waited,status=os.waitpid(producer_pid,0); assert waited==producer_pid and status==0
            producer_pid=None
            ledger.record('natural-temporary-disposal',host=True,holder=True,holderExit=holder.returncode)
            if holder_fault:
                assert f.supervisor.wait(timeout=3)==1
                ledger.record('prepared-supervisor-unknown-natural-exit',exit=f.supervisor.returncode)
                return
            # Do not reset/renew deadlines: checks must no longer consult either
            # dead original peer, lease or Docker. Actual pidfds are readable.
            controller.end=time.monotonic()-1
            assert select.select([producer_fd,lease.pidfd],[],[],0)[0]==[producer_fd,lease.pidfd]
            # Model elapsed wall time too, without editing the fixed plan bytes.
            # Any accidental temporary-authority consultation must fail loudly.
            with patch.object(time,'time',return_value=p['deadline']+1), \
                 patch.object(lease,'check',side_effect=AssertionError('expired holder consulted')), \
                 patch.object(host,'check',side_effect=AssertionError('disposed producer consulted')):
                assert owner.read_ordinary()==f.held.network_receipt
            ledger.record('expired-temporary-authority-independent-readback',monotonicExpired=True,wallExpired=True)
    finally:
        stop.set()
        if terminal: terminal.close()
        if thread: thread.join(5)
        if host: host.close()
        if owner and owner.coordinator_pidfd is not None: os.close(owner.coordinator_pidfd)
        if owner and owner.offer: owner.offer.close()
        if 'lease' in locals(): lease.close()
        if holder_channel: holder_channel.close()
        holder_server.close()
        invocation.close()
        holder_out=bytes(invocation.buffers['holderStdout'])
        holder_err=bytes(invocation.buffers['holderStderr'])
        if holder.returncode:
            ledger.record('actual-holder-failure',exit=holder.returncode,stdout=holder_out.decode(),stderr=holder_err.decode())
        os.close(fdwrite)
        if producer_pid is not None:
            if not select.select([producer_fd],[],[],2)[0]: signal.pidfd_send_signal(producer_fd,signal.SIGTERM)
            os.waitpid(producer_pid,0)
        os.close(producer_fd)
        store.close(); kernel.close(); journal.close()
        if host_errors.exists(): ledger.record('producer-error',value=json.loads(host_errors.read_text()))


class NativeControl(unittest.TestCase):
    def test_real_supported_native_coordinator_bridge_public_consumer(self):
        self.run_path(False)
    def run_path(self, ordinary, holder_fault=None):
        ledger=Ledger('ordinary-'+holder_fault if holder_fault else 'ordinary' if ordinary else 'native')
        error=None
        try:
            with prepared_v2(ordinary,expected_failure=bool(holder_fault)) as f:
                path=f.outer.root/'o.sock'; listener=socket.socket(socket.AF_UNIX)
                self.addCleanup(listener.close)
                listener.bind(str(path)); listener.listen(1)
                data=js_input(f,path,ordinary,ledger,holder_fault)
                environment={**os.environ,'NODE_PATH':os.environ.get('NODE_PATH','/home/leon/c3-anyorder-integration-20261104/node_modules')}
                peers=contextlib.nullcontext() if not ordinary else receiver(f,ledger,holder_fault)
                with peers as receiving:
                    if ordinary:
                        invocation=receiving[3]
                        original_wait=invocation.holder.wait
                        def observed_reap(*args,**kwargs):
                            self.assertIsNotNone(invocation.settlement.returncode)
                            if holder_fault:
                                self.assertGreaterEqual(time.monotonic(),invocation.end)
                            else:
                                self.assertTrue(receiving[0].finished)
                                self.assertEqual(invocation.settlement.returncode,0)
                                public=json.loads(read_noatime(Path(os.environ['C3_ORDINARY_EVIDENCE'])/ledger.name/'node-runtime.json')) if os.environ.get('C3_ORDINARY_EVIDENCE') else None
                                if public: self.assertEqual(public['bridgeExit'],{'code':0,'signal':None})
                            ledger.record('creator-reap-start',holderPid=invocation.holder.pid,
                                          publicOperationExit=invocation.settlement.returncode,
                                          ownerFinished=receiving[0].finished,
                                          originalDeadlineExpired=time.monotonic()>=invocation.end)
                            return original_wait(*args,**kwargs)
                        invocation.holder.wait=observed_reap
                        original_popen=subprocess.Popen
                        def fixed_settlement(argv,**kwargs):
                            assert tuple(argv)==creator.SETTLEMENT_ARGV
                            kwargs['env']=environment
                            return original_popen(['node',str(REPO/'tests/ordinaryOwnerRuntime.integration.test.js'),str(data)],
                                                  cwd=REPO,**kwargs)
                        with patch.object(subprocess,'Popen',fixed_settlement): invocation.start_settlement()
                        child=invocation.settlement
                    else:
                        child=subprocess.Popen(['node',str(REPO/'tests/ordinaryOwnerRuntime.integration.test.js'),str(data)],
                            cwd=REPO,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    try:
                        if holder_fault:
                            with self.assertRaises(Exception) as failure:
                                f.held.serve_fresh_owner(listener,platform=f.platform,socket_path=f.socket)
                            self.assertEqual(failure.exception.code,'COMMITTED_ACTIVATION_UNKNOWN')
                            self.assertIsNone(f.held.fresh_reply)  # no public success ACK queued
                        else:
                            f.held.serve_fresh_owner(listener,platform=f.platform,socket_path=f.socket)
                        listener.close()
                        f.held.complete_fresh_owner()
                        if ordinary:
                            if holder_fault:
                                with self.assertRaisesRegex(network.Refusal,'PUBLIC_SETTLEMENT_UNKNOWN_RETAINED'):
                                    invocation.finish_settlement()
                            else: invocation.finish_settlement()
                            out=bytes(invocation.buffers['settlementStdout']); err=bytes(invocation.buffers['settlementStderr'])
                        else: out,err=child.communicate(timeout=8)
                        ledger.record('public-consumer',exit=child.returncode,stdout=out.decode(),stderr=err.decode())
                        self.assertEqual(child.returncode,75 if holder_fault else 0,err.decode())
                        result=json.loads(out)
                        commit=f.fs.read(restore.COMMIT)[0]
                        self.assertEqual(result['commitSha256'],hashlib.sha256(commit).hexdigest())
                        self.assertEqual(f.count(),1)
                        self.assertTrue(f.held.handoff_completed)
                        self.assertEqual(result['code'],'COMMITTED_ACTIVATION_UNKNOWN' if holder_fault else
                                         'COMMITTED_FRESH_NETWORK_OWNED' if ordinary else 'COMMITTED_FRESH_ACTIVATION_CONFIRMED')
                        self.assertEqual('networkHandoff' in json.loads(commit),ordinary)
                        if ordinary:
                            owner,failures,hostfd,invocation=receiving
                            if holder_fault:
                                self.assertEqual([str(e) for e in failures],['ORIGINAL_HOLDER_EXIT_STATUS_UNKNOWN'])
                                self.assertFalse(owner.finished)
                            else:
                                self.assertEqual(failures,[])
                                self.assertEqual(result['networkOwnershipSha256'],network.digest(network.encode(owner.receipt)))
                                self.assertTrue(owner.finished)
                            self.assertTrue(select.select([hostfd],[],[],0)[0])
                            if not holder_fault: self.assertEqual(invocation.holder.returncode,0)
                        ledger.record('same-original-commit',sha256=hashlib.sha256(commit).hexdigest(),executions=f.count())
                    except BaseException as primary:
                        if ordinary:
                            assert receiving is not None
                            if receiving[1]:
                                failure=receiving[1][0]
                                ledger.record('genuine-producer-blocker',error=str(failure))
                                raise failure from primary
                        raise
                    finally:
                        listener.close()
                        if holder_fault and getattr(f.held,'network',None) is not None:
                            f.held.network.close(); f.held.network=None  # fixture transport disposal, never grant release
                        if ordinary:
                            invocation.close()
                            out=bytes(invocation.buffers['settlementStdout']); err=bytes(invocation.buffers['settlementStderr'])
                        else:
                            if child.poll() is None: child.kill()
                            out,err=child.communicate(timeout=5)
                        if child.returncode: ledger.record('consumer-failure',exit=child.returncode,stdout=out.decode(),stderr=err.decode())
        except BaseException as caught:
            error=caught; raise
        finally: ledger.finish(error)


class OrdinaryPositive(NativeControl):
    # Do not inherit/reexecute the native control as a separate acceptance count.
    test_real_supported_native_coordinator_bridge_public_consumer = None
    def test_genuine_producer_same_commit_receiver_disposal_public_positive(self):
        self.run_path(True)


class OrdinaryDisposalFailure(NativeControl):
    test_real_supported_native_coordinator_bridge_public_consumer = None
    def test_actual_client_channel_close_failure_has_no_public_success_ack(self):
        self.run_path(True,'channel-close')
    def test_actual_client_pipe_restore_failure_has_no_public_success_ack(self):
        self.run_path(True,'pipe-restore')


if __name__ == '__main__':
    if len(sys.argv) in (3,4) and sys.argv[1]=='--holder': holder_process(sys.argv[2],sys.argv[3] if len(sys.argv)==4 else None)
    else: unittest.main()
