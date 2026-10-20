"""Disposable source fixture ONLY. UID/SSH/kernel/systemd/guards SIMULATED.

Actual NodeOriginals capture, fsync, files, flock, child pipes and UDS are real.
Never installed/imported by the operational entry point.
"""
from contextlib import ExitStack
import base64
import copy
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import coordinated_capture as a
import coordinated_restore as c
import test_node_originals as t
import isolation as isolation
import physical_attestor as observer

HERE = Path(__file__).resolve().parent


class CaptureFixture:
    def __init__(self, *, large=False):
        self.large = large

    def __enter__(self):
        self.stack = ExitStack()
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='cap-')))
        self.children,self.fixtures = [],[]
        self.fs = t.n.Files(t.n.Fixture(self.root,os.getuid(),os.getgid(),None))
        self.origin = {'machineId':'f'*32,'bootId':'ffffffff-ffff-ffff-ffff-ffffffffffff','uid':0,'cgroup':'0::/SIMULATED-root-operator',
                       'pid':os.getpid(),'start':c.proc_start(os.getpid())}
        self.config = {'version':1,'context':'test.infograd.online','lifetimeSeconds':120,
                       'origin':{k:v for k,v in self.origin.items() if k not in ('pid','start')},'keySha256':'f'*64,
                       'protocolSha256':a.sha((HERE/'coordinated_restore.py').read_bytes()),'nodes':{},'ownerChallenge':{}}
        physical = {'version':1,'executionContext':{'target':'test','hostIdentity':'test.infograd.online'},'nodes':[],
                    'host':{'owner':'11111111-1111-4111-8111-111111111111','guard':{'pid':201,'start':'321','socket':'/var/lib/c3-test-node-isolation/host.sock',
                       'owner':'11111111-1111-4111-8111-111111111111','planHash':'c'*64,'session':{'pid':202,'start':'322'}},
                       'backend':{'instanceId':'a'*64,'pid':333,'processStartTime':'42'}}}
        for index,(node,(endpoint,profile)) in enumerate(a.NODES.items()):
            f = self.stack.enter_context(t.DualFixture() if endpoint == '104.143.201.72' else t.Fixture())
            f.node,f.profile = node,profile
            f.plan.update(nodeId=node,endpointIp=endpoint,targetProfile=profile,machineId='7fa266f995fe4aa69e96cf7d01359e34' if node == a.SHARED_NODE else str(index+1)*32,
                          maintenanceId=f'11111111-1111-4111-8111-{index+1:012d}')
            key = struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+bytes([index+1])*32
            f.plan['sshHostKeySha256'] = a.sha(key)
            f.guard = {'pid':100+index,'start':'123','socket':'/var/lib/c3-test-node-isolation/recovery.sock'}
            if profile == 'xray-main':
                f.config,f.unit = t.n.profile_paths(profile)
                f.put(f.config,f.original); f.put(f.unit,b'[Service]\n# original main fixture\n')
                state = copy.deepcopy(f.system.states['xray-bridge.service'])
                state.update(Id='xray.service',FragmentPath=f.unit)
                f.system.states['xray.service'] = state
            profiles = ['xray-main','xray-bridge'] if endpoint == '104.143.201.72' else [profile]
            if self.large:
                f.original = a.canonical({'inbounds':[],'padding':'x'*20000})
                for p in profiles: f.put(t.n.profile_paths(p)[0],f.original)
            # Actual Engine + journal; only physical/UID/SSH/kernel/systemd facts are simulated.
            f.plan.update(isolateUnits=[],hostHold={'owner':physical['host']['owner']})
            f.engine = isolation.Engine(f.path(t.n.STATE),f.plan,f.engine.host,validator=lambda p:p)
            f.accepted.update(t.n.identity(f.engine))
            f.put('/fixture-plan.json',a.canonical(f.plan))
            f.put(t.n.STATE+'/journal.json',a.canonical({'version':1,'phase':'held','plan':f.plan,'planHash':f.engine.plan_hash,
                'guard':f.guard,'saved':{},'initialProcesses':[],'dispatchInFlight':None,'dispatchCount':0,
                'accessBoundary':{'session':{'pid':78,'start':'999'},'ticks':'100'}}))
            # Installation is actually read; root UID/GID are simulated by the read adapter.
            f.put(observer.RUNNER,(HERE.parents[1]/'src/modules/relay-l2tp/node-artifacts/topology/runner.sh').read_bytes())
            f.path(observer.RUNNER).chmod(0o750)
            for p in profiles:
                f.path(t.n.profile_paths(p)[0]).parent.chmod(0o755)
                f.path(t.n.runner_lock(p)).unlink(missing_ok=True)
            f.put(a.ATTESTOR,(HERE/'physical_attestor.py').read_bytes())
            f.accepted['profiles'] = {p:{'files':{k:f.fs.info(path) for k,path in zip(('config','unit'),t.n.profile_paths(p))},
                    'service':f.system.unit(t.n.service_name(p)),'runtimeSha256':a.sha(a.canonical({'mode':'none','inbounds':{}}))} for p in profiles}
            f.put(t.n.ACCEPTED,a.canonical(f.accepted))
            f.writer = t.n.NodeOriginals(f.engine,f.module,fixture=f.fixture)
            f.put(a.SELF,(HERE/'coordinated_capture.py').read_bytes()); f.put(a.ORIGINALS,(HERE/'node_originals.py').read_bytes())
            pin = {'identity':t.n.identity(f.engine),'profiles':profiles,'guard':f.guard,'hostKey':base64.b64encode(key).decode(),
                   'files':{name:a.sha(f.fs.read(path)[0]) for name,path in {'self':a.SELF,'originals':a.ORIGINALS,'isolation':t.n.HELPER,'accepted':t.n.ACCEPTED,'attestor':a.ATTESTOR}.items()}}
            if node == a.SHARED_NODE:
                for name,path in (('shared',a.SHARED),('freezer',a.FREEZER)):
                    f.put(path,('independent SIMULATED '+name).encode()); pin['files'][name] = a.sha(f.fs.read(path)[0])
            self.config['nodes'][node] = pin
            original = f.accepted['profiles'][profile]
            physical['nodes'].append({'nodeId':node,'targetProfile':profile,'endpoint':{'ip':endpoint,'port':2222,'username':'c3-test-runner'},
                'physical':{k:f.plan[k] for k in ('machineId','bootId','sshHostKeySha256')},'maintenanceId':f.plan['maintenanceId'],
                'planHash':f.engine.plan_hash,'guard':f.guard,'operatorKeyPath':'/etc/celerity/SIMULATED-operator-key',
                'originalSnapshot':{'proofRef':'accepted-'+str(index),'configSha256':original['files']['config']['sha256'],
                    'unitSha256':original['files']['unit']['sha256'],'serviceActive':original['service']['ActiveState'],'serviceEnabled':original['service']['UnitFileState']}})
            f.put(a.STATE+'/host-guard.json',a.canonical(physical['host']['guard']))
            f.put('/fixture-live.json',a.canonical({'held':True}))
            f.put('/fixture-services.json',a.canonical(f.system.states))
            self.fixtures.append(f)
        physical['host']['guard']['planHash'] = self.config['nodes'][a.SHARED_NODE]['identity']['planHash']
        for f in self.fixtures:
            f.put(a.STATE+'/host-guard.json',a.canonical(physical['host']['guard']))
        self.physical = physical
        self.config['ownerChallenge'] = {'version':1,'executionContext':physical['executionContext'],'host':physical['host'],'nodes':[
            {'nodeId':p['nodeId'],'targetProfile':p['targetProfile'],'endpoint':p['endpoint'],
             'nodeIdentity':{k:p['physical'][k] for k in ('machineId','sshHostKeySha256')},'bootId':p['physical']['bootId'],
             **{k:p[k] for k in ('maintenanceId','planHash','guard','originalSnapshot')}} for p in physical['nodes']]}
        for f in self.fixtures:
            f.put(a.CONFIG,a.canonical(self.config))
        self.put(a.CONFIG,a.canonical(self.config))
        self.put(a.LOCK,b'')
        self.socket = self.root/'o.sock'
        return self

    def put(self,path,raw):
        target = self.root/path.lstrip('/')
        target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        for parent in target.parents:
            if parent == self.root.parent: break
            parent.chmod(0o700)
        target.write_bytes(raw); target.chmod(0o600)

    def spawn(self,node):
        f = next(f for f in self.fixtures if f.node == node)
        child = subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'node',str(f.root)],cwd=HERE,
                                 stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,
                                 env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        self.children.append(child)
        return child

    def __exit__(self,*_):
        for child in self.children:
            if child.poll() is None: child.kill(); child.wait(timeout=3)
            for stream in (child.stdin,child.stdout,child.stderr):
                if stream: stream.close()
        self.stack.close()


def node(root, *, observer_serve=False, runtime_observer=False, dispatch=None):
    n = t.n
    fixture = n.Fixture(Path(root),os.getuid(),os.getgid(),None)
    fs = n.Files(fixture)
    config = fs.read_json(a.CONFIG)
    accepted = fs.read_json(n.ACCEPTED)
    plan = fs.read_json('/fixture-plan.json')
    pin = config['nodes'][plan['nodeId']]
    import types
    observer = types.ModuleType('installed_fixture_attestor')
    raw = fs.read(a.ATTESTOR)[0]
    n.need(a.sha(raw) == pin['files']['attestor'], 'ATTESTOR_SOURCE_PIN_DRIFT')
    exec(compile(raw,str(Path(root)/a.ATTESTOR.lstrip('/')),'exec'),observer.__dict__)
    engine = isolation.Engine(Path(root)/n.STATE.lstrip('/'),plan,None,validator=lambda p:p)
    def held():
        n.need(fs.read_json('/fixture-live.json')['held'],'SIMULATED_GUARD_LOST')
        return engine.read()
    engine.host = SimpleNamespace(check_prerequisites=lambda *_:held(),assert_stopped=lambda *_:held(),
        check_inventory=lambda *args,**kwargs: (held() and {'processes':[]}),physical=lambda:{k:plan[k] for k in ('machineId','bootId','sshHostKeySha256')},operator_session=lambda:{'pid':78,'start':'999'})
    def guard_check(guard,session=None):
        n.need(guard == pin['guard'] and session in (None,{'pid':78,'start':'999'}), 'SIMULATED_SESSION_DRIFT')
        held()
    engine.host.guard_check = guard_check
    system = t.SimulatedSystem(SimpleNamespace(unit=n.profile_paths(plan['targetProfile'])[1]))
    system.states = fs.read_json('/fixture-services.json')
    fixture.system = system
    host = config['ownerChallenge']['host']
    plan['hostHold'] = {'owner':host['owner']}
    def shared_hold(*_):
        held()
        return {'containers':[{'name':'hysteria-backend','id':host['backend']['instanceId'],
                  'init':{'pid':host['backend']['pid'],'startTicks':host['backend']['processStartTime']}}]}
    shared = SimpleNamespace(check_hold=shared_hold) if plan['nodeId'] == a.SHARED_NODE else None
    engine.host.host_hold = shared_hold
    engine.host.unit = system.unit
    # Simulated UID only: every byte, stat, journal, flock and Engine check is real.
    def read(path,directory=False):
        path = str(path)
        if path.startswith(str(root)+'/'): path = path[len(str(root)):]
        raw = b'' if directory else fs.read(path)[0]
        st = (Path(root)/path.lstrip('/')).stat()
        return raw,SimpleNamespace(st_uid=0,st_gid=0,st_mode=st.st_mode,st_nlink=st.st_nlink)
    observer.installation.__defaults__ = (read,None)
    observer.config_snapshot.__defaults__ = (read,None)
    observer.durable_originals.__defaults__ = (read,)
    observer.secure_read = read
    observer.Path = lambda path: Path(root)/str(path).lstrip('/')
    module = SimpleNamespace(RESTORE_ADMISSION_VERSION=1,STATE=n.STATE,decode_json=isolation.decode_json,Host=lambda:engine.host)
    writer = n.NodeOriginals(engine,module,fixture=fixture)
    server = a.NodeServer(writer,n,config,a.Wire(0,1,time.monotonic()+120),c,shared=shared,attestor=observer)
    if dispatch is not None:
        # Same actual isolation journal/outer lock observed during capture and
        # ordinary attestation. Only UID/kernel/systemd/SSH are SIMULATED.
        import fcntl
        real_run = subprocess.run
        source = HERE.parents[1]/'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
        def actual_runner(argv, **kwargs):
            assert argv[:2] == ['/bin/bash', isolation.RUNNER]
            env = {**kwargs.pop('env'), 'CELERITY_TOPOLOGY_ROOT': str(root)}
            return real_run(['unshare', '--user', '--map-root-user', '/bin/bash', str(source), *argv[2:]],
                            env=env, timeout=40, **kwargs)
        with fs.opened(n.OUTER_LOCK) as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            isolation.subprocess.run = actual_runner
            sys.stdout.buffer.write(engine.dispatch(dispatch, sys.stdin.buffer.read(4194305), fd))
    elif runtime_observer:
        server.pins()
        observer.serve(engine,module,shared)
    elif observer_serve:
        server.pins()
        with a.CaptureHold(writer,n) as capture_hold:
            capture_hold.capture()
            observer.serve(engine,module,shared,held=capture_hold)
    else:
        server.serve()


def main():
    if sys.argv[1] == 'runtime-dispatch':
        node(sys.argv[2],dispatch=sys.argv[3]); return
    if sys.argv[1] in ('node','observer-serve','runtime-observer'):
        node(sys.argv[2],observer_serve=sys.argv[1] == 'observer-serve',runtime_observer=sys.argv[1] == 'runtime-observer'); return
    if sys.argv[1] == 'owner':
        fs = t.n.Files(t.n.Fixture(Path(sys.argv[2]),os.getuid(),os.getgid(),None))
        a.owner_bridge(fs,c,a.Wire(0,1,time.monotonic()+120),fixture_socket=sys.argv[3]); return
    if sys.argv[1] == 'supervisor':
        with CaptureFixture(large=len(sys.argv) == 3 and sys.argv[2] == 'large') as f:
            listener = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(f.socket)); listener.listen(1)
            try:
                with a.Coordinator(f.config,f.fs,f.spawn,c,origin=f.origin).capture_scope() as held:
                    print(json.dumps({'root':str(f.root),'socket':str(f.socket),'physical':f.physical,
                          'nodeRoots':{n.node:str(n.root) for n in f.fixtures}}),flush=True)
                    held.serve_owner(listener)
            finally:
                listener.close()
            # Preserve disposable files for exact post-scope readback. The
            # coordinator/OFD scope is already closed; no authority is retained.
            # The parent test owns this fixture process and closes it explicitly.
            print(json.dumps({'fixtureCaptureHoldersClosed': True}),flush=True)
            sys.stdin.buffer.read(1)
        return
    raise RuntimeError('fixture verb')


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        # Fixture diagnostics only; the installed CLI always redacts failures.
        if sys.argv[1] not in ('node','observer-serve'): raise
        import traceback
        traceback.print_exc()
        raise SystemExit(75)
