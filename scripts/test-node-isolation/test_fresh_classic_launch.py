"""Real exec/HTTP/proc/journals/flock. Root/sandbox inventory explicitly simulated."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent


def load():
    spec = importlib.util.spec_from_file_location('fresh_classic_launch', HERE/'fresh_classic_launch.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FreshLaunchTests(unittest.TestCase):
    def test_config_pin_refuses_before_commit_and_attempt(self):
        m=load()
        with launch_fixture(m, fault='config-pin') as f:
            with self.assertRaises(BaseException) as caught:
                f.launch()
            self.assertFalse(f.held.commit_attempted, 'config mismatch reached irreversible COMMIT')
            self.assertEqual(str(caught.exception),'ACCEPTED_COORDINATOR_REQUIRED')
            self.assertTrue(f.fs.absent(m.c.COMMIT))
            self.assertTrue(f.fs.absent(m.ATTEMPT))
            self.assertEqual(f.count(),0)

    def test_actual_fixed_exec_serves_and_survives_finite_controller(self):
        self.assertTrue((HERE/'fresh_classic_launch.py').is_file(),
                        'concrete fresh classic exec primitive missing')
        m = load()
        with launch_fixture(m) as f:
            result = f.launch()
            self.assertEqual(result['activationSet'], ['fresh-classic-process'])
            pid = result['serving']['pid']
            self.assertEqual(Path(f'/proc/{pid}/exe').stat().st_ino, Path(shutil.which('node')).stat().st_ino)
            self.assertEqual(result['serving']['start'], m.start(pid))
            self.assertTrue(result['serving']['socketInode'].isdigit())
            self.assertIsNone(f.supervisor.poll(), 'independent serving supervisor must outlive finite controller')
            self.assertTrue(Path(f'/proc/{pid}').exists(), 'finite controller exit must not kill serving child')
            self.assertEqual(m.http_probe('127.0.0.1', f.port), b'c3-classic-ready-v1\n')
            self.assertEqual(f.fs.read_json(m.ATTEMPT)['phase'], 'confirmed')
            self.assertEqual(f.count(), 1)

    def test_changed_source_and_settings_refuse_before_commit_with_zero_exec(self):
        m=load()
        for name in ('index.js','settings.json'):
            with self.subTest(name=name), launch_fixture(m, fault='expected-refusal') as f:
                (f.root/name).write_text('changed independently accepted bytes')
                with self.assertRaisesRegex(RuntimeError, 'CLOSURE_DRIFT'):
                    f.launch()
                self.assertTrue(f.fs.absent(m.c.COMMIT))
                self.assertTrue(f.fs.absent(m.ATTEMPT))
                self.assertEqual(f.count(),0)
    def test_postexec_faults_are_unknown_and_never_execute_twice(self):
        m=load()
        for fault in ('eof','timeout','fsync','death','cleanup'):
            with self.subTest(fault=fault), launch_fixture(m,fault=fault) as f:
                if fault == 'cleanup':
                    original=f.held.cleanup_channels
                    def broken_cleanup(primary=None):
                        original(primary)
                        raise OSError('SIMULATED cleanup failure after actual pipe disposal')
                    f.held.cleanup_channels=broken_cleanup
                with self.assertRaises(BaseException) as caught:
                    f.launch()
                if fault == 'cleanup': f.held.cleanup_channels=original
                self.assertEqual(getattr(caught.exception,'code',None),'COMMITTED_ACTIVATION_UNKNOWN')
                self.assertEqual(f.count(),1)
                self.assertEqual(f.fs.read_json(m.c.COMMIT)['activationSet'],m.ACTIVATION)
                with self.assertRaisesRegex(RuntimeError,'REPLAY'):
                    f.launch()
                self.assertEqual(f.count(),1)
                for fixture in f.fixtures:
                    self.assertEqual(fixture.fs.read_json('/fixture-live.json')['candidateFrozen'],True)

    def test_invalid_policy_identity_and_full_closure_refuse_zero_effect(self):
        m=load()
        for fault in ('identity','closure','settings','generation','old-permit'):
            with self.subTest(fault=fault), launch_fixture(m,fault='expected-refusal') as f:
                policy=f.fs.read_json(m.POLICY)
                if fault == 'identity': policy['context']='prod.infograd.online'
                if fault == 'closure': del policy['files']['/app/index.js']
                if fault == 'settings': policy['settings']='/arbitrary/settings'
                if fault == 'generation':
                    f.proof['nodes'][0]['owner']['generation']=f.proof['nodes'][0]['priorOwnerGeneration']
                if fault == 'old-permit':
                    f.fs.atomic(m.c.COMMIT,m.c.canonical({'activationSet':['existing-classic-backend']}),new=True)
                else:
                    f.fs.atomic(m.POLICY,m.c.canonical(policy))
                with self.assertRaises((RuntimeError,KeyError)): f.launch()
                self.assertTrue(f.fs.absent(m.ATTEMPT)); self.assertEqual(f.count(),0)


@contextlib.contextmanager
def launch_fixture(m, fault=None, *, bridge=False):
    """Disposable Node source/settings, no credentials or physical operations."""
    import types
    import test_coordinated_restore as ct
    import coordinated_restore as c
    with ct.cfixture(c, maintenance_id='12345678-1234-4234-8234-123456789abc' if bridge else None) as outer:
        root = outer.root/'fresh'
        root.mkdir()
        (outer.root/'state').mkdir(mode=0o700)
        (outer.root/'state/launch.lock').write_bytes(b'')
        (outer.root/'state/launch.lock').chmod(0o600)
        probe = socket.socket(); probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]; probe.close()
        source = root/'index.js'
        source.write_text("const fs=require('fs'),http=require('http'); const s=JSON.parse(fs.readFileSync(process.env.C3_SETTINGS)); fs.appendFileSync(s.count,'exec\\n'); http.createServer((q,r)=>r.end('c3-classic-ready-v1\\n')).listen(s.port,'127.0.0.1');\n")
        settings = root/'settings.json'; settings.write_text(json.dumps({'port':port, 'count':str(root/'executions')}))
        policy = {'version':1, 'context':'test.infograd.online', 'executable':'/runtime/node',
                  'source':'/app/index.js', 'settings':'/etc/classic.json',
                  'files':{'/runtime/node':m.digest(Path(shutil.which('node')).read_bytes()),
                           '/app/index.js':m.digest(source.read_bytes()), '/etc/classic.json':m.digest(settings.read_bytes())},
                  'environment':{'C3_SETTINGS':'/etc/classic.json', 'NODE_ENV':'production'},
                  'uid':65531, 'gid':65531, 'cgroup':'/system.slice/c3-test-fresh-classic.service',
                  'ingress':{'ip':'212.119.42.100', 'port':3000, 'path':'/classic-ready', 'bodySha256':m.digest(b'c3-classic-ready-v1\n')},
                  'inventory':inventory_fixture(m,outer.config)}
        if fault in ('root-alias','root-drift'):
            proc=root/'modeled-proc'; proc.mkdir(); (proc/'root').symlink_to(root)
            fd=os.open(root,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
            try:
                info=os.fstat(fd)
                mid=int(next(x.split()[1] for x in Path('/proc/self/fdinfo/'+str(fd)).read_text().splitlines() if x.startswith('mnt_id:')))
            finally: os.close(fd)
            mounts=modeled_mounts(mid+int(fault=='root-alias')); (proc/'mountinfo').write_bytes(mounts)
            policy['inventory'].update(root=[info.st_dev,info.st_ino],mountinfoSha256=m.digest(mounts))
        if fault == 'config-pin': policy['inventory']['coordinatorSha256']='f'*64
        if bridge:
            fresh_path = outer.root / c.FRESH.lstrip('/')
            fresh_path.parent.mkdir(parents=True, exist_ok=True)
            for parent in (fresh_path.parent, *fresh_path.parent.parents):
                if parent == outer.root.parent: break
                parent.chmod(0o700)
            fresh_raw = (HERE/'fresh_classic_launch.py').read_bytes()
            outer.fs.atomic(c.FRESH, fresh_raw, new=True)
            policy['files'][c.FRESH] = m.digest(fresh_raw)
        outer.fs.atomic(m.POLICY, c.canonical(policy), new=True)
        sock = root/'s.sock'
        listener = socket.socket(socket.AF_UNIX); listener.bind(str(sock)); listener.listen(1)
        # Only inventory/privileged identity/paths are simulated; supervisor
        # protocol, Popen/exec, HTTP, proc socket binding and all IO are real.
        code = '''import sys,os,json,socket
from pathlib import Path
import fresh_classic_launch as m
import test_node_originals as t
root=Path(sys.argv[1]); fs=t.n.Files(t.n.Fixture(root,os.getuid(),os.getgid(),None))
p=fs.read_json(m.POLICY)
class Simulated(m.Platform):
 checks=0
 def check(self,policy):
  self.checks+=1
  if sys.argv[5] in ('root-alias','root-drift'):
   if sys.argv[5]=='root-drift' and self.checks==2:
    path=root/'fresh/modeled-proc/mountinfo'
    lines=path.read_text().splitlines(); fields=lines[0].split(); fields[0]=str(int(fields[0])+1)
    lines[0]=' '.join(fields); path.write_text('\\n'.join(lines)+'\\n')
    policy['inventory']['mountinfoSha256']=m.digest(path.read_bytes())
   m.Platform().root_mount(policy,root/'fresh/modeled-proc')
  m.verify_files(policy,lambda name: sys.argv[3] if name=='/runtime/node' else (root/name.lstrip('/') if name==m.c.FRESH else root/'fresh'/('index.js' if name=='/app/index.js' else 'settings.json')))
 def paths(self,policy):
  base=root/'fresh'
  return [sys.argv[3],str(base/'index.js')],{'C3_SETTINGS':str(base/'settings.json'),'NODE_ENV':'production'},str(base)
 def observe(self,policy,pid): return m.observe(pid,'127.0.0.1',int(sys.argv[4]))
listener=socket.socket(fileno=int(sys.argv[2]))
if sys.argv[6] == 'bridge':
 # Fixture starts before public Mongo provisioning. Model separately scheduled
 # supervisor startup; production's five-second prepared accept is unchanged.
 raw_listener=listener
 class FixtureListener:
  def listen(self,value): raw_listener.listen(value)
  def settimeout(self,value): raw_listener.settimeout(70)
  def accept(self): return raw_listener.accept()
  def close(self): raw_listener.close()
 listener=FixtureListener()
m.supervise(listener,fs,Simulated(),fault=sys.argv[5] or None)
'''
        supervisor = subprocess.Popen([sys.executable,'-B','-c',code,str(outer.root),str(listener.fileno()),shutil.which('node'),str(port),fault or '', 'bridge' if bridge else ''],
            cwd=HERE, pass_fds=(listener.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        listener.close()
        class Simulated(m.Platform):
            def check(self, policy):
                m.verify_files(policy,lambda name: shutil.which('node') if name=='/runtime/node' else (outer.root/name.lstrip('/') if name==c.FRESH else root/('index.js' if name=='/app/index.js' else 'settings.json')))
            def supervisor(self, policy, pid):
                self.check(policy)
                return {'pid':pid, 'start':m.start(pid)}
            def endpoint(self, policy): return '127.0.0.1',port
            def observe(self, policy, pid): return m.observe(pid, '127.0.0.1',port)
        f=types.SimpleNamespace(fs=outer.fs,root=root,port=port,supervisor=supervisor,fixtures=outer.fixtures)
        def count(): return len((root/'executions').read_text().splitlines()) if (root/'executions').exists() else 0
        f.count=count
        try:
            scope=c.Coordinator(outer.config,outer.fs,outer.spawn,origin=outer.origin).restore_scope()
            held=scope.__enter__()
            try:
                f.outer=outer; f.platform=Simulated(); f.socket=str(sock)
                f.held=held
                f.client=m.FreshLaunch(held,Simulated(),socket_path=str(sock))
                import test_irreversible_handback as ih
                f.proof=ih.settlement_proof(outer,c)
                f.launch=lambda: f.client.run(f.proof)
                yield f
            finally:
                if held.handoff_completed: scope.__exit__(None,None,None)
                else:
                    error=RuntimeError('test-only scope disposal, never recovery')
                    scope.__exit__(RuntimeError,error,None)
        finally:
            # Test-only disposal, NEVER implementation recovery/rollback.
            for entry in root.glob('serving-*.json'):
                pid=json.loads(entry.read_text())['pid']
                try: os.kill(pid,15)
                except ProcessLookupError: pass
            if supervisor.poll() is None: supervisor.kill()
            out,err=supervisor.communicate(timeout=3)
            if err and not fault: raise AssertionError(err.decode())


def inventory_fixture(m, config):
    # Explicitly simulated physical inventory, independently pinned config.
    return {'coordinatorSha256':m.digest(m.c.canonical(config)),
            'supervisor':{'pid':123,'start':'456'}, 'root':[1,2],
            'namespaces':{n:'private-'+n for n in ('mnt','net','ipc','uts')},
            'hostNamespaces':{n:'host-'+n for n in ('mnt','net','ipc','uts')},
            'mountinfoSha256':'0'*64,'routesSha256':'0'*64,
            'sourceSha256':'0'*64,'unitSha256':'0'*64,'fdPins':{}}


class PolicyBoundaryTests(unittest.TestCase):
    def policy(self):
        m=load()
        return m, {'version':1,'context':'test.infograd.online','executable':'/runtime/node',
            'source':'/app/index.js','settings':'/etc/classic.json',
            'files':{n:'0'*64 for n in ('/runtime/node','/app/index.js','/etc/classic.json')},
            'environment':dict(m.ENV),'uid':65531,'gid':65531,'cgroup':m.CGROUP,
            'ingress':{'ip':'212.119.42.100','port':3000,'path':'/classic-ready','bodySha256':m.READY_BODY_SHA256},
            'inventory':inventory_fixture(m,{})}

    def test_strict_scalars_and_minimal_structures(self):
        import copy
        m,p=self.policy()
        self.assertIs(m.validate(p),p)
        for field in ('uid','gid','port'):
            for value in (float(p['ingress']['port'] if field=='port' else p[field]),True,False):
                q=copy.deepcopy(p)
                (q['ingress'] if field=='port' else q)[field]=value
                with self.subTest(field=field,value=value), self.assertRaises(m.c.Refusal): m.validate(q)
        for field in ('inventory','ingress','files'):
            for value in (None,[],0):
                q=copy.deepcopy(p); q[field]=value
                with self.subTest(field=field,value=value), self.assertRaises(m.c.Refusal): m.validate(q)
        for field,value in (('supervisor',[]),('root',[1.0,2]),('namespaces',{}),
                            ('hostNamespaces',[]),('fdPins',[]),('coordinatorSha256',[])):
            q=copy.deepcopy(p); q['inventory'][field]=value
            with self.subTest(field=field), self.assertRaises(m.c.Refusal): m.validate(q)
        from types import SimpleNamespace
        h=SimpleNamespace(config={'context':'test.infograd.online'})
        for proof in (None,[],{'context':'test.infograd.online','revision':1,'deployedRevision':1,'quietSha256':[], 'nodes':[]}):
            with self.subTest(proof=proof), self.assertRaises(m.c.Refusal): m.settlement(h,proof)


class ActualSupervisorTests(unittest.TestCase):
    def test_loaded_restart_force_override_rejected(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        m,p=PolicyBoundaryTests().policy()
        for force in ('SIGKILL','1',''):
            with self.subTest(force=force):
                unit=b'Restart=no\nKillMode=process\nRestartForceExitStatus='+force.encode()+b'\n'
                inv=p['inventory']; inv['sourceSha256']=m.digest(b'coord'); inv['unitSha256']=m.digest(unit)
                def readlink(path):
                    return ('host-' if '/proc/1/' in str(path) else 'private-')+Path(path).name
                def readtext(path,*a,**kw):
                    return {'cgroup':'0::'+m.CGROUP,'cgroup.procs':'123','cgroup.freeze':'0'}[Path(path).name]
                def loaded(argv,**kw):
                    properties={'MainPID':'123','Restart':'no','KillMode':'process','ControlGroup':m.CGROUP,
                                'NeedDaemonReload':'no','RestartForceExitStatus':force}
                    requested=argv[-1].split('=',1)[1].split(',')
                    return SimpleNamespace(stdout=''.join(k+'='+properties[k]+'\n' for k in requested).encode())
                with patch.object(m,'start',return_value='456'),patch.object(m,'verify_files'), \
                     patch.object(m.os,'readlink',side_effect=readlink),patch.object(Path,'read_text',readtext), \
                     patch.object(m.c,'trusted_read',side_effect=lambda x:unit if x.endswith('.service') else b'coord'), \
                     patch.object(m.subprocess,'run',side_effect=loaded):
                    if force:
                        with self.assertRaisesRegex(m.c.Refusal,'LOADED_SUPERVISOR_DRIFT'): m.Platform().supervisor(p,123)
                    else: self.assertEqual(m.Platform().supervisor(p,123),inv['supervisor'])


class AncillaryDisposalTests(unittest.TestCase):

    def test_all_rights_records_are_owned_before_semantic_rejection(self):
        import array
        from types import SimpleNamespace
        from unittest.mock import patch
        m=load()
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'ordinary'; path.write_bytes(b'x')
            fds=[os.open(path,os.O_RDONLY) for _ in range(2)]
            anc=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fds[0]]).tobytes()),
                 (socket.SOL_SOCKET,socket.SCM_CREDENTIALS,b'irrelevant'),
                 (socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fds[1]]).tobytes())]
            conn=SimpleNamespace(recvmsg=lambda *a:(b'x\n',anc,0,None))
            closed=[]; actual_close=os.close
            def close(fd):
                actual_close(fd); closed.append(fd)
                raise OSError('reported close failure')
            try:
                with patch.object(m.os,'close',side_effect=close):
                    with self.assertRaisesRegex(m.c.Refusal,'COMMIT_FD_REQUIRED'):
                        with m.commit_frame(conn): self.fail('invalid ancillary accepted')
                self.assertEqual(closed,fds)
                for fd in fds:
                    with self.assertRaises(OSError): os.fstat(fd)
            finally:
                for fd in fds:
                    try: actual_close(fd)
                    except OSError: pass

    def test_real_credentials_before_rights_all_disposed_despite_close_error(self):
        import array
        from types import SimpleNamespace
        from unittest.mock import patch, Mock
        m,p=PolicyBoundaryTests().policy()
        for close_error in (False,True):
            with self.subTest(close_error=close_error), tempfile.TemporaryDirectory() as root:
                path=Path(root)/'ordinary'; path.write_bytes(b'x')
                source=os.open(path,os.O_RDONLY)
                a,b=socket.socketpair()
                b.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
                a.sendmsg([b'x\n'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[source,source]))])
                received=[]; kinds=[]; closed=[]; actual_close=os.close
                class Connection:
                    def __getattr__(self,key): return getattr(b,key)
                    def recvmsg(self,*args):
                        raw,anc,flags,peer=b.recvmsg(4096,1024)
                        for level,kind,data in anc:
                            kinds.append(kind)
                            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                                fds=array.array('i'); fds.frombytes(data); received.extend(fds)
                        return raw,anc,flags,peer
                def close(fd):
                    actual_close(fd); closed.append(fd)
                    if close_error and len(closed)==1: raise OSError('close reported failure after disposal')
                fs=SimpleNamespace(fixture=object(),uid=os.getuid(),lock=lambda _:contextlib.nullcontext(),
                                   absent=lambda _:True,read_json=lambda _:p,atomic=Mock())
                platform=SimpleNamespace(check=lambda _:None,paths=Mock())
                listener=Mock(); listener.accept.return_value=(Connection(),None)
                try:
                    with patch.object(m.os,'close',side_effect=close):
                        with self.assertRaisesRegex(m.c.Refusal,'COMMIT_FD_REQUIRED'):
                            m.supervise(listener,fs,platform)
                    self.assertEqual(kinds,[socket.SCM_CREDENTIALS,socket.SCM_RIGHTS])
                    self.assertEqual(len(received),2)
                    self.assertEqual(closed,received)
                    for fd in received:
                        with self.assertRaises(OSError): os.fstat(fd)
                    fs.atomic.assert_not_called(); platform.paths.assert_not_called()
                finally:
                    for fd in received:
                        try: actual_close(fd)
                        except OSError: pass
                    actual_close(source); a.close(); b.close()


class RootMountTests(unittest.TestCase):
    @contextlib.contextmanager
    def topology(self,m,alias=False):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); directory=base/'ordinary'; directory.mkdir()
            fd=os.open(directory,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
            try:
                proc=base/'modeled-proc'; proc.mkdir()
                (proc/'root').symlink_to('/proc/self/fd/'+str(fd))
                info=os.fstat(fd)
                mid=int(next(x.split()[1] for x in Path('/proc/self/fdinfo/'+str(fd)).read_text().splitlines() if x.startswith('mnt_id:')))
                mounts=modeled_mounts(mid+int(alias))
                (proc/'mountinfo').write_bytes(mounts)
                p=PolicyBoundaryTests().policy()[1]
                p['inventory'].update(root=[info.st_dev,info.st_ino],mountinfoSha256=m.digest(mounts))
                yield p,proc
            finally: os.close(fd)

    def test_actual_open_path_mount_id_rejects_same_device_alias(self):
        m=load()
        self.assertTrue(callable(getattr(m.Platform,'root_mount',None)), 'retained root mount binding missing')
        for alias in (False,True):
            with self.subTest(alias=alias),self.topology(m,alias) as (p,proc):
                if alias:
                    with self.assertRaisesRegex(m.c.Refusal,'FRESH_ROOT_MOUNT_IDENTITY_REQUIRED'): m.Platform().root_mount(p,proc)
                else: m.Platform().root_mount(p,proc)

    def test_owned_path_fd_closes_on_stat_read_parse_and_close_fault(self):
        from unittest.mock import patch
        m=load()
        self.assertTrue(callable(getattr(m.Platform,'root_mount',None)), 'retained root mount binding missing')
        for fault in ('stat','read','parse','duplicate','close','read-close'):
            with self.subTest(fault=fault),self.topology(m) as (p,proc):
                opened=[]; closed=[]; actual_open=os.open; actual_close=os.close; actual_stat=os.fstat; actual_read=Path.read_bytes
                def opened_path(path,flags,*a,**kw):
                    fd=actual_open(path,flags,*a,**kw)
                    if str(path)==str(proc/'root'):
                        opened.append(fd)
                        self.assertTrue(flags & os.O_PATH and flags & os.O_CLOEXEC)
                        self.assertFalse(os.get_inheritable(fd))
                    return fd
                def stat_fd(fd):
                    if fault=='stat' and fd in opened: raise OSError('primary stat')
                    return actual_stat(fd)
                def read(path):
                    if '/proc/self/fdinfo/' in str(path):
                        self.assertEqual(len(opened),1); actual_stat(opened[0])  # still open
                        if fault in ('read','read-close'): raise OSError('primary read')
                        if fault=='parse': return b'mnt_id:\tbroken\n'
                        if fault=='duplicate': return b'mnt_id:\t1\nmnt_id:\t1\n'
                    return actual_read(path)
                def close(fd):
                    actual_close(fd); closed.append(fd)
                    if fault in ('close','read-close'): raise OSError('cleanup close')
                with patch.object(m.os,'open',side_effect=opened_path),patch.object(m.os,'fstat',side_effect=stat_fd), \
                     patch.object(Path,'read_bytes',read),patch.object(m.os,'close',side_effect=close):
                    expected='primary stat' if fault=='stat' else ('primary read' if fault in ('read','read-close') else ('cleanup close' if fault=='close' else 'ROOT_FDINFO'))
                    with self.assertRaisesRegex((OSError,m.c.Refusal),expected): m.Platform().root_mount(p,proc)
                self.assertEqual(closed,opened)
                for fd in opened:
                    with self.assertRaises(OSError): os.fstat(fd)

    def test_alias_refuses_zero_commit_exec_and_postprepared_drift_stays_unknown(self):
        m=load()
        self.assertTrue(callable(getattr(m.Platform,'root_mount',None)), 'retained root mount binding missing')
        for fault in ('root-alias','root-drift'):
            with self.subTest(fault=fault),launch_fixture(m,fault=fault) as f:
                with self.assertRaises(BaseException) as caught: f.launch()
                self.assertEqual(f.count(),0)
                if fault=='root-alias':
                    self.assertFalse(f.held.commit_attempted)
                    self.assertTrue(f.fs.absent(m.c.COMMIT)); self.assertTrue(f.fs.absent(m.ATTEMPT))
                else:
                    self.assertTrue(f.held.commit_attempted)
                    self.assertEqual(caught.exception.code,'COMMITTED_ACTIVATION_UNKNOWN')
                    self.assertFalse(f.fs.absent(m.c.COMMIT)); self.assertFalse(f.fs.absent(m.ATTEMPT))
                with self.assertRaisesRegex(RuntimeError,'REPLAY'): f.launch()
                for fixture in f.fixtures:
                    self.assertTrue(fixture.fs.read_json('/fixture-live.json')['candidateFrozen'])


def modeled_mounts(root_id):
    # Only mount topology/flags are modeled; O_PATH/fstat/fdinfo are real.
    return (f'{root_id} 0 0:1 / / ro,nodev,nosuid - tmpfs root ro\n'
            f'{root_id+10} {root_id} 0:2 / /proc ro,nodev,nosuid - proc proc ro\n'
            f'{root_id+20} {root_id} 0:3 / /state rw,nodev,nosuid,noexec - tmpfs state rw\n').encode()


if __name__ == '__main__': unittest.main()
