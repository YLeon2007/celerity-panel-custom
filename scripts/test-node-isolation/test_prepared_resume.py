"""Local real stopped PID/flock/UDS; physical root/unit authority SIMULATED.

No Node, Mongo, privileged operations or production acceptance in this suite.
"""
import contextlib
import fcntl
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import coordinated_restore as c
import fresh_classic_launch as fresh
from test_fresh_classic_launch import PolicyBoundaryTests

HERE = Path(__file__).resolve().parent


@contextlib.contextmanager
def stopped_listener(delay=.12, fault=''):
    with tempfile.TemporaryDirectory(prefix='pr-') as temp:
        root = Path(temp)
        code = '''import fcntl,os,signal,socket,sys,time
from pathlib import Path
root=Path(sys.argv[1]); listener=socket.socket(socket.AF_UNIX)
listener.bind(str(root/'s'))
if listener.fileno()!=3:
 os.dup2(listener.fileno(),3); listener.close(); listener=socket.socket(fileno=3)
with (root/'lock').open('a+b') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 os.kill(os.getpid(),signal.SIGSTOP)
 (root/'continued').write_bytes(b'once')
 time.sleep(float(sys.argv[2]))
 if sys.argv[3]=='death': sys.exit(0)
 if sys.argv[3]=='never': time.sleep(10)
 listener.listen(1); listener.settimeout(5)
 conn,_=listener.accept()
 (root/'accepted').write_bytes(b'once')
 conn.sendall(b'actual-only-connection'); conn.close()
'''
        process = subprocess.Popen([sys.executable, '-B', '-c', code, str(root), str(delay), fault],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+3
            while time.monotonic() < deadline:
                pid, status = os.waitpid(process.pid, os.WNOHANG|os.WUNTRACED)
                if pid:
                    if not os.WIFSTOPPED(status):
                        raise AssertionError(('child did not stop', status))
                    break
                time.sleep(.005)
            else: raise AssertionError('bounded stop wait expired')
            policy = PolicyBoundaryTests().policy()[1]
            policy['inventory']['supervisor'] = {'pid':process.pid, 'start':fresh.start(process.pid)}
            info = os.stat(f'/proc/{process.pid}/fd/3')
            policy['inventory']['fdPins'] = {'3':[info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)]}
            yield SimpleNamespace(root=root, process=process, policy=policy)
        finally:
            if process.poll() is None: process.kill()
            process.communicate(timeout=3)


class PreparedResumeTests(unittest.TestCase):
    def launch(self, f):
        # The real Coordinator type is retained; physical all-five checks are
        # simulated here. An assembled real five-channel regression is separate.
        held = object.__new__(c.Coordinator)
        held.fs = SimpleNamespace(fixture=object())
        held.prepared_resume_attempted = False
        held.nodes = []
        held.deadline = time.monotonic()+2
        held.check = lambda: fresh.need(time.monotonic()<held.deadline, 'RESTORATION_CAPABILITY_REVOKED')
        class Simulated(fresh.Platform):
            def prepared(self, policy, pid):
                fresh.need(policy['inventory']['supervisor'] == {'pid':pid, 'start':fresh.start(pid)},
                           'ACCEPTED_SUPERVISOR_REQUIRED')
        return fresh.FreshLaunch(held, Simulated(), socket_path=str(f.root/'s'))

    def test_resume_waits_for_kernel_listen_without_consuming_sole_accept(self):
        self.assertTrue(hasattr(fresh.FreshLaunch, '_resume_prepared'),
                        'same-Coordinator prepared resume sequencing missing')
        with stopped_listener() as f:
            launch = self.launch(f)
            with (f.root/'lock').open('rb') as lock:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.assertFalse((f.root/'continued').exists())
            sent=[]; real_send=signal.pidfd_send_signal
            def send(fd, sig, *args):
                self.assertEqual(sig, signal.SIGCONT)
                self.assertEqual(fresh.start(f.process.pid), f.policy['inventory']['supervisor']['start'])
                sent.append(sig); return real_send(fd, sig, *args)
            with patch.object(fresh.c.signal, 'pidfd_send_signal', side_effect=send):
                fd=launch._resume_prepared(f.policy)
            try:
                self.assertEqual(sent, [signal.SIGCONT])
                self.assertFalse((f.root/'accepted').exists(), 'readiness consumed the only accept')
                with socket.socket(socket.AF_UNIX) as conn:
                    conn.connect(str(f.root/'s'))
                    self.assertEqual(conn.recv(100), b'actual-only-connection')
                self.assertTrue((f.root/'accepted').exists())
            finally: os.close(fd)
            with self.assertRaisesRegex(c.Refusal, 'REPLAY'):
                fresh.FreshLaunch(launch.held, launch.platform, socket_path=launch.path)._resume_prepared(f.policy)
    def test_dead_reused_identity_fd_and_expired_hold_refuse_without_signal(self):
        for fault in ('dead','start','fd','deadline','guard'):
            with self.subTest(fault=fault), stopped_listener() as f:
                launch=self.launch(f)
                if fault=='dead': f.process.kill(); f.process.wait(timeout=2)
                if fault=='start': f.policy['inventory']['supervisor']['start']='0'
                if fault=='fd': f.policy['inventory']['fdPins']['3'][1]+=1
                if fault=='deadline': launch.held.deadline=time.monotonic()-1
                if fault=='guard': launch.held.check=lambda: fresh.need(False,'NONSELECTED_HOLD_LOST')
                with patch.object(signal,'pidfd_send_signal',wraps=signal.pidfd_send_signal) as sent:
                    with self.assertRaises((OSError,c.Refusal)): launch._resume_prepared(f.policy)
                    self.assertEqual(sent.call_count,0)
                self.assertFalse((f.root/'continued').exists())
                with self.assertRaisesRegex(c.Refusal,'REPLAY'): launch._resume_prepared(f.policy)

    def test_postsignal_death_timeout_and_guardloss_never_resignal_or_connect(self):
        for fault in ('death','never','guard'):
            with self.subTest(fault=fault), stopped_listener(.03,fault) as f:
                launch=self.launch(f)
                launch.held.deadline=time.monotonic()+.2
                if fault=='guard':
                    count=0
                    def check():
                        nonlocal count
                        count+=1
                        fresh.need(count==1,'NONSELECTED_HOLD_LOST')
                    launch.held.check=check
                before=set(os.listdir('/proc/self/fd'))
                with patch.object(signal,'pidfd_send_signal',wraps=signal.pidfd_send_signal) as sent:
                    with self.assertRaises((OSError,c.Refusal)): launch._resume_prepared(f.policy)
                    self.assertEqual(sent.call_count,1)
                    with self.assertRaisesRegex(c.Refusal,'REPLAY'): launch._resume_prepared(f.policy)
                    self.assertEqual(sent.call_count,1)
                self.assertEqual(set(os.listdir('/proc/self/fd')),before)
                self.assertFalse((f.root/'accepted').exists())

    def test_readiness_checkpoints_cannot_outlive_remaining_budget(self):
        with stopped_listener(.03,'never') as f:
            launch=self.launch(f); reader,writer=os.pipe()
            original_deadline=time.monotonic()+10
            wire=c.Wire(reader,writer,original_deadline)
            launch.held.nodes=[SimpleNamespace(wire=wire)]
            launch.held.deadline=time.monotonic()+.15
            calls=0
            def check():
                nonlocal calls
                calls+=1
                if calls>1: wire.receive()  # real silent pipe, not a sleep mock
            launch.held.check=check
            before=time.monotonic()
            try:
                with self.assertRaisesRegex(c.Refusal,'TIMEOUT'): launch._resume_prepared(f.policy)
                self.assertLess(time.monotonic()-before,1)
                self.assertEqual(wire.deadline,original_deadline)
            finally: os.close(reader); os.close(writer)

    def test_pidfd_unavailable_has_no_pid_signal_fallback(self):
        with stopped_listener() as f:
            launch=self.launch(f)
            with patch.object(os,'pidfd_open',side_effect=OSError('unsupported pidfd')), \
                 patch.object(os,'kill',side_effect=AssertionError('PID signal fallback forbidden')):
                with self.assertRaisesRegex(OSError,'unsupported'): launch._resume_prepared(f.policy)
            self.assertFalse((f.root/'continued').exists())


@contextlib.contextmanager
def prepared_fixture(m=fresh, fault=None, *, bridge=True):
    """Real preparer/flocks/five channels/protocol/Python exec, modeled platform.

    Python HTTP is an unprivileged protocol witness, NOT actual Node/app evidence.
    The accepted physical UID/root/mount/unit/source attestor is simulated.
    """
    import json
    import test_coordinated_restore as ct
    from test_fresh_classic_launch import inventory_fixture
    from test_irreversible_handback import settlement_proof
    with ct.cfixture(c, maintenance_id='12345678-1234-4234-8234-123456789abc') as outer:
        root=outer.root/'fresh'; root.mkdir()
        (outer.root/'state').mkdir(mode=0o700)
        (outer.root/'state/launch.lock').write_bytes(b'')
        (outer.root/'state/launch.lock').chmod(0o600)
        source=root/'index.py'
        source.write_text('''import http.server,json,os
from pathlib import Path
settings=json.loads(Path(os.environ['C3_SETTINGS']).read_text())
with open(settings['count'],'a') as out: out.write('exec\\n')
class Handler(http.server.BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def do_GET(self):
  body=b'c3-classic-ready-v1\\n'
  self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*args): pass
http.server.HTTPServer(('127.0.0.1',settings['port']),Handler).serve_forever()
''')
        probe=socket.socket(); probe.bind(('127.0.0.1',0)); port=probe.getsockname()[1]; probe.close()
        settings=root/'settings.json'; settings.write_text(json.dumps({'port':port,'count':str(root/'executions')}))
        installed=outer.root/c.FRESH.lstrip('/')
        installed.parent.mkdir(parents=True,mode=0o700)
        for parent in installed.parent.parents:
            if parent == outer.root.parent: break
            parent.chmod(0o700)
        outer.fs.atomic(c.FRESH,(HERE/'fresh_classic_launch.py').read_bytes(),new=True)
        outer.fs.atomic(c.SELF,(HERE/'coordinated_restore.py').read_bytes(),new=True)
        mapping={'/runtime/node':Path(sys.executable).resolve(), '/app/index.js':source,
                 '/etc/classic.json':settings, c.FRESH:outer.root/c.FRESH.lstrip('/'),
                 c.SELF:outer.root/c.SELF.lstrip('/')}
        policy=PolicyBoundaryTests().policy()[1]
        policy['files']={name:fresh.digest(path.read_bytes()) for name,path in mapping.items()}
        policy['inventory']=inventory_fixture(fresh,outer.config)
        policy['inventory']['sourceSha256']=policy['files'][c.SELF]
        outer.fs.atomic(fresh.POLICY,c.canonical(policy),new=True)
        sock=root/'s'
        listener=socket.socket(socket.AF_UNIX); listener.bind(str(sock))  # NOT listening
        code='''import os,socket,sys,time
from pathlib import Path
import fresh_classic_launch as m
import test_node_originals as t
root=Path(sys.argv[1]); fs=t.n.Files(t.n.Fixture(root,os.getuid(),os.getgid(),None))
bootstrap=fs.read_json(m.POLICY)
m.c.trusted_read=lambda name:fs.read(name)[0]
class Paused(m.PreparationSupervisorFiles):
 fixture=fs.fixture; uid=fs.uid
 lock=fs.lock; absent=fs.absent; atomic=fs.atomic
class Simulated(m.Platform):
 def check(self,policy):
  time.sleep(.12)  # delay between real SIGCONT and listen, not accept widening
  mapping={'/runtime/node':Path(sys.executable).resolve(),'/app/index.js':root/'fresh/index.py',
   '/etc/classic.json':root/'fresh/settings.json',m.c.FRESH:root/m.c.FRESH.lstrip('/'),m.c.SELF:root/m.c.SELF.lstrip('/')}
  m.verify_files(policy,lambda name:mapping[name])
 def paths(self,policy): return [sys.executable,'-B',str(root/'fresh/index.py')],{'C3_SETTINGS':str(root/'fresh/settings.json'),'NODE_ENV':'production'},str(root/'fresh')
 def observe(self,policy,pid): return m.observe(pid,'127.0.0.1',int(sys.argv[3]))
listener=socket.socket(fileno=int(sys.argv[2]))
if listener.fileno()!=3:
 os.dup2(listener.fileno(),3); listener.close(); listener=socket.socket(fileno=3)
m.supervise(listener,Paused(bootstrap['files']),Simulated(),fault=sys.argv[4] or None)
'''
        child=subprocess.Popen([sys.executable,'-B','-c',code,str(outer.root),str(listener.fileno()),str(port),fault or ''],
                               cwd=HERE,pass_fds=(listener.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        listener.close()
        scope=None; held=None
        try:
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                got,status=os.waitpid(child.pid,os.WNOHANG|os.WUNTRACED)
                if got:
                    if not os.WIFSTOPPED(status): raise AssertionError(('preparer exited before SIGSTOP',status,child.stderr.read()))
                    break
                time.sleep(.005)
            else: raise AssertionError('preparer stop deadline expired')
            policy['inventory']['supervisor']={'pid':child.pid,'start':fresh.start(child.pid)}
            policy['inventory']['fdPins']={leaf.name:[(s:=leaf.stat()).st_dev,s.st_ino,stat.S_IFMT(s.st_mode)]
                                          for leaf in Path(f'/proc/{child.pid}/fd').iterdir()}
            outer.fs.atomic(fresh.POLICY,c.canonical(policy))
            class Simulated(fresh.Platform):
                def supervisor(self,p,pid):
                    fresh.need(p['inventory']['supervisor']=={'pid':pid,'start':fresh.start(pid)},'ACCEPTED_SUPERVISOR_REQUIRED')
                    fresh.verify_files(p,lambda name:mapping[name])
                    return p['inventory']['supervisor']
                def prepared(self,p,pid):
                    self.supervisor(p,pid)
                    fresh.need(p==outer.fs.read_json(fresh.POLICY),'SUPERVISOR_POLICY_DRIFT')
                    actual={leaf.name:[(s:=leaf.stat()).st_dev,s.st_ino,stat.S_IFMT(s.st_mode)] for leaf in Path(f'/proc/{pid}/fd').iterdir()}
                    fresh.need(actual==p['inventory']['fdPins'],'INDEPENDENT_FRESH_DESCRIPTOR_PINS_REQUIRED')
                def observe(self,p,pid): return fresh.observe(pid,'127.0.0.1',port)
            scope=c.Coordinator(outer.config,outer.fs,outer.spawn,origin=outer.origin).restore_scope()
            held=scope.__enter__()
            f=SimpleNamespace(outer=outer,fs=outer.fs,root=root,port=port,supervisor=child,
                              fixtures=outer.fixtures,held=held,platform=Simulated(),socket=str(sock),
                              proof=settlement_proof(outer,c))
            f.count=lambda:len((root/'executions').read_text().splitlines()) if (root/'executions').exists() else 0
            yield f
        finally:
            if scope is not None and held is not None:
                if held.handoff_completed: scope.__exit__(None,None,None)
                else: scope.__exit__(RuntimeError,RuntimeError('test-only retained disposal'),None)
            for path in root.glob('serving-*.json'):
                try: os.kill(json.loads(path.read_text())['pid'],signal.SIGTERM)
                except ProcessLookupError: pass
            if child.poll() is None: child.kill()
            out,err=child.communicate(timeout=3)
            if err and not fault: raise AssertionError(err.decode())


class PreparedControllerTests(unittest.TestCase):
    def test_controller_checks_current_policy_root_routes_identity_and_descriptors(self):
        from test_fresh_classic_launch import modeled_mounts
        for fault in ('', 'uid','gid','groups','cap','nnp','state','thread','fds','root','routes','policy',
                      'unit','source','namespace','group','files'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='pp-') as temp:
                base=Path(temp); proc=base/'proc/123'; proc.mkdir(parents=True)
                policy=PolicyBoundaryTests().policy()[1]; inv=policy['inventory']
                candidate=base/'candidate'; candidate.mkdir(); (proc/'root').symlink_to(candidate)
                for name in policy['files']:
                    file=candidate/name.lstrip('/'); file.parent.mkdir(parents=True,exist_ok=True); file.write_bytes(b'closure')
                    policy['files'][name]=fresh.digest(b'closure')
                if fault=='files': (candidate/'app/index.js').write_bytes(b'drift')
                inv['sourceSha256']=fresh.digest(b'coordinator')
                unit=b'Restart=no\nKillMode=process\n'; inv['unitSha256']=fresh.digest(unit)
                (proc/'ns').mkdir(); (base/'proc/1/ns').mkdir(parents=True)
                for ns in inv['namespaces']:
                    (proc/'ns'/ns).symlink_to(inv['namespaces'][ns] if fault!='namespace' else 'drift')
                    (base/'proc/1/ns'/ns).symlink_to(inv['hostNamespaces'][ns])
                (proc/'cgroup').write_text('0::'+fresh.CGROUP)
                group=base/'sys/fs/cgroup'/fresh.CGROUP.lstrip('/'); group.mkdir(parents=True)
                (group/'cgroup.procs').write_text('124' if fault=='group' else '123')
                (group/'cgroup.freeze').write_text('0')
                with fresh.retained_path_identity(proc/'root') as (info,mount_id):
                    inv['root']=[info.st_dev,info.st_ino]
                mounts=modeled_mounts(mount_id); (proc/'mountinfo').write_bytes(mounts)
                inv['mountinfoSha256']=fresh.digest(mounts)
                (proc/'net').mkdir(); (proc/'net/route').write_bytes(b'route'); (proc/'net/fib_trie').write_bytes(b'fib')
                inv['routesSha256']=fresh.digest(b'routefib')
                (proc/'task/123').mkdir(parents=True)
                status={'State':'T (stopped)','Uid':'65531 '*4,'Gid':'65531 '*4,'Groups':'',
                        **{k:'0' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')},'NoNewPrivs':'1'}
                if fault in ('uid','gid'): status['Uid' if fault=='uid' else 'Gid']='0 '*4
                if fault=='groups': status['Groups']='65531'
                if fault=='cap': status['CapBnd']='1'
                if fault=='nnp': status['NoNewPrivs']='0'
                if fault=='state': status['State']='S (sleeping)'
                if fault=='thread': (proc/'task/124').mkdir()
                (proc/'status').write_text(''.join(k+':'+v+'\n' for k,v in status.items()))
                (proc/'fd').mkdir()
                listener=socket.socket(socket.AF_UNIX); listener.bind(str(base/'s'))
                fds=[os.memfd_create('c3-supervisor-stdio') for _ in range(3)]
                try:
                    for i,fd in enumerate([*fds,listener.fileno()]): (proc/'fd'/str(i)).symlink_to(f'/proc/self/fd/{fd}')
                    inv['fdPins']={p.name:[(s:=p.stat()).st_dev,s.st_ino,stat.S_IFMT(s.st_mode)] for p in (proc/'fd').iterdir()}
                    if fault=='fds': inv['fdPins']['0'][1]+=1
                    if fault=='root': inv['root'][1]+=1
                    if fault=='routes': (proc/'net/route').write_bytes(b'drift')
                    policy_path=candidate/fresh.POLICY.lstrip('/'); policy_path.parent.mkdir(parents=True,exist_ok=True)
                    policy_path.write_bytes(c.canonical({} if fault=='policy' else policy))
                    real_path=fresh.Path; real_link=os.readlink
                    def path(value):
                        if value in ('/proc','/proc/1/ns','/sys/fs/cgroup'): return base/value.lstrip('/')
                        return real_path(value)
                    def link(value):
                        if value.parent == proc/'fd' and value.name in ('0','1','2'): return '/memfd:c3-supervisor-stdio (deleted)'
                        return real_link(value)
                    platform=fresh.Platform()
                    def read(name): return unit if name.endswith('.service') else (b'drift' if fault=='source' else b'coordinator')
                    loaded={'MainPID':'123','Restart':'always' if fault=='unit' else 'no','KillMode':'process',
                            'ControlGroup':fresh.CGROUP,'NeedDaemonReload':'no','RestartForceExitStatus':''}
                    result=SimpleNamespace(stdout=''.join(k+'='+v+'\n' for k,v in loaded.items()).encode())
                    with patch.object(fresh,'Path',side_effect=path), patch.object(fresh,'start',return_value='456'), \
                         patch.object(os,'readlink',side_effect=link), patch.object(c,'trusted_read',side_effect=read), \
                         patch.object(fresh.subprocess,'run',return_value=result):
                        if fault:
                            with self.assertRaises(c.Refusal): platform.prepared(policy,123)
                        else: platform.prepared(policy,123)
                finally:
                    listener.close()
                    for fd in fds: os.close(fd)


class PreparedProtocolTests(unittest.TestCase):
    def test_all_five_lost_holds_prevent_resume_commit_and_exec(self):
        for index in range(5):
            with self.subTest(index=index), prepared_fixture(fault='expected-refusal') as f:
                node=f.fixtures[index]
                node.put('/fixture-live.json',c.canonical({'held':False,'candidateFrozen':True}))
                launch=c.load_fresh(f.fs).FreshLaunch(f.held,f.platform,socket_path=f.socket)
                with patch.object(signal,'pidfd_send_signal',wraps=signal.pidfd_send_signal) as sent:
                    with self.assertRaises(c.Refusal): launch.run_prepared(f.proof)
                    self.assertEqual(sent.call_count,0)
                self.assertTrue(f.fs.absent(c.COMMIT)); self.assertEqual(f.count(),0)
                self.assertEqual(Path(f'/proc/{f.supervisor.pid}/stat').read_text().rsplit(')',1)[1].split()[0],'T')
                self.assertTrue(all(n.fs.read_json('/fixture-live.json')['candidateFrozen'] for n in f.fixtures))

    def test_loaded_source_pin_refuses_before_resume(self):
        with prepared_fixture(fault='expected-refusal') as f:
            module=c.load_fresh(f.fs)
            policy=f.fs.read_json(fresh.POLICY); policy['files'][c.FRESH]='f'*64
            f.fs.atomic(fresh.POLICY,c.canonical(policy))
            with patch.object(signal,'pidfd_send_signal',wraps=signal.pidfd_send_signal) as sent:
                with self.assertRaisesRegex(c.Refusal,'EXECUTED_FRESH_SOURCE_DRIFT'):
                    module.FreshLaunch(f.held,f.platform,socket_path=f.socket).run_prepared(f.proof)
                self.assertEqual(sent.call_count,0)
            self.assertTrue(f.fs.absent(c.COMMIT)); self.assertEqual(f.count(),0)

    def test_postcommit_eof_fsync_and_cleanup_never_resume_or_exec_twice(self):
        for fault in ('eof','fsync','cleanup'):
            with self.subTest(fault=fault), prepared_fixture(fault=fault) as f:
                if fault=='cleanup':
                    original=f.held.cleanup_channels
                    def cleanup(primary=None):
                        original(primary)
                        if primary is None: raise OSError('SIMULATED cleanup after actual close')
                    f.held.cleanup_channels=cleanup
                launch=c.load_fresh(f.fs).FreshLaunch(f.held,f.platform,socket_path=f.socket)
                with patch.object(signal,'pidfd_send_signal',wraps=signal.pidfd_send_signal) as sent:
                    with self.assertRaises(BaseException) as caught: launch.run_prepared(f.proof)
                    self.assertEqual(caught.exception.code,'COMMITTED_ACTIVATION_UNKNOWN')
                    self.assertEqual(sent.call_count,1); self.assertEqual(f.count(),1)
                    with self.assertRaisesRegex(c.Refusal,'REPLAY'): launch.run_prepared(f.proof)
                    self.assertEqual(sent.call_count,1)
                self.assertTrue(all(n.fs.read_json('/fixture-live.json')['candidateFrozen'] for n in f.fixtures))
                if fault=='cleanup': f.held.cleanup_channels=original


if __name__ == '__main__': unittest.main()
