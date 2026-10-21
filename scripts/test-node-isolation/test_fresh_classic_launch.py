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
            self.assertEqual(m.http_probe('127.0.0.1', f.port), b'fresh-classic-fixture')
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
def launch_fixture(m, fault=None):
    """Disposable Node source/settings, no credentials or physical operations."""
    import types
    import test_coordinated_restore as ct
    import coordinated_restore as c
    with ct.cfixture(c) as outer:
        root = outer.root/'fresh'
        root.mkdir()
        (outer.root/'state').mkdir(mode=0o700)
        (outer.root/'state/launch.lock').write_bytes(b'')
        (outer.root/'state/launch.lock').chmod(0o600)
        probe = socket.socket(); probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]; probe.close()
        source = root/'index.js'
        source.write_text("const fs=require('fs'),http=require('http'); const s=JSON.parse(fs.readFileSync(process.env.C3_SETTINGS)); fs.appendFileSync(s.count,'exec\\n'); http.createServer((q,r)=>r.end('fresh-classic-fixture')).listen(s.port,'127.0.0.1');\n")
        settings = root/'settings.json'; settings.write_text(json.dumps({'port':port, 'count':str(root/'executions')}))
        policy = {'version':1, 'context':'test.infograd.online', 'executable':'/runtime/node',
                  'source':'/app/index.js', 'settings':'/etc/classic.json',
                  'files':{'/runtime/node':m.digest(Path(shutil.which('node')).read_bytes()),
                           '/app/index.js':m.digest(source.read_bytes()), '/etc/classic.json':m.digest(settings.read_bytes())},
                  'environment':{'C3_SETTINGS':'/etc/classic.json', 'NODE_ENV':'production'},
                  'uid':65531, 'gid':65531, 'cgroup':'/system.slice/c3-test-fresh-classic.service',
                  'ingress':{'ip':'212.119.42.100', 'port':3000, 'path':'/health', 'bodySha256':m.digest(b'fresh-classic-fixture')},
                  'inventory':{'explicitly':'SIMULATED kernel/root/resource inventory'}}
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
 def check(self,policy):
  m.verify_files(policy,lambda name: sys.argv[3] if name=='/runtime/node' else root/'fresh'/('index.js' if name=='/app/index.js' else 'settings.json'))
 def paths(self,policy):
  base=root/'fresh'
  return [sys.argv[3],str(base/'index.js')],{'C3_SETTINGS':str(base/'settings.json'),'NODE_ENV':'production'},str(base)
 def observe(self,policy,pid): return m.observe(pid,'127.0.0.1',int(sys.argv[4]))
listener=socket.socket(fileno=int(sys.argv[2]))
m.supervise(listener,fs,Simulated(),fault=sys.argv[5] or None)
'''
        supervisor = subprocess.Popen([sys.executable,'-B','-c',code,str(outer.root),str(listener.fileno()),shutil.which('node'),str(port),fault or ''],
            cwd=HERE, pass_fds=(listener.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        listener.close()
        class Simulated(m.Platform):
            def check(self, policy):
                m.verify_files(policy,lambda name: shutil.which('node') if name=='/runtime/node' else root/('index.js' if name=='/app/index.js' else 'settings.json'))
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


if __name__ == '__main__': unittest.main()
