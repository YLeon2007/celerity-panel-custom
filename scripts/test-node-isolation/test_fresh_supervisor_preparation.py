"""Real SIGSTOP/SIGCONT + flock tests; installed/root authority NOT simulated as GO."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent


def load():
    spec=importlib.util.spec_from_file_location('fresh_classic_launch',HERE/'fresh_classic_launch.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


class PreparationTests(unittest.TestCase):
    def spawn_paused(self, root):
        code='''import fcntl,json,os,sys
from pathlib import Path
import fresh_classic_launch as m
root=Path(sys.argv[1])
# Only trusted ownership/path reading is modeled; stop, file IO and flock are real.
m.c.trusted_read=lambda name:(root/'policy.json').read_bytes()
with (root/'lock').open('a+b') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 pins={m.c.SELF:'a'*64,m.c.FRESH:'b'*64}
 fs=m.PreparationSupervisorFiles(pins)
 value=fs.read_json(m.POLICY)
 try: fs.read_json(m.POLICY)
 except RuntimeError as error: replay=str(error)
 else: raise RuntimeError('second preparation unexpectedly allowed')
 (root/'after.json').write_text(json.dumps({'value':value,'replay':replay}))
'''
        p=subprocess.Popen([sys.executable,'-B','-c',code,str(root)],cwd=HERE,env={'PATH':'/usr/bin:/bin'},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            got,status=os.waitpid(p.pid,os.WUNTRACED|os.WNOHANG)
            if got:
                if os.WIFSTOPPED(status):
                    self.assertEqual(os.WSTOPSIG(status),signal.SIGSTOP);return p
                raise AssertionError(('child failed before pause',status,p.stderr.read().decode()))
            time.sleep(.01)
        p.kill();p.wait();raise AssertionError('bounded test wait for real preparation stop failed')

    def test_pauses_under_lock_before_policy_read_and_reads_final_bytes_after_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'policy.json').write_text('{"phase":"draft"}')
            p=self.spawn_paused(root)
            try:
                self.assertFalse((root/'after.json').exists())
                self.assertIn('T',Path(f'/proc/{p.pid}/status').read_text().split('State:')[1].splitlines()[0])
                with (root/'lock').open('r+b') as lock:
                    with self.assertRaises(BlockingIOError):fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                m=load();final={'phase':'final-candidate-not-accepted','files':{m.c.SELF:'a'*64,m.c.FRESH:'b'*64}}
                (root/'policy.json').write_text(json.dumps(final))
                os.kill(p.pid,signal.SIGCONT);out,err=p.communicate(timeout=5)
                self.assertEqual(p.returncode,0,err.decode())
                result=json.loads((root/'after.json').read_text())
                self.assertEqual(result['value'],final)
                self.assertEqual(result['replay'],'FRESH_PREPARATION_REPLAY_FORBIDDEN')
            finally:
                if p.poll() is None:p.kill();p.wait()
                p.stdout.close();p.stderr.close()

    def test_abandoned_preparation_never_reads_policy_or_launches(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'policy.json').write_text('not read before stop')
            p=self.spawn_paused(root)
            try:
                p.kill();p.communicate(timeout=5)
                self.assertEqual(p.returncode,-signal.SIGKILL)
                self.assertFalse((root/'after.json').exists())
            finally:
                if p.poll() is None:p.kill();p.wait()
                p.stdout.close();p.stderr.close()

    def test_ordinary_reader_does_not_pause_and_wrong_preparation_path_refuses_before_effect(self):
        m=load()
        with mock.patch.object(m.os,'kill',side_effect=AssertionError('unexpected signal')):
            with mock.patch.object(m.c,'trusted_read',return_value=b'{"ordinary":true}'):
                self.assertEqual(m.SupervisorFiles().read_json(m.POLICY),{'ordinary':True})
            with self.assertRaisesRegex(RuntimeError,'FIXED_SUPERVISOR_POLICY_ONLY'):
                m.PreparationSupervisorFiles({m.c.SELF:'a'*64,m.c.FRESH:'b'*64}).read_json('/arbitrary')

    def test_changed_bootstrap_source_pins_after_pause_refuse_without_return(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'policy.json').write_text('{"draft":true}')
            p=self.spawn_paused(root)
            try:
                m=load();(root/'policy.json').write_text(json.dumps({'files':{m.c.SELF:'c'*64,m.c.FRESH:'b'*64}}))
                os.kill(p.pid,signal.SIGCONT);out,err=p.communicate(timeout=5)
                self.assertNotEqual(p.returncode,0)
                self.assertIn(b'FRESH_PREPARATION_SOURCE_DRIFT',err)
                self.assertFalse((root/'after.json').exists())
            finally:
                if p.poll() is None:p.kill();p.wait()
                p.stdout.close();p.stderr.close()

    def test_fixed_entry_refuses_arguments_and_does_not_accept_unprivileged_bootstrap(self):
        path=HERE/'prepare_fresh_supervisor.py'
        self.assertTrue(path.is_file())
        for args in (['arbitrary'],[]):
            p=subprocess.run([sys.executable,'-I','-B',str(path),*args],cwd=HERE,env={},capture_output=True,timeout=5)
            self.assertEqual(p.returncode,75)
            self.assertEqual(p.stdout,b'')
            self.assertEqual(p.stderr,b'FRESH_PREPARATION_REFUSED\n')


if __name__=='__main__':unittest.main()
