"""Finite original-parent retention; real processes/pipes/pidfds/wait statuses."""
import os
import json
import fcntl
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import fresh_network as network
from test_fresh_network import plan


class CreatorTests(unittest.TestCase):
    def test_original_child_status_survives_until_public_operation_settles(self):
        # Import inside the test so the first RED names the missing producer.
        import fresh_network_invocation as creator
        p = plan(); p['deadline'] = int(time.time())+10
        p['ordinaryOwner'] = {'version':1,'stopConfigSha256':network.digest(network.encode(network.stopped_config(p)))}
        real_popen = subprocess.Popen
        child_code = "import sys; sys.stdin.buffer.readline(); print('holder-final',flush=True)"
        operator_code = "import time; time.sleep(.15); print('public-ack',flush=True)"
        def spawn(argv, **kwargs):
            self.assertIn(tuple(argv), (creator.HOLDER_ARGV, creator.SETTLEMENT_ARGV))
            code = child_code if tuple(argv) == creator.HOLDER_ARGV else operator_code
            return real_popen([sys.executable,'-I','-B','-c',code], **kwargs)
        with patch.object(network,'trusted_read',return_value=network.encode(p)), \
             patch.object(subprocess,'Popen',spawn):
            invocation = creator.Invocation(network)
            try:
                child = invocation.holder
                assert child is not None and invocation.pidfd is not None
                invocation.begin_handoff()
                invocation.start_settlement()
                self.assertTrue(select.select([invocation.pidfd],[],[],3)[0])
                self.assertIsNone(child.returncode)  # not poll()/wait() evidence
                fields = Path('/proc',str(child.pid),'stat').read_bytes().rsplit(b') ',1)[1].split()
                self.assertEqual(fields[0], b'Z')
                self.assertEqual(int(fields[1]), os.getpid())
                result = invocation.finish_settlement()
                self.assertEqual(result['settlementExit'], 0)
                self.assertEqual(result['holderExit'], 0)
                self.assertEqual(result['settlementStdout'], b'public-ack\n')
                self.assertEqual(result['holderStdout'], b'holder-final\n')
                self.assertRaises(ChildProcessError, os.waitpid, child.pid, os.WNOHANG)
            finally:
                invocation.close()

    def test_unknown_public_exit_is_not_a_retention_release(self):
        import fresh_network_invocation as creator
        p = plan(); p['deadline'] = int(time.time())+3
        p['ordinaryOwner'] = {'version':1,'stopConfigSha256':network.digest(network.encode(network.stopped_config(p)))}
        real_popen = subprocess.Popen
        def spawn(argv, **kwargs):
            code = 'import sys; sys.stdin.buffer.readline()' if tuple(argv)==creator.HOLDER_ARGV else 'raise SystemExit(75)'
            return real_popen([sys.executable,'-I','-B','-c',code],**kwargs)
        with patch.object(network,'trusted_read',return_value=network.encode(p)), patch.object(subprocess,'Popen',spawn):
            invocation=creator.Invocation(network)
            try:
                invocation.begin_handoff(); invocation.start_settlement()
                with self.assertRaisesRegex(network.Refusal,'PUBLIC_SETTLEMENT_UNKNOWN_RETAINED'):
                    invocation.finish_settlement()
                child=invocation.holder
                assert child is not None
                self.assertIsNone(child.returncode)
                self.assertEqual(Path('/proc',str(child.pid),'stat').read_bytes().rsplit(b') ',1)[1].split()[0],b'Z')
                with self.assertRaisesRegex(network.Refusal,'ONE_PUBLIC_SETTLEMENT_REQUIRED'): invocation.start_settlement()
                with self.assertRaisesRegex(network.Refusal,'ONE_PUBLIC_SETTLEMENT_REQUIRED'): invocation.finish_settlement()
                invocation.close()
                self.assertGreaterEqual(time.monotonic(),invocation.end)
                self.assertEqual(child.returncode,0)
                self.assertRaises(ChildProcessError,os.waitpid,child.pid,os.WNOHANG)
            finally: invocation.close()

    def test_first_pidfd_failure_reaps_registered_own_child(self):
        import fresh_network_invocation as creator
        p=plan(); p['ordinaryOwner']={'version':1,'stopConfigSha256':network.digest(network.encode(network.stopped_config(p)))}
        real_popen=subprocess.Popen; children=[]
        def spawn(argv,**kwargs):
            child=real_popen([sys.executable,'-I','-B','-c','import time; time.sleep(30)'],**kwargs)
            children.append(child); return child
        primary=OSError('actual pidfd pin refused')
        before=set(os.listdir('/proc/self/fd'))
        with patch.object(network,'trusted_read',return_value=network.encode(p)), \
             patch.object(subprocess,'Popen',spawn),patch.object(os,'pidfd_open',side_effect=primary):
            with self.assertRaises(OSError) as caught: creator.Invocation(network)
        self.assertIs(caught.exception,primary)
        self.assertEqual(len(children),1)
        self.assertIsNotNone(children[0].returncode)
        self.assertRaises(ChildProcessError,os.waitpid,children[0].pid,os.WNOHANG)
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_sigchld_autoreap_refused_before_child_creation(self):
        import fresh_network_invocation as creator
        before=signal.getsignal(signal.SIGCHLD)
        try:
            signal.signal(signal.SIGCHLD,signal.SIG_IGN)
            with patch.object(subprocess,'Popen') as spawn:
                with self.assertRaisesRegex(network.Refusal,'ORIGINAL_CHILD_REAPING_OWNER_REQUIRED'):
                    creator.Invocation(network)
                spawn.assert_not_called()
        finally: signal.signal(signal.SIGCHLD,before)

    def test_deadline_covers_popen_and_disposes_own_stubborn_child(self):
        import fresh_network_invocation as creator
        p=plan(); p['deadline']=int(time.time())+3
        p['ordinaryOwner']={'version':1,'stopConfigSha256':network.digest(network.encode(network.stopped_config(p)))}
        real_popen=subprocess.Popen; children=[]
        def spawn(argv,**kwargs):
            child=real_popen([sys.executable,'-I','-B','-c',
                'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print("ready",flush=True); time.sleep(30)'],**kwargs)
            children.append(child)
            assert child.stdout is not None
            self.assertEqual(child.stdout.readline(),b'ready\n')
            time.sleep(max(0,p['deadline']-time.time()+.02))
            return child
        start=time.monotonic()
        with patch.object(network,'trusted_read',return_value=network.encode(p)),patch.object(subprocess,'Popen',spawn):
            with self.assertRaisesRegex(network.Refusal,'FINITE_INVOCATION_EXPIRED'): creator.Invocation(network)
        self.assertLess(time.monotonic()-start,6)
        self.assertEqual(children[0].returncode,-signal.SIGKILL)
        self.assertRaises(ChildProcessError,os.waitpid,children[0].pid,os.WNOHANG)

    def test_invoked_operator_pipe_workflow_uses_only_fixed_roots(self):
        # Process/pipe entry control: modeled holder/operator bodies. The genuine
        # same-Coordinator public positive is in test_ordinary_owner_integration.
        env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}
        child=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'--invoker'],
                               stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        out,err=child.communicate(b'handoff\n',timeout=10)
        self.assertEqual(child.returncode,0,err.decode())
        lines=[json.loads(line) for line in out.splitlines()]
        self.assertEqual(lines[0]['accepted'],False)
        self.assertEqual(lines[1],{'phase':'prepared'})
        self.assertEqual(lines[2],{'holderFinal':True})
        self.assertEqual(lines[3],{'publicAck':True})

    def test_invoker_required_pipe_restore_failure_forwards_no_public_result(self):
        child=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'--invoker','pipe-restore'],
                               stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out,err=child.communicate(b'handoff\n',timeout=10)
        self.assertNotEqual(child.returncode,0)
        self.assertIn(b'invoker pipe restore failed after actual restore',err)
        lines=[json.loads(line) for line in out.splitlines()]
        self.assertEqual(len(lines),2)
        self.assertEqual(lines[-1],{'phase':'prepared'})

    def test_settlement_pin_failure_retains_holder_until_original_expiry(self):
        import fresh_network_invocation as creator
        p=plan(); p['deadline']=int(time.time())+3
        p['ordinaryOwner']={'version':1,'stopConfigSha256':network.digest(network.encode(network.stopped_config(p)))}
        real_popen=subprocess.Popen; real_pidfd=os.pidfd_open; children=[]
        def spawn(argv,**kwargs):
            code='import sys; sys.stdin.buffer.readline()' if tuple(argv)==creator.HOLDER_ARGV else 'import time; time.sleep(30)'
            child=real_popen([sys.executable,'-I','-B','-c',code],**kwargs); children.append(child); return child
        def pin(pid):
            if len(children)==2: raise OSError('settlement pin refused')
            return real_pidfd(pid)
        before=set(os.listdir('/proc/self/fd'))
        with patch.object(network,'trusted_read',return_value=network.encode(p)),patch.object(subprocess,'Popen',spawn), \
             patch.object(os,'pidfd_open',pin):
            invocation=creator.Invocation(network)
            try:
                invocation.begin_handoff()
                with self.assertRaisesRegex(OSError,'settlement pin refused'): invocation.start_settlement()
                self.assertIsNone(children[0].returncode)
            finally: invocation.close()
        self.assertGreaterEqual(time.monotonic(),invocation.end)
        for child in children:
            self.assertIsNotNone(child.returncode)
            self.assertRaises(ChildProcessError,os.waitpid,child.pid,os.WNOHANG)
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)


    def test_fixed_bootstrap_reads_checked_noatime_buffers_and_rejects_drift(self):
        import fresh_network_invocation as creator
        real_open=os.open; real_fstat=os.fstat; flags=[]
        fd=real_open(Path(__file__).with_name('fresh_network.py'),os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW)
        try: raw=os.read(fd,131073)
        finally: os.close(fd)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); installed=root/creator.NETWORK.lstrip('/')
            installed.parent.mkdir(parents=True,mode=0o700); installed.write_bytes(raw)
            installed.chmod(0o600)
            for parent in installed.parents:
                if parent == root.parent: break
                parent.chmod(0o700)
            def opened(path,bits,*args,**kwargs):
                flags.append(bits)
                return real_open(root if path=='/' else path,bits,*args,**kwargs)
            def root_stat(fd):
                value=real_fstat(fd)
                class Root:
                    def __getattr__(self,key): return 0 if key in ('st_uid','st_gid') else getattr(value,key)
                return Root()
            with patch.object(os,'open',opened),patch.object(os,'fstat',root_stat):
                self.assertTrue(callable(creator.load_network().validate_plan))
                installed.write_bytes(raw+b'\n')
                with self.assertRaisesRegex(RuntimeError,'INSTALLED_SOURCE_PIN_REQUIRED'): creator.load_network()
            required=os.O_NOATIME|os.O_NOFOLLOW|os.O_CLOEXEC
            self.assertTrue(flags)
            self.assertTrue(all(bits & required == required for bits in flags))


def invoked_fixture(fault=None):
    import fresh_network_invocation as creator
    p=plan(); p['deadline']=int(time.time())+10
    p['ordinaryOwner']={'version':1,'stopConfigSha256':network.digest(network.encode(network.stopped_config(p)))}
    real_popen=subprocess.Popen
    holder='''import os,json,sys
start=open('/proc/self/stat').read().rsplit(') ',1)[1].split()[19]
print(json.dumps({'holder':{'pid':os.getpid(),'start':start},'deadline':DEADLINE,'accepted':False,'physicalAccepted':False,'operationalGO':False}),flush=True)
print(json.dumps({'phase':'prepared'}),flush=True)
assert sys.stdin.buffer.readline()==b'handoff\\n'
print(json.dumps({'holderFinal':True}),flush=True)
'''.replace('DEADLINE',str(p['deadline']))
    def spawn(argv,**kwargs):
        assert tuple(argv) in (creator.HOLDER_ARGV,creator.SETTLEMENT_ARGV)
        code=holder if tuple(argv)==creator.HOLDER_ARGV else 'print(\'{"publicAck":true}\',flush=True)'
        return real_popen([sys.executable,'-I','-B','-c',code],**kwargs)
    # Only root pipe ownership metadata is modeled; FIFO/inode/access remain real.
    real_fstat=os.fstat
    real_fcntl=fcntl.fcntl
    def root_stat(fd):
        value=real_fstat(fd)
        class Root:
            def __getattr__(self,key): return 0 if key in ('st_uid','st_gid') else getattr(value,key)
        return Root()
    def flags(fd,op,*args):
        result=real_fcntl(fd,op,*args)
        if fault=='pipe-restore' and fd==0 and op==fcntl.F_SETFL:
            raise OSError('invoker pipe restore failed after actual restore')
        return result
    with patch.object(network,'trusted_read',return_value=network.encode(p)),patch.object(subprocess,'Popen',spawn), \
         patch.object(os,'fstat',root_stat),patch.object(fcntl,'fcntl',flags):
        creator.run(network)


if __name__ == '__main__':
    if sys.argv[1:2]==['--invoker']: invoked_fixture(sys.argv[2] if len(sys.argv)==3 else None)
    else: unittest.main()
