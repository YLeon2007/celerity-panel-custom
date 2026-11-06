"""B132 published return; real consumers/holds, explicitly modeled kernel/HTTP.

Measured sockets are projected below; synthetic proc files are NOT physical
proof. Live B132 /classic-ready returned404, not the modeled200 READY positive.
"""
import contextlib
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import test_fresh_network as legacy
from test_fresh_network_host_layout import host_plan

m = legacy.m
# Projection of strict read-only B132 tuple capture, not invented live output:
# proxy582004/start10493593; backend581974/start10493548; client127.0.0.1:45524.
# TCP6 v4-mapped peer words are Linux's measured per-word little-endian encoding.
LISTENER = ('0100007F:0BB8', '00000000:0000', '0A', '1882662')
INBOUND = ('0100007F:0BB8', '0100007F:B1D4', '01', '2120007')
OUTBOUND = ('010013AC:9AEA', '050013AC:0BB8', '01', '2120009')
BACKEND_LISTENER = ('00000000000000000000000000000000:0BB8',
                    '00000000000000000000000000000000:0000', '0A', '1883585')
BACKEND_TUPLE = ('0000000000000000FFFF0000050013AC:0BB8',
                 '0000000000000000FFFF0000010013AC:9AEA', '01', '2120010')


class TupleModel:
    """Real parser/FD-symlink logic over synthetic proc; HTTP deliberately modeled."""
    def __init__(self, root, backend=581974, proxy=582004, starts=None, fault=None):
        self.root = Path(root); self.backend=backend; self.proxy=proxy; self.fault=fault
        self.starts=starts or {backend:'10493548',proxy:'10493593'}
        self.published={'pid':proxy,'start':self.starts[proxy], 'listenerInode':LISTENER[3],
                        'executableSha256':'a'*64}
        self.closed=False; self.during=False; self.calls=0
        self.emit(False)

    def emit(self,during):
        self.during=during
        prows: list[tuple[str,str,str,str]]=[LISTENER]
        brows: list[tuple[str,str,str,str]]=[BACKEND_LISTENER]
        powned=[LISTENER[3]]; bowned=[BACKEND_LISTENER[3]]
        if during:
            prows += [INBOUND,OUTBOUND]; brows += [BACKEND_TUPLE]
            powned += [INBOUND[3],OUTBOUND[3]]; bowned += [BACKEND_TUPLE[3]]
        if self.fault == 'preexisting': powned += [OUTBOUND[3]]
        if during and self.fault == 'foreign-backend': bowned.remove(BACKEND_TUPLE[3])
        if during and self.fault == 'foreign-proxy': powned.remove(INBOUND[3])
        if during and self.fault == 'wrong-port':
            prows[-1]=(OUTBOUND[0],'050013AC:0BB9',OUTBOUND[2],OUTBOUND[3])
        if during and self.fault == 'wrong-peer':
            brows[-1]=(BACKEND_TUPLE[0],BACKEND_TUPLE[1].replace('9AEA','9AEB'),'01',BACKEND_TUPLE[3])
        if during and self.fault == 'ambiguous':
            prows.append(('010013AC:9AEC','050013AC:0BB8','01','99999'));powned.append('99999')
        if self.fault == 'listener': powned.remove(LISTENER[3])
        for pid,rows,owned in ((self.proxy,prows,powned),(self.backend,brows,bowned)):
            p=self.root/str(pid);(p/'net').mkdir(parents=True,exist_ok=True);(p/'fd').mkdir(exist_ok=True)
            for f in (p/'fd').iterdir(): f.unlink()
            for i,inode in enumerate(owned): (p/'fd'/str(i)).symlink_to('socket:['+inode+']')
            for table,n in (('tcp',13),('tcp6',37)):
                text='sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n'
                for i,(a,b,state,inode) in enumerate(rows):
                    if len(a) == n:
                        text += f'{i}: {a} {b} {state} 0:0 0:0 0 0 0 {inode}\n'
                (p/'net'/table).write_text(text)

    def path(self,*args):
        p=Path(*args)
        # Only socket rows/FDs are modeled; PID/nsfd lifetime remains real.
        parts=p.parts
        if len(parts)>3 and parts[1]=='proc' and parts[2] in (str(self.backend),str(self.proxy)) and parts[3] in ('net','fd'):
            return self.root.joinpath(*parts[2:])
        return p

    def connection(self,*args,**kwargs):
        assert args == ('127.0.0.1',3000), args
        model=self
        class Conn:
            sock=None
            def request(self,method,path,headers):
                assert (method,path,headers)==('GET','/classic-ready',{'Connection':'keep-alive'})
                model.calls+=1; model.emit(True); self.sock=self
            def getresponse(self): return self
            @property
            def status(self): return 404 if model.fault=='actual404' else 200
            def read(self,limit):
                return b'Not Found' if model.fault=='actual404' else m.READY
            def getsockname(self): return ('127.0.0.1',45524)
            def close(self): model.closed=True; model.emit(False)
        return Conn()

    @contextlib.contextmanager
    def context(self, starts=True):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(m,'Path',side_effect=self.path))
            stack.enter_context(patch.object(m.http.client,'HTTPConnection',side_effect=self.connection))
            if starts: stack.enter_context(patch.object(m,'proc_start',side_effect=lambda p:self.starts[p]))
            yield self

    def probe(self):
        return m.bound_published_probe(self.backend,self.starts[self.backend],'172.19.0.5',self.published)


class PublishedReturnTests(unittest.TestCase):
    def fixture(self, root):
        # Real local retained PID/nsfds; separately simulated Docker/host metadata.
        cls=next(c for c in vars(legacy).values() if isinstance(c,type) and 'return_fixture' in c.__dict__)
        helper=cls();self.addCleanup(helper.doCleanups)
        c,k,raw,container,writes=helper.return_fixture(root)
        p=host_plan();k.p=c.p=p;p['hostNetns']=[4,4026539999]
        value=m.decode(raw[0]);value['address']='172.19.0.5'
        container['NetworkSettings']['Networks']['old']['IPAddress']=value['address']
        binding=[{'HostIp':'127.0.0.1','HostPort':'3000'}]
        container['HostConfig']={'PortBindings':{'3000/tcp':copy.deepcopy(binding)}}
        container['NetworkSettings']['Ports']={'3000/tcp':copy.deepcopy(binding)}
        projection={'id':container['Id'],'pid':os.getpid(),'start':m.proc_start(os.getpid()),
            'netns':m.identity('/proc/self/ns/net'),'image':container['Image'],'restartCount':0,
            'networks':container['NetworkSettings']['Networks']}
        value['inspectSha256']=m.digest(m.encode(projection))
        value['published']={'pid':os.getpid(),'start':m.proc_start(os.getpid()),'executableSha256':'a'*64,
                            'listenerInode':LISTENER[3]}
        raw[0]=m.encode(value);k.current=p['newConfig']
        def config(v=None):
            if v is not None: writes.append(v);k.current=v
            return k.current
        k.config=config
        return c,k,raw,container,writes

    def test_host_return_consumer_holds_published_proxy_before_and_after_restore(self):
        with tempfile.TemporaryDirectory() as d:
            c,k,raw,container,writes=self.fixture(d);witnessed=[]
            def proof(*args):
                self.assertEqual(len(k.target_hold['processes']),3)
                for x in k.target_hold['processes']: os.fstat(x['pidfd']);os.fstat(x['nsfd'])
                witnessed.append(len(writes));return {'modeledHTTPAndKernel':True}
            with patch.object(m,'trusted_read',side_effect=lambda p:raw[0]), \
                 patch.object(m,'request',return_value=m.encode(container)), \
                 patch.object(m,'in_namespace',side_effect=lambda fd,fn:fn()), \
                 patch.object(m.Linux,'check_published_proxy',create=True), \
                 patch.object(m,'bound_published_probe',side_effect=proof,create=True), \
                 patch.object(m,'docker_backend_addresses') as dns:
                result=c.command({'generation':c.p['generation'],'sequence':1,'operation':'return'})
            self.assertEqual(result['phase'],'returned');self.assertEqual(writes,[c.p['oldConfig']])
            self.assertIn(0,witnessed);self.assertIn(1,witnessed)
            self.assertIsNone(k.target_hold);dns.assert_not_called()

    def test_real_return_consumer_uses_measured_tuple_parser_not_probe_stub(self):
        with tempfile.TemporaryDirectory() as d:
            c,k,raw,container,writes=self.fixture(d)
            children=[]
            try:
                for _ in range(2): children.append(subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(20)']))
                backend,proxy=(p.pid for p in children);starts={p.pid:m.proc_start(p.pid) for p in children}
                model=TupleModel(Path(d)/'proc',backend,proxy,starts)
                value=m.decode(raw[0]);value['serving']={'pid':backend,'start':starts[backend]}
                value['published']=model.published;container['State']['Pid']=backend
                projection={'id':container['Id'],'pid':backend,'start':starts[backend],
                    'netns':m.identity('/proc/'+str(backend)+'/ns/net'),'image':container['Image'],
                    'restartCount':0,'networks':container['NetworkSettings']['Networks']}
                value['inspectSha256']=m.digest(m.encode(projection));raw[0]=m.encode(value)
                with model.context(starts=False), \
                     patch.object(m,'trusted_read',side_effect=lambda p:raw[0]), \
                     patch.object(m,'request',return_value=m.encode(container)), \
                     patch.object(m,'in_namespace',side_effect=lambda fd,fn:fn()), \
                     patch.object(m.Linux,'check_published_proxy') as identity:
                    result=c.command({'generation':c.p['generation'],'sequence':1,'operation':'return'})
                self.assertEqual(result['phase'],'returned');self.assertGreater(model.calls,2)
                self.assertGreater(identity.call_count,2);self.assertEqual(len(writes),1)
            finally:
                k.close_holds()
                for child in children:
                    if child.poll() is None: child.terminate()
                    child.wait(timeout=3)

    def test_captured_dualstack_tuple_projection_green_with_modeled_ready_http(self):
        with tempfile.TemporaryDirectory() as d:
            model=TupleModel(d)
            with model.context():
                result=model.probe()
            self.assertEqual(result,{'pid':581974,'start':'10493548','bodySha256':m.digest(m.READY)})
            self.assertTrue(model.closed)

    def test_same_body_missing_foreign_wrong_or_ambiguous_socket_path_refuses(self):
        for fault in ('listener','preexisting','foreign-backend','foreign-proxy','wrong-port','wrong-peer','ambiguous','actual404'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                model=TupleModel(d,fault=fault)
                with model.context(),self.assertRaises(m.Refusal): model.probe()
                self.assertTrue(model.closed or model.calls==0)

    def test_pid_reuse_and_socket_loss_before_confirmation_refuse(self):
        for fault in ('pid','socket'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                model=TupleModel(d);calls=[0];original=m.tcp_sockets
                def rows(pid):
                    result=original(pid)
                    if model.during and pid==model.backend:
                        calls[0]+=1
                        if calls[0]==2:
                            if fault=='socket': return set()
                            model.starts[model.proxy]='1'
                    return result
                with model.context(),patch.object(m,'tcp_sockets',side_effect=rows),self.assertRaises(m.Refusal):model.probe()
                self.assertTrue(model.closed)

    def test_host_binding_missing_wrong_port_and_foreign_container_refuse_before_write(self):
        for fault in ('missing','host-port','container-port','container','socket-pin'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                c,k,raw,container,writes=self.fixture(d)
                if fault=='missing':
                    value=m.decode(raw[0]);del value['published'];raw[0]=m.encode(value)
                if fault=='host-port':container['HostConfig']['PortBindings']['3000/tcp'][0]['HostPort']='3001'
                if fault=='container-port':container['NetworkSettings']['Ports']={'3001/tcp':[{'HostIp':'127.0.0.1','HostPort':'3000'}]}
                if fault=='container':container['RestartCount']+=1
                if fault=='socket-pin':
                    value=m.decode(raw[0]);value['published']['listenerInode']=True;raw[0]=m.encode(value)
                with patch.object(m,'trusted_read',side_effect=lambda p:raw[0]),patch.object(m,'request',return_value=m.encode(container)), \
                     patch.object(m,'docker_backend_addresses') as dns,patch.object(m,'bound_published_probe') as probe:
                    with self.assertRaises(m.Refusal):c.command({'generation':c.p['generation'],'sequence':1,'operation':'return'})
                self.assertEqual(writes,[]);probe.assert_not_called();dns.assert_not_called()
                self.assertEqual(c.phase,'unknown-retained')

    def test_published_proof_drift_at_every_restore_boundary_is_sticky(self):
        for timing in ('prewrite','write','readback','public','observation'):
            with self.subTest(timing=timing),tempfile.TemporaryDirectory() as d:
                c,k,raw,container,writes=self.fixture(d);drift=[False]
                original_probe=k.return_probe;original_config=k.config
                def probe():
                    result=original_probe()
                    if timing=='prewrite':drift[0]=True
                    return result
                def config(value=None):
                    result=original_config(value)
                    if timing=='write' and value is not None:drift[0]=True
                    if timing=='readback' and value is None and writes:drift[0]=True
                    return result
                k.return_probe=probe;k.config=config
                if timing=='public':k.public_probe=lambda:drift.__setitem__(0,True)
                if timing=='observation':k.observation=lambda:drift.__setitem__(0,True)
                def held(*args):m.need(not drift[0],'RETURN_PUBLISHED_PROXY_IDENTITY_DRIFT')
                with patch.object(m,'trusted_read',side_effect=lambda p:raw[0]),patch.object(m,'request',return_value=m.encode(container)), \
                     patch.object(m,'in_namespace',side_effect=lambda fd,fn:fn()), \
                     patch.object(m.Linux,'check_published_proxy',side_effect=held),patch.object(m,'bound_published_probe',return_value={}):
                    with self.assertRaises(m.Refusal):c.command({'generation':c.p['generation'],'sequence':1,'operation':'return'})
                    drift[0]=False
                    with self.assertRaises(m.Refusal):c.command({'generation':c.p['generation'],'sequence':2,'operation':'observe'})
                self.assertEqual(len(writes),0 if timing=='prewrite' else 1)
                self.assertEqual(c.phase,'unknown-retained');self.assertIsNotNone(k.target_hold)
                records=[m.decode(p.read_bytes()) for p in sorted(c.j.path.iterdir())]
                self.assertFalse(any(r['kind']=='public-return-confirmed' for r in records))
                k.close_holds()


    def test_exact_proxy_argv_executable_namespace_principal_and_hash_are_required(self):
        for fault in (None,'argv','exe','hash','namespace','principal','cgroup','start','mode'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                root=Path(d);proc=root/'proxy';proc.mkdir();binary=root/'docker-proxy'
                binary.write_bytes(b'nonexecuted test executable; not the physical Docker binary')
                binary.chmod(0o755)
                argv=['/usr/bin/docker-proxy','-proto','tcp','-host-ip','127.0.0.1','-host-port','3000',
                      '-container-ip','172.19.0.5','-container-port','3000','-use-listen-fd']
                if fault=='argv':argv[8]='172.19.0.9'
                (proc/'cmdline').write_bytes(b'\0'.join(x.encode() for x in argv)+b'\0')
                (proc/'status').write_text('Uid:\t0\t0\t0\t0\n' if fault!='principal' else 'Uid:\t1\t1\t1\t1\n')
                (proc/'cgroup').write_text('0::/system.slice/docker.service\n' if fault!='cgroup' else '0::/foreign\n')
                if fault=='mode':binary.chmod(0o777)
                s=binary.stat();ns=[4,4026531840]
                k=m.Linux.__new__(m.Linux);k.p=host_plan()
                value={'address':'172.19.0.5','published':{'pid':582004,'start':'10493593',
                    'executableSha256':m.digest(binary.read_bytes()) if fault!='hash' else 'f'*64}}
                fds=[]
                def open_binary(path):
                    self.assertEqual(path,'/usr/bin/docker-proxy')
                    fd=os.open(binary,os.O_RDONLY);fds.append(fd);return fd
                def path(*args):
                    p=Path(*args)
                    if str(p).startswith('/proc/582004'):
                        return proc.joinpath(*p.parts[3:])
                    return p
                def identity(path):
                    if path.endswith('/ns/net'):return [4,99] if fault=='namespace' else ns
                    return [s.st_dev,s.st_ino+(1 if fault=='exe' else 0)]
                with patch.object(m,'Path',side_effect=path),patch.object(m,'identity',side_effect=identity), \
                     patch.object(m,'proc_start',return_value='1' if fault=='start' else '10493593'), \
                     patch.object(m,'trusted_fd',side_effect=open_binary):
                    if fault is None:k.check_published_proxy(value)
                    else:
                        with self.assertRaises(m.Refusal):k.check_published_proxy(value)
                for fd in fds:
                    with self.assertRaises(OSError):os.fstat(fd)


if __name__ == '__main__':unittest.main()
