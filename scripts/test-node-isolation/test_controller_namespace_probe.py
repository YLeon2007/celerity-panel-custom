"""Controller probe SOURCE tests. nsfs/CAP/setns/topology explicitly MODELED.

Real fork/pipe/FD disposal, same-held Coordinator, stopped supervisor, UDS,
SCM_RIGHTS, HTTP keepalive and /proc socket ownership; no privileged calls.
"""
import contextlib
import json
import os
from pathlib import Path
import signal
import time
import unittest
from unittest.mock import patch

import fresh_classic_launch as fresh
import coordinated_restore as c
import node_originals


def install_modeled_namespace(m, fs, policy, pid):
    """Independent fixture publication BEFORE launch; ordinary inode, NOT nsfs."""
    root=fs.fixture.root
    net=root/m.NETNS.lstrip('/'); net.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    net.write_bytes(b'MODELED accepted namespace'); net.chmod(0o400)
    info=net.stat()
    policy['inventory']['supervisor']={'pid':pid,'start':m.start(pid)}
    policy['inventory']['namespaces']['net']=f'net:[{info.st_ino}]'
    policy['inventory']['hostNamespaces']['net']='MODELED-host-net'
    plan={'version':1,'context':'test.infograd.online','files':policy['files'],
          'networkNamespace':{'device':info.st_dev,'inode':info.st_ino}}
    path=root/m.RESOURCE_PLAN.lstrip('/'); path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    for leaf in (net.parent,path.parent):
        for parent in (leaf,*leaf.parents):
            if parent == root.parent: break
            parent.chmod(0o700)
    fs.atomic(m.RESOURCE_PLAN,c.canonical(plan),new=True)
    fs.atomic(m.POLICY,c.canonical(policy))


def modeled_namespace(m, fs, policy, port):
    """Model ONLY namespace/CAP/cgroup facts; fork/proc/HTTP proof remains real."""
    root=fs.fixture.root/'fresh'; parent=os.getpid()
    class Modeled(m._ControllerNamespace):
        def record(self,event,**kw):
            with (root/'probe.jsonl').open('a') as out:
                out.write(json.dumps({'event':event,'pid':os.getpid(),**kw})+'\n')
        def _host(self): pass  # UID, host PID/mount view explicitly MODELED
        def _host_net(self): return 'MODELED-host-net'
        def _type(self): return m._NEWNET  # ordinary scratch FD, NOT nsfs
        def _net(self,pid):
            if pid == 1: return (-1,-1)
            return self.identity  # modeled target/supervisor/serving membership
        def _join(self): self.record('join')  # NO setns syscall
        def _serving_group(self): return Path('/proc/self/cgroup').read_text().strip()
        def _observe(self,pid):
            self.record('tcp')
            return m.observe(pid,'127.0.0.1',port)
    return Modeled(fs,policy)


class ControllerNamespaceTests(unittest.TestCase):
    def test_C1_actual_prepared_caller_joins_before_new_tcp_in_probe_only_child(self):
        self.assertTrue(callable(getattr(fresh.Platform, 'controller_namespace', None)),
                        'actual controller has no retained accepted-netns probe boundary')
        from test_prepared_resume import prepared_fixture
        with prepared_fixture() as f:
            parent=os.getpid(); origin=dict(f.held.origin)
            peers=[(x.process.pid,x.hello['start']) for x in f.held.nodes]
            module=c.load_fresh(f.fs)
            result=module.FreshLaunch(f.held,f.platform,socket_path=f.socket).run_prepared(f.proof)
            events=[json.loads(x) for x in (f.root/'probe.jsonl').read_text().splitlines()]
            joined=next(x for x in events if x['event']=='join')
            tcp=next(x for x in events if x['event']=='tcp')
            self.assertNotEqual(joined['pid'],parent)
            self.assertEqual(joined['pid'],tcp['pid'])
            self.assertLess(events.index(joined),events.index(tcp))
            self.assertFalse(Path('/proc',str(joined['pid'])).exists(), 'probe not reaped')
            self.assertEqual(f.held.origin,origin)
            commit=f.fs.read_json(c.COMMIT)
            self.assertEqual(commit['restoreIntent']['origin']['pid'],parent)
            self.assertEqual(set((x['pid'],x['start']) for x in commit['nodePeers'].values()),set(peers))
            self.assertEqual(result['code'],'COMMITTED_FRESH_ACTIVATION_CONFIRMED')
            self.assertEqual(f.count(),1)


    def test_C2_untrusted_accepted_nsfs_refuses_before_resume(self):
        from test_prepared_resume import prepared_fixture
        with prepared_fixture(fault='expected-refusal') as f:
            (f.outer.root/fresh.NETNS.lstrip('/')).chmod(0o666)
            module=c.load_fresh(f.fs)
            with patch.object(signal,'pidfd_send_signal',wraps=signal.pidfd_send_signal) as sent:
                with self.assertRaises(c.Refusal):
                    module.FreshLaunch(f.held,f.platform,socket_path=f.socket).run_prepared(f.proof)
                self.assertEqual(sent.call_count,0)
            self.assertTrue(f.fs.absent(c.COMMIT)); self.assertEqual(f.count(),0)


    def test_C3_child_revalidates_root_host_view_before_join_or_tcp(self):
        from test_prepared_resume import prepared_fixture
        with prepared_fixture(fault='expected-refusal') as f:
            parent=os.getpid(); original=f.platform.controller_namespace
            def target(fs,p):
                t=original(fs,p)
                def host():
                    fresh.need(os.getpid() == parent,'MODELED_CHILD_ROOT_OR_HOST_VIEW_LOST')
                t._host=host
                return t
            f.platform.controller_namespace=target
            with self.assertRaises(c.Refusal) as caught:
                c.load_fresh(f.fs).FreshLaunch(f.held,f.platform,socket_path=f.socket).run_prepared(f.proof)
            self.assertEqual(caught.exception.code,'COMMITTED_ACTIVATION_UNKNOWN')
            events=(f.root/'probe.jsonl').read_text() if (f.root/'probe.jsonl').exists() else ''
            self.assertNotIn('tcp',events)
            self.assertEqual(f.count(),1)


    def test_C4_parent_rechecks_serving_net_after_child_before_confirmation(self):
        from test_prepared_resume import prepared_fixture
        with prepared_fixture(fault='expected-refusal') as f:
            parent=os.getpid(); original=f.platform.controller_namespace
            def target(fs,p):
                t=original(fs,p); net=t._net; obs=t._observe
                marker=f.root/'after-proof'
                def observed(pid):
                    result=obs(pid); marker.write_bytes(str(pid).encode()); return result
                def network(pid):
                    if os.getpid()==parent and marker.exists() and str(pid)==marker.read_text(): return (-2,-2)
                    return net(pid)
                t._observe=observed; t._net=network
                return t
            f.platform.controller_namespace=target
            with self.assertRaises(c.Refusal) as caught:
                c.load_fresh(f.fs).FreshLaunch(f.held,f.platform,socket_path=f.socket).run_prepared(f.proof)
            self.assertEqual(caught.exception.code,'COMMITTED_ACTIVATION_UNKNOWN')
            self.assertFalse(f.held.activation_confirmed)
            self.assertNotEqual(f.fs.read_json(fresh.ATTEMPT)['phase'],'confirmed')


    def test_C5_real_child_drops_inherited_holds_and_checks_own_fd_close(self):
        from test_prepared_resume import prepared_fixture
        import socket
        for close_fault in (False,'retained','inherited'):
            with self.subTest(close_fault=close_fault), prepared_fixture(fault='expected-refusal' if close_fault else None) as f:
                read,write=os.pipe(); a,b=socket.socketpair(); parent=os.getpid()
                import fcntl
                lock=os.open(f.root/'probe-inherited-lock',os.O_CREAT|os.O_RDWR,0o600)
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                original=f.platform.controller_namespace; targets=[]; real_close=os.close
                extras=[read,write,a.fileno(),b.fileno(),lock]
                def target(fs,p):
                    t=original(fs,p); join=t._join; targets.append(t)
                    def joined():
                        for fd in extras+[x.wire.writer for x in f.held.nodes]+[x.wire.reader for x in f.held.nodes]:
                            try: os.fstat(fd)
                            except OSError: continue
                            raise AssertionError('child retained owner/hold/SSH/pipe FD')
                        t.close_fault_fd=t.fd
                        t.record('authority-closed'); join()
                    t._join=joined; return t
                def close(fd):
                    real_close(fd)
                    if os.getpid()!=parent and targets and (
                        close_fault=='retained' and fd==getattr(targets[0],'close_fault_fd',None) or
                        close_fault=='inherited' and fd==lock):
                        raise OSError('MODELED close failure after real disposal')
                f.platform.controller_namespace=target
                try:
                    with patch.object(os,'close',side_effect=close):
                        launch=c.load_fresh(f.fs).FreshLaunch(f.held,f.platform,socket_path=f.socket)
                        if close_fault:
                            with self.assertRaises(c.Refusal): launch.run_prepared(f.proof)
                            self.assertFalse(f.held.activation_confirmed)
                        else: launch.run_prepared(f.proof)
                    if close_fault=='inherited':
                        self.assertFalse((f.root/'probe.jsonl').exists(),'inherited close error reached join/TCP')
                    else: self.assertIn('authority-closed',(f.root/'probe.jsonl').read_text())
                    with (f.root/'probe-inherited-lock').open('rb') as contender:
                        with self.assertRaises(BlockingIOError): fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    self.assertEqual(f.count(),1)
                finally:
                    real_close(read); real_close(write); real_close(lock); a.close(); b.close()


    def test_C6_timeout_reaps_real_probe_within_existing_deadline(self):
        from test_prepared_resume import prepared_fixture
        with prepared_fixture(fault='expected-refusal') as f:
            module=c.load_fresh(f.fs); original=f.platform.controller_namespace
            def target(fs,p):
                t=original(fs,p); join=t._join
                def stalled(): join(); time.sleep(2)
                t._join=stalled; return t
            f.platform.controller_namespace=target
            actual=module._controller_observe; finish=[]
            def bounded(t,e,h,d):
                deadline=min(d,time.monotonic()+.15); finish.append(deadline)
                return actual(t,e,h,deadline)
            with patch.object(module,'_controller_observe',side_effect=bounded):
                with self.assertRaises(c.Refusal) as caught:
                    module.FreshLaunch(f.held,f.platform,socket_path=f.socket).run_prepared(f.proof)
            events=[json.loads(x) for x in (f.root/'probe.jsonl').read_text().splitlines()]
            pid=next(x['pid'] for x in events if x['event']=='join')
            try:
                self.assertFalse(Path('/proc',str(pid)).exists(),'probe zombie/alive after bounded timeout')
                self.assertEqual(caught.exception.code,'COMMITTED_ACTIVATION_UNKNOWN')
                self.assertNotEqual(f.fs.read_json(fresh.ATTEMPT)['phase'],'confirmed')
            finally:
                # Harness-owned zombie cleanup only, NOT production recovery.
                try: os.waitpid(pid,0)
                except ChildProcessError: pass


    def test_C2_accepted_target_fault_matrix_refuses_before_resume_tcp_commit(self):
        from test_prepared_resume import prepared_fixture
        faults=('missing-plan','plan-untrusted','policy-untrusted','bool-device','float-inode',
                'pin','files','policy-net','supervisor-start','supervisor-pid','missing-net','symlink',
                'wrong-type','host-net','supervisor-net','nonroot','foreign-mount')
        for fault in faults:
            with self.subTest(fault=fault), prepared_fixture(fault='expected-refusal') as f:
                policy=f.fs.read_json(fresh.POLICY); plan=f.fs.read_json(fresh.RESOURCE_PLAN)
                root=f.outer.root; path=root/fresh.RESOURCE_PLAN.lstrip('/'); net=root/fresh.NETNS.lstrip('/')
                if fault=='missing-plan': path.unlink()
                elif fault=='plan-untrusted': path.chmod(0o666)
                elif fault=='policy-untrusted': (root/fresh.POLICY.lstrip('/')).chmod(0o666)
                elif fault in ('bool-device','float-inode','pin','files'):
                    if fault=='bool-device': plan['networkNamespace']['device']=True
                    if fault=='float-inode': plan['networkNamespace']['inode']=float(plan['networkNamespace']['inode'])
                    if fault=='pin': plan['networkNamespace']['inode']+=1
                    if fault=='files': plan['files']['/app/index.js']='f'*64
                    f.fs.atomic(fresh.RESOURCE_PLAN,c.canonical(plan))
                elif fault in ('policy-net','supervisor-start','supervisor-pid'):
                    if fault=='policy-net': policy['inventory']['namespaces']['net']='net:[1]'
                    if fault=='supervisor-start': policy['inventory']['supervisor']['start']='0'
                    if fault=='supervisor-pid': policy['inventory']['supervisor']['pid']=99999999
                    f.fs.atomic(fresh.POLICY,c.canonical(policy))
                elif fault=='missing-net': net.unlink()
                elif fault=='symlink': net.unlink(); net.symlink_to('/proc/self/ns/net')
                else:
                    original=f.platform.controller_namespace
                    def target(fs,p):
                        t=original(fs,p); network=t._net
                        if fault=='wrong-type': t._type=lambda:0
                        if fault=='host-net': t._net=lambda pid:t.identity
                        if fault=='supervisor-net': t._net=lambda pid:(-2,-2) if pid==f.supervisor.pid else network(pid)
                        if fault in ('nonroot','foreign-mount'):
                            def refused(): raise c.Refusal('MODELED_ROOT_OR_HOST_VIEW_REFUSAL')
                            t._host=refused
                        return t
                    f.platform.controller_namespace=target
                with patch.object(signal,'pidfd_send_signal',wraps=signal.pidfd_send_signal) as sent:
                    # Files' fixture uses its separately digest-loaded class;
                    # module-name equality does not make exception types equal.
                    with self.assertRaises((RuntimeError,OSError)) as refused:
                        c.load_fresh(f.fs).FreshLaunch(f.held,f.platform,socket_path=f.socket).run_prepared(f.proof)
                    if isinstance(refused.exception,RuntimeError):
                        self.assertEqual(type(refused.exception).__name__,'Refusal')
                    if fault in ('plan-untrusted','policy-untrusted'):
                        self.assertEqual(str(refused.exception),'UNTRUSTED_FILE_RETAINED')
                    self.assertEqual(sent.call_count,0)
                self.assertTrue(f.fs.absent(c.COMMIT)); self.assertEqual(f.count(),0)
                self.assertFalse((f.root/'probe.jsonl').exists())

    def test_C3_join_failure_membership_and_nonnet_change_refuse_before_tcp(self):
        from test_prepared_resume import prepared_fixture
        for fault in ('setns','membership','nonnet'):
            with self.subTest(fault=fault),prepared_fixture(fault='expected-refusal') as f:
                parent=os.getpid(); original=f.platform.controller_namespace; real_link=os.readlink
                marker=f.root/'joined'
                def target(fs,p):
                    t=original(fs,p); join=t._join; network=t._net
                    def joining():
                        if fault=='setns': raise OSError('MODELED CAP/setns refusal')
                        join(); marker.write_bytes(b'joined')
                    t._join=joining
                    if fault=='membership': t._net=lambda pid:(-2,-2) if pid=='self' else network(pid)
                    return t
                def readlink(path,*a,**kw):
                    if fault=='nonnet' and os.getpid()!=parent and str(path)=='/proc/self/ns/mnt' and marker.exists(): return 'MODELED-FOREIGN-MNT'
                    return real_link(path,*a,**kw)
                f.platform.controller_namespace=target
                with patch.object(os,'readlink',side_effect=readlink):
                    with self.assertRaises(c.Refusal):
                        c.load_fresh(f.fs).FreshLaunch(f.held,f.platform,socket_path=f.socket).run_prepared(f.proof)
                events=(f.root/'probe.jsonl').read_text() if (f.root/'probe.jsonl').exists() else ''
                self.assertNotIn('tcp',events); self.assertEqual(f.count(),1)
                self.assertFalse(f.held.activation_confirmed)

    def test_C4_pid_owned_literal_proof_faults_are_unknown_without_replay(self):
        from test_prepared_resume import prepared_fixture
        for fault in ('pid','start','cgroup','listener','reverse-tuple','body','status','net','death'):
            with self.subTest(fault=fault),prepared_fixture(fault='expected-refusal') as f:
                original=f.platform.controller_namespace
                def target(fs,p):
                    t=original(fs,p); observe=t._observe; network=t._net
                    def observed(pid):
                        if fault=='pid': return observe(os.getpid())  # wrong PID owns no listener
                        if fault in ('listener','reverse-tuple'):
                            actual=Path.read_text
                            calls=0
                            def text(path,*a,**kw):
                                nonlocal calls
                                raw=actual(path,*a,**kw)
                                if str(path)==f'/proc/{pid}/net/tcp':
                                    calls+=1
                                    if (fault=='listener' and calls==1) or (fault=='reverse-tuple' and calls==2):
                                        return raw.splitlines()[0]+'\n'
                                return raw
                            with patch.object(Path,'read_text',text): return observe(pid)
                        if fault=='status':
                            actual=fresh.http.client.HTTPConnection.getresponse
                            def response(conn):
                                r=actual(conn); r.status=503; return r
                            with patch.object(fresh.http.client.HTTPConnection,'getresponse',response): return observe(pid)
                        result=observe(pid)
                        if fault=='start': result['start']='0'
                        if fault=='cgroup': result['cgroup']='0::/foreign'
                        if fault=='body': result['bodySha256']='f'*64
                        if fault=='death': os.kill(pid,signal.SIGTERM)
                        return result
                    t._observe=observed
                    if fault=='net': t._net=lambda pid:(-2,-2) if t.serving and pid==t.serving['pid'] else network(pid)
                    return t
                f.platform.controller_namespace=target
                launch=c.load_fresh(f.fs).FreshLaunch(f.held,f.platform,socket_path=f.socket)
                with self.assertRaises((c.Refusal,OSError)) as caught: launch.run_prepared(f.proof)
                self.assertEqual(caught.exception.code,'COMMITTED_ACTIVATION_UNKNOWN')
                self.assertEqual(f.count(),1); self.assertFalse(f.held.activation_confirmed)
                self.assertNotEqual(f.fs.read_json(fresh.ATTEMPT)['phase'],'confirmed')
                with self.assertRaisesRegex(c.Refusal,'REPLAY'): launch.run_prepared(f.proof)

    def test_C7_supervisor_observe_remains_direct_without_controller_authority(self):
        from test_fresh_classic_launch import launch_fixture
        with launch_fixture(fresh) as f:
            f.launch()
            pid=next(json.loads(x.read_text())['pid'] for x in f.root.glob('serving-*.json'))
            p=f.fs.read_json(fresh.POLICY); platform=fresh.Platform()
            with patch.object(platform,'endpoint',return_value=('127.0.0.1',f.port)), \
                 patch.object(fresh,'CGROUP',Path(f'/proc/{pid}/cgroup').read_text().strip()[3:]), \
                 patch.object(platform,'controller_namespace',side_effect=AssertionError('supervisor requested root target')), \
                 patch.object(fresh.os,'fork',side_effect=AssertionError('supervisor forked probe')), \
                 patch.object(fresh,'_input_snapshot',side_effect=AssertionError('supervisor read resource plan')):
                result=platform.observe(p,pid)
            self.assertEqual(result['bodySha256'],fresh.READY_BODY_SHA256)


    def test_C6_mutable_policy_after_child_cannot_confirm(self):
        from test_prepared_resume import prepared_fixture
        with prepared_fixture(fault='expected-refusal') as f:
            module=c.load_fresh(f.fs); actual=module._controller_observe
            def altered(target,*args):
                result=actual(target,*args)
                target.policy['files']['/app/index.js']='f'*64
                return result
            with patch.object(module,'_controller_observe',side_effect=altered):
                with self.assertRaises(c.Refusal):
                    module.FreshLaunch(f.held,f.platform,socket_path=f.socket).run_prepared(f.proof)
            self.assertFalse(f.held.activation_confirmed)
            self.assertNotEqual(f.fs.read_json(fresh.ATTEMPT)['phase'],'confirmed')


    def test_C6_probe_result_transport_and_durability_faults_stay_unknown(self):
        from test_prepared_resume import prepared_fixture
        for fault in ('malformed','oversize','eof','death','reap','pipe-close','target-close','fsync','late-http'):
            with self.subTest(fault=fault),prepared_fixture(fault='expected-refusal') as f:
                module=c.load_fresh(f.fs); parent=os.getpid(); stack=contextlib.ExitStack()
                if fault in ('malformed','oversize','eof','death'):
                    def child(t,w,p,e,d):
                        if fault=='malformed': os.write(w,b'{bad-json')
                        if fault=='oversize': os.write(w,b'x'*4097)
                        if fault=='death': os.kill(os.getpid(),signal.SIGKILL)
                        os._exit(0)
                    stack.enter_context(patch.object(module,'_probe_child',side_effect=child))
                if fault=='reap':
                    actual=os.waitpid; actual_fork=os.fork; once=[]; owned=[]
                    def fork():
                        pid=actual_fork()
                        if pid: owned.append(pid)
                        return pid
                    def wait(pid,flags):
                        if pid in owned and not once: once.append(1); raise OSError('MODELED waitpid failure')
                        return actual(pid,flags)
                    stack.enter_context(patch.object(os,'fork',side_effect=fork))
                    stack.enter_context(patch.object(os,'waitpid',side_effect=wait))
                if fault=='pipe-close':
                    actual_pipe=os.pipe2; actual_close=os.close; pipes=[]; once=[]
                    def pipe(flags):
                        pair=actual_pipe(flags); pipes.append(pair); return pair
                    def close(fd):
                        actual_close(fd)
                        if os.getpid()==parent and pipes and fd==pipes[0][0] and not once:
                            once.append(1); raise OSError('MODELED pipe close after real disposal')
                    stack.enter_context(patch.object(os,'pipe2',side_effect=pipe))
                    stack.enter_context(patch.object(os,'close',side_effect=close))
                if fault in ('target-close','late-http'):
                    original=f.platform.controller_namespace
                    def target(fs,p):
                        t=original(fs,p); close=t.close; observe=t._observe
                        def closed():
                            close()
                            if os.getpid()==parent: raise OSError('MODELED retained FD close failure')
                        def observed(pid):
                            result=observe(pid); time.sleep(.3); return result
                        if fault=='target-close': t.close=closed
                        else: t._observe=observed
                        return t
                    f.platform.controller_namespace=target
                    if fault=='late-http':
                        actual=module._controller_observe
                        stack.enter_context(patch.object(module,'_controller_observe',side_effect=lambda t,e,h,d:actual(t,e,h,min(d,time.monotonic()+.15))))
                if fault=='fsync':
                    actual=f.fs.atomic
                    def atomic(path,raw,*a,**kw):
                        if path==fresh.ATTEMPT and c.decode(raw).get('phase')=='confirmed': raise OSError('MODELED confirmation fsync failure')
                        return actual(path,raw,*a,**kw)
                    stack.enter_context(patch.object(f.fs,'atomic',side_effect=atomic))
                with stack:
                    launch=module.FreshLaunch(f.held,f.platform,socket_path=f.socket)
                    with self.assertRaises((c.Refusal,OSError,ValueError)) as caught: launch.run_prepared(f.proof)
                    self.assertEqual(caught.exception.code,'COMMITTED_ACTIVATION_UNKNOWN')
                    self.assertEqual(f.count(),1); self.assertFalse(f.held.activation_confirmed)
                    self.assertNotEqual(f.fs.read_json(fresh.ATTEMPT)['phase'],'confirmed')
                    with self.assertRaisesRegex(c.Refusal,'REPLAY'): launch.run_prepared(f.proof)

    def test_C6_inputs_replacement_and_each_postexec_hold_loss_cannot_confirm(self):
        from test_prepared_resume import prepared_fixture
        for fault in ('raw-plan','raw-policy','same-byte-replacement','net-replacement',0,1,2,3,4):
            with self.subTest(fault=fault),prepared_fixture(fault='expected-refusal') as f:
                module=c.load_fresh(f.fs); actual=module._controller_observe
                def changed(t,*args):
                    result=actual(t,*args)
                    if type(fault) is int:
                        node=f.fixtures[fault]
                        node.put('/fixture-live.json',c.canonical({'held':False,'candidateFrozen':True}))
                    elif fault=='net-replacement':
                        path=f.outer.root/fresh.NETNS.lstrip('/'); other=path.with_suffix('.other')
                        other.write_bytes(b'foreign'); other.chmod(0o400); other.replace(path)
                    else:
                        path=f.outer.root/(fresh.POLICY if fault=='raw-policy' else fresh.RESOURCE_PLAN).lstrip('/')
                        if fault=='same-byte-replacement':
                            other=path.with_suffix('.other'); other.write_bytes(path.read_bytes()); other.chmod(0o600); other.replace(path)
                        else: path.write_bytes(path.read_bytes()+b' ')
                    return result
                with patch.object(module,'_controller_observe',side_effect=changed):
                    with self.assertRaises((c.Refusal,node_originals.Refusal)) as caught:
                        module.FreshLaunch(f.held,f.platform,socket_path=f.socket).run_prepared(f.proof)
                self.assertEqual(caught.exception.code,'COMMITTED_ACTIVATION_UNKNOWN')
                self.assertFalse(f.held.activation_confirmed); self.assertEqual(f.count(),1)
                self.assertNotEqual(f.fs.read_json(fresh.ATTEMPT)['phase'],'confirmed')

    def test_C8_documented_source_only_boundary_keeps_old_artifact_frozen(self):
        text=(Path(__file__).parent/'FRESH_CLASSIC_LAUNCH.md').read_text()
        for token in ('Controller-only accepted-netns observation','NS_GET_NSTYPE','probe-only',
                      '9e full pack remains frozen','strict 3s repeatability is NOT proven'):
            self.assertIn(token,text)


    def test_C3_kernel_seams_exact_root_host_view_type_and_net_only_call(self):
        from unittest.mock import Mock
        t=fresh._ControllerNamespace(None,None); t.fd=123
        for fault in ('uid','euid','gid','egid','pid','mnt','net','ok'):
            with self.subTest(fault=fault),contextlib.ExitStack() as stack:
                for name in ('uid','euid','gid','egid'):
                    stack.enter_context(patch.object(os,'get'+name,return_value=1 if fault==name else 0))
                def link(path):
                    return 'foreign' if path=='/proc/self/ns/'+fault else 'MODELED-host'
                stack.enter_context(patch.object(os,'readlink',side_effect=link))
                if fault=='ok': t._host()
                else:
                    with self.assertRaisesRegex(c.Refusal,'ROOT_CONTROLLER|HOST_CONTROLLER'): t._host()
        with patch.object(fresh.fcntl,'ioctl',return_value=fresh._NEWNET) as ioctl:
            self.assertEqual(t._type(),fresh._NEWNET); ioctl.assert_called_once_with(123,0xb703)
        libc=Mock(); libc.setns.return_value=-1
        with patch.object(fresh.ctypes,'CDLL',return_value=libc),patch.object(fresh.ctypes,'get_errno',return_value=1):
            with self.assertRaisesRegex(OSError,'SETNS_REFUSED'): t._join()
        libc.setns.assert_called_once_with(123,fresh._NEWNET)


    def test_C6_short_raw_read_and_parent_close_error_cannot_accept_or_leak_fd(self):
        import tempfile
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); file=root/'c3-test-fresh-classic'; file.write_bytes(b'{} unread suffix')
            @contextlib.contextmanager
            def regular(path):
                fd=os.open(file,os.O_RDONLY)
                try: yield fd
                finally: os.close(fd)
            with self.subTest(fault='short-raw-read'),patch.object(os,'pread',return_value=b'{}'):
                with self.assertRaisesRegex(c.Refusal,'CONTROLLER_INPUT_DRIFT'):
                    fresh._input_snapshot(SimpleNamespace(opened=regular),fresh.RESOURCE_PLAN)
            @contextlib.contextmanager
            def parent(path,directory=False):
                fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
                try: yield fd
                finally:
                    os.close(fd)
                    raise OSError('MODELED trusted parent close failure')
            opened=[]; actual_open=os.open
            def opening(path,*a,**kw):
                fd=actual_open(path,*a,**kw)
                if path=='c3-test-fresh-classic': opened.append(fd)
                return fd
            with self.subTest(fault='parent-close'):
                try:
                    with patch.object(os,'open',side_effect=opening):
                        target=fresh._ControllerNamespace(SimpleNamespace(opened=parent),None)
                        with self.assertRaisesRegex(OSError,'parent close'): target._open_net()
                    self.assertEqual(len(opened),1)
                    for fd in opened:
                        with self.assertRaises(OSError,msg='net FD leaked on parent directory close failure'): os.fstat(fd)
                finally:
                    for fd in opened:
                        try: os.close(fd)
                        except OSError: pass


if __name__ == '__main__': unittest.main()
