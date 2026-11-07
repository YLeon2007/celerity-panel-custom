"""Local actual API/pipe tests. SSH/root/kernel/systemd acceptance is modeled."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
SCRATCH = '/home/leon/.hermes/cache/scratch'

def load(name):
    path = HERE / (name + '.py')
    fd = os.open(path, os.O_RDONLY | os.O_NOATIME | os.O_NOFOLLOW)
    try: raw = os.read(fd, 2 * 1024 * 1024)
    finally: os.close(fd)
    import types
    m = types.ModuleType(name); m.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m

def sha(raw): return hashlib.sha256(raw).hexdigest()


def inventory_nodes():
    """Real accepted-inventory producer; only physical acceptance is modeled."""
    m = load('isolation')
    def node(node_id, ip, profile, tag, profiles):
        return dict(nodeId=node_id, targetProfile=profile,
            endpoint=dict(ip=ip, port=2222, username=m.RUNNER_USER),
            physical=dict(machineId=tag*32,
                bootId='-'.join(tag*n for n in (8,4,4,4,12)), sshHostKeySha256=tag*64),
            profiles=profiles)
    value = dict(version=1, profile='accepted-test-v1',
        executionContext=dict(target='test', hostIdentity='test.infograd.online'),
        nodes=[node('6aecd36265572a55acf7c677', '10.203.61.2', 'xray-main', 'b', ['xray-main']),
               node('6aed089795ea4b863887d717', '10.203.61.1', 'xray-bridge', 'a', ['xray-main','xray-bridge'])],
        sharedNodeId='6aed089795ea4b863887d717')
    validated = m.validate_inventory(value)
    result = {}
    for pin in validated['nodes']:
        plan = dict(context='test.infograd.online', nodeId=pin['nodeId'],
            targetProfile=pin['targetProfile'], endpointIp=pin['endpoint']['ip'], **pin['physical'])
        actual = m.inventory_node(plan, inventory=validated)
        assert actual is pin  # consume the SAME full node, never a projected endpoint
        result[pin['nodeId']] = actual
    return result


def invalid_selected_nodes(node):
    """Narrow consumer-boundary substitutions, not another inventory schema."""
    yield 'foreign-id', dict(node, nodeId='0'*24)
    for field, value in (('ip','10.203.61.99'), ('port',22), ('port','2222'), ('port',2222.0),
                         ('username','root'), ('username','c3-test-operator')):
        yield field+'='+str(value), dict(node, endpoint=dict(node['endpoint'], **{field:value}))
    yield 'missing-username', dict(node, endpoint={k:v for k,v in node['endpoint'].items() if k != 'username'})
    yield 'extra-key', dict(node, endpoint=dict(node['endpoint'], extra=True))


def holder_fixture(root):
    """Actual Holder constructor/observation/connect; external host/root facts modeled."""
    root = Path(root); m = load('fresh_network'); control = load('fresh_network_control')
    client = load('fresh_network_client')
    m.INPUT = str(root/'plan'); m.LEASE = str(root/'lease'); m.SOCKET = str(root/'socket')
    real_identity = m.identity
    m.identity = lambda path: real_identity(str(path).replace('/proc/1/ns/', '/proc/self/ns/'))
    paths = {m.LIB: HERE/'fresh_network.py', client.CONTROL: HERE/'fresh_network_control.py',
             client.SERVER_ENTRY: HERE/'fresh_network_exec.py', client.CLIENT: HERE/'fresh_network_client.py'}
    m.trusted_read = lambda path: Path(path).read_bytes()
    m.trusted_fd = lambda path, directory=False: os.open(paths.get(path,path),
        os.O_RDONLY | os.O_NOATIME | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0))
    client.SOURCE_PINS = {p: sha(Path(source).read_bytes()) for p,source in paths.items() if p != client.CLIENT}
    client.__source_sha256__ = sha(paths[client.CLIENT].read_bytes())
    client._host = lambda mod,p,pid,start: mod.need(mod.proc_start(pid) == start, 'ACTUAL_PID_START')
    client._root_stat = lambda *a: None; client._server_host = lambda *a: None
    peer = client._peercred
    client._peercred = lambda channel: (peer(channel)[0],0,0)
    class Status:
        def __init__(self,*args): self.path = Path(*args)
        def read_text(self): return '\n'.join('Uid:\t0\t0\t0\t0' if x.startswith('Uid:') else x
                                               for x in self.path.read_text().splitlines())
    control.Path = Status
    control.holder_exit_access = lambda *a: None  # CAP_SYS_PTRACE/root userns modeled
    # Actual pipe protocol via existing client.run, including genuine first greeting.
    client._pipe = lambda *a: (1,2)  # root anonymous-pipe ownership only modeled
    client.run(m, control)


def server_fixture(root):
    """Real local network Controller.prepare/send. Namespace/host arm modeled."""
    import socket
    root = Path(root); m = load('fresh_network'); control = load('fresh_network_control')
    fixture = load('test_fresh_network')
    p = m.decode((root/'plan').read_bytes())
    class Kernel(fixture.ModelKernel):
        def observation(self):
            return dict(namespace=[7,8], snapshots={role: dict(links=[],addresses=[],routes=[],rules=[])
                        for role in ('host','fresh',*m.ROLES)}, configSha256=m.digest(m.encode(self.current)))
    kernel = Kernel(p); journal = m.Journal(root/'state'/p['generation'], p)
    controller = m.Controller(p, kernel, journal, guard=lambda: None)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
        listener.bind(str(root/'socket')); os.chmod(root/'socket',0o600); listener.listen(1)
        channel,_ = listener.accept()
        with channel:
            control.send(channel,controller.prepare(),m)
            # Keep the same independent server alive through actual Holder.receive.
            channel.recv(1)


def observer_fixture(root, mode):
    """Actual Observation constructor/wait over actual original pidfds; PID1 modeled."""
    root = Path(root); a=load('finite_test_caller'); m=load('fresh_physical'); observer=load('fresh_physical_observe')
    config=json.loads(sys.stdin.buffer.readline())
    m.INPUT=str(root/'input'); m.RESOURCE=str(root/'resources'); m.RUN_PLAN=str(root/'plan')
    m.REGISTER=str(root/'register'); m.CONTROL=str(root/'control'); m.ACCEPTANCE=str(root/'acceptance')
    m.POLICY=str(root/'host-policy')
    m.trusted_open=lambda path,directory=False: os.open(path,m.DIR if directory else m.FILE)
    m.trusted_read=lambda path,*a: Path(path).read_bytes()
    m.watcher_properties=lambda deadline: json.loads((root/'properties').read_bytes())
    def prepared(policy,pid):
        with m.ProcessLease(pid) as lease: lease.check(stopped=True)
        if mode == 'constructor-fail': raise RuntimeError('MODELED_PREPARED_REFUSAL')
    def emit(value):
        a.write_pipe(sys.stdout.buffer,m.encode(value),config['deadlineMonotonicNs']/1e9)
        if 'observerInitialized' in value and mode == 'early-exit': os._exit(75)
    a.observe_initialized(observer,m,prepared,lambda:None,deadline_ns=config['deadlineMonotonicNs'],emit=emit)


class RecoveryTests(unittest.TestCase):
    def validated_recovery(self, node_id, carrier, host):
        a = load('finite_test_caller'); m = load('isolation')
        node = inventory_nodes()[node_id]
        original = json.dumps(node, sort_keys=True)
        known = ('['+host+']:2222 ssh-ed25519 AAAA\n').encode()
        with patch.object(a, 'snapshot', return_value=(known, ())) as read:
            argv = a.recovery_argv(node, carrier=carrier, key='/accepted/operator-key',
                known_hosts='/accepted/known', known_hosts_sha256=sha(known))
        read.assert_called_once_with('/accepted/known')
        self.assertEqual(node['endpoint']['username'], m.RUNNER_USER)
        self.assertEqual(argv[-2:], [m.OPERATOR+'@'+host, 'sudo -n '+m.HELPER+' guard'])
        self.assertNotEqual(m.OPERATOR, m.RUNNER_USER)
        self.assertEqual(json.dumps(node, sort_keys=True), original)

    def test_validated_p_inventory_node_reaches_recovery_operator(self):
        self.validated_recovery('6aecd36265572a55acf7c677', 'P-public', '104.143.201.72')

    def test_validated_b_inventory_node_reaches_recovery_operator(self):
        self.validated_recovery('6aed089795ea4b863887d717', 'B-public', '132.243.230.19')

    def test_changed_selected_binding_refused_before_known_hosts_read(self):
        a = load('finite_test_caller'); m = load('isolation')
        for node in inventory_nodes().values():
            carrier = 'P-public' if node['nodeId'] == a.P_NODE else 'B-public'
            with patch.object(a, 'snapshot') as read:
                for label, bad in invalid_selected_nodes(node):
                    with self.subTest(node=node['nodeId'], change=label):
                        with self.assertRaisesRegex(RuntimeError, 'EXACT_SELECTED_ENDPOINT_REQUIRED'):
                            a.recovery_argv(bad, carrier=carrier, key='/accepted/key',
                                known_hosts='/accepted/known', known_hosts_sha256='a'*64)
                wrong_carrier = 'B-public' if node['nodeId'] == a.P_NODE else 'P-public'
                with self.assertRaisesRegex(RuntimeError, 'ACCEPTED_SELECTED_CARRIER_REQUIRED'):
                    a.recovery_argv(node, carrier=wrong_carrier, key='/accepted/key',
                        known_hosts='/accepted/known', known_hosts_sha256='a'*64)
                read.assert_not_called()
        # The actual producer still rejects abbreviated/foreign-account endpoints.
        for user in (None, 'root', m.OPERATOR):
            node = inventory_nodes()[a.B_NODE]
            endpoint = dict(node['endpoint'], username=user)
            if user is None: del endpoint['username']
            bad = dict(node, endpoint=endpoint)
            inventory = dict(version=1, profile='accepted-test-v1',
                executionContext=dict(target='test', hostIdentity='test.infograd.online'),
                nodes=[bad], sharedNodeId=a.B_NODE)
            with self.subTest(producer_user=user):
                with self.assertRaisesRegex(m.Refusal, 'INVALID_INVENTORY_ENDPOINT'):
                    m.validate_inventory(inventory)

    def test_selected_carrier_and_actual_nonce_roundtrip(self):
        a = load('finite_test_caller')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp, patch.object(a, 'ROOT_UID', os.getuid()):
            known = Path(tmp) / 'known'; known.write_text('[104.143.201.72]:2222 ssh-ed25519 AAAA\n')
            node = inventory_nodes()[a.P_NODE]
            with patch.object(a, 'snapshot', side_effect=lambda p: (Path(p).read_bytes(), ())):
                argv = a.recovery_argv(node, carrier='P-public', key='/accepted/operator-key',
                    known_hosts=str(known), known_hosts_sha256=sha(known.read_bytes()))
            self.assertEqual(argv[-2:], ['c3-test-operator@104.143.201.72',
                'sudo -n /usr/local/libexec/c3-test-node-isolation guard'])
            self.assertIn('StrictHostKeyChecking=yes', argv)
            self.assertIn('/dev/null', argv)
            real = subprocess.Popen; children = []
            code = ('import sys; sys.path.insert(0,sys.argv[1]); import isolation as m; '
                    'print(m.json.dumps({"guardReady":True,'
                    '"identity":{"pid":m.os.getpid(),"start":"17","socket":"/modeled/recovery.sock"},'
                    '"session":{"pid":1,"start":"1"}}),flush=True); m.recovery_roundtrip("a"*64)')
            def spawn(args, **kw):
                self.assertEqual(args, argv)
                child = real([sys.executable, '-B', '-c', code, str(HERE)], **kw)
                children.append(child); return child
            ready = []
            with patch.object(a.subprocess, 'Popen', spawn):
                a.serve_recovery(argv, end=time.monotonic()+3, on_ready=ready.append)
            self.assertEqual(ready[0]['session'], dict(pid=1, start='1'))
            self.assertEqual(children[0].returncode, 0)
            self.assertRaises(ChildProcessError, os.waitpid, children[0].pid, os.WNOHANG)

    def test_exact_selected_mapping_and_explicit_via_p_pin(self):
        a=load('finite_test_caller')
        known=b'\n'.join((h+' ssh-ed25519 AAAA').encode() for h in
            ('[104.143.201.72]:2222','[10.203.61.2]:2222','[132.243.230.19]:2222',
             '[10.203.61.1]:2222','104.143.201.72'))+b'\n'
        with patch.object(a,'snapshot',return_value=(known,())):
            for carrier,node_id,private,host in (
                ('P-public',a.P_NODE,'10.203.61.2','104.143.201.72'),
                ('P-private',a.P_NODE,'10.203.61.2','10.203.61.2'),
                ('B-public',a.B_NODE,'10.203.61.1','132.243.230.19'),
                ('B-private',a.B_NODE,'10.203.61.1','10.203.61.1'),
                ('B-private-via-P',a.B_NODE,'10.203.61.1','10.203.61.1')):
                with self.subTest(carrier=carrier):
                    node=inventory_nodes()[node_id]
                    self.assertEqual(node['endpoint']['ip'], private)
                    kw=dict(carrier=carrier,key='/accepted/key',known_hosts='/accepted/known',known_hosts_sha256=sha(known))
                    if carrier.endswith('via-P'):kw['jump']=dict(user='root',port=22,key='/accepted/jump-key')
                    argv=a.recovery_argv(node,**kw)
                    self.assertEqual(argv[-2],'c3-test-operator@'+host)
                    self.assertNotIn('StrictHostKeyChecking=no',argv)
                    self.assertEqual(any(x.startswith('ProxyCommand=') for x in argv),carrier.endswith('via-P'))
            with self.assertRaisesRegex(RuntimeError,'INDEPENDENT_P_JUMP_INPUT'):
                a.recovery_argv(node,carrier='B-private-via-P',key='/accepted/key',
                    known_hosts='/accepted/known',known_hosts_sha256=sha(known))
            with self.assertRaisesRegex(RuntimeError,'EXACT_SELECTED_ENDPOINT'):
                a.recovery_argv(dict(node,endpoint=dict(node['endpoint'],ip='10.203.61.2')),
                    carrier='B-private',key='/accepted/key',known_hosts='/accepted/known',known_hosts_sha256=sha(known))
            with self.assertRaisesRegex(RuntimeError,'ACCEPTED_KNOWN_HOSTS_PIN'):
                a.recovery_argv(node,carrier='B-private',key='/accepted/key',known_hosts='/accepted/known',known_hosts_sha256='f'*64)
        absent=b'[10.203.61.2]:2222 ssh-ed25519 AAAA\n'
        with patch.object(a,'snapshot',return_value=(absent,())):
            with self.assertRaisesRegex(RuntimeError,'EXACT_CARRIER_HOST_KEY_REQUIRED'):
                a.recovery_argv(node,carrier='B-private',key='/accepted/key',known_hosts='/accepted/known',known_hosts_sha256=sha(absent))

    def test_invalid_nonce_rejected_no_echo_and_owned_child_reaped(self):
        a=load('finite_test_caller'); real=subprocess.Popen; children=[]
        code='import sys; print(\'{"recoveryChallenge":"bad"}\',flush=True); print(repr(sys.stdin.buffer.read()),file=sys.stderr)'
        def spawn(argv,**kw):
            child=real([sys.executable,'-B','-c',code],**kw);children.append(child);return child
        with patch.object(a.subprocess,'Popen',spawn):
            with self.assertRaisesRegex(RuntimeError,'EXACT_RECOVERY_NONCE'):
                a.serve_recovery(['modeled-selected-ssh'],end=time.monotonic()+2,on_ready=lambda x:self.fail('false ready'))
        self.assertIsNotNone(children[0].returncode)
        self.assertRaises(ChildProcessError,os.waitpid,children[0].pid,os.WNOHANG)

    def test_existing_remote_independent_ancestry_contract_is_not_replaced(self):
        import pwd
        from types import SimpleNamespace
        m=load('isolation');host=m.Host();pid=os.getpid()
        def identity(n):
            return dict(pid=n,ppid=303 if n==pid else 404,start='7')
        with patch.dict(os.environ,{'SUDO_USER':m.OPERATOR,'SUDO_UID':'1701'}), \
             patch.object(pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=1701)), \
             patch.object(host,'unit',return_value={'MainPID':'404'}), \
             patch.object(m,'proc_identity',side_effect=identity),patch.object(Path,'read_text',return_value='sshd: modeled operator'):
            self.assertEqual(host.operator_session(),dict(pid=303,start='7'))
            with patch.dict(os.environ,{'SUDO_USER':'root'}):
                with self.assertRaisesRegex(m.Refusal,'INDEPENDENT_OPERATOR_SSH'):host.operator_session()
            with patch.object(Path,'read_text',return_value='bash'):
                with self.assertRaisesRegex(m.Refusal,'NOT_MAINTENANCE_SSH'):host.operator_session()

    def test_actual_recovery_server_original_two_second_deadline_is_not_reset(self):
        a=load('finite_test_caller'); real=subprocess.Popen;children=[]
        code=('import sys;sys.path.insert(0,sys.argv[1]);import isolation as m;'
              'print(m.json.dumps({"guardReady":True,"identity":{"pid":m.os.getpid(),"start":"17",'
              '"socket":"/modeled/recovery.sock"},"session":{"pid":1,"start":"1"}}),flush=True);'
              'm.recovery_roundtrip("b"*64)')
        def spawn(argv,**kw):
            child=real([sys.executable,'-B','-c',code,str(HERE)],**kw);children.append(child);return child
        start=time.monotonic()
        with patch.object(a.subprocess,'Popen',spawn):
            with self.assertRaises((RuntimeError,OSError)):
                a.serve_recovery(['modeled-selected-ssh'],end=start+4,on_ready=lambda x:time.sleep(2.2))
        self.assertGreaterEqual(time.monotonic()-start,2)
        self.assertNotEqual(children[0].returncode,0)

class LeaseTests(unittest.TestCase):
    def setUp(self):
        from contextlib import ExitStack
        self.stack=ExitStack(); self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir=SCRATCH)))
        (self.root/'state').mkdir()
        self.a=load('finite_test_caller'); self.m=load('fresh_network')
        self.control=load('fresh_network_control'); self.creator=load('fresh_network_invocation')
        p=load('test_fresh_network').plan(); p['deadline']=int(time.time())+10
        p['ordinaryOwner']=dict(version=1,stopConfigSha256=self.m.digest(self.m.encode(self.m.stopped_config(p))))
        self.raw=self.m.encode(p); (self.root/'plan').write_bytes(self.raw)
        self.m.INPUT=str(self.root/'plan'); self.m.LEASE=str(self.root/'lease')
        self.m.trusted_read=lambda path: Path(path).read_bytes()
        real_identity=self.m.identity
        self.m.identity=lambda path:real_identity(str(path).replace('/proc/1/ns/','/proc/self/ns/'))
        class Status:
            def __init__(self,*args): self.path=Path(*args)
            def read_text(self):return '\n'.join('Uid:\t0\t0\t0\t0' if x.startswith('Uid:') else x
                                                for x in self.path.read_text().splitlines())
        self.control.Path=Status; self.control.holder_exit_access=lambda *a:None
        real=subprocess.Popen
        self.children=[]
        def spawn(argv,**kw):
            self.assertEqual(tuple(argv),self.creator.HOLDER_ARGV)
            child=real([sys.executable,'-B',__file__,'--holder',str(self.root)],**kw)
            self.children.append(child); return child
        with patch.object(subprocess,'Popen',spawn): self.invocation=self.creator.Invocation(self.m)
        self.addCleanup(self.invocation.close)
        self.stack.enter_context(patch.object(self.a,'ROOT_UID',os.getuid()))
        self.greeting=self.a.holder_greeting(self.invocation)
        self.lease=dict(version=1,context=self.m.CONTEXT,generation=p['generation'],boot=p['boot'],
            planSha256=sha(self.raw),holder=json.loads(self.greeting)['holder'],deadline=p['deadline'],
            operations=['observe','cutover','return','abandon','handoff'])

    def issue(self,lease=None,pin=None,start=None):
        raw=self.m.encode(self.lease if lease is None else lease)
        return self.a.lease_then_prepare(self.invocation,self.control,self.greeting,
            accepted_greeting_sha256=sha(self.greeting) if pin is None else pin,
            accepted_lease_raw=raw,accepted_lease_sha256=sha(raw),start_network=start or self.start)

    def start(self):
        self.assertEqual((self.root/'lease').read_bytes(),self.m.encode(self.lease))
        self.server=subprocess.Popen([sys.executable,'-B',__file__,'--server',str(self.root)],
                                     stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.addCleanup(self.a.dispose_pipe_child,self.server)

    def test_actual_greeting_root_publication_network_start_prepared_no_reap(self):
        end=self.invocation.end
        self.assertFalse((self.root/'lease').exists())
        self.assertIs(json.loads(self.greeting)['accepted'],False)
        reply=self.issue()
        self.assertEqual(json.loads(reply)['phase'],'prepared')
        self.assertEqual(self.invocation.end,end)
        self.assertEqual(self.lease['deadline'],self.invocation.p['deadline'])
        self.assertIsNone(self.invocation.holder.returncode)
        self.assertFalse(self.invocation.public_completed)
        self.assertEqual(os.stat(self.root/'lease').st_mode&0o777,0o400)
        with self.assertRaisesRegex(RuntimeError,'ONE_ORIGINAL_LEASE'):self.issue()

    def test_no_independent_root_hash_no_publication_or_network_start(self):
        with patch.object(self,'start') as start:
            with self.assertRaisesRegex(RuntimeError,'INDEPENDENT_ROOT_INPUT_PINS'):self.issue(pin='f'*64)
            start.assert_not_called()
        self.assertFalse((self.root/'lease').exists())

    def test_wrong_original_deadline_rejected_by_real_lease_before_publication(self):
        bad=dict(self.lease,deadline=self.lease['deadline']+1)
        with self.assertRaisesRegex(self.m.Refusal,'INDEPENDENT_LIVE_LEASE'):self.issue(bad)
        self.assertFalse((self.root/'lease').exists())

    def test_wrong_holder_rejected_before_publication(self):
        bad=dict(self.lease,holder=dict(pid=os.getpid(),start=self.m.proc_start(os.getpid())))
        with self.assertRaisesRegex(RuntimeError,'EXACT_ACCEPTED_HOLDER'):self.issue(bad)
        self.assertFalse((self.root/'lease').exists())

    def test_network_start_unknown_is_retained_and_not_replayed(self):
        primary=OSError('modeled systemctl lost reply')
        with self.assertRaises(OSError) as caught:self.issue(start=lambda:(_ for _ in ()).throw(primary))
        self.assertIs(caught.exception,primary)
        self.assertEqual((self.root/'lease').read_bytes(),self.m.encode(self.lease))
        with self.assertRaisesRegex(RuntimeError,'ONE_ORIGINAL_LEASE'):self.issue()

class ObserverTests(unittest.TestCase):
    def open(self,f,mode=''):
        a=load('finite_test_caller'); real=subprocess.Popen
        (f.root/'properties').write_text(json.dumps(f.properties(None)))
        def spawn(argv,**kw):
            self.assertEqual(argv[-1],'observer-child')
            return real([sys.executable,'-B',__file__,'--observer',str(f.root),mode],**kw)
        with patch.object(a.subprocess,'Popen',spawn):
            child=a.ObserverChild(deadline_ns=f.deadline,loader_sha256='modeled-root-loader',source_pins={})
        self.addCleanup(child.close)
        return child

    def test_real_constructor_ack_precedes_separate_acceptance_then_real_wait(self):
        fixture=load('test_fresh_physical_observe')
        with fixture.WatchFixture() as f:
            with self.open(f) as child:
                self.assertFalse((f.root/'acceptance').exists())
                ready=child.ready()
                self.assertEqual(ready['observerInitialized']['watcherObservation'],f.generation['watcherObservation'])
                self.assertEqual(ready['observerInitialized']['deadlineMonotonicNs'],f.deadline)
                child.check_initialized()
                self.assertFalse((f.root/'acceptance').exists())
                f.accept()  # explicitly MODELED independent ROOT action, not emitted by adapter
                (f.root/'finish').touch(); self.assertEqual(f.watch.wait(timeout=3),0)
                nxt=f.root/'properties.next'; nxt.write_text(json.dumps(f.properties(None))); nxt.replace(f.root/'properties')
                result=child.finish()
                self.assertEqual(result['code'],'WATCHER_NATURAL_RELEASE_OBSERVED_UNACCEPTED')
                self.assertIs(result['physicalAccepted'],False)
                self.assertEqual(child.child.returncode,0)
                self.assertEqual(f.lease.check(stopped=True)['state'],'T')

    def test_actual_constructor_failure_emits_no_ready_or_acceptance(self):
        with load('test_fresh_physical_observe').WatchFixture() as f:
            with self.open(f,'constructor-fail') as child:
                with self.assertRaisesRegex(RuntimeError,'EOF_UNKNOWN'):child.ready()
                self.assertFalse(child.ready_seen)
                self.assertFalse((f.root/'acceptance').exists())
                self.assertEqual(f.lease.check(stopped=True)['state'],'T')

    def test_ready_then_actual_early_exit_cannot_permit_acceptance(self):
        import select
        with load('test_fresh_physical_observe').WatchFixture() as f:
            with self.open(f,'early-exit') as child:
                try: child.ready()
                except RuntimeError as error:self.assertIn('INITIALIZED_OBSERVER_LOST',str(error))
                self.assertTrue(select.select([child.pidfd],[],[],3)[0])
                with self.assertRaisesRegex(RuntimeError,'INITIALIZED_OBSERVER_LOST'):child.check_initialized()
                self.assertFalse((f.root/'acceptance').exists())

    def test_original_deadline_bounds_live_child_without_acceptance(self):
        with load('test_fresh_physical_observe').WatchFixture(seconds=2) as f:
            with self.open(f) as child:
                child.ready()
                with self.assertRaises((RuntimeError,TimeoutError)):child.finish()
                self.assertFalse((f.root/'acceptance').exists())
                self.assertGreaterEqual(time.monotonic_ns(),f.deadline)

    def test_pin_failure_reaps_registered_owned_child_and_preserves_primary(self):
        a=load('finite_test_caller'); real=subprocess.Popen; children=[]
        def spawn(argv,**kw):
            child=real([sys.executable,'-B','-c','import time; time.sleep(30)'],**kw)
            children.append(child); return child
        primary=OSError('original observer pidfd failure')
        with patch.object(a.subprocess,'Popen',spawn),patch.object(a.os,'pidfd_open',side_effect=primary):
            with self.assertRaises(OSError) as caught:
                a.ObserverChild(deadline_ns=time.monotonic_ns()+2_000_000_000,loader_sha256='x',source_pins={})
        self.assertIs(caught.exception,primary)
        self.assertIsNotNone(children[0].returncode)
        self.assertRaises(ChildProcessError,os.waitpid,children[0].pid,os.WNOHANG)

class CaptureTests(unittest.TestCase):
    def setUp(self):
        # Existing exact disposable proc/cgroup fixture; no real Docker/root IO.
        import types
        path=HERE.parent/'tests/test_panel_host_freezer.py'
        fd=os.open(path,os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW)
        try:raw=os.read(fd,200000)
        finally:os.close(fd)
        tests=types.ModuleType('existing_capture_tests'); tests.__file__=str(path)
        exec(compile(raw,str(path),'exec'),tests.__dict__)
        self.fixture=tests.CaptureTests('test_capture_reads_only_inventory_and_preserves_all_exact_pins')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture.f; self.a=load('finite_test_caller')
        self.node=inventory_nodes()[self.a.B_NODE]

    def capture(self,node=None):
        f=self.f; real_host=f.k.host
        # Actual LinuxKernel instance over disposable fixture proc/cgroup roots.
        f.k.host=lambda:dict(real_host(),machineId='a'*32)
        (f.k.root/'cgroup.controllers').touch()
        readlink=f.m.os.readlink
        with patch.object(f.m,'LinuxKernel',return_value=f.k),patch.object(f.m.os,'geteuid',return_value=0), \
             patch.object(f.m.os,'readlink',side_effect=lambda p:readlink(str(p).replace('/proc/1/ns/','/proc/self/ns/'))), \
             patch.object(f.m,'SystemdRelaunchBarrier',return_value=None), \
             patch.object(f.m,'host_precheck',wraps=f.m.host_precheck) as precheck:
            result=self.a.capture_b_originals(f.m,self.node if node is None else node)
            self.assertEqual(precheck.call_args.kwargs,dict(expected_machine_id='a'*32))
            return result

    def test_accepted_machine_reaches_actual_precheck_capture_and_linuxkernel(self):
        self.assertIsInstance(self.f.k,self.f.m.LinuxKernel)
        original=json.dumps(self.node,sort_keys=True)
        result=self.capture()
        self.assertEqual(json.dumps(self.node,sort_keys=True),original)
        self.assertEqual(result['host']['machineId'],'a'*32)
        self.assertEqual(len(result['containers']),5)
        self.assertNotIn('accepted',result)
        self.assertEqual(self.fixture.calls[0],['container','ls','--all','--quiet','--no-trunc'])

    def test_changed_b_binding_refused_before_linuxkernel_construction(self):
        with patch.object(self.f.m, 'LinuxKernel') as kernel:
            for label, bad in invalid_selected_nodes(self.node):
                with self.subTest(change=label):
                    with self.assertRaisesRegex(RuntimeError, 'EXACT_ACCEPTED_B_NODE_REQUIRED'):
                        self.a.capture_b_originals(self.f.m, bad)
            for machine in ('bad', 'A'*32, None):
                with self.subTest(machine=machine):
                    with self.assertRaisesRegex(RuntimeError, 'ACCEPTED_B_MACHINE_REQUIRED'):
                        self.a.capture_b_originals(self.f.m, dict(self.node, physical=dict(machineId=machine)))
            kernel.assert_not_called()
        self.assertEqual(self.fixture.calls, [])

    def test_wrong_machine_fails_before_capture_or_publication(self):
        wrong=dict(self.node,physical=dict(machineId='b'*32))
        with self.assertRaisesRegex(RuntimeError,'TEST host identity required'):self.capture(wrong)
        self.assertEqual(self.fixture.calls,[])
        self.assertFalse(any('accepted' in x.name for x in Path(self.f.tmp.name).iterdir()))

class BootstrapTests(unittest.TestCase):
    def test_actual_checked_loader_and_freezer_pin_use_noatime_nofollow(self):
        a=load('finite_test_caller')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp:
            root=Path(tmp); directory=root/'usr/local/libexec';directory.mkdir(parents=True)
            loader_bytes=(HERE/'fresh_network_client_exec.py').read_bytes()
            freezer_path=HERE.parent/'panel-host-freezer.py'
            fd=os.open(freezer_path,os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW)
            try:freezer_bytes=os.read(fd,200000)
            finally:os.close(fd)
            lp=directory/Path(a.LOADER).name;fp=directory/Path(a.FREEZER).name
            lp.write_bytes(loader_bytes);fp.write_bytes(freezer_bytes)
            for path in (root/'usr',root/'usr/local',directory):path.chmod(0o755)
            for path in (lp,fp):path.chmod(0o644)
            old=1_000_000_000
            for path in (lp,fp):os.utime(path,ns=(old,old))
            real_open=os.open;real_fstat=os.fstat;opens=[]
            class RootStat:
                st_uid=st_gid=0
                def __init__(self,s):self.s=s
                def __getattr__(self,k):return getattr(self.s,k)
            def opened(path,flags,*args,**kw):
                opens.append((str(path),flags))
                return real_open(root if path=='/' else path,flags,*args,**kw)
            with patch.object(a.os,'open',side_effect=opened), \
                 patch.object(a.os,'fstat',side_effect=lambda fd:RootStat(real_fstat(fd))):
                api=a.load_b_capture_api(loader_sha256=sha(loader_bytes),freezer_sha256=sha(freezer_bytes))
                self.assertTrue(callable(api.capture));self.assertTrue(callable(api.LinuxKernel))
                with self.assertRaisesRegex(RuntimeError,'INSTALLED_SOURCE_PIN'):
                    a.load_b_capture_api(loader_sha256=sha(loader_bytes),freezer_sha256='f'*64)
            self.assertTrue(all(flags&os.O_NOATIME and flags&os.O_NOFOLLOW for _,flags in opens))
            self.assertEqual(lp.stat().st_atime_ns,old);self.assertEqual(fp.stat().st_atime_ns,old)

    def test_no_replace_publication_preserves_existing_target(self):
        a=load('finite_test_caller')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp,patch.object(a,'ROOT_UID',os.getuid()):
            path=Path(tmp)/'lease';path.write_bytes(b'independently existing')
            with self.assertRaises(FileExistsError):a.publish_lease(str(path),b'new independently accepted bytes')
            self.assertEqual(path.read_bytes(),b'independently existing')
            self.assertEqual((Path(tmp)/'lease.finite-next').read_bytes(),b'new independently accepted bytes')

if __name__ == '__main__':
    if sys.argv[1:2] == ['--holder']:holder_fixture(sys.argv[2])
    elif sys.argv[1:2] == ['--server']:server_fixture(sys.argv[2])
    elif sys.argv[1:2] == ['--observer']:observer_fixture(sys.argv[2],sys.argv[3])
    else:unittest.main()
