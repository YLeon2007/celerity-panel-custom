"""Same-byte public parser / real supervisor check / network binding regression.

Only root ownership, namespace/mount/capability facts and PID1/kernel resources
are modeled. Platform.check/validate/root_mount, public JS parser, file digests,
SCM_RIGHTS and the network consumer's COMMIT/policy binding are not replaced.
This is bounded local contract evidence, not physical activation acceptance.
"""
import array
import contextlib
import copy
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import coordinated_restore as restore
import fresh_classic_launch as fresh
import fresh_network as network
import fresh_network_control as control
import test_fresh_classic_launch as launch_tests

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


class FixedInputsReached(Exception):
    """PID1 stage seam after the actual same-COMMIT binding and fixed-file checks."""


class PolicyFixture:
    def __init__(self, root, test):
        self.root, self.test = root, test
        self.files = {}
        self.policy = copy.deepcopy(launch_tests.PolicyBoundaryTests().policy()[1])
        sources = {restore.SELF: 'coordinated_restore.py', restore.FRESH: 'fresh_classic_launch.py',
                   restore.SHARED: 'shared_host.py', '/usr/local/libexec/c3-test-node-isolation': 'isolation.py',
                   restore.FREEZER: '../panel-host-freezer.py',
                   '/usr/local/libexec/c3-test-owner-restoration-channel.py': 'owner_restoration_channel.py',
                   '/usr/local/libexec/c3-test-fresh-owner-restoration-channel.py': 'fresh_owner_restoration_channel.py'}
        for name, source in sources.items():
            self.put(name, (HERE/source).read_bytes())
        # Closed public v2 input; node/physical acceptance is explicitly modeled.
        node = {'nodeId': '1'*24, 'targetProfile': 'xray-bridge',
                'endpoint': {'ip': '10.203.61.2', 'port': 2222, 'username': 'c3-test-runner'},
                'physical': {'machineId': '1'*32, 'bootId': '11111111-1111-4111-8111-111111111111',
                             'sshHostKeySha256': '2'*64}, 'profiles': ['xray-main', 'xray-bridge']}
        from test_fresh_network import plan
        p = plan()
        p.update(machine=node['physical']['machineId'], boot=node['physical']['bootId'])
        p['ordinaryOwner'] = {'version': 1, 'stopConfigSha256': network.digest(network.encode(network.stopped_config(p)))}
        self.network_sha = network.digest(network.encode(p))
        self.put(network.INPUT, network.encode(p))
        # Import the source-authoritative context, without duplicating its schema.
        r = subprocess.run(['node', '-e', "process.stdout.write(JSON.stringify(require('./src/modules/relay-l2tp/domain/topologyExecutionContext').TEST_TOPOLOGY_EXECUTION_CONTEXT))"],
                           cwd=REPO, capture_output=True, text=True, timeout=5, check=True)
        context = json.loads(r.stdout)
        inventory = {'version': 1, 'profile': 'accepted-test-v1', 'executionContext': context,
                     'nodes': [node], 'sharedNodeId': node['nodeId']}
        inventory_sha = restore.sha(restore.canonical(inventory))
        shared = {'version': 2, 'mode': 'shared-test', 'inventorySha256': inventory_sha,
                  'nodeId': node['nodeId'], 'targetProfile': node['targetProfile'], 'endpointIp': node['endpoint']['ip'],
                  **node['physical'], 'hostHold': {'owner': '22222222-2222-4222-8222-222222222222',
                  'freezerSha256': self.sha(restore.FREEZER), 'networkPlanSha256': self.network_sha,
                  'expected': {'host': {'machineId': p['machine'], 'bootId': p['boot']}}}}
        self.put('/etc/c3-test-node-isolation.json', restore.canonical(shared))
        identity = {'context': 'test.infograd.online', 'nodeId': node['nodeId'], 'endpointIp': node['endpoint']['ip'],
                    'targetProfile': node['targetProfile'], **node['physical'], 'inventorySha256': inventory_sha,
                    'maintenanceId': '33333333-3333-4333-8333-333333333333', 'planHash': restore.sha(restore.canonical(shared))}
        profile = {'files': {'config': {'sha256': 'a'*64}, 'unit': {'sha256': 'b'*64}},
                   'service': {'ActiveState': 'active', 'UnitFileState': 'enabled'}}
        accepted = restore.canonical({**identity, 'profiles': {name: profile for name in node['profiles']}})
        cfg = {'version': 2, 'context': 'test.infograd.online', 'inventorySha256': inventory_sha,
               'origin': {'machineId': p['machine'], 'bootId': p['boot']}, 'nodes': {node['nodeId']: {
               'identity': identity, 'profiles': node['profiles'], 'files': {'self': self.sha(restore.SELF),
               'accepted': restore.sha(accepted), 'shared': self.sha(restore.SHARED),
               'isolation': self.sha('/usr/local/libexec/c3-test-node-isolation'), 'freezer': self.sha(restore.FREEZER)}}}}
        import base64
        public = {'version': 2, 'mongoUri': 'mongodb://MODELED/never-connected',
                  'bridgeSha256': self.sha('/usr/local/libexec/c3-test-owner-restoration-channel.py'),
                  'freshBridgeSha256': self.sha('/usr/local/libexec/c3-test-fresh-owner-restoration-channel.py'),
                  'coordinatorSha256': self.sha(restore.SELF), 'inventorySha256': inventory_sha,
                  'networkPlanSha256': self.network_sha, 'oldBackend': {'instanceId': 'MODELED', 'pid': 42, 'processStartTime': '123'},
                  'plan': {'revision': 7, 'deployedRevision': 6, 'nodes': [{'nodeId': node['nodeId'],
                  'targetProfile': node['targetProfile'], 'enrollmentId': '44444444-4444-4444-8444-444444444444',
                  'ownerGeneration': '55555555-5555-4555-8555-555555555555'}]},
                  'acceptedOriginalsBase64': {node['nodeId']: base64.b64encode(accepted).decode()}}
        self.put('/etc/celerity/topology-test-fresh-owner-settlement.json', restore.canonical(public))
        self.put('/etc/celerity/topology-test-inventory.json', restore.canonical(inventory))
        self.put(restore.CONFIG, restore.canonical(cfg))
        self.policy['files'] = {name: self.sha(name) for name in sources}
        for name, raw in (('/runtime/node', b'modeled executable'), ('/app/index.js', b'modeled application'),
                          ('/etc/classic.json', b'{}')):
            self.put(name, raw); self.policy['files'][name] = self.sha(name)
        self.policy['inventory'].update(networkPlanSha256=self.network_sha,
            coordinatorSha256=restore.sha(restore.canonical(cfg)), sourceSha256=self.sha(restore.SELF))
        self.publish(self.policy)

    def put(self, name, raw):
        path = self.root/'inputs'/name.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw); path.chmod(0o600)
        self.files[name] = path
        return path

    def sha(self, name):
        return fresh.digest(self.files[name].read_bytes())

    def publish(self, policy):
        self.raw = restore.canonical(policy)
        self.put(fresh.POLICY, self.raw)

    def public(self):
        mapping = self.root/'mapping.json'
        mapping.write_text(json.dumps({name: str(path) for name, path in self.files.items()}))
        p = subprocess.run(['node', str(HERE/'ordinary_policy_parser_fixture.js'), str(mapping)],
                           cwd=REPO, capture_output=True, text=True, timeout=5)
        if p.returncode: raise AssertionError(p.stderr)
        return json.loads(p.stdout)

    @contextlib.contextmanager
    def resources(self, policy):
        """Model privileged OS reads, retaining all real Platform checks."""
        sealed = self.root/'sealed'; sealed.mkdir(mode=0o700, exist_ok=True)
        for name in policy['files']:
            path = sealed/name.lstrip('/'); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.files[name].read_bytes()); path.chmod(0o600)
        for directory, _, _ in os.walk(sealed): Path(directory).chmod(0o700)
        proc = self.root/'proc'; proc.mkdir(exist_ok=True)
        status = ''.join(k+':\t0\n' for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))+'NoNewPrivs:\t1\n'
        (proc/'status').write_text(status); (proc/'cgroup').write_text('0::'+fresh.CGROUP)
        if not (proc/'root').exists(): (proc/'root').symlink_to(sealed)
        fd = os.open(sealed, os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
        try:
            s = os.fstat(fd)
            mount_id = int(next(line.split()[1] for line in Path('/proc/self/fdinfo/'+str(fd)).read_text().splitlines() if line.startswith('mnt_id:')))
        finally: os.close(fd)
        mounts = launch_tests.modeled_mounts(mount_id)
        (proc/'mountinfo').write_bytes(mounts)
        route = b'modeled private route'; fib = b'modeled private fib'
        (proc/'net').mkdir(exist_ok=True); (proc/'net/route').write_bytes(route); (proc/'net/fib_trie').write_bytes(fib)
        mapped = sealed/'app/index.js'; info = mapped.stat()
        device = ':'.join(f'{x:02x}' for x in (os.major(info.st_dev), os.minor(info.st_dev)))
        (proc/'maps').write_text(f'1000-2000 r-xp 0000 {device} {info.st_ino} /app/index.js\n')
        policy['inventory'].update(root=[s.st_dev, s.st_ino], mountinfoSha256=fresh.digest(mounts),
                                   routesSha256=fresh.digest(route+fib))
        real_bytes, real_text, real_lstat = Path.read_bytes, Path.read_text, Path.lstat
        real_stat, real_open, real_walk = os.stat, os.open, os.walk
        root_paths = set(policy['files']) | {str(parent) for name in policy['files'] for parent in Path(name).parents}
        def resource(path):
            text = os.fspath(path)
            if text == '/proc/self' or text.startswith('/proc/self/') and not text.startswith('/proc/self/fdinfo/'):
                return proc/text.removeprefix('/proc/self').lstrip('/')
            if text == '/': return sealed
            if text in root_paths:
                return sealed/text.lstrip('/')
            return path
        def root_owned(value):
            class RootOwned:
                def __getattr__(self, key):
                    return 0 if key in ('st_uid', 'st_gid') else getattr(value, key)
            return RootOwned()
        def walk(path, **kwargs):
            assert path == '/'
            for directory, dirs, names in real_walk(sealed, **kwargs):
                yield '/'+str(Path(directory).relative_to(sealed)).removeprefix('.'), dirs, names
        self.reads = []
        def read_bytes(path):
            self.reads.append(str(path)); return real_bytes(Path(resource(path)))
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(Path, 'read_bytes', read_bytes))
            stack.enter_context(patch.object(Path, 'read_text', lambda p, *a, **kw: real_text(Path(resource(p)), *a, **kw)))
            stack.enter_context(patch.object(Path, 'lstat', lambda p, *a, **kw: root_owned(real_lstat(Path(resource(p)), *a, **kw))))
            stack.enter_context(patch.object(os, 'stat', lambda p, *a, **kw: real_stat(resource(p), *a, **kw)))
            stack.enter_context(patch.object(os, 'open', lambda p, *a, **kw: real_open(resource(p), *a, **kw)))
            stack.enter_context(patch.object(os, 'walk', walk))
            stack.enter_context(patch.object(os, 'listxattr', return_value=[]))
            stack.enter_context(patch.object(os, 'readlink', side_effect=lambda p: policy['inventory']['namespaces'][Path(p).name]))
            for name, value in (('geteuid', 65531), ('getegid', 65531), ('getgroups', [])):
                stack.enter_context(patch.object(os, name, return_value=value))
            yield

    def network_binding(self, raw, *, refusal=None):
        preparation = dict(networkPlanSha256=self.network_sha, generation='modeled-generation', ownerInvocationId='e'*32,
                           resourceSealSha256='b'*64, fdManifestSha256='c'*64)
        kernel = SimpleNamespace(accept_serving_live=lambda *args: None)
        owner = control.OwnerRuntime(network, SimpleNamespace(k=kernel, phase='prepared', live=lambda: None),
                                     None, SimpleNamespace(freezer=None), None)
        owner.preparation = preparation; owner.coordinator = {'nonce': 'n', 'pid': os.getpid()}
        owner.store = SimpleNamespace(stage=lambda *args: (_ for _ in ()).throw(FixedInputsReached()))
        serving = {'pid': os.getpid(), 'start': network.proc_start(os.getpid())}
        commit = {'networkHandoff': owner.handoff_binding(), 'nonce': 'n',
                  'restoreIntent': {'origin': {'pid': os.getpid()}}, 'freshPolicySha256': network.digest(raw)}
        commit_raw = network.encode(commit); pin = network.digest(commit_raw)
        blobs = (b'', b'', b'', b'', commit_raw, raw,
                 network.encode({'commitSha256': pin, 'phase': 'confirmed', 'serving': serving}))
        with contextlib.ExitStack() as stack:
            fds = []
            for index, data in enumerate(blobs):
                path = self.root/('rights-'+str(index)); path.write_bytes(data); path.chmod(0o600)
                fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC); fds.append(fd); stack.callback(os.close, fd)
            paths = dict(zip((control.HOST_STATE+'/handoff-commit.json', fresh.POLICY,
                              control.HOST_STATE+'/fresh-launch-attempt.json'), fds[4:]))
            left, right = socket.socketpair(); stack.callback(left.close); stack.callback(right.close)
            left.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))])
            receive = control.receive_rights
            def receive_owned(*args):
                result = receive(*args)
                for fd in result: stack.callback(os.close, fd)
                return result
            real_stat = os.fstat
            def root_stat(fd):
                info = real_stat(fd)
                return SimpleNamespace(**{key: getattr(info, key) for key in
                    ('st_mode', 'st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}, st_uid=0, st_gid=0)
            def fixed_fd(path):
                fd = os.dup(paths[path]); return fd
            stack.enter_context(patch.object(control, 'receive_rights', receive_owned))
            stack.enter_context(patch.object(os, 'fstat', root_stat))
            stack.enter_context(patch.object(network, 'trusted_fd', fixed_fd))
            expected = self.test.assertRaises(FixedInputsReached) if refusal is None else self.test.assertRaisesRegex(*refusal)
            with expected:
                owner.accept_ordinary(right, {'manifest': [], 'serving': serving, 'commitSha256': pin})


class OrdinaryPolicyParityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.fixture = PolicyFixture(Path(self.temp.name), self)

    def test_same_ordinary_policy_crosses_public_real_supervisor_and_network_binding(self):
        f = self.fixture; policy = f.policy
        with f.resources(policy): pass  # prepare independently modeled OS facts
        f.publish(policy)
        self.assertEqual(f.public(), {'accepted': True, 'policySha256': fresh.digest(f.raw)})
        f.network_binding(f.raw)
        print('PUBLIC_PARSER_AND_NETWORK_BINDING_ACCEPTED policySha256='+fresh.digest(f.raw), flush=True)
        with f.resources(policy):
            # No Platform subclass/override. Both pre-listen and pre-exec checks
            # use this method in supervise; exercise it twice on identical input.
            fresh.Platform().check(policy); fresh.Platform().check(policy)
        self.assertIn('/proc/self/mountinfo', f.reads)
        self.assertIn('/app/index.js', f.reads)
        self.assertEqual(restore.canonical(policy), f.raw)

    def test_native_ten_key_inventory_still_passes_real_check(self):
        f = self.fixture; policy = f.policy
        del policy['inventory']['networkPlanSha256']
        with f.resources(policy): fresh.Platform().check(policy)
        self.assertIn('/app/index.js', f.reads)
        config_path = f.files['/etc/celerity/topology-test-fresh-owner-settlement.json']
        config = restore.decode(config_path.read_bytes()); del config['networkPlanSha256']
        config_path.write_bytes(restore.canonical(config)); f.publish(policy)
        self.assertEqual(f.public(), {'accepted': True, 'policySha256': fresh.digest(f.raw)})

    def test_missing_ordinary_pin_is_refused_by_selected_public_and_network_consumers(self):
        f = self.fixture; policy = f.policy
        del policy['inventory']['networkPlanSha256']; f.publish(policy)
        self.assertEqual(f.public(), {'accepted': False, 'error': 'HELD_OWNER_RESTORATION_UNKNOWN_RETAINED'})
        # The network consumer indexes this mandatory selected-ordinary field;
        # missing input refuses before fixed-file/PID1 stage, never a grant.
        f.network_binding(f.raw, refusal=(KeyError, '^\'networkPlanSha256\'$'))

    def test_malformed_ordinary_pins_refuse_before_supervisor_os_reads_and_network_stage(self):
        f = self.fixture
        for value in ('A'*64, 'a'*63, '', 7, None, True, []):
            with self.subTest(value=value):
                policy = copy.deepcopy(f.policy); policy['inventory']['networkPlanSha256'] = value
                with patch.object(os, 'geteuid', side_effect=AssertionError('malformed policy reached OS')):
                    with self.assertRaisesRegex(restore.Refusal, '^INVALID_NETWORK_POLICY_PIN$'):
                        fresh.Platform().check(policy)
                f.publish(policy)
                self.assertEqual(f.public(), {'accepted': False, 'error': 'HELD_OWNER_RESTORATION_UNKNOWN_RETAINED'})
                f.network_binding(f.raw, refusal=(network.Refusal, '^SAME_COMMIT_SERVING_BINDING_REQUIRED$'))

    def test_well_formed_mismatched_pin_is_refused_at_public_and_network_binding(self):
        f = self.fixture; policy = f.policy
        policy['inventory']['networkPlanSha256'] = 'f'*64
        self.assertNotEqual(policy['inventory']['networkPlanSha256'], f.network_sha)
        with f.resources(policy): fresh.Platform().check(policy)
        f.publish(policy)
        self.assertEqual(f.public(), {'accepted': False, 'error': 'HELD_OWNER_RESTORATION_UNKNOWN_RETAINED'})
        f.network_binding(f.raw, refusal=(network.Refusal, '^SAME_COMMIT_SERVING_BINDING_REQUIRED$'))

    def test_unknown_inventory_key_refuses_both_shapes_before_supervisor_os_reads(self):
        for ordinary in (False, True):
            with self.subTest(ordinary=ordinary):
                policy = copy.deepcopy(self.fixture.policy)
                if not ordinary: del policy['inventory']['networkPlanSha256']
                policy['inventory']['unknown'] = 'a'*64
                with patch.object(os, 'geteuid', side_effect=AssertionError('unknown key reached OS')):
                    with self.assertRaisesRegex(restore.Refusal, '^INDEPENDENT_RESOURCE_INVENTORY_REQUIRED$'):
                        fresh.Platform().check(policy)

    def test_existing_file_hash_closure_still_refuses_real_check(self):
        f = self.fixture; policy = f.policy
        with f.resources(policy):
            (f.root/'sealed/app/index.js').write_bytes(b'changed after independent acceptance')
            with self.assertRaisesRegex(restore.Refusal, '^EXECUTABLE_SOURCE_SETTINGS_CLOSURE_DRIFT$'):
                fresh.Platform().check(policy)

    def test_default_supervise_checks_ordinary_policy_before_actual_listen(self):
        f = self.fixture; policy = f.policy
        with f.resources(policy): pass
        f.publish(policy)
        lock_path = f.root/'supervisor.lock'
        class Files:
            fixture = SimpleNamespace(root=f.root)
            @contextlib.contextmanager
            def lock(self, path):
                assert path == fresh.LOCK
                with lock_path.open('a+b') as stream:
                    fcntl.flock(stream, fcntl.LOCK_EX|fcntl.LOCK_NB); yield
            def absent(self, path): return not (f.root/path.lstrip('/')).exists()
            def read_json(self, path):
                assert path == fresh.POLICY
                return restore.decode(f.raw)
        class ListeningReached(Exception): pass
        listener = socket.socket(socket.AF_UNIX); self.addCleanup(listener.close)
        listener.bind(str(f.root/'supervisor.sock'))
        class Listener:
            def listen(self, backlog):
                listener.listen(backlog); raise ListeningReached()
        with f.resources(policy), self.assertRaises(ListeningReached):
            fresh.supervise(Listener(), Files())  # default actual Platform, not a test subclass
        self.assertEqual(restore.canonical(policy), f.raw)
        self.assertFalse((f.root/fresh.SUPERVISOR_ATTEMPT.lstrip('/')).exists())


if __name__ == '__main__': unittest.main()
