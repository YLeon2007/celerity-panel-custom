"""Real journals/flocks/subprocesses; physical kernel, root/SSH are SIMULATED.
Only existing-classic-backend thaw is supported: no runtime/updater/relaunch.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'tests'))
import test_candidate_closure as closure


class BoundedActivationTests(unittest.TestCase):
    put_pid = closure.CandidateClosureTests.put_pid

    def build(self, root, arm=True):
        p, kernel, fence = closure.CandidateClosureTests.build(self, root, arm=arm)
        backend = next(c for c in fence.expected['containers'] if c['cgroup'] == fence.expected['backend'])
        proc = kernel.proc/str(backend['init']['pid'])
        (proc/'ns').mkdir()
        (kernel.proc/'1/ns').mkdir(parents=True)
        for ns in ('mnt','pid','cgroup','net','ipc'):
            (kernel.proc/'1/ns'/ns).symlink_to(ns+':[SIMULATED-HOST]')
            (proc/'ns'/ns).symlink_to(ns+':[SIMULATED-CONTAINER]')
        (proc/'root/proc/1/ns').mkdir(parents=True)
        (proc/'root/proc/1/ns/pid').symlink_to('pid:[SIMULATED-CONTAINER]')
        (proc/'status').write_text(''.join(k+': 0000000000000000\n' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')))
        (proc/'mountinfo').write_text('1 0 0:1 / / rw - overlay overlay rw\n2 1 0:2 / /proc ro - proc proc rw\n3 1 0:3 / /sys/fs/cgroup ro - cgroup2 cgroup ro\n')
        provenance = {'mounts': [], 'binds': None, 'volumesFrom': None,
            'tmpfs': None, 'ipcMode': 'private',
            'shmPath': '/var/lib/docker/containers/'+backend['id']+'/mounts/shm'}
        for inventory in (p['hostHold']['expected'], fence.original, fence.expected):
            next(c for c in inventory['containers'] if c['cgroup'] == inventory['backend'])['mountProvenance'] = json.loads(json.dumps(provenance))
        (kernel.proc/'1/mountinfo').write_text('10 0 8:1 / / rw - ext4 /dev/sda rw\n11 10 0:33 / /dev/shm rw - tmpfs shm rw\n')
        # Only superblock facts are SIMULATED; the production seam uses stat(2).
        kernel.mount_device = lambda path: '0:44' if path.name == 'shm' else '0:1'
        (proc/'task'/str(backend['init']['pid'])).mkdir(parents=True)
        (proc/'fd').mkdir()
        (proc/'fdinfo').mkdir()
        (proc/'cwd').symlink_to(proc/'root', target_is_directory=True)
        return p,kernel,fence

    def test_retained_host_descriptor_or_unchecked_task_refuses_without_touching_fd(self):
        for fault in ('host-fd', 'host-fd-child', 'socket', 'anon-inode', 'fdinfo-only',
                      'thread', 'cwd-host', 'root-host', 'missing-fd-inventory', 'private'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='ih-fd-') as root:
                _, kernel, fence = self.build(root)
                fence.close_candidate(fence.owner)
                backend = next(c for c in fence.expected['containers'] if c['cgroup'] == fence.expected['backend'])
                proc = kernel.proc/str(backend['init']['pid'])
                if fault == 'host-fd-child':
                    pid = 9999
                    self.put_pid(kernel, pid, backend['init']['pid'], backend['init']['pid'], backend['cgroup'])
                    child = kernel.proc/str(pid)
                    (child/'ns').mkdir()
                    for ns in ('mnt','pid','cgroup','net','ipc'):
                        (child/'ns'/ns).symlink_to(ns+':[SIMULATED-CONTAINER]')
                    (child/'status').write_bytes((proc/'status').read_bytes())
                    (child/'root').symlink_to(proc/'root', target_is_directory=True)
                    (child/'cwd').symlink_to(proc/'root', target_is_directory=True)
                    (child/'task'/str(pid)).mkdir(parents=True)
                    (child/'fd').mkdir(); (child/'fdinfo').mkdir()
                    (kernel.group(backend['cgroup'])/'cgroup.procs').write_text(str(backend['init']['pid'])+'\n'+str(pid))
                    proc = child
                if fault in ('host-fd', 'host-fd-child'):
                    target = kernel.group(kernel.candidate)/'cgroup.freeze'
                    descriptor = os.open(target, os.O_WRONLY)
                    self.addCleanup(os.close, descriptor)
                    (proc/'fd/9').symlink_to(target)
                    (proc/'fdinfo/9').write_text('pos:\t0\nflags:\t0100001\nmnt_id:\t999\n')
                if fault in ('socket', 'anon-inode'):
                    (proc/'fd/9').symlink_to('socket:[123]' if fault == 'socket' else 'anon_inode:[io_uring]')
                if fault == 'fdinfo-only': (proc/'fdinfo/9').write_text('mnt_id:\t999\n')
                if fault == 'thread': (proc/'task/9999').mkdir()
                if fault in ('cwd-host', 'root-host'):
                    kernel.mount_device = lambda path: '8:1' if path.name == fault.split('-')[0] else '0:1'
                if fault == 'missing-fd-inventory': (proc/'fd').rmdir()
                before = list(kernel.calls)
                if fault == 'private':
                    kernel.assert_classic_activation_safe(fence.expected)
                else:
                    with self.assertRaises((RuntimeError, FileNotFoundError)):
                        kernel.assert_classic_activation_safe(fence.expected)
                self.assertEqual(kernel.calls,before)
                self.assertNotIn('classicActivation',fence.expected)
                self.assertEqual((kernel.group(kernel.candidate)/'cgroup.freeze').read_text(), '1')

    def test_private_tmpfs_requires_superblock_and_mount_provenance(self):
        for fault in ('host-shm', 'bind-provenance', 'host-ipc', 'missing-provenance',
                      'stat-mismatch', 'missing-host-inventory', 'host-ipc-namespace', 'private'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='ih-k02-') as root:
                _, kernel, fence = self.build(root)
                fence.close_candidate(fence.owner)
                backend = next(c for c in fence.expected['containers'] if c['cgroup'] == fence.expected['backend'])
                mounts = kernel.proc / str(backend['init']['pid']) / 'mountinfo'
                device = '0:33' if fault == 'host-shm' else '0:44'
                mounts.write_text(mounts.read_text()+f'4 1 {device} / /dev/shm rw,nosuid,nodev - tmpfs shm rw,size=65536k\n')
                kernel.mount_device = lambda path: (device if fault != 'stat-mismatch' else '0:55') if path.name == 'shm' else '0:1'
                if fault == 'bind-provenance':
                    backend['mountProvenance']['mounts'] = [{'Type':'bind','Source':'/dev/shm','Destination':'/dev/shm'}]
                if fault == 'host-ipc': backend['mountProvenance']['ipcMode'] = 'host'
                if fault == 'host-ipc-namespace':
                    ipc = kernel.proc/str(backend['init']['pid'])/'ns/ipc'
                    ipc.unlink(); ipc.symlink_to('ipc:[SIMULATED-HOST]')
                if fault == 'missing-provenance': del backend['mountProvenance']
                if fault == 'missing-host-inventory': (kernel.proc/'1/mountinfo').unlink()
                before = list(kernel.calls)
                if fault == 'private':
                    kernel.assert_classic_activation_safe(fence.expected)
                    result = fence.activate_classic(fence.owner, 'a'*64)
                    self.assertEqual(result['code'], 'COMMITTED_BOUNDED_ACTIVATION_CONFIRMED')
                    self.assertEqual(kernel.calls[len(before):], [(backend['cgroup'],False)])
                else:
                    with self.assertRaises((RuntimeError, FileNotFoundError)):
                        kernel.assert_classic_activation_safe(fence.expected)
                    self.assertEqual(kernel.calls, before)
                    self.assertNotIn('classicActivation', fence.expected)
                    self.assertEqual((kernel.group(kernel.candidate)/'cgroup.freeze').read_text(), '1')

    def test_private_mount_check_uses_real_stat_device_not_only_mountinfo(self):
        with tempfile.TemporaryDirectory(prefix='ih-stat-') as root:
            _, kernel, fence = self.build(root)
            backend = next(c for c in fence.expected['containers'] if c['cgroup'] == fence.expected['backend'])
            proc = kernel.proc/str(backend['init']['pid'])
            shm = proc/'root/dev/shm'
            shm.mkdir(parents=True)
            del kernel.mount_device  # Exercise the real stat(2) implementation.
            device = shm.stat().st_dev
            self.assertEqual(kernel.mount_device(shm), f'{os.major(device)}:{os.minor(device)}')
            mounts = proc/'mountinfo'
            unproven = f'{os.major(device)+1}:{os.minor(device)}'
            mounts.write_text(mounts.read_text()+f'4 1 {unproven} / /dev/shm rw - tmpfs shm rw\n')
            with self.assertRaisesRegex(RuntimeError, 'superblock'):
                kernel.assert_classic_activation_safe(fence.expected)

    def test_capture_retains_exact_mount_provenance_not_only_mountinfo_shape(self):
        import test_panel_host_freezer as ft
        fixture = ft.CaptureTests()
        fixture.setUp()
        try:
            row = fixture.rows[0]
            row['HostConfig'].update({'IpcMode':'private','Binds':['/dev/shm:/dev/shm'],
                'VolumesFrom':['foreign'], 'Tmpfs':{'/run':'rw'}})
            row['Mounts'] = [{'Type':'bind','Source':'/dev/shm','Destination':'/dev/shm'}]
            row['ShmPath'] = '/var/lib/docker/containers/'+row['Id']+'/mounts/shm'
            result = fixture.f.m.capture(fixture.f.k)
            captured = next(c for c in result['containers'] if c['id'] == row['Id'])
            self.assertEqual(captured.get('mountProvenance'), {'mounts':row['Mounts'],
                'binds':row['HostConfig']['Binds'], 'volumesFrom':['foreign'], 'tmpfs':{'/run':'rw'},
                'ipcMode':'private', 'shmPath':row['ShmPath']})
            row['Mounts'][0]['Source'] = '/changed'
            self.assertEqual(captured['mountProvenance']['mounts'][0]['Source'], '/dev/shm')
        finally:
            fixture.doCleanups()

    def test_proc_controls_and_aliases_refuse_before_precommit_eligibility(self):
        faults = {
            'writable-proc': None,
            'sysrq': '4 2 0:2 /sysrq-trigger /proc/sysrq-trigger rw - proc proc rw\n',
            'sysctl': '4 2 0:2 /sys /proc/sys rw - proc proc rw\n',
            'readonly-alias': '4 1 0:2 / /sys/alias ro - proc proc rw\n',
            'writable-alias': '4 1 0:2 /sysrq-trigger /sys/alias rw - proc proc rw\n',
            'missing-proc': '',
        }
        for fault, extra in faults.items():
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='ih-k01-') as root:
                _, kernel, fence = self.build(root)
                fence.close_candidate(fence.owner)
                backend = next(c for c in fence.expected['containers'] if c['cgroup'] == fence.expected['backend'])
                mountinfo = kernel.proc / str(backend['init']['pid']) / 'mountinfo'
                safe = mountinfo.read_text().replace('/ /proc rw', '/ /proc ro')
                if fault == 'writable-proc':
                    safe = safe.replace('/ /proc ro', '/ /proc rw')
                if fault == 'missing-proc':
                    safe = ''.join(line+'\n' for line in safe.splitlines() if ' - proc ' not in line)
                mountinfo.write_text(safe + (extra or ''))
                before = list(kernel.calls)
                journal = fence.journal.path.joinpath('hold.json').read_bytes()
                # Same predicate is called by prepare-classic before COMMIT.
                with self.assertRaisesRegex(RuntimeError, 'proc'):
                    kernel.assert_classic_activation_safe(fence.expected)
                self.assertEqual(kernel.calls, before)
                self.assertEqual(fence.journal.path.joinpath('hold.json').read_bytes(), journal)
                self.assertNotIn('classicActivation', fence.expected)

    def test_host_network_or_privileged_existing_child_refuse_activation_safety(self):
        for fault in ('host-network', 'privileged-child', 'host-network-child'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='ih-') as root:
                _,kernel,fence = self.build(root)
                backend = next(c for c in fence.expected['containers'] if c['cgroup'] == fence.expected['backend'])
                proc = kernel.proc/str(backend['init']['pid'])
                if fault == 'host-network':
                    (proc/'ns/net').unlink(); (proc/'ns/net').symlink_to('net:[SIMULATED-HOST]')
                else:
                    pid = 9999
                    self.put_pid(kernel,pid,backend['init']['pid'],backend['init']['pid'],backend['cgroup'])
                    child = kernel.proc/str(pid); (child/'ns').mkdir()
                    for ns in ('mnt','pid','cgroup','net','ipc'):
                        (child/'ns'/ns).symlink_to(ns+':[SIMULATED-CONTAINER]')
                    caps = '0000000000200000' if fault == 'privileged-child' else '0000000000000000'
                    (child/'status').write_text(''.join(k+': '+caps+'\n' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')))
                    if fault == 'host-network-child':
                        (child/'ns/net').unlink(); (child/'ns/net').symlink_to('net:[SIMULATED-HOST]')
                    (kernel.group(backend['cgroup'])/'cgroup.procs').write_text(str(backend['init']['pid'])+'\n'+str(pid))
                with self.assertRaisesRegex(RuntimeError,'namespace|capability'):
                    kernel.assert_classic_activation_safe(fence.expected)

    def test_host_bind_escape_refuses_before_writer_enable(self):
        with tempfile.TemporaryDirectory(prefix='ih-') as root:
            _,kernel,fence = self.build(root)
            fence.close_candidate(fence.owner)
            backend = next(c for c in fence.expected['containers'] if c['cgroup'] == fence.expected['backend'])
            mounts = kernel.proc/str(backend['init']['pid'])/'mountinfo'
            mounts.write_text(mounts.read_text()+'4 1 8:1 /var/lib/c3-test-node-isolation /host-state rw - ext4 /dev/sda rw\n')
            before = list(kernel.calls)
            with self.assertRaisesRegex(RuntimeError, 'bind/volume'):
                fence.activate_classic(fence.owner,'a'*64)
            self.assertEqual(kernel.calls,before)

    def test_existing_backend_child_host_namespace_is_not_authorized_by_safe_init(self):
        with tempfile.TemporaryDirectory(prefix='ih-') as root:
            _,kernel,fence = self.build(root)
            backend = next(c for c in fence.expected['containers'] if c['cgroup'] == fence.expected['backend'])
            pid = backend['init']['pid'] + 9000
            self.put_pid(kernel,pid,backend['init']['pid'],backend['init']['pid'],backend['cgroup'])
            group = kernel.group(backend['cgroup'])/'cgroup.procs'
            group.write_text(group.read_text()+'\n'+str(pid))
            child = kernel.proc/str(pid)
            (child/'ns').mkdir()
            for ns in ('mnt','pid','cgroup'):
                (child/'ns'/ns).symlink_to(ns+':[SIMULATED-HOST]')
            with self.assertRaisesRegex(RuntimeError,'namespace'):
                kernel.assert_classic_activation_safe(fence.expected)

    def test_only_existing_backend_is_enabled_and_candidate_runtime_stay_frozen(self):
        with tempfile.TemporaryDirectory(prefix='ih-') as root:
            _, kernel, fence = self.build(root)
            fence.close_candidate(fence.owner)
            self.assertTrue(hasattr(fence, 'activate_classic'), 'bounded committed activation missing')
            before = list(kernel.calls)
            result = fence.activate_classic(fence.owner, 'a'*64)
            self.assertEqual(kernel.calls[len(before):], [(fence.expected['backend'], False)])
            self.assertEqual(result['code'], 'COMMITTED_BOUNDED_ACTIVATION_CONFIRMED')
            self.assertNotIn('hostFence', result)
            self.assertIn(fence.expected['candidateClosure']['group'], fence.frozen)
            self.assertTrue(set(fence.expected['controls']) <= set(fence.frozen))
            self.assertIn('relaunch', fence.expected)
            with self.assertRaises(RuntimeError):
                fence.activate_classic(fence.owner, 'a'*64)
            with self.assertRaisesRegex(RuntimeError, 'candidate closure'):
                fence.restore(fence.owner)

    def test_timeout_after_actual_write_zero_is_committed_unknown_never_retry_or_refreeze(self):
        with tempfile.TemporaryDirectory(prefix='ih-') as root:
            _, kernel, fence = self.build(root)
            fence.close_candidate(fence.owner)
            self.assertTrue(hasattr(fence, 'activate_classic'), 'bounded committed activation missing')
            before = list(kernel.calls)
            freeze = kernel.freeze
            def lost_ack(group, value):
                freeze(group, value)
                if value is False:
                    raise TimeoutError('SIMULATED lost acknowledgement AFTER effect')
            with patch.object(kernel, 'freeze', side_effect=lost_ack):
                with self.assertRaises(TimeoutError):
                    fence.activate_classic(fence.owner, 'a'*64)
            self.assertEqual(kernel.calls[len(before):], [(fence.expected['backend'], False)])
            self.assertEqual(fence.phase, 'committed-activation-unknown')
            self.assertEqual(json.loads((Path(root) / 'journal/hold.json').read_bytes())['phase'], 'committed-activation-unknown')
            self.assertIn(fence.expected['candidateClosure']['group'], fence.frozen)
            with self.assertRaises(RuntimeError):
                fence.activate_classic(fence.owner, 'a'*64)

    def test_missing_candidate_closure_or_killed_backend_never_enable(self):
        for variant in ('open', 'killed'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(prefix='ih-') as root:
                _, kernel, fence = self.build(root)
                self.assertTrue(hasattr(fence, 'activate_classic'), 'bounded committed activation missing')
                if variant == 'killed':
                    fence.close_candidate(fence.owner)
                    with patch.object(kernel, 'kill'), patch.object(kernel, 'verify'):
                        fence.terminate(fence.owner, 'KILL_EXACT_OLD_BACKEND')
                before = list(kernel.calls)
                with self.assertRaises(RuntimeError):
                    fence.activate_classic(fence.owner, 'a'*64)
                self.assertEqual(kernel.calls, before)
    def test_all_five_commit_is_no_replay_durable_before_any_activation(self):
        import uuid
        import test_coordinated_restore as ct
        c = ct.load_c()
        with combined_fixture(c) as f:
            with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope() as held:
                self.assertTrue(hasattr(held, 'commit_handoff'), 'actual all-five COMMIT missing')
                proof = {'context': f.config['context'], 'revision': 7, 'deployedRevision': 6, 'quietSha256': 'd'*64, 'nodes': []}
                for node, pin in f.config['nodes'].items():
                    before, after = str(uuid.uuid4()), str(uuid.uuid4())
                    proof['nodes'].append({'nodeId': node, 'targetProfile': pin['identity']['targetProfile'],
                        'enrollmentId': str(uuid.uuid4()), 'enrollmentSha256': 'c'*64,
                        'priorOwnerGeneration': before, 'owner': {'owner': 'classic', 'generation': after,
                         'nodeIdentity': {k: pin['identity'][k] for k in ('machineId','sshHostKeySha256')},
                         'handbackReceipt': {'fromGeneration': before, 'toGeneration': after}}})
                commit = held.commit_handoff(proof)
                row = f.fs.read_json(c.COMMIT)
                self.assertEqual(row['settlement'], proof)
                self.assertEqual(row['nonce'], held.nonce)
                self.assertEqual(row['nodePeers'].keys(), f.config['nodes'].keys())
                self.assertEqual(commit, c.sha(f.fs.read(c.COMMIT)[0]))
                self.assertTrue(f.fs.absent(c.ACTIVATION))
                with self.assertRaises(RuntimeError):
                    held.commit_handoff(proof)
                self.assertEqual(f.fs.read_json(c.COMMIT), row)


def settlement_proof(f, c):
    import uuid
    proof = {'context': f.config['context'], 'revision': 7, 'deployedRevision': 6, 'quietSha256': 'd'*64, 'nodes': []}
    for node, pin in f.config['nodes'].items():
        before, after = str(uuid.uuid4()), str(uuid.uuid4())
        proof['nodes'].append({'nodeId': node, 'targetProfile': pin['identity']['targetProfile'],
            'enrollmentId': str(uuid.uuid4()), 'enrollmentSha256': 'c'*64,
            'priorOwnerGeneration': before, 'owner': {'owner': 'classic', 'generation': after,
                'nodeIdentity': {k: pin['identity'][k] for k in ('machineId','sshHostKeySha256')},
                'handbackReceipt': {'fromGeneration': before, 'toGeneration': after}}})
    return proof


def combined_fixture(c):
    import test_coordinated_restore as ct
    import subprocess
    class Combined(ct.cfixture):
        def __enter__(self):
            super().__enter__()
            atomic = self.fs.atomic
            def alias(path, raw, *args, **kwargs):
                result = atomic(path, raw, *args, **kwargs)
                if path == c.COMMIT:
                    # SIMULATED same-physical-host alias. Actual local node and
                    # coordinator read the SAME path, not a sixth host.
                    self.fixtures[-1].put(c.COMMIT, raw)
                return result
            self.fs.atomic = alias
            return self
        def spawn(self, node):
            f = self.fixtures[list(self.config['nodes']).index(node)]
            old = "shared=SimpleNamespace(check_hold=lambda *_:{'candidateClosure':{'group':'SIMULATED'}} if fs.read_json('/fixture-live.json')['candidateFrozen'] else {})"
            new = """def shared_check(*args, **kw):
 if kw.get('command') == 'activate-classic':
  raw=fs.read(c.COMMIT)[0]
  assert c.sha(raw)==kw['commit_sha']
  (root/'classic-activated').write_text(kw['commit_sha'])
 return {'candidateClosure':{'group':'SIMULATED'}} if fs.read_json('/fixture-live.json')['candidateFrozen'] else {}
shared=SimpleNamespace(check_hold=shared_check)"""
            code = ct.CHILD.replace(old, new)
            assert code != ct.CHILD
            child = subprocess.Popen([sys.executable, '-B', '-c', code, str(f.root)], cwd=HERE,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            self.children.append(child)
            return child
    return Combined(c)


class CombinedProtocolTests(unittest.TestCase):
    def test_real_owner_bridge_root_peer_grammar_completes_and_exits_naturally(self):
        import socket
        import subprocess
        import threading
        import test_coordinated_restore as ct
        c = ct.load_c()
        with combined_fixture(c) as f:
            sock = f.root/'o.sock'
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(sock)); listener.listen(1)
            f.fs.atomic('/proof.json', c.canonical(settlement_proof(f,c)), new=True)
            code = '''import os,sys
from pathlib import Path
import test_node_originals as t
import coordinated_restore as c
import owner_restoration_channel as b
fs=t.n.Files(t.n.Fixture(Path(sys.argv[1]),os.getuid(),os.getgid(),None))
channel=c.RestorationChannel(fs,fixture_socket=sys.argv[2])
try:
 channel.__enter__()
 b.serve(channel,lifetime=30)
finally:
 channel.close()
'''
            child = None
            def launch():
                return subprocess.Popen([sys.executable,'-B','-c',code,str(f.root),str(sock)], cwd=HERE,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            errors = []
            def operator():
                try:
                    for op in ('check','commit-handoff','activate-classic','complete-handoff'):
                        request = {'version':1,'op':op,'nonce':os.urandom(32).hex()}
                        if op == 'commit-handoff': request['proof'] = f.fs.read_json('/proof.json')
                        child.stdin.write(c.canonical(request)+b'\n'); child.stdin.flush()
                        reply = c.decode(child.stdout.readline())
                        self.assertEqual(reply['nonce'],request['nonce'])
                        self.assertEqual(reply['op'], 'checked' if op=='check' else op+'-ack')
                except BaseException as error: errors.append(error)
            thread = threading.Thread(target=operator)
            try:
                with c.Coordinator(f.config,f.fs,f.spawn,origin=f.origin).restore_scope() as held:
                    child = launch()
                    thread.start(); held.serve_owner(listener); thread.join(5)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(errors, [])
                out,err=child.communicate(timeout=5)
                self.assertEqual((child.returncode,out,err),(0,b'',b''))
            finally:
                listener.close()
                if child is not None and child.poll() is None: child.kill(); child.communicate(timeout=3)
                if thread.ident is not None: thread.join(5)

    def test_actual_all_five_hold_commit_activation_and_finite_natural_node_exit(self):
        import fcntl
        import test_coordinated_restore as ct
        c = ct.load_c()
        with combined_fixture(c) as f:
            with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope() as held:
                digest = held.commit_handoff(settlement_proof(f, c))
                self.assertFalse((f.fixtures[-1].root/'classic-activated').exists())
                held.activate_classic()
                self.assertEqual((f.fixtures[-1].root/'classic-activated').read_text(), digest)
                # Classic may legitimately change a restored local config AFTER
                # COMMIT; postcommit checks retain guards/admission/OFD, not an
                # eternal original-snapshot equality requirement.
                f.fixtures[-1].put(f.fixtures[-1].config, b'{"classic":true}')
                held.check()
                held.finish_handoff()
                self.assertTrue(held.handoff_completed)
                self.assertTrue(all(p.returncode == 0 for p in f.children))
            for node in f.fixtures:
                self.assertEqual(node.fs.read_json(ct.t.n.ADMISSION)['state'], 'closed')
                for profile in node.writer.profiles:
                    with open(node.path(ct.t.n.runner_lock(profile)), 'rb') as unlocked:
                        fcntl.flock(unlocked, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(f.fs.read_json(c.COMMIT)['activationSet'], ['existing-classic-backend'])
            self.assertEqual(f.fs.read_json(c.ACTIVATION)['confirmed'], [c.SHARED_NODE])

    def test_commit_fsync_unknown_never_enables_and_existing_run_never_replays(self):
        import test_coordinated_restore as ct
        c = ct.load_c()
        for fault in ('before-write', 'after-durable-write'):
            with self.subTest(fault=fault), combined_fixture(c) as f:
                with c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin).restore_scope() as held:
                    atomic = f.fs.atomic
                    def fail(path, *args, **kw):
                        if path == c.COMMIT:
                            if fault == 'after-durable-write': atomic(path, *args, **kw)
                            raise OSError('SIMULATED lost fsync acknowledgement')
                        return atomic(path, *args, **kw)
                    with patch.object(f.fs, 'atomic', side_effect=fail):
                        with self.assertRaises(OSError): held.commit_handoff(settlement_proof(f,c))
                    self.assertTrue(held.commit_attempted)
                    self.assertIsNone(held.commit_sha)
                    with self.assertRaises(RuntimeError): held.activate_classic()
                    with self.assertRaises(RuntimeError): held.commit_handoff(settlement_proof(f,c))
                    self.assertTrue(f.fs.absent(c.ACTIVATION))
                    self.assertFalse((f.fixtures[-1].root/'classic-activated').exists())
                    held.check()

    def test_postcommit_nonselected_guard_loss_stops_before_any_writer_enable(self):
        import test_coordinated_restore as ct
        c = ct.load_c()
        with combined_fixture(c) as f:
            held = c.Coordinator(f.config, f.fs, f.spawn, origin=f.origin)
            with self.assertRaises(RuntimeError) as failed:
                with held.restore_scope():
                    held.commit_handoff(settlement_proof(f,c))
                    f.fixtures[0].put('/fixture-live.json', c.canonical({'held':False,'candidateFrozen':True}))
                    held.activate_classic()
            self.assertEqual(failed.exception.code, 'COMMITTED_ACTIVATION_UNKNOWN')
            self.assertFalse(f.fs.absent(c.COMMIT))
            self.assertTrue(f.fs.absent(c.ACTIVATION))
            self.assertFalse((f.fixtures[-1].root/'classic-activated').exists())
class RootGuardActivationTests(unittest.TestCase):
    build = BoundedActivationTests.build
    put_pid = BoundedActivationTests.put_pid

    def test_actual_shared_root_guard_dispatches_only_same_holder_committed_backend(self):
        self.exercise_guard()

    def test_actual_prepare_classic_refuses_kernel_faults_before_commit_exists(self):
        for fault in ('proc-control', 'host-shm', 'host-fd'):
            with self.subTest(fault=fault):
                self.exercise_guard(fault)

    def exercise_guard(self, fault=None):
        import multiprocessing
        import time
        s,m,freezer = closure.s,closure.m,closure.f
        real_peer = s.peer_identity
        def uid(conn):
            pid,_,gid=real_peer(conn)
            return pid,0,gid  # only UID/SSH/kernel facts are SIMULATED
        class Host:
            def operator_session(self):
                return {k:m.proc_identity(os.getppid())[k] for k in ('pid','start')}
            def guard_check(self,*args): pass
        with tempfile.TemporaryDirectory(prefix='ihg-') as root:
            p,kernel,_ = self.build(root,arm=False)
            backend = next(c for c in p['hostHold']['expected']['containers'] if c['cgroup'] == p['hostHold']['expected']['backend'])
            proc = kernel.proc/str(backend['init']['pid'])
            if fault == 'proc-control':
                mounts = proc/'mountinfo'
                mounts.write_text(mounts.read_text()+'4 2 0:2 /sysrq-trigger /proc/sysrq-trigger rw - proc proc rw\n')
            if fault == 'host-shm':
                mounts = proc/'mountinfo'
                mounts.write_text(mounts.read_text()+'4 1 0:33 / /dev/shm rw - tmpfs shm rw\n')
            if fault == 'host-fd':
                target = kernel.group(kernel.candidate)/'cgroup.freeze'
                descriptor = os.open(target,os.O_WRONLY)
                self.addCleanup(os.close,descriptor)
                (proc/'fd/9').symlink_to(target)
                (proc/'fdinfo/9').write_text('flags:\t0100001\nmnt_id:\t999\n')
            kernel.journal_path=Path(root)/'host/hold.json'
            m.atomic_json(root,'guard.json',{'fixture':True})
            readfd,writefd=os.pipe()
            def guard():
                os.close(writefd)
                with patch.object(freezer,'capture',return_value=p['hostHold']['expected']), \
                     patch.object(s,'peer_identity',side_effect=uid), \
                     patch.object(m,'secure_file',side_effect=lambda path:Path(path).read_bytes()):
                    try: s.serve_hold(p,root,m,freezer,kernel,Host(),readfd)
                    except m.Refusal as e:
                        if str(e) != 'HOST_CONTROLLER_CHANNEL_LOST': raise
                    except RuntimeError as e:
                        if fault is None: raise
                        (Path(root)/'kernel-refusal').write_text(str(e))
            child=multiprocessing.get_context('fork').Process(target=guard)
            child.start();os.close(readfd)
            try:
                deadline=time.monotonic()+5
                while not (Path(root)/'host-guard.json').exists() and child.is_alive() and time.monotonic()<deadline:
                    time.sleep(.01)
                self.assertTrue((Path(root)/'host-guard.json').exists())
                with patch.object(s,'peer_identity',side_effect=uid), \
                     patch.object(s,'load_freezer',return_value=(freezer,kernel)), \
                     patch.object(m,'secure_file',side_effect=lambda path:Path(path).read_bytes()):
                    s.check_hold(p,root,m,command='close-candidate')
                    if fault:
                        with self.assertRaisesRegex(m.Refusal,'HOST_GUARD_LOST'):
                            s.check_hold(p,root,m,command='prepare-classic')
                        child.join(5)
                        self.assertFalse(child.is_alive()); self.assertEqual(child.exitcode,0)
                        self.assertRegex((Path(root)/'kernel-refusal').read_text(), 'proc|host-backed|descriptor')
                        self.assertFalse((Path(root)/'handoff-commit.json').exists())
                        self.assertEqual(json.loads(kernel.journal_path.read_bytes())['phase'],'unknown')
                        for group in [*p['hostHold']['expected']['freezeOrder'],kernel.candidate]:
                            self.assertEqual((kernel.group(group)/'cgroup.freeze').read_text(),'1')
                        return
                    s.check_hold(p,root,m,command='prepare-classic')
                    # This unit fixture isolates same-peer/commit-file dispatch;
                    # separate five-node tests produce the actual durable COMMIT.
                    commit={'context':p['context'],'activationSet':['existing-classic-backend'],
                        'nodePeers':{s.NODE:{k:m.proc_identity(os.getpid())[k] for k in ('pid','start')}},
                        'nodePins':{s.NODE:{'identity':{'planHash':s.plan_hash(p,m)}}}}
                    m.atomic_json(root,'handoff-commit.json',commit)
                    digest=m.digest((Path(root)/'handoff-commit.json').read_bytes())
                    active=s.check_hold(p,root,m,command='activate-classic',commit_sha=digest)
                    self.assertEqual(active['classicActivation']['commitSha256'],digest)
                    self.assertEqual((kernel.group(active['backend'])/'cgroup.freeze').read_text(),'0')
                    self.assertEqual((kernel.group(kernel.candidate)/'cgroup.freeze').read_text(),'1')
                    for group in active['controls']:
                        self.assertEqual((kernel.group(group)/'cgroup.freeze').read_text(),'1')
                    self.assertIn('relaunch',active)
                    s.check_hold(p,root,m)
                os.close(writefd);writefd=None
                child.join(5);self.assertFalse(child.is_alive());self.assertEqual(child.exitcode,0)
                self.assertEqual(json.loads(kernel.journal_path.read_bytes())['phase'],'committed-activation-unknown')
            finally:
                if writefd is not None: os.close(writefd)
                if child.is_alive():child.kill();child.join(3)
class RealReleaseBoundaryTests(unittest.TestCase):
    build = BoundedActivationTests.build
    put_pid = BoundedActivationTests.put_pid

    def writer(self,kernel,fence,root,ack):
        import subprocess
        group=kernel.group(fence.expected['backend'])
        effect=Path(root)/'classic-effect'
        script = '''import os,sys,time
from pathlib import Path
freeze,event,effect=map(Path,sys.argv[1:4])
print('ready',flush=True)
deadline=time.monotonic()+5
while freeze.read_text()!='0':
 if time.monotonic()>deadline:raise SystemExit(74)
 time.sleep(.001)
with open(effect,'xb') as out:
 out.write(b'classic executed after committed enable');out.flush();os.fsync(out.fileno())
if sys.argv[4]=='ack':event.write_text('frozen 0\\npopulated 1\\n')
'''
        process=subprocess.Popen([sys.executable,'-B','-c',script,str(group/'cgroup.freeze'),str(group/'cgroup.events'),str(effect),ack],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.assertEqual(process.stdout.readline().strip(),'ready')
        def cleanup():
            if process.poll() is None:process.kill()
            process.communicate(timeout=3)
        self.addCleanup(cleanup)
        return process,effect

    def test_actual_linux_freeze_timeout_after_write_zero_never_claims_classic_retained(self):
        with tempfile.TemporaryDirectory(prefix='ihb-') as root:
            _,kernel,fence=self.build(root);fence.close_candidate(fence.owner)
            process,effect=self.writer(kernel,fence,root,'no-ack')
            kernel.timeout=.3
            with patch.object(kernel,'freeze',side_effect=lambda g,v:closure.f.LinuxKernel.freeze(kernel,g,v)):
                with self.assertRaises(TimeoutError):fence.activate_classic(fence.owner,'a'*64)
            process.communicate(timeout=3);self.assertEqual(process.returncode,0)
            self.assertTrue(effect.exists());self.assertEqual(fence.phase,'committed-activation-unknown')
            self.assertEqual((kernel.group(kernel.candidate)/'cgroup.freeze').read_text(),'1')
            with self.assertRaises(RuntimeError):fence.activate_classic(fence.owner,'a'*64)

    def test_actual_fsync_failure_after_enable_retains_no_replay_intent_not_false_success(self):
        with tempfile.TemporaryDirectory(prefix='ihb-') as root:
            _,kernel,fence=self.build(root);fence.close_candidate(fence.owner)
            process,effect=self.writer(kernel,fence,root,'ack')
            sync=closure.f.os.fsync
            def fail(fd):
                if (kernel.group(fence.expected['backend'])/'cgroup.freeze').read_text()=='0':
                    raise OSError('SIMULATED fsync syscall error AFTER actual write zero')
                return sync(fd)
            with patch.object(kernel,'freeze',side_effect=lambda g,v:closure.f.LinuxKernel.freeze(kernel,g,v)), patch.object(closure.f.os,'fsync',side_effect=fail):
                with self.assertRaises(FileExistsError):fence.activate_classic(fence.owner,'a'*64)
            process.communicate(timeout=3);self.assertTrue(effect.exists())
            self.assertTrue((Path(root)/'journal/next.json').exists())
            self.assertEqual(fence.phase,'committed-activation-unknown')
            self.assertEqual((kernel.group(kernel.candidate)/'cgroup.freeze').read_text(),'1')

    def test_sigkill_after_actual_enable_preserves_durable_attempt_and_candidate_freeze(self):
        import multiprocessing
        import time
        with tempfile.TemporaryDirectory(prefix='ihb-') as root:
            _,kernel,fence=self.build(root);fence.close_candidate(fence.owner)
            process,effect=self.writer(kernel,fence,root,'no-ack');kernel.timeout=5
            with patch.object(kernel,'freeze',side_effect=lambda g,v:closure.f.LinuxKernel.freeze(kernel,g,v)):
                controller=multiprocessing.get_context('fork').Process(target=fence.activate_classic,args=(fence.owner,'a'*64))
                controller.start()
                try:
                    deadline=time.monotonic()+3
                    while not effect.exists() and controller.is_alive() and time.monotonic()<deadline:time.sleep(.001)
                    self.assertTrue(effect.exists());controller.kill();controller.join(3)
                    self.assertEqual(controller.exitcode,-9)
                finally:
                    if controller.is_alive():controller.kill();controller.join(3)
            process.communicate(timeout=3)
            row=json.loads((Path(root)/'journal/hold.json').read_bytes())
            self.assertEqual(row['phase'],'intent')
            self.assertEqual(row['expected']['classicActivation']['commitSha256'],'a'*64)
            self.assertEqual(row['pending']['action'],'activate-classic-backend')
            self.assertEqual((kernel.group(kernel.candidate)/'cgroup.freeze').read_text(),'1')
            for group in fence.expected['controls']:
                self.assertEqual((kernel.group(group)/'cgroup.freeze').read_text(),'1')
            with self.assertRaises(FileExistsError):closure.f.Journal(Path(root)/'journal')


if __name__ == '__main__':
    unittest.main()
