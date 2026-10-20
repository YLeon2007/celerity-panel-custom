"""Adversarial controller tests. Fake kernel is NOT host/remote evidence."""
import copy
import importlib.util
import pathlib
import unittest
import tempfile
import os
from unittest.mock import patch

PATH = pathlib.Path(__file__).parents[1] / 'panel-host-freezer.py'


def load():
    spec = importlib.util.spec_from_file_location('panel_host_freezer', PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class MemoryJournal:
    def __init__(self):
        self.rows = []
    def save(self, row):
        self.rows.append(copy.deepcopy(row))


class Kernel:
    def __init__(self):
        self.frozen = set()
        self.dead = False
        self.unknown = False
        self.effects = []
        self.groups = ['updater', 'docker', 'containerd', 'backend']
    def verify(self, expected, frozen, dead=False):
        if self.unknown or set(frozen) != self.frozen or dead != self.dead:
            raise RuntimeError('kernel identity/freezer drift')
    def freeze(self, group, value):
        self.effects.append(('freeze', group, value))
        (self.frozen.add if value else self.frozen.remove)(group)
    def prepare_relaunch(self, expected, owner, persist):
        return None
    def restore_relaunch(self, expected, persist):
        return None
    def split_proxies(self, expected, owner, persist):
        pass
    def restore_proxies(self, expected, persist):
        pass
    def kill(self, group):
        self.effects.append(('kill', group))
        self.dead = True


class Tests(unittest.TestCase):
    def test_real_arm_freezes_control_plane_before_backend(self):
        self.assertTrue(PATH.exists(), 'executable host freezer is missing')
        m = load()
        k, j = Kernel(), MemoryJournal()
        expected = {'freezeOrder': k.groups}
        f = m.Fence(expected, k, j, 'owner')
        f.arm()
        self.assertEqual(k.effects, [('freeze', x, True) for x in k.groups])
        self.assertEqual(f.check()['hostFence'], 'held')
        self.assertEqual(f.check()['nodeState'], 'unknown')
        self.assertEqual(f.check()['oldExecutor'], 'frozen')
        self.assertTrue(all(j.rows[i]['phase'] == 'intent' for i in (0, 2, 4, 6)))
    def test_kill_requires_live_frozen_guard_and_exact_ack(self):
        m = load()
        k, j = Kernel(), MemoryJournal()
        f = m.Fence({'freezeOrder': k.groups, 'backend': 'backend'}, k, j, 'owner')
        with self.assertRaises(RuntimeError):
            f.terminate('owner', 'KILL_EXACT_OLD_BACKEND')
        f.arm()
        for owner, ack in [('foreign', 'KILL_EXACT_OLD_BACKEND'), ('owner', 'yes')]:
            with self.assertRaises(RuntimeError):
                f.terminate(owner, ack)
        f.terminate('owner', 'KILL_EXACT_OLD_BACKEND')
        self.assertEqual(k.effects[-1], ('kill', 'backend'))
        self.assertEqual(f.check()['oldExecutor'], 'empty')
        with self.assertRaises(RuntimeError):
            f.restore('owner')
        self.assertEqual(k.frozen, set(k.groups))

    def test_unknown_is_sticky_and_never_thaws_even_if_kernel_recovers(self):
        m = load()
        k, j = Kernel(), MemoryJournal()
        expected = {'freezeOrder': k.groups}
        f = m.Fence(expected, k, j, 'owner')
        f.arm()
        k.unknown = True
        with self.assertRaises(RuntimeError):
            f.check()
        k.unknown = False
        with self.assertRaises(RuntimeError):
            f.check()
        with self.assertRaises(RuntimeError):
            f.restore('owner')
        self.assertEqual(k.frozen, set(k.groups))
        self.assertEqual(j.rows[-1]['phase'], 'unknown')

    def test_only_explicit_known_nondestructive_restore_thaws_in_reverse(self):
        m = load()
        k, j = Kernel(), MemoryJournal()
        expected = {'freezeOrder': k.groups}
        f = m.Fence(expected, k, j, 'owner')
        f.arm()
        f.restore('owner')
        self.assertEqual(k.effects[4:], [('freeze', x, False) for x in reversed(k.groups)])
        self.assertEqual(f.phase, 'restored')
        with self.assertRaises(RuntimeError):
            f.arm()
        with self.assertRaises(RuntimeError):
            f.check()

    def test_relaunch_parent_is_held_even_before_old_service_freezers(self):
        m = load()
        k, j = Kernel(), MemoryJournal()
        def prepare(expected, owner, persist):
            k.frozen.add('replacement-parent')
            return 'replacement-parent'
        def restore(expected, persist):
            k.frozen.remove('replacement-parent')
            return 'replacement-parent'
        k.prepare_relaunch, k.restore_relaunch = prepare, restore
        f = m.Fence({'freezeOrder': k.groups}, k, j, 'owner')
        f.arm()
        self.assertEqual(f.frozen[0], 'replacement-parent')
        f.restore('owner')
        self.assertEqual(k.frozen, set())

    def test_proxy_partition_is_held_and_reversed_only_before_nondestructive_thaw(self):
        m = load()
        k, j = Kernel(), MemoryJournal()
        k.split_proxies = lambda expected, owner, persist: k.effects.append(('split-proxy',))
        k.restore_proxies = lambda expected, persist: k.effects.append(('return-proxy',))
        f = m.Fence({'freezeOrder': k.groups}, k, j, 'owner')
        f.arm()
        self.assertEqual(k.effects[-1], ('split-proxy',))
        f.restore('owner')
        self.assertEqual(k.effects[5], ('return-proxy',))
        self.assertEqual(k.effects[6:], [('freeze', x, False) for x in reversed(k.groups)])

    def test_unrelated_proc_disappearance_does_not_reuse_previous_runtime_comm(self):
        m = load()
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            # Ordered numeric processes: real runtime then a vanished unrelated PID.
            p = root / '10'
            p.mkdir()
            (p / 'comm').write_text('dockerd\n')
            (p / 'exe').symlink_to('/usr/bin/dockerd')
            (root / '11').mkdir()
            k = m.LinuxKernel(proc=root)
            k.pid = lambda pid: {'pid': pid}
            k.proc = type('Proc', (), {'iterdir': lambda self: iter([p, root / '11'])})()
            self.assertEqual(k.runtime(), [{'pid': 10}])

    def test_timeout_partial_freeze_retains_hold_and_unknown_intent(self):
        m = load()
        k, j = Kernel(), MemoryJournal()
        original = k.freeze
        def partial(group, value):
            original(group, value)
            if group == 'docker':
                raise TimeoutError('frozen acknowledgement timeout')
        k.freeze = partial
        f = m.Fence({'freezeOrder': k.groups}, k, j, 'owner')
        with self.assertRaises(TimeoutError):
            f.arm()
        self.assertEqual(k.frozen, {'updater', 'docker'})
        self.assertEqual(j.rows[-1]['phase'], 'unknown')
        self.assertEqual(j.rows[-1].get('pending'), {'action': 'freeze', 'group': 'docker'})
        with self.assertRaises(RuntimeError):
            f.restore('owner')


class ProcFixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        root = pathlib.Path(self.tmp.name)
        self.m = load()
        self.proc, self.cg = root / 'proc', root / 'cg'
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        (self.proc / 'sys/kernel/random/boot_id').write_text('boot-1')
        self.machine = root / 'machine'
        self.machine.write_text('fixture-machine')
        self.k = self.m.LinuxKernel(proc=self.proc, cgroup=self.cg, machine=self.machine, timeout=.02)
        self.old = '/system.slice/docker-' + 'a' * 64 + '.scope'
        self.updater = '/system.slice/docker-' + 'b' * 64 + '.scope'
        self.survivor = '/system.slice/docker-' + 'c' * 64 + '.scope'
        controls = self.m.CONTROL[:]
        self.group(controls[0], [10])
        self.group(controls[1], [20, 21])
        self.group(controls[1] + '/accepted-child', [22])
        self.group(self.old, [30])
        self.group(self.updater, [40])
        self.group(self.survivor, [50])
        for pid, exe, cg in [(10, 'dockerd', controls[0]), (20, 'containerd', controls[1]),
                              (21, 'containerd-shim-runc-v2', controls[1]),
                              (22, 'runc', controls[1] + '/accepted-child'),
                              (30, 'node', self.old), (40, 'node', self.updater),
                              (50, 'mongod', self.survivor)]:
            self.pid(pid, exe, cg)
        (self.proc / '21/cmdline').write_bytes(b'containerd-shim-runc-v2\0-namespace\0moby\0-id\0' + b'a' * 64 + b'\0')
        cs = [{'id': c * 64, 'cgroup': cg, 'init': self.k.pid(pid)}
              for c, cg, pid in [('a', self.old, 30), ('b', self.updater, 40), ('c', self.survivor, 50)]]
        self.e = {'host': self.k.host(), 'containers': cs, 'controls': controls,
                  'backend': self.old, 'freezeOrder': [self.updater, *controls, self.old],
                  'groups': {g: self.k.pin(g) for g in controls + [self.old, self.updater, self.survivor]},
                  'runtime': self.k.runtime()}
        self.k.pins = {g: p['inode'] for g, p in self.e['groups'].items()}

    def group(self, name, pids):
        p = self.cg / name.lstrip('/')
        p.mkdir(parents=True)
        for f, value in {'cgroup.type': 'domain', 'cgroup.freeze': '0',
                         'cgroup.events': 'frozen 0\npopulated 1\n',
                         'cgroup.procs': '\n'.join(map(str, pids)), 'cgroup.kill': ''}.items():
            (p / f).write_text(value)
        return p

    def pid(self, pid, exe, cg):
        p = self.proc / str(pid)
        p.mkdir()
        fields = ['S', '1'] + ['0'] * 20
        fields[19] = str(pid * 100)
        (p / 'stat').write_text(f'{pid} ({exe}) ' + ' '.join(fields))
        (p / 'comm').write_text(exe[:15])  # Linux truncates comm, not exe.
        (p / 'cgroup').write_text('0::' + cg + '\n')
        (p / 'exe').symlink_to('/usr/bin/' + exe)

    def close(self):
        self.tmp.cleanup()


class KernelTests(unittest.TestCase):
    def setUp(self):
        self.f = ProcFixture()
        self.addCleanup(self.f.close)

    def test_recursive_runc_and_long_shim_names_are_pinned(self):
        f = self.f
        f.k.verify(f.e, [])
        self.assertEqual([r['pid'] for r in f.e['runtime']], [10, 20, 21, 22])
        self.assertEqual([r['pid'] for r in f.e['groups'][f.m.CONTROL[1]]['members']], [20, 21, 22])

    def test_pid_reuse_is_rejected(self):
        f = self.f
        p = f.proc / '30/stat'
        p.write_text(p.read_text().replace('3000', '3001'))
        with self.assertRaisesRegex(RuntimeError, 'tree drift'):
            f.k.verify(f.e, [])

    def test_boot_change_is_rejected(self):
        f = self.f
        (f.proc / 'sys/kernel/random/boot_id').write_text('new-boot')
        with self.assertRaisesRegex(RuntimeError, 'host/boot'):
            f.k.verify(f.e, [])

    def test_unknown_replica_cgroup_is_rejected(self):
        f = self.f
        f.group('/system.slice/docker-' + 'd' * 64 + '.scope', [])
        with self.assertRaisesRegex(RuntimeError, 'replica'):
            f.k.verify(f.e, [])

    def test_generic_accepted_work_child_cannot_escape_to_arbitrary_cgroup(self):
        f = self.f
        f.pid(60, 'busybox', '/unexpected-worker')
        p = f.proc / '60/stat'
        p.write_text(p.read_text().replace(' S 1 ', ' S 20 '))
        with self.assertRaisesRegex(RuntimeError, 'descendant escaped'):
            f.k.verify(f.e, [])

    def test_detached_buildkit_payload_cgroup_is_not_mistaken_for_host_service(self):
        f = self.f
        f.group('/docker/buildkit/accepted-run', [60])
        f.pid(60, 'busybox', '/docker/buildkit/accepted-run')
        with self.assertRaisesRegex(RuntimeError, 'unaccounted runtime cgroup'):
            f.k.verify(f.e, [])

    def test_foreign_runtime_outside_control_roots_is_rejected(self):
        f = self.f
        f.pid(60, 'buildkitd', '/other.service')
        # Even if accepted into the proposal it is not a fenced launch root.
        f.e['runtime'] = f.k.runtime()
        with self.assertRaisesRegex(RuntimeError, 'outside frozen'):
            f.k.verify(f.e, [])

    def test_unexpected_shim_container_is_rejected(self):
        f = self.f
        p = f.proc / '21/cmdline'
        p.write_bytes(p.read_bytes().replace(b'a' * 64, b'f' * 64))
        f.e['runtime'] = f.k.runtime()
        with self.assertRaisesRegex(RuntimeError, 'replica shim'):
            f.k.verify(f.e, [])

    def test_unknown_process_in_frozen_executor_tree_is_rejected(self):
        f = self.f
        f.pid(60, 'node', f.old)
        (f.k.group(f.old) / 'cgroup.procs').write_text('30\n60\n')
        with self.assertRaisesRegex(RuntimeError, 'tree drift'):
            f.k.verify(f.e, [])

    def test_survivor_must_remain_unfrozen(self):
        f = self.f
        (f.k.group(f.survivor) / 'cgroup.freeze').write_text('1')
        with self.assertRaisesRegex(RuntimeError, 'freezer'):
            f.k.verify(f.e, [])

    def test_freeze_request_without_kernel_ack_times_out_and_does_not_thaw(self):
        f = self.f
        with self.assertRaises(TimeoutError):
            f.k.freeze(f.old, True)
        self.assertEqual((f.k.group(f.old) / 'cgroup.freeze').read_text(), '1')

    def test_empty_without_all_old_execution_identities_gone_is_refused(self):
        f = self.f
        (f.k.group(f.old) / 'cgroup.events').write_text('frozen 1\npopulated 0\n')
        (f.k.group(f.old) / 'cgroup.freeze').write_text('1')
        (f.k.group(f.old) / 'cgroup.procs').write_text('')
        with self.assertRaisesRegex(RuntimeError, 'old process still exists'):
            f.k.verify(f.e, [f.old], dead=True)

    def test_kill_requires_exact_inode_and_acknowledged_freeze(self):
        f = self.f
        with self.assertRaisesRegex(RuntimeError, 'frozen'):
            f.k.kill(f.old)
        f.k.pins[f.old] += 1
        with self.assertRaisesRegex(RuntimeError, 'changed before kill'):
            f.k.kill(f.old)
        self.assertEqual((f.k.group(f.old) / 'cgroup.kill').read_text(), '')

    def test_symlinked_cgroup_is_rejected(self):
        f = self.f
        (f.cg / 'alias').symlink_to(f.k.group(f.old), target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'aliased'):
            f.k.group('/alias')

    def test_proxy_escape_hatch_never_moves_a_shim(self):
        f = self.f
        shim = next(r for r in f.e['runtime'] if r['pid'] == 21)
        with self.assertRaisesRegex(RuntimeError, 'proxy identity'):
            f.k.move_proxy(f.e, shim, f.old, lambda *args, **kw: None)

    def test_foreign_host_cannot_enter_test_mutation_path(self):
        f = self.f
        with patch.object(f.m.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'TEST host identity'):
                f.m.host_precheck(f.k)

    def test_journal_is_exclusive_and_durable_and_rejects_symlink_output(self):
        f = self.f
        p = pathlib.Path(f.tmp.name) / 'hold'
        journal = f.m.Journal(p)
        self.addCleanup(os.close, journal.fd)
        journal.save({'phase': 'intent'})
        import json
        self.assertEqual(json.loads((p / 'hold.json').read_text()), {'phase': 'intent'})
        with self.assertRaises(FileExistsError):
            f.m.Journal(p)
        (p / 'next.json').symlink_to(f.machine)
        with self.assertRaises(FileExistsError):
            journal.save({'phase': 'held'})
        self.assertEqual(f.machine.read_text(), 'fixture-machine')


class CaptureTests(unittest.TestCase):
    def setUp(self):
        import json
        self.f = f = ProcFixture()
        self.addCleanup(f.close)
        self.rows = []
        roles = [('a', 'backend', 30), ('b', 'updater', 40), ('c', 'mongo', 50),
                 ('d', 'redis', 60), ('e', 'caddy', 70)]
        for i, (c, role, pid) in enumerate(roles):
            cg = '/system.slice/docker-' + c * 64 + '.scope'
            if c in ('d', 'e'):
                f.group(cg, [pid])
                f.pid(pid, role, cg)
            if i > 0:
                sid = 22 + i
                f.pid(sid, 'containerd-shim-runc-v2', f.m.CONTROL[1])
                (f.proc / str(sid) / 'cmdline').write_bytes(b'shim\0-namespace\0moby\0-id\0' + c.encode() * 64 + b'\0')
            self.rows.append({'Id': c * 64, 'Name': '/hysteria-' + role,
                              'Image': 'sha256:' + c * 64, 'RestartCount': 0,
                              'Config': {'Image': 'fixture:' + role, 'Labels': {
                                  'com.docker.compose.project': 'hysteria-panel', 'com.docker.compose.service': role}},
                              'HostConfig': {'Privileged': False, 'PidMode': '', 'CgroupnsMode': 'private',
                                             'CapAdd': [], 'RestartPolicy': {'Name': 'always', 'MaximumRetryCount': 0}},
                              'State': {'Running': True, 'Pid': pid, 'StartedAt': 'fixed'}, 'Mounts': []})
        (f.k.group(f.m.CONTROL[1]) / 'cgroup.procs').write_text('20\n21\n23\n24\n25\n26\n')
        self.calls = []
        def reader(args):
            self.calls.append(args)
            if args[:2] == ['container', 'ls']:
                return ('\n'.join(c['Id'] for c in self.rows)).encode()
            self.assertEqual(args[:2], ['container', 'inspect'])
            return json.dumps(self.rows).encode()
        self.patch = patch.object(f.m, 'docker_read', side_effect=reader)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_capture_reads_only_inventory_and_preserves_all_exact_pins(self):
        f = self.f
        result = f.m.capture(f.k)
        self.assertEqual(len(result['containers']), 5)
        self.assertEqual(result['backend'], f.old)
        self.assertEqual(len([r for r in result['runtime'] if 'containerId' in r]), 5)
        self.assertEqual(self.calls[0], ['container', 'ls', '--all', '--quiet', '--no-trunc'])
        self.assertEqual(self.calls[1][:2], ['container', 'inspect'])
        self.assertEqual((f.k.group(f.old) / 'cgroup.freeze').read_text(), '0')

    def test_capture_refuses_missing_shim(self):
        f = self.f
        original = f.k.runtime
        f.k.runtime = lambda: [r for r in original() if r.get('containerId') != 'e' * 64]
        with self.assertRaisesRegex(RuntimeError, 'shim inventory'):
            f.m.capture(f.k)

    def test_capture_refuses_unknown_replica_name(self):
        self.rows[-1]['Name'] = '/unaccounted-replica'
        with self.assertRaisesRegex(RuntimeError, 'unexpected container'):
            self.f.m.capture(self.f.k)

    def test_capture_refuses_privileged_survivor(self):
        self.rows[-1]['HostConfig']['Privileged'] = True
        with self.assertRaisesRegex(RuntimeError, 'privileged'):
            self.f.m.capture(self.f.k)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.m = load()
        self.b = self.m.SystemdRelaunchBarrier(['fixture.service'])
        self.path = pathlib.Path(self.tmp.name) / 'refusal.conf'
        self.path.write_text(self.b.CONTENT)
        self.expected = {'supervisors': {'fixture.service': {'ControlGroup': '/fixture.service'}},
                         'relaunch': {'owner': 'fixture', 'dropins': [{'path': str(self.path), 'createdDirectory': False}]}}
        self.loaded = {'Restart': 'no', 'ControlGroup': '/fixture.service',
                       'ExecCondition': '{ path=/usr/bin/false ; argv[]=/usr/bin/false ; ignore_errors=no ; pid=0 ; }'}
        self.b.show = lambda unit: self.loaded
        self.conditions = [['ConditionPathExists', False, True, '/run', 0]]
        self.b.conditions = lambda unit: self.conditions

    def test_prefork_refusal_must_be_loaded_before_accepting_hold(self):
        for conditions in ([], [['ConditionPathExists', True, True, '/run', 0]],
                           [['ConditionPathExists', False, False, '/run', 0]]):
            self.conditions = conditions
            with self.assertRaisesRegex(RuntimeError, 'prefork activation refusal not loaded'):
                self.b.verify(self.expected)

    def test_loaded_manager_refusal_is_required_not_just_file_presence(self):
        self.b.verify(self.expected)
        self.loaded['ExecCondition'] = self.loaded['ExecCondition'].replace('/usr/bin/false', '/usr/bin/true')
        with self.assertRaisesRegex(RuntimeError, 'refusal not loaded'):
            self.b.verify(self.expected)

    def test_foreign_runtime_dropin_cannot_be_removed_as_owned(self):
        self.path.write_text('[Service]\nRestart=always\n')
        with self.assertRaisesRegex(RuntimeError, 'dropin changed'):
            self.b.restore(self.expected, None, lambda *args, **kw: None)
        self.assertTrue(self.path.exists())

    def test_changed_control_group_prevents_nondestructive_supervisor_restore(self):
        self.loaded['ControlGroup'] = '/replacement.service'
        with self.assertRaisesRegex(RuntimeError, 'group drift'):
            self.b.restore(self.expected, None, lambda *args, **kw: None)
        self.assertTrue(self.path.exists())


class PipeGuardTests(unittest.TestCase):
    def launch(self):
        import subprocess
        import sys
        import json
        td = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(td.cleanup)
        state = pathlib.Path(td.name) / 'state'
        code = ('import runpy; d=runpy.run_path(' + repr(str(pathlib.Path(__file__).resolve())) + '); '
                'm=d["load"](); k=d["Kernel"](); '
                'f=m.Fence({"freezeOrder":k.groups,"backend":"backend"},k,m.Journal(' + repr(str(state)) + '),"owner"); '
                'raise SystemExit(m.serve(f))')
        p = subprocess.Popen([sys.executable, '-B', '-c', code], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if p.poll() is None:
                p.kill()
            p.wait(timeout=5)
            for stream in (p.stdin, p.stdout, p.stderr):
                stream.close()
        self.addCleanup(cleanup)
        row = json.loads(p.stdout.readline())
        self.assertEqual(row['hostFence'], 'held')
        return p, state / 'hold.json'

    def test_pipe_eof_retains_unknown_frozen_hold(self):
        import json
        p, state = self.launch()
        p.stdin.close()
        self.assertEqual(p.wait(timeout=5), 2)
        row = json.loads(state.read_text())
        self.assertEqual(row['phase'], 'unknown')
        self.assertEqual(row['frozen'], ['updater', 'docker', 'containerd', 'backend'])

    def test_foreign_pipe_owner_does_not_thaw(self):
        import json
        p, state = self.launch()
        p.stdin.write('{"owner":"foreign","command":"restore","ack":"NO_DESTRUCTIVE_OR_NODE_MUTATION"}\n')
        p.stdin.flush()
        self.assertEqual(p.wait(timeout=5), 2)
        self.assertEqual(json.loads(state.read_text())['phase'], 'unknown')
        self.assertEqual(len(json.loads(state.read_text())['frozen']), 4)

    def test_sigterm_retains_unknown_hold(self):
        import json
        p, state = self.launch()
        p.terminate()
        self.assertEqual(p.wait(timeout=5), 2)
        self.assertEqual(json.loads(state.read_text())['phase'], 'unknown')
        self.assertEqual(len(json.loads(state.read_text())['frozen']), 4)

    def test_sigkill_never_produces_restore_or_reusable_journal(self):
        import json
        p, state = self.launch()
        p.kill()
        self.assertEqual(p.wait(timeout=5), -9)
        self.assertEqual(len(json.loads(state.read_text())['frozen']), 4)
        with self.assertRaises(FileExistsError):
            load().Journal(state.parent)

    def test_explicit_nondestructive_pipe_restore_exits_zero(self):
        import json
        p, state = self.launch()
        p.stdin.write('{"owner":"owner","command":"restore","ack":"NO_DESTRUCTIVE_OR_NODE_MUTATION"}\n')
        p.stdin.flush()
        row = json.loads(p.stdout.readline())
        self.assertEqual(row['hostFence'], 'released')
        self.assertEqual(p.wait(timeout=5), 0)
        self.assertEqual(json.loads(state.read_text())['phase'], 'restored')
        self.assertEqual(json.loads(state.read_text())['frozen'], [])


if __name__ == '__main__':
    unittest.main()
