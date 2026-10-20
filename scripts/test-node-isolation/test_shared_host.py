"""Local simulated kernel seams, never live host-authority evidence."""
import copy
import importlib.util
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_isolation as fixtures
m = fixtures.m
sys.modules[m.__name__] = m


def shared_module():
    path = HERE / 'shared_host.py'
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location('shared_host', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


s = shared_module()


def accepted():
    names = ['hysteria-backend', 'hysteria-updater', 'hysteria-mongo',
             'hysteria-redis', 'hysteria-caddy', 'c3-test-candidate']
    containers = []
    groups = {}
    for i, name in enumerate(names, 1):
        cid = format(i, '064x')
        group = '/system.slice/docker-' + cid + '.scope'
        init = {'pid': 1000 + i, 'startTicks': '20', 'cgroup': group,
                'exe': '/payload', 'comm': 'payload'}
        containers.append({'id': cid, 'name': name, 'cgroup': group, 'init': init})
        groups[group] = {'inode': i, 'members': [init]}
    controls = ['/system.slice/docker.service', '/system.slice/containerd.service']
    groups.update({g: {'inode': 20 + i, 'members': []} for i, g in enumerate(controls)})
    return {'schema': 1, 'host': {'machineId': '7fa266f995fe4aa69e96cf7d01359e34',
                               'bootId': fixtures.PlanTests().plan()['bootId']},
            'controls': controls, 'containers': containers, 'groups': groups,
            'backend': containers[0]['cgroup'],
            'freezeOrder': [containers[1]['cgroup'], *controls, containers[0]['cgroup']],
            'runtime': [], 'supervisors': {u: {'ControlGroup': g} for u, g in
                zip(['docker.service', 'containerd.service'], controls)}}


def plan():
    p = fixtures.PlanTests().plan()
    p.update({'nodeId': '6ab189dc63913ebd4a917399', 'endpointIp': '212.119.42.100',
              'machineId': '7fa266f995fe4aa69e96cf7d01359e34', 'mode': 'shared-test',
              'hostHold': {'owner': '01234567-89ab-cdef-0123-456789abcdef',
                           'freezerSha256': '2' * 64, 'expected': accepted()}})
    p['keepCgroups'].append('/system.slice/xl2tpd.service')
    return p


class SharedPlanTests(unittest.TestCase):
    def test_shared_requires_separate_exact_host_hold_not_dedicated_allowlist(self):
        self.assertIsNotNone(s, 'bounded shared host mode is missing')
        p = plan()
        self.assertEqual(s.validate_plan(p, m), p)
        with self.assertRaises(m.Refusal):
            m.validate_plan(p)
        for change in [{'hostHold': {'held': True}}, {'machineId': 'a' * 32},
                       {'endpointIp': 'test.infograd.online'}, {'nodeId': 'foreign'},
                       {'keepCgroups': ['/system.slice']},
                       {'isolateUnits': [*p['isolateUnits'], 'xl2tpd.service']}]:
            with self.subTest(change=change), self.assertRaises(m.Refusal):
                s.validate_plan({**p, **change}, m)


class FixtureKernelSurvivors:
    """Simulated immutable singleton payloads; NOT a live proof adapter."""
    def pid(self, number):
        return next(c['init'] for c in accepted()['containers'] if c['init']['pid'] == number)
    def members(self, group):
        return [c['init'] for c in accepted()['containers'] if c['cgroup'] == group]


class HostRecordTests(unittest.TestCase):
    def record(self):
        e = accepted()
        current = copy.deepcopy(e)
        current['relaunch'] = {'owner': plan()['hostHold']['owner'], 'dropins': [
            {'path': '/run/systemd/system/' + u + '.d/90-c3-test-host-isolation.conf',
             'createdDirectory': True} for u in ('docker.service', 'containerd.service')]}
        return {'phase': 'held', 'owner': plan()['hostHold']['owner'], 'pending': None,
                'originalExpected': e, 'expected': current, 'frozen': e['freezeOrder'], 'dead': False}

    def test_only_exact_original_proxies_can_leave_frozen_control_groups(self):
        p = plan(); row = self.record()
        proxy = {'pid': 333, 'startTicks': '300', 'cgroup': s.CONTROLS[0],
                 'exe': '/usr/bin/docker-proxy', 'comm': 'docker-proxy'}
        e = p['hostHold']['expected']; e['runtime'] = [proxy]
        e['groups'][s.CONTROLS[0]]['members'].append(proxy)
        row['originalExpected'] = copy.deepcopy(e)
        row['expected'] = copy.deepcopy(e)
        current = row['expected']; current['relaunch'] = self.record()['expected']['relaunch']
        group = '/system.slice/c3-test-host-proxies-' + row['owner'] + '.scope'
        moved = {**proxy, 'cgroup': group}
        current['proxyGroup'] = group; current['proxyOriginals'] = [proxy]
        current['runtime'] = [moved]; current['groups'][s.CONTROLS[0]]['members'] = []
        current['groups'][group] = {'inode': 99, 'members': [moved]}
        class Kernel(FixtureKernelSurvivors):
            def verify(self, *args):
                pass
        s.verify_record(row, p, Kernel(), m)
        for key, value in [('pid', 444), ('exe', '/usr/bin/containerd-shim-runc-v2')]:
            bad = copy.deepcopy(row)
            bad['expected']['groups'][group]['members'][0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(m.Refusal, 'HOST_POLICY_DRIFT_RETAINED'):
                s.verify_record(bad, p, Kernel(), m)

    def test_fresh_kernel_check_is_required_and_exact_frozen_policy_cannot_drift(self):
        self.assertTrue(hasattr(s, 'verify_record'), 'current host kernel proof is missing')
        class Kernel(FixtureKernelSurvivors):
            def __init__(self):
                self.calls = []
                self.bad = False
            def verify(self, expected, frozen, dead):
                self.calls.append((expected, frozen, dead))
                if self.bad:
                    raise RuntimeError('freezer not acknowledged')
        kernel = Kernel()
        row = self.record()
        s.verify_record(row, plan(), kernel, m)
        self.assertEqual(kernel.calls, [(row['expected'], row['frozen'], False)] * 2)
        kernel.bad = True
        with self.assertRaisesRegex(m.Refusal, 'HOST_KERNEL_PROOF_LOST'):
            s.verify_record(row, plan(), kernel, m)
        kernel.bad = False
        for changed in [dict(row, phase='unknown'), dict(row, owner='foreign'),
                        dict(row, frozen=row['frozen'][:-1]), dict(row, pending={'action': 'thaw'}),
                        dict(row, dead=True), dict(row, held=True)]:
            with self.subTest(changed=changed), self.assertRaises(m.Refusal):
                s.verify_record(changed, plan(), kernel, m)
        for key, value in [('host', {'machineId': 'foreign'}),
                           ('freezeOrder', []), ('runtime', [{'pid': 777}]),
                           ('groups', {})]:
            changed = copy.deepcopy(row)
            changed['expected'][key] = value
            with self.subTest(key=key), self.assertRaises(m.Refusal):
                s.verify_record(changed, plan(), kernel, m)


class SharedEngineTests(unittest.TestCase):
    def test_shared_apply_preserves_survivors_and_requires_live_host_guard_for_every_use(self):
        self.assertTrue(hasattr(s, 'make_engine'), 'shared enforcement entry point is missing')
        from unittest.mock import patch
        p = plan()
        row = HostRecordTests().record()
        checks = []
        def live(*args):
            checks.append('kernel')
            return row['expected']
        with tempfile.TemporaryDirectory() as root, patch.object(s, 'check_hold', side_effect=live):
            host = s.make_host(root, p, m)
            # Explicit fake systemd/process adapter, real shared Engine and disk journal.
            fixture = fixtures.EngineTests.FixtureHost()
            for name in ('unit', 'snapshot_mask', 'write_mask', 'stop', 'reload',
                         'assert_stopped', 'boot_ticks', 'operator_session'):
                setattr(host, name, getattr(fixture, name))
            inventory = {'jobsPresent': False, 'units': {}, 'unitFilePins': {}, 'processes': [
                {'pid': 42, 'start': '10', 'cgroup': '/system.slice/xray.service', 'exe': '/xray'},
                {'pid': 43, 'start': '10', 'cgroup': '/system.slice/xl2tpd.service', 'exe': '/xl2tpd'},
                {'pid': 1003, 'start': '20', 'cgroup': accepted()['containers'][2]['cgroup'], 'exe': '/mongod'}]}
            with patch.object(m.Host, 'check_prerequisites'), \
                 patch.object(m.Host, 'guard_check', side_effect=fixture.guard_check), \
                 patch.object(m.Host, 'inventory', return_value=inventory):
                e = s.make_engine(root, p, m, host)
                e.apply({'fixture': 'recovery'})
                self.assertEqual(e.read()['phase'], 'awaiting-fresh-login')
                with self.assertRaises(m.Refusal):
                    e.assert_held()
                with self.assertRaisesRegex(m.Refusal, 'POST_DRAIN_FRESH_LOGIN_REQUIRED'):
                    e.confirm_access()
                fixture.session = {'pid': 125, 'start': '101'}
                e.confirm_access()
                self.assertEqual(e.evidence(e.assert_held())['scope'], 'shared-test-node-maintenance-v1')
                self.assertTrue(checks)
                stopped = {event[1] for event in fixture.events if event[0] == 'stop'}
                self.assertEqual(stopped, set(p['isolateUnits']))
                self.assertNotIn('xray.service', stopped)
                self.assertNotIn('xl2tpd.service', stopped)
                with patch.object(s, 'check_hold', side_effect=m.Refusal('HOST_GUARD_LOST')):
                    with self.assertRaisesRegex(m.Refusal, 'HOST_GUARD_LOST'):
                        e.assert_held()
                    import shlex
                    values = ['close', 'op', p['nodeId'], 'sha256:' + 'a' * 64, 'backup',
                              p['targetProfile'], p['context'], 'attempt', 'generation', 'none', 'close']
                    argv = [part for pair in zip(['--' + key for key in m.NAMES], values) for part in pair]
                    with patch.object(m.subprocess, 'run') as execute:
                        with self.assertRaisesRegex(m.Refusal, 'HOST_GUARD_LOST'):
                            e.dispatch(shlex.join([m.RUNNER, *argv]), b'', 0)
                        execute.assert_not_called()
                    with self.assertRaises(m.Refusal):
                        e.restore()
                fixture.alive = False
                with self.assertRaisesRegex(m.Refusal, 'RECOVERY_GUARD_LOST'):
                    e.assert_held()
                fixture.alive = True
                inventory['units']['unreviewed.timer'] = {'LoadState': 'loaded', 'ActiveState': 'active'}
                with self.assertRaisesRegex(m.Refusal, 'UNREVIEWED_ACTIVATION_UNIT'):
                    e.assert_held()
                inventory['units'].clear()
                for group, exe in [('/system.slice/docker-' + 'f' * 64 + '.scope', '/mongod'),
                                   ('/user.slice/user-0.slice/session-old.scope', '/bash'),
                                   ('/system.slice/xray.service', '/cc-agent'),
                                   ('/system.slice/xray.service', '/sshd')]:
                    inventory['processes'].append({'pid': 99, 'start': '11', 'cgroup': group, 'exe': exe})
                    with self.subTest(group=group, exe=exe), self.assertRaises(m.Refusal):
                        e.assert_held()
                    inventory['processes'].pop()
                with self.assertRaisesRegex(m.Refusal, 'SHARED_HANDBACK_UNAVAILABLE'):
                    e.restore()


class HostGuardTests(unittest.TestCase):
    def test_real_socket_roundtrip_requires_live_owner_and_current_kernel_not_historical_json(self):
        self.assertTrue(hasattr(s, 'serve_hold'), 'live host hold supervisor is missing')
        import multiprocessing
        import os
        import json
        import time
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('freezer', HERE.parent / 'panel-host-freezer.py')
        freezer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(freezer)
        p = plan()
        real_peer = s.peer_identity
        def fixture_root_peer(conn):
            pid, uid, gid = real_peer(conn)
            return pid, 0, gid  # UID only is simulated; actual socket/PID/start remain real.
        class Kernel(FixtureKernelSurvivors):
            def __init__(self):
                self.frozen = []
            def verify(self, expected, frozen, dead=False):
                if frozen != self.frozen or dead:
                    raise RuntimeError('kernel drift')
            def prepare_relaunch(self, expected, owner, persist):
                expected['relaunch'] = HostRecordTests().record()['expected']['relaunch']
            def freeze(self, group, value):
                assert value is True
                self.frozen.append(group)
            def split_proxies(self, *args):
                pass
        class Host:
            def operator_session(self):
                return {k: m.proc_identity(os.getppid())[k] for k in ('pid', 'start')}
            def guard_check(self, *args):
                pass
        with tempfile.TemporaryDirectory() as root:
            m.atomic_json(root, 'guard.json', {'fixture': 'recovery'})
            readfd, writefd = os.pipe()
            def child():
                os.close(writefd)
                kernel = Kernel()
                with patch.object(freezer, 'capture', return_value=accepted()), \
                     patch.object(s, 'peer_identity', side_effect=fixture_root_peer), \
                     patch.object(m, 'secure_file', side_effect=lambda path: pathlib.Path(path).read_bytes()):
                    try:
                        s.serve_hold(p, root, m, freezer, kernel, Host(), readfd)
                    except m.Refusal as error:
                        if str(error) != 'HOST_CONTROLLER_CHANNEL_LOST':
                            raise
            proc = multiprocessing.get_context('fork').Process(target=child)
            proc.start()
            os.close(readfd)
            try:
                end = time.monotonic() + 5
                while not pathlib.Path(root, 'host-guard.json').exists() and proc.is_alive() and time.monotonic() < end:
                    time.sleep(.01)
                self.assertTrue(pathlib.Path(root, 'host-guard.json').exists())
                client_kernel = Kernel(); client_kernel.frozen = accepted()['freezeOrder']
                with patch.object(m, 'secure_file', side_effect=lambda path: pathlib.Path(path).read_bytes()), \
                     patch.object(s, 'peer_identity', side_effect=fixture_root_peer), \
                     patch.object(s, 'load_freezer', return_value=(freezer, client_kernel)):
                    self.assertEqual(s.check_hold(p, root, m)['host'], accepted()['host'])
                    client_kernel.frozen = []
                    with self.assertRaisesRegex(m.Refusal, 'HOST_KERNEL_PROOF_LOST'):
                        s.check_hold(p, root, m)
                    client_kernel.frozen = accepted()['freezeOrder']
                    for key, value in [('owner', 'foreign'), ('start', '0')]:
                        identity_path = pathlib.Path(root, 'host-guard.json')
                        raw = identity_path.read_bytes()
                        identity = json.loads(raw); identity[key] = value
                        identity_path.write_bytes(fixtures.json_bytes(identity))
                        with self.subTest(key=key), self.assertRaises(m.Refusal):
                            s.check_hold(p, root, m)
                        identity_path.write_bytes(raw)
                    os.close(writefd); writefd = None
                    proc.join(5)
                    self.assertFalse(proc.is_alive())
                    self.assertEqual(json.loads(pathlib.Path(root, 'host/hold.json').read_bytes())['phase'], 'unknown')
                    with self.assertRaises((m.Refusal, OSError)):
                        s.check_hold(p, root, m)
            finally:
                if writefd is not None:
                    os.close(writefd)
                if proc.is_alive():
                    proc.terminate(); proc.join(5)


class ModeRoutingTests(unittest.TestCase):
    def test_default_cli_does_not_adopt_shared_without_trusted_fixed_module(self):
        self.assertTrue(hasattr(m, 'select_mode'), 'default executable has no bounded shared route')
        from unittest.mock import patch
        p = plan()
        with patch.object(m, 'SHARED_MODULE', str(HERE / 'shared_host.py')), \
             patch.object(m, 'secure_file', side_effect=lambda path: pathlib.Path(path).read_bytes()):
            selected, module = m.select_mode(p)
            self.assertEqual(selected, p)
            self.assertIsNotNone(module)
            dedicated, module = m.select_mode(fixtures.PlanTests().plan())
            self.assertIsNone(module)
            self.assertEqual(dedicated['nodeId'], fixtures.PlanTests().plan()['nodeId'])
        with patch.object(m, 'secure_file', side_effect=m.Refusal('UNTRUSTED_PATH')):
            with self.assertRaisesRegex(m.Refusal, 'UNTRUSTED_PATH'):
                m.select_mode(p)
        for change in [{'mode': 'prod'}, {'hostHold': {'held': True}}]:
            with self.assertRaises((m.Refusal, OSError)):
                m.select_mode({**p, **change})


class AcceptedWorkTests(unittest.TestCase):
    def test_shared_refuses_shim_exec_in_preserved_payload_even_when_freezer_accepts_it(self):
        self.assertTrue(hasattr(s, 'assert_payload_lineage'), 'shared accepted-work exclusion is missing')
        spec = importlib.util.spec_from_file_location('freezer_lineage', HERE.parent / 'panel-host-freezer.py')
        assert spec is not None and spec.loader is not None
        f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
        with tempfile.TemporaryDirectory() as root:
            root = pathlib.Path(root)
            proc, cg = root / 'proc', root / 'cgroup'
            proc.mkdir(); cg.mkdir()
            kernel = f.LinuxKernel(proc=proc, cgroup=cg)
            group = accepted()['containers'][2]['cgroup']
            path = cg / group.lstrip('/'); path.mkdir(parents=True)
            (path / 'cgroup.procs').write_text('50\n60\n')
            def pid(number, parent, start):
                p = proc / str(number); p.mkdir(exist_ok=True)
                fields = ['S', str(parent)] + ['0'] * 20; fields[19] = start
                (p / 'stat').write_text(str(number) + ' (payload) ' + ' '.join(fields))
                (p / 'comm').write_text('payload')
                (p / 'cgroup').write_text('0::' + group)
                if not (p / 'exe').is_symlink():
                    (p / 'exe').symlink_to('/payload')
            pid(21, 1, '210'); pid(50, 21, '500'); pid(60, 50, '600')
            expected = {'containers': [{'name': 'hysteria-mongo', 'cgroup': group, 'init': kernel.pid(50)}]}
            s.assert_payload_lineage(expected, kernel, m)
            pid(60, 21, '600')  # Accepted docker exec sibling of the real payload init.
            # The original freezer only checks the known cgroup, not this boundary.
            with self.assertRaisesRegex(m.Refusal, 'ACCEPTED_WORK_IN_SURVIVOR'):
                s.assert_payload_lineage(expected, kernel, m)
            pid(60, 50, '601')
            expected['containers'][0]['init']['startTicks'] = 'old-reused-pid'
            with self.assertRaises(m.Refusal):
                s.assert_payload_lineage(expected, kernel, m)


class KernelReadbackTests(unittest.TestCase):
    def test_shared_hold_rechecks_real_proc_cgroup_adapter_for_boot_pid_inode_freezer_and_supervisor(self):
        import os
        import shutil
        spec = importlib.util.spec_from_file_location('freezer_readback', HERE.parent / 'panel-host-freezer.py')
        assert spec is not None and spec.loader is not None
        freezer = importlib.util.module_from_spec(spec); spec.loader.exec_module(freezer)
        for fault in ('none', 'boot', 'pid', 'inode', 'frozen', 'survivor-frozen', 'supervisor'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                root = pathlib.Path(root); proc = root / 'proc'; cg = root / 'cg'
                proc.mkdir(); cg.mkdir()
                p = plan(); e = p['hostHold']['expected']
                machine = root / 'machine'; machine.write_text(p['machineId'])
                boot = proc / 'sys/kernel/random/boot_id'; boot.parent.mkdir(parents=True); boot.write_text(p['bootId'])
                kernel = freezer.LinuxKernel(proc=proc, cgroup=cg, machine=machine)
                for c in e['containers']:
                    pid = c['init']['pid']; path = proc / str(pid); path.mkdir()
                    # Standard runc init leads its own session. Session zero was
                    # a stale fixture hidden by the pre-B1 freezer implementation.
                    fields = ['S', '1'] + ['0'] * 20
                    fields[3] = str(pid); fields[19] = '20'
                    (path / 'stat').write_text(str(pid) + ' (payload) ' + ' '.join(fields))
                    (path / 'comm').write_text('payload')
                    (path / 'cgroup').write_text('0::' + c['cgroup'])
                    (path / 'exe').symlink_to('/payload')
                    c['init'] = kernel.pid(pid)
                for g in e['groups']:
                    path = cg / g.lstrip('/'); path.mkdir(parents=True)
                    frozen = int(g in e['freezeOrder'])
                    for name, value in {'cgroup.type': 'domain', 'cgroup.freeze': str(frozen),
                        'cgroup.events': 'frozen ' + str(frozen) + '\npopulated 1\n',
                        'cgroup.procs': '\n'.join(str(c['init']['pid']) for c in e['containers'] if c['cgroup'] == g)}.items():
                        (path / name).write_text(value)
                e['groups'] = {g: kernel.pin(g) for g in e['groups']}
                class Barrier:
                    def verify(self, expected):
                        if fault == 'supervisor':
                            raise RuntimeError('prefork activation refusal not loaded')
                kernel.barrier = Barrier()
                row = HostRecordTests().record()
                row['originalExpected'] = copy.deepcopy(e); row['expected'] = copy.deepcopy(e)
                row['expected']['relaunch'] = HostRecordTests().record()['expected']['relaunch']
                row['frozen'] = e['freezeOrder']
                group = kernel.group(e['backend'])
                if fault == 'boot':
                    boot.write_text('changed')
                elif fault == 'pid':
                    path = proc / str(e['containers'][0]['init']['pid']) / 'stat'
                    path.write_text(path.read_text().replace(' 20 ', ' 21 '))
                elif fault == 'inode':
                    moved = group.with_name(group.name + '.old'); group.rename(moved); shutil.copytree(moved, group); shutil.rmtree(moved)
                elif fault == 'frozen':
                    (group / 'cgroup.freeze').write_text('0')
                elif fault == 'survivor-frozen':
                    (kernel.group(e['containers'][2]['cgroup']) / 'cgroup.freeze').write_text('1')
                if fault == 'none':
                    s.verify_record(row, p, kernel, m)
                else:
                    with self.assertRaisesRegex(m.Refusal, 'HOST_KERNEL_PROOF_LOST'):
                        s.verify_record(row, p, kernel, m)


if __name__ == '__main__':
    unittest.main()
