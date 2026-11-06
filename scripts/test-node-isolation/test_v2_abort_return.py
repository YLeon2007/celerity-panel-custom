"""Early OLD return: actual CLI/UDS/Fence, modeled systemd/physical facts only."""
import contextlib
import copy
import importlib.util
import io
import json
import multiprocessing
import os
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_shared_host as fixture
m, shared = fixture.m, fixture.s
assert shared is not None


def inventory():
    nodes = []
    for node, ip, profile, machine, profiles in (
        ('6aecd36265572a55acf7c677', '10.203.61.2', 'xray-main', 'a', ['xray-main']),
        ('6aed089795ea4b863887d717', '10.203.61.1', 'xray-bridge', 'b', ['xray-main', 'xray-bridge']),
    ):
        nodes.append({'nodeId': node, 'targetProfile': profile,
                      'endpoint': {'ip': ip, 'port': 2222, 'username': m.RUNNER_USER},
                      'physical': {'machineId': machine * 32, 'bootId': fixture.plan()['bootId'],
                                   'sshHostKeySha256': machine * 64}, 'profiles': profiles})
    return {'version': 1, 'profile': 'accepted-test-v1',
            'executionContext': {'target': 'test', 'hostIdentity': 'test.infograd.online'},
            'sharedNodeId': nodes[1]['nodeId'], 'nodes': nodes}


def plan(is_shared=False):
    inv = inventory()
    pin = inv['nodes'][int(is_shared)]
    p = fixture.plan() if is_shared else fixture.fixtures.PlanTests().plan()
    p.update(version=2, inventorySha256=m.digest(json.dumps(inv, sort_keys=True, separators=(',', ':')).encode()),
             nodeId=pin['nodeId'], endpointIp=pin['endpoint']['ip'], targetProfile=pin['targetProfile'],
             **pin['physical'])
    # No old login scopes in this tracer; their PIDs cannot be resurrected.
    p['isolateUnits'] = ['ssh.service', 'ssh.socket', 'cc-agent.service', 'cron.service',
                         'certbot.service', 'certbot.timer', 'atd.service']
    if is_shared:
        p['hostHold']['expected']['host'] = {k: p[k] for k in ('machineId', 'bootId')}
    return p


@contextlib.contextmanager
def accepted_files():
    def read(path, *args, **kwargs):
        if str(path) == m.INVENTORY:
            return json.dumps(inventory()).encode()
        # File ownership is modeled; real byte reads and JSON/hash checks remain.
        return pathlib.Path(path).read_bytes()
    with patch.object(m, 'secure_file', side_effect=read):
        yield


@contextlib.contextmanager
def modeled_root(root):
    original = pathlib.Path.lstat
    def lstat(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == pathlib.Path(root):
            fields = list(info); fields[4] = 0
            return os.stat_result(fields)
        return info
    with patch.object(pathlib.Path, 'lstat', lstat):
        yield


class Host(m.Host):
    """Only OS commands/physical authority are simulated; mask IO is real."""
    def __init__(self, p):
        self.p = p
        self.events = []
        self.alive = True
        self.fail_checkpoint = False
        self.fail_mask = False
        self.masks = 0
        self.states = {name: {'Id': name, 'ControlGroup': '/system.slice/' + name,
                             'KillMode': 'control-group', 'ActiveState': 'active',
                             'SubState': ('listening' if name.endswith('.socket') else 'waiting' if name.endswith('.timer') else 'running'),
                             'Job': '', 'LoadState': 'loaded', 'UnitFileState': 'enabled'}
                       for name in p['isolateUnits']}
        self.states['cc-agent.service'].update(ActiveState='inactive', SubState='dead', UnitFileState='disabled')
        self.original = copy.deepcopy(self.states)
        self.profiles = {'xray-main': b'UNCHANGED MAIN', 'xray-bridge': b'UNCHANGED BRIDGE'}
    def unit(self, name):
        return dict(self.states[name])
    def check_prerequisites(self, p):
        pass
    def check_inventory(self, p, held=False):
        return super().check_inventory(p, held)
    def inventory(self):
        pending = getattr(self, 'fail_virgin', False) or (self.fail_checkpoint and
                  sum(x[0] == 'stop' for x in self.events) == len(self.p['isolateUnits']))
        self.fail_virgin = False
        if pending:
            self.fail_checkpoint = False
        return {'processes': [], 'jobsPresent': pending, 'units': {}, 'unitFilePins': {}}
    def guard_check(self, *args):
        m.need(self.alive, 'RECOVERY_GUARD_LOST')
    def operator_session(self):
        return {k: m.proc_identity(os.getpid())[k] for k in ('pid', 'start')}
    def boot_ticks(self):
        return '100'
    def write_mask(self, name):
        super().write_mask(name)
        self.events.append(('mask', name))
        self.masks += 1
        if self.fail_mask and self.masks == 2:
            raise OSError('modeled post-effect fsync/ack failure')
    def reload(self):
        self.events.append(('reload',))
    def stop(self, name):
        self.events.append(('stop', name))
        if self.states[name]['ActiveState'] not in ('inactive', 'failed'):
            self.states[name].update(ActiveState='inactive', SubState='dead')
    def assert_stopped(self, name, group):
        m.need(self.states[name]['ActiveState'] in ('inactive', 'failed'), 'WRITER_NOT_STOPPED')
    def run(self, argv):
        self.events.append(tuple(argv))
        if argv[:2] == ['/usr/bin/systemctl', 'start']:
            name = argv[-1]
            self.states[name] = dict(self.original[name])
            return ''
        raise AssertionError('unexpected OS command: ' + repr(argv))
    def assert_runner_terminal(self, *args):
        pass


class NodeReturnTests(unittest.TestCase):
    def test_actual_apply_cli_returns_old_after_known_partial_pre_capture_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            root = pathlib.Path(root); masks = root / 'masks'; masks.mkdir()
            p = plan(); host = Host(p); host.fail_checkpoint = True
            config = root / 'plan.json'; config.write_text(json.dumps(p))
            (root / 'guard.json').write_text('{"fixture":"guard"}')
            # Includes an original regular file and an originally inactive unit.
            (masks / 'cron.service').write_bytes(b'ORIGINAL CRON UNIT\n')
            (masks / 'cron.service').chmod(0o640)
            before = {u: None if not (masks / u).exists() else (masks / u).read_bytes() for u in p['isolateUnits']}
            stdout = io.StringIO()
            with accepted_files(), modeled_root(root), patch.object(m, 'CONFIG', str(config)), patch.object(m, 'STATE', str(root)), \
                 patch.object(m, 'HELPER', str(HERE / 'isolation.py')), patch.object(m, 'MASK_ROOT', str(masks)), \
                 patch.object(m, 'Host', return_value=host), patch.object(m.os, 'geteuid', return_value=0), \
                 patch.object(sys, 'argv', [m.HELPER, 'apply']), contextlib.redirect_stdout(stdout):
                m.main()
            result = json.loads(stdout.getvalue())
            self.assertEqual(result['returnState'], 'OLD')
            self.assertEqual(result['phase'], 'early-returned')
            for name in p['isolateUnits']:
                path = masks / name
                self.assertFalse(path.is_symlink())
                self.assertEqual(path.read_bytes() if path.exists() else None, before[name])
                self.assertEqual(host.states[name], host.original[name])
            self.assertEqual((masks / 'cron.service').stat().st_mode & 0o777, 0o640)
            self.assertFalse(any(e[:2] == ('/usr/bin/systemctl', 'start') and e[-1] == 'cc-agent.service' for e in host.events))
            self.assertEqual(host.profiles, {'xray-main': b'UNCHANGED MAIN', 'xray-bridge': b'UNCHANGED BRIDGE'})


class SharedVirginTests(unittest.TestCase):
    def test_shared_virgin_old_outer_close_failure_is_unknown_without_success(self):
        self.exercise(outer_close_fault=True)

    def test_shared_partial_old_outer_close_failure_is_unknown_without_success(self):
        self.exercise(partial=True, outer_close_fault=True)

    def test_actual_shared_owner_socket_returns_virgin_old_and_naturally_exits(self):
        self.exercise()

    def test_actual_shared_apply_cli_returns_partial_node_and_same_fence_to_old(self):
        self.exercise(partial=True)

    def test_actual_shared_apply_known_virgin_inventory_refusal_returns_old(self):
        self.exercise(virgin_refusal=True)

    def test_actual_shared_return_refuses_capture_or_commit_unknown_without_thaw(self):
        for fault in ('originals', 'handoff-commit.json.next'):
            with self.subTest(fault=fault): self.exercise(fault=fault)

    def exercise(self, partial=False, fault=None, virgin_refusal=False, outer_close_fault=False):
        spec = importlib.util.spec_from_file_location('abort_freezer', HERE.parent / 'panel-host-freezer.py')
        assert spec is not None and spec.loader is not None
        freezer = importlib.util.module_from_spec(spec); spec.loader.exec_module(freezer)
        p = plan(True)
        host = Host(p)
        host.fail_checkpoint = partial
        host.fail_virgin = virgin_refusal
        class Kernel(fixture.FixtureKernelSurvivors):
            def __init__(self): self.frozen = []
            def verify(self, expected, frozen, dead=False):
                if frozen != self.frozen or dead: raise RuntimeError('kernel drift')
            def prepare_relaunch(self, expected, owner, persist):
                expected['relaunch'] = fixture.HostRecordTests().record()['expected']['relaunch']
            def freeze(self, group, value):
                (self.frozen.append if value else self.frozen.remove)(group)
            def split_proxies(self, *args): pass
            def restore_proxies(self, *args): pass
            def restore_relaunch(self, expected, persist): del expected['relaunch']
        class GuardHost(m.Host):
            def operator_session(self): return {k: m.proc_identity(os.getppid())[k] for k in ('pid', 'start')}
            def guard_check(self, *args): pass
        real_peer = shared.peer_identity
        def root_peer(conn):
            pid, uid, gid = real_peer(conn); return pid, 0, gid
        with tempfile.TemporaryDirectory() as root:
            root = pathlib.Path(root)
            (root / 'guard.json').write_text('{"fixture":"recovery"}')
            masks = root / 'masks'; masks.mkdir()
            readfd, writefd = os.pipe()
            def child():
                os.close(writefd)
                real_lock_check = m.Engine.require_outer_lock
                def lock_check(engine, fd):
                    with patch.object(m.os, 'geteuid', return_value=0):
                        return real_lock_check(engine, fd)
                with accepted_files(), patch.object(freezer, 'capture', return_value=p['hostHold']['expected']), \
                     patch.object(m.Engine, 'require_outer_lock', lock_check), \
                     patch.object(shared, 'peer_identity', side_effect=root_peer):
                    try: shared.serve_hold(p, root, m, freezer, Kernel(), GuardHost(), readfd)
                    except m.Refusal as error:
                        if fault is not None:
                            (root / 'owner-refusal.txt').write_text(str(error))
                            raise SystemExit(75)
                        if str(error) != 'HOST_CONTROLLER_CHANNEL_LOST': raise
            proc = multiprocessing.get_context('fork').Process(target=child)
            proc.start(); os.close(readfd)
            try:
                deadline = time.monotonic() + 5
                while not (root / 'host-guard.json').exists() and proc.is_alive() and time.monotonic() < deadline: time.sleep(.01)
                self.assertTrue((root / 'host-guard.json').exists())
                if fault == 'originals': (root / fault).mkdir()
                elif fault: (root / fault).write_text('{}')
                with accepted_files(), patch.object(shared, 'peer_identity', side_effect=root_peer):
                    # Real CLI entry and real UDS, not a direct Fence.restore call.
                    config = root / 'plan.json'; config.write_text(json.dumps(p))
                    stdout, stderr = io.StringIO(), io.StringIO()
                    close, closes = os.close, []
                    def close_outer(fd):
                        if sys._getframe(1).f_code is m.main.__code__:
                            pin, named = os.fstat(fd), (root / 'lock').stat()
                            self.assertEqual((pin.st_dev, pin.st_ino), (named.st_dev, named.st_ino))
                            closes.append(stdout.getvalue())
                            close(fd)  # Actual disposal, then modeled acknowledgement failure.
                            raise OSError('SIMULATED shared outer close acknowledgement lost')
                        return close(fd)
                    select_mode = m.select_mode
                    def modeled_select(value):
                        selected, module = select_mode(value)
                        module.peer_identity = root_peer
                        def load(*args):
                            kernel = Kernel()
                            kernel.frozen = json.loads((root / 'host/hold.json').read_bytes())['frozen']
                            return freezer, kernel
                        module.load_freezer = load
                        real_host = module.make_host
                        def modeled_host(*args):
                            result = real_host(*args)
                            for name in ('unit', 'write_mask', 'stop', 'reload', 'assert_stopped', 'operator_session', 'boot_ticks', 'run'):
                                setattr(result, name, getattr(host, name))
                            result.inventory = host.inventory
                            return result
                        module.make_host = modeled_host
                        return selected, module
                    with modeled_root(root), patch.object(m, 'select_mode', side_effect=modeled_select), patch.object(m, 'CONFIG', str(config)), patch.object(m, 'STATE', str(root)), \
                         patch.object(m, 'MASK_ROOT', str(masks)), patch.object(m, 'RUNNER_FENCES', str(root / 'fences')), \
                         patch.object(m.Host, 'check_prerequisites'), patch.object(m.Host, 'guard_check'), \
                         patch.object(m, 'HELPER', str(HERE / 'isolation.py')), \
                         patch.object(m, 'SHARED_MODULE', str(HERE / 'shared_host.py')), \
                         patch.object(m.os, 'geteuid', return_value=0), patch.object(sys, 'argv', [m.HELPER, 'apply' if partial or virgin_refusal else 'abort-return']), \
                         patch.object(m.os, 'close', new=close_outer) if outer_close_fault else contextlib.nullcontext(), \
                         contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        if fault:
                            with self.assertRaises(m.EarlyReturnUnknown): m.main()
                        elif outer_close_fault:
                            from test_v2_abort_outer_cleanup import actual_wrapper
                            with self.assertRaises(SystemExit) as failed: actual_wrapper()
                            self.assertEqual(failed.exception.code, 75)
                        else: m.main()
                    if fault:
                        proc.join(5)
                        self.assertFalse(proc.is_alive()); self.assertEqual(proc.exitcode, 75)
                        row = json.loads((root / 'host/hold.json').read_bytes())
                        self.assertEqual(row['phase'], 'unknown')
                        self.assertEqual(row['frozen'], p['hostHold']['expected']['freezeOrder'])
                        self.assertEqual((root / 'owner-refusal.txt').read_text(), 'EARLY_RETURN_DOWNSTREAM_UNKNOWN_RETAINED')
                        self.assertEqual(stdout.getvalue(), '')
                        return
                    if outer_close_fault:
                        self.assertEqual(closes, [''])
                        self.assertEqual(stdout.getvalue(), '')
                        self.assertEqual(json.loads(stderr.getvalue()), {
                            'ok': False, 'code': 'EARLY_RETURN_OUTCOME_UNKNOWN',
                            'returnState': 'UNKNOWN', 'exclusion': 'unknown', 'retryAllowed': False})
                    else:
                        self.assertEqual(json.loads(stdout.getvalue())['returnState'], 'OLD')
                    if virgin_refusal:
                        self.assertFalse((root / 'journal.json').exists())
                        self.assertEqual(host.events, [])
                    if partial:
                        self.assertTrue(any(e[0] == 'stop' for e in host.events))
                        self.assertEqual(host.states, host.original)
                        self.assertFalse(any((masks / name).is_symlink() for name in p['isolateUnits']))
                proc.join(5)
                self.assertFalse(proc.is_alive()); self.assertEqual(proc.exitcode, 0)
                row = json.loads((root / 'host/hold.json').read_bytes())
                self.assertEqual(row['phase'], 'restored'); self.assertEqual(row['frozen'], [])
                self.assertEqual(row['expected'], p['hostHold']['expected'])
            finally:
                os.close(writefd)
                if proc.is_alive(): proc.join(.3)
                if proc.is_alive(): proc.terminate(); proc.join(5)


class RefusalMatrixTests(unittest.TestCase):
    @contextlib.contextmanager
    def prepared(self, *, apply=True):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); masks = root / 'masks'; masks.mkdir()
            p = plan(); host = Host(p)
            with accepted_files(), patch.object(m, 'MASK_ROOT', str(masks)), \
                 patch.object(m, 'RUNNER_FENCES', str(root / 'fences')), patch.object(m.os, 'geteuid', return_value=0):
                engine = m.Engine(root, p, host)
                fd = os.open(root / 'lock', os.O_RDWR | os.O_CREAT, 0o600)
                m.fcntl.flock(fd, m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
                engine._outer_lock_fd = fd
                try:
                    if apply: engine.apply({'fixture': 'guard'})
                    yield engine, host, root, fd
                finally:
                    os.close(fd)

    def test_explicit_same_live_engine_return_after_apply_but_before_capture(self):
        with self.prepared() as (engine, host, root, fd):
            # Normal apply is still a hold, not a manufactured early-return success.
            self.assertEqual(engine.read()['phase'], 'awaiting-fresh-login')
            before = dict(host.profiles)
            result = engine.abort_return(fd)
            self.assertEqual(result['returnState'], 'OLD')
            self.assertEqual(host.states, host.original)
            self.assertEqual(host.profiles, before)
            self.assertEqual(engine.read()['phase'], 'early-returned')
            with self.assertRaisesRegex(m.Refusal, 'LIVE_OWNER_REQUIRED'): engine.abort_return(fd)

    def test_new_engine_cannot_adopt_even_a_known_awaiting_journal(self):
        with self.prepared() as (engine, host, root, fd):
            other = m.Engine(root, engine.plan, host)
            before = list(host.events)
            with self.assertRaisesRegex(m.Refusal, 'LIVE_OWNER_REQUIRED'): other.abort_return(fd)
            self.assertEqual(host.events, before)
            self.assertEqual(engine.read()['phase'], 'awaiting-fresh-login')

    def test_original_inactive_disabled_and_failed_units_are_not_started(self):
        with self.prepared(apply=False) as (engine, host, root, fd):
            host.states['atd.service'].update(ActiveState='failed', SubState='failed')
            host.original = copy.deepcopy(host.states)
            host.fail_checkpoint = True
            self.assertEqual(engine.apply({'fixture': 'guard'})['returnState'], 'OLD')
            self.assertEqual(host.states, host.original)
            starts = [row[-1] for row in host.events if row[:2] == ('/usr/bin/systemctl', 'start')]
            self.assertIn('cron.service', starts)
            self.assertNotIn('cc-agent.service', starts)
            self.assertNotIn('atd.service', starts)

    def test_lost_outer_lock_cannot_be_reacquired_to_retry_return(self):
        with self.prepared() as (engine, host, root, fd):
            before = list(host.events)
            m.fcntl.flock(fd, m.fcntl.LOCK_UN)
            with self.assertRaises(m.Refusal): engine.abort_return(fd)
            m.fcntl.flock(fd, m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
            with self.assertRaisesRegex(m.Refusal, 'LIVE_OWNER_REQUIRED'): engine.abort_return(fd)
            self.assertEqual(host.events, before)

    def test_unknown_mutator_ack_cannot_return_or_be_reclassified_as_known_partial(self):
        with self.prepared(apply=False) as (engine, host, root, fd):
            host.fail_mask = True
            with self.assertRaises(OSError): engine.apply({'fixture': 'guard'})
            before = list(host.events)
            for current in (engine, m.Engine(root, engine.plan, host)):
                with self.assertRaisesRegex(m.Refusal, 'LIVE_OWNER_REQUIRED'): current.abort_return(fd)
            self.assertEqual(engine.read()['phase'], 'isolating')
            self.assertEqual(host.events, before)
            self.assertTrue((root / 'masks/ssh.service').is_symlink())

    def test_unbranded_read_unknown_or_transient_guard_loss_never_authorizes_return(self):
        for fault in ('read', 'guard'):
            with self.subTest(fault=fault), self.prepared(apply=False) as (engine, host, root, fd):
                if fault == 'read':
                    original = host.check_inventory
                    def unknown(p, held=False):
                        if host.masks:
                            host.check_inventory = original
                            raise m.Refusal('UNCLASSIFIED_READ_UNKNOWN')
                        return original(p, held)
                    host.check_inventory = unknown
                else:
                    original = host.guard_check
                    def lost(*args):
                        if host.masks:
                            host.guard_check = original
                            raise m.Refusal('RECOVERY_GUARD_LOST')
                        return original(*args)
                    host.guard_check = lost
                with self.assertRaises(m.Refusal): engine.apply({'fixture': 'guard'})
                before = list(host.events)
                with self.assertRaises(m.Refusal): engine.abort_return(fd)
                self.assertEqual(host.events, before)
                self.assertEqual(engine.read()['phase'], 'isolating')

    def test_known_mask_only_partial_restores_only_completed_owned_masks(self):
        with self.prepared(apply=False) as (engine, host, root, fd):
            original_inventory = host.inventory
            def refuse():
                return {**original_inventory(), 'jobsPresent': host.masks == 2}
            host.inventory = refuse
            # A preexisting alias on an untouched later unit must stay byte/target identical.
            (root / 'masks/cron.service').symlink_to('/accepted-original-cron.service')
            result = engine.apply({'fixture': 'guard'})
            self.assertEqual(result['returnState'], 'OLD')
            self.assertEqual(os.readlink(root / 'masks/cron.service'), '/accepted-original-cron.service')
            self.assertFalse((root / 'masks/ssh.service').is_symlink())
            self.assertFalse(any(e[0] == 'stop' for e in host.events))
            self.assertFalse(any(e[:2] == ('/usr/bin/systemctl', 'start') for e in host.events))

    def test_capture_db_commit_unknown_and_runner_history_remain_retained(self):
        faults = ['originals', 'originals/originals.json.next', 'coordinated-capture.json',
                  'handoff-commit.json.next', 'restore-admission.json',
                  'fences/xray-main/journal.json', 'fences/xray-main/lock']
        for fault in faults:
            with self.subTest(fault=fault), self.prepared() as (engine, host, root, fd):
                path = root / fault
                if fault == 'originals': path.mkdir()
                else:
                    path.parent.mkdir(parents=True, exist_ok=True); path.write_text('{}')
                before = list(host.events)
                with self.assertRaises(m.Refusal): engine.abort_return(fd)
                self.assertEqual(host.events, before)
                self.assertEqual(engine.read()['phase'], 'awaiting-fresh-login')
                if path.is_dir(): path.rmdir()
                else: path.unlink()
                with self.assertRaisesRegex(m.Refusal, 'LIVE_OWNER_REQUIRED'): engine.abort_return(fd)

    def test_lost_guard_and_owned_mask_drift_are_not_repaired_or_retried(self):
        for fault in ('guard', 'mask', 'mask-replacement'):
            with self.subTest(fault=fault), self.prepared() as (engine, host, root, fd):
                if fault == 'guard': host.alive = False
                else:
                    path = root / 'masks/cron.service'
                    # Keep the old inode allocated so replacement identity differs.
                    path.rename(root / 'old-mask')
                    if fault == 'mask': path.write_bytes(b'FOREIGN WINNER')
                    else: path.symlink_to('/dev/null')
                before = list(host.events)
                with self.assertRaises(m.Refusal): engine.abort_return(fd)
                self.assertEqual(host.events, before)
                host.alive = True
                with self.assertRaisesRegex(m.Refusal, 'LIVE_OWNER_REQUIRED'): engine.abort_return(fd)
                if fault == 'mask': self.assertEqual(path.read_bytes(), b'FOREIGN WINNER')

    def test_post_start_ack_unknown_is_one_shot_not_old_or_retained_exclusion(self):
        with self.prepared() as (engine, host, root, fd):
            start = host.start
            def lost_ack(name):
                start(name)
                raise OSError('started but acknowledgement lost')
            host.start = lost_ack
            with self.assertRaises(m.EarlyReturnUnknown): engine.abort_return(fd)
            self.assertEqual(engine.read()['phase'], 'early-return-unknown')
            before = list(host.events)
            with self.assertRaises(m.Refusal): engine.abort_return(fd)
            self.assertEqual(host.events, before)


class FreezerReturnTests(unittest.TestCase):
    def test_failed_thaw_ack_is_return_unknown_not_a_claimed_retained_hold(self):
        spec = importlib.util.spec_from_file_location('return_freezer', HERE.parent / 'panel-host-freezer.py')
        assert spec is not None and spec.loader is not None
        freezer = importlib.util.module_from_spec(spec); spec.loader.exec_module(freezer)
        rows = []
        class Journal:
            def save(self, row): rows.append(copy.deepcopy(row))
        class Kernel:
            def __init__(self): self.frozen = []
            def verify(self, expected, frozen, dead=False):
                if frozen != self.frozen: raise RuntimeError('changed')
            def prepare_relaunch(self, *args): pass
            def split_proxies(self, *args): pass
            def restore_proxies(self, *args): pass
            def restore_relaunch(self, *args): pass
            def freeze(self, group, value):
                if value: self.frozen.append(group)
                else:
                    self.frozen.remove(group)
                    raise OSError('thaw happened but acknowledgement failed')
        kernel = Kernel()
        fence = freezer.Fence({'freezeOrder': ['owned']}, kernel, Journal(), 'owner')
        fence.arm()
        with self.assertRaises(OSError): fence.restore('owner')
        self.assertEqual(kernel.frozen, [])
        self.assertEqual(fence.phase, 'return-unknown')
        self.assertEqual(rows[-1]['phase'], 'return-unknown')
        with self.assertRaises(RuntimeError): fence.restore('owner')


if __name__ == '__main__': unittest.main()
