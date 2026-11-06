"""B132 source-only admission; actual observed constants, modeled OS/daemon seams.

No remote calls, setns, network construction or physical acceptance. Facts were
read through pinned SSH in wave76 (b132.stdout.json in the external evidence).
Boot/netns below are fixture observations, NOT new source acceptance authority:
the independently installed plan must still equal current live facts exactly.
"""
import copy
from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name+'_b132', HERE/(name+'.py'))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('fresh_network')
legacy = load('test_fresh_network')
B_MACHINE = '03ab697936cc4040aa9357936e136744'
B_BOOT = 'fc0be45a-5b0b-42b3-b882-f9cee14be8b4'
B_NETNS = [4, 4026531840]
B_ADDRESSES = [
    ('lo', '127.0.0.1', 8), ('eth0', '132.243.230.19', 24),
    ('docker0', '172.17.0.1', 16), ('br-bed4e62c6d47', '172.18.0.1', 16),
    ('br-bdc639b58573', '172.19.0.1', 16), ('c3test61', '10.203.61.1', 32),
]


def b132_plan():
    p = legacy.plan()
    p.update(machine=B_MACHINE, boot=B_BOOT, hostNetns=list(B_NETNS))
    return p


class PreflightModel:
    """Real validate/check_host/check/check_targets/preflight; OS/peers modeled.

    Only executable hashing/file descriptors are real. Address rows project the
    actual B132 readback; route/rule/peer/Docker/config/RPF facts are synthetic.
    No Linux.__init__, socket, subprocess, setns or mutation method is invoked.
    """
    def __init__(self, p=None):
        self.p = b132_plan() if p is None else p
        self.live = {'machine': B_MACHINE, 'boot': B_BOOT}
        self.identities = {'/proc/1/ns/net': list(B_NETNS), '/proc/self/ns/net': list(B_NETNS),
                           '/proc/1/ns/mnt': [4, 4026531841], '/proc/self/ns/mnt': [4, 4026531841],
                           m.DOCKER: list(self.p['daemon']['socket'])}
        self.snapshots = {r: {k: [] for k in ('links', 'addresses', 'routes', 'rules')}
                          for r in ('host', *m.ROLES)}
        self.snapshots['host']['addresses'] = [
            {'ifname': name, 'addr_info': [{'family': 'inet', 'local': address, 'prefixlen': prefix}]}
            for name, address, prefix in B_ADDRESSES]
        self.snapshots['host']['links'] = [{'ifname': name} for name, _, _ in B_ADDRESSES]
        self.requests = []; self.peers = []
        self.stack = ExitStack()

    def __enter__(self):
        try:
            root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
            self.exe = root/'modeled-executable'; self.exe.write_bytes(b'nonexecuted modeled tool\n')
            self.exe.chmod(0o644)
            self.p['executables'] = {p: m.digest(self.exe.read_bytes()) for p in (m.IP, m.NFT)}
            self.hosts = b'127.0.0.1 localhost\n'
            self.p['hostsSha256'] = m.digest(self.hosts)
            k = self.kernel = m.Linux.__new__(m.Linux)
            k.p = self.p; k.fds = {'host': 71, 'caddy': 72, 'mongo': 73, 'redis': 74}
            k.target_hold = None; k.path_state = 'absent'; k.sealed = None
            k.netns_fd = None; k.owned = {}
            k.check_peer = self.peers.append  # Explicitly modeled peer identity only.
            k.snapshot = lambda role: copy.deepcopy(self.snapshots[role])
            def config(value=None):
                if value is not None: raise AssertionError('NO_CONFIG_WRITE')
                return self.p['oldConfig']
            k.config = config
            read_text = Path.read_text
            def read(path, *args, **kwargs):
                if str(path) == '/etc/machine-id': return self.live['machine']+'\n'
                if str(path) == '/proc/sys/kernel/random/boot_id': return self.live['boot']+'\n'
                return read_text(path, *args, **kwargs)
            sock = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0, st_gid=0)
            real_stat, real_lstat, real_lexists = os.stat, os.lstat, os.path.lexists
            def request(conn, method, path, raw=None):
                if method != 'GET' or raw is not None: raise AssertionError('READ_ONLY_GET_REQUIRED')
                self.requests.append(path)
                if path == '/info': return m.encode({'ID': self.p['daemon']['id'],
                                                     'DockerRootDir': self.p['daemon']['root']})
                if path == '/networks': return b'[]'
                raise AssertionError('UNEXPECTED_DAEMON_READ')
            def trusted_fd(path):
                if path not in (m.IP, m.NFT): raise AssertionError('UNEXPECTED_TOOL')
                return os.open(self.exe, os.O_RDONLY | os.O_CLOEXEC)
            def trusted_read(path):
                if path != '/var/lib/c3-test-fresh-input/root/etc/hosts':
                    raise AssertionError('UNEXPECTED_INPUT')
                return self.hosts
            def joined(fd, fn):
                if fd != k.fds['caddy']: raise AssertionError('UNEXPECTED_JOIN')
                return '2'  # Synthetic read-only RPF result, never call fn/setns.
            for obj, name, value in (
                (Path, 'read_text', read), (m, 'identity', lambda path: list(self.identities[path])),
                (os, 'stat', lambda path, *a, **kw: sock if path == m.DOCKER else real_stat(path, *a, **kw)),
                (os, 'lstat', lambda path, *a, **kw: sock if path == m.DOCKER else real_lstat(path, *a, **kw)),
                (os.path, 'lexists', lambda path: False if path == m.NETNS else real_lexists(path)),
                (m, 'UnixHTTP', lambda host: object()), (m, 'request', request),
                (m, 'trusted_fd', trusted_fd), (m, 'trusted_read', trusted_read),
                (m, 'in_namespace', joined)):
                self.stack.enter_context(patch.object(obj, name, value))
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *args):
        self.stack.close()


class B132Tests(unittest.TestCase):
    def test_actual_b132_identity_passes_real_validate_plan_preserving_internal212(self):
        p = b132_plan()
        self.assertIs(m.validate_plan(p), p)
        self.assertEqual(m.PUBLIC, '212.119.42.100')
        dial = p['newConfig']['apps']['http']['servers']['s']['routes'][0]['handle'][0]['upstreams'][0]['dial']
        self.assertEqual(dial, '212.119.42.100:3000')
        self.assertEqual(p['hostNetns'], [4, 4026531840])

    def test_actual_b132_address_passes_full_real_preflight_with_modeled_os(self):
        with PreflightModel() as model:
            self.assertIs(m.validate_plan(model.p), model.p)
            self.assertEqual(model.kernel.preflight(), model.snapshots)
            self.assertEqual(model.requests, ['/info', '/networks'])
            self.assertEqual(model.peers, list(m.ROLES))

    def test_current_holder_consumes_actual_constructor_source_pin_before_host_boundary(self):
        client = load('fresh_network_client')
        raw = {m.INPUT: m.encode(b132_plan()),
               m.LIB: (HERE/'fresh_network.py').read_bytes(),
               client.CONTROL: (HERE/'fresh_network_control.py').read_bytes(),
               client.SERVER_ENTRY: (HERE/'fresh_network_exec.py').read_bytes(),
               client.CLIENT: (HERE/'fresh_network_client.py').read_bytes()}
        seen = []
        class Input:
            def __init__(self, module, path):
                seen.append(path); self.raw = raw[path]
            def close(self): pass
        class HostBoundary(RuntimeError): pass
        with patch.object(client, 'Input', Input), \
             patch.object(client, '__source_sha256__', m.digest(raw[client.CLIENT]), create=True), \
             patch.object(client.Holder, 'check', side_effect=HostBoundary('MODELED_HOST_BOUNDARY')):
            with self.assertRaisesRegex(HostBoundary, 'MODELED_HOST_BOUNDARY'):
                client.Holder(m, object())
        self.assertEqual(seen, list(raw))

    def test_unknown_machine_and_malformed_boot_remain_closed_plan_refusals(self):
        for machine in ('f'*32, B_MACHINE.upper(), [B_MACHINE], None, 132):
            with self.subTest(machine=machine):
                p = b132_plan(); p['machine'] = machine
                with self.assertRaisesRegex(m.Refusal, '^FIXED_TEST_MACHINE_BOOT_REQUIRED$'):
                    m.validate_plan(p)
        for boot in ('2'*36, B_BOOT.upper(), '', None, [B_BOOT]):
            with self.subTest(boot=boot):
                p = b132_plan(); p['boot'] = boot
                with self.assertRaisesRegex(m.Refusal, '^FIXED_TEST_MACHINE_BOOT_REQUIRED$'):
                    m.validate_plan(p)

    def test_wrong_live_machine_boot_and_host_namespaces_refuse_before_daemon(self):
        cases = ('machine', 'boot', 'hostNetns', 'selfNetns', 'mountNetns')
        for case in cases:
            with self.subTest(case=case), PreflightModel() as model:
                self.assertIs(m.validate_plan(model.p), model.p)
                if case == 'machine': model.live['machine'] = m.TEST_MACHINE
                if case == 'boot': model.live['boot'] = '22222222-2222-2222-2222-222222222222'
                if case == 'hostNetns': model.identities['/proc/1/ns/net'][1] += 1
                if case == 'selfNetns': model.identities['/proc/self/ns/net'][1] += 1
                if case == 'mountNetns': model.identities['/proc/self/ns/mnt'][1] += 1
                with self.assertRaisesRegex(m.Refusal, '^WRONG_TEST_HOST_OR_NAMESPACE$'):
                    model.kernel.preflight()
                self.assertEqual(model.requests, [])
                self.assertEqual(model.peers, [])

    def test_wrong_physical_interface_address_prefix_and_duplicates_refuse(self):
        for case in ('missing', 'interface', 'address', 'legacy212', 'prefix', 'duplicate'):
            with self.subTest(case=case), PreflightModel() as model:
                rows = model.snapshots['host']['addresses']; row = rows[1]
                if case == 'missing': rows.remove(row)
                if case == 'interface': row['ifname'] = 'enp0s18'
                if case == 'address': row['addr_info'][0]['local'] = '132.243.230.20'
                if case == 'legacy212': row['addr_info'][0]['local'] = '212.119.42.100'
                if case == 'prefix': row['addr_info'][0]['prefixlen'] = 32
                if case == 'duplicate': rows.append(copy.deepcopy(row))
                with self.assertRaisesRegex(m.Refusal, '^FIXED_TEST_PUBLIC_ADDRESS_REQUIRED$'):
                    model.kernel.preflight()
                self.assertEqual(model.requests, ['/info'])

    def test_legacy_placement_still_requires_legacy_host_address_not_b132(self):
        p = legacy.plan(); p.update(boot=B_BOOT, hostNetns=list(B_NETNS))
        with PreflightModel(p) as model:
            model.live['machine'] = m.TEST_MACHINE
            self.assertIs(m.validate_plan(p), p)
            with self.assertRaisesRegex(m.Refusal, '^FIXED_TEST_PUBLIC_ADDRESS_REQUIRED$'):
                model.kernel.preflight()
            model.snapshots['host']['addresses'][1]['addr_info'][0]['local'] = '212.119.42.100'
            self.assertEqual(model.kernel.preflight(), model.snapshots)
            self.assertEqual(model.requests, ['/info', '/info', '/networks'])

    def test_b132_does_not_change_private_lo_caddy_route_rule_or_probe(self):
        k = m.Linux.__new__(m.Linux); events = []
        k.step = lambda label, fn: events.append(label)  # Never call mutators.
        k.write_ip = lambda where, *args: events.append((where, args))
        k.create_namespace()
        self.assertEqual(events, ['netns-mountpoint-create', 'netns-private-mount',
            ('fresh', ('link', 'set', 'lo', 'up')),
            ('fresh', ('address', 'add', '212.119.42.100/32', 'dev', 'lo'))])
        p = b132_plan(); wire = legacy.WireKernel(p)
        with tempfile.TemporaryDirectory() as d:
            j = legacy.m.Journal(Path(d)/'generation', p)
            try:
                legacy.m.Controller(p, wire, j, guard=wire.guard)
                with patch.object(legacy.m, 'move_link', side_effect=wire.move):
                    wire.connect('caddy')
            finally: j.close()
        self.assertIn(('caddy', ('route', 'add', '212.119.42.100/32', 'via', '10.253.241.5',
             'dev', 'c3pc', 'src', '10.253.241.6', 'table', '39303')), wire.commands)
        self.assertIn(('caddy', ('rule', 'add', 'priority', '10303', 'to', '212.119.42.100/32',
             'ipproto', 'tcp', 'dport', '3000', 'table', '39303')), wire.commands)
        self.assertTrue(all(args[0] == 'link' for where, args in wire.commands if where == 'host'))
        k.fds = {'fresh': 81}; k.serving_pin = lambda: (123, '456')
        with patch.object(m, 'in_namespace', side_effect=lambda fd, fn: fn()) as joined, \
             patch.object(m, 'bound_probe', return_value='modeled-probe') as probe:
            self.assertEqual(k.direct_probe(), 'modeled-probe')
        self.assertEqual(joined.call_args.args[0], 81)
        probe.assert_called_once_with(123, '456')
        self.assertEqual(m.bound_probe.__defaults__, ('212.119.42.100', 3000))
        p['newConfig']['apps']['http']['servers']['s']['routes'][0]['handle'][0]['upstreams'][0]['dial'] = '132.243.230.19:3000'
        with self.assertRaisesRegex(m.Refusal, '^EXACT_ONE_CADDY_UPSTREAM_CHANGE_REQUIRED$'):
            m.validate_plan(p)

    def test_holder_rejects_each_changed_source_before_host_boundary(self):
        client = load('fresh_network_client')
        sources = {m.LIB: (HERE/'fresh_network.py').read_bytes(),
                   client.CONTROL: (HERE/'fresh_network_control.py').read_bytes(),
                   client.SERVER_ENTRY: (HERE/'fresh_network_exec.py').read_bytes(),
                   client.CLIENT: (HERE/'fresh_network_client.py').read_bytes()}
        for target in sources:
            with self.subTest(target=target):
                class Input:
                    def __init__(self, module, path):
                        self.raw = m.encode(b132_plan()) if path == m.INPUT else sources[path]
                        if path == target: self.raw += b'\n# changed source\n'
                    def close(self): pass
                with patch.object(client, 'Input', Input), \
                     patch.object(client, '__source_sha256__', m.digest(sources[client.CLIENT]), create=True), \
                     patch.object(client.Holder, 'check') as checked:
                    with self.assertRaisesRegex(m.Refusal, '^INSTALLED_SOURCE_PIN_REQUIRED$'):
                        client.Holder(m, object())
                    checked.assert_not_called()

    def test_frozen_server_and_client_entries_refuse_current_source_drift(self):
        # Real nofollow descriptor walk/hash guard; only root ownership is modeled.
        class RootStat:
            st_uid = st_gid = 0
            def __init__(self, raw): self.raw = raw
            def __getattr__(self, name): return getattr(self.raw, name)
            def __eq__(self, other): return isinstance(other, RootStat) and self.raw == other.raw
        real_open, real_fstat = os.open, os.fstat
        cases = (('fresh_network_exec', m.LIB, 'fresh_network.py'),
                 ('fresh_network_client_exec', m.LIB, 'fresh_network.py'),
                 ('fresh_network_client_exec', '/usr/local/libexec/c3-test-fresh-network-client.py', 'fresh_network_client.py'))
        for name, installed, local in cases:
            with self.subTest(entry=name, source=local), tempfile.TemporaryDirectory() as d:
                entry = load(name); raw = (HERE/local).read_bytes()
                self.assertNotEqual(entry.PINS[installed], m.digest(raw))
                root = Path(d); target = root/installed.lstrip('/')
                target.parent.mkdir(parents=True); target.write_bytes(raw); target.chmod(0o644)
                for directory in (root/'usr', root/'usr/local', root/'usr/local/libexec'):
                    directory.chmod(0o755)
                with patch.object(entry.os, 'open', side_effect=lambda path, *a, **kw:
                                  real_open(root if path == '/' else path, *a, **kw)), \
                     patch.object(entry.os, 'fstat', side_effect=lambda fd: RootStat(real_fstat(fd))):
                    with self.assertRaisesRegex(RuntimeError, '^INSTALLED_SOURCE_PIN_REQUIRED$'):
                        entry.load(installed)


if __name__ == '__main__':
    unittest.main()
