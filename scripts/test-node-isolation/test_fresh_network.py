"""Real files/process/codec tests; every kernel and Docker fact below is modeled."""
import copy
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('fresh_network', Path(__file__).with_name('fresh_network.py'))
assert SPEC is not None and SPEC.loader is not None
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def plan():
    old = {'apps': {'http': {'servers': {'s': {'routes': [{'handle': [
        {'handler': 'reverse_proxy', 'upstreams': [{'dial': 'backend:3000'}]}]}]}}}}}
    new = copy.deepcopy(old)
    new['apps']['http']['servers']['s']['routes'][0]['handle'][0]['upstreams'][0]['dial'] = m.PUBLIC+':3000'
    return {'version': 1, 'context': m.CONTEXT, 'machine': m.TEST_MACHINE, 'boot': '22222222-2222-2222-2222-222222222222',
            'hostNetns': [1, 2], 'generation': 'a'*32, 'deadline': int(time.time())+500,
            'daemon': {'socket': [1, 3], 'id': 'accepted-daemon', 'root': '/var/lib/docker'},
            'executables': {m.IP: 'a'*64, m.NFT: 'b'*64}, 'hostsSha256': 'c'*64,
            'peers': {role: {'id': str(i)*64, 'inspectSha256': 'd'*64,
                             'subnet': '10.253.241.%d/30' % (4*i),
                             'address': {'caddy': '172.19.0.4', 'mongo': '172.19.0.5', 'redis': '172.19.0.6'}[role]}
                      for i, role in enumerate(m.ROLES, 1)}, 'oldConfig': old, 'newConfig': new}


class ModelKernel:
    """Only models effects, never claimed as kernel/Docker/application evidence."""
    def __init__(self, p):
        self.p = p
        self.calls = []
        self.current = copy.deepcopy(p['oldConfig'])
        self.fail: str | None = None
    def call(self, name):
        self.calls.append(name)
        if name == self.fail:
            raise m.Refusal('MODELED_FAULT')
    def check(self): self.call('check')
    def preflight(self): self.call('preflight'); return {'modeled': True}
    def create_namespace(self): self.call('create')
    def firewall(self): self.call('firewall')
    def connect(self, role): self.call('connect-'+role)
    def seal(self): self.call('seal')
    def observation(self): self.call('observe'); return {'namespace': [7, 8], 'modeled': True}
    def direct_probe(self): self.call('direct-http')
    def caddy_probe(self): self.call('caddy-http')
    def return_probe(self): self.call('old-backend-bound-http')
    def close_holds(self): pass
    def public_probe(self): self.call('public-https')
    def config(self, value=None):
        if value is not None:
            self.call('write-config')
            self.current = copy.deepcopy(value)
        return self.current
    def remove(self, baseline): self.call('remove')


class WireKernel(m.Linux):
    """Real Linux orchestration; kernel writes/observations ONLY modeled in memory."""
    def __init__(self, p):
        self.p = p
        self.fds = {x: i+90 for i, x in enumerate(('host', 'fresh', *m.ROLES))}
        self.sealed = None; self.firewall_seal = None; self.netns_fd = None
        self.path_state = 'mounted'; self.path_identity = None
        self.owned = {}; self.commands = []; self.writes = []; self.lose_after: int | None = None; self.alive = True
        self.state = {x: {k: [] for k in ('links', 'addresses', 'routes', 'rules')} for x in self.fds}
    def require_empty_namespace(self): pass  # Explicitly modeled task inventory.
    def check_host(self): pass
    def check_peer(self, role): pass
    def nft_observation(self): return {'modeled': True}
    def snapshot(self, where): return copy.deepcopy(self.state[where])
    def config(self, value=None): return self.p['oldConfig']
    def guard(self): m.need(self.alive, 'MODELED_GUARD_LOST')
    def written(self, label):
        self.writes.append(label)
        if len(self.writes) == self.lose_after: self.alive = False
    def invoke(self, where, fn):
        self.boundary()
        # sysctl has an explicit modeled readback; never touch real proc controls.
        if fn.__name__ == 'rpf': self.written('sysctl:'+where); return True
        return fn()
    def move(self, index, target, before_send=lambda: None):
        before_send()
        where = next(k for k, v in self.fds.items() if v == target)
        row = next(x for x in self.state['host']['links'] if x['ifindex'] == index)
        self.state['host']['links'].remove(row); self.state[where]['links'].append(row)
        self.written('move:'+where)
        return True
    def ip(self, where, *args):
        self.boundary()
        self.commands.append((where, args))
        s = self.state[where]
        if args[:2] == ('link', 'add'):
            own, peer = args[2], args[-1]; index = 10+len(self.owned)
            for name, i, j in ((own, index, index+1), (peer, index+1, index)):
                s['links'].append({'ifname': name, 'ifindex': i, 'link_index': j,
                                   'link_type': 'ether', 'linkinfo': {'info_kind': 'veth'}})
        elif args[:2] == ('link', 'set'):
            row = next(x for x in s['links'] if x['ifname'] == args[2])
            if args[3] == 'alias': row['ifalias'] = args[4]
        elif args[:2] == ('link', 'del'):
            role = next(r for r in m.ROLES if m.NAMES[r][0] == args[2])
            for w, name in (('fresh', m.NAMES[role][0]), (role, m.NAMES[role][1])):
                for kind in ('links', 'addresses', 'routes'):
                    self.state[w][kind] = [x for x in self.state[w][kind]
                                           if x.get('ifname') != name and x.get('dev') != name]
        elif args[:2] == ('address', 'add'):
            s['addresses'].append({'ifname': args[-1], 'addr_info': [{'local': args[2]}]})
        elif args[0] == 'route':
            row = {'dst': args[2], 'gateway': args[4], 'dev': args[6], 'prefsrc': args[8]}
            if 'table' in args: row['table'] = args[-1]
            if args[1] == 'add': s['routes'].append(row)
            else: s['routes'].remove(row)
        elif args[0] == 'rule':
            row = {'priority': m.PRIORITY, 'table': m.TABLE}
            if args[1] == 'add': s['rules'].append(row)
            else: s['rules'].remove(row)
        else: raise AssertionError(args)
        self.written('ip:'+where+':'+':'.join(args))
        return ''


class NetworkTests(unittest.TestCase):
    def test_actual_link_serialization_is_narrow_and_no_adoption(self):
        p = m.link_commands('caddy', '10.253.241.0/30', 'a'*32)
        self.assertEqual(p[0], ('link', 'add', 'c3nc', 'type', 'veth', 'peer', 'name', 'c3pc'))
        self.assertEqual(p[1][-1], 'c3:'+'a'*32+':caddy:fresh')
        self.assertFalse(any('replace' in cmd or 'flush' in cmd or 'eth0' in cmd for cmd in p))

    def test_veth_move_is_serialized_as_namespace_fd_not_pid_or_path(self):
        raw = m.move_message(17, 41, 23)
        import struct
        length, kind, flags, seq, pid = struct.unpack_from('IHHII', raw)
        self.assertEqual((length, kind, flags, seq, pid), (40, 16, 5, 23, 0))
        self.assertEqual(struct.unpack_from('BBHiII', raw, 16), (0, 0, 0, 17, 0, 0))
        self.assertEqual(struct.unpack_from('HHi', raw, 32), (8, 28, 41))

    def test_closed_plan_and_private_subnets(self):
        self.assertIs(m.validate_plan(plan())['version'], 1)
        for mutation in ('context', 'machine', 'boot', 'version', 'extra', 'subnet', 'overlap', 'config', 'id'):
            p = plan()
            if mutation == 'context': p['context'] = 'prod.infograd.online'
            if mutation == 'machine': p['machine'] = 'f'*32
            if mutation == 'boot': p['boot'] = '2'*36
            if mutation == 'version': p['version'] = True
            if mutation == 'extra': p['command'] = 'echo forbidden'
            if mutation == 'subnet': p['peers']['caddy']['subnet'] = '212.119.42.0/30'
            if mutation == 'overlap': p['peers']['mongo']['subnet'] = p['peers']['caddy']['subnet']
            if mutation == 'config': p['newConfig']['admin'] = {'listen': ':2019'}
            if mutation == 'id': p['peers']['redis']['id'] = p['peers']['mongo']['id']
            with self.subTest(mutation=mutation), self.assertRaises(m.Refusal):
                m.validate_plan(p)

    def test_n3_config_isolation_rejects_json_type_changes(self):
        for before, after in ((False, 0), (True, 1), (1, 1.0)):
            with self.subTest(before=before, after=after):
                p = plan()
                p['oldConfig']['unrelated'] = {'nested': [before]}
                p['newConfig']['unrelated'] = {'nested': [after]}
                with self.assertRaisesRegex(m.Refusal, 'EXACT_ONE_CADDY'):
                    m.validate_plan(p)

    def test_missing_private_default_route_cannot_enable_vpn_egress(self):
        raw = m.nft_policy(plan()).decode()
        self.assertIn('chain forward { type filter hook forward priority 0; policy drop;', raw)
        self.assertEqual(raw.count('policy drop;'), 3)
        self.assertIn('ip daddr 172.19.0.5 tcp dport 27017 accept', raw)
        self.assertIn('ip daddr 172.19.0.6 tcp dport 6379 accept', raw)
        self.assertNotIn('masquerade', raw)
        self.assertNotIn('dnat', raw)

    def controller(self, root):
        p = plan(); k = ModelKernel(p); j = m.Journal(Path(root)/'generation', p)
        self.addCleanup(j.close)
        return m.Controller(p, k, j), k, j

    def command(self, c, op):
        return c.command({'generation': c.p['generation'], 'sequence': c.seq+1, 'operation': op})

    def test_model_prepare_does_not_change_public_config_and_seals_before_observation(self):
        with tempfile.TemporaryDirectory() as d:
            c, k, _ = self.controller(d)
            result = c.prepare()
            self.assertEqual(k.current, c.p['oldConfig'])
            self.assertLess(k.calls.index('firewall'), k.calls.index('connect-caddy'))
            self.assertIn('seal', k.calls)
            self.assertLess(k.calls.index('seal'), k.calls.index('observe'))
            self.assertEqual(result['phase'], 'prepared')
            self.assertIs(result['operationalGO'], False)
            self.assertIs(result['physicalAccepted'], False)

    def test_model_exact_cutover_return_abandon_and_no_replay(self):
        with tempfile.TemporaryDirectory() as d:
            c, k, j = self.controller(d); c.prepare()
            self.assertEqual(self.command(c, 'cutover')['phase'], 'cutover')
            self.assertLess(k.calls.index('direct-http'), k.calls.index('write-config'))
            self.assertLess(k.calls.index('caddy-http'), k.calls.index('write-config'))
            with self.assertRaises(m.Refusal): self.command(c, 'abandon')
            self.assertEqual(self.command(c, 'return')['phase'], 'returned')
            self.assertEqual(self.command(c, 'abandon')['phase'], 'abandoned')
            with self.assertRaises(m.Refusal): c.prepare()
            with self.assertRaises(FileExistsError): m.Journal(Path(d)/'generation', c.p)
            records = [m.decode(p.read_bytes()) for p in sorted((Path(d)/'generation').iterdir())]
            self.assertTrue(any(x.get('effect') == 'caddy-exact-new-config' and x['kind'] == 'intent' for x in records))

    def test_model_ambiguous_mutation_is_sticky_and_never_auto_restores(self):
        for failure in ('create', 'firewall', 'connect-mongo', 'write-config', 'public-https'):
            with tempfile.TemporaryDirectory() as d, self.subTest(failure=failure):
                c, k, _ = self.controller(d)
                if failure in ('write-config', 'public-https'):
                    c.prepare(); k.fail = failure
                    with self.assertRaises(m.Refusal): self.command(c, 'cutover')
                else:
                    k.fail = failure
                    with self.assertRaises(m.Refusal): c.prepare()
                self.assertEqual(c.phase, 'unknown-retained')
                previous = k.calls.count('write-config')
                k.fail = None
                for op in ('return', 'abandon', 'cutover'):
                    with self.assertRaises(m.Refusal): self.command(c, op)
                self.assertEqual(k.calls.count('write-config'), previous)
                self.assertNotIn('remove', k.calls)

    def test_model_expiry_and_stale_generation_refuse_before_effects(self):
        with tempfile.TemporaryDirectory() as d:
            c, k, _ = self.controller(d); c.prepare()
            seq = c.seq
            with self.assertRaises(m.Refusal):
                c.command({'generation': 'f'*32, 'sequence': seq+1, 'operation': 'cutover'})
            with self.assertRaises(m.Refusal):
                c.command({'generation': c.p['generation'], 'sequence': True, 'operation': 'cutover'})
            c.end = c.clock()-1
            with self.assertRaises(m.Refusal): self.command(c, 'cutover')
            self.assertNotIn('write-config', k.calls)
    def test_docker_dns_packet_parser_never_uses_host_dns_fallback(self):
        import struct
        token = b'xy'
        question = b'\x07backend\x00\x00\x01\x00\x01'
        raw = token+struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)+question
        raw += b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 600, 4)+socket.inet_aton('172.19.0.3')
        self.assertEqual(m.parse_backend_dns(raw, token), ['172.19.0.3'])
        for changed in (raw[:-1], b'zz'+raw[2:], raw+b'extra', raw[:2]+b'\x83\x80'+raw[4:]):
            with self.assertRaises(m.Refusal): m.parse_backend_dns(changed, token)

    def test_modeled_docker_inspect_refuses_wrong_id_network_and_address(self):
        pid = os.getpid()
        container = {'Id': '1'*64, 'State': {'Pid': pid, 'Running': True, 'Paused': False, 'Restarting': False},
                     'Image': 'sha256:'+'a'*64, 'RestartCount': 0,
                     'NetworkSettings': {'Networks': {'accepted': {'NetworkID': 'b'*64, 'IPAddress': '172.19.0.4'}}}}
        projection = {'id': container['Id'], 'pid': pid, 'start': m.proc_start(pid),
                      'netns': m.identity('/proc/self/ns/net'), 'image': container['Image'],
                      'restartCount': 0, 'networks': container['NetworkSettings']['Networks']}
        kernel = m.Linux.__new__(m.Linux); kernel.p = plan()
        kernel.p['peers']['caddy']['inspectSha256'] = m.digest(m.encode(projection))
        with patch.object(m, 'request', return_value=m.encode(container)):
            self.assertEqual(kernel.inspect('caddy'), projection)
        for mutation in ('id', 'network', 'address', 'restart'):
            changed = copy.deepcopy(container)
            if mutation == 'id': changed['Id'] = 'f'*64
            if mutation == 'network': changed['NetworkSettings']['Networks']['accepted']['NetworkID'] = 'f'*64
            if mutation == 'address': changed['NetworkSettings']['Networks']['accepted']['IPAddress'] = '172.19.0.8'
            if mutation == 'restart': changed['RestartCount'] = 1
            with self.subTest(mutation=mutation), patch.object(m, 'request', return_value=m.encode(changed)):
                with self.assertRaises(m.Refusal): kernel.inspect('caddy')

    def test_modeled_owned_network_drift_refuses_before_caddy_write(self):
        with tempfile.TemporaryDirectory() as d:
            c, k, _ = self.controller(d); c.prepare()
            k.fail = 'check'
            with self.assertRaises(m.Refusal): self.command(c, 'abandon')
            self.assertNotIn('remove', k.calls)
            self.assertNotIn('write-config', k.calls)

    def test_physical_constructor_consumes_exact_same_netns_path_and_no_host_repair(self):
        spec = importlib.util.spec_from_file_location('physical_contract', Path(__file__).with_name('fresh_physical.py'))
        assert spec is not None and spec.loader is not None
        physical = importlib.util.module_from_spec(spec); spec.loader.exec_module(physical)
        self.assertEqual(physical.NETNS, m.NETNS)
        self.assertEqual(physical.CONTEXT, m.CONTEXT)
        self.assertEqual(m.NETNS, '/run/netns/c3-test-fresh-classic')

    def test_root_owner_peer_refusal_uses_real_unix_credentials(self):
        spec = importlib.util.spec_from_file_location('control', Path(__file__).with_name('fresh_network_control.py'))
        assert spec is not None and spec.loader is not None
        control = importlib.util.module_from_spec(spec); spec.loader.exec_module(control)
        lease = control.Lease.__new__(control.Lease)
        lease.m = m
        lease.holder = {'pid': os.getpid()+1, 'start': m.proc_start(os.getpid())}
        checked = []
        lease.check = lambda: checked.append(True)
        a, b = socket.socketpair()
        with a, b:
            with self.assertRaisesRegex(m.Refusal, 'EXACT_ROOT_OWNER_REQUIRED'):
                lease.peer(b)
        self.assertEqual(checked, [])

    def test_owner_lease_loss_is_sticky_with_real_pidfd(self):
        spec = importlib.util.spec_from_file_location('control', Path(__file__).with_name('fresh_network_control.py'))
        assert spec is not None and spec.loader is not None
        control = importlib.util.module_from_spec(spec); spec.loader.exec_module(control)
        child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(5)'])
        fd = os.pidfd_open(child.pid)
        try:
            lease = control.Lease.__new__(control.Lease)
            lease.m = m; lease.p = plan(); lease.holder = {'pid': child.pid, 'start': m.proc_start(child.pid)}
            lease.pidfd = fd; lease.revoked = False
            child.terminate(); child.wait(timeout=3)
            with self.assertRaisesRegex(m.Refusal, 'OWNER_LEASE_LOST'): lease.check()
            self.assertTrue(lease.revoked)
            with self.assertRaises(m.Refusal): lease.check()
        finally:
            if child.poll() is None: child.kill(); child.wait(timeout=3)
            os.close(fd)

    def test_n1_connect_stops_after_first_external_dispatch_on_guard_loss(self):
        kernel = WireKernel(plan()); kernel.lose_after = 1
        mutations = kernel.writes
        guard = kernel.guard
        with tempfile.TemporaryDirectory() as d:
            j = m.Journal(Path(d)/'generation', kernel.p)
            self.addCleanup(j.close)
            c = m.Controller(kernel.p, kernel, j, guard=guard)
            with patch.object(m, 'move_link', side_effect=kernel.move):
                with self.assertRaises(m.Refusal):
                    c.effect('connect-caddy', lambda: kernel.connect('caddy'))
            self.assertEqual(len(mutations), 1, 'no dispatch after guard loss')
            self.assertEqual(c.phase, 'unknown-retained')
            records = [m.decode(x.read_bytes()) for x in sorted(j.path.iterdir())]
            self.assertFalse(any(x['kind'] == 'confirmed' for x in records))

    def test_n1_each_connect_boundary_retains_unknown_without_followup(self):
        for role in m.ROLES:
            for stop in range(1, 16 if role == 'caddy' else 15):
                with self.subTest(role=role, stop=stop), tempfile.TemporaryDirectory() as d:
                    k = WireKernel(plan()); k.lose_after = stop
                    j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
                    c = m.Controller(k.p, k, j, guard=k.guard)
                    with patch.object(m, 'move_link', side_effect=k.move):
                        with self.assertRaises(m.Refusal): k.connect(role)
                    self.assertEqual(len(k.writes), stop)
                    self.assertEqual(c.phase, 'unknown-retained')
                    records = [m.decode(x.read_bytes()) for x in sorted(j.path.iterdir())]
                    intents = [x for x in records if x['kind'] == 'intent']
                    confirmed = [x for x in records if x['kind'] == 'confirmed']
                    self.assertEqual(len(intents), stop)
                    self.assertEqual(len(confirmed), stop-1)
                    k.alive = True
                    with self.assertRaises(m.Refusal): k.connect(role)
                    self.assertEqual(len(k.writes), stop)

    def test_n1_remove_each_boundary_keeps_evolving_seal_and_stops(self):
        for stop in range(1, 8):
            with self.subTest(stop=stop), tempfile.TemporaryDirectory() as d:
                k = WireKernel(plan())
                baseline = copy.deepcopy(k.state)
                j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
                c = m.Controller(k.p, k, j, guard=k.guard)
                with patch.object(m, 'move_link', side_effect=k.move):
                    for role in m.ROLES: k.connect(role)
                k.seal(); k.writes.clear(); k.lose_after = stop
                mountpoint = Path(d)/'owned-netns'; mountpoint.write_bytes(b'owned')
                k.path_identity = m.identity(mountpoint)
                original_unlink = os.unlink
                def unmount(*args): k.written('umount'); return 0
                def unlink(path, *args, **kwargs):
                    original_unlink(path, *args, **kwargs); k.written('unlink')
                with patch.object(m, 'NETNS', str(mountpoint)), patch.object(m, 'syscall', side_effect=unmount), \
                     patch.object(m.os, 'unlink', side_effect=unlink):
                    with self.assertRaises(m.Refusal): k.remove(baseline)
                self.assertEqual(len(k.writes), stop)
                self.assertIsNotNone(k.sealed)
                self.assertEqual(c.phase, 'unknown-retained')
                records = [m.decode(x.read_bytes()) for x in sorted(j.path.iterdir())]
                self.assertEqual(records[-1]['kind'], 'intent')

    def test_n1_real_ack_parser_through_move_link_with_modeled_socket(self):
        import struct
        raw = m.move_message(17, 41, 1)
        ack = struct.pack('IHHIIi', 36, 2, 0, 1, 123, 0)+raw[:16]
        cases = [(ack, (0, 0), True),
                 (ack[:6]+struct.pack('H', 0x100)+ack[8:], (0, 0), True),
                 (ack[:20], (0, 0), False),
                 (ack+b'x', (0, 0), False), (ack, (123, 0), False),
                 (struct.pack('I', 40)+ack[4:]+b'junk', (0, 0), False),
                 (ack[:6]+struct.pack('H', 0x200)+ack[8:], (0, 0), False),
                 (ack[:8]+struct.pack('I', 2)+ack[12:], (0, 0), False),
                 (ack[:16]+struct.pack('i', -1)+ack[20:], (0, 0), False),
                 (ack[:20]+b'X'+ack[21:], (0, 0), False),
                 (struct.pack('IHHIIi', 36, 3, 0, 1, 123, 0)+raw[:16], (0, 0), False)]
        from unittest.mock import MagicMock
        for reply, sender, ok in cases:
            with self.subTest(reply=reply, sender=sender):
                channel = MagicMock(); channel.__enter__.return_value = channel
                channel.sendto.return_value = len(raw); channel.recvfrom.return_value = (reply, sender)
                with patch.object(m.socket, 'socket', return_value=channel):
                    if ok: self.assertTrue(m.move_link(17, 41))
                    else:
                        with self.assertRaises(m.Refusal): m.move_link(17, 41)

    def test_n1_owned_target_drift_after_completed_step_stops_next_dispatch(self):
        for operation in ('connect', 'remove'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as d:
                k = WireKernel(plan()); baseline = copy.deepcopy(k.state)
                j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
                c = m.Controller(k.p, k, j, guard=k.guard)
                with patch.object(m, 'move_link', side_effect=k.move):
                    if operation == 'remove':
                        for role in m.ROLES: k.connect(role)
                        k.seal(); k.writes.clear()
                    original = k.written
                    def drift(label):
                        original(label)
                        if len(k.writes) == (2 if operation == 'connect' else 1):
                            where = 'host' if operation == 'connect' else 'fresh'
                            k.state[where]['links'][0]['ifalias'] = 'foreign'
                    k.written = drift
                    with self.assertRaises(m.Refusal):
                        if operation == 'connect': k.connect('caddy')
                        else: k.remove(baseline)
                self.assertEqual(len(k.writes), 2 if operation == 'connect' else 1)
                self.assertEqual(c.phase, 'unknown-retained')
                self.assertTrue(k.alive)

    def test_n1_leaf_dispatch_rechecks_guard_after_namespace_join(self):
        for operation in ('ip', 'nft', 'caddy'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as d:
                k = WireKernel(plan()); k.pids = {'caddy': os.getpid()}
                k.invoke = lambda where, fn: m.Linux.invoke(k, where, fn)
                j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
                c = m.Controller(k.p, k, j, guard=k.guard)
                def joined(fd, fn):
                    k.alive = False
                    return fn()
                with patch.object(m, 'in_namespace', side_effect=joined), \
                     patch.object(m.subprocess, 'run') as run, patch.object(m, 'request') as request, \
                     patch.object(m, 'require_listener'):
                    with self.assertRaises(m.Refusal):
                        if operation == 'ip':
                            c.effect('leaf-ip', lambda: m.Linux.ip(k, 'fresh', 'link', 'set', 'lo', 'up'))
                        elif operation == 'nft': m.Linux.firewall(k)
                        else: m.Linux.config(k, k.p['newConfig'])
                run.assert_not_called(); request.assert_not_called()
                self.assertEqual(c.phase, 'unknown-retained')

    def test_n1_exact_control_socket_unlink_guard_loss_and_positive(self):
        spec = importlib.util.spec_from_file_location('control_unlink', Path(__file__).with_name('fresh_network_control.py'))
        assert spec is not None and spec.loader is not None
        control = importlib.util.module_from_spec(spec); spec.loader.exec_module(control)
        for timing in ('before', 'after', 'success'):
            with self.subTest(timing=timing), tempfile.TemporaryDirectory() as d:
                c, k, j = self.controller(d); c.phase = 'abandoned'
                path = str(Path(d)/'owned.sock')
                original = os.unlink
                def unlink(target, *args, **kwargs):
                    original(target, *args, **kwargs)
                    if timing == 'after': k.fail = 'check'
                with socket.socket(socket.AF_UNIX) as listener:
                    listener.bind(path); accepted = m.identity(path)
                    if timing == 'before': k.fail = 'check'
                    with patch.object(m, 'SOCKET', path), patch.object(control.os, 'unlink', side_effect=unlink):
                        if timing == 'success': control.unlink_owned_control(m, c, accepted)
                        else:
                            with self.assertRaises(m.Refusal): control.unlink_owned_control(m, c, accepted)
                    self.assertEqual(os.path.lexists(path), timing == 'before')
                    self.assertEqual(c.phase, 'abandoned' if timing == 'success' else 'unknown-retained')
                    records = [m.decode(x.read_bytes()) for x in sorted(j.path.iterdir())]
                    self.assertEqual(any(x['kind'] == 'confirmed' for x in records), timing == 'success')

    def test_n1_mountpoint_creation_guard_loss_prevents_next_mount(self):
        with tempfile.TemporaryDirectory() as d:
            k = WireKernel(plan()); k.path_state = 'absent'
            j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
            c = m.Controller(k.p, k, j, guard=k.guard)
            target = str(Path(d)/'owned-netns'); original = os.open
            def open_(path, flags, *args, **kwargs):
                fd = original(path, flags, *args, **kwargs)
                if flags & os.O_CREAT and path == 'owned-netns': k.alive = False
                return fd
            with patch.object(m, 'NETNS', target), patch.object(m, 'trusted_fd', side_effect=lambda *a, **kw: original(d, os.O_RDONLY | os.O_DIRECTORY)), \
                 patch.object(m.os, 'open', side_effect=open_), patch.object(m, 'syscall') as call:
                with self.assertRaises(m.Refusal): k.create_namespace()
            self.assertTrue(os.path.isfile(target)); call.assert_not_called()
            self.assertEqual(c.phase, 'unknown-retained')

    def test_n1_mount_guard_loss_after_child_unshare_prevents_mount(self):
        with tempfile.TemporaryDirectory() as d:
            k = WireKernel(plan()); k.host_fd = k.fds['host']
            target = Path(d)/'owned-underlay'; target.write_bytes(b'owned')
            k.path_identity = m.identity(target); k.path_state = 'underlay'
            j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
            c = m.Controller(k.p, k, j, guard=k.guard)
            def syscall(name, *args):
                self.assertEqual(name, 'unshare'); k.alive = False
            with patch.object(m, 'NETNS', str(target)), \
                 patch.object(m, 'in_namespace', side_effect=lambda fd, fn: fn()), \
                 patch.object(m, 'syscall', side_effect=syscall) as call:
                with self.assertRaises(m.Refusal): k.step('netns-private-mount', k.mount_namespace)
            self.assertEqual(call.call_count, 1)
            self.assertEqual(c.phase, 'unknown-retained')
            self.assertEqual(target.read_bytes(), b'owned')

    def test_n1_expiry_after_first_command_stops_connect(self):
        with tempfile.TemporaryDirectory() as d:
            k = WireKernel(plan()); clock = [10.0]
            j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
            c = m.Controller(k.p, k, j, clock=lambda: clock[0], guard=k.guard)
            written = k.written
            def expired(label): written(label); clock[0] = c.end+1
            k.written = expired
            with patch.object(m, 'move_link', side_effect=k.move):
                with self.assertRaisesRegex(m.Refusal, 'NETWORK_LEASE_EXPIRED'): k.connect('caddy')
            self.assertEqual(len(k.writes), 1)
            self.assertEqual(c.phase, 'unknown-retained')

    def test_n1_intent_fsync_guard_loss_refuses_before_dispatch(self):
        with tempfile.TemporaryDirectory() as d:
            c, k, j = self.controller(d)
            append = j.append
            def lost(record):
                append(record)
                if record['kind'] == 'intent': k.fail = 'check'
            j.append = lost
            with self.assertRaises(m.Refusal): c.effect('not-dispatched', lambda: k.call('MUTATION'))
            self.assertNotIn('MUTATION', k.calls)
            self.assertEqual(c.phase, 'unknown-retained')

    def test_n3_caddy_readback_is_type_exact_before_and_after_each_change(self):
        for operation in ('cutover', 'return'):
            for timing in ('before', 'after'):
                for before, after in ((False, 0), (True, 1), (1, 1.0)):
                    with self.subTest(operation=operation, timing=timing, before=before), tempfile.TemporaryDirectory() as d:
                        c, k, _ = self.controller(d)
                        for value in (c.p['oldConfig'], c.p['newConfig']): value['extra'] = [before]
                        c.phase = 'prepared' if operation == 'cutover' else 'cutover'
                        k.current = copy.deepcopy(c.p['oldConfig'] if operation == 'cutover' else c.p['newConfig'])
                        if timing == 'before': k.current['extra'] = [after]
                        original = k.config
                        def config(value=None):
                            result = original(value)
                            if timing == 'after' and value is not None: k.current['extra'] = [after]
                            return result
                        k.config = config
                        with self.assertRaises(m.Refusal): self.command(c, operation)
                        self.assertEqual(k.calls.count('write-config'), 0 if timing == 'before' else 1)
                        self.assertNotIn(c.phase, ('returned',) if operation == 'return' else ('cutover',))

    def test_n3_actual_caddy_load_readback_rejects_type_coercion(self):
        for before, after in ((False, 0), (True, 1), (1, 1.0)):
            with self.subTest(before=before), tempfile.TemporaryDirectory() as d:
                k = WireKernel(plan()); k.pids = {'caddy': os.getpid()}
                j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
                c = m.Controller(k.p, k, j, guard=k.guard)
                value = k.p['newConfig']; value['extra'] = [before]
                k.p['oldConfig']['extra'] = [before]
                changed = copy.deepcopy(value); changed['extra'] = [after]
                with patch.object(m, 'require_listener'), \
                     patch.object(m, 'request', side_effect=[m.encode(k.p['oldConfig']), b'', m.encode(changed)]):
                    with self.assertRaisesRegex(m.Refusal, 'CADDY_WRITE_UNCONFIRMED'):
                        c.effect('caddy', lambda: k.load_config(value))
                self.assertEqual(c.phase, 'unknown-retained')

    def test_actual_linux_connect_serialization_with_modeled_kernel_seams(self):
        kernel = WireKernel(plan()); commands = kernel.commands
        with tempfile.TemporaryDirectory() as d:
            j = m.Journal(Path(d)/'generation', kernel.p); self.addCleanup(j.close)
            m.Controller(kernel.p, kernel, j, guard=kernel.guard)
            with patch.object(m, 'move_link', side_effect=kernel.move) as move:
                kernel.connect('caddy'); kernel.connect('mongo'); kernel.connect('redis')
        self.assertEqual(move.call_count, 6)
        self.assertEqual([x.args[1] for x in move.call_args_list], [91, 92, 91, 93, 91, 94])
        caddy = [argv for where, argv in commands if where == 'caddy']
        self.assertIn(('rule', 'add', 'priority', '10303', 'to', m.PUBLIC+'/32',
                       'ipproto', 'tcp', 'dport', '3000', 'table', '39303'), caddy)
        self.assertIn(('route', 'add', m.PUBLIC+'/32', 'via', '10.253.241.5', 'dev', 'c3pc',
                       'src', '10.253.241.6', 'table', '39303'), caddy)
        for where, argv in commands:
            self.assertNotIn('replace', argv)
            self.assertNotIn('flush', argv)
            self.assertNotIn('eth0', argv)
            self.assertNotIn('default', argv)
            if where == 'host':
                self.assertEqual(argv[0], 'link')

    def test_ip_subprocess_argv_is_fixed_and_inherited_environment_is_not_used(self):
        kernel = m.Linux.__new__(m.Linux); kernel.fds = {'fresh': 19}
        with patch.object(m, 'in_namespace', side_effect=lambda fd, fn: fn()), \
             patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'[]', b'')) as run:
            self.assertEqual(kernel.ip('fresh', 'route', 'show', 'table', 'all'), '[]')
        self.assertEqual(run.call_args.args[0], [m.IP, '-j', '-4', 'route', 'show', 'table', 'all'])
        self.assertEqual(run.call_args.kwargs['env'], {'LC_ALL': 'C'})
        self.assertTrue(run.call_args.kwargs['check'])
        self.assertNotIn('shell', run.call_args.kwargs)

    def test_real_journal_replacement_refuses_and_retains_foreign_target(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'generation'; j = m.Journal(path, plan())
            self.addCleanup(j.close)
            path.rename(Path(d)/'owned-original'); path.mkdir()
            marker = path/'foreign'; marker.write_bytes(b'untouched')
            with self.assertRaisesRegex(m.Refusal, 'JOURNAL_REPLACED'):
                j.append({'kind': 'attempt'})
            self.assertEqual(marker.read_bytes(), b'untouched')
            self.assertEqual(sorted(x.name for x in path.iterdir()), ['foreign'])

    def test_caddy_admin_requires_actual_target_pid_listener_ownership(self):
        kernel = m.Linux.__new__(m.Linux)
        kernel.fds = {'caddy': 40}; kernel.pids = {'caddy': 234}
        kernel.dispatch = lambda label, fn: fn()
        with patch.object(m, 'in_namespace', side_effect=lambda fd, fn: fn()), \
             patch.object(m, 'require_listener', create=True, side_effect=m.Refusal('ADMIN_OWNER_DRIFT')), \
             patch.object(m, 'request') as request:
            with self.assertRaisesRegex(m.Refusal, 'ADMIN_OWNER_DRIFT'):
                kernel.config({'accepted': 'config'})
            request.assert_not_called()

    def test_fixed_entry_pins_exact_current_new_sources(self):
        import ast
        script = Path(__file__).with_name('fresh_network_exec.py')
        tree = ast.parse(script.read_text())
        pins = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and
                    any(isinstance(x, ast.Name) and x.id == 'PINS' for x in n.targets))
        for installed, local in ((m.LIB, 'fresh_network.py'),
                                 ('/usr/local/libexec/c3-test-fresh-network-control.py', 'fresh_network_control.py')):
            self.assertEqual(pins[installed], m.digest(Path(__file__).with_name(local).read_bytes()))

    def test_real_fixed_cli_refuses_arguments_before_loading_or_effects(self):
        script = Path(__file__).with_name('fresh_network_exec.py')
        result = subprocess.run([sys.executable, '-I', '-B', str(script), 'cutover'],
                                env={'PATH': '/forbidden', 'C3_NETWORK_COMMAND': 'cutover'},
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'FIXED_ROOT_NO_ARGUMENT_ENTRY_REQUIRED\n')
        self.assertEqual(result.stdout, b'')

    def test_real_codec_child_process_fragmentation_and_eof(self):
        control = Path(__file__).with_name('fresh_network_control.py')
        network = Path(__file__).with_name('fresh_network.py')
        code = ("import importlib.util,socket,sys; "
                "def_unused=0; "
                "s=importlib.util.spec_from_file_location('n',sys.argv[1]); "
                "n=importlib.util.module_from_spec(s); s.loader.exec_module(n); "
                "s=importlib.util.spec_from_file_location('c',sys.argv[2]); "
                "c=importlib.util.module_from_spec(s); s.loader.exec_module(c); "
                "x=socket.socket(fileno=int(sys.argv[3])); x.settimeout(2); "
                "v=c.receive(x,n); c.send(x,v,n)")
        import struct
        a, b = socket.socketpair()
        with a, b:
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', code, str(network), str(control), str(b.fileno())],
                                     pass_fds=(b.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            b.close(); a.settimeout(3)
            raw = m.encode({'generation': 'a'*32, 'sequence': 1, 'operation': 'observe'})
            frame = struct.pack('!I', len(raw))+raw
            for byte in frame: a.sendall(bytes([byte]))
            header = a.recv(4)
            self.assertEqual(len(header), 4)
            size = struct.unpack('!I', header)[0]
            result = b''
            while len(result) < size: result += a.recv(size-len(result))
            self.assertEqual(result, raw)
            stdout, stderr = child.communicate(timeout=3)
            self.assertEqual((child.returncode, stdout, stderr), (0, b'', b''))

    def test_real_protocol_refuses_duplicates_oversize_and_eof(self):
        spec = importlib.util.spec_from_file_location('control', Path(__file__).with_name('fresh_network_control.py'))
        assert spec is not None and spec.loader is not None
        control = importlib.util.module_from_spec(spec); spec.loader.exec_module(control)
        import struct
        for raw in (struct.pack('!I', 5000), struct.pack('!I', 13)+b'{"a":1,"a":2}', b'\x00\x00'):
            with self.subTest(raw=raw):
                a, b = socket.socketpair()
                with a, b:
                    a.sendall(raw); a.shutdown(socket.SHUT_WR); b.settimeout(1)
                    with self.assertRaises(m.Refusal): control.receive(b, m)

    def test_lost_guard_stays_unknown_after_repair(self):
        with tempfile.TemporaryDirectory() as d:
            c, k, _ = self.controller(d); c.prepare()
            k.fail = 'check'
            with self.assertRaises(m.Refusal): self.command(c, 'cutover')
            self.assertEqual(c.phase, 'unknown-retained')
            k.fail = None
            with self.assertRaises(m.Refusal): self.command(c, 'cutover')
            self.assertNotIn('write-config', k.calls)

    def return_fixture(self, root):
        k = WireKernel(plan()); pid = os.getpid()
        container = {'Id': 'f'*64, 'State': {'Pid': pid, 'Running': True, 'Paused': False, 'Restarting': False},
                     'Image': 'sha256:'+'e'*64, 'RestartCount': 0,
                     'NetworkSettings': {'Networks': {'old': {'IPAddress': '172.19.0.3'}}}}
        projection = {'id': container['Id'], 'pid': pid, 'start': m.proc_start(pid),
                      'netns': m.identity('/proc/self/ns/net'), 'image': container['Image'],
                      'restartCount': 0, 'networks': container['NetworkSettings']['Networks']}
        value = {'version': 1, 'context': m.CONTEXT, 'generation': k.p['generation'],
                 'container': container['Id'], 'inspectSha256': m.digest(m.encode(projection)),
                 'address': '172.19.0.3', 'serving': {'pid': pid, 'start': m.proc_start(pid)}}
        self.addCleanup(k.close_holds)
        raw = [m.encode(value)]
        k.return_probe = lambda: m.Linux.return_probe(k)
        k.public_probe = lambda: None
        k.observation = lambda: {'modeled': True}
        current = [k.p['newConfig']]; writes = []
        def config(v=None):
            if v is not None: writes.append(v); current[0] = v
            return current[0]
        k.config = config
        j = m.Journal(Path(root)/'generation', k.p); self.addCleanup(j.close)
        c = m.Controller(k.p, k, j, guard=k.guard); c.phase = 'cutover'
        return c, k, raw, container, writes

    def test_n2_return_root_pin_replacement_after_probe_blocks_caddy_write(self):
        with tempfile.TemporaryDirectory() as d:
            c, k, raw, container, writes = self.return_fixture(d)
            def bound(*args):
                raw[0] += b' '
                return {'modeled': True}
            with patch.object(m, 'trusted_read', side_effect=lambda path: raw[0]), \
                 patch.object(m, 'request', side_effect=lambda *args: m.encode(container)), \
                 patch.object(m, 'in_namespace', side_effect=lambda fd, fn: fn()), \
                 patch.object(m, 'docker_backend_addresses', return_value=['172.19.0.3']), \
                 patch.object(m, 'bound_probe', side_effect=bound):
                with self.assertRaises(m.Refusal): self.command(c, 'return')
            self.assertEqual(writes, [])
            self.assertEqual(c.phase, 'unknown-retained')
            k.close_holds()

    def test_n2_positive_return_holds_original_descriptors_until_final_readback(self):
        with tempfile.TemporaryDirectory() as d:
            c, k, raw, container, writes = self.return_fixture(d)
            observed = []
            def observation():
                self.assertEqual(len(k.target_hold['processes']), 2)
                for x in k.target_hold['processes']:
                    os.fstat(x['pidfd']); os.fstat(x['nsfd'])
                    observed.extend((x['pidfd'], x['nsfd']))
                return {'modeled': True}
            k.observation = observation
            with patch.object(m, 'trusted_read', side_effect=lambda path: raw[0]), \
                 patch.object(m, 'request', side_effect=lambda *args: m.encode(container)), \
                 patch.object(m, 'in_namespace', side_effect=lambda fd, fn: fn()), \
                 patch.object(m, 'docker_backend_addresses', return_value=['172.19.0.3']), \
                 patch.object(m, 'bound_probe', return_value={'modeled': True}) as probe:
                self.assertEqual(self.command(c, 'return')['phase'], 'returned')
            self.assertEqual(len(writes), 1)
            self.assertGreater(probe.call_count, 2)
            self.assertIsNone(k.target_hold)
            for fd in observed:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_n2_return_drift_at_each_confirmation_boundary_never_returns(self):
        for timing in ('prewrite', 'write', 'readback', 'public', 'observation'):
            for drift in ('raw', 'dns', 'container', 'namespace', 'process'):
                with self.subTest(timing=timing, drift=drift), tempfile.TemporaryDirectory() as d:
                    c, k, raw, container, writes = self.return_fixture(d)
                    changed = [False]; dns = ['172.19.0.3']
                    real_identity, real_start = m.identity, m.proc_start
                    def change():
                        changed[0] = True
                        if drift == 'raw': raw[0] += b' '
                        if drift == 'dns': dns[:] = ['172.19.0.9']
                        if drift == 'container': container['RestartCount'] += 1
                    def identity(path):
                        value = real_identity(path)
                        if changed[0] and drift == 'namespace' and str(path) == '/proc/'+str(os.getpid())+'/ns/net':
                            return [value[0], value[1]+1]
                        return value
                    def start(pid):
                        return '1' if changed[0] and drift == 'process' else real_start(pid)
                    original_probe, original_config = k.return_probe, k.config
                    def probe():
                        result = original_probe()
                        if timing == 'prewrite': change()
                        return result
                    def config(value=None):
                        result = original_config(value)
                        if timing == 'write' and value is not None: change()
                        if timing == 'readback' and value is None and writes: change()
                        return result
                    k.return_probe = probe; k.config = config
                    if timing == 'public': k.public_probe = change
                    if timing == 'observation':
                        def observation(): change(); return {'modeled': True}
                        k.observation = observation
                    with patch.object(m, 'trusted_read', side_effect=lambda path: raw[0]), \
                         patch.object(m, 'request', side_effect=lambda *args: m.encode(container)), \
                         patch.object(m, 'in_namespace', side_effect=lambda fd, fn: fn()), \
                         patch.object(m, 'docker_backend_addresses', side_effect=lambda: dns[:]), \
                         patch.object(m, 'bound_probe', return_value={'modeled': True}), \
                         patch.object(m, 'identity', side_effect=identity), patch.object(m, 'proc_start', side_effect=start):
                        with self.assertRaises(m.Refusal): self.command(c, 'return')
                    self.assertEqual(len(writes), 0 if timing == 'prewrite' else 1)
                    self.assertEqual(c.phase, 'unknown-retained')
                    self.assertIsNotNone(k.target_hold)
                    for item in k.target_hold['processes']:
                        os.fstat(item['pidfd']); os.fstat(item['nsfd'])
                    records = [m.decode(x.read_bytes()) for x in sorted(c.j.path.iterdir())]
                    self.assertFalse(any(x['kind'] == 'public-return-confirmed' for x in records))
                    k.close_holds()

    def test_n2_real_retained_pidfd_death_refuses_even_with_same_pin_bytes(self):
        child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(15)'])
        try:
            k = WireKernel(plan()); self.addCleanup(k.close_holds)
            raw = m.encode({'version': 1, 'serving': {'pid': child.pid, 'start': m.proc_start(child.pid)}})
            k.hold_target('/modeled-root-pin', raw, [(child.pid, m.proc_start(child.pid))])
            child.terminate(); child.wait(timeout=3)
            with patch.object(m, 'trusted_read', return_value=raw):
                with self.assertRaisesRegex(m.Refusal, 'HELD_TARGET_PROCESS_OR_NAMESPACE_DRIFT'): k.check_hold()
        finally:
            if child.poll() is None: child.kill(); child.wait(timeout=3)

    def test_n2_serving_pin_cannot_be_reauthorized_mid_cutover(self):
        with tempfile.TemporaryDirectory() as d:
            k = WireKernel(plan()); pid = os.getpid(); start = m.proc_start(pid)
            raw = m.encode({'version': 1, 'context': m.CONTEXT, 'generation': k.p['generation'],
                            'serving': {'pid': pid, 'start': start}})
            self.addCleanup(k.close_holds)
            k.hold_target('/etc/c3-test-fresh-network-serving.json', raw, [(pid, start)])
            with patch.object(m, 'trusted_read', return_value=raw+b' '):
                with self.assertRaisesRegex(m.Refusal, 'ACCEPTED_TARGET_PIN_DRIFT'): k.check_hold()
            with self.assertRaisesRegex(m.Refusal, 'ACCEPTED_TARGET_REPLACED'):
                k.hold_target('/etc/c3-test-fresh-network-serving.json', raw+b' ', [(pid, start)])

    def test_model_return_does_not_reactivate_an_unready_old_backend(self):
        with tempfile.TemporaryDirectory() as d:
            c, k, _ = self.controller(d); c.prepare(); self.command(c, 'cutover')
            k.fail = 'old-backend-bound-http'
            before = k.calls.count('write-config')
            with self.assertRaises(m.Refusal): self.command(c, 'return')
            self.assertEqual(k.calls.count('write-config'), before)
            self.assertEqual(k.current, c.p['newConfig'])


if __name__ == '__main__':
    unittest.main()
