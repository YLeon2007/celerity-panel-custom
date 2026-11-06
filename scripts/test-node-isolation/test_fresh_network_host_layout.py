"""Wave82 measured B132 layout; kernel/daemon seams explicitly modeled only."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_fresh_network as legacy

m = legacy.m
HERE = Path(__file__).parent
FACTS = json.loads((HERE/'fixtures/network_b132_wave82.json').read_text())


def host_plan():
    # Generation, deadline and /30s are synthetic test-only, never authority.
    p = legacy.plan()
    p.update({k: copy.deepcopy(FACTS[k]) for k in ('machine', 'boot', 'hostNetns', 'daemon', 'oldConfig')})
    p['newConfig'] = copy.deepcopy(p['oldConfig'])
    def change(v):
        if isinstance(v, dict):
            if v.get('handler') == 'reverse_proxy':
                for u in v['upstreams']:
                    if u['dial'] == '127.0.0.1:3000': u['dial'] = m.PUBLIC+':3000'
            for w in v.values(): change(w)
        elif isinstance(v, list):
            for w in v: change(w)
    change(p['newConfig'])
    for role, observed in FACTS['peers'].items():
        p['peers'][role].update(id=observed['id'], inspectSha256=m.digest(m.encode(observed)),
            address='127.0.0.1' if role == 'caddy' else next(iter(observed['networks'].values()))['IPAddress'])
    return p


class HostWire(legacy.WireKernel):
    def __init__(self, p):
        super().__init__(p)
        self.state['caddy'] = self.state['host']  # One modeled kernel namespace.
    def invoke(self, where, fn):
        if fn.__name__ == 'loopback_route':
            self.boundary(); self.written('route-localnet:'+where); return True
        return super().invoke(where, fn)
    def check_loopback_links(self):
        pass  # Explicitly modeled private sysctl observations, never read proc.
    def ip(self, where, *args):
        result = super().ip(where, *args)
        # Legacy simulator replaces lists on deletion; keep namespace aliases real.
        if args[:2] == ('link', 'del'):
            for r in ('caddy',):
                if self.state[r] is not self.state['host']:
                    raise AssertionError('LOST_MODELED_NAMESPACE_ALIAS')
        return result


class HostLayoutTests(unittest.TestCase):
    def test_measured_host_caddy_exact_one_change_is_accepted(self):
        p = host_plan()
        self.assertEqual(m.digest(m.encode(p['oldConfig'])),
            'b66e75cbc096e53e5633e4e544050ca21e8ee4f03388cf5f5fd7d618e2be9243')
        self.assertIs(m.validate_plan(p), p)


    def test_measured_host_caddy_inspect_and_retained_peer_checks(self):
        p = host_plan(); k = m.Linux.__new__(m.Linux); k.p = p
        observed = FACTS['peers']['caddy']
        container = {'Id': observed['id'], 'State': {'Pid': observed['pid'], 'Running': True,
            'Paused': False, 'Restarting': False}, 'Image': observed['image'], 'RestartCount': 0,
            'HostConfig': {'NetworkMode': 'host'}, 'NetworkSettings': {'Networks': copy.deepcopy(observed['networks'])}}
        k.fds = {'caddy': 17}; k.pids = {'caddy': observed['pid']}; k.pidfds = {'caddy': 18}
        import types
        with patch.object(m, 'proc_start', return_value=observed['start']), \
             patch.object(m, 'identity', return_value=observed['netns']), \
             patch.object(m, 'request', side_effect=lambda *a: m.encode(container)), \
             patch.object(m.os, 'fstat', return_value=types.SimpleNamespace(st_dev=4, st_ino=4026531840)), \
             patch.object(m.select, 'select', return_value=([], [], [])):
            self.assertEqual(k.inspect('caddy'), observed)
            k.check_peer('caddy')
            for fault in ('mode', 'namespace', 'ip', 'restart', 'id'):
                changed = copy.deepcopy(container)
                if fault == 'mode': changed['HostConfig']['NetworkMode'] = 'bridge'
                if fault == 'ip': changed['NetworkSettings']['Networks']['host']['IPAddress'] = '172.19.0.8'
                if fault == 'restart': changed['RestartCount'] = 1
                if fault == 'id': changed['Id'] = 'f'*64
                with self.subTest(fault=fault), \
                     patch.object(m, 'request', return_value=m.encode(changed)), \
                     patch.object(m, 'identity', return_value=[4, 99] if fault == 'namespace' else observed['netns']):
                    with self.assertRaises(m.Refusal): k.check_peer('caddy')


    def test_real_connect_remove_host_peer_routes_and_alias_seals_modeled_kernel(self):
        k = HostWire(host_plan()); baseline = copy.deepcopy(k.state)
        with tempfile.TemporaryDirectory() as d:
            j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
            m.Controller(k.p, k, j, guard=k.guard)
            with patch.object(m, 'move_link', side_effect=k.move) as moves:
                for r in m.ROLES: k.connect(r)
            self.assertEqual(moves.call_count, 5, 'do not move a host peer into its own namespace')
            host_routes = [a for w, a in k.commands if w == 'host' and a[0] in ('route', 'rule')]
            self.assertEqual(host_routes, [
                ('route', 'add', m.PUBLIC+'/32', 'via', '10.253.241.5', 'dev', 'c3pc',
                 'src', '10.253.241.6', 'table', m.TABLE),
                ('rule', 'add', 'priority', m.PRIORITY, 'to', m.PUBLIC+'/32',
                 'ipproto', 'tcp', 'dport', '3000', 'table', m.TABLE)])
            k.seal()
            target = Path(d)/'namespace'; target.write_bytes(b'owned'); k.path_identity = m.identity(target)
            with patch.object(m, 'NETNS', str(target)), patch.object(m, 'syscall'):
                k.remove(baseline)
            self.assertFalse(target.exists())
            self.assertEqual(k.state['host'], baseline['host'])
            self.assertEqual(k.state['caddy'], baseline['caddy'])
            self.assertIsNotNone(k.sealed)
            for w, a in k.commands:
                self.assertNotIn('default', a); self.assertNotIn('replace', a); self.assertNotIn('flush', a)


    def test_canonical_ip_path_does_not_follow_installed_sbin_symlink(self):
        self.assertEqual(m.IP, '/usr/bin/ip')
        p = host_plan()
        self.assertIs(m.validate_plan(p), p)
        p['executables']['/usr/sbin/ip'] = p['executables'].pop(m.IP)
        with self.assertRaisesRegex(m.Refusal, 'FIXED_EXECUTABLES_REQUIRED'): m.validate_plan(p)

    def test_measured_bridge_timers_are_not_identity_but_config_still_is(self):
        k = m.Linux.__new__(m.Linux)
        def snapshot(rows):
            def ip(where, *a):
                kind = 'links' if 'link' in a else 'addresses' if 'address' in a else 'routes' if 'route' in a else 'rules'
                return m.encode(rows[kind]).decode()
            k.ip = ip
            return k.snapshot('host')
        a, b = [snapshot(copy.deepcopy(FACTS['snapshots'][r])) for r in ('host', 'caddy')]
        self.assertEqual(a, b, 'measured gc countdown must not poison an unchanged host seal')
        client = __import__('fresh_network_client'); client._json_types(m, a)
        changed = copy.deepcopy(FACTS['snapshots']['host'])
        changed['links'][2]['linkinfo']['info_data']['ageing_time'] += 1
        self.assertNotEqual(a, snapshot(changed), 'keep bridge configuration and all routes/rules pinned')

    def test_numeric_loopback_mapping_is_exact_and_fresh_namespace_only(self):
        p = host_plan(); raw = m.nft_policy(p).decode()
        self.assertIn('hook output priority -100', raw)
        self.assertIn('ip daddr 127.0.0.1 tcp dport 27017 dnat ip to 172.19.0.2:27017', raw)
        self.assertIn('ip daddr 127.0.0.1 tcp dport 6379 dnat ip to 172.19.0.3:6379', raw)
        self.assertIn('oifname "c3nm" ip saddr 127.0.0.1 ip daddr 172.19.0.2 tcp dport 27017 snat ip to 10.253.241.9', raw)
        self.assertIn('oifname "c3nr" ip saddr 127.0.0.1 ip daddr 172.19.0.3 tcp dport 6379 snat ip to 10.253.241.13', raw)
        self.assertNotIn('masquerade', raw); self.assertNotIn('prerouting', raw)
        self.assertEqual(raw.count('dnat'), 2); self.assertEqual(raw.count('snat'), 2)
        self.assertNotIn('dnat', m.nft_policy(legacy.plan()).decode())


    def test_loopback_route_permission_only_on_new_fresh_data_links(self):
        k = HostWire(host_plan())
        with tempfile.TemporaryDirectory() as d:
            j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
            m.Controller(k.p, k, j, guard=k.guard)
            with patch.object(m, 'move_link', side_effect=k.move):
                for role in m.ROLES: k.connect(role)
            self.assertEqual(k.loopback_links, {'c3nm', 'c3nr'})
            self.assertEqual([x for x in k.writes if x.startswith('route-localnet:')],
                ['route-localnet:fresh', 'route-localnet:fresh'])
            rows = [m.decode(x.read_bytes()) for x in sorted(j.path.iterdir())]
            self.assertEqual([r['effect'] for r in rows if r.get('kind') == 'confirmed' and r['effect'].startswith('sysctl-loopback:')],
                ['sysctl-loopback:fresh:c3nm', 'sysctl-loopback:fresh:c3nr'])

    def test_preserved_direct_rs_settings_accepted_and_discovery_substitution_refused(self):
        # Endpoint/query are measured; no private settings/credentials in fixture.
        raw = {'environment': {'MONGO_URI': 'mongodb://127.0.0.1:27017/c3test?authSource=admin&replicaSet=rs0&directConnection=true',
                               'REDIS_URL': 'redis://127.0.0.1:6379'}}
        m.runtime_endpoints(m.encode(raw))
        for field, value in (
                ('MONGO_URI', raw['environment']['MONGO_URI'].replace('true', 'false')),
                ('MONGO_URI', raw['environment']['MONGO_URI']+'&directConnection=true'),
                ('MONGO_URI', raw['environment']['MONGO_URI'].replace('127.0.0.1', 'mongo')),
                ('REDIS_URL', 'redis://127.0.0.1:6380')):
            changed = copy.deepcopy(raw); changed['environment'][field] = value
            with self.subTest(value=value), self.assertRaisesRegex(m.Refusal, 'EXACT_RUNTIME_DATA_ENDPOINTS_REQUIRED'):
                m.runtime_endpoints(m.encode(changed))


    def test_measured_preflight_consumes_hosts_and_unchanged_direct_settings(self):
        import test_fresh_network_b132 as b132
        p = host_plan()
        settings = m.encode({'environment': {'MONGO_URI': 'mongodb://127.0.0.1:27017/c3test?authSource=admin&replicaSet=rs0&directConnection=true',
                                             'REDIS_URL': 'redis://127.0.0.1:6379'}})
        with b132.PreflightModel(p) as model:
            # Existing real host/preflight logic; modeled OS/peer/sysctl read.
            original = b132.m.trusted_read
            with patch.object(b132.m, 'trusted_read', side_effect=lambda path: settings if path.endswith('/etc/classic.json') else original(path)):
                self.assertEqual(model.kernel.preflight(), model.snapshots)
                self.assertEqual(model.kernel.runtime_settings, settings)
                with patch.object(b132.m, 'trusted_read', return_value=settings+b' '):
                    with self.assertRaisesRegex(b132.m.Refusal, 'RUNTIME_DATA_SETTINGS_DRIFT'):
                        model.kernel.check_targets()

    def test_host_layout_extra_config_change_duplicate_upstream_and_cross_machine_refuse(self):
        for fault in ('extra', 'duplicate', 'machine', 'address'):
            p = host_plan()
            if fault == 'extra': p['newConfig']['admin']['listen'] = ':2019'
            if fault == 'machine': p['machine'] = m.TEST_MACHINE
            if fault == 'address': p['peers']['caddy']['address'] = '172.19.0.4'
            if fault == 'duplicate':
                for config, dial in ((p['oldConfig'], '127.0.0.1:3000'), (p['newConfig'], m.PUBLIC+':3000')):
                    config['extra'] = {'handler': 'reverse_proxy', 'upstreams': [{'dial': dial}]}
            with self.subTest(fault=fault), self.assertRaisesRegex(m.Refusal, 'EXACT_ONE_CADDY_UPSTREAM_CHANGE_REQUIRED'):
                m.validate_plan(p)

    def test_host_return_missing_published_pin_does_not_use_bridge_dns(self):
        k = m.Linux.__new__(m.Linux); k.p = host_plan()
        with patch.object(m, 'trusted_read', return_value=m.encode({})) as read, \
             patch.object(m, 'docker_backend_addresses') as dns:
            with self.assertRaisesRegex(m.Refusal, 'HOST_CADDY_RETURN_LOOPBACK_PID_BINDING_REQUIRED'):
                k.return_probe()
        read.assert_called_once_with('/etc/c3-test-fresh-network-return.json'); dns.assert_not_called()


    def test_host_route_and_private_nat_steps_keep_existing_expiry_fence(self):
        for trigger, role in (('ip:host:route:add', 'caddy'), ('route-localnet:fresh', 'mongo')):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as d:
                k = HostWire(host_plan()); clock = [10.0]
                j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
                c = m.Controller(k.p, k, j, clock=lambda: clock[0], guard=k.guard)
                original = k.written
                def written(label):
                    original(label)
                    if label.startswith(trigger): clock[0] = c.end+1
                k.written = written
                with patch.object(m, 'move_link', side_effect=k.move):
                    with self.assertRaisesRegex(m.Refusal, 'NETWORK_LEASE_EXPIRED'): k.connect(role)
                self.assertTrue(k.writes[-1].startswith(trigger))
                self.assertEqual(c.phase, 'unknown-retained')
                before = list(k.writes); clock[0] = 10.0
                with self.assertRaises(m.Refusal): k.connect(role)
                self.assertEqual(k.writes, before)

    def test_host_cleanup_identity_drift_retains_alias_seal_without_next_effect(self):
        k = HostWire(host_plan()); baseline = copy.deepcopy(k.state)
        with tempfile.TemporaryDirectory() as d:
            j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
            c = m.Controller(k.p, k, j, guard=k.guard)
            with patch.object(m, 'move_link', side_effect=k.move):
                for role in m.ROLES: k.connect(role)
            k.seal(); k.writes.clear()
            old = k.written
            def drift(label):
                old(label)
                if len(k.writes) == 1: k.state['host']['links'][0]['ifalias'] = 'foreign'
            k.written = drift
            with self.assertRaises(m.Refusal): k.remove(baseline)
            self.assertEqual(len(k.writes), 1)
            self.assertEqual(c.phase, 'unknown-retained')
            self.assertIsNotNone(k.sealed)

    def test_actual_nofollow_walk_opens_canonical_binary_but_rejects_sbin_symlink(self):
        import test_fresh_network_entry as entry_tests
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for p in ('usr', 'usr/bin', 'usr/sbin'): (root/p).mkdir(exist_ok=True); (root/p).chmod(0o755)
            (root/'usr/bin/ip').write_bytes(b'nonexecuted installed binary fixture')
            (root/'usr/bin/ip').chmod(0o755)
            (root/'usr/sbin/ip').symlink_to('../bin/ip')
            import os
            with entry_tests.installed_walk(m, root):
                fd = m.trusted_fd('/usr/bin/ip')
                try: self.assertEqual(os.read(fd, 100), b'nonexecuted installed binary fixture')
                finally: os.close(fd)
                with self.assertRaises(OSError): m.trusted_fd('/usr/sbin/ip')

    def test_current_exact_loaders_and_holder_accept_host_plan_observe_abandon(self):
        import test_fresh_network_entry as entry_tests
        protocol = entry_tests.legacy
        class HostHarness(entry_tests.FixedServerHarness):
            def __enter__(self):
                super().__enter__()
                deadline = self.p['deadline']; self.p = host_plan(); self.p['deadline'] = deadline
                self.raw = protocol.m.encode(self.p); (self.root/'plan').write_bytes(self.raw)
                return self
        with HostHarness(self) as h:
            h.lease(); h.server(); holder = h.holder(); end = holder.end
            self.assertEqual(holder.connect()['phase'], 'prepared')
            self.assertEqual(holder.dispatch('observe')['phase'], 'prepared')
            self.assertEqual(holder.dispatch('abandon')['phase'], 'abandoned')
            self.assertEqual(holder.end, end); holder.close()
            stdout, stderr = h.child.communicate(timeout=3)
            self.assertEqual(h.child.returncode, 0, stderr.decode())
            self.assertNotIn('write-config', h.effects())
            self.assertFalse((h.root/'s').exists())


if __name__ == '__main__': unittest.main()
