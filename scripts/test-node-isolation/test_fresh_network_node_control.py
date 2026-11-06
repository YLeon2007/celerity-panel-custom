"""Real constructor/codec/journal, modeled ip/nft/sysctl; NO kernel packet proof."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_fresh_network as legacy
import test_fresh_network_host_layout as host

m = legacy.m
FACTS = json.loads((Path(__file__).parent/'fixtures/node_control_wave94.json').read_text())
FOREIGN = {'nftables': [{'table': {'family': 'inet', 'name': 'foreign'}}]}


def egress_plan():
    p = host.host_plan()
    p['nodeControlEgress'] = {'endpoints': copy.deepcopy(FACTS['endpoints']),
                            'hostRulesetSha256': m.digest(m.encode(FOREIGN))}
    return p


class EgressWire(host.HostWire):
    """Only external nft/ip/forwarding facts modeled; product lifecycle is real."""
    def __init__(self, p):
        super().__init__(p)
        self.host_nft: dict = copy.deepcopy(FOREIGN)
        self.state['host']['addresses'].append({'ifname': 'c3test61', 'addr_info': [
            {'local': '10.203.61.1', 'prefixlen': 32}]})
        self.state['host']['routes'].append({'dev': 'c3test61', 'dst': '10.203.61.2', 'scope': 'link'})
    def node_host_rules(self): return copy.deepcopy(self.host_nft)
    def node_forwarding(self) -> str: return '1'
    def node_nft_apply(self, raw):
        self.boundary()
        if raw.startswith(b'create table'):
            self.host_nft['nftables'].append({'table': {'family': 'ip', 'name': 'c3nodecontrol',
                                                      'comment': 'c3:'+self.p['generation']}})
            self.host_nft['nftables'].append({'rule': {'family': 'ip', 'table': 'c3nodecontrol',
                                                      'modeledScript': raw.decode()}})
            self.written('nft-node-create')
        else:
            assert raw == b'delete table ip c3nodecontrol\n'
            self.host_nft = copy.deepcopy(FOREIGN)
            self.written('nft-node-delete')
        return True


class NodeControlTests(unittest.TestCase):
    def wire(self, d, p=None):
        k = EgressWire(p or egress_plan())
        j = m.Journal(Path(d)/'generation', k.p); self.addCleanup(j.close)
        c = m.Controller(k.p, k, j, guard=k.guard)
        return k, c, j

    def connected(self, d):
        k,c,j = self.wire(d); baseline = copy.deepcopy(k.state)
        k.install_node_control()
        with patch.object(m, 'move_link', side_effect=k.move):
            for role in m.ROLES: k.connect(role)
        k.seal()
        return k,c,j,baseline

    def test_actual_selected_endpoints_reach_policy_routes_owned_cleanup(self):
        p = egress_plan()
        try:
            m.validate_plan(p)
        except m.Refusal as e:
            self.fail('actual selected finite trusted plan refused: '+str(e))
        policy = m.nft_policy(p).decode()
        for ep in FACTS['endpoints']:
            self.assertIn(f'oifname "c3nc" ip daddr {ep["address"]} tcp dport {ep["port"]} accept', policy)
        k = EgressWire(p); baseline = copy.deepcopy(k.state)
        with tempfile.TemporaryDirectory() as d:
            j = m.Journal(Path(d)/'generation', p); self.addCleanup(j.close)
            m.Controller(p, k, j, guard=k.guard)
            def private_nft(argv, **kwargs):
                self.assertEqual(argv,[m.NFT,'-f','-'])
                self.assertEqual(kwargs['input'],m.nft_policy(p))
                k.written('nft-private-create')
            with patch.object(m.subprocess,'run',side_effect=private_nft): k.firewall()
            self.assertEqual(k.writes[:2],['nft-private-create','nft-node-create'])
            with patch.object(m, 'move_link', side_effect=k.move):
                for role in m.ROLES: k.connect(role)
            self.assertEqual([a[2] for w,a in k.commands if w == 'fresh' and a[:2] == ('route','add')],
                             ['10.203.61.1/32','10.203.61.2/32','172.19.0.2/32','172.19.0.3/32'])
            k.seal()
            target = Path(d)/'namespace'; target.write_bytes(b'owned'); k.path_identity = m.identity(target)
            with patch.object(m, 'NETNS', str(target)), patch.object(m, 'syscall'):
                k.remove(baseline)
            self.assertEqual(k.host_nft, FOREIGN)
            self.assertEqual(k.state['host'], baseline['host'])
            self.assertFalse(target.exists())
            self.assertEqual(k.writes.count('nft-node-create'), 1)
            self.assertEqual(k.writes.count('nft-node-delete'), 1)

    def test_legacy_and_explicit_empty_keep_policy_routes_and_db_caddy_unchanged(self):
        p = host.host_plan(); empty = copy.deepcopy(p)
        empty['nodeControlEgress'] = {'endpoints': [], 'hostRulesetSha256': 'a'*64}
        self.assertIs(m.validate_plan(empty), empty)
        self.assertEqual(m.nft_policy(p), m.nft_policy(empty))
        extended = m.nft_policy(egress_plan()).decode()
        for ep in FACTS['endpoints']:
            extended = extended.replace(f'oifname "c3nc" ip daddr {ep["address"]} tcp dport {ep["port"]} accept\n','')
        self.assertEqual(extended.encode(), m.nft_policy(p))
        with tempfile.TemporaryDirectory() as d:
            k,c,j = self.wire(d, empty)
            k.node_host_rules = lambda: self.fail('empty must not read/write host nft')
            k.install_node_control(); k.remove_node_control()
            with patch.object(m, 'move_link', side_effect=k.move): k.connect('caddy')
            self.assertFalse(any(w=='fresh' and a[0]=='route' for w,a in k.commands))
            self.assertEqual(k.state['host']['rules'], [{'priority':m.PRIORITY,'table':m.TABLE}])

    def test_closed_finite_endpoints_refuse_missing_wrong_duplicate_malformed(self):
        for fault in ('missing','ip','public','port','protocol','duplicate','hostname','bool','string',
                      'extra','missing-pin','missing-endpoints','null','too-many','wrong-layout','overlap'):
            p = egress_plan(); e = p['nodeControlEgress']['endpoints']
            if fault=='missing': e.pop()
            if fault=='ip': e[0]['address']='10.203.61.3'
            if fault=='public': e[0]['address']='104.143.201.72'
            if fault=='port': e[0]['port']=22
            if fault=='protocol': e[0]['protocol']='udp'
            if fault=='duplicate': e[1]=copy.deepcopy(e[0])
            if fault=='hostname': e[0]['address']='selected-node.example'
            if fault=='bool': e[0]['port']=True
            if fault=='string': e[0]['port']='2222'
            if fault=='extra': e[0]['accept']=True
            if fault=='missing-pin': p['nodeControlEgress'].pop('hostRulesetSha256')
            if fault=='missing-endpoints': p['nodeControlEgress'].pop('endpoints')
            if fault=='null': p['nodeControlEgress']=None
            if fault=='too-many': e.append(copy.deepcopy(e[0]))
            if fault=='wrong-layout': p['machine']=m.TEST_MACHINE
            if fault=='overlap': p['peers']['caddy']['subnet']='10.203.61.0/30'
            with self.subTest(fault=fault), self.assertRaises(m.Refusal): m.validate_plan(p)

    def test_out_of_set_egress_and_dns_have_no_policy_rule(self):
        import re
        text = m.nft_policy(egress_plan()).decode()
        # Text-policy projection only, not an actual nft/kernel evaluator.
        permitted = {(ip, proto, int(port)) for ip,proto,port in re.findall(
            r'oifname "c3nc" ip daddr ([0-9.]+) (tcp|udp) dport ([0-9]+) accept', text)}
        self.assertEqual(permitted, {(e['address'],e['protocol'],e['port']) for e in FACTS['endpoints']})
        for endpoint in [('10.203.61.1','tcp',62080),('10.203.61.2','tcp',9999),
                         ('10.203.61.2','tcp',22),('10.203.61.2','udp',2222),
                         ('185.104.113.14','tcp',2222),('1.1.1.1','udp',53)]:
            with self.subTest(endpoint=endpoint): self.assertNotIn(endpoint, permitted)
        self.assertEqual(text.count('policy drop;'),3)
        self.assertNotIn('masquerade',text)

    def test_host_snat_is_only_remote_selected_tuples_never_host_local_or_generic(self):
        script = m.node_nft_policy(egress_plan()).decode()
        rules = [r for r in script.splitlines() if 'snat' in r]
        self.assertEqual(rules,[f'iifname "c3pc" oifname "c3test61" ip saddr 10.253.241.5 '
                               f'ip daddr 10.203.61.2 tcp dport {port} snat ip to 10.203.61.1'
                               for port in (2222,62080)])
        self.assertTrue(script.startswith('create table ip c3nodecontrol'))
        for forbidden in ('masquerade','dnat','hook forward','hook input','hook output','flush','replace','0.0.0.0/0'):
            self.assertNotIn(forbidden,script)
        self.assertNotIn(m.PUBLIC,script)

    def test_independent_raw_plan_lease_is_required_before_pidfd_or_dispatch(self):
        import fresh_network_control as control
        p = egress_plan(); legacy_p = copy.deepcopy(p); legacy_p.pop('nodeControlEgress')
        value = {'version':1,'context':m.CONTEXT,'generation':p['generation'],'boot':p['boot'],
                 'planSha256':m.digest(m.encode(legacy_p)),'deadline':p['deadline'],
                 'holder':{'pid':123,'start':'1'},'operations':['observe','cutover','return','abandon']}
        with patch.object(m,'trusted_read',return_value=m.encode(value)), patch.object(control.os,'pidfd_open') as pidfd:
            with self.assertRaisesRegex(m.Refusal,'INDEPENDENT_LIVE_LEASE_REQUIRED'):
                control.Lease(m,p,m.encode(p))
        pidfd.assert_not_called()

    def test_request_cannot_add_or_override_node_control(self):
        with tempfile.TemporaryDirectory() as d:
            k,c,j = self.wire(d)
            with self.assertRaisesRegex(m.Refusal,'CLOSED_SCHEMA_REQUIRED'):
                c.command({'generation':k.p['generation'],'sequence':1,'operation':'observe',
                           'nodeControlEgress':k.p['nodeControlEgress']})
            self.assertEqual(k.writes,[])

    def test_current_fixed_loaders_and_real_holder_lease_carry_optional_root_field(self):
        import test_fresh_network_entry as entry
        class EgressHarness(entry.FixedServerHarness):
            def __enter__(self):
                super().__enter__()
                deadline=self.p['deadline']; self.p=egress_plan(); self.p['deadline']=deadline
                self.raw=m.encode(self.p); (self.root/'plan').write_bytes(self.raw)
                return self
        with EgressHarness(self) as h:
            h.lease(); h.server(); holder=h.holder()
            try:
                prepared=holder.connect()
            except BaseException:
                if h.child.poll() is not None:
                    stdout,stderr=h.child.communicate(timeout=3)
                    self.fail('fixture server exited before prepared: '+stderr.decode()+' result='+
                              ((h.root/'result').read_text() if (h.root/'result').exists() else 'absent'))
                raise
            self.assertEqual(prepared['phase'],'prepared')
            self.assertEqual(holder.dispatch('observe')['phase'],'prepared')
            self.assertEqual(holder.dispatch('abandon')['phase'],'abandoned')
            holder.close(); stdout,stderr=h.child.communicate(timeout=3)
            self.assertEqual(h.child.returncode,0,stderr.decode())
            self.assertNotIn('write-config',h.effects())
        # Protocol + loaders/pidfds/lease are real; its entire Linux kernel is modeled.

    def test_plan_mutation_after_acceptance_is_sticky_before_any_dispatch(self):
        with tempfile.TemporaryDirectory() as d:
            k,c,j = self.wire(d)
            k.p['nodeControlEgress']['endpoints'][0]['port']=22
            with self.assertRaisesRegex(m.Refusal,'ACCEPTED_PLAN_MUTATED'):
                c.effect('install-node-control', k.install_node_control)
            self.assertTrue(c.failed); self.assertEqual(k.writes,[])
            k.p['nodeControlEgress']['endpoints'][0]['port']=2222
            with self.assertRaisesRegex(m.Refusal,'UNKNOWN_RETAINED'):
                c.effect('install-node-control', k.install_node_control)

    def test_missing_forwarding_path_or_unaccepted_policy_refuses_without_effect(self):
        for fault in ('forwarding','address','route','ruleset','preexisting-table'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as d:
                k,c,j = self.wire(d)
                if fault=='forwarding': k.node_forwarding=lambda:'0'
                if fault=='address': k.state['host']['addresses']=[]
                if fault=='route': k.state['host']['routes']=[]
                if fault=='ruleset': k.host_nft['nftables'].append({'table':{'family':'ip','name':'foreign2'}})
                if fault=='preexisting-table': k.host_nft['nftables'].append({'table':{
                    'family':'ip','name':'c3nodecontrol','comment':'c3:'+k.p['generation']}})
                with self.assertRaises(m.Refusal): k.install_node_control()
                self.assertEqual(k.writes,[]); self.assertTrue(c.failed)

    def test_foreign_owned_table_replacement_retains_every_resource(self):
        for fault in ('comment','extra-rule','missing-table','foreign-policy'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as d:
                k,c,j,baseline = self.connected(d); writes = list(k.writes)
                if fault=='comment': k.host_nft['nftables'][1]['table']['comment']='foreign'
                if fault=='extra-rule': k.host_nft['nftables'].append({'rule':{'family':'ip','table':'c3nodecontrol','foreign':True}})
                if fault=='missing-table': k.host_nft=copy.deepcopy(FOREIGN)
                if fault=='foreign-policy': k.host_nft['nftables'][0]['table']['name']='replaced'
                with self.assertRaises(m.Refusal): c.effect('remove-owned',lambda:k.remove(baseline))
                self.assertEqual(k.writes,writes); self.assertTrue(c.failed)
                self.assertNotIn('nft-node-delete',k.writes)

    def test_new_create_route_delete_boundaries_keep_intent_guard_unknown_retention(self):
        for boundary in ('nft-node-create','ip:fresh:route:add:10.203.61.1/32', 'nft-node-delete'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as d:
                if boundary=='nft-node-delete': k,c,j,baseline = self.connected(d)
                else: k,c,j = self.wire(d); baseline=copy.deepcopy(k.state)
                before=len(k.writes); original=k.written
                def written(label):
                    original(label)
                    if label.startswith(boundary): k.alive=False
                k.written=written
                with self.assertRaises(m.Refusal):
                    if boundary=='nft-node-create': k.install_node_control()
                    elif boundary=='nft-node-delete': k.remove(baseline)
                    else:
                        k.install_node_control()
                        with patch.object(m,'move_link',side_effect=k.move): k.connect('caddy')
                self.assertTrue(k.writes[-1].startswith(boundary)); self.assertTrue(c.failed)
                self.assertEqual(c.phase,'unknown-retained')
                writes=list(k.writes); k.alive=True
                with self.assertRaises(m.Refusal): k.remove(baseline)
                self.assertEqual(k.writes,writes)
                records=[m.decode(p.read_bytes()) for p in sorted(j.path.iterdir())]
                intents=[r['effect'] for r in records if r['kind']=='intent']
                self.assertTrue(any('node-control' in label for label in intents))
                self.assertGreater(len(k.writes),before)


if __name__ == '__main__': unittest.main()
