"""Real constructor/journal commands; captured IPv4 policy model, NOT kernel packets.

IPv6 is the exact canonical projection of real TEST wave99 save captures;
wave95 did not capture it. Kernel effects and executable trust remain modeled.
No network, privileged command, daemon, namespace or remote auth is invoked.
"""
import copy
import ipaddress
import json
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch
import test_fresh_network_node_control as old

m = old.m
FACTS = json.loads((Path(__file__).parent/'fixtures/node_forward_wave95.json').read_text())


def packet(port=2222, reply=False, **changes):
    source = m.addresses(old.egress_plan(), 'caddy')[0]
    p = dict(saddr='10.203.61.2' if reply else source,
             daddr=source if reply else '10.203.61.2',
             iif='c3test61' if reply else 'c3pc', oif='c3pc' if reply else 'c3test61',
             protocol='tcp', sport=port if reply else 49152,
             dport=49152 if reply else port, state='ESTABLISHED' if reply else 'NEW')
    p.update(changes)
    return p


def filter_model(text, p, chain='FORWARD', trail=None):
    """Finite evaluator for actual captured filter tokens; unknown syntax REFUSES."""
    tables = {}; table = None
    for line in text.splitlines():
        if line.startswith('*'): table=line[1:]; tables[table]={}
        elif line.startswith(':'):
            name, policy = line[1:].split()[:2]; tables[table][name]=[policy, []]
        elif line.startswith('-A '):
            tokens=shlex.split(line); tables[table][tokens[1]][1].append(tokens[2:])
    trail = [] if trail is None else trail
    def run(name, depth=0):
        assert depth < 12
        policy, rows = tables['filter'][name]
        for tokens in rows:
            matched=True; neg=False; i=0; target=None
            while i<len(tokens):
                option=tokens[i]; i+=1
                if option=='!': neg=True; continue
                value=tokens[i]; i+=1
                if option=='-j': target=value; continue
                if option=='-m':
                    assert value in ('tcp','udp','conntrack','comment'); continue
                if option=='--comment': continue
                if option in ('-s','-d'): result=ipaddress.ip_address(p['saddr' if option=='-s' else 'daddr']) in ipaddress.ip_network(value)
                elif option in ('-i','-o','-p'): result=p[{'-i':'iif','-o':'oif','-p':'protocol'}[option]]==value
                elif option in ('--dport','--sport'): result=p['dport' if option=='--dport' else 'sport']==int(value)
                elif option=='--ctstate': result=p['state'] in value.split(',')
                else: raise AssertionError('unsupported finite filter model option '+option)
                matched &= not result if neg else result; neg=False
            trail.append((name, matched, target))
            if matched:
                if target in ('ACCEPT','DROP','RETURN'):return target
                result=run(target,depth+1)
                if result!='RETURN':return result
        return 'RETURN' if policy=='-' else policy
    return run(chain)


def proposal():
    p=old.egress_plan()
    if hasattr(m,'node_forward_rules'):
        rules=m.node_forward_rules(p)
        return '\n'.join(FACTS['ipv4'].splitlines()[:0]) + inject(FACTS['ipv4'],rules)
    # Exact baseline proposal: private OUTPUT + scoped POSTROUTING SNAT only.
    # Evaluating the real FORWARD chain therefore still yields DROP, not schema error.
    m.node_nft_policy(p)
    return FACTS['ipv4']


def inject(text, rules):
    lines=text.splitlines(); at=next(i for i,l in enumerate(lines) if l.startswith('-A FORWARD '))
    for rule in reversed(rules): lines.insert(at, shlex.join(rule))
    return '\n'.join(lines)+'\n'


def forward_plan():
    p=old.egress_plan()
    compat={k:m.node_compat_canonical(FACTS[k]) for k in ('ipv4','ipv6','legacy4','legacy6')}
    link={'ifname':'c3test61','ifindex':87,'linkinfo':{'info_kind':'wireguard'},'flags':['UP']}
    p['nodeControlEgress']['hostRulesetSha256']=m.digest(m.encode(FACTS['nft']))
    p['nodeControlEgress']['forwardPolicy']={
        'mode':'docker-forward-v1','compatPolicySha256':m.digest(m.encode(compat)),
        'executables':{m.XTABLES:'d'*64,m.XTABLES_LEGACY:'e'*64},
        'wireguardLinkSha256':m.digest(m.encode(link))}
    return p,link


class ForwardWire(old.EgressWire):
    """Only the external command/kernel seam is modeled; actual Linux methods run."""
    node_nft_apply=m.Linux.node_nft_apply
    def __init__(self,p=None):
        default,link=forward_plan();super().__init__(p or default)
        self.state['host']['links'].append(link)
        self.host_nft=copy.deepcopy(FACTS['nft'])
        self.compat={k:m.node_compat_canonical(FACTS[k]) for k in ('ipv4','ipv6','legacy4','legacy6')}
        self.external=[];self.journal=None;self.before_write=lambda argv:None;self.after_write=lambda argv:None
        self.next_handle=1000
    def node_compat_binaries(self):
        pass  # Explicitly modeled root trust/executable byte observations.
    def mutation(self,argv,label,fn):
        assert self.journal is not None
        records=[m.decode(p.read_bytes()) for p in sorted(self.journal.path.iterdir())]
        assert records[-1]['kind']=='intent',records[-1]
        self.before_write(argv);fn();self.written(label);self.after_write(argv)
    def run(self,argv,**kw):
        import types
        self.external.append((list(argv),dict(kw)))
        result=''
        if argv[0]==m.XTABLES and argv[1]=='iptables' and '--version' in argv:
            result='iptables v1.8.10 (nf_tables)\n'
        elif argv[0] in (m.XTABLES,m.XTABLES_LEGACY) and argv[1].endswith('save'):
            name=('ipv6' if argv[1].startswith('ip6') else 'ipv4') if argv[0]==m.XTABLES else ('legacy6' if argv[1].startswith('ip6') else 'legacy4')
            text=self.compat[name]
            if '-t' in argv:
                table=argv[-1];blocks=text.split('*');result=next('*'+b for b in blocks if b.startswith(table+'\n'))
            else:result=text
        elif argv[:9]==[m.XTABLES,'iptables','-w','1','-t','filter','-I','FORWARD','1']:
            tokens=['-A','FORWARD',*argv[9:]]
            def add():
                self.compat['ipv4']=inject(self.compat['ipv4'],[tokens])
                self.next_handle+=1
                row={'rule':{'family':'ip','table':'filter','chain':'FORWARD','handle':self.next_handle,
                             'expr':[{'xt':{'type':'match','name':'conntrack'}},{'counter':None},{'accept':None}]}}
                at=next(i for i,r in enumerate(self.host_nft['nftables']) if 'rule'in r and r['rule'].get('family')=='ip' and r['rule'].get('table')=='filter' and r['rule'].get('chain')=='FORWARD')
                self.host_nft['nftables'].insert(at,row)
            self.mutation(argv,'forward-insert',add)
        elif argv==[m.NFT,'-f','-']:
            raw=kw['input']
            if raw==m.node_nft_policy(self.p):
                def nat():
                    self.host_nft['nftables'] += [
                        {'table':{'family':'ip','name':m.NODE_TABLE,'handle':3000,'comment':'c3:'+self.p['generation']}},
                        {'rule':{'family':'ip','table':m.NODE_TABLE,'chain':'source','handle':3001,'modeledScript':raw.decode()}}]
                self.mutation(argv,'nft-node-create',nat)
            elif raw==b'delete table ip c3nodecontrol\n':
                def delete_nat():
                    self.host_nft['nftables']=[r for r in self.host_nft['nftables'] if
                        not (next(iter(r.values())).get('family')=='ip' and
                        (next(iter(r.values())).get('name') if 'table'in r else next(iter(r.values())).get('table'))==m.NODE_TABLE)]
                self.mutation(argv,'nft-node-delete',delete_nat)
            elif raw.startswith(b'delete rule ip filter FORWARD handle '):
                handle=int(raw.decode().split()[-1]);seal=next(s for s in self.node_forward_seal if s['nft']['rule']['handle']==handle)
                def delete_rule():
                    self.host_nft['nftables'].remove(seal['nft'])
                    lines=self.compat['ipv4'].splitlines();tokens=seal['tokens']
                    at=next(i for i,l in enumerate(lines) if l.startswith('-A FORWARD') and m.node_owned_tokens(shlex.split(l))==m.node_owned_tokens(tokens))
                    del lines[at];self.compat['ipv4']='\n'.join(lines)+'\n'
                self.mutation(argv,'forward-delete',delete_rule)
            else:raise AssertionError('unexpected nft input')
        else:raise AssertionError('external command outside finite fixture '+repr(argv))
        return types.SimpleNamespace(stdout=result.encode(),stderr=b'',returncode=0)


class ForwardPolicyTests(unittest.TestCase):
    def wire(self,d,p=None):
        k=ForwardWire(p);j=m.Journal(Path(d)/'generation',k.p);self.addCleanup(j.close)
        k.journal=j;c=m.Controller(k.p,k,j,guard=k.guard)
        self.enterContext(patch.object(m,'in_namespace',side_effect=lambda fd,fn,**kwargs:fn()))
        self.enterContext(patch.object(m.subprocess,'run',side_effect=k.run))
        return k,c,j

    def test_real_generated_commands_readback_journal_and_exact_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            k,c,j=self.wire(d);self.assertIs(m.validate_plan(k.p),k.p)
            k.install_node_control()
            self.assertEqual(len(k.node_forward_seal),4)
            writes=[a for a,kw in k.external if '-I'in a]
            self.assertEqual(writes,[[m.XTABLES,'iptables','-w','1','-t','filter','-I','FORWARD','1',*t[2:]] for t in m.node_forward_rules(k.p)])
            for port in (2222,62080):
                self.assertEqual(filter_model(k.compat['ipv4'],packet(port)),'ACCEPT')
                self.assertEqual(filter_model(k.compat['ipv4'],packet(port,True)),'ACCEPT')
            handles=[s['nft']['rule']['handle'] for s in k.node_forward_seal]
            self.assertEqual(len(handles),len(set(handles)))
            k.remove_node_control()
            self.assertEqual(k.host_nft,FACTS['nft'])
            self.assertEqual(k.compat,{a:m.node_compat_canonical(FACTS[a]) for a in k.compat})
            self.assertEqual(k.node_forward_seal,[]);self.assertIsNone(k.node_table_seal)
            deleted=[kw['input'].decode() for a,kw in k.external if a==[m.NFT,'-f','-'] and kw['input'].startswith(b'delete rule')]
            self.assertEqual(deleted,[f'delete rule ip filter FORWARD handle {h}\n' for h in handles])
            records=[m.decode(p.read_bytes()) for p in sorted(j.path.iterdir())]
            intents=[r['effect'] for r in records if r['kind']=='intent']
            confirmed=[r['effect'] for r in records if r['kind']=='confirmed']
            self.assertEqual(intents,confirmed);self.assertEqual(len(intents),10)

    def test_captured_effective_drop_path_exact_proposal_allows_both_flows_replies(self):
        for port in (2222,62080):
            for reply in (False,True):
                p=packet(port,reply)
                self.assertEqual(filter_model(FACTS['ipv4'],p),'DROP')
                self.assertEqual(filter_model(proposal(),p),'ACCEPT',
                                 'current scoped SNAT proposal still DENIED by actual Docker FORWARD DROP')

    def test_negative_wrong_tuple_interfaces_states_and_foreign_policy_preserved(self):
        text=proposal()
        negatives=[]
        for port in (2222,62080):
            for reply in (False,True):
                for delta in ({'saddr':'10.203.61.3'},{'daddr':'10.253.241.99'},
                              {'iif':'c3foreign'},{'oif':'c3foreign'},{'protocol':'udp'},
                              {'state':'RELATED'},{'state':'INVALID'},
                              {'sport':9999} if reply else {'dport':9999}):
                    negatives.append(packet(port,reply,**delta))
            negatives.append(packet(port,True,state='NEW'))
            self.assertEqual(filter_model(text,packet(port,state='ESTABLISHED')),'ACCEPT')
        for p in negatives:
            with self.subTest(packet=p):self.assertEqual(filter_model(text,p),'DROP')
        # Existing unrelated Docker accepts are not revoked or adopted as ours.
        for p in (packet(iif='docker0'),packet(oif='docker0',state='ESTABLISHED'),
                  packet(saddr='172.19.0.2',iif='br-bdc639b58573')):
            self.assertEqual(filter_model(text,p),filter_model(FACTS['ipv4'],p))
        rules=m.node_forward_rules(old.egress_plan())
        self.assertTrue(all('RELATED' not in t and '-j' in t and t[-1]=='ACCEPT' for t in rules))
        self.assertTrue(all('10.203.61.1/32' not in t for t in rules),'no B INPUT grant')

    def test_complete_opaque_parameters_drift_refuses_even_identical_nft_json(self):
        changes=[('ipv4','RELATED,ESTABLISHED','NEW,RELATED,ESTABLISHED'),
                 ('ipv4','--dst-type LOCAL','--dst-type UNICAST'),
                 ('ipv4','--to-destination 172.19.0.2:27017','--to-destination 172.19.0.99:27017'),
                 ('ipv6','c3-test-native-wave61-tcp3001','changed-ip6-comment')]
        for key,old_text,new_text in changes:
            with self.subTest(key=key,change=old_text),tempfile.TemporaryDirectory() as d:
                k,c,j=self.wire(d);k.install_node_control();before=list(k.writes);nft=copy.deepcopy(k.host_nft)
                self.assertIn(old_text,k.compat[key]);k.compat[key]=k.compat[key].replace(old_text,new_text)
                self.assertEqual(k.host_nft,nft)
                with self.assertRaises(m.Refusal): k.remove_node_control()
                self.assertEqual(k.writes,before);self.assertTrue(c.failed)

    def test_legacy_nonempty_without_compat_binding_refuses_actual_opaque_policy(self):
        with tempfile.TemporaryDirectory() as d:
            p,_=forward_plan();p['nodeControlEgress'].pop('forwardPolicy')
            k,c,j=self.wire(d,p)
            with self.assertRaisesRegex(m.Refusal,'COMPLETE_COMPAT_BINDING_REQUIRED'):k.install_node_control()
            self.assertEqual(k.writes,[])

    def test_supported_shape_chain_identity_priority_and_unknown_hooks_refuse(self):
        for fault in ('handle','priority','policy','extra-hook','new-table','wg-replacement'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                k,c,j=self.wire(d)
                chain=next(r['chain'] for r in k.host_nft['nftables'] if 'chain'in r and r['chain'].get('family')=='ip' and r['chain'].get('name')=='FORWARD')
                if fault=='handle':chain['handle']+=1
                elif fault=='priority':chain['prio']=-1
                elif fault=='policy':chain['policy']='accept'
                elif fault=='extra-hook':k.host_nft['nftables'].append({'chain':{'family':'inet','name':'bypass','table':'x','hook':'forward','prio':-1,'policy':'accept'}})
                elif fault=='new-table':k.host_nft['nftables'].append({'table':{'family':'bridge','name':'foreign'}})
                else:k.state['host']['links'][0]['ifindex']=88
                with self.assertRaises(m.Refusal):k.install_node_control()
                self.assertEqual(k.writes,[])

    def test_forward_owned_replacement_missing_rule_and_comment_changes_never_cleaned(self):
        for fault in ('handle','expr','missing','comment','duplicate','ordering','foreign'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                k,c,j=self.wire(d);k.install_node_control();before=list(k.writes)
                row=k.node_forward_seal[0]['nft'];at=k.host_nft['nftables'].index(row)
                # Independent readback state, not a shared seal-reference fixture.
                k.host_nft=copy.deepcopy(k.host_nft)
                row=k.host_nft['nftables'][at]
                if fault=='handle':row['rule']['handle']+=400
                elif fault=='expr':row['rule']['expr'][-1]={'drop':None}
                elif fault=='missing':del k.host_nft['nftables'][at]
                elif fault=='comment':k.compat['ipv4']=k.compat['ipv4'].replace('62080reply','foreigncomment')
                elif fault=='duplicate':k.host_nft['nftables'].insert(at,copy.deepcopy(row))
                elif fault=='ordering':k.host_nft['nftables'][at:at+2]=reversed(k.host_nft['nftables'][at:at+2])
                else:k.compat['ipv4']=k.compat['ipv4'].replace(':FORWARD DROP',':FORWARD ACCEPT')
                with self.assertRaises(m.Refusal):k.remove_node_control()
                self.assertEqual(k.writes,before);self.assertTrue(c.failed)

    def test_creation_collision_and_unexpected_insert_delta_are_retained(self):
        for fault in ('preexisting-comment','own-table','wrong-written-tuple','extra-written-rule'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                k,c,j=self.wire(d)
                if fault=='preexisting-comment':k.compat['ipv4']=inject(k.compat['ipv4'],[m.node_forward_rules(k.p)[0]])
                elif fault=='own-table':k.host_nft['nftables'].append({'table':{'family':'ip','name':m.NODE_TABLE,'comment':'c3:'+k.p['generation']}})
                else:
                    def after(argv):
                        if '-I'in argv:
                            if fault=='wrong-written-tuple':k.compat['ipv4']=k.compat['ipv4'].replace('--dport 2222','--dport 9999')
                            else:k.host_nft['nftables'].append({'rule':{'family':'ip','table':'filter','chain':'FORWARD','handle':8000,'expr':[{'accept':None}]}})
                    k.after_write=after
                with self.assertRaises(m.Refusal):k.install_node_control()
                self.assertTrue(c.failed)
                self.assertNotIn('nft-node-delete',k.writes)
                self.assertEqual(k.writes.count('forward-insert'),0 if fault in ('preexisting-comment','own-table') else 1)

    def test_intent_fsync_failure_and_expiry_after_intent_prevent_forward_dispatch(self):
        for fault in ('io','guard','expiry'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                k,c,j=self.wire(d);append=j.append
                def journal(record):
                    append(record)
                    if record.get('kind')=='intent' and record.get('effect','').startswith('node-forward-insert'):
                        if fault=='io':raise OSError('modeled fsync ambiguity')
                        elif fault=='guard':k.alive=False
                        else:c.end=0
                j.append=journal
                with self.assertRaises((m.Refusal,OSError)):k.install_node_control()
                self.assertEqual(k.writes,['nft-node-create']);self.assertTrue(c.failed)

    def test_actual_joined_child_boundary_rechecks_guard_before_external_write(self):
        with tempfile.TemporaryDirectory() as d:
            k,c,j=self.wire(d);invoke=k.invoke
            def joined(where,fn):
                if fn.__name__=='call':k.alive=False
                return invoke(where,fn)
            k.invoke=joined
            with self.assertRaisesRegex(m.Refusal,'MODELED_GUARD_LOST'):k.install_node_control()
            self.assertEqual(k.writes,['nft-node-create']);self.assertTrue(c.failed)
            self.assertFalse(any('-I'in a for a,kw in k.external))

    def test_every_post_ack_guard_loss_is_unknown_no_followup_or_cleanup(self):
        for deleting in (False,True):
            for number in range(1,5):
                with self.subTest(deleting=deleting,number=number),tempfile.TemporaryDirectory() as d:
                    k,c,j=self.wire(d)
                    if deleting:k.install_node_control()
                    before=list(k.writes);count=[0]
                    def after(argv):
                        if ('-I'in argv) if not deleting else (argv==[m.NFT,'-f','-']):
                            count[0]+=1
                            if count[0]==number:k.alive=False
                    k.after_write=after
                    with self.assertRaises(m.Refusal):
                        k.remove_node_control() if deleting else k.install_node_control()
                    self.assertTrue(c.failed);self.assertEqual(c.phase,'unknown-retained')
                    self.assertEqual(k.writes[len(before):].count('forward-delete' if deleting else 'forward-insert'),number)
                    self.assertNotIn('nft-node-delete',k.writes)
                    saved=list(k.writes);k.alive=True;k.after_write=lambda argv:None
                    with self.assertRaises(m.Refusal):k.remove_node_control()
                    self.assertEqual(k.writes,saved)

    def test_partial_cleanup_seal_evolves_and_drift_stops_survivor_deletion(self):
        with tempfile.TemporaryDirectory() as d:
            k,c,j=self.wire(d);k.install_node_control();before=list(k.writes)
            def after(argv):
                if argv==[m.NFT,'-f','-']:
                    k.host_nft=copy.deepcopy(k.host_nft)
                    survivor=k.node_forward_seal[1]['nft'];row=next(r for r in k.host_nft['nftables'] if r==survivor)
                    row['rule']['handle']+=90
            k.after_write=after
            with self.assertRaises(m.Refusal):k.remove_node_control()
            self.assertEqual(k.writes[len(before):],['forward-delete'])
            self.assertTrue(c.failed);self.assertNotIn('nft-node-delete',k.writes)

    def test_full_constructor_connect_seal_and_cleanup_keep_route_and_veth_contract(self):
        with tempfile.TemporaryDirectory() as d:
            k,c,j=self.wire(d);baseline=copy.deepcopy(k.state);k.install_node_control()
            with patch.object(m,'move_link',side_effect=k.move):
                for role in m.ROLES:k.connect(role)
            k.seal();target=Path(d)/'namespace';target.write_bytes(b'owned');k.path_identity=m.identity(target)
            with patch.object(m,'NETNS',str(target)),patch.object(m,'syscall'):
                k.remove(baseline)
            self.assertEqual(k.state['host'],baseline['host']);self.assertFalse(target.exists())
            self.assertEqual(k.host_nft,FACTS['nft']);self.assertIsNotNone(k.sealed)
            self.assertEqual(k.writes.count('forward-delete'),4)

    def test_forward_policy_closed_fields_immutable_root_plan_and_request_refusal(self):
        for fault in ('mode','digest','executable','field','wg'):
            p,_=forward_plan();v=p['nodeControlEgress']['forwardPolicy']
            if fault=='mode':v['mode']='general-accept'
            elif fault=='digest':v['compatPolicySha256']=True
            elif fault=='executable':v['executables']['/usr/sbin/iptables']='f'*64
            elif fault=='field':v['adopt']=True
            else:v['wireguardLinkSha256']='x'*64
            with self.subTest(fault=fault),self.assertRaises(m.Refusal):m.validate_plan(p)
        with tempfile.TemporaryDirectory() as d:
            k,c,j=self.wire(d);k.p['nodeControlEgress']['forwardPolicy']['mode']='general-accept'
            with self.assertRaisesRegex(m.Refusal,'ACCEPTED_PLAN_MUTATED'):c.effect('new-forward',lambda:None)
            self.assertEqual(k.writes,[])

    def test_confirmed_journal_failure_after_ack_retains_measured_owned_handles(self):
        with tempfile.TemporaryDirectory() as d:
            k,c,j=self.wire(d);append=j.append
            def journal(record):
                if record.get('kind')=='confirmed' and record.get('effect','').startswith('node-forward-insert'):
                    raise OSError('modeled confirmation fsync failure')
                append(record)
            j.append=journal
            with self.assertRaises(OSError):k.install_node_control()
            self.assertEqual(len(k.node_forward_seal),1);self.assertTrue(c.failed)
            self.assertEqual(k.writes,['nft-node-create','forward-insert'])
            with self.assertRaises(m.Refusal):k.remove_node_control()
            self.assertNotIn('forward-delete',k.writes)

    def test_lost_cleanup_ack_retains_survivors_without_replay(self):
        with tempfile.TemporaryDirectory() as d:
            k,c,j=self.wire(d);k.install_node_control()
            def after(argv):
                if argv==[m.NFT,'-f','-']:raise OSError('modeled lost nft ACK')
            k.after_write=after
            with self.assertRaises(OSError):k.remove_node_control()
            self.assertTrue(c.failed);self.assertEqual(k.writes.count('forward-delete'),1)
            self.assertEqual(len(k.node_forward_seal),4,'unconfirmed delete does not advance seal')
            self.assertNotIn('nft-node-delete',k.writes)

    def test_unknown_ipv6_legacy_and_reused_handle_refused(self):
        for fault in ('ipv6-option','legacy','handle-reuse'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                k,c,j=self.wire(d)
                if fault=='ipv6-option':k.compat['ipv6']=k.compat['ipv6'].replace('--dst-type LOCAL','--src-type LOCAL')
                elif fault=='legacy':k.compat['legacy4']='*filter\n:FORWARD ACCEPT\nCOMMIT\n'
                else:
                    def after(argv):
                        if '-I'in argv:
                            row=next(r['rule'] for r in k.host_nft['nftables'] if 'rule'in r and r['rule'].get('handle')==1001)
                            row['handle']=17
                    k.after_write=after
                with self.assertRaises(m.Refusal):k.install_node_control()
                self.assertTrue(c.failed);self.assertNotIn('forward-delete',k.writes)

    def test_current_real_loaders_original_pidfd_lease_carry_complete_forward_field(self):
        import test_fresh_network_entry as entry
        class Harness(entry.FixedServerHarness):
            def __enter__(self):
                super().__enter__();deadline=self.p['deadline'];self.p,_=forward_plan()
                self.p['deadline']=deadline;self.raw=m.encode(self.p);(self.root/'plan').write_bytes(self.raw)
                return self
        with Harness(self) as h:
            h.lease();h.server();holder=h.holder()
            prepared=holder.connect();self.assertEqual(prepared['phase'],'prepared')
            self.assertEqual(holder.dispatch('observe')['phase'],'prepared')
            self.assertEqual(holder.dispatch('abandon')['phase'],'abandoned')
            holder.close();stdout,stderr=h.child.communicate(timeout=3)
            self.assertEqual(h.child.returncode,0,stderr.decode())
            self.assertNotIn('write-config',h.effects())
        # Real ordinary processes/FDs/protocol. Its privileged network is modeled.

    def test_regular_compat_binaries_byte_pins_and_backend_version(self):
        import os
        import types
        with tempfile.TemporaryDirectory() as d:
            p,_=forward_plan();k=m.Linux.__new__(m.Linux);k.p=p
            raw=b'explicitly-modeled-executable';target=Path(d)/'ordinary-file';target.write_bytes(raw)
            target.chmod(0o644)  # Exact non-writable fixture mode, independent of caller umask.
            self.assertEqual(target.stat().st_mode & 0o777,0o644)
            p['nodeControlEgress']['forwardPolicy']['executables']={m.XTABLES:m.digest(raw),m.XTABLES_LEGACY:m.digest(raw)}
            k.node_compat_exec=lambda argv:'iptables v1.8.10 (nf_tables)\n'
            with patch.object(m,'trusted_fd',side_effect=lambda path:os.open(target,os.O_RDONLY)):
                k.node_compat_binaries()
                target.write_bytes(b'different')
                with self.assertRaisesRegex(m.Refusal,'COMPAT_EXECUTABLE_DRIFT'):k.node_compat_binaries()
                target.write_bytes(raw);k.node_compat_exec=lambda argv:'iptables v1.8.10 (legacy)\n'
                with self.assertRaisesRegex(m.Refusal,'UNSUPPORTED_COMPAT_BACKEND'):k.node_compat_binaries()

    def test_complete_save_canonicalization_only_counter_header_and_quoting_projection(self):
        original=FACTS['ipv4'];canonical=m.node_compat_canonical(original)
        counted='\n'.join(replace_counter(l) for l in original.splitlines())+'\n'
        counted='# Generated by iptables-save v1.8.10 (nf_tables) on Sat Nov  7 09:50:09 2026\n'+counted+'# Completed on Sat Nov  7 09:50:09 2026\n'
        self.assertEqual(m.node_compat_canonical(counted),canonical)
        for bad in ('# unknown metadata\n'+original,original.replace('COMMIT\n','',1),
                    original.replace('*raw','*mangle'),original.replace(':FORWARD DROP',':FORWARD QUEUE')):
            with self.subTest(bad=bad[:30]),self.assertRaises(m.Refusal):m.node_compat_canonical(bad)


def replace_counter(line):
    if line.startswith(':'):return line+' [10:200]'
    if line.startswith('-A'):return '[11:220] '+line
    return line


if __name__=='__main__': unittest.main()
