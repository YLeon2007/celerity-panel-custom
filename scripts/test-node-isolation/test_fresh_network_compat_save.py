"""REAL TEST save bytes through real readers; kernel/UID trust explicitly MODELED.

The observation projection/pin is independently retained in the finite fixture,
not computed by the candidate codec to authorize itself. No live firewall IO.
"""
import copy
import json
from pathlib import Path
import re
import tempfile
import types
import unittest
from unittest.mock import patch
import test_fresh_network_node_forward as f

m = f.m
CAPTURE = json.loads((Path(__file__).parent/'fixtures/node_compat_wave99.json').read_text())
CANONICAL = CAPTURE['canonicalObservation']
COMPAT_PIN = '4cbb267aacdf73bb1789668b603079373b3f3b03628f545120aeaff7c74cb725'
IPV6_PIN = '9aef5acc8cf5c57ba108bc44d27183d81ebe6bb5f8156480190be32496e02bcc'


def raw_blocks(text):
    blocks = {}; block = []; table = None
    for line in text.splitlines():
        block.append(line)
        if line.startswith('*'): table = line[1:]
        if line.startswith('# Completed on '):
            assert table is not None and table not in blocks
            blocks[table] = '\n'.join(block)+'\n'; block = []; table = None
    assert not block
    return blocks


class RawSaveWire(f.ForwardWire):
    """Return captured producer bytes, adding ONLY modeled owned IPv4 rows.

    Existing ForwardWire owns its unchanged insertion/handle/cleanup model.
    Foreign save rows retain their exact original counters, quotes and headers.
    """
    def __init__(self, diagnostic_headers_only=False):
        p, _ = f.forward_plan()
        # Independently prepared modeled plan BEFORE Controller/Journal exists.
        assert m.digest(m.encode(CANONICAL)) == COMPAT_PIN
        p['nodeControlEgress']['forwardPolicy']['compatPolicySha256'] = COMPAT_PIN
        super().__init__(p)
        self.compat = copy.deepcopy(CANONICAL)
        self.diagnostic_headers_only = diagnostic_headers_only
        self.save_receipts = []

    def run(self, argv, **kw):
        if argv[0] not in (m.XTABLES,m.XTABLES_LEGACY) or not argv[1].endswith('save'):
            return super().run(argv, **kw)
        self.external.append((list(argv),dict(kw)))
        key = ('ipv6' if argv[1].startswith('ip6') else 'ipv4') if argv[0] == m.XTABLES else ('legacy6' if argv[1].startswith('ip6') else 'legacy4')
        text = CAPTURE['raw'][key]
        if '-t' in argv: text = raw_blocks(text)[argv[-1]]
        if key == 'ipv4' and (not '-t' in argv or argv[-1] == 'filter'):
            original = CANONICAL['ipv4'].splitlines()
            added = [line for line in self.compat['ipv4'].splitlines() if line not in original]
            assert all(line.startswith('-A FORWARD ') for line in added)
            if added:
                lines = text.splitlines()
                at = next(i for i,line in enumerate(lines) if re.match(r'(?:\[[0-9]+:[0-9]+\] )?-A FORWARD ',line))
                lines[at:at] = added
                text = '\n'.join(lines)+'\n'
        if self.diagnostic_headers_only:
            # Qualified diagnostic only: remove exactly the observed headers;
            # no chain/rule/counter edits and no production acceptance bypass.
            headers = {line for value in CAPTURE['raw'].values() for line in value.splitlines() if line.startswith('#')}
            text = '\n'.join(line for line in text.splitlines() if line not in headers)+ ('\n' if text else '')
        self.save_receipts.append({'argv':list(argv),'stdoutSha256':m.digest(text.encode())})
        return types.SimpleNamespace(stdout=text.encode(),stderr=b'',returncode=0)


class ActualSaveTests(unittest.TestCase):
    def wire(self, directory, diagnostic=False):
        k = RawSaveWire(diagnostic)
        j = m.Journal(Path(directory)/'generation',k.p); self.addCleanup(j.close)
        k.journal = j
        c = m.Controller(k.p,k,j,guard=k.guard)
        self.enterContext(patch.object(m,'in_namespace',side_effect=lambda fd,fn,**kw:fn()))
        self.enterContext(patch.object(m.subprocess,'run',side_effect=k.run))
        return k,c,j

    def test_actual_raw_header_through_real_reader_matches_independent_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            k,c,j = self.wire(directory)
            self.assertEqual(k.node_compat_rules(),CANONICAL)
            self.assertEqual(m.digest(CANONICAL['ipv6'].encode()),IPV6_PIN)
            self.assertEqual(k.writes,[])
            self.assertEqual(len(k.save_receipts),7)

    def test_header_only_diagnostic_still_requires_actual_complete_ipv6_install(self):
        with tempfile.TemporaryDirectory() as directory:
            k,c,j = self.wire(directory,diagnostic=True)
            self.assertEqual(k.node_compat_rules(),CANONICAL)
            k.install_node_control()
            self.assertEqual(len(k.node_forward_seal),4)
            k.remove_node_control()
            self.assertEqual(k.host_nft,f.FACTS['nft'])
            self.assertEqual(k.compat,CANONICAL)

    def test_actual_raw_install_four_scoped_rules_and_exact_cleanup_no_ipv6_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            k,c,j = self.wire(directory)
            k.install_node_control()
            self.assertEqual(len(k.node_forward_seal),4)
            self.assertEqual(k.compat['ipv6'],CANONICAL['ipv6'])
            self.assertEqual([a for a,kw in k.external if '-I' in a],
                             [[m.XTABLES,'iptables','-w','1','-t','filter','-I','FORWARD','1',*t[2:]] for t in m.node_forward_rules(k.p)])
            k.remove_node_control()
            self.assertEqual(k.host_nft,f.FACTS['nft'])
            self.assertEqual(k.compat,CANONICAL)
            self.assertEqual(k.writes,['nft-node-create']+['forward-insert']*4+['forward-delete']*4+['nft-node-delete'])
            self.assertFalse(any(a[0] == m.XTABLES and a[1] == 'ip6tables' for a,kw in k.external))
            records=[m.decode(p.read_bytes()) for p in sorted(j.path.iterdir())]
            self.assertEqual([r['effect'] for r in records if r['kind']=='intent'],
                             [r['effect'] for r in records if r['kind']=='confirmed'])


    def test_wrong_version_backend_timestamp_and_arbitrary_headers_refuse(self):
        raw = CAPTURE['raw']['ipv6']
        header = next(line for line in raw.splitlines() if line.startswith('# Generated by '))
        completed = next(line for line in raw.splitlines() if line.startswith('# Completed on '))
        changes = [
            raw.replace('v1.8.10','v1.8.11'),
            raw.replace('(nf_tables)','(legacy)'),
            raw.replace(' (nf_tables)',''),
            raw.replace(header,header+' trailing'),
            raw.replace(completed,completed+' trailing'),
            raw.replace('Sat Nov  7 09:50:09 2026','modeled-time'),
            raw.replace('09:50:09','24:50:09'),
            raw.replace('Sat Nov  7','Sat Nov 07'),
            raw+'# arbitrary trailing metadata\n',
        ]
        for index,text in enumerate(changes):
            with self.subTest(index=index),self.assertRaises(m.Refusal):
                m.node_compat_canonical(text)
        for key in ('ipv4','ipv6','legacy4','legacy6'):
            self.assertEqual(m.node_compat_canonical(CAPTURE['raw'][key]),CANONICAL[key])

    def test_complete_ipv6_closed_shape_negatives_with_matching_prepared_plan(self):
        blocks = CANONICAL['ipv6'].split('*')
        variants = []
        for table,name in (('nat','INPUT'),('nat','POSTROUTING'),('filter','OUTPUT')):
            for fault in ('missing','DROP','nonempty'):
                changed = []
                for block in blocks:
                    if block.startswith(table+'\n'):
                        if fault == 'missing': block = block.replace(':'+name+' ACCEPT\n','')
                        elif fault == 'DROP': block = block.replace(':'+name+' ACCEPT\n',':'+name+' DROP\n')
                        else: block = block.replace('COMMIT\n','-A '+name+' -j ACCEPT\nCOMMIT\n')
                    changed.append(block)
                variants.append((table+'/'+name+'/'+fault,'*'.join(changed)))
        variants.extend([
            ('unknown-chain',CANONICAL['ipv6'].replace('*nat\n','*nat\n:UNKNOWN ACCEPT\n')),
            ('parameter',CANONICAL['ipv6'].replace('--dst-type LOCAL','--dst-type UNICAST')),
            ('missing-existing-chain',CANONICAL['ipv6'].replace(':DOCKER-USER -\n','')),
        ])
        for label,text in variants:
            with self.subTest(case=label),tempfile.TemporaryDirectory() as directory:
                compat = copy.deepcopy(CANONICAL); compat['ipv6'] = text
                p,_ = f.forward_plan()
                # An intentionally matching independently prepared modeled pin
                # cannot waive the product's closed IPv6 recognition predicate.
                p['nodeControlEgress']['forwardPolicy']['compatPolicySha256'] = m.digest(m.encode(compat))
                k = f.ForwardWire(p); k.compat = compat
                j = m.Journal(Path(directory)/'generation',p)
                try:
                    k.journal=j; c=m.Controller(p,k,j,guard=k.guard)
                    with patch.object(m,'in_namespace',side_effect=lambda fd,fn,**kw:fn()),patch.object(m.subprocess,'run',side_effect=k.run):
                        with self.assertRaisesRegex(m.Refusal,'UNSUPPORTED_IPV6_COMPAT_POLICY'):
                            k.install_node_control()
                    self.assertEqual(k.writes,[])
                    self.assertTrue(c.failed)
                    self.assertEqual(c.phase,'unknown-retained')
                    self.assertEqual(k.host_nft,f.FACTS['nft'])
                finally: j.close()

    def test_actual_comment_and_parameter_drift_are_bound_not_discarded(self):
        raw = CAPTURE['raw']['ipv6']
        for old,new in [('c3-test-native-wave61-tcp3001','changed-comment'),
                        ('--dst-type LOCAL','--dst-type UNICAST')]:
            with self.subTest(operand=old),tempfile.TemporaryDirectory() as directory:
                k,c,j = self.wire(directory)
                with patch.dict(CAPTURE['raw'],ipv6=raw.replace(old,new)):
                    observed = k.node_compat_rules()
                    self.assertNotEqual(m.digest(m.encode(observed)),COMPAT_PIN)
                    self.assertIn(new,observed['ipv6'])
                    with self.assertRaisesRegex(m.Refusal,'COMPLETE_COMPAT_POLICY_DRIFT' if old.startswith('c3-') else 'UNSUPPORTED_IPV6_COMPAT_POLICY'):
                        k.install_node_control()
                self.assertEqual(k.writes,[])
                self.assertTrue(c.failed)
                self.assertEqual(k.host_nft,f.FACTS['nft'])


if __name__ == '__main__': unittest.main()
