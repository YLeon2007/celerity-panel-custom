"""Offline stroke status fixtures; no IKE, XFRM or service commands are run."""
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch


HOST = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
CONNECTION = b'Connections:\n  celerity-l2tp:  %any...%any  IKEv1\n  celerity-l2tp:   child:  dynamic[udp/l2f] === dynamic[udp] TRANSPORT\n'


def status(up, connecting, body):
    return CONNECTION + f'Security Associations ({up} up, {connecting} connecting):\n'.encode() + body


def ike(uid=1):
    return (f'  celerity-l2tp[{uid}]: ESTABLISHED 3 seconds ago, 192.0.2.1[192.0.2.1]...198.51.100.1[198.51.100.1]\n'
            f'  celerity-l2tp[{uid}]: IKEv1 SPIs: 88776655443322{uid:02x}_i 0011223344556677_r*\n'
            f'  celerity-l2tp[{uid}]: IKE proposal: AES_CBC_256/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_2048\n').encode()


def child(uid=1, state='INSTALLED', spi=1):
    return (f'  celerity-l2tp{{{uid}}}:  {state}, TRANSPORT, reqid 1, ESP in UDP SPIs: abcdef{spi:02x}_i fedcba{spi:02x}_o\n'
            f'  celerity-l2tp{{{uid}}}:  AES_CBC_256/HMAC_SHA1_96, 100 bytes_i, 0 bytes_o\n'
            f'  celerity-l2tp{{{uid}}}:   192.0.2.1/32[udp/l2f] === 198.51.100.1/32[udp/1701]\n').encode()


class IpsecCount(unittest.TestCase):
    def setUp(self):
        self.g = runpy.run_path(str(HOST))['main'].__globals__

    def test_counts_ike_connections_not_spis_children_or_peers(self):
        count = self.g['ipsec_status_inventory']
        self.assertEqual(len(count(status(0, 0, b'  none\n'))), 0)
        one = count(status(1, 0, ike() + child() + child(2, 'REKEYED', 2)))
        self.assertEqual(len(one), 1)
        self.assertEqual(one, count(status(1, 0, ike() + child() + child(2, 'REKEYED', 2))
                                    .replace(b'3 seconds', b'9 seconds').replace(b'100 bytes', b'120 bytes')))
        self.assertEqual(one, count(status(1, 0, ike() + child() + child(2, 'REKEYED', 3))))
        self.assertNotEqual(one, count(status(1, 0, ike(2) + child())))
        self.assertEqual(len(count(status(2, 0, ike() + child() + ike(2) + child(2, spi=2)))), 2)
        self.assertEqual(len(count(status(1, 0, ike()))), 1, 'established IKE without a CHILD still blocks Remove')

    def test_unknown_is_not_an_empty_inventory(self):
        count = self.g['ipsec_status_inventory']
        for data in (b'', status(1, 0, b''), status(0, 1, b'  celerity-l2tp[1]: CONNECTING\n'),
                     status(2, 0, ike() + child()), status(1, 0, ike() + child() + child()),
                     status(1, 0, child() + ike()), status(1, 0, ike() + child()).replace(b'TRANSPORT', b'TUNNEL'),
                     status(1, 0, ike().replace(b'celerity-l2tp', b'foreign')),
                     status(0, 0, b'  none\n').replace(b'Connections:\n', b'Connections:\n  foreign: x\n'),
                     status(0, 0, b'  none\nextra\n')):
            with self.subTest(data=data[:40]), self.assertRaises(self.g['Refusal']):
                count(data)

    def test_ipsec_drift_keeps_proved_ppp_but_invalidates_the_token(self):
        samples = iter([(0, 'idle'), (1, 'busy')])
        with patch.dict(self.g, {'ipsec_session_sample': lambda _: next(samples),
                                 'session_census': lambda _: {'activeSessions': 0, 'census': 'a' * 64}}):
            self.assertEqual(self.g['relay_session_census']({}),
                             {'activeSessions': 0, 'activeIpsec': None, 'census': None})


if __name__ == '__main__':
    unittest.main()