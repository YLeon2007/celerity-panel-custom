"""Socket-free DIRECT producer/consumer boundary; no service actions."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_rebuild_relay_ipsec_count import child, ike, status

HOST = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'


class RetirementCensusBoundary(unittest.TestCase):
    def setUp(self):
        self.host = runpy.run_path(str(HOST))['main'].__globals__

    def test_live_ipsec_census_does_not_authenticate_child_or_kernel_ownership(self):
        h = self.host
        observed = []
        with_child = status(1, 0, ike() + child())
        without_child = status(1, 0, ike())
        runtime = {'files': {'ike': 'file', 'starter': 'file'}, 'invocations': ['', '', 'current']}
        unit = {'ActiveState': 'active', 'SubState': 'running', 'InvocationID': 'current', 'MainPID': '23'}
        observations = [(with_child, b'owned-xfrm'), (without_child, b'no-corresponding-child')]

        def command(*argv, **_):
            observed.append(argv)
            if argv == ('/usr/sbin/ipsec', 'statusall'):
                return current[0]
            if argv == ('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys'):
                return current[1]
            raise AssertionError('unexpected host command')

        backup = {'runtime': runtime, 'after': {'ike': 'record', 'starter': 'record'}}
        mocks = dict(require_census_machine=lambda _: None, owned_installation=lambda _: ('manifest', 'record', backup, ''),
                     runtime_before=lambda _: {'boot': 'boot'}, remove_generation=lambda _: 'file',
                     read=lambda *_: 'record', after_match=lambda *_: True, ike_include_matches=lambda *_: True,
                     check_swan_profile=lambda *_: None, no_jobs=lambda *_: None, unit=lambda _: unit,
                     rollback_quiescent=lambda _: False, removal_native=lambda *_, **__: True, working=lambda _: True,
                     sock_rows=lambda: [('udp', '192.0.2.1', port, ['23']) for port in (500, 4500)],
                     in_cgroup=lambda *_: True, command=command, raw=lambda _: b'manifest',
                     session_census=lambda _: {'activeSessions': 1, 'census': 'a' * 64})
        receipts = []
        # Keep the PPP generation and the parent IKEv1 IDs/SPIs stable. A PPP
        # call still in the census may have lost its CHILD, so 1+1 is neither
        # proof of two separate clients nor proof that these are the same one.
        with patch.dict(h, mocks):
            for current in observations:
                receipts.append(h['relay_session_census']({'machineId': 'b' * 32}))
        self.assertEqual(receipts[0], receipts[1])
        self.assertEqual([receipts[0][key] for key in ('activeSessions', 'activeIpsec')], [1, 1])
        self.assertEqual(observed, [('/usr/sbin/ipsec', 'statusall')] * 4)

    def test_existing_remove_rechecks_under_flock_before_intent_and_preserves_unknown(self):
        h = self.host
        request = dict(action='remove', machineId='b' * 32, nodeId='a' * 24, backupId='c' * 32,
                       baseline='d' * 64, expectedCensus='e' * 64,
                       network=dict(clientCidr='10.5.0.0/24', tproxyPort=12345, fwmark=25, routeTable=125))
        state = dict(baseline=request['baseline'], before={}, current={}, profiles={}, units={h['XL']: {}},
                     policy={}, reserved=set(), sockets=[], boot_enrollment=None, ike_sockets=[], chap_backup={},
                     chap_expected={}, chap_digest='chap', intent='intent')
        with tempfile.TemporaryDirectory() as root:
            @contextlib.contextmanager
            def fixture_directory(path):
                self.assertEqual(path, root)
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    yield fd
                finally:
                    os.close(fd)

            for ppp, ipsec, proof, expected_code, expected_error, intents in [
                (1, 1, request['expectedCensus'], 70, 'DIRECT_REMOVE_IPSEC_BUSY\n', []),
                (1, 0, request['expectedCensus'], 70, 'DIRECT_REMOVE_REFUSED\n', []),
                (0, 0, '0' * 64, 70, 'DIRECT_REMOVE_REFUSED\n', []),
                (None, 0, None, 70, 'DIRECT_REMOVE_REFUSED\n', []),
                (0, 0, request['expectedCensus'], 75, '', ['intent']),
            ]:
                with self.subTest(ppp=ppp, ipsec=ipsec, proof=proof):
                    writes, checked = [], []

                    def check_lock():
                        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                        try:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        finally:
                            os.close(fd)

                    def census(*args):
                        check_lock()
                        checked.append(True)
                        return {'activeSessions': ppp, 'activeIpsec': ipsec, 'census': proof}

                    def write(path, *_):
                        check_lock()
                        writes.append(path)
                        # The first destructive boundary was entered; model a
                        # failure without performing the write or any stop.
                        raise h['Refusal']('RUNTIME_UNPROVED')

                    out, stderr = io.StringIO(), io.StringIO()
                    mocks = dict(SYSTEM=root, directory=fixture_directory, REMOVE_ENTERED=False,
                                 preflight=lambda _: {}, require_machine=lambda _: None,
                                 observe_removal=lambda _: state, no_jobs=lambda _: None, rollback_quiescent=lambda _: False,
                                 read=lambda _: {}, remove_chap=lambda *_: ({}, 'chap'), relay_session_census=census,
                                 sock_rows=list, removal_idle=lambda *_: None, write=write)
                    with patch.dict(h, mocks), patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()))), \
                            patch.object(h['os'], 'geteuid', return_value=0), contextlib.redirect_stdout(out), contextlib.redirect_stderr(stderr):
                        self.assertEqual(h['main'](), expected_code)
                    self.assertEqual(out.getvalue(), '')
                    self.assertEqual(stderr.getvalue(), expected_error)
                    self.assertEqual(writes, intents)
                    self.assertEqual(checked, [True])


if __name__ == '__main__':
    unittest.main()
