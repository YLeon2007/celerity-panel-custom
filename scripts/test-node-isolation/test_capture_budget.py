"""Capture-stage budget composition; original owner/clock explicitly MODELED.

No config value or caller timestamp is a ROOT lease. Native owner/guard checks
remain necessary; this fixture exercises the existing finite owner's budget.
"""
import copy
import os
import socket
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import coordinated_capture as capture
import coordinated_restore as protocol
from fresh_network_invocation import Invocation
from capture_fixture import CaptureFixture


class ModeledOriginalOwner:
    """Private clock/owner fixture, NOT physical authority or a lease issuer.

    Exercise the unchanged Invocation.budget method without spawning its holder.
    Selection is the trusted external caller's obligation, not config validation.
    """
    def __init__(self, now):
        self.now = now
        self.owner = Invocation.__new__(Invocation)
        self.owner.end = now[0] + 590
        self.owner.p = {'deadline': now[0] + 590}
        self.owner.cancelled = False
        self.owner.m = SimpleNamespace(need=capture.need)

    def select(self, config, seconds):
        capture.need(type(seconds) is int and 80 <= seconds <= 600)
        capture.need(seconds <= self.owner.budget(), 'CAPTURE_EXCEEDS_ORIGINAL_REMAINING')
        selected = copy.deepcopy(config)
        selected['lifetimeSeconds'] = seconds
        return capture.validate(selected)


class CaptureBudgetTests(unittest.TestCase):
    def test_preselected_300_second_capture_config_is_valid(self):
        with CaptureFixture() as f:
            f.config['lifetimeSeconds'] = 300
            self.assertIs(capture.validate(f.config), f.config)


    def test_legacy_boundaries_and_absolute_max_keep_strict_integer_codec(self):
        with CaptureFixture() as f:
            self.assertEqual(f.config['lifetimeSeconds'], 120)
            for seconds in (80, 100, 120, 121, 300, 600):
                with self.subTest(seconds=seconds):
                    f.config['lifetimeSeconds'] = seconds
                    capture.validate(f.config)
            for seconds in (None, True, False, 80.0, 120.0, 300.0, '300', 79, 0, -1, 601, [], {}):
                with self.subTest(seconds=seconds), self.assertRaises(capture.Refusal):
                    f.config['lifetimeSeconds'] = seconds
                    capture.validate(f.config)

    def test_external_selection_is_bounded_by_original_remaining_not_a_new_lease(self):
        now = [1000.0]
        with CaptureFixture() as f, patch('time.monotonic', side_effect=lambda: now[0]), \
                patch('time.time', side_effect=lambda: now[0]):
            fixture = ModeledOriginalOwner(now)
            original_end = fixture.owner.end
            selected = fixture.select(f.config, 300)
            self.assertEqual(selected['lifetimeSeconds'], 300)
            for seconds in (600, 601, True, 300.0):
                with self.subTest(seconds=seconds), self.assertRaises(capture.Refusal):
                    fixture.select(f.config, seconds)
            now[0] = original_end - 79
            with self.assertRaisesRegex(capture.Refusal, 'CAPTURE_EXCEEDS_ORIGINAL_REMAINING'):
                fixture.select(f.config, 80)
            # A reconnect/restarted child could locally compute a fresh 300s,
            # but the original owner must refuse it. No actual stage is resumed.
            hypothetical_child_end = now[0] + selected['lifetimeSeconds']
            now[0] = original_end
            self.assertGreater(hypothetical_child_end, now[0])
            with self.assertRaisesRegex(capture.Refusal, 'FINITE_INVOCATION_EXPIRED'):
                fixture.owner.budget(hypothetical_child_end)
            with self.assertRaisesRegex(capture.Refusal, 'FINITE_INVOCATION_EXPIRED'):
                fixture.select(f.config, 300)
            self.assertEqual(fixture.owner.end, original_end)
            self.assertEqual(f.config['lifetimeSeconds'], 120)

    def test_coordinator_checks_and_new_channels_do_not_renew_stage_end(self):
        now = [1000.0]
        with CaptureFixture() as f, patch('time.monotonic', side_effect=lambda: now[0]):
            f.config['lifetimeSeconds'] = 300
            f.put(capture.CONFIG, capture.canonical(f.config))
            coordinator = capture.Coordinator(f.config, f.fs, None, protocol, origin=f.origin)
            coordinator.active, coordinator.intent = True, {'modeledProtocolState': True}
            f.put(capture.INTENT, capture.canonical(coordinator.intent))
            original_end = coordinator.deadline
            for elapsed in (0, 121, 299):
                now[0] = 1000 + elapsed
                coordinator.live()
                process = SimpleNamespace(stdout=SimpleNamespace(fileno=lambda: 0),
                                          stdin=SimpleNamespace(fileno=lambda: 1))
                # Every downstream Channel gets the SAME constructor-fixed end.
                channel = capture.Channel(process, 'fixture', {}, 'n', f.origin,
                                          coordinator.deadline, protocol)
                self.assertEqual(channel.wire.deadline, original_end)
                self.assertEqual(coordinator.deadline, 1300)
            now[0] = original_end
            with self.assertRaisesRegex(capture.Refusal, 'CAPTURE_CAPABILITY_REVOKED'):
                coordinator.check()
            self.assertFalse(coordinator.active)
            self.assertEqual(coordinator.deadline, original_end)

    def test_real_uds_client_accepts_selected_budget_and_never_renews_on_check(self):
        # Synthetic protocol state, real UDS/peer credentials/Wire. No owner rows
        # or public-enrollment/physical claims are derived from this small seam.
        now = [1000.0]
        with CaptureFixture() as f:
            f.config['lifetimeSeconds'] = 300
            intent = {'phase': 'captured-held', 'inFlightNode': None,
                      'capturedNodes': list(f.config['nodes']),
                      'configSha256': capture.sha(capture.canonical(f.config)), 'origin': f.origin}
            f.put(capture.CONFIG, capture.canonical(f.config))
            f.put(capture.INTENT, capture.canonical(intent))
            errors = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(f.socket)); listener.listen(1)
                def serve():
                    try:
                        with listener.accept()[0] as conn:
                            wire = capture.Wire(conn.fileno(), conn.fileno(), 2000)
                            wire.send({'version': 1, 'op': 'owner-challenge', 'nonce': 'a'*64,
                                       'peer': {'pid': os.getpid(), 'start': protocol.proc_start(os.getpid())}})
                            for nonce in ('b'*64, 'c'*64):
                                frame = wire.receive()
                                wire.send({**frame, 'op': 'capture-held',
                                           'nodeCount': len(f.config['nodes']),
                                           'handbackAllowed': False, 'nextNonce': nonce})
                            self.assertEqual(conn.recv(1), b'')
                    except BaseException as error:
                        errors.append(error)
                with patch('time.monotonic', side_effect=lambda: now[0]):
                    thread = threading.Thread(target=serve)
                    thread.start()
                    client = capture.CaptureChannel(f.fs, protocol, fixture_socket=f.socket)
                    try:
                        client.__enter__()
                        self.assertEqual(client.wire.deadline, 1300)
                        now[0] = 1121
                        client.check()
                        self.assertEqual(client.wire.deadline, 1300)
                        now[0] = 1300
                        with self.assertRaisesRegex(capture.Refusal, 'CHANNEL_TIMEOUT_RETAINED'):
                            client.check()
                        self.assertFalse(client.active)
                        self.assertEqual(client.wire.deadline, 1300)
                    finally:
                        client.close()
                        thread.join(timeout=3)
                    self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
