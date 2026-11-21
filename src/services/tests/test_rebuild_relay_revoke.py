"""No daemons/signals: model kernel/journal observations, run the real DIRECT decision code."""
import contextlib
import json
import os
from pathlib import Path
import runpy
import signal
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HOST = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
BOOT = '01234567-89ab-cdef-0123-456789abcdef'
INVOCATION = 'd' * 32
CHAP = '/etc/ppp/chap-secrets'
MANIFEST = '/fixture/manifest'


def call(pid: int, peer: int = 10) -> tuple[tuple[int, int, int, int], str, str, int, int, int, int, list[int]]:
    return (1, pid, 2, pid), '10.20.0.1', f'10.20.0.{peer}', pid, 101, pid + 10, pid + 20, [1, pid, 2]


class Revoke(unittest.TestCase):
    def setUp(self):
        self.g = runpy.run_path(str(HOST))['main'].__globals__
        self.owner = (BOOT, INVOCATION, 500, (), 'manifest', {}, {}, ())
        self.request = {'revokedLogin': 'alice', 'currentUsers': [
            {'login': 'alice', 'ipAddress': '10.20.0.10'}, {'login': 'bob', 'ipAddress': '10.20.0.11'}]}
        self.blocked = {'currentUsers': self.request['currentUsers'][1:]}
        self.xl = dict(InvocationID=INVOCATION, MainPID='500', ActiveState='active', SubState='running')
        self.rows = [call(501), call(502, 11), call(503)]
        self.sent = []
        self.round = 0
        self.polled = -1
        self.sample_hook = lambda: (100, list(self.rows))
        self.send_hook = lambda _: None
        self.wait = True
        self.remove_on_exit = True
        self.generation = 123
        self.read_chap = 'blocked'

    @contextlib.contextmanager
    def view(self, owner):
        self.assertEqual(owner, self.owner)
        self.round += 1
        yield self.sample_hook, lambda pid: pid + 1000, lambda: None

    def send(self, fd, signo):
        self.assertEqual(signo, signal.SIGTERM)
        self.assertEqual(self.read_chap, 'blocked')
        self.send_hook(fd)
        pid = fd - 1000
        self.assertIn(pid, [501, 503])
        self.sent.append(pid)
        if self.remove_on_exit:
            self.rows = [row for row in self.rows if row[3] != pid]

    def poll(self):
        return SimpleNamespace(register=lambda fd, flags: setattr(self, 'polled', fd),
                               poll=lambda ms: [(self.polled, 1)] if self.wait else [])

    def drain(self, **seams):
        libsignal = SimpleNamespace(pidfd_send_signal=self.send, SIGTERM=signal.SIGTERM)
        with patch.dict(self.g, dict(signal=libsignal, select=SimpleNamespace(poll=self.poll, POLLIN=1),
                        revoke_ppp_view=self.view, revoke_peer_logins=lambda rows, owner, users:
                        {row[3]: 'alice' if row[2].endswith('.10') else 'bob' for row in rows},
                        session_owner=lambda request: self.owner, remove_generation=lambda p: self.generation,
                        read=lambda p, *cap: self.read_chap if p == CHAP else 'manifest',
                        **seams)):
            return self.g['revoke_ppp'](self.request, self.blocked, 'blocked', MANIFEST, 'manifest', self.xl)

    def test_two_calls_of_one_account_leave_other_account_connected(self):
        self.assertEqual(self.drain(), dict(sessionsTerminated=2, complete=True))
        self.assertEqual(self.sent, [501, 503])
        self.assertEqual(self.rows, [call(502, 11)])

    def test_zero_only_after_stable_complete_inventory(self):
        self.rows = [call(502, 11)]
        self.assertEqual(self.drain(), dict(sessionsTerminated=0, complete=True))
        self.assertEqual(self.sent, [])

    def test_reuse_after_sample_never_signals_new_pid(self):
        def natural_exit(fd):
            self.assertEqual(fd, 1501)
            self.send_hook = lambda _: None
            # Original pidfd is dead; numeric PID has been reused by another user.
            self.rows[0] = call(501, 11)
            raise ProcessLookupError
        self.send_hook = natural_exit
        self.assertEqual(self.drain(), dict(sessionsTerminated=1, complete=True))
        self.assertEqual(self.sent, [503])
        self.assertIn(call(501, 11), self.rows)

    def test_missing_readback_and_late_unjoined_process_are_not_success(self):
        self.wait = False
        self.remove_on_exit = False
        self.assertEqual(self.drain(), dict(sessionsTerminated=0, complete=False))
        self.assertEqual(self.sent, [501])
        self.sent.clear()
        self.wait = True
        self.remove_on_exit = True
        samples = 0
        def observe():
            nonlocal samples
            samples += 1
            if samples == 6:
                raise self.g['Refusal']('late handshake has no IPCP address yet')
            return 100, list(self.rows)
        self.sample_hook = observe
        self.assertEqual(self.drain(), dict(sessionsTerminated=1, complete=False))
        self.assertEqual(self.sent, [501])

    def test_exit_without_kernel_call_disappearance_is_not_counted(self):
        self.remove_on_exit = False
        self.assertEqual(self.drain(), dict(sessionsTerminated=0, complete=False))
        self.assertEqual(self.sent, [501])

    def test_same_bytes_chap_generation_change_refuses_before_signal(self):
        def observe():
            self.generation += 1
            return 100, list(self.rows)
        self.sample_hook = observe
        self.assertEqual(self.drain(), dict(sessionsTerminated=0, complete=False))
        self.assertEqual(self.sent, [])

    def test_journal_uses_authenticated_login_and_rejects_stale_or_forged_notice(self):
        keys = dict(_BOOT_ID=BOOT.replace('-', ''), _SYSTEMD_INVOCATION_ID=INVOCATION,
                    _SYSTEMD_UNIT='xl2tpd.service', _SYSTEMD_CGROUP='/system.slice/xl2tpd.service',
                    _UID='0', _EXE='/usr/sbin/pppd', _TRANSPORT='syslog', PRIORITY='5')
        now_ns = 5_000_000_000
        epoch_ns = 1_700_000_000_000_000_000
        clock = SimpleNamespace(CLOCK_BOOTTIME=7, time_ns=lambda: now_ns + epoch_ns,
                                clock_gettime_ns=lambda _: now_ns)

        def event(pid, login, **kw):
            return {**keys, '_PID': str(pid), 'MESSAGE': f'Peer {login} authenticated with CHAP',
                    '__MONOTONIC_TIMESTAMP': '2000000', '_SOURCE_REALTIME_TIMESTAMP': str(epoch_ns // 1000 + 2_000_000), **kw}

        rows = [call(501), call(502, 11)]
        users = {u['login']: u['ipAddress'] for u in self.request['currentUsers']}
        good = [event(501, 'alice'), event(502, 'bob')]
        command = Mock()
        with patch.dict(self.g, dict(time=clock, os=SimpleNamespace(sysconf=lambda _: 100), command=command)):
            def observe(events):
                command.return_value = b''.join(json.dumps(e).encode() + b'\n' for e in events)
                return self.g['revoke_peer_logins'](rows, self.owner, users)
            self.assertEqual(observe(good), {501: 'alice', 502: 'bob'})
            call_args = command.call_args.args
            self.assertEqual(call_args[0], '/usr/bin/journalctl')
            self.assertTrue(set(k + '=' + v for k, v in keys.items()) <= set(call_args))
            self.assertEqual(call_args[-2:], ('_PID=501', '_PID=502'))
            for invalid in [good[:1], [event(501, 'alice', __MONOTONIC_TIMESTAMP='1010000'), good[1]],
                            [event(501, 'alice', _SOURCE_REALTIME_TIMESTAMP=str(epoch_ns // 1000)), good[1]],
                            [event(501, 'alice', _SYSTEMD_INVOCATION_ID='e'*32), good[1]],
                            [event(501, 'old-account-that-used-this-ip'), good[1]],
                            [event(501, 'bob'), good[1]], [*good, event(501, 'bob')]]:
                with self.subTest(fields=len(invalid)), self.assertRaises(self.g['Refusal']):
                    observe(invalid)


if __name__ == '__main__':
    unittest.main()
