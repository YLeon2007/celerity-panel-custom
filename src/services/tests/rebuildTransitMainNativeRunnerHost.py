"""Exercise native adapter admission without running a real service manager."""
import functools
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rebuildTransitMainHost as host
from rebuildTransitMainRuntime import MainRuntimeObserver
from rebuildTransitMainSession import AUTHORITY, START, STOP, RESTART, HostMainFlock
from rebuildTransitMainWindow import PROPERTIES, UNIT, XRAY, XRAY_PROPS, WindowError


class NativeRunnerHost(unittest.TestCase):
    def test_exact_commands_join_a_child_with_bounded_pipes(self):
        launch = host._exchange
        seen = []
        unit_show = ['/usr/bin/systemctl', 'show', '--all', *('--property=' + p for p in PROPERTIES), '--', UNIT]
        xray_show = ['/usr/bin/systemctl', 'show', '--all', *('--property=' + p for p in XRAY_PROPS), '--', XRAY]
        journal = ['/usr/bin/journalctl', '--quiet', '--no-pager', '--output=cat', '--lines=128',
                   '_SYSTEMD_UNIT=cc-agent.service', '_SYSTEMD_INVOCATION_ID=' + 'a' * 32]

        def exchange(args, data, *, timeout, limit, end):
            seen.append((args, timeout, limit))
            self.assertEqual(data, b'')
            self.assertEqual(end, deadline)
            body = 'import sys; assert sys.stdin.read() == ""' + ("; print('fixture')" if limit else '')
            return launch(('/usr/bin/python3', '-IB', '-c', body), data, timeout=timeout, limit=limit, end=end)

        with patch.object(host, '_exchange', side_effect=exchange):
            deadline = time.monotonic() + 5
            for argv, budget, result in ((unit_show, 4, 'fixture\n'), (STOP, 25, ''), (xray_show, 4, 'fixture\n'),
                                         (journal, 4, 'fixture\n'), (RESTART, 25, ''), (START, 15, '')):
                self.assertEqual(host._run(deadline, argv, budget), result)
        self.assertEqual([row[0] for row in seen], [tuple(unit_show), STOP, tuple(xray_show), tuple(journal), RESTART, START])
        self.assertEqual([row[2] for row in seen], [16384, 0, 16384, 65536, 0, 0])
        self.assertTrue(all(0 < row[1] <= 5 for row in seen))

    def test_bad_command_expiry_and_late_success_are_not_retryable(self):
        with patch.object(host, '_exchange') as exchange, patch.object(host.time, 'monotonic', return_value=10):
            for argv, budget in ((('/usr/bin/systemctl', 'stop', '--job-mode=replace', '--', UNIT), 25),
                                 (('/usr/bin/systemctl', 'restart', '--job-mode=fail', '--', 'xray-bridge.service'), 25),
                                 (host._JOURNAL + ('_SYSTEMD_INVOCATION_ID=' + 'a' * 32 + '\n',), 4),
                                 (STOP, 26), (STOP, True)):
                with self.assertRaises(WindowError) as err:
                    host._run(11, argv, budget)
                self.assertEqual(err.exception.code, AUTHORITY)
            with self.assertRaisesRegex(subprocess.SubprocessError, '^REBUILD_MAIN_NATIVE_UNCONFIRMED$'):
                host._run(10, STOP, 25)
            exchange.assert_not_called()
        with patch.object(host.time, 'monotonic', side_effect=(10, 11)), patch.object(host, '_exchange', return_value=b'') as exchange:
            with self.assertRaisesRegex(subprocess.SubprocessError, '^REBUILD_MAIN_NATIVE_UNCONFIRMED$'):
                host._run(11, STOP, 25)
            exchange.assert_called_once_with(STOP, b'', timeout=1, limit=0, end=11)

    def test_factory_borrows_original_flock_and_rechecks_deadline_after_authority(self):
        options = dict(managed={'vless-in'}, routes_for=lambda *_: (), verify_manager_scope=lambda end: False)
        with tempfile.TemporaryDirectory() as tmp, HostMainFlock(Path(tmp)) as flock:
            with patch.object(host, '_exchange') as exchange:
                finish = time.monotonic() + 15
                make = functools.partial(host.create_main_session, finish, flock, **options)
                with self.assertRaises(WindowError):
                    make(verify_authority=lambda: True)
                with patch.object(host, 'DIRECT_LOCK', flock.path):
                    with make(verify_authority=lambda: True) as session:
                        self.assertEqual(session._fd, flock._fd)
                        self.assertIsInstance(session._runtime, MainRuntimeObserver)
                        self.assertEqual(session._runtime._deadline, finish)
                        with self.assertRaises(WindowError) as err:
                            session._runner(RESTART, 25)
                        self.assertEqual(err.exception.code, AUTHORITY)
                    session = make(verify_authority=lambda: True)
                    with patch.object(session, '_clock', side_effect=(finish - 1, finish)):
                        with self.assertRaises(WindowError) as err:
                            with session:
                                self.fail('late authority admitted')
                        self.assertEqual(err.exception.code, AUTHORITY)
                exchange.assert_not_called()
                flock.check()


if __name__ == '__main__':
    unittest.main()
