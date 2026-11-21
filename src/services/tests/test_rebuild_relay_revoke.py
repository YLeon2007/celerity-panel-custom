"""No daemons/signals: model kernel observations and use synthetic pppd TDB state."""
import contextlib
import fcntl
import os
from pathlib import Path
import runpy
import signal
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HOST = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
BOOT = '01234567-89ab-cdef-0123-456789abcdef'
INVOCATION = 'd' * 32
CHAP = '/etc/ppp/chap-secrets'
MANIFEST = '/fixture/manifest'


def call(
    pid: int, peer: int = 10, *, subnet: str = '10.20.0',
) -> tuple[tuple[int, int, int, int], str, str, int, int, int, int, list[int]]:
    return (1, pid, 2, pid), f'{subnet}.1', f'{subnet}.{peer}', pid, 101, pid + 10, pid + 20, [1, pid, 2]


def tdb_bytes(records):
    # pppd 2.5.2's bundled tdb.c layout (not a dump from any running pppd).
    chains = [0] * 132
    body = bytearray()
    for key, value in records:
        full_hash = (1103515243 * (0x238F13AF * len(key) + sum(
            byte << (i * 5 % 24) for i, byte in enumerate(key))) + 12345) & 0xffffffff
        bucket = 1 + full_hash % 131
        offset = 696 + len(body)
        pad = bytes(-(len(key) + len(value)) % 4)
        n = len(key) + len(value) + len(pad) + 4
        body += struct.pack('<6I', chains[bucket], n, len(key), len(value), full_hash, 0x26011999)
        body += key + value + pad + struct.pack('<I', n + 24)
        chains[bucket] = offset
    return struct.pack('<32s34I132I', b'TDB file\n', 0x2601196d, 131, *([0] * 32), *chains) + body


def state(row, login, *, name=None, peer=None):
    _, local, live_peer, pid, *_ = row
    name = name or f'ppp{pid - 501}'
    key = f'pppd{pid}'.encode()
    aliases = [f'PPPD_PID={pid}', f'IFNAME={name}', f'UNIT={name[3:]}']
    env = ['ORIG_UID=0', 'PPPLOGNAME=root', *aliases, f'PEERNAME={login}',
           f'IPLOCAL={local}', f'IPREMOTE={peer or live_peer}']
    # pppd 2.5.2 update_db_entry stores semicolons between entries and a final NUL.
    return [(key, ';'.join(env).encode() + b'\x00'), *((a.encode(), key) for a in aliases)]


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
        self.home = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.db = self.home / 'pppd2.tdb'
        self.proc = self.home / 'proc'
        self.proc.mkdir()
        for row in self.rows:
            fds = self.proc / str(row[3]) / 'fd'
            fds.mkdir(parents=True)
            (fds / '8').symlink_to(self.db)
        self.logins = {501: 'alice', 502: 'bob', 503: 'alice'}
        self.command = Mock(return_value=b'')  # Rotated: no auth notices for target or neighbor.

    def records(self):
        # IPREMOTE is a single-valued alias in TDB even when shared by calls.
        aliases = {f'IPREMOTE={row[2]}'.encode(): f'pppd{row[3]}'.encode() for row in self.rows}
        return ([record for row in self.rows for record in state(row, self.logins[row[3]])]
                + list(aliases.items()))

    def write_db(self, data):
        self.db.write_bytes(data)
        self.db.chmod(0o644)

    def pid_stamp(self, name, pid):
        return next((row[7] for row in self.rows if row[3] == pid and name == f'ppp{pid - 501}'), None)

    @contextlib.contextmanager
    def directory(self, path):
        actual = {'/run': self.home, '/proc': self.proc}[path]
        fd = os.open(actual, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

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

    def drain(self, *, write_db=True):
        if write_db:
            self.write_db(tdb_bytes(self.records()))
        libsignal = SimpleNamespace(pidfd_send_signal=self.send, SIGTERM=signal.SIGTERM)
        db_identity = self.g['revoke_db_identity']
        def fixture_identity(st):
            return db_identity(SimpleNamespace(st_uid=0, st_mode=st.st_mode, st_nlink=st.st_nlink,
                                               st_dev=st.st_dev, st_ino=st.st_ino))
        with patch.dict(self.g, dict(signal=libsignal, select=SimpleNamespace(poll=self.poll, POLLIN=1),
                        revoke_ppp_view=self.view, directory=self.directory, command=self.command,
                        revoke_db_identity=fixture_identity,
                        session_pid_stamp=self.pid_stamp,
                        session_owner=lambda request: self.owner, remove_generation=lambda p: self.generation,
                        read=lambda p, *cap: self.read_chap if p == CHAP else 'manifest')):
            return self.g['revoke_ppp'](self.request, self.blocked, 'blocked', MANIFEST, 'manifest', self.xl)

    def test_native_nul_terminated_value_revokes_only_target(self):
        target = call(501, 11, subnet='10.255.191')
        neighbor = call(502, 12, subnet='10.255.191')
        self.rows = [target, neighbor]
        self.request['currentUsers'] = [
            {'login': 'alice', 'ipAddress': target[2]},
            {'login': 'bob', 'ipAddress': neighbor[2]},
        ]
        self.blocked = {'currentUsers': self.request['currentUsers'][1:]}
        # Pin the target's native bytes independently of the state() builder.
        key = b'pppd501'
        value = (b'ORIG_UID=0;PPPLOGNAME=root;PPPD_PID=501;IFNAME=ppp0;UNIT=0;'
                 b'PEERNAME=alice;IPLOCAL=10.255.191.1;IPREMOTE=10.255.191.11\x00')
        self.write_db(tdb_bytes([
            (key, value), (b'PPPD_PID=501', key), (b'IFNAME=ppp0', key), (b'UNIT=0', key),
            (b'IPREMOTE=10.255.191.11', key), *state(neighbor, 'bob'),
            (b'IPREMOTE=10.255.191.12', b'pppd502'),
        ]))
        self.assertEqual(self.drain(write_db=False), dict(sessionsTerminated=1, complete=True))
        self.assertEqual(self.sent, [501])
        self.assertEqual(self.rows, [neighbor])
        self.command.assert_not_called()

    def test_malformed_value_separators_refuse_without_signaling(self):
        target = call(501)
        self.rows = [target]
        (key, value), *aliases = self.records()
        for label, malformed in (
            ('missing NUL', value[:-1]),
            ('semicolon before NUL', value[:-1] + b';\x00'),
            ('double NUL', value + b'\x00'),
            ('NUL between fields', value.replace(b';IPREMOTE=', b'\x00IPREMOTE=')),
            ('semicolon instead of NUL', value[:-1] + b';'),
        ):
            with self.subTest(label=label):
                self.rows = [target]
                self.sent.clear()
                self.write_db(tdb_bytes([(key, malformed), *aliases]))
                self.assertEqual(self.drain(write_db=False), dict(sessionsTerminated=0, complete=False))
                self.assertEqual(self.sent, [])
                self.assertEqual(self.rows, [target])
        self.command.assert_not_called()

    def test_rotated_journal_for_target_and_neighbor_leaves_only_neighbor(self):
        self.assertEqual(self.drain(), dict(sessionsTerminated=2, complete=True))
        self.assertEqual(self.sent, [501, 503])
        self.assertEqual(self.rows, [call(502, 11)])
        self.command.assert_not_called()

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
            self.logins[501] = 'bob'
            self.write_db(tdb_bytes(self.records()))
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

    def test_conflicting_or_missing_identity_refuses_before_any_signal(self):
        alice, bob, second = self.rows
        good = self.records()
        for label, records in (
            ('missing neighbor', state(alice, 'alice')),
            ('stale login with reused address', state(alice, 'old-account') + good[4:]),
            ('neighbor login with target address', state(alice, 'bob') + good[4:]),
            ('target login with neighbor address', state(alice, 'alice') + state(bob, 'alice') + state(second, 'alice')),
            ('different negotiated address', state(alice, 'alice', peer='10.20.0.99') + good[4:]),
            ('different interface', state(alice, 'alice', name='ppp9') + good[4:]),
            ('ambiguous key', good + [state(alice, 'bob')[0]]),
            ('unescaped peer name', state(alice, 'alice;OTHER=value') + good[4:]),
            ('wrong pid alias', [good[0], (b'PPPD_PID=501', b'pppd502'), *good[2:]]),
        ):
            with self.subTest(label=label):
                self.write_db(tdb_bytes(records))
                self.assertEqual(self.drain(write_db=False), dict(sessionsTerminated=0, complete=False))
                self.assertEqual(self.sent, [])
        self.command.assert_not_called()

    def test_replaced_tdb_not_open_in_neighbor_refuses(self):
        old = self.home / 'old'
        old.mkdir()
        stale = old / self.db.name
        stale.write_bytes(tdb_bytes(self.records()))
        fd_link = self.proc / '502/fd/8'
        fd_link.unlink()
        fd_link.symlink_to(stale)
        self.assertEqual(self.drain(), dict(sessionsTerminated=0, complete=False))
        self.assertEqual(self.sent, [])

    def test_change_between_native_reads_refuses(self):
        samples = 0
        def observe():
            nonlocal samples
            samples += 1
            if samples == 3:
                self.write_db(tdb_bytes(self.records()[4:]))
            return 100, list(self.rows)
        self.sample_hook = observe
        self.assertEqual(self.drain(), dict(sessionsTerminated=0, complete=False))
        self.assertEqual(self.sent, [])

    def test_missing_or_malformed_db_and_empty_inventory(self):
        self.assertEqual(self.drain(write_db=False), dict(sessionsTerminated=0, complete=False))
        self.write_db(b'not a TDB')
        self.assertEqual(self.drain(write_db=False), dict(sessionsTerminated=0, complete=False))
        self.rows = []
        self.assertEqual(self.drain(write_db=False), dict(sessionsTerminated=0, complete=True))
        self.assertEqual(self.sent, [])

    def test_corrupt_chain_refuses_even_after_matching_record(self):
        data = bytearray(tdb_bytes(self.records()))
        # The first record is pppd501. A self-loop after it makes even a
        # matching lookup ambiguous; the reader must check past the match.
        struct.pack_into('<I', data, 696, 696)
        self.write_db(data)
        self.assertEqual(self.drain(write_db=False), dict(sessionsTerminated=0, complete=False))
        self.assertEqual(self.sent, [])

    @unittest.skipUnless(hasattr(fcntl, 'F_OFD_SETLK') and os.uname().machine == 'x86_64', 'Linux x86_64 locks required')
    def test_busy_native_chain_lock_does_not_authorize_signal(self):
        self.write_db(tdb_bytes(self.records()))
        # An OFD lock conflicts with POSIX locks even in the same test
        # process. Use the bundled TDB's first chain-lock byte (header size).
        with self.db.open('r+b') as writer:
            lock = struct.pack('@hhqqi4x', fcntl.F_WRLCK, os.SEEK_SET, 168, 1, 0)
            fcntl.fcntl(writer, fcntl.F_OFD_SETLK, lock)
            self.assertEqual(self.drain(write_db=False), dict(sessionsTerminated=0, complete=False))
            self.assertEqual(self.sent, [])
        self.assertEqual(self.drain(write_db=False), dict(sessionsTerminated=2, complete=True))


if __name__ == '__main__':
    unittest.main()
