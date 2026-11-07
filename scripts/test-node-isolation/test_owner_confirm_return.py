"""Real ancestry/flock/SCM_RIGHTS/masks; modeled root, SSH auth and systemd only.

Every child is bounded and reaped. Set C3_CONFIRM_EVIDENCE to a fresh directory
for persistent receipts; disposable fixtures always live in approved TMPDIR.
"""
import array
import contextlib
import copy
import ctypes
import fcntl
import json
import os
from pathlib import Path
import pwd
import select
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_v2_abort_return as fixture
m = fixture.m
FILE = str(Path(__file__).resolve())


def put(path, value):
    m.atomic_json(Path(path).parent, Path(path).name, value)


def doc(path):
    return json.loads(Path(path).read_bytes())


def ident(pid):
    return {k: m.proc_identity(pid)[k] for k in ('pid', 'start')}


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def held(root):
    fd = os.open(Path(root) / 'lock', os.O_RDONLY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def effects(root):
    return doc(Path(root) / 'effects.json')


@contextlib.contextmanager
def boundaries(root):
    root = Path(root)
    class LocalHost(fixture.Host):
        operator_session = m.Host.operator_session
        boot_ticks = m.Host.boot_ticks

        def unit(self, name):
            if name == m.MAINT_UNIT:
                return {'MainPID': str(doc(root / 'manager.json')['pid'])}
            return doc(root / 'current.json')[name]

        def inventory(self):
            return {'processes': [], 'units': {}, 'unitFilePins': {}, 'jobsPresent': False}

        def guard_check(self, *args):
            # Only guard authentication is modeled; actual manager lifetime/start.
            assert ident(doc(root / 'manager.json')['pid']) == doc(root / 'manager.json')
            m.need(not (root / 'guard-lost').exists(), 'RECOVERY_GUARD_LOST')

        def check_prerequisites(self, p):
            self.guard_check(None)

        def run(self, argv):
            assert argv[0] == '/usr/bin/systemctl'
            values = effects(root)
            values.append(argv[1:])
            put(root / 'effects.json', values)
            if argv[1] == 'daemon-reload':
                return ''
            assert argv[1] in ('stop', 'start')
            name = argv[-1]
            states = doc(root / 'current.json')
            if argv[1] == 'start':
                states[name] = doc(root / 'original.json')[name]
            elif states[name]['ActiveState'] not in ('inactive', 'failed'):
                states[name].update(ActiveState='inactive', SubState='dead')
            put(root / 'current.json', states)
            if argv[1] == 'start' and (root / 'start-ack-lost').exists():
                raise OSError('MODELED start acknowledgement lost after effect')
            return ''

        def reload(self):
            return m.Host.reload(self)

        def stop(self, name):
            return m.Host.stop(self, name)

        def assert_stopped(self, name, group):
            m.need(self.unit(name)['ActiveState'] in ('inactive', 'failed'), 'WRITER_NOT_STOPPED')

    lookup = pwd.getpwnam
    root_os = types.SimpleNamespace(**vars(os))
    root_os.geteuid = lambda: 0
    with fixture.accepted_files(), patch.object(m, 'os', root_os), \
         patch.object(m, 'MASK_ROOT', str(root / 'masks')), \
         patch.object(m, 'RUNNER_FENCES', str(root / 'fences')), \
         patch.dict(os.environ, {'SUDO_USER': m.OPERATOR, 'SUDO_UID': str(os.getuid())}), \
         patch.object(pwd, 'getpwnam', lambda name: types.SimpleNamespace(pw_uid=os.getuid()) if name == m.OPERATOR else lookup(name)):
        host = LocalHost(fixture.plan())
        yield m.Engine(root, fixture.plan(), host), host


def snapshot(root, engine):
    return {'journal': engine.read(), 'masks': {n: engine.host.snapshot_mask(n) for n in engine.plan['isolateUnits']},
            'states': doc(Path(root) / 'current.json'), 'effects': effects(root), 'held': held(root)}


def refusal(work, code):
    try:
        work()
    except m.Refusal as error:
        assert code in str(error), (code, str(error))
        return str(error)
    raise AssertionError('expected refusal: ' + code)


def owner(root, fd, case):
    root = Path(root)
    channel = socket.socket(fileno=fd)
    lock = os.open(root / 'lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with boundaries(root) as (engine, host):
        engine._outer_lock_fd = lock  # Existing borrowed-lock contract, not _early mutation.
        try:
            assert engine.apply({'fixture': 'independent recovery authorization'})['phase'] == 'awaiting-fresh-login'
            initial = engine.read()
            before = snapshot(root, engine)
            refusal(engine.confirm_access, 'POST_DRAIN_FRESH_LOGIN_REQUIRED')
            assert snapshot(root, engine) == before
            # The fallback preserves a causal RED at abort_return on the exact
            # old source, not an AttributeError for the new optional seam.
            method = getattr(engine, 'fresh_confirmation', None)
            scope = method(lock) if method else contextlib.nullcontext(None)
            try:
                with scope as confirmation_fd:
                    descriptors = [lock] + ([] if confirmation_fd is None or case == 'no-channel' else [confirmation_fd])
                    channel.sendmsg([b'confirmation'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', descriptors))])
                    emit({'stage': 'applied', 'owner': ident(os.getpid()), 'session': host.operator_session(),
                          'boundary': initial['accessBoundary'], 'handoff': confirmation_fd is not None})
                    assert sys.stdin.buffer.readline() == b'return\n'
                    assert engine.read()['phase'] == 'held'
                    if case == 'pre-drift':
                        changed = engine.read()
                        changed['guard'] = {'fixture': 'foreign confirmation context'}
                        engine.save(changed)
            except (m.Refusal, OSError) as error:
                assert case in ('no-channel', 'stale', 'unrelated', 'pre-drift'), str(error)
                before = snapshot(root, engine)
                refusal(lambda: engine.abort_return(lock), 'LIVE_OWNER_REQUIRED')
                assert snapshot(root, engine) == before
                assert all(e[0] != 'start' for e in effects(root))
                assert all(host.snapshot_mask(n)['target'] == '/dev/null' for n in engine.plan['isolateUnits'])
                emit({'stage': 'refused', 'case': case, 'oneShot': True, 'code': str(error)})
                return
            # Scope exit authenticates the live confirmer, ACKs and reconciles
            # only its exact transition. No caller touches _early or journal.
            emit({'stage': 'accepted'})
            assert sys.stdin.buffer.readline() == b'confirmer-reaped\n'
            before = snapshot(root, engine)
            if case == 'new-engine':
                refusal(lambda: m.Engine(root, engine.plan, host).abort_return(lock), 'LIVE_OWNER_REQUIRED')
                assert snapshot(root, engine) == before
            if case == 'wrong-lock':
                wrong = os.open(root / 'lock', os.O_RDWR | os.O_NOFOLLOW)
                try:
                    try:
                        engine.abort_return(wrong)
                    except (m.Refusal, BlockingIOError):
                        pass
                    else:
                        raise AssertionError('foreign OFD accepted')
                finally:
                    os.close(wrong)
                refusal(lambda: engine.abort_return(lock), 'LIVE_OWNER_REQUIRED')
                assert snapshot(root, engine) == before
                emit({'stage': 'refused', 'case': case, 'oneShot': True})
                return
            if case in ('drift', 'dispatch', 'inflight'):
                state = engine.read()
                if case == 'drift': state['guard'] = {'fixture': 'unrelated guard'}
                elif case == 'dispatch': state['dispatchCount'] = 1
                else: state['dispatchInFlight'] = {'unknown': True}
                engine.save(state)  # Adversarial drift, never success setup.
            if case == 'capture': (root / 'originals').mkdir()
            if case == 'commit': (root / 'handoff-commit.json.next').write_text('{}')
            if case == 'guard': (root / 'guard-lost').touch()
            if case == 'unknown-start': (root / 'start-ack-lost').touch()
            if case not in ('positive', 'new-engine', 'unknown-start', 'success-only'):
                before = snapshot(root, engine)
                refusal(lambda: engine.abort_return(lock), 'RETAINED' if case in ('capture', 'commit') else 'RECOVERY_GUARD_LOST' if case == 'guard' else 'LIVE_OWNER_REQUIRED')
                assert snapshot(root, engine) == before
                refusal(lambda: engine.abort_return(lock), 'LIVE_OWNER_REQUIRED')
                emit({'stage': 'refused', 'case': case, 'oneShot': True})
                return
            if case == 'success-only':
                assert engine.assert_held()['phase'] == 'held'
                assert snapshot(root, engine) == before
                emit({'stage': 'held', 'owner': ident(os.getpid()), 'held': held(root)})
                return
            if case == 'unknown-start':
                try:
                    engine.abort_return(lock)
                except m.EarlyReturnUnknown:
                    pass
                else:
                    raise AssertionError('unknown start became OLD')
                assert engine.read()['phase'] == 'early-return-unknown'
                before = snapshot(root, engine)
                refusal(lambda: engine.abort_return(lock), 'LIVE_OWNER_REQUIRED')
                assert snapshot(root, engine) == before
                emit({'stage': 'unknown', 'case': case, 'oneShot': True})
                return
            result = engine.abort_return(lock)
            assert result['returnState'] == 'OLD'
            assert engine.read()['phase'] == 'early-returned'
            assert doc(root / 'current.json') == doc(root / 'original.json')
            for name, saved in initial['saved'].items():
                assert host.snapshot_mask(name) == saved['mask']
            before = snapshot(root, engine)
            refusal(lambda: engine.abort_return(lock), 'LIVE_OWNER_REQUIRED')
            assert snapshot(root, engine) == before
            emit({'stage': 'OLD', 'owner': ident(os.getpid()), 'result': result, 'held': held(root), 'oneShot': True})
        finally:
            os.close(lock)
            channel.close()


def confirmer(root, lock, confirmation, case):
    try:
        with boundaries(root) as (engine, host):
            session = host.operator_session()
            waiting = engine.read()
            assert int(session['start']) > int(waiting['accessBoundary']['ticks'])
            engine.require_early_lock(lock)
            if confirmation is None:
                result = engine.confirm_access()
            else:
                sendall = socket.socket.sendall
                def altered(conn, raw, *args):
                    if len(raw) == 32:
                        raw = bytes.fromhex(m.digest(json.dumps(waiting, sort_keys=True, separators=(',', ':')).encode())) if case == 'stale' else b'x' * 32
                    return sendall(conn, raw, *args)
                with patch.object(socket.socket, 'sendall', altered) if case in ('stale', 'unrelated') else contextlib.nullcontext():
                    result = engine.confirm_access(lock_fd=lock, confirmation_fd=confirmation)
            assert result['phase'] == 'held'
            before = snapshot(root, engine)
            refusal(lambda: engine.abort_return(lock), 'LIVE_OWNER_REQUIRED')
            assert snapshot(root, engine) == before
            emit({'stage': 'confirmed', 'session': session, 'confirmer': ident(os.getpid()), 'result': result})
    except (m.Refusal, OSError) as error:
        # A refused/unknown original return may intentionally close its channel.
        emit({'stage': 'confirmation-channel-refused', 'code': str(error)})
    finally:
        os.close(lock)
        if confirmation is not None:
            os.close(confirmation)


def session(role, root, case, fds):
    assert ctypes.CDLL(None).prctl(15, b'sshd', 0, 0, 0) == 0
    argv = [sys.executable, '-B', FILE, '--' + role, root, case, *map(str, fds)]
    child = subprocess.Popen(argv, pass_fds=tuple(fds), stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
    natural = False
    try:
        status = child.wait(timeout=20)
        natural = True
    finally:
        if child.returncode is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=2)
        for fd in fds:
            os.close(fd)
        put(Path(root) / (role + '-wait.json'), {'child': {'pid': child.pid}, 'session': ident(os.getpid()),
            'exit': child.returncode, 'natural': natural, 'reaped': child.returncode is not None})
    assert status == 0, status


def line(child):
    raw = bytearray()
    end = time.monotonic() + 10
    while not raw.endswith(b'\n'):
        left = end - time.monotonic()
        assert left > 0 and select.select([child.stdout], [], [], max(0, left))[0], 'bounded child output timeout'
        part = os.read(child.stdout.fileno(), 1)
        assert part, 'child EOF before receipt'
        raw.extend(part)
        assert len(raw) < 65536
    return json.loads(raw)


class OriginalOwnerConfirmationTests(unittest.TestCase):
    def exercise(self, case):
        with tempfile.TemporaryDirectory(prefix='wave129-', dir=os.environ['TMPDIR']) as directory:
            root = Path(directory)
            (root / 'masks').mkdir()
            (root / 'masks/cron.service').write_bytes(b'ORIGINAL CRON UNIT\n')
            (root / 'masks/cron.service').chmod(0o640)
            put(root / 'manager.json', ident(os.getpid()))
            states = fixture.Host(fixture.plan()).original
            put(root / 'original.json', states)
            put(root / 'current.json', states)
            put(root / 'effects.json', [])
            parent, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            parent.settimeout(10)
            children, rights, rows = [], [], []
            try:
                child = subprocess.Popen([sys.executable, '-B', FILE, '--session', 'owner', str(root), case, str(peer.fileno())],
                    pass_fds=(peer.fileno(),), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
                children.append(child)
                peer.close()
                rows.append(line(child))
                data, ancillary, flags, _ = parent.recvmsg(100, socket.CMSG_SPACE(2 * array.array('i').itemsize))
                assert data == b'confirmation' and not flags
                for level, kind, raw in ancillary:
                    assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                    received = array.array('i'); received.frombytes(raw); rights.extend(received)
                self.assertIn(len(rights), (1, 2))
                self.assertTrue(held(root))
                # Real clock ticks: don't start a fresh session in the boundary's
                # same tick. This is scheduling, never changed identity or policy.
                deadline = time.monotonic() + 1
                while int(m.Host().boot_ticks()) <= int(rows[0]['boundary']['ticks']):
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.001)
                fresh = subprocess.Popen([sys.executable, '-B', FILE, '--session', 'confirmer', str(root), case, *map(str, rights)],
                    pass_fds=tuple(rights), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
                children.append(fresh)
                # Wait only for the actual durable held journal, not for a
                # fabricated confirmer result. The confirmer awaits owner ACK.
                deadline = time.monotonic() + 10
                while doc(root / 'journal.json')['phase'] != 'held':
                    self.assertIsNone(fresh.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.001)
                assert child.stdin is not None
                child.stdin.write(b'return\n'); child.stdin.flush()
                accepted = line(child)
                out, err = fresh.communicate(timeout=10)
                rows.append({'freshOutput': out.decode(), 'freshError': err.decode(), 'freshExit': fresh.returncode})
                self.assertEqual(fresh.returncode, 0, err.decode())
                confirmed = json.loads(out)
                if case not in ('stale', 'unrelated', 'pre-drift'):
                    self.assertEqual(confirmed['stage'], 'confirmed')
                    self.assertNotEqual(confirmed['session'], rows[0]['session'])
                if accepted['stage'] == 'accepted':
                    child.stdin.write(b'confirmer-reaped\n'); child.stdin.flush()
                out, err = child.communicate(timeout=15)
                rows.append({'ownerOutput': out.decode(), 'ownerError': err.decode(), 'ownerExit': child.returncode})
                self.assertEqual(child.returncode, 0, err.decode())
                returned = json.loads(out) if accepted['stage'] == 'accepted' else accepted
                self.assertEqual(returned['stage'], 'OLD' if case in ('positive', 'new-engine') else 'held' if case == 'success-only' else 'unknown' if case == 'unknown-start' else 'refused')
                self.assertTrue(held(root))
            finally:
                cleanup = []
                for child in children:
                    natural = child.poll() is not None
                    if not natural:
                        child.terminate()
                        try:
                            child.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            child.kill(); child.wait(timeout=2)
                    cleanup.append({'pid': child.pid, 'exit': child.returncode, 'natural': natural, 'reaped': child.returncode is not None})
                    for name in ('stdin', 'stdout', 'stderr'):
                        stream = getattr(child, name)
                        if stream is not None:
                            stream.close()
                for fd in rights:
                    os.close(fd)
                parent.close(); peer.close()
                rows.append({'cleanup': cleanup, 'ownerWait': doc(root / 'owner-wait.json') if (root / 'owner-wait.json').exists() else None,
                             'confirmerWait': doc(root / 'confirmer-wait.json') if (root / 'confirmer-wait.json').exists() else None,
                             'finalJournal': doc(root / 'journal.json') if (root / 'journal.json').exists() else None,
                             'effects': effects(root), 'lockReleased': not held(root)})
                evidence = os.environ.get('C3_CONFIRM_EVIDENCE')
                if evidence:
                    destination = Path(evidence) / (self.id().rsplit('.', 1)[-1] + '.json')
                    assert not destination.exists()
                    put(destination, rows)
                self.assertTrue(all(c['reaped'] for c in cleanup))
                self.assertFalse(held(root))

    def test_original_owner_returns_old_after_genuine_fresh_confirmation(self):
        self.exercise('positive')

    def test_new_engine_and_confirmer_cannot_adopt_return_owner(self):
        self.exercise('new-engine')

    def test_independent_lock_ofd_cannot_return_or_retry(self):
        self.exercise('wrong-lock')

    def test_held_disk_without_owner_confirmation_channel_is_not_adopted(self):
        self.exercise('no-channel')

    def test_stale_confirmation_bytes_are_one_shot_refused(self):
        self.exercise('stale')

    def test_unrelated_confirmation_bytes_are_one_shot_refused(self):
        self.exercise('unrelated')

    def test_journal_drift_during_confirmation_is_not_adopted(self):
        self.exercise('pre-drift')

    def test_journal_drift_after_confirmation_remains_retained(self):
        self.exercise('drift')

    def test_capture_barrier_survives_fresh_confirmation(self):
        self.exercise('capture')

    def test_commit_intent_barrier_survives_fresh_confirmation(self):
        self.exercise('commit')

    def test_dispatch_count_barrier_survives_fresh_confirmation(self):
        self.exercise('dispatch')

    def test_dispatch_unknown_barrier_survives_fresh_confirmation(self):
        self.exercise('inflight')

    def test_guard_loss_after_confirmation_cannot_return_or_retry(self):
        self.exercise('guard')

    def test_start_ack_unknown_after_confirmation_is_not_old_or_replayable(self):
        self.exercise('unknown-start')

    def test_confirmation_can_continue_held_without_forcing_old_return(self):
        self.exercise('success-only')


class ConfirmationSetupTests(unittest.TestCase):
    def test_new_engine_cannot_open_original_confirmation_scope(self):
        with fixture.RefusalMatrixTests().prepared() as (engine, host, root, lock):
            other = m.Engine(root, engine.plan, host)
            with self.assertRaisesRegex(m.Refusal, 'LIVE_OWNER_REQUIRED'):
                with other.fresh_confirmation(lock):
                    self.fail('new engine acquired a confirmation scope')

    def test_uncertain_journal_at_scope_entry_consumes_original_return(self):
        with fixture.RefusalMatrixTests().prepared() as (engine, host, root, lock):
            before = list(host.events)
            uncertain = root / 'journal.json.next'
            uncertain.write_text('{}')
            with self.assertRaisesRegex(m.Refusal, 'JOURNAL_UNCERTAIN_RETAINED'):
                with engine.fresh_confirmation(lock):
                    self.fail('uncertain journal admitted')
            uncertain.unlink()  # Fault repaired only to prove one-shot refusal.
            with self.assertRaisesRegex(m.Refusal, 'LIVE_OWNER_REQUIRED'):
                engine.abort_return(lock)
            self.assertEqual(host.events, before)

    def test_lost_lock_at_scope_entry_cannot_be_reacquired_for_return(self):
        with fixture.RefusalMatrixTests().prepared() as (engine, host, root, lock):
            before = list(host.events)
            fcntl.flock(lock, fcntl.LOCK_UN)
            with self.assertRaisesRegex(m.Refusal, 'OUTER_LOCK_LOST_RETAINED'):
                with engine.fresh_confirmation(lock):
                    self.fail('lost lock admitted')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(m.Refusal, 'LIVE_OWNER_REQUIRED'):
                engine.abort_return(lock)
            self.assertEqual(host.events, before)


if __name__ == '__main__':
    try:
        if len(sys.argv) > 1 and sys.argv[1] == '--session':
            session(sys.argv[2], sys.argv[3], sys.argv[4], list(map(int, sys.argv[5:])))
        elif len(sys.argv) > 1 and sys.argv[1] == '--owner':
            owner(sys.argv[2], int(sys.argv[4]), sys.argv[3])
        elif len(sys.argv) > 1 and sys.argv[1] == '--confirmer':
            confirmer(sys.argv[2], int(sys.argv[4]), int(sys.argv[5]) if len(sys.argv) > 5 else None, sys.argv[3])
        else:
            unittest.main()
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
