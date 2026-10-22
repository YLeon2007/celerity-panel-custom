"""Local protocol/OFD tests. Guard's physical exclusion is MODELED, not proven."""
import array
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
import fcntl

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prod_helper', BASE / 'authority_helper.py')
helper = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(helper)
except FileNotFoundError:
    helper = None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


class ProtocolTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='prod-authority-', dir=os.environ['TMPDIR'])
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def test_ordinary_directory_is_not_a_real_cgroup2(self):
        module, guard, _, _ = self.make_guard()
        try:
            self.assertTrue(hasattr(module, 'require_cgroup2'), 'missing physical filesystem type refusal')
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertRaises(Exception, module.require_cgroup2, fd)
            finally:
                os.close(fd)
        finally:
            guard.close()

    def test_constructor_cleanup_preserves_primary_error_and_attaches_secondary(self):
        from unittest.mock import patch
        primary, cleanup = RuntimeError('primary'), RuntimeError('cleanup')
        original_dispose = helper.HeldAuthority._dispose
        def bad_dispose(self):
            original_dispose(self)
            raise cleanup
        policy = {'version': 1, 'generation': str(uuid.uuid4()),
                  'challenge': {'serverContext': {'target': 'production', 'hostIdentity': 'lm1.infograd.online'}},
                  'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  'guards': [{'socket': 'unused', 'holderId': 'unused'}],
                  'journal': str(self.root / 'attempt.json'), 'lifetimeMs': 1000}
        with patch.object(helper.HeldAuthority, '_record', side_effect=primary), patch.object(helper.HeldAuthority, '_dispose', bad_dispose):
            with self.assertRaises(RuntimeError) as caught:
                helper.HeldAuthority(policy, owner_uid=os.getuid(), trusted_root=self.root)
        self.assertIs(caught.exception, primary)
        self.assertEqual(caught.exception.cleanup_errors, [cleanup])

    def test_guard_channel_error_is_sticky(self):
        _, guard, _, _ = self.make_guard()
        try:
            guard.check()
            left, right = socket.socketpair()
            self.addCleanup(left.close)
            self.addCleanup(right.close)
            right.sendall(b'{"invalid":true}\n')
            self.assertRaises(Exception, guard.serve_connection, left)
            with self.assertRaises(Exception, msg='malformed admitted channel must permanently revoke guard'):
                guard.check()
        finally:
            guard.close()

    def make_guard(self):
        try:
            guard_spec = importlib.util.spec_from_file_location('prod_guard', BASE / 'exclusion_guard.py')
            module = importlib.util.module_from_spec(guard_spec)
            guard_spec.loader.exec_module(module)
        except FileNotFoundError:
            module = None
        self.assertIsNotNone(module, 'missing actual external exclusion guard')
        group = self.root / 'frozen'
        group.mkdir(mode=0o700)
        (group / 'cgroup.freeze').write_text('1\n')
        (group / 'cgroup.events').write_text('populated 0\nfrozen 1\n')
        (group / 'cgroup.procs').write_text('')
        for file in group.iterdir():
            file.chmod(0o600)
        accepted = {'version': 1, 'generation': str(uuid.uuid4()), 'holderId': str(uuid.uuid4()),
                    'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    'challengeSha256': 'b' * 64,
                    'scopes': [{'path': str(group), 'device': group.stat().st_dev,
                                'inode': group.stat().st_ino, 'processes': []}],
                    'lock': str(self.root / 'external.lock'),
                    'journal': str(self.root / 'external.json'),
                    'socket': str(self.root / 'external.sock')}
        guard = module.ExclusionGuard(accepted, owner_uid=os.getuid(), trusted_root=self.root,
                                      cgroup_root=self.root, allow_empty_for_test=True)
        return module, guard, group, accepted

    def test_real_guard_supplies_same_ofd_and_latches_frozen_scope_drift(self):
        module, guard, group, accepted = self.make_guard()
        try:
            guard.check()
            (group / 'cgroup.freeze').write_text('0\n')
            self.assertRaises(Exception, guard.check)
            (group / 'cgroup.freeze').write_text('1\n')
            self.assertRaises(Exception, guard.check)
            self.assertEqual(json.loads((self.root / 'external.json').read_text())['state'], 'unknown-retained')
        finally:
            guard.close()
        self.assertEqual((group / 'cgroup.freeze').read_text(), '1\n', 'disposal must not thaw')
        self.assertRaises(Exception, module.ExclusionGuard, accepted, owner_uid=os.getuid(), trusted_root=self.root,
                          cgroup_root=self.root, allow_empty_for_test=True)

    def test_real_helper_keeps_original_guard_ofd_and_finite_cleanup_never_unlocks_guard(self):
        self.protocol_case('success')

    def test_guard_wrong_nonce_is_refused(self):
        self.protocol_case('wrongNonce')

    def test_missing_scm_rights_is_refused(self):
        self.protocol_case('noRights')

    def test_extra_scm_rights_are_closed_and_refused(self):
        self.protocol_case('extraRights')

    def test_unlocked_descriptor_is_not_acquired_or_adopted(self):
        self.protocol_case('unlockedFd')

    def test_stale_peer_pid_is_refused(self):
        self.protocol_case('peerPid')

    def test_replaced_lock_path_is_sticky_loss(self):
        self.protocol_case('replacedLock')

    def test_changed_accepted_source_cannot_be_repaired(self):
        self.protocol_case('sourceDrift')

    def protocol_case(self, mode):
        self.assertIsNotNone(helper, 'missing fixed external PROD helper')
        lock = open(self.root / 'writer.lock', 'w+')
        self.addCleanup(lock.close)
        if mode != 'unlockedFd':
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        sockpath = str(self.root / 'g.sock')
        listener.bind(sockpath)
        os.chmod(sockpath, 0o600)
        os.chmod(self.root / 'writer.lock', 0o600)
        listener.settimeout(2)
        listener.listen(1)
        holder = str(uuid.uuid4())
        generation = str(uuid.uuid4())
        challenge = {'serverContext': {'target': 'production', 'hostIdentity': 'lm1.infograd.online'}}
        errors = []
        checks = []
        def guard():
            try:
                conn, _ = listener.accept()
                with conn, conn.makefile('rb') as stream:
                    while raw := stream.readline():
                        req = json.loads(raw)
                        checks.append(req['verb'])
                        reply = {**req, 'state': 'held-retained'}
                        if mode == 'wrongNonce':
                            reply['nonce'] = '0' * 64
                        if req['verb'] == 'attach':
                            rights = [] if mode == 'noRights' else [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                      array.array('i', [lock.fileno()] * (2 if mode == 'extraRights' else 1)))]
                            conn.sendmsg([canonical(reply) + b'\n'], rights)
                        else:
                            conn.sendall(canonical(reply) + b'\n')
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=guard)
        thread.start()
        start = Path(f'/proc/{os.getpid()}/stat').read_text().rsplit(')', 1)[1].split()[19]
        source = self.root / 'accepted-guard-source.py'
        source.write_text('# explicitly modeled executable provenance\n')
        source.chmod(0o600)
        pin = {'socket': sockpath, 'pid': os.getpid(), 'startTicks': start,
               'sources': [{'path': str(source), 'sha256': digest(source.read_bytes())}],
               'executableSha256': digest(Path('/proc/self/exe').read_bytes()),
               'argvSha256': digest(Path('/proc/self/cmdline').read_bytes()),
               'holderId': holder, 'lock': {'path': str(self.root / 'writer.lock'),
               'device': os.fstat(lock.fileno()).st_dev, 'inode': os.fstat(lock.fileno()).st_ino}}
        policy = {'version': 1, 'generation': generation, 'challenge': challenge,
                  'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  'guards': [pin], 'journal': str(self.root / 'attempt.json'), 'lifetimeMs': 5000}
        # Library-only path/UID seam: real socket credentials, proc, FD and flock.
        if mode == 'peerPid':
            pin['pid'] += 100000
        if mode in ('wrongNonce', 'noRights', 'extraRights', 'unlockedFd', 'peerPid'):
            descriptors = len(os.listdir('/proc/self/fd'))
            with self.assertRaises(Exception):
                helper.HeldAuthority(policy, owner_uid=os.getuid(), trusted_root=self.root)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(os.listdir('/proc/self/fd')), descriptors, 'SCM_RIGHTS disposal must not leak descriptors')
            if mode == 'unlockedFd':
                with open(self.root / 'writer.lock') as rival:
                    fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        held = helper.HeldAuthority(policy, owner_uid=os.getuid(), trusted_root=self.root)
        if mode in ('sourceDrift', 'replacedLock'):
            try:
                if mode == 'sourceDrift':
                    source.write_text('# changed\n')
                else:
                    replacement = self.root / 'replacement'
                    replacement.write_text('')
                    replacement.chmod(0o600)
                    os.replace(replacement, self.root / 'writer.lock')
                self.assertRaises(Exception, held.check, challenge)
                if mode == 'sourceDrift':
                    source.write_text('# explicitly modeled executable provenance\n')
                self.assertRaises(Exception, held.check, challenge)
            finally:
                held.close()
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            return
        try:
            held.check(challenge)
            with open(self.root / 'writer.lock') as rival:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
            held.retain_unknown(challenge)
            held.close()
            with open(self.root / 'writer.lock') as rival:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(json.loads((self.root / 'attempt.json').read_text())['state'], 'unknown-retained')
            self.assertRaises(Exception, helper.HeldAuthority, policy, owner_uid=os.getuid(), trusted_root=self.root)
        finally:
            held.close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(checks, ['attach', 'check', 'check', 'retain', 'check'])


if __name__ == '__main__':
    unittest.main()
