"""Offline DIRECT fresh cleanup dispatch: real flock, VAULT and file effects."""
import fcntl
import json
import os
import re
from pathlib import Path
import runpy
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT.parent / 'rebuildRelayDirectHost.py'
PARENT = runpy.run_path(str(ROOT / 'test_rebuild_relay_foreign_config.py'))
MACHINE = PARENT['MACHINE']
NETWORK = dict(clientCidr='10.14.0.0/24', tproxyPort=18080, fwmark=100, routeTable=101)
TOKEN = 'c' * 32
CHAP = b'# prior comment\nexample fixture synthetic *\n'


# Reuse the kernel/FS model, not the parent's independent legacy test cases.
class ForeignConfigFixture(unittest.TestCase):
    pass


for name, value in vars(PARENT['ForeignConfig']).items():
    if not name.startswith('__') and not name.startswith('test_'):
        # setUp has no super() reference in the inherited model.
        setattr(ForeignConfigFixture, name, value)


class Cleanup(ForeignConfigFixture):
    def setUp(self):
        # Confine every temporary write to the already allocated scratch root.
        self.enterContext(patch.object(tempfile, 'tempdir', str(ROOT.parents[2])))
        super().setUp()
        self.enterContext(patch.object(os, 'fchown', side_effect=self.fchown))
        # Exercise real filesystem primitives, but prohibit process/socket I/O.
        self.enterContext(patch('subprocess.Popen', side_effect=AssertionError('unexpected child')))
        self.enterContext(patch('socket.socket', side_effect=AssertionError('unexpected socket')))
        self.h['C3_REPLACEMENT'] = runpy.run_path(str(ROOT.parent / 'rebuildRelayReplacement.py'))
        self.h['command'] = self.command_cleanup
        self.h['remove_generation'] = self.generation
        self.h['observe_ppp_preparation'] = lambda **_: {'missing': []}
        self.h['observe'] = self.observe
        self.h['candidate'] = lambda *_: {key: self.h['entry'](b'{"candidate":true}')
                                           for key in (*self.h['NAMES'], 'swan')}
        self.h['validate_profiles'] = lambda _: None
        self.h['apply_ppp_preparation'] = self.prior_to_stock_install
        self.stock_entered = False
        self.seed()
        self.path('/var/lib').mkdir(parents=True)
        self.put(self.h['MAIN'], b'{"before":true}')
        self.put(self.h['NAMES']['chap'], CHAP, 0o640)

    def fchown(self, fd, uid, gid):
        self.assertEqual((uid, gid), (0, 0))
        self.assertEqual(os.fstat(fd).st_uid, 0)

    def command_cleanup(self, *args, **opts):
        if args == ('/usr/bin/systemctl', '--no-pager', 'daemon-reload'):
            self.calls.append(args)
            self.net_loaded = False
            return b''
        if args == ('/usr/sbin/ip', 'xfrm', 'policy', 'list'):
            return b''
        if args == ('/usr/sbin/ip', 'xfrm', 'policy', 'list', 'nosock'):
            return b''
        if args == ('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys'):
            return self.xfrm
        if args == ('/usr/sbin/ip', '-j', '-N', '-4', 'route', 'show', 'table', 'all'):
            return b'[]'
        if args == ('/usr/sbin/nft', '-j', 'list', 'tables'):
            return b'{"nftables":[]}'
        if args[:4] == ('/usr/bin/systemctl', '--no-pager', 'show', '--all'):
            if args[-1] == self.h['NET_UNIT']:
                if getattr(self, 'model_net_load', False):
                    self.net_loaded = getattr(self, 'net_loaded', False) or self.path(self.h['NET']).exists()
                    if self.net_loaded:
                        return (f'LoadState=loaded\nActiveState=inactive\nMainPID=0\nFragmentPath={self.h["NET"]}\n'
                                'DropInPaths=\nUnitFileState=static\n').encode()
                return b'LoadState=not-found\nActiveState=inactive\nMainPID=0\n'
            if args[-1] == self.h['X'] and self.path(self.h['SYSTEM'] + '/' + self.h['X']).exists():
                fragment = self.h['SYSTEM'] + '/' + self.h['X']
                return f'LoadState=loaded\nActiveState=active\nFragmentPath={fragment}\n'.encode()
            if args[-1] == self.h['XL']:
                return b'LoadState=loaded\nActiveState=inactive\nMainPID=0\nDropInPaths=\nNeedDaemonReload=no\n'
        return self.command(*args, **opts)

    def observe(self, machine, routing, transit, *, projection=None, **_):
        self.assertEqual((machine, routing), (MACHINE, NETWORK))
        chap = self.h['NAMES']['chap']
        data = projection[chap] if projection is not None and chap in projection else self.h['read'](chap)
        self.assertTrue(all(not row or row.startswith(b'#') for row in self.h['raw'](data).split(b'\n')))
        files = {key: projection[path] if projection and path in projection else self.h['read'](path)
                 for key, path in self.h['NAMES'].items()}
        files.update(chap=data, swan=None)
        units = {n: dict.fromkeys(self.h['INSTALL_UNIT_FIELDS'], '') for n in self.h['UNITS']}
        units[self.h['IKE']]['ActiveState'] = 'inactive'
        return dict(files=files, bridge=None, units=units,
                    sockets=[('tcp', '127.0.0.1', 9999)], boot=self.h['boot'](), installBoot=False,
                    ikeSockets=[], swanInputs='model', globalFiles=dict.fromkeys(
                        ('/etc/ppp/options', self.h['SWAN_CONF'], self.h['XL_DEFAULT'])))

    def prior_to_stock_install(self, *_):
        self.stock_entered = True
        path = self.path(self.h['manifest_path'](TOKEN))
        journal = json.loads(path.read_bytes())
        self.assertEqual(journal['phase'], 'applying')
        self.assertEqual(len(journal['foreignJournal']['done']), len(journal['foreignJournal']['edits']))
        self.assertTrue(self.path(self.h['VAULT'] + '/foreign-cleanup.pending').exists())
        self.assertEqual(self.path(self.h['NAMES']['chap']).read_bytes(), b'# prior comment\n# example fixture synthetic *\n')
        # Leave a visible cut at the untouched stock module-preparation seam.
        raise self.h['Refusal']('IN_FLIGHT')

    def consent(self):
        code, out, err = self.run_host()
        self.assertEqual((code, out), (70, ''))
        kind, keys, fingerprint, cleanable = err.strip().split(' ')
        self.assertEqual((kind, keys, cleanable), ('DIRECT_L2TP_FOREIGN_CONFIG', 'CHAP_NOT_EMPTY', 'CHAP_NOT_EMPTY'))
        self.assertRegex(fingerprint, '^[a-f0-9]{64}$')
        return {'digest': fingerprint, 'fixXrayUnitMode': False, 'at': '2026-11-25T08:25:00.000Z'}

    def prepare(self, auth):
        code, out, err = self.run_host('prepare', network=NETWORK, foreignCleanup=auth)
        self.assertEqual((code, err), (0, ''))
        return {'network': NETWORK, 'foreignCleanup': auth, 'backupId': TOKEN, 'baseline': json.loads(out)['baseline']}

    def test_readonly_join_and_stock_handoff(self):
        original = self.snapshot()
        auth = self.consent()
        self.assertEqual(self.run_host(foreignCleanup=auth)[0], 0)
        frame = self.prepare(auth)
        self.assertEqual(self.run_host('check', **frame)[0], 0)
        self.assertEqual(self.snapshot(), original)
        self.assertEqual(self.run_host('install', **frame), (75, '', ''))
        self.assertTrue(self.stock_entered)
        self.assertFalse(any(x[0] == '/usr/bin/systemctl' and set(x) & {'restart', 'stop', 'start', 'daemon-reload'}
                             for x in self.calls))

    def test_drift_and_disappearance_are_not_permission(self):
        auth = self.consent()
        frame = self.prepare(auth)
        leaf = self.h['NAMES']['chap']
        self.put(leaf, CHAP + b'other fixture changed *\n')
        code, out, error = self.run_host('install', **frame)
        self.assertEqual((code, out), (70, ''))
        self.assertRegex(error, r'^DIRECT_NO_WRITE_L2TP_FOREIGN_CONFIG_CHANGED CHAP_NOT_EMPTY [a-f0-9]{64} CHAP_NOT_EMPTY\n$')
        self.put(leaf, b'# harmless manual change\n')
        self.assertEqual(self.run_host('install', **frame), (70, '', 'DIRECT_NO_WRITE_L2TP_FOREIGN_CONFIG_CHANGED\n'))
        self.assertFalse(self.path(self.h['VAULT']).exists())

    def test_xfrm_after_durable_intent_blocks_first_edit(self):
        frame = self.prepare(self.consent())
        stock_write = self.h['write']
        def fault(path, before, after, **kwargs):
            result = stock_write(path, before, after, **kwargs)
            if path.endswith('/foreign-cleanup.pending'):
                self.xfrm = b'unexpected association'
            return result
        self.h['write'] = fault
        self.assertEqual(self.run_host('install', **frame), (75, '', ''))
        self.assertEqual(self.path(self.h['NAMES']['chap']).read_bytes(), CHAP)
        self.assertFalse(self.stock_entered)
        self.xfrm = b''
        self.assertEqual(self.run_host()[0], 75)

    def test_preinstall_rollback_restores_mode_and_bytes(self):
        frame = self.prepare(self.consent())
        stock_observe = self.h['observe_install']
        def fault(*args, **kwargs):
            if self.path(self.h['VAULT'] + '/foreign-cleanup.pending').exists():
                raise self.h['Refusal']('IN_FLIGHT')
            return stock_observe(*args, **kwargs)
        self.h['observe_install'] = fault
        self.assertEqual(self.run_host('install', **frame), (75, '', ''))
        leaf = self.path(self.h['NAMES']['chap'])
        self.assertNotEqual(leaf.read_bytes(), CHAP)
        self.h['observe_install'] = stock_observe
        args = {key: frame[key] for key in ('backupId', 'baseline', 'network')}
        self.assertEqual(self.run_host('rollback', **args)[0], 0)
        self.assertEqual(leaf.read_bytes(), CHAP)
        self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o640)
        self.assertFalse(self.path(self.h['VAULT'] + '/foreign-cleanup.pending').exists())
        self.assertFalse(self.stock_entered)

    def test_manual_folder_cannot_be_smuggled_into_plan(self):
        self.put(self.h['NFT_FILE'], b'create table inet celerity_rebuild_l2tp { # unknown\n}\n', 0o644)
        code, _, err = self.run_host()
        self.assertEqual(code, 70)
        suffix, keys, fingerprint, cleanable = err.strip().split(' ')
        self.assertEqual((suffix, keys, cleanable), ('DIRECT_L2TP_FOREIGN_CONFIG', 'CHAP_NOT_EMPTY,NFT_DIR_PRESENT', 'CHAP_NOT_EMPTY'))
        self.assertEqual(self.run_host(foreignCleanup={'digest': fingerprint, 'fixXrayUnitMode': False, 'at': '2026-11-25T08:25:00.000Z'})[2], err)
        self.assertFalse(self.path(self.h['VAULT']).exists())

    def test_known_nft_and_drop_are_journalled_as_exact_closed_trees(self):
        nft, drop = self.h['NFT_FILE'], self.h['DROP']
        self.put(nft, self.h['managed_nft_bytes'](NETWORK, TOKEN), 0o644)
        self.put(drop, f'[Unit]\nRequires={self.h["NET_UNIT"]} {self.h["IKE"]}\nAfter={self.h["NET_UNIT"]} {self.h["IKE"]}\n'.encode(), 0o644)
        for leaf in (nft, drop):
            self.path(leaf).parent.chmod(0o755)
        kind, keys, fingerprint, cleanable = self.run_host()[2].strip().split(' ')
        self.assertEqual((kind, keys, cleanable), ('DIRECT_L2TP_FOREIGN_CONFIG',
                         'CHAP_NOT_EMPTY,NFT_DIR_PRESENT,DROPIN_PRESENT', 'CHAP_NOT_EMPTY,NFT_DIR_PRESENT,DROPIN_PRESENT'))
        frame = self.prepare({'digest': fingerprint, 'fixXrayUnitMode': False, 'at': '2026-11-25T08:25:00.000Z'})
        self.assertEqual(self.run_host('install', **frame), (75, '', ''))
        self.assertTrue(self.stock_entered)
        for leaf in (nft, drop):
            self.assertFalse(self.path(leaf).parent.exists())

    def test_unacknowledged_edit_does_not_autorollback(self):
        frame = self.prepare(self.consent())
        chap = self.h['NAMES']['chap']
        stock_write = self.h['write']
        def fault(path, before, after, **kwargs):
            result = stock_write(path, before, after, **kwargs)
            if path == chap:
                raise OSError('simulated missing acknowledgement after effect')
            return result
        self.h['write'] = fault
        self.assertEqual(self.run_host('install', **frame), (75, '', ''))
        args = {key: frame[key] for key in ('backupId', 'baseline', 'network')}
        self.h['write'] = stock_write
        self.assertEqual(self.run_host('rollback', **args), (75, '', ''))
        self.assertNotEqual(self.path(chap).read_bytes(), CHAP)
        self.assertTrue(self.path(self.h['VAULT'] + '/foreign-cleanup.pending').exists())

    def xray_file_cut(self, *, lost_reload=False):
        generator = (ROOT.parent / 'configGenerator.js').read_bytes()
        original = re.search(rb'function generateXraySystemdService\(\) \{\n    return `([^`]+)`;', generator)[1]
        path = self.h['SYSTEM'] + '/' + self.h['X']
        leaf = self.put(path, original, 0o666)
        inode, mtime = leaf.stat().st_ino, leaf.stat().st_mtime_ns
        self.h['cleanup_xray_identity'] = lambda: {self.h['X']: ['invocation', 'pid', 'start']}
        line = self.run_host()[2]
        kind, keys, fingerprint, cleanable = line.strip().split(' ')
        self.assertEqual((kind, keys, cleanable), ('DIRECT_L2TP_FOREIGN_CONFIG',
                         'CHAP_NOT_EMPTY,XRAY_UNIT_0666', 'CHAP_NOT_EMPTY,XRAY_UNIT_0666'))
        auth = {'digest': fingerprint, 'fixXrayUnitMode': False, 'at': '2026-11-25T08:25:00.000Z'}
        self.assertEqual(self.run_host(foreignCleanup=auth), (70, '', line))
        frame = self.prepare({**auth, 'fixXrayUnitMode': True})
        observe_install = self.h['observe_install']
        fence = self.path(self.h['VAULT'] + '/foreign-cleanup.pending')
        def cut(*args, **kwargs):
            if fence.exists():
                raise self.h['Refusal']('IN_FLIGHT')
            return observe_install(*args, **kwargs)
        self.h['observe_install'] = cut
        if lost_reload:
            command = self.h['command']
            def miss_reload(*args, **opts):
                answer = command(*args, **opts)
                if args[-1] == 'daemon-reload':
                    raise subprocess.TimeoutExpired(args, 1)
                return answer
            self.h['command'] = miss_reload
        self.assertEqual(self.run_host('install', **frame), (75, '', ''))
        self.assertEqual((leaf.read_bytes(), stat.S_IMODE(leaf.stat().st_mode), leaf.stat().st_mtime_ns),
                         (original, 0o644, mtime))
        self.assertNotEqual(leaf.stat().st_ino, inode)
        args = {key: frame[key] for key in ('backupId', 'baseline', 'network')}
        return args, original, leaf, mtime, fence

    def test_xray_mode_requires_opt_in_and_restores_original_bytes_and_mode(self):
        args, original, leaf, mtime, fence = self.xray_file_cut()
        self.assertEqual(self.run_host('rollback', **args)[0], 0)
        self.assertEqual((leaf.read_bytes(), stat.S_IMODE(leaf.stat().st_mode), leaf.stat().st_mtime_ns),
                         (original, 0o666, mtime))
        self.assertFalse(fence.exists())
        self.assertEqual(sum(a[-1] == 'daemon-reload' for a in self.calls), 1)

    def test_xray_mode_rejects_new_process_and_byte_identical_inode(self):
        args, original, leaf, mtime, fence = self.xray_file_cut()
        pinned = self.h['cleanup_xray_identity']
        self.h['cleanup_xray_identity'] = lambda: {self.h['X']: ['another invocation', 'new pid', 'new start']}
        self.assertEqual(self.run_host('rollback', **args), (75, '', ''))
        self.h['cleanup_xray_identity'] = pinned
        other = leaf.with_suffix('.other')
        other.write_bytes(original)
        other.chmod(0o644)
        os.utime(other, ns=(mtime, mtime))
        other.replace(leaf)
        self.assertEqual(self.run_host('rollback', **args), (75, '', ''))
        self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o644)
        self.assertTrue(fence.exists())

    def test_lost_cleanup_reload_is_not_settled_by_inactive_services(self):
        args, _, leaf, _, fence = self.xray_file_cut(lost_reload=True)
        self.h['command'] = self.command_cleanup
        self.assertEqual(self.run_host('rollback', **args), (75, '', ''))
        self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o644)
        self.assertTrue(fence.exists())

    def file_failure(self, *, publish=False):
        frame = self.prepare(self.consent())
        self.h['apply_ppp_preparation'] = lambda _: None
        self.model_net_load = True
        # Leave the real file writers, journal, guard and dispatcher in place;
        # the native input/manager observations are synthetic in this fixture.
        self.h['SWAN_SETTINGS'] = b'{"candidate":true}'
        candidate = self.h['candidate']
        self.h['candidate'] = lambda *a: {**candidate(*a), 'swan': self.h['entry'](self.h['SWAN_SETTINGS'], 0o644)}
        self.h['swan_inputs'] = lambda *_a, **_kw: 'model'
        self.h['no_swan_rule'] = lambda: None
        self.path(self.h['SWAN_PROFILE']).parent.mkdir(parents=True, exist_ok=True)
        self.path(self.h['NFT_DIR']).parent.mkdir(parents=True, exist_ok=True)
        self.path(self.h['NAMES']['options']).parent.mkdir(parents=True, exist_ok=True)
        write, command = self.h['write'], self.h['command']
        leaf = self.h['NAMES']['lns']
        self.file_cut = False
        def fail(path, before, after, **kwargs):
            if path == leaf and not self.file_cut:
                self.file_cut = True
                if publish:
                    write(path, before, after, **kwargs)
                raise OSError('modeled file syscall failure')
            return write(path, before, after, **kwargs)
        self.h['write'] = fail
        self.h['command'] = lambda *a, **kw: b'' if a[:3] == ('/usr/sbin/nft', '-c', '-f') else command(*a, **kw)
        result = self.run_host('install', **frame)
        self.assertTrue(self.file_cut)
        self.assertFalse(any(set(a) & {'restart', 'stop', 'start'} for a in self.calls))
        return frame, result

    def generation(self, path):
        try:
            st = self.path(path).lstat()
        except FileNotFoundError:
            return None
        return [st.st_dev, st.st_ino, st.st_ctime_ns]

    def test_file_failure_before_publication_restores_known_prefix(self):
        self.h['C3_PACKAGE_GUARD'] = runpy.run_path(str(ROOT.parent / 'rebuildRelayPackageGuard.py'))
        frame, result = self.file_failure()
        self.assertEqual(result, (70, '', 'DIRECT_COMMAND_FAILED\n'))
        self.assertEqual(self.path(self.h['NAMES']['chap']).read_bytes(), CHAP)
        self.assertFalse(self.path(self.h['NFT_DIR']).exists())
        self.assertFalse(self.path(self.h['DROP_DIR']).exists())
        self.assertFalse(self.path(self.h['SWAN_PROFILE']).exists())
        self.assertFalse(self.path(self.h['VAULT'] + '/foreign-cleanup.pending').exists())
        args = {key: frame[key] for key in ('backupId', 'baseline', 'network')}
        self.assertEqual(self.run_host('rollback', **args), (0, '{"ok":true,"backupId":"' + TOKEN + '"}\n', ''))
        code, out, err = self.run_host('reconcile-install', network=NETWORK, backupId=TOKEN,
                                       nodeId='d' * 24, challenge='e' * 32)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(json.loads(out)['result'], 'rolled_back')

    def test_file_failure_after_unacknowledged_publication_stays_fenced(self):
        frame, result = self.file_failure(publish=True)
        self.assertEqual(result, (75, '', ''))
        self.assertNotEqual(self.path(self.h['NAMES']['chap']).read_bytes(), CHAP)
        self.assertTrue(self.path(self.h['VAULT'] + '/foreign-cleanup.pending').exists())
        args = {key: frame[key] for key in ('backupId', 'baseline', 'network')}
        self.assertEqual(self.run_host('rollback', **args), (75, '', ''))

    def test_terminal_requires_exact_manifest_and_sync_of_missing_fence(self):
        frame, result = self.file_failure()
        self.assertEqual(result, (70, '', 'DIRECT_COMMAND_FAILED\n'))
        args = {key: frame[key] for key in ('backupId', 'baseline', 'network')}
        terminal = self.path(self.h['manifest_path'](TOKEN))
        vault = self.path(self.h['VAULT'])
        targets = [terminal, terminal.parent, vault, vault.parent, vault]
        for fail_at in (0, 1, 4):
            seen, sync = [], os.fsync
            def fault(fd):
                seen.append(Path(os.readlink(f'/proc/self/fd/{fd}')))
                if len(seen) - 1 == fail_at:
                    raise OSError('modeled failed fsync')
                return sync(fd)
            with patch.object(os, 'fsync', side_effect=fault):
                self.assertEqual(self.run_host('rollback', **args), (75, '', ''))
            self.assertEqual(seen, targets[:fail_at + 1])
        self.assertEqual(self.run_host('rollback', **args)[0], 0)
        self.assertFalse((vault / 'foreign-cleanup.pending').exists())

    def test_lost_fence_unlink_sync_is_recovered_only_by_terminal_readback(self):
        vault = self.path(self.h['VAULT'])
        terminal = self.path(self.h['manifest_path'](TOKEN))
        fence = vault / 'foreign-cleanup.pending'
        sync, faulted = os.fsync, False
        def fault(fd):
            nonlocal faulted
            if (not faulted and Path(os.readlink(f'/proc/self/fd/{fd}')) == vault
                    and not fence.exists() and terminal.exists()
                    and json.loads(terminal.read_bytes())['phase'] == 'rolled-back'):
                faulted = True
                raise OSError('unlink visible but vault sync unacknowledged')
            return sync(fd)
        with patch.object(os, 'fsync', side_effect=fault):
            frame, result = self.file_failure()
        self.assertTrue(faulted)
        self.assertFalse(fence.exists())
        self.assertEqual(result, (75, '', ''))
        args = {key: frame[key] for key in ('backupId', 'baseline', 'network')}
        self.assertEqual(self.run_host('rollback', **args), (0, '{"ok":true,"backupId":"' + TOKEN + '"}\n', ''))
        self.assertEqual(self.path(self.h['NAMES']['chap']).read_bytes(), CHAP)

    def test_old_remove_attempt_blocks_even_a_terminal_repeat(self):
        frame, result = self.file_failure()
        self.assertEqual(result, (70, '', 'DIRECT_COMMAND_FAILED\n'))
        args = {key: frame[key] for key in ('backupId', 'baseline', 'network')}
        manifest = self.path(self.h['manifest_path'](TOKEN))
        remove = manifest.parent / 'remove-attempt.json'
        remove.symlink_to('missing-attempt')
        saved = self.snapshot()
        self.assertEqual(self.run_host('rollback', **args), (75, '', ''))
        self.assertEqual(self.snapshot(), saved)

    def test_cleanup_is_serialized_by_existing_install_flock(self):
        frame = self.prepare(self.consent())
        before = self.snapshot()
        with self.directory(self.h['SYSTEM']) as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_host('install', **frame), (75, '', ''))
        self.assertEqual(self.snapshot(), before)

    def test_reconcile_install_joins_existing_manifest_and_rolls_back(self):
        self.h['C3_PACKAGE_GUARD'] = runpy.run_path(str(ROOT.parent / 'rebuildRelayPackageGuard.py'))
        frame = self.prepare(self.consent())
        observe_install = self.h['observe_install']
        fence = self.path(self.h['VAULT'] + '/foreign-cleanup.pending')
        def cut(*args, **kwargs):
            if fence.exists():
                raise self.h['Refusal']('IN_FLIGHT')
            return observe_install(*args, **kwargs)
        self.h['observe_install'] = cut
        self.assertEqual(self.run_host('install', **frame), (75, '', ''))
        self.h['observe_install'] = observe_install
        request = dict(network=NETWORK, backupId=TOKEN, nodeId='d' * 24, challenge='e' * 32)
        for _ in range(2):
            code, out, err = self.run_host('reconcile-install', **request)
            self.assertEqual((code, err), (0, ''))
            self.assertEqual(json.loads(out), {**{k: v for k, v in request.items() if k != 'network'},
                                               'machineId': MACHINE, 'result': 'rolled_back'})
            self.assertFalse(fence.exists())
            self.assertEqual(self.path(self.h['NAMES']['chap']).read_bytes(), CHAP)

    def test_completed_remove_retires_preimages_without_reopening_backup_generation(self):
        h = self.h
        root = h['VAULT'] + '/' + TOKEN
        h['mkdir'](h['VAULT'], 0o700, exist_ok=True)
        h['mkdir'](root, 0o700)
        path, intent = root + '/manifest.json', root + '/remove-attempt.json'
        before = {'foreignCleanup': {'digest': 'a' * 64}}
        edits = [['CHAP_NOT_EMPTY', h['entry'](CHAP), None, []]]
        backup = dict(phase='installed', backupId=TOKEN, before=before,
                      foreignJournal=dict(edits=edits, editsSha256=h['digest'](h['encode'](edits))))
        original = h['entry'](h['encode'](backup))
        remove_intent = h['entry'](h['encode']({'baseline': 'b' * 64}))
        h['write'](path, None, original)
        state = dict(path=path, intent=intent, before=before, manifest=original)
        with self.assertRaises(h['Refusal']):
            h['discard_removed_cleanup_backup'](state, remove_intent)
        self.assertEqual(h['read'](path), original)
        h['write'](intent, None, remove_intent)
        h['discard_removed_cleanup_backup'](state, remove_intent)
        self.assertEqual(json.loads(h['raw'](h['read'](path))), {'phase': 'removed', 'backupId': TOKEN})
        self.assertEqual(h['read'](intent), remove_intent)
        with self.assertRaises(h['Refusal']):
            h['cleanup_no_remove'](path)

    def test_cleanup_is_not_a_remove_or_package_request_field(self):
        auth = self.consent()
        for action in ('rollback', 'verify', 'remove', 'prepare-packages', 'prove-applied-main'):
            expected = 'REMOVE_REFUSED' if action == 'remove' else 'CANDIDATE_INVALID'
            self.assertEqual(self.run_host(action, foreignCleanup=auth), (70, '', 'DIRECT_' + expected + '\n'))
        self.assertEqual(self.run_host(foreignCleanup={**auth, 'fixXrayUnitMode': 1}), (70, '', 'DIRECT_CANDIDATE_INVALID\n'))


if __name__ == '__main__':
    suite = unittest.TestSuite(Cleanup(name) for name in Cleanup.__dict__ if name.startswith('test_'))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
