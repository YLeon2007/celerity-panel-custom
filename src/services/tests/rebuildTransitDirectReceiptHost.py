"""Real MAIN/DIRECT file generations and writes, with modeled native observers."""
import copy
import fcntl
import json
import os
import stat
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

# The shared DIRECT fixture accepts a source override on its own CLI; don't
# pass unittest's test selector through to it. It installs a native-I/O veto.
with patch.object(sys, 'argv', sys.argv[:1]):
    import rebuildRelayDirectReattestHost as fixture
from rebuildTransitMainWindowHost import System

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rebuildTransitDirectReceipt import DirectReceipt, FINAL, LEGACY_NET, UNCONFIRMED, WRITERS
from rebuildTransitMainSession import HostMainSession, WindowError
import rebuildTransitMainWindow as window
from rebuildTransitMainWindow import XRAY_PROPS


class ReceiptFixture(unittest.TestCase):
    active_bridge = False

    def setUp(self):
        f = self.f = fixture.RuntimeReattest()
        self.addCleanup(f.doCleanups)
        f.setUp()
        self.h = h = f.h
        f.stage_pinned_network()
        self.x, self.xl, self.ike, self.net = f.watch
        b = h['B']
        f.units[b].update(FragmentPath='', UnitFileState='', ExecStart='', ControlGroup='', InvocationID='')
        self.lock = f.physical(h['SYSTEM'])
        f.manifest['before']['installLock'] = list((self.lock.stat().st_dev, self.lock.stat().st_ino))
        self.main = f.physical(h['MAIN'])
        # Match the existing DIRECT fixture's simulated root uid/gid. MAIN
        # still uses real file modes, inodes, bytes, rename and fsync.
        owners = patch.object(window, '_file_metadata', lambda st: (stat.S_IMODE(st.st_mode), 0, 0))
        owners.start()
        self.addCleanup(owners.stop)
        f.put(h['XRAY'], b'modeled binary\n', 0o755)
        f.put(f.units[self.x]['FragmentPath'], b'modeled MAIN unit\n', 0o644)
        f.put(f.units[self.ike]['FragmentPath'], b'modeled IKE unit\n', 0o644)
        params, handoff = f.apply_fixture(bridge=self.active_bridge)
        proof = self.call('publish-apply-profiles', **params)['proof']
        f.model_apply_main_restart(handoff)
        self.call('restart-apply-network', proof=proof)
        if self.active_bridge:
            f.units[b].update(LoadState='loaded', ActiveState='active', SubState='running', User='nobody',
                              FragmentPath=h['SYSTEM'] + '/' + b, UnitFileState='enabled', MainPID='76',
                              InvocationID='3' * 32, ModelCgroup=['76'], ControlGroup='/' + b)
            f.starts['76'] = 202
            f.rows.append(('tcp', '127.0.0.1', 9443, ['76']))
        self.call('finalize-apply-profiles', proof=proof)
        f.request['nodeId'] = f.node
        self.call('reattest-runtime')
        self.original = self.main.read_bytes()
        cfg = json.loads(self.original)
        cfg['inbounds'][0]['port'] = 444
        self.candidate = h['encode'](cfg)
        self.cg = f.root / 'system.slice'
        self.cg.mkdir()
        self.manager = System(self.cg)
        self.proofs = []
        self.permit_writers = True
        self.permit_final = True
        self.at_start = lambda: None
        self.write_calls = 0
        self.direct_write = h['write']
        h['write'] = self.count_write
        # Attribute process-cgroup witnesses to the modeled current PID.
        h['in_cgroup'] = lambda pid, row: pid == row['MainPID'] if row['ControlGroup'] == '/xray' else pid in row['ModelCgroup']

    def count_write(self, *args, **kwargs):
        self.write_calls += 1
        return self.direct_write(*args, **kwargs)

    def call(self, action, **kwargs):
        rc, out, err = self.f.call(action, **kwargs)
        self.assertEqual((rc, err), (0, ''))
        return json.loads(out)

    def run_model(self, argv, timeout):
        cmd = argv[1]
        if argv[-1] == self.x:
            row = self.f.units[self.x]
            if cmd == 'show':
                row = {**row, 'Id': self.x, 'Job': '', 'ExecStart': '{ path=/usr/local/bin/xray ; argv[]='
                       '/usr/local/bin/xray run -config /usr/local/etc/xray/config.json ; ignore_errors=no ; }'}
                return ''.join(f'{k}={row[k]}\n' for k in XRAY_PROPS)
            self.assertEqual(cmd, 'restart')
            self.manager.trace.append(tuple(argv))
            old = row['MainPID']
            pid = str(int(old) + 1)
            row.update(MainPID=pid, InvocationID=f'{int(pid) + 300:032x}')
            self.f.starts[pid] = int(pid) + 200
            self.loaded = self.main.read_bytes()
            port = json.loads(self.loaded)['inbounds'][0]['port']
            self.f.rows = [(p, a, port if n in (443, 444) else n, [pid] if owners == [old] else owners)
                           for p, a, n, owners in self.f.rows]
            return ''
        result = self.manager(argv, timeout)
        if cmd == 'start':
            self.manager.inv = f'{self.manager.generation:032x}'
        return result

    def runtime(self, phase, snapshot):
        self.proofs.append(phase)
        return phase == 'capture' or snapshot.main.data == self.loaded

    def final_proof(self, final):
        self.proofs.append('independent')
        return self.permit_final and final.main.data == self.loaded

    def session(self):
        return HostMainSession(self.run_model, lambda: True, self.runtime, frozenset({'client'}),
                               main=self.main, cgroup_root=self.cg, lock_dir=self.lock,
                               clock=lambda: self.manager.now, sleep=self.manager.sleep)

    def capture(self, session, **overrides):
        baseline = session.read()
        kwargs = dict(direct=SimpleNamespace(**self.h), machine_id=self.f.machine, backup_id=self.f.token,
                      node_id=self.f.node, network=self.f.network, verify_writers=lambda: self.permit_writers)
        return baseline, DirectReceipt.capture(session, baseline, **(kwargs | overrides))

    def cutover(self, session, baseline, receipt, target=None):
        session.stop()
        pending = session.capture(baseline, target or self.candidate)
        receipt.check_drained(pending)
        session.publish(*pending)
        session.restart()
        session.start()
        self.at_start()
        return session.reconcile()

    def manifest(self):
        return self.h['read_manifest'](self.f.token)[2]

    def effects(self):
        return [argv[1] for argv in self.manager.trace if argv[1] in ('start', 'stop', 'restart')]

    def rewrite_same(self, path):
        stage = path.with_name('independent-rewrite')
        stage.write_bytes(path.read_bytes())
        stage.chmod(path.stat().st_mode & 0o777)
        stage.replace(path)


class ReceiptHost(ReceiptFixture):
    def test_real_producer_then_forward_inverse_consumer(self):
        h, f = self.h, self.f
        before = f.image()
        prior = self.manifest()
        for target in (self.candidate, self.original):
            with self.session() as session:
                with open_lock(self.lock) as contender:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                frozen = f.image()
                baseline, receipt = self.capture(session)
                self.assertEqual(f.image(), frozen)
                final = self.cutover(session, baseline, receipt, target)
                self.assertEqual(self.manifest(), prior)
                receipt.advance(final, prove_final=self.final_proof)
                expected = copy.deepcopy(prior)
                expected['currentApply']['files']['main'] = h['file_pin'](*h['apply_profile_read'](h['MAIN']))
                expected['currentApply']['tcp'] = h['apply_tcp_pin'](f.rows, f.units[self.x], f.units[h['B']])
                expected['runtime']['pids'][0] = str(final.xray.pid)
                expected['runtime']['invocations'][0] = final.xray.invocation_id
                self.assertEqual(self.manifest(), expected)
                prior = expected
            self.assertEqual(self.proofs[-2:], ['reconcile', 'independent'])
            self.call('reattest-runtime')  # Actual reader, must be an exact no-op.
        self.assertEqual(self.main.read_bytes(), self.original)
        after = f.image()
        keys = {name for name in before if before[name] != after[name]}
        self.assertEqual(keys, {f.manifest_path[1:], h['MAIN'][1:], str(self.manager.events.relative_to(f.root))})
        self.assertEqual(self.write_calls, 2)

    def test_same_byte_predecessor_replacement_after_final_proof_is_not_adopted(self):
        p = self.f.physical(self.f.manifest_path)
        with self.session() as session:
            baseline, receipt = self.capture(session)
            final = self.cutover(session, baseline, receipt)
            def proof(snapshot):
                self.rewrite_same(p)
                return self.final_proof(snapshot)
            with self.assertRaises(WindowError):
                receipt.advance(final, prove_final=proof)
            with self.assertRaises(WindowError):
                receipt.advance(final, prove_final=self.final_proof)
        self.assertEqual(self.write_calls, 0)

    def test_same_byte_drain_rewrite_refuses_before_publish(self):
        with self.session() as session:
            baseline, receipt = self.capture(session)
            session.stop()
            self.rewrite_same(self.main)
            pending = session.capture(baseline, self.candidate)
            with self.assertRaises(WindowError):
                receipt.check_drained(pending)
        self.assertEqual(self.effects(), ['stop'])
        self.assertEqual(self.write_calls, 0)

    def test_same_byte_agent_startup_rewrite_never_stamps(self):
        self.at_start = lambda: self.rewrite_same(self.main)
        with self.session() as session:
            baseline, receipt = self.capture(session)
            with self.assertRaises(WindowError):
                self.cutover(session, baseline, receipt)
        self.assertEqual(self.write_calls, 0)

    def test_independent_final_proof_is_not_optional(self):
        self.permit_final = False
        with self.session() as session:
            baseline, receipt = self.capture(session)
            final = self.cutover(session, baseline, receipt)
            with self.assertRaisesRegex(WindowError, FINAL):
                receipt.advance(final, prove_final=self.final_proof)
        self.assertEqual(self.write_calls, 0)

    def test_missing_writer_exclusion_refuses_even_before_stop(self):
        self.permit_writers = False
        before = self.f.image()
        with self.session() as session, self.assertRaisesRegex(WindowError, WRITERS):
            self.capture(session)
        self.assertEqual(self.f.image(), before)
        self.assertEqual(self.effects(), [])

    def test_requires_network_is_not_upgraded(self):
        h, f = self.h, self.f
        manifest = self.manifest()
        net = h['network_unit'](f.network, False, legacy=True)
        f.put(h['NET'], net, 0o644)
        manifest['after']['net'], manifest['runtime']['files']['net'] = h['file_pin'](*h['apply_profile_read'](h['NET']))
        f.put(f.manifest_path, h['encode'](manifest), 0o600)
        before = f.image()
        with self.session() as session, self.assertRaisesRegex(WindowError, LEGACY_NET):
            self.capture(session)
        self.assertEqual(f.image(), before)
        self.assertEqual(self.effects(), [])

    def test_exact_non_requires_network_layout_is_not_upgraded(self):
        h, f = self.h, self.f
        manifest = self.manifest()
        net = h['network_unit'](f.network, False)
        f.put(h['NET'], net, 0o644)
        f.units[self.net]['ExecStart'] = fixture.NETWORK_FIXTURE['systemctl_start'](net)
        manifest['after']['net'], manifest['runtime']['files']['net'] = h['file_pin'](*h['apply_profile_read'](h['NET']))
        manifest['runtime']['nft'] = h['network_projection'](f.network, f.token)['nft']
        f.put(f.manifest_path, h['encode'](manifest), 0o600)
        with self.session() as session:
            baseline, receipt = self.capture(session)
            final = self.cutover(session, baseline, receipt)
            receipt.advance(final, prove_final=self.final_proof)
        after = self.manifest()
        self.assertEqual(after['after'], manifest['after'])
        self.assertEqual(after['runtime']['files'], manifest['runtime']['files'])
        self.call('reattest-runtime')
        self.assertEqual(self.write_calls, 1)

    def test_install_only_and_stale_or_unknown_receipts_never_stop(self):
        h, f = self.h, self.f
        original = self.manifest()

        def stale(receipt):
            receipt['runtime']['invocations'][0] = '9' * 32

        for edit in (lambda m: m.pop('currentApply'), lambda m: m['runtime'].pop('pids'), stale,
                     lambda m: m.update(phase='apply-profiles-pending'), lambda m: m.update(unknown=True)):
            with self.subTest(edit=edit):
                changed = copy.deepcopy(original)
                edit(changed)
                f.put(f.manifest_path, h['encode'](changed), 0o600)
                before = f.image()
                with self.session() as session, self.assertRaises(WindowError):
                    self.capture(session)
                self.assertEqual(f.image(), before)
        self.assertEqual(self.effects(), [])

    def test_orphaned_stage_is_evidence_not_cleanup_permission(self):
        f = self.f
        scratch = str(Path(f.manifest_path).with_name('.direct-' + 'a' * 32))
        f.put(scratch, b'orphaned staging evidence', 0o600)
        before = f.image()
        with self.session() as session, self.assertRaises(WindowError):
            self.capture(session)
        self.assertEqual(f.image(), before)
        self.assertEqual(self.effects(), [])

    def test_profile_guard_drift_refuses_before_publication(self):
        h = self.h
        cfg = json.loads(self.candidate)
        for row in cfg['routing']['rules'][:2]:
            row['ip'] = ['geoip:loopback']
        with self.session() as session:
            baseline, receipt = self.capture(session)
            session.stop()
            pending = session.capture(baseline, h['encode'](cfg))
            with self.assertRaises(WindowError):
                receipt.check_drained(pending)
        self.assertEqual(self.main.read_bytes(), self.original)
        self.assertEqual(self.effects(), ['stop'])

    def test_manifest_cas_rechecks_exclusion_after_staging(self):
        h = self.h
        with self.session() as session:
            baseline, receipt = self.capture(session)
            final = self.cutover(session, baseline, receipt)
            prior = self.manifest()
            def write(*args, **kw):
                reader = kw['reader']
                def veto_at_staged_read(path):
                    if any(self.f.physical(path).parent.glob('.direct-*')):
                        self.permit_writers = False
                    return reader(path)
                return self.count_write(*args, **(kw | dict(reader=veto_at_staged_read)))
            receipt._direct.write = write
            with self.assertRaisesRegex(WindowError, UNCONFIRMED):
                receipt.advance(final, prove_final=self.final_proof)
        self.assertEqual(self.manifest(), prior)
        self.assertEqual(self.write_calls, 1)
        self.assertEqual(list(self.f.physical(h['VAULT']).rglob('.direct-*')), [])

    def test_lost_ack_after_real_write_stays_unknown_and_never_replays(self):
        with self.session() as session:
            baseline, receipt = self.capture(session)
            final = self.cutover(session, baseline, receipt)
            def write(*args, **kwargs):
                self.count_write(*args, **kwargs)
                raise OSError('modeled lost acknowledgement')
            receipt._direct.write = write
            with self.assertRaisesRegex(WindowError, UNCONFIRMED):
                receipt.advance(final, prove_final=self.final_proof)
            with self.assertRaises(WindowError):
                receipt.advance(final, prove_final=self.final_proof)
        self.assertEqual(self.manifest()['runtime']['pids'][0], str(final.xray.pid))
        self.assertEqual(self.write_calls, 1)


    def test_same_byte_manifest_replacement_at_staged_cas_is_preserved(self):
        p = self.f.physical(self.f.manifest_path)
        changed = []
        with self.session() as session:
            baseline, receipt = self.capture(session)
            final = self.cutover(session, baseline, receipt)
            prior = p.read_bytes()
            def write(*args, **kw):
                reader = kw['reader']
                def replace_at_staged_read(path):
                    if list(p.parent.glob('.direct-*')):
                        self.rewrite_same(p)
                        changed.append(p.stat().st_ino)
                    return reader(path)
                return self.count_write(*args, **(kw | dict(reader=replace_at_staged_read)))
            receipt._direct.write = write
            with self.assertRaisesRegex(WindowError, UNCONFIRMED):
                receipt.advance(final, prove_final=self.final_proof)
        self.assertEqual(changed, [p.stat().st_ino])
        self.assertEqual(p.read_bytes(), prior)
        self.assertEqual(self.write_calls, 1)


class ActiveBridgeReceiptHost(ReceiptFixture):
    active_bridge = True

    def test_active_bridge_epoch_preserved_in_fenced_chap_phase(self):
        h, f = self.h, self.f
        users = [dict(login='synthetic', password='fixture-only', ipAddress='10.60.0.4', enabled=True)]
        self.call('sync-chap', currentUsers=[], desiredUsers=users)
        self.call('fence-chap', currentUsers=users, desiredUsers=users, generation=None)
        self.write_calls = 0
        before = self.manifest()
        self.assertIsNotNone(h['chap_generation'](before['phase']))
        with self.session() as session:
            baseline, receipt = self.capture(session)
            final = self.cutover(session, baseline, receipt)
            receipt.advance(final, prove_final=self.final_proof)
        after = self.manifest()
        self.assertEqual(after['currentApply']['bridgeUnit'], before['currentApply']['bridgeUnit'])
        self.assertEqual(after['currentApply']['files']['bridge'], before['currentApply']['files']['bridge'])
        self.assertEqual(after['runtime']['pids'][1:], before['runtime']['pids'][1:])
        self.assertEqual(after['phase'], before['phase'])
        self.assertEqual(after['currentChap'], before['currentChap'])
        self.call('reattest-runtime')
        self.assertEqual(self.call('check-chap', currentUsers=users, desiredUsers=users)['generation'],
                         h['chap_generation'](before['phase']))
        self.assertEqual(self.write_calls, 1)

    def test_foreign_remaining_bridge_listener_cannot_be_rebased(self):
        with self.session() as session:
            baseline, receipt = self.capture(session)
            final = self.cutover(session, baseline, receipt)
            self.f.rows.append(('tcp', '127.0.0.1', 9444, ['76']))
            with self.assertRaises(WindowError):
                receipt.advance(final, prove_final=self.final_proof)
        self.assertEqual(self.write_calls, 0)


class open_lock:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        return self.fd

    def __exit__(self, *_):
        os.close(self.fd)


if __name__ == '__main__':
    unittest.main()
