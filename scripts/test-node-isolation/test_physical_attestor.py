"""Local file/syscall evidence; UID, physical identity and systemd are SIMULATED."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('attestor', HERE / 'physical_attestor.py')
a = importlib.util.module_from_spec(spec) if spec and (HERE / 'physical_attestor.py').exists() else SimpleNamespace()
if (HERE / 'physical_attestor.py').exists():
    spec.loader.exec_module(a)


class InstallationTests(unittest.TestCase):
    def test_installation_hash_and_metadata_come_from_current_files_not_plan(self):
        self.assertTrue(hasattr(a, 'installation'), 'finite physical installation readback missing')
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            runner = root / 'runner'
            runner.write_bytes(b'actual installed bytes\n')
            runner.chmod(0o750)
            config = root / 'config'
            config.mkdir(mode=0o755)
            # Explicit local UID simulation, never exposed by the CLI.
            def read(path, directory=False):
                path = Path(path)
                st = path.lstat()
                return (b'' if directory else path.read_bytes(),
                        SimpleNamespace(st_uid=0, st_gid=0, st_mode=st.st_mode))
            paths = {'runner': str(runner), 'config': str(config), 'unit': str(root / 'unit')}
            value = a.installation('xray-main', None, read=read, paths=paths)
            import hashlib
            self.assertEqual(value['runner']['sha256'], 'sha256:' + hashlib.sha256(runner.read_bytes()).hexdigest())
            self.assertEqual(value['runner']['mode'], '0750')
            self.assertTrue(value['profile']['configDirectoryReady'])
            runner.write_bytes(b'changed bytes')
            self.assertNotEqual(a.installation('xray-main', None, read=read, paths=paths)['runner']['sha256'], value['runner']['sha256'])
            runner.chmod(0o770)
            with self.assertRaisesRegex(Exception, 'UNSAFE_RUNNER'):
                a.installation('xray-main', None, read=read, paths=paths)


    def test_observe_consumes_actual_engine_and_freezer_startticks_schema_and_checks_both_sides(self):
        import test_isolation as fixture
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root:
            engine = fixture.EngineTests().engine(root)
            fixture.fixture_hold(engine)
            engine.host.physical = lambda: {k: engine.plan[k] for k in ('machineId', 'bootId', 'sshHostKeySha256')}
            # Real dedicated engine/journal underneath a simulated shared hook.
            proxy = SimpleNamespace(plan={**engine.plan, 'hostHold': {'owner': 'accepted-host-owner'}},
                                    assert_held=engine.assert_held, host=engine.host, plan_hash=engine.plan_hash)
            current = {'containers': [{'name': 'hysteria-backend', 'id': 'b' * 64,
                                      'init': {'pid': 777, 'startTicks': '991', 'session': 777}}]}
            engine.host.host_hold = lambda: current
            guard = {'pid': 888, 'start': '900', 'socket': 'fixture'}
            with patch.object(a, 'installation', return_value={'runner': {}, 'profile': {}}), \
                 patch.object(a, 'config_snapshot', return_value={'simulated': True}), \
                 patch.object(a, 'runner_state', return_value={'head': None}), \
                 patch.object(a, 'secure_read', return_value=(json.dumps(guard).encode(), None)):
                value = a.observe(proxy, fixture.m, True)
                self.assertEqual(value['host']['backend']['processStartTime'], '991')
                self.assertEqual(value['host']['backend']['pid'], 777)
                self.assertEqual(value['guard'], engine.read()['guard'])
                engine.host.alive = False
                with self.assertRaisesRegex(fixture.m.Refusal, 'RECOVERY_GUARD_LOST'):
                    a.observe(proxy, fixture.m, True)
                self.assertEqual(engine.read()['phase'], 'held', 'readback never rewrites/restores external state')
                self.assertNotIn(('restore',), engine.host.events)

    def test_runner_state_reads_actual_close_journal_and_never_executes_or_writes(self):
        import test_isolation as fixture
        import subprocess
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / 'var/lib').mkdir(parents=True)
            (root / 'proc/sys/kernel/random').mkdir(parents=True)
            plan = fixture.PlanTests().plan()
            (root / 'proc/sys/kernel/random/boot_id').write_text(plan['bootId'] + '\n')
            values = {'command': 'close', 'operation-id': 'op-local', 'node-id': plan['nodeId'], 'candidate-hash': 'sha256:' + 'a' * 64,
                      'backup-id': 'backup-local', 'target-profile': plan['targetProfile'], 'execution-context': plan['context'],
                      'attempt-id': 'attempt-local', 'generation': 'generation-local', 'predecessor-generation': 'none', 'command-id': 'close-local'}
            runner = HERE.parents[1] / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
            args = [part for k, v in values.items() for part in ('--' + k, v)]
            closed = subprocess.run(['/bin/bash', str(runner), *args], env={**os.environ, 'CELERITY_TOPOLOGY_ROOT': str(root)}, capture_output=True)
            self.assertEqual(closed.returncode, 0, closed.stderr)
            receipt = json.loads(closed.stdout)
            predecessor = {'binding': {'generation': values['generation'], 'commandIds': {'close': values['command-id']}}}
            journal = root / 'var/lib/celerity/topology/fences/xray-main/journal.json'
            before = journal.read_bytes()
            with patch.object(a, 'Path', lambda fixed: root / str(fixed).lstrip('/')), \
                 patch.object(a, 'secure_read', lambda path, directory=False: (Path(path).read_bytes(), None)), \
                 patch.object(fixture.m, 'Host', lambda: SimpleNamespace(unit=lambda _: {'Job': ''})):
                value = a.runner_state(plan, fixture.m, predecessor)
                self.assertEqual(value['head'], 'generation-local')
                self.assertEqual(value['terminal'], {**receipt, 'command': 'status'})
                self.assertEqual(journal.read_bytes(), before)
                journal.with_name('journal.next').write_text('{}')
                with self.assertRaisesRegex(RuntimeError, 'RUNNER_UNKNOWN_RETAINED'):
                    a.runner_state(plan, fixture.m, predecessor)
                self.assertEqual(journal.read_bytes(), before)

    def test_attestation_request_deadline_interrupts_readback_without_restoring_state(self):
        import test_isolation as fixture
        import signal
        import time
        import io
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root:
            engine = fixture.EngineTests().engine(root)
            fixture.fixture_hold(engine)
            (Path(root) / 'lock').touch()
            readfd, writefd = os.pipe()
            os.write(writefd, (json.dumps({'nonce': 'a' * 64, 'predecessor': None}) + '\n').encode())
            os.close(writefd)
            previous = signal.getsignal(signal.SIGALRM)
            try:
                with os.fdopen(readfd, 'r') as inp, patch.object(fixture.m, 'STATE', root), \
                     patch.object(a, 'REQUEST_TIMEOUT_SECONDS', 0.03, create=True), \
                     patch.object(a, 'durable_originals', return_value={'SIMULATED': True}), \
                     patch.object(a, 'observe', side_effect=lambda *_: time.sleep(2)):
                    started = time.monotonic()
                    with self.assertRaisesRegex(RuntimeError, 'PHYSICAL_ATTESTOR_TIMEOUT_RETAINED'):
                        a.serve(engine, fixture.m, None, inp=inp, out=io.StringIO())
                    self.assertLess(time.monotonic() - started, 0.5)
                    self.assertEqual(engine.read()['phase'], 'held')
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)

    def test_runtime_durable_originals_reads_existing_bundle_after_candidate_mutation_without_recapture(self):
        import capture_fixture as fixture
        with fixture.t.Fixture() as node:
            node.module.decode_json = fixture.t.n.decode
            node.writer.capture()
            before = node.fs.read(fixture.t.n.BUNDLE)[0]
            node.put(node.config, b'{"candidate":"changed after enrollment"}')
            def read(path, directory=False):
                with node.fs.opened(path, directory=directory) as fd:
                    st = os.fstat(fd)
                    return (b'' if directory else node.fs.read(path)[0],
                            SimpleNamespace(st_uid=0, st_gid=0, st_mode=st.st_mode, st_nlink=st.st_nlink))
            self.assertTrue(hasattr(a, 'durable_originals'), 'ordinary attestor cannot yet verify accepted durable originals')
            value = a.durable_originals(node.engine, node.module, read=read)
            self.assertEqual(value['readback']['configSha256'], node.accepted['profiles'][node.profile]['files']['config']['sha256'])
            self.assertEqual(node.fs.read(fixture.t.n.BUNDLE)[0], before)
            self.assertNotIn('private', json.dumps(value))
            for fault in ['missing', 'bytes', 'identity', 'guard', 'runtime', 'partial']:
                with self.subTest(fault=fault):
                    if fault == 'missing': node.path(fixture.t.n.BUNDLE).unlink()
                    elif fault == 'partial': node.put(fixture.t.n.BUNDLE+'.next', b'{}')
                    else:
                        bundle = json.loads(before)
                        if fault == 'bytes': bundle['profiles'][node.profile]['files']['config']['data'] = 'Zm9yZWlnbg=='
                        if fault == 'identity': bundle['bootId'] = 'foreign'
                        if fault == 'guard': bundle['guard']['pid'] += 1
                        if fault == 'runtime': bundle['profiles'][node.profile]['runtime'] = {'mode': 'none', 'inbounds': {'foreign': []}}
                        node.put(fixture.t.n.BUNDLE, fixture.a.canonical(bundle))
                    with self.assertRaises(Exception): a.durable_originals(node.engine, node.module, read=read)
                    node.put(fixture.t.n.BUNDLE, before)
                    node.path(fixture.t.n.BUNDLE+'.next').unlink(missing_ok=True)

    def test_runtime_durable_originals_requires_the_dual_profile_backup_too(self):
        import test_node_originals as fixture
        with fixture.DualFixture() as node:
            node.module.decode_json = fixture.n.decode
            node.writer.capture()
            before = node.fs.read(fixture.n.BUNDLE)[0]
            def read(path, directory=False):
                with node.fs.opened(path, directory=directory) as fd:
                    st = os.fstat(fd)
                    return (b'' if directory else node.fs.read(path)[0],
                            SimpleNamespace(st_uid=0, st_gid=0, st_mode=st.st_mode, st_nlink=st.st_nlink))
            self.assertEqual(a.durable_originals(node.engine, node.module, read=read)['version'], 1)
            for fault in ['missing-profile', 'other-profile-bytes', 'metadata', 'accepted', 'mode']:
                with self.subTest(fault=fault):
                    bundle = json.loads(before)
                    if fault == 'missing-profile': del bundle['profiles']['xray-main']
                    if fault == 'other-profile-bytes': bundle['profiles']['xray-main']['files']['config']['data'] = 'Zm9yZWlnbg=='
                    if fault == 'metadata': bundle['profiles']['xray-main']['files']['unit']['uid'] += 1
                    if fault == 'accepted': bundle['acceptedSha256'] = 'f'*64
                    node.put(fixture.n.BUNDLE, fixture.n.canonical(bundle))
                    if fault == 'mode': node.path(fixture.n.BUNDLE).chmod(0o640)
                    with self.assertRaises(Exception): a.durable_originals(node.engine, node.module, read=read)
                    node.put(fixture.n.BUNDLE, before)

    def test_shared_mode_requires_the_actual_installed_shared_engine_hook(self):
        self.assertTrue(hasattr(a, 'select_engine'), 'shared engine selector missing')
        with self.assertRaisesRegex(RuntimeError, 'SHARED_HOST_ATTESTATION_HOOK_REQUIRED'):
            a.select_engine(SimpleNamespace(), {'mode': 'shared-test'})

    def test_bridge_hash_and_loaded_unit_are_read_from_actual_file(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            paths = {'runner': str(root / 'runner'), 'config': str(root / 'config'), 'unit': str(root / 'unit')}
            Path(paths['runner']).write_bytes(b'installed runner'); Path(paths['runner']).chmod(0o750)
            Path(paths['config']).mkdir(mode=0o755)
            Path(paths['unit']).write_bytes(b'installed bridge unit\n'); Path(paths['unit']).chmod(0o644)
            def read(path, directory=False):
                path = Path(path)
                return (b'' if directory else path.read_bytes(), SimpleNamespace(st_uid=0, st_gid=0, st_mode=path.lstat().st_mode))
            state = {'FragmentPath': paths['unit'], 'DropInPaths': '', 'LoadState': 'loaded', 'UnitFileState': 'enabled'}
            host = SimpleNamespace(unit=lambda _: state)
            import hashlib
            value = a.installation('xray-bridge', host, read=read, paths=paths)
            self.assertEqual(value['profile']['bridgeUnitSha256'], 'sha256:' + hashlib.sha256(Path(paths['unit']).read_bytes()).hexdigest())
            for field, bad in [('DropInPaths', '/etc/override.conf'), ('FragmentPath', '/usr/lib/systemd/system/xray-bridge.service'), ('UnitFileState', 'masked')]:
                original = state[field]; state[field] = bad
                with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'BRIDGE_UNIT_DRIFT'):
                    a.installation('xray-bridge', host, read=read, paths=paths)
                state[field] = original

if __name__ == '__main__':
    unittest.main()
