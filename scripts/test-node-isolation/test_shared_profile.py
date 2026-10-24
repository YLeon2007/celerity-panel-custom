"""Shared relay regression: real files/flocks/runner; physical/systemd/RPC simulated."""
import copy
import unittest
import test_node_originals as t
import node_originals as n
import coordinated_capture as capture
import coordinated_restore as restore
import test_shared_host as shared

NODE = '6ab189dc63913ebd4a917399'

class SharedFixture(t.DualFixture):
    def __enter__(self):
        super().__enter__()
        self.node = NODE
        self.plan.update(nodeId=NODE, endpointIp='212.119.42.100', targetProfile='xray-bridge')
        self.path(n.runner_lock('xray-main')).unlink()
        self.accepted.update(n.identity(self.engine))
        self.put(n.ACCEPTED, n.canonical(self.accepted))
        self.writer = n.NodeOriginals(self.engine, self.module, fixture=self.fixture)
        return self

    def mutate_and_admit(self, receipt):
        # Only bridge is an executed profile. Main has NO runner generation.
        t.Fixture.mutate_and_admit(self, receipt)
        self.restore_pins['profiles']['xray-main'] = {
            'files': copy.deepcopy(self.accepted['profiles']['xray-main']['files']),
            'service': copy.deepcopy(self.accepted['profiles']['xray-main']['service']),
            'journalSha256': None,
        }
        self.put(n.RESTORE_ACCEPTED, n.canonical(self.restore_pins))

class SharedProfileTests(unittest.TestCase):
    def test_shared_plan_requires_bridge_and_keeps_both_native_units(self):
        p = shared.plan()
        p['targetProfile'] = 'xray-bridge'
        if '/system.slice/xray-bridge.service' not in p['keepCgroups']:
            p['keepCgroups'].append('/system.slice/xray-bridge.service')
        self.assertEqual(shared.s.validate_plan(p, shared.m), p)
        for fault in ('main', 'no-main-survivor', 'no-bridge-survivor'):
            bad = copy.deepcopy(p)
            if fault == 'main': bad['targetProfile'] = 'xray-main'
            else: bad['keepCgroups'].remove('/system.slice/' + ('xray.service' if fault == 'no-main-survivor' else 'xray-bridge.service'))
            with self.subTest(fault=fault), self.assertRaises(shared.m.Refusal):
                shared.s.validate_plan(bad, shared.m)

    def test_capture_restore_originals_agree_on_bridge_execution(self):
        for module in (n, capture, restore):
            with self.subTest(module=module.__name__):
                self.assertEqual(module.NODES[NODE], ('212.119.42.100', 'xray-bridge'))

    def test_bridge_return_preserves_main_files_service_runtime_and_no_generation(self):
        with SharedFixture() as f:
            self.assertEqual(f.writer.profiles, ['xray-main', 'xray-bridge'])
            original = f.writer.snapshot('xray-main')
            receipt = f.writer.capture()
            self.assertEqual(set(f.fs.read_json(n.BUNDLE)['profiles']), {'xray-main', 'xray-bridge'})
            f.mutate_and_admit(receipt)
            writer = n.NodeOriginals(f.engine, f.module, fixture=f.fixture)
            writer.restore()
            self.assertEqual(writer.snapshot('xray-main'), original)
            self.assertTrue(f.fs.absent(n.runner_journal('xray-main')))
            self.assertFalse(any(event[1] == 'xray.service' for event in f.system.events))
            self.assertIn(('restart', 'xray-bridge.service'), f.system.events)
            self.assertEqual(f.path('/etc/ppp/chap-secrets').read_bytes(), b'PPP-untouched-fixture')

    def test_live_main_nonempty_users_and_process_survive_bridge_return(self):
        # Actual loopback Xray + dynamic RPC user; only bridge systemd is modeled.
        with t.RuntimeFixture() as f:
            child = f.system.child
            f.node, f.profile = NODE, 'xray-bridge'
            f.plan.update(nodeId=NODE, endpointIp='212.119.42.100', targetProfile=f.profile)
            f.path(n.runner_lock('xray-main')).unlink()
            f.config, f.unit = n.profile_paths(f.profile)
            f.accepted.update(n.identity(f.engine))
            f.system.states['xray-bridge.service'] = {
                **copy.deepcopy(f.system.states['xray.service']),
                'Id': 'xray-bridge.service', 'FragmentPath': f.unit,
            }
            f.accepted['profiles'][f.profile] = {
                'files': f.writer_files(), 'service': copy.deepcopy(f.system.states['xray-bridge.service']),
                'runtimeSha256': n.sha(n.canonical({'mode': 'none', 'inbounds': {}})),
            }
            f.put(n.ACCEPTED, n.canonical(f.accepted))
            writer = n.NodeOriginals(f.engine, f.module, fixture=f.fixture)
            action = f.system.action
            def bridge_action(verb, service=None, locks=()):
                self.assertNotEqual(service, 'xray.service', 'preserved main was mutated')
                return t.SimulatedSystem.action(f.system, verb, service, locks)
            f.system.action = bridge_action
            try:
                receipt = writer.capture()
                original = f.fs.read_json(n.BUNDLE)['profiles']['xray-main']
                self.assertTrue(original['runtime']['inbounds']['subscription'])
                SharedFixture.mutate_and_admit(f, receipt)
                writer = n.NodeOriginals(f.engine, f.module, fixture=f.fixture)
                writer.restore()
                self.assertEqual(writer.snapshot('xray-main'), original)
                self.assertIs(f.system.child, child)
                self.assertIsNone(child.poll())
                self.assertTrue(f.fs.absent(n.runner_journal('xray-main')))
            finally:
                f.system.action = action

    def test_fresh_main_without_runner_lock_or_journal_can_be_preserved(self):
        with SharedFixture() as f:
            self.assertTrue(f.fs.absent(n.runner_lock('xray-main')))
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            writer = n.NodeOriginals(f.engine, f.module, fixture=f.fixture)
            with writer.restoration_hold() as held:
                self.assertNotIn(n.runner_lock('xray-main'), writer.lock_paths)
                held.restore()
                held.verify()
            self.assertTrue(f.fs.absent(n.runner_lock('xray-main')))
            self.assertTrue(f.fs.absent(n.runner_journal('xray-main')))
            self.assertFalse(any(event[1] == 'xray.service' for event in f.system.events))

    def test_main_runner_lock_or_pending_generation_refuses_before_effects(self):
        for path in (n.runner_lock('xray-main'), n.runner_journal('xray-main').replace('journal.json', 'journal.next')):
            with self.subTest(path=path), SharedFixture() as f:
                receipt = f.writer.capture()
                f.mutate_and_admit(receipt)
                f.put(path, b'foreign')
                with self.assertRaisesRegex(n.Refusal, 'PRESERVED_PROFILE_GENERATION_RETAINED'):
                    n.NodeOriginals(f.engine, f.module, fixture=f.fixture).restore()
                self.assertEqual(f.system.events, [])

    def test_main_drift_refuses_before_any_service_effect(self):
        with SharedFixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            f.put(n.profile_paths('xray-main')[0], b'{"foreign-main":true}')
            with self.assertRaises(n.Refusal):
                n.NodeOriginals(f.engine, f.module, fixture=f.fixture).restore()
            self.assertEqual(f.system.events, [])

    def test_main_runner_generation_cannot_be_adopted_as_preserved(self):
        with SharedFixture() as f:
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)
            f.put(n.runner_journal('xray-main'), b'{"foreign-generation":true}')
            with self.assertRaises(n.Refusal):
                n.NodeOriginals(f.engine, f.module, fixture=f.fixture).restore()
            self.assertEqual(f.system.events, [])

if __name__ == '__main__': unittest.main()
