"""Actual Engine + actual marker closure + durable restore; physical facts SIMULATED.

Local filesystem, fsync, xattrs, locks and the runner-generated journal are real.
UID/recovery/SSH/systemd are explicit fixture adapters, not operational proof.
"""
import os
from pathlib import Path
import shlex
import unittest
from unittest.mock import patch

import test_isolation as isolation_fixture
from test_node_originals import Fixture, n

m = isolation_fixture.m


class OriginalsDispatchIntegration(unittest.TestCase):
    def test_actual_closure_authorizes_finite_restore_but_never_reopens_dispatch(self):
        with Fixture() as f:
            plan = isolation_fixture.PlanTests().plan()
            plan.update(f.plan)
            host = isolation_fixture.EngineTests.FixtureHost()
            host.physical = f.engine.host.physical
            host.held_current_runner_head = m.Host().held_current_runner_head
            f.engine = m.Engine(f.path(n.STATE), plan, host)
            isolation_fixture.fixture_hold(f.engine)
            f.plan = plan
            # Installed-byte pin is the exact integrated helper, not a facade.
            f.put(n.HELPER, (Path(__file__).parent / 'isolation.py').read_bytes())
            f.accepted.update(n.identity(f.engine))
            f.accepted['isolationSha256'] = n.sha(f.path(n.HELPER).read_bytes())
            f.put(n.ACCEPTED, n.canonical(f.accepted))
            f.writer = n.NodeOriginals(f.engine, m, fixture=f.fixture)
            before = f.engine.read()
            receipt = f.writer.capture()
            f.mutate_and_admit(receipt)  # Real runner close; fixture also supplies current pins.
            # Discard only the synthetic fixture marker: actual close_dispatch must publish it.
            f.path(n.ADMISSION).unlink()
            lock = os.open(f.path(n.OUTER_LOCK), os.O_RDWR)
            try:
                with (patch.object(m.os, 'geteuid', return_value=0),
                      patch.object(m, 'RUNNER_FENCES', str(f.path('/var/lib/celerity/topology/fences'))),
                      patch.object(m, 'secure_file', side_effect=lambda path: Path(path).read_bytes())):
                    closed = f.engine.close_dispatch(lock)
                self.assertEqual(closed['nodeEffects'], 'drained')
                self.assertEqual(closed['dispatchAdmission'], 'closed')
            finally:
                os.close(lock)
            marker = f.path(n.ADMISSION).read_bytes()
            values = ['close', 'operation-1', plan['nodeId'], 'sha256:' + 'e' * 64,
                      'backup-1', plan['targetProfile'], plan['context'], 'attempt-1',
                      'generation-1', 'none', 'close-1']
            argv = [x for pair in zip(['--' + k for k in m.NAMES], values) for x in pair]
            original = shlex.join([m.RUNNER, *argv])
            for phase in ('before', 'after'):
                with patch.object(m.subprocess, 'run') as run:
                    with self.assertRaisesRegex(m.Refusal, 'DISPATCH_ADMISSION_CLOSED_RETAINED'):
                        f.engine.dispatch(original, b'', 0)
                    run.assert_not_called()
                if phase == 'before':
                    # The exact module's exported compatibility contract must correspond
                    # to its actually enforced dispatch gate, not a SimpleNamespace boolean.
                    self.assertEqual(getattr(m, 'RESTORE_ADMISSION_VERSION', None), 1)
                    restored = n.NodeOriginals(f.engine, m, fixture=f.fixture).restore()
                    self.assertEqual(restored['code'], 'NODE_ORIGINALS_RESTORED_RETAINED')
                    self.assertEqual(f.path(f.config).read_bytes(), f.original)
                    self.assertEqual(f.fs.read_json(n.RESTORE_STATE)['phase'], 'verified-retained')
            self.assertEqual(f.path(n.ADMISSION).read_bytes(), marker)
            self.assertEqual(f.engine.read(), before)
            self.assertFalse(any(e[0] == 'restore' for e in host.events))
            with self.assertRaises(m.Refusal):
                f.engine.restore()


if __name__ == '__main__':
    unittest.main()
