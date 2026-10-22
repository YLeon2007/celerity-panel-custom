"""Real supervisor/Node exec/HTTP/proc/SCM_RIGHTS/five channels and journals.

Physical inventory is simulated by launch_fixture. Deterministic cases add a
supervisor-local logical clock and delay delivery of a REAL observation. The
wall-clock case sleeps past the real original Popen boundary. Identity-read
faults are explicitly simulated; child death is a real signal/wait. None of
these tests establishes actual application performance or physical authority.
"""
import atexit
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
import unittest

from test_fresh_classic_launch import launch_fixture, load


def inject_startup_fault(m, platform, root, mode):
    """Child-only seam; real exec/HTTP/proc remain in use, never invent success."""
    baseline = os.environ.get('C3_DEADLINE_BASELINE_SOURCE')
    source = Path(baseline) if baseline is not None else Path(m.__file__)
    if baseline is not None:
        # Immutable RED replay, never reset or overwrite the checked-out source.
        exec(compile(source.read_bytes(), str(source), 'exec'), m.__dict__)
    origin = time.monotonic()
    clock = [origin]
    real_popen = m.subprocess.Popen
    real_observe = platform.observe
    began = [0.0]
    calls = [0]
    faults = [False]
    children = []

    def record(event, **values):
        line = json.dumps({'event':event, 'elapsed':clock[0]-origin, **values})+'\n'
        with (root/'fresh/deadline.jsonl').open('a') as out:
            out.write(line)
        evidence = os.environ.get('C3_DEADLINE_EVIDENCE_DIR')
        if evidence:
            with (Path(evidence)/(mode+'.jsonl')).open('a') as out:
                out.write(line)

    def reap(child):
        child.wait()
        record('reaped', pid=child.pid, returncode=child.returncode)

    def popen(*args, **kwargs):
        began[0] = time.monotonic()
        child = real_popen(*args, **kwargs)
        children.append(child)
        record('popen', pid=child.pid, start=m.start(child.pid), at=began[0])
        # Test-only reaping after unknown, after the finite channel is closed.
        # Only disposable-fixture teardown sends TERM; never product recovery.
        atexit.register(reap, child)
        if mode == 'popen-boundary':
            clock[0] += 3.0
        if mode == 'popen-partial':
            clock[0] += 1.0
        if mode == 'dead-before-observe':
            child.kill(); child.wait(timeout=2)
            record('child-dead', pid=child.pid)
        return child

    def sleep(seconds):
        time.sleep(seconds)
        if mode == 'retry-sleep-boundary' and faults[0]:
            clock[0] = origin+3.0

    def observe(self, policy, pid):
        calls[0] += 1
        record('observe-enter', call=calls[0])
        if mode in ('retry-before', 'retry-boundary', 'retry-sleep-boundary') and not faults[0]:
            faults[0] = True
            clock[0] = origin+2.9
            record('readiness-error')
            raise OSError('injected initial readiness error')
        # Normal readiness errors are real, without advancing the logical clock.
        # Every successful result requires actual socket ownership/HTTP bytes.
        if mode == 'identity-boundary' and not faults[0]:
            real_probe = m.bound_http_probe
            real_start = m.start
            def probe(*args):
                body = real_probe(*args)
                # Simulated final identity read drift AFTER the real HTTP/proc
                # proof, not a fabricated serving result or actual PID reuse.
                clock[0] = origin+2.9
                m.start = lambda checked: '0' if checked == pid else real_start(checked)
                return body
            m.bound_http_probe = probe
            try:
                result = real_observe(self, policy, pid)
            except RuntimeError as error:
                if str(error) == 'SERVING_PID_REUSED':
                    faults[0] = True
                    record('identity-refused', reason=str(error))
                raise
            finally:
                m.bound_http_probe = real_probe
                m.start = real_start
        else:
            result = real_observe(self, policy, pid)
        if mode == 'wall-late':
            time.sleep(max(0, began[0]+3.03-time.monotonic()))
        else:
            elapsed = 2.999 if mode in ('before-boundary', 'retry-before', 'dead-after-observe') else 3.0
            if mode in ('after-boundary', 'retry-boundary'):
                elapsed = 3.001
            if mode == 'body-boundary' and not faults[0]:
                elapsed = 2.9
            clock[0] = origin+elapsed
        record('observe-success', serving=result, at=time.monotonic())
        if mode == 'body-boundary' and not faults[0]:
            faults[0] = True
            result = dict(result, bodySha256='0'*64)
            record('body-corrupted')  # explicit invalid-proof injection
        if mode == 'dead-after-observe':
            children[0].kill(); children[0].wait(timeout=2)
            record('child-dead', pid=pid)
        return result

    record('source', sha256=m.digest(source.read_bytes()), mode=mode,
           clock='real' if mode == 'wall-late' else 'injected-monotonic')
    m.subprocess = SimpleNamespace(Popen=popen)
    if mode != 'wall-late':
        # Keep coordinated_restore.Wire on real monotonic protocol deadlines.
        m.time = SimpleNamespace(monotonic=lambda:clock[0], sleep=sleep)
    platform.observe = observe


class StrictStartupDeadlineTests(unittest.TestCase):
    def test_success_observation_finishing_exactly_at_three_seconds_is_unknown(self):
        events = self.assert_unknown('exact-boundary')
        self.assertEqual(self.successes(events)[-1]['elapsed'], 3.0)

    def test_success_observation_finishing_after_three_seconds_is_unknown(self):
        self.assert_unknown('after-boundary')

    def test_popen_consuming_entire_budget_prevents_even_first_observation(self):
        events = self.assert_unknown('popen-boundary')
        self.assertFalse(any(row['event'] == 'observe-enter' for row in events))

    def test_popen_time_is_not_rebased_after_return(self):
        self.assert_unknown('popen-partial')

    def test_error_then_late_success_does_not_reset_original_deadline(self):
        events = self.assert_unknown('retry-boundary')
        self.assertTrue(any(row['event'] == 'readiness-error' for row in events))
        self.assertTrue(self.successes(events))

    def test_expiry_during_retry_sleep_prevents_next_observation(self):
        events = self.assert_unknown('retry-sleep-boundary')
        self.assertEqual(sum(row['event'] == 'observe-enter' for row in events), 1)

    def test_invalid_body_does_not_authorize_confirmation_or_reset_deadline(self):
        events = self.assert_unknown('body-boundary')
        self.assertTrue(any(row['event'] == 'body-corrupted' for row in events))
        self.assertGreaterEqual(len(self.successes(events)), 2)

    def test_invalid_identity_proof_does_not_authorize_late_confirmation(self):
        events = self.assert_unknown('identity-boundary')
        self.assertTrue(any(row['event'] == 'identity-refused' for row in events))
        self.assertTrue(self.successes(events))

    def test_child_death_before_observation_refuses_without_probe(self):
        events = self.assert_unknown('dead-before-observe', eventual_serving=False)
        self.assertFalse(any(row['event'] == 'observe-enter' for row in events))

    def test_real_child_death_after_valid_observation_refuses_within_budget(self):
        self.assert_unknown('dead-after-observe', eventual_serving=False)

    def test_real_slow_successful_probe_cannot_confirm_after_wall_deadline(self):
        events = self.assert_unknown('wall-late')
        began = next(row['at'] for row in events if row['event'] == 'popen')
        self.assertGreaterEqual(self.successes(events)[-1]['at']-began, 3.03)

    def test_valid_full_proof_just_before_boundary_completes(self):
        self.assert_confirmed('before-boundary')

    def test_readiness_error_then_valid_full_proof_before_boundary_completes(self):
        events = self.assert_confirmed('retry-before')
        self.assertTrue(any(row['event'] == 'readiness-error' for row in events))

    @staticmethod
    def events(f):
        return [json.loads(line) for line in (f.root/'deadline.jsonl').read_text().splitlines()]

    @staticmethod
    def successes(events):
        return [row for row in events if row['event'] == 'observe-success']

    def assert_confirmed(self, mode):
        m = load()
        with launch_fixture(m, startup_fault=mode) as f:
            result = f.launch()
            self.assertEqual(result['code'], 'COMMITTED_FRESH_ACTIVATION_CONFIRMED')
            self.assertEqual(result['candidate'], 'closed')
            self.assertEqual(result['serving'], f.platform.observe(f.fs.read_json(m.POLICY), result['serving']['pid']))
            self.assertEqual(f.fs.read_json(m.SUPERVISOR_ATTEMPT)['phase'], 'completed')
            self.assertEqual(f.fs.read_json(m.ATTEMPT)['phase'], 'confirmed')
            self.assertEqual(f.count(), 1)
            self.assertTrue(all(n.fs.read_json('/fixture-live.json')['candidateFrozen'] for n in f.fixtures))
            return self.events(f)

    def assert_unknown(self, mode, *, eventual_serving=True):
        m = load()
        with launch_fixture(m, fault='expected-refusal', startup_fault=mode) as f:
            with self.assertRaises(BaseException) as caught:
                f.launch()
            self.assertEqual(getattr(caught.exception, 'code', None), 'COMMITTED_ACTIVATION_UNKNOWN')
            self.assertTrue(f.held.commit_attempted)
            self.assertFalse(f.held.activation_confirmed)
            self.assertFalse(f.held.handoff_completed)
            self.assertEqual(f.fs.read_json(m.SUPERVISOR_ATTEMPT)['phase'], 'committed-activation-unknown')
            self.assertEqual(f.fs.read_json(m.ATTEMPT)['phase'], 'attempted')
            self.assertEqual(f.fs.read_json(m.c.COMMIT)['activationSet'], m.ACTIVATION)
            events = self.events(f)
            self.assertEqual(sum(row['event'] == 'popen' for row in events), 1)
            if eventual_serving:
                until = time.monotonic()+2
                while True:
                    try:
                        self.assertEqual(m.http_probe('127.0.0.1', f.port), b'c3-classic-ready-v1\n')
                        break
                    except OSError:
                        if time.monotonic() >= until: raise
                        time.sleep(.01)
                self.assertEqual(f.count(), 1)
                self.assertEqual(f.fs.read_json(m.SUPERVISOR_ATTEMPT)['phase'], 'committed-activation-unknown',
                                 'later real serving must not repair sticky unknown')
            # A fresh client must refuse from persisted state, not just used.
            with self.assertRaisesRegex(RuntimeError, 'REPLAY'):
                m.FreshLaunch(f.held, f.platform, socket_path=f.socket).run(f.proof)
            self.assertEqual(sum(row['event'] == 'popen' for row in self.events(f)), 1)
            self.assertTrue(all(n.fs.read_json('/fixture-live.json')['candidateFrozen'] for n in f.fixtures))
            return events


if __name__ == '__main__':
    unittest.main()
