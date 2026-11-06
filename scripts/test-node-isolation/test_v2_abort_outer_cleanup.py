"""R71-01: actual main/wrapper, real flock/close; modeled root/systemd only."""
import ast
import contextlib
import errno
import io
import json
import os
import pathlib
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_v2_abort_return as f

m = f.m
HERE = pathlib.Path(__file__).resolve().parent


def actual_wrapper():
    """Execute this loaded source's real top-level boundary, not a copied codec."""
    source = m.__file__
    assert isinstance(source, str)
    node = ast.parse(pathlib.Path(source).read_bytes()).body[-1]
    assert isinstance(node, ast.If)
    with patch.object(m, '__name__', '__main__'), patch.dict(sys.modules, {'__main__': m}):
        exec(compile(ast.Module(body=[node], type_ignores=[]), source, 'exec'), m.__dict__)


class OuterCleanupTests(unittest.TestCase):
    @contextlib.contextmanager
    def cli(self, *, lost_start_ack=False, close_fault=False, pre_effect=False,
            setup_fault=False, command='apply', delivery_fault=None, early_return=True):
        with tempfile.TemporaryDirectory(prefix='v2-outer-') as tmp:
            root = pathlib.Path(tmp)
            (root / 'masks').mkdir()
            (root / 'guard.json').write_text('{"fixture":"guard"}')
            (root / 'plan.json').write_text(json.dumps(f.plan()))
            (root / 'masks/cron.service').write_bytes(b'ORIGINAL CRON\n')
            (root / 'masks/cron.service').chmod(0o640)
            host = f.Host(f.plan())
            host.fail_checkpoint = early_return and not pre_effect and command != 'dispatch'
            if pre_effect:
                host.fail_virgin = True
            secondary = OSError(errno.EIO, 'SIMULATED lost outer close acknowledgement')
            setup_error = m.Refusal('SIMULATED_PRE_ENGINE_REFUSAL_RETAINED')
            start_error = OSError('SIMULATED writer enabled; start acknowledgement lost')
            captured, closes, reused = [], [], []
            output, errors = io.StringIO(), io.StringIO()
            events = []
            binary = io.BytesIO()
            runner_calls = []
            values = ['close', 'op', host.p['nodeId'], 'sha256:' + 'a' * 64, 'backup',
                      host.p['targetProfile'], host.p['context'], 'attempt', 'gen', 'none', 'close']
            argv = [v for pair in zip(['--' + k for k in m.NAMES], values) for v in pair]
            receipt = {'ok': True, 'protocolVersion': 2, 'bootId': host.p['bootId'],
                       'command': 'close', 'completion': 'completed', 'ownershipRetained': True,
                       **dict(zip(['operationId', 'nodeId', 'candidateHash', 'backupId', 'targetProfile',
                                   'executionContext', 'attemptId', 'generation', 'predecessorGeneration', 'commandId'], values[1:]))}
            runner_bytes = json.dumps(receipt).encode() + b'\n'
            real_engine, real_close, real_start = m.Engine, os.close, host.start

            def runner(*args, **kwargs):
                self.assertEqual(args[0], ['/bin/bash', m.RUNNER, *argv])
                fd, = kwargs['pass_fds']
                os.fstat(fd)
                runner_calls.append(args[0])
                return m.subprocess.CompletedProcess(args[0], 0, runner_bytes, b'')

            class Binary:
                def write(self, data):
                    events.append('delivery-write')
                    return binary.write(data)
                def flush(self):
                    events.append('delivery-flush')

            class Output:
                buffer = Binary()
                def write(self, text):
                    events.append('delivery-write')
                    if delivery_fault == 'write':
                        raise OSError('SIMULATED stdout write failure')
                    return output.write(text)
                def flush(self):
                    events.append('delivery-flush')
                    if delivery_fault == 'flush':
                        raise OSError('SIMULATED stdout flush acknowledgement lost')

            def engine(*args, **kwargs):
                if setup_fault:
                    raise setup_error
                value = real_engine(*args, **kwargs)
                captured.append(value)
                original = value.abort_return
                def abort(fd):
                    try:
                        return original(fd)
                    except BaseException as error:
                        captured.append(error)
                        raise
                value.abort_return = abort
                if pre_effect:
                    apply = value.apply
                    def refused(guard):
                        try:
                            return apply(guard)
                        except BaseException as error:
                            captured.append(error)
                            raise
                    value.apply = refused
                if command == 'dispatch':
                    value.apply({'fixture': 'guard'})
                    host.operator_session = lambda: {'pid': os.getpid(), 'start': '101'}
                    value.confirm_access()
                return value

            def start(name):
                real_start(name)
                if lost_start_ack:
                    raise start_error

            def close(fd):
                frame = sys._getframe(1)
                if frame.f_code is m.main.__code__:
                    info, named = os.fstat(fd), (root / 'lock').stat()
                    self.assertEqual((info.st_dev, info.st_ino), (named.st_dev, named.st_ino))
                    # Nothing may be acknowledged while the owned lock needs disposal.
                    closes.append({'fd': fd, 'stdoutBeforeClose': output.getvalue(),
                                   'binaryBeforeClose': binary.getvalue(),
                                   'localOwnerRetired': frame.f_locals.get('lock') is None,
                                   'borrowRetired': not captured or captured[0]._outer_lock_fd is None})
                    events.append('outer-close')
                    real_close(fd)
                    if close_fault:
                        # Linux may reuse the just-closed number immediately. A retry
                        # of uncertain close would silently dispose this other resource.
                        replacement = os.open(root / 'reused-fd', os.O_RDWR | os.O_CREAT, 0o600)
                        self.assertEqual(replacement, fd)
                        reused.append(replacement)
                        raise secondary
                    return
                return real_close(fd)

            contexts = (
                f.accepted_files(), f.modeled_root(root),
                patch.object(m, 'CONFIG', str(root / 'plan.json')), patch.object(m, 'STATE', str(root)),
                patch.object(m, 'HELPER', str(HERE / 'isolation.py')),
                patch.object(m, 'MASK_ROOT', str(root / 'masks')),
                patch.object(m, 'RUNNER_FENCES', str(root / 'fences')),
                patch.object(m, 'Host', return_value=host), patch.object(m, 'Engine', new=engine),
                patch.object(host, 'start', new=start), patch.object(m.os, 'geteuid', return_value=0),
                patch.object(m.os, 'close', new=close), patch.object(sys, 'argv', [m.HELPER, command]),
                patch.object(m.subprocess, 'run', new=runner),
                patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(b''))),
                patch.dict(os.environ, {'SSH_ORIGINAL_COMMAND': shlex.join([m.RUNNER, *argv])}),
                contextlib.redirect_stdout(Output()), contextlib.redirect_stderr(errors))
            with contextlib.ExitStack() as stack:
                for context in contexts:
                    stack.enter_context(context)
                case = {'root': root, 'host': host, 'output': output, 'errors': errors,
                        'binary': binary, 'runnerBytes': runner_bytes, 'runnerCalls': runner_calls,
                        'secondary': secondary, 'setupError': setup_error, 'startError': start_error,
                        'captured': captured, 'closes': closes, 'events': events}
                try:
                    yield case
                finally:
                    for fd in reused:
                        # Prove no second close touched the new owner, then retire it.
                        try:
                            os.fstat(fd)
                        finally:
                            real_close(fd)

    def assert_cleanup(self, case):
        self.assertEqual(len(case['closes']), 1)
        self.assertEqual(case['closes'][0]['stdoutBeforeClose'], '')
        self.assertEqual(case['closes'][0]['binaryBeforeClose'], b'')
        self.assertTrue(case['closes'][0]['localOwnerRetired'])
        self.assertTrue(case['closes'][0]['borrowRetired'])

    def assert_unknown(self, case, code):
        self.assertEqual(json.loads(case['errors'].getvalue()), {
            'ok': False, 'code': code, 'returnState': 'UNKNOWN',
            'exclusion': 'unknown', 'retryAllowed': False})

    def test_actual_main_preserves_exact_early_unknown_with_secondary_real_close_error(self):
        with self.cli(lost_start_ack=True, close_fault=True) as case:
            with self.assertRaises(m.EarlyReturnUnknown) as failed:
                m.main()
            self.assertIs(failed.exception, case['captured'][1])
            self.assertIs(failed.exception.__cause__, case['startError'])
            self.assertEqual(failed.exception.cleanup_errors, [case['secondary']])
            self.assertEqual(json.loads((case['root'] / 'journal.json').read_bytes())['phase'], 'early-return-unknown')
            self.assertTrue(any(e[:2] == ('/usr/bin/systemctl', 'start') for e in case['host'].events))
            self.assertEqual(case['output'].getvalue(), '')
            self.assert_cleanup(case)

    def test_actual_wrapper_preserves_early_unknown_after_real_close_ack_loss(self):
        with self.cli(lost_start_ack=True, close_fault=True) as case:
            with self.assertRaises(SystemExit) as failed:
                actual_wrapper()
            self.assertEqual(failed.exception.code, 75)
            self.assertEqual(case['output'].getvalue(), '')
            self.assert_unknown(case, 'EARLY_RETURN_OUTCOME_UNKNOWN')
            self.assertEqual(case['captured'][1].cleanup_errors, [case['secondary']])
            self.assert_cleanup(case)

    def test_actual_main_completed_old_with_close_failure_is_not_acknowledged(self):
        with self.cli(close_fault=True) as case:
            with self.assertRaises(m.EarlyReturnUnknown) as failed:
                m.main()
            self.assertIs(failed.exception.__cause__, case['secondary'])
            self.assertEqual(failed.exception.cleanup_errors, [case['secondary']])
            self.assertEqual(case['host'].states, case['host'].original)
            self.assertEqual(json.loads((case['root'] / 'journal.json').read_bytes())['phase'], 'early-returned')
            self.assertEqual(case['output'].getvalue(), '')
            self.assert_cleanup(case)

    def test_actual_wrapper_completed_old_close_failure_has_only_unknown_envelope(self):
        with self.cli(close_fault=True) as case:
            with self.assertRaises(SystemExit) as failed:
                actual_wrapper()
            self.assertEqual(failed.exception.code, 75)
            self.assertEqual(case['output'].getvalue(), '')
            self.assert_unknown(case, 'EARLY_RETURN_OUTCOME_UNKNOWN')
            self.assert_cleanup(case)

    def test_normal_old_acknowledgement_follows_required_close_and_is_flushed(self):
        with self.cli() as case:
            actual_wrapper()
            self.assertEqual(json.loads(case['output'].getvalue())['returnState'], 'OLD')
            self.assertEqual(case['host'].states, case['host'].original)
            self.assertEqual(case['errors'].getvalue(), '')
            self.assert_cleanup(case)
            self.assertLess(case['events'].index('outer-close'), case['events'].index('delivery-write'))
            self.assertEqual(case['events'][-1], 'delivery-flush')

    def test_pre_effect_refusal_identity_and_retained_envelope_survive_cleanup_failure(self):
        for wrapper in (False, True):
            with self.subTest(wrapper=wrapper), self.cli(pre_effect=True, close_fault=True) as case:
                if wrapper:
                    with self.assertRaises(SystemExit) as failed:
                        actual_wrapper()
                    self.assertEqual(failed.exception.code, 75)
                    self.assertEqual(json.loads(case['errors'].getvalue()), {
                        'ok': False, 'code': 'SYSTEMD_JOB_PENDING', 'ownershipRetained': True})
                else:
                    with self.assertRaises(m.KnownIsolationRefusal) as failed:
                        m.main()
                    self.assertIs(failed.exception, case['captured'][1])
                self.assertEqual(case['captured'][1].cleanup_errors, [case['secondary']])
                self.assertEqual(case['host'].events, [])
                self.assertFalse((case['root'] / 'journal.json').exists())
                self.assertEqual(case['output'].getvalue(), '')
                self.assert_cleanup(case)

    def test_pre_engine_setup_primary_survives_real_outer_close_failure(self):
        with self.cli(setup_fault=True, close_fault=True) as case:
            with self.assertRaises(m.Refusal) as failed:
                m.main()
            self.assertIs(failed.exception, case['setupError'])
            self.assertEqual(failed.exception.cleanup_errors, [case['secondary']])
            self.assertFalse((case['root'] / 'journal.json').exists())
            self.assertEqual(case['host'].events, [])
            self.assert_cleanup(case)

    def test_nonreturn_apply_cleanup_failure_keeps_existing_retained_classification(self):
        with self.cli(early_return=False, close_fault=True) as case:
            with self.assertRaises(SystemExit) as failed:
                actual_wrapper()
            self.assertEqual(failed.exception.code, 75)
            self.assertEqual(json.loads(case['errors'].getvalue()), {
                'ok': False, 'code': 'NODE_MAINTENANCE_UNKNOWN_RETAINED', 'ownershipRetained': True})
            self.assertEqual(json.loads((case['root'] / 'journal.json').read_bytes())['phase'], 'awaiting-fresh-login')
            self.assertFalse(any(e[:2] == ('/usr/bin/systemctl', 'start') for e in case['host'].events))
            self.assertEqual(case['output'].getvalue(), '')
            self.assert_cleanup(case)

    def test_old_stdout_write_failure_is_nonretryable_unknown_after_cleanup(self):
        with self.cli(delivery_fault='write') as case:
            with self.assertRaises(SystemExit) as failed:
                actual_wrapper()
            self.assertEqual(failed.exception.code, 75)
            self.assertEqual(case['output'].getvalue(), '')
            self.assert_unknown(case, 'EARLY_RETURN_OUTCOME_UNKNOWN')
            self.assert_cleanup(case)

    def test_old_stdout_flush_loss_cannot_claim_retained_or_retry(self):
        with self.cli(delivery_fault='flush') as case:
            with self.assertRaises(SystemExit) as failed:
                actual_wrapper()
            self.assertEqual(failed.exception.code, 75)
            # Bytes may have escaped; they cannot be retracted. Final outcome is
            # UNKNOWN, not rollback or permission to repeat the completed return.
            self.assertEqual(json.loads(case['output'].getvalue())['returnState'], 'OLD')
            self.assert_unknown(case, 'EARLY_RETURN_OUTCOME_UNKNOWN')
            self.assert_cleanup(case)

    def test_dispatch_raw_receipt_is_delayed_without_changing_bytes_or_journal(self):
        for fault in (False, True):
            with self.subTest(close_fault=fault), self.cli(command='dispatch', close_fault=fault) as case:
                if fault:
                    with self.assertRaises(SystemExit) as failed:
                        actual_wrapper()
                    self.assertEqual(failed.exception.code, 75)
                    self.assertEqual(case['binary'].getvalue(), b'')
                    self.assertEqual(json.loads(case['errors'].getvalue()), {
                        'ok': False, 'code': 'NODE_MAINTENANCE_UNKNOWN_RETAINED', 'ownershipRetained': True})
                else:
                    actual_wrapper()
                    self.assertEqual(case['binary'].getvalue(), case['runnerBytes'])
                    self.assertEqual(case['errors'].getvalue(), '')
                    self.assertEqual(case['events'][-1], 'delivery-flush')
                self.assertEqual(len(case['runnerCalls']), 1)
                state = json.loads((case['root'] / 'journal.json').read_bytes())
                self.assertEqual(state['phase'], 'held')
                self.assertEqual(state['dispatchCount'], 1)
                self.assertIsNone(state['dispatchInFlight'])
                self.assert_cleanup(case)


if __name__ == '__main__':
    unittest.main()
