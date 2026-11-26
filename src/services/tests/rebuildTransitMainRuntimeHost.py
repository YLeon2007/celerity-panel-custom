"""Socket-free observer controls; all child pipes and waits are real."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rebuildTransitMainRuntime as runtime
from rebuildTransitMainSession import MainSnapshot, XrayGeneration
from rebuildTransitMainWindow import AgentWindow, WindowError

SENTINEL = 'private-synthetic-marker'
ID = '00000000-0000-4000-8000-000000000002'
INV = 'a' * 32
ROUTES = (runtime.RouteCheck('vless-in', 'tcp', 443, 'blocked', target_domain='choice.example.invalid'),)


def profile():
    return {
        'api': {'tag': 'API', 'services': ['HandlerService', 'RoutingService', 'StatsService']},
        'inbounds': [
            {'tag': 'API_INBOUND', 'listen': '127.0.0.1', 'port': 61000, 'protocol': 'dokodemo-door',
             'settings': {'address': '127.0.0.1'}},
            {'tag': 'vless-in', 'protocol': 'vless', 'settings': {'clients': [
                {'id': ID, 'email': SENTINEL, 'level': 2}, {'id': 'anonymous-not-in-proof'},
            ]}},
            {'tag': 'extra', 'protocol': 'vless', 'settings': {'clients': []}},
        ],
        'outbounds': [{'tag': 'blocked', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'AsIs', 'rules': [
            {'type': 'field', 'inboundTag': ['API_INBOUND'], 'outboundTag': 'API'},
            {'type': 'field', 'inboundTag': ['vless-in'], 'outboundTag': 'blocked'},
        ]},
    }


class RuntimeHost(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.main = Path(self.tmp.name) / 'config.json'
        self.cfg = profile()
        self.proof = self.main.with_name('proof')
        self.proof.write_bytes(b'fixture-only')  # The exchange seam below prevents execution.
        self.proof.chmod(0o700)
        self.xray = self.proof.with_name('xray')
        self.xray.write_bytes(b'fixture-only')
        self.xray.chmod(0o700)
        self.invocation = INV
        self.unit_edits = {}
        self.unit_reads = 0
        self.calls = []
        self.proc = ('start', 'exe', 'netns', 'socket')
        self.routes = ROUTES
        self.observer = runtime.MainRuntimeObserver(
            {'vless-in', 'extra'}, lambda phase, snap: self.routes,
            _fixture_paths=(self.proof, self.xray, self.main), _fixture_show=self.manager,
        )

    def manager(self, argv, timeout):
        self.assertEqual(argv, ['/usr/bin/systemctl', 'show', '--all',
                               *('--property=' + p for p in runtime.XRAY_PROPS), '--', 'xray.service'])
        self.assertEqual(timeout, 4)
        self.unit_reads += 1
        row = dict(Id='xray.service', LoadState='loaded', NeedDaemonReload='no', ActiveState='active',
                   SubState='running', Job='', MainPID=str(os.getpid()), InvocationID=self.invocation,
                   ExecStart=f'{{ path={self.xray} ; argv[]={self.xray} run -config {self.main} ; ignore_errors=no ; }}')
        row.update(self.unit_edits)
        return ''.join(f'{key}={value}\n' for key, value in row.items())

    def snapshot(self):
        self.main.write_text(json.dumps(self.cfg), encoding='ascii')
        return MainSnapshot(AgentWindow(None, main=self.main).read_main(), XrayGeneration(os.getpid(), INV))

    @staticmethod
    def receipt():
        return {'version': runtime.VERSION, 'userScope': 'named-vless-email-index',
                'namedInbounds': [{'handlerCount': 0, 'enumeratedNamed': 0},
                                  {'handlerCount': 1, 'enumeratedNamed': 1}], 'routesVerified': 1}

    def observe(self, snapshot, reply=None, after=None, phase='capture'):
        def exchange(argv, data, *, timeout, limit):
            self.assertEqual(tuple(argv), (str(self.proof),))
            self.assertEqual(timeout, runtime.PROOF_TIMEOUT)
            self.assertEqual(limit, runtime.RECEIPT_LIMIT)
            self.calls.append(json.loads(data))
            if after:
                after()
            return json.dumps(self.receipt()).encode('ascii') if reply is None else reply

        with patch.object(runtime, '_process', side_effect=lambda *_: self.proc), \
             patch.object(runtime, '_exchange', side_effect=exchange):
            return self.observer(phase, snapshot)

    def refused(self, call):
        with self.assertRaises(WindowError) as err:
            call()
        self.assertEqual(str(err.exception), runtime.RUNTIME)
        self.assertIsNone(err.exception.__context__)
        self.assertIsNone(err.exception.__cause__)

    def test_callback_projects_only_named_fields_and_trusted_routes(self):
        snapshot = self.snapshot()
        for phase in ('baseline', 'capture', 'restart', 'reconcile'):
            self.assertIs(self.observe(snapshot, phase=phase), True)
        self.assertEqual(self.unit_reads, 16)
        self.assertEqual(self.calls, [{
            'version': runtime.VERSION,
            'namedInbounds': [{'tag': 'extra', 'users': []}, {'tag': 'vless-in', 'users': [
                {'email': SENTINEL, 'uuid': ID, 'flow': '', 'level': 2},
            ]}],
            'routes': [{'context': {'inboundTag': 'vless-in', 'network': 'tcp', 'targetPort': 443,
                                    'targetDomain': 'choice.example.invalid'}, 'outboundTag': 'blocked'}],
        }] * 4)

    def test_default_binding_is_fixed_and_does_not_observe_on_construction(self):
        observer = runtime.MainRuntimeObserver({'vless-in'}, lambda *_: ROUTES)
        self.assertEqual(str(observer._proof), '/usr/local/libexec/celerity/rebuild-main-proof')
        self.assertEqual(str(observer._xray), '/usr/local/bin/xray')
        self.assertEqual(str(observer._main), '/usr/local/etc/xray/config.json')
        self.refused(lambda: runtime.MainRuntimeObserver({'vless-in'}, lambda *_: ROUTES, _fixture_show=self.manager))
        self.assertEqual(self.unit_reads, 0)

    def test_ip_on_demand_checks_literal_ips_only(self):
        self.cfg['routing']['domainStrategy'] = 'IPOnDemand'
        snapshot = self.snapshot()
        self.routes = (ROUTES[0]._replace(target_ip='192.0.2.2'),)
        self.refused(lambda: self.observe(snapshot))  # IP + domain still causes DNS.
        self.assertEqual(self.unit_reads, 0)
        self.assertEqual(self.calls, [])
        self.routes = (self.routes[0]._replace(target_domain=None),)
        self.assertIs(self.observe(snapshot), True)
        self.assertEqual(self.calls[0]['routes'][0]['context']['targetIP'], '192.0.2.2')
        self.assertNotIn('targetDomain', self.calls[0]['routes'][0]['context'])

    def test_private_callback_error_is_not_attached_to_public_failure(self):
        snapshot = self.snapshot()
        with patch.object(self.observer, '_routes', side_effect=ValueError(SENTINEL)):
            self.refused(lambda: self.observe(snapshot))
        self.assertEqual(self.calls, [])

    def test_plan_refusals_do_not_launch(self):
        def api_displaced(cfg):
            cfg['routing']['rules'].reverse()

        for change in (
            lambda cfg: cfg['api']['services'].remove('RoutingService'),
            lambda cfg: cfg['routing'].update(domainStrategy='IPOnDemand'),
            lambda cfg: cfg['routing'].update(DomainStrategy='IPIfNonMatch'),
            lambda cfg: cfg['routing'].update(balancers=[{'tag': 'test'}]),
            lambda cfg: cfg['routing']['rules'][1].update(BalancerTag='test'),
            lambda cfg: cfg['inbounds'][2].update(protocol='vmess'),
            lambda cfg: cfg['inbounds'][1].update(Protocol='vmess'),
            lambda cfg: cfg['inbounds'][1]['settings']['clients'][0].update(level=True),
            lambda cfg: cfg['outbounds'].append({'tag': 'API', 'protocol': 'freedom'}),
            api_displaced,
        ):
            with self.subTest(change=change.__code__.co_firstlineno):
                self.cfg = profile()
                change(self.cfg)
                self.refused(lambda: self.observe(self.snapshot()))
        self.cfg = profile()
        snap = self.snapshot()
        for routes in ((), ({'context': SENTINEL},), ROUTES * 33, (ROUTES[0]._replace(inbound_tag='API_INBOUND'),)):
            self.routes = routes
            self.refused(lambda: self.observe(snap))
        self.refused(lambda: self.observe(snap, phase='arbitrary'))
        self.assertEqual(self.calls, [])

    def test_stale_snapshot_and_wrong_manager_rows_fail_before_launch(self):
        snap = self.snapshot()
        for edits in ({'Job': '42'}, {'MainPID': '1'}, {'InvocationID': 'b' * 32}, {'ExecStart': '/other'},
                      {'Id': 'xray-bridge.service'}, {'NeedDaemonReload': 'yes'}):
            self.unit_edits = edits
            self.refused(lambda: self.observe(snap))
        self.unit_edits = {}
        self.replace_main()
        self.refused(lambda: self.observe(snap))
        self.assertEqual(self.calls, [])

    def replace_main(self):
        other = self.main.with_suffix('.new')
        other.write_bytes(self.main.read_bytes())
        other.chmod(self.main.stat().st_mode & 0o777)
        other.replace(self.main)

    def test_same_byte_replacement_process_and_invocation_drift_after_reply(self):
        for mutate in (self.replace_main,
                       lambda: setattr(self, 'proc', ('new-start', 'exe', 'netns', 'socket')),
                       lambda: setattr(self, 'invocation', 'b' * 32)):
            with self.subTest(mutate=mutate.__name__):
                self.refused(lambda: self.observe(self.snapshot(), after=mutate))
        self.assertEqual(len(self.calls), 3)

    def test_exact_receipt_types_shape_and_counts(self):
        def changed(**kw):
            return json.dumps(dict(self.receipt(), **kw)).encode()

        good = changed()
        snap = self.snapshot()
        bad = (b'{"json":"' + SENTINEL.encode(), good + b'{}', b'\xff',
               good.replace(b'"routesVerified": 1', b'"routesVerified": 1, "routesVerified": 1'),
               changed(routesVerified=True), changed(routesVerified=1.0), changed(routesVerified=0),
               changed(namedInbounds=self.receipt()['namedInbounds'][::-1]),
               changed(namedInbounds=[{'handlerCount': False, 'enumeratedNamed': 0},
                                     self.receipt()['namedInbounds'][1]]),
               changed(userScope='all-users'), changed(extra=SENTINEL))
        for i, reply in enumerate(bad):
            with self.subTest(receipt=i):
                self.refused(lambda: self.observe(snap, reply=reply))
        self.assertEqual(len(self.calls), len(bad))

    def test_helper_path_is_not_replaced_or_followed(self):
        snapshot = self.snapshot()
        saved = self.proof.with_suffix('.saved')

        def replace():
            self.proof.rename(saved)
            self.proof.write_bytes(saved.read_bytes())
            self.proof.chmod(0o700)

        self.refused(lambda: self.observe(snapshot, after=replace))
        self.proof.unlink()
        self.proof.symlink_to(saved)
        self.refused(lambda: self.observe(snapshot))
        self.assertEqual(len(self.calls), 1)


class ChildPipes(unittest.TestCase):
    def exchange(self, body, data=b'input', limit=64, timeout=2.0):
        children = []
        popen = subprocess.Popen

        def tracked(*args, **kwargs):
            p = popen(*args, **kwargs)
            children.append(p)
            return p

        try:
            with patch.object(runtime.subprocess, 'Popen', side_effect=tracked):
                return runtime._exchange(['/usr/bin/python3', '-IB', '-c', body], data,
                                         timeout=timeout, limit=limit)
        finally:
            self.assertEqual(len(children), 1)
            p = children[0]
            if p.returncode is None:
                p.kill()
                p.wait(timeout=2)
                self.fail('original child not reaped by observer')
            self.assertTrue(all(pipe.closed for pipe in (p.stdin, p.stdout, p.stderr)))

    def test_eof_exact_stdin_and_isolated_environment(self):
        payload = b'x' * 200000
        self.assertEqual(self.exchange("import os,sys; assert not set(os.environ)-{'LC_ALL'}; "
                                       "assert sys.stdin.buffer.read() == b'x'*200000; print('ok')", payload), b'ok\n')

    def test_status_stderr_and_output_limits(self):
        for body in ("sys.stdout.write('ok'); sys.exit(1)", "sys.stdout.write('ok'); sys.exit(124)",
                     "sys.stderr.write('" + SENTINEL + "')", "sys.stdout.write('A'*100000)",
                     "os.kill(os.getpid(), 9)"):
            with self.subTest(body=body):
                with self.assertRaises(WindowError):
                    self.exchange('import sys,os; sys.stdin.read(); ' + body)

    def test_timeout_with_backpressure_reaps_original_child(self):
        since = time.monotonic()
        with self.assertRaises(WindowError):
            self.exchange('import time; time.sleep(20)', b'x' * 200000, timeout=0.25)
        self.assertLess(time.monotonic() - since, 2)

    def test_early_stdin_close_cannot_yield_a_success_receipt(self):
        with self.assertRaises((WindowError, BrokenPipeError)):
            self.exchange("import os; os.close(0); print('ok')", b'x' * 200000)

    def test_unknown_sigchld_handling_does_not_launch(self):
        with patch.object(runtime.signal, 'getsignal', return_value=runtime.signal.SIG_IGN), \
             patch.object(runtime.subprocess, 'Popen') as launch:
            with self.assertRaises(WindowError):
                runtime._exchange([str(runtime.PROOF)], b'', timeout=2, limit=64)
            launch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
