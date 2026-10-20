"""Actual Engine.dispatch + actual runner in disposable root/user namespace.

Physical/kernel/systemd authority is explicitly simulated. PPP verification and
nonempty Xray RPC/readback are real; these tests are not deployed-host evidence.
"""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import test_isolation as fixtures

m = fixtures.m
SOURCE = Path(__file__).resolve().parents[2] / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
VERIFIER = SOURCE.parent.parent / 'l2tp/verify-users.sh'


class ActualReadinessDispatch(unittest.TestCase):
    def put(self, name, content, mode=0o600):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes) else content.encode())
        target.chmod(mode)
        return target

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix='c3-actual-node-dispatch-')
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name) / 'runner'
        self.state = Path(scratch.name) / 'isolation'
        self.root.mkdir()
        self.state.mkdir()
        self.plan = fixtures.PlanTests().plan()
        self.plan['runnerSha256'] = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        self.engine = m.Engine(self.state, self.plan, fixtures.EngineTests.FixtureHost())
        fixtures.fixture_hold(self.engine)
        self.put('proc/sys/kernel/random/boot_id', self.plan['bootId'] + '\n')
        self.put('usr/local/etc/xray/config.json', '{"old":true}\n')
        (self.root / 'usr/local/share/xray').mkdir(parents=True)
        (self.root / 'var/lib').mkdir(parents=True)
        self.put('usr/local/bin/xray', '#!/bin/bash\nexit 0\n', 0o750)
        self.put('usr/bin/systemctl', '#!/bin/bash\ncase "$1" in\nrestart|stop) exit 0;;\nshow) printf "Job=\\nActiveState=active\\nSubState=running\\n";;\nis-active) exit 0;;\n*) exit 64;;\nesac\n', 0o750)
        self.fd = os.open(self.state / 'dispatch-test.lock', os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, self.fd)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        self.real_run = subprocess.run
        self.calls = []

    def request(self, command, content, checks=None):
        identity = hashlib.sha256(('topology-readiness-v1:' + command + ':verify-1').encode()).hexdigest() \
            if command in ('restore-users', 'verify-ppp-users') else command + '-1'
        values = [command, 'op-1', self.plan['nodeId'], 'sha256:' + hashlib.sha256(content).hexdigest(),
                  'backup-1', 'xray-main', 'test.infograd.online', 'attempt-1', 'generation-1', 'none', identity]
        argv = [item for key, value in zip(m.NAMES, values) for item in ('--' + key, value)]
        if checks is not None:
            argv += ['--checks', base64.urlsafe_b64encode(json.dumps(checks, separators=(',', ':')).encode()).decode().rstrip('=')]
        return m.RUNNER + ' ' + ' '.join(argv)

    def dispatch(self, command, content, checks=None, payload=b''):
        def actual_runner(argv, **kwargs):
            self.assertEqual(argv[:2], ['/bin/bash', m.RUNNER])
            self.calls.append(argv[3])
            env = {**kwargs.pop('env'), 'CELERITY_TOPOLOGY_ROOT': str(self.root)}
            return self.real_run(['unshare', '--user', '--map-root-user', '/bin/bash', str(SOURCE), *argv[2:]],
                                 env=env, timeout=40, **kwargs)
        with patch.object(m.subprocess, 'run', side_effect=actual_runner):
            raw = self.engine.dispatch(self.request(command, content, checks), payload, self.fd)
        return json.loads(raw)

    def prepared(self, content):
        self.dispatch('prepare', content, payload=content)
        self.dispatch('commit', content)
        self.dispatch('verify', content, checks=[])

    def test_payload_policy_refuses_before_dispatch_or_journal_mutation(self):
        content = b'{}\n'
        for command, checks, payload in [
                ('verify-ppp-users', {'bootId': self.plan['bootId'], 'operationId': 'ppp-1',
                    'expectedCredentialRevision': 1, 'expectedEnabledUserCount': 1}, b'forbidden'),
                ('close', None, b'forbidden'),
                ('restore-users', {'bootId': self.plan['bootId'], 'snapshotSha256': 'a' * 64,
                    'userCount': 1}, b'x' * 4194305)]:
            with self.subTest(command=command), self.assertRaisesRegex(m.Refusal, 'INVALID_STDIN'):
                self.engine.dispatch(self.request(command, content, checks), payload, self.fd)
        self.assertIsNone(self.engine.read()['dispatchInFlight'])
        self.assertEqual(self.engine.read()['dispatchCount'], 0)

    def test_bad_auxiliary_receipts_or_post_reply_guard_loss_retain_inflight(self):
        # Negative boundary tests intentionally simulate the child reply. The
        # positive tests below exercise real runner/PPP/Xray, not these responses.
        content = b'{}\n'
        counter = 0
        for command in ['restore-users', 'verify-ppp-users']:
            checks = {'bootId': self.plan['bootId'], 'snapshotSha256': 'a' * 64, 'userCount': 1} \
                if command == 'restore-users' else {'bootId': self.plan['bootId'], 'operationId': 'ppp-1',
                    'expectedCredentialRevision': 7, 'expectedEnabledUserCount': 1}
            original = self.request(command, content, checks)
            args = m.parse_runner(original, self.plan)
            request = dict(zip(m.NAMES + ['checks'], args[1::2]))
            fields = ['operationId', 'nodeId', 'candidateHash', 'backupId', 'targetProfile',
                      'executionContext', 'attemptId', 'generation', 'predecessorGeneration', 'commandId']
            result = {'ok': True, 'code': 'XRAY_USERS_RESTORED', 'userCount': 1, 'inboundCount': 1} \
                if command == 'restore-users' else {'ok': True, 'code': 'USERS_VERIFIED',
                    'credentialRevision': 7, 'enabledUserCount': 1, 'managedUserCount': 1}
            raw_checks = base64.urlsafe_b64decode(request['checks'] + '=' * (-len(request['checks']) % 4))
            template = dict(zip(fields, [request[key] for key in m.NAMES[1:]]), command=command,
                            protocolVersion=2, completion='completed', phase='verified',
                            ownershipRetained=True, bootId=self.plan['bootId'],
                            checksSha256=hashlib.sha256(raw_checks).hexdigest(), result=result)
            for fault in ['extra', 'missing', 'digest', 'phase', 'boot', 'node', 'ownership',
                          'result-extra', 'result-ok', 'result-bool', 'result-code', 'count', 'guard']:
                with self.subTest(command=command, fault=fault):
                    counter += 1
                    directory = self.state / ('negative-' + str(counter))
                    directory.mkdir()
                    engine = m.Engine(directory, self.plan, fixtures.EngineTests.FixtureHost())
                    fixtures.fixture_hold(engine)
                    reply = json.loads(json.dumps(template))
                    if fault == 'extra': reply['extra'] = True
                    elif fault == 'missing': del reply['checksSha256']
                    elif fault == 'digest': reply['checksSha256'] = 'f' * 64
                    elif fault == 'phase': reply['phase'] = 'closed'
                    elif fault == 'boot': reply['bootId'] = 'foreign'
                    elif fault == 'node': reply['nodeId'] = 'foreign'
                    elif fault == 'ownership': reply['ownershipRetained'] = False
                    elif fault == 'result-extra': reply['result']['extra'] = True
                    elif fault == 'result-ok': reply['result']['ok'] = 1
                    elif fault == 'result-code': reply['result']['code'] = 'UNCONFIRMED'
                    elif fault == 'result-bool': reply['result']['userCount' if command == 'restore-users' else 'enabledUserCount'] = True
                    elif fault == 'count': reply['result']['userCount' if command == 'restore-users' else 'enabledUserCount'] = 2
                    def simulated_reply(*_args, **_kwargs):
                        if fault == 'guard': engine.host.alive = False
                        return subprocess.CompletedProcess([], 0, (json.dumps(reply) + '\n').encode(), b'')
                    with patch.object(m.subprocess, 'run', side_effect=simulated_reply), self.assertRaises(m.Refusal):
                        engine.dispatch(original, b'{}' if command == 'restore-users' else b'', self.fd)
                    self.assertIsNotNone(engine.read()['dispatchInFlight'])
                    with self.assertRaises(m.Refusal):
                        engine.assert_held()

    def test_actual_dispatch_ppp_receipt_and_journal(self):
        content = b'{"inbounds":[],"outbounds":[]}\n'
        self.prepared(content)
        self.put('usr/local/lib/celerity/relay-l2tp/verify-users.sh', VERIFIER.read_bytes(), 0o750)
        for relative in ['usr', 'usr/local', 'usr/local/lib', 'usr/local/lib/celerity', 'usr/local/lib/celerity/relay-l2tp']:
            (self.root / relative).chmod(0o755)
        self.put('var/lib/celerity/l2tp/operations/ppp-sync-1/desired.json', json.dumps({'credentialRevision': 7,
            'users': [{'login': 'alice', 'password': 'local-fixture-only', 'ipAddress': '10.44.0.2', 'enabled': True}]}))
        chap = self.put('etc/ppp/chap-secrets', '# BEGIN CELERITY MANAGED L2TP USERS\n"alice" l2tpd "local-fixture-only" 10.44.0.2\n# END CELERITY MANAGED L2TP USERS\n')
        before = chap.read_bytes()
        checks = {'bootId': self.plan['bootId'], 'operationId': 'ppp-sync-1',
                  'expectedCredentialRevision': 7, 'expectedEnabledUserCount': 1}
        receipt = self.dispatch('verify-ppp-users', content, checks)
        self.assertEqual(receipt['result'], {'ok': True, 'code': 'USERS_VERIFIED',
            'credentialRevision': 7, 'enabledUserCount': 1, 'managedUserCount': 1})
        self.assertEqual(chap.read_bytes(), before)
        self.assertIsNone(self.engine.read()['dispatchInFlight'])
        self.assertEqual(self.dispatch('close', content)['phase'], 'closed')

    def test_actual_dispatch_nonempty_snapshot_and_rpc(self):
        binary = os.environ.get('C3_XRAY')
        self.assertTrue(binary and Path(binary).is_file(), 'C3_XRAY real binary required; never skip')
        assert binary is not None
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        config = {'log': {'loglevel': 'none'}, 'api': {'tag': 'API', 'services': ['HandlerService']},
            'inbounds': [{'tag': 'API_INBOUND', 'listen': '127.0.0.1', 'port': port, 'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1'}},
                         {'tag': 'vless-in', 'listen': '127.0.0.1', 'port': 0, 'protocol': 'vless', 'settings': {'decryption': 'none', 'clients': []}}],
            'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
            'routing': {'rules': [{'type': 'field', 'inboundTag': ['API_INBOUND'], 'outboundTag': 'API'}]}}
        content = (json.dumps(config, separators=(',', ':')) + '\n').encode()
        self.prepared(content)
        executable = self.root / 'usr/local/bin/xray'
        shutil.copyfile(binary, executable)
        executable.chmod(0o750)
        child = subprocess.Popen([binary, 'run', '-config', str(self.root / 'usr/local/etc/xray/config.json')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def stop():
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        self.addCleanup(stop)
        def query():
            return self.real_run([binary, 'api', 'inbounduser', '--server=127.0.0.1:' + str(port), '-tag=vless-in'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        deadline = time.monotonic() + 10
        while True:
            initial = query()
            if initial.returncode == 0:
                break
            self.assertIsNone(child.poll(), 'disposable Xray died')
            self.assertLess(time.monotonic(), deadline, 'disposable Xray not ready')
            time.sleep(0.02)
        self.assertEqual(json.loads(initial.stdout).get('users', []), [])
        users = [{'id': '550e8400-e29b-41d4-a716-446655440000', 'email': 'alice'}]
        payload = (json.dumps({'users': users}, separators=(',', ':')) + '\n').encode()
        checks = {'bootId': self.plan['bootId'], 'snapshotSha256': hashlib.sha256(payload).hexdigest(), 'userCount': 1}
        receipt = self.dispatch('restore-users', content, checks, payload)
        self.assertEqual(receipt['result'], {'ok': True, 'code': 'XRAY_USERS_RESTORED', 'userCount': 1, 'inboundCount': 1})
        actual = json.loads(query().stdout)['users']
        self.assertEqual([{'id': u['account']['id'], 'email': u['email']} for u in actual], users)
        self.assertIsNone(self.engine.read()['dispatchInFlight'])
        self.assertEqual(self.dispatch('close', content)['phase'], 'closed')


if __name__ == '__main__':
    unittest.main()
