#!/usr/bin/env python3
"""Finite readiness parser contract; no node commands or physical authority."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('readiness_isolation', Path(__file__).with_name('isolation.py'))
assert spec is not None and spec.loader is not None
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class FiniteReadinessGrammar(unittest.TestCase):
    plan = {'nodeId': 'node-1', 'targetProfile': 'xray-main'}

    def command(self, name, checks=None, **changes):
        values = {'command': name, 'operation-id': 'op-1', 'node-id': 'node-1',
                  'candidate-hash': 'sha256:' + 'a' * 64, 'backup-id': 'backup-1',
                  'target-profile': 'xray-main', 'execution-context': 'test.infograd.online',
                  'attempt-id': 'attempt-1', 'generation': 'generation-1',
                  'predecessor-generation': 'none', 'command-id': 'command-1'}
        values.update(changes)
        result = m.RUNNER + ' ' + ' '.join('--' + key + ' ' + values[key] for key in m.NAMES)
        if checks is not None:
            raw = checks if isinstance(checks, bytes) else json.dumps(checks, separators=(',', ':')).encode()
            result += ' --checks ' + base64.urlsafe_b64encode(raw).decode().rstrip('=')
        return result

    def valid(self):
        return [('restore-users', {'bootId': 'boot-1', 'snapshotSha256': 'a' * 64, 'userCount': 1}),
                ('verify-ppp-users', {'bootId': 'boot-1', 'operationId': 'ppp-1',
                                      'expectedCredentialRevision': 7, 'expectedEnabledUserCount': 1})]

    def test_existing_commands_unchanged(self):
        for name in ['prepare', 'commit', 'verify', 'rollback', 'close', 'status']:
            with self.subTest(name=name):
                m.parse_runner(self.command(name, [] if name == 'verify' else None), self.plan)

    def test_both_auxiliary_commands_are_finite(self):
        for name, checks in self.valid():
            with self.subTest(name=name):
                m.parse_runner(self.command(name, checks), self.plan)

    def test_exact_shape_types_and_bindings(self):
        for name, checks in self.valid():
            duplicate = json.dumps(checks, separators=(',', ':'))[:-1] + ',"bootId":"boot-1"}'
            commands = [self.command(name), self.command(name, dict(checks, extra=True)),
                        self.command(name, checks, **{'node-id': 'foreign'}),
                        self.command(name, checks, **{'target-profile': 'xray-bridge'}),
                        self.command(name, checks, **{'execution-context': 'lm1.infograd.online'}),
                        self.command(name, checks) + ';id', self.command(name, checks).replace(m.RUNNER, '/bin/bash'),
                        self.command(name, duplicate.encode()), self.command(name, b'null'),
                        self.command(name, checks) + '=', self.command(name) + ' --checks ' + 'A' * 8193]
            for key in checks:
                for value in [None, True, [], {}, '', '../escape']:
                    commands.append(self.command(name, dict(checks, **{key: value})))
                commands.append(self.command(name, {k: v for k, v in checks.items() if k != key}))
            for command in commands:
                with self.subTest(command=command):
                    with self.assertRaises(m.Refusal):
                        m.parse_runner(command, self.plan)

    def test_zero_empty_overflow_and_bridge_restore_refuse(self):
        name, checks = self.valid()[0]
        for count in [0, -1, 4097, 1.5]:
            with self.assertRaises(m.Refusal):
                m.parse_runner(self.command(name, dict(checks, userCount=count)), self.plan)
        bridge = dict(self.plan, targetProfile='xray-bridge')
        with self.assertRaises(m.Refusal):
            m.parse_runner(self.command(name, checks, **{'target-profile': 'xray-bridge'}), bridge)
        for command in ['close', 'prepare', 'commit', 'rollback', 'status']:
            with self.assertRaises(m.Refusal):
                m.parse_runner(self.command(command, checks), self.plan)
        name, checks = self.valid()[1]
        for key, value in [('expectedCredentialRevision', 0), ('expectedEnabledUserCount', -1),
                           ('expectedCredentialRevision', 2**53), ('expectedEnabledUserCount', 2**53)]:
            with self.assertRaises(m.Refusal):
                m.parse_runner(self.command(name, dict(checks, **{key: value})), self.plan)

    def test_ppp_bridge_and_valid_bounds(self):
        name, checks = self.valid()[1]
        bridge = dict(self.plan, targetProfile='xray-bridge')
        for count in [0, 2**53-1]:
            m.parse_runner(self.command(name, dict(checks, expectedEnabledUserCount=count,
                expectedCredentialRevision=2**53-1), **{'target-profile': 'xray-bridge'}), bridge)
        name, checks = self.valid()[0]
        m.parse_runner(self.command(name, dict(checks, userCount=4096)), self.plan)


if __name__ == '__main__':
    unittest.main()
