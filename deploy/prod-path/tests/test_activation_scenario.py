"""Offline: validate the actual CLI. No node, panel, network or deployment adapter."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CLI = Path(__file__).resolve().parents[1] / 'activation-scenario.py'
OP = 'abb507e7fe8a3dae930a20b5'
LINK = '6afafb6d991fd12f22e9f457'


class ActivationScenarioTest(unittest.TestCase):
    def invoke(self, config, *flags):
        with tempfile.TemporaryDirectory() as folder:
            cfg = Path(folder) / 'config.json'
            cfg.write_text(json.dumps(config), encoding='utf-8')
            return subprocess.run([sys.executable, '-I', '-B', str(CLI), '--config', str(cfg), *flags],
                                  cwd=folder, capture_output=True, text=True, timeout=5, check=False)

    def test_retained_pp16_never_submits_apply_or_reinstalls_guards(self):
        result = self.invoke({'target':'pp16', 'mode':'resume', 'linkId':LINK, 'operationId':OP}, '--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        obj = json.loads(result.stdout)
        self.assertEqual(obj['operationId'], OP)
        self.assertEqual(obj['steps'], ['preflight', 'check-backup', 'check-isolation-and-masks', 'check-live-guards',
                                       'start-backend', 'wait-original-succeeded', 'check-release', 'client-dns-https', 'report'])
        self.assertFalse(obj['executed'])

    def test_first_reverse_plans_backup_before_exclusion_and_client_after_settlement(self):
        result = self.invoke({'target':'prod','mode':'first-reverse','linkId':LINK}, '--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['steps'], ['preflight', 'backup', 'exclude-writers', 'install-helpers-guards-units',
                                                             'start-backend', 'submit-apply-once', 'wait-submitted-succeeded',
                                                             'check-release', 'client-dns-https', 'report'])

    def test_unknown_keys_and_foreign_resume_are_refused_without_echo(self):
        base = {'target':'pp16','mode':'resume','linkId':LINK,'operationId':OP}
        for cfg in ({**base, 'cmd':'do-not-echo-this'}, {**base,'operationId':'0'*24},
                    {**base,'target':'prod'}, {**base,'linkId':'1'*24}):
            with self.subTest():
                result = self.invoke(cfg, '--dry-run')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('do-not-echo-this', result.stdout + result.stderr)

    def test_no_flag_never_enables_even_pp16(self):
        for cfg in ({'target':'pp16','mode':'resume','operationId':OP,'linkId':LINK},
                    {'target':'prod','mode':'first-reverse','linkId':LINK}):
            result = self.invoke(cfg)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('LIVE_DISABLED', result.stderr)
            self.assertEqual(result.stdout, '')
