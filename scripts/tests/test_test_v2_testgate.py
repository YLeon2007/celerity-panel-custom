#!/usr/bin/env python3
"""Offline tests: no SSH, Docker, network or production dependencies."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'test-v2-testgate.py'


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], text=True, capture_output=True)


def archive(path, name='usr/local/etc/xray/config.json', contents=b'fixture', kind=None):
    with tarfile.open(path, 'w:gz') as tar:
        entry = tarfile.TarInfo(name)
        if kind == 'link':
            entry.type = tarfile.SYMTYPE
            entry.linkname = '/etc/shadow'
        else:
            entry.size = len(contents)
        tar.addfile(entry, None if kind else io.BytesIO(contents))
    path.chmod(0o600)


class TestGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.backup = self.root / 'backup'
        self.backup.mkdir(mode=0o700)
        archive(self.backup / 'node-config.tar.gz')
        (self.backup / 'hostname.txt').write_text('test-bridge-a\n')
        (self.backup / 'hostname.txt').chmod(0o600)
        self.host = 'test-bridge-a'

    def seal(self):
        result = run('seal', '--role', 'node', '--host', self.host, '--backup-dir', self.backup)
        self.assertEqual(result.returncode, 0, result.stderr)
        return hashlib.sha256((self.backup / 'test-v2-manifest.json').read_bytes()).hexdigest()

    def verify(self, digest, host=None):
        return run('verify', '--role', 'node', '--host', host or self.host,
                   '--backup-dir', self.backup, '--manifest-sha256', digest)

    def test_seal_and_offline_restore_drill(self):
        digest = self.seal()
        result = self.verify(digest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('offline_restore=passed', result.stdout)
        self.assertNotIn('fixture', result.stdout)
        self.assertNotIn(str(self.backup), result.stdout)

    def test_tampering_and_wrong_host_fail_closed(self):
        digest = self.seal()
        self.assertNotEqual(self.verify(digest, 'test-bridge-b').returncode, 0)
        archive(self.backup / 'node-config.tar.gz', contents=b'changed')
        self.assertNotEqual(self.verify(digest).returncode, 0)

    def test_unsafe_archive_refused_before_seal(self):
        for name, kind in [('../escape', None), ('/etc/shadow', None), ('usr/local/etc/xray/config', 'link')]:
            archive(self.backup / 'node-config.tar.gz', name, kind=kind)
            result = run('seal', '--role', 'node', '--host', self.host, '--backup-dir', self.backup)
            self.assertNotEqual(result.returncode, 0, (name, result.stdout))
            self.assertFalse((self.backup / 'test-v2-manifest.json').exists())

    def test_permissions_and_unlisted_files_refused(self):
        (self.backup / 'node-config.tar.gz').chmod(0o644)
        self.assertNotEqual(run('seal', '--role', 'node', '--host', self.host, '--backup-dir', self.backup).returncode, 0)
        (self.backup / 'node-config.tar.gz').chmod(0o600)
        digest = self.seal()
        (self.backup / 'extra').write_text('unexpected secret')
        self.assertNotEqual(self.verify(digest).returncode, 0)

    def test_panel_requires_restorable_source_and_test_domain(self):
        (self.backup / 'node-config.tar.gz').unlink()
        (self.backup / 'hostname.txt').unlink()
        for filename in ('mongo.archive.gz', '.env', 'docker-compose.yml',
                         'docker-compose.local.yml', 'Caddyfile'):
            (self.backup / filename).write_bytes(b'placeholder')
            (self.backup / filename).chmod(0o600)
        (self.backup / 'docker-compose.yml').write_bytes(b'fixture\n')
        archive(self.backup / 'source.tar.gz', name='docker-compose.yml', contents=b'fixture\n')
        repo = self.root / 'source'
        repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        (repo / 'docker-compose.yml').write_text('fixture\n')
        subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], check=True)
        subprocess.run(['git', '-C', str(repo), 'bundle', 'create',
                        str(self.backup / 'source.bundle'), '--all'], check=True)
        (self.backup / 'source.bundle').chmod(0o600)
        with gzip.open(self.backup / 'mongo.archive.gz', 'wb') as output:
            output.write(b'fixture')
        (self.backup / 'mongo.archive.gz').chmod(0o600)
        (self.backup / '.env').write_text('PANEL_DOMAIN=production.example\n')
        self.assertNotEqual(run('seal', '--role', 'panel', '--host', 'VM-976045',
                                '--backup-dir', self.backup).returncode, 0)
        (self.backup / '.env').write_text('PANEL_DOMAIN=test.infograd.online\n')
        result = run('seal', '--role', 'panel', '--host', 'VM-976045', '--backup-dir', self.backup)
        self.assertEqual(result.returncode, 0, result.stderr)
        digest = hashlib.sha256((self.backup / 'test-v2-manifest.json').read_bytes()).hexdigest()
        self.assertEqual(run('verify', '--role', 'panel', '--host', 'VM-976045',
                             '--backup-dir', self.backup, '--manifest-sha256', digest).returncode, 0)
        (self.backup / 'test-v2-manifest.json').unlink()
        archive(self.backup / 'source.tar.gz', name='README.md')
        self.assertNotEqual(run('seal', '--role', 'panel', '--host', 'VM-976045',
                                '--backup-dir', self.backup).returncode, 0)
        archive(self.backup / 'source.tar.gz', name='docker-compose.yml', contents=b'mismatch')
        self.assertNotEqual(run('seal', '--role', 'panel', '--host', 'VM-976045',
                                '--backup-dir', self.backup).returncode, 0)

    def test_archive_child_below_file_refused(self):
        path = self.backup / 'node-config.tar.gz'
        with tarfile.open(path, 'w:gz') as tar:
            for name in ('etc/xray', 'etc/xray/config.json'):
                data = b'fixture'
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        path.chmod(0o600)
        self.assertNotEqual(run('seal', '--role', 'node', '--host', self.host,
                                '--backup-dir', self.backup).returncode, 0)

    def test_egress_evidence_requires_correlated_both_routes(self):
        evidence = self.root / 'evidence.json'
        payload = {'schema': 1, 'target': 'TEST', 'client': 'disposable-loopback',
                   'routes': [
                       {'route': 'default', 'expected_bridge': 'test-bridge-a', 'observed_bridge': 'test-bridge-a',
                        'expected_egress_ip': '198.51.100.10', 'observed_egress_ip': '198.51.100.10',
                        'http_status': 200, 'bridge_request_seen': True, 'portal_request_seen': True},
                       {'route': 'geo', 'expected_bridge': 'test-bridge-b', 'observed_bridge': 'test-bridge-b',
                        'expected_egress_ip': '203.0.113.20', 'observed_egress_ip': '203.0.113.20',
                        'http_status': 200, 'bridge_request_seen': True, 'portal_request_seen': True}]}
        evidence.write_text(json.dumps(payload))
        self.assertEqual(run('egress', '--evidence', evidence).returncode, 0)
        payload['routes'][1]['expected_bridge'] = 'test-bridge-a'
        payload['routes'][1]['observed_bridge'] = 'test-bridge-a'
        evidence.write_text(json.dumps(payload))
        self.assertNotEqual(run('egress', '--evidence', evidence).returncode, 0)
        payload['routes'][1]['expected_bridge'] = 'test-bridge-b'
        payload['routes'][1]['observed_bridge'] = 'test-bridge-a'
        evidence.write_text(json.dumps(payload))
        self.assertNotEqual(run('egress', '--evidence', evidence).returncode, 0)
        payload['routes'][1]['observed_bridge'] = 'test-bridge-b'
        payload['routes'][1]['portal_request_seen'] = False
        evidence.write_text(json.dumps(payload))
        self.assertNotEqual(run('egress', '--evidence', evidence).returncode, 0)


if __name__ == '__main__':
    unittest.main()
