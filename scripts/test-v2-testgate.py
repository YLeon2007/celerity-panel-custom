#!/usr/bin/env python3
"""Offline TEST snapshot sealing, restore rehearsal and egress evidence gate.

Never connects to hosts, runs Docker or changes the install tree. A manifest hash
must be recorded out of band; a re-sealed corrupted snapshot is not trustworthy.
"""
import argparse
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

MANIFEST = 'test-v2-manifest.json'
REQUIRED = {
    'panel': {'source.bundle', 'source.tar.gz', 'mongo.archive.gz', '.env', 'docker-compose.yml',
              'docker-compose.local.yml', 'Caddyfile'},
    'node': {'node-config.tar.gz', 'hostname.txt'},
}
ARCHIVES = {'source.tar.gz', 'node-config.tar.gz'}
MAX_MEMBER = 128 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024


class Refused(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def digest_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def inspect_tree(root, role, manifest_exists):
    need(root.is_absolute() and root.is_dir() and not root.is_symlink(), 'snapshot directory must be an absolute real directory')
    need(stat.S_IMODE(root.stat().st_mode) & 0o077 == 0, 'snapshot directory must be private')
    files = {}
    for item in root.iterdir():
        need(item.is_file() and not item.is_symlink() and item.name != 'SHA256SUMS',
             'snapshot must contain only regular top-level files (no symlinks)')
        need(stat.S_IMODE(item.stat().st_mode) & 0o077 == 0, 'snapshot files must be private')
        if item.name == MANIFEST:
            need(manifest_exists, 'manifest already exists')
            continue
        need(item.stat().st_size > 0, 'snapshot has an empty file')
        files[item.name] = digest_file(item)
    need(REQUIRED[role] <= files.keys(), 'required snapshot components are missing')
    need(not ('node-config.tar.gz' in files and role == 'panel'), 'node artifact in panel snapshot')
    need(not ('mongo.archive.gz' in files and role == 'node'), 'panel artifact in node snapshot')
    return files


def restore_archive(path):
    """Stream and independently hash every extracted regular file in a disposable tree."""
    total = 0
    names = set()
    regular_files = set()
    restored_hashes = {}
    with tempfile.TemporaryDirectory(prefix='test-v2-restore-') as temp:
        with tarfile.open(path, 'r:gz') as archive:
            for member in archive:
                name = member.name
                parts = name.split('/')
                need(name and not name.startswith('/') and '\\' not in name and
                     all(part not in ('', '.', '..') for part in parts), 'unsafe archive path')
                need(name not in names, 'duplicate archive member')
                names.add(name)
                need(member.isfile() or member.isdir(), 'archive link or special member refused')
                destination = Path(temp).joinpath(*PurePosixPath(name).parts)
                need(not any('/'.join(parts[:index]) in regular_files
                             for index in range(1, len(parts))), 'archive child below file')
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                need(0 <= member.size <= MAX_MEMBER, 'oversized archive member')
                regular_files.add(name)
                total += member.size
                need(total <= MAX_TOTAL, 'oversized archive')
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                need(source is not None, 'unreadable archive member')
                expected = hashlib.sha256()
                remaining = member.size
                with destination.open('xb') as output:
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        need(chunk, 'truncated archive member')
                        expected.update(chunk)
                        output.write(chunk)
                        remaining -= len(chunk)
                need(digest_file(destination) == expected.hexdigest(), 'offline restore mismatch')
                restored_hashes[name] = expected.hexdigest()
    need(total > 0, 'archive contains no files')
    return restored_hashes


def check_artifacts(root, files, role, host):
    if role == 'panel':
        domains = []
        for raw in (root / '.env').read_text(encoding='utf-8').splitlines():
            line = raw.strip()
            if line.startswith('PANEL_DOMAIN='):
                domains.append(line.split('=', 1)[1])
        need(domains == ['test.infograd.online'], 'panel domain is not uniquely TEST')
        with tempfile.TemporaryDirectory(prefix='test-v2-bundle-') as repo:
            init = subprocess.run(['git', 'init', '-q', repo], capture_output=True)
            verified = subprocess.run(['git', '-C', repo, 'bundle', 'verify', str(root / 'source.bundle')],
                                      capture_output=True) if init.returncode == 0 else init
            need(verified.returncode == 0, 'source Git bundle cannot be verified')
    else:
        need((root / 'hostname.txt').read_text(encoding='utf-8').strip() == host,
             'node hostname does not match expected identity')
    for filename in sorted(files):
        if filename in ARCHIVES:
            restored_names = restore_archive(root / filename)
            if filename == 'source.tar.gz':
                need('docker-compose.yml' in restored_names,
                     'source archive lacks deployed Compose file')
                need(restored_names['docker-compose.yml'] == files['docker-compose.yml'],
                     'source archive and captured Compose differ')
            if filename == 'node-config.tar.gz':
                need(any(name.startswith('usr/local/etc/xray/') for name in restored_names),
                     'node archive lacks Xray configuration')
        if filename == 'mongo.archive.gz':
            with gzip.open(root / filename, 'rb') as stream:
                need(bool(stream.read(1)), 'Mongo archive is empty')
                expanded = 1
                while chunk := stream.read(1024 * 1024):
                    expanded += len(chunk)
                    need(expanded <= MAX_TOTAL, 'oversized Mongo archive')
                # gzip trailer checked; mongorestore --dryRun is still required remotely


def seal(args):
    root = Path(args.backup_dir)
    files = inspect_tree(root, args.role, False)
    check_artifacts(root, files, args.role, args.host)
    need(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}', args.host), 'unsafe host label')
    manifest = {'schema': 1, 'target': 'TEST', 'role': args.role, 'host': args.host,
                'files': files}
    data = (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode()
    descriptor = os.open(root / MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    print('snapshot_sealed=TEST')
    print('manifest_sha256=' + hashlib.sha256(data).hexdigest())


def verify(args):
    root = Path(args.backup_dir)
    need(re.fullmatch(r'[0-9a-f]{64}', args.manifest_sha256), 'invalid manifest pin')
    need((root / MANIFEST).is_file() and not (root / MANIFEST).is_symlink(), 'manifest missing or unsafe')
    need(digest_file(root / MANIFEST) == args.manifest_sha256, 'manifest hash differs from pinned value')
    manifest = json.loads((root / MANIFEST).read_text())
    need(type(manifest) is dict and set(manifest) == {'schema', 'target', 'role', 'host', 'files'} and
         manifest['schema'] == 1 and manifest['target'] == 'TEST' and
         manifest['role'] == args.role and manifest['host'] == args.host and
         type(manifest['files']) is dict, 'snapshot identity mismatch')
    files = inspect_tree(root, args.role, True)
    need(files == manifest['files'], 'snapshot file set or checksum differs')
    check_artifacts(root, files, args.role, args.host)
    print('snapshot_verified=TEST')
    print('offline_restore=passed')
    print('remote_mongorestore_dryrun=required' if args.role == 'panel' else 'remote_restore=required')


def egress(args):
    evidence_path = Path(args.evidence)
    need(evidence_path.is_file() and evidence_path.stat().st_size <= 32768, 'invalid evidence file')
    payload = json.loads(evidence_path.read_text())
    need(type(payload) is dict and set(payload) == {'schema', 'target', 'client', 'routes'} and
         payload['schema'] == 1 and payload['target'] == 'TEST' and
         payload['client'] == 'disposable-loopback' and type(payload['routes']) is list,
         'invalid TEST evidence schema')
    routes = payload['routes']
    need(len(routes) == 2 and {r.get('route') for r in routes if type(r) is dict} == {'default', 'geo'},
         'both default and geo routes are required')
    need(routes[0]['expected_bridge'] != routes[1]['expected_bridge'] and
         routes[0]['expected_egress_ip'] != routes[1]['expected_egress_ip'],
         'default and geo must use distinct bridge exits')
    fields = {'route', 'expected_bridge', 'observed_bridge', 'expected_egress_ip',
              'observed_egress_ip', 'http_status', 'bridge_request_seen', 'portal_request_seen'}
    for route in routes:
        need(set(route) == fields, 'unexpected or missing evidence field (do not include secrets)')
        need(type(route['expected_bridge']) is str and route['expected_bridge'].startswith('test-') and
             route['observed_bridge'] == route['expected_bridge'], 'bridge correlation failed')
        for field in ('expected_egress_ip', 'observed_egress_ip'):
            try:
                ip = ipaddress.ip_address(route[field])
            except (ValueError, TypeError):
                raise Refused('invalid egress IP') from None
            need(ip.version == 4, 'IPv4 egress evidence required')
        need(route['observed_egress_ip'] == route['expected_egress_ip'], 'egress IP mismatch')
        need(type(route['http_status']) is int and 200 <= route['http_status'] < 400,
             'probe HTTP result failed')
        need(route['bridge_request_seen'] is True and route['portal_request_seen'] is True,
             'portal/bridge request correlation missing')
    print('controlled_egress_evidence=passed')
    print('phone_happ_e2e=required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('seal', 'verify'):
        sub = commands.add_parser(name)
        sub.add_argument('--role', choices=('panel', 'node'), required=True)
        sub.add_argument('--host', required=True)
        sub.add_argument('--backup-dir', required=True)
        if name == 'verify':
            sub.add_argument('--manifest-sha256', required=True)
    commands.add_parser('egress').add_argument('--evidence', required=True)
    args = parser.parse_args()
    try:
        {'seal': seal, 'verify': verify, 'egress': egress}[args.command](args)
    except (Refused, OSError, ValueError, KeyError, TypeError, tarfile.TarError, EOFError) as error:
        # No exception values: OS/tar errors can contain sensitive filenames.
        print('TEST preflight refused: ' + (str(error) if isinstance(error, Refused) else type(error).__name__), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
