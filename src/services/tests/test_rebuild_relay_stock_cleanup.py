"""Offline stock cleanup: real files, memfds, planning and VAULT; no native children."""
import contextlib
import fcntl
import io
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import syslog
import tarfile
import time
import unittest
from email.utils import formatdate
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
CLEANUP = runpy.run_path(str(HERE / 'rebuildRelayDirectCleanupHost.py'))
MACHINE, NETWORK, TOKEN = (CLEANUP[k] for k in ('MACHINE', 'NETWORK', 'TOKEN'))
STARTER, SECRETS, LNS = ('STARTER_NOT_STOCK', 'SECRETS_NOT_EMPTY', 'LNS_NOT_STOCK')
STOCK = {STARTER: b'config setup\ninclude /etc/ipsec.d/*.conf\n', SECRETS: b'# Debian sample\n',
         LNS: b'# default xl2tpd\n'}
VERSIONS = {'strongswan-starter': '1:6.0.1-6+deb13u7', 'xl2tpd': '1.3.18-1+b1'}
FORMAT = r'-f=${binary:Package}\t${Status}\t${Architecture}\t${Version}\n${Conffiles}'


def tar(rows):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as out:
        for name, data in rows:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            out.addfile(member, io.BytesIO(data))
    return stream.getvalue()


class StockCleanup(CLEANUP['Cleanup']):
    def setUp(self):
        super().setUp()
        self.r = self.h['C3_REPLACEMENT']
        self.h['command'] = self.command_stock
        self.h['bounded_status'] = self.child
        self.h['native_vpn'] = lambda *_: self.native
        self.h['stock_workspace'] = self.workspace
        self.native = True
        self.children = []
        self.scratch = self.path('/run')
        self.scratch.mkdir()
        self.put('/usr/lib/os-release', b'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n')
        self.put('/usr/share/keyrings/debian-archive-keyring.pgp', b'synthetic keyring (signature child modeled)')
        self.path('/usr/share/keyrings/debian-archive-keyring.gpg').symlink_to('debian-archive-keyring.pgp')
        self.put('/usr/bin/gpgv', b'modeled verifier', 0o755)
        self.path('/var/cache/apt/archives').mkdir(parents=True)
        self.installed_arch = 'amd64'
        self.foreign = {}
        self.package_rows = dict.fromkeys(VERSIONS, b'')
        self.data_tar = {p: [] for p in VERSIONS}
        self.payload = {p: f'modeled deb bytes for {p}'.encode() for p in VERSIONS}
        self.downloaded = dict(self.payload)
        self.child_failure = None
        self.refresh_options = {}
        for name, key, package in zip(('starter', 'secrets', 'lns'), STOCK,
                                      ('strongswan-starter', 'strongswan-starter', 'xl2tpd')):
            path = self.h['NAMES'][name]
            self.foreign[path] = f'foreign {name} (private)\n'.encode()
            self.put(path, self.foreign[path])
            self.package_rows[package] += f" {path} {self.r['md5'](STOCK[key])}\n".encode()
            self.data_tar[package].append(('.' + path, STOCK[key]))
        self.stock = self.package_rows
        self.materialize_indexes()
        self.log = self.enterContext(patch.object(syslog, 'syslog'))
        # The stock adapter should not create stage files in actual /run.
        self.enterContext(patch.dict(self.r['stage_installed_stock'].__globals__, apt_stage_user=lambda: (0, 0)))
        self.enterContext(patch.object(os, 'chown', side_effect=lambda path, *_: self.assertEqual(path.parent.parent, self.scratch)))

    @contextlib.contextmanager
    def workspace(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=self.scratch) as work:
            yield Path(work)

    def index_response(self, suite, *, expired=False, exact=True):
        def record(package, blob):
            ver = VERSIONS[package] if exact else '1.0'
            pool = 'pool/updates' if suite == 'trixie-security' else 'pool'
            return (f'Package: {package}\nVersion: {ver}\nArchitecture: amd64\n'
                    f'Filename: {pool}/main/{package[0]}/{package}/{package}.deb\n'
                    f'Size: {len(blob)}\nSHA256: {self.r["sha256"](blob)}\n\n').encode()
        # Starter available only in security, xl2tpd only in the base suite.
        members = {'trixie': {'xl2tpd'}, 'trixie-security': {'strongswan-starter'}}.get(suite, set())
        index = b''.join(record(p, b) for p, b in self.payload.items() if p in members)
        release = (f'Origin: Debian\nCodename: {suite}\nDate: {formatdate(time.time() - 3600, usegmt=True)}\n'
                   f'Valid-Until: {formatdate(time.time() + (-1 if expired else 3600), usegmt=True)}\n'
                   f'SHA256:\n {self.r["sha256"](index)} {len(index)} main/binary-amd64/Packages\n').encode()
        return release, index

    def materialize_indexes(self, *, expired=False, compressed=False):
        release, index = self.index_response('trixie-security', expired=expired)
        stem = '/var/lib/apt/lists/deb.debian.org_debian-security_dists_trixie-security_'
        self.put(stem + 'InRelease', release)
        self.index = index
        if compressed:
            self.path(stem + 'main_binary-amd64_Packages').unlink(missing_ok=True)
            self.put(stem + 'main_binary-amd64_Packages.lz4', b'modeled compressed list')
        else:
            self.put(stem + 'main_binary-amd64_Packages', index)
        stem = '/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_'
        release, index = self.index_response('trixie', expired=expired)
        self.put(stem + 'InRelease', release)
        self.put(stem + 'main_binary-amd64_Packages', index)

    def command_stock(self, *args, **kwargs):
        if args[:3] == ('/usr/bin/dpkg-query', '-W', FORMAT):
            package = args[3]
            return (f'{package}\tinstall ok installed\t{self.installed_arch}\t{VERSIONS[package]}\n'.encode()
                    + self.package_rows[package])
        return self.command_cleanup(*args, **kwargs)

    def child(self, argv, end, maximum, **kwargs):
        self.children.append(tuple(argv))
        self.assertLess(time.monotonic(), end)
        self.assertGreater(maximum, 0)
        self.assertTrue(kwargs['stock_stage'])
        if argv[0] == '/usr/bin/sqv':
            self.assertTrue(self.path(argv[0]).is_file())
            self.assertEqual((argv[1], argv[3:5]), ('--keyring', ('--cleartext', '--output')))
            self.assertEqual(Path(argv[2]).read_bytes(), b'synthetic keyring (signature child modeled)')
            # sqv writes the cleartext to a named file; stdout isn't the Release.
            Path(argv[5]).write_bytes(Path(argv[-1]).read_bytes())
            return (1 if self.child_failure == 'signature' else 0), b'public signer fingerprint\n', b''
        if argv[0] == '/usr/bin/gpgv':
            self.assertTrue(self.path(argv[0]).is_file())
            if self.child_failure == 'signature':
                return 1, Path(argv[-1]).read_bytes(), b'private signature diagnostics'
            return 0, Path(argv[-1]).read_bytes(), b'synthetic good signature'
        if argv[:2] == ('/usr/lib/apt/apt-helper', 'cat-file'):
            self.assertEqual(Path(argv[2]).suffix, '.lz4')
            self.assertEqual(Path(argv[2]).read_bytes(), b'modeled compressed list')
            self.assertEqual(kwargs['stock_owner'], (0, 0))  # modeled identity, same seam as update/download
            self.assertEqual(Path(kwargs['stock_cwd']), Path(argv[2]).parent)
            self.assertEqual(Path(kwargs['stock_config']).read_text(),
                             'Dir::Etc::Parts "/dev/null";\nDir::Etc::Main "/dev/null";\n')
            return 0, self.index, b''
        if argv[0] == '/usr/bin/dpkg-deb':
            blob = Path(argv[2]).read_bytes()
            package, = [p for p, data in self.payload.items() if data == blob]
            with open(argv[2], 'rb') as fd:
                seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
            self.assertEqual(seals & 15, 15)
            if argv[1] == '--ctrl-tarfile':
                return 0, tar([('./control', f'Package: {package}\nVersion: {VERSIONS[package]}\nArchitecture: amd64\n'.encode())]), b''
            self.assertEqual(argv[1], '--fsys-tarfile')
            return 0, tar(self.data_tar[package]), b''
        self.assertEqual(argv[:4], ('/usr/bin/prlimit', argv[1], '--', '/usr/bin/apt-get'))
        self.assertRegex(argv[1], r'^--fsize=\d+:\d+$')
        config = Path(kwargs['stock_config']).read_text()
        for setting in ('Dir::Etc::Parts "/dev/null"', 'Dir::Bin::dpkg "/dev/null"',
                        'APT::Update::Error-Mode "any"', 'Acquire::Check-Valid-Until "true"',
                        'Dir::Etc::Main "/dev/null"', 'Dir::Etc::sourceparts "/dev/null"',
                        'Dir::State::status "/dev/null"', 'Dir::Cache::archives "/dev/null"',
                        'APT::Get::AllowUnauthenticated "false"', 'Acquire::https::AllowRedirect "false"'):
            self.assertIn(setting, config)
        match = re.search(r'Dir::State::lists "([^"]+)";', config)
        lists = Path(match[1])
        self.assertEqual(lists.parent, Path(kwargs['stock_config']).parent)
        self.assertEqual(Path(kwargs['stock_cwd']).parent.parent, self.scratch)
        self.assertEqual(kwargs['stock_owner'], (0, 0))  # UID/GID modeled in this suite
        self.assertEqual(Path(kwargs['stock_cwd']).stat().st_mode & 0o777, 0o700)
        self.assertEqual(lists.parent.stat().st_mode & 0o777, 0o711)
        self.assertEqual(lists.stat().st_mode & 0o777, 0o755)
        if argv[4] == 'update':
            incoming = lists.parent / 'incoming'
            self.assertEqual(argv[5:], ('-o', f'Dir::State::lists={incoming}/'))
            self.assertEqual(incoming.stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(incoming.iterdir()), [])
            self.assertEqual(list(lists.iterdir()), [])
            keyring = lists.parent / 'debian.gpg'
            sources = (lists.parent / 'sources.list').read_text().splitlines()
            fixtures = [('https://deb.debian.org/debian/', 'trixie', 'deb.debian.org_debian'),
                        ('https://deb.debian.org/debian/', 'trixie-updates', 'deb.debian.org_debian'),
                        ('https://security.debian.org/debian-security/', 'trixie-security', 'security.debian.org_debian-security')]
            self.assertEqual(sources, [f'deb [arch=amd64 signed-by={keyring}] {uri} {suite} main'
                                       for uri, suite, _ in fixtures])
            for _, suite, host in fixtures:
                release, index = self.index_response(suite, **{k: v for k, v in self.refresh_options.items() if k != 'corrupt'})
                stem = f'{host}_dists_{suite}_'
                (incoming / (stem + 'InRelease')).write_bytes(release)
                if index:
                    (incoming / (stem + 'main_binary-amd64_Packages')).write_bytes(index[:-1] + b'x' if self.refresh_options.get('corrupt') else index)
            if self.child_failure == 'update':
                return 100, b'', b'private connection diagnostics'
            if self.child_failure == 'update_warning':
                return 0, b'', b'private partial acquisition diagnostics'
            return 0, b'', b''
        self.assertEqual(len(argv), 6)
        self.assertEqual(argv[4], 'download')
        package, sep, spec = argv[5].partition(':')
        self.assertEqual((sep, spec), (':', f'amd64={VERSIONS[package]}'))
        suite = 'trixie-security' if package == 'strongswan-starter' else 'trixie'
        index, = lists.glob(f'*_dists_{suite}_*_Packages')
        self.assertEqual(index.read_bytes(), self.index_response(suite)[1])
        self.assertEqual(index.stat().st_mode & 0o777, 0o644)
        if self.child_failure == 'timeout':
            raise subprocess.TimeoutExpired(argv, 0)
        if self.child_failure == 'apt':
            return 100, b'', b'private apt diagnostics'
        (Path(kwargs['stock_cwd']) / 'fixture.deb').write_bytes(self.downloaded[package])
        if self.child_failure == 'unsandboxed':
            return 0, b'', b'W: Download is performed unsandboxed as root (private diagnostics)'
        return 0, b'', b''

    def challenge(self):
        code, out, err = self.run_host()
        self.assertEqual((code, out), (70, ''))
        kind, keys, digest, cleanable = err.strip().split(' ')
        self.assertEqual(kind, 'DIRECT_L2TP_FOREIGN_CONFIG')
        self.assertEqual(keys, 'STARTER_NOT_STOCK,SECRETS_NOT_EMPTY,CHAP_NOT_EMPTY,LNS_NOT_STOCK')
        self.assertEqual(cleanable, keys)
        return {'digest': digest, 'fixXrayUnitMode': False, 'at': '2026-11-25T08:25:00.000Z'}

    def test_observation_and_stale_consent_never_stage(self):
        before = self.snapshot()
        with patch.dict(self.h, stock_workspace=lambda: self.fail('unexpected staging before consent')):
            auth = self.challenge()
            self.assertEqual(self.snapshot(), before)
            auth['digest'] = '0' * 64
            self.assertTrue(self.run_host(foreignCleanup=auth)[2].startswith('DIRECT_L2TP_FOREIGN_CONFIG_CHANGED '))
        self.assertEqual(self.children, [])
        self.assertEqual(self.snapshot(), before)

    def seed_cache(self, data):
        self.put('/var/cache/apt/archives/strongswan-starter_1%3a6.0.1-6+deb13u7_amd64.deb', data)

    def apt_calls(self):
        return [a[4] for a in self.children if a[0] == '/usr/bin/prlimit']

    def test_expired_mirror_file_lists_authenticate_offline_cache(self):
        self.materialize_indexes(expired=True, compressed=True)
        lists = self.path('/var/lib/apt/lists')
        for leaf in lists.iterdir():
            leaf.rename(lists / leaf.name.replace('deb.debian.org_debian', '_etc_apt_mirrors_debian.list'))
        self.seed_cache(self.payload['strongswan-starter'])
        self.put('/var/cache/apt/archives/xl2tpd_1.3.18-1+b1_amd64.deb', self.payload['xl2tpd'])
        self.prepare(self.challenge())
        self.assertNotIn('/usr/bin/prlimit', [a[0] for a in self.children])

    def test_absent_lists_and_expired_lists_use_one_private_refresh(self):
        for absent in (True, False):
            with self.subTest(absent=absent):
                self.materialize_indexes(expired=True)
                if absent:
                    shutil.rmtree(self.path('/var/lib/apt/lists'))
                self.children.clear()
                self.prepare(self.challenge())
                apt = [a[4] for a in self.children if a[0] == '/usr/bin/prlimit']
                self.assertEqual(apt, ['update', 'download', 'download'])

    def test_authenticated_cache_and_exact_download_project_and_publish_only_after_vault(self):
        auth = self.challenge()
        self.seed_cache(self.payload['strongswan-starter'])
        before = self.snapshot()
        request = self.prepare(auth)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.apt_calls(), ['update', 'download'])
        self.assertEqual([a[5] for a in self.children if a[4:5] == ('download',)], ['xl2tpd:amd64=1.3.18-1+b1'])
        self.assertEqual(self.run_host('check', **request), (0, f'{{"ok":true,"backupId":"{TOKEN}"}}\n', ''))
        self.assertEqual(self.snapshot(), before)
        old_write = self.h['write']
        writes = []
        def write(path, *args, **kwargs):
            if path in self.foreign:
                manifest = self.h['read'](self.h['manifest_path'](TOKEN))
                fence = self.h['read'](self.h['VAULT'] + '/foreign-cleanup.pending')
                self.assertTrue(manifest and fence)
                writes.append(path)
            return old_write(path, *args, **kwargs)
        self.h['write'] = write
        self.assertEqual(self.run_host('install', **request)[0], 75)  # synthetic cut before ordinary Install
        self.assertTrue(self.stock_entered)
        self.assertEqual(writes, [self.h['NAMES'][k] for k in ('starter', 'secrets', 'lns')])
        self.assertEqual([self.path(p).read_bytes() for p in writes], list(STOCK.values()))

    def refused(self, auth):
        before = self.snapshot()
        code, out, err = self.run_host(**({'foreignCleanup': auth} if auth is not None else {}))
        self.assertEqual((code, out, err), (70, '', 'DIRECT_L2TP_FOREIGN_CONFIG CONFFILE_UNKNOWN\n'))
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.path(self.h['VAULT']).exists())

    def test_bad_md5_after_authenticated_archive_keeps_every_original(self):
        auth = self.challenge()
        self.data_tar['xl2tpd'] = [('./etc/xl2tpd/xl2tpd.conf', b'# wrong default\n')]
        self.refused(auth)
        self.assertEqual(sum(a[:2] == ('/usr/bin/dpkg-deb', '--fsys-tarfile') for a in self.children), 2)

    def test_sqv_only_pgp_only_empty_cache_downloads_both_packages(self):
        self.put('/usr/bin/sqv', b'modeled verifier', 0o755)
        self.path('/usr/bin/gpgv').unlink()
        self.path('/usr/share/keyrings/debian-archive-keyring.gpg').unlink()
        auth = self.challenge()
        before = self.snapshot()
        self.prepare(auth)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual([a[0] for a in self.children[:4]], ['/usr/bin/prlimit', *(['/usr/bin/sqv'] * 3)])
        self.assertEqual([a[5] for a in self.children if a[4:5] == ('download',)],
                         ['strongswan-starter:amd64=1:6.0.1-6+deb13u7', 'xl2tpd:amd64=1.3.18-1+b1'])

    def test_preferred_sqv_refusal_does_not_try_gpgv_or_use_output(self):
        self.put('/usr/bin/sqv', b'modeled verifier', 0o755)
        self.child_failure = 'signature'
        self.refused(self.challenge())
        self.assertEqual([a[0] for a in self.children], ['/usr/bin/prlimit', '/usr/bin/sqv'])

    def test_legacy_regular_gpg_keyring_still_works(self):
        keyring = self.path('/usr/share/keyrings/debian-archive-keyring.gpg')
        keyring.unlink()
        self.path('/usr/share/keyrings/debian-archive-keyring.pgp').rename(keyring)
        self.prepare(self.challenge())
        self.assertEqual(self.children[1][0], '/usr/bin/gpgv')

    def test_missing_verifiers_log_fixed_reason_without_staging(self):
        self.path('/usr/bin/gpgv').unlink()
        with patch.object(syslog, 'syslog') as log:
            auth = self.challenge()
            log.assert_not_called()
            self.refused(auth)
            log.assert_called_once_with(syslog.LOG_WARNING, 'celerity-rebuild-l2tp: STOCK_SIGNATURE_VERIFIER_MISSING')
        self.assertEqual(self.children, [])

    def test_success_status_with_unsandboxed_warning_never_extracts(self):
        self.child_failure = 'unsandboxed'
        self.refused(self.challenge())
        self.assertEqual(self.apt_calls(), ['update', 'download'])
        self.assertFalse(any(a[0] == '/usr/bin/dpkg-deb' for a in self.children))

    def test_bad_cache_no_download_or_extraction(self):
        auth = self.challenge()
        self.seed_cache(b'x' * len(self.payload['strongswan-starter']))
        self.refused(auth)
        self.assertEqual([a[0] for a in self.children], ['/usr/bin/gpgv'])

    def test_private_refresh_authenticates_existing_cache_when_lists_are_absent(self):
        shutil.rmtree(self.path('/var/lib/apt/lists'))
        auth = self.challenge()
        self.seed_cache(b'x' * len(self.payload['strongswan-starter']))
        self.refused(auth)
        self.assertEqual(self.apt_calls(), ['update'])
        self.assertFalse(any(a[0] == '/usr/bin/dpkg-deb' for a in self.children))
        self.log.assert_called_once_with(syslog.LOG_WARNING, 'celerity-rebuild-l2tp: REPLACEMENT_DEB_BYTES')
        self.children.clear()
        self.seed_cache(self.payload['strongswan-starter'])
        self.prepare(auth)
        self.assertEqual(self.apt_calls(), ['update', 'download'])
        self.assertEqual([a[5] for a in self.children if a[4:5] == ('download',)], ['xl2tpd:amd64=1.3.18-1+b1'])

    def test_compressed_list_uses_verified_uncompressed_bytes(self):
        auth = self.challenge()
        self.materialize_indexes(compressed=True)
        self.seed_cache(self.payload['strongswan-starter'])
        before = self.snapshot()
        self.assertEqual(self.run_host(foreignCleanup=auth)[0], 0)
        self.assertIn(('/usr/lib/apt/apt-helper', 'cat-file'), [a[:2] for a in self.children])
        self.assertEqual([a[5] for a in self.children if a[4:5] == ('download',)], ['xl2tpd:amd64=1.3.18-1+b1'])
        self.assertEqual(self.snapshot(), before)
        self.index = self.index[:-1] + b'x'  # same-size invalid decode
        self.children.clear()
        self.child_failure = 'update'
        self.refused(auth)
        self.assertIn(('/usr/lib/apt/apt-helper', 'cat-file'), [a[:2] for a in self.children])
        self.assertEqual(self.apt_calls(), ['update'])
        self.assertFalse(any(a[0] == '/usr/bin/dpkg-deb' for a in self.children))

    def test_bad_download_no_extraction(self):
        auth = self.challenge()
        self.downloaded['strongswan-starter'] = b'x' * len(self.payload['strongswan-starter'])
        self.refused(auth)
        self.assertEqual(self.apt_calls(), ['update', 'download'])
        self.assertFalse(any(a[0] == '/usr/bin/dpkg-deb' for a in self.children))

    def test_bad_release_index_version_and_unavailable_download_fail_closed(self):
        auth = self.challenge()
        for options, failure, reason in (({}, 'signature', 'STOCK_CHILD_FAILED'),
                ({'expired': True}, None, 'STOCK_RELEASE_EXPIRED'),
                ({'corrupt': True}, None, 'REPLACEMENT_ARCHIVE_RECORD'),
                ({'exact': False}, None, 'STOCK_VERSION_UNAVAILABLE'),
                ({}, 'update', 'STOCK_APT_UPDATE_FAILED'), ({}, 'update_warning', 'STOCK_APT_UPDATE_FAILED'),
                ({}, 'apt', 'STOCK_APT_DOWNLOAD_FAILED'), ({}, 'timeout', 'STOCK_STAGE_TIMEOUT')):
            with self.subTest(options=options, failure=failure, reason=reason):
                self.child_failure = failure
                self.refresh_options = options
                self.children.clear()
                self.log.reset_mock()
                self.refused(auth)
                self.assertEqual(self.apt_calls(), ['update'] + (['download'] if failure in ('apt', 'timeout') else []))
                self.assertFalse(any(a[0] == '/usr/bin/dpkg-deb' for a in self.children))
                self.log.assert_called_once_with(syslog.LOG_WARNING, 'celerity-rebuild-l2tp: ' + reason)

    def test_unsupported_installation_never_stages(self):
        self.native = False
        self.refused(None)
        self.assertEqual(self.children, [])


def load_tests(loader, _suite, _pattern):
    return unittest.TestSuite(StockCleanup(name) for name in vars(StockCleanup) if name.startswith('test_'))


if __name__ == '__main__':
    unittest.main()
