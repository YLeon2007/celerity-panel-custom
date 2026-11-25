"""VAULT phase 1: synthetic bytes only; no command or filesystem adapters."""
import hashlib
import io
import json
import runpy
import stat
import tarfile
import unittest
from pathlib import Path


SERVICES = Path(__file__).resolve().parents[1]
H = runpy.run_path(str(SERVICES / 'rebuildRelayReplacement.py'))
requirements, stage, plan = (H[n] for n in ('stock_requirements', 'stage_stock', 'plan_replacement'))
Refusal, Archive = H['Refusal'], H['Archive']
STARTER, SECRETS, LNS, CHAP = 'STARTER_NOT_STOCK', 'SECRETS_NOT_EMPTY', 'LNS_NOT_STOCK', 'CHAP_NOT_EMPTY'
X, B = 'XRAY_UNIT_0666', 'XRAY_BRIDGE_UNIT_0666'
DELETIONS = {
    'SWAN_PROFILE_PRESENT': '/etc/strongswan.d/celerity-rebuild-l2tp.conf',
    'IKE_PROFILE_PRESENT': '/etc/ipsec.d/celerity-rebuild-l2tp.conf',
    'OPTIONS_PRESENT': '/etc/ppp/options.xl2tpd',
    'MODULES_LOAD_FOREIGN': '/etc/modules-load.d/c3-l2tp.conf',
}
PATHS = {**DELETIONS, STARTER: '/etc/ipsec.conf', SECRETS: '/etc/ipsec.secrets', LNS: '/etc/xl2tpd/xl2tpd.conf',
         CHAP: '/etc/ppp/chap-secrets', X: '/etc/systemd/system/xray.service', B: '/etc/systemd/system/xray-bridge.service'}
ORDER = (*tuple(DELETIONS)[:3], STARTER, SECRETS, CHAP, LNS, X, B, 'MODULES_LOAD_FOREIGN')
OWNER = {STARTER: 'strongswan-starter', SECRETS: 'strongswan-starter', LNS: 'xl2tpd'}
STOCK = {STARTER: b'# package\r\nconfig setup\n', SECRETS: b'# packaged example\n', LNS: b'[global]\r\n; exact\xff'}
CHAP_BEFORE = b'\t# untouched\xff\r\n \t\n  fixture-row\r\n# unchanged\nfixture-row-2\n\n\tfinal-row'
CHAP_AFTER = b'\t# untouched\xff\r\n \t\n#   fixture-row\r\n# unchanged\n# fixture-row-2\n\n# \tfinal-row'


def md5(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(found):
    return sha(json.dumps(['foreign-config-v2', found], sort_keys=True, separators=(',', ':')).encode())


def tar(rows):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as out:
        for name, value in rows:
            member = tarfile.TarInfo(name)
            if type(value) is bytes:
                member.size = len(value)
                out.addfile(member, io.BytesIO(value))
            else:
                member.type, member.linkname = value
                out.addfile(member)
    return stream.getvalue()


class Replacement(unittest.TestCase):
    def setUp(self):
        self.keys = ORDER
        self.contents = {k: b'fixture-content\n' for k in self.keys}
        self.contents[CHAP] = CHAP_BEFORE
        self.found = {k: [PATHS[k], [1, i + 1, stat.S_IFREG | (0o666 if k in (X, B) else 0o600),
                                     0, 0, 1, len(self.contents[k]), 11, 12],
                          sha(self.contents[k]), md5(STOCK[k]) if k in STOCK else None]
                      for i, k in enumerate(self.keys)}
        self.debs = {p: b'modeled-deb:' + p.encode() for p in set(OWNER.values())}
        self.installed = {p: f'{p}\tinstall ok installed\tamd64\t1:2.3-4\n'.encode() + b''.join(
            f' {PATHS[k]} {md5(STOCK[k])}\n'.encode() for k in STOCK if OWNER[k] == p) for p in self.debs}
        self.archives = tuple(Archive(p, '1:2.3-4', 'amd64', 'trixie-security' if p == 'strongswan-starter' else 'trixie',
                                      ('pool/updates/main/s/strongswan/' if p == 'strongswan-starter' else 'pool/main/x/xl2tpd/')
                                      + p + '_2.3-4_amd64.deb', len(blob), sha(blob)) for p, blob in sorted(self.debs.items()))
        self.rows = {p: [(f'.{PATHS[k]}', STOCK[k]) for k in STOCK if OWNER[k] == p] for p in self.debs}
        self.calls = []

    def download(self, url, size):
        self.calls.append(('download', url, size))
        for p, b in self.debs.items():
            if url.endswith(f'/{p}_2.3-4_amd64.deb'):
                return b
        self.fail('unexpected archive URL')

    def data_tar(self, blob):
        self.calls.append(('data-tar', blob))
        return tar(self.rows[blob.decode().split(':')[-1]])

    def observe(self):
        return self.keys, fingerprint(self.found), self.found, self.contents

    def stage(self, **kwargs):
        args = dict(installed=self.installed, archives=self.archives, download=self.download, data_tar=self.data_tar)
        return stage(requirements(*self.observe()), **(args | kwargs))

    def test_exact_bytes_and_paths(self):
        staged = self.stage()
        result = plan(*self.observe(), staged=staged, allow_xray_mode=True)
        self.assertEqual(result.set_aside, ())
        self.assertEqual(tuple(e.key for e in result.edits), self.keys)
        self.assertEqual({e.path for e in result.edits if e.action == 'delete'}, set(DELETIONS.values()))
        for e in result.edits:
            self.assertEqual(e.path, PATHS[e.key])
            self.assertEqual(e.pin, tuple(self.found[e.key][1]))
            self.assertEqual(e.before, self.contents[e.key])
            if e.key in STOCK:
                self.assertEqual((e.action, e.after, e.mode), ('replace', STOCK[e.key], 0o600))
            elif e.key == CHAP:
                self.assertEqual((e.action, e.after), ('replace', CHAP_AFTER))
            elif e.key in (X, B):
                self.assertEqual((e.action, e.after, e.mode), ('chmod', e.before, 0o644))
            else:
                self.assertEqual((e.action, e.after, e.mode), ('delete', None, None))
        self.assertNotIn('fixture-row', repr(result))
        self.assertEqual(self.calls, [
            ('download', 'https://security.debian.org/debian-security/' + self.archives[0].filename, self.archives[0].size),
            ('data-tar', self.debs['strongswan-starter']),
            ('download', 'https://deb.debian.org/debian/' + self.archives[1].filename, self.archives[1].size),
            ('data-tar', self.debs['xl2tpd']),
        ])

    def test_no_xray_consent_and_no_staging_for_non_package_edits(self):
        self.keys = tuple(k for k in self.keys if k not in STOCK)
        self.found = {k: self.found[k] for k in self.keys}
        self.contents = {k: self.contents[k] for k in self.keys}
        self.assertEqual(requirements(*self.observe()), {})
        result = plan(*self.observe())
        self.assertEqual(result.set_aside, (X, B))
        self.assertEqual(tuple(e.key for e in result.edits), tuple(k for k in self.keys if k not in (X, B)))
        with self.assertRaises(Refusal):
            plan(*self.observe(), allow_xray_mode='true')
        self.assertEqual(self.calls, [])

    def test_unknown_manual_duplicate_or_stale_observation(self):
        for keys in (self.keys + ('UNIT_WRITABLE',), self.keys + ('NFT_DIR_PRESENT',),
                     self.keys + ('DROPIN_PRESENT',), self.keys + ('unknown',), self.keys + (X,), self.keys[1:]):
            with self.subTest(keys=keys), self.assertRaises(Refusal):
                requirements(keys, *self.observe()[1:])
        keys, proof, found, contents = self.observe()
        for changed in ({**contents, X: b'changed'}, {k: v for k, v in contents.items() if k != X}):
            with self.assertRaises(Refusal):
                requirements(keys, proof, found, changed)
        with self.assertRaises(Refusal):
            requirements(keys, '0' * 64, found, contents)
        self.assertEqual(self.calls, [])

    def test_stock_observer_fingerprint_joins_the_pure_plan(self):
        observer = runpy.run_path(str(SERVICES / 'rebuildRelayDirectHost.py'))['foreign_config_observation']

        def missing(*_, **__):
            raise FileNotFoundError

        by_path = {item[0]: key for key, item in self.found.items()}

        def leaf(path, **_):
            key = by_path.get(path)
            if key is not None:
                pin = self.found[key][1]
                return stat.S_IMODE(pin[2]), pin, self.contents[key]
            return None

        def conffiles(package):
            return {PATHS[k].encode(): md5(STOCK[k]).encode() for k in STOCK if OWNER[k] == package}

        observer.__globals__.update(directory=missing, foreign_leaf=leaf, recovery_stat=lambda _: None,
                                    foreign_conffiles=conffiles)
        keys, proof = observer()
        self.assertEqual((keys, proof), self.observe()[:2])
        self.assertEqual(requirements(keys, proof, self.found, self.contents), {k: md5(v) for k, v in STOCK.items()})

    def test_wrong_path_or_nonregular_linked_or_unsafe_leaf(self):
        original = self.found[X]
        for offset, value in [(2, stat.S_IFLNK | 0o777), (2, stat.S_IFREG | 0o664), (3, 1), (5, 2)]:
            pin = list(original[1]); pin[offset] = value
            self.found[X] = [original[0], pin, *original[2:]]
            with self.subTest(offset=offset, value=value), self.assertRaises(Refusal):
                requirements(*self.observe())
        self.found[X] = [PATHS[B], *original[1:]]
        with self.assertRaises(Refusal):
            requirements(*self.observe())

    def test_missing_wrong_or_ambiguous_installed_and_index_records(self):
        package = 'xl2tpd'
        raw = self.installed[package]
        for reply in (b'', raw.split(b'\n', 1)[0] + b'\n', raw.replace(b'install ok installed', b'deinstall ok config-files'),
                      raw.replace(b'1:2.3-4', b'1:2.3-5'), raw.replace(b'amd64', b'arm64'),
                      raw + raw.split(b'\n', 1)[1], raw.rstrip(b'\n') + b' obsolete\n',
                      raw.replace(md5(STOCK[LNS]).encode(), b'a' * 32)):
            with self.subTest(reply=reply), self.assertRaises(Refusal):
                self.stage(installed={**self.installed, package: reply})
        for rows in ((), self.archives[:1], self.archives + self.archives[-1:],
                     self.archives[:1] + (self.archives[1]._replace(suite='other'),)):
            with self.subTest(rows=rows), self.assertRaises(Refusal):
                self.stage(archives=rows)
        self.assertEqual(self.calls, [])

    def test_network_unavailable_failed_download_and_bad_deb_never_extract(self):
        def unavailable(*_):
            raise OSError('must not be exposed')
        size = self.archives[0].size
        for provider in (None, unavailable, lambda *_: None, lambda *_: b'x', lambda *_: b'x' * size):
            with self.subTest(provider=provider), self.assertRaises(Refusal) as refusal:
                self.stage(download=provider)
            self.assertNotIn('must not be exposed', str(refusal.exception))
        self.assertEqual(self.calls, [])

    def test_later_download_failure_does_not_return_partial_stage(self):
        def download(url, size):
            if 'xl2tpd_' in url:
                raise TimeoutError
            return self.download(url, size)
        with self.assertRaisesRegex(Refusal, '^REPLACEMENT_DOWNLOAD$'):
            self.stage(download=download)
        self.assertEqual([step for step, *_ in self.calls], ['download', 'data-tar'])

    def test_exact_installed_cache_then_private_download(self):
        acquire = H['stage_installed_stock']
        needed = requirements(*self.observe())
        calls = []

        def cache(package, version, arch):
            calls.append(('cache', package, version, arch))
            return self.debs[package] if package == 'strongswan-starter' else None

        def download(package, version, arch):
            calls.append(('download', package, version, arch))
            return self.debs[package]

        def control(blob):
            p = blob.partition(b':')[2]
            return tar([('./control', b'Package: ' + p + b'\nVersion: 1:2.3-4\nArchitecture: amd64\n')])

        args = dict(installed=self.installed, cached_deb=cache, download_deb=download,
                    control_tar=control, data_tar=self.data_tar)
        staged = acquire(needed, **args)
        actual = plan(*self.observe(), staged=staged)
        self.assertEqual({e.key: e.after for e in actual.edits if e.key in STOCK}, STOCK)
        self.assertEqual(calls, [('cache', 'strongswan-starter', '1:2.3-4', 'amd64'),
                                 ('cache', 'xl2tpd', '1:2.3-4', 'amd64'),
                                 ('download', 'xl2tpd', '1:2.3-4', 'amd64')])
        calls.clear()
        self.calls.clear()
        with self.assertRaisesRegex(Refusal, '^REPLACEMENT_ARCHIVE_IDENTITY$'):
            acquire(needed, **(args | {'control_tar': lambda _: tar([('control', b'Package: strongswan-starter\n'
                                                                 b'Version: 1:2.3-5\nArchitecture: amd64\n')])}))
        self.assertEqual(calls, [('cache', 'strongswan-starter', '1:2.3-4', 'amd64')])
        self.assertEqual(self.calls, [])
        original = self.rows['strongswan-starter']
        self.rows['strongswan-starter'] = [(original[0][0], b'not Debian stock'), original[1]]
        with self.assertRaisesRegex(Refusal, '^REPLACEMENT_STOCK_MD5$'):
            acquire(needed, **args)

    def test_wrong_bytes_missing_member_or_unusable_archive_is_not_staged(self):
        original = self.rows['strongswan-starter']
        first, second = original
        for rows in ([first], [first, (second[0], b'x' * len(second[1]))], [first, second, second],
                     [first, (second[0], (tarfile.SYMTYPE, '/other'))],
                     [first, (second[0], (tarfile.LNKTYPE, first[0]))],
                     [first, second, ('./etc', (tarfile.SYMTYPE, '/other'))]):
            with self.subTest(rows=rows), self.assertRaises(Refusal):
                self.rows['strongswan-starter'] = rows
                self.stage()
        with self.assertRaises(Refusal):
            self.stage(data_tar=lambda _: b'not a tar')
        with self.assertRaises(Refusal):
            self.stage(data_tar=lambda _: tar(original)[:2048])  # both members, no end records
        with self.assertRaises(Refusal):
            plan(*self.observe())


if __name__ == '__main__':
    unittest.main()
