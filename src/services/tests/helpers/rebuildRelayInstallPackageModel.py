"""Debian package argv/filesystem model for the existing joined DIRECT endpoint.

No package archives, programs, daemons or generators. Use the same private
root and shared installed tuples for the package guard and subsequent stock
Install. Synthetic init/defaults/generator bytes have test-only stock pins;
manager properties, file generations, manifests and frame checks are not
bypassed. The checked-in generated wrapper is used byte-for-byte.
"""

import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_rebuild_relay_packages import (  # noqa: E402
    Host, SIX, POLICY, SYSTEM, INDEXES, LISTS, REPOSITORIES, THIRD_PARTY,
    apt_option, package_ownership, read_apt_config, sealed_sources, sealed_text,
)
sys.path.pop(0)

DEFAULTS = '# synthetic xl2tpd defaults\n'
INIT = '#!/bin/sh\nexit 0\n'
GENERATOR = 'synthetic generator identity; never executed\n'
GENERATOR_PATH = '/usr/lib/systemd/system-generators/systemd-sysv-generator'
LNS = '; synthetic package conffile\n[global]\n'
APT_UPDATE = ('/usr/bin/apt-get', '--error-on=any', 'update')


def isolated_apt_config(argv, *, update):
    config = read_apt_config(argv)
    expected = {
        'Acquire::Languages': 'none', 'KeepCompressed': 'false',
        'Acquire::http::AllowRedirect': 'false', 'Acquire::https::AllowRedirect': 'false',
    }

    def option(key):
        return apt_option(config, key)

    assert {key: option(key) for key in expected} == expected
    assert '#clear APT::Update;\n' in config
    source_path, prefs = option('Dir::Etc::sourcelist'), option('Dir::Etc::preferences')
    sources = sealed_text(source_path)
    if prefs != '/dev/null':
        sealed_text(prefs)  # The stock plan model below may read only this validated carrier.
    assert sources == sealed_sources()
    no_dpkg = 'Dir::Bin::dpkg "/dev/null";\n'
    assert config.count(no_dpkg) == int(update)
    archives = option('Dir::Cache::archives')
    # Descriptor names, the pin carrier, the reservation-only archive path
    # and update's dpkg prohibition are checked separately from this digest.
    normalized = config.replace(no_dpkg, '').replace(source_path, '<sources>').replace(
        f'Dir::Etc::preferences "{prefs}";', 'Dir::Etc::preferences "<pins>";').replace(
        f'Dir::Cache::archives "{archives}";', 'Dir::Cache::archives "<archives>";')
    return hashlib.sha256((normalized + sources).encode()).hexdigest(), prefs


def sums(text):
    data = text.encode()
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()


class JoinedPackages(Host):
    def listed_indexes(self):
        return sorted(p.name for p in self.p(LISTS).iterdir() if p.name not in {'lock', 'partial', 'auxfiles'})

    def update(self, scenario):
        # Only the native child result and its index files are simulated.
        # A failed mirror/missing index can leave other suites downloaded.
        assert not self.listed_indexes()
        assert not self.p(POLICY).exists()
        self.effects.append('update')
        if scenario == 'package-stock-empty-untrusted':
            return 100, b'', b'E: The repository is not signed.\n'
        for i, (_, suite) in enumerate(REPOSITORIES):
            release, packages = INDEXES[2 * i:2 * i + 2]
            payload = f'Package: fixture-{suite}\nVersion: 1\nArchitecture: amd64\n\n'
            checksum = hashlib.sha256(payload.encode()).hexdigest()
            self.put(f'{LISTS}/{release}', '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\n'
                     f'Codename: {suite}\nArchitectures: amd64\nSHA256:\n'
                     f' {checksum} {len(payload)} main/binary-amd64/Packages\n'
                     '-----BEGIN PGP SIGNATURE-----\nmocked APT authentication\n-----END PGP SIGNATURE-----\n')
            if suite != 'trixie-security' or scenario in ('package-stock-empty-ok', 'package-stock-empty-foreign-source',
                                                         'package-stock-empty-tampered', 'package-stock-empty-plan'):
                # KeepCompressed=false: unlike stock .lz4 lists, this is the
                # exact uncompressed target named in the signed checksum.
                if suite == 'trixie-security' and scenario == 'package-stock-empty-tampered':
                    payload = payload.replace('fixture-', 'corrupt-')  # same byte length and target name
                self.put(f'{LISTS}/{packages}', payload)
        if scenario == 'package-stock-empty-acquisition':
            return 100, b'', b'E: Failed to fetch trixie-security Packages\n'
        assert scenario in ('package-stock-empty-ok', 'package-stock-empty-foreign-source',
                            'package-stock-empty-incomplete', 'package-stock-empty-tampered', 'package-stock-empty-plan')
        return 0, b'Reading package lists...\n', b''

    def native_exec(self, package):
        if package == 'strongswan-starter':
            return '/usr/sbin/ipsec start --nofork'
        return super().native_exec(package)

    def _install(self):
        old = self.installed.copy()
        super()._install()
        if 'strongswan-starter' not in old and 'strongswan-starter' in self.installed:
            self.put('/etc/ipsec.conf', 'config setup\n\ninclude /etc/ipsec.d/*.conf\n')
            self.put('/etc/ipsec.secrets', '# synthetic empty conffile\n', 0o600)
        if 'xl2tpd' in old or 'xl2tpd' not in self.installed:
            return
        assert self.p('/etc/init.d/xl2tpd').read_text() == INIT
        self.put('/etc/default/xl2tpd', DEFAULTS)
        self.put('/etc/xl2tpd/xl2tpd.conf', LNS)


def attach(root, state, scenario, h, request, assert_host_lock):
    model = JoinedPackages(unittest.TestCase(), root, seed=False)
    ledger = state['packageModel']
    empty = scenario.startswith('package-stock-empty-')
    model.installed = {n: tuple(v) for n, v in ledger['installed'].items()}
    model.apt_count = ledger['aptWrites']
    model.effects = ledger['effects']
    model.active = scenario == 'package-stock-active'
    guard = h['C3_PACKAGE_GUARD']
    assert guard['observe'].__globals__ is guard is guard['prepare'].__globals__
    guard.update(package_ownership(root, model.archive_owners))
    stock = h['C3_STOCK_RUNTIME']
    def trace_need(scope):
        original = scope['need']

        def observed(condition, code):
            if not condition:
                caller = sys._getframe(1)
                state['lastRefusal'] = [code, caller.f_code.co_name, caller.f_lineno]
            return original(condition, code)

        scope['need'] = observed

    trace_need(guard)
    trace_need(stock)
    assert stock['PACKAGE_ID'] == 'xl2tpd\tinstall ok installed\tamd64\t1.3.18-1+b1'
    stock['PACKAGE_FILES'] = {stock['INIT']: (0o755, *sums(INIT)), stock['DEFAULTS']: (0o644, *sums(DEFAULTS))}
    stock['SYSV_GENERATOR_SHA'] = sums(GENERATOR)[0]
    h['STOCK_XL_DEFAULT_SHA'], md5 = sums(DEFAULTS)
    h['STOCK_XL_DEFAULT_MD5'] = md5.encode()
    state['lnsMd5'] = sums(LNS)[1]

    def run(argv, end, maximum, *, may_write=False):
        try:
            assert maximum == h['PACKAGE_MAX_OUTPUT'] and time.monotonic() < end <= h['DEADLINE']
            assert request['action'] in ('preflight', 'prepare-packages')
            suffix = argv[7:] if argv[0] == '/usr/bin/env' else ()
            update = suffix == APT_UPDATE
            mode = suffix[1] if suffix else ''
            if suffix:
                assert may_write == (update or mode == '-y')
                if not may_write:
                    ledger['aptReads'][request['action']] = ledger['aptReads'].get(request['action'], 0) + 1
            token = request.get('backupId')
            if may_write:
                assert request['action'] == 'prepare-packages'
                assert_host_lock()
                vault = root / h['VAULT'][1:]
                pending = json.loads((vault / h['PACKAGE_PENDING']).read_bytes())
                assert pending == json.loads((vault / f'packages-{token}.json').read_bytes())
                assert [pending[k] for k in ('phase', 'backupId', 'packagePreparation')] == [
                    'preparing', token, request['packagePreparation']]
                assert not (vault / token).exists()
                if not model.effects:
                    # The real PackageRunner allowed this writer only after
                    # its checked enter(), with both durable intents visible.
                    assert (update if empty else argv[-1] == 'daemon-reload')
                    model.effects.append('enter')
            if empty and suffix:
                config, prefs = isolated_apt_config(argv, update=update)
                if update:
                    assert prefs == '/dev/null' and not ledger['updates']
                    response = model.update(scenario)
                    ledger['updates'].append({'action': request['action'], 'backupId': token, 'status': response[0],
                                              'argv': suffix, 'configDigest': config, 'indexes': model.listed_indexes()})
                    return response
                assert len(ledger['updates']) == 1 and ledger['updates'][0]['status'] == 0
                assert model.listed_indexes() == sorted(INDEXES), 'APT used incomplete indexes'
                assert config == ledger['updates'][0]['configDigest'], 'APT configuration changed after update'
                step = ('check' if suffix == ('/usr/bin/apt-get', '-s', 'check') else
                        'metadata' if mode == 'show' else 'install' if mode == '-y' else 'simulate')
                checks = ledger['afterUpdate']
                if step == 'install':
                    assert 'check' in checks and 'simulate' in checks and 'metadata' in checks
                checks.append(step)
            response = model.run(argv, round(end - time.monotonic()))
            ledger['aptWrites'] = model.apt_count
            ledger['installed'] = model.installed
            if suffix[:2] == ('/usr/bin/apt-get', '-s') and suffix[2:] != ('check',):
                invalid_plan = (scenario == 'package-stock-plan-preflight' or scenario == 'package-stock-empty-plan'
                                or (scenario == 'package-stock-plan-prepare' and any('=' in arg for arg in suffix[2:])))
                if invalid_plan:
                    # Keep the real guard parser and runner. Only change the modeled APT result.
                    assert response[0] == 0 and not response[2]
                    return 0, response[1].rstrip(b'\n') + b'\nRemv fixture-private-apt-package [1]\n', b''
            return response
        except Exception as error:
            state.setdefault('faults', []).append([type(error).__name__, list(argv), str(error)])
            raise

    h['bounded_status'] = run
    return model


def readback(model, state):
    """Independently project idle/disabled state at the real package ACK."""
    assert all(n in model.installed for n in SIX)
    assert model.archive_used is not None and not os.path.lexists(model.archive_used)
    assert not model.p(POLICY).exists()
    assert not any(p.is_symlink() for p in model.p(SYSTEM).glob('*.service'))
    assert not any(model.p('/etc').glob('rc?.d/S??xl2tpd'))
    for level in '0123456':
        assert model.p(f'/etc/rc{level}.d/K01xl2tpd').readlink() == Path('../init.d/xl2tpd')
    for unit in ('strongswan-starter.service', 'nftables.service'):
        assert not any(model.p(SYSTEM).glob(f'*.wants/{unit}'))
    ledger = state['packageModel']
    for name in ('strongswan-starter.service', 'xl2tpd.service', 'nftables.service'):
        rc, output, err = model._show(name)
        assert rc == 0 and not err
        info = dict(line.split('=', 1) for line in output.decode().splitlines())
        assert [info[k] for k in ('ActiveState', 'SubState', 'MainPID', 'Job')] == ['inactive', 'dead', '0', '']
        assert info['UnitFileState'] == ('generated' if name == 'xl2tpd.service' else 'disabled')
        ledger['quiet'][name] = info['UnitFileState']
        if name in state['units']:
            # The existing joined model projects Id/Names from the current
            # XL fragment, including alias disappearance on native reload.
            state['units'][name].update({k: v for k, v in info.items() if k not in ('Id', 'Names')})
    # These additional systemctl properties describe the checked-in SysV
    # wrapper when queried by stock-runtime (the package guard omits them).
    state['units']['xl2tpd.service'].update(Type='forking', KillMode='process', Restart='no', RemainAfterExit='yes')


if __name__ == '__main__':
    root, scenario = Path(sys.argv[1]), sys.argv[2]
    assert root.name.startswith('.relay-install-join-') and root.is_absolute() and root.resolve() == root
    os.umask(0o022)
    model = JoinedPackages(unittest.TestCase(), root)
    model.put(GENERATOR_PATH, GENERATOR, 0o755)
    if scenario == 'package-stock-active':
        # Already installed, running IKE with other requested packages absent.
        model.candidates = {n: v for n, v in model.candidates.items()
                            if n in {'strongswan', 'strongswan-starter', 'strongswan-charon', 'libstrongswan'}}
        model._install()
        model.p(SYSTEM + '/multi-user.target.wants/strongswan-starter.service').unlink()
    if scenario == 'package-stock-foreign':
        model.link('/run/systemd/system/strongswan-starter.service', '/opt/fixture-operator.service')
    ledger = dict(installed=model.installed, aptReads={}, aptWrites=0, effects=[], quiet={})
    if scenario.startswith('package-stock-empty-'):
        for name in model.listed_indexes():
            model.p(f'{LISTS}/{name}').unlink()
        for name in ('partial', 'auxfiles'):
            model.p(f'{LISTS}/{name}').mkdir(mode=0o700)
        model.put('/etc/apt/apt.conf.d/99-operator', 'APT::Get::AllowUnauthenticated "true";\n')
        model.put('/etc/apt/sources.list', '# operator comment, not an active source\n')
        suffix = '.list' if scenario == 'package-stock-empty-foreign-source' else '.list.disabled'
        model.put('/etc/apt/sources.list.d/operator' + suffix, THIRD_PARTY)
        ledger.update(updates=[], afterUpdate=[])
    print(json.dumps(ledger))
