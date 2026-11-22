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
from test_rebuild_relay_packages import Host, SIX, POLICY, SYSTEM  # noqa: E402
sys.path.pop(0)

DEFAULTS = '# synthetic xl2tpd defaults\n'
INIT = '#!/bin/sh\nexit 0\n'
GENERATOR = 'synthetic generator identity; never executed\n'
GENERATOR_PATH = '/usr/lib/systemd/system-generators/systemd-sysv-generator'
LNS = '; synthetic package conffile\n[global]\n'


def sums(text):
    data = text.encode()
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()


class JoinedPackages(Host):
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
    model.installed = {n: tuple(v) for n, v in ledger['installed'].items()}
    model.apt_count = ledger['aptWrites']
    model.effects = ledger['effects']
    model.active = scenario == 'package-stock-active'
    guard = h['C3_PACKAGE_GUARD']
    assert guard['observe'].__globals__ is guard is guard['prepare'].__globals__
    guard['_owner'] = lambda st: (st.st_uid, st.st_gid) == (os.getuid(), os.getgid())
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
            if argv[0] == '/usr/bin/env':
                _, mode = argv[7:9]
                assert may_write == (mode == '-y')
                if not may_write:
                    ledger['aptReads'][request['action']] = ledger['aptReads'].get(request['action'], 0) + 1
            if may_write:
                assert request['action'] == 'prepare-packages'
                assert_host_lock()
                token = request['backupId']
                vault = root / h['VAULT'][1:]
                pending = json.loads((vault / h['PACKAGE_PENDING']).read_bytes())
                assert pending == json.loads((vault / f'packages-{token}.json').read_bytes())
                assert [pending[k] for k in ('phase', 'backupId', 'packagePreparation')] == [
                    'preparing', token, request['packagePreparation']]
                assert not (vault / token).exists()
                if not model.effects:
                    # The real PackageRunner allowed this writer only after
                    # its checked enter(), with both durable intents visible.
                    assert argv[-1] == 'daemon-reload'
                    model.effects.append('enter')
            response = model.run(argv, round(end - time.monotonic()))
            ledger['aptWrites'] = model.apt_count
            ledger['installed'] = model.installed
            return response
        except Exception as error:
            state.setdefault('faults', []).append([type(error).__name__, list(argv)])
            raise

    h['bounded_status'] = run
    return model


def readback(model, state):
    """Independently project idle/disabled state at the real package ACK."""
    assert all(n in model.installed for n in SIX)
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
    print(json.dumps(dict(installed=model.installed, aptReads={}, aptWrites=0, effects=[], quiet={})))
