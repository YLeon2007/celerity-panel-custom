"""Package settlement regressions: only private files and synthetic Python children."""
import hashlib
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import rebuildRelayDirectPackageHost as adapter
import test_rebuild_relay_packages as package


g = package.g
SYSTEM, VENDOR, POLICY = package.SYSTEM, package.VENDOR, package.POLICY
ALIAS = 'ipsec.service'
PRIMARY = 'strongswan-starter.service'


class Layout(unittest.TestCase):
    h: package.Host
    setUp = package.TestPackageGuard.setUp
    observe = package.TestPackageGuard.observe
    prepare = package.TestPackageGuard.prepare

    def setup_native_alias(self, *, listed=True):
        frag = self.h.p(f'{VENDOR}/{PRIMARY}')
        frag.write_bytes(frag.read_bytes() + b'Alias=ipsec.service\n')
        self.h.put('/var/lib/dpkg/info/strongswan-starter.md5sums',
                   f'{hashlib.md5(frag.read_bytes()).hexdigest()}  {VENDOR[1:]}/{PRIMARY}\n')
        if listed:
            self.h.put('/var/lib/dpkg/info/strongswan-starter.list', f'{VENDOR}/{PRIMARY}\n{VENDOR}/{ALIAS}\n')
        return self.h.link(f'{VENDOR}/{ALIAS}', PRIMARY)

    def install_alias(self, *, listed=True, stale=False):
        install, show = self.h._install, self.h._show

        def install_with_alias():
            install()
            self.setup_native_alias(listed=listed)

        def show_alias(unit):
            self.show_calls.append((unit, self.h.p(f'{SYSTEM}/{unit}').is_symlink()))
            masked = self.h.p(f'{SYSTEM}/{unit}').is_symlink()
            if (unit in (ALIAS, PRIMARY) and self.h.p(f'{VENDOR}/{ALIAS}').is_symlink() and not masked):
                rc, out, err = show(PRIMARY)
                out = out.replace(b'Names=strongswan-starter.service\n',
                                  b'Names=strongswan-starter.service ipsec.service\n')
                if stale and unit == ALIAS:
                    out = out.replace(b'NeedDaemonReload=no\n', b'NeedDaemonReload=yes\n')
                return rc, out, err
            return show(unit)

        self.show_calls = []
        self.h._install, self.h._show = install_with_alias, show_alias

    def test_verified_vendor_alias_survives_and_is_checked_both_sides(self):
        self.install_alias()
        self.prepare(self.observe())
        self.assertEqual(self.h.p(f'{VENDOR}/{ALIAS}').readlink(), Path(PRIMARY))
        self.assertFalse(self.h.p(POLICY).exists())
        self.assertIn((ALIAS, True), self.show_calls)
        self.assertIn((ALIAS, False), self.show_calls[self.show_calls.index((ALIAS, True)):])
        self.assertEqual(self.observe()['missing'], [])

    def test_unowned_vendor_alias_is_rejected_before_unmask(self):
        self.install_alias(listed=False)
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_UNIT_OWNER'):
            self.prepare(self.observe())
        self.h.containment()

    def test_bad_manager_alias_readback_retains_policy(self):
        self.install_alias(stale=True)
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_UNIT_ACTIVE'):
            self.prepare(self.observe())
        self.assertTrue(self.h.p(POLICY).exists())

    def test_operator_alias_cannot_be_replaced_even_with_native_target(self):
        leaf = self.h.link(f'{SYSTEM}/{ALIAS}', f'{VENDOR}/{PRIMARY}')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_UNIT_OWNER'):
            self.observe()
        self.assertEqual(leaf.readlink(), Path(f'{VENDOR}/{PRIMARY}'))
        self.assertFalse(self.h.effects)

    def test_existing_deb_systemd_helper_mask_marker_blocks_before_effects(self):
        marker = self.h.put('/var/lib/systemd/deb-systemd-helper-masked/nftables.service', '')
        marker.parent.chmod(0o755)
        marker.parent.parent.chmod(0o755)
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_POLICY'):
            self.observe()
        self.assertTrue(marker.is_file())
        self.assertFalse(self.h.effects)

    def test_sysv_disable_never_overwrites_existing_stop_link(self):
        install = self.h._install
        def add_collision():
            install()
            self.h.link('/etc/rc2.d/K01xl2tpd', '../init.d/xl2tpd')
        self.h._install = add_collision
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_SYSV'):
            self.prepare(self.observe())
        self.h.containment()
        self.assertTrue(self.h.p('/etc/rc2.d/K01xl2tpd').is_symlink())
        self.assertTrue(self.h.p('/etc/rc2.d/S01xl2tpd').is_symlink())
        self.assertEqual(self.h.effects, ['enter', 'reload', 'apt'])


class Settlement(unittest.TestCase):
    h: dict[str, Any]
    root: Path
    system: Path
    vault: Path
    popen_patch: Any
    setUp = adapter.Adapter.setUp
    command = adapter.Adapter.command
    observe = adapter.Adapter.observe
    prepare = adapter.Adapter.prepare
    offered = adapter.Adapter.offered
    wire = adapter.Adapter.wire
    raw_wire = adapter.Adapter.raw_wire

    def start_prepare(self):
        return self.wire('prepare-packages', backupId=adapter.TOKEN, packagePreparation=self.offered())

    def stub_guard(self, status):
        self.h['bounded_status'] = lambda *a, **kw: (status, b'', b'')
        def prepare(root, run, expected, enter):
            enter()
            if status is not None:
                run(adapter.APT_INSTALL, 78)
        self.h['C3_PACKAGE_GUARD']['prepare'] = prepare

    def test_missing_apt_status_cannot_publish_ready(self):
        self.stub_guard(None)
        self.assertEqual(self.start_prepare(), (75, '', ''))
        self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).is_file())

    def test_nonzero_status_cannot_publish_ready(self):
        self.stub_guard(100)
        self.assertEqual(self.start_prepare(), (75, '', ''))
        self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).is_file())

    def test_timely_settled_status_can_publish_ready(self):
        self.stub_guard(0)
        status, stdout, stderr = self.start_prepare()
        self.assertEqual((status, stderr), (0, ''))
        self.assertTrue(json.loads(stdout)['packagesReady'])
        self.assertFalse((self.vault / self.h['PACKAGE_PENDING']).exists())

    def test_stock_preflight_keeps_fresh_only_signature(self):
        def preflight(machine, *, fresh=False):
            self.assertTrue(fresh)
            return dict(machineId=machine, ppp=True, masked=False, unitsLoaded=True)

        self.h['preflight'] = preflight
        status, stdout, stderr = self.wire('preflight')
        self.assertEqual((status, stderr), (0, ''))
        self.assertTrue(json.loads(stdout)['unitsLoaded'])
        self.assertFalse(self.vault.exists())

    def joined_package(self):
        root = self.root / 'stock'
        root.mkdir(mode=0o700)
        model = package.Host(self, root)
        self.system = model.p(SYSTEM)
        self.h.update(SYSTEM=str(self.system), stock_runtime_root=lambda: root)

        def prepare(root, run, plan, enter):
            def enter_both():
                enter()
                model.enter()
            return g.prepare(root, run, plan, enter_both)

        def status(argv, end, maximum, *, may_write):
            self.assertLessEqual(end, self.h['DEADLINE'])
            return model.run(argv, 78 if may_write else 6)

        self.h.update(C3_PACKAGE_GUARD={'Refusal': g.Refusal, 'observe': g.observe, 'prepare': prepare},
                      bounded_status=status)
        owner = patch.dict(vars(g), package.package_ownership(root, model.archive_owners))
        owner.start()
        self.addCleanup(owner.stop)
        return model

    def test_joined_guard_leaves_fences_on_apt_timeout(self):
        model = self.joined_package()
        model.apt_mode = 'timeout'
        self.assertEqual(self.start_prepare(), (75, '', ''))
        model.containment()
        self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).is_file())
        self.assertEqual(model.apt_count, 1)
        assert model.archive_used is not None
        self.assertTrue((model.archive_used / 'partial/incomplete.deb').is_file())

    def test_joined_guard_retires_only_attributed_sysv_and_native_links(self):
        model = self.joined_package()
        status, stdout, stderr = self.start_prepare()
        self.assertEqual((status, stderr), (0, ''))
        self.assertTrue(json.loads(stdout)['packagesReady'])
        self.assertEqual(model.effects, ['enter', 'reload', 'apt', 'reload', 'reload'])
        self.assertTrue(all(model.p(f'/etc/rc{i}.d/K01xl2tpd').is_symlink() for i in '0123456'))
        self.assertFalse(any(model.p('/etc').glob('rc?.d/S??xl2tpd')))
        self.assertFalse(any(model.p(SYSTEM).glob('*.wants/*.service')))
        self.assertFalse(model.p(POLICY).exists())
        self.assertFalse((self.vault / self.h['PACKAGE_PENDING']).exists())
        assert model.archive_used is not None
        self.assertFalse(os.path.lexists(model.archive_used))

    def test_expiry_during_ready_write_retains_pending(self):
        self.stub_guard(0)
        original = self.h['write']
        def write(path, before, after):
            original(path, before, after)
            if path.endswith(f'packages-{adapter.TOKEN}.json') and before is not None:
                self.h['DEADLINE'] = time.monotonic()
        self.h['write'] = write
        self.assertEqual(self.start_prepare(), (75, '', ''))
        self.assertTrue((self.vault / self.h['PACKAGE_PENDING']).is_file())

    def test_closed_pipes_and_apt_parent_zero_with_detached_child_are_not_settlement(self):
        self.popen_patch.stop()
        born, release = self.root / 'born', self.root / 'release'
        # The synthetic group/session escape is synchronized with the direct
        # child's zero exit. No production executable or external process is used.
        program = '''import os, sys, time
from pathlib import Path
born, release = map(Path, sys.argv[1:])
if not os.fork():
    os.setsid()
    os.close(1)
    os.close(2)
    born.write_text(str(os.getpid()))
    end = time.monotonic() + 4
    while not release.exists() and time.monotonic() < end:
        time.sleep(.01)
    os._exit(0)
while not born.exists():
    time.sleep(.01)
'''
        cmd = (sys.executable, '-I', '-B', '-c', program, str(born), str(release))
        try:
            with self.assertRaises((self.h['Refusal'], subprocess.TimeoutExpired)):
                self.h['bounded_status'](cmd, time.monotonic() + 2, 4096, may_write=True)
            self.assertTrue(born.is_file())
        finally:
            release.touch()
            if born.is_file():
                try:
                    os.waitpid(int(born.read_text()), 0)
                except ChildProcessError:
                    pass

    def test_writer_that_reaps_its_child_can_settle(self):
        self.popen_patch.stop()
        cmd = (sys.executable, '-I', '-B', '-c',
               'import os; pid = os.fork(); os._exit(0) if not pid else os.waitpid(pid, 0)')
        self.assertEqual(self.h['bounded_status'](cmd, time.monotonic() + 2, 4096, may_write=True), (0, b'', b''))


if __name__ == '__main__':
    unittest.main()
