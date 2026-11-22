"""DIRECT XTLS drop-in admission; manager and /proc are modeled, disk is real."""
import io
import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest

HOST = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
DROP = '/etc/systemd/system/xray.service.d/10-donot_touch_single_conf.conf'
XRAY = '/usr/local/bin/xray'
ARGV = XRAY + ' run -config /usr/local/etc/xray/config.json'
STOCK = (b'# Customize startup parameters in a separate file.\n\n[Service]\nExecStart=\nExecStart='
         + ARGV.encode() + b'\n')
START = (f'{{ path={XRAY} ; argv[]={ARGV} ; ignore_errors=no ; start_time=[Fri 2026-11-20 14:15:46 CET] ; '
         'stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }')


class XrayDropinTest(unittest.TestCase):
    def setUp(self):
        host = runpy.run_path(str(HOST))
        self.host = host['xray_argv'].__globals__
        for name in ('command', 'sc'):
            self.host[name] = lambda *_a, **_k: self.fail('unexpected command')
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.drop = root / DROP[1:]
        self.drop.parent.mkdir(parents=True)
        for name in self.drop.relative_to(root).parents:
            (root / name).chmod(0o755)
        self.drop.write_bytes(STOCK)
        self.drop.chmod(0o644)
        self.uid = self.gid = 0
        self.attrs = []
        self.cmdline = b'\0'.join(ARGV.encode().split()) + b'\0'
        self.exe = XRAY

        def openat(path, flags, *, dir_fd=None):
            if dir_fd is None:
                self.assertEqual(path, '/')
                return os.open(root, flags)
            self.assertEqual(path, os.path.basename(path))
            return os.open(path, flags, dir_fd=dir_fd)

        def fstat(fd):
            st = os.fstat(fd)
            leaf = st.st_ino == self.drop.lstat().st_ino if self.drop.exists() else False
            return SimpleNamespace(st_uid=self.uid if leaf else 0, st_gid=self.gid if leaf else 0,
                                   st_mode=st.st_mode, st_nlink=st.st_nlink, st_size=st.st_size)

        def open_proc(path, mode):
            self.assertEqual((path, mode), ('/proc/42/cmdline', 'rb'))
            return io.BytesIO(self.cmdline)

        def realpath(path):
            self.assertEqual(path, '/proc/42/exe')
            return self.exe

        names = ('O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK', 'fdopen', 'close', 'listdir')
        self.host['os'] = SimpleNamespace(**{k: getattr(os, k) for k in names}, open=openat, fstat=fstat,
                                          path=SimpleNamespace(split=os.path.split, basename=os.path.basename,
                                                               realpath=realpath), listxattr=lambda _fd: self.attrs)
        self.host['open'] = open_proc
        self.info = dict(LoadState='loaded', ActiveState='active', NeedDaemonReload='no', MainPID='42',
                         InvocationID='1' * 32, ExecStart=START, DropInPaths=DROP, PrivateNetwork='no',
                         WorkingDirectory='/', KillMode='control-group')

    def assertRefusal(self, code='XRAY_DROPIN_UNSUPPORTED', **props):
        with self.assertRaisesRegex(self.host['Refusal'], '^' + code + '$'):
            self.host['xray_argv']({**self.info, **props})

    def test_stock_dropin_and_legacy_no_dropin(self):
        self.assertEqual(self.host['xray_argv'](self.info), '42')
        self.drop.write_bytes(b'  ; additional comment\r\n\r\n' + STOCK.replace(b'\n', b'\r\n'))
        self.assertEqual(self.host['xray_argv'](self.info), '42')
        self.drop.unlink()
        self.assertEqual(self.host['xray_argv'](dict(self.info, DropInPaths='')), '42')

    def test_rejects_adjacent_loaded_overrides(self):
        for props in (
            dict(DropInPaths='/run/systemd/system/xray.service.d/' + self.drop.name),
            dict(DropInPaths=DROP + ' /etc/systemd/system/xray.service.d/override.conf'),
            dict(ExecStart=START + ' ' + START),
            dict(ExecStart=START.replace('config.json', 'config.json -test')),
            dict(ExecStart=START.replace('ignore_errors=no', 'ignore_errors=yes')),
            dict(NeedDaemonReload='yes'),
            *({k: 'unexpected'} for k in ('ExecCondition', 'ExecReload', 'ExecStartPre', 'ExecStartPost',
                                          'ExecStop', 'ExecStopPost', 'Environment', 'EnvironmentFiles',
                                          'PassEnvironment', 'UnsetEnvironment', 'RootDirectory', 'RootImage')),
        ):
            with self.subTest(props=props):
                self.assertRefusal(**props)

        # Duplicate ExecStart rows must also be rejected at the systemctl parser.
        def show(*args, **kw):
            self.assertEqual(args[-1], 'xray.service')
            return ('\n'.join(f'{k}={v}' for k, v in self.info.items()) + f'\nExecStart={START}\n').encode()

        self.host['command'] = show
        with self.assertRaisesRegex(self.host['Refusal'], '^XRAY_DROPIN_UNSUPPORTED$'):
            self.host['unit']('xray.service')

    def test_rejects_wrong_disk_content(self):
        for data in (b'', STOCK.replace(b'ExecStart=\n', b''), STOCK + b'Environment=OTHER=1\n',
                     STOCK.replace(b'[Service]', b'[Unit]'), STOCK.replace(b'-config', b'-confdir'),
                     STOCK.replace(b'[Service]', b'[Service]\\\n'), STOCK.replace(b'[Service]', b'[Service]\x00')):
            with self.subTest(data=data):
                self.drop.write_bytes(data)
                self.assertRefusal()
        self.drop.write_bytes(STOCK)
        self.drop.with_name('99-other.conf').touch()
        self.assertRefusal()

    def test_rejects_unsafe_disk_metadata(self):
        for mode in (0o664, 0o4755):
            self.drop.chmod(mode)
            self.assertRefusal()
        self.drop.chmod(0o644)
        self.uid = 12
        self.assertRefusal()
        self.uid, self.gid = 0, 12
        self.assertRefusal()
        self.gid = 0
        self.attrs = ['user.fixture']
        self.assertRefusal()
        self.attrs = []
        self.drop.parent.chmod(0o775)
        self.assertRefusal()
        self.drop.parent.chmod(0o755)
        other = self.drop.with_suffix('.original')
        self.drop.rename(other)
        self.assertRefusal()
        self.drop.hardlink_to(other)
        self.assertRefusal()
        self.drop.unlink()
        self.drop.symlink_to(other.name)
        self.assertRefusal()
        self.drop.unlink()
        other.rename(self.drop)
        real_dir = self.drop.parent.with_suffix('.original')
        self.drop.parent.rename(real_dir)
        self.drop.parent.symlink_to(real_dir.name)
        self.assertRefusal()

    def test_main_only_and_live_checks_unchanged(self):
        bridge = self.host['BRIDGE']
        with self.assertRaisesRegex(self.host['Refusal'], '^XRAY_DROPIN_UNSUPPORTED$'):
            self.host['xray_argv'](dict(self.info, ExecStart=START.replace(self.host['MAIN'], bridge)), bridge)
        cmdline = self.cmdline
        self.cmdline += b'extra\0'
        self.assertRefusal('RUNTIME_UNPROVED')
        self.cmdline = cmdline
        self.exe = '/unexpected/executable'
        self.assertRefusal('RUNTIME_UNPROVED')


if __name__ == '__main__':
    unittest.main()
