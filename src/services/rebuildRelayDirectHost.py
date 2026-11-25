# DIRECT TEST install and owned removal. This private endpoint accepts only the fixed
# actions/paths below. Package preparation is a separate guarded prerequisite.
import base64
import contextlib
import ctypes
import errno
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import re
import select
import selectors
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, cast

# Injected by the DIRECT payload, not loaded from the remote disk.
C3_STOCK_RUNTIME: dict[str, Any]
C3_STOCK_ENSURE: dict[str, Any]
C3_PACKAGE_GUARD: dict[str, Any]
C3_REPLACEMENT: dict[str, Any]

MAIN = '/usr/local/etc/xray/config.json'
XRAY_CONFIG_WRITABLE = 'XRAY_CONFIG_WRITABLE'
BRIDGE = '/usr/local/etc/xray-bridge/config.json'
XRAY = '/usr/local/bin/xray'
SYSTEM = '/etc/systemd/system'
NET_UNIT = 'celerity-rebuild-l2tp-network.service'
NET = SYSTEM + '/' + NET_UNIT
DROP_DIR = SYSTEM + '/xl2tpd.service.d'
DROP = DROP_DIR + '/50-celerity-rebuild-l2tp.conf'
NFT_DIR = '/etc/celerity-rebuild-l2tp'
NFT_FILE = NFT_DIR + '/ingress.nft'
VAULT = '/var/lib/celerity-rebuild-l2tp-direct'
XL, IKE, X, B = 'xl2tpd.service', 'strongswan-starter.service', 'xray.service', 'xray-bridge.service'
XRAY_DROPIN_NAME = '10-donot_touch_single_conf.conf'
# Exact files emitted by prepareAccessCommand in xraySetupRuntime.js.
XRAY_SETUP_DROPINS = {
    '90-celerity-config-access.conf': b'# Managed by Celerity Xray setup\n[Service]\nSupplementaryGroups=xray\n',
    '90-celerity-logs-directory.conf': b'# Managed by Celerity Xray setup\n[Service]\nLogsDirectory=xray\n',
}
XRAY_DROPIN_UNSUPPORTED = 'XRAY_DROPIN_UNSUPPORTED'
# Exact native unit emitted by the stock prerequisite installer.
NATIVE_XL_SHA = '20e9c67838fa8072a5378839fc729a1123d1580879fbf20f9121d558fd0fe0df'
XL_BOOT = SYSTEM + '/multi-user.target.wants/' + XL
XL_DEFAULT = '/etc/default/xl2tpd'
XL2TPD_CONFIG_MISSING = 'XL2TPD_CONFIG_MISSING'
# Extracted from signed Debian trixie/main xl2tpd_1.3.18-1+b1_amd64.deb
# (archive SHA256 dd6fdf32b90f9f7d516f5251e1abdb65851156c80163a41aab60cf94dcff16da).
STOCK_XL_DEFAULT_SHA = '37b5938f462ec60b4f8c179b34f70b548c09da4691c938e88ce111ce41268833'
STOCK_XL_DEFAULT_MD5 = b'fadc31f26078d8c3fb033d7d4516500b'
REQUIRED_PACKAGES = ('strongswan', 'strongswan-starter', 'strongswan-charon', 'xl2tpd', 'ppp', 'nftables')
PACKAGE_AUTOSTART_UNSAFE = 'RUNTIME_PACKAGE_AUTOSTART_UNSAFE'
PACKAGE_PENDING = 'package-preparation.pending'
INSTALL_ABSENT = 'reconciled-absent.json'
PACKAGE_MAX_OUTPUT = 256 * 1024  # per stream
# Per runner; preflight has its own runner. A host observation takes up to 36
# commands: 2 quiet sweeps (3 each), 4 dpkg, layout (1 + up to 4 SysV conffiles)
# and 21 unit shows. A fully observed plan adds 2 APT checks/simulations and up
# to 48 metadata reads. Prepare with populated indexes uses 3 full observations.
# Starting empty instead uses 2 host-only observations, 1 update and 2 full
# observations. Both paths also use 1 pinned simulation and 132 commands for
# containment/install/readback (early cleanup replaces later phases).
# Empty: 2*36 + 1 + 2*86 + 1 + 132 = 378; populated is still the maximum.
PACKAGE_MAX_COMMANDS = 391      # 3*86 + 1 + 4*26 + 3*4 + 4*3 + 3 + 1
NATIVE_MAX_OUTPUT = 128 * 1024
NATIVE_UNIT_REQUIRED = 'RUNTIME_NATIVE_UNIT_REQUIRED'
STOCK_IKE_INCLUDE = b'include /etc/ipsec.d/*.conf'
# Original Debian strongswan-starter 6.0.1-6+deb13u7 conffile, before
# install-runtime.sh adds its wildcard. DIRECT adds only the owned include.
STOCK_IKE_STARTER_SHA = '6a54e39267b981ca3239cd93579f26b5699983021a0d636408fdd5c70f3024d1'
SWAN_CONF = '/etc/strongswan.conf'
SWAN_DIR = '/etc/strongswan.d'
SWAN_PROFILE = SWAN_DIR + '/celerity-rebuild-l2tp.conf'
SWAN_SETTINGS = b'charon {\n    routing_table = 0\n    install_routes = no\n}\n'
SWAN_START_UNITS = (XL, IKE, NET_UNIT)
# Base and optional conffile sets from authenticated Debian trixie-security
# amd64 strongSwan 6.0.1-6+deb13u7. Each pin is the SHA256 of that set's
# canonical {path relative to /etc: [mode, gid, SHA256 of bytes]} projection.
STOCK_SWAN_SHA = 'ddc103e3bab4b312ab390428dd64ec6606ea6793d715d536d2fa2c0025e5d77e'
STOCK_SWAN_ADDONS = (
    # charon-systemd
    ('charon-systemd.conf', 'ae3da3badf12f70aba2c90e6ada3e68106ae37e281722292a44af467306a9c16'),
    # strongswan-swanctl
    ('swanctl.conf charon/vici.conf', '281f18aaf17874e2eab779b1a12516a4d67fc6e2909897dddec30a94b824a132'),
    # libcharon-extra-plugins
    ('tnc.conf charon/addrblock.conf charon/certexpire.conf charon/dhcp.conf '
     'charon/eap-aka.conf charon/eap-gtc.conf charon/eap-identity.conf charon/eap-md5.conf '
     'charon/eap-radius.conf charon/eap-tls.conf charon/eap-tnc.conf charon/eap-ttls.conf '
     'charon/error-notify.conf charon/farp.conf charon/forecast.conf charon/ha.conf '
     'charon/kernel-libipsec.conf charon/led.conf charon/lookip.conf charon/tnc-tnccs.conf '
     'charon/unity.conf charon/xauth-eap.conf charon/xauth-pam.conf',
     '9217d22d0b888e08f27e4df29a871e8dd459822d312b57bde761508161a307cf'),
)
UNITS = (XL, IKE, X, B, NET_UNIT)
TABLE = 'celerity_rebuild_l2tp'
PRIORITY = 10077
LEGACY_NFT = '/etc/nftables.d/celerity-l2tp.nft'
LEGACY_MODULES = '/etc/modules-load.d/c3-l2tp.conf'
# The classic default; also check the selected routing mark when one is known.
LEGACY_FWMARK = 100
NAMES = {
    'main': MAIN, 'lns': '/etc/xl2tpd/xl2tpd.conf', 'options': '/etc/ppp/options.xl2tpd',
    'chap': '/etc/ppp/chap-secrets', 'secrets': '/etc/ipsec.secrets', 'ike': '/etc/ipsec.d/celerity-rebuild-l2tp.conf',
    'starter': '/etc/ipsec.conf', 'nft': NFT_FILE, 'net': NET, 'drop': DROP,
}
# Install files in this order; all are joined before daemon-reload or starts.
ORDER = ('nft', 'net', 'drop', 'ike', 'starter', 'secrets', 'chap', 'options', 'lns', 'main')
FRESH_VPN_UNITS = (XL, IKE, 'ipsec.service', 'strongswan.service', 'strongswan-swanctl.service',
                   'charon.service', 'charon-systemd.service', 'charon-nm.service')
FRESH_VPN_COMM = {name[:-8].encode() for name in FRESH_VPN_UNITS} | {b'starter', b'pluto'}
FOREIGN_CONFIG = 'L2TP_FOREIGN_CONFIG'
FOREIGN_CHANGED = FOREIGN_CONFIG + '_CHANGED'
FOREIGN_PENDING = 'foreign-cleanup.pending'
FRESH_ACTIONS = ('preflight', 'prepare', 'check', 'install')
FRESH_CONFLICTS = (FOREIGN_CONFIG, FOREIGN_CHANGED, 'L2TP_DAEMON_ACTIVE', 'L2TP_UDP_BOUND', 'L2TP_PPP_ACTIVE')
# Canonical wire order; mirror in rebuildRelayInstallDiagnostics.js.
FOREIGN_REASONS = ('SWAN_PROFILE_PRESENT', 'IKE_PROFILE_PRESENT', 'OPTIONS_PRESENT', 'STARTER_NOT_STOCK',
                   'SECRETS_NOT_EMPTY', 'CHAP_NOT_EMPTY', 'LNS_NOT_STOCK', 'XRAY_UNIT_0666', 'XRAY_BRIDGE_UNIT_0666',
                   'UNIT_WRITABLE', 'NFT_DIR_PRESENT', 'DROPIN_PRESENT', 'MODULES_LOAD_FOREIGN',
                   'NETWORK_UNIT_ORPHANED', 'LEGACY_NFT_PRESENT', 'IPSEC_D_FOREIGN_CONF',
                   'SWAN_TREE_NOT_STOCK', 'CONFFILE_UNKNOWN', 'INCLUDE_FOREIGN')
MAX_FILE = 16 * 1024 * 1024
MAX_REQUEST = 25 * 1024 * 1024
HOST_STARTED = time.monotonic()
DEADLINE = HOST_STARTED + 115
# Two 78s APT children plus up to 54s total for stdin admission, observation,
# planning, containment, cleanup and receipt readback. The shell is 220s.
PACKAGE_PREPARE_DEADLINE = HOST_STARTED + 210
STAGE = 'PREREQUISITE'
REMOVE_ENTERED = False
CHAP_ENTERED = False
NETWORK_UPGRADE_ENTERED = False
NO_INSTALL_WRITES = False
PPP_PREPARING = False
NATIVE_PREPARING = False
CLEANUP_ENTERED = False
PPP_MODULES = ('ppp_generic', 'l2tp_ppp')
SOCKET_OBSERVERS = ('inet_diag', 'tcp_diag', 'udp_diag')
NFT_OBSERVERS = ('nfnetlink', 'nf_tables')
OBSERVERS = (*SOCKET_OBSERVERS, *NFT_OBSERVERS, 'xfrm_user')
PPP_DIRS = ('/etc/modules-load.d', '/run/modules-load.d', '/usr/local/lib/modules-load.d',
            '/usr/lib/modules-load.d', '/lib/modules-load.d')
PPP_CONF = '70-celerity-rebuild-l2tp.conf'
PPP_PATH = PPP_DIRS[0] + '/' + PPP_CONF
PPP_REQUIRED = 'PPP_MODULES_REQUIRED'
PPP_CONFLICT = 'PPP_MODULES_PERSISTENCE_CONFLICT'
PPP_FAILED = 'PPP_MODULES_LOAD_FAILED'
OBSERVATION_REQUIRED = 'NETWORK_OBSERVATION_REQUIRED'
MODULE_BLACKLISTED = 'KERNEL_MODULE_BLACKLISTED'
MODPROBE = '/usr/sbin/modprobe'


class Refusal(Exception):
    pass


class FreshInstallConflict(Refusal):
    def __init__(self, check, keys=(), fingerprint=None, cleanable=()):
        super().__init__(check)
        self.keys, self.fingerprint, self.cleanable = keys, fingerprint, cleanable


class PackageDiagnostic(Refusal):
    def __init__(self, suffix, *, uncertain=False):
        super().__init__(suffix)
        self.suffix = suffix
        self.uncertain = uncertain


def need(condition, code):
    if not condition:
        raise Refusal(code)


def command(*args, data=None, wait=6, unit_show=False, quiet=False, negative=None, refusal=None):
    limit = min(wait, DEADLINE - time.monotonic())
    if limit <= 0:
        raise subprocess.TimeoutExpired([], 0)
    result = subprocess.run(args, input=data, stdin=subprocess.DEVNULL if data is None else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE if quiet else subprocess.DEVNULL, timeout=limit,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, cwd='/')
    need(result.returncode >= 0, 'IN_FLIGHT')
    why = refusal or STAGE
    need(len(result.stdout) <= MAX_FILE, why)
    need(not quiet or not result.stderr, why)
    # Some systemd versions exit 1 for a structured not-found unit.
    if negative is not None:
        need(result.returncode == 1 and result.stdout == negative, why)
    else:
        need(result.returncode == 0 or (unit_show and result.returncode == 1
             and result.stdout.splitlines().count(b'LoadState=not-found') == 1), why)
    return result.stdout


@contextlib.contextmanager
def package_child_scope():
    # This one-shot helper is single-threaded and has no other child waiters.
    # Adopt orphaned descendants, including ones that call setsid() and close
    # both pipes. Once the original child is reaped, ECHILD proves there is
    # nothing left to join here; an adopted child of any status is uncertain.
    libc = ctypes.CDLL(None, use_errno=True)
    prior = ctypes.c_int()
    need(libc.prctl(37, ctypes.byref(prior), 0, 0, 0) == 0, 'IN_FLIGHT')  # PR_GET_CHILD_SUBREAPER
    need(libc.prctl(36, 1, 0, 0, 0) == 0, 'IN_FLIGHT')  # PR_SET_CHILD_SUBREAPER
    try:
        yield
        try:
            os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError as error:
            need(error.errno == errno.ECHILD, 'IN_FLIGHT')
        else:
            raise Refusal('IN_FLIGHT')
    finally:
        need(libc.prctl(36, prior.value, 0, 0, 0) == 0, 'IN_FLIGHT')


def install_progress(mark):
    # Only fixed marks, never child bytes. Don't block the host writer on UI.
    try:
        fd = sys.stderr.fileno()
        blocking = os.get_blocking(fd)
        os.set_blocking(fd, False)
        try:
            os.write(fd, ('DIRECT_PROGRESS ' + mark + '\n').encode('ascii'))
        finally:
            os.set_blocking(fd, blocking)
    except Exception:
        pass


class AptProgress:
    def __init__(self):
        self.line = b''
        self.overflow = False
        self.phase = 0

    def feed(self, chunk):
        for i, part in enumerate(chunk.split(b'\n')):
            if i:
                self.finish_line()
            if not self.overflow:
                if len(part) + len(self.line) <= 256:
                    self.line += part
                else:
                    self.overflow = True

    def finish_line(self):
        if not self.overflow and self.phase < 2:
            prefix = re.match(rb'^(Unpacking|Setting up) [a-z0-9][a-z0-9+.:\-]* \([^\r\n]+\) \.\.\.\r?$', self.line)
            if prefix:
                phase = 1 if prefix[1] == b'Unpacking' else 2
                if phase > self.phase:
                    self.phase = phase
                    install_progress('unpacking' if phase == 1 else 'settingUp')
        self.line = b''
        self.overflow = False


def bounded_status(argv, end, maximum, *, may_write=False, progress=None, stock_stage=False,
                   stock_cwd=None, stock_config=None, stock_owner=None):
    """Join bounded pipe EOF and original reap, plus writer descendant settlement."""
    with package_child_scope() if may_write or stock_stage else contextlib.nullcontext():
        result = _bounded_child_status(argv, end, maximum, may_write, progress,
                                       stock_stage=stock_stage, stock_cwd=stock_cwd, stock_config=stock_config,
                                       stock_owner=stock_owner)
    if time.monotonic() >= end:
        raise subprocess.TimeoutExpired((), 0)
    return result


def _bounded_child_status(argv, end, maximum, may_write, progress=None, *, stock_stage=False,
                          stock_cwd=None, stock_config=None, stock_owner=None):
    def left():
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired((), 0)
        return remaining

    left()
    # With SIGCHLD ignored, Popen.wait() can turn ECHILD into a false zero.
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'IN_FLIGHT')
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'}
    options = {'start_new_session': True} if stock_stage else {}
    if stock_config is not None:
        # Launch APT itself unprivileged. APT invoked as root
        # can disable its own sandbox when a destination probe fails.
        need(stock_stage and stock_cwd and stock_owner is not None and stock_owner[0] > 0, 'CONFFILE_UNKNOWN')
        env['APT_CONFIG'] = stock_config
        env['TMPDIR'] = stock_cwd
        options.update(user=stock_owner[0], group=stock_owner[1], extra_groups=[])
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=stock_cwd or '/', env=env, **options)
    try:
        assert child.stdout is not None and child.stderr is not None
        with child.stdout as stdout, child.stderr as stderr, selectors.DefaultSelector() as pipes:
            out, err = bytearray(), bytearray()
            pipes.register(stdout, selectors.EVENT_READ, out)
            pipes.register(stderr, selectors.EVENT_READ, err)
            while pipes.get_map():
                for key, _ in pipes.select(left()):
                    buf = key.data
                    data = os.read(key.fd, min(16384, maximum + 1 - len(buf)))
                    if not data:
                        pipes.unregister(key.fileobj)
                    else:
                        buf.extend(data)
                        if progress is not None and buf is out:
                            try:
                                progress.feed(data)
                            except Exception:
                                progress = None
                        if len(buf) > maximum:
                            raise subprocess.TimeoutExpired((), 0)
            status = child.wait(timeout=left())
        left()
        if status < 0:
            if stock_stage:
                raise subprocess.CalledProcessError(status, argv)
            raise subprocess.TimeoutExpired((), 0)
        return status, bytes(out), bytes(err)
    except BaseException:
        # Do not interrupt a package writer to manufacture settlement. The
        # durable pending fence survives us even if descendants remain live.
        if not may_write:
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                if stock_stage:
                    os.killpg(child.pid, signal.SIGKILL)
                else:
                    child.kill()
                child.wait(timeout=0.25)
        raise


def sc(*args, wait=6):
    return command('/usr/bin/systemctl', '--no-pager', *args, wait=wait)


def ip(*args):
    return json.loads(command('/usr/sbin/ip', '-j', '-N', '-4', *args))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def b64(data):
    return base64.b64encode(data).decode('ascii')


@contextlib.contextmanager
def directory(path, private=False):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for component in path.strip('/').split('/') if path != '/' else []:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            st = os.fstat(fd)
            need(st.st_uid == 0 and not st.st_mode & 0o022, 'PREREQUISITE')
        if private:
            st = os.fstat(fd)
            need(stat.S_IMODE(st.st_mode) == 0o700 and st.st_gid == 0, 'PREREQUISITE')
        yield fd
    finally:
        os.close(fd)


def read(path, maximum=MAX_FILE, *, diagnose_main_mode=False, diagnose_profile_owner=False):
    parent, name = os.path.split(path)
    try:
        with directory(parent) as fd:
            with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd), 'rb') as handle:
                st = os.fstat(handle.fileno())
                owner_ok = st.st_uid == 0 or (path in (MAIN, BRIDGE) and st.st_uid == pwd.getpwnam('nobody').pw_uid)
                writable = bool(st.st_mode & 0o022)
                diagnose_writable = diagnose_main_mode and path == MAIN
                owner_refusal = (diagnose_profile_owner and path in (MAIN, BRIDGE)
                                 and stat.S_ISREG(st.st_mode) and not owner_ok)
                need(stat.S_ISREG(st.st_mode) and owner_ok and st.st_nlink == 1
                     and not st.st_mode & 0o7000 and (not writable or diagnose_writable)
                     and not os.listxattr(handle.fileno()),
                     'XRAY_PROFILE_OWNER_UNSUPPORTED' if owner_refusal else 'PREREQUISITE')
                # Only install observation distinguishes this mode; do not read the payload.
                need(not writable, XRAY_CONFIG_WRITABLE)
                data = handle.read(maximum + 1)
                need(len(data) <= maximum and len(data) == st.st_size, 'PREREQUISITE')
                return entry(data, stat.S_IMODE(st.st_mode), st.st_gid, st.st_uid)
    except FileNotFoundError:
        return None


def raw(record):
    return base64.b64decode(record['data'], validate=True)


def entry(data, mode=0o600, gid=0, uid=0):
    record = {'data': b64(data), 'mode': mode, 'gid': gid}
    if uid:
        record['uid'] = uid
    return record


def mkdir(path, mode, exist_ok=False):
    parent, name = os.path.split(path)
    with directory(parent) as fd:
        try:
            os.mkdir(name, mode, dir_fd=fd)
            os.fsync(fd)
        except FileExistsError:
            need(exist_ok, 'ROLLBACK_DRIFT')
    with directory(path, private=mode == 0o700):
        pass


def rmdir(path):
    parent, name = os.path.split(path)
    with directory(parent) as fd:
        os.rmdir(name, dir_fd=fd)
        os.fsync(fd)


def write(path, before, after, *, generation=None, witness=False, reader=None, mtime_ns=None):
    get = reader if reader is not None else lambda path: read(path, 2 * MAX_FILE)
    need(get(path) == before, 'ROLLBACK_DRIFT')
    parent, name = os.path.split(path)

    def check_generation(fd):
        if generation is not None:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            need([st.st_dev, st.st_ino, st.st_ctime_ns] == generation, 'ROLLBACK_DRIFT')

    published = None
    with directory(parent) as fd:
        if after is None:
            if generation is not None:
                need(get(path) == before, 'ROLLBACK_DRIFT')
                check_generation(fd)
            os.unlink(name, dir_fd=fd)
        else:
            scratch = '.direct-' + uuid.uuid4().hex
            handle = os.open(scratch, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                with os.fdopen(handle, 'wb') as output:
                    output.write(raw(after))
                    output.flush()
                    uid = after.get('uid', 0)
                    need(uid == 0 or (path in (MAIN, BRIDGE) and uid == pwd.getpwnam('nobody').pw_uid), 'ROLLBACK_DRIFT')
                    os.fchown(output.fileno(), uid, after['gid'])
                    os.fchmod(output.fileno(), after['mode'])
                    if mtime_ns is not None:
                        os.utime(output.fileno(), ns=(mtime_ns, mtime_ns))
                    os.fsync(output.fileno())
                    if path == PPP_PATH or witness:
                        st = os.fstat(output.fileno())
                        published = [st.st_dev, st.st_ino]
                need(get(path) == before, 'ROLLBACK_DRIFT')
                check_generation(fd)
                if before is None:
                    os.link(scratch, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                else:
                    os.replace(scratch, name, src_dir_fd=fd, dst_dir_fd=fd)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(scratch, dir_fd=fd)
        os.fsync(fd)
        installed = None
        if published is not None:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            need([st.st_dev, st.st_ino] == published, 'ROLLBACK_DRIFT')
            installed = [*published, st.st_ctime_ns]
    need(get(path) == after, 'RUNTIME_UNPROVED')
    if installed is not None:
        need(remove_generation(path) == installed, 'ROLLBACK_DRIFT')
    return installed


def unit(name):
    keys = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'InvocationID',
            'NeedDaemonReload', 'FragmentPath', 'DropInPaths', 'ExecStart', 'User', 'Group', 'Job',
            'Environment', 'EnvironmentFiles', 'RootDirectory', 'RootImage', 'PrivateNetwork',
            'KillMode', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'WorkingDirectory',
            'Restart', 'Type', 'Requires', 'After', 'ControlGroup', 'RequiredBy', 'BoundBy', 'ConsistsOf',
            'PropagatesStopTo', 'Conflicts', 'ConflictedBy', 'Wants', 'BindsTo', 'PartOf', 'Upholds',
            'SourcePath', 'ExecCondition', 'ExecReload', 'PassEnvironment', 'UnsetEnvironment')
    # `systemctl show` returns nonzero for some not-found units. LoadState is
    # inspected explicitly; do not treat arbitrary command failures as absence.
    text = command('/usr/bin/systemctl', '--no-pager', 'show', '--all', '--property=' + ','.join(keys), name,
                   unit_show=True).decode('utf-8')
    pairs = [line.split('=', 1) for line in text.splitlines() if '=' in line]
    if name == NET_UNIT:
        starts = [value for key, value in pairs if key == 'ExecStart']
        if len(starts) > 1:
            # systemctl show emits a row per command for our three-command
            # oneshot. Preserve order and keep every other property unique.
            need(len(starts) == 3 and ['Type', 'oneshot'] in pairs
                 and ['LoadState', 'loaded'] in pairs
                 and all(re.fullmatch(r'\{ path=/[^ ;{}]+ ; argv\[\]=[^{}]+ \}', value) for value in starts),
                 'PREREQUISITE')
            pairs = [(key, value) for key, value in pairs if key != 'ExecStart']
            pairs.append(('ExecStart', ' '.join(starts)))
    info = dict(pairs)
    if len(pairs) != len(info):
        raise Refusal(XRAY_DROPIN_UNSUPPORTED if name == X and
                      any(key == 'DropInPaths' and value for key, value in pairs) else 'PREREQUISITE')
    need(info.get('LoadState') in ('loaded', 'masked', 'not-found') and
         info.get('ActiveState') in ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'), 'PREREQUISITE')
    return info


def no_jobs(units):
    # Systemd can continue executing jobs after its client has exited. Check
    # actual manager jobs before interpreting runtime or permitting restoration.
    jobs = sc('list-jobs', '--no-legend', '--plain').decode().splitlines()
    need(not any(set(line.split()) & set(units) for line in jobs), 'IN_FLIGHT')


def ppp_device():
    try:
        dev = os.lstat('/dev/ppp')
        return stat.S_ISCHR(dev.st_mode) and os.major(dev.st_rdev) == 108 and os.minor(dev.st_rdev) == 0
    except FileNotFoundError:
        return None


def ppp_registered():
    # Opening the device (or a PPPoX socket) could trigger kernel autoload.
    with open('/proc/devices', 'rb') as stream:
        registered = stream.read(65536).partition(b'Block devices:')[0]
    return re.search(rb'^\s*108\s+ppp\s*$', registered, re.M) is not None


def require_runtime_packages(refusal):
    for package in REQUIRED_PACKAGES:
        status = command('/usr/bin/dpkg-query', '-W', '-f=${db:Status-Abbrev}', package, refusal=refusal)
        need(status.startswith(b'ii '), refusal)


def require_machine(machine):
    with open('/etc/machine-id', 'rb') as source:
        match = re.fullmatch(rb'([a-f0-9]{32})\n?', source.read(34))
    if match is None:
        raise Refusal('PREREQUISITE')
    machine_id = match[1].decode('ascii')
    need(machine_id == machine, 'IDENTITY')
    return machine_id


def preflight(machine, *, fresh=False):
    machine_id = require_machine(machine)
    if fresh:
        package_no_pending()
        # A missing runtime package can start IKE/LNS in its maintainer
        # scripts. Check dpkg before interpreting unit state or preparing PPP;
        # Never change service policy or stop an existing service here.
        require_runtime_packages(PACKAGE_AUTOSTART_UNSAFE)
    ppp = ppp_device() is True and ppp_registered()
    xl, ike = (unit(name) for name in (XL, IKE))
    units = [xl['LoadState'], ike['LoadState']]
    if not fresh and units == ['loaded'] * 2:
        require_runtime_packages('PREREQUISITE')
    masked = 'masked' in units or (fresh and any(u.get('UnitFileState') in ('masked', 'masked-runtime') for u in (xl, ike)))
    return dict(machineId=machine_id, ppp=ppp, masked=masked, unitsLoaded=units == ['loaded'] * 2)


def fresh_udp_bound():
    # /proc/net avoids loading udp_diag and includes connected UDP sockets.
    bound = False
    for leaf, width in (('udp', 8), ('udp6', 32)):
        try:
            with open('/proc/net/' + leaf, 'rb') as stream:
                data = stream.read(2**20 + 1)
        except FileNotFoundError:
            if leaf == 'udp6':  # IPv6 may not be registered.
                continue
            raise
        need(0 < len(data) <= 2**20 and data.endswith(b'\n'), 'PREREQUISITE')
        header, *rows = data.splitlines()
        fields = header.split()
        need(fields[:2] == [b'sl', b'local_address'] and len(fields) >= 4
             and fields[2] in (b'rem_address', b'remote_address') and fields[3] == b'st', 'PREREQUISITE')
        for row in rows:
            match = re.match(rb'\s*[0-9]+:\s+[0-9A-F]{%d}:([0-9A-F]{4})\s' % width, row)
            need(match is not None, 'PREREQUISITE')
            bound |= int(match[1], 16) in (500, 4500, 1701)
    return bound


def fresh_runtime_conflict():
    units = {name: unit(name) for name in FRESH_VPN_UNITS}
    # Keep the existing rule-220 and unmanaged starter refusals (including the
    # more specific idle IKE diagnosis). This never authorizes stopping IKE.
    if units[IKE]['ActiveState'] == 'active':
        fresh_ike_guard(units[IKE], inspect_runtime=not missing_network_observers())
    # not-found/inactive includes the stock dangling strongswan.service alias.
    # A missing fragment is not evidence that a live invocation has stopped.
    if any(info['ActiveState'] == 'active' for info in units.values()):
        return 'L2TP_DAEMON_ACTIVE'
    tasks = command('/usr/bin/ps', '-ww', '-e', '-o', 'pid=', '-o', 'comm=', quiet=True)
    pairs = [row.strip().split(None, 1) for row in tasks.splitlines()]
    need(all(len(pair) == 2 and re.fullmatch(rb'[1-9][0-9]*', pair[0]) and pair[1] not in (b'-', b'?')
             for pair in pairs) and len({pair[0] for pair in pairs}) == len(pairs), 'PREREQUISITE')
    names = {pair[1] for pair in pairs}
    need(b'ps' in names, 'PREREQUISITE')
    if names & FRESH_VPN_COMM:
        return 'L2TP_DAEMON_ACTIVE'
    no_jobs(FRESH_VPN_UNITS)
    need(all(info['ActiveState'] == 'inactive' for info in units.values()), 'PREREQUISITE')
    if fresh_udp_bound():
        return 'L2TP_UDP_BOUND'
    if b'pppd' in names:
        return 'L2TP_PPP_ACTIVE'
    # link_type is independent of the interface name (pppd can rename it).
    links = json.loads(command('/usr/sbin/ip', '-j', '-details', 'link', 'show', quiet=True))
    need(type(links) is list and all(type(row) is dict and type(row.get('ifname')) is str
         and type(row.get('link_type')) is str for row in links)
         and any(row['ifname'] == 'lo' and row['link_type'] == 'loopback' for row in links), 'PREREQUISITE')
    if any(row['link_type'] == 'ppp' for row in links):
        return 'L2TP_PPP_ACTIVE'
    fresh_ike_guard(units[IKE], inspect_runtime=False)
    return None


def foreign_leaf(path, *, folder=False, unit_mode=False, read_unit=False):
    def stamp(st):
        return [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
                st.st_size, st.st_mtime_ns, st.st_ctime_ns]

    parent, name = os.path.split(path)
    # Use the original trusted ancestor walk; never use this observer for writes.
    with contextlib.ExitStack() as stack:
        try:
            fd = stack.enter_context(directory(parent))
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        mode = stat.S_IMODE(st.st_mode)
        need(st.st_uid == st.st_gid == 0 and not mode & 0o7000, 'PREREQUISITE')
        need(stat.S_ISDIR(st.st_mode) if folder else stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
             'PREREQUISITE')
        need(unit_mode or not mode & 0o022, 'PREREQUISITE')
        pin = stamp(st)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if folder else 0)
        leaf = os.open(name, flags, dir_fd=fd)
        try:
            need(stamp(os.fstat(leaf)) == pin and not os.listxattr(leaf), 'PREREQUISITE')
            data = None
            # A directory and an unsafe non-0666 unit are diagnosis only.
            # For an ordinary unit there is no reason to read its contents.
            if not folder and (not unit_mode or mode == 0o666 or read_unit):
                with os.fdopen(leaf, 'rb', closefd=False) as stream:
                    data = stream.read(1024 * 1024 + 1)
                need(len(data) == st.st_size and len(data) <= 1024 * 1024, 'PREREQUISITE')
            need(stamp(os.fstat(leaf)) == pin and stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)) == pin,
                 'BASELINE_CHANGED')
            return mode, pin, data
        finally:
            os.close(leaf)


def foreign_conffiles(package):
    output = command('/usr/bin/dpkg-query', '-W', r'-f=${Status}\n${Conffiles}', package, quiet=True, refusal='PREREQUISITE')
    status, separator, rows = output.partition(b'\n')
    need(separator and status == b'install ok installed' and len(rows) <= 65536, 'PREREQUISITE')
    hashes = {}
    for row in rows.split(b'\n'):
        if row:
            match = re.fullmatch(rb' (/[^\s]+) ([a-f0-9]{32})( obsolete)?', row)
            need(match is not None and match[1] not in hashes, 'PREREQUISITE')
            hashes[match[1]] = None if match[3] else match[2]
    return hashes


def old_network_idle(has_unit, fwmark, *, vacant=True, unlinked=False):
    if vacant and recovery_stat(VAULT) is not None:
        return False
    try:
        net = unit(NET_UNIT)
        if net['ActiveState'] != 'inactive' or net.get('Job') or net.get('DropInPaths'):
            return False
        if has_unit:
            if not (net['LoadState'] == 'loaded' and net.get('FragmentPath') == NET
                    and (net.get('UnitFileState') in ('static', 'disabled')
                         or unlinked and net.get('UnitFileState') in ('', None))
                    and net.get('DropInPaths') == '' and net.get('MainPID') == '0'):
                return False
        elif not (net['LoadState'] == 'not-found' and not net.get('FragmentPath') and not net.get('UnitFileState')
                  and (vacant or net.get('MainPID') == '0')):
            return False
        no_jobs((NET_UNIT,))
        marks = {LEGACY_FWMARK} if fwmark is None else {LEGACY_FWMARK, fwmark}
        for rows in swan_rule_dumps():
            for row in rows:
                if number(row['priority']) == PRIORITY:
                    return False
                if 'fwmark' in row:
                    mark, mask = number(row['fwmark']), number(row.get('fwmask', 0xffffffff))
                    if row.get('not') or row.get('invert') or any(mark == value & mask for value in marks):
                        return False
        routes = json.loads(command('/usr/sbin/ip', '-j', '-N', '-4', 'route', 'show', 'table', 'all', quiet=True))
        need(type(routes) is list and all(type(row) is dict for row in routes), 'NETWORK_CONFLICT')
        routes = cast(list[dict[str, Any]], routes)
        if any(row.get('type') in ('local', '2', 2) and row.get('dev') == 'lo'
               and row.get('dst') in ('default', '0.0.0.0/0') for row in routes):
            return False
        # Do not autoload a provider or infer safety from failed observation.
        if set(NFT_OBSERVERS).intersection(missing_network_observers()):
            return False
        return not any(row['name'] in (TABLE, 'celerity_l2tp') for row in nft_tables(strict=True))
    except (OSError, Refusal, ValueError, KeyError, TypeError):
        return False


def foreign_config_observation(fwmark=None, *, detailed=False, vacant=True):
    """Return fixed reasons and a private sample fingerprint, never write authority."""
    found = {}
    contents = {}
    metadata = {}
    diagnostic = set()

    def record(reason, path, leaf, stock=None):
        found[reason] = [path, leaf[1], digest(leaf[2]), stock.decode() if stock else None]
        contents[reason] = leaf[2]

    for reason, path in (('SWAN_PROFILE_PRESENT', SWAN_PROFILE), ('IKE_PROFILE_PRESENT', NAMES['ike']),
                         ('OPTIONS_PRESENT', NAMES['options']), ('MODULES_LOAD_FOREIGN', LEGACY_MODULES)):
        leaf = foreign_leaf(path)
        if leaf is not None:
            record(reason, path, leaf)

    def included(parent):
        try:
            with directory(parent) as fd, os.scandir(fd) as entries:
                for i, row in enumerate(entries):
                    need(i < 4096, 'PREREQUISITE')
                    yield row.name
        except FileNotFoundError:
            pass

    # A basename in a glob is not a cleanup candidate. Keep the existing
    # Debian strongSwan tree proof when there are other inputs in that tree.
    if any(name != os.path.basename(NAMES['ike']) and not name.startswith('.') and name.endswith('.conf')
           for name in included(os.path.dirname(NAMES['ike']))):
        diagnostic.add('IPSEC_D_FOREIGN_CONF')
    if set(included(SWAN_DIR)) - {os.path.basename(SWAN_PROFILE)} or recovery_stat(SWAN_CONF) is not None:
        try:
            swan_inputs('SWAN_PROFILE_PRESENT' in found, 'SWAN_TREE_NOT_STOCK')
        except Refusal as error:
            if str(error) != 'SWAN_TREE_NOT_STOCK':
                raise
            diagnostic.add('SWAN_TREE_NOT_STOCK')

    for reason, name, package in (('STARTER_NOT_STOCK', 'starter', 'strongswan-starter'),
                                  ('SECRETS_NOT_EMPTY', 'secrets', 'strongswan-starter'),
                                  ('LNS_NOT_STOCK', 'lns', 'xl2tpd')):
        path = NAMES[name]
        leaf = foreign_leaf(path)
        if leaf is None:
            continue
        if package not in metadata:
            try:
                metadata[package] = foreign_conffiles(package)
            except Refusal as error:
                if str(error) != 'PREREQUISITE':
                    raise
                metadata[package] = {}
        stock = metadata[package].get(path.encode())
        data = leaf[2]
        active = uncomment(data)
        if name != 'lns':
            # An include outside the reviewed starter glob is not a known leaf.
            if any(line.split(None, 1)[0].lower() == b'include' and not (name == 'starter' and line == STOCK_IKE_INCLUDE)
                   for line in active):
                diagnostic.add('INCLUDE_FOREIGN')
                continue
        if stock is None:
            diagnostic.add('CONFFILE_UNKNOWN')
            continue
        stock_bytes = hashlib.md5(data, usedforsecurity=False).hexdigest().encode() == stock
        if name == 'starter':
            # Also accept the exact wildcard append performed by install-runtime.sh.
            append = b'\n' + STOCK_IKE_INCLUDE + b'\n'
            stock_bytes |= (data.endswith(append) and
                            hashlib.md5(data[:-len(append)], usedforsecurity=False).hexdigest().encode() == stock)
        if (bool(active) if name == 'secrets' else not stock_bytes):
            record(reason, path, leaf, stock)

    path = NAMES['chap']
    chap = foreign_leaf(path)
    if chap is not None and any(line.strip() and not line.lstrip().startswith(b'#') for line in chap[2].split(b'\n')):
        record('CHAP_NOT_EMPTY', path, chap)
    for reason, name in (('XRAY_UNIT_0666', X), ('XRAY_BRIDGE_UNIT_0666', B)):
        path = SYSTEM + '/' + name
        leaf = foreign_leaf(path, unit_mode=True)
        if leaf is not None and leaf[0] & 0o022:
            if leaf[0] == 0o666:
                record(reason, path, leaf)
            else:
                diagnostic.add('UNIT_WRITABLE')
    for reason, path in (('NFT_DIR_PRESENT', NFT_DIR), ('DROPIN_PRESENT', DROP_DIR)):
        folder = foreign_leaf(path, folder=True)
        if folder is not None:
            diagnostic.add(reason)
            if detailed:
                leaf_path = NFT_FILE if path == NFT_DIR else DROP
                with directory(path) as fd, os.scandir(fd) as names:
                    inventory = []
                    for i, member in enumerate(names):
                        need(i < 128, 'PREREQUISITE')
                        st = member.stat(follow_symlinks=False)
                        inventory.append([member.name, st.st_ino, st.st_mode, st.st_size, st.st_ctime_ns])
                sample = [path, folder[1], sorted(inventory)]
                if len(inventory) == 1 and inventory[0][0] == os.path.basename(leaf_path):
                    try:
                        leaf = foreign_leaf(leaf_path)
                    except (OSError, Refusal):
                        leaf = None
                    if leaf is not None:
                        sample.append([leaf[1], digest(leaf[2])])
                        contents[reason] = leaf[2]
                need(foreign_leaf(path, folder=True) == folder, 'BASELINE_CHANGED')
                if reason == 'NFT_DIR_PRESENT':
                    sample.append(cleanup_nft_base())
                found[reason] = sample
    net_exists = recovery_stat(NET) is not None
    if net_exists or recovery_stat(LEGACY_NFT) is not None:
        if not old_network_idle(net_exists, fwmark, **({} if vacant else {'vacant': False})):
            raise FreshInstallConflict('L2TP_DAEMON_ACTIVE')
        net = foreign_leaf(NET)
        legacy_nft = foreign_leaf(LEGACY_NFT)
        need((net is not None) == net_exists and (net is not None or legacy_nft is not None), 'BASELINE_CHANGED')
        if net is not None:
            record('NETWORK_UNIT_ORPHANED', NET, net)
        if legacy_nft is not None:
            record('LEGACY_NFT_PRESENT', LEGACY_NFT, legacy_nft)
    keys = tuple(reason for reason in FOREIGN_REASONS if reason in found or reason in diagnostic)
    if detailed:
        for reason in diagnostic:
            found.setdefault(reason, None)
        return keys, digest(encode(['foreign-config-v2', found])) if keys else None, found, contents
    return keys, digest(encode(['foreign-config-v2', found])) if found and not diagnostic else None


@contextlib.contextmanager
def stock_workspace():
    # This is not the cleanup VAULT. Nothing from here is ever published.
    with directory('/run'), tempfile.TemporaryDirectory(prefix='c3-conffile-', dir='/run') as path:
        yield Path(path)


def cleanup_stock_inputs(keys, found, contents):
    planner = C3_REPLACEMENT
    bad = 'CONFFILE_UNKNOWN'
    release = read('/usr/lib/os-release', 8192)
    need(release is not None and os.uname().machine == 'x86_64', bad)
    lines = raw(release).split(b'\n')
    for k, v in ((b'ID', b'debian'), (b'VERSION_ID', b'13'), (b'VERSION_CODENAME', b'trixie')):
        need([line.split(b'=', 1)[1] for line in lines if line.startswith(k + b'=')] in ([v], [b'"' + v + b'"']), bad)
    need(all(native_vpn(unit(name), name) for name in (XL, IKE)), bad)
    sample = {key: found[key] for key in keys}
    wanted = planner['stock_requirements'](keys, digest(encode(['foreign-config-v2', sample])),
                                           sample, {key: contents[key] for key in keys})
    packages = sorted({planner['STOCK'][key][1] for key in keys})
    installed = {p: command('/usr/bin/dpkg-query', '-W',
                            r'-f=${binary:Package}\t${Status}\t${Architecture}\t${Version}\n${Conffiles}',
                            p, quiet=True, refusal=bad) for p in packages}
    need(all(row[2] == 'amd64' for row in planner['stock_identities'](wanted, installed).values()), bad)
    return wanted, installed


def cleanup_stage_stock(wanted, installed):
    bad = 'CONFFILE_UNKNOWN'
    end = min(DEADLINE, time.monotonic() + 28)
    planner = C3_REPLACEMENT
    def run(argv, maximum, *, stderr_ok=False, failure='STOCK_CHILD_FAILED', **options):
        try:
            rc, out, err = bounded_status(argv, end, maximum, stock_stage=True, **options)
        except subprocess.CalledProcessError:
            raise planner['Refusal'](failure) from None
        if time.monotonic() >= end:
            raise subprocess.TimeoutExpired((), 0)
        planner['need'](rc == 0 and (stderr_ok or not err), failure)
        return out
    try:
        staged = planner['stage_host_stock'](wanted, installed=installed, directory=directory,
                                             workspace=stock_workspace, run=run)
    except planner['Refusal'] as error:
        planner['stock_log'](str(error))  # only fixed codes; never child output
        raise
    except subprocess.TimeoutExpired:
        planner['stock_log']('STOCK_STAGE_TIMEOUT')
        raise
    except (OSError, ValueError, KeyError, OverflowError):
        planner['stock_log']('REPLACEMENT_ARCHIVE_IO')
        raise
    need(staged.keys() == wanted.keys() and time.monotonic() < end, bad)
    if 'STARTER_NOT_STOCK' in staged:
        data = staged['STARTER_NOT_STOCK'].data
        need(uncomment(data) in ([STOCK_IKE_INCLUDE], [b'config setup', STOCK_IKE_INCLUDE]) or
             digest(data) == STOCK_IKE_STARTER_SHA, bad)
    if 'SECRETS_NOT_EMPTY' in staged:
        need(not uncomment(staged['SECRETS_NOT_EMPTY'].data), bad)
    return staged


def fresh_install_conflicts(machine, lock_fd, fwmark=None, *, cleanup=None, detailed=False):
    def scope():
        need(time.monotonic() < DEADLINE, 'IN_FLIGHT')
        current = (require_machine(machine), boot(), install_lock_identity(lock_fd))
        need(bool(current[1]) and time.monotonic() < DEADLINE, 'IN_FLIGHT')
        return current

    original = scope()
    def observe_runtime():
        try:
            return fresh_runtime_conflict()
        except Refusal as error:
            if str(error) in ('IKE_ACTIVE_RULE_220', 'RULE_220_CONFLICT', 'IKE_ACTIVE_UNMANAGED'):
                need(scope() == original, 'BASELINE_CHANGED')
            raise

    runtime = observe_runtime()
    keys = ()
    if runtime is None:
        try:
            if detailed:
                keys, fingerprint, found, contents = foreign_config_observation(fwmark, detailed=True)
            else:
                keys, _ = foreign_config_observation(fwmark)
        except FreshInstallConflict:
            need(scope() == original, 'BASELINE_CHANGED')
            raise
        if keys:
            # Runtime vetoes take precedence. The digest is private protocol
            # data; never return file content or the sample itself.
            runtime = observe_runtime()
            if runtime is None and 'xfrm_user' not in missing_network_observers():
                if (command('/usr/sbin/ip', 'xfrm', 'policy', 'list', 'nosock', quiet=True).strip()
                        or command('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys', quiet=True).strip()):
                    runtime = 'L2TP_DAEMON_ACTIVE'
    need(scope() == original, 'BASELINE_CHANGED')
    if runtime is not None:
        raise FreshInstallConflict(runtime)
    if not detailed:
        if keys:
            raise FreshInstallConflict(FOREIGN_CONFIG, keys)
        return
    if not keys:
        if cleanup is not None:
            raise FreshInstallConflict(FOREIGN_CHANGED)
        return
    if cleanup is None and 'C3_REPLACEMENT' not in globals():
        raise FreshInstallConflict(FOREIGN_CONFIG, keys)
    try:
        edits = cleanup_edits(found, contents, fwmark, machine=machine, cleanup_at=cleanup['at'] if cleanup else None)
    except FreshInstallConflict:
        need(scope() == original, 'BASELINE_CHANGED')
        raise
    need(scope() == original, 'BASELINE_CHANGED')
    cleanable = tuple(key for key in keys if key in edits)
    if cleanup is not None and cleanup['digest'] != fingerprint:
        raise FreshInstallConflict(FOREIGN_CHANGED, keys, fingerprint, cleanable)
    planner = globals().get('C3_REPLACEMENT')
    stock_keys = tuple(key for key in cleanable if key in planner['STOCK']) if planner else ()
    if stock_keys:
        # First request proves intrinsic eligibility only. Do not touch cache,
        # APT indexes or staging until the authenticated consent is joined.
        try:
            wanted, installed = cleanup_stock_inputs(stock_keys, found, contents)
        except (planner['Refusal'], Refusal, OSError, ValueError, subprocess.TimeoutExpired):
            need(scope() == original, 'BASELINE_CHANGED')
            raise FreshInstallConflict(FOREIGN_CONFIG, ('CONFFILE_UNKNOWN',)) from None
        need(scope() == original, 'BASELINE_CHANGED')
    mode_keys = {'XRAY_UNIT_0666', 'XRAY_BRIDGE_UNIT_0666'}
    if cleanup is None or cleanable != keys or (mode_keys.intersection(keys) and not cleanup['fixXrayUnitMode']):
        raise FreshInstallConflict(FOREIGN_CONFIG, keys, fingerprint, cleanable)
    if stock_keys:
        try:
            staged = cleanup_stage_stock(wanted, installed)
            need(cleanup_stock_inputs(stock_keys, found, contents) == (wanted, installed), 'CONFFILE_UNKNOWN')
        except (planner['Refusal'], Refusal, OSError, ValueError, KeyError, OverflowError, subprocess.TimeoutExpired):
            need(scope() == original, 'BASELINE_CHANGED')
            raise FreshInstallConflict(FOREIGN_CONFIG, ('CONFFILE_UNKNOWN',)) from None
        need(foreign_config_observation(fwmark, detailed=True) == (keys, fingerprint, found, contents), 'BASELINE_CHANGED')
        edits = cleanup_edits(found, contents, fwmark, machine=machine, cleanup_at=cleanup['at'], staged=staged)
        need(scope() == original, 'BASELINE_CHANGED')
        need(edits.keys() == set(keys) and all(edits.values()), 'BASELINE_CHANGED')
    return [edit for key in keys for edit in edits[key]]



# These are projections of observed fixed paths, not a writable overlay.
def cleanup_paths():
    return {'SWAN_PROFILE_PRESENT': SWAN_PROFILE, 'IKE_PROFILE_PRESENT': NAMES['ike'],
            'OPTIONS_PRESENT': NAMES['options'], 'MODULES_LOAD_FOREIGN': LEGACY_MODULES,
            'STARTER_NOT_STOCK': NAMES['starter'], 'SECRETS_NOT_EMPTY': NAMES['secrets'], 'LNS_NOT_STOCK': NAMES['lns'],
            'CHAP_NOT_EMPTY': NAMES['chap'], 'XRAY_UNIT_0666': SYSTEM + '/' + X,
            'XRAY_BRIDGE_UNIT_0666': SYSTEM + '/' + B, 'NFT_DIR_PRESENT': NFT_DIR,
            'NFT_MEMBER': NFT_FILE, 'DROPIN_PRESENT': DROP_DIR, 'DROP_MEMBER': DROP,
            'NETWORK_UNIT_ORPHANED': NET, 'LEGACY_NFT_PRESENT': LEGACY_NFT}


CLEANUP_FOLDERS = ('NFT_DIR_PRESENT', 'DROPIN_PRESENT')
CLEANUP_MANAGER = ('DROPIN_PRESENT', 'NETWORK_UNIT_ORPHANED')
CLEANUP_XRAY_SHA = {
    'XRAY_UNIT_0666': '535cc050a1b1a0dfd209cdec45a43938d578a06ef5d05cec44a7a15e62253d9b',
    'XRAY_BRIDGE_UNIT_0666': '8419e3b8dc8345ed8f7c1ce585a1e8bd6300134d040fef2de70535aee773696a',
}


def cleanup_xray_identity():
    no_jobs((X, B))
    result = {}
    for name in (X, B):
        info = unit(name)
        if info['LoadState'] == 'not-found' and info['ActiveState'] == 'inactive' and info.get('MainPID') == '0' and name == B:
            result[name] = {k: info.get(k) for k in INSTALL_UNIT_FIELDS}
        else:
            path = MAIN if name == X else BRIDGE
            need(info.get('NeedDaemonReload') == 'no', 'BASELINE_CHANGED')
            pid = xray_argv(info, path)
            result[name] = [info['InvocationID'], pid, reattest_process(pid, info)]
    return result


def cleanup_runtime(fwmark, *, has_unit=False, unlinked=False):
    require_network_observers()
    conflict = fresh_runtime_conflict()
    if conflict is not None:
        raise FreshInstallConflict(conflict)
    if (command('/usr/sbin/ip', 'xfrm', 'policy', 'list', quiet=True).strip()
            or command('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys', quiet=True).strip()):
        raise FreshInstallConflict('L2TP_DAEMON_ACTIVE')
    need(old_network_idle(has_unit, fwmark, vacant=False, unlinked=unlinked), OBSERVATION_REQUIRED)


def cleanup_nft_base():
    """Absent, proven stock without includes, or unqualified (False)."""
    path = '/etc/nftables.conf'
    try:
        leaf = foreign_leaf(path)
        if leaf is None:
            return None
        _, pin, data = leaf
        if (data is not None and len(data) <= 65536 and not any(re.search(rb'\binclude\b', line, re.I)
                                           for line in data.splitlines() if not line.lstrip().startswith(b'#'))
                and foreign_conffiles('nftables').get(path.encode()) == hashlib.md5(data, usedforsecurity=False).hexdigest().encode()):
            return [pin, digest(data)]
    except (OSError, Refusal, subprocess.TimeoutExpired):
        pass
    return False


def cleanup_nft(data, *, classic, machine=None):
    # Demand byte equality with the known renderer; a table name/comment alone
    # is insufficient. Do not run even nft --check during a read-only action.
    try:
        if classic:
            cidr, port, mark = re.search(rb'ip saddr ([0-9./]+) meta l4proto tcp tproxy ip to :([0-9]+) meta mark set ([0-9]+) accept', data).groups()
            cidr, port, mark = cidr.decode(), int(port), int(mark)
            need(str(ipaddress.IPv4Network(cidr)) == cidr and 1 <= port <= 65535 and 1 <= mark <= 0xffffffff, 'PREREQUISITE')
            lines = ''.join(f'        iifname "ppp*" ip saddr {cidr} meta l4proto {proto} tproxy ip to :{port} meta mark set {mark} accept\n'
                            for proto in ('tcp', 'udp'))
            return data == ('table inet celerity_l2tp {\n    chain prerouting {\n'
                            '        type filter hook prerouting priority mangle; policy accept;\n' + lines +
                            '    }\n\n    chain forward {\n        type filter hook forward priority filter; policy accept;\n'
                            f'        iifname "ppp*" ip saddr {cidr} drop comment "block non-TPROXY PPP egress"\n'
                            '    }\n}\n').encode()
        token, cidr, port, mark = re.search(
            rb'\A(?:create )?table inet celerity_rebuild_l2tp \{\n    comment "([a-f0-9]{32})"\n.*?ip saddr ([0-9./]+) meta l4proto \{ tcp, udp \} tproxy ip to :([0-9]+) meta mark set ([0-9]+)',
            data, re.S).groups()
        cidr, port, mark = cidr.decode(), int(port), int(mark)
        need(str(ipaddress.IPv4Network(cidr)) == cidr and 1 <= port <= 65535 and 1 <= mark <= 0xffffffff, 'PREREQUISITE')
        rendered = managed_nft_bytes(dict(clientCidr=cidr, tproxyPort=port, fwmark=mark), token.decode())
        return data == rendered or (token.decode() == machine and mark == LEGACY_FWMARK
                                    and data == rendered.removeprefix(b'create '))
    except (AttributeError, Refusal, ValueError):
        return False


def cleanup_record(data, pin):
    return entry(data, stat.S_IMODE(pin[2]), pin[4], pin[3])


def cleanup_net_bytes(data):
    try:
        table, cidr, mark = re.search(rb'route add local 0\.0\.0\.0/0 dev lo table ([0-9]+)\n'
                                     rb'[^\n]+ from ([0-9./]+) fwmark ([0-9]+) table ', data).groups()
        table, cidr, mark = int(table), cidr.decode(), int(mark)
        if (str(ipaddress.IPv4Network(cidr)) == cidr and 1 <= table <= 0xffffffff
                and mark == LEGACY_FWMARK):
            d = dict(clientCidr=cidr, routeTable=table, fwmark=mark)
            return any(data == network_unit(d, sidecar, legacy=legacy)
                       for sidecar in (False, True) for legacy in (False, True))
    except (AttributeError, ValueError):
        pass
    return False


def cleanup_edits(found, contents, fwmark, *, machine=None, cleanup_at=None, staged=None):
    planner = globals().get('C3_REPLACEMENT')
    if planner is None:
        return {}
    try:
        cleanup_runtime(fwmark, has_unit='NETWORK_UNIT_ORPHANED' in found)
    except FreshInstallConflict:
        # A late positive runtime conflict takes precedence over file diagnostics.
        raise
    except Refusal as error:
        if str(error) != OBSERVATION_REQUIRED:
            raise
        return {}
    result = {}
    paths = cleanup_paths()
    for key, item in found.items():
        data = contents.get(key)
        if key not in paths or data is None:
            continue
        if key in CLEANUP_FOLDERS:
            member = item[3]
            mode = stat.S_IMODE(item[1][2])
            if mode not in (0o700, 0o755) or stat.S_IMODE(member[0][2]) != 0o644:
                continue
            if key == 'NFT_DIR_PRESENT':
                # A known body is not proof that a persistent include may be removed.
                qualified = item[4] is not False and cleanup_nft(data, classic=False, machine=machine)
                leaf = 'NFT_MEMBER'
            else:
                info = unit(XL)
                qualified = (info.get('DropInPaths') == DROP and info.get('NeedDaemonReload') == 'no'
                             and info['ActiveState'] == 'inactive' and info.get('MainPID') == '0'
                             and data == f'[Unit]\nRequires={NET_UNIT} {IKE}\nAfter={NET_UNIT} {IKE}\n'.encode())
                leaf = 'DROP_MEMBER'
            if qualified:
                result[key] = [[leaf, cleanup_record(data, member[0]), None, member[0]], [key, mode, None, item[1]]]
            continue
        if key == 'NETWORK_UNIT_ORPHANED' and (stat.S_IMODE(item[1][2]) != 0o644 or not cleanup_net_bytes(data)):
            continue
        if key == 'LEGACY_NFT_PRESENT':
            base_nft = read('/etc/nftables.conf', 65536)
            # No validator for a foreign persistent include graph.
            if base_nft is None and (
                    item[0] == paths[key] and stat.S_IMODE(item[1][2]) == 0o644 and cleanup_nft(data, classic=True)):
                result[key] = [[key, cleanup_record(data, item[1]), None, item[1]]]
            continue
        if key in CLEANUP_XRAY_SHA:
            name = X if key == 'XRAY_UNIT_0666' else B
            info = unit(name)
            if digest(data) != CLEANUP_XRAY_SHA[key] or info.get('FragmentPath') != paths[key]:
                continue
            try:
                cleanup_xray_identity()
            except (OSError, Refusal):
                continue
        try:
            sample = {key: item}
            args = ((key,), digest(encode(['foreign-config-v2', sample])), sample, {key: data})
            if key in planner['STOCK'] and staged is None:
                planner['stock_requirements'](*args)
                result[key] = ()  # intrinsic eligibility, not a materialized edit
                continue
            plan = planner['plan_replacement'](*args, staged={key: staged[key]} if key in planner['STOCK'] else None,
                                                allow_xray_mode=True, cleanup_at=cleanup_at)
        except planner['Refusal']:
            continue
        if plan.set_aside or len(plan.edits) != 1:
            continue
        edit, = plan.edits
        need(edit.key == key and edit.path == paths[key] and edit.before == data and list(edit.pin) == item[1], 'PREREQUISITE')
        before = cleanup_record(data, item[1])
        after = None if edit.after is None else {**before, 'data': b64(edit.after), 'mode': before['mode'] if edit.mode is None else edit.mode}
        result[key] = [[key, before, after, item[1]]]
    return result


def cleanup_view(edits):
    paths = cleanup_paths()
    return {paths[key]: after for key, _, after, _ in edits}


def foreign_no_pending():
    need(recovery_stat(VAULT + '/' + FOREIGN_PENDING) is None, 'IN_FLIGHT')


def stock_runtime_root():
    return Path('/')


def stock_runtime_command(*argv):
    status, stdout, stderr = bounded_status(argv, min(DEADLINE, time.monotonic() + 12), NATIVE_MAX_OUTPUT)
    return subprocess.CompletedProcess(argv, status, stdout.decode(), stderr.decode())


def pending_xl(info):
    if info['LoadState'] == 'not-found':
        return 'missing'
    if (info.get('UnitFileState') == 'generated' or info.get('SourcePath')
            or info.get('FragmentPath', '').startswith('/run/systemd/generator')):
        return 'generated'
    return None


def stock_runtime_observation(expected):
    runtime = globals().get('C3_STOCK_RUNTIME')
    helper = globals().get('C3_STOCK_ENSURE')
    if runtime is None or helper is None or digest(helper['UNIT']) != NATIVE_XL_SHA:
        raise Refusal(NATIVE_UNIT_REQUIRED)
    try:
        observed = runtime['observe'](stock_runtime_root(), stock_runtime_command, helper)
    except (runtime['Refusal'], OSError, ValueError):
        raise Refusal(NATIVE_UNIT_REQUIRED) from None
    need(observed['state'] == expected, NATIVE_UNIT_REQUIRED)
    return observed


def pending_native(xl, ike, state):
    # Independent live DIRECT sample must agree with the strict stock view.
    for info in (xl, ike):
        need((info['ActiveState'], info['SubState'], info.get('MainPID'), info.get('Job'),
              info.get('NeedDaemonReload'), info.get('DropInPaths')) == ('inactive', 'dead', '0', '', 'no', ''),
             NATIVE_UNIT_REQUIRED)
    need(ike['UnitFileState'] in ('enabled', 'disabled') and not ike.get('ExecCondition')
         and not ike.get('PassEnvironment') and removal_native(ike, IKE, {'units': {IKE: ike}}, installed=False),
         NATIVE_UNIT_REQUIRED)
    if state == 'generated':
        need((xl['LoadState'], xl.get('UnitFileState'), xl.get('FragmentPath'), xl.get('SourcePath')) == (
            'loaded', 'generated', '/run/systemd/generator.late/' + XL, '/etc/init.d/xl2tpd'), NATIVE_UNIT_REQUIRED)
    return stock_runtime_observation(state)


def ppp_config(observers=()):
    return entry(('# Managed by Celerity rebuild L2TP\n' + '\n'.join((*PPP_MODULES, *observers)) + '\n').encode(), mode=0o644)


def module_name(name):
    return name.replace('-', '_')


def ppp_boot_file(dependencies, installed=None, *, drop_legacy=False):
    # A same-name override may intentionally suppress a vendor module request.
    # Do not circumvent it by publishing our own file with a different name.
    def modules(path):
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) and os.readlink(path) == '/dev/null':
            return set()
        value = read(path, 65536)
        need(value is not None, PPP_CONFLICT)
        return {module_name(line.partition('#')[0].strip()) for line in raw(value).decode().splitlines()}

    try:
        selected = {}
        generation = remove_generation(PPP_PATH)
        own = read(PPP_PATH, 4096)
        need((own is None) == (generation is None) and generation == remove_generation(PPP_PATH), PPP_CONFLICT)
        need(own == installed if installed is not None else own in (None, ppp_config()), PPP_CONFLICT)
        for parent in PPP_DIRS:
            if parent.startswith('/lib/') and os.path.lexists('/lib') and stat.S_ISLNK(os.lstat('/lib').st_mode):
                need(os.readlink('/lib') in ('usr/lib', '/usr/lib'), PPP_CONFLICT)
                continue  # merged-/usr alias
            try:
                with directory(parent) as fd:
                    names = [name for name in os.listdir(fd) if name.endswith('.conf')]
            except FileNotFoundError:
                continue
            for name in names:
                path = parent + '/' + name
                if drop_legacy and path == LEGACY_MODULES:
                    continue
                if name == PPP_CONF:
                    need(path == PPP_PATH and own is not None, PPP_CONFLICT)
                elif name in {PPP_CONF[:-5] + '-' + observer + '.conf' for observer in OBSERVERS}:
                    # Never adopt or remove unreceipted files from an older attempt.
                    raise Refusal(PPP_CONFLICT)
                elif name in selected:
                    suppressed = modules(path) & dependencies
                    need(not suppressed or suppressed <= modules(selected[name]), PPP_CONFLICT)
                else:
                    selected[name] = path
        return {'record': own, 'generation': generation}
    except (OSError, UnicodeError, Refusal):
        raise Refusal(PPP_CONFLICT) from None


def ppp_policy(observers=(), *, include_ppp=True):
    try:
        with open('/proc/cmdline') as stream:
            cmdline = stream.read(65537)
        need(len(cmdline) <= 65536, PPP_REQUIRED)
        boot_args = [arg.partition('=') for arg in shlex.split(cmdline)]
        blocked = {module_name(name) for key, _, value in boot_args
                   if key in ('module_blacklist', 'modprobe.blacklist', 'rd.driver.blacklist')
                   for name in value.split(',')}
        boot_unit = 'systemd-modules-load.service'
        need(not any(key in ('systemd.mask', 'rd.systemd.mask') and value == boot_unit for key, _, value in boot_args), PPP_CONFLICT)
        try:
            loader = unit(boot_unit)
            need(loader['LoadState'] == 'loaded' and loader['UnitFileState'] == 'static'
                 and loader.get('FragmentPath') in ('/lib/systemd/system/' + boot_unit, '/usr/lib/systemd/system/' + boot_unit)
                 and not loader.get('DropInPaths') and loader.get('NeedDaemonReload') == 'no', PPP_CONFLICT)
        except (OSError, Refusal):
            raise Refusal(PPP_CONFLICT) from None
        config = command(MODPROBE, '--showconfig', quiet=True, refusal=PPP_REQUIRED)
        hooks = set()
        for line in config.decode().splitlines():
            words = line.split()
            if len(words) >= 2 and words[0] == 'blacklist':
                blocked.add(module_name(words[1]))
            if len(words) >= 2 and words[0] == 'install':
                hooks.add(module_name(words[1]))
        ppp = PPP_MODULES if include_ppp else ()
        deps, builtin, listings, observer_policy = set(ppp), set(), [], {}
        for name in (*ppp, *observers):
            observer = name in OBSERVERS
            need(name not in blocked, MODULE_BLACKLISTED if observer else PPP_REQUIRED)
            need(name not in hooks, OBSERVATION_REQUIRED if observer else PPP_REQUIRED)
            # Read-only resolution, including soft dependencies; no install hooks run.
            # For observers resolve even blacklisted dependencies so we can reject
            # them explicitly; only the dry-run is unfiltered. Real loads use -b.
            bad = OBSERVATION_REQUIRED if observer else PPP_REQUIRED
            flags = () if observer else ('--use-blacklist',)
            listing = command(MODPROBE, '--show-depends', *flags, '--', name, quiet=True, refusal=bad).decode()
            found = set()
            for fields in map(str.split, listing.splitlines()):
                if len(fields) == 2 and fields[0] == 'builtin':
                    found.add(module_name(fields[1]))
                    if not observer:
                        builtin.add(module_name(fields[1]))
                    continue
                need(len(fields) >= 2 and fields[0] == 'insmod', bad)
                match = re.fullmatch(r'/(?:usr/)?lib/modules/[^\s]+/([A-Za-z0-9_-]+)\.ko(?:\.(?:xz|zst|gz))?', fields[1])
                need(match, bad)
                found.add(module_name(cast(re.Match, match)[1]))
            need(name in found, bad)
            need(not (found & blocked), MODULE_BLACKLISTED if observer else PPP_REQUIRED)
            need(not (found & hooks), bad)
            deps.update(found)
            if observer:
                observer_policy[name] = digest(encode(listing))
            else:
                listings.append(listing)
        return deps, sorted(builtin), digest(encode(listings)), observer_policy
    except (OSError, ValueError):
        raise Refusal(PPP_REQUIRED) from None


def live_modules(refusal):
    with open('/proc/modules') as stream:
        data = stream.read(262145)
    need(len(data) <= 262144, refusal)
    return {fields[0] for line in data.splitlines() if len(fields := line.split()) >= 6 and fields[4] == 'Live'}


def ppp_loaded(builtin):
    return dict(ppp_generic=ppp_registered(), l2tp_ppp='l2tp_ppp' in live_modules(PPP_REQUIRED) or 'l2tp_ppp' in builtin)


def missing_network_observers():
    # Even read-only netlink requests can autoload protocol/subsystem modules.
    # Insist on available providers before ss, nft or ip xfrm, without loading
    # them as a side effect of preparing a PPP/install plan.
    try:
        active = live_modules(OBSERVATION_REQUIRED)
        missing = []
        for name in OBSERVERS:
            if name not in active:
                proof = command(MODPROBE, '--show-depends', '--', name,
                                quiet=True, refusal=OBSERVATION_REQUIRED)
                if b'builtin ' + name.encode() not in proof.splitlines():
                    missing.append(name)
        return missing
    except (OSError, ValueError):
        raise Refusal(OBSERVATION_REQUIRED) from None


def require_network_observers():
    need(not missing_network_observers(), OBSERVATION_REQUIRED)


def check_package_observer_policy():
    # Package preparation can precede the normal Install baseline. Reject a
    # known observer blacklist before publishing even the package intent.
    # PPP itself may not be ready until the runtime packages are installed.
    try:
        ppp_host_scope()
    except (OSError, ValueError):
        raise Refusal(PPP_REQUIRED) from None
    missing = missing_network_observers()
    if missing:
        ppp_policy(missing, include_ppp=False)


def ppp_host_scope():
    detect = '/usr/bin/systemd-detect-virt'
    # A full VM owns its kernel; a shared-kernel container does not. Require
    # the detector's documented negative result, not an arbitrary failed probe.
    need(command(detect, '--container', quiet=True, negative=b'none\n', refusal=PPP_REQUIRED) == b'none\n', PPP_REQUIRED)
    need(command(detect, '--chroot', quiet=True, negative=b'', refusal=PPP_REQUIRED) == b'', PPP_REQUIRED)
    # Linux reserves PROC_USER_INIT_INO for the initial user namespace. A
    # child namespace with a full UID map must not pass this check.
    need(os.readlink('/proc/self/ns/user') == 'user:[4026531837]', PPP_REQUIRED)
    with open('/proc/self/status') as stream:
        caps = re.search(r'^CapEff:\s*([0-9a-f]+)$', stream.read(65536), re.M)
    need(caps is not None and int(caps[1], 16) & (1 << 16), PPP_REQUIRED)  # CAP_SYS_MODULE
    with open('/proc/sys/kernel/modules_disabled') as stream:
        need(stream.read(8).strip() == '0', PPP_REQUIRED)


def observe_ppp_preparation(required_observers=(), *, installed=None, fresh=True, drop_legacy=False, precheck=False):
    """Observe boot policy separately from the modules needing a live load."""
    try:
        if precheck:
            ppp_host_scope()  # Fresh Install always persists boot policy.
        absent = missing_network_observers()
        # Fresh Install requests every provider at next boot, including the
        # modules already loaded or built in on this boot. Check their policy
        # and boot-file conflicts even if they need no live load.
        canonical = fresh and installed is None
        observers = OBSERVERS if canonical else tuple(name for name in OBSERVERS
                                                       if name in absent or name in required_observers)
        deps, builtin, policy, observer_policy = ppp_policy(observers)
        loaded, device = ppp_loaded(builtin), ppp_device()
        need(device is not False and (not loaded['ppp_generic'] or device is True), PPP_REQUIRED)
        if precheck:
            # Only the known legacy leaf can be removed. Prepare rechecks the
            # boot-file policy against the exact confirmed projection.
            ppp_boot_file(deps, drop_legacy=True)
            return
        before = ppp_boot_file(deps, installed, **({'drop_legacy': True} if drop_legacy else {}))
        persist = installed is None and (canonical or before['record'] is None or bool(absent))
        missing = [name for name in PPP_MODULES if not loaded[name]] + absent
        if missing or persist:
            ppp_host_scope()
        plan: dict[str, Any] = dict(missing=missing, persist=persist, builtin=builtin, policy=policy)
        if observers:
            plan['observers'] = observer_policy
        if persist:
            plan['bootFile'] = {'before': before, 'after': ppp_config(observers)}
        return plan
    except (OSError, ValueError):
        raise Refusal(PPP_REQUIRED) from None


def apply_ppp_preparation(expected):
    """Reserved Install only, under the same host flock and durable applying receipt."""
    need(observe_ppp_preparation() == expected, 'BASELINE_CHANGED')
    observers = expected.get('observers', {})

    def loaded(name):
        if name in OBSERVERS:
            return name in live_modules(PPP_FAILED)
        return ppp_loaded(expected['builtin'])[name]

    for name in expected['missing']:
        if not loaded(name):
            # Use ordinary kmod policy, never --ignore-install/force/insmod.
            command(MODPROBE, '--use-blacklist', '--', name, wait=10, quiet=True, refusal=PPP_FAILED)
            need(loaded(name), PPP_FAILED)
    if 'ppp_generic' in expected['missing']:
        # Give the kernel/devtmpfs/udev time to expose the node; never mknod.
        ready_by = min(DEADLINE, time.monotonic() + 2)
        while ppp_device() is None and time.monotonic() < ready_by:
            time.sleep(0.05)
    need(all(ppp_loaded(expected['builtin']).values()) and ppp_device() is True, PPP_FAILED)
    planned = expected.get('bootFile')
    generation = None
    if planned:
        deps, _, policy, observer_policy = ppp_policy(observers)
        previous = planned['before']
        need(policy == expected['policy'] and observer_policy == observers and ppp_boot_file(deps) == previous, PPP_CONFLICT)
        try:
            mkdir(PPP_DIRS[0], 0o755, exist_ok=True)
            generation = write(PPP_PATH, previous['record'], planned['after'], generation=previous['generation'])
        except (FileExistsError, PermissionError):
            raise Refusal(PPP_CONFLICT) from None
    ready = observe_ppp_preparation(observers, installed=planned['after'] if planned else None)
    need(not ready['missing'] and not ready['persist'] and ready['policy'] == expected['policy']
         and ready.get('observers', {}) == observers, PPP_FAILED)
    return generation


def module_boot_owner(backup, *, unwritten=False):
    """The private manifest binds one canonical file to this install generation."""
    plan = backup['before'].get('pppModules', {})
    if 'bootFile' not in plan:
        # Legacy PPP-only receipts never claimed ownership of persistence.
        need('modulePersistence' not in backup and not plan.get('observers'), 'ROLLBACK_DRIFT')
        return None
    images, generation = plan['bootFile'], backup.get('modulePersistence')
    if unwritten and 'modulePersistence' not in backup:
        previous = images['before']
        need(read(PPP_PATH, 4096) == previous['record'] and remove_generation(PPP_PATH) == previous['generation'],
             'ROLLBACK_DRIFT')
        return None
    checked = set(plan.get('observers', {}))
    legacy = set(plan['missing']) & set(OBSERVERS)
    # Older receipts checked and persisted only the absent observers. All
    # other subset combinations are drift, not alternate file ownership.
    need(checked in (set(OBSERVERS), legacy), 'ROLLBACK_DRIFT')
    names = [name for name in OBSERVERS if name in checked]
    need(plan['persist'] is True and set(images) == {'before', 'after'}
         and set(images['before']) == {'record', 'generation'} and images['after'] == ppp_config(names)
         and type(generation) is list and len(generation) == 3 and all(type(v) is int and v > 0 for v in generation),
         'ROLLBACK_DRIFT')
    previous = images['before']['record']
    need(previous is None or (previous == ppp_config() and bool(names)), 'ROLLBACK_DRIFT')
    return previous, images['after'], generation


def check_module_boot_owner(owner):
    if owner is not None:
        _, after, generation = owner
        need(read(PPP_PATH, 4096) == after and remove_generation(PPP_PATH) == generation, 'ROLLBACK_DRIFT')


def release_module_boot(owner):
    if owner is not None:
        before, after, generation = owner
        # The caller holds the DIRECT flock; do not adopt byte-identical replacements.
        write(PPP_PATH, after, before, generation=generation)


def sock_rows():
    rows = []
    for line in command('/usr/bin/ss', '-H', '-lntup').decode().splitlines():
        cols = line.split(maxsplit=6)
        need(len(cols) >= 6 and cols[0] in ('tcp', 'udp') and ':' in cols[4], 'RUNTIME_UNPROVED')
        address, port = cols[4].rsplit(':', 1)
        need(port.isdecimal(), 'RUNTIME_UNPROVED')
        rows.append((cols[0], address, int(port), sorted(set(re.findall(r'\bpid=(\d+),', cols[6] if len(cols) == 7 else '')))))
    return rows


def owned_sockets(rows, pid):
    return sorted([p, a, n] for p, a, n, owners in rows if pid in owners and pid != '0')


def verify_socks_handoff(rows, port, handoff_pid, *, active=True):
    bad = 'RUNTIME_UNPROVED'
    need(type(port) is int and 1 <= port <= 65535 and type(handoff_pid) is str
         and re.fullmatch(r'[1-9][0-9]*', handoff_pid), bad)
    loopback = '127.0.0.1'
    protocols = []
    for proto, address, number, owners in rows:
        if number == port:
            need(proto in ('tcp', 'udp') and address == loopback and owners == [handoff_pid], bad)
            protocols.append(proto)
    layout = sorted(protocols)
    need(layout in (['tcp'], ['tcp', 'udp']), bad)
    if not active or layout == ['tcp', 'udp']:
        return  # An exact fixed bind is the legacy proof. Invalid rows are not absence.

    # Newer cores allocate UDP per association. Use the observed layout, not
    # panel version metadata. One deadline covers connect, writes and every
    # partial read. Never send a UDP datagram or connect to the returned BND.
    until = min(DEADLINE, time.monotonic() + 1)

    def remaining():
        seconds = until - time.monotonic()
        need(seconds > 0, bad)
        return seconds

    def receive(sock, size):
        data = bytearray()
        while len(data) < size:
            sock.settimeout(remaining())
            chunk = sock.recv(size - len(data))
            need(bool(chunk), bad)
            data.extend(chunk)
        return bytes(data)

    try:
        remaining()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(remaining())
            sock.connect((loopback, port))
            sock.settimeout(remaining())
            sock.sendall(b'\x05\x01\x00')  # SOCKS5, offer only no authentication.
            need(receive(sock, 2) == b'\x05\x00', bad)
            sock.settimeout(remaining())
            sock.sendall(b'\x05\x03\x00\x01' + bytes(6))  # UDP ASSOCIATE, no client UDP endpoint yet.
            need(receive(sock, 4) == b'\x05\x00\x00\x01', bad)
            bound = receive(sock, 6)
            need(bound[:4] == b'\x7f\x00\x00\x01' and bound[4:] != b'\x00\x00', bad)
        remaining()
    except OSError:
        raise Refusal(bad) from None


def working(info):
    return (info.get('LoadState') == 'loaded' and info.get('ActiveState') == 'active'
            and info.get('NeedDaemonReload') == 'no' and info.get('MainPID', '0').isdigit()
            and int(info.get('MainPID', '0')) > 0 and bool(info.get('InvocationID', '').strip('0')))


def no_hooks(info):
    return all(not info.get(k) for k in ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost',
                                         'RootDirectory', 'RootImage')) and info.get('PrivateNetwork') == 'no'


def xray_dropin(info, path, argv):
    loaded = info.get('DropInPaths')
    bad = XRAY_DROPIN_UNSUPPORTED
    if path != MAIN:
        need(not loaded, bad)  # No exception for the separate xray-bridge service.
        return
    folder = SYSTEM + '/' + X + '.d'
    try:
        with directory(folder) as fd:
            names = sorted(n for n in os.listdir(fd) if n.endswith('.conf'))
    except FileNotFoundError:
        names = []
    except (OSError, Refusal):
        raise Refusal(bad) from None
    # Check even an empty manager list: a pending or foreign file is not absence.
    need(isinstance(loaded, str) and all(n == XRAY_DROPIN_NAME or n in XRAY_SETUP_DROPINS for n in names)
         and sorted(loaded.split(' ') if loaded else []) == [folder + '/' + n for n in names], bad)
    if not names:
        return
    need(info.get('LoadState') == 'loaded' and info.get('NeedDaemonReload') == 'no', bad)
    # An exact systemctl command record, not a prefix or the first of several.
    prefix = '{ path=' + XRAY + ' ; argv[]=' + ' '.join(argv) + ' ; '
    need(re.fullmatch(re.escape(prefix) + r'ignore_errors=no ; start_time=\[[^\[\]{};\r\n]+\] ; '
                      r'stop_time=\[[^\[\]{};\r\n]+\] ; pid=[0-9]+ ; code=[^ ;{}\r\n]+ ; status=[^ ;{}\r\n]+ \}',
                      info.get('ExecStart', '')) is not None and no_hooks(info)
         and not any(info.get(k) for k in ('ExecCondition', 'ExecReload', 'Environment', 'EnvironmentFiles',
                                           'PassEnvironment', 'UnsetEnvironment'))
         and info.get('WorkingDirectory') in ('', '/') and info.get('KillMode') == 'control-group', bad)
    try:
        for name in names:
            record = read(folder + '/' + name, 16384)
            need(record is not None and record['mode'] == 0o644 and record['gid'] == 0, bad)
            data = raw(record)
            if name != XRAY_DROPIN_NAME:
                need(data == XRAY_SETUP_DROPINS[name], bad)
                continue
            # Only the existing XTLS file permits inert comments and CRLF.
            lines = [line.removesuffix(b'\r').strip(b' \t') for line in data.split(b'\n')]
            need(all(not any(c in line for c in (b'\0', b'\r')) and not line.endswith(b'\\') for line in lines)
                 and [line for line in lines if line and not line.startswith((b'#', b';'))]
                     == [b'[Service]', b'ExecStart=', b'ExecStart=' + ' '.join(argv).encode()], bad)
    except (OSError, Refusal):
        raise Refusal(bad) from None


def same_xray_dropin(info, original):
    # This operation never owns, writes or changes the MAIN drop-in selection.
    need((info.get('DropInPaths') or '') == (original.get('DropInPaths') or ''), XRAY_DROPIN_UNSUPPORTED)


def retained_xray_dropin(info, original):
    same_xray_dropin(info, original)
    xray_dropin(info, MAIN, (XRAY, 'run', '-config', MAIN))


def xray_argv(info, path=MAIN):
    argv = [XRAY, 'run', '-config', path]
    xray_dropin(info, path, argv)
    prefix = '{ path=' + XRAY + ' ; argv[]=' + ' '.join(argv) + ' ;'
    need(working(info) and info.get('ExecStart', '').startswith(prefix) and no_hooks(info)
         and not info.get('Environment') and not info.get('EnvironmentFiles')
         and info.get('WorkingDirectory') in ('', '/') and info.get('KillMode') == 'control-group', 'PREREQUISITE')
    pid = info['MainPID']
    with open('/proc/' + pid + '/cmdline', 'rb') as handle:
        need(handle.read(4096) == b'\0'.join(arg.encode() for arg in argv) + b'\0', 'RUNTIME_UNPROVED')
    need(os.path.realpath('/proc/' + pid + '/exe') == XRAY, 'RUNTIME_UNPROVED')
    return pid


def transit_inbounds(data: dict[str, Any], transit: Any) -> dict[str, int]:
    # The applied graph under the panel's Apply lock supplies these descriptors.
    # HandlerService lists the email index, not generated anonymous accounts.
    need(type(transit) is list and len(transit) <= 32, 'PROFILE_USERS')
    owned: dict[str, int] = {}
    for edge in transit:
        need(type(edge) is dict and set(edge) == {'linkId', 'mode', 'port', 'uuid'}
             and type(edge['linkId']) is str and re.fullmatch(r'[a-f0-9]{24}', edge['linkId'])
             and edge['mode'] in ('forward', 'reverse') and type(edge['port']) is int and 1 <= edge['port'] <= 65535
             and type(edge['uuid']) is str and re.fullmatch(r'\S{1,128}', edge['uuid']), 'PROFILE_USERS')
        suffix = edge['linkId'][-8:]
        reverse = edge['mode'] == 'reverse'
        tag = ('rebuild-rp-conn-' if reverse else 'fwd-hop-') + suffix
        client = {'id': edge['uuid']}
        if reverse:
            client['reverse'] = {'tag': 'rebuild-rp-egress-' + suffix}
        matching = [i for i in data['inbounds'] if i.get('tag') == tag]
        need(tag not in owned and len(matching) == 1, 'PROFILE_USERS')
        row = matching[0]
        settings, stream = row.get('settings', {}), row.get('streamSettings', {})
        clients = settings.get('clients') if type(settings) is dict else None
        if (reverse and type(clients) is list and len(clients) == 1 and type(clients[0]) is dict
                and 'email' in clients[0] and type(stream) is dict and stream.get('network') == 'tcp'
                and stream.get('security') == 'reality' and settings.get('decryption') == 'none'
                and re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', edge['uuid'].lower())):
            digest = hashlib.sha256(edge['uuid'].lower().encode('ascii')).hexdigest()
            client['email'] = 'rproof-' + edge['linkId'] + '-' + digest + '@rebuild.invalid'
        need(row.get('protocol') == 'vless' and row.get('listen') == '0.0.0.0'
             and type(row.get('port')) is int and row['port'] == edge['port']
             and clients == [client], 'PROFILE_USERS')
        owned[tag] = int(row['port'])
    return owned


def xray_users(config, info, rows, transit=None):
    pid = xray_argv(info)
    data = unique_profile(config) if transit else json.loads(raw(config))
    ib = data['inbounds']
    api = [row for row in ib if row.get('tag') == 'API_INBOUND']
    targets = [row for row in ib if row.get('protocol') == 'vless']
    need(all(row.get('protocol') in ('vless', 'dokodemo-door', 'socks') for row in ib)
         and 1 <= len(targets) <= 32 and len(api) == 1, 'PROFILE_USERS')
    port = api[0].get('port')
    need(api[0].get('listen') == '127.0.0.1' and api[0].get('protocol') == 'dokodemo-door'
         and type(port) is int and 1 <= port <= 65535
         and data.get('api', {}).get('tag') == 'API' and 'HandlerService' in data['api'].get('services', [])
         and any(p == 'tcp' and a == '127.0.0.1' and n == port and owners == [pid] for p, a, n, owners in rows),
         'PROFILE_USERS')
    owned = transit_inbounds(data, transit) if transit is not None else {}
    for row in targets:
        tag = row.get('tag', '')
        clients = row.get('settings', {}).get('clients')
        need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', tag) and isinstance(clients, list), 'PROFILE_USERS')
        if tag in owned:
            listeners = [(address, owners) for p, address, n, owners in rows if p == 'tcp' and n == owned[tag]]
            # ss prints the IPv4 wildcard as 0.0.0.0 or * on a dual-stack socket.
            need(any(address in ('0.0.0.0', '*') for address, _ in listeners)
                 and all(owners == [pid] for _, owners in listeners), 'RUNTIME_UNPROVED')
            if not clients[0].get('email'):
                continue  # Legacy anonymous transit is not listed by HandlerService.
            # A labeled native reverse account is listed: verify it just like
            # a subscriber without giving up the transit socket/receipt checks.
        # Subscriber inventory still requires the full HandlerService list,
        # not a count. Refuse dynamic or unrecognised account shapes.
        result = json.loads(command(XRAY, 'api', 'inbounduser', '--server=127.0.0.1:' + str(port), '-tag=' + tag,
                                    wait=4, quiet=True))
        # Protobuf JSON can omit an empty repeated field. A nonempty expected
        # inventory still has to match the complete runtime inventory below.
        need(type(result) is dict and set(result) <= {'users'} and type(result.get('users', [])) is list, 'PROFILE_USERS')
        actual = []
        for u in result.get('users', []):
            account = u.get('account', {})
            need(not (set(u) - {'email', 'level', 'account'}) and
                 not (set(account) - {'id', 'flow', '_TypedMessage_', 'reverse'}) and
                 account.get('_TypedMessage_') == 'xray.proxy.vless.Account', 'PROFILE_USERS')
            actual.append(encode([u.get('email', ''), u.get('level', 0), account['id'], account.get('flow', ''), account.get('reverse')]))
        expected = []
        for u in clients:
            need(not (set(u) - {'email', 'level', 'id', 'flow', 'reverse'}), 'PROFILE_USERS')
            expected.append(encode([u.get('email', ''), u.get('level', 0), u['id'], u.get('flow', ''), u.get('reverse')]))
        need(sorted(actual) == sorted(expected), 'PROFILE_USERS')
    return owned_sockets(rows, pid)


def routing(arg):
    need(isinstance(arg, dict) and set(arg) == {'clientCidr', 'tproxyPort', 'fwmark', 'routeTable'}, 'CANDIDATE_INVALID')
    net = ipaddress.IPv4Network(arg['clientCidr'])
    need(str(net) == arg['clientCidr'] and 16 <= net.prefixlen <= 30 and
         any(net.subnet_of(ipaddress.IPv4Network(n)) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')),
         'CANDIDATE_INVALID')
    for k, lo, hi in [('tproxyPort', 1024, 65535), ('fwmark', 1, 0x7fffffff), ('routeTable', 1, 0x7fffffff)]:
        need(type(arg[k]) is int and lo <= arg[k] <= hi, 'CANDIDATE_INVALID')
    need(arg['tproxyPort'] not in (1701, 4500) and arg['routeTable'] not in (253, 254, 255), 'CANDIDATE_INVALID')
    return arg


def nft_tables(*, strict=False):
    output = command('/usr/sbin/nft', '-j', 'list', 'tables', **({'quiet': True} if strict else {}))
    rows = json.loads(output)['nftables']
    if strict:
        need(type(rows) is list and all(type(row) is dict and (
            set(row) == {'metainfo'} and type(row['metainfo']) is dict or
            set(row) == {'table'} and type(row['table']) is dict and
            all(type(row['table'].get(key)) is str and row['table'][key] for key in ('family', 'name'))
        ) for row in rows), 'NETWORK_CONFLICT')
    return [row['table'] for row in rows if 'table' in row]


def nft_projection(token):
    tables = [row for row in nft_tables() if row.get('family') == 'inet' and row.get('name') == TABLE]
    if not tables:
        return None
    rows = json.loads(command('/usr/sbin/nft', '-j', '-s', 'list', 'table', 'inet', TABLE))['nftables']
    own = [row['table'] for row in rows if 'table' in row]
    need(len(own) == 1 and own[0].get('comment') == token and own[0].get('name') == TABLE, 'ROLLBACK_DRIFT')
    return digest(encode(rows))


def number(value):
    return int(value, 0) if isinstance(value, str) and value.isdecimal() is False else int(value)


def network_projection(d, token, removing=False, *, inspect_nft=True, exact_flags=False, pinned=False):
    if pinned:
        return pinned_network_projection(d, token, removing)
    rules = ip('rule', 'show')
    routes = ip('route', 'show', 'table', 'all')
    # The narrow first-install profile supports only the stock all-source rules
    # plus this exact addition. No flushes, masking existing marks, or adoption.
    own_rules = [r for r in rules if r.get('priority') == PRIORITY]
    others = [r for r in rules if r.get('priority') != PRIORITY]
    names = {0: ('local', '255', 255), 32766: ('main', '254', 254), 32767: ('default', '253', 253)}
    table = d['routeTable']
    if removing:
        need(all(str(r.get('table')) != str(table) for r in others), 'NETWORK_CONFLICT')
    else:
        need(len(others) == 3 and all(type(r.get('priority')) is int for r in others)
             and {r['priority'] for r in others} == set(names) and all(
            r.get('src') == 'all' and r.get('table') in names[r['priority']]
            and not (set(r) - {'priority', 'src', 'table', 'protocol'}) for r in others), 'NETWORK_CONFLICT')
    own_routes = [r for r in routes if str(r.get('table')) == str(table)]
    # iproute2's ip/iprule.c prints IPv4 source addresses and prefix lengths
    # separately in JSON. Match the canonical candidate exactly in either
    # encoding; do not accept a hybrid or infer a missing prefix length.
    cidr = d['clientCidr']
    address, length = cidr.split('/')
    need(len(own_rules) <= 1 and all(
         type(r['priority']) is int and str(r.get('table')) == str(table)
         and ((r.get('src') == cidr and 'srclen' not in r)
              or (r.get('src') == address and type(r.get('srclen')) is int and r['srclen'] == int(length)))
         and type(r.get('fwmark')) in (int, str) and number(r['fwmark']) == d['fwmark']
         and not (set(r) - {'priority', 'src', 'srclen', 'table', 'fwmark', 'protocol'}) for r in own_rules),
         'NETWORK_CONFLICT')
    need(len(own_routes) <= 1 and all(r.get('type') in ('local', 2, '2') and r.get('dst') in ('default', '0.0.0.0/0') and r.get('dev') == 'lo'
         and r.get('scope') in ('host', 254, '254') and not (set(r) - {'type', 'dst', 'dev', 'table', 'scope', 'flags', 'protocol'})
         and (not exact_flags or r.get('flags', []) == [])
         for r in own_routes), 'NETWORK_CONFLICT')
    return dict(rule=bool(own_rules), route=bool(own_routes), nft=nft_projection(token) if inspect_nft else None)


def ppp_empty():
    return not any(line.split(':', 1)[0].strip().startswith('ppp')
                   for line in open('/proc/net/dev').read(65536).splitlines()[2:])


def vpn_empty(allow_socket_policies=False):
    # `nokeys` is essential even though the result is discarded on a nonempty
    # host. Text mode returns empty stdout for an empty dump, not JSON `[]`.
    options = ('nosock',) if allow_socket_policies else ()
    return (ppp_empty() and not command('/usr/sbin/ip', 'xfrm', 'policy', 'list', *options).strip()
            and not command('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys').strip())


def is_stock_lns(record):
    data = raw(record)
    if not uncomment(data):
        return True
    info = command('/usr/bin/dpkg-query', '-W', '-f=${Conffiles}', 'xl2tpd')
    match = re.search(rb'^ /etc/xl2tpd/xl2tpd\.conf ([a-f0-9]{32})\s*$', info, re.M)
    return match is not None and hashlib.md5(data, usedforsecurity=False).hexdigest().encode() == match[1]


def uncomment(data):
    return [line.strip() for line in data.split(b'\n') if line.strip() and not line.lstrip().startswith((b'#', b';'))]


def native_vpn(info, name):
    # Refuse generated SysV wrappers and unreviewed local native units.
    paths = ['/usr/lib/systemd/system/' + name, '/lib/systemd/system/' + name]
    fragment = info.get('FragmentPath')
    if name == XL and fragment == SYSTEM + '/' + XL:
        config = read(fragment, 4096)
        if config is not None and config['mode'] == 0o644 and config['gid'] == 0 and digest(raw(config)) == NATIVE_XL_SHA:
            paths.append(fragment)
    expected = [('/usr/sbin/xl2tpd', '-D'), ('/usr/bin/xl2tpd', '-D')] if name == XL else [('/usr/sbin/ipsec', 'start', '--nofork')]
    return (info.get('LoadState') == 'loaded' and fragment in paths
            and any(info.get('ExecStart', '').startswith('{ path=' + argv[0] + ' ; argv[]=' + ' '.join(argv) + ' ;')
                    for argv in expected)
            and info.get('NeedDaemonReload') == 'no' and info.get('PrivateNetwork') == 'no'
            and info.get('KillMode') == 'control-group' and info.get('User') in ('', 'root')
            and not any(info.get(k) for k in ('Environment', 'EnvironmentFiles', 'RootDirectory', 'RootImage', 'ExecStartPre', 'ExecStartPost')))


def xl_defaults_admitted(record, info):
    # An absent file cannot supply defaults. Keep the existing minimal layout.
    if record is None:
        return True
    metadata = command('/usr/bin/dpkg-query', '-W', r'-f=${Version}\n${Architecture}\n${Conffiles}', 'xl2tpd', quiet=True)
    version, arch, *rows = metadata.split(b'\n')
    need(version and arch, 'PREREQUISITE')
    conffiles = [fields[1:] for row in rows if (fields := row.split()) and fields[0] == XL_DEFAULT.encode()]
    data = raw(record)
    if (version, arch) != (b'1.3.18-1+b1', b'amd64'):
        # An inert local file is not the same as a package conffile edited to be inert.
        return not conffiles and not uncomment(data)
    # The dpkg MD5 is only a conffile record check. The authenticated package's
    # full SHA256 pins every byte (including both assignments and comments).
    # observe() has already checked native_vpn, including the helper unit's
    # on-disk digest and metadata. Only that exact unit can ignore these SysV defaults.
    return (conffiles == [[STOCK_XL_DEFAULT_MD5]] and record['mode'] == 0o644 and record['gid'] == 0
            and digest(data) == STOCK_XL_DEFAULT_SHA and info['FragmentPath'] == SYSTEM + '/' + XL
            and no_hooks(info) and info.get('Group', '') in ('', 'root')
            and not any(info.get(k) for k in ('SourcePath', 'ExecCondition', 'ExecReload', 'PassEnvironment', 'UnsetEnvironment'))
            and re.fullmatch(r'\{ path=/usr/sbin/xl2tpd ; argv\[\]=/usr/sbin/xl2tpd -D ;[^{}]*\}', info.get('ExecStart', '')) is not None)


def directory_absent(path):
    parent, name = os.path.split(path)
    with directory(parent) as fd:
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
            return False
        except FileNotFoundError:
            return True


def boot_link_at(fd, name):
    def identity(st):
        need(stat.S_ISLNK(st.st_mode) and st.st_uid == 0, 'ROLLBACK_DRIFT')
        return [st.st_dev, st.st_ino, st.st_ctime_ns]

    try:
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    pin = identity(st)
    target = os.readlink(name, dir_fd=fd)
    need(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == pin, 'ROLLBACK_DRIFT')
    return [target, *pin]


def boot_link():
    parent, name = os.path.split(XL_BOOT)
    with directory(parent) as fd:
        return boot_link_at(fd, name)


def enroll_boot(target, expected=None):
    parent, name = os.path.split(XL_BOOT)
    with directory(parent) as fd:
        if expected is None:
            os.symlink(target, name, dir_fd=fd)  # no replacement or broad systemctl disable
        else:
            # Verify and unlink relative to the same trusted directory FD.
            # As with the file writes, other administrative writers must be excluded.
            need(expected[0] == target and boot_link_at(fd, name) == expected, 'ROLLBACK_DRIFT')
            os.unlink(name, dir_fd=fd)
        os.fsync(fd)


def ike_include_matches(starter, expected, *, check_tree=False, removed=False):
    if check_tree or STOCK_IKE_INCLUDE in uncomment(raw(starter)):
        # A wildcard must never enroll or reload an unmanaged connection.
        with directory('/etc/ipsec.d') as fd:
            return sorted(name for name in os.listdir(fd) if not name.startswith('.') and name.endswith('.conf')
                          and not (removed and name == os.path.basename(NAMES['ike']))) == expected
    return True


def swan_inputs(present, bad, *, removed=False):
    # The reviewed bytes close both stock globs. Do not validate just individual
    # setting names: alternate includes, section references and other settings
    # could still bypass the managed routing configuration.
    profile = os.path.basename(SWAN_PROFILE)
    rows = {}
    try:
        with directory(SWAN_DIR) as fd:
            top = set(os.listdir(fd))
        if removed:
            top.discard(profile)
        need('charon' in top and (profile in top) == present, bad)
        top -= {'charon', profile}
        plugins = SWAN_DIR + '/charon'
        with directory(plugins) as fd:
            names = os.listdir(fd)
        need(len(top) + len(names) <= 50 and all(n.endswith('.conf') for n in (*top, *names)), bad)
        paths = [SWAN_CONF, *(SWAN_DIR + '/' + n for n in top), *(plugins + '/' + n for n in names)]
        for path in paths:
            record = read(path, 262144)
            if record is None or record.get('uid', 0) != 0:
                raise Refusal(bad)
            rows[path.removeprefix('/etc/')] = [record['mode'], record['gid'], digest(raw(record))]
    except (OSError, Refusal):
        raise Refusal(bad) from None

    base = rows.copy()
    for leaves, expected in STOCK_SWAN_ADDONS:
        keys = [SWAN_DIR.removeprefix('/etc/') + '/' + name for name in leaves.split()]
        addon = {key: base.pop(key) for key in keys if key in base}
        need(not addon or (len(addon) == len(keys) and digest(encode(addon)) == expected), bad)
    need(digest(encode(base)) == STOCK_SWAN_SHA, bad)
    # Pin the actual complete tree for phase comparisons, not the base projection.
    return digest(encode(rows))


def swan_rule_dumps() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rules4 = ip('rule', 'show')
    rules6 = json.loads(command('/usr/sbin/ip', '-j', '-N', '-6', 'rule', 'show'))
    need(type(rules4) is list and type(rules6) is list and all(
        isinstance(row, dict) for row in (*rules4, *rules6)), 'NETWORK_CONFLICT')
    return cast(list[dict[str, Any]], rules4), cast(list[dict[str, Any]], rules6)


def no_swan_rule():
    # Keep the existing guard for owned startup, verification and teardown.
    need(not any(row.get('priority') == 220 and str(row.get('table')) == '220'
                 for rules in swan_rule_dumps() for row in rules), 'NETWORK_CONFLICT')


def swan_default_environment(bad):
    # Environment/PassEnvironment on the unit alone do not cover the manager's
    # global service environment. Never expose the other variable values.
    env = command('/usr/bin/systemctl', '--no-pager', 'show-environment', quiet=True)
    need(not any(line.startswith(b'STRONGSWAN_CONF=') for line in env.splitlines()), bad)


def idle_ike(info, rows):
    sockets = [(p, a, n, owners) for p, a, n, owners in rows if n in (500, 4500)]
    if not working(info) or {n for _, _, n, _ in sockets} != {500, 4500} or not all(
        p == 'udp' and owners and all(in_cgroup(pid, info) for pid in owners) for p, _, _, owners in sockets
    ):
        raise Refusal('PREREQUISITE')
    status = command('/usr/sbin/ipsec', 'statusall')
    need(re.search(rb'^Connections:[ \t]*\nSecurity Associations \(0 up, 0 connecting\):\s+none\s*\Z', status, re.M), 'PREREQUISITE')
    return sorted([p, a, n] for p, a, n, _ in sockets)


def fresh_ike_guard(info, *, inspect_runtime=True):
    # Diagnose before the generic IPv4 projector (and before rejecting loaded
    # connection files). Even an exact lookalike predates our owned invocation.
    # Charon's stop may delete an indistinguishable foreign rule. Neither the
    # shape nor a native, idle socket owner gives us permission to stop it.
    matches = [[row for row in rules if row.get('priority') in (220, '220') or row.get('table') in (220, '220')]
               for rules in swan_rule_dumps()]
    active = info['ActiveState'] == 'active'
    if any(matches):
        need(active and all(len(rows) <= 1 and all(
            set(row) == {'priority', 'src', 'table'} and type(row['priority']) is int and row['priority'] == 220
            and row['src'] == 'all' and type(row['table']) in (str, int) and row['table'] in ('220', 220)
            for row in rows) for rows in matches), 'RULE_220_CONFLICT')
        if (inspect_runtime and working(info) and info['SubState'] == 'running' and info['UnitFileState'] in ('enabled', 'disabled')
                and not any(info.get(k) for k in ('DropInPaths', 'PassEnvironment', 'ExecCondition', 'SourcePath'))
                and removal_native(info, IKE, {'units': {IKE: info}}, installed=False)):
            try:
                idle_ike(info, sock_rows())
                idle = vpn_empty(allow_socket_policies=True)
            except Refusal as error:
                if str(error) == 'IN_FLIGHT':
                    raise
                idle = False
            except OSError:
                idle = False
            if idle:
                raise Refusal('IKE_ACTIVE_RULE_220')
    need(not active, 'IKE_ACTIVE_UNMANAGED')


def boot():
    return open('/proc/sys/kernel/random/boot_id').read(64).strip()


INSTALL_UNIT_FIELDS = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'InvocationID',
                       'FragmentPath', 'DropInPaths')
XRAY_ACCOUNT_FIELDS = ('User', 'Group')


def install_unit_pins(units):
    # ExecStart includes runtime timestamps. Record only the stable projection
    # and the original invocation/PID needed by same-boot rollback.
    pins = {name: {key: units[name].get(key) for key in INSTALL_UNIT_FIELDS} for name in UNITS}
    for name in (X, B):
        info = units[name]
        # An absent BRIDGE has no account to pin; Apply can create it later.
        if name == X or info['LoadState'] != 'not-found':
            need(all(type(info.get(k)) is str for k in XRAY_ACCOUNT_FIELDS), 'PREREQUISITE')
            pins[name].update({k: info[k] for k in XRAY_ACCOUNT_FIELDS})
    return pins


def xray_accounts_match(info, original):
    # Old Install receipts omitted these keys. An explicit empty systemd
    # property is a pin, not an omission. Check User and Group independently.
    return all(k not in original or (k in info and info[k] == original[k]) for k in XRAY_ACCOUNT_FIELDS)


def cleanup_project_units(units, projection):
    # Project only the known manager edges of the authenticated local files.
    # The plain observation after daemon-reload must match this prediction.
    units = {name: dict(info) for name, info in units.items()}
    if DROP in projection:
        xl = units[XL]
        need(xl.get('DropInPaths') == DROP and xl.get('NeedDaemonReload') == 'no', 'PREREQUISITE')
        xl['DropInPaths'] = ''
        for field in ('Requires', 'After'):
            xl[field] = ' '.join(n for n in xl[field].split() if n not in (IKE, NET_UNIT))
        ike = units[IKE]
        ike['RequiredBy'] = ' '.join(n for n in ike['RequiredBy'].split() if n != XL)
    if NET in projection:
        old = units[NET_UNIT]
        need(old['LoadState'] == 'loaded' and old['ActiveState'] == 'inactive'
             and old.get('MainPID') == '0' and old.get('FragmentPath') == NET
             and old.get('UnitFileState') in ('static', 'disabled') and old.get('DropInPaths') == ''
             and set(old.get('RequiredBy', '').split()) <= ({XL} if DROP in projection else set())
             and not any(old.get(k) for k in ('BoundBy', 'ConsistsOf', 'PropagatesStopTo')), 'PREREQUISITE')
        units[NET_UNIT] = dict.fromkeys(INSTALL_UNIT_FIELDS, '') | dict(
            LoadState='not-found', ActiveState='inactive', SubState='dead', MainPID='0')
    return units


def observe(machine, d, transit=None, *, diagnose_profile_owner=False, deferred=(), projection=None) -> dict[str, Any]:
    global STAGE
    STAGE = 'PREREQUISITE'
    projection = projection or {}
    ready = preflight(machine)
    need(not ready['masked'], 'PREREQUISITE')
    no_jobs(UNITS)
    units = {name: unit(name) for name in UNITS}
    if NET in projection or DROP in projection:
        units = cleanup_project_units(units, projection)
    inspect_sockets = not any(name in deferred for name in SOCKET_OBSERVERS)
    inspect_nft = not any(name in deferred for name in NFT_OBSERVERS)
    inspect_xfrm = 'xfrm_user' not in deferred
    fresh_ike_guard(units[IKE], inspect_runtime=inspect_sockets and inspect_xfrm)
    pending = pending_xl(units[XL])
    if pending == 'missing':
        require_runtime_packages(PACKAGE_AUTOSTART_UNSAFE)
    preparation = pending_native(units[XL], units[IKE], pending) if pending else None
    need(preparation is not None or ready['unitsLoaded'], 'PREREQUISITE')
    vpn = (IKE,) if preparation is not None else (XL, IKE)
    for name in vpn:
        info = units[name]
        stopped = info['ActiveState'] == 'inactive' and info['SubState'] == 'dead' and info['MainPID'] == '0'
        need(native_vpn(info, name) and stopped and not info.get('DropInPaths')
             and info['UnitFileState'] in ('enabled', 'disabled'), 'PREREQUISITE')
    # Enroll only the exact helper unit via its single WantedBy symlink.
    install_boot = units[XL]['UnitFileState'] == 'disabled'
    need(not install_boot or (units[XL]['FragmentPath'] == SYSTEM + '/' + XL and boot_link() is None), 'PREREQUISITE')
    need(preparation is None or boot_link() is None, 'PREREQUISITE')
    need(units[NET_UNIT]['LoadState'] == 'not-found'
         and units[B]['ActiveState'] in ('active', 'inactive'), 'PREREQUISITE')
    for path in (NFT_DIR, DROP_DIR):
        need(path in projection or directory_absent(path), 'PREREQUISITE')
    need(not any(p not in projection and os.path.lexists(p) for p in (LEGACY_NFT, '/etc/ipsec.d/celerity-l2tp.conf')),
         'PREREQUISITE')
    files = {key: read(path, diagnose_main_mode=True, diagnose_profile_owner=diagnose_profile_owner)
             if key == 'main' else projection[path] if path in projection else read(path)
             for key, path in NAMES.items()}
    need(all(files[k] is None for k in ('ike', 'options', 'nft', 'net', 'drop'))
         and all(files[k] is not None for k in ('main', 'starter', 'chap', 'secrets')), 'PREREQUISITE')
    starter = uncomment(raw(files['starter']))
    need(starter in ([], [b'config setup'], [STOCK_IKE_INCLUDE], [b'config setup', STOCK_IKE_INCLUDE])
         and not uncomment(raw(files['secrets']))
         and not uncomment(raw(files['chap'])), 'PREREQUISITE')
    if files['lns'] is None:
        # read() also returns None for a missing parent. Diagnose only an absent
        # leaf under the trusted directory, without following symlinks.
        if directory_absent(NAMES['lns']):
            raise Refusal(XL2TPD_CONFIG_MISSING)
        raise Refusal('PREREQUISITE')
    need(is_stock_lns(files['lns']), 'PREREQUISITE')
    stock_starter = digest(raw(files['starter'])) == STOCK_IKE_STARTER_SHA
    need(ike_include_matches(files['starter'], [], **({'check_tree': True} if stock_starter else {}),
                             **({'removed': True} if NAMES['ike'] in projection else {})), 'PREREQUISITE')
    bridge_generation = remove_generation(BRIDGE)
    bridge = read(BRIDGE, diagnose_profile_owner=diagnose_profile_owner)
    need(bridge is not None or units[B]['ActiveState'] == 'inactive', 'PREREQUISITE')
    placeholder = canonical_empty_bridge(bridge) and bridge_unit_absent(units[B])
    if placeholder:
        need(bridge_generation is not None and remove_generation(BRIDGE) == bridge_generation, 'BASELINE_CHANGED')
    global_paths = ('/etc/ppp/options', SWAN_CONF, XL_DEFAULT)
    for path in global_paths:
        # Fingerprint stock/default inputs that this installer never edits.
        if os.path.lexists(path):
            need(read(path, 262144) is not None, 'PREREQUISITE')
    globals_before = {path: read(path, 262144) for path in global_paths}
    if preparation is None:
        need(xl_defaults_admitted(globals_before[XL_DEFAULT], units[XL]), 'PREREQUISITE')
    else:
        # The strict package proof admitted exactly these SysV defaults. Only
        # the verified native postimage may use the ordinary native predicate.
        default = globals_before[XL_DEFAULT]
        need(default is not None and default['mode'] == 0o644 and default['gid'] == 0
             and default.get('uid', 0) == 0 and digest(raw(default)) == STOCK_XL_DEFAULT_SHA, 'PREREQUISITE')
    rows = sock_rows() if inspect_sockets else None
    net = ipaddress.IPv4Network(d['clientCidr'])
    for addr in ip('addr', 'show'):
        for item in addr.get('addr_info', []):
            host = ipaddress.IPv4Interface(item['local'] + '/' + str(item['prefixlen']))
            need(not net.overlaps(host.network), 'NETWORK_CONFLICT')
    for route in ip('route', 'show', 'table', 'all'):
        dst = route.get('dst', 'default')
        need(dst == 'default' or not net.overlaps(ipaddress.IPv4Network(dst)), 'NETWORK_CONFLICT')
    reserved = (500, 4500, 1701, d['tproxyPort'])
    need((rows is None or not any(n in reserved for _, _, n, _ in rows))
         and (vpn_empty() if inspect_xfrm else ppp_empty())
         and network_projection(d, '', **({} if inspect_nft else {'inspect_nft': False}))
         == {'nft': None, 'rule': False, 'route': False}, 'NETWORK_CONFLICT')
    need(not inspect_nft or not any(row.get('name') in ('celerity_l2tp', TABLE) for row in nft_tables()), 'NETWORK_CONFLICT')
    no_swan_rule()
    need(not units[IKE].get('PassEnvironment') and (STOCK_IKE_INCLUDE in starter or stock_starter), 'PREREQUISITE')
    need(all(removal_native(units[n], n, {'units': units}, installed=False)
             and not units[n].get('ExecCondition') for n in vpn), 'PREREQUISITE')
    removal_dependencies({n: units[n] for n in vpn}, installed=False)
    swan_default_environment('PREREQUISITE')
    files['swan'] = None if SWAN_PROFILE in projection else read(SWAN_PROFILE, 8192)
    need(files['swan'] is None, 'PREREQUISITE')
    swan = swan_inputs(False, 'PREREQUISITE', **({'removed': True} if SWAN_PROFILE in projection else {}))
    STAGE = 'PROFILE_USERS'
    sockets = xray_users(files['main'], units[X], rows, transit) if rows is not None else None
    need(rows is None or sockets, 'RUNTIME_UNPROVED')
    return dict(boot=boot(), files=files, units=install_unit_pins(units), bridge=bridge, sockets=sockets, globalFiles=globals_before,
                installBoot=install_boot, ikeSockets=[], swanInputs=swan,
                **({'nativePreparation': preparation} if preparation is not None else {}),
                **({'transit': transit} if transit is not None else {}),
                **({'emptyBridgeGeneration': bridge_generation} if placeholder else {}))


def candidate(request, before, *, active_probe=False):
    files = request['files']
    sidecar = 'bridge' in files
    need(set(files) - {'bridge'} == {'main', 'nft', 'ike', 'lns', 'options', 'secrets', 'chap'}, 'CANDIDATE_INVALID')
    bytes_ = {k: base64.b64decode(value, validate=True) for k, value in files.items()}
    need(all(0 < len(value) <= (MAX_FILE if k in ('main', 'bridge') else 1024 * 1024) for k, value in bytes_.items()), 'CANDIDATE_INVALID')
    d, token = request['network'], request['backupId']
    main = unique_profile({'data': files['main']}) if 'transit' in before else json.loads(bytes_['main'])
    if 'transit' in before:
        protected = transit_inbounds(main, before['transit'])
        original_main = unique_profile(before['files']['main'])
        need(encode([i for i in main['inbounds'] if i.get('tag') in protected])
             == encode([i for i in original_main['inbounds'] if i.get('tag') in protected]), 'CANDIDATE_INVALID')
    ppp = [i for i in main['inbounds'] if i.get('tag', '').startswith('relay-l2tp-')]
    owner = json.loads(bytes_['bridge']) if sidecar else main
    handoff = [i for i in owner['inbounds'] if i.get('tag') == 'rebuild-relay-ingress']
    need(len(ppp) == 1 and ppp[0].get('port') == d['tproxyPort'] and len(handoff) == 1
         and handoff[0].get('listen') == '127.0.0.1' and type(handoff[0].get('port')) is int, 'CANDIDATE_INVALID')
    rows = sock_rows() if before.get('sockets', []) is not None else None
    if sidecar:
        need(before['bridge'] is not None and not any(i.get('tag') == handoff[0]['tag'] for i in main['inbounds']), 'CANDIDATE_INVALID')
        side = unit(B)
        original_side = json.loads(raw(before['bridge']))
        # An existing managed sidecar only, with no separate dynamic-user API.
        need(not original_side.get('api') and not owner.get('api') and side.get('User') == 'nobody'
             and xray_accounts_match(side, before['units'][B])
             and side.get('UnitFileState') == 'enabled', 'PREREQUISITE')
        pid = xray_argv(side, BRIDGE)
        if rows is not None:
            try:
                verify_socks_handoff(rows, handoff[0]['port'], pid, active=active_probe)
            except Refusal:
                raise Refusal('NETWORK_CONFLICT') from None
    elif rows is not None:
        need(not any(n == handoff[0]['port'] for _, _, n, _ in rows), 'NETWORK_CONFLICT')
    drop = f'[Unit]\nRequires={NET_UNIT} {IKE}\nAfter={NET_UNIT} {IKE}\n'.encode()
    original = before['files']
    after = {key: entry(data, 0o644 if key in ('lns', 'ike', 'nft') else 0o600) for key, data in bytes_.items()}
    after['main'] = {**original['main'], 'data': b64(bytes_['main'])}
    if sidecar:
        after['bridge'] = {**before['bridge'], 'data': b64(bytes_['bridge'])}
    after['starter'] = original['starter'] if STOCK_IKE_INCLUDE in uncomment(raw(original['starter'])) else entry(
        raw(original['starter']) + b'\ninclude ' + NAMES['ike'].encode() + b'\n', original['starter']['mode'], original['starter']['gid'])
    for k in ('chap', 'secrets'):
        after[k] = entry(raw(original[k]) + b'\n' + bytes_[k])
    need(network_witness_absent(network_witness_path(token)), 'NETWORK_CONFLICT')
    after['net'], after['drop'] = entry(network_unit(d, sidecar, backup_id=token,
                                                   nft_sha256=digest(bytes_['nft'])), 0o644), entry(drop, 0o644)
    if 'swan' in original:
        after['swan'] = entry(SWAN_SETTINGS, 0o644)
    need(nft_marker(bytes_['nft'], token), 'CANDIDATE_INVALID')
    return after


NETWORK_START_CHECK = '/usr/bin/systemctl is-active --quiet ' + X
NETWORK_RUN = '/run'


def network_witness_path(token):
    need(isinstance(token, str) and re.fullmatch(r'[a-f0-9]{32}', token), 'CANDIDATE_INVALID')
    return NETWORK_RUN + '/celerity-rebuild-l2tp-network-' + token


# The same fixed observer runs in the packed DIRECT helper and in the unit.
# No /run receipt is created. A token alone is not proof of ownership: bind
# the full ordered rules in each chain, plus the complete route and RPDB rows.
NETWORK_POLICY_SOURCE = r'''import hashlib
import json
import os

def require(ok):
    if not ok:
        raise ValueError('unexpected policy state')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def witness_absent(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    return False

def nft_rows(run, *args):
    rows = json.loads(run('/usr/sbin/nft', '-j', *args))['nftables']
    require(type(rows) is list and all(type(row) is dict and len(row) == 1 for row in rows))
    return rows

def firewall(run, d, token, name):
    tables = nft_rows(run, 'list', 'tables')
    require(all('table' in row or 'metainfo' in row for row in tables))
    own = [row['table'] for row in tables if 'table' in row and row['table']['name'] == name]
    if not own:
        return None
    require(len(own) == 1 and own[0]['family'] == 'inet' and own[0]['comment'] == token)
    common = dict(family='inet', table=name)
    hooks = dict(prerouting=-150, input=0, forward=0)
    address, prefix = d['clientCidr'].split('/')
    mark, port = d['fwmark'], d['tproxyPort']

    def match(left, right):
        return dict(match=dict(op='==', left=left, right=right))

    def meta(key, value):
        return match(dict(meta=dict(key=key)), value)

    def payload(protocol, field, value):
        return match(dict(payload=dict(protocol=protocol, field=field)), value)

    ppp = meta('iifname', 'ppp*')
    src = payload('ip', 'saddr', dict(prefix=dict(addr=address, len=int(prefix))))
    l4 = meta('l4proto', dict(set=['tcp', 'udp']))
    l2tp = payload('udp', 'dport', 1701)
    accept, drop = dict(accept=None), dict(drop=None)
    expected = dict(
        prerouting=[[ppp, src, l4, dict(tproxy=dict(family='ip', port=port)),
                     dict(mangle=dict(key=dict(meta=dict(key='mark')), value=mark)), accept]],
        input=[[ppp, src, meta('mark', mark), accept], [ppp, drop],
               [l4, payload('th', 'dport', port), drop], [l2tp, meta('ipsec', True), accept], [l2tp, drop]],
        forward=[[ppp, drop]])
    chains, rules, table = {}, {key: [] for key in hooks}, None
    for row in nft_rows(run, '-s', '-a', 'list', 'table', 'inet', name):
        key, value = next(iter(row.items()))
        if key == 'metainfo':
            require(value['json_schema_version'] == 1)
            continue
        handle = value['handle']
        require(type(handle) is int and handle > 0)
        value = {k: v for k, v in value.items() if k != 'handle'}
        if key == 'table':
            require(table is None and handle == own[0]['handle'])
            table = value
        elif key == 'chain':
            chain = value['name']
            require(chain in hooks and chain not in chains)
            chains[chain] = value
        elif key == 'rule':
            chain = value['chain']
            expr = value['expr']
            require(value == dict(common, chain=chain, expr=expr))
            rules[chain].append(expr)
        else:
            require(False)
    require(table == dict(family='inet', name=name, comment=token)
            and canonical(chains) == canonical({key: dict(common, name=key, type='filter', hook=key,
                                                          prio=prio, policy='accept') for key, prio in hooks.items()})
            and canonical(rules) == canonical(expected))
    # Handles and library version are not an identity across a kernel boot.
    return sha(canonical([table, chains, rules]))

def observe_policy(run, d, token, name, priority, *, removing=False):
    def observe(kind, *opts):
        rows = json.loads(run('/usr/sbin/ip', '-j', '-N', '-4', kind, 'show', *opts))
        require(type(rows) is list and all(type(r) is dict and
                r.get('family', 'inet') in ('inet', '2', 2) for r in rows))
        for r in rows:
            r.pop('family', None)
        return rows

    def table_id(value):
        names = dict(local=255, main=254, default=253)
        if type(value) is str and value in names:
            return names[value]
        require(type(value) is int or (type(value) is str and value.isascii() and value.isdecimal()))
        return int(value)

    rules, routes = observe('rule'), observe('route', 'table', 'all')
    require(all(type(r['priority']) is int for r in rules))
    table = d['routeTable']
    others = [r for r in rules if r['priority'] != priority]
    own = [r for r in rules if r['priority'] == priority]
    if removing:
        require(all(table_id(r['table']) != table for r in others if 'table' in r))
    else:
        stock = {0: 255, 32766: 254, 32767: 253}
        require(len(others) == 3 and {r['priority'] for r in others} == set(stock)
                and all(r['src'] == 'all' and table_id(r['table']) == stock[r['priority']]
                        and not (set(r) - {'priority', 'src', 'table', 'protocol'}) for r in others))
    # iproute2 omits the table on main-table routes; their absence does not
    # mean table 0. -N avoids arbitrary rt_tables aliases on other rows.
    selected = [r for r in routes if table_id(r.get('table', 254)) == table]
    cidr = d['clientCidr']
    address, length = cidr.split('/')
    require(len(own) <= 1 and all(table_id(r['table']) == table and
            ((r['src'] == cidr and 'srclen' not in r) or
             (r['src'] == address and type(r.get('srclen')) is int and r['srclen'] == int(length))) and
            type(r['fwmark']) in (int, str) and
            (int(r['fwmark'], 10 if r['fwmark'].isdecimal() else 0) if type(r['fwmark']) is str else r['fwmark']) == d['fwmark'] and
            not (set(r) - {'priority', 'src', 'srclen', 'table', 'fwmark', 'protocol'}) for r in own))
    require(len(selected) <= 1 and all(r.get('type') in ('local', 2, '2') and r.get('dst') in ('default', '0.0.0.0/0')
            and r['dev'] == 'lo' and r['scope'] in ('host', 254, '254') and r.get('flags', []) == []
            and not (set(r) - {'type', 'dst', 'dev', 'scope', 'table', 'flags', 'protocol'}) for r in selected))
    return dict(nft=firewall(run, d, token, name), rule=bool(own), route=bool(selected))
'''

_NETWORK_POLICY: dict[str, Any] = {}
exec(NETWORK_POLICY_SOURCE, _NETWORK_POLICY)
network_witness_absent = _NETWORK_POLICY['witness_absent']


def pinned_network_projection(d, token, removing):
    try:
        need(network_witness_absent(network_witness_path(token)), 'ROLLBACK_DRIFT')
        return _NETWORK_POLICY['observe_policy'](command, d, token, TABLE, PRIORITY, removing=removing)
    except (KeyError, TypeError, ValueError, IndexError) as error:
        raise Refusal('ROLLBACK_DRIFT') from error


def network_unit_start():
    # The boot-time unit cannot depend on the transient DIRECT payload or
    # take its host flock (Install already holds it while starting XL).
    return (NETWORK_POLICY_SOURCE + r'''
import stat
import subprocess
import sys

def run(*args, data=None):
    result = subprocess.run(args, input=data, stdin=subprocess.DEVNULL if data is None else None,
                            capture_output=True, timeout=3, cwd='/',
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 16 * 1024 * 1024)
    return result.stdout

def read(path, mode, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        s = os.fstat(f.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == s.st_gid == 0
                and stat.S_IMODE(s.st_mode) == mode)
        data = f.read(limit + 1)
        require(len(data) <= limit)
        return data

def main():
    token, source_sha, nft_file, name, cidr, mark, table, priority, port, witness = sys.argv[1:]
    nft, ip = '/usr/sbin/nft', '/usr/sbin/ip'
    require(witness_absent(witness))
    policy = read(nft_file, 0o644, 1024 * 1024)
    require(sha(policy) == source_sha and
            policy.startswith(f'create table inet {name} {{\n    comment "{token}"\n'.encode()))
    d = dict(clientCidr=cidr, fwmark=int(mark), routeTable=int(table), tproxyPort=int(port))
    live = observe_policy(run, d, token, name, int(priority))
    require(witness_absent(witness))
    if all(live.values()):
        return
    # Never repair a partial policy on start. An empty kernel after boot is
    # legitimate; creation starts with the atomic, exclusive nft batch.
    require(not any(live.values()))
    run(nft, '-f', '-', data=policy)
    created = firewall(run, d, token, name)
    require(created is not None)
    run(ip, '-4', 'route', 'add', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', table)
    run(ip, '-4', 'rule', 'add', 'priority', priority, 'from', cidr, 'fwmark', mark, 'table', table)
    require(observe_policy(run, d, token, name, int(priority)) == dict(nft=created, rule=True, route=True))
    require(witness_absent(witness))

try:
    main()
except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError):
    raise SystemExit('Celerity L2TP policy missing, conflicting or unverified') from None
''').encode()


def managed_nft_bytes(d, backup_id):
    return f'''create table inet {TABLE} {{
    comment "{backup_id}"
    chain prerouting {{
        type filter hook prerouting priority mangle; policy accept;
        iifname "ppp*" ip saddr {d['clientCidr']} meta l4proto {{ tcp, udp }} tproxy ip to :{d['tproxyPort']} meta mark set {d['fwmark']} accept
    }}
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "ppp*" ip saddr {d['clientCidr']} meta mark {d['fwmark']} accept
        iifname "ppp*" drop
        meta l4proto {{ tcp, udp }} th dport {d['tproxyPort']} drop
        udp dport 1701 meta ipsec exists accept
        udp dport 1701 drop
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname "ppp*" drop
    }}
}}
'''.encode()


def network_unit(d, sidecar, *, legacy=False, backup_id=None, nft_sha256=None):
    """Render historical bytes, or explicitly construct a new install generation.

    Without install pins, legacy=True is the original Requires template and
    legacy=False is the c83c995 Wants template (also its old Apply replacement).
    Do not render pinned bytes as a replacement for either historical receipt.
    """
    prerequisite = X + (' ' + B if sidecar else '')
    dependency = 'Requires' if legacy else 'Wants'
    # Xray is needed to bring the network up, but a routine restart must not
    # stop the resident policy or the LNS. PPP can't fall back to forwarding:
    # that is denied by the resident nft table even with no Xray listener.
    startup = '' if legacy else f'ExecStartPre={NETWORK_START_CHECK}\n'
    header = f'''[Unit]
Description=Celerity rebuild L2TP TPROXY policy
Before={XL}
{dependency}={X}
After={prerequisite} nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=20s
{startup}'''
    if backup_id is not None or nft_sha256 is not None:
        need(not legacy and isinstance(backup_id, str) and re.fullmatch(r'[0-9a-f]{32}', backup_id)
             and isinstance(nft_sha256, str) and re.fullmatch(r'[0-9a-f]{64}', nft_sha256), 'CANDIDATE_INVALID')
        d = routing(d)
        # Bind this version to buildFiles' single exclusive NEWTABLE. Even an
        # already pinned file must not smuggle another nft command into startup.
        policy = managed_nft_bytes(d, backup_id)
        need(digest(policy) == nft_sha256, 'CANDIDATE_INVALID')
        code = network_unit_start().hex()
        # No ExecStop or ExecStopPost: Remove stops the unit before it tears
        # down the still-resident policy. Only host Remove/rollback delete it.
        return (header + f'ExecStart=/usr/bin/python3 -I -B -S -c "exec(bytes.fromhex(\'{code}\'))" '
                f'{backup_id} {nft_sha256} {NFT_FILE} {TABLE} {d["clientCidr"]} {d["fwmark"]} {d["routeTable"]} '
                f'{PRIORITY} {d["tproxyPort"]} {network_witness_path(backup_id)}\n').encode()
    return (header + f'''ExecStart=/usr/sbin/nft -f {NFT_FILE}
ExecStart=/usr/sbin/ip -4 route add local 0.0.0.0/0 dev lo table {d['routeTable']}
ExecStart=/usr/sbin/ip -4 rule add priority {PRIORITY} from {d['clientCidr']} fwmark {d['fwmark']} table {d['routeTable']}
''').encode()


def nft_marker(data, token):
    return data.startswith(f'create table inet {TABLE} {{\n    comment "{token}"\n'.encode())


def validate_profiles(after):
    for key, name, path in (('main', X, MAIN), ('bridge', B, BRIDGE)):
        if key not in after:
            continue
        info = unit(name)
        uid = pwd.getpwnam(info.get('User') or 'root')
        gid = grp.getgrnam(info['Group']).gr_gid if info.get('Group') else uid.pw_gid
        st = os.stat('/proc/' + info['MainPID'])
        need(st.st_uid == uid.pw_uid and st.st_gid == gid, 'PREREQUISITE')
        as_user = ('/usr/bin/setpriv', '--reuid=' + str(uid.pw_uid), '--regid=' + str(gid), '--init-groups')
        command(*as_user, XRAY, 'run', '-test', '-format', 'json', '-config', path, wait=8)
        command(*as_user, XRAY, 'run', '-test', '-format', 'json', '-config', 'stdin:', data=raw(after[key]), wait=8)



def manifest_path(token):
    return VAULT + '/' + token + '/manifest.json'


def read_manifest(token):
    with directory(VAULT, private=True), directory(VAULT + '/' + token, private=True):
        path = manifest_path(token)
        record = read(path, 2 * MAX_FILE)
        need(record is not None and record['mode'] == 0o600 and record['gid'] == 0, 'ROLLBACK_DRIFT')
        value = json.loads(raw(record))
    return path, record, value


def bound_manifest(request):
    path, record, value = read_manifest(request['backupId'])
    need(value['machineId'] == request['machineId'] and value['backupId'] == request['backupId'] and
         value['network'] == request['network'] and digest(encode(value['before'])) == request['baseline']
         and value['before'].get('boot') == boot(), 'ROLLBACK_DRIFT')
    return path, record, value


def runtime_before(backup, *, preparing_modules=False):
    before = backup['before']
    if not preparing_modules and before.get('sockets', []) is None:
        sockets = backup.get('preparedSockets')
        need(type(sockets) is list and bool(sockets), 'ROLLBACK_DRIFT')
        before = {**before, 'sockets': sockets}
    prepared = backup.get('nativePrepared')
    if prepared is None:
        need('nativePreparation' not in before, 'ROLLBACK_DRIFT')
        return before
    # Keep the true checked baseline immutable for bound_manifest(). Existing
    # teardown restores the proven *native* prerequisite, not the SysV view.
    return {**before, 'units': {**before['units'], XL: prepared['unit']},
            'installBoot': True, 'nativeGeneration': prepared['generation']}


def check_prepared_native(before):
    if 'nativeGeneration' in before:
        need(remove_generation(SYSTEM + '/' + XL) == before['nativeGeneration'], 'ROLLBACK_DRIFT')


def operation_files(records):
    return {**NAMES, **({'swan': SWAN_PROFILE} if 'swan' in records else {}),
            **({'bridge': BRIDGE} if 'bridge' in records else {})}


def operation_order(records):
    return (*(('swan',) if 'swan' in records else ()), *ORDER, *(('bridge',) if 'bridge' in records else ()))


def original_files(before, records):
    return {**before['files'], **({'bridge': before['bridge']} if 'bridge' in records else {})}


def neighbors(before, sidecar=False):
    check_prepared_native(before)
    b = unit(B)
    # Verify/rollback (and owned removal below) pin the admitted bytes and
    # metadata, rather than rerunning the pristine-unit defaults admission.
    need(all(read(path, 262144) == value for path, value in before['globalFiles'].items()), 'ROLLBACK_DRIFT')
    if sidecar:
        need(all(b.get(k) == before['units'][B][k] for k in ('LoadState', 'UnitFileState', 'FragmentPath', 'DropInPaths'))
             and b.get('User') == 'nobody' and xray_accounts_match(b, before['units'][B]), 'ROLLBACK_DRIFT')
    else:
        need(read(BRIDGE) == before['bridge'] and all(b.get(k) == v for k, v in before['units'][B].items()), 'ROLLBACK_DRIFT')
        if 'emptyBridgeGeneration' in before:
            need(bridge_unit_absent(b) and remove_generation(BRIDGE) == before['emptyBridgeGeneration'], 'ROLLBACK_DRIFT')


def file_generations(records=None, *, include_chap=True):
    result = {}
    for k, path in operation_files(records or {}).items():
        if k == 'chap' and not include_chap:
            continue
        st = os.lstat(path)
        need(stat.S_ISREG(st.st_mode), 'ROLLBACK_DRIFT')
        result[k] = [st.st_dev, st.st_ino, st.st_ctime_ns]
    return result


def in_cgroup(pid, unit_info):
    group = unit_info.get('ControlGroup')
    if not group or not re.fullmatch(r'[1-9][0-9]*', pid):
        return False
    with open('/proc/' + pid + '/cgroup') as handle:
        return '0::' + group in handle.read(65536).splitlines()


def installed_runtime(d, token, before, after):
    global STAGE
    STAGE = 'RUNTIME_UNPROVED'
    no_jobs(UNITS)
    sidecar = 'bridge' in after
    neighbors(before, sidecar)
    x, lns, ike, net_unit = (unit(name) for name in (X, XL, IKE, NET_UNIT))
    kind = network_kind(after['net'], d, sidecar, token, digest(raw(after['nft'])))
    need(network_unit_loaded(net_unit, kind == 'requires', after['net'] if kind == 'pinned' else None), 'RUNTIME_UNPROVED')
    need(native_vpn(lns, XL) and native_vpn(ike, IKE) and working(lns) and working(ike)
         and lns['UnitFileState'] == 'enabled'
         and ike['UnitFileState'] == before['units'][IKE]['UnitFileState']
         and lns['DropInPaths'] == DROP and NET_UNIT in lns['Requires'].split() and NET_UNIT in lns['After'].split()
         and net_unit.get('ActiveState') == 'active' and net_unit.get('SubState') == 'exited' and net_unit.get('FragmentPath') == NET,
         'RUNTIME_UNPROVED')
    rows = sock_rows()
    pid = xray_argv(x)
    same_xray_dropin(x, before['units'][X])
    need(xray_accounts_match(x, before['units'][X]), 'RUNTIME_UNPROVED')
    sockets = xray_users(after['main'], x, rows, before.get('transit'))
    need(set(tuple(s) for s in before['sockets']) <= set(tuple(s) for s in sockets)
         and x['InvocationID'] != before['units'][X]['InvocationID'], 'RUNTIME_UNPROVED')
    bridge_info = unit(B) if sidecar else None
    handoff_pid = xray_argv(bridge_info, BRIDGE) if bridge_info is not None else pid
    need(bridge_info is None or (bridge_info['InvocationID'] != before['units'][B]['InvocationID']
                                and xray_accounts_match(bridge_info, before['units'][B])), 'RUNTIME_UNPROVED')
    config = json.loads(raw(after['bridge' if sidecar else 'main']))
    handoff = next(i['port'] for i in config['inbounds'] if i['tag'] == 'rebuild-relay-ingress')
    need(all(any(p == proto and n == d['tproxyPort'] and owners == [pid] for p, _, n, owners in rows)
             for proto in ('tcp', 'udp')), 'RUNTIME_UNPROVED')
    verify_socks_handoff(rows, handoff, handoff_pid)
    l2tp_sockets = [owners for p, a, n, owners in rows if p == 'udp' and n == 1701]
    need(l2tp_sockets and all(owners == [lns['MainPID']] for owners in l2tp_sockets), 'RUNTIME_UNPROVED')
    for port in (500, 4500):
        ike_sockets = [owners for p, a, n, owners in rows if p == 'udp' and n == port]
        need(ike_sockets and all(owners and all(in_cgroup(pid, ike) for pid in owners) for owners in ike_sockets),
             'RUNTIME_UNPROVED')
    status = command('/usr/sbin/ipsec', 'statusall')
    need(re.search(rb'^\s*celerity-l2tp\s*:\s+[^\n]+', status, re.M), 'RUNTIME_UNPROVED')
    policy = network_projection(d, token, pinned=kind == 'pinned')
    need(policy['rule'] and policy['route'] and policy['nft'] is not None, 'RUNTIME_UNPROVED')
    need(all(read(path) == after[k] for k, path in operation_files(after).items()), 'RUNTIME_UNPROVED')
    need(ike_include_matches(after['starter'], [os.path.basename(NAMES['ike'])]), 'RUNTIME_UNPROVED')
    if 'swan' in after:
        need(not ike.get('PassEnvironment') and swan_inputs(True, STAGE) == before['swanInputs'], STAGE)
        no_swan_rule()
    return {'nft': policy['nft'], 'invocations': [u['InvocationID'] for u in (x, lns, ike, net_unit)]
            + ([bridge_info['InvocationID']] if bridge_info is not None else []),
            'files': file_generations(after), 'bootEnrollment': boot_link() if before.get('installBoot') else None}


def write_swan_profile(path, old_manifest, backup, after, *, pin=False):
    before = backup['before']
    need(before['files']['swan'] is None and not before['ikeSockets']
         and after['swan'] == entry(SWAN_SETTINGS, 0o644)
         and swan_inputs(False, 'ROLLBACK_DRIFT') == before['swanInputs'], 'ROLLBACK_DRIFT')
    no_swan_rule()
    generation = write(SWAN_PROFILE, None, after['swan'], witness=pin)
    backup['swanGeneration'] = generation if pin else remove_generation(SWAN_PROFILE)
    check_swan_profile(backup, read(SWAN_PROFILE))
    updated = entry(encode(backup))
    write(path, old_manifest, updated)
    return updated


def swan_unstarted(info, before, name):
    old = before['units'][name].get('InvocationID') or '0' * 32
    return (info.get('ActiveState'), info.get('SubState'), info.get('MainPID'), info.get('InvocationID') or '0' * 32) == (
        'inactive', 'dead', '0', old)


def swan_started_units(before):
    units = {n: unit(n) for n in SWAN_START_UNITS}
    removal_dependencies(units, installed=True)
    births = [units[n].get('InvocationID') for n in SWAN_START_UNITS]
    need(len(set(births)) == len(SWAN_START_UNITS) and all(isinstance(i, str) and re.fullmatch(r'[0-9a-f]{32}', i) and i != '0' * 32
             and i != before['units'][n].get('InvocationID') and units[n]['ActiveState'] == 'active'
             for n, i in zip(SWAN_START_UNITS, births)), 'RUNTIME_UNPROVED')
    return births


def prepare_native_install(request, before, after, lock_fd):
    created = C3_STOCK_RUNTIME['create_native'](stock_runtime_root(), stock_runtime_command, C3_STOCK_ENSURE)
    strict = stock_runtime_observation('native')
    old = before['nativePreparation']
    need(strict['inputs'] == old['inputs'] and strict['unitPath'] == old['unitPath']
         and strict['layout'] == {SYSTEM + '/' + XL: created}, 'BASELINE_CHANGED')
    # Fresh full observation on the very same flock. Only the XL fragment,
    # physical load/file state and eligibility for the owned boot link change.
    live = observe_install(request['machineId'], routing(request['network']), before.get('transit'), lock_fd)
    expected = dict(before)
    del expected['nativePreparation']
    native = {**before['units'][XL], 'LoadState': 'loaded', 'UnitFileState': 'disabled', 'FragmentPath': SYSTEM + '/' + XL}
    expected.update(units={**before['units'], XL: native}, installBoot=True)
    need(live == expected and candidate(request, live) == after
         and stock_runtime_observation('native') == strict, 'BASELINE_CHANGED')
    return dict(unit=live['units'][XL], generation=created)




def cleanup_current(key):
    path = cleanup_paths()[key]
    folder = key in CLEANUP_FOLDERS
    leaf = foreign_leaf(path, folder=folder, unit_mode=key in CLEANUP_XRAY_SHA, read_unit=True)
    if leaf is None:
        return None, None
    mode, pin, data = leaf
    return (mode if folder else cleanup_record(data, pin)), pin


def cleanup_fence(backup):
    before = backup['before']
    need('boot' in before, 'IN_FLIGHT')
    return entry(encode({k: backup[k] for k in ('backupId', 'machineId', 'network')} | {
        'boot': before['boot'], 'installLock': before['installLock'], 'digest': before['foreignCleanup']['digest']}))


def cleanup_guard(backup, fd, identity, *, file_net=False, legacy_net=False):
    scope = package_scope(backup['machineId'], fd)
    before = backup['before']
    need(scope['boot'] == before.get('boot') and scope['installLock'] == before['installLock']
         and read(VAULT + '/' + FOREIGN_PENDING, 2048) == cleanup_fence(backup), 'IN_FLIGHT')
    package_no_pending()
    has_unit = (file_net or legacy_net) and unit(NET_UNIT)['LoadState'] == 'loaded'
    cleanup_runtime(backup['network']['fwmark'], has_unit=has_unit, unlinked=legacy_net and recovery_stat(NET) is None)
    need(identity is None or cleanup_xray_identity() == identity, 'IN_FLIGHT')
    need(time.monotonic() < DEADLINE, 'IN_FLIGHT')


def cleanup_reload(edits):
    return any(e[0] in (*CLEANUP_XRAY_SHA, *CLEANUP_MANAGER) for e in edits)


def cleanup_manager_ready(edits):
    keys = {e[0] for e in edits}
    if 'DROPIN_PRESENT' in keys:
        xl = unit(XL)
        need(xl.get('DropInPaths') in ('', DROP) and xl.get('MainPID') == '0', 'IN_FLIGHT')
        if xl['DropInPaths'] != DROP or xl.get('NeedDaemonReload') != 'no':
            return False
    return 'NETWORK_UNIT_ORPHANED' not in keys or unit(NET_UNIT)['LoadState'] == 'loaded'


def cleanup_no_remove(path):
    need(removal_intent_matches(os.path.dirname(path) + '/remove-attempt.json', None), 'IN_FLIGHT')


def restore_unit_mode(path, key, current, pin, original, identity):
    # The forward replacement rotates away pre-existing writable FDs. On
    # undo never publish a world-writable temporary unit before its final name.
    parent, name = os.path.split(path)
    with directory(parent) as held:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=held)
        try:
            name_unit = X if key == 'XRAY_UNIT_0666' else B
            need(cleanup_xray_identity() == identity and unit(name_unit)['FragmentPath'] == path, 'IN_FLIGHT')
            live = os.fstat(fd)
            need(pin is not None and [live.st_dev, live.st_ino, live.st_ctime_ns] == [pin[0], pin[1], pin[8]]
                 and cleanup_current(key) == (current, pin) and current is not None
                 and current['mode'] == 0o644 and original == {**current, 'mode': 0o666}, 'IN_FLIGHT')
            os.fchmod(fd, original['mode'])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(held)


def cleanup_transition(path, record, backup, fd, *, restore=False, preinstall=False):
    journal = backup['foreignJournal']
    edits, done = journal['edits'], journal['done']
    need(journal.get('editsSha256') == digest(encode(edits)), 'IN_FLIGHT')
    paths = cleanup_paths()
    need(edits and len(edits) <= len(paths) and len({e[0] for e in edits}) == len(edits)
         and len(done) <= len(edits) and all(e[0] in paths for e in edits), 'IN_FLIGHT')
    identity = journal.get('rollbackXray', journal['xray']) if restore else journal['xray']
    need((identity is not None) == any(e[0] in CLEANUP_XRAY_SHA for e in edits), 'IN_FLIGHT')
    legacy_net = any(e[0] == 'NETWORK_UNIT_ORPHANED' for e in edits)
    cleanup_guard(backup, fd, identity, legacy_net=legacy_net)
    validated = {}
    for i, (key, before, after, pin) in enumerate(edits):
        live, live_pin = cleanup_current(key)
        if i < len(done):
            need(live == after and ((not preinstall and restore and key not in CLEANUP_XRAY_SHA)
                                    or live_pin == done[i]), 'IN_FLIGHT')
            validated[key] = live_pin
        else:
            # A tracked member deletion changes its parent timestamps. Never
            # infer a replacement directory from a pathname or from emptiness.
            need(live == before and live_pin is not None and (live_pin[:6] == pin[:6]
                 if key in CLEANUP_FOLDERS and i and i == len(done) else live_pin == pin), 'IN_FLIGHT')
    if restore and backup['phase'] != 'restoring-foreign':
        backup['phase'] = 'restoring-foreign'
        nxt = entry(encode(backup))
        write(path, record, nxt)
        record = nxt
    order = list(reversed(edits[:len(done)])) if restore else edits
    if restore:
        # Restore the manager before any Xray fragment returns to mode 0666.
        order.sort(key=lambda e: e[0] in CLEANUP_XRAY_SHA)

    def restore_manager():
        nonlocal record
        if not restore or cleanup_manager_ready(edits):
            return
        for key in CLEANUP_XRAY_SHA:
            current, _ = cleanup_current(key)
            need(current is None or not current['mode'] & 0o022, 'IN_FLIGHT')
        journal['reloadPending'] = True
        intent = entry(encode(backup))
        write(path, record, intent)
        sc('daemon-reload', wait=12)
        cleanup_guard(backup, fd, identity, legacy_net=legacy_net)
        need(cleanup_manager_ready(edits), 'IN_FLIGHT')
        del journal['reloadPending']
        record = entry(encode(backup))
        write(path, intent, record)

    for key, before, after, pin in order:
        if restore and key in CLEANUP_XRAY_SHA:
            restore_manager()
        cleanup_guard(backup, fd, identity, legacy_net=legacy_net)
        if not restore and key == 'NFT_MEMBER':
            need(cleanup_nft_base() is not False, 'IN_FLIGHT')
        if not restore and key == 'DROP_MEMBER':
            need(cleanup_manager_ready([['DROPIN_PRESENT']]), 'IN_FLIGHT')
        leaf = paths[key]
        publication = None
        current, live_pin = cleanup_current(key)
        need(current == (after if restore else before), 'IN_FLIGHT')
        if restore:
            need(live_pin == validated[key], 'IN_FLIGHT')
        if key in CLEANUP_FOLDERS:
            if restore:
                mkdir(leaf, before)
                with directory(leaf) as held:
                    os.fchmod(held, before)
                    os.fsync(held)
            else:
                need(live_pin is not None and live_pin[:6] == pin[:6], 'IN_FLIGHT')
                rmdir(leaf)  # never recurse or erase an unobserved member
        elif restore and key in CLEANUP_XRAY_SHA:
            restore_unit_mode(leaf, key, current, live_pin, before, identity)
        else:
            if not restore:
                need(live_pin == pin, 'IN_FLIGHT')
            generation = [live_pin[0], live_pin[1], live_pin[8]] if live_pin is not None else None
            publication = write(leaf, current, before if restore else after, generation=generation,
                                reader=lambda _: cleanup_current(key)[0], witness=key in CLEANUP_XRAY_SHA,
                                mtime_ns=pin[7] if key in CLEANUP_XRAY_SHA else None)
        observed, observed_pin = cleanup_current(key)
        need(observed == (before if restore else after), 'IN_FLIGHT')
        if key in CLEANUP_XRAY_SHA:
            need(observed_pin is not None, 'IN_FLIGHT')
            if restore:
                need(observed_pin[:2] == live_pin[:2], 'IN_FLIGHT')
                journal.setdefault('restoredXray', {})[key] = observed_pin
            else:
                need([observed_pin[0], observed_pin[1], observed_pin[8]] == publication, 'IN_FLIGHT')
        if not restore:
            done.append(observed_pin)
            nxt = entry(encode(backup))
            write(path, record, nxt)
            record = nxt
    restore_manager()
    cleanup_guard(backup, fd, identity, legacy_net=legacy_net)
    expected = {key: before if restore else after for key, before, after, _ in edits}
    need(all(cleanup_current(key)[0] == value for key, value in expected.items()), 'IN_FLIGHT')
    return record


def clear_cleanup_fence(backup):
    pending = VAULT + '/' + FOREIGN_PENDING
    fence = cleanup_fence(backup)
    st = recovery_stat(pending)
    if st is not None:
        write(pending, fence, None, generation=[st.st_dev, st.st_ino, st.st_ctime_ns])
    # A previous unlink can be visible even though its parent fsync failed.
    with directory(VAULT, private=True) as held:
        foreign_no_pending()
        os.fsync(held)
        foreign_no_pending()


def sync_rollback_receipt(path, record):
    token_dir, name = os.path.split(path)
    with directory(token_dir, private=True) as held:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=held)
        with os.fdopen(fd, 'rb') as handle:
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
                 and (st.st_uid, st.st_gid, st.st_nlink) == (0, 0, 1) and not os.listxattr(fd)
                 and handle.read(2 * MAX_FILE + 1) == raw(record), 'IN_FLIGHT')
            os.fsync(fd)
            os.fsync(held)
            live = os.stat(name, dir_fd=held, follow_symlinks=False)
            need((live.st_dev, live.st_ino, live.st_ctime_ns) == (st.st_dev, st.st_ino, st.st_ctime_ns)
                 and read(path, 2 * MAX_FILE) == record, 'IN_FLIGHT')
    for parent in (VAULT, os.path.dirname(VAULT)):
        with directory(parent, private=parent == VAULT) as held:
            os.fsync(held)


def complete_cleanup_rollback(path, record, backup):
    cleanup_no_remove(path)
    need(record == entry(encode(backup)) and backup['phase'] == 'rolled-back', 'IN_FLIGHT')
    sync_rollback_receipt(path, record)
    clear_cleanup_fence(backup)
    need(time.monotonic() < DEADLINE, 'IN_FLIGHT')


def verify_retained_cleanup_edits(backup):
    journal = backup['foreignJournal']
    managed = set(operation_files(backup['after']).values()) | {NFT_DIR, DROP_DIR}
    need(len(journal['edits']) == len(journal['done']) and all(
        cleanup_paths()[key] in managed or cleanup_current(key) == (after, pin)
        for (key, _, after, _), pin in zip(journal['edits'], journal['done'])), 'IN_FLIGHT')


def cleanup_rollback(request, path, record, backup, fd, *, file_undo=None, file_net=False):
    global CLEANUP_ENTERED
    before = backup['before']
    need(install_lock_identity(fd) == before['installLock'] and backup['machineId'] == request['machineId']
         and backup['backupId'] == request['backupId'] and encode(backup['network']) == encode(request['network'])
         and boot() == before.get('boot'), 'IN_FLIGHT')
    CLEANUP_ENTERED = True
    cleanup_no_remove(path)
    package_no_pending()
    journal = backup['foreignJournal']
    need(not journal.get('reloadPending'), 'IN_FLIGHT')
    if backup['phase'] == 'rolled-back':
        verify_cleanup_rollback(request, backup)
        complete_cleanup_rollback(path, record, backup)
        return
    if not package_entry_exists(FOREIGN_PENDING):
        need(installed_phase(backup['phase']), 'IN_FLIGHT')
        write(VAULT + '/' + FOREIGN_PENDING, None, cleanup_fence(backup))
    need(read(VAULT + '/' + FOREIGN_PENDING, 2048) == cleanup_fence(backup), 'IN_FLIGHT')
    pristine_phase = backup['phase'] == 'cleaning-foreign'
    if file_undo is not None:
        need(backup['phase'] == 'applying' and not backup.get('swanStart'), 'IN_FLIGHT')
        cleanup_guard(backup, fd, journal['xray'], file_net=file_net)
        verify_retained_cleanup_edits(backup)
        need(read(path, 2 * MAX_FILE) == record, 'IN_FLIGHT')
        backup['phase'] = 'restoring-foreign'
        restoring = entry(encode(backup))
        write(path, record, restoring)
        record = restoring
        file_undo()
        verify_cleanup_original_runtime(request, backup, projection={})
    elif not pristine_phase and backup['phase'] != 'projected-rollback':
        # Join stock rollback as before. It proves the projected baseline;
        # publish a distinct phase before attempting to restore foreign bytes.
        settled = journal.get('installSettled')
        need(settled is True or 'installSettled' not in journal and backup.get('swanStart'), 'IN_FLIGHT')
        if settled is True and backup['phase'] == 'applying':
            for n in (X, B):
                expected = journal.get('xrayBirths', {}).get(n, before['units'][n]['InvocationID'])
                need(unit(n).get('InvocationID') == expected, 'IN_FLIGHT')
        verify_retained_cleanup_edits(backup)
        if journal['xray'] is not None:
            need(cleanup_xray_identity() == journal.get('installXray', journal['xray']), 'IN_FLIGHT')
        rollback(request, path, record, backup, cleanup=True)
        record = entry(encode(backup))
    if not pristine_phase and file_undo is None:
        verify_rollback(request['network'], request['backupId'], backup)
    record = cleanup_transition(path, record, backup, fd, restore=True, preinstall=pristine_phase)
    # The foreign transition already restored the idle manager view before
    # returning any Xray fragment to 0666. No further reload is permitted.
    journal['preinstallRollback'] = pristine_phase or file_undo is not None
    verify_cleanup_rollback(request, backup)
    backup['phase'] = 'rolled-back'
    terminal = entry(encode(backup))
    write(path, record, terminal)
    complete_cleanup_rollback(path, terminal, backup)


def verify_cleanup_original_runtime(request, backup, *, projection):
    before = backup['before']
    live = observe(request['machineId'], request['network'], before.get('transit'), projection=projection)
    need(encode(live) == encode({k: v for k, v in before.items() if k not in
                                 ('pppModules', 'installLock', 'foreignCleanup')}), 'IN_FLIGHT')


def verify_cleanup_rollback(request, backup):
    journal = backup['foreignJournal']
    edits = journal['edits']
    need(journal.get('editsSha256') == digest(encode(edits)), 'IN_FLIGHT')
    need(all(cleanup_current(key)[0] == original for key, original, _, _ in edits), 'IN_FLIGHT')
    for i, (key, _, _, pin) in enumerate(edits):
        if key in CLEANUP_XRAY_SHA:
            expected = journal.get('restoredXray', {}).get(key) if i < len(journal['done']) else pin
            need(expected is not None and cleanup_current(key)[1] == expected, 'IN_FLIGHT')
    for key, member in (('NFT_DIR_PRESENT', NFT_FILE), ('DROPIN_PRESENT', DROP)):
        if any(edit[0] == key for edit in edits):
            with directory(cleanup_paths()[key]) as held, os.scandir(held) as rows:
                need(next(rows).name == os.path.basename(member) and next(rows, None) is None, 'IN_FLIGHT')
    need(cleanup_manager_ready(edits), 'IN_FLIGHT')
    cleanup_runtime(request['network']['fwmark'], has_unit=any(e[0] == 'NETWORK_UNIT_ORPHANED' for e in edits))
    identity = journal.get('rollbackXray', journal['xray'])
    need(identity is None or cleanup_xray_identity() == identity, 'IN_FLIGHT')
    if journal['preinstallRollback']:
        verify_cleanup_original_runtime(request, backup, projection=cleanup_view(edits))
        plan = backup['before'].get('pppModules', {}).get('bootFile')
        if 'modulePersistence' in backup:
            need(plan is not None and read(PPP_PATH, 4096) == plan['before']['record'], 'IN_FLIGHT')
    else:
        verify_rollback(request['network'], request['backupId'], backup, projection=cleanup_view(edits))


def cleanup_install_files(request, path, record, backup, fd, after, *, can_undo_modules):
    """Join only this helper's synchronous, acknowledged file prefix."""
    global CLEANUP_ENTERED
    before = backup['before']
    paths, originals = operation_files(after), original_files(before, after)
    expected = {k: (originals[k], remove_generation(p)) for k, p in paths.items()}
    dirs = {}
    identity = backup['foreignJournal']['xray']

    def verify_prefix():
        for key, leaf in paths.items():
            image, pin = expected[key]
            need((image is None) == (pin is None) and read(leaf) == image
                 and remove_generation(leaf) == pin, 'IN_FLIGHT')
        for leaf in (NFT_DIR, DROP_DIR):
            if leaf not in dirs:
                need(directory_absent(leaf), 'IN_FLIGHT')
                continue
            live, own = recovery_stat(leaf), os.fstat(dirs[leaf])
            need(live is not None and stat.S_ISDIR(live.st_mode)
                 and (live.st_dev, live.st_ino, live.st_mode, live.st_uid, live.st_gid)
                 == (own.st_dev, own.st_ino, own.st_mode, 0, 0), 'IN_FLIGHT')
            with os.scandir(dirs[leaf]) as rows:
                members = {os.path.basename(p) for k, p in paths.items()
                           if os.path.dirname(p) == leaf and expected[k][0] is not None}
                for row in rows:
                    need(row.name in members, 'IN_FLIGHT')
                    members.remove(row.name)
                need(not members, 'IN_FLIGHT')

    verify_prefix()
    touched_parent = os.path.dirname(SWAN_PROFILE)
    with contextlib.ExitStack() as held:
        try:
            if 'swan' in after:
                record = write_swan_profile(path, record, backup, after, pin=True)
                expected['swan'] = after['swan'], backup['swanGeneration']
            for folder in (NFT_DIR, DROP_DIR):
                touched_parent = os.path.dirname(folder)
                mkdir(folder, 0o755)
                dirs[folder] = held.enter_context(directory(folder))
            for key in operation_order(after):
                if key == 'swan' or originals[key] == after[key]:
                    continue
                leaf = paths[key]
                touched_parent = os.path.dirname(leaf)
                pin = write(leaf, originals[key], after[key], generation=expected[key][1], witness=True)
                expected[key] = after[key], pin
        except OSError as error:
            # No boot enrollment or service command was admitted in this
            # region. An unacknowledged publication (even byte-identical), a
            # left-over stage or a changed neighbor invalidates the whole join.
            need(not isinstance(error, BlockingIOError) and can_undo_modules, 'IN_FLIGHT')
            need(read(path, 2 * MAX_FILE) == record, 'IN_FLIGHT')
            with directory(touched_parent) as parent:
                recovery_scan(touched_parent, lambda name: name.startswith('.direct-'))
                os.fsync(parent)
            verify_prefix()
            owner = module_boot_owner(backup)
            check_module_boot_owner(owner)
            if 'swan' in after:
                check_swan_profile(backup, expected['swan'][0])
            file_net = expected['net'][0] != originals['net']

            def undo():
                for key in reversed(operation_order(after)):
                    image, pin = expected[key]
                    if image != originals[key]:
                        cleanup_guard(backup, fd, identity, file_net=file_net)
                        if key == 'swan':
                            check_swan_profile(backup, read(SWAN_PROFILE))
                        write(paths[key], image, originals[key], generation=pin)
                for folder in reversed(dirs):
                    h = os.fstat(dirs[folder])
                    live = recovery_stat(folder)
                    need(live is not None and (live.st_dev, live.st_ino) == (h.st_dev, h.st_ino), 'IN_FLIGHT')
                    rmdir(folder)
                release_module_boot(owner)
                if file_net or expected['drop'][0] != originals['drop']:
                    # The manager may have loaded a fragment on observation,
                    # even though our forward daemon-reload never ran.
                    sc('daemon-reload', wait=12)
                    cleanup_guard(backup, fd, identity)

            cleanup_rollback(request, path, record, backup, fd, file_undo=undo, file_net=file_net)
        else:
            return record
    # The existing typed rollback/reconcile reply still has to be read back
    # by the caller. This refusal is settled, but is never a no-write frame.
    need(time.monotonic() < DEADLINE, 'IN_FLIGHT')
    CLEANUP_ENTERED = False
    raise Refusal('COMMAND_FAILED')


def install(request, before, after, lock_fd=None, *, cleanup_edits=None):
    global STAGE, PPP_PREPARING, NATIVE_PREPARING, NO_INSTALL_WRITES, CLEANUP_ENTERED
    STAGE = 'COMMAND_FAILED'
    token, d = request['backupId'], request['network']
    pending = 'nativePreparation' in before
    backup: dict[str, Any] = dict(machineId=request['machineId'], backupId=token, before=before, network=d,
                  after={k: {**r, 'data': digest(raw(r))} for k, r in after.items()},
                  phase='preparing-native' if pending else 'applying')
    if cleanup_edits:
        need(before.get('boot') == boot(), 'BASELINE_CHANGED')
        backup['phase'] = 'cleaning-foreign'
        xray = cleanup_xray_identity() if any(e[0] in CLEANUP_XRAY_SHA for e in cleanup_edits) else None
        backup['foreignJournal'] = dict(edits=cleanup_edits, editsSha256=digest(encode(cleanup_edits)), done=[], xray=xray)
        need(not pending and lock_fd is not None, 'PREREQUISITE')
        cleanup_runtime(d['fwmark'], has_unit=any(e[0] == 'NETWORK_UNIT_ORPHANED' for e in cleanup_edits))
    payload = encode(backup)
    need(len(payload) <= 2 * MAX_FILE, 'CANDIDATE_INVALID')
    if cleanup_edits:
        # Include VAULT creation in the uncertain boundary. The manifest and
        # global pending marker are independently durable before host edits.
        NO_INSTALL_WRITES = False
        CLEANUP_ENTERED = True
    mkdir(VAULT, 0o700, exist_ok=True)
    mkdir(VAULT + '/' + token, 0o700)
    path = manifest_path(token)
    old_manifest = entry(payload)
    NATIVE_PREPARING = pending
    write(path, None, old_manifest)
    if cleanup_edits:
        with directory(os.path.dirname(VAULT)) as parent:
            os.fsync(parent)
        write(VAULT + '/' + FOREIGN_PENDING, None, cleanup_fence(backup))
        _, live_digest, _, _ = foreign_config_observation(d['fwmark'], detailed=True, vacant=False)
        need(live_digest == request['foreignCleanup']['digest'], 'IN_FLIGHT')
        if request.get('progress') is True:
            install_progress('foreignCleanup')
        old_manifest = cleanup_transition(path, old_manifest, backup, lock_fd)
        if cleanup_reload(cleanup_edits):
            journal = backup['foreignJournal']
            journal['reloadPending'] = True
            intent = entry(encode(backup))
            write(path, old_manifest, intent)
            sc('daemon-reload', wait=12)
            cleanup_guard(backup, lock_fd, journal['xray'])
            del journal['reloadPending']
            old_manifest = entry(encode(backup))
            write(path, intent, old_manifest)
        live = observe_install(request['machineId'], d, before.get('transit'), lock_fd)
        if any(e[0] == 'NETWORK_UNIT_ORPHANED' for e in cleanup_edits):
            # A never-started not-found unit may report a null invocation ID.
            net = live['units'][NET_UNIT]
            if net['InvocationID'] == '0' * 32:
                net['InvocationID'] = ''
        need({**live, 'foreignCleanup': request['foreignCleanup']} == before
             and candidate(request, live) == after, 'BASELINE_CHANGED')
        backup['phase'] = 'applying'
        backup['foreignJournal']['installSettled'] = True
        start = entry(encode(backup))
        write(path, old_manifest, start)
        old_manifest = start

    def checkpoint(settled):
        nonlocal old_manifest
        if cleanup_edits:
            # A client can outlive the helper's flock. Require its durable acknowledgement.
            backup['foreignJournal']['installSettled'] = settled
            nxt = entry(encode(backup))
            write(path, old_manifest, nxt)
            old_manifest = nxt

    def install_service(*args, wait, capture_xray=False, capture_swan=False):
        nonlocal old_manifest
        checkpoint(False)
        sc(*args, wait=wait)
        if cleanup_edits and capture_xray:
            journal = backup['foreignJournal']
            journal.setdefault('xrayBirths', {})[args[1]] = unit(args[1])['InvocationID']
            if journal['xray'] is not None:
                journal['installXray'] = cleanup_xray_identity()
        if capture_swan:
            backup['swanStart'] = swan_started_units(before)
            if not cleanup_edits:
                started = entry(encode(backup))
                write(path, old_manifest, started)
                old_manifest = started
        checkpoint(True)

    if pending:
        need(lock_fd is not None and observe_install(request['machineId'], routing(d), before.get('transit'), lock_fd) == before,
             'BASELINE_CHANGED')
        backup['nativePrepared'] = prepare_native_install(request, before, after, lock_fd)
        confirmed = entry(encode({**backup, 'phase': 'applying'}))
        write(path, old_manifest, confirmed)
        old_manifest = confirmed
        backup['phase'] = 'applying'
        before = runtime_before(backup, preparing_modules=True)
        NATIVE_PREPARING = False
    modules = before.get('pppModules')
    can_undo_modules = not modules or not modules['missing']
    if modules is not None:
        # The live kernel loads are shared and irreversible. Only the exact
        # boot-file generation published here can be released later.
        PPP_PREPARING = True
        need(lock_fd is not None and install_lock_identity(lock_fd) == before['installLock']
             and boot() == before['boot'] and preflight(request['machineId'])['masked'] is False, 'BASELINE_CHANGED')
        if cleanup_edits and 'bootFile' in modules:
            # Rollback owns the receipted boot file, not a newly created parent.
            can_undo_modules = can_undo_modules and recovery_stat(PPP_DIRS[0]) is not None
        if modules['missing'] or 'bootFile' in modules:
            checkpoint(False)
        generation = apply_ppp_preparation(modules)
        if 'bootFile' in modules:
            backup['modulePersistence'] = generation
            check_module_boot_owner(module_boot_owner(backup))
            current = entry(encode(backup))
            write(path, old_manifest, current)
            old_manifest = current
        if any(name in OBSERVERS for name in modules['missing']):
            # Re-run the full baseline and candidate under the reservation,
            # before any VPN config, policy or service changes.
            require_network_observers()
            live = observe(request['machineId'], routing(d), before.get('transit'))
            expected = {k: v for k, v in before.items() if k not in
                        ('installLock', 'pppModules', 'nativeGeneration', 'nativePreparation')}
            if expected['sockets'] is None:
                expected['sockets'] = live['sockets']
            need(live == expected and candidate(request, live, active_probe=True) == after
                 and install_lock_identity(lock_fd) == before['installLock'], 'BASELINE_CHANGED')
            if before['sockets'] is None:
                backup['preparedSockets'] = live['sockets']
                current = entry(encode(backup))
                write(path, old_manifest, current)
                old_manifest = current
                before = runtime_before(backup)
        elif 'bridge' in after:
            # TCP-only SOCKS handoff may allocate a UDP association on the
            # existing daemon. The read-only candidate checks only its bind.
            need(candidate(request, before, active_probe=True) == after, 'BASELINE_CHANGED')
        # Even check-only nft can autoload expression modules. Run it only
        # after the durable host intent and under the reserved host lock.
        command('/usr/sbin/nft', '-c', '-f', '-', data=raw(after['nft']))
        PPP_PREPARING = False
        checkpoint(True)
    if cleanup_edits:
        old_manifest = cleanup_install_files(request, path, old_manifest, backup, lock_fd, after,
                                             can_undo_modules=can_undo_modules)
    else:
        if 'swan' in after:
            old_manifest = write_swan_profile(path, old_manifest, backup, after)
        mkdir(NFT_DIR, 0o755)
        mkdir(DROP_DIR, 0o755)
        paths, originals = operation_files(after), original_files(before, after)
        for key in (*ORDER, 'bridge') if 'bridge' in after else ORDER:
            if originals[key] != after[key]:
                write(paths[key], originals[key], after[key])
    if before.get('installBoot'):
        target = before['units'][XL]['FragmentPath']
        checkpoint(False)
        enroll_boot(target)
        receipt = boot_link()
        need(receipt and receipt[0] == target, 'ROLLBACK_DRIFT')
        backup['bootEnrollment'] = receipt
        current = entry(encode(backup))
        write(path, old_manifest, current)
        old_manifest = current
        checkpoint(True)
    if request.get('progress') is True:
        install_progress('restart')
    install_service('daemon-reload', wait=12)
    if 'bridge' in after:
        need(xray_accounts_match(unit(B), before['units'][B]), 'ROLLBACK_DRIFT')
        install_service('restart', B, wait=22, capture_xray=True)
    x = unit(X)
    retained_xray_dropin(x, before['units'][X])
    need(xray_accounts_match(x, before['units'][X]), 'ROLLBACK_DRIFT')
    install_service('restart', X, wait=22, capture_xray=True)
    if before.get('ikeSockets'):
        install_service('restart', IKE, wait=22)
    no_jobs(UNITS)
    if 'swan' in after:
        check_swan_profile(backup, read(SWAN_PROFILE))
        units = {n: unit(n) for n in SWAN_START_UNITS}
        ike = units[IKE]
        removal_dependencies(units, installed=True)
        need(all(swan_unstarted(units[n], before, n) for n in SWAN_START_UNITS)
             and not any(port in (500, 4500, 1701) for _, _, port, _ in sock_rows()), 'ROLLBACK_DRIFT')
        need(removal_native(ike, IKE, before, installed=False) and not ike.get('PassEnvironment')
             and not ike.get('ExecCondition') and all(ike.get(k) == v for k, v in before['units'][IKE].items()),
             'ROLLBACK_DRIFT')
        swan_default_environment('ROLLBACK_DRIFT')
    if 'swan' in after and pinned_network_manifest(d, token, backup):
        # Settle the policy start before XL's parallel Requires jobs can start
        # IKE. A failed policy start can then be rolled back without claiming
        # ownership of an unrecorded VPN daemon invocation.
        install_service('start', NET_UNIT, wait=24)
    # A settled start and named invocations must be durable together.
    install_service('start', XL, wait=26, capture_swan='swan' in after)
    # Type=simple may be active before its API/UDP listeners are present.
    ready_by = min(DEADLINE, time.monotonic() + 6)
    while True:
        try:
            runtime = installed_runtime(d, token, before, after)
            break
        except Refusal as error:
            if str(error) not in ('RUNTIME_UNPROVED', 'PROFILE_USERS') or time.monotonic() >= ready_by:
                raise
            time.sleep(0.2)
    need(runtime.get('bootEnrollment') == backup.get('bootEnrollment'), 'ROLLBACK_DRIFT')
    if 'swan' in after:
        need(runtime['files']['swan'] == backup['swanGeneration']
             and runtime['invocations'][1:4] == backup['swanStart'], 'ROLLBACK_DRIFT')
    if cleanup_edits:
        verify_retained_cleanup_edits(backup)
    backup.update(phase='installed', runtime=runtime)
    write(path, old_manifest, entry(encode(backup)))
    if cleanup_edits:
        clear_cleanup_fence(backup)
        need(time.monotonic() < DEADLINE, 'IN_FLIGHT')


def after_match(record, expected):
    return record is not None and {**record, 'data': digest(raw(record))} == expected


CHAP_ACTIONS = ('check-chap', 'sync-chap', 'inspect-chap', 'read-chap-generation', 'fence-chap')
CHAP_GENERATION_PREFIX = 'installed-chap-v2:'
APPLY_NETWORK_ACTIONS = ('check-apply-network', 'prepare-apply-network', 'verify-apply-network', 'restart-apply-network',
                         'publish-apply-profiles', 'finalize-apply-profiles')
APPLY_PROFILES_PHASE = 'apply-profiles-pending'
# Exact fragment from generateBridgeSystemdService; stdin cannot select a
# different privileged service definition.
APPLY_BRIDGE_UNIT_SHA = '8419e3b8dc8345ed8f7c1ce585a1e8bd6300134d040fef2de70535aee773696a'
CHAP_BEGIN = b'# BEGIN CELERITY MANAGED L2TP USERS'
CHAP_END = b'# END CELERITY MANAGED L2TP USERS'
CHAP_LOGIN = rb'[A-Za-z0-9._@-]{1,64}'
CHAP_QUOTED_BYTE = rb'(?:[ !#-\[\]-~]|\\["\\])'
CHAP_ROW = re.compile(rb'"(' + CHAP_LOGIN + rb')" l2tpd "(' + CHAP_QUOTED_BYTE + rb'{1,255}|[A-Za-z0-9_-]{256})" ([0-9.]{7,15})')
CHAP_FOREIGN_TOKEN = re.compile(rb'(?:"' + CHAP_QUOTED_BYTE + rb'''*"|'[ -&(-\[\]-~]*'|[!$-&(-\[\]-~]+)''')


def chap_generation(phase):
    match = re.fullmatch(CHAP_GENERATION_PREFIX + r'([a-f0-9]{32})', phase) if type(phase) is str else None
    return match[1] if match else None


def installed_phase(phase):
    # Keep the real phase in the parsed backup. In particular, when Apply
    # rewrites its receipt it must not publish the legacy 'installed' again.
    return phase == 'installed' or chap_generation(phase) is not None


def chap_pool(lns, cidr):
    bounds = re.findall(rb'^ip range = ([0-9.]{7,15})-([0-9.]{7,15})$', lns, re.M)
    need(len(bounds) == 1, 'ROLLBACK_DRIFT')
    first, last = (ipaddress.IPv4Address(v.decode('ascii')) for v in bounds[0])
    network = ipaddress.IPv4Network(cidr)
    need(network.network_address < first <= last < network.broadcast_address, 'ROLLBACK_DRIFT')
    return first, last


def chap_user_rows(users: Any, pool):
    bad = 'CANDIDATE_INVALID'
    need(type(users) is list and len(users) <= 2048, bad)
    rows, logins, addresses = {}, set(), set()
    for row in cast(list[dict[str, Any]], users):
        need(type(row) is dict and set(row) == {'login', 'password', 'ipAddress', 'enabled'}
             and type(row['enabled']) is bool and all(type(row[k]) is str for k in ('login', 'password', 'ipAddress')), bad)
        login, password, address = (row[k].encode('ascii') for k in ('login', 'password', 'ipAddress'))
        need(re.fullmatch(CHAP_LOGIN, login) and (re.fullmatch(rb'[ -~]{1,255}', password)
             or re.fullmatch(rb'[A-Za-z0-9_-]{256}', password))
             and not password.startswith(b'@') and login not in logins and address not in addresses
             and pool[0] <= ipaddress.IPv4Address(row['ipAddress']) <= pool[1], bad)
        logins.add(login)
        addresses.add(address)
        if row['enabled']:
            quoted = password.replace(b'\\', b'\\\\').replace(b'"', b'\\"')
            rows[login] = b'"' + login + b'" l2tpd "' + quoted + b'" ' + address + b'\n'
    return rows, logins


def chap_parts(record):
    bad = 'ROLLBACK_DRIFT'
    need(record is not None and (record['mode'], record['gid'], record.get('uid', 0)) == (0o600, 0, 0), bad)
    data = raw(record)
    markers, offset = [], 0
    for line in data.split(b'\n'):
        if line.strip(b' \t\r\v\f') in (CHAP_BEGIN, CHAP_END):
            markers.append((line, offset))
        offset += len(line) + 1
    need([line for line, _ in markers] == [CHAP_BEGIN, CHAP_END], bad)
    start, end = markers[0][1], markers[1][1] + len(CHAP_END) + 1
    need(data[end-1:end] == b'\n', bad)
    block = data[start:end]
    lines = block.split(b'\n')[1:-2]
    need(len(lines) <= 2048, bad)
    rows, addresses = {}, set()
    for line in lines:
        match = CHAP_ROW.fullmatch(line)
        if match is None:
            raise Refusal(bad)
        login, password, address = match.groups()
        # Legacy Install allowed a 256-byte base64url secret; its original
        # block remains removable even without a DB projection on the wire.
        need(not password.startswith(b'@') and login not in rows and address not in addresses, bad)
        rows[login] = line + b'\n'
        addresses.add(address)
    return data[:start], block, data[end:], rows


def check_chap_neighbors(data, logins):
    for source in data.split(b'\n'):
        line = source.removesuffix(b'\r').lstrip(b' \t')
        if not line or line.startswith(b'#'):
            continue
        # Do not interpret a continuation, escaped name or ambiguous active
        # line as unrelated. Inline and full-line comments remain opaque.
        names, count = [], 0
        need(len(line) <= 8192, 'ROLLBACK_DRIFT')
        while line and not line.startswith(b'#'):
            match = CHAP_FOREIGN_TOKEN.match(line)
            if not match:
                raise Refusal('ROLLBACK_DRIFT')
            if count < 2:
                word = match.group()
                need(b'\\' not in word and len(word) <= 255, 'ROLLBACK_DRIFT')
                names.append(word[1:-1] if word.startswith((b'"', b"'")) else word)
            count += 1
            tail = line[match.end():]
            need(not tail or tail[:1] in (b' ', b'\t', b'#'), 'ROLLBACK_DRIFT')
            line = tail.lstrip(b' \t')
        need(count >= 3, 'ROLLBACK_DRIFT')
        login, server = names
        need(login not in logins and not (logins and login == b'*' and server in (b'*', b'l2tpd')), 'ROLLBACK_DRIFT')


def owned_chap(record, backup, expected=None):
    prefix, block, suffix, rows = chap_parts(record)
    if expected is None:
        # Released Install appended LF + managed block to the saved preimage.
        # Authenticate against that install receipt, never the current prefix.
        original = backup['before']['files']['chap']
        need(original is not None and after_match(entry(raw(original) + b'\n' + block), backup['after']['chap']), 'ROLLBACK_DRIFT')
        logins = rows.keys()
    else:
        expected_rows, logins = expected
        need(rows == expected_rows, 'ROLLBACK_DRIFT')
    check_chap_neighbors(prefix, logins)
    check_chap_neighbors(suffix, logins)
    return prefix, suffix, rows


def chap_expected(request, lns):
    if 'currentUsers' in request:
        need(lns is not None, 'ROLLBACK_DRIFT')
        return chap_user_rows(request['currentUsers'], chap_pool(raw(lns), request['network']['clientCidr']))
    return None


def chap_rows_digest(rows):
    return digest(b''.join(rows[key] for key in sorted(rows)))


def remove_chap(record, backup, expected):
    prefix, suffix, rows = owned_chap(record, backup, expected)
    need(record is not None, 'ROLLBACK_DRIFT')
    # Install added one LF. The exact saved prefix proves which byte it owns;
    # never trim an edited prefix. Keep that LF if dropping it would join the
    # original unterminated line to an independently appended suffix.
    original = backup['before']['files']['chap']
    original_bytes = raw(original) if original is not None else None
    if original_bytes is not None and prefix == original_bytes + b'\n':
        if not suffix:
            return original, chap_rows_digest(rows)
        if not original_bytes or original_bytes.endswith(b'\n') or suffix.startswith(b'\n'):
            prefix = original_bytes
    return {**record, 'data': b64(prefix + suffix)}, chap_rows_digest(rows)


def check_swan_profile(backup, record, bad='ROLLBACK_DRIFT'):
    before = backup['before']
    if 'swan' not in before['files']:
        # No enrollment or rebinding of an older manifest.
        need('swan' not in backup['after'] and 'swanGeneration' not in backup, bad)
        return
    generation = backup.get('swanGeneration')
    need('swan' in backup['after'] and before['files']['swan'] is None
         and before['units'][IKE]['ActiveState'] == 'inactive' and not before.get('ikeSockets')
         and swan_inputs(record is not None, bad) == before['swanInputs'], bad)
    if record is None:
        need(backup['phase'] == 'applying' and generation is None, bad)
    else:
        need(generation is not None and record == entry(SWAN_SETTINGS, 0o644)
             and after_match(record, backup['after']['swan']) and remove_generation(SWAN_PROFILE) == generation, bad)
    no_swan_rule()


def load_after(backup, require_all=False):
    current = {key: read(path) for key, path in operation_files(backup['after']).items()}
    check_swan_profile(backup, current.get('swan'))
    original = original_files(backup['before'], current)
    for key, value in current.items():
        need(after_match(value, backup['after'][key]) or (not require_all and value == original[key]),
             'ROLLBACK_DRIFT')
    return current


def rollback(request, path, old_manifest, backup, *, cleanup=False):
    global STAGE
    STAGE = 'COMMAND_FAILED'
    if cleanup:
        cleanup_no_remove(path)
    was_installed = installed_phase(backup['phase'])
    need(backup['phase'] == 'applying' or was_installed, 'ROLLBACK_DRIFT')
    # Reattestation does not transfer the original Install rollback authority,
    # even if only a service (not the machine boot) changed generation.
    need(not was_installed or 'boot' not in backup['runtime'], 'ROLLBACK_DRIFT')
    unwritten = cleanup and not was_installed and backup['foreignJournal'].get('installSettled') is True
    module_owner = module_boot_owner(backup, unwritten=True) if unwritten else module_boot_owner(backup)
    check_module_boot_owner(module_owner)
    before, d, token = runtime_before(backup), request['network'], request['backupId']
    no_jobs(UNITS)
    sidecar = 'bridge' in backup['after']
    neighbors(before, sidecar)
    current = load_after(backup, require_all=was_installed)
    need(ike_include_matches(current['starter'], [os.path.basename(NAMES['ike'])] if current['ike'] is not None else []),
         'ROLLBACK_DRIFT')
    boot_enrollment = boot_link() if before.get('installBoot') else None
    need(boot_enrollment == backup.get('bootEnrollment'), 'ROLLBACK_DRIFT')
    need(vpn_empty(allow_socket_policies=True), 'ROLLBACK_DRIFT')
    pinned = pinned_network_manifest(d, token, backup)
    policy = network_projection(d, token, pinned=pinned)
    if pinned:
        # A partial start only adds nft -> route -> rule. Refuse non-prefix
        # states and never remove policy without an installed unit postimage.
        need((not policy['rule'] or policy['route']) and
             (not policy['route'] or policy['nft'] is not None) and
             (not any(policy.values()) or current['net'] is not None and current['nft'] is not None), 'ROLLBACK_DRIFT')
    watched = (X, XL, IKE, NET_UNIT, B) if sidecar else (X, XL, IKE, NET_UNIT)
    swan_units = None
    started = None
    partial_start = False
    if 'swan' in current:
        swan_units = {n: unit(n) for n in SWAN_START_UNITS}
        started = backup.get('swanStart')
        if started is None:
            net = swan_units[NET_UNIT]
            net_unstarted = swan_unstarted(net, before, NET_UNIT)
            if not net_unstarted and pinned:
                # The pinned oneshot is now started separately, before the VPN
                # daemons. Admit only a settled, exact managed NET generation.
                need(current['net'] is not None and current['nft'] is not None
                     and network_unit_loaded(net, False, current['net'])
                     and ((net['ActiveState'], net['SubState']) == ('failed', 'failed')
                          or (net['ActiveState'], net['SubState']) == ('active', 'exited') and all(policy.values())),
                     'ROLLBACK_DRIFT')
                removal_dependencies(swan_units, installed=True)
                net_unstarted = True
            need(not was_installed and net_unstarted and all(swan_unstarted(swan_units[n], before, n) for n in (XL, IKE))
                 and not any(port in (500, 4500, 1701) for _, _, port, _ in sock_rows()), 'ROLLBACK_DRIFT')
        else:
            need(current['swan'] is not None and started == [swan_units[n].get('InvocationID') for n in SWAN_START_UNITS]
                 and (not was_installed or started == backup['runtime']['invocations'][1:4]), 'ROLLBACK_DRIFT')
            removal_dependencies(swan_units, installed=True)
            ike = swan_units[IKE]
            need(removal_native(ike, IKE, before, installed=True) and not ike.get('PassEnvironment'), 'ROLLBACK_DRIFT')
            partial_start = not was_installed
            if partial_start:
                need(removal_native(swan_units[XL], XL, before, installed=True), 'ROLLBACK_DRIFT')
                applying_vpn_ownership(sock_rows(), swan_units)
            else:
                removal_vpn_runtime(sock_rows(), swan_units)
    if was_installed:
        expected = backup['runtime']
        need(policy == {'nft': expected['nft'], 'rule': True, 'route': True}
             and file_generations(current) == expected['files']
             and [unit(n).get('InvocationID') for n in watched] == expected['invocations'], 'ROLLBACK_DRIFT')

    # Do not stop an administrator replacement or unmask a unit. Failed
    # first start can leave a failed (but never active at baseline) stock unit.
    for n in watched:
        info = unit(n)
        need(info['ActiveState'] in ('inactive', 'active', 'failed') and info['LoadState'] != 'masked', 'ROLLBACK_DRIFT')
        if n in (XL, IKE):
            need(native_vpn(info, n) or (info['NeedDaemonReload'] == 'yes' and info['ActiveState'] == 'inactive' and
                 info.get('FragmentPath') == before['units'][n]['FragmentPath']), 'ROLLBACK_DRIFT')
            allowed = ('enabled', 'disabled') if n == XL and boot_enrollment else (before['units'][n]['UnitFileState'],)
            need(info['UnitFileState'] in allowed and
                 info.get('DropInPaths') in (('', DROP) if n == XL else ('',)), 'ROLLBACK_DRIFT')
        if n == NET_UNIT:
            need(info['LoadState'] == 'not-found' or info.get('FragmentPath') == NET, 'ROLLBACK_DRIFT')
        if n == X:
            need(info['FragmentPath'] == before['units'][n]['FragmentPath']
                 and xray_accounts_match(info, before['units'][n]), 'ROLLBACK_DRIFT')
            retained_xray_dropin(info, before['units'][n])
            if working(info):
                original_invocation = info['InvocationID'] == before['units'][n]['InvocationID']
                xray_users(before['files']['main'] if original_invocation else current['main'], info, sock_rows(), before.get('transit'))
        if n == B:
            need(xray_accounts_match(info, before['units'][n]), 'ROLLBACK_DRIFT')
            if working(info):
                xray_argv(info, BRIDGE)
    if swan_units is not None and partial_start:
        no_jobs(UNITS)
        need(all(unit(n) == info for n, info in swan_units.items()), 'ROLLBACK_DRIFT')
    backup['phase'] = 'rolling-back'
    rolling = entry(encode(backup))
    write(path, old_manifest, rolling)
    for n in SWAN_START_UNITS:
        info = unit(n)
        if swan_units is not None:
            if started is None:
                if n == NET_UNIT and pinned:
                    no_jobs(UNITS)
                    need(info == swan_units[n] and unit(n) == info
                         and all(swan_unstarted(unit(k), before, k) for k in (XL, IKE))
                         and not any(port in (500, 4500, 1701) for _, _, port, _ in sock_rows()), 'ROLLBACK_DRIFT')
                else:
                    need(swan_unstarted(info, before, n), 'ROLLBACK_DRIFT')
            else:
                initial = swan_units[n]
                need(info.get('InvocationID') == initial.get('InvocationID'), 'ROLLBACK_DRIFT')
                if partial_start:
                    # Do not rebaseline ownership after recording rollback intent.
                    need(all(info.get(k) == initial.get(k) for k in ('MainPID', 'ControlGroup')), 'ROLLBACK_DRIFT')
                removal_dependencies({n: info}, installed=True)
        if swan_units is not None and partial_start and n == XL:
            ike = unit(IKE)
            need(ike == swan_units[IKE] and removal_native(info, XL, before, installed=True), 'ROLLBACK_DRIFT')
            check_swan_profile(backup, read(SWAN_PROFILE))
            applying_vpn_ownership(sock_rows(), {IKE: ike, XL: info})
            no_jobs(UNITS)
            need(unit(IKE) == ike and unit(n) == info, 'ROLLBACK_DRIFT')
        if n == IKE and 'swan' in current:
            if current['swan'] is None:
                need(read(SWAN_PROFILE) is None and swan_inputs(False, 'ROLLBACK_DRIFT') == before['swanInputs'],
                     'ROLLBACK_DRIFT')
                no_swan_rule()
            else:
                check_swan_profile(backup, read(SWAN_PROFILE))
            if started is not None:
                need(removal_native(info, IKE, before, installed=True) and not info.get('PassEnvironment'), 'ROLLBACK_DRIFT')
                xl = unit(XL)
                if partial_start:
                    need(rollback_quiescent(xl), 'ROLLBACK_DRIFT')
                removal_vpn_runtime(sock_rows(), {IKE: info, XL: xl})
                if partial_start:
                    no_jobs(UNITS)
                    need(unit(XL) == xl and unit(n) == info, 'ROLLBACK_DRIFT')
        if partial_start and n == NET_UNIT:
            # Stopping this dependency must not stop a new dependent generation.
            dependents = {name: unit(name) for name in (XL, IKE)}
            need(all(rollback_quiescent(u) for u in dependents.values()), 'ROLLBACK_DRIFT')
            removal_vpn_runtime(sock_rows(), dependents)
            no_jobs(UNITS)
            need(all(unit(name) == u for name, u in dependents.items()) and unit(n) == info, 'ROLLBACK_DRIFT')
        if info['LoadState'] == 'loaded' and info['ActiveState'] != 'inactive':
            sc('stop', n, wait=14)
            no_jobs(UNITS)
            if unit(n)['ActiveState'] == 'failed':
                sc('reset-failed', n)
    need(vpn_empty() and not any(p == 'udp' and port in (500, 4500, 1701) for p, a, port, owners in sock_rows()),
         'RUNTIME_UNPROVED')
    if pinned:
        need(network_projection(d, token, pinned=True) == policy, 'ROLLBACK_DRIFT')
    if policy['rule']:
        command('/usr/sbin/ip', '-4', 'rule', 'del', 'priority', str(PRIORITY), 'from', d['clientCidr'],
                'fwmark', str(d['fwmark']), 'table', str(d['routeTable']))
    if pinned:
        need(network_projection(d, token, pinned=True) == {**policy, 'rule': False}, 'ROLLBACK_DRIFT')
    if policy['route']:
        command('/usr/sbin/ip', '-4', 'route', 'del', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', str(d['routeTable']))
    if policy['nft'] is not None:
        if pinned:
            need(network_projection(d, token, pinned=True) == {**policy, 'rule': False, 'route': False}, 'ROLLBACK_DRIFT')
        else:
            need(nft_projection(token) == policy['nft'], 'ROLLBACK_DRIFT')
        command('/usr/sbin/nft', 'delete', 'table', 'inet', TABLE)
    paths, originals = operation_files(current), original_files(before, current)
    for k in reversed(operation_order(current)):
        if current[k] != originals[k]:
            if k == 'swan':
                check_swan_profile(backup, read(SWAN_PROFILE))
            write(paths[k], current[k], originals[k])
    if boot_enrollment:
        enroll_boot(before['units'][XL]['FragmentPath'], boot_enrollment)
    for p in (DROP_DIR, NFT_DIR):
        if not directory_absent(p):
            rmdir(p)
    sc('daemon-reload', wait=12)
    if sidecar:
        b = unit(B)
        if not working(b) or (current['bridge'] != originals['bridge'] and
                              (not cleanup or b['InvocationID'] != before['units'][B]['InvocationID'])):
            need(xray_accounts_match(b, before['units'][B]), 'ROLLBACK_DRIFT')
            sc('restart', B, wait=22)
    x = unit(X)
    retained_xray_dropin(x, before['units'][X])
    need(xray_accounts_match(x, before['units'][X]), 'ROLLBACK_DRIFT')
    if not working(x) or (current['main'] != before['files']['main'] and
                          (not cleanup or x['InvocationID'] != before['units'][X]['InvocationID'])):
        sc('restart', X, wait=22)
    if before.get('ikeSockets'):
        sc('start', IKE, wait=22)
    identity = None
    if cleanup and backup['foreignJournal']['xray'] is not None:
        identity = cleanup_xray_identity()
    verify_rollback(d, token, backup)
    if identity is not None:
        need(cleanup_xray_identity() == identity, 'IN_FLIGHT')
        backup['foreignJournal']['rollbackXray'] = identity
    need(read(path, 2 * MAX_FILE) == rolling, 'ROLLBACK_DRIFT')
    release_module_boot(module_owner)
    backup['phase'] = 'projected-rollback' if cleanup else 'rolled-back'
    write(path, rolling, entry(encode(backup)))


def verify_rollback(d, token, backup, *, projection=None):
    projection = projection or {}
    before = runtime_before(backup)
    paths = operation_files(backup['after'])
    originals = original_files(before, paths)
    sidecar = 'bridge' in paths
    no_jobs(UNITS)
    neighbors(before, sidecar)
    if 'swan' in paths:
        need(swan_inputs(False, STAGE, **({'removed': True} if SWAN_PROFILE in projection else {})) == before['swanInputs'], STAGE)
    if sidecar:
        bpid = xray_argv(unit(B), BRIDGE)
        handoff = next(i['port'] for i in json.loads(raw(originals['bridge']))['inbounds'] if i['tag'] == 'rebuild-relay-ingress')
        verify_socks_handoff(sock_rows(), handoff, bpid)
    need(all(p in projection or directory_absent(p) for p in (DROP_DIR, NFT_DIR)) and
         {key: projection[p] if p in projection else read(p) for key, p in paths.items()} == originals and
         (not before.get('installBoot') or boot_link() is None) and
         network_projection(d, token, pinned=pinned_network_manifest(d, token, backup))
         == {'nft': None, 'rule': False, 'route': False}
         and vpn_empty(allow_socket_policies=bool(before.get('ikeSockets'))), 'RUNTIME_UNPROVED')
    vpn_units = {n: unit(n) for n in (XL, IKE, NET_UNIT)}
    if NET in projection or DROP in projection:
        vpn_units = cleanup_project_units(vpn_units, projection)
    for n, info in vpn_units.items():
        fields = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'DropInPaths', 'FragmentPath')
        need(all(info.get(k) == before['units'][n][k] for k in fields), 'RUNTIME_UNPROVED')
        need((n == IKE and before.get('ikeSockets')) or info.get('MainPID') == before['units'][n]['MainPID'], 'RUNTIME_UNPROVED')
    rows = sock_rows()
    restored_ike = before.get('ikeSockets')
    if restored_ike:
        need(idle_ike(unit(IKE), rows) == restored_ike, 'RUNTIME_UNPROVED')
    reserved = (1701, d['tproxyPort']) if restored_ike else (500, 4500, 1701, d['tproxyPort'])
    x = unit(X)
    same_xray_dropin(x, before['units'][X])
    need(xray_accounts_match(x, before['units'][X]) and
         xray_users(before['files']['main'], x, rows, before.get('transit')) == before['sockets'] and
         not any(port in reserved for p, a, port, owners in rows), 'RUNTIME_UNPROVED')
    no_jobs(UNITS)


def unique_profile(record):
    def unique(pairs):
        result = dict(pairs)
        # Go's struct parser folds Unicode aliases too (e.g. long s → s).
        need(len({k.casefold() for k, _ in pairs}) == len(pairs), 'CANDIDATE_INVALID')
        return result

    def invalid(_):
        raise Refusal('CANDIDATE_INVALID')

    value = json.loads(raw(record).decode('utf-8'), object_pairs_hook=unique, parse_constant=invalid)
    need(all(type(rows) is list and all(type(row) is dict for row in rows)
             for rows in (value['inbounds'], value['outbounds'], value['routing']['rules'])), 'CANDIDATE_INVALID')
    return value


FOLLOW_RELAY_SOCKS = 'rebuild-relay-ingress'
FOLLOW_RELAY_HOP = 'rebuild-l2tp-handoff'
FOLLOW_RELAY_BLOCK = 'rebuild-l2tp-block'


def follow_relay_reserved(value, shared=False):
    return isinstance(value, str) and (value.startswith('relay-l2tp-')
        or value in (FOLLOW_RELAY_HOP, FOLLOW_RELAY_BLOCK) or (not shared and value == FOLLOW_RELAY_SOCKS))


def follow_relay_refs(value, shared=False):
    if type(value) is dict:
        return any(follow_relay_reserved(k, shared) or follow_relay_refs(v, shared) for k, v in value.items())
    if type(value) is list:
        return any(follow_relay_refs(v, shared) for v in value)
    return follow_relay_reserved(value, shared)


def follow_relay_port_conflict(inbounds, ports):
    for inbound in inbounds:
        for part in str(inbound.get('port', '')).split(','):
            m = re.fullmatch(r'\s*(\d+)(?:-(\d+))?\s*', part)
            if m is None:
                raise Refusal('CANDIDATE_INVALID')
            if any(int(m[1]) <= p <= int(m[2] or m[1]) for p in ports):
                return True
    return False


def follow_relay_tproxy(tag, port):
    return dict(tag=tag, listen='0.0.0.0', port=port, protocol='dokodemo-door',
                settings=dict(network='tcp,udp', followRedirect=True), streamSettings={'sockopt': {'tproxy': 'tproxy'}})


def follow_relay_hop(port):
    return dict(tag=FOLLOW_RELAY_HOP, protocol='socks', settings={'servers': [dict(address='127.0.0.1', port=port)]})


def follow_relay_guard(rule, scope):
    if rule.get('inboundTag') != [scope] or rule.get('outboundTag') != FOLLOW_RELAY_BLOCK:
        return None
    bad = 'CANDIDATE_INVALID'
    keys = set(rule) - {'type', 'inboundTag', 'outboundTag'}
    need(keys in ({'domain'}, {'ip'}) and rule.get('type') == 'field', bad)
    selector = next(iter(keys))
    values = rule[selector]
    need(type(values) is list and values and all(type(v) is str and v for v in values)
         and values == sorted(set(values)), bad)
    values = cast(list[str], values)
    if selector == 'domain':
        need(all(re.fullmatch(r'full:[a-z0-9.-]+', v) for v in values), bad)
    else:
        need('geoip:private' in values, bad)
        for value in values:
            if value != 'geoip:private':
                ipaddress.ip_network(value, strict=False) if '/' in value else ipaddress.ip_address(value)
    return selector, values


def validate_portal_rules(current, rules, shared_scope, targets):
    # Same narrow shape as the stock install validator. None of these rules
    # may lose a scope or otherwise change during subtraction.
    bad = 'CANDIDATE_INVALID'
    seen = set()
    pending = None
    for rule in rules:
        label = rule['ruleTag']
        match = re.fullmatch(r'rebuild-policy-portal-([0-9a-f]{8})-(?:default|geo-(?:0|[1-9][0-9]*)-(ip|domain))', label)
        need(match is not None, bad)
        suffix, geo = match.groups()
        scope, out = rule.get('inboundTag'), rule.get('outboundTag')
        keys = {'type', 'ruleTag', 'inboundTag', 'outboundTag'}
        if geo:
            keys.add(geo)
            values = rule.get(geo)
            need(type(values) is list and values and all(type(v) is str and v for v in values), bad)
        need(rule.get('type') == 'field' and set(rule) == keys and type(scope) is list and len(scope) == 1
             and scope[0] in shared_scope and type(out) is str and not follow_relay_refs(rule), bad)

        forward_tag, native_tag = 'fwd-hop-' + suffix, 'rebuild-rp-ingress-' + suffix
        forward = next((i for i in current['inbounds'] if i['tag'] == forward_tag), None)
        native = [o for o in current['outbounds'] if o.get('settings', {}).get('reverse', {}).get('tag') == native_tag]
        if scope == [forward_tag] and forward is not None:
            clients = forward.get('settings', {}).get('clients')
            need(not native and forward.get('protocol') in ('vless', 'vmess') and type(clients) is list
                 and len(clients) == 1 and type(clients[0]) is dict and set(clients[0]) == {'id'}
                 and type(clients[0]['id']) is str and re.fullmatch(r'\S+', clients[0]['id']), bad)
        else:
            need(scope == [native_tag] and forward is None and all(i['tag'] != native_tag for i in current['inbounds'])
                 and len(native) == 1 and native[0].get('protocol') == 'vless'
                 and native[0]['tag'] == 'rebuild-rp-dial-' + suffix, bad)

        kind = targets.get(out)
        reverse = re.fullmatch(r'rebuild-rp-egress-([0-9a-f]{8})', out)
        need((geo and out == 'block' and kind == 'blackhole')
             or (kind in ('vless', 'vmess') and re.fullmatch(r'fwd-[0-9a-f]{8}', out)
                 and 'reverse' not in next(o for o in current['outbounds'] if o['tag'] == out).get('settings', {}))
             or (kind == 'native' and reverse and any(i['tag'] == 'rebuild-rp-conn-' + reverse[1]
                 and i.get('protocol') == 'vless' and len(i.get('settings', {}).get('clients', [])) == 1
                 and i['settings']['clients'][0].get('reverse', {}).get('tag') == out for i in current['inbounds'])), bad)
        need(pending in (None, suffix) and label not in seen and f'rebuild-policy-portal-{suffix}-default' not in seen, bad)
        seen.add(label)
        pending = suffix if geo else None
    need(pending is None, bad)


def subtract_follow_relay(main, current, side, node_id, tproxy):
    # Inverse of attachLocalFollowRelay, against CURRENT, not the install
    # preimage. Recognize the two fixed listeners, two outbounds and precisely
    # scoped guards. Only canonical shared policy / subscriber denies may lose
    # an inboundTag entry. Never convert a singleton into an unscoped rule.
    ppp, socks, hop, block = ('relay-l2tp-' + node_id, FOLLOW_RELAY_SOCKS, FOLLOW_RELAY_HOP, FOLLOW_RELAY_BLOCK)
    port = 18000 + int(digest(f'cascade-path-ingress:{node_id}:follow-relay-v1'.encode())[:8], 16) % 2000
    bad = 'CANDIDATE_INVALID'
    need(port != tproxy, bad)
    rules = current['routing']['rules']
    reserved = follow_relay_reserved
    ppp_in = follow_relay_tproxy(ppp, tproxy)
    own_in = [i for i in current['inbounds'] if reserved(i.get('tag'))]
    need([i.get('tag') for i in own_in] == [ppp, socks] and encode(own_in[0]) == encode(ppp_in), bad)
    route_only = own_in[1].get('sniffing', {}).get('routeOnly')
    need(type(route_only) is bool, bad)
    socks_in = dict(tag=socks, port=port, listen='127.0.0.1', protocol='socks',
                    settings=dict(auth='noauth', udp=True, ip='127.0.0.1'),
                    sniffing=dict(enabled=True, destOverride=['http', 'tls', 'quic'], routeOnly=route_only))
    need(encode(own_in[1]) == encode(socks_in), bad)
    current['inbounds'] = [i for i in current['inbounds'] if not reserved(i.get('tag'))]
    need(not follow_relay_port_conflict(current['inbounds'] + (side['inbounds'] if side else []), (port, tproxy))
         and not follow_relay_refs(side), bad)

    outbounds = current['outbounds']
    need(outbounds[0].get('protocol') == 'blackhole' and not reserved(outbounds[0].get('tag')), bad)
    need(encode([o for o in outbounds if reserved(o.get('tag'))]) ==
         encode([dict(tag=block, protocol='blackhole'), follow_relay_hop(port)]), bad)
    current['outbounds'] = [o for o in outbounds if not reserved(o.get('tag'))]

    def strings(values):
        return type(values) is list and bool(values) and all(type(v) is str and v for v in values)

    guards = {ppp: [], socks: []}
    policy = {}
    portal = []
    kept = []
    handoff = 0
    plain = {'type', 'inboundTag', 'outboundTag'}
    tags = [i.get('tag') for i in current['inbounds']]
    need(strings(tags) and len(set(tags)) == len(tags), bad)
    subscribers = {t for t in tags if t != 'API_INBOUND' and not t.startswith(('fwd-hop-', 'rebuild-rp-conn-'))}
    transit = {t for t in tags if t.startswith('fwd-hop-')}
    targets = {}
    for o in current['outbounds']:
        need(type(o.get('tag')) is str and o['tag'] not in targets, bad)
        targets[o['tag']] = o.get('protocol')
        tag = o.get('settings', {}).get('reverse', {}).get('tag')
        if tag is not None:
            need(type(tag) is str and tag not in tags and tag not in transit, bad)
            transit.add(tag)
    for i in current['inbounds']:
        for client in i.get('settings', {}).get('clients', []):
            tag = client.get('reverse', {}).get('tag')
            if tag is not None:
                need(type(tag) is str and tag not in targets and i.get('protocol') == 'vless', bad)
                targets[tag] = 'native'
    for rule in rules:
        scope, target = rule.get('inboundTag', []), rule.get('outboundTag')
        need(scope == [] or strings(scope), bad)
        label = rule.get('ruleTag', '')
        need(type(label) is str, bad)
        if label.startswith('rebuild-policy-portal-'):
            need(not policy, bad)
            portal.append(rule)
            kept.append(rule)
        elif scope == [ppp] and target == hop:
            need(set(rule) == plain and rule['type'] == 'field', bad)
            handoff += 1
        elif scope in ([ppp], [socks]) and target == block:
            guards[scope[0]].append(follow_relay_guard(rule, scope[0]))
        elif label.startswith('rebuild-policy-'):
            selector = re.fullmatch(r'rebuild-policy-geo-\d+-(ip|domain)', label)
            keys = plain | {'ruleTag'}
            if selector:
                keys.add(selector[1])
                need(strings(rule.get(selector[1])), bad)
            need((selector or label == 'rebuild-policy-default') and label not in policy and set(rule) == keys
                 and rule['type'] == 'field' and len(scope) > 1 and scope[-1] == socks and len(set(scope)) == len(scope)
                 and set(scope[:-1]) <= subscribers | transit and targets.get(target) in ('blackhole', 'vless', 'vmess', 'native'), bad)
            policy[label] = scope[:-1]
            kept.append({**rule, 'inboundTag': scope[:-1]})
        elif socks in scope:
            # The only unlabelled shared rules are subscriber ACLs targeting
            # the original blackhole. Do not strip from API or tunnel rules.
            need(len(scope) > 1 and scope[-1] == socks and set(scope[:-1]) <= subscribers
                 and set(rule) <= plain | {'ip', 'domain', 'ruleTag'} and rule.get('type') == 'field'
                 and all(strings(rule[k]) for k in ('ip', 'domain') if k in rule)
                 and len(set(scope)) == len(scope) and targets.get(target) == 'blackhole', bad)
            kept.append({**rule, 'inboundTag': scope[:-1]})
        else:
            kept.append(rule)
    need(handoff == 1 and guards[ppp] == guards[socks] and [key for key, _ in guards[ppp]] in (['ip'], ['domain', 'ip'])
         and 'rebuild-policy-default' in policy and all(v == policy['rebuild-policy-default'] for v in policy.values()), bad)
    if portal:
        # Match the install suffix after removing the appended PPP handoff.
        need(list(policy)[-1] == 'rebuild-policy-default'
             and [rule.get('ruleTag') for rule in kept[-len(policy):]] == list(policy), bad)
        validate_portal_rules(current, portal, policy['rebuild-policy-default'], targets)
    current['routing']['rules'] = kept
    # Also catch reserved tag references outside the routing rules, e.g.
    # dialerProxy, native reverse tags, or other inbounds with a PPP tag.
    need(not follow_relay_refs(current) and not any(k in current for k in ('observatory', 'burstObservatory'))
         and not current['routing'].get('balancers'), bad)
    candidate = (json.dumps(current, allow_nan=False, separators=(',', ':')) + '\n').encode()
    need(len(candidate) <= MAX_FILE, bad)
    return {'main': {**main, 'data': b64(candidate)}}, port, X


def invert_installed_split(main, side, node_id, tproxy, backup):
    # This is deliberately not a structural inverse for a changed split pair.
    # The caller has already proved both installed file and service generations.
    # Check that the exact original bytes undo only the split composer's delta,
    # including its changes to the pre-existing SOCKS listener and DNS strategy.
    bad = 'CANDIDATE_INVALID'
    orig_main, orig_side = (unique_profile(backup['before']['files']['main']), unique_profile(backup['before']['bridge']))
    ppp, socks, hop, block = ('relay-l2tp-' + node_id, FOLLOW_RELAY_SOCKS, FOLLOW_RELAY_HOP, FOLLOW_RELAY_BLOCK)
    need(not follow_relay_refs(orig_main) and not follow_relay_refs(orig_side, shared=True)
         and not orig_side.get('api') and not side.get('api'), bad)
    listeners = [i for i in orig_side['inbounds'] if i.get('tag') == socks]
    need(len(listeners) == 1, bad)
    listener = listeners[0]
    port = listener.get('port')
    need(type(port) is int and 1 <= port <= 65535 and port not in (tproxy, 500, 4500, 1701)
         and listener.get('listen') == '127.0.0.1' and listener.get('protocol') == 'socks'
         and all(listener['settings'].get(k) == v for k, v in (('auth', 'noauth'), ('ip', '127.0.0.1')))
         and listener['settings'].get('udp') is True, bad)
    need(not follow_relay_port_conflict(orig_main['inbounds'] + [i for i in orig_side['inbounds'] if i is not listener],
                                       (port, tproxy)), bad)
    need(encode(main['inbounds']) == encode(orig_main['inbounds'] + [follow_relay_tproxy(ppp, tproxy)]), bad)
    main['inbounds'].pop()
    sniffing = dict(enabled=True, destOverride=['http', 'tls', 'quic'], routeOnly=True)
    need(encode(side['inbounds']) == encode([{**i, 'sniffing': sniffing} if i is listener else i
                                            for i in orig_side['inbounds']]), bad)
    side['inbounds'] = orig_side['inbounds']
    need(side['routing'].pop('domainStrategy', None) == 'IPOnDemand', bad)
    if 'domainStrategy' in orig_side['routing']:
        side['routing']['domainStrategy'] = orig_side['routing']['domainStrategy']
    handoff_rule = dict(type='field', inboundTag=[ppp], outboundTag=hop)
    guards = []
    for cfg, scope, additions in ((main, ppp, [follow_relay_hop(port)]), (side, socks, [])):
        owned = [dict(tag=block, protocol='blackhole'), *additions]
        need(encode(cfg['outbounds'][-len(owned):]) == encode(owned), bad)
        del cfg['outbounds'][-len(owned):]
        rules = cfg['routing']['rules']
        if cfg is main:
            need(rules.count(handoff_rule) == 1, bad)
            rules.remove(handoff_rule)
        scoped, kept = [], []
        for rule in rules:
            guard = follow_relay_guard(rule, scope)
            if guard is None:
                kept.append(rule)
            else:
                scoped.append(guard)
        guards.append(scoped)
        cfg['routing']['rules'] = kept
    need(guards[0] == guards[1] and [k for k, _ in guards[0]] in (['ip'], ['domain', 'ip'])
         and encode(main) == encode(orig_main) and encode(side) == encode(orig_side), bad)
    return port


def remove_generation(path):
    try:
        st = os.lstat(path)
        return [st.st_dev, st.st_ino, st.st_ctime_ns]
    except FileNotFoundError:
        return None


REMOVE_STOCK_DEPS = {'-.mount', 'system.slice', 'sysinit.target', 'basic.target', 'network.target',
                     'network-online.target', 'nss-lookup.target'}


def removal_dependencies(units, installed):
    # No start/stop propagation to an unrelated unit, including current BRIDGE.
    forward = {X: set(), IKE: set(), NET_UNIT: {X}, XL: {NET_UNIT, IKE}}
    reverse = {X: {NET_UNIT}, IKE: {XL}, NET_UNIT: {XL}, XL: set()}
    for name in units.keys() & forward.keys():
        info = units[name]
        if not installed and name == NET_UNIT and info['LoadState'] == 'not-found':
            continue
        permitted = reverse[name] if installed else set()
        deps = REMOVE_STOCK_DEPS | (forward[name] if installed else set())
        need(all(set(info[k].split()) <= permitted for k in ('RequiredBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo'))
             and all(set(info[k].split()) <= {'shutdown.target'} for k in ('Conflicts', 'ConflictedBy'))
             and all(set(info[k].split()) <= deps for k in ('Requires', 'Wants', 'BindsTo', 'Upholds')), 'ROLLBACK_DRIFT')


def removal_native(info, name, before, installed):
    original = before['units'][name]
    boot_added = name == XL and before.get('installBoot') and installed
    return (native_vpn(info, name) and info['FragmentPath'] == original['FragmentPath']
            and info['UnitFileState'] == ('enabled' if boot_added else original['UnitFileState'])
            and info['DropInPaths'] == (DROP if name == XL and installed else original['DropInPaths'])
            and info.get('Group') in ('', 'root') and not info.get('ExecStopPost')
            and (not info.get('ExecStop') or (name == IKE and re.fullmatch(
                 r'\{ path=/usr/sbin/ipsec ; argv\[\]=/usr/sbin/ipsec stop ; [^{}]*\}', info['ExecStop']))))


def removal_profiles(main, side, node_id, tproxy, backup, units, main_generation, side_generation):
    current = unique_profile(main)
    bridge = unique_profile(side) if side is not None else None
    # Current MAIN owns the handoff after canonical Apply, even with a split
    # install receipt. Do not use that receipt to restore BRIDGE in this case.
    if any(i.get('tag') == FOLLOW_RELAY_SOCKS for i in current['inbounds']):
        profiles, port, owner = subtract_follow_relay(main, current, bridge, node_id, tproxy)
        if (backup.get('currentApply') is None and main_generation == backup['runtime']['files']['main']
                and after_match(main, backup['after']['main'])):
            # The subtraction edits current in place. Only when it is exactly
            # the saved preimage modulo JSON serialization, reuse those bytes
            # (not its metadata) to preserve the panel's exact Apply digest.
            original = backup['before']['files']['main']
            try:
                preimage = unique_profile(original)
            except (Refusal, ValueError, KeyError, TypeError):
                pass  # An ambiguous preimage cannot prove byte reuse.
            else:
                if encode(current) == encode(preimage):
                    profiles['main']['data'] = original['data']
        return profiles, port, owner

    after, runtime = backup['after'], backup['runtime']
    if side is None:
        raise Refusal('ROLLBACK_DRIFT')
    need('bridge' in after and len(runtime['invocations']) == 5
         and after_match(main, after['main']) and after_match(side, after['bridge'])
         and main_generation == runtime['files']['main'] and side_generation == runtime['files']['bridge']
         and units[B]['User'] == 'nobody' and units[B]['UnitFileState'] == 'enabled', 'ROLLBACK_DRIFT')
    check_runtime_unit_epoch(runtime, X, units[X])
    check_runtime_unit_epoch(runtime, B, units[B])
    need(units[X]['InvocationID'] == runtime['invocations'][0]
         and units[B]['InvocationID'] == runtime['invocations'][4], 'ROLLBACK_DRIFT')
    port = invert_installed_split(current, bridge, node_id, tproxy, backup)
    original = backup['before']
    return {'main': {**main, 'data': original['files']['main']['data']},
            'bridge': {**side, 'data': original['bridge']['data']}}, port, B


def network_kind(record, d, sidecar, token, nft_sha, *, manifest=False):
    def matches(data):
        expected = entry(data, 0o644)
        return after_match(expected, record) if manifest else expected == record

    for legacy, kind in ((True, 'requires'), (False, 'wants')):
        if matches(network_unit(d, sidecar, legacy=legacy)):
            return kind
    need(matches(network_unit(d, sidecar, backup_id=token, nft_sha256=nft_sha)), 'ROLLBACK_DRIFT')
    return 'pinned'


def pinned_network_manifest(d, token, backup):
    after = backup['after']
    return network_kind(after['net'], d, 'bridge' in after, token, after['nft']['data'], manifest=True) == 'pinned'


def network_loaded_starts(info, record):
    commands = [line.removeprefix('ExecStart=') for line in raw(record).decode().splitlines()
                if line.startswith('ExecStart=')]
    text = info.get('ExecStart', '')
    loaded = re.findall(r'\{ path=([^ ;{}]+) ; argv\[\]=([^{}]+?) ; ignore_errors=no ;[^{}]*\}', text)
    if not commands or len(loaded) != len(commands) or not re.fullmatch(r'\{[^{}]+\}(?: \{[^{}]+\})*', text):
        return False
    for (path, value), line in zip(loaded, commands):
        argv = shlex.split(line)
        if path != argv[0]:
            return False
        # Native systemctl show joins argv literally. Also admit an equivalent
        # shell-quoted presentation without discarding Python's literal quotes.
        if value != ' '.join(argv):
            try:
                if shlex.split(value) != argv:
                    return False
            except ValueError:
                return False
    return True


def network_unit_loaded(net, legacy, record=None):
    pre = net.get('ExecStartPre', '')
    return (net['LoadState'] == 'loaded' and net['FragmentPath'] == NET and not net['DropInPaths']
            and net['UnitFileState'] == 'static' and net['NeedDaemonReload'] == 'no'
            and no_hooks({**net, 'ExecStartPre': ''})
            and not any(net.get(k) for k in ('Environment', 'EnvironmentFiles', 'ExecCondition', 'ExecReload'))
            and net.get('User') in ('', 'root') and net.get('Group') in ('', 'root') and net.get('Type') == 'oneshot'
            and net['MainPID'] == '0' and X in net['After'].split()
            and (X in net['Requires'].split()) == legacy and (X in net['Wants'].split()) != legacy
            and not any(net.get(k) for k in ('BindsTo', 'PartOf', 'Upholds'))
            and (record is None or network_loaded_starts(net, record))
            and (not pre if legacy else re.fullmatch(
                r'\{ path=/usr/bin/systemctl ; argv\[\]=' + re.escape(NETWORK_START_CHECK)
                + r' ; ignore_errors=no ;[^{}]*\}', pre)))


def removal_units(units, before, runtime, restart_bridge, legacy, net_record=None):
    bad = 'ROLLBACK_DRIFT'
    x, xl, ike, net = (units[name] for name in (X, XL, IKE, NET_UNIT))
    need(x['FragmentPath'] == before['units'][X]['FragmentPath'] and working(x)
         and xray_accounts_match(x, before['units'][X])
         and xray_accounts_match(units[B], before['units'][B]), bad)
    need(network_unit_loaded(net, legacy, net_record), bad)
    for name, info, sub in zip((XL, IKE, NET_UNIT), (xl, ike, net), ('running', 'running', 'exited')):
        if name != NET_UNIT:
            need(removal_native(info, name, before, installed=True), bad)
        if info['ActiveState'] == 'active':
            need(info['SubState'] == sub and (name == NET_UNIT or working(info)), bad)
            check_runtime_unit_epoch(runtime, name, info)
        else:
            # Apply restarts MAIN. systemd can stop its dependents or fail to
            # restart the oneshot (which attempts to add existing policy).
            # Accept only a quiescent service here; the kernel policy still
            # has to match the original installed receipt below.
            need(x['InvocationID'] != runtime['invocations'][0] and info['MainPID'] == '0'
                 and (info['ActiveState'], info['SubState']) in (('inactive', 'dead'), ('failed', 'failed')), bad)
    need(set(xl['Requires'].split()) >= {NET_UNIT, IKE} and set(xl['After'].split()) >= {NET_UNIT, IKE}, bad)
    removal_dependencies(units, installed=True)
    if restart_bridge:
        info = units[B]
        need(all(not info[k] for k in ('RequiredBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo'))
             and all(set(info[k].split()) <= {'shutdown.target'} for k in ('Conflicts', 'ConflictedBy'))
             and all(set(info[k].split()) <= REMOVE_STOCK_DEPS for k in ('Requires', 'Wants', 'BindsTo', 'Upholds')), bad)


def removal_boot(before, backup, runtime):
    check_prepared_native(before)
    receipt = backup.get('bootEnrollment')
    if before['units'][XL]['UnitFileState'] == 'disabled':
        target = before['units'][XL]['FragmentPath']
        need(before.get('installBoot') is True and target == SYSTEM + '/' + XL
             and type(receipt) is list and len(receipt) == 4 and receipt[0] == target
             and runtime.get('bootEnrollment') == receipt and boot_link() == receipt, 'ROLLBACK_DRIFT')
        return receipt
    need(before['units'][XL]['UnitFileState'] == 'enabled' and not before.get('installBoot')
         and receipt is None and runtime.get('bootEnrollment') is None, 'ROLLBACK_DRIFT')
    return None


def rollback_quiescent(info):
    return (info['ActiveState'], info['SubState'], info['MainPID']) == ('inactive', 'dead', '0')


def removal_vpn_runtime(rows, units):
    vpn_stop_checks(rows, units, require_xl_listener=True)


def applying_vpn_ownership(rows, units):
    # The caller already matched the persisted start receipt. An active XL
    # invocation still needs a proven PID; it need not have bound UDP/1701.
    xl = units[XL]
    need(xl['ActiveState'] != 'active' or working(xl), 'RUNTIME_UNPROVED')
    vpn_stop_checks(rows, units, require_xl_listener=False)


def vpn_listener_ownership(rows, units, *, require_xl_listener):
    xl, ike = units[XL], units[IKE]
    lns_active, ike_active = (info['ActiveState'] == 'active' for info in (xl, ike))
    lns_rows = [(p, owners) for p, _, n, owners in rows if n == 1701]
    ike_rows = [(p, n, owners) for p, _, n, owners in rows if n in (500, 4500)]
    lns_ready = bool(lns_rows) == lns_active or (not require_xl_listener and not lns_rows)
    need(lns_ready and all(p == 'udp' and owners == [xl['MainPID']] for p, owners in lns_rows)
         and {n for _, n, _ in ike_rows} == ({500, 4500} if ike_active else set())
         and all(p == 'udp' and owners and all(in_cgroup(pid, ike) for pid in owners) for p, _, owners in ike_rows),
         'RUNTIME_UNPROVED')


def vpn_stop_checks(rows, units, *, require_xl_listener):
    vpn_listener_ownership(rows, units, require_xl_listener=require_xl_listener)
    ike_active = units[IKE]['ActiveState'] == 'active'
    need(vpn_empty(allow_socket_policies=ike_active), 'ROLLBACK_DRIFT')
    if ike_active:
        # Don't stop a foreign connection or an in-flight negotiation.
        status = command('/usr/sbin/ipsec', 'statusall')
        match = re.search(rb'^Connections:[ \t]*\n(.*?)^Security Associations \(0 up, 0 connecting\):\s*(?:none\s*)?\Z',
                          status, re.M | re.S)
        need(match is not None and set(re.findall(rb'^\s*([^\s:]+):', match[1], re.M)) == {b'celerity-l2tp'},
             'ROLLBACK_DRIFT')


def removal_sockets(rows, units, d, handoff, handoff_unit):
    tproxy = d['tproxyPort']
    need(handoff != tproxy and sorted((p, owners) for p, _, n, owners in rows if n == tproxy)
         == [(p, [units[X]['MainPID']]) for p in ('tcp', 'udp')], 'RUNTIME_UNPROVED')
    verify_socks_handoff(rows, handoff, units[handoff_unit]['MainPID'])
    return {tproxy, 500, 4500, 1701} | ({handoff} if handoff_unit == X else set())


def removal_xray_sockets(rows, pid):
    need(all(owners == [pid] for _, _, _, owners in rows if pid in owners), 'RUNTIME_UNPROVED')
    return owned_sockets(rows, pid)


def removal_udp_endpoints(profile):
    # Read the admitted post-Remove profile, not a port range or the current
    # socket inventory. TPROXY and the handoff are checked separately.
    bad = 'CANDIDATE_INVALID'

    def fields(obj):
        # unique_profile has already rejected case-folded duplicate keys.
        need(type(obj) is dict, bad)
        return {k.casefold(): v for k, v in obj.items()}

    def string_list(value):
        if type(value) is str:
            return value.split(',')
        need(type(value) is list and all(type(v) is str for v in value), bad)
        return value

    config = unique_profile(profile)
    need(not fields(config).get('transport'), bad)
    endpoints = set()
    for row in config['inbounds']:
        inbound = fields(row)
        stream = fields(inbound.get('streamsettings', {}))
        transport = stream.get('network', 'tcp')
        need(stream.get('method') is None and type(transport) is str, bad)
        transport = transport.lower()
        if transport in ('xhttp', 'splithttp'):
            # Xray's splithttp listener uses UDP for TLS ALPN ["h3"].
            # Do not project an unreviewed transport as TCP-only.
            security = stream.get('security', 'none')
            need(type(security) is str and security.lower() in ('', 'none', 'reality', 'tls'), bad)
            if security.lower() == 'tls':
                alpn = string_list(fields(stream.get('tlssettings', {})).get('alpn', []))
                need('h3' not in alpn, bad)
        else:
            need(transport in ('tcp', 'raw', 'ws', 'websocket', 'grpc', 'httpupgrade'), bad)

        protocol = inbound.get('protocol')
        if protocol == 'vless':
            continue  # proxied UDP over a stream does not imply a UDP bind
        settings = fields(inbound.get('settings', {}))
        if protocol == 'socks':
            # UDP ASSOCIATE is a fixed bind in older cores but per-session
            # in newer cores. Only the separately guarded handoff is supported.
            need(settings.get('udp', False) is False, bad)
            continue
        need(protocol == 'dokodemo-door', bad)
        # DokodemoConfig.Network overrides AllowedNetwork; nil defaults to TCP.
        networks = settings.get('network')
        if networks is None:
            networks = settings.get('allowednetwork')
        networks = ['tcp'] if networks is None else [v.lower() for v in string_list(networks)]
        need(networks and set(networks) <= {'tcp', 'udp'}, bad)
        if 'udp' in networks:
            port, listen = inbound.get('port'), inbound.get('listen', '0.0.0.0')
            need(type(port) is int and 1 <= port <= 65535 and type(listen) is str and '%' not in listen, bad)
            try:
                address = ipaddress.ip_address(listen)
            except ValueError:
                raise Refusal(bad) from None
            endpoint = (str(address) if address.version == 4 else f'[{address}]', port)
            need(endpoint not in endpoints, bad)
            endpoints.add(endpoint)
    return endpoints


def removal_main_sockets(rows, pid, reserved, udp_endpoints):
    # ss -lu reports unconnected outbound sockets too. Their tuples can
    # change between preview, restart and readback; keep only proved binds.
    tcp = [row for row in removal_xray_sockets(rows, pid) if row[0] == 'tcp' and row[2] not in reserved]
    need(all(port not in reserved for _, port in udp_endpoints), 'RUNTIME_UNPROVED')
    seen, udp = set(), []
    for proto, address, port, owners in rows:
        if proto != 'udp':
            continue
        matches = [(address, port)] if address != '*' else [('0.0.0.0', port), ('[::]', port)]
        matches = udp_endpoints.intersection(matches)
        if matches:
            need(len(matches) == 1 and not seen.intersection(matches) and owners == [pid], 'RUNTIME_UNPROVED')
            seen.update(matches)
            udp.append([proto, address, port])
    need(seen == udp_endpoints, 'RUNTIME_UNPROVED')
    return sorted(tcp + udp)


def removal_intent_matches(path, expected):
    return directory_absent(path) if expected is None else read(path, 128) == expected


RUNTIME_REATTEST_REQUIRED = 'RUNTIME_REATTEST_REQUIRED'
RUNTIME_FOREIGN_CHANGE = 'RUNTIME_FOREIGN_CHANGE'
RUNTIME_EPOCH_READS = ('session-count', 'retirement-count', 'inspect-chap', 'prepare-remove',
                       'check-apply-network', 'verify-apply-network')
REATTEST_ENTERED = False
RUNTIME_UNITS = (X, XL, IKE, NET_UNIT, B)
BOOT_ID_PATTERN = r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'


def installed_boot(backup):
    # c83c995 receipts predate the separate installed runtime boot pin.
    return backup['runtime'].get('boot', backup['before']['boot'])


def check_runtime_boot(backup):
    current, recorded = boot(), installed_boot(backup)
    need(type(recorded) is str and bool(recorded) and bool(current), 'ROLLBACK_DRIFT')
    if current != recorded:
        need(re.fullmatch(BOOT_ID_PATTERN, current) and re.fullmatch(BOOT_ID_PATTERN, recorded), 'ROLLBACK_DRIFT')
        raise Refusal(RUNTIME_REATTEST_REQUIRED)
    return current


def check_runtime_unit_epoch(runtime, name, info):
    # Compare positive generations only. Inactivity/failure was never proof
    # of a replacement, and some Apply layouts deliberately leave units idle.
    i = RUNTIME_UNITS.index(name)
    if info.get('ActiveState') != 'active':
        return
    invocation, recorded = info.get('InvocationID', ''), runtime['invocations'][i]
    need(invocation and invocation.strip('0') and recorded and recorded.strip('0'), 'ROLLBACK_DRIFT')
    if invocation != recorded:
        need(all(re.fullmatch(r'[a-f0-9]{32}', inv) for inv in (invocation, recorded)), 'ROLLBACK_DRIFT')
        raise Refusal(RUNTIME_REATTEST_REQUIRED)
    if 'pids' in runtime:
        pid = info.get('MainPID', '')
        need(re.fullmatch(r'0' if name == NET_UNIT else r'[1-9][0-9]*', pid), 'ROLLBACK_DRIFT')
        need(pid == runtime['pids'][i], RUNTIME_REATTEST_REQUIRED)


def owned_installation(request, *, remove_intent=None, reattest=False, pending_apply=False):
    bad = 'ROLLBACK_DRIFT'
    token = request['backupId']
    path, manifest, backup = read_manifest(token)
    need((installed_phase(backup['phase']) or pending_apply and backup['phase'] == APPLY_PROFILES_PHASE)
         and backup['machineId'] == request['machineId']
         and backup['backupId'] == token and encode(backup['network']) == encode(request['network']), bad)
    intent = os.path.join(os.path.dirname(path), 'remove-attempt.json')
    need(removal_intent_matches(intent, remove_intent), bad)
    if not reattest:
        check_runtime_boot(backup)
    return path, manifest, backup, intent


def reattest_process(pid, info):
    need(in_cgroup(pid, info), RUNTIME_FOREIGN_CHANGE)
    with open('/proc/' + pid + '/stat', 'rb') as task:
        data = task.read(4097)
    prefix, separated, fields = data.rpartition(b') ')
    need(separated and prefix.startswith(pid.encode() + b' (') and len(data) <= 4096, RUNTIME_FOREIGN_CHANGE)
    state = fields.split()
    need(len(state) > 19 and state[0] not in (b'Z', b'X', b'x') and state[19].isdigit(), RUNTIME_FOREIGN_CHANGE)
    return int(state[19])


def reattest_files(backup):
    bad = RUNTIME_FOREIGN_CHANGE
    after, generations = backup['after'], backup['runtime']['files']
    paths = operation_files(after)
    need(set(paths) == set(after) == set(generations), bad)
    applied = backup.get('currentApply')
    if applied is not None:
        paths['bridge'] = BRIDGE
    records = {}
    for key, path in paths.items():
        generation = remove_generation(path)
        record = read(path)
        if applied is not None and key in ('main', 'bridge'):
            expected = applied['files'][key]
        else:
            expected = backup.get('currentChap', [after[key], generations[key]]) if key == 'chap' else [after[key], generations[key]]
        need(encode(file_pin(record, generation)) == encode(expected) and remove_generation(path) == generation, bad)
        records[key] = record
    return records


def checked_installed_policy(backup, kind, *, removing=False, exact_flags=False):
    d, token = backup['network'], backup['backupId']
    def current():
        return network_projection(d, token, removing=removing, exact_flags=exact_flags, pinned=kind == 'pinned')
    live = current()
    need(live['nft'] is not None and live['rule'] is True and live['route'] is True, 'ROLLBACK_DRIFT')
    if live['nft'] != backup['runtime']['nft']:
        # Older receipts hash nft JSON including boot-local handles. The opaque
        # hash cannot be normalized retrospectively. Prove the immutable input
        # and every live rule against the same known template instead. Retain
        # the new raw observation for this Remove's strict same-boot checks.
        need(kind in ('wants', 'requires') and boot() != backup['before']['boot'] and
             backup['after']['nft']['data'] == digest(managed_nft_bytes(d, token)), 'ROLLBACK_DRIFT')
        semantic = pinned_network_projection(d, token, removing)
        need(semantic['nft'] is not None and semantic['rule'] is True and semantic['route'] is True
             and current() == live, 'ROLLBACK_DRIFT')
    return live


def reattest_sample(request, backup):
    bad = RUNTIME_FOREIGN_CHANGE
    d, token = request['network'], request['backupId']
    epoch = boot()
    need(re.fullmatch(BOOT_ID_PATTERN, epoch), bad)
    before, runtime = runtime_before(backup), backup['runtime']
    after = backup['after']
    records = reattest_files(backup)
    need(nft_marker(raw(records['nft']), token), bad)
    removal_boot(before, backup, runtime)
    check_module_boot_owner(module_boot_owner(backup))
    check_swan_profile(backup, records.get('swan'), bad)
    need(ike_include_matches(records['starter'], [os.path.basename(NAMES['ike'])], check_tree=True), bad)
    need(all(read(name, 262144) == value for name, value in before['globalFiles'].items()), bad)

    no_jobs(UNITS)
    applied = backup.get('currentApply')
    sidecar = applied['bridgeActive'] if applied is not None else 'bridge' in after
    names = RUNTIME_UNITS if sidecar else RUNTIME_UNITS[:-1]
    need(re.fullmatch(BOOT_ID_PATTERN, installed_boot(backup)) and type(runtime['invocations']) is list
         and (len(runtime['invocations']) in (4, 5) if applied is not None else len(runtime['invocations']) == len(names))
         and all(re.fullmatch(r'[a-f0-9]{32}', inv) and inv != '0' * 32 for inv in runtime['invocations'])
         and ('pids' not in runtime and 'boot' not in runtime or type(runtime.get('pids')) is list and 'boot' in runtime
              and len(runtime['pids']) == len(runtime['invocations'])
              and all(re.fullmatch(r'0' if n == NET_UNIT else r'[1-9][0-9]*', p) for n, p in zip(RUNTIME_UNITS, runtime['pids']))), bad)
    infos = {name: unit(name) for name in names}
    old = before['units']
    x, xl, ike, net = (infos[name] for name in RUNTIME_UNITS[:-1])
    kind = network_kind(records['net'], d, 'bridge' in after, token, after['nft']['data'])
    need(network_unit_loaded(net, kind == 'requires', records['net']), bad)
    need(removal_native(xl, XL, before, installed=True) and removal_native(ike, IKE, before, installed=True)
         and set(xl['Requires'].split()) >= {NET_UNIT, IKE} and set(xl['After'].split()) >= {NET_UNIT, IKE}, bad)
    removal_dependencies(infos, installed=True)
    check_idle_bridge = not sidecar and any(k in old[B] for k in XRAY_ACCOUNT_FIELDS)
    b = infos[B] if sidecar else unit(B) if check_idle_bridge or applied is not None else None
    need(b is None or xray_accounts_match(b, old[B]), bad)
    if applied is not None:
        need(applied['nodeId'] == request['nodeId'] and apply_bridge_state(b, sidecar) == applied['bridgeUnit'], bad)
    for name in (X, B) if sidecar and applied is None else (X,):
        info = infos[name]
        enabled = 'enabled' if applied is not None else old[name].get('UnitFileState')
        need(info.get('UnitFileState') == enabled
             and all(info.get(key) == old[name].get(key) for key in ('FragmentPath', 'DropInPaths'))
             and (xray_accounts_match(info, old[X]) if name == X else info.get('User') == 'nobody')
             and not any(info.get(key) for key in ('ExecCondition', 'PassEnvironment', 'UnsetEnvironment')), bad)
    need(all(info.get('ActiveState') == 'active' and info.get('SubState') == ('exited' if name == NET_UNIT else 'running')
             and re.fullmatch(r'[a-f0-9]{32}', info.get('InvocationID', '')) and info['InvocationID'] != '0' * 32
             and (name == NET_UNIT or working(info)) for name, info in infos.items()), bad)
    invocations = [infos[name]['InvocationID'] for name in names]
    pids = [infos[name]['MainPID'] for name in names]
    need(len(set(invocations)) == len(names) and len(set(pids)) == len(names)
         and all(re.fullmatch(r'0' if name == NET_UNIT else r'[1-9][0-9]*', pid) for name, pid in zip(names, pids)), bad)
    processes = {pid: reattest_process(pid, infos[name]) for name, pid in zip(names, pids) if name != NET_UNIT}

    rows = sock_rows()
    xpid = xray_argv(x)
    sockets = xray_users(records['main'], x, rows, before.get('transit') if applied is None else apply_transit(records['main']))
    if sidecar:
        xray_argv(infos[B], BRIDGE)
    if applied is None:
        need(set(map(tuple, before['sockets'])) <= set(map(tuple, sockets)), bad)
    else:
        need(apply_tcp_pin(rows, x, infos.get(B)) == applied['tcp'], bad)
        apply_udp_check(records, rows, x, infos.get(B), d['tproxyPort'])
    split = sidecar and applied is None
    handoff_pid = infos[B]['MainPID'] if split else xpid
    profile = unique_profile(records['main'])
    tproxy = [i for i in profile['inbounds'] if i.get('tag', '').startswith('relay-l2tp-')]
    # The c83c995 manifest did not store a separate panel node ID. Bind the
    # request to the node tag in the authenticated installed MAIN profile.
    need(len(tproxy) == 1 and tproxy[0]['tag'] == 'relay-l2tp-' + request['nodeId']
         and tproxy[0].get('port') == d['tproxyPort'], bad)
    owner_profile = unique_profile(records['bridge']) if split else profile
    handoff = [i for i in owner_profile['inbounds'] if i.get('tag') == FOLLOW_RELAY_SOCKS]
    need(len(handoff) == 1 and handoff[0].get('protocol') == 'socks' and handoff[0].get('listen') == '127.0.0.1', bad)
    port = handoff[0]['port']
    verify_socks_handoff(rows, port, handoff_pid)
    listeners = [(proto, address, owners) for proto, address, number, owners in rows if number == d['tproxyPort']]
    need({proto for proto, _, _ in listeners} == {'tcp', 'udp'}
         and all(address in ('0.0.0.0', '*', '[::]') and owners == [xpid] for _, address, owners in listeners), bad)
    vpn_listener_ownership(rows, infos, require_xl_listener=True)
    for _, _, number, owners in rows:
        if number in (500, 4500):
            for pid in owners:
                processes[pid] = reattest_process(pid, ike)
    status = command('/usr/sbin/ipsec', 'statusall')
    connections = re.search(rb'^Connections:[ \t]*\n(.*?)^Security Associations ', status, re.M | re.S)
    need(connections is not None and connections[1].strip()
         and all(line.lstrip().startswith(b'celerity-l2tp:') for line in connections[1].splitlines() if line.strip()), bad)
    policy = checked_installed_policy(backup, kind, exact_flags=True)
    no_jobs(UNITS)
    need(all(unit(name) == info for name, info in infos.items()) and epoch == boot(), bad)
    if check_idle_bridge or applied is not None:
        confirmed_bridge = unit(B)
        need(xray_accounts_match(confirmed_bridge, old[B])
             and (applied is None or apply_bridge_state(confirmed_bridge, sidecar) == applied['bridgeUnit']), bad)
    return (dict(boot=epoch, invocations=invocations, pids=pids), infos, processes, connections[1], policy,
            sorted((proto, addr, number, owners) for proto, addr, number, owners in rows
                   if number in (port, d['tproxyPort'], 1701, 500, 4500)))


def reattest_runtime(request, lock_fd):
    global REATTEST_ENTERED
    bad = RUNTIME_FOREIGN_CHANGE
    try:
        lock_id = install_lock_identity(lock_fd)
        manifest_generation = remove_generation(manifest_path(request['backupId']))
        path, record, backup, intent = owned_installation(request, reattest=True)
        require_network_observers()
        need(ppp_device() is True and ppp_registered(), bad)
        first = reattest_sample(request, backup)
        need(first == reattest_sample(request, backup), bad)
        epoch = first[0]
        require_machine(request['machineId'])
        reattest_files(backup)
        removal_boot(runtime_before(backup), backup, backup['runtime'])
        need(epoch['boot'] == boot() and install_lock_identity(lock_fd) == lock_id and directory_absent(intent)
             and manifest_generation is not None and read(path, 2 * MAX_FILE) == record
             and remove_generation(path) == manifest_generation, bad)
        need(time.monotonic() < DEADLINE, 'IN_FLIGHT')
        runtime = backup['runtime']
        # No publication for an already-attested legacy epoch. In particular
        # do not replace the original Install rollback witness for a no-op.
        if (installed_boot(backup), runtime['invocations'], runtime.get('pids', epoch['pids'])) != (
                epoch['boot'], epoch['invocations'], epoch['pids']):
            replacement = entry(encode({**backup, 'runtime': {**runtime, **epoch}}))
            need(len(raw(replacement)) <= 2 * MAX_FILE, bad)
            REATTEST_ENTERED = True
            write(path, record, replacement, generation=manifest_generation)
            need(time.monotonic() < DEADLINE, 'IN_FLIGHT')
    except (BlockingIOError, subprocess.TimeoutExpired):
        raise
    except (Refusal, OSError, ValueError, KeyError, TypeError, IndexError) as error:
        if REATTEST_ENTERED or str(error) in ('IDENTITY', 'IN_FLIGHT', OBSERVATION_REQUIRED):
            raise
        raise Refusal(bad) from None
    return {'ok': True, 'backupId': request['backupId']}


def verify_apply_handoff(rows, units, xpid, *, main_only=False):
    bad = 'RUNTIME_UNPROVED'

    def listeners(path):
        record = read(path)
        need(record is not None, bad)
        return [i for i in json.loads(raw(record)).get('inbounds', []) if i.get('tag') == FOLLOW_RELAY_SOCKS]

    main = listeners(MAIN)
    if main_only and not main:
        return  # BRIDGE is started by the caller after the fenced MAIN restart.
    side = []
    if not main_only and units[B]['ActiveState'] == 'active':
        side = listeners(BRIDGE)
    need(len(main) + len(side) == 1, bad)
    handoff = (main or side)[0]
    need(handoff.get('protocol') == 'socks' and handoff.get('listen') == '127.0.0.1', bad)
    verify_socks_handoff(rows, handoff.get('port'), xpid if main else xray_argv(units[B], BRIDGE))


def apply_network_snapshot(d, token, backup, record, generation, *, listeners_required=True, handoff_check=True):
    bad = 'ROLLBACK_DRIFT'
    before, runtime = runtime_before(backup), backup['runtime']
    kind = network_kind(record, d, 'bridge' in backup['after'], token, backup['after']['nft']['data'])
    legacy = kind == 'requires'
    need(read(NET, 65536) == record and remove_generation(NET) == generation, bad)
    for key in ('drop', 'nft'):
        p = NAMES[key]
        need(after_match(read(p), backup['after'][key]) and remove_generation(p) == runtime['files'][key], bad)
    removal_boot(before, backup, runtime)
    no_jobs(UNITS)
    units = {n: unit(n) for n in UNITS}
    removal_units(units, before, runtime, False, legacy, record if kind == 'pinned' else None)
    xpid = xray_argv(units[X])
    # A sidecar may be stopped by putPair even if its replacement will be
    # empty. Neither it nor MAIN may propagate stop outside the old exact edge.
    for name in (X, B):
        info = units[name]
        if name == B and info['LoadState'] == 'not-found':
            continue
        need(info['LoadState'] == 'loaded' and info['NeedDaemonReload'] == 'no' and no_hooks(info)
             and not any(info.get(k) for k in ('ExecCondition', 'ExecReload'))
             and (name == X or not info.get('DropInPaths'))
             and set(info['RequiredBy'].split()) == ({NET_UNIT} if name == X and legacy else set())
             and not any(info[k] for k in ('BoundBy', 'ConsistsOf', 'PropagatesStopTo'))
             and all(set(info[k].split()) <= {'shutdown.target'} for k in ('Conflicts', 'ConflictedBy')), bad)
    need(set(units[NET_UNIT]['RequiredBy'].split()) == {XL}
         and not any(units[n][k] for n in (NET_UNIT, XL, IKE) for k in ('BindsTo', 'PartOf', 'PropagatesStopTo')), bad)
    # Unlike Remove, a negotiated IPsec SA and a live PPP session are allowed.
    # Check their supervisor generations and listener ownership, not emptiness.
    vpn = (XL, IKE, NET_UNIT)
    need(all(units[n]['ActiveState'] == 'active' for n in vpn), bad)
    rows = sock_rows()
    lns = [owners for proto, _, port, owners in rows if proto == 'udp' and port == 1701]
    need(lns and all(owners == [units[XL]['MainPID']] for owners in lns), bad)
    listeners = [(proto, addr, owners) for proto, addr, port, owners in rows if port == d['tproxyPort']]
    need(all(addr in ('0.0.0.0', '*', '[::]') and owners == [xpid] for _, addr, owners in listeners), bad)
    ready = {proto for proto, _, _ in listeners} == {'tcp', 'udp'}
    need(ready or not listeners_required, 'RUNTIME_UNPROVED')
    if ready and handoff_check:
        try:
            verify_apply_handoff(rows, units, xpid, main_only=not listeners_required)
        except Refusal as error:
            if listeners_required or str(error) != 'RUNTIME_UNPROVED':
                raise
            ready = False
    policy = checked_installed_policy(backup, kind, removing=True)
    no_jobs(UNITS)
    return legacy, [[units[n][key] for key in ('InvocationID', 'MainPID', 'ControlGroup')] for n in vpn], units[X]['InvocationID'], ready


def apply_profile_read(path):
    generation = remove_generation(path)
    record = read(path)
    need(remove_generation(path) == generation, 'ROLLBACK_DRIFT')
    return record, generation


# The compact JSON.stringify bytes of rebuildTopologyComposer.blackholeProfile
# after composeXrayConfig (the non-exit BRIDGE). Do not admit equivalent JSON.
EMPTY_BRIDGE_BYTES = (b'{"log":{"loglevel":"warning","access":"none"},"inbounds":[],"outbounds":'
                      b'[{"tag":"block","protocol":"blackhole"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[]}}')
BRIDGE_PLACEHOLDER_UNPROVED = 'BRIDGE_PLACEHOLDER_UNPROVED'


def canonical_empty_bridge(record):
    if record is None:
        return False
    try:
        group = grp.getgrnam('nogroup').gr_gid
        # Ordinary putPair uses the primary group of nobody on creation.
        return group == pwd.getpwnam('nobody').pw_gid and record == entry(EMPTY_BRIDGE_BYTES, 0o640, group)
    except KeyError:
        return False


def bridge_unit_absent_pin(info):
    # Only the stable systemd projection was recorded at Install.
    return (type(info) is dict and info.get('LoadState') == 'not-found'
            and tuple(info.get(key) for key in ('ActiveState', 'SubState', 'MainPID')) == ('inactive', 'dead', '0')
            and all(info.get(key) == '' for key in ('FragmentPath', 'DropInPaths', 'UnitFileState'))
            and info.get('InvocationID') in ('', '0' * 32))


def bridge_unit_absent(info):
    return (bridge_unit_absent_pin(info) and info.get('NeedDaemonReload') == 'no'
            and not any(info.get(key) for key in ('Job', 'ControlGroup', 'SourcePath', 'ExecCondition', 'ExecStart',
                                                  'ExecStartPre', 'ExecStartPost', 'ExecReload', 'ExecStop', 'ExecStopPost'))
            and directory_absent(SYSTEM + '/' + B))


def apply_bridge_state(info, active):
    bad = 'RUNTIME_UNPROVED'
    if info['LoadState'] == 'not-found':
        need(not active and rollback_quiescent(info) and directory_absent(SYSTEM + '/' + B), bad)
        return None
    need(info['FragmentPath'] == SYSTEM + '/' + B and not info['DropInPaths'] and info['User'] == 'nobody'
         and info['NeedDaemonReload'] == 'no' and no_hooks(info)
         and not any(info.get(k) for k in ('Environment', 'EnvironmentFiles', 'ExecCondition', 'ExecReload',
                                          'PassEnvironment', 'UnsetEnvironment')), bad)
    if active:
        need(info['UnitFileState'] == 'enabled' and xray_argv(info, BRIDGE) == info['MainPID'], bad)
    else:
        need(info['UnitFileState'] == 'disabled' and rollback_quiescent(info), bad)
    return file_pin(*apply_profile_read(SYSTEM + '/' + B))


def apply_tcp_pin(rows, *units):
    # UDP SS rows may be outbound ephemeral sockets. The managed fixed VPN,
    # TPROXY and SOCKS UDP endpoints are separately proved by their consumers.
    tcp = [row for row in rows if row[0] == 'tcp']
    return digest(encode([removal_xray_sockets(tcp, u['MainPID']) if u is not None and working(u) else [] for u in units]))


def apply_udp_check(records, rows, main, bridge, tproxy):
    # Do not pin outbound ephemeral UDP tuples. Require every supported fixed
    # endpoint from the authenticated config, in addition to the separate
    # VPN, TPROXY and SOCKS listener checks.
    profile = unique_profile(records['main'])
    handoff = next(i['port'] for i in profile['inbounds'] if i['tag'] == FOLLOW_RELAY_SOCKS)
    profile['inbounds'] = [i for i in profile['inbounds'] if not follow_relay_reserved(i['tag'])]
    reserved = {500, 4500, 1701, tproxy, handoff}
    endpoints = removal_udp_endpoints(entry(encode(profile)))
    removal_main_sockets(rows, main['MainPID'], reserved, endpoints)
    if bridge is not None and working(bridge):
        removal_main_sockets(rows, bridge['MainPID'], reserved, removal_udp_endpoints(records['bridge']))


def apply_transit(record):
    # Derive only from the exact staged/current Apply bytes, not foreign live files.
    result: list[dict[str, Any]] = []
    for inbound in unique_profile(record)['inbounds']:
        match = re.fullmatch(r'(fwd-hop-|rebuild-rp-conn-)([a-f0-9]{8})', inbound.get('tag', ''))
        if match:
            clients: Any = inbound['settings']['clients']
            need(type(clients) is list and len(clients) == 1, 'PROFILE_USERS')
            email = clients[0].get('email', '')
            label = re.fullmatch(r'rproof-([a-f0-9]{24})-[a-f0-9]{64}@rebuild\.invalid', email) if email else None
            need(not email or label is not None and label[1][-8:] == match[2], 'PROFILE_USERS')
            result.append(dict(linkId=label[1] if label else '0' * 16 + match[2],
                               mode='forward' if match[1] == 'fwd-hop-' else 'reverse',
                               port=inbound['port'], uuid=clients[0]['id']))
    return result


def read_apply_profiles(pins):
    records = {}
    for key, target in (('main', MAIN), ('bridge', BRIDGE)):
        record, generation = apply_profile_read(target)
        need(encode(file_pin(record, generation)) == encode(pins[key]), 'ROLLBACK_DRIFT')
        records[key] = record
    return records


def publish_apply_profiles(request, path, manifest, backup, live):
    global NETWORK_UPGRADE_ENTERED
    bad = 'ROLLBACK_DRIFT'
    after, runtime = backup['after'], backup['runtime']
    installed = backup.get('currentApply')
    before, replacements, plan = {}, {}, {}
    placeholder = False
    for key, target in (('main', MAIN), ('bridge', BRIDGE)):
        unpinned = installed is None and key not in after
        try:
            record, generation = apply_profile_read(target)
        except (Refusal, OSError):
            if not unpinned or key != 'bridge':
                raise
            raise Refusal(BRIDGE_PLACEHOLDER_UNPROVED) from None
        if not unpinned:
            expected = installed['files'][key] if installed is not None else [after[key], runtime['files'][key]]
            need(encode(file_pin(record, generation)) == encode(expected), bad)
        elif key == 'bridge':
            original = backup['before']
            pinned = 'emptyBridgeGeneration' in original
            if record is not None or original['bridge'] is not None or pinned:
                need(generation is not None and record == original['bridge'] and canonical_empty_bridge(record),
                     BRIDGE_PLACEHOLDER_UNPROVED)
                # v1.4.1 recorded the canonical file and the absent unit, but
                # not the original inode. Attest the live generation only for
                # this publication; never add a historical generation pin.
                need(generation == original['emptyBridgeGeneration'] if pinned
                     else bridge_unit_absent_pin(original['units'].get(B)), BRIDGE_PLACEHOLDER_UNPROVED)
                placeholder = True
        else:
            raise Refusal(bad)
        stage = read(target + '.rebuild-' + request['stageId'] + '.json')
        if stage is None:
            raise Refusal(bad)
        need(stage['mode'] == 0o600 and digest(raw(stage)) == request['profiles'][key], bad)
        before[key] = (record, generation)
        replacements[key] = {**(record or entry(b'', 0o640, pwd.getpwnam('nobody').pw_gid)), 'data': stage['data']}
        plan[key] = file_pin(replacements[key], [10**20 - 1] * 3)
    node = request['nodeId']
    pins = unique_profile(before['main'][0])['inbounds']
    need([i.get('tag') for i in pins if i.get('tag', '').startswith('relay-l2tp-')] == ['relay-l2tp-' + node], bad)
    side = unique_profile(replacements['bridge'])
    subtract_follow_relay(replacements['main'], unique_profile(replacements['main']), side, node, request['network']['tproxyPort'])
    transit_inbounds(unique_profile(replacements['main']), apply_transit(replacements['main']))
    active = bool(side['inbounds'] or any(o.get('protocol') == 'vless' and o.get('settings', {}).get('reverse', {}).get('tag')
                                         for o in side['outbounds']))
    info = unit(B)
    if placeholder:
        need(bridge_unit_absent(info), BRIDGE_PLACEHOLDER_UNPROVED)
    need(xray_accounts_match(info, backup['before']['units'][B]), bad)
    old_unit = apply_bridge_state(info, installed is not None and installed['bridgeActive'])
    need(old_unit == (None if installed is None else installed['bridgeUnit']), bad)
    unit_path = SYSTEM + '/' + B
    new_unit = entry(request['bridgeUnit'].encode(), 0o644) if active and old_unit is None else None
    need(new_unit is None or digest(raw(new_unit)) == APPLY_BRIDGE_UNIT_SHA, bad)
    pending: dict[str, Any] = dict(phase=backup['phase'], nodeId=node, bridgeActive=active, bridgeUnit=old_unit,
                   mainInvocation=live, files=plan)
    if new_unit is not None:
        pending['bridgeUnit'] = file_pin(new_unit, [10**20 - 1] * 3)
    journal = {**backup, 'phase': APPLY_PROFILES_PHASE, 'applyPending': pending}
    proof = entry(encode(journal))
    generation = remove_generation(path)
    if placeholder:
        need(bridge_unit_absent(unit(B)) and apply_profile_read(BRIDGE) == before['bridge'], BRIDGE_PLACEHOLDER_UNPROVED)
    need(generation is not None and len(raw(proof)) <= 2 * MAX_FILE and time.monotonic() < DEADLINE, bad)
    NETWORK_UPGRADE_ENTERED = True
    journal_generation = write(path, manifest, proof, generation=generation, witness=True)
    for key, target in (('bridge', BRIDGE), ('main', MAIN)):
        record, generation = before[key]
        if placeholder and key == 'bridge':
            need(bridge_unit_absent(unit(B)) and time.monotonic() < DEADLINE, bad)
        observed = write(target, record, replacements[key], generation=generation, witness=True)
        pending['files'][key] = file_pin(replacements[key], observed)
    if new_unit is not None:
        pending['bridgeUnit'] = file_pin(new_unit, write(unit_path, None, new_unit, witness=True))
    final = entry(encode(journal))
    read_apply_profiles(pending['files'])
    need(time.monotonic() < DEADLINE, 'IN_FLIGHT')
    write(path, proof, final, generation=journal_generation)
    return final


def apply_network(request, action):
    global NETWORK_UPGRADE_ENTERED
    token, d = request['backupId'], request['network']
    finalizing = action == 'finalize-apply-profiles'
    path, manifest, backup, _ = owned_installation(request, pending_apply=finalizing or action == 'restart-apply-network')
    pending = backup.get('applyPending')

    if pending is not None:
        need(backup['phase'] == APPLY_PROFILES_PHASE and installed_phase(pending['phase']), 'ROLLBACK_DRIFT')
        read_apply_profiles(pending['files'])
    record, generation = read(NET, 65536), remove_generation(NET)
    need(after_match(record, backup['after']['net']) and generation == backup['runtime']['files']['net'], 'ROLLBACK_DRIFT')
    # At restart entry the new files are already published, but MAIN still
    # runs the old generation and BRIDGE may be stopped. The caller checked
    # the old handoff before publishing; check MAIN after its restart and the
    # effective pair in the final verify, never join new files to old sockets.
    legacy, stable, main_invocation, _ = apply_network_snapshot(
        d, token, backup, record, generation, handoff_check=action != 'restart-apply-network')
    if legacy and action == 'prepare-apply-network':
        replacement = entry(network_unit(d, 'bridge' in backup['after']), 0o644)
        pin = digest(raw(replacement))
        # Do not adopt a partial file/manager/receipt transition on replay.
        # The intent retains the exact old receipt and the intended new bytes.
        pending = entry(encode({**backup, 'phase': 'network-upgrading', 'networkUpgrade': pin}))
        need(apply_network_snapshot(d, token, backup, record, generation)[:3]
             == (True, stable, main_invocation), 'ROLLBACK_DRIFT')
        NETWORK_UPGRADE_ENTERED = True
        write(path, manifest, pending)
        need(remove_generation(NET) == generation, 'ROLLBACK_DRIFT')
        write(NET, record, replacement)
        generation = remove_generation(NET)
        sc('daemon-reload', wait=12)
        need(apply_network_snapshot(d, token, backup, replacement, generation)[:3]
             == (False, stable, main_invocation), 'ROLLBACK_DRIFT')
        backup['after']['net'] = {**replacement, 'data': pin}
        backup['runtime']['files']['net'] = generation
        manifest = entry(encode(backup))
        write(path, pending, manifest)
        need(read(path, 2 * MAX_FILE) == manifest, 'ROLLBACK_DRIFT')
        legacy = False
    need(action != 'prepare-apply-network' or not legacy, 'RUNTIME_UNPROVED')
    proof = digest(encode([digest(raw(manifest)), generation, stable]))
    if finalizing or action in ('verify-apply-network', 'restart-apply-network', 'publish-apply-profiles'):
        need(not legacy and proof == request['proof'], 'RUNTIME_UNPROVED')
    if action == 'publish-apply-profiles':
        manifest = publish_apply_profiles(request, path, manifest, backup, main_invocation)
        proof = digest(encode([digest(raw(manifest)), generation, stable]))
    if action == 'restart-apply-network':
        # Final effective-graph observation and the actual restart share the
        # DIRECT flock; no manager reload or separate SSH channel intervenes.
        need(pending is None or main_invocation == pending['mainInvocation'], 'RUNTIME_UNPROVED')
        if pending is not None:
            read_apply_profiles(pending['files'])
        NETWORK_UPGRADE_ENTERED = True
        sc('restart', X, wait=45)
        until = min(DEADLINE, time.monotonic() + 6)
        while True:
            new_legacy, new_stable, active_invocation, ready = apply_network_snapshot(
                d, token, backup, record, generation, listeners_required=False)
            need(not new_legacy and new_stable == stable and active_invocation != main_invocation, 'RUNTIME_UNPROVED')
            need(time.monotonic() < until, 'RUNTIME_UNPROVED')
            if ready:
                break
            time.sleep(0.2)
    if finalizing:
        if pending is None:
            raise Refusal('ROLLBACK_DRIFT')
        NETWORK_UPGRADE_ENTERED = True  # The earlier publication has entered.
        need(main_invocation != pending['mainInvocation'], 'RUNTIME_UNPROVED')
        manifest_generation = remove_generation(path)
        x, b = unit(X), unit(B)
        old_units = backup['before']['units']
        need(xray_accounts_match(x, old_units[X]) and xray_accounts_match(b, old_units[B]), 'ROLLBACK_DRIFT')
        b_state = apply_bridge_state(b, pending['bridgeActive'])
        need(b_state == pending['bridgeUnit'], 'ROLLBACK_DRIFT')
        profiles = read_apply_profiles(pending['files'])
        rows = sock_rows()
        xray_users(profiles['main'], x, rows, apply_transit(profiles['main']))
        apply_udp_check(profiles, rows, x, b, d['tproxyPort'])
        tcp = apply_tcp_pin(rows, x, b)
        snapshot = apply_network_snapshot(d, token, backup, record, generation)
        confirmed_rows = sock_rows()
        apply_udp_check(profiles, confirmed_rows, x, b, d['tproxyPort'])
        need(snapshot[:3] == (False, stable, main_invocation) and x['InvocationID'] == main_invocation
             and x['UnitFileState'] == 'enabled'
             and apply_tcp_pin(confirmed_rows, x, b) == tcp and apply_bridge_state(b, pending['bridgeActive']) == b_state
             and unit(X) == x and unit(B) == b and manifest_generation is not None
             and time.monotonic() < DEADLINE, 'RUNTIME_UNPROVED')
        read_apply_profiles(pending['files'])
        finished = {**backup, 'phase': pending['phase'], 'currentApply': {
            'nodeId': pending['nodeId'], 'files': pending['files'], 'bridgeActive': pending['bridgeActive'],
            'bridgeUnit': b_state, 'tcp': tcp}}
        del finished['applyPending']
        replacement = entry(encode(finished))
        need(len(raw(replacement)) <= 2 * MAX_FILE, 'ROLLBACK_DRIFT')
        write(path, manifest, replacement, generation=manifest_generation)
    return {'ok': True, 'backupId': token, 'proof': proof}


def file_pin(record: Any, generation):
    need(record is not None and generation is not None, 'ROLLBACK_DRIFT')
    return [{**record, 'data': digest(raw(record))}, generation]


def chap_preconditions(request):
    bad = 'ROLLBACK_DRIFT'
    path, manifest, backup, intent = owned_installation(request)
    before, runtime = runtime_before(backup), backup['runtime']
    no_jobs(UNITS)
    removal_boot(before, backup, runtime)
    records = {}
    for key, file in operation_files(backup['after']).items():
        if key in ('main', 'bridge', 'chap'):
            continue
        generation = remove_generation(file)
        records[key] = read(file)
        need(after_match(records[key], backup['after'][key]) and generation == runtime['files'][key]
             and remove_generation(file) == generation, bad)
    check_swan_profile(backup, records.get('swan'), bad)
    pool = chap_pool(raw(records['lns']), request['network']['clientCidr'])
    current_rows, current_logins = chap_user_rows(request['currentUsers'], pool)
    desired_rows, desired_logins = chap_user_rows(request['desiredUsers'], pool)
    revoked = request.get('revokedLogin')
    if 'revokedLogin' in request:
        need(type(revoked) is str and re.fullmatch(CHAP_LOGIN, revoked.encode('ascii'))
             and revoked != 'relay-bootstrap', 'CANDIDATE_INVALID')
        current = {u['login']: u for u in request['currentUsers']}
        desired = {u['login']: u for u in request['desiredUsers']}
        need(revoked in current and (revoked not in desired or desired[revoked] == {**current[revoked], 'enabled': False})
             and {k: u for k, u in desired.items() if k != revoked} ==
                 {k: u for k, u in current.items() if k != revoked}, 'CANDIDATE_INVALID')
    xl = unit(XL)
    need(all(read(p, 262144) == record for p, record in before['globalFiles'].items())
         and removal_native(xl, XL, before, installed=True), bad)
    need(working(xl) or rollback_quiescent(xl) or (xl['ActiveState'], xl['SubState'], xl['MainPID']) == ('failed', 'failed', '0'), bad)
    check_runtime_unit_epoch(runtime, XL, xl)
    return path, manifest, backup, intent, xl, current_rows, desired_rows, current_logins | desired_logins


def sync_chap(request, *, write_changes):
    global CHAP_ENTERED
    bad = 'ROLLBACK_DRIFT'
    path, manifest, backup, intent, xl, current_rows, desired_rows, logins = chap_preconditions(request)
    generation = chap_generation(backup['phase'])
    # Omission belongs only to a genuinely unfenced install. In particular a
    # previously valid CHAP preimage does not authorize an obsolete command.
    need(not write_changes or request.get('generation') == generation, bad)
    target = NAMES['chap']
    manifest_generation, old_generation = remove_generation(path), remove_generation(target)
    record = read(target)
    prefix, suffix, rows = owned_chap(record, backup, (current_rows, logins))
    need(record is not None, bad)
    after = record
    if rows != desired_rows:
        data = prefix + CHAP_BEGIN + b'\n' + b''.join(desired_rows[k] for k in sorted(desired_rows)) + CHAP_END + b'\n' + suffix
        need(len(data) <= MAX_FILE, bad)
        after = {**record, 'data': b64(data)}
    need(manifest_generation is not None and old_generation is not None and read(path, 2 * MAX_FILE) == manifest
         and remove_generation(path) == manifest_generation and directory_absent(intent) and read(target) == record
         and remove_generation(target) == old_generation, bad)
    changed = after != record
    if write_changes and changed:
        # The control-plane intent owns DB settlement. Do not accept the desired
        # projection in place of current, or attempt a physical retry/rollback.
        # A valid managed DB projection does not authorize unrelated neighbor
        # bytes or an historical replacement inode for reboot reattestation.
        tracked = file_pin(record, old_generation) == backup.get('currentChap', [
            backup['after']['chap'], backup['runtime']['files']['chap']])
        if tracked:
            upper = entry(encode({**backup, 'currentChap': file_pin(after, [10**20-1]*3)}))
            need(len(raw(upper)) <= 2 * MAX_FILE, bad)
        CHAP_ENTERED = True
        actual = write(target, record, after, generation=old_generation, witness=True)
        if tracked:
            replacement = entry(encode({**backup, 'currentChap': file_pin(after, actual)}))
            need(len(raw(replacement)) <= 2 * MAX_FILE and remove_generation(target) == actual
                 and time.monotonic() < DEADLINE, bad)
            write(path, manifest, replacement, generation=manifest_generation)
            manifest = replacement
    reply = {'ok': True, 'backupId': request['backupId'], 'changed': changed}
    if not write_changes and generation is not None:
        reply['generation'] = generation
    if write_changes and 'revokedLogin' in request:
        # Even a previously disabled row can have surviving authenticated calls.
        CHAP_ENTERED = True
        reply.update(revoke_ppp(request, {**request, 'currentUsers': request['desiredUsers']}, after, path, manifest, xl))
    return reply


def chap_projection(record, current_rows, desired_rows, logins):
    prefix, _, suffix, rows = chap_parts(record)
    original, desired = rows == current_rows, rows == desired_rows
    need(original or desired, 'ROLLBACK_DRIFT')
    check_chap_neighbors(prefix, logins)
    check_chap_neighbors(suffix, logins)
    return original, desired


def fence_chap(request):
    global CHAP_ENTERED
    bad = 'ROLLBACK_DRIFT'
    path, manifest, backup, intent, xl, current_rows, desired_rows, logins = chap_preconditions(request)
    predecessor = chap_generation(backup['phase'])
    need(request['generation'] == predecessor, bad)
    target = NAMES['chap']
    generation = remove_generation(target)
    record = read(target)
    chap_projection(record, current_rows, desired_rows, logins)
    no_jobs(UNITS)
    need(unit(XL) == xl and directory_absent(intent) and generation is not None
         and read(target) == record and remove_generation(target) == generation, bad)
    # The exclusive SYSTEM flock spans the preimage and exact manifest CAS.
    # Old in-flight helpers accept only 'installed'; neither this action nor
    # a late replay of it can re-publish the predecessor phase.
    successor = uuid.uuid4().hex
    need(successor != predecessor, bad)
    session_need(time.monotonic() < DEADLINE)
    updated = entry(encode({**backup, 'phase': CHAP_GENERATION_PREFIX + successor}))
    CHAP_ENTERED = True
    write(path, manifest, updated)
    session_need(time.monotonic() < DEADLINE)
    return {'ok': True, 'backupId': request['backupId'], 'fenced': True}


class InspectUnproved(Refusal):
    pass


class PidfdGetfdDenied(Refusal):
    pass


@contextlib.contextmanager
def inspect_stage(stage):
    try:
        yield
    except (InspectUnproved, subprocess.TimeoutExpired, BlockingIOError):
        raise
    except Exception as error:
        if isinstance(error, Refusal) and str(error) in ('IN_FLIGHT', RUNTIME_REATTEST_REQUIRED):
            raise
        if time.monotonic() >= DEADLINE:
            raise subprocess.TimeoutExpired([], 0) from None
        # Only identify EPERM from this exact syscall, not a security policy.
        raise InspectUnproved('PIDFD_GETFD_EPERM' if isinstance(error, PidfdGetfdDenied) else stage) from None


def inspect_chap(request):
    bad = 'ROLLBACK_DRIFT'
    target = NAMES['chap']
    with inspect_stage('CHAP_PROJECTION_UNPROVED'):
        manifest_generation = remove_generation(manifest_path(request['backupId']))
        path, manifest, backup, intent, xl, current_rows, desired_rows, logins = chap_preconditions(request)
        # A failed daemon does not establish that its sessions are gone.
        need(xl['ActiveState'] != 'failed', bad)
        generation = remove_generation(target)
        record = read(target)
        original, desired = chap_projection(record, current_rows, desired_rows, logins)

    def unchanged():
        no_jobs(UNITS)
        check_runtime_boot(backup)
        need(unit(XL) == xl and directory_absent(intent) and read(path, 2 * MAX_FILE) == manifest
             and manifest_generation is not None and remove_generation(path) == manifest_generation
             and read(target) == record and generation is not None and remove_generation(target) == generation, bad)
        session_need(time.monotonic() < DEADLINE)

    revoked = request.get('revokedLogin')
    count = 0  # No target on a non-revoke; this does not assert PPP idleness.
    with inspect_stage('READBACK_UNPROVED'), contextlib.ExitStack() as stack:
        watch = None
        if revoked is not None:
            with inspect_stage('PPP_UNPROVED'):
                session_need(os.uname().machine == 'x86_64')
                # The owner reads the live CHAP projection. Authenticated sessions
                # are joined to the original users, including the removed login.
                observed = {**request, 'currentUsers': request['currentUsers' if original else 'desiredUsers']}
                if rollback_quiescent(xl):
                    quiet = quiescent_session_sample(observed)
                    session_need(quiet == quiescent_session_sample(observed))
                else:
                    owner = session_owner(observed)
                    session_need((owner[1], str(owner[2])) == (xl['InvocationID'], xl['MainPID']))
                    users = {u['login']: u['ipAddress'] for u in request['currentUsers']}
                    sample, _, watch = stack.enter_context(revoke_ppp_view(owner))
                    before = sample()
                    peers = revoke_peer_logins(before[1], users)
                    session_need(owner == session_owner(observed) and before == sample()
                                 and peers == revoke_peer_logins(before[1], users) and before == sample())
                    count = sum(login == revoked for login in peers.values())
        unchanged()
        if watch is not None:
            watch()
    if time.monotonic() >= DEADLINE:
        raise subprocess.TimeoutExpired([], 0)
    projection = 'both' if original and desired else 'original' if original else 'desired'
    reply = {'ok': True, 'backupId': request['backupId'], 'projection': projection, 'activeTargetSessions': count}
    if (epoch := chap_generation(backup['phase'])) is not None:
        reply['generation'] = epoch
    return reply


def observe_removal(request, *, quiescent=False, active=False, remove_intent=None):
    bad = 'ROLLBACK_DRIFT'
    token, d = request['backupId'], request['network']
    path, manifest, backup, intent = owned_installation(request, remove_intent=remove_intent)
    module_owner = module_boot_owner(backup)
    check_module_boot_owner(module_owner)
    before, runtime = runtime_before(backup), backup['runtime']
    no_jobs(UNITS)
    boot_enrollment = removal_boot(before, backup, runtime)
    original_ike = before.get('ikeSockets', [])
    need(bool(original_ike) == (before['units'][IKE]['ActiveState'] == 'active'), bad)
    paths = operation_files({'swan': None} if 'swan' in backup['after'] else {})
    current = {k: read(p) for k, p in paths.items()}
    check_swan_profile(backup, current.get('swan'), bad)
    main = current['main']
    if main is None:
        raise Refusal(bad)
    generations = file_generations(current, include_chap=False)
    # Apply can replace Xray profiles; CHAP owns only its managed rows. Other
    # owned files must still be the exact installed generation and bytes.
    need(all(after_match(current[k], backup['after'][k]) and generations[k] == runtime['files'][k]
             for k in paths if k not in ('main', 'chap')), bad)
    expected_chap = chap_expected(request, current['lns'])
    chap_after, chap_digest = remove_chap(current['chap'], backup, expected_chap)
    removal_owned_dirs()
    need(ike_include_matches(current['starter'], [os.path.basename(NAMES['ike'])]), bad)
    side, side_generation = read(BRIDGE), remove_generation(BRIDGE)
    need(all(read(p, 262144) == r for p, r in before['globalFiles'].items()), bad)
    units = {n: unit(n) for n in UNITS}
    b = units[B]
    if (applied := backup.get('currentApply')) is not None:
        need(applied['nodeId'] == request['nodeId']
             and encode(file_pin(main, generations['main'])) == encode(applied['files']['main'])
             and encode(file_pin(side, side_generation)) == encode(applied['files']['bridge'])
             and apply_bridge_state(b, applied['bridgeActive']) == applied['bridgeUnit'], bad)
    need(b['ActiveState'] in ('active', 'inactive') and b['NeedDaemonReload'] == 'no'
         and (working(b) and side is not None if b['ActiveState'] == 'active' else b['MainPID'] == '0'), bad)
    profiles, handoff, handoff_unit = removal_profiles(current['main'], side, request['nodeId'], d['tproxyPort'],
                                                       backup, units, generations['main'], side_generation)
    if b['ActiveState'] == 'active':
        xray_argv(b, BRIDGE)
    kind = network_kind(current['net'], d, 'bridge' in backup['after'], token, backup['after']['nft']['data'])
    pinned = kind == 'pinned'
    removal_units(units, before, runtime, 'bridge' in profiles, kind == 'requires', current['net'] if pinned else None)
    if quiescent:
        # An inactive unit alone does not prove the supported Apply layout.
        session_need(rollback_quiescent(units[XL])
                     and units[X]['InvocationID'] != runtime['invocations'][0])
    policy = checked_installed_policy(backup, kind, removing=True)
    rows = sock_rows()
    if applied is not None:
        need(apply_tcp_pin(rows, units[X], b) == applied['tcp'], bad)
        apply_udp_check({'main': main, 'bridge': side}, rows, units[X], b, d['tproxyPort'])
    if quiescent:
        # PPP absence does not require IKE/XFRM to be idle. Keep listener
        # ownership and the PPP guard; Remove still requires full VPN idleness.
        vpn_listener_ownership(rows, units, require_xl_listener=True)
        need(ppp_empty(), bad)
    elif active:
        vpn_listener_ownership(rows, units, require_xl_listener=True)
    else:
        removal_idle(request, rows, units)
    reserved = removal_sockets(rows, units, d, handoff, handoff_unit)
    transit = request.get('transit', before.get('transit'))
    xray_users(current['main'], units[X], rows, transit)
    udp_endpoints = removal_udp_endpoints(profiles['main'])
    sockets = removal_main_sockets(rows, units[X]['MainPID'], reserved, udp_endpoints)
    bridge_sockets = removal_xray_sockets(rows, b['MainPID'])
    binary = remove_generation(XRAY)
    need(binary is not None, bad)
    manifest_generation = remove_generation(path)
    baseline = digest(encode([request['nodeId'], digest(raw(manifest)), manifest_generation, generations, boot_enrollment,
                              current['main'], {k: digest(raw(v)) for k, v in profiles.items()}, binary,
                              side, side_generation, units, policy, sockets, bridge_sockets, sorted(reserved),
                              handoff, handoff_unit, transit, chap_digest]))
    return dict(baseline=baseline, intent=intent, path=path, manifest=manifest, before=before, current=current,
                runtime_boot=installed_boot(backup),
                profiles=profiles, units=units, side=side, side_generation=side_generation, sockets=sockets,
                udp_endpoints=udp_endpoints,
                bridge_sockets=bridge_sockets, retained_handoff=handoff if handoff_unit == B else None,
                reserved=reserved, policy=policy, pinned_network=pinned, generations=generations, binary=binary,
                boot_enrollment=boot_enrollment, ike_sockets=original_ike, manifest_generation=manifest_generation,
                transit=transit, chap_after=chap_after, chap_digest=chap_digest, chap_expected=expected_chap, chap_backup=backup,
                module_owner=module_owner,
                **({'swanBackup': backup} if 'swan' in current else {}))


def removal_owned_dirs():
    for folder, owned in ((NFT_DIR, NFT_FILE), (DROP_DIR, DROP)):
        with directory(folder) as fd:
            need(os.listdir(fd) == [os.path.basename(owned)], 'ROLLBACK_DRIFT')


def removal_neighbors(state):
    check_prepared_native(state['before'])
    # BRIDGE is checked separately against the selected layout and invocation.
    need(all(read(p, 262144) == r for p, r in state['before']['globalFiles'].items())
         and read(state['path'], 2 * MAX_FILE) == state['manifest']
         and remove_generation(state['path']) == state['manifest_generation']
         and boot() == state['runtime_boot'] and remove_generation(XRAY) == state['binary'], 'RUNTIME_UNPROVED')


def removal_units_after(state, restore_ike=False):
    before = state['before']
    units = {n: unit(n) for n in (X, XL, IKE, NET_UNIT)}
    keys = ('LoadState', 'UnitFileState', 'DropInPaths', 'FragmentPath')
    for n in (XL, IKE, NET_UNIT):
        after, original = units[n], before['units'][n]
        need(all(after.get(k) == original[k] for k in keys)
             and after['NeedDaemonReload'] == 'no', 'RUNTIME_UNPROVED')
        if n != NET_UNIT:
            need(removal_native(after, n, before, installed=False), 'RUNTIME_UNPROVED')
        if n == IKE and restore_ike:
            need(working(after) and after['SubState'] == original['SubState']
                 and after['InvocationID'] not in (original['InvocationID'], state['units'][IKE]['InvocationID']),
                 'RUNTIME_UNPROVED')
        else:
            need((after['ActiveState'], after['SubState'], after['MainPID']) == ('inactive', 'dead', '0'),
                 'RUNTIME_UNPROVED')
    x = units[X]
    # Compare against the fresh Remove snapshot even when the historical
    # Install did not record accounts.
    need(all(x.get(k) == state['units'][X].get(k) for k in ('FragmentPath', 'UnitFileState', 'User', 'Group', 'DropInPaths'))
         and xray_accounts_match(x, before['units'][X]) and working(x), 'RUNTIME_UNPROVED')
    removal_dependencies(units, installed=False)
    return units


def removal_files_after(state):
    before = state['before']
    paths = operation_files(state['current'])
    expected = {**before['files'], 'main': state['profiles']['main'], 'chap': state['chap_after']}
    need(all(read(p) == expected[k] for k, p in paths.items())
         and all(directory_absent(p) for p in (DROP_DIR, NFT_DIR))
         and (state['boot_enrollment'] is None or boot_link() is None)
         and ike_include_matches(before['files']['starter'], []), 'RUNTIME_UNPROVED')
    if 'swan' in paths:
        need(swan_inputs(False, 'RUNTIME_UNPROVED') == before['swanInputs'], 'RUNTIME_UNPROVED')


def removal_bridge_unit(state, restarted=False):
    b, old = unit(B), state['units'][B]
    keys = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'DropInPaths', 'FragmentPath', 'NeedDaemonReload', 'User', 'Group')
    need(all(b.get(k) == old.get(k) for k in keys), 'RUNTIME_UNPROVED')
    if restarted:
        need(b['InvocationID'] != old['InvocationID'], 'RUNTIME_UNPROVED')
    else:
        need(all(b[k] == old[k] for k in ('InvocationID', 'MainPID')), 'RUNTIME_UNPROVED')
    if b['ActiveState'] == 'active':
        xray_argv(b, BRIDGE)
    return b


def removal_bridge_sockets(state, rows, b):
    need(removal_xray_sockets(rows, b['MainPID']) == state['bridge_sockets'], 'RUNTIME_UNPROVED')
    port = state['retained_handoff']
    if port is not None:
        verify_socks_handoff(rows, port, b['MainPID'])


def removal_xray_ready(state, split):
    until = min(DEADLINE, time.monotonic() + 6)
    while True:
        no_jobs(UNITS)
        rows, x = sock_rows(), unit(X)
        need(not any(n in state['reserved'] for _, _, n, _ in rows), 'RUNTIME_UNPROVED')
        try:
            need(x['InvocationID'] != state['units'][X]['InvocationID']
                 and xray_accounts_match(x, state['units'][X]), 'RUNTIME_UNPROVED')
            xray_users(state['profiles']['main'], x, rows, state.get('transit'))
            need(removal_main_sockets(rows, x['MainPID'], state['reserved'], state['udp_endpoints'])
                 == state['sockets'], 'RUNTIME_UNPROVED')
            b = removal_bridge_unit(state, restarted=split)
            removal_bridge_sockets(state, rows, b)
            return x, b
        except Refusal as error:
            if str(error) not in ('PROFILE_USERS', 'RUNTIME_UNPROVED') or time.monotonic() >= until:
                raise
            time.sleep(0.2)


def removal_ike_ready(state):
    until = min(DEADLINE, time.monotonic() + 6)
    while True:
        no_jobs(UNITS)
        ike = unit(IKE)
        try:
            need(idle_ike(ike, sock_rows()) == state['ike_sockets'], 'RUNTIME_UNPROVED')
            return ike['InvocationID']
        except Refusal as error:
            if str(error) not in ('PREREQUISITE', 'RUNTIME_UNPROVED') or time.monotonic() >= until:
                raise
            time.sleep(0.2)


def discard_removed_cleanup_backup(state, intent_record):
    if 'foreignCleanup' not in state['before']:
        return
    path, record = state['path'], state['manifest']
    backup = json.loads(raw(record))
    journal = backup.get('foreignJournal')
    need(installed_phase(backup['phase']) and type(journal) is dict
         and journal.get('editsSha256') == digest(encode(journal['edits']))
         and removal_intent_matches(state['intent'], intent_record), 'ROLLBACK_DRIFT')
    # Retire all private preimages, not the no-replay generation. Older
    # receive helpers still collide with its exact existing token directory.
    tombstone = entry(encode({'phase': 'removed', 'backupId': backup['backupId']}))
    write(path, record, tombstone)
    need(read(path, 2 * MAX_FILE) == tombstone, 'ROLLBACK_DRIFT')


def remove_installation(request, state, *, drain=None):
    global REMOVE_ENTERED, STAGE
    token, d = request['backupId'], request['network']
    before, current, profiles, units = (state[k] for k in ('before', 'current', 'profiles', 'units'))
    policy, reserved, sockets = (state[k] for k in ('policy', 'reserved', 'sockets'))

    def observe_policy():
        return network_projection(d, token, removing=True, pinned=state.get('pinned_network', False))

    boot_enrollment, restore_ike = state['boot_enrollment'], bool(state['ike_sockets'])
    split = 'bridge' in profiles
    STAGE = 'RUNTIME_UNPROVED'
    no_jobs(UNITS)
    need(boot_enrollment is None or boot_link() == boot_enrollment, 'ROLLBACK_DRIFT')
    if 'swan' in current:
        check_swan_profile(state['swanBackup'], read(SWAN_PROFILE))

    def live_chap():
        record = read(NAMES['chap'])
        restored, chap_digest = remove_chap(record, state['chap_backup'], state['chap_expected'])
        need(chap_digest == state['chap_digest'], 'ROLLBACK_DRIFT')
        return record, restored

    live_chap()
    if drain is not None:
        drain[0]()  # Last full observation; retains the original pidfd and VICI peer.
    elif 'expectedCensus' in request:
        # Still under the exclusive DIRECT flock. A panel recount and prepare
        # snapshot cannot authorize a write against a busy or unknown census.
        census = relay_session_census(request, state['baseline'] if rollback_quiescent(units[XL]) else None)
        if census['activeIpsec'] is not None and not request.get('retirement'):
            need(census['activeIpsec'] == 0, 'REMOVE_IPSEC_BUSY')
        session_need(census['activeSessions'] == census['activeIpsec'] == 0
                     and census['census'] == request['expectedCensus'])
    else:
        # Older trusted callers don't supply a PPP census token. They still
        # need a positive IPsec zero, not an unreadable/unrecognized status.
        count, _ = ipsec_session_sample(request)
        need(count == 0, 'REMOVE_IPSEC_BUSY')
    # Keep the original residual guards, including unscoped/foreign state.
    if drain is None:
        removal_idle(request, sock_rows(), units)
    check_module_boot_owner(state.get('module_owner'))
    # Retain the install manifest unchanged. Durable no-replace intent
    # prevents blind replay even if the first stop's result is unknown.
    intent_record = entry(encode({'baseline': state['baseline']}))
    REMOVE_ENTERED = True
    write(state['intent'], None, intent_record)
    if drain is not None:
        drain[1](intent_record)
    for name in (XL, IKE, NET_UNIT):
        fresh = {n: unit(n) for n in (X, XL, IKE, NET_UNIT)}
        removal_dependencies(fresh, installed=True)
        info = fresh[name]
        need(info == units[name], 'ROLLBACK_DRIFT')
        if name in (XL, IKE):
            need(removal_native(info, name, before, installed=True), 'ROLLBACK_DRIFT')
        if info['ActiveState'] == 'active':
            if name in (XL, IKE):
                removal_vpn_runtime(sock_rows(), fresh)
            if name == XL and drain is not None:
                drain[2](1)  # No second pppd can be born while XL is still live.
            if name == IKE and drain is not None:
                drain[3]()
            if name == IKE and 'swan' in current:
                check_swan_profile(state['swanBackup'], read(SWAN_PROFILE))
            sc('stop', name, wait=14)
            no_jobs(UNITS)
        elif info['ActiveState'] == 'failed':
            sc('reset-failed', name)
            no_jobs(UNITS)
        after = unit(name)
        # xl2tpd exits 1 on SIGTERM even when systemctl stop itself succeeds.
        if (name == XL and info['ActiveState'] == 'active'
                and (after['ActiveState'], after['SubState'], after['MainPID']) == ('failed', 'failed', '0')):
            sc('reset-failed', name)
            no_jobs(UNITS)
            after = unit(name)
        need((after['ActiveState'], after['SubState'], after['MainPID']) == ('inactive', 'dead', '0'), STAGE)
    need(vpn_empty() and not any(n in (500, 4500, 1701) for _, _, n, _ in sock_rows())
         and observe_policy() == policy, STAGE)
    removal_neighbors(state)
    removal_owned_dirs()
    need(file_generations(current, include_chap=False) == state['generations'] and (boot_enrollment is None or boot_link() == boot_enrollment),
         'ROLLBACK_DRIFT')
    live_chap()
    # Keep the ingress firewall in place until the owned listeners are gone.
    x = unit(X)
    need(all(x[k] == units[X][k] for k in ('InvocationID', 'MainPID')), STAGE)
    removal_bridge_unit(state)
    need(read(BRIDGE) == state['side'] and remove_generation(BRIDGE) == state['side_generation'], STAGE)
    side_generation = state['side_generation']
    if split:
        write(BRIDGE, state['side'], profiles['bridge'])
        side_generation = remove_generation(BRIDGE)
    paths = operation_files(current)
    for k in reversed(operation_order(current)):
        if k == 'chap':
            # Re-read the foreign bytes at the actual write boundary; only the
            # owned rows are bound by the preview and the census.
            record, state['chap_after'] = live_chap()
            write(paths[k], record, state['chap_after'])
            continue
        need(remove_generation(paths[k]) == state['generations'][k], STAGE)
        restored = profiles[k] if k == 'main' else before['files'][k]
        if current[k] != restored:
            if k == 'swan':
                check_swan_profile(state['swanBackup'], read(SWAN_PROFILE))
            write(paths[k], current[k], restored, generation=state['generations'][k] if k == 'main' else None)
    if boot_enrollment is not None:
        enroll_boot(before['units'][XL]['FragmentPath'], boot_enrollment)
    main_generation = remove_generation(MAIN)

    def profiles_unchanged():
        need(read(MAIN) == profiles['main'] and remove_generation(MAIN) == main_generation
             and read(BRIDGE) == profiles.get('bridge', state['side'])
             and remove_generation(BRIDGE) == side_generation, STAGE)

    for folder in (DROP_DIR, NFT_DIR):
        rmdir(folder)
    sc('daemon-reload', wait=12)
    no_jobs(UNITS)
    removal_neighbors(state)
    removal_files_after(state)
    pre_restart = removal_units_after(state)[X]
    need(all(pre_restart[k] == units[X][k] for k in ('InvocationID', 'MainPID')), STAGE)
    xray_argv(pre_restart)
    profiles_unchanged()
    removal_bridge_unit(state)
    need(remove_generation(XRAY) == state['binary'], STAGE)
    sc('restart', X, wait=22)
    if split:
        no_jobs(UNITS)
        removal_bridge_unit(state)
        profiles_unchanged()
        need(remove_generation(XRAY) == state['binary'], STAGE)
        sc('restart', B, wait=22)
    x, b = removal_xray_ready(state, split)
    profiles_unchanged()
    need(remove_generation(XRAY) == state['binary'] and observe_policy() == policy, STAGE)
    command('/usr/sbin/ip', '-4', 'rule', 'del', 'priority', str(PRIORITY), 'from', d['clientCidr'], 'fwmark',
            str(d['fwmark']), 'table', str(d['routeTable']))
    need(observe_policy() == {**policy, 'rule': False}, STAGE)
    command('/usr/sbin/ip', '-4', 'route', 'del', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', str(d['routeTable']))
    need(observe_policy() == {**policy, 'rule': False, 'route': False}, STAGE)
    command('/usr/sbin/nft', 'delete', 'table', 'inet', TABLE)
    empty_policy = {'nft': None, 'rule': False, 'route': False}
    restored_invocation = None
    if restore_ike:
        # Only restart a previously running starter, after its original
        # inputs/dependencies are back and every install-only port is empty.
        no_jobs(UNITS)
        removal_neighbors(state)
        removal_files_after(state)
        removal_units_after(state)
        need(vpn_empty() and not any(n in reserved for _, _, n, _ in sock_rows())
             and observe_policy() == empty_policy, STAGE)
        sc('start', IKE, wait=22)
        restored_invocation = removal_ike_ready(state)
    no_jobs(UNITS)
    after = removal_units_after(state, restore_ike=restore_ike)
    rows, final_x = sock_rows(), after[X]
    if restore_ike:
        need(after[IKE]['InvocationID'] == restored_invocation
             and idle_ike(after[IKE], rows) == state['ike_sockets'], STAGE)
    absent = reserved - ({500, 4500} if restore_ike else set())
    final_b = removal_bridge_unit(state, restarted=split)
    removal_bridge_sockets(state, rows, final_b)
    profiles_unchanged()
    need(all(final_x[k] == x[k] and final_b[k] == b[k] for k in ('InvocationID', 'MainPID')), STAGE)
    xray_users(profiles['main'], final_x, rows, state.get('transit'))
    need(removal_main_sockets(rows, final_x['MainPID'], reserved, state['udp_endpoints']) == sockets
         and not any(n in absent for _, _, n, _ in rows)
         and observe_policy() == empty_policy
         and vpn_empty(allow_socket_policies=restore_ike) and read(state['path'], 2 * MAX_FILE) == state['manifest'] and state['runtime_boot'] == boot()
         and remove_generation(XRAY) == state['binary'], STAGE)
    removal_files_after(state)
    removal_neighbors(state)
    release_module_boot(state.get('module_owner'))
    discard_removed_cleanup_backup(state, intent_record)


SESSION_UNKNOWN = 'SESSION_COUNT_UNPROVED'
SESSION_GROUP = '/system.slice/xl2tpd.service'
SESSION_XL = '/usr/sbin/xl2tpd'
SESSION_PPP = '/usr/sbin/pppd'
# Debian trixie amd64 xl2tpd 1.3.18-1+b1 and ppp 2.5.2-1+1 (dpkg-deb -x).
SESSION_STOCK = {
    SESSION_XL: '48bd1fd6a7b9d4cdd3a5f20386654b2fa03ee19a9abdc9a1012ddf605290654b',
    SESSION_PPP: 'eb93a25616854a7bdeeff5e6317601eac9f33c69d68bc5a1d127a9eb4530c3bf',
    '/usr/lib/pppd/2.5.2/pppol2tp.so': 'e5bbd060e4bfd87661f14f9a766a0b2fcf17c7f4eb352127e8da9210b52fc3b8',
}
SESSION_GLOBAL = {
    '/etc/ppp/options': '5ec5ff67de7a81f6fedb5a32ef06b839f543a410a42055da169c8d2ef3d04246',
    '/etc/ppp/ip-pre-up': '4c94ffad8f1eed66bdccd9456f50a1f0aae54978cf6c1e84f439bcb46a32db57',
    '/etc/ppp/ip-up': '3a7c1bf309a3fa4ea4b324fccc5ca2c5d907ada04c6b3b7c35ef9893f0e0eab1',
    '/etc/ppp/ip-down': '57c4112f686ce228078d964555dec9ebf6f07f5dbf77daae01a7ba8e717cfb3f',
    '/etc/ppp/ip-up.d/0000usepeerdns': 'c6642e9baa8a2a489eb0ba1bdac1289aafa5e8e58aa5e46c078eece4eaa8cc4d',
    '/etc/ppp/ip-down.d/0000usepeerdns': 'a2f8eff7abd676b154d11b89522a5556263fdbc0cd43d3474a6122cf983ae492',
}


def session_need(ok):
    need(ok, SESSION_UNKNOWN)


def require_census_machine(machine):
    identity = read('/etc/machine-id', 34)
    match = None if identity is None else re.fullmatch(rb'([a-f0-9]{32})\n?', raw(identity))
    if match is None:
        raise Refusal(SESSION_UNKNOWN)
    need(match[1] == machine.encode('ascii'), 'IDENTITY')


def session_fs(libc, fd, magic):
    # x86_64 Linux: struct statfs begins with a native long f_type.
    buf = (ctypes.c_long * 32)()
    session_need(libc.fstatfs(fd, ctypes.byref(buf)) == 0 and buf[0] == magic)


def session_read(fd, name, maximum):
    with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd), 'rb') as f:
        data = f.read(maximum + 1)
    session_need(len(data) <= maximum)
    return data


def session_generation(st):
    return st.st_dev, st.st_ino, st.st_ctime_ns


def session_binary(path):
    # pppd is legitimately setuid in the stock archive; don't weaken read().
    folder, name = os.path.split(path)
    with directory(folder) as fd:
        with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd), 'rb') as f:
            st = os.fstat(f.fileno())
            session_need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o022
                         and 0 < st.st_size <= 2**21)
            data = f.read(2**21 + 1)
            generation = session_generation(st)
            session_need(len(data) == st.st_size and digest(data) == SESSION_STOCK[path]
                         and generation == session_generation(os.fstat(f.fileno()))
                         == session_generation(os.stat(name, dir_fd=fd, follow_symlinks=False)))
    return generation


def session_profile(lns, options, network):
    addr = rb'([0-9.]{7,15})'
    match = re.fullmatch(rb'\[global\]\nport = 1701\n\n\[lns default\]\nip range = ' + addr + rb'-' + addr
                         + rb'\nlocal ip = ' + addr + rb'\nrequire authentication = yes\n'
                         rb'pppoptfile = /etc/ppp/options\.xl2tpd\nlength bit = yes\n', lns)
    if match is None:
        raise Refusal(SESSION_UNKNOWN)
    start, end, local = (ipaddress.IPv4Address(item.decode('ascii')) for item in match.groups())
    cidr = ipaddress.IPv4Network(network['clientCidr'])
    session_need(cidr.network_address < start <= end < cidr.broadcast_address
                 and cidr.network_address < local < cidr.broadcast_address and not start <= local <= end)
    match = re.fullmatch(rb'auth\nrefuse-pap\nrefuse-chap\nrefuse-mschap\nrequire-mschap-v2\nrefuse-eap\nname l2tpd\n'
                         rb'mtu ([0-9]{3,4})\nmru ([0-9]{3,4})\nnoipv6\nnodefaultroute\n'
                         rb'(ms-dns [0-9.]{7,15}\n){1,4}', options)
    session_need(match is not None and all(576 <= int(n) <= 1500 for n in match.groups()[:2]))
    for line in options.split(b'\n'):
        if line.startswith(b'ms-dns '):
            ipaddress.IPv4Address(line[7:].decode('ascii'))
    return local, start, end


def session_owner(request, *, remove_intent=None):
    token, machine, network = (request[k] for k in ('backupId', 'machineId', 'network'))
    require_census_machine(machine)
    path, manifest, backup = read_manifest(token)
    before, runtime = runtime_before(backup), backup['runtime']
    session_need(installed_phase(backup['phase']) and backup['backupId'] == token and backup['machineId'] == machine
                 and encode(backup['network']) == encode(network)
                 and removal_intent_matches(os.path.dirname(path) + '/remove-attempt.json', remove_intent))
    epoch = check_runtime_boot(backup)
    no_jobs((XL, NET_UNIT, IKE))
    info = unit(XL)
    session_need(info['FragmentPath'] == SYSTEM + '/' + XL and removal_native(info, XL, before, installed=True)
                 and working(info) and info['SubState'] == 'running' and info['Type'] == 'simple'
                 and re.fullmatch(r'[a-f0-9]{32}', info['InvocationID']) and info['ControlGroup'] == SESSION_GROUP
                 and re.fullmatch(r'[1-9][0-9]*', info['MainPID'])
                 and re.fullmatch(r'\{ path=/usr/sbin/xl2tpd ; argv\[\]=/usr/sbin/xl2tpd -D ;[^{}]*\}', info['ExecStart'])
                 and not any(info.get(k) for k in ('SourcePath', 'ExecCondition', 'ExecReload', 'PassEnvironment', 'UnsetEnvironment'))
                 and set(info['Requires'].split()) >= {NET_UNIT, IKE} and set(info['After'].split()) >= {NET_UNIT, IKE})
    check_runtime_unit_epoch(runtime, XL, info)
    rows = [owners for proto, _, port, owners in sock_rows() if proto == 'udp' and port == 1701]
    session_need(rows and all(owners == [info['MainPID']] for owners in rows))
    records, generations = {}, {}
    for k in ('lns', 'options', 'drop', 'net', 'nft'):
        file = NAMES[k]
        generation = remove_generation(file)
        record = read(file, 65536)
        if record is None:
            raise Refusal(SESSION_UNKNOWN)
        records[k] = record
        session_need(encode({**record, 'data': digest(raw(record))}) == encode(backup['after'][k])
                     and encode(generation) == encode(runtime['files'][k]) and generation == remove_generation(file))
        generations[k] = generation
    session_need(nft_marker(raw(records['nft']), token))
    for folder, leaves in (('/etc/ppp/ip-pre-up.d', []), ('/etc/ppp/ip-up.d', ['0000usepeerdns']),
                           ('/etc/ppp/ip-down.d', ['0000usepeerdns'])):
        with directory(folder) as fd:
            session_need(os.listdir(fd) == leaves)
    session_need(pwd.getpwuid(0).pw_dir == '/root')
    for p in ('/root/.ppprc', '/etc/ppp/auth-up', '/etc/ppp/auth-down', '/etc/ppp/net-init', '/etc/ppp/net-pre-up',
              '/etc/ppp/net-down', '/etc/ppp/ip-pre-up.local', '/etc/ppp/ip-up.local', '/etc/ppp/ip-down.local'):
        session_need(directory_absent(p))
    for p, sha in SESSION_GLOBAL.items():
        current = read(p, 65536)
        session_need(current is not None and digest(raw(current)) == sha
                     and (p != '/etc/ppp/options' or current == before['globalFiles'][p]))
    profile = session_profile(raw(records['lns']), raw(records['options']), network)
    _, _, chap_rows = owned_chap(read(NAMES['chap']), backup, chap_expected(request, records['lns']))
    generations['chapRows'] = chap_rows_digest(chap_rows)
    return (epoch, info['InvocationID'], int(info['MainPID']), remove_generation(path), digest(raw(manifest)),
            generations, {p: session_binary(p) for p in SESSION_STOCK}, profile)


def session_cgroup(fd):
    data = session_read(fd, 'cgroup.procs', 32768)
    counts = session_read(fd, 'cgroup.stat', 65536).split(b'\n')
    session_need(re.fullmatch(rb'(?:[1-9][0-9]{0,9}\n)+', data) and b'nr_descendants 0' in counts
                 and b'nr_dying_descendants 0' in counts)
    pids = [int(p) for p in data.split()]
    session_need(len(pids) <= 2049 and len(pids) == len(set(pids)))
    return sorted(pids)


@contextlib.contextmanager
def session_process(proc, pid, main, binaries, watch):
    with contextlib.ExitStack() as stack:
        task = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=proc)
        stack.callback(os.close, task)
        data = session_read(task, 'stat', 4096)
        fields = data.rsplit(b') ', 1)[1].split()
        session_need(data.startswith(str(pid).encode() + b' (') and fields[0] in (b'R', b'S')
                     and (pid == main or int(fields[1]) == main) and int(fields[19]) > 0
                     and session_read(task, 'cgroup', 4096) == ('0::' + SESSION_GROUP + '\n').encode())
        for name in ('ns/net', 'ns/mnt', 'ns/pid', 'ns/user', 'ns/cgroup', 'root'):
            ours, theirs = os.stat('self/' + name, dir_fd=proc), os.stat(name, dir_fd=task)
            session_need((ours.st_dev, ours.st_ino) == (theirs.st_dev, theirs.st_ino))
        exe = SESSION_XL if pid == main else SESSION_PPP
        session_need(os.fstat(task).st_uid == 0 and os.readlink('exe', dir_fd=task) == exe
                     and session_generation(os.stat('exe', dir_fd=task)) == binaries[exe])
        argv = session_read(task, 'cmdline', 4096)
        watch()
        yield task, int(fields[19]), argv


def session_ppp_argv(argv, pool):
    # xl2tpd 1.3.18 control.c:ICCN -> start_pppd(), kernel LNS path.
    match = re.fullmatch(rb'/usr/sbin/pppd\0plugin\0pppol2tp\.so\0pppol2tp\0([1-9][0-9]{0,8})\0'
                         rb'pppol2tp_lns_mode\0pppol2tp_tunnel_id\0([1-9][0-9]{0,4})\0'
                         rb'pppol2tp_session_id\0([1-9][0-9]{0,4})\0passive\0nodetach\0'
                         rb'([0-9.]{7,15}):([0-9.]{7,15})\0auth\0file\0/etc/ppp/options\.xl2tpd\0', argv)
    if match is None:
        raise Refusal(SESSION_UNKNOWN)
    fd, tid, sid = map(int, match.groups()[:3])
    local, peer = (ipaddress.IPv4Address(row.decode()) for row in match.groups()[3:])
    session_need(tid <= 65535 and sid <= 65535 and local == pool[0] and pool[1] <= peer <= pool[2])
    return fd, tid, sid, str(local), str(peer)


@contextlib.contextmanager
def session_dup(libc, pidfd, fd):
    # Getters only; never open /dev/ppp, attach a channel, or open the control FIFO.
    dup = libc.pidfd_getfd(pidfd, fd, 0)
    if dup < 0 and ctypes.get_errno() == errno.EPERM:
        raise PidfdGetfdDenied(SESSION_UNKNOWN)
    session_need(dup >= 0)
    try:
        yield dup
    finally:
        os.close(dup)


def session_kernel(libc, task, pidfd, l2fd, main, tid, sid):
    with session_dup(libc, pidfd, l2fd) as fd:
        st = os.fstat(fd)
        session_need(stat.S_ISSOCK(st.st_mode) and os.readlink('fd/' + str(l2fd), dir_fd=task) == f'socket:[{st.st_ino}]')
        data = ctypes.create_string_buffer(128)
        length = ctypes.c_uint(len(data))
        abi = '=HIii16sHHHH'  # linux/if_pppox.h: packed v2 IPv4 sockaddr_pppol2tp
        session_need(libc.getsockname(fd, ctypes.byref(data), ctypes.byref(length)) == 0
                     and length.value == struct.calcsize(abi))
        family, proto, owner, tunnel_fd, address, t, s, remote_t, remote_s = struct.unpack_from(abi, data)
        session_need((family, proto, owner, t, s) == (24, 1, main, tid, sid) and address[:2] == b'\x02\x00'
                     and tunnel_fd >= 0 and remote_t > 0 and remote_s > 0)
    with contextlib.ExitStack() as stack:
        fds = os.open('fd', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=task)
        stack.callback(os.close, fds)
        entries = os.listdir(fds)
        session_need(len(entries) <= 128 and all(re.fullmatch(r'[0-9]{1,10}', x) for x in entries))
        ppp_fds = [int(x) for x in entries if os.readlink(x, dir_fd=fds) == '/dev/ppp']
        session_need(len(ppp_fds) == 2)
        units = []
        for number in ppp_fds:
            with session_dup(libc, pidfd, number) as fd:
                dev = os.fstat(fd)
                session_need(stat.S_ISCHR(dev.st_mode) and (os.major(dev.st_rdev), os.minor(dev.st_rdev)) == (108, 0))
                try:
                    index, = struct.unpack('=i', fcntl.ioctl(fd, 0x80047456, b'\0' * 4))  # PPPIOCGUNIT
                except OSError as error:
                    if error.errno != errno.ENOTTY:  # channel ENOIOCTLCMD is mapped by vfs_ioctl
                        raise
                    continue
                mode = fcntl.ioctl(fd, 0xc008744c, struct.pack('=ii', 0x21, -1))  # PPPIOCGNPMODE IPv4
                flags, = struct.unpack('=I', fcntl.ioctl(fd, 0x8004745a, b'\0' * 4))  # PPPIOCGFLAGS
                session_need(index >= 0 and mode == struct.pack('=ii', 0x21, 0)  # NPMODE_PASS
                             and not flags & 0x200)  # SC_LOOP_TRAFFIC
                units.append(index)
        session_need(len(units) == 1)
    return units[0], (t, s, remote_t, remote_s), st.st_ino


SESSION_L2TP_HEADER = (b'PPPoL2TP driver info, V2.0\nTUNNEL name, user-data-ok session-count\n'
                       b' debug tx-pkts/bytes/errs rx-pkts/bytes/errs\n'
                       b'  SESSION name, addr/port src-tid/sid dest-tid/sid state user-data-ok\n'
                       b'   mtu/mru/rcvseq/sendseq/lns debug reorderto\n'
                       b'   nr/ns tx-pkts/bytes/errs rx-pkts/bytes/errs\n')
SESSION_TUNNEL_ROW = re.compile(rb"\nTUNNEL 'tunl ([0-9]{1,5})', [YN] -?[0-9]+\n [0-9a-f]{8} (?:-?[0-9]+/){2}-?[0-9]+ "
                                rb'(?:-?[0-9]+/){2}-?[0-9]+\n')
SESSION_L2TP_ROW = re.compile(rb"  SESSION '[^'\n]*' [0-9A-F]{8}/([0-9]+) ([0-9A-F]{4})/([0-9A-F]{4}) -> "
                              rb'([0-9A-F]{4})/([0-9A-F]{4}) ([0-9]+) ([YN])\n'
                              rb'   0/0/[R-]/[S-]/(LNS|LAC) [0-9a-f]{8} [0-9]+\n'
                              rb'   [0-9]+/[0-9]+ (?:-?[0-9]+/){2}-?[0-9]+ (?:-?[0-9]+/){2}-?[0-9]+\n'
                              rb'(?:   interface ([^\n]*)\n)?')


def session_l2tp_interfaces(data, keys):
    # Linux 6.12 l2tp_ppp.c resolves the channel's current netdev. Parse to
    # EOF, including foreign rows, so an unsupported format is not absence.
    session_need(data.startswith(SESSION_L2TP_HEADER))
    rows = {}
    offset = len(SESSION_L2TP_HEADER)
    tunnel_id = 0
    while offset < len(data):
        tunnel = SESSION_TUNNEL_ROW.match(data, offset)
        if tunnel is not None:
            next_id = int(tunnel[1])
            session_need(tunnel_id < next_id <= 65535)
            tunnel_id = next_id
            offset = tunnel.end()
            continue
        match = SESSION_L2TP_ROW.match(data, offset)
        if match is None:
            raise Refusal(SESSION_UNKNOWN)
        offset = match.end()
        port, *ids, state, associated, role, iface = match.groups()
        key = tuple(int(x, 16) for x in ids)
        session_need(key[0] == tunnel_id and tunnel_id > 0)
        if key not in keys and port != b'1701':
            continue
        # l2tp_v2_session_get_next() skips the synthetic session 0 used by
        # the tunnel's control socket. A TUNNEL row alone isn't a call.
        if iface is None:
            raise Refusal(SESSION_UNKNOWN)
        session_need(key in keys and key not in rows and all(key) and port == b'1701' and state == b'3'
                     and associated == b'Y' and role == b'LNS' and re.fullmatch(rb'ppp[0-9]+', iface))
        rows[key] = iface.decode('ascii')
    session_need(set(rows) == keys)
    return rows


def session_links(rows, name, local, peer):
    session_need(type(rows) is list)
    selected = [row for row in rows if row['ifname'] == name]
    session_need(len(selected) == 1)
    link = selected[0]
    session_need(link.get('link_type') == 'ppp' and {'UP', 'POINTOPOINT', 'LOWER_UP'} <= set(link['flags'])
                 and type(link['ifindex']) is int and link['ifindex'] > 0
                 and len([row for row in rows if row['ifindex'] == link['ifindex']]) == 1)
    (addr,) = link['addr_info']
    session_need(addr.get('family') == 'inet' and addr.get('local') == local and (peer is None or addr.get('address') == peer)
                 and addr.get('prefixlen') == 32 and addr.get('scope') == 'global')
    if peer is None:
        return link['ifindex'], str(ipaddress.IPv4Address(addr['address']))
    return link['ifindex']


def session_pid_stamp(name, pid):
    path = '/run/' + name + '.pid'
    st = remove_generation(path)
    stamp = read(path, 32)
    session_need(st is not None and stamp is not None and raw(stamp) == (str(pid) + '\n').encode()
                 and st == remove_generation(path))
    return st


def session_sample(libc, proc, group, owner, held, watch, *, revoke=False):
    _, _, main, _, _, _, binaries, pool = owner
    pids = session_cgroup(group)
    session_need(main in pids)
    sample = {}
    main_start = 0
    for pid in pids:
        pfd = held(pid)
        with session_process(proc, pid, main, binaries, watch) as (task, start, argv):
            if pid == main:
                session_need(argv == b'/usr/sbin/xl2tpd\0-D\0')
                main_start = start
            else:
                l2fd, tid, sid, local, peer = session_ppp_argv(argv, pool)
                number, key, inode = session_kernel(libc, task, pfd, l2fd, main, tid, sid)
                name = 'ppp' + str(number)
                generation = session_pid_stamp(name, pid)
                session_need(key not in sample)
                sample[key] = pid, start, inode, name, local, peer, generation
    # No LNS/debug command; read even for zero to distinguish missing inventory.
    native = session_l2tp_interfaces(session_read(proc, 'self/net/pppol2tp', 2**20), set(sample))
    result = []
    if sample:
        # session_links needs named link types and scopes; the RPDB ip()
        # deliberately uses -N. Keep this dump separate and refuse warnings.
        links = json.loads(command('/usr/sbin/ip', '-j', '-4', '-details', 'addr', 'show', quiet=True))
        seen_names, seen_peers, seen_inodes = set(), set(), set()
        for key, (pid, start, inode, name, local, peer, generation) in sample.items():
            session_need(native[key] == name and name not in seen_names and (revoke or peer not in seen_peers) and inode not in seen_inodes)
            seen_names.add(name)
            seen_peers.add(peer)
            seen_inodes.add(inode)
            if revoke:
                # xl2tpd offers its next free pool slot. CHAP may replace it
                # at IPCP; multiple calls from one login may share the latter.
                ifindex, peer = session_links(links, name, local, None)
                session_need(pool[1] <= ipaddress.IPv4Address(peer) <= pool[2])
            else:
                ifindex = session_links(links, name, local, peer)
            result.append((key, local, peer, pid, start, inode, ifindex, generation))
    session_need(pids == session_cgroup(group))
    watch()
    return main_start, result


REVOKE_DB_NAME = 'pppd2.tdb'
# Built-in TDB in Debian trixie amd64 ppp 2.5.2-1+1 (SESSION_STOCK),
# pppd/tdb.h and tdb.c: little-endian default header, 131 hash buckets.
REVOKE_DB_BUCKETS = 131
REVOKE_DB_HEADER = struct.pack('<32sII', b'TDB file\n', 0x2601196d, REVOKE_DB_BUCKETS) + bytes(128)
REVOKE_DB_DATA = len(REVOKE_DB_HEADER) + 4 * (1 + REVOKE_DB_BUCKETS)
# pppd 2.5.2 update_db_entry stores a NUL terminator, not a trailing semicolon.
REVOKE_ENV = re.compile(rb'ORIG_UID=0;PPPLOGNAME=(?:' + CHAP_LOGIN + rb'|\(unknown\));'
                        rb'PPPD_PID=([1-9][0-9]{0,9});IFNAME=(ppp(?P<unit>0|[1-9][0-9]{0,9}));'
                        rb'UNIT=(?P=unit);PEERNAME=(' + CHAP_LOGIN + rb');'
                        rb'IPLOCAL=([0-9.]{7,15});IPREMOTE=([0-9.]{7,15})\x00')


def revoke_db_fetch(fd, size, key):
    def at(offset, count):
        data = os.pread(fd, count, offset)
        session_need(len(data) == count)
        return data

    hsize = len(REVOKE_DB_HEADER)
    value = 0x238f13af * len(key) + sum(byte << (i * 5 % 24) for i, byte in enumerate(key))
    full_hash = (1103515243 * value + 12345) & 0xffffffff
    bucket = full_hash % REVOKE_DB_BUCKETS
    offset, = struct.unpack('<I', at(hsize + 4 * (1 + bucket), 4))
    seen, found = set(), None
    while offset:
        session_need(REVOKE_DB_DATA <= offset <= size - 24 and offset % 4 == 0 and offset not in seen
                     and len(seen) < 4096 and time.monotonic() < DEADLINE)
        seen.add(offset)
        following, length, klen, vlen, hashed, magic = struct.unpack('<6I', at(offset, 24))
        end = offset + 24 + length
        session_need(klen + vlen + 4 <= length and end <= size and length % 4 == 0
                     and hashed % REVOKE_DB_BUCKETS == bucket and magic in (0x26011999, 0xfee1dead)
                     and struct.unpack('<I', at(end - 4, 4))[0] == 24 + length)
        if magic == 0x26011999 and full_hash == hashed and klen == len(key) and at(offset + 24, klen) == key:
            session_need(found is None and 0 < vlen <= 4096)
            found = at(offset + 24 + klen, vlen)
        offset = following
    if found is None:
        raise Refusal(SESSION_UNKNOWN)
    return found


def revoke_db_writer(proc, pid, identity):
    # Match the inode already opened by the attested child. No process env,
    # memory, fd contents or journal are read, and no writer FD is duplicated.
    fd = os.open(f'{pid}/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=proc)
    try:
        fds = os.listdir(fd)
        session_need(len(fds) <= 128 and all(re.fullmatch(r'[0-9]{1,10}', leaf) for leaf in fds))
        matches = 0
        for leaf in fds:
            if os.readlink(leaf, dir_fd=fd).rsplit('/', 1)[-1] == REVOKE_DB_NAME:
                st = os.stat(leaf, dir_fd=fd)
                matches += (st.st_dev, st.st_ino) == identity
        session_need(matches == 1)
    finally:
        os.close(fd)


def revoke_db_identity(st):
    session_need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
                 and not st.st_mode & 0o7022)
    return st.st_dev, st.st_ino


def revoke_peer_logins(rows, users):
    if not rows:
        return {}
    observed = {}
    with directory('/run') as run, directory('/proc') as proc:
        fd = os.open(REVOKE_DB_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=run)
        try:
            # Stock tdb_open(O_RDONLY) disables locking. Instead take a
            # nonblocking POSIX read lock covering init/alloc/hash-chain locks.
            identity = revoke_db_identity(os.fstat(fd))
            fcntl.lockf(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            size = os.fstat(fd).st_size
            header = REVOKE_DB_HEADER
            session_need(REVOKE_DB_DATA <= size <= MAX_FILE and os.pread(fd, len(header), 0) == header)
            for _, local, peer, pid, _, _, _, stamp in rows:
                revoke_db_writer(proc, pid, identity)
                pid_bytes = str(pid).encode('ascii')
                key = b'pppd' + pid_bytes
                # main.c writes this process' script_env under pppd<PID> at
                # startup and on updates. auth_peer_success() sets PEERNAME;
                # ipcp_up() sets IPLOCAL/IPREMOTE before kernel activation.
                # Require exact field order: values are not escaped, so a
                # permissive split(';') could truncate a foreign peer name.
                env = REVOKE_ENV.fullmatch(revoke_db_fetch(fd, size, key))
                if env is None:
                    raise Refusal(SESSION_UNKNOWN)
                db_pid, name, number, login, db_local, db_peer = env.groups()
                login = login.decode('ascii')
                session_need(pid not in observed and db_pid == pid_bytes
                             and (db_local, db_peer) == (local.encode('ascii'), peer.encode('ascii'))
                             and users.get(login) == peer and session_pid_stamp(name.decode('ascii'), pid) == stamp)
                # IPREMOTE is not a unique alias (two calls can share it).
                for alias in (b'PPPD_PID=' + pid_bytes, b'IFNAME=' + name, b'UNIT=' + number):
                    session_need(revoke_db_fetch(fd, size, alias) == key)
                observed[pid] = login
            session_need(revoke_db_identity(os.stat(REVOKE_DB_NAME, dir_fd=run, follow_symlinks=False)) == identity)
        finally:
            os.close(fd)  # releases the read lock before any signal/wait
    return observed


@contextlib.contextmanager
def revoke_ppp_view(owner):
    with owned_ppp_view(owner) as (sample, held, watch, _):
        yield sample, held, watch


@contextlib.contextmanager
def owned_ppp_view(owner, *, retirement=False):
    libc = ctypes.CDLL(None, use_errno=True)
    path = '/sys/fs/cgroup' + SESSION_GROUP
    with directory('/proc') as proc, directory(path) as group, contextlib.ExitStack() as stack, contextlib.ExitStack() as events:
        session_fs(libc, proc, 0x9fa0)
        session_fs(libc, group, 0x63677270)
        poll = select.poll()

        def route_watch(scope):
            sock = scope.enter_context(socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_NONBLOCK, 0))
            sock.bind((0, 1 | 16))  # RTMGRP_LINK | RTMGRP_IPV4_IFADDR; overflow also refuses.
            poll.register(sock, select.POLLIN)
            return sock

        route = route_watch(events)
        pids, exited = {}, set()

        def held(pid):
            session_need(pid not in exited)
            if pid not in pids:
                fd = os.pidfd_open(pid)
                stack.callback(os.close, fd)
                poll.register(fd, select.POLLIN)
                pids[pid] = fd
            return pids[pid]

        def watch():
            session_need(not poll.poll(0) and time.monotonic() < DEADLINE)

        def sample():
            value = session_sample(libc, proc, group, owner, held, watch, revoke=True)
            session_need(session_generation(os.fstat(group)) == session_generation(os.lstat(path)))
            return value

        def advance(pid):
            nonlocal route
            # Only after the selected original pidfd reported exit. Its link
            # removal makes the old route watch unusable. Arm the replacement
            # before resampling; never drop a surviving pidfd or allow reuse of
            # an exited PID. The caller must prove the exact shrinking set.
            session_need(pid in pids and pid not in exited and pid != owner[2])
            with contextlib.ExitStack() as next_events:
                fresh = route_watch(next_events)
                poll.unregister(route)
                events.close()
                events.enter_context(next_events.pop_all())
                route = fresh
            poll.unregister(pids[pid])
            exited.add(pid)
            watch()

        yield (sample, held, watch, group, advance) if retirement else (sample, held, watch, group)


def wait_ppp_exit(pfd):
    exited = select.poll()
    exited.register(pfd, select.POLLIN)
    session_need(any(fd == pfd and flags & select.POLLIN for fd, flags in
                     exited.poll(max(0, int((DEADLINE - time.monotonic()) * 1000)))))


def revoke_ppp(request, blocked, chap, path, manifest, xl):
    global DEADLINE
    count, completed = 0, False
    outer_deadline = DEADLINE
    DEADLINE = min(outer_deadline, time.monotonic() + 25)
    try:
        session_need(os.uname().machine == 'x86_64' and hasattr(signal, 'pidfd_send_signal'))
        chap_generation = remove_generation(NAMES['chap'])
        manifest_generation = remove_generation(path)

        def unchanged():
            session_need(chap_generation is not None and manifest_generation is not None and read(NAMES['chap']) == chap
                         and remove_generation(NAMES['chap']) == chap_generation and read(path, 2 * MAX_FILE) == manifest
                         and remove_generation(path) == manifest_generation and time.monotonic() < DEADLINE)

        unchanged()
        if rollback_quiescent(xl):
            quiet = quiescent_session_sample(blocked)
            session_need(quiet == quiescent_session_sample(blocked) and unit(XL) == xl)
            unchanged()
            return {'sessionsTerminated': 0, 'complete': True}
        owner = session_owner(blocked)
        session_need((owner[1], str(owner[2])) == (xl['InvocationID'], xl['MainPID']))
        users = {u['login']: u['ipAddress'] for u in request['currentUsers']}
        closed_call = None
        main_start = None
        while True:
            with revoke_ppp_view(owner) as (sample, held, watch):
                before = sample()
                if main_start is None:
                    main_start = before[0]
                session_need(main_start == before[0])
                session_need(owner == session_owner(blocked) and before == sample())
                unchanged()
                watch()
                if closed_call is not None:
                    key, index = closed_call
                    session_need(all(row[0] != key and row[6] != index for row in before[1]))
                    count += 1
                    closed_call = None
                logins = revoke_peer_logins(before[1], users)
                session_need(before == sample() and logins == revoke_peer_logins(before[1], users))
                unchanged()
                selected = next((row for row in before[1] if logins[row[3]] == request['revokedLogin']), None)
                watch()
                if selected is None:
                    completed = True
                    break
                key, _, _, pid, _, _, index, _ = selected
                pfd = held(pid)
                watch()
                try:
                    signal.pidfd_send_signal(pfd, signal.SIGTERM)
                except ProcessLookupError:
                    # Natural exit before delivery, not an operation closure.
                    continue
                wait_ppp_exit(pfd)
                # A count requires an accepted signal to the pinned instance,
                # its exit, and absence of both call and interface on readback.
                # It does not distinguish a concurrent natural disconnect as
                # the cause of that same targeted call's confirmed closure.
                closed_call = key, index
    except (Refusal, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        # A checked partial reply is not authority to publish or replay. Never
        # return state contents, PID, address or guessed count over the wire.
        completed = False
    finally:
        DEADLINE = outer_deadline
    return {'sessionsTerminated': count, 'complete': completed}


def session_census(request):
    # Caller holds the shared (preview) or exclusive (Remove) DIRECT flock.
    global DEADLINE
    session_need(os.uname().machine == 'x86_64')
    outer_deadline = DEADLINE
    DEADLINE = min(outer_deadline, time.monotonic() + 7)
    try:
        return collect_session_census(request)
    finally:
        DEADLINE = outer_deadline


def quiescent_session_sample(request):
    ready = preflight(request['machineId'])
    session_need(ready['machineId'] == request['machineId'] and ready['ppp'])
    state = observe_removal(request, quiescent=True)
    xl = state['units'][XL]
    session_need(xl['ControlGroup'] in ('', SESSION_GROUP))
    # KillMode and systemd's PID zero are not an inventory. Prove the actual
    # kernel group absent, or recursively empty. ps can omit cgroup metadata.
    group = '/sys/fs/cgroup' + SESSION_GROUP
    parent, name = os.path.split(group)
    session_need(command('/usr/bin/stat', '-f', '--format=%T', parent, quiet=True) == b'cgroup2fs\n')
    group_type = command('/usr/bin/find', '-P', parent, '-mindepth', '1', '-maxdepth', '1',
                         '-name', name, '-printf', '%y\n', quiet=True)
    session_need(group_type in (b'', b'd\n'))
    if group_type:
        events = command('/usr/bin/head', '-c', '1024', group + '/cgroup.events', quiet=True)
        session_need(events == b'populated 0\nfrozen 0\n')
    # Also refuse stray stock processes outside the native service cgroup.
    tasks = command('/usr/bin/ps', '-ww', '-e', '-o', 'pid=', '-o', 'comm=', quiet=True)
    has_observer = False
    for line in tasks.splitlines():
        fields = line.strip().split(None, 1)
        session_need(len(fields) == 2 and fields[0].isdigit() and fields[1] not in (b'xl2tpd', b'pppd', b'-', b'?'))
        has_observer |= fields[1] == b'ps'
    session_need(has_observer and all(remove_generation(p) is None for p in (
        '/run/xl2tpd.pid', '/run/xl2tpd/l2tp-control'))
        and not any(re.fullmatch(r'ppp.*\.pid', name) for name in os.listdir('/run')))
    # Unlike the Remove listener check, examine connected UDP sockets too.
    session_need(not command('/usr/bin/ss', '-H', '-aun', 'sport = :1701', quiet=True).strip())
    links = json.loads(command('/usr/sbin/ip', '-j', '-details', 'link', 'show', quiet=True))
    link_types = set()
    session_need(type(links) is list)
    for row in links:
        session_need(isinstance(row, dict) and type(row.get('link_type')) is str)
        link_types.add(row['link_type'])
    session_need('loopback' in link_types and 'ppp' not in link_types)  # includes renamed PPP netdevs
    # Require the actual empty kernel table, not ENOENT or a filtered empty
    # set of sessions: even a leftover tunnel without a call blocks Remove.
    native = command('/usr/bin/head', '-c', '1048577', '/proc/self/net/pppol2tp', quiet=True)
    session_need(native == SESSION_L2TP_HEADER)
    session_need(all(unit(name) == info for name, info in state['units'].items()))
    no_jobs(UNITS)
    return state['baseline'], group_type


def quiescent_session_token(baseline):
    return digest(encode(['ppp-quiescent-v1', baseline]))


def ipsec_status_inventory(status, *, joined=False):
    # strongSwan starter/stroke statusall prints each CHILD under its parent
    # IKE SA. Count managed IKEv1 connections, never ESP directions, overlapping
    # CHILD rekeys, address pairs or kernel policy templates.
    session_need(len(status) <= 2**20 and status.endswith(b'\n'))
    match = re.search(rb'^Connections:[ \t]*\n(.*?)^Security Associations '
                      rb'\(([0-9]{1,5}) up, 0 connecting\):[ \t]*\n([^\r]*)\Z', status, re.M | re.S)
    if match is None:
        raise Refusal(SESSION_UNKNOWN)
    config, up, body = match.groups()
    session_need(config.strip() and all(line.lstrip().startswith(b'celerity-l2tp:')
                                       for line in config.split(b'\n') if line.strip()))
    if int(up) == 0:
        session_need(body.strip() == b'none')
        return []
    inventory, children, parent, last_child = {}, set(), None, None
    installed = {}
    for line in body.split(b'\n')[:-1]:
        # stroke uses %12s, a minimum width; celerity-l2tp needs no padding.
        row = re.fullmatch(rb'[ \t]*celerity-l2tp(?:\[([1-9][0-9]{0,9})\]|\{([1-9][0-9]{0,9})\}):[ \t]+([^\x00-\x1f]+)', line)
        if row is None:
            raise Refusal(SESSION_UNKNOWN)
        ike, child, detail = row.groups()
        if ike and detail.startswith(b'ESTABLISHED '):
            parent = int(ike)
            session_need(parent not in inventory)
            inventory[parent] = None
            last_child = None
        elif ike:
            session_need(parent == int(ike) and last_child is None)
            spi = re.fullmatch(rb'IKEv1 SPIs: ([a-f0-9]{16})_i\*? ([a-f0-9]{16})_r\*?(?:, .+)?', detail)
            if spi:
                session_need(inventory[parent] is None)
                inventory[parent] = tuple(value.decode('ascii') for value in spi.groups())
            else:
                session_need(detail.startswith(b'IKE proposal: '))
        else:
            child = int(child)
            session_need(parent is not None)
            transform = re.fullmatch(rb'INSTALLED, TRANSPORT, reqid ([0-9]+), ESP( in UDP)? SPIs: ([a-f0-9]{8})_i ([a-f0-9]{8})_o', detail)
            if transform or (not joined and re.fullmatch(
                    rb'(?:REKEYING|REKEYED), TRANSPORT, reqid [0-9]+, expires in [0-9]+ (?:second|minute|hour|day)s?'
                    rb'|DELETING, TRANSPORT, reqid [0-9]+', detail)):
                session_need(child not in children)
                children.add(child)
                last_child = child
                if joined:
                    session_need(transform is not None and len(transform[1]) <= 10 and parent not in installed)
                    installed[parent] = child, int(transform[1]), transform[3].decode(), transform[4].decode(), bool(transform[2])
            else:
                session_need(last_child == child and (b' === ' in detail or b' bytes_i' in detail))
    identities = set(inventory.values())
    session_need(len(inventory) == len(identities) == int(up) and None not in identities)
    if joined:
        session_need(installed.keys() == inventory.keys())
        return sorted((ike_id, spis, installed[ike_id]) for ike_id, spis in inventory.items())
    return sorted(inventory.items())


def ipsec_session_sample(request):
    require_census_machine(request['machineId'])
    path, manifest, backup, _ = owned_installation(request)
    before, runtime = runtime_before(backup), backup['runtime']
    # Match installed configuration and starter include, not just a connection
    # name. No IPsec secrets are needed in the census.
    generations = []
    for key in ('ike', 'starter'):
        generation = remove_generation(NAMES[key])
        record = read(NAMES[key], 65536)
        session_need(generation == runtime['files'][key] and after_match(record, backup['after'][key])
                     and generation == remove_generation(NAMES[key]))
        if key == 'starter':
            session_need(ike_include_matches(record, [os.path.basename(NAMES['ike'])]))
        generations.append(generation)
    check_swan_profile(backup, read(SWAN_PROFILE) if 'swan' in backup['after'] else None)
    no_jobs((IKE,))
    ike = unit(IKE)
    session_need(removal_native(ike, IKE, before, installed=True))
    sockets = sorted((proto, address, port, sorted(owners)) for proto, address, port, owners in sock_rows()
                     if port in (500, 4500))
    if rollback_quiescent(ike):
        session_need(not sockets)
        inventory = []
    else:
        session_need(working(ike) and ike['SubState'] == 'running'
                     and {port for _, _, port, _ in sockets} == {500, 4500}
                     and all(proto == 'udp' and owners and all(in_cgroup(pid, ike) for pid in owners)
                             for proto, _, _, owners in sockets))
        check_runtime_unit_epoch(runtime, IKE, ike)
        inventory = ipsec_status_inventory(command('/usr/sbin/ipsec', 'statusall', quiet=True))
    if not inventory:
        # A stale child in the kernel or a failed dump is not a known zero.
        session_need(not command('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys', quiet=True).strip())
    session_need(ike == unit(IKE))
    no_jobs((IKE,))
    return len(inventory), digest(encode([check_runtime_boot(backup), remove_generation(path), digest(raw(manifest)),
                                         generations, ike['InvocationID'], ike['MainPID'], sockets, inventory]))


# Only bounded one-call-per-peer IPv4 cohorts are drainable. Plain ESP and
# common ESP-in-UDP are supported; shared addresses/transport selectors and
# rekey overlap are not. No raw keys or client identities leave the helper.
RETIRE_MAX_CLIENTS = 32  # Keep in sync with validRetirementCensus in JS.
RETIRE_CHANGED = 'REMOVE_PREVIEW_CHANGED'
RETIRE_ERRORS = (OSError, ValueError, KeyError, TypeError, IndexError, struct.error)
RETIRE_IP4 = rb'([0-9.]{7,15})'
RETIRE_SA = 'celerity-l2tp'
RETIRE_IKE_GROUP = '/system.slice/' + IKE


def retire_addresses(local, peer):
    pair = tuple(ipaddress.IPv4Address(value.decode('ascii')) for value in (local, peer))
    session_need(pair[0] != pair[1] and all(not (a.is_unspecified or a.is_multicast or a.is_loopback) for a in pair))
    return tuple(map(str, pair))


def retire_l2tp_endpoints():
    # Generic netlink reports the tunnel UDP tuple, independently of IPCP.
    data = command('/usr/sbin/ip', 'l2tp', 'show', 'tunnel', quiet=True)
    pattern = re.compile(rb'Tunnel ([0-9]{1,5}), encap UDP[ \t]*\n[ \t]+From ' + RETIRE_IP4 + rb' to ' + RETIRE_IP4
                         + rb'[ \t]*\n[ \t]+Peer tunnel ([0-9]{1,5})[ \t]*\n[ \t]+UDP source / dest ports:'
                         + rb'[ \t]+1701[ \t]*/[ \t]*1701[ \t]*\n'
                         + rb'(?:[ \t]+UDP checksum: (?:enabled|disabled)[ \t]*\n)?')
    tunnels, local_ids, peers = {}, set(), set()
    offset = 0
    while offset < len(data):
        row = pattern.match(data, offset)
        session_need(row is not None and len(tunnels) < RETIRE_MAX_CLIENTS)
        ids = int(row[1]), int(row[4])
        endpoints = retire_addresses(row[2], row[3])
        session_need(all(0 < n <= 65535 for n in ids) and ids[0] not in local_ids and endpoints[1] not in peers)
        tunnels[ids] = endpoints
        local_ids.add(ids[0])
        peers.add(endpoints[1])
        offset = row.end()
    return tunnels


def retire_xfrm(sas):
    states = command('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys', quiet=True)
    policies = command('/usr/sbin/ip', 'xfrm', 'policy', 'list', 'nosock', quiet=True)
    expected_states, expected_policies = {}, {}
    for endpoints, _, _, _, _, reqid, spi_in, spi_out, ports in sas:
        local, peer = endpoints
        expected_states[local, peer, spi_out, reqid] = ports
        expected_states[peer, local, spi_in, reqid] = ports[::-1] if ports else None
        expected_policies[local, peer, 'out'] = expected_policies[peer, local, 'in'] = reqid, endpoints
    session_need(len({(dst, spi) for _, dst, spi, _ in expected_states}) == len(expected_states))

    state_start = re.compile(rb'^src ' + RETIRE_IP4 + rb' dst ' + RETIRE_IP4 + rb'[ \t]*\n', re.M)
    chunks = list(state_start.finditer(states))
    session_need(len(chunks) == len(expected_states) and (chunks[0].start() == 0 if chunks else not states))
    for i, row in enumerate(chunks):
        data = states[row.end():chunks[i + 1].start() if i + 1 < len(chunks) else len(states)]
        head, *tail = data.splitlines()
        sa = re.fullmatch(rb'[ \t]+proto esp spi 0x([a-f0-9]{8}) reqid ([0-9]{1,10}) mode transport[ \t]*', head)
        session_need(sa is not None)
        item = (row[1].decode(), row[2].decode(), sa[1].decode(), int(sa[2]))
        session_need(item in expected_states)
        ports = expected_states.pop(item)
        encap = None
        # Closed grammar: marks, if_id, offload and unsupported selectors
        # cannot project as one of these transport ESP transforms.
        for line in tail:
            udp = re.fullmatch(rb'[ \t]+encap type espinudp sport ([0-9]{1,5}) dport ([0-9]{1,5}) addr 0\.0\.0\.0[ \t]*', line)
            if udp:
                session_need(encap is None)
                encap = int(udp[1]), int(udp[2])
            else:
                session_need(re.fullmatch(rb'[ \t]+(?:replay-window [0-9]+(?: flag (?:af-unspec|noecn))?|'
                                          rb'(?:auth(?:-trunc)?|enc|aead) [^\x00-\x1f]+|'
                                          rb'anti-replay context: seq 0x[a-f0-9]+, oseq 0x[a-f0-9]+, bitmap 0x[a-f0-9]+)[ \t]*', line))
        session_need(encap == ports)
    session_need(not expected_states)

    policy = re.compile(rb'src ' + RETIRE_IP4 + rb'(?:/32)? dst ' + RETIRE_IP4
                        + rb'(?:/32)? proto udp sport 1701 dport 1701[ \t]*\n[ \t]+dir (in|out) priority ([0-9]{1,10})'
                        + rb'(?: ptype main)?[ \t]*\n[ \t]+tmpl src ' + RETIRE_IP4 + rb' dst ' + RETIRE_IP4
                        + rb'[ \t]*\n[ \t]+proto esp reqid ([0-9]{1,10}) mode transport(?: level required)?[ \t]*\n')
    by_tunnel = {sa[0]: [] for sa in sas}
    offset = 0
    while offset < len(policies):
        row = policy.match(policies, offset)
        session_need(row is not None)
        s, d, direction, priority, ts, td, req = row.groups()
        item = tuple(x.decode() for x in (s, d, direction))
        session_need(item in expected_policies)
        reqid, endpoints = expected_policies.pop(item)
        # StrongSwan can leave transport template endpoints at INADDR_ANY.
        session_need((ts, td) in ((s, d), (b'0.0.0.0', b'0.0.0.0')) and int(req) == reqid)
        by_tunnel[endpoints].append((*item, int(priority), ts.decode(), td.decode()))
        offset = row.end()
    session_need(not expected_policies)
    return tuple((sa, tuple(sorted(by_tunnel[sa[0]]))) for sa in sas)


def retire_vici_message(data):
    # VICI element stream: sections, byte values and lists. Reject duplicate
    # names and any truncation; don't include unrecognized data in diagnostics.
    root, stack, items, offset = {}, [], None, 0
    node = root

    def take(n):
        nonlocal offset
        part = data[offset:offset + n]
        session_need(len(part) == n)
        offset += n
        return part

    while offset < len(data):
        tag = take(1)[0]
        if tag in (1, 3, 4) and items is None:
            key = take(take(1)[0]).decode('ascii')
            session_need(key and key not in node)
            if tag == 1:
                session_need(len(stack) < 6)
                stack.append(node)
                node[key] = child = {}
                node = child
            elif tag == 3:
                node[key] = take(int.from_bytes(take(2), 'big'))
            else:
                node[key] = items = []
        elif tag == 2 and stack and items is None:
            node = stack.pop()
        elif tag == 5 and items is not None:
            items.append(take(int.from_bytes(take(2), 'big')))
        elif tag == 6 and items is not None:
            items = None
        else:
            raise Refusal(SESSION_UNKNOWN)
    session_need(not stack and items is None)
    return root


def retire_udp_rows():
    # Include connected UDP sockets, which ordinary listener checks omit.
    data = command('/usr/bin/ss', '-H', '-aunp', '--cgroup', '-A', 'udp', quiet=True)
    for line in data.decode('utf-8').splitlines():
        cols = line.split(maxsplit=6)
        if cols and cols[0] == 'udp':
            _, state, rx, _, local, remote, *rest = cols
        else:  # ss may omit Netid for a single explicitly selected protocol.
            state, rx, _, local, remote, *rest = line.split(maxsplit=5)
        _, port = local.rsplit(':', 1)
        session_need(port.isdecimal())
        if int(port) not in (500, 4500, 1701):
            continue
        (details,) = rest
        yield (int(port), state, rx, local, remote, set(re.findall(r'\bpid=(\d+),', details)),
               re.findall(r'\bcgroup:(\S+)', details))


def retire_ike_sockets(pid):
    # Check both families; a distinct IPv6 bind is fine, a duplicate bind or
    # another owner is not. No queued UDP inputs at the fenced recheck.
    sockets = set()
    for port, state, rx, local, remote, owners, groups in retire_udp_rows():
        if port == 1701:
            continue
        session_need(state == 'UNCONN' and rx == '0' and (port, local, remote) not in sockets
                     and owners == {str(pid)} and groups == [RETIRE_IKE_GROUP])
        sockets.add((port, local, remote))
    session_need({port for port, _, _ in sockets} == {500, 4500})
    return tuple(sorted(sockets))


def retire_l2tp_sockets(main, tunnels, live):
    # Join each connected socket to exactly one observed tunnel. Only an
    # already closed call may have a tunnel without a connected socket.
    expected = {tuple(a + ':1701' for a in endpoints): live.get(ids) for ids, endpoints in tunnels.items()}
    rows, bound = {}, None
    for port, state, _, local, remote, owners, groups in retire_udp_rows():
        if port != 1701:
            continue
        session_need(groups == [SESSION_GROUP] and main in owners)
        if state == 'UNCONN':
            session_need(owners == {main} and bound is None)
            bound = local, remote
        else:
            key = local, remote
            session_need(state == 'ESTAB' and key in expected and key not in rows)
            pid = expected[key]
            session_need(owners <= ({main, str(pid)} if pid else {main}))
            rows[key] = tuple(sorted(owners))
    session_need(bound is not None and all(key in rows for key, pid in expected.items() if pid is not None))
    return bound, tuple(sorted(rows.items()))


@contextlib.contextmanager
def retire_vici(ike, held):
    # Use one peer-authenticated connection through census and exact delete.
    # A reused uniqueid on a newly started daemon cannot receive our request.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        def bounded():
            left = DEADLINE - time.monotonic()
            session_need(left > 0)
            channel.settimeout(min(left, 4))

        bounded()
        channel.connect('/run/charon.vici')
        pid, uid, _ = struct.unpack('=iII', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        session_need(pid > 1 and uid == 0)
        pfd = held(pid)
        poll = select.poll()
        poll.register(pfd, select.POLLIN)

        sockets = None

        def peer_check():
            session_need(not poll.poll(0) and unit(IKE) == ike and in_cgroup(str(pid), ike)
                         and os.readlink(f'/proc/{pid}/exe') == '/usr/lib/ipsec/charon')
            current = retire_ike_sockets(pid)
            session_need(sockets is None or sockets == current)
            return current

        def send(tag, name, data=b''):
            name = name.encode('ascii')
            packet = bytes((tag, len(name))) + name + data
            bounded()
            channel.sendall(struct.pack('!I', len(packet)) + packet)

        def recv():
            def read_full(n):
                value = bytearray()
                while len(value) < n:
                    bounded()
                    chunk = channel.recv(n - len(value))
                    session_need(chunk)
                    value.extend(chunk)
                return bytes(value)
            size, = struct.unpack('!I', read_full(4))
            session_need(0 < size <= 65536)
            return read_full(size)

        def list_sas():
            peer_check()
            send(3, 'list-sa')
            session_need(recv() == b'\x05')
            send(0, 'list-sas')
            prefix = b'\x07\x07list-sa'
            rows = []
            while (row := recv()) != b'\x01':
                session_need(row.startswith(prefix) and len(rows) < RETIRE_MAX_CLIENTS)
                rows.append(retire_ike_identity(retire_vici_message(row[len(prefix):])))
            send(4, 'list-sa')
            session_need(recv() == b'\x05')
            peer_check()
            # Independently reject duplicate peer, IKE ID, cookie pair, CHILD
            # ID and reqid; none may authorize two calls or two deletions.
            for values in ([r[0][1] for r in rows], [r[1] for r in rows], [r[2:4] for r in rows],
                           [r[4] for r in rows], [r[5] for r in rows]):
                session_need(len(set(values)) == len(rows))
            return tuple(sorted(rows))

        def terminate(ike_id):
            peer_check()
            value = str(ike_id).encode('ascii')
            send(0, 'terminate', b'\x03\x06ike-id' + struct.pack('!H', len(value)) + value
                 + b'\x03\x07timeout\x00\x042000')
            reply = recv()
            session_need(reply[:1] == b'\x01')
            props = retire_vici_message(reply[1:])
            session_need(all(props.get(k) == v for k, v in (('success', b'yes'), ('matches', b'1'), ('terminated', b'1'))))
            peer_check()

        with directory('/proc') as proc:
            start = int(session_read(proc, f'{pid}/stat', 4096).rsplit(b') ', 1)[1].split()[19])
        sockets = peer_check()
        yield (pid, start, sockets), list_sas, terminate, peer_check


def retire_ike_identity(info):
    session_need(set(info) == {RETIRE_SA})
    ike = info[RETIRE_SA]
    session_need(type(ike) is dict and (ike['version'], ike['state']) == (b'1', b'ESTABLISHED'))
    local, peer = ike['local-host'], ike['remote-host']
    endpoints = retire_addresses(local, peer)
    children = ike['child-sas']
    session_need(type(children) is dict and len(children) == 1)
    (child,) = children.values()
    session_need(type(child) is dict and (child['name'], child['state'], child['mode'], child['protocol']) ==
                 (RETIRE_SA.encode(), b'INSTALLED', b'TRANSPORT', b'ESP'))
    encap = child.get('encap')
    session_need(encap in (None, b'no', b'yes'))
    for who, address in (('local', local), ('remote', peer)):
        selector = child[who + '-ts']
        session_need(selector in ([address + b'/32[udp/1701]'], [address + b'/32[udp/l2f]']))

    def number(value):
        session_need(re.fullmatch(rb'[1-9][0-9]{0,9}', value) and int(value) <= 0xffffffff)
        return int(value)

    def spi(value, width):
        session_need(len(value) == width and re.fullmatch(rb'[a-f0-9]+', value) and int(value, 16))
        return value.decode('ascii')

    ports = None
    if encap == b'yes':
        ports = number(ike['local-port']), number(ike['remote-port'])
        session_need(ports[0] == 4500 and 0 < ports[1] <= 65535)
    return (endpoints, number(ike['uniqueid']), spi(ike['initiator-spi'], 16), spi(ike['responder-spi'], 16),
            number(child['uniqueid']), number(child['reqid']), spi(child['spi-in'], 8), spi(child['spi-out'], 8), ports)


def retire_ppp_links(expected):
    links = json.loads(command('/usr/sbin/ip', '-j', '-details', 'link', 'show', quiet=True))
    kinds = [row['link_type'] for row in links]
    session_need('loopback' in kinds and sorted(row['ifindex'] for row in links if row['link_type'] == 'ppp') == expected)


def retire_pids_input(group):
    limit = session_read(group, 'pids.max', 32)
    session_need(re.fullmatch(rb'(?:max|[1-9][0-9]{0,18})\n', limit))
    return limit


def retire_write_pids(group, value):
    fd = os.open('pids.max', os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=group)
    try:
        session_need(os.write(fd, value) == len(value))
    finally:
        os.close(fd)


def retire_group_same(group):
    path = '/sys/fs/cgroup' + SESSION_GROUP
    return session_generation(os.fstat(group)) == session_generation(os.lstat(path))


def retire_ike_gate(request):
    return 'celerity_retire_' + request['backupId']


def retire_ike_gate_absent(name):
    return not any(row.get('family') == 'inet' and row.get('name') == name for row in nft_tables())


@contextlib.contextmanager
def retire_ike_admission(name, peer_check):
    # Only drop ingress addressed to the owned service's sockets, even if an
    # unrelated application starts listening on the same ports elsewhere.
    # UDP/4500 carries both IKE (the four zero-byte Non-ESP Marker after
    # the UDP header) and live ESP (nonzero SPI). Do not drop data or short
    # NAT keepalives while the gate is still classifying pre-intent drift.
    peer_check()
    session_need(retire_ike_gate_absent(name))
    path = RETIRE_IKE_GROUP.lstrip('/')
    scope = f'socket cgroupv2 level 2 "{path}" drop'
    rules = (f'udp dport 500 {scope}', f'udp dport 4500 @th,64,32 0x0 {scope}')
    batch = (f'create table inet {name}\n'
             f'add chain inet {name} ingress {{ type filter hook input priority -10; policy accept; }}\n'
             + ''.join(f'add rule inet {name} ingress {rule}\n' for rule in rules)).encode()
    # Unsupported socket expression or missing cgroup: no installed rule.
    command('/usr/sbin/nft', '-c', '-f', '-', data=batch, quiet=True)

    def project():
        data = command('/usr/sbin/nft', '-a', '-s', '-y', 'list', 'table', 'inet', name, quiet=True)
        template = (rb'table inet ' + name.encode() + rb' \{ # handle ([1-9][0-9]*)\s+'
                    rb'chain ingress \{ # handle ([1-9][0-9]*)\s+'
                    rb'type filter hook input priority -10; policy accept;\s+'
                    + b''.join(re.escape(rule.encode()).replace(b'0x0', rb'(?:0|0x0{1,8})')
                               + rb' # handle ([1-9][0-9]*)\s+' for rule in rules)
                    + rb'\}\s+\}\s*')
        row = re.fullmatch(template, data)
        if row is None:
            raise Refusal(SESSION_UNKNOWN)
        return tuple(x.decode('ascii') for x in row.groups())

    try:
        command('/usr/sbin/nft', '-f', '-', data=batch, quiet=True)
        created = project()
    except (Refusal, *RETIRE_ERRORS, subprocess.TimeoutExpired) as error:
        # The atomic write might have landed, but we have no owned readback.
        raise Refusal('IN_FLIGHT') from error

    def checked():
        session_need(project() == created)
        peer_check()

    try:
        yield checked
    finally:
        try:
            # No auto-thaw/retry after a potentially partial drain. The exact
            # gate may be released after IKE stop or on a clean pre-effect veto.
            if not REMOVE_ENTERED:
                session_need(project() == created)
            if not REMOVE_ENTERED or rollback_quiescent(unit(IKE)):
                # The socket cgroup can already be gone, so nft may no longer
                # render its name. Delete the original handle, not a successor
                # table at the same pathname. DIRECT and other host writers
                # must be serialized as for ordinary Remove.
                command('/usr/sbin/nft', 'delete', 'table', 'inet', 'handle', created[0], quiet=True)
                session_need(retire_ike_gate_absent(name))
        except (Refusal, *RETIRE_ERRORS, subprocess.TimeoutExpired) as error:
            raise Refusal('IN_FLIGHT') from error


@contextlib.contextmanager
def retire_admission(group, original):
    # cgroup v2 pids.max=0 does not suspend or kill existing tasks. Already
    # charged forks must be visible/accounted in pids.current before the
    # fenced sample is admitted. No network path or other unit is changed.
    session_need(retire_group_same(group) and retire_pids_input(group) == original)

    def checked(tasks):
        session_need(retire_group_same(group) and session_read(group, 'pids.max', 32) == b'0\n'
                     and session_read(group, 'pids.current', 32) == f'{tasks}\n'.encode())

    complete = False
    try:
        retire_write_pids(group, b'0\n')
        yield checked
        complete = True
    finally:
        if complete or not REMOVE_ENTERED:
            try:
                try:
                    same = retire_group_same(group)
                except FileNotFoundError:
                    # systemd normally removes the original empty cgroup.
                    session_need(complete and rollback_quiescent(unit(XL)))
                else:
                    session_need(same)
                    if complete:
                        session_need(rollback_quiescent(unit(XL)))
                        checked(0)
                    value = session_read(group, 'pids.max', 32)
                    session_need(value in (b'0\n', original))
                    if value != original:
                        retire_write_pids(group, original)
                    session_need(retire_group_same(group) and retire_pids_input(group) == original)
            except (Refusal, *RETIRE_ERRORS) as error:
                raise Refusal('IN_FLIGHT') from error


@contextlib.contextmanager
def retire_active_view(request, state):
    session_need(os.uname().machine == 'x86_64' and hasattr(signal, 'pidfd_send_signal'))
    # Do not autoload the generic-netlink L2TP provider in a read-only preview.
    session_need('l2tp_netlink' in live_modules(SESSION_UNKNOWN))
    backup = state['chap_backup']
    xl, ike = (state['units'][n] for n in (XL, IKE))
    session_need(working(xl) and working(ike) and not state['ike_sockets']
                 and ike['ControlGroup'] == RETIRE_IKE_GROUP and retire_ike_gate_absent(retire_ike_gate(request)))
    owner = session_owner(request)
    session_need((owner[1], str(owner[2])) == (xl['InvocationID'], xl['MainPID']))
    _, _, rows = owned_chap(state['current']['chap'], backup, state['chap_expected'])
    users = {login.decode(): line.rstrip(b'\n').rsplit(b' ', 1)[1].decode() for login, line in rows.items()}
    # Reuse the stock pppd process/PPPoX/netdev watcher and TDB join from Disable.
    with owned_ppp_view(owner, retirement=True) as (ppp, held, watch, group, advance), \
            retire_vici(ike, held) as (charon, list_sas, terminate, peer_check):
        limit = retire_pids_input(group)

        def ike_snapshot():
            sas = list_sas()
            inventory = ipsec_status_inventory(command('/usr/sbin/ipsec', 'statusall', quiet=True), joined=True)
            stroke = sorted((sa[1], sa[2:4], (sa[4], sa[5], sa[6], sa[7], sa[8] is not None)) for sa in sas)
            session_need(inventory == stroke)  # No foreign config, negotiating IKE or extra CHILD.
            return retire_xfrm(sas)

        def ppp_snapshot(fence):
            def capacity():
                current = session_read(group, 'pids.current', 32)
                session_need(re.fullmatch(rb'[1-9][0-9]?\n', current) and int(current) <= 1 + RETIRE_MAX_CLIENTS)
                if fence:
                    fence(int(current))
                else:
                    session_need(retire_group_same(group) and retire_pids_input(group) == limit)
                return int(current)

            n = capacity()
            start, rows = ppp()
            rows = sorted(rows)
            logins = revoke_peer_logins(rows, users)
            for values in ([r[2] for r in rows], [r[3] for r in rows], [r[6] for r in rows], list(logins.values())):
                session_need(len(set(values)) == len(rows))
            retire_ppp_links(sorted(row[6] for row in rows))
            session_need(n == capacity() == 1 + len(rows))
            return start, tuple((row, logins[row[3]]) for row in rows)

        def l2tp_snapshot(native, allowed=None):
            live = {}
            for (key, _, _, pid, *_), _ in native[1]:
                ids = key[0], key[2]
                session_need(ids not in live)  # Never share a transport tunnel.
                live[ids] = pid
            tunnels = retire_l2tp_endpoints()
            session_need(live.keys() <= tunnels.keys())
            if allowed is None:
                session_need(live.keys() == tunnels.keys())
            else:
                session_need(all(allowed.get(ids) == peer for ids, peer in tunnels.items()))
            return tunnels, retire_l2tp_sockets(xl['MainPID'], tunnels, live)

        def witnessed():
            peer_check()
            require_census_machine(request['machineId'])
            watch()

        def sample(fence=None, *, remove_intent=None):
            def read_join():
                native = ppp_snapshot(fence)
                session_need(native[1])
                tunnels, sockets = l2tp_snapshot(native)
                generation = ike_snapshot()
                session_need(sorted(tunnels.values()) == [sa[0] for sa, _ in generation])
                return native, tuple(sorted(tunnels.items())), sockets, generation

            snapshot = read_join()
            session_need(owner == session_owner(request, remove_intent=remove_intent)
                         and observe_removal(request, active=True, remove_intent=remove_intent)['baseline'] == state['baseline'])
            session_need(snapshot == read_join())
            witnessed()
            return snapshot

        def token(snapshot):
            return digest(encode(['retirement-active-v2', state['baseline'], owner[:6], charon, limit.decode(),
                                  session_generation(os.fstat(group)), snapshot]))

        def disconnect(snapshot, fence, ike_fence):
            native, tunnels, (listener, sockets), generation = snapshot
            start, cohort = native
            live, sas = list(cohort), list(generation)
            tunnels, sockets = dict(tunnels), dict(sockets)

            def survivors():
                ike_fence()
                expected = start, tuple(live)
                session_need(ppp_snapshot(fence) == expected)
                observed, (bound, connected) = l2tp_snapshot(expected, tunnels)
                session_need(bound == listener)
                connected = dict(connected)
                for (key, *_), _ in live:
                    ids = key[0], key[2]
                    endpoints = tuple(a + ':1701' for a in tunnels[ids])
                    session_need(observed[ids] == tunnels[ids] and connected[endpoints] == sockets[endpoints])
                session_need(ike_snapshot() == tuple(sas))
                ike_fence()
                witnessed()

            # After each acknowledged effect, only the exact prior set minus
            # that identity is admissible. Do not chase arrivals or rekeys.
            survivors()
            for client in cohort:
                pid = client[0][3]
                pfd = held(pid)
                watch()
                signal.pidfd_send_signal(pfd, signal.SIGTERM)
                wait_ppp_exit(pfd)
                advance(pid)
                live.remove(client)
                survivors()
            for sa in generation:
                watch()
                terminate(sa[0][1])
                sas.remove(sa)
                survivors()
            return survivors

        yield group, limit, sample, token, disconnect, peer_check


def removal_idle(request, rows, units):
    try:
        removal_vpn_runtime(rows, units)
    except Refusal as error:
        # Classify a proven managed SA without accepting anything that the
        # original Remove guard refused. Foreign/unknown remain refusals.
        if str(error) != 'IN_FLIGHT':
            ipsec = census_observation(ipsec_session_sample, request)
            if ipsec and ipsec[0] > 0:
                raise Refusal('REMOVE_IPSEC_BUSY') from None
        raise


def census_observation(probe, request):
    try:
        return probe(request)
    except Refusal as error:
        if str(error) in ('IN_FLIGHT', 'IDENTITY', RUNTIME_REATTEST_REQUIRED):
            raise
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        pass  # Unreadable or unsupported, never a count of zero.
    return None


def relay_session_census(request, quiescent_baseline=None):
    global DEADLINE
    outer_deadline = DEADLINE
    DEADLINE = min(outer_deadline, time.monotonic() + 7)
    try:
        ipsec = census_observation(ipsec_session_sample, request)
        ppp = census_observation(session_census, {k: v for k, v in request.items()
                                                 if k not in ('action', 'baseline', 'expectedCensus')})
        if ipsec is not None and ipsec != census_observation(ipsec_session_sample, request):
            ipsec = None
        if ppp and quiescent_baseline is not None:
            session_need(ppp['census'] == quiescent_session_token(quiescent_baseline))
        session_need(ppp is not None or ipsec is not None)
        if time.monotonic() >= DEADLINE:
            raise subprocess.TimeoutExpired([], 0)
        return {'activeSessions': ppp['activeSessions'] if ppp else None,
                'activeIpsec': ipsec[0] if ipsec else None,
                'census': digest(encode(['vpn-census-v1', ppp['census'], ipsec[1]])) if ppp and ipsec else None}
    finally:
        DEADLINE = outer_deadline


def collect_session_census(request):
    if rollback_quiescent(unit(XL)):
        snapshot = quiescent_session_sample(request)
        session_need(quiescent_session_sample(request) == snapshot)
        if time.monotonic() >= DEADLINE:
            raise subprocess.TimeoutExpired([], 0)
        return {'activeSessions': 0, 'census': quiescent_session_token(snapshot[0])}
    libc = ctypes.CDLL(None, use_errno=True)
    owner = session_owner(request)
    group_path = '/sys/fs/cgroup' + SESSION_GROUP
    with directory('/proc') as proc, directory(group_path) as group, contextlib.ExitStack() as stack:
        session_fs(libc, proc, 0x9fa0)  # PROC_SUPER_MAGIC
        session_fs(libc, group, 0x63677270)  # CGROUP2_SUPER_MAGIC
        route = stack.enter_context(socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_NONBLOCK, 0))
        route.bind((0, 1 | 16))  # RTMGRP_LINK | RTMGRP_IPV4_IFADDR; overflow also refuses.
        poll = select.poll()
        poll.register(route, select.POLLIN)
        pids = {}

        def held(pid):
            if pid not in pids:
                fd = os.pidfd_open(pid)
                stack.callback(os.close, fd)
                poll.register(fd, select.POLLIN)
                pids[pid] = fd
            return pids[pid]

        def watch():
            session_need(not poll.poll(0) and time.monotonic() < DEADLINE)

        sample = session_sample(libc, proc, group, owner, held, watch)
        session_need(owner == session_owner(request))
        session_need(sample == session_sample(libc, proc, group, owner, held, watch)
                     and session_generation(os.fstat(group)) == session_generation(os.lstat(group_path)))
        watch()
    session_need(time.monotonic() < DEADLINE)
    # Include the authenticated managed rows, not the surrounding file/inode.
    return {'activeSessions': len(sample[1]), 'census': digest(encode([
        'ppp-census-v2', request['nodeId'], request['backupId'], owner[:4], owner[5], sample[0],
        [row[3:] for row in sample[1]]]))}


@contextlib.contextmanager
def retirement_observation():
    try:
        yield
    except Refusal as error:
        if str(error) in ('IDENTITY', 'IN_FLIGHT', RUNTIME_REATTEST_REQUIRED) or REMOVE_ENTERED:
            raise
        raise Refusal(RETIRE_CHANGED) from None
    except RETIRE_ERRORS:
        if REMOVE_ENTERED:
            raise
        raise Refusal(RETIRE_CHANGED) from None


def retirement_prepare_or_remove(request):
    active = request.get('drain', False)
    prepare = request['action'] == 'prepare-remove'
    with retirement_observation():
        state = observe_removal(request, active=True) if active else observe_removal(request)
        session_need(retire_ike_gate_absent(retire_ike_gate(request)))
        if not prepare:
            session_need(state['baseline'] == request['baseline'])
        if active:
            with retire_active_view(request, state) as (group, limit, sample, token, disconnect, peer_check):
                session_need(token(sample()) == request['expectedCensus'])
                if not prepare:
                    with retire_ike_admission(retire_ike_gate(request), peer_check) as ike_fence, retire_admission(group, limit) as fence:
                        rechecked = None

                        def check():
                            nonlocal rechecked
                            ike_fence()
                            rechecked = sample(fence)
                            session_need(token(rechecked) == request['expectedCensus'])
                            ike_fence()

                        drained = None

                        def finish(intent_record):
                            nonlocal drained
                            # Intent publication/fsync is itself a race window.
                            # The held proof must still match before signalling;
                            # reread ownership against our own intent rather
                            # than skipping the install/CHAP proof. Any
                            # failure here retains the published intent.
                            ike_fence()
                            session_need(rechecked == sample(fence, remove_intent=intent_record))
                            ike_fence()
                            drained = disconnect(rechecked, fence, ike_fence)

                        def before_xl_stop(tasks):
                            if drained is None or tasks != 1:
                                raise Refusal('IN_FLIGHT')
                            drained()

                        def before_ike_stop():
                            session_need(not retire_l2tp_endpoints() and all(row[0] != 1701 for row in retire_udp_rows()))
                            ike_fence()

                        remove_installation(request, state, drain=(check, finish, before_xl_stop, before_ike_stop))
        elif prepare:
            census = relay_session_census(request, state['baseline'] if rollback_quiescent(state['units'][XL]) else None)
            session_need(census['activeSessions'] == census['activeIpsec'] == 0 and census['census'] == request['expectedCensus'])
        else:
            remove_installation(request, state)
    if prepare:
        validate_profiles(state['profiles'])
        return {'ok': True, 'backupId': request['backupId'], 'machineId': request['machineId'], 'baseline': state['baseline']}
    return {'ok': True, 'backupId': request['backupId'], 'removed': True}


def read_session_count(request):
    keys = {'action', 'machineId', 'nodeId', 'backupId', 'network'}
    session_need(keys <= set(request) <= keys | {'transit', 'currentUsers'}
                 and ('transit' not in request or type(request['transit']) is list)
                 and re.fullmatch(r'[a-f0-9]{32}', request['machineId']) and re.fullmatch(r'[a-f0-9]{24}', request['nodeId'])
                 and re.fullmatch(r'[a-f0-9]{32}', request['backupId']))
    routing(request['network'])
    with directory(SYSTEM) as lock:
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        require_census_machine(request['machineId'])
        if request['action'] == 'retirement-count':
            # Try the joined positive shape first. An independently reported
            # pair of nonzero counts is never a positive retirement receipt.
            try:
                with retirement_observation():
                    state = observe_removal(request, active=True)
                    with retire_active_view(request, state) as (_, _, sample, token, _, _):
                        snapshot = sample()
                        count = len(snapshot[0][1])
                        return {'activeSessions': count, 'activeIpsec': count, 'census': token(snapshot), 'activeClients': count}
            except Refusal as error:
                if str(error) != RETIRE_CHANGED:
                    raise
        census = relay_session_census(request)
        require_census_machine(request['machineId'])
        if request['action'] == 'retirement-count':
            census['activeClients'] = 0 if census['activeSessions'] == census['activeIpsec'] == 0 else None
        return census


def install_lock_identity(lock_fd):
    st = os.fstat(lock_fd)
    lock_id = [st.st_dev, st.st_ino]
    with directory(SYSTEM) as current:
        live = os.fstat(current)
        need(lock_id == [live.st_dev, live.st_ino], 'BASELINE_CHANGED')
    return lock_id


class PackageRunner:
    def __init__(self):
        self.remaining = PACKAGE_MAX_COMMANDS
        self.entered = False
        self.failed = False
        self.update_dispatched = False
        self.update_settled = False
        self.apt_dispatched = False
        self.apt_settled = False
        self.check_profile = lambda: None
        self.emit_progress = False

    def __call__(self, argv: tuple[str, ...], timeout: int) -> tuple[int, bytes, bytes]:
        try:
            need(not self.failed and self.remaining > 0, 'IN_FLIGHT')
            # Only bundled guard code supplies argv. A closed executable set,
            # empty stdin and fixed environment keep this from being a shell seam.
            need(type(argv) is tuple and 1 < len(argv) <= 128 and all(
                type(arg) is str and 0 < len(arg) <= 4096 and '\0' not in arg for arg in argv)
                 and type(timeout) is int and timeout > 0, 'IN_FLIGHT')
            end = min(DEADLINE, time.monotonic() + timeout)
            already_updated = self.update_dispatched
            already_dispatched = self.apt_dispatched
            read_only = self.admit(argv)
            self.remaining -= 1
            apt_install = not already_dispatched and self.apt_dispatched
            if apt_install or (not already_updated and self.update_dispatched):
                self.check_profile()
            status = bounded_status(argv, end, PACKAGE_MAX_OUTPUT, may_write=not read_only,
                                    **({'progress': AptProgress()} if apt_install and self.emit_progress else {}))
            need(time.monotonic() < end and type(status[0]) is int and status[0] >= 0, 'IN_FLIGHT')
            if not already_updated and self.update_dispatched:
                # Like the guard's strict update check, reject warnings even on zero.
                self.update_settled = status[0] == 0 and status[2] == b''
            if not already_dispatched and self.apt_dispatched:
                self.apt_settled = status[0] == 0
            return status
        except Exception:
            # An ordinary nonzero status is returned to the guard and may
            # permit checked cleanup. A timeout, signal or broken status
            # channel must never be treated as a settled package command.
            self.failed = True
            raise subprocess.TimeoutExpired((), 0) from None

    def admit(self, argv):
        binary, *args = argv
        if binary == '/usr/bin/env':
            # The guard gives only this sandboxed APT prefix, with its own
            # sealed configuration descriptor. Do not forward arbitrary env.
            need(len(argv) >= 9 and argv[:6] == ('/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
                 'LC_ALL=C', 'DEBIAN_FRONTEND=noninteractive', 'UCF_FORCE_CONFFOLD=1') and
                 re.fullmatch(rf'APT_CONFIG=/proc/{os.getpid()}/fd/[0-9]{{1,10}}', argv[6]), 'IN_FLIGHT')
            binary, verb, *args = argv[7:]
            spec = r'[a-z0-9][a-z0-9+.-]+(?:=[0-9][A-Za-z0-9.+:~\-]*)?'
            if binary == '/usr/bin/apt-cache' and verb == 'show':
                need(len(args) == 1 and re.fullmatch(spec, args[0]), 'IN_FLIGHT')
                return True
            if binary == '/usr/bin/apt-get' and verb == '-s' and args == ['check']:
                return True
            if binary == '/usr/bin/apt-get' and verb == '--error-on=any' and args == ['update']:
                need(self.entered and not self.update_dispatched and not self.apt_dispatched, 'IN_FLIGHT')
                self.update_dispatched = True
                return False
            need(binary == '/usr/bin/apt-get' and len(args) > 5 and
                 args[:5] == ['--no-install-recommends', '--no-install-suggests', '--no-remove', '--no-upgrade', 'install']
                 and all(re.fullmatch(spec, arg) for arg in args[5:]), 'IN_FLIGHT')
            if verb == '-s':
                return True
            need(verb == '-y' and self.entered and not self.apt_dispatched
                 and (not self.update_dispatched or self.update_settled), 'IN_FLIGHT')
            self.apt_dispatched = True
            return False
        if binary == '/usr/bin/systemctl':
            need(argv[1:5] == ('--system', '--no-pager', '--no-ask-password', '--full') and len(argv) >= 6,
                 'IN_FLIGHT')
            if argv[5] in ('show', 'list-jobs'):
                return True
            need(self.entered and argv[5:] == ('daemon-reload',), 'IN_FLIGHT')
            return False

        need((binary == '/usr/bin/dpkg' and len(args) == 1 and args[0] in (
              '--print-architecture', '--print-foreign-architectures', '--audit')) or
             (binary == '/usr/bin/dpkg-query' and args[0] == '-W') or
             (binary == '/usr/bin/ps' and args == ['-e', '-o', 'pid=,comm=']),
             'IN_FLIGHT')
        return True


def package_entry_exists(name):
    try:
        with directory(VAULT, private=True) as fd:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def package_no_pending():
    need(not package_entry_exists(PACKAGE_PENDING), 'IN_FLIGHT')


def package_scope(machine, fd):
    machine_id = require_machine(machine)
    boot_id = boot()
    need(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot_id), PACKAGE_AUTOSTART_UNSAFE)
    need(time.monotonic() < DEADLINE, 'IN_FLIGHT')
    return {'machineId': machine_id, 'boot': boot_id, 'installLock': install_lock_identity(fd)}


def package_diagnostic(error):
    # Only the bundled guard's exact domain checks qualify. A cleanup note,
    # even on an otherwise known refusal, makes the diagnostic ambiguous.
    if getattr(error, '__notes__', None) or len(error.args) != 1 or type(error.args[0]) is not str:
        return None
    return {
        'PACKAGE_SOURCES_CONFIG': 'PACKAGE_SOURCES_UNSUPPORTED',
        'PACKAGE_APT_UPDATE_REJECTED': 'PACKAGE_INDEXES_UNVERIFIED',
        'PACKAGE_APT_INDEXES': 'PACKAGE_INDEXES_UNVERIFIED',
        'PACKAGE_APT_PLAN': 'PACKAGE_APT_PLAN',
        'PACKAGE_UNIT_OWNER_FOREIGN': 'PACKAGE_SERVICES_UNSAFE',
        'PACKAGE_UNIT_ACTIVE': 'PACKAGE_SERVICES_UNSAFE',
        'PACKAGE_UNIT_ENABLED': 'PACKAGE_SERVICES_UNSAFE',
        'PACKAGE_SYSV_ENABLED': 'PACKAGE_SERVICES_UNSAFE',
    }.get(error.args[0])


def package_observation(guard, machine, fd, run):
    scope = package_scope(machine, fd)
    try:
        plan = guard['observe'](stock_runtime_root(), run)
    except guard['Refusal'] as error:
        need(not run.failed, 'IN_FLIGHT')
        diagnostic = package_diagnostic(error)
        if diagnostic is not None:
            try:
                need(package_scope(machine, fd) == scope, 'IN_FLIGHT')
            except Exception:
                raise Refusal('IN_FLIGHT') from None
            raise PackageDiagnostic(diagnostic) from None
        raise Refusal(PACKAGE_AUTOSTART_UNSAFE) from None
    need(not run.failed, 'IN_FLIGHT')
    need(type(plan) is dict and type(plan.get('missing')) is list and bool(plan['missing']), PACKAGE_AUTOSTART_UNSAFE)
    need(package_scope(machine, fd) == scope, 'BASELINE_CHANGED')
    commit = encode({'version': 'direct-package-preparation-v1', 'scope': scope, 'plan': plan})
    need(len(commit) <= PACKAGE_MAX_OUTPUT and time.monotonic() < DEADLINE, 'IN_FLIGHT')
    return plan, scope, digest(commit)


def package_preflight(machine):
    guard = globals().get('C3_PACKAGE_GUARD')
    need(guard is not None, PACKAGE_AUTOSTART_UNSAFE)
    with directory(SYSTEM) as fd:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        require_machine(machine)
        package_no_pending()
        foreign_no_pending()
        try:
            fresh_install_conflicts(machine, fd)
        except FreshInstallConflict as error:
            if str(error) == FOREIGN_CONFIG:
                # Package preparation may autostart VPN units and cannot be
                # combined with cleanup. Keep runtime vetoes unchanged.
                raise Refusal(PACKAGE_AUTOSTART_UNSAFE) from None
            raise
        check_package_observer_policy()
        _, _, commit = package_observation(guard, machine, fd, PackageRunner())
    need(time.monotonic() < DEADLINE, 'IN_FLIGHT')
    return {'machineId': machine, 'packagePreparation': commit}


def applied_main_matches(machine, expected):
    # Join the exact Apply bytes to the service actually running the fixed
    # MAIN path. No package, nft or module observer is needed for this read.
    require_machine(machine)
    try:
        generation = remove_generation(MAIN)
        main = read(MAIN, diagnose_main_mode=True, diagnose_profile_owner=True)
        need(generation is not None and main is not None and digest(raw(main)) == expected, 'BASELINE_CHANGED')
        no_jobs((X,))
        info = unit(X)
        pid = xray_argv(info)
        current = unit(X)
        need(pid == xray_argv(current) and info['InvocationID'] == current['InvocationID']
             and read(MAIN) == main and generation == remove_generation(MAIN),
             'BASELINE_CHANGED')
        no_jobs((X,))
        need(time.monotonic() < DEADLINE, 'BASELINE_CHANGED')
    except Refusal as error:
        if str(error) in (XRAY_CONFIG_WRITABLE, 'XRAY_PROFILE_OWNER_UNSUPPORTED', XRAY_DROPIN_UNSUPPORTED):
            raise
        return False
    except OSError:
        return False
    require_machine(machine)
    return True


def prepare_packages(request):
    keys = {'action', 'machineId', 'backupId', 'packagePreparation', 'appliedMain'}
    need(keys <= set(request) <= keys | {'progress'} and request.get('progress', True) is True and all(
        type(request[key]) is str and re.fullmatch(pattern, request[key])
        for key, pattern in (('machineId', r'[a-f0-9]{32}'), ('backupId', r'[a-f0-9]{32}'),
                             ('packagePreparation', r'[a-f0-9]{64}'), ('appliedMain', r'[a-f0-9]{64}'))), 'CANDIDATE_INVALID')
    guard = globals().get('C3_PACKAGE_GUARD')
    if guard is None:
        raise Refusal(PACKAGE_AUTOSTART_UNSAFE)
    machine, token = request['machineId'], request['backupId']
    receipt_name = 'packages-' + token + '.json'
    receipt_path, pending_path = VAULT + '/' + receipt_name, VAULT + '/' + PACKAGE_PENDING
    journaling = refused = False
    diagnostic = None
    try:
        with directory(SYSTEM) as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require_machine(machine)
            package_no_pending()
            foreign_no_pending()
            need(not package_entry_exists(receipt_name) and not package_entry_exists(token), 'BASELINE_CHANGED')
            try:
                require_runtime_packages(PACKAGE_AUTOSTART_UNSAFE)
            except Refusal as error:
                if str(error) != PACKAGE_AUTOSTART_UNSAFE:
                    raise
            else:
                raise Refusal('BASELINE_CHANGED')

            def check_profile():
                need(applied_main_matches(machine, request['appliedMain']), 'BASELINE_CHANGED')

            check_profile()
            fresh_install_conflicts(machine, fd)
            run = PackageRunner()
            run.check_profile = check_profile
            run.emit_progress = request.get('progress') is True
            plan, scope, commit = package_observation(guard, machine, fd, run)
            need(commit == request['packagePreparation'], 'BASELINE_CHANGED')
            check_package_observer_policy()
            binding = {**scope, 'backupId': token, 'packagePreparation': commit}
            intent = entry(encode({**binding, 'phase': 'preparing'}))
            journaling = True
            # Do not create VAULT/<backupId>: stock Install still owns the
            # creation and no-replace publication of that directory/manifest.
            mkdir(VAULT, 0o700, exist_ok=True)
            with directory(os.path.dirname(VAULT)) as parent:
                os.fsync(parent)
            write(receipt_path, None, intent)
            write(pending_path, None, intent)

            def recheck(receipt=intent):
                need(not run.failed and package_scope(machine, fd) == scope and
                     read(receipt_path, 1024) == receipt and read(pending_path, 1024) == intent, 'IN_FLIGHT')
                need(time.monotonic() < DEADLINE, 'IN_FLIGHT')

            def enter():
                need(not run.entered, 'IN_FLIGHT')
                recheck()
                check_profile()
                run.entered = True

            try:
                result = guard['prepare'](stock_runtime_root(), run, plan, enter)
            except guard['Refusal'] as error:
                need(not run.failed, 'IN_FLIGHT')
                diagnostic = package_diagnostic(error)
                need(not run.entered or diagnostic is not None, 'IN_FLIGHT')
                refused = not run.entered
            else:
                # Only the guard's normal post-cleanup return proves packages
                # installed, with no owned masks/policy, and services idle.
                need(run.entered and run.apt_settled and result is None, 'IN_FLIGHT')
            recheck()
            # Even an authenticated refusal after entry is only a diagnostic;
            # do not advance the operation receipt or touch the pending fence.
            if refused or diagnostic is None:
                receipt = entry(encode({**binding, 'phase': 'refused' if refused else 'ready'}))
                write(receipt_path, intent, receipt)
                recheck(receipt)
                write(pending_path, intent, None)
                package_no_pending()
        need(time.monotonic() < DEADLINE, 'IN_FLIGHT')
    except Exception:
        if journaling:
            raise Refusal('IN_FLIGHT') from None
        raise
    if diagnostic is not None:
        raise PackageDiagnostic(diagnostic, uncertain=not refused)
    if refused:
        raise Refusal(PACKAGE_AUTOSTART_UNSAFE)
    return {'ok': True, 'backupId': token, 'packagesReady': True}


def recovery_stat(path):
    parent, leaf = os.path.split(path)
    try:
        with directory(parent) as fd:
            return os.stat(leaf, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def recovery_scan(path, refused, *, private=False):
    with directory(path, private=private) as fd, os.scandir(fd) as rows:
        for count, row in enumerate(rows):
            need(count < 4096 and time.monotonic() < DEADLINE and not refused(row.name), 'IN_FLIGHT')


def recovery_package_receipt(request, scope):
    token = request['backupId']
    path = VAULT + '/packages-' + token + '.json'
    package_no_pending()
    if not package_entry_exists(os.path.basename(path)):
        need('packagePreparation' not in request, 'IN_FLIGHT')
        return None
    record = read(path, 1024)
    value = json.loads(raw(record))
    plan, phase = value['packagePreparation'], value['phase']
    need(type(plan) is str and re.fullmatch(r'[a-f0-9]{64}', plan) and
         request.get('packagePreparation', plan) == plan and phase in ('refused', 'ready') and
         record == entry(encode({**scope, 'backupId': token, 'packagePreparation': plan, 'phase': phase})), 'IN_FLIGHT')
    return value


def recovery_package_artifacts():
    guard = C3_PACKAGE_GUARD
    # The terminal receipt proves the package writer joined. Independently
    # refuse leftover containment; recovery never removes it.
    need(recovery_stat(guard['POLICY']) is None, 'IN_FLIGHT')
    mask_dir = '/var/lib/systemd/deb-systemd-helper-masked'
    for name in guard['UNITS']:
        state = recovery_stat(SYSTEM + '/' + name)
        need((state is None or not stat.S_ISLNK(state.st_mode)) and
             recovery_stat(mask_dir + '/' + name) is None, 'IN_FLIGHT')
    for path in ('/usr/sbin', SYSTEM, guard['ARCHIVE_PARENT']):
        if recovery_stat(path) is not None:
            recovery_scan(path, lambda name: name.startswith('.relay-package-'))


def recovery_cold_vpn():
    # Corroborate the no-DIRECT-write proof without NETLINK_XFRM. These
    # reads do not claim that arbitrary foreign XFRM policies are absent.
    tasks = command('/usr/bin/ps', '-ww', '-e', '-o', 'pid=', '-o', 'comm=', quiet=True)
    pids = {}
    for row in tasks.splitlines():
        match = re.fullmatch(rb'\s*([1-9][0-9]*) +([^\t]+)', row)
        need(match is not None, 'IN_FLIGHT')
        pid, name = cast(re.Match, match).groups()
        need(pid not in pids and name not in (b'-', b'?')
             and name.decode().lower() not in C3_PACKAGE_GUARD['DAEMONS'], 'IN_FLIGHT')
        pids[pid] = name
    need(pids.get(b'1') == b'systemd' and b'ps' in pids.values(), 'IN_FLIGHT')
    # A plain RTM_GETLINK dump needs no link-kind provider. Check the named
    # link type as well as the PPP name prefix: interfaces can be renamed.
    result: Any = json.loads(command('/usr/sbin/ip', '-j', '-details', 'link', 'show', quiet=True))
    need(type(result) is list, 'IN_FLIGHT')
    links = cast(list[dict[str, Any]], result)
    need(all(
        isinstance(row, dict) and type(row.get('ifname')) is str and not row['ifname'].startswith('ppp')
        and type(row.get('link_type')) is str and row['link_type'] != 'ppp'
        and isinstance(row.get('linkinfo', {}), dict)
        and row.get('linkinfo', {}).get('info_kind') not in ('xfrm', 'vti', 'vti6')
        for row in links) and any(row['ifname'] == 'lo' and row['link_type'] == 'loopback' for row in links), 'IN_FLIGHT')
    no_swan_rule()


def recovery_empty(request):
    d, token = request['network'], request['backupId']
    fixed = (NFT_DIR, DROP_DIR, SWAN_PROFILE, PPP_PATH, XL_BOOT, SYSTEM + '/' + XL,
             '/etc/nftables.d/celerity-l2tp.nft', NAMES['ike'], NAMES['options'], NET)
    need(all(recovery_stat(path) is None for path in fixed), 'IN_FLIGHT')
    for path in {SYSTEM, SWAN_DIR, *(os.path.dirname(p) for p in (*NAMES.values(), BRIDGE, PPP_PATH, XL_BOOT))}:
        if recovery_stat(path) is not None:
            recovery_scan(path, lambda name: name.startswith('.direct-'))
    for path in (MAIN, BRIDGE):
        record = read(path)
        need((path == BRIDGE or record is not None) and
             (record is None or not follow_relay_refs(unique_profile(record), shared=path == BRIDGE)), 'IN_FLIGHT')
    for key in ('chap', 'secrets', 'starter', 'lns'):
        record = read(NAMES[key])
        if record is None:
            continue
        data = raw(record)
        if key == 'lns':
            need(is_stock_lns(record), 'IN_FLIGHT')
        elif key == 'starter':
            need(uncomment(data) in ([], [b'config setup'], [STOCK_IKE_INCLUDE], [b'config setup', STOCK_IKE_INCLUDE]), 'IN_FLIGHT')
        else:
            need(not uncomment(data) and CHAP_BEGIN not in data and CHAP_END not in data, 'IN_FLIGHT')
    watched = (*UNITS, *C3_PACKAGE_GUARD['UNITS'])
    no_jobs(watched)
    for name in (XL, IKE, NET_UNIT):
        info = unit(name)
        need(info['LoadState'] in (('not-found',) if name == NET_UNIT else ('not-found', 'loaded'))
             and info.get('ActiveState') == 'inactive' and info.get('SubState') == 'dead'
             and info.get('MainPID') == '0' and not info.get('DropInPaths'), 'IN_FLIGHT')
    missing = missing_network_observers()
    # This exception is only for the unentered Install branch. Without socket
    # or nft observers there is no independent proof here; never autoload.
    need(not missing or missing == ['xfrm_user'], 'IN_FLIGHT')
    need(not any(row[2] in (500, 4500, 1701, d['tproxyPort']) for row in sock_rows())
         and network_projection(d, token) == {'nft': None, 'rule': False, 'route': False}, 'IN_FLIGHT')
    if missing:
        recovery_cold_vpn()
    else:
        need(vpn_empty(), 'IN_FLIGHT')
    no_jobs(watched)


def recovery_manifest(request, scope):
    path, record, backup = read_manifest(request['backupId'])
    keys = {'phase', 'backupId', 'machineId', 'network', 'before', 'after'}
    need(type(backup) is dict and keys <= backup.keys(), 'IN_FLIGHT')
    phase, before, after = (backup[k] for k in ('phase', 'before', 'after'))
    # A legacy preimage missing the original boot cannot be rebound to this one.
    need(type(before) is dict and before.get('boot') == scope['boot'] and type(after) is dict, 'IN_FLIGHT')
    baseline_keys = {'boot', 'installLock', 'pppModules', 'files', 'units', 'bridge', 'sockets',
                     'globalFiles', 'installBoot', 'ikeSockets', 'swanInputs'}
    unit_keys = set(INSTALL_UNIT_FIELDS)
    account_keys = set(XRAY_ACCOUNT_FIELDS)
    need(set(backup) <= keys | {'runtime', 'nativePrepared', 'bootEnrollment', 'swanStart', 'swanGeneration',
                                      'preparedSockets', 'modulePersistence', 'foreignJournal'}
         and ('foreignJournal' in backup) == ('foreignCleanup' in before)
         and record == entry(encode(backup)) and backup['backupId'] == request['backupId']
         and backup['machineId'] == scope['machineId'] and encode(backup['network']) == encode(request['network'])
         and baseline_keys <= set(before) <= baseline_keys | {'transit', 'nativePreparation', 'emptyBridgeGeneration', 'foreignCleanup'}
         and before['installLock'] == scope['installLock']
         and type(before['installBoot']) is bool and type(before['ikeSockets']) is list
         and ((type(before['sockets']) is list and 'preparedSockets' not in backup)
              or (before['sockets'] is None and type(backup.get('preparedSockets')) is list
                  and bool(backup['preparedSockets']) and any(name in before['pppModules'].get('missing', ())
                                                            for name in SOCKET_OBSERVERS)))
         and set(before['units']) == set(UNITS)
         and all(set(info) == unit_keys or (name in (X, B) and unit_keys <= set(info) <= unit_keys | account_keys
                                           and all(type(info[k]) is str for k in account_keys & info.keys()))
                 for name, info in before['units'].items())
         and set(before['globalFiles']) == {'/etc/ppp/options', SWAN_CONF, XL_DEFAULT}
         and set(before['files']) == set(NAMES) | {'swan'} and before['files']['swan'] is None
         and set(after) - {'bridge'} == set(NAMES) | {'swan'}
         and all(type(item) is dict and set(item) in ({'data', 'mode', 'gid'}, {'data', 'mode', 'gid', 'uid'})
                 and isinstance(item['data'], str) and re.fullmatch(r'[a-f0-9]{64}', item['data'])
                 for item in after.values()), 'IN_FLIGHT')
    need(phase in ('installed', 'applying', 'rolled-back')
         or phase in ('cleaning-foreign', 'projected-rollback') and 'foreignJournal' in backup, 'IN_FLIGHT')
    # The legacy applying manifest precedes all native effects. The flock
    # alone doesn't join an orphaned systemctl client. The stock swanStart
    # receipt is written *after* the last native writer returns.
    if phase == 'installed' or phase == 'applying' and (
            backup.get('foreignJournal', {}).get('installSettled') is not True or 'swanStart' in backup):
        started = backup.get('swanStart')
        need(type(started) is list and len(started) == len(SWAN_START_UNITS)
             and all(isinstance(birth, str) and re.fullmatch(r'[a-f0-9]{32}', birth) and int(birth, 16) for birth in started)
             and len(set(started)) == len(started), 'IN_FLIGHT')
        # swanStart follows all file writes; a mixed set now means drift, not
        # an earlier stock applying transition that recovery may adopt.
        main = load_after(backup, require_all=True)['main'] if phase == 'applying' else read(MAIN)
        need(after_match(main, after['main']), 'IN_FLIGHT')
        tag = 'relay-l2tp-' + request['nodeId']
        need([row.get('tag') for row in unique_profile(main)['inbounds'] if
              str(row.get('tag', '')).startswith('relay-l2tp-')] == [tag], 'IN_FLIGHT')
    return path, record, backup


def reconcile_install(request):
    keys = {'action', 'machineId', 'nodeId', 'backupId', 'network', 'challenge'}
    need(keys <= set(request) <= keys | {'packagePreparation'} and all(
        type(request[k]) is str and re.fullmatch(r'[a-f0-9]{%d}' % length, request[k])
        for k, length in (('machineId', 32), ('backupId', 32), ('nodeId', 24), ('challenge', 32))) and
        ('packagePreparation' not in request or re.fullmatch(r'[a-f0-9]{64}', request['packagePreparation'])), 'IN_FLIGHT')
    token, machine, node = (request[k] for k in ('backupId', 'machineId', 'nodeId'))
    d = request['network']
    need(type(d) is dict and set(d) == {'clientCidr', 'tproxyPort', 'fwmark', 'routeTable'}, 'IN_FLIGHT')
    routing(d)
    token_dir = VAULT + '/' + token
    with directory(SYSTEM) as fd:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        scope = package_scope(machine, fd)
        package = recovery_package_receipt(request, scope)
        recovery_package_artifacts()
        recovery_scan(VAULT, lambda name: name.startswith('.direct-'), private=True)
        token_exists = package_entry_exists(token)
        if not token_exists or recovery_stat(manifest_path(token)) is None:
            foreign_no_pending()
            need(package is not None, 'IN_FLIGHT')
            marker_path = token_dir + '/' + INSTALL_ABSENT
            fence = entry(encode({**scope, 'backupId': token, 'nodeId': node, 'network': d, 'package': package}))
            if token_exists:
                recovery_scan(token_dir, lambda name: name != INSTALL_ABSENT, private=True)
                need(read(marker_path, 2048) == fence, 'IN_FLIGHT')
            # Under the writer flock, a terminal package receipt plus ENOENT
            # for the exact token (or our exact sole tombstone) proves that
            # stock Install never reached its durable backup / first effect.
            # A journal-less partial directory is NOT an empty preimage.
            recovery_empty(request)
            if not token_exists:
                # Old Install exclusively creates this same directory before its
                # first physical effect. A sidecar alone would not fence it.
                mkdir(token_dir, 0o700)
                write(marker_path, None, fence)
            with directory(VAULT, private=True) as vault, directory(token_dir, private=True) as held:
                os.fsync(held)
                os.fsync(vault)
            recovery_scan(token_dir, lambda name: name != INSTALL_ABSENT, private=True)
            need(read(marker_path, 2048) == fence, 'IN_FLIGHT')
            result = 'absent'
        else:
            require_network_observers()  # A manifest requires full rollback/readback proof.
            need(package is None or package['phase'] == 'ready', 'IN_FLIGHT')
            recovery_scan(token_dir, lambda name: name != 'manifest.json', private=True)
            path, record, backup = recovery_manifest(request, scope)
            if 'foreignJournal' in backup:
                cleanup_rollback(request, path, record, backup, fd)
            elif backup['phase'] == 'rolled-back':
                foreign_no_pending()
                verify_rollback(d, token, backup)
                owner = module_boot_owner(backup)
                need(owner is None or read(PPP_PATH, 4096) == owner[0], 'IN_FLIGHT')
            else:
                foreign_no_pending()
                rollback(request, path, record, backup)
            terminal = entry(encode(backup))
            need(backup['phase'] == 'rolled-back' and read(path, 2 * MAX_FILE) == terminal, 'IN_FLIGHT')
            if 'foreignJournal' not in backup:
                sync_rollback_receipt(path, terminal)
            result = 'rolled_back'
        need(package_scope(machine, fd) == scope and recovery_package_receipt(request, scope) == package, 'IN_FLIGHT')
    need(time.monotonic() < DEADLINE, 'IN_FLIGHT')
    return {'nodeId': node, 'backupId': token, 'machineId': machine, 'challenge': request['challenge'], 'result': result}


def observe_install(machine, network, transit, lock_fd, *, diagnose_profile_owner=False, edits=None):
    lock_id = install_lock_identity(lock_fd)
    projection = cleanup_view(edits) if edits else {}
    if edits is None:
        fresh_install_conflicts(machine, lock_fd, network['fwmark'], detailed=True)
    modules = observe_ppp_preparation(**({'drop_legacy': True} if LEGACY_MODULES in projection else {}))
    deferred = tuple(name for name in modules['missing'] if name in OBSERVERS)
    before = observe(machine, network, transit, diagnose_profile_owner=diagnose_profile_owner,
                     **({'deferred': deferred} if deferred else {}), **({'projection': projection} if projection else {}))
    need(install_lock_identity(lock_fd) == lock_id, 'BASELINE_CHANGED')
    return {**before, 'pppModules': modules, 'installLock': lock_id}


def cleanup_observe(request, d, transit, fd, *, diagnose_profile_owner=False):
    machine = request['machineId']
    cleanup = request.get('foreignCleanup')
    edits = (fresh_install_conflicts(machine, fd, d['fwmark'], cleanup=cleanup, detailed=True)
             if cleanup is not None else None)
    before = observe_install(machine, d, transit, fd, **({'diagnose_profile_owner': True} if diagnose_profile_owner else {}),
                             **({'edits': edits} if edits else {}))
    if edits:
        # Do not project a pending native service activation or absent observer.
        need('nativePreparation' not in before and not set(before['pppModules']['missing']).intersection(OBSERVERS)
             and before['sockets'] is not None, 'PREREQUISITE')
        before['foreignCleanup'] = cleanup
    return before, edits


def dispatch(request: dict[str, Any]):
    global STAGE, NO_INSTALL_WRITES, CLEANUP_ENTERED
    need(os.geteuid() == 0 and type(request) is dict, 'PREREQUISITE')
    action = request['action']
    NO_INSTALL_WRITES = action == 'install'
    CLEANUP_ENTERED = False
    cleanup = request.get('foreignCleanup')
    if 'foreignCleanup' in request:
        need(action in FRESH_ACTIONS and type(cleanup) is dict and set(cleanup) == {'digest', 'fixXrayUnitMode', 'at'}
             and type(cleanup['digest']) is str and re.fullmatch(r'[a-f0-9]{64}', cleanup['digest'])
             and type(cleanup['fixXrayUnitMode']) is bool and type(cleanup['at']) is str
             and re.fullmatch(r'[0-9]{4}(?:-[0-9]{2}){2}T[0-9]{2}(?::[0-9]{2}){2}\.[0-9]{3}Z', cleanup['at']), 'CANDIDATE_INVALID')
    if action == 'reconcile-install':
        return reconcile_install(request)
    if action == 'prove-applied-main':
        need(set(request) == {'action', 'machineId', 'appliedMain'}
             and all(type(request[k]) is str and re.fullmatch(p, request[k]) for k, p in
                     (('machineId', r'[a-f0-9]{32}'), ('appliedMain', r'[a-f0-9]{64}'))), 'CANDIDATE_INVALID')
        with directory(SYSTEM) as fd:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return {'applied': applied_main_matches(request['machineId'], request['appliedMain'])}
    if action == 'prepare-packages':
        NO_INSTALL_WRITES = False
        return prepare_packages(request)
    if action == 'reattest-runtime':
        NO_INSTALL_WRITES = False
        need(set(request) == {'action', 'machineId', 'backupId', 'nodeId', 'network'}
             and all(type(request[key]) is str and re.fullmatch(pattern, request[key])
                     for key, pattern in (('machineId', r'[a-f0-9]{32}'), ('backupId', r'[a-f0-9]{32}'),
                                          ('nodeId', r'[a-f0-9]{24}'))), 'CANDIDATE_INVALID')
        routing(request['network'])
        with directory(SYSTEM) as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require_machine(request['machineId'])
            foreign_no_pending()
            return reattest_runtime(request, fd)
    machine = request['machineId']
    if action in ('session-count', 'retirement-count'):
        return read_session_count(request)
    need(re.fullmatch(r'[a-f0-9]{32}', machine) and action in
         ('preflight', 'prepare', 'check', 'install', 'verify', 'rollback', 'prepare-remove', 'remove')
         + CHAP_ACTIONS + APPLY_NETWORK_ACTIONS, 'PREREQUISITE')
    if action == 'preflight':
        need(set(request) <= {'action', 'machineId', 'foreignCleanup'}, 'CANDIDATE_INVALID')
        try:
            with directory(SYSTEM) as fd:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                ready = preflight(machine, fresh=True)
                foreign_no_pending()
                if not ready['masked']:
                    observe_ppp_preparation(precheck=True)
                    xl = unit(XL)
                    pending = pending_xl(xl)
                    fresh_install_conflicts(machine, fd, cleanup=cleanup, detailed=True)
                    if pending:
                        need(cleanup is None, NATIVE_UNIT_REQUIRED)
                        pending_native(xl, unit(IKE), pending)
                        ready = {**ready, 'unitsLoaded': False, 'nativePreparation': True}
                package_no_pending()
                return {**ready, 'pppPreparation': True}
        except Refusal as error:
            if cleanup is None and str(error) == PACKAGE_AUTOSTART_UNSAFE:
                return package_preflight(machine)
            raise
    fresh = action in FRESH_ACTIONS
    ready = preflight(machine, fresh=True) if fresh else preflight(machine)
    d = routing(request['network'])
    # Lock a stable system directory without creating a lock file in prepare.
    # This only serializes DIRECT invocations; the caller must exclude other
    # administrative writers. No locks from the old runners are consulted.
    with directory(SYSTEM) as fd:
        fcntl.flock(fd, (fcntl.LOCK_SH if action in ('inspect-chap', 'read-chap-generation') else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        require_machine(machine)
        if fresh:
            package_no_pending()
        if action != 'rollback':
            foreign_no_pending()
        if action in APPLY_NETWORK_ACTIONS:
            keys = {'action', 'machineId', 'backupId', 'network'}
            if action in ('verify-apply-network', 'restart-apply-network', 'publish-apply-profiles', 'finalize-apply-profiles'):
                keys.add('proof')
                need(re.fullmatch(r'[a-f0-9]{64}', request['proof']), 'CANDIDATE_INVALID')
            if action == 'publish-apply-profiles':
                keys |= {'nodeId', 'stageId', 'profiles', 'bridgeUnit'}
                need(re.fullmatch(r'[a-f0-9]{24}', request['nodeId'])
                     and re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}', request['stageId'])
                     and type(request['profiles']) is dict and set(request['profiles']) == {'main', 'bridge'}
                     and all(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) for value in request['profiles'].values())
                     and type(request['bridgeUnit']) is str and 1 <= len(request['bridgeUnit']) <= 4096, 'CANDIDATE_INVALID')
            need(set(request) == keys and re.fullmatch(r'[a-f0-9]{32}', request['backupId']), 'CANDIDATE_INVALID')
            need(ready['ppp'] and ready['unitsLoaded'] and not ready['masked'], 'PREREQUISITE')
            return apply_network(request, action)
        if action in CHAP_ACTIONS:
            token = request['backupId']
            keys = {'action', 'machineId', 'backupId', 'network', 'nodeId'}
            need(re.fullmatch(r'[a-f0-9]{32}', token) and re.fullmatch(r'[a-f0-9]{24}', request['nodeId']), 'CANDIDATE_INVALID')
            need(ready['ppp'] and ready['unitsLoaded'] and not ready['masked'], 'PREREQUISITE')
            if action == 'read-chap-generation':
                need(set(request) == keys, 'CANDIDATE_INVALID')
                _, _, backup, _ = owned_installation(request)
                return {'ok': True, 'backupId': token, 'generation': chap_generation(backup['phase'])}
            keys |= {'currentUsers', 'desiredUsers'}
            optional = {'revokedLogin'}
            if action == 'fence-chap':
                keys.add('generation')
            if action == 'sync-chap':
                optional.add('generation')
            need(keys <= set(request) <= keys | optional, 'CANDIDATE_INVALID')
            if 'generation' in request:
                generation = request['generation']
                need((action == 'fence-chap' and generation is None)
                     or (type(generation) is str and re.fullmatch(r'[a-f0-9]{32}', generation)), 'CANDIDATE_INVALID')
            if action == 'fence-chap':
                return fence_chap(request)
            if action == 'inspect-chap':
                return inspect_chap(request)
            return sync_chap(request, write_changes=action == 'sync-chap')
        if action in ('prepare-remove', 'remove'):
            require_network_observers()
            token = request['backupId']
            keys = {'action', 'machineId', 'backupId', 'network', 'nodeId'}
            keys |= {'baseline'} if action == 'remove' else set()
            optional = {'transit', 'currentUsers'} | ({'expectedCensus'} if action == 'remove' else set())
            if request.get('retirement') is True:
                keys |= {'retirement', 'expectedCensus'}
                optional.add('drain')
            need(re.fullmatch(r'[a-f0-9]{32}', token) and re.fullmatch(r'[a-f0-9]{24}', request['nodeId'])
                 and keys <= set(request) <= keys | optional
                 and ('drain' not in request or request['drain'] is True)
                 and ('expectedCensus' not in request or re.fullmatch(r'[a-f0-9]{64}', request['expectedCensus']))
                 and ('transit' not in request or type(request['transit']) is list), 'CANDIDATE_INVALID')
            if request.get('retirement') is True:
                return retirement_prepare_or_remove(request)
            state = observe_removal(request)
            if action == 'prepare-remove':
                STAGE = 'CANDIDATE_INVALID'
                validate_profiles(state['profiles'])
                return {'ok': True, 'backupId': token, 'machineId': machine, 'baseline': state['baseline']}
            need(state['baseline'] == request['baseline'], 'BASELINE_CHANGED')
            remove_installation(request, state)
            return {'ok': True, 'backupId': token, 'removed': True}
        transit = request.get('transit')
        need('transit' not in request or type(transit) is list, 'CANDIDATE_INVALID')
        need('progress' not in request or (action == 'install' and request['progress'] is True), 'CANDIDATE_INVALID')
        if action == 'prepare':
            before, _ = cleanup_observe(request, d, transit, fd, diagnose_profile_owner=True)
            if 'nativePreparation' in before:
                ready = {**ready, 'unitsLoaded': False}
            main = raw(before['files']['main'])
            bridge = raw(before['bridge']) if before['bridge'] is not None else None
            return {**ready, 'baseline': digest(encode(before)), 'main': main.decode(), 'mainSha256': digest(main),
                    'bridge': bridge.decode() if bridge is not None else None, 'bridgeSha256': digest(bridge) if bridge is not None else None}
        token = request['backupId']
        need(re.fullmatch(r'[a-f0-9]{32}', token) and re.fullmatch(r'[a-f0-9]{64}', request['baseline']), 'CANDIDATE_INVALID')
        if action in ('check', 'install'):
            before, edits = cleanup_observe(request, d, transit, fd)
            need(digest(encode(before)) == request['baseline'], 'BASELINE_CHANGED')
            after = candidate(request, before)
            validate_profiles(after)
            if action == 'install':
                need(cleanup_observe(request, d, transit, fd) == (before, edits), 'BASELINE_CHANGED')
                if edits:
                    try:
                        install(request, before, after, fd, cleanup_edits=edits)
                    except Refusal as error:
                        if not CLEANUP_ENTERED or str(error) == 'IN_FLIGHT':
                            raise
                        path, record, backup = bound_manifest(request)
                        need(not installed_phase(backup['phase']), 'IN_FLIGHT')
                        cleanup_rollback(request, path, record, backup, fd)
                        CLEANUP_ENTERED = False
                        raise Refusal('COMMAND_FAILED') from None
                else:
                    NO_INSTALL_WRITES = False
                    install(request, before, after, fd)
        else:
            require_network_observers()
            path, record, backup = bound_manifest(request)
            if action == 'verify':
                need(installed_phase(backup['phase']), 'RUNTIME_UNPROVED')
                if 'pppModules' in backup['before']:
                    owner = module_boot_owner(backup)
                    check_module_boot_owner(owner)
                    observers = backup['before']['pppModules'].get('observers', {})
                    modules = observe_ppp_preparation(observers, installed=owner[1]) if owner else observe_ppp_preparation(fresh=False)
                    need(not modules['missing'] and not modules['persist'], 'RUNTIME_UNPROVED')
                files = load_after(backup, require_all=True)
                need(installed_runtime(d, token, runtime_before(backup), files) == backup['runtime'], 'RUNTIME_UNPROVED')
            else:
                need(backup['phase'] != 'preparing-native', 'IN_FLIGHT')
                if 'foreignJournal' in backup:
                    cleanup_rollback(request, path, record, backup, fd)
                else:
                    foreign_no_pending()
                    rollback(request, path, record, backup)
        return {'ok': True, 'backupId': token}


def main():
    global DEADLINE
    os.umask(0o077)
    action = None
    original_deadline = DEADLINE
    try:
        wire = sys.stdin.buffer.read(MAX_REQUEST + 1)
        need(0 < len(wire) <= MAX_REQUEST, 'CANDIDATE_INVALID')
        request = json.loads(wire)
        action = request.get('action') if type(request) is dict else None
        if action in ('preflight', 'prove-applied-main', 'prepare-packages', 'reconcile-install', 'reattest-runtime') \
                or type(request) is dict and 'foreignCleanup' in request:
            if action not in ('prepare', 'check', 'install'):
                need(len(wire) <= 1024, 'CANDIDATE_INVALID')

            def unique_fields(pairs):
                value = dict(pairs)
                need(len(value) == len(pairs), 'CANDIDATE_INVALID')
                return value

            request = json.loads(wire, object_pairs_hook=unique_fields)
            if action == 'prepare-packages':
                DEADLINE = PACKAGE_PREPARE_DEADLINE
            need(time.monotonic() < DEADLINE, 'IN_FLIGHT')
        result = dispatch(request)
        if action in ('prepare-packages', 'reconcile-install', 'reattest-runtime') or action == 'preflight' and 'packagePreparation' in result:
            need(time.monotonic() < DEADLINE, 'IN_FLIGHT')
    except (subprocess.TimeoutExpired, BlockingIOError):
        return 75
    except Refusal as error:
        if (action == 'reconcile-install' or REATTEST_ENTERED or REMOVE_ENTERED or CHAP_ENTERED or NETWORK_UPGRADE_ENTERED
                or NATIVE_PREPARING or CLEANUP_ENTERED or str(error) == 'IN_FLIGHT'):
            return 75
        if (str(error) in (RUNTIME_REATTEST_REQUIRED, RUNTIME_FOREIGN_CHANGE) or
                action == 'reattest-runtime' and str(error) == OBSERVATION_REQUIRED) and time.monotonic() >= DEADLINE:
            return 75
        if PPP_PREPARING and str(error) not in (PPP_REQUIRED, PPP_CONFLICT, PPP_FAILED, MODULE_BLACKLISTED, OBSERVATION_REQUIRED):
            return 75
        if isinstance(error, FreshInstallConflict):
            if time.monotonic() >= DEADLINE:
                return 75
            if (action not in FRESH_ACTIONS or str(error) not in FRESH_CONFLICTS
                    or (str(error) == FOREIGN_CONFIG and not error.keys)
                    or (error.keys and str(error) not in (FOREIGN_CONFIG, FOREIGN_CHANGED))
                    or tuple(k for k in FOREIGN_REASONS if k in error.keys) != error.keys
                    or tuple(k for k in error.keys if k in error.cleanable) != error.cleanable
                    or (error.fingerprint is not None and (not error.keys
                        or not re.fullmatch(r'[a-f0-9]{64}', error.fingerprint)))):
                print('DIRECT_PREREQUISITE', file=sys.stderr)
                return 70
            prefix = 'DIRECT_NO_WRITE_' if NO_INSTALL_WRITES else 'DIRECT_'
            detail = ' ' + ','.join(error.keys) if error.keys else ''
            if error.fingerprint is not None:
                detail += ' ' + error.fingerprint + ' ' + (','.join(error.cleanable) or '-')
            print(prefix + str(error) + detail, file=sys.stderr)
            return 70
        if isinstance(error, PackageDiagnostic):
            if time.monotonic() >= DEADLINE:
                return 75
            if error.uncertain:
                if action == 'prepare-packages':
                    print('DIRECT_UNCERTAIN_' + error.suffix, file=sys.stderr)
                return 75
            suffix = error.suffix if action in ('preflight', 'prepare-packages') else PACKAGE_AUTOSTART_UNSAFE
            print('DIRECT_' + suffix, file=sys.stderr)
            return 70
        print(('DIRECT_NO_WRITE_' if NO_INSTALL_WRITES else 'DIRECT_') + (
              'IDENTITY' if str(error) == 'IDENTITY' else
              RUNTIME_REATTEST_REQUIRED if action in RUNTIME_EPOCH_READS and str(error) == RUNTIME_REATTEST_REQUIRED else
              RETIRE_CHANGED if action in ('prepare-remove', 'remove') and str(error) == RETIRE_CHANGED else
              'REMOVE_IPSEC_BUSY' if action in ('prepare-remove', 'remove') and str(error) == 'REMOVE_IPSEC_BUSY' else
              'REMOVE_REFUSED' if action == 'remove' else
              'INSPECT_' + str(error) if action == 'inspect-chap' and isinstance(error, InspectUnproved)
              and str(error) in ('CHAP_PROJECTION_UNPROVED', 'PPP_UNPROVED', 'PIDFD_GETFD_EPERM', 'READBACK_UNPROVED') else
              'CHAP_REFUSED' if action in CHAP_ACTIONS else
              SESSION_UNKNOWN if action in ('session-count', 'retirement-count') else
              'ROLLBACK_DRIFT' if str(error) == RUNTIME_REATTEST_REQUIRED else str(error)), file=sys.stderr)
        return 70
    except Exception:
        # Trap parser failures without ever echoing file contents/child stderr.
        if (action == 'reconcile-install' or REATTEST_ENTERED or REMOVE_ENTERED or CHAP_ENTERED or NETWORK_UPGRADE_ENTERED
                or PPP_PREPARING or NATIVE_PREPARING or CLEANUP_ENTERED):
            return 75
        print(('DIRECT_NO_WRITE_' if NO_INSTALL_WRITES else 'DIRECT_') + ('REMOVE_REFUSED' if action == 'remove' else
              'CHAP_REFUSED' if action in CHAP_ACTIONS else
              SESSION_UNKNOWN if action in ('session-count', 'retirement-count') else STAGE), file=sys.stderr)
        return 70
    finally:
        DEADLINE = original_deadline
    print(json.dumps(result, ensure_ascii=True, separators=(',', ':')), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
