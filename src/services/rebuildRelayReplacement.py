"""Private DIRECT replacement planner and stock-file staging, without dispatch.

The host owns locking, authorization, native command adapters and the live
runtime safety proof. No private samples, plans or journals should leave it.
"""
import contextlib
import fcntl
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import stat
import syslog
import tarfile
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import NamedTuple


DELETE = {
    'SWAN_PROFILE_PRESENT': '/etc/strongswan.d/celerity-rebuild-l2tp.conf',
    'IKE_PROFILE_PRESENT': '/etc/ipsec.d/celerity-rebuild-l2tp.conf',
    'OPTIONS_PRESENT': '/etc/ppp/options.xl2tpd',
    'MODULES_LOAD_FOREIGN': '/etc/modules-load.d/c3-l2tp.conf',
    'NETWORK_UNIT_ORPHANED': '/etc/systemd/system/celerity-rebuild-l2tp-network.service',
    'LEGACY_NFT_PRESENT': '/etc/nftables.d/celerity-l2tp.nft',
}
STOCK = {
    'STARTER_NOT_STOCK': ('/etc/ipsec.conf', 'strongswan-starter'),
    'SECRETS_NOT_EMPTY': ('/etc/ipsec.secrets', 'strongswan-starter'),
    'LNS_NOT_STOCK': ('/etc/xl2tpd/xl2tpd.conf', 'xl2tpd'),
}
CHAP = 'CHAP_NOT_EMPTY'
XRAY = {'XRAY_UNIT_0666': '/etc/systemd/system/xray.service',
        'XRAY_BRIDGE_UNIT_0666': '/etc/systemd/system/xray-bridge.service'}
FOLDERS = {'NFT_DIR_PRESENT': '/etc/celerity-rebuild-l2tp', 'DROPIN_PRESENT': '/etc/systemd/system/xl2tpd.service.d'}
PATHS = {**DELETE, **{key: row[0] for key, row in STOCK.items()}, CHAP: '/etc/ppp/chap-secrets', **XRAY, **FOLDERS}
ORDER = ('SWAN_PROFILE_PRESENT', 'IKE_PROFILE_PRESENT', 'OPTIONS_PRESENT', 'STARTER_NOT_STOCK',
         'SECRETS_NOT_EMPTY', CHAP, 'LNS_NOT_STOCK', *XRAY, *FOLDERS, 'MODULES_LOAD_FOREIGN',
         'NETWORK_UNIT_ORPHANED', 'LEGACY_NFT_PRESENT')
VAULT = '/var/lib/celerity-rebuild-l2tp-direct'
REPOSITORIES = {'trixie': 'https://deb.debian.org/debian/', 'trixie-updates': 'https://deb.debian.org/debian/',
                'trixie-security': 'https://security.debian.org/debian-security/'}
MAX_FILE = 1024 * 1024  # foreign_leaf and projected after-images
MAX_DEB = 8 * 1024 * 1024
MAX_TAR = 32 * 1024 * 1024
STOCK_INCLUDE = b'include /etc/ipsec.d/*.conf'


class Refusal(Exception):
    """Fixed refusal code; never include bytes, names from inputs or child output."""


class Archive(NamedTuple):
    package: str
    version: str
    arch: str
    suite: str
    filename: str
    size: int
    sha256: str


@dataclass(frozen=True)
class _Stock:
    archive: tuple
    data: bytes = field(repr=False)


@dataclass(frozen=True)
class Edit:
    key: str
    path: str
    action: str
    pin: tuple
    before: bytes | None = field(repr=False)
    after: bytes | None = field(repr=False)
    mode: int | None
    stock: str | None = None


class Plan(NamedTuple):
    edits: tuple
    set_aside: tuple
    fingerprint: str | None = None


def need(ok, code):
    if not ok:
        raise Refusal(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def md5(data):
    # This is the installed conffile equality check, not repository authentication.
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def hex_string(value, size):
    return type(value) is str and len(value) == size and re.fullmatch('[a-f0-9]+', value) is not None


def active(line):
    return bool(line.strip()) and not line.lstrip().startswith(b'#')


def stock_active(data):
    return [line.strip() for line in data.split(b'\n') if line.strip() and not line.lstrip().startswith((b'#', b';'))]


def _observe(keys, fingerprint, found, contents):
    bad = 'REPLACEMENT_BASELINE_CHANGED'
    need(type(keys) in (tuple, list) and len(keys) <= len(ORDER) and
         all(type(key) is str and key in PATHS for key in keys) and tuple(keys) == tuple(k for k in ORDER if k in keys),
         'REPLACEMENT_MANUAL')
    need(type(found) is dict and type(contents) is dict and found.keys() == contents.keys() == set(keys), bad)
    wanted = {}
    for key in keys:
        item, data = found[key], contents[key]
        need(type(item) is list and len(item) == 4 and item[0] == PATHS[key], bad)
        _, pin, digest, stock = item
        need(type(pin) is list and len(pin) == 9 and all(type(x) is int and -2**63 <= x < 2**64 for x in pin), bad)
        mode = pin[2]
        folder = key in FOLDERS
        need(0 <= pin[0] and 0 < pin[1] and mode == ((stat.S_IFDIR if folder else stat.S_IFREG) | stat.S_IMODE(mode))
             and pin[3:5] == [0, 0] and (pin[5] >= 2 if folder else pin[5] == 1) and
             (stat.S_IMODE(mode) == 0o666 if key in XRAY else not mode & 0o7022), bad)
        if folder:
            need(data is None and stock is None and digest == sha256(b'[]'), bad)
            continue
        need(type(data) is bytes and len(data) == pin[6] <= MAX_FILE and hex_string(digest, 64) and sha256(data) == digest, bad)
        if key not in STOCK:
            need(stock is None, bad)
            if key == CHAP:
                need(any(map(active, data.split(b'\n'))), bad)
            continue
        need(hex_string(stock, 32), bad)
        if key in ('STARTER_NOT_STOCK', 'SECRETS_NOT_EMPTY'):
            lines = stock_active(data)
            need(all(line.split(None, 1)[0].lower() != b'include' or key == 'STARTER_NOT_STOCK' and line == STOCK_INCLUDE
                     for line in lines), 'REPLACEMENT_MANUAL')
        if key == 'SECRETS_NOT_EMPTY':
            need(bool(lines), bad)
        else:
            suffix = b'\n' + STOCK_INCLUDE + b'\n'
            need(md5(data) != stock and not (key == 'STARTER_NOT_STOCK' and data.endswith(suffix)
                 and md5(data[:-len(suffix)]) == stock), bad)
        wanted[key] = stock
    payload = encode(['foreign-config-v2', found])
    need(fingerprint == (sha256(payload) if keys else None), bad)
    return wanted


def stock_requirements(keys, fingerprint, found, contents):
    """Return the exact required installed MD5s after validating the whole observation."""
    return _observe(keys, fingerprint, found, contents)


def _installed_identity(package, raw, wanted):
    # Producer format: ${binary:Package}\t${Status}\t${Architecture}\t${Version}\n${Conffiles}
    bad = 'REPLACEMENT_INSTALLED_METADATA'
    need(type(raw) is bytes and len(raw) <= 65536, bad)
    row, separator, rest = raw.partition(b'\n')
    identity = re.fullmatch(re.escape(package.encode()) + rb'(?::(amd64|arm64))?\tinstall ok installed\t(amd64|arm64)\t((?:[0-9]{1,16}:)?[0-9][A-Za-z0-9.+~\-]{0,238})', row)
    need(separator and identity is not None, bad)
    need(identity[1] is None or identity[1] == identity[2], bad)
    conffiles = {}
    for row in rest.split(b'\n'):
        if row:
            item = re.fullmatch(rb' (/[^\s]+) ([a-f0-9]{32})( obsolete)?', row)
            need(item is not None and item[1] not in conffiles, bad)
            conffiles[item[1]] = None if item[3] else item[2]
    need(all(conffiles.get(STOCK[key][0].encode()) == expected.encode() for key, expected in wanted.items()), bad)
    return package, identity[3].decode('ascii'), identity[2].decode('ascii')


def _archive(identity, archives, *, offline=False):
    bad = 'REPLACEMENT_ARCHIVE_RECORD'
    rows = [row for row in archives if row[:3] == identity]
    need(len(rows) == 1, bad)
    row = rows[0]
    need(type(row.suite) is str and (row.suite in REPOSITORIES or offline and row.suite == 'trixie-backports')
         and type(row.filename) is str and len(row.filename) <= 512 and
         re.fullmatch(r'pool/(?:updates/)?main/(?:[a-zA-Z0-9+.~_\-]+/)+[a-zA-Z0-9+.~_\-]+\.deb', row.filename)
         and not {'.', '..'}.intersection(row.filename.split('/')) and
         row.filename.startswith('pool/updates/') == (row.suite == 'trixie-security') and
         type(row.size) is int and 0 < row.size <= MAX_DEB and hex_string(row.sha256, 64), bad)
    return row


def _tar_stock(raw, wanted):
    bad = 'REPLACEMENT_DATA_TAR'
    need(type(raw) is bytes and 1024 <= len(raw) <= MAX_TAR and len(raw) % 512 == 0, bad)
    names = {STOCK[key][0][1:]: key for key in wanted}
    parents = {''}
    for name in names:
        while '/' in name:
            name = name.rsplit('/', 1)[0]
            parents.add(name)
    read, seen = {}, set()
    try:
        with tarfile.open(mode='r:', fileobj=io.BytesIO(raw)) as archive:
            for i, member in enumerate(archive):
                name = member.name.removeprefix('./')
                if name == '.':
                    name = ''
                need(i < 8192 and (not name or not {'', '.', '..'}.intersection(name.split('/'))), bad)
                if name not in parents and name not in names:
                    continue  # No materialization; unrelated members are never opened.
                need(name not in seen, bad)
                seen.add(name)
                if name in parents:
                    need(member.isdir() and member.size == 0, bad)
                else:
                    need(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not member.sparse and
                         0 <= member.size <= MAX_FILE, bad)
                    key = names[name]
                    with archive.extractfile(member) as f:
                        data = f.read(MAX_FILE + 1)
                    need(len(data) == member.size and md5(data) == wanted[key], 'REPLACEMENT_STOCK_MD5')
                    read[key] = data
            need(len(raw) - archive.offset >= 1024 and not any(memoryview(raw)[archive.offset:]), bad)
    except (tarfile.TarError, OSError, ValueError, OverflowError, EOFError):
        raise Refusal(bad) from None
    need(read.keys() == wanted.keys(), bad)
    return read


def stage_stock(wanted, *, installed, archives, download, data_tar):
    """Return exact stock bytes (or no stage) from authenticated archive metadata.

    download(url, expected_size) returns bytes; data_tar(verified_bytes) returns
    raw tar bytes. Callers must bound time, writes and capture in both adapters.
    """
    need(type(wanted) is dict and all(type(key) is str and key in STOCK and hex_string(value, 32)
                                    for key, value in wanted.items()), 'REPLACEMENT_MANUAL')
    if not wanted:
        return {}
    need(type(installed) is dict, 'REPLACEMENT_INSTALLED_METADATA')
    need(type(archives) in (tuple, list) and all(type(row) is Archive for row in archives), 'REPLACEMENT_ARCHIVE_RECORD')
    packages = sorted({STOCK[key][1] for key in wanted})
    requests = []
    for package in packages:
        members = {key: value for key, value in wanted.items() if STOCK[key][1] == package}
        identity = _installed_identity(package, installed.get(package), members)
        requests.append((_archive(identity, archives), members))
    result = {}
    for row, members in requests:
        need(callable(download) and callable(data_tar), 'REPLACEMENT_DOWNLOAD')
        try:
            blob = download(REPOSITORIES[row.suite] + row.filename, row.size)
        except (OSError, ValueError):
            raise Refusal('REPLACEMENT_DOWNLOAD') from None
        need(type(blob) is bytes and len(blob) == row.size and sha256(blob) == row.sha256, 'REPLACEMENT_DEB_BYTES')
        try:
            raw = data_tar(blob)
        except (OSError, ValueError):
            raise Refusal('REPLACEMENT_DATA_TAR') from None
        result.update({key: _Stock(row, data) for key, data in _tar_stock(raw, members).items()})
    return result


def plan_replacement(keys, fingerprint, found, contents, *, staged=None, allow_xray_mode=False, cleanup_at=None):
    """Derive an immutable plan; consume only this invocation's private stage."""
    wanted = _observe(keys, fingerprint, found, contents)
    need(type(allow_xray_mode) is bool, 'REPLACEMENT_MANUAL')
    if staged is None:
        staged = {}
    need(type(staged) is dict and staged.keys() == wanted.keys() and all(
        type(item) is _Stock and item.archive[0] == STOCK[key][1] and
        type(item.data) is bytes and len(item.data) <= MAX_FILE and md5(item.data) == wanted[key]
        for key, item in staged.items()), 'REPLACEMENT_STOCK_MD5')
    edits, set_aside = [], []
    for key in keys:
        before = contents[key]
        pin = tuple(found[key][1])
        mode = stat.S_IMODE(pin[2])
        if key in XRAY:
            if not allow_xray_mode:
                set_aside.append(key)
                continue
            action, after, mode = 'chmod', before, 0o644
        elif key in DELETE or key in FOLDERS:
            action, after, mode = 'delete', None, None
        else:
            action = 'replace'
            if key == CHAP:
                # Neutralize older managed delimiters before appending a new owned block.
                label = b'# ' if cleanup_at is None else b'# removed by C3 cleanup ' + cleanup_at.encode('ascii') + b': '
                markers = {b'# BEGIN CELERITY MANAGED L2TP USERS', b'# END CELERITY MANAGED L2TP USERS'}
                after = b'\n'.join(label + line if active(line) or line.strip(b' \t\r\v\f') in markers else line
                                   for line in before.split(b'\n'))
                if cleanup_at is not None:
                    mode = 0o600
                need(len(after) <= MAX_FILE, 'REPLACEMENT_MANUAL')
            else:
                after = staged[key].data
        edits.append(Edit(key, PATHS[key], action, pin, before, after, mode, wanted.get(key)))
    return Plan(tuple(edits), tuple(set_aside), fingerprint)


def _control_identity(raw, identity):
    bad = 'REPLACEMENT_ARCHIVE_IDENTITY'
    need(type(raw) is bytes and 1024 <= len(raw) <= 1024 * 1024 and len(raw) % 512 == 0, bad)
    data = None
    try:
        with tarfile.open(mode='r:', fileobj=io.BytesIO(raw)) as archive:
            for i, member in enumerate(archive):
                need(i < 128, bad)
                if member.name.removeprefix('./') != 'control':
                    continue
                need(data is None and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not member.sparse
                     and 0 < member.size <= 65536, bad)
                with archive.extractfile(member) as stream:
                    data = stream.read(65537)
                need(len(data) == member.size, bad)
            need(len(raw) - archive.offset >= 1024 and not any(memoryview(raw)[archive.offset:]), bad)
    except (tarfile.TarError, OSError, ValueError, OverflowError, EOFError):
        raise Refusal(bad) from None
    need(data is not None, bad)
    for field_name, expected in zip((b'Package', b'Version', b'Architecture'), identity):
        lines = [line.split(b':', 1)[1].strip(b' \t') for line in data.split(b'\n')
                 if line.lower().startswith(field_name.lower() + b':')]
        need(lines == [expected.encode('ascii')], bad)


def stage_installed_stock(wanted, *, installed, cached_deb, download_deb, control_tar, data_tar):
    """Exact cache or private APT download; decode that same immutable blob twice.

    The trusted host adapter must authenticate APT acquisition, check cache
    safety (ownership is not a stock proof), bound capture/time and never run
    maintainer scripts. A corrupt existing archive is not a fallback signal.
    """
    bad = 'REPLACEMENT_INSTALLED_METADATA'
    need(type(wanted) is dict and all(type(k) is str and k in STOCK and hex_string(v, 32)
                                    for k, v in wanted.items()), bad)
    if not wanted:
        return {}
    need(type(installed) is dict, bad)
    jobs = []
    for package in sorted({STOCK[k][1] for k in wanted}):
        members = {k: v for k, v in wanted.items() if STOCK[k][1] == package}
        jobs.append((_installed_identity(package, installed.get(package), members), members))
    need(callable(cached_deb) and callable(control_tar) and callable(data_tar), 'REPLACEMENT_DOWNLOAD')
    result = {}
    for identity, members in jobs:
        try:
            blob = cached_deb(*identity)
            if blob is None:
                need(callable(download_deb), 'REPLACEMENT_DOWNLOAD')
                blob = download_deb(*identity)
            need(type(blob) is bytes and 0 < len(blob) <= MAX_DEB, 'REPLACEMENT_DEB_BYTES')
            _control_identity(control_tar(blob), identity)
            result.update({k: _Stock(identity, data) for k, data in _tar_stock(data_tar(blob), members).items()})
        except (OSError, ValueError):
            raise Refusal('REPLACEMENT_ARCHIVE_IO') from None
    return result


STOCK_LISTS = '/var/lib/apt/lists'
STOCK_CACHE = '/var/cache/apt/archives'
KEYRING = '/usr/share/keyrings/debian-archive-keyring.pgp'
MAX_INDEX = 128 * 1024 * 1024
APT_ISOLATION = 'Dir::Etc::Parts "/dev/null";\nDir::Etc::Main "/dev/null";\n'


def stock_identities(wanted, installed):
    return {p: _installed_identity(p, installed.get(p), {k: v for k, v in wanted.items() if STOCK[k][1] == p})
            for p in sorted({STOCK[k][1] for k in wanted})}


def _stat(fd, name):
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _stamp(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


@contextlib.contextmanager
def _stock_file(directory, path, maximum, *, owners=((0, 0),), optional=False):
    parent, name = os.path.split(path)
    bad = 'REPLACEMENT_ARCHIVE_IO'
    directory_fd = None
    with contextlib.ExitStack() as stack:
        try:
            directory_fd = stack.enter_context(directory(parent))
            observed = _stat(directory_fd, name)
        except FileNotFoundError:
            observed = None
        if observed is None and optional:
            yield None
            return
        need(directory_fd is not None and observed is not None and stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1
             and (observed.st_uid, observed.st_gid) in owners and not observed.st_mode & 0o7022
             and 0 < observed.st_size <= maximum, bad)
        def same(current):
            return (current is not None and (current.st_uid, current.st_gid) == (observed.st_uid, observed.st_gid)
                    and _stamp(current) == _stamp(observed))

        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(name, flags, dir_fd=directory_fd), 'rb') as stream:
            need(same(os.fstat(stream.fileno())), bad)
            yield stream
            need(same(_stat(directory_fd, name)) and same(os.fstat(stream.fileno())), bad)


def _stock_read(directory, path, maximum, **kwargs):
    with _stock_file(directory, path, maximum, **kwargs) as stream:
        if stream is None:
            return None
        data = stream.read(maximum + 1)
        need(len(data) == os.fstat(stream.fileno()).st_size <= maximum, 'REPLACEMENT_ARCHIVE_IO')
        return data


@contextlib.contextmanager
def _sealed_stock(data):
    fd = os.memfd_create('c3-conffile-stock', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        remaining = memoryview(data)
        while remaining:
            count = os.write(fd, remaining)
            need(count > 0, 'REPLACEMENT_ARCHIVE_IO')
            remaining = remaining[count:]
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        yield f'/proc/{os.getpid()}/fd/{fd}'
    finally:
        os.close(fd)


def _stock_fields(raw):
    bad = 'REPLACEMENT_ARCHIVE_RECORD'
    fields = {}
    for line in raw.rstrip(b'\n').split(b'\n'):
        if line.startswith((b' ', b'\t')):
            need(bool(fields), bad)
            fields[key] += b'\n' + line.strip()
        else:
            key, sep, value = line.partition(b':')
            key = key.lower()
            need(sep and re.fullmatch(rb'[a-z0-9][a-z0-9-]*', key) is not None and key not in fields, bad)
            fields[key] = value.strip()
    return fields


def _stock_index_release(raw, suite, *, fresh):
    bad = 'REPLACEMENT_ARCHIVE_RECORD'
    row = _stock_fields(raw)
    need(suite in (*REPOSITORIES, 'trixie-backports') and row.get(b'codename') == suite.encode() and
         row.get(b'origin') == (b'Debian Backports' if suite.endswith('-backports') else b'Debian'), bad)
    now = time.time()
    def date(key):
        value = parsedate_to_datetime(row.get(key, b'').decode('ascii'))
        need(value.tzinfo is not None, bad)
        return value.timestamp()
    need(date(b'date') <= now + 10, bad)
    if fresh and (suite != 'trixie' or b'valid-until' in row):
        need(date(b'valid-until') > now, 'STOCK_RELEASE_EXPIRED')
    hashes = [line.split() for line in row.get(b'sha256', b'').strip().split(b'\n')]
    need(all(len(line) == 3 for line in hashes) and len({line[2] for line in hashes}) == len(hashes), bad)
    wanted = [(h, s) for h, s, name in hashes if name == b'main/binary-amd64/Packages']
    need(len(wanted) == 1, bad)
    sha, size = wanted[0]
    need(re.fullmatch(rb'[a-f0-9]{64}', sha) and re.fullmatch(rb'(0|[1-9][0-9]{0,8})', size)
         and int(size) <= MAX_INDEX, bad)
    return sha.decode(), int(size)


def _stock_index_records(raw, suite, identities):
    for match in re.finditer(rb'(?m)^Package: (strongswan-starter|xl2tpd)\n', raw):
        prior = raw.rfind(b'\n\n', 0, match.start())
        end = raw.find(b'\n\n', match.end() - 1)
        stanza = raw[prior + 2 if prior >= 0 else 0:end if end >= 0 else len(raw)]
        need(len(stanza) <= 65536, 'REPLACEMENT_ARCHIVE_RECORD')
        fields = _stock_fields(stanza)
        package, ver, arch = (fields.get(k, b'').decode('ascii') for k in (b'package', b'version', b'architecture'))
        if identities.get(package) != (package, ver, arch):
            continue
        size = fields.get(b'size', b'')
        need(re.fullmatch(rb'[1-9][0-9]{0,7}', size), 'REPLACEMENT_ARCHIVE_RECORD')
        yield Archive(package, ver, arch, suite, fields.get(b'filename', b'').decode('ascii'), int(size),
                      fields.get(b'sha256', b'').decode('ascii'))


def apt_stage_user():
    user = pwd.getpwnam('_apt')
    need(user.pw_uid > 0 and user.pw_gid >= 0, 'REPLACEMENT_ARCHIVE_IO')
    return user.pw_uid, user.pw_gid


def stock_verifier(directory):
    with directory('/usr/bin') as fd:
        for name in ('sqv', 'gpgv'):
            st = _stat(fd, name)
            if st is not None:
                need(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0
                     and st.st_mode & 0o100 and not st.st_mode & 0o7022, 'REPLACEMENT_ARCHIVE_IO')
                return '/usr/bin/' + name
    raise Refusal('STOCK_SIGNATURE_VERIFIER_MISSING')


def stock_log(code):
    syslog.syslog(syslog.LOG_WARNING, 'celerity-rebuild-l2tp: ' + code)


def verify_stock_release(run, verifier, work, keyring, release):
    with _sealed_stock(release) as fd:
        if verifier == '/usr/bin/gpgv':
            return run((verifier, '--homedir', str(work), '--keyring', str(keyring), '--output', '-', fd),
                       MAX_FILE, stderr_ok=True)
        # sqv 1.3 prints signer fingerprints on stdout. `--output -` names
        # a literal file, not stdout. Read only the authenticated cleartext.
        output = work / 'Release'
        run((verifier, '--keyring', str(keyring), '--cleartext', '--output', str(output), fd),
            MAX_FILE, stderr_ok=True)
        with output.open('rb') as stream:
            verified = stream.read(MAX_FILE + 1)
        output.unlink()
        need(0 < len(verified) <= MAX_FILE, 'REPLACEMENT_ARCHIVE_RECORD')
        return verified


def _stock_index(directory, index, size, sha, work, run, *, compressed_ok=False, **kwargs):
    raw = _stock_read(directory, index, MAX_INDEX, optional=True, **kwargs) if size else b''
    if raw is None and compressed_ok:
        for suffix in ('.lz4', '.xz', '.gz', '.zst', '.bz2', '.lzma'):
            compressed = _stock_read(directory, index + suffix, MAX_INDEX, optional=True, **kwargs)
            if compressed is None:
                continue
            target = work / ('Packages' + suffix)
            try:
                target.write_bytes(compressed)
                target.chmod(0o644)
                work.chmod(0o711)
                raw = run(('/usr/lib/apt/apt-helper', 'cat-file', str(target)), size, stock_cwd=str(work),
                          stock_config=str(work / 'apt.conf'), stock_owner=apt_stage_user())
            finally:
                target.unlink(missing_ok=True)
            break
    need(raw is not None and len(raw) == size and sha256(raw) == sha, 'REPLACEMENT_ARCHIVE_RECORD')
    return raw


def _stock_cached(identity, directory):
    package, version, arch = identity
    # APT escapes the epoch; also accept the epoch-less download basename.
    versions = {version.split(':')[-1], version.replace(':', '%3a'), version.replace(':', '%3A')}
    blobs = [_stock_read(directory, f'{STOCK_CACHE}/{package}_{v}_{arch}.deb', MAX_DEB, optional=True)
             for v in sorted(versions)]
    blobs = [blob for blob in blobs if blob is not None]
    need(len(blobs) <= 1, 'REPLACEMENT_ARCHIVE_RECORD')
    return blobs[0] if blobs else None


def _stock_authenticate(row, blob):
    need(blob is not None and len(blob) == row.size and sha256(blob) == row.sha256, 'REPLACEMENT_DEB_BYTES')
    return blob


def _stock_offline(blobs, directory, work, verify, run):
    if not blobs:
        return {}
    try:
        with directory(STOCK_LISTS) as fd:
            names = os.listdir(fd)
    except FileNotFoundError:
        return {}
    stems = sorted(n.removesuffix('InRelease') for n in names if n.endswith('_InRelease'))
    need(len(stems) <= 64, 'REPLACEMENT_ARCHIVE_RECORD')
    verified = {}
    pending = {i[0]: i for i in blobs}
    for stem in stems:
        path = STOCK_LISTS + '/' + stem
        try:
            release = verify(_stock_read(directory, path + 'InRelease', MAX_FILE))
            suite = _stock_fields(release).get(b'codename', b'').decode('ascii')
            sha, size = _stock_index_release(release, suite, fresh=False)
            raw = _stock_index(directory, path + 'main_binary-amd64_Packages', size, sha, work, run, compressed_ok=True)
        except (Refusal, OSError, ValueError):
            # A foreign or concurrently refreshed list is not cache proof.
            continue
        rows = list(_stock_index_records(raw, suite, pending))
        for identity in {row[:3] for row in rows}:
            row = _archive(identity, rows, offline=True)
            verified[identity] = _stock_authenticate(row, blobs[identity])
            pending.pop(row.package)
        if not pending:
            break
    return verified


@contextlib.contextmanager
def _apt_owned_dir(parent, expected, owner):
    bad = 'REPLACEMENT_ARCHIVE_IO'
    need(parent == str(expected), bad)
    fd = os.open(expected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        need((st.st_uid, st.st_gid) == owner and stat.S_IMODE(st.st_mode) == 0o700, bad)
        yield fd
    finally:
        os.close(fd)


def stage_host_stock(wanted, *, installed, directory, workspace, run):
    """Use signed local cache proof or refresh official indexes in private state."""
    identities = stock_identities(wanted, installed)
    need(identities and all(row[2] == 'amd64' for row in identities.values()), 'REPLACEMENT_INSTALLED_METADATA')
    verifier = stock_verifier(directory)
    key_data = _stock_read(directory, KEYRING, MAX_DEB, optional=True)
    if key_data is None:
        key_data = _stock_read(directory, '/usr/share/keyrings/debian-archive-keyring.gpg', MAX_DEB)
    with workspace() as work:
        keyring = work / 'debian.gpg'
        keyring.write_bytes(key_data)
        keyring.chmod(0o644)
        config = work / 'apt.conf'
        config.write_text(APT_ISOLATION, encoding='ascii')
        config.chmod(0o644)

        def verify(release):
            return verify_stock_release(run, verifier, work, keyring, release)

        blobs = {identity: blob for identity in identities.values()
                 if (blob := _stock_cached(identity, directory)) is not None}
        cached = _stock_offline(blobs, directory, work, verify, run)
        missing = {p: i for p, i in identities.items() if i not in cached}
        records = {}
        owner = apt_stage_user() if missing else None
        if owner is not None:
            incoming, lists, update = (work / name for name in ('incoming', 'lists', 'update'))
            for path in (incoming, update):
                path.mkdir(mode=0o700)
                os.chown(path, *owner)
            lists.mkdir(mode=0o755)
            lists.chmod(0o755)
            work.chmod(0o711)  # _apt can traverse, not list or edit the workspace
            sources = work / 'sources.list'
            sources.write_text(''.join(f'deb [arch=amd64 signed-by={keyring}] {uri} {suite} main\n'
                                       for suite, uri in REPOSITORIES.items()), encoding='ascii')
            sources.chmod(0o644)
            config.write_text(APT_ISOLATION + f'''Dir::Etc::sourcelist "{sources}";
Dir::Etc::sourceparts "/dev/null";
Dir::Etc::preferences "/dev/null";
Dir::Etc::preferencesparts "/dev/null";
Dir::Etc::netrc "/dev/null";
Dir::Etc::netrcparts "/dev/null";
Dir::Etc::trusted "/dev/null";
Dir::Etc::trustedparts "/dev/null";
Dir::State "{update}/";
Dir::Cache "{update}/";
Dir::State::status "/dev/null";
Dir::State::lists "{lists}/";
Dir::State::extended_states "/dev/null";
Dir::Log "{update}/";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Dir::Cache::archives "/dev/null";
Dir::Bin::dpkg "/dev/null";
APT::Architecture "amd64";
APT::Architectures {{ "amd64"; }};
APT::Sandbox::User "_apt";
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowWeakRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::Check-Valid-Until "true";
APT::Update::Error-Mode "any";
#clear Acquire::IndexTargets;
Acquire::IndexTargets::deb::Packages {{
  MetaKey "$(COMPONENT)/binary-$(ARCHITECTURE)/Packages";
  ShortDescription "Packages";
  Description "$(RELEASE)/$(COMPONENT) $(ARCHITECTURE) Packages";
  DefaultEnabled "true";
  Optional "false";
  KeepCompressed "false";
}};
Acquire::Languages "none";
Acquire::PDiffs "false";
Acquire::Retries "0";
Acquire::EnableSrvRecords "false";
Acquire::https::Timeout "10";
Acquire::https::AllowRedirect "false";
Acquire::https::Proxy "DIRECT";
Acquire::https::Verify-Peer "true";
Acquire::https::Verify-Host "true";
''', encoding='ascii')
            config.chmod(0o644)
            run(('/usr/bin/prlimit', f'--fsize={MAX_INDEX}:{MAX_INDEX}', '--', '/usr/bin/apt-get',
                 'update', '-o', f'Dir::State::lists={incoming}/'), 65536, stock_cwd=str(update),
                stock_config=str(config), stock_owner=owner, failure='STOCK_APT_UPDATE_FAILED')

            def incoming_dir(parent):
                return _apt_owned_dir(parent, incoming, owner)

            for suite, uri in REPOSITORIES.items():
                stem = uri.split('://', 1)[1].rstrip('/').replace('/', '_') + '_dists_' + suite + '_'
                release = _stock_read(incoming_dir, str(incoming / (stem + 'InRelease')), MAX_FILE, owners=(owner,))
                sha, size = _stock_index_release(verify(release), suite, fresh=True)
                index = stem + 'main_binary-amd64_Packages'
                raw = _stock_index(incoming_dir, str(incoming / index), size, sha, work, run, owners=(owner,))
                rows = list(_stock_index_records(raw, suite, missing))
                for identity in {row[:3] for row in rows}:
                    row = _archive(identity, rows)
                    prior = records.setdefault(identity, row)
                    need((row.size, row.sha256) == (prior.size, prior.sha256), 'REPLACEMENT_ARCHIVE_RECORD')
                if rows:
                    # Use only verified bytes in the root-owned selection directory.
                    for name, data in ((stem + 'InRelease', release), (index, raw)):
                        target = lists / name
                        target.write_bytes(data)
                        target.chmod(0o644)
            need(records.keys() == set(missing.values()), 'STOCK_VERSION_UNAVAILABLE')
            for identity in records.keys() & blobs.keys():
                cached[identity] = _stock_authenticate(records[identity], blobs[identity])

        def download(*identity):
            if owner is None:
                raise Refusal('REPLACEMENT_DOWNLOAD')
            row = records[identity]
            package, version, arch = identity
            dest = work / 'download'
            dest.mkdir(mode=0o700)
            os.chown(dest, *owner)
            bad = 'REPLACEMENT_DOWNLOAD'
            # APT also writes temporary files; the signed size applies only to the .deb.
            limit = max(row.size, 1 << 20)
            try:
                run(('/usr/bin/prlimit', f'--fsize={limit}:{limit}', '--', '/usr/bin/apt-get',
                     'download', f'{package}:{arch}={version}'), 65536, stock_cwd=str(dest), stock_config=str(config),
                    stock_owner=owner, failure='STOCK_APT_DOWNLOAD_FAILED')
                with _apt_owned_dir(str(dest), dest, owner) as fd, os.scandir(fd) as entries:
                    item = next(entries, None)
                    if item is None or not re.fullmatch(r'[A-Za-z0-9.+%~_\-]+\.deb', item.name) or next(entries, None) is not None:
                        raise Refusal(bad)

                def download_dir(parent):
                    return _apt_owned_dir(parent, dest, owner)

                return _stock_authenticate(row, _stock_read(download_dir, str(dest / item.name), row.size, owners=(owner,)))
            finally:
                shutil.rmtree(dest)

        def decode(blob, flag, maximum):
            with _sealed_stock(blob) as fd:
                return run(('/usr/bin/dpkg-deb', flag, fd), maximum)

        return stage_installed_stock(wanted, installed=installed, cached_deb=lambda *i: cached.get(i), download_deb=download,
                                     control_tar=lambda blob: decode(blob, '--ctrl-tarfile', MAX_FILE),
                                     data_tar=lambda blob: decode(blob, '--fsys-tarfile', MAX_TAR))
