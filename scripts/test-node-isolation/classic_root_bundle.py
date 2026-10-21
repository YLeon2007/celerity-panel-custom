#!/usr/bin/python3 -I
"""Offline classic root candidate producer (never install/accept/GO).

Committed app and explicitly pinned supervisor sources, lock-exact installed
snapshot bytes (including dereferenced within-root aliases), private fixed TEST
settings and optional reviewed runtime-input proposal. Entire candidate stages
privately and publishes with Linux RENAME_NOREPLACE only after final byte checks.
Outer directory is 0700; payload directories 0755 and regular files 0644/0755.
No live authority, root ownership, namespace or mount acceptance is inferred.
"""

import argparse
import base64
import ctypes
import errno
import importlib.util
import hashlib
import json
import os
import re
from urllib.parse import urlsplit
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_FILE_BYTES = 256 * 1024 * 1024
FIXED_EXECUTABLE = "/runtime/node"
FIXED_SOURCE = "/app/index.js"
FIXED_SETTINGS = "/etc/classic.json"
DEP_ROOT = "/app/node_modules"
ELF_ROOT = "/runtime/lib"  # legacy explicitly pinned input, not a complete runtime
SUPERVISORS = {
    '/usr/local/libexec/c3-test-coordinated-restore.py': 'scripts/test-node-isolation/coordinated_restore.py',
    '/usr/local/libexec/c3-test-fresh-classic.py': 'scripts/test-node-isolation/fresh_classic_launch.py',
    '/usr/local/libexec/c3-test-fresh-prepare.py': 'scripts/test-node-isolation/prepare_fresh_supervisor.py',
}
POLICY_PATH = "/etc/c3-test-fresh-classic.json"
STATE_PATH = "/state"
INGRESS = {"ip": "212.119.42.100", "port": 3000}
SETTINGS_MODE = "TEST"
SETTINGS_FLAGS = ["L2TP_EXECUTION_ENABLED", "L2TP_MIGRATIONS_ENABLED",
    "TOPOLOGY_TEST_EXECUTION_ENABLED", "TOPOLOGY_PRODUCTION_EXECUTION_ENABLED",
    "L2TP_PRODUCTION_EXECUTION_ENABLED"]
SETTINGS_KEYS = ["PANEL_DOMAIN", "ACME_EMAIL", "ENCRYPTION_KEY", "SESSION_SECRET",
                 "MONGO_URI", "REDIS_URL", "USE_CADDY", "PORT", *SETTINGS_FLAGS]

CHUNK = 1024 * 1024
DIGEST_CHARS = set("0123456789abcdef")


class Refusal(Exception):
    """Hard refusal; the message is a stable code, never a secret value."""


def need(value, code):
    if not value:
        raise Refusal(code)


def sha256_file(path):
    hasher = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            size += len(block)
            need(size <= MAX_FILE_BYTES, "FILE_TOO_LARGE")
            hasher.update(block)
    return hasher.hexdigest(), size


def regular_file_only(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode), "SOURCE_MUST_BE_REGULAR_FILE")
    need(info.st_size <= MAX_FILE_BYTES, "FILE_TOO_LARGE")


def checked_image_path(image_root, root_path):
    """Map a fixed absolute root path into the image staging tree."""
    parts = Path(root_path).parts
    need(parts and parts[0] == os.sep and ".." not in parts and
         str(Path(root_path)) == root_path and root_path != '/', "INVALID_ROOT_PATH")
    return image_root.joinpath(*parts[1:])


def load_json_file(path, code):
    try:
        with open(path, "r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, ValueError):
        raise Refusal(code)


def load_source_allowlist(path):
    data = load_json_file(path, "INVALID_SOURCE_ALLOWLIST")
    need(type(data) is dict and set(data) in ({"repo", "commit", "files"},
                                             {"repo", "commit", "files", "pins"}),
         "INVALID_SOURCE_ALLOWLIST")
    repo, commit, files = data["repo"], data["commit"], data["files"]
    need(type(repo) is str and repo, "INVALID_SOURCE_ALLOWLIST")
    need(type(commit) is str and len(commit) == 40 and
         all(c in DIGEST_CHARS for c in commit), "INVALID_SOURCE_ALLOWLIST_COMMIT")
    need(type(files) is list and files, "INVALID_SOURCE_ALLOWLIST_FILES")
    need(all(type(x) is str and (x.startswith("/app/") or x in SUPERVISORS) and
             str(Path(x)) == x and not set(Path(x).parts) & {"..", ".env", ".git", "logs"} and
             not x.startswith(DEP_ROOT+'/') and
             not any(part.startswith('.env.') for part in Path(x).parts)
             for x in files), "INVALID_SOURCE_ALLOWLIST_FILES")
    need(len(set(files)) == len(files), "DUPLICATE_SOURCE_ALLOWLIST")
    pins = data.get('pins', {})
    need(type(pins) is dict and set(pins) == set(files) & SUPERVISORS.keys() and
         all(type(v) is str and re.fullmatch('[a-f0-9]{64}',v) for v in pins.values()),
         'SUPERVISOR_PINS_REQUIRED')
    return {"repo": repo, "commit": commit, "files": list(files), 'pins':pins}


def run_git(repo, args):
    result = subprocess.run(["git", "-C", repo, *args],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=60, check=False)
    need(result.returncode == 0, "GIT_PLUMBING_FAILED")
    return result.stdout


def export_committed_sources(allowlist, image_root):
    """Copy exactly the allowlisted committed regular files via git plumbing."""
    repo, commit = allowlist["repo"], allowlist["commit"]
    run_git(repo, ["cat-file", "-e", commit + "^{commit}"])
    entries = {}
    for root_path in sorted(allowlist["files"]):
        rel = SUPERVISORS.get(root_path, root_path[len("/app/"):])
        need(rel and "\x00" not in rel and ".." not in Path(rel).parts,
             "INVALID_SOURCE_ALLOWLIST_FILES")
        rows = [line.split() for line in
                run_git(repo, ["ls-tree", commit, "--", rel]).decode().splitlines()]
        need(len(rows) == 1 and len(rows[0]) == 4, "SOURCE_NOT_COMMITTED")
        need(rows[0][0] in ("100644", "100755"), "SOURCE_MUST_BE_COMMITTED_REGULAR_FILE")
        need(rows[0][1] == "blob", "SOURCE_NOT_COMMITTED")
        payload = run_git(repo, ["show", "%s:%s" % (commit, rel)])
        need(len(payload) <= MAX_FILE_BYTES, "FILE_TOO_LARGE")
        dest = checked_image_path(image_root, root_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as stream:
            stream.write(payload)
        pin = hashlib.sha256(payload).hexdigest()
        if root_path in SUPERVISORS:
            need(pin == allowlist['pins'][root_path], 'SUPERVISOR_SOURCE_DRIFT')
        os.chmod(dest, 0o755 if rows[0][0] == '100755' else 0o644)
        entries[root_path] = pin
    need(FIXED_SOURCE in entries, "FIXED_SOURCE_NOT_IN_ALLOWLIST")
    return entries


def lock_package_entries(lock_path):
    data = load_json_file(lock_path, "INVALID_PACKAGE_LOCK")
    need(type(data) is dict and type(data.get("packages")) is dict,
         "PACKAGE_LOCK_PACKAGES_REQUIRED")
    packages = data["packages"]
    lock_roots = sorted(key for key in packages if key == "" or key.startswith("node_modules/"))
    for key in lock_roots:
        entry = packages[key]
        need(type(entry) is dict and type(entry.get("version")) is str,
             "LOCK_ENTRY_MISSING_PIN")
        if key == "":
            continue  # workspace root: no integrity tarball, not an installed package
        need(type(entry.get("integrity")) is str, "LOCK_ENTRY_MISSING_PIN")
        algo, sep, expect = entry["integrity"].partition("-")
        need(sep and algo == "sha512" and expect, "UNSUPPORTED_LOCK_INTEGRITY")
        try:
            base64.b64decode(expect)
        except ValueError:
            raise Refusal("UNSUPPORTED_LOCK_INTEGRITY")
    return packages, lock_roots


def expected_platform_key(os_name, cpu):
    return "%s-%s" % (os_name, cpu)


def platform_optional_absent(entry, os_name, cpu):
    """True when a lock entry is an explicitly expected platform-optional absence."""
    if entry.get("optional") is not True:
        return False
    expected_os = entry.get("os")
    expected_cpu = entry.get("cpu")
    if type(expected_os) is list and os_name not in expected_os:
        return True
    if type(expected_cpu) is list and cpu not in expected_cpu:
        return True
    return False


def verify_lock_versions(node_modules, packages, lock_roots, os_name="linux", cpu="x64"):
    """Every lock-exact installed package version must match the lock.

    Lock entries pinned to other platforms (explicit os/cpu optional packages)
    must be absent from the installed tree; a present foreign-platform package
    is drift, and a missing same-platform package is also drift.
    """
    nm = Path(node_modules)
    need(nm.is_dir(), "NODE_MODULES_MISSING")
    installed = set()
    for base, dirs, files in os.walk(nm):
        dirs.sort()
        if "package.json" in files:
            rel = os.path.relpath(base, nm).replace(os.sep, "/")
            # package.json files inside examples/lib are data, not installed roots.
            if re.fullmatch(r'(?:@[^/]+/)?[^/@][^/]*(?:/node_modules/(?:@[^/]+/)?[^/@][^/]*)*', rel):
                installed.add(rel)
    expected = {key[len('node_modules/'):] for key in lock_roots if key}
    need(installed <= expected, 'UNEXPECTED_INSTALLED_PACKAGE')
    for key in lock_roots:
        if key == "":
            continue  # the workspace root entry is not an installed package
        rel = key[len("node_modules/"):]
        entry = packages[key]
        if platform_optional_absent(entry, os_name, cpu):
            need(rel not in installed, "FOREIGN_PLATFORM_PACKAGE_PRESENT:%s" % key)
            continue
        need(rel in installed, "LOCK_PACKAGE_NOT_INSTALLED")
        manifest = load_json_file(nm / rel / "package.json",
                                  "INSTALLED_PACKAGE_MANIFEST_INVALID")
        need(manifest.get("version") == entry["version"],
             "INSTALLED_VERSION_DRIFT:%s" % key)
    return len(installed)


def load_snapshot_index(path):
    """Explicit installed-tree snapshot pins: root path -> {sha256, size}.

    This is the offline integrity evidence the lock cannot provide without
    fabricating npm tarball proof: the slice that produced the lock-exact
    installed tree emits a snapshot of every installed package file, and this
    producer re-hashes every installed file against it.
    """
    data = load_json_file(path, "INVALID_SNAPSHOT_INDEX")
    need(type(data) is dict, "INVALID_SNAPSHOT_INDEX")
    for key, value in data.items():
        need(type(key) is str and key.startswith(DEP_ROOT + "/") and
             ".." not in Path(key).parts, "INVALID_SNAPSHOT_INDEX_PATH")
        need(type(value) is dict and set(value) == {"sha256", "size"} and
             type(value["sha256"]) is str and len(value["sha256"]) == 64 and
             type(value["size"]) is int and 0 <= value["size"] <= MAX_FILE_BYTES and
             all(c in DIGEST_CHARS for c in value["sha256"]),
             "INVALID_SNAPSHOT_INDEX_ENTRY")
    return data


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def read_beneath(root, relative):
    """Open every resolved component without following replacement symlinks."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in Path(relative).parts:
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            os.close(fd); fd = child
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE_BYTES,
             'DEPENDENCY_SPECIAL_FILE_REJECTED')
        need(not os.listxattr(fd), 'SOURCE_XATTR_REJECTED')
        chunks = []; left = MAX_FILE_BYTES+1
        while left:
            data = os.read(fd, min(left, CHUNK))
            if not data: break
            chunks.append(data); left -= len(data)
        raw = b''.join(chunks)
        need(len(raw) <= MAX_FILE_BYTES and identity(before) == identity(os.fstat(fd)),
             'DEPENDENCY_READ_DRIFT')
        return raw, before
    finally:
        os.close(fd)


def resolve_dependency(root, path):
    """Resolve at most 40 links, rejecting an escape at *any* hop."""
    pending = list(path.relative_to(root).parts)
    current = root
    hops = 0
    try:
        while pending:
            part = pending.pop(0)
            current = current.parent if part == '..' else current/part
            need(current.is_relative_to(root), 'DEPENDENCY_LINK_ESCAPES_ROOT')
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                hops += 1
                need(hops <= 40, 'DEPENDENCY_LINK_DANGLING')
                target = Path(os.readlink(current))
                # Preserve '..' until prior components have resolved their links.
                target = target if target.is_absolute() else current.parent/target
                need(target.is_relative_to(root), 'DEPENDENCY_LINK_ESCAPES_ROOT')
                pending = list(target.relative_to(root).parts)+pending
                current = root
        return current
    except OSError:
        raise Refusal('DEPENDENCY_LINK_DANGLING') from None


def dependency_closure(node_modules):
    root = Path(node_modules).resolve(strict=True)
    files = {}; directories = {}; metadata = {}

    def walk(path, relative, ancestors):
        resolved = resolve_dependency(root, path)
        need(resolved.is_relative_to(root), 'DEPENDENCY_LINK_ESCAPES_ROOT')
        info = resolved.lstat()
        need(not os.listxattr(path, follow_symlinks=False) and not os.listxattr(resolved),
             'SOURCE_XATTR_REJECTED')
        key = DEP_ROOT + ('/'+relative if relative else '')
        metadata[key] = (str(resolved), identity(path.lstat()), identity(info))
        if stat.S_ISDIR(info.st_mode):
            marker = (info.st_dev, info.st_ino)
            need(marker not in ancestors, 'DEPENDENCY_DIRECTORY_CYCLE')
            directories[key] = resolved
            for child in sorted(path.iterdir()):
                walk(child, relative+'/'+child.name if relative else child.name, ancestors | {marker})
        else:
            need(stat.S_ISREG(info.st_mode), 'DEPENDENCY_SPECIAL_FILE_REJECTED')
            files[key] = resolved
    walk(root, '', set())
    return root, files, directories, metadata


def materialize_dependencies(node_modules, snapshot_index, image_root):
    """Materialize actual target bytes with exact alias-inclusive snapshot pins."""
    root, files, directories, metadata = dependency_closure(node_modules)
    need(set(files) <= set(snapshot_index), 'SNAPSHOT_INDEX_MISSING')
    need(set(snapshot_index) <= set(files), 'SNAPSHOT_INDEX_UNEXPECTED')
    for key in directories:
        checked_image_path(image_root, key).mkdir(parents=True, exist_ok=True)
    entries = {}
    for key, source in sorted(files.items()):
        raw, info = read_beneath(root, source.relative_to(root))
        need(identity(info) == metadata[key][2], 'DEPENDENCY_READ_DRIFT')
        digest = hashlib.sha256(raw).hexdigest()
        need({'sha256': digest, 'size': len(raw)} == snapshot_index[key], 'DEPENDENCY_INTEGRITY_DRIFT')
        dest = checked_image_path(image_root, key)
        dest.write_bytes(raw)
        os.chmod(dest, 0o755 if info.st_mode & 0o111 else 0o644)
        entries[key] = digest
    need(dependency_closure(node_modules)[3] == metadata, 'DEPENDENCY_TREE_DRIFT')
    need(entries, 'DEPENDENCY_CLOSURE_EMPTY')
    return entries


def load_elf_allowlist(path):
    data = load_json_file(path, "INVALID_ELF_ALLOWLIST")
    need(type(data) is dict, "INVALID_ELF_ALLOWLIST")
    for key, value in data.items():
        need(type(key) is str and key.startswith(ELF_ROOT + "/") and
             ".." not in Path(key).parts, "INVALID_ELF_ALLOWLIST_PATH")
        need(type(value) is dict and set(value) == {"source", "sha256"} and
             type(value["source"]) is str and value["source"].startswith("/") and
             ".." not in Path(value["source"]).parts and
             type(value["sha256"]) is str and len(value["sha256"]) == 64,
             "INVALID_ELF_ALLOWLIST_ENTRY")
    return data


def materialize_elf(allowlist, image_root):
    entries = {}
    for root_path in sorted(allowlist):
        spec = allowlist[root_path]
        src = Path(spec["source"])
        try:
            regular_file_only(src)
        except OSError:
            raise Refusal("ELF_INPUT_MISSING")
        digest, _ = sha256_file(src)
        need(digest == spec["sha256"], "ELF_INPUT_DIGEST_DRIFT")
        dest = checked_image_path(image_root, root_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        copy_pinned(src, dest, digest, 'ELF_INPUT_DIGEST_DRIFT', executable=bool(src.stat().st_mode & 0o111))
        entries[root_path] = digest
    return entries


def settings_shape(value):
    if type(value) is dict:
        return {str(key): settings_shape(val) for key, val in sorted(value.items())}
    if type(value) is list:
        return {"list": len(value)}
    return {"type": type(value).__name__}


def settings_bytes(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 info.st_size <= 16384 and not info.st_mode & 0o022, "INVALID_SETTINGS_FILE")
            raw = stream.read(16385)
        need(len(raw) <= 16384, "INVALID_SETTINGS_FILE")
        # Match the application's UTF-8 decoding, not Python's bytes BOM/UTF-16/32 autodetection.
        # Keep the original bytes unchanged; BOM-free strict text is the accepted subset.
        data = json.loads(raw.decode('utf-8'))
    except (OSError, ValueError):
        raise Refusal("INVALID_SETTINGS_FILE") from None
    need(type(data) is dict and set(data) ==
         {"version", "context", "stateDirectory", "listenAddress", "environment"}, "INVALID_SETTINGS_SCHEMA")
    need(type(data['version']) is int and data['version'] == 1 and
         data['context'] == 'test.infograd.online', "SETTINGS_MODE_MUST_BE_TEST")
    need(data['stateDirectory'] == STATE_PATH, "SETTINGS_STATE_PATH_FIXED")
    need(data['listenAddress'] == INGRESS['ip'], "SETTINGS_INGRESS_FIXED")
    env = data['environment']
    need(type(env) is dict and set(env) == set(SETTINGS_KEYS), "INVALID_SETTINGS_SCHEMA")
    need(all(type(v) is str and 0 < len(v) <= 4096 and
             not re.search(r'[\x00-\x1f\x7f]', v) for v in env.values()), "INVALID_SETTINGS_VALUE")
    need(env['PANEL_DOMAIN'] == data['context'] and env['USE_CADDY'] == 'true', "INVALID_SETTINGS_VALUE")
    need(env['PORT'] == str(INGRESS['port']), "SETTINGS_INGRESS_FIXED")
    need(re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', env['ACME_EMAIL']) and
         len(env['ENCRYPTION_KEY']) >= 32 and len(env['SESSION_SECRET']) >= 32, "INVALID_SETTINGS_VALUE")
    try:
        mongo, redis = urlsplit(env['MONGO_URI']), urlsplit(env['REDIS_URL'])
        need(mongo.scheme == 'mongodb' and mongo.hostname and
             not re.search(r'[,%]', mongo.hostname) and not mongo.fragment and
             re.fullmatch(r'/[A-Za-z_][A-Za-z0-9_-]{0,63}', mongo.path), "INVALID_SETTINGS_VALUE")
        need(redis.scheme == 'redis' and redis.hostname and not redis.fragment and
             re.fullmatch(r'(?:/[0-9]+)?', redis.path), "INVALID_SETTINGS_VALUE")
        # Reject malformed port syntax before the application parses the URLs.
        mongo.port; redis.port
    except ValueError:
        raise Refusal("INVALID_SETTINGS_VALUE") from None
    need(all(env[key] == 'false' for key in SETTINGS_FLAGS), "SETTINGS_FLAGS_MUST_BE_FALSE")
    return raw, settings_shape(data)


def load_settings(path):
    return settings_bytes(path)[1]


def scan_image(image_root):
    """Fail closed on any symlink/hardlink/device/xattr or oversized file."""
    need(not os.listxattr(image_root) and stat.S_ISDIR(image_root.lstat().st_mode),
         'IMAGE_ROOT_REJECTED')
    for base, dirs, files in os.walk(image_root):
        dirs.sort()
        files.sort()
        for name in dirs + files:
            path = Path(base) / name
            info = path.lstat()
            need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                 "IMAGE_SPECIAL_ENTRY_REJECTED")
            need(not os.listxattr(path, follow_symlinks=False), "IMAGE_XATTR_REJECTED")
            if stat.S_ISREG(info.st_mode):
                need(info.st_nlink == 1, "IMAGE_HARDLINK_REJECTED")
                need(info.st_size <= MAX_FILE_BYTES, "FILE_TOO_LARGE")
    return True


def materialize_runtime(path, image_root):
    """Consume the separately reviewed runtime verifier, then pin copied bytes."""
    spec = importlib.util.spec_from_file_location('classic_runtime_inputs',
                           Path(__file__).with_name('classic_runtime_inputs.py'))
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    try:
        proposal = runtime.verify(load_json_file(path, 'INVALID_RUNTIME_INPUTS'))
        entries = {}
        for entry in proposal['files']:
            target = entry['target']
            need(target in ('/runtime/node','/usr/bin/python3') or
                 target.startswith(('/usr/lib/python3.13/','/lib/','/lib64/')),
                 'RUNTIME_TARGET_FORBIDDEN')
            raw, _ = runtime.read_regular(entry['source'])
            pin = hashlib.sha256(raw).hexdigest()
            need(pin == entry['sha256'], 'RUNTIME_INPUT_DRIFT')
            dest = checked_image_path(image_root, target)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            os.chmod(dest, 0o755 if entry['executable'] else 0o644)
            entries[target] = pin
        need({'/runtime/node','/usr/bin/python3','/lib64/ld-linux-x86-64.so.2'} <= entries.keys(),
             'RUNTIME_CLOSURE_REQUIRED')
        return entries
    except runtime.Refusal:
        raise Refusal('RUNTIME_INPUTS_REFUSED') from None


def copy_pinned(source, dest, pin, code, executable=False):
    source = Path(source)
    raw, _ = read_beneath(Path('/'), source.absolute().relative_to('/'))
    need(hashlib.sha256(raw).hexdigest() == pin, code)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(raw)
    os.chmod(dest, 0o755 if executable else 0o644)


def verify_image_manifest(image_root, manifest):
    scan_image(image_root)
    actual = {}
    for base, dirs, names in os.walk(image_root):
        need(stat.S_IMODE(Path(base).stat().st_mode) == 0o755, 'IMAGE_DIRECTORY_MODE')
        for name in names:
            path = Path(base)/name
            need(stat.S_IMODE(path.stat().st_mode) in (0o644,0o755), 'IMAGE_FILE_MODE')
            actual['/'+path.relative_to(image_root).as_posix()] = sha256_file(path)[0]
    need(actual == manifest, 'FINAL_IMAGE_MANIFEST_DRIFT')


def publish_noreplace(stage, output):
    """One Linux atomic directory rename, refusing even an existing empty target."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    need(rename is not None, 'ATOMIC_PUBLICATION_UNAVAILABLE')
    rename.argtypes = [ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    rename.restype = ctypes.c_int
    fd = os.open(output.parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        result = rename(fd, os.fsencode(stage.name), fd, os.fsencode(output.name), 1)
        if result != 0:
            error = ctypes.get_errno()
            raise Refusal('OUTPUT_EXISTS_FAIL_CLOSED' if error in (errno.EEXIST,errno.ENOTEMPTY)
                          else 'ATOMIC_PUBLICATION_REFUSED')
    finally:
        os.close(fd)


def build(args):
    stage = None
    try:
        output = Path(args.output).absolute()
        need(not os.path.lexists(output), 'OUTPUT_EXISTS_FAIL_CLOSED')
        output.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=output.name+'.partial-', dir=str(output.parent)))
        image_root = stage/'root'
        image_root.mkdir()
        allow = load_source_allowlist(args.source_allowlist)
        sources = export_committed_sources(allow, image_root)
        packages, lock_roots = lock_package_entries(args.package_lock)
        verify_lock_versions(args.node_modules, packages, lock_roots)
        snapshot = load_snapshot_index(args.snapshot_index)
        dependencies = materialize_dependencies(args.node_modules, snapshot, image_root)
        installed_count = verify_lock_versions(checked_image_path(image_root, DEP_ROOT), packages, lock_roots)
        elf = materialize_elf(load_elf_allowlist(args.elf_allowlist), image_root)
        runtime_path = getattr(args, 'runtime_inputs', None)
        runtime = materialize_runtime(runtime_path, image_root) if runtime_path else {}
        need(not set(runtime) & set(elf), 'RUNTIME_TARGET_COLLISION')
        settings_raw, settings_meta = settings_bytes(args.settings)
        need(type(args.node_digest) is str and re.fullmatch('[a-f0-9]{64}', args.node_digest),
             'INVALID_NODE_DIGEST')
        try:
            regular_file_only(Path(args.node_executable))
        except OSError:
            raise Refusal('NODE_EXECUTABLE_MISSING') from None
        node_dest = checked_image_path(image_root, FIXED_EXECUTABLE)
        if runtime:
            need(runtime[FIXED_EXECUTABLE] == args.node_digest, 'NODE_EXECUTABLE_DIGEST_DRIFT')
            need(sha256_file(args.node_executable)[0] == args.node_digest, 'NODE_EXECUTABLE_DIGEST_DRIFT')
        else:
            copy_pinned(args.node_executable, node_dest, args.node_digest,
                        'NODE_EXECUTABLE_DIGEST_DRIFT', executable=True)
        settings_dest = checked_image_path(image_root, FIXED_SETTINGS)
        settings_dest.parent.mkdir(parents=True, exist_ok=True)
        settings_dest.write_bytes(settings_raw)
        os.chmod(settings_dest, 0o644)
        entries = {}
        for section in (sources,dependencies,elf,runtime):
            need(not entries.keys() & section.keys(), 'IMAGE_SECTION_COLLISION')
            entries.update(section)
        entries[FIXED_EXECUTABLE] = args.node_digest
        entries[FIXED_SETTINGS] = hashlib.sha256(settings_raw).hexdigest()
        need(POLICY_PATH not in entries, 'POLICY_PATH_NOT_MANUFACTURED')
        manifest = dict(sorted(entries.items()))
        for base, dirs, files in os.walk(image_root):
            os.chmod(base, 0o755)
            for name in files:
                path = Path(base)/name
                os.chmod(path, 0o755 if path.stat().st_mode & 0o111 else 0o644)
        verify_image_manifest(image_root, manifest)
        report = {
            'schema':'c3-classic-root-candidate-report/v1', 'candidate':True,
            'physicalAccepted':False, 'settingsMode':SETTINGS_MODE,
            'ingress':dict(INGRESS), 'statePath':STATE_PATH,
            'sourceCommit':allow['commit'],
            'sourceTree':run_git(allow['repo'],['rev-parse',allow['commit']+'^{tree}']).decode().strip(),
            'supervisorPins':allow['pins'],
            'fixedPaths':{'executable':FIXED_EXECUTABLE,'source':FIXED_SOURCE,
                          'settings':FIXED_SETTINGS,'dependencyRoot':DEP_ROOT},
            'runtimeProposal':bool(runtime_path),
            'policyPath':POLICY_PATH,'policyManifestExcluded':True,
            'counts':{'sourceFiles':len(sources),'dependencyFiles':len(dependencies),
                      'elfFiles':len(elf),'runtimeFiles':len(runtime),'payloadFiles':len(manifest),
                      'lockPackages':len(lock_roots)-('' in lock_roots),
                      'installedPackages':installed_count,
                      'expectedOptionalAbsences':sum(platform_optional_absent(packages[k],'linux','x64')
                                                     for k in lock_roots if k)},
            'settingsMetadata':settings_meta,
            'acceptance':{'physicalAccepted':False,'required':[
                'root ownership of every image entry',
                'read-only source root with private /state and read-only /proc mounts',
                'independent live accepted inventory by the platform owner',
                'separately pinned policy path outside any producer manifest'],
                'owner':'integration/coordinator/platform'},
            'limitations':['Snapshot pins prove installed bytes, not npm archive integrity.',
                           'Offline candidate only; no live settings, authority, mounts or ownership accepted.']}
        for name, document in (('manifest.json',manifest),('report.json',report)):
            with open(stage/name, 'x', encoding='utf-8') as stream:
                json.dump(document, stream, indent=2, sort_keys=True)
                stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
            os.chmod(stage/name, 0o644)
        # Last byte-for-byte closure check after all producer work, before rename.
        verify_image_manifest(image_root, manifest)
        publish_noreplace(stage, output)
        return output/'manifest.json'
    except Refusal:
        raise
    except Exception:
        # OSError messages, paths, JSON values, URL credentials and tracebacks are private.
        raise Refusal('CANDIDATE_BUILD_REFUSED') from None
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-allowlist", required=True)
    parser.add_argument("--node-modules", required=True)
    parser.add_argument("--package-lock", required=True)
    parser.add_argument("--snapshot-index", required=True)
    parser.add_argument("--elf-allowlist", required=True)
    parser.add_argument("--runtime-inputs", help="explicit offline candidate runtime proposal, not accepted inventory")
    parser.add_argument("--node-executable", required=True)
    parser.add_argument("--node-digest", required=True)
    parser.add_argument("--settings", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        manifest_path = build(args)
    except Refusal as error:
        print("REFUSAL %s" % error, file=sys.stderr)
        return 2
    print("manifest %s" % manifest_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
