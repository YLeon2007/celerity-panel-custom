#!/usr/bin/env python3
"""Finite, preparation-only source export / native package build / byte checker.
No install, service activation, inventory, capture or authority operations exist here.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tarfile
import urllib.request

SOURCE = 'e9e51e0a43ca6b98aeadfd2158e78430d6a44148'
TREE = '398998b7dba14e72e342a7f8872db2db60f939b9'
NODE = '20.20.2'
NODE_ARCHIVE = f'node-v{NODE}-linux-x64.tar.xz'
NODE_SHA256 = 'df770b2a6f130ed8627c9782c988fda9669fa23898329a61a871e32f965e007d'
HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/anyorder-test-stand/'
ROOT_FILES = {'index.js', 'config.js', 'package.json', 'package-lock.json', 'LICENSE',
              'Dockerfile', '.dockerignore', 'docker-compose.yml', 'Caddyfile', 'docker.env.example'}
ROOT_DIRS = {'src', 'scripts', 'views', 'public', 'templates', 'updater'}
UNRESOLVED = [
    'candidate-independent-review-and-deploy-approval',
    'five-service-reinstallation-checkpoint-and-volume-preservation',
    'pinned-updater-and-caddy-images-and-tested-TLS-config',
    'private-env-files-and-loopback-database-URIs',
    'native-port-3001-ingress-exclusion-before-start',
    'real-private-/32-overlay-P104-to-panelB-no-default-route-change',
    'independent-maintenance-2222-fresh-login-and-recovery',
    'panelB-public-registration-and-readback-real-HyNode-ID',
    'HyNode-private-ip-runner-2222-supported-form-update-completed',
    'installed-runner-profiles-units-and-accepted-empty-originals',
    'actual-machine-boot-raw-host-key-plan-unit-and-keep-pins',
    'accepted-v2-physical-config-and-accepted-test-v1-inventory',
    'finite-schema-bootstrap-with-consumers-stopped',
    'independent-hold-drain-fresh-confirm-access-and-owner-enroll',
    'fresh-ordinary-root-attestor-proofs-before-native-activation',
]


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def selected(name):
    return name in ROOT_FILES or name.split('/')[0] in ROOT_DIRS


def export(repo, out):
    repo, out = Path(repo).resolve(), Path(out).resolve()
    need(not out.exists(), 'export output must be fresh')
    need(not git(repo, 'status', '--porcelain').strip(), 'producer worktree must be clean')
    need(git(repo, 'rev-parse', f'{SOURCE}^{{tree}}').decode().strip() == TREE, 'wrong source tree')
    producer = git(repo, 'rev-parse', 'HEAD').decode().strip()
    names = git(repo, 'ls-tree', '-rz', '--name-only', SOURCE).decode().split('\0')
    names = sorted(n for n in names if n and selected(n))
    out.mkdir(mode=0o700, parents=True)
    source_files = {}
    archive = git(repo, 'archive', '--format=tar', SOURCE, '--', *names)
    with tarfile.open(fileobj=io.BytesIO(archive)) as t:
        for m in t.getmembers():
            need(m.isfile() or m.isdir(), 'product source must contain only regular files/directories')
            if m.isfile():
                stream = t.extractfile(m)
                if stream is None:
                    raise ValueError('missing source archive member')
                # Git archive uses 0664/0775; the safe tar data filter drops
                # group/other writes. Preserve Git's executable bit, not its
                # archive umask defaults, as ordinary installed 0644/0755.
                source_files[m.name] = {'sha256': sha(stream.read()), 'mode': m.mode & 0o755}
    (out / 'source.tar').write_bytes(archive)
    package_names = sorted(n for n in git(repo, 'ls-tree', '-rz', '--name-only', producer, '--', PREFIX).decode().split('\0') if n)
    need(PREFIX + 'package.py' in package_names, 'producer must be committed')
    (out / 'producer').mkdir()
    producer_files = {}
    for name in package_names:
        relative = name[len(PREFIX):]
        data = git(repo, 'show', producer + ':' + name)
        target = out / 'producer' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        producer_files[relative] = sha(data)
    value = {'format': 'c3-test-native-build-input-v1', 'sourceCommit': SOURCE, 'sourceTree': TREE,
             'sourceArchiveSha256': sha(archive), 'sourceFiles': source_files,
             'producerCommit': producer, 'producerTree': git(repo, 'rev-parse', 'HEAD^{tree}').decode().strip(),
             'producerFiles': producer_files, 'nodeVersion': NODE, 'nodeArchiveSha256': NODE_SHA256}
    write_json(out / 'build-input.json', value)
    print(json.dumps({'export': str(out), 'sourceCommit': SOURCE, 'producerCommit': producer,
                      'sourceFiles': len(source_files), 'buildInputSha256': digest(out / 'build-input.json')}))


def extract(archive, target):
    with tarfile.open(archive) as t:
        # Python's data filter rejects escaping links, devices and unsafe paths.
        t.extractall(target, filter='data')


def records(root):
    result = {}
    for p in sorted(root.rglob('*')):
        n = p.relative_to(root).as_posix()
        if n == 'manifest.json':
            continue
        if p.is_symlink():
            need(p.resolve().is_relative_to(root.resolve()), 'escaping package symlink: ' + n)
            result[n] = {'type': 'symlink', 'target': os.readlink(p)}
        elif p.is_file():
            result[n] = {'type': 'file', 'sha256': digest(p), 'mode': p.stat().st_mode & 0o777}
        else:
            need(p.is_dir(), 'unexpected package object: ' + n)
    return result


def run(args, log, cwd=None, env=None, bounded=False):
    def limits():
        os.nice(10)
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        resource.setrlimit(resource.RLIMIT_CPU, (240, 240))
    # The log is closed before its bytes can be sealed in a manifest.
    with open(log, 'wb') as f:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT,
                                timeout=600, preexec_fn=limits if bounded else None)
    need(result.returncode == 0, 'command failed; inspect private log: ' + str(log))


def download(url, target):
    with urllib.request.urlopen(url, timeout=60) as response, open(target, 'wb') as f:
        shutil.copyfileobj(response, f)


def dependency_check(app):
    lock = json.loads((app / 'package-lock.json').read_text())['packages']
    actual = {}
    for p in (app / 'node_modules').rglob('package.json'):
        relative = p.parent.relative_to(app).as_posix()
        # Package-owned fixtures/examples can contain package.json: inspect only
        # actual package roots, whose basename immediately follows node_modules.
        bits = relative.split('/')
        i = len(bits) - 2 if len(bits) >= 2 and bits[-2] == 'node_modules' else len(bits) - 3
        if i < 0 or bits[i] != 'node_modules' or (len(bits) - i == 3 and not bits[i+1].startswith('@')):
            continue
        need(relative in lock, 'unlocked installed package: ' + relative)
        value = json.loads(p.read_text())
        need(value.get('version') == lock[relative].get('version'), 'dependency version drift: ' + relative)
        need(not lock[relative].get('dev'), 'development dependency installed: ' + relative)
        actual[relative] = value.get('version')
    required = [k for k, v in lock.items() if k and not v.get('dev') and not v.get('optional')]
    need(all(k in actual for k in required), 'required lock dependency missing')
    need(actual.get('node_modules/mongoose') == lock['node_modules/mongoose']['version'], 'mongoose missing')
    return {'installedPackages': len(actual), 'versionsSha256': sha(json.dumps(actual, sort_keys=True).encode()),
            'optionalMissing': sorted(k for k,v in lock.items() if k and v.get('optional') and not v.get('dev') and k not in actual)}


def build(stage, output):
    stage, output = Path(stage).resolve(), Path(output).resolve()
    need(stage.is_relative_to(Path('/opt/c3-test/staging')) and stage.name.startswith('native-package-'),
         'build permitted only in unique TEST staging/native-package-* directory')
    need(output.parent == stage and not output.exists(), 'artifact must be fresh and inside owned staging')
    data = json.loads((stage / 'build-input.json').read_text())
    validate_input(data)
    need(digest(stage / 'source.tar') == data['sourceArchiveSha256'], 'wrong source archive hash')
    need({p.relative_to(stage / 'producer').as_posix(): digest(p) for p in (stage / 'producer').rglob('*') if p.is_file()}
         == data['producerFiles'], 'producer input drift')
    root = stage / 'bundle'
    root.mkdir(mode=0o700)
    app = root / 'app'
    app.mkdir()
    extract(stage / 'source.tar', app)
    verify_source(app, data)
    (root / 'build').mkdir()
    shutil.copy2(stage / 'build-input.json', root / 'build' / 'build-input.json')
    dist = 'https://nodejs.org/dist/v' + NODE + '/'
    sums = stage / 'SHASUMS256.txt'
    tar = stage / NODE_ARCHIVE
    download(dist + 'SHASUMS256.txt', sums)
    need(f'{NODE_SHA256}  {NODE_ARCHIVE}' in sums.read_text().splitlines(), 'official checksum differs from reviewed pin')
    download(dist + NODE_ARCHIVE, tar)
    need(digest(tar) == NODE_SHA256, 'Node archive hash mismatch')
    extract(tar, stage / 'node-dist')
    dist_root = stage / 'node-dist' / f'node-v{NODE}-linux-x64'
    runtime = root / 'runtime'
    runtime.mkdir()
    shutil.copy2(dist_root / 'bin' / 'node', runtime / 'node')
    shutil.copy2(dist_root / 'LICENSE', runtime / 'LICENSE')
    shutil.copy2(sums, root / 'build' / sums.name)
    scratch = stage / 'tmp'
    scratch.mkdir(mode=0o700)
    env = dict(os.environ, PATH=str(dist_root / 'bin') + ':/usr/bin:/bin', HOME=str(stage),
               TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch),
               NODE_ENV='production', NODE_OPTIONS='--max-old-space-size=192 --v8-pool-size=1',
               npm_config_cache=str(stage / 'npm-cache'), npm_config_jobs='1', npm_config_update_notifier='false')
    # Normal lifecycle scripts match the product's npm ci, with no compiler/tool
    # install. ssh2 may select its supported JS fallback for optional accelerators.
    run([str(dist_root / 'bin' / 'node'), str(dist_root / 'lib/node_modules/npm/bin/npm-cli.js'),
         'ci', '--omit=dev', '--no-audit', '--no-fund'], root / 'build' / 'npm-ci.log', cwd=app, env=env, bounded=True)
    write_json(root / 'build' / 'dependencies.json', dependency_check(app))
    verify_source(app, data)
    deploy = root / 'deployment'
    deploy.mkdir()
    for name in ('compose.test-native.yml', 'c3-test-native.service', 'Caddyfile.test', 'native.env.example', 'README.md'):
        shutil.copy2(stage / 'producer' / name, deploy / name)
    tools = root / 'tools'
    tools.mkdir()
    for name in ('package.py', 'test_package.py'):
        shutil.copy2(stage / 'producer' / name, tools / name)
    # Mutable data is intentionally not included. Future installation supplies
    # private writable directories/symlinks separately and pins them before hold.
    probe(root, root / 'build' / 'runtime-probe.log')
    manifest = {'format': 'c3-test-native-artifact-v1', 'status': 'preparation-only',
                'installationReady': False, 'physicalInventory': None, 'authority': None,
                'sourceCommit': SOURCE, 'sourceTree': TREE, 'producerCommit': data['producerCommit'],
                'buildInputSha256': digest(stage / 'build-input.json'), 'nodeVersion': NODE,
                'nodeArchiveSha256': NODE_SHA256, 'unresolvedInstallationInputs': UNRESOLVED,
                'targets': {'node': '/opt/c3-test/native/runtime/node', 'entry': '/opt/c3-test/native/app/index.js',
                            'unit': '/etc/systemd/system/c3-test-native.service'}, 'files': records(root)}
    write_json(root / 'manifest.json', manifest)
    with tarfile.open(output, 'w:gz') as t:
        for p in sorted(root.iterdir()):
            t.add(p, arcname=p.name)
    print(json.dumps({'artifact': str(output), 'sha256': digest(output), 'manifestSha256': digest(root / 'manifest.json'),
                      'installationReady': False, 'status': 'preparation-only'}))


def validate_input(data):
    need(data['format'] == 'c3-test-native-build-input-v1' and data['sourceCommit'] == SOURCE
         and data['sourceTree'] == TREE and data['nodeVersion'] == NODE
         and data['nodeArchiveSha256'] == NODE_SHA256, 'wrong product source/runtime pin')


def verify_source(app, data):
    for n, v in data['sourceFiles'].items():
        p = app / n
        need(p.is_file() and not p.is_symlink() and digest(p) == v['sha256']
             and p.stat().st_mode & 0o777 == v['mode'], 'source/asset hash mismatch: ' + n)
    actual = {p.relative_to(app).as_posix() for p in app.rglob('*') if p.is_file() and 'node_modules' not in p.relative_to(app).parts}
    need(actual == set(data['sourceFiles']), 'untracked product source files')


def probe(root, log):
    node, app = root / 'runtime' / 'node', root / 'app'
    code = """const path=require('node:path');const {createRequire}=require('node:module');
const app=path.resolve(process.argv[1]);const req=createRequire(path.join(app,'index.js'));
const pkg=req('./package.json');const rows={};
for(const name of Object.keys(pkg.dependencies)){rows[name]=req.resolve(name); if(!rows[name].startsWith(path.join(app,'node_modules')+path.sep))throw Error('foreign resolution:'+name);}
const mongoose=req('mongoose');
console.log(JSON.stringify({node:process.version,entry:path.join(app,'index.js'),mongoose:mongoose.version,resolved:rows}));"""
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'NODE_ENV': 'production'}
    version = subprocess.check_output([str(node), '--version'], env=env, timeout=20).decode().strip()
    need(version == 'v' + NODE, 'wrong actual runtime version')
    run([str(node), '-e', code, str(app)], log, cwd=app, env=env)
    # No application imports/startup or database access; only package resolution
    # and loading the actual installed Mongoose module, from the app entry.
    ldd = subprocess.check_output(['/usr/bin/ldd', str(node)], env=env, timeout=20).decode()
    need('not found' not in ldd and 'ld-linux-x86-64.so.2' in ldd, 'incomplete glibc runtime closure')
    with open(log, 'a') as f:
        f.write('\n' + version + '\n' + ldd)


def check(root, expected_input, execute, accept):
    root = Path(root).resolve()
    manifest = json.loads((root / 'manifest.json').read_text())
    need(manifest['format'] == 'c3-test-native-artifact-v1' and manifest['sourceCommit'] == SOURCE
         and manifest['sourceTree'] == TREE, 'wrong artifact source pin')
    need(digest(root / 'build' / 'build-input.json') == expected_input == manifest['buildInputSha256'], 'wrong independent build input hash')
    data = json.loads((root / 'build' / 'build-input.json').read_text())
    validate_input(data)
    need(manifest['producerCommit'] == data['producerCommit'] and manifest['nodeVersion'] == NODE
         and manifest['nodeArchiveSha256'] == NODE_SHA256, 'artifact pin drift')
    need(manifest['status'] == 'preparation-only' and manifest['installationReady'] is False
         and manifest['physicalInventory'] is None and manifest['authority'] is None
         and manifest['unresolvedInstallationInputs'] == UNRESOLVED, 'artifact cannot assert installation acceptance')
    need(records(root) == manifest['files'], 'package file/hash/mode/symlink mismatch')
    verify_source(root / 'app', data)
    for directory in ('deployment', 'tools'):
        for p in (root / directory).iterdir():
            need(p.is_file() and digest(p) == data['producerFiles'].get(p.name), 'deployment/tool drift: ' + p.name)
    deps = dependency_check(root / 'app')
    need(deps == json.loads((root / 'build' / 'dependencies.json').read_text()), 'dependency graph drift')
    if execute:
        # Keep fresh checker logs OUTSIDE the sealed artifact.
        probe(root, root.parent / (root.name + '-checker-probe.log'))
    need(not accept, 'INSTALLATION_NOT_READY: unresolved accepted physical inputs; package is preparation-only')
    print(json.dumps({'packageVerified': True, 'sourceCommit': SOURCE, 'producerCommit': data['producerCommit'],
                      'filesVerified': len(manifest['files']), 'dependencies': deps['installedPackages'],
                      'runtimeExecuted': execute, 'installationReady': False,
                      'unresolvedInstallationInputs': len(UNRESOLVED)}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    s = p.add_subparsers(dest='command', required=True)
    x = s.add_parser('export'); x.add_argument('--repo', required=True); x.add_argument('--output', required=True)
    x = s.add_parser('build'); x.add_argument('--stage', required=True); x.add_argument('--output', required=True)
    x = s.add_parser('check'); x.add_argument('--root', required=True); x.add_argument('--expected-input-sha256', required=True)
    x.add_argument('--execute-runtime', action='store_true'); x.add_argument('--require-installation-ready', action='store_true')
    a = p.parse_args()
    if a.command == 'export': export(a.repo, a.output)
    elif a.command == 'build': build(a.stage, a.output)
    else: check(a.root, a.expected_input_sha256, a.execute_runtime, a.require_installation_ready)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print('REFUSED: ' + str(error), file=sys.stderr)
        sys.exit(1)
