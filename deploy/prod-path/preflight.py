#!/usr/bin/python3.13
"""PROD launch prerequisites. No mask changes, SSH, or DB I/O from this file."""
import json
import os
from pathlib import Path
import re
import runpy
import select
import socket
import stat
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
LIB = Path('/usr/local/libexec')
CORE = LIB / 'c3-prod-maintenance/authority_helper.py'
GUARD = CORE.with_name('exclusion_guard.py')
PHYSICAL = LIB / 'c3-production-physical.py'
EFFECTS = LIB / 'c3-production-original-effects.py'
CONFIG = Path('/etc/celerity')
GUARD_POLICY = CONFIG / 'prod-admission-exclusion.json'
NODE_POLICY = CONFIG / 'topology-production-node.json'
PANEL_POLICY = CONFIG / 'topology-production.json'
STATE = Path('/var/lib/celerity/prod-path')
BOOT = Path('/proc/sys/kernel/random/boot_id')
CGROUP = Path('/sys/fs/cgroup')
GUARD_ARGV = ['/usr/bin/python3.13', '-I', str(GUARD)]
GUARD_UNIT = 'c3-prod-guard.service'
BACKEND_UNIT = 'c3-prod-backend.service'
DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
SYSTEMCTL = ['/usr/bin/systemctl', '--system', '--no-pager']
CLEAN_ENV = {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'}
HEX = r'[a-f0-9]{64}'


class Refused(Exception):
    pass


def need(ok, stage):
    if not ok:
        raise Refused(stage)


def digest(raw):
    from hashlib import sha256
    return sha256(raw).hexdigest()


def uuid_ok(value):
    return isinstance(value, str) and str(uuid.UUID(value)) == value


def trusted(path, uid=0, root=Path('/'), private=False):
    path = Path(path)
    need(path.is_absolute() and (path == root or root in path.parents) and '..' not in path.parts, 'UNTRUSTED_PATH')
    for p in (path, *path.parents):
        st = p.lstat()
        need(st.st_uid == uid and not st.st_mode & 0o022 and not stat.S_ISLNK(st.st_mode), 'UNTRUSTED_PATH')
        if p == root:
            break
    need(not private or not path.lstat().st_mode & 0o077, 'NONPRIVATE_PATH')
    return path


def read_private(path, uid=0, root=Path('/')):
    path = trusted(path, uid, root, private=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        need(stat.S_ISREG(st.st_mode) and os.path.samestat(st, path.lstat()), 'NONPRIVATE_FILE')
        raw = stream.read(1024 * 1024 + 1)
        need(len(raw) <= 1024 * 1024, 'OVERSIZE_POLICY')
        return raw


def decode(raw):
    def unique(pairs):
        result = dict(pairs)
        need(len(pairs) == len(result), 'DUPLICATE_POLICY_KEY')
        return result

    def invalid(_):
        raise Refused('INVALID_POLICY_NUMBER')

    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=invalid)
    need(type(value) is dict, 'INVALID_POLICY')
    return value


def run(args, *, timeout=15, env=None):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, timeout=timeout, env=CLEAN_ENV if env is None else env)
    return result.stdout


def probe_peer_pidfd(peer):
    fd = peer.getsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_PEERPIDFD', 77))
    try:
        need(fd >= 0 and not select.select([fd], [], [], 0)[0], 'PEER_PIDFD_UNAVAILABLE')
    finally:
        os.close(fd)


def probe_kernel():
    a, b = socket.socketpair(socket.AF_UNIX)
    with a, b:
        probe_peer_pidfd(a)
    fd = os.pidfd_open(os.getpid())
    os.close(fd)
    need(hasattr(socket, 'MSG_CMSG_CLOEXEC'), 'SCM_RIGHTS_UNSUPPORTED')


def guard_source():
    for script in (GUARD, CORE, PHYSICAL, EFFECTS):
        read_private(script)
    return runpy.run_path(str(GUARD))


def python_preflight(native):
    need(sys.version_info[:2] == (3, 13) and os.path.samefile('/proc/self/exe', GUARD_ARGV[0]), 'GUARD_PYTHON_313_REQUIRED')
    fd = os.open(CGROUP, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        native['require_cgroup2'](fd)
    finally:
        os.close(fd)
    probe_kernel()
    # The holder argv uses the distribution python3, not the 3.13 guard interpreter.
    # Compile the installed exact bytes without executing the physical holder.
    run(['/usr/bin/python3', '-I', '-B', '-c',
         'import os,socket,sys; from pathlib import Path\n'
         'assert sys.version_info >= (3,10) and hasattr(os,"pidfd_open") and hasattr(socket,"MSG_CMSG_CLOEXEC")\n'
         'for p in sys.argv[1:]: compile(Path(p).read_bytes(), p, "exec")',
         str(CORE), str(PHYSICAL), str(EFFECTS)])


def validate_guard_policy(policy, boot):
    need(set(policy) == set('version generation holderId bootId challengeSha256 lock journal socket maskedWriters'.split())
         and type(policy['version']) is int and policy['version'] == 2
         and all(uuid_ok(policy[k]) for k in ('generation', 'holderId', 'bootId'))
         and policy['bootId'] == boot and re.fullmatch(HEX, policy['challengeSha256'])
         and type(policy['maskedWriters']) is list and 0 < len(policy['maskedWriters']) <= 64
         and len({pin['unit'] for pin in policy['maskedWriters']}) == len(policy['maskedWriters']), 'INVALID_OR_STALE_GUARD_POLICY')


def isolation(policy=None, node=None):
    native = guard_source()
    python_preflight(native)
    if policy is None:
        policy = decode(read_private(GUARD_POLICY))
    if node is None:
        node = decode(read_private(NODE_POLICY))
    validate_guard_policy(policy, BOOT.read_text().strip())
    need(node['kind'] in ('node', 'host'), 'UNKNOWN_PHYSICAL_ROLE')
    need(policy['generation'] == node['maintenanceId']
         and policy['challengeSha256'] == node['guardChallengeSha256'], 'GUARD_CHALLENGE_MISMATCH')
    if node['kind'] == 'node':
        need(any(pin['unit'] == 'cc-agent.service' for pin in policy['maskedWriters']), 'CC_AGENT_MASK_REQUIRED')
    for name in ('lock', 'journal', 'socket'):
        need(Path(policy[name]).is_absolute(), 'GUARD_RESOURCE_PATH')
        trusted(Path(policy[name]).parent, private=True)
    for pin in policy['maskedWriters']:
        native['check_masked_writer'](pin, Path('/'), CGROUP, 0)
    return policy


def main_pid(unit):
    return int(run([*SYSTEMCTL, 'show', '--value', '--property=MainPID', '--', unit], timeout=3))


def owns_listener(proc, path):
    # Non-connecting readiness. A probe connection from the wrong argv poisons v2.
    inodes = set()
    for line in Path('/proc/net/unix').read_text().splitlines()[1:]:
        fields = line.split(maxsplit=7)
        if len(fields) == 8 and fields[3:6] == ['00010000', '0001', '01'] and fields[7] == path:
            inodes.add('socket:[' + fields[6] + ']')
    for fd in (proc / 'fd').iterdir():
        try:
            if os.readlink(fd) in inodes:
                return True
        except FileNotFoundError:
            pass
    return False


def owns_flock(proc, pid, lock):
    """Read the same kernel lock shape the native checker expects on its received FD."""
    count = 0
    for fdinfo in (proc / 'fdinfo').iterdir():
        try:
            lines = fdinfo.read_text().splitlines()
        except FileNotFoundError:
            continue
        for line in lines:
            if not line.startswith('lock:'):
                continue
            row = line.split()
            if row[2:6] != ['FLOCK', 'ADVISORY', 'WRITE', str(pid)] or row[7:] != ['0', 'EOF']:
                continue
            major, minor, inode = row[6].split(':')
            count += (int(major, 16), int(minor, 16), int(inode)) == (os.major(lock.st_dev), os.minor(lock.st_dev), lock.st_ino)
    return count == 1


def guard_pin(policy, *, wait=0):
    # A listener is a birth/readback gate, not an attach or proof of an unpoisoned guard.
    end = time.monotonic() + wait
    while True:
        pid = main_pid(GUARD_UNIT)
        if pid > 1:
            proc = Path('/proc') / str(pid)
            pidfd = os.pidfd_open(pid)
            try:
                raw = proc.joinpath('cmdline').read_bytes()
                expected = b'\0'.join(map(os.fsencode, GUARD_ARGV)) + b'\0'
                need(raw == expected and proc.stat().st_uid == 0
                     and os.path.samefile(proc / 'exe', GUARD_ARGV[0]), 'GUARD_PROCESS_IDENTITY')
                if owns_listener(proc, policy['socket']):
                    # Same kernel lock shape the native consumer checks on the transferred FD.
                    lock = trusted(policy['lock'], private=True).stat()
                    need(stat.S_ISREG(lock.st_mode), 'INVALID_GUARD_LOCK')
                    peer = {'socket': str(trusted(policy['socket'], private=True)), 'pid': pid,
                            'startTicks': proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19],
                            'executableSha256': digest(proc.joinpath('exe').read_bytes()), 'argvSha256': digest(raw),
                            'holderId': policy['holderId'], 'lock': {'path': policy['lock'], 'device': lock.st_dev, 'inode': lock.st_ino},
                            'sources': [{'path': str(f), 'sha256': digest(read_private(f))} for f in (CORE, GUARD)]}
                    need(owns_flock(proc, pid, lock) and not select.select([pidfd], [], [], 0)[0]
                         and main_pid(GUARD_UNIT) == pid and owns_listener(proc, policy['socket']), 'GUARD_LOCK_NOT_HELD')
                    return peer
            finally:
                os.close(pidfd)
        need(time.monotonic() < end, 'GUARD_NOT_LISTENING')
        time.sleep(0.1)


def stopped_backend(value, project):
    try:
        state = value['State']
        labels = value['Config']['Labels']
        return (value['Name'] == '/hysteria-backend' and re.fullmatch(HEX, value['Id']) is not None
                and labels['com.docker.compose.project'] == project and labels['com.docker.compose.service'] == 'backend'
                and state['Status'] in ('created', 'exited') and type(state['Pid']) is int and state['Pid'] == 0
                and all(state[f] is False for f in ('Running', 'Paused', 'Restarting', 'Dead'))
                and value['HostConfig']['RestartPolicy']['Name'] == 'no')
    except (KeyError, TypeError):
        return False


def require_project(project):
    need(isinstance(project, str) and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', project), 'EXPLICIT_COMPOSE_PROJECT_REQUIRED')


def docker_exclusion(project):
    require_project(project)

    def ids(*filters):
        out = run([*DOCKER, 'container', 'ls', '--all', '--quiet', '--no-trunc',
                   *[arg for f in filters for arg in ('--filter', f)]])
        found = out.decode('ascii').splitlines()
        need(all(re.fullmatch(HEX, value) for value in found), 'DOCKER_INVENTORY_INVALID')
        return found

    label = 'label=com.docker.compose.project=' + project
    need(not ids('name=^/hysteria-updater$') and not ids(label, 'label=com.docker.compose.service=updater'), 'UPDATER_STILL_PRESENT')
    backend = ids('name=^/hysteria-backend$')
    need(len(backend) <= 1 and backend == ids(label, 'label=com.docker.compose.service=backend'), 'BACKEND_WRITER_IDENTITY')
    if backend:
        value, = json.loads(run([*DOCKER, 'container', 'inspect', backend[0]]))
        need(value['Id'] == backend[0] and stopped_backend(value, project), 'BACKEND_STILL_RESTARTABLE_OR_RUNNING')


def compose_command(project):
    checkout = HERE.parents[1]
    return [*DOCKER, 'compose', '--project-name', project, '--project-directory', str(checkout),
            '-f', str(checkout / 'docker-compose.yml'), '-f', str(HERE / 'compose.override.yml')]


def backend_model(model, image):
    services = model['services']
    b = services['backend']
    mounts = b['volumes']
    by_target = {m['target']: m for m in mounts}
    need(set(services) == {'mongo', 'redis', 'caddy', 'backend'}
         and b['image'] == image and not b.get('build') and b['restart'] == 'no'
         and b['pull_policy'] == 'never' and b['user'] == '0:0' and not b.get('privileged')
         and not b.get('network_mode') and not b.get('pid') and not b.get('devices') and not b.get('ports')
         and not b.get('volumes_from') and not b.get('cap_add')
         and b['entrypoint'] == ['/bin/sh', '-ec', 'node /app/deploy/prod-path/preflight-ssh.cjs && exec node /app/index.js']
         and not b.get('command') and b['environment']['UPDATER_URL'] == '' and b['environment']['UPDATER_SECRET'] == ''
         and all(b['environment'].get(name) == expected for name, expected in {
             'PANEL_DOMAIN': 'lm1.infograd.online', 'L2TP_EXECUTION_ENABLED': 'true',
             'L2TP_MIGRATIONS_ENABLED': 'true', 'TOPOLOGY_PRODUCTION_EXECUTION_ENABLED': 'true',
             'TOPOLOGY_TEST_EXECUTION_ENABLED': 'false', 'TOPOLOGY_TEST_STARTUP_MODE': '',
             'L2TP_PRODUCTION_EXECUTION_ENABLED': 'false'}.items())
         and len(by_target) == len(mounts) == 5 and set(by_target) == {'/etc/celerity', '/app/logs', '/app/backups', '/app/data', '/caddy_data'}
         and by_target['/etc/celerity']['type'] == 'bind' and by_target['/etc/celerity']['source'] == '/etc/celerity'
         and by_target['/etc/celerity'].get('read_only') is True
         and not by_target['/etc/celerity'].get('bind', {}).get('create_host_path', False)
         and by_target['/caddy_data']['type'] == 'volume' and by_target['/caddy_data'].get('read_only') is True
         and all(by_target[target]['type'] == 'bind' and by_target[target]['source'] == str(HERE.parents[1] / leaf)
                 for target, leaf in (('/app/logs', 'logs'), ('/app/backups', 'backups'), ('/app/data', 'data'))), 'UNSAFE_COMPOSE_MODEL')


def wait_datastores(project, *, wait=120):
    end = time.monotonic() + wait
    while True:
        ready = True
        for service in ('mongo', 'redis'):
            value, = json.loads(run([*DOCKER, 'container', 'inspect', 'hysteria-' + service], timeout=5))
            labels = value['Config']['Labels']
            need(labels['com.docker.compose.project'] == project and labels['com.docker.compose.service'] == service,
                 'DATASTORE_PROJECT_MISMATCH')
            ready &= value['State']['Running'] is True and value['State']['Health']['Status'] == 'healthy'
        if ready and time.monotonic() < end:
            return
        need(time.monotonic() < end, 'DATASTORES_NOT_READY')
        time.sleep(1)


def start_backend():
    env = dict(CLEAN_ENV, HOME='/root', COMPOSE_PROFILES='')
    image = os.environ.get('C3_PROD_BACKEND_IMAGE', '')
    project = os.environ.get('C3_PROD_COMPOSE_PROJECT', '')
    need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:' + HEX, image), 'BACKEND_IMAGE_DIGEST_REQUIRED')
    require_project(project)
    env['C3_PROD_BACKEND_IMAGE'] = image
    cmd = compose_command(project)
    backend_model(decode(run([*cmd, 'config', '--format=json'], env=env)), image)
    wait_datastores(project)
    docker_exclusion(project)
    guard_pin(isolation())
    # No deps: start/approve the retained datastores independently. No updater, pull or build.
    os.execve(cmd[0], [*cmd, 'up', '--no-deps', '--no-build', '--pull', 'never', '--exit-code-from', 'backend', 'backend'], env)


def main():
    try:
        need(os.geteuid() == 0 and len(sys.argv) == 2, 'ROOT_AND_EXACT_COMMAND_REQUIRED')
        mode = sys.argv[1]
        if mode == 'isolation':
            isolation()
        elif mode == 'guard-ready':
            guard_pin(isolation(), wait=10)
        elif mode == 'backend':
            start_backend()
        else:
            raise Refused('UNKNOWN_PREFLIGHT_COMMAND')
        print('C3_PREFLIGHT_OK')
        return 0
    except Refused as exc:
        print('C3_PREFLIGHT_REFUSED:' + str(exc), file=sys.stderr)
    except Exception:
        print('C3_PREFLIGHT_REFUSED:HOST_CHECK_FAILED', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
