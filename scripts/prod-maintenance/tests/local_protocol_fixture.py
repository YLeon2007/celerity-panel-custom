#!/usr/bin/python3
"""TEST ONLY: fake kernel/UID, real independent guard process and broker codec.

The guard stays alive after broker refusal until the Node fixture has completed
DB cleanup. No product process or guard is simulated by a successful receipt.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

BASE = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, BASE / (name + '.py'))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
helper = load('authority_helper')
guard_module = load('exclusion_guard')

if sys.argv[1] == '--guard':
    policy_file = Path(sys.argv[2])
    root = policy_file.parent
    guard = guard_module.ExclusionGuard(json.loads(policy_file.read_text()), owner_uid=os.getuid(),
                trusted_root=root, cgroup_root=root, allow_empty_for_test=True)
    try:
        guard.serve()  # actual resident no-release implementation, separate PID/OFD
    finally:
        guard.close()
    sys.exit(1)

challenge_file = Path(sys.argv[1])
challenge = json.loads(challenge_file.read_text())
root = Path(tempfile.mkdtemp(prefix='prod-fixed-protocol-', dir=os.environ['TMPDIR']))
root.chmod(0o700)
group = root / 'cg'
group.mkdir(mode=0o700)
for name, data in [('cgroup.freeze', '1\n'), ('cgroup.events', 'frozen 1\npopulated 0\n'), ('cgroup.procs', '')]:
    group.joinpath(name).write_text(data)
    group.joinpath(name).chmod(0o600)
generation = challenge.get('maintenanceGeneration', str(uuid.uuid4()))
boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
policy = {'version': 1, 'generation': generation, 'holderId': str(uuid.uuid4()), 'bootId': boot,
          'challengeSha256': helper.sha(helper.canonical(challenge)),
          'scopes': [{'path': str(group), 'device': group.stat().st_dev, 'inode': group.stat().st_ino, 'processes': []}],
          'lock': str(root / 'guard.lock'), 'journal': str(root / 'guard.json'), 'socket': str(root / 'g.sock')}
guard_file = root / 'guard-policy.json'
guard_file.write_bytes(helper.canonical(policy))
guard_file.chmod(0o600)
guard_process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--guard', str(guard_file)],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
code = 1
try:
    deadline = time.monotonic() + 5
    while not Path(policy['socket']).exists():
        if guard_process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError('LOCAL_GUARD_FIXTURE_START_FAILED')
        time.sleep(0.01)
    proc = Path('/proc') / str(guard_process.pid)
    start = proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]
    lock_st = Path(policy['lock']).stat()
    sources = []
    for name in ['authority_helper.py', 'exclusion_guard.py']:
        target = root / name
        target.write_bytes(BASE.joinpath(name).read_bytes())
        target.chmod(0o600)
        sources.append({'path': str(target), 'sha256': helper.sha(target.read_bytes())})
    pin = {'socket': policy['socket'], 'pid': guard_process.pid, 'startTicks': start, 'sources': sources,
           'executableSha256': helper.sha(proc.joinpath('exe').read_bytes()),
           'argvSha256': helper.sha(proc.joinpath('cmdline').read_bytes()),
           'holderId': policy['holderId'], 'lock': {'path': policy['lock'], 'device': lock_st.st_dev, 'inode': lock_st.st_ino}}
    accepted = {'version': 1, 'generation': generation, 'challenge': challenge, 'bootId': boot, 'guards': [pin],
                'journal': str(root / 'helper.json'), 'lifetimeMs': 120000}
    policy_file = root / 'accepted.json'
    policy_file.write_bytes(helper.canonical(accepted))
    policy_file.chmod(0o600)
    challenge_file.with_suffix('.control.json').write_text(json.dumps(
        {'root': str(root), 'freeze': str(group / 'cgroup.freeze'), 'lock': policy['lock'], 'guardPid': guard_process.pid}))
    code = helper.serve(policy_path=policy_file, owner_uid=os.getuid(), trusted_root=root)
finally:
    if code:
        # Simulate broker EOF while independent guard remains resident and owns
        # the original lock through Node's subsequent required DB disposal.
        sys.stdout.flush()
        os.close(1)
    cleanup_deadline = time.monotonic() + 5
    while not challenge_file.with_suffix('.cleanup').exists() and time.monotonic() < cleanup_deadline:
        time.sleep(0.01)
    guard_process.terminate()  # disposable local child ONLY, after DB cleanup
    try:
        guard_process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        guard_process.kill()
        guard_process.wait(timeout=3)
    if not os.environ.get('C3_KEEP_AUTHORITY_FIXTURE'):
        shutil.rmtree(root)
sys.exit(code)
