#!/usr/bin/env python3
"""Local assembled-test adapter: real isolation dispatch + real fenced runner.

Host/UID/kernel/systemd/SSH authority is deliberately SIMULATED through the
existing test adapter. This executable is never installed or used in production.
No fake success replies are returned for runner commands or Xray user RPC.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
helper, root_name, command, node_id = sys.argv[1:]
helper = Path(helper).resolve()
spec = importlib.util.spec_from_file_location('dispatch_test_isolation', helper.with_name('test_isolation.py'))
assert spec is not None and spec.loader is not None
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)

m = fixtures.m
# Assert the assembly uses the actual accepted helper beside its fixtures.
assert Path(m.__file__).resolve() == helper
root = Path(root_name).resolve()
source = helper.parents[2] / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
plan = fixtures.PlanTests().plan()
assert node_id == '6ab18adc63913ebd4a917471'
plan['nodeId'] = node_id
plan['bootId'] = (root / 'proc/sys/kernel/random/boot_id').read_text().strip()
plan['runnerSha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
directory = root / 'node-isolation-simulated-authority'
directory.mkdir(mode=0o700, exist_ok=True)
engine = m.Engine(directory, plan, fixtures.EngineTests.FixtureHost())
real_run = subprocess.run

def actual_runner(argv, **kwargs):
    assert argv[:2] == ['/bin/bash', m.RUNNER]
    env = {**kwargs.pop('env'), 'CELERITY_TOPOLOGY_ROOT': str(root)}
    return real_run(['unshare', '--user', '--map-root-user', '/bin/bash', str(source), *argv[2:]],
                    env=env, timeout=40, **kwargs)

fd = os.open(directory / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if engine.read() is None:
        fixtures.fixture_hold(engine)
    payload = sys.stdin.buffer.read(4194305)
    m.subprocess.run = actual_runner
    sys.stdout.buffer.write(engine.dispatch(command, payload, fd))
except m.Refusal as error:
    print(json.dumps({'ok': False, 'code': str(error), 'ownershipRetained': True}), file=sys.stderr)
    raise SystemExit(75)
finally:
    os.close(fd)
