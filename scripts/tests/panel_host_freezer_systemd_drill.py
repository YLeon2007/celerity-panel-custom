#!/usr/bin/env python3
"""LOCAL disposable automatic-restart/socket-start refusal drill; never TEST."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess as sp
import sys
import time
import uuid

P = Path(sys.argv[1]).resolve()
assert os.geteuid() == 0 and str(P).startswith('/home/leon/.hermes/cache/scratch/') and not P.exists()
P.mkdir(mode=0o700)
spec = importlib.util.spec_from_file_location('freezer', Path(__file__).parents[1] / 'panel-host-freezer.py')
assert spec is not None and spec.loader is not None
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
assert Path('/etc/machine-id').read_text().strip() != m.TEST_MACHINE_ID, 'local drill must not touch TEST'
owner = str(uuid.uuid4())
unit = 'c3-freezer-relaunch-drill-' + str(os.getpid()) + '.service'
barrier = m.SystemdRelaunchBarrier([unit])
kernel = m.LinuxKernel()
expected = {'groups': {}}
rows = []
success = False


def emit(event, **data):
    rows.append({'event': event, **data})
    print(json.dumps(rows[-1]), flush=True)


def persist(phase, **args):
    emit(phase, **args)




try:
    code = f"open({str(P / 'starts')!r},'a').write('started\\n'); __import__('time').sleep(120)"
    helper = f"import time\nwhile True:\n open({str(P / 'helper-ticks')!r}, 'a').write('tick\\n'); time.sleep(.02)\n"
    (P / 'helper.py').write_text(helper)
    code = "import subprocess\nsubprocess.Popen(['/usr/bin/python3', " + repr(str(P / 'helper.py')) + "])\n" + code
    (P / 'worker.py').write_text(code)
    unit_file = Path('/run/systemd/system') / unit
    unit_content = '[Service]\nExecStart=/usr/bin/python3 ' + str(P / 'worker.py') + '\nRestart=always\nRestartSec=0.3s\nKillMode=process\n'
    fd = os.open(unit_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(unit_content)
    barrier.run('daemon-reload')
    barrier.run('start', unit)
    end = time.monotonic() + 5
    while not (P / 'starts').exists() and time.monotonic() < end:
        time.sleep(.02)
    assert (P / 'starts').read_text() == 'started\n'
    expected['supervisors'] = barrier.original()
    original = expected['supervisors'][unit]
    barrier.prepare(expected, kernel, owner, persist)
    barrier.restore(expected, kernel, persist)
    assert barrier.original() == expected['supervisors'] and 'relaunch' not in expected
    emit('exact-nondestructive-supervisor-restore', original=original)
    barrier.prepare(expected, kernel, owner, persist)
    oldpid = int(barrier.run('show', unit, '--property=MainPID', '--value').strip())
    end = time.monotonic() + 3
    while not (P / 'helper-ticks').exists() and time.monotonic() < end:
        time.sleep(.02)
    kernel.freeze(original['ControlGroup'], True)
    ticks_before = (P / 'helper-ticks').stat().st_size
    os.kill(oldpid, signal.SIGKILL)
    time.sleep(1)
    state = barrier.show(unit)
    assert state['Restart'] == 'no' and (P / 'starts').read_text() == 'started\n'
    assert (P / 'helper-ticks').stat().st_size == ticks_before, 'accepted helper resumed on main PID loss'
    assert m.events(kernel.group(original['ControlGroup']) / 'cgroup.events')['frozen'] == 1
    # Manual start also exercises the manager's socket/dependency activation
    # path: the negated /run condition must refuse BEFORE PID1 forks into a
    # still-frozen service cgroup. ExecCondition=false alone is insufficient.
    barrier.run('start', unit)
    time.sleep(.2)
    state = barrier.show(unit)
    assert state['ActiveState'] in ('inactive', 'failed')
    assert '/usr/bin/false' in state['ExecCondition']
    assert (P / 'helper-ticks').stat().st_size == ticks_before, 'accepted helper resumed on activation'
    assert m.events(kernel.group(original['ControlGroup']) / 'cgroup.events')['frozen'] == 1
    assert (P / 'starts').read_text() == 'started\n'
    emit('automatic-restart-and-activation-refused', state=state, startMarkerCount=1,
         conditions=barrier.conditions(unit), acceptedHelperFrozen=True,
         helperHeartbeatGrowth=(P / 'helper-ticks').stat().st_size - ticks_before,
         frozen=m.events(kernel.group(original['ControlGroup']) / 'cgroup.events')['frozen'],
         managerResponsive=True)
    success = True
finally:
    # Only a fresh disposable unit is cleaned up. This is NOT production restore
    # or permission to thaw after an executor/daemon identity was lost.
    if 'original' in locals():
        group = kernel.group(original['ControlGroup'])
        if group.exists():
            (group / 'cgroup.kill').write_text('1')
    sp.run(['systemctl', 'stop', unit], timeout=10, capture_output=True)
    for row in expected.get('relaunch', {}).get('dropins', []):
        p = Path(row['path'])
        if p.exists():
            assert p.read_text() == barrier.CONTENT
            p.unlink()
            if row['createdDirectory']:
                p.parent.rmdir()
    if 'unit_file' in locals() and unit_file.exists():
        assert unit_file.read_text() == unit_content
        unit_file.unlink()
    barrier.run('daemon-reload')
    sp.run(['systemctl', 'reset-failed', unit], timeout=10, capture_output=True)
    emit('cleanup', success=success, serviceState=barrier.show(unit).get('ActiveState'),
         dropinExists=(Path('/run/systemd/system') / (unit + '.d') / '90-c3-test-host-isolation.conf').exists())
    (P / 'result.json').write_text(json.dumps(rows, indent=2))
    for p in P.iterdir():
        os.chown(p, 1000, 1000)
    os.chown(P, 1000, 1000)
if not success:
    sys.exit(1)
