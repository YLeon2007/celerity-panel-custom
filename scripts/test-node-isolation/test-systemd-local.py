#!/usr/bin/python3 -I
"""Explicit LOCAL root-only systemd/cgroup probe; never touches SSH or /run/sshd.

Run via /usr/local/bin/hermes-admin /usr/bin/python3 -I <absolute script>.
Only random transient units, their private /run directory and mission scratch
files are changed. This is kernel/systemd evidence, NOT deployed SSH evidence.
"""
import configparser
import json
import os
import pathlib
import subprocess
import tempfile
import time
import uuid


def run(*args):
    return subprocess.run(args, check=True, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=20).stdout


def wait_for(predicate):
    deadline = time.monotonic() + 8
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError('local probe deadline')
        time.sleep(0.05)


def main():
    assert os.geteuid() == 0, 'explicit root invocation required'
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(pathlib.Path(__file__).with_name('c3-test-maintenance-sshd.service'))
    service = cfg['Service']
    assert service['RuntimeDirectory'] == 'sshd'
    tag = 'c3-local-' + uuid.uuid4().hex
    old, maint = tag + '-old.service', tag + '-maint.service'
    runtime = pathlib.Path('/run', tag)
    cgfd = None
    dropdir = pathlib.Path('/run/systemd/system', old + '.d')
    dropfile = dropdir / 'c3-test-runtime.conf'
    evidence: dict = {'scope': 'local-isolated-systemd-not-deployed-ssh', 'tag': tag,
                'systemd': run('/usr/bin/systemctl', '--version').splitlines()[0]}
    with tempfile.TemporaryDirectory(prefix=tag + '-', dir='/home/leon/.hermes/cache/scratch') as scratch:
        child_file = pathlib.Path(scratch, 'child.json')
        def start(unit, process=False):
            args = ['/usr/bin/systemd-run', '--quiet', '--collect', '--unit=' + unit,
                    '--property=Type=exec', '--property=RuntimeDirectory=' + tag,
                    '--property=RuntimeDirectoryMode=' + service['RuntimeDirectoryMode'],
                    '--property=RuntimeDirectoryPreserve=' + ('no' if process else service['RuntimeDirectoryPreserve']),
                    '--property=User=' + service['User'], '--property=Group=' + service['Group'],
                    '--property=KillMode=' + ('process' if process else 'control-group')]
            if process:
                code = ('import os,pathlib,time,json; p=os.fork(); '
                        'pathlib.Path(' + repr(str(child_file)) + ').write_text(json.dumps({"pid":os.getpid()})) if p==0 else None; '
                        'time.sleep(120)')
                args += ['/usr/bin/python3', '-I', '-c', code]
            else:
                args += ['/usr/bin/sleep', '120']
            run(*args)
        def stop(unit):
            run('/usr/bin/systemctl', 'stop', '--', unit)
        def stat_runtime():
            st = runtime.stat()
            assert (st.st_uid, st.st_gid, st.st_mode & 0o777) == (0, 0, 0o755)
            return st.st_ino
        try:
            start(old, process=True)
            wait_for(child_file.exists)
            child = json.loads(child_file.read_text())['pid']
            group = run('/usr/bin/systemctl', 'show', '--value', '--property=ControlGroup', '--', old).strip()
            assert group == '/system.slice/' + old
            cgfd = os.open('/sys/fs/cgroup' + group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            pin = os.fstat(cgfd)
            start(maint)
            inode = stat_runtime()
            before = run('/usr/bin/systemctl', 'show', '--value', '--property=RuntimeDirectoryPreserve', '--', old).strip()
            assert before == 'no'
            dropdir.mkdir()
            dropfile.write_bytes(pathlib.Path(__file__).with_name('normal-ssh-runtime.conf').read_bytes())
            run('/usr/bin/systemctl', 'daemon-reload')
            after = run('/usr/bin/systemctl', 'show', '--value', '--property=RuntimeDirectoryPreserve', '--', old).strip()
            assert after == 'yes'
            evidence['oldPreservationOverrideWithoutRestart'] = {'before': before, 'after': after}
            run('/usr/bin/systemctl', 'mask', '--runtime', '--', old)
            run('/usr/bin/systemctl', 'daemon-reload')
            stop(old)
            assert stat_runtime() == inode, 'old unit removed shared runtime directory'
            evidence['sharedDirectorySurvivedOldStop'] = True
            assert pathlib.Path('/proc', str(child)).exists(), 'probe did not retain a KillMode=process child'
            assert os.fstat(cgfd).st_ino == pin.st_ino
            kill = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=cgfd)
            try:
                assert os.write(kill, b'1\n') == 2
            finally:
                os.close(kill)
            def joined():
                events = pathlib.Path('/sys/fs/cgroup' + group, 'cgroup.events')
                return not events.exists() or 'populated 0' in events.read_text()
            wait_for(joined)
            evidence['processKillModeChildJoinedViaPinnedCgroupKill'] = True
            assert stat_runtime() == inode
            stop(maint)
            stat_runtime()
            evidence['preservedAfterLastStop'] = True
            runtime.rmdir()  # Own empty private path only; emulate an empty /run at boot.
            start(maint)
            stat_runtime()
            evidence['maintenanceAloneCreatedDirectory'] = True
            run('/usr/bin/systemctl', 'restart', '--', maint)
            stat_runtime()
            evidence['maintenanceRestartCreatedDirectory'] = True
        finally:
            if cgfd is not None:
                try:
                    cleanup_kill = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=cgfd)
                    try:
                        os.write(cleanup_kill, b'1\n')
                    finally:
                        os.close(cleanup_kill)
                except FileNotFoundError:
                    pass
                finally:
                    os.close(cgfd)
            for unit in (old, maint):
                subprocess.run(['/usr/bin/systemctl', 'stop', '--', unit], capture_output=True, timeout=20)
            if dropfile.exists():
                dropfile.unlink()
                dropdir.rmdir()
            run('/usr/bin/systemctl', 'unmask', '--runtime', '--', old)
            run('/usr/bin/systemctl', 'daemon-reload')
        if runtime.exists():
            runtime.rmdir()  # RuntimeDirectoryPreserve=yes intentionally leaves it.
        assert not runtime.exists(), 'private runtime cleanup failed'
        assert not dropdir.exists(), 'private drop-in cleanup failed'
        assert not pathlib.Path('/run/systemd/system', old).is_symlink(), 'private mask cleanup failed'
        states = {unit: run('/usr/bin/systemctl', 'show', '--value', '--property=ActiveState', '--', unit).strip()
                  for unit in (old, maint)}
        assert set(states.values()) <= {'inactive', 'failed'}
        evidence['cleanup'] = {'runtimeDirectoryAbsent': True, 'privateDropInAndMaskAbsent': True, 'unitStates': states}
    print(json.dumps(evidence, sort_keys=True))


if __name__ == '__main__':
    main()
