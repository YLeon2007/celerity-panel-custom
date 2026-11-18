"""Characterize installed PROD attach/observe and runner with synthetic boot IDs.

Only fixed helper methods are loaded; guard, SSH, systemd and physical identity
are modeled inputs. Files, the original bundle writer and runner are real.
"""
import ast
import copy
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
import uuid

REPO = Path(__file__).resolve().parents[3]
HOLDER = REPO / 'scripts/production-topology-physical.py'
RUNNER = REPO / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
EFFECTS = REPO / 'scripts/test-node-isolation/original_effects.py'
CORE = REPO / 'scripts/prod-maintenance/authority_helper.py'
STATE = '/var/lib/celerity/production-physical'
OLD = '10000000-0000-4000-8000-000000000001'
NEW = '20000000-0000-4000-8000-000000000002'
OWNER = '30000000-0000-4000-8000-000000000003'
BOOT = '/proc/sys/kernel/random/boot_id'


def load_methods(root, policy, system):
    e = runpy.run_path(str(EFFECTS))
    c = runpy.run_path(str(CORE))
    prod = {'target': 'production', 'hostIdentity': 'lm1.infograd.online'}
    # The disposable directory may inherit a setgid worktree's group.
    fs = e['Files'](SimpleNamespace(root=root, uid=os.getuid(), gid=root.stat().st_gid))
    rooted = lambda fixed: root / fixed.lstrip('/')

    def check():
        c['need'](rooted(BOOT).read_text().strip() == policy['physical']['bootId'])

    ns = {k: c[k] for k in ('need', 'sha', 'canonical', 'decode', 'Refusal')}
    ns.update(e={**e, 'Files': lambda: fs, 'System': lambda: system}, p=policy, ROOT=STATE,
              check=check, physical=lambda: copy.deepcopy(policy['physical']), PROD=prod,
              Path=Path, uuid=uuid, ExitStack=ExitStack, time=time, raw=c['canonical'](policy),
              scope=SimpleNamespace(guards=()),
              os=SimpleNamespace(path=SimpleNamespace(lexists=lambda fixed: os.path.lexists(rooted(fixed)))))
    source = ast.parse(HOLDER.read_text())
    serve = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'serve')
    methods = [n for n in serve.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))
               and n.name in ('Holder', 'current', 'pristine', 'observation')]
    assert {n.name for n in methods} == {'Holder', 'current', 'pristine', 'observation'}
    exec(compile(ast.Module(body=[*methods], type_ignores=[]), str(HOLDER), 'exec'), ns)
    ns['holder'] = ns['Holder']()
    ns['holder'].deadline = time.monotonic() + 20
    return ns


def runner(root, policy, action):
    pairs = {
        'command': action, 'operation-id': 'fixture-operation', 'node-id': policy['nodeId'],
        'candidate-hash': 'sha256:' + 'c' * 64, 'backup-id': 'fixture-backup',
        'target-profile': policy['targetProfile'], 'execution-context': 'lm1.infograd.online',
        'attempt-id': 'fixture-attempt', 'generation': 'fixture-generation',
        'predecessor-generation': 'none', 'command-id': 'fixture-close',
    }
    args = [part for k, v in pairs.items() for part in ('--' + k, v)]
    return subprocess.run(['/bin/bash', str(RUNNER), *args], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=10, check=False,
                          env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'CELERITY_TOPOLOGY_ROOT': str(root)})


class SelectedGuestBlocker(unittest.TestCase):
    def test_real_original_attach_and_real_runner_refuse_cross_boot_for_both_profiles(self):
        for profile in ('xray-bridge', 'xray-main'):  # B then P
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(prefix='s3-guest-') as tmp:
                self.exercise(Path(tmp), profile)

    def exercise(self, root, profile):
        e = runpy.run_path(str(EFFECTS))

        def private_dir(path):
            current = root
            for part in path.relative_to(root).parts:
                current /= part
                current.mkdir(exist_ok=True, mode=0o700)

        def put(fixed, raw):
            p = root / fixed.lstrip('/')
            private_dir(p.parent)
            p.write_text(raw)
            p.chmod(0o600)

        def snapshot():
            return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_ino, p.stat().st_mode,
                                               p.stat().st_uid, p.stat().st_gid, p.stat().st_mtime_ns)
                    for p in root.rglob('*') if p.is_file() and p != root / BOOT[1:]}

        config, unit = e['profile_paths'](profile)
        put(config, '{}\n')
        put(unit, '[Service]\n# fixture only\n')
        put(BOOT, OLD + '\n')
        private_dir(root / STATE[1:])
        system = SimpleNamespace(unit=lambda service: {
            'Id': service, 'LoadState': 'loaded', 'FragmentPath': unit,
            'DropInPaths': '', 'ActiveState': 'inactive', 'UnitFileState': 'disabled',
            'Job': '', 'NeedDaemonReload': 'no',
        })
        policy = {
            'kind': 'node', 'nodeId': 'b' * 24 if profile == 'xray-bridge' else 'a' * 24,
            'targetProfile': profile, 'profiles': [profile], 'guards': [{'holderId': OLD}],
            'physical': {'bootId': OLD, 'machineId': 'd' * 32, 'sshHostKeySha256': 'e' * 64},
            'codePins': {'fixture': 'c' * 64}, 'maintenanceId': 'fixture',
            'endpoint': {'ip': '192.0.2.11', 'port': 222, 'username': 'root'},
            'oldBackend': {'instanceId': 'fixture', 'pid': 22, 'processStartTime': '1'},
        }
        original = load_methods(root, policy, system)
        policy['originalSnapshot'] = original['current'](profile)
        original['holder'].capture()
        held = original['holder'].bind(OWNER)
        accepted = {k: held[k] for k in ('epoch', 'bundleSha256', 'ownerGeneration')}
        pristine = snapshot()
        # Same boot with a new observer is the positive control, not reboot.
        same = load_methods(root, policy, system)
        self.assertTrue(same['observation']()['pristine'])
        self.assertEqual(same['holder'].attach(accepted), held)
        self.assertEqual(same['holder'].view(), held)
        self.assertEqual(snapshot(), pristine)

        # No runner journal is *not* a workaround. Even granting a synthetic
        # matching new boot/guard to observe, unchanged originals cannot attach.
        put(BOOT, NEW + '\n')
        next_policy = {**policy, 'physical': {**policy['physical'], 'bootId': NEW},
                       'guards': [{'holderId': NEW}]}
        stale = load_methods(root, policy, system)
        with self.assertRaises(stale['Refusal']):
            stale['observation']()
        for pin in (next_policy, {**policy, 'guards': next_policy['guards']}):
            guard_only = pin['physical']['bootId'] == OLD
            if guard_only:
                put(BOOT, OLD + '\n')
            repinned = load_methods(root, pin, system)
            self.assertTrue(repinned['observation']()['pristine'])
            self.assertEqual(repinned['observation']()['physical'], pin['physical'])
            with self.assertRaises(repinned['Refusal']):
                repinned['holder'].attach(accepted)
            self.assertIsNone(repinned['holder'].original)
            self.assertEqual(snapshot(), pristine)

        # Create authentic v2 history via the actual runner, not by editing JSON.
        put(BOOT, OLD + '\n')
        closed = runner(root, policy, 'close')
        self.assertEqual((closed.returncode, closed.stderr), (0, ''), closed)
        old_status = runner(root, policy, 'status')
        self.assertEqual((old_status.returncode, old_status.stderr), (0, ''), old_status)
        same = load_methods(root, policy, system)
        self.assertEqual(same['observation']()['journal']['bootId'], OLD)
        self.assertEqual(same['holder'].attach(accepted), held)
        before = snapshot()
        put(BOOT, NEW + '\n')
        repinned = load_methods(root, next_policy, system)
        with self.assertRaises(repinned['Refusal']):
            repinned['observation']()
        blocked = runner(root, policy, 'status')
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn('BOOT_CHANGED_UNCERTAIN', blocked.stderr)
        self.assertEqual(snapshot(), before)
