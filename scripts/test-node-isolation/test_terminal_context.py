"""B1 regression: real CLOSE-only runner journals, actual Holder terminal path.
Run with python -I -B. Source is relative to this test (no foreign checkout).
C3_CONTEXT_EVIDENCE and TMPDIR must name disposable owned directories.
Only physical/exclusion identity and systemd observation are modeled; journal,
file snapshots, Holder checkpoint/read_current/prepare/view and flock are real.
"""
import ast
import copy
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
import uuid

REPO = Path(__file__).absolute().parents[2]
CONTEXTS = ('test.infograd.online', 'lm1.infograd.online')
RUNNER_SHA = 'b0a17dd8bc4581ecb02b6d791ff98cd90b8c7159ffb9d77d35f2bc13ecb148cf'


def read_source(path):
    """No foreign atime, symlink traversal or bytecode cache."""
    parts = path.parts[1:]
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOATIME | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(leaf, 'rb') as stream:
            return stream.read()
    finally:
        os.close(fd)


class TerminalContextTests(unittest.TestCase):
    def test_real_close_contexts_through_holder(self):
        os.umask(0o077)
        evidence = Path(os.environ['C3_CONTEXT_EVIDENCE']).absolute()
        evidence.mkdir(parents=True, exist_ok=True)
        effects_path = REPO / 'scripts/test-node-isolation/original_effects.py'
        holder_path = REPO / 'scripts/production-topology-physical.py'
        runner_path = REPO / 'src/modules/relay-l2tp/node-artifacts/topology/runner.sh'
        effects, physical, runner = [read_source(p) for p in (effects_path, holder_path, runner_path)]
        self.assertEqual(hashlib.sha256(runner).hexdigest(), RUNNER_SHA)
        e = {'__name__': 'context_regression_effects'}
        exec(compile(effects, str(effects_path), 'exec'), e)
        self.assertEqual(e['OriginalEffects'].execution_context, CONTEXTS[0])
        serve = next(n for n in ast.parse(physical).body if isinstance(n, ast.FunctionDef) and n.name == 'serve')
        holder_ast = next(n for n in serve.body if isinstance(n, ast.ClassDef) and n.name == 'Holder')
        results = []
        for context in CONTEXTS:
            for wrong in (False, True):
                label = ('test' if context == CONTEXTS[0] else 'prod') + ('-wrong' if wrong else '-valid')
                with self.subTest(case=label), tempfile.TemporaryDirectory(prefix='context-', dir=os.environ['TMPDIR']) as directory:
                    root = Path(directory)
                    def put(path, data):
                        target = root / path.lstrip('/')
                        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        target.write_bytes(data)
                        target.chmod(0o600)
                    boot = '01234567-89ab-cdef-0123-456789abcdef'
                    node, profile = '6ab18d9c63913ebd4a917670', 'xray-bridge'
                    put('/proc/sys/kernel/random/boot_id', (boot + '\n').encode())
                    (root / 'var/lib').mkdir(parents=True, mode=0o700)
                    values = {'command': 'close', 'operation-id': 'operation-1', 'node-id': node,
                              'candidate-hash': 'sha256:' + 'e' * 64, 'backup-id': 'backup-1',
                              'target-profile': profile, 'execution-context': context, 'attempt-id': 'attempt-1',
                              'generation': 'generation-1', 'predecessor-generation': 'none', 'command-id': 'close-1'}
                    # Execute exactly the bytes just pinned, not an external mutable runner path.
                    put('/runner.sh', runner)
                    argv = ['/bin/bash', str(root / 'runner.sh'), *[v for k, x in values.items() for v in ('--' + k, x)]]
                    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                              'CELERITY_TOPOLOGY_ROOT': str(root), 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
                              'TMPDIR': str(root)}) as child:
                        try:
                            stdout, stderr = child.communicate(timeout=10)
                        except BaseException:
                            child.kill()
                            child.communicate(timeout=5)
                            raise
                        invocation = {'argv': argv, 'runnerSha256': RUNNER_SHA, 'pid': child.pid,
                                      'exitCode': child.returncode, 'stdout': stdout.decode(),
                                      'stderr': stderr.decode(), 'joined': child.poll() is not None}
                    (evidence / (label + '-runner.json')).write_text(json.dumps(invocation, indent=2) + '\n')
                    self.assertEqual((child.returncode, stderr), (0, b''), invocation)
                    fixture = SimpleNamespace(root=root, uid=os.getuid(), gid=os.getgid())
                    fs = e['Files'](fixture)
                    jp = e['runner_journal'](profile)
                    raw = fs.read(jp)[0]
                    (evidence / (label + '-genuine-journal.json')).write_bytes(raw)
                    if wrong:
                        journal = json.loads(raw)
                        record = journal['generations']['generation-1']
                        other = CONTEXTS[1 - CONTEXTS.index(context)]
                        record['binding']['executionContext'] = other
                        record['commands']['close-1']['receipt']['executionContext'] = other
                        raw = e['canonical'](journal)
                        put(jp, raw)
                    (evidence / (label + '-consumed-journal.json')).write_bytes(raw)
                    config, unit = e['profile_paths'](profile)
                    put(config, b'{}\n')
                    put(unit, b'[Service]\n# disposable snapshot fixture\n')
                    state = {'Id': e['service_name'](profile), 'LoadState': 'loaded', 'FragmentPath': unit,
                             'DropInPaths': '', 'ActiveState': 'inactive', 'UnitFileState': 'disabled',
                             'Job': '', 'NeedDaemonReload': 'no'}
                    checkpoints = []
                    def check():
                        # Modeled already-held physical exclusion; no attach, SSH or native job.
                        checkpoints.append('modeled-held-identity')
                    def pristine():
                        raise AssertionError('terminal path must not use pristine/cold recovery')
                    ns = {'e': e, 'p': {'targetProfile': profile, 'profiles': [profile]}, 'check': check,
                          'sha': e['sha'], 'canonical': e['canonical'], 'ROOT': '/fixture-holder',
                          'need': lambda ok: e['need'](ok, 'HOLDER_CHECK_RETAINED'), 'time': time,
                          'os': SimpleNamespace(path=SimpleNamespace(lexists=lambda p: os.path.lexists(root / p.lstrip('/')))),
                          'pristine': pristine, 'uuid': uuid, 'ExitStack': ExitStack}
                    exec(compile(ast.fix_missing_locations(ast.Module(body=[holder_ast], type_ignores=[])),
                                 str(holder_path), 'exec'), ns)
                    self.assertEqual(ns['Holder'].execution_context, CONTEXTS[1])
                    h = ns['Holder'].__new__(ns['Holder'])
                    h.execution_context, h.fs, h.fixture = context, fs, fixture
                    h.system = SimpleNamespace(unit=lambda service: copy.deepcopy(state))
                    h.physical, h.locks, h.deadline = {'nodeId': node, 'bootId': boot}, (), time.monotonic() + 25
                    h.epoch, h.generation = '11111111-2222-4333-8444-555555555555', 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
                    h.prepared, h.intent, h.restored = None, None, False
                    h.original = {'profiles': {profile: h.snapshot(profile)}}
                    h.bundle = e['canonical'](h.original)
                    put('/fixture-holder/originals.json', h.bundle)
                    put('/fixture-holder/binding.json', e['canonical']({'epoch': h.epoch, 'bundleSha256': e['sha'](h.bundle),
                                                                      'ownerGeneration': h.generation}))
                    ns['current'] = lambda p: {'source': 'node-readback', 'configSha256': h.snapshot(p)['files']['config']['sha256'],
                                              'unitSha256': h.snapshot(p)['files']['unit']['sha256'],
                                              'serviceActive': state['ActiveState'], 'serviceEnabled': state['UnitFileState']}
                    expected = {**h.snapshot_pin(h.snapshot(profile)), 'journalSha256': e['sha'](raw)}
                    outcome = {'case': label, 'context': context, 'nestedMismatch': wrong, 'runner': invocation,
                               'journalSha256': e['sha'](raw), 'actualMethods': ['checkpoint', 'snapshot', 'read_current', 'prepare', 'view']}
                    with ExitStack() as stack:
                        h.runner = stack
                        for method in ('read_current', 'prepare'):
                            try:
                                if method == 'read_current':
                                    self.assertEqual(h.read_current(), expected)
                                else:
                                    view = h.prepare({'epoch': h.epoch, 'ownerGeneration': h.generation, 'current': expected})
                                    self.assertEqual(h.prepared, expected)
                                    self.assertEqual(view['phase'], 'captured-held')
                                outcome[method] = 'PASS'
                            except e['Refusal'] as ex:
                                outcome[method] = str(ex)
                    outcome['checkpoints'] = len(checkpoints)
                    outcome['locksClosed'] = not stack._exit_callbacks
                    results.append(outcome)
                    (evidence / 'cases.json').write_text(json.dumps(results, indent=2) + '\n')
                    wanted = 'RUNNER_UNKNOWN_RETAINED' if wrong else 'PASS'
                    self.assertEqual([outcome[k] for k in ('read_current', 'prepare')], [wanted, wanted])
                    self.assertGreater(len(checkpoints), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
