"""Blocker characterization, NOT clean classic launch acceptance.

Node exec/HTTP/proc resources, journals and five-node OFDs are real. Payload
namespaces, cgroups/freezer, root/SSH/systemd and DB settlement are SIMULATED.
No new activation authority or launcher is supplied by this test.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_irreversible_handback as ih
import test_coordinated_restore as ct


TARGET = r'''const fs = require('node:fs');
const http = require('node:http');
const settings = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
let count = 0;
const server = http.createServer((request, response) => {
  response.end(JSON.stringify({pid: process.pid, token: settings.token}));
  if (++count === 2) server.close(() => clearTimeout(deadline));
});
const deadline = setTimeout(() => {
  server.close(); process.exitCode = 74;
}, 10000);
server.listen(0, '127.0.0.1', () => {
  console.log(JSON.stringify({pid: process.pid, port: server.address().port}));
});
'''


def digest(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


@contextmanager
def actual_node():
    executable = shutil.which('node')
    if executable is None:
        raise AssertionError('Real Node executable required; do not skip acceptance')
    with tempfile.TemporaryDirectory(prefix='cc-target-') as root:
        root = Path(root)
        source, settings = root/'target.js', root/'settings.json'
        source.write_text(TARGET)
        token = os.urandom(32).hex()
        settings.write_text(json.dumps({'token': token}))
        child = subprocess.Popen([executable, str(source), str(settings)], cwd=root,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, close_fds=True,
                                 env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        try:
            assert child.stdout is not None
            if not select.select([child.stdout], [], [], 5)[0]:
                raise AssertionError('Real Node HTTP startup timed out')
            hello = json.loads(child.stdout.readline())
            assert hello['pid'] == child.pid
            invoked, running = os.stat(executable), os.stat(f'/proc/{child.pid}/exe')
            assert (invoked.st_dev, invoked.st_ino) == (running.st_dev, running.st_ino)
            start = ct.load_c().proc_start(child.pid)
            root_stat = os.stat(f'/proc/{child.pid}/root')
            cwd_stat = os.stat(f'/proc/{child.pid}/cwd')
            evidence = {'pid': child.pid, 'start': start,
                        'rootDeviceInode': [root_stat.st_dev, root_stat.st_ino],
                        'cwdDeviceInode': [cwd_stat.st_dev, cwd_stat.st_ino],
                        'cgroup': Path(f'/proc/{child.pid}/cgroup').read_text().strip(),
                        'executable': str(Path(executable).resolve()),
                        'executableSha256': digest(executable),
                        'sourceSha256': digest(source), 'settingsSha256': digest(settings),
                        'taskCount': len(list(Path(f'/proc/{child.pid}/task').iterdir())),
                        'fdCount': len(list(Path(f'/proc/{child.pid}/fd').iterdir())),
                        'physicalAuthority': 'SIMULATED_NOT_A_LAUNCHER',
                        'servingIsOnlyDisposableTarget': True}
            def request():
                conn = http.client.HTTPConnection('127.0.0.1', hello['port'], timeout=2)
                try:
                    conn.request('GET', '/')
                    response = conn.getresponse()
                    assert response.status == 200
                    assert json.loads(response.read()) == {'pid': child.pid, 'token': token}
                finally:
                    conn.close()
            request()
            yield child, evidence
            request()
            out, err = child.communicate(timeout=5)
            assert (child.returncode, out, err) == (0, b'', b'')
            print('ACTUAL_NODE_CHARACTERIZATION ' + json.dumps(evidence, sort_keys=True))
        finally:
            if child.poll() is None:
                child.kill()  # exact owned disposable cleanup, never production rollback
            child.communicate(timeout=3)


def expose_actual_resources(kernel, fence, pid, resource):
    backend = next(c for c in fence.expected['containers']
                   if c['cgroup'] == fence.expected['backend'])
    proc = kernel.proc/str(backend['init']['pid'])
    # Only the selected live proc inventory is real. Other eligibility facts are
    # the existing explicitly simulated sealed-payload fixture, not the target.
    names = ('task',) if resource == 'tasks' else ('fd', 'fdinfo')
    for name in names:
        shutil.rmtree(proc/name)
        (proc/name).symlink_to(f'/proc/{pid}/{name}', target_is_directory=True)


class CleanReturnBlockerTests(unittest.TestCase):
    build = ih.BoundedActivationTests.build
    put_pid = ih.BoundedActivationTests.put_pid

    def test_actual_node_threads_refuse_without_changing_original_hold(self):
        self.resource_refusal('tasks', 'multi-task')

    def test_actual_node_fds_refuse_even_with_modeled_single_task(self):
        self.resource_refusal('fds', 'descriptor')

    def resource_refusal(self, resource, reason):
        with actual_node() as (child, evidence), tempfile.TemporaryDirectory(prefix='cc-guard-') as root:
            self.assertGreater(evidence['taskCount'], 1)
            self.assertGreater(evidence['fdCount'], 0)
            _, kernel, fence = self.build(root)
            fence.close_candidate(fence.owner)
            expose_actual_resources(kernel, fence, child.pid, resource)
            before = Path(root, 'journal/hold.json').read_bytes()
            calls = list(kernel.calls)
            with self.assertRaisesRegex(RuntimeError, reason):
                fence.activate_classic(fence.owner, 'a'*64)
            self.assertEqual(Path(root, 'journal/hold.json').read_bytes(), before)
            self.assertEqual(kernel.calls, calls)
            self.assertNotIn('classicActivation', fence.expected)
            for group in fence.frozen:
                self.assertEqual((kernel.group(group)/'cgroup.freeze').read_text(), '1')
            with self.assertRaisesRegex(RuntimeError, 'candidate closure'):
                fence.restore(fence.owner)
            self.assertIsNone(child.poll())

    def test_actual_five_node_precommit_refusal_preserves_no_commit_and_sticky_holds(self):
        c = ct.load_c()
        with actual_node() as (target, _), ct.cfixture(c) as f:
            original_spawn = f.spawn
            def spawn(node):
                if node != c.SHARED_NODE:
                    return original_spawn(node)
                node_fixture = f.fixtures[-1]
                old = "shared=SimpleNamespace(check_hold=lambda *_:{'candidateClosure':{'group':'SIMULATED'}} if fs.read_json('/fixture-live.json')['candidateFrozen'] else {})"
                new = '''import test_irreversible_handback as ih
import test_clean_classic_return_gate as gate
case=ih.BoundedActivationTests()
model=root/'activation-model'; model.mkdir()
_,kernel,fence=case.build(model)
fence.close_candidate(fence.owner)
gate.expose_actual_resources(kernel,fence,TARGET_PID,'tasks')
def shared_check(*args, **kw):
 if kw.get('command') == 'prepare-classic':
  try: kernel.assert_classic_activation_safe(fence.expected)
  except RuntimeError as error:
   (root/'actual-resource-refusal').write_text(str(error))
   raise
 return {'candidateClosure':{'group':'SIMULATED'}} if fs.read_json('/fixture-live.json')['candidateFrozen'] else {}
shared=SimpleNamespace(check_hold=shared_check)'''.replace('TARGET_PID', str(target.pid))
                code = ct.CHILD.replace(old, new)
                self.assertNotEqual(code, ct.CHILD)
                child = subprocess.Popen([sys.executable, '-B', '-c', code, str(node_fixture.root)],
                    cwd=ct.HERE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, bufsize=0)
                f.children.append(child)
                return child
            held = c.Coordinator(f.config, f.fs, spawn, origin=f.origin)
            with self.assertRaises(RuntimeError) as failed, held.restore_scope():
                # These are the actual five-node outer and descendant runner
                # flocks, not cooperative booleans or historical receipts.
                def assert_locked():
                    for node_fixture in f.fixtures:
                        for path in (ct.t.n.OUTER_LOCK, *(ct.t.n.runner_lock(p) for p in node_fixture.writer.profiles)):
                            with open(node_fixture.path(path), 'rb') as competitor:
                                with self.assertRaises(BlockingIOError):
                                    fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                assert_locked()
                with self.assertRaises(RuntimeError):
                    held.commit_handoff(ih.settlement_proof(f, c))
                self.assertIn('multi-task', (f.fixtures[-1].root/'actual-resource-refusal').read_text())
                self.assertFalse(held.commit_attempted)
                self.assertIsNone(held.commit_sha)
                self.assertFalse(held.activation_attempted)
                self.assertTrue(f.fs.absent(c.COMMIT))
                self.assertTrue(f.fs.absent(c.ACTIVATION))
                # The failed peer exits, so its scope has unwound; never claim
                # all OFDs survive peer death. The other FOUR remain held now.
                for node_fixture in f.fixtures[:-1]:
                    for profile in node_fixture.writer.profiles:
                        with open(node_fixture.path(ct.t.n.runner_lock(profile)), 'rb') as competitor:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # Scope exit fails closed on the known dead shared peer.
            self.assertEqual(getattr(failed.exception, 'code'), 'COORDINATED_RESTORE_UNKNOWN_RETAINED')
            model = f.fixtures[-1].root/'activation-model'
            row = json.loads((model/'journal/hold.json').read_bytes())
            self.assertNotIn('classicActivation', row['expected'])
            for group in row['frozen']:
                self.assertEqual((model/'cg'/group.lstrip('/')/'cgroup.freeze').read_text(), '1')
            for node_fixture in f.fixtures:
                self.assertEqual(node_fixture.fs.read_json(ct.t.n.ADMISSION)['state'], 'closed')


if __name__ == '__main__':
    unittest.main()
