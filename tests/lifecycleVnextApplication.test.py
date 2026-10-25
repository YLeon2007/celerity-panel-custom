#!/usr/bin/env python3
"""Actual tracked index.js, disposable Mongo, optional REAL Redis; never emulate it.

If Redis is absent, degraded Mongo/HTTP evidence is still exercised, and a named
acceptance test FAILS. That result is not a successful Mongo/Redis vertical slice.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lifecycle_tests', ROOT / 'tests/lifecycleVnextSupervisor.test.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
EVIDENCE = Path(os.environ['C3_REAL_EVIDENCE'])
NODE = os.environ['C3_NODE']


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def http(port, path='/health'):
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}{path}', timeout=1) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def until(fn, seconds=30):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            return fn()
        except (OSError, AssertionError, subprocess.CalledProcessError) as e:
            last = e
            time.sleep(.1)
    raise AssertionError('actual readiness timeout: ' + str(last))


def inventory(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob('*')) if p.is_file()}


class ActualAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix='vnext-actual-', dir=os.environ['TMPDIR']))
        cls.peers = []
        cls.addClassCleanup(cls.stop_peers)
        cls.app = cls.dir / 'app'
        cls.app.mkdir()
        names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
        for name in filter(None, names):
            src, dst = ROOT / name, cls.app / name
            if not src.is_file():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            dst.chmod(0o444)
        cls.before = inventory(cls.app)
        (EVIDENCE / 'executed-source-sha256.json').write_text(json.dumps(cls.before, indent=2))
        for path in sorted(cls.app.rglob('*'), reverse=True):
            if path.is_dir():
                path.chmod(0o555)
        cls.app.chmod(0o555)
        cls.mongo_port, cls.redis_port, cls.http_port = free_port(), free_port(), free_port()
        cls.dbdir = cls.dir / 'mongo'
        cls.dbdir.mkdir()
        cls.mongo = cls.peer(os.environ['C3_MONGOD'], ['--dbpath', str(cls.dbdir), '--port', str(cls.mongo_port),
                '--bind_ip', '127.0.0.1', '--wiredTigerCacheSizeGB', '0.25',
                '--setParameter', 'diagnosticDataCollectionEnabled=false',
                '--setParameter', 'maxIndexBuildMemoryUsageMegabytes=64'], 'mongo')
        cls.uri = f'mongodb://127.0.0.1:{cls.mongo_port}/vnext_local'
        until(lambda: cls.mongo_command('console.log(await db.command({ping:1}));'))
        cls.has_redis = bool(os.environ.get('C3_REDIS_SERVER'))
        if cls.has_redis:
            cls.redis = cls.peer(os.environ['C3_REDIS_SERVER'], ['--bind', '127.0.0.1', '--port', str(cls.redis_port),
                    '--save', '', '--appendonly', 'no', '--maxmemory', '32mb', '--dir', str(cls.dir)], 'redis')
            until(lambda: subprocess.check_output([NODE, '-e',
                "const R=require('ioredis');const r=new R(process.argv[1],{retryStrategy:()=>null});r.ping().then(x=>{console.log(x);r.disconnect()}).catch(()=>process.exit(1))",
                f'redis://127.0.0.1:{cls.redis_port}'], env=os.environ, timeout=3))
        cls.settings = cls.dir / 'settings.json'
        settings = dict(version=1, context='test.infograd.online', stateDirectory=str(cls.dir / 'state'),
            listenAddress='127.0.0.1', environment=dict(PANEL_DOMAIN='test.infograd.online',
            ACME_EMAIL='local@example.invalid', ENCRYPTION_KEY='e'*32, SESSION_SECRET='s'*32,
            MONGO_URI=cls.uri, REDIS_URL=f'redis://127.0.0.1:{cls.redis_port}', USE_CADDY='true', PORT=str(cls.http_port),
            **{k:'false' for k in ['L2TP_EXECUTION_ENABLED', 'L2TP_MIGRATIONS_ENABLED', 'TOPOLOGY_TEST_EXECUTION_ENABLED',
                'TOPOLOGY_PRODUCTION_EXECUTION_ENABLED', 'L2TP_PRODUCTION_EXECUTION_ENABLED']}))
        cls.settings.write_text(json.dumps(settings))
        cls.settings.chmod(0o600)
        (EVIDENCE / 'fixture.json').write_text(json.dumps(dict(mongo='8.0.16 standalone loopback, NOT TEST Mongo7 rs0',
            redisAvailable=cls.has_redis, caddyAvailable=False, authority='SIMULATED_LOCAL_TEMPORARY',
            rollbackArtifact='same tracked artifact: not genuine previous-version rollback',
            terminalDispatch=False, fixturePath=str(cls.dir)), indent=2))

    @classmethod
    def peer(cls, binary, args, name):
        with open(EVIDENCE / (name + '.log'), 'ab', buffering=0) as log:
            p = subprocess.Popen([binary, *args], cwd=cls.dir, stdout=log, stderr=log,
                env=dict(os.environ, OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1'))
            # Own every spawned, unreaped direct child before closing the log or pinning.
            owned = len(cls.peers)
            cls.peers.append((name, p, None))
        fd = os.pidfd_open(p.pid)
        cls.peers[owned] = (name, p, fd)
        return p

    @classmethod
    def stop_peers(cls):
        result, errors = [], []
        for name, p, fd in reversed(cls.peers):
            try:
                if p.poll() is None:
                    if fd is None:
                        # This unreaped direct Popen is owned, not a journal-PID adoption.
                        p.terminate()
                    else:
                        signal.pidfd_send_signal(fd, signal.SIGTERM)
                try:
                    code = p.wait(timeout=15)
                    result.append(dict(peer=name, exit=code, forced=False))
                except subprocess.TimeoutExpired:
                    if fd is None:
                        p.kill()
                    else:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    result.append(dict(peer=name, exit=p.wait(timeout=5), forced=True))
            except Exception as exc:
                errors.append(exc)
            finally:
                try:
                    if fd is not None:
                        os.close(fd)
                except Exception as exc:
                    errors.append(exc)
        try:
            (EVIDENCE / 'peer-exits.json').write_text(json.dumps(result, indent=2))
        except Exception as exc:
            errors.append(exc)
        try:
            assert all(p.poll() is not None for _, p, _ in cls.peers), 'live peer: refuse tree removal'
            def restore(path):
                if path.is_dir() and not path.is_symlink():
                    assert path.stat().st_uid == os.getuid()
                    path.chmod(path.stat().st_mode | 0o700)
                    for child in path.iterdir():
                        restore(child)
            restore(cls.dir)
            shutil.rmtree(cls.dir)
            (EVIDENCE / 'fixture-cleanup.json').write_text(json.dumps(dict(path=str(cls.dir), removed=not cls.dir.exists())))
        except Exception as exc:
            errors.append(exc)
        if not all(p['exit'] == 0 and not p['forced'] for p in result):
            errors.append(AssertionError(result))
        if errors:
            raise ExceptionGroup('actual fixture cleanup failures', errors)

    @classmethod
    def mongo_command(cls, code):
        script = "const {MongoClient}=require('mongodb');(async()=>{const c=await new MongoClient(process.argv[1],{serverSelectionTimeoutMS:500}).connect();try{const db=c.db();" + code + "}finally{await c.close()}})().catch(e=>{console.error(e.message);process.exitCode=1});"
        return subprocess.check_output([NODE, '--v8-pool-size=1', '-e', script, cls.uri], env=os.environ, timeout=5).decode()

    def launch(self, name, **kw):
        return m.Invocation(self, artifact=self.app, settings=self.settings, peer=self.mongo,
                            lifetime=45, grace_ms=1500, evidence=EVIDENCE / name, **kw)

    def serving(self):
        def check():
            status, body = http(self.http_port)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)['status'], 'ok')
            return json.loads(body)
        health = until(check)
        status, body = http(self.http_port, '/classic-ready')
        self.assertEqual(status, 200 if self.has_redis else 503)
        if self.has_redis:
            self.assertEqual(body, 'c3-classic-ready-v1\n')
        return dict(health=health, classicReadyStatus=status, classicReadyBody=body)

    def test_actual_01_sequential_F_R_same_owner_deadline_exact_stop(self):
        run = self.launch('sequential', sequential=True)
        first = run.started()
        responses = [self.serving()]
        run.send()
        self.assertTrue(select.select([run.app_fd], [], [], 5)[0])
        exit_f = m.wait_for(lambda: next((e for e in m.events(run.file) if e['event']=='EXIT'), None))
        self.assertEqual(exit_f['appExit'], 0)
        self.assertFalse(exit_f['forced'])
        os.close(run.app_fd)
        os.close(run.supervisor_fd)
        run.app_fd = run.supervisor_fd = None
        run.file = Path(run.next_phase['events'])
        run.invocation, run.token = run.next_phase['invocation'], run.next_phase['token']
        run.binding['role'] = run.next_phase['role']
        second = run.started()
        responses.append(self.serving())
        self.assertNotEqual(first['appPid'], second['appPid'])
        self.assertEqual(first['deadlineNs'], second['deadlineNs'])
        self.assertGreater(int(self.mongo_command("console.log(await db.collection('settings').countDocuments());")), 0)
        run.send()
        exit_r = run.finished()
        self.assertEqual(exit_r['appExit'], 0)
        self.assertFalse(exit_r['forced'])
        self.assertEqual(run.owner.returncode, 0)
        self.assertEqual(inventory(self.app), self.before)
        (EVIDENCE / 'actual-serving.json').write_text(json.dumps(dict(responses=responses,
            originalOwnerPid=run.owner.pid, originalOwnerExit=run.owner.returncode, F=exit_f, R=exit_r,
            sourceUnchanged=True, normalDDispatched=False), indent=2))

    def test_actual_02_owner_sigkill_both_roles(self):
        for role in ['F', 'R']:
            with self.subTest(role=role):
                run = self.launch('owner-death-' + role, role=role)
                run.started()
                self.serving()
                signal.pidfd_send_signal(run.owner_fd, signal.SIGKILL)
                e = run.finished()
                self.assertEqual(e['reason'], 'OWNER_DEAD')
                self.assertEqual(e['supervisorExit'], 0)
                self.assertLess(e['finishedNs'], run.deadline)

    def test_actual_03_stopped_owner_original_expiry(self):
        run = self.launch('stopped-owner', role='R')
        run.started()
        self.serving()
        signal.pidfd_send_signal(run.owner_fd, signal.SIGSTOP)
        self.assertTrue(select.select([run.app_fd], [], [], 48)[0])
        e = m.wait_for(lambda: next((e for e in m.events(run.file) if e['event']=='EXIT'), None))
        self.assertEqual(e['reason'], 'DEADLINE')
        self.assertLess(e['finishedNs'], run.deadline)
        self.assertEqual(e['appExit'], 0)
        self.assertFalse(e['forced'])
        signal.pidfd_send_signal(run.owner_fd, signal.SIGCONT)
        run.owner.wait(timeout=5)

    def test_actual_04_app_death_no_restart(self):
        run = self.launch('app-death', role='F')
        run.started()
        self.serving()
        signal.pidfd_send_signal(run.app_fd, signal.SIGKILL)
        e = run.finished()
        self.assertEqual(e['reason'], 'APP_DEAD')
        self.assertEqual(e['supervisorExit'], 1)

    def test_actual_05_mongo_peer_death_no_repin(self):
        run = self.launch('mongo-death', role='R')
        run.started()
        self.serving()
        mongo_fd = next(fd for name, _, fd in self.peers if name == 'mongo')
        signal.pidfd_send_signal(mongo_fd, signal.SIGTERM)
        self.assertEqual(self.mongo.wait(timeout=15), 0)
        e = run.finished()
        self.assertEqual(e['reason'], 'PEER_DEAD')
        self.assertTrue(select.select([run.app_fd], [], [], 0)[0])

    def test_actual_06_source_unchanged(self):
        self.assertEqual(inventory(self.app), self.before)

    def test_required_real_redis_available(self):
        self.assertTrue(self.has_redis, 'BLOCKED: prior Redis launcher target was pruned; real Redis binary unavailable; degraded HTTP is NOT Mongo/Redis acceptance')


if __name__ == '__main__':
    m.test_main()
