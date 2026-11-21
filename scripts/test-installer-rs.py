#!/usr/bin/env python3
"""Run the actual installer with real local Git/files and a Docker/mongosh fixture."""
import base64
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / 'scripts/install.sh'

# Execute the installer-provided JS, not a mock of its state machine. Only the
# Docker transport and server replies are modeled. Record no argv or secrets.
MONGO_FIXTURE = r'''
const fs = require('fs');
const [code, scenario, root] = process.argv.slice(2);
const trace = (x) => fs.appendFileSync(`${root}/events`, `${x}\n`);
function response(obj) {
  if (obj.code && scenario !== 'returned94') throw Object.assign(new Error(), obj);
  return obj;
}
global.print = (x) => console.log(x);
global.db = { getSiblingDB(name) {
  if (name !== 'admin') throw Error();
  return { runCommand(command) {
    trace(Object.keys(command)[0]);
    if (command.replSetGetStatus === 1) {
      if (scenario === 'denied') return response({ok: 0, code: 13});
      if (scenario === 'string94') return response({ok: 0, code: '94'});
      if (scenario === 'wrongSet') return {ok: 1, set: 'other', myState: 1};
      if (scenario === 'secondary') return {ok: 1, set: 'rs0', myState: 2};
      if (scenario === 'existing' || fs.existsSync(`${root}/initiated`)) {
        // After initiate, send one non-PRIMARY reply before the election.
        if (scenario !== 'existing' && !fs.existsSync(`${root}/elected`)) {
          fs.writeFileSync(`${root}/elected`, '');
          return {ok: 1, set: 'rs0', myState: 2};
        }
        trace('PRIMARY');
        return {ok: 1, set: 'rs0', myState: 1};
      }
      return response({ok: 0, code: 94});
    }
    if (command.replSetInitiate?._id !== 'rs0' ||
        command.replSetInitiate.members.length !== 1 ||
        command.replSetInitiate.members[0]._id !== 0 ||
        command.replSetInitiate.members[0].host !== 'mongo:27017') throw Error();
    if (scenario === 'initError') return response({ok: 0, code: 93});
    fs.writeFileSync(`${root}/initiated`, '');
    if (scenario === 'lostReply') process.exit(1);
    if (scenario === 'raced') return response({ok: 0, code: 23});
    return {ok: 1};
  }};
}};
eval(code);
'''

DOCKER = r'''#!/usr/bin/env bash
set -eu
trace() { printf '%s\n' "$1" >>"$TEST_ROOT/events"; }
case "$*" in
  'compose version'|info) trace docker-check ;;
  'compose -f docker-compose.yml config --quiet') trace config ;;
  'compose -f docker-compose.yml build backend updater')
    trace build; [ "$CASE" != buildError ] ;;
  'compose -f docker-compose.yml up -d mongo redis') trace dependencies ;;
  'compose -f docker-compose.yml up -d') trace app ;;
  'compose -f docker-compose.yml ps') trace ps ;;
  'inspect -f {{.State.Status}} '*) printf 'running\n' ;;
  'inspect -f {{if .State.Health}}{{.State.Health.Status}}{{end}} '*) printf 'healthy\n' ;;
  'inspect -f '*' hysteria-backend') : ;;
  'inspect -f '*' hysteria-updater')
    printf 'bind | /var/run/docker.sock | /var/run/docker.sock | true\n'
    printf 'bind | %s | %s | true\n' "$INSTALL_DIR" "$INSTALL_DIR" ;;
  'exec hysteria-backend node -e '*) : ;;
  'exec -i hysteria-backend node') /bin/cat >/dev/null ;;
  'compose -f docker-compose.yml exec -T mongo sh -ec '*)
    # Model Compose's effective env, then execute the real in-container sh argv.
    [[ -z ${MONGO_PASSWORD+x} && -z ${UPDATER_SECRET+x} ]] || exit 91
    password=$(sed -n 's/^MONGO_PASSWORD=//p' .env)
    trace mongo-probe
    [ "$CASE" != noTransport ] || exit 1
    [ "$CASE" != hungTransport ] || exec /bin/sleep 60
    export MONGO_INITDB_ROOT_USERNAME="$MONGO_USER" MONGO_INITDB_ROOT_PASSWORD="$password"
    shift 6
    exec "$@" ;;
  *) trace unexpected-docker; exit 92 ;;
esac
'''

MONGOSH = r'''#!/usr/bin/env bash
set -eu
[[ $# = 11 && $1 == 'mongodb://mongo:27017/admin?'* && $1 == *'directConnection=true'* &&
   $2 == --quiet && $3 == --norc && $4 == --username && $5 == "$MONGO_INITDB_ROOT_USERNAME" &&
   $6 == --password && $7 == "$MONGO_INITDB_ROOT_PASSWORD" && -n $7 &&
   $8 == --authenticationDatabase && $9 == admin && ${10} == --eval ]] || exit 91
exec node "$TEST_ROOT/mongosh.cjs" "${11}" "$CASE" "$TEST_ROOT"
'''


class Installer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='.installer-rs-', dir=REPO)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.project = self.root / 'project'
        self.origin = self.root / 'origin'
        self.events = self.root / 'events'
        self.events.touch()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env = {k: os.environ[k] for k in ('PATH', 'HOME', 'USER') if k in os.environ}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                        GIT_ALLOW_PROTOCOL='file', LC_ALL='C', TEST_ROOT=str(self.root),
                        INSTALL_DIR=str(self.project), BACKUP_ROOT=str(self.root / 'backups'),
                        INSTALL_USER=subprocess.check_output(['id', '-un'], text=True).strip(),
                        PANEL_DOMAIN='fixture.invalid', ACME_EMAIL='operator@fixture.invalid',
                        CELERITY_INSTALLER_LIBRARY='1', SKIP_HTTPS_CHECK='1',
                        REPO='fixture/repo', BRANCH='main', START_TIMEOUT='30')
        self.path = str(self.bin) + ':' + self.env['PATH']
        self.git('init', '-q', '-b', 'main', str(self.origin))
        self.git('-C', str(self.origin), 'config', 'user.name', 'fixture')
        self.git('-C', str(self.origin), 'config', 'user.email', 'fixture@fixture.invalid')
        for name in ('.gitignore', '.dockerignore', 'docker-compose.yml'):
            (self.origin / name).write_bytes((REPO / name).read_bytes())
        (self.origin / 'package.json').write_text('{"version": "fixture"}\n')
        self.commit('baseline fixture')
        (self.root / 'mongosh.cjs').write_text(MONGO_FIXTURE)
        self.stub('docker', DOCKER)
        self.stub('mongosh', MONGOSH)
        self.stub('chown', r'''#!/usr/bin/env bash
case "$*" in
  999\ *) printf 'chown-999\n' >>"$TEST_ROOT/events"; [ "$CASE" != chownError ] ;;
  *-R*|*mongo-keyfile*) printf 'unexpected-chown\n' >>"$TEST_ROOT/events"; exit 93 ;;
  *) exec /usr/bin/chown "$@" ;;
esac
''')
        self.stub('openssl', r'''#!/usr/bin/env bash
if [ "$*" = 'rand -base64 756' ]; then
  printf 'keygen\n' >>"$TEST_ROOT/events"
  if [ "$CASE" = opensslError ]; then printf 'partial'; exit 1; fi
fi
exec /usr/bin/openssl "$@"
''')

    def stub(self, name, script):
        file = self.bin / name
        file.write_text(script)
        file.chmod(0o700)

    def git(self, *args):
        result = subprocess.run(['git', *args], env=self.env, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, 'local Git fixture failed')

    def commit(self, message):
        self.git('-C', str(self.origin), 'add', '.')
        self.git('-C', str(self.origin), 'commit', '-qm', message)

    def run_install(self, case='fresh', error=None, **overrides):
        self.events.write_text('')
        result = subprocess.run(['bash', '-c', r'''
source "$1"
need_root() { :; }
install_base_tools() { :; }
# Use a local checkout without exercising the network in this sandbox.
eval "$(declare -f validate_inputs | sed '1s/validate_inputs/validate_local_inputs/')"
validate_inputs() {
  validate_local_inputs
  REPO_URL="file://$TEST_ROOT/origin"
  if [ "$CASE" = hungTransport ]; then START_TIMEOUT=2; fi
}
# Avoid real delays when transport or primary never materializes. The next
# iteration must see the same production deadline, already expired.
sleep() {
  if [[ $CASE = secondary || $CASE = noTransport ]]; then SECONDS=100; fi
}
main
''', 'test-installer-rs', str(INSTALLER)], cwd=REPO,
            env=dict(self.env, PATH=self.path, CASE=case, **overrides),
            capture_output=True, timeout=10)
        output = result.stdout + result.stderr
        if error is None:
            self.assertEqual(result.returncode, 0, 'installer failed; output withheld')
        else:
            self.assertNotEqual(result.returncode, 0, 'installer unexpectedly succeeded')
            self.assertTrue(error.encode() in output, 'missing expected error; output withheld')
        return self.events.read_text().splitlines()

    def digest(self, file):
        return hashlib.sha256(file.read_bytes()).digest()

    def check_key(self):
        key = self.project / 'mongo-keyfile'
        self.assertTrue(stat.S_IMODE(key.stat().st_mode) == 0o400, 'incorrect key mode')
        self.assertTrue(len(base64.b64decode(b''.join(key.read_bytes().split()), validate=True)) == 756,
                        'incorrect key encoding/length')
        return key

    def assert_new_env(self):
        modes = [line for line in (self.project / '.env').read_bytes().splitlines() if line.startswith(b'C3_')]
        self.assertTrue(modes == [b'C3_REBUILD_ENABLED=true'], 'wrong fresh .env flags')

    def test_no_start_prepares_files_without_docker(self):
        events = self.run_install(NO_START='1')
        self.assertEqual(events, ['keygen', 'chown-999'])
        self.check_key()
        self.assert_new_env()
        ignored = subprocess.run(['git', '-C', str(self.project), 'check-ignore', '-q', 'mongo-keyfile'],
                                 env=self.env, capture_output=True)
        self.assertEqual(ignored.returncode, 0)
        self.assertIn('mongo-keyfile', (self.project / '.dockerignore').read_text().splitlines())

    def test_start_waits_for_primary_and_only_initiates_once(self):
        for case in ('fresh', 'returned94', 'raced'):
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory(dir=self.root) as stage:
                    self.project = Path(stage) / 'project'
                    self.env['INSTALL_DIR'] = str(self.project)
                    (self.root / 'initiated').unlink(missing_ok=True)
                    (self.root / 'elected').unlink(missing_ok=True)
                    events = self.run_install(case)
                    self.assertEqual(events.count('replSetInitiate'), 1)
                    self.assertEqual(events.count('PRIMARY'), 1)
                    phases = [events.index(x) for x in ('build', 'dependencies', 'replSetInitiate', 'PRIMARY', 'app')]
                    self.assertEqual(phases, sorted(phases))
                    self.assertGreater(events.count('replSetGetStatus'), 2)
                    self.check_key()
                    self.assert_new_env()

    def test_force_preserves_env_key_config_and_data(self):
        self.run_install(NO_START='1')
        env = self.project / '.env'
        env.write_bytes(env.read_bytes().replace(b'C3_REBUILD_ENABLED=true\n', b'') + b'CUSTOM_OPERATOR_FLAG=keep\n')
        key = self.check_key()
        config = self.project / 'operator.conf'
        data = self.project / 'data/operator-state'
        config.touch()
        data.touch()
        data.chmod(0o640)
        (self.origin / 'version.txt').write_text('updated\n')
        self.commit('incoming unrelated source update')
        before = [(p.stat().st_ino, self.digest(p), p.stat().st_mode, p.stat().st_uid) for p in (env, key, config, data)]
        with_result = self.run_install('existing', FORCE='1', MONGO_PASSWORD=os.urandom(16).hex(),
                                      UPDATER_SECRET=os.urandom(16).hex())
        self.assertEqual(with_result.count('replSetInitiate'), 0)
        self.assertLess(with_result.index('PRIMARY'), with_result.index('app'))
        self.assertFalse({'keygen', 'chown-999', 'unexpected-chown'} & set(with_result))
        self.assertEqual(before, [(p.stat().st_ino, self.digest(p), p.stat().st_mode, p.stat().st_uid)
                                  for p in (env, key, config, data)], 'operator state changed')
        self.assertTrue((self.project / 'version.txt').is_file())

    def test_force_rejects_ignored_collision_and_dirty_tracked_config(self):
        self.run_install(NO_START='1')
        config = self.project / 'docker-compose.yml'
        clean = config.read_bytes()
        config.write_bytes(clean + b'\n# operator override\n')
        events = self.run_install(FORCE='1', error='Existing checkout has local changes')
        self.assertEqual(events, [])
        self.assertTrue(config.read_bytes().endswith(b'# operator override\n'))
        config.write_bytes(clean)

        # Git normally overwrites ignored files; the installer must not.
        (self.project / '.git/info/exclude').write_text('/local-settings\n')
        local = self.project / 'local-settings'
        local.write_text('operator state\n')
        (self.origin / local.name).write_text('incoming source\n')
        self.commit('incoming conflicts with local state')
        events = self.run_install(FORCE='1', error='would be overwritten by merge')
        self.assertEqual(events, [])
        self.assertTrue(local.read_text() == 'operator state\n')

    def test_force_initializes_empty_regular_key(self):
        self.run_install(NO_START='1')
        key = self.check_key()
        key.chmod(0o600)
        key.write_bytes(b'')
        self.assertEqual(self.run_install(FORCE='1', NO_START='1'), ['keygen', 'chown-999'])
        self.check_key()

    def test_existing_nongit_is_not_deleted(self):
        self.project.mkdir()
        marker = self.project / 'custom-settings'
        marker.touch()
        ino = marker.stat().st_ino
        self.run_install(NO_START='1', FORCE='1', error='not a Git checkout')
        self.assertEqual(marker.stat().st_ino, ino)
        self.assertTrue(list((self.root / 'backups').glob('*.tar.gz')))

    def test_unsafe_secret_paths_are_rejected_before_start(self):
        self.project.mkdir()
        for name in ('.env', 'mongo-keyfile'):
            for kind in ('dangling', 'symlink', 'hardlink', 'fifo', 'directory'):
                with self.subTest(name=name, kind=kind):
                    path, target = self.project / name, self.root / 'protected'
                    target.write_bytes(os.urandom(16))
                    before = self.digest(target)
                    if kind == 'dangling':
                        path.symlink_to(self.root / 'absent')
                    elif kind == 'symlink':
                        path.symlink_to(target)
                    elif kind == 'hardlink':
                        path.hardlink_to(target)
                    elif kind == 'fifo':
                        os.mkfifo(path)
                    else:
                        path.mkdir()
                    events = self.run_install(NO_START='1', FORCE='1', error=f'Unsafe {name}')
                    self.assertEqual(events, [])
                    self.assertTrue(self.digest(target) == before, 'neighbor file touched')
                    if kind == 'directory':
                        path.rmdir()
                    else:
                        path.unlink()

    def test_failed_key_generation_or_ownership_does_not_publish(self):
        for case, message in (('opensslError', 'generate Mongo keyfile'), ('chownError', 'set Mongo keyfile owner')):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=self.root) as stage:
                self.project = Path(stage) / 'project'
                self.env['INSTALL_DIR'] = str(self.project)
                events = self.run_install(case, NO_START='1', error=message)
                self.assertNotIn('docker-check', events)
                self.assertFalse((self.project / 'mongo-keyfile').exists())
                self.assertFalse(list(self.project.glob('.mongo-keyfile.*')))

    def test_failures_do_not_start_app_or_retry_initiate(self):
        cases = [('denied', 'replSetGetStatus failed', 0),
                 ('string94', 'replSetGetStatus failed', 0),
                 ('wrongSet', 'replSetGetStatus failed', 0),
                 ('secondary', 'did not reach PRIMARY', 0),
                 ('noTransport', 'did not reach PRIMARY', 0),
                 ('hungTransport', 'did not reach PRIMARY', 0),
                 ('initError', 'replSetInitiate failed', 1),
                 ('lostReply', 'replSetInitiate outcome unknown', 1),
                 ('buildError', None, 0)]
        for case, message, attempts in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=self.root) as stage:
                self.project = Path(stage) / 'project'
                self.env['INSTALL_DIR'] = str(self.project)
                events = self.run_install(case, error=message or 'Building backend')
                self.assertEqual(events.count('replSetInitiate'), attempts)
                self.assertNotIn('app', events)
                if case == 'buildError':
                    self.assertNotIn('dependencies', events)


if __name__ == '__main__':
    unittest.main(verbosity=2)
