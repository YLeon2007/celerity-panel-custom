'use strict';
// Executes the emitted Python constructor on real scratch files. Root ownership,
// nobody credentials and systemd/Xray are MODELED; no privileged/service/SSH calls.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
const helper = require('../src/services/classicPortalBridgeBootstrap');
const harness = String.raw`
import sys, os, stat, shlex, json, tempfile, subprocess, pwd, types, contextlib, io
request = json.load(sys.stdin)
# Never use system /tmp: respect the Hermes scratch directory.
with tempfile.TemporaryDirectory(prefix='portal-bridge-', dir=os.environ['TMPDIR']) as root:
    def mapped(source):
        import re
        return re.sub(r'(?<![A-Za-z0-9_/])/(usr|etc|run|lib)(?=[/\x27\x22])', lambda m: root + m[0], source)
    def source(command):
        return mapped(shlex.split(command.split('\n', 1)[1])[2])
    real_lstat, real_chmod = os.lstat, os.chmod
    owners, events, tested = {}, [], []
    for p in ['usr/local/bin', 'usr/local/etc', 'etc/systemd/system', 'run/systemd/system', 'usr/lib/systemd/system', 'lib/systemd/system']:
        os.makedirs(root + '/' + p, exist_ok=True)
    for parent, dirs, files in os.walk(root): os.chmod(parent, 0o755)
    binary = root + '/usr/local/bin/xray'
    with open(binary, 'wb') as f: f.write(b'installed canonical binary fixture')
    os.chmod(binary, 0o755)
    directory, config = root + '/usr/local/etc/xray-bridge', root + '/usr/local/etc/xray-bridge/config.json'
    unit = root + '/etc/systemd/system/xray-bridge.service'
    # Production must set exact modes even with a restrictive service umask.
    os.umask(0o077)
    def lstat(p, *a, **kw):
        s = real_lstat(p, *a, **kw)
        fields = {name: getattr(s, name) for name in dir(s) if name.startswith('st_')}
        fields['st_uid'], fields['st_gid'] = owners.get(str(p), (0, 0))
        return types.SimpleNamespace(**fields)
    def chown(p, uid, gid):
        owners[str(p)] = (uid, gid)
        events.append(['chown', str(p), uid, gid])
    def fchown(fd, uid, gid): chown(os.readlink('/proc/self/fd/' + str(fd)), uid, gid)
    os.lstat, os.chown, os.fchown = lstat, chown, fchown
    os.geteuid = lambda: 0
    pwd.getpwnam = lambda name: types.SimpleNamespace(pw_uid=65534, pw_gid=65534) if name == 'nobody' else None
    namespace = {}
    def fake_run(argv, **kw):
        assert kw['timeout'] == 3
        events.append(argv)
        out = b''
        code = 0
        if argv[0] == binary:
            assert kw['user'] == 65534 and kw['group'] == 65534 and kw['extra_groups'] == []
            assert kw['cwd'] == '/' and kw['env']['PATH'] == root + '/usr/local/bin:' + root + '/usr/bin:/bin'
            assert argv[1:6] == ['run', '-test', '-format', 'json', '-config']
            file = argv[6]
            if file == 'stdin:':
                content = kw['input']
            else:
                assert owners[directory] == (0, 65534)
                assert owners[file] == (0, 65534)
                assert stat.S_IMODE(real_lstat(directory).st_mode) == 0o750
                assert stat.S_IMODE(real_lstat(file).st_mode) == 0o640
                content = open(file, 'rb').read()
            payload = json.loads(content)
            assert not payload.get('reverse') and not payload.get('inbounds')
            assert not payload['routing']['rules']
            if request.get('case') == 'incompatible-binary': code = 1
            tested.append(file)
        elif argv[0] == root + '/usr/bin/python3':
            assert kw['user'] == 65534 and kw['group'] == 65534 and kw['extra_groups'] == []
            assert 'os.access' in argv[2]
            if request.get('case') == 'nobody-no-traverse': code = 1
        else:
            assert argv[0] == 'systemctl', 'no installer/download/other command allowed'
            if argv[1] == 'show' and '--property=LoadState' in argv:
                state = 'loaded' if request.get('case') == 'loaded-custom' else 'not-found'
                out = ('LoadState=' + state + '\nActiveState=inactive\nMainPID=0\nFragmentPath=\nDropInPaths=\nUnitFileState=\n').encode()
            elif argv[1] == 'list-jobs': out = b'22 xray-bridge.service start waiting\n' if request.get('case') == 'job' else b''
            elif argv[1] == 'show':
                out = ('FragmentPath=' + unit + '\nDropInPaths=\nUser=nobody\nGroup=\nSupplementaryGroups=\nNeedDaemonReload=no\nExecStart={ path=' + binary + ' ; argv[]=' + binary + ' run -config ' + config + ' ; }\n').encode()
            elif argv[1] == 'enable':
                assert tested[-1] == config, 'FINAL file DAC must be tested before enable'
                if request.get('case') == 'enable-failure': code = 1
            else: assert argv[1] in ['daemon-reload', 'is-active', 'is-enabled']
        return types.SimpleNamespace(returncode=code, stdout=out, stderr=b'')
    subprocess.run = fake_run
    case = request.get('case', 'fresh')
    if case in ['empty-directory', 'partial-config']:
        os.mkdir(directory)
        if case == 'partial-config':
            with open(config, 'w') as f: f.write('{}')
    if case in ['custom-unit', 'dropin', 'dangling-unit', 'vendor-unit']:
        p = unit if case != 'vendor-unit' else root + '/usr/lib/systemd/system/xray-bridge.service'
        if case == 'dropin': os.mkdir(p + '.d')
        elif case == 'dangling-unit': os.symlink(root + '/missing', p)
        else:
            with open(p, 'w') as f: f.write('custom unit')
    if case == 'unsafe-parent': real_chmod(root + '/usr/local/etc', 0o777)
    error = None
    try:
        # Run actual emitted read-only preflight, then actual emitted constructor.
        with contextlib.redirect_stdout(io.StringIO()) as output:
            exec(source(request['preflight']), namespace)
        pin = output.getvalue()
        assert len(pin) == 64
        if request.get('mutate-between'):
            with open(unit, 'w') as f: f.write('foreign race winner')
        constructor = source(request['bootstrap']).replace('"' + 'a' * 64 + '"', repr(pin))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            exec(constructor, namespace)
        assert output.getvalue() == 'C3_BRIDGE_READY'
        assert open(config, 'rb').read() == namespace['IDLE']
        assert open(unit, 'rb').read() == namespace['UNIT_BYTES']
        assert stat.S_IMODE(real_lstat(unit).st_mode) == 0o644
    except Exception as e:
        import traceback
        error = traceback.format_exc()
    result = {'error': error, 'events': events, 'tested': tested, 'hasConfig': os.path.lexists(config), 'hasUnit': os.path.lexists(unit), 'root': root}
    # Restore real lstat before TemporaryDirectory cleanup (modeled object is not
    # a native stat_result and deliberately cannot stand in for kernel metadata).
    os.lstat = real_lstat
    print(json.dumps(result))
`;
function run(options = {}) {
    const result = spawnSync('python3', ['-c', harness], { input: JSON.stringify({
        preflight: helper.preflightCommand(), bootstrap: helper.bootstrapCommand('a'.repeat(64)), ...options,
    }), encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
}

test('emitted constructor: real scratch modes under umask 0077, modeled nobody DAC test before enable', () => {
    const r = run();
    assert.equal(r.error, null);
    const commands = r.events.filter(row => row[0] === 'systemctl');
    assert.equal(commands.filter(row => row[1] === 'daemon-reload').length, 1);
    assert.deepEqual(commands.filter(row => row[1] === 'enable').map(row => row.slice(1)), [['enable', '--now', 'xray-bridge.service']]);
    assert.equal(r.tested.at(-1), `${r.root}/usr/local/etc/xray-bridge/config.json`);
});
for (const value of ['empty-directory', 'partial-config', 'custom-unit', 'dropin', 'dangling-unit', 'vendor-unit', 'loaded-custom', 'job', 'unsafe-parent', 'incompatible-binary', 'nobody-no-traverse']) {
    test(`emitted constructor refuses ${value} without mutation`, () => {
        const r = run({ case: value });
        assert.match(r.error, /CLASSIC_SCOPED_BRIDGE_BOOTSTRAP_REFUSED/);
        assert.equal(r.events.some(row => row[0] === 'chown' || row[1] === 'daemon-reload' || row[1] === 'enable'), false);
    });
}
test('repeat preflight preserves a racing foreign unit without adoption', () => {
    const r = run({ 'mutate-between': true });
    assert.match(r.error, /CLASSIC_SCOPED_BRIDGE_BOOTSTRAP_REFUSED/);
    assert.equal(r.hasConfig, false);
    assert.equal(r.hasUnit, true);
});
test('enable failure retains created idle files, never retries or rolls back', () => {
    const r = run({ case: 'enable-failure' });
    assert.match(r.error, /CLASSIC_SCOPED_BRIDGE_BOOTSTRAP_REFUSED/);
    assert.equal(r.hasConfig, true);
    assert.equal(r.hasUnit, true);
    assert.equal(r.events.filter(row => row[0] === 'systemctl' && row[1] === 'enable').length, 1);
});
