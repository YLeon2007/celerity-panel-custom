'use strict';

const { generateBridgeSystemdService } = require('./configGenerator');
const quote = value => `'${value.replace(/'/g, `'"'"'`)}'`;
// Deliberately no reverse listeners, tunnels, log files or geo-data dependencies.
// This is a baseline for ordinary scoped composition, never a link deployment.
const IDLE_BYTES = JSON.stringify({ log: { loglevel: 'warning' }, inbounds: [],
    outbounds: [{ tag: 'freedom', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4' } },
        { tag: 'blackhole', protocol: 'blackhole' }],
    routing: { domainStrategy: 'IPIfNonMatch', rules: [] } }, null, 2);

// A finite root-only constructor. No installer, download, binary write, MAIN
// config/restart, adoption or partial-state cleanup. The repeat preflight is
// deliberately inside the mutating dispatch too (TOCTOU refusal, not adoption).
const COMMON = String.raw`
import os, stat, pwd, json, hashlib, subprocess
BINARY = '/usr/local/bin/xray'
DIRECTORY = '/usr/local/etc/xray-bridge'
CONFIG = DIRECTORY + '/config.json'
UNIT = '/etc/systemd/system/xray-bridge.service'
SERVICE = 'xray-bridge.service'
IDLE = ${JSON.stringify(IDLE_BYTES)}.encode()
UNIT_BYTES = ${JSON.stringify(generateBridgeSystemdService())}.encode()
def require(ok):
    if not ok: raise RuntimeError('CLASSIC_SCOPED_BRIDGE_BOOTSTRAP_REFUSED')
def run(argv, **kw):
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, **kw)
def checked(argv, **kw):
    result = run(argv, **kw)
    require(result.returncode == 0)
    return result.stdout
def safe(path, directory=False):
    s = os.lstat(path)
    require((stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)) and s.st_uid == 0 and not s.st_mode & 0o022)
    return [s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
def properties():
    r = run(['systemctl', 'show', SERVICE, '--property=LoadState', '--property=ActiveState', '--property=MainPID', '--property=FragmentPath', '--property=DropInPaths', '--property=UnitFileState'])
    require(r.returncode in (0, 1))
    lines = r.stdout.decode().splitlines()
    require(len(lines) == 6 and len({line.split('=', 1)[0] for line in lines}) == 6)
    return dict(line.split('=', 1) for line in lines)
def service_test(file, account, content=None):
    # subprocess drops supplementary groups explicitly, not root's Xray -test.
    checked([BINARY, 'run', '-test', '-format', 'json', '-config', file],
        input=content, user=account.pw_uid, group=account.pw_gid, extra_groups=[], cwd='/',
        env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'XRAY_LOCATION_ASSET': '/usr/local/share/xray'})
def preflight():
    require(os.geteuid() == 0)
    account = pwd.getpwnam('nobody')
    require(account.pw_uid > 0 and account.pw_gid > 0)
    facts = [safe(p, True) for p in ['/usr', '/usr/local', '/usr/local/bin', '/usr/local/etc', '/etc', '/etc/systemd', '/etc/systemd/system']]
    facts += [safe(BINARY), hashlib.sha256(open(BINARY, 'rb').read()).hexdigest(), account.pw_uid, account.pw_gid]
    require(os.access(BINARY, os.X_OK))
    require(not os.path.lexists(DIRECTORY))
    for prefix in ['/etc/systemd/system', '/run/systemd/system', '/usr/local/lib/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system']:
        require(not os.path.lexists(prefix + '/' + SERVICE) and not os.path.lexists(prefix + '/' + SERVICE + '.d'))
    require(properties() == {'LoadState': 'not-found', 'ActiveState': 'inactive', 'MainPID': '0', 'FragmentPath': '', 'DropInPaths': '', 'UnitFileState': ''})
    jobs = checked(['systemctl', 'list-jobs', '--no-legend', '--no-pager']).decode()
    require(not any(SERVICE in line.split() for line in jobs.splitlines()))
    # Installed canonical binary must actually accept the idle config as nobody.
    service_test('stdin:', account, IDLE)
    # Check future config traversal with the actual DAC/ACL identity BEFORE
    # creating anything. Testing stdin as root/nobody cannot prove this path.
    checked(['/usr/bin/python3', '-c', 'import os,sys; sys.exit(0 if all(os.access(p, os.X_OK) for p in ["/usr", "/usr/local", "/usr/local/etc"]) else 1)'],
        user=account.pw_uid, group=account.pw_gid, extra_groups=[], cwd='/', env={'PATH': '/usr/bin:/bin'})
    return hashlib.sha256(json.dumps(facts, separators=(',', ':')).encode()).hexdigest(), account
`;
function command(label, source) { return `# ${label}\npython3 -c ${quote(source)}`; }
function preflightCommand() {
    return command('C3_PORTAL_BRIDGE_PREFLIGHT', `${COMMON}\nprint(preflight()[0], end='')\n`);
}
function bootstrapCommand(pin) {
    if (typeof pin !== 'string' || !/^[a-f0-9]{64}$/.test(pin)) throw new Error('CLASSIC_SCOPED_BRIDGE_PREFLIGHT_INVALID');
    return command('C3_PORTAL_BRIDGE_BOOTSTRAP', `${COMMON}
observed, account = preflight()
require(observed == ${JSON.stringify(pin)})
os.mkdir(DIRECTORY, 0o750)
os.chown(DIRECTORY, 0, account.pw_gid)
os.chmod(DIRECTORY, 0o750)
def create(path, content, mode, gid):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(content)
        f.flush()
        os.fchown(f.fileno(), 0, gid)
        os.fchmod(f.fileno(), mode)
        os.fsync(f.fileno())
create(CONFIG, IDLE, 0o640, account.pw_gid)
create(UNIT, UNIT_BYTES, 0o644, 0)
# Test the FINAL idle file through the real directory DAC before enabling it.
service_test(CONFIG, account)
checked(['systemctl', 'daemon-reload'])
loaded = checked(['systemctl', 'show', SERVICE, '--property=FragmentPath', '--property=DropInPaths', '--property=User', '--property=Group', '--property=SupplementaryGroups', '--property=ExecStart', '--property=NeedDaemonReload']).decode()
props = dict(line.split('=', 1) for line in loaded.splitlines())
require(props.get('FragmentPath') == UNIT and props.get('DropInPaths') == '' and props.get('User') == 'nobody' and props.get('Group') == '' and props.get('SupplementaryGroups') == '' and props.get('NeedDaemonReload') == 'no')
require('path=' + BINARY + ' ; argv[]=' + BINARY + ' run -config ' + CONFIG + ' ;' in props.get('ExecStart', ''))
require(open(CONFIG, 'rb').read() == IDLE and open(UNIT, 'rb').read() == UNIT_BYTES)
require(safe(DIRECTORY, True)[2:] == [0, account.pw_gid, 0o750] and safe(CONFIG)[2:] == [0, account.pw_gid, 0o640] and safe(UNIT)[2:] == [0, 0, 0o644])
checked(['systemctl', 'enable', '--now', SERVICE])
checked(['systemctl', 'is-active', '--quiet', SERVICE])
checked(['systemctl', 'is-enabled', '--quiet', SERVICE])
require(open(CONFIG, 'rb').read() == IDLE and open(UNIT, 'rb').read() == UNIT_BYTES)
require(safe(DIRECTORY, True)[2:] == [0, account.pw_gid, 0o750] and safe(CONFIG)[2:] == [0, account.pw_gid, 0o640] and safe(UNIT)[2:] == [0, 0, 0o644])
print('C3_BRIDGE_READY', end='')
`);
}
function stageTestCommand(file) {
    if (!/^\/usr\/local\/etc\/xray-bridge\/config\.json\.[a-f0-9]{24}\.stage$/.test(file)) throw new Error('CLASSIC_SCOPED_STAGE_INVALID');
    return command('C3_PORTAL_BRIDGE_STAGE_TEST', `${COMMON}
account = pwd.getpwnam('nobody')
require(account.pw_uid > 0 and account.pw_gid > 0)
safe(DIRECTORY, True)
safe(${JSON.stringify(file)})
os.chown(${JSON.stringify(file)}, 0, account.pw_gid)
os.chmod(${JSON.stringify(file)}, 0o640)
service_test(${JSON.stringify(file)}, account)
`);
}

// daemon-reload can reset only the nested ExecStart start_time/pid bookkeeping
// while the actual outer process remains identical. Do not drop arbitrary argv,
// outer PID/start identity, exit status or any unit/config fields from equality.
function sameProfileAcrossBootstrapReload(before, after) {
    if (before.bytes === 'C3_CONFIG_ABSENT') return JSON.stringify(before) === JSON.stringify(after);
    const outer = profile => profile.runtime?.[0]?.match(/^MainPID=([1-9]\d*)$/)?.[1];
    const start = profile => profile.runtime?.[2]?.match(/^ExecMainStartTimestampMonotonic=([1-9]\d*)$/)?.[1];
    const field = (profile, name) => profile.runtime?.[1]?.match(new RegExp(` ; ${name}=([^;]*) ;`))?.[1];
    const permittedReset = (name, reset) => field(before, name) !== undefined && field(after, name) !== undefined
        && (field(before, name) === field(after, name) || field(after, name) === reset);
    const nested = profile => profile.runtime?.[1]?.replace(/start_time=[^;]* ; /, '').replace(/pid=\d+ ; /, '');
    return !!outer(before) && !!start(before) && outer(before) === outer(after) && start(before) === start(after)
        && permittedReset('start_time', '[n/a]') && permittedReset('pid', '0')
        && before.bytes === after.bytes && before.unit === after.unit
        && JSON.stringify(before.loaded) === JSON.stringify(after.loaded) && nested(before) === nested(after);
}
module.exports = { IDLE_BYTES, preflightCommand, bootstrapCommand, stageTestCommand, sameProfileAcrossBootstrapReload };
