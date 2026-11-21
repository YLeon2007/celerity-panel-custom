'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
const { existsSync, mkdtempSync, readlinkSync, rmSync } = require('node:fs');

// Exact data member of the signed trixie/amd64 xl2tpd 1.3.18-1+b1 package.
const defaults = `# Defaults for xl2tpd initscript
# sourced by /etc/init.d/xl2tpd
# installed at /etc/default/xl2tpd by the maintainer scripts

#
# This is a POSIX shell fragment
#

# Where the l2tp-control pipe is located
XL2TPD_RUN_DIR="/var/run/xl2tpd"

# Additional options that are passed to the Daemon.
DAEMON_OPTS=""
`;

// Run actual DIRECT dispatch, observe, native_vpn, read and flock. Project / to
// a private scratch tree; each modeled observation is read-only. No systemd,
// dpkg, sockets, /dev/ppp or host configuration are accessed by this test.
const harness = String.raw`
import io, json, os, runpy, subprocess, sys
from pathlib import Path
from types import SimpleNamespace as NS

source, unit_helper, root = sys.argv[1:]
opts = json.load(sys.stdin)
h = dict(__name__='fixture')
exec(compile(Path(source).read_bytes(), source, 'exec'), h)
root = Path(root)
XL, IKE, X, B, NET = (h[k] for k in ('XL','IKE','X','B','NET_UNIT'))
system = h['SYSTEM']
local_xl = system + '/' + XL
path = '/etc/default/xl2tpd'
boot = h['XL_BOOT']

def backing(p):
    assert p.startswith('/') and '..' not in Path(p).parts
    return root / p[1:]

def put(p, data, mode=0o644):
    f = backing(p)
    f.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    f.write_bytes(data)
    f.chmod(mode)
    return f

os.umask(0o022)
helper = runpy.run_path(unit_helper)
frag = opts.get('fragment', local_xl)
put(local_xl, helper['UNIT'] + (b'# altered\n' if opts.get('editedUnit') else b''), opts.get('unitMode', 0o644))
backing(boot).parent.mkdir()
if opts.get('enabled'):
    backing(boot).symlink_to(local_xl)
for k in ('lns', 'chap', 'secrets', 'starter', 'main'):
    put(h['NAMES'][k], b'{}' if k == 'main' else (b'config setup\ninclude /etc/ipsec.d/*.conf\n' if k == 'starter' else b'# minimal\n'))
backing('/etc/ipsec.d').mkdir()
backing(h['NFT_DIR']).parent.mkdir(exist_ok=True)
backing(path).parent.mkdir()
if opts['defaults'] is not None:
    f = put(path, opts['defaults'].encode(), opts.get('mode', 0o644))
    if opts.get('symlink'):
        f.rename(f.with_suffix('.target'))
        f.symlink_to(f.with_suffix('.target').name)
    if opts.get('hardlink'):
        os.link(f, f.with_suffix('.alias'))

owners = {backing(p).stat().st_ino: owner for p, owner in (
    (path, (opts.get('uid', 0), opts.get('gid', 0))), (local_xl, (0, opts.get('unitGid', 0)))) if backing(p).is_file()}

class ProjectedOS:
    path = NS(split=os.path.split, basename=os.path.basename, lexists=lambda p: os.path.lexists(backing(p)))
    def __getattr__(self, name):
        # Only the read side and existing FD traversal are allowed.
        assert name in ('O_RDONLY','O_DIRECTORY','O_NOFOLLOW','O_NONBLOCK','close','fdopen','listxattr','listdir','umask')
        return getattr(os, name)
    def open(self, part, flags, *, dir_fd=None):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)
        if dir_fd is None:
            assert part == '/'
            return os.open(root, flags)
        assert '/' not in part and part not in ('', '.', '..')
        return os.open(part, flags, dir_fd=dir_fd)
    def stat(self, part, *, dir_fd, follow_symlinks):
        return os.stat(part, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
    def lstat(self, path): return os.lstat(backing(path))
    def fstat(self, fd):
        st = os.fstat(fd)
        uid,gid = owners.get(st.st_ino, (0,0))
        return NS(st_mode=st.st_mode, st_uid=uid, st_gid=gid, st_nlink=st.st_nlink, st_size=st.st_size,
                  st_dev=st.st_dev, st_ino=st.st_ino)
    def geteuid(self): return 0

h['os'] = ProjectedOS()
units = {n: dict(LoadState='loaded', ActiveState='inactive', SubState='dead', MainPID='0', InvocationID='',
                UnitFileState='enabled', NeedDaemonReload='no', FragmentPath='/usr/lib/systemd/system/'+n,
                DropInPaths='', PrivateNetwork='no', User='', KillMode='control-group') for n in (XL,IKE,X,B,NET)}
units[NET].update(LoadState='not-found', FragmentPath='')
units[X].update(ActiveState='active', SubState='running', MainPID='101', InvocationID='main')
units[XL].update(FragmentPath=frag, UnitFileState='disabled' if frag == local_xl and not opts.get('enabled') else 'enabled',
                 ExecStart='{ path=/usr/sbin/xl2tpd ; argv[]=/usr/sbin/xl2tpd -D ; ignore_errors=no ; pid=0 ; code=(null) ; status=0/0 }')
units[XL].update(opts.get('unit', {}))
units[IKE]['ExecStart'] = '{ path=/usr/sbin/ipsec ; argv[]=/usr/sbin/ipsec start --nofork ; }'
commands = []
unmodeled = []
rpdb = opts.get('rpdbNetns')
ip_show = ('/usr/sbin/ip', '-j', '-N', '-4', 'rule', 'show')
ip6_show = ('/usr/sbin/ip', '-j', '-N', '-6', 'rule', 'show')
if rpdb:
    assert os.readlink('/proc/self/ns/net') != rpdb
    subprocess.run(['/usr/sbin/ip', '-4', 'rule', 'add', 'priority', '220', 'table', '220'], check=True, timeout=4)
    with_foreign_rule = subprocess.check_output(ip_show, timeout=4)

def run(argv, **kw):
    commands.append(list(argv))
    if rpdb and argv in (ip_show, ip6_show, ('/usr/sbin/ip', '-j', '-N', '-4', 'route', 'show', 'table', 'all'),
                         ('/usr/sbin/ip', '-j', '-N', '-4', 'addr', 'show')):
        return subprocess.run(argv, **kw)
    if argv[:4] == ('/usr/bin/systemctl','--no-pager','show','--all'):
        props = argv[4].removeprefix('--property=').split(',')
        data = ''.join(f'{k}={units[argv[5]].get(k, "")}\n' for k in props).encode()
    elif argv == ('/usr/bin/systemctl','--no-pager','list-jobs','--no-legend','--plain'):
        data = b''
    elif argv == ('/usr/bin/systemctl','--no-pager','show-environment'):
        data = b'LANG=C\n'
    elif argv == ip6_show:
        data = b'[]'
    elif argv == ('/usr/bin/dpkg-query', '-W', '-f=$'+'{Version}\\n$'+'{Architecture}\\n$'+'{Conffiles}', 'xl2tpd'):
        version = opts.get('version','1.3.18-1+b1')
        arch = opts.get('arch','amd64')
        lines = [' /etc/xl2tpd/xl2tpd.conf 3c7f48565aff98751a9ef2d734b56405',
                 ' /etc/default/xl2tpd.other 00000000000000000000000000000000']
        if opts.get('record', True):
            lines.append(' ' + path + ' ' + opts.get('recordDigest','fadc31f26078d8c3fb033d7d4516500b'))
            if opts.get('duplicateRecord'):
                lines.append(lines[-1])
        data = '\n'.join([version, arch, '', *lines]).encode()
        return NS(returncode=int(opts.get('queryFailed', False)), stdout=data,
                  stderr=opts.get('queryWarning', '').encode())
    else:
        unmodeled.append(argv)
        raise AssertionError(f'unmodeled command: {argv!r}')
    return NS(returncode=0, stdout=data, stderr=b'')

h.update(subprocess=NS(run=run, PIPE=-1, DEVNULL=-3, TimeoutExpired=h['subprocess'].TimeoutExpired),
         preflight=lambda machine: dict(machineId=machine, ppp=True, unitsLoaded=True, masked=False),
         observe_ppp_preparation=lambda: dict(missing=[], persist=False, builtin=[], policy='fixture'),
         require_network_observers=lambda: None,
         boot=lambda: 'fixture-boot', vpn_empty=lambda **kw: True, sock_rows=lambda: [], nft_tables=lambda: [],
         xray_users=lambda *args: [['tcp','127.0.0.1',8080]])
# The signed settings tree is exercised by rebuildRelayDirectSwanFiles.py;
# this fixture independently exercises the xl2tpd package/defaults gate.
def settings_tree(present, _bad):
    assert not present and h['read'](h['SWAN_PROFILE']) is None
    return h['STOCK_SWAN_SHA']
h['swan_inputs'] = settings_tree
if not rpdb:
    h.update(ip=lambda *args: [], network_projection=lambda *args: dict(nft=None, rule=False, route=False))

machine = 'a'*32
network = dict(clientCidr='10.255.1.0/24', tproxyPort=12345, fwmark=77, routeTable=177)
req = dict(action='prepare' if opts['accept'] else 'install', machineId=machine, network=network,
           backupId='b'*32, baseline='c'*64)
sys.stdin = io.TextIOWrapper(io.BytesIO(json.dumps(req).encode()))
status = h['main']()
assert not unmodeled, unmodeled
assert status == (0 if opts['accept'] else 70), status
assert not backing(h['VAULT']).exists()
assert not backing(h['DROP_DIR']).exists()
assert backing(boot).is_symlink() == bool(opts.get('enabled'))
if rpdb:
    assert h['NO_INSTALL_WRITES'] and list(ip_show) in commands
    assert subprocess.check_output(ip_show, timeout=4) == with_foreign_rule
if opts['accept']:
    before = h['observe'](machine, network)
    assert before['globalFiles'][path] == h['read'](path)
    if opts.get('drift'):
        # These are the real neighbor guards used by verify/rollback and remove.
        # The latter also checks the manifest and binary, which we pin here.
        # The pristine admission must not be rerun against the owned drop-in.
        units[XL]['DropInPaths'] = h['DROP']
        receipt = '/etc/fixture-receipt.json'
        put(receipt, b'{}')
        put(h['XRAY'], b'fixture binary', 0o755)
        state = dict(before=before, path=receipt, manifest=h['read'](receipt),
                     manifest_generation=h['remove_generation'](receipt), binary=h['remove_generation'](h['XRAY']))
        def guard_neighbors(mutated=False):
            for check, arg, code in (('neighbors', before, 'ROLLBACK_DRIFT'),
                                     ('removal_neighbors', state, 'RUNTIME_UNPROVED')):
                try:
                    h[check](arg)
                except h['Refusal'] as e:
                    assert mutated and str(e) == code, (check, str(e))
                else:
                    assert not mutated, check
        guard_neighbors()
        f = backing(path)
        original = f.read_bytes()
        assert h['uncomment'](original) == [b'XL2TPD_RUN_DIR="/var/run/xl2tpd"', b'DAEMON_OPTS=""']
        for changed in (b'# altered\n' + original, b''):
            f.write_bytes(changed)
            guard_neighbors(mutated=True)
        f.write_bytes(original)
        f.chmod(0o600)
        guard_neighbors(mutated=True)
        f.unlink()
        guard_neighbors(mutated=True)
        put(path, original)
        guard_neighbors()
if opts['defaults'] is None:
    assert not any(argv[0] == '/usr/bin/dpkg-query' for argv in commands)
`;

const packaged = '/usr/lib/systemd/system/xl2tpd.service';
const scenarios = [
    ['exact two stock assignments and complete conffile', { accept: true, drift: true }],
    ['exact defaults on pre-enabled helper', { accept: true, enabled: true }],
    ['absent defaults on the minimal layout', { accept: true, defaults: null, fragment: packaged }],
    ['absent defaults on the disabled helper layout', { accept: true, defaults: null }],
    ['unrecorded inert defaults on the minimal layout', { accept: true, defaults: '# local placeholder\n', record: false, fragment: packaged, version: '1.3.18-1' }],
    ['stock edited to empty', { defaults: '' }],
    ['stock edited to comments only', { defaults: '# local placeholder\n' }],
    ['same active lines, changed comment', { defaults: '# local edition\n' + defaults }],
    ['only the two assignments, without stock comments', { defaults: 'XL2TPD_RUN_DIR="/var/run/xl2tpd"\nDAEMON_OPTS=""\n' }],
    ['changed daemon options', { defaults: defaults.replace('DAEMON_OPTS=""', 'DAEMON_OPTS="-D"') }],
    ['additional assignment', { defaults: defaults + 'ADDITIONAL=""\n' }],
    ['looser group-write mode', { mode: 0o664 }],
    ['non-exact read-only mode', { mode: 0o600 }],
    ['non-root file group', { gid: 1 }],
    ['non-root file owner', { uid: 1 }],
    ['symlink', { symlink: true }],
    ['hardlink', { hardlink: true }],
    ['missing conffile record with active defaults', { record: false }],
    ['different conffile record', { recordDigest: '00000000000000000000000000000000' }],
    ['obsolete stock conffile record', { recordDigest: 'fadc31f26078d8c3fb033d7d4516500b obsolete' }],
    ['duplicate stock conffile records', { duplicateRecord: true }],
    ['failed conffile query cannot admit inert file', { defaults: '# local placeholder\n', record: false, queryFailed: true }],
    ['warning from conffile query prevents admission', { queryWarning: 'dpkg-query: warning: fixture\n' }],
    ['different package version', { version: '1.3.18-1' }],
    ['different package architecture', { arch: 'arm64' }],
    ['native packaged unit is not the exact helper', { fragment: packaged }],
    ['SysV wrapper stays refused even with no defaults', { fragment: '/run/systemd/generator.late/xl2tpd.service', defaults: null }],
    ['modified helper is refused', { editedUnit: true }],
    ['helper with looser mode is refused', { unitMode: 0o664 }],
    ['helper with non-root group is refused', { unitGid: 1 }],
    ['drop-in is refused even with no defaults', { defaults: null, unit: { DropInPaths: '/etc/systemd/system/xl2tpd.service.d/foreign.conf' } }],
    ['loaded helper that reads defaults is refused', { unit: { EnvironmentFiles: '/etc/default/xl2tpd (ignore_errors=yes)' } }],
    ['loaded helper with reload pending is refused', { unit: { NeedDaemonReload: 'yes' } }],
    ['loaded helper with SysV source is refused', { unit: { SourcePath: '/etc/init.d/xl2tpd' } }],
    ['loaded helper with stop hook is refused', { unit: { ExecStop: '{ path=/etc/init.d/xl2tpd ; argv[]=/etc/init.d/xl2tpd stop ; }' } }],
    ['loaded helper with second start command is refused', { unit: { ExecStart: '{ path=/usr/sbin/xl2tpd ; argv[]=/usr/sbin/xl2tpd -D ; } { path=/etc/init.d/xl2tpd ; argv[]=/etc/init.d/xl2tpd start ; }' } }],
];

for (const [name, changes] of scenarios) {
    test(`DIRECT xl2tpd defaults: ${name}`, () => {
        const opts = { defaults, accept: false, ...changes };
        const dir = mkdtempSync(join(process.cwd(), '.direct-defaults-fixture-'));
        try {
            const result = spawnSync('python3', ['-I', '-B', '-c', harness,
                join(__dirname, '../rebuildRelayDirectHost.py'),
                join(__dirname, '../../modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py'), dir],
            { encoding: 'utf8', input: JSON.stringify(opts), timeout: 10000 });
            assert.equal(result.status, 0, result.stderr || result.error?.message);
            assert.equal(result.stderr, opts.accept ? '' : 'DIRECT_NO_WRITE_PREREQUISITE\n');
            if (opts.accept) {
                const prepared = JSON.parse(result.stdout);
                assert.match(prepared.baseline, /^[0-9a-f]{64}$/);
                assert.equal(prepared.main, '{}');
            } else assert.equal(result.stdout, '');
        } finally { rmSync(dir, { recursive: true, force: true }); }
    });
}

test('DIRECT install refuses an unattributed rule 220 before any write', t => {
    const unshare = '/usr/bin/unshare';
    const flags = ['--user', '--map-root-user', '--net', '--'];
    if (process.platform !== 'linux' || ![unshare, '/usr/sbin/ip', '/usr/bin/python3'].every(existsSync)) {
        t.skip('requires Linux local namespace tools');
        return;
    }
    const probe = spawnSync(unshare, [...flags, '/usr/bin/true'], { encoding: 'utf8', timeout: 3000 });
    if (probe.status !== 0 && /Operation not permitted|Permission denied/.test(probe.stderr ?? '')) {
        t.skip('unprivileged user/network namespaces unavailable');
        return;
    }
    assert.equal(probe.status, 0, probe.stderr || probe.error?.message);
    const dir = mkdtempSync(join(process.cwd(), '.direct-rpdb-fixture-'));
    try {
        const result = spawnSync(unshare, [...flags, '/usr/bin/python3', '-I', '-B', '-c', harness,
            join(__dirname, '../rebuildRelayDirectHost.py'),
            join(__dirname, '../../modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py'), dir],
        { encoding: 'utf8', input: JSON.stringify({ accept: false, defaults: null,
            rpdbNetns: readlinkSync('/proc/self/ns/net') }), timeout: 10000 });
        assert.equal(result.status, 0, result.stderr || result.error?.message);
        assert.equal(result.stdout, '');
        assert.equal(result.stderr, 'DIRECT_NO_WRITE_RULE_220_CONFLICT\n');
    } finally { rmSync(dir, { recursive: true, force: true }); }
});
