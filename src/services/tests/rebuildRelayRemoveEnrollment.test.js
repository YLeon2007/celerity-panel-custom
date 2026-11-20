'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { join, dirname } = require('node:path');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { composeRebuildRelayPair } = require('../rebuildRelayInstallSteps');
const { composeRebuildProfiles } = require('../../modules/relay-l2tp/tests/helpers/rebuildComposerFixture');
const stockSwan = require('./helpers/rebuildRelayStockSwan');

const nodeId = 'a'.repeat(24), backupId = 'b'.repeat(32), machineId = 'c'.repeat(32);
const network = { clientCidr: '10.255.1.0/24', tproxyPort: 12345, fwmark: 77, routeTable: 177 };
const node = { _id: nodeId, cascadeRole: 'relay', type: 'xray', active: true, ip: '192.0.2.19', port: 22001,
    xray: { inboundTag: 'client', security: 'none', transport: 'tcp', apiPort: 31001 } };
const controls = ['panel.test.invalid', node.ip];
const main = (relay, follow) => composeRebuildProfiles({ nodes: [relay], links: [], controlPlaneAddresses: controls,
    usersByNode: { [nodeId]: [] }, followRelayStates: follow ? [{ node: nodeId, status: 'installed',
        desiredState: 'installed', routingMode: 'follow-relay', routingVersion: 1, secretRevision: 1,
        tproxyPort: network.tproxyPort }] : [],
}).find(p => p.nodeId === nodeId && p.profile === 'main').config;
const stockMain = JSON.stringify(main(node, false));
const installed = composeRebuildRelayPair({ main: stockMain, bridge: null }, { nodeId,
    tproxyPort: network.tproxyPort, carryDomain: false, controlPlaneAddresses: controls,
    mainSha256: createHash('sha256').update(stockMain).digest('hex'), bridgeSha256: null }).main;
const later = { ...node, port: 22019, aclRules: ['reject(deny.test.invalid)'] };
const xl = 'xl2tpd.service', ike = 'strongswan-starter.service', x = 'xray.service', b = 'xray-bridge.service';
const net = 'celerity-rebuild-l2tp-network.service', system = '/etc/systemd/system';
const boot = `${system}/multi-user.target.wants/${xl}`, mpath = '/usr/local/etc/xray/config.json';
const bpath = '/usr/local/etc/xray-bridge/config.json';
const nft = `create table inet celerity_rebuild_l2tp {\n    comment "${backupId}"\n}\n`;
const v = { machineId, backupId, network, nodeId };

// Reuse the joined install host's filesystem and command facade, adding only
// remove-side manager behavior/faults. No production command can be spawned.
const shim = String.raw`
from pathlib import Path
import sys
from types import SimpleNamespace
helper = sys.argv.pop(1)
case = sys.argv.pop(2)
source = Path(helper).read_text()
marker = 'h.update(os=LocalOS()'
assert source.count(marker) == 1
extension = r'''
_stock_run, _stock_reload, _stock_sockets = run, reloaded, sockets

def reloaded():
    _stock_reload()
    u = s['units']
    if backing(h['NET']).exists():
        u[NET].update(Type='oneshot', Requires=X + ' sysinit.target system.slice', RequiredBy=XL)
        u[NET]['After'] = X + ' nftables.service'
        u[X]['RequiredBy'], u[IKE]['RequiredBy'] = NET, XL
    else:
        u[X]['RequiredBy'] = B if case == 'foreign-post-reload' and request['action'] == 'remove' else ''
        u[IKE]['RequiredBy'] = ''
    if request['action'] == 'remove' and not backing(h['NET']).exists() and case == 'foreign-ike-post-reload-dependency':
        u[IKE]['Wants'] = B

def sockets():
    rows = _stock_sockets()

    if request['action'] in ('prepare-remove', 'remove') and case == 'foreign-ike-socket':
        rows.append(('udp', '192.0.2.8', 4500, '999'))
    if request['action'] in ('prepare-remove', 'remove') and case == 'missing-active-socket':
        rows = [row for row in rows if row[2] != 1701]
    return rows

def run(argv, **kwargs):
    if tuple(argv) == ('/usr/sbin/ipsec', 'statusall'):
        if not s['nft']:
            status = 'Connections:\nSecurity Associations (0 up, 0 connecting):\n  none\n'
        elif case == 'active-ike-sa' and request['action'] == 'prepare-remove':
            status = 'Connections:\n  celerity-l2tp: transport\nSecurity Associations (0 up, 1 connecting):\n'
        else:
            status = 'Connections:\n  celerity-l2tp: transport\nSecurity Associations (0 up, 0 connecting):\n  none\n'
        return SimpleNamespace(returncode=0, stdout=status.encode(), stderr=b'')
    action = tuple(argv[2:]) if tuple(argv[:2]) == ('/usr/bin/systemctl', '--no-pager') else ()
    if action == ('start', IKE) and request['action'] == 'remove':
        raise AssertionError('v2 must not restart a pre-existing IKE invocation')
    if action == ('reset-failed', NET):
        s['units'][NET].update(ActiveState='inactive', SubState='dead', MainPID='0', InvocationID='')
        s['effects'].append(list(action))
        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
    result = _stock_run(argv, **kwargs)

    if action == ('stop', XL) and request['action'] == 'remove':
        if case == 'boot-after-stop':
            p = backing(h['XL_BOOT']); q = p.with_suffix('.replacement')
            q.symlink_to(p.readlink()); q.replace(p)
        if case == 'foreign-ike-after-stop':
            s['units'][IKE]['InvocationID'] = 'f' * 32
        if case in ('owned-file-after-stop', 'swan-generation-after-stop'):
            p = backing(h['SWAN_PROFILE'] if case == 'swan-generation-after-stop' else h['NAMES']['options'])
            q = p.with_suffix('.replacement')
            q.write_bytes(p.read_bytes()); q.chmod(p.stat().st_mode & 0o777); q.replace(p)
    return result
'''
exec(compile(source.replace(marker, extension + '\n' + marker), helper, 'exec'))
`;

function setFixtureMode(path, mode) {
    fs.chmodSync(path, mode);
    assert.equal(fs.statSync(path).mode & 0o777, mode, `fixture mode: ${path}`);
}

function host(t, scenario) {
    const root = fs.mkdtempSync(join(process.cwd(), '.relay-remove-join-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const p = path => join(root, path);
    const put = (path, bytes, mode = 0o600) => {
        fs.mkdirSync(dirname(p(path)), { recursive: true, mode: 0o755 });
        fs.writeFileSync(p(path), bytes, { mode });
    };
    const helper = name => join(__dirname, name);
    const unitScript = helper('../../modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py');
    const ensure = spawnSync('/usr/bin/python3', ['-I', '-B', unitScript, root], { encoding: 'utf8' });
    assert.equal(ensure.status, 0, ensure.stderr);
    const initialEnabled = scenario === 'initially-enabled';
    const initialIdle = scenario === 'initially-idle-ike';
    fs.mkdirSync(dirname(p(boot)));
    fs.mkdirSync(p('/var/lib'), { recursive: true });
    fs.mkdirSync(p('/etc/ipsec.d'));
    const swanLeaves = stockSwan.seed(root);
    put('/usr/local/bin/xray', 'modeled executable', 0o755);
    put(mpath, stockMain, 0o640);
    setFixtureMode(p(mpath), 0o640);
    fs.mkdirSync(dirname(p(bpath)), { mode: 0o755 });
    const starter = '/etc/ipsec.conf';
    const vpn = { [starter]: [scenario === 'explicit-ike-include' ? '# stock\nconfig setup\n'
        : '# stock\nconfig setup\ninclude /etc/ipsec.d/*.conf\n', 0o644],
        '/etc/ppp/chap-secrets': ['# stock chap\n', 0o640], '/etc/ipsec.secrets': ['# stock secret\n', 0o640],
        '/etc/xl2tpd/xl2tpd.conf': ['[global]\n', 0o644] };
    for (const [path, [text, mode]] of Object.entries(vpn)) {
        put(path, text, mode);
        setFixtureMode(p(path), mode);
    }
    const native = (name, cmd, more = {}) => ({ LoadState: 'loaded', ActiveState: 'inactive', SubState: 'dead',
        UnitFileState: 'disabled', MainPID: '0', InvocationID: '', NeedDaemonReload: 'no', DropInPaths: '',
        FragmentPath: `${system}/${name}`, ExecStart: cmd, KillMode: 'control-group', PrivateNetwork: 'no',
        Requires: 'sysinit.target system.slice', Conflicts: 'shutdown.target', ...more });
    const original = {
        [xl]: native(xl, '{ path=/usr/sbin/xl2tpd ; argv[]=/usr/sbin/xl2tpd -D ; }', {
            UnitFileState: initialEnabled ? 'enabled' : 'disabled', ControlGroup: `/system.slice/${xl}`,
        }),
        [ike]: native(ike, '{ path=/usr/sbin/ipsec ; argv[]=/usr/sbin/ipsec start --nofork ; }', {
            FragmentPath: `/usr/lib/systemd/system/${ike}`, ControlGroup: `/system.slice/${ike}`, UnitFileState: 'enabled',
            ...(initialIdle && { ActiveState: 'active', SubState: 'running', MainPID: '200', InvocationID: 'c'.repeat(32) }),
        }),
        [x]: native(x, `{ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${mpath} ; }`,
            { ActiveState: 'active', SubState: 'running', MainPID: '101', InvocationID: '65'.padStart(32, '0'),
                UnitFileState: 'enabled', User: 'nobody', ControlGroup: `/system.slice/${x}` }),
        [b]: native(b, '', { LoadState: 'not-found', FragmentPath: '', UnitFileState: '' }),
        [net]: native(net, '', { LoadState: 'not-found', FragmentPath: '', UnitFileState: '' }),
    };
    if (initialEnabled) fs.symlinkSync(`../${xl}`, p(boot));
    const chmodDirs = path => {
        fs.chmodSync(path, 0o755);
        for (const row of fs.readdirSync(path, { withFileTypes: true })) if (row.isDirectory()) chmodDirs(join(path, row.name));
    };
    chmodDirs(root);
    const gid = 65534;
    const manager = 'manager.json';
    const report = () => JSON.parse(fs.readFileSync(p(manager)));
    const set = state => fs.writeFileSync(p(manager), JSON.stringify(state));
    set({ machine: machineId, main: JSON.parse(stockMain), original, units: original, effects: [], nft: null,
        rule: null, route: null, stockRules: [{ priority: 0, src: 'all', table: 255 }, { priority: 32766, src: 'all', table: 254 }, { priority: 32767, src: 'all', table: 253 }],
        rules6: [{ priority: 0, src: 'all', table: 255 }, { priority: 32766, src: 'all', table: 254 }], managerEnvironment: 'LANG=C\n',
        foreign: { sockets: [], routes: [], tables: [], rules: [] },
        running: { [x]: JSON.parse(stockMain) }, charonPid: '201', nextPid: 300,
        ikeConnection: false, lnsMd5: createHash('md5').update(vpn['/etc/xl2tpd/xl2tpd.conf'][0]).digest('hex'),
        packages: ['strongswan', 'strongswan-starter', 'strongswan-charon', 'xl2tpd', 'ppp', 'nftables'],
        owners: { [fs.statSync(p(mpath)).ino]: [65534, gid], ...Object.fromEntries(Object.keys(vpn).map(
            path => [fs.statSync(p(path)).ino, [0, gid]])) } });
    const command = ['/usr/bin/timeout', '-k', '4s', '125s', '/usr/bin/python3', '-I', '-B', '-c',
        fs.readFileSync(helper('../rebuildRelayDirectHost.py'), 'utf8')].map(arg => `'${arg.replaceAll("'", "'\\''")}'`).join(' ');
    const wire = (action, fields = {}) => {
        const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', shim,
            helper('helpers/rebuildRelayInstallHost.py'), root, scenario, 'ike-active'],
        { input: JSON.stringify(command) + '\n' + JSON.stringify({ action, ...fields }), encoding: 'utf8', timeout: 10000 });
        assert.ok(!result.error && [0, 70, 75].includes(result.status), 'local fixture subprocess failed');
        assert.deepEqual(report().faults ?? [], [], 'closed host command model');
        return result;
    };
    const ok = result => {
        assert.equal(result.status, 0, JSON.stringify({ wire: result.stderr.trim(), guard: report().lastRefusal }));
        return JSON.parse(result.stdout);
    };
    const prepared = wire('prepare', { machineId, network });
    if (initialIdle || scenario === 'explicit-ike-include') {
        assert.deepEqual([prepared.status, prepared.stdout, prepared.stderr], [70, '', 'DIRECT_PREREQUISITE\n']);
        assert.deepEqual(report().effects, []);
        assert.deepEqual(report().units, original);
        assert.ok(!fs.existsSync(p(stockSwan.profile)) && !fs.existsSync(p('/var/lib/celerity-rebuild-l2tp-direct')));
        assert.equal(fs.readFileSync(p(starter), 'utf8'), vpn[starter][0]);
        return { prepareRefused: true };
    }
    const plan = ok(prepared);
    const files = { main: installed, nft, chap: '# BEGIN CELERITY MANAGED L2TP USERS\n# END CELERITY MANAGED L2TP USERS\n',
        ...Object.fromEntries(['ike', 'lns', 'options', 'secrets'].map(k => [k, 'fixture-only'])) };
    ok(wire('install', { machineId, network, backupId, baseline: plan.baseline,
        files: Object.fromEntries(Object.entries(files).map(([k, text]) => [k, Buffer.from(text).toString('base64')])) }));
    ok(wire('verify', { machineId, network, backupId, baseline: plan.baseline }));
    const manifest = `/var/lib/celerity-rebuild-l2tp-direct/${backupId}/manifest.json`;
    const saved = fs.readFileSync(p(manifest));
    const identity = path => {
        const s = fs.lstatSync(p(path), { bigint: true });
        return [s.dev, s.ino, s.ctimeNs];
    };
    const owner = path => report().owners[fs.statSync(p(path)).ino];
    const replaceBoot = target => {
        fs.symlinkSync(target, p(boot + '.other'));
        fs.renameSync(p(boot + '.other'), p(boot));
    };
    return { p, put, wire, ok, report, set, saved, manifest, vpn, starter, owner, identity, replaceBoot,
        swanLeaves, initialEnabled, intent: dirname(manifest) + '/remove-attempt.json' };
}

const refusals = new Set(['boot-same-target', 'boot-other-target', 'boot-before-remove', 'boot-missing', 'boot-regular-file', 'missing-active-socket',
    'foreign-ike-socket', 'foreign-include', 'active-ike-sa', 'foreign-dependency']);
const uncertain = new Set(['boot-after-stop', 'swan-generation-after-stop', 'foreign-ike-after-stop', 'foreign-post-reload',
    'owned-file-after-stop', 'foreign-ike-post-reload-dependency']);
for (const scenario of ['stock', 'apply-live', 'apply-quiescent', 'inactive-ike', 'initially-enabled', 'initially-idle-ike', 'explicit-ike-include', ...refusals, ...uncertain]) {
    test(`stock DIRECT remove: ${scenario}`, t => {
        const f = host(t, scenario);
        if (f.prepareRefused) {
            assert.ok(['initially-idle-ike', 'explicit-ike-include'].includes(scenario));
            return;
        }
        const s = f.report(), apply = scenario.startsWith('apply-');
        const swanBefore = new Map(f.swanLeaves.map(path => [path, f.identity(path)]));
        const swanGeneration = f.identity(stockSwan.profile);
        let neighbor;
        if (apply) {
            const replacement = f.p(mpath + '.apply');
            fs.writeFileSync(replacement, JSON.stringify(main(later, true)), { mode: 0o644 });
            setFixtureMode(replacement, 0o644);
            fs.renameSync(replacement, f.p(mpath));
            s.owners[fs.statSync(f.p(mpath)).ino] = [0, 65534];
            Object.assign(s.units[x], { MainPID: '401', InvocationID: '191'.padStart(32, '0') });
            s.running[x] = main(later, true);
            neighbor = JSON.stringify({ inbounds: [{ tag: 'neighbor', listen: '127.0.0.1', port: 30201, protocol: 'vless' }],
                outbounds: [], routing: { rules: [] } });
            f.put(bpath, neighbor, 0o640);
            s.running[b] = JSON.parse(neighbor);
            s.owners[fs.statSync(f.p(bpath)).ino] = [65534, 65534];
            Object.assign(s.units[b], { ActiveState: 'active', SubState: 'running', LoadState: 'loaded',
                MainPID: '402', InvocationID: '192'.padStart(32, '0'), UnitFileState: 'enabled', User: 'nobody', ControlGroup: `/system.slice/${b}`,
                FragmentPath: `${system}/${b}`, ExecStart: `{ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${bpath} ; }` });
            if (scenario === 'apply-quiescent') {
                for (const n of [xl, ike]) Object.assign(s.units[n], { ActiveState: 'inactive', SubState: 'dead', MainPID: '0', InvocationID: '' });
                Object.assign(s.units[net], { ActiveState: 'failed', SubState: 'failed', MainPID: '0', InvocationID: '193'.padStart(32, '0') });
            }
        }
        if (scenario === 'boot-same-target') f.replaceBoot(`${system}/${xl}`);
        if (scenario === 'boot-other-target') f.replaceBoot(`../${xl}`);
        if (['boot-missing', 'boot-regular-file'].includes(scenario)) fs.unlinkSync(f.p(boot));
        if (scenario === 'boot-regular-file') fs.writeFileSync(f.p(boot), 'not a symlink');
        if (scenario === 'foreign-include') fs.writeFileSync(f.p('/etc/ipsec.d/foreign.conf'), 'foreign');
        if (scenario === 'foreign-dependency') s.units[ike].RequiredBy += ` ${b}`;
        const bootBefore = scenario === 'boot-missing' ? null : f.identity(boot), starterBefore = f.identity(f.starter);
        const bridgeBefore = apply ? f.identity(bpath) : null;
        const effectsBefore = s.effects.length;
        f.set(s);
        const prepared = f.wire('prepare-remove', v);
        assert.equal(f.report().effects.length, effectsBefore);
        assert.ok(!fs.existsSync(f.p(f.intent)));
        if (refusals.has(scenario) && scenario !== 'boot-before-remove') {
            const reason = ['missing-active-socket', 'foreign-ike-socket'].includes(scenario) ? 'RUNTIME_UNPROVED' : 'ROLLBACK_DRIFT';
            assert.deepEqual([prepared.status, prepared.stdout, prepared.stderr], [70, '', `DIRECT_${reason}\n`], JSON.stringify(f.report().lastRefusal));
            if (bootBefore) assert.deepEqual(f.identity(boot), bootBefore);
            else assert.throws(() => fs.lstatSync(f.p(boot)), { code: 'ENOENT' });
            return;
        }
        const proof = f.ok(prepared);
        if (scenario === 'boot-before-remove') f.replaceBoot(`${system}/${xl}`);
        const removed = f.wire('remove', { ...v, baseline: proof.baseline }), after = f.report();
        assert.ok(fs.readFileSync(f.p(f.manifest)).equals(f.saved));
        if (scenario === 'boot-before-remove') {
            assert.deepEqual([removed.status, removed.stdout, removed.stderr], [70, '', 'DIRECT_REMOVE_REFUSED\n']);
            assert.equal(after.effects.length, effectsBefore);
            assert.ok(!fs.existsSync(f.p(f.intent)));
            return;
        }
        assert.ok(fs.existsSync(f.p(f.intent)));
        const effects = after.effects.slice(effectsBefore);
        if (uncertain.has(scenario)) {
            assert.deepEqual([removed.status, removed.stdout, removed.stderr], [75, '', '']);
            assert.notEqual(f.wire('prepare-remove', v).status, 0);
            if (scenario === 'boot-after-stop') assert.notDeepEqual(f.identity(boot), bootBefore);
            if (scenario === 'foreign-ike-after-stop') assert.ok(!effects.some(e => e.join(' ') === `stop ${ike}`));
            if (scenario === 'foreign-post-reload') assert.ok(!effects.some(e => e[0] === 'restart'));
            if (scenario === 'foreign-ike-post-reload-dependency') {
                assert.ok(effects.some(e => e[0] === 'daemon-reload'));
                assert.ok(!effects.some(e => e[0] === 'restart' || e[0] === 'delete' || e.includes('del')));
            }
            if (scenario === 'owned-file-after-stop') assert.deepEqual(f.identity(boot), bootBefore);
            if (scenario === 'swan-generation-after-stop') {
                assert.notDeepEqual(f.identity(stockSwan.profile), swanGeneration);
                assert.ok(!effects.some(e => e.join(' ') === `stop ${ike}`));
                assert.equal(after.nft, backupId);
            }
            return;
        }
        assert.deepEqual(f.ok(removed), { ok: true, backupId, removed: true });
        if (f.initialEnabled) assert.deepEqual(f.identity(boot), bootBefore);
        else assert.throws(() => fs.lstatSync(f.p(boot)), { code: 'ENOENT' });
        assert.equal(after.units[xl].UnitFileState, f.initialEnabled ? 'enabled' : 'disabled');
        assert.equal(after.units[xl].ActiveState, 'inactive');
        assert.equal(after.units[net].LoadState, 'not-found');
        assert.equal(after.units[x].RequiredBy, '');
        assert.equal(after.units[ike].ActiveState, 'inactive');
        assert.equal(after.units[ike].MainPID, '0');
        assert.ok(!fs.existsSync(f.p(stockSwan.profile)));
        for (const [path, identity] of swanBefore) assert.deepEqual(f.identity(path), identity);
        assert.equal(after.nft, null);
        assert.equal(after.rule, null);
        assert.equal(after.route, null);
        for (const kind of ['rule', 'route']) assert.ok(effects.some(e => e.slice(0, 3).join(' ') === `-4 ${kind} del`));
        if (apply) {
            assert.deepEqual(f.identity(bpath), bridgeBefore);
            assert.equal(fs.readFileSync(f.p(bpath), 'utf8'), neighbor);
            assert.deepEqual(f.owner(bpath), [65534, 65534]);
            assert.deepEqual(after.units[b], s.units[b]);
            assert.ok(!effects.some(effect => effect.includes(b)));
        }
        assert.deepEqual(JSON.parse(fs.readFileSync(f.p(mpath))), apply ? main(later, false) : JSON.parse(stockMain));
        assert.deepEqual(f.owner(mpath), [apply ? 0 : 65534, 65534]);
        assert.equal(fs.statSync(f.p(mpath)).mode & 0o777, apply ? 0o644 : 0o640);
        for (const [path, [bytes, mode]] of Object.entries(f.vpn)) {
            assert.equal(fs.readFileSync(f.p(path), 'utf8'), bytes);
            assert.equal(fs.statSync(f.p(path)).mode & 0o777, mode);
            assert.deepEqual(f.owner(path), [0, 65534]);
        }
        assert.deepEqual(f.identity(f.starter), starterBefore);
        assert.ok(!effects.some(e => ['restart', 'start'].includes(e[0]) && e[1] === ike));
    });
}
