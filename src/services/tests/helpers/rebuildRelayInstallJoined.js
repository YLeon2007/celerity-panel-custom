'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { EventEmitter } = require('node:events');
const { Client } = require('ssh2');
const { generateXrayConfigWithApi, generateXraySystemdService, generateBridgeSystemdService } = require('../../configGenerator');
const { composeRebuildProfiles } = require('../../../modules/relay-l2tp/services/rebuildTopologyComposer');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const { tmpdir } = require('node:os');
const { join, dirname } = require('node:path');
const applyWire = require('./rebuildRelayApplyWire');
const { rebuildApplyMachineGuard } = require('./rebuildApplyMachineGuard');
const stockSwan = require('./rebuildRelayStockSwan');
const { handler: installHandler } = require('../../../routes/panel/rebuildRelayInstall');

const xlPackageFiles = {
    '/etc/init.d/xl2tpd': '5d8342a68119d1b25daf55d4e6d8dfac6b4443103eef4c17f267461433afc914',
    '/etc/default/xl2tpd': '37b5938f462ec60b4f8c179b34f70b548c09da4691c938e88ce111ce41268833',
    '/etc/xl2tpd/xl2tpd.conf': '6059e4ca86e092a982f9c55e437f2595284b542c992199b410e2503afeec5659',
};
const starterFiles = {
    '/etc/ipsec.conf': '6a54e39267b981ca3239cd93579f26b5699983021a0d636408fdd5c70f3024d1',
    '/etc/ipsec.secrets': 'ad4e4802bdfeeb8d0133650707e18863e3fe1d95a0c3e3b34343c15553cc59bd',
    '/usr/lib/systemd/system/strongswan-starter.service': '7cff4bbc1bce2eafdc2456e93a20515094129f4ee9a9ab17dea900f1cfe71a27',
};
const generatedPath = '/run/systemd/generator.late/xl2tpd.service';
const generatedAlias = '/run/systemd/generator.late/l2tpd.service';
const foreignDropIn = '/run/systemd/system/l2tpd.service.d/foreign.conf';
const foreignFragment = '/usr/local/lib/systemd/system/l2tpd.service';
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function seedNativeStock(put, root, generated) {
    // Extract data only from the previously verified Debian archives. The
    // starter extract can be merged with the xl2tpd extract for this fixture.
    const xl = process.env.C3_VERIFIED_XL2TPD_EXTRACT;
    const starter = process.env.C3_VERIFIED_SWAN_STARTER_EXTRACT || xl;
    for (const [source, files] of [[xl, xlPackageFiles], [starter, starterFiles]]) {
        assert.ok(source?.startsWith('/') && fs.realpathSync(source) !== '/', 'require private Debian package extract');
        for (const [path, digest] of Object.entries(files)) {
            const file = join(source, path), info = fs.lstatSync(file), bytes = fs.readFileSync(file);
            assert.ok(info.isFile());
            assert.equal(sha256(bytes), digest, path);
            put(path, bytes, info.mode & 0o777);
        }
    }
    if (generated) {
        const executable = fs.readFileSync(join(process.env.C3_FIXTURE_GENERATOR_EXTRACT, '/usr/lib/systemd/system-generators/systemd-sysv-generator'));
        assert.equal(sha256(executable), '662f91830e6f76e08a47be605ba2480ae87add1eac44aa095629bc0a4484cb11');
        put('/usr/lib/systemd/system-generators/systemd-sysv-generator', executable, 0o755);
        // Same no-start-links generator bytes as test_rebuild_relay_stock_runtime.py.
        const wrapper = fs.readFileSync(join(__dirname, 'trixie-xl2tpd-generated.fixture'));
        assert.equal(sha256(wrapper), '02a7d3131dd4be414a8cc025ca4144edd904f01d644572aec4722b14182ca2a3');
        put(generatedPath, wrapper, 0o644);
        fs.symlinkSync('xl2tpd.service', join(root, generatedAlias));
    }
}

module.exports = ({ fixture, sessionFixture, accountIntentFixture, id, oid, machineId, decrypt, wireOnly = false }) => {
    if (!wireOnly) test.after(() => require.cache[require.resolve('../../sshPoolService')]?.exports.closeAll());

    function seedHost(t, f, relay, machineId, scenario, { preEnabled = false, idleIke = false, subscribers = [], lifecycle = false,
        mainUid = 65534, cohort = false } = {}) {
        const id = String(relay._id);
        const number = f.nodes.indexOf(relay);
        const nativeStock = scenario.startsWith('native-stock-');
        const root = fs.mkdtempSync(join(nativeStock ? tmpdir() : process.cwd(), '.relay-install-join-'));
        t.after(() => fs.rmSync(root, { recursive: true, force: true }));
        const put = (file, bytes, mode = 0o600) => {
            const path = join(root, file);
            fs.mkdirSync(dirname(path), { recursive: true, mode: 0o755 });
            fs.writeFileSync(path, bytes, { mode });
            fs.chmodSync(path, mode);
            return path;
        };
        const mainPath = '/usr/local/etc/xray/config.json', bridgePath = '/usr/local/etc/xray-bridge/config.json';
        const xl = 'xl2tpd.service', ike = 'strongswan-starter.service', x = 'xray.service', b = 'xray-bridge.service';
        const net = 'celerity-rebuild-l2tp-network.service';
        const bootLink = '/etc/systemd/system/multi-user.target.wants/' + xl;
        const nativePath = '/etc/systemd/system/' + xl;
        const barePackages = scenario === 'fresh-stock-runtime';
        const generatedStock = nativeStock && scenario !== 'native-stock-missing';
        const freshStock = barePackages || nativeStock;
        const stock = join(__dirname, '../../../modules/relay-l2tp/node-artifacts/l2tp');
        const key = Buffer.from('synthetic SSH wire key:' + id);
        const pin = createHash('sha256').update(key).digest('hex');
        Object.assign(relay, { port: 21443, xray: { apiPort: 61001, security: 'none' },
            aclRules: ['reject(denied.invalid)'], ssh: { username: 'root', port: 22, password: 'local-fixture-only' } });
        const exit = { _id: oid((number ? '9' : 'd').repeat(24)), type: 'xray', active: true, ip: `192.0.2.${99 - number}`,
            cascadeRole: 'bridge', ssh: relay.ssh };
        f.nodes.push(exit);
        f.links.push({ _id: oid((number ? '5' : 'e').repeat(24)), portalNode: relay._id, bridgeNode: exit._id,
            tunnelProtocol: 'vmess', tunnelPort: 20443, tunnelUuid: '7b159424-f38c-4869-bbf8-cb426fa00354',
            mode: 'forward', active: true, status: scenario === 'offline' ? 'offline' : 'deployed' });
        if (scenario === 'transit-forward') {
            const [link] = f.links;
            const portal = { ...exit, _id: oid('8'.repeat(24)), cascadeRole: 'portal', ip: '192.0.2.88' };
            f.nodes.push(portal);
            f.links.push({ ...link, _id: oid('d'.repeat(24)), portalNode: portal._id, bridgeNode: relay._id,
                tunnelPort: 20444, tunnelProtocol: 'vless', tunnelSecurity: 'tls', tlsServerName: 'test.invalid' });
        } else if (scenario.startsWith('transit-') && scenario !== 'transit-foreign') {
            Object.assign(f.links[0], { mode: 'reverse', tunnelProtocol: 'vless', tunnelSecurity: 'reality',
                realityDest: 'test.invalid:443', realitySni: ['test.invalid'], realityShortIds: ['0123abcd'],
                realityPrivateKey: 'fixture-private', realityPublicKey: 'fixture-public' });
        }
        const usersByNode = { [id]: subscribers };
        const dialerVersions = new Map([[String(exit._id), '26.3.27']]); // Matches the apply-wire fixture.
        const generated = composeRebuildProfiles({ nodes: f.nodes, links: f.links, usersByNode, dialerVersions });
        // Use the same unmodified pretty JSON as regular Setup for the negative.
        const setupMain = scenario === 'legacy-setup-profile' ? generateXrayConfigWithApi(relay, subscribers) : null;
        const main = setupMain ? JSON.parse(setupMain) : generated.find(row => row.nodeId === id && row.profile === 'main').config;
        const bridge = generated.find(row => row.nodeId === id && row.profile === 'bridge').config;
        if (scenario === 'transit-drift') {
            main.inbounds.find(row => row.tag === 'rebuild-rp-conn-eeeeeeee').settings.clients[0].id =
                '00000000-0000-4000-8000-000000000007';
        }
        if (scenario === 'transit-mixed') {
            main.inbounds.find(row => row.tag === 'rebuild-rp-conn-eeeeeeee').settings.clients.push({
                email: 'fixture-other', id: '00000000-0000-4000-8000-000000000007',
            });
        }
        if (scenario.startsWith('transit-ambiguous')) {
            const field = scenario === 'transit-ambiguous-ascii' ? 'Clients' : 'client\u017f';
            main.inbounds.find(row => row.tag === 'rebuild-rp-conn-eeeeeeee').settings[field] = [];
        }
        if (scenario === 'transit-foreign') {
            main.inbounds.push({ tag: 'rebuild-rp-conn-eeeeeeee', port: 20444, listen: '0.0.0.0', protocol: 'vless',
                settings: { clients: [{ id: '00000000-0000-4000-8000-000000000007' }] } });
        }
        if (scenario.startsWith('sidecar')) {
            // Put the stock decision suffix behind an already-owned loopback listener.
            const shared = 'rebuild-relay-ingress', port = 24081;
            bridge.inbounds.push({ tag: shared, port, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' } });
            bridge.outbounds.push(...main.outbounds.splice(1));
            bridge.routing.rules = main.routing.rules.filter(row => row.outboundTag !== 'API').map(row => ({ ...row, inboundTag: [shared] }));
            main.routing.rules = main.routing.rules.filter(row => !row.ruleTag?.startsWith('rebuild-policy-'));
            main.outbounds.push({ tag: 'relay-policy', protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port }] } });
            main.routing.rules.push({ type: 'field', inboundTag: [main.inbounds[0].tag], outboundTag: 'relay-policy' });
            if (scenario === 'sidecar-unsafe') {
                bridge.outbounds.push({ tag: 'bad-direct', protocol: 'freedom' });
                bridge.routing.rules.unshift({ type: 'field', outboundTag: 'bad-direct' });
            }
        }
        const bridgeActive = bridge.inbounds.length > 0;
        const mainMode = 0o640, bridgeMode = lifecycle && bridgeActive ? 0o644 : 0o640;
        const mpath = put(mainPath, setupMain ?? JSON.stringify(main), mainMode), bpath = put(bridgePath, JSON.stringify(bridge), bridgeMode);
        put('/usr/local/bin/xray', 'modeled executable\n', 0o755);
        put('/etc/systemd/system/' + x, generateXraySystemdService(), 0o644);
        if (bridgeActive) put('/etc/systemd/system/' + b, generateBridgeSystemdService(), 0o644);
        fs.mkdirSync(dirname(join(root, bootLink)), { recursive: true, mode: 0o755 });
        fs.mkdirSync(join(root, 'var/lib'), { recursive: true, mode: 0o755 });
        put('/etc/ppp/chap-secrets', '# stock chap\n', lifecycle ? 0o640 : 0o600);
        put('/etc/ppp/options', '# stock options\n');
        put('/etc/systemd/system/foreign.service', '[Service]\nExecStart=/bin/false\n', 0o644);
        fs.mkdirSync(join(root, 'etc/ipsec.d'), { mode: 0o755 });
        let lns;
        if (nativeStock) {
            seedNativeStock(put, root, generatedStock);
            if (scenario === 'native-stock-orphan-wrapper') {
                fs.unlinkSync(join(root, '/usr/lib/systemd/system-generators/systemd-sysv-generator'));
            }
            put('/usr/lib/os-release', 'ID=debian\nVERSION_CODENAME=trixie\n', 0o644);
            lns = fs.readFileSync(join(root, '/etc/xl2tpd/xl2tpd.conf'));
            if (scenario === 'native-stock-dropin') put(foreignDropIn, '[Service]\nEnvironment=FIXTURE=foreign\n', 0o644);
            if (scenario === 'native-stock-fragment') put(foreignFragment, '[Service]\nExecStart=/bin/false\n', 0o644);
        } else {
            lns = '; package conffile\n[global]\n';
            put('/etc/xl2tpd/xl2tpd.conf', lns, 0o644);
            put('/etc/ipsec.secrets', '# stock secrets\n');
            put('/etc/ipsec.conf', '# stock starter\nconfig setup\n');
            put('/usr/lib/systemd/system/' + ike, '[Service]\nExecStart=/usr/sbin/ipsec start --nofork\n', 0o644);
        }
        // The refusal-only variant cannot reach settings-tree observation.
        // Use the authenticated fixture when supplied; do not invent its bytes.
        const swanLeaves = !barePackages || process.env.C3_FIXTURE_SWAN_ETC ? stockSwan.seed(root) : [];
        const packages = ['strongswan', 'strongswan-starter', 'strongswan-charon', 'xl2tpd', 'ppp', 'nftables'];
        if (!freshStock) {
            // One absolute path projected; the shipped ensure helper is used unchanged.
            put('bin/dpkg-query', `#!/bin/sh\n[ "$#" -eq 3 ] && [ "$1" = -W ] && [ "$2" = '-f=\${db:Status-Abbrev}' ] || exit 91\ncase "$3" in ${packages.join('|')}) printf 'ii ';; *) exit 91;; esac\n`, 0o700);
            put('bin/apt-get', '#!/bin/sh\nexit 92\n', 0o700);
            put('bin/systemctl', '#!/bin/sh\ncase "$*" in "show xl2tpd.service --value -p LoadState") printf "not-found\\n";; daemon-reload) test -f "$ROOT/etc/systemd/system/xl2tpd.service";; *) exit 93;; esac\n', 0o700);
            put('bin/python3', '#!/bin/sh\n[ "$#" -eq 1 ] && [ "$1" = "$ROOT/ensure-xl2tpd-unit.py" ] || exit 94\nexec /usr/bin/python3 -I -B "$1" "$ROOT"\n', 0o700);
            for (const name of ['grep', 'dirname']) fs.symlinkSync('/usr/bin/' + name, join(root, 'bin', name));
            const script = fs.readFileSync(join(stock, 'install-runtime.sh'), 'utf8');
            const absolute = "readonly IPSEC_CONF='/etc/ipsec.conf'";
            assert.equal(script.split(absolute).length, 2);
            fs.symlinkSync(join(stock, 'ensure-xl2tpd-unit.py'), join(root, 'ensure-xl2tpd-unit.py'));
            const runtime = put('install-runtime.sh', script.replace(absolute, 'readonly IPSEC_CONF="$ROOT/etc/ipsec.conf"'));
            const prereq = spawnSync('/bin/bash', [runtime],
                { env: { ROOT: root, PATH: join(root, 'bin') }, encoding: 'utf8', timeout: 10000 });
            assert.equal(prereq.status, 0, prereq.stderr);
            assert.deepEqual(JSON.parse(prereq.stdout), { status: 'ok', changed: 2, present: 6 });
        }
        const unit = (path, extra = {}) => ({ LoadState: 'loaded', UnitFileState: 'disabled', ActiveState: 'inactive', SubState: 'dead',
            FragmentPath: path, MainPID: '0', InvocationID: '', DropInPaths: '', NeedDaemonReload: 'no', PrivateNetwork: 'no',
            KillMode: 'control-group', User: '', ...extra });
        const stockX = (name, path, active, pid) => unit('/etc/systemd/system/' + name, { User: 'nobody',
            UnitFileState: active ? 'enabled' : 'disabled', ...(active && { ActiveState: 'active', SubState: 'running',
                MainPID: pid, InvocationID: Number(pid).toString(16).padStart(32, '0'), ControlGroup: '/system.slice/' + name }),
            ExecStart: `{ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${path} ; }` });
        const original = {
            [x]: stockX(x, mainPath, true, '101'), [b]: bridgeActive ? stockX(b, bridgePath, true, '103') : unit('', { LoadState: 'not-found', UnitFileState: '' }),
            [xl]: generatedStock ? unit(generatedPath, { UnitFileState: 'generated', SourcePath: '/etc/init.d/xl2tpd',
                KillMode: 'process', Type: 'forking', Restart: 'no', RemainAfterExit: 'yes',
                ...(scenario === 'native-stock-active' && { ActiveState: 'active', SubState: 'running', MainPID: '202', InvocationID: 'd'.repeat(32) }),
            }) : freshStock ? unit('', { LoadState: 'not-found', UnitFileState: '' }) : unit(nativePath, { LoadState: scenario === 'masked' ? 'masked' : 'loaded',
                UnitFileState: scenario === 'masked' ? 'masked' : preEnabled || scenario === 'prewrite' ? 'enabled' : 'disabled',
                ControlGroup: '/system.slice/' + xl, ExecStart: '{ path=/usr/sbin/xl2tpd ; argv[]=/usr/sbin/xl2tpd -D ; }' }),
            [ike]: unit('/usr/lib/systemd/system/' + ike, { ExecStart: '{ path=/usr/sbin/ipsec ; argv[]=/usr/sbin/ipsec start --nofork ; }',
                ControlGroup: '/system.slice/' + ike, ...((idleIke || scenario.startsWith('ike-')) && { ActiveState: 'active', SubState: 'running',
                    MainPID: '200', InvocationID: 'c'.repeat(32), UnitFileState: 'enabled' }) }),
            [net]: unit('', { LoadState: 'not-found', UnitFileState: '' }),
        };
        if (preEnabled || scenario === 'prewrite') {
            fs.symlinkSync(original[xl].FragmentPath, join(root, bootLink));
        }

        if (scenario === 'unit-drift') fs.appendFileSync(join(root, original[xl].FragmentPath), '# changed\n');
        const foreign = { rules: [], routes: [{ dst: '198.51.100.0/24', table: 201, dev: 'fixture0' }],
            tables: [{ table: { family: 'inet', name: 'foreign', comment: 'operator-owned' } }],
            sockets: [['tcp', '192.0.2.4', 39491, '999']] };
        put('/etc/machine-id', machineId + '\n', 0o644);
        const modulesPath = '/etc/modules-load.d/70-celerity-rebuild-l2tp.conf';
        put('/etc/modules-load.d/10-unrelated.conf', '# operator-owned\nloop\n', 0o644);
        if (!barePackages && (!scenario.startsWith('ppp-') || ['ppp-ready', 'ppp-container-ready'].includes(scenario))) {
            put(modulesPath, '# Managed by Celerity rebuild L2TP\nppp_generic\nl2tp_ppp\n', 0o644);
        }
        if (scenario === 'ppp-conflict') put(modulesPath, '# foreign\n', 0o644);
        if (scenario === 'ppp-mask') fs.symlinkSync('/dev/null', join(root, modulesPath));
        if (scenario === 'ppp-shadow-mask') {
            put('/usr/lib/modules-load.d/50-stock.conf', 'l2tp_ppp\n', 0o644);
            fs.symlinkSync('/dev/null', join(root, '/etc/modules-load.d/50-stock.conf'));
        }
        const manager = put('manager.json', JSON.stringify({ packages, machine: machineId, address: relay.ip, cohort, original, units: original,
            missingPackages: barePackages ? ['strongswan-starter', 'xl2tpd'] : scenario === 'package' ? ['ppp'] : [],
            modules: barePackages || ['ppp-both', 'ppp-reservation-ack'].includes(scenario) ? []
                : ['ppp-l2tp', 'ppp-load-failure', 'ppp-load-timeout', 'ppp-no-readback', 'ppp-lost-ack'].includes(scenario)
                ? ['ppp_generic'] : ['ppp_generic', 'l2tp_ppp'],
            running: { [x]: main, ...(bridgeActive && { [b]: bridge }) }, nextPid: 300, charonPid: '201', ikeConnection: false,
            lnsMd5: createHash('md5').update(lns).digest('hex'), effects: [], rule: null, route: null, nft: null, foreign,
            stockRules: [[0, 255], [32766, 254], [32767, 253]].map(([priority, table]) => ({ priority, src: 'all', table: String(table) })),
            rules6: [[0, 255], [32766, 254], ...(scenario === 'foreign-rpdb6' ? [[220, 220]] : [])]
                .map(([priority, table]) => ({ priority, src: 'all', table: String(table) })),
            managerEnvironment: scenario === 'manager-override' ? 'STRONGSWAN_CONF=/fixture-foreign.conf\n' : 'LANG=C\n',
            owners: { [fs.statSync(mpath).ino]: [scenario === 'prewrite' ? 0 : mainUid, 65534], [fs.statSync(bpath).ino]: [0, 65534] } }));
        const actions = [], refusals = [], nativeReplies = [];
        let removeBaseline, expectedRemoveTransit;
        const records = () => JSON.parse(fs.readFileSync(manager, 'utf8'));
        const writeRecords = value => fs.writeFileSync(manager, JSON.stringify(value));
        const applyHandlers = new Map();
        if (lifecycle) {
            const pool = require('../../sshPoolService');
            // Use the supported pool-disabled branch; no settings DB or real SSH.
            const { settingsLoaded, config } = pool;
            pool.settingsLoaded = true;
            pool.config = { ...config, enabled: false };
            t.after(() => Object.assign(pool, { settingsLoaded, config }));
            applyHandlers.set(relay.ip, applyWire({ root, records, writeRecords, mainPath, bridgePath }));
            const peerRoot = join(root, 'peer');
            const peer = { units: {}, effects: [], running: {}, owners: {}, nextPid: 600 };
            for (const { profile, config: cfg } of generated.filter(row => row.nodeId === String(exit._id))) {
                const [name, path] = profile === 'main' ? [x, mainPath] : [b, bridgePath];
                put(join('peer', path), JSON.stringify(cfg), 0o640);
                peer.running[name] = cfg;
                peer.units[name] = stockX(name, path, true, String(++peer.nextPid));
            }
            applyHandlers.set(exit.ip, applyWire({ root: peerRoot, records: () => peer, writeRecords: () => {}, mainPath, bridgePath }));
        }
        const execute = (command, stdin) => {
            const request = JSON.parse(stdin);
            const { action } = request;
            actions.push(action);
            const state = f.states.find(row => String(row.node) === id);
            const rows = f.users.filter(row => String(row.relayNode) === id);
            if (action === 'install') assert.ok(state?.status === 'installing' && rows.length
                && rows.every(user => user.syncStatus === 'pending'));
            if (nativeStock && ['preflight', 'prepare', 'check', 'install', 'verify', 'rollback'].includes(action)) {
                const reserved = ['install', 'verify', 'rollback'].includes(action);
                assert.deepEqual(f.nativeCommits, reserved ? ['commit'] : []);
                assert.equal(f.states.length, Number(reserved));
                assert.equal(f.users.length, Number(reserved));
                if (reserved) {
                    assert.equal(state.status, 'installing');
                    assert.equal(state.backupId, request.backupId);
                    assert.equal(rows[0].syncStatus, 'pending');
                } else {
                    assert.deepEqual(records().effects, []);
                    assert.ok(!present(join(root, nativePath)));
                }
            }
            if (scenario.startsWith('ppp-') && action === 'install') assert.ok(f.lockHeld);
            if (cohort) {
                assert.ok(f.lockHeld);
                assert.equal(request.machineId, machineId);
                if (request.nodeId) assert.equal(request.nodeId, id);
                if (['session-count', 'prepare-remove', 'remove', 'check-chap', 'sync-chap'].includes(action)) {
                    assert.equal(request.currentUsers.length, rows.length);
                    assert.deepEqual(request.currentUsers.map(u => [u.login, u.enabled, u.ipAddress]).sort(), rows
                        .map(u => [u.login, u.enabled, u.ip]).sort());
                }
            }
            if (action === 'prepare-remove' || action === 'remove') {
                assert.ok(f.lockHeld);
                assert.equal(state.status, action === 'remove' ? 'removing' : 'installed');
                assert.ok(rows.length && rows.every(user => user.syncStatus === 'synced'));
                if (!cohort) assert.equal(rows.length, 1);
                const network = Object.fromEntries(['clientCidr', 'tproxyPort', 'fwmark', 'routeTable'].map(key => [key, state[key]]));
                const transit = expectedRemoveTransit ?? [];
                const { currentUsers, expectedCensus, ...rest } = request;
                assert.deepEqual(rest, { action, machineId, nodeId: id, backupId: state.backupId, network, transit,
                    ...(action === 'remove' ? { baseline: removeBaseline } : {}) });
                if (!cohort) assert.ok(!Object.hasOwn(request, 'currentUsers') && !Object.hasOwn(request, 'expectedCensus'));
                if (cohort && action === 'remove') assert.match(expectedCensus, /^[a-f0-9]{64}$/);
            }
            const result = spawnSync('/usr/bin/python3', ['-I', '-B', join(__dirname, 'rebuildRelayInstallHost.py'), root, scenario],
                { input: JSON.stringify(command) + '\n' + stdin, env: {}, encoding: 'utf8', timeout: 10000, maxBuffer: 4 * 1024 * 1024 });
            assert.ok(!result.error && [0, 70, 75].includes(result.status), 'local DIRECT harness exit: ' + (result.error?.code ?? result.status));
            assert.deepEqual(records().faults ?? [], [], 'closed DIRECT command model');
            if (/^DIRECT_[A-Z_]+\n$/.test(result.stderr)) refusals.push(result.stderr.trim());
            if (nativeStock && result.status === 0 && ['preflight', 'prepare'].includes(action)) {
                const reply = JSON.parse(result.stdout);
                nativeReplies.push({ action, unitsLoaded: reply.unitsLoaded, nativePreparation: reply.nativePreparation });
            }
            if (action === 'prepare-remove' && result.status === 0) removeBaseline = JSON.parse(result.stdout).baseline;
            if (scenario === 'ppp-lost-ack' && action === 'install' && result.status === 0) {
                return { status: 75, stdout: '', stderr: '' };
            }
            return result;
        };
        const before = Object.fromEntries([mainPath, bridgePath, '/etc/ipsec.conf', '/etc/ppp/chap-secrets', '/etc/ipsec.secrets',
            '/etc/xl2tpd/xl2tpd.conf', '/etc/ppp/options', '/etc/systemd/system/' + x, ...(!freshStock ? [nativePath] : []),
            '/etc/systemd/system/foreign.service', '/usr/lib/systemd/system/' + ike, '/usr/local/bin/xray',
            ...(nativeStock ? Object.keys(xlPackageFiles).slice(0, 2) : []),
            ...(generatedStock ? [generatedPath] : []),
            ...(scenario === 'native-stock-dropin' ? [foreignDropIn] : []), ...(scenario === 'native-stock-fragment' ? [foreignFragment] : []),
            ...swanLeaves, ...(bridgeActive ? ['/etc/systemd/system/' + b] : [])]
            .map(path => [path, fs.readFileSync(join(root, path))]));
        const beforeChannel = () => {
            if (scenario === 'ppp-lock-lost' && actions.at(-1) === 'check') f.loseLock();
        };
        return { id, relay, machineId, key, pin, execute, beforeChannel, applyHandlers, actions, refusals, root, before, mainPath, bridgePath,
            mpath, bpath, bridge, bootLink, nativePath, nativeReplies, generated, usersByNode, x, b, xl, ike, net, records, writeRecords, removeBaseline: () => removeBaseline,
            expectRemoveTransit: value => { expectedRemoveTransit = value; },
        };
    }

    function wire(t, hosts) {
        const routes = new Map(hosts.map(host => [host.relay.ip, host]));
        const applyHandlers = new Map(hosts.flatMap(h => [...h.applyHandlers]));
        const wireFaults = [], frames = [];
        // Model ssh2 at the connection/channel boundary. Production NodeSSH
        // still pins the endpoint, opens the direct client and ships stdin.
        const peers = new WeakMap(), liveClients = new Set();
        t.mock.method(Client.prototype, 'connect', function (options) {
            const host = routes.get(options.host);
            assert.ok(host || applyHandlers.has(options.host));
            assert.equal(options.port, 22);
            assert.equal(options.username, 'root');
            if (options.hostVerifier) {
                assert.ok(host);
                assert.equal(options.hostVerifier(host.key), true);
                for (const other of hosts.filter(candidate => candidate !== host)) assert.equal(options.hostVerifier(other.key), false);
                assert.equal(options.hostVerifier(Buffer.from('other key')), false);
            }
            peers.set(this, { ip: options.host, pinned: typeof options.hostVerifier === 'function' });
            liveClients.add(this);
            queueMicrotask(() => this.emit('ready'));
            return this;
        });
        t.mock.method(Client.prototype, 'end', function () { liveClients.delete(this); });
        t.mock.method(Client.prototype, 'exec', function (command, ready) {
            const peer = peers.get(this);
            const direct = command.startsWith('/usr/bin/timeout -k ');
            const expectsStdin = direct || command.includes('; cat > ');
            const stream = new EventEmitter(), chunks = [];
            stream.stderr = new EventEmitter();
            stream.write = chunk => { chunks.push(Buffer.from(chunk)); return true; };
            const execute = stdin => {
                if (!direct) {
                    const host = routes.get(peer.ip);
                    assert.equal(peer.pinned, Boolean(host));
                    if (command === '/usr/bin/head -c 34 /etc/machine-id') {
                        assert.ok(host && stdin === undefined);
                        peer.observed = true;
                        return { status: 0, stdout: `${host.machineId}\n`, stderr: '' };
                    }
                    assert.ok(applyHandlers.has(peer.ip));
                    const guarded = rebuildApplyMachineGuard(command);
                    if (guarded.accepts) assert.ok(peer.pinned && guarded.accepts(host.machineId));
                    return applyHandlers.get(peer.ip)(guarded.command, stdin);
                }
                const host = routes.get(peer.ip);
                assert.ok(peer.pinned && host);
                const { action } = JSON.parse(stdin);
                if (!action.endsWith('-apply-network')) {
                    assert.equal(peer.observed, true, 'DIRECT payload requires attestation on this client');
                    peer.observed = false;
                }
                frames.push([host.id, action]);
                return host.execute(command, stdin);
            };
            let ended = false;
            const finish = stdin => {
                try {
                    const result = execute(stdin);
                    stream.emit('data', result.stdout);
                    stream.stderr.emit('data', result.stderr);
                    stream.stderr.emit('end');
                    stream.emit('close', result.status);
                } catch (error) {
                    wireFaults.push(error);
                    stream.emit('error', error);
                }
            };
            stream.end = done => {
                if (ended) return;
                ended = true;
                done();
                queueMicrotask(() => finish(Buffer.concat(chunks).toString('utf8')));
            };
            if (direct) routes.get(peer.ip)?.beforeChannel?.();
            ready(null, stream);
            // Stdin receivers wait for EOF, even if async authorization delays the first write.
            // Control-only execs never call channel.end().
            if (!expectsStdin) queueMicrotask(() => {
                if (ended) return;
                ended = true;
                finish(undefined);
            });
        });
        t.after(() => {
            assert.deepEqual(wireFaults, [], 'fixture wire must handle every dispatched frame');
            assert.equal(liveClients.size, 0, 'all SSH clients closed');
        });
        return frames;
    }

    if (wireOnly) return wire;

    test('joined DIRECT wire waits for stdin EOF and completes only once', async t => {
        const command = '/usr/bin/timeout -k fixture';
        const ip = '192.0.2.4', key = Buffer.from('fixture key');
        const received = [], events = [];
        const frames = wire(t, [{ id, relay: { ip }, key, machineId, applyHandlers: new Map(), execute(cmd, stdin) {
            assert.equal(cmd, command);
            received.push(stdin);
            return { status: 0, stdout: 'ok', stderr: '' };
        } }]);
        const client = new Client();
        client.connect({ host: ip, port: 22, username: 'root', hostVerifier: candidate => candidate.equals(key) });
        try {
            await new Promise(resolve => client.exec('/usr/bin/head -c 34 /etc/machine-id', (error, channel) => {
                assert.ifError(error);
                channel.on('close', status => { assert.equal(status, 0); resolve(); });
            }));
            let stream;
            client.exec(command, (error, channel) => {
                assert.ifError(error);
                stream = channel.on('error', error => events.push(error.name)).on('close', status => events.push(status));
            });
            await Promise.resolve(); // The receiver stays open while local authorization is pending.
            assert.deepEqual(events, []);
            stream.write('{"action":');
            stream.write('"check-chap"}');
            await Promise.resolve();
            assert.deepEqual(frames, [], 'writes alone must not dispatch the request');
            assert.deepEqual(events, []);
            stream.end(() => {});
            stream.end(() => {});
            await Promise.resolve();
            assert.deepEqual(received, ['{"action":"check-chap"}']);
            assert.deepEqual(frames, [[id, 'check-chap']]);
            assert.deepEqual(events, [0]);
        } finally { client.end(); }
    });

    function host(t, scenario, options) {
        const f = fixture(t);
        const seeded = seedHost(t, f, f.nodes[0], machineId, scenario, options);
        wire(t, [seeded]);
        f.env.C3_REBUILD_L2TP_SSH_SHA256 = seeded.pin;
        const build = f.create;
        const create = overrides => build({ createRelayDirect: undefined, ...overrides });
        return Object.assign(f, seeded, { create });
    }

    for (const [scenario, expected, loads, retained] of [
        ['ppp-both', 'installed', ['ppp_generic', 'l2tp_ppp']],
        ['ppp-l2tp', 'installed', ['l2tp_ppp']],
        ['ppp-persist', 'installed', []],
        ['ppp-ready', 'installed', []],
        ['ppp-container-ready', 'installed', []],
        ['ppp-container', 'PPP_MODULES_REQUIRED', []],
        ['ppp-child-userns', 'PPP_MODULES_REQUIRED', []],
        ['ppp-device-missing', 'PPP_MODULES_REQUIRED', []],
        ['ppp-blacklist', 'PPP_MODULES_REQUIRED', []],
        ['ppp-dependency-blacklist', 'PPP_MODULES_REQUIRED', []],
        ['ppp-install-hook', 'PPP_MODULES_REQUIRED', []],
        ['ppp-boot-blacklist', 'PPP_MODULES_REQUIRED', []],
        ['ppp-disabled', 'PPP_MODULES_REQUIRED', []],
        ['ppp-conflict', 'PPP_MODULES_PERSISTENCE_CONFLICT', []],
        ['ppp-mask', 'PPP_MODULES_PERSISTENCE_CONFLICT', []],
        ['ppp-shadow-mask', 'PPP_MODULES_PERSISTENCE_CONFLICT', []],
        ['ppp-service-mask', 'PPP_MODULES_PERSISTENCE_CONFLICT', []],
        ['ppp-network-observers', 'NETWORK_OBSERVATION_REQUIRED', []],
        ['ppp-publish-race', 'PPP_MODULES_PERSISTENCE_CONFLICT', [], true],
        ['ppp-load-failure', 'PPP_MODULES_LOAD_FAILED', ['l2tp_ppp'], true],
        ['ppp-no-readback', 'PPP_MODULES_LOAD_FAILED', ['l2tp_ppp'], true],
        ['ppp-load-timeout', undefined, ['l2tp_ppp'], true],
        ['ppp-lost-ack', undefined, ['l2tp_ppp'], true],
    ]) {
        test(`joined Install PPP prerequisite: ${scenario}`, async t => {
            const f = host(t, scenario);
            const file = join(f.root, '/etc/modules-load.d/70-celerity-rebuild-l2tp.conf');
            const before = fs.lstatSync(file, { throwIfNoEntry: false });
            let status = 200, result;
            const res = { status(value) { status = value; return this; }, json(value) { result = value; } };
            await installHandler(f.create)({ params: { id }, body: {} }, res);
            assert.equal(status, expected === 'installed' ? 200 : 409);
            if (expected === 'installed') assert.equal(result.status, 'installed', diagnostic(f));
            else assert.deepEqual(result.error, {
                code: retained ? 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN' : 'REBUILD_L2TP_DIRECT_PREREQUISITE',
                outcome: retained ? 'unknown' : 'refused', ...(expected && { check: expected }),
                ...(retained && expected && { retryAllowed: false }),
            }, diagnostic(f));
            const { moduleLoads = [], effects } = f.records();
            assert.deepEqual(moduleLoads, loads);
            assert.equal(fs.readFileSync(join(f.root, '/etc/modules-load.d/10-unrelated.conf'), 'utf8'), '# operator-owned\nloop\n');
            if (expected === 'installed' || scenario === 'ppp-lost-ack') {
                assert.equal(fs.readFileSync(file, 'utf8'), '# Managed by Celerity rebuild L2TP\nppp_generic\nl2tp_ppp\n');
                assert.equal(fs.statSync(file).mode & 0o777, 0o644);
                if (before) assert.equal(fs.statSync(file).ino, before.ino);
            } else {
                assert.equal(effects.length, 0);
                assert.ok(fs.readFileSync(f.mpath).equals(f.before[f.mainPath]));
                if (scenario === 'ppp-publish-race') assert.equal(fs.readFileSync(file, 'utf8'), '# foreign late arrival\n');
                else assert.equal(fs.lstatSync(file, { throwIfNoEntry: false })?.ino, before?.ino);
                if (scenario === 'ppp-mask') assert.equal(fs.readlinkSync(file), '/dev/null');
            }
            if (retained) {
                assert.equal(f.states[0].status, 'installing');
                assert.equal(f.users[0].syncStatus, 'pending');
                assert.deepEqual(f.actions.slice(-1), ['install']);
                await assert.rejects(f.create().installRelay(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
            } else if (expected !== 'installed') {
                assert.equal(f.states.length + f.users.length, 0);
                assert.ok(!f.actions.includes('install'));
            }
        });
    }

    test('joined Install from unprepared Debian refuses unsafe package autostart before any effects', async t => {
        const f = host(t, 'fresh-stock-runtime');
        const absent = [f.bootLink, '/etc/systemd/system/' + f.xl, '/etc/modules-load.d/70-celerity-rebuild-l2tp.conf',
            '/var/lib/celerity-rebuild-l2tp-direct', '/install-runtime.sh'];
        const checkUnchanged = () => {
            assert.ok(absent.every(path => !fs.lstatSync(join(f.root, path), { throwIfNoEntry: false })));
            for (const [path, bytes] of Object.entries(f.before)) assert.ok(fs.readFileSync(join(f.root, path)).equals(bytes), path);
            assert.deepEqual(f.records().modules, []);
            assert.deepEqual(f.records().effects, []);
            assert.deepEqual(f.records().moduleLoads ?? [], []);
            assert.deepEqual(f.records().units, f.records().original);
            assert.equal(f.states.length + f.users.length, 0);
        };
        const submit = async expected => {
            let status = 200, result;
            await installHandler(f.create)({ params: { id }, body: {} }, {
                status(value) { status = value; return this; }, json(value) { result = value; },
            });
            assert.deepEqual(result.error, { code: 'REBUILD_L2TP_DIRECT_PREREQUISITE', check: expected, outcome: 'refused' }, diagnostic(f));
            assert.equal(status, 409);
            checkUnchanged();
        };
        checkUnchanged();
        await submit('RUNTIME_PACKAGE_AUTOSTART_UNSAFE');
        assert.deepEqual(f.actions, ['preflight']);
        assert.deepEqual(f.refusals, ['DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE']);
        assert.deepEqual(f.records().packageChecks, ['strongswan', 'strongswan-starter']);

        // xl2tpd has its own SysV postinst autostart path. Removing only the
        // strongSwan blocker must not allow dispatch either.
        f.writeRecords({ ...f.records(), missingPackages: ['xl2tpd'], packageChecks: [] });
        await submit('RUNTIME_PACKAGE_AUTOSTART_UNSAFE');
        assert.deepEqual(f.records().packageChecks, ['strongswan', 'strongswan-starter', 'strongswan-charon', 'xl2tpd']);

        assert.deepEqual(f.actions, ['preflight', 'preflight']);
        assert.deepEqual(f.refusals, ['DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE', 'DIRECT_RUNTIME_PACKAGE_AUTOSTART_UNSAFE']);
    });

    function nativeHost(t, layout) {
        const f = host(t, 'native-stock-' + layout, { cohort: true });
        const { events } = sessionFixture(t, f);
        f.nativeCommits = events;
        f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify([{ nodeId: id, host: f.relay.ip, port: 22,
            username: 'root', sshHostKeySha256: f.pin, machineId }]);
        assert.ok(!present(join(f.root, f.nativePath)) && !present(join(f.root, '/install-runtime.sh')));
        return f;
    }

    async function submitNative(f) {
        let status = 200, result;
        await installHandler(f.create)({ params: { id }, body: {} }, {
            status(value) { status = value; return this; }, json(value) { result = value; },
        });
        return { status, result };
    }

    function assertPendingFrames(f) {
        assert.deepEqual(f.nativeReplies, [
            { action: 'preflight', unitsLoaded: false, nativePreparation: true },
            { action: 'preflight', unitsLoaded: false, nativePreparation: true },
            { action: 'prepare', unitsLoaded: false, nativePreparation: undefined },
        ]);
    }

    const snapshotNative = f => ['etc', 'usr', 'run', 'var'].filter(dir => present(join(f.root, dir))).flatMap(dir =>
        fs.readdirSync(join(f.root, dir), { recursive: true, withFileTypes: true }).map(entry => {
            const path = join(entry.parentPath, entry.name).slice(f.root.length);
            const stat = fs.lstatSync(join(f.root, path));
            return [path, entry.isDirectory() ? [stat.ino, stat.mode] : fingerprint(f, path)];
        })).sort(([a], [b]) => a.localeCompare(b));

    for (const layout of ['generated', 'missing']) test(`joined native stock Install: ${layout} reaches installed readback`, async t => {
        const f = nativeHost(t, layout);
        const untouched = [f.bridgePath, ...Object.keys(xlPackageFiles).slice(0, 2),
            '/usr/lib/systemd/system/' + f.ike, '/etc/systemd/system/foreign.service'];
        const before = untouched.map(path => fingerprint(f, path));
        const { status, result } = await submitNative(f);
        assert.equal(status, 200, diagnostic(f));
        assert.deepEqual(result, { executionMode: 'rebuild', status: 'installed', nodeId: id });
        assertPendingFrames(f);
        assert.deepEqual(f.actions, installedActions);
        assert.deepEqual(f.refusals, []);
        assert.deepEqual(f.nativeCommits, ['commit', 'commit']);
        assert.equal(f.lockHeld, false);

        const state = await require('../../../modules/relay-l2tp/models/relayL2tpStateModel').findOne({ node: oid(id) }).select('+rebuildMachineId').lean();
        const accounts = await require('../../../modules/relay-l2tp/models/l2tpUserModel').find({ relayNode: oid(id) }).lean();
        assert.equal(state.status, 'installed');
        assert.equal(state.desiredState, 'installed');
        assert.equal(state.rebuildMachineId, machineId);
        assert.match(state.backupId, /^[a-f0-9]{32}$/);
        assert.ok(state.installedAt instanceof Date && state.lastVerifiedAt instanceof Date);
        assert.deepEqual(accounts.map(row => [row.login, row.enabled, row.syncStatus]), [['relay-bootstrap', true, 'synced']]);
        assert.equal(accounts[0].desiredRevision, accounts[0].appliedRevision);

        const model = f.records(), unit = fingerprint(f, f.nativePath);
        assert.deepEqual(model.nativeReload, { action: 'install', inode: unit.inode });
        assert.deepEqual(model.nativeCreates, ['install']);
        assert.equal(unit.mode, 0o644);
        assert.deepEqual(model.effects[0], ['daemon-reload']);
        assert.equal(model.effects.filter(([action, name]) => action === 'start' && name === f.xl).length, 1);
        assert.ok(model.nativeReadback.includes('install'));
        assert.equal(model.units[f.xl].FragmentPath, f.nativePath);
        assert.equal(model.units[f.xl].UnitFileState, 'enabled');
        assert.equal(fs.readlinkSync(join(f.root, f.bootLink)), f.nativePath);
        assert.ok(!present(join(f.root, generatedPath)) && !present(join(f.root, generatedAlias)));
        for (const name of [f.xl, f.ike, f.net]) assert.equal(model.units[name].ActiveState, 'active');
        assert.ok(model.sockets.some(([kind, , port, pid]) => kind === 'udp' && port === 1701 && pid === model.units[f.xl].MainPID));
        assert.equal(model.nft, state.backupId);
        const manifest = readJson(join(f.root, `/var/lib/celerity-rebuild-l2tp-direct/${state.backupId}/manifest.json`));
        assert.equal(manifest.phase, 'installed');
        assert.deepEqual(untouched.map(path => fingerprint(f, path)), before);
        const removed = await f.create().removeRelay(id).catch(error => error);
        assert.equal(removed.status, 'not_installed', JSON.stringify({ code: removed.code, ...JSON.parse(diagnostic(f)) }));
        assert.deepEqual(fingerprint(f, f.nativePath), unit);
        assert.equal(f.records().units[f.xl].UnitFileState, 'disabled');
        assert.equal(f.records().units[f.xl].ActiveState, 'inactive');
        assert.ok(!present(join(f.root, f.bootLink)));
        assert.ok(fs.readFileSync(join(f.root, '/etc/ipsec.conf')).equals(f.before['/etc/ipsec.conf']));
    });

    for (const layout of ['fragment', 'dropin', 'active', 'orphan-wrapper']) test(`joined native stock Install: refuses ${layout} without writes`, async t => {
        const f = nativeHost(t, layout);
        const before = snapshotNative(f);
        const { status, result } = await submitNative(f);
        assert.equal(status, 409, diagnostic(f));
        assert.equal(result.error.code, 'REBUILD_L2TP_DIRECT_PREREQUISITE', diagnostic(f));
        assert.equal(result.error.outcome, 'refused');
        assert.deepEqual(snapshotNative(f), before, 'native/foreign inodes, modes and bytes unchanged');
        const { effects, units, original, stockManagerCalls = [] } = f.records();
        assert.deepEqual(effects, []);
        assert.deepEqual(units, original);
        assert.deepEqual(f.nativeCommits, []);
        assert.equal(f.states.length + f.users.length, 0);
        assert.ok(!f.actions.includes('install'));
        if (layout !== 'active') assert.ok(stockManagerCalls.some(([, argv]) => argv[2] === '--property=UnitPath'), 'real stock file proof ran');
    });

    test('joined native stock Install: unproved native readback retains the reservation', async t => {
        const f = nativeHost(t, 'readback-failed');
        const { status, result } = await submitNative(f);
        assert.equal(status, 409, diagnostic(f));
        assert.equal(result.error.code, 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN', diagnostic(f));
        assert.equal(result.error.outcome, 'unknown');
        assertPendingFrames(f);
        assert.deepEqual(f.actions, installedActions.slice(0, -1));
        const model = f.records();
        assert.deepEqual(model.effects, [['daemon-reload']]);
        assert.deepEqual(model.nativeCreates, ['install']);
        assert.ok(present(join(f.root, f.nativePath)));
        assert.ok(!present(join(f.root, f.bootLink)));
        assert.ok(fs.readFileSync(f.mpath).equals(f.before[f.mainPath]));
        assert.deepEqual(f.nativeCommits, ['commit']);
        assert.equal(f.states[0].status, 'installing');
        assert.equal(f.users[0].syncStatus, 'pending');
        await assert.rejects(f.create().installRelay(id), { code: 'REBUILD_L2TP_NOT_FRESH_RELAY' });
        assert.deepEqual(f.actions, installedActions.slice(0, -1));
    });

    test('joined Install PPP preparation cannot dispatch after lock is lost at stdin', async t => {
        const f = host(t, 'ppp-lock-lost');
        await assert.rejects(f.create().installRelay(id), { code: 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN' });
        assert.equal(f.states[0].status, 'installing');
        assert.equal(f.users[0].syncStatus, 'pending');
        assert.equal(f.actions.at(-1), 'check');
        assert.deepEqual(f.records().moduleLoads ?? [], []);
        assert.equal(fs.existsSync(join(f.root, '/etc/modules-load.d/70-celerity-rebuild-l2tp.conf')), false);
    });

    test('joined Install PPP preparation cannot dispatch after an unacknowledged majority reservation', async t => {
        const f = host(t, 'ppp-reservation-ack', { cohort: true });
        const { events, hooks } = sessionFixture(t, f);
        f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify([{ nodeId: id, host: f.relay.ip, port: 22,
            username: 'root', sshHostKeySha256: f.pin, machineId }]);
        hooks.commit = commit => { commit(); throw new Error('modeled lost reservation acknowledgement'); };
        await assert.rejects(f.create().installRelay(id), { code: 'REBUILD_L2TP_RESERVATION_FAILED' });
        assert.deepEqual(events, ['commit']);
        assert.equal(f.states[0].status, 'installing');
        assert.equal(f.users[0].syncStatus, 'pending');
        assert.equal(f.actions.at(-1), 'check');
        assert.deepEqual(f.records().moduleLoads ?? [], []);
        assert.equal(fs.existsSync(join(f.root, '/etc/modules-load.d/70-celerity-rebuild-l2tp.conf')), false);
    });

    for (const scenario of ['transit-ok', 'transit-forward', 'transit-missing-client', 'transit-drift',
        'transit-mixed', 'transit-foreign', 'transit-loopback-listener', 'transit-ambiguous-ascii', 'transit-ambiguous-unicode']) {
        test(`joined DIRECT: ${scenario}`, async t => {
            const f = host(t, scenario, { subscribers: [
                { userId: 'fixture-subscriber', xrayUuid: '00000000-0000-4000-8000-000000000005' },
            ] });
            const result = await f.create().installRelay(id).catch(error => error);
            if (scenario === 'transit-ok' || scenario === 'transit-forward') {
                assert.equal(result.status ?? result.code, 'installed', diagnostic(f));
                assert.deepEqual(f.actions, ['preflight', 'preflight', 'prepare', 'check', 'install', 'verify']);
                const current = JSON.parse(fs.readFileSync(f.mpath));
                assert.deepEqual(current.inbounds.slice(0, -2), JSON.parse(f.before[f.mainPath]).inbounds);
                assert.ok(f.records().inboundUserCalls.includes('vless-in'));
                assert.ok(!f.records().inboundUserCalls.some(tag => /^(rebuild-rp-conn-|fwd-hop-)/.test(tag)));
            } else {
                const expected = scenario.startsWith('transit-ambiguous') ? 'CANDIDATE_INVALID'
                    : scenario === 'transit-loopback-listener' ? 'RUNTIME_UNPROVED' : 'PROFILE_USERS';
                assert.equal(result.code, `REBUILD_L2TP_DIRECT_${expected}`, diagnostic(f));
                if (expected === 'PROFILE_USERS') assert.equal(result.check, 'XRAY_PROFILE_USERS_UNPROVED');
                if (expected === 'RUNTIME_UNPROVED') assert.equal(result.check, 'XRAY_RUNTIME_UNPROVED');
                assert.deepEqual(f.actions, ['preflight', 'preflight', 'prepare']);
                assert.equal(f.states.length + f.users.length + f.records().effects.length, 0);
                assert.ok(fs.readFileSync(f.mpath).equals(f.before[f.mainPath]));
                if (scenario === 'transit-foreign') assert.ok(f.records().inboundUserCalls.includes('rebuild-rp-conn-eeeeeeee'));
            }
        });
    }

    for (const scenario of ['main', 'sidecar', 'offline', 'settled', 'sidecar-refusal', 'prewrite', 'masked', 'package',
        'ike-active', 'unit-drift', 'user-rpc-error', 'legacy-setup-profile', 'foreign-profile-owner', 'sidecar-unsafe',
        'foreign-rpdb6', 'manager-override', 'unacknowledged-start']) {
        test(`joined DIRECT + stock prerequisites: ${scenario}`, async t => {
            const f = host(t, scenario, scenario === 'foreign-profile-owner' ? { mainUid: 12345 } : undefined);
            const expected = { settled: 'REBUILD_L2TP_INSTALL_FAILED', 'sidecar-refusal': 'REBUILD_L2TP_INSTALL_FAILED',
                'ike-active': 'REBUILD_L2TP_DIRECT_PREREQUISITE', 'unit-drift': 'REBUILD_L2TP_DIRECT_PREREQUISITE',
                'foreign-rpdb6': 'REBUILD_L2TP_DIRECT_PREREQUISITE', 'manager-override': 'REBUILD_L2TP_DIRECT_PREREQUISITE',
                'unacknowledged-start': 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN',
                prewrite: 'REBUILD_L2TP_INSTALL_FAILED', masked: 'REBUILD_L2TP_HOST_NOT_READY',
                package: 'REBUILD_L2TP_DIRECT_PREREQUISITE', 'user-rpc-error': 'REBUILD_L2TP_DIRECT_PROFILE_USERS',
                'sidecar-unsafe': 'REBUILD_L2TP_XRAY_BASELINE_UNSUPPORTED',
                'foreign-profile-owner': 'REBUILD_L2TP_DIRECT_PREREQUISITE',
                'legacy-setup-profile': 'REBUILD_L2TP_XRAY_BASELINE_UNSUPPORTED' }[scenario];
            const outcome = await f.create().installRelay(id).catch(error => error);
            assert.equal(outcome.code ?? outcome.status, expected ?? 'installed', diagnostic(f));
            if (scenario === 'package') assert.equal(outcome.check, 'RUNTIME_PACKAGE_AUTOSTART_UNSAFE');
            if (expected === 'REBUILD_L2TP_XRAY_BASELINE_UNSUPPORTED' || scenario === 'foreign-profile-owner') {
                assert.equal(outcome.outcome, 'refused');
                assert.equal(outcome.check, scenario === 'foreign-profile-owner'
                    ? 'XRAY_PROFILE_OWNER_UNSUPPORTED' : 'XRAY_BASELINE_UNSUPPORTED');
                assert.deepEqual(f.actions, ['preflight', 'preflight', 'prepare']);
                assert.deepEqual(f.events, []); // No installation-state or account writes.
            }
            if (scenario === 'ike-active' || scenario === 'foreign-rpdb6') {
                assert.equal(outcome.check, scenario === 'ike-active' ? 'IKE_ACTIVE_UNMANAGED' : 'RULE_220_CONFLICT');
                assert.equal(outcome.outcome, 'refused');
            }
            if (!expected) {
                assert.deepEqual(f.actions, ['preflight', 'preflight', 'prepare', 'check', 'install', 'verify']);
                if (scenario === 'main') {
                    const main = f.generated.find(row => row.nodeId === id && row.profile === 'main').config;
                    assert.equal(f.before[f.mainPath].toString(), JSON.stringify(main));
                }
                assert.ok(fs.lstatSync(join(f.root, f.bootLink)).isSymbolicLink());
                const current = JSON.parse(fs.readFileSync(f.mpath)), side = JSON.parse(fs.readFileSync(f.bpath));
                assert.ok(current.inbounds.some(row => row.tag === `relay-l2tp-${id}`));
                const policy = scenario === 'sidecar' ? side : current;
                const fallback = policy.routing.rules.find(row => row.ruleTag === 'rebuild-policy-default');
                assert.ok(fallback.inboundTag.includes('rebuild-relay-ingress'));
                assert.equal(policy.outbounds[0].protocol, 'blackhole');
                assert.ok(policy.routing.rules.slice(0, policy.routing.rules.indexOf(fallback)).some(rule =>
                    rule.inboundTag?.includes('rebuild-relay-ingress') && rule.outboundTag === 'block'
                    && rule.domain?.includes('full:denied.invalid')));
                if (scenario !== 'sidecar') assert.ok(fs.readFileSync(f.bpath).equals(Buffer.from(JSON.stringify(f.bridge))));
                assert.deepEqual(f.records().owners[String(fs.statSync(f.mpath).ino)], [65534, 65534]);
                if (scenario === 'sidecar') assert.deepEqual(f.records().owners[String(fs.statSync(f.bpath).ino)], [0, 65534]);
                assert.equal(fs.statSync(f.mpath).mode & 0o777, 0o640);
                assert.equal(f.states[0].status, 'installed');
                assert.equal(f.users[0].syncStatus, 'synced');
                return;
            }
            if (scenario === 'unacknowledged-start') {
                assert.equal(f.actions.at(-1), 'rollback');
                assert.deepEqual(f.refusals, ['DIRECT_COMMAND_FAILED', 'DIRECT_ROLLBACK_DRIFT']);
                const [state] = f.states;
                assert.equal(state.status, 'installing');
                assert.equal(f.users[0].syncStatus, 'pending');
                const backup = readJson(join(f.root, `/var/lib/celerity-rebuild-l2tp-direct/${state.backupId}/manifest.json`));
                assert.equal(backup.phase, 'applying');
                assert.ok(!Object.hasOwn(backup, 'swanStart'));
                assert.equal(f.records().units[f.ike].ActiveState, 'active');
                assert.ok(!f.records().effects.some(effect => effect[0] === 'stop'));
                assert.equal(f.records().nft, state.backupId);
                return;
            }
            assert.equal(f.states.length + f.users.length, 0);
            for (const [path, bytes] of Object.entries(f.before)) {
                if (scenario === 'prewrite' && path === '/etc/ppp/options') {
                    assert.equal(fs.readFileSync(join(f.root, path), 'utf8'), '# external change\n');
                } else assert.ok(fs.readFileSync(join(f.root, path)).equals(bytes), path);
            }
            if (['settled', 'sidecar-refusal'].includes(scenario)) {
                assert.equal(f.actions.at(-1), 'rollback');
                assert.ok(f.refusals.includes('DIRECT_RUNTIME_UNPROVED'));
                assert.equal(f.records().nft, null);
                assert.ok(!present(join(f.root, stockSwan.profile)));
                assert.equal(f.records().units[f.ike].ActiveState, 'inactive');
                assert.equal(fs.existsSync(join(f.root, f.bootLink)), false);
                assert.deepEqual(f.records().owners[String(fs.statSync(f.mpath).ino)], [65534, 65534]);
                if (scenario === 'sidecar-refusal') assert.deepEqual(f.records().owners[String(fs.statSync(f.bpath).ino)], [0, 65534]);
                assert.equal(fs.statSync(f.mpath).mode & 0o777, 0o640);
            } else {
                assert.ok(!f.actions.includes('rollback'));
                assert.equal(f.records().effects.length, 0);
                assert.equal(fs.existsSync(join(f.root, 'var/lib/celerity-rebuild-l2tp-direct')), false);
                if (scenario === 'prewrite') assert.deepEqual(f.refusals, ['DIRECT_NO_WRITE_BASELINE_CHANGED']);
                if (scenario === 'ike-active') {
                    assert.deepEqual(f.actions, ['preflight', 'preflight', 'prepare']);
                    assert.deepEqual(f.records().units[f.ike], f.records().original[f.ike]);
                    assert.deepEqual(f.records().sockets.filter(row => [500, 4500].includes(row[2])),
                        [500, 4500].map(port => ['udp', '0.0.0.0', port, '201']));
                }
            }
        });
    }

    function applyOptions(t, f) {
        const Link = require('../../../models/cascadeLinkModel');
        const State = require('../../../modules/relay-l2tp/models/relayL2tpStateModel');
        t.mock.method(require('../../configGenerator'), 'buildPanelInlineCertificate', () => null);
        const session = { synthetic: true };
        t.mock.method(Link.db, 'transaction', fn => fn(session));
        t.mock.method(State.collection, 'updateOne', async (where, update, options) => {
            const [row] = f.states;
            assert.equal(options.session.synthetic, true);
            for (const [k, value] of Object.entries(where)) assert.equal(String(row[k] ?? null), String(value));
            Object.assign(row, update.$set);
            return { acknowledged: true, matchedCount: 1 };
        });
        t.mock.method(Link.collection, 'updateOne', async (where, update, options) => {
            assert.equal(options.session.synthetic, true);
            const row = f.links.find(row => String(where._id) === String(row._id));
            assert.ok(row && row.active && !row.rebuildDelete);
            // Collection receives a cast Mongoose subdocument. Keep the
            // backing row as the corresponding BSON-shaped lean object.
            Object.assign(row, update.$set, { rebuildApplied: update.$set.rebuildApplied.toBSON() });
            return { acknowledged: true, matchedCount: 1 };
        });
        return { sync: { _getUsersForNode: async node => structuredClone(f.usersByNode[String(node._id)] ?? []) },
            cache: { invalidateAllSubscriptions: async () => {} } };
    }

    const fingerprint = (f, path) => {
        const file = join(f.root, path), st = fs.lstatSync(file);
        return { inode: st.ino, mode: st.mode & 0o777, owner: f.records().owners[st.ino] ?? [0, 0],
            digest: createHash('sha256').update(st.isSymbolicLink() ? fs.readlinkSync(file) : fs.readFileSync(file)).digest('hex') };
    };
    const present = path => fs.lstatSync(path, { throwIfNoEntry: false }) !== undefined;
    const readJson = path => JSON.parse(fs.readFileSync(path, 'utf8'));
    const ownerReceipt = row => Object.fromEntries(['backupId', 'rebuildMachineId', 'rebuildInstallToken', 'pskEncrypted',
        'secretRevision', 'installedAt', 'lastVerifiedAt', 'lastSyncAt'].map(k => [k, row[k]]));
    const digestAccount = row => createHash('sha256').update(JSON.stringify(row)).digest('hex');
    const installedActions = ['preflight', 'preflight', 'prepare', 'check', 'install', 'verify'];
    const status = outcome => outcome.code ?? outcome.status;
    const diagnostic = f => JSON.stringify({ action: f.actions.at(-1), wire: f.refusals.at(-1), guard: f.records().lastRefusal });

    test('joined two-relay DIRECT: install, inherit, mutate shared accounts and confirm selected removal', async t => {
        const f = fixture(t);
        const { events: commits } = sessionFixture(t, f);
        const intent = accountIntentFixture(t, f);
        const a = seedHost(t, f, f.nodes[0], machineId, 'main', { cohort: true });
        const second = { ...a.relay, _id: oid('c'.repeat(24)), ip: '192.0.2.20', domain: 'relay-b.fixture.invalid' };
        f.nodes.push(second);
        const b = seedHost(t, f, second, 'd'.repeat(32), 'main', { cohort: true });
        const hosts = [a, b];
        const frames = wire(t, hosts);
        f.env.C3_REBUILD_L2TP_RELAYS_JSON = JSON.stringify(hosts.map(h => ({
            nodeId: h.id, host: h.relay.ip, username: h.relay.ssh.username, port: h.relay.ssh.port,
            machineId: h.machineId, sshHostKeySha256: h.pin,
        })));
        const service = f.create({ createRelayDirect: undefined, assertNoRelayAccountIntent: undefined });
        const state = h => f.states.find(row => String(row.node) === h.id);
        const users = h => f.users.filter(row => String(row.relayNode) === h.id).sort((l, r) => l.login.localeCompare(r.login));
        const receipt = h => users(h).map(digestAccount);
        const chapPath = '/etc/ppp/chap-secrets';
        const readChap = h => fs.readFileSync(join(h.root, chapPath), 'utf8');
        const proveChap = (h, expected) => {
            assert.deepEqual(users(h).map(u => [u.login, u.enabled]), Object.entries(expected).sort());
            const rows = readChap(h).match(/# BEGIN CELERITY MANAGED L2TP USERS\n([\s\S]*)# END CELERITY MANAGED L2TP USERS\n/);
            assert.ok(rows, 'managed CHAP markers present');
            const expectedRows = users(h).filter(u => u.enabled).map(u =>
                `"${u.login}" l2tpd "${decrypt(u.passwordEncrypted, f.env.ENCRYPTION_KEY)}" ${u.ip}\n`).sort().join('');
            assert.ok(rows[1] === expectedRows, 'complete enabled CHAP projection matches persisted rows');
            for (const row of users(h)) {
                assert.equal(row.syncStatus, 'synced');
                assert.equal(row.desiredRevision, row.appliedRevision);
                const octets = ip => ip.split('.');
                assert.deepEqual(octets(row.ip).slice(0, 3), octets(state(h).poolStart).slice(0, 3));
                assert.ok(+octets(state(h).poolStart)[3] <= +octets(row.ip)[3] && +octets(row.ip)[3] <= +octets(state(h).poolEnd)[3]);
            }
        };
        const bootstrap = { 'relay-bootstrap': true };
        const inherited = { ...bootstrap, 'early-disabled': false };
        const install = async h => {
            const result = await service.installRelay(h.id).catch(error => error);
            assert.equal(status(result), 'installed', diagnostic(h));
            assert.deepEqual(result, { executionMode: 'rebuild', status: 'installed', nodeId: h.id });
            assert.equal(state(h).rebuildMachineId, h.machineId);
        };
        const mutate = async (action, login, selected) => {
            const n = frames.length;
            const effects = selected.map(h => h.records().effects);
            const result = await service[`${action}RelayAccount`]({ login,
                ...(action === 'create' && { password: 'offline-fixture-account-value' }),
            }).catch(error => error);
            assert.equal(status(result), { create: 'created', disable: 'disabled', delete: 'deleted' }[action],
                JSON.stringify(selected.map(diagnostic)));
            assert.equal(result.relayCount, selected.length);
            assert.deepEqual(frames.slice(n), ['check-chap', 'sync-chap'].flatMap(op => selected.map(h => [h.id, op])));
            assert.deepEqual(selected.map(h => h.records().effects), effects, 'CHAP updates do not restart services or change network policy');
            assert.equal(intent.pending, undefined);
        };
        const replicas = () => {
            assert.notEqual(state(a).clientCidr, state(b).clientCidr);
            assert.notEqual(state(a).poolStart, state(b).poolStart);
            assert.deepEqual(users(a).map(u => u.login), users(b).map(u => u.login));
            for (const [i, row] of users(a).entries()) {
                const other = users(b)[i];
                assert.equal(row.enabled, other.enabled);
                assert.ok(row.passwordEncrypted === other.passwordEncrypted, 'same encrypted envelope');
                assert.notEqual(row.ip, other.ip);
                assert.notEqual(String(row._id), String(other._id));
            }
        };
        await install(a);
        assert.equal(state(b), undefined);
        assert.deepEqual(users(b), []);
        assert.deepEqual(b.actions, []);
        proveChap(a, bootstrap);
        await mutate('create', 'early-disabled', [a]);
        proveChap(a, { ...bootstrap, 'early-disabled': true });
        await mutate('disable', 'early-disabled', [a]);
        proveChap(a, inherited);
        const beforeInheritance = [receipt(a), fingerprint(a, chapPath), a.records().effects];
        const n = frames.length;
        await install(b);
        assert.deepEqual(frames.slice(n), installedActions.map(op => [b.id, op]), 'published directory needs no source host');
        assert.deepEqual([receipt(a), fingerprint(a, chapPath), a.records().effects], beforeInheritance);
        proveChap(b, inherited);
        replicas();

        for (const [action, expected] of [['create', { ...inherited, 'late-shared': true }],
            ['disable', { ...inherited, 'late-shared': false }], ['delete', inherited]]) {
            await mutate(action, 'late-shared', hosts);
            for (const h of hosts) proveChap(h, expected);
            replicas();
        }
        // Add a foreign CHAP neighbor after Install. Remove must subtract the
        // managed block, not restore a stale whole-file backup.
        const neighbor = '# unrelated CHAP data added after install\n';
        fs.appendFileSync(join(b.root, chapPath), neighbor);
        const survivor = () => [digestAccount(state(a)), receipt(a), a.records(), a.actions.slice(),
            [chapPath, a.mainPath, a.bridgePath, a.bootLink, stockSwan.profile].map(path => fingerprint(a, path))];
        const beforeRemove = survivor();

        for (const h of [b, a]) {
            const n = frames.length;
            const preview = await service.previewRemoveRelay(h.id);
            assert.deepEqual(preview, { nodeId: h.id, accountCount: 2, activeSessions: 0, activeIpsec: 0, confirmable: true }, diagnostic(h));
            const result = await service.confirmRemoveRelay(h.id, preview).catch(error => error);
            assert.equal(status(result), 'not_installed', diagnostic(h));
            assert.deepEqual(result, { executionMode: 'rebuild', status: 'not_installed', nodeId: h.id });
            assert.deepEqual(frames.slice(n), ['session-count', 'session-count', 'prepare-remove', 'remove'].map(op => [h.id, op]));
            assert.deepEqual(h.records().censusCalls, ['session-count', 'session-count', 'remove']);
            assert.deepEqual(users(h), []);
            assert.deepEqual([state(h).status, state(h).desiredState], ['not_installed', 'absent']);
            assert.equal(readChap(h), h.before[chapPath].toString() + (h === b ? neighbor : ''));
            assert.deepEqual(readJson(h.mpath), JSON.parse(h.before[h.mainPath]), 'selected MAIN restored');
            assert.ok(!present(join(h.root, h.bootLink)));
            assert.deepEqual([h.records().rule, h.records().route, h.records().nft], [null, null, null]);
            if (h === b) assert.deepEqual(survivor(), beforeRemove, 'removing B did not change A DB/host');
        }
        assert.deepEqual(intent.writes, ['create', 'disable', 'create', 'disable', 'delete']
            .flatMap(action => [`begin:${action}`, `settle:${action}`]));
        // Install and Remove reserve and settle in separate transactions on
        // each relay; each shared mutation commits intent and settlement.
        assert.deepEqual(commits, Array(2 * hosts.length * 2 + 5 * 2).fill('commit'));
        assert.deepEqual(hosts.map(h => h.refusals), [[], []]);
        assert.equal(f.lockHeld, false);
    });

    async function laterApply(f, service) {
        const ownership = ownerReceipt(f.states[0]);
        const account = () => f.users.find(user => String(user.relayNode) === id);
        const beforeAccount = digestAccount(account());
        const boot = fingerprint(f, f.bootLink);
        const beforeMain = fingerprint(f, f.mainPath);
        const originalInvocation = f.records().units[f.x].InvocationID;
        f.nodes[0].aclRules = ['reject(new-deny.invalid)'];
        assert.equal((await service.execute({ nodeId: id })).allowed, true);
        assert.deepEqual(ownerReceipt(f.states[0]), ownership, 'Apply changed the persisted install owner');
        assert.equal(digestAccount(account()), beforeAccount, 'Apply changed the persisted bootstrap account');
        assert.deepEqual(fingerprint(f, f.bootLink), boot, 'Apply changed boot enrollment');
        const afterMain = fingerprint(f, f.mainPath);
        assert.notEqual(afterMain.inode, beforeMain.inode);
        assert.deepEqual([afterMain.owner, afterMain.mode], [beforeMain.owner, beforeMain.mode]);
        assert.notEqual(f.records().units[f.x].InvocationID, originalInvocation);
        assert.equal(f.records().units[f.net].ActiveState, 'active');
        assert.equal(f.records().units[f.xl].ActiveState, 'active');
        assert.ok(f.records().rule && f.records().route && f.records().nft, 'Apply retains the installed kernel policy');
        const main = readJson(f.mpath);
        assert.ok(main.routing.rules.some(rule => rule.domain?.includes('full:new-deny.invalid')
            && rule.outboundTag === 'block' && rule.inboundTag.includes('rebuild-relay-ingress')));
        assert.ok(main.inbounds.some(row => row.tag === `relay-l2tp-${id}` && row.port === f.states[0].tproxyPort));
    }

    const applyActions = ['check-apply-network', 'prepare-apply-network', 'verify-apply-network', 'restart-apply-network', 'verify-apply-network'];
    for (const legacy of [false, true]) test(`joined DIRECT: switching the default tunnel keeps PPP (${legacy ? 'published unit' : 'new install'})`, async t => {
        const f = host(t, 'sidecar', { lifecycle: true });
        if (legacy) f.writeRecords({ ...f.records(), legacyNetwork: true });
        const service = f.create(applyOptions(t, f));
        assert.equal((await service.installRelay(id)).status, 'installed');
        const before = f.records();
        const manifestPath = `/var/lib/celerity-rebuild-l2tp-direct/${f.states[0].backupId}/manifest.json`;
        const manifest = () => readJson(join(f.root, manifestPath));
        const originalReceipt = manifest();
        assert.equal(before.units[f.net].Requires.includes(f.x), legacy);
        const ppp = { interface: 'ppp0', pid: 710, start: 810, l2tpId: 7 };
        f.writeRecords({ ...before, ppp });
        const [link] = f.links;
        const defaultPort = () => {
            const main = f.records().running[f.x];
            const route = main.routing.rules.find(row => row.ruleTag === 'rebuild-policy-default');
            return main.outbounds.find(row => row.tag === route.outboundTag).settings.vnext[0].port;
        };
        link.tunnelPort++;
        const preview = await service.execute({ nodeId: id, preview: true });
        assert.equal(preview.allowed, true);
        assert.deepEqual(f.records(), { ...before, ppp }, 'Preview did not touch the relay');
        assert.equal((await service.execute({ nodeId: id, expectedPreview: preview.previewId })).allowed, true);
        const after = f.records();
        assert.deepEqual(f.actions, [...installedActions, ...applyActions]);
        assert.notEqual(after.units[f.x].InvocationID, before.units[f.x].InvocationID);
        assert.equal(defaultPort(), link.tunnelPort, 'the new tunnel is selected by the live MAIN model');
        assert.deepEqual(after.ppp, ppp, 'PPP did not survive MAIN restart');
        for (const name of [f.xl, f.ike, f.net]) {
            assert.equal(after.units[name].ActiveState, 'active');
            assert.equal(after.units[name].MainPID, before.units[name].MainPID);
            assert.equal(after.units[name].InvocationID, before.units[name].InvocationID);
        }
        for (const key of ['nft', 'rule', 'route']) assert.deepEqual(after[key], before[key]);
        assert.equal(after.units[f.net].Requires.includes(f.x), false);
        assert.equal(after.units[f.net].Wants.includes(f.x), true);
        const settled = manifest();
        if (legacy) {
            assert.notDeepEqual(settled.after.net, originalReceipt.after.net);
            assert.notDeepEqual(settled.runtime.files.net, originalReceipt.runtime.files.net);
            originalReceipt.after.net = settled.after.net;
            originalReceipt.runtime.files.net = settled.runtime.files.net;
        }
        assert.deepEqual(settled, originalReceipt, 'no changes outside the exact owned unit receipt');
        f.writeRecords(Object.fromEntries(Object.entries(after).filter(([key]) => key !== 'ppp')));
        assert.equal((await service.removeRelay(id)).status, 'not_installed');
    });

    test('joined DIRECT: interrupted unit transition is fenced before DELETE or MAIN restart', async t => {
        const f = host(t, 'sidecar', { lifecycle: true });
        f.writeRecords({ ...f.records(), legacyNetwork: true });
        const service = f.create(applyOptions(t, f));
        assert.equal((await service.installRelay(id)).status, 'installed');
        const before = f.records();
        const ppp = { interface: 'ppp0', pid: 710, start: 810 };
        f.writeRecords({ ...before, failApplyReload: true, ppp });
        const linkBefore = structuredClone(f.links[0]);
        const linkId = String(f.links[0]._id);
        const preview = await service.execute({ linkId, preview: true, remove: true });
        await assert.rejects(service.execute({ linkId, remove: true, expectedPreview: preview.previewId }),
            { code: 'REBUILD_L2TP_APPLY_NETWORK_OUTCOME_UNKNOWN', remoteOutcomeUncertain: true });
        const manifest = `/var/lib/celerity-rebuild-l2tp-direct/${f.states[0].backupId}/manifest.json`;
        assert.equal(readJson(join(f.root, manifest)).phase, 'network-upgrading');
        assert.equal(f.links[0].rebuildDelete, linkBefore.rebuildDelete);
        assert.equal(f.records().units[f.x].InvocationID, before.units[f.x].InvocationID);
        assert.deepEqual(f.records().ppp, ppp);
        await assert.rejects(service.execute({ linkId }), { code: 'REBUILD_L2TP_APPLY_NETWORK_REFUSED' });
        assert.deepEqual(f.actions, [...installedActions, ...applyActions.slice(0, 2), 'check-apply-network']);
    });

    test('joined DIRECT: reload-induced stop propagation refuses at the native restart boundary', async t => {
        const f = host(t, 'sidecar', { lifecycle: true });
        const service = f.create(applyOptions(t, f));
        assert.equal((await service.installRelay(id)).status, 'installed');
        const before = f.records();
        const ppp = { interface: 'ppp0', pid: 710, start: 810 };
        f.writeRecords({ ...before, driftOnApplyEnable: true, ppp });
        f.links[0].tunnelPort++;
        await assert.rejects(service.execute({ nodeId: id }), { code: 'REBUILD_L2TP_APPLY_NETWORK_REFUSED' });
        assert.equal(f.records().units[f.x].InvocationID, before.units[f.x].InvocationID);
        assert.deepEqual(f.records().ppp, ppp);
        assert.deepEqual(f.actions, [...installedActions, ...applyActions.slice(0, 4)]);
    });

    test('joined DIRECT: Remove uses the applied port despite a pending edit and ignores an unapplied draft', async t => {
        const f = host(t, 'transit-ok', { lifecycle: true, subscribers: [
            { userId: 'fixture-subscriber', xrayUuid: '00000000-0000-4000-8000-000000000005' },
        ] });
        const service = f.create(applyOptions(t, f));
        const installed = await service.installRelay(id).catch(error => error);
        assert.equal(status(installed), 'installed', diagnostic(f));
        const tag = 'rebuild-rp-conn-eeeeeeee';
        const connector = () => readJson(f.mpath).inbounds.find(row => row.tag === tag);
        const old = connector();
        f.links[0].tunnelPort++;
        await laterApply(f, service);
        const applied = { ...old, port: f.links[0].tunnelPort };
        assert.deepEqual(connector(), applied);
        const receipt = { mode: 'reverse', protocol: 'vless', port: applied.port,
            uuid: old.settings.clients[0].id, listener: oid(id) };
        const draft = { ...f.links[0], _id: oid('c'.repeat(24)), tunnelPort: applied.port + 2,
            status: 'pending', rebuildApplied: null };
        Object.assign(f.links[0], { status: 'pending', tunnelPort: applied.port + 1 });
        f.links.push(draft);
        f.expectRemoveTransit([{ linkId: String(f.links[0]._id), mode: 'reverse', port: applied.port, uuid: receipt.uuid }]);
        const removed = await service.removeRelay(id).catch(error => error);
        assert.equal(status(removed), 'not_installed', diagnostic(f));
        assert.deepEqual(connector(), applied);
        assert.equal(f.links[0].tunnelPort, applied.port + 1);
        assert.deepEqual(f.links[0].rebuildApplied, receipt);
        assert.deepEqual(f.links[1], draft);
        assert.ok(f.records().inboundUserCalls.includes('vless-in'));
        assert.ok(!f.records().inboundUserCalls.includes(tag));
    });

    test('joined DIRECT: legacy pending link without an Apply receipt refuses Remove without writes', async t => {
        const f = host(t, 'transit-ok', { lifecycle: true });
        const service = f.create(applyOptions(t, f));
        assert.equal((await service.installRelay(id)).status, 'installed');
        Object.assign(f.links[0], { status: 'pending', tunnelPort: f.links[0].tunnelPort + 1 });
        const before = JSON.stringify([f.states, f.users, f.links, f.records().effects]);
        const main = fingerprint(f, f.mainPath);
        await assert.rejects(service.removeRelay(id), { code: 'REBUILD_L2TP_APPLIED_LINK_UNPROVED' });
        assert.deepEqual(f.actions, installedActions);
        assert.deepEqual(fingerprint(f, f.mainPath), main);
        assert.equal(JSON.stringify([f.states, f.users, f.links, f.records().effects]), before);
    });

    // The pre-enabled control separates the baseline removal path from the
    // boot-enrollment case, and exposes sidecar/idle-IKE failures independently.
    for (const { name, sidecar = false, preEnabled = false, idleIke = false, apply = false, mainUid } of [
        { name: 'MAIN, root-owned pre-enabled control', preEnabled: true, mainUid: 0 },
        { name: 'MAIN, non-root ownership', preEnabled: true },
        { name: 'MAIN, install-enrolled boot' },
        { name: 'MAIN, initially idle active IKE', preEnabled: true, idleIke: true },
        { name: 'sidecar handoff', sidecar: true, preEnabled: true },
        { name: 'later Apply, install-enrolled boot', apply: true },
        { name: 'later Apply, root-owned pre-enabled control', apply: true, preEnabled: true, mainUid: 0 },
        { name: 'later Apply, from sidecar install', apply: true, sidecar: true, preEnabled: true },
    ]) test(`joined install → ${apply ? 'Apply → ' : ''}remove: ${name}`, async t => {
        const subscribers = [{ userId: 'fixture-subscriber', xrayUuid: '00000000-0000-4000-8000-000000000005' }];
        const f = host(t, sidecar ? 'sidecar' : 'main', { preEnabled, idleIke, subscribers, lifecycle: true, mainUid });
        const service = f.create(applyOptions(t, f));
        const before = Object.fromEntries(Object.keys(f.before).map(path => [path, fingerprint(f, path)]));
        const leaves = () => ['etc', 'usr', 'var', 'peer'].flatMap(dir => fs.readdirSync(join(f.root, dir), { recursive: true, withFileTypes: true })
            .filter(entry => !entry.isDirectory()).map(entry => join(entry.parentPath, entry.name).slice(f.root.length))).sort();
        const beforeLeaves = leaves();
        const bootBefore = preEnabled ? fingerprint(f, f.bootLink) : null;
        const stockUnits = f.records().original;
        const foreignUser = { _id: oid('7'.repeat(24)), relayNode: oid('8'.repeat(24)), login: 'relay-bootstrap',
            enabled: true, passwordEncrypted: 'unrelated-fixture-value', syncStatus: 'synced' };
        const foreignAccountReceipt = digestAccount(foreignUser);
        // Distinct node and same login: a broad cleanup would delete both.
        f.users.push(foreignUser);
        const installed = await service.installRelay(id).catch(error => error);
        if (idleIke) {
            assert.equal(status(installed), 'REBUILD_L2TP_DIRECT_PREREQUISITE', diagnostic(f));
            assert.deepEqual(f.actions, ['preflight', 'preflight', 'prepare']);
            assert.deepEqual(f.records().effects, []);
            assert.deepEqual(f.records().units[f.ike], stockUnits[f.ike]);
            assert.deepEqual(leaves(), beforeLeaves);
            assert.deepEqual(Object.fromEntries(Object.keys(f.before).map(path => [path, fingerprint(f, path)])), before);
            assert.deepEqual(fingerprint(f, f.bootLink), bootBefore);
            assert.deepEqual(f.states, []);
            assert.deepEqual(f.users.map(digestAccount), [foreignAccountReceipt]);
            return;
        }
        assert.equal(status(installed), 'installed', diagnostic(f));
        assert.deepEqual(f.actions, installedActions);
        const state = { ...f.states[0] };
        const account = f.users.find(user => String(user.relayNode) === id);
        assert.ok(account?.enabled && account.syncStatus === 'synced' && account.passwordEncrypted);
        const installedMain = readJson(f.mpath);
        const installedSide = readJson(f.bpath);
        const ownedTag = `relay-l2tp-${id}`;
        const handoffIn = cfg => cfg.inbounds.find(row => row.tag === 'rebuild-relay-ingress');
        const hasSubscriber = cfg => cfg.inbounds.some(i => i.settings?.clients?.some(client =>
            client.email === subscribers[0].userId && client.id === subscribers[0].xrayUuid));
        const installedHandoff = handoffIn(sidecar ? installedSide : installedMain);
        assert.equal(installedMain.inbounds.find(i => i.tag === ownedTag)?.port, state.tproxyPort);
        assert.ok(installedHandoff && installedHandoff.listen === '127.0.0.1');
        assert.ok(hasSubscriber(installedMain));
        const staged = f.records();
        assert.equal(staged.nft, state.backupId);
        assert.equal(staged.rule.table, String(state.routeTable));
        assert.equal(staged.route.table, String(state.routeTable));
        assert.ok(staged.ikeConnection);
        const ports = state => new Set(state.sockets.map(([, , port]) => port));
        for (const port of [state.tproxyPort, installedHandoff.port, 1701, 500, 4500]) assert.ok(ports(staged).has(port), `installed listener ${port}`);
        assert.equal(fs.readlinkSync(join(f.root, f.bootLink)), '/etc/systemd/system/' + f.xl);

        const ownedFiles = [stockSwan.profile, '/etc/ppp/options.xl2tpd', '/etc/ipsec.d/celerity-rebuild-l2tp.conf',
            '/etc/celerity-rebuild-l2tp/ingress.nft', '/etc/systemd/system/' + f.net,
            '/etc/systemd/system/xl2tpd.service.d/50-celerity-rebuild-l2tp.conf'];
        for (const path of ownedFiles) assert.ok(fs.lstatSync(join(f.root, path)).isFile(), path);
        const vault = `/var/lib/celerity-rebuild-l2tp-direct/${state.backupId}`;
        const manifestPath = vault + '/manifest.json';
        const manifest = fingerprint(f, manifestPath);
        assert.equal(readJson(join(f.root, manifestPath)).phase, 'installed');

        const ownedSwan = fingerprint(f, stockSwan.profile);
        if (apply) await laterApply(f, service);
        assert.deepEqual(fingerprint(f, stockSwan.profile), ownedSwan);
        const beforeRemove = f.records();
        const currentHandoff = handoffIn(readJson(f.mpath))?.port;
        const bridgeBeforeRemove = fingerprint(f, f.bridgePath);
        const peerBefore = [f.mainPath, f.bridgePath].map(path => fingerprint(f, join('peer', path)));
        const preserve = structuredClone(beforeRemove.foreign);
        // Additional non-overlapping rule is legal after install; the stricter
        // clean-install rule census must not be bypassed to seed it earlier.
        preserve.rules.push({ priority: 10078, src: '198.51.100.0/24', table: 201 });
        f.writeRecords({ ...beforeRemove, foreign: preserve });
        const linksBefore = JSON.stringify(f.links);
        const accountBefore = digestAccount(account);
        const prepareSnapshot = Object.fromEntries(leaves().map(path => [path, fingerprint(f, path)]));
        const outcome = await service.removeRelay(id).catch(error => error);
        assert.equal(f.lockHeld, false);
        // Keep testing success below: characterize failures without counting
        // them as successful removal or loosening the accepted host state.
        if (outcome.code && f.actions.at(-1) === 'prepare-remove') {
            assert.deepEqual(Object.fromEntries(leaves().map(path => [path, fingerprint(f, path)])), prepareSnapshot);
            assert.deepEqual(f.records().effects, beforeRemove.effects);
            assert.equal(f.states[0].status, 'installed');
            assert.equal(digestAccount(f.users.find(user => String(user.relayNode) === id)), accountBefore);
        }
        if (outcome.code === 'REBUILD_L2TP_REMOVE_OUTCOME_UNKNOWN' && f.actions.at(-1) === 'remove') {
            assert.equal(f.states[0].status, 'removing');
            assert.equal(f.states[0].desiredState, 'absent');
            assert.equal(digestAccount(f.users.find(user => String(user.relayNode) === id)), accountBefore);
        }
        assert.equal(status(outcome), 'not_installed', diagnostic(f));
        assert.deepEqual(outcome, { executionMode: 'rebuild', status: 'not_installed', nodeId: id });
        assert.deepEqual(f.actions, [...installedActions, ...(apply ? applyActions : []), 'prepare-remove', 'remove']);

        const current = f.records();
        assert.deepEqual([current.rule, current.route, current.nft, current.ikeConnection], [null, null, null, false]);
        assert.deepEqual(current.foreign, preserve);
        assert.deepEqual(current.stockRules, staged.stockRules);
        assert.deepEqual(current.rules6, staged.rules6);
        assert.ok(current.sockets.some(row => JSON.stringify(row) === JSON.stringify(preserve.sockets[0])));
        const reserved = [state.tproxyPort, 1701, 500, 4500];
        if (!sidecar) reserved.push(installedHandoff.port);
        if (currentHandoff) reserved.push(currentHandoff);
        for (const port of reserved) assert.ok(!ports(current).has(port), `lingering listener ${port}`);
        for (const name of [f.xl, f.ike, f.net]) {
            for (const prop of ['LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'DropInPaths', 'FragmentPath']) {
                assert.equal(current.units[name][prop], stockUnits[name][prop], `${name}:${prop}`);
            }
        }
        assert.equal(current.units[f.x].ActiveState, 'active');
        assert.notEqual(current.units[f.x].InvocationID, beforeRemove.units[f.x].InvocationID);

        for (const path of [...ownedFiles, '/etc/celerity-rebuild-l2tp', '/etc/systemd/system/xl2tpd.service.d']) {
            assert.ok(!present(join(f.root, path)), `lingering owned path ${path}`);
        }
        if (preEnabled) assert.deepEqual(fingerprint(f, f.bootLink), bootBefore);
        else assert.ok(!present(join(f.root, f.bootLink)), 'lingering install-owned boot link');
        for (const path of Object.keys(before).filter(path => path !== f.mainPath && path !== f.bridgePath)) {
            const attrs = fingerprint(f, path);
            assert.deepEqual({ ...attrs, inode: before[path].inode }, before[path], path);
            // The VPN conffiles can be atomically restored. Unowned files must
            // never be rewritten, even to their original bytes.
            if (!['/etc/ipsec.conf', '/etc/ipsec.secrets', '/etc/ppp/chap-secrets', '/etc/xl2tpd/xl2tpd.conf'].includes(path)) {
                assert.equal(attrs.inode, before[path].inode, path);
            }
        }
        assert.deepEqual(fingerprint(f, manifestPath), manifest, 'original install receipt is retained, not a live artifact');
        assert.match(f.removeBaseline(), /^[a-f0-9]{64}$/);
        assert.deepEqual(readJson(join(f.root, vault, 'remove-attempt.json')), { baseline: f.removeBaseline() });
        assert.deepEqual(fs.readdirSync(join(f.root, vault)).sort(), ['manifest.json', 'remove-attempt.json']);
        assert.deepEqual(leaves(), [...beforeLeaves, manifestPath, vault + '/remove-attempt.json'].sort(), 'no extra live or staging files');

        const config = readJson(f.mpath);
        const expected = apply ? composeRebuildProfiles({ nodes: f.nodes, links: f.links, usersByNode: f.usersByNode,
            dialerVersions: new Map(f.nodes.map(node => [String(node._id), '26.3.27'])),
            panelTls: { serverName: f.env.PANEL_DOMAIN },
            controlPlaneAddresses: [f.env.PANEL_DOMAIN, ...f.nodes.flatMap(n => [n.ip, n.domain]).filter(Boolean)],
        }).find(row => row.nodeId === id && row.profile === 'main').config : JSON.parse(f.before[f.mainPath]);
        assert.deepEqual(config, expected, 'remove subtracts PPP, not current subscriber/tunnel/ACL policy');
        assert.ok(hasSubscriber(config), 'subscriber remains configured');
        assert.deepEqual(current.running[f.x], expected, 'MAIN read back after restart');
        const sideFinal = fingerprint(f, f.bridgePath);
        if (sidecar && !apply) {
            assert.deepEqual(readJson(f.bpath), JSON.parse(f.before[f.bridgePath]), 'restore the originally installed sidecar policy');
            assert.deepEqual(current.running[f.b], JSON.parse(f.before[f.bridgePath]));
            assert.deepEqual([sideFinal.owner, sideFinal.mode], [before[f.bridgePath].owner, before[f.bridgePath].mode]);
            assert.deepEqual(current.sockets.filter(row => row[2] === installedHandoff.port), [
                ['tcp', '127.0.0.1', installedHandoff.port, current.units[f.b].MainPID],
                ['udp', '127.0.0.1', installedHandoff.port, current.units[f.b].MainPID],
            ], 'the pre-existing sidecar listener is not owned by the install');
        } else {
            assert.deepEqual(sideFinal, bridgeBeforeRemove);
            assert.deepEqual(current.units[f.b], beforeRemove.units[f.b]);
            if (sidecar && apply) assert.ok(!ports(current).has(installedHandoff.port));
        }
        assert.deepEqual([f.mainPath, f.bridgePath].map(path => fingerprint(f, join('peer', path))), peerBefore);
        assert.equal(JSON.stringify(f.links), linksBefore);
        assert.deepEqual(f.users.map(digestAccount), [foreignAccountReceipt]);
        const [remaining] = f.states;
        assert.equal(f.states.length, 1);
        assert.equal(String(remaining._id), String(state._id));
        assert.deepEqual([remaining.status, remaining.desiredState], ['not_installed', 'absent']);
        for (const key of [...Object.keys(ownerReceipt(state)), 'pskHint', 'clientCidr', 'tproxyPort', 'fwmark', 'routeTable',
            'routingMode', 'routingVersion', 'localAddress', 'poolStart', 'poolEnd', 'dnsServers', 'mtu', 'mru']) {
            assert.ok(!Object.hasOwn(remaining, key), `lingering installed field ${key}`);
        }
        const mainFinal = fingerprint(f, f.mainPath);
        assert.deepEqual({ owner: mainFinal.owner, mode: mainFinal.mode },
            { owner: before[f.mainPath].owner, mode: before[f.mainPath].mode }, 'restore MAIN owner and mode');
    });
};
