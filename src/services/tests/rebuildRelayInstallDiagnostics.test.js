'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { runInNewContext } = require('node:vm');
const express = require('express');
const session = require('express-session');
const { request } = require('./helpers/rebuildPanelRequest');
const { createRelayDirect } = require('../rebuildRelayDirect');
const attested = require('./helpers/rebuildRelayDirectWire');
const { runFreshRelayInstall } = require('../rebuildRelayInstall');
const { installCheckIds } = require('../rebuildRelayInstallDiagnostics');
const { AcknowledgedCommitCleanupError } = require('../rebuildRelayInstallTransaction');
const { i18nMiddleware } = require('../../middleware/i18n');

const nodeId = 'a'.repeat(24), machineId = 'b'.repeat(32), marker = 'FIXTURE_PRIVATE_VALUE';
const base = '/panel/rebuild/relays';
const installUrl = `${base}/${nodeId}/l2tp/install`;
const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true', C3_REBUILD_L2TP_RELAY_ID: nodeId,
    C3_REBUILD_L2TP_RELAY_MACHINE_ID: machineId, C3_REBUILD_L2TP_SSH_SHA256: 'c'.repeat(64) };
const node = { _id: nodeId, ip: '192.0.2.19', ssh: { username: 'root', port: 22 } };
const ready = { machineId, ppp: true, masked: false, unitsLoaded: true };
const nativePending = { ...ready, ppp: false, unitsLoaded: false, pppPreparation: true, nativePreparation: true };
const desired = { psk: marker, users: [], clientCidr: '10.255.1.0/24', localAddress: '10.255.1.1', poolStart: '10.255.1.10',
    poolEnd: '10.255.1.50', mtu: 1380, mru: 1370, dnsServers: ['192.0.2.53'], routeTable: 177, fwmark: 77, tproxyPort: 12345 };
const main = JSON.stringify({ inbounds: [{ tag: 'fwd-hop-a', protocol: 'vless', port: 443 }],
    outbounds: [{ tag: 'block', protocol: 'blackhole' }],
    routing: { rules: [{ type: 'field', ruleTag: 'rebuild-policy-default', inboundTag: ['fwd-hop-a'], outboundTag: 'block' }] } });
const ok = value => ({ code: 0, stdout: `${JSON.stringify(value)}\n`, stderr: '' });
const refusal = stderr => ({ code: 70, stdout: '', stderr });
const root = join(__dirname, '../../..');

// Run the exact helper bytes packed by DIRECT. Only host prerequisites are modeled;
// no manager/kernel/network command is allowed to run. The exception includes a
// private filename so the producer's exception path is exercised, not fabricated.
const hostPreflight = String.raw`
import io, json, re, shlex, stat, sys, types
command, request = json.load(sys.stdin)
argv = shlex.split(command)
assert argv[:-1] == ['/usr/bin/timeout', '-k', '4s', '125s', '/usr/bin/python3', '-I', '-B', '-c']
faults = []
def no_host_dispatch(event, _):
    if event in {'subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.exec', 'os.fork'} or event.startswith('socket.'):
        faults.append(event)
        raise AssertionError('non-modeled host dispatch')
sys.addaudithook(no_host_dispatch)
host = {'__name__': 'fixture_host'}
exec(compile(argv[-1], '<DIRECT command>', 'exec'), host)
assert json.loads(request)['action'] == 'preflight'
assert re.fullmatch(r'[a-f0-9]{32}', json.loads(request)['machineId'])
host['os'].geteuid = lambda: 0
host['os'].lstat = lambda path: types.SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=host['os'].makedev(108, 0))
host['open'] = lambda path, mode: io.BytesIO({ '/etc/machine-id': json.loads(request)['machineId'].encode() + b'\n',
    '/proc/devices': b'Character devices:\n108 ppp\nBlock devices:\n' }[path])
host['unit'] = lambda name: {'LoadState': 'loaded'}
package_calls = []
def read_package(*args, **kwargs):
    assert args[0] == '/usr/bin/dpkg-query'
    package_calls.append(args[0])
    raise FileNotFoundError('/fixture/FIXTURE_PRIVATE_VALUE')
host['command'] = read_package
sys.stdin = io.TextIOWrapper(io.BytesIO(request.encode()))
status = host['main']()
assert not faults, faults
assert package_calls == ['/usr/bin/dpkg-query']
sys.exit(status)
`;

function localizedFrontend(html, response, headers, app) {
    const attr = (source, key) => {
        const match = new RegExp(`\\b${key}="([^"]*)"`).exec(source);
        assert.ok(match, `SSR attribute missing: ${key}`);
        const entities = { '#34': '"', '#39': "'", lt: '<', gt: '>', amp: '&' };
        return match[1].replace(/&(#34|#39|lt|gt|amp);/g, (_, name) => entities[name]);
    };
    const open = html.match(/<div id="rebuild-l2tp"[^>]*>/)[0];
    const button = html.match(/<button[^>]*\bdata-install-url=[^>]*>/)[0];
    const dataset = { csrf: attr(open, 'data-csrf'), messages: attr(open, 'data-messages'),
        installChecks: attr(open, 'data-install-checks') };
    const status = { textContent: '' }, refresh = { hidden: true, addEventListener() {} };
    let click, finished;
    const task = new Promise(resolve => { finished = resolve; });
    let calls = 0;
    const install = { disabled: false, dataset: { installUrl: attr(button, 'data-install-url'), nodeId: attr(button, 'data-node-id') },
        addEventListener(event, callback) { assert.equal(event, 'click'); click = callback; } };
    const page = { dataset,
        querySelector: key => ({ '[data-action-status]': status, '[data-refresh]': refresh })[key] ?? null,
        querySelectorAll: key => key === '[data-install-url]' ? [install] : [] };
    const script = readFileSync(join(root, 'public/js/rebuild-l2tp.js'), 'utf8');
    runInNewContext(script, { document: { getElementById: () => page },
        window: { addEventListener() {}, location: { reload: () => assert.fail('no automatic reload') } },
        async fetch(path, options) {
            calls++;
            assert.equal(options.method, 'POST');
            assert.equal(path, installUrl);
            assert.equal(options.headers['x-csrf-token'], dataset.csrf);
            let result;
            try { result = await request(app, path, { headers: { ...headers, 'x-csrf-token': dataset.csrf },
                body: JSON.parse(options.body) }); }
            finally { finished(result); }
            return { ok: result.status === 200, status: result.status, json: async () => JSON.parse(result.body) };
        },
    });
    assert.equal(calls, 0);
    click();
    return task.then(async result => {
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(calls, 1);
        assert.deepEqual(JSON.parse(result.body), response);
        return [status.textContent, install.disabled, refresh.hidden];
    });
}

test('closed diagnostics reach the authenticated API and the rendered RU/EN install control', { timeout: 15000 }, async t => {
    const previous = process.env.C3_REBUILD_ENABLED;
    process.env.C3_REBUILD_ENABLED = 'true';
    t.after(() => { if (previous === undefined) delete process.env.C3_REBUILD_ENABLED; else process.env.C3_REBUILD_ENABLED = previous; });
    const { createPanelRouter } = require('../../routes/panel');
    const { invalidateOnboardingCache } = require('../../routes/panel/helpers');
    const { issuePanelCsrfToken } = require('../../routes/panel/csrf');
    const Settings = require('../../models/settingsModel');
    t.mock.method(Settings, 'get', async () => ({ deployment: { completed: true } }));
    t.mock.method(Settings, 'findById', () => ({ select: () => ({ lean: Settings.get }) }));
    t.after(() => { invalidateOnboardingCache(); require.cache[require.resolve('../sshPoolService')]?.exports.closeAll(); });
    invalidateOnboardingCache();
    const app = express();
    app.set('view engine', 'ejs');
    app.set('views', join(root, 'views'));
    app.use(i18nMiddleware);
    app.use(session({ secret: 'fixture-only-signing-key', saveUninitialized: false, resave: false }));
    app.get('/fixture/session', (req, res) => {
        req.session.authenticated = true;
        res.json({ csrf: issuePanelCsrfToken(req) });
    });
    let scenario, log;
    class SSH {
        connect() {}
        disconnect() {}
        exec(command, { stdin }) {
            const { action, backupId } = JSON.parse(stdin);
            log.push(action);
            if (action === 'preflight') {
                if (scenario === 'host-preflight') {
                    const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', hostPreflight], {
                        input: JSON.stringify([command, stdin]), encoding: 'utf8', env: {}, timeout: 5000,
                    });
                    assert.deepEqual([result.status, result.stdout, result.stderr], [70, '', 'DIRECT_PREREQUISITE\n']);
                    return { code: result.status, stdout: result.stdout, stderr: result.stderr };
                }
                if (freshChecks.includes(scenario)) return refusal(`DIRECT_${scenario}\n`);
                if (scenario === 'missing-ppp') return ok({ ...ready, ppp: false });
                if (scenario === 'pending-ppp-bad-capability') return ok({ ...ready, ppp: false, pppPreparation: 1 });
                if (scenario === 'pending-ppp-missing-units') return ok({ ...ready, ppp: false, pppPreparation: true, unitsLoaded: false });
                if (scenario === 'native-post-intent-unknown') return ok(nativePending);
                if (scenario === 'pending-ppp' || scenario.startsWith('snapshot-')) {
                    return ok({ ...ready, ppp: false, pppPreparation: true });
                }
                return ok(ready);
            }
            if (action === 'prepare') {
                if (hostChecks.includes(scenario)) return refusal(`DIRECT_${scenario}\n`);
                if (scenario === 'baseline') return refusal('DIRECT_PREREQUISITE\n');
                if (scenario === 'payload') return { ...refusal('DIRECT_RULE_220_CONFLICT\n'), stdout: marker };
                const snapshot = { ...ready, main, mainSha256: createHash('sha256').update(main).digest('hex'), bridge: null,
                    bridgeSha256: null, baseline: 'd'.repeat(64) };
                if (scenario === 'pending-ppp' || scenario.startsWith('snapshot-')) snapshot.ppp = false;
                if (scenario === 'snapshot-forged-capability') snapshot.pppPreparation = true;
                if (scenario === 'snapshot-missing-units') delete snapshot.unitsLoaded;
                if (scenario === 'snapshot-unloaded') snapshot.unitsLoaded = false;
                if (scenario === 'native-post-intent-unknown') Object.assign(snapshot, { ppp: false, unitsLoaded: false });
                return ok(snapshot);
            }
            if (action === 'check' && ['candidate', 'pending-ppp'].includes(scenario)) return refusal('DIRECT_PREREQUISITE\n');
            if (action === 'install') {
                // Consumer fixture for the host's post-intent unknown (e.g. lost reload acknowledgement).
                if (scenario === 'native-post-intent-unknown') return { code: 75, stdout: '', stderr: '' };
                if (scenario === 'install-prerequisite') return refusal('DIRECT_NO_WRITE_PREREQUISITE\n');
                if (scenario === 'no-write' || scenario === 'lost-no-write-restore') return refusal('DIRECT_NO_WRITE_PPP_MODULES_LOAD_FAILED\n');
                if (scenario === 'write' || scenario === 'lost-rollback') return refusal('DIRECT_XRAY_CONFIG_WRITABLE\n');
                if (scenario === 'unknown-frame') return refusal('DIRECT_NO_WRITE_REBUILD_FIXTURE_PRIVATE_VALUE\n');
                if (scenario === 'bad-verify' || scenario === 'installed-cleanup') return ok({ ok: true, backupId });
                return refusal('DIRECT_PPP_MODULES_LOAD_FAILED\n');
            }
            if (action === 'verify' && scenario === 'bad-verify') return { ...ok({ ok: true, backupId }), stderr: marker };
            if (action === 'rollback' && scenario === 'lost-rollback') return { code: 75, stdout: '', stderr: '' };
            return ok({ ok: true, backupId });
        }
    }
    const installRelay = id => {
        if (scenario === 'raw-error' || scenario === 'forged-check') throw Object.assign(new Error(marker), {
            code: scenario === 'raw-error' ? `REBUILD_${marker}` : 'REBUILD_L2TP_DIRECT_PREREQUISITE',
            check: 'XRAY_DROPIN_UNSUPPORTED', outcome: marker,
        });
        return runFreshRelayInstall(id, {
            authorize: () => true, machineId, inventory: async () => ({ eligible: true, pristine: true }),
            async lock(fn) {
                if (scenario === 'busy') throw Object.assign(new Error(marker), { code: 'REBUILD_BUSY' });
                return fn(() => true);
            },
            connect: async () => createRelayDirect({ node, env, SSH: attested(SSH, machineId) }),
            prepare: (_, remote) => remote.prepare({ nodeId, desired, carryDomain: false, controlPlaneAddresses: ['panel.fixture.invalid'] }),
            reserve: async () => { log.push('reserve'); return {}; }, verifyReservation: async () => {},
            restore: async () => {
                log.push('restore');
                if (scenario === 'lost-no-write-restore') throw Error(marker);
            },
            async finish() {
                assert.equal(scenario, 'installed-cleanup');
                log.push('finish');
                throw new AcknowledgedCommitCleanupError(new Error(marker));
            },
        });
    };
    t.mock.method(require('../rebuildService'), 'createRebuildService', () => ({ installRelay }));
    app.use('/panel', createPanelRouter({ rebuildL2tpOverview: { overview: async () => ({
        relays: [{ id: nodeId, name: 'fixture', ip: node.ip, status: 'not_installed', bound: true, canInstall: true }],
        accounts: [], canManageAccounts: false,
    }) }, l2tpRateLimiter: (_req, _res, next) => next() }));
    app.use((_req, res) => res.status(404).json({ error: 'not found' }));
    const signed = await request(app, '/fixture/session', { method: 'GET' });
    const cookie = signed.headers['set-cookie'][0].split(';')[0];
    const csrf = JSON.parse(signed.body).csrf;
    const auth = { cookie, 'content-type': 'application/json' };
    log = [];
    assert.equal((await request(app, installUrl, { headers: { 'x-csrf-token': csrf } })).status, 302);
    assert.equal((await request(app, installUrl, { headers: auth })).status, 403);
    assert.equal((await request(app, `/api/cascade${installUrl.slice('/panel'.length)}`, { headers: auth })).status, 404);
    assert.equal((await request(app, installUrl, { headers: { ...auth, 'x-csrf-token': csrf }, body: { check: 'anything' } })).status, 400);
    assert.deepEqual(log, []);

    const apply = ['preflight', 'preflight', 'prepare', 'check', 'reserve', 'install'];
    const hostChecks = ['XRAY_DROPIN_UNSUPPORTED', 'PPP_MODULES_REQUIRED', 'PPP_MODULES_PERSISTENCE_CONFLICT',
        'PPP_MODULES_LOAD_FAILED', 'NETWORK_OBSERVATION_REQUIRED', 'IKE_ACTIVE_RULE_220', 'RULE_220_CONFLICT', 'IKE_ACTIVE_UNMANAGED',
        'XL2TPD_CONFIG_MISSING', 'XRAY_CONFIG_WRITABLE', 'XL2TPD_NATIVE_UNIT_REQUIRED', 'XL2TPD_NATIVE_UNIT_CONFLICT'];
    const freshChecks = ['RUNTIME_PACKAGE_AUTOSTART_UNSAFE', 'RUNTIME_NATIVE_UNIT_REQUIRED'];
    const matrix = [
        ...freshChecks.map(check => [check, 'REBUILD_L2TP_DIRECT_PREREQUISITE', 'refused', check, 'installRefused', ['preflight']]),
        ['host-preflight', 'REBUILD_L2TP_DIRECT_PREREQUISITE', 'refused', 'HOST_PREFLIGHT', 'installRefused', ['preflight']],
        ['missing-ppp', 'REBUILD_L2TP_HOST_NOT_READY', 'refused', 'PPP_MODULES_REQUIRED', 'installRefused', ['preflight']],
        ['pending-ppp-bad-capability', 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', 'unknown', undefined, 'uncertain', ['preflight']],
        ['pending-ppp-missing-units', 'REBUILD_L2TP_HOST_NOT_READY', 'refused', 'VPN_UNITS_NOT_LOADED', 'installRefused', ['preflight']],
        ['pending-ppp', 'REBUILD_L2TP_DIRECT_PREREQUISITE', 'refused', 'HOST_CANDIDATE', 'installRefused', apply.slice(0, 4)],
        ['snapshot-missing-units', 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', 'unknown', undefined, 'uncertain', apply.slice(0, 3)],
        ['snapshot-forged-capability', 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', 'unknown', undefined, 'uncertain', apply.slice(0, 3)],
        ['snapshot-unloaded', 'REBUILD_L2TP_HOST_NOT_READY', 'refused', 'VPN_UNITS_NOT_LOADED', 'installRefused', apply.slice(0, 3)],
        ...hostChecks.map(check => [check, 'REBUILD_L2TP_DIRECT_PREREQUISITE', 'refused', check, 'installRefused', apply.slice(0, 3)]),
        ['baseline', 'REBUILD_L2TP_DIRECT_PREREQUISITE', 'refused', 'HOST_BASELINE', 'installRefused', apply.slice(0, 3)],
        ['candidate', 'REBUILD_L2TP_DIRECT_PREREQUISITE', 'refused', 'HOST_CANDIDATE', 'installRefused', apply.slice(0, 4)],
        ['install-prerequisite', 'REBUILD_L2TP_INSTALL_FAILED', 'refused', 'HOST_INSTALL', 'installRefused', [...apply, 'restore']],
        ['no-write', 'REBUILD_L2TP_INSTALL_FAILED', 'refused', 'PPP_MODULES_LOAD_FAILED', 'installRefused', [...apply, 'restore']],
        ['lost-no-write-restore', 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN', 'unknown', 'PPP_MODULES_LOAD_FAILED', 'uncertain', [...apply, 'restore']],
        ['partial-ppp', 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN', 'unknown', 'PPP_MODULES_LOAD_FAILED', 'uncertain', apply, false],
        ['native-post-intent-unknown', 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN', 'unknown', undefined, 'uncertain', apply],
        ['write', 'REBUILD_L2TP_INSTALL_FAILED', 'rolled_back', 'XRAY_CONFIG_WRITABLE', 'installRolledBack', [...apply, 'rollback', 'restore']],
        ['lost-rollback', 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN', 'unknown', 'XRAY_CONFIG_WRITABLE', 'uncertain', [...apply, 'rollback']],
        ['unknown-frame', 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN', 'unknown', undefined, 'uncertain', apply],
        ['bad-verify', 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN', 'unknown', undefined, 'uncertain', [...apply, 'verify']],
        ['installed-cleanup', 'REBUILD_L2TP_INSTALLED_CLEANUP_FAILED', 'installed', undefined, 'installCleanupFailed', [...apply, 'verify', 'finish']],
        ['payload', 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', 'unknown', undefined, 'uncertain', apply.slice(0, 3)],
        ['busy', 'REBUILD_BUSY', 'busy', undefined, 'installBusy', []],
        ['raw-error', 'REBUILD_L2TP_INSTALL_FAILED', 'unknown', undefined, 'uncertain', []],
        ['forged-check', 'REBUILD_L2TP_DIRECT_PREREQUISITE', 'refused', undefined, 'installRefused', []],
    ];
    for (const lang of ['ru', 'en']) {
        const words = require(`../../locales/${lang}.json`).rebuildL2tp;
        assert.deepEqual(Object.keys(words.installChecks).sort(), [...installCheckIds].sort());
        const headers = { ...auth, 'accept-language': lang };
        const { status, body } = await request(app, '/panel/l2tp', { method: 'GET', headers });
        assert.equal(status, 200);
        for (const [name, code, outcome, check, message, actions, retryAllowed] of matrix) {
            scenario = name;
            log = [];
            const expected = { error: { code, outcome, ...(check !== undefined && { check }),
                ...(retryAllowed === false && { retryAllowed }) } };
            const result = await request(app, installUrl, { headers: { ...headers, 'x-csrf-token': csrf } });
            assert.equal(result.status, 409, name);
            assert.deepEqual(JSON.parse(result.body), expected, name);
            assert.doesNotMatch(result.body, /FIXTURE_PRIVATE_VALUE|Traceback/);
            assert.deepEqual(log, actions, name);
            log = [];
            const [text, disabled, hidden] = await localizedFrontend(body, expected, headers, app);
            assert.equal(text, words.messages[message] + (check ? ` ${words.installChecks[check]}` : ''), `${name}: ${lang}`);
            assert.deepEqual(log, actions, name);
            assert.equal(disabled, ['unknown', 'rolled_back', 'installed'].includes(outcome), name);
            assert.equal(hidden, !disabled, name);
        }
    }
});
