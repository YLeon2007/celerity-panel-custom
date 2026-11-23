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
const { i18nMiddleware, t: translate } = require('../../middleware/i18n');

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
vault_checks = []
def absent_fixture_vault(path, private=False):
    assert path == host['VAULT'] and private is True
    vault_checks.append(path)
    raise FileNotFoundError(path)
host['directory'] = absent_fixture_vault
package_calls = []
def read_package(*args, **kwargs):
    assert args[0] == '/usr/bin/dpkg-query'
    package_calls.append(args[0])
    raise FileNotFoundError('/fixture/FIXTURE_PRIVATE_VALUE')
host['command'] = read_package
sys.stdin = io.TextIOWrapper(io.BytesIO(request.encode()))
status = host['main']()
assert not faults, faults
assert vault_checks == [host['VAULT']]
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
    assert.match(html, /<script src="\/js\/rebuild-l2tp\.js\?v=[a-f0-9]+" defer><\/script>/);
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
        // Even if the click handler is reached again, a refresh-required
        // outcome must not cause a second request from the stale page.
        if (install.disabled) click();
        assert.equal(calls, 1);
        assert.deepEqual(JSON.parse(result.body), response);
        return [status.textContent, install.disabled, refresh.hidden];
    });
}

async function diagnosticPanel(t, installRelay) {
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
    assert.equal((await request(app, installUrl, { headers: { 'x-csrf-token': csrf } })).status, 302);
    assert.equal((await request(app, installUrl, { headers: auth })).status, 403);
    assert.equal((await request(app, `/api/cascade${installUrl.slice('/panel'.length)}`, { headers: auth })).status, 404);
    assert.equal((await request(app, installUrl, { headers: { ...auth, 'x-csrf-token': csrf }, body: { check: 'anything' } })).status, 400);
    return { app, auth, csrf };
}

test('closed diagnostics reach the authenticated API and the localized install control', { timeout: 15000 }, async t => {
    let scenario, log = [];
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
                if (scenario === 'profile-owner') return refusal('DIRECT_XRAY_PROFILE_OWNER_UNSUPPORTED\n');
                if (scenario === 'profile-users') return refusal('DIRECT_PROFILE_USERS\n');
                if (scenario === 'profile-runtime') return refusal('DIRECT_RUNTIME_UNPROVED\n');
                if (scenario === 'baseline') return refusal('DIRECT_PREREQUISITE\n');
                if (scenario === 'payload') return { ...refusal('DIRECT_RULE_220_CONFLICT\n'), stdout: marker };
                const profile = scenario === 'profile-format' ? JSON.stringify(JSON.parse(main), null, 2) : main;
                const snapshot = { ...ready, main: profile, mainSha256: createHash('sha256').update(profile).digest('hex'), bridge: null,
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
    const { app, auth, csrf } = await diagnosticPanel(t, installRelay);
    assert.deepEqual(log, []);

    const apply = ['preflight', 'preflight', 'prepare', 'check', 'reserve', 'install'];
    const hostChecks = ['XRAY_DROPIN_UNSUPPORTED', 'PPP_MODULES_REQUIRED', 'PPP_MODULES_PERSISTENCE_CONFLICT',
        'PPP_MODULES_LOAD_FAILED', 'KERNEL_MODULE_BLACKLISTED', 'NETWORK_OBSERVATION_REQUIRED', 'IKE_ACTIVE_RULE_220', 'RULE_220_CONFLICT', 'IKE_ACTIVE_UNMANAGED',
        'XL2TPD_CONFIG_MISSING', 'XRAY_CONFIG_WRITABLE', 'XL2TPD_NATIVE_UNIT_REQUIRED', 'XL2TPD_NATIVE_UNIT_CONFLICT'];
    const freshChecks = ['RUNTIME_PACKAGE_AUTOSTART_UNSAFE', 'RUNTIME_NATIVE_UNIT_REQUIRED', 'PACKAGE_APT_PLAN'];
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
        ['profile-format', 'REBUILD_L2TP_XRAY_BASELINE_UNSUPPORTED', 'refused', 'XRAY_BASELINE_UNSUPPORTED', 'installRefused', apply.slice(0, 3)],
        ['profile-owner', 'REBUILD_L2TP_DIRECT_PREREQUISITE', 'refused', 'XRAY_PROFILE_OWNER_UNSUPPORTED', 'installRefused', apply.slice(0, 3)],
        ['profile-users', 'REBUILD_L2TP_DIRECT_PROFILE_USERS', 'refused', 'XRAY_PROFILE_USERS_UNPROVED', 'installRefused', apply.slice(0, 3)],
        ['profile-runtime', 'REBUILD_L2TP_DIRECT_RUNTIME_UNPROVED', 'refused', 'XRAY_RUNTIME_UNPROVED', 'installRefused', apply.slice(0, 3)],
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
    for (const lang of ['ru', 'en', 'zh-CN']) {
        const words = require(`../../locales/${lang}.json`).rebuildL2tp;
        if (lang !== 'zh-CN') assert.deepEqual(Object.keys(words.installChecks).sort(), [...installCheckIds].sort());
        for (const key of ['REBUILD_LINKS_NOT_APPLIED', 'XRAY_BASELINE_UNSUPPORTED', 'XRAY_PROFILE_OWNER_UNSUPPORTED',
            'XRAY_PROFILE_USERS_UNPROVED', 'XRAY_RUNTIME_UNPROVED']) {
            assert.ok(words.installChecks?.[key], `${lang}: ${key}`);
        }
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
            assert.equal(text, translate(`rebuildL2tp.messages.${message}`, lang)
                + (check ? ` ${translate(`rebuildL2tp.installChecks.${check}`, lang)}` : ''), `${name}: ${lang}`);
            assert.deepEqual(log, actions, name);
            assert.equal(disabled, ['unknown', 'rolled_back', 'installed'].includes(outcome), name);
            assert.equal(hidden, !disabled, name);
        }
    }
});

const packageChecks = ['PACKAGE_SOURCES_UNSUPPORTED', 'PACKAGE_INDEXES_UNVERIFIED', 'PACKAGE_SERVICES_UNSAFE', 'PACKAGE_APT_PLAN'];
const packageLanguages = ['ru', 'en'];

test('package diagnostics have explicit Russian and English operator copy', () => {
    const [ru, en] = packageLanguages.map(lang => require(`../../locales/${lang}.json`).rebuildL2tp.installChecks);
    for (const check of packageChecks) {
        for (const strings of [ru, en]) {
            assert.ok(Object.hasOwn(strings, check), `missing explicit translation: ${check}`);
            assert.ok(strings[check].trim());
            assert.ok(!strings[check].includes(check));
        }
        assert.notEqual(ru[check], en[check], check);
    }
    assert.match(ru.PACKAGE_SOURCES_UNSUPPORTED, /Debian 13.*trixie.*main.*ключ/);
    assert.match(en.PACKAGE_SOURCES_UNSUPPORTED, /Debian 13.*trixie.*main.*keyring/);
    assert.match(ru.PACKAGE_INDEXES_UNVERIFIED, /подписанн.*индекс.*доступност.*время/i);
    assert.match(en.PACKAGE_INDEXES_UNVERIFIED, /signed.*indexes.*reach.*time/i);
    assert.match(ru.PACKAGE_SERVICES_UNSAFE, /IKE.*xl2tpd.*неактивн.*автозапуск/i);
    assert.match(en.PACKAGE_SERVICES_UNSAFE, /IKE.*xl2tpd.*inactive.*autostart/i);
    assert.match(ru.PACKAGE_APT_PLAN, /APT.*план/i);
    assert.match(en.PACKAGE_APT_PLAN, /APT.*plan/i);
    assert.match(require('../../locales/zh-CN.json').rebuildL2tp.installChecks.PACKAGE_APT_PLAN, /APT.*计划/);
});

test('package diagnostics reach the authenticated route and localized Install control only in scope', { timeout: 15000 }, async t => {
    const packagePreparation = 'e'.repeat(64);
    const fence = { merged: true, listMode: true, source: 'db', check() {},
        binding: { host: node.ip, port: 22, username: 'root', machineId, sshHostKeySha256: 'c'.repeat(64) } };
    const preflight = ['preflight'];
    const packageWrite = 'prepare-packages';
    const reserved = [...preflight, 'reserve', packageWrite, 'retain'];
    const baseline = ['preflight', 'preflight', 'prepare'];
    const candidate = [...baseline, 'check'];
    const installing = [...candidate, 'reserve', 'install', 'retain'];
    const wireFrame = (code, check, prefix = '') => ({ code, stdout: '', stderr: `DIRECT_${prefix}${check}\n` });
    const plan = 'PACKAGE_APT_PLAN';
    const plan70 = wireFrame(70, plan), plan75 = wireFrame(75, plan, 'UNCERTAIN_');
    const noHint = undefined;
    // SSH, host replies, grant and persistence are modeled. We exercise the
    // real DIRECT parser, installer, authenticated route/SSR and browser script
    // (with a DOM seam), not the host's diagnostic production.
    const matrix = [
        ...packageChecks.flatMap(check => [
            [`preflight: ${check}`, 'preflight', wireFrame(70, check), check, preflight],
            [`reserved rc70: ${check}`, packageWrite, wireFrame(70, check), check, reserved],
            [`reserved rc75: ${check}`, packageWrite, wireFrame(75, check, 'UNCERTAIN_'), check, reserved],
        ]),
        ['observer blacklist before package admission', 'preflight', wireFrame(70, 'KERNEL_MODULE_BLACKLISTED'),
            'KERNEL_MODULE_BLACKLISTED', preflight],
        ['observer blacklist before package intent', packageWrite, wireFrame(70, 'KERNEL_MODULE_BLACKLISTED'),
            'KERNEL_MODULE_BLACKLISTED', reserved],
        ['unknown plan lookalike at preflight', 'preflight', wireFrame(70, `PACKAGE_APT_PLAN_${marker}`), noHint, preflight],
        ['unknown plan lookalike after reservation', packageWrite, wireFrame(70, `PACKAGE_APT_PLAN_${marker}`), noHint, reserved],
        ['future check', packageWrite, wireFrame(75, `PACKAGE_${marker}`, 'UNCERTAIN_'), noHint, reserved],
        ['naked rc75', packageWrite, { code: 75, stdout: '', stderr: '' }, noHint, reserved],
        ['lost SSH ACK', packageWrite, null, noHint, reserved],
        ['private stdout', packageWrite, { ...plan70, stdout: marker }, noHint, reserved],
        ['private stderr after valid line', packageWrite, { ...plan75, stderr: plan75.stderr + `/fixture/${marker}\n` }, noHint, reserved],
        ['missing LF', packageWrite, { ...plan75, stderr: plan75.stderr.trimEnd() }, noHint, reserved],
        ['extra LF', packageWrite, { ...plan70, stderr: `${plan70.stderr}\n` }, noHint, reserved],
        ['CRLF', 'preflight', { ...plan70, stderr: plan70.stderr.replace('\n', '\r\n') }, noHint, preflight],
        ['private stdout at preflight', 'preflight', { ...plan70, stdout: marker }, noHint, preflight],
        ['preflight rc75 is not package entry', 'preflight', plan75, noHint, preflight],
        ['rc75 needs uncertainty prefix', packageWrite, { ...plan70, code: 75 }, noHint, reserved],
        ['rc70 cannot carry uncertainty prefix', packageWrite, { ...plan75, code: 70 }, noHint, reserved],
        ...packageChecks.map(check => [`wrong action prepare: ${check}`, 'prepare', wireFrame(70, check), noHint, baseline]),
        ['wrong action check', 'check', plan70, noHint, candidate],
        ['wrong action install', 'install', plan70, noHint, installing],
        ['wrong action install no-write alias', 'install', wireFrame(70, plan, 'NO_WRITE_'), noHint, installing],
    ];
    const snapshot = { ...ready, main, mainSha256: createHash('sha256').update(main).digest('hex'),
        bridge: null, bridgeSha256: null, baseline: 'd'.repeat(64) };
    let failingAction, frame, log = [], reservation;
    class SSH {
        connect() {}
        disconnect() {}
        async exec(_command, { stdin }, verify) {
            await verify();
            const input = JSON.parse(stdin);
            const { action, backupId } = input;
            if (action === packageWrite) {
                assert.match(reservation.backupId, /^[a-f0-9]{32}$/);
                assert.deepEqual(input, { action, machineId, backupId: reservation.backupId, packagePreparation });
            }
            log.push(action);
            if (action === failingAction) {
                if (frame === null) throw Error(`lost reply: /fixture/${marker}`);
                return frame;
            }
            if (action === 'preflight') return ok(failingAction === packageWrite ? { machineId, packagePreparation } : ready);
            if (action === 'prepare') return ok(snapshot);
            return ok({ ok: true, backupId });
        }
    }
    const { app, auth, csrf } = await diagnosticPanel(t, id => runFreshRelayInstall(id, {
        authorize: () => true, machineId, inventory: async () => ({ eligible: true, pristine: true }),
        unifiedIdentity: true, allowPackagePreparation: true,
        lock: fn => fn(() => true, () => log.push('retain')),
        connect: async () => createRelayDirect({ node, fence, SSH: attested(SSH, machineId) }),
        prepare: (_, remote) => remote.prepare({ nodeId, desired, carryDomain: false, controlPlaneAddresses: ['panel.fixture.invalid'] }),
        reserve: async (_, backupId) => {
            log.push('reserve');
            reservation = { backupId };
            return reservation;
        },
        verifyReservation: async value => assert.equal(value, reservation),
        restore: async () => { log.push('restore'); },
        finish: async () => { log.push('finish'); },
    }));
    assert.deepEqual(log, []);

    for (const lang of packageLanguages) {
        const { installChecks, messages } = require(`../../locales/${lang}.json`).rebuildL2tp;
        const headers = { ...auth, 'accept-language': lang };
        const page = await request(app, '/panel/l2tp', { method: 'GET', headers });
        assert.equal(page.status, 200);
        for (const [name, action, reply, check, actions] of matrix) {
            await t.test(`${lang}: ${name}`, async () => {
                [failingAction, frame] = [action, reply];
                const refused = action === 'preflight' && check !== undefined;
                const expected = { error: {
                    code: refused ? 'REBUILD_L2TP_DIRECT_PREREQUISITE' : action === 'install'
                        ? 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN' : 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN',
                    outcome: refused ? 'refused' : 'unknown',
                    ...(check && { check }),
                    ...(actions.includes('retain') && { retryAllowed: false }),
                } };
                log = [];
                const result = await request(app, installUrl, { headers: { ...headers, 'x-csrf-token': csrf } });
                assert.equal(result.status, 409);
                assert.deepEqual(JSON.parse(result.body), expected);
                assert.doesNotMatch(result.body, /FIXTURE_PRIVATE_VALUE|\/fixture\/|Traceback|DIRECT_(?:UNCERTAIN_)?PACKAGE_/);
                assert.deepEqual(log, actions);
                log = [];
                const [text, disabled, refreshHidden] = await localizedFrontend(page.body, expected, headers, app);
                assert.equal(text, (refused ? messages.installRefused : messages.uncertain)
                    + (check ? ` ${installChecks[check]}` : ''));
                assert.doesNotMatch(text, /FIXTURE_PRIVATE_VALUE|\/fixture\/|Traceback|PACKAGE_(SOURCES|INDEXES|SERVICES|APT_PLAN)|REBUILD_L2TP_/);
                assert.deepEqual(log, actions);
                assert.equal(disabled, !refused);
                assert.equal(refreshHidden, refused);
            });
        }
    }
});
