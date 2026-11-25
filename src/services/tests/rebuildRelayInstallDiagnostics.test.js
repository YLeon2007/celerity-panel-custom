'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash, webcrypto } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { runInNewContext } = require('node:vm');
const express = require('express');
const session = require('express-session');
const { request } = require('./helpers/rebuildPanelRequest');
const { createRelayDirect } = require('../rebuildRelayDirect');
const attested = require('./helpers/rebuildRelayDirectWire');
const { runFreshRelayInstall } = require('../rebuildRelayInstall');
const { installCheckIds, freshConflictFromFrame } = require('../rebuildRelayInstallDiagnostics');
const { AcknowledgedCommitCleanupError } = require('../rebuildRelayInstallTransaction');
const { i18nMiddleware, t: translate } = require('../../middleware/i18n');

const nodeId = 'a'.repeat(24), machineId = 'b'.repeat(32), marker = 'FIXTURE_PRIVATE_VALUE';
const base = '/panel/rebuild/relays';
const installUrl = `${base}/${nodeId}/l2tp/install`;
const progressUrl = `${installUrl}/progress`, overviewUrl = '/panel/l2tp';
const observation = 'x-rebuild-l2tp-observation';
const progressAt = new Date('2026-01-01T00:00:00Z');
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

async function localizedFrontend(html, expected, { app, headers, csrf }) {
    const attr = (source, key) => {
        const match = new RegExp(`\\b${key}="([^"]*)"`).exec(source);
        assert.ok(match, `SSR attribute missing: ${key}`);
        const entities = { '#34': '"', '#39': "'", lt: '<', gt: '>', amp: '&' };
        return match[1].replace(/&(#34|#39|lt|gt|amp);/g, (_, name) => entities[name]);
    };
    const pageTag = markup => markup.match(/<div id="rebuild-l2tp"[^>]*>/)[0];
    const open = pageTag(html);
    const dataset = { csrf: attr(open, 'data-csrf'), messages: attr(open, 'data-messages'),
        installChecks: attr(open, 'data-install-checks') };
    assert.equal(dataset.csrf, csrf);
    const status = { textContent: '' }, refresh = { hidden: true, addEventListener() {} };
    const label = { textContent: '' }, bar = { value: 0 };
    let view;
    function renderView(markup) {
        assert.match(markup, /<div data-l2tp-view>/);
        const button = markup.match(/<button[^>]*\bdata-install-url=[^>]*>/)[0];
        const progressTag = markup.match(/<div data-install-progress[^>]*>/)[0];
        const install = { disabled: /\sdisabled(?:\s|>)/.test(button),
            dataset: { installUrl: attr(button, 'data-install-url'), nodeId: attr(button, 'data-node-id') },
            addEventListener(event, callback) { assert.equal(event, 'click'); this.click = callback; } };
        const progress = { hidden: /\shidden(?:\s|>)/.test(progressTag),
            dataset: { progressUrl: attr(progressTag, 'data-progress-url'), progressWords: attr(progressTag, 'data-progress-words') },
            get isConnected() { return view.progress === this; },
            querySelector: key => ({ '[data-progress-text]': label, progress: bar })[key] ?? null };
        return { install, progress, progressNode: attr(progressTag, 'data-progress-node'),
            replaceWith(next) { assert.equal(view, this); view = next; } };
    }
    view = renderView(html);
    const initialView = view;
    const page = { dataset,
        contains: element => element === view.install,
        querySelector: key => ({ '[data-action-status]': status, '[data-refresh]': refresh, '[data-l2tp-view]': view,
            [`[data-install-progress][data-progress-node="${view.progressNode}"]`]: view.progress })[key] ?? null,
        querySelectorAll: key => key === '[data-install-url]' ? [view.install] : [] };
    const document = { getElementById: id => id === 'rebuild-l2tp' ? page : null,
        createElement(tag) {
            assert.equal(tag, 'template');
            return { set innerHTML(markup) {
                const parsed = renderView(markup);
                this.content = { querySelector: key => key === '#rebuild-l2tp' ? {
                    dataset: { csrf: attr(pageTag(markup), 'data-csrf') },
                    querySelector: selector => selector === '[data-l2tp-view]' ? parsed : null,
                } : null };
            } };
        } };
    const calls = [], timers = new Map();
    let now = 0, interval, releasePost, overviewReads = 0;
    const heldPost = new Promise(resolve => { releasePost = resolve; });
    const flush = () => new Promise(resolve => setImmediate(resolve));
    async function advance(to) {
        now = to;
        for (const [key, { at, callback }] of timers) {
            if (at <= now) { timers.delete(key); callback(); }
        }
        await flush();
    }
    const unknown = expected.error.outcome === 'unknown';
    const location = { origin: 'http://panel.fixture.invalid', reload: () => assert.fail('no automatic reload') };
    const window = Object.assign(new EventTarget(), { location, crypto: webcrypto });
    const context = { document, window, location, URL, CustomEvent, AbortController, Headers,
        performance: { now: () => now }, Date: class extends Date { static now() { return now; } },
        setTimeout(callback, delay) { const key = {}; timers.set(key, { at: now + delay, callback }); return key; },
        clearTimeout: key => timers.delete(key),
        setInterval(callback, delay) { interval = { callback, delay }; return interval; },
        clearInterval(key) { if (key === interval) interval = undefined; },
        async fetch(path, options) {
            const { method, body, headers: sent } = options;
            const call = { path, options };
            calls.push(call);
            const post = method === 'POST' && path === installUrl && calls.length === 1;
            const read = method === 'GET' && (path === progressUrl || path === overviewUrl);
            if (!post && !read) throw new Error('unexpected diagnostic UI request');
            // Forward the browser's actual headers, not a fixture-injected CSRF token or nonce.
            const forwarded = Object.fromEntries(Object.entries(sent ?? {}).map(([key, value]) => [key.toLowerCase(), value]));
            const result = await (call.reply = request(app, path, { method, headers: {
                cookie: headers.cookie, 'accept-language': headers['accept-language'], ...forwarded,
            }, ...(body !== undefined && { body: JSON.parse(body) }) }));
            if (post) await heldPost;
            // First ambiguous read models otherwise valid HTML with a different session token.
            const wrongCsrf = path === overviewUrl && unknown && ++overviewReads === 1;
            return { status: result.status, ok: result.status >= 200 && result.status < 300,
                url: new URL(path, location.origin).href, redirected: result.status >= 300 && result.status < 400,
                headers: new Headers(result.headers), json: async () => JSON.parse(result.body),
                text: async () => wrongCsrf ? result.body.replace(`data-csrf="${csrf}"`, 'data-csrf="wrong-session"') : result.body };
        },
    };
    const scripts = [...html.matchAll(/<script src="\/js\/(rebuild-l2tp(?:-install-progress)?\.js)\?v=[a-f0-9]+" defer><\/script>/g)]
        .map(match => match[1]);
    assert.deepEqual(scripts, ['rebuild-l2tp-install-progress.js', 'rebuild-l2tp.js']);
    for (const script of scripts) runInNewContext(readFileSync(join(root, 'public/js', script), 'utf8'), context, { filename: script });
    assert.equal(calls.length, 0);

    const { install, progress } = initialView;
    install.click();
    assert.equal(install.disabled, true);
    install.click(); // Deliberately reach the handler despite the disabled button.
    assert.deepEqual(calls.map(call => [call.options.method, call.path]), [['POST', installUrl]]);
    const post = calls[0].options;
    assert.equal(post.headers['x-csrf-token'], csrf);
    assert.deepEqual(JSON.parse(post.body), {});
    const token = post.headers[observation];
    assert.match(token, /^[a-f0-9]{32}$/);
    assert.equal(progress.hidden, false);
    assert.equal(label.textContent, translate('rebuildL2tp.installProgress.preflight', headers['accept-language']));
    assert.equal(interval?.delay, 2000);
    await interval.callback();
    const checkRead = (index, path, headers) => {
        assert.equal(calls.length, index + 1);
        const call = calls[index];
        assert.equal(call.path, path);
        const { method, body, headers: sent, cache, credentials, redirect, signal } = call.options;
        assert.deepEqual([method, body, cache, credentials, redirect], ['GET', undefined, 'no-store', 'same-origin', 'error']);
        assert.deepEqual({ ...sent }, headers);
        assert.ok(signal instanceof AbortSignal);
        return call;
    };
    const progressRead = checkRead(1, progressUrl, {});
    assert.equal((await progressRead.reply).status, 200);
    assert.equal(bar.value, 10);
    assert.equal(label.textContent, translate('rebuildL2tp.installProgress.reserve', headers['accept-language']));
    const result = await calls[0].reply;
    assert.equal(result.status, 409);
    assert.deepEqual(JSON.parse(result.body), expected);
    releasePost();
    await flush();
    assert.equal(interval, undefined);
    assert.equal(progress.hidden, true);
    assert.equal(progressRead.options.signal.aborted, true);

    const initialText = status.textContent;
    let readCount = 0;
    if (unknown) {
        // The refresh control remains hidden while automatic readback is busy.
        assert.equal(refresh.hidden, true);
        await advance(1999);
        assert.equal(calls.length, 2);
        for (const time of [2000, 4000]) {
            await advance(time);
            assert.equal(view.install.disabled, true);
            view.install.click();
            const read = checkRead(2 + readCount++, overviewUrl, { Accept: 'text/html', [observation]: token });
            const snapshot = await read.reply;
            assert.equal(snapshot.status, 200);
            assert.equal(snapshot.headers[observation], undefined, 'no acknowledgement for an unknown install');
            await flush();
            assert.equal(view === initialView, time === 2000, 'replace only a CSRF-matched overview');
            assert.equal(status.textContent, initialText, 'read-only overview must not settle the unknown install');
        }
        await advance(300000); // Expire the observation window without waiting or replaying missed slots.
        assert.equal(timers.size, 0);
    } else if (['rolled_back', 'installed'].includes(expected.error.outcome)) {
        const read = checkRead(2 + readCount++, overviewUrl, { Accept: 'text/html' });
        assert.equal((await read.reply).status, 200);
        await flush();
        assert.notEqual(view, initialView);
    }
    if (unknown || readCount) {
        install.click(); // Detached after an accepted GET.
        view.install.click(); // Still refresh-required, even on the new view.
    }
    assert.equal(calls.length, 2 + readCount);
    return { initialText, finalText: status.textContent, disabled: view.install.disabled, refreshHidden: refresh.hidden };
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
    const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
    t.mock.method(State, 'findOne', ({ node: id }) => {
        assert.equal(id, nodeId);
        const read = { select: () => read, read: () => read, readConcern: () => read, setOptions: () => read,
            lean: async () => ({ status: 'installing', installProgress: { stage: 'reserve', percent: 10, at: progressAt } }) };
        return read;
    });
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
        assert.deepEqual(Object.keys(words.installChecks).sort(), [...installCheckIds].sort());
        for (const key of ['REBUILD_LINKS_NOT_APPLIED', 'XRAY_BASELINE_UNSUPPORTED', 'XRAY_PROFILE_OWNER_UNSUPPORTED',
            'XRAY_PROFILE_USERS_UNPROVED', 'XRAY_RUNTIME_UNPROVED']) {
            assert.ok(words.installChecks?.[key], `${lang}: ${key}`);
        }
        const headers = { ...auth, 'accept-language': lang };
        const { status, body } = await request(app, overviewUrl, { method: 'GET', headers });
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
            const { initialText, finalText, disabled, refreshHidden } = await localizedFrontend(body, expected, { headers, app, csrf });
            const note = check ? ` ${translate(`rebuildL2tp.installChecks.${check}`, lang)}` : '';
            const stopped = text => translate('rebuildL2tp.messages.installStopped', lang).replace('{reason}', text);
            const summary = translate(`rebuildL2tp.messages.${message}`, lang) + note;
            const failed = ['refused', 'rolled_back', 'busy'].includes(outcome);
            assert.equal(initialText, outcome === 'unknown' ? translate('rebuildL2tp.messages.checkingResult', lang)
                : failed ? stopped(summary) : summary, `${name}: ${lang}`);
            assert.equal(finalText, outcome === 'unknown' ? translate('rebuildL2tp.messages.observationTimeout', lang) + note
                : failed ? stopped(summary) : summary, `${name}: ${lang}`);
            assert.deepEqual(log, actions, name);
            assert.equal(disabled, ['unknown', 'rolled_back', 'installed'].includes(outcome), name);
            assert.equal(refreshHidden, !disabled, name);
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
            if (action === 'prove-applied-main') return ok({ applied: input.appliedMain === snapshot.mainSha256 });
            if (action === packageWrite) {
                assert.match(reservation.backupId, /^[a-f0-9]{32}$/);
                assert.deepEqual(input, { action, machineId, backupId: reservation.backupId, packagePreparation, appliedMain: snapshot.mainSha256, progress: true });
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
        proveMain: (_, remote, guard) => remote.proveAppliedMain(snapshot.mainSha256, guard),
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
        const page = await request(app, overviewUrl, { method: 'GET', headers });
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
                const { initialText, finalText, disabled, refreshHidden } = await localizedFrontend(page.body, expected, { headers, app, csrf });
                const note = check ? ` ${installChecks[check]}` : '';
                const stopped = messages.installStopped.replace('{reason}', messages.installRefused + note);
                assert.equal(initialText, refused ? stopped : messages.checkingResult);
                assert.equal(finalText, refused ? stopped : messages.observationTimeout + note);
                for (const text of [initialText, finalText]) {
                    assert.doesNotMatch(text, /FIXTURE_PRIVATE_VALUE|\/fixture\/|Traceback|PACKAGE_(SOURCES|INDEXES|SERVICES|APT_PLAN)|REBUILD_L2TP_/);
                }
                assert.deepEqual(log, actions);
                assert.equal(disabled, !refused);
                assert.equal(refreshHidden, refused);
            });
        }
    }
});


const typedForeignKeys = ['SWAN_PROFILE_PRESENT', 'IKE_PROFILE_PRESENT', 'OPTIONS_PRESENT', 'STARTER_NOT_STOCK',
    'SECRETS_NOT_EMPTY', 'CHAP_NOT_EMPTY', 'LNS_NOT_STOCK', 'XRAY_UNIT_0666', 'XRAY_BRIDGE_UNIT_0666',
    'UNIT_WRITABLE', 'NFT_DIR_PRESENT', 'DROPIN_PRESENT', 'MODULES_LOAD_FOREIGN'];

test('closed foreign-config grammar accepts exactly ordered, bounded diagnostics for fresh actions', () => {
    const action = 'install';
    const header = 'DIRECT_NO_WRITE_L2TP_FOREIGN_CONFIG ';
    const full = `${header}${typedForeignKeys.join(',')}\n`;
    assert.equal(Buffer.byteLength(full), 261);
    assert.deepEqual(freshConflictFromFrame(action, refusal(full)), { check: 'L2TP_FOREIGN_CONFIG', keys: typedForeignKeys });
    for (const id of typedForeignKeys) {
        const item = refusal(`${header}${id}\n`);
        assert.deepEqual(freshConflictFromFrame(action, item), { check: 'L2TP_FOREIGN_CONFIG', keys: [id] });
        for (const other of ['verify', 'rollback', 'prepare-packages', 'prepare-remove']) {
            assert.equal(freshConflictFromFrame(other, item), undefined);
        }
    }
    for (const bad of [full + '\n', full.replace('\n', '\r\n'), full.replace(',', ', '),
        `${header}chap-secrets\n`, `${header}/etc/ipsec.conf\n`, `${header}CHAP_NOT_EMPTY,\n`,
        `${header}CHAP_NOT_EMPTY,CHAP_NOT_EMPTY\n`, `${header}UNIT_WRITABLE\t\n`,
        'DIRECT_NO_WRITE_CHAP_NOT_EMPTY\n', `${header}__proto__\n`]) {
        assert.equal(freshConflictFromFrame(action, refusal(bad)), undefined);
    }
});

test('fresh L2TP conflicts reach only the authenticated Install refusal envelope', async t => {
    const keys = typedForeignKeys;
    const foreign = 'L2TP_FOREIGN_CONFIG';
    const allowed = [foreign, 'L2TP_DAEMON_ACTIVE', 'L2TP_UDP_BOUND', 'L2TP_PPP_ACTIVE'];
    const frame = (check, list) => refusal(`DIRECT_${check}${list ? ` ${list}` : ''}\n`);
    let result, actions;
    class SSH {
        connect() {}
        disconnect() {}
        async exec(_command, { stdin }, verify) {
            await verify();
            actions.push(JSON.parse(stdin).action);
            return result;
        }
    }
    const { app, auth, csrf } = await diagnosticPanel(t, id => runFreshRelayInstall(id, {
        authorize: () => true, machineId, inventory: async () => ({ eligible: true, pristine: true }),
        lock: fn => fn(() => true), connect: async () => createRelayDirect({ node, env, SSH: attested(SSH, machineId) }),
        reserve: async () => assert.fail('must not reserve'),
    }));
    const headers = { ...auth, 'x-csrf-token': csrf };
    const requestInstall = async () => {
        actions = [];
        const reply = await request(app, installUrl, { headers, body: {} });
        assert.equal(reply.status, 409);
        assert.equal(reply.headers['cache-control'], 'no-store');
        assert.deepEqual(actions, ['preflight']);
        return JSON.parse(reply.body);
    };
    for (const check of allowed) {
        const listing = check === foreign ? keys : undefined;
        result = frame(check, listing);
        assert.deepEqual(await requestInstall(), { error: { code: `REBUILD_${check}`, outcome: 'refused', check,
            ...(listing && { keys: listing }) } });
    }
    for (const bad of [frame(foreign), frame(foreign, [keys[0], keys[0]]), frame(foreign, [...keys].reverse()),
        frame(foreign, [keys[0], marker]), frame(foreign, [keys[0], 'a'.repeat(64)]),
        frame(`NO_WRITE_${foreign}`, keys), frame('L2TP_UDP_BOUND', keys),
        { ...frame(foreign, keys), stdout: marker }, { ...frame(foreign, keys), code: 75 },
        refusal(frame(foreign, keys).stderr + `/${marker}\n`)]) {
        result = bad;
        assert.deepEqual(await requestInstall(), { error: { code: 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN', outcome: 'unknown' } });
    }
    for (const lang of ['ru', 'en', 'zh-CN']) {
        const localized = { ...auth, 'accept-language': lang };
        const page = await request(app, overviewUrl, { method: 'GET', headers: localized });
        assert.equal(page.status, 200);
        const copies = require(`../../locales/${lang}.json`).rebuildL2tp.installChecks;
        for (const id of keys) {
            assert.ok(copies[id] && page.body.includes(copies[id]), `${lang}: ${id}`);
        }
        for (const check of allowed) {
            const copy = require(`../../locales/${lang}.json`).rebuildL2tp.installChecks[check];
            assert.ok(copy && page.body.includes(copy));
            const listing = check === foreign ? keys : undefined;
            result = frame(check, listing);
            const expected = { error: { code: `REBUILD_${check}`, outcome: 'refused', check,
                ...(listing && { keys: listing }) } };
            const view = await localizedFrontend(page.body, expected, { app, headers: localized, csrf });
            const detail = [copy, ...(listing ?? []).map(key => copies[key])].join(' ');
            const stopped = translate('rebuildL2tp.messages.installStopped', lang)
                .replace('{reason}', `${translate('rebuildL2tp.messages.installRefused', lang)} ${detail}`);
            assert.equal(view.initialText, stopped);
            assert.equal(view.finalText, stopped);
        }
        assert.doesNotMatch(page.body, /data-(replace|cleanup)-url/);
    }
});


test('late L2TP conflict preserves Install cleanup authority and never calls rollback', async t => {
    const snapshot = { ...ready, main, mainSha256: createHash('sha256').update(main).digest('hex'),
        bridge: null, bridgeSha256: null, baseline: 'd'.repeat(64) };
    let frame, actions, lostRestore;
    class SSH {
        connect() {}
        disconnect() {}
        async exec(_command, { stdin }, verify) {
            await verify();
            const { action, backupId } = JSON.parse(stdin);
            actions.push(action);
            if (action === 'preflight') return ok(ready);
            if (action === 'prepare') return ok(snapshot);
            if (action === 'check') return ok({ ok: true, backupId });
            assert.equal(action, 'install');
            return frame;
        }
    }
    const { app, auth, csrf } = await diagnosticPanel(t, id => runFreshRelayInstall(id, {
        authorize: () => true, machineId, inventory: async () => ({ eligible: true, pristine: true }),
        unifiedIdentity: true, lock: fn => fn(() => true, () => actions.push('retain')),
        connect: async () => createRelayDirect({ node, env, SSH: attested(SSH, machineId) }),
        prepare: (_, remote) => remote.prepare({ nodeId, desired, carryDomain: false, controlPlaneAddresses: ['panel.fixture.invalid'] }),
        reserve: async () => { actions.push('reserve'); return {}; }, verifyReservation: async () => {},
        restore: async () => { actions.push('restore'); if (lostRestore) throw Error(marker); },
        finish: async () => assert.fail('must not publish Install'),
    }));
    const foreign = 'L2TP_FOREIGN_CONFIG';
    const late = (prefix = 'NO_WRITE_') => refusal(`DIRECT_${prefix}${foreign} CHAP_NOT_EMPTY\n`);
    for (const [reply, lost, expected, tail] of [
        [late(), false, { code: `REBUILD_${foreign}`, outcome: 'refused', check: foreign, keys: ['CHAP_NOT_EMPTY'] }, ['restore']],
        [late(), true, { code: 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN', outcome: 'unknown', check: foreign, retryAllowed: false }, ['restore', 'retain']],
        [late(''), false, { code: 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN', outcome: 'unknown', retryAllowed: false }, ['retain']],
        [refusal('DIRECT_PROGRESS restart\n' + late().stderr), false,
            { code: 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN', outcome: 'unknown', retryAllowed: false }, ['retain']],
    ]) {
        [frame, lostRestore, actions] = [reply, lost, []];
        const response = await request(app, installUrl, { headers: { ...auth, 'x-csrf-token': csrf }, body: {} });
        assert.equal(response.status, 409);
        assert.deepEqual(JSON.parse(response.body), { error: expected });
        assert.deepEqual(actions, ['preflight', 'preflight', 'prepare', 'check', 'reserve', 'install', ...tail]);
    }
});
