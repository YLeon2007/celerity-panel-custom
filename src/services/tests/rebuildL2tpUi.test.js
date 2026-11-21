'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { runInNewContext } = require('node:vm');
const { mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { pathToFileURL } = require('node:url');
const ejs = require('ejs');
const { t } = require('../../middleware/i18n');
const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');

const root = join(__dirname, '../../..');
const route = '/panel/rebuild/relays';
const id = 'a'.repeat(24), otherId = 'b'.repeat(24), csrf = 'test-"<&-csrf';
const hostile = '\"><img src=x onerror=alert(1)>&';
const bindingRu = 'Нет привязки SSH/machine-id, добавьте релей в настройки оператора';
const statuses = State.schema.path('status').enumValues;
const rebuildL2tpScriptVersion = createHash('sha256')
    .update(readFileSync(join(root, 'public/js/rebuild-l2tp.js'))).digest('hex').slice(0, 16);
const scriptTag = `<script src="/js/rebuild-l2tp.js?v=${rebuildL2tpScriptVersion}" defer></script>`;

const installed = { id, name: hostile, ip: '192.0.2.42', status: 'installed', bound: true, canInstall: false,
    canRemove: true, canRevealPsk: true, psk: 'SERVER-ONLY-PSK', pskEncrypted: 'SERVER-ONLY-ENCRYPTED' };
const fresh = { id: otherId, name: 'East', ip: '192.0.2.43', status: 'not_installed', bound: true, canInstall: true,
    canRemove: false, canRevealPsk: false };
const account = { login: 'alice.test', enabled: true, consistent: true, canRevealPassword: true, password: 'SERVER-ONLY-PASSWORD',
    addresses: [{ id, ip: '10.66.0.42' }, { id: otherId, ip: '10.67.0.42' }] };
const unsafeAccount = { login: hostile, enabled: false, consistent: false, addresses: [{ id, ip: hostile }] };

async function render(lang, overrides) {
    const translate = key => t(key, lang);
    const data = { page: 'l2tp', title: translate('rebuildL2tp.title'), csrfToken: csrf, t: translate, lang,
        relays: [installed, fresh], accounts: [account, unsafeAccount], canManageAccounts: true, rebuildL2tpScriptVersion, ...overrides };
    const content = await ejs.renderFile(join(root, 'views/rebuild-l2tp.ejs'), data);
    const layout = await ejs.renderFile(join(root, 'views/layout.ejs'), { ...data, content });
    return { content, layout };
}

test('rebuild L2TP SSR composes with layout and does not serialize private or untrusted markup', async () => {
    const { layout } = await render('en');
    assert.match(layout, /href="\/panel\/l2tp" class="active"/);
    assert.match(layout, /<h1>L2TP\/IPsec relays<\/h1>/);
    assert.ok(layout.includes(scriptTag));
    for (const text of ['192.0.2.42', 'alice.test', '10.66.0.42', '10.67.0.42']) assert.ok(layout.includes(text));
    assert.ok(layout.includes('&#34;&gt;&lt;img src=x onerror=alert(1)&gt;&amp;'));
    assert.doesNotMatch(layout, /SERVER-ONLY-|<img src=x|type="password"/);
    assert.ok(layout.includes(`/panel/nodes/${id}#rebuild-l2tp-remove`));
    assert.ok(!layout.includes(`${route}/${id}/l2tp/remove`));
    assert.ok(layout.includes(`${route}/${otherId}/l2tp/install`));
    const { content } = await render('en', { relays: [{ ...installed, id: '../odd#id?x=1' }], accounts: [] });
    assert.doesNotMatch(content, /\/panel\/nodes\/\.\.|data-secret-url=|data-install-url=/);
});

test('a read-only singleton exposes password reveal but no account mutation controls', async () => {
    const { content } = await render('en', { canManageAccounts: false, accounts: [{ ...account, login: 'relay-bootstrap' }] });
    assert.ok(content.includes(`${route}/l2tp/accounts/reveal`));
    assert.doesNotMatch(content, /data-create|data-account-action|SERVER-ONLY-PASSWORD/);
});

test('pending supersedes generic conflict/unavailable text and hides mutation and reveal controls in RU and EN', async () => {
    for (const [lang, message] of [['ru', 'Незавершённая операция, выполняется сверка'], ['en', 'Unfinished operation, reconciliation in progress']]) {
        const { content } = await render(lang, { accountsPending: true, canReconcileAccounts: true });
        assert.match(content, new RegExp(`>${message}<`));
        assert.ok(content.includes(`data-reconcile-url="${route}/l2tp/accounts/reconcile"`));
        for (const key of ['inconsistent', 'accountsReadOnly', 'loadError']) assert.ok(!content.includes(t(`rebuildL2tp.${key}`, lang)));
        assert.doesNotMatch(content, /data-create|data-account-action|data-secret-url|data-install-url|#rebuild-l2tp-remove|SERVER-ONLY-/);
    }
    const singleton = await render('ru', { accountsPending: true, canReconcileAccounts: false });
    assert.doesNotMatch(singleton.content, /data-reconcile-url|data-secret-url/);
    const clear = await render('ru');
    assert.doesNotMatch(clear.content, /data-reconcile-url/);
});

test('opening a pending section POSTs once, then shows settled, pending or unconfirmed without retry/reload', async () => {
    const script = readFileSync(join(root, 'public/js/rebuild-l2tp.js'), 'utf8');
    for (const [outcome, responseStatus, receipt, messageKey, count] of [
        ['settled', 200, { executionMode: 'rebuild', status: 'settled' }, 'reconcileSettled'],
        ['settled with closures', 200, { executionMode: 'rebuild', status: 'settled', sessionsTerminated: 2,
            sessionsTerminatedScope: 'request' }, 'reconcileSettled', 2],
        ['unscoped', 200, { executionMode: 'rebuild', status: 'settled', sessionsTerminated: 2 }, 'reconcileSettled'],
        ['pending', 200, { executionMode: 'rebuild', status: 'pending', sessionsTerminated: 2,
            sessionsTerminatedScope: 'request' }, 'reconcileStillPending'],
        ['refused', 503, { error: { message: 'PRIVATE_FIXTURE' } }, 'reconcileUnconfirmed'],
        ['unexpected', 200, { executionMode: 'classic', status: 'settled' }, 'reconcileUnconfirmed'],
        ['lost', null, null, 'reconcileUnconfirmed'],
        ['disabled', null, null, null],
    ]) {
        const url = `${route}/l2tp/accounts/reconcile`;
        const words = require('../../locales/ru.json').rebuildL2tp;
        const status = { textContent: words.accountsPending }, refresh = { hidden: true };
        const page = {
            dataset: { csrf, messages: JSON.stringify(words.messages), ...(messageKey && { reconcileUrl: url }) },
            querySelector: key => ({ '[data-action-status]': status, '[data-refresh]': refresh })[key] ?? null,
            querySelectorAll: () => [],
        };
        const calls = [];
        runInNewContext(script, {
            document: { getElementById: () => page },
            window: { addEventListener() {}, location: { reload: () => calls.push('reload') } },
            async fetch(path, options) {
                calls.push({ path, options });
                if (responseStatus === null) throw new Error('PRIVATE_FIXTURE');
                return { ok: responseStatus === 200, status: responseStatus, json: async () => receipt };
            },
        });
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(calls.length, messageKey ? 1 : 0, outcome);
        assert.equal(refresh.hidden, !messageKey, outcome);
        const message = messageKey ? words.messages[messageKey] : words.accountsPending;
        assert.equal(status.textContent, count === undefined ? message : `${message} Подтверждено завершение сеансов этим запросом: ${count}.`, outcome);
        if (messageKey) {
            assert.equal(calls[0].path, url);
            const { method, headers, credentials, mode, body, redirect, cache } = calls[0].options;
            assert.deepEqual({ method, credentials, mode, body, redirect, cache, ...headers }, {
                method: 'POST', credentials: 'same-origin', mode: 'same-origin', body: '{}', redirect: 'error', cache: 'no-store',
                'x-csrf-token': csrf, 'Content-Type': 'application/json',
            });
        }
    }
});

test('renders EN, RU and English fallback for every relay status and fails closed for missing binding and load error', async () => {
    const relays = statuses.map((status, i) => ({ ...fresh, id: i.toString(16).padStart(24, '0'), status, canInstall: false }));
    relays.push({ ...installed, status: 'constructor', bound: false, canInstall: true });
    for (const lang of ['en', 'ru', 'zh-CN']) {
        const { content } = await render(lang, { relays, accounts: [], canManageAccounts: false });
        const files = require(`../../locales/${lang === 'zh-CN' ? 'en' : lang}.json`).rebuildL2tp;
        for (const status of statuses) {
            assert.ok(files.status[status], `${lang}: missing ${status}`);
            assert.ok(content.includes(`>${files.status[status]}</`), `${lang}: did not render ${status}`);
        }
        assert.ok(content.includes(files.status.unknown));
        assert.ok(content.includes(lang === 'ru' ? bindingRu : 'No SSH/machine-id binding. Add the relay to the operator settings.'));
        assert.doesNotMatch(content, /constructor|data-install-url=|data-secret-url=|#rebuild-l2tp-remove|data-create/);
    }
    const { content } = await render('ru', { loadError: true });
    assert.ok(content.includes(t('rebuildL2tp.loadError', 'ru')));
    assert.doesNotMatch(content, /data-install-url=|data-secret-url=|#rebuild-l2tp-remove|data-create/);
    const en = require('../../locales/en.json').rebuildL2tp;
    const ru = require('../../locales/ru.json').rebuildL2tp;
    const leaves = (value, prefix = '') => Object.entries(value).flatMap(([key, entry]) =>
        typeof entry === 'string' ? [prefix + key] : leaves(entry, `${prefix}${key}.`)).sort();
    assert.deepEqual(leaves(ru), leaves(en));
});

// This runs against Firefox's actual DOM, events and Web Crypto. Only fetch,
// the OS clipboard and the confirmation prompt are replaced at the boundary.
async function browserScenario({ route, id, otherId, csrf, words, terminal }) {
    const check = (value, message) => { if (!value) throw new Error(message); };
    const $ = selector => document.querySelector(selector);
    const $$ = selector => [...document.querySelectorAll(selector)];
    const flush = () => new Promise(resolve => setTimeout(resolve, 0));
    const response = (data, status = 200) => ({ status, ok: status >= 200 && status < 300, json: async () => data });
    const waitFor = async (predicate, message) => {
        for (let attempts = 0; attempts < 100; attempts++) {
            if (predicate()) return;
            await flush();
        }
        throw new Error(message);
    };
    const marker = '<b>fixture secret & text</b>';
    const fetchCalls = [], clipboard = [];
    let respond, confirmChoice = false;
    window.fetch = (url, options) => {
        fetchCalls.push({ url, options });
        return respond();
    };
    window.confirm = () => confirmChoice;
    Object.defineProperty(navigator, 'clipboard', { value: {
        async writeText(text) { clipboard.push(text); },
        async write(items) { clipboard.push(await (await items[0].getType('text/plain')).text()); },
    } });
    const params = (path, body, keys = Object.keys(body)) => {
        const { url, options } = fetchCalls.at(-1);
        check(url === path && options.method === 'POST', 'wrong POST target');
        const headers = new Headers(options.headers);
        check(headers.get('x-csrf-token') === csrf && headers.get('content-type') === 'application/json', 'CSRF or content type missing');
        check(options.credentials === 'same-origin' && options.mode === 'same-origin' && options.cache === 'no-store' &&
            options.redirect === 'error', 'unsafe fetch options');
        const payload = JSON.parse(options.body);
        check(JSON.stringify(Object.keys(payload).sort()) === JSON.stringify([...keys].sort()), 'wrong POST fields');
        check(Object.keys(body).every(key => body[key] === payload[key]), 'wrong POST values');
        return payload;
    };
    await new Promise(resolve => window.addEventListener('load', resolve, { once: true }));
    await flush();
    check(fetchCalls.length === 0, 'fetched without user action');
    check(!$('#rebuild-l2tp').innerHTML.includes(marker) && !$('img[src="x"]'), 'unsafe initial DOM');

    const [psk, password] = $$('[data-secret-url]');
    const relayEye = psk.querySelector('[data-show-secret]'), relayText = psk.querySelector('[data-secret-value]');
    const eye = password.querySelector('[data-show-secret]'), value = password.querySelector('[data-secret-value]');
    const copy = password.querySelector('[data-copy-secret]');
    check(eye.getAttribute('aria-label') === words.password.show && copy.getAttribute('aria-label') === words.password.copy, 'inaccessible secret controls');
    const accountReveal = `${route}/l2tp/accounts/reveal`;
    respond = async () => response({ secret: marker });
    eye.click();
    await flush();
    params(accountReveal, { login: 'alice.test' });
    check(!value.hidden && value.textContent === marker && !value.firstElementChild, 'show did not safely render secret');
    check(eye.getAttribute('aria-label') === words.password.hide && eye.getAttribute('aria-expanded') === 'true', 'eye does not expose hide state');
    eye.click();
    check(value.hidden && value.textContent === '', 'hide retained secret');
    check(fetchCalls.length === 1, 'hide fetched again');
    copy.click();
    await waitFor(() => clipboard.length === 1, 'hidden copy did not reach the clipboard');
    params(accountReveal, { login: 'alice.test' });
    check(clipboard.length === 1 && clipboard[0] === marker && value.hidden && value.textContent === '', 'hidden copy leaked or failed');
    relayEye.click();
    await flush();
    params(`${route}/${id}/l2tp/psk/reveal`, {});
    check(relayText.textContent === marker, 'relay PSK was not shown');
    psk.querySelector('[data-copy-secret]').click();
    await flush();
    check(clipboard.length === 2 && clipboard[1] === marker && fetchCalls.length === 3, 'visible copy made an extra request or failed');

    let finish;
    respond = () => new Promise(resolve => { finish = resolve; });
    eye.click();
    check(eye.getAttribute('aria-label') === words.password.hide, 'pending reveal is not cancellable');
    eye.click();
    finish(response({ secret: marker }));
    await flush();
    check(value.hidden && value.textContent === '', 'stale response after hide was displayed');
    copy.click();
    window.dispatchEvent(new PageTransitionEvent('pagehide'));
    finish(response({ secret: marker }));
    await flush();
    check(relayText.hidden && relayText.textContent === '' && value.hidden && value.textContent === '' && clipboard.length === 2,
        'pagehide did not clear shown data or invalidate a pending copy');
    window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
    respond = async () => response({ error: { code: marker } }, 403);
    eye.click();
    await flush();
    check(password.querySelector('[role="status"]').textContent === words.messages.revealFailed && value.hidden,
        'reveal failure exposed backend text or was not localized');
    check(relayEye.getAttribute('aria-label') === words.psk.show, 'pagehide left the relay eye in its hide state');

    const form = $('[data-create]'), login = form.querySelector('input');
    const submit = form.querySelector('button');
    const disable = $('[data-account-action="disable"]'), del = $('[data-account-action="delete"]');
    const install = $('[data-install-url]'), status = $('[data-action-status]');
    const before = fetchCalls.length;
    del.click();
    check(fetchCalls.length === before, 'cancelled delete posted');
    confirmChoice = true;
    respond = async () => response({ error: { code: marker } }, 429);
    install.click();
    await flush();
    params(`${route}/${otherId}/l2tp/install`, {});
    check(status.textContent === words.messages.rateLimited, 'rate limit was not localized');
    disable.click();
    await flush();
    params(`${route}/l2tp/accounts/disable`, { login: 'alice.test' });
    del.click();
    await flush();
    params(`${route}/l2tp/accounts/delete`, { login: 'alice.test' });

    login.value = 'relay-bootstrap';
    const beforeInvalid = fetchCalls.length;
    submit.click();
    check(fetchCalls.length === beforeInvalid && status.textContent === words.messages.invalidLogin, 'reserved login posted');
    login.value = 'new.user';
    const rng = window.crypto.getRandomValues.bind(window.crypto);
    let randomBytes = 0;
    window.crypto.getRandomValues = array => { randomBytes += array.byteLength; return rng(array); };
    submit.click();
    await flush();
    const first = params(`${route}/l2tp/accounts/create`, { login: 'new.user' }, ['login', 'password']).password;
    check(randomBytes >= 24 && /^[A-Za-z0-9_-]{32,256}$/.test(first), 'password strength or alphabet not suitable');
    check(!document.documentElement.innerHTML.includes(first) && !location.href.includes(first) && localStorage.length === 0,
        'generated password persisted in browser-visible storage');
    window.crypto.getRandomValues = () => { throw new Error('CSPRNG unavailable'); };
    const beforeFailure = fetchCalls.length;
    submit.click();
    await flush();
    check(fetchCalls.length === beforeFailure && status.textContent === words.messages.cryptoUnavailable, 'weak fallback used or missing localized crypto error');
    window.crypto.getRandomValues = rng;
    let expectedMessage = words.messages.uncertain;
    if (terminal === 'uncertainInstall') {
        respond = async () => response({ error: { code: 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN' } }, 409);
        install.click();
        await flush();
        params(`${route}/${otherId}/l2tp/install`, {});
    } else if (terminal === 'recoveredDisable' || terminal === 'recoveredPartial') {
        const partial = terminal === 'recoveredPartial';
        respond = async () => partial
            ? response({ error: { code: 'REBUILD_L2TP_ACCOUNTS_OUTCOME_UNKNOWN', retryAllowed: false,
                confirmedSessionsTerminated: 2, sessionsTerminatedScope: 'request' } }, 409)
            : response({ executionMode: 'rebuild', status: 'disabled', login: 'alice.test', relayCount: 2,
                recovered: true, sessionsTerminated: 0, sessionsTerminatedScope: 'request' });
        disable.click();
        await flush();
        params(`${route}/l2tp/accounts/disable`, { login: 'alice.test' });
        expectedMessage = partial ? `${words.messages.uncertain} Session closures confirmed by this request: 2.`
            : `${words.messages.disabled} Session closures confirmed by this request: 0.`;
    } else {
        const canceled = terminal === 'canceled' || terminal === 'wrongLogin';
        respond = async () => terminal === 'uncertainAccount'
            ? response({ error: { code: 'REBUILD_L2TP_ACCOUNTS_OUTCOME_UNKNOWN', retryAllowed: false } }, 409)
            : response({ executionMode: 'rebuild', status: canceled ? 'canceled' : 'created',
                login: terminal === 'wrongLogin' ? 'other.user' : 'new.user', relayCount: 1, ...(canceled && { recovered: true }) },
            canceled ? 200 : 201);
        submit.click();
        await flush();
        const second = params(`${route}/l2tp/accounts/create`, { login: 'new.user' }, ['login', 'password']).password;
        check(second !== first, 'password reused between submissions');
        if (terminal === 'created') {
            check(login.value === '', 'successful form was not cleared');
            expectedMessage = words.messages.created;
        }
        if (terminal === 'canceled') {
            check(login.value === 'new.user', 'canceled request was treated as a creation');
            expectedMessage = 'The requested account change was canceled and not applied. Reload L2TP data to see the current state.';
        }
    }
    check(status.textContent === expectedMessage, 'wrong terminal message: ' + status.textContent);
    check(submit.disabled && install.disabled && disable.disabled && !$('[data-refresh]').hidden,
        'terminal action did not require a fresh view');
    const count = fetchCalls.length;
    submit.click();
    install.click();
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    await flush();
    check(fetchCalls.length === count, 'terminal mutation was replayed');
}

const firefox = process.env.REBUILD_L2TP_FIREFOX || 'firefox';
const browserAvailable = spawnSync(firefox, ['--version'], { timeout: 3000 }).status === 0;

for (const [lang, terminal] of [['en', 'uncertainAccount'], ['ru', 'uncertainInstall'], ['en', 'created'],
    ...['canceled', 'wrongLogin', 'recoveredDisable', 'recoveredPartial'].map(terminal => ['en', terminal])]) {
    test(`Firefox: clicks, secret lifecycle and account/relay requests (${lang}, ${terminal})`, {
        skip: browserAvailable ? false : 'requires local Firefox (or REBUILD_L2TP_FIREFOX)',
    }, async () => {
        const { content } = await render(lang);
        const client = readFileSync(join(root, 'public/js/rebuild-l2tp.js'), 'utf8');
        const words = require(`../../locales/${lang}.json`).rebuildL2tp;
        const input = JSON.stringify({ route, id, otherId, csrf, words, terminal }).replaceAll('<', '\\u003c');
        const home = mkdtempSync(join(tmpdir(), 'rebuild-l2tp-ui-'));
        try {
            const settings = {
                'browser.dom.window.dump.enabled': true,
                'browser.shell.checkDefaultBrowser': false,
                'browser.startup.page': 0,
                'network.proxy.type': 1,
                'network.proxy.http': '127.0.0.1', 'network.proxy.http_port': 9,
                'network.proxy.ssl': '127.0.0.1', 'network.proxy.ssl_port': 9,
                'network.proxy.no_proxies_on': '', 'network.proxy.failover_direct': false,
                'network.trr.mode': 5, 'network.dns.disablePrefetch': true,
                'network.prefetch-next': false, 'network.captive-portal-service.enabled': false,
                'network.connectivity-service.enabled': false,
                'app.update.enabled': false, 'extensions.update.enabled': false,
                'toolkit.telemetry.enabled': false, 'datareporting.policy.dataSubmissionEnabled': false,
                'browser.safebrowsing.malware.enabled': false, 'browser.safebrowsing.phishing.enabled': false,
            };
            writeFileSync(join(home, 'user.js'), Object.entries(settings)
                .map(([key, value]) => `user_pref(${JSON.stringify(key)}, ${JSON.stringify(value)});`).join('\n'));
            const file = join(home, 'fixture.html');
            const inline = `<script>(${browserScenario})(${input}).then(() => dump('L2TP_UI:OK\\n'),
                error => dump('L2TP_UI:FAIL ' + error.message + '\\n'));</script><script>${client}</script>`;
            assert.ok(content.includes(scriptTag));
            writeFileSync(file, '<!doctype html><meta charset="UTF-8">' +
                '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'unsafe-inline\'; style-src \'unsafe-inline\'">' +
                content.replace(scriptTag, () => inline));
            await new Promise((resolve, reject) => {
                const child = spawn(firefox, ['--no-remote', '--headless', '--profile', home, pathToFileURL(file).href], {
                    env: { PATH: process.env.PATH, HOME: home, TMPDIR: home, MOZ_CRASHREPORTER_DISABLE: '1' },
                    stdio: ['ignore', 'pipe', 'pipe'],
                });
                let output = '', diagnostics = '', timedOut = false;
                const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, 15000);
                child.stdout.setEncoding('utf8').on('data', chunk => {
                    output += chunk;
                    if (/^L2TP_UI:(?:OK|FAIL .*?)\n/m.test(output)) child.kill();
                });
                child.stderr.setEncoding('utf8').on('data', chunk => { diagnostics += chunk; });
                child.on('error', reject);
                child.on('close', () => {
                    clearTimeout(timer);
                    if (!timedOut && /^L2TP_UI:OK\n/m.test(output)) resolve();
                    else reject(new Error(output.match(/^L2TP_UI:FAIL .*/m)?.[0] || `Firefox fixture did not complete: ${diagnostics}`));
                });
            });
        } finally {
            rmSync(home, { recursive: true, force: true });
        }
    });
}
