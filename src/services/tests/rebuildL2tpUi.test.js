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

test('pending offers manual recovery and hides mutation and reveal controls in RU and EN', async () => {
    for (const [lang, message] of [['ru', 'Есть незавершённая операция. Действия заблокированы.'],
        ['en', 'An unfinished operation is pending. Controls are locked.']]) {
        const { content } = await render(lang, { accountsPending: true, canReconcileAccounts: true });
        assert.ok(content.includes(`>${message}<`));
        assert.ok(content.includes(`data-reconcile-url="${route}/l2tp/accounts/reconcile"`));
        assert.ok(content.includes(`data-reconcile disabled>${t('rebuildL2tp.admission.recoverAccounts', lang)}<`));
        assert.match(content, /href="\/panel\/l2tp" data-refresh hidden/);
        for (const key of ['inconsistent', 'accountsReadOnly', 'loadError']) assert.ok(!content.includes(t(`rebuildL2tp.${key}`, lang)));
        assert.doesNotMatch(content, /data-create|data-account-action|data-secret-url|data-install-url|#rebuild-l2tp-remove|data-admission-action|SERVER-ONLY-/);
    }
    const singleton = await render('ru', { accountsPending: true, canReconcileAccounts: false });
    assert.doesNotMatch(singleton.content, /data-reconcile-url|data-secret-url/);
    const clear = await render('ru');
    assert.doesNotMatch(clear.content, /data-reconcile-url/);
    const refreshed = await render('en', { accountsPending: true, canReconcileAccounts: true, reconcileViewOnly: true });
    assert.match(refreshed.content, />An unfinished operation is pending\. Controls are locked\.</);
    assert.doesNotMatch(refreshed.content, /data-reconcile-url|data-install-url|data-secret-url|data-account-action|data-create/);
});

function clickControl(disabled = false) {
    let click;
    return { disabled, addEventListener(name, handler) { if (name === 'click') click = handler; },
        click() { if (!this.disabled) click?.(); } };
}

test('pending page does not POST until click; each outcome requires a fresh view before retry', async () => {
    const script = readFileSync(join(root, 'public/js/rebuild-l2tp.js'), 'utf8');
    for (const [outcome, responseStatus, receipt, messageKey, count] of [
        ['settled', 200, { executionMode: 'rebuild', status: 'settled' }, 'reconcileSettled'],
        ['settled with closures', 200, { executionMode: 'rebuild', status: 'settled', sessionsTerminated: 2,
            sessionsTerminatedScope: 'request' }, 'reconcileSettled', 2],
        ['unscoped', 200, { executionMode: 'rebuild', status: 'settled', sessionsTerminated: 2 }, 'reconcileSettled'],
        ['pending', 200, { executionMode: 'rebuild', status: 'pending', sessionsTerminated: 2,
            sessionsTerminatedScope: 'request' }, 'reconcileStillPending'],
        ['refused', 503, { error: { message: 'PRIVATE_FIXTURE' } }, 'reconcileUnconfirmed'],
        ['rate limited', 429, { error: { code: 'REBUILD_RATE_LIMITED' } }, 'rateLimited'],
        ['ineligible', 409, { error: { code: 'REBUILD_L2TP_RECONCILE_DISABLED' } }, 'recoveryIneligible'],
        ['unexpected', 200, { executionMode: 'classic', status: 'settled' }, 'reconcileUnconfirmed'],
        ['lost', null, null, 'reconcileUnconfirmed'],
        ['disabled', null, null, null],
    ]) {
        const url = `${route}/l2tp/accounts/reconcile`;
        const words = require('../../locales/ru.json').rebuildL2tp;
        const status = { textContent: words.accountsPendingLocked }, refresh = { hidden: true };
        const recover = messageKey ? Object.assign(clickControl(true), { dataset: { reconcileUrl: url } }) : null;
        const page = {
            contains: () => true, dataset: { csrf, messages: JSON.stringify(words.messages), admissionMessages: JSON.stringify(words.admission),
                ...(messageKey && { reconcileUrl: url }) },
            querySelector: key => ({ '[data-action-status]': status, '[data-refresh]': refresh, '[data-reconcile]': recover })[key] ?? null,
            querySelectorAll: () => [],
        };
        const calls = [];
        let complete;
        runInNewContext(script, {
            AbortController, performance, setTimeout() {}, clearTimeout() {}, document: { getElementById: () => page },
            window: { addEventListener() {}, location: { reload: () => calls.push('reload') } },
            async fetch(path, options) {
                calls.push({ path, options });
                await new Promise(resolve => { complete = resolve; });
                if (responseStatus === null) throw new Error('PRIVATE_FIXTURE');
                return { ok: responseStatus === 200, status: responseStatus, json: async () => receipt };
            },
        });
        await new Promise(resolve => setImmediate(resolve));
        assert.deepEqual(calls, [], outcome);
        assert.equal(status.textContent, words.accountsPendingLocked, outcome);
        assert.equal(refresh.hidden, true, outcome);
        if (recover) {
            assert.equal(recover.disabled, false, outcome);
            recover.click();
            assert.equal(status.textContent, words.messages.working, outcome);
            assert.ok(recover.disabled && refresh.hidden, outcome);
            recover.click();
            assert.equal(calls.length, 1, outcome);
            complete();
            await new Promise(resolve => setImmediate(resolve));
            assert.equal(recover.disabled, true, outcome);
            recover.click();
            await new Promise(resolve => setImmediate(resolve));
        }
        assert.equal(calls.filter(call => call.options.method === 'POST').length, recover ? 1 : 0, outcome);
        assert.equal(calls.filter(call => call.options.method === 'GET').length, messageKey === 'reconcileSettled' ? 1 : 0, outcome);
        assert.equal(refresh.hidden, !messageKey || messageKey === 'reconcileSettled', outcome);
        const message = messageKey ? words.messages[messageKey] ?? words.admission[messageKey] : words.accountsPendingLocked;
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

test('unproved inspection replaces the working status with localized, allowlisted guidance and never unlocks', async () => {
    const script = readFileSync(join(root, 'public/js/rebuild-l2tp.js'), 'utf8');
    const chars = { '&#34;': '"', '&#39;': "'", '&amp;': '&', '&lt;': '<', '&gt;': '>' };
    for (const [lang, guidance] of [
        ['en', 'Do not retry blindly or edit the database.'],
        ['ru', 'Не повторяйте операцию вслепую и не правьте базу данных.'],
    ]) {
        const { content } = await render(lang, { accountsPending: true, canReconcileAccounts: true });
        const messages = /data-messages="([^"]+)"/.exec(content)[1].replace(/&#34;|&#39;|&amp;|&lt;|&gt;/g, match => chars[match]);
        const text = JSON.parse(messages);
        for (const [reason, key] of [
            ['host-inspection-unproved', 'reconcileHostInspection'], ['chap-projection-unproved', 'reconcileChapProjection'],
            ['ppp-unproved', 'reconcilePppInspection'], ['pidfd-getfd-eperm', 'reconcilePidfdGetfdEperm'],
            ['inspect-readback-unproved', 'reconcileInspectReadback'], ['FIXTURE_PRIVATE_DETAIL', null], ['constructor', null],
        ]) {
            const status = { textContent: /data-action-status role="status">([^<]*)</.exec(content)[1] };
            const refresh = { hidden: true }, staleControl = clickControl(), recover = clickControl(true);
            const url = /data-reconcile-url="([^"]+)"/.exec(content)[1];
            recover.dataset = { reconcileUrl: url };
            const page = { contains: () => true, dataset: { csrf, messages },
                querySelector: selector => ({ '[data-action-status]': status, '[data-refresh]': refresh, '[data-reconcile]': recover })[selector] ?? null,
                querySelectorAll: selector => selector === '[data-install-url]' ? [staleControl] : [] };
            const calls = [];
            runInNewContext(script, {
                document: { getElementById: () => page },
                window: { addEventListener() {}, location: { reload: () => calls.push('reload') } },
                async fetch(path) {
                    calls.push(path);
                    return { ok: true, json: async () => ({ executionMode: 'rebuild', status: 'inspection-unproved',
                        reason, retryAllowed: false, message: 'FIXTURE_PRIVATE_DETAIL', sessionsTerminated: 2, sessionsTerminatedScope: 'request' }) };
                },
            });
            await new Promise(resolve => setImmediate(resolve));
            assert.deepEqual(calls, []);
            recover.click();
            assert.equal(status.textContent, text.working);
            assert.ok(staleControl.disabled && recover.disabled);
            await new Promise(resolve => setImmediate(resolve));
            assert.equal(refresh.hidden, false);
            assert.ok(staleControl.disabled && recover.disabled);
            recover.click(); staleControl.click();
            await new Promise(resolve => setImmediate(resolve));
            assert.deepEqual(calls, [url]);
            assert.equal(status.textContent, text.reconcileInspectionUnproved + (key ? ` ${text[key]}` : ''));
            assert.ok(status.textContent.includes(guidance));
            assert.doesNotMatch(status.textContent, /FIXTURE_PRIVATE_DETAIL|undefined|seccomp/i);
            if (reason === 'pidfd-getfd-eperm') assert.match(status.textContent, /pidfd_getfd \(EPERM\)/);
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
        if (options.method === 'GET') return new Promise(() => {});
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
    if (terminal === 'secretPagehide') {
        copy.click();
        window.dispatchEvent(new PageTransitionEvent('pagehide'));
        finish(response({ secret: marker }));
        await flush();
        check(relayText.hidden && relayText.textContent === '' && value.hidden && value.textContent === '' && clipboard.length === 2,
            'pagehide did not clear shown data or invalidate a pending copy');
        check(relayEye.getAttribute('aria-label') === words.psk.show, 'pagehide left the relay eye in its hide state');
        return;
    }
    respond = async () => response({ error: { code: marker } }, 403);
    eye.click();
    await flush();
    check(password.querySelector('[role="status"]').textContent === words.messages.revealFailed && value.hidden,
        'reveal failure exposed backend text or was not localized');

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
                expectedMessage = words.messages.created;
        }
        if (terminal === 'canceled') {
            check(login.value === 'new.user', 'canceled request was treated as a creation');
            expectedMessage = words.messages.canceled;
        }
    }
    check(status.textContent === expectedMessage, 'wrong terminal message: ' + status.textContent);
    check(submit.disabled && install.disabled && disable.disabled,
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

async function admissionVisibility({ route, id, otherId, words, lang }) {
    const $ = selector => document.querySelector(selector);
    const click = selector => $(selector).click();
    const check = (ok, message) => { if (!ok) throw new Error(message); };
    const approvals = ['verify', 'confirm', 'revoke'];
    const dialog = $('[data-admission-dialog]');
    const review = $('[data-review]');
    const visible = el => getComputedStyle(el).display !== 'none' && el.getClientRects().length > 0;
    const consoleCheck = $('[data-admission-console]');
    const command = String.raw`for f in /etc/ssh/ssh_host_*_key.pub; do printf "%-22s %s\n" "$(cut -d" " -f1 "$f")" "$(cut -d" " -f2 "$f" | base64 -d | sha256sum | cut -d" " -f1)"; done; echo; cat /etc/machine-id`;
    const consoleLabel = lang === 'ru'
        ? 'Выполните в консоли провайдера (не через SSH панели) и сравните строку того же типа ключа'
        : 'Run in the provider console (not via panel SSH) and compare the line for the same key type';
    function buttons(step) {
        for (const action of approvals) {
            const button = $(`[data-admission-approve="${action}"]`);
            const display = getComputedStyle(button).display;
            check(display === (action === step ? 'inline-flex' : 'none'), `${step ?? 'no approval'}: ${action} has display ${display}`);
            check(visible(button) === (action === step), `${action} has wrong layout visibility`);
            const instruction = $(`[data-admission-step="${action}"]`);
            check(visible(instruction) === (action === step), `${action} instructions have wrong visibility`);
        }
        check(visible(consoleCheck) === (step === 'verify' || step === 'confirm'), 'console command has wrong visibility');
    }
    const flush = () => new Promise(resolve => setTimeout(resolve, 0));
    const requests = [];
    const markup = $('#rebuild-l2tp').outerHTML;
    window.fetch = (url, options) => options.method === 'GET' ? Promise.resolve({ status: 200,
        url: 'http://fixture.invalid/panel/l2tp', headers: new Headers({ 'content-type': 'text/html', 'cache-control': 'no-store' }),
        text: async () => markup }) : new Promise(resolve => requests.push({ url, options, resolve }));
    const respond = async (path, data, ok = true) => {
        const request = requests.shift();
        check(request?.url === path && request.options.method === 'POST', `expected ${path}`);
        request.resolve({ ok, status: ok ? 200 : 409, json: async () => data });
        await flush();
        check(requests.length === 0, 'a later step was dispatched automatically');
        return JSON.parse(request.options.body);
    };
    async function copyConsole(binding) {
        check($('[data-admission-console-label]').textContent === consoleLabel, 'wrong console label');
        check($('[data-admission-key-type]').textContent === 'ssh-rsa', 'wrong published key type');
        check($('[data-admission-key]').textContent === binding.sshHostKeySha256, 'wrong published pin');
        check($('[data-admission-command]').textContent === command, 'literal command changed');
        check(visible($('[data-admission-command]')) && visible($('[data-admission-copy-command]')), 'command is not copyable');
        await navigator.clipboard.writeText('synthetic clipboard sentinel');
        click('[data-admission-copy-command]');
        for (let i = 0; i < 50 && !$('[data-admission-copy-status]').textContent; i++) {
            await new Promise(resolve => setTimeout(resolve, 20));
        }
        check(await navigator.clipboard.readText() === command, 'clipboard did not receive the exact command');
        check($('[data-admission-copy-status]').textContent === words.messages.copied, 'no copy feedback');
        check(requests.length === 0, 'copy dispatched a request');
    }

    await flush(); // allow the shipped script to bind the real rendered DOM
    check(getComputedStyle(dialog).display === 'none' && !visible(review), 'closed dialog or review is visible');
    buttons(null);
    click('[data-admission-action="grant"]');
    check(dialog.open && visible(dialog), 'grant dialog did not open');
    buttons(null);
    const binding = { nodeId: id, host: '192.0.2.42', port: 22, username: 'root', sshHostKeySha256: 'b'.repeat(64) };
    const discovery = { ...binding, sshHostKeyType: 'ssh-rsa' };
    await respond(`${route}/${otherId}/l2tp/admission/probe`, { ...discovery, nodeId: otherId, challenge: 'c'.repeat(64) });
    buttons('verify');
    await copyConsole(binding);
    click('[data-admission-cancel]');

    click('[data-admission-action="revoke"]');
    check(dialog.open && visible(dialog), 'revoke dialog did not open');
    buttons('revoke');
    check(requests.length === 0, 'opening revoke dispatched a request');
    click('[data-admission-cancel]');
    check(getComputedStyle(dialog).display === 'none', 'cancel did not hide the dialog');

    click('[data-account-action="disable"]');
    await respond(`${route}/l2tp/accounts/disable`, { error: { code: 'REBUILD_L2TP_IDENTITY_CHANGED', outcome: 'refused', nodeId: id } }, false);
    check(visible(review) && review.getAttribute('href') === `#relay-${id}`, 'identity refusal did not expose scoped review');
    check($(`[data-node-id="${otherId}"][data-admission-action="grant"]`).disabled, 'unrelated grant became enabled');
    click('[data-admission-action="reconfirm"]');
    check(dialog.open && visible(dialog), 'reconfirm dialog did not open');
    buttons(null);
    const url = `${route}/${id}/l2tp/admission`;
    const identified = { ...binding, machineId: 'e'.repeat(32) };
    await respond(`${url}/probe`, { ...discovery, challenge: 'c'.repeat(64) });
    buttons('verify');
    await copyConsole(binding);
    check(!visible($('[data-admission-machine-row]')), 'probe exposed the machine field before verification');
    click('[data-admission-approve="verify"]');
    const verified = await respond(`${url}/verify`, { ...identified, sshHostKeyType: discovery.sshHostKeyType, challenge: 'd'.repeat(64) });
    check(JSON.stringify(verified) === JSON.stringify({ challenge: 'c'.repeat(64) }), 'verify changed its challenge-only payload');
    buttons('confirm');
    check(visible($('[data-admission-machine-row]')), 'verification did not expose the machine field');
    check($('[data-admission-machine]').textContent === identified.machineId, 'verification displayed the wrong identity');
    await copyConsole(binding);
    click('[data-admission-approve="confirm"]');
    const confirmed = await respond(`${url}/confirm`, identified);
    check(JSON.stringify(confirmed) === JSON.stringify({ challenge: 'd'.repeat(64) }), 'confirm changed its challenge-only payload');
    check(getComputedStyle(dialog).display === 'none' && !visible(review) && !visible($('[data-refresh]')),
        'confirmation did not close the dialog and adopt fresh controls');
    const beforeRevoke = $('[data-l2tp-view]');
    click('[data-admission-action="revoke"]');
    check(requests.length === 0, 'revoke preflight issued a POST');
    click('[data-admission-approve="revoke"]');
    click('[data-admission-approve="revoke"]');
    await respond(`${url}/revoke`, { nodeId: id });
    check(!beforeRevoke.isConnected && !dialog.open, 'affirmative revoke did not refresh the overview');
}


async function refreshMatrix({ terminal, route, id, otherId, csrf, words, snapshots }) {
    const check = (ok, message) => { if (!ok) throw new Error(message); };
    const $ = selector => document.querySelector(selector);
    const defer = () => {
        let resolve, reject;
        const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
        return { resolve, reject, promise };
    };
    const flush = async () => { for (let i = 0; i < 24; i++) await Promise.resolve(); };
    const loaded = new Promise(resolve => window.addEventListener('load', resolve, { once: true }));
    const calls = [], reads = [], timers = new Map();
    let time = 0, nextTimer = 0;
    const tick = async target => {
        for (;;) {
            const due = [...timers].filter(([, t]) => t.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
            if (!due) break;
            const [key, t] = due;
            timers.delete(key); time = t.at; t.callback(); await flush();
        }
        time = target; await flush();
    };
    Object.defineProperty(performance, 'now', { value: () => time });
    Date.now = () => time;
    window.setTimeout = (callback, delay) => { const key = ++nextTimer; timers.set(key, { callback, at: time + delay }); return key; };
    window.clearTimeout = key => timers.delete(key);
    window.confirm = () => true;
    const nonceHeader = 'x-rebuild-l2tp-observation';
    function html(markup, echo) {
        const wrapper = '<script>window.badInsertion=true;</scr' + 'ipt><p id="not-in-fragment">layout</p>';
        return { status: 200, url: 'http://fixture.invalid/panel/l2tp', text: async () => wrapper + markup,
            headers: new Headers({ 'content-type': 'text/html', 'cache-control': 'no-store', ...(echo && { [nonceHeader]: echo }) }) };
    }
    const post = defer();
    let progress;
    window.addEventListener('rebuild-l2tp:install-start', event => { progress = event.detail; });
    window.fetch = (url, options) => {
        check(options.mode === 'same-origin' && options.credentials === 'same-origin' && options.redirect === 'error'
            && options.cache === 'no-store', 'wrong transport options');
        if (options.method === 'GET') {
            check(url === '/panel/l2tp' && !options.body && options.headers.Accept === 'text/html', 'unsafe refresh request');
            const wait = defer(); reads.push({ wait, options, time }); return wait.promise;
        }
        calls.push({ url, options });
        check(!url.endsWith('/reveal') && options.headers['x-csrf-token'] === csrf, 'unrequested reveal or token mismatch');
        return post.promise;
    };
    await loaded;
    check(calls.length === 0 && reads.length === 0, 'automatic request at startup');
    const respond = (data, status = 200) => post.resolve({ status, ok: status < 400, json: async () => data });
    const relayUrl = `${route}/${otherId}/l2tp`;
    const accounts = `${route}/l2tp/accounts`;
    const model = status => ({ status, executionMode: 'rebuild' });
    const table = () => $('[aria-labelledby="rebuild-l2tp-accounts"]');
    const priorTable = table();
    if (terminal === 'matrixRemove' || terminal === 'matrixRemoveLost') {
        const button = $('[data-l2tp-remove] [value="confirm"]');
        button.click(); button.click();
        check(calls.length === 1 && button.disabled && calls[0].url.endsWith(`/${id}/l2tp/remove`), 'Remove was not single-shot');
        const token = calls[0].options.headers[nonceHeader];
        check(calls[0].options.body.toString() === `decision=confirm&ticket=${'1'.repeat(64)}`, 'Remove did not use the exact preview ticket');
        if (terminal === 'matrixRemoveLost') {
            respond({ error: { outcome: 'unknown' } }, 503); await flush(); await tick(2000);
            check(reads[0].options.headers[nonceHeader] === token && !window.navigation, 'Remove guessed an outcome');
            reads[0].wait.resolve(html(snapshots.after, `${token}:removed`));
        } else respond({ ...model('not_installed'), nodeId: id });
        await flush();
        check(window.navigation === '/panel/l2tp' && calls.length === 1, 'Remove did not navigate to the current overview');
        return;
    }
    const actions = {
        matrixInstall: ['[data-install-url]', `${relayUrl}/install`, { ...model('installed'), nodeId: otherId }],
        matrixInstallLost: ['[data-install-url]', `${relayUrl}/install`, null],
        matrixTimeout: ['[data-install-url]', `${relayUrl}/install`, null],
        matrixRecover: ['[data-install-recovery-url]', `${relayUrl}/install/recover`, { ...model('can_install_again'), nodeId: otherId }],
        matrixCreate: ['[data-create] button[type="submit"]', `${accounts}/create`, { ...model('created'), login: 'new.user' }],
        matrixDisable: ['[data-account-action="disable"]', `${accounts}/disable`, { ...model('disabled'), login: 'alice.test' }],
        matrixDisableLost: ['[data-account-action="disable"]', `${accounts}/disable`, null],
        matrixDelete: ['[data-account-action="delete"]', `${accounts}/delete`, { ...model('deleted'), login: 'alice.test' }],
        matrixReconcile: ['[data-reconcile]', `${accounts}/reconcile`, model('settled')],
    };
    if (terminal === 'matrixCreate') $('[data-create] input').value = 'new.user';
    const [selector, url, receipt] = actions[terminal];
    const old = $(selector);
    old.click(); old.click();
    check(calls.length === 1 && calls[0].url === url && old.disabled, 'action not locked after one POST');
    if (terminal === 'matrixInstall') {
        check(progress.nodeId === otherId && !progress.signal.aborted, 'install progress hook is missing');
        const stale = progress.refresh();
        const current = progress.refresh();
        check(reads.length === 2 && reads[0].options.signal.aborted, 'superseded GET still live');
        reads[1].wait.resolve(html(snapshots.progress));
        check(await current && $(`#relay-${otherId}`).textContent.includes(words.status.installing), 'in-flight Install was not rendered');
        check(!await stale, 'superseded request reported success');
        respond(receipt); await flush();
        check(progress.signal.aborted && !await progress.refresh(), 'progress hook survived POST completion');
        reads[2].wait.resolve(html(snapshots.after));
        reads[0].wait.resolve(html(snapshots.before));
    } else if (receipt) {
        respond(receipt); await flush();
        check(reads.length === 1 && old.disabled && table() === priorTable, 'did not wait for a fresh authenticated view');
        reads[0].wait.resolve(html(snapshots.after));
    } else {
        const token = calls[0].options.headers[nonceHeader];
        const outcome = terminal === 'matrixDisableLost' ? 'disabled' : 'installed';
        check(/^[a-f0-9]{32}$/.test(token), 'missing operation correlation');
        if (terminal === 'matrixDisableLost') post.reject(new TypeError('fixture network loss'));
        else respond({}, terminal === 'matrixTimeout' ? 408 : 503);
        await flush();
        await tick(1999); check(reads.length === 0, 'polled too early');
        await tick(2000);
        check(reads.length === 1 && reads[0].options.headers[nonceHeader] === token, 'poll not bound to original POST');
        // Even a matching-looking terminal row with another request's receipt cannot confirm.
        reads[0].wait.resolve(html(terminal === 'matrixTimeout' ? snapshots.after : snapshots.before, `${'f'.repeat(32)}:${outcome}`));
        await flush();
        check($('[data-action-status]').textContent === words.messages.uncertain, 'inferred success from an unrelated observation');
        if (terminal === 'matrixTimeout') {
            await tick(298000);
            check(reads.at(-1).time === 298000, 'wrong last poll slot');
            const last = reads.at(-1), lastTable = table();
            time = 300000; last.wait.resolve(html(snapshots.after, `${token}:installed`)); await flush();
            await tick(300001);
            check(lastTable === table(), 'exact-deadline reply was accepted');
            check($('[data-action-status]').textContent === words.messages.observationTimeout && !$('[data-refresh]').hidden,
                'deadline did not leave the UI locked and unknown');
            old.click(); await tick(302000);
            check(calls.length === 1 && reads.at(-1) === last, 'continued observing or replayed after deadline');
            return;
        }
        await tick(4000);
        check(reads.length === 2, 'wrong read-only polling cadence');
        reads[1].wait.resolve(html(snapshots.after, `${token}:${outcome}`));
    }
    await flush();
    check(priorTable !== table() && !priorTable.isConnected && !old.isConnected, 'rows/account table were not replaced');
    check(table().textContent.includes('fixture.after') && !$('#not-in-fragment') && !window.badInsertion, 'did not isolate safe refreshed fragment');
    check(!$('[data-l2tp-view]').innerHTML.includes('SERVER-ONLY-') && [...document.querySelectorAll('[data-secret-value]')]
        .every(value => value.hidden && !value.textContent), 'refresh exposed secret values');
    check(!$('[data-account-action="disable"][data-login="fixture.after"]').disabled, 'fresh eligible control was not rebound');
    check($('[data-refresh]').hidden && calls.length === 1, 'action replayed or fresh view still marked stale');
    old.dispatchEvent(new Event('click')); check(calls.length === 1, 'detached stale control dispatched');
    $('[data-account-action="disable"][data-login="fixture.after"]').click();
    check(calls.length === 2 && JSON.parse(calls[1].options.body).login === 'fixture.after', 'fresh control did not handle an explicit click');
}

for (const [lang, terminal] of [['en', 'uncertainAccount'], ['ru', 'uncertainInstall'], ['en', 'created'], ['ru', 'admissionVisibility'],
    ...['secretPagehide', 'canceled', 'wrongLogin', 'recoveredDisable', 'recoveredPartial', 'admissionVisibility',
        'matrixInstall', 'matrixInstallLost', 'matrixTimeout', 'matrixRemove', 'matrixRemoveLost', 'matrixRecover',
        'matrixCreate', 'matrixDisable', 'matrixDisableLost', 'matrixDelete', 'matrixReconcile'].map(terminal => ['en', terminal])]) {
    const admission = terminal === 'admissionVisibility', matrix = terminal.startsWith('matrix');
    test(matrix ? `Firefox: refresh regression ${terminal}` : admission ? `Firefox: current admission approval, identity and console command copy (${lang})`
        : `Firefox: clicks, secret lifecycle and account/relay requests (${lang}, ${terminal})`, {
        skip: browserAvailable ? false : 'requires local Firefox (or REBUILD_L2TP_FIREFOX)',
    }, async () => {
        let { content } = await render(lang, terminal === 'matrixRecover' ? { canRequestInstallRecovery: true,
            relays: [installed, { ...fresh, status: 'installing', grantSource: 'db', canRecoverInstall: true }] }
            : terminal === 'matrixReconcile' ? { accountsPending: true, canReconcileAccounts: true }
            : admission ? { relays: [
            { ...installed, grantSource: 'db', canReconfirm: true, canRevoke: true },
            { ...fresh, grantSource: null, canGrant: true },
        ] } : undefined);
        const client = readFileSync(join(root, 'public/js/rebuild-l2tp.js'), 'utf8');
        const words = require(`../../locales/${lang}.json`).rebuildL2tp;
        const snapshots = matrix ? { before: content,
            progress: (await render(lang, { relays: [installed, { ...fresh, status: 'installing', canInstall: false }] })).content,
            after: (await render(lang, { relays: [installed, { ...fresh, status: 'installed', canInstall: false }],
                accounts: [{ ...account, login: 'fixture.after' }] })).layout } : null;
        if (terminal.startsWith('matrixRemove')) {
            const card = await ejs.renderFile(join(root, 'views/node-form.ejs'), { t: key => t(key, lang), lang, csrfToken: csrf,
                node: { _id: id, cascadeRole: 'relay', type: 'xray' }, error: null, groups: [], candidateNodes: [],
                cascadeLinks: [], panelDomain: '', lastInitScript: '', baseUrl: '', rebuildRemoval: {
                    summary: 'Fixture preview', ticket: '1'.repeat(64), scriptVersion: rebuildL2tpScriptVersion },
            });
            content = card.match(/<details class="form-section" id="rebuild-l2tp-remove"[\s\S]*?<\/details>/)[0];
        }
        const input = JSON.stringify({ route, id, otherId, csrf, words, terminal, lang, snapshots }).replaceAll('<', '\\u003c');
        const home = mkdtempSync(join(tmpdir(), 'rebuild-l2tp-ui-'));
        try {
            const settings = {
                'browser.dom.window.dump.enabled': true,
                // Use Firefox's actual headless clipboard without user permission prompts.
                ...(admission && { 'dom.events.testing.asyncClipboard': true, 'dom.events.asyncClipboard.readText': true }),
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
            const scenario = matrix ? refreshMatrix : admission ? admissionVisibility : browserScenario;
            const stylesheet = admission ? `<style>${readFileSync(join(root, 'public/css/style.min.css'), 'utf8')}</style>` : '';
            const inline = `<script>(${scenario})(${input}).then(() => dump('L2TP_UI:OK\\n'),
                error => dump('L2TP_UI:FAIL ' + error.message + '\\n'));</script><script>((location) => { ${client} })(
                    { origin: 'http://fixture.invalid', assign: path => { window.navigation = path; } });</script>`;
            assert.ok(content.includes(scriptTag));
            writeFileSync(file, '<!doctype html><meta charset="UTF-8">' +
                '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'unsafe-inline\'; style-src \'unsafe-inline\'">' +
                stylesheet + content.replace(scriptTag, () => inline));
            await new Promise((resolve, reject) => {
                const child = spawn(firefox, ['--no-remote', '--headless', '--profile', home, pathToFileURL(file).href], {
                    env: { PATH: process.env.PATH, HOME: home, TMPDIR: home, MOZ_CRASHREPORTER_DISABLE: '1',
                        ...(process.env.REBUILD_L2TP_FIREFOX && process.env.LD_LIBRARY_PATH && { LD_LIBRARY_PATH: process.env.LD_LIBRARY_PATH }) },
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
