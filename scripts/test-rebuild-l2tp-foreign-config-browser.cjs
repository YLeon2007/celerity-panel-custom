'use strict';

// Run with local Firefox and offline dependencies in a private loopback-only netns:
// unshare -Urn sh -c 'ip link set lo up && exec node scripts/test-rebuild-l2tp-foreign-config-browser.cjs'
const assert = require('node:assert/strict');
const { once } = require('node:events');
const { mkdtempSync, rmSync } = require('node:fs');
const { networkInterfaces, tmpdir } = require('node:os');
const path = require('node:path');
const express = require('express');
const ejs = require('ejs');
const { Firefox, sleep } = require('../browser-assets-wave8/firefox-bidi.cjs');
const { t } = require('../src/middleware/i18n');
const { requirePanelCsrf } = require('../src/routes/panel/csrf');
const { installCheckIds } = require('../src/services/rebuildRelayInstallDiagnostics');
const { rebuildL2tpScriptVersion } = require('../src/routes/panel/rebuildL2tpObservation');

const nodeId = 'a'.repeat(24), siblingId = 'b'.repeat(24);
const installUrl = `/panel/rebuild/relays/${nodeId}/l2tp/install`;
const header = 'x-rebuild-l2tp-observation';
const csrf = 'fixture-csrf';
const name = 'Relay <i data-foreign-fixture>literal $&</i>';
const taint = '<img src="/foreign-response-canary" data-foreign-fixture>';
const options = 'OPTIONS_PRESENT', xray = 'XRAY_UNIT_0666', bridge = 'XRAY_BRIDGE_UNIT_0666';
const manualKey = 'IPSEC_D_FOREIGN_CONF';
const first = '1'.repeat(64), fresh = '2'.repeat(64);
const initialCode = 'REBUILD_L2TP_FOREIGN_CONFIG';
const changedCode = 'REBUILD_L2TP_FOREIGN_CONFIG_CHANGED';
const check = 'L2TP_FOREIGN_CONFIG';
const challenge = (keys, cleanable, manual, cleanupToken, code = initialCode) => ({
    code, outcome: 'refused', check, keys, cleanable, manual,
    ...(cleanupToken !== undefined && { cleanupToken }), paths: [taint], relayName: taint,
});
const modal = '[data-foreign-cleanup-dialog]';
const heading = `${modal} h2`;
const confirm = '[data-foreign-cleanup-confirm]';
const cancel = '[data-foreign-cleanup-cancel]';
const xrayOption = '[data-foreign-cleanup-xray] input';
const install = `#relay-${nodeId} [data-install-url]`;
const sibling = `#relay-${siblingId} [data-install-url]`;
const status = `#relay-${nodeId} [data-relay-action-status]`;
const progress = `#relay-${nodeId} [data-progress-text]`;
const el = selector => `document.querySelector(${JSON.stringify(selector)})`;
const visible = selector => `!!${el(selector)}?.getClientRects().length`;
const text = selector => `${el(selector)}?.textContent`;

async function main() {
    assert.deepEqual(Object.keys(networkInterfaces()), ['lo'], 'requires a loopback-only namespace');
    const root = path.resolve(__dirname, '..');
    const app = express(), browser = new Firefox(), requests = [];
    const scratch = mkdtempSync(path.join(tmpdir(), 'rebuild-l2tp-foreign-firefox-'));
    const session = { authenticated: true, panelCsrfToken: csrf };
    let lang, replies, release, progressPercent;
    app.use(express.json(), (req, res, next) => {
        if (!req.path.startsWith('/js/')) requests.push({
            method: req.method, path: req.path, body: req.body, nonce: req.get(header),
        });
        req.session = session;
        res.set('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:");
        res.set('Cache-Control', 'no-store');
        next();
    });
    app.use('/js', express.static(path.join(root, 'public/js')));
    app.get('/panel/l2tp', (_, res, next) => {
        const translate = key => t(key, lang);
        const relay = (id, name) => ({ id, name, ip: '192.0.2.10', status: 'not_installed', bound: true, canInstall: true });
        ejs.renderFile(path.join(root, 'views/rebuild-l2tp.ejs'), {
            t: translate, csrfToken: csrf, rebuildL2tpScriptVersion: rebuildL2tpScriptVersion(),
            installChecks: Object.fromEntries(installCheckIds.map(id => [id, translate(`rebuildL2tp.installChecks.${id}`)])),
            relays: [relay(nodeId, name), relay(siblingId, 'Sibling relay')], accounts: [], canManageAccounts: false,
        }, (error, html) => error ? next(error)
            : res.type('html').send(`<!doctype html><meta charset="utf-8"><link rel="icon" href="data:,">${html}`));
    });
    // Model only the not-yet-merged Install/progress producer; run real CSRF and the actual view/assets.
    app.post(installUrl, requirePanelCsrf, async (_, res) => {
        const error = replies.shift();
        if (!error) return res.sendStatus(500);
        if (typeof error === 'function') return res.status(409).json({ error: await error() });
        res.status(409).json({ error });
    });
    app.get(`${installUrl}/progress`, (_, res) => res.json({ nodeId,
        installProgress: { stage: 'foreignCleanup', percent: progressPercent, at: new Date().toISOString() },
    }));
    const server = app.listen(0, '127.0.0.1');
    try {
        await once(server, 'listening');
        const origin = `http://127.0.0.1:${server.address().port}`;
        await browser.start(scratch);
        const postRequests = () => requests.filter(({ method }) => method === 'POST');
        const open = async () => {
            await browser.click(install);
            await waitModal();
        };
        const waitModal = () => browser.wait(`${el(modal)}?.open === true`, 3500);
        const finished = () => browser.wait(`!${el(modal)}?.open && !${el(install)}.disabled`);
        const start = async (locale, ...errors) => {
            lang = locale;
            replies = errors;
            progressPercent = 70;
            await browser.navigate(`${origin}/panel/l2tp?lang=${locale}`);
            requests.length = 0;
            await browser.evaluate('window.fixtureSameDocument = true');
            return require(`../src/locales/${locale}.json`).rebuildL2tp;
        };
        const checkHeading = async words => {
            assert.equal(await browser.evaluate(text(heading)), words.foreignCleanup.title.replace('{name}', () => name));
            assert.equal(await browser.evaluate('document.querySelector("[data-foreign-fixture]") === null'), true);
            assert.equal(await browser.evaluate(`${text(modal)}.includes(${JSON.stringify(taint)})`), false);
        };
        const checkPostBodies = expected => {
            assert.deepEqual(postRequests().map(r => [r.path, r.body]), expected.map(body => [installUrl, body]));
            const nonces = postRequests().map(r => r.nonce);
            for (const nonce of nonces) assert.match(nonce, /^[a-f0-9]{32}$/);
            assert.equal(new Set(nonces).size, nonces.length, 'each explicit submission must have its own nonce');
        };
        for (const locale of ['ru', 'en', 'zh-CN']) {
            const words = await start(locale, challenge([options, xray, bridge], [options, xray, bridge], [], first));
            await open();
            await checkHeading(words);
            assert.equal(await browser.evaluate(text(status)), words.messages.installAwaitingCleanup);
            if (locale === 'ru') {
                assert.equal(words.foreignCleanup.title, 'На релее «{name}» обнаружены чужие настройки протокола L2TP');
                assert.equal(await browser.evaluate(text(confirm)), 'Удалить настройки и продолжить установку');
                assert.equal(await browser.evaluate(text(cancel)), 'Отменить установку');
            }
            assert.equal(await browser.evaluate(`${el(install)}.disabled && ${el(sibling)}.disabled`), true);
            assert.equal(await browser.evaluate(`document.activeElement === ${el(cancel)}`), true);
            assert.equal(await browser.evaluate(`${el(xrayOption)}.checked && ${visible(xrayOption)}`), true);
            assert.equal(await browser.evaluate(`${text('[data-foreign-cleanup-files]')}.includes('xray')`), false);
            assert.deepEqual(await browser.evaluate(`Array.from(${el('[data-foreign-cleanup-xray]')}.querySelectorAll('code'), e => e.textContent)`),
                ['/etc/systemd/system/xray.service', '/etc/systemd/system/xray-bridge.service']);
            assert.equal(await browser.evaluate(visible(progress)), false);
            checkPostBodies([{}]);
            if (locale === 'en') {
                await browser.send('input.performActions', { context: browser.context, actions: [{ type: 'key', id: 'kbd',
                    actions: [{ type: 'keyDown', value: '\uE00C' }, { type: 'keyUp', value: '\uE00C' }] }] });
            } else if (locale === 'zh-CN') {
                await browser.pointer(1, 1);
            } else await browser.click(cancel);
            await finished();
            assert.equal(await browser.evaluate(text(status)), words.messages.installCanceled);
            assert.equal(await browser.evaluate(`document.activeElement === ${el(install)}`), true);
            assert.equal(await browser.evaluate('window.fixtureSameDocument'), true);
            if (locale === 'ru') await sleep(2100); // prove no delayed POST/progress/overview follows Cancel
            assert.deepEqual(requests.map(r => r.method), ['POST']);
            console.log(`${locale}: localized heading and native dismissal, no follow-up request`);
        }

        let words = await start('zh-CN', challenge([options, xray, manualKey], [options, xray], [manualKey], first));
        await open();
        await checkHeading(words);
        assert.equal(await browser.evaluate(visible(confirm)), false);
        assert.equal(await browser.evaluate(`${el(xrayOption)}.disabled`), true);
        assert.deepEqual(await browser.evaluate(`Array.from(${el('[data-foreign-cleanup-manual]')}.querySelectorAll('code'), e => e.textContent)`), ['/etc/ipsec.d/']);
        await browser.evaluate(`${el(confirm)}.click()`);
        await browser.click(cancel);
        await finished();
        checkPostBodies([{}]);
        assert.equal(await browser.evaluate(text(status)), words.messages.installCanceled);
        console.log('manual: fixed path only, no confirmation even with a token');

        words = await start('en',
            () => new Promise(resolve => { release = () => resolve(challenge([options], [options], [], first)); }),
            challenge([options, xray], [options, xray], [], fresh, changedCode));
        await browser.click(install);
        await browser.wait(`performance.getEntriesByName(${JSON.stringify(`${origin}${installUrl}/progress`)}).length > 0`);
        assert.equal(await browser.evaluate(text(progress)), words.installProgress.preflight,
            'an unconsented progress response must not display cleanup');
        release();
        await waitModal();
        await browser.click(confirm);
        await browser.wait(`${el(modal)}?.open && ${visible('[data-foreign-cleanup-changed]')}`);
        assert.equal(await browser.evaluate(`${el(xrayOption)}.checked && ${visible(xrayOption)}`), true);
        await browser.click(cancel);
        await finished();
        checkPostBodies([{}, { foreignCleanup: { token: first, fixXrayUnitMode: false } }]);
        assert.equal(await browser.evaluate(text(status)), words.messages.installCanceled);
        assert.equal(await browser.evaluate('window.fixtureSameDocument'), true);
        console.log('progress and drift cancellation: no cleanup label before consent, no retry after cancellation');

        words = await start('ru',
            challenge([options, xray], [options, xray], [], first),
            challenge([options], [options], [], fresh, changedCode),
            () => new Promise(resolve => { release = () => resolve({ outcome: 'rolled_back',
                code: 'REBUILD_L2TP_INSTALL_FAILED', check: 'FOREIGN_CONFIG_RESTORED' }); }));
        await open();
        await browser.click(xrayOption);
        await browser.click(confirm);
        await browser.wait(`${el(modal)}?.open && ${visible('[data-foreign-cleanup-changed]')}`);
        assert.equal(await browser.evaluate(text('[data-foreign-cleanup-changed]')), words.foreignCleanup.changed);
        assert.equal(await browser.evaluate(visible(xrayOption)), false);
        assert.equal(await browser.evaluate(visible(progress)), false);
        await sleep(250);
        checkPostBodies([{}, { foreignCleanup: { token: first, fixXrayUnitMode: false } }]);
        await browser.click(confirm);
        await browser.wait(`${text(progress)} === ${JSON.stringify(words.installProgress.foreignCleanup)}`);
        await browser.wait(`${el(`#relay-${nodeId} progress`)}.value === ${progressPercent}`);
        checkPostBodies([{}, { foreignCleanup: { token: first, fixXrayUnitMode: false } },
            { foreignCleanup: { token: fresh, fixXrayUnitMode: false } }]);
        release();
        await browser.wait(`${text(status)}?.includes(${JSON.stringify(words.installChecks.FOREIGN_CONFIG_RESTORED)})`);
        await finished();
        assert.equal(await browser.evaluate('window.fixtureSameDocument'), true);
        assert.equal(await browser.evaluate(visible('[data-refresh]')), false);
        assert.equal(requests.filter(r => r.method === 'GET' && r.path === '/panel/l2tp').length, 1);
        console.log('drift: fresh explicit consent, distinct nonces, cleanup progress and rollback-restored status');

        words = await start('en', challenge([xray], [xray], [], first), { outcome: 'rolled_back', code: 'REBUILD_L2TP_INSTALL_FAILED' });
        await open();
        await browser.click(confirm);
        await finished();
        checkPostBodies([{}, { foreignCleanup: { token: first, fixXrayUnitMode: true } }]);
        assert.ok((await browser.evaluate(text(status))).includes(words.messages.installRolledBack));
        assert.ok(!(await browser.evaluate(text(status))).includes(words.installChecks.FOREIGN_CONFIG_RESTORED));
        console.log('Xray: checked choice sends true; generic rollback does not claim restoration');

        for (const error of [
            { code: initialCode, outcome: 'refused', check, keys: [options], message: taint },
            challenge([options], [options], [], first + '\n'),
            challenge([options], [options], [], first.slice(1) + '\n'),
            challenge([options], [options], [options], first),
            challenge([taint], [taint], [], first),
        ]) {
            words = await start('en', error);
            await browser.click(install);
            await finished();
            const message = await browser.evaluate(text(status));
            assert.ok(message.includes(words.installChecks[check]));
            if (error.keys.includes(options)) assert.ok(message.includes(words.installChecks[options]));
            assert.ok(!message.includes(taint));
            checkPostBodies([{}]);
        }
        console.log('legacy + malformed: localized status fallback, no modal or consent POST');
        assert.deepEqual(browser.events.filter(e => e.method === 'log.entryAdded' && e.params.type === 'javascript'), []);
    } finally {
        release?.();
        try { await browser.close(); }
        finally {
            await new Promise(resolve => server.close(resolve));
            rmSync(scratch, { recursive: true, force: true });
        }
    }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
