'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { runInNewContext } = require('node:vm');
const ejs = require('ejs');
const { t } = require('../../../middleware/i18n');
const words = require('../../../locales/en.json').rebuildL2tp;
const root = resolve(__dirname, '../../../..');
const script = readFileSync(resolve(root, 'public/js/rebuild-l2tp.js'), 'utf8');
const ids = ['a', 'b', 'c'].map(value => value.repeat(24));
const key = '1'.repeat(64), first = '2'.repeat(64), second = '3'.repeat(64), machineId = '4'.repeat(32);
const id = ids[0];
const receipt = { nodeId: id, host: '2001:db8::1', port: 2222, username: 'root', sshHostKeySha256: key };
const baseUrl = nodeId => `/panel/rebuild/relays/${nodeId}/l2tp/admission`;

function render(lang, overrides = {}) {
    const relays = ids.map((id, i) => ({ id, ip: `192.0.2.${i + 1}`, name: `Relay ${i + 1} <host>`,
        status: 'not_installed', grantSource: [null, 'db', 'env'][i], bound: i !== 0,
        canGrant: true, canReconfirm: true, canRevoke: true, canInstall: i !== 0 }));
    return ejs.renderFile(resolve(root, 'views/rebuild-l2tp.ejs'), { relays, accounts: [], t: key => t(key, lang),
        rebuildL2tpScriptVersion: 'fixture', canManageAccounts: true, csrfToken: 'fixture', ...overrides });
}

test('all grant sources and permissions render in EN, RU and ZH; a registry failure is not "not admitted"', async () => {
    for (const lang of ['en', 'ru', 'zh-CN']) {
        const copy = require(`../../../locales/${lang}.json`).rebuildL2tp.admission;
        assert.deepEqual(Object.keys(copy).sort(), Object.keys(words.admission).sort());
        const html = await render(lang);
        for (const text of [copy.db, copy.env, copy.none, copy.envReadOnly, copy.verifyInstructions, copy.confirmInstructions]) {
            assert.ok(html.includes(text));
        }
        for (const action of ['grant', 'reconfirm', 'revoke']) assert.match(html, new RegExp(`data-admission-action="${action}"`));
        assert.ok(!html.includes(baseUrl(ids[2])));
        assert.doesNotMatch(html, /<host>/);
        const error = await render(lang, { grantProblem: 'REBUILD_L2TP_GRANT_PERSISTENCE_UNAVAILABLE' });
        assert.ok(error.includes(copy.grantUnavailable));
        assert.doesNotMatch(error, /data-install-url=|data-admission-action=|data-create/);
        assert.ok(!error.includes(`>${copy.none}<`));
        for (const [grantProblem, key] of [['REBUILD_L2TP_GRANT_CONFLICT', 'grantConflict'],
            ['REBUILD_L2TP_GRANT_CHANGED', 'grantConflict'], ['REBUILD_L2TP_INSTALL_DISABLED', 'disabled'],
            ['REBUILD_L2TP_ACCOUNTS_BLOCKED', 'blocked'],
            ['<unknown grant problem>', 'grantUnavailable']]) {
            const blocked = await render(lang, { grantProblem, accountsPending: true, canReconcileAccounts: true });
            assert.ok(blocked.includes(`role="alert">${copy[key]}</p>`), `${lang}: ${grantProblem}`);
            assert.doesNotMatch(blocked, /data-install-url=|data-admission-action=|data-create|data-reconcile|<unknown grant problem>/);
        }
        const manual = await render(lang, { grantProblem: 'REBUILD_L2TP_IDENTITY_CHANGED', accountsPending: true, canReconcileAccounts: true });
        const manualCopy = require(`../../../locales/${lang}.json`).rebuildL2tp.messages.reconcileManualBlock;
        assert.ok(manualCopy && manual.includes(`role="alert">${manualCopy}</p>`));
        assert.doesNotMatch(manual, /data-install-url=|data-admission-action=|data-create|data-reconcile/);
    }
});

test('a conflicting DB row cannot reconfirm; identity-change review remains service-gated', async () => {
    const relay = { id, name: 'Relay', ip: receipt.host, status: 'not_installed', grantSource: 'db', bound: true,
        canReconfirm: true, canRevoke: true, canInstall: true, canRemove: true, canRevealPsk: true };
    for (const [grantProblem, key, canReconfirm] of [
        ['REBUILD_L2TP_GRANT_CONFLICT', 'grantConflict', true],
        ['REBUILD_L2TP_IDENTITY_CHANGED', 'identityChanged', true],
        ['REBUILD_L2TP_IDENTITY_CHANGED', 'identityChanged', false],
    ]) {
        const html = await render('en', { relays: [{ ...relay, grantProblem, canReconfirm }] });
        assert.ok(html.includes(`>${words.admission[key]}<`));
        assert.doesNotMatch(html, /data-install-url=|data-secret-url=|data-remove-link|data-admission-action="revoke"/);
        assert.equal(html.includes('data-admission-action="reconfirm"'), key === 'identityChanged' && canReconfirm);
    }
});

function widget(dataset = {}) {
    const events = new Map();
    return { dataset, hidden: false, disabled: false, open: false, textContent: '',
        addEventListener: (name, handler) => events.set(name, handler),
        click(detail = 1) { if (!this.disabled && !this.hidden) events.get('click')?.({ detail, preventDefault() {} }); },
        showModal() { this.open = true; }, close() { this.open = false; } };
}

function launch(action = 'grant', { target = id, pending = false, admissionWords = words.admission } = {}) {
    const replies = [], calls = [];
    const dialog = widget(), status = widget(), refresh = widget(), review = widget(), recover = widget();
    const install = widget({ nodeId: target, installUrl: '/install' });
    const account = widget({ accountAction: 'disable', login: 'test' });
    const button = (admissionAction, nodeId) => widget({ admissionAction, nodeId, admissionUrl: baseUrl(nodeId), nodeName: '<untrusted relay>' });
    const selected = button(action, target), other = button('reconfirm', ids[1]);
    const fields = new Map();
    const field = name => {
        if (!fields.has(name)) fields.set(name, widget());
        return fields.get(name);
    };
    dialog.querySelector = selector => field(selector.slice('[data-admission-'.length, -1));
    const approvals = Object.fromEntries(['verify', 'confirm', 'revoke'].map(admissionApprove => [admissionApprove, widget({ admissionApprove })]));
    dialog.querySelectorAll = selector => selector === '[data-admission-approve]' ? Object.values(approvals)
        : ['verify', 'confirm', 'revoke'].map(admissionStep => widget({ admissionStep }));
    const page = { dataset: { csrf: 'fixture', messages: JSON.stringify(words.messages),
        accountUrl: '/accounts', admissionMessages: JSON.stringify(admissionWords), ...(pending && { reconcileUrl: '/accounts/reconcile' }) },
    querySelector: selector => ({ '[data-action-status]': status, '[data-refresh]': refresh,
        '[data-review]': review, '[data-admission-dialog]': dialog, '[data-reconcile]': pending ? recover : null })[selector] ?? null,
    querySelectorAll: selector => ({ '[data-install-url]': [install], '[data-account-action]': [account],
        '[data-admission-action]': [selected, other] })[selector] ?? [] };
    runInNewContext(script, { document: { getElementById: key => key === 'rebuild-l2tp' ? page : null },
        window: { addEventListener() {} }, async fetch(url, options) {
            calls.push({ url, body: JSON.parse(options.body), csrf: options.headers['x-csrf-token'], method: options.method });
            const reply = replies.shift();
            if (!reply) throw new Error('lost reply');
            return { status: reply.status ?? 200, ok: !reply.status, json: async () => reply.data };
        } });
    return { replies, calls, status, refresh, review, selected, other, field, install, account, dialog, approvals, recover };
}
const flush = () => new Promise(resolve => setImmediate(resolve));

for (const action of ['grant', 'reconfirm']) {
    test(`${action}: pin and machine ID require independent clicks; no automatic Install`, async () => {
        const f = launch(action);
        f.replies.push({ data: { ...receipt, challenge: first } }, { data: { ...receipt, machineId, challenge: second } },
            { data: { ...receipt, machineId } });
        assert.deepEqual(f.calls, []);
        f.selected.click(); await flush();
        assert.deepEqual(f.calls.map(({ url }) => url), [`${baseUrl(id)}/probe`]);
        assert.equal(f.field('key').textContent, key);
        assert.equal(f.field('name').textContent, '<untrusted relay>');
        assert.equal(f.field('endpoint').textContent, '[2001:db8::1]:2222');
        assert.equal(f.approvals.verify.hidden, false);
        assert.equal(f.approvals.confirm.hidden, true);
        assert.equal(f.field('machine-row').hidden, true);
        f.approvals.verify.click(); await flush();
        assert.equal(f.calls.length, 2);
        assert.equal(f.field('machine').textContent, machineId);
        assert.equal(f.approvals.verify.hidden, true);
        assert.equal(f.approvals.confirm.hidden, false);
        f.approvals.verify.click(2); f.approvals.confirm.click(2); await flush();
        assert.equal(f.calls.length, 2);
        f.approvals.confirm.click(); await flush();
        assert.deepEqual(f.calls, ['probe', 'verify', 'confirm'].map((action, i) => ({ url: `${baseUrl(id)}/${action}`,
            body: i ? { challenge: i === 1 ? first : second } : {}, csrf: 'fixture', method: 'POST' })));
        assert.equal(f.dialog.open, false);
        assert.equal(f.field('key').textContent, '');
        assert.equal(f.refresh.hidden, false);
        assert.ok(f.install.disabled && f.account.disabled && f.selected.disabled);
    });
}

test('an account identity refusal does not replay or redirect; explicit reconfirm starts a new probe', async () => {
    const f = launch('reconfirm');
    f.replies.push({ status: 409, data: { error: { code: 'REBUILD_L2TP_IDENTITY_CHANGED', nodeId: id, private: 'private' } } });
    f.account.click(); await flush();
    assert.equal(f.status.textContent, words.admission.identityChanged);
    assert.equal(f.review.href, `#relay-${id}`);
    assert.ok(f.install.disabled && f.account.disabled && f.other.disabled && !f.selected.disabled);
    assert.deepEqual(f.calls.map(({ url }) => url), ['/accounts/disable']);
    f.selected.click(); await flush();
    assert.equal(f.calls[1].url, `${baseUrl(id)}/probe`);
});

test('revoke needs explicit approval, and a failed verification cannot advance or reuse its challenge', async () => {
    const revoke = launch('revoke');
    revoke.selected.click(); await flush();
    assert.deepEqual(revoke.calls, []);
    revoke.replies.push({ data: { nodeId: id } });
    revoke.approvals.revoke.click(); await flush();
    assert.deepEqual(revoke.calls.map(({ url }) => url), [`${baseUrl(id)}/revoke`]);
    const f = launch();
    f.replies.push({ data: { ...receipt, challenge: first } }, { data: { ...receipt, machineId, challenge: second, sshHostKeySha256: first } });
    f.selected.click(); await flush();
    f.approvals.verify.click(); await flush();
    assert.ok(Object.values(f.approvals).every(button => button.hidden));
    assert.equal(f.field('status').textContent, words.admission.checkUnavailable);
    f.approvals.verify.click(); await flush();
    assert.equal(f.calls.length, 2);
});

test('last-grant refusal shows localized recovery guidance and leaves account controls usable', async () => {
    for (const lang of ['en', 'ru', 'zh-CN']) {
        const admissionWords = require(`../../../locales/${lang}.json`).rebuildL2tp.admission;
        const html = await render(lang);
        assert.ok(html.match(/data-admission-messages="([^"]*)"/)?.[1]
            .includes(ejs.escapeXML(JSON.stringify({ legacySingletonInUse: admissionWords.legacySingletonInUse }).slice(1, -1))));
        const f = launch('revoke', { admissionWords });
        f.replies.push({ status: 409, data: { error: { code: 'REBUILD_L2TP_GRANT_LEGACY_SINGLETON_IN_USE' } } });
        f.selected.click();
        f.approvals.revoke.click();
        await flush();
        assert.equal(f.field('status').textContent, admissionWords.legacySingletonInUse);
        f.field('cancel').click();
        assert.equal(f.dialog.open, false);
        assert.equal(f.account.disabled, false);
        assert.deepEqual(f.calls.map(({ url }) => url), [`${baseUrl(id)}/revoke`]);
    }
});

test('even with a pending account operation, the page takes no action until the operator clicks reconcile', async () => {
    const html = await render('en', { accountsPending: true, canReconcileAccounts: true });
    assert.match(html, /data-reconcile disabled/);
    assert.doesNotMatch(html, /data-install-url=|data-admission-action=|data-create/);
    const f = launch('grant', { pending: true });
    await flush();
    assert.deepEqual(f.calls, []);
    f.replies.push({ data: { executionMode: 'rebuild', status: 'settled' } });
    f.recover.click(); await flush();
    assert.equal(f.status.textContent, words.messages.reconcileSettled);
    assert.equal(f.recover.disabled, true);
    f.recover.click(); await flush();
    assert.deepEqual(f.calls.map(({ url }) => url), ['/accounts/reconcile']);
});

test('manual block after a reconcile click never presents reconfirmation or retry', async () => {
    const f = launch('reconfirm', { pending: true });
    f.replies.push({ status: 409, data: { error: { code: 'REBUILD_L2TP_ACCOUNTS_MANUAL_BLOCK', retryAllowed: false } } });
    f.recover.click(); await flush();
    assert.ok(words.messages.reconcileManualBlock);
    assert.equal(f.status.textContent, words.messages.reconcileManualBlock);
    assert.equal(f.recover.disabled, true);
    assert.equal(f.review.hidden, true);
    f.recover.click(); f.selected.click(); await flush();
    assert.deepEqual(f.calls.map(({ url }) => url), ['/accounts/reconcile']);
});

test('grant dialog shows only localized conflict fields/sources and never follows up automatically', async () => {
    for (const [conflict, suffix] of [
        [{ field: 'endpoint', sources: ['env', 'db'], value: '<untrusted>' },
            ' Conflicting field: SSH endpoint. Conflicting sources: ENV, DB.'],
        [{ field: 'constructor', sources: ['env', '<untrusted>'] }, ''],
    ]) {
        const f = launch();
        f.replies.push({ status: 409, data: { error: { code: 'REBUILD_L2TP_GRANT_CONFLICT', conflict, message: '<untrusted>' } } });
        f.selected.click(); await flush();
        assert.equal(f.field('status').textContent, words.admission.grantConflict + suffix);
        assert.ok(Object.values(f.approvals).every(button => button.hidden));
        assert.deepEqual(f.calls.map(({ url }) => url), [`${baseUrl(id)}/probe`]);
    }
});

test('admission blocked by a pending operation requires refresh and cannot reuse its challenge', async () => {
    const f = launch();
    f.replies.push({ data: { ...receipt, challenge: first } }, { data: { ...receipt, machineId, challenge: second } },
        { status: 409, data: { error: { code: 'REBUILD_L2TP_ACCOUNTS_BLOCKED' } } });
    f.selected.click(); await flush();
    f.approvals.verify.click(); await flush();
    f.approvals.confirm.click(); await flush();
    assert.equal(f.status.textContent, words.admission.blocked);
    assert.equal(f.refresh.hidden, false);
    f.field('cancel').click();
    assert.ok(f.selected.disabled && f.other.disabled && f.install.disabled && f.account.disabled);
    f.selected.click(); f.approvals.confirm.click(); await flush();
    assert.equal(f.calls.length, 3);
});
