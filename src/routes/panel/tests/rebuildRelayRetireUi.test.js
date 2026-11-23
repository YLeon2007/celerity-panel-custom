'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { runInNewContext } = require('node:vm');
const ejs = require('ejs');
const { t } = require('../../../middleware/i18n');

const root = resolve(__dirname, '../../../..');
const ids = ['a', 'b', 'c'].map(c => c.repeat(24));
const id = ids[0];
const url = (nodeId, action) => `/panel/rebuild/relays/${nodeId}/retire/${action}`;
const nodeName = 'Relay <a> "fixture"';
const ticket = '1'.repeat(64), freshTicket = '2'.repeat(64);
const languages = ['en', 'ru', 'zh-CN'];
const words = lang => require(`../../../locales/${lang}.json`).nodes.retireRelay;
const expected = {
    ru: {
        ordinary: 'Удалить?',
        force: 'К релею по L2TP подключено 12 активных клиентов. Удалить релей и разорвать эти соединения?',
        offline: time => `Релей недоступен с ${time}. Удалить его из панели без очистки сервера? Число L2TP-клиентов неизвестно; MikroTik'и, подключённые к нему, потеряют связь`,
        accounts: 'Учётных записей L2TP: 4.',
    },
    en: {
        ordinary: 'Delete?',
        force: '12 active clients are connected to the relay via L2TP. Delete the relay and disconnect these clients?',
        offline: time => `The relay has been unavailable since ${time}. Delete it from the panel without cleaning up the server? The number of L2TP clients is unknown; MikroTik devices connected to it will lose connectivity.`,
        accounts: 'L2TP accounts: 4.',
    },
};

function render(lang, c3Rebuild = true) {
    const nodes = ids.map((_id, i) => ({ _id, name: i ? `Node ${i}` : nodeName, ip: `192.0.2.${i + 1}`,
        type: 'xray', cascadeRole: i < 2 ? 'relay' : 'portal', active: true, groups: [], status: 'online' }));
    return ejs.renderFile(resolve(root, 'views/nodes.ejs'), { t: key => t(key, lang), lang,
        nodes, groups: [], linksCount: 0, ipProtocolCount: {}, loadBalancingEnabled: false, c3Rebuild, csrfToken: 'fixture' });
}

const attr = (tag, name) => (tag.match(new RegExp(` ${name}="([^"]*)"`))?.[1] ?? '')
    .replace(/&quot;|&#34;|&#39;|&lt;|&gt;|&amp;/g, match => ({ '&quot;': '"', '&#34;': '"', '&#39;': "'", '&lt;': '<', '&gt;': '>', '&amp;': '&' })[match]);

function widget(tag) {
    assert.ok(tag, 'control exists in rendered markup');
    const events = new Map();
    return {
        hidden: tag.includes(' hidden'), disabled: tag.includes(' disabled'), open: false, textContent: '',
        addEventListener(name, handler) { events.set(name, handler); },
        click(detail = 1) { if (!this.hidden && !this.disabled) return events.get('click')?.({ detail }); },
        showModal() { this.open = true; },
        close() { this.open = false; events.get('close')?.(); },
        focus() {},
    };
}

async function launch(lang) {
    const html = await render(lang);
    const tag = html.match(/<dialog\b[^>]* id="relay-retire-dialog"[^>]*>/)?.[0];
    const dialog = widget(tag);
    dialog.dataset = { csrf: attr(tag, 'data-csrf'), messages: attr(tag, 'data-messages'), locale: attr(tag, 'data-locale') };
    const fields = Object.fromEntries(['target', 'message', 'status', 'confirm', 'close'].map(field =>
        [field, widget(html.match(new RegExp(`<\\w+ [^>]*data-retire-${field}(?=[ >])[^>]*>`))?.[0])]));
    dialog.querySelector = selector => fields[selector.slice('[data-retire-'.length, -1)];
    const buttons = [...html.matchAll(/<button\b[^>]* data-retire-node="[^"]*"[^>]*>/g)].map(([tag]) => ({ ...widget(tag),
        dataset: { retireNode: attr(tag, 'data-retire-node'), retireName: attr(tag, 'data-retire-name') } }));
    const src = html.match(/<script\b[^>]* src="(\/js\/rebuild-relay-retire\.js)(?:\?[^" ]*)?"/)?.[1];
    assert.ok(src, 'page loads the retirement script');
    const calls = [], replies = [], reloads = [];
    runInNewContext(readFileSync(resolve(root, `public${src}`), 'utf8'), {
        document: { getElementById: key => key === 'relay-retire-dialog' ? dialog : null, querySelectorAll: () => buttons },
        location: { reload() { reloads.push(true); } },
        async fetch(path, opts) {
            calls.push({ path, body: JSON.parse(opts.body), method: opts.method, csrf: opts.headers['x-csrf-token'], redirect: opts.redirect });
            const response = await replies.shift();
            if (!response) throw new Error('lost fixture reply');
            return { status: response.status ?? 200, ok: !response.status, json: async () => response.data };
        },
    });
    return { dialog, ...fields, buttons, calls, replies, reloads };
}

const preview = (override = {}) => ({ nodeId: id, mode: 'online', activeClients: 0, accountCount: 2,
    unavailableSince: null, allowed: true, ticket, ...override });
const drift = replacement => ({ status: 409, data: { error: { code: 'PREVIEW_CHANGED' },
    ...(replacement !== undefined && { preview: replacement }) } });
const flush = () => new Promise(resolve => setImmediate(resolve));

test('localized neighbor refusal never enables confirmation or prints unknown details', async () => {
    for (const lang of languages) {
        const f = await launch(lang);
        const code = 'REBUILD_RETIRE_NEIGHBOR_REFUSED';
        const copy = words(lang);
        for (const [reason, key] of [['RUNTIME_FOREIGN_CHANGE', 'neighborRuntimeForeignChange'],
            ['NETWORK_OBSERVATION_REQUIRED', 'neighborNetworkNotReady']]) {
            f.replies.push({ status: 409, data: { error: { code, neighborName: '212 East', reason } } });
            await f.buttons[0].click();
            assert.equal(f.status.textContent, copy.neighborRefused.replace('{name}', '212 East') + ' ' + copy[key]);
            assert.equal(f.confirm.hidden, true);
            assert.equal(f.confirm.disabled, true);
            f.dialog.close();
        }
        f.replies.push({ status: 409, data: { error: { code, neighborName: '/private/path', reason: '<raw error>' } } });
        await f.buttons[0].click();
        assert.equal(f.status.textContent, copy.neighborRefused.replace('{name}', copy.neighborUnknown));
        assert.equal(f.confirm.disabled, true);
        assert.equal(f.calls.length, 3);
    }
});

for (const lang of languages) {
    test(`${lang}: rendered desktop/mobile relay actions differ from ordinary Delete and load translated dialog copy`, async () => {
        const html = await render(lang);
        for (const relayId of ids.slice(0, 2)) {
            assert.equal([...html.matchAll(new RegExp(`data-retire-node="${relayId}"`, 'g'))].length, 2);
            assert.ok(!html.includes(`deleteNode('${relayId}')`));
        }
        assert.equal([...html.matchAll(new RegExp(`deleteNode\\('${ids[2]}'\\)`, 'g'))].length, 2);
        const classic = await render(lang, false);
        assert.doesNotMatch(classic, /data-retire-node|rebuild-relay-retire\.js/);
        assert.ok(classic.includes(`deleteNode('${id}')`));
        const current = words(lang);
        assert.deepEqual(Object.keys(current), Object.keys(words('en')));
        for (const key of Object.keys(current)) assert.deepEqual(current[key].match(/\{\w+\}/g), words('en')[key].match(/\{\w+\}/g));
    });
}

test('ordinary confirmation follows a read-only preview of the selected relay; other card and duplicate clicks cannot retarget it', async () => {
    const f = await launch('en');
    assert.deepEqual(f.calls, []);
    let resolvePreview;
    f.replies.push(new Promise(resolve => { resolvePreview = resolve; }));
    f.buttons[0].click();
    f.buttons[1].click();
    f.confirm.click();
    assert.equal(f.calls.length, 1);
    resolvePreview({ data: { preview: preview() } });
    await flush();
    assert.equal(f.target.textContent, `${nodeName} (${id})`);
    assert.equal(f.message.textContent, expected.en.ordinary);
    assert.equal(f.confirm.hidden, false);
    f.replies.push({ data: { nodeId: id, status: 'deleted' } });
    f.confirm.click(); f.confirm.click();
    await flush();
    assert.deepEqual(f.calls, [
        { path: url(id, 'preview'), body: {}, method: 'POST', csrf: 'fixture', redirect: 'error' },
        { path: url(id, 'confirm'), body: { ticket, decision: 'delete' }, method: 'POST', csrf: 'fixture', redirect: 'error' },
    ]);
    assert.deepEqual(f.reloads, [true]);
});

test('a changed census renders the new count and requires an independent explicit force confirmation', async () => {
    const f = await launch('ru');
    f.replies.push({ data: { preview: preview() } }, { status: 409, data: { error: { code: 'PREVIEW_CHANGED' },
        preview: preview({ activeClients: 12, ticket: freshTicket }) } });
    f.buttons[0].click(); await flush();
    f.confirm.click(); await flush();
    assert.equal(f.calls.length, 2);
    assert.equal(f.message.textContent, expected.ru.force);
    assert.equal(f.status.textContent, words('ru').changed);
    assert.equal(f.confirm.textContent, words('ru').confirmForce.replace('{count}', '12'));
    f.confirm.click(2); await flush();
    assert.equal(f.calls.length, 2);
    f.replies.push({ data: { nodeId: id, status: 'deleted' } });
    f.confirm.click(); await flush();
    assert.deepEqual(f.calls[2].body, { ticket: freshTicket, decision: 'force' });
});

test('a changed initial preview offers the replacement ticket only for an explicit click', async () => {
    const f = await launch('ru');
    f.replies.push(drift(preview({ activeClients: 12, ticket: freshTicket })));
    await f.buttons[0].click();
    assert.equal(f.target.textContent, `${nodeName} (${id})`);
    assert.equal(f.message.textContent, expected.ru.force);
    assert.equal(f.status.textContent, words('ru').changed);
    assert.equal(f.confirm.textContent, words('ru').confirmForce.replace('{count}', '12'));
    assert.equal(f.confirm.disabled, false);
    assert.equal(f.calls.length, 1);
    f.replies.push({ data: { nodeId: id, status: 'deleted' } });
    await f.confirm.click();
    assert.deepEqual(f.calls.map(({ path, body }) => ({ path, body })), [
        { path: url(id, 'preview'), body: {} },
        { path: url(id, 'confirm'), body: { ticket: freshTicket, decision: 'force' } },
    ]);
});

test('renewed drift clears approval and asks for a new preview from either dialog state', async () => {
    for (const afterConfirm of [false, true]) {
        const f = await launch('en');
        if (afterConfirm) f.replies.push({ data: { preview: preview() } });
        f.replies.push(drift());
        await f.buttons[0].click();
        if (afterConfirm) await f.confirm.click();
        assert.equal(f.status.textContent, words('en').newPreviewRequired);
        assert.equal(f.message.textContent, '');
        assert.equal(f.confirm.hidden, true);
        assert.equal(f.confirm.disabled, true);
        await f.confirm.click();
        assert.deepEqual(f.calls.map(c => c.path), [url(id, 'preview'), ...(afterConfirm ? [url(id, 'confirm')] : [])]);
        assert.deepEqual(f.reloads, []);

        f.close.click();
        f.replies.push(drift(preview({ ticket: freshTicket })));
        await f.buttons[0].click();
        assert.equal(f.status.textContent, words('en').changed);
        assert.equal(f.confirm.disabled, false);
        assert.equal(f.calls.at(-1).path, url(id, 'preview'));
    }
});

test('RU and EN render ordinary and force questions with the live census, not the account count', async () => {
    for (const lang of ['ru', 'en']) for (const activeClients of [0, 12]) {
        const f = await launch(lang);
        f.replies.push({ data: { preview: preview({ activeClients, accountCount: 4 }) } });
        f.buttons[0].click(); await flush();
        assert.equal(f.message.textContent, expected[lang][activeClients ? 'force' : 'ordinary']);
    }
});

test('RU and EN render the outage time or honest fallback, with accounts separate from unknown live clients', async () => {
    const iso = '2026-01-02T03:04:05.000Z';
    for (const lang of ['ru', 'en']) for (const known of [true, false]) {
        const f = await launch(lang);
        f.replies.push({ data: { preview: preview({ mode: 'abandon', activeClients: null, accountCount: known ? 4 : null,
            unavailableSince: known ? iso : null }) } });
        f.buttons[0].click(); await flush();
        const stamp = new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' }).format(Date.parse(iso));
        const [warning, accounts] = f.message.textContent.split('\n');
        assert.equal(warning, known ? expected[lang].offline(`${stamp} (UTC)`) : words(lang).offlineSinceUnknown);
        assert.equal(accounts, known ? expected[lang].accounts : words(lang).accountCountUnknown);
        assert.equal(f.confirm.textContent, words(lang).confirmAbandon);
        assert.equal(f.calls.length, 1);
        f.replies.push({ data: { nodeId: id, status: 'deleted' } });
        f.confirm.click(); await flush();
        assert.deepEqual(f.calls[1].body, { ticket, decision: 'abandon' });
    }
});

test('stale abandon consumes its ticket without a replacement preview or another request', async () => {
    const f = await launch('en');
    f.replies.push({ data: { preview: preview({ mode: 'abandon', activeClients: null }) } },
        { status: 409, data: { error: { code: 'PREVIEW_CHANGED' } } });
    f.buttons[0].click(); await flush();
    f.confirm.click(); await flush();
    assert.equal(f.status.textContent, words('en').newPreviewRequired);
    assert.equal(f.confirm.hidden, true);
    assert.equal(f.calls.length, 2);
});

test('neighbor/protected refusal and a wrong-node preview do not offer confirmation', async () => {
    for (const [reply, copy] of [
        [{ status: 409, data: { error: { code: 'REBUILD_NEIGHBOR_UNAVAILABLE' } } }, 'neighborUnavailable'],
        [{ data: { preview: preview({ allowed: false, ticket: undefined }) } }, 'protectedChange'],
        [{ data: { preview: preview({ nodeId: ids[1] }) } }, 'previewUnavailable'],
        [drift(preview({ nodeId: ids[1] })), 'previewUnavailable'],
        [drift(preview({ allowed: false, ticket: undefined })), 'protectedChange'],
        [{ ...drift(preview()), status: 503 }, 'previewUnavailable'],
    ]) {
        const f = await launch('ru');
        f.replies.push(reply);
        f.buttons[0].click(); await flush();
        assert.equal(f.status.textContent, words('ru')[copy]);
        assert.equal(f.confirm.hidden, true);
        f.confirm.click();
        assert.equal(f.calls.length, 1);
    }
});

test('after confirm, a protected-change refusal is shown without retry; a mismatched receipt never reloads the page', async () => {
    for (const [reply, key] of [
        [{ status: 409, data: { error: { code: 'REBUILD_RETIRE_PROTECTED_CHANGE' } } }, 'protectedChange'],
        [{ data: { nodeId: ids[1], status: 'deleted' } }, 'outcomeUnconfirmed'],
    ]) {
        const f = await launch('en');
        f.replies.push({ data: { preview: preview() } }, reply);
        f.buttons[0].click(); await flush();
        f.confirm.click(); await flush();
        assert.equal(f.status.textContent, words('en')[key]);
        assert.equal(f.confirm.hidden, true);
        assert.equal(f.calls.length, 2);
        assert.deepEqual(f.reloads, []);
    }
});

test('cancel discards the local ticket; lost confirmation reply never replays', async () => {
    const f = await launch('en');
    f.replies.push({ data: { preview: preview() } }, { data: { preview: preview({ ticket: freshTicket }) } });
    f.buttons[0].click(); await flush();
    f.close.click();
    f.confirm.click();
    assert.equal(f.calls.length, 1);
    f.buttons[0].click(); await flush();
    f.confirm.click(); await flush();
    assert.equal(f.status.textContent, words('en').outcomeUnconfirmed);
    assert.equal(f.confirm.hidden, true);
    f.confirm.click(); f.close.click(); f.buttons[0].click(); await flush();
    assert.deepEqual(f.calls.map(({ path, body }) => ({ path, body })), [
        { path: url(id, 'preview'), body: {} }, { path: url(id, 'preview'), body: {} },
        { path: url(id, 'confirm'), body: { ticket: freshTicket, decision: 'delete' } },
    ]);
    assert.deepEqual(f.reloads, []);
});
