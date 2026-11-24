'use strict';

// Offline: use the checked-out source and locales; NODE_PATH may point at existing jsdom/esbuild.
const assert = require('node:assert/strict');
const path = require('node:path');
const { test } = require('node:test');
const { JSDOM } = require('jsdom');
const { buildSync } = require('esbuild');
const model = require('../public/js/network/src/core/model');
const { kcpApplyFingerprint, projectLinkHealth } = require('../src/services/rebuildReverseLinkHealth');

const root = path.resolve(__dirname, '..');
const bundle = buildSync({ absWorkingDir: root, stdin: { resolveDir: root, contents: `
    export { createToolbar } from './public/js/network/src/ui/toolbar.js';
    export { createStore } from './public/js/network/src/core/store.js';
    export { mount } from './public/js/network/src/views/chains.js';
` }, bundle: true, format: 'iife', globalName: 'fixture', write: false }).outputFiles[0].text;
const node = (id, status, extra = {}) => ({ data: { id, label: id, status, ...extra } });
const link = (id, source, target, status, extra = {}) => ({ data: { id, label: id, source, target, status, mode: 'forward', ...extra } });
const topo = (nodes = [], edges = []) => ({ nodes, edges });
const unknown = topo([node('A', 'unknown'), node('B'), node('C', 'unknown'), node('D')],
    [link('AB', 'A', 'B', 'deployed'), link('CD', 'C', 'D', 'deployed')]);
function kcp(mode, applied, overrides = {}) {
    const listener = '1'.repeat(24), dialer = '2'.repeat(24);
    const row = { _id: '3'.repeat(24), portalNode: listener, bridgeNode: dialer, mode, active: true,
        tunnelTransport: 'kcp', tunnelPort: 4433, tunnelUuid: 'fixture-id', rebuildApplyEpoch: 'a'.repeat(32),
        status: 'online', latencyMs: 17 };
    if (applied) {
        row.rebuildApplied = { listener: mode === 'reverse' ? listener : dialer, mode, protocol: 'vless', port: 4433, uuid: 'fixture-id' };
        row.rebuildKcpApplied = kcpApplyFingerprint(row, row.rebuildApplyEpoch);
    }
    return projectLinkHealth({ ...row, ...overrides }, true);
}

function mount(t, locale = 'ru') {
    const { network } = require(`../src/locales/${locale}.json`);
    const dom = new JSDOM(`<html lang="${locale}"><body><div id="networkRoot"><div id="toolbar"></div><div id="stage"></div></div></body></html>`,
        { url: 'https://panel.invalid', runScripts: 'outside-only' });
    const w = dom.window;
    const labels = w.document.createElement('script');
    labels.type = 'application/json';
    labels.id = 'networkI18n';
    labels.textContent = JSON.stringify(network);
    w.document.body.append(labels);
    const one = selector => w.document.querySelector(selector);
    const all = selector => [...w.document.querySelectorAll(selector)];
    const text = el => el.textContent.trim();
    w.requestAnimationFrame = cb => w.setTimeout(cb, 0);
    // Drive the real API/store with in-memory responses and a controllable clock; no sockets.
    let now = 1_000_000;
    let timerId = 0;
    const timers = new Map();
    w.Date.now = () => now;
    w.setTimeout = (fn, delay) => { timers.set(++timerId, { fn, at: now + delay }); return timerId; };
    w.clearTimeout = id => timers.delete(id);
    let next;
    w.fetch = async (url, options) => {
        assert.equal(url, '/api/cascade/topology');
        assert.equal(options.method, 'GET');
        assert.ok(next, 'scripted topology');
        return { ok: true, json: async () => w.JSON.parse(JSON.stringify(next)) };
    };
    w.eval(bundle);
    const store = w.fixture.createStore({ isVisible: () => true });
    const toolbar = w.fixture.createToolbar(one('#toolbar'), { store });
    const view = w.fixture.mount(one('#stage'), { store, toolbar });
    const events = [];
    store.on('error', error => assert.fail(error));
    store.on('data', change => { events.push(change.structural); toolbar.update(); view.update({ type: 'data', ...change }); });
    store.on('filter', () => view.update({ type: 'filter' }));
    t.after(() => { view.destroy(); store.destroy(); w.close(); });
    const advance = ms => {
        now += ms;
        for (const [id, timer] of timers) {
            if (timer.at <= now) { timers.delete(id); timer.fn(); }
        }
    };
    return { one, all, text, store, events, advance, now: () => now, toolbar, network,
        refresh: fixture => { next = fixture; return store.refresh(); },
        status: () => text(one('.nm-attention')), kpi: () => text(one('.nmc-kpis [data-attention] .v')),
    };
}

test('severity classifies projected mKCP, explicit failures and bounded reverse evidence', () => {
    for (const mode of ['forward', 'reverse']) {
        const pending = kcp(mode, false), deployed = kcp(mode, true), error = kcp(mode, true, { status: 'error' });
        assert.deepEqual([pending.status, pending.tunnelVerification, deployed.status, deployed.tunnelVerification],
            ['pending', 'mkcp_apply_unconfirmed', 'deployed', 'mkcp_runtime_unsupported']);
        for (const data of [pending, deployed, { ...pending, status: 'online' }]) assert.equal(model.attention('link', data), 'unverified');
        assert.equal(model.attention('link', error), 'problem');
    }
    for (const status of ['error', 'offline']) {
        assert.equal(model.attention('node', { status }), 'problem');
        assert.equal(model.attention('link', { status, tunnelVerification: 'mkcp_apply_unconfirmed' }), 'problem');
    }
    for (const status of [undefined, 'unknown', 'pending', 'deployed', 'syncing']) {
        assert.equal(model.attention('node', { status }), 'unverified');
        assert.equal(model.attention('link', { status }), 'unverified');
    }
    assert.equal(model.attention('node', null), 'unverified');
    const now = Date.now();
    for (const [expiresAt, expected] of [[undefined, 'unverified'], [now, 'unverified'], [now + 1000, 'ok'], [now + 91_000, 'unverified']]) {
        assert.equal(model.attention('link', { status: 'online', mode: 'reverse', observationExpiresAt: expiresAt }), expected);
    }
});

test('RU toolbar, KPI, lane and attention filter show six unverified, not six errors', async t => {
    const ui = mount(t);
    await ui.refresh(unknown);
    const stats = model.stats(model.buildIndex(unknown));
    assert.deepEqual([stats.problems, stats.unverified, stats.chainsOk, stats.avgLatency], [0, 6, 0, null]);
    assert.equal(ui.status(), '6 не проверено');
    assert.equal(ui.kpi(), '6 не проверено');
    assert.ok(ui.one('.nmc-lane-head .meta').textContent.includes('3 не проверено'));
    const latency = ui.all('.nmc-kcard').find(card => card.querySelector('.k').textContent.trim() === 'Средняя задержка');
    assert.equal(ui.text(latency.querySelector('.v')), '—');
    ui.one('.nm-attention').click();
    assert.equal(ui.all('.nm-pop .nm-prob').length, 6);
    assert.equal(ui.all('.nm-pop .nm-prob.error, .nm-pop .nm-prob.warn').length, 0);
    ui.one('.nm-attention-filter').click();
    assert.ok(ui.store.state.filter.problemsOnly);
    assert.equal(ui.all('.nmc-lane').length, 2);
    ui.store.setFilter({ query: 'absent' });
    assert.equal(ui.text(ui.one('.nmc-empty .msg')), 'Ничего не найдено');
    assert.ok(!ui.one('.nmc-empty .ti-circle-check'));
});

test('mixed failures lead unverified; synthetic mirrors do not count', async t => {
    const ui = mount(t);
    const nodes = [node('A', 'online'), node('B', 'unknown'), node('C', 'offline'), node('D', 'online'),
        node('internet', 'error', { type: 'internet' }), node('cdn', 'error', { type: 'cdn' })];
    const edges = [link('AB', 'A', 'B', 'online', { latencyMs: 53 }), link('BC', 'B', 'C', 'error'),
        link('nested', 'cdn', 'D', 'error', { isCdnEdge: true }), link('out', 'D', 'internet', 'error', { isInternetEdge: true })];
    await ui.refresh(topo(nodes, edges));
    assert.equal(ui.status(), '2 проблемы · 1 не проверено');
    assert.equal(ui.kpi(), ui.status());
    assert.equal(ui.one('.nm-attention').dataset.attention, 'problem');
    ui.one('.nm-attention').click();
    assert.deepEqual(ui.all('.nm-prob .t').map(ui.text), ['BC', 'C', 'B']);
    assert.equal(ui.store.model.stats(ui.store.index).avgLatency, 53);
    assert.equal(ui.store.model.chainSummary(ui.store.index, ui.store.model.chains(ui.store.index)[0]).status, 'error');
    ui.store.setFilter({ problemsOnly: true });
    assert.equal(ui.one('.nmc-solo[data-node="D"]'), null);
    assert.ok(ui.one('.nmc-card[data-node="A"]'), 'retain chain context');
    assert.deepEqual([...model.attentionScope(model.buildIndex(topo(nodes, edges))).nodes].sort(), ['B', 'C']);
});

test('missing endpoints cannot erase an error or yield a green summary', async t => {
    const ui = mount(t);
    await ui.refresh(topo([node('A', 'online')], [link('AB', 'A', 'B', 'online', { latencyMs: 17 })]));
    assert.equal(ui.status(), '1 не проверено');
    assert.equal(ui.store.model.stats(ui.store.index).avgLatency, null);
    await ui.refresh(topo([node('A', 'online')], [link('AB', 'A', 'B', 'error')]));
    assert.equal(ui.status(), '1 проблема');
    ui.one('.nm-attention').click();
    assert.ok(ui.one('.nm-pop .nm-prob.error').disabled, 'do not navigate to an unplaceable link');
});

for (const [locale, good, notFound, unchecked] of [
    ['ru', 'Проблем нет', 'Ничего не найдено', '1 не проверено'],
    ['en', 'No problems', 'Nothing found', '1 unverified'],
    ['zh-CN', '没有问题', '未找到结果', '1 项未验证'],
]) {
    test(`${locale}: all-online, empty search, empty inventory, and observation expiry`, async t => {
        const ui = mount(t, locale);
        await ui.refresh(topo([node('A', 'online'), node('B', 'online')],
            [link('AB', 'A', 'B', 'online', { mode: 'reverse', observationExpiresAt: ui.now() + 5000 })]));
        assert.equal(ui.status(), good);
        assert.equal(ui.kpi(), good);
        assert.equal(ui.store.model.stats(ui.store.index).chainsOk, 1);
        ui.store.setFilter({ query: 'absent' });
        assert.equal(ui.status(), notFound);
        assert.equal(ui.kpi(), notFound);
        ui.store.setFilter({ query: '' });
        ui.one('.nm-attention-filter').click();
        assert.equal(ui.all('.nmc-lane').length, 0);
        ui.advance(5000);
        assert.deepEqual(ui.events, [true, false]);
        assert.equal(ui.status(), unchecked);
        assert.equal(ui.kpi(), unchecked);
        assert.equal(ui.store.index.links.get('AB').status, 'deployed');
        assert.equal(ui.all('.nmc-lane').length, 1);
        assert.equal(ui.store.model.stats(ui.store.index).avgLatency, null);
        await ui.refresh(topo([node('internet', 'online'), node('cdn', 'online', { type: 'cdn' })]));
        assert.equal(ui.status(), ui.network.map.noStatusData);
        assert.equal(ui.kpi(), ui.status());
        assert.notEqual(ui.one('.nm-attention').dataset.attention, 'ok');
    });
}
