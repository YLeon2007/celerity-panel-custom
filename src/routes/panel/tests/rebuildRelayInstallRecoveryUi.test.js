'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { runInNewContext } = require('node:vm');
const ejs = require('ejs');
const { t: translate } = require('../../../middleware/i18n');

const root = resolve(__dirname, '../../../..');
const script = readFileSync(resolve(root, 'public/js/rebuild-l2tp.js'), 'utf8');
const id = 'a'.repeat(24);
const url = `/panel/rebuild/relays/${id}/l2tp/install/recover`;
const relay = { id, name: 'Fixture', ip: '192.0.2.20', status: 'installing', bound: true,
    grantSource: 'db', canRecoverInstall: true };

function render(lang = 'ru', overrides = {}) {
    return ejs.renderFile(resolve(root, 'views/rebuild-l2tp.ejs'), { t: key => translate(key, lang),
        relays: [relay], accounts: [], csrfToken: 'fixture-csrf', canManageAccounts: false,
        canRequestInstallRecovery: true, rebuildL2tpScriptVersion: 'fixture', ...overrides });
}

test('localized recovery is rendered only for an eligible installing card and an authorized view', async () => {
    for (const lang of ['en', 'ru', 'zh-CN']) {
        const copy = require(`../../../locales/${lang}.json`).rebuildL2tp;
        const html = await render(lang, { relays: [{ ...relay, canInstall: true }] });
        assert.ok(html.includes(`data-install-recovery-url="${url}"`));
        assert.ok(html.includes(`>${ejs.escapeXML(copy.recoverInstall)}<`));
        assert.ok(html.includes(`>${ejs.escapeXML(copy.refresh)}<`));
        assert.ok(html.includes(`>${ejs.escapeXML(copy.status.installing)}<`));
        for (const message of ['working', 'canInstallAgain', 'installRecoveryUnconfirmed']) {
            assert.equal(typeof copy.messages[message], 'string');
            assert.ok(html.includes(ejs.escapeXML(copy.messages[message])));
        }
        assert.doesNotMatch(html, /data-install-url=/);
    }
    assert.match(await render(), />Проверить и продолжить</);
    for (const overrides of [{ canRequestInstallRecovery: false }, { accountsPending: true },
        { changedRelayId: id }, { grantProblem: 'REBUILD_L2TP_GRANT_UNAVAILABLE' }, { loadError: true },
        ...[{ status: 'not_installed' }, { status: 'installed' }, { bound: false },
            { grantProblem: 'REBUILD_L2TP_IDENTITY_CHANGED' }, { canRecoverInstall: false }]
            .map(patch => ({ relays: [{ ...relay, ...patch }] }))]) {
        assert.doesNotMatch(await render('ru', overrides), /data-install-recovery-url=/);
    }
});

test('the real overview projects a rebuild reservation as a recovery affordance, never as Install', async () => {
    const { createRebuildL2tpOverview } = require('../../../services/rebuildL2tpOverview');
    const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../../../modules/relay-l2tp/domain/l2tpRoutingSelection');
    const binding = { nodeId: id, machineId: 'b'.repeat(32), sshHostKeySha256: 'c'.repeat(64),
        host: relay.ip, port: 22, username: 'root' };
    const env = { C3_REBUILD_ENABLED: 'true', C3_REBUILD_L2TP_INSTALL_ENABLED: 'true',
        C3_REBUILD_L2TP_RELAYS_JSON: JSON.stringify([binding]), ENCRYPTION_KEY: 'fixture-key-only'.repeat(3) };
    const card = { _id: id, name: relay.name, ip: relay.ip, ssh: { port: 22, username: 'root' },
        cascadeRole: 'relay', active: true, type: 'xray' };
    const state = { _id: id, node: id, status: 'installing', desiredState: 'installed',
        routingMode: FOLLOW_RELAY_MODE, routingVersion: FOLLOW_RELAY_VERSION, rebuildMachineId: binding.machineId,
        backupId: 'd'.repeat(32), rebuildInstallToken: '12345678-1234-4abc-8123-000000000001' };
    let source = 'db', pending = false, duplicates = false;
    // Read-only persistence stubs; no mutating API or transport is supplied.
    const db = { collection: () => ({ findOne: async ({ _id }) => _id === 'pending' && pending ? { _id } : null,
        distinct: async () => [] }) };
    const model = rows => ({ db, find() {
        return { sort() { return this; }, select() { return this; }, read() { return this; },
            readConcern() { return this; }, maxTimeMS() { return this; }, lean: async () => rows() };
    } });
    const overview = createRebuildL2tpOverview({ Node: model(() => [card]), L2tpUser: model(() => []),
        State: { ...model(() => duplicates ? [state, state] : [state]), schema: { path: () => ({ enumValues: ['installing'] }) } },
        env, relayGrantStore: { snapshot: async () => ({ env, grants: [binding], sourceFor: () => source }) } });
    const initial = await overview.overview();
    assert.equal(initial.relays[0].canRecoverInstall, true);
    assert.equal(initial.relays[0].canInstall, false);
    for (const witness of [state.backupId, state.rebuildInstallToken, state.rebuildMachineId]) {
        assert.ok(!JSON.stringify(initial).includes(witness));
    }
    assert.match(await render('ru', initial), /data-install-recovery-url=/);
    async function blocked() {
        const view = await overview.overview();
        assert.notEqual(view.relays[0].canRecoverInstall, true);
        assert.doesNotMatch(await render('ru', view), /data-install-recovery-url=|data-install-url=/);
    }
    source = 'env'; await blocked(); source = 'db';
    duplicates = true; await blocked(); duplicates = false;
    pending = true; await blocked(); pending = false;
    card.type = 'hysteria'; await blocked(); card.type = 'xray';
    env.C3_REBUILD_L2TP_INSTALL_ENABLED = 'false'; await blocked(); env.C3_REBUILD_L2TP_INSTALL_ENABLED = 'true';
    state.rebuildMachineId = 'e'.repeat(32); await blocked(); state.rebuildMachineId = binding.machineId;
    state.rebuildInstallToken = 'invalid'; await blocked();
});

function control(dataset = {}) {
    const listeners = {};
    return { dataset, disabled: true, hidden: true, textContent: '',
        addEventListener(name, fn) { listeners[name] = fn; }, click() { listeners.click?.(); } };
}

async function launch() {
    const html = await render();
    const attr = name => html.match(new RegExp(`data-${name}="([^"]*)"`))[1].replace(/&(amp|lt|gt|#34|#39);/g,
        (_, key) => ({ amp: '&', lt: '<', gt: '>', '#34': '"', '#39': "'" })[key]);
    const status = control(), refresh = control(), calls = [];
    let reply;
    const recovery = control({ installRecoveryUrl: attr('install-recovery-url'), nodeId: id });
    const install = control(); // Another relay's normal Install button.
    const page = { dataset: { csrf: attr('csrf'), messages: attr('messages') },
        querySelector: sel => ({ '[data-action-status]': status, '[data-refresh]': refresh })[sel],
        querySelectorAll: sel => ({ '[data-install-recovery-url]': [recovery], '[data-install-url]': [install] })[sel] ?? [] };
    runInNewContext(script, { document: { getElementById: () => page }, window: { addEventListener() {} },
        fetch: (...params) => { calls.push(params); return new Promise(resolve => { reply = resolve; }); } });
    return { status, refresh, recovery, install, calls,
        resolve: value => reply(value), next: () => new Promise(resolve => setImmediate(resolve)) };
}

const receipt = { executionMode: 'rebuild', status: 'can_install_again', nodeId: id };

test('one explicit click sends only empty JSON and waits for the bound success receipt; no reload or replay', async () => {
    const f = await launch();
    await f.next();
    assert.deepEqual(f.calls, []);
    assert.equal(f.recovery.disabled, false);
    f.recovery.click();
    f.recovery.click();
    assert.equal(f.recovery.disabled, true);
    assert.equal(f.install.disabled, true);
    assert.equal(f.calls.length, 1);
    const [[path, options]] = f.calls;
    assert.equal(path, url);
    for (const [key, expected] of Object.entries({ method: 'POST', mode: 'same-origin', credentials: 'same-origin',
        cache: 'no-store', redirect: 'error', body: '{}' })) assert.equal(options[key], expected);
    assert.equal(options.headers['x-csrf-token'], 'fixture-csrf');
    assert.doesNotMatch(f.status.textContent, /Можно установить заново/);
    f.resolve({ ok: true, json: async () => receipt });
    await f.next();
    assert.match(f.status.textContent, /^Можно установить заново\./);
    assert.equal(f.refresh.hidden, false);
    assert.equal(f.recovery.disabled, true);
    assert.equal(f.install.disabled, true);
    f.recovery.click();
    assert.equal(f.calls.length, 1);
});

test('unavailable, malformed, ambiguous or misbound responses never show permission to reinstall', async () => {
    for (const response of [() => Promise.reject(new Error('PRIVATE')),
        () => ({ ok: false, status: 503, json: async () => ({ error: { message: 'PRIVATE' } }) }),
        () => ({ ok: true, json: async () => { throw new Error('PRIVATE'); } }),
        () => ({ ok: true, json: async () => ({ ...receipt, nodeId: 'b'.repeat(24) }) }),
        () => ({ ok: true, json: async () => ({ ...receipt, error: { outcome: 'unknown' }, detail: 'PRIVATE' }) })]) {
        const f = await launch();
        f.recovery.click();
        f.resolve(response());
        await f.next();
        assert.equal(f.status.textContent, require('../../../locales/ru.json').rebuildL2tp.messages.installRecoveryUnconfirmed);
        assert.doesNotMatch(f.status.textContent, /Можно установить заново|PRIVATE/);
        assert.equal(f.recovery.disabled, true);
        assert.equal(f.install.disabled, true);
        assert.equal(f.refresh.hidden, false);
        f.recovery.click();
        assert.equal(f.calls.length, 1);
    }
});
