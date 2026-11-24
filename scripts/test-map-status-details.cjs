'use strict';

// Firefox is used for the real DOM and CSS, with no server or downloads.
// Run offline: unshare -Urn --map-current-user node scripts/test-map-status-details.cjs SCRATCH_DIR
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { kcpApplyFingerprint, projectLinkHealth } = require('../src/services/rebuildReverseLinkHealth');

const [scratch] = process.argv.slice(2);
assert.ok(scratch, 'Pass a private scratch directory for Firefox artifacts');
const root = path.resolve(__dirname, '..');
const src = path.join(root, 'public/js/network/src');
const read = f => fs.readFileSync(f, 'utf8');
const moduleUrl = code => 'data:text/javascript;base64,' + Buffer.from(code).toString('base64');
const memo = new Map();
// Data URLs work for native modules on file: without changing Firefox's origin
// policy. Keep implementation bodies intact, adapting only the CJS export.
function sourceModule(file) {
    if (memo.has(file)) return memo.get(file);
    let code = read(file).replace(/^(import .+? from )(['"])(\.\.?\/[^'"]+)\2;/gms,
        (_, prefix, quote, spec) => `${prefix}${quote}${sourceModule(path.resolve(path.dirname(file), spec))}${quote};`);
    if (file === path.join(src, 'core/model.js')) code = code.replace('module.exports =', 'export default');
    const url = moduleUrl(code);
    memo.set(file, url);
    return url;
}

function projectedKcp(applied) {
    const row = { _id: '3'.repeat(24), portalNode: '1'.repeat(24), bridgeNode: '2'.repeat(24),
        status: 'online', mode: 'reverse', active: true, tunnelProtocol: 'vless', tunnelTransport: 'kcp',
        tunnelSecurity: 'none', tunnelPort: 12345, tunnelUuid: 'fixture-id', rebuildApplyEpoch: 'a'.repeat(32) };
    if (applied) {
        row.rebuildApplied = { listener: row.portalNode, mode: row.mode, protocol: row.tunnelProtocol, port: row.tunnelPort, uuid: row.tunnelUuid };
        row.rebuildKcpApplied = kcpApplyFingerprint(row, row.rebuildApplyEpoch);
    }
    return projectLinkHealth(row, true);
}

function exercise(lang, network, kcp) {
    const check = (predicate, message) => { if (!predicate) throw new Error(`${lang}: ${message}`); };
    const contains = (el, value, message) => check(value && el.textContent.includes(value), message);
    const details = network.map.details;
    document.getElementById('networkI18n').textContent = JSON.stringify(network);
    const sidebar = document.querySelector('aside');
    const nodeBase = { id: 'p', label: 'Fixture portal', status: 'online', cascadeRole: 'portal' };
    const target = { id: 'b', label: 'Fixture exit', status: 'online', cascadeRole: 'bridge' };
    const edgeBase = { id: 'link-fixture', source: 'p', target: 'b', label: 'Fixture link', mode: 'reverse',
        tunnelProtocol: 'vless', tunnelTransport: 'tcp', tunnelSecurity: 'reality', tunnelPort: 12345 };
    const store = { state: { selection: { kind: 'link', id: edgeBase.id } } };
    const inspector = createInspector(sidebar, { store });
    const link = (props, title, description, compact) => {
        store.state.selection = { kind: 'link', id: edgeBase.id };
        store.index = model.buildIndex({ nodes: [{ data: nodeBase }, { data: target }], edges: [{ data: { ...edgeBase, ...props } }] });
        const edge = store.index.links.get(edgeBase.id);
        const now = Date.now();
        const stats = model.stats(store.index);
        const status = model.attentionStatus('link', edge, now);
        const level = model.attention('link', edge, now);
        check(level === (stats.problems ? 'problem' : stats.unverified ? 'unverified' : 'ok') &&
            stats.linksOk === Number(level === 'ok'), 'fixture disagrees with KPI');
        const pill = h(`div.nm-pill.${status}`, null, pillContent(edge));
        document.getElementById('networkRoot').append(pill);
        tip.show(0, 0, linkTip(store.index, edge));
        const hover = document.querySelector('.nm-tip');
        inspector.render();
        const sub = sidebar.querySelector('.nm-insp-title .sub');
        const heading = sub.querySelector(`.nm-st.${status}`);
        const tipTitle = hover.querySelector('.m > b');
        check(heading && hover.querySelector(`.t > .nm-dot.${status}`),
            `expected model status ${status} in detail for ${JSON.stringify(props)}`);
        check(sub.scrollWidth <= sub.clientWidth, 'status badge overflows the inspector header');
        check(heading.textContent === title && tipTitle?.textContent === title, `wrong detailed status: ${title}`);
        for (const el of [hover, sidebar]) {
            if (description) contains(el, description, `missing detailed explanation: ${description}`);
        }
        const hasLatency = level === 'ok' && stats.avgLatency !== null;
        check(Boolean(sidebar.querySelector('.nm-path .nm-hop-arrow .ms')) === hasLatency, 'path latency disagrees with KPI');
        if (compact !== null) check(pill.textContent.trim() === compact, `wrong compact label: ${pill.textContent}`);
        return { pill, hover, sidebar };
    };
    function noGreen({ sidebar, hover }) {
        check(!sidebar.querySelector('.nm-st.online') && !hover.querySelector('.nm-dot.online'), 'unverified/failure rendered online');
    }
    function neutral({ sidebar, hover }) {
        noGreen({ sidebar, hover });
        check(sidebar.querySelector('.nm-insp-body > .nm-alert.muted'), 'expected a muted explanation');
        check(!sidebar.querySelector('.nm-st.error,.nm-st.offline') && !hover.querySelector('.nm-dot.error,.nm-dot.offline'),
            'unverified rendered as an error or offline');
    }
    const unverified = details.unverifiedShort;
    const deployed = network.map.status.deployed;
    const unsupported = { tunnelTransport: 'kcp', tunnelVerification: 'mkcp_runtime_unsupported' };
    const now = Date.now();
    Date.now = () => now;
    const sample = '<i data-fixture-injection>literal</i>';
    const sensitive = 'SYNTHETIC_FIELD_NOT_FOR_DISPLAY';
    const recent = new Date(now - 5000).toISOString();
    const staleLatency = network.map.ms.replace('{n}', '777');

    let ui = link({ status: 'deployed', latencyMs: 777 }, deployed, details.linkUnverifiedDesc, unverified);
    neutral(ui);
    check(![ui.hover, ui.sidebar, ui.pill].some(el => el.textContent.includes(staleLatency)), 'stale latency displayed');
    check(ui.pill.getBoundingClientRect().width < 132, 'unverified pill exceeds compact width');
    neutral(link(kcp.applied, network.mkcpAppliedUnverified, network.mkcpRuntimeUnsupported, unverified));
    neutral(link(kcp.pending, network.map.status.pending, network.mkcpApplyUnconfirmed, unverified));
    neutral(link({ status: 'pending' }, network.map.status.pending, network.map.alert.linkPendingDesc, unverified));

    ui = link({ status: 'online', lastHealthCheck: recent, observationExpiresAt: now + 90_000 },
        details.linkObserved, details.linkObservedDesc, '—');
    const checkPrefix = network.map.lastCheck.split('{when}')[0];
    const expiryPrefix = details.observationExpires.split('{when}')[0];
    for (const el of [ui.hover, ui.sidebar]) {
        check(el.textContent.includes(checkPrefix) && el.textContent.includes(expiryPrefix), 'missing observation timestamp');
    }
    check(ui.sidebar.querySelector('.nm-st.online') && ui.hover.querySelector('.nm-dot.online'), 'fresh observation not online');
    for (const flags of [unsupported, { tunnelVerification: unsupported.tunnelVerification }, { tunnelTransport: 'kcp' },
        { tunnelVerification: 'mkcp_apply_unconfirmed' }]) {
        const status = flags.tunnelVerification === 'mkcp_apply_unconfirmed' ? 'pending' : 'deployed';
        ui = link({ status: 'online', observationExpiresAt: now + 30000, ...flags, latencyMs: 777 }, network.map.status[status],
            status === 'pending' ? network.map.alert.linkPendingDesc : details.linkUnverifiedDesc, unverified);
        neutral(ui);
        check(![ui.hover, ui.sidebar, ui.pill].some(el => [expiryPrefix, details.linkObserved, staleLatency]
            .some(value => el.textContent.includes(value))), 'stray reverse metadata exposed as a live observation');
    }
    ui = link({ status: 'online', observationExpiresAt: now,
        latencyMs: 777 }, deployed, details.linkObservationStaleDesc, unverified);
    neutral(ui);
    check(![ui.hover, ui.sidebar].some(el => el.textContent.includes(staleLatency)), 'expired observation displays latency');
    for (const expiry of [undefined, now + 90_001, { private: sensitive }]) {
        neutral(link({ status: 'online', observationExpiresAt: expiry }, deployed, details.linkUnverifiedDesc, unverified));
    }
    neutral(link({ status: 'online', ...unsupported, observationExpiresAt: now - 1 }, deployed, details.linkUnverifiedDesc, unverified));
    neutral(link({ status: 'online', missingEndpoint: true, observationExpiresAt: now + 30_000 },
        network.map.status.unknown, details.linkUnverifiedDesc, unverified));
    neutral(link({ status: 'future_enum' }, network.map.status.unknown, details.linkUnverifiedDesc, unverified));
    const ahead = { ...edgeBase, status: 'online', observationExpiresAt: now + 90_001 };
    check(linkDisplayStatus(ahead, now + 1) === 'online' && h('div', null, pillContent(ahead, now + 1)).textContent === '—',
        'detail classification ignored supplied clock');
    ui = link({ status: 'online', mode: 'forward', latencyMs: 19 }, network.map.status.online, null, network.map.ms.replace('{n}', '19'));
    check(ui.sidebar.querySelector('.nm-st.online') && ui.hover.querySelector('.nm-dot.online'), 'ordinary online forward probe lost');
    link({ status: 'online', mode: 'forward', latencyMs: -1 }, network.map.status.online, null, '—');

    for (const status of ['error', 'offline']) {
        ui = link({ ...unsupported, status, latencyMs: 777, lastHealthCheck: recent,
            lastError: sample + 'x'.repeat(400) + 'TRUNCATED_TAIL', rebuildApplied: { private: sensitive } },
        network.map.status[status], null, network.map.pill[status]);
        noGreen(ui);
        check(ui.sidebar.querySelector(`.nm-st.${status}`) && ui.hover.querySelector(`.nm-dot.${status}`), 'failure style lost');
        for (const el of [ui.hover, ui.sidebar]) {
            contains(el, sample, 'plain diagnostic not shown');
            check(!el.querySelector('[data-fixture-injection]') && el.textContent.includes('…') && !el.textContent.includes('TRUNCATED_TAIL') &&
                !el.textContent.includes(sensitive), 'diagnostic not plain, bounded text');
        }
    }
    ui = link({ status: 'error', lastHealthCheck: { private: sensitive }, lastError: { private: sensitive } },
        network.map.status.error, null, network.map.pill.error);
    check(![ui.hover, ui.sidebar].some(el => /\[object Object\]|SYNTHETIC_FIELD_NOT_FOR_DISPLAY/.test(el.textContent)), 'object rendered');

    const unknown = { ...nodeBase, status: 'unknown', lastSync: recent, onlineUsers: 113 };
    store.index = model.buildIndex({ nodes: [{ data: unknown }] });
    store.state.selection = { kind: 'node', id: unknown.id };
    inspector.render();
    tip.show(0, 0, nodeTip(unknown));
    const hover = document.querySelector('.nm-tip');
    for (const el of [hover, sidebar]) {
        contains(el, network.map.status.unknown, 'unknown node status missing');
        contains(el, details.nodeUnknownDesc, 'unknown node explanation missing');
        check(!el.textContent.includes('113') && !el.querySelector('.nm-alert.error,.nm-st.online,.nm-st.offline'),
            'unknown node reports stale users, online or offline');
    }
    const unknownPill = sidebar.querySelector('.nm-st.unknown');
    check(unknownPill && getComputedStyle(unknownPill, '::before').boxShadow !== 'none' && sidebar.querySelector('.nm-alert.muted'),
        'unknown node has no neutral style');
}

const imports = [
    ['model', 'core/model.js'],
    ['{ h, tip }', 'ui/dom.js'],
    ['{ linkDisplayStatus, pillContent, linkTip, nodeTip }', 'ui/format.js'],
    ['{ createInspector }', 'ui/inspector.js'],
].map(([name, file]) => `import ${name} from ${JSON.stringify(sourceModule(path.join(src, file)))};`).join('\n');
const css = read(path.join(root, 'public/css/network-map.css'));
const temp = fs.mkdtempSync(path.join(path.resolve(scratch), 'map-status-dom-'));
const profile = path.join(temp, 'profile');
const runtime = path.join(temp, 'runtime');
for (const p of [profile, runtime]) fs.mkdirSync(p, { mode: 0o700 });
fs.writeFileSync(path.join(profile, 'user.js'), 'user_pref("browser.dom.window.dump.enabled", true);\n');
try {
    const kcp = { applied: projectedKcp(true), pending: projectedKcp(false) };
    assert.deepEqual([kcp.applied.status, kcp.applied.tunnelVerification, kcp.pending.status, kcp.pending.tunnelVerification],
        ['deployed', 'mkcp_runtime_unsupported', 'pending', 'mkcp_apply_unconfirmed']);
    for (const lang of ['en', 'ru', 'zh-CN']) {
        const { network } = JSON.parse(read(path.join(root, 'src/locales', `${lang}.json`)));
        const pass = `PASS map-status-details ${lang}`;
        const script = moduleUrl(`${imports}\ntry { (${exercise})(${JSON.stringify(lang)},${JSON.stringify(network)},${JSON.stringify(kcp)}); dump(${JSON.stringify(pass + '\n')}); } catch (err) { dump('FAIL ' + err.message + '\\n'); }`);
        const page = path.join(temp, `${lang}.html`);
        fs.writeFileSync(page, `<!doctype html><html lang="${lang}"><meta charset="utf-8">
            <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src data:; style-src 'unsafe-inline'">
            <style>${css}</style><body><div id="tabNetwork" class="active"><main id="networkRoot"><aside class="nm-insp"></aside></main></div>
            <script type="application/json" id="networkI18n"></script><script type="module" src="${script}"></script>`);
        const run = spawnSync('firefox', ['--headless', '--no-remote', '--profile', profile, '--window-size', '320,700',
            '--screenshot', path.join(temp, `${lang}.png`), pathToFileURL(page).href], {
            encoding: 'utf8', timeout: 30000, env: { HOME: temp, TMPDIR: temp, XDG_RUNTIME_DIR: runtime, PATH: '/usr/bin:/bin' },
        });
        assert.ifError(run.error);
        assert.equal(run.status, 0, run.stderr);
        assert.ok(run.stdout.split('\n').includes(pass), run.stdout + run.stderr);
        console.log(pass);
    }
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}
