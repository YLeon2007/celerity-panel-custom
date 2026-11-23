'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const { handler } = require('../../routes/panel/rebuildRelayInstallProgress');
const { progressWire } = require('../rebuildInstallProgressWire');
const { publicProgress } = require('../rebuildInstallProgress');
const id = 'a'.repeat(24), at = new Date('2026-01-01T00:00:00.000Z');
const progress = (stage, percent) => ({ stage, percent, at });

test('typed projection and schema do not coerce, leak fields or announce false completion', () => {
    const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
    for (const p of [progress('no-such-stage', 10), progress('reserve', '10'), progress('reserve', 11),
        { ...progress('reserve', 10), at: at.toISOString() }, { ...progress('reserve', 10), data: 'secret-fixture' }]) {
        assert.equal(publicProgress({ status: 'installing', installProgress: p }), null);
        assert.ok(new State({ node: id, installProgress: p }).validateSync());
    }
    assert.equal(new State({ node: id, installProgress: progress('reserve', 10) }).validateSync(), undefined);
    assert.equal(publicProgress({ status: 'installing', installProgress: progress('installed', 100) }), null);
    assert.equal(publicProgress({ status: 'not_installed', installProgress: progress('unknown', 10) }), null);
    assert.deepEqual(publicProgress({ status: 'installed', installProgress: progress('installed', 100) }),
        { stage: 'installed', percent: 100, at: at.toISOString() });
});

test('progress endpoint is a session-only read with an exact ID and an allowlisted payload', async () => {
    let reads = 0;
    const action = handler(async found => {
        reads++; assert.equal(found, id);
        return { status: 'installing', installProgress: progress('preparePackages', 30), backupId: 'private-fixture' };
    });
    const request = { method: 'GET', params: { id }, sessionID: 'fixture', session: { authenticated: true }, url: '/progress' };
    let status = 200, reply;
    const res = { set() { return this; }, status(value) { status = value; return this; }, end() {}, json(value) { reply = value; } };
    for (const [overrides, expected] of [[{ session: undefined }, 403], [{ method: 'POST' }, 405], [{ url: '/progress?' }, 400],
        [{ params: { id: id + '\n' } }, 400]]) {
        await action({ ...request, ...overrides }, res); assert.equal(status, expected);
    }
    assert.equal(reads, 0);
    await action(request, res);
    assert.equal(reads, 1);
    assert.deepEqual(reply, { nodeId: id, installProgress: { stage: 'preparePackages', percent: 30, at: at.toISOString() } });
});

test('only bounded, ordered, action-scoped SSH progress is consumed', () => {
    const marks = [];
    const wire = progressWire('prepare-packages', mark => marks.push(mark));
    for (const chunk of ['DIRECT_PROG', 'RESS unpacking\nDIRECT_PROGRESS settingUp\n', 'DIRECT_PROGRESS unpacking\n', 'fake-private-stdout']) {
        wire.tap(Buffer.from(chunk));
    }
    assert.deepEqual(marks, ['unpacking', 'settingUp']);
    assert.equal(wire.strip('DIRECT_PROGRESS unpacking\nDIRECT_PROGRESS settingUp\nDIRECT_UNCERTAIN_PACKAGE_SERVICES_UNSAFE\n'),
        'DIRECT_UNCERTAIN_PACKAGE_SERVICES_UNSAFE\n');
    assert.equal(wire.strip('DIRECT_PROGRESS restart\n'), 'DIRECT_PROGRESS restart\n');
    assert.equal(wire.strip('DIRECT_PROGRESS settingUp\nDIRECT_PROGRESS unpacking\n'), 'DIRECT_PROGRESS unpacking\n');
    const long = progressWire('install', mark => marks.push(mark));
    long.tap(Buffer.alloc(257)); long.tap('DIRECT_PROGRESS restart\n');
    assert.equal(marks.length, 2);
});

test('local progress UI polls GET at 2 s only while its POST owner is active', async () => {
    let tick, cleared = 0, read, payload;
    const label = {}, bar = {}, page = { querySelector: () => root };
    const url = `/panel/rebuild/relays/${id}/l2tp/install/progress`;
    const root = { hidden: true, isConnected: true, dataset: { progressUrl: url,
        progressWords: JSON.stringify({ preflight: 'Preflight', preparePackages: 'Packages', unknown: 'Unknown' }) },
        querySelector: q => q === 'progress' ? bar : label };
    const window = {};
    vm.runInNewContext(readFileSync(join(__dirname, '../../../public/js/rebuild-l2tp-install-progress.js'), 'utf8'), {
        window, AbortController, setInterval: (callback, delay) => { assert.equal(delay, 2000); tick = callback; return 17; },
        clearInterval: timer => { assert.equal(timer, 17); cleared++; },
        fetch: async (path, options) => { assert.equal(path, url); read = options; return { ok: true, json: async () => payload }; },
    });
    const stop = window.rebuildL2tpInstallProgress.start(page, id);
    assert.equal(root.hidden, false);
    assert.equal(label.textContent, 'Preflight');
    payload = { nodeId: id, installProgress: { stage: 'preparePackages', percent: 45, at: at.toISOString() } };
    await tick();
    assert.equal(read.method, 'GET');
    assert.equal(read.cache, 'no-store');
    assert.equal(bar.value, 45);
    payload.installProgress.percent = 30;
    await tick();
    assert.equal(bar.value, 45);
    payload.installProgress = { stage: 'installed', percent: 100, at: at.toISOString() };
    await tick();
    assert.equal(bar.value, 45, 'the synchronous POST owns completion');
    stop();
    assert.equal(read.signal.aborted, true);
    assert.equal(cleared, 1);
    assert.equal(root.hidden, true);
});

for (const [locale, topology] of [['ru', 'Сначала создайте и примените связь релея с бриджем'],
    ['en', 'First create and apply a relay-to-bridge link']]) test(`install progress and topology refusal: ${locale}`, () => {
    const { rebuildL2tp } = require(`../../locales/${locale}.json`);
    assert.equal(rebuildL2tp.installChecks.REBUILD_LINKS_NOT_APPLIED, topology);
    for (const field of ['preflight', 'reserve', 'preparePackages', 'prepare', 'install', 'restart', 'verify', 'unknown']) {
        assert.equal(typeof rebuildL2tp.installProgress[field], 'string');
    }
});


test('Apply MAIN readback fails closed on bytes different from the candidate pin', async () => {
    const { createTransport, profileBytes, profileSha256 } = require('../rebuildTransport');
    const profile = { inbounds: [], outbounds: [], routing: { rules: [] } };
    let bytes = profileBytes(profile);
    const pin = profileSha256(bytes);
    const SSH = class {
        async connect() {}
        disconnect() {}
        async exec() { return { code: 0, stdout: bytes, stderr: '' }; }
    };
    const transport = createTransport({}, SSH);
    try {
        assert.deepEqual(await transport.read('main', pin), profile);
        bytes += '\n';
        assert.deepEqual(await transport.read('main'), profile);
        await assert.rejects(transport.read('main', pin), { code: 'REBUILD_READBACK_MISMATCH' });
    } finally { await transport.close(); }
});
