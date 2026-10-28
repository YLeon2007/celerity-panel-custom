'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const fs = require('node:fs');
const path = require('node:path');
process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
const generator = require('../configGenerator');
const ROOT = path.resolve(__dirname, '..');
const SOURCE = '066a4f1905bd15d92be675f3';
const BRIDGE = '69f3948451e5c2bce1edd8a3';
const TARGET = '6ae13ae24bc4b4e3e44e65c6';
const BASE = '6a365c01ae589c8705c9c803';
const MAIN = '/usr/local/etc/xray/config.json';
const TRANSIT = '/usr/local/etc/xray-bridge/config.json';
function load(file, replacements) {
    const filename = path.join(ROOT, file);
    const mod = new Module(filename, module);
    mod.filename = filename; mod.paths = Module._nodeModulePaths(ROOT);
    mod.require = id => Object.hasOwn(replacements, id) ? replacements[id] : Module.prototype.require.call(mod, id);
    mod._compile(fs.readFileSync(filename, 'utf8'), filename);
    return mod.exports;
}
function query(value) {
    return { populate() { return this; }, setOptions() { return this; }, select() { return this; },
        lean: async () => structuredClone(value), then(resolve, reject) { return Promise.resolve(structuredClone(value)).then(resolve, reject); } };
}
function fixture(t, options = {}) {
    const oldEnv = { ...process.env };
    Object.assign(process.env, { PANEL_DOMAIN: 'lm1.infograd.online', L2TP_EXECUTION_ENABLED: 'true',
        L2TP_MIGRATIONS_ENABLED: 'true', L2TP_PRODUCTION_EXECUTION_ENABLED: 'true' });
    t.after(() => { for (const key of Object.keys(process.env)) if (!(key in oldEnv)) delete process.env[key]; Object.assign(process.env, oldEnv); });
    const nodes = {
        [SOURCE]: { _id: SOURCE, ip: '192.0.2.1', type: 'xray', active: true, cascadeRole: 'relay', ssh: { password: 'fixture' },
            xray: { inboundTag: 'vless-in', extraInbounds: [{ inboundTag: 'extra-in' }], agentToken: 'must-not-use' } },
        [BRIDGE]: { _id: BRIDGE, ip: '192.0.2.2', type: 'hysteria', active: true, cascadeRole: 'bridge', ssh: { password: 'fixture' } },
    };
    const otherPortal = { _id: '6a36589bae589c8705c9c4dd', ip: '192.0.2.3' };
    const target = { _id: TARGET, active: true, status: 'pending', mode: 'reverse', portalNode: nodes[SOURCE], bridgeNode: nodes[BRIDGE],
        tunnelPort: 10096, tunnelUuid: 'caea5a59-30e2-43fe-bd01-269410c4a995' };
    const baseline = { ...target, _id: BASE, status: 'online', portalNode: otherPortal, tunnelPort: 10086,
        tunnelUuid: 'baa54cac-323a-4a0a-8cb2-e8f605980fe0' };
    const links = [target, baseline];
    const main = { log: { loglevel: 'warning' }, inbounds: [
        { tag: 'vless-in', port: 443, protocol: 'vless', settings: { clients: [{ id: 'existing-user', email: 'private-user' }] } },
        { tag: 'extra-in', port: 8443, protocol: 'vless', settings: { clients: [{ id: 'other-user' }] } },
    ], outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: { domainStrategy: 'IPIfNonMatch', rules: [{ type: 'field', ip: ['geoip:private'], outboundTag: 'block' }] } };
    const files = new Map([[`${SOURCE}:${MAIN}`, JSON.stringify(main)],
        [`${SOURCE}:${TRANSIT}`, JSON.stringify({ orphan: 'preserve-this-byte-for-byte' })],
        [`${BRIDGE}:${TRANSIT}`, generator.generateCombinedBridgeConfig([baseline])]]);
    const original = new Map(files);
    const locks = new Map(), events = [], commands = [], writes = [];
    const state = { _id: 'singleton', revision: 17 };
    const model = {
        async create(row) { events.push(['acquire', String(row.node), row.leaseUntil.getTime() - Date.now()]);
            if (options.conflict === String(row.node) || locks.has(String(row.node))) throw Object.assign(new Error('conflict'), { code: 11000 });
            locks.set(String(row.node), { ...row }); return row; },
        findOne({ node }) { return query(locks.get(String(node))); },
        async deleteOne(filter) { const row = locks.get(String(filter.node));
            assert.ok(row); for (const [key, value] of Object.entries(filter)) assert.equal(String(row[key]), String(value));
            events.push(['release', String(filter.node)]); locks.delete(String(filter.node)); return { deletedCount: 1 }; },
    };
    const held = load('classicNodeConfigWrite.js', {
        '../modules/relay-l2tp/models/nodeOperationLockModel': model,
        './topologyConfigOwnership': { topologyManagesNodeConfig: async node => !!options.ownerVeto && String(node._id) === options.ownerVeto },
    });
    const linkModel = {
        findById: id => query(links.find(row => row._id === String(id))),
        find(filter) {
            const ids = filter._id?.$in?.map(String);
            return query(links.filter(row => (!ids || ids.includes(row._id)) && (!filter.active || row.active)
                && (!filter.status?.$in || filter.status.$in.includes(row.status))
                && (!filter.$or || filter.$or.some(term => term._id === row._id || term.status?.$in.includes(row.status)))));
        },
        async updateOne(filter, update) { const row = links.find(row => row._id === String(filter._id));
            assert.ok(row); Object.assign(row, update.$set); return { acknowledged: true, matchedCount: 1 }; },
    };
    class SSH {
        constructor(node) { this.node = node; }
        async connect() { events.push(['connect', this.node._id]); assert.equal(locks.size, 2); }
        disconnect() { events.push(['disconnect', this.node._id]); }
        async exec(command, execOptions = {}) {
            const id = this.node._id;
            assert.equal(locks.size, 2, 'both exact generations must span all remote calls');
            commands.push({ id, command, options: execOptions });
            const injected = await options.fault?.({ id, command, options: execOptions, files, locks, events });
            if (injected) return injected;
            const marker = command.match(/C3_SCOPED_DONE_[a-f0-9]+/);
            assert.ok(marker, 'each call needs a fresh checked completion receipt');
            let stdout = '';
            if (command.includes('C3_READ_CONFIG')) {
                const configPath = command.match(/\/usr\/local\/etc\/xray(?:-bridge)?\/config\.json(?:\.[a-f0-9]+\.stage)?/)[0];
                stdout = files.get(`${id}:${configPath}`) ?? 'C3_CONFIG_ABSENT';
            } else if (command.includes('systemctl show')) {
                const configPath = command.includes('xray-bridge') ? TRANSIT : MAIN;
                stdout = `ActiveState=active\nNeedDaemonReload=no\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${configPath} ; }\n`;
            } else if (execOptions.stdin !== undefined) {
                const stage = command.match(/\/usr\/local\/etc\/xray(?:-bridge)?\/[^'\s]+\.stage/)[0];
                files.set(`${id}:${stage}`, String(execOptions.stdin)); writes.push([id, stage]);
            } else if (command.includes('mv --')) {
                const stage = command.match(/\/usr\/local\/etc\/xray(?:-bridge)?\/[^'\s]+\.stage/)[0];
                const configPath = stage.replace(/\.[a-f0-9]+\.stage$/, '');
                files.set(`${id}:${configPath}`, files.get(`${id}:${stage}`)); files.delete(`${id}:${stage}`);
            } else if (command.includes('ss -tnH')) stdout = '0 0 192.0.2.1:10096 192.0.2.2:49900\n';
            return { code: 0, stdout: `${stdout}\n${marker[0]}\n`, stderr: '' };
        }
    }
    const cascade = load('cascadeService.js', {
        '../models/cascadeLinkModel': linkModel, '../models/hyNodeModel': { findById: id => query(nodes[String(id)]) },
        '../models/settingsModel': {}, './nodeSSH': SSH, './classicNodeConfigWrite': held,
        '../modules/relay-l2tp/models/cascadeTopologyStateModel': { findById: () => query(state) },
        '../modules/relay-l2tp/models/relayL2tpStateModel': { exists: () => query(options.l2tp ? { _id: 'installed' } : null) },
        './cacheService': {}, '../utils/logger': { info() {}, error() {}, warn() {} }, './webhookService': {},
        './topologyConfigOwnership': { APPLIED_LINK_STATUSES: ['staged', 'deployed', 'online'], topologyManagesNodeConfig: async () => false, usesTestTopologyConfig: () => false },
        '../modules/relay-l2tp/services/legacyCascadeUndeploy': { trackLegacyCascadeUndeploy: work => work() },
    });
    return { cascade, held, locks, events, commands, writes, original, files, nodes, target, baseline, links, state, main,
        run: args => cascade.deployScopedClassicLink({ linkId: TARGET, expectedTopologyRevision: 17, baselineLinkIds: [BASE], ...args }) };
}

function physicalForward(f) {
    delete f.nodes[SOURCE].xray.extraInbounds;
    const main = structuredClone(f.main);
    main.inbounds = [main.inbounds[0], { tag: 'cascade-pilot-main', listen: '127.0.0.1', port: 18019,
        protocol: 'socks', settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' } },
        { tag: 'unrelated-service', port: 18020, protocol: 'socks' }];
    const forward = { inbounds: [], outbounds: [], routing: { rules: [] } };
    generator.applyForwardChain(forward, [f.target], ['vless-in']);
    main.outbounds.push(...forward.outbounds, { tag: 'cascade-pilot-main', protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: 18019 }] } });
    main.routing.rules.unshift(...['vless-in', 'cascade-pilot-main'].map(tag => ({ type: 'field', inboundTag: [tag], outboundTag: `fwd-${TARGET.slice(-8)}` })));
    const targetMain = structuredClone(f.main);
    generator.applyForwardHopInbound(targetMain, [f.target]);
    f.files.set(`${SOURCE}:${MAIN}`, JSON.stringify(main));
    f.files.set(`${BRIDGE}:${MAIN}`, JSON.stringify(targetMain));
    f.files.set(`${SOURCE}:${TRANSIT}`, JSON.stringify({ reverse: { bridges: [{ tag: 'old-test', domain: 'test.invalid' }] },
        inbounds: [{ tag: 'old-test', port: 12345 }], outbounds: [{ tag: 'old-test', protocol: 'freedom' }], routing: { rules: [] } }));
    return { main, targetMain, orphan: f.files.get(`${SOURCE}:${TRANSIT}`) };
}

test('actual forward migration retires only exact owned fragments across three staged profiles', async t => {
    const f = fixture(t), before = physicalForward(f);
    f.links.push({ ...f.baseline, _id: '1'.repeat(24), portalNode: { _id: '2'.repeat(24) }, bridgeNode: { _id: '3'.repeat(24) } });
    const result = await f.run();
    assert.equal(result.success, true);
    assert.equal(result.receipt.profiles.length, 3);
    const main = JSON.parse(f.files.get(`${SOURCE}:${MAIN}`));
    assert.deepEqual(main.inbounds.slice(0, 3), before.main.inbounds);
    assert.deepEqual(main.outbounds, before.main.outbounds.filter(row => row.tag !== `fwd-${TARGET.slice(-8)}`));
    const clientRule = main.routing.rules.find(row => row.outboundTag === `portal-${TARGET.slice(-8)}` && !row.domain);
    assert.deepEqual(clientRule.inboundTag, ['vless-in', 'cascade-pilot-main']);
    assert.equal(clientRule.inboundTag.includes('unrelated-service'), false);
    const retired = structuredClone(before.targetMain);
    retired.inbounds = retired.inbounds.filter(row => row.tag !== `fwd-hop-${TARGET.slice(-8)}`);
    retired.routing.rules = retired.routing.rules.filter(row => !row.inboundTag?.includes(`fwd-hop-${TARGET.slice(-8)}`));
    assert.deepEqual(JSON.parse(f.files.get(`${BRIDGE}:${MAIN}`)), retired);
    assert.equal(f.files.get(`${SOURCE}:${TRANSIT}`), before.orphan);
    const firstRestart = f.commands.findIndex(row => row.command.includes('mv --'));
    assert.equal(f.commands.slice(0, firstRestart).filter(row => row.command.includes('run -test')).length, 3);
    const oldCombined = JSON.parse(f.original.get(`${BRIDGE}:${TRANSIT}`));
    const combined = JSON.parse(f.files.get(`${BRIDGE}:${TRANSIT}`));
    for (const row of oldCombined.routing.rules) assert.ok(combined.routing.rules.some(item => JSON.stringify(item) === JSON.stringify(row)));
});

test('matching reverse replay including pending same-link PUT performs no remote mutations', async t => {
    const f = fixture(t); physicalForward(f);
    await f.run();
    const bytes = new Map(f.files);
    for (const status of ['deployed', 'pending']) {
        f.target.status = status;
        const start = f.commands.length;
        const result = await f.run();
        assert.equal(result.receipt.profiles.length, 3);
        assert.equal(result.receipt.tunnelEstablished, true);
        assert.deepEqual(f.files, bytes);
        assert.equal(f.commands.slice(start).some(row => /cat >|mv --|ufw allow|run -test/.test(row.command)), false);
        assert.ok(f.commands.slice(start).some(row => row.command.includes('ss -tnH')));
    }
});

for (const kind of ['outbound', 'hop', 'route']) {
    test(`corrupted old forward ${kind} refuses before writes`, async t => {
        const f = fixture(t); physicalForward(f);
        const key = `${kind === 'hop' ? BRIDGE : SOURCE}:${MAIN}`;
        const config = JSON.parse(f.files.get(key));
        if (kind === 'outbound') config.outbounds.find(row => row.tag === `fwd-${TARGET.slice(-8)}`).settings.vnext[0].users[0].id = 'wrong';
        if (kind === 'hop') config.inbounds.find(row => row.tag === `fwd-hop-${TARGET.slice(-8)}`).settings.clients[0].id = 'wrong';
        if (kind === 'route') config.routing.rules[0].domain = ['foreign'];
        f.files.set(key, JSON.stringify(config));
        await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_OLD_FORWARD_MISMATCH' });
        assert.equal(f.writes.length, 0);
        assert.equal(f.commands.some(row => /mv --|ufw allow/.test(row.command)), false);
    });
}

test('touching offline dependency refuses before SSH and is not treated as missing', async t => {
    const f = fixture(t); f.baseline.status = 'offline';
    await assert.rejects(f.run({ baselineLinkIds: [] }), { code: 'CLASSIC_SCOPED_OFFLINE_DEPENDENCY_UNSUPPORTED' });
    assert.equal(f.commands.length, 0);
});

for (const kind of ['duplicate', 'credential', 'unknown-port']) {
    test(`reverse replay refuses ${kind} collision before any remote mutation`, async t => {
        const f = fixture(t); physicalForward(f); await f.run();
        const config = JSON.parse(f.files.get(`${SOURCE}:${MAIN}`));
        const connector = config.inbounds.find(row => row.tag === `bridge-conn-${TARGET.slice(-8)}`);
        if (kind === 'duplicate') config.inbounds.push(structuredClone(connector));
        if (kind === 'credential') connector.settings.clients[0].id = 'foreign';
        if (kind === 'unknown-port') config.inbounds.push({ tag: 'foreign', port: 10096, protocol: 'socks' });
        f.files.set(`${SOURCE}:${MAIN}`, JSON.stringify(config));
        const start = f.commands.length;
        await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_LISTENER_OR_TAG_CONFLICT' });
        assert.equal(f.commands.slice(start).some(row => /cat >|mv --|ufw allow/.test(row.command)), false);
    });
}

test('third profile validation failure cannot restart either earlier profile', async t => {
    const f = fixture(t, { fault({ id, command }) {
        if (id === BRIDGE && command.includes('run -test -config /usr/local/etc/xray/config.json.')) {
            return { code: 1, stdout: '', stderr: 'invalid third payload' };
        }
    } });
    physicalForward(f);
    await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_COMPLETION_UNCERTAIN' });
    assert.equal(f.writes.length, 3);
    assert.equal(f.commands.some(row => row.command.includes('mv --')), false);
    assert.equal(f.locks.size, 2);
});

test('orphan source PID drift is refused without adopting or restarting that profile', async t => {
    let reads = 0;
    const f = fixture(t, { fault({ id, command }) {
        if (id !== SOURCE || !command.includes('systemctl show xray-bridge')) return;
        const marker = command.match(/C3_SCOPED_DONE_[a-f0-9]+/)[0];
        return { code: 0, stderr: '', stdout: `ActiveState=active\nNeedDaemonReload=no\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${TRANSIT} ; pid=${++reads === 1 ? 100 : 101} ; }\n\n${marker}\n` };
    } });
    await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_PHYSICAL_BASELINE_DRIFT' });
    assert.equal(f.writes.length, 0);
});

test('scoped entry refuses malformed input without remote effects', async t => {
    const f = fixture(t);
    await assert.rejects(f.run({ baselineLinkIds: [BASE, BASE] }), { code: 'CLASSIC_SCOPED_INPUT_INVALID' });
    assert.equal(f.commands.length, 0);
    assert.equal(f.locks.size, 0);
});

test('disabled existing fence authorization cannot silently take the unfenced classic path', async t => {
    const f = fixture(t);
    process.env.L2TP_PRODUCTION_EXECUTION_ENABLED = 'false';
    await assert.rejects(f.run(), { code: 'CLASSIC_CONFIG_WRITE_SCOPE_CLOSED' });
    assert.equal(f.commands.length, 0);
    assert.equal(f.locks.size, 0);
    assert.equal(f.events.some(row => row[0] === 'connect'), false);
});

test('scoped no-upstream reverse adds main portal and shared bridge without touching orphan transit or users', async t => {
    const f = fixture(t);
    const result = await f.run();
    assert.equal(result.success, true);
    assert.equal(result.remoteQuiescent, true);
    assert.equal(result.receipt.kind, 'classic-scoped-reverse');
    assert.equal(result.receipt.linkId, TARGET);
    assert.equal(result.receipt.topologyRevision, 17);
    assert.equal(result.operationId, undefined, 'not a fabricated native operation');
    assert.deepEqual(f.events.filter(row => row[0] === 'acquire').map(row => row[1]), [SOURCE, BRIDGE].sort());
    assert.ok(f.events.filter(row => row[0] === 'acquire').every(row => row[2] > 110000 && row[2] <= 120000));
    assert.equal(f.locks.size, 0);
    assert.equal(f.files.get(`${SOURCE}:${TRANSIT}`), f.original.get(`${SOURCE}:${TRANSIT}`));
    const main = JSON.parse(f.files.get(`${SOURCE}:${MAIN}`));
    assert.deepEqual(main.inbounds.slice(0, 2), f.main.inbounds);
    assert.deepEqual(main.outbounds, f.main.outbounds);
    assert.equal(main.reverse.portals[0].tag, `portal-${TARGET.slice(-8)}`);
    assert.ok(main.routing.rules.some(row => row.inboundTag?.includes('extra-in') && row.outboundTag === `portal-${TARGET.slice(-8)}`));
    const bridge = JSON.parse(f.files.get(`${BRIDGE}:${TRANSIT}`));
    assert.deepEqual(bridge.reverse.bridges.map(row => row.tag).sort(), [`bridge-${BASE.slice(-8)}`, `bridge-${TARGET.slice(-8)}`].sort());
    const old = JSON.parse(f.original.get(`${BRIDGE}:${TRANSIT}`));
    for (const outbound of old.outbounds) assert.ok(bridge.outbounds.some(row => JSON.stringify(row) === JSON.stringify(outbound)));
    for (const rule of old.routing.rules) assert.ok(bridge.routing.rules.some(row => JSON.stringify(row) === JSON.stringify(rule)));
    assert.equal(f.target.status, 'deployed');
    assert.equal(f.commands.some(row => row.command.includes('|| true')), false);
    assert.equal(f.commands.some(row => /install-release|daemon-reload|enable xray/.test(row.command)), false);
});

for (const status of ['staged', 'deployed', 'online']) {
    test(`preserves explicitly confirmed ${status} baseline`, async t => {
        const f = fixture(t); f.baseline.status = status;
        assert.equal((await f.run()).remoteQuiescent, true);
        assert.equal(f.baseline.status, status);
    });
}
test('ordinary confirmed-link health and node monitor updates do not change admitted config scope', async t => {
    let changed = false, f;
    f = fixture(t, { fault() {
        if (changed) return;
        changed = true;
        f.baseline.status = 'deployed'; f.baseline.lastHealthCheck = new Date(); f.baseline.latencyMs = 123;
        f.nodes[SOURCE].onlineUsers = 9; f.nodes[BRIDGE].status = 'online';
    } });
    assert.equal((await f.run()).remoteQuiescent, true);
    assert.equal(f.baseline.status, 'deployed');
});

test('preserves legacy single-bridge tags while adding the new combined tunnel', async t => {
    const f = fixture(t);
    const bytes = generator.generateBridgeConfig(f.baseline, f.baseline.portalNode);
    f.files.set(`${BRIDGE}:${TRANSIT}`, bytes);
    await f.run();
    const after = JSON.parse(f.files.get(`${BRIDGE}:${TRANSIT}`)), before = JSON.parse(bytes);
    for (const row of before.reverse.bridges) assert.ok(after.reverse.bridges.some(item => JSON.stringify(item) === JSON.stringify(row)));
    for (const row of before.outbounds) assert.ok(after.outbounds.some(item => JSON.stringify(item) === JSON.stringify(row)));
    for (const row of before.routing.rules) assert.ok(after.routing.rules.some(item => JSON.stringify(item) === JSON.stringify(row)));
});

test('preserves every confirmed shared-bridge tunnel and custom profile sections', async t => {
    const f = fixture(t);
    const second = { ...f.baseline, _id: '4a365c01ae589c8705c9c803', tunnelPort: 10087,
        portalNode: { _id: '4a36589bae589c8705c9c4dd', ip: '192.0.2.4' }, status: 'staged' };
    f.links.push(second);
    const old = JSON.parse(generator.generateCombinedBridgeConfig([f.baseline, second]));
    old.log.access = '/var/log/xray-bridge/access.log'; old.policy = { levels: { 0: { handshake: 4 } } };
    f.files.set(`${BRIDGE}:${TRANSIT}`, JSON.stringify(old));
    await f.run({ baselineLinkIds: [BASE, second._id] });
    const after = JSON.parse(f.files.get(`${BRIDGE}:${TRANSIT}`));
    assert.equal(after.reverse.bridges.length, 3);
    assert.deepEqual(after.log, old.log); assert.deepEqual(after.policy, old.policy);
    for (const row of old.routing.rules) assert.ok(after.routing.rules.some(item => JSON.stringify(item) === JSON.stringify(row)));
    assert.equal(second.status, 'staged');
});

for (const status of ['pending', 'error']) {
    test(`never adds unrelated ${status} links to generated configs`, async t => {
        const f = fixture(t);
        const foreign = { ...f.target, _id: '5ae13ae24bc4b4e3e44e65c7', tunnelPort: 11111, status };
        f.links.push(foreign);
        await f.run();
        for (const [key, bytes] of f.files) if (!key.endsWith('.stage')) assert.equal(bytes.includes(foreign._id.slice(-8)), false);
    });
}
for (const [kind, code, modify] of [
    ['revision', 'CLASSIC_SCOPED_REVISION_CONFLICT', f => { f.state.revision++; }],
    ['missing baseline', 'CLASSIC_SCOPED_BASELINE_CONFLICT', f => { f.baseline.active = false; }],
    ['upstream', 'CLASSIC_SCOPED_REVERSE_UPSTREAM_UNSUPPORTED', f => { f.baseline.bridgeNode = f.nodes[SOURCE]; }],
    ['forward dependency', 'CLASSIC_SCOPED_FORWARD_DEPENDENCY_UNSUPPORTED', f => { f.baseline.mode = 'forward'; }],
    ['shared source', 'CLASSIC_SCOPED_SHARED_SOURCE_UNSUPPORTED', f => { f.baseline.portalNode = f.nodes[SOURCE]; }],
    ['transit bridge', 'CLASSIC_SCOPED_TRANSIT_BRIDGE_UNSUPPORTED', f => { f.baseline.portalNode = f.nodes[BRIDGE]; }],
    ['no SSH', 'CLASSIC_SCOPED_ENDPOINT_UNSUPPORTED', f => { delete f.nodes[SOURCE].ssh; }],
]) {
    test(`refuses ${kind} before SSH dispatch`, async t => {
        const f = fixture(t); modify(f);
        await assert.rejects(f.run(), { code });
        assert.equal(f.commands.length, 0);
        assert.equal(f.events.some(row => row[0] === 'connect'), false);
        assert.equal(f.locks.size, 2);
    });
}
for (const [name, options, count] of [
    ['first lock conflict', { conflict: SOURCE }, 0], ['second lock conflict', { conflict: BRIDGE }, 1],
    ['owner veto', { ownerVeto: BRIDGE }, 2], ['L2TP state', { l2tp: true }, 2],
]) {
    test(`${name} cannot dispatch or release the acquired generation`, async t => {
        const f = fixture(t, options);
        await assert.rejects(f.run());
        assert.equal(f.commands.length, 0);
        assert.equal(f.events.some(row => row[0] === 'connect'), false);
        assert.equal(f.locks.size, count);
        assert.equal(f.events.some(row => row[0] === 'release'), false);
    });
}
for (const step of ['C3_READ_CONFIG', 'cat >', 'run -test', 'ufw allow', 'mv --', 'systemctl show', 'ss -tnH']) {
    for (const failure of ['nonzero', 'missing-exit', 'missing-receipt', 'throw']) {
        test(`${step} ${failure} retains both locks and never retries`, async t => {
            let failed = false;
            const f = fixture(t, { fault({ command }) {
                if (failed || !command.includes(step)) return;
                failed = true;
                if (failure === 'throw') throw new Error('SECRET: do not expose remote text');
                const marker = command.match(/C3_SCOPED_DONE_[a-f0-9]+/)[0];
                return { code: failure === 'nonzero' ? 1 : failure === 'missing-exit' ? undefined : 0,
                    stdout: failure === 'missing-receipt' ? '' : `\n${marker}\n`, stderr: 'SECRET' };
            } });
            await assert.rejects(f.run(), error => error.code === 'CLASSIC_SCOPED_COMPLETION_UNCERTAIN' && !error.message.includes('SECRET'));
            assert.equal(failed, true);
            assert.equal(f.locks.size, 2);
            assert.equal(f.events.some(row => row[0] === 'release'), false);
            assert.equal(f.target.status, 'pending');
        });
    }
}

test('refuses an unrepresented shared-bridge tunnel instead of activating foreign pending config', async t => {
    const f = fixture(t);
    const config = JSON.parse(f.files.get(`${BRIDGE}:${TRANSIT}`));
    config.reverse.bridges.push({ tag: 'bridge-foreign', domain: 'foreign.reverse.tunnel.internal' });
    f.files.set(`${BRIDGE}:${TRANSIT}`, JSON.stringify(config));
    await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_UNREPRESENTED_BRIDGE_CONFIG' });
    assert.equal(f.writes.length, 0);
    assert.equal(f.locks.size, 2);
});

test('refuses a listener collision in the preserved orphan source transit profile', async t => {
    const f = fixture(t);
    f.files.set(`${SOURCE}:${TRANSIT}`, JSON.stringify({ inbounds: [{ tag: 'orphan', port: 10096 }], outbounds: [], routing: { rules: [] } }));
    await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_LISTENER_OR_TAG_CONFLICT' });
    assert.equal(f.writes.length, 0);
});

test('loaded service config mismatch cannot be hidden by matching unit-file text', async t => {
    const f = fixture(t, { fault({ command }) {
        if (!command.includes('systemctl show xray ')) return;
        const marker = command.match(/C3_SCOPED_DONE_[a-f0-9]+/)[0];
        return { code: 0, stderr: '', stdout: `ActiveState=active\nNeedDaemonReload=no\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config /wrong/config.json ; }\n# stale unit\nExecStart=/usr/local/bin/xray run -config ${MAIN}\n\n${marker}\n` };
    } });
    await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_SERVICE_LAYOUT_UNSUPPORTED' });
    assert.equal(f.writes.length, 0);
});

test('foreign forward fragments in main cannot be reactivated during scoped restart', async t => {
    const f = fixture(t);
    const main = JSON.parse(f.files.get(`${SOURCE}:${MAIN}`));
    main.outbounds.push({ tag: 'fwd-foreign', protocol: 'vless', settings: {} });
    f.files.set(`${SOURCE}:${MAIN}`, JSON.stringify(main));
    await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_UNREPRESENTED_MAIN_CONFIG' });
    assert.equal(f.writes.length, 0);
});

test('an unrelated established peer is not target tunnel proof', async t => {
    const realTimeout = global.setTimeout;
    t.mock.method(global, 'setTimeout', (fn, ms, ...args) => realTimeout(fn, ms === 500 ? 0 : ms, ...args));
    const f = fixture(t, { fault({ command }) {
        if (!command.includes('ss -tnH')) return;
        const marker = command.match(/C3_SCOPED_DONE_[a-f0-9]+/)[0];
        return { code: 0, stderr: '', stdout: `0 0 192.0.2.1:10096 198.51.100.55:40000\n\n${marker}\n` };
    } });
    await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_TUNNEL_UNCONFIRMED' });
    assert.equal(f.locks.size, 2);
    assert.equal(f.target.status, 'pending');
});

test('a timed-out foreground writer stays fenced even after late completion', async t => {
    const realTimeout = global.setTimeout;
    t.mock.method(global, 'setTimeout', (fn, ms, ...args) => realTimeout(fn, ms === 15000 ? 10 : ms, ...args));
    let complete, entered;
    const ready = new Promise(resolve => { entered = resolve; });
    const f = fixture(t, { fault({ command, files }) {
        if (!command.includes('cat >')) return;
        entered();
        return new Promise(resolve => { complete = () => {
            files.set('late-writer-evidence', 'writer completed after caller timeout');
            const marker = command.match(/C3_SCOPED_DONE_[a-f0-9]+/)[0];
            resolve({ code: 0, stdout: `\n${marker}\n`, stderr: '' });
        }; });
    } });
    const run = f.run();
    await ready;
    const exact = structuredClone([...f.locks]);
    await assert.rejects(run, { code: 'CLASSIC_SCOPED_COMPLETION_UNCERTAIN' });
    assert.deepEqual([...f.locks], exact);
    complete(); await new Promise(resolve => setImmediate(resolve));
    assert.equal(f.files.has('late-writer-evidence'), true);
    assert.deepEqual([...f.locks], exact);
    assert.equal(f.events.some(row => row[0] === 'release'), false);
});

test('lost exact generation after dispatch cannot authorize either release', async t => {
    let replaced = false;
    const f = fixture(t, { fault({ command, locks }) {
        if (replaced || !command.includes('cat >')) return;
        replaced = true;
        locks.get(SOURCE).generation = 'foreign-winner';
    } });
    await assert.rejects(f.run(), { code: 'CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN' });
    assert.equal(f.locks.get(SOURCE).generation, 'foreign-winner');
    assert.equal(f.locks.size, 2);
    assert.equal(f.events.some(row => row[0] === 'release'), false);
});

for (const leaseMs of [0, -1, 999, 120001, 1.5, Infinity, NaN]) {
    test(`classic server lease refuses invalid bound ${String(leaseMs)}`, async t => {
        const f = fixture(t);
        await assert.rejects(f.held.withClassicNodeConfigWrite({ nodeId: SOURCE, kind: 'test', leaseMs },
            async () => assert.fail('invalid lease must not invoke callback')), { code: 'CLASSIC_CONFIG_WRITE_INVALID' });
        assert.equal(f.locks.size, 0);
    });
}

test('post-bridge source service drift is caught by final whole-scope readback', async t => {
    let bridgeRestarted = false;
    const f = fixture(t, { fault({ id, command }) {
        if (id === BRIDGE && command.includes('mv --')) bridgeRestarted = true;
        if (!bridgeRestarted || id !== SOURCE || !command.includes('systemctl show xray ')) return;
        const marker = command.match(/C3_SCOPED_DONE_[a-f0-9]+/)[0];
        return { code: 0, stderr: '', stdout: `ActiveState=failed\nNeedDaemonReload=no\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config ${MAIN} ; }\n\n${marker}\n` };
    } });
    await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_CONFIG_READBACK_MISMATCH' });
    assert.equal(f.locks.size, 2);
    assert.equal(f.target.status, 'pending');
});

test('actual shell migrates three forward profiles then replays without restarting in a scratch root', async t => {
    // Real /bin/sh, timeout, stdin, cat, stat, chmod/chown and mv. Xray,
    // systemd and ss are explicit local stand-ins, not physical flow proof.
    const { spawnSync } = require('node:child_process');
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || '/home/leon/.hermes/cache/scratch', 'classic-scoped-shell-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const bin = path.join(root, 'bin'); fs.mkdirSync(bin);
    const script = (name, body) => { const file = path.join(bin, name); fs.writeFileSync(file, body, { mode: 0o700 }); return file; };
    const xray = script('xray', `#!/usr/bin/env node\nconst fs=require('node:fs'); const args=process.argv.slice(2); if(args.slice(0,3).join(' ')!=='run -test -config')process.exit(23); JSON.parse(fs.readFileSync(args[3],'utf8'));\n`);
    const systemctl = script('systemctl', `#!/bin/sh\nset -eu\ncase "$1" in\nshow) if test "$2" = xray; then file=${MAIN}; else file=${TRANSIT}; fi; printf 'ActiveState=active\\nNeedDaemonReload=no\\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -config %s ; }\\n' "$file";;\ncat) printf '# stable local unit\\n';;\nrestart) printf '%s\\n' "$2" >> '${root}/restarts';;\nis-active) test "$2" = --quiet;;\n*) exit 24;;\nesac\n`);
    const ss = script('ss', `#!/bin/sh\nprintf '0 0 192.0.2.1:10096 192.0.2.2:49900\\n'\n`);
    const f = fixture(t, { fault({ id, command, options }) {
        const local = command.replaceAll('/usr/local/etc', `${root}/${id}/etc`).replaceAll('/usr/local/bin/xray', xray)
            .replace(/\bsystemctl\b/g, systemctl).replace(/\bss -tnH/g, `${ss} -tnH`)
            .replaceAll('command -v ufw', 'false').replaceAll('command -v firewall-cmd', 'false');
        const result = spawnSync('/bin/sh', ['-c', local], { input: options.stdin, encoding: 'utf8', timeout: 15000 });
        return { code: result.status, stdout: result.stdout || '', stderr: result.stderr || '' };
    } });
    const forward = physicalForward(f);
    for (const [key, bytes] of f.files) {
        const [id, file] = key.split(':');
        const dest = `${root}/${id}${file.replace('/usr/local', '')}`;
        fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.writeFileSync(dest, bytes, { mode: 0o600 });
    }
    const result = await f.run();
    assert.equal(result.remoteQuiescent, true);
    assert.equal(fs.readFileSync(`${root}/${SOURCE}/etc/xray-bridge/config.json`, 'utf8'), forward.orphan);
    const main = JSON.parse(fs.readFileSync(`${root}/${SOURCE}/etc/xray/config.json`, 'utf8'));
    assert.deepEqual(main.inbounds.slice(0, 3), forward.main.inbounds);
    assert.equal(main.inbounds.at(-1).port, 10096);
    const bridge = JSON.parse(fs.readFileSync(`${root}/${BRIDGE}/etc/xray-bridge/config.json`, 'utf8'));
    assert.equal(bridge.reverse.bridges.length, 2);
    assert.equal(fs.readFileSync(`${root}/restarts`, 'utf8'), 'xray\nxray-bridge\nxray\n');
    f.target.status = 'pending';
    assert.equal((await f.run()).receipt.profiles.length, 3);
    assert.equal(fs.readFileSync(`${root}/restarts`, 'utf8'), 'xray\nxray-bridge\nxray\n');
    assert.equal(f.locks.size, 0);
});

test('real firewall shell refuses failed permanent change without reload or completion receipt', async t => {
    const { spawnSync } = require('node:child_process');
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || '/home/leon/.hermes/cache/scratch', 'classic-scoped-firewall-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const firewall = path.join(root, 'firewall-cmd');
    fs.writeFileSync(firewall, `#!/bin/sh\nprintf '%s\\n' "$1" >> '${root}/calls'\ncase "$1" in --permanent) exit 42;; *) exit 0;; esac\n`, { mode: 0o700 });
    const f = fixture(t, { fault({ command }) {
        if (!command.includes('ufw allow')) return;
        const local = command.replaceAll('command -v ufw', 'false').replaceAll('command -v firewall-cmd', 'true')
            .replace(/\bfirewall-cmd\b/g, firewall);
        const result = spawnSync('/bin/sh', ['-c', local], { encoding: 'utf8', timeout: 15000 });
        assert.equal(result.status, 42);
        assert.equal(result.stdout.includes('C3_SCOPED_DONE_'), false);
        return { code: result.status, stdout: result.stdout, stderr: result.stderr };
    } });
    await assert.rejects(f.run(), { code: 'CLASSIC_SCOPED_COMPLETION_UNCERTAIN' });
    assert.equal(fs.readFileSync(`${root}/calls`, 'utf8'), '--permanent\n');
    assert.equal(f.locks.size, 2);
    assert.equal(f.events.some(row => row[0] === 'release'), false);
});
