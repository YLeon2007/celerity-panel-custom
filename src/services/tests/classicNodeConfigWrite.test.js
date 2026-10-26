'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const Module = require('node:module');
const path = require('node:path');
const fs = require('node:fs');
const filename = path.resolve(__dirname, '../classicNodeConfigWrite.js');
const enabled = { PANEL_DOMAIN: 'test.infograd.online', L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
const NODE = '507f1f77bcf86cd799439011';

function fixture({ veto = false, rows = new Map(), createError, deleteError } = {}) {
    const events = [];
    const model = {
        async create(row) {
            events.push('acquire');
            if (createError) throw createError;
            if (rows.has(String(row.node))) throw Object.assign(new Error('duplicate'), { code: 11000 });
            rows.set(String(row.node), { ...row });
            return row;
        },
        findOne({ node }) { return { lean: async () => rows.get(String(node)) }; },
        async deleteOne(filter) {
            events.push('release');
            if (deleteError) throw deleteError;
            const row = rows.get(String(filter.node));
            if (!row || !Object.entries(filter).every(([key, value]) => String(row[key]) === String(value))) return { deletedCount: 0 };
            rows.delete(String(filter.node));
            return { deletedCount: 1 };
        },
    };
    const loaded = new Module(filename, module);
    loaded.filename = filename;
    loaded.paths = Module._nodeModulePaths(path.dirname(filename));
    loaded.require = id => {
        if (id.endsWith('/nodeOperationLockModel')) { events.push('model'); return model; }
        if (id === './topologyConfigOwnership') return { topologyManagesNodeConfig: async node => {
            events.push('veto'); assert.equal(String(node._id), NODE);
            if (veto instanceof Error) throw veto;
            return veto;
        } };
        return Module.prototype.require.call(loaded, id);
    };
    loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
    return { ...loaded.exports, events, rows, model };
}

test('disabled classic helper has no optional model or owner dependency effects', async () => {
    assert.ok(fs.existsSync(filename), 'classic config writer fence helper is missing');
    const f = fixture();
    assert.equal(await f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: {} }, async () => 'legacy'), 'legacy');
    assert.deepEqual(f.events, []);
});

test('holds insert-only uncertain generation through callback and releases only exact success', async () => {
    const f = fixture();
    let held;
    assert.equal(await f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => {
        held = { ...f.rows.get(NODE) };
        assert.equal(held.remoteUncertain, true);
        assert.deepEqual(f.events, ['model', 'acquire', 'veto']);
        assert.equal(await f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => false), false);
        return true;
    }), true);
    // Nested unverified completion poisons the outer result even if swallowed.
    assert.deepEqual(f.rows.get(NODE), held);
    assert.equal(f.events.includes('release'), false);
    const clean = fixture();
    assert.equal(await clean.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => true), true);
    assert.equal(clean.rows.size, 0);
    assert.deepEqual(clean.events, ['model', 'acquire', 'veto', 'release']);
});

for (const outcome of ['throw', 'false', 'unknown', 'nonzero']) {
    test(`retains uncertain exact generation on ${outcome}`, async () => {
        const f = fixture();
        const run = () => f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => {
            if (outcome === 'throw') throw new Error('transport unknown');
            return { false: false, unknown: undefined, nonzero: { code: 1 } }[outcome];
        });
        if (outcome === 'throw') await assert.rejects(run(), /transport unknown/); else await run();
        assert.equal(f.rows.get(NODE).remoteUncertain, true);
        assert.equal(f.events.includes('release'), false);
    });
}

for (const veto of [true, new Error('owner read unavailable')]) {
    test(`durable owner veto/read failure prevents callback (${String(veto)})`, async () => {
        const f = fixture({ veto });
        let callbacks = 0;
        await assert.rejects(f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => { callbacks++; return true; }));
        assert.equal(callbacks, 0);
        assert.equal(f.rows.size, 1);
    });
}

test('expired foreign uncertain generation cannot be replaced or released', async () => {
    const winner = { node: NODE, owner: 'l2tp', operationId: 'l2tp-op', generation: 'winner',
        remoteUncertain: true, leaseUntil: new Date(0) };
    const f = fixture({ rows: new Map([[NODE, winner]]) });
    let callbacks = 0;
    await assert.rejects(f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => { callbacks++; return true; }), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
    assert.equal(callbacks, 0);
    assert.deepEqual(f.rows.get(NODE), winner);
    assert.deepEqual(f.events, ['model', 'acquire']);
});

test('competing asynchronous classic call loses before callback while first remote is pending', async () => {
    const f = fixture();
    let finish;
    let started;
    const ready = new Promise(resolve => { started = resolve; });
    const first = f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => {
        started(); await new Promise(resolve => { finish = resolve; }); return true;
    });
    await ready;
    const generation = f.rows.get(NODE).generation;
    await assert.rejects(f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'cascade', env: enabled }, async () => { throw new Error('must not dispatch'); }), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
    assert.equal(f.rows.get(NODE).generation, generation);
    finish();
    await first;
    assert.equal(f.rows.size, 0);
});

test('nested success reuses private same-node generation without exposing authority', async () => {
    const f = fixture();
    await f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'cascade', env: enabled }, async () =>
        f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => true));
    assert.deepEqual(f.events, ['model', 'acquire', 'veto', 'release']);
});

test('unknown insert never invokes callback or attempts cleanup', async () => {
    const f = fixture({ createError: new Error('unknown insert') });
    let calls = 0;
    await assert.rejects(f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => { calls++; return true; }), /unknown insert/);
    assert.equal(calls, 0);
    assert.deepEqual(f.events, ['model', 'acquire']);
});

test('exact release cannot delete a replacement generation', async () => {
    const f = fixture();
    let replacement;
    await assert.rejects(f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => {
        replacement = { ...f.rows.get(NODE), generation: 'foreign-generation' };
        f.rows.set(NODE, replacement);
        return true;
    }), { code: 'CLASSIC_CONFIG_WRITE_LOCK_UNCERTAIN' });
    assert.deepEqual(f.rows.get(NODE), replacement);
    assert.equal(f.events.includes('release'), false);
});

test('failed delete acknowledgement never retries or adopts another generation', async () => {
    const f = fixture({ deleteError: new Error('delete unconfirmed') });
    await assert.rejects(f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => true), /delete unconfirmed/);
    assert.equal(f.rows.size, 1);
    assert.equal(f.events.filter(event => event === 'release').length, 1);
});

for (const mode of ['test', 'production']) {
    test(`canonical ${mode} authorization activates lock; mismatched flags stay dormant`, async () => {
        const env = mode === 'test' ? enabled : { ...enabled, PANEL_DOMAIN: 'lm1.infograd.online', L2TP_PRODUCTION_EXECUTION_ENABLED: 'true' };
        const f = fixture();
        await f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env }, async () => true);
        assert.equal(f.events.includes('acquire'), true);
        const dormant = fixture();
        await dormant.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: { ...env, L2TP_MIGRATIONS_ENABLED: 'false' } }, async () => true);
        assert.deepEqual(dormant.events, []);
    });
}

test('unawaited same-node work keeps lock even when outer callback returns true', async () => {
    const f = fixture();
    let finish;
    let nested;
    await f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'cascade', env: enabled }, async () => {
        nested = f.withClassicNodeConfigWrite({ nodeId: NODE, kind: 'sync', env: enabled }, async () => {
            await new Promise(resolve => { finish = resolve; }); return true;
        });
        return true;
    });
    assert.equal(f.rows.size, 1);
    assert.equal(f.events.includes('release'), false);
    finish(); await assert.rejects(nested, { code: 'CLASSIC_CONFIG_WRITE_SCOPE_CLOSED' });
    assert.equal(f.rows.size, 1);
});

function syncFixture(options = {}) {
    const f = fixture(options);
    const events = f.events;
    const target = { _id: NODE, name: 'fixture', ip: '127.0.0.1', type: 'xray', cascadeRole: 'standalone',
        ssh: { privateKey: 'not-a-real-key' }, xray: {} };
    class SSH {
        async connect() { events.push('connect'); }
        disconnect() { events.push('disconnect'); }
        async exec(command) {
            events.push(command.startsWith('cat ') ? 'read' : 'exec');
            return options.execResult || { code: 0, stdout: options.liveConfig || '' };
        }
        async uploadContent(content) {
            events.push('upload'); f.upload = content;
            if (options.uploadError) throw new Error('upload uncertain');
        }
    }
    const syncFilename = path.resolve(__dirname, '../syncService.js');
    const loaded = new Module(syncFilename, module);
    loaded.filename = syncFilename;
    loaded.paths = Module._nodeModulePaths(path.dirname(syncFilename));
    loaded.require = id => {
        if (id === './classicNodeConfigWrite') return f;
        if (id === './classicL2tpConfigComposition') return Module.prototype.require.call(loaded, id);
        // This fixture has no cascade links/groups; the actual composition is
        // exercised by l2tpDefaultRootIntegration with persisted path records.
        if (id === './cascadeService') return { _applyClassicL2tpPathIngress: async config => config };
        if (id.endsWith('/l2tpExecutionAuthorization') || id.endsWith('/l2tpXrayConfigMerge')) return Module.prototype.require.call(loaded, id);
        if (id === './topologyConfigOwnership') return { APPLIED_LINK_STATUSES: [], usesTestTopologyConfig: () => false,
            topologyManagesNodeConfig: async () => !!options.initialVeto };
        if (id === './nodeSSH') return SSH;
        if (id === './configGenerator') return { generateXrayConfigWithApi() {
            events.push('generate'); return JSON.stringify({ inbounds: [], outbounds: [], routing: { rules: [] } });
        }, ensurePrivateIpBlock() {} };
        if (id.endsWith('/relayL2tpStateModel')) return { exists: async () => options.installed || false };
        if (id.endsWith('/cascadeLinkModel')) return { find: () => Object.assign(Promise.resolve([]), { populate: async () => [] }) };
        if (id.endsWith('/hyNodeModel')) return { updateOne: async () => ({}) };
        if (id === '../utils/helpers') return { invalidateNodesCache: async () => {} };
        if (id === '../utils/logger') return { info() {}, warn() {}, error() {} };
        if (id === './nodeSetup') return { reloadCcAgent: async () => { if (options.reloadError) throw new Error('reload uncertain'); } };
        if (id === 'https') return require('node:https');
        return {};
    };
    loaded._compile(fs.readFileSync(syncFilename, 'utf8'), syncFilename);
    const sync = loaded.exports;
    sync._getUsersForNode = async () => [];
    sync._agentRequest = async (_node, _method, requestPath) => {
        events.push(requestPath);
        if (options.agentError) throw new Error('agent outcome uncertain');
        return { status: 200, data: {} };
    };
    sync.checkXrayAgentHealth = async () => ({ online: true });
    return { ...f, sync, target, get uploaded() { return f.upload; } };
}
async function inEnabledEnv(fn) {
    const saved = { ...process.env };
    Object.assign(process.env, enabled);
    try { return await fn(); } finally {
        for (const key of Object.keys(enabled)) { if (saved[key] === undefined) delete process.env[key]; else process.env[key] = saved[key]; }
    }
}

test('sync writer loses shared lock before generation, SSH, agent or live read', async () => {
    const winner = { node: NODE, owner: 'l2tp', operationId: 'op', generation: 'winner', remoteUncertain: true };
    const f = syncFixture({ rows: new Map([[NODE, winner]]) });
    await inEnabledEnv(async () => {
        await assert.rejects(f.sync.updateXrayNodeConfig(f.target), { code: 'NODE_OPERATION_LOCK_CONFLICT' });
    });
    assert.deepEqual(f.events, ['model', 'acquire']);
    assert.deepEqual(f.rows.get(NODE), winner);
});

test('sync acquires before live preservation read/generation and retains L2TP sections', async () => {
    const inbound = { tag: 'relay-l2tp-tproxy', protocol: 'dokodemo-door' };
    const outbound = { tag: 'path-socks', protocol: 'socks' };
    const rule = { inboundTag: [inbound.tag], outboundTag: outbound.tag };
    const f = syncFixture({ installed: true, liveConfig: JSON.stringify({ inbounds: [inbound], outbounds: [outbound], routing: { rules: [rule] } }) });
    await inEnabledEnv(async () => assert.equal(await f.sync.updateXrayNodeConfig(f.target), true));
    assert.deepEqual(f.events, ['model', 'acquire', 'veto', 'generate', 'connect', 'read', 'upload', 'disconnect', 'connect', 'exec', 'disconnect', 'release']);
    assert.equal(f.rows.size, 0);
    const uploaded = JSON.parse(f.uploaded);
    assert.deepEqual(uploaded.inbounds, [inbound]);
    assert.deepEqual(uploaded.outbounds, [outbound]);
    assert.deepEqual(uploaded.routing.rules, [rule, { type: 'field', ip: ['geoip:private'], outboundTag: 'blackhole' }]);
});

for (const options of [
    { uploadError: true }, { execResult: { code: 1, stdout: 'failure' } }, { execResult: { stdout: 'no exit status' } },
    { installed: true, liveConfig: '' }, { agentError: true }, { reloadError: true },
]) {
    test(`sync retains uncertain lock on swallowed transport outcome ${JSON.stringify(options)}`, async () => {
        const f = syncFixture(options);
        if (options.agentError || options.reloadError) f.target.xray.agentToken = 'not-a-real-token';
        await inEnabledEnv(async () => assert.equal(await f.sync.updateXrayNodeConfig(f.target), false));
        assert.equal(f.rows.size, 1);
        assert.equal(f.rows.get(NODE).remoteUncertain, true);
        assert.equal(f.events.includes('release'), false);
    });
}

test('invalid live L2TP JSON must not authorize overwriting preserved sections', async () => {
    const f = syncFixture({ installed: true, liveConfig: 'not-json' });
    await inEnabledEnv(async () => assert.equal(await f.sync.updateXrayNodeConfig(f.target), false));
    assert.equal(f.events.includes('upload'), false);
    assert.equal(f.events.includes('release'), false);
    assert.equal(f.rows.size, 1);
});

test('sync durable veto acquired after initial classic check blocks before generation', async () => {
    const f = syncFixture({ veto: true });
    await inEnabledEnv(async () => assert.rejects(f.sync.updateXrayNodeConfig(f.target), { code: 'CLASSIC_CONFIG_WRITE_OWNER_VETO' }));
    assert.deepEqual(f.events, ['model', 'acquire', 'veto']);
});

test('managed sync remains user-only with no optional node-lock model activation', async () => {
    const f = syncFixture({ initialVeto: true });
    f.target.xray.agentToken = 'not-a-real-token';
    await inEnabledEnv(async () => assert.equal(await f.sync.updateXrayNodeConfig(f.target), true));
    assert.deepEqual(f.events, ['/sync']);
});
