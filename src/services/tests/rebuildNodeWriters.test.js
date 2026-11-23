'use strict';

const assert = require('node:assert/strict');
const { Duplex } = require('node:stream');
const { IncomingMessage, ServerResponse } = require('node:http');
const test = require('node:test');
const express = require('express');
const mongoose = require('mongoose');
const id = 'a'.repeat(24), relayId = 'b'.repeat(24);
const ip = '192.0.2.10';
const session = { authenticated: true };

function request(app, method, url, body = {}) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const socket = new Duplex({ read() {}, write(chunk, _, done) { chunks.push(chunk.toString()); done(); } });
        socket.remoteAddress = '192.0.2.1';
        const req = new IncomingMessage(socket);
        Object.assign(req, { method, url, headers: { host: 'fixture.invalid' }, body, session, sessionID: 'fixture' });
        req.push(null);
        const res = new ServerResponse(req);
        res.assignSocket(socket);
        res.once('error', reject);
        res.once('finish', () => {
            const body = chunks.join('').split('\r\n\r\n')[1];
            resolve({ status: res.statusCode, location: res.getHeader('location'), body: body && res.getHeader('content-type')?.includes('json') ? JSON.parse(body) : body });
            socket.destroy();
        });
        app(req, res);
    });
}

test('mounted rebuild node writers cooperate with the real Apply lock and pending-account fence', { timeout: 10000 }, async t => {
    const prev = process.env.C3_REBUILD_ENABLED;
    t.after(() => { if (prev === undefined) delete process.env.C3_REBUILD_ENABLED; else process.env.C3_REBUILD_ENABLED = prev; });
    process.env.C3_REBUILD_ENABLED = 'true';
    const Node = require('../../models/hyNodeModel');
    const User = require('../../models/hyUserModel');
    const State = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
    const Account = require('../../modules/relay-l2tp/models/l2tpUserModel');
    const setup = require('../nodeSetup');
    const cache = require('../cacheService');
    const sync = require('../syncService');
    const { makeLocks } = require('../rebuildLocks');
    const panelHelpers = require('../../routes/panel/helpers');
    const { invalidateOnboardingCache } = panelHelpers;
    const { manageNode } = require('../../mcp/tools/nodes');
    invalidateOnboardingCache();
    t.after(invalidateOnboardingCache);
    t.after(() => require('../sshPoolService').closeAll());
    let onboarded = true;
    t.mock.method(require('../../models/settingsModel'), 'get', async () => ({ deployment: { completed: onboarded } }));
    for (const method of ['invalidateNodes', 'invalidateAllSubscriptions', 'invalidateDashboardCounts']) t.mock.method(cache, method, async () => {});

    const rows = [
        { id, name: 'Sibling', type: 'hysteria', cascadeRole: 'standalone' },
        { id: relayId, name: 'Relay', type: 'xray', cascadeRole: 'relay', xray: { agentToken: 'fixture' } },
    ].map(({ id, ...row }) => ({ ...row, _id: new mongoose.Types.ObjectId(id), ip, active: true, ssh: { port: 22, username: 'root', password: 'fixture' } }));
    let held, pending = true, inRebuild = true, expectUserSync = false, relayState = 'installed';
    let incident, grant, replica;
    const effects = [];
    const lockStore = {
        async insertOne(row) { if (held) throw Object.assign(new Error('busy'), { code: 11000 }); held = row; },
        async findOne({ _id, token }) { return held?._id === _id && held.token === token ? held : null; },
        async deleteMany(filter) { assert.deepEqual(filter, { _id: 'apply', token: held.token }); held = null; return { acknowledged: true, deletedCount: 1 }; },
    };
    const collection = mongoose.connection.collection.bind(mongoose.connection);
    t.mock.method(mongoose.connection, 'collection', (name, ...options) => {
        if (name === 'c3_rebuild_locks') return lockStore;
        if (name === 'c3_rebuild_l2tp_retired_relays') return { async findOne({ _id }) {
            assert.ok(held);
            assert.equal(_id, relayId);
            return null;
        } };
        if (name === 'c3_rebuild_l2tp_relay_grants') return { async findOne({ nodeId }) {
            assert.ok(held);
            return nodeId === relayId && grant ? { nodeId } : null;
        } };
        if (name !== 'c3_rebuild_relay_accounts') return collection(name, ...options);
        return { async findOne(filter, options) {
            assert.ok(held, 'pending read must hold Apply');
            assert.deepEqual(filter, { _id: 'pending' });
            assert.equal(options.readPreference, 'primary');
            assert.equal(options.readConcern.level, 'majority');
            if (pending instanceof Error) throw pending;
            return pending ? filter : null;
        } };
    });
    const observe = (name, options) => {
        effects.push(name);
        assert.equal(!!held, inRebuild && !expectUserSync, `${name} used the wrong lock scope`);
        if (options && inRebuild && !expectUserSync) assert.equal(options.writeConcern?.w, 'majority');
    };
    const matching = ({ _id, ip, type, cascadeRole }) => rows.filter(row => (
        (!_id || (_id.$ne ? String(row._id) !== String(_id.$ne) : String(row._id) === String(_id)))
        && (!ip || row.ip === ip) && (!type || row.type === type) && (!cascadeRole || row.cascadeRole === cascadeRole)
    ));
    function fixture(model, collection) {
        const { buffer, collection: prior } = model.collection;
        model.collection.buffer = false;
        model.collection.collection = collection;
        t.after(() => { model.collection.buffer = buffer; model.collection.collection = prior; });
    }
    const copy = row => row && { ...row, ssh: { ...row.ssh }, ...(row.xray && { xray: { ...row.xray } }) };
    fixture(Node, {
        async findOne(filter) { return copy(matching(filter)[0]) ?? null; },
        find(filter) { return { toArray: async () => matching(filter).map(copy) }; },
        async findOneAndUpdate(filter, _, options) { observe('edit', options); return copy(matching(filter)[0]); },
        async updateOne(_, __, options) { observe('edit', options); return { acknowledged: true, matchedCount: 1 }; },
        async updateMany(_, __, options) { observe('siblings', options); return { acknowledged: true, matchedCount: 1 }; },
        async findOneAndDelete(filter, options) { observe('delete', options); return copy(matching(filter)[0]); },
    });
    fixture(User, { async updateMany(_, __, options) { observe('user unlink', options); return { acknowledged: true }; } });
    fixture(State, { async findOne({ node }, options) {
        assert.ok(held, 'ownership read must hold Apply');
        assert.equal(options.readConcern.level, 'majority');
        assert.equal(options.readPreference.mode, 'primary');
        if (relayState instanceof Error) throw relayState;
        return String(node) === relayId && relayState ? { status: relayState, desiredState: 'installed' } : null;
    } });
    fixture(Account, { async countDocuments() { return 2; }, async findOne({ relayNode: { $in: [relayNode] } }) {
        assert.ok(held);
        return String(relayNode) === relayId && replica ? { _id: rows[1]._id } : null;
    } });
    for (const method of ['setupXrayNode', 'setupXrayNodeWithAgent', 'setupNode', 'startNodeRuntime', 'stopNodeRuntime', 'connectSSH']) {
        t.mock.method(setup, method, async () => { observe(method); return { success: true }; });
    }
    t.mock.method(sync, 'schedulePush', () => { effects.push('schedule push'); });
    t.mock.method(sync, 'probeXrayHealth', async () => ({ online: true, xrayStatus: 'online', agentStatus: 'online', info: {}, lastError: '' }));
    const syncStub = t.mock.method(sync, 'updateNodeConfig', async () => { observe('sync'); return true; });
    t.mock.method(panelHelpers, 'connectNodeSSH', async () => { effects.push('connectNodeSSH'); assert.fail('no SSH key transport'); });
    t.mock.method(require('../nodeSSH').prototype, 'connect', async () => { effects.push('NodeSSH.connect'); assert.fail('no config transport'); });
    fixture(require('../../models/serverGroupModel'), {
        async findOneAndUpdate() { effects.push('starter group'); assert.fail('no starter bundle after refusal'); },
    });
    fixture(require('../../models/cascadeLinkModel'), { async findOne(filter, options) {
        if (!incident) return null;
        assert.ok(held, 'incident check holds the same lock as deletion');
        assert.equal(options.readConcern.level, 'majority');
        assert.equal(options.readPreference, 'primary');
        assert.deepEqual(filter, { $or: ['portalNode', 'bridgeNode', 'source', 'target', 'rebuildApplied.listener'].map(field => ({
            [field]: { $in: [rows[1]._id, relayId] },
        })) });
        return incident;
    } });
    const { createPanelRouter } = require('../../routes/panel');

    const app = express();
    app.use('/api/nodes', require('../../middleware/auth'), require('../../routes/nodes'));
    app.use('/panel', createPanelRouter());
    const api = (method, n, suffix = '', body) => request(app, method, `/api/nodes/${n}${suffix}`, body);
    const panel = (n, suffix = '', body) => request(app, 'POST', `/panel/nodes/${n}${suffix}`, body);
    const mcp = (action, n, data) => manageNode({ action, id: n, data }, () => {});
    const panelEdit = { name: 'Relay', type: 'xray', ip, active: 'on' };
    const http = (send, code = 409) => async reason => {
        const res = await send();
        assert.equal(res.status, code);
        if (code !== 302) {
            assert.equal(res.body.code, reason);
            if (reason === 'REBUILD_L2TP_ACCOUNTS_BLOCKED') assert.equal(res.body.retryAllowed, false);
        }
        else assert.match(res.location, /\?error=/);
    };
    const tool = send => async reason => { const res = await send(); assert.equal(res.code, 409); assert.equal(res.reason, reason); };
    const writers = {
        'REST PUT without role': http(() => api('PUT', relayId, '', { active: false })),
        'REST PUT relay SSH': http(() => api('PUT', relayId, '', { ssh: { username: 'wrong' } })),
        'REST PUT sibling SSH': http(() => api('PUT', id, '', { ssh: { port: 2222 } })),
        'panel save without role': http(() => panel(relayId, '', { ...panelEdit, ip: '192.0.2.99' }), 302),
        'REST delete': http(() => api('DELETE', relayId)),
        'MCP delete': tool(() => mcp('delete', relayId)),
        'REST setup': http(() => api('POST', relayId, '/setup')),
        'panel setup': http(() => panel(relayId, '/setup')),
        'MCP setup': tool(() => mcp('setup', relayId)),
        'MCP SSH replacement': tool(() => mcp('update', relayId, { ssh: { port: 22, username: 'root' } })),
        'MCP update': tool(() => mcp('update', relayId, { type: 'hysteria' })),
        'REST disable': http(() => api('POST', relayId, '/disable')),
        'REST enable': http(() => api('POST', relayId, '/enable')),
        'panel SSH key': http(() => panel(relayId, '/generate-ssh-key')),
        'wizard reused Xray card': http(async () => {
            onboarded = false;
            try {
                return await request(app, 'POST', '/panel/wizard/self-host', { installXray: 'on', 'ssh.ip': ip, 'ssh.password': 'fixture' });
            } finally { onboarded = true; }
        }, 302),
    };
    for (const [name, refuse] of Object.entries(writers)) await t.test(`pending: ${name}`, async () => {
        effects.length = 0;
        await refuse('REBUILD_L2TP_ACCOUNTS_BLOCKED');
        assert.deepEqual(effects, []);
        assert.equal(held, null);
    });
    effects.length = 0;
    await http(() => panel(relayId, '/restart'))('REBUILD_L2TP_ACCOUNTS_BLOCKED');
    assert.deepEqual(effects, []);
    pending = false;
    for (const [name, refuse] of Object.entries(writers)) await t.test(`installed: ${name}`, async () => {
        effects.length = 0;
        await refuse('REBUILD_L2TP_NODE_WRITE_BLOCKED');
        assert.deepEqual(effects, []);
        assert.equal(held, null);
    });
    for (const state of ['installing', 'removing', 'error', 'not_installed']) {
        relayState = state; // `not_installed` paired with install intent still blocks.
        await writers['REST delete']('REBUILD_L2TP_NODE_WRITE_BLOCKED');
    }
    relayState = new Error('fixture ownership unavailable');
    await http(() => api('DELETE', relayId), 503)('REBUILD_L2TP_ROLE_STATE_UNAVAILABLE');
    relayState = 'installed';
    rows[0].ssh.port = 2222;
    await writers['REST PUT sibling SSH']('REBUILD_L2TP_NODE_WRITE_BLOCKED');
    rows[0].ssh.port = 22;
    pending = new Error('fixture intent read unavailable');
    await http(() => api('PUT', id, '', { ssh: { port: 2222 } }))('REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE');
    pending = false;
    assert.deepEqual(effects, []);
    effects.length = 0;
    assert.equal((await api('PUT', relayId, '', { name: 'Rename' })).status, 200);
    assert.equal((await panel(relayId, '', { ...panelEdit, 'ssh.port': '22', 'ssh.username': 'root' })).location, '/panel/nodes');
    assert.ok(effects.includes('edit'));
    await makeLocks(lockStore).run(() => writers['REST setup']('REBUILD_BUSY'));

    relayState = null;
    effects.length = 0;
    assert.equal((await api('PUT', id, '', { ssh: { port: 2222 } })).status, 200);
    assert.deepEqual(effects, ['edit', 'siblings', 'schedule push']);
    effects.length = 0;
    assert.equal((await api('POST', relayId, '/setup')).status, 200);
    assert.deepEqual(effects, ['setupXrayNodeWithAgent', 'edit']);
    effects.length = 0;
    assert.equal((await panel(relayId, '/setup')).status, 200);
    assert.equal((await mcp('setup', relayId)).success, true);
    assert.deepEqual(effects, ['setupXrayNodeWithAgent', 'edit', 'setupXrayNodeWithAgent', 'edit']);
    effects.length = 0;
    incident = { _id: rows[0]._id, active: false, rebuildDelete: true };
    await writers['REST delete']('REBUILD_NODE_HAS_LINKS');
    await writers['MCP delete']('REBUILD_NODE_HAS_LINKS');
    assert.deepEqual(effects, []);
    assert.equal((await api('PUT', relayId, '', { name: 'still editable' })).status, 200);
    effects.length = 0;
    incident = null;
    grant = true;
    await writers['REST delete']('REBUILD_NODE_RETIRE_REQUIRED');
    await writers['MCP delete']('REBUILD_NODE_RETIRE_REQUIRED');
    grant = false;
    const keys = ['C3_REBUILD_L2TP_RELAY_ID', 'C3_REBUILD_L2TP_RELAY_MACHINE_ID', 'C3_REBUILD_L2TP_RELAYS_JSON'];
    const previous = keys.map(key => process.env[key]);
    process.env[keys[0]] = relayId;
    process.env[keys[1]] = 'b'.repeat(32);
    delete process.env[keys[2]];
    try { await writers['REST delete']('REBUILD_NODE_RETIRE_REQUIRED'); }
    finally { keys.forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i]; }); }
    replica = true;
    await writers['REST delete']('REBUILD_NODE_RETIRE_REQUIRED');
    replica = false;
    assert.deepEqual(effects, []);
    assert.equal((await mcp('delete', relayId)).success, true);
    assert.deepEqual(effects, ['delete', 'user unlink']);

    await t.test('full config sync is fenced; stale standalone snapshots only sync users on a relay', async () => {
        syncStub.mock.restore();
        const row = rows[1];
        t.mock.method(sync, '_getUsersForNode', async node => {
            assert.equal(node.cascadeRole, 'relay');
            return [];
        });
        t.mock.method(sync, '_agentRequest', async (_node, method, path) => {
            assert.equal(method, 'POST');
            effects.push(path);
        });
        pending = true;
        effects.length = 0;
        row.cascadeRole = 'standalone';
        await http(() => api('POST', relayId, '/update-config'))('REBUILD_L2TP_ACCOUNTS_BLOCKED');
        await tool(() => mcp('update_config', relayId))('REBUILD_L2TP_ACCOUNTS_BLOCKED');
        assert.deepEqual(effects, []);
        const stale = Node.hydrate(copy(row));
        row.cascadeRole = 'relay';
        expectUserSync = true;
        assert.equal(await sync.updateXrayNodeConfig(stale), true);
        assert.deepEqual(effects, ['edit', '/sync', 'edit']);
        expectUserSync = false;
        pending = false;
    });

    inRebuild = false;
    pending = true;
    relayState = 'installed';
    process.env.C3_REBUILD_ENABLED = 'false';
    effects.length = 0;
    assert.equal((await api('POST', relayId, '/setup')).status, 200);
    assert.equal((await mcp('delete', relayId)).success, true);
    assert.deepEqual(effects, ['setupXrayNodeWithAgent', 'edit', 'delete', 'user unlink']);
});
