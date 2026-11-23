'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const test = require('node:test');
const express = require('express');
const requireAuth = require('../../middleware/auth');
const Node = require('../../models/hyNodeModel');
const ApiKey = require('../../models/apiKeyModel');
const cache = require('../../services/cacheService');
const setup = require('../../services/nodeSetup');
const sync = require('../../services/syncService');

const id = 'a'.repeat(24);
const token = 'synthetic-agent-token-not-in-loaded-node';
const ssh = { password: 'synthetic-ssh-password' };

test.after(() => require('../../services/sshPoolService').closeAll());

async function fixture(t) {
    const row = { _id: id, name: 'fixture', ip: '192.0.2.10', active: true,
        type: 'xray', cascadeRole: 'standalone', xray: {}, ssh };
    const f = { row, reads: [], installs: [], probes: [], writes: [], health: 'online', failure: null };
    t.mock.method(Node, 'findById', async selected => {
        f.reads.push(selected);
        return selected === id ? row : null;
    });
    t.mock.method(Node, 'findByIdAndUpdate', async (selected, update) => {
        assert.equal(selected, id);
        f.writes.push(update.$set);
    });
    t.mock.method(Node, 'findOneAndUpdate', async (filter, update) => {
        assert.equal(filter._id, id);
        assert.equal(filter['xray.agentToken'] === token, true, 'health write needs the provisioned token');
        f.writes.push(update.$set);
        return { status: update.$set.status, lastError: update.$set.lastError };
    });
    for (const method of ['invalidateNodes', 'invalidateAllSubscriptions', 'invalidateDashboardCounts']) {
        t.mock.method(cache, method, async () => {});
    }
    t.mock.method(require('../../models/settingsModel'), 'get', async () => ({ deployment: { completed: true } }));
    t.mock.method(require('../../models/cascadeLinkModel'), 'countDocuments', async () => 0);
    t.mock.method(ApiKey, 'findByKey', async key => ({ _id: id, keyPrefix: 'fixture', rateLimit: 10,
        scopes: key === 'fixture-mcp-only' ? ['mcp:enabled'] : [] }));
    t.mock.method(ApiKey, 'findByIdAndUpdate', async () => {});
    t.mock.method(cache, 'checkApiKeyRateLimit', async () => ({ allowed: true, limit: 10, count: 1 }));
    for (const method of ['setupXrayNode', 'setupXrayNodeWithAgent', 'setupNode']) {
        t.mock.method(setup, method, async (node, options) => {
            assert.equal(node, row);
            f.installs.push([method, options]);
            if (f.failure) return { success: false, error: f.failure, logs: ['install failed'] };
            return { success: true, logs: ['installed'], useTlsFiles: true,
                ...(method === 'setupXrayNodeWithAgent' && { agentToken: token }) };
        });
    }
    t.mock.method(sync, '_agentRequest', async (target, method, path) => {
        f.probes.push([method, path]);
        assert.equal(target.xray.agentToken === token, true, 'probe needs the provisioned token');
        return { status: 200, data: path === '/xray-health' ? { xray_status: f.health } : {} };
    });

    const app = express();
    app.use(express.json(), (req, _res, next) => {
        if (!req.headers.authorization && req.headers['x-fixture-session']) req.session = { authenticated: true };
        next();
    });
    app.use('/panel', require('../panel'));
    app.use('/api/nodes', requireAuth, require('../nodes'));
    app.use('/api/mcp', requireAuth, require('../mcp'));
    const server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise(resolve => server.close(resolve)));
    f.send = async (surface, { selected = id, body = {}, auth = 'session' } = {}) => {
        const headers = { 'content-type': 'application/json' };
        if (auth === 'session') headers['x-fixture-session'] = '1';
        else if (auth) headers.authorization = `Bearer ${auth}`;
        let path = `/${surface}/nodes/${selected}/setup`;
        if (surface === 'mcp') {
            path = '/api/mcp';
            body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'manage_node',
                arguments: { action: 'setup', id: selected, ...body } } };
        }
        const res = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
            method: 'POST', headers, body: JSON.stringify(body), redirect: 'manual',
        });
        const text = await res.text();
        assert.equal(text.includes(token) || text.includes(ssh.password), false, 'setup must not expose secrets');
        if (res.headers.get('content-type')?.startsWith('text/event-stream')) {
            const line = text.split('\n\n').find(event => event.startsWith('event: message\n'));
            const rpc = JSON.parse(line.split('\n')[1].slice('data: '.length));
            assert.equal(rpc.id, 1);
            const { content, isError } = rpc.result;
            const contentText = content[0].text;
            return { status: res.status, isError: !!isError,
                body: contentText.startsWith('{') ? JSON.parse(contentText) : contentText };
        }
        return { status: res.status, body: res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : null };
    };
    return f;
}

for (const surface of ['panel', 'api', 'mcp']) {
    test(`${surface} setup follows the persisted Xray role and verifies only non-bridges`, async t => {
        const f = await fixture(t);
        for (const role of ['standalone', 'portal', 'relay', 'bridge']) {
            f.row.cascadeRole = role;
            const res = await f.send(surface, { body: surface === 'mcp'
                ? { data: { cascadeRole: 'bridge' } } : { cascadeRole: 'bridge' } });
            assert.equal(res.status, 200, `${role} setup status`);
            assert.equal(res.body.success, true);
            const bridge = role === 'bridge';
            assert.deepEqual(f.installs.splice(0), [bridge
                ? ['setupXrayNode', { restartService: false, exitOnly: true }]
                : ['setupXrayNodeWithAgent', { restartService: true }]]);
            assert.deepEqual(f.probes.splice(0), bridge ? [] : [['GET', '/xray-health'], ['GET', '/info']]);
            assert.equal(f.writes.pop().status, bridge ? 'offline' : 'online');
            assert.deepEqual(f.reads.splice(0), [id]);
            if (bridge) {
                assert.equal(res.body.xray_status, undefined);
                assert.ok(res.body.logs.some(log => log.includes('Create a cascade link')));
            } else assert.equal(res.body.xray_status, 'online');
        }
    });
}

test('REST and MCP preserve restart options, setup errors, and Hysteria options', async t => {
    const f = await fixture(t);
    for (const surface of ['api', 'mcp']) {
        const send = (opts = {}) => f.send(surface, { body: surface === 'api' ? opts : { setupOptions: opts } });
        f.health = 'offline';
        const failedCheck = await send();
        assert.equal(failedCheck.status, surface === 'api' ? 502 : 200);
        assert.equal(failedCheck.body.success, false);
        if (surface === 'mcp') {
            assert.equal(failedCheck.isError, true);
            assert.equal(failedCheck.body.code, 502);
        }
        const deferred = await send({ restartService: false });
        assert.equal(deferred.status, 200);
        assert.equal(deferred.body.success, true);
        assert.match(deferred.body.warning, /service restart was not requested/);
        assert.deepEqual(f.installs.splice(0), [
            ['setupXrayNodeWithAgent', { restartService: true }], ['setupXrayNodeWithAgent', { restartService: false }],
        ]);
        assert.equal(f.probes.splice(0).length, 4);
        f.failure = 'fixture installer refused';
        const failedInstall = await send();
        assert.equal(failedInstall.status, surface === 'api' ? 500 : 200);
        assert.deepEqual(failedInstall.body, { success: false, error: f.failure, logs: ['install failed'] });
        assert.equal(f.writes.pop().status, 'error');
        assert.deepEqual(f.probes, []);
        f.failure = null;
        f.installs.length = 0;
        f.row.type = 'hysteria';
        const opts = { installHysteria: false, setupPortHopping: false, restartService: false };
        const hysteria = await send(opts);
        assert.deepEqual(hysteria.body, { success: true, logs: ['installed'] });
        assert.deepEqual(f.installs.splice(0), [['setupNode', opts]]);
        assert.equal(f.writes.pop().useTlsFiles, true);
        f.row.type = 'xray';
    }
});

test('REST and MCP keep auth, scope, node selection, and unsupported-node refusals', async t => {
    const f = await fixture(t);
    assert.equal((await f.send('api', { auth: null })).status, 401);
    assert.equal((await f.send('api', { auth: 'fixture-mcp-only' })).status, 403);
    assert.equal((await f.send('mcp', { auth: null })).status, 401);
    assert.equal((await f.send('mcp', { auth: 'fixture-no-scopes' })).status, 403);
    const deniedTool = await f.send('mcp', { auth: 'fixture-mcp-only' });
    assert.equal(deniedTool.isError, true);
    assert.equal(deniedTool.body, 'Missing scope: nodes:write');
    assert.deepEqual(f.reads, []);

    const other = 'b'.repeat(24);
    assert.equal((await f.send('api', { selected: other })).status, 404);
    assert.equal((await f.send('mcp', { selected: other })).body.code, 404);
    assert.deepEqual(f.reads, [other, other]);
    f.row.ssh = undefined;
    assert.equal((await f.send('api')).status, 400);
    assert.equal((await f.send('mcp')).body.error, 'SSH credentials not configured');
    f.row.type = 'virtual';
    assert.equal((await f.send('api')).body.error, 'SSH credentials not configured for this node');
    f.row.ssh = ssh;
    assert.equal((await f.send('api')).body.error, 'Virtual nodes have no remote server to set up');
    f.row.ssh = undefined;
    assert.equal((await f.send('mcp')).body.error, 'Virtual nodes have no remote server to set up');
    assert.deepEqual([f.installs, f.probes, f.writes], [[], [], []]);
});
