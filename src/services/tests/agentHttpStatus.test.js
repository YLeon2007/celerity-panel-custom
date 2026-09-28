'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test, after } = require('node:test');

process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
const syncService = require('../syncService');
const sshPool = require('../sshPoolService');
const HyNode = require('../../models/hyNodeModel');
const NodeSSH = require('../nodeSSH');
const configGenerator = require('../configGenerator');
const cache = require('../cacheService');
const logger = require('../../utils/logger');
after(() => sshPool.closeAll());

async function withAgent(t, status, fn) {
    const server = http.createServer((req, res) => {
        res.writeHead(typeof status === 'function' ? status(req) : status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'private-agent-response-secret' }));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const node = { _id: '507f1f77bcf86cd799439011', name: 'local test node', ip: '127.0.0.1',
        xray: { agentTls: false, agentPort: server.address().port, agentToken: 'private-agent-token' } };
    return fn(node);
}

function stubNodeSync(t, topologyManaged) {
    const updates = [];
    const info = [];
    let healthChecks = 0;
    let sshConnections = 0;
    t.mock.method(syncService, '_topologyManagesNode', async () => topologyManaged);
    t.mock.method(syncService, '_getUsersForNode', async () => [{ userId: 'u1', xrayUuid: 'uuid-1' }]);
    t.mock.method(syncService, 'checkXrayAgentHealth', async () => { healthChecks++; return { online: true }; });
    t.mock.method(HyNode, 'updateOne', async (_query, update) => { updates.push(update); return {}; });
    t.mock.method(NodeSSH.prototype, 'connect', async () => { sshConnections++; });
    t.mock.method(configGenerator, 'generateXrayConfigWithApi', () => '{}');
    t.mock.method(logger, 'info', message => { info.push(message); });
    for (const key of ['invalidateNodes', 'invalidateAllSubscriptions', 'invalidateDashboardCounts']) {
        t.mock.method(cache, key, async () => {});
    }
    return { updates, info, get healthChecks() { return healthChecks; }, get sshConnections() { return sshConnections; } };
}

test('agent 423 denial rejects without exposing response or credentials', async t => {
    await withAgent(t, 423, async node => {
        await assert.rejects(syncService._agentRequest(node, 'POST', '/sync', { secret: 'private-body-secret' }), error => {
            assert.match(error.message, /423/);
            assert.doesNotMatch(error.message, /private-agent-(?:response-secret|token)|private-body-secret/);
            return true;
        });
    });
});

test('agent 500 rejects with a safe HTTP status', async t => {
    await withAgent(t, 500, async node => {
        await assert.rejects(syncService._agentRequest(node, 'GET', '/info'), error => {
            assert.equal(error.code, 'AGENT_HTTP_ERROR');
            assert.match(error.message, /500/);
            assert.doesNotMatch(error.message, /private-agent-response-secret/);
            return true;
        });
    });
});

test('agent 200 remains successful', async t => {
    await withAgent(t, 200, async node => {
        const response = await syncService._agentRequest(node, 'GET', '/info');
        assert.equal(response.status, 200);
    });
});

test('agent 401 retains its unauthorized exception', async t => {
    await withAgent(t, 401, async node => {
        await assert.rejects(syncService._agentRequest(node, 'GET', '/info'), error => {
            assert.equal(error.code, 'AGENT_HTTP_ERROR');
            assert.match(error.message, /Unauthorized — check agentToken/);
            assert.doesNotMatch(error.message, /private-agent-response-secret|private-agent-token/);
            return true;
        });
    });
});

for (const operation of ['add', 'remove']) {
    test(`agent 423 ${operation} user reports failure without success log`, async t => {
        await withAgent(t, 423, async node => {
            const info = [];
            t.mock.method(logger, 'info', message => { info.push(message); });
            const user = { userId: 'u1', xrayUuid: 'uuid-1' };
            const result = operation === 'add'
                ? await syncService.addXrayUser(node, user)
                : await syncService.removeXrayUser(node, user);
            assert.equal(result, false);
            assert.equal(info.some(message => /Added user|Removed user/.test(message)), false);
        });
    });
}

test('agent /info 423 marks health offline without setting node online', async t => {
    const updates = [];
    t.mock.method(HyNode, 'findOneAndUpdate', async (_query, update) => {
        updates.push(update);
        return { healthFailures: 0, status: 'online' };
    });
    await withAgent(t, 423, async node => {
        assert.deepEqual(await syncService.checkXrayAgentHealth(node), { online: false });
    });
    assert.equal(updates.length, 1);
    assert.equal(updates[0].$set.agentStatus, 'offline');
    assert.match(updates[0].$set.lastError, /423/);
    assert.equal(updates.some(update => update.$set?.status === 'online'), false);
});

test('managed node refuses 423 /sync without SSH fallback or false online state', async t => {
    const calls = stubNodeSync(t, true);
    await withAgent(t, 423, async node => {
        node.ssh = { password: 'unused' };
        assert.equal(await syncService.updateXrayNodeConfig(node), false);
    });
    assert.equal(calls.sshConnections, 0);
    assert.equal(calls.healthChecks, 0);
    assert.equal(calls.updates.at(-1).$set.status, 'error');
    assert.match(calls.updates.at(-1).$set.lastError, /423/);
    assert.equal(calls.updates.some(update => update.$set?.status === 'online'), false);
    assert.equal(calls.info.some(message => /synced .* users via agent|sync complete/.test(message)), false);
});

test('classic node refuses agent /sync 423 without false online state', async t => {
    const calls = stubNodeSync(t, false);
    const paths = [];
    await withAgent(t, req => { paths.push(req.url); return req.url === '/sync' ? 423 : 200; }, async node => {
        assert.equal(await syncService.updateXrayNodeConfig(node), false);
    });
    assert.deepEqual(paths, ['/restart', '/sync']);
    assert.equal(calls.healthChecks, 0);
    assert.equal(calls.updates.at(-1).$set.status, 'error');
    assert.equal(calls.updates.some(update => update.$set?.status === 'online'), false);
});

test('classic node refuses agent restart 423 without alternate SSH or false online state', async t => {
    const calls = stubNodeSync(t, false);
    const paths = [];
    await withAgent(t, req => { paths.push(req.url); return req.url === '/restart' ? 423 : 200; }, async node => {
        // No SSH credentials: the agent restart must not be bypassed by a successful sync/health probe.
        assert.equal(await syncService.updateXrayNodeConfig(node), false);
    });
    assert.deepEqual(paths, ['/restart']);
    assert.equal(calls.sshConnections, 0);
    assert.equal(calls.healthChecks, 0);
    assert.equal(calls.updates.at(-1).$set.status, 'error');
    assert.equal(calls.updates.some(update => update.$set?.status === 'online'), false);
});
