'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { after } = require('node:test');

process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
const syncService = require('../syncService');
const sshPool = require('../sshPoolService');
const HyNode = require('../../models/hyNodeModel');
const CascadeLink = require('../../models/cascadeLinkModel');
const NodeSSH = require('../nodeSSH');
const configGenerator = require('../configGenerator');
const nodeSetup = require('../nodeSetup');
const RelayL2tpState = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
const cache = require('../cacheService');
after(() => sshPool.closeAll());

const FLAGS = ['L2TP_EXECUTION_ENABLED', 'L2TP_MIGRATIONS_ENABLED', 'TOPOLOGY_TEST_EXECUTION_ENABLED'];
async function withFlags(values, fn) {
    const prior = FLAGS.map(k => process.env[k]);
    try {
        FLAGS.forEach((k, i) => { if (values[i]) process.env[k] = 'true'; else delete process.env[k]; });
        return await fn();
    } finally {
        FLAGS.forEach((k, i) => { if (prior[i] === undefined) delete process.env[k]; else process.env[k] = prior[i]; });
    }
}

function node(role = 'portal') {
    return { _id: '507f1f77bcf86cd799439011', name: 'test node', ip: '127.0.0.1', type: 'xray', cascadeRole: role,
        ssh: { password: 'test' }, xray: { agentToken: 'test', transport: 'tcp', security: 'reality' } };
}

function stubSync(t, { connected = true } = {}) {
    const calls = { queries: [], uploads: [], sshConnections: 0, agent: [], generated: 0 };
    t.mock.method(CascadeLink, 'exists', async query => {
        calls.queries.push(query);
        return connected ? { _id: 'link-1' } : null;
    });
    t.mock.method(HyNode, 'updateOne', async () => ({}));
    t.mock.method(CascadeLink, 'find', () => ({ populate: async () => [] }));
    t.mock.method(RelayL2tpState, 'exists', async () => null);
    t.mock.method(nodeSetup, 'reloadCcAgent', async () => {});
    t.mock.method(syncService, '_getUsersForNode', async () => [{ userId: 'u1', xrayUuid: 'uuid-1' }]);
    t.mock.method(syncService, 'checkXrayAgentHealth', async () => ({ online: true }));
    for (const key of ['invalidateNodes', 'invalidateAllSubscriptions', 'invalidateDashboardCounts']) {
        t.mock.method(cache, key, async () => {});
    }
    t.mock.method(NodeSSH.prototype, 'connect', async () => { calls.sshConnections++; });
    t.mock.method(NodeSSH.prototype, 'disconnect', () => {});
    t.mock.method(NodeSSH.prototype, 'uploadContent', async (content, path) => { calls.uploads.push({ content, path }); });
    t.mock.method(NodeSSH.prototype, 'exec', async () => ({ stdout: '' }));
    t.mock.method(configGenerator, 'generateXrayConfigWithApi', () => {
        calls.generated++;
        return JSON.stringify({ inbounds: [], outbounds: [], routing: { rules: [] } });
    });
    t.mock.method(syncService, '_agentRequest', async (_node, method, path, payload) => {
        calls.agent.push({ method, path, payload });
        return { data: {} };
    });
    return calls;
}

test('connected portal/relay/bridge topology owns full config, never regenerates or restarts, but syncs users', async t => {
    const calls = stubSync(t);
    await withFlags([true, true, true], async () => {
        for (const role of ['portal', 'relay', 'bridge']) {
            assert.equal(await syncService.updateXrayNodeConfig(node(role)), true);
        }
    });
    assert.equal(calls.generated, 0);
    assert.deepEqual(calls.uploads, []);
    assert.equal(calls.sshConnections, 0);
    assert.deepEqual(calls.agent.map(c => c.path), ['/sync', '/sync', '/sync']);
    for (const request of calls.agent) {
        assert.deepEqual(request.payload.users, [{ id: 'uuid-1', email: 'u1', flow: 'xtls-rprx-vision' }]);
    }
    assert.equal(calls.queries.length, 3);
    for (const query of calls.queries) {
        assert.equal(query.active, true);
        assert.deepEqual(query.$or, [{ portalNode: '507f1f77bcf86cd799439011' }, { bridgeNode: '507f1f77bcf86cd799439011' }]);
    }
});

test('connected topology node without agent does not fall back to SSH restart', async t => {
    const calls = stubSync(t);
    const relay = node('relay');
    delete relay.xray.agentToken;
    await withFlags([true, true, true], async () => {
        assert.equal(await syncService.updateXrayNodeConfig(relay), true);
    });
    assert.equal(calls.generated, 0);
    assert.equal(calls.sshConnections, 0);
    assert.deepEqual(calls.uploads, []);
    assert.deepEqual(calls.agent, []);
});

test('prepared unconnected portal keeps ordinary full config upload, restart and user sync', async t => {
    const calls = stubSync(t, { connected: false });
    await withFlags([true, true, true], async () => {
        assert.equal(await syncService.updateXrayNodeConfig(node()), true);
    });
    assert.equal(calls.generated, 1);
    assert.equal(calls.uploads.length, 1);
    assert.equal(calls.uploads[0].path, '/usr/local/etc/xray/config.json');
    assert.deepEqual(calls.agent.map(c => c.path), ['/restart', '/sync']);
});

test('each disabled topology flag and non-topology role retain classic sync', async t => {
    const calls = stubSync(t);
    for (let i = 0; i < FLAGS.length; i++) {
        const flags = [true, true, true]; flags[i] = false;
        await withFlags(flags, async () => {
            assert.equal(await syncService.updateXrayNodeConfig(node('relay')), true);
        });
    }
    await withFlags([true, true, true], async () => {
        assert.equal(await syncService.updateXrayNodeConfig(node('standalone')), true);
    });
    assert.equal(calls.generated, 4);
    assert.equal(calls.uploads.length, 4);
    assert.deepEqual(calls.agent.map(c => c.path), ['/restart', '/sync', '/restart', '/sync', '/restart', '/sync', '/restart', '/sync']);
    assert.deepEqual(calls.queries, []);
});
