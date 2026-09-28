'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);

const cascadeService = require('../cascadeService');
const syncService = require('../syncService');
const CascadeLink = require('../../models/cascadeLinkModel');
const configGenerator = require('../configGenerator');
const NodeSSH = require('../nodeSSH');
const sshPool = require('../sshPoolService');
test.after(() => sshPool.closeAll());

function stubPortalDeployment(t, agentError) {
    const calls = { uploads: [], execs: [], agent: [], statuses: [], connections: 0 };
    t.mock.method(syncService, '_getUsersForNode', async () => []);
    t.mock.method(configGenerator, 'generateXrayConfigWithApi', () => JSON.stringify({
        inbounds: [], outbounds: [], routing: { rules: [] },
    }));
    t.mock.method(CascadeLink, 'find', () => Object.assign(Promise.resolve([]), {
        populate: async () => [],
    }));
    t.mock.method(CascadeLink, 'updateOne', async (_query, update) => {
        calls.statuses.push(update.$set);
    });
    t.mock.method(NodeSSH.prototype, 'connect', async () => { calls.connections++; });
    t.mock.method(NodeSSH.prototype, 'uploadContent', async (...args) => { calls.uploads.push(args); });
    t.mock.method(NodeSSH.prototype, 'exec', async command => { calls.execs.push(command); });
    t.mock.method(NodeSSH.prototype, 'disconnect', () => {});
    t.mock.method(syncService, '_agentRequest', async (_node, method, path) => {
        calls.agent.push([method, path]);
        throw agentError;
    });
    return calls;
}

function portal() {
    return {
        _id: '507f1f77bcf86cd799439011', name: 'test portal', type: 'xray',
        ssh: { password: 'mock-only' }, xray: { agentToken: 'mock-only' },
    };
}

test('explicit cc-agent HTTP restart refusal never triggers SSH restart or reports link deployed', async t => {
    const refusal = new Error('Agent request failed (HTTP 403)');
    refusal.code = 'AGENT_HTTP_ERROR';
    refusal.status = 403;
    const calls = stubPortalDeployment(t, refusal);
    const result = await cascadeService.deployLink({
        _id: '507f1f77bcf86cd799439012', name: 'test link',
        portalNode: portal(), bridgeNode: { _id: '507f1f77bcf86cd799439013' },
    });

    assert.deepEqual(calls.agent, [['POST', '/restart']]);
    assert.equal(calls.uploads.length, 1, 'the earlier config upload is independent of the restart refusal');
    assert.deepEqual(calls.execs, [], 'SSH must not override an explicit agent denial');
    assert.equal(calls.connections, 1, 'only the prior config upload may connect via SSH');
    assert.equal(result.success, false);
    assert.match(result.error, /HTTP 403/);
    assert.equal(calls.statuses.at(-1).status, 'error');
    assert.ok(!calls.statuses.some(s => ['online', 'deployed'].includes(s.status)));
});

test('HTTP 423 refusal also propagates without an SSH restart', async t => {
    const refusal = new Error('[Agent] HTTP 423 for node test portal');
    refusal.code = 'AGENT_HTTP_ERROR';
    const calls = stubPortalDeployment(t, refusal);
    await assert.rejects(cascadeService._deployPortalConfig(portal()), err => err === refusal);
    assert.deepEqual(calls.agent, [['POST', '/restart']]);
    assert.equal(calls.uploads.length, 1);
    assert.equal(calls.connections, 1);
    assert.deepEqual(calls.execs, []);
});

test('agent transport failure retains legacy SSH restart fallback', async t => {
    const calls = stubPortalDeployment(t, new Error('ECONNRESET'));
    await cascadeService._deployPortalConfig(portal());
    assert.deepEqual(calls.agent, [['POST', '/restart']]);
    assert.equal(calls.uploads.length, 1);
    assert.equal(calls.connections, 2);
    assert.deepEqual(calls.execs, ['systemctl restart xray']);
});

test('no-agent portal retains direct SSH restart', async t => {
    const calls = stubPortalDeployment(t, new Error('agent should not be called'));
    const node = portal();
    delete node.xray.agentToken;
    await cascadeService._deployPortalConfig(node);
    assert.deepEqual(calls.agent, []);
    assert.equal(calls.uploads.length, 1);
    assert.equal(calls.connections, 2);
    assert.deepEqual(calls.execs, ['systemctl restart xray']);
});
