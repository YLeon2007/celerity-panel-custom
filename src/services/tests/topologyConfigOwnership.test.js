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
const TopologyOperation = require('../../modules/relay-l2tp/models/topologyOperationModel');
const cascadeService = require('../cascadeService');
const sift = require('sift').default;
const NodeSSH = require('../nodeSSH');
const configGenerator = require('../configGenerator');
const nodeSetup = require('../nodeSetup');
const RelayL2tpState = require('../../modules/relay-l2tp/models/relayL2tpStateModel');
const cache = require('../cacheService');
after(() => sshPool.closeAll());

const FLAGS = ['L2TP_EXECUTION_ENABLED', 'L2TP_MIGRATIONS_ENABLED', 'TOPOLOGY_TEST_EXECUTION_ENABLED'];
async function withEnv(values, fn) {
    const prior = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
    try {
        for (const [key, value] of Object.entries(values)) {
            if (value === undefined) delete process.env[key]; else process.env[key] = value;
        }
        return await fn();
    } finally {
        for (const [key, value] of Object.entries(prior)) {
            if (value === undefined) delete process.env[key]; else process.env[key] = value;
        }
    }
}
async function withFlags(values, fn) {
    return withEnv({ PANEL_DOMAIN: 'test.infograd.online',
        ...Object.fromEntries(FLAGS.map((key, i) => [key, values[i] ? 'true' : undefined])),
    }, fn);
}

function node(role = 'portal') {
    return { _id: '507f1f77bcf86cd799439011', name: 'test node', ip: '127.0.0.1', type: 'xray', cascadeRole: role,
        ssh: { password: 'test' }, xray: { agentToken: 'test', transport: 'tcp', security: 'reality' } };
}

function stubSync(t, { connected = true, linkStatuses = ['deployed'], links = [], operations = [] } = {}) {
    const calls = { queries: [], updates: [], uploads: [], sshConnections: 0, agent: [], generated: 0 };
    t.mock.method(TopologyOperation, 'exists', async query => operations.find(sift(query)) || null);
    t.mock.method(CascadeLink, 'exists', async query => {
        calls.queries.push(query);
        return connected && linkStatuses.some(status => !query.status || query.status.$in?.includes(status))
            ? { _id: 'link-1' } : null;
    });
    t.mock.method(HyNode, 'updateOne', async (_query, update) => { calls.updates.push(update); return {}; });
    t.mock.method(CascadeLink, 'find', query => {
        const found = links.filter(link => Object.entries(query).every(([key, value]) => {
            if (key === 'status') return value.$in ? value.$in.includes(link.status) : value.$ne !== link.status;
            return link[key] === value;
        }));
        return Object.assign(Promise.resolve(found), { populate: async () => found });
    });
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
        assert.deepEqual(query.status, { $in: ['staged', 'deployed', 'online'] });
        assert.deepEqual(query.$or, [{ portalNode: '507f1f77bcf86cd799439011' }, { bridgeNode: '507f1f77bcf86cd799439011' }]);
    }
});

test('managed node without agent fails closed without falling back to SSH restart', async t => {
    const calls = stubSync(t);
    const relay = node('relay');
    delete relay.xray.agentToken;
    await withFlags([true, true, true], async () => {
        assert.equal(await syncService.updateXrayNodeConfig(relay), false);
    });
    assert.equal(calls.generated, 0);
    assert.equal(calls.sshConnections, 0);
    assert.deepEqual(calls.uploads, []);
    assert.deepEqual(calls.agent, []);
    assert.equal(calls.updates.at(-1).$set.status, 'error');
    assert.match(calls.updates.at(-1).$set.lastError, /no agent token/);
});

test('managed node with failing user sync fails closed and never reports online', async t => {
    const calls = stubSync(t);
    t.mock.method(syncService, '_agentRequest', async () => { throw new Error('agent /sync unavailable'); });
    await withFlags([true, true, true], async () => {
        assert.equal(await syncService.updateXrayNodeConfig(node()), false);
    });
    assert.equal(calls.generated, 0);
    assert.equal(calls.sshConnections, 0);
    assert.deepEqual(calls.uploads, []);
    assert.equal(calls.updates.at(-1).$set.status, 'error');
    assert.match(calls.updates.at(-1).$set.lastError, /agent \/sync unavailable/);
});

test('pending-only prepared portal still receives its initial classic config', async t => {
    const calls = stubSync(t, { linkStatuses: ['pending'] });
    await withFlags([true, true, true], async () => {
        assert.equal(await syncService.updateXrayNodeConfig(node()), true);
    });
    assert.equal(calls.generated, 1);
    assert.equal(calls.uploads.length, 1);
    assert.equal(calls.uploads[0].path, '/usr/local/etc/xray/config.json');
    assert.deepEqual(calls.agent.map(c => c.path), ['/restart', '/sync']);
});

test('pending-only links never add reverse, forward or hop topology to initial classic config', async t => {
    const id = node()._id;
    const links = [
        { _id: 'reverse-draft', portalNode: id, bridgeNode: 'bridge-a', mode: 'reverse', active: true, status: 'pending' },
        { _id: 'forward-draft', portalNode: id, bridgeNode: 'bridge-b', mode: 'forward', active: true, status: 'pending' },
        { _id: 'hop-draft', portalNode: 'upstream', bridgeNode: id, mode: 'forward', active: true, status: 'pending' },
    ];
    const calls = stubSync(t, { linkStatuses: ['pending'], links });
    const applied = [];
    for (const method of ['applyReversePortal', 'applyForwardChain', 'applyForwardHopInbound']) {
        t.mock.method(configGenerator, method, () => { applied.push(method); });
    }
    await withFlags([true, true, true], async () => {
        assert.equal(await syncService.updateXrayNodeConfig(node()), true);
    });
    assert.deepEqual(applied, []);
    assert.equal(calls.uploads.length, 1);
    assert.deepEqual(calls.agent.map(c => c.path), ['/restart', '/sync']);
});

test('legacy sync with a disabled topology flag still applies pending classic links', async t => {
    const id = node()._id;
    const links = [
        { _id: 'reverse-draft', portalNode: id, bridgeNode: 'bridge-a', mode: 'reverse', active: true, status: 'pending' },
        { _id: 'forward-draft', portalNode: id, bridgeNode: 'bridge-b', mode: 'forward', active: true, status: 'pending' },
        { _id: 'hop-draft', portalNode: 'upstream', bridgeNode: id, mode: 'forward', active: true, status: 'pending' },
    ];
    const calls = stubSync(t, { links });
    const applied = [];
    for (const method of ['applyReversePortal', 'applyForwardChain', 'applyForwardHopInbound']) {
        t.mock.method(configGenerator, method, () => { applied.push(method); });
    }
    await withFlags([true, true, false], async () => {
        assert.equal(await syncService.updateXrayNodeConfig(node()), true);
    });
    assert.deepEqual(applied, ['applyReversePortal', 'applyForwardChain', 'applyForwardHopInbound']);
    assert.equal(calls.uploads.length, 1);
});

test('forward-chain resolver excludes draft downstream hops only when status-limited', async t => {
    const id = node()._id;
    stubSync(t, { links: [
        { _id: 'first', portalNode: id, bridgeNode: 'mid', mode: 'forward', active: true, status: 'deployed' },
        { _id: 'draft', portalNode: 'mid', bridgeNode: 'end', mode: 'forward', active: true, status: 'pending' },
    ] });
    assert.deepEqual((await syncService._getForwardChainLinks(id, ['staged', 'deployed', 'online'])).map(l => l._id), ['first']);
    assert.deepEqual((await syncService._getForwardChainLinks(id)).map(l => l._id), ['first', 'draft']);
});

test('a confirmed applied link protects config even with a pending sibling', async t => {
    const id = node()._id;
    const calls = stubSync(t, { linkStatuses: ['pending', 'staged'], links: [
        { _id: 'applied', portalNode: id, bridgeNode: 'bridge-a', mode: 'reverse', active: true, status: 'staged' },
        { _id: 'draft', portalNode: id, bridgeNode: 'bridge-b', mode: 'forward', active: true, status: 'pending' },
    ] });
    const applied = [];
    for (const method of ['applyReversePortal', 'applyForwardChain', 'applyForwardHopInbound']) {
        t.mock.method(configGenerator, method, () => { applied.push(method); });
    }
    await withFlags([true, true, true], async () => {
        assert.equal(await syncService.updateXrayNodeConfig(node()), true);
    });
    assert.deepEqual(applied, []);
    assert.equal(calls.generated, 0);
    assert.deepEqual(calls.uploads, []);
    assert.deepEqual(calls.agent.map(c => c.path), ['/sync']);
});

test('online applied links retain topology ownership', async t => {
    const calls = stubSync(t, { linkStatuses: ['online'] });
    await withFlags([true, true, true], async () => {
        assert.equal(await syncService.updateXrayNodeConfig(node('bridge')), true);
    });
    assert.equal(calls.generated, 0);
    assert.deepEqual(calls.uploads, []);
    assert.deepEqual(calls.agent.map(c => c.path), ['/sync']);
});

test('legacy classic sync preserves its result on failed agent user sync', async t => {
    const calls = stubSync(t, { connected: false });
    t.mock.method(syncService, '_agentRequest', async (_node, _method, path) => {
        if (path === '/sync') throw new Error('agent /sync unavailable');
        return { data: {} };
    });
    await withFlags([true, true, true], async () => {
        assert.equal(await syncService.updateXrayNodeConfig(node()), true);
    });
    assert.equal(calls.generated, 1);
    assert.equal(calls.uploads.length, 1);
    assert.equal(calls.updates.at(-1).$set.status, 'online');
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

test('PROD with all TEST flags preserves legacy config even when production execution is opted in', async t => {
    const calls = stubSync(t);
    await withFlags([true, true, true], () => withEnv({
        PANEL_DOMAIN: 'lm1.infograd.online', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true',
    }, async () => {
        assert.equal(await syncService.updateXrayNodeConfig(node('relay')), true);
    }));
    assert.equal(calls.generated, 1, 'execution flags are not per-node adoption evidence');
    assert.equal(calls.uploads.length, 1);
    assert.deepEqual(calls.agent.map(call => call.path), ['/restart', '/sync']);
});

function legacyLinks(status) {
    const id = node()._id;
    return [
        ...Array.from({ length: 8 }, (_, i) => ({ _id: `reverse-${i}`, portalNode: id,
            bridgeNode: `exit-${i}`, mode: 'reverse', tunnelPort: 11000 + i,
            tunnelUuid: `legacy-reverse-${i}`, active: true, status })),
        { _id: 'forward-out', portalNode: id, bridgeNode: 'downstream', mode: 'forward',
            tunnelPort: 12000, tunnelUuid: 'legacy-forward', active: true, status },
        { _id: 'forward-in', portalNode: 'upstream', bridgeNode: id, mode: 'forward',
            tunnelPort: 13000, tunnelUuid: 'legacy-hop', active: true, status },
    ];
}

for (const writer of ['sync', 'cascade']) {
    test(`${writer}: enabled TEST excludes pending reverse/forward listeners from initial config`, async t => {
        const calls = stubSync(t, { linkStatuses: ['pending'], links: legacyLinks('pending') });
        await withFlags([true, true, true], async () => {
            if (writer === 'sync') await syncService.updateXrayNodeConfig(node('relay'));
            else await cascadeService._deployPortalConfig(node('relay'));
        });
        assert.equal(calls.uploads.length, 1);
        const config = JSON.parse(calls.uploads[0].content);
        assert.deepEqual(config.inbounds, []);
        assert.deepEqual(config.outbounds, []);
    });

    test(`${writer}: PROD TEST flags do not strip pending legacy reverse/forward listeners`, async t => {
        const calls = stubSync(t, { linkStatuses: ['pending'], links: legacyLinks('pending') });
        await withFlags([true, true, true], () => withEnv({ PANEL_DOMAIN: 'lm1.infograd.online' }, async () => {
            if (writer === 'sync') await syncService.updateXrayNodeConfig(node('relay'));
            else await cascadeService._deployPortalConfig(node('relay'));
        }));
        assert.equal(calls.uploads.length, 1);
        const config = JSON.parse(calls.uploads[0].content);
        assert.deepEqual(config.inbounds.map(inbound => inbound.port), [11000, 11001, 11002, 11003, 11004, 11005, 11006, 11007, 13000]);
        assert.equal(config.inbounds.at(-1).settings.clients[0].id, 'legacy-hop');
        assert.equal(config.outbounds[0].settings.vnext[0].users[0].id, 'legacy-forward');
    });

    test(`${writer}: changing panel identity cannot hand back a recorded topology node to classic`, async t => {
        const calls = stubSync(t, { connected: false, operations: [{ status: 'succeeded',
            nodes: [{ node: node()._id, state: 'committed' }] }] });
        await withEnv({ PANEL_DOMAIN: undefined }, async () => {
            if (writer === 'sync') await syncService.updateXrayNodeConfig(node());
            else await cascadeService._deployPortalConfig(node());
        });
        assert.equal(calls.generated, 0);
        assert.deepEqual(calls.uploads, []);
    });

    test(`${writer}: durable node execution evidence protects a new PROD topology config with flags disabled`, async t => {
        const calls = stubSync(t, { connected: false, operations: [{ status: 'succeeded',
            nodes: [{ node: node()._id, state: 'committed' }] }] });
        await withFlags([false, false, false], () => withEnv({ PANEL_DOMAIN: 'lm1.infograd.online',
            TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false' }, async () => {
            if (writer === 'sync') await syncService.updateXrayNodeConfig(node('standalone'));
            else await cascadeService._deployPortalConfig(node('standalone'));
        }));
        assert.equal(calls.generated, 0);
        assert.deepEqual(calls.uploads, []);
        assert.equal(calls.sshConnections, 0);
        assert.deepEqual(calls.agent.map(call => call.path), writer === 'sync' ? ['/sync'] : []);
    });
}

for (const writer of ['sync', 'cascade']) {
    for (const host of ['test.infograd.online', 'lm1.infograd.online', 'unknown.invalid']) {
        for (const enabled of [true, false]) {
            for (const productionOptIn of ['true', 'false']) {
                for (const status of ['pending', 'deployed']) {
                    test(`${writer}: ownership matrix ${host} TEST=${enabled} PROD=${productionOptIn} ${status}`, async t => {
                        const calls = stubSync(t, { linkStatuses: [status], links: legacyLinks(status) });
                        await withFlags([enabled, enabled, enabled], () => withEnv({ PANEL_DOMAIN: host,
                            TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: productionOptIn }, async () => {
                            if (writer === 'sync') await syncService.updateXrayNodeConfig(node('relay'));
                            else await cascadeService._deployPortalConfig(node('relay'));
                        }));
                        const testTopology = enabled && host === 'test.infograd.online';
                        if (testTopology && status === 'deployed') {
                            assert.equal(calls.generated, 0);
                            assert.deepEqual(calls.uploads, []);
                            assert.equal(calls.sshConnections, 0);
                        } else {
                            assert.equal(calls.generated, 1);
                            assert.equal(calls.uploads.length, 1);
                            const config = JSON.parse(calls.uploads[0].content);
                            assert.equal(config.inbounds.length, testTopology ? 0 : 9);
                            assert.equal(config.outbounds.length, testTopology ? 0 : 1);
                            if (!testTopology) {
                                assert.equal(config.inbounds[0].settings.clients[0].id, 'legacy-reverse-0');
                                assert.equal(config.inbounds.at(-1).settings.clients[0].id, 'legacy-hop');
                                assert.equal(config.outbounds[0].settings.vnext[0].users[0].id, 'legacy-forward');
                            }
                        }
                    });
                }
            }
        }
    }
}

for (const [name, operation, expected] of [
    ['queued plan', { status: 'queued', nodes: [{ node: node()._id, state: 'pending' }] }, true],
    ['preparing plan', { status: 'preparing', nodes: [{ node: node()._id, state: 'pending' }] }, true],
    ['uncertain failure', { status: 'failed', nodes: [{ node: node()._id, state: 'failed' }] }, true],
    ['retained terminal admission', { status: 'failed', heldTopologyAdmission: true,
        nodes: [{ node: node()._id, state: 'pending' }] }, true],
    ['prepared node', { status: 'failed', nodes: [{ node: node()._id, state: 'prepared' }] }, true],
    ['rolled-back node', { status: 'rolled_back', nodes: [{ node: node()._id, state: 'rolled_back' }] }, false],
    ['unexecuted failure', { status: 'failed', nodes: [{ node: node()._id, state: 'pending' }] }, false],
    ['foreign committed node', { status: 'succeeded', nodes: [{ node: 'foreign', state: 'committed' }] }, false],
    ['foreign state cannot join local node', { status: 'failed', nodes: [
        { node: node()._id, state: 'pending' }, { node: 'foreign', state: 'committed' }] }, false],
]) {
    test(`PROD operation evidence: ${name}`, async t => {
        stubSync(t, { connected: false, operations: [operation] });
        await withEnv({ PANEL_DOMAIN: 'lm1.infograd.online', TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' }, async () => {
            assert.equal(await syncService._topologyManagesNode(node()), expected);
        });
    });
}

for (const writer of ['sync', 'cascade']) {
    test(`${writer}: selected PROD legacy policy survives a later environment change`, async t => {
        const calls = stubSync(t, { linkStatuses: ['pending'], links: legacyLinks('pending') });
        t.mock.method(syncService, '_getUsersForNode', async () => {
            process.env.PANEL_DOMAIN = 'test.infograd.online';
            return [];
        });
        await withFlags([true, true, true], () => withEnv({ PANEL_DOMAIN: 'lm1.infograd.online' }, async () => {
            if (writer === 'sync') await syncService.updateXrayNodeConfig(node('relay'));
            else await cascadeService._deployPortalConfig(node('relay'));
        }));
        assert.equal(calls.uploads.length, 1);
        assert.equal(JSON.parse(calls.uploads[0].content).inbounds.length, 9);
    });

    test(`${writer}: unreadable durable ownership fails closed before generation or transport`, async t => {
        const calls = stubSync(t);
        t.mock.method(TopologyOperation, 'exists', async () => { throw new Error('ownership unavailable'); });
        await withEnv({ PANEL_DOMAIN: 'lm1.infograd.online' }, async () => {
            await assert.rejects(writer === 'sync'
                ? syncService.updateXrayNodeConfig(node())
                : cascadeService._deployPortalConfig(node()), /ownership unavailable/);
        });
        assert.equal(calls.generated, 0);
        assert.deepEqual(calls.uploads, []);
        assert.equal(calls.sshConnections, 0);
        assert.deepEqual(calls.agent, []);
    });
}
