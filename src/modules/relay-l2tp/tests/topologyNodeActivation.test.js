'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {fixture, id} = require('./cascadeAnyOrderSelectedApply.test');
const apply = (f,n) => f.coordinator.queue({expectedTopologyRevision: f.CascadeTopologyState.rows[0].revision, scope: {kind: 'link.apply', linkId:id(n), linkIds:[id(n)]}});

// Explicit node metadata activation: the anchor is scope, never a link apply.
test('explicit node activation overlays only selected security through coordinator/composer/worker/finalizer', async () => {
    const f = fixture();
    const initial = await apply(f, 11);
    assert.equal((await f.worker.run(initial.operationId)).status, 'succeeded');
    const before = structuredClone(f.TopologyOperation.rows[0].effectiveTopology);
    const portal = f.HyNode.rows.find(n => n._id === id(3));
    portal.xray = { ...portal.xray, security: 'reality', flow: 'xtls-rprx-vision',
        realityDest: 'www.microsoft.com:443', realitySni: ['www.microsoft.com'],
        realityPrivateKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE', realityPublicKey: 'public-key', realityShortIds: ['aabbccdd'],
        wsPath: '/pending-do-not-apply', apiPort: 62000 };
    portal.port = 49999;
    f.CascadeLink.rows[1].tunnelPort = 29999;
    f.CascadeLink.rows[1].tunnelUuid = '33333333-3333-4333-8333-333333333333';
    f.HyNode.rows[3].xray.security = 'tls';
    f.CascadeTopologyState.rows[0].revision++;
    const activation = { nodeId: id(3), targetProfile: 'xray-main' };
    const queued = await f.coordinator.queue({ expectedTopologyRevision: 8,
        scope: { kind: 'link.apply', linkId: id(11), linkIds: [id(11)], nodeActivation: activation } });
    const op = f.TopologyOperation.rows.find(n => n._id === queued.operationId);
    assert.deepEqual(op.nodeActivation, activation);
    assert.deepEqual(op.effectiveTopology.links, before.links);
    const after = op.effectiveTopology.nodes.find(n => n.id === id(3));
    assert.equal(after.xray.security, 'reality');
    assert.equal(after.xray.flow, 'xtls-rprx-vision');
    assert.equal(after.port, 443);
    assert.equal(after.xray.wsPath, undefined);
    assert.equal(after.xray.apiPort, undefined);
    assert.equal(op.effectiveTopology.nodes.find(n => n.id === id(4)).xray.security, 'none');
    const candidate = JSON.parse(Buffer.from(op.nodes.find(n => n.node === id(3)).candidate.bytes));
    assert.equal(candidate.inbounds.find(n => n.protocol === 'vless').streamSettings.security, 'reality');
    assert.equal(candidate.inbounds.some(n => n.port === 29999 || n.port === 49999), false);
    assert.equal((await f.worker.run(queued.operationId)).status, 'succeeded');
    assert.equal(op.heldTopologyAdmission, false);
    assert.equal(f.NodeOperationLock.rows.length, 0);
    assert.equal(f.CascadeLink.rows[1].tunnelPort, 29999);
    assert.equal(f.CascadeLink.rows[1].status, 'deployed');
});
test('explicit node activation refuses wrong node/profile and selected security drift before dispatch', async () => {
    for (const bad of [{ nodeId: id(4), targetProfile: 'xray-main' }, { nodeId: id(3), targetProfile: 'xray-bridge' },
        { nodeId: id(1), targetProfile: 'xray-main' }, { nodeId: id(3), targetProfile: 'xray-main', extra: true }]) {
        const f = fixture(); const initial = await apply(f, 11); await f.worker.run(initial.operationId);
        const writes = f.calls.length;
        await assert.rejects(f.coordinator.queue({ expectedTopologyRevision: 7,
            scope: { kind: 'link.apply', linkId: id(11), linkIds: [id(11)], nodeActivation: bad } }));
        assert.equal(f.calls.length, writes);
    }
    const f = fixture(); const initial = await apply(f, 11); await f.worker.run(initial.operationId);
    f.calls.length = 0;
    const queued = await f.coordinator.queue({ expectedTopologyRevision: 7,
        scope: { kind: 'link.apply', linkId: id(11), linkIds: [id(11)], nodeActivation: { nodeId: id(3), targetProfile: 'xray-main' } } });
    f.HyNode.rows[2].xray.security = 'reality';
    assert.equal((await f.worker.run(queued.operationId)).status, 'failed');
    assert.equal(f.calls.length, 0);
});

// Actual product pipeline and public renderer; persistence, execution and cache
// are modeled here. The companion Mongo test exercises HTTP and real persistence.
test('explicit node activation publishes settled source port and security, not saved-only drafts', async t => {
    const savedModules = new Map();
    const stub = (name, exports) => {
        const filename = require.resolve(name);
        savedModules.set(filename, require.cache[filename]);
        require.cache[filename] = { id: filename, filename, loaded: true, exports };
    };
    const settings = { loadBalancing: {}, subscription: {}, routing: { enabled: false } };
    const rendered = new Map();
    stub('../../../services/cacheService', {
        getSettings: async () => settings,
        getSubscription: async (token, format) => rendered.get(`${token}:${format}`) || null,
        setSubscription: async (token, format, value) => { rendered.set(`${token}:${format}`, value); },
    });
    stub('../../../utils/logger', { info() {}, warn() {}, error() {}, debug() {} });
    stub('../../../services/uaStatsService', { track() {} });
    stub('../../../services/webhookService', {});
    stub('../../../middleware/i18n', { getDateLocale: () => 'en-US', normalizeLanguage: () => 'en' });
    const subscriptionFilename = require.resolve('../../../routes/subscription');
    const previousSubscription = require.cache[subscriptionFilename];
    delete require.cache[subscriptionFilename];
    t.after(() => {
        for (const [filename, previous] of savedModules) {
            if (previous) require.cache[filename] = previous;
            else delete require.cache[filename];
        }
        if (previousSubscription) require.cache[subscriptionFilename] = previousSubscription;
        else delete require.cache[subscriptionFilename];
    });
    const { serveSubscription } = require('../../../routes/subscription');
    const { readSettledSelectedOperation } = require('../services/topologySelectedProofState');
    const { SECURITY_FIELDS } = require('../services/topologyNodeActivation');
    const { TEST_TOPOLOGY_EXECUTION_CONTEXT: executionContext } = require('../domain/topologyExecutionContext');
    const f = fixture(), phases = [], mismatches = [];
    // Assembly seam only: calls the real repository, not a fabricated applied flag.
    stub('../../../modules/l2tpActiveHostProvider', { l2tpActiveHostProvider: { getActiveHost: () => ({
        readAppliedNodePublication: input => f.deployment.readAppliedNodePublication({ ...input, executionContext }),
    }) } });
    const portal = f.HyNode.rows.find(n => n._id === id(3));
    portal.name = 'publication-fixture-portal';
    const originalSecurity = structuredClone(portal.xray);
    const user = { userId: 'publication-fixture-user', enabled: true,
        xrayUuid: '11111111-1111-4111-8111-111111111111', nodes: [portal], groups: [] };
    const candidate = op => JSON.parse(Buffer.from(op.nodes.find(n => n.node === id(3)).candidate.bytes))
        .inbounds.find(n => n.protocol === 'vless');
    const project = inbound => ({ port: inbound.port, network: inbound.streamSettings.network,
        security: inbound.streamSettings.security });
    const publish = async (phase, op, token = phase) => {
        let body;
        const res = { locals: { lang: 'en' }, statusCode: 200, set() { return this; },
            type() { return this; }, status(code) { this.statusCode = code; return this; },
            send(value) { body = value; return this; } };
        await serveSubscription({ headers: { 'user-agent': 'Happ/1.0 (Android)', accept: 'application/json' },
            query: { format: 'xray-json' } }, res, { user, cacheToken: `publication-fixture-${token}`,
            baseUrl: 'http://127.0.0.1/not-requested' });
        assert.equal(res.statusCode, 200, 'ordinary availability predicates must be preserved');
        const profile = JSON.parse(body)[0];
        const proxy = profile.outbounds.find(n => n.protocol === 'vless');
        const expected = project(candidate(op));
        const actual = { port: proxy.settings.vnext[0].port, network: proxy.streamSettings.network,
            security: proxy.streamSettings.security || 'none' };
        const uuidPreserved = proxy.settings.vnext[0].users[0].id === user.xrayUuid;
        const realityAuthPreserved = actual.security === 'reality' ? (
            proxy.streamSettings.realitySettings.publicKey === 'public-key'
            && proxy.streamSettings.realitySettings.serverName === 'www.microsoft.com'
            && proxy.streamSettings.realitySettings.shortId === 'aabbccdd') : null;
        assert.equal(uuidPreserved, true);
        if (actual.security === 'reality') assert.equal(realityAuthPreserved, true);
        phases.push({ phase, expected, actual, uuidPreserved, realityAuthPreserved });
        if (JSON.stringify(actual) !== JSON.stringify(expected)) mismatches.push(phase);
    };
    const run = async queued => {
        assert.equal((await f.worker.run(queued.operationId)).status, 'succeeded');
        const op = f.TopologyOperation.rows.find(n => n._id === queued.operationId);
        assert.equal(op.heldTopologyAdmission, false);
        assert.equal(f.NodeOperationLock.rows.length, 0);
        return op;
    };
    const activate = () => f.coordinator.queue({ expectedTopologyRevision: f.CascadeTopologyState.rows[0].revision,
        scope: { kind: 'link.apply', linkId: id(11), linkIds: [id(11)],
            nodeActivation: { nodeId: id(3), targetProfile: 'xray-main' } } });
    const initial = await run(await apply(f, 11));
    await publish('initial', initial, 'warm');
    portal.port = 49999;
    portal.xray = { ...portal.xray, security: 'reality', flow: 'xtls-rprx-vision',
        realityDest: 'www.microsoft.com:443', realitySni: ['www.microsoft.com'],
        realityPrivateKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE', realityPublicKey: 'public-key',
        realityShortIds: ['aabbccdd'], wsPath: '/saved-only' };
    f.CascadeLink.rows[1].tunnelPort = 29999;
    f.CascadeTopologyState.rows[0].revision++;
    const activated = await run(await activate());
    assert.deepEqual(project(candidate(activated)), { port: 443, network: 'tcp', security: 'reality' });
    const proofReaderAfterActivation = Boolean(await readSettledSelectedOperation(f.deployment, activated));
    await publish('activation-cold-exact-B1', activated);
    await publish('activation-warm-versioned-cache', activated, 'warm');
    portal.xray.transport = 'ws';
    portal.xray.security = 'none';
    f.CascadeTopologyState.rows[0].revision++;
    const proofReaderWithSavedSecurityDraft = Boolean(await readSettledSelectedOperation(f.deployment, activated));
    assert.equal(proofReaderAfterActivation, true);
    assert.equal(proofReaderWithSavedSecurityDraft, false, 'client-proof desiredVersion guard stays strict');
    await publish('saved-only-selected-port-transport-security', activated);
    await publish('saved-only-warm-cache', activated, 'warm');
    for (const key of SECURITY_FIELDS) delete portal.xray[key];
    for (const key of SECURITY_FIELDS) if (originalSecurity[key] !== undefined) portal.xray[key] = originalSecurity[key];
    f.CascadeTopologyState.rows[0].revision++;
    const restored = await run(await activate());
    assert.deepEqual(project(candidate(restored)), { port: 443, network: 'tcp', security: 'none' });
    await publish('restored-source-security', restored);
    await publish('restored-source-warm-cache', restored, 'warm');
    assert.equal(portal.port, 49999);
    assert.equal(portal.xray.transport, 'ws');
    assert.equal(portal.xray.wsPath, '/saved-only');
    assert.equal(f.CascadeLink.rows[1].tunnelPort, 29999);
    console.log('PUBLICATION_B1_RECEIPT ' + JSON.stringify({ phases, mismatches,
        proofReaderAfterActivation, proofReaderWithSavedSecurityDraft, physicalAcceptance: false }));
    assert.deepEqual(mismatches, []);
    const activatedSecurity = activated.effectiveTopology.nodes.find(n => n.id === id(3)).xray;
    for (const key of SECURITY_FIELDS) if (activatedSecurity[key] !== undefined) portal.xray[key] = activatedSecurity[key];
    f.CascadeTopologyState.rows[0].revision++;
    const queuedOnly = await activate();
    await publish('new-pending-operation-keeps-settled-source', restored);
    assert.equal(f.TopologyOperation.rows.find(n => n._id === queuedOnly.operationId).status, 'queued');
    const entry = restored.nodes.find(n => n.node === id(3)), oldByte = entry.candidate.bytes[0];
    entry.candidate.bytes[0] ^= 1;
    await assert.rejects(f.deployment.readAppliedNodePublication({ nodeIds: [id(3)], executionContext }),
        /Invalid canonical Xray topology candidate|applied baseline/);
    entry.candidate.bytes[0] = oldByte;
});
