'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { isDeepStrictEqual } = require('node:util');
const express = require('express');
const { mongo: { BSON }, Types: { ObjectId } } = require('mongoose');
const { request } = require('./helpers/rebuildPanelRequest');
const Link = require('../../models/cascadeLinkModel');
const Node = require('../../models/hyNodeModel');
const cascade = require('../cascadeService');
const mcp = require('../../mcp/tools/cascade');
const router = require('../../routes/cascade');
const { createRebuildService } = require('../rebuildService');
const { generateXrayConfigWithApi } = require('../configGenerator');
const { createCascadeLinksRouter, readLinkSnapshot } = require('../../routes/cascadeLinks');

test.after(() => require('../sshPoolService').closeAll());

const clone = record => BSON.deserialize(BSON.serialize(record));
const equal = (a, b) => a instanceof ObjectId ? a.equals(b) : isDeepStrictEqual(a?.toBSON?.() ?? a, b);
const matches = (row, filter) => Object.entries(filter).every(([key, want]) => {
    if (key === '$or') return want.some(part => matches(row, part));
    const got = key.split('.').reduce((value, path) => value?.[path], row);
    if (want?.$in) return want.$in.some(item => item === null ? got == null : equal(item, got));
    if (want?.$exists !== undefined) return (got !== undefined) === want.$exists;
    if (want?.$ne !== undefined) return !equal(want.$ne, got);
    if (want?.$type === 'null') return got === null;
    if (want?.$not) return !matches(row, { [key]: want.$not });
    if (want?.$nin) return !want.$nin.some(item => equal(item, got));
    return want === null ? got == null : equal(want, got);
});
function find(records, filter, { projection } = {}) {
    return records.filter(row => matches(row, filter)).map(row => {
        if (!projection) return clone(row);
        const inclusive = Object.values(projection).includes(1);
        return clone(Object.fromEntries(Object.entries(row).filter(([key]) =>
            inclusive ? key === '_id' || projection[key] === 1 : projection[key] !== 0)));
    });
}

test('real Apply settlement publishes only mKCP configuration state through REST, graph and MCP', async t => {
    const nodes = ['portal', 'relay', 'bridge'].map((cascadeRole, i) => ({
        _id: new ObjectId(), name: `node-${i}`, ip: `192.0.2.${i + 1}`, type: 'xray', active: true,
        cascadeRole, xrayVersion: '26.6.1', port: 20000 + i, xray: { security: 'none', transport: 'tcp', inboundTag: 'client', apiPort: 23000 + i },
    }));
    const rows = ['forward', 'reverse'].map((mode, i) => ({ _id: new ObjectId(), name: mode, mode,
        portalNode: nodes[i]._id, bridgeNode: nodes[i + 1]._id, status: 'pending', active: true,
        tunnelPort: 43119 + i, tunnelUuid: `00000000-0000-4000-8000-00000000000${i}`, tunnelProtocol: 'vless',
        tunnelTransport: 'kcp', tunnelSecurity: 'none', tunnelEncryption: 'none', rebuildApplied: null }));
    for (const [model, records] of [[Link, rows], [Node, nodes]]) {
        t.mock.method(model.collection, 'find', (filter, options) => ({ toArray: async () => find(records, filter, options) }));
        t.mock.method(model.collection, 'findOne', async (filter, options) => find(records, filter, options)[0] ?? null);
    }
    for (const model of [require('../../modules/relay-l2tp/models/cascadeTopologyStateModel'), require('../../models/settingsModel')]) {
        t.mock.method(model.collection, 'findOne', async () => null);
    }
    const session = new class FixtureTransaction {}();
    t.mock.method(Link.db, 'transaction', work => work(session));
    const writes = t.mock.method(Link.collection, 'updateOne', async (filter, update) => {
        const row = rows.find(row => matches(row, filter));
        if (row) {
            Object.assign(row, clone(update.$set));
            for (const key of Object.keys(update.$unset || {})) delete row[key];
        }
        return { acknowledged: true, matchedCount: Number(!!row), modifiedCount: Number(!!row) };
    });
    t.mock.method(Link.collection, 'updateMany', async filter => {
        assert.ok(!rows.some(row => matches(row, filter)), 'cleanup must not target the mKCP rows');
        return { acknowledged: true, matchedCount: 0, modifiedCount: 0 };
    });
    const profiles = new Map(nodes.map(node => [String(node._id), { main: JSON.parse(generateXrayConfigWithApi(node, [])), bridge: null }]));
    const service = createRebuildService({ Link, Node, State: { find: () => ({ select() { return this; }, lean: async () => [] }) },
        env: { C3_REBUILD_ENABLED: 'true', PANEL_DOMAIN: 'panel.fixture.invalid' },
        locks: { run: work => work(async () => {}) }, assertNoRelayAccountIntent: async () => {},
        sync: { _getUsersForNode: async () => [] }, cache: { invalidateAllSubscriptions: async () => {} },
        connect(node) {
            const current = profiles.get(String(node._id));
            return { async requireSupportedCore() {}, async close() {}, async stagePair() {},
                async read(profile) { return structuredClone(current[profile]); },
                async putPair(pair) { for (const { profile, config } of pair) current[profile] = structuredClone(config); } };
        },
    });
    const linkId = String(rows[0]._id);
    const preview = await service.execute({ linkId, preview: true });
    assert.equal(preview.allowed, true);
    assert.equal(writes.mock.callCount(), 0);
    await service.execute({ linkId, expectedPreview: preview.previewId });
    assert.equal(writes.mock.callCount(), 2);
    for (const row of rows) assert.match(row.rebuildKcpApplied, /^[a-f0-9]{64}$/);

    const env = process.env.C3_REBUILD_ENABLED;
    t.after(() => { if (env === undefined) delete process.env.C3_REBUILD_ENABLED; else process.env.C3_REBUILD_ENABLED = env; });

    t.mock.method(require('../webhookService'), 'emit', () => {});
    const counters = [[cascade, '_measureTcpLatency'], [cascade, '_checkTunnel'], [require('../syncService'), 'readRebuildReverseObservation']]
        .map(([target, key]) => t.mock.method(target, key, async () => assert.fail('unexpected probe')));
    for (const rebuild of [true, false]) {
        process.env.C3_REBUILD_ENABLED = String(rebuild);
        // The list/detail router deliberately pins its mode at construction.
        const app = express();
        app.use('/cascade/links', createCascadeLinksRouter({ deploymentEnv: process.env }));
        app.use('/cascade', router);
        const get = async path => {
            const res = await request(app, `/cascade/${path}`, { method: 'GET', session: { authenticated: true } });
            assert.equal(res.status, 200, path);
            return JSON.parse(res.body);
        };
        await cascade.healthCheckAll();
        await cascade.healthCheckRebuildReverse();
        const expected = rebuild ? 'deployed' : 'pending';
        const reason = rebuild ? 'mkcp_runtime_unsupported' : 'mkcp_apply_unconfirmed';
        const list = await get(`links?status=${expected}`);
        assert.equal(list.links.length, 2);
        assert.equal((await get('links?status=online')).links.length, 0);
        const map = await get('topology');
        const mcpMap = await mcp.getTopology();
        for (const row of rows) {
            const id = String(row._id), health = await get(`links/${id}/health`), detail = await get(`links/${id}`);
            assert.equal(health.healthy, false);
            const projections = [health, detail, list.links.find(link => link._id === id),
                map.edges.find(edge => edge.data.linkId === id).data, (await mcp.queryCascade({ id })).link,
                mcpMap.links.find(link => String(link._id) === id)];
            for (const entry of projections) {
                assert.deepEqual([entry.status, entry.tunnelState, entry.tunnelVerification], [expected, 'unknown', reason]);
                assert.equal(entry.observationExpiresAt, undefined);
                assert.equal(entry.rebuildKcpApplied, undefined);
            }
            assert.equal(detail.applicationState, rebuild ? 'applied' : 'reconcile_required');
        }
        let lookedUp = false;
        const snapshot = await readLinkSnapshot({ Link, revisions: { revision: 1, deployedRevision: 1 }, rebuild,
            readLinkApplicationState: async () => { lookedUp = true; return []; } });
        assert.equal(lookedUp, false);
        assert.ok(snapshot.links.every(link => link.tunnelState === 'unknown' && !link.clientReadiness));
        assert.equal(writes.mock.callCount(), 2, 'health reads and sweeps never publish mKCP status');
        assert.ok(counters.every(probe => probe.mock.callCount() === 0));
    }

    // The old KCP stamp is not an Apply receipt for the saved TCP profile.
    const forward = rows[0];
    Object.assign(forward, { status: 'pending', tunnelTransport: 'tcp' });
    process.env.C3_REBUILD_ENABLED = 'true';
    const next = await service.execute({ linkId, preview: true });
    await service.execute({ linkId, expectedPreview: next.previewId });
    assert.equal(forward.rebuildKcpApplied, undefined);
    assert.equal(forward.status, 'deployed');
    counters[0].mock.mockImplementation(async () => 2);
    assert.equal(await cascade.healthCheckLink(clone(forward)), true, 'accepted TCP forward health still works');
    assert.equal(forward.status, 'online');

    // Test the actual update predicate after a TCP probe has already started.
    counters[0].mock.mockImplementation(async () => {
        forward.tunnelTransport = 'kcp';
        return 2;
    });
    const stale = clone(forward);
    assert.equal(await cascade.healthCheckLink(stale), false);
    assert.ok(matches(forward, { tunnelTransport: 'kcp' }));
    assert.equal(forward.lastHealthCheck.getTime(), stale.lastHealthCheck.getTime());

    // Preserve the established reverse TCP/REALITY contract using the real
    // consumer. Only the receiver's authenticated wire reply is modeled here.
    const { createReverseObserver, projectLinkHealth } = require('../rebuildReverseLinkHealth');
    const tcp = { ...rows[1], _id: new ObjectId(), tunnelTransport: 'tcp', tunnelSecurity: 'reality' };
    delete tcp.rebuildKcpApplied;
    rows.push(tcp);
    const receiver = { ip: nodes[1].ip, xray: { agentToken: 'fixture-token' } };
    let requests = 0;
    const observer = createReverseObserver({ Link,
        Node: { findOne: () => ({ select() { return this; }, maxTimeMS() { return this; }, lean: async () => receiver }) },
        request: async (node, path) => {
            requests++;
            const url = new URL(path, 'http://fixture.invalid');
            assert.equal(node, receiver);
            assert.equal(url.pathname, `/rebuild/reverse-observation/${tcp._id}`);
            return { status: 200, headers: { 'content-type': 'application/json' }, data: JSON.stringify({
                version: 1, linkId: String(tcp._id), port: tcp.tunnelPort,
                challenge: url.searchParams.get('challenge'), established: true,
            }) };
        },
    });
    const healthy = await observer.manual(tcp._id);
    assert.equal(requests, 1);
    assert.equal(healthy, true);
    assert.equal(projectLinkHealth(tcp, true).status, 'online');
    assert.equal(projectLinkHealth({ ...tcp, tunnelTransport: 'kcp' }, true).status, 'pending');
    assert.equal(projectLinkHealth({ ...tcp, tunnelSecurity: 'none' }, true).status, 'deployed');
    assert.equal(projectLinkHealth({ ...tcp, rebuildApplyEpoch: 'a'.repeat(32) }, true).status, 'deployed');
});
