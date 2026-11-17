'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { MAIN, TRANSIT, IDS, GRAPHS, CREATION_CASES, permutations, createHarness, createNativeHarness, createdId,
    expectApplied, semanticLinks, copy } = require('./cascadeAnyOrderFixtures');

// Same bounded positive cases: G1 retains classic compatibility; multi-hop,
// forward and durable-job scenarios use the existing ordinary native fixture.
// Persistence, executor and RPC are modeled, never physical acceptance evidence.
const forGraph = (t, graph) => (graph.name === 'G1' ? createHarness : createNativeHarness)(t);
const autoStatus = h => h.native ? 202 : 201;
const deployStatus = h => h.native ? 202 : 200;
test.after(() => require('../../../services/sshPoolService').closeAll());
function diagnostic(t, h, action) {
    t.diagnostic(JSON.stringify({ action, coreFailures: h.calls.failures,
        refusal: h.calls.diagnostics.at(-1)?.internalCode,
        retainedNodeLocks: h.rows.NodeOperationLock.length,
        retainedReservation: !!h.state().replacementReservation }));
}
function assertSettled(h) {
    assert.equal(h.rows.NodeOperationLock.length, 0);
    assert.equal(h.state().replacementReservation, undefined);
    assert.equal(h.state().classicLifecycleAttempt, undefined);
    if (h.native) assert.deepEqual(h.users, h.originalUsers, 'native RPC preserves saved subscription identities');
}
function assertDesired(h, graph) {
    assert.deepEqual(semanticLinks(h.rows.CascadeLink), graph.edges.map(edge => ({
        name: edge.key, source: IDS[edge.source], target: IDS[edge.target], mode: 'reverse',
        port: edge.port, priority: edge.priority, geo: edge.geoRouting?.enabled === true,
    })).sort((left, right) => left.name.localeCompare(right.name)));
}

test('enumerates the complete bounded G1-G3 creation matrix programmatically', t => {
    assert.deepEqual(GRAPHS.map(graph => [graph.name, permutations(graph.edges).length]),
        [['G1', 1], ['G2', 2], ['G3', 6]]);
    assert.equal(new Set(CREATION_CASES.map(entry => entry.label)).size, 9);
    for (const entry of CREATION_CASES) t.diagnostic(entry.label);
});

for (const { graph, order, label } of CREATION_CASES) {
    test(`${label}: actual POST AutoDeploy completes without full Sync`, async t => {
        const h = await forGraph(t, graph);
        const roles = copy(h.rows.HyNode);
        for (const edge of order) {
            const response = await h.create(edge, true);
            diagnostic(t, h, `auto ${edge.key}`);
            assert.equal(response.status, autoStatus(h), JSON.stringify(response.body));
            assert.ok(createdId(response), 'successful save must identify the link');
            expectApplied(response, `${label}, ${edge.key}`);
            const saved = (await h.snapshot()).links.find(link => link.name === edge.key);
            assert.ok(['deployed', 'online', 'staged'].includes(saved.status), `${edge.key} never applied`);
            assertSettled(h);
        }
        assertDesired(h, graph);
        assert.deepEqual(h.rows.HyNode, roles, 'CRUD must not rewrite operator roles/credentials');
        assert.equal(h.calls.core.filter(call => call.method === (h.native ? 'link.apply' : 'deployScopedClassicLink')).length, graph.edges.length);
        assert.equal(h.calls.failures.length, 0);
        assert.ok(h.calls.writes.length > 0, 'real worker reaches the modeled candidate commit');
    });

    test(`${label}: save-only accepts every intermediate desired graph without remote writes`, async t => {
        const h = await forGraph(t, graph);
        const before = new Map(h.files);
        for (const edge of order) {
            const response = await h.create(edge, false);
            assert.equal(response.status, 201, JSON.stringify(response.body));
            const snapshot = await h.snapshot();
            assert.equal(snapshot.links.length, order.indexOf(edge) + 1);
            assert.ok(snapshot.links.every(link => link.status === 'pending'));
            assert.equal(response.body.autoDeployResult, undefined);
            assert.equal(response.body.autoDeployOperation, undefined);
            assert.equal(response.body.autoDeployJob, undefined);
        }
        assertDesired(h, graph);
        assert.deepEqual(h.files, before);
        assert.equal(h.calls.transport.length, 0, 'save-only must never construct a transport');
        assert.equal(h.calls.core.length, 0);
        assertSettled(h);
    });

    test(`${label}: save all then explicit manual Deploy in that order`, async t => {
        const h = await forGraph(t, graph);
        const ids = new Map();
        for (const edge of [...order].reverse()) {
            const response = await h.create(edge, false);
            assert.equal(response.status, 201, JSON.stringify(response.body));
            ids.set(edge.key, createdId(response));
        }
        assert.equal(h.calls.transport.length, 0);
        for (const edge of order) {
            const response = await h.deploy(ids.get(edge.key));
            diagnostic(t, h, `manual ${edge.key}`);
            assert.equal(response.status, deployStatus(h), JSON.stringify(response.body));
            if (h.native) expectApplied(response, label);
            else assert.equal(response.body.status, 'succeeded');
            assertSettled(h);
            const stillPending = h.rows.CascadeLink.filter(link => link.status === 'pending').map(link => link._id);
            const selectedScope = h.calls.core.at(-1);
            assert.ok(stillPending.every(linkId => !selectedScope.baselineLinkIds.includes(linkId)),
                'manual Deploy must exclude every unrequested pending neighbor');
        }
        assertDesired(h, graph);
        assert.ok(h.rows.CascadeLink.every(link => ['deployed', 'online', 'staged'].includes(link.status)));
    });
}

for (const method of ['auto', 'manual']) test(`${method}: pending shared-relay branch is never implicitly applied`, async t => {
    const h = await createNativeHarness(t), graph = GRAPHS[2];
    const pending = await h.create(graph.edges[2], false);
    assert.equal(pending.status, 201);
    const pendingId = createdId(pending);
    const branchProfile = h.files.get(`${IDS.B2}:${TRANSIT}`);
    const created = await h.create(graph.edges[0], method === 'auto');
    assert.equal(created.status, method === 'auto' ? 202 : 201, JSON.stringify(created.body));
    if (method === 'auto') expectApplied(created, 'selected prefix');
    else expectApplied(await h.deploy(createdId(created)), 'manual selected prefix');
    const pendingRow = (await h.snapshot()).links.find(link => link._id === pendingId);
    assert.equal(pendingRow.status, 'pending');
    assert.equal(h.files.get(`${IDS.B2}:${TRANSIT}`), branchProfile);
    assert.ok(h.calls.core.every(call => call.linkId !== pendingId && !call.baselineLinkIds.includes(pendingId)));
    assert.ok([...h.files.values()].every(bytes => !bytes.includes(pendingId.slice(-8))),
        'unrequested branch tags must not enter any generated profile');
    assertSettled(h);
});

test('G1 manual replay keeps users, credentials, config bytes and restart count unchanged', async t => {
    const h = await createHarness(t);
    const created = await h.create(GRAPHS[0].edges[0], false);
    assert.equal(created.status, 201);
    assert.equal((await h.deploy(createdId(created))).status, 200);
    const before = new Map(h.files), rows = copy(h.rows.CascadeLink);
    const writeCount = h.calls.writes.length;
    const restartCount = h.calls.transport.filter(call => /systemctl restart/.test(call.command || '')).length;
    const replay = await h.deploy(createdId(created));
    assert.equal(replay.status, 200, JSON.stringify(replay.body));
    assert.deepEqual(h.files, before);
    assert.equal(h.calls.writes.length, writeCount);
    assert.equal(h.calls.transport.filter(call => /systemctl restart/.test(call.command || '')).length, restartCount);
    assert.equal(h.rows.CascadeLink[0].tunnelUuid, rows[0].tunnelUuid);
    assert.deepEqual(JSON.parse(h.files.get(`${IDS.P}:${MAIN}`)).inbounds.find(row => row.tag === 'vless-in').settings.clients,
        [{ id: 'synthetic-existing-user', email: 'fixture@example.invalid' }]);
    assertSettled(h);
});

for (const edge of GRAPHS[1].edges) test(`${edge.key}: applied incomplete segment is staged, not a complete route`, async t => {
    const h = await createNativeHarness(t);
    const created = await h.create(edge, true);
    assert.equal(created.status, 202, JSON.stringify(created.body));
    expectApplied(created, edge.key);
    assert.equal(created.settled.staged, true);
    assert.notEqual(created.settled.routeState, 'complete', 'transport success cannot represent a complete P-to-B route');
    assert.notEqual(created.settled.clientReadiness, 'verified');
    assertSettled(h);
});

for (const method of ['auto', 'manual']) test(`G1 ${method}: accepted apply exposes a durable operation/job identity`, async t => {
    const h = await createNativeHarness(t);
    const saved = await h.create(GRAPHS[0].edges[0], method === 'auto');
    assert.equal(saved.status, method === 'auto' ? 202 : 201, JSON.stringify(saved.body));
    const response = method === 'auto' ? saved : await h.deploy(createdId(saved));
    expectApplied(response, method);
    assert.match(response.body.job.jobId, /^[a-f0-9]{24}$/);
    assert.match(response.settled._id, /^[a-f0-9]{24}$/);
});

test('P-to-R without an outlet never routes cascade traffic through relay freedom', async t => {
    const h = await createNativeHarness(t);
    const saved = await h.create(GRAPHS[1].edges[0], true);
    assert.equal(saved.status, 202, JSON.stringify(saved.body));
    expectApplied(saved, 'P-to-R incomplete prefix');
    const config = JSON.parse(h.files.get(`${IDS.R}:${TRANSIT}`));
    const ingress = new Set((config.reverse?.bridges || []).map(bridge => bridge.tag));
    const direct = new Set(config.outbounds.filter(outbound => outbound.protocol === 'freedom').map(outbound => outbound.tag));
    assert.ok(ingress.size > 0);
    assert.ok(!config.routing.rules.some(rule => rule.inboundTag?.some(tag => ingress.has(tag)) && direct.has(rule.outboundTag)));
    const blocked = new Set(config.outbounds.filter(outbound => outbound.protocol === 'blackhole').map(outbound => outbound.tag));
    for (const tag of ingress) {
        const catchAll = config.routing.rules.find(rule => rule.inboundTag?.includes(tag) && !rule.domain && !rule.ip);
        assert.ok(catchAll && blocked.has(catchAll.outboundTag), 'explicit drop must prevent freedom fallback');
    }
});

test('forward AutoDeploy is admitted through the actual create route', async t => {
    const h = await createNativeHarness(t);
    const saved = await h.create(GRAPHS[1].edges[1], true, 'forward');
    assert.equal(saved.status, 202, JSON.stringify(saved.body));
    expectApplied(saved, 'forward segment');
});

for (const graph of GRAPHS.filter(graph => graph.name !== 'G1')) {
    for (const modes of [graph.edges.map(() => 'forward'), graph.edges.map((_, i) => i % 2 ? 'reverse' : 'forward')]) {
        test(`${graph.name}: per-edge ${modes.join('/')} save/manual contract`, async t => {
            const h = await createNativeHarness(t), ids = [];
            for (const [i, edge] of graph.edges.entries()) {
                const saved = await h.create(edge, false, modes[i]);
                assert.equal(saved.status, 201, JSON.stringify(saved.body));
                ids.push(createdId(saved));
            }
            assert.deepEqual(h.rows.CascadeLink.map(link => link.mode), modes, 'modes must not be unified');
            assert.equal(h.calls.transport.length, 0);
            const deployed = await h.deploy(ids[0]);
            expectApplied(deployed, 'mixed/forward manual');
        });
    }
}
