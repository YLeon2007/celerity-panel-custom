'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { MAIN, TRANSIT, IDS, GRAPHS, CREATION_CASES, permutations, createHarness,
    expectApplied, semanticLinks, copy } = require('./cascadeAnyOrderFixtures');

// No skip/todo/expected-failure inversion: these are executable acceptance
// assertions, intentionally RED where the current classic path rejects cascades.
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
        const h = await createHarness(t);
        const roles = copy(h.rows.HyNode);
        for (const edge of order) {
            const response = await h.create(edge, true);
            diagnostic(t, h, `auto ${edge.key}`);
            assert.equal(response.status, 201, `${edge.key}: ${JSON.stringify(response.body)}`);
            assert.ok(response.body.createdLinkId, 'successful save must identify the link');
            expectApplied(response, `${label}, ${edge.key}`);
            const saved = (await h.snapshot()).links.find(link => link.name === edge.key);
            assert.ok(['deployed', 'online', 'staged'].includes(saved.status), `${edge.key} never applied`);
            assertSettled(h);
        }
        assertDesired(h, graph);
        assert.deepEqual(h.rows.HyNode, roles, 'CRUD must not rewrite operator roles/credentials');
        assert.equal(h.calls.core.filter(call => call.method === 'deployScopedClassicLink').length, graph.edges.length);
        assert.equal(h.calls.failures.length, 0);
        assert.ok(h.calls.writes.length > 0, 'exercise real generated/staged/read-back config bytes');
    });

    test(`${label}: save-only accepts every intermediate desired graph without remote writes`, async t => {
        const h = await createHarness(t);
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
        const h = await createHarness(t);
        const ids = new Map();
        // Reverse draft insertion vs application order without a Cartesian matrix.
        for (const edge of [...order].reverse()) {
            const response = await h.create(edge, false);
            assert.equal(response.status, 201, JSON.stringify(response.body));
            ids.set(edge.key, response.body.createdLinkId);
        }
        assert.equal(h.calls.transport.length, 0);
        for (const edge of order) {
            const response = await h.deploy(ids.get(edge.key));
            diagnostic(t, h, `manual ${edge.key}`);
            assert.equal(response.status, 200, `${label}, ${edge.key}: ${JSON.stringify(response.body)}`);
            assert.equal(response.body.status, 'succeeded');
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
    const h = await createHarness(t);
    const graph = GRAPHS[2];
    const pending = await h.create(graph.edges[2], false);
    assert.equal(pending.status, 201);
    const pendingId = pending.body.createdLinkId;
    const branchProfile = h.files.get(`${IDS.B2}:${TRANSIT}`);
    const created = await h.create(graph.edges[0], method === 'auto');
    assert.equal(created.status, 201, JSON.stringify(created.body));
    if (method === 'auto') expectApplied(created, 'selected prefix');
    else {
        const deployed = await h.deploy(created.body.createdLinkId);
        assert.equal(deployed.status, 200, JSON.stringify(deployed.body));
    }
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
    assert.equal((await h.deploy(created.body.createdLinkId)).status, 200);
    const before = new Map(h.files);
    const rows = copy(h.rows.CascadeLink);
    const writeCount = h.calls.writes.length;
    const restartCount = h.calls.transport.filter(call => /systemctl restart/.test(call.command || '')).length;
    const replay = await h.deploy(created.body.createdLinkId);
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
    const h = await createHarness(t);
    const created = await h.create(edge, true);
    assert.equal(created.status, 201, JSON.stringify(created.body));
    expectApplied(created, edge.key);
    const saved = (await h.snapshot()).links.find(link => link._id === created.body.createdLinkId);
    assert.equal(saved.status, 'staged', 'INV-06 / FR-01: transport success cannot represent a complete P-to-B route');
    assert.notEqual(saved.clientReadiness?.status, 'ready');
});

for (const method of ['auto', 'manual']) test(`G1 ${method}: accepted apply exposes a durable operation/job identity`, async t => {
    const h = await createHarness(t);
    const saved = await h.create(GRAPHS[0].edges[0], method === 'auto');
    assert.equal(saved.status, 201, JSON.stringify(saved.body));
    const response = method === 'auto' ? saved : await h.deploy(saved.body.createdLinkId);
    assert.equal(response.status, method === 'auto' ? 201 : 200, JSON.stringify(response.body));
    const body = response.body;
    const operationId = body.autoDeployOperation?.operationId || body.operationId
        || body.autoDeployJob?.jobId || body.autoDeployJob?.id || body.autoDeployJob?._id;
    assert.ok(typeof operationId === 'string' && operationId.length > 0,
        'FR-02/03: HTTP success and synchronous classic result are not a durable operation identity');
});

test('P-to-R without an outlet never routes cascade traffic through relay freedom', async t => {
    const h = await createHarness(t);
    const saved = await h.create(GRAPHS[1].edges[0], true);
    assert.equal(saved.status, 201, JSON.stringify(saved.body));
    expectApplied(saved, 'P-to-R incomplete prefix');
    const config = JSON.parse(h.files.get(`${IDS.R}:${TRANSIT}`));
    const ingress = new Set((config.reverse?.bridges || []).map(bridge => bridge.tag));
    const direct = new Set(config.outbounds.filter(outbound => outbound.protocol === 'freedom').map(outbound => outbound.tag));
    assert.ok(ingress.size > 0, 'the selected prefix must actually reach its receiving profile');
    assert.ok(!config.routing.rules.some(rule => rule.inboundTag?.some(tag => ingress.has(tag)) && direct.has(rule.outboundTag)),
        'INV-04 / FR-01: a relay with no allowed outlet must not be treated as a terminal direct-egress bridge');
    const blocked = new Set(config.outbounds.filter(outbound => outbound.protocol === 'blackhole').map(outbound => outbound.tag));
    for (const tag of ingress) {
        const catchAll = config.routing.rules.find(rule => rule.inboundTag?.includes(tag) && !rule.domain && !rule.ip);
        assert.ok(catchAll && blocked.has(catchAll.outboundTag),
            'missing explicit drop must not fall through to the default freedom outbound');
    }
});

test('forward AutoDeploy is admitted through the actual create route', async t => {
    const h = await createHarness(t);
    const saved = await h.create(GRAPHS[1].edges[1], true, 'forward');
    assert.equal(saved.status, 201, `FR-06: ${JSON.stringify(saved.body)}`);
    expectApplied(saved, 'forward segment');
});

for (const graph of GRAPHS.filter(graph => graph.name !== 'G1')) {
    for (const modes of [graph.edges.map(() => 'forward'), graph.edges.map((_, i) => i % 2 ? 'reverse' : 'forward')]) {
        test(`${graph.name}: per-edge ${modes.join('/')} save/manual contract`, async t => {
            const h = await createHarness(t);
            const ids = [];
            for (const [i, edge] of graph.edges.entries()) {
                const saved = await h.create(edge, false, modes[i]);
                assert.equal(saved.status, 201, JSON.stringify(saved.body));
                ids.push(saved.body.createdLinkId);
            }
            assert.deepEqual(h.rows.CascadeLink.map(link => link.mode), modes, 'modes must not be unified');
            assert.equal(h.calls.transport.length, 0);
            const deployed = await h.deploy(ids[0]);
            diagnostic(t, h, 'mixed/forward manual');
            assert.equal(deployed.status, 200, JSON.stringify(deployed.body));
        });
    }
}
