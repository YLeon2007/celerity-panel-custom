'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { MAIN, IDS, GRAPHS, permutations, createHarness, seedAppliedGraph,
    expectApplied, semanticLinks, copy } = require('./cascadeAnyOrderFixtures');

async function appliedBaseline(h, graph) {
    if (graph.name !== 'G1') return seedAppliedGraph(h, graph);
    const created = await h.create(graph.edges[0], true);
    assert.equal(created.status, 201, JSON.stringify(created.body));
    expectApplied(created, 'G1 baseline');
    return new Map([[graph.edges[0].key, created.body.createdLinkId]]);
}
function report(t, h, edge) {
    t.diagnostic(JSON.stringify({ edge, coreFailures: h.calls.failures,
        refusal: h.calls.diagnostics.at(-1)?.internalCode,
        retainedNodeLocks: h.rows.NodeOperationLock.length,
        retainedReservation: !!h.state().replacementReservation }));
}
function assertSettled(h) {
    assert.equal(h.rows.NodeOperationLock.length, 0);
    assert.equal(h.state().replacementReservation, undefined);
    assert.equal(h.state().classicLifecycleAttempt, undefined);
}
function assertAbsent(h, oldId) {
    assert.ok(!h.rows.CascadeLink.some(link => link._id === oldId), 'desired row removal must read back');
    assert.ok([...h.files.values()].every(bytes => !bytes.includes(oldId.slice(-8))),
        'old connector/reverse/routing tags must be absent from every profile');
    assert.ok([...h.files.keys()].every(file => !file.endsWith('.stage')), 'no orphan stages');
}

for (const graph of GRAPHS) for (const edge of graph.edges) {
    test(`${graph.name}: DELETE applied ${edge.key}, preserve siblings, recreate on same port`, async t => {
        const h = await createHarness(t);
        const ids = await appliedBaseline(h, graph);
        const oldId = ids.get(edge.key);
        const before = copy(h.rows.CascadeLink);
        const roles = copy(h.rows.HyNode);
        const clients = new Map(h.rows.HyNode.map(node => [node._id,
            JSON.parse(h.files.get(`${node._id}:${MAIN}`)).inbounds.find(row => row.tag === 'vless-in').settings.clients]));
        const response = await h.remove(oldId);
        report(t, h, edge.key);
        assert.equal(response.status, 200, `${graph.name} ${edge.key}: ${JSON.stringify(response.body)}`);
        assertAbsent(h, oldId);
        assertSettled(h);
        assert.deepEqual(semanticLinks(h.rows.CascadeLink), semanticLinks(before.filter(link => link._id !== oldId)));
        for (const sibling of before.filter(link => link._id !== oldId)) {
            assert.deepEqual(h.rows.CascadeLink.find(link => link._id === sibling._id), sibling,
                'unselected applied links must keep identity, status, policy and credentials');
        }
        for (const [nodeId, expected] of clients) assert.deepEqual(
            JSON.parse(h.files.get(`${nodeId}:${MAIN}`)).inbounds.find(row => row.tag === 'vless-in').settings.clients,
            expected, 'existing VLESS clients are not recreated');
        assert.deepEqual(h.rows.HyNode, roles);
        const recreated = await h.create(edge, true);
        report(t, h, `recreate ${edge.key}`);
        assert.equal(recreated.status, 201, JSON.stringify(recreated.body));
        assert.notEqual(recreated.body.createdLinkId, oldId);
        expectApplied(recreated, `${graph.name} recreate ${edge.key}`);
        assertAbsent(h, oldId);
        assert.deepEqual(semanticLinks(h.rows.CascadeLink), semanticLinks(before));
        assertSettled(h);
    });
}

for (const graph of GRAPHS) for (const order of permutations(graph.edges)) {
    test(`${graph.name}: sequential applied DELETE ${order.map(edge => edge.key).join(' > ')}`, async t => {
        const h = await createHarness(t);
        const ids = await appliedBaseline(h, graph);
        let remaining = graph.edges.length;
        for (const edge of order) {
            const response = await h.remove(ids.get(edge.key));
            report(t, h, edge.key);
            assert.equal(response.status, 200, JSON.stringify(response.body));
            remaining--;
            assert.equal((await h.snapshot()).links.length, remaining);
            assertAbsent(h, ids.get(edge.key));
            assertSettled(h);
        }
        assert.equal(h.rows.CascadeLink.length, 0);
    });
}

test('G1: completed DELETE permits recreate on a different free port', async t => {
    const h = await createHarness(t);
    const graph = GRAPHS[0];
    const ids = await appliedBaseline(h, graph);
    const oldId = ids.get('PB1');
    const removed = await h.remove(oldId);
    assert.equal(removed.status, 200, JSON.stringify(removed.body));
    const recreated = await h.create({ ...graph.edges[0], port: 12501 }, true);
    assert.equal(recreated.status, 201, JSON.stringify(recreated.body));
    expectApplied(recreated, 'different free port');
    assert.equal(h.rows.CascadeLink[0].tunnelPort, 12501);
    assertAbsent(h, oldId);
    assertSettled(h);
});

for (const graph of GRAPHS) test(`${graph.name}: never-dispatched pending DELETE is DB-only`, async t => {
    const h = await createHarness(t);
    const ids = [];
    for (const edge of [...graph.edges].reverse()) {
        const response = await h.create(edge, false);
        assert.equal(response.status, 201, JSON.stringify(response.body));
        ids.push(response.body.createdLinkId);
    }
    const original = new Map(h.files);
    // No apply/operation/dispatch history exists in this explicit local fixture.
    assert.equal(h.calls.core.length, 0);
    for (const linkId of ids.reverse()) {
        const removed = await h.remove(linkId);
        assert.equal(removed.status, 200, JSON.stringify(removed.body));
        assert.equal(h.calls.transport.length, 0,
            'FR-07: proven never-dispatched pending deletion must not require SSH');
        assert.deepEqual(h.files, original);
        assertSettled(h);
    }
});

// Suffix-only inventory isolates the second-outlet guard from the upstream
// guard that wins first in a complete G3 graph. No alternate product algorithm.
for (const edge of GRAPHS[2].edges.slice(1)) test(`G3 suffix: DELETE ${edge.key} preserves the other outlet`, async t => {
    const h = await createHarness(t);
    const graph = { name: 'G3 suffix', edges: GRAPHS[2].edges.slice(1) };
    const ids = await seedAppliedGraph(h, graph);
    const response = await h.remove(ids.get(edge.key));
    report(t, h, edge.key);
    assert.equal(response.status, 200, JSON.stringify(response.body));
    assertAbsent(h, ids.get(edge.key));
    assert.equal(h.rows.CascadeLink.length, 1);
    assert.equal(h.rows.CascadeLink[0].status, 'deployed');
    assert.equal(h.rows.CascadeLink[0].portalNode, IDS.R);
    assertSettled(h);
});
