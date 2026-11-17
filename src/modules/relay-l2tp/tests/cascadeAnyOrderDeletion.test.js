'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { MAIN, IDS, GRAPHS, permutations, createHarness, createNativeHarness, createdId,
    expectApplied, semanticLinks, copy } = require('./cascadeAnyOrderFixtures');
test.after(() => require('../../../services/sshPoolService').closeAll());
const forGraph = (t, graph) => (graph.name === 'G1' ? createHarness : createNativeHarness)(t);
const appliedStatus = h => h.native ? 202 : 200;
async function appliedBaseline(h, graph) {
    const ids = new Map();
    // Native baseline is produced by the actual existing public runtime, never
    // by seeding an applied status or manufacturing settlement/ownership rows.
    for (const edge of graph.edges) {
        const created = await h.create(edge, true);
        assert.equal(created.status, h.native ? 202 : 201, JSON.stringify(created.body));
        expectApplied(created, graph.name + ' baseline');
        ids.set(edge.key, createdId(created));
    }
    return ids;
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
    if (h.native) {
        assert.deepEqual(h.users, h.originalUsers);
        assert.ok(h.rows.TopologyOperation.every(op => op.status === 'succeeded' && op.heldTopologyAdmission === false));
    }
}
function assertAbsent(h, oldId) {
    assert.ok(!h.rows.CascadeLink.some(link => link._id === oldId));
    const suffix = h.native ? h.artifactSuffixes.get(oldId) : oldId.slice(-8);
    assert.ok(suffix, 'test observes the actual generated artifact identity before deletion');
    assert.ok([...h.files.values()].every(bytes => !bytes.includes(suffix)),
        'old connector/reverse/routing tags must be absent from every modeled committed profile');
    // Classic fixture models staged files. Native fixture records only committed
    // candidates; actual native staging cleanup remains covered by runner tests.
    if (!h.native) assert.ok([...h.files.keys()].every(file => !file.endsWith('.stage')));
}

for (const graph of GRAPHS) for (const edge of graph.edges) {
    test(`${graph.name}: DELETE applied ${edge.key}, preserve siblings, recreate on same port`, async t => {
        const h = await forGraph(t, graph), ids = await appliedBaseline(h, graph);
        const oldId = ids.get(edge.key), before = copy(h.rows.CascadeLink), roles = copy(h.rows.HyNode);
        const clients = new Map(h.rows.HyNode.map(node => [node._id,
            JSON.parse(h.files.get(`${node._id}:${MAIN}`)).inbounds.find(row => row.tag === 'vless-in').settings.clients]));
        const response = await h.remove(oldId);
        report(t, h, edge.key);
        assert.equal(response.status, appliedStatus(h), JSON.stringify(response.body));
        assertAbsent(h, oldId); assertSettled(h);
        assert.deepEqual(semanticLinks(h.rows.CascadeLink), semanticLinks(before.filter(link => link._id !== oldId)));
        for (const sibling of before.filter(link => link._id !== oldId)) assert.deepEqual(
            h.rows.CascadeLink.find(link => link._id === sibling._id), sibling,
            'unselected applied links retain identity, status, policy and credentials');
        for (const [nodeId, expected] of clients) assert.deepEqual(
            JSON.parse(h.files.get(`${nodeId}:${MAIN}`)).inbounds.find(row => row.tag === 'vless-in').settings.clients,
            expected, 'existing config clients are not recreated; native RPC identities are checked separately');
        assert.deepEqual(h.rows.HyNode, roles);
        const recreated = await h.create(edge, true);
        report(t, h, 'recreate ' + edge.key);
        assert.equal(recreated.status, h.native ? 202 : 201, JSON.stringify(recreated.body));
        assert.notEqual(createdId(recreated), oldId);
        expectApplied(recreated, graph.name + ' recreate ' + edge.key);
        assertAbsent(h, oldId);
        assert.deepEqual(semanticLinks(h.rows.CascadeLink), semanticLinks(before));
        assertSettled(h);
    });
}

for (const graph of GRAPHS) for (const order of permutations(graph.edges)) {
    test(`${graph.name}: sequential applied DELETE ${order.map(edge => edge.key).join(' > ')}`, async t => {
        const h = await forGraph(t, graph), ids = await appliedBaseline(h, graph);
        let remaining = graph.edges.length;
        for (const edge of order) {
            const response = await h.remove(ids.get(edge.key));
            report(t, h, edge.key);
            assert.equal(response.status, appliedStatus(h), JSON.stringify(response.body));
            remaining--;
            assert.equal((await h.snapshot()).links.length, remaining);
            assertAbsent(h, ids.get(edge.key)); assertSettled(h);
        }
        assert.equal(h.rows.CascadeLink.length, 0);
    });
}

test('G1: completed DELETE permits recreate on a different free port', async t => {
    const h = await createHarness(t), graph = GRAPHS[0], ids = await appliedBaseline(h, graph), oldId = ids.get('PB1');
    assert.equal((await h.remove(oldId)).status, 200);
    const recreated = await h.create({ ...graph.edges[0], port: 12501 }, true);
    assert.equal(recreated.status, 201, JSON.stringify(recreated.body));
    expectApplied(recreated, 'different free port');
    assert.equal(h.rows.CascadeLink[0].tunnelPort, 12501);
    assertAbsent(h, oldId); assertSettled(h);
});

for (const graph of GRAPHS) test(`${graph.name}: never-dispatched pending DELETE is DB-only`, async t => {
    const h = await createNativeHarness(t), ids = [];
    for (const edge of [...graph.edges].reverse()) {
        const response = await h.create(edge, false);
        assert.equal(response.status, 201, JSON.stringify(response.body));
        ids.push(createdId(response));
    }
    const original = new Map(h.files);
    assert.equal(h.calls.core.length, 0);
    for (const linkId of ids.reverse()) {
        const removed = await h.remove(linkId);
        assert.equal(removed.status, 202, JSON.stringify(removed.body));
        assert.equal(h.calls.transport.length, 0, 'proven never-dispatched pending deletion must not require node effects');
        assert.deepEqual(h.files, original); assertSettled(h);
    }
});

for (const edge of GRAPHS[2].edges.slice(1)) test(`G3 suffix: DELETE ${edge.key} preserves the other outlet`, async t => {
    const h = await createNativeHarness(t), graph = { name: 'G3 suffix', edges: GRAPHS[2].edges.slice(1) };
    const ids = await appliedBaseline(h, graph);
    const sibling = copy(h.rows.CascadeLink.find(link => link._id !== ids.get(edge.key)));
    const response = await h.remove(ids.get(edge.key));
    report(t, h, edge.key);
    assert.equal(response.status, 202, JSON.stringify(response.body));
    assertAbsent(h, ids.get(edge.key));
    assert.equal(h.rows.CascadeLink.length, 1);
    assert.deepEqual(h.rows.CascadeLink[0], sibling);
    assert.equal(h.rows.CascadeLink[0].portalNode, IDS.R);
    assertSettled(h);
});
