'use strict';
// Phase C: actual public producers/coordinator/queue/worker/typed executor/gates/
// finalizer. ALL persistence, physical authority, systemd/Xray/PPP IO MODELED.
const test = require('node:test');
const assert = require('node:assert/strict');
const { lifecycleFixture, id } = require('./helpers/cascadeLegacyInstalledGroupLifecycleFixture');

async function succeeded(f, request) {
    const job = await f.accept(request);
    const operation = await f.consume(job);
    assert.equal(operation.status, 'succeeded', `worker ${operation.status}/${operation.errorCode || 'none'} at ${f.stage}`);
    await f.assertPreserved();
    assert.ok(f.options.gateCalls.includes('MAIN') && f.options.gateCalls.includes('PPP'));
    assert.ok(f.options.userPushes > 0, 'actual user resync consumed independent existing client inventory');
    assert.equal(operation.v2Terminal.state, 'proven');
    assert.equal(operation.heldTopologyAdmission, false);
    assert.ok(operation.nodes.every(node => node.state === 'committed'));
    assert.ok(f.dispatches.some(call => call.command === 'close') && f.dispatches.some(call => call.command === 'status'));
    return { job, operation };
}

test('C existing G2 import -> unchanged APPLY d -> durable replay -> revised byte-noop -> DELETE d kept-empty -> new-ID recreate -> fresh reader', { timeout: 180000 }, async t => {
    const f = await lifecycleFixture(t);
    await f.adoptAndEnroll();
    await f.assertInitial();
    const firstRequest = await f.request('link.apply', id(11), 'C-d-initial');
    const first = await succeeded(f, firstRequest);
    await f.assertFresh(id(11), [id(10), id(11)], [id(11)]);
    const dispatches = f.dispatches.length, operations = f.data.TopologyOperation.length;
    const replay = await f.freshIntentService().accept(firstRequest);
    assert.equal(replay.jobId, first.job.jobId);
    assert.equal(replay.status, 'succeeded');
    assert.equal(await f.consumer.claim(), null);
    assert.equal(f.dispatches.length, dispatches);
    assert.equal(f.data.TopologyOperation.length, operations);
    const physical = f.physicalFingerprint();
    await f.advanceRevision();
    const noop = await succeeded(f, await f.request('link.apply', id(11), 'C-d-noop'));
    assert.notEqual(String(noop.operation._id), String(first.operation._id));
    assert.equal(f.physicalFingerprint(), physical, 'genuine byte-noop retains config bytes/inode/modeled PID/start/restart counts');
    const deleted = await succeeded(f, await f.request('link.delete', id(11), 'C-d-delete'));
    assert.equal(await f.models.CascadeLink.findById(id(11)).lean(), null);
    await f.assertFresh(id(10), [id(10)], []);
    f.assertBlocked();
    assert.equal(deleted.operation.v2Terminal.sideEffects.installedIngressProof.pppInternetProof, 'not_applicable');
    const recreated = await succeeded(f, await f.createRequest(id(11), 'C-d-recreate'));
    assert.notEqual(recreated.job.createdLinkId, id(11));
    await f.assertFresh(recreated.job.createdLinkId, [id(10), recreated.job.createdLinkId], [recreated.job.createdLinkId]);
    f.assertRetired(id(11), 25001);
    assert.equal(f.data.NodeOperationLock.length, 0);
});

test('C fresh existing G2 import -> DELETE u preserves installed R-to-B PPP suffix/disconnected portal -> new-ID u recreate -> fresh reader', { timeout: 180000 }, async t => {
    const f = await lifecycleFixture(t);
    await f.adoptAndEnroll();
    await f.assertInitial();
    const deleted = await succeeded(f, await f.request('link.delete', id(10), 'C-u-delete'));
    assert.equal(await f.models.CascadeLink.findById(id(10)).lean(), null);
    await f.assertFresh(id(11), [id(11)], [id(11)]);
    assert.equal(deleted.operation.routeState, 'no_portal_input');
    assert.equal(deleted.operation.v2Terminal.sideEffects.installedIngressProof.pppInternetProof, 'unverified');
    f.assertSuffix();
    const recreated = await succeeded(f, await f.createRequest(id(10), 'C-u-recreate'));
    assert.notEqual(recreated.job.createdLinkId, id(10));
    await f.assertFresh(recreated.job.createdLinkId, [recreated.job.createdLinkId, id(11)], [id(11)]);
    f.assertRetired(id(10), 25000);
    assert.equal(f.data.NodeOperationLock.length, 0);
});

// Bounded one-field controls at the two real installed-readiness boundaries;
// deletion makes premature path publication observable (old [d] versus new []).
const refusals = [
    ['MAIN wrong SOCKS port', f => f.corruptMain(config => { config.outbounds.find(o => o.tag === 'cascade-legacy-main').settings.servers[0].port++; }), 'INGRESS_UNVERIFIED'],
    ['MAIN wrong group inbound tag', f => f.corruptMain(config => { config.inbounds.find(i => i.tag.startsWith('relay-l2tp-')).tag = 'relay-l2tp-wrong-group'; }), 'INGRESS_UNVERIFIED'],
    ['MAIN unreadable', f => { f.options.unreadableMain = true; }, 'INGRESS_UNVERIFIED'],
    ['MAIN inactive', f => f.deactivateMain(), 'INGRESS_UNVERIFIED'],
    ['PPP wrong credential readback', f => { f.options.wrongCredential = true; }, 'INGRESS_PPP_UNVERIFIED'],
    ['PPP wrong managed-user readback', f => { f.options.wrongUsers = true; }, 'INGRESS_PPP_UNVERIFIED'],
    ['PPP unreadable', f => { f.options.unreadablePpp = true; }, 'INGRESS_PPP_UNVERIFIED'],
    ['PPP user desired-applied mismatch', f => { f.data.L2tpUser[0].appliedRevision--; }, 'INGRESS_PPP_UNVERIFIED'],
];
async function retained(f, label) {
    const job = await f.accept(await f.request('link.delete', id(11), label));
    const operation = await f.consume(job);
    assert.equal(operation.status, 'committing');
    assert.equal(f.lastResult.errorCode, 'TOPOLOGY_V2_SETTLEMENT_UNCONFIRMED');
    assert.equal(operation.heldTopologyAdmission, true);
    assert.deepEqual(f.data.CascadeRouteGroup[0].paths[0].linkIds.map(String), [id(11)], 'failed delete must not publish empty path');
    assert.equal(f.data.RelayL2tpState[0].appliedTopologyRevision, 7, 'failed gate/final CAS must not publish revision');
    assert.equal(f.data.CascadeTopologyState[0].topologyAdmissionCount, 1);
    assert.equal(f.data.NodeOperationLock.length, 3);
    for (const node of operation.nodes) {
        const lock = f.data.NodeOperationLock.find(row => String(row.node) === String(node.node));
        const binding = f.data.TopologyExecutionBinding.find(row => row.nodeId === String(node.node) && row.operationId === String(operation._id));
        assert.ok(lock && binding);
        assert.equal(lock.operationId, String(operation._id)); assert.equal(lock.generation, binding.generation);
        assert.equal(lock.remoteUncertain, true);
    }
    assert.ok(f.data.TopologyConfigOwner.every(row => row.lastSettledOperation === undefined));
    assert.equal((await f.models.CascadeLink.findById(id(11)).lean()).lifecycle.state, 'deleting');
    assert.equal(await f.consumer.settle(await f.models.TopologyCreateIntent.findById(job.jobId).lean()), false);
    assert.equal((await f.freshIntentService().get(job.jobId)).status, 'admitted');
    assert.equal(f.data.L2tpOperation.length, 1, 'no PPP repair-sync is allowed to mask refusal');
    return operation;
}
for (const [name, change, innerCode] of refusals) test(`C actual installed refusal: ${name} retains exact ownership and old path`, { timeout: 60000 }, async t => {
    const f = await lifecycleFixture(t); await f.adoptAndEnroll(); await f.assertInitial(); change(f);
    await retained(f, `C-negative-${name.replaceAll(' ', '-')}`);
    assert.deepEqual(f.options.prepareErrors, [innerCode]);
    assert.ok(f.options.gateCalls.includes('MAIN'));
    assert.equal(f.dispatches.some(call => call.command === 'close'), false);
});

for (const drift of ['owner', 'group', 'credential-epoch']) test(`C after readiness ${drift} drift refuses final publication without releasing the admitted generation`, { timeout: 60000 }, async t => {
    const f = await lifecycleFixture(t); await f.adoptAndEnroll(); await f.assertInitial();
    f.options.afterPrepare = () => {
        // Intentional adversarial competing row changes, ONLY after public
        // producers and actual successful readiness; never seeded success.
        if (drift === 'owner') f.data.TopologyConfigOwner[0].generation = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
        else if (drift === 'group') f.data.CascadeRouteGroup[0].paths[0].priority++;
        else f.data.RelayL2tpState[0].secretRevision++;
    };
    await retained(f, `C-final-${drift}`);
    assert.equal(f.options.prepares.length, 1, 'actual MAIN and PPP producer succeeded before the drift');
    assert.deepEqual(f.options.prepareErrors, []);
    assert.ok(f.options.gateCalls.includes('PPP'));
    if (drift === 'owner') assert.equal(f.data.TopologyConfigOwner[0].generation, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
    if (drift === 'group') assert.equal(f.data.CascadeRouteGroup[0].paths[0].priority, 5);
    if (drift === 'credential-epoch') assert.equal(f.data.RelayL2tpState[0].secretRevision, 42);
});
