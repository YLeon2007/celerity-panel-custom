'use strict';
// Internal, one-shot fresh TEST acceptance composition. No CLI/HTTP/startup mode.
// Caller supplies existing same-connection models/store and an unstarted runtime
// hook; native and classic callbacks are the existing serving paths, not proofs.
const { isDeepStrictEqual: same } = require('node:util');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../src/modules/relay-l2tp/domain/topologyExecutionContext');
const { TopologyConfigTransfer } = require('../src/services/topologyConfigTransfer');
const { topologyManagesNodeConfig } = require('../src/services/topologyConfigOwnership');
const { assertTestContext } = require('./test-topology-owner');
function need(value) { if (!value) throw new Error('DEDICATED_ORIGINAL_CYCLE_REFUSED'); }
async function runDedicatedOriginalCycle({ env, authority, lifecycle, store, models, consumers,
    runTopologyServing, acceptCurrent, runClassicServing } = {}) {
    assertTestContext(env);
    need(env.TOPOLOGY_TEST_STARTUP_MODE === 'dedicated-runtime-v1'
        && typeof consumers?.start === 'function' && typeof consumers.enrollTestOwners === 'function'
        && typeof consumers.drainForOriginalHandback === 'function'
        && [runTopologyServing,acceptCurrent,runClassicServing].every(f=>typeof f==='function'));
    // Same discovered-primary connection/index contracts remain enforced by the
    // real BindingStore and existing owner enrollment. No model rows constructed here.
    need(models.TopologyConfigOwner?.db && models.TopologyExecutionEnrollment?.db === models.TopologyConfigOwner.db);
    const originalEpochs = await authority.captureOriginals();
    need(originalEpochs.length === 2); // only the parent-authorized minimal two-role epoch
    // Use the HOST's existing enrollment entry: its onReconciled callback opens
    // normal consumers. Calling the helper directly bypasses dedicated activation.
    const enrolled = await consumers.enrollTestOwners();
    need(enrolled.nodes.length===2);
    await consumers.start();
    const serving = await runTopologyServing(enrolled);
    // This is the actual existing stop/join, followed by controller admission closure.
    // Never root.stop(): normal shutdown destroys the only original holder/cache.
    await consumers.drainForOriginalHandback();
    const observed = await authority.readOriginalRestoreCurrent();
    const accepted = await acceptCurrent(observed, serving);
    need(same(observed,accepted));
    await authority.restoreOriginals(accepted);
    const transfer = new TopologyConfigTransfer({ executionContext:TEST, TopologyConfigOwner:models.TopologyConfigOwner,
        withVerifiedMaintenance:lifecycle.withVerifiedMaintenance.bind(lifecycle) });
    const returned=[];
    for (const n of enrolled.nodes) {
        const owner=await models.TopologyConfigOwner.findOne({node:n.nodeId,profile:n.targetProfile,
            owner:'topology',generation:n.ownerGeneration}).read('primary').readConcern('majority').maxTimeMS(5000).lean();
        need(owner?.adoptionReceipt?.toGeneration===n.ownerGeneration);
        // The original public transfer performs generation CAS + majority readback;
        // retained remote holder verifies exact original bytes before/after both.
        returned.push(await lifecycle.run(()=>transfer.handback({node:n.nodeId,profile:n.targetProfile,
            generation:n.ownerGeneration,proofRef:'dedicated-'+originalEpochs.find(x=>x.nodeId===n.nodeId).maintenanceId})));
    }
    // Do not admit classic merely because a config-owner label changed. The
    // existing full-history predicate must permit it with ALL history retained.
    for (const row of returned) need(await topologyManagesNodeConfig({_id:String(row.node)},env)===false);
    await authority.releaseOriginals();
    const classic=await runClassicServing(returned);
    return Object.freeze({level:'dedicated-original-cycle',originalEpochs,enrolled,serving,returned,classic});
}
module.exports={runDedicatedOriginalCycle};
