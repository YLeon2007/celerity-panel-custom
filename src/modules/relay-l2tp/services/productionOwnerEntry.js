'use strict';
// Internal PROD entry over the existing public ownership + seven-key store ABI.
const { isDeepStrictEqual: same } = require('node:util');
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const { freeze } = require('../models/topologyExecutionBindingContract');
const { TopologyConfigTransfer } = require('../../../services/topologyConfigTransfer');
const { acceptedExecutionEnrollment, handbackReentryEvidence } = require('../repositories/topologyExecutionBindingStore');
function need(value) { if (!value) throw Object.assign(new Error('PRODUCTION_OWNER_ENTRY_UNPROVEN'), { code: 'PRODUCTION_OWNER_ENTRY_UNPROVEN' }); }
const read = query => query.read('primary').readConcern('majority').maxTimeMS(5000).lean();
async function inspectEnrollmentPlan(plan, check, models) {
    need(same(plan.executionContext, PROD));
    for (const pin of plan.nodes) {
        await check();
        const owner = await read(models.TopologyConfigOwner.findOne({ node: pin.nodeId, profile: pin.targetProfile }).select('+executionEnrollment'));
        const alias = await read(models.TopologyExecutionEnrollment.findOne({ nodeId: pin.nodeId, targetProfile: pin.targetProfile }));
        if (plan.mode === 'runtime') continue;
        need(pin.acceptedOwner.owner === 'absent' ? !owner && !alias
            : pin.acceptedOwner.owner === 'classic' && owner?.owner === 'classic'
                && owner.generation === pin.acceptedOwner.generation && same(owner.executionContext, PROD) && same(owner.nodeIdentity, pin.nodeIdentity));
        await require('./topologyReentryPolicy').assertOwnerReentryAllowed(owner, models);
        const collision = await read(models.TopologyExecutionEnrollment.findOne({ $or: [
            { 'nodeIdentity.machineId': pin.nodeIdentity.machineId }, { 'nodeIdentity.sshHostKeySha256': pin.nodeIdentity.sshHostKeySha256 },
            { 'endpoint.ip': pin.endpoint.ip, 'endpoint.port': pin.endpoint.port } ] }));
        need(!collision || collision._id === alias?._id);
        if (!alias && owner) need(owner.adoptionReceipt === undefined && owner.handbackReceipt === undefined && owner.executionEnrollment === undefined);
        if (alias) {
            handbackReentryEvidence(alias, owner);
            need(same(alias.endpoint, pin.endpoint) && same(alias.nodeIdentity, pin.nodeIdentity));
            // This transition admits the B2 zero-business previous cycle only.
            // Even terminal business history is unsupported, never discarded.
            for (const [Model, query] of [[models.TopologyExecutionBinding, { nodeId: pin.nodeId }],
                [models.TopologyOperation, { $or: [{ 'nodes.node': pin.nodeId }, { resourceNodeIds: pin.nodeId }] }],
                [models.NodeOperationLock, { node: pin.nodeId }], [models.RemoteAdmission, { nodeId: pin.nodeId }]]) {
                need(!await read(Model.findOne(query)));
            }
            const state = await read(models.CascadeTopologyState.findById('singleton'));
            need(state && state.remoteAdmissionCount === 0 && state.topologyAdmissionCount === 0
                && !state.remoteDrain && !state.replacementReservation && !state.classicLifecycleAttempt);
        }
        await check();
    }
}
async function enrollProductionOwners({ lifecycle, store, models }) {
    need(same(lifecycle?.executionContext, PROD) && store);
    // This is an expected product refusal, not a failed maintenance attempt.
    // Check it before acquiring physical exclusion so classic keeps running.
    const restriction = await require('./topologyReentryPolicy').readBusinessReentryRestriction({
        executionContext: PROD, TopologyConfigOwner: models.TopologyConfigOwner,
        TopologyOperation: models.TopologyOperation, TopologyExecutionBinding: models.TopologyExecutionBinding,
    });
    if (restriction.blocked) throw require('./topologyReentryPolicy').businessReentryError();
    let legacyTopologyByNode;
    const transfer = new TopologyConfigTransfer({ executionContext: PROD, TopologyConfigOwner: models.TopologyConfigOwner,
        withVerifiedMaintenance: lifecycle.withVerifiedMaintenance.bind(lifecycle) });
    return lifecycle.run(() => lifecycle.withCapturedOwnerEnrollment(async (plan, check) => {
        // Repeat after capture under the held scope; the earlier observation is
        // only a deterministic refusal gate, not adoption permission.
        await inspectEnrollmentPlan(plan, check, models);
        need(same(plan.executionContext, PROD)); const result = [];
        for (const pin of plan.nodes) {
            await check();
            let owner = await read(models.TopologyConfigOwner.findOne({ node: pin.nodeId, profile: pin.targetProfile }).select('+originalSnapshot +executionEnrollment'));
            const existing = await read(models.TopologyExecutionEnrollment.findOne({ nodeId: pin.nodeId, targetProfile: pin.targetProfile }));
            await check();
            if (plan.mode === 'runtime') {
                const current = acceptedExecutionEnrollment(existing, owner);
                const { proofRef: _ref, ...snapshot } = pin.originalSnapshot;
                need(owner?.owner === 'topology' && owner.generation === pin.acceptedOwner.generation
                    && same(owner.executionContext, PROD) && same(owner.nodeIdentity, pin.nodeIdentity)
                    && same(owner.originalSnapshot, snapshot) && owner.adoptionReceipt?.toGeneration === owner.generation
                    && current.executionContext === PROD.hostIdentity && current.ownerGeneration === owner.generation
                    && same(current.nodeIdentity, pin.nodeIdentity) && same(current.endpoint, pin.endpoint) && current.bootId === pin.bootId);
                result.push({ nodeId: pin.nodeId, targetProfile: pin.targetProfile, ownerGeneration: owner.generation, enrollmentId: existing._id,
                    proofRef: pin.originalSnapshot.proofRef });
                continue;
            }
            if (existing) handbackReentryEvidence(existing, owner);
            if (pin.acceptedOwner.owner === 'absent') {
                need(!owner);
                owner = await transfer.initializeClassic({ node: pin.nodeId, profile: pin.targetProfile, nodeIdentity: pin.nodeIdentity });
            } else need(owner?.owner === 'classic' && pin.acceptedOwner.owner === 'classic'
                && owner.generation === pin.acceptedOwner.generation && same(owner.executionContext, PROD) && same(owner.nodeIdentity, pin.nodeIdentity));
            await check();
            const legacyTopology = plan.legacyTopology ?? legacyTopologyByNode?.[pin.nodeId];
            const adopted = await transfer.adopt({ node: pin.nodeId, profile: pin.targetProfile, generation: owner.generation,
                proofRef: pin.originalSnapshot.proofRef,
                ...(legacyTopology === undefined ? {} : { legacyTopology }) });
            await check();
            const enrolled = await store.preEnroll(freeze({ nodeId: pin.nodeId, targetProfile: pin.targetProfile,
                endpoint: pin.endpoint, nodeIdentity: pin.nodeIdentity, bootId: pin.bootId,
                predecessorGeneration: 'none', ownerGeneration: adopted.generation }));
            await check();
            result.push({ nodeId: pin.nodeId, targetProfile: pin.targetProfile, ownerGeneration: adopted.generation,
                enrollmentId: enrolled.enrollmentId, proofRef: pin.originalSnapshot.proofRef });
        }
        await check(); return freeze({ executionContext: PROD, status: 'enrolled', nodes: result });
    }, async (plan, check, readProfile) => {
        await inspectEnrollmentPlan(plan, check, models);
        if (plan.mode === 'enroll' && plan.legacyTopology === undefined) {
            legacyTopologyByNode = await require('./classicBaselineImport').readClassicAppliedTopologies({
                nodes: plan.nodes, readProfile,
                HyNode: models.HyNode, CascadeLink: models.CascadeLink, CascadeRouteGroup: models.CascadeRouteGroup,
            });
            await check();
        }
    }));
}
async function handbackProductionOwners({ lifecycle, authority, models, enrollment, acceptedCurrent, env }) {
    need(same(lifecycle?.executionContext, PROD) && enrollment?.nodes?.length > 0 && acceptedCurrent);
    const ids = enrollment.nodes.map(n => n.nodeId);
    // Unknown, historical locks and admissions are retained, not treated as
    // expired permission. No operation replay, manual COMMIT or history deletion.
    need(!(await read(models.NodeOperationLock.findOne({ node: { $in: ids } }))));
    need(!(await read(models.RemoteAdmission.findOne({ nodeId: { $in: ids } }))));
    const state = await read(models.CascadeTopologyState.findById('singleton'));
    need(state && state.remoteAdmissionCount === 0 && state.topologyAdmissionCount === 0
        && !state.remoteDrain && !state.replacementReservation && !state.classicLifecycleAttempt);
    const current = await authority.readOriginalRestoreCurrent(); need(same(current, acceptedCurrent));
    await authority.restoreOriginals(acceptedCurrent);
    const transfer = new TopologyConfigTransfer({ executionContext: PROD, TopologyConfigOwner: models.TopologyConfigOwner,
        withVerifiedMaintenance: lifecycle.withVerifiedMaintenance.bind(lifecycle) });
    const returned = [];
    for (const n of enrollment.nodes) returned.push(await lifecycle.run(() => transfer.handback({ node: n.nodeId,
        profile: n.targetProfile, generation: n.ownerGeneration, proofRef: n.proofRef })));
    for (const row of returned) need(await require('../../../services/topologyConfigOwnership')
        .topologyManagesNodeConfig({ _id: String(row.node) }, env) === false);
    await authority.releaseOriginals();
    return freeze({ status: 'handed-back', nodes: returned.map(row => ({ nodeId: String(row.node), profile: row.profile, generation: row.generation })) });
}
module.exports = { enrollProductionOwners, handbackProductionOwners };
