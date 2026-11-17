'use strict';
// Read-only compatibility for a legacy full reconcile immediately following a
// selected settlement. Rebuild from that immutable predecessor, not desired
// links; every resulting byte must equal the actual V2-closed full candidate.
const { isDeepStrictEqual: same } = require('node:util');
const { createHash } = require('node:crypto');
const { validTerminalReceipt } = require('../models/topologyExecutionBindingContract');
const { durableSelectedTopology, selectedAdmissionFingerprint } = require('../repositories/topologyOperationRepository');
const plain = value => JSON.parse(JSON.stringify(value));
const id = value => String(value?._id ?? value);
const fail = () => { throw Object.assign(new Error('Settled full reconcile baseline unproven'), { code: 'APPLIED_BASELINE_REQUIRED' }); };
// New full reconciles carry their own admission-time graph. No desired rows,
// predecessor synthesis or read-time metadata hydration supplies this evidence.
function recoverFrozenFullReconcile({ operation: op, owners }) {
    const { selectedAdmissionFingerprint } = require('../repositories/topologyOperationRepository');
    const { projectNodes, projectLinks, projectGroups } = require('../domain/topologyDraft');
    if (!op || (op.kind !== undefined && op.kind !== 'domain.reconcile') || op.admissionScope !== undefined || op.effectiveTopology !== undefined
        || op.status !== 'succeeded' || op.heldTopologyAdmission !== false || op.v2Terminal?.state !== 'proven'
        || op.admissionFingerprint !== selectedAdmissionFingerprint(op)) fail();
    const topology = durableSelectedTopology(op.fullTopology);
    const policy = require('../domain/primaryReservePolicy');
    const compiledTopology = policy.compileConfiguredTopology({
        nodes: projectNodes(topology.nodes), links: projectLinks(topology.links),
        groups: projectGroups(topology.groups), healthByPathKey: {},
    });
    const generated = require('./frozenTopologyDeploymentPlanComposer').composeFrozenTopologyDeploymentPlan({
        snapshot: topology, staged: op.kind === 'domain.reconcile', executionContext: op.executionContext,
        nodeMetadata: topology.nodes, linkMetadata: topology.links,
        // Identical compiler/projection to admission, including configured
        // relay ingress and geo branches. A bare compile changes actual bytes.
        compiledTopology,
    });
    if (op.nodes.length !== topology.nodes.length || generated.nodes.length !== op.nodes.length
        || (op.kind !== undefined && (topology.links.length !== op.linkIds?.length || topology.links.some(link => !op.linkIds.includes(link.id))))
        || generated.nodes.some(entry => !op.nodes.some(row => id(row.node) === entry.node
            && row.role === entry.role && row.targetProfile === entry.targetProfile && row.candidateHash === entry.candidate.sha256))) fail();
    const pins = [];
    for (const entry of op.nodes) {
        const owner = owners.find(row => id(row.node) === id(entry.node) && row.profile === entry.targetProfile);
        const bindings = op.v2Terminal.bindings?.filter(row => row.nodeId === id(entry.node));
        const b = bindings?.[0];
        const proofs = op.v2Terminal.proofs?.filter(row => row.commandId === b?.commandIds?.close);
        const fences = op.v2Terminal.ownerFences?.filter(row => row.node === id(entry.node) && row.profile === entry.targetProfile);
        if (!owner || owner.owner !== 'topology' || owner.handbackReceipt !== undefined
            || owner.lastSettledOperation !== id(op) || owner.lastSettledRevision !== op.topologyRevision
            || entry.state !== 'committed' || bindings?.length !== 1 || proofs?.length !== 1 || fences?.length !== 1
            || b.operationId !== id(op) || b.targetProfile !== entry.targetProfile
            || b.candidateHash !== 'sha256:' + entry.candidateHash || b.backupId !== entry.backupId
            || b.owner !== op.leaseOwner || b.attempt !== op.attempts || b.topologyRevision !== op.topologyRevision
            || b.priorDeployedRevision !== op.priorDeployedRevision || b.executionContext !== op.executionContext.hostIdentity
            || b.generation !== owner.lastSettledGeneration || b.commandIds.close !== owner.lastSettledCloseId
            || !validTerminalReceipt(proofs[0], b) || proofs[0].terminalOutcome !== 'verified'
            || createHash('sha256').update(Buffer.from(entry.candidate.bytes)).digest('hex') !== entry.candidateHash
            || entry.candidate.sha256 !== entry.candidateHash) fail();
        const root = Object.fromEntries(['node','profile','executionContext','owner','generation','nodeIdentity','originalSnapshot','adoptionReceipt']
            .map(key => [key, key === 'node' ? id(owner.node) : plain(owner[key])]));
        if (!same(plain(fences[0]), root)) fail();
        pins.push(root);
    }
    // Exactly the producer's configured-policy identity choice. Synthetic
    // refs are regenerated and checked by the existing transition verifier.
    if (policy.primaryReservePolicies(topology, compiledTopology).length === 0) {
        for (const [index, link] of [...topology.links].sort((a,b)=>a.id.localeCompare(b.id,'en')).entries()) link.artifactRef = `link-${index+1}`;
    }
    return { topology, pins };
}
function recoverSettledFullReconcile({ operation: op, predecessor: prior, owners, groups }) {
    if (op?.kind !== 'domain.reconcile' || op.admissionScope !== undefined || op.effectiveTopology !== undefined
        || op.status !== 'succeeded' || op.heldTopologyAdmission !== false || op.v2Terminal?.state !== 'proven'
        || prior?.admissionScope !== 'selected' || prior.status !== 'succeeded' || prior.heldTopologyAdmission !== false
        || prior.v2Terminal?.state !== 'proven' || prior.admissionFingerprint !== selectedAdmissionFingerprint(prior)
        || !same(op.executionContext, prior.executionContext) || op.executionContext?.target !== 'test'
        || prior.selectedOwnerPins?.some(pin => pin.profileTargetPin !== undefined)
        || !Array.isArray(op.nodes) || op.nodes.length !== prior.nodes?.length
        || !same([...(op.linkIds || [])].sort(), prior.effectiveTopology?.links?.map(link => link.id).sort())) fail();
    const check = (operation, entry, binding, terminal, owner) => {
        const proof = terminal.proofs?.filter(row => row.commandId === binding?.commandIds?.close);
        const fence = terminal.ownerFences?.filter(row => row.node === id(entry.node) && row.profile === entry.targetProfile);
        const root = Object.fromEntries(['node','profile','executionContext','owner','generation','nodeIdentity','originalSnapshot','adoptionReceipt'].map(key => [key, key === 'node' ? id(owner.node) : plain(owner[key])]));
        if (!binding || binding.operationId !== id(operation) || binding.nodeId !== id(entry.node)
            || binding.targetProfile !== entry.targetProfile || binding.candidateHash !== 'sha256:' + entry.candidateHash
            || binding.backupId !== entry.backupId || binding.owner !== operation.leaseOwner
            || binding.attempt !== operation.attempts || binding.topologyRevision !== operation.topologyRevision
            || binding.priorDeployedRevision !== operation.priorDeployedRevision
            || binding.executionContext !== operation.executionContext.hostIdentity || entry.state !== 'committed'
            || proof?.length !== 1 || !validTerminalReceipt(proof[0], binding) || proof[0].terminalOutcome !== 'verified'
            || fence?.length !== 1 || !same(plain(fence[0]), root)
            || createHash('sha256').update(Buffer.from(entry.candidate.bytes)).digest('hex') !== entry.candidateHash
            || entry.candidate.sha256 !== entry.candidateHash) fail();
    };
    for (const entry of op.nodes) {
        const owner = owners.find(row => id(row.node) === id(entry.node) && row.profile === entry.targetProfile);
        const bindings = op.v2Terminal.bindings?.filter(row => row.nodeId === id(entry.node));
        const oldEntries = prior.nodes.filter(row => id(row.node) === id(entry.node) && row.targetProfile === entry.targetProfile);
        const oldBindings = prior.v2Terminal.bindings?.filter(row => row.nodeId === id(entry.node));
        if (!owner || owner.owner !== 'topology' || owner.handbackReceipt !== undefined
            || owner.lastSettledOperation !== id(op) || bindings?.length !== 1 || oldEntries.length !== 1 || oldBindings?.length !== 1
            || bindings[0].predecessorGeneration !== oldBindings[0].generation
            || owner.lastSettledGeneration !== bindings[0].generation || owner.lastSettledCloseId !== bindings[0].commandIds.close
            || owner.lastSettledRevision !== op.topologyRevision || !prior.selectedOwnerPins?.some(pin => pin.node === id(entry.node)
                && pin.profile === owner.profile && pin.generation === owner.generation
                && same(pin.nodeIdentity, plain(owner.nodeIdentity)) && same(pin.originalSnapshot, plain(owner.originalSnapshot))
                && same(pin.adoptionReceipt, plain(owner.adoptionReceipt)))) fail();
        check(op, entry, bindings[0], op.v2Terminal, owner);
        check(prior, oldEntries[0], oldBindings[0], prior.v2Terminal, owner);
    }
    const topology = durableSelectedTopology(prior.effectiveTopology);
    // Full-sync's documented identity-only contract uses deterministic UUIDs,
    // not the predecessor descriptor's stored tunnel credential override.
    topology.links = topology.links.map(({ tunnelUuid, ...link }) => link);
    const ids = topology.links.map(link => link.id);
    topology.groups = require('../domain/topologyDraft').projectGroups(groups)
        .filter(group => group.paths.some(path => path.linkIds.some(link => ids.includes(link))));
    if (topology.groups.some(group => group.paths.some(path => path.linkIds.some(link => !ids.includes(link))))
        || prior.effectiveTopology.groups.some(group => !topology.groups.some(row => same(row, group)))) fail();
    const generated = require('./frozenTopologyDeploymentPlanComposer').composeFrozenTopologyDeploymentPlan({
        snapshot: topology, staged: true, nodeMetadata: topology.nodes, linkMetadata: topology.links,
        compiledTopology: require('../domain/topologyCompiler').compileTopology({ ...topology, healthByPathKey: {} }),
    });
    if (generated.nodes.length !== op.nodes.length || generated.nodes.some(entry => !op.nodes.some(row =>
        id(row.node) === entry.node && row.targetProfile === entry.targetProfile && row.candidateHash === entry.candidate.sha256))) fail();
    // Ref provenance comes from the exact canonical full plan just proved.
    // It is private frozen descriptor metadata, never a request/desired field.
    for (const [index, link] of [...topology.links].sort((a,b)=>a.id.localeCompare(b.id,'en')).entries()) link.artifactRef = `link-${index+1}`;
    return topology;
}
module.exports = { recoverSettledFullReconcile, recoverFrozenFullReconcile };
