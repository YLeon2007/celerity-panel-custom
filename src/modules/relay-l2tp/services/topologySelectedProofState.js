'use strict';

const { isDeepStrictEqual: same } = require('node:util');
const { selectedAdmissionFingerprint, durableSelectedTopology } = require('../repositories/topologyOperationRepository');
const { matchesTopologyExecutionContext, topologyExecutionContext } = require('../domain/topologyExecutionContext');
const { linkDesiredVersion } = require('./topologyIntentService');
const { validTerminalReceipt } = require('../models/topologyExecutionBindingContract');
const PRIVATE_PROOF_SELECT = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +installedPath +deleteJobId +clientProofFingerprint +clientProofCredentialDigest';
const plain = value => JSON.parse(JSON.stringify(value));

// Config owner pointers and frozen descriptors are authority. Neither the
// panel-wide revision nor a mutable desired neighbour is an applied snapshot.
async function readSettledSelectedOperation(repository, expected) {
    try {
        if (expected?.admissionScope !== 'selected') return null;
        const context = topologyExecutionContext(expected.executionContext?.target, expected.executionContext?.hostIdentity);
        if (!matchesTopologyExecutionContext(expected.executionContext, context)) return null;
        const operation = await repository.TopologyOperation.findById(expected._id).select(PRIVATE_PROOF_SELECT).lean();
        if (!operation || operation.admissionScope !== 'selected' || operation.status !== 'succeeded'
            || operation.heldTopologyAdmission !== false || operation.pppWait != null
            || operation.admissionFingerprint !== expected.admissionFingerprint
            || operation.idempotencyKey !== expected.idempotencyKey
            || !matchesTopologyExecutionContext(operation.executionContext, context)
            || operation.admissionFingerprint !== selectedAdmissionFingerprint(operation)
            || !Array.isArray(operation.selectedOwnerPins) || !operation.selectedOwnerPins.length
            || new Set(operation.selectedOwnerPins.map(pin => pin.node)).size !== operation.selectedOwnerPins.length
            || operation.resourceNodeIds?.length !== operation.selectedOwnerPins.length
            || operation.nodes.length !== operation.selectedOwnerPins.length
            || operation.resourceNodeIds.some(node => !operation.selectedOwnerPins.some(pin => pin.node === node))
            || operation.nodes.some(node => node.state !== 'committed')) return null;
        durableSelectedTopology(operation.effectiveTopology);
        for (const pin of operation.selectedOwnerPins) {
            const owner = await repository.TopologyConfigOwner.findOne({ node: pin.node, profile: pin.profile }).lean();
            if (!owner || owner.owner !== 'topology' || owner.lastSettledOperation !== String(operation._id)
                || owner.lastSettledRevision !== operation.topologyRevision || !owner.lastSettledGeneration
                || !matchesTopologyExecutionContext(owner.executionContext, context)
                || !operation.nodes.some(node => String(node.node) === pin.node && node.targetProfile === pin.profile)
                || ['generation', 'nodeIdentity', 'originalSnapshot', 'adoptionReceipt', 'handbackReceipt']
                    .some(key => !same(owner[key] === undefined ? undefined : plain(owner[key]), pin[key]))) return null;
            if (operation.v2Terminal) {
                const binding = operation.v2Terminal.bindings?.find(item => item.nodeId === pin.node);
                const proof = operation.v2Terminal.proofs?.find(item => item.commandId === owner.lastSettledCloseId);
                if (operation.v2Terminal.state !== 'proven' || !binding
                    || binding.generation !== owner.lastSettledGeneration
                    || binding.commandIds?.close !== owner.lastSettledCloseId
                    || !validTerminalReceipt(proof, binding) || proof.terminalOutcome !== 'verified') return null;
            } else if (operation.executionContext.target !== 'test') return null;
        }
        if (repository.NodeOperationLock?.exists && await repository.NodeOperationLock.exists({ node: { $in: operation.resourceNodeIds } })) return null;
        const link = await repository.snapshotReader.CascadeLink.findById(operation.linkId).lean();
        if (operation.kind === 'link.delete' ? link != null
            : !link || link.lifecycle?.state === 'deleting' || linkDesiredVersion(link) !== operation.desiredVersion) return null;
        return operation;
    } catch { return null; }
}
module.exports = { PRIVATE_PROOF_SELECT, readSettledSelectedOperation };
