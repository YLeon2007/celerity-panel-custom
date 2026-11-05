'use strict';

const { isDeepStrictEqual: same } = require('node:util');
const { selectedAdmissionFingerprint, durableSelectedTopology } = require('../repositories/topologyOperationRepository');
const { matchesTopologyExecutionContext, topologyExecutionContext } = require('../domain/topologyExecutionContext');
const { linkDesiredVersion } = require('./topologyIntentService');
const { validTerminalReceipt } = require('../models/topologyExecutionBindingContract');
const { assertSelectedProfileTargets, verifyImportedProfileTargetPin } = require('./topologyProfileTarget');
const PRIVATE_PROOF_SELECT = '+admissionScope +resourceNodeIds +baselineTopology +effectiveTopology +selectedOwnerPins +desiredVersion +installedPath +deleteJobId +clientProofFingerprint +clientProofCredentialDigest';
const plain = value => JSON.parse(JSON.stringify(value));
const hasTargetPin = value => value && Object.hasOwn(value, 'profileTargetPin');

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
        assertSelectedProfileTargets(operation);
        for (const pin of operation.selectedOwnerPins) {
            const owner = await repository.TopologyConfigOwner.findOne({ node: pin.node, profile: pin.profile })
                .select('+legacyAppliedTopology +profileTargetPin').lean();
            if (!owner || owner.owner !== 'topology' || owner.lastSettledOperation !== String(operation._id)
                || owner.lastSettledRevision !== operation.topologyRevision || !owner.lastSettledGeneration
                || !matchesTopologyExecutionContext(owner.executionContext, context)
                || !operation.nodes.some(node => String(node.node) === pin.node && node.targetProfile === pin.profile)
                || ['generation', 'nodeIdentity', 'originalSnapshot', 'adoptionReceipt', 'handbackReceipt', 'profileTargetPin']
                    .some(key => !same(owner[key] === undefined ? undefined : plain(owner[key]), pin[key]))) return null;
            if (hasTargetPin(owner) || hasTargetPin(pin)) {
                verifyImportedProfileTargetPin({ owner, profileTargetPin: pin.profileTargetPin, executionContext: context });
                const entries = operation.nodes.filter(node => String(node.node) === pin.node);
                if (entries.length !== 1 || entries[0].targetProfile !== pin.profile
                    || !same(entries[0].profileTargetPin, pin.profileTargetPin)) return null;
                // Current bytes must be the committed canonical candidate, not
                // the immutable original descriptor used to qualify placement.
                require('./topologyXrayCandidate').projectCanonicalXrayCandidate(entries[0].candidate, entries[0].candidateHash);
            }
            if (operation.v2Terminal) {
                const binding = operation.v2Terminal.bindings?.find(item => item.nodeId === pin.node);
                const proof = operation.v2Terminal.proofs?.find(item => item.commandId === owner.lastSettledCloseId);
                if (operation.v2Terminal.state !== 'proven' || !binding
                    || binding.generation !== owner.lastSettledGeneration
                    || binding.commandIds?.close !== owner.lastSettledCloseId
                    || !validTerminalReceipt(proof, binding) || proof.terminalOutcome !== 'verified') return null;
                if (hasTargetPin(pin)) {
                    const entry = operation.nodes.find(node => String(node.node) === pin.node);
                    if (operation.v2Terminal.bindings.filter(item => item.nodeId === pin.node).length !== 1
                        || operation.v2Terminal.proofs.filter(item => item.commandId === owner.lastSettledCloseId).length !== 1
                        || !same(binding.profileTargetPin, pin.profileTargetPin)
                        || binding.operationId !== String(operation._id) || binding.targetProfile !== pin.profile
                        || binding.candidateHash !== `sha256:${entry.candidateHash}` || binding.backupId !== entry.backupId
                        || binding.executionContext !== context.hostIdentity || binding.owner !== operation.leaseOwner
                        || binding.attempt !== operation.attempts || binding.topologyRevision !== operation.topologyRevision
                        || binding.priorDeployedRevision !== operation.priorDeployedRevision) return null;
                }
            } else if (hasTargetPin(pin) || operation.executionContext.target !== 'test') return null;
        }
        if (repository.NodeOperationLock?.exists && await repository.NodeOperationLock.exists({ node: { $in: operation.resourceNodeIds } })) return null;
        const link = await repository.snapshotReader.CascadeLink.findById(operation.linkId).lean();
        if (operation.kind === 'link.delete' ? link != null
            : !link || link.lifecycle?.state === 'deleting' || linkDesiredVersion(link) !== operation.desiredVersion) return null;
        return operation;
    } catch { return null; }
}
module.exports = { PRIVATE_PROOF_SELECT, readSettledSelectedOperation };
