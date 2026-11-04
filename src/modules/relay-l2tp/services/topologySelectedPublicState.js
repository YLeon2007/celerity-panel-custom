'use strict';

const { isDeepStrictEqual: same } = require('node:util');
const { linkDesiredVersion } = require('./topologyIntentService');
const { matchesTopologyExecutionContext } = require('../domain/topologyExecutionContext');
const { selectedAdmissionFingerprint } = require('../repositories/topologyOperationRepository');
const { PRIVATE_PROOF_SELECT: PRIVATE_SELECT } = require('./topologySelectedProofState');
const ID = /^[a-f0-9]{24}$/;
const VERSION = /^[a-f0-9]{64}$/;
const STATUSES = new Set(['queued', 'preparing', 'committing', 'rolling_back', 'succeeded', 'failed', 'rolled_back']);
const KINDS = new Set(['link.apply', 'link.delete', 'link.attach', 'link.replace', 'domain.reconcile']);
const ROUTES = new Set(['complete', 'no_portal_input', 'no_bridge_exit', 'policy_ambiguous']);

// Read-only projection over the existing selected-baseline verifier. It follows
// current settled profile pointers, not mutable desired neighbours or global
// revision. Never return any object read from the private operation/owner store.
function createTopologySelectedPublicState({ topologyRepository, operationRepository, executionContext }) {
    const Link = topologyRepository.snapshotReader.CascadeLink;
    const Operation = operationRepository.model;

    async function appliedState(linkId, desiredVersion) {
        const link = await Link.findById(linkId).lean();
        if (!link || linkDesiredVersion(link) !== desiredVersion) return null;
        const selected = await topologyRepository.readSelected({
            snapshot: await topologyRepository.snapshotReader.readDraft(),
            scope: { kind: 'link.apply', linkId }, desiredVersion, executionContext,
        });
        const before = selected.baselineTopology.links.find(row => row.id === linkId);
        const after = selected.effectiveTopology.links.find(row => row.id === linkId);
        if (!before || !after || !same(before, after)) return null;
        const pins = selected.selectedOwnerPins;
        const pointers = [...new Set(pins.map(pin => pin.lastSettledOperation))];
        if (pointers.length !== 1 || typeof pointers[0] !== 'string' || !ID.test(pointers[0])) return null;
        const operation = await Operation.findById(pointers[0]).select(PRIVATE_SELECT).lean();
        if (!operation || operation.admissionScope !== 'selected' || operation.status !== 'succeeded'
            || operation.heldTopologyAdmission !== false
            || !matchesTopologyExecutionContext(operation.executionContext, executionContext)
            || operation.admissionFingerprint !== selectedAdmissionFingerprint(operation)) return null;
        return { link, selected, operation };
    }

    async function readLinkApplicationState({ links } = {}) {
        if (!Array.isArray(links) || links.length > 1024) return [];
        const states = [];
        const seen = new Set();
        for (const entry of links) {
            if (typeof entry?.linkId !== 'string' || !ID.test(entry.linkId)
                || typeof entry.desiredVersion !== 'string' || !VERSION.test(entry.desiredVersion)
                || seen.has(entry.linkId)) continue;
            seen.add(entry.linkId);
            try {
                const checked = await appliedState(entry.linkId, entry.desiredVersion);
                if (!checked || !ROUTES.has(checked.selected.routeState)) continue;
                states.push({ linkId: entry.linkId, desiredVersion: entry.desiredVersion,
                    operationId: String(checked.operation._id),
                    applicationState: checked.link.lifecycle?.state === 'deleting' ? 'deleting' : 'applied',
                    routeState: checked.selected.routeState,
                    // A synthetic Xray request never establishes PPP traffic.
                    tunnelState: 'unknown', ...await selectedReadiness(checked.operation) });
            } catch { /* Unreadable or changed owner/descriptor never paints ready. */ }
        }
        return states;
    }

    async function selectedReadiness(operation) {
        const noExit = operation.routeState === 'no_bridge_exit';
        const proof = await operationRepository.findPublicById(String(operation._id));
        const portal = operation.effectiveTopology?.nodes.some(node => node.role === 'portal');
        return { xrayReadiness: noExit || !portal ? 'not_applicable'
            : proof?.xrayReadiness === 'verified' ? 'verified' : 'unverified',
            xrayInternetProof: noExit || !portal ? 'not_applicable'
                : proof?.xrayInternetProof === 'verified' ? 'verified' : 'unverified',
            ...(proof?.xrayInternetProof === 'verified' && !noExit && portal
                ? { xrayProofScope: 'configured_probe_user' } : {}),
            pppReadiness: noExit || proof?.pppReadiness === 'not_applicable' ? 'not_applicable' : 'unverified',
            pppInternetProof: noExit || proof?.pppReadiness === 'not_applicable' ? 'not_applicable' : 'unverified' };
    }

    async function readPublicOperation(operationId) {
        if (typeof operationId !== 'string' || !ID.test(operationId)) return null;
        const operation = await Operation.findById(operationId).select(PRIVATE_SELECT).lean();
        if (!operation || !matchesTopologyExecutionContext(operation.executionContext, executionContext)
            || !STATUSES.has(operation.status)) return null;
        let fresh = false;
        if (operation.admissionScope === 'selected' && operation.status === 'succeeded'
            && operation.heldTopologyAdmission === false) {
            try {
                fresh = await operationRepository.isLiveRevision(operation);
            } catch { /* Conservative stale/unverified projection. */ }
        }
        const legacy = operation.admissionScope === undefined
            ? await operationRepository.findPublicById(operationId) : null;
        const readiness = operation.admissionScope === 'selected' && fresh ? await selectedReadiness(operation) : null;
        return { operationId, status: operation.status,
            ...(Number.isSafeInteger(operation.topologyRevision) && operation.topologyRevision >= 0
                ? { topologyRevision: operation.topologyRevision } : {}),
            ...(KINDS.has(operation.kind) ? { kind: operation.kind } : {}),
            ...(typeof operation.linkId === 'string' && ID.test(operation.linkId) ? { linkId: operation.linkId } : {}),
            clientReadiness: legacy?.clientReadiness === 'verified' || readiness?.xrayReadiness === 'verified'
                && readiness.pppReadiness === 'not_applicable' ? 'verified' : 'unverified',
            ...(readiness || (operation.admissionScope === 'selected'
                ? { xrayReadiness: 'unverified', pppReadiness: 'unverified', pppInternetProof: 'unverified' } : {})),
            ...(operation.admissionScope === 'selected' ? {
                applicationState: operation.status === 'succeeded' ? fresh ? 'applied' : 'reconcile_required'
                    : ['failed', 'rolled_back'].includes(operation.status)
                        ? operation.heldTopologyAdmission === true ? 'reconcile_required' : 'not_applied' : 'applying',
                ...(fresh && ROUTES.has(operation.routeState) ? { routeState: operation.routeState } : {}),
            } : {}),
            heldTopologyAdmission: operation.heldTopologyAdmission === true,
            pppWaiting: !!operation.pppWait,
            ...(typeof operation.failedNodeId === 'string' && ID.test(operation.failedNodeId)
                ? { failedNodeId: operation.failedNodeId } : {}),
            ...(['TOPOLOGY_INTENT_RESOURCE_BUSY', 'TOPOLOGY_DEPLOY_BUSY', 'TOPOLOGY_RECONCILE_REQUIRED'].includes(operation.waitingReason)
                ? { waitingReason: operation.waitingReason } : {}),
        };
    }
    return Object.freeze({ readLinkApplicationState, readPublicOperation });
}
module.exports = { createTopologySelectedPublicState };
