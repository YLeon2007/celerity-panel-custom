'use strict';

const FINALIZATION_INPUT_KEYS = Object.freeze([
    'leaseUntil',
    'operationId',
    'owner',
    'priorDeployedRevision',
    'topologyRevision',
]);

function validDate(value) {
    return value instanceof Date && Number.isFinite(value.getTime());
}

function validRevision(value) {
    return Number.isSafeInteger(value) && value >= 0;
}

function hasExactKeys(value, expectedKeys) {
    return Boolean(value)
        && typeof value === 'object'
        && !Array.isArray(value)
        && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expectedKeys);
}

function assertFinalizationInput(input) {
    const hasPppProof = Boolean(input) && Object.hasOwn(input, 'pppProof');
    const expectedKeys = hasPppProof
        ? [...FINALIZATION_INPUT_KEYS, 'pppProof'].sort()
        : FINALIZATION_INPUT_KEYS;
    if (!hasExactKeys(input, expectedKeys)
        || typeof input.operationId !== 'string'
        || input.operationId.length === 0
        || typeof input.owner !== 'string'
        || input.owner.length === 0
        || !validDate(input.leaseUntil)
        || !validRevision(input.topologyRevision)
        || !validRevision(input.priorDeployedRevision)
        || (hasPppProof && (!Array.isArray(input.pppProof)
            || input.pppProof.length === 0
            || input.pppProof.some(item => !hasExactKeys(item, ['credentialRevision', 'relayNode'])
                || typeof item.relayNode !== 'string' || item.relayNode.length === 0
                || !validRevision(item.credentialRevision) || item.credentialRevision < 1)))) {
        throw new TypeError('Invalid topology operation finalization input');
    }
}

const SCOPED_RESULT_KINDS = new Set(['link.apply', 'domain.reconcile', 'link.replace', 'link.attach']);

function projectFinalized(result, input) {
    const scoped = SCOPED_RESULT_KINDS.has(result?.scopeKind);
    const expectedDeployedRevision = scoped
        ? input.priorDeployedRevision
        : input.topologyRevision;
    if (!result
        || (result.scopeKind !== undefined && !scoped)
        || result.operationId !== input.operationId
        || result.topologyRevision !== input.topologyRevision
        || result.deployedRevision !== expectedDeployedRevision
        || !validDate(result.finishedAt)) {
        return null;
    }
    return Object.freeze({
        operationId: input.operationId,
        topologyRevision: input.topologyRevision,
        deployedRevision: expectedDeployedRevision,
        finishedAt: result.finishedAt,
    });
}

class TopologyOperationFinalizer {
    constructor({ repository, clock } = {}) {
        if (!repository || typeof repository.finalizeSucceeded !== 'function') {
            throw new TypeError('Topology operation finalizer requires atomic persistence');
        }
        if (!clock || typeof clock.now !== 'function') {
            throw new TypeError('Topology operation finalizer requires a clock');
        }
        this.repository = repository;
        this.clock = clock;
    }

    async finalizeSucceeded(input) {
        assertFinalizationInput(input);
        const now = this.clock.now();
        if (!validDate(now)) {
            throw new TypeError('Topology operation finalizer clock returned an invalid date');
        }
        const finalized = await this.repository.finalizeSucceeded({ ...input, now });
        return projectFinalized(finalized, input);
    }
}

module.exports = {
    FINALIZATION_INPUT_KEYS,
    TopologyOperationFinalizer,
    assertFinalizationInput,
};
