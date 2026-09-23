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
    if (!hasExactKeys(input, FINALIZATION_INPUT_KEYS)
        || typeof input.operationId !== 'string'
        || input.operationId.length === 0
        || typeof input.owner !== 'string'
        || input.owner.length === 0
        || !validDate(input.leaseUntil)
        || !validRevision(input.topologyRevision)
        || !validRevision(input.priorDeployedRevision)) {
        throw new TypeError('Invalid topology operation finalization input');
    }
}

function projectFinalized(result, input) {
    if (!result
        || result.operationId !== input.operationId
        || result.topologyRevision !== input.topologyRevision
        || result.deployedRevision !== input.topologyRevision
        || !validDate(result.finishedAt)) {
        return null;
    }
    return Object.freeze({
        operationId: input.operationId,
        topologyRevision: input.topologyRevision,
        deployedRevision: input.topologyRevision,
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
