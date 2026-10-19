'use strict';

// Server-owned identities only. Never derive an execution target from a request.
const TEST_TOPOLOGY_EXECUTION_CONTEXT = Object.freeze({
    target: 'test',
    hostIdentity: 'test.infograd.online',
});
const PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT = Object.freeze({
    target: 'production',
    hostIdentity: 'lm1.infograd.online',
});
const TOPOLOGY_EXECUTION_CONTEXTS = Object.freeze([
    TEST_TOPOLOGY_EXECUTION_CONTEXT,
    PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT,
]);

function topologyExecutionContext(target, hostIdentity) {
    return TOPOLOGY_EXECUTION_CONTEXTS.find(context => (
        context.target === target && context.hostIdentity === hostIdentity
    ));
}

function matchesTopologyExecutionContext(value, context) {
    return Boolean(value && context)
        && Object.keys(value).sort().join(',') === 'hostIdentity,target'
        && topologyExecutionContext(value.target, value.hostIdentity) === context;
}

function matchesTopologyOperationExecutionContext(operation, context) {
    if (!matchesTopologyExecutionContext(operation?.executionContext, context)
        || !Number.isSafeInteger(operation.topologyRevision) || operation.topologyRevision < 0
        || typeof operation.idempotencyKey !== 'string') return false;
    const prefix = `topology:${context.target}:revision-${operation.topologyRevision}:`;
    const suffix = operation.idempotencyKey.slice(prefix.length).split(':');
    return operation.idempotencyKey.startsWith(prefix)
        && suffix.at(-2) === `host-${context.hostIdentity}`
        && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(suffix.at(-1));
}

module.exports = {
    matchesTopologyOperationExecutionContext,
    matchesTopologyExecutionContext,
    PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT,
    TEST_TOPOLOGY_EXECUTION_CONTEXT,
    TOPOLOGY_EXECUTION_CONTEXTS,
    topologyExecutionContext,
};
