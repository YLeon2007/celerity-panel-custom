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

module.exports = {
    PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT,
    TEST_TOPOLOGY_EXECUTION_CONTEXT,
    TOPOLOGY_EXECUTION_CONTEXTS,
    topologyExecutionContext,
};
