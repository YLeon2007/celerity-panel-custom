'use strict';

const { topologyExecutionContext, TOPOLOGY_EXECUTION_CONTEXTS } = require('./topologyExecutionContext');

function resolveL2tpExecutionAuthorization(env) {
    const selected = env && typeof env === 'object' && !Array.isArray(env)
        ? TOPOLOGY_EXECUTION_CONTEXTS.find(pair => pair.hostIdentity === env.PANEL_DOMAIN) : undefined;
    const enabled = !!selected && env.L2TP_EXECUTION_ENABLED === 'true'
        && env.L2TP_MIGRATIONS_ENABLED === 'true'
        && (selected.target === 'production' ? env.L2TP_PRODUCTION_EXECUTION_ENABLED === 'true'
            : env.TOPOLOGY_TEST_EXECUTION_ENABLED === 'true');
    const executionContext = enabled ? selected : undefined;
    return Object.freeze({
        executionContext,
        enableProductionExecution: enabled && selected.target === 'production',
        enableUnsafeExecutionForTests: enabled && selected.target === 'test',
        enableInstallAdmission: enabled,
    });
}

// Copy nothing from callers: select one immutable server allowlist entry.
function selectExecutionContext(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || Object.keys(value).sort().join('\0') !== 'hostIdentity\0target') return undefined;
    return topologyExecutionContext(value.target, value.hostIdentity);
}

function bindExecutionAuthorization(owner, { executionContext, enableProductionExecution = false } = {}) {
    Object.defineProperties(owner, {
        executionContext: { value: selectExecutionContext(executionContext) },
        enableProductionExecution: { value: enableProductionExecution === true },
    });
}

function executionAuthorized(owner, testEnabled = true) {
    return !!owner.executionContext && (owner.executionContext.target === 'production'
        ? owner.enableProductionExecution === true : testEnabled === true);
}

function authorizationError() {
    return Object.assign(new Error('L2TP execution is not authorized'), {
        code: 'L2TP_EXECUTION_NOT_AUTHORIZED',
    });
}

function assertExecutionAuthorized(owner, testEnabled = true) {
    if (!executionAuthorized(owner, testEnabled)) {
        throw authorizationError();
    }
}

function matchesExecutionContext(value, expected) {
    return !!expected && selectExecutionContext(value) === expected;
}

function assertExecutionBinding(owner, binding) {
    assertExecutionAuthorized(owner);
    if (!matchesExecutionContext(binding, owner.executionContext)) throw authorizationError();
}

function executionContextFilter(context) {
    return { 'executionContext.target': context.target,
        'executionContext.hostIdentity': context.hostIdentity };
}

module.exports = { resolveL2tpExecutionAuthorization, selectExecutionContext, bindExecutionAuthorization, executionAuthorized,
    assertExecutionAuthorized, assertExecutionBinding, matchesExecutionContext, executionContextFilter };
