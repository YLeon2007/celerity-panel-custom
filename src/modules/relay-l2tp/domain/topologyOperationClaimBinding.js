'use strict';

const { matchesTopologyOperationExecutionContext } = require('./topologyExecutionContext');

// Bounded producer grammar. Do not adopt legacy keys or arbitrary middle segments.
const SCOPE = '(?::(?:link\\.apply|domain\\.reconcile):[A-Za-z0-9._-]{1,128}'
    + '|:(?:link\\.replace|link\\.attach):[A-Za-z0-9._-]{1,128}:[a-f0-9]{64})?';
const UUID = '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}';
function keyParts(context) {
    return [
        `^topology:${context.target}:revision-`,
        `${SCOPE}:host-${context.hostIdentity.replace(/\./g, '\\.')}:${UUID}(?![\\s\\S])`,
    ];
}

function matchesTopologyOperationClaimBinding(operation, context) {
    if (!matchesTopologyOperationExecutionContext(operation, context)) return false;
    const [prefix, suffix] = keyParts(context);
    return new RegExp(`${prefix}${operation.topologyRevision}${suffix}`).test(operation.idempotencyKey);
}

function topologyOperationClaimBindingFilter(context) {
    const [prefix, suffix] = keyParts(context);
    const revision = { $convert: { input: '$topologyRevision', to: 'long', onError: -1, onNull: -1 } };
    return {
        'executionContext.target': context.target,
        'executionContext.hostIdentity': context.hostIdentity,
        topologyRevision: { $type: ['double', 'int', 'long'], $gte: 0, $lte: Number.MAX_SAFE_INTEGER },
        $expr: { $and: [
            // Exact object equality rejects extra fields, arrays and partial historical bindings.
            { $eq: ['$executionContext', { $literal: { ...context } }] },
            { $eq: ['$topologyRevision', revision] },
            { $regexMatch: {
                input: { $convert: { input: '$idempotencyKey', to: 'string', onError: '', onNull: '' } },
                regex: { $concat: [prefix, { $toString: revision }, suffix] },
            } },
        ] },
    };
}

module.exports = { matchesTopologyOperationClaimBinding, topologyOperationClaimBindingFilter };
