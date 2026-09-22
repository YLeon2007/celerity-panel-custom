'use strict';

const { buildL2tpXrayFragment } = require('./l2tpXrayFragmentProvider');

const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

class L2tpXrayCandidateError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'L2tpXrayCandidateError';
        this.code = code;
    }
}

function fail(code, message) {
    throw new L2tpXrayCandidateError(code, message);
}

function entityId(entity) {
    const value = entity !== null && typeof entity === 'object'
        ? entity._id ?? entity.id ?? entity.nodeId
        : entity;
    return value === null || value === undefined ? null : String(value);
}

function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assertSafeId(value) {
    return typeof value === 'string' && SAFE_ID_PATTERN.test(value);
}

function assertSafePlan(plan) {
    if (!isPlainObject(plan)) {
        fail('INVALID_OPERATION_PLAN', 'A safe L2TP operation plan is required');
    }
    if (plan.ok !== true || plan.error !== undefined) {
        fail('BLOCKED_TOPOLOGY', 'The L2TP topology selection is blocked');
    }
    if (
        !assertSafeId(plan.operationId)
        || !assertSafeId(plan.relayId)
        || !assertSafeId(plan.routeGroupId)
        || !assertSafeId(plan.selectedPathKey)
        || !assertSafeId(plan.nextHopNodeId)
        || !Number.isSafeInteger(plan.desired?.tproxyPort)
        || plan.desired.tproxyPort < 1
        || plan.desired.tproxyPort > 65535
    ) {
        fail('INVALID_OPERATION_PLAN', 'The L2TP operation plan selection is invalid');
    }
}

function assertNode(plan, node) {
    if (!isPlainObject(node)) {
        fail('NODE_NOT_FOUND', 'The L2TP relay node was not found');
    }
    const nodeId = entityId(node);
    if (nodeId !== null && nodeId !== plan.relayId) {
        fail('NODE_NOT_FOUND', 'The L2TP relay node was not found');
    }
    if (node.type !== 'xray') {
        fail('NODE_TYPE_NOT_XRAY', 'The L2TP relay node is not an Xray node');
    }
    if (node.active !== true) {
        fail('NODE_NOT_ACTIVE', 'The L2TP relay node is not active');
    }
    if ((node.cascadeRole ?? node.role) !== 'relay') {
        fail('NODE_NOT_RELAY', 'The L2TP node is not a relay');
    }
    if (typeof node.ip !== 'string' || node.ip.length === 0 || /\s/.test(node.ip)) {
        fail('NODE_CONFIG_INVALID', 'The L2TP relay node configuration is invalid');
    }
}

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
    return value;
}

function buildSnapshot(plan, node) {
    const outboundTag = `cascade-${plan.selectedPathKey}`;
    return {
        plan: {
            relay: {
                id: plan.relayId,
                controlPlaneIps: [node.ip],
            },
            group: { id: plan.routeGroupId },
            paths: [{
                pathKey: plan.selectedPathKey,
                healthy: true,
                outboundTag,
            }],
            selectedPathKey: plan.selectedPathKey,
        },
        tproxyPort: plan.desired.tproxyPort,
        tags: {
            inbound: `relay-l2tp-${plan.routeGroupId}`,
            blockOutbound: 'block',
        },
    };
}

function parseCandidate(generated) {
    if (typeof generated === 'string') {
        try {
            return { content: generated, config: JSON.parse(generated) };
        } catch {
            fail('INVALID_XRAY_CANDIDATE', 'The generated Xray candidate is invalid');
        }
    }
    if (!isPlainObject(generated)) {
        fail('INVALID_XRAY_CANDIDATE', 'The generated Xray candidate is invalid');
    }
    try {
        return { content: JSON.stringify(generated, null, 2), config: generated };
    } catch {
        fail('INVALID_XRAY_CANDIDATE', 'The generated Xray candidate is invalid');
    }
}

function assertCandidateConfig(config, snapshot) {
    const inboundTag = snapshot.tags.inbound;
    const outboundTag = snapshot.plan.paths[0].outboundTag;
    if (
        !isPlainObject(config)
        || !Array.isArray(config.inbounds)
        || !Array.isArray(config.outbounds)
        || !isPlainObject(config.routing)
        || !Array.isArray(config.routing.rules)
        || config.inbounds.filter(inbound => inbound?.tag === inboundTag).length !== 1
        || !config.outbounds.some(outbound => outbound?.tag === 'block')
        || !config.outbounds.some(outbound => outbound?.tag === outboundTag)
        || !config.routing.rules.some(rule => (
            Array.isArray(rule?.inboundTag)
            && rule.inboundTag.includes(inboundTag)
            && rule.outboundTag === outboundTag
        ))
    ) {
        fail('INVALID_XRAY_CANDIDATE', 'The generated Xray candidate is invalid');
    }
}

class L2tpXrayCandidateService {
    constructor({
        configGenerator,
        userResolver,
        nodeResolver,
        fragmentProvider = buildL2tpXrayFragment,
    } = {}) {
        if (
            typeof configGenerator !== 'function'
            || typeof userResolver !== 'function'
            || typeof nodeResolver !== 'function'
            || typeof fragmentProvider !== 'function'
        ) {
            throw new TypeError(
                'L2tpXrayCandidateService requires configGenerator, userResolver, nodeResolver, and fragmentProvider functions',
            );
        }
        this.configGenerator = configGenerator;
        this.userResolver = userResolver;
        this.nodeResolver = nodeResolver;
        this.fragmentProvider = fragmentProvider;
    }

    async buildCandidate({ plan } = {}) {
        assertSafePlan(plan);

        let node;
        try {
            node = await this.nodeResolver({
                operationId: plan.operationId,
                nodeId: plan.relayId,
            });
        } catch {
            fail('NODE_NOT_FOUND', 'The L2TP relay node was not found');
        }
        assertNode(plan, node);

        let users;
        try {
            users = await this.userResolver(node);
        } catch {
            fail('USER_RESOLUTION_FAILED', 'Failed to resolve Xray users for the L2TP relay');
        }
        if (!Array.isArray(users)) {
            fail('USER_RESOLUTION_FAILED', 'Failed to resolve Xray users for the L2TP relay');
        }

        const snapshot = buildSnapshot(plan, node);
        let fragment;
        try {
            fragment = deepFreeze(this.fragmentProvider(snapshot));
        } catch {
            fail('XRAY_CONFIG_GENERATION_FAILED', 'Failed to generate the Xray candidate');
        }

        let generated;
        try {
            generated = await this.configGenerator(node, users, { fragments: [fragment] });
        } catch {
            fail('XRAY_CONFIG_GENERATION_FAILED', 'Failed to generate the Xray candidate');
        }

        const { content, config } = parseCandidate(generated);
        assertCandidateConfig(config, snapshot);
        return Object.freeze({ operationId: plan.operationId, content });
    }
}

module.exports = {
    L2tpXrayCandidateError,
    L2tpXrayCandidateService,
};
