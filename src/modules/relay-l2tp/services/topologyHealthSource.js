'use strict';

const DEFAULT_MAX_STALENESS_MS = 60_000;
const DEFAULT_CLOCK = Object.freeze({ now: () => new Date() });
const NODE_HEALTH_FILTER = Object.freeze({});
const LINK_HEALTH_FILTER = Object.freeze({});
const GROUP_HEALTH_FILTER = Object.freeze({});
const NODE_HEALTH_SELECT = '_id active status agentStatus agentLastSeen';
const LINK_HEALTH_SELECT = '_id active portalNode bridgeNode';
const GROUP_HEALTH_SELECT = '_id paths.pathKey paths.linkIds';

function stringId(value) {
    if (value === undefined || value === null) return null;
    return String(value._id ?? value.id ?? value);
}

function isActiveNode(node) {
    return node?.active === true;
}

function isCurrentOnline(node, nowMs, maxStalenessMs) {
    if (!isActiveNode(node) || node.status !== 'online' || node.agentStatus !== 'online') {
        return false;
    }

    const lastSeenMs = new Date(node.agentLastSeen).getTime();
    const ageMs = nowMs - lastSeenMs;
    return Number.isFinite(lastSeenMs) && ageMs >= 0 && ageMs <= maxStalenessMs;
}

class TopologyHealthSource {
    constructor({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        clock = DEFAULT_CLOCK,
        maxStalenessMs = DEFAULT_MAX_STALENESS_MS,
    }) {
        if (!Number.isFinite(maxStalenessMs) || maxStalenessMs <= 0) {
            throw new RangeError('maxStalenessMs must be a positive finite number');
        }

        this.HyNode = HyNode;
        this.CascadeLink = CascadeLink;
        this.CascadeRouteGroup = CascadeRouteGroup;
        this.clock = clock;
        this.maxStalenessMs = maxStalenessMs;
    }

    async getHealthByPathKey() {
        const [nodeRows, linkRows, groupRows] = await Promise.all([
            this.HyNode.find(NODE_HEALTH_FILTER).select(NODE_HEALTH_SELECT).lean(),
            this.CascadeLink.find(LINK_HEALTH_FILTER).select(LINK_HEALTH_SELECT).lean(),
            this.CascadeRouteGroup.find(GROUP_HEALTH_FILTER).select(GROUP_HEALTH_SELECT).lean(),
        ]);
        const nodesById = new Map(nodeRows.map(node => [stringId(node._id ?? node.id), node]));
        const linksById = new Map(linkRows.map(link => [stringId(link._id ?? link.id), link]));
        const nowMs = this.clock.now().getTime();
        const healthByPathKey = {};

        for (const group of groupRows) {
            const groupId = stringId(group._id ?? group.id);
            if (!groupId) continue;

            for (const path of group.paths || []) {
                const linkIds = (path.linkIds || []).map(stringId);
                healthByPathKey[`${groupId}:${path.pathKey}`] = linkIds.length > 0
                    && linkIds.every(linkId => {
                        const link = linksById.get(linkId);
                        const portalNode = nodesById.get(stringId(link?.portalNode));
                        const bridgeNode = nodesById.get(stringId(link?.bridgeNode));
                        return link?.active === true
                            && isActiveNode(portalNode)
                            && isCurrentOnline(bridgeNode, nowMs, this.maxStalenessMs);
                    });
            }
        }

        return healthByPathKey;
    }
}

module.exports = {
    DEFAULT_MAX_STALENESS_MS,
    GROUP_HEALTH_FILTER,
    GROUP_HEALTH_SELECT,
    LINK_HEALTH_FILTER,
    LINK_HEALTH_SELECT,
    NODE_HEALTH_FILTER,
    NODE_HEALTH_SELECT,
    TopologyHealthSource,
};
