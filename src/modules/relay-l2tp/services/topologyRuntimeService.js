'use strict';

const ACTIVE_TOPOLOGY_ROLES = Object.freeze(['portal', 'relay', 'bridge']);
const NODE_TOPOLOGY_FILTER = Object.freeze({
    type: 'xray',
    active: true,
    cascadeRole: Object.freeze({ $in: ACTIVE_TOPOLOGY_ROLES }),
});
const LINK_TOPOLOGY_FILTER = Object.freeze({ active: true });
const GROUP_TOPOLOGY_FILTER = Object.freeze({});
const NODE_TOPOLOGY_SELECT = '_id cascadeRole';
const LINK_TOPOLOGY_SELECT = '_id portalNode bridgeNode mode';
const GROUP_TOPOLOGY_SELECT = '_id mode strategy paths.pathKey paths.linkIds paths.priority';

function stringId(value) {
    if (value === undefined || value === null) return null;
    return String(value._id ?? value.id ?? value);
}

function compareIds(left, right) {
    return String(left.id ?? left._id).localeCompare(String(right.id ?? right._id));
}

function projectNodes(rows) {
    return rows
        .map(node => ({
            id: stringId(node._id ?? node.id),
            role: node.cascadeRole ?? node.role,
        }))
        .filter(node => node.id && ACTIVE_TOPOLOGY_ROLES.includes(node.role))
        .sort(compareIds);
}

function projectLinks(rows, activeNodeIds) {
    return rows
        .map(link => ({
            id: stringId(link._id ?? link.id),
            source: stringId(link.portalNode ?? link.source),
            target: stringId(link.bridgeNode ?? link.target),
            mode: link.mode,
        }))
        .filter(link => (
            link.id
            && activeNodeIds.has(link.source)
            && activeNodeIds.has(link.target)
        ))
        .sort(compareIds);
}

function projectGroups(rows) {
    return rows
        .map(group => ({
            _id: stringId(group._id ?? group.id),
            mode: group.mode,
            strategy: group.strategy,
            paths: (group.paths || [])
                .map(path => ({
                    pathKey: path.pathKey,
                    linkIds: (path.linkIds || []).map(stringId),
                    priority: path.priority,
                }))
                .sort((left, right) => String(left.pathKey).localeCompare(String(right.pathKey))),
        }))
        .filter(group => group._id)
        .sort(compareIds);
}

async function readHealthSource(healthByPathKey) {
    const source = typeof healthByPathKey === 'function'
        ? await healthByPathKey()
        : healthByPathKey;
    return source && typeof source === 'object' ? source : {};
}

function isKnownHealthy(source, key) {
    return source instanceof Map ? source.get(key) === true : source[key] === true;
}

function failClosedHealth(groups, links, source) {
    const activeLinkIds = new Set(links.map(link => link.id));
    const health = {};

    for (const group of groups) {
        for (const path of group.paths) {
            const key = `${group._id}:${path.pathKey}`;
            const complete = path.linkIds.length > 0
                && path.linkIds.every(linkId => activeLinkIds.has(linkId));
            health[key] = complete && isKnownHealthy(source, key);
        }
    }

    return health;
}

class TopologyRuntimeService {
    constructor({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        compiler,
        healthByPathKey = {},
    }) {
        this.HyNode = HyNode;
        this.CascadeLink = CascadeLink;
        this.CascadeRouteGroup = CascadeRouteGroup;
        this.compiler = compiler;
        this.healthByPathKey = healthByPathKey;
    }

    async getRelayGroupPlan(relayId, groupId) {
        const [nodeRows, linkRows, groupRows, healthSource] = await Promise.all([
            this.HyNode.find(NODE_TOPOLOGY_FILTER)
                .select(NODE_TOPOLOGY_SELECT)
                .lean(),
            this.CascadeLink.find(LINK_TOPOLOGY_FILTER)
                .select(LINK_TOPOLOGY_SELECT)
                .lean(),
            this.CascadeRouteGroup.find(GROUP_TOPOLOGY_FILTER)
                .select(GROUP_TOPOLOGY_SELECT)
                .lean(),
            readHealthSource(this.healthByPathKey),
        ]);
        const nodes = projectNodes(nodeRows);
        const activeNodeIds = new Set(nodes.map(node => node.id));
        const links = projectLinks(linkRows, activeNodeIds);
        const groups = projectGroups(groupRows);
        const healthByPathKey = failClosedHealth(groups, links, healthSource);
        const compiled = this.compiler({ nodes, links, groups, healthByPathKey });
        const relay = compiled.relays.find(entry => String(entry.nodeId) === String(relayId));

        return relay?.routeGroups.find(
            entry => String(entry.groupId) === String(groupId),
        ) ?? null;
    }
}

module.exports = {
    ACTIVE_TOPOLOGY_ROLES,
    GROUP_TOPOLOGY_FILTER,
    GROUP_TOPOLOGY_SELECT,
    LINK_TOPOLOGY_FILTER,
    LINK_TOPOLOGY_SELECT,
    NODE_TOPOLOGY_FILTER,
    NODE_TOPOLOGY_SELECT,
    TopologyRuntimeService,
};
