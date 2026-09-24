'use strict';

const {
    cascadePathIngressPort,
    cascadePathIngressTag,
} = require('./cascadePathIngress');

class TopologyDraftError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'TopologyDraftError';
        this.code = code;
        Object.assign(this, details);
    }
}

function entityId(value) {
    if (value === undefined || value === null) return null;
    const id = typeof value === 'object' ? value._id ?? value.id : value;
    return id === undefined || id === null ? null : String(id);
}

function projectNodes(nodes) {
    return (nodes || []).map(node => ({
        id: entityId(node),
        role: node.cascadeRole ?? node.role,
    }));
}

function projectLinks(links) {
    return (links || [])
        .filter(link => link.active !== false)
        .map(link => ({
            id: entityId(link),
            source: entityId(link.portalNode ?? link.source),
            target: entityId(link.bridgeNode ?? link.target),
            mode: link.mode,
        }));
}

function projectGroups(groups) {
    return (groups || []).map(group => {
        const groupId = entityId(group);
        return {
            _id: groupId,
            mode: group.mode,
            strategy: group.strategy,
            paths: (group.paths || []).map(path => {
                const projected = {
                    pathKey: path.pathKey,
                    linkIds: (path.linkIds || []).map(entityId),
                    priority: path.priority,
                    enabled: path.enabled !== false,
                };
                if (groupId !== null && typeof path.pathKey === 'string' && path.pathKey.length > 0) {
                    projected.cascadePathIngress = {
                        tag: cascadePathIngressTag(path.pathKey),
                        port: cascadePathIngressPort(groupId, path.pathKey),
                    };
                }
                return projected;
            }),
        };
    });
}

function buildCandidate(snapshot, mutation) {
    let links = [...(snapshot.links || [])];
    let groups = [...(snapshot.groups || [])];

    if (mutation.kind === 'link.create') {
        const linkId = entityId(mutation.document);
        if (!linkId) {
            throw new TopologyDraftError('INVALID_LINK_ID', 'A cascade link id is required');
        }
        if (links.some(link => entityId(link) === linkId)) {
            throw new TopologyDraftError('CASCADE_LINK_CONFLICT', 'The cascade link already exists', {
                linkId,
            });
        }
        links = [...links, mutation.document];
    } else if (mutation.kind === 'link.update') {
        const linkId = entityId(mutation.id);
        const linkIndex = links.findIndex(link => entityId(link) === linkId);
        if (linkIndex < 0) {
            throw new TopologyDraftError('CASCADE_LINK_NOT_FOUND', 'The cascade link was not found', {
                linkId,
            });
        }
        links[linkIndex] = {
            ...links[linkIndex],
            ...(mutation.changes || {}),
            _id: links[linkIndex]._id ?? links[linkIndex].id,
        };
    } else if (mutation.kind === 'link.delete') {
        const linkId = entityId(mutation.id);
        const linkIndex = links.findIndex(link => entityId(link) === linkId);
        if (linkIndex < 0) {
            throw new TopologyDraftError('CASCADE_LINK_NOT_FOUND', 'The cascade link was not found', {
                linkId,
            });
        }
        // A deleted link must not linger in route group paths (the validator
        // rejects UNKNOWN_LINK). Strip every path that used the link; groups
        // left without any path are dropped unless active relay state still
        // references them (an active empty group is valid — it simply has no
        // egress path until the operator wires a new one).
        const activeGroupIds = new Set((snapshot.activeRouteGroupIds || []).map(entityId));
        groups = groups
            .map(group => {
                const paths = group.paths || [];
                const keptPaths = paths.filter(path =>
                    !(path.linkIds || []).some(pathLinkId => entityId(pathLinkId) === linkId));
                return keptPaths.length === paths.length ? group : { ...group, paths: keptPaths };
            })
            .filter(group => (group.paths || []).length > 0 || activeGroupIds.has(entityId(group)));
        links = links.filter((link, index) => index !== linkIndex);
    } else if (mutation.kind === 'group.create') {
        const routeGroupId = entityId(mutation.document);
        if (!routeGroupId) {
            throw new TopologyDraftError('INVALID_ROUTE_GROUP_ID', 'A route group id is required');
        }
        if (groups.some(group => entityId(group) === routeGroupId)) {
            throw new TopologyDraftError(
                'CASCADE_ROUTE_GROUP_CONFLICT',
                'The cascade route group already exists',
                { routeGroupId },
            );
        }
        groups = [...groups, mutation.document];
    } else if (mutation.kind === 'group.update') {
        const routeGroupId = entityId(mutation.id);
        const groupIndex = groups.findIndex(group => entityId(group) === routeGroupId);
        if (groupIndex < 0) {
            throw new TopologyDraftError(
                'CASCADE_ROUTE_GROUP_NOT_FOUND',
                'The cascade route group was not found',
                { routeGroupId },
            );
        }
        groups[groupIndex] = {
            ...groups[groupIndex],
            ...(mutation.changes || {}),
            _id: groups[groupIndex]._id ?? groups[groupIndex].id,
        };
    } else if (mutation.kind === 'group.delete') {
        const routeGroupId = entityId(mutation.id);
        const groupIndex = groups.findIndex(group => entityId(group) === routeGroupId);
        if (groupIndex < 0) {
            throw new TopologyDraftError(
                'CASCADE_ROUTE_GROUP_NOT_FOUND',
                'The cascade route group was not found',
                { routeGroupId },
            );
        }
        if ((snapshot.activeRouteGroupIds || []).some(id => entityId(id) === routeGroupId)) {
            throw new TopologyDraftError(
                'CASCADE_ROUTE_GROUP_IN_USE',
                'The cascade route group is referenced by active relay state',
                { routeGroupId },
            );
        }
        groups = groups.filter((group, index) => index !== groupIndex);
    } else {
        throw new TopologyDraftError(
            'UNSUPPORTED_TOPOLOGY_MUTATION',
            `Unsupported topology mutation: ${mutation.kind}`,
        );
    }

    const candidate = {
        nodes: projectNodes(snapshot.nodes),
        links: projectLinks(links),
        groups: projectGroups(groups),
    };
    return { candidate, mutation };
}

module.exports = {
    TopologyDraftError,
    buildCandidate,
    entityId,
    projectGroups,
    projectLinks,
    projectNodes,
};
