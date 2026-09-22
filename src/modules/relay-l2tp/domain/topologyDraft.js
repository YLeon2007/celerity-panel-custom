'use strict';

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
    return (groups || []).map(group => ({
        _id: entityId(group),
        mode: group.mode,
        strategy: group.strategy,
        paths: (group.paths || []).map(path => ({
            pathKey: path.pathKey,
            linkIds: (path.linkIds || []).map(entityId),
            priority: path.priority,
            enabled: path.enabled !== false,
        })),
    }));
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
        const routeGroupIds = groups
            .filter(group => (group.paths || []).some(path =>
                (path.linkIds || []).some(pathLinkId => entityId(pathLinkId) === linkId)
            ))
            .map(entityId)
            .sort();
        if (routeGroupIds.length > 0) {
            throw new TopologyDraftError(
                'CASCADE_LINK_IN_USE',
                'The cascade link is referenced by a route group',
                { linkId, routeGroupIds },
            );
        }
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
