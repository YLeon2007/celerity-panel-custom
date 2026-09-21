'use strict';

function hasDirectedCycle(nodeIds, links) {
    const uniqueNodeIds = [...new Set(nodeIds)];
    const outgoing = new Map(uniqueNodeIds.map(nodeId => [nodeId, []]));
    const indegree = new Map(uniqueNodeIds.map(nodeId => [nodeId, 0]));

    for (const link of links) {
        if (link.source === link.target) continue;
        outgoing.get(link.source).push(link.target);
        indegree.set(link.target, indegree.get(link.target) + 1);
    }

    const queue = uniqueNodeIds.filter(nodeId => indegree.get(nodeId) === 0);
    let visitedCount = 0;

    while (queue.length > 0) {
        const nodeId = queue.shift();
        visitedCount += 1;

        for (const targetNodeId of outgoing.get(nodeId)) {
            const nextIndegree = indegree.get(targetNodeId) - 1;
            indegree.set(targetNodeId, nextIndegree);
            if (nextIndegree === 0) queue.push(targetNodeId);
        }
    }

    return visitedCount !== uniqueNodeIds.length;
}

function validateTopology({ links = [], groups = [] } = {}) {
    const errors = [];

    for (const group of groups) {
        const nodeIds = group.nodeIds || [];
        const groupNodeIds = new Set(nodeIds);
        const groupLinks = links.filter(link =>
            groupNodeIds.has(link.source) && groupNodeIds.has(link.target)
        );
        const pathLinks = [];

        for (const link of groupLinks) {
            if (link.source === link.target) {
                errors.push({
                    code: 'SELF_LOOP',
                    groupId: group.id,
                    linkId: link.id,
                    nodeId: link.source,
                });
            }
        }

        if (hasDirectedCycle(nodeIds, groupLinks)) {
            errors.push({
                code: 'CYCLE_DETECTED',
                groupId: group.id,
            });
        }

        for (let index = 0; index < nodeIds.length - 1; index += 1) {
            const sourceNodeId = nodeIds[index];
            const targetNodeId = nodeIds[index + 1];
            const link = groupLinks.find(candidate =>
                candidate.source === sourceNodeId && candidate.target === targetNodeId
            );

            if (!link) {
                errors.push({
                    code: 'DISCONTINUOUS_PATH',
                    groupId: group.id,
                    sourceNodeId,
                    targetNodeId,
                });
            } else {
                pathLinks.push(link);
            }
        }

        const modes = [...new Set(pathLinks.map(link => link.mode))].sort();
        if (modes.length > 1) {
            errors.push({
                code: 'MIXED_LINK_MODES',
                groupId: group.id,
                modes,
            });
        }
    }

    return {
        valid: errors.length === 0,
        errors,
    };
}

module.exports = { validateTopology };
