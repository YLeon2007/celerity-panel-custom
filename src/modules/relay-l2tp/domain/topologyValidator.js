'use strict';

function hasDirectedCycle(links) {
    const uniqueNodeIds = [...new Set(links.flatMap(link => [link.source, link.target]))];
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
    const linksById = new Map(links.map(link => [String(link.id), link]));

    for (const group of groups) {
        const groupId = String(group._id ?? group.id);

        for (const path of group.paths || []) {
            const pathKey = path.pathKey;
            const linkIds = (path.linkIds || []).map(String);
            const pathLinks = linkIds
                .map(linkId => linksById.get(linkId))
                .filter(Boolean);

            for (const linkId of linkIds) {
                if (linksById.has(linkId)) continue;
                errors.push({
                    code: 'UNKNOWN_LINK',
                    groupId,
                    pathKey,
                    linkId,
                });
            }

            for (const link of pathLinks) {
                if (link.source !== link.target) continue;
                errors.push({
                    code: 'SELF_LOOP',
                    groupId,
                    pathKey,
                    linkId: link.id,
                    nodeId: link.source,
                });
            }

            if (hasDirectedCycle(pathLinks)) {
                errors.push({
                    code: 'CYCLE_DETECTED',
                    groupId,
                    pathKey,
                });
            }

            for (let index = 0; index < pathLinks.length - 1; index += 1) {
                const sourceNodeId = pathLinks[index].target;
                const targetNodeId = pathLinks[index + 1].source;

                if (sourceNodeId === targetNodeId) continue;
                errors.push({
                    code: 'DISCONTINUOUS_PATH',
                    groupId,
                    pathKey,
                    sourceNodeId,
                    targetNodeId,
                });
            }
        }
    }

    return {
        valid: errors.length === 0,
        errors,
    };
}

module.exports = { validateTopology };
