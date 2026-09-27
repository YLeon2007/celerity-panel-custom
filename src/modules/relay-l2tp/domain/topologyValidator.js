'use strict';

// The deployment plan composer rejects domains whose links mix forward and
// reverse modes (MIXED_TOPOLOGY_MODES). Mode uniformity is therefore a
// domain-level (connected component) invariant, not just a path-level one:
// links outside every route-group path (e.g. fan-in portal links) never hit
// the per-path check below and could otherwise be persisted as an
// undeployable draft. Independent components may still legitimately use
// different modes, so uniformity is enforced per component, not globally.
function findMixedModeComponents(links) {
    const parent = new Map();
    const find = node => {
        let root = node;
        while (parent.get(root) !== root) root = parent.get(root);
        let current = node;
        while (parent.get(current) !== current) {
            const next = parent.get(current);
            parent.set(current, root);
            current = next;
        }
        return root;
    };
    const addNode = node => {
        if (!parent.has(node)) parent.set(node, node);
    };
    for (const link of links) {
        if (link.source == null || link.target == null) continue;
        const source = String(link.source);
        const target = String(link.target);
        addNode(source);
        addNode(target);
        const sourceRoot = find(source);
        const targetRoot = find(target);
        if (sourceRoot !== targetRoot) parent.set(sourceRoot, targetRoot);
    }
    const modesByRoot = new Map();
    for (const link of links) {
        if (link.source == null || link.target == null) continue;
        const root = find(String(link.source));
        if (!modesByRoot.has(root)) modesByRoot.set(root, new Set());
        modesByRoot.get(root).add(link.mode || 'reverse');
    }
    const mixed = [];
    for (const modes of modesByRoot.values()) {
        if (modes.size > 1) mixed.push([...modes].sort());
    }
    return mixed;
}

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
                if (group.mode && link.mode !== group.mode) {
                    errors.push({
                        code: 'GROUP_MODE_MISMATCH',
                        groupId,
                        pathKey,
                        linkId: String(link.id),
                        groupMode: group.mode,
                        linkMode: link.mode,
                    });
                }
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

            const modes = [...new Set(pathLinks.map(link => link.mode))].sort();
            if (modes.length > 1) {
                errors.push({
                    code: 'MIXED_LINK_MODES',
                    groupId,
                    pathKey,
                    modes,
                });
            }
        }
    }

    for (const modes of findMixedModeComponents(links)) {
        errors.push({
            code: 'MIXED_TOPOLOGY_MODES',
            modes,
        });
    }

    return {
        valid: errors.length === 0,
        errors,
    };
}

module.exports = { validateTopology };
