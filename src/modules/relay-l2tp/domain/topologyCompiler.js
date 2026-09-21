'use strict';

const { validateTopology } = require('./topologyValidator');
const { selectActivePath } = require('./routePolicy');

function compileTopology({ nodes = [], links = [], groups = [], healthByPathKey = {} } = {}) {
    const orderedLinks = [...links]
        .sort((left, right) => String(left.id).localeCompare(String(right.id)));
    const validation = validateTopology({ nodes, links: orderedLinks, groups });
    const nodesById = new Map(nodes.map(node => [node.id, node]));
    const groupsById = new Map(groups.map(group => [group.id, group]));
    const relaysByNodeId = new Map();

    for (const group of groups) {
        const nodeIds = group.nodeIds || [];

        for (let index = 0; index < nodeIds.length - 1; index += 1) {
            const nodeId = nodeIds[index];
            if (nodesById.get(nodeId)?.role !== 'relay') continue;

            const suffixLinks = [];
            for (let pairIndex = index; pairIndex < nodeIds.length - 1; pairIndex += 1) {
                const link = orderedLinks.find(candidate =>
                    candidate.source === nodeIds[pairIndex]
                    && candidate.target === nodeIds[pairIndex + 1]
                );
                if (link) suffixLinks.push({ ...link });
            }
            const candidate = {
                pathKey: group.id,
                priority: group.priority,
                nextHopNodeId: nodeIds[index + 1],
                suffixLinks,
            };
            const relay = relaysByNodeId.get(nodeId) || { nodeId, candidates: [] };
            relay.candidates.push(candidate);
            relaysByNodeId.set(nodeId, relay);
        }
    }

    const relays = [...relaysByNodeId.values()]
        .sort((left, right) => left.nodeId.localeCompare(right.nodeId));
    for (const relay of relays) {
        relay.candidates.sort((left, right) => left.pathKey.localeCompare(right.pathKey));

        const selection = selectActivePath(
            relay.candidates.map(candidate => ({
                key: candidate.pathKey,
                priority: candidate.priority,
                enabled: groupsById.get(candidate.pathKey)?.enabled === true,
                complete: !validation.errors.some(error => error.groupId === candidate.pathKey),
            })),
            healthByPathKey,
        );
        if (selection.decision === 'select') {
            const selectedCandidate = relay.candidates.find(
                candidate => candidate.pathKey === selection.pathKey
            );
            relay.decision = {
                ...selection,
                nextHopNodeId: selectedCandidate.nextHopNodeId,
            };
        } else {
            relay.decision = selection;
        }
    }

    return {
        valid: validation.valid,
        errors: validation.errors,
        relays,
    };
}

module.exports = { compileTopology };
