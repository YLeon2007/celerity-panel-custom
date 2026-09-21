'use strict';

const { validateTopology } = require('./topologyValidator');
const { selectActivePath } = require('./routePolicy');

function compileTopology({ nodes = [], links = [], groups = [], healthByPathKey = {} } = {}) {
    const orderedLinks = [...links]
        .sort((left, right) => String(left.id).localeCompare(String(right.id)));
    const validation = validateTopology({ nodes, links: orderedLinks, groups });
    const nodesById = new Map(nodes.map(node => [String(node.id), node]));
    const linksById = new Map(orderedLinks.map(link => [String(link.id), link]));
    const relaysByNodeId = new Map();

    for (const group of groups) {
        const groupId = String(group._id ?? group.id);

        for (const path of group.paths || []) {
            const pathLinks = (path.linkIds || [])
                .map(linkId => linksById.get(String(linkId)))
                .filter(Boolean);

            for (let index = 0; index < pathLinks.length; index += 1) {
                const nodeId = pathLinks[index].source;
                if (nodesById.get(String(nodeId))?.role !== 'relay') continue;

                const candidate = {
                    groupId,
                    pathKey: path.pathKey,
                    priority: path.priority,
                    nextHopNodeId: pathLinks[index].target,
                    suffixLinks: pathLinks.slice(index).map(link => ({ ...link })),
                };
                const relay = relaysByNodeId.get(nodeId) || { nodeId, candidates: [] };
                relay.candidates.push(candidate);
                relaysByNodeId.set(nodeId, relay);
            }
        }
    }

    const relays = [...relaysByNodeId.values()]
        .sort((left, right) => left.nodeId.localeCompare(right.nodeId));
    for (const relay of relays) {
        relay.candidates.sort((left, right) =>
            left.groupId.localeCompare(right.groupId)
            || left.pathKey.localeCompare(right.pathKey)
        );

        const selection = selectActivePath(
            relay.candidates.map(candidate => ({
                key: candidate.pathKey,
                priority: candidate.priority,
                enabled: true,
                complete: !validation.errors.some(error =>
                    error.groupId === candidate.groupId && error.pathKey === candidate.pathKey
                ),
            })),
            healthByPathKey,
        );
        if (selection.decision === 'select') {
            const selectedCandidate = relay.candidates.find(
                candidate => candidate.pathKey === selection.pathKey
            );
            relay.decision = {
                ...selection,
                groupId: selectedCandidate.groupId,
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
