'use strict';

const ROUTE_GROUP_MODE = 'route-group';
const FOLLOW_RELAY_MODE = 'follow-relay';
const FOLLOW_RELAY_VERSION = 1;

function selectL2tpRoutingMode(state) {
    const { routingMode = ROUTE_GROUP_MODE, routingVersion } = state ?? {};
    if (routingMode === ROUTE_GROUP_MODE && routingVersion === undefined) return routingMode;
    if (routingMode === FOLLOW_RELAY_MODE && routingVersion === FOLLOW_RELAY_VERSION) return routingMode;
    throw Object.assign(new Error('Unsupported L2TP routing selection'), { code: 'L2TP_ROUTING_SELECTION_INVALID' });
}

// Only the rebuild caller partitions dependencies. The original rows (and
// their retained group references) remain available for PPP checks/rollback.
function partitionRebuildL2tpStates(states) {
    const legacyStates = [], followRelayStates = [];
    for (const state of states) {
        (selectL2tpRoutingMode(state) === FOLLOW_RELAY_MODE ? followRelayStates : legacyStates).push(state);
    }
    return { legacyStates, followRelayStates };
}

module.exports = { ROUTE_GROUP_MODE, FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION, selectL2tpRoutingMode, partitionRebuildL2tpStates };
