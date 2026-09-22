'use strict';

const NODE_PANEL_SELECT = '_id name active status cascadeRole';
const STATE_PANEL_SELECT = [
    'node',
    'desiredState',
    'status',
    'clientCidr',
    'localAddress',
    'poolStart',
    'poolEnd',
    'dnsServers',
    'tproxyPort',
    'fwmark',
    'routeTable',
    'routeGroup',
    'appliedTopologyRevision',
    'activePathKey',
    'lastVerifiedAt',
].join(' ');
const TOPOLOGY_PANEL_SELECT = 'revision';
const ROUTE_GROUP_PANEL_SELECT = '_id name mode strategy paths.pathKey paths.priority';
const OPERATION_PANEL_SELECT = [
    '_id',
    'node',
    'kind',
    'status',
    'step',
    'progress',
    'errorCode',
    'topologyRevision',
    'routeGroupId',
    'createdAt',
    'updatedAt',
].join(' ');

function id(value) {
    return value === null || value === undefined ? null : String(value);
}

function createPanelOverviewLoader({
    HyNode,
    RelayL2tpState,
    CascadeTopologyState,
    CascadeRouteGroup,
    L2tpOperation,
}) {
    return async function loadPanelOverview() {
        const [nodes, states, topology, groups, operations] = await Promise.all([
            HyNode.find({ cascadeRole: 'relay' })
                .select(NODE_PANEL_SELECT)
                .lean(),
            RelayL2tpState.find({})
                .select(STATE_PANEL_SELECT)
                .lean(),
            CascadeTopologyState.findById('singleton')
                .select(TOPOLOGY_PANEL_SELECT)
                .lean(),
            CascadeRouteGroup.find({})
                .select(ROUTE_GROUP_PANEL_SELECT)
                .lean(),
            L2tpOperation.find({})
                .select(OPERATION_PANEL_SELECT)
                .sort({ createdAt: -1 })
                .limit(25)
                .lean(),
        ]);

        const statesByNodeId = new Map(
            (states || []).map(state => [id(state.node), state]),
        );

        return {
            topologyRevision: topology?.revision ?? 0,
            relays: (nodes || []).map(node => {
                const state = statesByNodeId.get(id(node._id)) || {};
                return {
                    id: id(node._id),
                    name: node.name,
                    active: Boolean(node.active),
                    nodeStatus: node.status,
                    l2tpStatus: state.status || 'not_installed',
                    desiredState: state.desiredState || 'absent',
                    clientCidr: state.clientCidr || '',
                    localAddress: state.localAddress || '',
                    poolStart: state.poolStart || '',
                    poolEnd: state.poolEnd || '',
                    dnsServers: Array.isArray(state.dnsServers) ? [...state.dnsServers] : [],
                    tproxyPort: state.tproxyPort ?? null,
                    fwmark: state.fwmark ?? null,
                    routeTable: state.routeTable ?? null,
                    routeGroupId: id(state.routeGroup),
                    appliedTopologyRevision: state.appliedTopologyRevision ?? null,
                    activePathKey: state.activePathKey || '',
                    lastVerifiedAt: state.lastVerifiedAt ?? null,
                };
            }),
            routeGroups: (groups || []).map(group => ({
                id: id(group._id),
                name: group.name,
                mode: group.mode,
                strategy: group.strategy,
                paths: (group.paths || []).map(path => ({
                    pathKey: path.pathKey,
                    priority: path.priority,
                })),
            })),
            operations: (operations || []).map(operation => ({
                id: id(operation._id),
                nodeId: id(operation.node),
                kind: operation.kind,
                status: operation.status,
                step: operation.step,
                progress: operation.progress,
                errorCode: operation.errorCode,
                topologyRevision: operation.topologyRevision,
                routeGroupId: id(operation.routeGroupId),
                createdAt: operation.createdAt,
                updatedAt: operation.updatedAt,
            })),
        };
    };
}

module.exports = {
    createPanelOverviewLoader,
    NODE_PANEL_SELECT,
    OPERATION_PANEL_SELECT,
    ROUTE_GROUP_PANEL_SELECT,
    STATE_PANEL_SELECT,
    TOPOLOGY_PANEL_SELECT,
};
