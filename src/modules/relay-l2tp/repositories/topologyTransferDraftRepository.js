'use strict';

const ACTIVE_NODE_ROLES = Object.freeze(['portal', 'relay', 'bridge']);
const CURRENT_NODE_FILTER = Object.freeze({
    type: 'xray',
    active: true,
    cascadeRole: Object.freeze({ $in: ACTIVE_NODE_ROLES }),
});
const CURRENT_NODE_SELECT = '_id name cascadeRole';
const CURRENT_LINK_SELECT = '_id name portalNode bridgeNode mode active';
const CURRENT_ROUTE_GROUP_SELECT = [
    '_id',
    'name',
    'mode',
    'strategy',
    'paths.pathKey',
    'paths.linkIds',
    'paths.priority',
    'paths.enabled',
].join(' ');
const CURRENT_RELAY_STATE_SELECT = [
    'node',
    'desiredState',
    'clientCidr',
    'localAddress',
    'poolStart',
    'poolEnd',
    'dnsServers',
    'mtu',
    'mru',
    'routingMode',
    'routeGroup',
].join(' ');
const DRAFT_FIELDS = Object.freeze([
    'draftId',
    'status',
    'source',
    'name',
    'document',
    'counts',
    'createdAt',
]);
const DRAFT_READ_SELECT = DRAFT_FIELDS.join(' ');
const DRAFT_SUMMARY_FIELDS = Object.freeze(DRAFT_FIELDS.filter(field => field !== 'document'));
const DRAFT_SUMMARY_SELECT = DRAFT_SUMMARY_FIELDS.join(' ');
const DRAFT_WRITE_FIELDS = Object.freeze([
    'draftId',
    'source',
    'name',
    'document',
    'counts',
]);

function pickDefined(source, fields = DRAFT_FIELDS) {
    return fields.reduce((result, field) => {
        if (source?.[field] !== undefined) result[field] = source[field];
        return result;
    }, {});
}

function plainObject(value) {
    return value && typeof value.toObject === 'function' ? value.toObject() : value;
}

class TopologyTransferDraftRepository {
    constructor({
        HyNode,
        CascadeLink,
        CascadeRouteGroup,
        RelayL2tpState,
        RelayL2tpTopologyTransferDraft,
    } = {}) {
        for (const [name, model] of Object.entries({
            HyNode,
            CascadeLink,
            CascadeRouteGroup,
            RelayL2tpState,
            RelayL2tpTopologyTransferDraft,
        })) {
            if (!model) throw new TypeError(`${name} model is required`);
        }
        this.HyNode = HyNode;
        this.CascadeLink = CascadeLink;
        this.CascadeRouteGroup = CascadeRouteGroup;
        this.RelayL2tpState = RelayL2tpState;
        this.RelayL2tpTopologyTransferDraft = RelayL2tpTopologyTransferDraft;
    }

    async createDraft(fields) {
        const draft = {
            ...pickDefined(fields, DRAFT_WRITE_FIELDS),
            status: 'DRAFT',
        };
        const created = await this.RelayL2tpTopologyTransferDraft.create(draft);
        return pickDefined(plainObject(created));
    }

    async listDrafts() {
        const drafts = await this.RelayL2tpTopologyTransferDraft.find({ status: 'DRAFT' })
            .select(DRAFT_SUMMARY_SELECT)
            .sort({ createdAt: -1, draftId: 1 })
            .lean();
        return (drafts || []).map(draft => pickDefined(draft, DRAFT_SUMMARY_FIELDS));
    }

    async findDraftById(draftId) {
        const draft = await this.RelayL2tpTopologyTransferDraft.findOne({
            draftId,
            status: 'DRAFT',
        })
            .select(DRAFT_READ_SELECT)
            .lean();
        return draft ? pickDefined(draft) : null;
    }

    async loadCurrentTopology() {
        const [nodes, links, routeGroups, relayStates] = await Promise.all([
            this.HyNode.find(CURRENT_NODE_FILTER)
                .select(CURRENT_NODE_SELECT)
                .sort({ _id: 1 })
                .lean(),
            this.CascadeLink.find({})
                .select(CURRENT_LINK_SELECT)
                .sort({ _id: 1 })
                .lean(),
            this.CascadeRouteGroup.find({})
                .select(CURRENT_ROUTE_GROUP_SELECT)
                .sort({ _id: 1 })
                .lean(),
            this.RelayL2tpState.find({})
                .select(CURRENT_RELAY_STATE_SELECT)
                .sort({ node: 1 })
                .lean(),
        ]);
        return {
            nodes: nodes || [],
            links: links || [],
            routeGroups: routeGroups || [],
            relayStates: relayStates || [],
        };
    }
}

module.exports = {
    ACTIVE_NODE_ROLES,
    CURRENT_LINK_SELECT,
    CURRENT_NODE_FILTER,
    CURRENT_NODE_SELECT,
    CURRENT_RELAY_STATE_SELECT,
    CURRENT_ROUTE_GROUP_SELECT,
    DRAFT_FIELDS,
    DRAFT_READ_SELECT,
    DRAFT_SUMMARY_SELECT,
    TopologyTransferDraftRepository,
    pickDefined,
};
