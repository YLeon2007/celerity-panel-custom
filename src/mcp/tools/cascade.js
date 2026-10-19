/**
 * MCP Tools — Cascade link management and topology
 * Tools: query (cascade), manage_cascade, get_topology
 */

const { z } = require('zod');
const mongoose = require('mongoose');
const CascadeLink = require('../../models/cascadeLinkModel');
const HyNode = require('../../models/hyNodeModel');
const CascadeTopologyState = require('../../modules/relay-l2tp/models/cascadeTopologyStateModel');
const cascadeService = require('../../services/cascadeService');
const cache = require('../../services/cacheService');
const logger = require('../../utils/logger');

async function invalidateCascadeCache() {
    await cache.invalidateAllSubscriptions();
}

// ─── Schemas ────────────────────────────────────────────────────────────────

const queryCascadeSchema = z.object({
    id: z.string().optional().describe('Cascade link MongoDB _id'),
    filter: z.object({
        nodeId: z.string().optional().describe('Filter by portal or bridge node ID'),
        status: z.string().optional(),
        active: z.boolean().optional(),
    }).optional(),
});

const manageCascadeSchema = z.object({
    expectedTopologyRevision: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional()
        .describe('Required for create/update/delete; exact revision from the topology draft'),
    action: z.enum(['create', 'update', 'delete', 'deploy', 'undeploy', 'reconnect']),
    id: z.string().optional().describe('Link _id (required for all except create)'),
    data: z.object({
        name: z.string().optional(),
        portalNodeId: z.string().optional(),
        bridgeNodeId: z.string().optional(),
        tunnelPort: z.number().int().min(1).max(65535).optional(),
        tunnelProtocol: z.enum(['vless', 'vmess']).optional(),
        tunnelSecurity: z.enum(['none', 'tls', 'reality']).optional(),
        tunnelTransport: z.enum(['tcp', 'ws', 'grpc', 'splithttp']).optional(),
        mode: z.enum(['reverse', 'forward']).optional(),
        priority: z.number().int().optional(),
    }).optional(),
});

const getTopologySchema = z.object({});

// ─── Handlers ────────────────────────────────────────────────────────────────

async function queryCascade(args) {
    const parsed = queryCascadeSchema.parse(args);

    if (parsed.id) {
        const link = await CascadeLink.findById(parsed.id)
            .populate('portalNode', 'name ip status')
            .populate('bridgeNode', 'name ip status');
        if (!link) return { error: `Cascade link '${parsed.id}' not found`, code: 404 };
        return { link };
    }

    const filter = {};
    if (parsed.filter?.active !== undefined) filter.active = parsed.filter.active;
    if (parsed.filter?.status) filter.status = parsed.filter.status;
    if (parsed.filter?.nodeId) {
        filter.$or = [{ portalNode: parsed.filter.nodeId }, { bridgeNode: parsed.filter.nodeId }];
    }

    const links = await CascadeLink.find(filter)
        .populate('portalNode', 'name ip status')
        .populate('bridgeNode', 'name ip status')
        .sort({ createdAt: -1 });

    return { links };
}

let draftWriteService;
function getDraftWriteService() {
    if (!draftWriteService) {
        draftWriteService = require('../../modules/relay-l2tp/services/topologyDraftWriteService')
            .createTopologyDraftWriteService({
                HyNode, CascadeLink,
                CascadeRouteGroup: require('../../modules/relay-l2tp/models/cascadeRouteGroupModel'),
                CascadeTopologyState,
                RelayL2tpState: require('../../modules/relay-l2tp/models/relayL2tpStateModel'),
            });
    }
    return draftWriteService;
}

async function manageCascade(args, emit) {
    const parsed = manageCascadeSchema.parse(args);
    const { action, id, data = {}, expectedTopologyRevision } = parsed;
    if (['create', 'update', 'delete'].includes(action)
        && !Number.isSafeInteger(expectedTopologyRevision)) {
        throw Object.assign(new Error('An explicit expectedTopologyRevision is required for draft writes'), {
            code: 'INVALID_TOPOLOGY_REVISION',
        });
    }

    switch (action) {
        case 'create': {
            if (!data.name || !data.portalNodeId || !data.bridgeNodeId) {
                throw new Error('name, portalNodeId, and bridgeNodeId are required for create');
            }

            const [portalNode, bridgeNode] = await Promise.all([
                HyNode.findById(data.portalNodeId),
                HyNode.findById(data.bridgeNodeId),
            ]);
            if (!portalNode) return { error: 'Portal node not found', code: 404 };
            if (!bridgeNode) return { error: 'Bridge node not found', code: 404 };
            if (data.portalNodeId === data.bridgeNodeId) {
                return { error: 'Portal and Bridge must be different nodes', code: 400 };
            }

            const port = data.tunnelPort || 10086;
            const linkMode = data.mode || 'reverse';
            const sec = data.tunnelSecurity || 'none';
            const trans = data.tunnelTransport || 'tcp';

            if (sec === 'reality' && trans === 'ws') {
                return { error: 'REALITY is not compatible with WebSocket transport', code: 400 };
            }

            const portCheckField = linkMode === 'forward' ? 'bridgeNode' : 'portalNode';
            const portCheckId = linkMode === 'forward' ? data.bridgeNodeId : data.portalNodeId;
            const conflict = await CascadeLink.findOne({ [portCheckField]: portCheckId, tunnelPort: port, active: true });
            if (conflict) {
                return { error: `Port ${port} is already used by link "${conflict.name}"`, code: 409 };
            }

            const crypto = require('crypto');
            const link = {
                _id: new mongoose.Types.ObjectId(),
                name: data.name,
                mode: linkMode,
                portalNode: data.portalNodeId,
                bridgeNode: data.bridgeNodeId,
                tunnelUuid: crypto.randomUUID(),
                tunnelPort: port,
                tunnelDomain: 'reverse.tunnel.internal',
                tunnelProtocol: data.tunnelProtocol || 'vless',
                tunnelSecurity: sec,
                tunnelTransport: trans,
                priority: data.priority || 100,
                tcpFastOpen: true,
                tcpKeepAlive: 100,
                tcpNoDelay: true,
                wsPath: '/cascade',
                grpcServiceName: 'cascade',
                xhttpPath: '/cascade',
                xhttpMode: 'auto',
                muxEnabled: false,
                muxConcurrency: 8,
            };
            const revisions = await getDraftWriteService().createLink({ expectedTopologyRevision, link });

            await invalidateCascadeCache();
            logger.info(`[MCP] Created cascade link ${data.name}: ${portalNode.name} -> ${bridgeNode.name}`);

            const populated = await CascadeLink.findById(link._id)
                .populate('portalNode', 'name ip status')
                .populate('bridgeNode', 'name ip status');

            return { success: true, link: populated, topologyRevision: revisions.revision, deployedRevision: revisions.deployedRevision };
        }

        case 'update': {
            if (!id) throw new Error('id is required for update');
            const allowed = ['name', 'tunnelPort', 'tunnelProtocol', 'tunnelSecurity', 'tunnelTransport', 'mode', 'priority'];
            const updates = {};
            for (const k of allowed) {
                if (data[k] !== undefined) updates[k] = data[k];
            }
            const revisions = await getDraftWriteService().updateLink({
                expectedTopologyRevision, linkId: id, changes: updates,
            });
            const link = await CascadeLink.findById(id)
                .populate('portalNode', 'name ip status')
                .populate('bridgeNode', 'name ip status');
            await invalidateCascadeCache();
            return { success: true, link, topologyRevision: revisions.revision, deployedRevision: revisions.deployedRevision };
        }

        case 'delete': {
            if (!id) throw new Error('id is required for delete');
            const link = await CascadeLink.findById(id);
            if (!link) return { error: `Cascade link '${id}' not found`, code: 404 };
            const revisions = await getDraftWriteService().deleteLink({ expectedTopologyRevision, linkId: id });
            await invalidateCascadeCache();
            logger.info(`[MCP] Deleted cascade link ${link.name}`);
            return { success: true, message: `Link '${link.name}' deleted`,
                topologyRevision: revisions.revision, deployedRevision: revisions.deployedRevision };
        }

        case 'deploy': {
            return {
                success: false,
                code: 'REVISION_SAFE_TOPOLOGY_DEPLOY_REQUIRED',
                error: 'Use POST /api/cascade/topology/deploy with expectedTopologyRevision',
            };
        }

        case 'undeploy': {
            if (!id) throw new Error('id is required for undeploy');
            if (!await CascadeLink.findById(id)) return { error: `Cascade link '${id}' not found`, code: 404 };
            const link = await require('../../modules/relay-l2tp/services/legacyCascadeUndeploy')
                .withLegacyCascadeUndeploy(async () => {
                    const current = await CascadeLink.findById(id)
                        .populate('portalNode').populate('bridgeNode');
                    if (!current) throw new Error('Cascade link disappeared before undeploy');
                    emit('progress', { message: `Undeploying cascade link '${current.name}'...` });
                    await cascadeService.undeployLink(current);
                    return current;
                });
            await invalidateCascadeCache();
            return { success: true, message: `Link '${link.name}' undeployed` };
        }

        case 'reconnect': {
            return {
                success: false,
                code: 'REVISION_SAFE_TOPOLOGY_DEPLOY_REQUIRED',
                error: 'Reconnect the topology draft, then deploy its exact revision',
            };
        }

        default:
            throw new Error(`Unknown action: ${action}`);
    }
}

async function getTopology() {
    const [state, nodes, links] = await Promise.all([
        CascadeTopologyState.findById('singleton').select('revision deployedRevision').lean(),
        HyNode.find({ active: true }).select('name ip status cascadeRole country type').lean(),
        CascadeLink.find({})
            .populate('portalNode', 'name ip status')
            .populate('bridgeNode', 'name ip status')
            .lean(),
    ]);

    return {
        topologyRevision: state?.revision ?? 0,
        deployedRevision: state?.deployedRevision ?? 0,
        nodes,
        links: links.map(l => ({
            _id: l._id,
            name: l.name,
            status: l.status,
            mode: l.mode,
            tunnelPort: l.tunnelPort,
            portal: l.portalNode ? { _id: l.portalNode._id, name: l.portalNode.name } : null,
            bridge: l.bridgeNode ? { _id: l.bridgeNode._id, name: l.bridgeNode.name } : null,
        })),
    };
}

module.exports = {
    queryCascade,
    manageCascade,
    getTopology,
    schemas: {
        queryCascade: queryCascadeSchema,
        manageCascade: manageCascadeSchema,
        getTopology: getTopologySchema,
    },
};
