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
const {
    isClassicProductionDeploymentConfigured,
    createClassicScopedCascadeDeploymentService,
} = require('../../services/classicScopedCascadeDeploymentService');
const { issueClassicLifecycleGrant } = require('../../services/classicLifecycleAuthorization');
const { isRebuildEnabled, rebuildStrictDisabled } = require('../../services/rebuildMode');
const { projectReverseHealth, observationSelect } = require('../../services/rebuildReverseLinkHealth');

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
    requestKey: z.string().min(1).max(128).optional()
        .describe('Stable caller idempotency key required for native delete acceptance; poll the returned job'),
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
    const rebuild = isRebuildEnabled();
    if (parsed.id) {
        const query = CascadeLink.findById(parsed.id);
        if (rebuild) query.select(observationSelect).lean();
        const link = await query
            .populate('portalNode', 'name ip status')
            .populate('bridgeNode', 'name ip status');
        if (!link) return { error: `Cascade link '${parsed.id}' not found`, code: 404 };
        return { link: rebuild ? projectReverseHealth(link) : link };
    }

    const filter = {};
    if (parsed.filter?.active !== undefined) filter.active = parsed.filter.active;
    if (!rebuild && parsed.filter?.status) filter.status = parsed.filter.status;
    if (parsed.filter?.nodeId) {
        filter.$or = [{ portalNode: parsed.filter.nodeId }, { bridgeNode: parsed.filter.nodeId }];
    }

    const query = CascadeLink.find(filter);
    if (rebuild) query.select(observationSelect).lean();
    const links = await query
        .populate('portalNode', 'name ip status')
        .populate('bridgeNode', 'name ip status')
        .sort({ createdAt: -1 });

    return { links: rebuild ? links.map(link => projectReverseHealth(link))
        .filter(link => !parsed.filter?.status || parsed.filter.status === link.status) : links };
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

let classicTopologyCoordinator;
function getClassicTopologyCoordinator() {
    if (!classicTopologyCoordinator) {
        classicTopologyCoordinator = createClassicScopedCascadeDeploymentService({
            env: process.env,
            HyNode, CascadeLink, CascadeTopologyState,
            CascadeRouteGroup: require('../../modules/relay-l2tp/models/cascadeRouteGroupModel'),
            RelayL2tpState: require('../../modules/relay-l2tp/models/relayL2tpStateModel'),
            TopologyOperation: require('../../modules/relay-l2tp/models/topologyOperationModel'),
            NodeOperationLock: require('../../modules/relay-l2tp/models/nodeOperationLockModel'),
        });
    }
    return classicTopologyCoordinator;
}

async function manageCascade(args, emit) {
    if (isRebuildEnabled()) throw rebuildStrictDisabled();
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
            if (linkMode === 'reverse' && isClassicProductionDeploymentConfigured(process.env)) {
                const grant = issueClassicLifecycleGrant(link, process.env);
                if (grant !== undefined) link.classicLifecycleGrant = grant;
            }
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
            const selectedService = require('../../modules/l2tpActiveHostProvider').l2tpActiveHostProvider.getActiveHost()?.selectedTopologyIntentService;
            const nativeConfigured = process.env.TOPOLOGY_TEST_EXECUTION_ENABLED === 'true'
                || process.env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'true';
            if (!isClassicProductionDeploymentConfigured(process.env) && (nativeConfigured || typeof selectedService?.accept === 'function')) {
                // The same supervised selected intent path as HTTP. A raw draft
                // delete cannot prove an applied tunnel absent or own cleanup.
                const service = selectedService;
                if (typeof service?.accept !== 'function') throw Object.assign(new Error('Selected intent runtime is unavailable'),
                    { code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE' });
                if (!parsed.requestKey) throw Object.assign(new Error('Native delete requires a caller requestKey'),
                    { code: 'TOPOLOGY_INTENT_KEY_REQUIRED' });
                const job = await service.accept({ version: 2, kind: 'link.delete', expectedTopologyRevision,
                    requestKey: parsed.requestKey, linkId: id,
                    desiredVersion: require('../../modules/relay-l2tp/services/topologyIntentService').linkDesiredVersion(link) });
                await invalidateCascadeCache();
                return { success: true, accepted: true,
                    ...require('../../routes/cascadeLinks').acceptedIntentResponse(job) };
            }
            const deletionService = isClassicProductionDeploymentConfigured(process.env)
                ? getClassicTopologyCoordinator() : getDraftWriteService();
            if (typeof deletionService?.deleteLink !== 'function') {
                throw Object.assign(new Error('Checked cascade deletion is unavailable'), {
                    code: 'TOPOLOGY_DEPLOYMENT_UNAVAILABLE',
                });
            }
            const revisions = await deletionService.deleteLink({ expectedTopologyRevision, linkId: id });
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
            if (isClassicProductionDeploymentConfigured(process.env)) {
                return {
                    success: false,
                    code: 'REVISION_SAFE_TOPOLOGY_DEPLOY_REQUIRED',
                    error: 'Use delete with expectedTopologyRevision for checked classic removal, or the HTTP revision-safe deploy path',
                };
            }
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
    const rebuild = isRebuildEnabled();
    const query = CascadeLink.find({});
    if (rebuild) query.select(observationSelect);
    const [state, nodes, links] = await Promise.all([
        CascadeTopologyState.findById('singleton').select('revision deployedRevision').lean(),
        HyNode.find({ active: true }).select('name ip status cascadeRole country type').lean(),
        query
            .populate('portalNode', 'name ip status')
            .populate('bridgeNode', 'name ip status')
            .lean(),
    ]);

    return {
        topologyRevision: state?.revision ?? 0,
        deployedRevision: state?.deployedRevision ?? 0,
        nodes,
        links: links.map(row => {
            const l = rebuild ? projectReverseHealth(row) : row;
            return {
                _id: l._id,
                name: l.name,
                status: l.status,
                ...(rebuild && l.observationExpiresAt ? { observationExpiresAt: l.observationExpiresAt } : {}),
                mode: l.mode,
                tunnelPort: l.tunnelPort,
                portal: l.portalNode ? { _id: l.portalNode._id, name: l.portalNode.name } : null,
                bridge: l.bridgeNode ? { _id: l.bridgeNode._id, name: l.bridgeNode.name } : null,
            };
        }),
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
