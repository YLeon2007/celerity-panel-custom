'use strict';

const net = require('node:net');
const { TopologyPublishedProfileSource } = require('./topologyPublishedProfileSource');
const { TopologyClientProfileProbe } = require('./topologyClientProfileProbe');

const fail = () => ({ passed: false });
const id = value => value == null ? '' : typeof value.toHexString === 'function'
    ? value.toHexString() : String(value._id ?? value);
const confirmed = link => link?.active === true && ['deployed', 'online'].includes(link.status);
const scopedKinds = new Set(['link.apply', 'domain.reconcile', 'link.replace', 'link.attach']);
// Full Sync has no scoped identity. Never reinterpret incomplete/unknown scoped
// metadata as permission to discover a different graph from the current DB.
const scopedFields = ['kind', 'linkId', 'linkIds', 'staged', 'oldLinkId', 'groupId',
    'pathKey', 'ownerNodeId', 'ownerTopologyRevision', 'ownerCredentialRevision',
    'oldPathLinkIds', 'newPathLinkIds'];
const bounded = async (work, ms) => {
    let timer;
    try {
        return await Promise.race([Promise.resolve().then(work), new Promise((_, reject) => {
            timer = setTimeout(() => reject(Error('deadline')), ms);
        })]);
    } finally { clearTimeout(timer); }
};

function completeFullGraph(roles, links, portalIds) {
    const outgoing = new Map([...roles.keys()].map(nodeId => [nodeId, []]));
    for (const link of links.values()) {
        if (roles.get(id(link.bridgeNode)) === 'portal') return false;
        outgoing.get(id(link.portalNode)).push(link);
    }
    const visiting = new Set();
    const visited = new Set();
    const visit = nodeId => {
        if (visiting.has(nodeId)) return false;
        if (visited.has(nodeId)) return true;
        const edges = outgoing.get(nodeId);
        if (roles.get(nodeId) === 'bridge' ? edges.length !== 0
            : edges.filter(link => link.geoRouting?.enabled !== true).length !== 1) return false;
        visiting.add(nodeId);
        if (!edges.every(link => visit(id(link.bridgeNode)))) return false;
        visiting.delete(nodeId);
        visited.add(nodeId);
        return true;
    };
    // Include geo branches in completeness, not in default-egress selection.
    return portalIds.every(visit) && visited.size === roles.size;
}

class TopologyClientProofExecutor {
    constructor({ HyNode, CascadeLink, CascadeRouteGroup, RelayL2tpState, CascadeTopologyState, NodeSSH,
        profileSource = new TopologyPublishedProfileSource(),
        profileProbe = new TopologyClientProfileProbe(), timeoutMs = 30000,
        selectedTopologyRepository, L2tpUser, pppReadinessGate } = {}) {
        if (![HyNode, CascadeLink, CascadeRouteGroup, RelayL2tpState].every(model => typeof model?.find === 'function')
            || typeof NodeSSH !== 'function' || typeof profileSource?.load !== 'function'
            || typeof profileProbe?.probe !== 'function' || !Number.isSafeInteger(timeoutMs)
            || timeoutMs < 1 || timeoutMs > 60000) throw new TypeError('Invalid topology proof dependencies');
        Object.assign(this, { HyNode, CascadeLink, CascadeRouteGroup, RelayL2tpState,
            NodeSSH, CascadeTopologyState, profileSource, profileProbe, timeoutMs,
            selectedTopologyRepository, L2tpUser, pppReadinessGate });
    }

    async readSelectedSnapshot(op) {
        try {
            const { readSettledSelectedOperation } = require('./topologySelectedProofState');
            const settled = await readSettledSelectedOperation(this.selectedTopologyRepository, op);
            if (!settled) return null;
            const nodeIds = settled.effectiveTopology.nodes.map(node => node.id);
            const { NODE_METADATA_SELECT } = require('./topologyOperationPlanMaterializer');
            const nodeRows = await this.HyNode.find({ _id: { $in: nodeIds } })
                .select(`${NODE_METADATA_SELECT} name flag xray.realityPublicKey ssh groups`).lean();
            if (nodeRows.length !== nodeIds.length || new Set(nodeRows.map(n => id(n._id))).size !== nodeIds.length) return null;
            const same = require('node:util').isDeepStrictEqual;
            const get = (row, path) => path.replace(/^\+/, '').split('.').reduce((value, key) => value?.[key], row);
            const configFields = NODE_METADATA_SELECT.split(' ').filter(key => !['_id', 'type', 'active', 'cascadeRole'].includes(key));
            for (const frozen of settled.effectiveTopology.nodes) {
                const current = nodeRows.find(node => id(node._id) === frozen.id);
                if (!current || current.cascadeRole !== frozen.role || current.active !== true || current.type !== frozen.type
                    || configFields.some(key => !same(get(current, key), get(frozen, key)))) return null;
            }
            const portalNodes = nodeRows.filter(n => n.cascadeRole === 'portal').map(n => ({ ...n, _id: id(n._id) }))
                .sort((a, b) => a._id.localeCompare(b._id));
            const identity = portalNodes.length ? await this.profileSource.readProofIdentity(portalNodes) : null;
            if (portalNodes.length && !identity) return null;
            const relayIds = nodeRows.filter(n => n.cascadeRole === 'relay').map(n => id(n._id));
            const states = relayIds.length ? await this.RelayL2tpState.find({ node: { $in: relayIds } })
                .select('node desiredState status secretRevision routeGroup activePathKey appliedTopologyRevision').lean() : [];
            const users = relayIds.length ? await this.L2tpUser.find({ relayNode: { $in: relayIds } })
                .select('relayNode login ip +passwordEncrypted enabled desiredRevision appliedRevision syncStatus syncOperationId').lean() : [];
            const canonical = value => value instanceof Date ? value.toISOString() : Array.isArray(value) ? value.map(canonical)
                : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
            const sortRows = rows => rows.map(row => JSON.parse(JSON.stringify(row))).sort((a, b) => JSON.stringify(canonical(a)).localeCompare(JSON.stringify(canonical(b))));
            const credentialDigest = require('node:crypto').createHash('sha256').update(JSON.stringify(canonical({
                identity, nodes: sortRows(nodeRows), states: sortRows(states), users: sortRows(users),
            }))).digest('hex');
            const pppApplicable = relayIds.some(nodeId => {
                const rows = states.filter(state => id(state.node) === nodeId);
                return !(rows.length === 1 && rows[0].status === 'not_installed'
                    && ['absent', 'not_installed'].includes(rows[0].desiredState)
                    && !users.some(user => id(user.relayNode) === nodeId));
            });
            // The existing client path authenticates only the configured user.
            // Pin all assignments, but do not turn that into runtime proof of
            // any other user's presence or traffic.
            const assignmentsCoveredByProbe = Boolean(identity && identity.assignments.every(assignment =>
                assignment.users.length === 1 && assignment.users[0].userId === identity.probeUserId));
            return { operation: settled, nodeRows, portalNodes, states, pppApplicable, assignmentsCoveredByProbe, credentialDigest };
        } catch { return null; }
    }

    async probeSelectedOperation(op) {
        const before = await bounded(() => this.readSelectedSnapshot(op), this.timeoutMs);
        if (!before || !['complete', 'no_portal_input'].includes(before.operation.routeState)) return fail();
        const settled = before.operation;
        // Staged means missing portal input, not permission to skip installed PPP.
        // Node users/readback is mandatory, but it is NOT a real PPP client test.
        if (before.nodeRows.some(node => node.cascadeRole === 'relay')) {
            const gate = await this.pppReadinessGate?.verifyPlan({ ...settled,
                ...(settled.installedPath ? { ...settled.installedPath,
                    ownerTopologyRevision: settled.topologyRevision } : {}) });
            if (gate?.ok !== true) return fail();
        }
        if (!before.portalNodes.length) return fail(); // PPP Internet stays unverified.
        const frozenLinks = settled.effectiveTopology.links.map(link => ({ ...link, _id: link.id,
            portalNode: link.source, bridgeNode: link.target, active: true, status: 'deployed' }));
        // Reuse the existing graph/default-exit and actual profile/client probe;
        // replace only mutable graph reads with the exact settled descriptors.
        const result = await this.probeGraphOperation({ ...settled, staged: false,
            kind: 'link.apply', nodes: settled.nodes.filter(node => settled.effectiveTopology.nodes.some(n => n.id === id(node.node))),
            linkIds: frozenLinks.map(link => link._id) }, [before.nodeRows, frozenLinks,
            before.states.filter(s => s.desiredState === 'installed'), settled.effectiveTopology.groups]);
        if (result?.passed !== true) return fail();
        const after = await bounded(() => this.readSelectedSnapshot(op), this.timeoutMs);
        return after && after.credentialDigest === before.credentialDigest
            ? { passed: true, admissionFingerprint: settled.admissionFingerprint, credentialDigest: before.credentialDigest } : fail();
    }

    async currentFullRevision(op) {
        if (!Number.isSafeInteger(op.topologyRevision) || op.topologyRevision < 0
            || typeof this.CascadeTopologyState?.findById !== 'function') return false;
        const state = await bounded(() => this.CascadeTopologyState.findById('singleton')
            .select('revision deployedRevision').lean(), this.timeoutMs);
        return state?.revision === op.topologyRevision && state.deployedRevision === op.topologyRevision;
    }

    async probeOperation(op) {
        try {
            return op?.admissionScope === 'selected' ? await this.probeSelectedOperation(op) : await this.probeGraphOperation(op);
        } catch { return fail(); }
    }

    async probeGraphOperation(op, pinnedSnapshot) {
        try {
            const full = !scopedFields.some(field => op?.[field] !== undefined);
            if (op?.status !== 'succeeded' || op.staged === true
                || full && (op.heldTopologyAdmission === true || op.pppWait != null)
                || op.kind !== undefined && !scopedKinds.has(op.kind)
                || !Array.isArray(op.nodes) || op.nodes.length === 0
                || !full && (!Array.isArray(op.linkIds) || op.linkIds.length === 0
                    || new Set(op.linkIds.map(id)).size !== op.linkIds.length)
                || op.nodes.some(n => n.state !== 'committed' || !['portal', 'relay', 'bridge'].includes(n.role))) return fail();
            if (full && !await this.currentFullRevision(op)) return fail();
            const roles = new Map(op.nodes.map(n => [id(n.node), n.role]));
            if (roles.size !== op.nodes.length || roles.has('')) return fail();
            const portalIds = [...roles].filter(([, role]) => role === 'portal').map(([nodeId]) => nodeId);
            if (!portalIds.length) return fail();
            const [nodeRows, linkRows, states, groups] = pinnedSnapshot ?? await bounded(() => Promise.all([
                this.HyNode.find(full ? { type: 'xray', active: true, cascadeRole: { $in: ['portal', 'relay', 'bridge'] } }
                    : { _id: { $in: [...roles.keys()] } }).select('_id name flag domain ip port xray type active cascadeRole ssh').lean(),
                this.CascadeLink.find(full ? { active: true } : { _id: { $in: op.linkIds } }).select('_id portalNode bridgeNode active status geoRouting.enabled').lean(),
                this.RelayL2tpState.find({ node: { $in: [...roles.keys()] }, desiredState: 'installed' }).select('node desiredState status routeGroup activePathKey').lean(),
                this.CascadeRouteGroup.find({}).select('_id paths.pathKey paths.enabled paths.linkIds').lean(),
            ]), this.timeoutMs);
            if (![nodeRows, linkRows, states, groups].every(Array.isArray)) return fail();
            const nodes = new Map(nodeRows.map(n => [id(n._id), n]));
            const links = new Map(linkRows.map(l => [id(l._id), l]));
            if (nodes.size !== roles.size || links.size === 0
                || links.size !== (full ? linkRows.length : op.linkIds.length)
                || nodes.has('') || links.has('') || full && nodeRows.length !== nodes.size) return fail();
            for (const [nodeId, role] of roles) {
                const node = nodes.get(nodeId);
                if (!node || node.active !== true || node.type !== 'xray' || node.cascadeRole !== role) return fail();
            }
            if ([...links.values()].some(link => !confirmed(link)
                || !roles.has(id(link.portalNode)) || !roles.has(id(link.bridgeNode)))) return fail();
            if (full && !completeFullGraph(roles, links, portalIds)) return fail();
            const owners = new Map();
            for (const state of states) {
                const nodeId = id(state.node);
                if (owners.has(nodeId) || state.desiredState !== 'installed' || state.status !== 'installed') return fail();
                owners.set(nodeId, state);
            }
            const groupById = new Map(groups.map(g => [id(g._id), g]));
            if (groupById.size !== groups.length) return fail();
            const bridgeIds = new Set();
            for (const portalId of portalIds) {
                let current = portalId;
                const visited = new Set();
                let mainSuffix = null;
                while (roles.get(current) !== 'bridge') {
                    if (visited.has(current)) return fail();
                    visited.add(current);
                    const owner = owners.get(current);
                    if (owner) {
                        // The installed owner's enabled main route is the only authority
                        // for a default exit; a geo branch is never an alternative.
                        if (mainSuffix) return fail();
                        const group = groupById.get(id(owner.routeGroup));
                        const mains = group?.paths?.filter(p => p.pathKey === 'main' && p.enabled === true);
                        if (owner.activePathKey !== 'main' || mains?.length !== 1
                            || !Array.isArray(mains[0].linkIds) || !mains[0].linkIds.length) return fail();
                        mainSuffix = mains[0].linkIds.map(id);
                        if (new Set(mainSuffix).size !== mainSuffix.length) return fail();
                    }
                    const choices = [...links.values()].filter(l => id(l.portalNode) === current && l.geoRouting?.enabled !== true);
                    if (choices.length !== 1) return fail();
                    const nextLink = choices[0];
                    if (mainSuffix && mainSuffix.shift() !== id(nextLink._id)) return fail();
                    current = id(nextLink.bridgeNode);
                }
                if (mainSuffix?.length || !roles.has(current)) return fail();
                bridgeIds.add(current);
            }
            if (bridgeIds.size !== 1 || full && !await this.currentFullRevision(op)) return fail();
            const bridge = nodes.get([...bridgeIds][0]);
            if (!bridge?.ip || typeof bridge.ssh?.username !== 'string'
                || !(bridge.ssh.privateKey || bridge.ssh.password)) return fail();
            const expectedEgressIp = await bounded(async () => {
                const ssh = new this.NodeSSH(bridge);
                try {
                    await ssh.connect();
                    const output = await ssh.exec('curl --disable --noproxy "*" --fail --silent --show-error --max-time 8 --max-filesize 64 https://api.ipify.org');
                    if (output?.code !== 0 || output.stderr !== '' || typeof output.stdout !== 'string'
                        || output.stdout.length > 64) return null;
                    const address = output.stdout.trim();
                    return net.isIP(address) === 4 ? address : null;
                } finally { ssh.disconnect(); }
            }, this.timeoutMs);
            if (!expectedEgressIp) return fail();
            // Graph lookup already proved each row's _id equals this operation ID.
            // The published source needs a canonical string, not lean()'s ObjectId.
            if (portalIds.some(nodeId => !/^[0-9a-f]{24}$/.test(nodeId))) return fail();
            const portalNodes = portalIds.map(nodeId => ({ ...nodes.get(nodeId), _id: nodeId }));
            const observed = new Set();
            const loaded = await bounded(() => this.profileSource.load({ portalNodes, consumeProfile: async (nodeId, profile) => {
                if (!portalIds.includes(nodeId) || observed.has(nodeId)) return { ok: false };
                const result = await bounded(() => this.profileProbe.probe({
                    profile, endpoint: 'https://api.ipify.org', expectedEgressIp,
                }), this.timeoutMs);
                if (result?.ok !== true || result.observedEgressIp !== expectedEgressIp) return { ok: false };
                observed.add(nodeId);
                return { ok: true };
            } }), this.timeoutMs * portalIds.length);
            if (full && !await this.currentFullRevision(op)) return fail();
            return loaded?.ok === true && loaded.verifiedCount === portalIds.length && observed.size === portalIds.length
                ? { passed: true } : fail();
        } catch {
            // No raw DB, SSH, subscription, or client exceptions cross this boundary.
            return fail();
        }
    }
}

let defaultExecutor;
function probeOperation(op) {
    if (!defaultExecutor) defaultExecutor = new TopologyClientProofExecutor({
        HyNode: require('../../../models/hyNodeModel'),
        CascadeLink: require('../../../models/cascadeLinkModel'),
        CascadeRouteGroup: require('../models/cascadeRouteGroupModel'),
        CascadeTopologyState: require('../models/cascadeTopologyStateModel'),
        RelayL2tpState: require('../models/relayL2tpStateModel'),
        NodeSSH: require('../../../services/nodeSSH'),
    });
    return defaultExecutor.probeOperation(op);
}
module.exports = { TopologyClientProofExecutor, probeOperation };
