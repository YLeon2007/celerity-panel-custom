'use strict';

const net = require('node:net');
const { TopologyPublishedProfileSource } = require('./topologyPublishedProfileSource');
const { TopologyClientProfileProbe } = require('./topologyClientProfileProbe');

const fail = () => ({ passed: false });
const id = value => value == null ? '' : typeof value.toHexString === 'function'
    ? value.toHexString() : String(value._id ?? value);
const confirmed = link => link?.active === true && ['deployed', 'online'].includes(link.status);
const bounded = async (work, ms) => {
    let timer;
    try {
        return await Promise.race([Promise.resolve().then(work), new Promise((_, reject) => {
            timer = setTimeout(() => reject(Error('deadline')), ms);
        })]);
    } finally { clearTimeout(timer); }
};

class TopologyClientProofExecutor {
    constructor({ HyNode, CascadeLink, CascadeRouteGroup, RelayL2tpState, NodeSSH,
        profileSource = new TopologyPublishedProfileSource(),
        profileProbe = new TopologyClientProfileProbe(), timeoutMs = 30000 } = {}) {
        if (![HyNode, CascadeLink, CascadeRouteGroup, RelayL2tpState].every(model => typeof model?.find === 'function')
            || typeof NodeSSH !== 'function' || typeof profileSource?.load !== 'function'
            || typeof profileProbe?.probe !== 'function' || !Number.isSafeInteger(timeoutMs)
            || timeoutMs < 1 || timeoutMs > 60000) throw new TypeError('Invalid topology proof dependencies');
        Object.assign(this, { HyNode, CascadeLink, CascadeRouteGroup, RelayL2tpState,
            NodeSSH, profileSource, profileProbe, timeoutMs });
    }

    async probeOperation(op) {
        try {
            if (op?.status !== 'succeeded' || op.staged === true
                || !Array.isArray(op.nodes) || op.nodes.length === 0
                || !Array.isArray(op.linkIds) || op.linkIds.length === 0
                || new Set(op.linkIds.map(id)).size !== op.linkIds.length
                || op.nodes.some(n => n.state !== 'committed' || !['portal', 'relay', 'bridge'].includes(n.role))) return fail();
            const roles = new Map(op.nodes.map(n => [id(n.node), n.role]));
            if (roles.size !== op.nodes.length || roles.has('')) return fail();
            const portalIds = [...roles].filter(([, role]) => role === 'portal').map(([nodeId]) => nodeId);
            if (!portalIds.length) return fail();
            const [nodeRows, linkRows, states, groups] = await bounded(() => Promise.all([
                this.HyNode.find({ _id: { $in: [...roles.keys()] } }).select('_id name flag domain ip port xray type active cascadeRole ssh').lean(),
                this.CascadeLink.find({ _id: { $in: op.linkIds } }).select('_id portalNode bridgeNode active status geoRouting.enabled').lean(),
                this.RelayL2tpState.find({ node: { $in: [...roles.keys()] }, desiredState: 'installed' }).select('node desiredState status routeGroup activePathKey').lean(),
                this.CascadeRouteGroup.find({}).select('_id paths.pathKey paths.enabled paths.linkIds').lean(),
            ]), this.timeoutMs);
            if (![nodeRows, linkRows, states, groups].every(Array.isArray)) return fail();
            const nodes = new Map(nodeRows.map(n => [id(n._id), n]));
            const links = new Map(linkRows.map(l => [id(l._id), l]));
            if (nodes.size !== roles.size || links.size !== op.linkIds.length || nodes.has('') || links.has('')) return fail();
            for (const [nodeId, role] of roles) {
                const node = nodes.get(nodeId);
                if (!node || node.active !== true || node.type !== 'xray' || node.cascadeRole !== role) return fail();
            }
            if ([...links.values()].some(link => !confirmed(link)
                || !roles.has(id(link.portalNode)) || !roles.has(id(link.bridgeNode)))) return fail();
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
                if (!mainSuffix || mainSuffix.length || !roles.has(current)) return fail();
                bridgeIds.add(current);
            }
            if (bridgeIds.size !== 1) return fail();
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
            const portalNodes = portalIds.map(nodeId => nodes.get(nodeId));
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
        RelayL2tpState: require('../models/relayL2tpStateModel'),
        NodeSSH: require('../../../services/nodeSSH'),
    });
    return defaultExecutor.probeOperation(op);
}
module.exports = { TopologyClientProofExecutor, probeOperation };
