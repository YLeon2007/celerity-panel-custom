'use strict';

const { createHash } = require('node:crypto');
const { verifyLegacyAppliedProfile } = require('../../../services/topologyConfigTransfer');
const { NODE_METADATA_SELECT, LINK_METADATA_SELECT } = require('./topologyOperationPlanMaterializer');
const EMPTY = new Set(['{}', '{}\n'].map(value => createHash('sha256').update(value).digest('hex')));
const read = query => query.read('primary').readConcern('majority').maxTimeMS(5000).lean();
const plain = value => JSON.parse(JSON.stringify(value));

function importError(node, profile, cause) {
    const code = 'CLASSIC_BASELINE_IMPORT_REFUSED';
    const error = Object.assign(new Error(
        `Нельзя принять classic-конфигурацию узла ${node} (${profile}): фактический профиль не совпадает с поддерживаемой конфигурацией classic. `
        + 'Проверьте связи и конфиг узла; изменения и захват исходного состояния не выполнены.'),
    { code, nodeId: node, profile, causeCode: cause?.code || 'CONFIG_LEGACY_IMPORT_INVALID' });
    return error;
}

// Called inside the already held physical-authority scope, BEFORE capture.
// Desired rows provide descriptors, never applied authority: every member's
// bytes come from its pinned SSH helper and pass the existing public checker.
// No ownership/admission/index/operation writes occur in this reader.
async function readClassicAppliedTopologies({ nodes: pins, readProfile,
    HyNode = require('../../../models/hyNodeModel'),
    CascadeLink = require('../../../models/cascadeLinkModel'),
    CascadeRouteGroup = require('../models/cascadeRouteGroupModel'),
} = {}) {
    if (pins.every(pin => EMPTY.has(pin.originalSnapshot.configSha256))) return undefined;
    const ids = pins.map(pin => pin.nodeId);
    const rows = await read(HyNode.find({ _id: { $in: ids } }).select(NODE_METADATA_SELECT));
    const linkRows = await read(CascadeLink.find({ active: true, $or: [
        { portalNode: { $in: ids } }, { bridgeNode: { $in: ids } },
    ] }).select(`${LINK_METADATA_SELECT} tunnelUuid active name priority status`));
    const links = linkRows.map(row => {
        const { _id, portalNode, bridgeNode, ...fields } = plain(row);
        delete fields.__v; delete fields.createdAt; delete fields.updatedAt;
        return { ...fields, id: String(_id), source: String(portalNode), target: String(bridgeNode) };
    });
    const groupRows = await read(CascadeRouteGroup.find({ 'paths.linkIds': { $in: links.map(link => link.id) } }));
    const groups = require('../domain/topologyDraft').projectGroups(plain(groupRows));
    const nodes = [];
    for (const pin of pins) {
        try {
            const row = rows.find(row => String(row._id) === pin.nodeId);
            if (!row || row.type !== 'xray' || row.active !== true) throw new Error();
            const { _id, cascadeRole, ...fields } = plain(row);
            delete fields.__v; delete fields.createdAt; delete fields.updatedAt;
            const profileConfig = await readProfile(pin.nodeId);
            if (typeof profileConfig !== 'string' || Buffer.byteLength(profileConfig) > 1024 * 1024
                || createHash('sha256').update(profileConfig).digest('hex') !== pin.originalSnapshot.configSha256) {
                throw Object.assign(new Error(), { code: 'CONFIG_LEGACY_IMPORT_READBACK_MISMATCH' });
            }
            nodes.push({ ...fields, id: String(_id), role: cascadeRole, profileConfig });
        } catch (cause) { throw importError(pin.nodeId, pin.targetProfile, cause); }
    }
    const byNode = {};
    for (const pin of pins) {
        if (EMPTY.has(pin.originalSnapshot.configSha256)) continue;
        const members = new Set([pin.nodeId]);
        let changed;
        do {
            changed = false;
            for (const link of links) if (members.has(link.source) || members.has(link.target)) {
                for (const id of [link.source, link.target]) if (!members.has(id)) { members.add(id); changed = true; }
            }
        } while (changed);
        const component = { nodes: nodes.filter(node => members.has(node.id)),
            links: links.filter(link => members.has(link.source) || members.has(link.target)),
            groups: groups.filter(group => group.paths.some(path => path.linkIds.some(id =>
                links.some(link => link.id === id && (members.has(link.source) || members.has(link.target)))))) };
        try {
            if ([...members].some(id => !ids.includes(id))) throw new Error();
            // Check all peers now, not just the local matching half. Public adopt
            // will independently bind the same bytes again after genuine capture.
            let verified;
            for (const peer of pins.filter(peer => members.has(peer.nodeId))) {
                try {
                    verified = verifyLegacyAppliedProfile(component, { node: peer.nodeId, profile: peer.targetProfile,
                        originalSnapshot: peer.originalSnapshot });
                } catch (cause) { throw importError(peer.nodeId, peer.targetProfile, cause); }
            }
            byNode[pin.nodeId] = verified;
        } catch (cause) {
            if (cause.code === 'CLASSIC_BASELINE_IMPORT_REFUSED') throw cause;
            throw importError(pin.nodeId, pin.targetProfile, cause);
        }
    }
    return byNode;
}

module.exports = { readClassicAppliedTopologies };
