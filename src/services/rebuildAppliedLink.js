'use strict';

const { read } = require('./rebuildRelayBackendStore');
const unproved = () => Object.assign(new Error('REBUILD_L2TP_APPLIED_LINK_UNPROVED'), {
    code: 'REBUILD_L2TP_APPLIED_LINK_UNPROVED',
});
const confirmedStatus = new Set(['deployed', 'online', 'offline']);
const validId = id => typeof id === 'string' && /^[a-f0-9]{24}$/.test(id);

// Same normalized mode/protocol and listener side as the rebuild compiler.
// This is not an alternate source of desired configuration.
function appliedLink(link) {
    const mode = link.mode === undefined ? 'reverse' : link.mode;
    return {
        mode,
        protocol: mode === 'reverse' ? 'vless' : (link.tunnelProtocol ?? 'vless'),
        port: link.tunnelPort,
        uuid: link.tunnelUuid,
        listener: mode === 'reverse' ? link.portalNode : link.bridgeNode,
    };
}

// Caller holds the same global Apply lock plus this relay's node lock. DIRECT
// must still match the resulting claim against MAIN and the owned live socket.
async function readAppliedTransit(Link, nodeId) {
    const rows = await read(Link.find({ $or: [
        { portalNode: nodeId }, { bridgeNode: nodeId }, { 'rebuildApplied.listener': nodeId },
    ] }).select('portalNode bridgeNode rebuildDelete lifecycle status rebuildApplied'));
    const transit = [];
    for (const row of rows) {
        const receipt = row.rebuildApplied;
        if (receipt === null) continue; // explicitly marked by the new-draft route
        if (receipt === undefined) {
            if (!confirmedStatus.has(row.status) || row.rebuildDelete || row.lifecycle) throw unproved();
            // Legacy applied status is not a receipt. Treat any unrecognized
            // MAIN inbound as before; never exempt it from HandlerService.
            continue;
        }
        if (typeof receipt !== 'object' || Object.keys(receipt).length !== 5) throw unproved();
        const { mode, protocol, port, uuid } = receipt;
        const listener = String(receipt.listener);
        const linkId = String(row._id);
        if (!validId(linkId) || !validId(listener) || !['forward', 'reverse'].includes(mode) ||
            !['vless', 'vmess'].includes(protocol) || (mode === 'reverse' && protocol !== 'vless') ||
            listener !== String(mode === 'reverse' ? row.portalNode : row.bridgeNode) ||
            !Number.isInteger(port) || port < 1 || port > 65535 || typeof uuid !== 'string' || !/^\S+$/.test(uuid)) {
            throw unproved();
        }
        if (listener === nodeId && protocol === 'vless') transit.push({ linkId, mode, port, uuid });
    }
    return transit.sort((a, b) => a.linkId.localeCompare(b.linkId));
}

module.exports = { appliedLink, readAppliedTransit };
