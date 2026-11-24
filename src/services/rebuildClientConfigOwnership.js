'use strict';

const { isDeepStrictEqual } = require('node:util');
const vless = require('../utils/vlessEncryption');

const PROTECTED = 'REBUILD_VLESS_CLIENT_PROTECTED';
const UNAVAILABLE = 'REBUILD_VLESS_CLIENT_OWNERSHIP_UNAVAILABLE';
const fail = code => Object.assign(new Error(code), { code });
const topologyRole = role => !!role && role !== 'standalone';

// Use the same freshly loaded card and active incident-edge rule as config
// Sync, not the submitted role or a view/cache of the topology.
async function rebuildManagesClientConfig(node) {
    return topologyRole(node.cascadeRole) || !!await require('../models/cascadeLinkModel').exists({
        $or: [{ portalNode: node._id }, { bridgeNode: node._id }], active: true,
    });
}

function enabledEncryption(xray) {
    const settings = inbound => vless.FIELDS.map(key => key === 'vlessEncryptionTicket'
        ? vless.normalizeTicket(inbound[key]) : inbound[key]);
    return {
        main: xray?.vlessEncryption === true ? settings(xray) : null,
        extras: (Array.isArray(xray?.extraInbounds) ? xray.extraInbounds : [])
            .filter(extra => extra?.vlessEncryption === true).map(extra => [extra.id, settings(extra)])
            .sort(([left], [right]) => String(left).localeCompare(String(right))),
    };
}

// Called only inside the existing node edit writer, against a settled
// candidate (keys are server-owned and have already been validated).
async function assertRebuildVlessEditAllowed(current, before, next, profile) {
    if (!current) return; // Rebuild off: no new read/write/dispatch.
    const wasEnabled = vless.hasEnabledInbound(before);
    if (!wasEnabled && !vless.hasEnabledInbound(next)) return;

    // Do not allow demoting an enabled portal to unlock a later rotation.
    // Promotion with unchanged credentials is allowed after standalone sync.
    const demotes = wasEnabled && topologyRole(current.cascadeRole) && !topologyRole(profile.cascadeRole);
    if (!demotes && isDeepStrictEqual(enabledEncryption(before), enabledEncryption(next))) return;

    // Also refuse an encryption change bundled with promotion: the queued
    // Sync would observe the new role and would not install that credential.
    if (topologyRole(profile.cascadeRole)) throw fail(PROTECTED);
    let managed;
    try { managed = await rebuildManagesClientConfig(current); }
    catch { throw fail(UNAVAILABLE); }
    if (managed) throw fail(PROTECTED);
}

module.exports = { rebuildManagesClientConfig, assertRebuildVlessEditAllowed, PROTECTED, UNAVAILABLE };