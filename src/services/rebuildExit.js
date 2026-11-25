'use strict';

const { Types: { ObjectId } } = require('mongoose');
const { compileRebuildGraph, PORTAL_EXIT_AMBIGUOUS } = require('../modules/relay-l2tp/domain/rebuildTopologyCompiler');
const { normalizeRebuildExit, PORTAL_EXIT_INVALID } = require('../modules/relay-l2tp/domain/rebuildPortalExit');
const PORTAL_EXIT_UNSUPPORTED = 'REBUILD_PORTAL_EXIT_UNSUPPORTED';
const fail = code => Object.assign(new Error(code), { code });
const hex = /^[a-f0-9]{24}(?![\s\S])/i;
const id = value => typeof value === 'string' && hex.test(value) ? value.toLowerCase()
    : value instanceof ObjectId ? value.toHexString() : undefined;
const plain = value => value !== null && typeof value === 'object'
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
const plainName = value => typeof value === 'string'
    ? value.replace(/[\p{Cc}\p{Cf}<>]/gu, '').trim().slice(0, 120) : '';
const role = node => node?.role ?? node?.cascadeRole;

function inputExit(body) {
    if (!plain(body) || Object.keys(body).some(key => key.startsWith('$') || key.includes('.')
        || key.includes('[') || ['__proto__', 'constructor', 'prototype', 'rebuildAppliedExit', 'appliedRebuildExit'].includes(key))) {
        throw fail('REBUILD_INVALID_REQUEST');
    }
    if (!Object.hasOwn(body, 'rebuildExit')) return undefined;
    const selector = body.rebuildExit;
    if (selector === null) return null;
    if (!plain(selector) || !Object.hasOwn(selector, 'nodeId')
        || (selector.nodeId !== null && (typeof selector.nodeId !== 'string' || !id(selector.nodeId)))) {
        throw fail(PORTAL_EXIT_INVALID);
    }
    return asExit(normalizeRebuildExit({ ...selector, nodeId: selector.nodeId === null ? null : id(selector.nodeId) }));
}

const asExit = value => value?.nodeId === null ? null : value;

// Strictly project stored data; undefined means absent or unrecognized.
function storedExit(value) {
    try { return asExit(normalizeRebuildExit(value)); }
    catch { return undefined; }
}

function sameExit(a, b) {
    return a?.nodeId === b?.nodeId && a?.relayGeo === b?.relayGeo;
}

function validReceipt(receipt) {
    return plain(receipt) && Object.keys(receipt).length === 5 && !!id(receipt.listener)
        && ['reverse', 'forward'].includes(receipt.mode)
        && (receipt.protocol === 'vless' || (receipt.mode === 'forward' && receipt.protocol === 'vmess'))
        && Number.isInteger(receipt.port) && receipt.port >= 1 && receipt.port <= 65535
        && typeof receipt.uuid === 'string' && /^\S+$/.test(receipt.uuid);
}

function exitDto(row, rebuild) {
    if (!rebuild) return {};
    const desired = storedExit(row.rebuildExit);
    const applied = validReceipt(row.rebuildApplied) ? storedExit(row.rebuildAppliedExit) : undefined;
    return { ...(desired !== undefined ? { rebuildExit: desired } : row.rebuildExit === undefined ? { rebuildExit: null } : {}),
        ...(applied !== undefined ? { appliedRebuildExit: applied } : {}) };
}

async function validateExit({ Link, Node, selector, from, to, ingress, componentFor }) {
    if (!selector) return;
    const invalid = () => fail(PORTAL_EXIT_INVALID);
    const fromId = id(from._id), relayId = id(to._id), ingressId = id(ingress._id);
    const targetId = selector.nodeId;
    if (role(from) !== 'portal' || role(to) !== 'relay' || from.useCustomConfig || to.useCustomConfig
        || ingress.active !== true || targetId === fromId || targetId === relayId) throw invalid();
    const inventory = await Link.find({ active: true })
        .select('portalNode bridgeNode active rebuildDelete lifecycle mode tunnelProtocol priority geoRouting').lean();
    // Validate the proposed ingress in its desired graph, not in a two-node
    // sample that cannot see shadowed ingress routes or a second relay hop.
    // Other pending picks don't affect reachability and aren't being edited here.
    const link = { ...ingress, rebuildExit: selector };
    const links = [...inventory.filter(row => id(row._id) !== ingressId && !row.rebuildDelete
        && row.lifecycle?.state !== 'deleting'), link];
    const scope = new Set(componentFor(links, [fromId, relayId]));
    const peers = [...scope].filter(nodeId => nodeId !== fromId && nodeId !== relayId);
    const nodes = [from, to, ...await Node.find({ _id: { $in: peers } })
        .select('role cascadeRole type active useCustomConfig').lean()];
    const target = nodes.find(node => id(node._id) === targetId);
    if (role(target) !== 'bridge' || target.type !== 'xray'
        || target.active !== true || target.useCustomConfig) throw invalid();
    try {
        compileRebuildGraph({ nodes, links: links.filter(row => scope.has(id(row.portalNode)) && scope.has(id(row.bridgeNode))) });
    } catch (error) {
        throw [PORTAL_EXIT_UNSUPPORTED, PORTAL_EXIT_AMBIGUOUS].includes(error?.code) ? fail(error.code) : invalid();
    }
}

const inUseRefusals = new WeakMap();
const exitRefusalForError = error => inUseRefusals.get(error);
const primary = query => query.read('primary').readConcern('majority');
const liveEdge = row => row.active === true && row.rebuildDelete !== true && row.lifecycle?.state !== 'deleting';

const pinRows = (Link, filter) => primary(Link.find(filter)
    .select('_id portalNode bridgeNode active lifecycle rebuildDelete rebuildExit rebuildApplied rebuildAppliedExit')).lean();

function pinsMatch(row, matches) {
    const desired = id(row.rebuildExit?.nodeId), applied = id(row.rebuildAppliedExit?.nodeId);
    // Even a malformed non-null tunnel receipt does not prove an old pin is
    // gone. Only public known-applied projection requires a valid receipt.
    return (liveEdge(row) && desired !== undefined && matches(desired))
        || (row.rebuildApplied != null && applied !== undefined && matches(applied));
}

// Caller holds the global Rebuild lock. A retired portal link does not imply
// its source portal node is retired; applied references stay live until readback.
async function assertExitsUnused({ Link, Node, removedIds, retiredNodeId }) {
    const removing = new Set(removedIds.map(id).filter(Boolean));
    if (!removing.size) return;
    const rows = await primary(Link.find({ $or: [{ active: true }, { rebuildApplied: { $ne: null } }] })
        .select('_id portalNode bridgeNode active lifecycle rebuildDelete geoRouting rebuildExit rebuildApplied rebuildAppliedExit')).lean();
    if (!rows.some(row => removing.has(id(row._id)))) return;
    const retired = id(retiredNodeId);
    const outgoing = new Map();
    for (const row of rows) {
        const from = id(row.portalNode);
        if (!outgoing.has(from)) outgoing.set(from, []);
        outgoing.get(from).push(row);
    }
    // Applied rows are independent of the next desired selector. Legacy
    // active rows without an explicit "unapplied" receipt may still serve.
    // A draft-only row is not proof of an alternative applied path.
    const available = (row, applied, after) => {
        if (after && (removing.has(id(row._id)) || !liveEdge(row))) return false;
        if (applied && row.rebuildApplied != null) return true;
        return row.active === true && (!applied || row.rebuildApplied !== null)
            && (liveEdge(row) || removing.has(id(row._id)));
    };
    const used = (start, target, applied, after) => {
        const seen = new Set([start]);
        for (const from of seen) {
            for (const row of outgoing.get(from) ?? []) {
                if (!available(row, applied, after)) continue;
                const next = id(row.bridgeNode);
                if (next === target) return true;
                if (next && row.geoRouting?.enabled !== true) seen.add(next);
            }
        }
        return false;
    };
    await refusePinnedPortals(Node, rows.filter(row => {
        if (retired && id(row.portalNode) === retired) return false;
        const start = id(row.bridgeNode);
        const desired = liveEdge(row) && id(row.rebuildExit?.nodeId);
        const applied = row.rebuildApplied != null && id(row.rebuildAppliedExit?.nodeId);
        return [[desired, false], [applied, true]].some(([target, observed]) => target
            && used(start, target, observed, false) && !used(start, target, observed, true));
    }));
}

// An edit to the portal itself can invalidate its ingress regardless of how
// many redundant edges the relay has to the selected exit node.
async function assertPortalSourceExitsUnused({ Link, Node, nodeId }) {
    const rows = await pinRows(Link, { portalNode: nodeId });
    await refusePinnedPortals(Node, rows.filter(row => pinsMatch(row, () => true)));
}

async function refusePinnedPortals(Node, rows) {
    const portals = new Set(rows.map(row => id(row.portalNode) ?? id(row._id) ?? 'Unknown portal'));
    if (!portals.size) return;
    const cards = await Node.find({ _id: { $in: [...portals].filter(id) } }).select('_id name').lean();
    const names = new Map(cards.map(node => [id(node._id), plainName(node.name)]));
    const error = fail('REBUILD_EXIT_IN_USE');
    inUseRefusals.set(error, { code: error.code,
        portalNames: [...new Set([...portals].map(portal => names.get(portal) || portal))].sort().slice(0, 100) });
    throw error;
}

module.exports = { inputExit, storedExit, sameExit, exitDto, validateExit, assertExitsUnused, exitRefusalForError,
    assertPortalSourceExitsUnused, plainName, id, PORTAL_EXIT_INVALID };
