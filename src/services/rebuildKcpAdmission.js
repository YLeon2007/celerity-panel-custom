'use strict';

const { isIP } = require('node:net');
const { isDeepStrictEqual } = require('node:util');

const { MIN_KCP_XRAY_VERSION: minimumVersion } = require('../utils/cascadeTransport');
const minimumTriplet = minimumVersion.split('.').map(Number);
function belowMinimum(actual) {
    const firstDifference = actual.findIndex((part, i) => part !== minimumTriplet[i]);
    return firstDifference !== -1 && actual[firstDifference] < minimumTriplet[firstDifference];
}
const refs = link => [String(link.portalNode), String(link.bridgeNode)];
const kcpListenerId = link => String(link.mode === 'forward' ? link.bridgeNode : link.portalNode);
// Match the installed layout that uses DIRECT for Apply, not an unowned
// historical route-group row. Do not reinterpret the installation receipt.
const hasDirectLifecycle = state => state?.rebuildInstallToken != null || state?.rebuildMachineId != null;
const objectId = /^[a-f0-9]{24}(?![\s\S])/i;

function label(row, nodeId) {
    const name = typeof row?.name === 'string' ? row.name.trim() : '';
    return { nodeId, nodeName: name.length <= 160 && /^[\p{L}\p{M}\p{N} ._()#–—-]+(?![\s\S])/u.test(name) ? name : nodeId };
}

// Only published, safe fields are created here. A transport/driver error with
// the same code or arbitrary metadata cannot masquerade as an operation refusal.
const refusals = new WeakMap();
function refuse(code, details = {}) {
    const error = Object.assign(new Error(code), { code });
    refusals.set(error, { code, ...details });
    throw error;
}
const operationRefusalForError = error => refusals.get(error);
const refuseStaleKcpPreview = () => refuse('REBUILD_PREVIEW_CHANGED');

function versionTriplet(value) {
    // Authenticated cc-agent /info stores the bare version token, not its
    // banner. Do not coerce, trim, extract substrings or accept prereleases.
    const match = typeof value === 'string' && /^(0|[1-9]\d{0,3})\.(0|[1-9]\d?)\.(0|[1-9]\d?)(?![\s\S])/.exec(value);
    if (!match || Number(match[2]) > 12 || Number(match[3]) > 31) return null;
    return match.slice(1).map(Number);
}

function observeKcpVersions(links, nodes) {
    const ids = [...new Set(links.flatMap(refs))].sort();
    const inventory = new Map(nodes.map(n => [String(n._id), n]));
    const issues = [], versions = [];
    for (const nodeId of ids) {
        if (!objectId.test(nodeId)) throw Object.assign(new Error('REBUILD_INVALID_ID'), { code: 'REBUILD_INVALID_ID' });
        const node = inventory.get(nodeId);
        const triplet = versionTriplet(node?.xrayVersion);
        if (!triplet || belowMinimum(triplet)) {
            issues.push({ ...label(node, nodeId), version: triplet ? node.xrayVersion : null,
                reason: triplet ? 'too_old' : 'unknown' });
        } else versions.push([nodeId, node.xrayVersion]);
    }
    if (issues.length) refuse('REBUILD_KCP_XRAY_VERSION_UNSUPPORTED', { minimumVersion, issues });
    return versions;
}

function host(value) {
    if (typeof value !== 'string' || !value) return '';
    const bare = value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
    if (isIP(bare) === 6 && !bare.includes('%')) return new URL(`http://[${bare}]/`).hostname;
    return bare.toLowerCase().replace(/\.$/, '');
}

function hoppingContains(port, range) {
    if (typeof range !== 'string' || !range.includes('-')) return false;
    // Match the existing Hysteria setup path's parseInt of the first two
    // segments as well as normal 'start-end' ranges. Only real UDP ports count.
    const [min, max] = range.split('-', 2).map(s => parseInt(s.trim()));
    return min > 0 && max <= 65535 && port >= min && port <= max;
}

function checkKcpUdpPorts(links, nodes, hysteria, installed = new Map()) {
    const byId = new Map(nodes.map(n => [String(n._id), n]));
    const byHost = new Map();
    for (const row of hysteria) {
        const ip = host(row.ip);
        if (!ip) continue;
        if (!byHost.has(ip)) byHost.set(ip, []);
        byHost.get(ip).push(row);
    }
    const issues = [];
    for (const link of links) {
        const nodeId = kcpListenerId(link);
        const node = byId.get(nodeId), port = link.tunnelPort;
        if (!Number.isInteger(port) || port < 1 || port > 65535) continue; // composer validates shape
        const state = installed.get(nodeId);
        if (state && [500, 4500, 1701, state.tproxyPort].includes(port)) {
            issues.push({ ...label(node, nodeId), port, reason: 'l2tp_reserved' });
        }
        for (const row of byHost.get(host(node?.ip)) || []) {
            // Inactive in the panel does not mean stopped on the host or that
            // prerouting rules were removed. Explicitly disabled aliases are not advertised.
            const entries = [{ port: row.port || 443, portRange: row.portRange },
                ...(Array.isArray(row.portConfigs) ? row.portConfigs.filter(c => c && c.enabled !== false) : [])];
            const direct = entries.some(c => c.port === port);
            if (!direct && !entries.some(c => hoppingContains(port, c.portRange))) continue;
            const ownerId = String(row._id);
            issues.push({ ...label(node, nodeId), port, ...(objectId.test(ownerId) && { ownerId }),
                reason: direct ? 'hysteria_port' : 'hysteria_hop_range' });
        }
    }
    if (issues.length) {
        const distinct = new Map(issues.map(issue => [JSON.stringify(issue), issue]));
        refuse('REBUILD_KCP_UDP_PORT_CONFLICT', { issues: [...distinct.keys()].sort().map(key => distinct.get(key)) });
    }
}

async function readKcpAdmission(Node, links, nodes, installed) {
    const ids = [...new Set(links.flatMap(refs))].sort();
    const fresh = await Node.find({ _id: { $in: ids }, active: true, type: 'xray' })
        .select('_id name ip xrayVersion').read('primary').readConcern('majority').lean();
    const versions = observeKcpVersions(links, fresh);
    const addresses = new Map(nodes.map(n => [String(n._id), n.ip]));
    if (fresh.some(n => n.ip !== addresses.get(String(n._id)))) refuseStaleKcpPreview();
    // Do not add a remote firewall or listener writer. This is only an
    // inventory reservation; host-local/firewall reachability is not proved.
    const hysteria = await Node.find({ type: 'hysteria' }).select('_id ip port portRange portConfigs')
        .read('primary').readConcern('majority').lean();
    checkKcpUdpPorts(links, fresh, hysteria, installed);
    // DIRECT's retained MAIN listener check is TCP-only, and its Remove
    // profile check cannot prove fixed mKCP UDP binds. Never stage that layout.
    const blocked = [...new Set(links.map(kcpListenerId))].sort()
        .filter(id => hasDirectLifecycle(installed?.get(id)));
    if (blocked.length) refuse('REBUILD_L2TP_KCP_LISTENER_UNSUPPORTED', {
        issues: blocked.map(id => label(fresh.find(n => String(n._id) === id), id)),
    });
    return versions;
}

function assertKcpVersionsUnchanged(before, after) {
    if (!isDeepStrictEqual(before, after)) refuseStaleKcpPreview();
}

module.exports = { readKcpAdmission, kcpListenerId, hasDirectLifecycle, assertKcpVersionsUnchanged,
    refuseStaleKcpPreview, operationRefusalForError };
