'use strict';

const { createHash } = require('node:crypto');
const { isIP } = require('node:net');

const TTL_MS = 60_000;
const MAX_CLOCK_LEAD_MS = 5_000;
const MAX_BYTES = 2 * 1024 * 1024;
const NODE_FIELDS = 'type active status cascadeRole createdAt agentVersion ip xray.agentToken xray.agentPort xray.agentTls groups onlineUsers';
const NODE_ROLES = ['portal', 'standalone'];
const NODE_ROLE_FILTER = { $or: [{ cascadeRole: { $in: NODE_ROLES } }, { cascadeRole: { $exists: false } }] };

function agentVersionState(version, minimumPatch = 0) {
    if (typeof version !== 'string' || version.length > 128) return 'unavailable';
    const match = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[\da-z-]+(?:\.[\da-z-]+)*)?(?:\+[\da-z-]+(?:\.[\da-z-]+)*)?$/i.exec(version);
    if (!match || match[0] !== version) return 'unavailable';
    const [major, minor, patch] = match.slice(1, 4).map(Number);
    if (![major, minor, patch].every(Number.isSafeInteger)) return 'unavailable';
    const old = major < 1 || (major === 1 && (minor < 6 || (minor === 6 &&
        (patch < minimumPatch || (patch === minimumPatch && match[4])))));
    return old ? 'old-agent' : 'eligible';
}

function nodeState(node) {
    if (node?.type !== 'xray' || node.active !== true || node.status !== 'online'
        || (node.cascadeRole !== undefined && !NODE_ROLES.includes(node.cascadeRole))
        || typeof node.xray?.agentToken !== 'string' || !node.xray.agentToken) return 'unavailable';
    return agentVersionState(node.agentVersion);
}

// Require the observed agent endpoint and node identity to remain current.
// A missing legacy role is the schema's default standalone, but a null role is not.
function nodeIdentity(node) {
    return Object.fromEntries(Object.entries({
        createdAt: node.createdAt, ip: node.ip, cascadeRole: node.cascadeRole, agentVersion: node.agentVersion,
        'xray.agentToken': node.xray?.agentToken, 'xray.agentPort': node.xray?.agentPort,
        'xray.agentTls': node.xray?.agentTls,
    }).map(([key, value]) => [key, value === undefined ? { $exists: false } : value]));
}

function nodeFingerprint(node) {
    return createHash('sha256').update(JSON.stringify(nodeIdentity(node))).digest('hex');
}

function parseUtc(value) {
    if (typeof value !== 'string') return NaN;
    const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(value);
    if (!match || match[0] !== value) return NaN;
    const canonical = `${match[1]}.${(match[2] || '').padEnd(3, '0').slice(0, 3)}Z`;
    const epoch = Date.parse(canonical);
    return Number.isFinite(epoch) && new Date(epoch).toISOString() === canonical ? epoch : NaN;
}

function validUserId(id) {
    // Xray configGenerator uses the panel userId verbatim as its email. This
    // isn't an RFC email address; don't normalize it or permit a bare IP ID.
    return id.length > 0 && id.length <= 256 && id === id.trim() && !/[\p{Cc}\p{Cs}]/u.test(id)
        && isIP(id) === 0 && !['__proto__', 'prototype', 'constructor'].includes(id);
}

function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function decodeSnapshot(payload, wallTime, monotonicTime, agentVersion) {
    if (!isRecord(payload) || typeof payload.supported !== 'boolean' || !isRecord(payload.users)) return null;
    const supported = payload.supported;
    if (!supported && (agentVersionState(agentVersion, 1) !== 'eligible' || Object.keys(payload.users).length)) return null;
    const updatedAt = parseUtc(payload.updatedAt);
    const clockDelta = wallTime - updatedAt;
    if (!Number.isFinite(clockDelta) || clockDelta < -MAX_CLOCK_LEAD_MS || clockDelta >= TTL_MS) return null;
    // Small clock skew must not reject a healthy agent or extend retention.
    const age = Math.max(0, clockDelta);
    const expiresAt = monotonicTime + TTL_MS - age;
    const users = new Map();
    let total = 0;
    for (const [id, rows] of Object.entries(payload.users)) {
        if (!Array.isArray(rows) || (total += rows.length + 1) > 20_000) return null;
        if (!validUserId(id)) continue;
        const ips = new Map();
        for (const row of rows) {
            if (!isRecord(row) || typeof row.ip !== 'string' || row.ip.length > 45 || row.ip.includes('%')) return null;
            const family = isIP(row.ip);
            const seen = parseUtc(row.lastSeen);
            if (!family || !Number.isFinite(seen) || seen > updatedAt) return null;
            // Xray records the last open, not a heartbeat. Presence in the
            // online map is authoritative for the lifetime of this snapshot.
            const ip = family === 4 ? row.ip : new URL(`http://[${row.ip}]`).hostname.slice(1, -1);
            if (seen <= (ips.get(ip)?.seen ?? -Infinity)) continue;
            ips.set(ip, { ip, seen, lastSeen: new Date(seen).toISOString() });
        }
        if (ips.size) users.set(id, ips);
    }
    return { state: supported ? 'ready' : 'no-data', expiresAt, updatedAt, users };
}

function nullableText(value) {
    return typeof value === 'string' && value.length <= 256 && !/[\p{Cc}\p{Cs}]/u.test(value) ? value : null;
}

function geoFields(value) {
    const asn = value?.asn;
    return {
        country: nullableText(value?.country), region: nullableText(value?.region), city: nullableText(value?.city),
        asn: (Number.isInteger(asn) && asn > 0 && asn <= 0xffffffff) ||
            (typeof asn === 'string' && /^(?:AS)?[1-9]\d{0,9}$/i.test(asn) && asn === asn.trim()) ? asn : null,
        isp: nullableText(value?.isp),
    };
}

module.exports = { MAX_BYTES, NODE_FIELDS, NODE_ROLE_FILTER, nodeState, nodeIdentity, nodeFingerprint, decodeSnapshot, geoFields };
