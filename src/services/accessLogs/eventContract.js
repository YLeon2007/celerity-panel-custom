/**
 * Canonical access-log event contract shared across the pipeline.
 *
 * The cc-agent ships raw Xray access-log lines (with minimal metadata). All
 * parsing happens on the panel so the parser can evolve without rebuilding the
 * agent. This module is the single source of truth for:
 *   - the parser version (bump when the parsing logic changes materially),
 *   - the canonical field set stored in Parquet,
 *   - the Xray access-line parser.
 *
 * A canonical event looks like:
 *   {
 *     eventId, timestamp (Date), nodeId, email,
 *     sourceIp, sourcePort, destinationHost, destinationIp, destinationPort,
 *     network, inboundTag, outboundTag, action,
 *     raw, parseOk, parserVersion
 *   }
 */

const crypto = require('crypto');

// Bump when the parsing logic changes in a way that would produce different
// structured output for the same raw line. Stored per event so historical
// Parquet can be re-parsed if needed.
const PARSER_VERSION = 1;

// Ordered list of canonical columns. Kept explicit so the Parquet schema and
// the parser never drift apart.
const EVENT_COLUMNS = [
    'eventId',
    'timestamp',
    'nodeId',
    'email',
    'sourceIp',
    'sourcePort',
    'destinationHost',
    'destinationIp',
    'destinationPort',
    'network',
    'inboundTag',
    'outboundTag',
    'action',
    'raw',
    'parseOk',
    'parserVersion',
];

// Xray access log line (default text format), examples:
//   2023/11/22 17:01:32 192.168.1.33:11421 accepted tcp:example.com:443 [vless-in -> direct] email: 42
//   2024/05/01 08:12:00.123456 from 1.2.3.4:5555 accepted udp:8.8.8.8:53 [in -> out] email: user@x
// The timestamp is in the node's local time; the caller supplies a fallback
// reference time and time zone handling is done at ingest/worker level.
const ACCESS_LINE_RE = new RegExp(
    '^(?<ts>\\d{4}/\\d{2}/\\d{2} \\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?)\\s+' +
    '(?:from\\s+)?' +
    '(?<src>\\S+?)\\s+' +
    '(?<action>accepted|rejected|blocked)\\s+' +
    '(?<net>tcp|udp)\\s*:\\s*(?<dest>\\S+?)' +
    '(?:\\s+\\[(?<route>[^\\]]*)\\])?' +
    '(?:\\s+email:\\s*(?<email>\\S+))?' +
    '\\s*$'
);

const MAX_RAW_LEN = 8192;

function truncate(value, max) {
    if (typeof value !== 'string') return value;
    return value.length > max ? value.slice(0, max) : value;
}

// Split "host:port" from the right so IPv6 literals like [::1]:443 and
// bracket-less forms both work reasonably. Returns { host, port|null }.
function splitHostPort(value) {
    if (!value) return { host: '', port: null };
    let v = value.trim();
    // Bracketed IPv6: [::1]:443
    const bracket = v.match(/^\[(.+)\]:(\d+)$/);
    if (bracket) {
        return { host: bracket[1], port: Number(bracket[2]) };
    }
    const idx = v.lastIndexOf(':');
    if (idx === -1) return { host: v, port: null };
    const portStr = v.slice(idx + 1);
    if (/^\d+$/.test(portStr)) {
        return { host: v.slice(0, idx), port: Number(portStr) };
    }
    return { host: v, port: null };
}

function isIpLiteral(host) {
    if (!host) return false;
    // IPv4
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
    // IPv6 (loose)
    if (host.includes(':')) return true;
    return false;
}

// Parse "vless-in -> direct" route annotation into inbound/outbound tags.
function parseRoute(route) {
    if (!route) return { inboundTag: '', outboundTag: '' };
    const parts = route.split('->').map(s => s.trim());
    if (parts.length === 2) {
        return { inboundTag: parts[0], outboundTag: parts[1] };
    }
    return { inboundTag: route.trim(), outboundTag: '' };
}

// Convert Xray timestamp ("2023/11/22 17:01:32" or with fractional seconds)
// to a Date. Xray writes local time without a zone; we treat it as UTC here
// and let the worker apply clock-skew quarantine relative to panel time. The
// raw line is always preserved so this can be corrected later.
function parseTimestamp(ts) {
    if (!ts) return null;
    const m = ts.match(/^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/);
    if (!m) return null;
    const [, y, mo, d, h, mi, s, frac] = m;
    const ms = frac ? Number(('0.' + frac)) * 1000 : 0;
    const date = new Date(Date.UTC(
        Number(y), Number(mo) - 1, Number(d),
        Number(h), Number(mi), Number(s), Math.floor(ms)
    ));
    return isNaN(date.getTime()) ? null : date;
}

/**
 * Deterministic event id for idempotent storage and dedup within a chunk.
 * Derived from node id, raw line and read offset so identical retries collapse
 * while legitimately repeated access lines (same text, different offset) stay
 * distinct.
 */
function computeEventId(nodeId, raw, offset) {
    return crypto
        .createHash('sha256')
        .update(String(nodeId || ''))
        .update('\x00')
        .update(String(raw || ''))
        .update('\x00')
        .update(String(offset == null ? '' : offset))
        .digest('hex')
        .slice(0, 32);
}

/**
 * Privacy mask for client IPs (settings.accessLogs.maskClientIp).
 * IPv4 keeps the /24 (last octet zeroed); IPv6 keeps the first three hextets.
 * Exact source-IP search becomes impossible by design.
 */
function maskIp(ip) {
    if (!ip) return '';
    const v4 = ip.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/);
    if (v4) return `${v4[1]}.0`;
    if (ip.includes(':')) {
        const parts = ip.split(':');
        return parts.slice(0, 3).join(':') + '::';
    }
    return ip;
}

/**
 * Apply the client-IP mask to a canonical event. Also scrubs the raw line so
 * the original address does not survive in the stored `raw` column. The event
 * id is left untouched (it was derived from the original line before masking,
 * which keeps retry dedup deterministic).
 */
function maskEventSourceIp(ev) {
    if (!ev || !ev.sourceIp) return ev;
    const masked = maskIp(ev.sourceIp);
    if (masked === ev.sourceIp) return ev;
    const raw = ev.raw ? ev.raw.split(ev.sourceIp).join(masked) : ev.raw;
    return { ...ev, sourceIp: masked, raw };
}

/**
 * Parse a single raw Xray access-log line into a canonical event.
 *
 * @param {string} raw       Raw log line (without trailing newline).
 * @param {Object} meta      { nodeId, offset } metadata from the agent.
 * @returns {Object} canonical event; parseOk=false when the line did not match.
 */
function parseAccessLine(raw, meta = {}) {
    const nodeId = meta.nodeId || '';
    const offset = meta.offset;
    const rawTrunc = truncate(String(raw == null ? '' : raw), MAX_RAW_LEN);

    const base = {
        eventId: computeEventId(nodeId, rawTrunc, offset),
        timestamp: null,
        nodeId,
        email: '',
        sourceIp: '',
        sourcePort: null,
        destinationHost: '',
        destinationIp: '',
        destinationPort: null,
        network: '',
        inboundTag: '',
        outboundTag: '',
        action: '',
        raw: rawTrunc,
        parseOk: false,
        parserVersion: PARSER_VERSION,
    };

    const m = ACCESS_LINE_RE.exec(rawTrunc);
    if (!m || !m.groups) {
        return base;
    }

    const g = m.groups;
    const src = splitHostPort(g.src);
    const dest = splitHostPort(g.dest);
    const route = parseRoute(g.route);

    return {
        ...base,
        timestamp: parseTimestamp(g.ts),
        email: g.email ? truncate(g.email, 256) : '',
        sourceIp: src.host,
        sourcePort: src.port,
        destinationHost: isIpLiteral(dest.host) ? '' : dest.host,
        destinationIp: isIpLiteral(dest.host) ? dest.host : '',
        destinationPort: dest.port,
        network: g.net || '',
        inboundTag: route.inboundTag,
        outboundTag: route.outboundTag,
        action: g.action || '',
        parseOk: true,
    };
}

module.exports = {
    PARSER_VERSION,
    EVENT_COLUMNS,
    MAX_RAW_LEN,
    parseAccessLine,
    computeEventId,
    parseTimestamp,
    splitHostPort,
    parseRoute,
    maskIp,
    maskEventSourceIp,
};
