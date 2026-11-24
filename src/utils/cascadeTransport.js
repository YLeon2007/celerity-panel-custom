'use strict';

const CASCADE_TRANSPORTS = Object.freeze(['tcp', 'ws', 'grpc', 'xhttp', 'splithttp', 'kcp']);
const CASCADE_SECURITIES = Object.freeze(['none', 'tls', 'reality']);
const KCP_HEADERS = Object.freeze(['none', 'wechat', 'dtls', 'srtp', 'wireguard']);
const KCP_LIMITS = Object.freeze({
    mtu: Object.freeze({ min: 576, max: 1460 }),
    tti: Object.freeze({ min: 10, max: 100 }),
    capacity: Object.freeze({ min: 1, max: 1000 }),
});
const KCP_DEFAULTS = Object.freeze({ mtu: 1350, tti: 20, uplinkCapacity: 100, downlinkCapacity: 100, header: 'none' });
const MIN_KCP_XRAY_VERSION = '26.6.1'; // First upstream release with finalmask mkcp-legacy.
const KCP_NUMERIC_FIELDS = Object.freeze({
    kcpMtu: KCP_LIMITS.mtu,
    kcpTti: KCP_LIMITS.tti,
    kcpUplinkCapacity: KCP_LIMITS.capacity,
    kcpDownlinkCapacity: KCP_LIMITS.capacity,
});
const KCP_INPUT_FIELDS = Object.freeze([...Object.keys(KCP_NUMERIC_FIELDS), 'kcpHeader']);

const normalizeTransport = transport => transport === 'splithttp' ? 'xhttp' : (transport || 'tcp');
const isKcpTransport = transport => transport === 'kcp';
const CLASSIC_KCP_REBUILD_ONLY = 'CLASSIC_KCP_REBUILD_ONLY';
const CLASSIC_KCP_MESSAGE = 'mKCP (UDP) is supported only in Rebuild. Use Rebuild Preview and Apply.';
function assertClassicTunnelTransport(...links) {
    if (links.some(link => isKcpTransport(link?.tunnelTransport))) {
        throw Object.assign(new Error(CLASSIC_KCP_MESSAGE), { code: CLASSIC_KCP_REBUILD_ONLY });
    }
}
const tunnelSocketProtocol = link => isKcpTransport(link?.tunnelTransport) ? 'udp' : 'tcp';
const isKcpSecurity = security => security === 'none' || security === 'tls';

function validateTransportSecurity(transport = 'tcp', security = 'none') {
    if (!CASCADE_TRANSPORTS.includes(transport)) return `tunnelTransport must be one of: ${CASCADE_TRANSPORTS.join(', ')}`;
    if (!CASCADE_SECURITIES.includes(security)) return `tunnelSecurity must be one of: ${CASCADE_SECURITIES.join(', ')}`;
    if (isKcpTransport(transport) && !isKcpSecurity(security)) {
        return 'REALITY security is not compatible with mKCP transport. Use none or TLS.';
    }
    if (transport === 'ws' && security === 'reality') {
        return 'REALITY security is not compatible with WebSocket transport. Use TCP, gRPC, or SplitHTTP.';
    }
    return null;
}

/** Allowlisted, partial public settings. Passwords are never inputs. */
function sanitizeKcpInput(input = {}) {
    const fields = {};
    for (const [key, { min, max }] of Object.entries(KCP_NUMERIC_FIELDS)) {
        if (!Object.hasOwn(input ?? {}, key) || input[key] === undefined) continue;
        const raw = input[key];
        const value = typeof raw === 'string' && raw && !/\D/.test(raw) ? Number(raw) : raw;
        if (!Number.isSafeInteger(value) || value < min || value > max) {
            return { fields: {}, error: `${key} must be an integer between ${min} and ${max}` };
        }
        fields[key] = value;
    }
    if (Object.hasOwn(input ?? {}, 'kcpHeader') && input.kcpHeader !== undefined) {
        if (!KCP_HEADERS.includes(input.kcpHeader)) {
            return { fields: {}, error: `kcpHeader must be one of: ${KCP_HEADERS.join(', ')}` };
        }
        fields.kcpHeader = input.kcpHeader;
    }
    return { fields, error: null };
}

/** Socket ownership of the fixed inbounds emitted by panel generators. */
function xrayListenerProtocols({ protocol, settings, streamSettings } = {}) {
    const network = normalizeTransport(streamSettings?.network);
    if (isKcpTransport(network) || network === 'hysteria' || protocol === 'hysteria') return ['udp'];
    const alpn = streamSettings?.tlsSettings?.alpn;
    if (network === 'xhttp' && streamSettings.security === 'tls' && alpn?.length === 1 && alpn[0] === 'h3') return ['udp'];
    if (protocol === 'dokodemo-door' && typeof settings?.network === 'string') {
        const networks = settings.network.split(',').map(value => value.trim().toLowerCase());
        return ['tcp', 'udp'].filter(value => networks.includes(value));
    }
    // SOCKS UDP may be bound on demand rather than as a fixed listener on some
    // core versions. Reserve it nonetheless when the profile requests UDP.
    return protocol === 'socks' && settings?.udp === true ? ['tcp', 'udp'] : ['tcp'];
}

function portInRange(port, range) {
    const match = /^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$/.exec(String(range || ''));
    return !!match && port >= Number(match[1]) && port <= Number(match[2]);
}

function findHysteriaUdpConflict(port, hysteriaNodes) {
    for (const node of hysteriaNodes || []) {
        const entries = [{ port: node.port || 443, portRange: node.portRange },
            ...(node.portConfigs || []).filter(entry => entry && entry.enabled !== false)];
        for (const entry of entries) {
            if (entry.port === port) return `UDP port ${port} is used by Hysteria on ${node.name}`;
            if (portInRange(port, entry.portRange)) {
                return `UDP port ${port} is inside the Hysteria port hopping range ${entry.portRange} on ${node.name}`;
            }
        }
    }
    return null;
}

/** Display-only JSON.stringify replacer; never use for configs sent to Xray. */
function redactKcpConfigValue(key, value) {
    if (key.toLowerCase() === 'kcppassword') return '<redacted>';
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || !Object.entries(value).some(([k, v]) => k.toLowerCase() === 'type'
            && typeof v === 'string' && v.toLowerCase() === 'mkcp-legacy')) return value;
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k,
        k.toLowerCase() === 'settings' && v && typeof v === 'object' && !Array.isArray(v)
            ? Object.fromEntries(Object.entries(v).map(([field, content]) => [field,
                field.toLowerCase() === 'value' && content !== '' ? '<redacted>' : content])) : v]));
}

module.exports = {
    CASCADE_TRANSPORTS, CASCADE_SECURITIES, KCP_HEADERS, KCP_LIMITS, KCP_DEFAULTS, KCP_NUMERIC_FIELDS, KCP_INPUT_FIELDS,
    MIN_KCP_XRAY_VERSION,
    CLASSIC_KCP_REBUILD_ONLY, CLASSIC_KCP_MESSAGE, assertClassicTunnelTransport,
    normalizeTransport, isKcpTransport, isKcpSecurity, validateTransportSecurity, sanitizeKcpInput, tunnelSocketProtocol,
    xrayListenerProtocols, portInRange, findHysteriaUdpConflict, redactKcpConfigValue,
};