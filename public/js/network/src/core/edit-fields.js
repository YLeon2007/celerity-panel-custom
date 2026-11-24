// The details route returns a lean row, so persisted values and model defaults
// are distinct. Defaults below are for display/comparison, never a PUT template.
export const DEFAULT_PORT = 10086;
export const TRANSPORTS = [['tcp', 'TCP'], ['ws', 'WebSocket'], ['grpc', 'gRPC'], ['xhttp', 'XHTTP / SplitHTTP'], ['kcp', 'mKCP (UDP)']];
export const KCP_HEADERS = ['none', 'wechat', 'dtls', 'srtp', 'wireguard'];
// Match cascadeTransport.js, including its sparse-on-disk mKCP defaults.
export const KCP_NUMBERS = {
    kcpMtu: [576, 1460, 1350],
    kcpTti: [10, 100, 20],
    kcpUplinkCapacity: [1, 1000, 100],
    kcpDownlinkCapacity: [1, 1000, 100],
};
export const allowsReality = transport => transport !== 'kcp' && transport !== 'ws';
export const allowsVmess = (mode, security) => mode === 'forward' && security !== 'reality';
export const inRange = (value, min, max) => Number.isInteger(value) && value >= min && value <= max;

export function tlsNameOK(name) {
    if (typeof name !== 'string' || !name || name.length > 253) return false;
    if (!name.includes(':')) return name.split('.').every(part => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(part));
    if (!/^[\da-f:.]+$/i.test(name)) return false;
    try { return Boolean(new URL(`http://[${name}]/`).hostname); } catch (_) { return false; }
}

const transportOK = value => TRANSPORTS.some(([key]) => key === value);
const text = value => typeof value === 'string' && !/[\p{Cc}\p{Bidi_Control}]/u.test(value);
const validators = {
    name: value => text(value) && value.trim().length > 0 && value.length <= 100,
    mode: value => ['reverse', 'forward'].includes(value),
    tunnelPort: value => inRange(value, 1, 65535),
    tunnelProtocol: value => ['vless', 'vmess'].includes(value),
    tunnelTransport: transportOK,
    tunnelSecurity: value => ['none', 'tls', 'reality'].includes(value),
    tlsServerName: tlsNameOK,
    kcpHeader: value => KCP_HEADERS.includes(value),
    ...Object.fromEntries(Object.entries(KCP_NUMBERS).map(([key, [min, max]]) => [key, value => inRange(value, min, max)])),
};
const isKcpField = key => key === 'kcpHeader' || Object.hasOwn(KCP_NUMBERS, key);
const fieldError = key => key === 'tlsServerName' ? 'badTlsName' : isKcpField(key) ? 'badKcp' : 'badSettings';

export class InvalidEditFields extends Error {
    constructor(key = 'badSettings') {
        super('Invalid edit fields');
        this.key = key;
    }
}

// Never retain the raw response or copy arbitrary values from it. The server
// reads rebuildTlsServerName ?? tlsServerName but writes only tlsServerName input.
export function projectEditFields(row) {
    const fields = {};
    for (const [key, valid] of Object.entries(validators)) {
        const value = key === 'tlsServerName' ? row.rebuildTlsServerName ?? row.tlsServerName : row[key];
        if (value === undefined) continue;
        // Preserve legacy display values without treating them as new writes.
        const safe = key === 'name' || key === 'tlsServerName' ? text(value)
            : key === 'tunnelTransport' && value === 'splithttp' || valid(value);
        if (!safe) throw new InvalidEditFields(fieldError(key));
        fields[key] = value;
    }
    if (!fields.name?.trim()) throw new InvalidEditFields();
    return fields;
}

export function editValues(edit) {
    return {
        name: edit.name,
        mode: edit.mode ?? 'reverse',
        tunnelPort: edit.tunnelPort ?? DEFAULT_PORT,
        tunnelProtocol: edit.tunnelProtocol ?? 'vless',
        tunnelTransport: edit.tunnelTransport === 'splithttp' ? 'xhttp' : edit.tunnelTransport ?? 'tcp',
        tunnelSecurity: edit.tunnelSecurity ?? 'none',
        tlsServerName: edit.tlsServerName ?? '',
        kcpHeader: edit.kcpHeader ?? 'none',
        ...Object.fromEntries(Object.entries(KCP_NUMBERS).map(([key, [, , fallback]]) => [key, edit[key] ?? fallback])),
    };
}

// Wire allowlist shared by the form, controller and PUT client. No generic
// serialization of controls, endpoints or draft/detail objects.
function writableEditFields(input) {
    const fields = {};
    for (const [key, valid] of Object.entries(validators)) {
        if (!Object.hasOwn(input, key)) continue;
        const value = input[key];
        if (!valid(value)) throw new InvalidEditFields(fieldError(key));
        fields[key] = value;
    }
    return fields;
}

export function editPatch(edit, proposed) {
    if (!proposed || typeof proposed !== 'object' || Array.isArray(proposed)) throw new InvalidEditFields();
    const before = editValues(edit);
    const submitted = key => Object.hasOwn(proposed, key) ? proposed[key] : before[key];
    const transport = submitted('tunnelTransport'), security = submitted('tunnelSecurity');
    const patch = {};
    for (const key of Object.keys(validators)) {
        if (!Object.hasOwn(proposed, key) || (key === 'tlsServerName' && security !== 'tls')
            || (isKcpField(key) && transport !== 'kcp')) continue;
        const raw = proposed[key];
        // SplitHTTP is an alias on the server, not a new write on round-trip.
        if (key === 'tunnelTransport' && raw === 'splithttp' && before[key] === 'xhttp') continue;
        const trim = key === 'name' || key === 'tlsServerName';
        const value = trim && typeof raw === 'string' ? raw.trim() : raw;
        if (value !== (trim ? before[key].trim() : before[key])) patch[key] = value;
    }
    if (!Object.keys(patch).length) return patch;
    const result = writableEditFields(patch);
    if ((security === 'reality' && !allowsReality(transport))
        || (submitted('tunnelProtocol') === 'vmess' && !allowsVmess(submitted('mode'), security))) throw new InvalidEditFields();
    if (security === 'tls' && !tlsNameOK(result.tlsServerName ?? before.tlsServerName)) {
        throw new InvalidEditFields('badTlsName');
    }
    return result;
}
