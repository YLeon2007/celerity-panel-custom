function normalizeClientOs(device = {}) {
    const raw = `${device.platform || ''} ${device.userAgent || ''} ${device.deviceModel || ''}`.toLowerCase();
    if (/\b(ipados|ios|iphone|ipad|ipod)\b/.test(raw) || /cpu (iphone )?os /.test(raw)) return 'ios';
    if (/android/.test(raw)) return 'android';
    if (/windows|win32|win64|windows nt/.test(raw)) return 'windows';
    if (/mac os|macintosh|darwin/.test(raw)) return 'macos';
    if (/linux/.test(raw)) return 'linux';
    return 'unknown';
}

function pluralRuDevice(n) {
    const abs = Math.abs(n);
    const mod10 = abs % 10;
    const mod100 = abs % 100;
    if (mod10 === 1 && mod100 !== 11) return 'устройство';
    if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return 'устройства';
    return 'устройств';
}

function deviceWord(n, lang = 'ru') {
    if (String(lang).startsWith('ru')) return pluralRuDevice(n);
    return n === 1 ? 'device' : 'devices';
}

function uniqPreserveOrder(values) {
    const seen = new Set();
    const out = [];
    values.forEach((value) => {
        if (!seen.has(value)) {
            seen.add(value);
            out.push(value);
        }
    });
    return out;
}

function buildClientStats(devices = [], options = {}) {
    const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
    const onlineTtlSeconds = Math.max(1, Number(options.onlineTtlSeconds || 10));
    const lang = options.lang || 'ru';
    const cutoff = now.getTime() - onlineTtlSeconds * 1000;

    const sorted = [...devices].sort((a, b) => new Date(b.lastSeenAt || 0) - new Date(a.lastSeenAt || 0));
    const osList = uniqPreserveOrder(sorted.map(normalizeClientOs));
    const onlineDevices = sorted.filter((device) => {
        const ts = new Date(device.lastSeenAt || 0).getTime();
        return Number.isFinite(ts) && ts >= cutoff;
    });

    let osSummary = '—';
    if (osList.length === 1 && sorted.length <= 1) {
        osSummary = osList[0];
    } else if (sorted.length > 0) {
        osSummary = `${sorted.length} ${deviceWord(sorted.length, lang)} ${osList.join('+')}`;
    }

    return {
        online: onlineDevices.length > 0,
        deviceCount: sorted.length,
        onlineDeviceCount: onlineDevices.length,
        osList,
        osSummary,
        lastSeenAt: sorted[0]?.lastSeenAt || null,
    };
}

function attachClientStatsToUsers(users = [], devices = [], options = {}) {
    const byUser = new Map();
    devices.forEach((device) => {
        if (!device || !device.userId) return;
        if (!byUser.has(device.userId)) byUser.set(device.userId, []);
        byUser.get(device.userId).push(device);
    });

    return users.map((user) => {
        const userId = user.userId;
        const stats = buildClientStats(byUser.get(userId) || [], options);
        if (user && typeof user.toObject === 'function') {
            return { ...user.toObject(), clientStats: stats };
        }
        return { ...user, clientStats: stats };
    });
}

module.exports = {
    normalizeClientOs,
    buildClientStats,
    attachClientStatsToUsers,
};
