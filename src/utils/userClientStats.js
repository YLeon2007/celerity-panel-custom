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

function toOnlineUserIdSet(value) {
    if (!value) return new Set();
    if (value instanceof Set) return value;
    if (Array.isArray(value)) return new Set(value.map(String));
    return new Set(Object.keys(value).filter(userId => value[userId]));
}

function isPositiveNumber(value) {
    const n = Number(value || 0);
    return Number.isFinite(n) && n > 0;
}

function isXrayUserOnline(stats = {}) {
    if (stats.online === true || stats.active === true || stats.isOnline === true) return true;
    if (isPositiveNumber(stats.tx) || isPositiveNumber(stats.rx)) return true;
    if (isPositiveNumber(stats.uplink) || isPositiveNumber(stats.downlink)) return true;
    if (isPositiveNumber(stats.upload) || isPositiveNumber(stats.download)) return true;
    return false;
}

function extractXrayOnlineUserIds(usersStats = {}) {
    return Object.entries(usersStats)
        .filter(([, stats]) => isXrayUserOnline(stats || {}))
        .map(([userId]) => userId);
}

function buildClientStats(devices = [], options = {}) {
    const lang = options.lang || 'ru';
    const onlineUserIds = toOnlineUserIdSet(options.onlineUserIds);
    const userId = options.userId ? String(options.userId) : '';

    const sorted = [...devices].sort((a, b) => new Date(b.lastSeenAt || 0) - new Date(a.lastSeenAt || 0));
    const osList = uniqPreserveOrder(sorted.map(normalizeClientOs));
    const online = userId ? onlineUserIds.has(userId) : false;

    let osSummary = '—';
    if (sorted.length > 0) {
        osSummary = `${sorted.length} ${deviceWord(sorted.length, lang)} ${osList.join('+')}`;
    }

    return {
        online,
        deviceCount: sorted.length,
        onlineDeviceCount: online ? 1 : 0,
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
        const stats = buildClientStats(byUser.get(userId) || [], { ...options, userId });
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
    extractXrayOnlineUserIds,
};
