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

function hasNonEmptyCollection(value) {
    if (Array.isArray(value)) return value.length > 0;
    if (value && typeof value === 'object') return Object.keys(value).length > 0;
    return false;
}

function xrayTrafficTotal(stats = {}) {
    return ['tx', 'rx', 'uplink', 'downlink', 'upload', 'download']
        .reduce((sum, key) => sum + Number(stats[key] || 0), 0);
}

function isTrafficGrowing(stats = {}, previousStats = null) {
    const current = xrayTrafficTotal(stats);
    if (!isPositiveNumber(current)) return false;
    if (!previousStats) return false;
    return current > xrayTrafficTotal(previousStats);
}

function isXrayUserOnline(stats = {}, options = {}) {
    const previousStats = options.previousStats || null;
    const requireTrafficChange = options.requireTrafficChange === true;

    // Prefer explicit live signals when future/current agents provide them.
    if (stats.online === true || stats.active === true || stats.isOnline === true) return true;
    if (stats.connected === true || stats.isConnected === true || stats.hasConnection === true) return true;
    if (isPositiveNumber(stats.connections) || isPositiveNumber(stats.connectionCount)) return true;
    if (isPositiveNumber(stats.onlineConnections) || isPositiveNumber(stats.sessionCount)) return true;
    if (hasNonEmptyCollection(stats.sessions) || hasNonEmptyCollection(stats.connectionsList)) return true;
    if (hasNonEmptyCollection(stats.connectionIds) || hasNonEmptyCollection(stats.clientIps)) return true;

    // Current cc-agent builds may expose only per-user traffic counters. On prod
    // those counters can remain present after disconnect, so the sync job passes
    // requireTrafficChange=true and a previous snapshot: online only if the
    // counter grows between polls. Unit callers can still treat one positive
    // traffic sample as online by leaving requireTrafficChange=false.
    if (requireTrafficChange) return isTrafficGrowing(stats, previousStats);
    return isPositiveNumber(xrayTrafficTotal(stats));
}

function extractXrayOnlineUserIds(usersStats = {}, options = {}) {
    const previousUsersStats = options.previousUsersStats || {};
    return Object.entries(usersStats)
        .filter(([userId, stats]) => isXrayUserOnline(stats || {}, {
            ...options,
            previousStats: previousUsersStats[userId] || null,
        }))
        .map(([userId]) => userId);
}

function buildClientStats(devices = [], options = {}) {
    const lang = options.lang || 'ru';
    const onlineUserIds = toOnlineUserIdSet(options.onlineUserIds);
    const userId = options.userId ? String(options.userId) : '';

    const sorted = [...devices].sort((a, b) => new Date(b.lastSeenAt || 0) - new Date(a.lastSeenAt || 0));
    const osList = uniqPreserveOrder(sorted.map(normalizeClientOs));
    const freshDeviceOnlineMs = Number(options.freshDeviceOnlineMs || 0);
    const nowMs = options.now ? new Date(options.now).getTime() : Date.now();
    const hasFreshDeviceHeartbeat = freshDeviceOnlineMs > 0 && sorted.some((device) => {
        const lastSeenMs = new Date(device.lastSeenAt || 0).getTime();
        return Number.isFinite(lastSeenMs) && nowMs - lastSeenMs <= freshDeviceOnlineMs;
    });
    const online = userId ? (onlineUserIds.has(userId) || hasFreshDeviceHeartbeat) : false;

    let osSummary = `0 ${deviceWord(0, lang)} unknown`;
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
