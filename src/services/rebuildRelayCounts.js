'use strict';

const validCount = value => Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);

async function readAccountCount(User, nodeId) {
    try {
        const result = await User.countDocuments({ relayNode: nodeId }).read('primary').readConcern('majority').maxTimeMS(5000);
        if (validCount(result)) return result;
    } catch { /* Unavailable, not zero. */ }
    return null;
}

// The caller must first establish the enrolled installed generation. Neither
// a user-row count nor an SSH refusal says anything about active PPP sessions.
async function readSessionCensus(remote, input) {
    if (typeof remote?.readSessionCount !== 'function' || typeof remote.close !== 'function') return null;
    try {
        const { activeSessions, census } = await remote.readSessionCount(input);
        if (validCount(activeSessions) && typeof census === 'string' && census.length === 64 && /^[0-9a-f]{64}$/.test(census)) {
            return Object.freeze({ activeSessions, census });
        }
    } catch { /* Unavailable, not zero. */ }
    return null;
}

function formatRelayCounts({ accountCount, activeSessions }, t) {
    const show = count => validCount(count) ? String(count) : t('nodes.rebuildCountUnavailable');
    return t('nodes.rebuildRelayCounts')
        .replace('{accounts}', show(accountCount))
        .replace('{sessions}', show(activeSessions));
}

module.exports = { readAccountCount, readSessionCensus, formatRelayCounts };
