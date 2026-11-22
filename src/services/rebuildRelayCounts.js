'use strict';

const validCount = value => Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
function validCensus(value) {
    if (value == null || Object.keys(value).length !== 3
        || !['activeSessions', 'activeIpsec', 'census'].every(key => Object.hasOwn(value, key))) return false;
    const { activeSessions, activeIpsec, census } = value;
    if (validCount(activeSessions) && validCount(activeIpsec)) {
        return typeof census === 'string' && census.length === 64 && /^[0-9a-f]{64}$/.test(census);
    }
    return census === null && ((activeSessions === null && validCount(activeIpsec))
        || (activeIpsec === null && validCount(activeSessions)));
}

function validRetirementCensus(value) {
    if (!value || !Object.hasOwn(value, 'activeClients')) return false;
    const { activeClients, ...ordinary } = value;
    return validCensus(ordinary) && (activeClients === null
        // Same bound as RETIRE_MAX_CLIENTS in the DIRECT host helper.
        || (validCount(activeClients) && activeClients <= 32 && activeClients === ordinary.activeSessions
            && activeClients === ordinary.activeIpsec && !!ordinary.census));
}

async function readAccountCount(User, nodeId) {
    try {
        const result = await User.countDocuments({ relayNode: nodeId }).read('primary').readConcern('majority').maxTimeMS(5000);
        if (validCount(result)) return result;
    } catch { /* Unavailable, not zero. */ }
    return null;
}

// The caller must first establish the enrolled installed generation. Neither
// a user-row count nor an SSH refusal says anything about active PPP sessions.
async function readSessionCensus(remote, input, retirement = false) {
    const method = retirement && typeof remote?.readRetirementCount === 'function' ? 'readRetirementCount' : 'readSessionCount';
    if (typeof remote?.[method] !== 'function' || typeof remote.close !== 'function') return null;
    try {
        const reply = await remote[method](input);
        if (method === 'readRetirementCount' ? validRetirementCensus(reply) : validCensus(reply)) {
            const { activeSessions, activeIpsec, census } = reply;
            const activeClients = method === 'readRetirementCount' ? reply.activeClients
                : activeSessions === 0 && activeIpsec === 0 ? 0 : null;
            return Object.freeze({ activeSessions, activeIpsec, census, ...(retirement && { activeClients }) });
        }
    } catch (error) {
        if (error?.code === 'REBUILD_L2TP_IDENTITY_CHANGED') throw error;
        // Unavailable, not zero.
    }
    return null;
}

function formatRelayCounts({ accountCount, activeSessions, activeIpsec }, t) {
    const show = count => validCount(count) ? String(count) : t('nodes.rebuildCountUnavailable');
    return t('nodes.rebuildRelayCounts')
        .replace('{accounts}', show(accountCount))
        .replace('{sessions}', show(activeSessions))
        .replace('{ipsec}', show(activeIpsec));
}

module.exports = { readAccountCount, readSessionCensus, formatRelayCounts, validCensus, validRetirementCensus };
