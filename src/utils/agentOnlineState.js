function extractAgentOnlineUserIds(payload) {
    const users = payload?.users || {};
    return Object.entries(users)
        .filter(([, state]) => state && state.online === true)
        .map(([userId]) => String(userId))
        .filter(Boolean);
}

function mergeNodeOnlineContributions(contributions, activeNodeKeys = []) {
    const active = new Set((activeNodeKeys || []).map(String));
    const next = new Map();

    for (const [nodeKey, ids] of contributions.entries()) {
        const key = String(nodeKey);
        if (!active.has(key)) continue;
        next.set(key, new Set([...(ids || [])].map(String).filter(Boolean)));
    }

    const userIds = new Set();
    for (const ids of next.values()) {
        ids.forEach(userId => userIds.add(userId));
    }

    return { contributions: next, userIds };
}

module.exports = {
    extractAgentOnlineUserIds,
    mergeNodeOnlineContributions,
};
