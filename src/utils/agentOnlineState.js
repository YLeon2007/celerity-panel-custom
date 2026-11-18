function extractAgentOnlineUserIds(payload) {
    const users = payload?.users || {};
    return Object.entries(users)
        .filter(([, state]) => state && state.online === true)
        .map(([userId]) => String(userId))
        .filter(Boolean);
}

// Keep a recent sample through transient refusals, but polling must not
// extend its lifetime. Bound the grace by the agent's idle window.
const maxSampleAgeMs = 45_000;

function mergeNodeOnlineContributions(contributions, activeNodeKeys, now) {
    const active = new Set(Array.from(activeNodeKeys, String));
    const next = new Map();
    const userIds = new Set();
    for (const [nodeKey, sample] of contributions) {
        const key = String(nodeKey);
        const age = now - sample.observedAt;
        if (!active.has(key) || !Number.isFinite(age) || age < 0 || age >= maxSampleAgeMs) continue;
        next.set(key, sample);
        for (const id of sample.ids) if (id) userIds.add(String(id));
    }
    return { contributions: next, userIds };
}

module.exports = {
    extractAgentOnlineUserIds,
    mergeNodeOnlineContributions,
};
