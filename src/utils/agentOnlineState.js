function extractAgentOnlineUserIds(payload) {
    const users = payload?.users || {};
    return Object.entries(users)
        .filter(([, state]) => state && state.online === true)
        .map(([userId]) => String(userId))
        .filter(Boolean);
}

module.exports = {
    extractAgentOnlineUserIds,
};
