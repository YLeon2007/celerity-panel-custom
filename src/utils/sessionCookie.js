function parseSessionCookieSecure(value) {
    if (value === undefined || value === null || value === '') {
        return true;
    }

    const normalized = String(value).trim().toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;

    throw new Error('SESSION_COOKIE_SECURE must be "true" or "false"');
}

function buildSessionCookieOptions(env = process.env) {
    return {
        secure: parseSessionCookieSecure(env.SESSION_COOKIE_SECURE),
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
    };
}

module.exports = {
    buildSessionCookieOptions,
    parseSessionCookieSecure,
};
