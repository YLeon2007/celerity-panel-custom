'use strict';

const { randomBytes, timingSafeEqual } = require('node:crypto');

const SESSION_TOKEN_KEY = 'panelCsrfToken';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function csrfError(code, message) {
    const error = new Error(message);
    error.code = code;
    error.statusCode = 403;
    return error;
}

function issuePanelCsrfToken(req) {
    if (!req.session?.authenticated) {
        throw csrfError('CSRF_AUTH_REQUIRED', 'Authenticated panel session required');
    }

    if (!req.session[SESSION_TOKEN_KEY]) {
        req.session[SESSION_TOKEN_KEY] = randomBytes(32).toString('base64url');
    }

    return req.session[SESSION_TOKEN_KEY];
}

function rejectCsrf(res, code) {
    return res.status(403).json({
        error: 'CSRF validation failed',
        code,
    });
}

function originMatchesHost(req) {
    const origin = req.headers?.origin;
    if (origin === undefined) return true;

    const host = req.headers?.host;
    if (typeof origin !== 'string' || typeof host !== 'string') return false;

    try {
        const parsedOrigin = new URL(origin);
        const hostMatches = parsedOrigin.host.toLowerCase() === host.toLowerCase();
        const protocolMatches = typeof req.protocol !== 'string'
            || parsedOrigin.protocol === `${req.protocol.toLowerCase()}:`;
        return hostMatches && protocolMatches;
    } catch {
        return false;
    }
}

function requirePanelCsrf(req, res, next) {
    if (SAFE_METHODS.has(String(req.method || '').toUpperCase())) {
        return next();
    }

    if (!req.session?.authenticated) {
        return rejectCsrf(res, 'CSRF_AUTH_REQUIRED');
    }

    if (!originMatchesHost(req)) {
        return rejectCsrf(res, 'CSRF_ORIGIN_INVALID');
    }

    const submittedToken = req.headers?.['x-csrf-token'] || req.body?._csrf;
    const storedToken = req.session[SESSION_TOKEN_KEY];

    if (
        typeof storedToken === 'string'
        && storedToken.length > 0
        && typeof submittedToken === 'string'
        && submittedToken.length === storedToken.length
        && timingSafeEqual(Buffer.from(submittedToken), Buffer.from(storedToken))
    ) {
        return next();
    }

    return rejectCsrf(res, 'CSRF_TOKEN_INVALID');
}

module.exports = {
    issuePanelCsrfToken,
    requirePanelCsrf,
};
