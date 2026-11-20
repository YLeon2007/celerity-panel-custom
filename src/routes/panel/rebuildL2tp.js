'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const { requireAuth, render } = require('./helpers');
const { requirePanelCsrf } = require('./csrf');

const pagePath = /^\/l2tp$/;
const accountPath = /^\/rebuild\/relays\/l2tp\/accounts\/reveal$/;
// No Express parameter capture: validate the raw segment, without URL decoding.
const pskPath = /^\/rebuild\/relays\/[^/]+\/l2tp\/psk\/reveal$/;
const loginPattern = /^[A-Za-z0-9._@-]{1,64}(?![\s\S])/;
const idPattern = /^[a-f0-9]{24}(?![\s\S])/;
const jsonString = String.raw`"(?:[^"\\]|\\.)*"`;
const accountJson = new RegExp(String.raw`^\s*\{\s*${jsonString}\s*:\s*${jsonString}\s*\}\s*$`);
const pskJson = /^\s*\{\s*\}\s*$/;

function noStore(_req, res, next) {
    res.set('Cache-Control', 'no-store');
    next();
}

function revealError(res, status, code) {
    return res.status(status).json({ error: { code } });
}

function unavailable(res) {
    return revealError(res, 503, 'REBUILD_L2TP_REVEAL_UNAVAILABLE');
}

function invalidRequest(res) {
    return revealError(res, 400, 'REBUILD_L2TP_REVEAL_INVALID_REQUEST');
}

// Mount at app level before CORS and the general parsers. The panel router
// cannot mark or sanitize requests that those earlier middlewares terminate.
const parseRevealJson = express.json({
    limit: '1kb',
    inflate: false,
    verify(req, _res, bytes) {
        // Verify the wire shape before JSON.parse can discard duplicate keys.
        const pattern = accountPath.test(req.path.slice('/panel'.length)) ? accountJson : pskJson;
        if (!pattern.test(bytes.toString('utf8'))) throw new Error('Invalid reveal request');
    },
});

function revealIngress(req, res, next) {
    if (!/^\/panel\//i.test(req.path)) return next();
    const path = req.path.slice('/panel'.length);
    if (!accountPath.test(path) && !pskPath.test(path)) return next();
    res.set('Cache-Control', 'no-store');
    if (req.method !== 'POST') return next();
    if (req.url.includes('?') || !req.is('application/json') || req.get('content-length') === '0') return invalidRequest(res);
    return parseRevealJson(req, res, err => err ? invalidRequest(res) : next());
}

function renderPage(res, model) {
    const t = res.locals.t;
    const title = t?.('rebuildL2tp.title');
    return render(res, 'rebuild-l2tp', { title: title && title !== 'rebuildL2tp.title' ? title : 'L2TP', page: 'l2tp', ...model });
}

function sendLoadError(res) {
    res.status(503);
    try {
        return renderPage(res, { loadError: true, relays: [], accounts: [], canManageAccounts: false });
    } catch {
        return res.type('text/plain').send(res.locals.t?.('dashboard.loadError') || 'Loading error');
    }
}

// The shared legacy onboarding middleware allows requests through on a failed
// Settings read. Neither this page nor secret access can use that fallback.
function requireCompletedOnboarding(onUnavailable) {
    return async (_req, res, next) => {
        let settings;
        try {
            const Settings = require('../../models/settingsModel');
            settings = await Settings.findById('settings').select('deployment.completed').lean();
        } catch {
            return onUnavailable(res);
        }
        if (settings?.deployment?.completed !== true) return res.redirect('/panel/wizard');
        next();
    };
}

function requireSessionId(req, res, next) {
    if (req.session?.authenticated !== true || typeof req.sessionID !== 'string' || !req.sessionID) {
        return revealError(res, 403, 'REBUILD_L2TP_SESSION_REQUIRED');
    }
    next();
}

function checkCsrf(req, res, next) {
    // This API only accepts the header. Reject non-ASCII before the shared
    // comparison, which expects string length and byte length to agree.
    const token = req.get('x-csrf-token');
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}(?![\s\S])/.test(token)) {
        return res.status(403).json({ error: 'CSRF validation failed', code: 'CSRF_TOKEN_INVALID' });
    }
    return requirePanelCsrf(req, res, next);
}

function revealInput(isAccount) {
    return (req, res, next) => {
        const body = req.body;
        const identifier = isAccount ? body?.login : req.path.split('/')[3];
        const keys = body && Object.getPrototypeOf(body) === Object.prototype ? Object.keys(body) : null;
        if (req.url.includes('?') || !req.is('application/json') || req.get('content-length') === '0' || !keys
            || (isAccount ? keys.length !== 1 || keys[0] !== 'login' || typeof identifier !== 'string' || !loginPattern.test(identifier)
                : keys.length !== 0 || !idPattern.test(identifier))) {
            return invalidRequest(res);
        }
        res.locals.rebuildL2tpIdentifier = identifier;
        next();
    };
}

function mountNoStore(router) {
    router.all([accountPath, pskPath], noStore);
    router.get(pagePath, (req, res, next) => req.method === 'GET' ? noStore(req, res, next) : next());
}

function mountOverview(router, getOverview, exposePanelCsrfToken) {
    router.get(pagePath, (req, _res, next) => req.method === 'GET' ? next() : next('route'),
        requireAuth, exposePanelCsrfToken, requireCompletedOnboarding(sendLoadError), async (_req, res) => {
            try {
                return renderPage(res, await getOverview().overview());
            } catch {
                return sendLoadError(res);
            }
        });
}

function mountReveals(router, getOverview) {
    const revealLimiter = rateLimit({
        windowMs: 60 * 1000,
        max: 10,
        keyGenerator: req => req.sessionID,
        standardHeaders: true,
        legacyHeaders: false,
        handler: (_req, res) => revealError(res, 429, 'REBUILD_L2TP_REVEAL_RATE_LIMITED'),
    });
    const onboarded = requireCompletedOnboarding(unavailable);
    for (const [path, method, isAccount] of [[accountPath, 'revealPassword', true], [pskPath, 'revealPsk', false]]) {
        router.post(path, requireAuth, requireSessionId, checkCsrf, revealInput(isAccount), revealLimiter, onboarded,
            async (_req, res) => {
                let secret;
                try {
                    secret = await getOverview()[method](res.locals.rebuildL2tpIdentifier);
                } catch {
                    return unavailable(res);
                }
                if (secret === null) return revealError(res, 404, 'REBUILD_L2TP_SECRET_NOT_FOUND');
                if (typeof secret !== 'string' || !secret) return unavailable(res);
                // Avoid generating an ETag from a secret response.
                return res.type('application/json').end(JSON.stringify({ secret }));
            });
        router.all(path, (_req, res) => revealError(res.set('Allow', 'POST'), 405, 'METHOD_NOT_ALLOWED'));
        router.all(path, (_err, _req, res, _next) => unavailable(res));
    }
}

function createRoutes(service) {
    // No service import, construction or query at startup or on a refused request.
    const getOverview = () => service ??= require('../../services/rebuildL2tpOverview').createRebuildL2tpOverview();
    return {
        mountNoStore,
        mountOverview: (router, exposePanelCsrfToken) => mountOverview(router, getOverview, exposePanelCsrfToken),
        mountReveals: router => mountReveals(router, getOverview),
    };
}

module.exports = { createRoutes, revealIngress };
