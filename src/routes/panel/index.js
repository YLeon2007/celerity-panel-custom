/**
 * Panel routes aggregator.
 * Mounts sub-routers for auth, nodes, users, settings, system, and modules.
 */

const express = require('express');
const rateLimit = require('express-rate-limit');

const l2tpModuleEntry = require('../../modules/relay-l2tp');
const {
    createL2tpRouteBindings,
    l2tpActiveHostProvider,
} = require('../../modules/l2tpActiveHostProvider');
const { checkIpWhitelist, requireAuth, requireOnboarding, render } = require('./helpers');
const { issuePanelCsrfToken, requirePanelCsrf } = require('./csrf');

const authRoutes = require('./auth');
const wizardRoutes = require('./wizard');
const nodesRoutes = require('./nodes');
const usersRoutes = require('./users');
const settingsRoutes = require('./settings');
const systemRoutes = require('./system');
const migrationRoutes = require('./migration');
const accessLogsRoutes = require('./accessLogs');

const l2tpRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
});

function exposePanelCsrfToken(req, res, next) {
    if (req.session?.authenticated) {
        res.locals.csrfToken = issuePanelCsrfToken(req);
    }
    next();
}

function renderL2tpPage(res, data) {
    return render(res, 'l2tp', data);
}

function createPanelRouter({
    activeHostProvider = l2tpActiveHostProvider,
    l2tpModuleEntry: injectedL2tpModuleEntry = l2tpModuleEntry,
    l2tpRateLimiter: injectedL2tpRateLimiter = l2tpRateLimiter,
    renderL2tpPage: injectedRenderL2tpPage = renderL2tpPage,
} = {}) {
    const router = express.Router();

    // IP whitelist applies to all panel routes
    router.use(checkIpWhitelist);

    // Auth routes are public (login, setup, totp, logout)
    router.use('/', authRoutes);

    // Authenticated templates and scripts can submit the session-bound CSRF token.
    router.use('/', exposePanelCsrfToken);

    // Wizard routes require auth but bypass requireOnboarding (they ARE the onboarding)
    router.use('/', requireAuth, wizardRoutes);

    // All other routes require authentication and completed onboarding
    router.use('/', requireAuth, requireOnboarding, nodesRoutes);
    router.use('/', requireAuth, requireOnboarding, usersRoutes);
    router.use('/', requireAuth, requireOnboarding, settingsRoutes);
    router.use('/', requireAuth, requireOnboarding, systemRoutes);
    router.use('/', requireAuth, requireOnboarding, migrationRoutes);
    router.use('/', requireAuth, requireOnboarding, accessLogsRoutes);

    const routeBindings = createL2tpRouteBindings(activeHostProvider);
    injectedL2tpModuleEntry.registerRoutes({
        panelRouter: router,
        l2tpService: routeBindings.l2tpService,
        stateManagementService: routeBindings.stateManagementService,
        userManagementService: routeBindings.userManagementService,
        requireAuth,
        requireOnboarding,
        csrf: requirePanelCsrf,
        rateLimiter: injectedL2tpRateLimiter,
        loadPanelOverview: routeBindings.loadPanelOverview,
        renderPage: injectedRenderL2tpPage,
    });

    return router;
}

const router = createPanelRouter();
Object.defineProperties(router, {
    createPanelRouter: { value: createPanelRouter },
    exposePanelCsrfToken: { value: exposePanelCsrfToken },
    l2tpRateLimiter: { value: l2tpRateLimiter },
    renderL2tpPage: { value: renderL2tpPage },
});

module.exports = router;
