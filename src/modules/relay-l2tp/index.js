'use strict';

const manifest = require('./manifest.json');

let routesRegistered = false;

function validateHost(hostCapabilities, candidateManifest = manifest) {
    return candidateManifest;
}

function registerModels({ modelRegistry } = {}) {
    const models = {
        RelayL2tpState: require('./models/relayL2tpStateModel'),
        L2tpUser: require('./models/l2tpUserModel'),
        CascadeRouteGroup: require('./models/cascadeRouteGroupModel'),
        CascadeTopologyState: require('./models/cascadeTopologyStateModel'),
        L2tpOperation: require('./models/l2tpOperationModel'),
        TopologyOperation: require('./models/topologyOperationModel'),
        NodeOperationLock: require('./models/nodeOperationLockModel'),
    };

    if (modelRegistry) {
        for (const [modelName, modelConstructor] of Object.entries(models)) {
            modelRegistry.register(modelName, modelConstructor);
        }
    }

    return models;
}

function registerConfigFragments({ configFragmentRegistry }) {
    const { buildL2tpXrayFragment } = require('./services/l2tpXrayFragmentProvider');

    configFragmentRegistry.register(manifest.id, buildL2tpXrayFragment);
    return buildL2tpXrayFragment;
}

function registerRoutes(context) {
    if (routesRegistered) {
        throw new Error('registerRoutes has already been called');
    }
    if (!context || typeof context !== 'object') {
        throw new TypeError('registerRoutes context is required');
    }

    const {
        panelRouter,
        l2tpService,
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        loadPanelOverview,
        renderPage,
    } = context;
    if (!panelRouter || typeof panelRouter.use !== 'function') {
        throw new TypeError('registerRoutes requires panelRouter');
    }
    if (!l2tpService) {
        throw new TypeError('registerRoutes requires l2tpService');
    }
    if (typeof requireAuth !== 'function') {
        throw new TypeError('registerRoutes requires requireAuth');
    }
    if (typeof requireOnboarding !== 'function') {
        throw new TypeError('registerRoutes requires requireOnboarding');
    }
    if (typeof csrf !== 'function') {
        throw new TypeError('registerRoutes requires csrf');
    }
    if (typeof rateLimiter !== 'function') {
        throw new TypeError('registerRoutes requires rateLimiter');
    }
    if (typeof loadPanelOverview !== 'function') {
        throw new TypeError('registerRoutes requires loadPanelOverview');
    }
    if (typeof renderPage !== 'function') {
        throw new TypeError('registerRoutes requires renderPage');
    }

    routesRegistered = true;
    const { createL2tpRouter } = require('./routes/panel');
    const l2tpRouter = createL2tpRouter({
        l2tpService,
        requireAuth,
        requireOnboarding,
        csrf,
        rateLimiter,
        loadPanelOverview,
        renderPage,
    });

    panelRouter.use('/', l2tpRouter);
}

module.exports = {
    manifest,
    validateHost,
    registerModels,
    registerConfigFragments,
    registerRoutes,
};
