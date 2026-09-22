'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const PANEL_PATH = require.resolve('..');

test('panel aggregator preserves existing routes and registers the L2TP runtime service', () => {
    const result = spawnSync(process.execPath, ['--eval', `
        const assert = require('node:assert/strict');
        const panelRouter = require(${JSON.stringify(PANEL_PATH)});
        const { requireAuth, requireOnboarding, checkIpWhitelist } = require(${JSON.stringify(require.resolve('../helpers'))});
        const authRoutes = require(${JSON.stringify(require.resolve('../auth'))});
        const wizardRoutes = require(${JSON.stringify(require.resolve('../wizard'))});
        const nodesRoutes = require(${JSON.stringify(require.resolve('../nodes'))});
        const usersRoutes = require(${JSON.stringify(require.resolve('../users'))});
        const settingsRoutes = require(${JSON.stringify(require.resolve('../settings'))});
        const systemRoutes = require(${JSON.stringify(require.resolve('../system'))});
        const migrationRoutes = require(${JSON.stringify(require.resolve('../migration'))});
        const accessLogsRoutes = require(${JSON.stringify(require.resolve('../accessLogs'))});
        const { requirePanelCsrf } = require(${JSON.stringify(require.resolve('../csrf'))});

        const calls = [];
        const l2tpService = { kind: 'l2tp-service' };
        const l2tpMarker = function l2tpMarker(req, res, next) { next(); };
        const rateLimiter = function rateLimiter(req, res, next) { next(); };
        const moduleEntry = {
            registerRoutes(context) {
                calls.push({ method: 'registerRoutes', context });
                context.panelRouter.use('/', l2tpMarker);
            },
        };
        const runtime = Object.create(null, {
            service: { value: l2tpService, enumerable: true },
            worker: {
                get() {
                    throw new Error('panel mount must not access or start the worker');
                },
            },
        });

        const router = panelRouter.createPanelRouter({
            l2tpRateLimiter: rateLimiter,
            createL2tpHost(dependencies) {
                calls.push({ method: 'createL2tpHost', dependencies });
                return { moduleEntry, runtime };
            },
        });

        assert.equal(calls.length, 2);
        assert.deepEqual(calls[0], {
            method: 'createL2tpHost',
            dependencies: {
                requireAuth,
                csrf: requirePanelCsrf,
                rateLimiter,
            },
        });
        assert.equal(calls[1].method, 'registerRoutes');
        assert.strictEqual(calls[1].context.panelRouter, router);
        assert.strictEqual(calls[1].context.l2tpService, l2tpService);
        assert.strictEqual(calls[1].context.requireAuth, requireAuth);
        assert.strictEqual(calls[1].context.csrf, requirePanelCsrf);
        assert.strictEqual(calls[1].context.rateLimiter, rateLimiter);

        assert.deepEqual(router.stack.map(layer => layer.handle), [
            checkIpWhitelist,
            authRoutes,
            panelRouter.exposePanelCsrfToken,
            requireAuth,
            wizardRoutes,
            requireAuth,
            requireOnboarding,
            nodesRoutes,
            requireAuth,
            requireOnboarding,
            usersRoutes,
            requireAuth,
            requireOnboarding,
            settingsRoutes,
            requireAuth,
            requireOnboarding,
            systemRoutes,
            requireAuth,
            requireOnboarding,
            migrationRoutes,
            requireAuth,
            requireOnboarding,
            accessLogsRoutes,
            l2tpMarker,
        ]);
        process.exit(0);
    `], {
        encoding: 'utf8',
        timeout: 5_000,
    });

    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, result.stderr);
});

test('authenticated panel requests receive a reusable CSRF token in response locals', () => {
    const result = spawnSync(process.execPath, ['--eval', `
        const assert = require('node:assert/strict');
        const panelRouter = require(${JSON.stringify(PANEL_PATH)});
        const request = { session: { authenticated: true } };
        const response = { locals: {} };
        let nextCalls = 0;

        panelRouter.exposePanelCsrfToken(request, response, () => {
            nextCalls += 1;
        });
        const firstToken = response.locals.csrfToken;
        panelRouter.exposePanelCsrfToken(request, response, () => {
            nextCalls += 1;
        });

        assert.equal(nextCalls, 2);
        assert.equal(typeof firstToken, 'string');
        assert.match(firstToken, /^[A-Za-z0-9_-]{43}$/);
        assert.equal(request.session.panelCsrfToken, firstToken);
        assert.equal(response.locals.csrfToken, firstToken);
        process.exit(0);
    `], {
        encoding: 'utf8',
        timeout: 5_000,
    });

    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, result.stderr);
});
