'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const PANEL_PATH = require.resolve('..');
const PANEL_HOST_PATH = require.resolve('../../../modules/createL2tpPanelHost');
const L2TP_ROUTES_PATH = require.resolve('../../../modules/relay-l2tp/routes/panel');

test('panel mounts one late-bound L2TP router and delegates configure and preflight to the active host', () => {
    const result = spawnSync(process.execPath, ['--eval', `
        const assert = require('node:assert/strict');
        const express = require('express');
        let hostConstructions = 0;
        require.cache[${JSON.stringify(PANEL_HOST_PATH)}] = {
            id: ${JSON.stringify(PANEL_HOST_PATH)},
            filename: ${JSON.stringify(PANEL_HOST_PATH)},
            loaded: true,
            exports: {
                createL2tpPanelHost() {
                    hostConstructions += 1;
                    throw new Error('panel import must not construct an L2TP host');
                },
            },
        };

        const panelRouter = require(${JSON.stringify(PANEL_PATH)});
        const { createL2tpRouter } = require(${JSON.stringify(L2TP_ROUTES_PATH)});
        const { requireAuth, requireOnboarding, checkIpWhitelist } = require(${JSON.stringify(require.resolve('../helpers'))});
        const authRoutes = require(${JSON.stringify(require.resolve('../auth'))});
        const wizardRoutes = require(${JSON.stringify(require.resolve('../wizard'))});
        const nodesRoutes = require(${JSON.stringify(require.resolve('../nodes'))});
        const usersRoutes = require(${JSON.stringify(require.resolve('../users'))});
        const settingsRoutes = require(${JSON.stringify(require.resolve('../settings'))});
        const systemRoutes = require(${JSON.stringify(require.resolve('../system'))});
        const migrationRoutes = require(${JSON.stringify(require.resolve('../migration'))});
        const accessLogsRoutes = require(${JSON.stringify(require.resolve('../accessLogs'))});

        (async () => {
            assert.equal(hostConstructions, 0);
            const calls = [];
            let activeHost = null;
            let mountedL2tpRouter;
            const l2tpMarker = function l2tpMarker(req, res, next) { next(); };
            const rateLimiter = function rateLimiter(req, res, next) { next(); };
            const passThrough = (req, res, next) => next();
            const activeHostProvider = {
                getActiveHost() {
                    return activeHost;
                },
            };
            const moduleEntry = {
                registerRoutes(context) {
                    calls.push({ method: 'registerRoutes', context });
                    mountedL2tpRouter = createL2tpRouter({
                        ...context,
                        requireAuth: passThrough,
                        requireOnboarding: passThrough,
                        csrf: passThrough,
                        rateLimiter: passThrough,
                    });
                    context.panelRouter.use('/', l2tpMarker);
                },
            };

            const router = panelRouter.createPanelRouter({
                activeHostProvider,
                l2tpModuleEntry: moduleEntry,
                l2tpRateLimiter: rateLimiter,
                createL2tpHost() {
                    throw new Error('panel router must not construct a dormant host');
                },
            });

            assert.equal(hostConstructions, 0);
            assert.equal(calls.length, 1);
            assert.equal(calls[0].method, 'registerRoutes');
            assert.strictEqual(calls[0].context.panelRouter, router);
            assert.strictEqual(calls[0].context.requireAuth, requireAuth);
            assert.strictEqual(calls[0].context.requireOnboarding, requireOnboarding);
            assert.strictEqual(calls[0].context.rateLimiter, rateLimiter);
            assert.equal(typeof calls[0].context.userManagementService.createUser, 'function');

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

            const app = express();
            app.use(express.json());
            app.use(mountedL2tpRouter);
            const server = await new Promise(resolve => {
                const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
            });
            const request = async (path, body) => {
                const response = await fetch(
                    \`http://127.0.0.1:\${server.address().port}\${path}\`,
                    {
                        method: 'POST',
                        headers: { 'content-type': 'application/json' },
                        body: JSON.stringify(body),
                    },
                );
                return { status: response.status, body: await response.json() };
            };

            try {
                const unavailable = await request('/nodes/relay-a/l2tp/preflight', {});
                assert.equal(unavailable.status, 500);
                assert.deepEqual(unavailable.body, {
                    error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
                });

                activeHost = {
                    runtime: {
                        service: {
                            async preflight(nodeId, input) {
                                calls.push({ method: 'preflight', nodeId, input });
                                return { ok: true, source: 'active-host' };
                            },
                        },
                        stateManagementService: {
                            async configureRelay(nodeId, input) {
                                calls.push({ method: 'configureRelay', nodeId, input });
                                return {
                                    node: nodeId,
                                    desiredState: 'installed',
                                    status: 'not_installed',
                                    clientCidr: input.clientCidr,
                                };
                            },
                        },
                        userManagementService: {
                            async createUser(nodeId, input) {
                                calls.push({ method: 'createUser', nodeId, input });
                                return {
                                    id: 'user-a',
                                    relayNode: nodeId,
                                    login: input.login,
                                    ip: input.ip,
                                    enabled: input.enabled,
                                    password: input.password,
                                    passwordEncrypted: 'sealed-password',
                                };
                            },
                            async listUsers() { return []; },
                            async updateUser() {},
                            async disableUser() {},
                        },
                    },
                    async loadPanelOverview() {
                        return { source: 'active-host' };
                    },
                };

                const configured = await request('/nodes/relay-a/l2tp/configure', {
                    clientCidr: '10.77.0.0/24',
                    unexpected: 'drop-me',
                });
                assert.equal(configured.status, 200);
                assert.deepEqual(configured.body, {
                    node: 'relay-a',
                    desiredState: 'installed',
                    status: 'not_installed',
                    clientCidr: '10.77.0.0/24',
                });

                const preflight = await request('/nodes/relay-a/l2tp/preflight', {
                    routeGroupId: 'group-a',
                    unexpected: 'drop-me',
                });
                assert.equal(preflight.status, 200);
                assert.deepEqual(preflight.body, { ok: true, source: 'active-host' });

                const createdUser = await request('/nodes/relay-a/l2tp/users', {
                    login: 'alice',
                    ip: '10.77.0.10',
                    password: 'input-only-password',
                    enabled: true,
                    passwordEncrypted: 'attacker-ciphertext',
                });
                assert.equal(createdUser.status, 201);
                assert.deepEqual(createdUser.body, {
                    id: 'user-a',
                    relayNode: 'relay-a',
                    login: 'alice',
                    ip: '10.77.0.10',
                    enabled: true,
                });
                assert.doesNotMatch(JSON.stringify(createdUser.body), /password|sealed|ciphertext/i);
                assert.deepEqual(calls.slice(1).map(call => call.method), [
                    'configureRelay',
                    'preflight',
                    'createUser',
                ]);
                assert.deepEqual(calls[1], {
                    method: 'configureRelay',
                    nodeId: 'relay-a',
                    input: { clientCidr: '10.77.0.0/24' },
                });
                assert.deepEqual(calls[2], {
                    method: 'preflight',
                    nodeId: 'relay-a',
                    input: {
                        clientCidr: undefined,
                        dnsServers: undefined,
                        routeGroupId: 'group-a',
                        expectedTopologyRevision: undefined,
                    },
                });
                assert.deepEqual(calls[3], {
                    method: 'createUser',
                    nodeId: 'relay-a',
                    input: {
                        login: 'alice',
                        ip: '10.77.0.10',
                        password: 'input-only-password',
                        enabled: true,
                    },
                });
            } finally {
                await new Promise((resolve, reject) => {
                    server.close(error => (error ? reject(error) : resolve()));
                });
            }
        })().then(
            () => process.exit(0),
            error => {
                console.error(error);
                process.exit(1);
            },
        );
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
