'use strict';
process.env.PANEL_DOMAIN ||= 'panel.test.invalid';
process.env.ACME_EMAIL ||= 'admin@test.invalid';
process.env.ENCRYPTION_KEY ||= 'test-encryption-key-32-characters-long';
process.env.SESSION_SECRET ||= 'test-session-secret';
const assert = require('node:assert/strict');
const test = require('node:test');
const moduleApi = require('..');
const native = require('../runtime/createTopologyOperationRuntime');
const env = () => ({ PANEL_DOMAIN: 'lm1.infograd.online',
    L2TP_EXECUTION_ENABLED: 'true', L2TP_MIGRATIONS_ENABLED: 'true',
    L2TP_PRODUCTION_EXECUTION_ENABLED: 'true',
    CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true',
    CLASSIC_TOPOLOGY_PRODUCTION_LINK_IDS: '6ae13ae24bc4b4e3e44e65c6',
    TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'false', TOPOLOGY_TEST_EXECUTION_ENABLED: 'false' });

test('classic PROD selection requires exact canonical identity and every explicit flag', () => {
    assert.equal(moduleApi.isClassicProductionDeploymentEnabled(env()), true);
    for (const key of Object.keys(env())) {
        for (const value of [undefined, '', 'TRUE', true, 'garbage']) {
            const candidate = { ...env(), [key]: value };
            assert.equal(moduleApi.isClassicProductionDeploymentEnabled(candidate), false, `${key}:${value}`);
        }
    }
    assert.equal(moduleApi.isClassicProductionDeploymentEnabled({ ...env(), PANEL_DOMAIN: 'lm2.infograd.online' }), false);
});

test('explicit classic mode assembles scoped service without constructing native runtime', t => {
    t.mock.method(native, 'createTopologyOperationRuntime', () => { throw new Error('native constructed'); });
    const service = moduleApi.createTopologyDeploymentService({ env: env() });
    assert.equal(typeof service.queue, 'function');
    assert.equal(typeof service.deploy, 'function');
});

test('native enabled or incomplete mode never falls back to classic, including native factory throw', t => {
    const sentinel = {};
    const factory = t.mock.method(native, 'createTopologyOperationRuntime', () => sentinel);
    for (const candidate of [{ ...env(), TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' },
        { ...env(), TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' },
        { ...env(), TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: undefined }]) {
        assert.equal(moduleApi.createTopologyDeploymentService({ env: candidate }), sentinel);
    }
    factory.mock.mockImplementation(() => { throw new Error('native incomplete'); });
    assert.throws(() => moduleApi.createTopologyDeploymentService({ env: {
        ...env(), TOPOLOGY_PRODUCTION_EXECUTION_ENABLED: 'true' } }), /native incomplete/);
});
