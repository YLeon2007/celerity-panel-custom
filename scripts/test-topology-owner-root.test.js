'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createL2tpRootLifecycle, createL2tpRuntimeLifecycleHook } = require('../src/modules/l2tpRuntimeLifecycleHook');
const env = { PANEL_DOMAIN: 'test.infograd.online', L2TP_EXECUTION_ENABLED: 'true',
    L2TP_MIGRATIONS_ENABLED: 'true', TOPOLOGY_TEST_EXECUTION_ENABLED: 'true' };
test('explicit root owner entry composes without schema writes or worker start and joins stop', async () => {
    const calls = [];
    const root = createL2tpRootLifecycle({ env,
        createMigrationBootstrap() { assert.fail('owner enrollment cannot run automatic migration'); },
        ensureModelIndexes() { assert.fail('owner enrollment cannot install indexes'); },
        createRuntimeLifecycleHook(options) {
            assert.equal(options.startWorkers, false);
            calls.push('compose');
            return { async enrollTestOwners() { calls.push('enroll'); return 17; }, async stop() { calls.push('stop'); } };
        },
    });
    assert.equal(typeof root.enrollTestOwnersAfterDatabase, 'function', 'explicit root owner entry absent');
    assert.deepEqual(calls, []);
    assert.equal(await root.enrollTestOwnersAfterDatabase(), 17);
    await assert.rejects(root.startAfterDatabase(), /TEST_OWNER_STARTUP_MODE_CONFLICT/);
    await root.stop(); assert.deepEqual(calls, ['compose', 'enroll', 'stop']);
});
test('maintenance hook must not call lifecycle.start but keeps authority close on stop', async () => {
    const calls = [];
    const lifecycle = createL2tpRuntimeLifecycleHook({ env, startWorkers: false,
        createHostDependencies: () => ({ createCandidateService() {}, createPreflightRunner() {},
            createUserSnapshotResolver() {}, createUserSyncReconciler() {},
            topologyExecutionAuthority: { close() { calls.push('close'); } } }),
        createStartupLifecycle: () => ({ start() { calls.push('start'); }, async stop() { calls.push('stop'); }, async enrollTestOwners() { return 19; } }),
    });
    assert.deepEqual(calls, []); assert.equal(await lifecycle.enrollTestOwners(), 19);
    await lifecycle.stop(); assert.deepEqual(calls, ['stop', 'close']);
});
