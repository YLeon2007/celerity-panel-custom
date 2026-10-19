'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createL2tpRootLifecycle } = require('../l2tpRuntimeLifecycleHook');
const tick = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }

test('readiness is awaited with migrations disabled before runtime and HTTP acceptance boundary resolves', async () => {
    const ready = deferred(); const calls = [];
    const root = createL2tpRootLifecycle({ env: {},
        createMigrationBootstrap: () => ({ async run() { calls.push('migration-skipped'); } }),
        ensureModelIndexes: async () => { calls.push('indexes'); await ready.promise; },
        createRuntimeLifecycleHook: () => { calls.push('runtime'); return { async stop() {} }; },
    });
    let accepting = false;
    const start = root.startAfterDatabase().then(() => { accepting = true; });
    await tick();
    assert.deepEqual(calls, ['migration-skipped', 'indexes']);
    assert.equal(accepting, false);
    ready.resolve(); await start;
    assert.deepEqual(calls, ['migration-skipped', 'indexes', 'runtime']);
    assert.equal(accepting, true);
});

test('readiness rejects a missing or weaker persisted unique/sparse index even after createIndexes resolves', async () => {
    const { ensureL2tpModelIndexes } = require('../l2tpModelIndexReadiness');
    for (const actual of [[], [{ key: { operationId: 1 }, unique: false, sparse: true }],
        [{ key: { operationId: 1 }, unique: true }],
        [{ key: { operationId: 1 }, unique: true, sparse: true, partialFilterExpression: { status: 'waiting' } }]]) {
        const model = {
            async createCollection() {}, async createIndexes() {},
            schema: { indexes: () => [[{ operationId: 1 }, { unique: true, sparse: true }]] },
            collection: { async indexes() { return [{ key: { _id: 1 } }, ...actual]; } },
        };
        await assert.rejects(ensureL2tpModelIndexes({ loadModels: () => ({ TopologyCreateIntent: model }) }), /index readiness.*TopologyCreateIntent/);
    }
});

test('index build or metadata failure rejects the shared readiness promise before runtime publication', async () => {
    for (const error of [new Error('duplicate queue keys'), new Error('index readiness failed')]) {
        let runtimeStarts = 0;
        const root = createL2tpRootLifecycle({ env: {},
            createMigrationBootstrap: () => ({ async run() {} }),
            async ensureModelIndexes() { throw error; },
            createRuntimeLifecycleHook: () => { runtimeStarts++; },
        });
        const first = root.startAfterDatabase();
        assert.strictEqual(first, root.startAfterDatabase());
        await assert.rejects(first, e => e === error);
        assert.equal(runtimeStarts, 0);
        await root.stop();
    }
});

test('stop before database readiness permanently forbids subsequent startup', async () => {
    let initialization = 0;
    const root = createL2tpRootLifecycle({ env: {},
        createMigrationBootstrap: () => { initialization++; return { async run() {} }; },
        async ensureModelIndexes() { initialization++; },
        createRuntimeLifecycleHook: () => { initialization++; },
    });
    await root.stop(); await root.startAfterDatabase();
    assert.equal(initialization, 0);
});

test('stop during index initialization prevents any runtime from starting', async () => {
    const ready = deferred(); let starts = 0;
    const root = createL2tpRootLifecycle({ env: {},
        createMigrationBootstrap: () => ({ async run() {} }),
        ensureModelIndexes: () => ready.promise,
        createRuntimeLifecycleHook: () => { starts++; return { async stop() {} }; },
    });
    const start = root.startAfterDatabase(); await tick();
    const stop = root.stop(); ready.resolve();
    await Promise.all([start, stop]);
    assert.equal(starts, 0);
});
