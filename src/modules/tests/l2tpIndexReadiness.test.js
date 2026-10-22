'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createL2tpRootLifecycle } = require('../l2tpRuntimeLifecycleHook');
const tick = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }

// Deferred Mongo model APIs expose ordering without database or wall-clock races.
function controlledModel(name, calls) {
    const stages = { collection: deferred(), build: deferred(), readback: deferred() };
    const actual = [{ key: { _id: 1 } }, { key: { operationId: 1 }, unique: true, sparse: true }];
    return {
        stages, actual,
        model: {
            async createCollection() { calls.push(`${name}:collection`); await stages.collection.promise; },
            async createIndexes() { calls.push(`${name}:build`); await stages.build.promise; },
            schema: { indexes: () => [[{ operationId: 1 }, { unique: true, sparse: true }]] },
            collection: { async indexes() { calls.push(`${name}:readback`); await stages.readback.promise; return actual; } },
        },
        release() { for (const stage of Object.values(stages)) stage.resolve(); },
    };
}

test('readiness runs at most two complete ordered model pipelines and awaits the final readback', async () => {
    const { ensureL2tpModelIndexes } = require('../l2tpModelIndexReadiness');
    const calls = [];
    const controls = Array.from({ length: 5 }, (_, i) => controlledModel(`Model${i}`, calls));
    const models = Object.fromEntries(controls.map((control, i) => [`Model${i}`, control.model]));
    let settled = false;
    const start = ensureL2tpModelIndexes({ loadModels: () => models }).finally(() => { settled = true; });
    const expected = [];
    try {
        for (let offset = 0; offset < controls.length; offset += 2) {
            const batch = controls.slice(offset, offset + 2);
            expected.push(...batch.map((_, i) => `Model${offset + i}:collection`));
            await tick();
            assert.deepEqual(calls, expected, 'exactly this batch may enter createCollection');
            assert.equal(settled, false);
            for (const [i, control] of batch.entries()) {
                control.stages.collection.resolve(); await tick();
                expected.push(`Model${offset + i}:build`);
                assert.deepEqual(calls, expected, 'build must wait for its own collection');
                control.stages.build.resolve(); await tick();
                expected.push(`Model${offset + i}:readback`);
                assert.deepEqual(calls, expected, 'readback must wait for its own build');
                assert.equal(settled, false, 'readiness cannot publish before exact metadata readback');
                control.stages.readback.resolve(); await tick();
                if (i < batch.length - 1) {
                    assert.deepEqual(calls, expected, 'no later batch while a sibling remains in flight');
                    assert.equal(settled, false);
                }
            }
        }
        await start;
        assert.equal(settled, true);
        assert.deepEqual(calls, expected);
    } finally {
        controls.forEach(control => control.release());
        await start.catch(() => {});
    }
});

test('failed readiness drains both admitted pipelines before rejecting or stopping and admits no later models', async t => {
    const { ensureL2tpModelIndexes } = require('../l2tpModelIndexReadiness');
    for (const stage of ['collection', 'build', 'readback']) {
        for (const failedIndex of [0, 1]) {
            await t.test(`${stage} failure in pipeline ${failedIndex}`, async () => {
                const calls = [];
                const controls = Array.from({ length: 4 }, (_, i) => controlledModel(`Model${i}`, calls));
                const error = new Error(`${stage} failed`);
                const failed = controls[failedIndex];
                const sibling = controls[1 - failedIndex];
                let runtimeStarts = 0, settled = false, stopped = false;
                const root = createL2tpRootLifecycle({ env: { L2TP_EXECUTION_ENABLED: 'false', L2TP_MIGRATIONS_ENABLED: 'false' },
                    createMigrationBootstrap: () => ({ async run() {} }),
                    ensureModelIndexes: () => ensureL2tpModelIndexes({
                        loadModels: () => Object.fromEntries(controls.map((control, i) => [`Model${i}`, control.model])),
                    }),
                    createRuntimeLifecycleHook: () => { runtimeStarts++; return { async stop() {} }; },
                });
                const start = root.startAfterDatabase();
                assert.strictEqual(start, root.startAfterDatabase());
                const observed = start.then(() => { settled = true; }, () => { settled = true; });
                const rejected = assert.rejects(start, e => e === error);
                let stop;
                try {
                    await tick();
                    assert.deepEqual([...calls], ['Model0:collection', 'Model1:collection']);
                    for (const [name, gate] of Object.entries(failed.stages)) {
                        if (name === stage) { gate.reject(error); break; }
                        gate.resolve(); await tick();
                    }
                    await tick();
                    stop = root.stop().then(() => { stopped = true; });
                    await tick();
                    assert.equal(settled, false, 'startup must drain the sibling before rejecting');
                    assert.equal(stopped, false, 'shutdown must join in-flight readiness');
                    for (const [name, gate] of Object.entries(sibling.stages)) {
                        if (name === 'readback') break;
                        gate.resolve(); await tick();
                        assert.equal(settled, false);
                        assert.equal(stopped, false);
                        assert.ok(calls.every(call => !/^Model[23]:/.test(call)), 'no later batch after failure');
                    }
                    sibling.stages.readback.resolve();
                    await Promise.all([rejected, observed, stop]);
                    assert.equal(settled, true);
                    assert.equal(stopped, true);
                    assert.equal(runtimeStarts, 0);
                    assert.ok(calls.every(call => !/^Model[23]:/.test(call)));
                    const stageNames = ['collection', 'build', 'readback'];
                    assert.deepEqual(calls.filter(call => call.startsWith(`Model${failedIndex}:`)),
                        stageNames.slice(0, stageNames.indexOf(stage) + 1).map(name => `Model${failedIndex}:${name}`));
                    assert.deepEqual(calls.filter(call => call.startsWith(`Model${1 - failedIndex}:`)),
                        stageNames.map(name => `Model${1 - failedIndex}:${name}`));
                } finally {
                    controls.forEach(control => control.release());
                    await Promise.all([rejected, observed, stop]);
                }
            });
        }
    }
});

test('every existing metadata gate remains exact after concurrent builds', async t => {
    const { ensureL2tpModelIndexes } = require('../l2tpModelIndexReadiness');
    const key = { operationId: 1, ordinal: -1 };
    const options = { unique: true,
        partialFilterExpression: { status: 'waiting', ordinal: { $gt: 0 } },
        collation: { locale: 'en', strength: 2 } };
    const valid = () => [
        { key: { _id: 1 } },
        { key: { ...key }, ...structuredClone(options) },
        { key: { requestKey: 1 }, unique: true, sparse: true },
        { key: { expireAt: 1 }, expireAfterSeconds: 300 },
    ];
    const cases = [
        ['missing _id', indexes => indexes.shift()],
        ['wrong _id key', indexes => { indexes[0].key = { _id: -1 }; }],
        ['missing declared index', indexes => indexes.splice(1, 1)],
        ['reversed compound key', indexes => { indexes[1].key = { ordinal: -1, operationId: 1 }; }],
        ['weaker uniqueness', indexes => { indexes[1].unique = false; }],
        ['missing sparse', indexes => { delete indexes[2].sparse; }],
        ['unexpected sparse', indexes => { indexes[3].sparse = true; }],
        ['changed partial filter', indexes => { indexes[1].partialFilterExpression.status = 'done'; }],
        ['missing partial filter', indexes => { delete indexes[1].partialFilterExpression; }],
        ['changed TTL', indexes => { indexes[3].expireAfterSeconds = 301; }],
        ['missing TTL', indexes => { delete indexes[3].expireAfterSeconds; }],
        ['changed collation', indexes => { indexes[1].collation.strength = 1; }],
        ['missing collation', indexes => { delete indexes[1].collation; }],
    ];
    const modelFor = indexes => ({
        async createCollection() {}, async createIndexes() {},
        schema: { indexes: () => [[key, options], [{ requestKey: 1 }, { unique: true, sparse: true }],
            [{ expireAt: 1 }, { expireAfterSeconds: 300 }]] },
        collection: { async indexes() { return indexes; } },
    });
    for (const [name, mutate] of cases) {
        await t.test(name, async () => {
            const indexes = valid(); mutate(indexes);
            await assert.rejects(ensureL2tpModelIndexes({ loadModels: () => ({ CheckedModel: modelFor(indexes) }) }),
                /index readiness failed for CheckedModel/);
        });
    }
    await t.test('equivalent filter property order and extra operator index remain accepted', async () => {
        const indexes = valid();
        indexes[1].partialFilterExpression = { ordinal: { $gt: 0 }, status: 'waiting' };
        indexes.push({ key: { operatorField: 1 } });
        await ensureL2tpModelIndexes({ loadModels: () => ({ CheckedModel: modelFor(indexes) }) });
        assert.equal(indexes.length, 5, 'readiness must not remove operator indexes');
    });
});

test('metadata refusal drains the sibling before rejection without admitting a later batch', async t => {
    const { ensureL2tpModelIndexes } = require('../l2tpModelIndexReadiness');
    for (const missingId of [true, false]) {
        await t.test(missingId ? 'missing _id' : 'weaker unique index', async () => {
            const calls = [];
            const bad = controlledModel('Bad', calls), peer = controlledModel('Peer', calls);
            const later = controlledModel('Later', calls);
            if (missingId) bad.actual.shift(); else bad.actual[1].unique = false;
            let settled = false;
            const start = ensureL2tpModelIndexes({ loadModels: () => ({ Bad: bad.model, Peer: peer.model, Later: later.model }) });
            const observed = start.then(() => { settled = true; }, () => { settled = true; });
            const rejected = assert.rejects(start, missingId ? /Bad: missing _id index/ : /Bad:.*operationId/);
            try {
                bad.release(); await tick();
                assert.equal(settled, false);
                assert.deepEqual([...calls], ['Bad:collection', 'Peer:collection', 'Bad:build', 'Bad:readback']);
                peer.release();
                await Promise.all([observed, rejected]);
                assert.equal(settled, true);
                assert.deepEqual(calls, ['Bad:collection', 'Peer:collection', 'Bad:build', 'Bad:readback', 'Peer:build', 'Peer:readback']);
            } finally {
                [bad, peer, later].forEach(control => control.release());
                await Promise.all([observed, rejected]);
            }
        });
    }
});

test('synchronous and asynchronous failures in one batch are both drained and retain the original error', async () => {
    const { ensureL2tpModelIndexes } = require('../l2tpModelIndexReadiness');
    const calls = [], original = new Error('collection failed synchronously');
    const peer = controlledModel('Peer', calls), later = controlledModel('Later', calls);
    let settled = false;
    const start = ensureL2tpModelIndexes({ loadModels: () => ({
        First: { createCollection() { calls.push('First:collection'); throw original; } },
        Peer: peer.model, Later: later.model,
    }) });
    const observed = start.then(() => { settled = true; }, () => { settled = true; });
    const rejected = assert.rejects(start, e => e === original);
    try {
        await tick();
        assert.equal(settled, false);
        assert.deepEqual([...calls], ['First:collection', 'Peer:collection']);
        peer.stages.collection.resolve(); await tick();
        assert.equal(settled, false);
        peer.stages.build.reject(new Error('second index build failed'));
        await Promise.all([observed, rejected]);
        assert.deepEqual(calls, ['First:collection', 'Peer:collection', 'Peer:build']);
    } finally {
        [peer, later].forEach(control => control.release());
        await Promise.all([observed, rejected]);
    }
});

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
