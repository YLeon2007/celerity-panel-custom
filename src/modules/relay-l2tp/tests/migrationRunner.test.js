'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const EXPECTED_MODEL_ORDER = [
    'RelayL2tpState',
    'L2tpUser',
    'CascadeRouteGroup',
    'CascadeTopologyState',
    'L2tpOperation',
    'TopologyOperation',
    'NodeOperationLock',
];

function createFakeModels(calls = []) {
    return Object.fromEntries(EXPECTED_MODEL_ORDER.map(modelName => [
        modelName,
        {
            async createIndexes() {
                calls.push({ action: 'createIndexes', modelName });
            },
        },
    ]));
}

function createValidRunnerDependencies(overrides = {}) {
    const { migrations } = require('../migrations');

    return {
        migrations,
        models: createFakeModels(),
        stateRepository: {
            async getState() {
                return { version: 0, appliedMigrationIds: [] };
            },
            async recordApplied() {},
        },
        clock: { now: () => new Date('2026-09-22T12:00:00.000Z') },
        ...overrides,
    };
}

test('runner validates migration, model, state repository, and clock dependencies', () => {
    const { createMigrationRunner } = require('../migrations/migrationRunner');
    const dependencies = createValidRunnerDependencies();
    const modelsWithoutCreateIndexes = createFakeModels();
    modelsWithoutCreateIndexes.RelayL2tpState = {};

    assert.throws(() => createMigrationRunner(), /migrations/i);
    assert.throws(
        () => createMigrationRunner({ ...dependencies, models: undefined }),
        /models/i,
    );
    assert.throws(
        () => createMigrationRunner({ ...dependencies, models: modelsWithoutCreateIndexes }),
        /RelayL2tpState.*createIndexes/i,
    );
    assert.throws(
        () => createMigrationRunner({ ...dependencies, stateRepository: undefined }),
        /stateRepository/i,
    );
    assert.throws(
        () => createMigrationRunner({
            ...dependencies,
            stateRepository: { recordApplied() {} },
        }),
        /stateRepository\.getState/i,
    );
    assert.throws(
        () => createMigrationRunner({
            ...dependencies,
            stateRepository: { getState() {} },
        }),
        /stateRepository\.recordApplied/i,
    );
    assert.throws(
        () => createMigrationRunner({ ...dependencies, clock: undefined }),
        /clock/i,
    );
    assert.throws(
        () => createMigrationRunner({ ...dependencies, clock: {} }),
        /clock\.now/i,
    );
});

test('runner rejects malformed migration state before any model or state write', async () => {
    const { createMigrationRunner } = require('../migrations/migrationRunner');
    const modelCalls = [];
    let stateWrites = 0;
    let currentState = null;
    const dependencies = createValidRunnerDependencies({
        models: createFakeModels(modelCalls),
        stateRepository: {
            async getState() {
                return currentState;
            },
            async recordApplied() {
                stateWrites += 1;
            },
        },
    });
    const runner = createMigrationRunner(dependencies);
    const malformedStates = [
        null,
        { version: 0 },
        { version: -1, appliedMigrationIds: [] },
        { version: 0, appliedMigrationIds: '001-ensure-module-indexes' },
        { version: 0, appliedMigrationIds: [1] },
    ];

    for (const malformedState of malformedStates) {
        currentState = malformedState;
        await assert.rejects(runner.run(), /migration state/i);
    }

    assert.deepEqual(modelCalls, []);
    assert.equal(stateWrites, 0);
});

test('dry-run returns the exact ordered index steps without model or state writes', async () => {
    const { migrations } = require('../migrations');
    const { createMigrationRunner } = require('../migrations/migrationRunner');
    const modelCalls = [];
    let stateWrites = 0;
    const stateRepository = {
        async getState() {
            return { version: 0, appliedMigrationIds: [] };
        },
        async recordApplied() {
            stateWrites += 1;
        },
    };
    const runner = createMigrationRunner({
        migrations,
        models: createFakeModels(modelCalls),
        stateRepository,
        clock: { now: () => new Date('2026-09-22T12:00:00.000Z') },
    });

    const result = await runner.run({ dryRun: true });

    assert.deepEqual(result, {
        dryRun: true,
        steps: EXPECTED_MODEL_ORDER.map(modelName => ({
            migrationId: '001-ensure-module-indexes',
            version: 1,
            action: 'createIndexes',
            modelName,
        })),
        appliedMigrationIds: [],
        skippedMigrationIds: [],
    });
    assert.deepEqual(modelCalls, []);
    assert.equal(stateWrites, 0);
});

test('apply ensures only module indexes in order before recording migration success', async () => {
    const { migrations } = require('../migrations');
    const { createMigrationRunner } = require('../migrations/migrationRunner');
    const events = [];
    const models = {
        ...createFakeModels(events),
        HyNode: {
            async createIndexes() {
                throw new Error('host model indexes must not be touched');
            },
        },
    };
    const stateRepository = {
        async getState() {
            return { version: 0, appliedMigrationIds: [] };
        },
        async recordApplied(state) {
            events.push({ action: 'recordApplied', state });
        },
    };
    const runner = createMigrationRunner({
        migrations,
        models,
        stateRepository,
        clock: { now: () => new Date('2026-09-22T12:00:00.000Z') },
    });

    const result = await runner.run();

    assert.deepEqual(events, [
        ...EXPECTED_MODEL_ORDER.map(modelName => ({ action: 'createIndexes', modelName })),
        {
            action: 'recordApplied',
            state: {
                migrationId: '001-ensure-module-indexes',
                version: 1,
                appliedAt: new Date('2026-09-22T12:00:00.000Z'),
            },
        },
    ]);
    assert.deepEqual(result, {
        dryRun: false,
        steps: EXPECTED_MODEL_ORDER.map(modelName => ({
            migrationId: '001-ensure-module-indexes',
            version: 1,
            action: 'createIndexes',
            modelName,
        })),
        appliedMigrationIds: ['001-ensure-module-indexes'],
        skippedMigrationIds: [],
    });
});

test('a repeated apply skips recorded migrations without ensuring indexes again', async () => {
    const { migrations } = require('../migrations');
    const { createMigrationRunner } = require('../migrations/migrationRunner');
    const modelCalls = [];
    const stateWrites = [];
    const state = { version: 0, appliedMigrationIds: [] };
    const stateRepository = {
        async getState() {
            return {
                version: state.version,
                appliedMigrationIds: [...state.appliedMigrationIds],
            };
        },
        async recordApplied(record) {
            stateWrites.push(record);
            state.version = Math.max(state.version, record.version);
            state.appliedMigrationIds.push(record.migrationId);
        },
    };
    const runner = createMigrationRunner({
        migrations,
        models: createFakeModels(modelCalls),
        stateRepository,
        clock: { now: () => new Date('2026-09-22T12:00:00.000Z') },
    });

    await runner.run();
    const result = await runner.run();

    assert.equal(modelCalls.length, EXPECTED_MODEL_ORDER.length);
    assert.equal(stateWrites.length, 1);
    assert.deepEqual(result, {
        dryRun: false,
        steps: [],
        appliedMigrationIds: [],
        skippedMigrationIds: ['001-ensure-module-indexes'],
    });
});

test('a createIndexes failure rejects without recording success or running later migrations', async () => {
    const { createMigrationRunner } = require('../migrations/migrationRunner');
    const indexFailure = new Error('index ensure failed');
    const events = [];
    let stateWrites = 0;
    let clockCalls = 0;
    const migrations = [
        {
            id: '001-failing-indexes',
            version: 1,
            steps: [
                { action: 'createIndexes', modelName: 'FirstModel' },
                { action: 'createIndexes', modelName: 'FailingModel' },
                { action: 'createIndexes', modelName: 'UnreachedModel' },
            ],
        },
        {
            id: '002-later-migration',
            version: 2,
            steps: [{ action: 'createIndexes', modelName: 'LaterModel' }],
        },
    ];
    const models = Object.fromEntries([
        'FirstModel',
        'FailingModel',
        'UnreachedModel',
        'LaterModel',
    ].map(modelName => [modelName, {
        async createIndexes() {
            events.push(modelName);
            if (modelName === 'FailingModel') {
                throw indexFailure;
            }
        },
    }]));
    const runner = createMigrationRunner({
        migrations,
        models,
        stateRepository: {
            async getState() {
                return { version: 0, appliedMigrationIds: [] };
            },
            async recordApplied() {
                stateWrites += 1;
            },
        },
        clock: {
            now() {
                clockCalls += 1;
                return new Date('2026-09-22T12:00:00.000Z');
            },
        },
    });

    await assert.rejects(runner.run(), error => error === indexFailure);

    assert.deepEqual(events, ['FirstModel', 'FailingModel']);
    assert.equal(stateWrites, 0);
    assert.equal(clockCalls, 0);
});
