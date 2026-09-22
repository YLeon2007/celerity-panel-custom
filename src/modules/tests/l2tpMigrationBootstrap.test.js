'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    createL2tpMigrationBootstrap,
    parseL2tpMigrationsEnabled,
} = require('../l2tpMigrationBootstrap');

test('parses L2TP_MIGRATIONS_ENABLED as an exact disabled-by-default boolean', () => {
    assert.equal(parseL2tpMigrationsEnabled(undefined), false);
    assert.equal(parseL2tpMigrationsEnabled('false'), false);
    assert.equal(parseL2tpMigrationsEnabled('true'), true);

    for (const value of ['', 'TRUE', 'False', '1', '0', true, false, null]) {
        assert.throws(
            () => parseL2tpMigrationsEnabled(value),
            /L2TP_MIGRATIONS_ENABLED must be exactly "true" or "false"/,
            String(value),
        );
    }
});

test('construction and disabled runs do not load module models, migrations, or repositories', async () => {
    const calls = [];
    const bootstrap = createL2tpMigrationBootstrap({
        env: {},
        loadModuleEntry() {
            calls.push('loadModuleEntry');
            throw new Error('disabled migrations must not load the module entry');
        },
        createStateRepository() {
            calls.push('createStateRepository');
            throw new Error('disabled migrations must not create a repository');
        },
        createMigrationRunner() {
            calls.push('createMigrationRunner');
            throw new Error('disabled migrations must not create a runner');
        },
    });

    assert.deepEqual(calls, []);
    assert.deepEqual(await bootstrap.run(), {
        enabled: false,
        ran: false,
        steps: [],
        appliedMigrationIds: [],
        skippedMigrationIds: [],
    });
    assert.deepEqual(calls, []);
});

test('enabled runs register ordered module migrations, apply once, then report skips safely', async () => {
    const { createMigrationRunner } = require('../relay-l2tp/migrations/migrationRunner');
    const calls = [];
    const appliedMigrationIds = [];
    let version = 0;
    const clock = { now: () => new Date('2026-09-22T12:00:00.000Z') };
    const models = {
        FirstModel: {
            secretKey: 'first-model-secret',
            async createIndexes() {
                calls.push('FirstModel.createIndexes');
            },
        },
        SecondModel: {
            password: 'second-model-secret',
            async createIndexes() {
                calls.push('SecondModel.createIndexes');
            },
        },
        RelayL2tpMigrationState: { connectionSecret: 'state-model-secret' },
    };
    const migrations = [
        {
            id: '001-first',
            version: 1,
            steps: [{ action: 'createIndexes', modelName: 'FirstModel' }],
        },
        {
            id: '002-second',
            version: 2,
            steps: [{ action: 'createIndexes', modelName: 'SecondModel' }],
        },
    ];
    const moduleEntry = {
        manifest: { id: 'relay-l2tp' },
        registerModels({ modelRegistry }) {
            calls.push('registerModels');
            for (const [modelName, model] of Object.entries(models)) {
                modelRegistry.register(modelName, model);
            }
            return models;
        },
        registerMigrations({ migrationRegistry }) {
            calls.push('registerMigrations');
            for (const migration of migrations) {
                migrationRegistry.register(this.manifest.id, migration);
            }
            return migrations;
        },
    };
    const stateRepository = {
        async getState() {
            calls.push('getState');
            return { version, appliedMigrationIds: [...appliedMigrationIds] };
        },
        async recordApplied(record) {
            calls.push({ action: 'recordApplied', record });
            version = Math.max(version, record.version);
            appliedMigrationIds.push(record.migrationId);
        },
    };
    const bootstrap = createL2tpMigrationBootstrap({
        env: { L2TP_MIGRATIONS_ENABLED: 'true' },
        clock,
        loadModuleEntry() {
            calls.push('loadModuleEntry');
            return moduleEntry;
        },
        createStateRepository({ model }) {
            calls.push('createStateRepository');
            assert.strictEqual(model, models.RelayL2tpMigrationState);
            return stateRepository;
        },
        createMigrationRunner(options) {
            calls.push('createMigrationRunner');
            assert.deepEqual(options.migrations, migrations);
            assert.deepEqual(options.models, models);
            assert.strictEqual(options.stateRepository, stateRepository);
            assert.strictEqual(options.clock, clock);
            return createMigrationRunner(options);
        },
    });

    assert.deepEqual(calls, []);
    const firstResult = await bootstrap.run();
    const secondResult = await bootstrap.run();

    assert.deepEqual(calls, [
        'loadModuleEntry',
        'registerModels',
        'registerMigrations',
        'createStateRepository',
        'createMigrationRunner',
        'getState',
        'FirstModel.createIndexes',
        {
            action: 'recordApplied',
            record: {
                migrationId: '001-first',
                version: 1,
                appliedAt: new Date('2026-09-22T12:00:00.000Z'),
            },
        },
        'SecondModel.createIndexes',
        {
            action: 'recordApplied',
            record: {
                migrationId: '002-second',
                version: 2,
                appliedAt: new Date('2026-09-22T12:00:00.000Z'),
            },
        },
        'getState',
    ]);
    assert.deepEqual(firstResult, {
        enabled: true,
        ran: true,
        steps: [
            {
                migrationId: '001-first',
                version: 1,
                action: 'createIndexes',
                modelName: 'FirstModel',
            },
            {
                migrationId: '002-second',
                version: 2,
                action: 'createIndexes',
                modelName: 'SecondModel',
            },
        ],
        appliedMigrationIds: ['001-first', '002-second'],
        skippedMigrationIds: [],
    });
    assert.deepEqual(secondResult, {
        enabled: true,
        ran: true,
        steps: [],
        appliedMigrationIds: [],
        skippedMigrationIds: ['001-first', '002-second'],
    });
    assert.doesNotMatch(
        JSON.stringify([firstResult, secondResult]),
        /first-model-secret|second-model-secret|state-model-secret/,
    );
});
