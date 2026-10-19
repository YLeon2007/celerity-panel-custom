'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { migrations } = require('../migrations');
const { createMigrationRunner } = require('../migrations/migrationRunner');

test('an installation with 001 already applied builds new queue/admission indexes before recording 002', async () => {
    const calls = [];
    const names = ['TopologyCreateIntent', 'TopologyIntentQueueState', 'RemoteAdmission'];
    const models = Object.fromEntries([...new Set(migrations.flatMap(m => m.steps.map(s => s.modelName))), ...names]
        .map(name => [name, { async createIndexes() { calls.push(name); } }]));
    const runner = createMigrationRunner({ migrations, models, clock: { now: () => new Date(0) },
        stateRepository: {
            async getState() { return { version: 1, appliedMigrationIds: ['001-ensure-module-indexes'] }; },
            async recordApplied({ migrationId }) { calls.push(migrationId); },
        },
    });
    await runner.run();
    assert.deepEqual(calls, [...names, '002-ensure-queue-admission-indexes']);
});
