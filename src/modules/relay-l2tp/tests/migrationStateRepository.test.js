'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { createMigrationStateRepository } = require('../migrations/migrationStateRepository');

test('reads only module migration state and supplies an empty initial state', async () => {
    const calls = [];
    const model = {
        findById(id) {
            calls.push({ method: 'findById', id });
            return {
                select(paths) {
                    calls.push({ method: 'select', paths });
                    return this;
                },
                async lean() {
                    calls.push({ method: 'lean' });
                    return null;
                },
            };
        },
    };
    const repository = createMigrationStateRepository({ model });

    assert.deepEqual(await repository.getState(), {
        version: 0,
        appliedMigrationIds: [],
    });
    assert.deepEqual(calls, [
        { method: 'findById', id: 'relay-l2tp' },
        { method: 'select', paths: 'version appliedMigrationIds -_id' },
        { method: 'lean' },
    ]);
});

test('records an applied ID and monotonically advances module-owned version state', async () => {
    const calls = [];
    const model = {
        async updateOne(filter, update, options) {
            calls.push({ filter, update, options });
            return { acknowledged: true };
        },
    };
    const repository = createMigrationStateRepository({ model });
    const appliedAt = new Date('2026-09-22T12:00:00.000Z');

    await repository.recordApplied({
        migrationId: '001-ensure-module-indexes',
        version: 1,
        appliedAt,
    });

    assert.deepEqual(calls, [{
        filter: { _id: 'relay-l2tp' },
        update: {
            $max: { version: 1 },
            $addToSet: { appliedMigrationIds: '001-ensure-module-indexes' },
            $set: { lastAppliedAt: appliedAt },
        },
        options: { upsert: true, runValidators: true },
    }]);
});
