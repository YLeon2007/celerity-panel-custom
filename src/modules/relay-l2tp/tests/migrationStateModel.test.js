'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const RelayL2tpMigrationState = require('../models/relayL2tpMigrationStateModel');

test('migration state is module-owned and persists version and applied IDs only', () => {
    const appliedAt = new Date('2026-09-22T12:00:00.000Z');
    const state = new RelayL2tpMigrationState({
        version: 1,
        appliedMigrationIds: ['001-ensure-module-indexes'],
        lastAppliedAt: appliedAt,
        secretKey: 'must-not-persist',
        hostState: { mustNotPersist: true },
    });

    assert.equal(state.validateSync(), undefined);
    assert.deepEqual(state.toObject(), {
        _id: 'relay-l2tp',
        version: 1,
        appliedMigrationIds: ['001-ensure-module-indexes'],
        lastAppliedAt: appliedAt,
    });
});

test('migration state rejects another module identity and invalid versions', () => {
    const wrongModule = new RelayL2tpMigrationState({ _id: 'host', version: 0 })
        .validateSync();
    const invalidVersion = new RelayL2tpMigrationState({ version: -1 })
        .validateSync();

    assert.equal(wrongModule.errors._id.kind, 'enum');
    assert.equal(invalidVersion.errors.version.kind, 'min');
});
