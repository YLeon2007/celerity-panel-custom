'use strict';

function validateMigrations(migrations) {
    if (!Array.isArray(migrations)) {
        throw new TypeError('migrations must be an array');
    }

    const migrationIds = new Set();
    for (const [migrationIndex, migration] of migrations.entries()) {
        if (!migration || typeof migration !== 'object' || Array.isArray(migration)) {
            throw new TypeError(`migrations[${migrationIndex}] must be an object`);
        }
        if (typeof migration.id !== 'string' || migration.id.length === 0) {
            throw new TypeError(`migrations[${migrationIndex}].id must be a non-empty string`);
        }
        if (migrationIds.has(migration.id)) {
            throw new TypeError(`migration id must be unique: ${migration.id}`);
        }
        migrationIds.add(migration.id);
        if (!Number.isInteger(migration.version) || migration.version < 0) {
            throw new TypeError(`migration ${migration.id} version must be a non-negative integer`);
        }
        if (!Array.isArray(migration.steps)) {
            throw new TypeError(`migration ${migration.id} steps must be an array`);
        }

        for (const [stepIndex, step] of migration.steps.entries()) {
            if (!step || typeof step !== 'object' || Array.isArray(step)) {
                throw new TypeError(`migration ${migration.id} steps[${stepIndex}] must be an object`);
            }
            if (step.action !== 'createIndexes') {
                throw new TypeError(`migration ${migration.id} steps[${stepIndex}] has unsupported action`);
            }
            if (typeof step.modelName !== 'string' || step.modelName.length === 0) {
                throw new TypeError(
                    `migration ${migration.id} steps[${stepIndex}].modelName must be a non-empty string`,
                );
            }
        }
    }
}

function validateDependencies({ migrations, models, stateRepository, clock }) {
    validateMigrations(migrations);

    if (!models || typeof models !== 'object' || Array.isArray(models)) {
        throw new TypeError('models must be an object');
    }
    for (const migration of migrations) {
        for (const step of migration.steps) {
            if (typeof models[step.modelName]?.createIndexes !== 'function') {
                throw new TypeError(`models.${step.modelName}.createIndexes must be a function`);
            }
        }
    }

    if (!stateRepository || typeof stateRepository !== 'object') {
        throw new TypeError('stateRepository must be an object');
    }
    if (typeof stateRepository.getState !== 'function') {
        throw new TypeError('stateRepository.getState must be a function');
    }
    if (typeof stateRepository.recordApplied !== 'function') {
        throw new TypeError('stateRepository.recordApplied must be a function');
    }

    if (!clock || typeof clock !== 'object') {
        throw new TypeError('clock must be an object');
    }
    if (typeof clock.now !== 'function') {
        throw new TypeError('clock.now must be a function');
    }
}

function validateMigrationState(state) {
    if (!state || typeof state !== 'object' || Array.isArray(state)) {
        throw new TypeError('migration state must be an object');
    }
    if (!Number.isInteger(state.version) || state.version < 0) {
        throw new TypeError('migration state version must be a non-negative integer');
    }
    if (!Array.isArray(state.appliedMigrationIds)) {
        throw new TypeError('migration state appliedMigrationIds must be an array');
    }
    if (state.appliedMigrationIds.some(id => typeof id !== 'string' || id.length === 0)) {
        throw new TypeError('migration state appliedMigrationIds must contain non-empty strings');
    }
}

function createMigrationRunner({ migrations, models, stateRepository, clock } = {}) {
    validateDependencies({ migrations, models, stateRepository, clock });

    return {
        async run({ dryRun = false } = {}) {
            const state = await stateRepository.getState();
            validateMigrationState(state);
            const applied = new Set(state.appliedMigrationIds);
            const pendingMigrations = migrations.filter(migration => !applied.has(migration.id));
            const steps = pendingMigrations.flatMap(migration => migration.steps.map(step => ({
                migrationId: migration.id,
                version: migration.version,
                action: step.action,
                modelName: step.modelName,
            })));
            const skippedMigrationIds = migrations
                .filter(migration => applied.has(migration.id))
                .map(migration => migration.id);

            if (dryRun) {
                return {
                    dryRun: true,
                    steps,
                    appliedMigrationIds: [],
                    skippedMigrationIds,
                };
            }

            const appliedMigrationIds = [];
            for (const migration of pendingMigrations) {
                for (const step of migration.steps) {
                    await models[step.modelName].createIndexes();
                }
                await stateRepository.recordApplied({
                    migrationId: migration.id,
                    version: migration.version,
                    appliedAt: clock.now(),
                });
                appliedMigrationIds.push(migration.id);
            }

            return {
                dryRun: false,
                steps,
                appliedMigrationIds,
                skippedMigrationIds,
            };
        },
    };
}

module.exports = {
    createMigrationRunner,
};
