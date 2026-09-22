'use strict';

function parseL2tpMigrationsEnabled(value) {
    if (value === undefined || value === 'false') return false;
    if (value === 'true') return true;
    throw new TypeError(
        'L2TP_MIGRATIONS_ENABLED must be exactly "true" or "false"; refusing startup',
    );
}

function toSafeRunResult(result) {
    return {
        enabled: true,
        ran: true,
        steps: result.steps.map(step => ({
            migrationId: step.migrationId,
            version: step.version,
            action: step.action,
            modelName: step.modelName,
        })),
        appliedMigrationIds: [...result.appliedMigrationIds],
        skippedMigrationIds: [...result.skippedMigrationIds],
    };
}

function createL2tpMigrationBootstrap({
    env = process.env,
    loadModuleEntry = () => require('./relay-l2tp'),
    createStateRepository = options => (
        require('./relay-l2tp/migrations/migrationStateRepository')
            .createMigrationStateRepository(options)
    ),
    createMigrationRunner = options => (
        require('./relay-l2tp/migrations/migrationRunner').createMigrationRunner(options)
    ),
    clock = { now: () => new Date() },
} = {}) {
    let runner;

    function getRunner() {
        if (runner !== undefined) return runner;

        const moduleEntry = loadModuleEntry();
        const models = {};
        moduleEntry.registerModels({
            modelRegistry: {
                register(modelName, model) {
                    models[modelName] = model;
                },
            },
        });
        const migrations = [];
        moduleEntry.registerMigrations({
            migrationRegistry: {
                register(moduleId, migration) {
                    if (moduleId !== moduleEntry.manifest.id) {
                        throw new Error(
                            `L2TP migration registration used unexpected module id: ${moduleId}`,
                        );
                    }
                    migrations.push(migration);
                },
            },
        });
        const stateRepository = createStateRepository({
            model: models.RelayL2tpMigrationState,
        });
        runner = createMigrationRunner({
            migrations,
            models,
            stateRepository,
            clock,
        });
        return runner;
    }

    return {
        async run() {
            const enabled = parseL2tpMigrationsEnabled(env.L2TP_MIGRATIONS_ENABLED);
            if (!enabled) {
                return {
                    enabled: false,
                    ran: false,
                    steps: [],
                    appliedMigrationIds: [],
                    skippedMigrationIds: [],
                };
            }

            return toSafeRunResult(await getRunner().run());
        },
    };
}

module.exports = {
    createL2tpMigrationBootstrap,
    parseL2tpMigrationsEnabled,
};
