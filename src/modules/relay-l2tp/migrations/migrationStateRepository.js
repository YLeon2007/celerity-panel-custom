'use strict';

const MODULE_STATE_ID = 'relay-l2tp';
const STATE_SELECT = 'version appliedMigrationIds -_id';

function createMigrationStateRepository({ model } = {}) {
    return {
        async getState() {
            const state = await model.findById(MODULE_STATE_ID)
                .select(STATE_SELECT)
                .lean();

            return state ?? {
                version: 0,
                appliedMigrationIds: [],
            };
        },

        async recordApplied({ migrationId, version, appliedAt }) {
            await model.updateOne(
                { _id: MODULE_STATE_ID },
                {
                    $max: { version },
                    $addToSet: { appliedMigrationIds: migrationId },
                    $set: { lastAppliedAt: appliedAt },
                },
                { upsert: true, runValidators: true },
            );
        },
    };
}

module.exports = {
    createMigrationStateRepository,
};
