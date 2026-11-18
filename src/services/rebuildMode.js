'use strict';

const STRICT_FLAGS = Object.freeze([
    'L2TP_EXECUTION_ENABLED',
    'L2TP_MIGRATIONS_ENABLED',
    'L2TP_PRODUCTION_EXECUTION_ENABLED',
    'TOPOLOGY_TEST_EXECUTION_ENABLED',
    'TOPOLOGY_PRODUCTION_EXECUTION_ENABLED',
    'CLASSIC_TOPOLOGY_PRODUCTION_EXECUTION_ENABLED',
    'CLASSIC_TOPOLOGY_LIFECYCLE_ENABLED',
]);

function isRebuildEnabled(env = process.env) {
    return env.C3_REBUILD_ENABLED === 'true';
}

function validateRebuildMode(env = process.env) {
    const value = env.C3_REBUILD_ENABLED;
    if (value !== undefined && value !== 'false' && value !== 'true') {
        throw new TypeError('C3_REBUILD_ENABLED must be exactly "true" or "false"; refusing startup');
    }
    if (!isRebuildEnabled(env)) return false;
    const conflict = STRICT_FLAGS.find(key => env[key] !== undefined && env[key] !== 'false')
        ?? ['TOPOLOGY_TEST_STARTUP_MODE', 'C3_SETTINGS'].find(key => env[key] !== undefined);
    if (conflict) throw new TypeError(`C3_REBUILD_ENABLED conflicts with ${conflict}; refusing startup`);
    return true;
}

function rebuildStrictDisabled() {
    return Object.assign(new Error('This operation is unavailable in rebuild mode'), { code: 'REBUILD_STRICT_DISABLED' });
}

function rejectRebuildRoute(_req, res) {
    const { code, message } = rebuildStrictDisabled();
    return res.status(409).json({ error: { code, message } });
}

module.exports = { isRebuildEnabled, validateRebuildMode, rebuildStrictDisabled, rejectRebuildRoute };
