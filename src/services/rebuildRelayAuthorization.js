'use strict';
const {validateRebuildMode} = require('./rebuildMode');
// Independent opt-in for a single TEST relay. No classic execution context or
// generic L2TP worker is ever authorized by this predicate.
function canInstallRelay(env, id) {
    try {
        return validateRebuildMode(env) === true && env.C3_REBUILD_L2TP_INSTALL_ENABLED === 'true'
            && typeof id === 'string' && id.length === 24 && /^[a-f0-9]{24}$/.test(id)
            && env.C3_REBUILD_L2TP_RELAY_ID === id
            && typeof env.C3_REBUILD_L2TP_RELAY_MACHINE_ID === 'string'
            && env.C3_REBUILD_L2TP_RELAY_MACHINE_ID.length === 32
            && /^[a-f0-9]{32}$/.test(env.C3_REBUILD_L2TP_RELAY_MACHINE_ID);
    } catch { return false; }
}
module.exports = {canInstallRelay};
