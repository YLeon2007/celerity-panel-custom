#!/usr/bin/env node
'use strict';
// No options/env/UI receipt can select a target, policy, pins or helper.
async function main() {
    try {
        if (process.argv.length !== 2) throw new Error('REFUSED');
        const { runProductionAdmissionMaintenance } = require('../src/modules/relay-l2tp/runtime/productionAdmissionMaintenanceEntry');
        const result = await runProductionAdmissionMaintenance();
        process.stdout.write(JSON.stringify({ initialized: result.initialized === true, ready: false,
            dormant: true, holdRequired: true, mode: 'insert-only', stateSha256: result.stateSha256 }) + '\n');
    } catch {
        process.exitCode = 1;
        // A failure can follow a durable insert; false would imply rollback.
        process.stdout.write(JSON.stringify({ initialized: null, ready: false, dormant: true,
            holdRequired: true, code: 'PROD_ADMISSION_MAINTENANCE_REFUSED' }) + '\n');
    }
}
if (require.main === module) main();
module.exports = { main };
