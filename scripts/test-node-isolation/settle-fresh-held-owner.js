#!/usr/bin/env node
'use strict';
// Explicit finite operator entry; NOT imported by panel startup or HTTP/MCP.
const mongoose = require('mongoose');
const { HeldTestOwnerSettlement } = require('../../src/services/heldTestOwnerSettlement');
const { HeldOwnerSettlementJournal } = require('../../src/services/heldOwnerSettlementJournal');
const { freshOperationalInputs, withFreshOperationalRestoration } = require('../../src/services/heldRestorationChannel');
async function main() {
    if (process.getuid() !== 0 || process.argv.length !== 2) throw new Error('FIXED_ROOT_FRESH_SETTLEMENT_ENTRY_REQUIRED');
    const inputs = freshOperationalInputs();
    const db = await mongoose.createConnection(inputs.config.mongoUri, { autoCreate: false, autoIndex: false,
        serverSelectionTimeoutMS: 5000, connectTimeoutMS: 5000, socketTimeoutMS: 5000, retryWrites: false }).asPromise();
    const bind = (name, location) => db.model(name, require(location).schema);
    let result, failure;
    try {
        const models = {
            Owner: bind('TopologyConfigOwner', '../../src/models/topologyConfigOwnerModel'),
            Enrollment: bind('TopologyExecutionEnrollment', '../../src/modules/relay-l2tp/models/topologyExecutionEnrollmentModel'),
            Binding: bind('TopologyExecutionBinding', '../../src/modules/relay-l2tp/models/topologyExecutionBindingModel'),
            Operation: bind('TopologyOperation', '../../src/modules/relay-l2tp/models/topologyOperationModel'),
            Lock: bind('NodeOperationLock', '../../src/modules/relay-l2tp/models/nodeOperationLockModel'),
            Topology: bind('CascadeTopologyState', '../../src/modules/relay-l2tp/models/cascadeTopologyStateModel'),
            Intent: bind('TopologyCreateIntent', '../../src/modules/relay-l2tp/models/topologyCreateIntentModel'),
            Queue: bind('TopologyIntentQueueState', '../../src/modules/relay-l2tp/models/topologyIntentQueueStateModel'),
            Link: bind('CascadeLink', '../../src/models/cascadeLinkModel'),
            L2tpOperation: bind('L2tpOperation', '../../src/modules/relay-l2tp/models/l2tpOperationModel'),
        };
        const journal = new HeldOwnerSettlementJournal();
        const service = new HeldTestOwnerSettlement({ models, journal,
            withRestorationScope: work => withFreshOperationalRestoration(inputs, work) });
        result = await service.freshHandback(inputs.config.plan);
    } catch (error) { failure = error; }
    finally {
        try { await db.close(); } catch (error) {
            // Cleanup after committed completion cannot become a precommit
            // retained-exclusion claim or mask an earlier precise failure.
            failure ||= error;
            if (result?.code === 'COMMITTED_FRESH_ACTIVATION_CONFIRMED') failure.code = 'COMMITTED_ACTIVATION_UNKNOWN';
        }
    }
    if (failure) throw failure;
    process.stdout.write(JSON.stringify(result) + '\n');
}
if (require.main === module) main().catch(error => {
    const code = ['COMMITTED_ACTIVATION_UNKNOWN'].includes(error.code) ? error.code : 'TEST_OWNER_SETTLEMENT_UNKNOWN_RETAINED';
    process.stderr.write(code + '; no automatic retry or ownership rollback\n');
    process.exitCode = 75;
});
module.exports = { main };
