#!/usr/bin/env node
'use strict';
// Explicit finite operator entry; NOT imported by panel startup or HTTP/MCP.
const mongoose = require('mongoose');
const { HeldTestOwnerSettlement } = require('../../src/services/heldTestOwnerSettlement');
const { HeldOwnerSettlementJournal } = require('../../src/services/heldOwnerSettlementJournal');
const { operationalInputs, withOperationalRestoration } = require('../../src/services/heldRestorationChannel');
async function main() {
    if (process.getuid() !== 0 || process.argv.length !== 2) throw new Error('FIXED_ROOT_TEST_SETTLEMENT_ENTRY_REQUIRED');
    const inputs = operationalInputs();
    const db = await mongoose.createConnection(inputs.config.mongoUri, { autoCreate: false, autoIndex: false,
        serverSelectionTimeoutMS: 5000, connectTimeoutMS: 5000, socketTimeoutMS: 5000, retryWrites: false }).asPromise();
    const bind = (name, location) => db.model(name, require(location).schema);
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
            withRestorationScope: work => withOperationalRestoration(inputs, async scope => {
                const checkpoint = await work(scope);
                // This is a checkpoint WHILE all five original flock scopes and
                // external fences remain held, never transferable release/GO.
                process.stdout.write(JSON.stringify(checkpoint) + '\n');
                // No finish/release verb exists here. Keep the actual channel
                // live for its finite original deadline; expiry/error remains
                // unknown-retained and requires independent reconciliation.
                await scope.retain();
            }) });
        await service.settle(inputs.config.plan);
    } finally { await db.close(); }
}
if (require.main === module) main().catch(() => {
    process.stderr.write('TEST_OWNER_SETTLEMENT_UNKNOWN_RETAINED; no external handback\n');
    process.exitCode = 75;
});
module.exports = { main };
