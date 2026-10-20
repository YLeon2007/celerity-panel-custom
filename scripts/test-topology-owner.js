#!/usr/bin/env node
'use strict';
// Explicit internal maintenance entry, never imported/called by normal startup.
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('../src/modules/relay-l2tp/domain/topologyExecutionContext');
const { freeze } = require('../src/modules/relay-l2tp/models/topologyExecutionBindingContract');
function failure(code) { return Object.assign(new Error(code), { code }); }
function assertTestContext(env) {
    if (env?.PANEL_DOMAIN !== TEST.hostIdentity || env.L2TP_EXECUTION_ENABLED !== 'true'
        || env.L2TP_MIGRATIONS_ENABLED !== 'true' || env.TOPOLOGY_TEST_EXECUTION_ENABLED !== 'true'
        || env.TOPOLOGY_PRODUCTION_EXECUTION_ENABLED === 'true' || env.L2TP_PRODUCTION_EXECUTION_ENABLED === 'true') {
        throw failure('TEST_OWNER_CONTEXT_REQUIRED');
    }
}
async function enrollTestOwners({ env, lifecycle, store, TopologyConfigOwner } = {}) {
    assertTestContext(env);
    if (typeof lifecycle?.withCapturedTestOwnerEnrollment !== 'function') {
        throw failure('TEST_DURABLE_ORIGINALS_CAPTURE_REQUIRED');
    }
    // No caller-provided node inventory, owner generation, receipt or flag can
    // supply the plan: only the actual held controller's private accepted pins.
    return lifecycle.run(() => lifecycle.withCapturedTestOwnerEnrollment(async (plan, check) => {
        const { TopologyConfigTransfer } = require('../src/services/topologyConfigTransfer');
        const transfer = new TopologyConfigTransfer({ executionContext: TEST, TopologyConfigOwner,
            withVerifiedMaintenance: lifecycle.withVerifiedMaintenance.bind(lifecycle) });
        const enrolled = [];
        for (const pin of plan.nodes) {
            await check();
            const classic = await transfer.initializeClassic({ node: pin.nodeId, profile: pin.targetProfile, nodeIdentity: pin.nodeIdentity });
            await check();
            const adopted = await transfer.adopt({ node: pin.nodeId, profile: pin.targetProfile,
                generation: classic.generation, proofRef: pin.originalSnapshot.proofRef });
            await check();
            const result = await store.preEnroll(freeze({ nodeId: pin.nodeId, targetProfile: pin.targetProfile,
                endpoint: pin.endpoint, nodeIdentity: pin.nodeIdentity, bootId: pin.bootId,
                predecessorGeneration: 'none', ownerGeneration: adopted.generation }));
            await check();
            enrolled.push({ nodeId: pin.nodeId, targetProfile: pin.targetProfile, enrollmentId: result.enrollmentId,
                ownerGeneration: adopted.generation });
        }
        return freeze({ status: 'enrolled', executionContext: TEST, nodes: enrolled });
    }));
}
async function main(argv = process.argv.slice(2)) {
    if (argv.length !== 1 || argv[0] !== 'enroll') {
        process.stderr.write('Usage: node scripts/test-topology-owner.js enroll\n'); return 2;
    }
    // Reuse existing private dotenv/config and database credentials, never print
    // their values. No argv/env path, node selector, shell, upload or live probe.
    require('dotenv').config({ quiet: true });
    assertTestContext(process.env);
    const config = require('../config');
    const mongoose = require('mongoose');
    const { createL2tpRootLifecycle } = require('../src/modules/l2tpRuntimeLifecycleHook');
    const root = createL2tpRootLifecycle();
    try {
        // Enrollment never installs schema or starts background consumers.
        await mongoose.connect(config.MONGO_URI, { autoCreate: false, autoIndex: false, serverSelectionTimeoutMS: 5000 });
        const result = await root.enrollTestOwnersAfterDatabase();
        process.stdout.write(JSON.stringify(result) + '\n'); return 0;
    } finally { try { await root.stop(); } finally { await mongoose.disconnect(); } }
}
if (require.main === module) main().then(code => { process.exitCode = code; }, () => {
    // Driver/controller exceptions can contain credentials or secret file bytes.
    process.stderr.write('TEST_OWNER_ENROLLMENT_REFUSED_RETAINED\n'); process.exitCode = 1;
});
module.exports = { enrollTestOwners, assertTestContext, main };
