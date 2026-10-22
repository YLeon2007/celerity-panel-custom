'use strict';
// Finite entry; intentionally NOT wired to application startup or activation.
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT: PROD } = require('../domain/topologyExecutionContext');
const { createProductionMaintenanceAuthority, readAccepted } = require('./productionMaintenanceAuthority');
const { isDeepStrictEqual: equal } = require('node:util');
function fail() { throw Object.assign(new Error('PROD_MAINTENANCE_UNKNOWN_RETAINED'), { code: 'PROD_MAINTENANCE_UNKNOWN_RETAINED' }); }
async function runAccepted({ config, authority, createClient }) {
    // Copy before the first await. No environment/UI/request receipt selection.
    const accepted = structuredClone(config);
    const challenge = accepted.challenge;
    if (!equal(challenge?.serverContext, PROD)) fail();
    return authority.withHeldMaintenance(challenge, async scope => {
        let client, primary, result;
        const check = async () => { if (await scope.assertHeld(challenge) !== undefined) fail(); };
        try {
            await check();
            client = createClient(accepted.mongoUri, { retryWrites: false, readPreference: 'primary',
                serverSelectionTimeoutMS: 2000, connectTimeoutMS: 2000, socketTimeoutMS: 2000, timeoutMS: 2000 });
            await check();
            await client.connect();
            await check();
            // Native DB only, no models, auto-DDL, app pools, workers or consumers.
            const { createProductionAdmissionInitializer } = require('../services/productionAdmissionInitializer');
            const initializer = createProductionAdmissionInitializer({ db: client.db(challenge.databaseName),
                serverContext: PROD, expectedDatabaseName: challenge.databaseName,
                expectedDeployment: challenge.deployment, acceptedClassicLinks: challenge.acceptedClassicLinks,
                initialState: challenge.initialState, acceptedManifestSha256: challenge.manifestSha256,
                maintenanceGeneration: challenge.maintenanceGeneration,
                acceptedMissingCollections: challenge.acceptedMissingCollections,
                // Reuse the SAME still-held scope. No nested lock or new helper.
                maintenanceAuthority: { async withHeldMaintenance(same, work) {
                    if (!equal(same, challenge)) fail();
                    await check(); const value = await work(scope); await check(); return value;
                } } });
            result = await initializer.initialize();
            await check();
        } catch (error) { primary = error; }
        finally {
            if (client) {
                // Always drain own DB resources even on revocation; loss of the
                // capability can never become permission to resume old writers.
                try { await check(); } catch (error) { primary ||= error; }
                try { await client.close(); } catch (error) { primary ||= error; }
                try { await check(); } catch (error) { primary ||= error; }
            }
        }
        if (primary) {
            try { await scope.retainUnknown(challenge); } catch { /* durable exclusion stays retained */ }
            throw primary;
        }
        return result;
    });
}
async function runProductionAdmissionMaintenance() {
    const config = readAccepted();
    const authority = createProductionMaintenanceAuthority(config.challenge);
    return runAccepted({ config, authority, createClient(uri, options) {
        const { mongo } = require('mongoose');
        return new mongo.MongoClient(uri, options);
    } });
}
module.exports = { runProductionAdmissionMaintenance, testing: Object.freeze({ runAccepted }) };
