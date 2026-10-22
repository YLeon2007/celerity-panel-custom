'use strict';

const { isDeepStrictEqual } = require('node:util');

function matchesIndex(actual, key, options) {
    // Compound-key ordering matters; object property order inside filters does not.
    return isDeepStrictEqual(Object.entries(actual.key), Object.entries(key))
        && Boolean(actual.unique) === Boolean(options.unique)
        && Boolean(actual.sparse) === Boolean(options.sparse)
        && isDeepStrictEqual(actual.partialFilterExpression, options.partialFilterExpression)
        && isDeepStrictEqual(actual.expireAfterSeconds, options.expireAfterSeconds)
        && isDeepStrictEqual(actual.collation, options.collation);
}

// Always awaited, independently of the one-time migration ledger and execution
// flags: HTTP queue admission also requires database uniqueness to be ready.
async function ensureL2tpModelIndexes({
    loadModels = () => require('./relay-l2tp').registerModels(),
    batchIndexes = false,
} = {}) {
    const entries = Object.entries(loadModels());
    // Independent collections can progress together without unbounded DDL fan-out.
    for (let offset = 0; offset < entries.length; offset += 2) {
        // allSettled is also a shutdown barrier: an early rejection must not
        // leave an admitted collection/index build running after startup fails.
        const results = await Promise.allSettled(entries.slice(offset, offset + 2).map(async ([modelName, model]) => {
            // Batched DDL must be selected before connection/model initialization,
            // never race an automatic per-index build or mask its failure.
            if (batchIndexes && (model.schema.options.autoIndex ?? model.db?.config.autoIndex) !== false) {
                throw new Error(`L2TP batched index startup requires disabled autoIndex for ${modelName}`);
            }
            // Public, memoized init joins Mongoose's already-started automatic DDL.
            // Its rejection is authoritative: never mask a failed automatic build.
            await model.init();
            const required = model.schema.indexes();
            const refusal = actual => {
                if (!actual.some(index => isDeepStrictEqual(Object.entries(index.key), [['_id', 1]]))) {
                    return new Error(`L2TP index readiness failed for ${modelName}: missing _id index`);
                }
                for (const [key, options] of required) {
                    if (!actual.some(index => matchesIndex(index, key, options))) {
                        return new Error(`L2TP index readiness failed for ${modelName}: ${JSON.stringify(key)}`);
                    }
                }
                return null;
            };
            let actual;
            try {
                actual = await model.collection.indexes();
            } catch (error) {
                // Only an absent namespace permits creation; network/auth/read
                // failures must refuse, not silently turn into a rebuild attempt.
                if (error.code !== 26) throw error;
            }
            if (actual && !refusal(actual)) return;
            // autoCreate/autoIndex may be disabled, or required indexes missing.
            // Add all declared indexes and prove the complete metadata again.
            // Do not syncIndexes(): readiness must never drop an operator's indexes.
            if (!batchIndexes || !actual) await model.createCollection();
            if (batchIndexes) {
                // One Mongo build per collection retains every declared spec,
                // rather than serializing a build/commit for each individual index.
                const specifications = required.map(([key, options]) => ({
                    ...(model.schema.options.collation ? { collation: model.schema.options.collation } : {}),
                    ...options, key,
                }));
                if (specifications.length) await model.collection.createIndexes(specifications);
            } else {
                await model.createIndexes();
            }
            const error = refusal(await model.collection.indexes());
            if (error) throw error;
        }));
        const failed = results.find(result => result.status === 'rejected');
        if (failed) throw failed.reason; // No later batch may start after failure.
    }
}

module.exports = { ensureL2tpModelIndexes };
