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
} = {}) {
    const entries = Object.entries(loadModels());
    // Independent collections can progress together without unbounded DDL fan-out.
    for (let offset = 0; offset < entries.length; offset += 2) {
        // allSettled is also a shutdown barrier: an early rejection must not
        // leave an admitted collection/index build running after startup fails.
        const results = await Promise.allSettled(entries.slice(offset, offset + 2).map(async ([modelName, model]) => {
            await model.createCollection();
            // Do not syncIndexes(): readiness must never drop an operator's indexes.
            await model.createIndexes();
            const actual = await model.collection.indexes();
            if (!actual.some(index => isDeepStrictEqual(Object.entries(index.key), [['_id', 1]]))) {
                throw new Error(`L2TP index readiness failed for ${modelName}: missing _id index`);
            }
            for (const [key, options] of model.schema.indexes()) {
                if (!actual.some(index => matchesIndex(index, key, options))) {
                    throw new Error(`L2TP index readiness failed for ${modelName}: ${JSON.stringify(key)}`);
                }
            }
        }));
        const failed = results.find(result => result.status === 'rejected');
        if (failed) throw failed.reason; // No later batch may start after failure.
    }
}

module.exports = { ensureL2tpModelIndexes };
