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
    const models = loadModels();
    for (const [modelName, model] of Object.entries(models)) {
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
    }
}

module.exports = { ensureL2tpModelIndexes };
