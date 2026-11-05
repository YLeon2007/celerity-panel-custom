'use strict';
// Faithful accepted C fixture local query/transaction seam; NOT Mongo.
const {isDeepStrictEqual: same} = require('node:util');
const copy = value => structuredClone(value);
function model(rows, db) {
    const matches = (row, filter) => Object.entries(filter).every(([field, value]) =>
        value?.$in ? value.$in.includes(row[field]) : same(row[field], value));
    const query = work => {
        let imported = false;
        const q = { select(fields) { imported ||= fields.split(/\s+/).includes('+legacyAppliedTopology'); return q; },
            session() { return q; }, read() { return q; }, readConcern() { return q; }, maxTimeMS() { return q; },
            async lean() {
                const result = copy(work());
                if (!imported) for (const row of Array.isArray(result) ? result : [result]) if (row) delete row.legacyAppliedTopology;
                return result;
            }, then(a, b) { return q.lean().then(a, b); } };
        return q;
    };
    return { rows, db,
        collection: { indexes: async () => [{ key: { node: 1, profile: 1 }, unique: true }] },
        async create(docs) {
            for (const doc of docs) {
                if (rows.some(row => row.node === doc.node && row.profile === doc.profile)) {
                    throw Object.assign(Error('duplicate owner profile'), { code: 11000 });
                }
                rows.push(copy(doc));
            }
            return copy(docs);
        },
        find: filter => query(() => rows.filter(row => matches(row, filter))),
        findById: value => query(() => rows.find(row => row._id === value) || null),
        findOne: filter => query(() => rows.find(row => matches(row, filter)) || null),
        findOneAndUpdate: (filter, change) => query(() => {
            const row = rows.find(row => matches(row, filter));
            if (!row) return null;
            Object.assign(row, copy(change.$set || {}));
            for (const field of Object.keys(change.$unset || {})) delete row[field];
            return row;
        }),
    };
}
module.exports = {model};
