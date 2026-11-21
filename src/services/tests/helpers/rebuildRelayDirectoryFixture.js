'use strict';

const assert = require('node:assert/strict');
const { isDeepStrictEqual: equal } = require('node:util');

// Model raw directory DML alongside the existing Mongoose fixture sessions.
// Call commitDirectory only when the fixture transaction actually lands.
function bindDirectory(t, db) {
    let value = null;
    const collection = {
        async findOne(filter, { session, readConcern } = {}) {
            assert.deepEqual(filter, { _id: 'directory' });
            if (!session) assert.equal(readConcern.level, 'majority');
            return structuredClone(session?.nextDirectory ?? value);
        },
        async updateMany(filter, update, { session, upsert, writeConcern }) {
            assert.equal(filter._id, 'directory');
            if (!session) assert.equal(writeConcern.w, 'majority');
            if (upsert) {
                if (value) throw Object.assign(new Error('fixture duplicate'), { code: 11000 });
                assert.equal(filter.generation, update.$setOnInsert.generation);
            } else if (!equal(value, filter.$expr.$eq[1].$literal)) {
                return { acknowledged: true, matchedCount: 0 };
            }
            const next = structuredClone(upsert ? update.$setOnInsert : { ...value, ...update.$set });
            if (session) {
                session.nextDirectory = next;
                session.commitDirectory = () => { value = next; };
            } else value = next;
            return { acknowledged: true, [upsert ? 'upsertedCount' : 'matchedCount']: 1 };
        },
    };
    const original = db.collection.bind(db);
    t.mock.method(db, 'collection', (name, ...args) => name === 'c3_rebuild_relay_accounts' ? collection : original(name, ...args));
    return collection;
}

module.exports = { bindDirectory };
