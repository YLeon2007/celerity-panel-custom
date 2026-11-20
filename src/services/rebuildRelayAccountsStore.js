'use strict';

const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');

const COLLECTION = 'c3_rebuild_relay_accounts';
const singleton = { _id: 'pending' };
const readOptions = { readPreference: 'primary', readConcern: { level: 'majority' }, maxTimeMS: 5000 };
const writeOptions = { writeConcern: { w: 'majority' } };
class RelayAccountsError extends Error {
    constructor(suffix, details) {
        const code = `REBUILD_L2TP_ACCOUNTS_${suffix}`;
        super(code);
        Object.assign(this, { code, ...details });
    }
}
const accountError = (suffix, details) => new RelayAccountsError(suffix, details);

// Every cooperating rebuild writer must call this under the same Apply lock,
// before any host action or business write, even for unrelated nodes. Stale
// Apply unlock does not clear this separate, non-expiring singleton.
async function assertNoPendingRelayAccounts(db) {
    let row;
    try { row = await db.collection(COLLECTION).findOne(singleton, { ...readOptions, projection: { _id: 1 } }); }
    catch { throw accountError('PERSISTENCE_UNAVAILABLE'); }
    if (row !== null) throw accountError('BLOCKED', { retryAllowed: false });
}

const read = (query, session) => {
    query = query.read('primary').maxTimeMS(5000).lean();
    return session ? query.session(session) : query.readConcern('majority');
};
const exact = row => Object.fromEntries(Object.entries(row).map(([key, value]) => [key,
    { $eq: value, ...(value === null && { $exists: true }) }]));
const requireOne = (result, counter) => {
    if (result?.acknowledged !== true || result[counter] !== 1) throw accountError('CHANGED');
};

function createRebuildRelayAccountsStore({ Node, State, L2tpUser }) {
    const db = L2tpUser.db;
    if (Node.db !== db || State.db !== db) throw accountError('PERSISTENCE_UNAVAILABLE');
    const fence = () => db.collection(COLLECTION);
    const owner = intentId => ({ ...singleton, intentId });
    return {
        assertNoPending: () => assertNoPendingRelayAccounts(db),
        states: session => read(State.find({ $nor: [{ status: 'not_installed', desiredState: 'absent' }] })
            .select('+rebuildInstallToken +rebuildMachineId').sort({ node: 1, _id: 1 }), session),
        async inventory(ids, login, session) {
            // Sequential queries also support reuse within a single transaction.
            const nodes = await read(Node.find({ _id: { $in: ids } })
                .select('ip ssh active type cascadeRole useCustomConfig').sort({ _id: 1 }), session);
            const users = await read(L2tpUser.find({ $or: [{ relayNode: { $in: ids } }, { login }] })
                .select('+passwordEncrypted').sort({ relayNode: 1, login: 1, _id: 1 }), session);
            return { nodes, users };
        },
        async begin(intent) {
            // _id is unique. A competing owner cannot match this write; the
            // resulting duplicate key is not authority to adopt their intent.
            // Multi forms are not automatically replayed by retryWrites.
            requireOne(await fence().updateMany(owner(intent.intentId), { $setOnInsert: intent },
                { ...writeOptions, upsert: true }), 'upsertedCount');
        },
        async verifyIntent(intentId) {
            if (!(await fence().findOne(owner(intentId), { ...readOptions, projection: { _id: 1 } }))) {
                throw accountError('CHANGED');
            }
        },
        async publish({ action, changes, recheck, verifyAuthority }) {
            const session = await db.startSession();
            let commitAttempted = false, primary;
            try {
                session.startTransaction({ readPreference: 'primary', readConcern: { level: 'snapshot' },
                    writeConcern: { w: 'majority' } });
                // Re-read the whole original scope before the first account write.
                await recheck(session);
                if (action === 'create') {
                    const inserted = await L2tpUser.insertMany(changes.map(({ after }) => after), { session });
                    if (inserted.length !== changes.length) throw accountError('CHANGED');
                } else {
                    for (const { before, after } of changes) {
                        const options = { session, timestamps: false };
                        if (action === 'delete') {
                            requireOne(await L2tpUser.deleteMany(exact(before), options), 'deletedCount');
                        } else {
                            requireOne(await L2tpUser.updateMany(exact(before), { $set: after }, options), 'matchedCount');
                        }
                    }
                }
                await verifyAuthority();
                // No withTransaction callback replay. Never abort or retry the
                // workflow on an uncertain commit; the separate fence remains.
                commitAttempted = true;
                await session.commitTransaction();
            } catch (error) {
                primary = error;
                if (!commitAttempted && session.inTransaction()) {
                    try { await session.abortTransaction(); } catch { /* Preserve original failure. */ }
                }
                throw error;
            } finally {
                try { await session.endSession(); }
                catch (error) { if (!primary) throw error; }
            }
        },
        async release(intentId) {
            requireOne(await fence().deleteMany(owner(intentId), writeOptions), 'deletedCount');
        },
    };
}

module.exports = { accountError, RelayAccountsError, assertNoPendingRelayAccounts, createRebuildRelayAccountsStore };
