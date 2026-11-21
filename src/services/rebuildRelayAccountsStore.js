'use strict';

const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');
const { transactOnce } = require('./rebuildRelayInstallTransaction');

const COLLECTION = 'c3_rebuild_relay_accounts';
const singleton = { _id: 'pending' };
const readOptions = { readPreference: 'primary', readConcern: { level: 'majority' }, maxTimeMS: 5000 };

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
            // Commit the actual pending intent before any host write. A
            // standalone cannot perform this upsert. An unknown commit is
            // not permission to dispatch, even if the row later appears.
            await transactOnce(State, L2tpUser, async session => {
                // A competing owner cannot match the unique singleton _id.
                requireOne(await fence().updateMany(owner(intent.intentId), { $setOnInsert: intent },
                    { session, upsert: true }), 'upsertedCount');
            });
        },
        async verifyIntent(intentId) {
            if (!(await fence().findOne(owner(intentId), { ...readOptions, projection: { _id: 1 } }))) {
                throw accountError('CHANGED');
            }
        },
        async publish({ intentId, action, changes, recheck, verifyAuthority }) {
            await transactOnce(State, L2tpUser, async session => {
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
                        } else if (after) {
                            requireOne(await L2tpUser.updateMany(exact(before), { $set: after }, options), 'matchedCount');
                        }
                    }
                }
                // Settle the exact owner's intent with the account rows. A
                // failed CAS cannot publish any of the account changes.
                requireOne(await fence().deleteMany(owner(intentId), { session }), 'deletedCount');
                await verifyAuthority();
            });
        },
    };
}

module.exports = { accountError, RelayAccountsError, assertNoPendingRelayAccounts, createRebuildRelayAccountsStore };
