'use strict';

const { Types: { ObjectId } } = require('mongoose');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');
const { transactOnce } = require('./rebuildRelayInstallTransaction');
const { collectionName: COLLECTION, readDirectory, writeDirectory, logicalAccount } = require('./rebuildRelayDirectory');
const { inspectAccountSources, isDormantClassicState, readClassicOperations } = require('./rebuildRelayAccountInventory');
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
async function assertNoPendingRelayAccounts(db, session) {
    let row;
    try { row = await db.collection(COLLECTION).findOne(singleton, {
        ...(session ? { session, maxTimeMS: readOptions.maxTimeMS } : readOptions), projection: { _id: 1 },
    }); }
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
    // A writer owns the exact BSON row it observed, not just a UUID. Use the
    // raw read image, including fields/order as stored, as the CAS operand.
    const owner = (intentId, intent) => {
        if (typeof intentId !== 'string' || intent?._id !== singleton._id || intent.intentId !== intentId) {
            throw accountError('CHANGED');
        }
        return { ...singleton, intentId, $expr: { $eq: ['$$ROOT', { $literal: intent }] } };
    };
    return {
        assertNoPending: () => assertNoPendingRelayAccounts(db),
        async pending() {
            try { return await fence().findOne(singleton, readOptions); }
            catch { throw accountError('PERSISTENCE_UNAVAILABLE'); }
        },
        async states(session) {
            // Read the unfiltered scope: even an absent row can have a new
            // operation or duplicate another member's identity.
            const states = await read(State.find({}).select('+rebuildInstallToken +rebuildMachineId').sort({ node: 1, _id: 1 }), session);
            const classicStates = states.filter(isDormantClassicState);
            if (!classicStates.length) return states;
            const classicIds = new Set(classicStates.map(row => String(row.node)));
            const cohort = states.filter(row => !classicIds.has(String(row.node)));
            if (states.length - cohort.length !== classicIds.size) throw accountError('NOT_OWNED');

            try {
                const classicOperations = await readClassicOperations(db, classicStates, session);
                // A same-login inventory read is not enough: any local user
                // precludes skipping this relay. Match both persisted ID types.
                const refs = [...classicIds].flatMap(id => [new ObjectId(id), id]);
                const localUser = await db.collection(L2tpUser.collection.name).findOne({ relayNode: { $in: refs } }, {
                    ...(session ? { session, maxTimeMS: readOptions.maxTimeMS } : readOptions),
                    projection: { _id: 1 }, collation: { locale: 'simple' },
                });
                inspectAccountSources({ rows: { states: classicStates, users: localUser === null ? [] : [localUser], classicOperations },
                    listMode: true });
            } catch (error) {
                if (['REBUILD_L2TP_ACCOUNT_SOURCE_BUSY', 'REBUILD_L2TP_ACCOUNT_INVENTORY_INVALID'].includes(error?.code)) {
                    throw accountError('NOT_OWNED');
                }
                throw error;
            }
            return cohort;
        },
        async inventory(ids, login, session) {
            // Sequential queries also support reuse within a single transaction.
            const nodes = await read(Node.find({ _id: { $in: ids } })
                .select('ip ssh active type cascadeRole useCustomConfig').sort({ _id: 1 }), session);
            const users = await read(L2tpUser.find({ $or: [{ relayNode: { $in: ids } }, { login }] })
                .select('+passwordEncrypted').sort({ relayNode: 1, login: 1, _id: 1 }), session);
            return { nodes, users, directory: await readDirectory(db, session) };
        },
        async begin(intent) {
            // Commit the actual pending intent before any host write. A
            // standalone cannot perform this upsert. An unknown commit is
            // not permission to dispatch, even if the row later appears.
            await transactOnce(State, L2tpUser, async session => {
                // A competing owner cannot match the unique singleton _id.
                requireOne(await fence().updateMany({ ...singleton, intentId: intent.intentId }, { $setOnInsert: intent },
                    { session, upsert: true }), 'upsertedCount');
            });
        },
        async verifyIntent(intentId, intent) {
            if (!(await fence().findOne(owner(intentId, intent), { ...readOptions, projection: { _id: 1 } }))) {
                throw accountError('CHANGED');
            }
        },
        async cancel({ intent, recheck, verifyAuthority }) {
            const filter = owner(intent?.intentId, intent);
            await transactOnce(State, L2tpUser, async session => {
                await recheck(session);
                requireOne(await fence().deleteMany(filter, { session }), 'deletedCount');
                await verifyAuthority();
            });
        },
        async publish({ intentId, intent, action, changes, recheck, verifyAuthority, directory, directoryBase, login }) {
            const filter = owner(intentId, intent);
            await transactOnce(State, L2tpUser, async session => {
                // Re-read the whole original scope before the first account write.
                await recheck(session);
                let next = directoryBase;
                if (action === 'create') {
                    const inserted = await L2tpUser.insertMany(changes.map(({ after }) => after), { session });
                    if (inserted.length !== changes.length) throw accountError('CHANGED');
                    next = [...next, logicalAccount(inserted[0])];
                } else {
                    for (const { before, after } of changes) {
                        const options = { session, timestamps: false };
                        if (action === 'delete') {
                            requireOne(await L2tpUser.deleteMany(exact(before), options), 'deletedCount');
                        } else if (after) {
                            requireOne(await L2tpUser.updateMany(exact(before), { $set: after }, options), 'matchedCount');
                        }
                    }
                    next = action === 'delete' ? next.filter(row => row.login !== login)
                        : next.map(row => row.login === login ? { ...row, enabled: false } : row);
                }
                await writeDirectory(db, directory, next, session);
                // Settle the exact owner's intent with the account rows. A
                // failed CAS cannot publish any of the account changes.
                requireOne(await fence().deleteMany(filter, { session }), 'deletedCount');
                await verifyAuthority();
            });
        },
    };
}

module.exports = { accountError, RelayAccountsError, assertNoPendingRelayAccounts, createRebuildRelayAccountsStore };
