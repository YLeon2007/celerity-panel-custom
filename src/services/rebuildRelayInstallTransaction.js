'use strict';

const options = { maxTimeMS: 5000, timeoutMS: 5000 };

// No withTransaction (body replay) or ClientSession.commitTransaction
// (implicit commit retry). A lost commit response stays unknown. Keep this
// one-shot driver boundary aligned with topologyV2Settlement in this repo.
async function transactOnce(State, User, work) {
    const db = State.db;
    if (!db || db !== User.db) throw new Error('Install requires a shared transaction-capable database');
    const session = await db.startSession();
    let attempted = false, primary;
    try {
        if (typeof session.transaction?.transition !== 'function') throw new Error('Unsupported transaction session');
        session.startTransaction({ readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
        const result = await work(session);
        attempted = true;
        try {
            const reply = await db.getClient().db('admin').command({ commitTransaction: 1,
                ...(session.transaction.recoveryToken ? { recoveryToken: session.transaction.recoveryToken } : {}),
                writeConcern: { w: 'majority', wtimeout: 5000 }, maxTimeMS: options.maxTimeMS }, { session, ...options });
            if (reply.ok !== 1 || reply.writeConcernError || reply.writeErrors?.length || reply.errorLabels?.length) {
                throw new Error('Install transaction commit unconfirmed');
            }
        } catch (error) {
            primary = error;
            throw error;
        } finally {
            // Prevent endSession from trying to abort an attempted commit.
            try { session.transaction.transition('TRANSACTION_COMMITTED'); }
            catch (error) { if (!primary) throw error; }
        }
        return result;
    } catch (error) {
        primary = error;
        if (!attempted && session.inTransaction()) {
            try { await session.abortTransaction(); } catch { /* retain the original refusal */ }
        }
        throw error;
    } finally {
        try { await session.endSession(); } catch (error) { if (!primary) throw error; }
    }
}

module.exports = { transactOnce };
