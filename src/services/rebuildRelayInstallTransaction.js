'use strict';

const options = { maxTimeMS: 5000, timeoutMS: 5000 };

class AcknowledgedCommitCleanupError extends Error {
    constructor(cause) {
        super('Transaction committed; session cleanup failed', { cause });
    }
}

// No withTransaction (body replay) or ClientSession.commitTransaction
// (implicit commit retry). A lost commit response stays unknown. Keep this
// one-shot driver boundary aligned with topologyV2Settlement in this repo.
async function transactOnce(State, User, work) {
    const db = State.db;
    if (!db || db !== User.db) throw new Error('Install requires a shared transaction-capable database');
    const session = await db.startSession();
    let attempted = false, acknowledged = false, failed = false;
    try {
        if (typeof session.transaction?.transition !== 'function') throw new Error('Unsupported transaction session');
        session.startTransaction({ readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' }, readPreference: 'primary' });
        const result = await work(session);
        attempted = true;
        const reply = await db.getClient().db('admin').command({ commitTransaction: 1,
            ...(session.transaction.recoveryToken ? { recoveryToken: session.transaction.recoveryToken } : {}),
            writeConcern: { w: 'majority', wtimeout: 5000 }, maxTimeMS: options.maxTimeMS }, { session, ...options });
        if (reply.ok !== 1 || reply.writeConcernError || reply.writeErrors?.length || reply.errorLabels?.length) {
            throw new Error('Install transaction commit unconfirmed');
        }
        acknowledged = true;
        return result;
    } catch (error) {
        failed = true;
        if (!attempted) {
            try { if (session.inTransaction()) await session.abortTransaction(); }
            catch { /* retain the original refusal */ }
        }
        throw error;
    } finally {
        try {
            // endSession auto-aborts an active transaction. Do not call it
            // after an attempted commit unless the local transition succeeded.
            if (attempted) {
                session.transaction.transition('TRANSACTION_COMMITTED');
                if (session.inTransaction()) throw new Error('Install transaction session remained active');
            }
            await session.endSession();
        } catch (error) {
            if (!failed) throw acknowledged ? new AcknowledgedCommitCleanupError(error) : error;
        }
    }
}

module.exports = { transactOnce, AcknowledgedCommitCleanupError };
