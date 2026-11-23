'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { withNode } = require('./rebuildLocks');
const { read } = require('./rebuildRelayBackendStore');
const { readRelayAuthority, captureRelayEffect } = require('./rebuildRelayEffectAuthority');
const { relayInstallEnabled } = require('./rebuildRelayAuthorization');
const { assertNoPendingRelayAccounts } = require('./rebuildRelayAccountsStore');
const { installRecoveryWasNotSent } = require('./rebuildRelayDirect');
const { BLOCKED, changed, createRecoveryStore, grantIdentity, validActor } = require('./rebuildRelayInstallRecoveryStore');
const { transactOnce, AcknowledgedCommitCleanupError } = require('./rebuildRelayInstallTransaction');

const UNCONFIRMED = 'REBUILD_L2TP_INSTALL_RECOVERY_UNCONFIRMED';
const fail = code => Object.assign(new Error(code), { code, retryAllowed: false });
const defaultDriver = options => require('./rebuildRelayDirect').createRelayDirect(options);

// The authenticated actor is composition input, never a recovery request field.
function createRebuildRelayInstallRecovery({ Node, State, L2tpUser, locks, env, actor, relayGrantStore,
    createRelayDirect = defaultDriver,
    assertNoRelayAccountIntent = session => assertNoPendingRelayAccounts(L2tpUser.db, session) }) {
    return async id => {
        const db = State.db;
        if (typeof id !== 'string' || id.length !== 24 || !/^[a-f0-9]{24}$/.test(id) || !validActor(actor) || !db
            || Node.db !== db || L2tpUser.db !== db || !relayGrantStore || typeof locks?.readInstallRecovery !== 'function'
            || !relayInstallEnabled(env)) {
            throw fail(BLOCKED);
        }
        const store = createRecoveryStore(State, L2tpUser);
        const getNode = session => read(Node.findById(id).select('ip domain active type cascadeRole useCustomConfig ssh').maxTimeMS(5000), session);
        let held, stagedClaim, remote, mayHaveDispatched = false, closing = false, settling = false;
        // Claim the global fence before entering the process-local node queue.
        // An active Install or another claimant is refused, not queued behind.
        try {
            // This intentionally refuses unbound 8a56425 rows: no durable
            // owner exit, grant/actor binding or prior absence preimage.
            const pending = await locks.readInstallRecovery(db, id, actor);
            const node = await getNode();
            const snapshot = await readRelayAuthority(env, relayGrantStore);
            const fence = captureRelayEffect(env, relayGrantStore, snapshot, id, node);
            const key = env.ENCRYPTION_KEY;
            if (String(node?._id) !== id || node.active !== true || node.type !== 'xray' || node.cascadeRole !== 'relay'
                || node.useCustomConfig || fence.source !== 'db' || !fence.listMode
                || typeof key !== 'string' || key.length < 32) throw changed();
            const authority = grantIdentity(fence);
            const checkAuthority = async session => {
                const current = await getNode(session);
                if (!equal(current, node) || env.ENCRYPTION_KEY !== key || !relayInstallEnabled(env)) throw changed();
                await fence.check(current);
                await assertNoRelayAccountIntent(session);
            };
            const check = async session => {
                if (held) await held.verify(session);
                await checkAuthority(session);
                const image = await store.checked(pending.receipt, authority, key, session);
                if (held) await held.verify(session);
                return image;
            };
            await check();
            // This checked write also refuses non-transaction-capable
            // stores before any remote recovery dispatch. No stale takeover.
            try {
                held = await transactOnce(State, L2tpUser, async session => {
                    await check(session);
                    return stagedClaim = await pending.claim(session);
                });
            } catch (error) {
                // COMMIT was acknowledged, but dispatch is prohibited after
                // session cleanup failure. The exact temporary claim is ours.
                if (error instanceof AcknowledgedCommitCleanupError) held = stagedClaim;
                throw error;
            }
            return await withNode(id, async () => {
                const { state } = await check();
                remote = await createRelayDirect({ node, env, fence });
                if (typeof remote?.reconcileInstall !== 'function' || typeof remote.close !== 'function') throw changed();
                let revoked = false, verified = false;
                const verifyLock = async () => {
                    if (revoked) throw changed();
                    try { await check(); verified = true; }
                    catch { revoked = true; throw changed(); }
                };
                const { clientCidr, tproxyPort, fwmark, routeTable } = state;
                const { backupId, packagePreparation } = pending.receipt;
                const network = { clientCidr, tproxyPort: Number(tproxyPort), fwmark: Number(fwmark), routeTable: Number(routeTable) };
                await check();
                mayHaveDispatched = true;
                let result;
                try {
                    result = await remote.reconcileInstall({ nodeId: id, backupId, network,
                        ...(packagePreparation !== null && { packagePreparation }) }, verifyLock);
                } catch (error) {
                    if (installRecoveryWasNotSent(error)) mayHaveDispatched = false;
                    throw error;
                }
                if (!verified || revoked || (result !== 'absent' && result !== 'rolled_back')) throw changed();
                closing = true;
                await remote.close();
                await check();
                settling = true;
                await transactOnce(State, L2tpUser, async session => {
                    const image = await check(session);
                    await store.restore(image, session);
                    await checkAuthority(session);
                    await held.settle(session);
                });
                return { status: 'can_install_again' };
            });
        } catch (error) {
            if (remote && !closing && typeof remote.close === 'function') {
                try { await remote.close(); } catch { /* The claim remains if dispatch was possible. */ }
            }
            // Only a definite pre-dispatch refusal can undo our claim. In
            // particular, an unsafe/unacknowledged host operation or an
            // unknown settlement COMMIT is never retried or read back as
            // success. If COMMIT landed, all three effects landed together.
            if (held && !mayHaveDispatched) {
                try { await held.releaseClaim(); } catch { throw fail(UNCONFIRMED); }
            }
            if (settling && error instanceof AcknowledgedCommitCleanupError) {
                throw fail('REBUILD_L2TP_INSTALL_RECOVERY_CLEANUP_FAILED');
            }
            throw fail(mayHaveDispatched || (stagedClaim && !held) ? UNCONFIRMED : BLOCKED);
        }
    };
}

module.exports = { createRebuildRelayInstallRecovery };
