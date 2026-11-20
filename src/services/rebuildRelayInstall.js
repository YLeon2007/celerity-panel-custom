'use strict';

const fail = code => Object.assign(new Error(code), { code });
const UNKNOWN = 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN';
const ROLLBACK_UNKNOWN = 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN';
const safe = (error, fallback) => fail(typeof error?.code === 'string' && /^REBUILD_[A-Z0-9_]+$/.test(error.code)
    ? error.code : fallback);

async function runFreshRelayInstall(id, deps) {
    if (!deps.authorize()) throw fail('REBUILD_L2TP_INSTALL_DISABLED');
    if (typeof id !== 'string' || !/^[a-f0-9]{24}$/.test(id)) throw fail('REBUILD_INVALID_REQUEST');
    let primary, installed = false;
    try {
        return await deps.lock(async verifyLock => {
            const checkAuthorization = () => {
                if (!deps.authorize()) throw fail('REBUILD_L2TP_INSTALL_DISABLED');
            };
            const checkAuthority = async () => {
                checkAuthorization();
                if (await verifyLock() === false) throw fail('REBUILD_LOCK_LOST');
                if (deps.verifyBinding) await deps.verifyBinding();
                checkAuthorization();
            };
            let remote;
            try {
                await checkAuthority();
                const inventory = await deps.inventory(id);
                if (inventory.eligible !== true || inventory.pristine !== true) throw fail('REBUILD_L2TP_NOT_FRESH_RELAY');
                if (deps.verifyBinding) await checkAuthority();
                checkAuthorization();
                remote = await deps.connect(inventory);
                checkAuthorization();
                const host = await remote.preflight();
                if (deps.machineId !== undefined && host?.machineId !== deps.machineId) {
                    throw fail('REBUILD_L2TP_INSTALL_IDENTITY_MISMATCH');
                }
                if (host?.ppp !== true || host.masked !== false) throw fail('REBUILD_L2TP_HOST_NOT_READY');
                if (deps.verifyBinding) await checkAuthority();
                checkAuthorization();
                const plan = await deps.prepare(inventory, remote);
                const backupId = plan?.backupId;
                if (typeof backupId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(backupId)) {
                    throw fail('REBUILD_L2TP_INSTALL_PLAN_INVALID');
                }
                await checkAuthority();
                let reservation;
                try { reservation = await deps.reserve(inventory, backupId, checkAuthority); }
                catch { throw fail('REBUILD_L2TP_RESERVATION_FAILED'); }
                const guard = async () => {
                    await checkAuthority();
                    await deps.verifyReservation(reservation);
                    await checkAuthority();
                };

                const rollback = async (code, noHostChanges = false) => {
                    try {
                        await guard();
                        if (!noHostChanges && await remote.rollback(plan, guard) !== true) throw fail(ROLLBACK_UNKNOWN);
                        await guard();
                        await deps.restore(reservation, checkAuthority);
                    } catch { throw fail(ROLLBACK_UNKNOWN); }
                    throw fail(code);
                };

                let installResult;
                try {
                    await guard();
                    installResult = await remote.install(plan, guard);
                } catch (error) {
                    // A thrown error is ambiguous unless the direct driver has
                    // explicit proof that all dispatched mutations have settled.
                    // Do not infer settlement from errno, timeout or SSH close.
                    if (error?.commandSettled === true) await rollback('REBUILD_L2TP_INSTALL_FAILED', error.noHostChanges === true);
                    throw fail(UNKNOWN);
                }
                if (installResult === false) await rollback('REBUILD_L2TP_INSTALL_FAILED');
                let verified;
                try { verified = await remote.verify(plan); }
                catch { throw fail(UNKNOWN); }
                if (verified === false) await rollback('REBUILD_L2TP_VERIFY_FAILED');
                if (verified !== true) throw fail(UNKNOWN);
                try {
                    await guard();
                    // Once settlement is attempted, never retry or restore the
                    // host: the final CAS may have reached majority already.
                    await deps.finish(reservation, checkAuthority);
                } catch { throw fail('REBUILD_L2TP_FINISH_OUTCOME_UNKNOWN'); }
                installed = true;
                return { executionMode: 'rebuild', status: 'installed', nodeId: id };
            } catch (error) {
                primary = safe(error, 'REBUILD_L2TP_INSTALL_FAILED');
                throw primary;
            } finally {
                if (remote) {
                    try { await remote.close(); }
                    catch {
                        if (!primary) throw fail(installed ? 'REBUILD_L2TP_INSTALLED_CLEANUP_FAILED' : 'REBUILD_TRANSPORT_CLEANUP_FAILED');
                    }
                }
            }
        });
    } catch (error) {
        // Neither transport disposal nor global lock release can reclassify a
        // known or uncertain terminal outcome.
        throw primary ?? (installed ? fail('REBUILD_L2TP_INSTALLED_CLEANUP_FAILED') : safe(error, 'REBUILD_L2TP_INSTALL_FAILED'));
    }
}

module.exports = { runFreshRelayInstall };
