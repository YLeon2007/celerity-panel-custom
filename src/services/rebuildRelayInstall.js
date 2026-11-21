'use strict';

const { AcknowledgedCommitCleanupError } = require('./rebuildRelayInstallTransaction');

const fail = code => Object.assign(new Error(code), { code });
const UNKNOWN = 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN';
const ROLLBACK_UNKNOWN = 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN';
const safe = (error, fallback) => Object.assign(fail(typeof error?.code === 'string' && /^REBUILD_[A-Z0-9_]+$/.test(error.code)
    ? error.code : fallback), error?.retryAllowed === false ? { retryAllowed: false } : {});

async function runFreshRelayInstall(id, deps) {
    if (!deps.authorize()) throw fail('REBUILD_L2TP_INSTALL_DISABLED');
    if (typeof id !== 'string' || !/^[a-f0-9]{24}$/.test(id)) throw fail('REBUILD_INVALID_REQUEST');
    let primary, installed = false;
    try {
        return await deps.lock(async verifyLock => {
            let inventory;
            const checkAuthorization = () => {
                if (!deps.authorize()) throw fail('REBUILD_L2TP_INSTALL_DISABLED');
            };
            const checkAuthority = async () => {
                checkAuthorization();
                if (await verifyLock() === false) throw fail('REBUILD_LOCK_LOST');
                if (deps.verifyBinding) {
                    await deps.verifyBinding(inventory);
                    if (await verifyLock() === false) throw fail('REBUILD_LOCK_LOST');
                }
                checkAuthorization();
            };
            let remote;
            try {
                await checkAuthority();
                inventory = await deps.inventory(id);
                if (inventory.eligible !== true || inventory.pristine !== true) throw fail('REBUILD_L2TP_NOT_FRESH_RELAY');
                if (deps.verifyBinding) await checkAuthority();
                if (deps.precheckSources) await deps.precheckSources(inventory, checkAuthority);
                checkAuthorization();
                remote = await deps.connect(inventory);
                checkAuthorization();
                const host = await remote.preflight();
                if (deps.machineId !== undefined && host?.machineId !== deps.machineId) {
                    throw fail('REBUILD_L2TP_INSTALL_IDENTITY_MISMATCH');
                }
                if (host?.masked !== false || (host.ppp !== true && host.pppPreparation !== true)) {
                    throw fail('REBUILD_L2TP_HOST_NOT_READY');
                }
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
                catch (error) {
                    // No host dispatch without both a checked commit and a
                    // clean handoff, even when the reservation is durable.
                    throw fail(error instanceof AcknowledgedCommitCleanupError
                        ? 'REBUILD_L2TP_RESERVATION_CLEANUP_FAILED' : 'REBUILD_L2TP_RESERVATION_FAILED');
                }
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
                    } catch (error) {
                        throw fail(error instanceof AcknowledgedCommitCleanupError
                            ? 'REBUILD_L2TP_ROLLBACK_CLEANUP_FAILED' : ROLLBACK_UNKNOWN);
                    }
                    throw fail(code);
                };

                let installResult;
                try {
                    await guard();
                    installResult = await remote.install(plan, guard);
                } catch (error) {
                    if (error?.prerequisiteRefusal === true && typeof error.noHostChanges === 'boolean') {
                        if (error.noHostChanges) await rollback(error.code, true);
                        // A checked prerequisite failure may have left a module
                        // loaded or the host receipt written. Keep the reservation.
                        throw Object.assign(fail(error.code), { retryAllowed: false });
                    }
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
                } catch (error) {
                    throw fail(error instanceof AcknowledgedCommitCleanupError
                        ? 'REBUILD_L2TP_INSTALLED_CLEANUP_FAILED' : 'REBUILD_L2TP_FINISH_OUTCOME_UNKNOWN');
                }
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
