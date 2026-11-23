'use strict';

const { randomBytes } = require('node:crypto');
const { AcknowledgedCommitCleanupError, ReservationOutcomeUnknownError } = require('./rebuildRelayInstallTransaction');
const { classifyInstallFailure, installFailure, hasPackagePreparation, requireInstallHostReady,
    checkedInstallId } = require('./rebuildRelayInstallDiagnostics');
const { IDENTITY_CHANGED, isIdentityChanged } = require('./rebuildRelayEffectAuthority');

const fail = code => Object.assign(new Error(code), { code });
const UNKNOWN = 'REBUILD_L2TP_INSTALL_OUTCOME_UNKNOWN';
const ROLLBACK_UNKNOWN = 'REBUILD_L2TP_ROLLBACK_OUTCOME_UNKNOWN';

async function runFreshRelayInstall(id, deps) {
    // The standalone gate is synchronous; enter its lock without an async
    // yield. A grant-backed gate awaits the registry before requesting it.
    const authorized = deps.authorize();
    if (!(typeof authorized?.then === 'function' ? await authorized : authorized)) throw fail('REBUILD_L2TP_INSTALL_DISABLED');
    const identityAfterReservation = () => installFailure(IDENTITY_CHANGED, 'unknown', undefined, { retryAllowed: false });
    if (typeof id !== 'string' || !/^[a-f0-9]{24}$/.test(id)) throw fail('REBUILD_INVALID_REQUEST');
    let primary, installed = false;
    try {
        return await deps.lock(async (verifyLock, retainLock) => {
            let inventory;
            const checkAuthorization = async () => {
                if (!await deps.authorize()) throw fail('REBUILD_L2TP_INSTALL_DISABLED');
            };
            const checkAuthority = async () => {
                if (!deps.unifiedIdentity) await checkAuthorization();
                if (await verifyLock() === false) throw fail('REBUILD_LOCK_LOST');
                if (deps.verifyBinding) await deps.verifyBinding(inventory);
                if (deps.verifyBinding && await verifyLock() === false) throw fail('REBUILD_LOCK_LOST');
                await checkAuthorization();
            };
            let remote, unsettled = false;
            try {
                await checkAuthority();
                inventory = await deps.inventory(id);
                if (inventory.eligible !== true || inventory.pristine !== true) throw fail('REBUILD_L2TP_NOT_FRESH_RELAY');
                if (deps.verifyBinding) await checkAuthority();
                if (deps.precheckSources) await deps.precheckSources(inventory, checkAuthority);
                await checkAuthorization();
                remote = await deps.connect(inventory);
                await checkAuthorization();
                const host = await remote.preflight();
                if (deps.machineId !== undefined && host?.machineId !== deps.machineId) {
                    throw fail(deps.unifiedIdentity ? IDENTITY_CHANGED : 'REBUILD_L2TP_INSTALL_IDENTITY_MISMATCH');
                }
                const preparePackages = deps.allowPackagePreparation === true && hasPackagePreparation(host);
                if (!preparePackages) requireInstallHostReady(host);
                if (deps.verifyBinding) await checkAuthority();
                else await checkAuthorization();
                // The fully installed path still does read-only prepare/check
                // before reserving. The package path must reserve before its
                // first host write, using an ID generated only on this server.
                let plan;
                if (!preparePackages) plan = await deps.prepare(inventory, remote);
                const backupId = preparePackages ? randomBytes(16).toString('hex') : plan?.backupId;
                if (typeof backupId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(backupId)) {
                    throw fail('REBUILD_L2TP_INSTALL_PLAN_INVALID');
                }
                await checkAuthority();
                let reservation;
                try { reservation = await deps.reserve(inventory, backupId, checkAuthority, preparePackages ? host.packagePreparation : undefined); }
                catch (error) {
                    unsettled = error instanceof ReservationOutcomeUnknownError || error instanceof AcknowledgedCommitCleanupError;
                    if (isIdentityChanged(error)) throw error;
                    // No host dispatch without both a checked commit and a
                    // clean handoff, even when the reservation is durable.
                    throw fail(error instanceof AcknowledgedCommitCleanupError
                        ? 'REBUILD_L2TP_RESERVATION_CLEANUP_FAILED' : 'REBUILD_L2TP_RESERVATION_FAILED');
                }
                unsettled = true;
                const guard = async () => {
                    await checkAuthority();
                    await deps.verifyReservation(reservation);
                    await checkAuthority();
                };

                if (preparePackages) {
                    await guard();
                    if (await remote.preparePackages(backupId, guard) !== true) throw fail(UNKNOWN);
                    await guard();
                    // DIRECT repeats ordinary preflight in prepare, on this
                    // same pinned client. Do not reserve or generate an ID again.
                    plan = await deps.prepare(inventory, remote);
                    if (plan?.backupId !== backupId) throw fail('REBUILD_L2TP_INSTALL_PLAN_INVALID');
                }

                const rollback = async (code, { noHostChanges = false, check } = {}) => {
                    // Not even a no-write Install refusal establishes that the
                    // earlier package phase was undone. Retain the reservation.
                    if (preparePackages) throw installFailure(code, 'unknown', check, { retryAllowed: false });
                    try {
                        await guard();
                        if (!noHostChanges && await remote.rollback(plan, guard) !== true) throw fail(ROLLBACK_UNKNOWN);
                        await guard();
                        await deps.restore(reservation, checkAuthority);
                        unsettled = false;
                    } catch (error) {
                        if (isIdentityChanged(error)) throw identityAfterReservation();
                        throw installFailure(error instanceof AcknowledgedCommitCleanupError
                            ? 'REBUILD_L2TP_ROLLBACK_CLEANUP_FAILED' : ROLLBACK_UNKNOWN, 'unknown', check);
                    }
                    throw installFailure(code, noHostChanges ? 'refused' : 'rolled_back', check);
                };

                let installResult;
                try {
                    await guard();
                    installResult = await remote.install(plan, guard);
                } catch (error) {
                    if (isIdentityChanged(error)) throw identityAfterReservation();
                    const check = checkedInstallId(error);
                    if (error?.prerequisitePartial === true && check !== undefined) {
                        // Keep the reservation and any shared host effects.
                        throw installFailure(UNKNOWN, 'unknown', check, { retryAllowed: false });
                    }
                    // A thrown error is ambiguous unless the direct driver has
                    // explicit proof that all dispatched mutations have settled.
                    // Do not infer settlement from errno, timeout or SSH close.
                    if (error?.commandSettled === true) await rollback('REBUILD_L2TP_INSTALL_FAILED', {
                        noHostChanges: error.noHostChanges === true, check,
                    });
                    throw fail(UNKNOWN);
                }
                if (installResult === false) await rollback('REBUILD_L2TP_INSTALL_FAILED');
                let verified;
                try { verified = await remote.verify(plan); }
                catch (error) {
                    if (isIdentityChanged(error)) throw identityAfterReservation();
                    throw fail(UNKNOWN);
                }
                if (verified === false) await rollback('REBUILD_L2TP_VERIFY_FAILED');
                if (verified !== true) throw fail(UNKNOWN);
                try {
                    await guard();
                    // Once settlement is attempted, never retry or restore the
                    // host: the final CAS may have reached majority already.
                    await deps.finish(reservation, checkAuthority);
                } catch (error) {
                    if (isIdentityChanged(error)) throw identityAfterReservation();
                    if (error instanceof AcknowledgedCommitCleanupError) unsettled = false;
                    throw fail(error instanceof AcknowledgedCommitCleanupError
                        ? 'REBUILD_L2TP_INSTALLED_CLEANUP_FAILED' : 'REBUILD_L2TP_FINISH_OUTCOME_UNKNOWN');
                }
                unsettled = false;
                installed = true;
                return { executionMode: 'rebuild', status: 'installed', nodeId: id };
            } catch (error) {
                primary = classifyInstallFailure(error);
                if (deps.unifiedIdentity && unsettled) {
                    retainLock?.();
                    primary = installFailure(primary.code, 'unknown', checkedInstallId(primary), { retryAllowed: false });
                } else if (deps.unifiedIdentity && primary.outcome === 'installed') {
                    primary = installFailure(primary.code, 'installed', undefined, { retryAllowed: false });
                }
                throw primary;
            } finally {
                if (remote) {
                    try { await remote.close(); deps.handBackRecovery?.(); }
                    catch {
                        if (!primary) throw fail(installed ? 'REBUILD_L2TP_INSTALLED_CLEANUP_FAILED' : 'REBUILD_TRANSPORT_CLEANUP_FAILED');
                    }
                }
            }
        });
    } catch (error) {
        // Neither transport disposal nor global lock release can reclassify a
        // known or uncertain terminal outcome.
        throw primary ?? (installed && deps.unifiedIdentity
            ? installFailure('REBUILD_L2TP_INSTALLED_CLEANUP_FAILED', 'installed', undefined, { retryAllowed: false })
            : classifyInstallFailure(installed ? fail('REBUILD_L2TP_INSTALLED_CLEANUP_FAILED') : error));
    }
}

module.exports = { runFreshRelayInstall };
