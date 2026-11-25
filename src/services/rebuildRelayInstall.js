'use strict';

const { randomBytes } = require('node:crypto');
const { AcknowledgedCommitCleanupError, ReservationOutcomeUnknownError } = require('./rebuildRelayInstallTransaction');
const { classifyInstallFailure, installFailure, hasPackagePreparation, requireInstallHostReady,
    checkedInstallId, freshConflict, conflictCode, setCleanupChallenge, withInstallCheck } = require('./rebuildRelayInstallDiagnostics');
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
            let remote, reservation, consumedCleanup, cleanup, unsettled = false, progressTail = Promise.resolve(), percent = 10, lastStage = 'reserve';
            let firstPreflight = false;
            const verifyTopology = async () => {
                if (deps.verifyTopology) await deps.verifyTopology(inventory);
            };
            const topologyGuard = async () => {
                await checkAuthority();
                await verifyTopology();
                await checkAuthority();
            };
            const proveMain = async () => {
                if (!deps.proveMain) return;
                await topologyGuard();
                await deps.proveMain(inventory, remote, topologyGuard);
                await topologyGuard();
            };
            const progress = (stage, next = percent) => {
                if (!reservation || !deps.progress || next < percent || (stage === lastStage && next === percent)) return progressTail;
                percent = next;
                lastStage = stage;
                progressTail = progressTail.then(async () => {
                    // Advisory telemetry cannot supersede a phase or change its outcome.
                    if (await verifyLock() === false) return;
                    await deps.progress(reservation, stage, next);
                }).catch(() => {});
                return progressTail;
            };
            try {
                await checkAuthority();
                if (deps.foreignCleanup && !deps.cleanupConsent) throw withInstallCheck(fail('REBUILD_L2TP_CLEANUP_CONSENT_REQUIRED'), 'CLEANUP_CONSENT_REQUIRED');
                inventory = await deps.inventory(id);
                if (inventory.eligible !== true || inventory.pristine !== true) throw fail('REBUILD_L2TP_NOT_FRESH_RELAY');
                if (deps.verifyBinding) await checkAuthority();
                if (deps.precheckSources) await deps.precheckSources(inventory, checkAuthority);
                await checkAuthorization();
                remote = await deps.connect(inventory);
                await checkAuthorization();
                await proveMain();
                let host;
                if (!deps.foreignCleanup) {
                    firstPreflight = true;
                    host = await remote.preflight();
                    firstPreflight = false;
                } else {
                    let observed, refusal;
                    try { await remote.preflight(); } catch (error) {
                        observed = freshConflict(error);
                        if (!observed) throw error;
                        if (observed.check !== 'L2TP_FOREIGN_CONFIG') {
                            await checkAuthority();
                            // Burn only this actor/session/admission's ticket on a positive runtime veto.
                            try { await deps.cleanupConsent.consume(deps.foreignCleanup, undefined); }
                            catch { /* Keep the authoritative runtime refusal. */ }
                            throw error;
                        }
                        refusal = error;
                    }
                    await checkAuthority();
                    try { consumedCleanup = await deps.cleanupConsent.consume(deps.foreignCleanup, observed); }
                    catch (error) {
                        if (error.code === 'REBUILD_L2TP_CLEANUP_CONSENT_CHANGED' && refusal) {
                            throw installFailure('REBUILD_L2TP_FOREIGN_CONFIG_CHANGED', 'refused', observed.check, { conflict: observed });
                        }
                        if (error.code === 'REBUILD_L2TP_CLEANUP_CONSENT_CHANGED') {
                            throw installFailure('REBUILD_L2TP_FOREIGN_CONFIG_CHANGED', 'refused', 'L2TP_FOREIGN_CONFIG');
                        }
                        throw withInstallCheck(error, error.code?.slice('REBUILD_L2TP_'.length));
                    }
                    cleanup = Object.freeze({ digest: observed.digest, fixXrayUnitMode: consumedCleanup.fixXrayUnitMode,
                        at: new Date().toISOString() });
                    host = await remote.preflight(cleanup);
                }
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
                if (cleanup && preparePackages) throw fail('REBUILD_L2TP_HOST_NOT_READY');
                if (!preparePackages) plan = await deps.prepare(inventory, remote, ...(cleanup ? [cleanup] : []));
                const backupId = preparePackages ? randomBytes(16).toString('hex') : plan?.backupId;
                if (typeof backupId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(backupId)) {
                    throw fail('REBUILD_L2TP_INSTALL_PLAN_INVALID');
                }
                await proveMain();
                if (cleanup) {
                    try { await deps.cleanupConsent.bind(deps.foreignCleanup, backupId); }
                    catch { throw withInstallCheck(fail('REBUILD_L2TP_CLEANUP_CONSENT_UNAVAILABLE'), 'CLEANUP_CONSENT_UNAVAILABLE'); }
                }
                try { reservation = await deps.reserve(inventory, backupId, deps.verifyTopology ? topologyGuard : checkAuthority, preparePackages ? host.packagePreparation : undefined); }
                catch (error) {
                    unsettled = error instanceof ReservationOutcomeUnknownError || error instanceof AcknowledgedCommitCleanupError;
                    if (isIdentityChanged(error) || ['REBUILD_L2TP_TOPOLOGY_NOT_APPLIED',
                        'REBUILD_L2TP_KCP_LISTENER_UNSUPPORTED'].includes(error?.code)) throw error;
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
                    await progress('preparePackages', 20);
                    const packageGuard = async () => { await guard(); await topologyGuard(); };
                    if (await remote.preparePackages(backupId, packageGuard, mark => {
                        if (mark === 'unpacking') void progress('preparePackages', 30);
                        if (mark === 'settingUp') void progress('preparePackages', 45);
                    }) !== true) throw fail(UNKNOWN);
                    await guard();
                    // DIRECT repeats ordinary preflight in prepare, on this
                    // same pinned client. Do not reserve or generate an ID again.
                    await progress('prepare', 50);
                    plan = await deps.prepare(inventory, remote);
                    if (plan?.backupId !== backupId) throw fail('REBUILD_L2TP_INSTALL_PLAN_INVALID');
                }

                if (!preparePackages) await progress('prepare', 50);
                const rollback = async (code, { noHostChanges = false, check, conflict } = {}) => {
                    // Not even a no-write Install refusal establishes that the
                    // earlier package phase was undone. Retain the reservation.
                    if (preparePackages) throw installFailure(conflict ? UNKNOWN : code, 'unknown', check, { retryAllowed: false });
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
                    throw installFailure(code, noHostChanges ? 'refused' : 'rolled_back',
                        cleanup && !noHostChanges ? 'FOREIGN_CONFIG_RESTORED' : check, { conflict });
                };

                let installResult;
                try {
                    await guard();
                    await progress('install', 65);
                    installResult = await remote.install(plan, guard, mark => {
                        if (mark === 'foreignCleanup' && cleanup) void progress('foreignCleanup', 70);
                        if (mark === 'restart') void progress('restart', 80);
                    });
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
                    const conflict = freshConflict(error);
                    if (error?.commandSettled === true) await rollback(conflict ? conflictCode(conflict) : 'REBUILD_L2TP_INSTALL_FAILED', {
                        noHostChanges: error.noHostChanges === true, check, conflict,
                    });
                    throw fail(UNKNOWN);
                }
                if (installResult === false) await rollback('REBUILD_L2TP_INSTALL_FAILED');
                let verified;
                await progress('verify', 92);
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
                if (unsettled) await progress('unknown');
                else await progressTail;
                if (deps.unifiedIdentity && unsettled) {
                    retainLock?.();
                    primary = installFailure(freshConflict(primary) ? UNKNOWN : primary.code, 'unknown',
                        checkedInstallId(primary), { retryAllowed: false });
                } else if (deps.unifiedIdentity && primary.outcome === 'installed') {
                    primary = installFailure(primary.code, 'installed', undefined, { retryAllowed: false });
                }
                const proof = freshConflict(primary);
                if (firstPreflight && !unsettled && primary.outcome === 'refused' && proof?.digest && deps.cleanupConsent) {
                    try {
                        await checkAuthority();
                        const { cleanable, manual } = proof;
                        const issued = !manual.length ? await deps.cleanupConsent.issue(proof) : undefined;
                        setCleanupChallenge(primary, { cleanable, manual, ...(issued && { cleanupToken: issued.token }) });
                    } catch { /* No valid ticket means no destructive control. */ }
                }
                throw primary;
            } finally {
                if (consumedCleanup) {
                    const result = installed ? 'installed' : unsettled ? 'unknown' : primary?.outcome === 'rolled_back'
                        ? 'rolled_back' : primary?.outcome === 'installed' ? 'installed' : 'refused';
                    // Audit is advisory to settlement: never replay a possible write to repair audit.
                    try { await deps.cleanupConsent.finish(deps.foreignCleanup, result); } catch { /* Retain the original consent audit. */ }
                }
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
