'use strict';

const { isIP } = require('node:net');
const { isDeepStrictEqual: equal } = require('node:util');
const { withNode } = require('./rebuildLocks');
const { readRelayAuthority, captureRelayEffect, isIdentityChanged, identityChanged } = require('./rebuildRelayEffectAuthority');
const { sameRelayBinding } = require('./rebuildRelayAuthorization');
const { read, createStore } = require('./rebuildRelayBackendStore');
const { projectRelayChap, inspectAccountSources } = require('./rebuildRelayAccountInventory');
const { readDirectory, writeDirectory, checkDirectory, logicalAccount, sameAccounts } = require('./rebuildRelayDirectory');
const { transactOnce, AcknowledgedCommitCleanupError } = require('./rebuildRelayInstallTransaction');
const { readAccountCount, readSessionCensus } = require('./rebuildRelayCounts');
const { runtimeForeignChange, isRuntimeForeignChange, isUnconfirmedRuntimeWrite,
    networkNotReadyDetails, isNetworkObservationRequired } = require('./rebuildRelayRuntimeRefusal');
const { readAppliedTransit } = require('./rebuildAppliedLink');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');

const fail = code => Object.assign(new Error(code), { code });
const phaseError = (error, outcome) => Object.assign(error, { outcome, retryAllowed: false });
const DISABLED = 'REBUILD_L2TP_REMOVE_DISABLED';
const NOT_OWNED = 'REBUILD_L2TP_REMOVE_NOT_OWNED';
const CHANGED = 'REBUILD_L2TP_REMOVE_CHANGED';
const UNKNOWN = 'REBUILD_L2TP_REMOVE_OUTCOME_UNKNOWN';
const FINISH_UNKNOWN = 'REBUILD_L2TP_REMOVE_FINISH_OUTCOME_UNKNOWN';
const RESERVATION_FAILED = 'REBUILD_L2TP_REMOVE_RESERVATION_FAILED';
const RESERVATION_UNKNOWN = 'REBUILD_L2TP_REMOVE_RESERVATION_OUTCOME_UNKNOWN';
const CLEANUP = 'REBUILD_L2TP_REMOVED_CLEANUP_FAILED';
const CONFIRM = 'REBUILD_L2TP_REMOVE_CONFIRMATION_REQUIRED';
const PREVIEW_CHANGED = 'REBUILD_L2TP_REMOVE_PREVIEW_CHANGED';
const COUNT_UNAVAILABLE = 'REBUILD_L2TP_REMOVE_COUNT_UNAVAILABLE';
const SESSIONS_BUSY = 'REBUILD_L2TP_REMOVE_SESSIONS_BUSY';
const IPSEC_BUSY = 'REBUILD_L2TP_REMOVE_IPSEC_BUSY';
const DIRECT_IPSEC_BUSY = 'REBUILD_L2TP_DIRECT_REMOVE_IPSEC_BUSY';
const DIRECT_PREVIEW_CHANGED = 'REBUILD_L2TP_DIRECT_REMOVE_PREVIEW_CHANGED';
const LOCK_LOST = 'REBUILD_LOCK_LOST';
const PREVIEW_TTL_MS = 120_000;
// Private proof accompanying the immutable public estimate. Neither the
// installation receipt nor the host census is sent to the browser.
const previews = new WeakMap();
const safe = (error, fallback = 'REBUILD_L2TP_REMOVE_FAILED') => Object.assign(fail(
    typeof error?.code === 'string' && /^REBUILD_[A-Z0-9_]+$(?!\n)/.test(error.code) ? error.code : fallback), {
    ...(error?.outcome === 'unknown' && { outcome: 'unknown' }),
    ...(error?.retryAllowed === false && { retryAllowed: false }),
    ...(error?.code === 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN' && error.remoteOutcomeUncertain === true
        && { remoteOutcomeUncertain: true, retryAllowed: false }),
});
const write = { writeConcern: { w: 'majority' }, timestamps: false };
const defaultDriver = options => require('./rebuildRelayDirect').createRelayDirect(options);
const nodeFields = 'ip domain active type cascadeRole useCustomConfig ssh';
const stateFields = '+pskEncrypted +rebuildInstallToken +rebuildMachineId';
const networkKeys = ['clientCidr', 'tproxyPort', 'fwmark', 'routeTable'];
const installedFields = [...networkKeys, 'pskEncrypted', 'pskHint', 'secretRevision', 'localAddress', 'poolStart', 'poolEnd',
    'dnsServers', 'mtu', 'mru', 'backupId', 'routingMode', 'routingVersion', 'rebuildInstallToken', 'rebuildMachineId',
    'installedAt', 'lastVerifiedAt', 'lastSyncAt'];
const stateKeys = [...installedFields, '_id', 'node', 'status', 'desiredState', 'updatedAt', 'routeGroup', 'activePathKey',
    'operationId', 'appliedTopologyRevision', 'pppDriftQueueFence', 'replacementFence', 'lastErrorCode', 'lastError'];
const accountKeys = ['_id', 'relayNode', 'login', 'ip', 'enabled', 'passwordEncrypted', 'desiredRevision', 'appliedRevision',
    'syncStatus', 'syncOperationId', 'createdAt', 'updatedAt', 'lastSyncedAt', 'createdBy', 'updatedBy', 'comment',
    'lastErrorCode', 'lastError', '__v'];
const unsetInstalled = Object.fromEntries(installedFields.map(key => [key, '']));
const exact = (row, keys) => Object.fromEntries(keys.map(key => [key, Object.hasOwn(row, key)
    ? { $eq: row[key], ...(row[key] === null && { $exists: true }) } : { $exists: false }]));
const orderedAccounts = rows => [...rows].sort((a, b) => String(a._id).localeCompare(String(b._id)));
const exactDocument = (row, ownerKey) => ({ ...exact(row, ['_id', ownerKey]),
    $expr: { $eq: ['$$ROOT', { $literal: row }] } });
const integer = (value, min, max) => Number.isInteger(value) && value >= min && value <= max;
const nonempty = value => typeof value === 'string' && value.length > 0;
const empty = value => value == null || value === '';
const stamp = value => value instanceof Date ? value.getTime() : NaN;

function installedNetwork(state, nodeId, machineId) {
    if (!state?._id || String(state.node) !== nodeId || state.status !== 'installed' || state.desiredState !== 'installed'
        || state.routingMode !== FOLLOW_RELAY_MODE || state.routingVersion !== FOLLOW_RELAY_VERSION
        || state.routeGroup != null || state.operationId != null || !empty(state.activePathKey)
        || state.appliedTopologyRevision != null || ![0, null, undefined].includes(state.pppDriftQueueFence)
        || ![0, null, undefined].includes(state.replacementFence) || state.rebuildMachineId !== machineId
        || typeof state.rebuildInstallToken !== 'string' || state.rebuildInstallToken.length !== 36
        || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(state.rebuildInstallToken)
        || typeof state.backupId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(state.backupId)
        || state.backupId.trim() !== state.backupId || !nonempty(state.pskEncrypted) || state.secretRevision !== 1) throw fail(NOT_OWNED);
    const { clientCidr, tproxyPort, fwmark, routeTable } = state;
    const cidr = typeof clientCidr === 'string' && /^([^/]+)\/(0|[1-9][0-9]?)$/.exec(clientCidr);
    if (!cidr || cidr[0] !== clientCidr || isIP(cidr[1]) !== 4 || +cidr[2] > 32 || !integer(tproxyPort, 1024, 65535)
        || [1701, 4500].includes(tproxyPort) || !integer(fwmark, 1, 0x7fffffff) || !integer(routeTable, 1, 0x7fffffff)
        || [253, 254, 255].includes(routeTable)) throw fail(NOT_OWNED);
    return { clientCidr, tproxyPort, fwmark, routeTable };
}

function ownedAccount(rows, state, nodeId) {
    const [account] = rows;
    const installed = stamp(state.installedAt);
    // Install doesn't persist a user foreign key. Join its one bootstrap account
    // to the exact shared finish receipt, not merely the reserved login. Apply
    // may change state.updatedAt, but never changes this receipt.
    if (rows.length !== 1 || !account?._id || String(account.relayNode) !== nodeId || account.login !== 'relay-bootstrap'
        || typeof account.ip !== 'string' || isIP(account.ip) !== 4 || account.ip !== state.poolStart || account.enabled !== true
        || account.desiredRevision !== 1 || account.appliedRevision !== 1 || account.syncStatus !== 'synced'
        || account.syncOperationId != null || !empty(account.createdBy) || !empty(account.updatedBy)
        || !nonempty(account.passwordEncrypted) || !(stamp(account.createdAt) <= installed)
        || stamp(state.lastVerifiedAt) !== installed || stamp(state.lastSyncAt) !== installed
        || stamp(account.lastSyncedAt) !== installed || stamp(account.updatedAt) !== installed) throw fail(NOT_OWNED);
    return account;
}

function createRebuildRelayRemove({ Link, Node, State, L2tpUser, locks, withHeldLock, env, relayGrantStore, createRelayDirect = defaultDriver }) {
    const retirementPreviews = new WeakMap();
    const run = async (id, phase, estimate, heldLock) => {
        if (typeof id !== 'string' || id.length !== 24 || !/^[a-f0-9]{24}$/.test(id)) throw fail('REBUILD_INVALID_REQUEST');
        const proofStore = heldLock ? retirementPreviews : previews;
        const phaseAware = !!(relayGrantStore || heldLock);
        let fence;
        const snapshot = await readRelayAuthority(env, relayGrantStore);
        const proof = phase === 'confirm' ? proofStore.get(estimate) : undefined;
        if (relayGrantStore && proof && proof.source !== snapshot.sourceFor(id)) throw identityChanged();
        try { fence = captureRelayEffect(env, relayGrantStore, snapshot, id); }
        catch (error) { if (error?.code !== 'REBUILD_L2TP_INSTALL_DISABLED') throw error; throw fail(DISABLED); }
        const { machineId } = fence.binding;
        const chapKey = env.ENCRYPTION_KEY;
        const authorize = async node => {
            try { await fence.check(node); } catch (error) {
                if (error.code === 'REBUILD_L2TP_INSTALL_DISABLED') throw fail(DISABLED);
                throw error;
            }
        };
        const checkPreview = () => {
            if (phase === 'confirm' && (!proof || estimate.nodeId !== id || performance.now() >= proof.expires)) {
                throw fail(CONFIRM);
            }
        };
        checkPreview();
        if (heldLock && proof) proofStore.delete(estimate);
        if (proof && (proof.source !== fence.source || proof.generation !== fence.generation)) throw identityChanged();
        if (proof && (proof.listMode !== fence.listMode || !sameRelayBinding(proof.binding, fence.binding))) {
            throw relayGrantStore ? identityChanged() : fail(PREVIEW_CHANGED);
        }
        let primary, removed = false;
        try {
            const removeUnderLock = (verifyLock, retainLock) => withNode(id, async () => {
                let remote, reserved = false;
                const authority = async () => {
                    if (await verifyLock() === false) throw fail(LOCK_LOST);
                    await authorize();
                    if (await verifyLock() === false) throw fail(LOCK_LOST);
                    if (fence.listMode && env.ENCRYPTION_KEY !== chapKey) throw fail(CHANGED);
                };
                try {
                    await authority();
                    const getNode = session => read(Node.findById(id).select(nodeFields), session);
                    const node = await getNode();
                    if (String(node?._id) !== id || node.active !== true || node.type !== 'xray' || node.cascadeRole !== 'relay'
                        || node.useCustomConfig || (!fence.listMode && !isIP(node.ip))) throw fail(NOT_OWNED);
                    const authoritySnapshot = await readRelayAuthority(env, relayGrantStore);
                    try { await fence.check(node, authoritySnapshot); }
                    catch (error) { if (error?.code === 'REBUILD_L2TP_INSTALL_DISABLED') throw fail(DISABLED); throw error; }
                    const bound = relayGrantStore && captureRelayEffect(env, relayGrantStore, authoritySnapshot, id, node);
                    const open = () => createRelayDirect({ node, env, ...(bound && { fence: bound }),
                        ...(heldLock && { verifyRemoveStdin: true }) });
                    const checkNode = async () => {
                        if (fence.listMode || bound || heldLock) {
                            const current = await getNode();
                            if (bound) await bound.check(current ?? null);
                            if (!equal(current, node)) throw fail(CHANGED);
                        }
                        await authority();
                    };
                    const state = await read(State.findOne({ node: id }).select(stateFields));
                    if (relayGrantStore && state?.rebuildMachineId != null && state.rebuildMachineId !== machineId) throw identityChanged();
                    const network = installedNetwork(state, id, machineId);
                    const User = L2tpUser ?? require('../modules/relay-l2tp/models/l2tpUserModel');
                    // One overflow row is enough to refuse an inventory too
                    // large for DIRECT. Never dispatch a partial projection.
                    const users = session => read(User.find({ relayNode: id }).select('+passwordEncrypted')
                        .limit(2049).maxTimeMS(5000), session);
                    const getState = session => read(State.findOne({ _id: state._id, node: id }).select(stateFields), session);
                    const stateFence = exact(state, stateKeys);
                    let rows, approved = false, currentUsers;
                    try { rows = await users(); }
                    catch (error) { if (phase !== 'preview') throw error; }
                    const accounts = rows && orderedAccounts(rows);
                    if (proof && (!equal(proof.node, node) || !equal(proof.stateFence, stateFence)
                        || (heldLock && !equal(proof.state, state))
                        || !equal(proof.accounts, accounts))) throw fail(PREVIEW_CHANGED);
                    try {
                        if (fence.listMode) currentUsers = projectRelayChap(state, accounts, chapKey);
                        else ownedAccount(accounts, state, id);
                        approved = true;
                    } catch { if (phase !== 'preview') throw fail(NOT_OWNED); }

                    const checkInventory = async (expected, accounts, session) => {
                        // Mongo transactions cannot issue concurrent operations on one session.
                        const [currentNode, currentState, currentRows] = session
                            ? [await getNode(session), await getState(session), accounts && await users(session)]
                            : await Promise.all([getNode(), getState(), accounts && users()]);
                        if (bound) await bound.check(currentNode ?? null);
                        if (!equal(currentNode, node) || !currentState || !equal(exact(currentState, stateKeys), exact(expected, stateKeys))
                            || (heldLock && !equal(currentState, expected))
                            || (accounts && !equal(orderedAccounts(currentRows), accounts))) throw fail(CHANGED);
                        await authority();
                        return currentState;
                    };
                    // Legacy singleton still authenticates its unchanged block
                    // against the original host receipt. A list enrollment never
                    // falls back to it if the current DB projection is unavailable.
                    const input = { nodeId: id, backupId: state.backupId, network, ...(currentUsers && { currentUsers }) };
                    if (phase === 'preview') {
                        const accountCount = await readAccountCount(User, id);
                        let transitProved = true;
                        // The stopped-path proof uses the same applied listener
                        // ownership as Remove. Missing link proof needn't hide a
                        // live PPP count, but it cannot authorize confirmation.
                        try { if (Link) input.transit = await readAppliedTransit(Link, id); }
                        catch { transitProved = false; }
                        await checkNode();
                        let census = null;
                        try {
                            if (!fence.listMode || approved) {
                                remote = await open();
                                census = await readSessionCensus(remote, input, !!heldLock, () => checkInventory(state, accounts));
                            }
                        } catch (error) {
                            if (isIdentityChanged(error) || error?.remoteOutcomeUncertain === true
                                || (!heldLock && (isRuntimeForeignChange(error) || isNetworkObservationRequired(error)))) throw error;
                            // Unavailable, not zero.
                        }
                        finally {
                            if (typeof remote?.close === 'function') {
                                try { await remote.close(); } catch { census = null; }
                            }
                            remote = undefined;
                        }
                        const activeSessions = !transitProved && census?.activeSessions === 0 ? null : census?.activeSessions ?? null;
                        const activeIpsec = census?.activeIpsec ?? null;
                        const idle = activeSessions === 0 && activeIpsec === 0;
                        const activeClients = heldLock ? census?.activeClients ?? null : null;
                        let confirmable = approved && transitProved && accountCount === accounts.length
                            && (heldLock ? activeClients !== null : idle) && !!census?.census;
                        let directory;
                        if (heldLock && confirmable) {
                            try {
                                directory = await readDirectory(User.db);
                                confirmable = directory === null || sameAccounts(directory.accounts, accounts);
                            } catch { confirmable = false; }
                        }
                        await checkInventory(state, approved ? accounts : undefined);
                        const snapshot = Object.freeze({ nodeId: id, accountCount, activeSessions, activeIpsec,
                            ...(heldLock && { activeClients }), confirmable });
                        if (confirmable) proofStore.set(snapshot, { node, stateFence, accounts,
                            ...(heldLock && { state, transit: input.transit, directory, activeClients }),
                            binding: fence.binding, listMode: fence.listMode, source: fence.source, generation: fence.generation, census: census.census,
                            expires: performance.now() + PREVIEW_TTL_MS });
                        return snapshot;
                    }
                    const directorySnapshot = async session => {
                        const directory = await readDirectory(User.db, session);
                        if (directory) {
                            if (!sameAccounts(directory.accounts, accounts)) throw fail(NOT_OWNED);
                            return { directory };
                        }
                        // Backfill only from an unambiguous legacy cohort. No
                        // peer connection or live relay owner is needed.
                        if (!fence.listMode) return { directory, legacy: accounts.map(logicalAccount) };
                        const rows = await createStore(State, User, true).sourceRows(null, session);
                        const { legacy } = inspectAccountSources({ rows, listMode: true });
                        if (rows.directory || !legacy || !sameAccounts(legacy, accounts)) throw fail(CHANGED);
                        return { directory, legacy, rows };
                    };
                    const baselineDirectory = await directorySnapshot();
                    if (heldLock && !equal(proof.directory, baselineDirectory.directory)) throw fail(PREVIEW_CHANGED);
                    let retainedDirectory = baselineDirectory.directory;
                    const preserveDirectory = async session => {
                        if (!equal(await directorySnapshot(session), baselineDirectory) || env.ENCRYPTION_KEY !== chapKey) throw fail(CHANGED);
                        if (!retainedDirectory) retainedDirectory = await writeDirectory(User.db, null, baselineDirectory.legacy, session);
                    };
                    // Only a confirmed Apply receipt can classify the physical
                    // MAIN listener as transport. A PUT can change draft fields.
                    if (Link) input.transit = await readAppliedTransit(Link, id);
                    if (heldLock && !equal(proof.transit, input.transit)) throw fail(PREVIEW_CHANGED);
                    if (proof) {
                        const accountCount = await readAccountCount(User, id);
                        if (accountCount === null) throw fail(COUNT_UNAVAILABLE);
                        if (accountCount !== estimate.accountCount) throw fail(PREVIEW_CHANGED);
                        checkPreview();
                    }
                    await checkNode();
                    remote = await open();
                    if (typeof remote?.prepareRemove !== 'function' || typeof remote.remove !== 'function' || typeof remote.close !== 'function') {
                        throw fail('REBUILD_L2TP_REMOVE_BACKEND_UNAVAILABLE');
                    }
                    const checkReadAuthority = async () => { await checkInventory(state, accounts); checkPreview(); };
                    let expectedCensus;
                    if (proof || currentUsers) {
                        const census = await readSessionCensus(remote, input, !!heldLock, checkReadAuthority);
                        if (heldLock) {
                            if (!census || census.activeClients !== proof.activeClients || census.census !== proof.census) {
                                throw fail(PREVIEW_CHANGED);
                            }
                        } else {
                            if (!census) throw fail(COUNT_UNAVAILABLE);
                            if (census.activeSessions > 0) throw fail(SESSIONS_BUSY);
                            if (census.activeIpsec > 0) throw fail(IPSEC_BUSY);
                        }
                        if (!census.census) throw fail(COUNT_UNAVAILABLE);
                        if (proof && census.census !== proof.census) throw fail(PREVIEW_CHANGED);
                        expectedCensus = census.census;
                        await checkInventory(state, accounts);
                        checkPreview();
                    }
                    // No saved MAIN is sent or rebuilt here. The direct driver
                    // prepares subtraction against the current physical profiles.
                    // The actual host Remove must recheck the confirmed census.
                    let plan;
                    try {
                        plan = await remote.prepareRemove({ ...input, ...(expectedCensus && { expectedCensus }),
                            ...(heldLock && { retirement: true, ...(proof.activeClients > 0 && { drain: true }) }) },
                        checkReadAuthority);
                    } catch (error) {
                        if (heldLock && error?.code === DIRECT_PREVIEW_CHANGED) throw fail(PREVIEW_CHANGED);
                        if (error?.code === DIRECT_IPSEC_BUSY) throw fail(IPSEC_BUSY);
                        throw error;
                    }
                    if (plan == null) throw fail('REBUILD_L2TP_REMOVE_PLAN_INVALID');
                    await checkInventory(state, accounts);
                    checkPreview();

                    const transition = { status: 'removing', desiredState: 'absent', updatedAt: new Date() };
                    const reservation = { ...state, ...transition };
                    // All mutation filters bind the unique _id. Multi forms
                    // opt out of the driver's automatic retryable writes.
                    if (fence.listMode) {
                        // Include the actual reservation, not a topology probe,
                        // in the one-shot majority commit. All snapshot reads
                        // must belong to the session's model connection.
                        let readyToCommit = false;
                        try {
                            if (Node.db !== State.db) throw fail(RESERVATION_FAILED);
                            await transactOnce(State, User, async session => {
                                await checkInventory(state, accounts, session);
                                checkPreview();
                                await preserveDirectory(session);
                                const result = await State.updateMany(exactDocument(state, 'node'), { $set: transition },
                                    { session, timestamps: false });
                                if (result?.acknowledged !== true) throw fail(RESERVATION_FAILED);
                                if (result.matchedCount !== 1) throw fail(CHANGED);
                                await authority();
                                checkPreview();
                                readyToCommit = true;
                            });
                        } catch (error) {
                            if (error instanceof AcknowledgedCommitCleanupError) {
                                reserved = true;
                                throw fail('REBUILD_L2TP_REMOVE_RESERVATION_CLEANUP_FAILED');
                            }
                            // A later observation of `removing` cannot replace
                            // the missing commit ACK or permit a retry/restore.
                            reserved = readyToCommit;
                            throw readyToCommit ? fail(RESERVATION_UNKNOWN) : safe(error, RESERVATION_FAILED);
                        }
                    } else {
                        let result;
                        try { result = await State.updateMany(heldLock ? exactDocument(state, 'node') : stateFence, { $set: transition }, write); }
                        catch { throw fail(RESERVATION_UNKNOWN); }
                        if (result?.acknowledged !== true) throw fail(RESERVATION_UNKNOWN);
                        if (result.matchedCount !== 1) throw fail(CHANGED);
                        // Historical standalone Mongo: make the logical copy
                        // durable before any host removal or projection delete.
                        try { await preserveDirectory(); }
                        catch { throw fail(RESERVATION_UNKNOWN); }
                    }

                    reserved = true;
                    let revoked;
                    const guard = async () => {
                        if (revoked) throw revoked;
                        try {
                            const current = await checkInventory(reservation, accounts);
                            await checkDirectory(User.db, retainedDirectory);
                            if (heldLock && Link && !equal(await readAppliedTransit(Link, id), input.transit)) throw fail(CHANGED);
                            await authority();
                            return current;
                        }
                        catch (error) { revoked = safe(error); throw revoked; }
                    };
                    await guard();
                    try {
                        if (await remote.remove(plan, async () => { await guard(); }) !== true) throw fail(UNKNOWN);
                    } catch (error) {
                        if (isIdentityChanged(error)) throw error;
                        const changed = !!heldLock && error?.code === DIRECT_PREVIEW_CHANGED;
                        if ((!changed && !['REBUILD_L2TP_DIRECT_REMOVE_REFUSED', DIRECT_IPSEC_BUSY].includes(error?.code)) || error.commandSettled !== true
                            || error.remoteOutcomeUncertain) throw fail(UNKNOWN);
                        // DIRECT guarantees this receipt can only precede intent.
                        // Recheck our lease and exact inventories before a single
                        // non-retryable CAS. Never retire an account on refusal.
                        const { status, desiredState, updatedAt } = state;
                        const restore = { $set: { status, desiredState }, ...(Object.hasOwn(state, 'updatedAt')
                            ? {} : { $unset: { updatedAt: '' } }) };
                        if (Object.hasOwn(state, 'updatedAt')) restore.$set.updatedAt = updatedAt;
                        try {
                            const current = await guard();
                            // Whole-document BSON comparison is order-sensitive.
                            const reverted = await State.updateMany(heldLock ? exactDocument(current, 'node')
                                : exact(reservation, stateKeys), restore, write);
                            if (reverted?.acknowledged !== true || reverted.matchedCount !== 1) throw fail(CHANGED);
                            await checkInventory(state, accounts);
                        } catch (error) { if (isIdentityChanged(error)) throw error; throw fail(UNKNOWN); }
                        reserved = false;
                        throw fail(changed ? PREVIEW_CHANGED : error.code === DIRECT_IPSEC_BUSY ? IPSEC_BUSY : 'REBUILD_L2TP_REMOVE_REFUSED');
                    }

                    try {
                        await guard();
                        const settle = async session => {
                            if (session) await checkInventory(reservation, accounts, session);
                            await checkDirectory(User.db, retainedDirectory, session);
                            const options = session ? { session, timestamps: false } : write;
                            for (const row of accounts) {
                                // Match the entire list-mode row: enumerating known
                                // fields could miss a field added since the snapshot.
                                const filter = session || heldLock ? exactDocument(row, 'relayNode')
                                    : exact(row, [...new Set([...accountKeys, ...Object.keys(row)])]);
                                const deleted = await User.deleteMany(filter, options);
                                if (deleted?.acknowledged !== true || deleted.deletedCount !== 1) throw fail(CHANGED);
                            }
                            const current = await checkInventory(reservation, [], session);
                            const finished = await State.updateMany(heldLock ? exactDocument(current, 'node') : exact(reservation, stateKeys), {
                                $set: { status: 'not_installed', updatedAt: new Date() }, $unset: unsetInstalled,
                            }, options);
                            if (finished?.acknowledged !== true || finished.matchedCount !== 1) throw fail(CHANGED);
                            if (session) await authority();
                        };
                        // List mode requires atomic retirement and publication,
                        // even with one account. Preserve the non-transactional
                        // no-list bootstrap path for standalone MongoDB.
                        if (fence.listMode) await transactOnce(State, User, settle);
                        else await settle();
                    } catch (error) {
                        if (isIdentityChanged(error)) throw error;
                        if (phaseAware && error instanceof AcknowledgedCommitCleanupError) {
                            reserved = false;
                            removed = true;
                            throw fail(CLEANUP);
                        }
                        throw fail(FINISH_UNKNOWN);
                    }
                    removed = true;
                    return { executionMode: 'rebuild', status: 'not_installed', nodeId: id };
                } catch (error) {
                    primary = !heldLock && isUnconfirmedRuntimeWrite(error) ? phaseError(fail(UNKNOWN), 'unknown')
                        : !heldLock && isNetworkObservationRequired(error) ? Object.assign(fail(networkNotReadyDetails.code), networkNotReadyDetails)
                        : !heldLock && isRuntimeForeignChange(error) ? Object.assign(fail(runtimeForeignChange), { retryAllowed: false })
                            : safe(error);
                    if (phaseAware && (reserved || primary.code === RESERVATION_UNKNOWN)) {
                        retainLock?.();
                        phaseError(primary, 'unknown');
                    } else if (removed) {
                        phaseError(primary, 'removed');
                    } else if (reserved && isIdentityChanged(primary)) {
                        primary.retryAllowed = false;
                    }
                    throw primary;
                } finally {
                    if (typeof remote?.close === 'function') {
                        try { await remote.close(); }
                        catch { if (!primary) throw fail(CLEANUP); }
                    }
                }
            });
            return heldLock ? await removeUnderLock(heldLock.verify, heldLock.retain) : await locks.run(removeUnderLock);
        } catch (error) {
            // Do not allow lock/transport teardown to reclassify settlement.
            throw primary ?? (removed ? (phaseAware ? phaseError(fail(CLEANUP), 'removed') : fail(CLEANUP)) : safe(error));
        }
    };
    // Composition supplies a verifier/retain pair from the SAME active
    // global-lock acquisition and runs the existing pending-account fence.
    // Never accept a caller's stand-alone truthy callback or reacquire here.
    const retire = async (id, phase, estimate, heldVerify, retain) => {
        if (typeof withHeldLock !== 'function' || typeof heldVerify !== 'function') throw fail(LOCK_LOST);
        return withHeldLock(heldVerify, retain, async (verify, retainLock) => {
            if (verify !== heldVerify || typeof retainLock !== 'function' || await verify() === false) throw fail(LOCK_LOST);
            return run(id, phase, estimate, { verify, retain: retainLock });
        });
    };
    return {
        previewRemoveRelay: id => run(id, 'preview'),
        confirmRemoveRelay: (id, estimate) => run(id, 'confirm', estimate),
        previewRetireL2tp: (id, heldVerify, retain) => retire(id, 'preview', undefined, heldVerify, retain),
        confirmRetireL2tp: (id, estimate, heldVerify, retain) => retire(id, 'confirm', estimate, heldVerify, retain),
        // Trusted lifecycle caller only. The panel always uses confirmRemoveRelay.
        removeRelay: id => run(id, 'internal'),
    };
}

module.exports = { createRebuildRelayRemove };
