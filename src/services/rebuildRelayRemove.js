'use strict';

const { isIP } = require('node:net');
const { isDeepStrictEqual: equal } = require('node:util');
const { withNode } = require('./rebuildLocks');
const { captureRelayBinding, sameRelayBinding } = require('./rebuildRelayAuthorization');
const { read } = require('./rebuildRelayBackendStore');
const { projectRelayChap } = require('./rebuildRelayAccountInventory');
const { transactOnce } = require('./rebuildRelayInstallTransaction');
const { readAccountCount, readSessionCensus } = require('./rebuildRelayCounts');
const { readAppliedTransit } = require('./rebuildAppliedLink');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');

const fail = code => Object.assign(new Error(code), { code });
const DISABLED = 'REBUILD_L2TP_REMOVE_DISABLED';
const NOT_OWNED = 'REBUILD_L2TP_REMOVE_NOT_OWNED';
const CHANGED = 'REBUILD_L2TP_REMOVE_CHANGED';
const UNKNOWN = 'REBUILD_L2TP_REMOVE_OUTCOME_UNKNOWN';
const FINISH_UNKNOWN = 'REBUILD_L2TP_REMOVE_FINISH_OUTCOME_UNKNOWN';
const CLEANUP = 'REBUILD_L2TP_REMOVED_CLEANUP_FAILED';
const CONFIRM = 'REBUILD_L2TP_REMOVE_CONFIRMATION_REQUIRED';
const PREVIEW_CHANGED = 'REBUILD_L2TP_REMOVE_PREVIEW_CHANGED';
const COUNT_UNAVAILABLE = 'REBUILD_L2TP_REMOVE_COUNT_UNAVAILABLE';
const SESSIONS_BUSY = 'REBUILD_L2TP_REMOVE_SESSIONS_BUSY';
const PREVIEW_TTL_MS = 120_000;
// Private proof accompanying the immutable public estimate. Neither the
// installation receipt nor the host census is sent to the browser.
const previews = new WeakMap();
const safe = error => fail(typeof error?.code === 'string' && /^REBUILD_[A-Z0-9_]+$(?!\n)/.test(error.code)
    ? error.code : 'REBUILD_L2TP_REMOVE_FAILED');
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
const exactAccount = row => ({ ...exact(row, ['_id', 'relayNode']), $expr: { $eq: ['$$ROOT', { $literal: row }] } });
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

function createRebuildRelayRemove({ Link, Node, State, L2tpUser, locks, env, createRelayDirect = defaultDriver }) {
    const run = async (id, phase, estimate) => {
        if (typeof id !== 'string' || id.length !== 24 || !/^[a-f0-9]{24}$/.test(id)) throw fail('REBUILD_INVALID_REQUEST');
        let fence;
        try { fence = captureRelayBinding(env, id); } catch { throw fail(DISABLED); }
        const { machineId } = fence.binding;
        const chapKey = fence.listMode ? env.ENCRYPTION_KEY : undefined;
        const authorize = node => {
            try { fence.check(node); } catch (error) {
                if (error.code === 'REBUILD_L2TP_INSTALL_DISABLED') throw fail(DISABLED);
                throw error;
            }
        };
        const proof = phase === 'confirm' ? previews.get(estimate) : undefined;
        const checkPreview = () => {
            if (phase === 'confirm' && (!proof || estimate.nodeId !== id || performance.now() >= proof.expires)) {
                throw fail(CONFIRM);
            }
        };
        checkPreview();
        if (proof && (proof.listMode !== fence.listMode || !sameRelayBinding(proof.binding, fence.binding))) throw fail(PREVIEW_CHANGED);
        let primary, removed = false;
        try {
            return await locks.run(verifyLock => withNode(id, async () => {
                let remote;
                const authority = async () => {
                    authorize();
                    if (await verifyLock() === false) throw fail('REBUILD_LOCK_LOST');
                    authorize();
                    if (fence.listMode && env.ENCRYPTION_KEY !== chapKey) throw fail(CHANGED);
                };
                try {
                    await authority();
                    const getNode = session => read(Node.findById(id).select(nodeFields), session);
                    const node = await getNode();
                    if (String(node?._id) !== id || node.active !== true || node.type !== 'xray' || node.cascadeRole !== 'relay'
                        || node.useCustomConfig || (!fence.listMode && !isIP(node.ip))) throw fail(NOT_OWNED);
                    authorize(node);
                    const checkNode = async () => {
                        if (fence.listMode && !equal(await getNode(), node)) throw fail(CHANGED);
                        await authority();
                    };
                    const state = await read(State.findOne({ node: id }).select(stateFields));
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
                        if (!equal(currentNode, node) || !currentState || !equal(exact(currentState, stateKeys), exact(expected, stateKeys))
                            || (accounts && !equal(orderedAccounts(currentRows), accounts))) throw fail(CHANGED);
                        await authority();
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
                                remote = createRelayDirect({ node, env });
                                census = await readSessionCensus(remote, input);
                            }
                        } catch { /* Refusal or unavailable driver, not zero. */ }
                        finally {
                            if (typeof remote?.close === 'function') {
                                try { await remote.close(); } catch { census = null; }
                            }
                            remote = undefined;
                        }
                        if (!transitProved && census?.activeSessions === 0) census = null;
                        const confirmable = approved && accountCount === accounts.length && census?.activeSessions === 0;
                        await checkInventory(state, approved ? accounts : undefined);
                        const snapshot = Object.freeze({ nodeId: id, accountCount, activeSessions: census?.activeSessions ?? null,
                            confirmable });
                        if (confirmable) previews.set(snapshot, { node, stateFence, accounts,
                            binding: fence.binding, listMode: fence.listMode, census: census.census,
                            expires: performance.now() + PREVIEW_TTL_MS });
                        return snapshot;
                    }
                    // Only a confirmed Apply receipt can classify the physical
                    // MAIN listener as transport. A PUT can change draft fields.
                    if (Link) input.transit = await readAppliedTransit(Link, id);
                    if (proof) {
                        const accountCount = await readAccountCount(User, id);
                        if (accountCount === null) throw fail(COUNT_UNAVAILABLE);
                        if (accountCount !== estimate.accountCount) throw fail(PREVIEW_CHANGED);
                        checkPreview();
                    }
                    await checkNode();
                    remote = createRelayDirect({ node, env });
                    if (typeof remote?.prepareRemove !== 'function' || typeof remote.remove !== 'function' || typeof remote.close !== 'function') {
                        throw fail('REBUILD_L2TP_REMOVE_BACKEND_UNAVAILABLE');
                    }
                    let expectedCensus;
                    if (proof || currentUsers) {
                        const census = await readSessionCensus(remote, input);
                        if (!census) throw fail(COUNT_UNAVAILABLE);
                        if (census.activeSessions !== 0) throw fail(SESSIONS_BUSY);
                        if (proof && census.census !== proof.census) throw fail(PREVIEW_CHANGED);
                        expectedCensus = census.census;
                        await checkInventory(state, accounts);
                        checkPreview();
                    }
                    // No saved MAIN is sent or rebuilt here. The direct driver
                    // prepares subtraction against the current physical profiles.
                    // The actual host Remove must recheck the confirmed census.
                    const plan = await remote.prepareRemove({ ...input, ...(expectedCensus && { expectedCensus }) });
                    if (plan == null) throw fail('REBUILD_L2TP_REMOVE_PLAN_INVALID');
                    await checkInventory(state, accounts);
                    checkPreview();

                    const transition = { status: 'removing', desiredState: 'absent', updatedAt: new Date() };
                    const reservation = { ...state, ...transition };
                    // All mutation filters bind the unique _id. Multi forms
                    // opt out of the driver's automatic retryable writes.
                    let result;
                    try { result = await State.updateMany(stateFence, { $set: transition }, write); }
                    catch { throw fail('REBUILD_L2TP_REMOVE_RESERVATION_OUTCOME_UNKNOWN'); }
                    if (result?.acknowledged !== true) throw fail('REBUILD_L2TP_REMOVE_RESERVATION_OUTCOME_UNKNOWN');
                    if (result.matchedCount !== 1) throw fail(CHANGED);

                    let revoked;
                    const guard = async () => {
                        if (revoked) throw revoked;
                        try { await checkInventory(reservation, accounts); }
                        catch (error) { revoked = safe(error); throw revoked; }
                    };
                    await guard();
                    try {
                        if (await remote.remove(plan, guard) !== true) throw fail(UNKNOWN);
                    } catch (error) {
                        if (error?.code !== 'REBUILD_L2TP_DIRECT_REMOVE_REFUSED' || error.commandSettled !== true
                            || error.remoteOutcomeUncertain) throw fail(UNKNOWN);
                        // DIRECT guarantees this receipt can only precede intent.
                        // Recheck our lease and exact inventories before a single
                        // non-retryable CAS. Never retire an account on refusal.
                        const { status, desiredState, updatedAt } = state;
                        const restore = { $set: { status, desiredState }, ...(Object.hasOwn(state, 'updatedAt')
                            ? {} : { $unset: { updatedAt: '' } }) };
                        if (Object.hasOwn(state, 'updatedAt')) restore.$set.updatedAt = updatedAt;
                        try {
                            await guard();
                            const reverted = await State.updateMany(exact(reservation, stateKeys), restore, write);
                            if (reverted?.acknowledged !== true || reverted.matchedCount !== 1) throw fail(CHANGED);
                            await checkInventory(state, accounts);
                        } catch { throw fail(UNKNOWN); }
                        throw fail('REBUILD_L2TP_REMOVE_REFUSED');
                    }

                    try {
                        await guard();
                        const settle = async session => {
                            if (session) await checkInventory(reservation, accounts, session);
                            const options = session ? { session, timestamps: false } : write;
                            for (const row of accounts) {
                                // Match the entire list-mode row: enumerating known
                                // fields could miss a field added since the snapshot.
                                const filter = session ? exactAccount(row) : exact(row, [...new Set([...accountKeys, ...Object.keys(row)])]);
                                const deleted = await User.deleteMany(filter, options);
                                if (deleted?.acknowledged !== true || deleted.deletedCount !== 1) throw fail(CHANGED);
                            }
                            await checkInventory(reservation, [], session);
                            const finished = await State.updateMany(exact(reservation, stateKeys), {
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
                    } catch { throw fail(FINISH_UNKNOWN); }
                    removed = true;
                    return { executionMode: 'rebuild', status: 'not_installed', nodeId: id };
                } catch (error) {
                    primary = safe(error);
                    throw primary;
                } finally {
                    if (typeof remote?.close === 'function') {
                        try { await remote.close(); }
                        catch { if (!primary) throw fail(CLEANUP); }
                    }
                }
            }));
        } catch (error) {
            // Do not allow lock/transport teardown to reclassify settlement.
            throw primary ?? (removed ? fail(CLEANUP) : safe(error));
        }
    };
    return {
        previewRemoveRelay: id => run(id, 'preview'),
        confirmRemoveRelay: (id, estimate) => run(id, 'confirm', estimate),
        // Trusted lifecycle caller only. The panel always uses confirmRemoveRelay.
        removeRelay: id => run(id, 'internal'),
    };
}

module.exports = { createRebuildRelayRemove };
