'use strict';

const { isIP } = require('node:net');
const { isDeepStrictEqual: equal } = require('node:util');
const { withNode } = require('./rebuildLocks');
const { canInstallRelay } = require('./rebuildRelayAuthorization');
const { read } = require('./rebuildRelayBackendStore');
const { readTopology } = require('./rebuildRelayBackend');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');

const fail = code => Object.assign(new Error(code), { code });
const DISABLED = 'REBUILD_L2TP_REMOVE_DISABLED';
const NOT_OWNED = 'REBUILD_L2TP_REMOVE_NOT_OWNED';
const CHANGED = 'REBUILD_L2TP_REMOVE_CHANGED';
const UNKNOWN = 'REBUILD_L2TP_REMOVE_OUTCOME_UNKNOWN';
const FINISH_UNKNOWN = 'REBUILD_L2TP_REMOVE_FINISH_OUTCOME_UNKNOWN';
const CLEANUP = 'REBUILD_L2TP_REMOVED_CLEANUP_FAILED';
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
    'lastErrorCode', 'lastError'];
const unsetInstalled = Object.fromEntries(installedFields.map(key => [key, '']));
const exact = (row, keys) => Object.fromEntries(keys.map(key => [key, Object.hasOwn(row, key)
    ? { $eq: row[key], ...(row[key] === null && { $exists: true }) } : { $exists: false }]));
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
    return async function removeRelay(id) {
        if (typeof id !== 'string' || id.length !== 24 || !/^[a-f0-9]{24}$/.test(id)) throw fail('REBUILD_INVALID_REQUEST');
        const machineId = env.C3_REBUILD_L2TP_RELAY_MACHINE_ID;
        const authorize = () => {
            if (!canInstallRelay(env, id) || env.C3_REBUILD_L2TP_RELAY_MACHINE_ID !== machineId) throw fail(DISABLED);
        };
        authorize();
        let primary, removed = false;
        try {
            return await locks.run(verifyLock => withNode(id, async () => {
                let remote;
                const authority = async () => {
                    authorize();
                    if (await verifyLock() === false) throw fail('REBUILD_LOCK_LOST');
                    authorize();
                };
                try {
                    await authority();
                    const getNode = () => read(Node.findById(id).select(nodeFields));
                    const node = await getNode();
                    if (String(node?._id) !== id || node.active !== true || node.type !== 'xray' || node.cascadeRole !== 'relay'
                        || node.useCustomConfig || typeof node.ip !== 'string' || !isIP(node.ip)) throw fail(NOT_OWNED);
                    const state = await read(State.findOne({ node: id }).select(stateFields));
                    const network = installedNetwork(state, id, machineId);
                    const User = L2tpUser ?? require('../modules/relay-l2tp/models/l2tpUserModel');
                    const users = () => read(User.find({ relayNode: id }).select('+passwordEncrypted').limit(2));
                    const account = ownedAccount(await users(), state, id);
                    const accountFence = exact(account, accountKeys);
                    const checkInventory = async (expected, expectAccount) => {
                        const [currentNode, currentState, currentUsers] = await Promise.all([
                            getNode(), read(State.findOne({ _id: state._id, node: id }).select(stateFields)), users(),
                        ]);
                        if (!equal(currentNode, node) || !currentState || !equal(exact(currentState, stateKeys), exact(expected, stateKeys))
                            || (expectAccount ? currentUsers.length !== 1 || !equal(exact(currentUsers[0], accountKeys), accountFence)
                                : currentUsers.length !== 0)) throw fail(CHANGED);
                        await authority();
                    };

                    await authority();
                    remote = createRelayDirect({ node, env });
                    if (typeof remote?.prepareRemove !== 'function' || typeof remote.remove !== 'function' || typeof remote.close !== 'function') {
                        throw fail('REBUILD_L2TP_REMOVE_BACKEND_UNAVAILABLE');
                    }
                    // No saved MAIN is sent or rebuilt here. The direct driver
                    // prepares subtraction against the current physical profiles.
                    // Apply may have changed transport listeners since Install.
                    // Unrelated drafts do not override the applied graph or the
                    // full HandlerService check for unrecognized inbounds.
                    const topology = Link && await readTopology(Node, Link, node, env.PANEL_DOMAIN, { appliedOnly: true });
                    await authority();
                    const plan = await remote.prepareRemove({ nodeId: id, backupId: state.backupId, network,
                        ...(topology && { transit: topology.transit ?? [] }) });
                    if (plan == null) throw fail('REBUILD_L2TP_REMOVE_PLAN_INVALID');
                    await checkInventory(state, true);

                    const transition = { status: 'removing', desiredState: 'absent', updatedAt: new Date() };
                    const reservation = { ...state, ...transition };
                    // All mutation filters bind the unique _id. Multi forms
                    // opt out of the driver's automatic retryable writes.
                    let result;
                    try { result = await State.updateMany(exact(state, stateKeys), { $set: transition }, write); }
                    catch { throw fail('REBUILD_L2TP_REMOVE_RESERVATION_OUTCOME_UNKNOWN'); }
                    if (result?.acknowledged !== true) throw fail('REBUILD_L2TP_REMOVE_RESERVATION_OUTCOME_UNKNOWN');
                    if (result.matchedCount !== 1) throw fail(CHANGED);

                    let revoked;
                    const guard = async () => {
                        if (revoked) throw revoked;
                        try { await checkInventory(reservation, true); }
                        catch (error) { revoked = safe(error); throw revoked; }
                    };
                    await guard();
                    try {
                        if (await remote.remove(plan, guard) !== true) throw fail(UNKNOWN);
                    } catch { throw fail(UNKNOWN); }

                    try {
                        await guard();
                        const deleted = await User.deleteMany(accountFence, write);
                        if (deleted?.acknowledged !== true || deleted.deletedCount !== 1) throw fail(CHANGED);
                        await checkInventory(reservation, false);
                        const finished = await State.updateMany(exact(reservation, stateKeys), {
                            $set: { status: 'not_installed', updatedAt: new Date() }, $unset: unsetInstalled,
                        }, write);
                        if (finished?.acknowledged !== true || finished.matchedCount !== 1) throw fail(CHANGED);
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
}

module.exports = { createRebuildRelayRemove };
