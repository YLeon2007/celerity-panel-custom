'use strict';

const { isRebuildEnabled } = require('./rebuildMode');
const { makeLocks, withNode } = require('./rebuildLocks');
const { t: translate } = require('../middleware/i18n');

const BLOCKED = 'REBUILD_L2TP_ROLE_BLOCKED';
const UNAVAILABLE = 'REBUILD_L2TP_ROLE_STATE_UNAVAILABLE';
const STALE = 'REBUILD_NODE_ROLE_CHANGED';
const reasons = Object.freeze({
    [UNAVAILABLE]: 'nodes.rebuildRoleStateUnavailable',
    [STALE]: 'nodes.rebuildRoleChanged',
    REBUILD_BUSY: 'nodes.rebuildRoleBusy',
    REBUILD_LOCK_LOST: 'nodes.rebuildRoleBusy',
});
const fail = code => Object.assign(new Error(code), { code });
const primary = query => query.read('primary').readConcern('majority').maxTimeMS(5000);

async function relayRoleBlock(nodeId) {
    let state;
    try {
        const State = require('../modules/relay-l2tp/models/relayL2tpStateModel');
        state = await primary(State.findOne({ node: nodeId }).select('status desiredState')).lean();
    } catch {
        return fail(UNAVAILABLE);
    }
    // No managed state row is the stock uninstalled baseline. Do not let a
    // contradictory install intent or an unknown/nonterminal status pass.
    if (!state || (state.status === 'not_installed' && ['absent', 'not_installed', undefined].includes(state.desiredState))) return null;

    // Panel account records (including disabled/pending ones), NOT live PPP
    // credentials or sessions. Rebuild has no relay-scoped session producer.
    let accountCount = null;
    try {
        const User = require('../modules/relay-l2tp/models/l2tpUserModel');
        const count = await primary(User.countDocuments({ relayNode: nodeId }));
        if (Number.isSafeInteger(count) && count >= 0) accountCount = count;
    } catch { /* Keep blocking even if the count could not be read. */ }
    return Object.assign(fail(BLOCKED), { accountCount, activeSessions: null });
}

async function saveNodeRole(nodeId, requestedRole, persist, { expectedRole } = {}) {
    if (!isRebuildEnabled() || requestedRole === undefined) return persist({});
    // Same singleton and lock ordering as Apply / Install / Remove. A fresh
    // primary role and L2TP state read must be inside the lock, as must the write.
    const Node = require('../models/hyNodeModel');
    return makeLocks().run(verify => withNode(nodeId, async () => {
        await verify();
        const node = await primary(Node.findById(nodeId).select('cascadeRole')).lean();
        if (!node) return null;
        if (node.cascadeRole === 'relay' && requestedRole !== 'relay') {
            const block = await relayRoleBlock(nodeId);
            if (block) throw block;
        }
        // Panel uses a hydrated RMW snapshot; don't save it after a competing role edit.
        if (expectedRole !== undefined && expectedRole !== (node.cascadeRole || 'standalone')) throw fail(STALE);
        await verify();
        return persist({ writeConcern: { w: 'majority' } });
    }));
}

function describeRoleError(error, t = translate) {
    const code = error?.code;
    if (code === BLOCKED) {
        const key = error.accountCount === null ? 'nodes.rebuildRoleCountUnavailable' : 'nodes.rebuildRoleBlocked';
        return { status: 409, code, message: t(key).replace('{count}', String(error.accountCount)),
            accountCount: error.accountCount, activeSessions: null };
    }
    if (!Object.hasOwn(reasons, code)) return null;
    return { status: code === UNAVAILABLE ? 503 : 409, code, message: t(reasons[code]) };
}

module.exports = { relayRoleBlock, saveNodeRole, describeRoleError };
