'use strict';

const { isRebuildEnabled } = require('./rebuildMode');
const { makeLocks, withNode } = require('./rebuildLocks');
const { t: translate } = require('../middleware/i18n');
const { readAccountCount, formatRelayCounts } = require('./rebuildRelayCounts');
const { assertNoPendingRelayAccounts } = require('./rebuildRelayAccountsStore');
const { assertNoIncidentLinks, assertNoRelayEnrollment } = require('./rebuildNodeDeleteGuard');
const { isPristine } = require('./rebuildRelayBackendStore');

const BLOCKED = 'REBUILD_L2TP_ROLE_BLOCKED';
const WRITE_BLOCKED = 'REBUILD_L2TP_NODE_WRITE_BLOCKED';
const UNAVAILABLE = 'REBUILD_L2TP_ROLE_STATE_UNAVAILABLE';
const reasons = Object.freeze({
    [UNAVAILABLE]: 'nodes.rebuildRoleStateUnavailable',
    REBUILD_BUSY: 'nodes.rebuildRoleBusy',
    REBUILD_LOCK_LOST: 'nodes.rebuildRoleBusy',
    REBUILD_L2TP_ACCOUNTS_BLOCKED: 'nodes.rebuildNodeAccountsPending',
    REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE: 'nodes.rebuildRoleStateUnavailable',
    REBUILD_NODE_HAS_LINKS: 'nodes.rebuildNodeHasLinks',
    REBUILD_NODE_RETIRE_REQUIRED: 'nodes.rebuildNodeRetireRequired',
    REBUILD_NODE_DELETE_UNAVAILABLE: 'nodes.rebuildNodeDeleteUnavailable',
});
const fail = code => Object.assign(new Error(code), { code });
const primary = query => query.read('primary').readConcern('majority').maxTimeMS(5000);

async function relayRoleBlock(nodeId, preview, code = BLOCKED, bareDelete = false) {
    let state;
    try {
        const State = require('../modules/relay-l2tp/models/relayL2tpStateModel');
        const fields = bareDelete ? '+pskEncrypted +rebuildInstallToken +rebuildMachineId' : 'status desiredState';
        state = await primary(State.findOne({ node: nodeId }).select(fields)).lean();
    } catch {
        return fail(UNAVAILABLE);
    }
    // No managed state row is the stock uninstalled baseline. Do not let a
    // contradictory install intent or an unknown/nonterminal status pass.
    if (bareDelete ? isPristine(state)
        : !state || (state.status === 'not_installed' && ['absent', 'not_installed', undefined].includes(state.desiredState))) return null;

    // Role writes never connect to the host just to decide a refusal. The
    // authenticated panel preview may supply a live estimate for display only.
    let estimate;
    try {
        if (preview) estimate = await preview(String(nodeId));
    } catch { /* Keep blocking on a busy, unowned, or unavailable preview. */ }
    const counts = estimate ?? Object.freeze({
        accountCount: await readAccountCount(require('../modules/relay-l2tp/models/l2tpUserModel'), nodeId),
        activeSessions: null,
        activeIpsec: null,
    });
    return Object.assign(fail(code), { counts, estimate });
}

const currentWrites = new WeakMap();
const nodeWriteVerifier = node => currentWrites.get(node);

async function withNodeWriterFence(write) {
    if (!isRebuildEnabled()) return write({}, async () => {});
    const Node = require('../models/hyNodeModel');
    return makeLocks().run(async verify => {
        await verify();
        await assertNoPendingRelayAccounts(Node.db);
        return write({ writeConcern: { w: 'majority' } }, verify);
    });
}

async function withNodeWrite(nodeId, write, { bareDelete = false, requireRemoval = false, fullSetup = false, select } = {}) {
    if (!isRebuildEnabled()) return write({}, undefined, async () => {});
    // Same singleton and lock ordering as Apply / Install / Remove. Never
    // admit from a route's previously loaded card or from a pending read made
    // outside the lock. Keep it held through host actions and related writes.
    const Node = require('../models/hyNodeModel');
    return withNodeWriterFence((options, verify) => withNode(nodeId, async () => {
        if (bareDelete) await assertNoIncidentLinks(require('../models/cascadeLinkModel'), nodeId);
        const query = primary(Node.findById(nodeId));
        if (select) query.select(select);
        const node = await query;
        if (!node) return null;
        if (fullSetup) await assertRelaySetupAllowed(node);
        else if (requireRemoval || bareDelete) await assertRelayNodeWritable(nodeId, WRITE_BLOCKED, bareDelete);
        if (bareDelete) await assertNoRelayEnrollment(Node, require('../modules/relay-l2tp/models/l2tpUserModel'), nodeId);
        await verify();
        currentWrites.set(node, verify);
        try { return await write(options, node, verify); }
        finally { currentWrites.delete(node); }
    }));
}

async function assertRelayNodeWritable(nodeId, code = WRITE_BLOCKED, bareDelete = false) {
    const block = await relayRoleBlock(nodeId, undefined, code, bareDelete);
    if (block) throw block;
}

async function assertRelaySetupAllowed(node) {
    await assertRelayNodeWritable(node._id);
    // A second Xray card for the same address still writes the same service.
    if (node.type === 'xray' && node.ip) {
        const Node = require('../models/hyNodeModel');
        const siblings = await primary(Node.find({ ip: node.ip, type: 'xray', _id: { $ne: node._id } }).select('_id')).lean();
        for (const sibling of siblings) await assertRelayNodeWritable(sibling._id);
    }
}

const sshKeys = ['port', 'username', 'password', 'privateKey'];
function changesIdentityField(node, key, value) {
    return (value == null ? value : node.schema.path(key).cast(value)) !== node.get(key);
}

// Only invalidate L2TP ownership on a real change. In particular, the panel
// always resubmits the SSH port and username when saving a cosmetic edit.
async function assertNodeEditAllowed(node, updates, sshUpdates = {}) {
    if (!node) return; // Non-rebuild write.
    const changed = key => Object.hasOwn(updates, key) && changesIdentityField(node, key, updates[key]);
    if (changed('cascadeRole')) await assertRelayNodeWritable(node._id, BLOCKED);
    if (['ip', 'type', 'active', 'useCustomConfig', ...sshKeys.map(key => `ssh.${key}`)].some(changed)
        || (Object.hasOwn(updates, 'ssh') && sshKeys.some(key => changesIdentityField(node, `ssh.${key}`, updates.ssh?.[key])))) {
        await assertRelayNodeWritable(node._id);
    }

    // A same-address edit also writes the sibling cards. Check them *before*
    // the primary edit, including when its own submitted SSH values are a no-op.
    if (node.ip && !changed('ip') && Object.keys(sshUpdates).length) {
        const Node = require('../models/hyNodeModel');
        const siblings = await primary(Node.find({ ip: node.ip, _id: { $ne: node._id } }).select('ssh'));
        for (const sibling of siblings) {
            if (Object.entries(sshUpdates).some(([key, value]) => changesIdentityField(sibling, key, value))) {
                await assertRelayNodeWritable(sibling._id);
            }
        }
    }
}

function describeRoleError(error, t = translate) {
    const code = error?.code;
    if (code === BLOCKED || code === WRITE_BLOCKED) {
        const { accountCount, activeSessions, activeIpsec } = error.counts;
        const key = code === BLOCKED ? 'nodes.rebuildRoleBlocked' : 'nodes.rebuildNodeWriteBlocked';
        return { status: 409, code, message: t(key).replace('{counts}', formatRelayCounts(error.counts, t)),
            accountCount, activeSessions, activeIpsec };
    }
    if (!Object.hasOwn(reasons, code)) return null;
    return { status: [UNAVAILABLE, 'REBUILD_NODE_DELETE_UNAVAILABLE'].includes(code) ? 503 : 409, code, message: t(reasons[code]),
        ...(error.retryAllowed === false && { retryAllowed: false }) };
}

module.exports = { relayRoleBlock, withNodeWriterFence, withNodeWrite, nodeWriteVerifier, assertNodeEditAllowed, assertRelaySetupAllowed, describeRoleError };
