'use strict';

const { isIP } = require('node:net');
const { withNode } = require('./rebuildLocks');
const { componentFor } = require('./rebuildCoordinator');
const { captureRelayBinding } = require('./rebuildRelayAuthorization');
const { runFreshRelayInstall } = require('./rebuildRelayInstall');
const { createStore, read } = require('./rebuildRelayBackendStore');
const { makeDesired } = require('./rebuildRelayBackendDesired');
const { resolveAccountSources } = require('./rebuildRelayAccountInventory');
const { compileRebuildGraph } = require('../modules/relay-l2tp/domain/rebuildTopologyCompiler');

const fail = code => Object.assign(new Error(code), { code });
const eligible = (node, id, listMode) => String(node?._id) === id && node.type === 'xray'
    && node.active === true && node.cascadeRole === 'relay' && !node.useCustomConfig && (listMode || !!isIP(node.ip));

async function readTopology(Node, Link, node, panelDomain) {
    const id = String(node._id);
    const links = await read(Link.find({ $or: [{ active: true }, { rebuildDelete: true }] })
        .select('portalNode bridgeNode active rebuildDelete lifecycle status geoRouting priority mode tunnelProtocol tunnelPort tunnelUuid'));
    // Offline also describes an applied link whose tunnel is unconfirmed.
    const applied = link => !link.rebuildDelete && !link.lifecycle && ['deployed', 'online', 'offline'].includes(link.status);

    const ids = new Set(componentFor(links, [id]));
    const scoped = links.filter(link => ids.has(String(link.portalNode)) && ids.has(String(link.bridgeNode)));
    // This is a graph inventory, not evidence that the data plane works.
    if (scoped.some(link => !applied(link))) {
        throw fail('REBUILD_L2TP_TOPOLOGY_NOT_APPLIED');
    }
    const peers = ids.size > 1 ? await read(Node.find({ _id: { $in: [...ids].filter(n => n !== id) } })
        .select('type active useCustomConfig cascadeRole ip domain')) : [];
    if (peers.length !== ids.size - 1 || peers.some(n => n.type !== 'xray' || !n.active || n.useCustomConfig)) {
        throw fail('REBUILD_L2TP_TOPOLOGY_NOT_APPLIED');
    }
    const nodes = [node, ...peers];
    const { byNodeId } = compileRebuildGraph({ nodes, links: scoped, affectedNodeIds: [...ids] });
    const relay = byNodeId.get(id);
    const transit = [...relay.outgoing.filter(edge => edge.mode === 'reverse'),
        ...relay.incoming.filter(edge => edge.mode === 'forward' && edge.protocol === 'vless')]
        .map(({ id: linkId, mode, link }) => ({ linkId, mode, port: link.tunnelPort, uuid: link.tunnelUuid }));
    return {
        controlPlaneAddresses: [...new Set([panelDomain, ...nodes.flatMap(n => [n.ip, n.domain])].filter(Boolean))],
        carryDomain: relay.carryDomain,
        ...(transit.length && { transit }),
    };
}

// Load the production driver only after the locked inventory checks.
function defaultDriver(options) {
    return require('./rebuildRelayDirect').createRelayDirect(options);
}

async function precheckSource({ node, binding, installation, currentUsers }, createRelayDirect, env, checkAuthority) {
    await checkAuthority();
    const refused = () => fail('REBUILD_L2TP_ACCOUNT_SOURCE_PREFLIGHT_REFUSED');
    let remote, primary;
    try {
        remote = await createRelayDirect({ node, env, binding });
        if (typeof remote?.checkChap !== 'function' || typeof remote?.close !== 'function') throw refused();
        // The persisted source projection is an expected preimage, not evidence
        // of host state. DIRECT authenticates the host, receipt and actual CHAP
        // rows. This is an inspection only, with no requested CHAP delta.
        if ((await remote.checkChap(installation, currentUsers, currentUsers, checkAuthority))?.changed !== false) throw refused();
    } catch (error) {
        primary = error?.code === 'REBUILD_LOCK_LOST' ? error : refused();
        throw primary;
    } finally {
        try { await remote?.close?.(); }
        catch { if (!primary) throw refused(); }
    }
    await checkAuthority();
}

function createRebuildRelayBackend({ Node, Link, State, L2tpUser, locks, env, createRelayDirect = defaultDriver }) {
    return async function installRelay(id) {
        const fence = captureRelayBinding(env, id);
        const { machineId } = fence.binding;
        const authorize = () => { try { fence.check(); return true; } catch { return false; } };
        const getNode = (nodeId = id) => read(Node.findById(nodeId).select('ip domain active type cascadeRole useCustomConfig ssh'));
        let store;
        return runFreshRelayInstall(id, {
            authorize, machineId,
            lock: fn => locks.run(verifyLock => withNode(id, async () => {
                if (await verifyLock() === false) throw fail('REBUILD_LOCK_LOST');
                return fn(verifyLock);
            })),
            async inventory() {
                const node = await getNode();
                if (!eligible(node, id, fence.listMode)) return { eligible: false };
                fence.check(node);
                store = createStore(State, L2tpUser ?? require('../modules/relay-l2tp/models/l2tpUserModel'));
                const snapshot = await store.snapshot(id);
                if (!snapshot.pristine) return snapshot;
                const topology = await readTopology(Node, Link, node, env.PANEL_DOMAIN);
                const sourceSnapshot = await store.sourceRows(id);
                const key = env.ENCRYPTION_KEY;
                const sourceInventory = await resolveAccountSources({ nodeId: id, rows: sourceSnapshot, env, key,
                    readNode: getNode, listMode: fence.listMode });
                const payload = makeDesired(id, sourceInventory.occupied, topology.controlPlaneAddresses, key, sourceInventory);
                if (sourceInventory.inherited && payload.desired.users[0].ipAddress !== payload.desired.poolStart) {
                    throw fail('REBUILD_L2TP_ACCOUNT_INVENTORY_INVALID');
                }
                return { ...snapshot, ...topology, ...payload, sourceSnapshot, replicated: !!sourceInventory.inherited,
                    sources: sourceInventory.prechecks, key, node, eligible: true, nodeId: id };
            },
            verifyBinding: fence.listMode ? async inventory => {
                const current = await getNode();
                if (!eligible(current, id, true)) throw fail('REBUILD_L2TP_NOT_FRESH_RELAY');
                fence.check(current);
                if (inventory?.replicated && env.ENCRYPTION_KEY !== inventory.key) throw fail('REBUILD_L2TP_CREDENTIAL_KEY_INVALID');
                for (const source of inventory?.sources ?? []) await source.verifyBinding();
            } : undefined,
            precheckSources: async ({ sources }, checkAuthority) => {
                for (const source of sources) await precheckSource(source, createRelayDirect, env, checkAuthority);
            },
            connect: inventory => createRelayDirect({ node: inventory.node, env }),
            prepare: ({ nodeId, desired, controlPlaneAddresses, carryDomain, transit }, remote) =>
                remote.prepare({ nodeId, desired, controlPlaneAddresses, carryDomain, ...(transit && { transit }) }),
            reserve: (inventory, backupId, verifyLock) => store.reserve({ ...inventory, backupId, machineId }, verifyLock),
            verifyReservation: reservation => store.verifyReservation(reservation),
            finish: (reservation, verifyLock) => store.finish(reservation, verifyLock),
            restore: (reservation, verifyLock) => store.restore(reservation, verifyLock),
        });
    };
}

module.exports = { createRebuildRelayBackend };
