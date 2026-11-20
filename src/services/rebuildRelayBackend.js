'use strict';

const { isIP } = require('node:net');
const { withNode } = require('./rebuildLocks');
const { componentFor } = require('./rebuildCoordinator');
const { canInstallRelay } = require('./rebuildRelayAuthorization');
const { runFreshRelayInstall } = require('./rebuildRelayInstall');
const { createStore, read } = require('./rebuildRelayBackendStore');
const { makeDesired } = require('./rebuildRelayBackendDesired');
const { compileRebuildGraph } = require('../modules/relay-l2tp/domain/rebuildTopologyCompiler');

const fail = code => Object.assign(new Error(code), { code });
const eligible = node => node?.type === 'xray' && node.active === true && node.cascadeRole === 'relay'
    && !node.useCustomConfig && !!isIP(node.ip);

async function readTopology(Node, Link, node, panelDomain, { appliedOnly = false } = {}) {
    const id = String(node._id);
    const inventory = await read(Link.find({ $or: [{ active: true }, { rebuildDelete: true }] })
        .select('portalNode bridgeNode active rebuildDelete lifecycle status geoRouting priority mode tunnelProtocol tunnelPort tunnelUuid'));
    // Offline also describes an applied link whose tunnel is unconfirmed.
    const applied = link => !link.rebuildDelete && !link.lifecycle && ['deployed', 'online', 'offline'].includes(link.status);
    const links = appliedOnly ? inventory.filter(applied) : inventory;
    const ids = new Set(componentFor(links, [id]));
    const scoped = links.filter(link => ids.has(String(link.portalNode)) && ids.has(String(link.bridgeNode)));
    // This is a graph inventory, not evidence that the data plane works.
    if (!appliedOnly && scoped.some(link => !applied(link))) {
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

// The production driver is loaded only on authorized, eligible first install.
function defaultDriver(options) {
    return require('./rebuildRelayDirect').createRelayDirect(options);
}

function createRebuildRelayBackend({ Node, Link, State, L2tpUser, locks, env, createRelayDirect = defaultDriver }) {
    return function installRelay(id) {
        const machineId = env.C3_REBUILD_L2TP_RELAY_MACHINE_ID;
        const authorize = () => canInstallRelay(env, id) && env.C3_REBUILD_L2TP_RELAY_MACHINE_ID === machineId;
        let store;
        return runFreshRelayInstall(id, {
            authorize, machineId,
            lock: fn => locks.run(verifyLock => withNode(id, async () => {
                await verifyLock();
                return fn(verifyLock);
            })),
            async inventory() {
                const node = await read(Node.findById(id).select('ip domain active type cascadeRole useCustomConfig ssh'));
                if (!eligible(node)) return { eligible: false };
                store = createStore(State, L2tpUser ?? require('../modules/relay-l2tp/models/l2tpUserModel'));
                const snapshot = await store.snapshot(id);
                if (!snapshot.pristine) return snapshot;
                const topology = await readTopology(Node, Link, node, env.PANEL_DOMAIN);
                const payload = makeDesired(id, await store.occupied(id), topology.controlPlaneAddresses, env.ENCRYPTION_KEY);
                return { ...snapshot, ...topology, ...payload, node, eligible: true, nodeId: id };
            },
            connect: inventory => createRelayDirect({ node: inventory.node, env }),
            prepare: ({ nodeId, desired, controlPlaneAddresses, carryDomain, transit }, remote) =>
                remote.prepare({ nodeId, desired, controlPlaneAddresses, carryDomain, ...(transit && { transit }) }),
            reserve: (inventory, backupId) => store.reserve({ ...inventory, backupId, machineId }),
            verifyReservation: reservation => store.verifyReservation(reservation),
            finish: (reservation, verifyLock) => store.finish(reservation, verifyLock),
            restore: (reservation, verifyLock) => store.restore(reservation, verifyLock),
        });
    };
}

module.exports = { createRebuildRelayBackend, readTopology };
