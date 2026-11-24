'use strict';
const fs = require('node:fs');
const { randomUUID } = require('node:crypto');
const { composeRebuildProfiles } = require('/source/src/modules/relay-l2tp/services/rebuildTopologyComposer');
const a = JSON.parse(fs.readFileSync(0, 'utf8'));

const ids = Object.fromEntries(['p1', 'p2', 'p3', 'gateway', 'A', 'B']
    .map((name, i) => [name, (i + 1).toString(16).repeat(24)]));
const role = name => name === 'gateway' ? 'relay' : name.startsWith('p') ? 'portal' : 'bridge';
const labels = Object.keys(ids);
const nodes = labels.map(name => ({
    _id: ids[name], cascadeRole: role(name), ip: '127.0.0.1', type: 'xray', active: true,
    ...(role(name) === 'bridge' ? {} : { port: a.ports[name] }),
    xray: { security: 'none', transport: 'tcp', apiPort: a.ports[`api-${name}`] },
}));
const users = Object.fromEntries(labels.filter(name => role(name) === 'portal')
    .map(name => [name, { userId: `synthetic-${name}`, xrayUuid: randomUUID() }]));
const descriptions = [];
function link(n, source, target, priority, mode = 'reverse', geoRouting) {
    const _id = (n + 8).toString(16).repeat(24);
    const tunnelPort = a.ports[`link-${n}`];
    descriptions.push({ index: n, id: _id, source, target, mode, port: tunnelPort });
    return { _id, portalNode: ids[source], bridgeNode: ids[target], mode, priority, active: true,
        tunnelPort, tunnelProtocol: 'vless', tunnelUuid: randomUUID(), tunnelTransport: 'tcp',
        tunnelEncryption: 'none', tunnelSecurity: 'reality', tcpFastOpen: false,
        ...a.reality[n], ...(geoRouting && { geoRouting }) };
}
const other = a.mode === 'mixed' ? 'forward' : 'reverse';
const links = [
    link(0, 'p1', 'gateway', 100),
    link(1, 'p2', 'gateway', 100, other),
    link(2, 'gateway', 'A', 100),
    link(3, 'gateway', 'B', 200, other),
    link(4, 'gateway', 'A', 50, 'reverse', { enabled: true, domains: ['full:fixture.invalid'] }),
    link(5, 'p3', 'gateway', 100),
    ...(a.preferred ? [link(6, 'gateway', 'B', 30, 'reverse', { enabled: true, domains: ['full:other.invalid'] })] : []),
];
// Both pick B, even when the preferred (geo) channel is removed. Only P1
// keeps the relay's geo rules. P3 retains the original shared policy.
links[0].rebuildExit = { nodeId: ids.B, relayGeo: true };
links[1].rebuildExit = { nodeId: ids.B, relayGeo: false };
for (const [i, link] of links.entries()) {
    if (link.rebuildExit) descriptions[i].rebuildExit = link.rebuildExit;
}

const profiles = composeRebuildProfiles({ nodes, links,
    usersByNode: Object.fromEntries(Object.entries(users).map(([name, user]) => [ids[name], [user]])),
    dialerVersions: new Map(nodes.map(n => [n._id, n.cascadeRole === 'bridge' ? a.bridgeVersion : a.version])),
});
const names = Object.fromEntries(Object.entries(ids).map(([k, v]) => [v, k]));
process.stdout.write(JSON.stringify({ profiles: profiles.map(p => ({ ...p, name: names[p.nodeId] })),
    users, links: descriptions }));
