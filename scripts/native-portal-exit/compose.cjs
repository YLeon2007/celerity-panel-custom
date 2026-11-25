'use strict';
const fs = require('node:fs');
const { randomUUID } = require('node:crypto');
const { composeRebuildProfiles, ingressTag, egressTag } = require('/source/src/modules/relay-l2tp/services/rebuildTopologyComposer');
const a = JSON.parse(fs.readFileSync(0, 'utf8'));

const ids = Object.fromEntries(['p1', 'p2', 'p3', 'gateway', 'A', 'B', ...(a.chain ? ['tail'] : [])]
    .map((name, i) => [name, (i + 1).toString(16).repeat(24)]));
const role = name => ['gateway', 'tail'].includes(name) ? 'relay' : name.startsWith('p') ? 'portal' : 'bridge';
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
    link(2, a.chain ? 'tail' : 'gateway', 'A', 100),
    link(3, a.chain ? 'tail' : 'gateway', 'B', 200, other),
    link(4, a.chain ? 'tail' : 'gateway', 'A', 50, 'reverse', { enabled: true, domains: ['full:fixture.invalid'] }),
    link(5, 'p3', a.chain ? 'tail' : 'gateway', 100),
    ...(a.preferred ? [link(6, a.chain ? 'tail' : 'gateway', 'B', 30, 'reverse', { enabled: true, domains: ['full:other.invalid'] })] : []),
    ...(a.chain ? [link(7, 'gateway', 'tail', 100), link(8, 'gateway', 'tail', 200, other)] : []),
];
// Both pick B, even when the preferred (geo) channel is removed. Only P1
// keeps the relay's geo rules. P3 retains the original shared policy.
if (!a.chain) {
    links[0].rebuildExit = { nodeId: ids.B, relayGeo: true };
    links[1].rebuildExit = { nodeId: ids.B, relayGeo: false };
}
for (const [i, link] of links.entries()) {
    if (link.rebuildExit) descriptions[i].rebuildExit = link.rebuildExit;
}

const profiles = composeRebuildProfiles({ nodes, links,
    usersByNode: Object.fromEntries(Object.entries(users).map(([name, user]) => [ids[name], [user]])),
    dialerVersions: new Map(nodes.map(n => [n._id, n.cascadeRole === 'bridge' ? a.bridgeVersion : a.version])),
});
if (a.chain) {
    // Transport experiment only: use real generated tunnel pairs but inject
    // policy selection by hand until the compiler can produce it itself.
    const cfg = name => profiles.find(p => p.nodeId === ids[name] && p.profile === 'main').config;
    const tagged = index => ({ ...links[index], id: links[index]._id });
    const rule = (input, output, selector = {}) => ({ type: 'field', inboundTag: [ingressTag(tagged(input))],
        outboundTag: egressTag(tagged(output)), ...selector });
    const prepend = (name, rules) => {
        const list = cfg(name).routing.rules;
        list.splice(list.findIndex(r => r.ruleTag?.startsWith('rebuild-policy-')), 0, ...rules);
    };
    prepend('gateway', [rule(0, 7), rule(1, 8)]);
    prepend('tail', [rule(7, 4, { domain: ['full:fixture.invalid'] }), rule(7, 6), rule(8, 2)]);
}
const names = Object.fromEntries(Object.entries(ids).map(([k, v]) => [v, k]));
process.stdout.write(JSON.stringify({ profiles: profiles.map(p => ({ ...p, name: names[p.nodeId] })),
    users, links: descriptions }));
