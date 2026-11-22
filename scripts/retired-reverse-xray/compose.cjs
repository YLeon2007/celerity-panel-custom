'use strict';

const { randomUUID } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { composeRebuildProfiles } = require('./src/modules/relay-l2tp/services/rebuildTopologyComposer');

const { subscriber, portalApi, relayClient, relayApi, bridgeApi, reused, downstream } =
    JSON.parse(readFileSync(0, 'utf8'));
const lo = '127.0.0.1';
const node = (char, cascadeRole, port, apiPort) => ({
    _id: char.repeat(24), cascadeRole, ip: lo, type: 'xray', active: true, port,
    xray: { security: 'none', transport: 'tcp', apiPort },
});
const portal = node('a', 'portal', subscriber, portalApi);
const relay = node('b', 'relay', relayClient, relayApi);
const bridge = node('c', 'bridge', undefined, bridgeApi);
const reverse = (char, source, target, tunnelPort) => ({
    _id: char.repeat(24), portalNode: source._id, bridgeNode: target._id,
    active: true, mode: 'reverse', tunnelProtocol: 'vless', tunnelTransport: 'tcp',
    tunnelSecurity: 'none', tunnelEncryption: 'none', tunnelPort, tunnelUuid: randomUUID(),
});
const retired = reverse('d', portal, relay, reused);
const exit = reverse('e', relay, bridge, downstream);
const replacement = reverse('f', portal, bridge, reused);
const usersByNode = { [portal._id]: [{ userId: 'fixture-subscriber', xrayUuid: randomUUID() }] };

// This is a desired-graph fixture, not a call to relay DELETE. Use the stock
// compiler/composer for both complete inventories. The surviving portal's
// replacement edge intentionally reuses the retired edge's TCP endpoint.
const before = composeRebuildProfiles({ nodes: [portal, relay, bridge], links: [retired, exit], usersByNode });
const after = composeRebuildProfiles({ nodes: [portal, bridge], links: [replacement], usersByNode });
const profile = (entries, n, kind) => entries.find(p => p.nodeId === n._id && p.profile === kind).config;
const dial = entries => profile(entries, bridge, 'bridge').outbounds.find(o => o.settings?.reverse);
process.stdout.write(JSON.stringify({
    before: profile(before, portal, 'main'), after: profile(after, portal, 'main'),
    retired: profile(before, relay, 'main'), beforeExit: dial(before), afterExit: dial(after),
}));
