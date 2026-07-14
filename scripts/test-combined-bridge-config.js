'use strict';

const assert = require('assert');
const configGenerator = require('../src/services/configGenerator');

function link(id, portalIp, port, domain) {
    return {
        _id: id,
        name: `link-${id}`,
        tunnelUuid: `00000000-0000-4000-8000-${String(id).padStart(12, '0')}`,
        tunnelPort: port,
        tunnelDomain: domain,
        tunnelProtocol: 'vless',
        tunnelSecurity: 'none',
        tunnelTransport: 'tcp',
        portalNode: { _id: `portal-${id}`, ip: portalIp, name: `portal-${id}` },
    };
}

const links = [
    link('11111111', '95.105.78.83', 10086, 'portal-a.reverse.internal'),
    link('22222222', '95.161.192.30', 10087, 'portal-b.reverse.internal'),
];

assert.strictEqual(typeof configGenerator.generateCombinedBridgeConfig, 'function', 'generateCombinedBridgeConfig must be exported');

const config = JSON.parse(configGenerator.generateCombinedBridgeConfig(links));
const loggedConfig = JSON.parse(configGenerator.generateCombinedBridgeConfig(links, {
    accessLog: '/var/log/xray-bridge/access.log',
}));

const bridges = config.reverse?.bridges || [];
const outbounds = config.outbounds || [];
const rules = config.routing?.rules || [];

assert.strictEqual(bridges.length, 2, 'must create one reverse bridge per active link');
assert.strictEqual(config.log?.access, undefined, 'access logging must remain opt-in');
assert.strictEqual(loggedConfig.log?.access, '/var/log/xray-bridge/access.log', 'bridge sidecar must emit access logs to its own file');
assert.deepStrictEqual(loggedConfig.reverse, config.reverse, 'access logging must not alter reverse config');
assert.deepStrictEqual(loggedConfig.outbounds, config.outbounds, 'access logging must not alter outbounds');
assert.deepStrictEqual(loggedConfig.routing, config.routing, 'access logging must not alter routing');
assert.deepStrictEqual(bridges.map(b => b.tag).sort(), ['bridge-11111111', 'bridge-22222222']);
assert.deepStrictEqual(bridges.map(b => b.domain).sort(), ['11111111.portal-a.reverse.internal', '22222222.portal-b.reverse.internal']);

for (const id of ['11111111', '22222222']) {
    assert(outbounds.some(o => o.tag === `tunnel-${id}`), `missing tunnel outbound for ${id}`);
    assert(rules.some(r => r.outboundTag === `tunnel-${id}`), `missing domain -> tunnel rule for ${id}`);
    assert(rules.some(r => Array.isArray(r.inboundTag) && r.inboundTag.includes(`bridge-${id}`) && r.outboundTag === 'freedom'), `missing bridge -> freedom rule for ${id}`);
}

assert(outbounds.some(o => o.tag === 'freedom'), 'missing freedom outbound');
assert(outbounds.some(o => o.tag === 'blackhole'), 'missing blackhole outbound');

const portalConfig = { inbounds: [], outbounds: [{ tag: 'direct', protocol: 'freedom' }], routing: { rules: [] } };
configGenerator.applyReversePortal(portalConfig, links, ['client-in']);
assert.deepStrictEqual(
    portalConfig.reverse.portals.map(p => p.domain).sort(),
    ['11111111.portal-a.reverse.internal', '22222222.portal-b.reverse.internal'],
    'portal and bridge configs must use the same per-link tunnel domains'
);
assert(portalConfig.routing.rules.some(r => JSON.stringify(r.domain) === JSON.stringify(['full:11111111.portal-a.reverse.internal'])), 'missing portal connector rule for first unique domain');
assert(portalConfig.routing.rules.some(r => JSON.stringify(r.domain) === JSON.stringify(['full:22222222.portal-b.reverse.internal'])), 'missing portal connector rule for second unique domain');

console.log('combined bridge config test passed');
