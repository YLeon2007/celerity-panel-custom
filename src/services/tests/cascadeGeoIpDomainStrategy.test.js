'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
process.env.PANEL_DOMAIN ||= 'test.invalid';
process.env.ACME_EMAIL ||= 'test@test.invalid';
process.env.ENCRYPTION_KEY ||= 'a'.repeat(32);
process.env.SESSION_SECRET ||= 'b'.repeat(32);
const { applyReversePortal, applyForwardChain } = require('../configGenerator');

const base = () => ({ routing: { domainStrategy: 'IPIfNonMatch', rules: [] }, inbounds: [], outbounds: [] });
const link = (id, geo) => ({
    _id: `507f1f77bcf86cd7994390${id}`,
    tunnelProtocol: 'vless', tunnelSecurity: 'none', tunnelUuid: '00000000-0000-4000-8000-000000000001',
    tunnelPort: 12345, bridgeNode: { ip: '127.0.0.2' },
    geoRouting: geo ? { enabled: true, geoip: ['ru'] } : { enabled: false },
});

test('reverse geoip routing resolves domain targets before the default inbound catch-all', () => {
    const c = base();
    applyReversePortal(c, [link('01', true), link('02', false)], ['vless-in']);
    assert.equal(c.routing.domainStrategy, 'IPOnDemand');
    assert(c.routing.rules.find(r => r.ip?.includes('geoip:ru')));
});

test('forward geoip branch resolves domain targets before default route', () => {
    const c = base();
    applyForwardChain(c, [link('01', false)], ['vless-in'], [], [{ link: link('02', true) }]);
    assert.equal(c.routing.domainStrategy, 'IPOnDemand');
    assert(c.routing.rules.find(r => r.ip?.includes('geoip:ru')));
});

test('no geoip branch leaves explicit routing strategy alone', () => {
    const c = base();
    applyForwardChain(c, [link('01', false)], ['vless-in']);
    assert.equal(c.routing.domainStrategy, 'IPIfNonMatch');
});
