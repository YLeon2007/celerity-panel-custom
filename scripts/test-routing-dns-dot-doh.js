'use strict';

/**
 * Regression coverage for Split DNS remote resolver settings.
 *
 * The panel exposes separate optional DoT and DoH inputs. Runtime selection is:
 * DoH when filled, otherwise DoT, otherwise Quad9 defaults.
 */

const assert = require('assert');
const fs = require('fs');
const subscription = require('../src/routes/subscription');

assert(subscription._test, 'subscription route must expose test helpers');
assert.strictEqual(typeof subscription._test.buildHappRoutingProfile, 'function');
assert.strictEqual(typeof subscription._test.buildXrayDns, 'function');
assert.strictEqual(typeof subscription._test.buildSingboxDns, 'function');
assert.strictEqual(typeof subscription._test.buildSingboxRules, 'function');
assert.strictEqual(typeof subscription._test.generateSingboxJSON, 'function');
assert.strictEqual(typeof subscription._test.generateClashYAML, 'function');

const quad9Routing = {
    enabled: true,
    dns: { domestic: '', dot: '', doh: '' },
    rules: [],
};
const quad9HappProfile = subscription._test.buildHappRoutingProfile(quad9Routing);
assert(quad9HappProfile, 'HAPP routing profile must exist even when no split rules are configured');
assert.strictEqual(quad9HappProfile.RemoteDNSType, 'DoH');
assert.strictEqual(quad9HappProfile.RemoteDNSDomain, 'https://dns.quad9.net/dns-query');
assert.strictEqual(quad9HappProfile.RemoteDNSIP, '9.9.9.9');
assert.deepStrictEqual(quad9HappProfile.DnsHosts, { 'dns.quad9.net': '9.9.9.9' });
assert.strictEqual(quad9HappProfile.DomesticDNSIP, '9.9.9.9');
assert.deepStrictEqual(subscription._test.buildXrayDns([], quad9Routing.dns), [
    'https://dns.quad9.net/dns-query',
    '9.9.9.9',
]);

const manualDohRouting = {
    enabled: true,
    dns: { domestic: '', dot: 'tls://1.1.1.1', doh: 'https://dns.google/dns-query' },
    rules: [],
};
const manualDohProfile = subscription._test.buildHappRoutingProfile(manualDohRouting);
assert.strictEqual(manualDohProfile.RemoteDNSType, 'DoH', 'manual DoH must take priority over DoT');
assert.strictEqual(manualDohProfile.RemoteDNSDomain, 'https://dns.google/dns-query');
assert.strictEqual(manualDohProfile.RemoteDNSIP, '8.8.8.8');
assert.deepStrictEqual(subscription._test.buildXrayDns([], manualDohRouting.dns), [
    'https://dns.google/dns-query',
    '8.8.8.8',
]);

const manualDotRouting = {
    enabled: true,
    dns: { domestic: '', dot: 'tls://1.1.1.1', doh: '' },
    rules: [],
};
const manualDotProfile = subscription._test.buildHappRoutingProfile(manualDotRouting);
assert.strictEqual(manualDotProfile.RemoteDNSType, 'DoT', 'manual DoT must be used when DoH is empty');
assert.strictEqual(manualDotProfile.RemoteDNSIP, '1.1.1.1');
assert.deepStrictEqual(subscription._test.buildXrayDns([], manualDotRouting.dns), [
    'https://1.1.1.1/dns-query',
    '1.1.1.1',
]);

const legacyRemoteRouting = {
    enabled: true,
    dns: { domestic: '9.9.9.9', remote: 'tls://1.1.1.1' },
    rules: [],
};
assert.strictEqual(subscription._test.buildHappRoutingProfile(legacyRemoteRouting).RemoteDNSType, 'DoT',
    'legacy single remote field must remain backward-compatible until the new panel fields are saved');

const singboxQuad9Dns = subscription._test.buildSingboxDns([], quad9Routing.dns);
assert.deepStrictEqual(singboxQuad9Dns.servers[0], {
    type: 'https',
    tag: 'dns-remote',
    server: 'dns.quad9.net',
    domain_resolver: 'dns-local',
    detour: 'proxy',
}, 'sing-box DoH must be dialed through the proxy tunnel and keep Quad9 default');
assert.deepStrictEqual(singboxQuad9Dns.servers[1], { type: 'udp', tag: 'dns-direct', server: '9.9.9.9', detour: 'direct' });
assert.strictEqual(singboxQuad9Dns.final, 'dns-remote');

const singboxManualDohDns = subscription._test.buildSingboxDns([], manualDohRouting.dns);
assert.deepStrictEqual(singboxManualDohDns.servers[0], {
    type: 'https',
    tag: 'dns-remote',
    server: 'dns.google',
    domain_resolver: 'dns-local',
    detour: 'proxy',
}, 'manual sing-box DoH must be dialed through the proxy tunnel');

const singboxManualDotDns = subscription._test.buildSingboxDns([], manualDotRouting.dns);
assert.deepStrictEqual(singboxManualDotDns.servers[0], {
    type: 'tls',
    tag: 'dns-remote',
    server: '1.1.1.1',
    domain_resolver: 'dns-local',
    detour: 'proxy',
}, 'manual sing-box DoT must be dialed through the proxy tunnel');

const singboxRuleResult = subscription._test.buildSingboxRules([
    { enabled: true, action: 'direct', type: 'geosite', value: 'ru' },
    { enabled: true, action: 'direct', type: 'geoip', value: 'ru' },
    { enabled: true, action: 'direct', type: 'geoip', value: 'telegram' },
    { enabled: true, action: 'block', type: 'geosite', value: '../bad' },
]);
assert(singboxRuleResult.ruleSets.some(rs => rs.tag === 'geosite-category-ru'), 'sing-box geosite ru must map to published category-ru rule-set');
assert(singboxRuleResult.ruleSets.some(rs => rs.tag === 'geoip-ru'), 'sing-box geoip country code must be kept');
assert(!JSON.stringify(singboxRuleResult).includes('telegram'), 'unsupported sing-box geoip provider lists must be dropped instead of breaking the config');
assert(!JSON.stringify(singboxRuleResult).includes('../bad'), 'invalid sing-box rule-set values must not escape rule-set URLs');

const singboxEmptyRulesConfig = subscription._test.generateSingboxJSON(
    { userId: 'tester', password: 'secret' },
    [{ type: 'hysteria', name: 'Node', ip: '203.0.113.10', port: 443, flag: '🇩🇪', obfs: {} }],
    quad9Routing,
);
assert.strictEqual(singboxEmptyRulesConfig.dns.servers[0].server, 'dns.quad9.net', 'routing enabled with empty rules must still use selected Quad9 DNS');
assert.strictEqual(singboxEmptyRulesConfig.dns.servers[0].detour, 'proxy', 'sing-box encrypted DNS must stay inside tunnel even with empty rules');
assert.strictEqual(singboxEmptyRulesConfig.route.default_domain_resolver, 'dns-direct', 'sing-box must resolve outbound server names directly before the tunnel is up');
assert(!JSON.stringify(singboxEmptyRulesConfig).includes('223.5.5.5'), 'custom fork must not fall back to upstream AliDNS when routing DNS is configured');

const clashEmptyRulesYaml = subscription._test.generateClashYAML(
    { userId: 'tester', password: 'secret' },
    [{ type: 'hysteria', name: 'Node', ip: '203.0.113.10', port: 443, flag: '🇩🇪', obfs: {} }],
    quad9Routing,
);
assert(clashEmptyRulesYaml.includes('dns:'), 'Clash must publish DNS section when routing DNS is enabled even if split rules are empty');
assert(clashEmptyRulesYaml.includes('https://dns.quad9.net/dns-query'), 'Clash must keep custom Quad9 DoH for empty-rules routing');
assert(!clashEmptyRulesYaml.includes('tls://1.1.1.1'), 'Clash must not fall back to old upstream DoT default');

const settingsModelSource = fs.readFileSync('src/models/settingsModel.js', 'utf8');
assert(settingsModelSource.includes("domestic: { type: String, default: '9.9.9.9' }"));
assert(settingsModelSource.includes("dot:      { type: String, default: '' }"));
assert(settingsModelSource.includes("doh:      { type: String, default: '' }"));

const settingsRouteSource = fs.readFileSync('src/routes/panel/settings.js', 'utf8');
assert(settingsRouteSource.includes('const legacyRemoteKey = `${prefix}.dns.remote`;'), 'settings POST must keep reading legacy *.dns.remote');
assert(settingsRouteSource.includes("readRoutingDnsFormValues(req.body, 'routing')"));
assert(settingsRouteSource.includes("readRoutingDnsFormValues(req.body, 'routingIos')"));
assert(settingsRouteSource.includes("updates['routing.dns.remote'] = routingDns.remote"));
assert(settingsRouteSource.includes("updates['routingIos.dns.remote'] = routingIosDns.remote"));
assert(settingsRouteSource.includes('const dotKey = `${prefix}.dns.dot`;'));
assert(settingsRouteSource.includes('const dohKey = `${prefix}.dns.doh`;'));
assert(settingsRouteSource.includes("readRoutingDnsFormValues(req.body, 'routingIos')"));

const routingViewSource = fs.readFileSync('views/partials/settings/routing.ejs', 'utf8');
assert(routingViewSource.includes('name="routing.dns.dot"'));
assert(routingViewSource.includes('name="routing.dns.doh"'));
assert(routingViewSource.includes("settings?.routing?.dns?.dot || ''"));
assert(routingViewSource.includes("settings?.routing?.dns?.doh || ''"));

const routingIosViewSource = fs.readFileSync('views/partials/settings/routing-ios.ejs', 'utf8');
assert(routingIosViewSource.includes('name="routingIos.dns.dot"'));
assert(routingIosViewSource.includes('name="routingIos.dns.doh"'));
assert(routingIosViewSource.includes("settings?.routingIos?.dns?.dot || ''"));
assert(routingIosViewSource.includes("settings?.routingIos?.dns?.doh || ''"));

for (const locale of ['ru', 'en', 'zh-CN']) {
    const source = fs.readFileSync(`src/locales/${locale}.json`, 'utf8');
    assert(source.includes('routingDnsRemoteDot'), `${locale} locale must label DoT`);
    assert(source.includes('routingDnsRemoteDoh'), `${locale} locale must label DoH`);
}

console.log('routing DNS DoT/DoH tests passed');
