'use strict';

const { ingressTag, egressTag } = require('/source/src/modules/relay-l2tp/services/rebuildTopologyComposer');

const hexId = value => typeof value === 'string' && /^[a-f0-9]{24}(?![\s\S])/.test(value);
const port = value => Number.isInteger(value) && value >= 1 && value <= 65535;
const missing = () => Object.assign(new Error('REBUILD_SCOPED_TRANSIT_PROBE_INVALID'), { code: 'REBUILD_SCOPED_TRANSIT_PROBE_INVALID' });
const need = valid => { if (!valid) throw missing(); };
const one = (rows, predicate) => {
    need(Array.isArray(rows));
    const selected = rows.filter(predicate);
    need(selected.length === 1);
    return selected[0];
};
const block = { tag: 'block', protocol: 'blackhole' };
const loopback = '127.0.0.1';
const probeIn = 'rebuild-proof-request', proofOut = 'rebuild-proof-response';
const tcp = row => row?.streamSettings?.network === 'tcp';
const accountId = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);

// Lab-only transport probe. Extract the listener/dialer from candidate MAIN profiles;
// preserve the real port, authentication, binary-specific wire options and
// direction. This tiny pair has no MAIN users, PPP, DNS or direct escape.
// Producing it is NOT readiness: the caller must supervise both processes and
// independently prove the exact channel and a fresh application round trip.
function transitProofProfiles({ channel, profiles, requestPort, responderPort }) {
    const { id, source, target, mode, physicalId, link } = channel;
    need([id, source, target, physicalId].every(hexId) && id !== physicalId && source !== target && ['forward', 'reverse'].includes(mode)
        && port(requestPort) && port(responderPort) && requestPort !== responderPort);
    const sourceConfig = one(profiles, row => row?.nodeId === source && row.profile === 'main').config;
    const targetConfig = one(profiles, row => row?.nodeId === target && row.profile === 'main').config;
    const reverse = mode === 'reverse', suffix = id.slice(-8), inbound = ingressTag(channel), outbound = egressTag(channel);
    const listener = one((reverse ? sourceConfig : targetConfig)?.inbounds,
        row => row?.tag === (reverse ? `rebuild-rp-conn-${suffix}` : inbound));
    const dialer = one((reverse ? targetConfig : sourceConfig)?.outbounds,
        row => row?.tag === (reverse ? `rebuild-rp-dial-${suffix}` : outbound));
    one(targetConfig?.routing?.rules, rule => rule?.ruleTag === `rebuild-policy-transit-${suffix}-default`
        && Array.isArray(rule.inboundTag) && rule.inboundTag.length === 1 && rule.inboundTag[0] === inbound);
    const accounts = listener.settings?.clients;
    const endpoint = reverse ? dialer.settings : one(dialer.settings?.vnext, () => true);
    const users = reverse ? [endpoint] : endpoint?.users;
    need(tcp(listener) && tcp(dialer) && ['vless', 'vmess'].includes(listener.protocol) && dialer.protocol === listener.protocol
        && port(listener.port) && listener.port === link?.tunnelPort && endpoint?.port === listener.port
        && endpoint.address === loopback && requestPort !== listener.port && responderPort !== listener.port
        && Array.isArray(accounts) && accounts.length === 1 && accountId(accounts[0]?.id)
        && Array.isArray(users) && users.length === 1 && accounts[0].id === users[0]?.id && users[0].id === link.tunnelUuid);
    if (reverse) need(listener.protocol === 'vless' && accounts[0].reverse?.tag === outbound && endpoint.reverse?.tag === inbound);
    const probe = { tag: probeIn, protocol: 'dokodemo-door', listen: loopback, port: requestPort,
        settings: { network: 'tcp', address: loopback, port: responderPort } };
    const responder = { tag: proofOut, protocol: 'freedom', settings: {
        domainStrategy: 'AsIs', finalRules: [{ action: 'allow', ip: [`${loopback}/32`] }, { action: 'block' }],
    } };
    const rule = (i, o) => ({ type: 'field', inboundTag: [i], outboundTag: o,
        ip: [`${loopback}/32`], port: String(responderPort), network: 'tcp' });
    const config = (inbounds, outbounds, routingRule) => ({
        inbounds, outbounds: [block, ...outbounds], routing: { domainStrategy: 'AsIs', rules: [routingRule] },
    });
    return structuredClone({ listenerPort: listener.port,
        request: config(reverse ? [probe, listener] : [probe], reverse ? [] : [dialer], rule(probeIn, outbound)),
        response: config(reverse ? [] : [listener], reverse ? [responder, dialer] : [responder], rule(inbound, proofOut)),
    });
}

module.exports = { transitProofProfiles };
