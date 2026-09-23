'use strict';

const {
    cascadePathIngressPort,
} = require('../domain/cascadePathIngress');

function buildL2tpXrayFragment(snapshot) {
    const { plan, tags, tproxyPort } = snapshot;
    const selectedPath = plan.paths.find(path => (
        path.pathKey === plan.selectedPathKey && path.healthy === true
    ));

    // The fragment carries its own cascade-<pathKey> socks outbound pointing at
    // the deterministic loopback ingress listener that the relay bridge-profile
    // candidate exposes for this path. Without a healthy selected path the
    // fragment stays fail-closed (no outbound, catch-all routes to block).
    const outbounds = [];
    if (selectedPath) {
        const groupId = plan.group?.id;
        if (typeof groupId !== 'string' || groupId.length === 0) {
            throw new TypeError('L2TP Xray fragment requires the route group identity');
        }
        outbounds.push({
            tag: selectedPath.outboundTag,
            protocol: 'socks',
            settings: {
                servers: [{
                    address: '127.0.0.1',
                    port: cascadePathIngressPort(groupId, selectedPath.pathKey),
                }],
            },
        });
    }

function isIpMatcher(entry) {
    return entry.startsWith('geoip:') || /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(entry);
}

function buildControlPlaneRule(entries, tags) {
    // Xray rejects domains inside `ip` rules ("unsupported address for router"),
    // while panel node addresses may legitimately be hostnames.
    const ipMatchers = [];
    const domainMatchers = [];
    for (const entry of [...entries].sort()) {
        if (isIpMatcher(entry)) {
            ipMatchers.push(entry);
        } else {
            domainMatchers.push(entry);
        }
    }
    const rule = {
        type: 'field',
        inboundTag: [tags.inbound],
        outboundTag: tags.blockOutbound,
    };
    if (ipMatchers.length > 0) {
        rule.ip = ipMatchers;
    }
    if (domainMatchers.length > 0) {
        rule.domain = domainMatchers;
    }
    return rule;
}

    return {
        id: 'relay-l2tp',
        inbounds: [{
            tag: tags.inbound,
            listen: '0.0.0.0',
            port: tproxyPort,
            protocol: 'dokodemo-door',
            settings: {
                network: 'tcp,udp',
                followRedirect: true,
            },
            streamSettings: {
                sockopt: { tproxy: 'tproxy' },
            },
        }],
        outbounds,
        routingRules: [
            {
                type: 'field',
                inboundTag: [tags.inbound],
                ip: ['geoip:private'],
                outboundTag: tags.blockOutbound,
            },
            buildControlPlaneRule(plan.relay.controlPlaneIps, tags),
            {
                type: 'field',
                inboundTag: [tags.inbound],
                outboundTag: selectedPath?.outboundTag ?? tags.blockOutbound,
            },
        ],
    };
}

module.exports = { buildL2tpXrayFragment };
