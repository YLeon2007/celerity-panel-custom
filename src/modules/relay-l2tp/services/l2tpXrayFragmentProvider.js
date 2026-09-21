'use strict';

function buildL2tpXrayFragment(snapshot) {
    const { plan, tags, tproxyPort } = snapshot;
    const selectedPath = plan.paths.find(path => (
        path.pathKey === plan.selectedPathKey && path.healthy === true
    ));

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
        outbounds: [],
        routingRules: [
            {
                type: 'field',
                inboundTag: [tags.inbound],
                ip: ['geoip:private'],
                outboundTag: tags.blockOutbound,
            },
            {
                type: 'field',
                inboundTag: [tags.inbound],
                ip: [...plan.relay.controlPlaneIps].sort(),
                outboundTag: tags.blockOutbound,
            },
            {
                type: 'field',
                inboundTag: [tags.inbound],
                outboundTag: selectedPath?.outboundTag ?? tags.blockOutbound,
            },
        ],
    };
}

module.exports = { buildL2tpXrayFragment };
