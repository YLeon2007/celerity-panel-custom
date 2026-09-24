'use strict';

const { isIP } = require('node:net');

const MAX_DNS_SERVERS = 4;

function parseIpv4(value) {
    if (typeof value !== 'string') {
        return null;
    }

    const octets = value.split('.');
    if (octets.length !== 4 || octets.some(octet => !/^(0|[1-9]\d{0,2})$/.test(octet))) {
        return null;
    }

    const numbers = octets.map(Number);
    if (numbers.some(octet => octet > 255)) {
        return null;
    }

    return numbers.reduce((address, octet) => (address * 256) + octet, 0);
}

function parseClientCidr(value) {
    if (typeof value !== 'string') {
        return null;
    }

    const match = value.match(/^([^/]+)\/(\d{1,2})$/);
    if (!match) {
        return null;
    }

    const address = parseIpv4(match[1]);
    const prefix = Number(match[2]);
    if (address === null || prefix > 32) {
        return null;
    }

    const blockSize = 2 ** (32 - prefix);
    const first = Math.floor(address / blockSize) * blockSize;
    if (address !== first) {
        return null;
    }

    return { first, last: first + blockSize - 1 };
}

function invalidClientCidr(value) {
    const error = new Error('clientCidr must be a canonical IPv4 CIDR');
    error.name = 'L2tpConfigError';
    error.code = 'INVALID_CLIENT_CIDR';
    error.field = 'clientCidr';
    error.value = value;
    return error;
}

function poolOutsideClientCidr(desired) {
    const error = new Error('pool must be an ordered IPv4 range within clientCidr');
    error.name = 'L2tpConfigError';
    error.code = 'POOL_OUTSIDE_CLIENT_CIDR';
    error.field = 'pool';
    error.value = {
        start: desired.poolStart,
        end: desired.poolEnd,
    };
    error.clientCidr = desired.clientCidr;
    return error;
}

function invalidPsk() {
    const error = new Error('psk cannot be represented safely in ipsec.secrets');
    error.name = 'L2tpConfigError';
    error.code = 'INVALID_PSK';
    error.field = 'psk';
    return error;
}

function invalidDnsServers() {
    const error = new Error('dnsServers must contain canonical IP address literals');
    error.name = 'L2tpConfigError';
    error.code = 'INVALID_DNS_SERVERS';
    error.field = 'dnsServers';
    return error;
}

function isCanonicalIpLiteral(value) {
    if (typeof value !== 'string' || /\s/.test(value)) {
        return false;
    }
    if (parseIpv4(value) !== null) {
        return true;
    }
    if (isIP(value) !== 6) {
        return false;
    }

    return new URL(`http://[${value}]/`).hostname === `[${value}]`;
}

function buildL2tpArtifacts(desired) {
    const clientRange = parseClientCidr(desired.clientCidr);
    if (!clientRange) {
        throw invalidClientCidr(desired.clientCidr);
    }

    const poolStart = parseIpv4(desired.poolStart);
    const poolEnd = parseIpv4(desired.poolEnd);
    if (
        poolStart === null
        || poolEnd === null
        || poolStart > poolEnd
        || poolStart < clientRange.first
        || poolEnd > clientRange.last
    ) {
        throw poolOutsideClientCidr(desired);
    }

    if (
        typeof desired.psk !== 'string'
        || desired.psk.trim().length === 0
        || /["\r\n]/.test(desired.psk)
    ) {
        throw invalidPsk();
    }

    if (
        !Array.isArray(desired.dnsServers)
        || desired.dnsServers.length === 0
        || desired.dnsServers.length > MAX_DNS_SERVERS
        || desired.dnsServers.some(server => !isCanonicalIpLiteral(server))
    ) {
        throw invalidDnsServers();
    }

    const dnsOptions = desired.dnsServers.map(server => `ms-dns ${server}\n`).join('');

    return {
        files: [
            {
                path: 'etc/ipsec.d/celerity-l2tp.conf',
                mode: 0o644,
                content: `# Managed by Celerity. Do not edit.
config setup
    uniqueids=no

conn celerity-l2tp
    keyexchange=ikev1
    type=transport
    authby=psk
    aggressive=no
    ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024,aes256-sha256-modp2048,aes128-sha256-modp2048!
    esp=aes256-sha1-modp1024,aes192-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024,aes256-sha256-modp1024,aes128-sha256-modp1024,aes256-sha1,aes128-sha1,aes256-sha256!
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    dpdaction=clear
    auto=add
`,
            },
            {
                path: 'etc/ipsec.secrets',
                mode: 0o600,
                content: `%any %any : PSK "${desired.psk}"\n`,
            },
            {
                path: 'etc/xl2tpd/xl2tpd.conf',
                mode: 0o644,
                content: `[global]
port = 1701

[lns celerity-l2tp]
ip range = ${desired.poolStart}-${desired.poolEnd}
local ip = ${desired.localAddress}
require authentication = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
`,
            },
            {
                path: 'etc/ppp/options.xl2tpd',
                mode: 0o600,
                content: `auth
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
refuse-eap
name l2tpd
mtu 1400
mru 1400
nodefaultroute
lock
${dnsOptions}`,
            },
            {
                path: 'etc/nftables.d/celerity-l2tp.nft',
                mode: 0o644,
                content: `table inet celerity_l2tp {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        iifname "ppp*" ip saddr ${desired.clientCidr} meta l4proto tcp tproxy ip to :${desired.tproxyPort} meta mark set ${desired.fwmark} accept
        iifname "ppp*" ip saddr ${desired.clientCidr} meta l4proto udp tproxy ip to :${desired.tproxyPort} meta mark set ${desired.fwmark} accept
    }

    chain forward {
        type filter hook forward priority filter; policy accept;
        iifname "ppp*" ip saddr ${desired.clientCidr} drop comment "block non-TPROXY PPP egress"
    }
}
`,
            },
        ],
        metadata: {
            namespace: 'celerity_l2tp',
            clientCidr: desired.clientCidr,
            localAddress: desired.localAddress,
            pool: {
                start: desired.poolStart,
                end: desired.poolEnd,
            },
            dnsServers: [...desired.dnsServers],
            tproxy: {
                port: desired.tproxyPort,
                fwmark: desired.fwmark,
                routeTable: desired.routeTable,
            },
        },
    };
}

module.exports = { buildL2tpArtifacts };
