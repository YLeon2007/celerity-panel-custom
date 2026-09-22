'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { buildL2tpArtifacts } = require('../services/l2tpConfigService');

function desired(overrides = {}) {
    return {
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        poolStart: '10.77.0.10',
        poolEnd: '10.77.0.200',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        tproxyPort: 12345,
        fwmark: 77,
        routeTable: 177,
        psk: 'correct horse battery staple',
        ...overrides,
    };
}

function fileByPath(result, path) {
    return result.files.find(file => file.path === path);
}

test('builds deterministic artifacts at fixed paths and modes', () => {
    const first = buildL2tpArtifacts(desired());
    const second = buildL2tpArtifacts(desired());

    assert.deepEqual(first, second);
    assert.deepEqual(first.files.map(({ path, mode }) => ({ path, mode })), [
        { path: 'etc/ipsec.d/celerity-l2tp.conf', mode: 0o644 },
        { path: 'etc/ipsec.secrets', mode: 0o600 },
        { path: 'etc/xl2tpd/xl2tpd.conf', mode: 0o644 },
        { path: 'etc/ppp/options.xl2tpd', mode: 0o600 },
        { path: 'etc/nftables.d/celerity-l2tp.nft', mode: 0o644 },
    ]);
    for (const file of first.files) {
        assert.equal(typeof file.content, 'string');
        assert.match(file.content, /\n$/);
    }
});

test('builds a managed IKEv1 transport-mode PSK ipsec drop-in without aggressive mode', () => {
    const result = buildL2tpArtifacts(desired());

    assert.equal(fileByPath(result, 'etc/ipsec.d/celerity-l2tp.conf').content, `# Managed by Celerity. Do not edit.
config setup
    uniqueids=no

conn celerity-l2tp
    keyexchange=ikev1
    type=transport
    authby=psk
    aggressive=no
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    dpdaction=clear
    auto=add
`);
    assert.doesNotMatch(
        fileByPath(result, 'etc/ipsec.d/celerity-l2tp.conf').content,
        /aggressive=yes/,
    );
});

test('writes the PSK only to ipsec.secrets', () => {
    const result = buildL2tpArtifacts(desired());

    assert.equal(
        fileByPath(result, 'etc/ipsec.secrets').content,
        '%any %any : PSK "correct horse battery staple"\n',
    );
    for (const file of result.files) {
        if (file.path !== 'etc/ipsec.secrets') {
            assert.doesNotMatch(file.content, /correct horse battery staple/);
        }
    }
});

test('rejects a PSK containing a double quote without exposing the secret', () => {
    const psk = 'unsafe"quote-secret';

    assert.throws(
        () => buildL2tpArtifacts(desired({ psk })),
        error => {
            assert.equal(error.name, 'L2tpConfigError');
            assert.equal(error.code, 'INVALID_PSK');
            assert.equal(error.field, 'psk');
            assert.equal(Object.hasOwn(error, 'value'), false);
            assert.equal(error.message.includes(psk), false);
            assert.equal(JSON.stringify(error).includes(psk), false);
            return true;
        },
    );
});

test('rejects PSKs containing CR or LF without exposing the secret', () => {
    for (const psk of ['unsafe\rsecret', 'unsafe\nsecret', 'unsafe\r\nsecret']) {
        assert.throws(
            () => buildL2tpArtifacts(desired({ psk })),
            error => {
                assert.equal(error.name, 'L2tpConfigError');
                assert.equal(error.code, 'INVALID_PSK');
                assert.equal(error.field, 'psk');
                assert.equal(Object.hasOwn(error, 'value'), false);
                assert.equal(error.message.includes(psk), false);
                assert.equal(JSON.stringify(error).includes(psk), false);
                return true;
            },
        );
    }
});

test('restricts xl2tpd to the desired client pool and local address', () => {
    const result = buildL2tpArtifacts(desired());

    assert.equal(fileByPath(result, 'etc/xl2tpd/xl2tpd.conf').content, `[global]
port = 1701

[lns celerity-l2tp]
ip range = 10.77.0.10-10.77.0.200
local ip = 10.77.0.1
require authentication = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
`);
});

test('requires MSCHAPv2 in PPP options and rejects PAP and CHAP', () => {
    const result = buildL2tpArtifacts(desired());

    assert.equal(fileByPath(result, 'etc/ppp/options.xl2tpd').content, `auth
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
ms-dns 1.1.1.1
ms-dns 9.9.9.9
`);
});

test('builds namespaced TCP and UDP TPROXY nft rules with fail-closed PPP egress', () => {
    const result = buildL2tpArtifacts(desired());

    assert.equal(fileByPath(result, 'etc/nftables.d/celerity-l2tp.nft').content, `table inet celerity_l2tp {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        iifname "ppp*" ip saddr 10.77.0.0/24 meta l4proto tcp tproxy to :12345 meta mark set 77 accept
        iifname "ppp*" ip saddr 10.77.0.0/24 meta l4proto udp tproxy to :12345 meta mark set 77 accept
    }

    chain forward {
        type filter hook forward priority filter; policy accept;
        iifname "ppp*" ip saddr 10.77.0.0/24 drop comment "block non-TPROXY PPP egress"
    }
}
`);
});

test('returns secret-free metadata that is safe to log', () => {
    const result = buildL2tpArtifacts(desired());

    assert.deepEqual(result.metadata, {
        namespace: 'celerity_l2tp',
        clientCidr: '10.77.0.0/24',
        localAddress: '10.77.0.1',
        pool: {
            start: '10.77.0.10',
            end: '10.77.0.200',
        },
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        tproxy: {
            port: 12345,
            fwmark: 77,
            routeTable: 177,
        },
    });
    assert.doesNotMatch(JSON.stringify(result.metadata), /correct horse battery staple/);
});

test('rejects malformed IPv4 client CIDRs with a structured error', () => {
    for (const clientCidr of ['10.77.0.0', '10.77.0.999/24', '10.77.0.0/33', 'not-a-cidr']) {
        assert.throws(
            () => buildL2tpArtifacts(desired({ clientCidr })),
            error => {
                assert.equal(error.name, 'L2tpConfigError');
                assert.equal(error.code, 'INVALID_CLIENT_CIDR');
                assert.equal(error.field, 'clientCidr');
                assert.equal(error.value, clientCidr);
                assert.doesNotMatch(error.message, /correct horse battery staple/);
                return true;
            },
        );
    }
});

test('rejects a client pool outside clientCidr with a structured error', () => {
    const outsidePools = [
        { poolStart: '10.76.255.250', poolEnd: '10.77.0.200' },
        { poolStart: '10.77.0.10', poolEnd: '10.77.1.1' },
    ];

    for (const pool of outsidePools) {
        assert.throws(
            () => buildL2tpArtifacts(desired(pool)),
            error => {
                assert.equal(error.name, 'L2tpConfigError');
                assert.equal(error.code, 'POOL_OUTSIDE_CLIENT_CIDR');
                assert.equal(error.field, 'pool');
                assert.deepEqual(error.value, {
                    start: pool.poolStart,
                    end: pool.poolEnd,
                });
                assert.equal(error.clientCidr, '10.77.0.0/24');
                assert.doesNotMatch(error.message, /correct horse battery staple/);
                return true;
            },
        );
    }
});
