'use strict';

const { createHash, randomBytes } = require('node:crypto');
const { isIP } = require('node:net');
const { encrypt } = require('../modules/relay-l2tp/services/secretBoxService');

const fail = code => Object.assign(new Error(code), { code });
const ipv4 = ip => ip.split('.').reduce((n, part) => n * 256 + Number(part), 0);

function occupiedRange(cidr) {
    const match = typeof cidr === 'string' && /^([^/]+)\/(\d{1,2})$/.exec(cidr);
    if (!match || isIP(match[1]) !== 4 || Number(match[2]) > 32) throw fail('REBUILD_L2TP_ADDRESS_INVENTORY_INVALID');
    const size = 2 ** (32 - Number(match[2]));
    const first = Math.floor(ipv4(match[1]) / size) * size;
    return [first, first + size - 1];
}

function makeDesired(nodeId, occupied, controlPlaneAddresses, key) {
    if (typeof key !== 'string' || key.length < 32) throw fail('REBUILD_L2TP_CREDENTIAL_KEY_INVALID');
    const ranges = occupied.map(row => occupiedRange(row.clientCidr));
    for (const address of controlPlaneAddresses) {
        if (isIP(address) === 4) ranges.push([ipv4(address), ipv4(address)]);
    }
    // Same addressing range and host-local TPROXY policy as the stock simple installer.
    const span = 224;
    const start = createHash('sha256').update(nodeId).digest()[0] % span;
    let prefix;
    for (let i = 0; i < span; i++) {
        const candidate = `10.255.${16 + (start + i) % span}`;
        const first = ipv4(`${candidate}.0`);
        if (!ranges.some(([lo, hi]) => lo <= first + 255 && hi >= first)) {
            prefix = candidate;
            break;
        }
    }
    if (!prefix) throw fail('REBUILD_L2TP_ADDRESS_SPACE_EXHAUSTED');
    const network = {
        clientCidr: `${prefix}.0/24`, localAddress: `${prefix}.1`, poolStart: `${prefix}.10`, poolEnd: `${prefix}.250`,
        dnsServers: ['1.1.1.1', '8.8.8.8'], tproxyPort: 12345, fwmark: 100, routeTable: 100, mtu: 1400, mru: 1400,
    };
    const psk = randomBytes(24).toString('base64url');
    const password = randomBytes(24).toString('base64url');
    const login = 'relay-bootstrap';
    const ip = network.poolStart;
    return {
        desired: { ...network, psk, credentialRevision: 1, users: [{ login, password, ipAddress: ip, enabled: true }] },
        state: { ...network, secretRevision: 1, pskEncrypted: encrypt(psk, key), pskHint: psk.slice(-4) },
        user: { login, ip, enabled: true, passwordEncrypted: encrypt(password, key), desiredRevision: 1 },
    };
}

module.exports = { makeDesired };
