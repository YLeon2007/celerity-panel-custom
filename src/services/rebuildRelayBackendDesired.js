'use strict';

const { createHash, randomBytes } = require('node:crypto');
const { isIP } = require('node:net');
const { decrypt, encrypt } = require('../modules/relay-l2tp/services/secretBoxService');

const fail = code => Object.assign(new Error(code), { code });
const ipv4 = ip => ip.split('.').reduce((n, part) => n * 256 + Number(part), 0);
const addressAt = n => [24, 16, 8, 0].map(shift => (n >>> shift) & 255).join('.');
const validLogin = login => typeof login === 'string' && /^[A-Za-z0-9._@-]{1,64}(?![\s\S])/.test(login);

function occupiedRange(cidr) {
    const match = typeof cidr === 'string' && /^([^/]+)\/(\d{1,2})$/.exec(cidr);
    if (!match || isIP(match[1]) !== 4 || Number(match[2]) > 32) throw fail('REBUILD_L2TP_ADDRESS_INVENTORY_INVALID');
    const size = 2 ** (32 - Number(match[2]));
    const first = Math.floor(ipv4(match[1]) / size) * size;
    return [first, first + size - 1];
}

function makeDesired(nodeId, occupied, controlPlaneAddresses, key, { inherited, allocations = [] } = {}) {
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
    const reserved = new Set([network.localAddress, ...allocations]);
    if ([...reserved].some(ip => isIP(ip) !== 4)) throw fail('REBUILD_L2TP_ADDRESS_INVENTORY_INVALID');
    const nextAddresses = [];
    for (let n = ipv4(network.poolStart); n <= ipv4(network.poolEnd); n++) {
        const address = addressAt(n);
        if (!reserved.has(address)) nextAddresses.push(address);
    }
    if (inherited?.length === 0) throw fail('REBUILD_L2TP_ACCOUNT_INVENTORY_INVALID');
    if (nextAddresses.length < (inherited?.length ?? 1)) throw fail('REBUILD_L2TP_ACCOUNT_POOL_EXHAUSTED');
    let accounts;
    if (inherited) {
        try {
            accounts = inherited.map(account => {
                const password = decrypt(account.passwordEncrypted, key);
                // The DIRECT serializer owns quoting and format checks. Keep
                // failure secret-free and never fall back to a new password.
                if (!password || /[\r\n\0]/.test(password)) throw new Error();
                return { ...account, password };
            });
        } catch { throw fail('REBUILD_L2TP_ACCOUNT_INVENTORY_INVALID'); }
    } else {
        const password = randomBytes(24).toString('base64url');
        accounts = [{ login: 'relay-bootstrap', enabled: true, password, passwordEncrypted: encrypt(password, key) }];
    }
    const psk = randomBytes(24).toString('base64url');
    return {
        desired: { ...network, psk, credentialRevision: 1, users: accounts.map(({ login, password, enabled }, i) =>
            ({ login, password, ipAddress: nextAddresses[i], enabled })) },
        state: { ...network, secretRevision: 1, pskEncrypted: encrypt(psk, key), pskHint: psk.slice(-4) },
        accounts: accounts.map(({ login, passwordEncrypted, enabled }, i) =>
            ({ login, ip: nextAddresses[i], enabled, passwordEncrypted, desiredRevision: 1 })),
    };
}

module.exports = { makeDesired, ipv4, occupiedRange, validLogin };
