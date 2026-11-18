'use strict';
// Executes inside the actual backend container, before index.js or DB startup.
// Reuse the ordinary producer and exact SSH verifier. No capture/bind/replay.
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { createRootProductionPhysicalAuthority } = require('../../src/modules/relay-l2tp/runtime/productionPhysicalAuthority');
const PROD_CONFIG = '/etc/celerity/topology-production.json';

function need(test, code) {
    if (!test) throw new Error(code);
}

function privateReader(root = '/etc/celerity', uid = 0) {
    return file => {
        need(file.startsWith(root + '/') && path.normalize(file) === file, 'PRIVATE_PATH');
        for (let p = file; ; p = path.dirname(p)) {
            const st = fs.lstatSync(p);
            need(st.uid === uid && !(st.mode & 0o022) && !st.isSymbolicLink()
                && (p === file ? st.isFile() : st.isDirectory()), 'PRIVATE_PATH');
            if (p === '/') break;
        }
        const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        try {
            const st = fs.fstatSync(fd);
            need(st.uid === uid && st.isFile() && !(st.mode & 0o077) && st.size > 0 && st.size <= 1024 * 1024, 'PRIVATE_FILE');
            return fs.readFileSync(fd);
        } finally { fs.closeSync(fd); }
    };
}

function routable(ip) {
    if (net.isIP(ip) === 4) {
        const first = Number(ip.split('.')[0]);
        return first > 0 && first !== 127 && first < 224;
    }
    if (net.isIP(ip) === 6) {
        const canonical = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
        // Do not accept mapped/compatible v4 or scoped link-local addresses.
        return /^[23abcdef][0-9a-f]*:/i.test(canonical) && !/^(?:ff|fe[89ab])/i.test(canonical);
    }
    return false;
}

function readOnlyConfigMount(mountInfo) {
    const binds = mountInfo.trim().split('\n').map(line => line.split(' '))
        .filter(row => row[4] === '/etc/celerity' || row[4]?.startsWith('/etc/celerity/'));
    return binds.length === 1 && binds[0][4] === '/etc/celerity' && binds[0][5].split(',').includes('ro');
}

async function preflight({ env = process.env, uid = process.getuid(), read = privateReader(),
    mountInfo = () => fs.readFileSync('/proc/self/mountinfo', 'utf8') } = {}) {
    need(uid === 0, 'CONTAINER_ROOT_REQUIRED');
    need(readOnlyConfigMount(mountInfo()), 'CONFIG_BIND_NOT_READ_ONLY');
    const bytes = read(PROD_CONFIG);
    const config = JSON.parse(bytes);
    const authority = createRootProductionPhysicalAuthority({ env, read(file) {
        return file === PROD_CONFIG ? bytes : read(file);
    } });
    need(authority, 'PROD_SELECTOR_REQUIRED');
    try {
        const targets = [config.host, ...config.nodes];
        for (const pin of targets) need(routable(pin.endpoint.ip), 'NON_ROUTABLE_ENDPOINT');
        // Refuse unreadable or over-permissive keys before opening any channel.
        for (const file of new Set(targets.map(pin => pin.privateKeyPath))) read(file);
        await authority.withHeldAuthority(config.executionContext, async () => {});
    } finally { authority.close(); }
}

if (require.main === module) {
    // Bound the whole container preflight and close normally on successful checks.
    // No error object/config/credentials enter logs. Native failures remain retained.
    const timer = setTimeout(() => {
        process.stderr.write('C3_CONTAINER_SSH_PREFLIGHT_TIMEOUT\n');
        process.exit(1);
    }, 120000);
    preflight().then(() => {
        clearTimeout(timer);
        process.stdout.write('C3_CONTAINER_SSH_PREFLIGHT_OK\n');
    }, () => {
        clearTimeout(timer);
        process.stderr.write('C3_CONTAINER_SSH_PREFLIGHT_REFUSED\n');
        process.exitCode = 1;
    });
}

module.exports = { preflight, privateReader, readOnlyConfigMount, routable };
