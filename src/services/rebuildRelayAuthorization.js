'use strict';
const { isIP } = require('node:net');
const { validateRebuildMode } = require('./rebuildMode');

const LIST = 'C3_REBUILD_L2TP_RELAYS_JSON';
const fields = ['nodeId', 'host', 'port', 'username', 'machineId', 'sshHostKeySha256'];
const fail = suffix => Object.assign(new Error(`REBUILD_L2TP_${suffix}`), { code: `REBUILD_L2TP_${suffix}` });
const disabled = () => fail('INSTALL_DISABLED');
const hex = (value, size) => typeof value === 'string' && value.length === size && /^[a-f0-9]+$/.test(value);
const validPort = port => Number.isInteger(port) && port >= 1 && port <= 65535;
const validLogin = name => typeof name === 'string' && /^[A-Za-z_][A-Za-z0-9_.-]{0,63}(?![\s\S])/.test(name);

function hostIdentity(host) {
    if (typeof host !== 'string' || host.length > 254 || host.includes('%')) return;
    const ip = isIP(host);
    if (ip === 4) return host;
    if (ip === 6) {
        const canonical = new URL(`http://[${host}]/`).hostname.slice(1, -1);
        const mapped = /^::ffff:([\da-f]+):([\da-f]+)$/.exec(canonical);
        if (!mapped) return canonical;
        return mapped.slice(1).flatMap(word => { const n = parseInt(word, 16); return [n >> 8, n & 255]; }).join('.');
    }
    const dns = host.toLowerCase().replace(/\.$/, '');
    if (dns.length <= 253 && /^[A-Za-z0-9.-]+(?![\s\S])/.test(host)
        && dns.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
        // Reject numeric spellings that resolvers can treat as noncanonical IPv4.
        && !/^(?:\d+|0x[0-9a-f]+)$/.test(dns.split('.').at(-1))) return dns;
}

function listBinding(raw, id) {
    if (typeof raw !== 'string' || raw.length > 128 * 1024) throw disabled();
    let rows;
    try { rows = JSON.parse(raw); } catch { throw disabled(); }
    if (!Array.isArray(rows)) throw disabled();
    const ids = new Set(), machines = new Set(), pins = new Set(), endpoints = new Set();
    let match;
    for (const row of rows) {
        if (!row || typeof row !== 'object' || Object.keys(row).length !== fields.length
            || !fields.every(key => Object.hasOwn(row, key))) throw disabled();
        const { nodeId, host, port, username, machineId, sshHostKeySha256 } = row;
        const address = hostIdentity(host);
        if (!address || !validPort(port) || !validLogin(username)
            || !hex(nodeId, 24) || !hex(machineId, 32) || !hex(sshHostKeySha256, 64)) throw disabled();
        const endpoint = `${address}/${port}`;
        if (ids.has(nodeId) || machines.has(machineId) || pins.has(sshHostKeySha256) || endpoints.has(endpoint)) throw disabled();
        ids.add(nodeId); machines.add(machineId); pins.add(sshHostKeySha256); endpoints.add(endpoint);
        if (nodeId === id) match = row;
    }
    // At this point the JSON is valid and its values are all flat scalars.
    // Count lexical member names too: JSON.parse silently collapses duplicate keys.
    let members = 0;
    for (const [, separator] of raw.matchAll(/"(?:[^"\\]|\\[\s\S])*"\s*(:)?/g)) if (separator) members++;
    if (members !== rows.length * fields.length) throw disabled();
    return match && Object.freeze(match);
}

function rebuildAllowed(env) {
    try { return validateRebuildMode(env) === true; } catch { return false; }
}

function resolveRelayBinding(env, id, node, { optional = false } = {}) {
    const listMode = Object.hasOwn(env, LIST);
    let binding;
    if (optional) {
        if (listMode) {
            try { binding = listBinding(env[LIST], id); }
            catch (error) {
                // Invalid enrollment is not evidence of an unenrolled relay.
                // It does not gate ordinary non-relay nodes without state.
                if (error.code === 'REBUILD_L2TP_INSTALL_DISABLED' && node?.cascadeRole !== 'relay') return;
                throw error;
            }
            if (!binding) return;
        } else if (env.C3_REBUILD_L2TP_RELAY_ID !== id) {
            return;
        }
    }
    if (!rebuildAllowed(env) || env.C3_REBUILD_L2TP_INSTALL_ENABLED !== 'true' || !hex(id, 24)) throw disabled();
    if (listMode) {
        binding ??= listBinding(env[LIST], id);
        if (!binding) throw disabled();
        if (node !== undefined && (String(node?._id ?? node?.id ?? '') !== id
            || hostIdentity(node?.ip) !== hostIdentity(binding.host)
            || node?.ssh?.port !== binding.port || node?.ssh?.username !== binding.username)) throw fail('BINDING_MISMATCH');
        return binding;
    }
    const machineId = env.C3_REBUILD_L2TP_RELAY_MACHINE_ID;
    const sshHostKeySha256 = env.C3_REBUILD_L2TP_SSH_SHA256;
    if (env.C3_REBUILD_L2TP_RELAY_ID !== id || !hex(machineId, 32)) throw disabled();
    const host = node?.ip, { port, username } = node?.ssh ?? {};
    // Legacy route admission and non-SSH callers only need the singleton ID and
    // machine ID. The real DIRECT driver must also resolve the pin and endpoint.
    if (node !== undefined) {
        if (!hex(sshHostKeySha256, 64)) throw fail('SSH_PIN_INVALID');
        if (String(node?._id ?? node?.id ?? '') !== id || typeof host !== 'string' || !host
            || !validPort(port) || username !== 'root') throw fail('SSH_ENDPOINT_INVALID');
    }
    return Object.freeze({ nodeId: id, host, port, username, machineId, sshHostKeySha256 });
}

function canInstallRelay(env, id) {
    try { resolveRelayBinding(env, id); return true; } catch { return false; }
}

function sameRelayBinding(a, b) {
    return fields.every(key => a[key] === b[key]);
}

// Capture admission before waiting for Apply exclusion; re-resolve under that
// exclusion and at effect boundaries. Switching modes also revokes the grant.
function captureRelayBinding(env, id, node, options) {
    const binding = resolveRelayBinding(env, id, node, options);
    if (!binding) return;
    const listMode = Object.hasOwn(env, LIST);
    return Object.freeze({ binding, listMode, check(currentNode = node) {
        if (Object.hasOwn(env, LIST) !== listMode) throw disabled();
        const current = resolveRelayBinding(env, id, listMode || node !== undefined ? currentNode : undefined);
        if (!sameRelayBinding(current, binding)) throw fail('BINDING_MISMATCH');
        return binding;
    } });
}

module.exports = { canInstallRelay, resolveRelayBinding, captureRelayBinding, sameRelayBinding };
