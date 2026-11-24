'use strict';

// Read-only preview, NOT a writer fence or a proof that later deployment is safe.
// No install, staging, config writes, firewall changes or lock acquisition here.
const { randomBytes } = require('node:crypto');
const net = require('node:net');
const { assertClassicTunnelTransport, xrayListenerProtocols } = require('../utils/cascadeTransport');
const MAIN = '/usr/local/etc/xray/config.json';
const TRANSIT = '/usr/local/etc/xray-bridge/config.json';
const unavailable = () => Object.assign(new Error('Tunnel port inspection unavailable'), { code: 'TUNNEL_PORT_CHECK_UNAVAILABLE' });
const occupied = () => Object.assign(new Error('Tunnel port is already in use on the selected node'), { code: 'TUNNEL_PORT_IN_USE' });
const id = value => String(value?._id ?? value);
const quote = text => `'${text.replace(/'/g, `'\\''`)}'`;
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
    : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
        : JSON.stringify(value);
function config(text) {
    if (text === 'C3_CONFIG_ABSENT') return { inbounds: [] };
    const value = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || (value.inbounds !== undefined && !Array.isArray(value.inbounds))) throw unavailable();
    return value;
}
function includesPort(value, port) {
    if (Number.isInteger(value) && value >= 1 && value <= 65535) return value === port;
    if (typeof value === 'string' && /^[1-9]\d{0,4}(?:-[1-9]\d{0,4})?$/.test(value)) {
        const [lo, hi = lo] = value.split('-').map(Number);
        if (lo <= hi && hi <= 65535) return lo <= port && port <= hi;
    }
    throw unavailable();
}
function ownsFragment(main, target, node) {
    if (!target || target.active !== true || target.tunnelPort < 1 || !target.tunnelUuid) return false;
    const mode = target.mode ?? 'reverse';
    if (!['forward', 'reverse'].includes(mode)
        || id(mode === 'reverse' ? target.portalNode : target.bridgeNode) !== id(node)) return false;
    const generator = require('./configGenerator');
    const suffix = id(target).slice(-8);
    const delta = { inbounds: [], outbounds: [], routing: { rules: [] } };
    if (mode === 'reverse') {
        const configured = [node.xray?.inboundTag || 'vless-in', ...(node.xray?.extraInbounds || []).map(row => row.inboundTag).filter(Boolean)];
        const routes = (main.routing?.rules || []).filter(row => row.outboundTag === `portal-${suffix}` && !row.domain);
        // Domain-only geo generation has no domain-free client route; the
        // held writer then uses configured tags. Keep full fragment equality.
        const tags = routes.length ? routes.flatMap(row => row.inboundTag || []) : configured;
        if (!tags.length || new Set(tags).size !== tags.length || configured.some(tag => !tags.includes(tag))
            || tags.some(tag => typeof tag !== 'string' || main.inbounds?.filter(row => row.tag === tag).length !== 1)) return false;
        // Match the held core's exact replay, including a prior REALITY decoy.
        const listener = main.inbounds?.find(row => row.tag === `bridge-conn-${suffix}`);
        if (target.tunnelSecurity === 'reality' && listener) {
            const reality = listener.streamSettings?.realitySettings;
            const dest = typeof reality?.dest === 'string'
                ? reality.dest.match(/^(?:\[([0-9a-fA-F:]+)\]|([^:\[\]]+)):([1-9]\d{0,4})$/) : null;
            const host = value => {
                if (typeof value !== 'string') return false;
                if (net.isIP(value)) return true;
                const labels = value.split('.');
                return value.length <= 253 && labels.length > 1 && /[A-Za-z]/.test(labels.at(-1))
                    && labels.every(label => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label));
            };
            if (!dest || Number(dest[3]) > 65535 || !host(dest[1] || dest[2])
                || !Array.isArray(reality.serverNames) || !reality.serverNames.length
                || reality.serverNames.some(name => !host(name) || net.isIP(name))) return false;
            target = { ...target, realityDest: reality.dest, realitySni: reality.serverNames };
        }
        generator.applyReversePortal(delta, [target], tags);
    } else generator.applyForwardHopInbound(delta, [target]);
    const sections = [['inbounds', main, delta], ['outbounds', main, delta],
        ['portals', main.reverse || {}, delta.reverse || {}], ['bridges', main.reverse || {}, delta.reverse || {}],
        ['rules', main.routing || {}, delta.routing]];
    const owned = row => JSON.stringify(row).includes(suffix);
    return delta.inbounds.length === 1 && sections.every(([key, from, expected]) => {
        const actual = (from[key] || []).filter(owned), wanted = (expected[key] || []).filter(owned);
        return actual.length === wanted.length && wanted.every(row => actual.filter(item => canonical(item) === canonical(row)).length === 1);
    });
}

async function inspectTunnelPort({ node, port, target = null, tunnelTransport }, exec) {
    assertClassicTunnelTransport({ tunnelTransport }, target);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw unavailable();
    const read = file => exec(`# C3_READ_CONFIG\nif test -e ${file}; then\n test -f ${file} && test ! -L ${file} && test "$(stat -c %s ${file})" -le 1048576 && cat ${file}\nelse\n printf C3_CONFIG_ABSENT\nfi`);
    const main = config(await read(MAIN)), transit = config(await read(TRANSIT));
    const inbounds = profile => (profile.inbounds || []).filter(row => includesPort(row?.port, port)
        && xrayListenerProtocols(row).join(',') !== 'udp');
    const mainHits = inbounds(main), transitHits = inbounds(transit);
    const own = target?.tunnelPort === port && mainHits.length === 1 && ownsFragment(main, target, node);
    if (transitHits.length || (mainHits.length && !own)) throw occupied();
    // All TCP listeners on the requested port, including non-Xray processes and
    // sockets absent from either JSON profile. No grep/exit-one-as-free shortcut.
    const sockets = await exec(`ss -H -ltnp 'sport = :${port}'`);
    if (!sockets.trim()) return;
    if (!own) throw occupied();
    const service = await exec('systemctl show xray --property=ActiveState --property=MainPID --property=NeedDaemonReload --property=ExecStart');
    const pid = service.match(/^MainPID=([1-9]\d*)$/m)?.[1];
    const loaded = service.match(/^ExecStart=\{ path=([^;]+) ; argv\[\]=([^;]+) ;[^\n]*$/m);
    if (!pid || !service.includes('ActiveState=active\n') || !service.includes('NeedDaemonReload=no\n')
        || loaded?.[1].trim() !== '/usr/local/bin/xray' || loaded?.[2].trim() !== `/usr/local/bin/xray run -config ${MAIN}`) throw occupied();
    for (const line of sockets.trim().split('\n')) {
        const fields = line.trim().split(/\s+/), pids = [...line.matchAll(/\bpid=(\d+)\b/g)].map(match => match[1]);
        if (fields[0] !== 'LISTEN' || !/^\d+$/.test(fields[1]) || !/^\d+$/.test(fields[2])
            || !fields[3]?.endsWith(`:${port}`) || !pids.length || pids.some(actual => actual !== pid)) throw occupied();
    }
}

async function preflightTunnelPort(input, { NodeSSH, timeoutMs = 15000 } = {}) {
    assertClassicTunnelTransport(input, input.target);
    let ssh, expired = false, timer;
    const deadline = performance.now() + timeoutMs;
    const guard = () => { if (expired || performance.now() >= deadline) throw unavailable(); };
    const work = async () => {
        const node = input.node;
        if (!node || node.active !== true || !node.ip || (!node.ssh?.password && !node.ssh?.privateKey)) throw unavailable();
        const Transport = NodeSSH ?? require('./nodeSSH');
        ssh = new Transport(node);
        await ssh.connect();
        if (expired) { ssh.disconnect(); throw unavailable(); }
        guard();
        await inspectTunnelPort(input, async command => {
            guard();
            const marker = `C3_PORT_READ_${randomBytes(24).toString('hex')}`;
            const result = await ssh.exec(`timeout --signal=TERM --kill-after=1s 5s sh -c ${quote(`set -eu\n${command}`)} && printf '\\n${marker}\\n'`,
                { timeout: Math.min(7000, Math.max(1, deadline - performance.now())) });
            guard();
            const suffix = `\n${marker}\n`;
            if (result?.code !== 0 || typeof result.stdout !== 'string' || typeof result.stderr !== 'string'
                || result.stdout.length > 1100000 || !result.stdout.endsWith(suffix)) throw unavailable();
            return result.stdout.slice(0, -suffix.length);
        });
    };
    try {
        await Promise.race([work(), new Promise((_, reject) => { timer = setTimeout(() => {
            expired = true; reject(unavailable());
        }, timeoutMs); })]);
    } catch (error) {
        throw error?.code === 'TUNNEL_PORT_IN_USE' ? occupied() : unavailable();
    } finally { expired = true; clearTimeout(timer); ssh?.disconnect(); }
}
module.exports = { preflightTunnelPort, inspectTunnelPort };
