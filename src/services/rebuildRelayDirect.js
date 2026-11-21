'use strict';

const { readFileSync } = require('node:fs');
const { deflateSync } = require('node:zlib');
const { join } = require('node:path');
const { randomBytes } = require('node:crypto');
const { isIPv4 } = require('node:net');
const { performance } = require('node:perf_hooks');
const { captureRelayBinding } = require('./rebuildRelayAuthorization');
const { CONNECT_TIMEOUT_MS } = require('./rebuildSshLimits');
const { validCensus } = require('./rebuildRelayCounts');
const { composeRebuildRelayPair } = require('./rebuildRelayInstallSteps');
const { buildL2tpArtifacts } = require('../modules/relay-l2tp/services/l2tpConfigService');
const { reconcileChapSecrets } = require('../modules/relay-l2tp/services/l2tpUserSyncService');

const TIMEOUT = 145000;
const SESSION_COUNT_TIMEOUT = 12000;
const PIN = /^[a-f0-9]{64}$/;
const TOKEN = /^[a-f0-9]{32}$/;
const fail = (suffix, uncertain = false) => Object.assign(new Error(`REBUILD_L2TP_${suffix}`), {
    code: `REBUILD_L2TP_${suffix}`, ...(uncertain && { remoteOutcomeUncertain: true }),
});
const requireThat = (condition, suffix) => { if (!condition) throw fail(suffix); };
const integer = (v, lo, hi) => Number.isSafeInteger(v) && v >= lo && v <= hi;
const ipv4 = value => typeof value === 'string' && isIPv4(value)
    ? value.split('.').reduce((acc, octet) => acc * 256 + Number(octet), 0) : NaN;
const safeSecret = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,256}$/.test(value);
const tokenMatches = (re, value) => typeof value === 'string' && re.test(value);

function removeNetwork(value, invalid = 'REMOVE_INPUT_INVALID') {
    const keys = ['clientCidr', 'tproxyPort', 'fwmark', 'routeTable'];
    requireThat(value && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)),
        invalid);
    const { clientCidr, tproxyPort, fwmark, routeTable } = value;
    const match = typeof clientCidr === 'string' && /^(\d+\.\d+\.\d+\.\d+)\/(1[6-9]|2\d|30)(?![\s\S])/.exec(clientCidr);
    const first = match ? ipv4(match[1]) : NaN;
    const size = match ? 2 ** (32 - Number(match[2])) : 1;
    requireThat(first % size === 0 && [[0x0a000000, 0x0affffff], [0xac100000, 0xac1fffff], [0xc0a80000, 0xc0a8ffff]]
        .some(([lo, hi]) => first >= lo && first + size - 1 <= hi)
        && integer(tproxyPort, 1024, 65535) && ![1701, 4500].includes(tproxyPort)
        && integer(fwmark, 1, 0x7fffffff) && integer(routeTable, 1, 0x7fffffff)
        && ![253, 254, 255].includes(routeTable), invalid);
    return { clientCidr, tproxyPort, fwmark, routeTable };
}

function chapUsers(users, invalid) {
    requireThat(Array.isArray(users) && users.length <= 2048, invalid);
    const logins = new Set(), addresses = new Set();
    return Array.from(users, row => {
        const { login, password, ipAddress, enabled } = row ?? {};
        requireThat(typeof login === 'string' && /^[A-Za-z0-9._@-]{1,64}(?![\s\S])/.test(login)
            && typeof password === 'string' && (/^[ -~]{1,255}(?![\s\S])/.test(password) || /^[A-Za-z0-9_-]{256}(?![\s\S])/.test(password)) && !password.startsWith('@')
            && typeof ipAddress === 'string' && isIPv4(ipAddress) && typeof enabled === 'boolean'
            && !logins.has(login) && !addresses.has(ipAddress), invalid);
        logins.add(login); addresses.add(ipAddress);
        return { login, password, ipAddress, enabled };
    });
}

function makeDesired(input) {
    const bad = () => fail('INSTALL_INPUT_INVALID');
    try {
        const { psk, users, clientCidr, localAddress, poolStart, poolEnd, dnsServers, mtu, mru, tproxyPort, fwmark, routeTable } = input;
        const [network, prefixText, extra] = clientCidr.split('/');
        const prefix = Number(prefixText);
        const first = ipv4(network), size = 2 ** (32 - prefix), last = first + size - 1;
        const usable = address => ipv4(address) > first && ipv4(address) < last;
        const pool = address => usable(address) && ipv4(address) >= ipv4(poolStart) && ipv4(address) <= ipv4(poolEnd);
        if (input.routeGroup != null || !safeSecret(psk) || !Array.isArray(users) || users.length > 2048
            || extra !== undefined || String(prefix) !== prefixText || !integer(prefix, 16, 30) || first % size !== 0
            || ![[0x0a000000, 0x0affffff], [0xac100000, 0xac1fffff], [0xc0a80000, 0xc0a8ffff]]
                .some(([lo, hi]) => first >= lo && last <= hi)
            || ![localAddress, poolStart, poolEnd].every(usable) || ipv4(poolStart) > ipv4(poolEnd) || pool(localAddress)
            || !integer(mtu, 576, 1500) || !integer(mru, 576, 1500)
            || !integer(tproxyPort, 1024, 65535) || [1701, 4500].includes(tproxyPort)
            || !integer(fwmark, 1, 0x7fffffff) || !integer(routeTable, 1, 0x7fffffff) || [253, 254, 255].includes(routeTable)
            || !Array.isArray(dnsServers) || !integer(dnsServers.length, 1, 2) || !dnsServers.every(isIPv4)) throw bad();
        const addresses = new Set(), logins = new Set();
        const rows = Array.from(users, ({ login, password, ipAddress, enabled }) => {
            if (typeof login !== 'string' || !/^[A-Za-z0-9._@-]{1,64}$/.test(login) || !safeSecret(password)
                || !pool(ipAddress) || typeof enabled !== 'boolean' || logins.has(login) || addresses.has(ipAddress)) throw bad();
            logins.add(login); addresses.add(ipAddress);
            return Object.freeze({ login, password, ipAddress, enabled });
        });
        return Object.freeze({ psk, users: Object.freeze(rows), clientCidr, localAddress, poolStart, poolEnd,
            dnsServers: Object.freeze([...dnsServers]), mtu, mru, tproxyPort, fwmark, routeTable });
    } catch { throw bad(); }
}

function buildFiles(d, profiles, backupId) {
    const stock = Object.fromEntries(buildL2tpArtifacts(d).files.map(row => [row.path, row.content]));
    // Include the marker in the exclusive NEWTABLE, not in a later declaration.
    const nft = `create table inet celerity_rebuild_l2tp {
    comment "${backupId}"
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        iifname "ppp*" ip saddr ${d.clientCidr} meta l4proto { tcp, udp } tproxy ip to :${d.tproxyPort} meta mark set ${d.fwmark} accept
    }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "ppp*" ip saddr ${d.clientCidr} meta mark ${d.fwmark} accept
        iifname "ppp*" drop
        meta l4proto { tcp, udp } th dport ${d.tproxyPort} drop
        udp dport 1701 meta ipsec exists accept
        udp dport 1701 drop
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        iifname "ppp*" drop
    }
}
`;
    return Object.fromEntries(Object.entries({
        ...profiles, nft,
        ike: stock['etc/ipsec.d/celerity-l2tp.conf'].replace(/config setup\n    uniqueids=no\n\n/, ''),
        secrets: stock['etc/ipsec.secrets'], lns: stock['etc/xl2tpd/xl2tpd.conf'],
        options: stock['etc/ppp/options.xl2tpd'].replace('mtu 1400\nmru 1400', `mtu ${d.mtu}\nmru ${d.mru}\nnoipv6`),
        chap: reconcileChapSecrets('', d.users).content,
    }).map(([name, value]) => [name, Buffer.from(value).toString('base64')]));
}

let directSource;
function directCommand(limits) {
    // Compress the static helper to fit the remote shell's per-argument limit.
    // Only local source enters shell argv; all request data travels via stdin.
    directSource ??= deflateSync(readFileSync(join(__dirname, 'rebuildRelayDirectHost.py'))).toString('base64');
    const script = `import base64,zlib;exec(compile(zlib.decompress(base64.b64decode("${directSource}")),"<DIRECT host>","exec"))`;
    return `/usr/bin/timeout ${limits} /usr/bin/python3 -I -B -c '${script}'`;
}

function createRelayDirect({ node, env = process.env, SSH } = {}) {
    const nodeId = String(node?._id ?? node?.id ?? '');
    const fence = captureRelayBinding(env, nodeId, node);
    const { host: ip, port, username, machineId, sshHostKeySha256 } = fence.binding;
    // In list mode the card corroborates the endpoint but supplies only auth
    // material to the transport: no socket, proxy, or host verification options.
    const transportNode = fence.listMode ? Object.freeze({ _id: nodeId, name: nodeId, ip,
        ssh: Object.freeze({ port, username, password: node.ssh.password, privateKey: node.ssh.privateKey }),
    }) : node;

    const ssh = new (SSH || require('./nodeSSH'))(transportNode, {
        expectedHostKeySha256: sshHostKeySha256, expectedEndpoint: { ip, port, username },
    });
    ssh.usePool = false;
    let connected = false, closed = false, busy = false, poisoned = false;
    let held;
    const disconnect = () => { try { ssh.disconnect(); } catch { /* cleanup cannot replace outcome */ } };
    function checkBinding() {
        try {
            fence.check();
        } catch (error) {
            poisoned = true;
            disconnect();
            throw error;
        }
    }

    async function connect(timeout) {
        if (connected) return;
        let timer, pending;
        try {
            pending = Promise.resolve(ssh.connect());
            await Promise.race([pending, new Promise((_, reject) => { timer = setTimeout(reject, timeout); })]);
            requireThat(!closed, 'DIRECT_CLOSED');
            connected = true;
        } catch {
            closed = true;
            disconnect();
            void pending?.then(disconnect, () => {});
            throw fail('SSH_CONNECT_FAILED');
        } finally { clearTimeout(timer); }
    }

    async function exec(action, params = {}, write = false, validate = () => true) {
        const count = action === 'session-count';
        const chap = action === 'check-chap' || action === 'sync-chap';
        requireThat(!closed && !poisoned, 'DIRECT_CLOSED');
        checkBinding();
        await connect(count ? 5000 : CONNECT_TIMEOUT_MS);
        requireThat(!closed, 'DIRECT_CLOSED');
        checkBinding();
        const stdin = JSON.stringify({ action, machineId, ...params });
        requireThat(Buffer.byteLength(stdin) <= 25 * 1024 * 1024, 'INSTALL_INPUT_INVALID');
        const unknown = () => {
            if (write) { poisoned = true; disconnect(); }
            return fail('DIRECT_OUTCOME_UNKNOWN', write);
        };
        let result;
        try { result = await ssh.exec(directCommand(count ? '-k 1s 9s' : '-k 4s 125s'), {
            stdin, timeout: count ? SESSION_COUNT_TIMEOUT : TIMEOUT,
        }); }
        catch { throw unknown(); }
        try { checkBinding(); }
        catch (error) { if (write) throw fail('DIRECT_OUTCOME_UNKNOWN', true); throw error; }
        if (!integer(result?.code, 0, 255) || [75, 124, 125, 126, 127].includes(result.code) || result.code >= 128) throw unknown();
        if (result.code !== 0) {
            const refusal = typeof result.stderr === 'string' && /^DIRECT_(NO_WRITE_)?([A-Z_]+)\n$/.exec(result.stderr);
            const raw = refusal?.[2];
            if (count && (result.code !== 70 || result.stdout !== ''
                || result.stderr !== 'DIRECT_SESSION_COUNT_UNPROVED\n')) throw unknown();
            const ipsecBusy = ['prepare-remove', 'remove'].includes(action) && result.stderr === 'DIRECT_REMOVE_IPSEC_BUSY\n';
            if ((action === 'remove' || ipsecBusy) && (result.code !== 70 || result.stdout !== ''
                || (!ipsecBusy && result.stderr !== 'DIRECT_REMOVE_REFUSED\n'))) throw unknown();
            if (chap && (result.code !== 70 || result.stdout !== ''
                || result.stderr !== 'DIRECT_CHAP_REFUSED\n')) throw unknown();
            const codes = ['IDENTITY', 'PREREQUISITE', 'BASELINE_CHANGED', 'PROFILE_USERS', 'NETWORK_CONFLICT',
                'CANDIDATE_INVALID', 'ROLLBACK_DRIFT', 'RUNTIME_UNPROVED', 'COMMAND_FAILED', 'REMOVE_REFUSED'];
            if (count) codes.push('SESSION_COUNT_UNPROVED');
            if (ipsecBusy) codes.push('REMOVE_IPSEC_BUSY');
            if (chap) codes.push('CHAP_REFUSED');
            // Only the installed helper's closed refusal frame certifies a settled write.
            // A shell/transport exit alone is not authority to race a remote mutation.
            if (write && (result.code !== 70 || result.stdout !== '' || !codes.includes(raw))) throw unknown();
            if (refusal?.[1] && action !== 'install') throw unknown();
            const error = fail(codes.includes(raw) ? `DIRECT_${raw}` : 'DIRECT_COMMAND_FAILED');
            if (write) error.commandSettled = true;
            if (refusal?.[1] || chap) error.noHostChanges = true;
            throw error;
        }
        try {
            const replyLimit = (count || chap) ? 160 : 46 * 1024 * 1024;
            if (result.stderr !== '' || Buffer.byteLength(result.stdout) > replyLimit) throw Error();
            const reply = JSON.parse(result.stdout);
            if ((count || chap) && (closed || result.stdout !== `${JSON.stringify(reply)}\n`)) throw Error();
            if (!validate(reply)) throw Error();
            return reply;
        } catch { throw unknown(); }
    }

    const serial = async fn => {
        requireThat(!busy && !closed && !poisoned, 'DIRECT_UNAVAILABLE');
        busy = true;
        try { return await fn(); } finally { busy = false; }
    };
    async function preflight() {
        const proof = await exec('preflight', {}, false, value => value && tokenMatches(TOKEN, value.machineId)
            && ['ppp', 'masked', 'unitsLoaded'].every(key => typeof value[key] === 'boolean'));
        requireThat(proof.machineId === machineId, 'INSTALL_IDENTITY_MISMATCH');
        return { machineId, ppp: proof.ppp, masked: proof.masked, unitsLoaded: proof.unitsLoaded };
    }
    async function lock(check) {
        requireThat(typeof check === 'function', 'DIRECT_LOCK_REQUIRED');
        requireThat(await check() !== false, 'DIRECT_LOCK_REQUIRED');
    }
    const exactAck = backupId => value => value?.ok === true && value.backupId === backupId;

    const chapOperation = (action, installation, currentUsers, desiredUsers, verifyLock, revokedLogin) => serial(async () => {
        const invalid = 'CHAP_INPUT_INVALID', write = action === 'sync-chap';
        requireThat(!held && installation?.nodeId === nodeId && Object.keys(installation).length === 3
            && ['nodeId', 'backupId', 'network'].every(key => Object.hasOwn(installation, key))
            && installation.backupId?.length === 32 && tokenMatches(TOKEN, installation.backupId), invalid);
        const { backupId } = installation;
        const revoke = revokedLogin !== undefined;
        requireThat(!revoke || (tokenMatches(/^[A-Za-z0-9._@-]{1,64}(?![\s\S])/, revokedLogin)
            && revokedLogin !== 'relay-bootstrap'), invalid);
        const params = { nodeId, backupId, network: removeNetwork(installation.network, invalid),
            currentUsers: chapUsers(currentUsers, invalid), desiredUsers: chapUsers(desiredUsers, invalid),
            ...(revoke && { revokedLogin }) };
        requireThat(typeof verifyLock === 'function', 'DIRECT_LOCK_REQUIRED');
        await connect(CONNECT_TIMEOUT_MS);
        await lock(verifyLock);
        const draining = revoke && write;
        const { changed, sessionsTerminated, complete } = await exec(action, params, write, reply => exactAck(backupId)(reply)
            && typeof reply.changed === 'boolean' && (draining ? Object.keys(reply).length === 5
                && integer(reply.sessionsTerminated, 0, Number.MAX_SAFE_INTEGER) && typeof reply.complete === 'boolean'
                : Object.keys(reply).length === 3));
        try {
            await lock(verifyLock);
            requireThat(!closed, 'DIRECT_CLOSED');
        } catch (error) {
            if (!write) throw error;
            poisoned = true;
            disconnect();
            throw fail('DIRECT_OUTCOME_UNKNOWN', true);
        }
        return draining ? { changed, sessionsTerminated, complete } : { changed };
    });

    return Object.freeze({
        preflight: () => serial(preflight),
        checkChap: (...args) => chapOperation('check-chap', ...args),
        syncChap: (...args) => chapOperation('sync-chap', ...args),
        readSessionCount: input => serial(async () => {
            const invalid = 'SESSION_COUNT_INPUT_INVALID';
            requireThat(input?.nodeId === nodeId
                && ['nodeId', 'backupId', 'network'].every(key => Object.hasOwn(input, key))
                && Object.keys(input).every(key => ['nodeId', 'backupId', 'network', 'transit', 'currentUsers'].includes(key))
                && (!Object.hasOwn(input, 'transit') || Array.isArray(input.transit))
                && input.backupId?.length === 32 && tokenMatches(TOKEN, input.backupId), invalid);
            const { backupId } = input;
            const network = removeNetwork(input.network, invalid);
            const params = { nodeId, backupId, network,
                ...(Object.hasOwn(input, 'currentUsers') && { currentUsers: chapUsers(input.currentUsers, invalid) }),
                ...(input.transit !== undefined && { transit: structuredClone(input.transit) }) };
            return exec('session-count', params, false, validCensus);
        }),
        prepare: input => serial(async () => {
            requireThat(!held && input?.nodeId === nodeId && typeof input.carryDomain === 'boolean'
                && Array.isArray(input.controlPlaneAddresses), 'INSTALL_INPUT_INVALID');
            const d = makeDesired(input.desired);
            const controlPlaneAddresses = [...input.controlPlaneAddresses], carryDomain = input.carryDomain;
            const host = await preflight();
            requireThat(host.ppp && !host.masked && host.unitsLoaded, 'HOST_NOT_READY');
            const network = { clientCidr: d.clientCidr, tproxyPort: d.tproxyPort, fwmark: d.fwmark, routeTable: d.routeTable };
            const topology = input.transit === undefined ? {} : { transit: structuredClone(input.transit) };
            const snapshot = await exec('prepare', { network, ...topology }, false, v => v && tokenMatches(PIN, v.baseline));
            requireThat(snapshot.machineId === machineId, 'INSTALL_IDENTITY_MISMATCH');
            const profiles = composeRebuildRelayPair(snapshot, { nodeId, tproxyPort: d.tproxyPort, controlPlaneAddresses,
                carryDomain, mainSha256: snapshot.mainSha256, bridgeSha256: snapshot.bridgeSha256 });
            const backupId = randomBytes(16).toString('hex');
            const params = { backupId, baseline: snapshot.baseline, network, ...topology, files: buildFiles(d, profiles, backupId) };
            await exec('check', params, false, v => v?.ok === true);
            const plan = { nodeId, backupId };
            Object.defineProperty(plan, 'getDesired', { value: () => d });
            held = { plan: Object.freeze(plan), params, phase: 'prepared' };
            return plan;
        }),
        install: (plan, verifyLock) => serial(async () => {
            requireThat(held?.plan === plan && held.phase === 'prepared', 'DIRECT_PLAN_INVALID');
            await lock(verifyLock);
            requireThat(!closed, 'DIRECT_CLOSED');
            held.phase = 'failed';
            held.start = performance.now();
            try { await exec('install', held.params, true, exactAck(plan.backupId)); }
            catch (error) {
                if (error.noHostChanges) held.phase = 'refused';
                throw error;
            }
            held.phase = 'installed';
        }),
        verify: plan => serial(async () => {
            if (held?.plan !== plan || held.phase !== 'installed') return false;
            const { backupId, baseline, network } = held.params;
            try { await exec('verify', { backupId, baseline, network }, false, exactAck(backupId)); return true; }
            catch { return false; }
        }),
        async rollback(plan, verifyLock) {
            if (poisoned || closed || busy || held?.plan !== plan || !['failed', 'installed'].includes(held.phase)
                || performance.now() - held.start >= 300000) return false;
            return serial(async () => {
                const { backupId, baseline, network } = held.params;
                const deadline = held.start + 300000;
                await lock(verifyLock);
                if (closed || performance.now() >= deadline) return false;
                held.phase = 'rollback-attempted';
                try { await exec('rollback', { backupId, baseline, network }, true, exactAck(backupId)); return true; }
                catch (err) { if (err.remoteOutcomeUncertain) throw err; return false; }
            });
        },
        prepareRemove: input => serial(async () => {
            const invalid = 'REMOVE_INPUT_INVALID';
            requireThat(!held && input?.nodeId === nodeId
                && Object.keys(input).every(key => ['nodeId', 'backupId', 'network', 'transit', 'expectedCensus', 'currentUsers'].includes(key))
                && typeof input.backupId === 'string'
                && input.backupId.length === 32 && TOKEN.test(input.backupId), 'REMOVE_INPUT_INVALID');
            const hasCensus = Object.hasOwn(input, 'expectedCensus');
            const { expectedCensus } = input;
            requireThat(!hasCensus || (tokenMatches(PIN, expectedCensus) && expectedCensus.length === 64), 'REMOVE_INPUT_INVALID');
            const params = { nodeId, backupId: input.backupId, network: removeNetwork(input.network),
                ...(Object.hasOwn(input, 'currentUsers') && { currentUsers: chapUsers(input.currentUsers, invalid) }),
                ...(input.transit !== undefined && { transit: structuredClone(input.transit) }) };
            const proof = await exec('prepare-remove', params, false, value => exactAck(params.backupId)(value)
                && value.machineId === machineId && typeof value.baseline === 'string' && value.baseline.length === 64
                && PIN.test(value.baseline));
            const plan = Object.freeze({});
            held = { plan, params: { ...params, baseline: proof.baseline, ...(hasCensus && { expectedCensus }) },
                phase: 'remove-prepared' };
            return plan;
        }),
        remove(plan, verifyLock) {
            if (busy || closed || poisoned || held?.phase !== 'remove-prepared' || held.plan !== plan) return Promise.resolve(false);
            return serial(async () => {
                const { params } = held;
                held.phase = 'remove-attempted';
                // The caller owns exclusion against Apply throughout; DIRECT
                // also rechecks the host snapshot under its local flock.
                try { await lock(verifyLock); } catch { return false; }
                if (closed) return false;
                // Preserve the authenticated pre-intent refusal; only this
                // exact frame permits the caller to unwind its DB reservation.
                await exec('remove', params, true, value => exactAck(params.backupId)(value) && value.removed === true);
                try {
                    await lock(verifyLock);
                    requireThat(!closed, 'DIRECT_CLOSED');
                } catch {
                    poisoned = true;
                    disconnect();
                    throw fail('DIRECT_OUTCOME_UNKNOWN', true);
                }
                return true;
            });
        },
        async close() { if (!closed) { closed = true; held = undefined; disconnect(); } },
    });
}

async function applyRelayNetwork(run, machineId, state, action, proof) {
    const invalid = 'APPLY_NETWORK_NOT_OWNED';
    const { backupId, rebuildMachineId, clientCidr, tproxyPort, fwmark, routeTable } = state;
    requireThat(rebuildMachineId === machineId && backupId?.length === 32 && tokenMatches(TOKEN, backupId)
        && typeof state.rebuildInstallToken === 'string' && state.rebuildInstallToken.length === 36
        && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(state.rebuildInstallToken), invalid);
    const network = removeNetwork({ clientCidr, tproxyPort, fwmark, routeTable }, invalid);
    const unknown = () => fail('APPLY_NETWORK_OUTCOME_UNKNOWN', ['prepare-apply-network', 'restart-apply-network'].includes(action));
    let result;
    try {
        result = await run(directCommand('-k 4s 125s'), { timeout: TIMEOUT,
            stdin: JSON.stringify({ action, machineId, backupId, network, ...(proof !== undefined && { proof }) }) });
    } catch { throw unknown(); }
    if (result?.code === 70 && result.stdout === '' && /^DIRECT_(?:ROLLBACK_DRIFT|IDENTITY|PREREQUISITE|RUNTIME_UNPROVED|CANDIDATE_INVALID|COMMAND_FAILED)\n$(?![\s\S])/.test(result.stderr)) {
        throw fail('APPLY_NETWORK_REFUSED');
    }
    if (result?.code !== 0 || result.stderr !== '' || typeof result.stdout !== 'string' || result.stdout.length > 140) throw unknown();
    let reply;
    try { reply = JSON.parse(result.stdout); } catch { throw unknown(); }
    if (reply?.ok !== true || reply.backupId !== backupId || reply.proof?.length !== 64 || !tokenMatches(PIN, reply.proof)
        || result.stdout !== `${JSON.stringify({ ok: true, backupId, proof: reply.proof })}\n`
        || (proof !== undefined && proof !== reply.proof)) throw unknown();
    return reply.proof;
}

module.exports = { createRelayDirect, applyRelayNetwork };
