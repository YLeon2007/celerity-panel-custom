'use strict';

const { readFileSync } = require('node:fs');
const { deflateSync } = require('node:zlib');
const { join } = require('node:path');
const { randomBytes } = require('node:crypto');
const { isIPv4 } = require('node:net');
const { performance } = require('node:perf_hooks');
const { identityChanged, isIdentityChanged } = require('./rebuildRelayEffectAuthority');
const { captureRelayBinding } = require('./rebuildRelayAuthorization');
const { CONNECT_TIMEOUT_MS } = require('./rebuildSshLimits');
const { validCensus, validRetirementCensus } = require('./rebuildRelayCounts');
const { composeRebuildRelayPair } = require('./rebuildRelayInstallSteps');
const { isInstallStage, specificHostRefusal, packageWriteCheck, prerequisiteCheck, hasNativePreparation, hasPackagePreparation, requireInstallHostReady,
    withInstallCheck } = require('./rebuildRelayInstallDiagnostics');
const { buildL2tpArtifacts } = require('../modules/relay-l2tp/services/l2tpConfigService');
const { reconcileChapSecrets } = require('../modules/relay-l2tp/services/l2tpUserSyncService');
const { reasonFromInspectionFrame } = require('./rebuildRelayInspection');

const TIMEOUT = 145000;
// The package host has 210s from bootstrap; allow shell startup, kill grace,
// and channel handoff/close without widening any other receiver.
const PACKAGE_PREPARE_TIMEOUT = 240000;
const SESSION_COUNT_TIMEOUT = 12000;
const RETIREMENT_COUNT_TIMEOUT = 25000;
const MACHINE_ID_COMMAND = '/usr/bin/head -c 34 /etc/machine-id';
const MACHINE_ID_FRAME = /^([a-f0-9]{32})\n?(?![\s\S])/;
const PIN = /^[a-f0-9]{64}$/;
const TOKEN = /^[a-f0-9]{32}$/;
const CHAP_ACTIONS = ['check-chap', 'sync-chap', 'inspect-chap', 'read-chap-generation', 'fence-chap'];
const directRefusals = new Set(['IDENTITY', 'PREREQUISITE', 'BASELINE_CHANGED', 'PROFILE_USERS', 'NETWORK_CONFLICT',
    'CANDIDATE_INVALID', 'ROLLBACK_DRIFT', 'RUNTIME_UNPROVED', 'COMMAND_FAILED']);
const refusalFrame = /^DIRECT_(NO_WRITE_)?([A-Z][A-Z0-9_]*)\n(?![\s\S])/;
const exactKeys = (value, keys) => value && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
// Python's helper uses compact json.dumps(..., ensure_ascii=True) and LF.
const installReplyFrame = value => `${JSON.stringify(value).replace(/[\u007f-\uffff]/g,
    char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`)}\n`;
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

let directScript;
function encodeDirectBytes(bytes) {
    // RFC 1924 alphabet (Python b85decode). No quotes, backslashes or
    // whitespace, so the result fits both Python string and shell quoting.
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';
    let packed = '';
    for (let i = 0; i < bytes.length; i += 4) {
        const length = Math.min(bytes.length - i, 4);
        let word = 0;
        for (let j = 0; j < 4; j++) word = word * 256 + (j < length ? bytes[i + j] : 0);
        let part = '';
        for (let j = 0; j < 5; j++) {
            part = alphabet[word % 85] + part;
            word = Math.floor(word / 85);
        }
        packed += part.slice(0, length + 1);
    }
    return packed;
}

function bundleDirectScript() {
    const pack = path => encodeDirectBytes(deflateSync(readFileSync(join(__dirname, path))));
    const load = (key, path, name, filename) =>
        `${key}={"__name__":"${name}","__file__":"${filename}"};exec(_c3_compile("${pack(path)}","${filename}"),${key})`;
    // These are fixed repository sources, not imports from the remote working
    // directory. Non-main namespaces keep their standalone entrypoints inert.
    return [
        'import base64,zlib',
        '_c3_compile=lambda data,filename:compile(zlib.decompress(base64.b85decode(data)),filename,"exec")',
        // Runtime's standalone path calculation needs an absolute __file__
        // with parents; the direct host gets the ensure code as a separate dict.
        load('C3_STOCK_RUNTIME', 'rebuildRelayStockRuntime.py', 'c3_stock_runtime',
            '/__c3_direct__/services/rebuildRelayStockRuntime.py'),
        load('C3_STOCK_ENSURE', '../modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py', 'c3_stock_ensure',
            '/__c3_direct__/modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py'),
        load('C3_PACKAGE_GUARD', 'rebuildRelayPackageGuard.py', 'c3_package_guard',
            '/__c3_direct__/services/rebuildRelayPackageGuard.py'),
        `exec(_c3_compile("${pack('rebuildRelayDirectHost.py')}","<DIRECT host>"))`,
    ].join(';');
}

function directCommand(limits) {
    // Only static local source enters shell argv; all request data uses stdin.
    directScript ??= bundleDirectScript();
    const command = `/usr/bin/timeout ${limits} /usr/bin/python3 -I -B -c '${directScript}'`;
    // The whole command is also an argument to the remote shell. Count its NUL.
    requireThat(Buffer.byteLength(command) + 1 <= 128 * 1024, 'DIRECT_COMMAND_TOO_LARGE');
    return command;
}

const recoveryUnsent = new WeakSet();
const installRecoveryWasNotSent = error => recoveryUnsent.has(error);

function createRelayDirect({ node, env = process.env, SSH, fence: authority, verifyRemoveStdin = false } = {}) {
    const nodeId = String(node?._id ?? node?.id ?? '');
    const fence = authority ?? captureRelayBinding(env, nodeId, node);
    const merged = fence.merged === true;
    const { host: ip, port, username, machineId, sshHostKeySha256 } = fence.binding;
    // In list mode the card corroborates the endpoint but supplies only auth
    // material to the transport: no socket, proxy, or host verification options.
    const transportNode = fence.listMode ? Object.freeze({ _id: nodeId, name: nodeId, ip,
        ssh: Object.freeze({ port, username, password: node.ssh.password, privateKey: node.ssh.privateKey }),
    }) : node;

    const Transport = SSH || require('./nodeSSH');
    const ssh = new Transport(transportNode, {
        expectedHostKeySha256: sshHostKeySha256, expectedEndpoint: { ip, port, username },
    });
    ssh.usePool = false;
    let closed = false, busy = false, poisoned = false;
    let execPinned, held, chapObservation, packagePreparation, packageAttempt;
    const disconnect = () => { try { ssh.disconnect(); } catch { /* cleanup cannot replace outcome */ } };
    const poison = () => { if (!poisoned && !closed) { poisoned = true; disconnect(); } };
    async function checkBinding() {
        try {
            await fence.check();
        } catch (error) {
            poison();
            throw error;
        }
    }

    async function connect(timeout) {
        if (execPinned) return;
        try {
            const run = await ssh.connectDirectOnce(timeout);
            requireThat(!closed && typeof run === 'function', 'DIRECT_UNAVAILABLE');
            execPinned = run;
        } catch (error) {
            closed = true;
            disconnect();
            if (error?.code === 'SSH_HOST_KEY_MISMATCH') throw identityChanged();
            throw fail('SSH_CONNECT_FAILED');
        }
    }

    async function attestMachine(timeout) {
        let result;
        try { result = await execPinned(MACHINE_ID_COMMAND, { timeout, maxOutputBytes: 34 }); }
        catch { /* Unavailable, not evidence of a changed identity. */ }
        const observed = result?.code === 0 && result.stderr === '' && typeof result.stdout === 'string'
            && MACHINE_ID_FRAME.exec(result.stdout)?.[1];
        if (observed === machineId && !closed && !poisoned) return;
        poison();
        throw observed && observed !== machineId ? identityChanged() : fail('DIRECT_OUTCOME_UNKNOWN');
    }

    async function exec(action, params = {}, write = false, validate = () => true, verifyLock, dispatch) {
        const retirementCount = action === 'retirement-count';
        const count = action === 'session-count' || retirementCount;
        const chap = CHAP_ACTIONS.includes(action);
        const packageWrite = action === 'prepare-packages';
        const recovery = action === 'reconcile-install';
        const guarded = chap || packageWrite || recovery || action === 'install' || (merged && write)
            || (action === 'remove' && verifyRemoveStdin === true);
        requireThat(!closed && !poisoned, 'DIRECT_CLOSED');
        await checkBinding();
        await connect(count ? 5000 : CONNECT_TIMEOUT_MS);
        requireThat(!closed, 'DIRECT_CLOSED');
        await checkBinding();
        if (guarded) requireThat(typeof verifyLock === 'function', 'DIRECT_LOCK_REQUIRED');
        // No payload construction or receiver channel until this operation's
        // secret-free observation succeeds on the original pinned client.
        await attestMachine(count ? 5000 : CONNECT_TIMEOUT_MS);
        await checkBinding();
        requireThat(!closed && !poisoned, 'DIRECT_CLOSED');
        const stdin = JSON.stringify({ action, machineId, ...params });
        requireThat(Buffer.byteLength(stdin) <= 25 * 1024 * 1024, 'INSTALL_INPUT_INVALID');
        let identityRefusal;
        const verifyBeforeStdin = async () => {
            try {
                requireThat(busy && !closed && !poisoned, 'DIRECT_UNAVAILABLE');
                if (guarded) await lock(verifyLock);
                await fence.check();
                requireThat(busy && !closed && !poisoned, 'DIRECT_UNAVAILABLE');
            } catch (error) {
                // The SSH wrapper sanitizes stdin errors; preserve a local
                // identity veto made before the stream is allowed to write.
                if (isIdentityChanged(error)) identityRefusal = error;
                poison();
                throw error;
            }
        };
        const unknown = () => {
            if (write) poison();
            return fail('DIRECT_OUTCOME_UNKNOWN', write);
        };
        const shellLimits = retirementCount ? '-k 1s 22s' : count ? '-k 1s 9s' : packageWrite ? '-k 4s 220s' : '-k 4s 125s';
        const timeout = retirementCount ? RETIREMENT_COUNT_TIMEOUT : count ? SESSION_COUNT_TIMEOUT
            : packageWrite ? PACKAGE_PREPARE_TIMEOUT : TIMEOUT;
        let result;
        try {
            const command = directCommand(shellLimits);
            if (dispatch) dispatch.possible = true;
            result = await execPinned(command, {
                stdin, timeout,
                ...(packageWrite && { maxOutputBytes: 160 }),
                ...(recovery && { maxOutputBytes: 256 }),
            }, verifyBeforeStdin);
        } catch (error) {
            if (dispatch && !SSH && Transport.execStdinWasNotAttempted(error)) dispatch.possible = false;
            throw identityRefusal ?? unknown();
        }
        try { await checkBinding(); }
        catch (error) { if (write && !isIdentityChanged(error)) throw fail('DIRECT_OUTCOME_UNKNOWN', true); throw error; }
        // A verified diagnostic on rc75 is informational only. Missing or
        // tainted frames take the very same unknown/poison path without a hint.
        if (packageWrite && result?.code === 75) throw withInstallCheck(unknown(), packageWriteCheck(result));
        if (recovery && result?.code !== 0) throw unknown();
        if (!integer(result?.code, 0, 255) || [75, 124, 125, 126, 127].includes(result.code) || result.code >= 128) throw unknown();
        if (result.code !== 0) {
            if (result.code === 70 && result.stdout === ''
                && (result.stderr === 'DIRECT_IDENTITY\n' || action === 'install' && result.stderr === 'DIRECT_NO_WRITE_IDENTITY\n')) {
                poison();
                throw identityChanged();
            }
            // A package-phase refusal isn't an Install no-write certificate.
            // Whatever stopped the helper, do not infer package settlement.
            if (packageWrite) throw withInstallCheck(unknown(), packageWriteCheck(result));
            if (action === 'inspect-chap') {
                const reason = !closed && result.code === 70 && result.stdout === '' && reasonFromInspectionFrame(result.stderr);
                if (!reason) throw unknown();
                throw Object.assign(fail('DIRECT_INSPECT_UNPROVED'), { inspectionReason: reason });
            }
            const refusal = typeof result.stderr === 'string' && refusalFrame.exec(result.stderr);
            if (result.code !== 70 || result.stdout !== '' || !refusal) throw unknown();
            const [, noWrite, raw] = refusal;
            if (noWrite && action !== 'install') throw unknown();
            const specific = specificHostRefusal(action, raw, Boolean(noWrite));
            const ipsecBusy = ['prepare-remove', 'remove'].includes(action) && raw === 'REMOVE_IPSEC_BUSY';
            const retirementChanged = ['prepare-remove', 'remove'].includes(action) && params.retirement === true
                && raw === 'REMOVE_PREVIEW_CHANGED';
            const allowed = count ? raw === 'SESSION_COUNT_UNPROVED'
                : chap ? raw === 'CHAP_REFUSED'
                    : action === 'remove' ? retirementChanged || ipsecBusy || raw === 'REMOVE_REFUSED'
                        : retirementChanged || ipsecBusy || directRefusals.has(raw) || specific !== undefined;
            if (!allowed) throw unknown();
            // Only the installed helper's closed refusal frame certifies a settled write.
            // A shell/transport exit alone is not authority to race a remote mutation.
            const error = fail(`DIRECT_${specific ? 'PREREQUISITE' : raw}`);
            const check = specific?.check ?? (raw === 'PREREQUISITE' ? prerequisiteCheck(action) : undefined);
            withInstallCheck(error, check);
            // Shared PPP preparation may have no safe inverse.
            if (specific?.prerequisitePartial) {
                error.prerequisitePartial = true;
                throw error;
            }
            if (write) error.commandSettled = true;
            if (noWrite || chap) error.noHostChanges = true;
            throw error;
        }
        try {
            const replyLimit = recovery ? 256 : action === 'inspect-chap' ? 170 : (count || chap || packageWrite) ? 160 : 46 * 1024 * 1024;
            if (result.stderr !== '' || Buffer.byteLength(result.stdout) > replyLimit) throw Error();
            const reply = JSON.parse(result.stdout);
            if ((count || chap) && (closed || result.stdout !== `${JSON.stringify(reply)}\n`)) throw Error();
            if ((packageWrite || recovery || isInstallStage(action) || ['verify', 'rollback'].includes(action))
                && (closed || result.stdout !== installReplyFrame(reply))) throw Error();
            if (!validate(reply)) throw Error();
            return reply;
        } catch { throw unknown(); }
    }

    const serial = async fn => {
        requireThat(!busy && !closed && !poisoned, 'DIRECT_UNAVAILABLE');
        busy = true;
        try { return await fn(); } finally { busy = false; }
    };
    const readinessKeys = ['machineId', 'ppp', 'masked', 'unitsLoaded'];
    const preparationKeys = [...readinessKeys, 'pppPreparation'];
    const validReadiness = value => tokenMatches(TOKEN, value.machineId) && value.machineId.length === 32
        && ['ppp', 'masked', 'unitsLoaded'].every(key => typeof value[key] === 'boolean');
    async function preflight() {
        const proof = await exec('preflight', {}, false, value => hasPackagePreparation(value) || ((exactKeys(value, readinessKeys)
            || (exactKeys(value, preparationKeys) && value.pppPreparation === true)
            || hasNativePreparation(value)) && validReadiness(value)));
        if (proof.machineId !== machineId) { poison(); throw merged ? identityChanged() : fail('INSTALL_IDENTITY_MISMATCH'); }
        return proof;
    }
    async function lock(check) {
        requireThat(typeof check === 'function', 'DIRECT_LOCK_REQUIRED');
        requireThat(await check() !== false, 'DIRECT_LOCK_REQUIRED');
    }
    const exactAck = backupId => value => value?.ok === true && value.backupId === backupId;
    const installAck = backupId => value => exactKeys(value, ['ok', 'backupId']) && exactAck(backupId)(value);
    const validGeneration = value => value?.length === 32 && tokenMatches(TOKEN, value);

    const chapOperation = (action, installation, currentUsers, desiredUsers, verifyLock, revokedLogin) => serial(async () => {
        const invalid = 'CHAP_INPUT_INVALID', sync = action === 'sync-chap';
        const inspect = action === 'inspect-chap', retire = action === 'fence-chap', write = sync || retire;
        if (!sync) chapObservation = undefined;
        requireThat(!held && installation?.nodeId === nodeId && Object.keys(installation).length === 3
            && ['nodeId', 'backupId', 'network'].every(key => Object.hasOwn(installation, key))
            && installation.backupId?.length === 32 && tokenMatches(TOKEN, installation.backupId), invalid);
        const { backupId } = installation;
        const revoke = revokedLogin !== undefined;
        requireThat(!revoke || (tokenMatches(/^[A-Za-z0-9._@-]{1,64}(?![\s\S])/, revokedLogin)
            && revokedLogin !== 'relay-bootstrap'), invalid);
        const binding = { nodeId, backupId, network: removeNetwork(installation.network, invalid) };
        const installKey = JSON.stringify(binding);
        const params = { ...binding,
            currentUsers: chapUsers(currentUsers, invalid), desiredUsers: chapUsers(desiredUsers, invalid),
            ...(revoke && { revokedLogin }) };
        requireThat(typeof verifyLock === 'function', 'DIRECT_LOCK_REQUIRED');
        if (sync) {
            requireThat(chapObservation?.installKey === installKey, 'DIRECT_CHAP_CHECK_REQUIRED');
            if (chapObservation.generation !== undefined) params.generation = chapObservation.generation;
        }
        await lock(verifyLock);
        if (retire) {
            // Read only the CAS preimage, not the CHAP/PPP projection. The
            // coordinator must inspect again after the retirement is durable.
            const preimage = await exec('read-chap-generation', binding, false, value => exactAck(backupId)(value)
                && Object.keys(value).length === 3 && (value.generation === null || validGeneration(value.generation)), verifyLock);
            await lock(verifyLock);
            params.generation = preimage.generation;
        }
        const draining = revoke && sync;
        const reply = await exec(action, params, write, value => {
            if (!exactAck(backupId)(value)) return false;
            if (retire) return Object.keys(value).length === 3 && value.fenced === true;
            const versioned = Object.hasOwn(value, 'generation');
            if (versioned && (sync || !validGeneration(value.generation))) return false;
            const keys = Object.keys(value).length - Number(versioned);
            if (inspect) return keys === 4 && ['original', 'desired', 'both'].includes(value.projection)
                && integer(value.activeTargetSessions, 0, revoke ? Number.MAX_SAFE_INTEGER : 0);
            return typeof value.changed === 'boolean' && (draining ? keys === 5
                && integer(value.sessionsTerminated, 0, Number.MAX_SAFE_INTEGER) && typeof value.complete === 'boolean'
                : keys === 3);
        }, verifyLock);
        try {
            await lock(verifyLock);
            requireThat(!closed, 'DIRECT_CLOSED');
        } catch (error) {
            if (!write) throw error;
            poison();
            if (isIdentityChanged(error)) throw error;
            throw fail('DIRECT_OUTCOME_UNKNOWN', true);
        }
        if (retire) return { fenced: true };
        if (!sync) chapObservation = { installKey, generation: reply.generation };
        if (inspect) return { projection: reply.projection, activeTargetSessions: reply.activeTargetSessions };
        const { changed, sessionsTerminated, complete } = reply;
        return draining ? { changed, sessionsTerminated, complete } : { changed };
    });

    const sessionCount = (input, retirement) => serial(async () => {
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
        return retirement ? exec('retirement-count', params, false, validRetirementCensus)
            : exec('session-count', params, false, validCensus);
    });

    return Object.freeze({
        preflight: () => serial(async () => {
            packagePreparation = undefined;
            const proof = await preflight();
            if (!packageAttempt && hasPackagePreparation(proof)) packagePreparation = proof.packagePreparation;
            return proof;
        }),
        preparePackages: (backupId, verifyLock) => serial(async () => {
            requireThat(merged && fence.listMode === true && fence.source === 'db' && !held && !packageAttempt
                && packagePreparation !== undefined && validGeneration(backupId), 'INSTALL_INPUT_INVALID');
            requireThat(typeof verifyLock === 'function', 'DIRECT_LOCK_REQUIRED');
            // Only the pinned client's preflight can supply this proof. Burn
            // it before attempting the write, even if the reply is lost.
            const params = { backupId, packagePreparation };
            packagePreparation = undefined;
            packageAttempt = { backupId, ready: false };
            await exec('prepare-packages', params, true, value => exactKeys(value, ['ok', 'backupId', 'packagesReady'])
                && exactAck(backupId)(value) && value.packagesReady === true, verifyLock);
            packageAttempt.ready = true;
            return true;
        }),
        checkChap: (...args) => chapOperation('check-chap', ...args),
        syncChap: (...args) => chapOperation('sync-chap', ...args),
        inspectChap: (...args) => chapOperation('inspect-chap', ...args),
        fenceChap: (...args) => chapOperation('fence-chap', ...args),
        readSessionCount: input => sessionCount(input, false),
        readRetirementCount: input => sessionCount(input, true),
        prepare: input => serial(async () => {
            requireThat(!held && (!packageAttempt || packageAttempt.ready) && input?.nodeId === nodeId && typeof input.carryDomain === 'boolean'
                && Array.isArray(input.controlPlaneAddresses), 'INSTALL_INPUT_INVALID');
            const d = makeDesired(input.desired);
            const controlPlaneAddresses = [...input.controlPlaneAddresses], carryDomain = input.carryDomain;
            const host = await preflight();
            requireInstallHostReady(host);
            const network = { clientCidr: d.clientCidr, tproxyPort: d.tproxyPort, fwmark: d.fwmark, routeTable: d.routeTable };
            const topology = input.transit === undefined ? {} : { transit: structuredClone(input.transit) };
            const snapshot = await exec('prepare', { network, ...topology }, false, v => exactKeys(v,
                [...readinessKeys, 'baseline', 'main', 'mainSha256', 'bridge', 'bridgeSha256'])
                && validReadiness(v) && tokenMatches(PIN, v.baseline) && v.baseline.length === 64);
            if (snapshot.machineId !== machineId) { poison(); throw merged ? identityChanged() : fail('INSTALL_IDENTITY_MISMATCH'); }
            // Prepare has no capability fields. Use only the fresh preflight
            // proof from this serial exchange on the same pinned connection.
            requireInstallHostReady(snapshot, host);
            const profiles = composeRebuildRelayPair(snapshot, { nodeId, tproxyPort: d.tproxyPort, controlPlaneAddresses,
                carryDomain, mainSha256: snapshot.mainSha256, bridgeSha256: snapshot.bridgeSha256 });
            const backupId = packageAttempt?.backupId ?? randomBytes(16).toString('hex');
            const params = { backupId, baseline: snapshot.baseline, network, ...topology, files: buildFiles(d, profiles, backupId) };
            await exec('check', params, false, installAck(backupId));
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
            try { await exec('install', held.params, true, installAck(plan.backupId), verifyLock); }
            catch (error) {
                if (error.noHostChanges) held.phase = 'refused';
                if (error.prerequisitePartial) held.phase = 'prerequisite-partial';
                throw error;
            }
            held.phase = 'installed';
        }),
        verify: plan => serial(async () => {
            if (held?.plan !== plan || held.phase !== 'installed') return false;
            const { backupId, baseline, network } = held.params;
            try { await exec('verify', { backupId, baseline, network }, false, installAck(backupId)); return true; }
            catch (error) {
                // Bad or lost readback is not a checked negative receipt.
                if (error.code === 'REBUILD_L2TP_DIRECT_OUTCOME_UNKNOWN' || isIdentityChanged(error)) throw error;
                return false;
            }
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
                try { await exec('rollback', { backupId, baseline, network }, true, installAck(backupId), verifyLock); return true; }
                catch (err) { if (err.remoteOutcomeUncertain || isIdentityChanged(err)) throw err; return false; }
            });
        },
        reconcileInstall(input, verifyLock) {
            const dispatch = { possible: false };
            return serial(async () => {
                const invalid = 'INSTALL_INPUT_INVALID';
                requireThat(merged && fence.listMode === true && fence.source === 'db' && !execPinned
                    && !held && !packageAttempt && input?.nodeId === nodeId && validGeneration(input.backupId)
                    && Object.keys(input).every(key => ['nodeId', 'backupId', 'network', 'packagePreparation'].includes(key)), invalid);
                const { backupId, packagePreparation: planDigest } = input;
                requireThat(!Object.hasOwn(input, 'packagePreparation') || (planDigest?.length === 64 && tokenMatches(PIN, planDigest)), invalid);
                const network = removeNetwork(input.network, invalid);
                const challenge = randomBytes(16).toString('hex');
                const params = { nodeId, backupId, network, challenge, ...(planDigest !== undefined && { packagePreparation: planDigest }) };
                try {
                    await lock(verifyLock);
                    const proof = await exec('reconcile-install', params, true, value =>
                        ['absent', 'rolled_back'].includes(value?.result)
                        && JSON.stringify(value) === JSON.stringify({ nodeId, backupId, machineId, challenge, result: value.result }), verifyLock, dispatch);
                    await lock(verifyLock);
                    await checkBinding();
                    requireThat(!closed && !poisoned, 'DIRECT_UNAVAILABLE');
                    return proof.result;
                } finally {
                    // Recovery never joins or reuses an old Install connection, and
                    // this driver does not open a second channel to replay it.
                    if (!closed && !poisoned) disconnect();
                    closed = true;
                }
            }).catch(() => {
                // Errors/codes supplied by a peer or an alternative transport
                // cannot certify no dispatch. Only the local writer can.
                const error = fail('DIRECT_OUTCOME_UNKNOWN', true);
                if (!dispatch.possible) recoveryUnsent.add(error);
                throw error;
            });
        },
        prepareRemove: input => serial(async () => {
            const invalid = 'REMOVE_INPUT_INVALID';
            requireThat(!held && input?.nodeId === nodeId
                && Object.keys(input).every(key => ['nodeId', 'backupId', 'network', 'transit', 'expectedCensus', 'currentUsers', 'retirement', 'drain'].includes(key))
                && typeof input.backupId === 'string'
                && input.backupId.length === 32 && TOKEN.test(input.backupId), 'REMOVE_INPUT_INVALID');
            const hasCensus = Object.hasOwn(input, 'expectedCensus');
            const { expectedCensus } = input;
            requireThat(!hasCensus || (tokenMatches(PIN, expectedCensus) && expectedCensus.length === 64), 'REMOVE_INPUT_INVALID');
            const retirement = Object.hasOwn(input, 'retirement'), drain = Object.hasOwn(input, 'drain');
            requireThat((!retirement || (input.retirement === true && hasCensus && verifyRemoveStdin === true))
                && (!drain || (retirement && input.drain === true)), invalid);
            const params = { nodeId, backupId: input.backupId, network: removeNetwork(input.network),
                ...(Object.hasOwn(input, 'currentUsers') && { currentUsers: chapUsers(input.currentUsers, invalid) }),
                ...(input.transit !== undefined && { transit: structuredClone(input.transit) }),
                ...(retirement && { retirement: true, expectedCensus, ...(drain && { drain: true }) }) };
            const proof = await exec('prepare-remove', params, false, value => exactAck(params.backupId)(value)
                && tokenMatches(TOKEN, value.machineId) && typeof value.baseline === 'string' && value.baseline.length === 64
                && PIN.test(value.baseline));
            if (proof.machineId !== machineId) { poison(); throw identityChanged(); }
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
                try { await lock(verifyLock); } catch (error) { if (isIdentityChanged(error)) throw error; return false; }
                if (closed) return false;
                // Preserve the authenticated pre-intent refusal; only this
                // exact frame permits the caller to unwind its DB reservation.
                await exec('remove', params, true, value => exactAck(params.backupId)(value) && value.removed === true, verifyLock);
                try {
                    await lock(verifyLock);
                    requireThat(!closed, 'DIRECT_CLOSED');
                } catch (error) {
                    poison();
                    if (isIdentityChanged(error)) throw error;
                    throw fail('DIRECT_OUTCOME_UNKNOWN', true);
                }
                return true;
            });
        },
        async close() { if (!closed) { closed = true; held = undefined; if (!poisoned) disconnect(); } },
    });
}

async function applyRelayNetwork(run, machineId, state, action, proof, merged = false) {
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
    } catch (error) { if (isIdentityChanged(error)) throw error; throw unknown(); }
    if (merged && result?.code === 70 && result.stdout === '' && result.stderr === 'DIRECT_IDENTITY\n') throw identityChanged();
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

module.exports = { createRelayDirect, applyRelayNetwork, installRecoveryWasNotSent };
