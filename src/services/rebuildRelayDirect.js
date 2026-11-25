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
    withInstallCheck, freshConflictFromFrame, withFreshConflict } = require('./rebuildRelayInstallDiagnostics');
const { buildL2tpArtifacts } = require('../modules/relay-l2tp/services/l2tpConfigService');
const { reconcileChapSecrets } = require('../modules/relay-l2tp/services/l2tpUserSyncService');
const { reasonFromInspectionFrame } = require('./rebuildRelayInspection');
const { networkObservationRequired } = require('./rebuildRelayRuntimeRefusal');

const { progressWire } = require('./rebuildInstallProgressWire');
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
const RUNTIME_READS = new Set(['session-count', 'retirement-count', 'inspect-chap', 'check-chap', 'read-chap-generation', 'prepare-remove']);
const runtimeReattestRequired = Symbol('authenticated runtime reattestation refusal');
const runtimeReattestFrame = result => result?.code === 70 && result.stdout === ''
    && result.stderr === 'DIRECT_RUNTIME_REATTEST_REQUIRED\n';
const runtimeForeignFrame = result => result?.code === 70 && result.stdout === ''
    && result.stderr === 'DIRECT_RUNTIME_FOREIGN_CHANGE\n';
// Accepted only for installed observations and their metadata reattestation.
const networkObservationFrame = result => result?.code === 70 && result.stdout === ''
    && result.stderr === `DIRECT_${networkObservationRequired}\n`;
const runtimeIdentityFrame = result => result?.code === 70 && result.stdout === '' && result.stderr === 'DIRECT_IDENTITY\n';
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

async function readWithRuntimeReattestation(read, reattest) {
    try { return await read(); }
    catch (error) { if (error !== runtimeReattestRequired) throw error; }
    if (reattest) await reattest();
    else throw fail('DIRECT_RUNTIME_REATTEST_REQUIRED');
    // The ACK is not an observation. Only the original read, run once more
    // with its original inputs and authority, can yield a fresh observation.
    try { return await read(); }
    catch (error) {
        if (error === runtimeReattestRequired) throw fail('DIRECT_RUNTIME_REATTEST_REQUIRED');
        throw error;
    }
}

const runtimeAck = (result, backupId) => result?.code === 0 && result.stderr === ''
    && result.stdout === installReplyFrame({ ok: true, backupId });

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
// Seven base-120 digits carry six bytes. The SSH exec string (no PTY) and
// POSIX single quotes preserve this ASCII alphabet verbatim. Exclude NUL,
// CR/LF, EOF/DEL and both layers' quote/escape characters.
const directAlphabet = Array.from({ length: 127 }, (_, i) => i + 1)
    .filter(i => ![10, 13, 26, 34, 39, 92, 127].includes(i)).map(i => String.fromCharCode(i)).join('');
function encodeDirectBytes(bytes) {
    let packed = '';
    // 120**29 covers all 25-byte words; larger blocks reduce radix padding
    // without needing any non-stdlib decoder or changing the SSH frame.
    for (let i = 0; i < bytes.length; i += 25) {
        let word = 0n;
        for (let j = 0; j < 25; j++) word = (word << 8n) | BigInt(bytes[i + j] ?? 0);
        let part = '';
        for (let j = 0; j < 29; j++) {
            part = directAlphabet[Number(word % 120n)] + part;
            word /= 120n;
        }
        packed += part;
    }
    return packed;
}

function bundleDirectScript() {
    // Compress a single stream to share the zlib window across sources, but
    // compile the original bytes separately in their original namespaces.
    const sources = ['../modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py', 'rebuildRelayStockRuntime.py',
        'rebuildRelayPackageGuard.py', 'rebuildRelayDirectHost.py'].map(path => readFileSync(join(__dirname, path)));
    const offsets = sources.reduce((indexes, source) => [...indexes, indexes.at(-1) + source.length], [0]);
    const joined = Buffer.concat(sources);
    // Give frequent identifiers and whitespace runs (including newline + indent) a one-byte representation
    // before deflate. Only use byte values absent from the original sources:
    // UTF-8 and all other original bytes must survive without normalization.
    const text = joined.toString('latin1'), tokens = /\n *| +|[A-Za-z_][A-Za-z0-9_]+/g;
    const counts = new Map();
    for (const [word] of text.matchAll(tokens)) counts.set(word, (counts.get(word) || 0) + 1);
    const dictionary = {}, codes = new Map();
    const available = Array.from({ length: 128 }, (_, i) => i + 128).filter(byte => !joined.includes(byte));
    const savings = ([word, count]) => (word.length - 1) * (count - 1);
    [...counts].filter(item => savings(item) > 0).sort((a, b) => savings(b) - savings(a))
        .slice(0, available.length).forEach(([word], i) => {
            dictionary[available[i]] = word;
            codes.set(word, String.fromCharCode(available[i]));
        });
    const packed = Buffer.from(`${JSON.stringify(dictionary)}\n${text.replace(tokens, word => codes.get(word) ?? word)}`, 'latin1');
    const compressed = deflateSync(packed, { level: 9, memLevel: 9 });
    const load = (key, index, name, filename) =>
        `${key}={"__name__":"${name}","__file__":"${filename}"};exec(_c3_compile(${index},"${filename}"),${key})`;
    // These are fixed repository sources, not imports from the remote working
    // directory. Non-main namespaces keep their standalone entrypoints inert.
    return [
        'import zlib,functools,json,re',
        `_c3_digits={c:i for i,c in enumerate("${directAlphabet}")}`,
        '_c3_chunk=lambda chunk:functools.reduce(lambda n,c:n*120+_c3_digits[c],chunk,0).to_bytes(25,"big")',
        `_c3_payload="${encodeDirectBytes(compressed)}"`,
        `_c3_dict,_,_c3_packed=zlib.decompress(b"".join(_c3_chunk(_c3_payload[i:i+29]) for i in range(0,len(_c3_payload),29))[:${compressed.length}]).partition(b"\\n")`,
        '_c3_words={int(k):v.encode("ascii") for k,v in json.loads(_c3_dict).items()}',
        '_c3_sources=re.sub(rb"[\\x80-\\xff]",lambda m:_c3_words.get(m[0][0],m[0]),_c3_packed)',
        `_c3_offsets=${JSON.stringify(offsets)}`,
        '_c3_compile=lambda n,filename:compile(_c3_sources[_c3_offsets[n]:_c3_offsets[n+1]],filename,"exec")',
        // Runtime's standalone path calculation needs an absolute __file__
        // with parents; the direct host gets the ensure code as a separate dict.
        load('C3_STOCK_RUNTIME', 1, 'c3_stock_runtime',
            '/__c3_direct__/services/rebuildRelayStockRuntime.py'),
        load('C3_STOCK_ENSURE', 0, 'c3_stock_ensure',
            '/__c3_direct__/modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py'),
        load('C3_PACKAGE_GUARD', 2, 'c3_package_guard',
            '/__c3_direct__/services/rebuildRelayPackageGuard.py'),
        'exec(_c3_compile(3,"<DIRECT host>"))',
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
    let execPinned, held, chapObservation, packagePreparation, packageAttempt, appliedMain;
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

    async function exec(action, params = {}, write = false, validate = () => true, verifyLock, dispatch, notify) {
        const retirementCount = action === 'retirement-count';
        const count = action === 'session-count' || retirementCount;
        const chap = CHAP_ACTIONS.includes(action);
        const packageWrite = action === 'prepare-packages';
        const mainProof = action === 'prove-applied-main';
        const telemetry = progressWire(action, notify);
        const recovery = action === 'reconcile-install';
        const reattest = action === 'reattest-runtime';
        const guarded = chap || packageWrite || mainProof || recovery || action === 'install' || (merged && write)
            || reattest || (action === 'remove' && verifyRemoveStdin === true) || (RUNTIME_READS.has(action) && verifyLock !== undefined);
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
        const stdin = JSON.stringify({ action, machineId, ...params, ...(telemetry && { progress: true }) });
        requireThat(Buffer.byteLength(stdin) <= 25 * 1024 * 1024, 'INSTALL_INPUT_INVALID');
        let identityRefusal, localReadVeto;
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
                if (reattest || mainProof || RUNTIME_READS.has(action)) localReadVeto = { error };
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
                ...(packageWrite && { maxOutputBytes: 160 + (telemetry ? 64 : 0) }),
                ...(mainProof && { maxOutputBytes: 160 }),
                ...(telemetry && { observeStderr: telemetry.tap }),
                ...((recovery || reattest) && { maxOutputBytes: 256 }),
            }, verifyBeforeStdin);
        } catch (error) {
            if (dispatch && !SSH && Transport.execStdinWasNotAttempted(error)) dispatch.possible = false;
            if (localReadVeto) throw localReadVeto.error;
            if (reattest && !SSH && Transport.execStdinWasNotAttempted(error)) throw fail('SSH_CONNECT_FAILED');
            throw identityRefusal ?? unknown();
        }
        const conflictFrame = result;
        if (telemetry && result) result = { ...result, stderr: telemetry.strip(result.stderr) };
        try { await checkBinding(); }
        catch (error) { if (write && !isIdentityChanged(error)) throw fail('DIRECT_OUTCOME_UNKNOWN', true); throw error; }
        if (reattest) {
            if (!closed && runtimeAck(result, params.backupId)) return;
            if (!closed && runtimeIdentityFrame(result)) { poison(); throw identityChanged(); }
            if (!closed && runtimeForeignFrame(result)) throw fail('DIRECT_RUNTIME_FOREIGN_CHANGE');
            if (!closed && networkObservationFrame(result)) throw fail(`DIRECT_${networkObservationRequired}`);
            throw unknown();
        }
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
            if (RUNTIME_READS.has(action) && !closed) {
                if (runtimeReattestFrame(result)) throw runtimeReattestRequired;
                if (runtimeForeignFrame(result)) throw fail('DIRECT_RUNTIME_FOREIGN_CHANGE');
                if (networkObservationFrame(result)) throw fail(`DIRECT_${networkObservationRequired}`);
            }
            if (action === 'inspect-chap') {
                const reason = !closed && result.code === 70 && result.stdout === '' && reasonFromInspectionFrame(result.stderr);
                if (!reason) throw unknown();
                throw Object.assign(fail('DIRECT_INSPECT_UNPROVED'), { inspectionReason: reason });
            }
            // Restart progress follows host effects and contradicts a fresh no-write claim.
            const conflict = !closed && !poisoned && freshConflictFromFrame(action, conflictFrame);
            if (conflict) {
                const error = withFreshConflict(fail(conflict.check.slice('L2TP_'.length)), conflict);
                if (action === 'install') Object.assign(error, { commandSettled: true, noHostChanges: true });
                throw error;
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
            const replyLimit = recovery ? 256 : action === 'inspect-chap' ? 170 : (count || chap || packageWrite || mainProof) ? 160 : 46 * 1024 * 1024;
            if (result.stderr !== '' || Buffer.byteLength(result.stdout) > replyLimit) throw Error();
            const reply = JSON.parse(result.stdout);
            if ((count || chap) && (closed || result.stdout !== `${JSON.stringify(reply)}\n`)) throw Error();
            if ((packageWrite || mainProof || recovery || isInstallStage(action) || ['verify', 'rollback'].includes(action))
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
    function readInstalled(action, params, validate, verifyLock) {
        const { backupId, network } = params;
        const installation = { nodeId, backupId, network };
        return readWithRuntimeReattestation(() => exec(action, params, false, validate, verifyLock), async () => {
            requireThat(nodeId.length === 24 && tokenMatches(/^[a-f0-9]{24}$/, nodeId), 'DIRECT_RUNTIME_REATTEST_REQUIRED');
            await lock(verifyLock);
            await exec('reattest-runtime', installation, true, undefined, verifyLock);
            await lock(verifyLock);
        });
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
            const preimage = await readInstalled('read-chap-generation', binding, value => exactAck(backupId)(value)
                && Object.keys(value).length === 3 && (value.generation === null || validGeneration(value.generation)), verifyLock);
            await lock(verifyLock);
            params.generation = preimage.generation;
        }
        const draining = revoke && sync;
        const validate = value => {
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
        };
        const reply = RUNTIME_READS.has(action) ? await readInstalled(action, params, validate, verifyLock)
            : await exec(action, params, write, validate, verifyLock);
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

    const sessionCount = (input, retirement, verifyLock) => serial(async () => {
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
        return retirement ? readInstalled('retirement-count', params, validRetirementCensus, verifyLock)
            : readInstalled('session-count', params, validCensus, verifyLock);
    });

    return Object.freeze({
        preflight: () => serial(async () => {
            packagePreparation = undefined;
            const proof = await preflight();
            if (!packageAttempt && hasPackagePreparation(proof)) packagePreparation = proof.packagePreparation;
            return proof;
        }),
        proveAppliedMain: (sha256, guard) => serial(async () => {
            requireThat(sha256?.length === 64 && tokenMatches(PIN, sha256), 'INSTALL_INPUT_INVALID');
            const reply = await exec('prove-applied-main', { appliedMain: sha256 }, false,
                value => exactKeys(value, ['applied']) && typeof value.applied === 'boolean', guard);
            appliedMain = reply.applied ? sha256 : undefined;
            return reply.applied;
        }),
        preparePackages: (backupId, verifyLock, notify) => serial(async () => {
            requireThat(merged && fence.listMode === true && fence.source === 'db' && !held && !packageAttempt
                && appliedMain !== undefined && packagePreparation !== undefined && validGeneration(backupId), 'INSTALL_INPUT_INVALID');
            requireThat(typeof verifyLock === 'function', 'DIRECT_LOCK_REQUIRED');
            // Only the pinned client's preflight can supply this proof. Burn
            // it before attempting the write, even if the reply is lost.
            const params = { backupId, packagePreparation, appliedMain };
            packagePreparation = undefined;
            packageAttempt = { backupId, ready: false };
            await exec('prepare-packages', params, true, value => exactKeys(value, ['ok', 'backupId', 'packagesReady'])
                && exactAck(backupId)(value) && value.packagesReady === true, verifyLock, undefined, notify);
            packageAttempt.ready = true;
            return true;
        }),
        checkChap: (...args) => chapOperation('check-chap', ...args),
        syncChap: (...args) => chapOperation('sync-chap', ...args),
        inspectChap: (...args) => chapOperation('inspect-chap', ...args),
        fenceChap: (...args) => chapOperation('fence-chap', ...args),
        readSessionCount: (input, verifyLock) => sessionCount(input, false, verifyLock),
        readRetirementCount: (input, verifyLock) => sessionCount(input, true, verifyLock),
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
            if (input.appliedMain !== undefined && (input.appliedMain !== appliedMain || input.appliedMain !== snapshot.mainSha256)) {
                throw fail('TOPOLOGY_NOT_APPLIED');
            }
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
        install: (plan, verifyLock, notify) => serial(async () => {
            requireThat(held?.plan === plan && held.phase === 'prepared', 'DIRECT_PLAN_INVALID');
            await lock(verifyLock);
            requireThat(!closed, 'DIRECT_CLOSED');
            held.phase = 'failed';
            held.start = performance.now();
            try { await exec('install', held.params, true, installAck(plan.backupId), verifyLock, undefined, notify); }
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
        prepareRemove: (input, verifyLock) => serial(async () => {
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
            const proof = await readInstalled('prepare-remove', params, value => exactAck(params.backupId)(value)
                && tokenMatches(TOKEN, value.machineId) && typeof value.baseline === 'string' && value.baseline.length === 64
                && PIN.test(value.baseline), verifyLock);
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

async function applyRelayNetwork(run, machineId, state, action, proof, merged = false, runtime, publication) {
    const invalid = 'APPLY_NETWORK_NOT_OWNED';
    const { backupId, rebuildMachineId, clientCidr, tproxyPort, fwmark, routeTable } = state;
    requireThat(rebuildMachineId === machineId && backupId?.length === 32 && tokenMatches(TOKEN, backupId)
        && typeof state.rebuildInstallToken === 'string' && state.rebuildInstallToken.length === 36
        && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(state.rebuildInstallToken), invalid);
    const network = removeNetwork({ clientCidr, tproxyPort, fwmark, routeTable }, invalid);
    const publishing = action === 'publish-apply-profiles';
    const finalizing = action === 'finalize-apply-profiles';
    if (publishing) requireThat(publication && publication.nodeId === String(state.node ?? '')
        && tokenMatches(/^[a-f0-9]{24}$/, publication.nodeId), invalid);
    const unknown = () => fail('APPLY_NETWORK_OUTCOME_UNKNOWN', publishing || finalizing
        || ['prepare-apply-network', 'restart-apply-network'].includes(action));
    const read = async () => {
        let result;
        try {
            result = await run(directCommand('-k 4s 125s'), { timeout: TIMEOUT,
                stdin: JSON.stringify({ action, machineId, backupId, network, ...(proof !== undefined && { proof }),
                    ...(publishing && { nodeId: publication.nodeId, stageId: publication.stageId,
                        profiles: publication.profiles, bridgeUnit: publication.bridgeUnit }) }) });
        } catch (error) { if (isIdentityChanged(error)) throw error; throw unknown(); }
        // Pipeline Verify is bound to a previous proof and can follow live
        // writes. Do not change its epoch or replay any part of activation.
        if (['check-apply-network', 'verify-apply-network'].includes(action) && runtimeReattestFrame(result)) {
            throw runtimeReattestRequired;
        }
        if (action === 'check-apply-network') checkObservationRefusal(result);
        return result;
    };
    const checkObservationRefusal = result => {
        const reason = runtimeForeignFrame(result) ? 'RUNTIME_FOREIGN_CHANGE'
            : networkObservationFrame(result) ? networkObservationRequired : undefined;
        if (reason) throw Object.assign(fail('APPLY_NETWORK_REFUSED'), { reason });
    };
    const reattest = action === 'check-apply-network' && typeof runtime?.run === 'function' ? async () => {
        const { nodeId } = runtime;
        requireThat(nodeId?.length === 24 && tokenMatches(/^[a-f0-9]{24}$/, nodeId)
            && String(state.node ?? '') === nodeId, 'APPLY_NETWORK_NOT_OWNED');
        const uncertain = () => fail('APPLY_NETWORK_OUTCOME_UNKNOWN', true);
        const response = await runtime.run(directCommand('-k 4s 125s'), { timeout: TIMEOUT, maxOutputBytes: 256,
            stdin: JSON.stringify({ action: 'reattest-runtime', machineId, nodeId, backupId, network }) });
        if (runtimeIdentityFrame(response)) throw identityChanged();
        checkObservationRefusal(response);
        if (!runtimeAck(response, backupId)) throw uncertain();
    } : undefined;
    const result = await readWithRuntimeReattestation(read, reattest);
    if (merged && result?.code === 70 && result.stdout === '' && result.stderr === 'DIRECT_IDENTITY\n') throw identityChanged();
    if (publishing && result?.code === 70 && result.stdout === '' && result.stderr === 'DIRECT_BRIDGE_PLACEHOLDER_UNPROVED\n') {
        throw fail('APPLY_BRIDGE_PLACEHOLDER_UNPROVED');
    }
    if (result?.code === 70 && result.stdout === '' && /^DIRECT_(?:ROLLBACK_DRIFT|IDENTITY|PREREQUISITE|RUNTIME_UNPROVED|CANDIDATE_INVALID|COMMAND_FAILED)\n$(?![\s\S])/.test(result.stderr)) {
        if (finalizing) throw unknown();
        throw fail('APPLY_NETWORK_REFUSED');
    }
    if (result?.code !== 0 || result.stderr !== '' || typeof result.stdout !== 'string' || result.stdout.length > 140) throw unknown();
    let reply;
    try { reply = JSON.parse(result.stdout); } catch { throw unknown(); }
    if (reply?.ok !== true || reply.backupId !== backupId || reply.proof?.length !== 64 || !tokenMatches(PIN, reply.proof)
        || result.stdout !== `${JSON.stringify({ ok: true, backupId, proof: reply.proof })}\n`
        || (proof !== undefined && (publishing ? proof === reply.proof : proof !== reply.proof))) throw unknown();
    return reply.proof;
}

module.exports = { createRelayDirect, applyRelayNetwork, installRecoveryWasNotSent };
