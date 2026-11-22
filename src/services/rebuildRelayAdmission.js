'use strict';

const { randomBytes } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { makeLocks, withNode } = require('./rebuildLocks');
const { assertNoPendingRelayAccounts } = require('./rebuildRelayAccountsStore');
const { validateRebuildMode } = require('./rebuildMode');
const { normalizeRelayBinding } = require('./rebuildRelayAuthorization');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');

const INVALID = 'REBUILD_L2TP_ADMISSION_INVALID_REQUEST';
const CHALLENGE = 'REBUILD_L2TP_ADMISSION_CHALLENGE_INVALID';
const CONFLICT = 'REBUILD_L2TP_GRANT_CONFLICT';
const CHANGED = 'REBUILD_L2TP_IDENTITY_CHANGED';
const UNAVAILABLE = 'REBUILD_L2TP_ADMISSION_UNAVAILABLE';
const DISABLED = 'REBUILD_L2TP_INSTALL_DISABLED';
const GRANT_UNAVAILABLE = 'REBUILD_L2TP_GRANT_UNAVAILABLE';
const UNKNOWN = 'REBUILD_L2TP_GRANT_OUTCOME_UNKNOWN';
const RELEASE = 'REBUILD_LOCK_RELEASE_UNCONFIRMED';
const allowedCodes = new Set([INVALID, CHALLENGE, CONFLICT, CHANGED, UNAVAILABLE, DISABLED, UNKNOWN, RELEASE, GRANT_UNAVAILABLE,
    'REBUILD_L2TP_GRANT_INVALID', 'REBUILD_L2TP_IDENTITY_UNAVAILABLE',
    'REBUILD_BUSY', 'REBUILD_LOCK_LOST', 'REBUILD_L2TP_ACCOUNTS_BLOCKED', 'REBUILD_L2TP_ACCOUNTS_PERSISTENCE_UNAVAILABLE']);
const mappedCodes = new Map([
    ['REBUILD_L2TP_GRANT_CHANGED', CONFLICT],
    ['REBUILD_L2TP_GRANT_ENV_INVALID', GRANT_UNAVAILABLE], ['REBUILD_L2TP_GRANT_REGISTRY_INVALID', GRANT_UNAVAILABLE],
    ['REBUILD_L2TP_GRANT_PERSISTENCE_UNAVAILABLE', GRANT_UNAVAILABLE],
]);
const details = new Set(['nodeId', 'machineId', 'sshHostKeySha256', 'endpoint', 'host', 'port', 'username',
    'env-read-only', 'no-db-grant', 'grant-changed', 'node-ineligible', 'node-changed',
    'installation-not-absent', 'host-absence-unproved', 'installed-ownership-unproved', 'ownership-conflict']);
const fail = (code, detail, outcome) => Object.assign(new Error(code), { code,
    ...(detail && { detail }), ...(outcome && { outcome }),
    ...(['unknown', 'applied'].includes(outcome) && { retryAllowed: false }) });
const hex = (v, size) => typeof v === 'string' && v.length === size && /^[a-f0-9]+(?![\s\S])/.test(v);
const bounded = (v, size) => typeof v === 'string' && v.length > 0 && v.length <= size && !/[\p{C}\u2028\u2029]/u.test(v);
const bindingFor = ({ nodeId, host, port, username, machineId, sshHostKeySha256 }) => Object.freeze({
    nodeId, host, port, username, machineId, sshHostKeySha256,
});
const sameEndpoint = (a, b) => a.host === b.host && a.port === b.port && a.username === b.username;
const readOptions = { readPreference: 'primary', readConcern: { level: 'majority' }, maxTimeMS: 5000, timeoutMS: 5000 };
const nodeProjection = { ip: 1, active: 1, type: 1, cascadeRole: 1, useCustomConfig: 1, 'ssh.port': 1, 'ssh.username': 1 };

const installationFields = ['pskEncrypted', 'pskHint', 'backupId', 'managedVersion', 'configFingerprint', 'rebuildInstallToken',
    'rebuildMachineId', 'activePathKey', 'routeGroup', 'routingVersion', 'operationId', 'installedAt', 'lastVerifiedAt',
    'lastSyncAt', 'appliedTopologyRevision', 'lastErrorCode', 'lastError', 'tproxyPort', 'fwmark', 'routeTable', 'poolStart', 'poolEnd'];
const fences = ['pppDriftQueueFence', 'replacementFence'];
const stateProjection = Object.fromEntries(['node', 'status', 'desiredState', 'routingMode', 'updatedAt', 'secretRevision',
    'clientCidr', ...installationFields, ...fences].map(key => [key, 1]));
const empty = value => value == null || value === '';
const pristine = row => row?.status === 'not_installed' && row.desiredState === 'absent'
    && [undefined, null, 'route-group'].includes(row.routingMode)
    && installationFields.every(key => empty(row[key])) && (row.secretRevision == null || row.secretRevision === 0)
    // These counters survive a settled Remove. Check the actual locks and
    // pending operation records separately; never reset either counter.
    && fences.every(key => row[key] == null || (Number.isSafeInteger(row[key]) && row[key] >= 0));

async function loadFootprint(db, id, machineIds) {
    const { Types } = require('mongoose');
    const node = new Types.ObjectId(id);
    const exists = (name, filter) => db.collection(name).findOne(filter, { ...readOptions, projection: { _id: 1 } });
    const [states, accounts, operation, admission, operationLock] = await Promise.all([
        db.collection('relayl2tpstates').find({ $or: [{ node }, { rebuildMachineId: { $in: machineIds } }] },
            { ...readOptions, projection: stateProjection }).limit(3).toArray(),
        exists('l2tpusers', { relayNode: node }),
        exists('l2tpoperations', { node, status: { $nin: ['succeeded', 'rolled_back', 'cancelled'] } }),
        exists('remoteadmissions', { nodeId: id, phase: { $ne: 'completed' } }),
        exists('nodeoperationlocks', { node }),
    ]);
    return { states, accounts, operation, admission, operationLock };
}

// A passive witness for the managed baseline, not a preflight or cleanup.
// The shared DIRECT flock is taken on the existing directory; nothing is
// created and no package, unit, PPP, firewall or routing change is attempted.
// A retained Remove attempt only qualifies alongside a persisted absence row
// AND the live absence checks below. It is not a terminal host receipt alone.
const ABSENCE_CHECK = String.raw`import fcntl, json, os, re, stat, subprocess, sys

def need(ok):
    if not ok:
        raise ValueError()

def missing(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    return False

def read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0)
        data = f.read(limit + 1)
        need(len(data) <= limit)
        return data

def command(*args, codes=(0,)):
    r = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=3,
                       env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"})
    need(r.returncode in codes and not r.stderr and len(r.stdout) <= 1048576)
    return r.returncode, r.stdout

def observe():
    need(os.geteuid() == 0)
    machine = read("/etc/machine-id", 33)
    need(re.fullmatch(rb"[0-9a-f]{32}\n?", machine))
    system = "/etc/systemd/system"
    fd = os.open(system, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        net = "celerity-rebuild-l2tp-network.service"
        for path in (system + "/" + net, system + "/xl2tpd.service.d",
                     "/etc/celerity-rebuild-l2tp", "/etc/ipsec.d/celerity-rebuild-l2tp.conf",
                     "/etc/strongswan.d/celerity-rebuild-l2tp.conf"):
            need(missing(path))
        for path in ("/etc/ppp/chap-secrets", "/etc/ipsec.secrets", "/etc/ipsec.conf", "/etc/xl2tpd/xl2tpd.conf",
                     "/etc/ppp/options.xl2tpd", "/usr/local/etc/xray/config.json",
                     "/usr/local/etc/xray-bridge/config.json"):
            if not missing(path):
                value = read(path, 16 * 1024 * 1024).lower()
                need(not any(tag in value for tag in (b"celerity managed l2tp", b"celerity-rebuild-l2tp",
                                                       b"rebuild-relay-ingress", b"rebuild-l2tp-", b"relay-l2tp-")))
        vault = "/var/lib/celerity-rebuild-l2tp-direct"
        if not missing(vault):
            st = os.lstat(vault)
            need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077)
            with os.scandir(vault) as entries:
                for i, entry in enumerate(entries):
                    need(i < 64 and re.fullmatch(r"[a-f0-9]{32}", entry.name) and entry.is_dir(follow_symlinks=False))
                    receipt = json.loads(read(entry.path + "/manifest.json", 32 * 1024 * 1024))
                    need(receipt["backupId"] == entry.name and receipt["machineId"].encode() == machine.strip())
                    intent = entry.path + "/remove-attempt.json"
                    if receipt["phase"] == "rolled-back":
                        need(missing(intent))
                    else:
                        need(sys.argv[1] == "recorded-absent" and re.fullmatch(
                            r"installed(?:-chap-v2:[a-f0-9]{32})?", receipt["phase"]))
                        attempt = json.loads(read(intent, 256))
                        need(set(attempt) == {"baseline"} and re.fullmatch(r"[a-f0-9]{64}", attempt["baseline"]))
        for name in (net, "xl2tpd.service", "strongswan-starter.service", "strongswan.service", "strongswan-swanctl.service"):
            code, value = command("/usr/bin/systemctl", "--no-pager", "show", "--all",
                                  "--property=LoadState,ActiveState,SubState,MainPID,Job", name, codes=(0, 1))
            rows = value.decode("ascii").splitlines()
            info = dict(row.split("=", 1) for row in rows)
            load = info.pop("LoadState")
            need(len(rows) == len(info) + 1 and load in ("not-found", "loaded", "masked"))
            need((code == 0 or load == "not-found") and (name != net or load == "not-found"))
            need(info == {"ActiveState": "inactive", "SubState": "dead", "Job": "", "MainPID": "0"}
                 or load == "not-found" and info == {"ActiveState": "inactive", "SubState": "dead", "Job": ""})
        for path in ("/proc/net/udp", "/proc/net/udp6"):
            rows = read(path, 1048576).splitlines()
            need(rows and rows[0].split()[:2] == [b"sl", b"local_address"]
                 and rows[0].split()[2] in (b"rem_address", b"remote_address"))
            for row in rows[1:]:
                port = int(row.split()[1].rsplit(b":", 1)[1], 16)
                need(port not in (500, 4500, 1701))
        names = read("/proc/net/dev", 1048576).splitlines()
        need(len(names) > 2 and not any(row.split(b":", 1)[0].strip().startswith((b"ppp", b"l2tp"))
                                        for row in names[2:]))
        # A detached or partly removed ingress can outlive its unit files.
        tables = json.loads(command("/usr/sbin/nft", "-j", "list", "tables")[1])["nftables"]
        need(type(tables) is list)
        for row in tables:
            if set(row) == {"metainfo"}:
                need(type(row["metainfo"]) is dict)
            else:
                need(set(row) == {"table"} and type(row["table"]["name"]) is str
                     and row["table"]["name"] != "celerity_rebuild_l2tp")
        rules = json.loads(command("/usr/sbin/ip", "-j", "-4", "rule", "show")[1])
        need(type(rules) is list and rules and all(type(row["priority"]) is int and row["priority"] != 10077 for row in rules))
        routes = json.loads(command("/usr/sbin/ip", "-j", "-4", "route", "show", "table", "all")[1])
        need(type(routes) is list and all(type(row["dst"]) is str for row in routes))
        need(not any(row.get("type") == "local" and row["dst"] in ("default", "0.0.0.0/0") for row in routes))
        need(not command("/usr/sbin/ip", "xfrm", "policy", "list")[1].strip()
             and not command("/usr/sbin/ip", "xfrm", "state", "list", "nokeys")[1].strip())
        a, b = os.stat(system, follow_symlinks=False), os.fstat(fd)
        need((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and read("/etc/machine-id", 33) == machine)
    finally:
        os.close(fd)
    print("absent:" + machine.strip().decode("ascii"))

try:
    observe()
except Exception:
    sys.exit(1)
`;

async function witnessHost(node, binding, recordedAbsent, SSH) {
    const ssh = new SSH(node, { expectedHostKeySha256: binding.sshHostKeySha256,
        expectedEndpoint: { ip: binding.host, port: binding.port, username: binding.username } });
    ssh.usePool = false;
    let rec;
    try {
        await ssh.connectDirectOnce(5000);
        // Static code and a fixed selector; no card data or binding in argv.
        const record = recordedAbsent ? 'recorded-absent' : 'no-record';
        const command = `/usr/bin/timeout -k 1s 15s /usr/bin/python3 -I -B -c '${ABSENCE_CHECK}' ${record}`;
        rec = await ssh.exec(command, { timeout: 17000 });
    } finally { ssh.disconnect(); }
    if (rec?.code !== 0 || rec.stderr !== '') return false;
    if (typeof rec.stdout === 'string' && /^absent:[a-f0-9]{32}\n(?![\s\S])/.test(rec.stdout)
        && rec.stdout !== `absent:${binding.machineId}\n`) throw fail(CHANGED);
    return rec.stdout === `absent:${binding.machineId}\n`;
}

async function witnessInstalledHost(node, binding, state, SSH) {
    const ssh = new SSH(node, { expectedHostKeySha256: binding.sshHostKeySha256,
        expectedEndpoint: { ip: binding.host, port: binding.port, username: binding.username } });
    ssh.usePool = false;
    try {
        await ssh.connectDirectOnce(5000);
        // This exact DIRECT action checks the original manifest, owned files,
        // boot and runtime under the host flock. Neither prepare (which can
        // upgrade the receipt) nor any write-capable action belongs here.
        await require('./rebuildRelayDirect').applyRelayNetwork((command, options) => ssh.exec(command, options),
            binding.machineId, state, 'check-apply-network', undefined, true);
        return true;
    } catch (error) {
        if (error?.code === CHANGED || error?.code === 'SSH_HOST_KEY_MISMATCH') throw fail(CHANGED);
        return false;
    } finally { ssh.disconnect(); }
}

function createRebuildRelayAdmission({ db = require('mongoose').connection, env = process.env,
    store, probe, loadNode, readFootprint, assertNoPending, witnessAbsent, witnessInstalled, locks, SSH, normalizeBinding = normalizeRelayBinding,
    clock = () => performance.now(), ttlMs = 120_000, maxChallenges = 1024 } = {}) {
    store ??= require('./rebuildRelayGrantStore').createRelayGrantStore({ db, env });
    probe ??= require('./rebuildRelayIdentityProbe').createRelayIdentityProbe();
    locks ??= makeLocks(db.collection('c3_rebuild_locks'));
    loadNode ??= (nodeId, authenticated) => {
        const { Types } = require('mongoose');
        const projection = authenticated ? { ...nodeProjection, 'ssh.password': 1, 'ssh.privateKey': 1 } : nodeProjection;
        return db.collection('hynodes').findOne({ _id: new Types.ObjectId(nodeId) }, { ...readOptions, projection });
    };
    readFootprint ??= (id, machines) => loadFootprint(db, id, machines);
    assertNoPending ??= () => assertNoPendingRelayAccounts(db);
    witnessAbsent ??= (node, binding, recordedAbsent) => witnessHost(node, binding, recordedAbsent, SSH ?? require('./nodeSSH'));
    witnessInstalled ??= (node, binding, state) => witnessInstalledHost(node, binding, state, SSH ?? require('./nodeSSH'));
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || !Number.isSafeInteger(maxChallenges) || maxChallenges < 1) {
        throw new TypeError('Invalid relay admission challenge limits');
    }
    const challenges = new Map();
    const fresh = ticket => {
        if (!(clock() < ticket.expires)) throw fail(CHALLENGE);
    };
    const consume = (action, scope, challenge) => {
        const ticket = challenges.get(challenge);
        if (!ticket || ticket.action !== action || !equal(ticket.scope, scope)) throw fail(CHALLENGE);
        challenges.delete(challenge); // Synchronous, before any I/O or lock wait.
        fresh(ticket);
        return ticket;
    };
    const issue = (action, scope, proof) => {
        const now = clock();
        for (const [key, ticket] of challenges) if (!(now < ticket.expires)) challenges.delete(key);
        if (challenges.size >= maxChallenges) throw fail(UNAVAILABLE);
        const challenge = randomBytes(32).toString('hex');
        if (challenges.has(challenge)) throw fail(UNAVAILABLE);
        challenges.set(challenge, { action, scope, proof, expires: now + ttlMs });
        return challenge;
    };
    const enabled = () => {
        let rebuild;
        try { rebuild = validateRebuildMode(env); } catch { throw fail(DISABLED); }
        if (!rebuild || env.C3_REBUILD_L2TP_INSTALL_ENABLED !== 'true') throw fail(DISABLED);
    };
    const card = async (nodeId, authenticated, expected) => {
        const node = await loadNode(nodeId, authenticated);
        const ineligible = () => expected ? fail(CHANGED, 'node-changed') : fail(CONFLICT, 'node-ineligible');
        if (!node || String(node._id) !== nodeId || node.active !== true || node.type !== 'xray' || node.cascadeRole !== 'relay'
            || node.useCustomConfig) throw ineligible();
        // The shared normalizer validates endpoint and identity together. These
        // placeholders are used only to normalize the endpoint, never as pins.
        const { host, port, username } = normalizeBinding({ nodeId, host: node.ip, port: node.ssh?.port,
            username: node.ssh?.username, machineId: '0'.repeat(32), sshHostKeySha256: '0'.repeat(64) }, ineligible);
        const endpoint = { nodeId, host, port, username };
        if (expected && !sameEndpoint(expected, endpoint)) throw fail(CHANGED, 'node-changed');
        return { endpoint, transport: { _id: nodeId, name: nodeId, ip: host, ssh: { port, username,
            ...(authenticated && { password: node.ssh.password, privateKey: node.ssh.privateKey }) } } };
    };
    const prior = async nodeId => {
        enabled();
        const snapshot = await store.snapshot();
        const source = snapshot.sourceFor(nodeId);
        if (source === 'env') throw fail(CONFLICT, 'env-read-only');
        const rows = snapshot.grants.filter(row => row.nodeId === nodeId);
        if (source === null && rows.length === 0) return { binding: null, generation: null };
        if (source !== 'db' || rows.length !== 1 || !bounded(rows[0].generation, 128)) throw fail(UNAVAILABLE);
        return { binding: bindingFor(rows[0]), generation: rows[0].generation };
    };
    const recheckPrior = async (id, expected) => {
        if (!equal(await prior(id), expected)) throw fail(CONFLICT, 'grant-changed');
    };
    const pinnedMachine = async (node, pin) => {
        const machine = await probe.readMachine(node, pin);
        if (!hex(machine, 32)) throw fail(UNAVAILABLE);
        return machine;
    };
    const footprint = async (id, binding, old) => {
        const view = await readFootprint(id, [...new Set([binding.machineId, old?.machineId].filter(Boolean))]);
        if (!Array.isArray(view?.states)) throw fail(UNAVAILABLE);
        if (view.operation !== null || view.admission !== null || view.operationLock !== null) {
            throw fail(CONFLICT, 'installation-not-absent');
        }
        if (view.states.length > 1 || view.states.some(row => !row || String(row.node) !== id)) {
            throw fail(CONFLICT, 'ownership-conflict');
        }
        return view;
    };
    const isAbsent = ({ states, accounts }) => accounts === null && (states.length === 0 || pristine(states[0]));
    const checkReconfirmOwnership = async (id, transport, binding, old) => {
        const view = await footprint(id, binding, old);
        if (isAbsent(view)) return;
        const [state] = view.states;
        // Only the SSH key may change on an installed owner's existing DB
        // grant. Observing the same machine ID alone is not ownership proof.
        if (!old || !sameEndpoint(binding, old) || binding.machineId !== old.machineId
            || state?.status !== 'installed' || state.desiredState !== 'installed'
            || state.rebuildMachineId !== binding.machineId) throw fail(CONFLICT, 'ownership-conflict');
        if (binding.sshHostKeySha256 === old.sshHostKeySha256) return;
        if (state.routingMode !== FOLLOW_RELAY_MODE || state.routingVersion !== FOLLOW_RELAY_VERSION || state.secretRevision !== 1
            || state.operationId != null || state.routeGroup != null || !empty(state.activePathKey)
            || state.appliedTopologyRevision != null || fences.some(key => (state[key] ?? 0) !== 0) || !hex(state.backupId, 32)
            || typeof state.rebuildInstallToken !== 'string'
            || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}(?![\s\S])/.test(state.rebuildInstallToken)
            || await witnessInstalled(transport, binding, state) !== true) throw fail(CONFLICT, 'installed-ownership-unproved');
        if (!equal(await footprint(id, binding, old), view)) throw fail(CONFLICT, 'ownership-conflict');
    };
    async function perform(input) {
        const { action, nodeId, actor, sessionId, challenge } = input ?? {};
        const next = action === 'probe' ? 'verify' : action === 'verify' ? 'confirm' : null;
        const needsTicket = action === 'verify' || action === 'confirm';
        if ((!next && action !== 'confirm' && action !== 'revoke') || !hex(nodeId, 24) || !bounded(actor, 256) || actor.trim() !== actor
            || !bounded(sessionId, 256) || (!needsTicket && challenge !== undefined)) throw fail(INVALID);
        const scope = { nodeId, actor, sessionId };
        const audit = (outcome, code) => store.audit({ action, nodeId, actor, outcome, ...(code && { code }) });
        let acknowledged = false, issued;
        try {
            const ticket = needsTicket ? consume(action, scope, hex(challenge, 64) ? challenge : undefined) : null;
            enabled();
            if (next) {
                const previous = ticket ? ticket.proof.previous : await prior(nodeId);
                if (ticket) await recheckPrior(nodeId, previous);
                const { endpoint, transport } = await card(nodeId, !!ticket, ticket?.proof.endpoint);
                if (ticket) fresh(ticket);
                const pin = ticket ? ticket.proof.pin : await probe.probeKey(transport);
                if (!hex(pin, 64)) throw fail(UNAVAILABLE);
                const machineId = ticket ? await pinnedMachine(transport, pin) : undefined;
                await card(nodeId, false, endpoint);
                await recheckPrior(nodeId, previous);
                if (ticket) fresh(ticket);
                issued = issue(next, scope, { endpoint, previous, pin, machineId });
                await audit('success', 'OK');
                if (ticket) fresh(ticket);
                const ready = challenges.get(issued);
                if (!ready) throw fail(CHALLENGE);
                fresh(ready);
                return { ...endpoint, sshHostKeySha256: pin, ...(ticket && { machineId }), challenge: issued };
            }
            // Capture revoke generation before lock acquisition too: a queued
            // revoke must not silently target a successor grant.
            const previous = ticket ? ticket.proof.previous : await prior(nodeId);
            if (!ticket && !previous.binding) throw fail(CONFLICT, 'no-db-grant');
            return await locks.run(verify => withNode(nodeId, async () => {
                const verifyLock = async () => {
                    if (await verify() === false) throw fail('REBUILD_LOCK_LOST');
                };
                await verifyLock();
                await assertNoPending();
                await recheckPrior(nodeId, previous);
                const { endpoint, transport } = await card(nodeId, true, ticket?.proof.endpoint ?? previous.binding);
                let binding, mutation;
                if (ticket) {
                    fresh(ticket);
                    const { machineId, pin } = ticket.proof;
                    if (await pinnedMachine(transport, pin) !== machineId) throw fail(CHANGED);
                    binding = bindingFor({ ...endpoint, machineId, sshHostKeySha256: pin });
                    await checkReconfirmOwnership(nodeId, transport, binding, previous.binding);
                    mutation = previous.binding ? 'reconfirm' : 'grant';
                } else {
                    binding = previous.binding;
                    const before = await footprint(nodeId, binding);
                    if (!isAbsent(before)) throw fail(CONFLICT, 'installation-not-absent');
                    if (await witnessAbsent(transport, binding, before.states.length === 1) !== true) {
                        throw fail(CONFLICT, 'host-absence-unproved');
                    }
                    if (!equal(await footprint(nodeId, binding), before)) throw fail(CONFLICT, 'installation-not-absent');
                    mutation = 'revoke';
                }
                await card(nodeId, false, endpoint);
                await assertNoPending();
                await recheckPrior(nodeId, previous);
                await verifyLock();
                enabled();
                if (ticket) fresh(ticket);
                try {
                    // Store owns the final generation CAS, unique checks and
                    // transactional mutation+success audit. Do not replay it.
                    await store.mutate({ action: mutation, binding, expectedGeneration: previous.generation, actor });
                } catch (error) {
                    if (error?.code === 11000) throw fail(CONFLICT);
                    throw error;
                }
                acknowledged = true;
                return mutation === 'revoke' ? { nodeId, source: null } : { ...binding, source: 'db' };
            }));
        } catch (error) {
            if (issued) challenges.delete(issued);
            if (acknowledged) throw fail(RELEASE, undefined, 'applied');
            const cause = error?.code;
            const code = mappedCodes.get(cause) ?? (allowedCodes.has(cause) ? cause : UNAVAILABLE);
            const value = cause === 'REBUILD_L2TP_GRANT_CHANGED' ? 'grant-changed' : error?.detail ?? error?.field;
            const detail = (code === CONFLICT || code === CHANGED) && details.has(value) ? value : undefined;
            const outcome = code === UNKNOWN ? 'unknown' : 'refused';
            const auditCode = code === GRANT_UNAVAILABLE ? (mappedCodes.has(cause) ? cause : 'REBUILD_L2TP_GRANT_PERSISTENCE_UNAVAILABLE') : code;
            try { await audit(outcome === 'refused' ? 'denied' : 'unknown', auditCode); }
            catch { /* Do not replace a refusal or an unknown write outcome. */ }
            throw fail(code, detail, outcome);
        }
    }
    return { perform };
}

module.exports = { createRebuildRelayAdmission };
