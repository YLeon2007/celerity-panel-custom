'use strict';

const fs = require('node:fs');
const { join } = require('node:path');
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { canInstallRelay } = require('./rebuildRelayAuthorization');
const { applyFollowRelay, attachLocalFollowRelay, REBUILD_RELAY_INGRESS_TAG, FOLLOW_RELAY_OUTBOUND_TAG } = require('../modules/relay-l2tp/services/l2tpFollowRelay');
const { FOLLOW_RELAY_MODE, FOLLOW_RELAY_VERSION } = require('../modules/relay-l2tp/domain/l2tpRoutingSelection');
const MAIN_ARTIFACT = Object.freeze({ type: 'xrayCandidate', path: 'xray-candidate.json' });

const BLOCKER = 'REBUILD_L2TP_STOCK_INSTALL_OUT_OF_SCOPE';
const PROFILE_ERROR = 'REBUILD_L2TP_XRAY_BASELINE_UNSUPPORTED';
const ARTIFACT_ERROR = 'REBUILD_L2TP_STOCK_ARTIFACT_MISMATCH';
const STOCK_DIR = join(__dirname, '../modules/relay-l2tp/node-artifacts/l2tp');
// Pin the reviewed installer independently of its own PAYLOAD_SHA256 table.
const INSTALLER_SHA256 = 'b1a68cb91eeeea7928a56e3d050481b3faee533a4a3a32924cd6f0b5cb463845';
const POLICY_PREFIX = 'rebuild-policy-';
const MAX_PROFILE_BYTES = 16 * 1024 * 1024; // stock receiver ceiling
const fail = code => Object.assign(new Error(code), { code });
const requireThat = (condition, code) => { if (!condition) throw fail(code); };
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const record = value => value != null && Object.getPrototypeOf(value) === Object.prototype;
const strings = xs => Array.isArray(xs) && xs.length > 0 && xs.every(x => typeof x === 'string' && x.length > 0);
const tproxyPortAllowed = value => Number.isSafeInteger(value) && value > 0 && value <= 65535
    && ![500, 1701, 4500].includes(value); // IPsec IKE/NAT-T and L2TP listeners

function readStockBundle() {
    try {
        const read = name => {
            const path = join(STOCK_DIR, name);
            if (!fs.lstatSync(path).isFile()) throw fail(ARTIFACT_ERROR);
            return fs.readFileSync(path);
        };
        const installer = read('install.sh');
        requireThat(sha256(installer) === INSTALLER_SHA256, ARTIFACT_ERROR);
        const payloads = [...installer.toString('utf8').matchAll(/^ +\[([a-z0-9-]+\.(?:sh|py))\]='([a-f0-9]{64})'$/gm)]
            .map(([, name, digest]) => {
                requireThat(sha256(read(name)) === digest, ARTIFACT_ERROR);
                return Object.freeze({ name, sha256: digest });
            });
        requireThat(isDeepStrictEqual(
            fs.readdirSync(STOCK_DIR).filter(name => /\.(sh|py)$/.test(name)).sort(),
            ['install.sh', ...payloads.map(item => item.name)].sort(),
        ), ARTIFACT_ERROR);
        return Object.freeze({ installerSha256: INSTALLER_SHA256, payloads: Object.freeze(payloads) });
    } catch {
        throw fail(ARTIFACT_ERROR);
    }
}

function pinnedProfile(bytes, pin, optional = false) {
    if (optional && bytes === null && pin === null) return null;
    requireThat(typeof bytes === 'string' && Buffer.byteLength(bytes) <= MAX_PROFILE_BYTES
        && typeof pin === 'string' && /^[0-9a-f]{64}$/.test(pin) && sha256(bytes) === pin,
    'REBUILD_L2TP_PROFILE_PRECONDITION');
    try {
        const profile = JSON.parse(bytes);
        const canonical = JSON.stringify(profile);
        // Rebuild writes compact JSON. Duplicate keys and other parser-dependent
        // encodings are not a baseline from which we can preserve Xray semantics.
        requireThat(bytes === canonical || bytes === `${canonical}\n`, PROFILE_ERROR);
        requireThat(record(profile) && record(profile.routing) && (optional || !Object.hasOwn(profile, 'reverse'))
            && !Object.hasOwn(profile.routing, 'balancers')
            && [profile.inbounds, profile.outbounds, profile.routing.rules]
                .every(rows => Array.isArray(rows) && rows.every(record)), PROFILE_ERROR);
        return profile;
    } catch {
        // JSON parser errors may contain excerpts of configuration bytes.
        throw fail(PROFILE_ERROR);
    }
}

function sharedRules(main, bridge) {
    const reserved = tag => typeof tag === 'string' && (tag.startsWith('relay-l2tp-')
        || [REBUILD_RELAY_INGRESS_TAG, FOLLOW_RELAY_OUTBOUND_TAG, 'rebuild-l2tp-block'].includes(tag));
    for (const cfg of [main, bridge]) {
        requireThat(![...cfg.inbounds, ...cfg.outbounds].some(row => reserved(row.tag))
            && cfg.routing.rules.every(rule => strings(rule.inboundTag) && !rule.inboundTag.some(reserved)
                && !reserved(rule.outboundTag)), PROFILE_ERROR);
    }
    const rules = main.routing.rules;
    const first = rules.findIndex(rule => typeof rule.ruleTag === 'string' && rule.ruleTag.startsWith(POLICY_PREFIX));
    const fallback = rules.at(-1);
    const inboundTags = main.inbounds.map(row => row.tag);
    requireThat(first >= 0 && fallback.ruleTag === `${POLICY_PREFIX}default`
        && strings(inboundTags) && new Set(inboundTags).size === inboundTags.length
        && new Set(fallback.inboundTag).size === fallback.inboundTag.length
        && main.outbounds[0]?.protocol === 'blackhole', PROFILE_ERROR);
    const nativeIngress = main.outbounds.filter(row => row.protocol === 'vless')
        .map(outbound => outbound.settings?.reverse?.tag).filter(tag => typeof tag === 'string');
    const forwardIngress = new Set(inboundTags.filter(tag => tag.startsWith('fwd-hop-')));
    const transit = tag => forwardIngress.has(tag) || nativeIngress.includes(tag);
    const subscribers = new Set(main.inbounds.filter(row => row.tag !== 'API_INBOUND'
        && !transit(row.tag) && !row.tag?.startsWith('rebuild-rp-conn-')).map(row => row.tag));
    requireThat(fallback.inboundTag.every(tag => transit(tag) || subscribers.has(tag)), PROFILE_ERROR);

    const target = tag => {
        if (typeof tag !== 'string' || !tag) return undefined;
        const matching = main.outbounds.filter(row => row.tag === tag);
        const native = main.inbounds.flatMap(row => Array.isArray(row.settings?.clients) && row.protocol === 'vless'
            ? row.settings.clients : []).filter(client => client?.reverse?.tag === tag);
        return matching.length + native.length !== 1 ? undefined : native.length ? 'native' : matching[0].protocol;
    };
    const shared = rules.slice(first);
    for (const rule of shared) {
        const geo = /^rebuild-policy-geo-\d+-(ip|domain)$/.exec(rule.ruleTag)?.[1];
        const keys = ['type', 'ruleTag', 'inboundTag', 'outboundTag', ...(geo ? [geo] : [])];
        requireThat(rule.type === 'field' && (rule === fallback || (geo && strings(rule[geo])))
            && Object.keys(rule).every(key => keys.includes(key))
            && isDeepStrictEqual(rule.inboundTag, fallback.inboundTag)
            && ['blackhole', 'native', 'vless', 'vmess'].includes(target(rule.outboundTag)), PROFILE_ERROR);
    }
    // The rebuild generator emits subscriber-only deny rules before its shared
    // suffix. Preserve deny-all as well as domain/IP denies; never attach PPP to API.
    const denies = rules.slice(0, first).filter(rule => rule.inboundTag.some(tag => subscribers.has(tag)));
    requireThat(denies.every(rule => rule.type === 'field' && target(rule.outboundTag) === 'blackhole'
        && rule.inboundTag.every(tag => subscribers.has(tag))
        && Object.keys(rule).every(key => ['type', 'inboundTag', 'outboundTag', 'ruleTag', 'ip', 'domain'].includes(key))
        && ['ip', 'domain'].every(key => !Object.hasOwn(rule, key) || strings(rule[key]))), PROFILE_ERROR);
    return [...denies, ...shared];
}

function composeMain(main, bridge, { nodeId, tproxyPort, controlPlaneAddresses, carryDomain }) {
    try {
        const candidate = structuredClone(main);
        const policy = sharedRules(candidate, bridge);
        const policySet = new Set(policy);
        const originalRules = [...candidate.routing.rules];
        // This shape is only a fact supplied to the pure composer. No installed
        // database state, credential revision, or on-host fact is created here.
        const state = { node: nodeId, desiredState: 'installed', status: 'installed', secretRevision: 1,
            routingMode: FOLLOW_RELAY_MODE, routingVersion: FOLLOW_RELAY_VERSION, tproxyPort };
        attachLocalFollowRelay({ nodeId, state, main: candidate, bridge, policy, controlPlaneAddresses, carryDomain });
        const expectedRules = main.routing.rules.map((rule, index) => policySet.has(originalRules[index])
            ? { ...rule, inboundTag: [...rule.inboundTag, REBUILD_RELAY_INGRESS_TAG] } : rule);
        const oldRules = new Set(originalRules);
        requireThat(isDeepStrictEqual(candidate.routing.rules.filter(rule => oldRules.has(rule)), expectedRules)
            && candidate.routing.rules.filter(rule => !oldRules.has(rule)).every(rule => rule.inboundTag.length === 1
                && [REBUILD_RELAY_INGRESS_TAG, `relay-l2tp-${nodeId}`].includes(rule.inboundTag[0]))
            && isDeepStrictEqual(candidate.inbounds.slice(0, main.inbounds.length), main.inbounds)
            && isDeepStrictEqual(candidate.outbounds.slice(0, main.outbounds.length), main.outbounds), PROFILE_ERROR);
        const content = `${JSON.stringify(candidate)}\n`;
        requireThat(Buffer.byteLength(content) <= MAX_PROFILE_BYTES, PROFILE_ERROR);
        return content;
    } catch {
        throw fail(PROFILE_ERROR);
    }
}

function composeRebuildRelayMain(snapshot, options) {
    const result = composeRebuildRelayPair(snapshot, options);
    requireThat(result.bridge === undefined, PROFILE_ERROR);
    return result.main;
}

function composeRebuildRelayPair(snapshot, options) {
    requireThat(tproxyPortAllowed(options.tproxyPort) && typeof options.carryDomain === 'boolean',
        'REBUILD_L2TP_INSTALL_INPUT_INVALID');
    const main = pinnedProfile(snapshot.main, options.mainSha256);
    const bridge = pinnedProfile(snapshot.bridge, options.bridgeSha256, true)
        ?? { inbounds: [], outbounds: [], routing: { rules: [] } };
    const policy = cfg => cfg.routing.rules.some(rule => rule.ruleTag?.startsWith?.(POLICY_PREFIX));
    const encode = cfg => {
        const bytes = `${JSON.stringify(cfg)}\n`;
        requireThat(Buffer.byteLength(bytes) <= MAX_PROFILE_BYTES, PROFILE_ERROR);
        return bytes;
    };
    if (policy(main)) {
        requireThat(!policy(bridge) && !Object.hasOwn(bridge, 'reverse'), PROFILE_ERROR);
        return { main: composeMain(main, bridge, options) };
    }
    try {
        // The split layout already owns the SOCKS listener. Only join that
        // listener; never guess the target from an arbitrary SOCKS outbound.
        const { nodeId, tproxyPort, controlPlaneAddresses } = options;
        const owned = tag => typeof tag === 'string' && (tag.startsWith('relay-l2tp-')
            || [FOLLOW_RELAY_OUTBOUND_TAG, 'rebuild-l2tp-block'].includes(tag));
        for (const cfg of [main, bridge]) {
            requireThat(![...cfg.inbounds, ...cfg.outbounds].some(row => owned(row.tag))
                && !cfg.routing.rules.some(row => owned(row.outboundTag) || row.inboundTag?.some(owned)), PROFILE_ERROR);
        }
        requireThat(!main.inbounds.some(row => row.tag === REBUILD_RELAY_INGRESS_TAG)
            && main.outbounds[0]?.protocol === 'blackhole' && bridge.outbounds[0]?.protocol === 'blackhole', PROFILE_ERROR);
        const state = { node: nodeId, desiredState: 'installed', status: 'installed', secretRevision: 1,
            routingMode: FOLLOW_RELAY_MODE, routingVersion: FOLLOW_RELAY_VERSION, tproxyPort };
        const result = applyFollowRelay({ nodeId, state, main, bridge, routeState: 'egress_configured', controlPlaneAddresses });
        return { main: encode(result.main), bridge: encode(result.bridge) };
    } catch {
        throw fail(PROFILE_ERROR);
    }
}

/** Snapshot and independent byte pins must come from a trusted TEST caller, never an HTTP body. */
function createRebuildRelayInstallSteps({ env = process.env } = {}) {
    function requireFresh(inventory) {
        const nodeId = inventory?.nodeId;
        requireThat(typeof nodeId === 'string' && canInstallRelay(env, nodeId), 'REBUILD_L2TP_INSTALL_DISABLED');
        requireThat(inventory.eligible === true && inventory.pristine === true, 'REBUILD_L2TP_NOT_FRESH_RELAY');
        return nodeId;
    }

    function materialize({ inventory, snapshot, profilePins, tproxyPort, controlPlaneAddresses, carryDomain } = {}) {
        const nodeId = requireFresh(inventory);
        requireThat(snapshot?.nodeId === nodeId && snapshot.machineId === env.C3_REBUILD_L2TP_RELAY_MACHINE_ID,
            'REBUILD_L2TP_INSTALL_IDENTITY_MISMATCH');
        requireThat(snapshot.pristine === true, 'REBUILD_L2TP_NOT_FRESH_RELAY');
        requireThat(snapshot.ppp === true && snapshot.masked === false, 'REBUILD_L2TP_HOST_NOT_READY');
        requireThat(tproxyPortAllowed(tproxyPort) && typeof carryDomain === 'boolean', 'REBUILD_L2TP_INSTALL_INPUT_INVALID');
        const { mainSha256, bridgeSha256 } = profilePins ?? {};
        const content = composeRebuildRelayMain(snapshot, { nodeId, tproxyPort, controlPlaneAddresses, carryDomain,
            mainSha256, bridgeSha256 });
        const stockArtifacts = readStockBundle();
        return Object.freeze({
            kind: 'rebuild-l2tp-first-install', status: 'blocked', blocker: BLOCKER, nodeId,
            preconditions: Object.freeze({ mainSha256, bridgeSha256 }), stockArtifacts,
            mainCandidateSha256: sha256(content),
            // Explicit private accessor. No config bytes in enumerable plan data or error details.
            getMainArtifact: () => Object.freeze({ stepType: 'compose_xray_fragment',
                ...MAIN_ARTIFACT, owner: 'root', group: 'root', mode: 0o600, content }),
        });
    }

    // Only a trusted server-generated desired may enter DIRECT. A legacy
    // inventory/transport without that contract cannot opt into dispatch.
    async function prepare(inventory, remote) {
        const nodeId = requireFresh(inventory);
        requireThat(inventory.desired && typeof remote.prepare === 'function', BLOCKER);
        return remote.prepare({ nodeId, desired: inventory.desired,
            controlPlaneAddresses: inventory.controlPlaneAddresses, carryDomain: inventory.carryDomain });
    }
    async function install(plan, remote, verifyLock) {
        requireThat(typeof remote.install === 'function', BLOCKER);
        return remote.install(plan, verifyLock);
    }
    async function verify(plan, remote) { return typeof remote.verify === 'function' && await remote.verify(plan) === true; }
    async function rollback(plan, remote, verifyLock) {
        return typeof remote.rollback === 'function' && await remote.rollback(plan, verifyLock) === true;
    }

    return Object.freeze({ materialize, prepare, install, verify, rollback });
}

module.exports = { createRebuildRelayInstallSteps, composeRebuildRelayPair };
