'use strict';

const { isIP } = require('node:net');
const { isDeepStrictEqual } = require('node:util');
const { FOLLOW_RELAY_MODE, selectL2tpRoutingMode } = require('../domain/l2tpRoutingSelection');
const { cascadePathIngressPort, cascadePathIngressTag } = require('../domain/cascadePathIngress');

const REBUILD_RELAY_INGRESS_TAG = 'rebuild-relay-ingress';
const FOLLOW_RELAY_OUTBOUND_TAG = 'rebuild-l2tp-handoff';
const BLOCK_TAG = 'rebuild-l2tp-block';
const PPP_PREFIX = 'relay-l2tp-';
const LOOPBACK = '127.0.0.1';
const SAFE_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const TUNNELS = new Set(['vless', 'vmess', 'trojan', 'shadowsocks']);
const ROUTE_STATES = new Set(['egress_configured', 'no_bridge_exit', 'detached']);
const BASE_RULE_KEYS = ['type', 'inboundTag', 'outboundTag'];

function fail(kind, message) {
    throw Object.assign(new Error(message), { code: `L2TP_FOLLOW_RELAY_${kind}` });
}

const plain = row => row != null && Object.getPrototypeOf(row) === Object.prototype;
const validPort = port => Number.isSafeInteger(port) && port > 0 && port <= 65535;
const validTag = tag => typeof tag === 'string' && SAFE_TAG.test(tag);
const strings = values => Array.isArray(values) && values.every(value => typeof value === 'string' && value.length > 0);
const matches = (rows, tag) => rows.filter(row => row.tag === tag);
const scoped = (tag, outboundTag, match) => ({ type: 'field', inboundTag: [tag], outboundTag, ...match });
const fieldRule = (row, ...keys) => row.type === 'field' && validTag(row.outboundTag)
    && Object.keys(row).every(key => BASE_RULE_KEYS.includes(key) || keys.includes(key));

function identity(value) {
    // A BSON ObjectId's .id is a byte buffer and its ._id can point to itself.
    return typeof value?.toHexString === 'function' ? value.toHexString() : value;
}

function validateInstalled(nodeId, state) {
    const relayId = identity(nodeId);
    const groupId = identity(state.routeGroup);
    if (!validTag(relayId) || identity(state.node) !== relayId || state.desiredState !== 'installed'
        || state.status !== 'installed' || !validPort(state.tproxyPort)
        || !Number.isSafeInteger(state.secretRevision) || state.secretRevision < 1
        || groupId != null && !validTag(groupId)) {
        fail('NOT_INSTALLED', 'Follow-relay requires the matching installed PPP state');
    }
    return { inboundTag: `${PPP_PREFIX}${groupId ?? relayId}`, groupId };
}

function candidate(value) {
    if (!plain(value) || !Array.isArray(value.inbounds) || !Array.isArray(value.outbounds)
        || !plain(value.routing) || !Array.isArray(value.routing.rules)
        || [value.inbounds, value.outbounds, value.routing.rules,
            value.reverse?.portals ?? [], value.reverse?.bridges ?? []]
            .some(rows => !Array.isArray(rows) || !rows.every(plain))
        || value.inbounds.some(row => row.tag !== undefined && typeof row.tag !== 'string')
        || value.routing.rules.some(row => row.inboundTag !== undefined && !strings(row.inboundTag))) {
        fail('CANDIDATE', 'Follow-relay expects parsed Xray candidates');
    }
    return structuredClone(value);
}

function domainName(address) {
    if (typeof address !== 'string') return null;
    const domain = address.toLowerCase().replace(/\.$/, '');
    return domain.length <= 253 && domain.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
        && !/^[0-9.]+$/.test(domain) ? domain : null;
}

function protections(controlPlaneAddresses, configs) {
    if (!strings(controlPlaneAddresses) || controlPlaneAddresses.length === 0) {
        fail('CONTROL_PLANE', 'Follow-relay requires explicit control-plane addresses');
    }
    const ip = new Set(['geoip:private']);
    const domain = new Set();
    for (const address of controlPlaneAddresses) {
        const cidr = address.match(/^([^/]+)\/(0|[1-9]\d{0,2})$/);
        const family = cidr && isIP(cidr[1]);
        if (isIP(address) || family && Number(cidr[2]) <= (family === 4 ? 32 : 128)) ip.add(address);
        else if (domainName(address)) domain.add(`full:${domainName(address)}`);
        else fail('CONTROL_PLANE', 'Invalid follow-relay control-plane address');
    }
    for (const config of configs) {
        for (const reverse of [...(config?.reverse?.bridges ?? []), ...(config?.reverse?.portals ?? [])]) {
            const name = domainName(reverse.domain);
            if (!name) fail('CANDIDATE', 'Invalid reverse control domain');
            domain.add(`full:${name}`);
        }
    }
    return tag => [
        ...(domain.size ? [scoped(tag, BLOCK_TAG, { domain: [...domain].sort() })] : []),
        scoped(tag, BLOCK_TAG, { ip: [...ip].sort() }),
    ];
}

function withoutIngress(rules, tag) {
    return rules.flatMap(rule => {
        if (!rule.inboundTag?.includes(tag)) return [rule];
        const inboundTag = rule.inboundTag.filter(value => value !== tag);
        return inboundTag.length ? [{ ...rule, inboundTag }] : [];
    });
}

function targetOf(config, tag) {
    if (!validTag(tag)) return null;
    const outbounds = matches(config.outbounds, tag);
    const portals = matches(config.reverse?.portals ?? [], tag);
    return outbounds.length + portals.length === 1 ? { outbound: outbounds[0], portal: portals[0] } : null;
}

const isBlock = (config, tag) => targetOf(config, tag)?.outbound?.protocol === 'blackhole';
const isTunnel = (config, tag) => {
    const target = targetOf(config, tag);
    return Boolean(target?.portal) || TUNNELS.has(target?.outbound?.protocol);
};

function isReverseControl(config, rule) {
    return fieldRule(rule, 'domain') && strings(rule.domain) && rule.domain.length === 1
        && config.reverse?.bridges?.some(bridge => rule.domain[0] === `full:${bridge.domain}`)
        && TUNNELS.has(targetOf(config, rule.outboundTag)?.outbound?.protocol);
}

function isConditionalGlobalBlock(config, rule) {
    return isBlock(config, rule.outboundTag) && ['ip', 'domain'].some(key => fieldRule(rule, key)
        && strings(rule[key]) && rule[key].length > 0 && !rule[key].includes('0.0.0.0/0'));
}

function validateSharedPolicy(bridge, ingressTag) {
    const rules = bridge.routing.rules;
    const policy = rules.filter(rule => rule.inboundTag?.includes(ingressTag));
    const fallback = policy.at(-1);
    const native = tag => !targetOf(bridge, tag) && bridge.inbounds.filter(row => row.protocol === 'vless')
        .flatMap(row => row.settings?.clients ?? []).filter(client => client.reverse?.tag === tag).length === 1
        && !matches(bridge.outbounds, tag).length && !matches(bridge.reverse?.portals ?? [], tag).length;
    const tunnel = tag => isTunnel(bridge, tag) || native(tag);
    const tagged = (rule, key) => !Object.hasOwn(rule, 'ruleTag') || (typeof rule.ruleTag === 'string'
        && (key ? /^rebuild-policy-geo-\d+-(ip|domain)$/.exec(rule.ruleTag)?.[1] === key
            : rule.ruleTag === 'rebuild-policy-default'));
    if (!fallback || !fieldRule(fallback, 'ruleTag') || !tagged(fallback)
        || !(tunnel(fallback.outboundTag) || (fallback.ruleTag === 'rebuild-policy-default' && isBlock(bridge, fallback.outboundTag)))
        || policy.slice(0, -1).some(rule => {
            const keys = ['ip', 'domain'].filter(key => Object.hasOwn(rule, key));
            if (rule.ruleTag === 'acl-catch-all' && fieldRule(rule, 'ruleTag') && isBlock(bridge, rule.outboundTag)) return false;
            return keys.length !== 1 || !fieldRule(rule, 'ruleTag', ...keys) || !tagged(rule, keys[0]) || !strings(rule[keys[0]])
                || rule[keys[0]].length === 0 || !(tunnel(rule.outboundTag) || isBlock(bridge, rule.outboundTag));
        }) || rules.slice(0, rules.indexOf(fallback)).some(rule => !rule.inboundTag?.length
            && !isConditionalGlobalBlock(bridge, rule) && !isReverseControl(bridge, rule))) {
        fail('POLICY', 'Missing, unsafe or shadowed shared relay policy');
    }
}

const socksOutbound = (tag, port) => ({ tag, protocol: 'socks', settings: { servers: [{ address: LOOPBACK, port }] } });

function bindsPort(inbound, port) {
    // Xray also supports string ports and ranges. Both profiles share one host.
    return String(inbound.port ?? '').split(',').some(part => {
        const match = part.trim().match(/^(\d+)(?:-(\d+))?$/);
        return match && Number(match[1]) <= port && Number(match[2] ?? match[1]) >= port;
    });
}

function ensureTproxy(main, bridge, tag, port) {
    const existing = matches(main.inbounds, tag);
    const expected = { tag, listen: '0.0.0.0', port, protocol: 'dokodemo-door',
        settings: { network: 'tcp,udp', followRedirect: true }, streamSettings: { sockopt: { tproxy: 'tproxy' } } };
    if (existing.length > 1 || [...main.inbounds, ...(bridge?.inbounds ?? [])].some(row => row !== existing[0]
        && (row.tag?.startsWith(PPP_PREFIX) || bindsPort(row, port)))
        || existing[0] && (existing[0].protocol !== expected.protocol || existing[0].listen !== expected.listen
            || existing[0].port !== port || existing[0].settings?.network !== 'tcp,udp'
            || existing[0].settings?.followRedirect !== true || existing[0].streamSettings?.sockopt?.tproxy !== 'tproxy')) {
        fail('TPROXY', 'Installed TPROXY inbound has an inconsistent identity or port');
    }
    if (existing.length === 0) main.inbounds.push(expected);
}

function removeOwnedRules(config, scope, reserved) {
    for (const rule of config.routing.rules) {
        if (reserved.includes(rule.outboundTag) && !isDeepStrictEqual(rule.inboundTag, [scope])) {
            fail('CANDIDATE', 'Follow-relay reserved outbound is used outside its scope');
        }
    }
    config.routing.rules = config.routing.rules.filter(rule => !reserved.includes(rule.outboundTag));
}

function ensureBlock(config) {
    const expected = { tag: BLOCK_TAG, protocol: 'blackhole' };
    const existing = matches(config.outbounds, BLOCK_TAG);
    if (matches(config.reverse?.portals ?? [], BLOCK_TAG).length || existing.length > 1
        || existing[0] && !isDeepStrictEqual(existing[0], expected)) fail('CANDIDATE', 'Follow-relay block tag conflict');
    if (existing.length === 0) {
        if (!config.outbounds.length) fail('CANDIDATE', 'Missing Xray default outbound');
        config.outbounds.push(expected);
    }
}

function prependMainGuards(main, rules) {
    // These PPP-only rules must not displace the loopback API's first rule.
    const first = main.routing.rules[0];
    const apiFirst = first?.type === 'field' && first.outboundTag === main.api?.tag &&
        isDeepStrictEqual(first.inboundTag, ['API_INBOUND']);
    main.routing.rules.splice(apiFirst ? 1 : 0, 0, ...rules);
}

function replacePppRouting(main, tag, groupId, pathKey, port, guard) {
    removeOwnedRules(main, tag, [BLOCK_TAG, FOLLOW_RELAY_OUTBOUND_TAG]);
    main.routing.rules = withoutIngress(main.routing.rules, tag);
    const owned = matches(main.outbounds, FOLLOW_RELAY_OUTBOUND_TAG);
    if (matches(main.reverse?.portals ?? [], FOLLOW_RELAY_OUTBOUND_TAG).length || owned.length > 1
        || owned[0] && (owned[0] === main.outbounds[0]
            || !validPort(owned[0].settings?.servers?.[0]?.port)
            || !isDeepStrictEqual(owned[0], socksOutbound(FOLLOW_RELAY_OUTBOUND_TAG, owned[0].settings.servers[0].port)))) {
        fail('CANDIDATE', 'Follow-relay outbound tag conflict');
    }
    if (owned[0] && port !== undefined && owned[0].settings.servers[0].port !== port) {
        fail('INGRESS', 'The follow-relay handoff port must stay stable');
    }
    const obsolete = groupId != null && validTag(pathKey)
        ? socksOutbound(cascadePathIngressTag(pathKey), cascadePathIngressPort(groupId, pathKey)) : null;
    main.outbounds = main.outbounds.filter((row, index) => row !== owned[0]
        && !(index > 0 && obsolete && isDeepStrictEqual(row, obsolete)
            && !main.routing.rules.some(rule => rule.outboundTag === row.tag)));
    ensureBlock(main);
    if (port !== undefined) main.outbounds.push(socksOutbound(FOLLOW_RELAY_OUTBOUND_TAG, port));
    prependMainGuards(main, guard(tag));
    // Existing global blackholes preceding any generic forwarding still apply
    // to PPP (e.g. IPv6). The generic/default egress itself never applies to PPP.
    const generic = main.routing.rules.findIndex(rule => !rule.inboundTag?.length && !isBlock(main, rule.outboundTag));
    main.routing.rules.splice(generic < 0 ? main.routing.rules.length : generic, 0,
        scoped(tag, port === undefined ? BLOCK_TAG : FOLLOW_RELAY_OUTBOUND_TAG));
}

function prepareBridge(bridge, main, ingressTag, routeState, guard) {
    const inbounds = matches(bridge.inbounds, ingressTag);
    const listener = inbounds[0];
    if (inbounds.length !== 1 || listener.listen !== LOOPBACK || !validPort(listener.port)
        || listener.protocol !== 'socks' || listener.settings?.auth !== 'noauth'
        || listener.settings?.udp !== true || listener.settings?.ip !== LOOPBACK
        || [...main.inbounds, ...bridge.inbounds].some(row => row !== listener && bindsPort(row, listener.port))) {
        fail('INGRESS', 'Shared relay ingress must be a unique loopback TCP/UDP SOCKS listener');
    }
    removeOwnedRules(bridge, ingressTag, [BLOCK_TAG]);
    ensureBlock(bridge);
    if (routeState === 'no_bridge_exit') {
        bridge.routing.rules = [scoped(ingressTag, BLOCK_TAG), ...withoutIngress(bridge.routing.rules, ingressTag)];
    } else {
        validateSharedPolicy(bridge, ingressTag);
        bridge.routing.rules.unshift(...guard(ingressTag));
    }
    // routeOnly metadata cannot be transported via SOCKS from MAIN. Inspect
    // the payload locally, at the process that actually makes the geo decision.
    listener.sniffing = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };
    bridge.routing.domainStrategy = 'IPOnDemand';
    return routeState === 'egress_configured' ? listener.port : undefined;
}

// Rebuild integration seam: no reads, deployment, state transition or claim
// about traffic. The graph owner supplies a FRESH sidecar and its route state.
function applyFollowRelay({ nodeId, state, main, bridge = null, routeState, controlPlaneAddresses,
    ingressTag = REBUILD_RELAY_INGRESS_TAG } = {}) {
    if (selectL2tpRoutingMode(state) !== FOLLOW_RELAY_MODE) return { main, bridge, applied: false };
    const { inboundTag, groupId } = validateInstalled(nodeId, state);
    if (!ROUTE_STATES.has(routeState) || !validTag(ingressTag) || ingressTag.startsWith(PPP_PREFIX)
        || [BLOCK_TAG, FOLLOW_RELAY_OUTBOUND_TAG].includes(ingressTag)) fail('STATE', 'Invalid rebuild route state or ingress tag');
    const nextMain = candidate(main);
    const nextBridge = bridge === null ? null : candidate(bridge);
    if (routeState === 'detached' ? nextBridge && (matches(nextBridge.inbounds, ingressTag).length
        || nextBridge.routing.rules.some(rule => rule.inboundTag?.includes(ingressTag) || rule.outboundTag === BLOCK_TAG)
        || matches(nextBridge.outbounds, BLOCK_TAG).length) : !nextBridge) {
        fail('STATE', 'Shared relay ingress does not match the rebuild route state');
    }
    ensureTproxy(nextMain, nextBridge, inboundTag, state.tproxyPort);
    const guard = protections(controlPlaneAddresses, [nextMain, nextBridge]);
    const port = routeState === 'detached' ? undefined : prepareBridge(nextBridge, nextMain, ingressTag, routeState, guard);
    replacePppRouting(nextMain, inboundTag, groupId, state.activePathKey, port, guard);
    return { main: nextMain, bridge: nextBridge, applied: true, inboundTag, routeState };
}

// Rebuild places relay graph artifacts in MAIN. Keep a stable loopback hop for
// IP-addressed PPP, but attach that listener to the actual generated policy,
// not a second copy of the policy or a stale per-path outbound in BRIDGE.
function attachLocalFollowRelay({ nodeId, state, main, bridge, policy, controlPlaneAddresses, carryDomain }) {
    if (selectL2tpRoutingMode(state) !== FOLLOW_RELAY_MODE) fail('STATE', 'Explicit follow-relay selection required');
    const { inboundTag, groupId } = validateInstalled(nodeId, state);
    const tag = REBUILD_RELAY_INGRESS_TAG, port = cascadePathIngressPort(String(nodeId), 'follow-relay-v1');
    ensureTproxy(main, bridge, inboundTag, state.tproxyPort);
    if (policy.length === 0 || policy.at(-1).ruleTag !== 'rebuild-policy-default'
        || [...main.inbounds, ...bridge.inbounds].some(i => i.tag === tag || bindsPort(i, port))) {
        fail('INGRESS', 'Stable local ingress conflicts with the relay configuration');
    }
    const guard = protections(controlPlaneAddresses, [main, bridge]);
    replacePppRouting(main, inboundTag, groupId, state.activePathKey, port, guard);
    main.inbounds.push({ tag, port, protocol: 'socks', listen: LOOPBACK,
        settings: { auth: 'noauth', udp: true, ip: LOOPBACK },
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: !carryDomain } });
    prependMainGuards(main, guard(tag));
    // replacePppRouting retains the ordinary shared rule objects when this
    // fresh graph does not yet contain the transparent ingress tag.
    for (const rule of policy) rule.inboundTag.push(tag);
}

module.exports = { applyFollowRelay, attachLocalFollowRelay, REBUILD_RELAY_INGRESS_TAG, FOLLOW_RELAY_OUTBOUND_TAG };
