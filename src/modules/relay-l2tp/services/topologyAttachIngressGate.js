'use strict';

const { cascadePathIngressPort, cascadePathIngressTag } = require('../domain/cascadePathIngress');
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function validIdentity(value) {
    return typeof value === 'string' && SAFE_ID.test(value);
}

function matchingTag(entries, tag) {
    return Array.isArray(entries) ? entries.filter(item => item?.tag === tag) : [];
}

function routeToIngress(candidate, tag, port, { blocked = false, owned = false } = {}) {
    let config;
    try {
        config = JSON.parse(Buffer.from(candidate.bytes).toString('utf8'));
    } catch {
        return false;
    }
    if (!config || typeof config !== 'object' || Array.isArray(config)) return false;
    const matches = matchingTag(config.inbounds, tag);
    if (matches.length !== 1 || matches[0].listen !== '127.0.0.1'
        || matches[0].port !== port || matches[0].protocol !== 'socks'
        || matches[0].settings?.auth !== 'noauth'
        || matches[0].settings?.ip !== '127.0.0.1'
        || matches[0].settings?.udp !== true) return false;
    const rules = config.routing?.rules;
    if (!Array.isArray(rules) || rules.some(rule => !rule || typeof rule !== 'object'
        || Array.isArray(rule) || rule.inboundTag !== undefined && (!Array.isArray(rule.inboundTag)
            || rule.inboundTag.some(value => typeof value !== 'string' || !value)
            || new Set(rule.inboundTag).size !== rule.inboundTag.length))) return false;
    const selected = rules.filter(rule => rule.inboundTag?.includes(tag));
    if (selected.length === 0) return false;
    const fallback = selected.at(-1);
    const fieldRule = (rule, condition) => rule.type === 'field'
        && typeof rule.outboundTag === 'string'
        && Object.keys(rule).every(key => ['type', 'inboundTag', 'outboundTag', ...condition].includes(key));
    const uniqueTarget = target => {
        const outbounds = matchingTag(config.outbounds, target);
        const portals = matchingTag(config.reverse?.portals, target);
        return outbounds.length + portals.length === 1 ? { outbound: outbounds[0], portal: portals[0] } : null;
    };
    const tunnelTarget = target => {
        const resolved = uniqueTarget(target);
        return target !== 'block' && target !== 'direct' && resolved
            && (!owned || resolved.portal
                || ['vless', 'vmess', 'trojan', 'shadowsocks'].includes(resolved.outbound?.protocol));
    };
    // The final rule must be the sole unconditional default. Earlier rules
    // may split domain/geoip traffic, but each is checked, not ignored. Their
    // target must also be a unique non-direct tunnel, never a balancer, freedom
    // alias or an absent/ambiguous reverse portal. Generated mixed-mode rules
    // can share the same policy with upstream transit inbound tags.
    if (!fieldRule(fallback, [])) return false;
    if (blocked) {
        if (selected.length !== 1 || fallback.inboundTag.length !== 1
            || fallback.outboundTag !== 'block'
            || uniqueTarget('block')?.outbound?.protocol !== 'blackhole') return false;
    } else {
        if (!tunnelTarget(fallback.outboundTag)) return false;
        const conditions = new Set();
        for (const rule of selected.slice(0, -1)) {
            const fields = ['domain', 'ip'].filter(key => Object.hasOwn(rule, key));
            if (fields.length !== 1 || !fieldRule(rule, fields)
                || !Array.isArray(rule[fields[0]]) || rule[fields[0]].length === 0
                || rule[fields[0]].some(value => typeof value !== 'string' || !value.trim())
                || rule.outboundTag === fallback.outboundTag || !tunnelTarget(rule.outboundTag)) return false;
            const key = JSON.stringify([fields[0], rule[fields[0]]]);
            if (conditions.has(key)) return false;
            conditions.add(key);
        }
    }
    // Reverse control traffic has one generated, exact reserved-domain route
    // to its paired tunnel outbound. It is not a geo/default client route.
    // Blocked ingress still must precede it (PPP must not escape via control).
    const reverseHandshake = rule => {
        if (blocked || !fieldRule(rule, ['domain']) || rule.inboundTag !== undefined
            || !rule.outboundTag.startsWith('tunnel-')) return false;
        const bridges = matchingTag(config.reverse?.bridges, `bridge-${rule.outboundTag.slice('tunnel-'.length)}`);
        return bridges.length === 1 && typeof bridges[0].domain === 'string'
            && Array.isArray(rule.domain) && rule.domain.length === 1
            && rule.domain[0] === `full:${bridges[0].domain}` && tunnelTarget(rule.outboundTag);
    };
    // A global rule applies to PPP too. Apart from paired reverse control,
    // only a unique blackhole can precede this policy without inbound scoping.
    return !rules.slice(0, rules.indexOf(fallback)).some(rule =>
        (!rule.inboundTag || rule.inboundTag.length === 0)
        && uniqueTarget(rule.outboundTag)?.outbound?.protocol !== 'blackhole'
        && !reverseHandshake(rule));
}

// Shared structural evidence only: executor readback still proves the candidate
// was installed. In particular a staged marker is never authority to skip PPP.
function ownedIngressRouteState(plan) {
    if (!['link.attach', 'link.replace', 'link.apply', 'link.delete'].includes(plan?.kind)
        || !validIdentity(plan.groupId) || !validIdentity(plan.pathKey)
        || !validIdentity(plan.ownerNodeId) || !Array.isArray(plan.nodes)) return null;
    const owners = plan.nodes.filter(node => node?.node === plan.ownerNodeId && node.role === 'relay');
    if (owners.length !== 1) return null;
    const blocked = plan.routeState === 'no_bridge_exit';
    // APPLY may legitimately prepare an incomplete installed route, and a later
    // DELETE may keep a previously emptied path blocked. Candidate blocking is
    // proved here; the service checks actual old membership, owner and epochs.
    if (blocked && (!Array.isArray(plan.newPathLinkIds)
        || plan.newPathLinkIds.length !== 0 || !Array.isArray(plan.oldPathLinkIds)
        || !Array.isArray(plan.effectiveTopology?.links)
        || plan.effectiveTopology.links.some(link => link.id === plan.linkId) === (plan.kind === 'link.delete'))) return null;
    if (!blocked && plan.routeState !== undefined
        && !['complete', 'no_portal_input'].includes(plan.routeState)) return null;
    return routeToIngress(owners[0].candidate, cascadePathIngressTag(plan.pathKey),
        cascadePathIngressPort(plan.groupId, plan.pathKey), { blocked, owned: true })
        ? blocked ? 'no_bridge_exit' : 'egress_configured' : null;
}

// No shell interpolation, no artifact runner/bootstrap and no config/secret output.
// The only remote stdout is exactly one ASCII boolean; errors are masked.
function mainProbeScript(inboundTag, outboundTag, port, { blocked = false } = {}) {
    return `import json
import subprocess

def probe():
    with open('/usr/local/etc/xray/config.json', 'r', encoding='utf-8') as source:
        raw = source.read(4194305)
    if len(raw) > 4194304:
        return False
    config = json.loads(raw)
    inbound = ${JSON.stringify(inboundTag)}
    outbound = ${JSON.stringify(outboundTag)}
    port = ${port}
    ins = config.get('inbounds', [])
    outs = config.get('outbounds', [])
    rules = config.get('routing', {}).get('rules', [])
    if not all(isinstance(items, list) for items in (ins, outs, rules)):
        return False
    ins = [item for item in ins if isinstance(item, dict) and item.get('tag') == inbound]
    outs = [item for item in outs if isinstance(item, dict) and item.get('tag') == outbound]
    if len(ins) != 1 or len(outs) != 1:
        return False
    entry, target = ins[0], outs[0]
    if (entry.get('protocol') != 'dokodemo-door'
        or entry.get('listen') != '0.0.0.0'
        or type(entry.get('port')) is not int or not 1 <= entry['port'] <= 65535
        or entry.get('settings', {}).get('network') != 'tcp,udp'
        or entry.get('settings', {}).get('followRedirect') is not True
        or entry.get('streamSettings', {}).get('sockopt', {}).get('tproxy') != 'tproxy'
        or target.get('protocol') != 'socks'
        or target.get('settings', {}).get('servers') != [{'address': '127.0.0.1', 'port': port}]):
        return False
    selected = [rule for rule in rules if isinstance(rule, dict)
                and isinstance(rule.get('inboundTag'), list) and inbound in rule['inboundTag']]
    if (not selected or selected[-1].get('type') != 'field' or selected[-1].get('inboundTag') != [inbound]
        or selected[-1].get('outboundTag') != outbound
        or any(key in selected[-1] for key in ('ip', 'domain', 'port', 'network', 'protocol'))):
        return False
    if any(rule.get('outboundTag') == outbound or
           not any(key in rule for key in ('ip', 'domain', 'port', 'network', 'protocol'))
           for rule in selected[:-1]):
        return False
    if ${blocked ? 'True' : 'False'}:
        # Even a correct final SOCKS route cannot prove blocking if an earlier
        # MAIN rule releases this PPP input before it reaches the sidecar.
        for rule in rules[:rules.index(selected[-1])]:
            if not isinstance(rule, dict):
                return False
            tags = rule.get('inboundTag')
            if not tags or inbound in tags:
                targets = [item for item in config.get('outbounds', [])
                           if isinstance(item, dict) and item.get('tag') == rule.get('outboundTag')]
                if len(targets) != 1 or targets[0].get('protocol') != 'blackhole':
                    return False
    service = subprocess.run(['systemctl', 'is-active', 'xray.service'],
                             capture_output=True, text=True, timeout=5, check=False)
    return service.returncode == 0 and service.stdout == 'active\\n' and service.stderr == ''

try:
    print('1' if probe() else '0')
except Exception:
    print('0')
`;
}

class TopologyAttachIngressGate {
    constructor({ nodeExecutionResolver } = {}) {
        if (typeof nodeExecutionResolver?.resolve !== 'function') {
            throw new TypeError('Attach ingress proof requires node execution resolver');
        }
        this.nodeExecutionResolver = nodeExecutionResolver;
    }

    async verifyPlan(plan) {
        const owned = plan?.ownerCredentialRevision !== undefined || plan?.kind !== 'link.attach';
        if ((owned ? !ownedIngressRouteState(plan) : plan?.kind !== 'link.attach')
            || !validIdentity(plan.groupId) || !validIdentity(plan.pathKey)
            || !validIdentity(plan.ownerNodeId) || !Array.isArray(plan.nodes)) return { ok: false };
        const owners = plan.nodes.filter(node => node.node === plan.ownerNodeId && node.role === 'relay');
        if (owners.length !== 1) return { ok: false };
        const tag = cascadePathIngressTag(plan.pathKey);
        const port = cascadePathIngressPort(plan.groupId, plan.pathKey);
        if (!owned && !routeToIngress(owners[0].candidate, tag, port)) return { ok: false };
        let ssh;
        let verified = false;
        try {
            ssh = await this.nodeExecutionResolver.resolve({ nodeId: plan.ownerNodeId, role: 'relay' });
            await ssh.connect();
            const result = await ssh.exec('python3 -', {
                stdin: mainProbeScript(`relay-l2tp-${plan.groupId}`, tag, port,
                    { blocked: plan.routeState === 'no_bridge_exit' }),
                timeout: 10000,
            });
            verified = result?.code === 0 && result.stdout === '1\n' && result.stderr === '';
        } catch {
            verified = false;
        } finally {
            try { ssh?.disconnect(); } catch { verified = false; }
        }
        return { ok: verified };
    }
}

module.exports = { TopologyAttachIngressGate, mainProbeScript, ownedIngressRouteState };
