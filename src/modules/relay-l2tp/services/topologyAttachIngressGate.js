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
    const selected = Array.isArray(rules) ? rules.filter(rule =>
        Array.isArray(rule?.inboundTag) && rule.inboundTag.includes(tag)) : [];
    if (selected.length !== 1 || selected[0].type !== 'field'
        || selected[0].inboundTag.length !== 1
        || Object.keys(selected[0]).some(key => !['type', 'inboundTag', 'outboundTag'].includes(key))
        || typeof selected[0].outboundTag !== 'string') return false;
    const target = selected[0].outboundTag;
    const outbounds = matchingTag(config.outbounds, target);
    const portals = matchingTag(config.reverse?.portals, target);
    if (outbounds.length + portals.length !== 1) return false;
    if (blocked) {
        // A rule without inboundTag can preempt this ingress too. A private-IP
        // blackhole is safe; an earlier wildcard/direct/balancer is not.
        const before = rules.slice(0, rules.indexOf(selected[0]));
        if (before.some(rule => (!Array.isArray(rule?.inboundTag) || rule.inboundTag.length === 0)
            && matchingTag(config.outbounds, rule?.outboundTag)[0]?.protocol !== 'blackhole')) return false;
    }
    if (blocked) return target === 'block' && outbounds[0]?.protocol === 'blackhole';
    return target !== 'block' && target !== 'direct'
        && (!owned || portals.length === 1
            || ['vless', 'vmess', 'trojan', 'shadowsocks'].includes(outbounds[0]?.protocol));
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
    if (blocked && (plan.kind !== 'link.delete' || !Array.isArray(plan.newPathLinkIds)
        || plan.newPathLinkIds.length !== 0 || !Array.isArray(plan.oldPathLinkIds)
        || plan.oldPathLinkIds.length === 0 || !plan.oldPathLinkIds.includes(plan.linkId))) return null;
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
