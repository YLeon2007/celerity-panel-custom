'use strict';

const { cascadePathIngressPort, cascadePathIngressTag } = require('../domain/cascadePathIngress');
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function validIdentity(value) {
    return typeof value === 'string' && SAFE_ID.test(value);
}

function matchingTag(entries, tag) {
    return Array.isArray(entries) ? entries.filter(item => item?.tag === tag) : [];
}

function routeToIngress(candidate, tag, port) {
    let config;
    try {
        config = JSON.parse(Buffer.from(candidate.bytes).toString('utf8'));
    } catch {
        return false;
    }
    const matches = matchingTag(config.inbounds, tag);
    if (matches.length !== 1 || matches[0].listen !== '127.0.0.1'
        || matches[0].port !== port || matches[0].protocol !== 'socks'
        || matches[0].settings?.auth !== 'noauth'
        || matches[0].settings?.ip !== '127.0.0.1'
        || matches[0].settings?.udp !== true) return false;
    const rules = config.routing?.rules;
    const selected = Array.isArray(rules) ? rules.filter(rule =>
        Array.isArray(rule?.inboundTag) && rule.inboundTag.includes(tag)) : [];
    return selected.length === 1 && selected[0].type === 'field'
        && selected[0].inboundTag.length === 1
        && !['ip', 'domain', 'port', 'network', 'protocol'].some(key => key in selected[0])
        && typeof selected[0].outboundTag === 'string'
        && selected[0].outboundTag !== 'block'
        && matchingTag(config.outbounds, selected[0].outboundTag).length
            + matchingTag(config.reverse?.portals, selected[0].outboundTag).length === 1;
}

// No shell interpolation, no artifact runner/bootstrap and no config/secret output.
// The only remote stdout is exactly one ASCII boolean; errors are masked.
function mainProbeScript(inboundTag, outboundTag, port) {
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
        if (plan?.kind !== 'link.attach' || !validIdentity(plan.groupId)
            || !validIdentity(plan.pathKey) || !validIdentity(plan.ownerNodeId)
            || !Array.isArray(plan.nodes)) return { ok: false };
        const owners = plan.nodes.filter(node => node.node === plan.ownerNodeId && node.role === 'relay');
        if (owners.length !== 1) return { ok: false };
        const tag = cascadePathIngressTag(plan.pathKey);
        const port = cascadePathIngressPort(plan.groupId, plan.pathKey);
        if (!routeToIngress(owners[0].candidate, tag, port)) return { ok: false };
        let ssh;
        let verified = false;
        try {
            ssh = await this.nodeExecutionResolver.resolve({ nodeId: plan.ownerNodeId, role: 'relay' });
            await ssh.connect();
            const result = await ssh.exec('python3 -', {
                stdin: mainProbeScript(`relay-l2tp-${plan.groupId}`, tag, port),
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

module.exports = { TopologyAttachIngressGate, mainProbeScript };
