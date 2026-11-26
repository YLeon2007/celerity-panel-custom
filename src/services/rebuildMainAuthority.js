'use strict';

const { createHash, hkdfSync } = require('node:crypto');
const { BlockList, isIP } = require('node:net');
const { isDeepStrictEqual: equal } = require('node:util');
const { createFileCutoverJournal } = require('./rebuildTransitCutoverJournal');
const { createCutoverArtifactStore } = require('./rebuildTransitCutoverArtifacts');
const { planSerialScopedTransition } = require('./rebuildTransitActivationPlan');

const PATHS = Object.freeze({ journal: '/app/data/rebuild-main/journal', artifacts: '/app/data/rebuild-main/artifacts' });
const MAIN_CARD_SELECT = 'ip ssh.port ssh.username cascadeRole role active type useCustomConfig machineId ssh.machineId ssh.hostKeySha256 sshHostKeySha256 xray.agentPort xray.agentTls xray.agentToken';
const fail = () => Object.assign(new Error('REBUILD_MAIN_AUTHORITY_UNPROVED'), { code: 'REBUILD_MAIN_AUTHORITY_UNPROVED' });
const need = value => { if (!value) throw fail(); };
const sha = data => createHash('sha256').update(data).digest('hex');
const hex = (value, length) => typeof value === 'string' && value.length === length && /^[a-f0-9]+$/.test(value);
const tag = value => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}(?![\s\S])/.test(value);

// Ordinary cards are not DIRECT grants. Only an already persisted identity is
// considered, not telemetry, a fetched key, or the separate topology owner.
function storedIdentity(top, nested, length) {
    const value = top ?? nested ?? null;
    need((value === null || hex(value, length)) && (nested == null || nested === value));
    return value;
}
function mainCardIdentity(node) {
    return {
        machineId: storedIdentity(node.machineId, node.ssh?.machineId, 32),
        sshHostKeySha256: storedIdentity(node.sshHostKeySha256, node.ssh?.hostKeySha256, 64),
    };
}
function mainCardBinding(node) {
    return [node.ip, node.ssh?.port || 22, node.ssh?.username || 'root', node.cascadeRole, node.role,
        node.active, node.type, node.useCustomConfig, ...Object.values(mainCardIdentity(node)),
        agentTarget(node), node.xray?.agentToken];
}
function agentTarget(node) {
    return { nodeId: String(node._id), ip: node.ip, agentTls: node.xray?.agentTls !== false,
        agentPort: node.xray?.agentPort ?? 62080 };
}

// Independent, stdin-free snapshot observation on the same authenticated SSH
// client. Never return MAIN bytes, agent credentials, or raw manager output.
// The receiver still owns exclusion, runtime TestRoute, and final DIRECT CAS.
const observeScript = String.raw`import os, stat, sys, json, hashlib, subprocess, re

def file(path, bound):
    with os.fdopen(os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK), 'rb') as f:
        s = os.fstat(f.fileno())
        assert stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and not s.st_mode & 0o022
        data = f.read(bound+1)
        assert 0 < len(data) <= bound
        for t in (os.fstat(f.fileno()), os.stat(path, follow_symlinks=False)):
            assert gen(s) == gen(t)
        return s, data

def gen(s):
    return [str(s.st_dev), str(s.st_ino), str(s.st_ctime_ns)]

def unique(pairs):
    d = dict(pairs)
    assert len(d) == len(pairs)
    return d

def unit(name, binary, argv):
    keys = ('ActiveState','SubState','MainPID','InvocationID','Job','ExecStart','NeedDaemonReload')
    data = subprocess.run(['/usr/bin/systemctl','show','--all',*['-p'+k for k in keys],'--',name],
        stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=3)
    assert not data.stderr and len(data.stdout) <= 16384
    fields = unique(line.split('=',1) for line in data.stdout.decode().splitlines())
    assert set(fields) == set(keys) and fields['ActiveState'] == 'active' and fields['SubState'] == 'running'
    assert fields['Job'] in ('','0') and fields['NeedDaemonReload'] == 'no'
    pid = int(fields['MainPID']); inv = fields['InvocationID']
    assert 0 < pid < 2**31 and re.fullmatch('[a-f0-9]{32}', inv)
    path = '/proc/'+str(pid)
    assert os.readlink(path+'/exe') == binary
    with open(path+'/cmdline','rb') as f:
        assert f.read(4096).split(b'\0') in argv
    with open(path+'/stat','rb') as f:
        ticks = int(f.read(4096).rsplit(b') ',1)[1].split()[19])
    return pid, inv, ticks, fields['ExecStart']

def owns_port(pid, port):
    own = set()
    path = '/proc/'+str(pid)
    for fd in os.listdir(path+'/fd'):
        try: link = os.readlink(path+'/fd/'+fd)
        except FileNotFoundError: continue
        if link.startswith('socket:['): own.add(link[8:-1])
    found = []
    for p, wildcard in (('tcp','0'*8),('tcp6','0'*32)):
        with open(path+'/net/'+p) as f:
            lines = f.read((8<<20)+1)
        assert len(lines) <= 8<<20
        for line in lines.splitlines()[1:]:
            fields = line.split(); addr, raw_port = fields[1].split(':')
            if int(raw_port,16) == port and fields[3] == '0A':
                found.append(addr == wildcard and fields[9] in own)
    assert found and all(found)

def main():
    xbin = '/usr/local/bin/xray'; abin = '/usr/local/bin/cc-agent'; main = '/usr/local/etc/xray/config.json'
    args = [[xbin.encode(),b'run',flag,main.encode(),b''] for flag in (b'-c', b'-config')]
    x = unit('xray.service',xbin,args)
    a = unit('cc-agent.service',abin,[[abin.encode(),b'']])
    s, data = file(main,8<<20)
    path = '/etc/cc-agent/config.json'
    ac, raw = file(path,65536)
    cfg = json.loads(raw,object_pairs_hook=unique)
    assert type(cfg) is dict and all(k.lower() not in ('listen','token','xray_api','tls','inbounds','inbound_tag','http_mutation_policy') or k == k.lower() for k in cfg)
    port = int(sys.argv[1]); assert cfg.get('listen','0.0.0.0:62080') == '0.0.0.0:'+str(port)
    assert cfg.get('xray_api','127.0.0.1:61000') == '127.0.0.1:61000' and 'http_mutation_policy' not in cfg
    tls = cfg.get('tls',{}).get('enabled',False); assert type(tls) is bool
    token = cfg['token']; assert type(token) is str and token
    rows = cfg.get('inbounds'); assert rows is None or type(rows) is list
    if rows:
        assert all(type(row) is dict and all(k.lower() not in ('tag','flow') or k == k.lower() for k in row) for row in rows)
        flows = [[row['tag'],'' if row.get('flow') is None else row['flow']] for row in rows]
    else:
        # Legacy agent probes the exact on-disk Xray transport at process birth.
        flows = [[cfg.get('inbound_tag','vless-in'),None]]
    owns_port(a[0],port)
    # btime rounds down: refuse rather than accepting a post-birth config.
    with open('/proc/stat', 'rb') as f:
        boot = next(int(row.split()[1]) for row in f if row.startswith(b'btime '))
    assert ac.st_ctime_ns <= boot*10**9 + a[2]*10**9//os.sysconf('SC_CLK_TCK')
    assert gen(s) == gen(os.stat(main,follow_symlinks=False)) and gen(ac) == gen(os.stat(path,follow_symlinks=False))
    assert x == unit('xray.service',xbin,args) and a == unit('cc-agent.service',abin,[[abin.encode(),b'']])
    print(json.dumps(dict(main=hashlib.sha256(data).hexdigest(),metadata=[stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid],
        generation=gen(s),xray=x[:2],agent=a[:3],agentConfig=gen(ac),token=hashlib.sha256(token.encode()).hexdigest(),tls=tls,flows=flows)))

try: main()
except Exception: sys.exit(70)
`;
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
async function observeMain(transport, node) {
    const { agentPort, agentTls } = agentTarget(node);
    need(Number.isInteger(agentPort) && agentPort > 0 && agentPort <= 65535 && typeof node.xray?.agentToken === 'string' && node.xray.agentToken);
    const result = await transport.observeMain(`exec /usr/bin/timeout -k 1s 10s /usr/bin/env -i LC_ALL=C /usr/bin/python3 -I -B -c ${quote(observeScript)} ${agentPort}`);
    need(result?.code === 0 && result.stderr === '' && typeof result.stdout === 'string');
    let proof;
    try { proof = JSON.parse(result.stdout); } catch { throw fail(); }
    need(hex(proof?.main, 64) && equal(proof.token, sha(node.xray.agentToken)) && proof.tls === agentTls &&
        Array.isArray(proof.flows) && proof.flows.length > 0 && proof.flows.length <= 16 &&
        proof.flows.every(pair => Array.isArray(pair) && pair.length === 2 && tag(pair[0]) && [null, '', 'xtls-rprx-vision'].includes(pair[1])) &&
        new Set(proof.flows.map(pair => pair[0])).size === proof.flows.length);
    return proof;
}

const probeIP = '127.0.0.1';
function matchesProbeIP(selector) {
    if (selector === 'geoip:private') return true; // stock assets include loopback
    if (typeof selector !== 'string') return undefined;
    const [address, prefix, extra] = selector.split('/');
    const family = isIP(address);
    if (!family || extra !== undefined || (prefix !== undefined && !/^(0|[1-9]\d{0,2})$/.test(prefix))) return undefined;
    if (family === 6) return false;
    if (prefix === undefined) return address === probeIP;
    if (Number(prefix) > 32) return undefined;
    const list = new BlockList();
    list.addSubnet(address, Number(prefix));
    return list.check(probeIP);
}

// Only certify an explicit, stable first match across the boot images. A
// literal destination cannot match a domain or IPv6-only selector. If an
// earlier GeoIP rule may match, both branches must choose the same outbound
// (e.g. the country deny and private deny in a stock ACL).
function deriveRoutes(images, managed) {
    const routes = [];
    for (const inboundTag of managed) {
        const outbound = config => {
            need(['AsIs', 'IPOnDemand', 'IPIfNonMatch'].includes(config.routing.domainStrategy ?? 'AsIs') && !(config.routing.balancers?.length));
            let possible;
            for (const { type, ruleTag, inboundTag: scope, outboundTag, ...match } of config.routing.rules) {
                if (scope?.length && !scope.includes(inboundTag)) continue;
                if (match.domain && Object.keys(match).length === 1) continue;
                let definite = true;
                if (Object.keys(match).length) {
                    if (Object.keys(match).length !== 1 || !Array.isArray(match.ip)) return null;
                    const matches = match.ip.map(matchesProbeIP);
                    definite = matches.includes(true);
                    if (!definite && !matches.includes(undefined)) continue;
                }
                if (type !== 'field' || !tag(outboundTag) || (possible !== undefined && possible !== outboundTag)) return null;
                if (definite) return outboundTag;
                possible = outboundTag;
            }
            return null;
        };
        const expected = images.map(outbound);
        if (expected[0] && expected.every(value => value === expected[0])) {
            routes.push({ inboundTag, network: 'tcp', targetPort: 443, outboundTag: expected[0], targetIP: probeIP });
        }
    }
    need(routes.length > 0);
    return routes;
}
function bootstrapDirect(state, nodeId, machineId) {
    if (!state) return null;
    const { backupId, rebuildMachineId, clientCidr, tproxyPort, fwmark, routeTable } = state;
    need(machineId === rebuildMachineId && hex(backupId, 32) && String(state.node) === nodeId);
    return { nodeId, backupId, network: { clientCidr, tproxyPort, fwmark, routeTable } };
}

// Request-local provider: all clients were admitted by ordinary Apply, before
// its confirmation. Never build a connector or reacquire a writer lock here.
function createSerialMainAuthority({ env, transports, bindings, composition, admittedNodes, admittedStates, verifyApply, confirmation, stores }) {
    return async ({ ids, nodes, states, verify }) => {
        need(env.C3_REBUILD_CHAIN_APPLY === '1' && confirmation);
        const root = env.ENCRYPTION_KEY;
        need(typeof root === 'string' && root.trim().length >= 32);
        const fence = async () => {
            need(env.C3_REBUILD_CHAIN_APPLY === '1' && env.ENCRYPTION_KEY === root);
            need(await verify() !== false && await verifyApply() !== false);
            need(env.C3_REBUILD_CHAIN_APPLY === '1' && env.ENCRYPTION_KEY === root);
            return true;
        };
        await fence();
        const { before, after, coreIdentities } = confirmation;
        need(equal(states, admittedStates));
        const steps = planSerialScopedTransition({ before, after, composition, allowMainRestart: true });
        need(steps.length > 0);
        const touched = new Map(), peers = new Map(), unchangedMainPins = new Map();
        const admitted = new Map(admittedNodes.map(node => [String(node._id), node]));
        const cards = new Map(nodes.map(node => [String(node._id), node]));
        const baselineMain = new Map(before.filter(row => row.profile === 'main').map(row => [row.nodeId, row.config]));
        for (const id of ids) {
            const node = cards.get(id), transport = transports.get(id), binding = bindings.get(id)?.binding;
            need(node && admitted.has(id) && equal(mainCardBinding(node), mainCardBinding(admitted.get(id))) && transport);
            const cardIdentity = mainCardIdentity(node), identity = binding ?? cardIdentity;
            if (binding && cardIdentity.machineId !== null) need(cardIdentity.machineId === binding.machineId);
            const authoritySha256 = sha(JSON.stringify(['rebuild-main-apply-peer-v1', id, binding?.host ?? node.ip,
                binding?.port ?? node.ssh?.port ?? 22, binding?.username ?? node.ssh?.username ?? 'root',
                identity.machineId, identity.sshHostKeySha256]));
            const own = steps.filter(step => step.nodeId === id);
            const readMainSha256 = async () => {
                const observed = await transport.readMainSha256();
                if (!own.length && !unchangedMainPins.has(id)) {
                    // Do not settle an out-of-band edit between confirmation
                    // and the first independent fingerprint on a read-only peer.
                    need(equal(await transport.read('main'), baselineMain.get(id)) && await transport.readMainSha256() === observed);
                    unchangedMainPins.set(id, observed);
                }
                return observed;
            };
            const peer = { authoritySha256, readMainSha256, async verify(target, expected) {
                return target === id && expected === authoritySha256 && await transport.verifyMainConnection() === true;
            } };
            if (own.length) {
                const first = await observeMain(transport, node);
                const managed = first.flows.map(pair => pair[0]).sort();
                const images = [own[0].before, ...own.map(step => step.after)];
                const subscriberTags = new Set([node.xray?.inboundTag || 'vless-in',
                    ...(node.xray?.extraInbounds ?? []).map(row => row?.inboundTag)]);
                need(managed.every(inboundTag => subscriberTags.has(inboundTag) && images.every(config =>
                    config.inbounds.some(row => row.tag === inboundTag && row.protocol === 'vless'))));
                peer.managed = managed;
                const bootstrap = { machineId: identity.machineId, managed, direct: bootstrapDirect(states.get(id), id, identity.machineId),
                    routes: deriveRoutes(images, managed) };
                touched.set(id, { first, node, transport, bootstrap, latest: null });
            }
            peers.set(id, peer);
        }
        const storage = stores ?? {
            journal: createFileCutoverJournal({ directory: PATHS.journal }),
            artifacts: createCutoverArtifactStore({ directory: PATHS.artifacts,
                key: Buffer.from(hkdfSync('sha256', root, 'celerity/rebuild/main/v1', 'artifacts', 32)) }),
        };
        const hostProof = async (id, snap, target) => {
            const entry = touched.get(id);
            need(entry && (!target || equal(target, agentTarget(entry.node))));
            await fence();
            const live = await observeMain(entry.transport, entry.node);
            need(equal(live.agentConfig, entry.first.agentConfig) && equal(live.flows, entry.first.flows) &&
                live.main === sha(Buffer.from(snap.data, 'base64')) && equal(live.metadata, snap.metadata) &&
                equal(live.generation, snap.generation) && equal(live.xray, snap.xray));
            await fence();
            return live;
        };
        return { ...storage, before, profiles: composition, coreIdentities, peers,
            verifyFence: fence,
            async openWindow(id, options) {
                const entry = touched.get(id);
                need(entry);
                await fence();
                return entry.transport.openMainWindow({ ...options, timeout: 30 * 60 * 1000, bootstrap: entry.bootstrap });
            },
            async verifySnapshot(id, phase, snap) {
                const proof = await hostProof(id, snap);
                const entry = touched.get(id);
                if (phase === 'before') {
                    need(equal(proof.agent, entry.latest?.agent ?? entry.first.agent));
                    entry.sync = null;
                } else {
                    need(phase === 'after' && entry.sync && equal(entry.sync.snap, snap) && equal(entry.sync.agent, proof.agent));
                    entry.latest = { snap, agent: proof.agent };
                }
                return true;
            },
            async verifyAgentEndpoint(id, target, snap) {
                const live = await hostProof(id, snap, target), entry = touched.get(id);
                entry.sync ??= { snap, agent: live.agent };
                return equal(entry.sync.snap, snap) && equal(entry.sync.agent, live.agent);
            },
            async readAgentManagedFlows(id, target, snap) {
                const live = await hostProof(id, snap, target);
                const sync = touched.get(id).sync;
                need(sync && equal(sync.snap, snap) && equal(sync.agent, live.agent));
                const cfg = JSON.parse(Buffer.from(snap.data, 'base64').toString('utf8'));
                return new Map(live.flows.map(([tag, flow]) => {
                    const inbound = cfg.inbounds.find(row => row.tag === tag);
                    need(inbound?.protocol === 'vless');
                    // Legacy cc-agent only reads client[0].flow from the
                    // same generation it loaded on startup.
                    const value = flow ?? inbound.settings?.clients?.[0]?.flow ?? '';
                    need(['', 'xtls-rprx-vision'].includes(value));
                    return [tag, value];
                }));
            },
            async prove() {
                for (const [id, entry] of touched) if (entry.latest) {
                    const live = await hostProof(id, entry.latest.snap);
                    need(equal(live.agent, entry.latest.agent));
                }
                return true;
            },
            async verifyTerminal(ctx, latest) {
                const evidence = [];
                for (const [id, snap] of latest) {
                    const live = await hostProof(id, snap);
                    need(equal(live.agent, touched.get(id).latest?.agent));
                    evidence.push([id, live.main, live.generation, live.xray, live.agent]);
                }
                return { evidence: Buffer.from(JSON.stringify(['rebuild-main-live-v1', ctx.direction, evidence])),
                    unchangedMainPins: new Map(unchangedMainPins) };
            },
            async observe() { return 'unavailable'; }, // No fresh-process recovery authority.
        };
    };
}
module.exports = { createSerialMainAuthority, mainCardIdentity, mainCardBinding, MAIN_CARD_SELECT, PATHS };
