/**
 * Subscription API (Hysteria 2 + VLESS)
 * 
 * Single route /api/files/:token:
 * - Browser → HTML page
 * - App → subscription in the appropriate format
 * 
 * With Redis caching for high performance
 */

const express = require('express');
const router = express.Router();
const QRCode = require('qrcode');
const HyUser = require('../models/hyUserModel');
const HyNode = require('../models/hyNodeModel');
const cache = require('../services/cacheService');
const logger = require('../utils/logger');
const { getNodesByGroups, getSettings, parseDurationSeconds, normalizeHopInterval } = require('../utils/helpers');
const uaStats = require('../services/uaStatsService');

// ==================== HELPERS ====================

function detectFormat(userAgent) {
    const ua = (userAgent || '').toLowerCase();
    // Shadowrocket expects base64-encoded URI list
    if (/shadowrocket/.test(ua)) return 'shadowrocket';
    // HAPP (Xray-core based) — plain URI list (individual servers in HAPP UI)
    // v2ray-json available via ?format=v2ray-json for users who want routing rules
    if (/happ/.test(ua)) return 'uri';
    // sing-box based clients — checked BEFORE clash because Hiddify UA contains "ClashMeta"
    // Example: "HiddifyNext/4.0.5 (android) like ClashMeta v2ray sing-box"
    if (/hiddify|hiddifynext|sing-?box|nekobox|nekoray|neko|sfi|sfa|sfm|sft|karing/.test(ua)) return 'singbox';
    if (/clash|stash|surge|loon/.test(ua)) return 'clash';
    return 'uri';
}

function isBrowser(req) {
    const accept = req.headers.accept || '';
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    return accept.includes('text/html') && /mozilla|chrome|safari|edge|opera/.test(ua);
}

async function getUserByToken(token) {
    // Single query instead of two (optimization)
    const user = await HyUser.findOne({
        $or: [
            { subscriptionToken: token },
            { userId: token }
        ]
    })
        .populate('nodes', 'active name type status onlineUsers maxOnlineUsers rankingCoefficient domain sni ip port portRange hopInterval portConfigs obfs flag xray')
        .populate('groups', '_id name subscriptionTitle');
    
    return user;
}

/**
 * Get subscription title for a user.
 * Takes subscriptionTitle from the first group, or the group name.
 */
function getSubscriptionTitle(user) {
    if (!user.groups || user.groups.length === 0) {
        return 'Hysteria';
    }
    
    // Take the first group
    const group = user.groups[0];
    return group.subscriptionTitle || group.name || 'Hysteria';
}

/**
 * Encode title in base64 (Marzban-compatible format)
 */
function encodeTitle(text) {
    return `base64:${Buffer.from(text).toString('base64')}`;
}

/**
 * Get active nodes (with caching)
 */
async function getActiveNodesWithCache() {
    const cached = await cache.getActiveNodes();
    if (cached) return cached;

    // Include type, xray, obfs, and cascadeRole fields needed for URI generation and filtering
    const nodes = await HyNode.find({ active: true })
        .select('name type flag ip domain sni port portRange hopInterval portConfigs obfs active status onlineUsers maxOnlineUsers rankingCoefficient groups xray cascadeRole')
        .lean();
    await cache.setActiveNodes(nodes);
    return nodes;
}

async function getActiveNodes(user) {
    let nodes = [];
    let settings;
    
    // Check if user has linked nodes
    if (user.nodes && user.nodes.length > 0) {
        // User has linked nodes - only need settings
        nodes = user.nodes.filter(n => n && n.active);
        settings = await getSettings();
        logger.debug(`[Sub] User ${user.userId}: ${nodes.length} linked active nodes`);
    } else {
        // No linked nodes - fetch nodes and settings in parallel for better performance
        const [allNodes, loadedSettings] = await Promise.all([
            getActiveNodesWithCache(),
            getSettings()
        ]);
        settings = loadedSettings;
        
        // Filter by user groups
        const userGroupIds = (user.groups || []).map(g => g._id?.toString() || g.toString());
        nodes = allNodes.filter(n => {
            const nodeGroupIds = (n.groups || []).map(g => g._id?.toString() || g.toString());
            return nodeGroupIds.some(gId => userGroupIds.includes(gId));
        });
        
        logger.debug(`[Sub] User ${user.userId}: ${nodes.length} nodes by groups`);
    }
    
    const lb = settings.loadBalancing || {};
    
    // Exclude exit (bridge) and relay nodes — users connect to entry (portal) or standalone nodes only.
    // Traffic is routed through the cascade automatically.
    {
        const beforeCascadeFilter = nodes.length;
        nodes = nodes.filter(n => n.cascadeRole !== 'bridge' && n.cascadeRole !== 'relay');
        if (nodes.length < beforeCascadeFilter) {
            logger.debug(`[Sub] Filtered out ${beforeCascadeFilter - nodes.length} bridge/relay nodes from subscription`);
        }
    }

    // Filter overloaded nodes (if enabled)
    if (lb.hideOverloaded) {
        const beforeFilter = nodes.length;
        nodes = nodes.filter(n => {
            if (!n.maxOnlineUsers || n.maxOnlineUsers === 0) return true;
            return n.onlineUsers < n.maxOnlineUsers;
        });
        if (nodes.length < beforeFilter) {
            logger.debug(`[Sub] Filtered out ${beforeFilter - nodes.length} overloaded nodes`);
        }
    }
    
    // Log node statuses (debug level to reduce overhead)
    if (nodes.length > 0) {
        const statuses = nodes.map(n => `${n.name}:${n.status}(${n.onlineUsers}/${n.maxOnlineUsers || '∞'})`).join(', ');
        logger.debug(`[Sub] Nodes for ${user.userId}: ${statuses}`);
    } else {
        logger.warn(`[Sub] NO NODES for user ${user.userId}! Check: active=true, groups match`);
    }
    
    // Sort nodes: by load percentage when LB is enabled, otherwise by rankingCoefficient
    if (lb.enabled) {
        nodes.sort((a, b) => {
            const loadA = a.maxOnlineUsers ? a.onlineUsers / a.maxOnlineUsers : 0;
            const loadB = b.maxOnlineUsers ? b.onlineUsers / b.maxOnlineUsers : 0;
            if (loadA !== loadB) return loadA - loadB;
            if (a.onlineUsers !== b.onlineUsers) return a.onlineUsers - b.onlineUsers;
            return (a.rankingCoefficient || 1) - (b.rankingCoefficient || 1);
        });
        logger.debug(`[Sub] Load balancing applied`);
    } else {
        nodes.sort((a, b) => (a.rankingCoefficient || 1) - (b.rankingCoefficient || 1));
    }

    return nodes;
}

function validateUser(user) {
    if (!user) return { valid: false, error: 'Not found' };
    if (!user.enabled) return { valid: false, error: 'Inactive' };
    if (user.expireAt && new Date(user.expireAt) < new Date()) return { valid: false, error: 'Expired' };
    if (user.trafficLimit > 0) {
        const used = (user.traffic?.tx || 0) + (user.traffic?.rx || 0);
        if (used >= user.trafficLimit) return { valid: false, error: 'Traffic exceeded' };
    }
    return { valid: true };
}

function getNodeConfigs(node) {
    const configs = [];
    const host = node.domain || node.ip;
    // SNI logic:
    // - If domain is set (ACME): SNI MUST be domain (server's sniGuard will reject other values)
    // - If no domain (self-signed): can use custom SNI for domain fronting
    const sni = node.domain ? node.domain : (node.sni || '');
    // hasCert: true if domain is set (ACME = valid cert)
    const hasCert = !!node.domain;
    const hopInterval = node.hopInterval || '';
    
    const obfs = node.obfs?.type || '';
    const obfsPassword = node.obfs?.password || '';

    if (node.portConfigs && node.portConfigs.length > 0) {
        node.portConfigs.filter(c => c.enabled).forEach(cfg => {
            configs.push({
                name: cfg.name || `Port ${cfg.port}`,
                host,
                port: cfg.port,
                portRange: cfg.portRange || '',
                hopInterval,
                sni,
                hasCert,
                obfs,
                obfsPassword,
            });
        });
    } else {
        configs.push({ name: 'TLS', host, port: node.port || 443, portRange: '', hopInterval, sni, hasCert, obfs, obfsPassword });
        // Port 80 removed (used for ACME)
        if (node.portRange) {
            configs.push({ name: 'Hopping', host, port: node.port || 443, portRange: node.portRange, hopInterval, sni, hasCert, obfs, obfsPassword });
        }
    }
    
    return configs;
}


// ==================== URI GENERATION ====================

function generateURI(user, node, config) {
    // Auth contains userId for server-side identification
    const auth = `${user.userId}:${user.password}`;
    const params = [];
    
    // SNI for TLS handshake (can be custom domain for masquerading)
    if (config.sni) params.push(`sni=${config.sni}`);
    params.push('alpn=h3');
    // insecure=1 only if no valid certificate (self-signed without domain)
    params.push(`insecure=${config.hasCert ? '0' : '1'}`);
    if (config.portRange) {
        params.push(`mport=${config.portRange}`);
        const hopSec = parseDurationSeconds(normalizeHopInterval(config.hopInterval));
        if (hopSec > 0) params.push(`mportHopInt=${hopSec}`);
    }
    if (config.obfs === 'salamander' && config.obfsPassword) {
        params.push('obfs=salamander');
        params.push(`obfs-password=${encodeURIComponent(config.obfsPassword)}`);
    }
    
    const name = `${node.flag || ''} ${node.name} ${config.name}`.trim();
    const uri = `hysteria2://${auth}@${config.host}:${config.port}?${params.join('&')}#${encodeURIComponent(name)}`;
    return uri;
}

/**
 * Build the list of inbound descriptors to advertise in the subscription.
 * The first entry is the main inbound (port = node.port, name = node label),
 * followed by every entry of `node.xray.extraInbounds` that has a port. Each
 * descriptor carries enough state to build a single VLESS URI / Clash proxy
 * / sing-box outbound / v2ray vnext.
 *
 * @param {Object} node - Node document with xray sub-object
 * @returns {Array<Object>} Inbound descriptors with `{port, nameSuffix, ...inboundFields}`
 */
function getXrayPublishedInbounds(node) {
    const xray = node.xray || {};
    const main = {
        port: node.port || 443,
        nameSuffix: '',
        transport: xray.transport,
        security: xray.security,
        flow: xray.flow,
        fingerprint: xray.fingerprint,
        alpn: xray.alpn,
        realityPublicKey: xray.realityPublicKey,
        realitySni: xray.realitySni,
        realityShortIds: xray.realityShortIds,
        realitySpiderX: xray.realitySpiderX,
        wsPath: xray.wsPath,
        wsHost: xray.wsHost,
        grpcServiceName: xray.grpcServiceName,
        xhttpPath: xray.xhttpPath,
        xhttpHost: xray.xhttpHost,
        xhttpMode: xray.xhttpMode,
    };

    const extras = (Array.isArray(xray.extraInbounds) ? xray.extraInbounds : [])
        .filter(i => i && i.port)
        .map(i => ({
            port: i.port,
            // Use a stable, human-readable suffix to disambiguate names inside
            // the client UI (clients keep server names unique). Prefer the
            // explicit label, fall back to "<transport>:<port>".
            nameSuffix: i.label && String(i.label).trim()
                ? String(i.label).trim()
                : `${i.transport || 'tcp'}:${i.port}`,
            transport: i.transport,
            security: i.security,
            flow: i.flow,
            fingerprint: i.fingerprint,
            alpn: i.alpn,
            realityPublicKey: i.realityPublicKey,
            realitySni: i.realitySni,
            realityShortIds: i.realityShortIds,
            realitySpiderX: i.realitySpiderX,
            wsPath: i.wsPath,
            wsHost: i.wsHost,
            grpcServiceName: i.grpcServiceName,
            xhttpPath: i.xhttpPath,
            xhttpHost: i.xhttpHost,
            xhttpMode: i.xhttpMode,
        }));

    return [main, ...extras];
}

/**
 * Build a server display name for a single inbound. Main inbound uses the
 * node label as-is; extras append the suffix in parentheses for clarity.
 */
function _xrayInboundName(node, inbound) {
    const base = `${node.flag || ''} ${node.name}`.trim();
    return inbound.nameSuffix ? `${base} (${inbound.nameSuffix})` : base;
}

/**
 * Generate a VLESS URI for one inbound of an Xray node.
 * vless://{uuid}@{host}:{port}?type={transport}&security={security}&...#{name}
 */
function generateVlessURIForInbound(user, node, inbound) {
    const uuid = user.xrayUuid;
    if (!uuid) return null;

    const host = node.domain || node.ip;
    const port = inbound.port || node.port || 443;
    const transport = inbound.transport || 'tcp';
    const security = inbound.security || 'reality';
    const fingerprint = inbound.fingerprint || 'chrome';

    const params = new URLSearchParams();
    // xhttp → splithttp in URI type parameter
    params.set('type', transport === 'xhttp' ? 'splithttp' : transport);
    params.set('security', security);

    if (security === 'reality') {
        if (inbound.flow && transport === 'tcp') params.set('flow', inbound.flow);
        if (inbound.realityPublicKey) params.set('pbk', inbound.realityPublicKey);
        const sni = inbound.realitySni && inbound.realitySni[0] ? inbound.realitySni[0] : '';
        if (sni) params.set('sni', sni);
        // Prefer non-empty shortId if available
        const shortIds = inbound.realityShortIds || [''];
        const sid = shortIds.find(id => id && id.length > 0) || shortIds[0] || '';
        params.set('sid', sid);
        if (inbound.realitySpiderX) params.set('spx', inbound.realitySpiderX);
        params.set('fp', fingerprint);
    } else if (security === 'tls') {
        if (inbound.flow && transport === 'tcp') params.set('flow', inbound.flow);
        const sni = node.domain || node.sni || '';
        if (sni) params.set('sni', sni);
        params.set('fp', fingerprint);
        if (inbound.alpn && inbound.alpn.length > 0) {
            params.set('alpn', inbound.alpn.join(','));
        }
    }

    if (transport === 'ws') {
        params.set('path', inbound.wsPath || '/');
        if (inbound.wsHost) params.set('host', inbound.wsHost);
    } else if (transport === 'grpc') {
        params.set('serviceName', inbound.grpcServiceName || 'grpc');
        params.set('mode', 'gun');
    } else if (transport === 'xhttp') {
        params.set('path', inbound.xhttpPath || '/');
        if (inbound.xhttpHost) params.set('host', inbound.xhttpHost);
        if (inbound.xhttpMode && inbound.xhttpMode !== 'auto') params.set('mode', inbound.xhttpMode);
    }

    const name = _xrayInboundName(node, inbound);
    return `vless://${uuid}@${host}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

/**
 * Generate VLESS URIs for every published inbound of an Xray node (main + extras).
 * Returns an array of strings (skip null results when uuid is missing).
 */
function generateVlessURIs(user, node) {
    const uuid = user.xrayUuid;
    if (!uuid) return [];
    return getXrayPublishedInbounds(node)
        .map(inbound => generateVlessURIForInbound(user, node, inbound))
        .filter(Boolean);
}

/**
 * Backward-compatible single-URI helper: returns the URI for the main inbound
 * only. Existing callers that show one URI per node (preview pages, single-node
 * helpers) keep working unchanged. New callers should use generateVlessURIs.
 */
function generateVlessURI(user, node) {
    const uris = generateVlessURIs(user, node);
    return uris.length > 0 ? uris[0] : null;
}

// ==================== ROUTING RULE CONVERTERS ====================

/**
 * Convert routing rules array from DB to Xray routing rules array.
 * Rules of the same action and field type are grouped for efficiency.
 */
function buildXrayRules(rules) {
    if (!rules || rules.length === 0) return [];

    const xrayRules = [];
    // Group consecutive rules of the same action into domain/ip buckets
    // to produce minimal rule objects (one object per action+fieldType pair)
    const domainRulesByAction = { direct: [], block: [] };
    const ipRulesByAction     = { direct: [], block: [] };
    // We process in order and flush when action changes
    const domainTypes = new Set(['domain_suffix', 'domain_keyword', 'domain', 'geosite']);
    const ipTypes     = new Set(['geoip', 'ip_cidr']);

    for (const r of rules) {
        if (!r.enabled) continue;
        const action = r.action === 'block' ? 'block' : 'direct';

        if (domainTypes.has(r.type)) {
            let xrayVal;
            if      (r.type === 'domain_suffix')  xrayVal = `domain:${r.value.replace(/^\./, '')}`;
            else if (r.type === 'domain_keyword')  xrayVal = `keyword:${r.value}`;
            else if (r.type === 'domain')          xrayVal = `full:${r.value}`;
            else                                   xrayVal = `geosite:${r.value}`;
            domainRulesByAction[action].push(xrayVal);
        } else if (ipTypes.has(r.type)) {
            let xrayVal = r.type === 'geoip' ? `geoip:${r.value}` : r.value;
            ipRulesByAction[action].push(xrayVal);
        }
    }

    for (const action of ['direct', 'block']) {
        if (domainRulesByAction[action].length > 0) {
            xrayRules.push({ type: 'field', domain: domainRulesByAction[action], outboundTag: action });
        }
        if (ipRulesByAction[action].length > 0) {
            xrayRules.push({ type: 'field', ip: ipRulesByAction[action], outboundTag: action });
        }
    }
    return xrayRules;
}

/**
 * Build Xray split-DNS servers array from routing rules + dns settings.
 * Domestic domains get routed to domestic DNS server.
 */
function buildXrayDns(rules, dns) {
    const domesticDns = (dns && dns.domestic) ? dns.domestic : '77.88.8.8';
    const remoteDns   = (dns && dns.remote)   ? dns.remote   : '1.1.1.1';

    const domesticDomains = [];
    for (const r of (rules || [])) {
        if (!r.enabled || r.action !== 'direct') continue;
        if (r.type === 'domain_suffix')  domesticDomains.push(`domain:${r.value.replace(/^\./, '')}`);
        else if (r.type === 'domain')    domesticDomains.push(`full:${r.value}`);
        else if (r.type === 'geosite')   domesticDomains.push(`geosite:${r.value}`);
    }

    const servers = [];
    if (domesticDomains.length > 0) {
        servers.push({ address: domesticDns, domains: domesticDomains });
    }
    servers.push(remoteDns);
    servers.push('8.8.8.8');
    return servers;
}

/**
 * Convert routing rules to sing-box 1.13+ route.rules entries.
 * geosite/geoip replaced with rule_set references (removed in sing-box 1.12).
 * Returns { rules: [], ruleSets: [] } so the caller can inject rule_set definitions.
 */
function buildSingboxRules(rules) {
    if (!rules || rules.length === 0) return { rules: [], ruleSets: [] };

    const buckets = {};
    const order   = [];
    const ruleSetTags = new Set();

    for (const r of rules) {
        if (!r.enabled) continue;
        const action = r.action === 'block' ? 'block' : 'direct';
        const key = `${action}:${r.type}`;

        if (!buckets[key]) {
            buckets[key] = { action, _type: r.type, values: [] };
            order.push(key);
        }
        buckets[key].values.push(r.value);
    }

    const resultRules = order.map(k => {
        const b = buckets[k];
        const rule = b.action === 'block'
            ? { action: 'reject' }
            : { action: 'route', outbound: 'direct' };

        switch (b._type) {
            case 'domain_suffix':  rule.domain_suffix  = b.values; break;
            case 'domain_keyword': rule.domain_keyword = b.values; break;
            case 'domain':         rule.domain         = b.values; break;
            case 'geosite':
                rule.rule_set = b.values.map(v => {
                    const tag = `geosite-${v}`;
                    ruleSetTags.add(tag);
                    return tag;
                });
                break;
            case 'geoip':
                rule.rule_set = b.values.map(v => {
                    const tag = `geoip-${v}`;
                    ruleSetTags.add(tag);
                    return tag;
                });
                break;
            case 'ip_cidr':        rule.ip_cidr        = b.values; break;
        }
        return rule;
    });

    const ruleSets = [...ruleSetTags].map(tag => {
        const isGeoip = tag.startsWith('geoip-');
        const repo = isGeoip ? 'sing-geoip' : 'sing-geosite';
        return {
            tag,
            type: 'remote',
            format: 'binary',
            url: `https://raw.githubusercontent.com/SagerNet/${repo}/rule-set/${tag}.srs`,
        };
    });

    return { rules: resultRules, ruleSets };
}

/**
 * Build sing-box 1.13+ DNS servers+rules for split DNS.
 * Uses typed server format and rule_set instead of deprecated geosite.
 * Returns { servers, rules, final, ruleSets }.
 */
function buildSingboxDns(rules, dns) {
    const domesticAddr = (dns && dns.domestic) ? dns.domestic : '77.88.8.8';
    const remoteAddr   = (dns && dns.remote)   ? dns.remote   : 'tls://1.1.1.1';
    const ruleSetTags = new Set();

    const remoteServer = _parseSingboxDnsServer(remoteAddr, 'dns-remote', 'dns-local');
    const servers = [
        remoteServer,
        { type: 'udp', tag: 'dns-direct', server: domesticAddr, detour: 'direct' },
        { type: 'udp', tag: 'dns-local',  server: domesticAddr, detour: 'direct' },
    ];

    const dnsRules = [];

    const suffixes = [], geositeTags = [];
    for (const r of (rules || [])) {
        if (!r.enabled || r.action !== 'direct') continue;
        if (r.type === 'domain_suffix') suffixes.push(r.value);
        if (r.type === 'geosite') {
            const tag = `geosite-${r.value}`;
            geositeTags.push(tag);
            ruleSetTags.add(tag);
        }
    }
    if (suffixes.length > 0) dnsRules.push({ domain_suffix: suffixes, server: 'dns-direct' });
    if (geositeTags.length > 0) dnsRules.push({ rule_set: geositeTags, server: 'dns-direct' });

    const ruleSets = [...ruleSetTags].map(tag => ({
        tag,
        type: 'remote',
        format: 'binary',
        url: `https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/${tag}.srs`,
    }));

    return { servers, rules: dnsRules, final: 'dns-remote', ruleSets };
}

/**
 * Parse a DNS address string into a sing-box 1.12+ typed server object.
 */
function _parseSingboxDnsServer(addr, tag, domainResolver) {
    if (addr.startsWith('tls://')) {
        const server = { type: 'tls', tag, server: addr.slice(6) };
        if (domainResolver) server.domain_resolver = domainResolver;
        return server;
    }
    if (addr.startsWith('https://')) {
        try {
            const url = new URL(addr);
            const server = { type: 'https', tag, server: url.hostname };
            if (domainResolver) server.domain_resolver = domainResolver;
            return server;
        } catch { /* fall through */ }
    }
    const server = { type: 'udp', tag, server: addr };
    if (domainResolver) server.domain_resolver = domainResolver;
    return server;
}

/**
 * Convert routing rules to Clash Meta rules array strings.
 */
function buildClashRules(rules) {
    if (!rules || rules.length === 0) return [];

    const result = [];
    for (const r of rules) {
        if (!r.enabled) continue;
        const target = r.action === 'block' ? 'REJECT' : 'DIRECT';
        switch (r.type) {
            case 'domain_suffix':  result.push(`DOMAIN-SUFFIX,${r.value},${target}`); break;
            case 'domain_keyword': result.push(`DOMAIN-KEYWORD,${r.value},${target}`); break;
            case 'domain':         result.push(`DOMAIN,${r.value},${target}`); break;
            case 'geosite':        result.push(`GEOSITE,${r.value},${target}`); break;
            case 'geoip':          result.push(`GEOIP,${r.value},${target},no-resolve`); break;
            case 'ip_cidr':        result.push(`IP-CIDR,${r.value},${target},no-resolve`); break;
        }
    }
    return result;
}

/**
 * Build HAPP-native routing profile JSON from DB rules.
 * HAPP uses its own routing format (DirectSites/DirectIp/BlockSites/BlockIp)
 * delivered via happ://routing/onadd/{base64} link.
 * See: https://www.happ.su/main/dev-docs/routing
 */
function buildHappRoutingProfile(routing) {
    if (!routing || !routing.enabled || !routing.rules || routing.rules.length === 0) return null;

    const domesticDns = (routing.dns && routing.dns.domestic) || '77.88.8.8';
    const remoteDns   = (routing.dns && routing.dns.remote)   || 'tls://1.1.1.1';

    const profile = {
        Name: 'Auto',
        GlobalProxy: 'true',
        DomainStrategy: 'IPIfNonMatch',
        FakeDNS: 'false',
        DirectSites: [],
        DirectIp: [
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
            '169.254.0.0/16', '224.0.0.0/4', '255.255.255.255',
        ],
        ProxySites: [],
        ProxyIp: [],
        BlockSites: [],
        BlockIp: [],
    };

    // Parse remote DNS (tls://IP → DoT, https://url → DoH, plain IP → DoU)
    if (remoteDns.startsWith('tls://')) {
        profile.RemoteDNSType = 'DoT';
        profile.RemoteDNSIP = remoteDns.slice(6);
        profile.RemoteDNSDomain = '';
    } else if (remoteDns.startsWith('https://')) {
        profile.RemoteDNSType = 'DoH';
        profile.RemoteDNSDomain = remoteDns;
        profile.RemoteDNSIP = '1.1.1.1';
        try {
            const hostname = new URL(remoteDns).hostname;
            profile.DnsHosts = { [hostname]: profile.RemoteDNSIP };
        } catch {}
    } else {
        profile.RemoteDNSType = 'DoU';
        profile.RemoteDNSIP = remoteDns;
        profile.RemoteDNSDomain = '';
    }

    // Domestic DNS (plain IP → DoU)
    profile.DomesticDNSType = 'DoU';
    profile.DomesticDNSIP = domesticDns;
    profile.DomesticDNSDomain = '';

    for (const r of routing.rules) {
        if (!r.enabled) continue;

        // Domain-type rules → DirectSites / BlockSites
        let siteVal = null;
        if      (r.type === 'geosite')        siteVal = `geosite:${r.value}`;
        else if (r.type === 'domain_suffix')   siteVal = `domain:${r.value.replace(/^\./, '')}`;
        else if (r.type === 'domain')          siteVal = `full:${r.value}`;
        else if (r.type === 'domain_keyword')  siteVal = `keyword:${r.value}`;

        // IP-type rules → DirectIp / BlockIp
        let ipVal = null;
        if      (r.type === 'geoip')   ipVal = `geoip:${r.value}`;
        else if (r.type === 'ip_cidr') ipVal = r.value;

        if (r.action === 'direct') {
            if (siteVal) profile.DirectSites.push(siteVal);
            if (ipVal)   profile.DirectIp.push(ipVal);
        } else if (r.action === 'block') {
            if (siteVal) profile.BlockSites.push(siteVal);
            if (ipVal)   profile.BlockIp.push(ipVal);
        }
    }

    return profile;
}

/**
 * Build Clash DNS section for split DNS.
 */
function buildClashDns(rules, dns) {
    const domestic = (dns && dns.domestic) ? dns.domestic : '77.88.8.8';
    const remote   = (dns && dns.remote)   ? dns.remote   : 'tls://1.1.1.1';

    const policy = {};
    for (const r of (rules || [])) {
        if (!r.enabled || r.action !== 'direct') continue;
        if (r.type === 'domain_suffix') policy[`+${r.value}`]    = domestic;
        if (r.type === 'geosite')       policy[`geosite:${r.value}`] = domestic;
    }

    return {
        enable: true,
        ipv6: false,
        'default-nameserver': [domestic],
        nameserver: [remote],
        'nameserver-policy': Object.keys(policy).length > 0 ? policy : undefined,
    };
}

// ==================== FORMAT GENERATORS ====================

function generateURIList(user, nodes) {
    const uris = [];
    nodes.forEach(node => {
        if (node.type === 'xray') {
            // One URI per published inbound (main + extras).
            generateVlessURIs(user, node).forEach(uri => uris.push(uri));
        } else {
            getNodeConfigs(node).forEach(cfg => {
                uris.push(generateURI(user, node, cfg));
            });
        }
    });
    return uris.join('\n');
}

function _buildClashVlessProxyForInbound(user, node, inbound) {
    const host = node.domain || node.ip;
    const transport = inbound.transport || 'tcp';
    const security = inbound.security || 'reality';
    const fingerprint = inbound.fingerprint || 'chrome';
    const name = _xrayInboundName(node, inbound);

    // Clash Meta doesn't support splithttp/xhttp - skip these inbounds
    if (transport === 'xhttp') {
        return { name, proxy: null };
    }

    let proxy = `  - name: "${name}"
    type: vless
    server: ${host}
    port: ${inbound.port || node.port || 443}
    uuid: "${user.xrayUuid}"
    udp: true`;

    if (security === 'reality') {
        const sni = inbound.realitySni && inbound.realitySni[0] ? inbound.realitySni[0] : host;
        proxy += `
    network: ${transport}
    tls: true
    reality-opts:
      public-key: "${inbound.realityPublicKey || ''}"
      short-id: "${(inbound.realityShortIds || ['']).find(id => id && id.length > 0) || ''}"
    servername: ${sni}
    client-fingerprint: ${fingerprint}`;
        if (transport === 'tcp' && inbound.flow) proxy += `\n    flow: ${inbound.flow}`;
    } else if (security === 'tls') {
        proxy += `
    network: ${transport}
    tls: true
    servername: ${node.domain || node.sni || host}
    client-fingerprint: ${fingerprint}`;
        if (inbound.alpn && inbound.alpn.length > 0) {
            proxy += `\n    alpn:\n${inbound.alpn.map(a => `      - ${a}`).join('\n')}`;
        }
        if (transport === 'tcp' && inbound.flow) proxy += `\n    flow: ${inbound.flow}`;
    } else {
        proxy += `\n    network: ${transport}`;
    }

    if (transport === 'ws') {
        proxy += `
    ws-opts:
      path: "${inbound.wsPath || '/'}"`;
        if (inbound.wsHost) proxy += `\n      headers:\n        Host: "${inbound.wsHost}"`;
    } else if (transport === 'grpc') {
        proxy += `
    grpc-opts:
      grpc-service-name: "${inbound.grpcServiceName || 'grpc'}"`;
    }

    return { name, proxy };
}

/**
 * Build Clash proxies for every published inbound of an Xray node.
 * Returns an array of `{name, proxy}` items; entries with `proxy === null`
 * (e.g. xhttp transport not supported by Clash) are filtered by the caller.
 */
function _buildClashVlessProxies(user, node) {
    return getXrayPublishedInbounds(node)
        .map(inbound => _buildClashVlessProxyForInbound(user, node, inbound));
}

function generateClashYAML(user, nodes, routing) {
    const auth = `${user.userId}:${user.password}`;
    const proxies = [];
    const proxyNames = [];
    
    nodes.forEach(node => {
        if (node.type === 'xray') {
            if (!user.xrayUuid) return;
            // One Clash entry per published inbound (main + extras).
            _buildClashVlessProxies(user, node).forEach(({ name, proxy }) => {
                if (!proxy) return; // xhttp not supported by Clash
                proxyNames.push(name);
                proxies.push(proxy);
            });
        } else {
            getNodeConfigs(node).forEach(cfg => {
                const name = `${node.flag || ''} ${node.name} ${cfg.name}`.trim();
                proxyNames.push(name);

                let proxy = `  - name: "${name}"
    type: hysteria2
    server: ${cfg.host}
    port: ${cfg.port}
    password: "${auth}"
    sni: ${cfg.sni || cfg.host}
    skip-cert-verify: ${!cfg.hasCert}
    alpn:
      - h3`;

                if (cfg.portRange) proxy += `\n    ports: ${cfg.portRange}`;
                const hopIntervalSec = parseDurationSeconds(normalizeHopInterval(cfg.hopInterval));
                if (hopIntervalSec > 0) proxy += `\n    hop-interval: ${hopIntervalSec}`;
                if (cfg.obfs === 'salamander' && cfg.obfsPassword) {
                    proxy += `\n    obfs: salamander\n    obfs-password: "${cfg.obfsPassword}"`;
                }
                proxies.push(proxy);
            });
        }
    });
    
    let yaml = `proxies:\n${proxies.join('\n')}\n\nproxy-groups:\n  - name: "Proxy"\n    type: select\n    proxies:\n${proxyNames.map(n => `      - "${n}"`).join('\n')}\n`;

    if (routing && routing.enabled && routing.rules && routing.rules.length > 0) {
        const clashDns = buildClashDns(routing.rules, routing.dns);
        const dnsLines = ['dns:', '  enable: true', '  ipv6: false'];
        dnsLines.push(`  default-nameserver:\n    - ${clashDns['default-nameserver'][0]}`);
        dnsLines.push(`  nameserver:\n    - ${clashDns.nameserver[0]}`);
        const policy = clashDns['nameserver-policy'];
        if (policy && Object.keys(policy).length > 0) {
            dnsLines.push('  nameserver-policy:');
            for (const [k, v] of Object.entries(policy)) {
                dnsLines.push(`    "${k}": "${v}"`);
            }
        }
        yaml += '\n' + dnsLines.join('\n') + '\n';

        const clashRules = buildClashRules(routing.rules);
        if (clashRules.length > 0) {
            yaml += '\nrules:\n';
            yaml += clashRules.map(r => `  - ${r}`).join('\n') + '\n';
            yaml += '  - MATCH,Proxy\n';
        }
    }

    return yaml;
}

function _buildSingboxVlessOutboundForInbound(user, node, inbound) {
    const host = node.domain || node.ip;
    const transport = inbound.transport || 'tcp';
    const security = inbound.security || 'reality';
    const fingerprint = inbound.fingerprint || 'chrome';
    const tag = _xrayInboundName(node, inbound);

    // Sing-box doesn't support splithttp/xhttp - skip these inbounds
    if (transport === 'xhttp') {
        return { tag, outbound: null };
    }

    const outbound = {
        type: 'vless',
        tag,
        server: host,
        server_port: inbound.port || node.port || 443,
        uuid: user.xrayUuid,
    };

    if (transport === 'tcp' && (security === 'reality' || security === 'tls')) {
        outbound.flow = inbound.flow || 'xtls-rprx-vision';
    }

    if (security === 'reality') {
        outbound.tls = {
            enabled: true,
            server_name: inbound.realitySni && inbound.realitySni[0] ? inbound.realitySni[0] : host,
            utls: { enabled: true, fingerprint },
            reality: {
                enabled: true,
                public_key: inbound.realityPublicKey || '',
                short_id: (inbound.realityShortIds || ['']).find(id => id && id.length > 0) || '',
            },
        };
    } else if (security === 'tls') {
        outbound.tls = {
            enabled: true,
            server_name: node.domain || node.sni || host,
            utls: { enabled: true, fingerprint },
        };
        if (inbound.alpn && inbound.alpn.length > 0) {
            outbound.tls.alpn = inbound.alpn;
        }
    }

    if (transport === 'ws') {
        outbound.transport = {
            type: 'ws',
            path: inbound.wsPath || '/',
            headers: inbound.wsHost ? { Host: inbound.wsHost } : {},
        };
    } else if (transport === 'grpc') {
        outbound.transport = {
            type: 'grpc',
            service_name: inbound.grpcServiceName || 'grpc',
        };
    }

    return { tag, outbound };
}

/**
 * Build sing-box outbounds for every published inbound of an Xray node.
 * Entries with `outbound === null` (xhttp) are skipped by the caller.
 */
function _buildSingboxVlessOutbounds(user, node) {
    return getXrayPublishedInbounds(node)
        .map(inbound => _buildSingboxVlessOutboundForInbound(user, node, inbound));
}

/**
 * Generate full Xray-compatible JSON config for HAPP and v2rayNG clients.
 * Includes VLESS and Hysteria2 outbounds (if Xray-core supports it), routing rules and split DNS.
 */
function generateV2rayJSON(user, nodes, routing) {
    const auth = `${user.userId}:${user.password}`;
    const outbounds = [];
    const allTags = [];

    // Build proxy outbounds
    nodes.forEach(node => {
        if (node.type === 'xray') {
            if (!user.xrayUuid) return;
            const host = node.domain || node.ip;
            // One v2ray outbound per published inbound (main + extras).
            getXrayPublishedInbounds(node).forEach(inbound => {
                const transport = inbound.transport || 'tcp';
                const security = inbound.security || 'reality';
                const tag = _xrayInboundName(node, inbound);

                const streamSettings = { network: transport === 'xhttp' ? 'splithttp' : transport };

                if (security === 'reality') {
                    const sni = inbound.realitySni && inbound.realitySni[0] ? inbound.realitySni[0] : '';
                    const shortIds = inbound.realityShortIds || [''];
                    const sid = shortIds.find(id => id && id.length > 0) || shortIds[0] || '';
                    streamSettings.security = 'reality';
                    streamSettings.realitySettings = {
                        fingerprint: inbound.fingerprint || 'chrome',
                        serverName: sni,
                        publicKey: inbound.realityPublicKey || '',
                        shortId: sid,
                        spiderX: inbound.realitySpiderX || '',
                    };
                } else if (security === 'tls') {
                    streamSettings.security = 'tls';
                    streamSettings.tlsSettings = {
                        serverName: node.domain || node.sni || host,
                        fingerprint: inbound.fingerprint || 'chrome',
                    };
                    if (inbound.alpn && inbound.alpn.length > 0) {
                        streamSettings.tlsSettings.alpn = inbound.alpn;
                    }
                }

                if (transport === 'ws') {
                    streamSettings.wsSettings = { path: inbound.wsPath || '/', headers: inbound.wsHost ? { Host: inbound.wsHost } : {} };
                } else if (transport === 'grpc') {
                    streamSettings.grpcSettings = { serviceName: inbound.grpcServiceName || 'grpc', multiMode: false };
                } else if (transport === 'xhttp') {
                    streamSettings.splithttpSettings = { path: inbound.xhttpPath || '/', host: inbound.xhttpHost || '' };
                }

                const vnextUser = { id: user.xrayUuid, encryption: 'none' };
                if (transport === 'tcp' && (security === 'reality' || security === 'tls') && inbound.flow) {
                    vnextUser.flow = inbound.flow;
                }

                outbounds.push({
                    tag,
                    protocol: 'vless',
                    settings: { vnext: [{ address: host, port: inbound.port || node.port || 443, users: [vnextUser] }] },
                    streamSettings,
                });
                allTags.push(tag);
            });
        } else {
            getNodeConfigs(node).forEach(cfg => {
                const tag = `${node.flag || ''} ${node.name} ${cfg.name}`.trim();
                const hysteriaSettings = { version: 2, auth };
                if (cfg.portRange) {
                    hysteriaSettings.udphop = { port: cfg.portRange };
                    const hopSec = parseDurationSeconds(normalizeHopInterval(cfg.hopInterval));
                    if (hopSec > 0) hysteriaSettings.udphop.interval = hopSec;
                }

                const streamSettings = {
                    network: 'hysteria',
                    hysteriaSettings,
                    security: 'tls',
                    tlsSettings: {
                        serverName: cfg.sni || cfg.host,
                        allowInsecure: !cfg.hasCert,
                        alpn: ['h3'],
                    },
                };

                if (cfg.obfs === 'salamander' && cfg.obfsPassword) {
                    streamSettings.udpmasks = [{ type: 'salamander', settings: { password: cfg.obfsPassword } }];
                }

                outbounds.push({
                    tag,
                    protocol: 'hysteria',
                    settings: { version: 2, address: cfg.host, port: cfg.port },
                    streamSettings,
                });
                allTags.push(tag);
            });
        }
    });

    outbounds.push({ tag: 'direct', protocol: 'freedom',   settings: {} });
    outbounds.push({ tag: 'block',  protocol: 'blackhole',  settings: { response: { type: 'http' } } });

    // Routing rules
    const routingRules = [
        { type: 'field', port: '53', outboundTag: 'direct' },
    ];

    if (routing && routing.enabled && routing.rules && routing.rules.length > 0) {
        routingRules.push(...buildXrayRules(routing.rules));
    }

    // Final rule: all remaining traffic through first proxy
    // (This is implicit in Xray when we set the routing config tag for balancer/urltest — use first tag as default)
    const dnsServers = (routing && routing.enabled && routing.rules)
        ? buildXrayDns(routing.rules, routing.dns)
        : ['1.1.1.1', '8.8.8.8'];

    return {
        log: { loglevel: 'warning' },
        dns: { servers: dnsServers },
        inbounds: [
            {
                tag: 'socks-in',
                port: 10808,
                protocol: 'socks',
                settings: { auth: 'noauth', udp: true },
                sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
            },
            {
                tag: 'http-in',
                port: 10809,
                protocol: 'http',
                settings: {},
                sniffing: { enabled: true, destOverride: ['http', 'tls'] },
            },
        ],
        outbounds,
        routing: {
            domainStrategy: 'IPIfNonMatch',
            rules: routingRules,
        },
    };
}

function generateSingboxJSON(user, nodes, routing) {
    const auth = `${user.userId}:${user.password}`;
    const proxyOutbounds = [];
    const tags = [];
    
    nodes.forEach(node => {
        if (node.type === 'xray') {
            if (!user.xrayUuid) return;
            // One sing-box outbound per published inbound (main + extras).
            _buildSingboxVlessOutbounds(user, node).forEach(({ tag, outbound }) => {
                if (!outbound) return; // xhttp not supported by sing-box
                tags.push(tag);
                proxyOutbounds.push(outbound);
            });
        } else {
            getNodeConfigs(node).forEach(cfg => {
                const tag = `${node.flag || ''} ${node.name} ${cfg.name}`.trim();
                tags.push(tag);

                const outbound = {
                    type: 'hysteria2',
                    tag,
                    server: cfg.host,
                    password: auth,
                    tls: {
                        enabled: true,
                        server_name: cfg.sni || cfg.host,
                        insecure: !cfg.hasCert,
                        alpn: ['h3'],
                    },
                };

                if (cfg.portRange) {
                    outbound.server_ports = [cfg.portRange.replace('-', ':')];
                } else {
                    outbound.server_port = cfg.port;
                }

                const hopInterval = normalizeHopInterval(cfg.hopInterval);
                if (hopInterval) {
                    outbound.hop_interval = hopInterval;
                }

                if (cfg.obfs === 'salamander' && cfg.obfsPassword) {
                    outbound.obfs = { type: 'salamander', password: cfg.obfsPassword };
                }

                proxyOutbounds.push(outbound);
            });
        }
    });
    
    const outbounds = [
        { type: 'selector', tag: 'proxy', outbounds: tags.length > 0 ? [...tags, 'direct'] : ['direct'], default: tags[0] || 'direct' },
        { type: 'urltest', tag: 'auto', outbounds: tags, url: 'https://www.gstatic.com/generate_204', interval: '3m', tolerance: 50 },
        ...proxyOutbounds,
        { type: 'direct', tag: 'direct' },
    ];

    const allRuleSets = [];
    const hasRouting = routing && routing.enabled && routing.rules && routing.rules.length > 0;

    // Build sing-box DNS section (split DNS when routing enabled)
    let dnsSection;
    if (hasRouting) {
        const dnsResult = buildSingboxDns(routing.rules, routing.dns);
        dnsSection = { servers: dnsResult.servers, rules: dnsResult.rules, final: dnsResult.final };
        allRuleSets.push(...dnsResult.ruleSets);
    } else {
        dnsSection = {
            servers: [
                { type: 'tls', tag: 'dns-remote', server: '8.8.8.8', domain_resolver: 'dns-local' },
                { type: 'udp', tag: 'dns-local', server: '223.5.5.5', detour: 'direct' },
            ],
            rules: [],
            final: 'dns-remote',
        };
    }

    // Build route.rules using 1.13+ action format
    const routeRules = [
        { protocol: 'dns', action: 'hijack-dns' },
        { inbound: 'tun-in', action: 'sniff' },
        { ip_is_private: true, action: 'route', outbound: 'direct' },
    ];
    if (hasRouting) {
        const routeResult = buildSingboxRules(routing.rules);
        routeRules.push(...routeResult.rules);
        allRuleSets.push(...routeResult.ruleSets);
    }

    // Deduplicate rule_set definitions by tag
    const uniqueRuleSets = [...new Map(allRuleSets.map(rs => [rs.tag, rs])).values()];

    const config = {
        log: { level: 'warn', timestamp: true },
        dns: dnsSection,
        inbounds: [
            {
                type: 'tun',
                tag: 'tun-in',
                address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
                mtu: 9000,
                auto_route: true,
                strict_route: true,
                stack: 'system',
            },
        ],
        outbounds,
        route: {
            rules: routeRules,
            final: 'proxy',
            auto_detect_interface: true,
        },
    };

    if (uniqueRuleSets.length > 0) {
        config.route.rule_set = uniqueRuleSets;
        config.experimental = { cache_file: { enabled: true } };
    }

    return config;
}

// ==================== HTML PAGE ====================

async function generateHTML(user, nodes, token, baseUrl, settings) {
    // Collect all configs
    const allConfigs = [];
    nodes.forEach(node => {
        if (node.type === 'xray') {
            // Render one card per published inbound (main + extras).
            const inbounds = getXrayPublishedInbounds(node);
            inbounds.forEach(inbound => {
                const uri = generateVlessURIForInbound(user, node, inbound);
                if (uri) {
                    allConfigs.push({
                        location: inbound.nameSuffix
                            ? `${node.name} (${inbound.nameSuffix})`
                            : node.name,
                        flag: node.flag || '🌐',
                        name: 'VLESS',
                        uri,
                    });
                }
            });
        } else {
            getNodeConfigs(node).forEach(cfg => {
                allConfigs.push({
                    location: node.name,
                    flag: node.flag || '🌐',
                    name: cfg.name,
                    uri: generateURI(user, node, cfg),
                });
            });
        }
    });
    
    const trafficUsed = ((user.traffic?.tx || 0) + (user.traffic?.rx || 0)) / (1024 * 1024 * 1024);
    const trafficLimit = user.trafficLimit ? user.trafficLimit / (1024 * 1024 * 1024) : 0;
    const expireDate = user.expireAt ? new Date(user.expireAt).toLocaleDateString('ru-RU') : 'Бессрочно';
    
    // Group by location preserving node sort order (Map keeps insertion order for all key types)
    const locations = new Map();
    allConfigs.forEach(cfg => {
        if (!locations.has(cfg.location)) {
            locations.set(cfg.location, { flag: cfg.flag, configs: [] });
        }
        locations.get(cfg.location).configs.push({ name: cfg.name, uri: cfg.uri });
    });

    // Customization from settings
    const sub = settings?.subscription || {};
    const logoUrl   = sub.logoUrl   || '';
    const pageTitle = sub.pageTitle || 'Подключение';

    const logoHtml = logoUrl
        ? `<img src="${logoUrl}" style="height:48px; border-radius:10px; object-fit:contain;" onerror="this.style.display='none'">`
        : '<i class="ti ti-rocket"></i>';

    // QR code for subscription link (cached)
    let qrDataUrl = await cache.getQR(baseUrl);
    if (!qrDataUrl) {
        try {
            qrDataUrl = await QRCode.toDataURL(baseUrl, { width: 180, margin: 1, color: { dark: '#ffffff', light: '#141414' } });
            await cache.setQR(baseUrl, qrDataUrl);
        } catch (e) {
            logger.warn(`[Sub] QR generation failed: ${e.message}`);
        }
    }

    const qrSectionHtml = qrDataUrl
        ? `<div class="section" style="text-align:center;">
            <h2 style="justify-content:center;"><i class="ti ti-qrcode"></i> QR-КОД</h2>
            <div style="display:inline-block; background:#141414; padding:12px; border-radius:12px; margin-bottom:8px;">
                <img src="${qrDataUrl}" alt="QR" style="width:160px; height:160px; border-radius:8px; display:block;">
            </div>
            <div style="font-size:12px; color:var(--muted);">Отсканируйте для импорта подписки в приложение</div>
           </div>`
        : '';

    function escAttr(s) {
        return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function resolveButtonUrl(rawUrl, subUrl) {
        if (!rawUrl) return null;
        const b64 = Buffer.from(subUrl).toString('base64');
        const resolved = rawUrl
            .replace(/\{url_encoded\}/g, encodeURIComponent(subUrl))
            .replace(/\{url_b64\}/g, b64)
            .replace(/\{url\}/g, subUrl);
        if (/^javascript:/i.test(resolved)) return null;
        return resolved;
    }

    const buttons = (sub.buttons || []).filter(b => b.label && b.url);
    const buttonsHtml = buttons.length > 0
        ? `<div class="section" style="padding:12px;">
            <div class="btn-grid">
                ${buttons.map(b => {
                    const href = resolveButtonUrl(b.url, baseUrl);
                    if (!href) return '';
                    const iconClass = (b.icon || '').trim().replace(/[^a-zA-Z0-9-]/g, '') || 'ti-external-link';
                    const safeLabel = escAttr(b.label);
                    return `<a href="${escAttr(href)}" target="_blank" rel="noopener noreferrer" class="app-btn">
                        <i class="ti ${iconClass}" style="font-size:18px; color:var(--accent); flex-shrink:0;"></i>
                        <span>${safeLabel}</span>
                    </a>`;
                }).filter(Boolean).join('')}
            </div>
           </div>`
        : '';

    return `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${pageTitle}</title>
    <style>
        :root { --bg: #0a0a0a; --card: #141414; --border: #252525; --text: #fff; --muted: #888; --accent: #3b82f6; --success: #22c55e; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; padding: 16px; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { text-align: center; padding: 32px 16px; background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); border-radius: 16px; margin-bottom: 16px; }
        .header h1 { font-size: 24px; margin-bottom: 4px; }
        .header p { color: var(--muted); font-size: 14px; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 16px; }
        .stat { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 12px; text-align: center; }
        .stat-value { font-size: 18px; font-weight: 600; color: var(--accent); }
        .stat-label { font-size: 11px; color: var(--muted); margin-top: 2px; }
        .section { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-bottom: 12px; }
        .section h2 { font-size: 14px; margin-bottom: 12px; color: var(--muted); }
        .location { border: 1px solid var(--border); border-radius: 10px; margin-bottom: 8px; overflow: hidden; }
        .location-header { display: flex; align-items: center; gap: 10px; padding: 12px; cursor: pointer; background: var(--bg); }
        .location-header:hover { background: #1a1a1a; }
        .location-flag { font-size: 24px; }
        .location-name { flex: 1; font-weight: 500; }
        .location-arrow { color: var(--muted); transition: transform 0.2s; display: inline-flex; }
        .location.open .location-arrow { transform: rotate(180deg); }
        .location-configs { display: none; border-top: 1px solid var(--border); }
        .location.open .location-configs { display: block; }
        .config { display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; border-bottom: 1px solid var(--border); }
        .config:last-child { border-bottom: none; }
        .config-name { font-size: 13px; }
        .copy-btn { padding: 6px 12px; background: var(--accent); border: none; border-radius: 6px; color: #fff; font-size: 12px; cursor: pointer; }
        .copy-btn:active { transform: scale(0.95); }
        .copy-btn.success { background: var(--success); }
        .sub-box { display: flex; gap: 8px; }
        .sub-box input { flex: 1; padding: 10px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 12px; min-width: 0; }
        .toast { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%) translateY(100px); background: var(--success); color: #fff; padding: 10px 20px; border-radius: 8px; font-size: 14px; transition: transform 0.3s; display: flex; align-items: center; gap: 8px; }
        .toast.show { transform: translateX(-50%) translateY(0); }
        .header h1 { display: flex; align-items: center; justify-content: center; gap: 8px; }
        .section h2 { display: flex; align-items: center; gap: 8px; }
        .copy-btn { display: inline-flex; align-items: center; gap: 6px; }
        .btn-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
        .app-btn { display: flex; align-items: center; gap: 10px; padding: 12px 14px; background: var(--bg); border: 1px solid var(--border); border-radius: 10px; color: var(--text); text-decoration: none; font-size: 14px; transition: background 0.15s, border-color 0.15s; }
        .app-btn:hover { background: #1a1a1a; border-color: var(--accent); }
        @media (max-width: 360px) { .btn-grid { grid-template-columns: 1fr; } }
    </style>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>${logoHtml} ${pageTitle}</h1>
            <p>Ваша персональная конфигурация</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value">${trafficUsed.toFixed(1)} ГБ</div>
                <div class="stat-label">Использовано${trafficLimit > 0 ? ` / ${trafficLimit.toFixed(0)} ГБ` : ''}</div>
            </div>
            <div class="stat">
                <div class="stat-value">${locations.size}</div>
                <div class="stat-label">Локаций</div>
            </div>
            <div class="stat">
                <div class="stat-value">${expireDate}</div>
                <div class="stat-label">Действует до</div>
            </div>
        </div>
        
        <div class="section">
            <h2><i class="ti ti-link"></i> ССЫЛКА ДЛЯ ПРИЛОЖЕНИЙ</h2>
            <div class="sub-box">
                <input type="text" value="${baseUrl}" readonly id="subUrl">
                <button class="copy-btn" onclick="copyText('${baseUrl}', this)">Копировать</button>
            </div>
        </div>
        
        <div class="section">
            <h2><i class="ti ti-world"></i> ЛОКАЦИИ</h2>
            ${[...locations.entries()].map(([name, loc], locIdx) => `
            <div class="location">
                <div class="location-header" onclick="this.parentElement.classList.toggle('open')">
                    <span class="location-flag">${loc.flag}</span>
                    <span class="location-name">${name}</span>
                    <span class="location-arrow"><i class="ti ti-chevron-down"></i></span>
                </div>
                <div class="location-configs">
                    ${loc.configs.map((cfg, i) => `
                    <div class="config">
                        <span class="config-name">${cfg.name}</span>
                        <button class="copy-btn" onclick="copyUri(this)">Копировать</button>
                    </div>
                    `).join('')}
                </div>
            </div>
            `).join('')}
        </div>

        ${qrSectionHtml}
        ${buttonsHtml}
    </div>
    
    <div class="toast" id="toast"><i class="ti ti-check"></i> Скопировано</div>
    
    <script>
        // All URIs for copying
        const uris = ${JSON.stringify(allConfigs.map(c => c.uri))};
        
        function copyText(text, btn) {
            doCopy(text, btn);
        }
        
        function copyUri(btn) {
            const allBtns = document.querySelectorAll('.location-configs .copy-btn');
            let idx = 0;
            for (let i = 0; i < allBtns.length; i++) {
                if (allBtns[i] === btn) {
                    idx = i;
                    break;
                }
            }
            doCopy(uris[idx], btn);
        }
        
        function doCopy(text, btn) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(() => success(btn)).catch(() => fallback(text, btn));
            } else {
                fallback(text, btn);
            }
        }
        
        function fallback(text, btn) {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.cssText = 'position:fixed;left:-9999px';
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); success(btn); } catch(e) {}
            document.body.removeChild(ta);
        }
        
        function success(btn) {
            const orig = btn.textContent;
            btn.innerHTML = '<i class="ti ti-check"></i>';
            btn.classList.add('success');
            document.getElementById('toast').classList.add('show');
            setTimeout(() => {
                btn.textContent = orig;
                btn.classList.remove('success');
                document.getElementById('toast').classList.remove('show');
            }, 1500);
        }
    </script>
</body>
</html>`;
}

// ==================== MAIN ROUTE ====================

/**
 * GET /files/:token - Single route
 * - Browser → HTML
 * - App → subscription
 * 
 * With Redis caching for generated subscriptions
 */
router.get('/files/:token', async (req, res) => {
    try {
        const token = req.params.token;
        const userAgent = req.headers['user-agent'] || 'unknown';
        
        // Detect format
        let format = req.query.format;
        const browser = isBrowser(req);
        
        // Browser without format param — don't cache (serve fresh HTML)
        if (browser && !format) {
            // HTML page — not cached, show fresh data
            const [user, settings] = await Promise.all([
                getUserByToken(token),
                getSettings(),
            ]);
            
            if (!user) {
                logger.warn(`[Sub] User not found for token: ${token}`);
                return res.status(404).type('text/plain').send('# User not found');
            }
            
            const validation = validateUser(user);
            if (!validation.valid) {
                logger.warn(`[Sub] User ${user.userId} invalid: ${validation.error}`);
                return res.status(403).type('text/plain').send(`# ${validation.error}`);
            }
            
            const nodes = await getActiveNodes(user);
            if (nodes.length === 0) {
                return res.status(503).type('text/plain').send('# No servers available');
            }
            
            const baseUrl = `${req.protocol}://${req.get('host')}/api/files/${token}`;
            const html = await generateHTML(user, nodes, token, baseUrl, settings);
            return res.type('text/html').send(html);
        }
        
        // For apps — detect format and cache
        if (!format) {
            format = detectFormat(userAgent);
            logger.debug(`[Sub] UA: "${userAgent}" → format: ${format}`);
        }
        uaStats.track(token, userAgent);
        
        // Read settings (from Redis cache — fast)
        const settings = await getSettings();

        // Check cache
        const cached = await cache.getSubscription(token, format);
        if (cached) {
            logger.debug(`[Sub] Cache HIT: ${token}:${format}`);
            return sendCachedSubscription(res, cached, format, userAgent, settings);
        }
        
        // Cache miss — generate
        logger.debug(`[Sub] Cache MISS: token=${token.substring(0,8)}..., format=${format}`);
        
        const user = await getUserByToken(token);
        
        if (!user) {
            logger.warn(`[Sub] User not found for token: ${token}`);
            return res.status(404).type('text/plain').send('# User not found');
        }
        
        const validation = validateUser(user);
        
        if (!validation.valid) {
            logger.warn(`[Sub] User ${user.userId} invalid: ${validation.error}`);
            return res.status(403).type('text/plain').send(`# ${validation.error}`);
        }
        
        const nodes = await getActiveNodes(user);
        if (nodes.length === 0) {
            logger.error(`[Sub] NO SERVERS for user ${user.userId}! Check nodes in panel.`);
            return res.status(503).type('text/plain').send('# No servers available');
        }
        
        logger.debug(`[Sub] Serving ${nodes.length} nodes to user ${user.userId}`);
        
        // Generate subscription
        const subscriptionData = generateSubscriptionData(user, nodes, format, userAgent, settings?.subscription?.happProviderId || '', settings?.routing);
        
        // Save to cache
        await cache.setSubscription(token, format, subscriptionData);
        
        // Send response
        return sendCachedSubscription(res, subscriptionData, format, userAgent, settings);
        
    } catch (error) {
        logger.error(`[Sub] Error: ${error.message}`);
        res.status(500).type('text/plain').send('# Error');
    }
});

/**
 * Generate subscription data for caching
 */
function generateSubscriptionData(user, nodes, format, userAgent, happProviderId = '', routing = null) {
    let content;
    let needsBase64 = false;
    
    switch (format) {
        case 'shadowrocket':
            content = generateURIList(user, nodes);
            needsBase64 = true;
            break;
        case 'clash':
        case 'yaml':
            content = generateClashYAML(user, nodes, routing);
            break;
        case 'singbox':
        case 'json':
            content = JSON.stringify(generateSingboxJSON(user, nodes, routing), null, 2);
            break;
        case 'v2ray-json':
            content = JSON.stringify(generateV2rayJSON(user, nodes, routing), null, 2);
            break;
        case 'uri':
        case 'raw':
        default:
            content = generateURIList(user, nodes);
            // HAPP reads #providerid from body as fallback (in case headers are stripped by a proxy)
            if (happProviderId) {
                content = `#providerid ${happProviderId}\n${content}`;
            }
            if (/quantumult/i.test(userAgent)) {
                needsBase64 = true;
            }
            break;
    }
    
    if (needsBase64) {
        content = Buffer.from(content).toString('base64');
    }
    
    return {
        content,
        profileTitle: getSubscriptionTitle(user),
        username: user.username || user.userId,
        traffic: {
            tx: user.traffic?.tx || 0,
            rx: user.traffic?.rx || 0,
        },
        trafficLimit: user.trafficLimit || 0,
        expireAt: user.expireAt,
    };
}

/**
 * Send cached subscription response
 */
function sendCachedSubscription(res, data, format, userAgent, settings) {
    let contentType = 'text/plain';
    
    switch (format) {
        case 'clash':
        case 'yaml':
            contentType = 'text/yaml';
            break;
        case 'singbox':
        case 'json':
        case 'v2ray-json':
            contentType = 'application/json';
            break;
    }
    
    const headers = {
        'Content-Type': `${contentType}; charset=utf-8`,
        'Content-Disposition': `attachment; filename="${data.username}"`,
        'Profile-Title': encodeTitle(data.profileTitle),
        'Profile-Update-Interval': String(settings?.subscription?.updateInterval || 12),
        'Subscription-Userinfo': [
            `upload=${data.traffic.tx}`,
            `download=${data.traffic.rx}`,
            data.trafficLimit > 0 ? `total=${data.trafficLimit}` : null,
            `expire=${data.expireAt ? Math.floor(new Date(data.expireAt).getTime() / 1000) : 0}`,
        ].filter(Boolean).join('; '),
    };

    const sub = settings?.subscription;
    if (sub?.supportUrl)     headers['support-url']          = sub.supportUrl;
    if (sub?.webPageUrl)     headers['profile-web-page-url'] = sub.webPageUrl;
    if (sub?.happProviderId) headers['providerid']            = sub.happProviderId;

    let content = data.content;

    // HAPP: deliver routing rules and advanced settings via HTTP headers
    if (/happ/i.test(userAgent)) {
        if (settings?.routing?.enabled) {
            const profile = buildHappRoutingProfile(settings.routing);
            if (profile) {
                const b64 = Buffer.from(JSON.stringify(profile)).toString('base64');
                const routingLink = `happ://routing/onadd/${b64}`;
                headers['routing'] = routingLink;
                if (format === 'uri' || format === 'raw') {
                    content = `${routingLink}\n${content}`;
                }
            }
        } else {
            headers['routing'] = 'happ://routing/off';
            if (format === 'uri' || format === 'raw') {
                content = `happ://routing/off\n${content}`;
            }
        }

        const happ = settings?.subscription?.happ;
        if (happ) {
            if (happ.announce) {
                const hasNonAscii = /[^\x20-\x7E]/.test(happ.announce);
                headers['announce'] = hasNonAscii
                    ? 'base64:' + Buffer.from(happ.announce).toString('base64')
                    : happ.announce;
            }
            if (sub?.happProviderId) {
                if (happ.hideSettings)  headers['hide-settings']                  = '1';
                if (happ.notifyExpire)  headers['notification-subs-expire']       = '1';
                if (happ.alwaysHwid)    headers['subscription-always-hwid-enable'] = '1';
                if (happ.pingType) {
                    headers['ping-type'] = happ.pingType;
                    if ((happ.pingType === 'proxy' || happ.pingType === 'proxy-head') && happ.pingUrl) {
                        headers['check-url-via-proxy'] = happ.pingUrl;
                    }
                }
                if (happ.colorProfile)  headers['color-profile'] = happ.colorProfile;
            }
        }
    }

    res.set(headers);
    res.send(content);
}

// ==================== INFO ====================

router.get('/info/:token', async (req, res) => {
    try {
        const user = await getUserByToken(req.params.token);
        if (!user) return res.status(404).json({ error: 'Not found' });
        
        const nodes = await getActiveNodes(user);
        
        res.json({
            enabled: user.enabled,
            groups: user.groups,
            traffic: { used: (user.traffic?.tx || 0) + (user.traffic?.rx || 0), limit: user.trafficLimit },
            expire: user.expireAt,
            servers: nodes.length,
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
