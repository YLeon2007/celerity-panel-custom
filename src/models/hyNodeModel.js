/**
 * Hysteria + Xray node model with cascade topology support
 */

const mongoose = require('mongoose');

const portConfigSchema = new mongoose.Schema({
    name: { type: String, default: '' },
    port: { type: Number, required: true },
    portRange: { type: String, default: '' },
    enabled: { type: Boolean, default: true },
}, { _id: false });

const outboundSchema = new mongoose.Schema({
    name: { type: String, required: true },
    type: { type: String, enum: ['direct', 'socks5', 'http'], required: true },
    addr: { type: String, default: '' },
    username: { type: String, default: '' },
    password: { type: String, default: '' },
    insecure: { type: Boolean, default: false },
    direct: {
        mode: { type: String, default: '' },
        bindIPv4: { type: String, default: '' },
        bindIPv6: { type: String, default: '' },
        bindDevice: { type: String, default: '' },
        fastOpen: { type: Boolean, default: false },
    },
}, { _id: false });

const acmeOptionsSchema = new mongoose.Schema({
    email: { type: String, default: '' },
    ca: { type: String, default: 'letsencrypt' },
    listenHost: { type: String, default: '0.0.0.0' },
    type: { type: String, enum: ['', 'http', 'tls', 'dns'], default: '' },
    httpAltPort: { type: Number, default: 0 },
    tlsAltPort: { type: Number, default: 0 },
    dnsName: { type: String, default: '' },
    dnsConfig: { type: Object, default: {} },
}, { _id: false });

const masqueradeSchema = new mongoose.Schema({
    type: { type: String, enum: ['proxy', 'string'], default: 'proxy' },
    proxy: {
        url: { type: String, default: 'https://www.google.com' },
        rewriteHost: { type: Boolean, default: true },
        insecure: { type: Boolean, default: false },
    },
    string: {
        content: { type: String, default: 'Service Unavailable' },
        headers: { type: Object, default: { 'content-type': 'text/plain' } },
        statusCode: { type: Number, default: 503 },
    },
    listenHTTP: { type: String, default: '' },
    listenHTTPS: { type: String, default: '' },
    forceHTTPS: { type: Boolean, default: false },
}, { _id: false });

const bandwidthSchema = new mongoose.Schema({
    up: { type: String, default: '' },
    down: { type: String, default: '' },
}, { _id: false });

const resolverSchema = new mongoose.Schema({
    enabled: { type: Boolean, default: false },
    type: { type: String, enum: ['udp', 'tcp', 'tls', 'https'], default: 'udp' },
    udpAddr: { type: String, default: '8.8.4.4:53' },
    udpTimeout: { type: String, default: '4s' },
    tcpAddr: { type: String, default: '8.8.8.8:53' },
    tcpTimeout: { type: String, default: '4s' },
    tlsAddr: { type: String, default: '1.1.1.1:853' },
    tlsTimeout: { type: String, default: '10s' },
    tlsSni: { type: String, default: 'cloudflare-dns.com' },
    tlsInsecure: { type: Boolean, default: false },
    httpsAddr: { type: String, default: '1.1.1.1:443' },
    httpsTimeout: { type: String, default: '10s' },
    httpsSni: { type: String, default: 'cloudflare-dns.com' },
    httpsInsecure: { type: Boolean, default: false },
}, { _id: false });

const aclSettingsSchema = new mongoose.Schema({
    enabled: { type: Boolean, default: true },
    type: { type: String, enum: ['inline', 'file'], default: 'inline' },
    file: { type: String, default: '' },
    geoip: { type: String, default: '' },
    geosite: { type: String, default: '' },
    geoUpdateInterval: { type: String, default: '' },
}, { _id: false });

const sniffSchema = new mongoose.Schema({
    enabled: { type: Boolean, default: false },
    enable: { type: Boolean, default: true },
    timeout: { type: String, default: '2s' },
    rewriteDomain: { type: Boolean, default: false },
    tcpPorts: { type: String, default: '80,443,8000-9000' },
    udpPorts: { type: String, default: '443,80,53' },
}, { _id: false });

const quicSchema = new mongoose.Schema({
    enabled: { type: Boolean, default: false },
    initStreamReceiveWindow: { type: Number, default: 8388608 },
    maxStreamReceiveWindow: { type: Number, default: 8388608 },
    initConnReceiveWindow: { type: Number, default: 20971520 },
    maxConnReceiveWindow: { type: Number, default: 20971520 },
    maxIdleTimeout: { type: String, default: '60s' },
    maxIncomingStreams: { type: Number, default: 256 },
    disablePathMTUDiscovery: { type: Boolean, default: false },
}, { _id: false });

// Per-inbound stream/security settings shared by the main inbound and extras.
// Extras add `id`, `label`, `port` and reuse their own `inboundTag` instead of
// the node-level fields.
const xrayExtraInboundSchema = new mongoose.Schema({
    // Stable client-generated id (uuid) used to track edits across form submits
    id: { type: String, required: true },
    label: { type: String, default: '' },
    // When true, the subscription server name is just the label (issue #74)
    // instead of "<node name> (<label>)".
    uniqueName: { type: Boolean, default: false },
    port: { type: Number, required: true },
    inboundTag: { type: String, required: true },

    transport: { type: String, enum: ['tcp', 'ws', 'grpc', 'xhttp'], default: 'tcp' },
    security: { type: String, enum: ['reality', 'tls', 'none'], default: 'reality' },
    flow: { type: String, default: 'xtls-rprx-vision' },

    fingerprint: { type: String, default: 'chrome' },
    alpn: { type: [String], default: [] },

    realityDest: { type: String, default: 'www.google.com:443' },
    realitySni: { type: [String], default: ['www.google.com'] },
    realityPrivateKey: { type: String, default: '' },
    realityPublicKey: { type: String, default: '' },
    realityShortIds: { type: [String], default: [''] },
    realitySpiderX: { type: String, default: '/' },

    wsPath: { type: String, default: '/' },
    wsHost: { type: String, default: '' },

    grpcServiceName: { type: String, default: 'grpc' },

    xhttpPath: { type: String, default: '/' },
    xhttpHost: { type: String, default: '' },
    xhttpMode: { type: String, enum: ['auto', 'packet-up', 'stream-up', 'stream-one'], default: 'auto' },
}, { _id: false });

const xrayConfigSchema = new mongoose.Schema({
    // Transport: tcp, ws, grpc, xhttp (splithttp)
    transport: { type: String, enum: ['tcp', 'ws', 'grpc', 'xhttp'], default: 'tcp' },
    // Security: reality (no cert needed), tls (cert files), none
    security: { type: String, enum: ['reality', 'tls', 'none'], default: 'reality' },
    // XTLS flow — only for tcp+reality/tls
    flow: { type: String, default: 'xtls-rprx-vision' },

    // TLS Fingerprint (uTLS) — chrome, firefox, safari, ios, android, edge, random, randomized
    fingerprint: { type: String, default: 'chrome' },
    // ALPN — comma-separated or array: h3, h2, http/1.1
    alpn: { type: [String], default: [] },

    // Reality-specific
    realityDest: { type: String, default: 'www.google.com:443' },
    realitySni: { type: [String], default: ['www.google.com'] },
    realityPrivateKey: { type: String, default: '' },
    realityPublicKey: { type: String, default: '' },
    realityShortIds: { type: [String], default: [''] },
    realitySpiderX: { type: String, default: '/' },

    // WebSocket-specific
    wsPath: { type: String, default: '/' },
    wsHost: { type: String, default: '' },

    // gRPC-specific
    grpcServiceName: { type: String, default: 'grpc' },

    // xhttp (splithttp) specific
    xhttpPath: { type: String, default: '/' },
    xhttpHost: { type: String, default: '' },
    xhttpMode: { type: String, enum: ['auto', 'packet-up', 'stream-up', 'stream-one'], default: 'auto' },

    // TLS certificate provisioning strategy (only relevant when security==='tls'):
    //   panel       — masquerade under PANEL_DOMAIN; LE cert read from panel disk
    //                 (Caddy/Greenlock) and inlined into the node's config.json.
    //                 Requires no cert files on the remote node.
    //   manual      — operator pastes a custom domain (node.domain) plus full PEM
    //                 cert + private key in the form; PEM is inlined into config.json.
    //   self-signed — nodeSetup generates a self-signed cert on the node; client
    //                 must connect with allowInsecure=true (testing only).
    tlsSource: { type: String, enum: ['panel', 'manual', 'self-signed'], default: 'panel' },
    // Public PEM (full chain) for tlsSource==='manual'. Stored as-is; safe to return.
    manualCert: { type: String, default: '' },
    // Private key PEM for tlsSource==='manual'. select:false → never returned by
    // .find()/.findOne() unless explicitly selected. API responses must use a
    // ***SET*** placeholder when surfacing the field to the form (see routes).
    manualKey: { type: String, default: '', select: false },

    // gRPC API port for user management (local, not exposed)
    apiPort: { type: Number, default: 61000 },

    // Inbound tag used in config and API calls
    inboundTag: { type: String, default: 'vless-in' },

    // CC Agent settings
    agentPort: { type: Number, default: 62080 },
    agentToken: { type: String, default: '' },
    agentTls: { type: Boolean, default: true },

    // Additional VLESS inbounds running alongside the main one with their own
    // ports and transports (Reality TCP + WS+TLS + gRPC, etc). Optional, the
    // main inbound is still defined by the flat fields above.
    extraInbounds: { type: [xrayExtraInboundSchema], default: [] },
}, { _id: false });

const hyNodeSchema = new mongoose.Schema({
    // 'hysteria' (default) or 'xray'
    type: { type: String, enum: ['hysteria', 'xray'], default: 'hysteria' },

    name: { type: String, required: true },
    flag: { type: String, default: '' },
    ip: { type: String, required: true },
    domain: { type: String, default: '' },
    sni: { type: String, default: '' },
    port: { type: Number, default: 443 },
    portRange: { type: String, default: '20000-50000' },
    hopInterval: { type: String, default: '' },
    portConfigs: { type: [portConfigSchema], default: [] },
    obfs: {
        type: { type: String, enum: ['', 'salamander'], default: '' },
        password: { type: String, default: '' },
    },
    acme: { type: acmeOptionsSchema, default: () => ({}) },
    masquerade: { type: masqueradeSchema, default: () => ({}) },
    bandwidth: { type: bandwidthSchema, default: () => ({}) },
    ignoreClientBandwidth: { type: Boolean, default: false },
    speedTest: { type: Boolean, default: false },
    disableUDP: { type: Boolean, default: false },
    udpIdleTimeout: { type: String, default: '' },
    sniff: { type: sniffSchema, default: () => ({}) },
    quic: { type: quicSchema, default: () => ({}) },
    resolver: { type: resolverSchema, default: () => ({}) },
    acl: { type: aclSettingsSchema, default: () => ({}) },
    statsPort: { type: Number, default: 9999 },
    statsSecret: { type: String, default: '' },

    // Xray-specific configuration (only used when type === 'xray')
    xray: { type: xrayConfigSchema, default: () => ({}) },
    
    groups: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'ServerGroup',
    }],
    
    ssh: {
        port: { type: Number, default: 22 },
        username: { type: String, default: 'root' },
        privateKey: { type: String, default: '' },
        password: { type: String, default: '' },
    },
    
    paths: {
        config: { type: String, default: '/etc/hysteria/config.yaml' },
        cert: { type: String, default: '/etc/hysteria/cert.pem' },
        key: { type: String, default: '/etc/hysteria/key.pem' },
    },
    
    outbounds: { type: [outboundSchema], default: [] },
    aclRules: { type: [String], default: [] },
    
    active: { type: Boolean, default: true },
    status: { type: String, enum: ['online', 'offline', 'error', 'syncing'], default: 'offline' },
    lastError: { type: String, default: '' },
    lastSync: { type: Date, default: null },

    // Agent & Xray version info (populated by health checks)
    xrayVersion: { type: String, default: '' },
    agentVersion: { type: String, default: '' },
    agentStatus: { type: String, enum: ['online', 'offline', 'unknown'], default: 'unknown' },
    agentLastSeen: { type: Date, default: null },
    onlineUsers: { type: Number, default: 0 },
    maxOnlineUsers: { type: Number, default: 0 },
    healthFailures: { type: Number, default: 0 },
    
    traffic: {
        tx: { type: Number, default: 0 },
        rx: { type: Number, default: 0 },
        lastUpdate: { type: Date, default: null },
    },
    
    rankingCoefficient: { type: Number, default: 1.0 },
    settings: { type: Object, default: {} },
    customConfig: { type: String, default: '' },
    useCustomConfig: { type: Boolean, default: false },
    useTlsFiles: { type: Boolean, default: false },
    initScript: { type: String, default: '' },

    // Cascade topology fields
    cascadeRole: {
        type: String,
        enum: ['standalone', 'portal', 'relay', 'bridge'],
        default: 'standalone',
    },
    mapPosition: {
        x: { type: Number, default: null },
        y: { type: Number, default: null },
    },
    country: { type: String, default: '' },

}, { timestamps: true });

// One IP may host at most one node per protocol type
hyNodeSchema.index({ ip: 1, type: 1 }, { unique: true });
hyNodeSchema.index({ active: 1 });
hyNodeSchema.index({ groups: 1 });
hyNodeSchema.index({ status: 1 });

hyNodeSchema.virtual('serverAddress').get(function() {
    const host = this.domain || this.ip;
    return `${host}:${this.portRange}`;
});

hyNodeSchema.methods.getSubscriptionAddress = function() {
    const host = this.domain || this.ip;
    if (this.portRange && this.portRange.includes('-')) {
        return `${host}:${this.portRange}`;
    }
    return `${host}:${this.port}`;
};

module.exports = mongoose.model('HyNode', hyNodeSchema);
