'use strict';

process.env.PANEL_DOMAIN = process.env.PANEL_DOMAIN || 'panel.example.com';
process.env.ACME_EMAIL = process.env.ACME_EMAIL || 'admin@example.com';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '0123456789abcdef0123456789abcdef';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret-0123456789abcdef';

const assert = require('assert');
const fs = require('fs');
const YAML = require('yaml');
const packageJson = require('../package.json');
const configGenerator = require('../src/services/configGenerator');
const helpers = require('../src/routes/panel/helpers');
const subscription = require('../src/routes/subscription')._test;
const syncService = require('../src/services/syncService');
const {
    buildXrayDotUpdates,
    validateXrayCreateNode,
    validateResultingXrayUpdate,
    validatedXrayUpdateOptions,
    XRAY_VALIDATION_SELECT,
} = require('../src/utils/xrayUpdates');
const HyNode = require('../src/models/hyNodeModel');
const nodeSetup = require('../src/services/nodeSetup');
const { safeUser } = require('../src/mcp/tools/users')._test;
const { NODE_SAFE_SELECT } = require('../src/mcp/tools/nodes')._test;

assert(NODE_SAFE_SELECT.includes('-xray.extraInbounds.realityPrivateKey'));
assert.strictEqual(typeof XRAY_VALIDATION_SELECT, 'string', 'update validation must expose one shared projection');
assert(XRAY_VALIDATION_SELECT.includes('+xray.manualKey'));
assert(XRAY_VALIDATION_SELECT.includes('+xray.hysteria.obfsPassword'));
assert(!XRAY_VALIDATION_SELECT.split(/\s+/).includes('xray'),
    'MongoDB forbids selecting parent xray together with included secret descendants');
const projectionProbe = HyNode.findById('64b000000000000000000001').select(XRAY_VALIDATION_SELECT);
assert.strictEqual(projectionProbe.selectedInclusively(), false,
    '+path overrides must preserve the default full-document projection');
assert.deepStrictEqual(projectionProbe._fieldsForExec(), {
    '+xray.manualKey': 1,
    '+xray.hysteria.obfsPassword': 1,
});
for (const sourcePath of ['src/routes/nodes.js', 'src/mcp/tools/nodes.js']) {
    const source = fs.readFileSync(sourcePath, 'utf8');
    assert(source.includes('.select(XRAY_VALIDATION_SELECT)'), `${sourcePath} must use the shared projection`);
    assert(!source.includes("xray +xray.manualKey +xray.hysteria.obfsPassword"),
        `${sourcePath} must not reintroduce the MongoDB parent/child projection collision`);
}

assert.strictEqual(packageJson.version, '1.3.4.0dev');
assert.strictEqual(nodeSetup.parseInstalledAgentVersion('cc-agent 1.5.0'), '1.5.0');
assert.strictEqual(nodeSetup.parseInstalledAgentVersion('cc-agent v1.5.1'), '1.5.1');
assert.strictEqual(nodeSetup.parseInstalledAgentVersion('installed'), '');

const sanitizedMcpUser = safeUser({
    userId: 'safe-user', username: 'Safe', password: 'legacy-password',
    subscriptionToken: 'subscription-secret', xrayUuid: '11111111-2222-4333-8444-555555555555',
    enabled: true,
});
assert.strictEqual(sanitizedMcpUser.password, undefined);
assert.strictEqual(sanitizedMcpUser.subscriptionToken, undefined);
assert.strictEqual(sanitizedMcpUser.xrayUuid, undefined);
assert.strictEqual(sanitizedMcpUser.userId, 'safe-user');

const redactedNode = new HyNode({
    name: 'secret-test', type: 'xray', ip: '127.0.0.1', statsSecret: 'stats-secret',
    ssh: { password: 'encrypted-password', privateKey: 'encrypted-private-key' },
    xray: {
        realityPrivateKey: 'private-reality-key', manualKey: 'manual-pem-key', agentToken: 'agent-secret',
        extraInbounds: [{
            id: 'extra-secret-test', inboundTag: 'extra-in', port: 10443,
            transport: 'tcp', security: 'reality', realityPrivateKey: 'extra-private-reality-key',
        }],
        hysteria: { enabled: true, obfsPassword: 'native-hy-secret' },
        accessLogs: { ingestTokenEncrypted: 'encrypted-ingest', ingestTokenHash: 'hashed-ingest' },
    },
}).toJSON();
const redactedNodeObject = new HyNode({
    name: 'secret-object-test', type: 'xray', ip: '127.0.0.2', statsSecret: 'stats-secret',
    ssh: { password: 'encrypted-password', privateKey: 'encrypted-private-key' },
    xray: {
        realityPrivateKey: 'private-reality-key', manualKey: 'manual-pem-key', agentToken: 'agent-secret',
        extraInbounds: [{
            id: 'extra-object-secret', inboundTag: 'extra-object-in', port: 11443,
            transport: 'tcp', security: 'reality', realityPrivateKey: 'extra-private-reality-key',
        }],
        hysteria: { enabled: true, obfsPassword: 'native-hy-secret' },
        accessLogs: { ingestTokenEncrypted: 'encrypted-ingest', ingestTokenHash: 'hashed-ingest' },
    },
}).toObject();
assert.strictEqual(redactedNodeObject.statsSecret, undefined, 'toObject REST responses must redact node secrets');
assert.strictEqual(redactedNodeObject.xray.realityPrivateKey, undefined);
assert.strictEqual(redactedNodeObject.xray.extraInbounds[0].realityPrivateKey, undefined);
assert.strictEqual(redactedNodeObject.xray.agentToken, undefined);
assert.strictEqual(redactedNodeObject.xray.hysteria.obfsPassword, undefined);
assert.strictEqual(redactedNodeObject.xray.accessLogs.ingestTokenHash, undefined);
assert.strictEqual(redactedNode.statsSecret, undefined);
assert.strictEqual(redactedNode.ssh.password, undefined);
assert.strictEqual(redactedNode.ssh.privateKey, undefined);
assert.strictEqual(redactedNode.xray.realityPrivateKey, undefined);
assert.strictEqual(redactedNode.xray.extraInbounds[0].realityPrivateKey, undefined);
assert.strictEqual(redactedNode.xray.manualKey, undefined);
assert.strictEqual(redactedNode.xray.agentToken, undefined);
assert.strictEqual(redactedNode.xray.hysteria.obfsPassword, undefined);
assert.strictEqual(redactedNode.xray.accessLogs.ingestTokenEncrypted, undefined);
assert.strictEqual(redactedNode.xray.accessLogs.ingestTokenHash, undefined);

assert.deepStrictEqual(buildXrayDotUpdates({
    security: 'reality',
    hysteria: { enabled: true, port: 24443, obfsPassword: '' },
}), {
    'xray.security': 'reality',
    'xray.hysteria.enabled': true,
    'xray.hysteria.port': 24443,
}, 'partial REST/MCP updates must not erase the write-only Hysteria PSK');
assert.deepStrictEqual(buildXrayDotUpdates({
    hysteria: {
        masquerade: { url: 'https://updated.example/path' },
    },
}), {
    'xray.hysteria.masquerade.url': 'https://updated.example/path',
}, 'partial masquerade updates must preserve omitted nested fields');

assert.strictEqual(syncService.xrayVersionAtLeast('26.3.27'), true);
assert.strictEqual(syncService.xrayVersionAtLeast('Xray 26.7.11'), true);
assert.strictEqual(syncService.xrayVersionAtLeast('26.3.26'), false);
assert.strictEqual(syncService.xrayVersionAtLeast('25.12.31'), false);
assert.strictEqual(syncService.agentVersionAtLeast('1.5.0'), true);
assert.strictEqual(syncService.agentVersionAtLeast('cc-agent 1.5.1'), true);
assert.strictEqual(syncService.agentVersionAtLeast('1.4.0'), false);
assert.strictEqual(syncService.agentVersionAtLeast('installed'), false);
assert.strictEqual(syncService.agentVersionAtLeast(''), false);

const user = {
    userId: 'native-hy-user',
    password: 'legacy-password',
    xrayUuid: '11111111-2222-4333-8444-555555555555',
};

function baseNode(enabled) {
    return {
        _id: 'native-hy-node',
        type: 'xray',
        active: true,
        status: 'online',
        name: 'Test Xray',
        flag: '🧪',
        ip: '203.0.113.20',
        port: 9443,
        cascadeRole: 'standalone',
        xray: {
            transport: 'tcp',
            security: 'reality',
            flow: 'xtls-rprx-vision',
            inboundTag: 'vless-in',
            apiPort: 61000,
            tlsSource: 'self-signed',
            realityDest: 'www.google.com:443',
            realitySni: ['www.google.com'],
            realityPrivateKey: 'private-key-for-structure-test',
            realityPublicKey: 'public-key-for-subscription-test',
            realityShortIds: ['', '0123456789abcdef'],
            extraInbounds: [],
            hysteria: {
                enabled,
                port: 24443,
                inboundTag: 'hysteria-in',
                obfs: 'salamander',
                obfsPassword: 'native-hy-secret',
                udpIdleTimeout: 60,
                masquerade: {
                    type: 'string',
                    content: 'Not Found',
                    statusCode: 404,
                },
            },
        },
        outbounds: [],
        aclRules: [],
    };
}

const disabled = JSON.parse(configGenerator.generateXrayConfig(baseNode(false), [user]));
assert.strictEqual(disabled.inbounds.some(i => i.protocol === 'hysteria'), false,
    'native Hysteria must be opt-in and absent from existing node configs');

const node = baseNode(true);
const generated = JSON.parse(configGenerator.generateXrayConfig(node, [user]));
const hy = generated.inbounds.find(i => i.tag === 'hysteria-in');
assert(hy, 'enabled native Hysteria inbound must be generated');
assert.strictEqual(hy.protocol, 'hysteria');
assert.strictEqual(hy.port, 24443);
assert.deepStrictEqual(hy.settings.clients, [{ auth: user.xrayUuid, email: user.userId, level: 0 }]);
assert.strictEqual(hy.settings.users, undefined, 'Xray Hysteria server schema uses settings.clients');
assert.strictEqual(hy.streamSettings.network, 'hysteria');
assert.strictEqual(hy.streamSettings.security, 'tls');
assert.deepStrictEqual(hy.streamSettings.tlsSettings.alpn, ['h3']);
assert.strictEqual(hy.streamSettings.tlsSettings.certificates[0].certificateFile, '/usr/local/etc/xray/cert.pem');
assert.strictEqual(hy.streamSettings.hysteriaSettings.version, 2);
assert.strictEqual(hy.streamSettings.hysteriaSettings.udpIdleTimeout, 60);
assert.strictEqual(hy.streamSettings.hysteriaSettings.masquerade.statusCode, 404);
assert.strictEqual(hy.streamSettings.finalmask.udp[0].type, 'salamander');
assert.strictEqual(hy.streamSettings.finalmask.udp[0].settings.password, 'native-hy-secret');
assert(generated.inbounds.some(i => i.tag === 'vless-in' && i.protocol === 'vless'),
    'VLESS must coexist with native Hysteria in the same Xray config');

const missingPskNode = baseNode(true);
missingPskNode.xray.hysteria.obfsPassword = '';
assert.throws(
    () => configGenerator.generateXrayConfig(missingPskNode, [user]),
    err => err.code === 'NATIVE_HYSTERIA_SECRET_UNAVAILABLE',
    'Salamander must fail closed when its stored PSK was not loaded'
);

const parsed = helpers.parseXrayFormFields({
    'xray.transport': 'tcp',
    'xray.security': 'reality',
    'xray.inboundTag': 'vless-in',
    'xray.hysteria.enabled': 'on',
    'xray.hysteria.port': '24443',
    'xray.hysteria.inboundTag': 'hysteria-in',
    'xray.hysteria.obfs': 'salamander',
    'xray.hysteria.obfsPassword': 'native-hy-secret',
    'xray.hysteria.udpIdleTimeout': '60',
    'xray.hysteria.masquerade.type': 'string',
    'xray.hysteria.masquerade.content': 'Not Found',
    'xray.hysteria.masquerade.statusCode': '404',
});
assert.strictEqual(parsed.hysteria.enabled, true);
assert.strictEqual(parsed.hysteria.port, 24443);
assert.strictEqual(helpers.validateXrayFormFields(parsed, { port: 9443 }), null);
const badSecret = JSON.parse(JSON.stringify(parsed));
badSecret.hysteria.obfsPassword = 'short';
assert.match(helpers.validateXrayFormFields(badSecret, { port: 9443 }), /at least 8/);

const sanitized = helpers.sanitizeXrayForRender({
    manualKey: '',
    hysteria: { enabled: true, obfs: 'salamander', obfsPassword: 'native-hy-secret' },
});
assert.strictEqual(sanitized.hysteria.obfsPassword, '***SET***', 'PSK must not reach rendered HTML');
assert.strictEqual(sanitized.hysteria.obfsPasswordSet, true);
const resolvedSecret = helpers.resolveManualKeyPlaceholder({
    hysteria: { enabled: true, obfs: 'salamander', obfsPassword: '***SET***' },
}, {
    hysteria: { obfsPassword: 'native-hy-secret' },
});
assert.strictEqual(resolvedSecret.hysteria.obfsPassword, 'native-hy-secret', 'placeholder must preserve stored PSK');

const uriList = subscription.generateURIList(user, [node]);
const uriLines = uriList.split('\n');
assert(uriLines.some(line => line.startsWith('vless://')), 'URI list must preserve VLESS');
const hyUri = uriLines.find(line => line.startsWith('hysteria2://'));
assert(hyUri, 'URI list must add native Hysteria');
assert(hyUri.includes(encodeURIComponent(user.xrayUuid)), 'Hysteria URI auth must be the Xray UUID');
assert(hyUri.includes('sni=203.0.113.20'), 'self-signed test profile must publish node IP as SNI');
assert(hyUri.includes('insecure=1'));
assert(hyUri.includes('obfs=salamander'));

const clash = subscription.generateClashYAML(user, [node]);
const parsedBaseClash = YAML.parse(clash);
assert(parsedBaseClash.proxies.some(proxy => proxy.type === 'vless'));
const baseHyProxy = parsedBaseClash.proxies.find(proxy => proxy.type === 'hysteria2');
assert(baseHyProxy);
assert.strictEqual(baseHyProxy.password, user.xrayUuid);
assert.strictEqual(baseHyProxy.obfs, 'salamander');
assert.strictEqual(baseHyProxy['obfs-password'], 'native-hy-secret');
const yamlNode = JSON.parse(JSON.stringify(node));
yamlNode.name = 'Quoted "node"\n- injected';
yamlNode.xray.hysteria.obfsPassword = 'mask"secret\nproxy-groups: injected';
const parsedClash = YAML.parse(subscription.generateClashYAML(user, [yamlNode]));
const parsedHyProxy = parsedClash.proxies.find(proxy => proxy.type === 'hysteria2');
assert(parsedHyProxy, 'Clash YAML must remain parseable with operator-controlled strings');
assert.strictEqual(parsedHyProxy.name, `🧪 ${yamlNode.name} (Hysteria 2)`);
assert.strictEqual(parsedHyProxy['obfs-password'], yamlNode.xray.hysteria.obfsPassword);
assert.strictEqual(parsedClash['proxy-groups'].length, 1, 'YAML strings must not inject additional groups');

// The whole Clash document must be object-serialized. Exercise every
// operator-controlled VLESS scalar called out by independent security review.
const hostile = suffix => `quoted:"${suffix}\nproxy-groups: injected-${suffix}`;
const hostileXrayNode = baseNode(false);
hostileXrayNode.name = hostile('node-name');
hostileXrayNode.domain = hostile('server');
hostileXrayNode.xray.transport = 'tcp';
hostileXrayNode.xray.realityPublicKey = hostile('public-key');
hostileXrayNode.xray.realityShortIds = [hostile('short-id')];
hostileXrayNode.xray.realitySni = [hostile('sni')];
hostileXrayNode.xray.fingerprint = hostile('fingerprint');
hostileXrayNode.xray.flow = hostile('flow');
hostileXrayNode.xray.extraInbounds = [
    {
        id: 'hostile-ws', label: hostile('ws-label'), inboundTag: 'ws-in', port: 10443,
        transport: 'ws', security: 'tls', wsPath: hostile('ws-path'), wsHost: hostile('ws-host'),
        fingerprint: hostile('ws-fingerprint'), alpn: [hostile('alpn')],
    },
    {
        id: 'hostile-grpc', label: hostile('grpc-label'), inboundTag: 'grpc-in', port: 11443,
        transport: 'grpc', security: 'none', grpcServiceName: hostile('grpc-service'),
    },
    {
        id: 'hostile-xhttp', label: hostile('xhttp-label'), inboundTag: 'xhttp-in', port: 12443,
        transport: 'xhttp', security: 'none', xhttpPath: hostile('xhttp-path'),
        xhttpMode: hostile('xhttp-mode'), xhttpHost: hostile('xhttp-host'),
    },
];
const hostileLegacyNode = {
    _id: 'hostile-legacy', type: 'hysteria', active: true, name: hostile('legacy-name'), flag: '⚠️',
    domain: hostile('legacy-server'), ip: '198.51.100.4', sni: hostile('legacy-sni'), port: 24444,
    portRange: '', hopInterval: '',
    obfs: { type: hostile('legacy-obfs'), password: hostile('legacy-psk') },
    portConfigs: [{ name: hostile('legacy-config-name'), port: 24444, enabled: true }],
};
const hostileLegacyNoDomain = {
    ...hostileLegacyNode,
    _id: 'hostile-legacy-no-domain',
    name: hostile('legacy-no-domain-name'),
    domain: '',
    ip: hostile('legacy-ip-server'),
    sni: hostile('legacy-separate-sni'),
    port: 24445,
    portConfigs: [{ name: hostile('legacy-no-domain-config'), port: 24445, enabled: true }],
};
const hostileVirtual = {
    _id: 'hostile-virtual', type: 'virtual', name: hostile('virtual-name'), flag: '⚖️',
    _resolvedSources: [{ _id: hostileXrayNode._id }],
    virtual: {
        strategy: 'leastPing',
        observatory: { destination: hostile('virtual-url'), interval: '1m' },
    },
};
const hostileUser = {
    ...user,
    userId: hostile('user-id'),
    password: hostile('user-password'),
    xrayUuid: hostile('uuid'),
};
const hostileDocument = YAML.parse(subscription.generateClashYAML(
    hostileUser,
    [hostileXrayNode, hostileLegacyNode, hostileLegacyNoDomain, hostileVirtual]
));
assert.strictEqual(hostileDocument['proxy-groups'].length, 2);
const hostileVless = hostileDocument.proxies.find(p => p.type === 'vless' && p.network === 'tcp');
assert.strictEqual(hostileVless.name, `🧪 ${hostileXrayNode.name}`);
assert.strictEqual(hostileVless.server, hostileXrayNode.domain);
assert.strictEqual(hostileVless.uuid, hostileUser.xrayUuid);
assert.strictEqual(hostileVless['reality-opts']['public-key'], hostileXrayNode.xray.realityPublicKey);
assert.strictEqual(hostileVless['reality-opts']['short-id'], hostileXrayNode.xray.realityShortIds[0]);
assert.strictEqual(hostileVless.servername, hostileXrayNode.xray.realitySni[0]);
assert.strictEqual(hostileVless['client-fingerprint'], hostileXrayNode.xray.fingerprint);
assert.strictEqual(hostileVless.flow, hostileXrayNode.xray.flow);
const hostileWs = hostileDocument.proxies.find(p => p['ws-opts']);
assert.strictEqual(hostileWs['ws-opts'].path, hostileXrayNode.xray.extraInbounds[0].wsPath);
assert.strictEqual(hostileWs['ws-opts'].headers.Host, hostileXrayNode.xray.extraInbounds[0].wsHost);
assert.deepStrictEqual(hostileWs.alpn, hostileXrayNode.xray.extraInbounds[0].alpn);
const hostileGrpc = hostileDocument.proxies.find(p => p['grpc-opts']);
assert.strictEqual(hostileGrpc['grpc-opts']['grpc-service-name'], hostileXrayNode.xray.extraInbounds[1].grpcServiceName);
const hostileXhttp = hostileDocument.proxies.find(p => p['xhttp-opts']);
assert.strictEqual(hostileXhttp['xhttp-opts'].path, hostileXrayNode.xray.extraInbounds[2].xhttpPath);
assert.strictEqual(hostileXhttp['xhttp-opts'].mode, hostileXrayNode.xray.extraInbounds[2].xhttpMode);
assert.strictEqual(hostileXhttp['xhttp-opts'].host, hostileXrayNode.xray.extraInbounds[2].xhttpHost);
const hostileLegacy = hostileDocument.proxies.find(p => p.server === hostileLegacyNode.domain);
assert.strictEqual(hostileLegacy.sni, hostileLegacyNode.domain);
assert.strictEqual(hostileLegacy.password, `${hostileUser.userId}:${hostileUser.password}`);
assert.strictEqual(hostileLegacy.obfs, hostileLegacyNode.obfs.type);
assert.strictEqual(hostileLegacy['obfs-password'], hostileLegacyNode.obfs.password);
const hostileLegacySeparateSni = hostileDocument.proxies.find(p => p.server === hostileLegacyNoDomain.ip);
assert.strictEqual(hostileLegacySeparateSni.server, hostileLegacyNoDomain.ip);
assert.strictEqual(hostileLegacySeparateSni.sni, hostileLegacyNoDomain.sni);
const hostileVirtualGroup = hostileDocument['proxy-groups'].find(g => g.type === 'url-test');
assert.strictEqual(hostileVirtualGroup.name, `⚖️ ${hostileVirtual.name}`);
assert.strictEqual(hostileVirtualGroup.url, hostileVirtual.virtual.observatory.destination);
assert.strictEqual(hostileDocument['proxy-groups'].filter(g => g.name === 'Proxy').length, 1);

const singbox = subscription.generateSingboxJSON(user, [node]);
const singHy = singbox.outbounds.find(o => o.type === 'hysteria2');
assert(singHy, 'sing-box must contain native Hysteria outbound');
assert.strictEqual(singHy.password, user.xrayUuid);
assert.strictEqual(singHy.server_port, 24443);
assert.deepStrictEqual(singHy.obfs, { type: 'salamander', password: 'native-hy-secret' });

const v2ray = subscription.generateV2rayJSON(user, [node]);
const xrayHy = v2ray.outbounds.find(o => o.protocol === 'hysteria');
assert(xrayHy, 'Xray JSON must contain native Hysteria outbound');
assert.strictEqual(xrayHy.settings.address, node.ip);
assert.strictEqual(xrayHy.settings.port, 24443);
assert.strictEqual(xrayHy.streamSettings.hysteriaSettings.auth, user.xrayUuid);

const happProfiles = subscription.generateXrayJSON(user, [node]);
assert(happProfiles.some(p => p.outbounds.some(o => o.protocol === 'vless')),
    'HAPP profiles must preserve VLESS');
assert(happProfiles.some(p => p.outbounds.some(o => o.protocol === 'hysteria')),
    'HAPP profiles must add native Hysteria');

async function runRestartContractTests() {
    assert.deepStrictEqual(validatedXrayUpdateOptions(), {
        new: true, runValidators: true, context: 'query',
    });
    assert.strictEqual(typeof validateXrayCreateNode, 'function',
        'REST/MCP create paths must share a pre-save cross-field validator');
    const createNode = hyPort => new HyNode({
        name: 'create-validation', type: 'xray', ip: '203.0.113.55', port: 9443,
        xray: {
            apiPort: 61000, agentPort: 62080, inboundTag: 'vless-in',
            extraInbounds: [{
                id: 'create-extra', inboundTag: 'extra-in', port: 10443,
                transport: 'tcp', security: 'reality',
            }],
            hysteria: {
                enabled: true, port: hyPort, inboundTag: 'hysteria-in',
                obfs: '', udpIdleTimeout: 60,
                masquerade: { type: 'string', content: 'Not Found', statusCode: 404 },
            },
        },
    });
    for (const [label, port] of [
        ['main VLESS', 9443], ['API', 61000], ['agent', 62080], ['extra', 10443],
    ]) {
        assert.match(validateXrayCreateNode(createNode(port)), /already used/i,
            `pre-save create validator must reject ${label} port conflict`);
    }
    assert.strictEqual(validateXrayCreateNode(createNode(24443)), null);

    const existingXrayNode = {
        type: 'xray', port: 9443, domain: 'test.example.com',
        xray: {
            inboundTag: 'vless-in', apiPort: 61000, agentPort: 62080,
            tlsSource: 'self-signed', security: 'reality',
            extraInbounds: [{
                id: 'extra', inboundTag: 'extra-in', port: 10443,
                transport: 'tcp', security: 'reality',
            }],
            hysteria: {
                enabled: true, port: 24443, inboundTag: 'hysteria-in',
                obfs: 'salamander', obfsPassword: 'preserved-secret',
                udpIdleTimeout: 60,
                masquerade: { type: 'string', content: 'Not Found', statusCode: 404 },
            },
        },
    };
    assert.match(validateResultingXrayUpdate(existingXrayNode, {
        'xray.hysteria.inboundTag': 'vless-in',
    }), /must differ from the main VLESS tag/);
    assert.match(validateResultingXrayUpdate(existingXrayNode, {
        'xray.hysteria.inboundTag': 'extra-in',
    }), /already used/);
    const noExtrasXrayNode = {
        ...existingXrayNode,
        xray: { ...existingXrayNode.xray, extraInbounds: [] },
    };
    for (const [label, port] of [
        ['main VLESS', noExtrasXrayNode.port],
        ['API', noExtrasXrayNode.xray.apiPort],
        ['agent', noExtrasXrayNode.xray.agentPort],
    ]) {
        const directXray = JSON.parse(JSON.stringify(noExtrasXrayNode.xray));
        directXray.hysteria.port = port;
        assert.match(
            helpers.validateXrayFormFields(directXray, noExtrasXrayNode),
            new RegExp(`Native Hysteria.*${label}`, 'i'),
            `direct validator must reject native Hysteria conflict with ${label}`
        );
        assert.match(
            validateResultingXrayUpdate(noExtrasXrayNode, { 'xray.hysteria.port': port }),
            new RegExp(`Native Hysteria.*${label}`, 'i'),
            `partial update validator must reject native Hysteria conflict with ${label}`
        );
    }
    assert.strictEqual(validateResultingXrayUpdate(existingXrayNode, {
        'xray.hysteria.port': 24444,
    }), null, 'partial updates must preserve the selected Salamander PSK during resulting-config validation');

    for (const [path, value] of [
        ['xray.hysteria.port', 0],
        ['xray.hysteria.udpIdleTimeout', 5],
        ['xray.hysteria.masquerade.statusCode', 700],
        ['xray.hysteria.masquerade.url', 'file:///etc/passwd'],
        ['xray.hysteria.inboundTag', 'bad tag with spaces'],
        ['xray.hysteria.obfsPassword', 'short'],
        ['xray.hysteria.obfs', 'invalid-obfs'],
    ]) {
        const query = HyNode.findByIdAndUpdate(
            '64b000000000000000000001',
            { $set: { [path]: value } },
            validatedXrayUpdateOptions()
        );
        const castUpdate = query._castUpdate(query.getUpdate());
        await assert.rejects(
            () => query.validate(castUpdate, query.getOptions(), false),
            error => error?.name === 'ValidationError' && !!error.errors?.[path],
            `REST/MCP query validators must reject ${path}=${value}`
        );
    }

    assert.strictEqual(typeof syncService.restartXrayFailClosed, 'function');
    assert.strictEqual(typeof nodeSetup.validateCcAgentReloadResult, 'function');
    assert.throws(() => nodeSetup.validateCcAgentReloadResult(
        { name: 'hy-node', xray: { hysteria: { enabled: true } } },
        { code: 1, stderr: 'service failed' }
    ), /cc-agent did not become active/);
    assert.strictEqual(nodeSetup.validateCcAgentReloadResult(
        { name: 'legacy-node', xray: { hysteria: { enabled: false } } },
        { code: 1, stderr: 'service failed' }
    ), false);
    const calls = [];
    const fallback = await syncService.restartXrayFailClosed({
        nativeHysteria: true,
        hasAgent: true,
        hasSsh: true,
        restartViaAgent: async () => { calls.push('agent'); throw new Error('agent down'); },
        restartViaSsh: async () => { calls.push('ssh'); },
    });
    assert.strictEqual(fallback, 'ssh');
    assert.deepStrictEqual(calls, ['agent', 'ssh']);

    await assert.rejects(() => syncService.restartXrayFailClosed({
        nativeHysteria: true,
        hasAgent: true,
        hasSsh: false,
        restartViaAgent: async () => { throw new Error('agent down'); },
        restartViaSsh: async () => {},
    }), /Native Hysteria restart failed closed/);

    assert.strictEqual(await syncService.restartXrayFailClosed({
        nativeHysteria: false,
        hasAgent: true,
        hasSsh: false,
        restartViaAgent: async () => { throw new Error('legacy agent down'); },
        restartViaSsh: async () => {},
    }), null);
}

runRestartContractTests()
    .then(() => {
        console.log('native Xray Hysteria tests passed');
        process.exit(0);
    })
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
