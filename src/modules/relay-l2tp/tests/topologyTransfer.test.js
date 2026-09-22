'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    IMPORT_DRAFT_KIND,
    TRANSFER_KIND,
    canonicalizeTopologyTransfer,
    exportTopologyTransfer,
} = require('../domain/topologyTransfer');

const IDS = Object.freeze({
    relay: '64a1b2c3d4e5f6a7b8c9d002',
    bridge: '64a1b2c3d4e5f6a7b8c9d001',
    link: '64a1b2c3d4e5f6a7b8c9d003',
    group: '64a1b2c3d4e5f6a7b8c9d004',
});

test('exports current topology canonically without secrets or database ObjectIds', () => {
    const exported = exportTopologyTransfer({
        nodes: [
            {
                _id: IDS.relay,
                name: ' Relay west ',
                cascadeRole: 'relay',
                ssh: { password: 'node-secret', privateKey: 'private-secret' },
            },
            {
                _id: IDS.bridge,
                name: 'Bridge east',
                cascadeRole: 'bridge',
                xray: { realityPrivateKey: 'xray-secret' },
            },
        ],
        links: [{
            _id: IDS.link,
            name: 'Relay to bridge',
            portalNode: IDS.relay,
            bridgeNode: IDS.bridge,
            mode: 'reverse',
            active: true,
            tunnelUuid: 'tunnel-secret',
            rawShell: 'rm -rf /',
        }],
        routeGroups: [{
            _id: IDS.group,
            name: 'Primary route',
            mode: 'reverse',
            strategy: 'priority-failover',
            paths: [{
                pathKey: 'primary',
                linkIds: [IDS.link],
                priority: 1,
                enabled: false,
            }],
        }],
        relayStates: [{
            node: IDS.relay,
            desiredState: 'installed',
            clientCidr: '10.66.0.0/24',
            localAddress: '10.66.0.1',
            dnsServers: ['9.9.9.9'],
            routingMode: 'route-group',
            routeGroup: IDS.group,
            pskEncrypted: 'encrypted-secret',
            lastError: 'private-error',
        }],
    });

    assert.deepEqual(exported, {
        schemaVersion: 1,
        module: 'relay-l2tp',
        kind: TRANSFER_KIND,
        topology: {
            nodes: [
                { key: 'node-001', name: 'Bridge east', role: 'bridge' },
                { key: 'node-002', name: 'Relay west', role: 'relay' },
            ],
            links: [{
                key: 'link-001',
                name: 'Relay to bridge',
                source: 'node-002',
                target: 'node-001',
                mode: 'reverse',
                active: true,
            }],
            routeGroups: [{
                key: 'group-001',
                name: 'Primary route',
                mode: 'reverse',
                strategy: 'priority-failover',
                paths: [{
                    pathKey: 'primary',
                    links: ['link-001'],
                    priority: 1,
                    enabled: false,
                }],
            }],
            relayStates: [{
                node: 'node-002',
                desiredState: 'installed',
                clientCidr: '10.66.0.0/24',
                localAddress: '10.66.0.1',
                dnsServers: ['9.9.9.9'],
                routingMode: 'route-group',
                routeGroup: 'group-001',
            }],
        },
    });
    const serialized = JSON.stringify(exported);
    assert.doesNotMatch(serialized, /\b[a-f0-9]{24}\b/i);
    assert.doesNotMatch(
        serialized,
        /node-secret|private-secret|xray-secret|tunnel-secret|encrypted-secret|private-error|rawShell|rm -rf/i,
    );
});

test('canonicalizes a portable transfer into a secret-free import DRAFT payload', () => {
    const canonical = canonicalizeTopologyTransfer({
        schemaVersion: 1,
        module: 'relay-l2tp',
        kind: TRANSFER_KIND,
        ignoredTopLevel: 'discarded',
        topology: {
            nodes: [
                { key: 'node-002', name: ' Bridge east ', role: 'bridge', ignored: true },
                { key: 'node-001', name: 'Relay west', role: 'relay' },
            ],
            links: [{
                key: 'link-001',
                name: ' Relay to bridge ',
                source: 'node-001',
                target: 'node-002',
                mode: 'reverse',
                ignored: true,
            }],
            routeGroups: [{
                key: 'group-001',
                name: ' Primary route ',
                mode: 'reverse',
                strategy: 'priority-failover',
                paths: [{
                    pathKey: 'primary',
                    links: ['link-001'],
                    priority: 1,
                }],
            }],
            relayStates: [{
                node: 'node-001',
                desiredState: 'installed',
                routeGroup: 'group-001',
            }],
        },
    });

    assert.deepEqual(canonical, {
        schemaVersion: 1,
        module: 'relay-l2tp',
        kind: IMPORT_DRAFT_KIND,
        topology: {
            nodes: [
                { key: 'node-001', name: 'Relay west', role: 'relay' },
                { key: 'node-002', name: 'Bridge east', role: 'bridge' },
            ],
            links: [{
                key: 'link-001',
                name: 'Relay to bridge',
                source: 'node-001',
                target: 'node-002',
                mode: 'reverse',
                active: true,
            }],
            routeGroups: [{
                key: 'group-001',
                name: 'Primary route',
                mode: 'reverse',
                strategy: 'priority-failover',
                paths: [{
                    pathKey: 'primary',
                    links: ['link-001'],
                    priority: 1,
                    enabled: true,
                }],
            }],
            relayStates: [{
                node: 'node-001',
                desiredState: 'installed',
                routeGroup: 'group-001',
            }],
        },
    });
});
