'use strict';

const MODULE_ID = 'relay-l2tp';
const SCHEMA_VERSION = 1;
const TRANSFER_KIND = 'relay-l2tp-topology-transfer';
const IMPORT_DRAFT_KIND = 'relay-l2tp-topology-import-draft';
const OBJECT_ID_PATTERN = /\b[a-f0-9]{24}\b/i;
const SECRET_KEY_PATTERN = /(?:password|passwd|privatekey|private_key|credential|api[_-]?key|token|secret|psk|encrypted)/i;
const SECRET_VALUE_PATTERNS = Object.freeze([
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?):\/\/[^\s/:@]+:[^\s/@]+@/i,
    /\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|psk)\s*[:=]/i,
]);
const NODE_ROLES = new Set(['portal', 'relay', 'bridge']);
const LINK_MODES = new Set(['reverse', 'forward']);
const ROUTE_GROUP_STRATEGIES = new Set(['priority-failover']);
const DESIRED_STATES = new Set(['absent', 'installed']);

class TopologyTransferValidationError extends Error {
    constructor(message, details = []) {
        super(message);
        this.name = 'TopologyTransferValidationError';
        this.code = 'INVALID_TOPOLOGY_TRANSFER';
        this.details = details;
    }
}

function fail(message, details) {
    throw new TopologyTransferValidationError(message, details);
}

function objectValue(value, label) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        fail(`${label} must be an object`);
    }
    return value;
}

function arrayValue(value, label) {
    if (value === undefined) return [];
    if (!Array.isArray(value)) fail(`${label} must be an array`);
    return value;
}

function stringValue(value, label, { optional = false, maximumLength = 500 } = {}) {
    if (optional && value === undefined) return undefined;
    if (typeof value !== 'string' || value.trim() === '') {
        fail(`${label} must be a non-empty string`);
    }
    const normalized = value.trim();
    if (normalized.length > maximumLength) fail(`${label} is too long`);
    return normalized;
}

function finiteNumber(value, label, { optional = false, positive = false } = {}) {
    if (optional && (value === undefined || value === null)) return undefined;
    if (!Number.isFinite(value) || (positive && value <= 0)) {
        fail(`${label} must be ${positive ? 'a positive ' : 'a '}finite number`);
    }
    return value;
}

function booleanValue(value, label, defaultValue) {
    if (value === undefined) return defaultValue;
    if (typeof value !== 'boolean') fail(`${label} must be a boolean`);
    return value;
}

function entityReference(value, label) {
    let candidate = value;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
        candidate = value._id ?? value.id ?? value.key;
    }
    if (candidate === undefined || candidate === null || String(candidate).trim() === '') {
        fail(`${label} is required`);
    }
    return String(candidate);
}

function sortByEntityReference(records, label) {
    return [...records].sort((left, right) => (
        entityReference(left, `${label} identifier`)
            .localeCompare(entityReference(right, `${label} identifier`))
    ));
}

function buildAliases(records, prefix, label) {
    const aliases = new Map();
    records.forEach((record, index) => {
        objectValue(record, `${label}[${index}]`);
        const reference = entityReference(record, `${label}[${index}] identifier`);
        if (aliases.has(reference)) fail(`${label} contains a duplicate identifier`);
        aliases.set(reference, `${prefix}-${String(index + 1).padStart(3, '0')}`);
    });
    return aliases;
}

function resolveAlias(aliases, value, label) {
    const reference = entityReference(value, label);
    const alias = aliases.get(reference);
    if (!alias) fail(`${label} references an unknown record`);
    return alias;
}

function enumValue(value, allowed, label) {
    const normalized = stringValue(value, label);
    if (!allowed.has(normalized)) fail(`${label} has an unsupported value`);
    return normalized;
}

function projectOptionalStringFields(source, target, fields, label) {
    for (const field of fields) {
        const value = stringValue(source[field], `${label}.${field}`, { optional: true });
        if (value !== undefined) target[field] = value;
    }
}

function projectOptionalNumberFields(source, target, fields, label) {
    for (const field of fields) {
        const value = finiteNumber(source[field], `${label}.${field}`, {
            optional: true,
            positive: true,
        });
        if (value !== undefined) target[field] = value;
    }
}

function assertNoSensitiveMaterial(value, location = '$') {
    if (Array.isArray(value)) {
        value.forEach((entry, index) => assertNoSensitiveMaterial(entry, `${location}[${index}]`));
        return;
    }
    if (value && typeof value === 'object') {
        for (const [key, entry] of Object.entries(value)) {
            if (SECRET_KEY_PATTERN.test(key)) {
                fail(`Sensitive field is not allowed in topology transfer: ${location}.${key}`);
            }
            assertNoSensitiveMaterial(entry, `${location}.${key}`);
        }
        return;
    }
    if (typeof value !== 'string') return;
    if (OBJECT_ID_PATTERN.test(value)) {
        fail(`Database ObjectId is not allowed in topology transfer: ${location}`);
    }
    if (SECRET_VALUE_PATTERNS.some(pattern => pattern.test(value))) {
        fail(`Secret-like value is not allowed in topology transfer: ${location}`);
    }
}

function portableKey(value, prefix, label) {
    const key = stringValue(value, label, { maximumLength: 72 });
    if (!new RegExp(`^${prefix}-[a-z0-9][a-z0-9._-]{0,63}$`, 'i').test(key)) {
        fail(`${label} is not a portable ${prefix} key`);
    }
    return key;
}

function uniqueKeySet(records, label) {
    const keys = records.map(record => record.key);
    if (new Set(keys).size !== keys.length) fail(`${label} keys must be unique`);
    return new Set(keys);
}

function canonicalizeTopologyTransfer(source, { kind = IMPORT_DRAFT_KIND } = {}) {
    objectValue(source, 'topology transfer');
    if (source.schemaVersion !== SCHEMA_VERSION) {
        fail('Unsupported topology transfer schemaVersion');
    }
    if (source.module !== MODULE_ID) fail('Unexpected topology transfer module');
    if (![TRANSFER_KIND, IMPORT_DRAFT_KIND].includes(source.kind)) {
        fail('Unexpected topology transfer kind');
    }
    if (![TRANSFER_KIND, IMPORT_DRAFT_KIND].includes(kind)) {
        fail('Unexpected canonical topology transfer kind');
    }
    const topology = objectValue(source.topology, 'topology');

    const nodes = arrayValue(topology.nodes, 'topology.nodes').map((node, index) => {
        objectValue(node, `topology.nodes[${index}]`);
        return {
            key: portableKey(node.key, 'node', `topology.nodes[${index}].key`),
            name: stringValue(node.name, `topology.nodes[${index}].name`, { maximumLength: 120 }),
            role: enumValue(node.role, NODE_ROLES, `topology.nodes[${index}].role`),
        };
    }).sort((left, right) => left.key.localeCompare(right.key));
    const nodeKeys = uniqueKeySet(nodes, 'Node');

    const links = arrayValue(topology.links, 'topology.links').map((link, index) => {
        objectValue(link, `topology.links[${index}]`);
        const portable = {
            key: portableKey(link.key, 'link', `topology.links[${index}].key`),
            name: stringValue(link.name, `topology.links[${index}].name`, { maximumLength: 120 }),
            source: portableKey(link.source, 'node', `topology.links[${index}].source`),
            target: portableKey(link.target, 'node', `topology.links[${index}].target`),
            mode: enumValue(link.mode, LINK_MODES, `topology.links[${index}].mode`),
            active: booleanValue(link.active, `topology.links[${index}].active`, true),
        };
        if (!nodeKeys.has(portable.source) || !nodeKeys.has(portable.target)) {
            fail(`topology.links[${index}] references an unknown node`);
        }
        return portable;
    }).sort((left, right) => left.key.localeCompare(right.key));
    const linkKeys = uniqueKeySet(links, 'Link');

    const routeGroups = arrayValue(topology.routeGroups, 'topology.routeGroups')
        .map((group, groupIndex) => {
            objectValue(group, `topology.routeGroups[${groupIndex}]`);
            const paths = arrayValue(group.paths, `topology.routeGroups[${groupIndex}].paths`)
                .map((routePath, pathIndex) => {
                    objectValue(
                        routePath,
                        `topology.routeGroups[${groupIndex}].paths[${pathIndex}]`,
                    );
                    const pathLinks = arrayValue(
                        routePath.links,
                        `topology.routeGroups[${groupIndex}].paths[${pathIndex}].links`,
                    ).map((linkKey, linkIndex) => portableKey(
                        linkKey,
                        'link',
                        `topology.routeGroups[${groupIndex}].paths[${pathIndex}].links[${linkIndex}]`,
                    ));
                    if (new Set(pathLinks).size !== pathLinks.length) {
                        fail(`topology.routeGroups[${groupIndex}].paths[${pathIndex}] has duplicate links`);
                    }
                    if (pathLinks.some(linkKey => !linkKeys.has(linkKey))) {
                        fail(`topology.routeGroups[${groupIndex}].paths[${pathIndex}] references an unknown link`);
                    }
                    return {
                        pathKey: stringValue(
                            routePath.pathKey,
                            `topology.routeGroups[${groupIndex}].paths[${pathIndex}].pathKey`,
                            { maximumLength: 120 },
                        ),
                        links: pathLinks,
                        priority: finiteNumber(
                            routePath.priority,
                            `topology.routeGroups[${groupIndex}].paths[${pathIndex}].priority`,
                            { positive: true },
                        ),
                        enabled: booleanValue(
                            routePath.enabled,
                            `topology.routeGroups[${groupIndex}].paths[${pathIndex}].enabled`,
                            true,
                        ),
                    };
                })
                .sort((left, right) => left.priority - right.priority
                    || left.pathKey.localeCompare(right.pathKey));
            if (new Set(paths.map(routePath => routePath.pathKey)).size !== paths.length) {
                fail(`topology.routeGroups[${groupIndex}] path keys must be unique`);
            }
            if (new Set(paths.map(routePath => routePath.priority)).size !== paths.length) {
                fail(`topology.routeGroups[${groupIndex}] path priorities must be unique`);
            }
            return {
                key: portableKey(group.key, 'group', `topology.routeGroups[${groupIndex}].key`),
                name: stringValue(
                    group.name,
                    `topology.routeGroups[${groupIndex}].name`,
                    { maximumLength: 120 },
                ),
                mode: enumValue(
                    group.mode,
                    LINK_MODES,
                    `topology.routeGroups[${groupIndex}].mode`,
                ),
                strategy: enumValue(
                    group.strategy,
                    ROUTE_GROUP_STRATEGIES,
                    `topology.routeGroups[${groupIndex}].strategy`,
                ),
                paths,
            };
        })
        .sort((left, right) => left.key.localeCompare(right.key));
    const groupKeys = uniqueKeySet(routeGroups, 'Route group');

    const relayStates = arrayValue(topology.relayStates, 'topology.relayStates')
        .map((state, index) => {
            objectValue(state, `topology.relayStates[${index}]`);
            const portable = {
                node: portableKey(state.node, 'node', `topology.relayStates[${index}].node`),
                desiredState: enumValue(
                    state.desiredState,
                    DESIRED_STATES,
                    `topology.relayStates[${index}].desiredState`,
                ),
            };
            if (!nodeKeys.has(portable.node)) {
                fail(`topology.relayStates[${index}] references an unknown node`);
            }
            projectOptionalStringFields(
                state,
                portable,
                ['clientCidr', 'localAddress', 'poolStart', 'poolEnd'],
                `topology.relayStates[${index}]`,
            );
            if (state.routingMode !== undefined) {
                portable.routingMode = enumValue(
                    state.routingMode,
                    new Set(['route-group']),
                    `topology.relayStates[${index}].routingMode`,
                );
            }
            projectOptionalNumberFields(
                state,
                portable,
                ['mtu', 'mru'],
                `topology.relayStates[${index}]`,
            );
            if (state.dnsServers !== undefined) {
                portable.dnsServers = arrayValue(
                    state.dnsServers,
                    `topology.relayStates[${index}].dnsServers`,
                ).map((value, dnsIndex) => stringValue(
                    value,
                    `topology.relayStates[${index}].dnsServers[${dnsIndex}]`,
                    { maximumLength: 253 },
                ));
            }
            if (state.routeGroup !== undefined && state.routeGroup !== null) {
                portable.routeGroup = portableKey(
                    state.routeGroup,
                    'group',
                    `topology.relayStates[${index}].routeGroup`,
                );
                if (!groupKeys.has(portable.routeGroup)) {
                    fail(`topology.relayStates[${index}] references an unknown route group`);
                }
            }
            return portable;
        })
        .sort((left, right) => left.node.localeCompare(right.node));
    if (new Set(relayStates.map(state => state.node)).size !== relayStates.length) {
        fail('Relay state node keys must be unique');
    }

    const result = {
        schemaVersion: SCHEMA_VERSION,
        module: MODULE_ID,
        kind,
        topology: { nodes, links, routeGroups, relayStates },
    };
    assertNoSensitiveMaterial(result);
    return result;
}

function exportTopologyTransfer(source) {
    objectValue(source, 'topology export source');
    const rawNodes = sortByEntityReference(arrayValue(source.nodes, 'nodes'), 'nodes');
    const rawLinks = sortByEntityReference(arrayValue(source.links, 'links'), 'links');
    const rawGroups = sortByEntityReference(
        arrayValue(source.routeGroups ?? source.groups, 'routeGroups'),
        'routeGroups',
    );
    const rawRelayStates = [...arrayValue(source.relayStates, 'relayStates')]
        .sort((left, right) => entityReference(left?.node, 'relay state node')
            .localeCompare(entityReference(right?.node, 'relay state node')));
    const nodeAliases = buildAliases(rawNodes, 'node', 'nodes');
    const linkAliases = buildAliases(rawLinks, 'link', 'links');
    const groupAliases = buildAliases(rawGroups, 'group', 'routeGroups');

    const nodes = rawNodes.map((node, index) => ({
        key: `node-${String(index + 1).padStart(3, '0')}`,
        name: stringValue(node.name, `nodes[${index}].name`, { maximumLength: 120 }),
        role: enumValue(node.role ?? node.cascadeRole, NODE_ROLES, `nodes[${index}].role`),
    }));

    const links = rawLinks.map((link, index) => ({
        key: `link-${String(index + 1).padStart(3, '0')}`,
        name: stringValue(link.name, `links[${index}].name`, { maximumLength: 120 }),
        source: resolveAlias(
            nodeAliases,
            link.source ?? link.sourceNode ?? link.portalNode,
            `links[${index}].source`,
        ),
        target: resolveAlias(
            nodeAliases,
            link.target ?? link.targetNode ?? link.bridgeNode,
            `links[${index}].target`,
        ),
        mode: enumValue(link.mode, LINK_MODES, `links[${index}].mode`),
        active: booleanValue(link.active, `links[${index}].active`, true),
    }));

    const routeGroups = rawGroups.map((group, groupIndex) => ({
        key: `group-${String(groupIndex + 1).padStart(3, '0')}`,
        name: stringValue(group.name, `routeGroups[${groupIndex}].name`, { maximumLength: 120 }),
        mode: enumValue(group.mode, LINK_MODES, `routeGroups[${groupIndex}].mode`),
        strategy: enumValue(
            group.strategy,
            ROUTE_GROUP_STRATEGIES,
            `routeGroups[${groupIndex}].strategy`,
        ),
        paths: arrayValue(group.paths, `routeGroups[${groupIndex}].paths`)
            .map((routePath, pathIndex) => {
                objectValue(routePath, `routeGroups[${groupIndex}].paths[${pathIndex}]`);
                return {
                    pathKey: stringValue(
                        routePath.pathKey,
                        `routeGroups[${groupIndex}].paths[${pathIndex}].pathKey`,
                        { maximumLength: 120 },
                    ),
                    links: arrayValue(
                        routePath.linkIds ?? routePath.links,
                        `routeGroups[${groupIndex}].paths[${pathIndex}].links`,
                    ).map((linkReference, linkIndex) => resolveAlias(
                        linkAliases,
                        linkReference,
                        `routeGroups[${groupIndex}].paths[${pathIndex}].links[${linkIndex}]`,
                    )),
                    priority: finiteNumber(
                        routePath.priority,
                        `routeGroups[${groupIndex}].paths[${pathIndex}].priority`,
                        { positive: true },
                    ),
                    enabled: booleanValue(
                        routePath.enabled,
                        `routeGroups[${groupIndex}].paths[${pathIndex}].enabled`,
                        true,
                    ),
                };
            })
            .sort((left, right) => left.priority - right.priority
                || left.pathKey.localeCompare(right.pathKey)),
    }));

    const relayStates = rawRelayStates.map((state, index) => {
        objectValue(state, `relayStates[${index}]`);
        const portable = {
            node: resolveAlias(nodeAliases, state.node, `relayStates[${index}].node`),
            desiredState: enumValue(
                state.desiredState,
                DESIRED_STATES,
                `relayStates[${index}].desiredState`,
            ),
        };
        projectOptionalStringFields(
            state,
            portable,
            ['clientCidr', 'localAddress', 'poolStart', 'poolEnd'],
            `relayStates[${index}]`,
        );
        if (state.routingMode !== undefined) {
            portable.routingMode = enumValue(
                state.routingMode,
                new Set(['route-group']),
                `relayStates[${index}].routingMode`,
            );
        }
        projectOptionalNumberFields(
            state,
            portable,
            ['mtu', 'mru'],
            `relayStates[${index}]`,
        );
        if (state.dnsServers !== undefined) {
            portable.dnsServers = arrayValue(state.dnsServers, `relayStates[${index}].dnsServers`)
                .map((value, dnsIndex) => stringValue(
                    value,
                    `relayStates[${index}].dnsServers[${dnsIndex}]`,
                    { maximumLength: 253 },
                ));
        }
        if (state.routeGroup !== undefined && state.routeGroup !== null) {
            portable.routeGroup = resolveAlias(
                groupAliases,
                state.routeGroup,
                `relayStates[${index}].routeGroup`,
            );
        }
        return portable;
    });

    const result = {
        schemaVersion: SCHEMA_VERSION,
        module: MODULE_ID,
        kind: TRANSFER_KIND,
        topology: { nodes, links, routeGroups, relayStates },
    };
    assertNoSensitiveMaterial(result);
    return result;
}

module.exports = {
    DESIRED_STATES,
    IMPORT_DRAFT_KIND,
    LINK_MODES,
    MODULE_ID,
    NODE_ROLES,
    ROUTE_GROUP_STRATEGIES,
    SCHEMA_VERSION,
    TRANSFER_KIND,
    TopologyTransferValidationError,
    assertNoSensitiveMaterial,
    canonicalizeTopologyTransfer,
    exportTopologyTransfer,
};
