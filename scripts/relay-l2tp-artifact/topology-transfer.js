#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const MODULE_ID = 'relay-l2tp';
const KINDS = new Set([
    'relay-l2tp-topology-transfer',
    'relay-l2tp-topology-import-draft',
]);
const OBJECT_ID_PATTERN = /\b[a-f0-9]{24}\b/i;
const SECRET_KEY_PATTERN = /(?:password|passwd|privatekey|private_key|credential|api[_-]?key|token|secret|psk|encrypted)/i;
const SECRET_VALUE_PATTERNS = [
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?):\/\/[^\s/:@]+:[^\s/@]+@/i,
    /\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|psk)\s*[:=]/i,
];

function fail(message) {
    throw new Error(message);
}

function objectValue(value, label) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
    return value;
}

function arrayValue(value, label) {
    if (value === undefined) return [];
    if (!Array.isArray(value)) fail(`${label} must be an array`);
    return value;
}

function stringValue(value, label, { optional = false } = {}) {
    if (optional && value === undefined) return undefined;
    if (typeof value !== 'string' || value.trim() === '') fail(`${label} must be a non-empty string`);
    return value.trim();
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

function buildAliases(records, prefix, label) {
    const aliases = new Map();
    records.forEach((record, index) => {
        objectValue(record, `${label}[${index}]`);
        const reference = entityReference(record._id ?? record.id ?? record.key, `${label}[${index}] identifier`);
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

function exportDraft(source) {
    objectValue(source, 'topology export source');
    const rawNodes = arrayValue(source.nodes, 'nodes');
    const rawLinks = arrayValue(source.links, 'links');
    const rawGroups = arrayValue(source.routeGroups ?? source.groups, 'routeGroups');
    const rawRelayStates = arrayValue(source.relayStates, 'relayStates');
    const nodeAliases = buildAliases(rawNodes, 'node', 'nodes');
    const linkAliases = buildAliases(rawLinks, 'link', 'links');
    const groupAliases = buildAliases(rawGroups, 'group', 'routeGroups');

    const nodes = rawNodes.map((node, index) => ({
        key: `node-${String(index + 1).padStart(3, '0')}`,
        name: stringValue(node.name, `nodes[${index}].name`),
        role: stringValue(node.role ?? node.cascadeRole, `nodes[${index}].role`),
    }));

    const links = rawLinks.map((link, index) => ({
        key: `link-${String(index + 1).padStart(3, '0')}`,
        name: stringValue(link.name, `links[${index}].name`),
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
        mode: stringValue(link.mode, `links[${index}].mode`),
        active: booleanValue(link.active, `links[${index}].active`, true),
    }));

    const routeGroups = rawGroups.map((group, groupIndex) => ({
        key: `group-${String(groupIndex + 1).padStart(3, '0')}`,
        name: stringValue(group.name, `routeGroups[${groupIndex}].name`),
        mode: stringValue(group.mode, `routeGroups[${groupIndex}].mode`),
        strategy: stringValue(group.strategy, `routeGroups[${groupIndex}].strategy`),
        paths: arrayValue(group.paths, `routeGroups[${groupIndex}].paths`).map((routePath, pathIndex) => ({
            pathKey: stringValue(routePath.pathKey, `routeGroups[${groupIndex}].paths[${pathIndex}].pathKey`),
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
        })),
    }));

    const relayStates = rawRelayStates.map((state, index) => {
        objectValue(state, `relayStates[${index}]`);
        const portable = {
            node: resolveAlias(nodeAliases, state.node, `relayStates[${index}].node`),
            desiredState: stringValue(state.desiredState, `relayStates[${index}].desiredState`),
        };
        for (const field of ['clientCidr', 'localAddress', 'poolStart', 'poolEnd', 'routingMode']) {
            const value = stringValue(state[field], `relayStates[${index}].${field}`, { optional: true });
            if (value !== undefined) portable[field] = value;
        }
        for (const field of ['mtu', 'mru']) {
            const value = finiteNumber(state[field], `relayStates[${index}].${field}`, { optional: true, positive: true });
            if (value !== undefined) portable[field] = value;
        }
        if (state.dnsServers !== undefined) {
            portable.dnsServers = arrayValue(state.dnsServers, `relayStates[${index}].dnsServers`)
                .map((value, dnsIndex) => stringValue(value, `relayStates[${index}].dnsServers[${dnsIndex}]`));
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

    return canonicalDraft({
        schemaVersion: 1,
        module: MODULE_ID,
        kind: 'relay-l2tp-topology-transfer',
        topology: { nodes, links, routeGroups, relayStates },
    }, 'relay-l2tp-topology-transfer');
}

function assertPortableKey(value, prefix, label) {
    const key = stringValue(value, label);
    if (!new RegExp(`^${prefix}-[0-9]{3,}$`).test(key)) fail(`${label} is not a portable ${prefix} key`);
    return key;
}

function uniqueKeys(records, label) {
    const keys = records.map(record => record.key);
    if (new Set(keys).size !== keys.length) fail(`${label} keys must be unique`);
    return new Set(keys);
}

function canonicalDraft(source, requestedKind = source?.kind) {
    objectValue(source, 'topology draft');
    if (source.schemaVersion !== 1) fail('Unsupported topology draft schemaVersion');
    if (source.module !== MODULE_ID) fail('Unexpected topology draft module');
    if (!KINDS.has(requestedKind)) fail('Unexpected topology draft kind');
    const topology = objectValue(source.topology, 'topology');

    const nodes = arrayValue(topology.nodes, 'topology.nodes').map((node, index) => {
        objectValue(node, `topology.nodes[${index}]`);
        return {
            key: assertPortableKey(node.key, 'node', `topology.nodes[${index}].key`),
            name: stringValue(node.name, `topology.nodes[${index}].name`),
            role: stringValue(node.role, `topology.nodes[${index}].role`),
        };
    });
    const nodeKeys = uniqueKeys(nodes, 'Node');

    const links = arrayValue(topology.links, 'topology.links').map((link, index) => {
        objectValue(link, `topology.links[${index}]`);
        const portable = {
            key: assertPortableKey(link.key, 'link', `topology.links[${index}].key`),
            name: stringValue(link.name, `topology.links[${index}].name`),
            source: assertPortableKey(link.source, 'node', `topology.links[${index}].source`),
            target: assertPortableKey(link.target, 'node', `topology.links[${index}].target`),
            mode: stringValue(link.mode, `topology.links[${index}].mode`),
            active: booleanValue(link.active, `topology.links[${index}].active`, true),
        };
        if (!nodeKeys.has(portable.source) || !nodeKeys.has(portable.target)) {
            fail(`topology.links[${index}] references an unknown node`);
        }
        return portable;
    });
    const linkKeys = uniqueKeys(links, 'Link');

    const routeGroups = arrayValue(topology.routeGroups, 'topology.routeGroups').map((group, groupIndex) => {
        objectValue(group, `topology.routeGroups[${groupIndex}]`);
        const paths = arrayValue(group.paths, `topology.routeGroups[${groupIndex}].paths`)
            .map((routePath, pathIndex) => {
                objectValue(routePath, `topology.routeGroups[${groupIndex}].paths[${pathIndex}]`);
                const pathLinks = arrayValue(
                    routePath.links,
                    `topology.routeGroups[${groupIndex}].paths[${pathIndex}].links`,
                ).map((linkKey, linkIndex) => assertPortableKey(
                    linkKey,
                    'link',
                    `topology.routeGroups[${groupIndex}].paths[${pathIndex}].links[${linkIndex}]`,
                ));
                if (pathLinks.some(linkKey => !linkKeys.has(linkKey))) {
                    fail(`topology.routeGroups[${groupIndex}].paths[${pathIndex}] references an unknown link`);
                }
                return {
                    pathKey: stringValue(
                        routePath.pathKey,
                        `topology.routeGroups[${groupIndex}].paths[${pathIndex}].pathKey`,
                    ),
                    links: pathLinks,
                    priority: finiteNumber(
                        routePath.priority,
                        `topology.routeGroups[${groupIndex}].paths[${pathIndex}].priority`,
                        { positive: true },
                    ),
                };
            });
        if (new Set(paths.map(routePath => routePath.pathKey)).size !== paths.length) {
            fail(`topology.routeGroups[${groupIndex}] path keys must be unique`);
        }
        return {
            key: assertPortableKey(group.key, 'group', `topology.routeGroups[${groupIndex}].key`),
            name: stringValue(group.name, `topology.routeGroups[${groupIndex}].name`),
            mode: stringValue(group.mode, `topology.routeGroups[${groupIndex}].mode`),
            strategy: stringValue(group.strategy, `topology.routeGroups[${groupIndex}].strategy`),
            paths,
        };
    });
    const groupKeys = uniqueKeys(routeGroups, 'Route group');

    const relayStates = arrayValue(topology.relayStates, 'topology.relayStates').map((state, index) => {
        objectValue(state, `topology.relayStates[${index}]`);
        const portable = {
            node: assertPortableKey(state.node, 'node', `topology.relayStates[${index}].node`),
            desiredState: stringValue(state.desiredState, `topology.relayStates[${index}].desiredState`),
        };
        if (!nodeKeys.has(portable.node)) fail(`topology.relayStates[${index}] references an unknown node`);
        for (const field of ['clientCidr', 'localAddress', 'poolStart', 'poolEnd', 'routingMode']) {
            const value = stringValue(state[field], `topology.relayStates[${index}].${field}`, { optional: true });
            if (value !== undefined) portable[field] = value;
        }
        for (const field of ['mtu', 'mru']) {
            const value = finiteNumber(
                state[field],
                `topology.relayStates[${index}].${field}`,
                { optional: true, positive: true },
            );
            if (value !== undefined) portable[field] = value;
        }
        if (state.dnsServers !== undefined) {
            portable.dnsServers = arrayValue(state.dnsServers, `topology.relayStates[${index}].dnsServers`)
                .map((value, dnsIndex) => stringValue(
                    value,
                    `topology.relayStates[${index}].dnsServers[${dnsIndex}]`,
                ));
        }
        if (state.routeGroup !== undefined && state.routeGroup !== null) {
            portable.routeGroup = assertPortableKey(
                state.routeGroup,
                'group',
                `topology.relayStates[${index}].routeGroup`,
            );
            if (!groupKeys.has(portable.routeGroup)) {
                fail(`topology.relayStates[${index}] references an unknown route group`);
            }
        }
        return portable;
    });
    if (new Set(relayStates.map(state => state.node)).size !== relayStates.length) {
        fail('Relay state node keys must be unique');
    }

    const result = {
        schemaVersion: 1,
        module: MODULE_ID,
        kind: requestedKind,
        topology: { nodes, links, routeGroups, relayStates },
    };
    assertNoSensitiveMaterial(result);
    return result;
}

function assertNoSensitiveMaterial(value, location = '$') {
    if (Array.isArray(value)) {
        value.forEach((entry, index) => assertNoSensitiveMaterial(entry, `${location}[${index}]`));
        return;
    }
    if (value && typeof value === 'object') {
        for (const [key, entry] of Object.entries(value)) {
            if (SECRET_KEY_PATTERN.test(key)) fail(`Sensitive field is not allowed in topology draft: ${location}.${key}`);
            assertNoSensitiveMaterial(entry, `${location}.${key}`);
        }
        return;
    }
    if (typeof value !== 'string') return;
    if (OBJECT_ID_PATTERN.test(value)) fail(`Database ObjectId is not allowed in topology draft: ${location}`);
    if (SECRET_VALUE_PATTERNS.some(pattern => pattern.test(value))) {
        fail(`Secret-like value is not allowed in topology draft: ${location}`);
    }
}

function readJson(filePath) {
    let value;
    try {
        value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (error) {
        fail(`Unable to read JSON input: ${error.message}`);
    }
    return value;
}

function writeJsonAtomic(filePath, value) {
    const absolutePath = path.resolve(filePath);
    const parent = path.dirname(absolutePath);
    fs.mkdirSync(parent, { recursive: true });
    const tempRoot = fs.mkdtempSync(path.join(parent, '.relay-l2tp-topology-'));
    const tempPath = path.join(tempRoot, 'draft.json');
    try {
        fs.writeFileSync(tempPath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
        fs.renameSync(tempPath, absolutePath);
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
}

function runTransfer({ action, inputPath, outputPath }) {
    const input = readJson(path.resolve(inputPath));
    if (action === 'validate') {
        const draft = canonicalDraft(input);
        return {
            valid: true,
            kind: draft.kind,
            nodes: draft.topology.nodes.length,
            links: draft.topology.links.length,
            routeGroups: draft.topology.routeGroups.length,
            relayStates: draft.topology.relayStates.length,
        };
    }

    const draft = action === 'export'
        ? exportDraft(input)
        : canonicalDraft(input, 'relay-l2tp-topology-import-draft');
    writeJsonAtomic(outputPath, draft);
    return {
        action,
        output: path.resolve(outputPath),
        kind: draft.kind,
        nodes: draft.topology.nodes.length,
        links: draft.topology.links.length,
        routeGroups: draft.topology.routeGroups.length,
        relayStates: draft.topology.relayStates.length,
    };
}

function parseArguments(argv) {
    const [action, ...args] = argv;
    if (!['export', 'import', 'validate'].includes(action)) {
        fail('Usage: topology-transfer.js <export|import|validate> --input FILE [--output FILE]');
    }
    const values = { action };
    for (let index = 0; index < args.length; index += 2) {
        const name = args[index];
        const value = args[index + 1];
        if (!['--input', '--output'].includes(name) || value === undefined) fail(`Invalid argument: ${name || ''}`);
        values[name === '--input' ? 'inputPath' : 'outputPath'] = value;
    }
    if (!values.inputPath) fail('--input is required');
    if (action !== 'validate' && !values.outputPath) fail('--output is required');
    if (action === 'validate' && values.outputPath) fail('--output is not valid with validate');
    return values;
}

if (require.main === module) {
    try {
        process.stdout.write(`${JSON.stringify(runTransfer(parseArguments(process.argv.slice(2))))}\n`);
    } catch (error) {
        process.stderr.write(`Topology transfer failed: ${error.message}\n`);
        process.exitCode = 1;
    }
}

module.exports = {
    assertNoSensitiveMaterial,
    canonicalDraft,
    exportDraft,
    runTransfer,
};
