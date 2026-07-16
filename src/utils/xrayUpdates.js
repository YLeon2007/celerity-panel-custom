'use strict';

/**
 * Flatten an Xray partial update into MongoDB dot-paths. Native Hysteria is
 * flattened one level deeper so an update such as {enabled:true,port:24443}
 * does not replace the whole subdocument and erase its write-only PSK.
 */
function appendNestedUpdates(updates, prefix, value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        updates[prefix] = value;
        return;
    }
    for (const [key, nestedValue] of Object.entries(value)) {
        appendNestedUpdates(updates, `${prefix}.${key}`, nestedValue);
    }
}

function buildXrayDotUpdates(xray) {
    const updates = {};
    if (!xray || typeof xray !== 'object' || Array.isArray(xray)) return updates;

    for (const [key, value] of Object.entries(xray)) {
        if (key === 'hysteria' && value && typeof value === 'object' && !Array.isArray(value)) {
            const hysteria = { ...value };
            if (hysteria.obfsPassword === '' || hysteria.obfsPassword === null || hysteria.obfsPassword === undefined) {
                delete hysteria.obfsPassword;
            }
            appendNestedUpdates(updates, 'xray.hysteria', hysteria);
            continue;
        }
        updates[`xray.${key}`] = value;
    }
    return updates;
}

function setNestedValue(target, dottedPath, value) {
    const parts = dottedPath.split('.');
    let cursor = target;
    for (let i = 0; i < parts.length - 1; i++) {
        const key = parts[i];
        const current = cursor[key];
        cursor[key] = current && typeof current === 'object' && !Array.isArray(current)
            ? { ...current }
            : {};
        cursor = cursor[key];
    }
    cursor[parts[parts.length - 1]] = value;
}

function clonePlain(value) {
    if (!value) return {};
    if (typeof value.toObject === 'function') {
        return value.toObject({ transform: false, depopulate: true });
    }
    return JSON.parse(JSON.stringify(value));
}

function validateXrayCreateNode(node) {
    if (node?.type !== 'xray') return null;
    const { validateXrayFormFields } = require('../routes/panel/helpers');
    return validateXrayFormFields(clonePlain(node.xray), {
        port: node.port,
        domain: node.domain,
    });
}

/**
 * Validate the resulting Xray configuration, not just individual update
 * fields. This catches tag/port/TLS/PSK conflicts after REST/MCP partial
 * dot-path updates while preserving omitted write-only secrets.
 */
function validateResultingXrayUpdate(existingNode, updates) {
    const nextType = updates.type || existingNode?.type;
    const touchesXray = Object.keys(updates).some(key => key === 'port' || key === 'domain' || key.startsWith('xray.'));
    if (nextType !== 'xray' || !touchesXray) return null;

    const xray = clonePlain(existingNode?.xray);
    for (const [path, value] of Object.entries(updates)) {
        if (!path.startsWith('xray.')) continue;
        setNestedValue(xray, path.slice('xray.'.length), value);
    }

    const node = {
        port: updates.port !== undefined ? updates.port : existingNode?.port,
        domain: updates.domain !== undefined ? updates.domain : existingNode?.domain,
    };
    const { validateXrayFormFields } = require('../routes/panel/helpers');
    return validateXrayFormFields(xray, node);
}

function validatedXrayUpdateOptions() {
    return { new: true, runValidators: true, context: 'query' };
}

module.exports = {
    buildXrayDotUpdates,
    validateXrayCreateNode,
    validateResultingXrayUpdate,
    validatedXrayUpdateOptions,
};
