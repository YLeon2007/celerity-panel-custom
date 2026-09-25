'use strict';

// A plain node sync regenerates the base Xray config from scratch and would
// silently drop the L2TP-managed sections (tproxy inbound, per-path socks
// outbound, their routing rules), stranding every L2TP client until a
// reinstall. Before uploading the regenerated config the sync re-attaches
// those sections from the node's live config.

const L2TP_INBOUND_PREFIX = 'relay-l2tp-';

function ruleTouchesInbound(rule, inboundTags) {
    const tags = Array.isArray(rule?.inboundTag) ? rule.inboundTag : [];
    return tags.some(tag => inboundTags.has(tag));
}

function mergePreservedL2tpSections(generated, current) {
    const preservedInbounds = (current.inbounds || []).filter(inbound =>
        typeof inbound?.tag === 'string' && inbound.tag.startsWith(L2TP_INBOUND_PREFIX));
    if (preservedInbounds.length === 0) return generated;

    const inboundTags = new Set(preservedInbounds.map(inbound => inbound.tag));
    const preservedRules = (current.routing?.rules || [])
        .filter(rule => ruleTouchesInbound(rule, inboundTags));
    const neededOutboundTags = new Set(
        preservedRules.map(rule => rule?.outboundTag).filter(Boolean),
    );

    const result = {
        ...generated,
        inbounds: [...(generated.inbounds || [])],
        outbounds: [...(generated.outbounds || [])],
        routing: {
            ...(generated.routing || {}),
            rules: [...(generated.routing?.rules || [])],
        },
    };

    const knownInboundTags = new Set(result.inbounds.map(inbound => inbound?.tag));
    for (const inbound of preservedInbounds) {
        if (!knownInboundTags.has(inbound.tag)) result.inbounds.push(inbound);
    }

    const knownOutboundTags = new Set(result.outbounds.map(outbound => outbound?.tag));
    for (const outbound of current.outbounds || []) {
        if (neededOutboundTags.has(outbound?.tag) && !knownOutboundTags.has(outbound.tag)) {
            result.outbounds.push(outbound);
            knownOutboundTags.add(outbound.tag);
        }
    }

    const serializedRules = new Set(result.rules?.map?.(rule => JSON.stringify(rule)) || []);
    for (const rule of preservedRules) {
        const key = JSON.stringify(rule);
        if (!serializedRules.has(key)) {
            result.routing.rules.push(rule);
            serializedRules.add(key);
        }
    }
    return result;
}

function mergePreservedL2tpConfig(generatedContent, currentContent) {
    let generated;
    let current;
    try {
        generated = JSON.parse(generatedContent);
        current = JSON.parse(currentContent);
    } catch {
        return generatedContent;
    }
    if (!generated || typeof generated !== 'object' || !current || typeof current !== 'object') {
        return generatedContent;
    }
    return JSON.stringify(mergePreservedL2tpSections(generated, current), null, 2);
}

module.exports = {
    mergePreservedL2tpConfig,
    mergePreservedL2tpSections,
};
