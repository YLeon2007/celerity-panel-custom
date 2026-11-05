'use strict';

// Observation, not adoption: call only inside the existing classic writer scope
// using its checked SSH connection. Desired status/autoDeploy never prove that
// an artifact is installed. Unknown/edited layouts must not authorize a rewrite.
const { isDeepStrictEqual: equal } = require('node:util');
const generator = require('./configGenerator');
const MAIN = '/usr/local/etc/xray/config.json';
const BRIDGE = '/usr/local/etc/xray-bridge/config.json';
const ABSENT = 'C3_CLASSIC_PROFILE_ABSENT';
const fail = code => Object.assign(new Error(code), { code });
const id = row => String(row?._id || row);
const short = row => id(row).slice(-8);
const clone = value => JSON.parse(JSON.stringify(value));
const empty = () => ({ inbounds: [], outbounds: [], routing: { rules: [] } });
const owned = tag => typeof tag === 'string' && /^(?:portal-|bridge-conn-|bridge(?:-|$)|tunnel(?:-|$)|conn-down-|fwd-|cascade-in-)/.test(tag);
const ruleOwned = rule => owned(rule.outboundTag) || owned(rule.balancerTag)
    || rule.balancerTag === 'cascade-balancer' || rule.balancerTag === 'down-balancer'
    || rule.inboundTag?.some(owned);

async function readClassicProfile(ssh, path, { allowAbsent = false } = {}) {
    if (![MAIN, BRIDGE].includes(path)) throw fail('CLASSIC_APPLIED_PROFILE_INVALID');
    const result = await ssh.exec(`if test -f ${path}; then cat ${path}; elif test ! -e ${path}; then printf '${ABSENT}'; else exit 1; fi`);
    if (result?.code !== 0 || typeof result.stdout !== 'string' || typeof result.stderr !== 'string') {
        throw fail('CLASSIC_APPLIED_READ_UNCONFIRMED');
    }
    if (result.stdout === ABSENT && allowAbsent) return null;
    let current;
    try { current = JSON.parse(result.stdout); } catch { throw fail('CLASSIC_APPLIED_BASELINE_UNAVAILABLE'); }
    if (!current || typeof current !== 'object' || Array.isArray(current)
        || !Array.isArray(current.outbounds) || !Array.isArray(current.routing?.rules)
        || (current.inbounds !== undefined && !Array.isArray(current.inbounds))) throw fail('CLASSIC_APPLIED_BASELINE_INVALID');
    return current;
}

function sections(config) {
    return [config.inbounds || [], config.outbounds || [], config.reverse?.portals || [],
        config.reverse?.bridges || [], config.routing.balancers || []];
}
function verifyArtifacts(current, expected) {
    const actual = sections(current), wanted = sections(expected);
    for (let i = 0; i < actual.length; i++) {
        // Reverse entries are never classified as unrelated by their spelling.
        const project = rows => i === 2 || i === 3 ? rows : rows.filter(row => owned(row.tag)
            || ['cascade-balancer', 'down-balancer'].includes(row.tag));
        const rows = project(actual[i]), expectedRows = project(wanted[i]);
        if (rows.length !== expectedRows.length || expectedRows.some(row => rows.filter(value => equal(value, row)).length !== 1)) {
            throw fail('CLASSIC_APPLIED_ARTIFACT_MISMATCH');
        }
    }
    const foreignTags = new Set((current.inbounds || []).filter(row => !owned(row.tag)).map(row => row.tag));
    const known = new Set(sections(expected).flat().map(row => row.tag));
    const expectedRules = expected.routing.rules.filter(ruleOwned);
    const retainedClientRule = row => !expectedRules.some(rule => equal(rule, row))
        && row.inboundTag?.length && row.inboundTag.every(tag => foreignTags.has(tag))
        && known.has(row.outboundTag) && !row.balancerTag;
    if (!equal(current.routing.rules.filter(ruleOwned).filter(row => !retainedClientRule(row)), expectedRules)) {
        throw fail('CLASSIC_APPLIED_ROUTING_MISMATCH');
    }
}
function tagsFor(node) {
    return [node.xray?.inboundTag || 'vless-in', ...(node.xray?.extraInbounds || []).map(row => row.inboundTag).filter(Boolean)];
}
function mainArtifacts(node, { reverse, forward, hops }) {
    const config = empty();
    if (reverse.length) generator.applyReversePortal(config, reverse, tagsFor(node));
    if (forward.length) generator.applyForwardChain(config, forward, tagsFor(node));
    if (hops.length) generator.applyForwardHopInbound(config, hops);
    return clone(config);
}
function orderedByTags(rows, actual, tag) {
    const positions = new Map(actual.map((row, index) => [row.tag, index]));
    return rows.filter(row => positions.has(tag(row))).sort((a, b) => positions.get(tag(a)) - positions.get(tag(b)));
}

function selectClassicMain({ node, current, bridgeCurrent = null, portalLinks = [], forwardLinks = [], hopLinks = [],
    selectedLinkIds = [], excludeLinkIds = [] }) {
    if (!current) throw fail('CLASSIC_APPLIED_BASELINE_UNAVAILABLE');
    const before = {
        reverse: orderedByTags(portalLinks.filter(row => row.mode !== 'forward'), current.reverse?.portals || [], row => `portal-${short(row)}`),
        forward: orderedByTags(forwardLinks, current.outbounds, row => `fwd-${short(row)}`),
        hops: orderedByTags(hopLinks.filter(row => row.mode === 'forward'), current.inbounds || [], row => `fwd-hop-${short(row)}`),
    };
    const artifacts = mainArtifacts(node, before);
    verifyArtifacts(current, artifacts);
    const selected = new Set(selectedLinkIds.map(String)), excluded = new Set(excludeLinkIds.map(String));
    // A desired reverse upstream (even "online") does not prove the sidecar
    // owns any listeners. Recognize that profile under the same held SSH scope
    // before removing exact old MAIN duplicates or moving a removed upstream's
    // installed downstreams back to MAIN. Never select a save-only neighbor.
    const sidecar = bridgeCurrent ? selectClassicBridge({ current: bridgeCurrent,
        links: hopLinks.filter(row => row.mode !== 'forward'),
        downstreamLinks: portalLinks.filter(row => row.mode !== 'forward'), allowEmpty: true }) : null;
    const sidecarDownstream = sidecar?.downstreamLinks || [];
    const transit = sidecar?.links.some(row => !excluded.has(id(row)));
    const restoreMainPortals = sidecar?.links.length && !transit && sidecar.links.some(row => excluded.has(id(row)));
    const overlay = (installed, candidates) => {
        const rows = installed.filter(row => !excluded.has(id(row)));
        for (const row of candidates) if (selected.has(id(row)) && !excluded.has(id(row)) && !rows.some(value => id(value) === id(row))) rows.push(row);
        return rows;
    };
    const after = {
        reverse: overlay(restoreMainPortals ? [...before.reverse, ...sidecarDownstream.filter(row => !before.reverse.some(value => id(value) === id(row)))]
            : before.reverse, portalLinks.filter(row => row.mode !== 'forward'))
            .filter(row => !transit || !sidecarDownstream.some(value => id(value) === id(row))),
        forward: overlay(before.forward, forwardLinks.filter(row => id(row.portalNode) === id(node)
            || before.forward.some(installed => id(installed.bridgeNode) === id(row.portalNode)))),
        hops: overlay(before.hops, hopLinks.filter(row => row.mode === 'forward')),
    };
    const unchanged = Object.keys(before).every(key => equal(before[key].map(id), after[key].map(id)));
    const next = unchanged ? artifacts : mainArtifacts(node, after);
    return { ...after, compose: base => composeProfile(current, artifacts, next, base) };
}

// Remove only exactly recognized generator artifacts, retaining arbitrary clients,
// keys, unrelated rules and profile fields. New base settings are still allowed;
// a tag collision with an unrecognized cascade artifact has already refused.
function composeProfile(current, before, after, base = empty()) {
    const result = clone(current);
    const afterTags = new Set(sections(after).flat().map(row => row.tag));
    const beforeTags = new Set(sections(before).flat().filter(row => owned(row.tag)
        || ['cascade-balancer', 'down-balancer'].includes(row.tag)).map(row => row.tag));
    if (current.routing.rules.some(rule => beforeTags.has(rule.outboundTag) && !afterTags.has(rule.outboundTag)
        && !before.routing.rules.some(row => equal(row, rule)))) throw fail('CLASSIC_APPLIED_DEPENDENT_RULE');
    const oldSections = sections(before), newSections = sections(after), resultSections = sections(result);
    for (let i = 0; i < resultSections.length; i++) {
        const rows = resultSections[i];
        for (let n = rows.length - 1; n >= 0; n--) if ((i === 2 || i === 3 || owned(rows[n].tag)
            || ['cascade-balancer', 'down-balancer'].includes(rows[n].tag))
            && oldSections[i].some(row => equal(row, rows[n]))
            && !newSections[i].some(row => row.tag === rows[n].tag)) rows.splice(n, 1);
    }
    const oldRules = before.routing.rules.filter(ruleOwned);
    const first = result.routing.rules.findIndex(ruleOwned);
    result.routing.rules = result.routing.rules.filter(rule => !oldRules.some(row => equal(row, rule)));
    const mergeRows = (target, incoming) => {
        for (const row of incoming) {
            const index = target.findIndex(value => value.tag === row.tag);
            if (index < 0) target.push(clone(row)); else target[index] = clone(row);
        }
    };
    for (const source of [base, after]) {
        if (source.inbounds?.length) mergeRows(result.inbounds ||= [], source.inbounds);
        mergeRows(result.outbounds, source.outbounds || []);
        for (const section of ['portals', 'bridges']) if (source.reverse?.[section]?.length) {
            mergeRows((result.reverse ||= {})[section] ||= [], source.reverse[section]);
        }
        if (source.routing?.balancers?.length) mergeRows(result.routing.balancers ||= [], source.routing.balancers);
    }
    for (const [key, value] of Object.entries(base)) if (!['inbounds', 'outbounds', 'routing', 'reverse'].includes(key)) result[key] = clone(value);
    const newRules = after.routing.rules.filter(ruleOwned);
    result.routing.rules.splice(first < 0 ? result.routing.rules.length : first, 0, ...clone(newRules));
    for (const rule of base.routing?.rules || []) if (!result.routing.rules.some(row => equal(row, rule))) result.routing.rules.push(clone(rule));
    if (after.routing.domainStrategy) result.routing.domainStrategy = after.routing.domainStrategy;
    require('./classicL2tpConfigComposition').finishClassicConfigRouting(result);
    return result;
}

function selectClassicBridge({ current, links, downstreamLinks = [], selectedLinkIds = [], excludeLinkIds = [], allowEmpty = false }) {
    const selected = new Set(selectedLinkIds.map(String)), excluded = new Set(excludeLinkIds.map(String));
    let beforeLinks = [], before = empty();
    const beforeDownstream = orderedByTags(downstreamLinks, current?.reverse?.portals || [], row => `portal-down-${short(row)}`);
    const relay = current?.reverse?.bridges?.some(row => row.tag === 'bridge-up');
    const relayArtifacts = (upstream, downstream) => {
        if (!upstream.length) {
            if (downstream.length) throw fail('CLASSIC_APPLIED_RELAY_WITHOUT_UPSTREAM');
            return empty();
        }
        const [first, ...rest] = upstream;
        return JSON.parse(generator.generateRelayConfig(first, first.portalNode, downstream, [],
            rest.map(link => ({ link, portal: link.portalNode }))));
    };
    if (current) {
        beforeLinks = orderedByTags(links, current.reverse?.bridges || [], row => `bridge-${short(row)}`);
        if (beforeLinks.length) before = JSON.parse(generator.generateCombinedBridgeConfig(beforeLinks));
        if (relay) {
            const extra = orderedByTags(links, current.reverse.bridges, row => `bridge-up-${short(row)}`);
            const matches = links.filter(row => !extra.some(value => id(value) === id(row))).filter(row => {
                try { verifyArtifacts(current, relayArtifacts([row, ...extra], beforeDownstream)); return true; } catch { return false; }
            });
            if (matches.length !== 1) throw fail('CLASSIC_APPLIED_ARTIFACT_MISMATCH');
            beforeLinks = [matches[0], ...extra]; before = relayArtifacts(beforeLinks, beforeDownstream);
        }
        // Accept the actual older single-bridge layout without changing keys or
        // domains. No import/store/ownership protocol is involved.
        if (!beforeLinks.length && current.reverse?.bridges?.some(row => row.tag === 'bridge')) {
            const matches = links.filter(row => {
                try { verifyArtifacts(current, JSON.parse(generator.generateBridgeConfig(row, row.portalNode))); return true; } catch { return false; }
            });
            if (matches.length !== 1) throw fail('CLASSIC_APPLIED_ARTIFACT_MISMATCH');
            beforeLinks = matches; before = JSON.parse(generator.generateBridgeConfig(matches[0], matches[0].portalNode));
        } else verifyArtifacts(current, before);
    }
    const afterLinks = beforeLinks.filter(row => !excluded.has(id(row)));
    for (const row of links) if (selected.has(id(row)) && !excluded.has(id(row)) && !afterLinks.some(value => id(value) === id(row))) afterLinks.push(row);
    const afterDownstream = beforeDownstream.filter(row => !excluded.has(id(row)));
    for (const row of downstreamLinks) if (selected.has(id(row)) && !excluded.has(id(row))
        && !afterDownstream.some(value => id(value) === id(row))) afterDownstream.push(row);
    if (!afterLinks.length && !allowEmpty) throw fail('CLASSIC_APPLIED_NO_REVERSE_LINKS');
    const after = equal(beforeLinks.map(id), afterLinks.map(id)) && equal(beforeDownstream.map(id), afterDownstream.map(id)) ? before
        : relay || afterDownstream.length ? relayArtifacts(afterLinks, afterDownstream)
            : afterLinks.length ? JSON.parse(generator.generateCombinedBridgeConfig(afterLinks)) : empty();
    return { links: afterLinks, downstreamLinks: afterDownstream,
        compose: () => current ? composeProfile(current, before, after) : after };
}

function selectClassicForwardHop({ current, links, selectedLinkIds = [], excludeLinkIds = [] }) {
    const artifacts = rows => rows.length ? JSON.parse(generator.generateForwardHopConfig(rows)) : empty();
    const beforeLinks = orderedByTags(links, current?.inbounds || [], row => `cascade-in-${short(row)}`);
    const before = artifacts(beforeLinks);
    if (current) verifyArtifacts(current, before);
    const selected = new Set(selectedLinkIds.map(String)), excluded = new Set(excludeLinkIds.map(String));
    const afterLinks = beforeLinks.filter(row => !excluded.has(id(row)));
    for (const row of links) if (selected.has(id(row)) && !excluded.has(id(row)) && !afterLinks.some(value => id(value) === id(row))) afterLinks.push(row);
    const after = equal(beforeLinks.map(id), afterLinks.map(id)) ? before : artifacts(afterLinks);
    return { links: afterLinks, compose: () => current ? composeProfile(current, before, after) : after };
}

module.exports = { MAIN, BRIDGE, readClassicProfile, selectClassicMain, selectClassicBridge, selectClassicForwardHop };
