(function () {
    'use strict';

    const previewRoles = ['portal', 'bridge', 'relay', 'standalone'];
    const previewSections = ['inbounds', 'outbounds', 'routing', 'reverse', 'log', 'api', 'stats', 'policy', 'dns', 'observatory'];
    // In Russian the verb can agree with the first named section.
    const pluralPreviewSections = new Set(['routing', 'reverse', 'policy']);
    const exitWarningKeys = new Map([['lost', 'exitLost'], ['blocked', 'exitBlocked'], ['default-lost', 'defaultExitLost']]);
    let previewDialogPending = false;

    const publicId = value => typeof value === 'string' && value.length === 24 && /^[a-f0-9]+$/i.test(value);
    const channelRef = value => typeof value === 'string' && /^[a-f0-9]{8}(?![\s\S])/.test(value);
    const oneLine = value => typeof value === 'string' ? value.replace(/[\s\p{Cc}\p{Bidi_Control}]+/gu, ' ').trim().slice(0, 120) : '';

    function exitName(exit, lookupNode, labels) {
        if (exit === null) return labels.noPortalExit;
        if (!publicId(exit?.nodeId)) return labels.unknownPortalExit;
        const name = [exit.name, lookupNode(exit.nodeId)?.label].map(oneLine)
            .find(value => value && value.toLowerCase() !== exit.nodeId.toLowerCase()) || labels.unknownPortalExit;
        const suffix = publicId(exit.linkId) ? exit.linkId.slice(-8) : channelRef(exit.channelRef) ? exit.channelRef : null;
        if (!suffix) return name;
        const label = oneLine(exit.linkName);
        const shortId = '#' + suffix;
        return `${name} (${label ? `${label} · ${shortId}` : shortId})`;
    }

    function rebuildPreviewText(nodes, removing, lookupNode, labels, transit) {
        const details = [], warnings = [];
        let protectedChanged = false;
        let mainRestart = false;
        const listFormat = typeof Intl.ListFormat === 'function' ? new Intl.ListFormat(labels.lang) : null;
        nodes.forEach((node, index) => {
            const inventory = lookupNode(node.nodeId);
            // Render the name as a single line even in the plain-text fallback.
            const label = typeof inventory?.label === 'string'
                ? inventory.label.replace(/[\s\p{Cc}\p{Bidi_Control}]+/gu, ' ').trim() : '';
            const name = label && label !== node.nodeId ? label : labels.unknownNode.replace('{number}', index + 1);
            const role = previewRoles.includes(node.role) ? node.role
                : previewRoles.includes(inventory?.role) ? inventory.role : 'standalone';
            const changed = node.profiles.filter(profile => profile.change !== 'unchanged');
            const sections = new Set(changed.flatMap(profile => profile.sections));
            const namedSections = previewSections.filter(section => sections.has(section));
            const sectionLabels = namedSections.map(section => labels[section]);
            const changes = pluralPreviewSections.has(namedSections[0]) ? labels.changesPlural : labels.changes;
            const summary = sectionLabels.length
                ? changes.replace('{sections}', listFormat?.format(sectionLabels) ?? sectionLabels.join(', '))
                : changed.length ? labels.otherChanges : labels.unchanged;
            const settingsChanged = node.profiles.some(profile => profile.protectedChanged === true);
            protectedChanged ||= settingsChanged;
            const lines = [name + ' — ' + labels[role] + ': ' + summary,
                settingsChanged ? labels.settingsChanged : labels.settingsUnchanged];
            if (node.routingServiceRequired === true && labels.routingServiceRequired) lines.push(labels.routingServiceRequired);
            if (labels.mainRestartCount && Number.isSafeInteger(node.mainRestartCount) && node.mainRestartCount > 0) {
                mainRestart = true;
                lines.push(labels.mainRestartCount.replace('{count}', node.mainRestartCount));
            }
            if (node.profiles.some(profile => profile.tunnelMigration === 'legacy-to-vless-reverse')) lines.push(labels.migration);
            if (transit) {
                const changes = { create: labels.transitCreate, replace: labels.transitReplace, unchanged: labels.unchanged };
                for (const { profile, change } of node.profiles) {
                    if (profile === 'main' || profile === 'bridge') lines.push(`${profile.toUpperCase()}: ${changes[change]}`);
                }
            }
            const path = node.portalExitPath;
            const formatPath = hops => Array.isArray(hops) && hops.length
                ? hops.map(hop => exitName(hop, lookupNode, labels)).join(' → ') : labels.unknownPortalExit;
            if (role === 'portal' && labels.transitPath && path) {
                lines.push(labels.transitPath.replace(/\{(before|after)\}/g, (_, key) => formatPath(path[key])));
            }
            const geoPaths = node.portalExitGeoPaths;
            if (role === 'portal' && labels.transitGeoPaths && Array.isArray(geoPaths?.before) && Array.isArray(geoPaths.after)) {
                const formatPaths = list => list.map(formatPath).join('; ') || '—';
                lines.push(labels.transitGeoPaths.replace(/\{(before|after)\}/g, (_, key) => formatPaths(geoPaths[key])));
            }
            if (labels.transitListeners && Array.isArray(node.transitListeners)) {
                const port = value => Number.isInteger(value) && value > 0 && value <= 65535 ? String(value) : '—';
                for (const listener of node.transitListeners) {
                    const suffix = publicId(listener?.channelId) ? listener.channelId.slice(-8)
                        : channelRef(listener?.channelRef) ? listener.channelRef : null;
                    if (suffix) lines.push(`${labels.transitListeners} #${suffix}: ${port(listener.before)} → ${port(listener.after)}`);
                }
            }
            const exitChange = node.portalExitChange;
            const hasChannels = publicId(exitChange?.before?.linkId) && publicId(exitChange?.after?.linkId);
            const defaultLabel = labels.portalExitChange || (hasChannels && labels.portalExitChannelChange);
            if (defaultLabel && role === 'portal' && exitChange
                && Object.hasOwn(exitChange, 'before') && Object.hasOwn(exitChange, 'after')) {
                const exits = Object.fromEntries(['before', 'after'].map(key => [key, exitName(exitChange[key], lookupNode, labels)]));
                if (exitChange.before?.nodeId !== exitChange.after?.nodeId || exits.before !== exits.after
                    || (hasChannels && exitChange.before.linkId !== exitChange.after.linkId)) {
                    lines.push(defaultLabel.replace(/\{(before|after)\}/g, (_, key) => exits[key]));
                }
                const geo = node.portalExitRelayGeoChange;
                if (labels.portalExitChange && typeof geo?.before === 'boolean' && typeof geo.after === 'boolean' && geo.before !== geo.after) {
                    lines.push(geo.after ? labels.portalExitRelayGeoOn : labels.portalExitRelayGeoOff);
                }
            }
            const geo = node.portalExitGeoChange;
            if (role === 'portal' && labels.portalExitGeo && Array.isArray(geo?.before) && Array.isArray(geo.after)) {
                const format = exits => {
                    const names = exits.map(exit => exitName(exit, lookupNode, labels));
                    return names.length ? (listFormat?.format(names) ?? names.join(', ')) : '—';
                };
                const before = format(geo.before), after = format(geo.after);
                // The matcher changed even if the safe exit labels are identical.
                const summary = before === after ? labels.changesPlural.replace('{sections}', () => labels.routing) : `${before} → ${after}`;
                lines.push(`${labels.portalExitGeo}: ${summary}`);
            }
            details.push(lines.join('\n'));
            const warningKey = removing && exitWarningKeys.get(node.exitImpact);
            if (warningKey) warnings.push(labels[warningKey].replace('{name}', () => name));
        });
        if (mainRestart && labels.mainRestartWarning) warnings.unshift(labels.mainRestartWarning);
        return { details: details.join('\n\n'), warning: warnings.join('\n\n'), protectedChanged };
    }

    async function showRebuildPreview({ title, warning, details, allowed, applyLabel }, labels) {
        const dialog = document.getElementById('rebuildPreview');
        // Never replace a pending question with a different Preview.
        if (previewDialogPending || dialog?.open) return false;
        if (typeof dialog?.showModal !== 'function') {
            const text = [warning, title, details].filter(Boolean).join('\n\n');
            if (!allowed) { window.alert(text); return false; }
            return window.confirm(text);
        }
        const get = suffix => document.getElementById('rebuildPreview' + suffix);
        const warningElement = get('Warning'), apply = get('Apply'), cancel = get('Cancel');
        get('Title').textContent = title;
        get('Details').textContent = details;
        warningElement.textContent = warning;
        warningElement.hidden = !warning;
        apply.textContent = applyLabel;
        apply.hidden = !allowed;
        cancel.textContent = allowed ? labels.cancel : labels.close;
        previewDialogPending = true;
        try {
            const approved = new Promise(resolve => {
                let accepted = false;
                dialog.onclose = () => resolve(accepted);
                cancel.onclick = () => dialog.close();
                apply.onclick = () => {
                    if (!allowed || !dialog.open) return;
                    accepted = true;
                    dialog.close();
                };
                dialog.showModal();
                get('Body').scrollTop = 0;
            });
            return await approved;
        } finally {
            dialog.onclose = apply.onclick = cancel.onclick = null;
            previewDialogPending = false;
        }
    }

    function validReportShape(report) {
        if (typeof report?.allowed !== 'boolean' || !Array.isArray(report.nodes)) return false;
        for (const node of report.nodes) {
            if (typeof node?.nodeId !== 'string' || !node.nodeId || !Array.isArray(node.profiles) || !node.profiles.length) return false;
            for (const profile of node.profiles) {
                if (!['create', 'replace', 'unchanged'].includes(profile?.change) || typeof profile.protectedChanged !== 'boolean'
                    || !Array.isArray(profile.sections)) return false;
                for (const section of profile.sections) if (typeof section !== 'string') return false;
            }
        }
        return true;
    }

    const managerProperties = new Set([
        'RequiredBy', 'RequisiteOf', 'BoundBy', 'UpheldBy', 'ConsistsOf', 'TriggeredBy',
        'PropagatesStopTo', 'PropagatesReloadTo', 'StopPropagatedFrom', 'OnSuccess', 'OnFailure',
        'StopWhenUnneeded', 'RefuseManualStop', 'RefuseManualStart', 'Requires', 'BindsTo',
        'Wants', 'Conflicts', 'ConflictedBy', 'ActiveState', 'PartOf', 'Triggers', 'Upholds', 'Requisite',
    ]);
    const managerChecks = new Set(['list-jobs', 'active-invocations', 'shutdown.target:ActiveState',
        ...['cc-agent.service', 'xray.service'].flatMap(unit => [...managerProperties].map(key => `${unit}:${key}`))]);
    function describeManagerChecks(detail) {
        if (detail?.reason !== 'REBUILD_MAIN_AUTHORITY_UNPROVED' || !Array.isArray(detail.checks) ||
            !detail.checks.length || detail.checks.length > managerChecks.size) return '';
        const checks = [...new Set(detail.checks)];
        return checks.every(check => managerChecks.has(check)) ? `(${checks.join(', ')})` : '';
    }

    // Use page-local copy and fixed check IDs only, never the HTTP message.
    function describeApplyFailure(status, error) {
        const labels = window._networkRebuildPreviewI18n;
        const copy = labels?.mainCutover;
        if (status !== 409 || !copy) return null;
        if (error?.code === 'REBUILD_MAIN_ROUTING_SERVICE_REQUIRED' && error.retryAllowed === false) {
            return { title: labels.refused, message: labels.routingServiceRequired };
        }
        if (error?.code === 'REBUILD_SCOPED_TRANSIT_APPLY_UNAVAILABLE') {
            return { title: labels.refused, message: copy.guardedPreflight };
        }
        if (error?.code === 'REBUILD_MAIN_CUTOVER_HANDBACK_UNCONFIRMED' &&
            error.outcome === 'handback-unconfirmed' && error.retryAllowed === false) {
            return { title: labels.refused, message: copy.handbackUnconfirmed };
        }
        const lookup = (map, key) => map && typeof key === 'string' && Object.hasOwn(map, key) ? map[key] : '';
        const settled = error?.code === 'REBUILD_MAIN_CUTOVER_ROLLED_BACK' && error.outcome === 'rolled-back' ? copy.rolledBack
            : error?.code === 'REBUILD_MAIN_CUTOVER_NOT_DISPATCHED' && error.outcome === 'not-dispatched' ? copy.notDispatched : null;
        if (settled && error.retryAllowed === false) return { title: labels.refused,
            message: [settled, lookup(copy.reason, error.failure?.reason), describeManagerChecks(error.failure)].filter(Boolean).join(' ') };
        if (error?.code !== 'REBUILD_MAIN_CUTOVER_UNRESOLVED') return null;
        // Older servers may send just the error code. That is still unknown,
        // but no phase or reason is attributable without the typed envelope.
        const detail = error.outcome === 'unknown' && error.retryAllowed === false ? error.failure : null;
        return { title: copy.title, message: [copy.unknown, lookup(copy.phase, detail?.phase),
            lookup(copy.reason, detail?.reason), describeManagerChecks(detail)].filter(Boolean).join(' ') };
    }

    async function showRefusal(message, title) {
        const labels = window._networkRebuildPreviewI18n;
        if (!labels) return;
        await showRebuildPreview({ title: title || labels.refused, warning: message || labels.unavailable,
            details: '', allowed: false, applyLabel: labels.apply }, labels);
    }

    // Only the legacy map supplies onStop, to retain its localized toast (and
    // saved-draft prefix). Both maps use the same null-or-confirmed-ID result.
    async function confirmReport(options, onStop = undefined) {
        const labels = window._networkRebuildPreviewI18n;
        const { report, removing, lookupNode } = options ?? {};
        const stop = message => { onStop?.(message); return null; };
        if (!labels || typeof removing !== 'boolean' || typeof lookupNode !== 'function' || !validReportShape(report)) {
            return stop(labels?.unavailable);
        }
        const { previewId } = report;
        const text = rebuildPreviewText(report.nodes, removing, lookupNode, labels, report.transitBlocked === true);
        if (report.transitBlocked === true) text.warning = [text.warning, labels.transitBlocked].filter(Boolean).join('\n\n');
        const allowed = report.allowed && !text.protectedChanged && report.transitBlocked !== true &&
            !report.nodes.some(node => node.routingServiceRequired === true);
        if (allowed && (typeof previewId !== 'string' || ![64, 128].includes(previewId.length) || /[^a-f0-9]/.test(previewId))) {
            return stop(labels.unavailable);
        }
        const title = allowed ? (removing ? labels.removeTitle : labels.deployTitle) : labels.refused;
        const applyLabel = removing ? labels.remove : labels.apply;
        const accepted = await showRebuildPreview({ title, ...text, allowed, applyLabel }, labels);
        return allowed && accepted === true ? previewId : stop(allowed ? labels.cancelled : title);
    }

    window.C3RebuildPreview = Object.freeze({ confirmReport, showRefusal, describeApplyFailure });
})();
