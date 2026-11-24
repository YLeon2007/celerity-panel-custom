(function () {
    'use strict';

    const previewRoles = ['portal', 'bridge', 'relay', 'standalone'];
    const previewSections = ['inbounds', 'outbounds', 'routing', 'reverse', 'log', 'api', 'stats', 'policy', 'dns', 'observatory'];
    // In Russian the verb can agree with the first named section.
    const pluralPreviewSections = new Set(['routing', 'reverse', 'policy']);
    const exitWarningKeys = new Map([['lost', 'exitLost'], ['blocked', 'exitBlocked'], ['default-lost', 'defaultExitLost']]);
    let previewDialogPending = false;

    function rebuildPreviewText(nodes, removing, lookupNode, labels) {
        const details = [], warnings = [];
        let protectedChanged = false;
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
            if (node.profiles.some(profile => profile.tunnelMigration === 'legacy-to-vless-reverse')) lines.push(labels.migration);
            details.push(lines.join('\n'));
            const warningKey = removing && exitWarningKeys.get(node.exitImpact);
            if (warningKey) warnings.push(labels[warningKey].replace('{name}', () => name));
        });
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

    async function showRefusal(message) {
        const labels = window._networkRebuildPreviewI18n;
        if (!labels) return;
        await showRebuildPreview({ title: labels.refused, warning: message || labels.unavailable,
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
        const text = rebuildPreviewText(report.nodes, removing, lookupNode, labels);
        const allowed = report.allowed && !text.protectedChanged;
        if (allowed && (typeof previewId !== 'string' || ![64, 128].includes(previewId.length) || /[^a-f0-9]/.test(previewId))) {
            return stop(labels.unavailable);
        }
        const title = allowed ? (removing ? labels.removeTitle : labels.deployTitle) : labels.refused;
        const applyLabel = removing ? labels.remove : labels.apply;
        const accepted = await showRebuildPreview({ title, ...text, allowed, applyLabel }, labels);
        return allowed && accepted === true ? previewId : stop(allowed ? labels.cancelled : title);
    }

    window.C3RebuildPreview = Object.freeze({ confirmReport, showRefusal });
})();
