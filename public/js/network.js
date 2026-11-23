/**
 * Network topology visualization using cytoscape.js
 * With particle traffic animation and glow effects.
 */

(function () {
    'use strict';

    // ==================== PURE HELPERS (exported for tests) ====================

    // Newly created rebuild links default to Chrome. Edits retain even an empty
    // legacy value unless the operator explicitly selects a fingerprint.
    const CREATE_DEFAULT_FINGERPRINT = 'chrome';
    const REALITY_FINGERPRINTS_26_11 = ['chrome', 'firefox', 'safari'];

    function expireReverseStatus(row, now = Date.now()) {
        if (row.isInternetEdge || row.mode === 'forward' || row.status !== 'online') return row;
        const until = row.observationExpiresAt;
        if (Number.isSafeInteger(until) && now < until && until - now <= 90_000) return row;
        return { ...row, status: 'deployed', tunnelState: 'unknown', lastHealthCheck: null,
            latencyMs: null, observationExpiresAt: undefined };
    }

    function resolveRealityFingerprint(saved, mode) {
        const value = typeof saved === 'string' ? saved : '';
        return mode === 'edit' ? value : (value.trim() || CREATE_DEFAULT_FINGERPRINT);
    }

    function fingerprintForLinkEdit(saved, selected) {
        if (!saved && !selected) return undefined;
        return selected;
    }

    // Backend cause codes -> Russian UI text. Codes are enum-like and safe to
    // display; free-form backend messages are not trusted (see below).
    const TOPOLOGY_CAUSE_TEXT_RU = Object.freeze({
        TOPOLOGY_BUSINESS_REENTRY_BLOCKED: 'Повторное включение any-order после бизнес-операций и возврата управления classic временно недоступно. Схема classic продолжает работать; история и пользователи сохранены.',
        CLASSIC_DEPLOY_UNSUPPORTED: 'Classic поддерживает только отдельный Deploy активной reverse-связи',
        CLASSIC_DEPLOY_BUSY: 'Топология занята или не инициализирована — требуется проверка',
        CLASSIC_DEPLOY_NODE_BUSY: 'Один из узлов связи занят другой операцией. Повторите после её завершения.',
        CLASSIC_DEPLOY_PREFLIGHT_FAILED: 'Предварительная проверка узлов не пройдена. Изменений на узлах не было; повторный деплой доступен.',
        CLASSIC_DEPLOY_SCOPE_CHANGED: 'Состав применённых связей изменился — обновите топологию',
        CLASSIC_DEPLOY_IN_USE: 'Связь используется L2TP или группой маршрутов — classic запрещён',
        CLASSIC_DEPLOY_OWNER_VETO: 'Конфигурация узла принадлежит другому исполнителю',
        CLASSIC_DEPLOY_UNCERTAIN: 'Завершение classic не подтверждено; блокировка сохранена для восстановления',
        CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED: 'Конфигурация применена и проверена, но соединение туннеля не установлено. Проверьте доступность узлов друг для друга. Повторный деплой и удаление доступны.',
        CLASSIC_DEPLOY_FENCE_LOST: 'Владение блокировкой classic не подтверждено — требуется проверка',
        CLASSIC_DEPLOY_PORT_CONFLICT: 'Порт туннеля уже занят на слушающем узле. Выберите другой порт и повторите деплой.',
        TUNNEL_PORT_IN_USE: 'Порт туннеля уже занят на слушающем узле. Выберите другой порт и повторите деплой.',
        INVALID_REQUEST: 'Некорректный запрос',
        INVALID_TOPOLOGY_REVISION: 'Некорректная ревизия топологии',
        STALE_TOPOLOGY_REVISION: 'Топология изменилась — обновите данные и повторите',
        INVALID_TOPOLOGY_DEPLOYMENT: 'Топология не прошла проверку',
        NODE_DEPLOY_FAILED: 'Не удалось применить конфигурацию на узле',
        NODE_VERIFICATION_FAILED: 'Узел не прошёл проверку после деплоя',
        NODE_DEPLOYER_CONTRACT_VIOLATION: 'Узел вернул некорректный результат деплоя',
        DEPLOYED_REVISION_UPDATE_FAILED: 'Не удалось зафиксировать применённую ревизию',
        TOPOLOGY_DEPLOYMENT_FAILED: 'Деплой топологии завершился ошибкой',
        TOPOLOGY_OPERATION_QUEUE_FAILED: 'Не удалось поставить операцию в очередь',
        TOPOLOGY_DEPLOYMENT_UNAVAILABLE: 'Сервис деплоя топологии недоступен',
        TOPOLOGY_DEPLOY_RATE_LIMITED: 'Слишком много запросов на деплой — повторите позже',
        TOPOLOGY_DEPLOY_BUSY: 'Другая операция топологии уже выполняется — дождитесь завершения, обновите топологию и повторите вручную',
        TOPOLOGY_OPERATION_BUSY: 'Другая операция топологии уже выполняется — дождитесь завершения, обновите топологию и повторите вручную',
        TOPOLOGY_DEPLOYMENT_BUSY: 'Другая операция топологии уже выполняется — дождитесь завершения, обновите топологию и повторите вручную',
        OPERATION_IN_PROGRESS: 'Другая операция уже выполняется — дождитесь завершения, обновите топологию и повторите вручную',
        SCOPE_LINK_MISSING: 'Связь отсутствует в зафиксированной топологии',
        SCOPE_LINK_UNCONFIRMED: 'Базовая связь ещё не подтверждена как применённая — сначала выполните отдельный Deploy этой связи, дождитесь завершения и повторите Sync применённого домена',
        UNCONFIRMED_LINK_IN_FULL_DEPLOY: 'Есть ожидающие связи: используйте отдельный деплой связи, не синхронизируйте всю топологию',
        USER_SYNC_UNAVAILABLE: 'Синхронизация пользователей Xray недоступна: готовность не подтверждена',
        L2TP_PPP_READBACK_UNAVAILABLE: 'Проверка пользователей PPP на реле недоступна: готовность не подтверждена',
        L2TP_PPP_CHAP_SECRETS_DRIFT: 'Данные PPP на реле отличаются от ожидаемых: требуется повторная синхронизация',
        SCOPE_GROUP_CONFLICT: 'Группа маршрутов пересекает границу выбранного участка',
        INCOMPLETE_REALITY_PARAMETERS: 'Неполные параметры REALITY',
        INVALID_TOPOLOGY_ROLES: 'Некорректные роли узлов в топологии',
        MISSING_NODE_ROLE: 'У узла не задана роль',
        INVALID_TUNNEL_PORT: 'Некорректный порт туннеля',
        INVALID_NODE_CONFIG: 'Некорректная конфигурация узла',
    });

    function topologyCauseText(code) {
        if (typeof code !== 'string' || !code) return null;
        if (code === 'CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED') {
            return (typeof window !== 'undefined' && window._networkI18n?.classicTunnelUnconfirmed)
                || TOPOLOGY_CAUSE_TEXT_RU[code];
        }
        if (['CLASSIC_DEPLOY_PORT_CONFLICT', 'TUNNEL_PORT_IN_USE'].includes(code)) {
            return (typeof window !== 'undefined' && window._networkI18n?.portCheckDeployConflict)
                || TOPOLOGY_CAUSE_TEXT_RU[code];
        }
        return TOPOLOGY_CAUSE_TEXT_RU[code] || null;
    }

    // Free-form backend messages can contain short credentials, not just long
    // key-like tokens. Show only known diagnostics or a bounded machine code.
    function describeTopologyError(payload, fallback) {
        const err = payload && payload.error;
        const validationCode = Array.isArray(payload && payload.errors)
            && payload.errors[0] && typeof payload.errors[0].code === 'string'
            ? payload.errors[0].code
            : null;
        const causeCode = (err && err.causeCode)
            || (payload && payload.causeCode)
            || validationCode
            || (err && err.code)
            || null;
        const mapped = topologyCauseText(causeCode);
        if (mapped) return mapped + ' (' + causeCode + ')';
        if (typeof causeCode === 'string' && /^[A-Z][A-Z0-9_]{1,64}$/.test(causeCode)) {
            return 'Операция не выполнена (' + causeCode + ')';
        }
        return fallback || 'Операция не выполнена';
    }

    // Operation-specific polling: while a queued topology operation is in
    // flight, refresh faster than the global 30s status loop. Bounded by a
    // finite attempt budget and driven by a self-terminating setTimeout chain,
    // so it can never leave an infinite timer behind.
    const OPERATION_POLL_INTERVAL_MS = 3000;
    // Native per-node proof/settlement can exceed the former two-minute UI
    // window. Keep exact-operation reads finite through a 30-minute budget;
    // the global topology list is not a substitute for terminal operation proof.
    const OPERATION_POLL_MAX_ATTEMPTS = 600;
    const TRACKED_OPERATION_STATUSES = ['queued', 'preparing', 'committing', 'rolling_back', 'succeeded'];

    function shouldContinueOperationPolling(state = {}) {
        const attempt = Number.isSafeInteger(state.attempt) ? state.attempt : 0;
        const maxAttempts = Number.isSafeInteger(state.maxAttempts)
            ? state.maxAttempts
            : OPERATION_POLL_MAX_ATTEMPTS;
        if (attempt >= maxAttempts) return false;
        if (state.status === 'succeeded') {
            return state.clientReadiness !== 'verified' && state.clientProofState !== 'degraded';
        }
        return !['failed', 'rolled_back'].includes(state.status);
    }

    const CLIENT_READINESS_UNVERIFIED = 'Готовность клиента не подтверждена';

    // Optional UI projection only: an applied topology or green edge is not
    // client evidence. Until the API supplies a revision-bound successful
    // probe, the drawer explicitly reports unknown rather than inferring ready.
    function clientReadinessMessage(proof, topologyRevision, deployedRevision) {
        if (Number.isSafeInteger(topologyRevision) && topologyRevision >= 0
            && Number.isSafeInteger(deployedRevision) && deployedRevision >= 0
            && proof?.topologyRevision === topologyRevision
            && proof.priorDeployedRevision === deployedRevision
            && proof.status === 'ready' && proof.clientProbe === 'passed') {
            return 'Готовность подтверждена проверкой клиента';
        }
        return CLIENT_READINESS_UNVERIFIED;
    }

    function isCompletedClassicDeploymentResult(result, revision) {
        return !!result && result.status === 'succeeded' && result.executionMode === 'classic'
            && Number.isSafeInteger(revision) && revision >= 0 && result.topologyRevision === revision
            && Object.keys(result).sort().join(',') === 'executionMode,status,topologyRevision';
    }

    function deployResultMessage(result, labels = {}) {
        const job = result?.job || result?.autoDeployJob;
        if (job?.jobId) return (labels.jobAccepted || 'Намерение сохранено; задание принято. Применение ещё не подтверждено.') + ' ' + job.jobId;
        const outcome = isCompletedClassicDeploymentResult(result, result.topologyRevision)
            ? (labels.classicLinkApplied || 'Связь применена (classic)')
            : result.status === 'succeeded'
                ? (labels.operationApplied || 'Конфигурация применена')
                : result.status === 'queued'
                    ? (labels.deployQueued || 'Deployment queued')
                    : (labels.deployInProgress || 'Деплой выполняется');
        return outcome + ' — ' + (labels.clientReadinessUnverified || CLIENT_READINESS_UNVERIFIED);
    }

    function renderBusinessReentryRestriction(policy, document) {
        const notice = document.getElementById('topologyReentryNotice');
        if (!notice) return;
        const blocked = policy?.blocked === true && policy.code === 'TOPOLOGY_BUSINESS_REENTRY_BLOCKED';
        notice.hidden = !blocked;
        notice.querySelector('button').disabled = true;
        notice.querySelector('[role="status"]').textContent = blocked
            ? TOPOLOGY_CAUSE_TEXT_RU.TOPOLOGY_BUSINESS_REENTRY_BLOCKED : '';
    }

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            CREATE_DEFAULT_FINGERPRINT,
            OPERATION_POLL_INTERVAL_MS,
            OPERATION_POLL_MAX_ATTEMPTS,
            TOPOLOGY_CAUSE_TEXT_RU,
            clientReadinessMessage,
            deployResultMessage,
            isCompletedClassicDeploymentResult,
            expireReverseStatus,
            describeTopologyError,
            fingerprintForLinkEdit,
            resolveRealityFingerprint,
            shouldContinueOperationPolling,
            topologyCauseText,
            renderBusinessReentryRestriction,
        };
    }

    if (typeof cytoscape === 'undefined') return;

    if (typeof cytoscapeDagre !== 'undefined') {
        cytoscape.use(cytoscapeDagre);
    }

    const i18n = window._networkI18n || {};
    let csrfToken = window._networkCsrfToken || '';
    const rebuild = window._c3Rebuild === true;
    const previewLabels = window._networkRebuildPreviewI18n;
    const fingerprintLabels = previewLabels?.fingerprint;
    const csrfMessages = new Map([
        ['CSRF_TOKEN_INVALID', i18n.csrfTokenInvalid || 'Reload the topology page, sign in again if needed, then retry manually.'],
        ['CSRF_AUTH_REQUIRED', i18n.csrfAuthRequired || 'Sign in to the panel again, reopen the topology, then retry manually.'],
        ['CSRF_ORIGIN_INVALID', i18n.csrfOriginInvalid || 'Open the topology at the panel’s configured address before retrying. If this persists, check the proxy scheme and host.'],
    ]);
    let csrfRead;

    class TopologyCsrfRejection extends Error {}
    class RebuildPreviewStopped extends Error {}
    class RebuildFingerprintRefusal extends Error {}

    // /api/nodes normally holds the numeric version extracted by the agent.
    // Accept only that or an exact Xray banner, never an embedded number.
    function xrayVersionHint(value) {
        if (typeof value !== 'string') return '';
        const number = /^(\d{1,4}\.\d{1,4}\.\d{1,4})$/;
        const banner = /^Xray (\d{1,4}\.\d{1,4}\.\d{1,4})(?: \(Xray, Penetrates Everything\.\)(?: [a-f0-9]{7,64} \(go[0-9.]+ [a-z0-9]+\/[a-z0-9]+\))?)?$/;
        const text = value.trim();
        return (number.exec(text) || banner.exec(text))?.[1] || '';
    }

    const fingerprintInventory = { main: new Map(), quick: new Map() };
    function readFingerprintInventory(nodes) {
        return new Map(nodes.filter(n => typeof n?._id === 'string').map(n => [n._id, {
            name: typeof n.name === 'string' ? n.name : '', version: xrayVersionHint(n.xrayVersion),
        }]));
    }

    function fingerprintCopy(key, values) {
        return fingerprintLabels[key].replace(/\{(\w+)\}/g, (_, name) => values[name] ?? '');
    }

    function fingerprintRefusal(status, payload) {
        if (!rebuild || status !== 409 || payload?.error?.code !== 'REBUILD_REALITY_FINGERPRINT_UNSUPPORTED') return '';
        const issue = payload.fingerprintIssue;
        if (!fingerprintLabels) return payload.error.code;
        if (!issue || typeof issue.dialerId !== 'string') return fingerprintLabels.refused;
        const id = issue.dialerId;
        const name = fingerprintInventory.main.get(id)?.name || fingerprintInventory.quick.get(id)?.name
            || _allNodes.get(id)?.label || id;
        const allowed = Array.isArray(issue.allowed) && issue.allowed.length > 0
            && issue.allowed.every(fp => typeof fp === 'string' && /^[a-z][a-z0-9-]{0,31}$/.test(fp))
            ? issue.allowed : REALITY_FINGERPRINTS_26_11;
        return fingerprintCopy('serverMismatch', { name, version: xrayVersionHint(issue.version) || fingerprintLabels.unknownVersion,
            fingerprint: typeof issue.fingerprint === 'string' && issue.fingerprint || fingerprintLabels.unset,
            allowed: allowed.join(', ') });
    }

    function neighborRefusal(status, error) {
        const labels = previewLabels?.neighbor;
        if (!rebuild || !labels || status !== 409 || error?.code !== 'REBUILD_RETIRE_NEIGHBOR_REFUSED') return '';
        const name = typeof error.neighborName === 'string' && error.neighborName.length <= 160
            && /^[\p{L}\p{M}\p{N} ._()#–—-]+(?![\s\S])/u.test(error.neighborName) ? error.neighborName : labels.neighborUnknown;
        const detail = error.reason === 'RUNTIME_FOREIGN_CHANGE' ? labels.neighborRuntimeForeignChange
            : error.reason === 'NETWORK_OBSERVATION_REQUIRED' ? labels.neighborNetworkNotReady : '';
        return labels.neighborRefused.replace('{name}', () => name) + (detail ? ' ' + detail : '');
    }

    async function fetchInPanel(path, options) {
        const url = new URL(path, window.location.origin);
        if (url.origin !== window.location.origin || url.username || url.password) throw new Error('Invalid panel URL');
        const response = await fetch(url.href, { ...options, mode: 'same-origin', credentials: 'same-origin', redirect: 'error' });
        if (response.redirected || response.url !== url.href) throw new Error('Unexpected panel response URL');
        return response;
    }

    function isJson(response) {
        return /^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '');
    }

    async function rereadCsrfToken(rejectedToken) {
        // Share a pending read across concurrent refusals. A late refusal of
        // the old token must not overwrite a refresh that already succeeded.
        if (csrfToken !== rejectedToken) return true;
        if (!csrfRead) {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);
            csrfRead = (async () => {
                const response = await fetchInPanel('/api/cascade/rebuild/csrf-token', {
                    method: 'GET', cache: 'no-store', signal: controller.signal,
                });
                if (response.status !== 200 || !isJson(response)) return false;
                const data = await response.json();
                const token = data?.csrfToken;
                if (data?.csrfRequired !== true || typeof token !== 'string' || token.length !== 43
                    || !/^[A-Za-z0-9_-]+$/.test(token) || token === rejectedToken) return false;
                csrfToken = token;
                return true;
            })().catch(() => false).finally(() => {
                clearTimeout(timeout);
                csrfRead = undefined;
            });
        }
        return csrfRead;
    }

    async function fetchTopologyWrite(path, options, sentToken = csrfToken) {
        if (!rebuild) return fetch(path, options);
        const response = await fetchInPanel(path, { ...options, headers: { ...options.headers, 'x-csrf-token': sentToken } });
        if (response.status !== 403 || !isJson(response)) return response;
        const payload = await response.clone().json().catch(() => null);
        // requirePanelCsrf rejects before the handler with a top-level code;
        // nested operation errors and other 403s don't prove a CSRF refusal.
        if (payload?.error !== 'CSRF validation failed' || Object.keys(payload).length !== 2
            || !csrfMessages.has(payload.code)) return response;
        const refreshed = payload.code === 'CSRF_TOKEN_INVALID' && await rereadCsrfToken(sentToken);
        const message = refreshed
            ? (i18n.csrfTokenRefreshed || 'The session token was refreshed. Review the topology. Retry the action manually.')
            : csrfMessages.get(payload.code);
        // Never resend a submitted action, even with a new token: the current
        // session may have changed and a prior step may already have saved data.
        throw new TopologyCsrfRejection(message + ' (' + payload.code + ')');
    }

    const previewRoles = ['portal', 'bridge', 'relay', 'standalone'];
    const previewSections = ['inbounds', 'outbounds', 'routing', 'reverse', 'log', 'api', 'stats', 'policy', 'dns', 'observatory'];
    // In Russian the verb can agree with the first named section.
    const pluralPreviewSections = new Set(['routing', 'reverse', 'policy']);
    const exitWarningKeys = new Map([['lost', 'exitLost'], ['blocked', 'exitBlocked'], ['default-lost', 'defaultExitLost']]);
    let previewDialogPending = false;

    function rebuildPreviewText(nodes, removing) {
        const labels = previewLabels;
        const details = [], warnings = [];
        let protectedChanged = false;
        const listFormat = typeof Intl.ListFormat === 'function' ? new Intl.ListFormat(labels.lang) : null;
        nodes.forEach((node, index) => {
            const inventory = _allNodes.get(node.nodeId);
            // Render the name as a single line even in the plain-text fallback.
            const label = inventory?.label?.replace(/[\s\p{Cc}\p{Bidi_Control}]+/gu, ' ').trim();
            const name = label && label !== node.nodeId ? label : labels.unknownNode.replace('{number}', index + 1);
            const role = previewRoles.includes(node.role) ? node.role : inventory?.role || 'standalone';
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

    async function showRebuildPreview({ title, warning, details, allowed, applyLabel }) {
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
        cancel.textContent = allowed ? previewLabels.cancel : previewLabels.close;
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

    async function rebuildPreview(payload, report, sessionToken) {
        const unavailable = previewLabels?.unavailable || 'Preview unavailable.';
        if (!previewLabels) throw new RebuildPreviewStopped(unavailable);
        if (!report) {
            const response = await fetchTopologyWrite('/api/cascade/rebuild/preview', { method: 'POST',
                headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }, sessionToken);
            report = await response.json();
            if (!response.ok) {
                const neighbor = neighborRefusal(response.status, report?.error);
                if (neighbor) {
                    await showRebuildPreview({ title: previewLabels.refused, warning: neighbor, details: '', allowed: false,
                        applyLabel: previewLabels.apply });
                    throw new RebuildPreviewStopped(neighbor);
                }
                const refusal = fingerprintRefusal(response.status, report);
                if (refusal) {
                    await showRebuildPreview({ title: previewLabels.refused, warning: refusal, details: '', allowed: false,
                        applyLabel: previewLabels.apply });
                    throw new RebuildFingerprintRefusal(refusal);
                }
                throw new RebuildPreviewStopped(report.error?.code || unavailable);
            }
        }
        const removing = payload.remove === true;
        const { previewId } = report;
        const text = rebuildPreviewText(report.nodes, removing);
        const allowed = report.allowed === true && !text.protectedChanged;
        if (allowed && (typeof previewId !== 'string' || !/^(?:[a-f0-9]{64}|[a-f0-9]{128})$/.test(previewId))) {
            throw new RebuildPreviewStopped(unavailable);
        }
        const title = allowed ? (removing ? previewLabels.removeTitle : previewLabels.deployTitle) : previewLabels.refused;
        const applyLabel = removing ? previewLabels.remove : previewLabels.apply;
        const accepted = await showRebuildPreview({ title, ...text, allowed, applyLabel });
        if (!allowed || accepted !== true) throw new RebuildPreviewStopped(allowed ? previewLabels.cancelled : title);
        return previewId;
    }

    // Do not reuse legacy chain labels: domain.reconcile excludes pending edges
    // and reconciles only the selected confirmed-applied connected component.
    const syncDomainLabel = i18n.syncAppliedDomain || 'Sync применённого домена';
    const syncDomainScope = i18n.syncAppliedDomainScope
        || 'Только подтверждённые применённые связи в связанном домене выбранной связи. Ожидающие связи не включаются.';

    const STATUS_COLORS = {
        online:   '#22c55e',
        offline:  '#64748b',
        error:    '#ef4444',
        syncing:  '#eab308',
        deployed: '#3b82f6',
        staged:   '#d97706',
        pending:  '#475569',
    };

    const ROLE_BG = {
        standalone: '#0f172a',
        portal:     '#150e3a',
        bridge:     '#1a0e00',
        relay:      '#130a2a',
        internet:   '#0a2e1a',
    };

    const ROLE_BORDER_ACCENT = {
        standalone: '#334155',
        portal:     '#6366f1',
        bridge:     '#f59e0b',
        relay:      '#8b5cf6',
        internet:   '#22c55e',
    };

    const ROLE_GLOW = {
        standalone: null,
        portal:   '#6366f1',
        bridge:   '#f59e0b',
        relay:    '#8b5cf6',
        internet: '#22c55e',
    };

    const ROLE_LABELS = {
        standalone: '',
        portal:   i18n.rolePortal || 'PORTAL',
        relay:    i18n.roleRelay  || 'RELAY',
        bridge:   i18n.roleBridge || 'BRIDGE',
        internet: '',
    };

    let cy = null;
    let linkModalMode = 'create';
    let linkModalSavedFingerprint = null;
    let linkModalGeneration = 0;
    let injectedFingerprintOption;
    const pendingCreateRequests = { main: null, quick: null };
    const intentPolls = new Map();
    const deleteTombstones = new Map();
    const confirmedDeletions = new Set();
    const linkProgress = new Map();
    let listedLinkIds = new Set();
    let topologyRevision = null;
    let deployedRevision = null;
    let _allLinks = [];
    let _allNodes = new Map();
    let observationTimer, topologyRead = 0;

    function expireReverseDisplay() {
        clearTimeout(observationTimer);
        const now = Date.now();
        let next = Infinity;
        _allLinks = _allLinks.map(link => expireReverseStatus(link, now));
        for (const edge of cy.edges()) {
            const current = edge.data();
            const fresh = expireReverseStatus(current, now);
            if (fresh !== current) {
                edge.data({ status: fresh.status, tunnelState: fresh.tunnelState, observationExpiresAt: null });
            } else if (fresh.status === 'online' && fresh.observationExpiresAt) {
                next = Math.min(next, fresh.observationExpiresAt);
            }
        }
        document.getElementById('nodeInfoBody')?.querySelectorAll('[data-reverse-expires]').forEach(el => {
            const until = Number(el.dataset.reverseExpires);
            const current = cy.getElementById('link-' + el.dataset.reverseLink);
            if (!current.length || current.data('status') !== 'online' || !(now < until && until - now <= 90_000)) {
                el.classList.remove('online');
                el.classList.add('deployed');
                el.textContent = el.dataset.reverseFallback;
            } else next = Math.min(next, until);
        });
        if (Number.isFinite(next)) observationTimer = setTimeout(expireReverseDisplay, next - now);
    }

    function applyLinkSnapshot(snapshot) {
        if (!snapshot || !Number.isSafeInteger(snapshot.topologyRevision)
            || !Number.isSafeInteger(snapshot.deployedRevision)
            || !Array.isArray(snapshot.links)) {
            throw new Error('Invalid cascade-link snapshot');
        }
        topologyRevision = snapshot.topologyRevision;
        deployedRevision = snapshot.deployedRevision;
        listedLinkIds = new Set(snapshot.links.map(link => link._id));
        for (const link of snapshot.links) {
            if (!rebuild && link.lifecycle?.state === 'deleting' && /^[a-f0-9]{24}$/.test(link.lifecycle.deleteJobId || '')) {
                retainDeletion(link, link.lifecycle.deleteJobId);
                startIntentPolling({ jobId: link.lifecycle.deleteJobId, version: 2, kind: 'link.delete', linkId: link._id });
            }
        }
        _allLinks = snapshot.links.map(link => deleteTombstones.has(link._id)
            ? deletionLink(link, deleteTombstones.get(link._id)) : (rebuild ? expireReverseStatus(link) : link));
        for (const [linkId, state] of deleteTombstones) {
            if (!listedLinkIds.has(linkId)) _allLinks.push(deletionLink(state.link, state));
        }
        return snapshot;
    }

    function retainDeletion(link, jobId) {
        if (!link) return;
        const previous = deleteTombstones.get(link._id);
        if (previous?.jobId && previous.jobId !== jobId) return;
        deleteTombstones.set(link._id, previous?.jobId ? previous : { link: { ...(previous?.link || link) }, jobId, reconcile: !jobId });
    }

    function deletionLink(link, state) {
        return { ...link, lifecycle: state.jobId ? { ...link.lifecycle, state: 'deleting', deleteJobId: state.jobId } : link.lifecycle,
            applicationState: state.reconcile ? 'reconcile_required' : 'deleting', clientReadiness: undefined,
            xrayReadiness: 'unverified' };
    }

    function responseJob(payload, expectedKind, expectedLinkId) {
        const job = payload?.job || payload?.autoDeployJob;
        if (!job) return null;
        if (typeof job.jobId !== 'string' || !/^[a-f0-9]{24}$/.test(job.jobId)
            || (job.version !== undefined && job.version !== 2)
            || (expectedKind && expectedKind !== 'link.create' && job.version !== 2)
            || (payload.job && payload.autoDeployJob && payload.job.jobId !== payload.autoDeployJob.jobId)
            || (job.version === 2 && (!['link.create', 'link.apply', 'link.delete'].includes(job.kind)
                || typeof job.linkId !== 'string' || !/^[a-f0-9]{24}$/.test(job.linkId)
                || job.desiredSaved !== true || (expectedKind && job.kind !== expectedKind)
                || (expectedLinkId && job.linkId !== expectedLinkId)))) {
            throw new Error(i18n.operationUnconfirmed || 'Ответ задания не подтверждён; обновите топологию.');
        }
        return job;
    }

    async function handleDraftMutationResponse(response, expectedKind, expectedLinkId) {
        const payload = await response.json().catch(() => ({}));
        const refusal = fingerprintRefusal(response.status, payload);
        const neighbor = neighborRefusal(response.status, payload?.error);
        const errorMessage = (payload.desiredSaved === true
            ? ((refusal && fingerprintLabels?.savedNotApplied) || i18n.savedApplyUnconfirmed
                || 'Изменения сохранены; принятие применения не подтверждено. Обновите топологию.') + ' ' : '')
            + (neighbor || refusal || describeTopologyError(payload, 'HTTP ' + response.status));
        if (response.status === 409) {
            await loadTopology();
            showToast((i18n.networkError || 'Error') + ': ' + errorMessage, 'error');
            if (refusal && payload.desiredSaved === true) return { fingerprintApplyRefused: true };
            return null;
        }
        if (!response.ok && payload.desiredSaved === true) await loadTopology();
        if (!response.ok) throw new Error(errorMessage);
        if (rebuild && payload.executionMode === 'rebuild') return payload;
        const job = response.status === 202 ? responseJob(payload, expectedKind, expectedLinkId) : null;
        if (job) {
            if (job.version === 2 && (payload.desiredSaved !== true || payload.linkId !== job.linkId)) {
                throw new Error(i18n.operationUnconfirmed || 'Ответ задания не подтверждён');
            }
            // Acceptance is not a draft snapshot and must not advance the visible revision.
            return payload;
        }
        return applyLinkSnapshot(payload);
    }

    // ==================== INIT ====================

    function init() {
        if (rebuild) {
            const parent = document.getElementById('btnAddLink')?.parentElement;
            if (parent) { const unlock = document.createElement('button'); unlock.type='button'; unlock.className='btn btn-sm btn-outline';
                unlock.textContent='Блокировка Apply'; parent.appendChild(unlock); unlock.onclick=async()=>{try{
                    const sessionToken = csrfToken;
                    const r=await fetchInPanel('/api/cascade/rebuild/lock');const s=await r.json(); if(!r.ok)throw Error('Статус блокировки недоступен');
                    if(!s.stale){ showToast(s.locked?'Apply занят':'Свободно');return; }
                    if(!confirm('Предыдущий исполнитель и его команды на нодах остановлены? Снять именно эту устаревшую блокировку?'))return;
                    const u=await fetchTopologyWrite('/api/cascade/rebuild/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:s.token})}, sessionToken);
                    if(!u.ok)throw Error('Блокировка не снята');showToast('Устаревшая блокировка снята');
                }catch(e){showToast(e.message,'error');}}; }
        }
        cy = cytoscape({
            container: document.getElementById('cy'),
            style: getCytoscapeStyle(),
            layout: { name: 'preset' },
            minZoom: 0.15,
            maxZoom: 4,
            wheelSensitivity: 0.3,
            boxSelectionEnabled: false,
        });

        cy.on('tap', 'node', onNodeTap);
        cy.on('tap', 'edge', onEdgeTap);
        cy.on('tap', function (e) { if (e.target === cy) closeInfoModal(); });
        cy.on('dragfree', 'node', onNodeDragEnd);

        document.getElementById('btnAutoLayout').addEventListener('click', runAutoLayout);
        document.getElementById('btnFitView').addEventListener('click', function () { cy.fit(50); });
        document.getElementById('btnRefresh').addEventListener('click', loadTopology);
        document.getElementById('btnAddLink').addEventListener('click', openAddLinkModal);
        document.getElementById('nodeInfoClose').addEventListener('click', closeInfoModal);
        document.getElementById('nodeInfoModal').addEventListener('click', function (e) {
            if (e.target === this) closeInfoModal();
        });
        document.getElementById('modalClose').addEventListener('click', closeModal);
        document.getElementById('modalCancel').addEventListener('click', closeModal);
        document.getElementById('addLinkForm').addEventListener('submit', onAddLinkSubmit);
        document.querySelector('#addLinkForm [name="autoDeploy"]')?.addEventListener('change', updateLinkSubmitIntent);

        // Mode switcher
        initModeSwitcher('modeSwitcher', 'linkModeInput', 'modeHint');
        initModeSwitcher('quickModeSwitcher', 'quickLinkMode');

        // Security change -> show/hide REALITY section + refresh warnings
        var secSel = document.getElementById('selectSecurity');
        if (secSel) secSel.addEventListener('change', function () {
            var rs = document.getElementById('realitySection');
            if (rs) rs.style.display = this.value === 'reality' ? '' : 'none';
            updateLinkFormWarnings();
        });
        if (rebuild) document.querySelector('#addLinkForm [name="tunnelProtocol"]')
            ?.addEventListener('change', updateLinkFormWarnings);

        // Transport change -> disable REALITY for ws + refresh warnings
        var transSel = document.getElementById('selectTransport');
        if (transSel) transSel.addEventListener('change', function () {
            var secSelect = document.getElementById('selectSecurity');
            if (!secSelect) return;
            var realityOpt = secSelect.querySelector('option[value="reality"]');
            if (!realityOpt) return;
            if (this.value === 'ws' && !rebuild) {
                realityOpt.disabled = true;
                if (secSelect.value === 'reality') {
                    secSelect.value = 'none';
                    secSelect.dispatchEvent(new Event('change'));
                }
            } else {
                realityOpt.disabled = false;
            }
            updateLinkFormWarnings();
        });

        if (rebuild) initFingerprintWarnings();
        else initPortWarnings();

        // Geo routing toggle
        var geoCheck = document.getElementById('geoRoutingEnabled');
        if (geoCheck) geoCheck.addEventListener('change', function () {
            var fields = document.getElementById('geoRoutingFields');
            if (fields) fields.style.display = this.checked ? '' : 'none';
        });

        // Quick link modal handlers
        var quickForm = document.getElementById('quickLinkForm');
        if (quickForm) quickForm.addEventListener('submit', onQuickLinkSubmit);
        var quickClose = document.getElementById('quickModalClose');
        if (quickClose) quickClose.addEventListener('click', closeQuickModal);
        var quickCancel = document.getElementById('quickModalCancel');
        if (quickCancel) quickCancel.addEventListener('click', closeQuickModal);
        var swapBtn = document.getElementById('quickSwapBtn');
        if (swapBtn) swapBtn.addEventListener('click', onQuickSwap);

        setTimeout(function () {
            cy.resize();
            loadTopology();
        }, 30);

        setInterval(refreshStatuses, 30000);
        if (rebuild) document.addEventListener('visibilitychange', expireReverseDisplay);

        if (typeof ResizeObserver !== 'undefined') {
            new ResizeObserver(function () { if (cy) cy.resize(); })
                .observe(document.getElementById('cy'));
        }

        window._networkResize = function () {
            if (cy) { cy.resize(); cy.fit(50); }
        };
    }

    // ==================== DATA LOADING ====================

    async function loadTopology() {
        const read = ++topologyRead;
        // A read-only diagnostic; a failed read never enables a previously
        // disabled action. Backend enrollment independently enforces the ban.
        if (!rebuild) fetch('/api/cascade/topology/activation-policy').then(async response => {
            if (response.ok) renderBusinessReentryRestriction(await response.json(), document);
        }).catch(() => {});
        showLoading(true);
        setEmptyState(false);
        try {
            const [topologyRes, linksRes] = await Promise.all([
                fetch('/api/cascade/topology'),
                fetch('/api/cascade/links'),
            ]);
            if (!topologyRes.ok) throw new Error('HTTP ' + topologyRes.status);
            if (!linksRes.ok) throw new Error('HTTP ' + linksRes.status);
            const data = await topologyRes.json();
            const links = await linksRes.json();
            if (rebuild && read !== topologyRead) return false;
            applyLinkSnapshot(links);
            renderGraph(data);
            return true;
        } catch (err) {
            console.error('[Network] Topology load error:', err);
            return false;
        } finally {
            showLoading(false);
        }
    }

    async function refreshStatuses() {
        const read = ++topologyRead;
        try {
            const [res, linksRes] = await Promise.all([fetch('/api/cascade/topology'), fetch('/api/cascade/links')]);
            if (!res.ok || !linksRes.ok) return;
            const data = await res.json();
            const links = await linksRes.json();
            if (rebuild && read !== topologyRead) return;
            applyLinkSnapshot(links);
            renderGraph(data);
        } catch (_) {}
    }

    function renderGraph(data) {
        if (rebuild) {
            _allNodes = new Map((data.nodes || []).filter(node => typeof node?.data?.id === 'string').map(({ data }) => [data.id, {
                label: typeof data.label === 'string' ? data.label : '',
                role: previewRoles.includes(data.cascadeRole) ? data.cascadeRole : 'standalone',
            }]));
        }
        // Link mutations reload the graph, but must not discard the positions
        // currently visible to the user (including positions not saved yet).
        const previousNodes = cy.nodes();
        const hadGraph = previousNodes.length > 0;
        const previousPositions = new Map(previousNodes.map(n => [n.id(), { ...n.position() }]));
        const previousPan = hadGraph ? cy.pan() : null;
        const previousZoom = hadGraph ? cy.zoom() : null;
        cy.elements().remove();

        const isEmpty = (!data.nodes || data.nodes.length === 0) &&
                        (!data.edges || data.edges.length === 0);
        if (isEmpty) {
            if (rebuild) expireReverseDisplay();
            setEmptyState(true);
            return;
        }
        setEmptyState(false);

        const elements = [];

        for (const n of data.nodes) {
            const role = n.data.cascadeRole || 'standalone';
            const roleLabel = ROLE_LABELS[role] || '';
            const displayLabel = (n.data.flag ? n.data.flag + '\u2009' : '') + (n.data.label || n.data.ip || '');
            const subtitle = n.data.ip || '';

            elements.push({
                group: 'nodes',
                data: {
                    ...n.data,
                    roleLabel,
                    displayLabel,
                    subtitle,
                    roleBg:     ROLE_BG[role]            || ROLE_BG.standalone,
                    roleAccent: ROLE_BORDER_ACCENT[role] || ROLE_BORDER_ACCENT.standalone,
                    roleGlow:   ROLE_GLOW[role]          || null,
                },
                position: previousPositions.get(n.data.id) || n.position || undefined,
            });
        }

        // Only the drawable projection is filtered. Inactive/deleted endpoints
        // can survive in cached graphs; they must not break every other edge.
        // The link inventory and deployment authorization remain unchanged.
        const visibleNodeIds = new Set(data.nodes.map(n => n.data.id));
        const edges = [...data.edges];
        const edgeIds = new Set(edges.map(edge => edge.data.linkId));
        for (const link of _allLinks) {
            if (!deleteTombstones.has(link._id) || edgeIds.has(link._id)) continue;
            const nodeId = node => typeof node === 'string' ? node : node?._id;
            edges.push({ data: { ...link, id: 'link-' + link._id, linkId: link._id,
                source: nodeId(link.portalNode), target: nodeId(link.bridgeNode), label: link.name } });
        }
        for (const e of edges) {
            if (!e?.data || !visibleNodeIds.has(e.data.source) || !visibleNodeIds.has(e.data.target)) continue;
            if (confirmedDeletions.has(e.data.linkId) && !listedLinkIds.has(e.data.linkId)) continue;
            const link = _allLinks.find(link => link._id === e.data.linkId);
            const projection = {};
            if (link) for (const key of ['applicationState', 'routeState', 'tunnelState', 'pppReadiness',
                'xrayReadiness', 'clientReadiness', 'appliedOperationId', 'desiredVersion', 'lifecycle']) projection[key] = link[key];
            let edgeData = { ...e.data, ...projection, progress: linkProgress.get(e.data.linkId) };
            if (rebuild && !edgeData.isInternetEdge && edgeData.mode !== 'forward' && edgeData.status === 'online') {
                // Two parallel reads can straddle a cut or edit. Both must
                // still say online; use the earlier of the two deadlines.
                edgeData.observationExpiresAt = link?.status === 'online'
                    ? Math.min(edgeData.observationExpiresAt, link.observationExpiresAt) : undefined;
                edgeData = expireReverseStatus(edgeData);
            }
            if (rebuild && !edgeData.isInternetEdge && edgeData.mode !== 'forward' && edgeData.status !== 'online') {
                edgeData.tunnelState = 'unknown';
            }
            elements.push({
                group: 'edges',
                data: { ...edgeData, edgeLabel: buildEdgeLabel(edgeData) },
            });
        }

        cy.add(elements);
        if (rebuild) expireReverseDisplay();

        if (hadGraph) {
            cy.zoom(previousZoom);
            cy.pan(previousPan);
        } else {
            const hasPositions = data.nodes.some(n => n.position);
            if (hasPositions) { cy.fit(50); } else { runAutoLayout(); }
        }

        initParticleSystem();
    }

    function buildEdgeLabel(d) {
        const parts = [];
        if (deleteTombstones.has(d.linkId)) parts.push(d.applicationState === 'reconcile_required'
            ? (i18n.reconcileRequired || 'Ожидает сверки') : (i18n.linkDeleting || 'Удаляется'));
        const modePrefix = d.mode === 'forward' ? 'F' : 'R';
        parts.push(modePrefix);
        if (d.tunnelProtocol) parts.push(d.tunnelProtocol.toUpperCase());
        if (d.tunnelPort)     parts.push(':' + d.tunnelPort);
        if (d.latencyMs != null) parts.push(d.latencyMs + 'ms');
        if (d.muxEnabled) parts.push('MUX');
        return parts.join(' ');
    }

    // ==================== CYTOSCAPE STYLE ====================

    function getCytoscapeStyle() {
        return [
            // ---- Node base ----
            {
                selector: 'node',
                style: {
                    'shape': 'round-rectangle',
                    'width': 154,
                    'height': 54,
                    'background-color': function (e) { return e.data('roleBg') || ROLE_BG.standalone; },
                    'border-width': 1.5,
                    'border-color': function (e) {
                        const s = e.data('status');
                        if (s === 'online')  return STATUS_COLORS.online;
                        if (s === 'error')   return STATUS_COLORS.error;
                        return e.data('roleAccent') || ROLE_BORDER_ACCENT.standalone;
                    },
                    'label': function (e) {
                        const rl = e.data('roleLabel');
                        const main = e.data('displayLabel') || e.data('label') || '';
                        const sub = e.data('subtitle') || '';
                        return (rl ? '[' + rl + ']\n' : '') + main + (sub ? '\n' + sub : '');
                    },
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'color': '#e2e8f0',
                    'font-size': '11px',
                    'font-family': 'JetBrains Mono, "Fira Code", monospace',
                    'font-weight': 500,
                    'text-wrap': 'wrap',
                    'text-max-width': '140px',
                    'line-height': 1.45,
                    'overlay-opacity': 0,
                    // glow: default subtle
                    'shadow-blur':      12,
                    'shadow-color':     function (e) { return e.data('roleGlow') || '#000'; },
                    'shadow-opacity':   function (e) { return e.data('roleGlow') ? 0.45 : 0; },
                    'shadow-offset-x':  0,
                    'shadow-offset-y':  0,
                },
            },
            // ---- Online node — green glow ----
            {
                selector: 'node[status = "online"]',
                style: {
                    'border-color':   STATUS_COLORS.online,
                    'border-width':   2,
                    'shadow-blur':    22,
                    'shadow-color':   STATUS_COLORS.online,
                    'shadow-opacity': 0.55,
                },
            },
            // ---- Error node — red pulse ----
            {
                selector: 'node[status = "error"]',
                style: {
                    'border-color':   STATUS_COLORS.error,
                    'shadow-blur':    16,
                    'shadow-color':   STATUS_COLORS.error,
                    'shadow-opacity': 0.5,
                },
            },
            // ---- Internet node — globe icon ----
            {
                selector: 'node[cascadeRole = "internet"]',
                style: {
                    'shape': 'ellipse',
                    'width': 60,
                    'height': 60,
                    'background-color': '#0a2e1a',
                    'border-width': 2,
                    'border-color': '#22c55e',
                    'label': '🌐\nInternet',
                    'font-size': '10px',
                    'shadow-blur': 20,
                    'shadow-color': '#22c55e',
                    'shadow-opacity': 0.5,
                },
            },
            // ---- Selected ----
            {
                selector: 'node:selected',
                style: {
                    'border-width':   2.5,
                    'border-color':   '#818cf8',
                    'shadow-blur':    24,
                    'shadow-color':   '#6366f1',
                    'shadow-opacity': 0.7,
                    'overlay-opacity': 0,
                },
            },
            { selector: 'node:active', style: { 'overlay-opacity': 0 } },

            // ---- Edge base ----
            {
                selector: 'edge',
                style: {
                    'width': 1.5,
                    'line-color':          function (e) { return STATUS_COLORS[e.data('status')] || STATUS_COLORS.pending; },
                    'target-arrow-color':  function (e) { return STATUS_COLORS[e.data('status')] || STATUS_COLORS.pending; },
                    'target-arrow-shape':  'triangle',
                    'curve-style':         'bezier',
                    'arrow-scale':         1,
                    'label':               function (e) { return e.data('edgeLabel') || ''; },
                    'font-size':           '9px',
                    'font-family':         'JetBrains Mono, monospace',
                    'color':               '#64748b',
                    'text-background-color':   '#0a0f1e',
                    'text-background-opacity': 0.9,
                    'text-background-padding': '3px',
                    'text-background-shape':   'round-rectangle',
                    'text-rotation':       'autorotate',
                    'overlay-opacity': 0,
                    'line-style': function (e) {
                        return e.data('mode') === 'forward' ? 'solid' : 'dashed';
                    },
                    'line-dash-pattern': [6, 4],
                    'line-dash-offset': 0,
                },
            },
            {
                selector: 'edge[status = "online"]',
                style: {
                    'width': 2.5,
                    'line-dash-pattern': [10, 5],
                    'shadow-blur':    8,
                    'shadow-color':   STATUS_COLORS.online,
                    'shadow-opacity': 0.5,
                    'shadow-offset-x': 0,
                    'shadow-offset-y': 0,
                },
            },
            {
                selector: 'edge[status = "deployed"]',
                style: {
                    'width': 2,
                    'line-dash-pattern': [8, 4],
                    'shadow-blur':    6,
                    'shadow-color':   STATUS_COLORS.deployed,
                    'shadow-opacity': 0.4,
                    'shadow-offset-x': 0,
                    'shadow-offset-y': 0,
                },
            },
            {
                selector: 'edge[status = "syncing"]',
                style: {
                    'width': 2,
                    'line-color': STATUS_COLORS.syncing,
                    'line-dash-pattern': [4, 3],
                },
            },
            {
                selector: 'edge:selected',
                style: {
                    'width': 3,
                    'line-color':         '#818cf8',
                    'target-arrow-color': '#818cf8',
                    'shadow-blur':    12,
                    'shadow-color':   '#6366f1',
                    'shadow-opacity': 0.6,
                    'shadow-offset-x': 0,
                    'shadow-offset-y': 0,
                },
            },
            // ---- Internet edge — green dashed ----
            {
                selector: 'edge[?isInternetEdge]',
                style: {
                    'width': 1.5,
                    'line-color': '#22c55e',
                    'target-arrow-color': '#22c55e',
                    'line-dash-pattern': [4, 6],
                    'opacity': 0.7,
                },
            },
        ];
    }

    // ==================== DASH ANIMATION ====================

    let dashOffset = 0;
    let dashAnimFrame = null;

    function startDashAnimation() {
        if (dashAnimFrame) cancelAnimationFrame(dashAnimFrame);

        function loop() {
            dashOffset -= 0.55;
            cy.batch(function () {
                cy.edges().style('line-dash-offset', dashOffset);
            });
            dashAnimFrame = requestAnimationFrame(loop);
        }
        loop();
    }

    // ==================== PARTICLE SYSTEM ====================

    let particleCanvas = null;
    let particles = [];
    let particleAnimFrame = null;

    function initParticleSystem() {
        const page = document.querySelector('.network-page');
        if (!page) return;

        if (!particleCanvas) {
            particleCanvas = document.createElement('canvas');
            particleCanvas.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;pointer-events:none;z-index:4';
            page.appendChild(particleCanvas);
        }

        spawnParticles();

        if (!particleAnimFrame) {
            animateParticles();
        }

        if (!dashAnimFrame) {
            startDashAnimation();
        }

        cy.on('add remove', 'edge', spawnParticles);
        cy.on('data', 'edge', spawnParticles);
        cy.on('layoutstop', spawnParticles);
    }

    function spawnParticles() {
        particles = [];
        if (!cy) return;

        cy.edges().forEach(function (edge) {
            const status = edge.data('status');
            if (status !== 'online' && status !== 'deployed') return;

            const isOnline = status === 'online';
            const color    = isOnline ? [34, 197, 94] : [59, 130, 246];
            const count    = isOnline ? 4 : 2;

            // Reverse mode: particles flow target→source (Bridge initiates to Portal)
            // Forward mode: particles flow source→target (Portal connects to Bridge)
            const isForward = edge.data('mode') === 'forward';
            for (let i = 0; i < count; i++) {
                const spd = 0.0035 + Math.random() * 0.003;
                particles.push({
                    edge,
                    progress: i / count,
                    speed: isForward ? spd : -spd,
                    size: isOnline ? 2.8 : 2.2,
                    color,
                });
            }
        });
    }

    function animateParticles() {
        const dpr = window.devicePixelRatio || 1;
        const page = document.querySelector('.network-page');
        if (!page || !particleCanvas || !cy) {
            particleAnimFrame = requestAnimationFrame(animateParticles);
            return;
        }

        const W = page.offsetWidth;
        const H = page.offsetHeight;

        if (particleCanvas.width !== W * dpr || particleCanvas.height !== H * dpr) {
            particleCanvas.width  = W * dpr;
            particleCanvas.height = H * dpr;
        }

        const ctx = particleCanvas.getContext('2d');
        ctx.clearRect(0, 0, particleCanvas.width, particleCanvas.height);

        const zoom = cy.zoom();
        const pan  = cy.pan();

        for (const p of particles) {
            p.progress += p.speed;
            if (p.progress >= 1) p.progress -= 1;
            if (p.progress < 0) p.progress += 1;

            const src = p.edge.source().position();
            const tgt = p.edge.target().position();

            // Bezier mid-point approximation (cytoscape default bend)
            const midX = (src.x + tgt.x) / 2;
            const midY = (src.y + tgt.y) / 2;

            // Quadratic bezier: P = (1-t)^2 * src + 2*(1-t)*t * mid + t^2 * tgt
            const t  = p.progress;
            const mt = 1 - t;
            const bx = mt * mt * src.x + 2 * mt * t * midX + t * t * tgt.x;
            const by = mt * mt * src.y + 2 * mt * t * midY + t * t * tgt.y;

            const sx = (bx * zoom + pan.x) * dpr;
            const sy = (by * zoom + pan.y) * dpr;
            const r  = p.size * dpr * Math.sqrt(zoom);

            // Trail
            const TRAIL = 7;
            for (let i = TRAIL; i >= 1; i--) {
                const tp = p.progress - i * p.speed * 2.5;
                if (tp < 0) continue;
                const ttm = 1 - tp;
                const tx = (ttm * ttm * src.x + 2 * ttm * tp * midX + tp * tp * tgt.x) * zoom + pan.x;
                const ty2 = (ttm * ttm * src.y + 2 * ttm * tp * midY + tp * tp * tgt.y) * zoom + pan.y;
                const alpha = (1 - i / TRAIL) * 0.5;
                const tr = r * (1 - i / TRAIL * 0.6);
                const [R, G, B] = p.color;
                ctx.beginPath();
                ctx.arc(tx * dpr, ty2 * dpr, Math.max(tr, 0.3), 0, Math.PI * 2);
                ctx.fillStyle = `rgba(${R},${G},${B},${alpha})`;
                ctx.fill();
            }

            // Main particle with radial glow
            const [R, G, B] = p.color;
            const grad = ctx.createRadialGradient(sx, sy, 0, sx, sy, r * 4);
            grad.addColorStop(0,    `rgba(${R},${G},${B},1)`);
            grad.addColorStop(0.35, `rgba(${R},${G},${B},0.55)`);
            grad.addColorStop(1,    `rgba(${R},${G},${B},0)`);

            ctx.beginPath();
            ctx.arc(sx, sy, r * 4, 0, Math.PI * 2);
            ctx.fillStyle = grad;
            ctx.fill();
        }

        particleAnimFrame = requestAnimationFrame(animateParticles);
    }

    // ==================== LAYOUT ====================

    function runAutoLayout() {
        const layout = cy.layout({
            name:              'dagre',
            rankDir:           'LR',
            nodeSep:           80,
            rankSep:           160,
            edgeSep:           30,
            animate:           true,
            animationDuration: 400,
            fit:               true,
            padding:           70,
        });
        layout.run();
    }

    // ==================== INFO MODAL ====================

    function openInfoModal(title, bodyHtml) {
        document.getElementById('nodeInfoTitleText').textContent = title;
        document.getElementById('nodeInfoBody').innerHTML = bodyHtml;
        document.getElementById('nodeInfoModal').classList.add('active');
    }

    function closeInfoModal() {
        document.getElementById('nodeInfoModal').classList.remove('active');
        cy.elements(':selected').unselect();
    }

    function onNodeTap(evt) {
        const d = evt.target.data();

        // Internet node - show simple info
        if (d.cascadeRole === 'internet') {
            const html =
                '<div class="info-grid">' +
                '<div class="info-field" style="text-align:center; padding:20px;">' +
                '<div style="font-size:48px; margin-bottom:10px;">🌐</div>' +
                '<div style="color:#22c55e; font-size:14px;">' + (i18n.internetDesc || 'Traffic exits to the Internet from connected nodes') + '</div>' +
                '</div>' +
                '</div>';
            openInfoModal('Internet', html);
            return;
        }

        const sc = d.status || 'offline';
        const roleLabel = d.roleLabel
            ? '<span class="info-role-badge role-' + d.cascadeRole + '">' + d.roleLabel + '</span>'
            : '';

        const html =
            '<div class="info-grid">' +
            field(i18n.drawerStatus || 'Status',
                '<div class="info-status ' + sc + '">\u25CF ' + (d.status || 'unknown') + roleLabel + '</div>') +
            field('ti-network',    i18n.drawerIP     || 'IP',           d.ip     || '—') +
            field('ti-cpu',        i18n.drawerType   || 'Type',         d.type   || '—') +
            field('ti-topology-star-3', i18n.drawerRole || 'Role',      d.cascadeRole || 'standalone') +
            field('ti-users',      i18n.drawerOnline || 'Online Users', d.onlineUsers || 0) +
            field('ti-plug',       i18n.drawerPort   || 'Port',         d.port   || '—') +
            '</div>' +
            '<div class="info-actions">' +
            '<a href="/panel/nodes/' + d.id + '" class="btn btn-sm btn-outline">' +
            '<i class="ti ti-external-link"></i> ' + (i18n.openNode || 'Open Node') + '</a>' +
            (d.sshConfigured
                ? '<a href="/panel/nodes/' + d.id + '/terminal" target="_blank" rel="noopener" class="btn btn-sm btn-outline">' +
                  '<i class="ti ti-terminal-2"></i> ' + (i18n.terminal || 'SSH Terminal') + '</a>'
                : '<button class="btn btn-sm btn-outline" disabled title="' + (i18n.sshNotConfigured || 'SSH not configured') + '">' +
                  '<i class="ti ti-terminal-2"></i> ' + (i18n.terminal || 'SSH Terminal') + '</button>') +
            '</div>';

        openInfoModal((d.flag ? d.flag + ' ' : '') + (d.label || d.ip || ''), html);
    }

    // Match the API admission states, not the graph's optimistic syncing color.
    // The server still fences/revalidates the snapshot; this is guidance only.
    function domainSyncAnchorError(linkId) {
        const link = _allLinks.find(link => String(link._id) === linkId);
        if (!link) return topologyCauseText('SCOPE_LINK_MISSING');
        if (rebuild) return null;
        if (link.active === false) return 'Связь отключена — включите её перед синхронизацией домена';
        return ['deployed', 'online', 'staged'].includes(link.status)
            ? null : topologyCauseText('SCOPE_LINK_UNCONFIRMED');
    }

    function onEdgeTap(evt) {
        const d = rebuild ? expireReverseStatus(evt.target.data()) : evt.target.data();
        const sc = d.status || 'pending';
        const lid = d.linkId;

        if (d.isInternetEdge) {
            const html =
                '<div class="info-grid">' +
                '<div class="info-field" style="text-align:center; padding:20px;">' +
                '<div style="font-size:32px; margin-bottom:10px;">🌐</div>' +
                '<div style="color:#22c55e; font-size:14px;">' + (i18n.internetExitDesc || 'Internet exit point') + '</div>' +
                '</div>' +
                '</div>';
            openInfoModal(i18n.internetExit || 'Internet Exit', html);
            return;
        }

        const modeLabel = d.mode === 'forward'
            ? '<span class="info-mode-badge forward">' + (i18n.modeForward || 'Forward Chain') + '</span>'
            : '<span class="info-mode-badge reverse">' + (i18n.modeReverse || 'Reverse Proxy') + '</span>';

        const secLabel = (d.tunnelSecurity || 'none').toUpperCase();
        const extras = [];
        if (d.muxEnabled) extras.push('MUX');
        if (d.tunnelSecurity === 'reality') extras.push('REALITY');

        const summary = buildRouteSummary(d);

        const html =
            '<div class="info-grid">' +
            '<div class="info-summary">' +
            '<span class="beta-badge">' + escHtml(i18n.betaBadge || 'BETA') + '</span>' +
            field(i18n.selectedSegment || 'Выбранный участок', escHtml(summary.chain)) +
            '<p class="info-hint">' + escHtml(i18n.fullRouteUnconfirmed
                || 'Полный применённый маршрут и выход не подтверждены.') + '</p>' +
            field('ti-login-2',     i18n.routeEntry     || 'Entry',             escHtml(summary.entry)) +
            field('ti-logout-2',    i18n.routeExit      || 'Exit',              escHtml(summary.exit)) +
            field('ti-shield-lock', i18n.routeEncryption || 'Tunnel encryption', escHtml(summary.encryption)) +
            '</div>' +
            field(i18n.drawerStatus || 'Status',
                '<div class="info-status ' + sc + '"' + (rebuild && Number.isSafeInteger(d.observationExpiresAt)
                    ? ' data-reverse-expires="' + d.observationExpiresAt + '" data-reverse-link="' + escHtml(lid)
                        + '" data-reverse-fallback="● deployed"' : '')
                    + '>\u25CF ' + (d.status || 'pending') + '</div>') +
            linkStateFields(d) +
            (d.xrayReadiness === undefined ? field('ti-shield-check', 'Готовность клиента',
                escHtml(clientReadinessMessage(d.clientReadiness, topologyRevision, deployedRevision))) : '') +
            field(i18n.linkMode || 'Mode', modeLabel) +
            field('ti-plug',           i18n.drawerTunnelPort        || 'Tunnel Port',         d.tunnelPort || '—') +
            field('ti-arrows-exchange',i18n.drawerProtocolTransport || 'Protocol / Transport',
                (d.tunnelProtocol || 'vless').toUpperCase() + ' / ' + (d.tunnelTransport || 'tcp') + ' / ' + secLabel) +
            field('ti-clock',          i18n.drawerLatency           || 'Latency',
                d.latencyMs != null ? d.latencyMs + ' ms' : '—') +
            (extras.length > 0
                ? field('ti-settings', 'Features', extras.join(', '))
                : '') +
            '</div>' +
            '<div class="info-actions">' +
            (!rebuild || document.getElementById('linkIdInput')
                ? '<button class="btn btn-sm btn-outline" id="btnEdit" onclick="window._cascadeEdit(\'' + lid + '\')">' +
                    '<i class="ti ti-edit"></i> ' + (i18n.edit || 'Edit') + '</button>' : '') +
            '<button class="btn btn-sm btn-success" id="btnDeploy" onclick="window._cascadeDeploy(\'' + lid + '\')">' +
            '<i class="ti ti-upload"></i> ' + (i18n.deploy || 'Deploy') + '</button>' +
            '<button class="btn btn-sm btn-primary" id="btnDeployChain" onclick="window._cascadeDeployChain(\'' + lid + '\')">' +
            '<i class="ti ti-link"></i> ' + escHtml(syncDomainLabel) + '</button>' +
            (rebuild ? '' :
                '<button class="btn btn-sm btn-outline" id="btnUndeploy" onclick="window._cascadeUndeploy(\'' + lid + '\')">' +
                '<i class="ti ti-player-stop"></i> ' + (i18n.undeployLink || 'Undeploy') + '</button>') +
            '<button class="btn btn-sm btn-danger" id="btnDelete" onclick="window._cascadeDelete(\'' + lid + '\')">' +
            '<i class="ti ti-trash"></i> ' + (i18n.delete || 'Delete') + '</button>' +
            '</div>';

        openInfoModal(d.label || 'Cascade Link', html +
            '<p class="info-hint">' + escHtml(syncDomainScope) + '</p>' +
            (domainSyncAnchorError(lid)
                ? '<p class="info-hint">' + escHtml(domainSyncAnchorError(lid)) + '</p>' : ''));
        if (rebuild) expireReverseDisplay();
    }

    function linkStateFields(d) {
        const application = { not_applied: i18n.linkNotApplied || 'Не применено', applying: i18n.deployInProgress || 'Применяется',
            applied: i18n.linkApplied || 'Конфигурация участка применена', deleting: i18n.linkDeleting || 'Удаляется',
            reconcile_required: i18n.reconcileRequired || 'Ожидает сверки' };
        const routes = { complete: i18n.routeComplete || 'Маршрут завершён; клиентские проверки отдельно',
            no_portal_input: i18n.routeNoPortal || 'Нет входящего пути от портала',
            no_bridge_exit: i18n.routeNoBridge || 'Нет выхода к бриджу', policy_ambiguous: i18n.routeAmbiguous || 'Политика выхода неоднозначна',
            unknown: i18n.routeUnknown || 'Целостность маршрута не подтверждена' };
        const tunnels = { connected: i18n.tunnelConnected || 'Соединён', disconnected: i18n.tunnelDisconnected || 'Не соединён',
            unknown: i18n.tunnelUnknown || 'Соединение не подтверждено' };
        const verified = i18n.readinessVerified || 'Подтверждено';
        const unverified = i18n.clientReadinessUnverified || CLIENT_READINESS_UNVERIFIED;
        const xrayVerified = d.xrayReadiness === 'verified' && d.applicationState === 'applied'
            && d.routeState === 'complete' && d.tunnelState === 'connected'
            && typeof d.appliedOperationId === 'string' && /^[a-f0-9]{24}$/.test(d.appliedOperationId);
        return field(i18n.applicationStateLabel || 'Применение', escHtml(application[d.applicationState] || '—'))
            + field(i18n.routeStateLabel || 'Целостность маршрута', escHtml(routes[d.routeState] || routes.unknown))
            + field(i18n.tunnelStateLabel || 'Туннель', rebuild && Number.isSafeInteger(d.observationExpiresAt) && d.tunnelState === 'connected'
                ? '<span data-reverse-expires="' + d.observationExpiresAt + '" data-reverse-link="' + escHtml(d.linkId)
                    + '" data-reverse-fallback="' + escHtml(tunnels.unknown) + '">' + escHtml(tunnels.connected) + '</span>'
                : escHtml(tunnels[d.tunnelState] || tunnels.unknown))
            + field('PPP/L2TP', escHtml(d.pppReadiness === 'verified' ? verified : unverified))
            + field('Xray/VLESS/REALITY', escHtml(xrayVerified ? verified : unverified))
            + (d.progress ? field(i18n.operationProgress || 'Задание / фаза / причина / следующее действие', escHtml(progressMessage(d.progress))) : '');
    }

    function escHtml(v) {
        return String(v == null ? '' : v)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function buildRouteSummary(edgeData) {
        const srcNode = cy.getElementById(edgeData.source);
        const tgtNode = cy.getElementById(edgeData.target);
        const entryLabel = srcNode.length
            ? (srcNode.data('label') || srcNode.data('ip') || edgeData.source)
            : edgeData.source;
        const exitLabel = tgtNode.length
            ? (tgtNode.data('label') || tgtNode.data('ip') || edgeData.target)
            : edgeData.target;

        // The current snapshot describes desired arrows, not an applied path
        // or exit policy. Show only this segment in traffic direction, for
        // either transport mode. Never infer Client/Internet or follow a
        // pending sibling (nor choose the first branch as the active exit).
        // A full route needs a separately supplied, bound backend projection.

        const sec = edgeData.tunnelSecurity || 'none';
        const encLabel = sec === 'none'
            ? 'None'
            : sec.toUpperCase() + ' (' + (edgeData.tunnelProtocol || 'vless').toUpperCase() + ')';

        return {
            chain: entryLabel + ' → ' + exitLabel,
            entry: entryLabel,
            exit: exitLabel,
            encryption: encLabel,
        };
    }

    /** Helper: render a drawer field row */
    function field(iconOrLabel, labelOrValue, value) {
        if (value === undefined) {
            // called as field(label, htmlValue) — first arg is plain text label
            return '<div class="info-field"><div class="info-label">' + iconOrLabel + '</div>' +
                   '<div>' + labelOrValue + '</div></div>';
        }
        return '<div class="info-field">' +
               '<div class="info-label"><i class="ti ' + iconOrLabel + '"></i> ' + labelOrValue + '</div>' +
               '<div class="info-value">' + value + '</div>' +
               '</div>';
    }

    // ==================== NODE DRAG / POSITIONS ====================

    let positionSaveTimer = null;
    function onNodeDragEnd() {
        clearTimeout(positionSaveTimer);
        positionSaveTimer = setTimeout(saveAllPositions, 600);
    }

    async function saveAllPositions() {
        const positions = cy.nodes().map(function (n) {
            const p = n.position();
            return { id: n.data('id'), x: Math.round(p.x), y: Math.round(p.y) };
        });
        try {
            await fetch('/api/cascade/topology/positions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ positions }),
            });
        } catch (_) {}
    }

    // ==================== ADD LINK MODAL ====================

    function updateLinkSubmitIntent() {
        const edit = linkModalMode === 'edit';
        const form = document.getElementById('addLinkForm');
        const label = document.getElementById('linkAutoDeployLabel');
        const submit = document.getElementById('linkModalSubmit');
        if (label) label.textContent = edit
            ? (i18n.deployAfterEdit || 'Deploy this link after saving')
            : (i18n.autoDeploy || 'Auto Deploy');
        if (submit) submit.textContent = edit
            ? (form.autoDeploy.checked ? (i18n.saveAndDeploy || 'Save & Deploy') : (i18n.save || 'Save'))
            : (i18n.createLink || 'Create');
    }

    function ensureFingerprintOption(select, value) {
        if (!select) return;
        const exists = Array.prototype.some.call(select.options, o => o.value === value);
        if (!exists) {
            const opt = document.createElement('option');
            opt.value = value;
            opt.textContent = value || fingerprintLabels?.unset || 'Keep existing value';
            select.appendChild(opt);
            injectedFingerprintOption = opt;
        }
        select.value = value;
    }

    async function openAddLinkModal({ editing = false } = {}) {
        const generation = ++linkModalGeneration;
        resetPortWarning('main');
        const modal       = document.getElementById('addLinkModal');
        const portalSelect = document.getElementById('selectPortal');
        const bridgeSelect = document.getElementById('selectBridge');
        const title = document.getElementById('linkModalTitle');
        const submit = document.getElementById('linkModalSubmit');
        const linkIdInput = document.getElementById('linkIdInput');

        linkModalMode = 'create';
        linkModalSavedFingerprint = null;
        if (title) title.textContent = i18n.addLink || 'Add Link';
        if (submit) submit.textContent = i18n.createLink || 'Create';
        if (linkIdInput) linkIdInput.value = '';
        const form = document.getElementById('addLinkForm');
        form.autoDeploy.checked = true;
        if (rebuild && !editing) {
            form.tunnelTransport.value = 'tcp';
            form.tunnelSecurity.value = 'reality';
            if (form.tunnelEncryption) form.tunnelEncryption.checked = true;
        }
        const realitySection = document.getElementById('realitySection');
        if (realitySection) realitySection.style.display = form.tunnelSecurity.value === 'reality' ? '' : 'none';
        updateLinkSubmitIntent();
        // A brand-new link starts from Chrome, not an earlier edit's choice.
        var createFp = document.querySelector('#addLinkForm [name="realityFingerprint"]');
        injectedFingerprintOption?.remove();
        injectedFingerprintOption = undefined;
        if (createFp) {
            createFp.value = resolveRealityFingerprint(null, 'create');
        }
        fingerprintInventory.main = new Map();
        renderFingerprintHint('main');

        try {
            const [nodesRes, linksRes] = await Promise.all([
                fetch('/api/nodes', rebuild ? { cache: 'no-store', redirect: 'error' } : undefined),
                fetch('/api/cascade/links'),
            ]);
            if (!nodesRes.ok || !linksRes.ok) throw new Error();
            const [nodes, snapshot] = await Promise.all([nodesRes.json(), linksRes.json()]);
            if (generation !== linkModalGeneration) return;
            applyLinkSnapshot(snapshot);
            if (rebuild) fingerprintInventory.main = readFingerprintInventory(nodes);
            fillLinkNodeOptions(portalSelect, i18n.selectPortal || '— Select Portal —', nodes);
            fillLinkNodeOptions(bridgeSelect, i18n.selectBridge || '— Select Bridge —', nodes);
        } catch (_) {
            if (generation !== linkModalGeneration) return;
            const message = i18n.errorLoadingNodes || 'Error loading nodes';
            fillLinkNodeOptions(portalSelect, message, []);
            fillLinkNodeOptions(bridgeSelect, message, []);
        }
        if (!editing) modal.classList.add('active');
        updateLinkFormWarnings();
        return generation;
    }

    function fillLinkNodeOptions(select, placeholder, nodes) {
        select.textContent = '';
        const append = (value, label) => {
            const option = document.createElement('option');
            option.value = value;
            option.textContent = label;
            select.appendChild(option);
        };
        append('', placeholder);
        for (const node of nodes) append(node._id, `${node.flag || ''} ${node.name} (${node.ip})`);
    }

    async function openEditLinkModal(linkId) {
        const form = document.getElementById('addLinkForm');
        const title = document.getElementById('linkModalTitle');
        const submit = document.getElementById('linkModalSubmit');
        const linkIdInput = document.getElementById('linkIdInput');

        const generation = await openAddLinkModal({ editing: true });
        if (generation !== linkModalGeneration) return;
        const res = await fetch('/api/cascade/links/' + linkId);
        if (!res.ok) throw new Error('Failed to load link');
        const link = await res.json();
        if (generation !== linkModalGeneration) return;
        linkModalMode = 'edit';
        if (title) title.textContent = (i18n.edit || 'Edit') + ' Link';
        if (submit) submit.textContent = i18n.save || 'Save';
        if (linkIdInput) linkIdInput.value = linkId;

        form.name.value = link.name || '';
        form.mode.value = link.mode || 'reverse';
        form.portalNodeId.value = link.portalNode?._id || link.portalNode || '';
        form.bridgeNodeId.value = link.bridgeNode?._id || link.bridgeNode || '';
        form.tunnelPort.value = link.tunnelPort || 10086;
        form.tunnelProtocol.value = link.tunnelProtocol || 'vless';
        form.tunnelTransport.value = link.tunnelTransport === 'splithttp' ? 'xhttp' : (link.tunnelTransport || 'tcp');
        form.tunnelSecurity.value = link.tunnelSecurity || 'none';
        if (rebuild && form.tunnelEncryption) form.tunnelEncryption.checked = link.tunnelEncryption !== 'none';
        form.tunnelDomain.value = link.tunnelDomain || 'reverse.tunnel.internal';
        form.muxEnabled.checked = !!link.muxEnabled;
        form.muxConcurrency.value = link.muxConcurrency || 8;
        form.priority.value = link.priority ?? 100;
        // The saved preference is metadata, not consent to deploy on this edit.
        form.autoDeploy.checked = false;
        updateLinkSubmitIntent();

        if (form.realityDest) form.realityDest.value = link.realityDest || '';
        if (form.realitySni) form.realitySni.value = Array.isArray(link.realitySni) ? link.realitySni.join(', ') : (link.realitySni || '');
        if (form.realityPrivateKey) form.realityPrivateKey.value = link.realityPrivateKey || '';
        if (form.realityPublicKey) form.realityPublicKey.value = link.realityPublicKey || '';
        if (form.realityShortIds) form.realityShortIds.value = Array.isArray(link.realityShortIds) ? link.realityShortIds.join(', ') : (link.realityShortIds || '');
        // Preserve the saved fingerprint exactly; inject an option if the saved
        // value is outside the builtin list so re-saving never rewrites it.
        linkModalSavedFingerprint = link.realityFingerprint;
        ensureFingerprintOption(
            form.realityFingerprint,
            resolveRealityFingerprint(linkModalSavedFingerprint, 'edit'),
        );

        const geoEnabled = document.getElementById('geoRoutingEnabled');
        const geoFields = document.getElementById('geoRoutingFields');
        const geoDomains = document.getElementById('geoRoutingDomains');
        const geoGeoip = document.getElementById('geoRoutingGeoip');
        if (geoEnabled) geoEnabled.checked = !!link.geoRouting?.enabled;
        if (geoFields) geoFields.style.display = link.geoRouting?.enabled ? '' : 'none';
        if (geoDomains) geoDomains.value = Array.isArray(link.geoRouting?.domains) ? link.geoRouting.domains.join(', ') : '';
        if (geoGeoip) geoGeoip.value = Array.isArray(link.geoRouting?.geoip) ? link.geoRouting.geoip.join(', ') : '';

        var realitySec = document.getElementById('realitySection');
        if (realitySec) realitySec.style.display = form.tunnelSecurity.value === 'reality' ? '' : 'none';
        var domGroup = document.getElementById('tunnelDomainGroup');
        if (domGroup) domGroup.style.display = form.mode.value === 'forward' ? 'none' : '';
        var hint = document.getElementById('modeHint');
        if (hint) {
            hint.textContent = form.mode.value === 'forward'
                ? (i18n.modeForwardHint || 'Portal connects to Bridge directly. All nodes need public IP.')
                : (i18n.modeReverseHint || 'Bridge initiates tunnel to Portal. Bridge can be behind NAT.');
        }
        var switcher = document.getElementById('modeSwitcher');
        if (switcher) {
            switcher.querySelectorAll('.mode-btn').forEach(function (b) {
                b.classList.toggle('active', b.getAttribute('data-mode') === form.mode.value);
            });
        }
        document.getElementById('addLinkModal').classList.add('active');
        updateLinkFormWarnings();
    }

    function closeModal() {
        ++linkModalGeneration;
        resetPortWarning('main');
        document.getElementById('addLinkModal').classList.remove('active');
        document.getElementById('addLinkForm').reset();
        linkModalMode = 'create';
        updateLinkSubmitIntent();
        var title = document.getElementById('linkModalTitle');
        if (title) title.textContent = i18n.addLink || 'Add Link';
        var submit = document.getElementById('linkModalSubmit');
        if (submit) submit.textContent = i18n.createLink || 'Create';
        var linkIdInput = document.getElementById('linkIdInput');
        if (linkIdInput) linkIdInput.value = '';
        // Reset mode switcher to reverse
        var modeInput = document.getElementById('linkModeInput');
        if (modeInput) modeInput.value = 'reverse';
        var switcher = document.getElementById('modeSwitcher');
        if (switcher) {
            switcher.querySelectorAll('.mode-btn').forEach(function (b) {
                b.classList.toggle('active', b.getAttribute('data-mode') === 'reverse');
            });
        }
        var hint = document.getElementById('modeHint');
        if (hint) hint.textContent = i18n.modeReverseHint || 'Bridge initiates tunnel to Portal. Bridge can be behind NAT.';
        var realitySec = document.getElementById('realitySection');
        if (realitySec) realitySec.style.display = 'none';
        var geoEnabled = document.getElementById('geoRoutingEnabled');
        if (geoEnabled) geoEnabled.checked = false;
        var geoDomains = document.getElementById('geoRoutingDomains');
        if (geoDomains) geoDomains.value = '';
        var geoGeoip = document.getElementById('geoRoutingGeoip');
        if (geoGeoip) geoGeoip.value = '';
        var geoFields = document.getElementById('geoRoutingFields');
        if (geoFields) geoFields.style.display = 'none';
        var domGroup = document.getElementById('tunnelDomainGroup');
        if (domGroup) domGroup.style.display = '';
        renderFingerprintHint('main');
    }

    function progressMessage(progress) {
        const parts = [];
        if (/^[a-f0-9]{24}$/.test(progress?.jobId || '')) parts.push('Job: ' + progress.jobId);
        if (/^[a-f0-9]{24}$/.test(progress?.operationId || '')) parts.push('Operation: ' + progress.operationId);
        const phases = { waiting: i18n.phaseWaiting, admitted: i18n.phaseAdmitted, preparing: i18n.phasePreparing,
            applying: i18n.phaseApplying, rolling_back: i18n.phaseRollback, completed: i18n.phaseCompleted,
            failed: i18n.phaseFailed, rolled_back: i18n.phaseRollback, succeeded: i18n.phaseCompleted,
            blocked: i18n.reconcileRequired, reconcile_required: i18n.reconcileRequired };
        if (Object.hasOwn(phases, progress?.phase)) parts.push(phases[progress.phase] || progress.phase);
        const reasons = { TOPOLOGY_INTENT_RESOURCE_BUSY: i18n.waitResources, TOPOLOGY_DEPLOY_BUSY: i18n.waitResources,
            TOPOLOGY_RECONCILE_REQUIRED: i18n.reconcileRequired, PPP_SYNC_PENDING: i18n.waitPPP };
        if (Object.hasOwn(reasons, progress?.waitingReason)) parts.push((reasons[progress.waitingReason] || '') + ' (' + progress.waitingReason + ')');
        if (/^[a-f0-9]{24}$/.test(progress?.nodeId || '')) parts.push((i18n.operationNode || 'Узел') + ': ' + progress.nodeId);
        const actions = { poll_operation: i18n.pollOperation, inspect_operation: i18n.inspectOperation,
            refresh_topology: i18n.refreshTopology, retry_later: i18n.retryLater };
        if (Object.hasOwn(actions, progress?.nextAction)) parts.push(actions[progress.nextAction] || progress.nextAction);
        return parts.join(' · ');
    }

    function startIntentPolling(job) {
        const jobId = job?.jobId;
        if (!/^[a-f0-9]{24}$/.test(jobId || '') || intentPolls.has(jobId)
            || [...intentPolls.values()].filter(state => !state.done).length >= 128) return;
        const state = { failures: 0, attempts: 0, done: false, job };
        if (job.linkId) linkProgress.set(job.linkId, job);
        const step = async () => {
            try {
                const response = await fetch('/api/cascade/links/auto-deploy-jobs/' + encodeURIComponent(jobId));
                if (!response.ok) throw new Error('Job status unavailable');
                const current = responseJob(await response.json(), job.kind, job.linkId);
                if (current?.jobId !== jobId || (job.version === 2 && current.version !== 2)) throw new Error('Job identity mismatch');
                state.failures = 0;
                if (current.linkId) linkProgress.set(current.linkId, current);
                if (['failed', 'blocked'].includes(current.status)) {
                    state.done = true;
                    const tombstone = deleteTombstones.get(job.linkId);
                    if (tombstone) tombstone.reconcile = true;
                    showToast((current.status === 'blocked' ? (i18n.reconcileRequired || 'Ожидает сверки')
                        : (i18n.deployFailed || 'Операция не выполнена')) + ': ' + jobId
                        + ' ' + describeTopologyError({ error: { code: current.errorCode } }, ''), 'error');
                    await loadTopology(); return;
                }
                if (typeof current.operationId === 'string' && /^[a-f0-9]{24}$/.test(current.operationId) && ['admitted', 'succeeded'].includes(current.status)) {
                    state.done = true;
                    startBoundOperationPolling(current.operationId, current.kind === 'link.delete' ? 'link.delete' : 'link.apply', current.linkId, jobId);
                    await loadTopology(); return;
                }
                const message = progressMessage(current);
                if (message !== state.message) { state.message = message; showToast(message); }
                await loadTopology();
            } catch (_) {
                if (++state.failures >= 6) {
                    state.done = true;
                    showToast((i18n.jobUnavailable || 'Статус задания недоступен. Принятый запрос остаётся на сервере.') + ' ' + jobId, 'error');
                    return;
                }
            }
            if (++state.attempts >= 80) {
                state.done = true;
                showToast((i18n.jobStillWaiting || 'Задание остаётся на сервере; завершение не подтверждено.') + ' ' + jobId, 'error');
                return;
            }
            state.timer = setTimeout(step, 1500);
        };
        intentPolls.set(jobId, state);
        state.timer = setTimeout(step, 1500);
    }

    function jobAcceptedMessage(job) {
        const message = job.version === 2 && job.desiredSaved === true
            ? (i18n.jobAccepted || 'Намерение сохранено; задание принято. Применение ещё не подтверждено.')
            : (i18n.legacyJobAccepted || 'Запрос принят. Создание связи и применение ещё не подтверждены.');
        return message + ' ' + job.jobId;
    }

    async function handleLinkAutoDeploy(snapshot, optedIn, sessionToken) {
        if (rebuild && snapshot?.executionMode === 'rebuild') {
            if (snapshot.status==='awaiting_preview') {
                try {
                    await deployTopology(snapshot.linkId, undefined, snapshot.preview, sessionToken);
                } catch (error) {
                    if (error instanceof RebuildFingerprintRefusal) {
                        showToast((fingerprintLabels?.savedNotApplied || i18n.csrfSavedDraft || 'The link was saved.') + ' ' + error.message, 'error');
                        return;
                    }
                    if (!(error instanceof TopologyCsrfRejection || error instanceof RebuildPreviewStopped)) throw error;
                    showToast((i18n.csrfSavedDraft || 'The link was saved. Use Deploy on that link instead of saving it again.') + ' ' + error.message, 'error');
                    return;
                }
                await loadTopology(); showToast('Схема пересобрана, файлы сверены');return;
            }
            showToast(snapshot.status==='succeeded'?'Схема пересобрана, файлы сверены':'Сохранено без применения'); return;
        }
        if (!optedIn) {
            showToast(i18n.savedWithoutDeploy || 'Изменения сохранены. Деплой не запускался.');
            return;
        }
        const job = responseJob(snapshot);
        if (job?.jobId) {
            showToast(jobAcceptedMessage(job));
            startIntentPolling(job);
            return;
        }
        const completed = snapshot?.autoDeployResult;
        if (isCompletedClassicDeploymentResult(completed, snapshot?.topologyRevision)) {
            showToast(deployResultMessage(completed));
            return;
        }
        const operation = snapshot?.autoDeployOperation;
        if (TRACKED_OPERATION_STATUSES.includes(operation?.status) && operation.operationId) {
            startOperationPolling(operation);
            showToast(deployResultMessage(operation, i18n));
            return;
        }
        // Saving a draft is not evidence of physical deployment. In
        // particular, never fall back to an unscoped full-topology deploy.
        const error = snapshot?.autoDeployError
            || { code: snapshot?.autoDeployCauseCode || snapshot?.autoDeployStatus };
        if (error.code === 'CLASSIC_DEPLOY_TUNNEL_UNCONFIRMED') {
            showToast(topologyCauseText(error.code), 'error');
            return;
        }
        const classicRefusal = typeof error.code === 'string' && error.code.startsWith('CLASSIC_DEPLOY_');
        const savedMessage = classicRefusal
            ? (i18n.savedClassicDeployUnconfirmed || 'Изменения сохранены; применение не подтверждено')
            : (i18n.savedAutoDeployBlocked || 'Изменения сохранены, но автодеплой не запущен');
        showToast(savedMessage + ': '
            + describeTopologyError({ error }, 'Автодеплой не подтверждён')
            + (classicRefusal ? '. Проверьте состояние и блокировки перед повторной попыткой.'
                : '. Для применения используйте отдельный Deploy этой связи.'), 'error');
    }

    function createRequestHeaders(data, formKind) {
        const headers = { 'Content-Type': 'application/json' };
        if (rebuild) return headers;
        if (data.autoDeploy === true) {
            // Revision refresh is not a new logical create. Keep each form's
            // identity through rejected/unknown deliveries; retire on acceptance.
            const signature = JSON.stringify({ ...data, expectedTopologyRevision: undefined });
            if (pendingCreateRequests[formKind]?.signature !== signature) {
                let key = window.crypto?.randomUUID?.();
                if (!key && window.crypto?.getRandomValues) {
                    // getRandomValues remains available on HTTP pages where
                    // randomUUID may require a secure context.
                    key = 'ui-' + Array.from(window.crypto.getRandomValues(new Uint8Array(16)),
                        byte => byte.toString(16).padStart(2, '0')).join('');
                }
                if (!key) throw new Error(i18n.operationUnconfirmed || 'Не удалось создать ключ запроса.');
                pendingCreateRequests[formKind] = { signature, key };
            }
            headers['Idempotency-Key'] = pendingCreateRequests[formKind].key;
        }
        return headers;
    }

    async function onAddLinkSubmit(e) {
        e.preventDefault();
        if (portSubmissionBlocked('main')) return;
        if (fingerprintSubmissionBlocked('main')) return;
        const form = e.target;
        const btn  = form.querySelector('[type="submit"]');
        const linkId = form.linkId?.value || '';

        const data = {
            name:           form.name.value,
            mode:           form.mode.value || 'reverse',
            portalNodeId:   form.portalNodeId.value,
            bridgeNodeId:   form.bridgeNodeId.value,
            tunnelPort:     parseInt(form.tunnelPort.value) || 10086,
            tunnelProtocol: form.tunnelProtocol.value,
            tunnelTransport:form.tunnelTransport.value,
            tunnelSecurity: form.tunnelSecurity.value,
            // PUT true is an activation command. Omit it on ordinary edits,
            // regardless of the link's persisted autoDeploy preference.
            autoDeploy:     linkId ? (form.autoDeploy?.checked ? true : undefined)
                : !!form.autoDeploy?.checked,
            muxEnabled:     form.muxEnabled?.checked || false,
            muxConcurrency: parseInt(form.muxConcurrency?.value) || 8,
            priority:       Number(form.priority?.value || 100),
        };
        if (canSetTunnelEncryption(form)) data.tunnelEncryption = form.tunnelEncryption.checked ? 'vless-enc' : 'none';

        // Tunnel domain (reverse only)
        if (form.tunnelDomain?.value) {
            data.tunnelDomain = form.tunnelDomain.value;
        }

        // REALITY fields
        if (data.tunnelSecurity === 'reality') {
            if (rebuild && data.tunnelTransport === 'ws') {
                showToast(i18n.realityWsUnsupported || 'REALITY несовместим с WebSocket. Выберите другой транспорт или режим защиты.', 'error');
                return;
            }
            data.realityDest = form.realityDest?.value || '';
            data.realitySni = form.realitySni?.value || '';
            data.realityPrivateKey = form.realityPrivateKey?.value || '';
            data.realityPublicKey = form.realityPublicKey?.value || '';
            data.realityShortIds = form.realityShortIds?.value || '';
            const fingerprint = linkId
                ? fingerprintForLinkEdit(linkModalSavedFingerprint, form.realityFingerprint?.value)
                : resolveRealityFingerprint(form.realityFingerprint?.value, 'create');
            if (fingerprint !== undefined) data.realityFingerprint = fingerprint;
        }

        // Geo routing (always sent so unchecking persists)
        const geoEnabled = document.getElementById('geoRoutingEnabled');
        const domStr = (document.getElementById('geoRoutingDomains')?.value || '').trim();
        const ipStr  = (document.getElementById('geoRoutingGeoip')?.value || '').trim();
        data.geoRouting = {
            enabled: !!geoEnabled?.checked,
            domains: domStr ? domStr.split(/[,\s]+/).filter(Boolean) : [],
            geoip:   ipStr  ? ipStr.split(/[,\s]+/).filter(Boolean)  : [],
        };

        if (!data.name || !data.portalNodeId || !data.bridgeNodeId) {
            alert(i18n.fillRequired || 'Please fill in all required fields');
            return;
        }

        data.expectedTopologyRevision = topologyRevision;
        btn.disabled = true;
        btn.innerHTML = '<i class="ti ti-loader-2 spin"></i>';

        try {
            linkFormWrites.add('main');
            const requestScope = linkId ? 'edit:' + linkId : 'main';
            if(rebuild && data.autoDeploy===true)data.interactivePreview=true;
            const headers = createRequestHeaders(data, requestScope);
            const sessionToken = csrfToken;
            const res = await fetchTopologyWrite(linkId ? ('/api/cascade/links/' + linkId) : '/api/cascade/links', {
                method: linkId ? 'PUT' : 'POST',
                headers,
                body: JSON.stringify(data),
            }, sessionToken);
            const savedSnapshot = await handleDraftMutationResponse(res, linkId ? 'link.apply' : 'link.create', linkId || undefined);
            if (!savedSnapshot) return;
            pendingCreateRequests[requestScope] = null;
            closeModal();
            if (savedSnapshot.fingerprintApplyRefused === true) return;
            await loadTopology();
            await handleLinkAutoDeploy(savedSnapshot, data.autoDeploy === true, sessionToken);
        } catch (err) {
            showToast((i18n.networkError || 'Error') + ': ' + err.message, 'error');
        } finally {
            linkFormWrites.delete('main');
            btn.disabled = false;
            btn.innerHTML = (linkId ? '' : '<i class="ti ti-plus"></i> ') + (linkId
                ? (data.autoDeploy === true ? (i18n.saveAndDeploy || 'Save & Deploy') : (i18n.save || 'Save'))
                : (i18n.createLink || 'Create'));
            renderFingerprintHint('main');
        }
    }

    // ==================== CASCADE ACTIONS ====================

    function setActionLoading(msg) {
        ['btnDeploy','btnDeployChain','btnDelete'].forEach(function (id) {
            const b = document.getElementById(id);
            if (b) b.disabled = true;
        });
        const body = document.getElementById('nodeInfoBody');
        if (body && !body.querySelector('.info-loading')) {
            const el = document.createElement('div');
            el.className = 'info-loading';
            el.innerHTML = '<i class="ti ti-loader-2 spin"></i> ' + msg;
            body.appendChild(el);
        }
    }

    function resetActionLoading() {
        ['btnDeploy','btnDeployChain','btnDelete'].forEach(function (id) {
            const b = document.getElementById(id);
            if (b) b.disabled = false;
        });
        const el = document.querySelector('.info-loading');
        if (el) el.remove();
    }

    async function deployTopology(linkId, domainLinkId, report, sessionToken = csrfToken) {
        const payload = { expectedTopologyRevision: topologyRevision };
        if (linkId) payload.linkId = linkId;
        if (domainLinkId) payload.domainLinkId = domainLinkId;
        // A concurrent reread applies to a new action, not to a workflow that
        // has already started under an older session token.
        if (rebuild) payload.expectedPreview = await rebuildPreview(payload, report, sessionToken);
        const scope = 'apply:' + linkId;
        const headers = linkId ? createRequestHeaders({ ...payload, autoDeploy: true,
            desiredVersion: _allLinks.find(link => link._id === linkId)?.desiredVersion }, scope) : { 'Content-Type': 'application/json' };
        const res = await fetchTopologyWrite('/api/cascade/topology/deploy', {
            method: 'POST',
            headers: rebuild ? headers : { ...headers, 'x-csrf-token': csrfToken },
            body: JSON.stringify(payload),
        }, sessionToken);
        const data = await res.json().catch(() => ({}));
        if (res.status === 409) {
            await loadTopology();
        }
        if (!res.ok) {
            const refusal = fingerprintRefusal(res.status, data);
            if (refusal) throw new RebuildFingerprintRefusal(refusal);
            throw new Error(describeTopologyError(data, 'HTTP ' + res.status));
        }
        const job = responseJob(data, 'link.apply', linkId);
        if (rebuild && data.executionMode === 'rebuild' && data.status === 'succeeded') return data;
        if (res.status === 202 && job) {
            if (data.desiredSaved !== true || data.linkId !== job.linkId) throw new Error(i18n.operationUnconfirmed || 'Ответ задания не подтверждён');
            pendingCreateRequests[scope] = null;
            startIntentPolling(job);
            return data;
        }
        if (!TRACKED_OPERATION_STATUSES.includes(data.status)) {
            throw new Error((i18n.deploymentEndedWithStatus || 'Deployment ended with status') + ': ' + (data.status || 'unknown'));
        }
        startOperationPolling(data);
        pendingCreateRequests[scope] = null;
        return data;
    }

    // ==================== OPERATION-SPECIFIC POLLING ====================

    const operationPolls = new Map();
    function stopOperationPolling(state) {
        const operationPollTimer = state.timer;
        if (operationPollTimer) {
            clearTimeout(operationPollTimer);
        }
        operationPolls.delete(state.operationId);
    }

    function startOperationPolling(result) {
        if (!TRACKED_OPERATION_STATUSES.includes(result?.status)) return;
        startBoundOperationPolling(result.operationId, result.kind, result.linkId);
    }

    function startBoundOperationPolling(operationId, kind, linkId, jobId) {
        if (!/^[a-f0-9]{24}$/i.test(operationId || '') || operationPolls.has(operationId)) return;
        const state = { operationId, kind: kind || null, linkId, jobId, timer: null };
        operationPolls.set(operationId, state);
        scheduleOperationPollStep(state, 0);
    }

    function scheduleOperationPollStep(state, attempt) {
        state.timer = setTimeout(function () {
            state.timer = null;
            return runOperationPollStep(state, attempt);
        }, OPERATION_POLL_INTERVAL_MS);
    }

    async function runOperationPollStep(state, attempt) {
        let operation = null;
        let freshList = false;
        try {
            const res = await fetch('/api/cascade/topology/operations/' + encodeURIComponent(state.operationId));
            if (res.ok) {
                const payload = await res.json();
                if (payload?.operationId === state.operationId
                    && (!state.jobId || (payload.kind === state.kind && payload.linkId === state.linkId))) operation = payload;
            }
            if (operation && state.linkId) linkProgress.set(state.linkId, { ...operation, jobId: state.jobId });
            freshList = await loadTopology();
        } catch (_) {
            // Reads alone may be retried; accepted mutations are never replayed.
        }
        if (operationPolls.get(state.operationId) !== state) return;
        const status = operation?.status || null;
        const reconcile = operation?.phase === 'reconcile_required'
            || operation?.waitingReason === 'TOPOLOGY_RECONCILE_REQUIRED';
        const tombstone = deleteTombstones.get(state.linkId);
        if (reconcile && tombstone) tombstone.reconcile = true;
        const deleted = state.kind === 'link.delete' && status === 'succeeded'
            && operation?.phase === 'completed' && !reconcile && freshList && !listedLinkIds.has(state.linkId);
        const keepPolling = state.kind === 'link.delete'
            ? !deleted && !reconcile && !['failed', 'rolled_back'].includes(status) && attempt < OPERATION_POLL_MAX_ATTEMPTS
            : !reconcile && shouldContinueOperationPolling({ attempt, status,
                clientReadiness: operation?.clientReadiness, clientProofState: operation?.clientProofState });
        const progress = progressMessage(operation);
        if (keepPolling) {
            if (progress && progress !== state.message) { state.message = progress; showToast(progress); }
            scheduleOperationPollStep(state, attempt + 1);
            return;
        }
        stopOperationPolling(state);
        if (deleted) {
            confirmedDeletions.add(state.linkId);
            deleteTombstones.delete(state.linkId);
            linkProgress.delete(state.linkId);
            await loadTopology();
            showToast(i18n.deleteSuccess || 'Связь удалена');
            return;
        }
        if (reconcile || state.kind === 'link.delete') {
            if (tombstone) tombstone.reconcile = true;
            await loadTopology();
            showToast((i18n.reconcileRequired || 'Ожидает сверки; завершение не подтверждено.') + ' ' + state.operationId
                + (progress ? ' · ' + progress : ''), 'error');
            return;
        }
        const applied = status === 'succeeded';
        const verified = applied && operation?.clientReadiness === 'verified';
        const degraded = applied && operation?.clientProofState === 'degraded';
        showToast(
            verified
                ? (i18n.operationApplied || 'Деплой завершён: топология применена') + ' — готовность подтверждена проверкой клиента'
                : applied
                    ? state.kind === 'link.apply'
                        ? 'Связь установлена; готовность полной цепочки ещё не подтверждена; готовность клиента не подтверждена'
                        : (i18n.operationApplied || 'Деплой завершён: топология применена') + ' — готовность клиента не подтверждена'
                    : status === 'failed' || status === 'rolled_back'
                        ? (i18n.deployFailed || 'Деплой не выполнен') + ': ' + status
                        : (i18n.operationStillRunning || 'Операция всё ещё выполняется в фоне'),
            applied && !degraded ? 'success' : 'error',
        );
    }

    window._cascadeDeploy = async function (linkId) {
        if (!rebuild && !confirm(i18n.confirmDeploy || 'Deploy this cascade link?')) return;
        setActionLoading(i18n.deploying || 'Deploying...');

        const edge = cy.edges().filter(e => e.data('linkId') === linkId);
        const prev = edge.length ? edge.data('status') : null;
        if (edge.length) edge.data('status', 'syncing');

        try {
            const result = await deployTopology(linkId);
            showToast(deployResultMessage(result, i18n));
            loadTopology();
            closeInfoModal();
        } catch (err) {
            if (edge.length && prev) edge.data('status', prev);
            if (err instanceof RebuildPreviewStopped) return showToast(err.message, 'info');
            showToast((i18n.deployFailed || 'Failed') + ': ' + err.message, 'error');
        } finally { resetActionLoading(); }
    };

    window._cascadeDeployChain = async function (linkId) {
        const anchorError = domainSyncAnchorError(linkId);
        if (anchorError) {
            showToast(anchorError, 'error');
            return;
        }
        if (!confirm(syncDomainLabel + '? ' + syncDomainScope)) return;
        setActionLoading(escHtml(i18n.syncingAppliedDomain || 'Синхронизация применённого домена...'));

        const edge = cy.edges().filter(e => e.data('linkId') === linkId);
        if (edge.length) edge.data('status', 'syncing');

        try {
            const result = await deployTopology(null, linkId);
            showToast(deployResultMessage(result, i18n));
            loadTopology();
            closeInfoModal();
        } catch (err) {
            showToast((i18n.appliedDomainSyncFailed || 'Не удалось синхронизировать применённый домен') + ': ' + err.message, 'error');
            loadTopology();
        } finally { resetActionLoading(); }
    };

    // Explicit legacy full Sync includes every active edge. The per-chain
    // action never falls through to this global operation.
    window._cascadeDeployFull = async function () {
        if (!confirm('Синхронизировать всю топологию? Все активные связи будут включены.')) return;
        setActionLoading(i18n.syncingChain || 'Syncing topology...');
        try {
            const result = await deployTopology();
            showToast(deployResultMessage(result, i18n));
            loadTopology();
        } catch (err) {
            showToast((i18n.chainDeployFailed || 'Full sync failed') + ': ' + err.message, 'error');
            loadTopology();
        } finally { resetActionLoading(); }
    };

    window._cascadeUndeploy = async function (linkId) {
        if (rebuild) return;
        if (!confirm(i18n.confirmUndeploy || 'Undeploy this cascade link?')) return;
        setActionLoading(i18n.undeploying || 'Undeploying...');

        const edge = cy.edges().filter(e => e.data('linkId') === linkId);
        const prev = edge.length ? edge.data('status') : null;
        if (edge.length) edge.data('status', 'syncing');

        try {
            const response = await fetch('/api/cascade/links/' + linkId + '/undeploy', { method: 'POST' });
            const payload = await response.json().catch(() => ({}));
            if (!response.ok || payload.success !== true) {
                throw new Error(describeTopologyError(payload,
                    i18n.undeployFailed || 'Снятие деплоя не подтверждено'));
            }
            showToast(i18n.undeploySuccess || 'Undeployed');
            await loadTopology();
            closeInfoModal();
        } catch (err) {
            if (edge.length && prev) edge.data('status', prev);
            showToast((i18n.networkError || 'Error') + ': ' + err.message, 'error');
            await loadTopology();
        } finally { resetActionLoading(); }
    };

    window._cascadeDelete = async function (linkId) {
        const pending = deleteTombstones.get(linkId);
        if (pending?.jobId) {
            showToast((pending.reconcile ? (i18n.reconcileRequired || 'Ожидает сверки')
                : (i18n.linkDeleting || 'Удаляется')) + ' · ' + pending.jobId, pending.reconcile ? 'error' : undefined);
            return;
        }
        if (!rebuild && !confirm(i18n.confirmDeleteLink
            || 'Удалить каскадную связь? Удаление может прервать маршруты и трафик пользователей. Без другого разрешённого выхода маршрут останется без выхода.')) return;
        setActionLoading(i18n.deleting || 'Deleting...');

        const link = _allLinks.find(link => link._id === linkId);
        let response;
        try {
            const scope = 'delete:' + linkId;
            const sessionToken = csrfToken;
            const expectedPreview = rebuild ? await rebuildPreview({linkId,remove:true}, undefined, sessionToken) : undefined;
            response = await fetchTopologyWrite('/api/cascade/links/' + linkId, {
                method: 'DELETE',
                headers: createRequestHeaders({ autoDeploy: true, linkId }, scope),
                body: JSON.stringify({ expectedTopologyRevision: topologyRevision, expectedPreview }),
            }, sessionToken);
            const result = await handleDraftMutationResponse(response, 'link.delete', linkId);
            if (!result) return;
            if(rebuild && result.executionMode==='rebuild' && result.deleted===linkId){showToast('Связь удалена, обе части пересобраны');await loadTopology();closeInfoModal();return;}
            const job = responseJob(result, 'link.delete', linkId);
            if (job) {
                retainDeletion(link, job.jobId);
                const tombstone = deleteTombstones.get(linkId);
                if (tombstone && (result.applicationState === 'reconcile_required' || ['blocked', 'failed'].includes(job.status))) tombstone.reconcile = true;
                startIntentPolling(job);
                pendingCreateRequests[scope] = null;
                showToast(jobAcceptedMessage(job));
                await loadTopology();
                return;
            }
            if (result.links.some(link => link._id === linkId)) throw new Error(i18n.operationUnconfirmed || 'Удаление не подтверждено');
            deleteTombstones.delete(linkId);
            confirmedDeletions.add(linkId);
            pendingCreateRequests[scope] = null;
            showToast(i18n.deleteSuccess || 'Deleted');
            await loadTopology();
            closeInfoModal();
        } catch (err) {
            if (err instanceof RebuildPreviewStopped) return showToast(err.message, 'info');
            if (err instanceof RebuildFingerprintRefusal) return showToast(err.message, 'error');
            if (!(err instanceof TopologyCsrfRejection) && (!response || response.ok || response.status >= 500)) {
                // A lost/malformed acceptance is not proof of no accepted job.
                // Retain the segment, but do not invent a server job or marker.
                retainDeletion(link, null);
                await loadTopology();
            }
            showToast((i18n.networkError || 'Error') + ': ' + err.message, 'error');
        } finally { resetActionLoading(); }
    };

    window._cascadeEdit = async function (linkId) {
        try {
            await openEditLinkModal(linkId);
            closeInfoModal();
        } catch (err) {
            showToast((i18n.networkError || 'Error') + ': ' + err.message, 'error');
        }
    };

    // ==================== HELPERS ====================

    function showLoading(show) {
        let el = document.querySelector('.network-loading');
        if (show && !el) {
            el = document.createElement('div');
            el.className = 'network-loading';
            el.innerHTML = '<div class="spinner"></div> ' + (i18n.loadingTopology || 'Loading...');
            const c = document.querySelector('.network-container');
            if (c) c.appendChild(el);
        } else if (!show && el) {
            el.remove();
        }
    }

    function setEmptyState(show) {
        const el  = document.getElementById('networkEmpty');
        const leg = document.getElementById('networkLegend');
        if (el)  el.style.display  = show ? 'flex' : 'none';
        if (leg) leg.style.display = show ? 'none' : '';
    }

    function showToast(message, type) {
        if (typeof window.showToast === 'function') {
            window.showToast(message, type || 'success');
            return;
        }
        let toast = document.getElementById('toast');
        if (!toast) {
            toast = document.createElement('div');
            toast.id = 'toast';
            toast.className = 'toast';
            document.body.appendChild(toast);
        }
        toast.textContent = message;
        toast.className = 'toast show ' + (type || 'success');
        setTimeout(function () { toast.className = 'toast'; }, 3500);
    }

    // ==================== MODE SWITCHER ====================

    function initModeSwitcher(switcherId, inputId, hintId) {
        var switcher = document.getElementById(switcherId);
        if (!switcher) return;
        var btns = switcher.querySelectorAll('.mode-btn');
        btns.forEach(function (btn) {
            btn.addEventListener('click', function () {
                btns.forEach(function (b) { b.classList.remove('active'); });
                btn.classList.add('active');
                var mode = btn.getAttribute('data-mode');
                var input = document.getElementById(inputId);
                if (input) input.value = mode;
                if (hintId) {
                    var hint = document.getElementById(hintId);
                    if (hint) {
                        hint.textContent = mode === 'forward'
                            ? (i18n.modeForwardHint || 'Portal connects to Bridge directly. All nodes need public IP.')
                            : (i18n.modeReverseHint || 'Bridge initiates tunnel to Portal. Bridge can be behind NAT.');
                    }
                }
                // Show/hide tunnel domain field (reverse only)
                var domGroup = document.getElementById('tunnelDomainGroup');
                if (domGroup) domGroup.style.display = mode === 'forward' ? 'none' : '';
                if (inputId === 'quickLinkMode') {
                    schedulePortWarning('quick');
                    renderFingerprintHint('quick');
                }
                else updateLinkFormWarnings();
            });
        });
    }

    function canSetTunnelEncryption(form) {
        return rebuild && form.tunnelEncryption && form.tunnelSecurity.value === 'none'
            && (form.mode?.value !== 'forward' || form.tunnelProtocol.value === 'vless');
    }

    function updateLinkFormWarnings() {
        var form = document.getElementById('addLinkForm');
        if (!form) return;
        const encryptionGroup = document.getElementById('tunnelEncryptionGroup');
        if (encryptionGroup) encryptionGroup.hidden = !canSetTunnelEncryption(form);
        var mode = (document.getElementById('linkModeInput') || {}).value || 'reverse';
        var isForward = mode === 'forward';

        var flowHint = document.getElementById('modeFlowHint');
        if (flowHint) {
            flowHint.textContent = isForward
                ? (i18n.modeForwardFlow || 'Traffic path: Client → Portal → Relay → Bridge → Internet.')
                : (i18n.modeReverseFlow || 'Traffic path: Client → Portal → Bridge → Internet. Tunnel initiated by Bridge.');
        }

        var warnHint = document.getElementById('modeWarnHint');
        if (warnHint) {
            warnHint.textContent = isForward
                ? (i18n.modeForwardWarning || 'Forward Chain requires all hops to have a public IP. Verify exit after each sync.')
                : (i18n.modeReverseWarning || 'After deploy, confirm the tunnel is up and traffic exits from the expected Bridge.');
        }

        var portHint = document.getElementById('tunnelPortHint');
        if (portHint) {
            portHint.textContent = isForward
                ? (i18n.tunnelPortForwardHint || 'In Forward Chain this port is listened on the Bridge/Relay side of this hop.')
                : (i18n.tunnelPortReverseHint || 'In Reverse mode this port is listened on the Portal node.');
        }

        schedulePortWarning('main');
        renderFingerprintHint('main');
    }

    function renderFingerprintHint(kind) {
        if (!rebuild) return false;
        const quick = kind === 'quick';
        const get = id => document.getElementById(id);
        const form = get('addLinkForm');
        const active = get(quick ? 'quickLinkModal' : 'addLinkModal')?.classList.contains('active');
        const security = quick ? (get('quickTunnelSecurity')?.value || 'reality') : form?.tunnelSecurity?.value;
        const mode = quick ? get('quickLinkMode')?.value : form?.mode?.value;
        const source = quick ? get('quickPortalId') : form?.portalNodeId;
        const target = quick ? get('quickBridgeId') : form?.bridgeNodeId;
        // Unlike port checks, the fingerprint belongs to the outbound dialer.
        const dialerId = (mode === 'forward' ? source : target)?.value;
        const node = fingerprintInventory[kind].get(dialerId);
        const version = node?.version;
        const pick = !quick && form?.realityFingerprint;
        const selected = resolveRealityFingerprint(pick?.value, quick ? 'create' : linkModalMode);
        const show = active && security === 'reality' && !!dialerId;
        const limited = security === 'reality' && /^26\.11\./.test(version);
        // A disabled, already-selected option remains visible until changed.
        // The submit handler rechecks so synthetic/keyboard paths cannot send it.
        const blocked = limited && !!selected && !REALITY_FINGERPRINTS_26_11.includes(selected);
        if (pick) for (const option of pick.options) {
            option.disabled = show && limited && !!option.value && !REALITY_FINGERPRINTS_26_11.includes(option.value);
        }
        const hint = get(quick ? 'quickFingerprintHint' : 'linkFingerprintHint');
        if (hint && fingerprintLabels) {
            const values = { name: node?.name || _allNodes.get(dialerId)?.label || dialerId, version,
                fingerprint: selected || fingerprintLabels.unset, allowed: REALITY_FINGERPRINTS_26_11.join(', ') };
            hint.textContent = show ? fingerprintCopy(!version ? 'unknown' : blocked ? 'mismatch' : limited ? 'limited' : 'known', values) : '';
            hint.hidden = !show;
        }
        const submit = get(quick ? 'quickLinkSubmit' : 'linkModalSubmit');
        if (submit) submit.disabled = (show && blocked) || linkFormWrites.has(kind);
        return blocked;
    }

    const linkFormWrites = new Set();

    function fingerprintSubmissionBlocked(kind) {
        if (rebuild && linkFormWrites.has(kind)) return true;
        return renderFingerprintHint(kind);
    }

    let quickFingerprintRead;
    function resetQuickFingerprintHint() {
        quickFingerprintRead = undefined;
        fingerprintInventory.quick = new Map();
        renderFingerprintHint('quick');
    }

    function initFingerprintWarnings() {
        for (const id of ['selectPortal', 'selectBridge']) {
            document.getElementById(id)?.addEventListener('change', updateLinkFormWarnings);
        }
        document.querySelector('#addLinkForm [name="realityFingerprint"]')
            ?.addEventListener('change', updateLinkFormWarnings);
        const modal = document.getElementById('quickLinkModal');
        if (!modal || !document.getElementById('quickFingerprintHint')) return;
        async function updateQuick() {
            if (!modal.classList.contains('active')) return resetQuickFingerprintHint();
            renderFingerprintHint('quick');
            if (quickFingerprintRead || document.getElementById('quickTunnelSecurity')?.value !== 'reality') return;
            const read = fetch('/api/nodes', { cache: 'no-store', redirect: 'error' });
            quickFingerprintRead = read;
            try {
                const response = await read;
                if (!response.ok) return;
                const nodes = await response.json();
                if (read !== quickFingerprintRead || !modal.classList.contains('active')) return;
                fingerprintInventory.quick = readFingerprintInventory(nodes);
                renderFingerprintHint('quick');
            } catch (_) { /* The form already shows an unknown-version hint. */ }
        }
        for (const id of ['quickPortalId', 'quickBridgeId', 'quickTunnelSecurity']) {
            document.getElementById(id)?.addEventListener('change', updateQuick);
        }
        new MutationObserver(updateQuick).observe(modal, { attributes: true, attributeFilter: ['class'] });
        void updateQuick();
    }

    const portWarnings = {
        main: { generation: 0, key: null, status: null, timer: null, deadline: null, controller: null },
        quick: { generation: 0, key: null, status: null, timer: null, deadline: null, controller: null },
    };

    function portWarningContext(kind) {
        const quick = kind === 'quick';
        const form = document.getElementById('addLinkForm');
        const value = id => document.getElementById(id)?.value || '';
        const mode = quick ? value('quickLinkMode') : (form?.mode?.value || 'reverse');
        const portal = quick ? value('quickPortalId') : (form?.portalNodeId?.value || '');
        const bridge = quick ? value('quickBridgeId') : (form?.bridgeNodeId?.value || '');
        const rawPort = quick ? value('quickTunnelPort') : (form?.tunnelPort?.value || '');
        const linkId = quick ? '' : value('linkIdInput');
        const nodeId = mode === 'forward' ? bridge : portal;
        const port = /^\d+$/.test(rawPort) ? Number(rawPort) : NaN;
        const modal = document.getElementById(quick ? 'quickLinkModal' : 'addLinkModal');
        const valid = modal?.classList.contains('active') && /^[a-f0-9]{24}$/i.test(nodeId)
            && (!linkId || /^[a-f0-9]{24}$/i.test(linkId))
            && Number.isInteger(port) && port >= 1 && port <= 65535;
        return { nodeId, port, linkId, key: valid ? JSON.stringify([nodeId, port, linkId, mode, portal, bridge]) : null };
    }

    function cachedPortConflict(context) {
        return context.key && _allLinks.find(link => {
            if (!link?.active || String(link._id) === context.linkId) return false;
            // Each existing link has its own listening side, even in mixed modes.
            const ref = link[link.mode === 'forward' ? 'bridgeNode' : 'portalNode'];
            const nodeId = ref && typeof ref === 'object' ? ref._id : ref;
            return String(nodeId || '') === context.nodeId && Number(link.tunnelPort) === context.port;
        });
    }

    function portWarningText(key, fallback, context) {
        return (i18n[key] || fallback).replace(/\{port\}/g, String(context.port))
            .replace(/\{node\}/g, context.nodeId);
    }

    function renderPortWarning(kind, context) {
        const hint = document.getElementById(kind === 'quick' ? 'quickPortConflictHint' : 'portConflictHint');
        if (!hint) return;
        const state = portWarnings[kind];
        const conflict = cachedPortConflict(context);
        const status = conflict ? 'occupied' : state.status;
        hint.style.display = context.key ? '' : 'none';
        hint.textContent = !context.key ? '' : status === 'occupied'
            ? portWarningText('portCheckOccupied', 'Port {port} is already in use on listening node {node}. Choose another port before deploying. Saving without deployment is still possible.', context)
                + (conflict ? ' (' + (conflict.name || 'link') + ')' : '')
            : status === 'available'
                ? portWarningText('portCheckAvailable', 'Port {port} is available on listening node {node}. It will be checked again when saving or deploying.', context)
                : status === 'unknown'
                    ? portWarningText('portCheckUnknown', 'Could not check port {port} on listening node {node}. Availability is unknown; saving or deploying will check again.', context)
                    : portWarningText('portCheckChecking', 'Checking port {port} on listening node {node}…', context);
    }

    function resetPortWarning(kind) {
        const state = portWarnings[kind];
        state.generation += 1;
        clearTimeout(state.timer);
        clearTimeout(state.deadline);
        state.controller?.abort();
        state.timer = state.deadline = state.controller = state.key = state.status = null;
    }

    function schedulePortWarning(kind) {
        // The classic listener probe is unavailable in rebuild mode.
        if (rebuild) return;
        const context = portWarningContext(kind);
        const state = portWarnings[kind];
        if (context.key === state.key) { renderPortWarning(kind, context); return; }
        resetPortWarning(kind);
        state.key = context.key;
        renderPortWarning(kind, context);
        if (!context.key) return;
        const generation = state.generation;
        state.timer = setTimeout(async function () {
            state.timer = null;
            const controller = new AbortController();
            state.controller = controller;
            const current = () => state.generation === generation
                && portWarningContext(kind).key === context.key;
            const deadline = state.deadline = setTimeout(() => {
                if (!current()) return;
                state.generation += 1; // Ignore late JSON even if abort is not honored.
                state.status = 'unknown';
                state.controller = state.deadline = null;
                controller.abort();
                renderPortWarning(kind, context);
            }, 10000);
            try {
                const query = new URLSearchParams({ nodeId: context.nodeId, port: String(context.port) });
                if (context.linkId) query.set('linkId', context.linkId);
                const response = await fetch('/api/cascade/links/port-check?' + query.toString(), {
                    signal: controller.signal, cache: 'no-store', credentials: 'same-origin',
                });
                if (response.status !== 200) throw new Error('Port check unavailable');
                const result = await response.json();
                if (result?.port !== context.port || typeof result.available !== 'boolean'
                    || result.code !== (result.available ? null : 'TUNNEL_PORT_IN_USE')) {
                    throw new Error('Invalid port check response');
                }
                if (current()) state.status = result.available ? 'available' : 'occupied';
            } catch (_) {
                if (current()) state.status = 'unknown';
            } finally {
                clearTimeout(deadline);
                if (current()) {
                    state.controller = state.deadline = null;
                    renderPortWarning(kind, context);
                }
            }
        }, 300);
    }

    function portSubmissionBlocked(kind) {
        // Rebuild leaves admission to the server and its guarded preview.
        if (rebuild) return false;
        schedulePortWarning(kind);
        const context = portWarningContext(kind);
        const deploying = kind === 'quick' ? document.getElementById('quickAutoDeploy')?.checked
            : document.getElementById('addLinkForm')?.autoDeploy?.checked;
        if (deploying && context.key && (cachedPortConflict(context) || portWarnings[kind].status === 'occupied')) {
            showToast(portWarningText('portCheckOccupied',
                'Port {port} is already in use on listening node {node}. Choose another port before deploying. Saving without deployment is still possible.', context), 'error');
            return true;
        }
        // Unknown/checking is advisory, not a new save-only restriction. The
        // server must recheck the actual listener before any deployment write.
        return false;
    }

    function initPortWarnings() {
        ['selectPortal', 'selectBridge'].forEach(id => {
            document.getElementById(id)?.addEventListener('change', updateLinkFormWarnings);
        });
        const port = document.querySelector('#addLinkForm [name="tunnelPort"]');
        ['input', 'change'].forEach(event => port?.addEventListener(event, updateLinkFormWarnings));
        ['quickTunnelPort', 'quickPortalId', 'quickBridgeId'].forEach(id => {
            ['input', 'change'].forEach(event => document.getElementById(id)?.addEventListener(event,
                () => schedulePortWarning('quick')));
        });
        // Also covers quick-form opening by graph/UI integrations and closing
        // before an outstanding response arrives. Never poll a hidden modal.
        ['main', 'quick'].forEach(kind => {
            const modal = document.getElementById(kind === 'quick' ? 'quickLinkModal' : 'addLinkModal');
            if (modal) new MutationObserver(() => schedulePortWarning(kind))
                .observe(modal, { attributes: true, attributeFilter: ['class'] });
        });
    }

    // ==================== QUICK LINK MODAL ====================

    function closeQuickModal() {
        resetPortWarning('quick');
        var modal = document.getElementById('quickLinkModal');
        if (modal) modal.classList.remove('active');
        var security = document.getElementById('quickTunnelSecurity');
        if (rebuild && security) security.value = 'reality';
        resetQuickFingerprintHint();
    }

    function onQuickSwap() {
        var pId = document.getElementById('quickPortalId');
        var bId = document.getElementById('quickBridgeId');
        var pName = document.getElementById('quickPortalName');
        var bName = document.getElementById('quickBridgeName');
        if (!pId || !bId) return;
        var tmpId = pId.value; pId.value = bId.value; bId.value = tmpId;
        var tmpName = pName.textContent; pName.textContent = bName.textContent; bName.textContent = tmpName;
        schedulePortWarning('quick');
        renderFingerprintHint('quick');
    }

    async function onQuickLinkSubmit(e) {
        e.preventDefault();
        if (portSubmissionBlocked('quick')) return;
        if (fingerprintSubmissionBlocked('quick')) return;
        var data = {
            name: document.getElementById('quickLinkName').value,
            mode: document.getElementById('quickLinkMode').value || 'reverse',
            portalNodeId: document.getElementById('quickPortalId').value,
            bridgeNodeId: document.getElementById('quickBridgeId').value,
            tunnelPort: parseInt(document.getElementById('quickTunnelPort').value) || 10086,
            tunnelProtocol: document.getElementById('quickTunnelProtocol').value,
            autoDeploy: document.getElementById('quickAutoDeploy')?.checked || false,
        };
        if (rebuild) {
            data.tunnelSecurity = document.getElementById('quickTunnelSecurity')?.value || 'reality';
            if (data.tunnelSecurity === 'reality') data.realityFingerprint = CREATE_DEFAULT_FINGERPRINT;
        }
        if (!data.name || !data.portalNodeId || !data.bridgeNodeId) {
            alert(i18n.fillRequired || 'Please fill in all required fields');
            return;
        }
        data.expectedTopologyRevision = topologyRevision;
        var btn = document.getElementById('quickLinkSubmit');
        if (btn) { btn.disabled = true; btn.innerHTML = '<i class="ti ti-loader-2 spin"></i>'; }
        linkFormWrites.add('quick');
        try {
            if(rebuild && data.autoDeploy===true)data.interactivePreview=true;
            const sessionToken = csrfToken;
            var res = await fetchTopologyWrite('/api/cascade/links', {
                method: 'POST',
                headers: createRequestHeaders(data, 'quick'),
                body: JSON.stringify(data),
            }, sessionToken);
            const createdSnapshot = await handleDraftMutationResponse(res, 'link.create');
            if (!createdSnapshot) return;
            pendingCreateRequests.quick = null;
            closeQuickModal();
            if (createdSnapshot.fingerprintApplyRefused === true) return;
            await loadTopology();
            await handleLinkAutoDeploy(createdSnapshot, data.autoDeploy === true, sessionToken);
        } catch (err) {
            showToast((i18n.networkError || 'Error') + ': ' + err.message, 'error');
        } finally {
            linkFormWrites.delete('quick');
            if (btn) { btn.disabled = false; btn.innerHTML = '<i class="ti ti-plus"></i> ' + (i18n.createLink || 'Create'); }
            renderFingerprintHint('quick');
        }
    }

    // ==================== START ====================

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
