/**
 * Network topology visualization using cytoscape.js
 * With particle traffic animation and glow effects.
 */

(function () {
    'use strict';

    // ==================== PURE HELPERS (exported for tests) ====================

    // Newly created links default to Random. Edits must retain even an empty
    // legacy value unless the operator explicitly selects a fingerprint.
    const CREATE_DEFAULT_FINGERPRINT = 'random';

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
    const OPERATION_POLL_MAX_ATTEMPTS = 40; // ~2 minutes, then the 30s loop takes over

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

    function deployResultMessage(result, labels = {}) {
        const outcome = result.status === 'succeeded'
            ? (labels.deployAlreadyDeployed || 'Topology already deployed')
            : (labels.deployQueued || 'Deployment queued');
        return outcome + ' — ' + (labels.clientReadinessUnverified || CLIENT_READINESS_UNVERIFIED);
    }

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            CREATE_DEFAULT_FINGERPRINT,
            OPERATION_POLL_INTERVAL_MS,
            OPERATION_POLL_MAX_ATTEMPTS,
            TOPOLOGY_CAUSE_TEXT_RU,
            clientReadinessMessage,
            deployResultMessage,
            describeTopologyError,
            fingerprintForLinkEdit,
            resolveRealityFingerprint,
            shouldContinueOperationPolling,
            topologyCauseText,
        };
    }

    if (typeof cytoscape === 'undefined') return;

    if (typeof cytoscapeDagre !== 'undefined') {
        cytoscape.use(cytoscapeDagre);
    }

    const i18n = window._networkI18n || {};
    const csrfToken = window._networkCsrfToken || '';

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
    let topologyRevision = null;
    let deployedRevision = null;
    let _allLinks = [];

    function applyLinkSnapshot(snapshot) {
        if (!snapshot || !Number.isSafeInteger(snapshot.topologyRevision)
            || !Number.isSafeInteger(snapshot.deployedRevision)
            || !Array.isArray(snapshot.links)) {
            throw new Error('Invalid cascade-link snapshot');
        }
        topologyRevision = snapshot.topologyRevision;
        deployedRevision = snapshot.deployedRevision;
        _allLinks = snapshot.links;
        return snapshot;
    }

    async function handleDraftMutationResponse(response) {
        const payload = await response.json().catch(() => ({}));
        const errorMessage = describeTopologyError(payload, 'HTTP ' + response.status);
        if (response.status === 409) {
            await loadTopology();
            showToast((i18n.networkError || 'Error') + ': ' + errorMessage, 'error');
            return null;
        }
        if (!response.ok) throw new Error(errorMessage);
        return applyLinkSnapshot(payload);
    }

    // ==================== INIT ====================

    function init() {
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

        // Transport change -> disable REALITY for ws + refresh warnings
        var transSel = document.getElementById('selectTransport');
        if (transSel) transSel.addEventListener('change', function () {
            var secSelect = document.getElementById('selectSecurity');
            if (!secSelect) return;
            var realityOpt = secSelect.querySelector('option[value="reality"]');
            if (!realityOpt) return;
            if (this.value === 'ws') {
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

        // Portal/Bridge selects -> refresh port conflict hint
        ['selectPortal', 'selectBridge'].forEach(function (id) {
            var el = document.getElementById(id);
            if (el) el.addEventListener('change', updateLinkFormWarnings);
        });

        // Tunnel port input -> refresh port conflict hint
        var tpInput = document.querySelector('#addLinkForm [name="tunnelPort"]');
        if (tpInput) tpInput.addEventListener('input', updateLinkFormWarnings);

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
            applyLinkSnapshot(await linksRes.json());
            renderGraph(data);
        } catch (err) {
            console.error('[Network] Topology load error:', err);
        } finally {
            showLoading(false);
        }
    }

    async function refreshStatuses() {
        try {
            const res = await fetch('/api/cascade/topology');
            if (!res.ok) return;
            const data = await res.json();
            cy.batch(function () {
                for (const n of data.nodes) {
                    const ele = cy.getElementById(n.data.id);
                    if (ele.length) {
                        ele.data('status', n.data.status);
                        ele.data('onlineUsers', n.data.onlineUsers);
                    }
                }
                for (const e of data.edges) {
                    const ele = cy.getElementById(e.data.id);
                    if (ele.length) {
                        ele.data('status', e.data.status);
                        ele.data('latencyMs', e.data.latencyMs);
                        ele.data('clientReadiness', e.data.clientReadiness);
                    }
                }
            });
        } catch (_) {}
    }

    function renderGraph(data) {
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
        if (isEmpty) { setEmptyState(true); return; }
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

        for (const e of data.edges) {
            elements.push({
                group: 'edges',
                data: { ...e.data, edgeLabel: buildEdgeLabel(e.data) },
            });
        }

        cy.add(elements);

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
        if (link.active === false) return 'Связь отключена — включите её перед синхронизацией домена';
        return ['deployed', 'online', 'staged'].includes(link.status)
            ? null : topologyCauseText('SCOPE_LINK_UNCONFIRMED');
    }

    function onEdgeTap(evt) {
        const d = evt.target.data();
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
            field(i18n.routePath || 'Traffic path', escHtml(summary.chain)) +
            field('ti-login-2',     i18n.routeEntry     || 'Entry',             escHtml(summary.entry)) +
            field('ti-logout-2',    i18n.routeExit      || 'Exit',              escHtml(summary.exit)) +
            field('ti-shield-lock', i18n.routeEncryption || 'Tunnel encryption', escHtml(summary.encryption)) +
            '</div>' +
            field(i18n.drawerStatus || 'Status',
                '<div class="info-status ' + sc + '">\u25CF ' + (d.status || 'pending') + '</div>') +
            field('ti-shield-check', 'Готовность клиента',
                escHtml(clientReadinessMessage(d.clientReadiness, topologyRevision, deployedRevision))) +
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
            '<button class="btn btn-sm btn-outline" id="btnEdit" onclick="window._cascadeEdit(\'' + lid + '\')">' +
            '<i class="ti ti-edit"></i> ' + (i18n.edit || 'Edit') + '</button>' +
            '<button class="btn btn-sm btn-success" id="btnDeploy" onclick="window._cascadeDeploy(\'' + lid + '\')">' +
            '<i class="ti ti-upload"></i> ' + (i18n.deploy || 'Deploy') + '</button>' +
            '<button class="btn btn-sm btn-primary" id="btnDeployChain" onclick="window._cascadeDeployChain(\'' + lid + '\')">' +
            '<i class="ti ti-link"></i> ' + escHtml(syncDomainLabel) + '</button>' +
            '<button class="btn btn-sm btn-outline" id="btnUndeploy" onclick="window._cascadeUndeploy(\'' + lid + '\')">' +
            '<i class="ti ti-player-stop"></i> ' + (i18n.undeployLink || 'Undeploy') + '</button>' +
            '<button class="btn btn-sm btn-danger" id="btnDelete" onclick="window._cascadeDelete(\'' + lid + '\')">' +
            '<i class="ti ti-trash"></i> ' + (i18n.delete || 'Delete') + '</button>' +
            '</div>';

        openInfoModal(d.label || 'Cascade Link', html +
            '<p class="info-hint">' + escHtml(syncDomainScope) + '</p>' +
            (domainSyncAnchorError(lid)
                ? '<p class="info-hint">' + escHtml(domainSyncAnchorError(lid)) + '</p>' : ''));
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

        // Walk the chain following edges with the same mode
        const hops = ['Client', entryLabel];
        const visited = new Set([edgeData.source]);
        let curId = edgeData.target;
        let safety = 0;
        while (curId && !visited.has(curId) && safety++ < 8) {
            visited.add(curId);
            const node = cy.getElementById(curId);
            const lbl = node.length ? (node.data('label') || node.data('ip') || curId) : curId;
            hops.push(lbl);
            const nextEdge = cy.edges().toArray().find(function (e) {
                return e.data('mode') === edgeData.mode &&
                    !e.data('isInternetEdge') &&
                    e.data('source') === curId;
            });
            if (!nextEdge) break;
            curId = nextEdge.data('target');
        }
        hops.push('Internet');

        const sec = edgeData.tunnelSecurity || 'none';
        const encLabel = sec === 'none'
            ? 'None'
            : sec.toUpperCase() + ' (' + (edgeData.tunnelProtocol || 'vless').toUpperCase() + ')';

        return {
            chain: hops.join(' → '),
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
            opt.textContent = value || 'Сохранить прежнее значение';
            select.appendChild(opt);
        }
        select.value = value;
    }

    async function openAddLinkModal() {
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
        document.getElementById('addLinkForm').autoDeploy.checked = true;
        updateLinkSubmitIntent();
        // A brand-new link starts from the Random REALITY fingerprint, even if
        // the form still carries an injected option from a previous edit.
        var createFp = document.querySelector('#addLinkForm [name="realityFingerprint"]');
        if (createFp) {
            Array.from(createFp.options).forEach(option => {
                if (option.value === '') option.remove();
            });
            createFp.value = resolveRealityFingerprint(null, 'create');
        }

        try {
            const [nodesRes, linksRes] = await Promise.all([
                fetch('/api/nodes'),
                fetch('/api/cascade/links'),
            ]);
            if (!nodesRes.ok || !linksRes.ok) throw new Error();
            const nodes = await nodesRes.json();
            applyLinkSnapshot(await linksRes.json());
            const opts  = nodes.map(n =>
                '<option value="' + n._id + '">' + (n.flag || '') + ' ' + n.name + ' (' + n.ip + ')</option>'
            ).join('');

            portalSelect.innerHTML = '<option value="">' + (i18n.selectPortal || '— Select Portal —') + '</option>' + opts;
            bridgeSelect.innerHTML = '<option value="">' + (i18n.selectBridge || '— Select Bridge —') + '</option>' + opts;
        } catch (_) {
            const err = '<option value="">' + (i18n.errorLoadingNodes || 'Error loading nodes') + '</option>';
            portalSelect.innerHTML = bridgeSelect.innerHTML = err;
        }
        updateLinkFormWarnings();
        modal.classList.add('active');
    }

    async function openEditLinkModal(linkId) {
        const form = document.getElementById('addLinkForm');
        const title = document.getElementById('linkModalTitle');
        const submit = document.getElementById('linkModalSubmit');
        const linkIdInput = document.getElementById('linkIdInput');

        await openAddLinkModal();
        linkModalMode = 'edit';
        if (title) title.textContent = (i18n.edit || 'Edit') + ' Link';
        if (submit) submit.textContent = i18n.save || 'Save';
        if (linkIdInput) linkIdInput.value = linkId;

        const res = await fetch('/api/cascade/links/' + linkId);
        if (!res.ok) throw new Error('Failed to load link');
        const link = await res.json();

        form.name.value = link.name || '';
        form.mode.value = link.mode || 'reverse';
        form.portalNodeId.value = link.portalNode?._id || link.portalNode || '';
        form.bridgeNodeId.value = link.bridgeNode?._id || link.bridgeNode || '';
        form.tunnelPort.value = link.tunnelPort || 10086;
        form.tunnelProtocol.value = link.tunnelProtocol || 'vless';
        form.tunnelTransport.value = link.tunnelTransport === 'splithttp' ? 'xhttp' : (link.tunnelTransport || 'tcp');
        form.tunnelSecurity.value = link.tunnelSecurity || 'none';
        form.tunnelDomain.value = link.tunnelDomain || 'reverse.tunnel.internal';
        form.muxEnabled.checked = !!link.muxEnabled;
        form.muxConcurrency.value = link.muxConcurrency || 8;
        form.priority.value = link.priority || 100;
        // The saved preference is metadata, not consent to deploy on this edit.
        form.autoDeploy.checked = false;
        updateLinkSubmitIntent();

        form.realityDest.value = link.realityDest || '';
        form.realitySni.value = Array.isArray(link.realitySni) ? link.realitySni.join(', ') : (link.realitySni || '');
        form.realityPrivateKey.value = link.realityPrivateKey || '';
        form.realityPublicKey.value = link.realityPublicKey || '';
        form.realityShortIds.value = Array.isArray(link.realityShortIds) ? link.realityShortIds.join(', ') : (link.realityShortIds || '');
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
        updateLinkFormWarnings();
    }

    function closeModal() {
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
    }

    function handleLinkAutoDeploy(snapshot, optedIn) {
        if (!optedIn) return;
        const operation = snapshot?.autoDeployOperation;
        if (operation?.status === 'queued' && operation.operationId) {
            startOperationPolling(operation);
            showToast(deployResultMessage(operation));
            return;
        }
        // Saving a draft is not evidence of physical deployment. In
        // particular, never fall back to an unscoped full-topology deploy.
        const error = snapshot?.autoDeployError
            || { code: snapshot?.autoDeployCauseCode || snapshot?.autoDeployStatus };
        showToast((i18n.savedAutoDeployBlocked || 'Изменения сохранены, но автодеплой не запущен') + ': '
            + describeTopologyError({ error }, 'Автодеплой не поставлен в очередь')
            + '. Для применения используйте отдельный Deploy этой связи.', 'error');
    }

    async function onAddLinkSubmit(e) {
        e.preventDefault();
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
            priority:       parseInt(form.priority?.value) || 100,
        };

        // Tunnel domain (reverse only)
        if (form.tunnelDomain?.value) {
            data.tunnelDomain = form.tunnelDomain.value;
        }

        // REALITY fields
        if (data.tunnelSecurity === 'reality') {
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
            const res = await fetch(linkId ? ('/api/cascade/links/' + linkId) : '/api/cascade/links', {
                method: linkId ? 'PUT' : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });
            const savedSnapshot = await handleDraftMutationResponse(res);
            if (!savedSnapshot) return;
            closeModal();
            await loadTopology();
            handleLinkAutoDeploy(savedSnapshot, data.autoDeploy === true);
        } catch (err) {
            showToast((i18n.networkError || 'Error') + ': ' + err.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = (linkId ? '' : '<i class="ti ti-plus"></i> ') + (linkId
                ? (data.autoDeploy === true ? (i18n.saveAndDeploy || 'Save & Deploy') : (i18n.save || 'Save'))
                : (i18n.createLink || 'Create'));
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

    async function deployTopology(linkId, domainLinkId) {
        const payload = { expectedTopologyRevision: topologyRevision };
        if (linkId) payload.linkId = linkId;
        if (domainLinkId) payload.domainLinkId = domainLinkId;
        const res = await fetch('/api/cascade/topology/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
            body: JSON.stringify(payload),
        });
        const data = await res.json().catch(() => ({}));
        if (res.status === 409) {
            await loadTopology();
        }
        if (!res.ok) {
            throw new Error(describeTopologyError(data, 'HTTP ' + res.status));
        }
        if (!['queued', 'succeeded'].includes(data.status)) {
            throw new Error((i18n.deploymentEndedWithStatus || 'Deployment ended with status') + ': ' + (data.status || 'unknown'));
        }
        if (data.status === 'queued') startOperationPolling(data);
        return data;
    }

    // ==================== OPERATION-SPECIFIC POLLING ====================

    let operationPollTimer = null;
    let operationPollGeneration = 0;
    function stopOperationPolling() {
        operationPollGeneration += 1;
        if (operationPollTimer) {
            clearTimeout(operationPollTimer);
            operationPollTimer = null;
        }
    }

    function startOperationPolling(result) {
        stopOperationPolling();
        if (!result || result.status !== 'queued') return;
        if (!/^[a-f0-9]{24}$/i.test(result.operationId || '')) return;
        scheduleOperationPollStep({ operationId: result.operationId, kind: result.kind || null }, 0, operationPollGeneration);
    }

    function scheduleOperationPollStep(state, attempt, generation) {
        operationPollTimer = setTimeout(function () {
            operationPollTimer = null;
            runOperationPollStep(state, attempt, generation);
        }, OPERATION_POLL_INTERVAL_MS);
    }

    async function runOperationPollStep(state, attempt, generation) {
        let operation = null;
        try {
            const res = await fetch('/api/cascade/topology/operations/' + encodeURIComponent(state.operationId));
            if (res.ok) {
                const payload = await res.json();
                if (payload?.operationId === state.operationId) operation = payload;
                const linksResponse = await fetch('/api/cascade/links');
                if (linksResponse.ok) {
                    applyLinkSnapshot(await linksResponse.json());
                    refreshStatuses();
                }
            }
        } catch (_) {
            // Transient failure: stay within the attempt budget and retry.
        }
        if (generation !== operationPollGeneration) return;
        const status = operation?.status || null;
        if (shouldContinueOperationPolling({
            attempt,
            maxAttempts: OPERATION_POLL_MAX_ATTEMPTS,
            status,
            clientReadiness: operation?.clientReadiness,
            clientProofState: operation?.clientProofState,
        })) {
            scheduleOperationPollStep(state, attempt + 1, generation);
            return;
        }
        await loadTopology();
        if (generation !== operationPollGeneration) return;
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
        if (!confirm(i18n.confirmDeploy || 'Deploy this cascade link?')) return;
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
        if (!confirm(i18n.confirmUndeploy || 'Undeploy this cascade link?')) return;
        setActionLoading(i18n.undeploying || 'Undeploying...');

        const edge = cy.edges().filter(e => e.data('linkId') === linkId);
        if (edge.length) edge.data('status', 'syncing');

        try {
            await fetch('/api/cascade/links/' + linkId + '/undeploy', { method: 'POST' });
            showToast(i18n.undeploySuccess || 'Undeployed');
            loadTopology();
            closeInfoModal();
        } catch (err) {
            showToast((i18n.networkError || 'Error') + ': ' + err.message, 'error');
        } finally { resetActionLoading(); }
    };

    window._cascadeDelete = async function (linkId) {
        if (!confirm(i18n.confirmDeleteLink || 'Delete this cascade link?')) return;
        setActionLoading(i18n.deleting || 'Deleting...');

        try {
            const response = await fetch('/api/cascade/links/' + linkId, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ expectedTopologyRevision: topologyRevision }),
            });
            if (!await handleDraftMutationResponse(response)) return;
            showToast(i18n.deleteSuccess || 'Deleted');
            loadTopology();
            closeInfoModal();
        } catch (err) {
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
                updateLinkFormWarnings();
            });
        });
    }

    function updateLinkFormWarnings() {
        var form = document.getElementById('addLinkForm');
        if (!form) return;
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

        // Port conflict check using cached links
        var portConflict = document.getElementById('portConflictHint');
        if (!portConflict) return;
        portConflict.style.display = 'none';
        portConflict.textContent = '';

        var portalId = (form.portalNodeId || {}).value || '';
        var bridgeId = (form.bridgeNodeId || {}).value || '';
        var tunnelPort = parseInt((form.tunnelPort || {}).value, 10) || 10086;
        var linkId = (document.getElementById('linkIdInput') || {}).value || '';
        var checkNodeId = isForward ? bridgeId : portalId;
        var checkField = isForward ? 'bridgeNode' : 'portalNode';

        if (!checkNodeId || !_allLinks.length) return;

        var conflict = _allLinks.find(function (l) {
            if (!l || !l.active) return false;
            if (linkId && String(l._id) === linkId) return false;
            var nodeRef = l[checkField];
            var nid = nodeRef && typeof nodeRef === 'object' ? (nodeRef._id || '') : (nodeRef || '');
            return String(nid) === checkNodeId && Number(l.tunnelPort) === tunnelPort;
        });

        if (conflict) {
            portConflict.style.display = '';
            portConflict.textContent =
                (i18n.portConflictClientHint || 'This tunnel port is already used by another active link on the listening side.') +
                ' (' + (conflict.name || 'link') + ')';
        }
    }

    // ==================== QUICK LINK MODAL ====================

    function closeQuickModal() {
        var modal = document.getElementById('quickLinkModal');
        if (modal) modal.classList.remove('active');
    }

    function onQuickSwap() {
        var pId = document.getElementById('quickPortalId');
        var bId = document.getElementById('quickBridgeId');
        var pName = document.getElementById('quickPortalName');
        var bName = document.getElementById('quickBridgeName');
        if (!pId || !bId) return;
        var tmpId = pId.value; pId.value = bId.value; bId.value = tmpId;
        var tmpName = pName.textContent; pName.textContent = bName.textContent; bName.textContent = tmpName;
    }

    async function onQuickLinkSubmit(e) {
        e.preventDefault();
        var data = {
            name: document.getElementById('quickLinkName').value,
            mode: document.getElementById('quickLinkMode').value || 'reverse',
            portalNodeId: document.getElementById('quickPortalId').value,
            bridgeNodeId: document.getElementById('quickBridgeId').value,
            tunnelPort: parseInt(document.getElementById('quickTunnelPort').value) || 10086,
            tunnelProtocol: document.getElementById('quickTunnelProtocol').value,
            autoDeploy: document.getElementById('quickAutoDeploy')?.checked || false,
        };
        if (!data.name || !data.portalNodeId || !data.bridgeNodeId) {
            alert(i18n.fillRequired || 'Please fill in all required fields');
            return;
        }
        data.expectedTopologyRevision = topologyRevision;
        var btn = document.getElementById('quickLinkSubmit');
        if (btn) { btn.disabled = true; btn.innerHTML = '<i class="ti ti-loader-2 spin"></i>'; }
        try {
            var res = await fetch('/api/cascade/links', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });
            const createdSnapshot = await handleDraftMutationResponse(res);
            if (!createdSnapshot) return;
            closeQuickModal();
            await loadTopology();
            handleLinkAutoDeploy(createdSnapshot, data.autoDeploy === true);
        } catch (err) {
            showToast((i18n.networkError || 'Error') + ': ' + err.message, 'error');
        } finally {
            if (btn) { btn.disabled = false; btn.innerHTML = '<i class="ti ti-plus"></i> ' + (i18n.createLink || 'Create'); }
        }
    }

    // ==================== START ====================

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
