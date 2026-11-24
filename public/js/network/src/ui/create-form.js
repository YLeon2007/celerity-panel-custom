import { isObjectId } from '../core/api.js';
import { DEFAULT_PORT, TRANSPORTS, KCP_HEADERS, KCP_NUMBERS, allowsReality, allowsVmess, inRange,
    tlsNameOK, editValues, editPatch, InvalidEditFields } from '../core/edit-fields.js';
import { t } from '../core/i18n.js';
import { h, icon } from './dom.js';
import { nodeTitle, roleName } from './format.js';

const FROM_ROLES = ['portal', 'relay'];
const TO_ROLES = ['relay', 'bridge'];
const label = (key, vars) => t(`map.create.${key}`, vars);
const editLabel = key => t(`map.edit.${key}`);

// Shared with the legacy link modal. Rebuild uses its own server-side port
// admission (including UDP reservations); the map cannot infer a free port.
export function usedPorts(index, nodeId) {
    const ports = new Set();
    for (const l of index.links.values()) {
        if (l.source === nodeId || l.target === nodeId) ports.add(Number(l.tunnelPort));
    }
    return ports;
}

export function suggestPort(index, nodeId) {
    const used = usedPorts(index, nodeId);
    let port = DEFAULT_PORT;
    while (used.has(port) && port < 65535) port++;
    return port;
}

function eligible(node, roles) {
    // getTopology already queries active:true; the node projection has no
    // active flag. status is runtime health, not configured activity.
    return node?.type === 'xray' && node.active !== false && isObjectId(node.id) && roles.includes(node.cascadeRole);
}

const option = (value, text) => h('option', { value }, text);
const select = (name, options) => h('select.nm-input', { name, required: true }, options);
const field = (key, control, hint) => h('div.nm-field', null,
    h('label', null, h('span', null, label(key)), control), hint);

function numberInput(name, min, max, value) {
    return h('input.nm-input.mono', { name, type: 'number', min, max, value, step: 1, required: true, inputmode: 'numeric' });
}

/** Edit uses the validated projection from actions.loadEdit. The owner disposes on unmount. */
export function renderCreateForm(container, { store, actions, source, target, edit, onCancel, onCreated, onUncertain }) {
    const editing = edit != null;
    const edgeId = editing ? `link-${edit._id}` : null;
    const formLabel = editing ? editLabel : label;
    let pending = false;
    let finished = false;
    let closed = false;
    let nameTouched = false;
    const controller = new AbortController();
    const eventOptions = { signal: controller.signal };

    // In edit mode these controls have no endpoint names or values to submit.
    const endpoint = (fieldName) => editing
        ? h('input.nm-input', { type: 'text', readonly: true, 'aria-describedby': 'nm-edit-endpoints-hint' })
        : select(fieldName);
    const from = endpoint('portalNodeId');
    const to = endpoint('bridgeNodeId');
    const mode = h('input', { name: 'mode', type: 'hidden', value: 'reverse' });
    const modeButtons = ['forward', 'reverse'].map(value => h('button', {
        type: 'button', 'data-mode': value,
    }, icon(value === 'forward' ? 'arrow-right' : 'arrows-exchange'), label(value)));
    const modeHint = h('div.hint', { role: 'status' });
    const portHint = h('div.hint');
    const availability = h('div.nm-alert.muted', { hidden: true }, label('noPair'));
    const status = h('div.nm-alert.warn', { role: 'alert', hidden: true });

    const name = h('input.nm-input', { name: 'name', type: 'text', maxlength: 100, required: true, autocomplete: 'off' });
    const port = numberInput('tunnelPort', 1, 65535, DEFAULT_PORT);
    const vmess = option('vmess', 'VMess');
    const protocol = select('tunnelProtocol', [option('vless', 'VLESS'), vmess]);
    const transport = select('tunnelTransport', TRANSPORTS.map(([value, text]) => option(value, text)));
    const reality = option('reality', 'REALITY');
    const security = select('tunnelSecurity', [reality, option('tls', 'TLS'), option('none', label('securityNone'))]);
    const wsHint = h('div.hint', { hidden: true }, label('wsHint'));
    const tls = h('input.nm-input', { name: 'tlsServerName', type: 'text', maxlength: 253, required: true,
        autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' });
    const tlsField = field('tlsServerName', tls, h('div.hint', null, label('tlsHint')));
    const kcpInputs = Object.fromEntries(Object.entries(KCP_NUMBERS).map(([key, args]) => [key, numberInput(key, ...args)]));
    const headerNames = [label('kcpHeaderNone'), label('kcpHeaderWechat'), 'DTLS 1.2', 'SRTP', 'WireGuard'];
    const header = select('kcpHeader', KCP_HEADERS.map((value, i) => option(value, headerNames[i])));
    const kcpFields = h('fieldset', { hidden: true, disabled: true },
        h('legend', null, 'mKCP (UDP)'), h('div.hint', null, label('kcpHint')),
        field('kcpHeader', header),
        Object.entries(kcpInputs).map(([key, input]) => field(key, input)));
    const advanced = h('details.nm-adv', { open: editing },
        h('summary', null, label('more')),
        field('name', name), field('port', port, portHint), field('protocol', protocol),
        field('transport', transport), field('security', security, wsHint), tlsField, kcpFields);
    const fields = h('fieldset.nm-insp-body', { style: { border: '0', margin: '0', minWidth: '0' } },
        field('from', from), field('to', to), editing
            ? h('div.hint', { id: 'nm-edit-endpoints-hint' }, editLabel('endpointsHint')) : availability,
        h('div.nm-field', null, h('div', null, label('how')),
            h('div.nm-seg', { role: 'group', 'aria-label': label('how') }, modeButtons), mode, modeHint),
        advanced, status);
    const submit = h('button.nm-btn.primary.block', { type: 'submit' });
    const close = h('button.nm-btn.ghost.icon.sm', { type: 'button', 'aria-label': t('map.close') }, icon('x'));
    const cancel = h('button.nm-btn.ghost', { type: 'button' }, label('cancel'));
    const form = h('form', { [editing ? 'data-nm-edit' : 'data-nm-create']: '', novalidate: editing,
        style: { display: 'flex', flexDirection: 'column', flex: '1', minHeight: '0' } },
        h('div.nm-insp-head', null, h('div.nm-avatar.edge', null, icon(editing ? 'edit' : 'link-plus')),
            h('div.nm-insp-title', null, h('h3', null, formLabel('title')), h('div.sub', null, formLabel('sub'))), close),
        fields, h('div.nm-insp-foot', null, submit, cancel));
    container.append(form);

    let optionKey;
    let canChoose = false;
    const attached = () => !closed && form.parentNode === container && form.isConnected;
    const nodeLabel = node => node?.label || node?.ip || '';

    function syncEndpoints(sourceId = from.value, targetId = to.value) {
        if (editing) {
            const displayEndpoint = id => {
                const node = store.index.nodes.get(id);
                return node ? `${nodeTitle(node)} — ${roleName(node.cascadeRole)}` : id;
            };
            from.value = displayEndpoint(edit.portalNode);
            to.value = displayEndpoint(edit.bridgeNode);
            canChoose = isObjectId(edit._id) && store.index.links.get(edgeId)?.canEdit === true;
            updateDirection();
            updateControls();
            return;
        }
        const nodes = [...store.index.nodes.values()].sort((a, b) => nodeLabel(a).localeCompare(nodeLabel(b)) || a.id.localeCompare(b.id));
        const sources = nodes.filter(node => eligible(node, FROM_ROLES));
        const targets = nodes.filter(node => eligible(node, TO_ROLES));
        const sourceValue = sources.some(node => node.id === sourceId) ? sourceId : '';
        const choices = targets.filter(node => node.id !== sourceValue);
        const targetValue = choices.some(node => node.id === targetId) ? targetId : '';
        const rows = list => list.map(node => [node.id, `${nodeTitle(node)} — ${roleName(node.cascadeRole)}`]);
        const lists = [rows(sources), rows(choices)];
        const key = JSON.stringify(lists);
        if (key !== optionKey) {
            optionKey = key;
            from.replaceChildren(option('', label('chooseFrom')), ...lists[0].map(args => option(...args)));
            to.replaceChildren(option('', label('chooseTo')), ...lists[1].map(args => option(...args)));
        }
        from.value = sourceValue;
        to.value = targetValue;
        canChoose = sources.some(node => targets.length > 1 || (targets[0] && targets[0].id !== node.id));
        availability.hidden = canChoose;
        if (!nameTouched) name.value = sourceValue && targetValue
            ? `${nodeLabel(store.index.nodes.get(sourceValue))} → ${nodeLabel(store.index.nodes.get(targetValue))}`.slice(0, 100) : '';
        updateDirection();
        updateControls();
    }

    function updateDirection() {
        const forward = mode.value === 'forward';
        modeButtons.forEach(button => {
            const active = button.dataset.mode === mode.value;
            button.classList.toggle('active', active);
            button.setAttribute('aria-pressed', String(active));
        });
        const a = nodeTitle(store.index.nodes.get(editing ? edit.portalNode : from.value)) || label('from');
        const b = nodeTitle(store.index.nodes.get(editing ? edit.bridgeNode : to.value)) || label('to');
        const direction = t(forward ? 'map.modeForwardDesc' : 'map.modeReverseDesc', { a, b });
        portHint.textContent = t('map.listensOn', { name: forward ? b : a });
        modeHint.textContent = `${direction}. ${portHint.textContent}. ${label('trafficDirection')}`;
    }

    function updateTransport() {
        reality.disabled = !allowsReality(transport.value);
        if (!editing && reality.disabled && security.value === 'reality') security.value = 'none';
        vmess.disabled = !allowsVmess(mode.value, security.value);
        if (!editing && vmess.disabled && protocol.value === 'vmess') protocol.value = 'vless';
        wsHint.hidden = transport.value !== 'ws';
        tlsField.hidden = tls.disabled = security.value !== 'tls';
        kcpFields.hidden = kcpFields.disabled = transport.value !== 'kcp';
    }

    function updateControls() {
        fields.disabled = pending || finished;
        submit.disabled = pending || finished || !canChoose;
        close.disabled = cancel.disabled = pending;
        submit.replaceChildren(icon(pending ? 'loader-2' : 'arrow-right', pending ? 'nm-spin' : ''),
            formLabel(pending ? (editing ? 'saving' : 'creating') : 'submit'));
    }

    function showStatus(key) {
        const localize = editing && (key === 'noChanges' || key === 'unknown') ? editLabel : label;
        status.textContent = key ? localize(key) : '';
        status.hidden = !key;
    }

    const editControls = { name, mode, tunnelPort: port, tunnelProtocol: protocol, tunnelTransport: transport,
        tunnelSecurity: security, tlsServerName: tls, kcpHeader: header, ...kcpInputs };

    function collectEdit() {
        const values = {};
        for (const [key, control] of Object.entries(editControls)) {
            if (control === tls && tls.disabled) continue;
            if ((control === header || Object.hasOwn(kcpInputs, key)) && kcpFields.disabled) continue;
            values[key] = control.type === 'number' ? control.valueAsNumber : control.value;
        }
        try { return editPatch(edit, values); } catch (err) {
            advanced.open = true;
            showStatus(err instanceof InvalidEditFields ? err.key : 'badSettings');
            if (err.key === 'badTlsName') tls.focus();
        }
    }

    function collect() {
        const body = {
            name: name.value.trim(), mode: mode.value, portalNodeId: from.value, bridgeNodeId: to.value,
            tunnelPort: port.valueAsNumber, tunnelProtocol: protocol.value,
            tunnelTransport: transport.value, tunnelSecurity: security.value,
        };
        const { portalNodeId, bridgeNodeId, tunnelTransport, tunnelSecurity, tunnelProtocol } = body;
        if (portalNodeId === bridgeNodeId || !eligible(store.index.nodes.get(portalNodeId), FROM_ROLES)
            || !eligible(store.index.nodes.get(bridgeNodeId), TO_ROLES)) return showStatus('badPair');
        if (!['reverse', 'forward'].includes(body.mode)) return showStatus('badSettings');
        if (!body.name || body.name.length > 100 || !inRange(body.tunnelPort, 1, 65535)
            || !TRANSPORTS.some(([value]) => value === tunnelTransport)
            || !['none', 'tls', 'reality'].includes(tunnelSecurity)
            || (tunnelSecurity === 'reality' && !allowsReality(tunnelTransport))
            || (tunnelProtocol !== 'vless' && !(tunnelProtocol === 'vmess' && allowsVmess(body.mode, tunnelSecurity)))) {
            advanced.open = true;
            return showStatus('badSettings');
        }
        if (tunnelSecurity === 'tls') {
            body.tlsServerName = tls.value.trim();
            if (!tlsNameOK(body.tlsServerName)) {
                advanced.open = true;
                tls.focus();
                return showStatus('badTlsName');
            }
        }
        if (tunnelTransport === 'kcp') {
            body.kcpHeader = header.value;
            if (!KCP_HEADERS.includes(body.kcpHeader)) return showStatus('badKcp');
            for (const [key, [min, max]] of Object.entries(KCP_NUMBERS)) {
                const value = kcpInputs[key].valueAsNumber;
                if (!inRange(value, min, max)) return showStatus('badKcp');
                body[key] = value;
            }
        }
        return body;
    }

    async function onSubmit(event) {
        event.preventDefault();
        if (!attached() || pending || finished) return;
        const body = editing ? collectEdit() : collect();
        if (!body) return;
        showStatus();
        pending = true;
        updateControls();
        let result;
        try {
            result = editing ? await actions.editAndDeploy(edgeId, body) : await actions.createAndDeploy(body);
        } catch (_) {
            // A thrown workflow/readback error does not prove the save failed.
        }
        if (!attached()) return;
        const outcome = result?.status ?? result?.outcome;
        pending = false;
        if (outcome === 'busy' || outcome === 'not_saved' || outcome === 'unchanged') {
            syncEndpoints();
            showStatus(outcome === 'busy' ? 'busy' : outcome === 'unchanged' ? 'noChanges' : 'notSaved');
            return;
        }
        finished = true; // Set before callbacks; never resubmit from this form.
        updateControls();
        if ((outcome === 'saved' || outcome === 'applied') && isObjectId(result.linkId)
            && (!editing || result.linkId === edit._id)) {
            showStatus(outcome === 'saved' ? 'saved' : 'applied');
            onCreated?.(result.linkId);
        } else {
            showStatus('unknown');
            onUncertain?.();
        }
    }

    const offData = store.on('data', () => {
        if (attached() && !pending && !finished) syncEndpoints();
    });
    function dispose() {
        if (closed) return;
        closed = true;
        offData();
        controller.abort();
        form.remove();
    }
    function cancelForm() {
        if (!attached() || pending) return;
        dispose();
        onCancel?.();
    }
    close.addEventListener('click', cancelForm, eventOptions);
    cancel.addEventListener('click', cancelForm, eventOptions);
    for (const button of modeButtons) button.addEventListener('click', () => {
        if (!attached() || pending || finished) return;
        mode.value = button.dataset.mode;
        updateDirection();
        updateTransport();
        showStatus();
    }, eventOptions);
    form.addEventListener('input', event => {
        if (pending || finished) return;
        if (event.target === name) nameTouched = true;
        showStatus();
    }, eventOptions);
    form.addEventListener('change', event => {
        if (pending || finished) return;
        if (event.target === name) nameTouched = true;
        if (event.target === from || event.target === to) syncEndpoints();
        if (event.target === transport || event.target === security) updateTransport();
        showStatus();
    }, eventOptions);
    form.addEventListener('invalid', event => {
        if (advanced.contains(event.target)) advanced.open = true;
    }, { ...eventOptions, capture: true });
    form.addEventListener('submit', onSubmit, eventOptions);
    if (editing) {
        for (const [key, value] of Object.entries(editValues(edit))) editControls[key].value = value;
    }
    syncEndpoints(source, target);
    updateTransport();
    return dispose;
}
