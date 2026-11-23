'use strict';

const prefix = 'DIRECT_PROGRESS ';
const names = { 'prepare-packages': ['unpacking', 'settingUp'], install: ['restart'] };
function progressWire(action, notify) {
    const allowed = names[action];
    if (!allowed || typeof notify !== 'function') return undefined;
    const decode = text => {
        const mark = text.startsWith(prefix) ? text.slice(prefix.length) : '';
        return allowed.indexOf(mark);
    };
    let pending = '', seen = -1, disabled = false;
    return {
        // Passive: the pinned transport still counts/collects original bytes.
        tap(chunk) {
            if (disabled) return;
            pending += chunk.toString();
            if (pending.length > 256) { pending = ''; disabled = true; return; }
            let end;
            while ((end = pending.indexOf('\n')) !== -1) {
                const index = decode(pending.slice(0, end));
                pending = pending.slice(end + 1);
                if (index < 0 || index <= seen) { disabled = true; return; }
                seen = index;
                try { notify(allowed[index]); } catch { /* advisory */ }
            }
        },
        strip(text) {
            // Strip only closed, action-scoped, ordered frames. The original
            // settlement decoder still rejects any other stderr contamination.
            let prev = -1;
            while (typeof text === 'string' && text.startsWith(prefix)) {
                const end = text.indexOf('\n');
                if (end < 0) break;
                const index = decode(text.slice(0, end));
                if (index < 0 || index <= prev) break;
                prev = index;
                text = text.slice(end + 1);
            }
            return text;
        },
    };
}
module.exports = { progressWire };
