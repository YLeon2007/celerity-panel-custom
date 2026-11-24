/** The read-only map has no Classic API client or mutation capability. */
const TIMEOUT_MS = 20000;

export async function fetchTopology() {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    try {
        const res = await fetch('/api/cascade/topology', {
            method: 'GET',
            credentials: 'same-origin',
            redirect: 'error',
            headers: { Accept: 'application/json' },
            signal: ctrl.signal,
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (!Array.isArray(data?.nodes) || !Array.isArray(data?.edges)) {
            throw new Error('Invalid topology response');
        }
        return data;
    } finally {
        clearTimeout(timer);
    }
}

// Source-compatible imports for the inactive upstream form/actions modules.
// There is intentionally no mutation method in this release's client.
export function isObjectId(id) {
    return typeof id === 'string' && /^[0-9a-f]{24}$/i.test(id);
}

export function linkIdOf(edgeId) {
    const id = typeof edgeId === 'string' && edgeId.startsWith('link-') ? edgeId.slice(5) : '';
    return isObjectId(id) ? id : null;
}

export const api = Object.freeze({ topology: fetchTopology });
