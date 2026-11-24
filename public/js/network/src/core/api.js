/** Panel transport for the Rebuild map. No Classic API or retry path. */
const TIMEOUT_MS = 20000;
const CASCADE = '/api/cascade';

export async function fetchTopology() {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    try {
        const res = await fetch('/api/cascade/topology', {
            method: 'GET',
            credentials: 'same-origin',
            redirect: 'error',
            cache: 'no-store',
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

export function isObjectId(id) {
    return typeof id === 'string' && /^[0-9a-f]{24}(?![\s\S])/i.test(id);
}

export function linkIdOf(edgeId) {
    const id = typeof edgeId === 'string' && edgeId.startsWith('link-') ? edgeId.slice(5) : '';
    return isObjectId(id) ? id : null;
}

export function isPreviewId(value) {
    return typeof value === 'string' && /^(?:[0-9a-f]{64}|[0-9a-f]{128})(?![\s\S])/.test(value);
}

export class SessionChanged extends Error {}

export class RebuildRequestError extends Error {
    constructor(status, body) {
        super(`HTTP ${status}`);
        this.status = status;
        this.body = body;
    }

    get csrfRejected() {
        return this.status === 403 && this.body?.error === 'CSRF validation failed'
            && Object.keys(this.body).length === 2
            && ['CSRF_TOKEN_INVALID', 'CSRF_AUTH_REQUIRED', 'CSRF_ORIGIN_INVALID'].includes(this.body.code);
    }
}

function linkPath(linkId) {
    if (!isObjectId(linkId)) throw new Error('Invalid cascade link ID');
    return `/links/${linkId}`;
}

// Scope the token to one workflow. Do not reread/rotate it or retry a write.
export function createRebuildClient() {
    const token = window._networkCsrfToken;
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}(?![\s\S])/.test(token)) throw new SessionChanged();
    const assertSession = () => {
        if (window._networkCsrfToken !== token) throw new SessionChanged();
    };

    async function request(path, method, body) {
        const url = new URL(CASCADE + path, window.location.origin);
        const write = method !== 'GET';
        const headers = { Accept: 'application/json' };
        if (write) Object.assign(headers, { 'Content-Type': 'application/json', 'x-csrf-token': token });
        const json = write ? JSON.stringify(body) : undefined;
        assertSession();
        // Rebuild is synchronous server-side and may span several nodes;
        // the topology poll's short timeout is not a mutation deadline.
        const res = await fetch(url.href, {
            method, headers, body: json, mode: 'same-origin', credentials: 'same-origin',
            redirect: 'error', cache: 'no-store',
        });
        if (res.redirected || res.url !== url.href) throw new Error('Unexpected panel response URL');
        if (!/^application\/json(?:\s*;|$)/i.test(res.headers.get('content-type') || '')) {
            throw new RebuildRequestError(res.status);
        }
        const data = await res.json();
        if (!res.ok || res.status !== 200) throw new RebuildRequestError(res.status, data);
        return data;
    }

    function apply(path, method, expectedPreview, fields) {
        if (!isPreviewId(expectedPreview)) throw new Error('Invalid preview ID');
        return request(path, method, { ...fields, expectedPreview });
    }

    return Object.freeze({
        assertSession,
        preview(linkId, removing) {
            if (!isObjectId(linkId)) throw new Error('Invalid cascade link ID');
            return request('/rebuild/preview', 'POST', { linkId, ...(removing === true && { remove: true }) });
        },
        deploy: (id, expectedPreview) => apply(`${linkPath(id)}/deploy`, 'POST', expectedPreview),
        deployChain(id, expectedPreview) {
            if (!isObjectId(id)) throw new Error('Invalid cascade link ID');
            return apply('/chain/deploy', 'POST', expectedPreview, { linkId: id });
        },
        remove: (id, expectedPreview) => apply(linkPath(id), 'DELETE', expectedPreview),
        checkHealth: id => request(`${linkPath(id)}/health`, 'GET'),
        async savePositions(rows) {
            const positions = new Map();
            for (const { id, x, y } of rows) {
                if (id !== 'internet' && !isObjectId(id)) continue;
                if (![x, y].every(v => Number.isFinite(v) && Math.abs(v) <= 1e6)) throw new Error('Invalid coordinates');
                const key = id.toLowerCase();
                positions.set(key, { id: key, x: Math.round(x * 10) / 10, y: Math.round(y * 10) / 10 });
            }
            if (!positions.size || positions.size > 1000) throw new Error('Invalid layout size');
            const data = await request('/topology/positions', 'POST', { positions: Array.from(positions.values()) });
            if (data?.success !== true) throw new Error('Position save not acknowledged');
        },
        saveDraft(body) {
            // The form provides desired settings, not authority to deploy or
            // override the CSRF header. Keep this route strictly save-only.
            const draft = { ...body };
            for (const key of ['autoDeploy', '_csrf', 'expectedPreview', 'toJSON']) delete draft[key];
            return request('/links', 'POST', draft);
        },
    });
}

export const api = Object.freeze({ topology: fetchTopology });
