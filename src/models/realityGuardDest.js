// Shared by the policy model and the node form. The browser has no node:net;
// its syntax-only public check mirrors (and is tested against) service parseDest.
const realityGuardDests = (() => {
    const ipv4 = /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/;
    const hostname = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
    const ipv4Octets = host => ipv4.test(host) && host.split('.').every(n => Number(n) <= 255)
        ? host.split('.').map(Number) : null;

    function local4([a, b, c, d]) {
        return (a === 0 && b === 0 && c === 0 && d === 0) || a === 127 || a === 10
            || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
            || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
    }

    function public4(ip) {
        const [a, b, c] = ip;
        return !local4(ip) && a !== 0 && a < 224
            && !(a === 192 && ((b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99)))
            && !(a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
            && !(a === 203 && b === 0 && c === 113);
    }

    function classifyRealityGuardDest(dest, parsePublic) {
        if (parsePublic?.(dest)) return 'public';
        if (typeof dest !== 'string') return 'unknown';
        if (/^(?:unix:(?:\/|@)|\/|@)[^\0\r\n]+$/.test(dest)) return 'local';
        if (dest.length > 262 || /\s/.test(dest)) return 'unknown';
        const match = /^(?:\[([^\]]+)\]|([^:[\]]+)):(\d{1,5})$/.exec(dest);
        if (!match || Number(match[3]) < 1 || Number(match[3]) > 65535) return 'unknown';
        const host = (match[1] || match[2]).toLowerCase();
        if (!match[1]) {
            const ip = ipv4Octets(host);
            if (ip && local4(ip)) return 'local';
            const unrooted = host.replace(/\.$/, '');
            if (unrooted === 'localhost' || (unrooted.endsWith('.localhost') && hostname.test(unrooted))) return 'local';
            if (!parsePublic && (ip ? public4(ip) : host.length <= 253 && hostname.test(host)
                && !/\.(?:local|localhost|internal|home)$/.test(host))) return 'public';
            return 'unknown';
        }

        const scoped = /^([0-9a-f:.]+)(?:%[a-z0-9_.~-]+)?$/.exec(host);
        if (!scoped) return 'unknown';
        let ip;
        try { ip = new URL(`http://[${scoped[1]}]`).hostname.slice(1, -1); }
        catch { return 'unknown'; }
        const [first, second] = ip.split(':').map(n => parseInt(n || '0', 16));
        if (ip === '::' || ip === '::1' || (first & 0xfe00) === 0xfc00
            || (first & 0xff80) === 0xfe80) return 'local';
        const mapped = /^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(ip);
        if (mapped) {
            const hi = parseInt(mapped[1], 16), lo = parseInt(mapped[2], 16);
            if (local4([hi >> 8, hi & 255, lo >> 8, lo & 255])) return 'local';
        }
        if (!parsePublic && !host.includes('%') && (first & 0xe000) === 0x2000
            && !(first === 0x2001 && (second <= 0x1ff || second === 0xdb8))
            && first !== 0x2002 && !(first === 0x3fff && second <= 0xfff)) return 'public';
        return 'unknown';
    }

    function summarizeRealityGuardDests(values, classify = classifyRealityGuardDest) {
        const classes = values.map(value => classify(value));
        if (!classes.length) return 'none';
        if (classes.every(kind => kind === 'local')) return 'local';
        if (classes.includes('public')) return classes.every(kind => kind === 'public') ? 'public' : 'mixed';
        return 'unknown';
    }
    return { classifyRealityGuardDest, summarizeRealityGuardDests };
})();

if (typeof module === 'object' && module.exports) module.exports = realityGuardDests;
