/**
 * Extract the bare client IP from a Hysteria `addr` field (`IP:port`).
 *
 * Shared by the auth route (device-limit grouping) and the auth rate limiter
 * (per-client bucketing). Returns the full IP so IPv6 keys stay collision-free;
 * returns '' when the input is missing/unparseable so callers can fall back.
 *
 * Hysteria always sends `IP:port` (IPv6 bracketed), so these are the real cases:
 *   - IPv4 with port:        203.0.113.10:443        -> 203.0.113.10
 *   - IPv6 with brackets:    [2001:db8::1]:55239     -> 2001:db8::1
 *   - IPv4 without port:     203.0.113.10            -> 203.0.113.10
 *
 * A bare (port-less, bracket-less) IPv6 is not a real input and is NOT parsed
 * correctly (its last group is mistaken for a port); acceptable since it never
 * occurs and the result is still a stable per-client key.
 */
function extractClientIp(addr) {
    if (!addr) return '';

    // IPv6 with brackets: [2001:db8::1]:55239
    if (addr.startsWith('[')) {
        const endBracket = addr.indexOf(']');
        if (endBracket > 0) {
            return addr.substring(1, endBracket);
        }
    }

    // Strip a trailing :port only when the suffix is purely numeric. This keeps
    // bare IPv4 untouched; bare bracket-less IPv6 is not a real Hysteria input.
    const lastColon = addr.lastIndexOf(':');
    if (lastColon > 0) {
        const afterColon = addr.substring(lastColon + 1);
        if (/^\d+$/.test(afterColon)) {
            return addr.substring(0, lastColon);
        }
    }

    return addr;
}

module.exports = { extractClientIp };
