'use strict';

const { X509Certificate } = require('node:crypto');
const { isIP } = require('node:net');
const fail = code => Object.assign(new Error(code), { code });
const CERT_PATH = '/usr/local/etc/xray/cert.pem';
const nameOK = name => typeof name === 'string' && name.length <= 253 &&
    (isIP(name) || name.split('.').every(s => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(s)));

function tunnelName(link) {
    const name = link.rebuildTlsServerName ?? link.tlsServerName;
    if (!nameOK(name)) throw fail('REBUILD_TLS_SERVER_NAME_REQUIRED');
    return name;
}

// These commands handle public certificates only. Never copy a key to the dialer,
// use the listener's CA store, or promote a presented certificate to a trust root.
const READ_CHAIN = `/bin/bash -c 'set -euo pipefail; test -f ${CERT_PATH}; test "$(wc -c < ${CERT_PATH})" -le 131072; ` +
    `openssl crl2pkcs7 -nocrl -certfile ${CERT_PATH} | openssl pkcs7 -print_certs'`;
const VERIFY_CHAIN = `/bin/bash -c 'set -eu; IFS= read -r kind; IFS= read -r name; ` +
    `case "$kind" in DNS) flag=-verify_hostname;; IP) flag=-verify_ip;; *) exit 1;; esac; ` +
    `pem=$(cat); unset SSL_CERT_DIR SSL_CERT_FILE; ` +
    `printf "%s\\n" "$pem" | openssl verify -purpose sslserver "$flag" "$name" ` +
    `-untrusted <(printf "%s\\n" "$pem") >/dev/null 2>&1'`;

function checkedChain(raw, name) {
    if (typeof raw !== 'string' || raw.length > 196608) throw fail('REBUILD_TLS_CERT_UNREADABLE');
    const blocks = raw.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/g);
    let certs;
    try {
        if (!blocks?.length || blocks.length > 16) throw Error();
        certs = blocks.map(pem => new X509Certificate(pem));
    } catch { throw fail('REBUILD_TLS_CERT_UNREADABLE'); }
    // Go/Xray does not fall back to the legacy Common Name. OpenSSL by itself can.
    const match = isIP(name) ? certs[0].checkIP(name) : certs[0].checkHost(name,
        { subject: 'never', partialWildcards: false, multiLabelWildcards: false });
    if (!match) throw fail('REBUILD_TLS_NAME_MISMATCH');
    return certs.map(c => c.toString().trim()).join('\n') + '\n';
}

// Called by the service on every Preview AND on the fresh Apply build, before
// key persistence, tombstones or staging. Source is the actual certificate file
// used by the candidate, not node.tlsSource, a DB trust flag or a live peer pin.
async function verifyTunnelTrust(links, panelTls, transports) {
    const files = new Map();
    for (const link of links) {
        if (link.tunnelSecurity !== 'tls') continue;
        const name = tunnelName(link);
        const forward = link.mode === 'forward';
        const listener = String(forward ? link.bridgeNode : link.portalNode);
        const dialer = String(forward ? link.portalNode : link.bridgeNode);
        let raw;
        if (name === panelTls.serverName?.trim()) {
            raw = panelTls.certificate?.join('\n');
        } else {
            if (!files.has(listener)) {
                try { files.set(listener, await transports.get(listener).readTunnelCertificate()); }
                catch { throw fail('REBUILD_TLS_CERT_UNREADABLE'); }
            }
            raw = files.get(listener);
        }
        const pem = checkedChain(raw, name);
        try { await transports.get(dialer).verifyTunnelCertificate(`${isIP(name) ? 'IP' : 'DNS'}\n${name}\n${pem}`); }
        catch { throw fail('REBUILD_TLS_TRUST_UNVERIFIED'); }
    }
}

module.exports = { tunnelName, verifyTunnelTrust, READ_CHAIN, VERIFY_CHAIN };
