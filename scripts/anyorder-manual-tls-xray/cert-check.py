#!/usr/bin/env python3
"""Real private-trust TLS/hostname proof and rejecting controls."""
import hashlib
import json
import socket
import ssl
import sys

port = int(sys.argv[1])
name = 'manual-tls-test-only.invalid'

def connect(context, hostname):
    context.set_alpn_protocols(['http/1.1', 'h2'])
    with socket.create_connection(('127.0.0.1', port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as secured:
            return {'version': secured.version(), 'alpn': secured.selected_alpn_protocol(),
                    'peerCertificateSha256': hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest(),
                    'subjectAltName': secured.getpeercert()['subjectAltName']}

ctx = ssl.create_default_context(cafile='/root/manual-trust.crt')
assert ctx.check_hostname and ctx.verify_mode == ssl.CERT_REQUIRED
result = connect(ctx, name)
assert ('DNS', name) in result['subjectAltName']
assert result['alpn'] in ['http/1.1', 'h2']
expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(open('/root/manual-trust.crt').read())).hexdigest()
assert result['peerCertificateSha256'] == expected
controls = {}
for label, context, hostname in [('wrong-name', ctx, 'wrong-name.invalid'),
                                 ('untrusted', ssl.create_default_context(), name)]:
    try:
        connect(context, hostname)
    except ssl.SSLCertVerificationError as error:
        controls[label] = {'rejected': True, 'verifyCode': error.verify_code}
    else:
        raise AssertionError(label + ' unexpectedly accepted')
print(json.dumps({'status': 'passed', 'hostname': name, 'privateTrust': True,
                  'hostnameCheck': True, 'certificateRequired': True, **result, 'controls': controls}))
