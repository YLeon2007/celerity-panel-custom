#!/usr/bin/env python3
"""Private REALITY handshake destination, not a public TLS endpoint."""
import socket
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
ctx.set_alpn_protocols(['h2', 'http/1.1'])
ctx.load_cert_chain('/root/anyorder-tls.crt', '/root/anyorder-tls.key')
with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 18443))
    listener.listen(16)
    while True:
        connection, _ = listener.accept()
        connection.settimeout(3)
        try:
            with ctx.wrap_socket(connection, server_side=True) as secured:
                secured.recv(4096)
        except (OSError, ssl.SSLError):
            connection.close()
