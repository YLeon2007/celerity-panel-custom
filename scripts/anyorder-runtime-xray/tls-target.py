#!/usr/bin/env python3
"""Bounded private REALITY handshake destination, never a public endpoint."""
import concurrent.futures
import socket
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
ctx.set_ecdh_curve('X25519')
ctx.set_alpn_protocols(['h2', 'http/1.1'])
ctx.load_cert_chain('/root/anyorder-tls.crt', '/root/anyorder-tls.key')


def serve(connection):
    connection.settimeout(5)
    try:
        with ctx.wrap_socket(connection, server_side=True) as secured:
            secured.recv(4096)
    except (OSError, ssl.SSLError):
        connection.close()


# More than one simultaneous handshake: REALITY also probes its destination.
# The fixture has no published ports or external peers; workers are capped.
with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 18443))
    listener.listen(16)
    while True:
        connection, _ = listener.accept()
        workers.submit(serve, connection)
