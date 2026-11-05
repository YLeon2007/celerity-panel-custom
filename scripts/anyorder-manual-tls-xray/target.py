#!/usr/bin/env python3
"""Loopback-only exit witness and portal/relay direct-leak canary."""
import http.server
import json
import sys
import urllib.parse

role, identity = sys.argv[1:]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        nonce = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get('nonce', [''])[0]
        payload = json.dumps({'role': role, 'identity': identity, 'nonce': nonce,
                              'peer': self.client_address[0]}).encode()
        with open('/root/witness.jsonl', 'ab', buffering=0) as ledger:
            ledger.write(payload + b'\n')
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass

http.server.ThreadingHTTPServer(('127.0.0.1', 18080), Handler).serve_forever()
