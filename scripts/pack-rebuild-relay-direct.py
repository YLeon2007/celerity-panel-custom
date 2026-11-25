#!/usr/bin/env python3
"""Regenerate or verify the byte-exact, offline DIRECT Python payload."""
import argparse
import hashlib
import json
import lzma
import re
from pathlib import Path

SERVICES = Path(__file__).resolve().parents[1] / 'src/services'
SOURCES = (
    '../modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py',
    'rebuildRelayStockRuntime.py',
    'rebuildRelayPackageGuard.py',
    'rebuildRelayReplacement.py',
    'rebuildRelayDirectHost.py',
)
PAYLOAD = SERVICES / 'rebuildRelayDirectPayload.xz'
MANIFEST = SERVICES / 'rebuildRelayDirectPayload.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    files = [(SERVICES / path).read_bytes() for path in SOURCES]
    source = b''.join(files)
    # A run of tabs encodes both the newline and its four-space indents.
    # Reject literal tabs so reversal preserves every byte, including strings.
    if b'\t' in source:
        raise SystemExit('DIRECT source contains literal tabs')
    indent = rb'\n(?: {4})+(?= *[^ \n])'  # never merge runs across a whitespace-only line
    packed = PAYLOAD.read_bytes() if args.check else lzma.compress(
        re.sub(indent, lambda m: b'\t' * ((len(m[0]) - 1) // 4), source),
        filters=[dict(id=lzma.FILTER_LZMA2, preset=9 | lzma.PRESET_EXTREME, dict_size=2**20, pb=0)])
    manifest = {
        'sources': [{'path': path, 'size': len(data), 'sha256': sha(data)} for path, data in zip(SOURCES, files)],
        'sha256': sha(packed),
    }
    # Reserve space for the bootstrap and shell wrapper with NUL.
    # directCommand also checks the exact argv.
    assert 120**139 >= 256**120
    encoded_size = (len(packed) + 119) // 120 * 139
    decoded = re.sub(rb'\t+', lambda m: b'\n' + b'    ' * len(m[0]), lzma.decompress(packed, memlimit=16777216))
    if decoded != source or encoded_size + 1900 >= 131072:
        raise SystemExit('DIRECT source mismatch or shell argument too large')
    body = json.dumps(manifest, indent=2) + '\n'
    if args.check:
        if MANIFEST.read_text() != body:
            raise SystemExit('DIRECT payload manifest is stale')
    else:
        PAYLOAD.write_bytes(packed)
        MANIFEST.write_text(body)
    print(f'DIRECT exact sources={len(files)} encoded bytes={encoded_size}')


if __name__ == '__main__':
    main()
