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
    'rebuildTransitMainWindow.py',
    'rebuildTransitMainSession.py',
    'rebuildTransitMainRuntime.py',
    'rebuildTransitMainHost.py',
    'rebuildTransitMainWire.py',
    'rebuildTransitDirectReceipt.py',
    'rebuildTransitMainReceiver.py',
)
DIRECT_COUNT = 5
PAYLOAD = SERVICES / 'rebuildRelayDirectPayload.xz'
MANIFEST = SERVICES / 'rebuildRelayDirectPayload.json'
# Reversible, fixed byte dictionary; the checked manifest carries the table
# used by the receiver. Reserved bytes must not occur in the original source.
TOKENS = (b'ROLLBACK_DRIFT', b'IN_FLIGHT', b'RUNTIME_UNPROVED', b'need(', b"['", b"']", b'.get(',
          b' and ', b' is not None', b' is None', b' not ', b'    ', b'None,', b'return ', b'before',
          b'backup', b'def ', b' == ', b' != ', b' or ', b' in ', b' for ', b' and', b' not', b'\n\n',
          b'backup[', b'paths[', b'after', b'record', b'unit(', b'if ', b'self.', b'raise ',
          b'CANDIDATE_INVALID', b'PREREQUISITE', b'generation', b'request', b'PACKAGE_', b'Refusal(',
          b'data', b'encode(', b'observ', b'remove_generation', b'value')
INDENT_BASE = 160
WORD_CODES = (*range(255, 226, -1), *range(225, 210, -1))  # 226 already occurs in UTF-8 source


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    files = [(SERVICES / path).read_bytes() for path in SOURCES]
    source = b''.join(files[:DIRECT_COUNT])
    main_source = b''.join(files[DIRECT_COUNT:])
    table = {i: b'\n' + b'    ' * (i - INDENT_BASE) for i in range(INDENT_BASE + 1, INDENT_BASE + 17)}
    table.update(zip(WORD_CODES[:len(TOKENS)], TOKENS, strict=True))
    if set(source) & table.keys():
        raise SystemExit('DIRECT source contains reserved dictionary bytes')
    indent = rb'\n(?: {4}){1,16}(?= *[^ \n])'
    transformed = re.sub(indent, lambda m: bytes([INDENT_BASE + (len(m[0]) - 1) // 4]), source)
    for code, token in zip(WORD_CODES, TOKENS):
        transformed = transformed.replace(token, bytes([code]))
    if args.check:
        existing = json.loads(MANIFEST.read_text())
        payload = PAYLOAD.read_bytes()
        length = existing['directSize']
        if type(length) is not int or not 0 < length < len(payload):
            raise SystemExit('DIRECT payload section size is invalid')
        packed, main_packed = payload[:length], payload[length:]
    else:
        packed = lzma.compress(transformed, filters=[dict(id=lzma.FILTER_LZMA2, preset=9 | lzma.PRESET_EXTREME,
                                                       dict_size=2**20, pb=0, nice_len=120)])
        main_packed = lzma.compress(main_source, preset=6)
    rows = [{'path': path, 'size': len(data), 'sha256': sha(data)}
            for path, data in zip(SOURCES, files, strict=True)]
    manifest = {
        'sources': rows[:DIRECT_COUNT],
        'sha256': sha(packed),
        'directSize': len(packed),
        'main': {'sources': rows[DIRECT_COUNT:], 'sha256': sha(main_packed), 'size': len(main_packed)},
        'dictionary': {str(k): v.decode('ascii') for k, v in table.items()},
    }
    # Reserve space for the bootstrap and shell wrapper with NUL.
    # directCommand also checks the exact argv.
    assert 120**139 >= 256**120
    encoded_size = (len(packed) + 119) // 120 * 139
    decoded = b''.join(table.get(b, bytes([b])) for b in lzma.decompress(packed, memlimit=16777216))
    if decoded != source or encoded_size + 1660 > 131072:
        raise SystemExit('DIRECT source mismatch or shell argument too large')
    if lzma.decompress(main_packed, memlimit=16777216) != main_source:
        raise SystemExit('MAIN payload source mismatch')
    body = json.dumps(manifest, indent=2) + '\n'
    if args.check:
        if MANIFEST.read_text() != body:
            raise SystemExit('DIRECT payload manifest is stale')
    else:
        PAYLOAD.write_bytes(packed + main_packed)
        MANIFEST.write_text(body)
    print(f'DIRECT exact sources={DIRECT_COUNT} encoded bytes={encoded_size}; '
          f'MAIN exact sources={len(files) - DIRECT_COUNT} packed bytes={len(main_packed)}')


if __name__ == '__main__':
    main()
