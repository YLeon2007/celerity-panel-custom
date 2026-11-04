#!/usr/bin/env python3
"""Preserve compact attempt evidence while keeping bulky raw local diagnostics."""
import hashlib
import json
from pathlib import Path

folder = Path(__file__).resolve().parent
for n in range(1, 11):
    p = folder / f'run-{n:02d}' / 'evidence.json'
    raw = p.read_bytes()
    x = json.loads(raw)
    cases = [{k: c[k] for k in ['name', 'status', 'durationMs', 'error'] if k in c} for c in x['cases']]
    summary = {
        'scope': 'compact diagnostic attempt, not a final acceptance result; raw file remains local',
        'rawSha256': hashlib.sha256(raw).hexdigest(), 'rawBytes': len(raw),
        'success': x.get('success'), 'totals': x.get('totals'), 'cases': cases,
        'asset': x.get('asset'), 'engine': x.get('engine'),
        'uiObstructions': x.get('uiObstructions', []),
        'backendBlocker': x.get('backendBlocker'),
        'consoleErrors': sorted({e.get('text', '') for e in x.get('console', []) if e.get('level') == 'error'}),
        'browserCleanup': x.get('browserCleanup'), 'applicationCleanup': x.get('applicationCleanup'),
        'mutations': [{k: r[k] for k in ['method', 'path', 'status', 'key', 'droppedAfterRealRoute'] if k in r}
                      for r in x.get('requests', []) if r['method'] != 'GET'],
    }
    p.with_name('summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(p.parent.name, json.dumps(summary['totals']))
