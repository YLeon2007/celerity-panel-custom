#!/usr/bin/env python3
"""Finite serial replay in an independently bounded heavy scope; stop on failure."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('/home/leon/c3-anyorder-execution-20261104/installed-group-xray-wave43')
os.umask(0o077)
ROOT.mkdir(parents=True, exist_ok=True)
batch = ROOT / ('batch-' + secrets.token_hex(5))
batch.mkdir()
rows = []
for scenario in ['delete-d', 'delete-u']:
    with (batch / (scenario + '.log')).open('w') as stream:
        p = subprocess.run([sys.executable, str(HERE / 'launch.py'), '--execute-local-fixture', '--scenario', scenario],
                           stdout=stream, stderr=subprocess.STDOUT, timeout=720)
    rows.append({'scenario': scenario, 'exit': p.returncode, 'log': str(batch / (scenario + '.log'))})
    (batch / 'outcomes.json').write_text(json.dumps(rows, indent=2) + '\n')
    if p.returncode:
        break
print(json.dumps({'batch': str(batch), 'outcomes': rows}), flush=True)
sys.exit(0 if len(rows) == 2 and all(row['exit'] == 0 for row in rows) else 1)
