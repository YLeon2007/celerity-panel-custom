#!/usr/bin/env python3
"""Serial finite supervisor; preserve failed attempts, never force success."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('/home/leon/c3-anyorder-execution-20261104/manual-tls-xray-wave35')
os.umask(0o077)
ROOT.mkdir(parents=True, exist_ok=True)
batch = ROOT / ('batch-' + secrets.token_hex(5))
batch.mkdir()
rows = []
for variant in ['primary', 'extra']:
    with (batch / (variant + '.log')).open('w') as stream:
        p = subprocess.run([sys.executable, str(HERE / 'launch.py'), '--execute-local-fixture', '--variant', variant], stdout=stream, stderr=subprocess.STDOUT, timeout=720)
    rows.append({'variant': variant, 'exit': p.returncode, 'log': str(batch / (variant + '.log'))})
    (batch / 'outcomes.json').write_text(json.dumps(rows, indent=2) + '\n')
print(json.dumps({'batch': str(batch), 'outcomes': rows}), flush=True)
sys.exit(0 if all(row['exit'] == 0 for row in rows) else 1)
