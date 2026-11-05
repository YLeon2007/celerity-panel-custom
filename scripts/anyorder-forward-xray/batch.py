#!/usr/bin/env python3
"""Serial finite supervisor; preserve failed attempts, never force success."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('/home/leon/c3-anyorder-execution-20261104/forward-xray-wave31')
os.umask(0o077)
ROOT.mkdir(parents=True, exist_ok=True)
batch = ROOT / ('batch-' + secrets.token_hex(5))
batch.mkdir()
rows = []
for security in ['none', 'reality']:
    with (batch / (security + '.log')).open('w') as stream:
        p = subprocess.run([sys.executable, str(HERE / 'launch.py'), '--execute-local-fixture', '--security', security], stdout=stream, stderr=subprocess.STDOUT, timeout=720)
    rows.append({'security': security, 'exit': p.returncode, 'log': str(batch / (security + '.log'))})
    (batch / 'outcomes.json').write_text(json.dumps(rows, indent=2) + '\n')
print(json.dumps({'batch': str(batch), 'outcomes': rows}), flush=True)
sys.exit(0 if all(row['exit'] == 0 for row in rows) else 1)
