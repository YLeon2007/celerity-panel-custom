#!/usr/bin/env python3
"""Offline plan for the two activation entry points; this revision has no live executor."""
import argparse
import json
import os
import re
import stat
import sys

PP16_LINK = '6afafb6d991fd12f22e9f457'
PP16_OPERATION = 'abb507e7fe8a3dae930a20b5'
MAX_CONFIG_BYTES = 4096
RESUME = ('preflight', 'check-backup', 'check-isolation-and-masks', 'check-live-guards',
          'start-backend', 'wait-original-succeeded', 'check-release', 'client-dns-https', 'report')
FIRST = ('preflight', 'backup', 'exclude-writers', 'install-helpers-guards-units', 'start-backend',
         'submit-apply-once', 'wait-submitted-succeeded', 'check-release', 'client-dns-https', 'report')


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def read_config(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= MAX_CONFIG_BYTES:
            raise ValueError('invalid configuration')
        data = f.read(MAX_CONFIG_BYTES + 1)
        if len(data) != st.st_size:
            raise ValueError('invalid configuration')
    return json.loads(data.decode('utf-8'), object_pairs_hook=unique_fields)


def build_plan(cfg):
    if not isinstance(cfg, dict) or not all(isinstance(v, str) for v in cfg.values()):
        raise ValueError('invalid configuration')
    if cfg.get('target') == 'pp16' and cfg.get('mode') == 'resume':
        if cfg != {'target': 'pp16', 'mode': 'resume', 'linkId': PP16_LINK, 'operationId': PP16_OPERATION}:
            raise ValueError('wrong retained operation')
        steps = RESUME
    elif cfg.get('target') == 'prod' and cfg.get('mode') == 'first-reverse':
        if set(cfg) != {'target', 'mode', 'linkId'} or not re.fullmatch(r'[0-9a-f]{24}', cfg['linkId']):
            raise ValueError('invalid selection')
        steps = FIRST
    else:
        raise ValueError('unsupported plan')
    # No validation of a live topology, backup, scope or approval takes place here.
    return dict(cfg, executed=False, steps=list(steps))


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'INVALID_ARGUMENTS\n')


def main():
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--config', required=True, help='small JSON file containing selection only')
    parser.add_argument('--dry-run', action='store_true', help='print the plan, without running any step')
    args = parser.parse_args()
    if not args.dry_run:
        print('LIVE_DISABLED', file=sys.stderr)
        return 2
    try:
        plan = build_plan(read_config(args.config))
    except (OSError, ValueError, RecursionError):
        print('INVALID_CONFIG', file=sys.stderr)
        return 2
    print(json.dumps(plan, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
