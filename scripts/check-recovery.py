#!/usr/bin/env python3
"""Check what needs recovery in the recovery workflow."""
import json
import os
import sys

recovery_whois_dir = sys.argv[1] if len(sys.argv) > 1 else 'recovery_whois'
recovery_state_dir = sys.argv[2] if len(sys.argv) > 2 else 'recovery_state'
recovery_blocks_dir = sys.argv[3] if len(sys.argv) > 3 else 'recovery_blocks'

results = {
    'need_whois_retry': False,
    'retry_count': 0,
    'incomplete_blocks': [],
}

# Check for failed WHOIS retries
whois_retry_file = os.path.join(recovery_whois_dir, 'whois_retry.json')
if os.path.exists(whois_retry_file):
    try:
        with open(whois_retry_file) as f:
            retry_data = json.load(f)
        if isinstance(retry_data, list):
            results['retry_count'] = len(retry_data)
        elif isinstance(retry_data, dict):
            results['retry_count'] = len(retry_data.get('failed', []))
        results['need_whois_retry'] = results['retry_count'] > 0
    except Exception:
        pass

# Find incomplete blocks
blocks_file = os.path.join(recovery_blocks_dir, 'blocks.json')
state_file = os.path.join(recovery_state_dir, 'scan_state.json')

all_blocks = []
if os.path.exists(blocks_file):
    try:
        with open(blocks_file) as f:
            data = json.load(f)
            all_blocks = data.get('blocks', [])
    except Exception:
        pass

# Load scan state
state = {'blocks': {}}
if os.path.exists(state_file):
    try:
        with open(state_file) as f:
            state = json.load(f)
    except Exception:
        pass

completed = set()
for k, v in state.get('blocks', {}).items():
    if v == 'completed':
        completed.add(int(k))

for b in all_blocks:
    if b['block'] not in completed:
        results['incomplete_blocks'].append(b['block'])

print(json.dumps(results))
