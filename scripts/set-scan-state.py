#!/usr/bin/env python3
"""Aggregate completed block states into scan_state.json for resumption."""
import json
import os
import glob
import sys

results_dir = sys.argv[1] if len(sys.argv) > 1 else 'scan_results'
output_file = sys.argv[2] if len(sys.argv) > 2 else 'scan_state.json'

completed = set()
for f in glob.glob(os.path.join(results_dir, 'state_*.json')):
    try:
        state = json.load(open(f))
        if state.get('status') == 'completed':
            completed.add(state['block_id'])
    except Exception:
        pass

state = {
    'blocks': {str(b): 'completed' for b in sorted(completed)},
    'total_completed': len(completed)
}
with open(output_file, 'w') as f:
    json.dump(state, f, indent=2)

print(f'Completed blocks: {len(completed)}')
