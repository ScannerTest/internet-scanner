#!/usr/bin/env python3
"""Generate minimal block matrix for GHA output - used in scan workflow init job."""
import json
import sys

blocks = json.load(open('blocks.json'))['blocks']
minimal = [{'block': b['block'], 'cidr': b['cidr']} for b in blocks]
print(f'block_count={len(blocks)}')
print(f'blocks={json.dumps(minimal)}')
