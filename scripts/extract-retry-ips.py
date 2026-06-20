#!/usr/bin/env python3
"""Extract unique IPs from WHOIS retry queue files."""
import json
import os
import sys

retry = []
for f in sys.argv[1:]:
    try:
        with open(f) as fh:
            data = json.load(fh)
            if isinstance(data, list):
                retry.extend(data)
            elif isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, list):
                        retry.extend(v)
    except Exception:
        pass

ips = list(set(r.get("ip", "") for r in retry if r.get("ip")))
with open("retry_ips.txt", "w") as f:
    for ip in ips:
        f.write(ip + "\n")
print(f"Retrying {len(ips)} IPs")
