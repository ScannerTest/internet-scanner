#!/usr/bin/env python3
"""Generate a sample IP per /24 subnet from blocks config for WHOIS scanning.
Outputs bare IPs (e.g. 1.0.0.1) not CIDR notation, because whois servers
expect individual IPs. Caching in whois-cached.sh groups by /24 subnet."""
import argparse
import ipaddress
import json

def main():
    parser = argparse.ArgumentParser(description="Generate sample IPs per /24 subnet")
    parser.add_argument("blocks_file", help="Path to blocks.json")
    parser.add_argument("output_file", help="Output file path")
    parser.add_argument("--max-subnets", type=int, default=20000,
                        help="Max subnets to generate (default 20000, ~5.5h at 1/sec)")
    args = parser.parse_args()

    with open(args.blocks_file) as f:
        data = json.load(f)

    count = 0
    with open(args.output_file, 'w') as out:
        for block in data.get('blocks', []):
            cidr = block.get('cidr', '')
            if count >= args.max_subnets:
                break
            if '/8' in cidr:
                prefix = cidr.split('.')[0]
                for b in range(256):
                    for c in range(256):
                        if count >= args.max_subnets:
                            break
                        # Use .1 as representative IP for this /24
                        out.write(f"{prefix}.{b}.{c}.1\n")
                        count += 1
                    if count >= args.max_subnets:
                        break
            else:
                net = ipaddress.IPv4Network(cidr, strict=False)
                for subnet in net.subnets(new_prefix=24):
                    if count >= args.max_subnets:
                        break
                    # Use first host as representative IP
                    first_host = next(subnet.hosts())
                    out.write(f"{first_host}\n")
                    count += 1
                if count >= args.max_subnets:
                    break

    print(f"Generated {count} /24 subnet sample IPs")

if __name__ == "__main__":
    main()
