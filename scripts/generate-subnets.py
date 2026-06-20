#!/usr/bin/env python3
"""Generate /24 subnet CIDRs from blocks config for WHOIS scanning.
Only generates up to --max-subnets per run since WHOIS is rate-limited."""
import argparse
import ipaddress
import json

def main():
    parser = argparse.ArgumentParser(description="Generate /24 subnets from blocks config")
    parser.add_argument("blocks_file", help="Path to blocks.json")
    parser.add_argument("output_file", help="Output file path")
    parser.add_argument("--max-subnets", type=int, default=10000,
                        help="Max subnets to generate (default 10000, ~2.8h at 1/sec)")
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
                        out.write(f"{prefix}.{b}.{c}.0/24\n")
                        count += 1
                    if count >= args.max_subnets:
                        break
            else:
                net = ipaddress.IPv4Network(cidr, strict=False)
                for subnet in net.subnets(new_prefix=24):
                    if count >= args.max_subnets:
                        break
                    out.write(f"{subnet}\n")
                    count += 1
                if count >= args.max_subnets:
                    break

    print(f"Generated {count} /24 subnets")

if __name__ == "__main__":
    main()
