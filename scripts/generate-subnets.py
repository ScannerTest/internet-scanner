#!/usr/bin/env python3
"""Generate a sample IP per /24 subnet for WHOIS scanning.

Outputs bare IPs (e.g. 1.0.0.1) not CIDR notation, because whois servers
expect individual IPs. Caching in whois-cached.sh groups by /24 subnet.

Two modes:
  1. From blocks config: python3 generate-subnets.py blocks.json output.txt
  2. From single CIDR:   python3 generate-subnets.py --cidr 1.0.0.0/8 output.txt
"""
import argparse
import ipaddress
import json
import sys


def generate_from_cidr(cidr_str, out_file, max_subnets):
    """Generate sample IPs for all /24 subnets within a CIDR."""
    count = 0
    net = ipaddress.IPv4Network(cidr_str, strict=False)
    
    # Optimize: for /8, use fast loop instead of subnet() iterator
    if net.prefixlen <= 8:
        prefix = str(net.network_address).split('.')[0]
        for b in range(256):
            for c in range(256):
                if count >= max_subnets:
                    return count
                out_file.write(f"{prefix}.{b}.{c}.1\n")
                count += 1
    else:
        for subnet in net.subnets(new_prefix=24):
            if count >= max_subnets:
                break
            first_host = next(subnet.hosts())
            out_file.write(f"{first_host}\n")
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description="Generate sample IPs per /24 subnet")
    parser.add_argument("blocks_file", nargs='?', help="Path to blocks.json")
    parser.add_argument("output_file", help="Output file path")
    parser.add_argument("--cidr", help="Single CIDR block (e.g. 1.0.0.0/8) instead of blocks file")
    parser.add_argument("--max-subnets", type=int, default=12000,
                        help="Max subnets to generate per block (default 12000, ~3.7h at 1/sec)")
    args = parser.parse_args()
    
    if args.cidr:
        # Single CIDR mode (used by per-block WHOIS matrix)
        with open(args.output_file, 'w') as out:
            count = generate_from_cidr(args.cidr, out, args.max_subnets)
        print(f"Generated {count} /24 subnet sample IPs for {args.cidr}")
        return
    
    if not args.blocks_file:
        print("Error: provide blocks_file or --cidr", file=sys.stderr)
        sys.exit(1)
    
    # Blocks config mode (for standalone whois job)
    with open(args.blocks_file) as f:
        data = json.load(f)
    
    blocks = data if isinstance(data, list) else data.get('blocks', [])
    
    total = 0
    with open(args.output_file, 'w') as out:
        for block in blocks:
            cidr = block.get('cidr', '')
            if not cidr:
                continue
            count = generate_from_cidr(cidr, out, args.max_subnets)
            total += count
            if count >= args.max_subnets:
                print(f"  {cidr}: {count} subnets (cap reached)")
            else:
                print(f"  {cidr}: {count} subnets (all)")
    
    print(f"Total: {total} /24 subnet sample IPs")


if __name__ == "__main__":
    main()
