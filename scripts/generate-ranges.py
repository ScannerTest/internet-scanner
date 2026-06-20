#!/usr/bin/env python3
"""
Generate balanced CIDR blocks covering the entire IPv4 space.
Outputs JSON array for use in GitHub Actions matrix.

Also checks for previous run state to enable checkpoint-based resumption.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone


def generate_blocks():
    """Generate 256 /8 CIDR blocks covering all IPv4."""
    blocks = []
    for i in range(256):
        cidr = f"{i}.0.0.0/8"
        # Use ipaddress module to get block metadata
        import importlib
        try:
            ipaddress = importlib.import_module("ipaddress")
            network = ipaddress.IPv4Network(cidr, strict=False)
            blocks.append({
                "block": i,
                "cidr": str(cidr),
                "start_ip": str(network.network_address),
                "end_ip": str(network.broadcast_address),
                "num_hosts": network.num_addresses,
                "is_private": network.is_private,
                "is_loopback": network.is_loopback,
                "is_multicast": network.is_multicast,
                "is_reserved": network.is_reserved,
            })
        except Exception as e:
            blocks.append({
                "block": i,
                "cidr": cidr,
                "error": str(e)
            })
    return blocks


def load_completed_blocks(artifact_dir):
    """Check for state artifacts from previous runs to know what's done."""
    completed = set()
    state_file = os.path.join(artifact_dir, "scan_state.json")
    if os.path.exists(state_file):
        try:
            with open(state_file) as f:
                state = json.load(f)
            for block_id, status in state.get("blocks", {}).items():
                if status == "completed":
                    completed.add(int(block_id))
        except (json.JSONDecodeError, KeyError):
            pass
    return completed


def main():
    parser = argparse.ArgumentParser(description="Generate CIDR blocks for scanning matrix")
    parser.add_argument("--max-blocks", type=int, default=256, help="Maximum number of blocks (default: 256)")
    parser.add_argument("--skip-completed", action="store_true", help="Skip blocks that are already completed")
    parser.add_argument("--artifact-dir", default=".", help="Directory to check for previous artifacts")
    parser.add_argument("--offset", type=int, default=0, help="Start from this block index")
    parser.add_argument("--output", default="blocks.json", help="Output file path")
    args = parser.parse_args()

    all_blocks = generate_blocks()
    
    # Load completed blocks if resuming
    completed = set()
    if args.skip_completed:
        completed = load_completed_blocks(args.artifact_dir)
    
    # Filter: skip completed blocks, apply offset and max
    filtered = []
    for block in all_blocks:
        bid = block["block"]
        if bid in completed:
            continue
        if bid < args.offset:
            continue
        if len(filtered) >= args.max_blocks:
            break
        filtered.append(block)
    
    output = {
        "total_blocks": len(all_blocks),
        "completed_blocks": sorted(completed),
        "remaining_blocks": len(filtered),
        "blocks": filtered,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"Generated {len(filtered)} blocks to scan ({len(completed)} already completed)")
    print(f"Output written to {args.output}")


if __name__ == "__main__":
    main()
