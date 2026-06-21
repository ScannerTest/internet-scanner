#!/usr/bin/env python3
"""
http-banner-chunk.py — Extract HTTP targets from masscan output and split into chunks.

Each chunk gets all IP:port combos for (hash(IP) % total_chunks == chunk_id).
This guarantees every IP goes to exactly one chunk, never duplicated across chunks.

Usage:
    python3 http-banner-chunk.py <masscan.json> <chunk_id> <total_chunks> [http_ports]
    # Outputs httpx-compatible IP:port list to stdout

Example:
    python3 http-banner-chunk.py masscan_0.json 0 8
    # Outputs httpx targets for chunk 0/8
"""
import json
import hashlib
import sys

# Default HTTP ports to probe
DEFAULT_HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000, 8008, 8889, 9090, 9443, 81, 82, 88, 90]


def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <masscan.json> <chunk_id> <total_chunks> [http_ports]",
              file=sys.stderr)
        sys.exit(1)

    masscan_file = sys.argv[1]
    chunk_id = int(sys.argv[2])
    total_chunks = int(sys.argv[3])

    if chunk_id < 0 or chunk_id >= total_chunks:
        print(f"Error: chunk_id {chunk_id} must be 0..{total_chunks - 1}", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) >= 5:
        http_ports = [int(p) for p in sys.argv[4].split(",")]
    else:
        http_ports = DEFAULT_HTTP_PORTS

    port_set = set(http_ports)
    count = 0
    chunk_count = 0

    try:
        with open(masscan_file) as f:
            for line in f:
                line = line.strip()
                if not line or line in ("[", "]", "{", "}"):
                    continue
                # Strip trailing comma from JSONL
                if line.endswith(","):
                    line = line[:-1]
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                ip = entry.get("ip", "")
                port = entry.get("port", 0)

                if not ip or port not in port_set:
                    continue

                count += 1

                # Deterministic chunk assignment: hash(ip) % total_chunks
                ip_hash = int(hashlib.md5(ip.encode()).hexdigest(), 16)
                assigned_chunk = ip_hash % total_chunks

                if assigned_chunk == chunk_id:
                    chunk_count += 1
                    print(f"{ip}:{port}")
    except FileNotFoundError:
        print(f"Error: masscan file not found: {masscan_file}", file=sys.stderr)
        sys.exit(1)

    # Log stats to stderr (so stdout is clean httpx input)
    print(f"Chunk {chunk_id}/{total_chunks}: {chunk_count} targets (from {count} total HTTP hits)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
