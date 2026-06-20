#!/bin/bash
# ============================================================
# whois-cached.sh - WHOIS lookups with subnet caching
#
# Features:
# - Caches WHOIS results per /24 subnet (covers 256 IPs with 1 lookup)
# - Rate limited to avoid getting blocked
# - Failed lookups go to a dead-letter queue for retry
# - Never does redundant lookups
# - Checkpointing for long-running batches
# ============================================================
set -euo pipefail

INPUT_FILE="${1:-}"
CACHE_FILE="${2:-whois_cache.json}"
RETRY_FILE="${3:-whois_retry.json}"
OUTPUT_FILE="${4:-whois_results.json}"
CHECKPOINT="${5:-whois_checkpoint.json}"
RATE_LIMIT_MS="${RATE_LIMIT_MS:-1100}"  # ~1 query per second to be safe

if [ -z "$INPUT_FILE" ] || [ ! -f "$INPUT_FILE" ]; then
    echo "Usage: $0 <input_ips_file> [cache_file] [retry_file] [output_file] [checkpoint]"
    echo "Input file: one IP per line"
    exit 1
fi

# ---------- Initialize files ----------
touch "$OUTPUT_FILE"
[ ! -f "$CACHE_FILE" ] && echo '{}' > "$CACHE_FILE"
[ ! -f "$RETRY_FILE" ] && echo '[]' > "$RETRY_FILE"
[ ! -f "$CHECKPOINT" ] && echo '{"processed":0,"last_ip":""}' > "$CHECKPOINT"

# ---------- Helper: Get /24 subnet ----------
get_subnet() {
    local ip="$1"
    echo "$ip" | awk -F. '{print $1"."$2"."$3".0/24"}'
}

# ---------- Helper: Check cache ----------
check_cache() {
    local subnet="$1"
    python3 -c "
import json, os, sys
try:
    if os.path.getsize('$CACHE_FILE') > 0:
        with open('$CACHE_FILE') as f:
            cache = json.load(f)
    else:
        cache = {}
except Exception:
    cache = {}
print(json.dumps(cache.get('$subnet', None)))
" 2>/dev/null || echo 'null'
}

# ---------- Helper: Update cache ----------
update_cache() {
    local subnet="$1"
    local data="$2"
    python3 -c "
import json, os
try:
    if os.path.getsize('$CACHE_FILE') > 0:
        with open('$CACHE_FILE') as f:
            cache = json.load(f)
    else:
        cache = {}
except Exception:
    cache = {}
try:
    cache['$subnet'] = $data
    with open('$CACHE_FILE', 'w') as f:
        json.dump(cache, f, indent=2)
except Exception:
    pass
" 2>/dev/null || true
}

# ---------- Helper: WHOIS lookup with rate limiting ----------
do_whois() {
    local ip="$1"
    local subnet
    subnet=$(get_subnet "$ip")
    
    # Check cache first
    CACHED=$(check_cache "$subnet")
    if [ "$CACHED" != "null" ] && [ -n "$CACHED" ]; then
        echo "$CACHED"
        return 0
    fi
    
    # Rate limit
    sleep "$(echo "scale=3; $RATE_LIMIT_MS / 1000" | bc)"
    
    # Do WHOIS lookup, extract key fields
    RESULT=$(whois "$ip" 2>/dev/null || echo '{"error":"whois_failed"}')
    
    # Parse result for key fields
    PARSED=$(printf '%s\n' "$RESULT" | python3 -c "
import sys, json
data = sys.stdin.read()
result = {'raw_ip': '$ip', 'subnet': '$subnet'}

# Extract common WHOIS fields
import re
fields = {
    'org': r'(?:OrgName|organisation|org-name|Organization|owner):\s*(.+)',
    'netname': r'(?:netname|NetName|net-name):\s*(.+)',
    'country': r'(?:Country|country):\s*(.+)',
    'asn': r'(?:origin|OriginAS|ASNumber|as-number|aut-num):\s*AS?(\d+)',
    'cidr': r'(?:CIDR|inetnum|NetRange|inetnum):\s*(.+)',
    'descr': r'(?:descr|description|Descr|Desc):\s*(.+)',
    'status': r'(?:status|Status|admin-c):\s*(.+)',
}

for key, pattern in fields.items():
    match = re.search(pattern, data, re.IGNORECASE)
    if match:
        result[key] = match.group(1).strip()

print(json.dumps(result))
" 2>/dev/null) || RESULT='{"error":"parse_failed","ip":"'$ip'","subnet":"'$subnet'"}'
    
    # Update cache
    if printf '%s\n' "$PARSED" | python3 -c "import json,sys; d=json.load(sys.stdin); assert 'error' not in d or d.get('org')" 2>/dev/null; then
        update_cache "$subnet" "$PARSED"
        echo "$PARSED"
    else
        # Lookup failed - add to retry queue
        echo "$PARSED" >> "$RETRY_FILE.tmp"
        echo '{"error":"lookup_failed","ip":"'$ip'","subnet":"'$subnet'"}'
    fi
}

# ---------- Main ----------
echo "Starting WHOIS lookups with subnet caching..."
echo "Input: $INPUT_FILE ($(wc -l < "$INPUT_FILE") IPs)"
echo "Cache: $(python3 -c "import json; print(len(json.load(open('$CACHE_FILE'))))") entries"

# Load checkpoint
LAST_PROCESSED=$(python3 -c "import json; print(json.load(open('$CHECKPOINT')).get('processed', 0))")
echo "Resuming from IP #$LAST_PROCESSED"

# Process IPs
COUNT=0
SUCCESS=0
CACHED_HITS=0
FAILED=0

while IFS= read -r ip; do
    COUNT=$((COUNT + 1))
    
    # Skip already processed (checkpoint resume)
    if [ "$COUNT" -le "$LAST_PROCESSED" ]; then
        continue
    fi
    
    # Skip empty lines
    [ -z "$ip" ] && continue
    
    # Get or lookup WHOIS
    SUBNET=$(get_subnet "$ip")
    CACHED=$(check_cache "$subnet")
    
    if [ "$CACHED" != "null" ] && [ -n "$CACHED" ]; then
        # Cache hit - just record
        echo "$CACHED" >> "$OUTPUT_FILE.$$"
        CACHED_HITS=$((CACHED_HITS + 1))
    else
        # Cache miss - do lookup
        RESULT=$(do_whois "$ip")
        echo "$RESULT" >> "$OUTPUT_FILE.$$"
        
        if printf '%s\n' "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); assert 'error' not in d" 2>/dev/null; then
            SUCCESS=$((SUCCESS + 1))
        else
            FAILED=$((FAILED + 1))
        fi
    fi
    
    # Save checkpoint every 100 IPs
    if [ $((COUNT % 100)) -eq 0 ]; then
        python3 -c "import json; json.dump({'processed': $COUNT, 'last_ip': '$ip'}, open('$CHECKPOINT','w'))"
        echo "  Progress: $COUNT IPs processed | Cache hits: $CACHED_HITS | Lookups: $SUCCESS | Failed: $FAILED"
    fi
    
done < "$INPUT_FILE"

# Finalize
python3 -c "import json; json.dump({'processed': $COUNT, 'last_ip': '', 'complete': True}, open('$CHECKPOINT','w'))"

# Merge output
if [ -f "$OUTPUT_FILE.$$" ]; then
    sort -u "$OUTPUT_FILE.$$" > "$OUTPUT_FILE"
    rm -f "$OUTPUT_FILE.$$"
fi

# Finalize retry queue
if [ -f "$RETRY_FILE.tmp" ]; then
    sort -u "$RETRY_FILE.tmp" > "$RETRY_FILE"
    rm -f "$RETRY_FILE.tmp"
fi

echo ""
echo "============================================================"
echo "  WHOIS Complete"
echo "  Total IPs processed: $COUNT"
echo "  Cache hits:          $CACHED_HITS"
echo "  New lookups:         $SUCCESS"
echo "  Failed (retry):      $FAILED"
echo "  Cache size:          $(python3 -c "import json; print(len(json.load(open('$CACHE_FILE'))))") subnets"
echo "============================================================"
